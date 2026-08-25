from __future__ import annotations

import json
from datetime import UTC, datetime
from urllib.parse import parse_qs, urlsplit

import pytest

from hecavex_radar.domain_context import collect, public_records, read_state
from hecavex_radar.safety import defang_host, stable_id
from hecavex_radar.signal_detail import build_signal_details


def test_dns_and_rdap_context_is_bounded_and_repeatable(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    domain = "login.secure-swedbank-login.com"
    display = defang_host(domain)
    signal_id = stable_id(display.lower())
    snapshot = {
        "schemaVersion": 2,
        "dataset": "live",
        "signals": [{"id": signal_id, "domain": display}],
    }
    snapshot_path = tmp_path / "public" / "data" / "radar.json"
    snapshot_path.parent.mkdir(parents=True)
    snapshot_path.write_text(json.dumps(snapshot), encoding="utf-8")

    rdap_urls: list[str] = []

    def requester(url: str, host: str):
        if host == "data.iana.org":
            return {"services": [[ ["com"], ["https://rdap.example.test/"] ]]}
        if host == "cloudflare-dns.com":
            record_type = parse_qs(urlsplit(url).query)["type"][0]
            answers = {
                "A": [{"type": 1, "TTL": 300, "data": "192.0.2.10"}],
                "NS": [{"type": 2, "TTL": 600, "data": "ns1.example.net."}],
            }.get(record_type, [])
            return {"Status": 0, "Answer": answers}
        assert host == "rdap.example.test"
        rdap_urls.append(url)
        return {
            "events": [
                {"eventAction": "registration", "eventDate": "2026-08-25T10:00:00Z"},
                {"eventAction": "registration", "eventDate": "2026-08-24T10:00:00Z"},
                {"eventAction": "expiration", "eventDate": "2027-08-24T10:00:00Z"},
                {"eventAction": "expiration", "eventDate": "2028-08-24T10:00:00Z"},
            ],
            "status": ["client transfer prohibited"],
            "entities": [
                {
                    "roles": ["registrar"],
                    "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]],
                }
            ],
        }

    result = collect(
        requester,
        now=datetime(2026, 8, 25, 12, 0, tzinfo=UTC),
        per_run=1,
    )
    state = read_state()

    assert result["outcome"] == "completed"
    assert len(state["records"]) == 1
    record = state["records"][0]
    assert record["signalId"] == signal_id
    assert record["dns"]["a"] == ["192[.]0[.]2[.]10"]
    assert record["dns"]["ns"] == ["ns1[.]example[.]net"]
    assert record["dns"]["minimumTtl"] == 300
    assert record["registration"]["registrar"] == "Example Registrar"
    assert record["registration"]["domain"] == "secure-swedbank-login[.]com"
    assert record["registration"]["registeredAt"] == "2026-08-24T10:00:00.000Z"
    assert record["registration"]["expiresAt"] == "2028-08-24T10:00:00.000Z"
    assert record["registration"]["statuses"] == ["client-transfer-prohibited"]
    assert rdap_urls[0].endswith("/domain/secure-swedbank-login.com")

    contexts = public_records(now=datetime(2026, 8, 25, 12, 1, tzinfo=UTC))
    details = build_signal_details(
        [
            {
                "id": signal_id,
                "url": display,
                "domain": display,
                "firstSeen": "2026-08-25T12:00:00.000Z",
                "lastSeen": "2026-08-25T12:00:00.000Z",
                "sources": ["CertStream"],
                "status": "suspected",
                "brand": "Swedbank",
                "country": None,
                "host": None,
                "screenshotUrl": None,
                "matchScore": 90,
                "evidenceTier": "name-only",
                "reviewState": "unreviewed",
                "ltRelevance": "lithuanian-brand-relevance",
                "confidence": 90,
            }
        ],
        [],
        "2026-08-25T12:01:00.000Z",
        contexts,
    )
    assert details[signal_id]["observations"] == []
    assert details[signal_id]["domainContext"]["dns"]["a"] == ["192[.]0[.]2[.]10"]


def test_rdap_bootstrap_failure_still_refreshes_independent_dns_context(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    domain = "login-swedbank.example"
    display = defang_host(domain)
    signal_id = stable_id(display.lower())
    snapshot_path = tmp_path / "public" / "data" / "radar.json"
    snapshot_path.parent.mkdir(parents=True)
    snapshot_path.write_text(
        json.dumps({"schemaVersion": 2, "dataset": "live", "signals": [{"id": signal_id, "domain": display}]}),
        encoding="utf-8",
    )

    def healthy(url: str, host: str):
        if host == "data.iana.org":
            return {"services": [[ ["example"], ["https://rdap.example.test/"] ]]}
        if host == "cloudflare-dns.com":
            return {"Status": 0, "Answer": []}
        return {
            "events": [{"eventAction": "registration", "eventDate": "2026-08-20T00:00:00Z"}],
            "entities": [],
            "status": [],
        }

    collect(healthy, now=datetime(2026, 8, 25, 10, 0, tzinfo=UTC), per_run=1)
    def bootstrap_failure(url: str, host: str):
        if host == "data.iana.org":
            raise RuntimeError("temporary bootstrap failure")
        assert host == "cloudflare-dns.com"
        return {"Status": 0, "Answer": [{"type": 1, "TTL": 120, "data": "192.0.2.42"}]}

    result = collect(bootstrap_failure, now=datetime(2026, 8, 25, 11, 0, tzinfo=UTC), per_run=1)
    assert result["outcome"] == "partial"
    record = read_state()["records"][0]
    assert record["observedAt"] == "2026-08-25T11:00:00.000Z"
    assert record["dns"]["a"] == ["192[.]0[.]2[.]42"]
    assert record["registration"] is None


def test_all_dns_servfail_is_not_completed_context(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    domain = "secure-swedbank-login.com"
    display = defang_host(domain)
    signal_id = stable_id(display.lower())
    snapshot_path = tmp_path / "public" / "data" / "radar.json"
    snapshot_path.parent.mkdir(parents=True)
    snapshot_path.write_text(
        json.dumps({"schemaVersion": 2, "dataset": "live", "signals": [{"id": signal_id, "domain": display}]}),
        encoding="utf-8",
    )

    def requester(url: str, host: str):
        if host == "data.iana.org":
            return {"services": [[ ["com"], ["https://rdap.example.test/"] ]]}
        if host == "cloudflare-dns.com":
            return {"Status": 2}
        pytest.fail("RDAP must not run after all DNS queries fail")

    result = collect(requester, now=datetime(2026, 8, 25, 12, 0, tzinfo=UTC), per_run=1)
    assert result["outcome"] == "failed"
    assert read_state()["records"] == []
