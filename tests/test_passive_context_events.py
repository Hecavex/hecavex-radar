from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest

from hecavex_radar import passive_context
from hecavex_radar.models import RadarSignal, RawDomainIntelligence
from hecavex_radar.passive_context import _event, _semantic_changes, _urlscan_snapshot
from hecavex_radar.safety import stable_id
from hecavex_radar.signal_detail import load_recent_context_changes
from hecavex_radar.urlscan import _primary_certificate_sha256


def _dns(**updates: object) -> dict[str, object]:
    value: dict[str, object] = {
        "a": [],
        "aaaa": [],
        "cname": [],
        "ns": ["ns1[.]example"],
        "mx": [],
        "minimumTtl": 300,
        "queriesCompleted": 5,
        "observedAt": "2026-08-26T09:00:00.000Z",
    }
    value.update(updates)
    return value


def test_dns_resolution_transitions_are_explicit() -> None:
    unresolved = _dns()
    resolved = _dns(a=["192[.]0[.]2[.]10"])

    assert _semantic_changes("dns", unresolved, resolved) == [("first-resolving", ["a"])]
    assert _semantic_changes("dns", resolved, unresolved) == [("stopped-resolving", ["a"])]


def test_dns_record_families_change_independently() -> None:
    before = _dns(a=["192[.]0[.]2[.]10"], cname=["old[.]example"])
    after = _dns(
        a=["192[.]0[.]2[.]11"],
        aaaa=["2001:db8::1"],
        cname=["new[.]example"],
        ns=["ns2[.]example"],
        mx=["10 mail[.]example"],
    )

    assert _semantic_changes("dns", before, after) == [
        ("dns-a-changed", ["a"]),
        ("dns-aaaa-changed", ["aaaa"]),
        ("dns-cname-changed", ["cname"]),
        ("dns-ns-changed", ["ns"]),
        ("dns-mx-changed", ["mx"]),
    ]


def test_dns_rrset_order_does_not_create_a_change() -> None:
    before = _dns(
        a=["192[.]0[.]2[.]10", "192[.]0[.]2[.]11"],
        aaaa=["2001:db8::1", "2001:db8::2"],
        ns=["ns1[.]example", "ns2[.]example"],
        mx=["10 mail1[.]example", "20 mail2[.]example"],
    )
    after = _dns(
        a=["192[.]0[.]2[.]11", "192[.]0[.]2[.]10"],
        aaaa=["2001:db8::2", "2001:db8::1"],
        ns=["ns2[.]example", "ns1[.]example"],
        mx=["20 mail2[.]example", "10 mail1[.]example"],
    )

    assert _semantic_changes("dns", before, after) == []


def test_rdap_changes_are_field_specific() -> None:
    before = {
        "registrar": "Old Registrar",
        "statuses": ["active"],
        "expiresAt": "2026-09-01T00:00:00.000Z",
    }
    after = {
        "registrar": "New Registrar",
        "statuses": ["client-hold"],
        "expiresAt": "2027-09-01T00:00:00.000Z",
    }

    assert _semantic_changes("rdap", before, after) == [
        ("rdap-registrar-changed", ["registrar"]),
        ("rdap-status-changed", ["statuses"]),
        ("rdap-expiry-changed", ["expiresAt"]),
    ]


def test_rdap_status_order_does_not_create_a_change() -> None:
    before = {"statuses": ["active", "client-hold"]}
    after = {"statuses": ["client-hold", "active"]}

    assert _semantic_changes("rdap", before, after) == []


def test_urlscan_hash_certificate_and_page_changes_are_explicit() -> None:
    before = {
        "pageTitle": "Old title",
        "redirectedToDomain": None,
        "httpStatus": 200,
        "ipAddress": "192[.]0[.]2[.]10",
        "asn": 64500,
        "primaryHtmlSha256": ["a" * 64],
        "certificateFingerprintSha256": "b" * 64,
        "certificateIssuer": "Old CA",
        "certificateNotBefore": "2026-08-01T00:00:00.000Z",
        "certificateNotAfter": "2026-11-01T00:00:00.000Z",
    }
    after = {
        "pageTitle": "New title",
        "redirectedToDomain": "login[.]example",
        "httpStatus": 302,
        "ipAddress": "192[.]0[.]2[.]11",
        "asn": 64501,
        "primaryHtmlSha256": ["c" * 64],
        "certificateFingerprintSha256": "d" * 64,
        "certificateIssuer": "New CA",
        "certificateNotBefore": "2026-08-20T00:00:00.000Z",
        "certificateNotAfter": "2026-11-20T00:00:00.000Z",
    }

    changes = _semantic_changes("urlscan", before, after)
    assert [change_type for change_type, _fields in changes] == [
        "urlscan-title-changed",
        "urlscan-redirect-changed",
        "urlscan-http-status-changed",
        "urlscan-ip-changed",
        "urlscan-asn-changed",
        "urlscan-primary-html-sha256-changed",
        "urlscan-certificate-fingerprint-changed",
        "certificate-reissued",
    ]
    assert changes[-1][1] == [
        "certificateFingerprintSha256",
        "certificateIssuer",
        "certificateNotBefore",
        "certificateNotAfter",
    ]


def test_collection_timestamp_drift_does_not_create_a_change() -> None:
    before = _dns(observedAt="2026-08-26T09:00:00.000Z", minimumTtl=300)
    after = _dns(observedAt="2026-08-26T10:00:00.000Z", minimumTtl=120)

    assert _semantic_changes("dns", before, after) == []


def test_nonfinite_component_is_rejected_before_hashing_or_write() -> None:
    with pytest.raises(ValueError, match="Out of range float"):
        passive_context._component({"score": float("nan")})


def test_event_persists_provider_timestamp_and_reference() -> None:
    event = _event(
        "a" * 20,
        "login[.]example",
        "2026-08-26T10:00:00.000Z",
        "urlscan",
        "urlscan-title-changed",
        ["pageTitle"],
        "2026-08-26T09:55:00.000Z",
        "https://urlscan.io/result/00000000-0000-0000-0000-000000000001/",
        {"pageTitle": "Old"},
        {"pageTitle": "New"},
    )

    assert event["schemaVersion"] == 2
    assert event["sourceObservedAt"] == "2026-08-26T09:55:00.000Z"
    assert event["sourceReference"] == (
        "https://urlscan.io/result/00000000-0000-0000-0000-000000000001/"
    )


def test_urlscan_baseline_retains_bounded_hash_and_certificate_evidence() -> None:
    signal = cast(
        RadarSignal,
        {
            "referenceUrl": "https://urlscan.io/result/00000000-0000-0000-0000-000000000001/",
            "hashes": ["A" * 64, "a" * 64, "b" * 64],
        },
    )
    intelligence = RawDomainIntelligence(
        domain="login.example",
        source="URLScan",
        observed_at="2026-08-26T09:55:00.000Z",
        certificate={"fingerprints": {"sha256": "C" * 64}},
    )

    baseline = _urlscan_snapshot(intelligence, signal)
    assert baseline["referenceUrl"] == signal["referenceUrl"]
    assert baseline["primaryHtmlSha256"] == ["a" * 64, "b" * 64]
    assert baseline["certificateFingerprintSha256"] == "c" * 64


def test_primary_certificate_fingerprint_is_bound_to_document_response() -> None:
    fingerprint = "d" * 64
    detail = {
        "page": {"url": "https://login.example/"},
        "data": {
            "requests": [
                {
                    "type": "Document",
                    "request": {"request": {"url": "https://login.example/"}},
                    "response": {
                        "response": {"url": "https://login.example/"},
                        "securityDetails": {"certificateId": fingerprint},
                    },
                }
            ]
        },
    }

    assert _primary_certificate_sha256(detail) == fingerprint
    detail["data"]["requests"][0]["response"]["response"]["url"] = "https://cdn.example/"
    assert _primary_certificate_sha256(detail) is None


def _journal_event(domain: str = "login[.]example") -> dict[str, object]:
    return _event(
        stable_id(domain),
        domain,
        "2026-08-26T10:00:00.000Z",
        "dns",
        "dns-ns-changed",
        ["ns"],
        "2026-08-26T09:59:00.000Z",
        "https://cloudflare-dns.com/dns-query",
        {"ns": ["ns1[.]example"]},
        {"ns": ["ns2[.]example"]},
    )


def test_journal_writer_rejects_malformed_and_duplicate_existing_rows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    target = tmp_path / "data/history/context/2026-08-26/events.ndjson"
    target.parent.mkdir(parents=True)
    target.write_text("not json\n", encoding="utf-8")
    with pytest.raises(ValueError, match="malformed"):
        passive_context._write_events([_journal_event()], "data/history/context", datetime(2026, 8, 26).date())

    encoded = json.dumps(_journal_event(), separators=(",", ":"))
    target.write_text(f"{encoded}\n{encoded}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        passive_context._write_events([_journal_event()], "data/history/context", datetime(2026, 8, 26).date())


def test_public_journal_reader_rejects_malformed_duplicate_and_invalid_semantics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    target = tmp_path / "data/history/context/2026-08-26/events.ndjson"
    target.parent.mkdir(parents=True)
    target.write_text("not json\n", encoding="utf-8")
    with pytest.raises(ValueError, match="malformed"):
        load_recent_context_changes("data/history/context", "2026-08-26T12:00:00.000Z")

    encoded = json.dumps(_journal_event(), separators=(",", ":"))
    target.write_text(f"{encoded}\n{encoded}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        load_recent_context_changes("data/history/context", "2026-08-26T12:00:00.000Z")

    invalid = _journal_event()
    invalid["changeType"] = "dns-a-changed"
    invalid["changedFields"] = ["a"]
    target.write_text(json.dumps(invalid) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="invalid change semantics"):
        load_recent_context_changes("data/history/context", "2026-08-26T12:00:00.000Z")


def test_public_journal_reader_rejects_hash_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    event = _journal_event()
    event["currentHash"] = "f" * 64
    target = tmp_path / "data/history/context/2026-08-26/events.ndjson"
    target.parent.mkdir(parents=True)
    target.write_text(json.dumps(event) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="hash mismatch"):
        load_recent_context_changes("data/history/context", "2026-08-26T12:00:00.000Z")


def test_state_failure_rolls_back_same_run_journal_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    now = datetime(2026, 8, 26, 12, tzinfo=UTC)
    observed_at = "2026-08-26T12:00:00.000Z"
    domain = "login[.]example"
    signal_id = stable_id(domain)
    context_path = tmp_path / "data/enrichment/domain-context.json"
    context_path.parent.mkdir(parents=True)
    current_dns = _dns(ns=["ns2[.]example"], observedAt=observed_at)
    context_path.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "dataset": "domain-context",
                "generatedAt": observed_at,
                "cursor": 0,
                "latestRun": None,
                "records": [
                    {
                        "signalId": signal_id,
                        "domain": domain,
                        "observedAt": observed_at,
                        "dns": {key: value for key, value in current_dns.items() if key != "observedAt"},
                        "registration": None,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    state_path = tmp_path / "data/enrichment/passive-context.json"
    passive_context.write_state(
        {
            "schemaVersion": 1,
            "dataset": "passive-context-state",
            "generatedAt": observed_at,
            "cursor": 0,
            "baselines": [
                {
                    "signalId": signal_id,
                    "domain": domain,
                    "observedAt": observed_at,
                    "components": {"dns": _dns(ns=["ns1[.]example"], observedAt=observed_at)},
                }
            ],
            "ripeCache": [],
            "latestRun": None,
        }
    )
    original_state = state_path.read_bytes()
    journal_target = tmp_path / "data/history/context/2026-08-26/events.ndjson"
    journal_target.parent.mkdir(parents=True)
    journal_target.write_text(json.dumps(_journal_event("other[.]example")) + "\n", encoding="utf-8")
    original_journal = journal_target.read_bytes()
    monkeypatch.setattr(
        passive_context,
        "write_state",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("injected state failure")),
    )

    with pytest.raises(OSError, match="injected state failure"):
        passive_context.refresh(now=now)

    assert state_path.read_bytes() == original_state
    assert journal_target.read_bytes() == original_journal


@pytest.mark.parametrize(
    ("cname", "expected_events"),
    [(["target[.]example"], 1), ([], 0)],
)
def test_first_complete_dns_baseline_records_resolution_lifecycle_only_when_resolving(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    cname: list[str],
    expected_events: int,
) -> None:
    monkeypatch.chdir(tmp_path)
    now = datetime(2026, 8, 26, 12, tzinfo=UTC)
    observed_at = "2026-08-26T12:00:00.000Z"
    domain = "login[.]example"
    signal_id = stable_id(domain)
    context_path = tmp_path / "data/enrichment/domain-context.json"
    context_path.parent.mkdir(parents=True)
    current_dns = _dns(cname=cname, observedAt=observed_at)
    context_path.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "dataset": "domain-context",
                "generatedAt": observed_at,
                "cursor": 0,
                "latestRun": None,
                "records": [
                    {
                        "signalId": signal_id,
                        "domain": domain,
                        "observedAt": observed_at,
                        "dns": {key: value for key, value in current_dns.items() if key != "observedAt"},
                        "registration": None,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    result = passive_context.refresh(
        lambda *_args: pytest.fail("a CNAME-only baseline must not query RIPEstat"),
        now=now,
    )

    assert result["eventsWritten"] == expected_events
    journal = tmp_path / "data/history/context/2026-08-26/events.ndjson"
    if expected_events:
        event = json.loads(journal.read_text(encoding="utf-8"))
        assert event["changeType"] == "first-resolving"
        assert event["changedFields"] == ["cname"]
        assert event["before"] == {}
    else:
        assert not journal.exists()


def _directory_symlink_or_skip(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=True)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"directory symlinks are unavailable: {error}")


def _file_symlink_or_skip(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"file symlinks are unavailable: {error}")


def test_passive_context_rejects_symlinked_repository_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_root = tmp_path / "real-root"
    real_root.mkdir()
    linked_root = tmp_path / "linked-root"
    _directory_symlink_or_skip(linked_root, real_root)
    monkeypatch.setattr(passive_context.os, "getcwd", lambda: str(linked_root))

    with pytest.raises(ValueError, match="repository root"):
        passive_context._bounded_path(
            "data/enrichment/passive-context.json",
            expected="data/enrichment/passive-context.json",
        )


def test_passive_context_rejects_symlinked_journal_partition_and_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    journal_root = tmp_path / "data/history/context"
    journal_root.mkdir(parents=True)
    external_directory = tmp_path / "outside-date"
    external_directory.mkdir()
    partition = journal_root / "2026-08-26"
    _directory_symlink_or_skip(partition, external_directory)

    with pytest.raises(ValueError, match="symlinked path component"):
        passive_context._journal_path("data/history/context", datetime(2026, 8, 26).date())
    with pytest.raises(ValueError, match="symlinked partition"):
        passive_context._prune_journal(
            "data/history/context",
            today=datetime(2026, 10, 26).date(),
            retention_days=30,
        )

    partition.unlink()
    partition.mkdir()
    external_file = tmp_path / "outside-events.ndjson"
    external_file.write_text("do not touch\n", encoding="utf-8")
    _file_symlink_or_skip(partition / "events.ndjson", external_file)
    with pytest.raises(ValueError, match="symlinked path component"):
        passive_context._journal_path("data/history/context", datetime(2026, 8, 26).date())
    assert external_file.read_text(encoding="utf-8") == "do not touch\n"
