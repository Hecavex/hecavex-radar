from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import cast

from jsonschema import Draft202012Validator

from hecavex_radar import passive_context
from hecavex_radar.brands import load_brand_registry
from hecavex_radar.models import RadarSignal, RawDomainIntelligence
from hecavex_radar.public_schemas import MISP_EVENT_SCHEMA, MISP_MANIFEST_SCHEMA, MISP_WARNINGLIST_SCHEMA
from hecavex_radar.safety import stable_id
from hecavex_radar.sbom import build_sbom, write_sbom
from hecavex_radar.sharing import build_misp_feed, build_official_domain_warninglist
from hecavex_radar.signal_detail import build_signal_details, load_recent_context_changes

NOW = "2026-08-26T12:00:00.000Z"


def test_misp_is_reviewed_only_and_never_authorizes_detection_use() -> None:
    domain = "support-vinted[.]ph"
    reviewed = {
        "signalId": stable_id(domain),
        "domain": domain,
        "brand": "Vinted",
        "reviewState": "confirmed-suspicious",
        "dispositionReason": "brand-impersonation",
        "evidenceCodes": ["analyst-reviewed"],
        "ltRelevance": "lithuanian-brand-relevance",
        "reviewedAt": "2026-08-25T10:00:00.000Z",
        "modifiedAt": "2026-08-25T10:01:00.000Z",
        "expiresAt": "2026-09-25T10:00:00.000Z",
        "analystConfidence": 90,
        "revoked": False,
    }
    suspected = {**reviewed, "signalId": "f" * 20, "domain": "not-reviewed[.]example", "reviewState": "inconclusive"}

    manifest, event = build_misp_feed([reviewed, suspected], NOW)
    Draft202012Validator(MISP_MANIFEST_SCHEMA).validate(manifest)
    Draft202012Validator(MISP_EVENT_SCHEMA).validate(event)
    attributes = cast(list[dict[str, object]], cast(dict[str, object], event["Event"])["Attribute"])

    assert [row["value"] for row in attributes] == ["support-vinted.ph"]
    assert attributes[0]["to_ids"] is False

    warninglist = build_official_domain_warninglist(load_brand_registry())
    Draft202012Validator(MISP_WARNINGLIST_SCHEMA).validate(warninglist)
    assert warninglist["type"] == "hostname"
    assert "domain|ip" in cast(list[str], warninglist["matching_attributes"])


def test_context_journal_projection_is_bounded_and_urlscan_is_permission_gated(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    domain = "support-vinted[.]ph"
    signal_id = stable_id(domain)
    root = tmp_path / "data/history/context/2026-08-26"
    root.mkdir(parents=True)
    rows = [
        passive_context._event(
            signal_id,
            domain,
            "2026-08-26T11:00:00.000Z",
            "dns",
            "dns-a-changed",
            ["a"],
            "2026-08-26T10:59:00.000Z",
            "https://cloudflare-dns.com/dns-query",
            {"a": ["192[.]0[.]2[.]1"]},
            {"a": ["192[.]0[.]2[.]2"]},
        ),
        passive_context._event(
            signal_id,
            domain,
            "2026-08-26T11:01:00.000Z",
            "urlscan",
            "urlscan-title-changed",
            ["pageTitle"],
            "2026-08-26T11:00:00.000Z",
            "https://urlscan.io/result/00000000-0000-0000-0000-000000000001/",
            {"pageTitle": "Old"},
            {
                "pageTitle": "New",
                "primaryHtmlSha256": ["d" * 64],
                "certificateFingerprintSha256": "e" * 64,
            },
        ),
    ]
    (root / "events.ndjson").write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")

    default = load_recent_context_changes("data/history/context", NOW)
    assert [row["component"] for row in default[signal_id]] == ["dns"]
    permitted = load_recent_context_changes(
        "data/history/context",
        NOW,
        allow_urlscan_redistribution=True,
    )
    assert {row["component"] for row in permitted[signal_id]} == {"dns", "urlscan"}

    signal = cast(
        RadarSignal,
        {
            "id": signal_id,
            "url": "hxxps://support-vinted[.]ph",
            "domain": domain,
            "firstSeen": NOW,
            "lastSeen": NOW,
            "sources": ["URLScan"],
            "status": "suspected",
            "brand": "Vinted",
            "country": None,
            "host": None,
            "screenshotUrl": None,
            "referenceUrl": "https://urlscan.io/result/00000000-0000-0000-0000-000000000001/",
            "hashes": ["c" * 64],
            "matchScore": 100,
            "evidenceTier": "corroborated",
            "reviewState": "unreviewed",
            "ltRelevance": "lithuanian-brand-relevance",
            "confidence": 100,
        },
    )
    detail = build_signal_details([signal], [], NOW, context_changes=permitted)[signal_id]
    assert [row["changeType"] for row in detail["contextChanges"]] == [
        "urlscan-title-changed",
        "dns-a-changed",
    ]
    assert detail["contextChanges"][0]["source"]["observedAt"] == "2026-08-26T11:00:00.000Z"
    assert detail["contextChanges"][0]["evidence"]["primaryHtmlSha256"] == ["d" * 64]
    assert detail["contextChanges"][0]["evidence"]["certificateSha256"] == "e" * 64
    assert detail["contextChanges"][1]["evidence"]["primaryHtmlSha256"] == []


def test_passive_context_does_not_persist_urlscan_without_redistribution_permission(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    domain = "support-vinted[.]ph"
    signal_id = stable_id(domain)
    now = "2026-08-26T12:00:00.000Z"
    context_path = tmp_path / "data/enrichment/domain-context.json"
    context_path.parent.mkdir(parents=True)
    context_path.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "dataset": "domain-context",
                "generatedAt": now,
                "cursor": 0,
                "latestRun": None,
                "records": [
                    {
                        "signalId": signal_id,
                        "domain": domain,
                        "observedAt": now,
                        "dns": {
                            "a": [],
                            "aaaa": [],
                            "cname": [],
                            "ns": [],
                            "mx": [],
                            "minimumTtl": None,
                            "queriesCompleted": 5,
                        },
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
            "generatedAt": now,
            "cursor": 0,
            "baselines": [
                {
                    "signalId": signal_id,
                    "domain": domain,
                    "observedAt": now,
                    "components": {"urlscan": {"pageTitle": "previous"}},
                }
            ],
            "ripeCache": [],
            "latestRun": None,
        },
        state_path,
    )
    calls = 0

    def urlscan_records(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        return [
            RawDomainIntelligence(
                domain="support-vinted.ph",
                source="URLScan",
                observed_at=now,
                page={"title": "Vinted login", "httpStatus": 200},
            )
        ]

    monkeypatch.setattr(passive_context, "read_recent_urlscan_intelligence", urlscan_records)
    monkeypatch.delenv("URLSCAN_DERIVED_REDISTRIBUTION_CONFIRMED", raising=False)
    passive_context.refresh(
        lambda *_args: (_ for _ in ()).throw(AssertionError("network must not be used")),
        now=datetime.fromisoformat(now.replace("Z", "+00:00")),
    )
    disabled_state = passive_context.read_state()
    assert calls == 0
    assert "urlscan" not in disabled_state["baselines"][0]["components"]
    assert not (tmp_path / "data/history/context").exists()

    monkeypatch.setenv("URLSCAN_DERIVED_REDISTRIBUTION_CONFIRMED", "true")
    passive_context.refresh(
        lambda *_args: (_ for _ in ()).throw(AssertionError("network must not be used")),
        now=datetime.fromisoformat(now.replace("Z", "+00:00")),
    )
    enabled_state = passive_context.read_state()
    assert calls == 1
    assert "urlscan" in enabled_state["baselines"][0]["components"]


def test_weekly_sbom_is_spdx_and_covers_both_release_files(tmp_path: Path, monkeypatch) -> None:
    repository = Path(__file__).resolve().parents[1]
    monkeypatch.chdir(tmp_path)
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="radar"\nversion="1.2.3"\nlicense="Apache-2.0"\n',
        encoding="utf-8",
    )
    lock = tmp_path / "requirements/automation-runtime-py312.lock"
    lock.parent.mkdir(parents=True)
    lock.write_text("idna==3.19 --hash=sha256:" + "a" * 64 + "\n", encoding="utf-8")
    assets = tmp_path / "_release/assets"
    assets.mkdir(parents=True)
    archive = assets / "radar-data-2026-W35.tar.gz"
    archive.write_bytes(b"archive")
    manifest = assets / "radar-data-2026-W35.manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "tag": "radar-data-2026-W35",
                "sourceCommit": "a" * 40,
                "snapshotGeneratedAt": NOW,
            }
        ),
        encoding="utf-8",
    )
    sbom = build_sbom(
        tag="radar-data-2026-W35",
        repository="Hecavex/radar.hecavex.com",
        commit="a" * 40,
        release_manifest=manifest,
        files=[archive, manifest],
        package_path=repository / "package.json",
        pnpm_lock=repository / "pnpm-lock.yaml",
    )
    output = write_sbom(sbom, assets / "radar-data-2026-W35.spdx.json")
    decoded = json.loads(output.read_text(encoding="utf-8"))

    assert decoded["spdxVersion"] == "SPDX-2.3"
    assert {row["fileName"] for row in decoded["files"]} == {
        "./radar-data-2026-W35.tar.gz",
        "./radar-data-2026-W35.manifest.json",
    }


def test_reporting_tool_is_non_sending_and_has_no_free_form_case_fields() -> None:
    repository = Path(__file__).resolve().parents[1]
    html = (repository / "public/reporting/index.html").read_text(encoding="utf-8")
    script = (repository / "public/reporting/app.js").read_text(encoding="utf-8")

    assert "connect-src 'none'" in html and "form-action 'none'" in html
    assert all(token not in script for token in ("fetch(", "XMLHttpRequest", "WebSocket", "sendBeacon", "localStorage"))
    assert all(token not in html for token in ('id="notes"', 'id="indicator"', 'id="case-reference"'))
    assert "confirmed-suspicious" in script and "assessment?.revoked !== false" in script
    assert "originalFilenamesIncluded: false" in script and ".name" not in script
    assert "innerHTML" not in script
