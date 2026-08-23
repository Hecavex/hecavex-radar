import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pytest import MonkeyPatch

from hecavex_radar.brands import load_brand_registry
from hecavex_radar.models import RadarSignal, RawSignal, SourceResult
from hecavex_radar.safety import stable_id
from hecavex_radar.sync import (
    _load_existing_snapshot,
    _preserve_generated_at_if_unchanged,
    _represented_records,
    _retain_only_unrefreshed_sources,
    _scope_raw_signal,
    _snapshot_content_unchanged,
    _validate_snapshot_size,
    synchronize,
)


def _write_snapshot(path: Path, count: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {"schemaVersion": 1, "dataset": "live", "generatedAt": "2026-08-21T00:00:00Z", "signals": [{}] * count}
        ),
        encoding="utf-8",
    )


def test_rejects_an_empty_or_sharply_reduced_snapshot(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    target = tmp_path / "radar.json"
    _write_snapshot(target, 100)
    monkeypatch.setenv("RADAR_MIN_SIGNALS", "1")
    monkeypatch.setenv("RADAR_MIN_RETAINED_PERCENT", "25")
    with pytest.raises(RuntimeError, match="at least 25"):
        _validate_snapshot_size(24, target)
    _validate_snapshot_size(25, target)


def test_allows_an_explicit_intentional_snapshot_reset(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    target = tmp_path / "radar.json"
    _write_snapshot(target, 100)
    monkeypatch.setenv("RADAR_ALLOW_SMALL_SNAPSHOT", "true")
    _validate_snapshot_size(0, target)


def test_allows_an_empty_snapshot_after_previous_rows_age_out(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    target = tmp_path / "radar.json"
    target.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "dataset": "live",
                "signals": [{"lastSeen": "2026-07-01T00:00:00.000Z"}],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("RADAR_MIN_SIGNALS", "0")
    monkeypatch.setenv("RADAR_MIN_RETAINED_PERCENT", "25")
    monkeypatch.setenv("RADAR_SNAPSHOT_GUARD_DAYS", "30")

    _validate_snapshot_size(0, target, datetime(2026, 8, 21, tzinfo=UTC))


def test_unchanged_snapshot_ignores_only_publication_timestamps(tmp_path: Path) -> None:
    target = tmp_path / "radar.json"
    source: dict[str, object] = {
        "name": "URLScan",
        "homepage": "https://urlscan.io/",
        "fetchedAt": "2026-08-21T09:00:00.000Z",
        "records": 0,
        "state": "healthy",
        "note": "Passive results",
    }
    original: dict[str, object] = {
        "schemaVersion": 1,
        "dataset": "live",
        "generatedAt": "2026-08-21T09:00:00.000Z",
        "lastSuccessfulSyncAt": "2026-08-21T09:00:00.000Z",
        "signals": [],
        "sources": [source],
    }
    target.write_text(json.dumps(original), encoding="utf-8")
    timestamp_source = {**source, "fetchedAt": "2026-08-21T10:00:00.000Z"}
    timestamp_only: dict[str, object] = {
        **original,
        "generatedAt": "2026-08-21T10:00:00.000Z",
        "lastSuccessfulSyncAt": "2026-08-21T10:00:00.000Z",
        "sources": [timestamp_source],
    }

    assert _snapshot_content_unchanged(target, timestamp_only)
    assert not _snapshot_content_unchanged(
        target,
        {**timestamp_only, "sources": [{**timestamp_source, "state": "partial"}]},
    )


def test_unchanged_snapshot_advances_heartbeat_but_preserves_data_timestamp(tmp_path: Path) -> None:
    target = tmp_path / "radar.json"
    original: dict[str, object] = {
        "schemaVersion": 1,
        "dataset": "live",
        "generatedAt": "2026-08-21T09:00:00.000Z",
        "lastSuccessfulSyncAt": "2026-08-21T09:00:00.000Z",
        "signals": [],
        "sources": [],
    }
    target.write_text(json.dumps(original), encoding="utf-8")
    candidate: dict[str, object] = {
        **original,
        "generatedAt": "2026-08-21T10:00:00.000Z",
        "lastSuccessfulSyncAt": "2026-08-21T10:00:00.000Z",
    }

    assert _preserve_generated_at_if_unchanged(target, candidate)
    assert candidate["generatedAt"] == "2026-08-21T09:00:00.000Z"
    assert candidate["lastSuccessfulSyncAt"] == "2026-08-21T10:00:00.000Z"


def test_changed_snapshot_advances_data_and_heartbeat_together(tmp_path: Path) -> None:
    target = tmp_path / "radar.json"
    original: dict[str, object] = {
        "schemaVersion": 1,
        "dataset": "live",
        "generatedAt": "2026-08-21T09:00:00.000Z",
        "lastSuccessfulSyncAt": "2026-08-21T09:00:00.000Z",
        "signals": [],
        "sources": [],
    }
    target.write_text(json.dumps(original), encoding="utf-8")
    candidate: dict[str, object] = {
        **original,
        "generatedAt": "2026-08-21T10:00:00.000Z",
        "lastSuccessfulSyncAt": "2026-08-21T10:00:00.000Z",
        "sources": [{"name": "CertStream", "state": "partial"}],
    }

    assert not _preserve_generated_at_if_unchanged(target, candidate)
    assert candidate["generatedAt"] == candidate["lastSuccessfulSyncAt"]


def test_requires_a_hecavex_url_when_integration_is_enabled(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv("HECAVEX_ENABLED", "true")
    monkeypatch.delenv("HECAVEX_FEED_URL", raising=False)
    with pytest.raises(RuntimeError, match="HECAVEX_FEED_URL"):
        synchronize()


def test_failed_sync_does_not_advance_the_existing_heartbeat(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    registry = load_brand_registry()
    target = tmp_path / "public" / "data" / "radar.json"
    target.parent.mkdir(parents=True)
    original = {
        "schemaVersion": 1,
        "dataset": "live",
        "generatedAt": "2026-08-21T09:00:00.000Z",
        "lastSuccessfulSyncAt": "2026-08-21T10:00:00.000Z",
        "signals": [],
        "sources": [],
    }
    target.write_text(json.dumps(original), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CERTSTREAM_ARCHIVE_ENABLED", "false")
    monkeypatch.setenv("URLSCAN_ARCHIVE_ENABLED", "false")
    monkeypatch.setenv("HECAVEX_ENABLED", "false")
    monkeypatch.setattr("hecavex_radar.sync.load_brand_registry", lambda: registry)

    with pytest.raises(RuntimeError, match="No source completed"):
        synchronize()

    assert json.loads(target.read_text(encoding="utf-8")) == original


def test_retains_only_recent_valid_defanged_signals(tmp_path: Path) -> None:
    target = tmp_path / "radar.json"
    valid = {
        "id": stable_id("secure-brand[.]example"),
        "url": "hxxps://secure-brand[.]example/login",
        "domain": "secure-brand[.]example",
        "firstSeen": "2026-08-20T09:00:00.000Z",
        "lastSeen": "2026-08-21T09:00:00.000Z",
        "sources": ["HECAVEX"],
        "status": "active",
        "brand": "Example",
        "country": None,
        "host": None,
        "screenshotUrl": None,
        "referenceUrl": None,
        "hashes": [],
        "confidence": 90,
    }
    stale = {**valid, "id": "b" * 20, "lastSeen": "2026-08-01T09:00:00.000Z"}
    unsafe = {**valid, "id": "c" * 20, "url": "https://secure-brand.example/login"}
    target.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "dataset": "live",
                "generatedAt": "2026-08-21T09:00:00.000Z",
                "signals": [valid, stale, unsafe],
                "sources": [
                    {
                        "name": "HECAVEX",
                        "fetchedAt": "2026-08-21T09:00:00.000Z",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    signals, source_fetches = _load_existing_snapshot(
        target,
        "2026-08-21T10:00:00.000Z",
        7,
    )

    assert signals == [{**valid, "hashes": []}]
    assert source_fetches == {"HECAVEX": "2026-08-21T09:00:00.000Z"}


def test_retention_rejects_noncanonical_timestamps_and_inconsistent_ids(tmp_path: Path) -> None:
    domain = "secure-swedbank-login[.]example"
    valid = {
        "id": stable_id(domain),
        "url": f"hxxps://{domain}/login",
        "domain": domain,
        "firstSeen": "2026-08-21T08:00:00.000Z",
        "lastSeen": "2026-08-21T09:00:00.000Z",
        "sources": ["HECAVEX"],
        "status": "suspected",
        "brand": "Swedbank",
        "country": None,
        "host": None,
        "screenshotUrl": None,
        "confidence": 90,
    }
    target = tmp_path / "radar.json"
    target.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "dataset": "live",
                "signals": [
                    {**valid, "id": "a" * 20},
                    {**valid, "lastSeen": "2026-08-21T09:00:00Z"},
                    {**valid, "lastSeen": "2026-08-21T10:06:00.000Z"},
                ],
                "sources": [],
            }
        ),
        encoding="utf-8",
    )

    signals, _ = _load_existing_snapshot(target, "2026-08-21T10:00:00.000Z", 7)

    assert signals == []


def test_retention_drops_sources_that_refreshed_successfully() -> None:
    signal: RadarSignal = {
        "id": "a" * 20,
        "url": "hxxps://secure-brand[.]example/login",
        "domain": "secure-brand[.]example",
        "firstSeen": "2026-08-20T09:00:00.000Z",
        "lastSeen": "2026-08-21T09:00:00.000Z",
        "sources": ["CertStream", "HECAVEX"],
        "status": "active",
        "brand": "Example",
        "country": None,
        "host": None,
        "screenshotUrl": None,
        "confidence": 90,
    }

    carried = _retain_only_unrefreshed_sources([signal], {"CertStream"})

    assert len(carried) == 1
    assert carried[0]["sources"] == ["HECAVEX"]
    assert _retain_only_unrefreshed_sources([signal], {"CertStream", "HECAVEX"}) == []


def test_retention_drops_removed_source_names() -> None:
    signal: RadarSignal = {
        "id": "b" * 20,
        "url": "hxxps://secure-swedbank[.]example/login",
        "domain": "secure-swedbank[.]example",
        "firstSeen": "2026-08-20T09:00:00.000Z",
        "lastSeen": "2026-08-21T09:00:00.000Z",
        "sources": ["Removed source"],
        "status": "suspected",
        "brand": "Swedbank",
        "country": None,
        "host": None,
        "screenshotUrl": None,
        "confidence": 80,
    }
    assert _retain_only_unrefreshed_sources([signal], set()) == []


def test_retention_drops_a_known_source_that_is_intentionally_disabled() -> None:
    signal: RadarSignal = {
        "id": "d" * 20,
        "url": "hxxps://secure-swedbank[.]example/login",
        "domain": "secure-swedbank[.]example",
        "firstSeen": "2026-08-20T09:00:00.000Z",
        "lastSeen": "2026-08-21T09:00:00.000Z",
        "sources": ["HECAVEX"],
        "status": "suspected",
        "brand": "Swedbank",
        "country": None,
        "host": None,
        "screenshotUrl": None,
        "confidence": 80,
    }

    assert _retain_only_unrefreshed_sources([signal], set(), {"CertStream", "URLScan"}) == []


def test_source_record_counts_follow_final_merged_rows() -> None:
    signal: RadarSignal = {
        "id": "c" * 20,
        "url": "hxxps://secure-swedbank[.]example/login",
        "domain": "secure-swedbank[.]example",
        "firstSeen": "2026-08-21T08:00:00.000Z",
        "lastSeen": "2026-08-21T09:00:00.000Z",
        "sources": ["CertStream", "URLScan"],
        "status": "suspected",
        "brand": "Swedbank",
        "country": None,
        "host": None,
        "screenshotUrl": None,
        "confidence": 90,
    }

    assert _represented_records([signal], "CertStream") == 1
    assert _represented_records([signal], "URLScan") == 1
    assert _represented_records([signal], "HECAVEX") == 0


def test_scope_rejects_a_declared_brand_that_conflicts_with_the_domain() -> None:
    registry = load_brand_registry()
    conflicting = RawSignal(
        url="https://secure-swedbank-login.example",
        source="HECAVEX",
        brand="Revolut",
    )
    matching = RawSignal(
        url="https://secure-swedbank-login.example",
        source="HECAVEX",
        brand="Swedbank",
    )
    ambiguous = RawSignal(
        url="https://swedbank-revolut-login.com",
        source="URLScan",
        brand="Swedbank",
    )

    assert _scope_raw_signal(conflicting, registry) is None
    assert _scope_raw_signal(matching, registry) == matching
    assert _scope_raw_signal(ambiguous, registry) is None


def test_sync_publishes_certstream_candidate_without_urlscan_evidence(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    registry = load_brand_registry()
    certstream = SourceResult(
        source={
            "name": "CertStream",
            "homepage": "https://certstream.dev/",
            "fetchedAt": "2026-08-21T10:00:00.000Z",
            "records": 1,
            "state": "healthy",
            "note": "Test CertStream archive",
        },
        signals=[
            RawSignal(
                url="secure-swedbank-login.example",
                first_seen="2026-08-21T09:55:00.000Z",
                last_seen="2026-08-21T09:55:00.000Z",
                source="CertStream",
                status="suspected",
                brand="Swedbank",
                confidence=100,
            )
        ],
    )
    empty_urlscan = SourceResult(
        source={
            "name": "URLScan",
            "homepage": "https://urlscan.io/",
            "fetchedAt": "2026-08-21T10:00:00.000Z",
            "records": 0,
            "state": "healthy",
            "note": "No matching public reports",
        },
        signals=[],
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("RADAR_OUTPUT", "public/data/radar.json")
    monkeypatch.setenv("RADAR_ALLOW_SMALL_SNAPSHOT", "true")
    monkeypatch.setenv("RADAR_RETAIN_EXISTING_SIGNALS", "false")
    monkeypatch.setenv("HECAVEX_ENABLED", "false")
    monkeypatch.setattr("hecavex_radar.sync.load_brand_registry", lambda: registry)
    monkeypatch.setattr("hecavex_radar.sync.load_certstream", lambda *_args: certstream)
    monkeypatch.setattr("hecavex_radar.sync.load_urlscan", lambda *_args: empty_urlscan)

    target = synchronize()
    snapshot = json.loads(target.read_text(encoding="utf-8"))

    assert len(snapshot["signals"]) == 1
    assert snapshot["signals"][0] == {
        "id": stable_id("secure-swedbank-login[.]example"),
        "url": "hxxps://secure-swedbank-login[.]example",
        "domain": "secure-swedbank-login[.]example",
        "firstSeen": "2026-08-21T09:55:00.000Z",
        "lastSeen": "2026-08-21T09:55:00.000Z",
        "sources": ["CertStream"],
        "status": "suspected",
        "brand": "Swedbank",
        "country": None,
        "host": None,
        "screenshotUrl": None,
        "referenceUrl": None,
        "hashes": [],
        "confidence": 100,
    }
    assert snapshot["sources"][0]["records"] == 1
    assert snapshot["sources"][1]["records"] == 0
