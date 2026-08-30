from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from hecavex_radar.health_sentinel import evaluate, markdown

NOW = datetime(2026, 8, 26, 12, 0, tzinfo=UTC)


def _timestamp(value: datetime) -> str:
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _write(repository: Path, relative: str, value: object) -> None:
    target = repository / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(value), encoding="utf-8")


def _healthy_repository(repository: Path) -> None:
    current = _timestamp(NOW)
    _write(
        repository,
        "public/data/radar.json",
        {"schemaVersion": 2, "dataset": "live", "lastSuccessfulSyncAt": current, "signals": [], "sources": []},
    )
    _write(
        repository,
        "public/data/collection-health.json",
        {
            "lastSuccessAt": current,
            "staleAfterSeconds": 2700,
            "latestAttempt": {"endedAt": current, "outcome": "healthy-empty"},
        },
    )
    _write(
        repository,
        "data/urlscan/hunt-state.json",
        {
            "configured": True,
            "lastRunAt": current,
            "lastOutcome": "completed",
            "lastSuccessAt": current,
            "consecutiveFailures": 0,
            "degradedSince": None,
        },
    )
    _write(
        repository,
        "data/ct-search/state.json",
        {
            "latestRun": {"endedAt": current, "outcome": "completed", "failureCodes": []},
            "providerHealth": {
                "lastSuccessAt": current,
                "consecutiveFailures": 0,
                "degradedSince": None,
                "nextAttemptAt": None,
            },
        },
    )
    _write(
        repository,
        "data/enrichment/domain-context.json",
        {"latestRun": {"endedAt": current, "outcome": "completed"}},
    )
    _write(
        repository,
        "data/enrichment/passive-context.json",
        {"latestRun": {"endedAt": current, "outcome": "completed"}},
    )
    _write(
        repository,
        "public/data/pipeline-health.json",
        {
            "generatedAt": current,
            "windows": [{"hours": 24, "collection": {"scheduledSlots": 96, "recordedAttempts": 96}}],
        },
    )


def test_healthy_repository_has_no_findings(tmp_path: Path) -> None:
    _healthy_repository(tmp_path)

    report = evaluate(tmp_path, now=NOW)

    assert report["healthy"] is True
    assert report["findings"] == []


def test_persistent_failures_use_only_controlled_aggregate_codes(tmp_path: Path) -> None:
    _healthy_repository(tmp_path)
    old = _timestamp(NOW - timedelta(hours=8))
    _write(
        tmp_path,
        "data/ct-search/state.json",
        {
            "latestRun": {
                "endedAt": old,
                "outcome": "failed",
                "failureCodes": ["provider-timeout"],
            }
        },
    )
    _write(
        tmp_path,
        "data/urlscan/hunt-state.json",
        {"configured": True, "lastRunAt": old, "lastOutcome": "failed"},
    )

    report = evaluate(tmp_path, now=NOW)
    codes = {finding["code"] for finding in report["findings"]}
    body = markdown(report)

    assert report["healthy"] is False
    assert {"ct-search-degraded", "ct-search-stale", "urlscan-failed", "urlscan-stale"} <= codes
    assert "provider-timeout" in body
    assert "private" not in body.lower()


def test_repeated_fresh_ct_failures_are_not_hidden_by_latest_attempt_time(tmp_path: Path) -> None:
    _healthy_repository(tmp_path)
    fresh = _timestamp(NOW - timedelta(minutes=5))
    _write(
        tmp_path,
        "data/ct-search/state.json",
        {
            "latestRun": {
                "endedAt": fresh,
                "outcome": "failed",
                "failureCodes": ["provider-http"],
            },
            "providerHealth": {
                "lastSuccessAt": _timestamp(NOW - timedelta(hours=2)),
                "consecutiveFailures": 2,
                "degradedSince": _timestamp(NOW - timedelta(minutes=65)),
                "nextAttemptAt": _timestamp(NOW + timedelta(minutes=5)),
            },
        },
    )

    report = evaluate(tmp_path, now=NOW)
    finding = next(item for item in report["findings"] if item["code"] == "ct-search-degraded")

    assert "2 consecutive provider failures" in finding["observed"]
    assert not any(item["code"] == "ct-search-stale" for item in report["findings"])


def test_repeated_fresh_urlscan_failures_are_not_hidden_by_latest_attempt_time(tmp_path: Path) -> None:
    _healthy_repository(tmp_path)
    fresh = _timestamp(NOW - timedelta(minutes=5))
    _write(
        tmp_path,
        "data/urlscan/hunt-state.json",
        {
            "configured": True,
            "lastRunAt": fresh,
            "lastOutcome": "failed",
            "lastSuccessAt": _timestamp(NOW - timedelta(hours=4)),
            "consecutiveFailures": 2,
            "degradedSince": _timestamp(NOW - timedelta(hours=2)),
        },
    )

    report = evaluate(tmp_path, now=NOW)
    finding = next(item for item in report["findings"] if item["code"] == "urlscan-failed")

    assert "2 consecutive failed runs" in finding["observed"]
    assert not any(item["code"] == "urlscan-stale" for item in report["findings"])


def test_fresh_failures_use_last_success_for_staleness(tmp_path: Path) -> None:
    _healthy_repository(tmp_path)
    fresh = _timestamp(NOW - timedelta(minutes=5))
    _write(
        tmp_path,
        "data/ct-search/state.json",
        {
            "latestRun": {"endedAt": fresh, "outcome": "failed", "failureCodes": ["provider-http"]},
            "providerHealth": {
                "lastSuccessAt": _timestamp(NOW - timedelta(hours=4)),
                "consecutiveFailures": 1,
                "degradedSince": _timestamp(NOW - timedelta(hours=2)),
                "nextAttemptAt": None,
            },
        },
    )

    report = evaluate(tmp_path, now=NOW)
    codes = {finding["code"] for finding in report["findings"]}

    assert {"ct-search-degraded", "ct-search-stale"} <= codes


def test_fresh_ct_backlog_without_provider_failures_is_not_provider_degradation(tmp_path: Path) -> None:
    _healthy_repository(tmp_path)
    current = _timestamp(NOW)
    _write(
        tmp_path,
        "data/ct-search/state.json",
        {
            "latestRun": {"endedAt": current, "outcome": "partial", "failureCodes": []},
            "providerHealth": {
                "lastSuccessAt": current,
                "consecutiveFailures": 0,
                "degradedSince": None,
                "nextAttemptAt": None,
            },
        },
    )

    report = evaluate(tmp_path, now=NOW)

    assert not any(item["code"] == "ct-search-degraded" for item in report["findings"])


def test_incompatible_snapshot_contract_is_reported_without_raising(tmp_path: Path) -> None:
    _healthy_repository(tmp_path)
    _write(
        tmp_path,
        "public/data/radar.json",
        {"schemaVersion": 3, "dataset": "live", "lastSuccessfulSyncAt": _timestamp(NOW), "signals": [], "sources": []},
    )

    report = evaluate(tmp_path, now=NOW)

    assert any(finding["code"] == "snapshot-contract-incompatible" for finding in report["findings"])


def test_urlscan_stalled_backlog_is_reported_without_query_terms(tmp_path: Path) -> None:
    _healthy_repository(tmp_path)
    current = _timestamp(NOW)
    old = _timestamp(NOW - timedelta(hours=25))
    _write(
        tmp_path,
        "data/urlscan/hunt-state.json",
        {
            "configured": True,
            "lastRunAt": current,
            "lastOutcome": "completed",
            "checkpointCoverage": {
                "queries": 4,
                "complete": 2,
                "partial": 2,
                "backlog": 1,
                "oldestBacklogProgressAt": old,
            },
        },
    )

    report = evaluate(tmp_path, now=NOW)
    finding = next(item for item in report["findings"] if item["code"] == "urlscan-backlog-stalled")

    assert finding["source"] == "URLScan"
    assert finding["observed"] == "1 aggregate backlog queries; oldest progress 25 hours ago"
    assert "query" not in json.dumps(finding).lower().replace("backlog queries", "")


def test_far_future_timestamp_cannot_suppress_stale_detection(tmp_path: Path) -> None:
    _healthy_repository(tmp_path)
    future = _timestamp(NOW + timedelta(days=365))
    snapshot = json.loads((tmp_path / "public/data/radar.json").read_text(encoding="utf-8"))
    snapshot["lastSuccessfulSyncAt"] = future
    _write(tmp_path, "public/data/radar.json", snapshot)

    report = evaluate(tmp_path, now=NOW)

    assert any(finding["code"] == "snapshot-timestamp-invalid" for finding in report["findings"])


def test_stale_pipeline_health_and_passive_context_are_reported(tmp_path: Path) -> None:
    _healthy_repository(tmp_path)
    old = _timestamp(NOW - timedelta(hours=13))
    _write(
        tmp_path,
        "public/data/pipeline-health.json",
        {"generatedAt": old, "windows": []},
    )
    _write(
        tmp_path,
        "data/enrichment/passive-context.json",
        {"latestRun": {"endedAt": old, "outcome": "failed"}},
    )

    report = evaluate(tmp_path, now=NOW)
    codes = {finding["code"] for finding in report["findings"]}

    assert {"pipeline-health-stale", "passive-context-stale", "passive-context-failed"} <= codes
