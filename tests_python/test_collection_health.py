import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pytest import MonkeyPatch

import hecavex_radar.collect_certstream as collector_module
from hecavex_radar.collect_certstream import _collection_outcome
from hecavex_radar.collection_health import (
    CollectionMetrics,
    begin_attempt,
    complete_attempt,
    finalize_workflow,
    is_collection_health,
    read_collection_health,
)


def _at(hour: int, minute: int, second: int = 0) -> datetime:
    return datetime(2026, 8, 21, hour, minute, second, tzinfo=UTC)


def test_scheduled_attempt_records_actual_delay_and_stays_bounded(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CERTSTREAM_DURATION_SECONDS", "240")
    path = Path("public/data/collection-health.json")

    begin_attempt(path, now=_at(19, 13, 30), trigger_value="schedule")
    running = read_collection_health(path, allow_running=True)

    assert running is not None
    assert running["latestAttempt"]["startedAt"] == "2026-08-21T19:13:30.000Z"
    assert running["latestAttempt"]["scheduledFor"] == "2026-08-21T19:02:00.000Z"
    assert running["latestAttempt"]["scheduleStatus"] == "delayed"
    assert running["latestAttempt"]["delaySeconds"] == 690
    assert running["latestAttempt"]["expectedListeningSeconds"] == 240
    assert path.stat().st_size < 32 * 1024
    assert not path.with_name("collection-health.json.tmp").exists()


def test_healthy_empty_attempt_records_counts_and_last_success(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    path = Path("public/data/collection-health.json")
    begin_attempt(path, now=_at(19, 2), trigger_value="schedule")
    metrics = CollectionMetrics(
        collector_started_at=_at(19, 2, 5),
        listening_seconds=240.004,
        messages=83_875,
        dns_names=146_591,
        matches=0,
        new_records=0,
        connection_attempts=1,
        connections=1,
        completed_window=True,
    )

    complete_attempt(metrics, "healthy-empty", path, now=_at(19, 6, 6))
    health = read_collection_health(path)

    assert health is not None
    assert health["lastSuccessAt"] == "2026-08-21T19:06:06.000Z"
    assert health["freshness"] == {
        "status": "current",
        "referenceAt": "2026-08-21T19:06:06.000Z",
        "ageSeconds": 0,
    }
    assert health["latestAttempt"]["listeningSeconds"] == 240.004
    assert health["latestAttempt"]["messages"] == 83_875
    assert health["latestAttempt"]["dnsNames"] == 146_591
    assert health["latestAttempt"]["matches"] == 0
    assert health["latestAttempt"]["outcome"] == "healthy-empty"
    assert set(health["latestAttempt"]) == {
        "startedAt",
        "collectorStartedAt",
        "endedAt",
        "trigger",
        "scheduledFor",
        "scheduleStatus",
        "delaySeconds",
        "expectedListeningSeconds",
        "listeningSeconds",
        "messages",
        "dnsNames",
        "matches",
        "newRecords",
        "connectionAttempts",
        "connections",
        "outcome",
        "summary",
    }


def test_failure_preserves_last_success_and_reports_stale_freshness(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    path = Path("public/data/collection-health.json")
    begin_attempt(path, now=_at(17, 2), trigger_value="schedule")
    successful = CollectionMetrics(
        collector_started_at=_at(17, 2, 2),
        listening_seconds=240,
        messages=10,
        dns_names=15,
        connection_attempts=1,
        connections=1,
        completed_window=True,
    )
    complete_attempt(successful, "healthy-empty", path, now=_at(17, 6, 2))
    begin_attempt(path, now=_at(19, 2), trigger_value="schedule")

    monkeypatch.setenv("CERTSTREAM_PREPARE_OUTCOME", "failure")
    monkeypatch.setenv("CERTSTREAM_COLLECTOR_OUTCOME", "skipped")
    finalize_workflow(path, now=_at(19, 3))
    health = read_collection_health(path)

    assert health is not None
    assert health["lastSuccessAt"] == "2026-08-21T17:06:02.000Z"
    assert health["freshness"]["status"] == "stale"
    assert health["latestAttempt"]["outcome"] == "failed"
    assert health["latestAttempt"]["messages"] == 0


@pytest.mark.parametrize(
    ("metrics", "duration", "failed", "expected"),
    [
        (CollectionMetrics(), 240, True, "failed"),
        (CollectionMetrics(connections=1, connection_attempts=1, completed_window=True), 240, True, "no-input"),
        (
            CollectionMetrics(
                connections=1,
                connection_attempts=1,
                dns_names=10,
                listening_seconds=100,
                completed_window=True,
            ),
            240,
            False,
            "partial",
        ),
        (
            CollectionMetrics(
                connections=1,
                connection_attempts=1,
                dns_names=10,
                listening_seconds=240,
                completed_window=True,
            ),
            240,
            False,
            "healthy-empty",
        ),
        (
            CollectionMetrics(
                connections=1,
                connection_attempts=1,
                dns_names=10,
                matches=1,
                listening_seconds=240,
                completed_window=True,
            ),
            240,
            False,
            "healthy-matches",
        ),
    ],
)
def test_collection_outcomes_are_unambiguous(
    metrics: CollectionMetrics,
    duration: int,
    failed: bool,
    expected: str,
) -> None:
    assert _collection_outcome(metrics, duration, failed) == expected


def test_successful_zero_match_collection_records_its_daily_partition(
    monkeypatch: MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    async def successful_empty(metrics: CollectionMetrics | None = None) -> int:
        assert metrics is not None
        metrics.collector_started_at = _at(19, 2)
        metrics.listening_seconds = 240
        metrics.messages = 10
        metrics.dns_names = 20
        metrics.connection_attempts = 1
        metrics.connections = 1
        metrics.completed_window = True
        return 0

    def record(_root: object, **values: object) -> Path:
        observed.update(values)
        return Path("data/certstream/2026-08-21/attempts.ndjson")

    monkeypatch.setattr(collector_module, "collect", successful_empty)
    monkeypatch.setattr(collector_module, "record_successful_attempt", record)
    monkeypatch.setenv("CERTSTREAM_DURATION_SECONDS", "240")
    monkeypatch.delenv("CERTSTREAM_HEALTH_PATH", raising=False)

    assert collector_module.main() == 0
    assert observed["outcome"] == "healthy-empty"
    assert observed["dns_names"] == 20
    assert observed["matches"] == 0


def test_rejects_unbounded_or_outside_artifacts(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    path = Path("public/data/collection-health.json")
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"schemaVersion": 1, "rawCandidates": ["sensitive.example"]}), encoding="utf-8")

    with pytest.raises(ValueError, match="schema version 1"):
        read_collection_health(path)
    with pytest.raises(ValueError, match="inside the repository"):
        begin_attempt(tmp_path.parent / "outside.json", now=_at(19, 2))


def test_checked_in_collection_health_matches_the_public_contract() -> None:
    value = json.loads(Path("public/data/collection-health.json").read_text(encoding="utf-8"))
    assert is_collection_health(value)
    attempt = value["latestAttempt"]
    if attempt is None:
        assert value["lastSuccessAt"] is None
    else:
        assert attempt["outcome"] in {"healthy-empty", "healthy-matches", "no-input", "partial", "failed"}
        assert set(attempt) == {
            "startedAt",
            "collectorStartedAt",
            "endedAt",
            "trigger",
            "scheduledFor",
            "scheduleStatus",
            "delaySeconds",
            "expectedListeningSeconds",
            "listeningSeconds",
            "messages",
            "dnsNames",
            "matches",
            "newRecords",
            "connectionAttempts",
            "connections",
            "outcome",
            "summary",
        }
    assert Path("public/data/collection-health.json").stat().st_size < 32 * 1024
