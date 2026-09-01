from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from hecavex_radar.collection_health import (
    CollectionMetrics,
    attempt_is_due,
    begin_attempt,
    begin_attempt_if_due,
    complete_attempt,
    is_collection_health,
    main,
    read_collection_health,
)

ROOT = Path(__file__).resolve().parents[1]


def test_shared_relay_fixture_matches_python_contract() -> None:
    value = json.loads(
        (ROOT / "tests" / "fixtures" / "collection-health-v1-relayed.json").read_text(encoding="utf-8")
    )
    assert is_collection_health(value)


@pytest.mark.parametrize(
    ("trigger", "schedule_status"),
    [
        ("schedule", "relayed"),
        ("cadence-relay", "unknown"),
        ("manual", "unknown"),
        ("unknown", "manual"),
    ],
)
def test_trigger_and_schedule_status_pairings_are_exact(trigger: str, schedule_status: str) -> None:
    value = json.loads(
        (ROOT / "tests" / "fixtures" / "collection-health-v1-relayed.json").read_text(encoding="utf-8")
    )
    value["latestAttempt"]["trigger"] = trigger
    value["latestAttempt"]["scheduleStatus"] = schedule_status

    assert not is_collection_health(value)


def test_automated_worker_start_guard_suppresses_cron_relay_duplicate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    path = "public/data/collection-health.json"
    started = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    begin_attempt(path, now=started, trigger_value="cadence-relay")
    complete_attempt(
        CollectionMetrics(
            collector_started_at=started,
            listening_seconds=480,
            messages=1,
            dns_names=1,
            connection_attempts=1,
            connections=1,
        ),
        "healthy-empty",
        path,
        now=started + timedelta(minutes=8),
    )

    due, _ = begin_attempt_if_due(path, now=started + timedelta(minutes=8), trigger_value="schedule")

    assert due is False
    health = read_collection_health(path)
    assert health is not None
    assert health["latestAttempt"]["startedAt"] == "2026-08-30T12:00:00.000Z"
    assert health["latestAttempt"]["trigger"] == "cadence-relay"
    assert health["latestAttempt"]["scheduleStatus"] == "relayed"
    assert health["latestAttempt"]["delaySeconds"] is None


def test_automated_guard_waits_out_scheduler_jitter_without_starting_early(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    path = "public/data/collection-health.json"
    started = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    begin_attempt(path, now=started, trigger_value="schedule")
    waited: list[float] = []

    due, _ = begin_attempt_if_due(
        path,
        now=started + timedelta(minutes=14, seconds=50),
        trigger_value="cadence-relay",
        sleeper=waited.append,
    )
    health = read_collection_health(path, allow_running=True)

    assert waited == [10.0]
    assert due is True
    assert health is not None
    assert health["latestAttempt"]["startedAt"] == "2026-08-30T12:15:00.000Z"
    assert health["latestAttempt"]["trigger"] == "cadence-relay"


def test_automated_guard_keeps_the_exact_interval_boundary_with_positive_tolerance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CERTSTREAM_DUE_TOLERANCE_SECONDS", "300")
    path = "public/data/collection-health.json"
    started = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    begin_attempt(path, now=started, trigger_value="schedule")

    assert not attempt_is_due(
        path,
        now=started + timedelta(seconds=899.999),
        trigger_value="cadence-relay",
    )
    assert attempt_is_due(
        path,
        now=started + timedelta(seconds=900),
        trigger_value="cadence-relay",
    )


def test_automated_guard_rechecks_after_jitter_wait_and_preserves_newer_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    path = "public/data/collection-health.json"
    started = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    begin_attempt(path, now=started, trigger_value="schedule")

    def claim_during_wait(seconds: float) -> None:
        assert seconds == 10.0
        begin_attempt(path, now=started + timedelta(minutes=14, seconds=55), trigger_value="schedule")

    due, _ = begin_attempt_if_due(
        path,
        now=started + timedelta(minutes=14, seconds=50),
        trigger_value="cadence-relay",
        sleeper=claim_during_wait,
    )
    health = read_collection_health(path, allow_running=True)

    assert due is False
    assert health is not None
    assert health["latestAttempt"]["startedAt"] == "2026-08-30T12:14:55.000Z"
    assert health["latestAttempt"]["trigger"] == "schedule"


def test_automated_guard_rejects_runs_outside_jitter_tolerance_and_allows_manual_bypass(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    path = "public/data/collection-health.json"
    started = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    begin_attempt(path, now=started, trigger_value="schedule")
    waited: list[float] = []

    early_due, _ = begin_attempt_if_due(
        path,
        now=started + timedelta(minutes=9, seconds=59),
        trigger_value="cadence-relay",
        sleeper=waited.append,
    )
    manual_path = "public/data/manual-collection-health.json"
    manual_due, _ = begin_attempt_if_due(manual_path, now=started + timedelta(minutes=1), trigger_value="manual")
    manual_health = read_collection_health(manual_path, allow_running=True)

    assert early_due is False
    assert waited == []
    assert manual_due is True
    assert manual_health is not None
    assert manual_health["latestAttempt"]["trigger"] == "manual"


def test_begin_if_due_cli_emits_github_step_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    output = tmp_path / "github-output.txt"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.setenv("CERTSTREAM_TRIGGER", "schedule")

    assert main(["begin-if-due"]) == 0
    assert main(["begin-if-due"]) == 0

    assert output.read_text(encoding="utf-8").splitlines() == ["due=true", "due=false"]
