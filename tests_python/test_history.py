import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pytest import MonkeyPatch

import hecavex_radar.history as history_module
from hecavex_radar.brands import load_brand_registry
from hecavex_radar.history import (
    append_history_events,
    build_history_events,
    compact_history,
    previous_statuses,
    read_event_file,
    update_history,
)
from hecavex_radar.models import RadarSignal
from hecavex_radar.safety import stable_id


def _signal(
    domain: str = "secure-swedbank-login[.]example",
    *,
    source: str = "CertStream",
    brand: str = "Swedbank",
    status: str = "suspected",
    observed_at: str = "2026-08-22T09:00:00.000Z",
) -> RadarSignal:
    return {
        "id": stable_id(domain.lower()),
        "url": f"hxxps://{domain}",
        "domain": domain,
        "firstSeen": observed_at,
        "lastSeen": observed_at,
        "sources": [source],
        "status": status,  # type: ignore[typeddict-item]
        "brand": brand,
        "country": None,
        "host": None,
        "screenshotUrl": None,
        "confidence": 90,
        "reasonCodes": ["brand-domain-match", "suspicious-context"],
    }


def test_history_events_are_deterministic_and_do_not_require_urlscan() -> None:
    signal = _signal()
    first = build_history_events([signal], [signal], {})
    second = build_history_events([signal], [signal], {})

    assert first == second
    assert {event["eventType"] for event in first} == {"observation", "status-transition"}
    assert all(event["sources"] == ["CertStream"] for event in first)
    assert any("first-publication" in event["reasonCodes"] for event in first)


def test_history_never_synthesizes_offline_from_absence() -> None:
    signal = _signal()
    assert build_history_events([], [], {signal["id"]: "suspected"}) == []


def test_history_rejects_cross_brand_observation_before_archiving() -> None:
    swedbank = _signal()
    revolut = _signal(brand="Revolut")

    events = build_history_events([swedbank], [revolut], {})

    assert all(event["eventType"] != "observation" for event in events)


def test_daily_archive_is_append_only_and_deduplicates_event_ids(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    signal = _signal()
    events = build_history_events([signal], [signal], {})

    assert append_history_events("data/history", events) == 2
    assert append_history_events("data/history", events) == 0
    path = tmp_path / "data/history/daily/2026-08-22/events.ndjson"
    assert read_event_file(path) == events


def test_daily_archive_deduplicates_one_addition_batch_and_fails_on_overflow(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    event = build_history_events([_signal()], [_signal()], {})[0]

    assert append_history_events("data/history", [event, event]) == 1
    monkeypatch.setattr(history_module, "MAXIMUM_DAILY_EVENTS", 1)
    other = build_history_events(
        [_signal(observed_at="2026-08-22T09:01:00.000Z")],
        [_signal(observed_at="2026-08-22T09:01:00.000Z")],
        {event["signalId"]: "suspected"},
    )[0]
    with pytest.raises(ValueError, match="Refusing to exceed"):
        append_history_events("data/history", [other])


def test_daily_archive_fails_closed_on_malformed_record(tmp_path: Path) -> None:
    path = tmp_path / "data/history/daily/2026-08-22/events.ndjson"
    path.parent.mkdir(parents=True)
    path.write_text('{"schemaVersion":1}\n', encoding="utf-8")

    with pytest.raises(ValueError, match="invalid event"):
        read_event_file(path)


def test_future_compaction_watermark_fails_without_deleting_detail(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    event = build_history_events(
        [_signal(observed_at="2026-06-01T09:00:00.000Z")],
        [_signal(observed_at="2026-06-01T09:00:00.000Z")],
        {},
    )[0]
    append_history_events("data/history", [event])
    detail = tmp_path / "data/history/daily/2026-06-01/events.ndjson"
    summary = tmp_path / "data/history/summary.json"
    summary.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "dataset": "radar-history-summary",
                "generatedAt": "2026-08-22T00:00:00.000Z",
                "compactedThrough": "2026-08-23",
                "signals": [],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="future"):
        compact_history("data/history", datetime(2026, 8, 22, tzinfo=UTC), 30, 730)
    assert detail.exists()


def test_previous_statuses_fails_closed_on_existing_malformed_history(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    target = tmp_path / "public/data/history.json"
    target.parent.mkdir(parents=True)
    target.write_text('{"schemaVersion":1,"dataset":"history","signals":[]}', encoding="utf-8")

    with pytest.raises(ValueError, match="schema version 1"):
        previous_statuses("public/data/history.json")
    target.unlink()
    assert previous_statuses("public/data/history.json") == {}


def test_old_detail_compacts_into_bounded_public_summary(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    registry = load_brand_registry()
    repository = tmp_path / "repository"
    repository.mkdir()
    monkeypatch.chdir(repository)
    signal = _signal(observed_at="2026-07-01T09:00:00.000Z")
    events = build_history_events([signal], [signal], {})

    output = update_history(
        root="data/history",
        output="public/data/history.json",
        events=events,
        now=datetime(2026, 8, 22, tzinfo=UTC),
        registry=registry,
        is_suppressed=lambda _domain, _brand: False,
        detail_days=30,
        summary_days=730,
    )

    assert not (repository / "data/history/daily/2026-07-01/events.ndjson").exists()
    summary = json.loads((repository / "data/history/summary.json").read_text(encoding="utf-8"))
    public = json.loads(output.read_text(encoding="utf-8"))
    assert summary["signals"][0]["observationCount"] == 1
    assert public["signals"][0]["latestStatus"] == "suspected"
    assert public["signals"][0]["statusTransitions"][0]["previousStatus"] is None


def test_compaction_watermark_prevents_old_replay_from_inflating_counts(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    registry = load_brand_registry()
    repository = tmp_path / "repository"
    repository.mkdir()
    monkeypatch.chdir(repository)
    start = datetime(2026, 6, 1, tzinfo=UTC)
    signals = [
        _signal(
            observed_at=(start + timedelta(minutes=index))
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z")
        )
        for index in range(65)
    ]
    events = [
        event
        for signal in signals
        for event in build_history_events([signal], [signal], {signal["id"]: "suspected"})
    ]
    arguments = {
        "root": "data/history",
        "output": "public/data/history.json",
        "now": datetime(2026, 8, 22, tzinfo=UTC),
        "registry": registry,
        "is_suppressed": lambda _domain, _brand: False,
        "detail_days": 30,
        "summary_days": 730,
    }

    update_history(events=events, **arguments)  # type: ignore[arg-type]
    update_history(events=[events[0]], **arguments)  # type: ignore[arg-type]

    summary = json.loads((repository / "data/history/summary.json").read_text(encoding="utf-8"))
    assert summary["signals"][0]["observationCount"] == 65
    assert len(summary["signals"][0]["recentEventIds"]) == 64


def test_public_history_rejects_ambiguous_cross_brand_domain(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    registry = load_brand_registry()
    repository = tmp_path / "repository"
    repository.mkdir()
    monkeypatch.chdir(repository)
    signal = _signal(
        domain="swedbank-revolut-login[.]com",
        source="URLScan",
        brand="Swedbank",
    )
    signal["reasonCodes"] = ["brand-title-match"]

    output = update_history(
        root="data/history",
        output="public/data/history.json",
        events=build_history_events([signal], [signal], {}),
        now=datetime(2026, 8, 22, 10, tzinfo=UTC),
        registry=registry,
        is_suppressed=lambda _domain, _brand: False,
    )

    assert json.loads(output.read_text(encoding="utf-8"))["signals"] == []


def test_public_history_applies_review_suppressions(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    registry = load_brand_registry()
    repository = tmp_path / "repository"
    repository.mkdir()
    monkeypatch.chdir(repository)
    signal = _signal()

    output = update_history(
        root="data/history",
        output="public/data/history.json",
        events=build_history_events([signal], [signal], {}),
        now=datetime(2026, 8, 22, 10, tzinfo=UTC),
        registry=registry,
        is_suppressed=lambda domain, brand: domain == signal["domain"] and brand == signal["brand"],
    )

    assert json.loads(output.read_text(encoding="utf-8"))["signals"] == []
