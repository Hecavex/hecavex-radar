import json
from pathlib import Path

import pytest
from pytest import MonkeyPatch

from hecavex_radar.sync import _validate_snapshot_size, synchronize


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


def test_requires_an_application_key_when_automation_guard_is_enabled(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv("PHISHTANK_ENABLED", "true")
    monkeypatch.setenv("PHISHTANK_REQUIRE_APP_KEY", "true")
    monkeypatch.delenv("PHISHTANK_APP_KEY", raising=False)
    with pytest.raises(RuntimeError, match="PHISHTANK_APP_KEY"):
        synchronize()
