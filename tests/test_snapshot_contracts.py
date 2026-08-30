from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import cast

import pytest
from jsonschema import Draft202012Validator, ValidationError

from hecavex_radar import review as review_module
from hecavex_radar.brands import load_brand_registry
from hecavex_radar.domain_context import _snapshot_signals
from hecavex_radar.event_feeds import build_event_feeds
from hecavex_radar.health_sentinel import _evaluate_snapshot
from hecavex_radar.hecavex import read_snapshot_signals
from hecavex_radar.provider_checks import _load_signal
from hecavex_radar.public_schemas import RADAR_SCHEMA
from hecavex_radar.review_queue import build_review_queue
from hecavex_radar.stix import build_stix_bundle
from hecavex_radar.sync import _existing_signal_count, _load_existing_snapshot
from hecavex_radar.urlscan import _load_radar_snapshot_seeds

REPOSITORY = Path(__file__).resolve().parents[1]
SNAPSHOT_PATH = REPOSITORY / "public/data/radar.json"
FIXTURE_PATH = REPOSITORY / "tests/fixtures/radar-snapshot-v2-minimal.json"
SIGNAL_ID = "634e49d160844cdcc2e6"


def _read(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return cast(dict[str, object], value)


def _install_snapshot(root: Path, value: dict[str, object]) -> Path:
    target = root / "public/data/radar.json"
    target.parent.mkdir(parents=True)
    target.write_text(json.dumps(value), encoding="utf-8")
    return target


def _empty_review(generated_at: str) -> dict[str, object]:
    return {
        "schemaVersion": 3,
        "dataset": "radar-review-decisions",
        "generatedAt": generated_at,
        "suppressions": [],
        "candidates": [],
        "assessments": [],
    }


def _assert_python_consumers_accept(
    snapshot: dict[str, object],
    target: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generated_at = cast(str, snapshot["generatedAt"])
    successful_at = cast(str, snapshot["lastSuccessfulSyncAt"])
    now = datetime.fromisoformat(successful_at.replace("Z", "+00:00"))
    registry = load_brand_registry(REPOSITORY / "data/brands-lt.json")
    monkeypatch.chdir(target.parents[2])
    monkeypatch.setenv("URLSCAN_RADAR_SNAPSHOT", "public/data/radar.json")

    Draft202012Validator(RADAR_SCHEMA).validate(snapshot)
    assert read_snapshot_signals("public/data/radar.json") == snapshot["signals"]
    assert _snapshot_signals("public/data/radar.json")
    assert _existing_signal_count(target) == len(cast(list[object], snapshot["signals"]))
    assert _load_existing_snapshot(target, successful_at, 90)[0]
    assert _load_radar_snapshot_seeds(registry, now, 90)
    assert build_event_feeds([], snapshot, generated_at).artifact["dataset"] == "radar-events"
    assert build_stix_bundle(snapshot)["type"] == "bundle"
    first_signal = cast(dict[str, object], cast(list[object], snapshot["signals"])[0])
    assert _load_signal(cast(str, first_signal["id"]))[0]
    selected = build_review_queue(
        snapshot,
        _empty_review(generated_at),
        generated_at=generated_at,
    )["selected"]
    assert isinstance(selected, int) and 1 <= selected <= 24
    findings = []
    _evaluate_snapshot(target.parents[2], now, findings)
    assert not findings


def test_minimal_v2_fixture_passes_every_python_consumer(tmp_path, monkeypatch) -> None:
    snapshot = _read(FIXTURE_PATH)
    target = _install_snapshot(tmp_path, snapshot)

    _assert_python_consumers_accept(snapshot, target, monkeypatch)


def test_current_live_snapshot_passes_every_python_consumer(tmp_path, monkeypatch) -> None:
    snapshot = _read(SNAPSHOT_PATH)
    target = _install_snapshot(tmp_path, snapshot)

    _assert_python_consumers_accept(snapshot, target, monkeypatch)


@pytest.mark.parametrize("unsupported_version", [1, 3])
def test_unsupported_live_snapshot_versions_are_rejected(
    unsupported_version: int,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = deepcopy(_read(FIXTURE_PATH))
    snapshot["schemaVersion"] = unsupported_version
    target = _install_snapshot(tmp_path, snapshot)
    generated_at = cast(str, snapshot["generatedAt"])
    successful_at = cast(str, snapshot["lastSuccessfulSyncAt"])
    now = datetime.fromisoformat(successful_at.replace("Z", "+00:00"))
    registry = load_brand_registry(REPOSITORY / "data/brands-lt.json")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("URLSCAN_RADAR_SNAPSHOT", "public/data/radar.json")

    with pytest.raises(ValidationError):
        Draft202012Validator(RADAR_SCHEMA).validate(snapshot)
    with pytest.raises(ValueError, match="snapshot"):
        read_snapshot_signals("public/data/radar.json")
    with pytest.raises(ValueError, match="snapshot"):
        _snapshot_signals("public/data/radar.json")
    assert _existing_signal_count(target) is None
    assert _load_existing_snapshot(target, successful_at, 90) == ([], {})
    with pytest.raises(ValueError, match="snapshot"):
        _load_radar_snapshot_seeds(registry, now, 90)
    with pytest.raises(ValueError, match="schema version 2"):
        build_event_feeds([], snapshot, generated_at)
    with pytest.raises(ValueError, match="snapshot schema"):
        build_stix_bundle(snapshot)
    with pytest.raises(ValueError, match="contract"):
        _load_signal(SIGNAL_ID)
    with pytest.raises(ValueError, match="contract"):
        build_review_queue(snapshot, _empty_review(generated_at), generated_at=generated_at)
    findings = []
    _evaluate_snapshot(tmp_path, now, findings)
    assert [finding.code for finding in findings] == ["snapshot-contract-incompatible"]


def test_review_v1_has_one_version_read_migration(tmp_path, monkeypatch) -> None:
    registry = load_brand_registry(REPOSITORY / "data/brands-lt.json")
    monkeypatch.setattr(review_module, "PROJECT_ROOT", tmp_path)
    target = tmp_path / "data/review/legacy-v1.json"
    target.parent.mkdir(parents=True)
    target.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "dataset": "radar-review-decisions",
                "generatedAt": "2026-08-26T00:00:00.000Z",
                "suppressions": [],
                "candidates": [],
            }
        ),
        encoding="utf-8",
    )

    policy = review_module.load_public_review(target, registry=registry)

    assert policy.suppressions == ()
    assert policy.candidates == ()
    assert policy.assessments == ()


def test_review_brand_fallback_accepts_only_live_snapshot_v2(tmp_path, monkeypatch) -> None:
    registry = load_brand_registry(REPOSITORY / "data/brands-lt.json")
    monkeypatch.setattr(review_module, "PROJECT_ROOT", tmp_path)
    target = tmp_path / "public/data/radar.json"
    target.parent.mkdir(parents=True)
    snapshot = {
        "schemaVersion": 2,
        "dataset": "live",
        "signals": [{"domain": "neutral-example[.]invalid", "brand": "Vinted"}],
    }
    target.write_text(json.dumps(snapshot), encoding="utf-8")

    assert review_module._current_brand("neutral-example.invalid", registry) == "Vinted"

    snapshot["schemaVersion"] = 1
    target.write_text(json.dumps(snapshot), encoding="utf-8")
    assert review_module._current_brand("neutral-example.invalid", registry) is None


def test_current_contract_version_is_explicit_across_python_consumers() -> None:
    snapshot = _read(SNAPSHOT_PATH)

    assert snapshot["schemaVersion"] == 2
    assert RADAR_SCHEMA["properties"]["schemaVersion"] == {"const": 2}
