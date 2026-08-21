from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pytest import MonkeyPatch

from hecavex_radar import hecavex
from hecavex_radar.models import RadarSignal

NOW = datetime(2026, 8, 21, 12, tzinfo=UTC)


def _signal(
    domain: str,
    sources: list[str],
    *,
    last_seen: str = "2026-08-21T11:00:00.000Z",
) -> RadarSignal:
    return {
        "id": "f" * 20,
        "url": f"https://{domain}/login?token=must-not-leak",
        "domain": domain,
        "firstSeen": "2026-08-21T10:00:00.000Z",
        "lastSeen": last_seen,
        "sources": sources,
        "status": "suspected",
        "brand": "Swedbank",
        "country": "LT",
        "host": "Example provider 192.0.2.10 provider.example",
        "screenshotUrl": "https://urlscan.io/screenshots/11111111-1111-1111-1111-111111111111.png",
        "referenceUrl": "https://urlscan.io/result/11111111-1111-1111-1111-111111111111/",
        "hashes": ["a" * 64],
        "confidence": 92,
    }


def test_builds_defanged_potential_candidates_from_passive_sources_only() -> None:
    payload = hecavex.build_hecavex_candidates(
        [
            _signal("urlscan-bank.example", ["URLScan"]),
            _signal("cert-bank.example", ["CertStream"]),
            _signal("corroborated-bank.example", ["HECAVEX", "URLScan"]),
            _signal("private-only.example", ["HECAVEX"]),
            _signal("community-seeded.example", ["URLScan", "UnpublishedSeed"]),
            _signal("unknown-seeded.example", ["CertStream", "SecretFeed"]),
        ],
        NOW,
    )

    assert payload["schemaVersion"] == 1
    assert payload["dataset"] == "hecavex-candidates"
    assert payload["generatedAt"] == "2026-08-21T12:00:00.000Z"
    assert payload["disposition"] == "potential"
    assert len(payload["signals"]) == 3
    assert {signal["domain"] for signal in payload["signals"]} == {
        "urlscan-bank[.]example",
        "cert-bank[.]example",
        "corroborated-bank[.]example",
    }
    assert all(set(signal["sources"]) <= {"CertStream", "URLScan"} for signal in payload["signals"])
    serialized = json.dumps(payload)
    assert "must-not-leak" not in serialized
    assert "192.0.2.10" not in serialized
    assert "provider.example" not in serialized
    assert "192[.]0[.]2[.]10" in serialized
    assert "provider[.]example" in serialized


def test_caps_signal_count_and_encoded_size(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(hecavex, "MAXIMUM_EXPORT_SIGNALS", 2)
    payload = hecavex.build_hecavex_candidates(
        [
            _signal("old.example", ["CertStream"], last_seen="2026-08-21T09:00:00.000Z"),
            _signal("new.example", ["URLScan"], last_seen="2026-08-21T11:00:00.000Z"),
            _signal("newer.example", ["URLScan"], last_seen="2026-08-21T12:00:00.000Z"),
        ],
        NOW,
    )
    assert {signal["domain"] for signal in payload["signals"]} == {"new[.]example", "newer[.]example"}

    empty = hecavex.build_hecavex_candidates([], NOW)
    empty_size = len(json.dumps(empty, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) + 1
    monkeypatch.setattr(hecavex, "MAXIMUM_EXPORT_BYTES", empty_size)
    size_bounded = hecavex.build_hecavex_candidates([_signal("large.example", ["URLScan"])], NOW)
    assert size_bounded["signals"] == []


def test_ignores_an_unrepresentable_confidence_value() -> None:
    assert hecavex._number(10**400) is None


def test_writer_stays_inside_repository_and_replaces_atomically(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    target = hecavex.write_hecavex_candidates(
        "data/hecavex/candidates.json",
        [_signal("safe.example", ["URLScan"])],
        NOW,
    )
    assert target == tmp_path / "data" / "hecavex" / "candidates.json"
    assert json.loads(target.read_text(encoding="utf-8"))["signals"][0]["domain"] == "safe[.]example"
    assert not list(target.parent.glob(".*.tmp"))

    with pytest.raises(ValueError, match="inside data/hecavex"):
        hecavex.write_hecavex_candidates("../outside.json", [], NOW)
    with pytest.raises(ValueError, match="inside data/hecavex"):
        hecavex.write_hecavex_candidates("public/candidates.json", [], NOW)

    target.write_text("previous", encoding="utf-8")

    def fail_replace(_source: object, _destination: object) -> None:
        raise OSError("simulated replacement failure")

    monkeypatch.setattr("hecavex_radar.hecavex.os.replace", fail_replace)
    with pytest.raises(OSError, match="simulated replacement failure"):
        hecavex.write_hecavex_candidates(target, [_signal("other.example", ["CertStream"])], NOW)
    assert target.read_text(encoding="utf-8") == "previous"
    assert not list(target.parent.glob(".*.tmp"))
