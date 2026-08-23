from datetime import UTC, datetime

import pytest
from pytest import MonkeyPatch

from hecavex_radar import sources
from hecavex_radar.brands import load_brand_registry
from hecavex_radar.certstream_archive import candidate_from_match
from hecavex_radar.models import CandidateMatch


def test_hecavex_source_rejects_an_unexpected_payload(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(sources, "fetch_json", lambda *_args, **_kwargs: {"unexpected": []})
    with pytest.raises(ValueError, match="unexpected payload"):
        sources.fetch_hecavex("2026-08-21T10:00:00Z", "https://feed.example.test/radar.json")


def test_hecavex_source_uses_explicit_attribution(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(
        sources,
        "fetch_json",
        lambda *_args, **_kwargs: {
            "signals": [
                {
                    "url": "https://secure-swedbank.example/login",
                    "source": "Untrusted label",
                    "brand": "Swedbank",
                    "status": "suspected",
                    "confidence": 88,
                    "hashType": "primary-html-sha256",
                    "hashes": ["a" * 64],
                }
            ]
        },
    )

    result = sources.fetch_hecavex("2026-08-21T10:00:00Z", "https://feed.example.test/radar.json")

    assert result.signals[0].source == "HECAVEX"
    assert result.signals[0].hashes == ["a" * 64]


def test_hecavex_source_ignores_untyped_hashes(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(
        sources,
        "fetch_json",
        lambda *_args, **_kwargs: {
            "signals": [
                {
                    "url": "https://secure-swedbank.example/login",
                    "brand": "Swedbank",
                    "hashes": ["a" * 64],
                }
            ]
        },
    )

    result = sources.fetch_hecavex("2026-08-21T10:00:00Z", "https://feed.example.test/radar.json")

    assert result.signals[0].hashes is None


def test_hecavex_source_ignores_unbounded_numeric_confidence(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(
        sources,
        "fetch_json",
        lambda *_args, **_kwargs: {
            "signals": [
                {
                    "url": "https://secure-swedbank.example/login",
                    "brand": "Swedbank",
                    "confidence": 10**10_000,
                }
            ]
        },
    )

    result = sources.fetch_hecavex("2026-08-21T10:00:00Z", "https://feed.example.test/radar.json")

    assert result.signals[0].confidence is None


def test_hecavex_source_caps_the_number_of_inspected_records(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(sources, "MAXIMUM_HECAVEX_RECORDS", 2)
    monkeypatch.setattr(
        sources,
        "fetch_json",
        lambda *_args, **_kwargs: [
            {"url": "https://one.example"},
            {"url": "https://two.example"},
            {"url": "https://three.example"},
        ],
    )

    result = sources.fetch_hecavex("2026-08-21T10:00:00Z", "https://feed.example.test/radar.json")

    assert [signal.url for signal in result.signals] == ["https://one.example", "https://two.example"]


def test_certstream_revalidates_stale_archive_matches(monkeypatch: MonkeyPatch) -> None:
    observed = datetime(2026, 8, 21, 10, tzinfo=UTC)
    stale = candidate_from_match(
        CandidateMatch("sberbank.example", "sberbank.example", "Swedbank", 73, ["old fuzzy match"]), observed
    )
    valid = candidate_from_match(
        CandidateMatch(
            "secure-swedbank.example",
            "secure-swedbank.example",
            "Swedbank",
            95,
            ["brand text match: swedbank"],
        ),
        observed,
    )
    registry = load_brand_registry()
    monkeypatch.setattr(sources, "load_brand_registry", lambda: registry)
    monkeypatch.setattr(sources, "read_recent_candidates", lambda *_args: [stale, valid])

    result = sources.load_certstream("2026-08-21T11:00:00Z", "data/certstream", 7)

    assert result.source["records"] == 1
    assert "1 candidate no longer passed current registry rules" in (result.source["note"] or "")
    assert len(result.signals) == 1
    assert result.signals[0].brand == "Swedbank"


@pytest.mark.parametrize(
    ("outcome", "expected_state", "note_fragment"),
    [
        ("completed", "healthy", "completed"),
        ("budget-limited", "partial", "request budget"),
        ("failed", "partial", "failed"),
        ("skipped-not-configured", "skipped", "not configured"),
    ],
)
def test_urlscan_source_state_reflects_the_latest_hunt(
    monkeypatch: MonkeyPatch,
    outcome: str,
    expected_state: str,
    note_fragment: str,
) -> None:
    monkeypatch.setattr(sources, "read_recent_urlscan", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        sources,
        "read_urlscan_hunt_state",
        lambda *_args: {
            "lastOutcome": outcome,
            "lastRunAt": "2026-08-21T09:00:00.000Z",
        },
    )

    result = sources.load_urlscan("2026-08-21T10:00:00.000Z", "data/urlscan", 7)

    assert result.source["state"] == expected_state
    assert result.source["fetchedAt"] == "2026-08-21T09:00:00.000Z"
    assert note_fragment in (result.source["note"] or "")


def test_urlscan_source_without_hunt_state_does_not_claim_health(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(sources, "read_recent_urlscan", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(sources, "read_urlscan_hunt_state", lambda *_args: None)

    result = sources.load_urlscan("2026-08-21T10:00:00.000Z", "data/urlscan", 7)

    assert result.source["state"] == "skipped"
    assert result.source["fetchedAt"] is None
    assert "state is unavailable" in (result.source["note"] or "")
