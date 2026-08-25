from __future__ import annotations

import json
from pathlib import Path

import pytest

from hecavex_radar.brands import BrandEntry, BrandRegistry
from hecavex_radar.coverage_ledger import build_brand_coverage, read_recent_certstream_candidates


def _registry() -> BrandRegistry:
    return BrandRegistry(
        scope="test",
        reviewed_at="2026-08-26",
        entries=[
            BrandEntry(
                brand="Vinted",
                last_reviewed_at="2026-08-24",
                aliases=["vinted"],
                fuzzy_aliases=["vinted"],
                excluded_terms=["vintage"],
                excluded_domains=[],
                category="marketplace",
                official_domains=["vinted.lt"],
                sources=["https://www.vinted.lt/"],
            )
        ],
    )


def test_brand_coverage_tracks_bounded_collection_and_review_state() -> None:
    artifact = build_brand_coverage(
        _registry(),
        ct_state={
            "queries": {
                "brand:vinted": {
                    "brand": "Vinted",
                    "lastOutcome": "completed",
                    "lastRunAt": "2026-08-26T08:00:00.000Z",
                }
            }
        },
        certstream_candidates=[{"brand": "Vinted", "observedAt": "2026-08-26T09:00:00.000Z"}],
        asset_state={
            "assets": [
                {
                    "brand": "Vinted",
                    "sha256": "a" * 64,
                    "resourceType": "javascript",
                    "lastValidatedAt": "2026-08-26T09:30:00.000Z",
                    "supportingScans": [
                        {"scanId": "one", "observedAt": "2026-08-20T00:00:00.000Z"},
                        {"scanId": "two", "observedAt": "2026-08-21T00:00:00.000Z"},
                    ],
                }
            ]
        },
        hunt_state={
            "lastRunAt": "2026-08-26T10:00:00.000Z",
            "lastOutcome": "completed",
            "candidateCursor": 4,
        },
        review_export={
            "suppressions": [{"brand": "Vinted"}],
            "assessments": [{"brand": "Vinted", "reviewState": "confirmed-suspicious"}],
        },
        matcher_corpus={
            "unicodeProfile": {"uts46": "test", "uts39": "test"},
            "cases": [
                {
                    "brand": "Vinted",
                    "domain": "secure-vinted-login.example",
                    "expected": {
                        "matched": True,
                        "brand": "Vinted",
                        "scoreBand": [90, 100],
                        "reasonCodes": ["brand-exact-token", "suspicious-context"],
                    },
                }
            ],
        },
        generated_at="2026-08-26T12:00:00.000Z",
    )
    record = artifact["brands"][0]
    assert record["lastReviewedAt"] == "2026-08-24"
    assert record["ctSearch"]["latestBoundedPollState"] == "completed"
    assert record["ctSearch"]["completedQueries"] == 1
    assert record["ctSearch"]["backloggedQueries"] == 0
    assert record["ctSearch"]["neverAttemptedQueries"] == 0
    assert record["ctSearch"]["lastSuccessfulQueryAt"] == "2026-08-26T08:00:00.000Z"
    assert record["certStream"]["latestMatchAt"] == "2026-08-26T09:00:00.000Z"
    assert record["urlscanAssets"]["supportedByTwoRecentOfficialScans"] == 1
    assert record["urlscanAssets"]["hashSupport"] == [
        {"sha256": "a" * 64, "resourceType": "javascript", "twoRecentOfficialScans": True}
    ]
    assert record["reviewOutcomes"] == {"confirmed-suspicious": 1, "suppressed": 1}
    assert record["collisionCorpus"] == {"cases": 1, "passing": 1, "status": "passing"}
    assert "urlscanHunt" not in record
    assert artifact["globalCollectorState"]["urlscanHunt"]["candidateCursor"] == 4


def test_brand_coverage_distinguishes_backlog_from_never_attempted() -> None:
    artifact = build_brand_coverage(
        _registry(),
        ct_state={
            "queryCursor": 7,
            "queries": {
                "brand:vinted": {
                    "brand": "Vinted",
                    "lastOutcome": "partial",
                    "lastRunAt": "2026-08-26T08:00:00.000Z",
                    "lastId": 42,
                },
                "alias:vinted": {
                    "brand": "Vinted",
                    "lastOutcome": None,
                    "lastRunAt": None,
                    "lastId": 0,
                },
            },
        },
        certstream_candidates=[],
        asset_state={"assets": []},
        hunt_state={},
        review_export={"assessments": []},
        matcher_corpus={"cases": []},
        generated_at="2026-08-26T12:00:00.000Z",
    )
    state = artifact["brands"][0]["ctSearch"]
    assert state["latestBoundedPollState"] == "backlogged"
    assert state["backloggedQueries"] == 1
    assert state["neverAttemptedQueries"] == 1
    assert state["cursorAdvancedQueries"] == 1


@pytest.mark.parametrize("outcome", ["budget-limited", "skipped-not-configured"])
def test_brand_coverage_preserves_real_urlscan_noncompleted_outcomes(outcome: str) -> None:
    artifact = build_brand_coverage(
        _registry(),
        ct_state={"queries": {}},
        certstream_candidates=[],
        asset_state={"assets": []},
        hunt_state={"lastOutcome": outcome},
        review_export={"assessments": []},
        matcher_corpus={"cases": []},
        generated_at="2026-08-26T12:00:00.000Z",
    )
    assert artifact["globalCollectorState"]["urlscanHunt"]["lastOutcome"] == outcome


def test_recent_certstream_reader_is_strict_and_keeps_one_latest_row_per_brand(tmp_path: Path) -> None:
    archive = tmp_path / "data/certstream/2026-08-25/domains.ndjson"
    archive.parent.mkdir(parents=True)
    rows = [
        {"brand": "Vinted", "observedAt": "2026-08-25T08:00:00.000Z"},
        {"brand": "Vinted", "observedAt": "2026-08-25T09:00:00.000Z"},
        {"brand": "Swedbank", "observedAt": "2026-08-25T07:00:00.000Z"},
    ]
    archive.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")

    result = read_recent_certstream_candidates(
        tmp_path / "data/certstream",
        "2026-08-26T12:00:00.000Z",
    )
    assert result == [rows[2], rows[1]]

    archive.write_text("not-json\n", encoding="utf-8")
    with pytest.raises(ValueError, match="invalid NDJSON"):
        read_recent_certstream_candidates(
            tmp_path / "data/certstream",
            "2026-08-26T12:00:00.000Z",
        )
