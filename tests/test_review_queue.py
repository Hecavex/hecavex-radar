from __future__ import annotations

from typing import cast

from hecavex_radar.review_queue import build_review_queue


def _signal(
    identifier: str,
    *,
    brand: str,
    source: str,
    score: int,
    evidence: str,
    reason: str,
    first_seen: str,
) -> dict[str, object]:
    return {
        "id": identifier,
        "brand": brand,
        "sources": [source],
        "matchScore": score,
        "evidenceTier": evidence,
        "reasonCodes": [reason],
        "firstSeen": first_seen,
    }


def test_review_queue_balances_facets_and_excludes_assessed_signals() -> None:
    snapshot = {
        "schemaVersion": 2,
        "dataset": "live",
        "signals": [
            _signal(
                "00000000000000000001",
                brand="A",
                source="CertStream",
                score=99,
                evidence="name-only",
                reason="brand-exact-token",
                first_seen="2026-08-25T10:00:00.000Z",
            ),
            _signal(
                "00000000000000000002",
                brand="A",
                source="CertStream",
                score=98,
                evidence="name-only",
                reason="brand-exact-token",
                first_seen="2026-08-25T11:00:00.000Z",
            ),
            _signal(
                "00000000000000000003",
                brand="B",
                source="URLScan",
                score=80,
                evidence="corroborated",
                reason="unicode-confusable",
                first_seen="2026-08-18T10:00:00.000Z",
            ),
        ]
    }
    reviews = {"assessments": [{"signalId": "00000000000000000002"}]}
    queue = build_review_queue(snapshot, reviews, generated_at="2026-08-26T12:00:00.000Z", limit=2)
    selected = cast(list[dict[str, object]], queue["candidates"])
    assert queue["availableUnreviewed"] == 2
    assert queue["selected"] == 2
    assert {item["signalId"] for item in selected} == {
        "00000000000000000001",
        "00000000000000000003",
    }
    assert {cast(list[str], item["sources"])[0] for item in selected} == {"CertStream", "URLScan"}
    assert all("domain" not in item for item in selected)


def test_review_queue_is_deterministic() -> None:
    snapshot = {
        "schemaVersion": 2,
        "dataset": "live",
        "signals": [
            _signal(
                f"{index:020x}",
                brand=f"Brand {index % 2}",
                source="CertStream" if index % 2 else "URLScan",
                score=60 + index,
                evidence="name-only",
                reason="brand-domain-match",
                first_seen=f"2026-08-{20 + index:02d}T10:00:00.000Z",
            )
            for index in range(1, 5)
        ]
    }
    first = build_review_queue(snapshot, {"assessments": []}, generated_at="2026-08-26T12:00:00.000Z", limit=3)
    second = build_review_queue(snapshot, {"assessments": []}, generated_at="2026-08-26T12:00:00.000Z", limit=3)
    assert first == second
