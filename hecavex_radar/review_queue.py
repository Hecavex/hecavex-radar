from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from .coverage_ledger import read_bounded_json
from .provenance import REASON_CODES

MAXIMUM_CANDIDATES = 100
KNOWN_SOURCES = frozenset({"CertStream", "URLScan", "HECAVEX"})
EVIDENCE_TIERS = frozenset({"name-only", "corroborated", "reviewed"})


def _timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00").astimezone(UTC)
    except ValueError:
        return None
    canonical = parsed.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return parsed if canonical == value else None


def _score_band(value: int) -> str:
    if value < 70:
        return "00-69"
    if value < 85:
        return "70-84"
    if value < 95:
        return "85-94"
    return "95-100"


def _age_band(first_seen: datetime, generated_at: datetime) -> str:
    days = max(0, int((generated_at - first_seen).total_seconds() // 86_400))
    if days <= 1:
        return "0-1d"
    if days <= 7:
        return "2-7d"
    if days <= 30:
        return "8-30d"
    return "31d+"


def _reviewed_signal_ids(review_export: dict[str, object]) -> set[str]:
    assessments = review_export.get("assessments")
    if not isinstance(assessments, list):
        return set()
    return {
        signal_id
        for assessment in assessments[:10_000]
        if isinstance(assessment, dict)
        and isinstance((signal_id := assessment.get("signalId")), str)
        and len(signal_id) == 20
    }


def _candidate(signal: object, generated: datetime) -> dict[str, object] | None:
    if not isinstance(signal, dict):
        return None
    identifier = signal.get("id")
    brand = signal.get("brand")
    score = signal.get("matchScore")
    first_seen_value = signal.get("firstSeen")
    first_seen = _timestamp(first_seen_value)
    evidence = signal.get("evidenceTier")
    sources = signal.get("sources")
    reasons = signal.get("reasonCodes")
    if (
        not isinstance(identifier, str)
        or len(identifier) != 20
        or not isinstance(brand, str)
        or not 1 <= len(brand) <= 80
        or not isinstance(score, int)
        or isinstance(score, bool)
        or not 0 <= score <= 100
        or first_seen is None
        or first_seen > generated
        or not isinstance(evidence, str)
        or evidence not in EVIDENCE_TIERS
        or not isinstance(sources, list)
        or not isinstance(reasons, list)
    ):
        return None
    safe_sources = sorted({value for value in sources if isinstance(value, str) and value in KNOWN_SOURCES})
    safe_reasons = sorted({value for value in reasons if isinstance(value, str) and value in REASON_CODES})
    if not safe_sources or not safe_reasons:
        return None
    return {
        "signalId": identifier,
        "recordPath": f"/signals/{identifier}/",
        "brand": brand,
        "sources": safe_sources,
        "scoreBand": _score_band(score),
        "evidenceTier": evidence,
        "reasonCodes": safe_reasons,
        "candidateAgeBand": _age_band(first_seen, generated),
        "firstSeen": cast(str, first_seen_value),
    }


def _facets(candidate: dict[str, object]) -> tuple[str, ...]:
    return (
        f"brand:{candidate['brand']}",
        f"score:{candidate['scoreBand']}",
        f"evidence:{candidate['evidenceTier']}",
        f"age:{candidate['candidateAgeBand']}",
        *(f"source:{source}" for source in cast(list[str], candidate["sources"])),
        *(f"reason:{reason}" for reason in cast(list[str], candidate["reasonCodes"])),
    )


def build_review_queue(
    snapshot: dict[str, object],
    review_export: dict[str, object],
    *,
    generated_at: str,
    limit: int = 24,
) -> dict[str, object]:
    generated = _timestamp(generated_at)
    if generated is None:
        raise ValueError("Review queue generatedAt must be canonical UTC with milliseconds.")
    if not 1 <= limit <= MAXIMUM_CANDIDATES:
        raise ValueError(f"Review queue limit must be from 1 to {MAXIMUM_CANDIDATES}.")
    signals = snapshot.get("signals")
    if (
        snapshot.get("schemaVersion") != 2
        or snapshot.get("dataset") != "live"
        or not isinstance(signals, list)
    ):
        raise ValueError("Radar snapshot has an unsupported contract.")

    reviewed = _reviewed_signal_ids(review_export)
    available = [candidate for value in signals[:25_000] if (candidate := _candidate(value, generated))]
    available = [candidate for candidate in available if candidate["signalId"] not in reviewed]
    available.sort(key=lambda item: (cast(str, item["firstSeen"]), cast(str, item["signalId"])))
    total_available = len(available)

    selected: list[dict[str, object]] = []
    facet_counts: Counter[str] = Counter()
    while available and len(selected) < limit:
        ranked = sorted(
            available,
            key=lambda item: (
                sum(facet_counts[facet] for facet in _facets(item)),
                max((facet_counts[facet] for facet in _facets(item)), default=0),
                cast(str, item["firstSeen"]),
                cast(str, item["signalId"]),
            ),
        )
        chosen = ranked[0]
        available.remove(chosen)
        selected.append(chosen)
        facet_counts.update(_facets(chosen))

    return {
        "schemaVersion": 1,
        "dataset": "radar-stratified-review-queue",
        "generatedAt": generated_at,
        "samplingPolicy": {
            "method": "deterministic-greedy-facet-balancing",
            "dimensions": ["source", "brand", "score-band", "evidence-tier", "reason-code", "candidate-age"],
            "excludes": "Signals already represented by a sanitized assessment.",
            "semantics": "A review worklist, not a random or prevalence-representative sample.",
        },
        "availableUnreviewed": total_available,
        "selected": len(selected),
        "candidates": selected,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build a deterministic stratified Radar review queue.")
    parser.add_argument("--snapshot", type=Path, default=Path("public/data/radar.json"))
    parser.add_argument("--reviews", type=Path, default=Path("data/review/public-decisions.json"))
    parser.add_argument("--output", type=Path, default=Path("data/review/review-queue.json"))
    parser.add_argument("--generated-at", required=True)
    parser.add_argument("--limit", type=int, default=24)
    options = parser.parse_args(argv)
    snapshot = read_bounded_json(options.snapshot, 512 * 1024)
    reviews = read_bounded_json(options.reviews, 2 * 1024 * 1024)
    artifact = build_review_queue(snapshot, reviews, generated_at=options.generated_at, limit=options.limit)
    options.output.parent.mkdir(parents=True, exist_ok=True)
    options.output.write_text(json.dumps(artifact, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {artifact['selected']} review candidates to {options.output}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
