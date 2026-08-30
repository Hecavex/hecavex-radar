from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime, timedelta
from statistics import median
from typing import cast

from .provenance import REASON_CODES
from .review import ASSESSMENT_REASONS, EVIDENCE_CODES, SUPPRESSION_REASONS

MAXIMUM_WINDOW_DAYS = 365
KNOWN_SOURCES = frozenset({"CertStream", "URLScan", "HECAVEX"})
KNOWN_OUTCOMES = frozenset(
    {
        "confirmed-suspicious",
        "false-positive",
        "benign-brand-reference",
        "inconclusive",
        "retracted",
    }
)


def _timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00").astimezone(UTC)
    except ValueError:
        return None
    canonical = parsed.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return parsed if canonical == value else None


def _safe_brand(value: object) -> str | None:
    if not isinstance(value, str) or value != value.strip() or not 1 <= len(value) <= 80:
        return None
    # Brand names are public facets. Reject values that look like indicators or
    # markup so malformed upstream data cannot disclose a raw domain or URL.
    if any(character in value for character in (".", "/", "\\", "@", "<", ">", "[", "]")):
        return None
    if any(ord(character) < 32 for character in value):
        return None
    return value


def _counts(values: Iterable[str], maximum: int = 64) -> dict[str, int]:
    counter = Counter(values)
    return dict(sorted(counter.items(), key=lambda item: (-item[1], item[0]))[:maximum])


def _percentage(numerator: int, denominator: int) -> float | None:
    return None if denominator == 0 else round(100 * numerator / denominator, 2)


def _percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    # Nearest-rank is deterministic and understandable for small review sets.
    index = max(0, min(len(ordered) - 1, int((len(ordered) * percentile) + 0.999999) - 1))
    return round(ordered[index], 2)


def _history_index(history: Mapping[str, object]) -> dict[str, dict[str, object]]:
    raw_signals = history.get("signals")
    if not isinstance(raw_signals, list):
        return {}
    indexed: dict[str, dict[str, object]] = {}
    for raw_signal in raw_signals[:25_000]:
        if not isinstance(raw_signal, dict):
            continue
        signal_id = raw_signal.get("id")
        first_seen = _timestamp(raw_signal.get("firstSeen"))
        if not isinstance(signal_id, str) or len(signal_id) != 20 or first_seen is None:
            continue
        sources = raw_signal.get("sources")
        reasons = raw_signal.get("reasonCodes")
        indexed[signal_id] = {
            "firstSeen": first_seen,
            "sources": sorted(
                {
                    source
                    for source in sources
                    if isinstance(sources, list) and isinstance(source, str) and source in KNOWN_SOURCES
                }
            )
            if isinstance(sources, list)
            else [],
            "reasonCodes": sorted(
                {
                    reason
                    for reason in reasons
                    if isinstance(reasons, list) and isinstance(reason, str) and reason in REASON_CODES
                }
            )
            if isinstance(reasons, list)
            else [],
        }
    return indexed


def _review_outcome(assessment: Mapping[str, object]) -> str | None:
    if assessment.get("revoked") is True:
        return "retracted"
    state = assessment.get("reviewState")
    return state if isinstance(state, str) and state in KNOWN_OUTCOMES else None


def build_quality_metrics(
    review_export: Mapping[str, object],
    history: Mapping[str, object],
    generated_at: str,
    *,
    window_days: int = MAXIMUM_WINDOW_DAYS,
) -> dict[str, object]:
    """Build public quality metrics without publishing review subjects.

    The sanitized review contract supports dated positive and negative labels,
    but it does not claim that the reviewed worklist is a probability sample.
    The artifact therefore reports review dispositions and current exclusions,
    while deliberately leaving population precision and false-positive rate
    unavailable until a defensible sample design is linked to the decisions.
    """

    generated = _timestamp(generated_at)
    if generated is None:
        raise ValueError("Quality metrics require a canonical UTC generatedAt timestamp.")
    if not 1 <= window_days <= MAXIMUM_WINDOW_DAYS:
        raise ValueError(f"Quality metrics window must be between 1 and {MAXIMUM_WINDOW_DAYS} days.")
    window_start = generated - timedelta(days=window_days)
    history_by_id = _history_index(history)

    raw_assessments = review_export.get("assessments")
    assessments: list[dict[str, object]] = []
    if isinstance(raw_assessments, list):
        for raw in raw_assessments[:2_500]:
            if not isinstance(raw, dict):
                continue
            reviewed_at = _timestamp(raw.get("reviewedAt"))
            signal_id = raw.get("signalId")
            outcome = _review_outcome(raw)
            if (
                reviewed_at is None
                or not window_start <= reviewed_at <= generated
                or not isinstance(signal_id, str)
                or len(signal_id) != 20
                or outcome is None
            ):
                continue
            assessments.append({**raw, "_reviewedAt": reviewed_at, "_outcome": outcome})
    assessments.sort(
        key=lambda item: (
            str(item.get("reviewedAt", "")),
            str(item.get("signalId", "")),
            str(item.get("id", "")),
        )
    )

    outcomes: list[str] = []
    brands: list[str] = []
    evidence: list[str] = []
    dispositions: list[str] = []
    linked_sources: list[str] = []
    linked_reasons: list[str] = []
    linked_assessments = 0
    assessment_signal_ids: set[str] = set()
    earliest_review_by_signal: dict[str, datetime] = {}
    for assessment in assessments:
        signal_id = str(assessment["signalId"])
        reviewed_at = cast(datetime, assessment["_reviewedAt"])
        assessment_signal_ids.add(signal_id)
        outcomes.append(str(assessment["_outcome"]))
        brand = _safe_brand(assessment.get("brand"))
        if brand is not None:
            brands.append(brand)
        raw_evidence = assessment.get("evidenceCodes")
        if isinstance(raw_evidence, list):
            evidence.extend(
                item for item in raw_evidence if isinstance(item, str) and item in EVIDENCE_CODES
            )
        disposition = assessment.get("dispositionReason")
        if isinstance(disposition, str) and disposition in ASSESSMENT_REASONS:
            dispositions.append(disposition)
        history_signal = history_by_id.get(signal_id)
        if history_signal is not None:
            linked_assessments += 1
            linked_sources.extend(cast(list[str], history_signal["sources"]))
            linked_reasons.extend(cast(list[str], history_signal["reasonCodes"]))
        previous = earliest_review_by_signal.get(signal_id)
        if previous is None or reviewed_at < previous:
            earliest_review_by_signal[signal_id] = reviewed_at

    latency_hours: list[float] = []
    for signal_id, reviewed_at in earliest_review_by_signal.items():
        history_signal = history_by_id.get(signal_id)
        first_seen = history_signal.get("firstSeen") if history_signal else None
        if isinstance(first_seen, datetime) and first_seen <= reviewed_at:
            latency_hours.append((reviewed_at - first_seen).total_seconds() / 3_600)

    eligible_signal_ids: set[str] = set()
    for signal_id, signal in history_by_id.items():
        first_seen = signal.get("firstSeen")
        if isinstance(first_seen, datetime) and window_start <= first_seen <= generated:
            eligible_signal_ids.add(signal_id)
    assessed_eligible = assessment_signal_ids & eligible_signal_ids

    raw_suppressions = review_export.get("suppressions")
    suppressions = (
        [
            item
            for item in raw_suppressions[:2_500]
            if isinstance(item, dict)
            and item.get("scope") in {"exact", "subdomains"}
            and isinstance(item.get("reasonCode"), str)
            and item["reasonCode"] in SUPPRESSION_REASONS
        ]
        if isinstance(raw_suppressions, list)
        else []
    )
    suppression_reasons = [
        reason
        for suppression in suppressions
        for reason in [suppression.get("reasonCode")]
        if isinstance(reason, str) and reason in SUPPRESSION_REASONS
    ]
    exact_suppressions = sum(item.get("scope") == "exact" for item in suppressions)
    subtree_suppressions = sum(item.get("scope") == "subdomains" for item in suppressions)

    artifact: dict[str, object] = {
        "schemaVersion": 1,
        "dataset": "radar-quality-metrics",
        "generatedAt": generated_at,
        "window": {
            "days": window_days,
            "from": window_start.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "to": generated_at,
        },
        "semantics": (
            "Review metrics describe the bounded public analyst sample, not the accuracy of all Radar "
            "candidates and not phishing prevalence in Lithuania."
        ),
        "reviewSample": {
            "assessments": len(assessments),
            "uniqueSignals": len(assessment_signal_ids),
            "outcomes": _counts(outcomes),
            "byBrand": _counts(brands),
            "bySource": _counts(linked_sources),
            "sourceLinkedAssessments": linked_assessments,
            "byEvidence": _counts(evidence),
            "byDispositionReason": _counts(dispositions),
            "byDetectionReason": _counts(linked_reasons),
        },
        "reviewCoverage": {
            "eligiblePublishedSignals": len(eligible_signal_ids),
            "assessedSignals": len(assessed_eligible),
            "percent": _percentage(len(assessed_eligible), len(eligible_signal_ids)),
            "scope": "Signals first published inside the stated window and represented in public history.",
        },
        "reviewLatencyHours": {
            "sampleSize": len(latency_hours),
            "median": round(float(median(latency_hours)), 2) if latency_hours else None,
            "p90": _percentile(latency_hours, 0.9),
            "minimum": round(min(latency_hours), 2) if latency_hours else None,
            "maximum": round(max(latency_hours), 2) if latency_hours else None,
            "scope": "First public observation to earliest supportable public assessment per signal.",
        },
        "currentExclusions": {
            "sampleSize": len(suppressions),
            "exact": exact_suppressions,
            "subdomainPolicies": subtree_suppressions,
            "byReason": _counts(suppression_reasons),
            "scope": "Current sanitized exclusions have no public decision timestamp and are not in timed metrics.",
        },
        "precision": {
            "available": False,
            "sampleSize": 0,
            "estimatePercent": None,
            "reason": (
                "Dated positive and negative outcomes are supported, but no completed probability sample or "
                "review census is linked to the current decisions. A population precision estimate would "
                "therefore be misleading."
            ),
        },
        "privacy": "Aggregate counters only; no domains, URLs, signal identifiers, analyst identity or private notes.",
    }
    return artifact
