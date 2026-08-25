from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

from .brands import BrandEntry, BrandRegistry, load_brand_registry, score_domain
from .provenance import reason_codes_from_match

MAXIMUM_JSON_BYTES = 16 * 1024 * 1024
MAXIMUM_CERTSTREAM_FILE_BYTES = 2 * 1024 * 1024
MAXIMUM_CERTSTREAM_TOTAL_BYTES = 32 * 1024 * 1024
MAXIMUM_CERTSTREAM_FILES = 100
MAXIMUM_CERTSTREAM_ROWS = 100_000
MAXIMUM_CERTSTREAM_LINE_BYTES = 32 * 1024
CERTSTREAM_COVERAGE_DAYS = 90


def _timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00").astimezone(UTC)
    except ValueError:
        return None
    canonical = parsed.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return parsed if canonical == value else None


def _latest(values: list[object]) -> str | None:
    timestamps = [(parsed, value) for value in values if (parsed := _timestamp(value)) is not None]
    return cast(str, max(timestamps)[1]) if timestamps else None


def _revision(entry: BrandEntry) -> str:
    value = {
        "brand": entry.brand,
        "lastReviewedAt": entry.last_reviewed_at,
        "aliases": entry.aliases,
        "fuzzyAliases": entry.fuzzy_aliases,
        "excludedTerms": entry.excluded_terms,
        "excludedDomains": entry.excluded_domains,
        "category": entry.category,
        "officialDomains": entry.official_domains,
        "sources": entry.sources,
    }
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()[:16]


def _corpus_passes(case: dict[str, object], registry: BrandRegistry) -> bool:
    domain = case.get("domain")
    expected = case.get("expected")
    if not isinstance(domain, str) or not isinstance(expected, dict) or not isinstance(expected.get("matched"), bool):
        return False
    match = score_domain(domain, registry)
    if not expected["matched"]:
        return match is None
    if match is None or match.brand != expected.get("brand"):
        return False
    score_band = expected.get("scoreBand")
    reasons = expected.get("reasonCodes")
    return (
        isinstance(score_band, list)
        and len(score_band) == 2
        and all(isinstance(value, int) for value in score_band)
        and score_band[0] <= match.confidence <= score_band[1]
        and isinstance(reasons, list)
        and set(value for value in reasons if isinstance(value, str)) <= set(reason_codes_from_match(match.reasons))
    )


def build_brand_coverage(
    registry: BrandRegistry,
    *,
    ct_state: dict[str, object],
    certstream_candidates: list[dict[str, object]],
    asset_state: dict[str, object],
    hunt_state: dict[str, object],
    review_export: dict[str, object],
    matcher_corpus: dict[str, object],
    generated_at: str,
) -> dict[str, object]:
    generated = _timestamp(generated_at)
    if generated is None:
        raise ValueError("Coverage ledger generatedAt must be canonical UTC with milliseconds.")
    recent_asset_cutoff = generated - timedelta(days=45)
    raw_queries = ct_state.get("queries")
    queries = raw_queries if isinstance(raw_queries, dict) else {}
    raw_assets = asset_state.get("assets")
    assets = raw_assets if isinstance(raw_assets, list) else []
    raw_assessments = review_export.get("assessments")
    assessments = raw_assessments if isinstance(raw_assessments, list) else []
    raw_suppressions = review_export.get("suppressions")
    suppressions = raw_suppressions if isinstance(raw_suppressions, list) else []
    raw_cases = matcher_corpus.get("cases")
    corpus_cases = raw_cases if isinstance(raw_cases, list) else []
    latest_certstream_by_brand: dict[str, str] = {}
    for candidate in certstream_candidates:
        brand = candidate.get("brand")
        observed_at = candidate.get("observedAt")
        if not isinstance(brand, str) or _timestamp(observed_at) is None:
            continue
        previous = latest_certstream_by_brand.get(brand)
        if previous is None or cast(str, observed_at) > previous:
            latest_certstream_by_brand[brand] = cast(str, observed_at)

    records: list[dict[str, object]] = []
    for entry in registry.entries:
        brand_queries = [
            value
            for value in queries.values()
            if isinstance(value, dict) and value.get("brand") == entry.brand
        ]
        completed_queries = [value for value in brand_queries if value.get("lastOutcome") == "completed"]
        query_outcomes: Counter[str] = Counter(
            cast(str, value["lastOutcome"])
            for value in brand_queries
            if value.get("lastOutcome") in {"completed", "partial", "failed"}
        )
        never_attempted_queries = sum(_timestamp(value.get("lastRunAt")) is None for value in brand_queries)
        cursor_advanced_queries = sum(
            isinstance(value.get("lastId"), int) and cast(int, value["lastId"]) > 0
            for value in brand_queries
        )
        if not brand_queries:
            bounded_poll_state = "not-configured"
        elif query_outcomes["partial"]:
            bounded_poll_state = "backlogged"
        elif query_outcomes["failed"]:
            bounded_poll_state = "failed"
        elif never_attempted_queries:
            bounded_poll_state = "never-attempted"
        elif query_outcomes["completed"] == len(brand_queries):
            bounded_poll_state = "completed"
        else:
            bounded_poll_state = "incomplete"
        latest_ct_success = _latest([value.get("lastRunAt") for value in completed_queries])
        latest_certstream = latest_certstream_by_brand.get(entry.brand)

        brand_assets = [value for value in assets if isinstance(value, dict) and value.get("brand") == entry.brand]
        supported_assets = 0
        asset_support: list[dict[str, object]] = []
        for asset in brand_assets:
            scans = asset.get("supportingScans")
            scans = scans if isinstance(scans, list) else []
            recent_scan_ids = {
                scan_id
                for scan in scans
                if isinstance(scan, dict)
                and isinstance((scan_id := scan.get("scanId")), str)
                and (observed := _timestamp(scan.get("observedAt"))) is not None
                and observed >= recent_asset_cutoff
            }
            has_two_recent_scans = len(recent_scan_ids) >= 2
            if has_two_recent_scans:
                supported_assets += 1
            sha256 = asset.get("sha256")
            resource_type = asset.get("resourceType")
            if isinstance(sha256, str):
                asset_support.append(
                    {
                        "sha256": sha256,
                        "resourceType": resource_type if isinstance(resource_type, str) else None,
                        "twoRecentOfficialScans": has_two_recent_scans,
                    }
                )

        outcomes: Counter[str] = Counter()
        outcomes["suppressed"] = sum(
            isinstance(suppression, dict) and suppression.get("brand") == entry.brand
            for suppression in suppressions
        )
        for assessment in assessments:
            if not isinstance(assessment, dict) or assessment.get("brand") != entry.brand:
                continue
            if assessment.get("revoked") is True:
                outcomes["retracted"] += 1
            elif isinstance((state := assessment.get("reviewState")), str):
                outcomes[state] += 1
                if (
                    isinstance(assessment.get("reviewedAt"), str)
                    and isinstance(assessment.get("modifiedAt"), str)
                    and assessment["reviewedAt"] != assessment["modifiedAt"]
                ):
                    outcomes["corrected"] += 1

        brand_cases = [case for case in corpus_cases if isinstance(case, dict) and case.get("brand") == entry.brand]
        passed_cases = sum(_corpus_passes(case, registry) for case in brand_cases)
        records.append(
            {
                "brand": entry.brand,
                "registryRevision": _revision(entry),
                "lastReviewedAt": entry.last_reviewed_at,
                "registry": {
                    "aliases": len(entry.aliases),
                    "officialDomains": len(entry.official_domains),
                    "authoritativeSources": len(entry.sources),
                    "excludedTerms": len(entry.excluded_terms),
                    "excludedDomains": len(entry.excluded_domains),
                },
                "ctSearch": {
                    "configuredQueries": len(brand_queries),
                    "latestBoundedPollState": bounded_poll_state,
                    "completedQueries": query_outcomes["completed"],
                    "backloggedQueries": query_outcomes["partial"],
                    "failedQueries": query_outcomes["failed"],
                    "neverAttemptedQueries": never_attempted_queries,
                    "cursorAdvancedQueries": cursor_advanced_queries,
                    "lastAttemptAt": _latest([value.get("lastRunAt") for value in brand_queries]),
                    "lastSuccessfulQueryAt": latest_ct_success,
                },
                "certStream": {"latestMatchAt": latest_certstream},
                "urlscanAssets": {
                    "assetHashes": len(brand_assets),
                    "supportedByTwoRecentOfficialScans": supported_assets,
                    "allHashesHaveTwoRecentOfficialScans": bool(brand_assets) and supported_assets == len(brand_assets),
                    "lastValidatedAt": _latest([value.get("lastValidatedAt") for value in brand_assets]),
                    "hashSupport": sorted(asset_support, key=lambda value: cast(str, value["sha256"])),
                },
                "reviewOutcomes": {
                    state: count for state, count in sorted(outcomes.items()) if count > 0
                },
                "collisionCorpus": {
                    "cases": len(brand_cases),
                    "passing": passed_cases,
                    "status": (
                        "not-covered"
                        if not brand_cases
                        else "passing"
                        if passed_cases == len(brand_cases)
                        else "failing"
                    ),
                },
            }
        )

    return {
        "schemaVersion": 1,
        "dataset": "radar-brand-coverage-ledger",
        "generatedAt": generated_at,
        "registryReviewedAt": registry.reviewed_at,
        "semantics": (
            "Coverage describes bounded collector and review activity. Zero observed candidates is not "
            "evidence that no phishing exists."
        ),
        "globalCollectorState": {
            "semantics": "Scheduler-wide state below is not attributed to any individual brand.",
            "ctSearch": {
                "stateGeneratedAt": ct_state.get("generatedAt")
                if _timestamp(ct_state.get("generatedAt"))
                else None,
                "queryCursor": ct_state.get("queryCursor")
                if isinstance(ct_state.get("queryCursor"), int)
                else None,
                "configuredQueries": len(queries),
            },
            "urlscanHunt": {
                "stateGeneratedAt": hunt_state.get("generatedAt")
                if _timestamp(hunt_state.get("generatedAt"))
                else None,
                "lastRunAt": hunt_state.get("lastRunAt")
                if _timestamp(hunt_state.get("lastRunAt"))
                else None,
                "lastOutcome": hunt_state.get("lastOutcome")
                if hunt_state.get("lastOutcome")
                in {"completed", "budget-limited", "failed", "skipped-not-configured"}
                else None,
                "candidateCursor": hunt_state.get("candidateCursor")
                if isinstance(hunt_state.get("candidateCursor"), int)
                else None,
                "candidateCount": hunt_state.get("candidateCount")
                if isinstance(hunt_state.get("candidateCount"), int)
                else None,
            },
        },
        "unicodeProfile": matcher_corpus.get("unicodeProfile"),
        "brands": records,
    }


def read_bounded_json(path: Path, maximum_bytes: int = MAXIMUM_JSON_BYTES) -> dict[str, object]:
    if path.is_symlink():
        raise ValueError(f"{path} must not be a symbolic link.")
    try:
        size = path.stat().st_size
    except OSError as error:
        raise ValueError(f"{path} is unavailable.") from error
    if not path.is_file() or not 0 < size <= maximum_bytes:
        raise ValueError(f"{path} exceeds its bounded JSON input contract.")
    try:
        value: object = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{path} does not contain valid UTF-8 JSON.") from error
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain one JSON object.")
    return value


def read_recent_certstream_candidates(root: Path, generated_at: str) -> list[dict[str, object]]:
    generated = _timestamp(generated_at)
    if generated is None:
        raise ValueError("CertStream coverage requires a canonical generatedAt timestamp.")
    if root.is_symlink():
        raise ValueError("CertStream archive root must not be a symbolic link.")
    cutoff = generated.date() - timedelta(days=CERTSTREAM_COVERAGE_DAYS)
    selected: list[Path] = []
    for path in sorted(root.glob("*/domains.ndjson")):
        if path.is_symlink() or path.parent.is_symlink():
            raise ValueError(f"{path} must not be a symbolic link.")
        try:
            archive_date = datetime.strptime(path.parent.name, "%Y-%m-%d").date()
        except ValueError as error:
            raise ValueError(f"{path} has an invalid archive date directory.") from error
        if cutoff <= archive_date <= generated.date():
            selected.append(path)
    if len(selected) > MAXIMUM_CERTSTREAM_FILES:
        raise ValueError("CertStream coverage exceeds its bounded file count.")

    total_bytes = 0
    total_rows = 0
    latest_by_brand: dict[str, dict[str, object]] = {}
    for path in selected:
        try:
            size = path.stat().st_size
        except OSError as error:
            raise ValueError(f"{path} is unavailable.") from error
        total_bytes += size
        if not path.is_file() or size > MAXIMUM_CERTSTREAM_FILE_BYTES or total_bytes > MAXIMUM_CERTSTREAM_TOTAL_BYTES:
            raise ValueError("CertStream coverage exceeds its bounded byte budget.")
        try:
            handle = path.open("r", encoding="utf-8")
        except OSError as error:
            raise ValueError(f"{path} is unreadable.") from error
        with handle:
            for line_number, line in enumerate(handle, start=1):
                if len(line.encode("utf-8")) > MAXIMUM_CERTSTREAM_LINE_BYTES:
                    raise ValueError(f"{path}:{line_number} exceeds the bounded row size.")
                if not line.strip():
                    raise ValueError(f"{path}:{line_number} contains an empty NDJSON row.")
                total_rows += 1
                if total_rows > MAXIMUM_CERTSTREAM_ROWS:
                    raise ValueError("CertStream coverage exceeds its bounded row count.")
                try:
                    value: object = json.loads(line)
                except json.JSONDecodeError as error:
                    raise ValueError(f"{path}:{line_number} contains invalid NDJSON.") from error
                if not isinstance(value, dict):
                    raise ValueError(f"{path}:{line_number} must contain one JSON object.")
                brand = value.get("brand")
                observed_at = value.get("observedAt")
                if not isinstance(brand, str) or _timestamp(observed_at) is None:
                    raise ValueError(f"{path}:{line_number} lacks canonical brand observation fields.")
                previous = latest_by_brand.get(brand)
                if previous is None or cast(str, observed_at) > cast(str, previous["observedAt"]):
                    latest_by_brand[brand] = value
    return [latest_by_brand[brand] for brand in sorted(latest_by_brand)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate the per-brand Radar coverage ledger.")
    parser.add_argument("--generated-at", required=True)
    parser.add_argument("--output", type=Path, default=Path("data/coverage/brand-coverage.json"))
    options = parser.parse_args(argv)
    artifact = build_brand_coverage(
        load_brand_registry(),
        ct_state=read_bounded_json(Path("data/ct-search/state.json"), 8 * 1024 * 1024),
        certstream_candidates=read_recent_certstream_candidates(Path("data/certstream"), options.generated_at),
        asset_state=read_bounded_json(Path("data/urlscan/official-brand-assets.json"), 8 * 1024 * 1024),
        hunt_state=read_bounded_json(Path("data/urlscan/hunt-state.json"), 2 * 1024 * 1024),
        review_export=read_bounded_json(Path("data/review/public-decisions.json"), 2 * 1024 * 1024),
        matcher_corpus=read_bounded_json(Path("data/matcher/lithuanian-brands-v1.json"), 2 * 1024 * 1024),
        generated_at=options.generated_at,
    )
    options.output.parent.mkdir(parents=True, exist_ok=True)
    options.output.write_text(json.dumps(artifact, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(cast(list[object], artifact['brands']))} brand coverage records to {options.output}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
