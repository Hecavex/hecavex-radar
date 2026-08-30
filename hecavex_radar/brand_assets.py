from __future__ import annotations

import json
import os
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal, cast
from urllib.parse import urlsplit

from .brands import BrandEntry, BrandRegistry, load_brand_registry, normalize_domain
from .models import RadarSignal, RawDomainIntelligence
from .normalize import merge_signals
from .urlscan import (
    EMPTY_SHA256,
    PROVIDER_DAILY_RESULT_LIMIT,
    PROVIDER_DAILY_SEARCH_LIMIT,
    PROVIDER_MINUTE_LIMIT,
    SHA256,
    UUID,
    _bounded,
    _bounded_archive_root,
    _brand_evidence,
    _BudgetedRequester,
    _candidate_scan_url,
    _dictionary,
    _hostname,
    _page_url,
    _request_json,
    _result_urls,
    _safe_detail,
    _scan_uuid,
    _search,
    _signal_from_scan,
    _string,
    _timestamp,
    _verdict,
    write_urlscan_archive,
    write_urlscan_intelligence_archive,
)

AssetKind = Literal["favicon", "javascript"]

STATE_FILENAME = "official-brand-assets.json"
STATE_DATASET = "urlscan-official-brand-assets"
STATE_OUTCOMES = frozenset({"skipped-not-configured", "completed", "budget-limited", "failed"})
MAXIMUM_STATE_BYTES = 512 * 1024
MAXIMUM_ASSETS = 600
MAXIMUM_HASH_OWNERS = 600
MAXIMUM_BLOCKED_HASHES = 300
MAXIMUM_ASSET_AGE = timedelta(days=45)
MAXIMUM_FUTURE_SKEW = timedelta(minutes=5)
MAXIMUM_SUPPORTING_SCANS = 3
MAXIMUM_OFFICIAL_DOMAINS_PER_ASSET = 4
MAXIMUM_FAVICONS_PER_BRAND = 3
MAXIMUM_JAVASCRIPTS_PER_BRAND = 10
MAXIMUM_FAVICON_BYTES = 1024 * 1024
MAXIMUM_JAVASCRIPT_BYTES = 10 * 1024 * 1024
MINIMUM_FAVICON_BYTES = 32
MINIMUM_JAVASCRIPT_BYTES = 256


@dataclass(frozen=True, slots=True)
class _OfficialDomain:
    brand: str
    domain: str
    entry: BrandEntry


@dataclass(frozen=True, slots=True)
class _AssetObservation:
    brand: str
    official_domain: str
    resource_type: AssetKind
    sha256: str
    observed_at: str
    scan_id: str


@dataclass(frozen=True, slots=True)
class _AssetSupport:
    scan_id: str
    observed_at: str


@dataclass(frozen=True, slots=True)
class _AssetRecord:
    brand: str
    official_domains: tuple[str, ...]
    resource_type: AssetKind
    sha256: str
    first_seen: str
    last_seen: str
    last_validated_at: str
    supporting_scans: tuple[_AssetSupport, ...]


@dataclass(frozen=True, slots=True)
class _BlockedHash:
    sha256: str
    last_seen: str


@dataclass(frozen=True, slots=True)
class _HashOwner:
    sha256: str
    brand: str
    last_seen: str


@dataclass(slots=True)
class _AssetHuntResult:
    signals: list[RadarSignal]
    intelligence: list[RawDomainIntelligence]
    assets: list[_AssetRecord]
    hash_owners: list[_HashOwner]
    blocked_hashes: list[_BlockedHash]
    official_cursor: int
    asset_cursor: int
    official_count: int
    eligible_asset_count: int
    selected_official_domains: int
    selected_asset_hashes: int


def _reviewed_official_domains(registry: BrandRegistry) -> list[_OfficialDomain]:
    """Return every reviewed official domain in deterministic registry order.

    A brand can legitimately use several country or product domains. Sampling
    only the first one leaves the asset baseline biased toward a single site
    and can miss a favicon or JavaScript bundle used on another reviewed
    property. Ambiguous domains are still rejected later by
    :func:`_official_for_result` rather than being assigned to either brand.
    """
    return [
        _OfficialDomain(brand=entry.brand, domain=domain, entry=entry)
        for entry in registry.entries
        for domain in entry.official_domains
    ]


def _chunks[T](values: list[T], size: int) -> list[list[T]]:
    return [values[index : index + size] for index in range(0, len(values), size)]


def _rotating_window[T](values: list[T], cursor: int, maximum: int) -> tuple[list[T], int]:
    if not values or maximum <= 0:
        return [], 0
    start = max(0, cursor) % len(values)
    count = min(len(values), maximum)
    selected = [values[(start + offset) % len(values)] for offset in range(count)]
    return selected, (start + count) % len(values)


def _public_query(expression: str, lookback_days: int) -> str:
    return f"date:>now-{lookback_days}d AND task.visibility:public AND ({expression})"


def _official_domain_query(domains: list[str], lookback_days: int) -> str:
    normalized = list(dict.fromkeys(domain for value in domains if (domain := normalize_domain(value))))
    if not normalized:
        raise ValueError("An official-asset query requires at least one reviewed domain.")
    clauses = " OR ".join(
        clause for domain in normalized for clause in (f'task.domain:"{domain}"', f'page.domain:"{domain}"')
    )
    return _public_query(clauses, lookback_days)


def _belongs_to(value: str | None, domain: str) -> bool:
    host = normalize_domain(value or "")
    return host is not None and (host == domain or host.endswith(f".{domain}"))


def _brand_for_official_host(host: str | None, domains: list[_OfficialDomain]) -> _OfficialDomain | None:
    matches = [candidate for candidate in domains if _belongs_to(host, candidate.domain)]
    brands = {candidate.brand for candidate in matches}
    if len(brands) != 1:
        return None
    return max(matches, key=lambda candidate: len(candidate.domain))


def _official_for_result(result: dict[str, Any], domains: list[_OfficialDomain]) -> _OfficialDomain | None:
    matches = [
        candidate
        for value in _result_urls(result)
        if (host := _hostname(value)) is not None and (candidate := _brand_for_official_host(host, domains)) is not None
    ]
    brands = {candidate.brand for candidate in matches}
    return max(matches, key=lambda candidate: len(candidate.domain)) if len(brands) == 1 else None


def _integer(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _response_metadata(value: dict[str, Any]) -> tuple[str | None, str | None, str, int, int]:
    request_container = _dictionary(value.get("request"))
    request = _dictionary(request_container.get("request"))
    response = _dictionary(value.get("response"))
    metadata = _dictionary(response.get("response"))
    response_url = _string(metadata.get("url")) or _string(request.get("url"))
    digest = _string(response.get("hash"))
    mime = (_string(metadata.get("mimeType")) or "").lower()
    resource_type = _string(value.get("type")) or _string(request_container.get("type")) or _string(request.get("type"))
    status = _integer(metadata.get("status")) or _integer(response.get("status")) or 0
    size = (
        _integer(metadata.get("encodedDataLength"))
        or _integer(metadata.get("dataLength"))
        or _integer(response.get("size"))
        or 0
    )
    return response_url, digest, f"{mime}\n{(resource_type or '').lower()}", status, size


def _resource_kind(url: str, description: str, size: int) -> AssetKind | None:
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme not in {"http", "https"}
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 80, 443}
    ):
        return None
    path = parsed.path.lower()
    favicon_name = any(marker in path for marker in ("/favicon", "apple-touch-icon", "android-chrome-", "mstile-"))
    favicon_mime = any(marker in description for marker in ("image/x-icon", "image/vnd.microsoft.icon"))
    if (favicon_name or favicon_mime) and MINIMUM_FAVICON_BYTES <= size <= MAXIMUM_FAVICON_BYTES:
        return "favicon"
    javascript = "script" in description or "javascript" in description or "ecmascript" in description
    if javascript and MINIMUM_JAVASCRIPT_BYTES <= size <= MAXIMUM_JAVASCRIPT_BYTES:
        return "javascript"
    return None


def _scan_time(detail: dict[str, Any], now: datetime) -> str | None:
    value = _string(_dictionary(detail.get("task")).get("time"))
    if value:
        try:
            observed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if observed.tzinfo is not None:
                observed_utc = observed.astimezone(UTC)
                reference = now.astimezone(UTC)
                if reference - MAXIMUM_ASSET_AGE <= observed_utc <= reference + MAXIMUM_FUTURE_SKEW:
                    return _timestamp(observed_utc)
        except ValueError:
            pass
    return None


def _extract_official_assets(
    detail: dict[str, Any],
    official: _OfficialDomain,
    scan_id: str,
    now: datetime,
) -> list[_AssetObservation]:
    page_host = _hostname(_page_url(detail) or "")
    if not any(_belongs_to(page_host, domain) for domain in official.entry.official_domains):
        return []
    requests = _dictionary(detail.get("data")).get("requests")
    if not isinstance(requests, list):
        return []

    observed_at = _scan_time(detail, now)
    if observed_at is None:
        return []
    observations: list[_AssetObservation] = []
    per_kind: dict[AssetKind, int] = {"favicon": 0, "javascript": 0}
    limits: dict[AssetKind, int] = {"favicon": 3, "javascript": 12}
    seen_hashes: set[tuple[AssetKind, str]] = set()
    for raw in requests:
        item = _dictionary(raw)
        response_url, digest, description, status, size = _response_metadata(item)
        host = _hostname(response_url or "")
        if (
            response_url is None
            or host is None
            or not any(_belongs_to(host, domain) for domain in official.entry.official_domains)
            or not 200 <= status < 300
            or digest is None
            or digest.lower() == EMPTY_SHA256
            or not SHA256.fullmatch(digest)
        ):
            continue
        kind = _resource_kind(response_url, description, size)
        normalized_digest = digest.lower()
        asset_key = (kind, normalized_digest) if kind is not None else None
        if kind is None or asset_key in seen_hashes or per_kind[kind] >= limits[kind]:
            continue
        seen_hashes.add((kind, normalized_digest))
        observations.append(
            _AssetObservation(
                brand=official.brand,
                official_domain=official.domain,
                resource_type=kind,
                sha256=normalized_digest,
                observed_at=observed_at,
                scan_id=scan_id,
            )
        )
        per_kind[kind] += 1
    return list(
        {
            (observation.brand, observation.resource_type, observation.sha256): observation
            for observation in observations
        }.values()
    )


def _asset_hash_present(detail: dict[str, Any], digest: str, kind: AssetKind) -> bool:
    requests = _dictionary(detail.get("data")).get("requests")
    if not isinstance(requests, list):
        return False
    for raw in requests:
        response_url, candidate, description, status, size = _response_metadata(_dictionary(raw))
        if (
            response_url is not None
            and candidate is not None
            and candidate.lower() == digest
            and 200 <= status < 300
            and _resource_kind(response_url, description, size) == kind
        ):
            return True
    return False


def _parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or _timestamp(parsed) != value:
        raise ValueError("Asset state contains a non-canonical timestamp.")
    return parsed.astimezone(UTC)


def _merge_assets(
    current: list[_AssetRecord],
    observations: list[_AssetObservation],
    hash_owners: list[_HashOwner],
    blocked_hashes: list[_BlockedHash],
    now: datetime,
) -> tuple[list[_AssetRecord], list[_HashOwner], list[_BlockedHash]]:
    cutoff = now.astimezone(UTC) - MAXIMUM_ASSET_AGE
    blocked = {
        item.sha256: item for item in blocked_hashes if _parse_timestamp(item.last_seen) >= cutoff
    }
    owners = {
        item.sha256: item
        for item in hash_owners
        if _parse_timestamp(item.last_seen) >= cutoff and item.sha256 not in blocked
    }
    combined: dict[tuple[str, AssetKind, str], _AssetRecord] = {}

    def block_digest(digest: str, last_seen: str) -> None:
        existing = blocked.get(digest)
        blocked[digest] = _BlockedHash(
            sha256=digest,
            last_seen=max(existing.last_seen, last_seen) if existing else last_seen,
        )
        owners.pop(digest, None)
        for key in [key for key in combined if key[2] == digest]:
            combined.pop(key, None)

    def register_owner(digest: str, brand: str, last_seen: str) -> bool:
        existing_block = blocked.get(digest)
        if existing_block is not None:
            block_digest(digest, max(existing_block.last_seen, last_seen))
            return False
        owner = owners.get(digest)
        if owner is None:
            owners[digest] = _HashOwner(sha256=digest, brand=brand, last_seen=last_seen)
            return True
        if owner.brand != brand:
            block_digest(digest, max(owner.last_seen, last_seen))
            return False
        owners[digest] = _HashOwner(sha256=digest, brand=brand, last_seen=max(owner.last_seen, last_seen))
        return True

    for item in current:
        active_supports = tuple(
            support for support in item.supporting_scans if _parse_timestamp(support.observed_at) >= cutoff
        )
        if not active_supports:
            continue
        first_seen = min(support.observed_at for support in active_supports)
        last_seen = max(support.observed_at for support in active_supports)
        if register_owner(item.sha256, item.brand, last_seen):
            combined[(item.brand, item.resource_type, item.sha256)] = _AssetRecord(
                brand=item.brand,
                official_domains=item.official_domains,
                resource_type=item.resource_type,
                sha256=item.sha256,
                first_seen=first_seen,
                last_seen=last_seen,
                last_validated_at=item.last_validated_at,
                supporting_scans=active_supports,
            )

    validated_at = _timestamp(now)
    for observation in observations:
        if _parse_timestamp(observation.observed_at) < cutoff:
            continue
        if not register_owner(observation.sha256, observation.brand, observation.observed_at):
            continue
        key = (observation.brand, observation.resource_type, observation.sha256)
        existing = combined.get(key)
        if existing is None:
            combined[key] = _AssetRecord(
                brand=observation.brand,
                official_domains=(observation.official_domain,),
                resource_type=observation.resource_type,
                sha256=observation.sha256,
                first_seen=observation.observed_at,
                last_seen=observation.observed_at,
                last_validated_at=validated_at,
                supporting_scans=(_AssetSupport(observation.scan_id, observation.observed_at),),
            )
            continue
        supports = {support.scan_id: support for support in existing.supporting_scans}
        support = supports.get(observation.scan_id)
        if support is None or observation.observed_at > support.observed_at:
            supports[observation.scan_id] = _AssetSupport(observation.scan_id, observation.observed_at)
        active_supports = tuple(
            sorted(supports.values(), key=lambda item: (item.observed_at, item.scan_id), reverse=True)[
                :MAXIMUM_SUPPORTING_SCANS
            ]
        )
        combined[key] = _AssetRecord(
            brand=existing.brand,
            official_domains=tuple(dict.fromkeys([*existing.official_domains, observation.official_domain]))[
                -MAXIMUM_OFFICIAL_DOMAINS_PER_ASSET:
            ],
            resource_type=existing.resource_type,
            sha256=existing.sha256,
            first_seen=min(item.observed_at for item in active_supports),
            last_seen=max(item.observed_at for item in active_supports),
            last_validated_at=validated_at,
            supporting_scans=active_supports,
        )

    fresh = list(combined.values())
    grouped: dict[tuple[str, AssetKind], list[_AssetRecord]] = defaultdict(list)
    for item in fresh:
        grouped[(item.brand, item.resource_type)].append(item)
    bounded: list[_AssetRecord] = []
    for (_, kind), values in grouped.items():
        limit = MAXIMUM_FAVICONS_PER_BRAND if kind == "favicon" else MAXIMUM_JAVASCRIPTS_PER_BRAND
        bounded.extend(
            sorted(
                values,
                key=lambda item: (
                    len(item.supporting_scans),
                    item.last_validated_at,
                    item.last_seen,
                    item.sha256,
                ),
                reverse=True,
            )[:limit]
        )
    assets = sorted(bounded, key=lambda item: (item.brand.casefold(), item.resource_type, item.sha256))[:MAXIMUM_ASSETS]
    asset_digests = {item.sha256 for item in assets}
    retained_owners = sorted(
        (item for item in owners.values() if item.sha256 not in asset_digests),
        key=lambda item: (item.last_seen, item.sha256),
        reverse=True,
    )[:MAXIMUM_HASH_OWNERS]
    retained_blocks = sorted(blocked.values(), key=lambda item: (item.last_seen, item.sha256), reverse=True)[
        :MAXIMUM_BLOCKED_HASHES
    ]
    return assets, retained_owners, retained_blocks


def _eligible_assets(assets: list[_AssetRecord]) -> list[_AssetRecord]:
    return [asset for asset in assets if len(asset.supporting_scans) >= 2]


def _request_counter(requester: Any, name: str) -> int | None:
    value = getattr(requester, name, None)
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _request_was_blocked(requester: Any, name: str, before: int | None) -> bool:
    after = _request_counter(requester, name)
    return before is not None and after == before and bool(getattr(requester, "exhausted", False))


def hunt_official_asset_hashes(
    api_key: str,
    now: datetime,
    requester: Any,
    registry: BrandRegistry,
    current_assets: list[_AssetRecord],
    current_hash_owners: list[_HashOwner],
    current_blocked_hashes: list[_BlockedHash],
    *,
    official_cursor: int,
    asset_cursor: int,
) -> _AssetHuntResult:
    """Derive and pivot hashes using only existing public URLScan reports."""
    lookback = _bounded(os.environ.get("URLSCAN_ASSET_LOOKBACK_DAYS"), 30, 1, 90)
    official_limit = _bounded(os.environ.get("URLSCAN_ASSET_OFFICIAL_DOMAINS_PER_RUN"), 20, 1, 500)
    official_batch = _bounded(os.environ.get("URLSCAN_ASSET_OFFICIAL_BATCH_SIZE"), 1, 1, 20)
    official_search_size = _bounded(os.environ.get("URLSCAN_ASSET_OFFICIAL_SEARCH_LIMIT"), 100, 1, 200)
    official_detail_limit = _bounded(os.environ.get("URLSCAN_ASSET_OFFICIAL_DETAIL_LIMIT"), 40, 1, 80)
    pivots_per_run = _bounded(os.environ.get("URLSCAN_ASSET_HASHES_PER_RUN"), 12, 1, 20)
    pivot_search_size = _bounded(os.environ.get("URLSCAN_ASSET_HASH_RESULT_LIMIT"), 5, 1, 50)
    pivot_detail_limit = _bounded(os.environ.get("URLSCAN_ASSET_HASH_DETAIL_LIMIT"), 60, 1, 80)

    official_domains = _reviewed_official_domains(registry)
    official_start = max(0, official_cursor) % len(official_domains) if official_domains else 0
    selected_official, _ = _rotating_window(official_domains, official_cursor, official_limit)
    attempted_official_domains = 0
    observations: list[_AssetObservation] = []
    processed_official: set[str] = set()
    official_detail_attempts = 0
    per_domain_attempts: dict[str, int] = defaultdict(int)
    per_domain_scans: dict[str, int] = defaultdict(int)
    for batch in _chunks(selected_official, official_batch):
        if official_detail_attempts >= official_detail_limit:
            break
        query = _official_domain_query([candidate.domain for candidate in batch], lookback)
        search_before = _request_counter(requester, "run_search_requests")
        search_results = _search(query, official_search_size, api_key, requester)
        if _request_was_blocked(requester, "run_search_requests", search_before):
            break
        batch_complete = True
        for result in search_results:
            if official_detail_attempts >= official_detail_limit:
                batch_complete = False
                break
            scan_id = _scan_uuid(result)
            official = _official_for_result(result, batch)
            if (
                scan_id is None
                or scan_id in processed_official
                or official is None
                or per_domain_attempts[official.domain] >= 4
                or per_domain_scans[official.domain] >= 2
            ):
                continue
            per_domain_attempts[official.domain] += 1
            official_detail_attempts += 1
            result_before = _request_counter(requester, "run_result_requests")
            fetched = _safe_detail(result, api_key, requester)
            if fetched is None and _request_was_blocked(requester, "run_result_requests", result_before):
                batch_complete = False
                break
            if fetched is None:
                continue
            processed_official.add(scan_id)
            _, detail = fetched
            extracted = _extract_official_assets(detail, official, scan_id, now)
            if extracted:
                per_domain_scans[official.domain] += 1
                observations.extend(extracted)
        if not batch_complete:
            break
        attempted_official_domains += len(batch)

    next_official_cursor = (
        (official_start + attempted_official_domains) % len(official_domains) if official_domains else 0
    )

    assets, hash_owners, blocked_hashes = _merge_assets(
        current_assets,
        observations,
        current_hash_owners,
        current_blocked_hashes,
        now,
    )
    eligible = _eligible_assets(assets)
    asset_start = max(0, asset_cursor) % len(eligible) if eligible else 0
    selected_assets, _ = _rotating_window(eligible, asset_cursor, pivots_per_run)
    attempted_asset_hashes = 0
    processed_candidates: set[tuple[str, str]] = set()
    detail_cache: dict[str, dict[str, Any]] = {}
    signals: list[RadarSignal] = []
    intelligence: list[RawDomainIntelligence] = []
    candidate_details = 0
    for asset in selected_assets:
        if candidate_details >= pivot_detail_limit:
            break
        query = _public_query(f"hash:{asset.sha256}", lookback)
        search_before = _request_counter(requester, "run_search_requests")
        search_results = _search(query, pivot_search_size, api_key, requester)
        if _request_was_blocked(requester, "run_search_requests", search_before):
            break
        hash_complete = True
        for result in search_results:
            if candidate_details >= pivot_detail_limit:
                hash_complete = False
                break
            scan_id = _scan_uuid(result)
            candidate_url = _candidate_scan_url(result, {}, registry)
            if (
                scan_id is None
                or (scan_id, asset.sha256) in processed_candidates
                or candidate_url is None
            ):
                continue
            processed_candidates.add((scan_id, asset.sha256))
            candidate_detail = detail_cache.get(scan_id)
            if candidate_detail is None:
                result_before = _request_counter(requester, "run_result_requests")
                fetched = _safe_detail(result, api_key, requester)
                if fetched is None and _request_was_blocked(requester, "run_result_requests", result_before):
                    hash_complete = False
                    break
                if fetched is None:
                    continue
                _, candidate_detail = fetched
                detail_cache[scan_id] = candidate_detail
                candidate_details += 1
            matched_url = _candidate_scan_url(result, candidate_detail, registry)
            if (
                matched_url is None
                or not _asset_hash_present(candidate_detail, asset.sha256, asset.resource_type)
            ):
                continue
            # A scan can have a legitimate or unrelated tasked URL. For this
            # pivot, domain evidence must belong to the candidate URL itself.
            evidence = _brand_evidence(result, candidate_detail, asset.brand, registry, matched_url=matched_url)
            verdict = _verdict(candidate_detail)
            independently_qualified = evidence.domain or evidence.verdict or (evidence.title and verdict.phishing)
            if evidence.conflicting or not independently_qualified:
                continue
            base_confidence = 94 if evidence.verdict else 88 if evidence.domain else 84
            if verdict.phishing:
                base_confidence = max(base_confidence, 96)
            signal = _signal_from_scan(
                result,
                candidate_detail,
                matched_url,
                asset.brand,
                base_confidence,
                now,
                registry,
                evidence,
                intelligence_sink=intelligence,
            )
            if signal is not None:
                signals.append(signal)
        if not hash_complete:
            break
        attempted_asset_hashes += 1

    next_asset_cursor = (asset_start + attempted_asset_hashes) % len(eligible) if eligible else 0

    return _AssetHuntResult(
        signals=merge_signals(signals, 500),
        intelligence=intelligence,
        assets=assets,
        hash_owners=hash_owners,
        blocked_hashes=blocked_hashes,
        official_cursor=next_official_cursor,
        asset_cursor=next_asset_cursor,
        official_count=len(official_domains),
        eligible_asset_count=len(eligible),
        selected_official_domains=attempted_official_domains,
        selected_asset_hashes=attempted_asset_hashes,
    )


def _record_to_json(record: _AssetRecord) -> dict[str, object]:
    return {
        "brand": record.brand,
        "officialDomains": list(record.official_domains),
        "resourceType": record.resource_type,
        "sha256": record.sha256,
        "firstSeen": record.first_seen,
        "lastSeen": record.last_seen,
        "lastValidatedAt": record.last_validated_at,
        "supportingScans": [
            {"scanId": support.scan_id, "observedAt": support.observed_at}
            for support in record.supporting_scans
        ],
    }


def _blocked_hash_to_json(record: _BlockedHash) -> dict[str, str]:
    return {"sha256": record.sha256, "lastSeen": record.last_seen}


def _hash_owner_to_json(record: _HashOwner) -> dict[str, str]:
    return {"sha256": record.sha256, "brand": record.brand, "lastSeen": record.last_seen}


def _state_path(root: str | Path) -> Path:
    return _bounded_archive_root(root) / STATE_FILENAME


def _validated_asset(value: object, registry: BrandRegistry, now: datetime) -> _AssetRecord | None:
    if not isinstance(value, dict) or set(value) != {
        "brand",
        "officialDomains",
        "resourceType",
        "sha256",
        "firstSeen",
        "lastSeen",
        "lastValidatedAt",
        "supportingScans",
    }:
        return None
    brand = value.get("brand")
    kind = value.get("resourceType")
    digest = value.get("sha256")
    official_domains = value.get("officialDomains")
    supporting_scans = value.get("supportingScans")
    entry = next((candidate for candidate in registry.entries if candidate.brand == brand), None)
    if (
        entry is None
        or kind not in {"favicon", "javascript"}
        or not isinstance(digest, str)
        or digest != digest.lower()
        or digest == EMPTY_SHA256
        or not SHA256.fullmatch(digest)
        or not isinstance(official_domains, list)
        or not 1 <= len(official_domains) <= MAXIMUM_OFFICIAL_DOMAINS_PER_ASSET
        or len(set(official_domains)) != len(official_domains)
        or not all(isinstance(domain, str) and domain in entry.official_domains for domain in official_domains)
        or not isinstance(supporting_scans, list)
        or not 1 <= len(supporting_scans) <= MAXIMUM_SUPPORTING_SCANS
    ):
        return None
    supports: list[_AssetSupport] = []
    for raw_support in supporting_scans:
        if not isinstance(raw_support, dict) or set(raw_support) != {"scanId", "observedAt"}:
            return None
        scan_id = raw_support.get("scanId")
        observed_at = raw_support.get("observedAt")
        if not isinstance(scan_id, str) or not UUID.fullmatch(scan_id) or not isinstance(observed_at, str):
            return None
        try:
            observed = _parse_timestamp(observed_at)
        except ValueError:
            return None
        if observed > now.astimezone(UTC) + MAXIMUM_FUTURE_SKEW:
            return None
        supports.append(_AssetSupport(scan_id=scan_id, observed_at=observed_at))
    if len({support.scan_id for support in supports}) != len(supports):
        return None
    timestamps = [value.get(field) for field in ("firstSeen", "lastSeen", "lastValidatedAt")]
    if not all(isinstance(timestamp, str) for timestamp in timestamps):
        return None
    try:
        first_seen, last_seen, validated = [_parse_timestamp(cast(str, timestamp)) for timestamp in timestamps]
    except ValueError:
        return None
    reference = now.astimezone(UTC)
    if (
        first_seen > last_seen
        or last_seen > reference + MAXIMUM_FUTURE_SKEW
        or validated > reference + MAXIMUM_FUTURE_SKEW
        or any(not first_seen <= _parse_timestamp(support.observed_at) <= last_seen for support in supports)
        or first_seen != min(_parse_timestamp(support.observed_at) for support in supports)
        or last_seen != max(_parse_timestamp(support.observed_at) for support in supports)
    ):
        return None
    return _AssetRecord(
        brand=cast(str, brand),
        official_domains=tuple(cast(list[str], official_domains)),
        resource_type=cast(AssetKind, kind),
        sha256=digest,
        first_seen=cast(str, timestamps[0]),
        last_seen=cast(str, timestamps[1]),
        last_validated_at=cast(str, timestamps[2]),
        supporting_scans=tuple(supports),
    )


def _validated_blocked_hash(value: object, now: datetime) -> _BlockedHash | None:
    if not isinstance(value, dict) or set(value) != {"sha256", "lastSeen"}:
        return None
    digest = value.get("sha256")
    last_seen = value.get("lastSeen")
    if (
        not isinstance(digest, str)
        or digest != digest.lower()
        or digest == EMPTY_SHA256
        or not SHA256.fullmatch(digest)
        or not isinstance(last_seen, str)
    ):
        return None
    try:
        observed = _parse_timestamp(last_seen)
    except ValueError:
        return None
    if observed > now.astimezone(UTC) + MAXIMUM_FUTURE_SKEW:
        return None
    return _BlockedHash(sha256=digest, last_seen=last_seen)


def _validated_hash_owner(value: object, registry: BrandRegistry, now: datetime) -> _HashOwner | None:
    if not isinstance(value, dict) or set(value) != {"sha256", "brand", "lastSeen"}:
        return None
    digest = value.get("sha256")
    brand = value.get("brand")
    last_seen = value.get("lastSeen")
    if (
        not isinstance(digest, str)
        or digest != digest.lower()
        or digest == EMPTY_SHA256
        or not SHA256.fullmatch(digest)
        or not isinstance(brand, str)
        or brand not in {entry.brand for entry in registry.entries}
        or not isinstance(last_seen, str)
    ):
        return None
    try:
        observed = _parse_timestamp(last_seen)
    except ValueError:
        return None
    if observed > now.astimezone(UTC) + MAXIMUM_FUTURE_SKEW:
        return None
    return _HashOwner(sha256=digest, brand=brand, last_seen=last_seen)


def _read_state(root: str | Path, registry: BrandRegistry, now: datetime) -> dict[str, Any] | None:
    path = _state_path(root)
    try:
        if path.stat().st_size > MAXIMUM_STATE_BYTES:
            raise ValueError("Official brand asset state exceeds 512 KiB.")
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("Official brand asset state is unreadable.") from error
    if not isinstance(payload, dict) or set(payload) != {
        "schemaVersion",
        "dataset",
        "generatedAt",
        "configured",
        "budgetDay",
        "searchRequests",
        "resultRequests",
        "officialCursor",
        "assetCursor",
        "officialCount",
        "eligibleAssetCount",
        "selectedOfficialDomains",
        "selectedAssetHashes",
        "lastOutcome",
        "lastRunSearchRequests",
        "lastRunResultRequests",
        "assets",
        "hashOwners",
        "blockedHashes",
    }:
        raise ValueError("Official brand asset state has an unexpected contract.")
    integer_fields = (
        "searchRequests",
        "resultRequests",
        "officialCursor",
        "assetCursor",
        "officialCount",
        "eligibleAssetCount",
        "selectedOfficialDomains",
        "selectedAssetHashes",
        "lastRunSearchRequests",
        "lastRunResultRequests",
    )
    assets = payload.get("assets")
    hash_owners = payload.get("hashOwners")
    blocked_hashes = payload.get("blockedHashes")
    if (
        payload.get("schemaVersion") != 1
        or payload.get("dataset") != STATE_DATASET
        or not isinstance(payload.get("configured"), bool)
        or payload.get("lastOutcome") not in STATE_OUTCOMES
        or not all(
            isinstance(payload.get(field), int) and not isinstance(payload.get(field), bool) for field in integer_fields
        )
        or not isinstance(assets, list)
        or len(assets) > MAXIMUM_ASSETS
        or not isinstance(hash_owners, list)
        or len(hash_owners) > MAXIMUM_HASH_OWNERS
        or not isinstance(blocked_hashes, list)
        or len(blocked_hashes) > MAXIMUM_BLOCKED_HASHES
        or not isinstance(payload.get("generatedAt"), str)
        or not isinstance(payload.get("budgetDay"), str)
    ):
        raise ValueError("Official brand asset state has invalid fields.")
    try:
        generated = _parse_timestamp(payload["generatedAt"])
        if datetime.fromisoformat(payload["budgetDay"]).date().isoformat() != payload["budgetDay"]:
            raise ValueError
    except ValueError as error:
        raise ValueError("Official brand asset state has invalid timestamps.") from error
    if generated > now.astimezone(UTC) + MAXIMUM_FUTURE_SKEW:
        raise ValueError("Official brand asset state is future-dated.")
    search_requests = cast(int, payload["searchRequests"])
    result_requests = cast(int, payload["resultRequests"])
    official_cursor = cast(int, payload["officialCursor"])
    asset_cursor = cast(int, payload["assetCursor"])
    official_count = cast(int, payload["officialCount"])
    eligible_count = cast(int, payload["eligibleAssetCount"])
    selected_official = cast(int, payload["selectedOfficialDomains"])
    selected_assets = cast(int, payload["selectedAssetHashes"])
    last_search = cast(int, payload["lastRunSearchRequests"])
    last_result = cast(int, payload["lastRunResultRequests"])
    if (
        not 0 <= search_requests <= PROVIDER_DAILY_SEARCH_LIMIT
        or not 0 <= result_requests <= PROVIDER_DAILY_RESULT_LIMIT
        or not 0 <= official_count <= 1_000
        or not 0 <= eligible_count <= MAXIMUM_ASSETS
        or not 0 <= selected_official <= official_count
        or not 0 <= selected_assets <= eligible_count
        or (official_count == 0 and official_cursor != 0)
        or (official_count > 0 and not 0 <= official_cursor < official_count)
        or (eligible_count == 0 and asset_cursor != 0)
        or (eligible_count > 0 and not 0 <= asset_cursor < eligible_count)
        or not 0 <= last_search <= PROVIDER_MINUTE_LIMIT
        or not 0 <= last_result <= PROVIDER_MINUTE_LIMIT
        or generated.date().isoformat() != payload["budgetDay"]
        or (payload["lastOutcome"] == "skipped-not-configured") != (payload["configured"] is False)
    ):
        raise ValueError("Official brand asset state has invalid counters.")
    current_brands = {entry.brand: entry for entry in registry.entries}
    validated_assets: list[_AssetRecord] = []
    for value in assets:
        asset = _validated_asset(value, registry, now)
        if asset is not None:
            validated_assets.append(asset)
            continue

        # A reviewed brand or official domain can be removed between runs.
        # Structurally valid records that no longer belong to the registry are
        # retired instead of making every future scheduled run fail.
        if not isinstance(value, dict) or set(value) != {
            "brand",
            "officialDomains",
            "resourceType",
            "sha256",
            "firstSeen",
            "lastSeen",
            "lastValidatedAt",
            "supportingScans",
        }:
            raise ValueError("Official brand asset state contains an invalid asset.")
        brand = value.get("brand")
        official_domains = value.get("officialDomains")
        entry = current_brands.get(brand) if isinstance(brand, str) else None
        retired = entry is None or (
            isinstance(official_domains, list)
            and bool(official_domains)
            and all(isinstance(domain, str) for domain in official_domains)
            and any(domain not in entry.official_domains for domain in official_domains)
        )
        if not retired:
            raise ValueError("Official brand asset state contains an invalid asset.")

    keys = [(asset.brand, asset.resource_type, asset.sha256) for asset in validated_assets]
    if len(keys) != len(set(keys)):
        raise ValueError("Official brand asset state contains duplicate assets.")
    reconciled_eligible_count = len(_eligible_assets(validated_assets))
    registry_changed = (
        official_count != len(_reviewed_official_domains(registry))
        or len(validated_assets) != len(assets)
    )
    if not registry_changed and eligible_count != reconciled_eligible_count:
        raise ValueError("Official brand asset state has an inconsistent eligible count.")
    validated_blocks = [_validated_blocked_hash(value, now) for value in blocked_hashes]
    if any(item is None for item in validated_blocks):
        raise ValueError("Official brand asset state contains an invalid blocked hash.")
    blocks = cast(list[_BlockedHash], validated_blocks)
    if len({item.sha256 for item in blocks}) != len(blocks):
        raise ValueError("Official brand asset state contains duplicate blocked hashes.")
    owners: list[_HashOwner] = []
    for value in hash_owners:
        owner = _validated_hash_owner(value, registry, now)
        if owner is not None:
            owners.append(owner)
            continue
        if (
            isinstance(value, dict)
            and set(value) == {"sha256", "brand", "lastSeen"}
            and isinstance(value.get("brand"), str)
            and value.get("brand") not in current_brands
        ):
            continue
        raise ValueError("Official brand asset state contains an invalid hash owner.")
    if len({item.sha256 for item in owners}) != len(owners):
        raise ValueError("Official brand asset state contains duplicate hash owners.")
    blocked_digests = {item.sha256 for item in blocks}
    asset_digests = {asset.sha256 for asset in validated_assets}
    if any(asset.sha256 in blocked_digests for asset in validated_assets) or any(
        owner.sha256 in blocked_digests for owner in owners
    ) or any(owner.sha256 in asset_digests for owner in owners):
        raise ValueError("Official brand asset state retains overlapping active, owner, or blocked hashes.")
    current_official_count = len(_reviewed_official_domains(registry))
    payload["assets"] = validated_assets
    payload["hashOwners"] = owners
    payload["blockedHashes"] = blocks
    payload["officialCount"] = current_official_count
    payload["eligibleAssetCount"] = reconciled_eligible_count
    payload["officialCursor"] = official_cursor % current_official_count if current_official_count else 0
    payload["assetCursor"] = asset_cursor % reconciled_eligible_count if reconciled_eligible_count else 0
    payload["selectedOfficialDomains"] = min(selected_official, current_official_count)
    payload["selectedAssetHashes"] = min(selected_assets, reconciled_eligible_count)
    return cast(dict[str, Any], payload)


def read_brand_asset_hunt_state(root: str | Path, now: datetime) -> dict[str, object] | None:
    """Return only bounded operational fields, never hashes or scan identifiers."""
    try:
        state = _read_state(root, load_brand_registry(), now)
    except ValueError:
        return None
    if state is None:
        return None
    return {
        "generatedAt": state["generatedAt"],
        "configured": state["configured"],
        "lastOutcome": state["lastOutcome"],
        "eligibleAssetCount": state["eligibleAssetCount"],
        "selectedAssetHashes": state["selectedAssetHashes"],
    }


def _write_state(
    root: str | Path,
    state: dict[str, Any],
    registry: BrandRegistry,
    now: datetime,
) -> None:
    serializable = {
        **state,
        "assets": [_record_to_json(asset) for asset in state["assets"]],
        "hashOwners": [_hash_owner_to_json(item) for item in state["hashOwners"]],
        "blockedHashes": [_blocked_hash_to_json(item) for item in state["blockedHashes"]],
    }
    assets = serializable.get("assets")
    hash_owners = serializable.get("hashOwners")
    blocked_hashes = serializable.get("blockedHashes")
    integer_fields = (
        "searchRequests",
        "resultRequests",
        "officialCursor",
        "assetCursor",
        "officialCount",
        "eligibleAssetCount",
        "selectedOfficialDomains",
        "selectedAssetHashes",
        "lastRunSearchRequests",
        "lastRunResultRequests",
    )
    if (
        serializable.get("schemaVersion") != 1
        or serializable.get("dataset") != STATE_DATASET
        or not isinstance(serializable.get("configured"), bool)
        or serializable.get("lastOutcome") not in STATE_OUTCOMES
        or not isinstance(serializable.get("generatedAt"), str)
        or not isinstance(serializable.get("budgetDay"), str)
        or not all(
            isinstance(serializable.get(field), int) and not isinstance(serializable.get(field), bool)
            for field in integer_fields
        )
        or not isinstance(assets, list)
        or len(assets) > MAXIMUM_ASSETS
        or any(_validated_asset(asset, registry, now) is None for asset in assets)
        or not isinstance(hash_owners, list)
        or len(hash_owners) > MAXIMUM_HASH_OWNERS
        or any(_validated_hash_owner(item, registry, now) is None for item in hash_owners)
        or not isinstance(blocked_hashes, list)
        or len(blocked_hashes) > MAXIMUM_BLOCKED_HASHES
        or any(_validated_blocked_hash(item, now) is None for item in blocked_hashes)
    ):
        raise ValueError("Official brand asset state cannot be serialized safely.")
    asset_digests = {cast(str, asset["sha256"]) for asset in cast(list[dict[str, object]], assets)}
    owner_digests = {cast(str, item["sha256"]) for item in cast(list[dict[str, object]], hash_owners)}
    block_digests = {
        cast(str, item["sha256"]) for item in cast(list[dict[str, object]], blocked_hashes)
    }
    if (
        len(owner_digests) != len(cast(list[dict[str, object]], hash_owners))
        or len(block_digests) != len(cast(list[dict[str, object]], blocked_hashes))
        or asset_digests & owner_digests
        or owner_digests & block_digests
        or asset_digests & block_digests
    ):
        raise ValueError("Official brand asset state cannot retain duplicate or active blocked hashes.")
    try:
        generated = _parse_timestamp(cast(str, serializable["generatedAt"]))
    except ValueError as error:
        raise ValueError("Official brand asset state cannot be serialized safely.") from error
    official_count = cast(int, serializable["officialCount"])
    eligible_count = cast(int, serializable["eligibleAssetCount"])
    official_cursor = cast(int, serializable["officialCursor"])
    asset_cursor = cast(int, serializable["assetCursor"])
    if (
        generated.date().isoformat() != serializable["budgetDay"]
        or (serializable["lastOutcome"] == "skipped-not-configured")
        != (serializable["configured"] is False)
        or official_count != len(_reviewed_official_domains(registry))
        or not 0 <= eligible_count <= len(assets)
        or (official_count == 0 and official_cursor != 0)
        or (official_count > 0 and not 0 <= official_cursor < official_count)
        or (eligible_count == 0 and asset_cursor != 0)
        or (eligible_count > 0 and not 0 <= asset_cursor < eligible_count)
    ):
        raise ValueError("Official brand asset state cannot be serialized safely.")
    body = json.dumps(serializable, ensure_ascii=False, separators=(",", ":")) + "\n"
    if len(body.encode("utf-8")) > MAXIMUM_STATE_BYTES:
        raise ValueError("Official brand asset state exceeds 512 KiB.")
    path = _state_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.tmp")
    temporary.write_text(body, encoding="utf-8", newline="\n")
    temporary.chmod(0o600)
    os.replace(temporary, path)


def _state_for_run(
    now: datetime,
    result: _AssetHuntResult,
    requester: _BudgetedRequester,
    outcome: str,
    *,
    configured: bool,
) -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "dataset": STATE_DATASET,
        "generatedAt": _timestamp(now),
        "configured": configured,
        "budgetDay": now.astimezone(UTC).date().isoformat(),
        "searchRequests": requester.search_used,
        "resultRequests": requester.result_used,
        "officialCursor": result.official_cursor,
        "assetCursor": result.asset_cursor,
        "officialCount": result.official_count,
        "eligibleAssetCount": result.eligible_asset_count,
        "selectedOfficialDomains": result.selected_official_domains,
        "selectedAssetHashes": result.selected_asset_hashes,
        "lastOutcome": outcome,
        "lastRunSearchRequests": requester.run_search_requests,
        "lastRunResultRequests": requester.run_result_requests,
        "assets": result.assets,
        "hashOwners": result.hash_owners,
        "blockedHashes": result.blocked_hashes,
    }


def main() -> int:
    now = datetime.now(UTC)
    root = os.environ.get("URLSCAN_ARCHIVE_ROOT", "").strip() or "data/urlscan"
    registry = load_brand_registry()
    previous = _read_state(root, registry, now)
    same_day = previous is not None and previous["budgetDay"] == now.date().isoformat()
    search_used = cast(int, previous["searchRequests"]) if same_day and previous else 0
    result_used = cast(int, previous["resultRequests"]) if same_day and previous else 0
    requester = _BudgetedRequester(
        _request_json,
        search_used=search_used,
        result_used=result_used,
        daily_search_cap=_bounded(os.environ.get("URLSCAN_ASSET_DAILY_SEARCH_CAP"), 80, 1, PROVIDER_DAILY_SEARCH_LIMIT),
        daily_result_cap=_bounded(
            os.environ.get("URLSCAN_ASSET_DAILY_RESULT_CAP"), 400, 1, PROVIDER_DAILY_RESULT_LIMIT
        ),
        run_search_cap=_bounded(os.environ.get("URLSCAN_ASSET_RUN_SEARCH_CAP"), 40, 1, PROVIDER_MINUTE_LIMIT - 20),
        run_result_cap=_bounded(os.environ.get("URLSCAN_ASSET_RUN_RESULT_CAP"), 100, 1, PROVIDER_MINUTE_LIMIT - 20),
    )
    current_assets = cast(list[_AssetRecord], previous["assets"]) if previous else []
    current_hash_owners = cast(list[_HashOwner], previous["hashOwners"]) if previous else []
    current_blocked_hashes = cast(list[_BlockedHash], previous["blockedHashes"]) if previous else []
    official_cursor = cast(int, previous["officialCursor"]) if previous else 0
    asset_cursor = cast(int, previous["assetCursor"]) if previous else 0
    api_key = os.environ.get("URLSCAN_API_KEY", "").strip()
    if not api_key:
        try:
            assets, hash_owners, blocked_hashes = _merge_assets(
                current_assets,
                [],
                current_hash_owners,
                current_blocked_hashes,
                now,
            )
            official_count = len(_reviewed_official_domains(registry))
            eligible_count = len(_eligible_assets(assets))
            skipped = _AssetHuntResult(
                signals=[],
                intelligence=[],
                assets=assets,
                hash_owners=hash_owners,
                blocked_hashes=blocked_hashes,
                official_cursor=(official_cursor % official_count) if official_count else 0,
                asset_cursor=(asset_cursor % eligible_count) if eligible_count else 0,
                official_count=official_count,
                eligible_asset_count=eligible_count,
                selected_official_domains=0,
                selected_asset_hashes=0,
            )
            _write_state(
                root,
                _state_for_run(now, skipped, requester, "skipped-not-configured", configured=False),
                registry,
                now,
            )
            print("Official brand asset hunt skipped: URLSCAN_API_KEY is not configured; no request was made.")
            return 0
        except Exception as error:
            message = str(error).splitlines()[0] if str(error) else type(error).__name__
            print(f"Official brand asset skip state failed: {message}.")
            return 1
    try:
        result = hunt_official_asset_hashes(
            api_key,
            now,
            requester,
            registry,
            current_assets,
            current_hash_owners,
            current_blocked_hashes,
            official_cursor=official_cursor,
            asset_cursor=asset_cursor,
        )
        signal_count = write_urlscan_archive(root, result.signals, now)
        detail_count = write_urlscan_intelligence_archive(root, result.intelligence, now)
        outcome = "budget-limited" if requester.exhausted else "completed"
        _write_state(root, _state_for_run(now, result, requester, outcome, configured=True), registry, now)
        print(
            f"Official brand assets: {len(result.assets)} retained, "
            f"{result.eligible_asset_count} stable and unambiguous, "
            f"{len(result.signals)} reviewed signals ({signal_count} new), "
            f"{detail_count} new detail records; {requester.run_search_requests} search and "
            f"{requester.run_result_requests} result requests; outcome {outcome}."
        )
        return 0
    except Exception as error:
        official_count = len(_reviewed_official_domains(registry))
        eligible_count = len(_eligible_assets(current_assets))
        fallback = _AssetHuntResult(
            signals=[],
            intelligence=[],
            assets=current_assets,
            hash_owners=current_hash_owners,
            blocked_hashes=current_blocked_hashes,
            official_cursor=(official_cursor % official_count) if official_count else 0,
            asset_cursor=(asset_cursor % eligible_count) if eligible_count else 0,
            official_count=official_count,
            eligible_asset_count=eligible_count,
            selected_official_domains=0,
            selected_asset_hashes=0,
        )
        state_error_message: str | None = None
        try:
            _write_state(root, _state_for_run(now, fallback, requester, "failed", configured=True), registry, now)
        except Exception as state_error:
            state_error_message = str(state_error).splitlines()[0] if str(state_error) else type(state_error).__name__
        message = str(error).splitlines()[0] if str(error) else type(error).__name__
        suffix = f" Failure state was not written: {state_error_message}" if state_error_message else ""
        print(f"Official brand asset hunt failed: {message}.{suffix}")
        return 1


def run() -> None:
    raise SystemExit(main())


if __name__ == "__main__":
    run()
