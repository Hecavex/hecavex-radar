from __future__ import annotations

import json
import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from http.client import HTTPMessage
from pathlib import Path
from typing import IO, Any, cast
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from zoneinfo import ZoneInfo

from .brands import (
    BrandRegistry,
    _canonical,
    is_brand_collision,
    is_suppressed_domain,
    load_brand_registry,
    match_brand_text,
    normalize_domain,
    resolve_brand_name,
    score_domain,
)
from .certstream_archive import read_recent_candidates, vilnius_date
from .models import BrandEvidence, CandidateMatch, RadarSignal, RawSignal
from .normalize import merge_signals, prepare_signal
from .safety import parse_and_defang_url, refang, safe_reference_url, safe_screenshot_url, stable_id
from .seeds import IntelligenceSeed, load_intelligence_seeds

API_ROOT = "https://urlscan.io"
SEARCH_ENDPOINT = f"{API_ROOT}/api/v1/search/"
RESULT_ENDPOINT = f"{API_ROOT}/api/v1/result"
SHA256 = re.compile(r"^[a-f\d]{64}$", re.IGNORECASE)
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
UTC_MILLISECOND_TIMESTAMP = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$"
)
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
BRAND_EVIDENCE_VALUES: frozenset[BrandEvidence] = frozenset(
    {"domain", "title", "verdict", "primary-html-sha256"}
)
URLSCAN_ARCHIVE_FIELDS = frozenset(
    {
        "schemaVersion",
        "hashType",
        "brandEvidence",
        "id",
        "url",
        "domain",
        "firstSeen",
        "lastSeen",
        "sources",
        "status",
        "brand",
        "country",
        "host",
        "screenshotUrl",
        "referenceUrl",
        "hashes",
        "confidence",
    }
)
MAXIMUM_RESPONSE_BYTES = 20 * 1024 * 1024
MAXIMUM_DAILY_RECORDS = 2_500
MAXIMUM_ARCHIVE_BYTES = 20 * 1024 * 1024
MAXIMUM_ARCHIVE_OBSERVATION_AGE = timedelta(days=91)
MAXIMUM_TIMESTAMP_FUTURE_SKEW = timedelta(minutes=5)
VILNIUS = ZoneInfo("Europe/Vilnius")

JsonRequester = Callable[[str, str], Any]


@dataclass(frozen=True, slots=True)
class _HuntSeed:
    domain: str
    brand: str
    confidence: int


@dataclass(frozen=True, slots=True)
class _ScanVerdict:
    malicious: bool
    phishing: bool
    score: int


@dataclass(frozen=True, slots=True)
class _BrandEvidence:
    domain: bool
    title: bool
    verdict: bool
    conflicting: bool

    @property
    def any(self) -> bool:
        return self.domain or self.title or self.verdict

    @property
    def labels(self) -> list[BrandEvidence]:
        labels: list[BrandEvidence] = []
        if self.domain:
            labels.append("domain")
        if self.title:
            labels.append("title")
        if self.verdict:
            labels.append("verdict")
        return labels


class _URLScanFatalError(RuntimeError):
    pass


class _URLScanRateLimitError(_URLScanFatalError):
    pass


class _URLScanAccessError(_URLScanFatalError):
    pass


def _bounded(value: str | None, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value) if value is not None else default
    except ValueError:
        parsed = default
    return max(minimum, min(maximum, parsed))


def _enabled(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    return default if value is None else value.strip().lower() == "true"


class _UrlscanRedirectHandler(HTTPRedirectHandler):
    def redirect_request(
        self,
        request: Request,
        file_pointer: IO[bytes],
        code: int,
        message: str,
        headers: HTTPMessage,
        new_url: str,
    ) -> Request | None:
        destination = urlsplit(urljoin(request.full_url, new_url))
        if (
            code not in {301, 302, 303, 307, 308}
            or destination.scheme != "https"
            or destination.hostname != "urlscan.io"
            or destination.username is not None
            or destination.password is not None
            or destination.port is not None
        ):
            raise HTTPError(
                request.full_url,
                code,
                "URLScan returned an unapproved redirect.",
                headers,
                file_pointer,
            )
        return super().redirect_request(
            request,
            file_pointer,
            code,
            message,
            headers,
            destination.geturl(),
        )


def _request_json(url: str, api_key: str) -> Any:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "urlscan.io"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
    ):
        raise ValueError("URLScan requests must stay on https://urlscan.io.")
    request = Request(  # noqa: S310 - URL is checked against the fixed HTTPS origin above
        url,
        headers={"Accept": "application/json", "api-key": api_key, "User-Agent": "hecavex-radar/0.1"},
    )
    opener = build_opener(_UrlscanRedirectHandler())
    try:
        with opener.open(  # noqa: S310 - initial URL and redirects use one fixed HTTPS origin
            request,
            timeout=45,
        ) as response:
            body = response.read(MAXIMUM_RESPONSE_BYTES + 1)
    except HTTPError as error:
        if error.code == 429:
            raise _URLScanRateLimitError("URLScan rate limit reached (HTTP 429).") from error
        if error.code in {401, 403}:
            raise _URLScanAccessError(
                f"URLScan API authentication or authorization failed (HTTP {error.code})."
            ) from error
        raise RuntimeError(f"URLScan returned HTTP {error.code}.") from error
    except URLError as error:
        raise RuntimeError("URLScan request failed.") from error
    if len(body) > MAXIMUM_RESPONSE_BYTES:
        raise ValueError("URLScan response exceeds 20 MiB.")
    try:
        return json.loads(body)
    except json.JSONDecodeError as error:
        raise ValueError("URLScan returned invalid JSON.") from error


def _dictionary(value: object) -> dict[str, Any]:
    return cast(dict[str, Any], value) if isinstance(value, dict) else {}


def _string(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _search_terms(registry: BrandRegistry) -> list[str]:
    terms: set[str] = set()
    for entry in registry.entries:
        for alias in entry.aliases:
            term = _canonical(alias)
            if 5 <= len(term) <= 40:
                terms.add(term)
        for domain in entry.official_domains:
            label = domain.split(".", 1)[0]
            term = _canonical(label)
            if 5 <= len(term) <= 40:
                terms.add(term)
    return sorted(terms)


def _public_search_query(expression: str, lookback_days: int) -> str:
    return f"date:>now-{lookback_days}d AND task.visibility:public AND ({expression})"


def build_domain_query(registry: BrandRegistry, lookback_days: int) -> str:
    alternatives = " OR ".join(f"*{term}*" for term in _search_terms(registry))
    return _public_search_query(
        f"task.domain.keyword:({alternatives}) OR page.domain.keyword:({alternatives})",
        lookback_days,
    )


def build_title_query(registry: BrandRegistry, lookback_days: int) -> str:
    alternatives = " OR ".join(f"*{term}*" for term in _search_terms(registry))
    return _public_search_query(f"page.title.keyword:({alternatives})", lookback_days)


def build_exact_domain_query(domains: list[str], lookback_days: int) -> str:
    normalized = list(
        dict.fromkeys(domain for value in domains if (domain := normalize_domain(value)) is not None)
    )
    if not normalized:
        raise ValueError("An exact-domain URLScan query requires at least one valid domain.")
    alternatives = " OR ".join(
        clause
        for domain in normalized
        for clause in (f'task.domain.keyword:"{domain}"', f'page.domain.keyword:"{domain}"')
    )
    return _public_search_query(alternatives, lookback_days)


def _is_public_scan(value: dict[str, Any]) -> bool:
    return _dictionary(value.get("task")).get("visibility") == "public"


def _search(query: str, size: int, api_key: str, requester: JsonRequester) -> list[dict[str, Any]]:
    if "task.visibility:public" not in query:
        raise ValueError("URLScan searches must be restricted to public scans.")
    url = f"{SEARCH_ENDPOINT}?{urlencode({'q': query, 'size': size, 'datasource': 'scans'})}"
    payload = requester(url, api_key)
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
        raise ValueError("URLScan search returned an unexpected payload.")
    return [
        cast(dict[str, Any], item)
        for item in payload["results"]
        if isinstance(item, dict) and _is_public_scan(item)
    ]


def _scan_uuid(result: dict[str, Any]) -> str | None:
    task = _dictionary(result.get("task"))
    candidate = _string(result.get("_id")) or _string(task.get("uuid"))
    return candidate.lower() if candidate and UUID.fullmatch(candidate) else None


def _result_detail(uuid: str, api_key: str, requester: JsonRequester) -> dict[str, Any]:
    payload = requester(f"{RESULT_ENDPOINT}/{uuid}/", api_key)
    if not isinstance(payload, dict):
        raise ValueError("URLScan result returned an unexpected payload.")
    return cast(dict[str, Any], payload)


def _result_urls(result: dict[str, Any]) -> list[str]:
    task = _dictionary(result.get("task"))
    page = _dictionary(result.get("page"))
    values = [_string(task.get("url")), _string(page.get("url"))]
    return list(dict.fromkeys(value for value in values if value))


def _page_url(result: dict[str, Any]) -> str | None:
    return _string(_dictionary(result.get("page")).get("url")) or _string(
        _dictionary(result.get("task")).get("url")
    )


def _hostname(value: str) -> str | None:
    candidate = refang(value)
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    try:
        return urlsplit(candidate).hostname
    except ValueError:
        return None


def _official(domain: str, registry: BrandRegistry) -> bool:
    return is_suppressed_domain(domain, registry)


def _verdict(detail: dict[str, Any]) -> _ScanVerdict:
    verdicts = _dictionary(detail.get("verdicts"))
    urlscan = _dictionary(verdicts.get("urlscan"))
    score_value = urlscan.get("score")
    score = score_value if isinstance(score_value, int) and not isinstance(score_value, bool) else 0
    categories_value = urlscan.get("categories")
    phishing = isinstance(categories_value, list) and any(
        isinstance(value, str) and value.strip().lower() == "phishing"
        for value in categories_value
    )
    malicious = urlscan.get("malicious") is True or score > 0 or phishing
    return _ScanVerdict(
        malicious=malicious,
        phishing=phishing,
        score=max(-100, min(100, score)),
    )


def _verdict_brand(detail: dict[str, Any], registry: BrandRegistry) -> str | None:
    urlscan = _dictionary(_dictionary(detail.get("verdicts")).get("urlscan"))
    brands = urlscan.get("brands")
    if not isinstance(brands, list):
        return None
    matched_brands: set[str] = set()
    for value in brands:
        if not isinstance(value, dict):
            continue
        name = _string(value.get("name"))
        matched = match_brand_text(name, registry)
        if matched:
            matched_brands.add(matched)
    return matched_brands.pop() if len(matched_brands) == 1 else None


def _primary_hashes(detail: dict[str, Any], registry: BrandRegistry) -> list[str]:
    page_url = _string(_dictionary(detail.get("page")).get("url"))
    page_host = _hostname(page_url) if page_url else None
    if not page_url or not page_host or _official(page_host, registry):
        return []
    requests = _dictionary(detail.get("data")).get("requests")
    if not isinstance(requests, list):
        return []
    matches: list[str] = []
    for value in requests:
        item = _dictionary(value)
        request_container = _dictionary(item.get("request"))
        request = _dictionary(request_container.get("request"))
        response = _dictionary(item.get("response"))
        metadata = _dictionary(response.get("response"))
        response_url = _string(metadata.get("url")) or _string(request.get("url"))
        digest = _string(response.get("hash"))
        mime = (_string(metadata.get("mimeType")) or "").lower()
        resource_type = (
            _string(item.get("type"))
            or _string(request_container.get("type"))
            or _string(request.get("type"))
        )
        status_value = metadata.get("status")
        if not isinstance(status_value, int) or isinstance(status_value, bool):
            status_value = response.get("status")
        status = (
            status_value
            if isinstance(status_value, int) and not isinstance(status_value, bool)
            else 0
        )
        size_value = metadata.get("encodedDataLength") or metadata.get("dataLength") or response.get("size")
        size = size_value if isinstance(size_value, int) and not isinstance(size_value, bool) else 0
        if (
            response_url == page_url
            and 200 <= status < 300
            and digest
            and SHA256.fullmatch(digest)
            and digest.lower() != EMPTY_SHA256
            and "html" in mime
            and (resource_type is None or resource_type.lower() == "document")
            and size >= 512
        ):
            matches.append(digest.lower())
    return list(dict.fromkeys(matches))[:2]


def _host_summary(page: dict[str, Any]) -> str | None:
    values = [_string(page.get("asn")), _string(page.get("asnname")), _string(page.get("ip"))]
    present = [value for value in values if value]
    return " · ".join(present) if present else None


def _timestamp(value: datetime) -> str:
    aware = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    return aware.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _signal_from_scan(
    summary: dict[str, Any],
    detail: dict[str, Any],
    matched_url: str,
    brand: str,
    base_confidence: int,
    now: datetime,
    registry: BrandRegistry,
    brand_evidence: _BrandEvidence,
    primary_hash_pivot: bool = False,
) -> RadarSignal | None:
    uuid = _scan_uuid(summary) or _scan_uuid(detail)
    if not uuid:
        return None
    page = {**_dictionary(summary.get("page")), **_dictionary(detail.get("page"))}
    task = {**_dictionary(summary.get("task")), **_dictionary(detail.get("task"))}
    verdict = _verdict(detail)
    confidence = base_confidence
    if verdict.phishing:
        confidence = max(confidence, min(99, 95 + max(0, verdict.score) // 25))
    elif verdict.malicious:
        confidence = max(confidence, min(90, 80 + max(0, verdict.score)))
    observed_at = _string(task.get("time")) or _timestamp(now)
    hashes = _primary_hashes(detail, registry)
    signal = prepare_signal(
        RawSignal(
            url=matched_url,
            first_seen=observed_at,
            last_seen=observed_at,
            source="URLScan",
            status="suspected",
            brand=brand,
            country=_string(page.get("country")),
            host=_host_summary(page),
            screenshot_url=f"{API_ROOT}/screenshots/{uuid}.png",
            reference_url=f"{API_ROOT}/result/{uuid}/",
            hashes=hashes,
            confidence=confidence,
        ),
        _timestamp(now),
    )
    if signal is None:
        return None
    signal["brandEvidence"] = brand_evidence.labels
    if primary_hash_pivot:
        signal["brandEvidence"].append("primary-html-sha256")
    return signal


def _summary_match(result: dict[str, Any], registry: BrandRegistry, minimum_confidence: int) -> CandidateMatch | None:
    matches: list[CandidateMatch] = []
    for value in _result_urls(result):
        hostname = _hostname(value)
        match = score_domain(hostname, registry) if hostname else None
        if match and match.confidence >= minimum_confidence:
            matches.append(match)
    if len({match.brand for match in matches}) != 1:
        return None
    return max(matches, key=lambda match: match.confidence)


def _matched_url(result: dict[str, Any], match: CandidateMatch) -> str:
    return next(
        (
            value
            for value in _result_urls(result)
            if (hostname := _hostname(value)) and hostname == match.domain
        ),
        match.domain,
    )


def _safe_detail(
    result: dict[str, Any], api_key: str, requester: JsonRequester
) -> tuple[str, dict[str, Any]] | None:
    uuid = _scan_uuid(result)
    if not uuid or not _is_public_scan(result):
        return None
    try:
        detail = _result_detail(uuid, api_key, requester)
    except _URLScanFatalError:
        raise
    except (RuntimeError, ValueError):
        return None
    return (uuid, detail) if _is_public_scan(detail) else None


def _title(result: dict[str, Any], detail: dict[str, Any]) -> str | None:
    return _string(_dictionary(detail.get("page")).get("title")) or _string(
        _dictionary(result.get("page")).get("title")
    )


def _brand_evidence(
    result: dict[str, Any],
    detail: dict[str, Any],
    brand: str,
    registry: BrandRegistry,
) -> _BrandEvidence:
    domain_brands = {
        match.brand
        for value in [*_result_urls(result), *_result_urls(detail)]
        if (hostname := _hostname(value)) is not None
        and (match := score_domain(hostname, registry)) is not None
    }
    title_brand = match_brand_text(_title(result, detail), registry)
    verdict_brand = _verdict_brand(detail, registry)
    observed_brands = set(domain_brands)
    if title_brand:
        observed_brands.add(title_brand)
    if verdict_brand:
        observed_brands.add(verdict_brand)
    return _BrandEvidence(
        domain=brand in domain_brands,
        title=title_brand == brand,
        verdict=verdict_brand == brand,
        conflicting=any(observed != brand for observed in observed_brands),
    )


def _merge_hunt_seeds(seeds: list[_HuntSeed], maximum: int) -> list[_HuntSeed]:
    combined: dict[tuple[str, str], _HuntSeed] = {}
    brands_by_domain: dict[str, set[str]] = {}
    for seed in seeds:
        domain = normalize_domain(seed.domain)
        if not domain:
            continue
        brands_by_domain.setdefault(domain, set()).add(seed.brand)
        key = (domain, seed.brand)
        current = combined.get(key)
        if current is None:
            combined[key] = _HuntSeed(
                domain=domain,
                brand=seed.brand,
                confidence=seed.confidence,
            )
            continue
        combined[key] = _HuntSeed(
            domain=domain,
            brand=seed.brand,
            confidence=max(current.confidence, seed.confidence),
        )
    unambiguous = [
        seed
        for seed in combined.values()
        if len(brands_by_domain.get(seed.domain, set())) == 1
    ]
    return sorted(unambiguous, key=lambda seed: (-seed.confidence, seed.domain, seed.brand))[:maximum]


def _load_hunt_seeds(registry: BrandRegistry, now: datetime) -> list[_HuntSeed]:
    seeds: list[_HuntSeed] = []
    if _enabled("URLSCAN_CT_SEEDS_ENABLED", default=True):
        lookback = _bounded(os.environ.get("URLSCAN_CT_LOOKBACK_DAYS"), 7, 1, 90)
        limit = _bounded(os.environ.get("URLSCAN_CT_SEED_LIMIT"), 100, 0, 1_000)
        minimum = _bounded(os.environ.get("URLSCAN_CT_SEED_MIN_CONFIDENCE"), 80, 50, 100)
        archive_root = os.environ.get("URLSCAN_CT_ARCHIVE_ROOT", "").strip() or "data/certstream"
        candidates = read_recent_candidates(archive_root, lookback, now, maximum=max(1, limit)) if limit else []
        for candidate in candidates:
            domain = normalize_domain(refang(candidate["domain"]))
            match = score_domain(domain, registry) if domain else None
            if match and match.confidence >= minimum:
                seeds.append(
                    _HuntSeed(
                        domain=match.domain,
                        brand=match.brand,
                        confidence=match.confidence,
                    )
                )

    if _enabled("URLSCAN_INTELLIGENCE_SEEDS_ENABLED", default=True):
        intelligence = load_intelligence_seeds(registry)
        seeds.extend(
            _HuntSeed(
                domain=seed.domain,
                brand=seed.brand,
                confidence=seed.confidence,
            )
            for seed in intelligence.seeds
            if isinstance(seed, IntelligenceSeed)
        )

    maximum = _bounded(os.environ.get("URLSCAN_EXACT_SEED_LIMIT"), 250, 0, 1_000)
    return _merge_hunt_seeds(seeds, maximum)


def _seed_for_result(result: dict[str, Any], seeds_by_domain: dict[str, _HuntSeed]) -> _HuntSeed | None:
    matches = {
        seed
        for value in _result_urls(result)
        if (hostname := _hostname(value)) is not None
        and (seed := seeds_by_domain.get(hostname)) is not None
    }
    brands = {seed.brand for seed in matches}
    if len(brands) != 1:
        return None
    return max(matches, key=lambda seed: (seed.confidence, seed.domain))


def _seed_url(summary: dict[str, Any], detail: dict[str, Any], seed: _HuntSeed) -> str | None:
    task_values = [
        _string(_dictionary(detail.get("task")).get("url")),
        _string(_dictionary(summary.get("task")).get("url")),
    ]
    page_values = [
        _string(_dictionary(detail.get("page")).get("url")),
        _string(_dictionary(summary.get("page")).get("url")),
    ]
    return next(
        (
            value
            for value in [*task_values, *page_values]
            if value and _hostname(value) == seed.domain
        ),
        None,
    )


def _chunks(values: list[_HuntSeed], size: int) -> list[list[_HuntSeed]]:
    return [values[index : index + size] for index in range(0, len(values), size)]


def hunt_urlscan(
    api_key: str,
    now: datetime,
    requester: JsonRequester = _request_json,
    registry: BrandRegistry | None = None,
) -> list[RadarSignal]:
    """Passively hunt existing URLScan results for reviewed Lithuanian targets."""
    if not api_key.strip():
        raise ValueError("URLSCAN_API_KEY is required.")
    brand_registry = registry or load_brand_registry()
    lookback = _bounded(os.environ.get("URLSCAN_LOOKBACK_DAYS"), 7, 1, 90)
    minimum = _bounded(os.environ.get("URLSCAN_MIN_CONFIDENCE"), 80, 50, 100)
    search_limit = _bounded(os.environ.get("URLSCAN_SEARCH_LIMIT"), 100, 1, 1_000)
    detail_limit = _bounded(os.environ.get("URLSCAN_DETAIL_LIMIT"), 30, 1, 200)
    title_limit = _bounded(os.environ.get("URLSCAN_TITLE_DETAIL_LIMIT"), 10, 0, 100)
    pivot_limit = _bounded(os.environ.get("URLSCAN_HASH_PIVOT_LIMIT"), 3, 0, 20)
    pivot_results = _bounded(os.environ.get("URLSCAN_HASH_RESULT_LIMIT"), 10, 1, 100)
    pivot_detail_limit = _bounded(os.environ.get("URLSCAN_HASH_DETAIL_LIMIT"), 30, 0, 200)
    seed_batch_size = _bounded(os.environ.get("URLSCAN_SEED_BATCH_SIZE"), 20, 1, 50)
    seed_search_limit = _bounded(os.environ.get("URLSCAN_SEED_SEARCH_LIMIT"), 50, 1, 200)
    seed_detail_limit = _bounded(os.environ.get("URLSCAN_SEED_DETAIL_LIMIT"), 30, 0, 200)
    maximum = _bounded(os.environ.get("URLSCAN_MAX_SIGNALS"), 500, 1, MAXIMUM_DAILY_RECORDS)

    signals: list[RadarSignal] = []
    processed: set[str] = set()
    hash_seeds: list[tuple[str, str]] = []
    exact_seeds = _load_hunt_seeds(brand_registry, now)
    seed_details = 0

    for batch in _chunks(exact_seeds, seed_batch_size):
        if seed_details >= seed_detail_limit:
            break
        seeds_by_domain = {seed.domain: seed for seed in batch}
        query = build_exact_domain_query(list(seeds_by_domain), lookback)
        for result in _search(query, seed_search_limit, api_key, requester):
            if seed_details >= seed_detail_limit:
                break
            uuid = _scan_uuid(result)
            seed = _seed_for_result(result, seeds_by_domain)
            if not uuid or uuid in processed or not seed or _official(seed.domain, brand_registry):
                continue
            fetched = _safe_detail(result, api_key, requester)
            if not fetched:
                continue
            processed.add(uuid)
            seed_details += 1
            _, detail = fetched
            matched_url = _seed_url(result, detail, seed)
            final_host = _hostname(_page_url(detail) or "")
            if not matched_url or (final_host and _official(final_host, brand_registry)):
                continue
            evidence = _brand_evidence(result, detail, seed.brand, brand_registry)
            if evidence.conflicting or not evidence.any:
                continue
            signal = _signal_from_scan(
                result,
                detail,
                matched_url,
                seed.brand,
                seed.confidence,
                now,
                brand_registry,
                evidence,
            )
            if signal:
                signals.append(signal)
                if evidence.title or evidence.verdict:
                    hash_seeds.extend(
                        (seed.brand, digest) for digest in _primary_hashes(detail, brand_registry)
                    )

    detail_count = 0

    for result in _search(build_domain_query(brand_registry, lookback), search_limit, api_key, requester):
        if detail_count >= detail_limit:
            break
        uuid = _scan_uuid(result)
        match = _summary_match(result, brand_registry, minimum)
        if not uuid or uuid in processed or not match:
            continue
        fetched = _safe_detail(result, api_key, requester)
        if not fetched:
            continue
        processed.add(uuid)
        detail_count += 1
        _, detail = fetched
        final_host = _hostname(_page_url(detail) or "")
        if final_host and _official(final_host, brand_registry):
            continue
        evidence = _brand_evidence(result, detail, match.brand, brand_registry)
        if evidence.conflicting or not evidence.domain:
            continue
        signal = _signal_from_scan(
            result,
            detail,
            _matched_url(result, match),
            match.brand,
            match.confidence,
            now,
            brand_registry,
            evidence,
        )
        if signal:
            signals.append(signal)
            if evidence.title or evidence.verdict:
                hash_seeds.extend(
                    (match.brand, digest) for digest in _primary_hashes(detail, brand_registry)
                )

    title_details = 0
    if title_limit:
        for result in _search(build_title_query(brand_registry, lookback), search_limit, api_key, requester):
            if title_details >= title_limit:
                break
            uuid = _scan_uuid(result)
            summary_page = _dictionary(result.get("page"))
            hostname = _hostname(_string(summary_page.get("url")) or "")
            brand = match_brand_text(_string(summary_page.get("title")), brand_registry)
            if not uuid or uuid in processed or not hostname or _official(hostname, brand_registry) or not brand:
                continue
            fetched = _safe_detail(result, api_key, requester)
            if not fetched:
                continue
            processed.add(uuid)
            title_details += 1
            _, detail = fetched
            final_host = _hostname(_page_url(detail) or "")
            if final_host and _official(final_host, brand_registry):
                continue
            evidence = _brand_evidence(result, detail, brand, brand_registry)
            verdict = _verdict(detail)
            if evidence.conflicting or not evidence.title or (not evidence.verdict and not verdict.phishing):
                continue
            matched_url = _page_url(detail) or _page_url(result) or hostname
            signal = _signal_from_scan(result, detail, matched_url, brand, 92, now, brand_registry, evidence)
            if signal:
                signals.append(signal)
                hash_seeds.extend((brand, digest) for digest in _primary_hashes(detail, brand_registry))

    unique_seeds = list(dict.fromkeys(hash_seeds))[:pivot_limit]
    pivot_details = 0
    for brand, digest in unique_seeds:
        if pivot_details >= pivot_detail_limit:
            break
        query = _public_search_query(f"hash:{digest}", lookback)
        for result in _search(query, pivot_results, api_key, requester):
            if pivot_details >= pivot_detail_limit:
                break
            uuid = _scan_uuid(result)
            if not uuid or uuid in processed:
                continue
            page_url = _page_url(result) or ""
            hostname = _hostname(page_url)
            if not hostname or _official(hostname, brand_registry):
                continue
            fetched = _safe_detail(result, api_key, requester)
            if not fetched:
                continue
            processed.add(uuid)
            pivot_details += 1
            _, detail = fetched
            primary_hashes = _primary_hashes(detail, brand_registry)
            evidence = _brand_evidence(result, detail, brand, brand_registry)
            if digest not in primary_hashes or evidence.conflicting or not evidence.any:
                continue
            signal = _signal_from_scan(
                result,
                detail,
                page_url,
                brand,
                94,
                now,
                brand_registry,
                evidence,
                primary_hash_pivot=True,
            )
            if signal:
                signals.append(signal)

    return merge_signals(signals, maximum)


def _bounded_archive_root(value: str | Path) -> Path:
    repository = Path.cwd().resolve()
    root = (repository / value).resolve()
    if root == repository or not root.is_relative_to(repository):
        raise ValueError("URLSCAN_ARCHIVE_ROOT must stay inside the repository.")
    return root


def _valid_day(value: str) -> bool:
    try:
        return date.fromisoformat(value).isoformat() == value
    except ValueError:
        return False


def _archive_path(root: str | Path, day: str) -> Path:
    if not _valid_day(day):
        raise ValueError("Invalid URLScan archive date.")
    return _bounded_archive_root(root) / day / "signals.ndjson"


def _archive_signal(
    value: Any,
    *,
    partition_day: date | None = None,
    reference_time: datetime | None = None,
) -> RadarSignal | None:
    if (
        not isinstance(value, dict)
        or not set(value).issubset(URLSCAN_ARCHIVE_FIELDS)
        or value.get("schemaVersion") != 2
        or value.get("hashType") != "primary-html-sha256"
    ):
        return None
    required_strings = ("id", "url", "domain", "firstSeen", "lastSeen")
    if not all(isinstance(value.get(field), str) for field in required_strings):
        return None
    identifier = value["id"]
    url = value["url"]
    domain = value["domain"]
    sources = value.get("sources")
    hashes = value.get("hashes", [])
    brand_evidence = value.get("brandEvidence")
    reference = value.get("referenceUrl")
    screenshot = value.get("screenshotUrl")
    confidence = value.get("confidence")
    parsed_url = parse_and_defang_url(url)
    if (
        not re.fullmatch(r"[a-f\d]{20}", identifier)
        or identifier != stable_id(domain.lower())
        or not url.startswith(("hxxp://", "hxxps://"))
        or "?" in url
        or "#" in url
        or parsed_url is None
        or parsed_url.display_url != url
        or parsed_url.display_domain != domain
        or sources != ["URLScan"]
        or value.get("status") != "suspected"
        or isinstance(confidence, bool)
        or not isinstance(confidence, int)
        or not 0 <= confidence <= 100
        or not isinstance(hashes, list)
        or len(hashes) > 8
        or not all(
            isinstance(digest, str)
            and digest == digest.lower()
            and digest != EMPTY_SHA256
            and SHA256.fullmatch(digest)
            for digest in hashes
        )
        or not isinstance(brand_evidence, list)
        or not 1 <= len(brand_evidence) <= len(BRAND_EVIDENCE_VALUES)
        or not all(
            isinstance(label, str) and label in BRAND_EVIDENCE_VALUES
            for label in brand_evidence
        )
        or len(set(brand_evidence)) != len(brand_evidence)
        or not {"domain", "title", "verdict"}.intersection(brand_evidence)
        or safe_reference_url(reference) != reference
        or safe_screenshot_url(screenshot) != screenshot
    ):
        return None
    if any(
        value.get(field) is not None and not isinstance(value.get(field), str)
        for field in ("brand", "country", "host")
    ):
        return None
    try:
        first_seen = datetime.fromisoformat(value["firstSeen"].replace("Z", "+00:00"))
        last_seen = datetime.fromisoformat(value["lastSeen"].replace("Z", "+00:00"))
    except ValueError:
        return None
    if (
        not UTC_MILLISECOND_TIMESTAMP.fullmatch(value["firstSeen"])
        or not UTC_MILLISECOND_TIMESTAMP.fullmatch(value["lastSeen"])
        or first_seen.tzinfo is None
        or last_seen.tzinfo is None
        or _timestamp(first_seen) != value["firstSeen"]
        or _timestamp(last_seen) != value["lastSeen"]
        or first_seen > last_seen
    ):
        return None
    first_seen_utc = first_seen.astimezone(UTC)
    last_seen_utc = last_seen.astimezone(UTC)
    if reference_time is not None:
        reference_utc = (
            reference_time
            if reference_time.tzinfo is not None
            else reference_time.replace(tzinfo=UTC)
        ).astimezone(UTC)
        if last_seen_utc > reference_utc + MAXIMUM_TIMESTAMP_FUTURE_SKEW:
            return None
    if partition_day is not None:
        partition_start = datetime.combine(partition_day, datetime.min.time(), tzinfo=VILNIUS)
        partition_end = partition_start + timedelta(days=1)
        if (
            first_seen_utc
            < partition_start.astimezone(UTC) - MAXIMUM_ARCHIVE_OBSERVATION_AGE
            or last_seen_utc
            > partition_end.astimezone(UTC) + MAXIMUM_TIMESTAMP_FUTURE_SKEW
        ):
            return None
    return cast(
        RadarSignal,
        {
            "id": stable_id(domain.lower()),
            "url": url,
            "domain": domain,
            "firstSeen": value["firstSeen"],
            "lastSeen": value["lastSeen"],
            "sources": ["URLScan"],
            "status": "suspected",
            "brand": value.get("brand"),
            "country": value.get("country"),
            "host": value.get("host"),
            "screenshotUrl": screenshot,
            "referenceUrl": reference,
            "hashes": hashes,
            "brandEvidence": [cast(BrandEvidence, label) for label in brand_evidence],
            "confidence": confidence,
        },
    )


def read_urlscan_file(
    path: Path,
    maximum: int = MAXIMUM_DAILY_RECORDS,
    *,
    now: datetime | None = None,
    reviewer: Callable[[RadarSignal], bool] | None = None,
) -> list[RadarSignal]:
    try:
        if path.stat().st_size > MAXIMUM_ARCHIVE_BYTES:
            raise ValueError(f"URLScan archive exceeds 20 MiB: {path.relative_to(Path.cwd())}")
        body = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    partition_day = date.fromisoformat(path.parent.name) if _valid_day(path.parent.name) else None
    records: list[RadarSignal] = []
    for line in body.splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        signal = _archive_signal(value, partition_day=partition_day, reference_time=now)
        if signal and (reviewer is None or reviewer(signal)):
            records.append(signal)
        if len(records) >= maximum:
            break
    return records


def _reviewed_archive_signal(signal: RadarSignal, registry: BrandRegistry) -> bool:
    hostname = _hostname(signal["domain"])
    brand = resolve_brand_name(signal["brand"], registry)
    if (
        not hostname
        or not brand
        or is_suppressed_domain(hostname, registry)
        or is_brand_collision(hostname, brand, registry)
    ):
        return False
    current_match = score_domain(hostname, registry)
    if current_match is not None:
        return current_match.brand == brand
    evidence = set(signal.get("brandEvidence", []))
    return bool(evidence.intersection({"title", "verdict"}))


def write_urlscan_archive(
    root: str | Path,
    signals: list[RadarSignal],
    now: datetime,
    registry: BrandRegistry | None = None,
) -> int:
    path = _archive_path(root, vilnius_date(now))
    brand_registry = registry or load_brand_registry()
    archived = read_urlscan_file(path, now=now)
    if not signals and not archived and not path.exists():
        return 0
    existing = [signal for signal in archived if _reviewed_archive_signal(signal, brand_registry)]
    partition_day = date.fromisoformat(path.parent.name)
    signals = [
        validated
        for signal in signals
        if (
            validated := _archive_signal(
                {"schemaVersion": 2, "hashType": "primary-html-sha256", **signal},
                partition_day=partition_day,
                reference_time=now,
            )
        )
        is not None
        and _reviewed_archive_signal(validated, brand_registry)
    ]
    existing_ids = {signal["id"] for signal in existing}
    merged = merge_signals(existing + signals, MAXIMUM_DAILY_RECORDS)
    lines = [
        json.dumps(
            {"schemaVersion": 2, "hashType": "primary-html-sha256", **signal},
            ensure_ascii=False,
            separators=(",", ":"),
        )
        for signal in merged
    ]
    body = "\n".join(lines) + ("\n" if lines else "")
    if len(body.encode("utf-8")) > MAXIMUM_ARCHIVE_BYTES:
        raise ValueError("URLScan archive exceeds 20 MiB.")
    try:
        if path.read_text(encoding="utf-8") == body:
            return 0
    except FileNotFoundError:
        pass
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.tmp")
    temporary.write_text(body, encoding="utf-8", newline="\n")
    temporary.chmod(0o600)
    os.replace(temporary, path)
    return sum(signal["id"] not in existing_ids for signal in signals)


def read_recent_urlscan(
    root: str | Path,
    lookback_days: int,
    now: datetime,
    maximum: int = MAXIMUM_DAILY_RECORDS,
    registry: BrandRegistry | None = None,
) -> list[RadarSignal]:
    archive_root = _bounded_archive_root(root)
    try:
        directories = sorted(
            (entry.name for entry in archive_root.iterdir() if entry.is_dir() and _valid_day(entry.name)),
            reverse=True,
        )
    except FileNotFoundError:
        return []
    today = date.fromisoformat(vilnius_date(now))
    permitted = {(today - timedelta(days=offset)).isoformat() for offset in range(lookback_days)}
    brand_registry = registry or load_brand_registry()

    def reviewer(signal: RadarSignal) -> bool:
        return _reviewed_archive_signal(signal, brand_registry)

    records: list[RadarSignal] = []
    for day in (value for value in directories if value in permitted):
        remaining = maximum - len(records)
        if remaining <= 0:
            break
        records.extend(
            read_urlscan_file(
                _archive_path(root, day),
                remaining,
                now=now,
                reviewer=reviewer,
            )
        )
    return merge_signals(records, maximum)


def main() -> int:
    api_key = os.environ.get("URLSCAN_API_KEY", "").strip()
    if not api_key:
        print("URLScan hunt failed: URLSCAN_API_KEY is required.")
        return 1
    try:
        now = datetime.now(UTC)
        signals = hunt_urlscan(api_key, now)
        root = os.environ.get("URLSCAN_ARCHIVE_ROOT", "").strip() or "data/urlscan"
        added = write_urlscan_archive(root, signals, now)
        print(f"URLScan: {len(signals)} reviewed signals; {added} new archive records.")
        return 0
    except Exception as error:
        message = str(error).splitlines()[0] if str(error) else type(error).__name__
        print(f"URLScan hunt failed: {message}")
        return 1


def run() -> None:
    raise SystemExit(main())


if __name__ == "__main__":
    run()
