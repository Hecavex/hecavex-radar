from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from http.client import HTTPMessage
from itertools import islice
from typing import IO, Any
from urllib.error import HTTPError
from urllib.parse import urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .brands import load_brand_registry, score_domain
from .certstream_archive import read_recent_candidates
from .models import RadarSource, RawSignal, SourceResult, SourceState
from .provenance import reason_codes_from_evidence, reason_codes_from_match
from .safety import refang, safe_feed_url
from .urlscan import read_recent_urlscan, read_urlscan_hunt_state

MAXIMUM_SOURCE_BYTES = 20 * 1024 * 1024
MAXIMUM_HECAVEX_RECORDS = 25_000


@dataclass(frozen=True, slots=True)
class SourceDefinition:
    name: str
    homepage: str


SOURCE_DEFINITIONS = {
    "certstream": SourceDefinition("CertStream", "https://certstream.dev/"),
    "urlscan": SourceDefinition("URLScan", "https://urlscan.io/"),
    "hecavex": SourceDefinition("HECAVEX", "https://hecavex.com/"),
}
SOURCE_NAMES = frozenset(definition.name for definition in SOURCE_DEFINITIONS.values())


def _source(
    definition: SourceDefinition,
    *,
    fetched_at: str | None,
    records: int,
    state: SourceState,
    note: str | None,
) -> RadarSource:
    return {
        "name": definition.name,
        "homepage": definition.homepage,
        "fetchedAt": fetched_at,
        "records": records,
        "state": state,
        "note": note,
    }


def skipped_sources() -> list[RadarSource]:
    return [
        _source(definition, fetched_at=None, records=0, state="skipped", note="Not configured")
        for definition in SOURCE_DEFINITIONS.values()
    ]


class _SameHostRedirectHandler(HTTPRedirectHandler):
    def __init__(self, hostname: str) -> None:
        self._hostname = hostname
        super().__init__()

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
            or destination.hostname != self._hostname
            or destination.username is not None
            or destination.password is not None
            or destination.port is not None
        ):
            raise HTTPError(request.full_url, code, "Source returned an unapproved redirect.", headers, file_pointer)
        return super().redirect_request(request, file_pointer, code, message, headers, destination.geturl())


def fetch_json(url: str, headers: dict[str, str] | None = None) -> Any:
    safe_url = safe_feed_url(url)
    parsed = urlsplit(safe_url)
    if not parsed.hostname or parsed.port is not None:
        raise ValueError("Source URL must use a hostname and the default HTTPS port.")
    opener = build_opener(_SameHostRedirectHandler(parsed.hostname))
    request = Request(safe_url, headers=headers or {}, method="GET")  # noqa: S310 - scheme/host are enforced above
    try:
        with opener.open(request, timeout=45) as response:
            content_length = response.headers.get("Content-Length")
            if content_length and int(content_length) > MAXIMUM_SOURCE_BYTES:
                raise ValueError("Source response exceeds 20 MiB.")
            body = response.read(MAXIMUM_SOURCE_BYTES + 1)
    except HTTPError as error:
        raise ValueError(f"Source request failed with HTTP {error.code}.") from error
    if len(body) > MAXIMUM_SOURCE_BYTES:
        raise ValueError("Source response exceeds 20 MiB.")
    try:
        return json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Source returned invalid JSON.") from error


def _string(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _number(value: object) -> float | None:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return None
    try:
        return float(value)
    except OverflowError:
        return None


def _first_number(*values: object) -> float | None:
    return next((number for value in values if (number := _number(value)) is not None), None)


def load_certstream(now: str, archive_root: str, lookback_days: int) -> SourceResult:
    candidates = read_recent_candidates(
        archive_root,
        lookback_days,
        datetime.fromisoformat(now.replace("Z", "+00:00")),
    )
    registry = load_brand_registry()
    signals: list[RawSignal] = []
    for candidate in candidates:
        match = score_domain(candidate["domain"].replace("[.]", "."), registry)
        if match is None:
            continue
        signals.append(
            RawSignal(
                url=match.domain,
                first_seen=candidate["observedAt"],
                last_seen=candidate["observedAt"],
                source="CertStream",
                status="suspected",
                brand=match.brand,
                confidence=match.confidence,
                reason_codes=reason_codes_from_match(match.reasons),
            )
        )
    suffix = "" if lookback_days == 1 else "s"
    suppressed = len(candidates) - len(signals)
    note = f"Open heuristic candidates from the last {lookback_days} day{suffix}"
    if suppressed:
        note += f"; {suppressed} candidate{'s' if suppressed != 1 else ''} no longer passed current registry rules"
    return SourceResult(
        source=_source(
            SOURCE_DEFINITIONS["certstream"],
            fetched_at=now,
            records=len(signals),
            state="healthy",
            note=note,
        ),
        signals=signals,
    )


def load_urlscan(now: str, archive_root: str, lookback_days: int) -> SourceResult:
    observed_at = datetime.fromisoformat(now.replace("Z", "+00:00"))
    archived = read_recent_urlscan(archive_root, lookback_days, observed_at)
    hunt_state = read_urlscan_hunt_state(archive_root)
    signals = [
        RawSignal(
            url=refang(signal["url"]),
            first_seen=signal["firstSeen"],
            last_seen=signal["lastSeen"],
            source="URLScan",
            status=signal["status"],
            brand=signal["brand"],
            country=signal["country"],
            host=signal["host"],
            screenshot_url=signal["screenshotUrl"],
            reference_url=signal.get("referenceUrl"),
            hashes=signal.get("hashes"),
            confidence=signal["confidence"],
            reason_codes=reason_codes_from_evidence(signal.get("brandEvidence", [])),
        )
        for signal in archived
    ]
    suffix = "" if lookback_days == 1 else "s"
    if hunt_state is None:
        state: SourceState = "partial" if signals else "skipped"
        note = f"Validated passive archive from the last {lookback_days} day{suffix}; hunt state is unavailable"
        fetched_at = None
    else:
        outcome = hunt_state["lastOutcome"]
        fetched_at = hunt_state["lastRunAt"]
        if outcome == "skipped-not-configured":
            state = "skipped"
            note = (
                f"Validated passive archive from the last {lookback_days} day{suffix}; "
                "URLScan API key is not configured"
            )
        elif outcome == "failed":
            state = "partial"
            note = (
                f"Validated passive archive from the last {lookback_days} day{suffix}; the latest passive hunt failed"
            )
        elif outcome == "budget-limited":
            state = "partial"
            note = (
                f"Validated passive archive from the last {lookback_days} day{suffix}; "
                "the latest hunt reached a configured request budget"
            )
        else:
            state = "healthy"
            note = (
                f"Passive public results validated from the last {lookback_days} day{suffix}; "
                "the latest scheduled hunt completed"
            )
    return SourceResult(
        source=_source(
            SOURCE_DEFINITIONS["urlscan"],
            fetched_at=fetched_at,
            records=len(signals),
            state=state,
            note=note,
        ),
        signals=signals,
    )


def _hecavex_signals(payload: Any) -> Iterable[Any]:
    if isinstance(payload, list):
        values = payload
    elif isinstance(payload, dict) and isinstance(payload.get("signals"), list):
        values = payload["signals"]
    else:
        raise ValueError("HECAVEX export returned an unexpected payload.")
    return islice(values, MAXIMUM_HECAVEX_RECORDS)


def _primary_html_hashes(value: dict[str, Any]) -> list[str] | None:
    hashes = value.get("hashes")
    if value.get("hashType") != "primary-html-sha256" or not isinstance(hashes, list):
        return None
    return [digest for digest in hashes if isinstance(digest, str)]


def fetch_hecavex(now: str, source_url: str, token: str | None = None) -> SourceResult:
    headers = {"Accept": "application/json", "User-Agent": "hecavex-radar/0.1"}
    if token and token.strip():
        headers["Authorization"] = f"Bearer {token.strip()}"
    payload = fetch_json(source_url, headers)
    signals: list[RawSignal] = []
    for value in _hecavex_signals(payload):
        if not isinstance(value, dict):
            continue
        url = _string(value.get("url")) or _string(value.get("indicator")) or _string(value.get("domain"))
        if not url:
            continue
        signals.append(
            RawSignal(
                url=url,
                first_seen=_string(value.get("firstSeen")) or _string(value.get("first_seen")),
                last_seen=_string(value.get("lastSeen")) or _string(value.get("last_seen")) or now,
                source="HECAVEX",
                status=_string(value.get("status")),
                brand=_string(value.get("brand"))
                or _string(value.get("brandTargeted"))
                or _string(value.get("brand_targeted")),
                country=_string(value.get("country")),
                host=_string(value.get("host")) or _string(value.get("hosting")),
                screenshot_url=_string(value.get("screenshotUrl")) or _string(value.get("screenshot_url")),
                reference_url=_string(value.get("referenceUrl")) or _string(value.get("reference_url")),
                hashes=_primary_html_hashes(value),
                confidence=_first_number(
                    value.get("confidence"), value.get("confidenceScore"), value.get("confidence_score")
                ),
                reason_codes=["hecavex-public-export"],
            )
        )
    return SourceResult(
        source=_source(
            SOURCE_DEFINITIONS["hecavex"],
            fetched_at=now,
            records=len(signals),
            state="healthy",
            note="Configured HECAVEX source",
        ),
        signals=signals,
    )
