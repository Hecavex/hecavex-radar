from __future__ import annotations

import gzip
import html
import io
import json
import re
from dataclasses import dataclass
from datetime import datetime
from http.client import HTTPMessage
from typing import IO, Any
from urllib.error import HTTPError
from urllib.parse import quote, urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .candidates import read_recent_candidates
from .models import FeedResult, FeedState, RadarSource, RawSignal
from .safety import clean_text, safe_feed_url

DEFAULT_MAXIMUM_BYTES = 100 * 1024 * 1024
REPORT_CARD = re.compile(r"<div\s+class=[\"']reportContainer[\"'][^>]*>", re.IGNORECASE)
URL_KIND = re.compile(r"<div\s+class=[\"']name[\"'][^>]*>\s*URL\s*</div>", re.IGNORECASE)
TITLE = re.compile(r"<div\s+class=[\"']title[\"'][^>]*>([\s\S]*?)</div>", re.IGNORECASE)
DATE = re.compile(r"<div\s+class=[\"']dateString[\"'][^>]*>([\s\S]*?)</div>", re.IGNORECASE)
TAGS = re.compile(r"<[^>]+>")


@dataclass(frozen=True, slots=True)
class SourceDefinition:
    name: str
    homepage: str


SOURCE_DEFINITIONS = {
    "phishtank": SourceDefinition("PhishTank", "https://phishtank.org/"),
    "openphish": SourceDefinition("OpenPhish", "https://openphish.com/"),
    "certstream": SourceDefinition("CertStream", "https://certstream.dev/"),
    "vmray": SourceDefinition("VMRay", "https://threatfeed.vmray.com/?classification=39"),
    "hecavex": SourceDefinition("HECAVEX", "https://hecavex.com/"),
}


def _source(
    definition: SourceDefinition,
    *,
    fetched_at: str | None,
    records: int,
    state: FeedState,
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


class _SafeRedirectHandler(HTTPRedirectHandler):
    def __init__(self, allowed_hosts: tuple[str, ...]) -> None:
        self._allowed_hosts = allowed_hosts
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
        hostname = (destination.hostname or "").lower()
        allowed = any(hostname == host or hostname.endswith(f".{host}") for host in self._allowed_hosts)
        if code not in {301, 302, 303, 307, 308} or destination.scheme != "https" or not allowed:
            raise HTTPError(request.full_url, code, "Feed returned an unapproved redirect.", headers, file_pointer)
        if destination.username is not None or destination.password is not None:
            raise HTTPError(request.full_url, code, "Feed returned an unapproved redirect.", headers, file_pointer)
        return super().redirect_request(request, file_pointer, code, message, headers, destination.geturl())


def fetch_bytes(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout_seconds: float = 45,
    maximum_bytes: int = DEFAULT_MAXIMUM_BYTES,
    allowed_redirect_hosts: tuple[str, ...] = (),
) -> bytes:
    safe_url = safe_feed_url(url)
    opener = build_opener(_SafeRedirectHandler(allowed_redirect_hosts))
    request = Request(safe_url, headers=headers or {}, method="GET")
    try:
        with opener.open(request, timeout=timeout_seconds) as response:
            content_length = response.headers.get("Content-Length")
            if content_length and int(content_length) > maximum_bytes:
                raise ValueError("Feed exceeded the download limit.")
            chunks: list[bytes] = []
            received = 0
            while chunk := response.read(64 * 1024):
                received += len(chunk)
                if received > maximum_bytes:
                    raise ValueError("Feed exceeded the download limit.")
                chunks.append(chunk)
            return b"".join(chunks)
    except HTTPError as error:
        raise ValueError(f"Feed request failed with HTTP {error.code}.") from error


def fetch_text(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout_seconds: float = 45,
    maximum_bytes: int = DEFAULT_MAXIMUM_BYTES,
    allowed_redirect_hosts: tuple[str, ...] = (),
    decompress_gzip: bool = False,
) -> str:
    body = fetch_bytes(
        url,
        headers=headers,
        timeout_seconds=timeout_seconds,
        maximum_bytes=maximum_bytes,
        allowed_redirect_hosts=allowed_redirect_hosts,
    )
    if decompress_gzip:
        with gzip.GzipFile(fileobj=io.BytesIO(body)) as compressed:
            body = compressed.read(maximum_bytes + 1)
        if len(body) > maximum_bytes:
            raise ValueError("Feed exceeded the decompressed download limit.")
    return body.decode("utf-8", errors="strict")


def _json(text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError as error:
        raise ValueError("Feed returned invalid JSON.") from error


def _string(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _number(value: object) -> float | None:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _first_number(*values: object) -> float | None:
    return next((number for value in values if (number := _number(value)) is not None), None)


def fetch_phishtank(now: str, app_key: str | None, user_agent: str) -> FeedResult:
    key_segment = f"{quote(app_key.strip(), safe='')}/" if app_key and app_key.strip() else ""
    payload = _json(
        fetch_text(
            f"https://data.phishtank.com/data/{key_segment}online-valid.json.gz",
            headers={"User-Agent": user_agent},
            allowed_redirect_hosts=("cdn.phishtank.com",),
            decompress_gzip=True,
        )
    )
    if not isinstance(payload, list):
        raise ValueError("PhishTank returned an unexpected payload.")
    signals: list[RawSignal] = []
    for value in payload:
        if not isinstance(value, dict) or not isinstance(value.get("url"), str):
            continue
        raw_details = value.get("details")
        details = (
            raw_details[0] if isinstance(raw_details, list) and raw_details and isinstance(raw_details[0], dict) else {}
        )
        ip_address = clean_text(details.get("ip_address"), 80)
        network = clean_text(details.get("announcing_network"), 40)
        host_parts = [f"AS{network.removeprefix('AS').removeprefix('as')}" if network else None, ip_address]
        signals.append(
            RawSignal(
                url=value["url"],
                first_seen=_string(value.get("submission_time")) or _string(value.get("verification_time")),
                last_seen=now,
                source=SOURCE_DEFINITIONS["phishtank"].name,
                status="active" if value.get("online") == "yes" else "offline",
                brand=_string(value.get("target")),
                country=_string(details.get("country")),
                host=" · ".join(part for part in host_parts if part) or None,
                confidence=95 if value.get("verified") == "yes" else 70,
            )
        )
    note = "Verified online feed" if app_key and app_key.strip() else "Verified online feed (anonymous download)"
    return FeedResult(
        source=_source(
            SOURCE_DEFINITIONS["phishtank"], fetched_at=now, records=len(signals), state="healthy", note=note
        ),
        signals=signals,
    )


def fetch_openphish(now: str) -> FeedResult:
    body = fetch_text(
        "https://openphish.com/feed.txt",
        headers={"User-Agent": "hecavex-radar/0.1 (+https://radar.hecavex.com)"},
    )
    signals = [
        RawSignal(url=line, first_seen=now, last_seen=now, source="OpenPhish", status="active", confidence=85)
        for raw_line in body.splitlines()
        if (line := raw_line.strip()) and not line.startswith("#")
    ]
    return FeedResult(
        source=_source(
            SOURCE_DEFINITIONS["openphish"],
            fetched_at=now,
            records=len(signals),
            state="healthy",
            note="Community feed",
        ),
        signals=signals,
    )


def _decode_html(value: str) -> str:
    return " ".join(html.unescape(TAGS.sub(" ", value)).split()).strip()


def parse_vmray_page(body: str, now: str) -> list[RawSignal]:
    signals: list[RawSignal] = []
    for card in REPORT_CARD.split(body)[1:]:
        if not URL_KIND.search(card):
            continue
        title = TITLE.search(card)
        date = DATE.search(card)
        url = _decode_html(title.group(1)) if title else ""
        if not re.match(r"^https?://", url, flags=re.IGNORECASE):
            continue
        signals.append(
            RawSignal(
                url=url,
                first_seen=_decode_html(date.group(1)) if date else now,
                last_seen=now,
                source="VMRay",
                status="active",
                confidence=90,
            )
        )
    return signals


def fetch_vmray(now: str, pages: int) -> FeedResult:
    signals: list[RawSignal] = []
    for page in range(1, pages + 1):
        body = fetch_text(
            f"https://threatfeed.vmray.com/?classification=39&page={page}",
            headers={"Accept": "text/html", "User-Agent": "hecavex-radar/0.1 (+https://radar.hecavex.com)"},
            maximum_bytes=5 * 1024 * 1024,
        )
        if not REPORT_CARD.search(body):
            raise ValueError("VMRay page no longer matches the expected report-card layout.")
        signals.extend(parse_vmray_page(body, now))
    suffix = "" if pages == 1 else "s"
    return FeedResult(
        source=_source(
            SOURCE_DEFINITIONS["vmray"],
            fetched_at=now,
            records=len(signals),
            state="healthy",
            note=f"Public phishing page ({pages} page{suffix})",
        ),
        signals=signals,
    )


def load_certstream(now: str, archive_root: str, lookback_days: int) -> FeedResult:
    candidates = read_recent_candidates(archive_root, lookback_days, datetime.fromisoformat(now.replace("Z", "+00:00")))
    suffix = "" if lookback_days == 1 else "s"
    return FeedResult(
        source=_source(
            SOURCE_DEFINITIONS["certstream"],
            fetched_at=now,
            records=len(candidates),
            state="healthy",
            note=f"Open heuristic candidates from the last {lookback_days} day{suffix}",
        ),
        signals=[
            RawSignal(
                url=candidate["domain"],
                first_seen=candidate["observedAt"],
                last_seen=candidate["observedAt"],
                source="CertStream",
                status="suspected",
                brand=candidate["brand"],
                confidence=candidate["confidence"],
            )
            for candidate in candidates
        ],
    )


def _hecavex_signals(payload: Any) -> list[Any]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict) and isinstance(payload.get("signals"), list):
        return list(payload["signals"])
    raise ValueError("HECAVEX export returned an unexpected payload.")


def fetch_hecavex(now: str, feed_url: str, token: str | None = None) -> FeedResult:
    headers = {"Accept": "application/json", "User-Agent": "hecavex-radar/0.1"}
    if token and token.strip():
        headers["Authorization"] = f"Bearer {token.strip()}"
    payload = _json(fetch_text(safe_feed_url(feed_url), headers=headers))
    signals: list[RawSignal] = []
    for value in _hecavex_signals(payload):
        if not isinstance(value, dict):
            continue
        url = _string(value.get("url")) or _string(value.get("indicator")) or _string(value.get("domain"))
        if not url:
            continue
        raw_sources = value.get("sources")
        sources = [source for source in raw_sources if isinstance(source, str)] if isinstance(raw_sources, list) else []
        signals.append(
            RawSignal(
                url=url,
                first_seen=_string(value.get("firstSeen")) or _string(value.get("first_seen")),
                last_seen=_string(value.get("lastSeen")) or _string(value.get("last_seen")) or now,
                source=sources[0] if sources else _string(value.get("source")) or "HECAVEX",
                status=_string(value.get("status")),
                brand=_string(value.get("brand"))
                or _string(value.get("brandTargeted"))
                or _string(value.get("brand_targeted")),
                country=_string(value.get("country")),
                host=_string(value.get("host")) or _string(value.get("hosting")),
                screenshot_url=_string(value.get("screenshotUrl")) or _string(value.get("screenshot_url")),
                confidence=_first_number(
                    value.get("confidence"), value.get("confidenceScore"), value.get("confidence_score")
                ),
            )
        )
    return FeedResult(
        source=_source(
            SOURCE_DEFINITIONS["hecavex"],
            fetched_at=now,
            records=len(signals),
            state="healthy",
            note="Approved public export",
        ),
        signals=signals,
    )
