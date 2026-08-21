from __future__ import annotations

import ipaddress
import math
import re
from datetime import UTC, datetime

from .models import RadarSignal, RawSignal, SignalStatus
from .safety import (
    clean_text,
    defang_domains_in_text,
    defang_host,
    parse_and_defang_url,
    safe_screenshot_url,
    stable_id,
)

IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
IPV6_CANDIDATE = re.compile(r"(?<![\da-f:])\[?[\da-f:]*:[\da-f:]+\]?(?![\da-f:])", re.IGNORECASE)


def _parse_date(value: str | None, fallback: str) -> str:
    if not value:
        return fallback
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    except ValueError:
        return fallback


def _date_value(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _map_status(value: str | None) -> SignalStatus:
    normalized = value.strip().lower() if value else ""
    if normalized in {"active", "confirmed", "live", "online", "verified"}:
        return "active"
    if normalized in {"potential", "pending", "suspected"}:
        return "suspected"
    if normalized in {"down", "inactive", "offline"}:
        return "offline"
    if normalized in {"mitigated", "removed", "takedown"}:
        return "mitigated"
    return "unknown"


def _confidence(value: float | None) -> int:
    if value is None or not math.isfinite(value):
        return 50
    return math.floor(min(100.0, max(0.0, value)) + 0.5)


def _safe_host(value: str | None) -> str | None:
    cleaned = clean_text(value, 160)
    if not cleaned:
        return None

    def defang_ipv6(match: re.Match[str]) -> str:
        candidate = match.group(0).removeprefix("[").removesuffix("]")
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            return match.group(0)
        return defang_host(candidate) if address.version == 6 else match.group(0)

    ipv4_defanged = IPV4.sub(lambda match: defang_host(match.group(1)), cleaned)
    return defang_domains_in_text(IPV6_CANDIDATE.sub(defang_ipv6, ipv4_defanged))


def prepare_signal(raw: RawSignal, now: str, allowed_screenshot_hosts: list[str]) -> RadarSignal | None:
    safe_url = parse_and_defang_url(raw.url)
    source = clean_text(raw.source, 80)
    if not safe_url or not source:
        return None
    last_seen = _parse_date(raw.last_seen, now)
    first_seen = _parse_date(raw.first_seen, last_seen)
    if _date_value(first_seen) > _date_value(last_seen):
        first_seen = last_seen
    return {
        "id": stable_id(safe_url.key),
        "url": safe_url.display_url,
        "domain": safe_url.display_domain,
        "firstSeen": first_seen,
        "lastSeen": last_seen,
        "sources": [source],
        "status": _map_status(raw.status),
        "brand": clean_text(raw.brand, 120),
        "country": clean_text(raw.country, 80),
        "host": _safe_host(raw.host),
        "screenshotUrl": safe_screenshot_url(raw.screenshot_url, allowed_screenshot_hosts),
        "confidence": _confidence(raw.confidence),
    }


STATUS_PRIORITY: dict[SignalStatus, int] = {
    "active": 5,
    "suspected": 4,
    "unknown": 3,
    "offline": 2,
    "mitigated": 1,
}


def merge_signals(signals: list[RadarSignal], maximum: int) -> list[RadarSignal]:
    merged: dict[str, RadarSignal] = {}
    for signal in signals:
        current = merged.get(signal["id"])
        if current is None:
            merged[signal["id"]] = signal.copy()
            continue
        current["firstSeen"] = min(current["firstSeen"], signal["firstSeen"], key=_date_value)
        current["lastSeen"] = max(current["lastSeen"], signal["lastSeen"], key=_date_value)
        current["sources"] = sorted(set(current["sources"] + signal["sources"]))
        if STATUS_PRIORITY[signal["status"]] > STATUS_PRIORITY[current["status"]]:
            current["status"] = signal["status"]
        current["brand"] = current["brand"] or signal["brand"]
        current["country"] = current["country"] or signal["country"]
        current["host"] = current["host"] or signal["host"]
        current["screenshotUrl"] = current["screenshotUrl"] or signal["screenshotUrl"]
        current["confidence"] = max(current["confidence"], signal["confidence"])

    ordered = sorted(
        merged.values(),
        key=lambda signal: (
            -_date_value(signal["lastSeen"]).timestamp(),
            -_date_value(signal["firstSeen"]).timestamp(),
            signal["id"],
        ),
    )
    return ordered[:maximum]
