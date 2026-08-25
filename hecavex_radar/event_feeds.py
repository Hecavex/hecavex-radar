from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import unicodedata
import xml.etree.ElementTree as ET
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from pathlib import Path
from typing import Any, Literal, TypedDict, cast

from .brands import normalize_domain
from .history import KNOWN_SOURCES, KNOWN_STATUSES, read_event_file
from .provenance import normalize_reason_codes
from .safety import clean_text, defang_domains_in_text, defang_host, stable_id

WINDOW_DAYS: Literal[30] = 30
PUBLIC_BASE_URL = "https://radar.hecavex.com"
MAXIMUM_INPUT_BYTES = 2 * 1024 * 1024
MAXIMUM_HISTORY_EVENTS = 50_000
MAXIMUM_FEED_EVENTS = 1_000
MAXIMUM_BRAND_FEEDS = 128
MAXIMUM_EVENT_JSON_BYTES = 1024 * 1024
MAXIMUM_SYNDICATION_BYTES = 2 * 1024 * 1024
SIGNAL_ID = re.compile(r"^[a-f\d]{20}$")
EVENT_ID = re.compile(r"^[a-f\d]{32}$")
UTC_MILLISECONDS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")

FeedEventType = Literal["first-publication", "reobservation", "status-change", "retraction"]
FeedStatus = Literal["active", "suspected", "offline", "mitigated", "unknown", "retracted"]


class FeedEvent(TypedDict):
    id: str
    type: FeedEventType
    occurredAt: str
    signalId: str
    signalPath: str
    domain: str
    brand: str
    status: FeedStatus
    previousStatus: str | None
    sources: list[str]


FeedWindow = TypedDict(
    "FeedWindow",
    {"days": Literal[30], "from": str, "to": str},
)


class EventArtifact(TypedDict):
    schemaVersion: Literal[1]
    dataset: Literal["radar-events"]
    generatedAt: str
    window: FeedWindow
    totalAvailable: int
    truncated: bool
    events: list[FeedEvent]


@dataclass(frozen=True, slots=True)
class EventFeedBundle:
    artifact: EventArtifact
    event_json: bytes
    atom: bytes
    rss: bytes
    json_feed: bytes


@dataclass(frozen=True, slots=True)
class BrandFeedBundle:
    brand: str
    slug: str
    event_count: int
    atom: bytes
    rss: bytes
    json_feed: bytes


def _timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not UTC_MILLISECONDS.fullmatch(value):
        return None
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError:
        return None
    canonical = parsed.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return parsed if canonical == value else None


def _timestamp_text(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _canonical_domain(value: object) -> str | None:
    if not isinstance(value, str) or len(value) > 512 or "://" in value:
        return None
    normalized = normalize_domain(value.replace("[.]", ".").replace("[:]", ":"))
    if normalized is None:
        return None
    canonical = defang_host(normalized)
    return value if canonical == value else None


def _safe_brand(value: object) -> str | None:
    if not isinstance(value, str) or "://" in value:
        return None
    cleaned = clean_text(value, 120)
    if (
        cleaned is None
        or cleaned != value
        or any(
            not (
                code in {0x09, 0x0A, 0x0D}
                or 0x20 <= code <= 0xD7FF
                or 0xE000 <= code <= 0xFFFD
                or 0x10000 <= code <= 0x10FFFF
            )
            for code in map(ord, cleaned)
        )
    ):
        return None
    return defang_domains_in_text(cleaned)


def _history_identifier(value: Mapping[str, object]) -> str:
    identity = {
        key: value[key]
        for key in (
            "schemaVersion",
            "signalId",
            "eventType",
            "observedAt",
            "sources",
            "status",
            "previousStatus",
        )
    }
    canonical = json.dumps(identity, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32]


def _valid_history_event(value: object) -> bool:
    fields = {
        "schemaVersion",
        "eventId",
        "signalId",
        "eventType",
        "observedAt",
        "domain",
        "brand",
        "sources",
        "status",
        "previousStatus",
        "confidence",
        "reasonCodes",
    }
    if not isinstance(value, dict) or set(value) != fields:
        return False
    domain = _canonical_domain(value.get("domain"))
    brand = _safe_brand(value.get("brand"))
    sources = value.get("sources")
    reasons = value.get("reasonCodes")
    previous = value.get("previousStatus")
    return bool(
        value.get("schemaVersion") == 1
        and isinstance(value.get("eventId"), str)
        and EVENT_ID.fullmatch(value["eventId"])
        and value["eventId"] == _history_identifier(value)
        and isinstance(value.get("signalId"), str)
        and SIGNAL_ID.fullmatch(value["signalId"])
        and domain is not None
        and value["signalId"] == stable_id(domain.lower())
        and brand is not None
        and value.get("eventType") in {"observation", "status-transition"}
        and _timestamp(value.get("observedAt")) is not None
        and isinstance(sources, list)
        and 1 <= len(sources) <= len(KNOWN_SOURCES)
        and sources == sorted(set(sources))
        and all(source in KNOWN_SOURCES for source in sources)
        and value.get("status") in KNOWN_STATUSES
        and (previous is None or previous in KNOWN_STATUSES)
        and (value["eventType"] == "status-transition" or previous is None)
        and type(value.get("confidence")) is int
        and 0 <= value["confidence"] <= 100
        and isinstance(reasons, list)
        and reasons == normalize_reason_codes(reasons)
        and bool(reasons)
    )


def _feed_identifier(
    event_type: FeedEventType,
    source_identifier: str,
    signal_identifier: str,
    occurred_at: str,
) -> str:
    value = f"{event_type}\0{source_identifier}\0{signal_identifier}\0{occurred_at}"
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]


def _event_from_history(value: Mapping[str, object], event_type: FeedEventType) -> FeedEvent:
    signal_identifier = cast(str, value["signalId"])
    previous = cast(str | None, value["previousStatus"])
    return {
        "id": _feed_identifier(
            event_type,
            cast(str, value["eventId"]),
            signal_identifier,
            cast(str, value["observedAt"]),
        ),
        "type": event_type,
        "occurredAt": cast(str, value["observedAt"]),
        "signalId": signal_identifier,
        "signalPath": f"/signals/{signal_identifier}/",
        "domain": cast(str, value["domain"]),
        "brand": cast(str, _safe_brand(value["brand"])),
        "status": cast(FeedStatus, value["status"]),
        "previousStatus": previous,
        "sources": cast(list[str], value["sources"]),
    }


def _snapshot_first_seen(snapshot: Mapping[str, object]) -> dict[str, str]:
    if snapshot.get("schemaVersion") != 2 or snapshot.get("dataset") != "live":
        raise ValueError("The Radar snapshot must use the live schema version 2 contract.")
    signals = snapshot.get("signals")
    if not isinstance(signals, list) or len(signals) > 2_500:
        raise ValueError("The Radar snapshot has an invalid or oversized signal collection.")
    first_seen: dict[str, str] = {}
    for value in signals:
        if not isinstance(value, dict):
            raise ValueError("The Radar snapshot contains a malformed signal.")
        identifier = value.get("id")
        domain = _canonical_domain(value.get("domain"))
        observed = value.get("firstSeen")
        raw_brand = value.get("brand")
        if (
            not isinstance(identifier, str)
            or not SIGNAL_ID.fullmatch(identifier)
            or domain is None
            or identifier != stable_id(domain.lower())
            or _timestamp(observed) is None
            or (raw_brand is not None and _safe_brand(raw_brand) is None)
            or identifier in first_seen
        ):
            raise ValueError("The Radar snapshot contains an invalid signal identity.")
        first_seen[identifier] = cast(str, observed)
    return first_seen


def _retraction_events(review: Mapping[str, object] | None) -> list[FeedEvent]:
    if review is None:
        return []
    if review.get("schemaVersion") != 2 or review.get("dataset") != "radar-review-decisions":
        raise ValueError("The review export must use schema version 2.")
    assessments = review.get("assessments")
    if not isinstance(assessments, list) or len(assessments) > 2_500:
        raise ValueError("The review export has an invalid or oversized assessment collection.")
    events: list[FeedEvent] = []
    for value in assessments:
        if not isinstance(value, dict) or value.get("revoked") is not True:
            continue
        identifier = value.get("signalId")
        decision_identifier = value.get("id")
        domain = _canonical_domain(value.get("domain"))
        brand = _safe_brand(value.get("brand"))
        occurred_at = value.get("modifiedAt")
        if (
            not isinstance(identifier, str)
            or not SIGNAL_ID.fullmatch(identifier)
            or not isinstance(decision_identifier, str)
            or not re.fullmatch(r"[a-f\d]{24}", decision_identifier)
            or domain is None
            or identifier != stable_id(domain.lower())
            or brand is None
            or _timestamp(occurred_at) is None
        ):
            raise ValueError("The review export contains an invalid revoked assessment.")
        events.append(
            {
                "id": _feed_identifier(
                    "retraction", decision_identifier, identifier, cast(str, occurred_at)
                ),
                "type": "retraction",
                "occurredAt": cast(str, occurred_at),
                "signalId": identifier,
                "signalPath": f"/signals/{identifier}/",
                "domain": domain,
                "brand": brand,
                "status": "retracted",
                "previousStatus": None,
                "sources": ["HECAVEX"],
            }
        )
    return events


def _classify_events(
    history_events: Sequence[Mapping[str, object]],
    snapshot_first_seen: Mapping[str, str],
) -> list[FeedEvent]:
    first_publications: dict[str, str] = {}
    for value in history_events:
        if (
            value["eventType"] == "status-transition"
            and value["previousStatus"] is None
            and "first-publication" in cast(list[str], value["reasonCodes"])
        ):
            identifier = cast(str, value["signalId"])
            first_publications[identifier] = min(
                first_publications.get(identifier, cast(str, value["observedAt"])),
                cast(str, value["observedAt"]),
            )

    classified: list[FeedEvent] = []
    for value in history_events:
        event_type = value["eventType"]
        previous = value["previousStatus"]
        identifier = cast(str, value["signalId"])
        observed_at = cast(str, value["observedAt"])
        reasons = cast(list[str], value["reasonCodes"])
        if event_type == "status-transition" and previous is None and "first-publication" in reasons:
            classified.append(_event_from_history(value, "first-publication"))
            continue
        if event_type == "status-transition" and previous is not None:
            classified.append(_event_from_history(value, "status-change"))
            continue
        if event_type != "observation":
            continue

        publication_at = first_publications.get(identifier)
        if publication_at is not None:
            if observed_at > publication_at:
                classified.append(_event_from_history(value, "reobservation"))
            continue
        known_first_seen = snapshot_first_seen.get(identifier)
        if known_first_seen is not None and observed_at > known_first_seen:
            classified.append(_event_from_history(value, "reobservation"))
    return classified


def _event_title(event: FeedEvent) -> str:
    lead = {
        "first-publication": "First publication",
        "reobservation": "Reobserved",
        "status-change": "Status changed",
        "retraction": "Assessment retracted",
    }[event["type"]]
    return f"{lead}: {event['domain']}"


def _event_summary(event: FeedEvent) -> str:
    source_text = ", ".join(event["sources"])
    if event["type"] == "status-change":
        state = f"Status changed from {event['previousStatus']} to {event['status']}."
    elif event["type"] == "retraction":
        state = "A previously published analyst assessment was retracted."
    elif event["type"] == "reobservation":
        state = f"The {event['brand']} candidate was observed again."
    else:
        state = f"A {event['brand']} candidate was published for the first time."
    return f"{state} Source: {source_text}. Indicator: {event['domain']}."


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def _public_url(path: str) -> str:
    return path if path.startswith(f"{PUBLIC_BASE_URL}/") else f"{PUBLIC_BASE_URL}{path}"


def _atom_bytes(
    artifact: EventArtifact,
    *,
    title: str = "HECAVEX Radar changes",
    identifier: str = "urn:hecavex-radar:events",
    home_page_url: str = "/changes/",
    feed_url: str = "/data/events.atom.xml",
) -> bytes:
    namespace = "http://www.w3.org/2005/Atom"
    ET.register_namespace("", namespace)
    feed = ET.Element(f"{{{namespace}}}feed")
    ET.SubElement(feed, f"{{{namespace}}}id").text = identifier
    ET.SubElement(feed, f"{{{namespace}}}title").text = title
    ET.SubElement(feed, f"{{{namespace}}}updated").text = artifact["generatedAt"]
    ET.SubElement(
        feed,
        f"{{{namespace}}}link",
        {"rel": "alternate", "href": _public_url(home_page_url)},
    )
    ET.SubElement(
        feed,
        f"{{{namespace}}}link",
        {"rel": "self", "type": "application/atom+xml", "href": _public_url(feed_url)},
    )
    author = ET.SubElement(feed, f"{{{namespace}}}author")
    ET.SubElement(author, f"{{{namespace}}}name").text = "HECAVEX"
    for event in artifact["events"]:
        entry = ET.SubElement(feed, f"{{{namespace}}}entry")
        ET.SubElement(entry, f"{{{namespace}}}id").text = f"urn:hecavex-radar:event:{event['id']}"
        ET.SubElement(entry, f"{{{namespace}}}title").text = _event_title(event)
        ET.SubElement(entry, f"{{{namespace}}}updated").text = event["occurredAt"]
        ET.SubElement(entry, f"{{{namespace}}}link", {"href": _public_url(event["signalPath"])})
        ET.SubElement(entry, f"{{{namespace}}}category", {"term": event["type"]})
        ET.SubElement(entry, f"{{{namespace}}}summary").text = _event_summary(event)
    body = cast(
        bytes,
        ET.tostring(feed, encoding="utf-8", xml_declaration=True, short_empty_elements=True),
    )
    return body + b"\n"


def _rss_bytes(
    artifact: EventArtifact,
    *,
    title: str = "HECAVEX Radar changes",
    channel_path: str = "/changes/",
) -> bytes:
    rss = ET.Element("rss", {"version": "2.0"})
    channel = ET.SubElement(rss, "channel")
    ET.SubElement(channel, "title").text = title
    ET.SubElement(channel, "link").text = _public_url(channel_path)
    ET.SubElement(channel, "description").text = (
        "Bounded publication, reobservation, status-change and retraction events."
    )
    generated = cast(datetime, _timestamp(artifact["generatedAt"]))
    ET.SubElement(channel, "lastBuildDate").text = format_datetime(generated, usegmt=True)
    for event in artifact["events"]:
        item = ET.SubElement(channel, "item")
        ET.SubElement(item, "title").text = _event_title(event)
        ET.SubElement(item, "link").text = _public_url(event["signalPath"])
        ET.SubElement(item, "guid", {"isPermaLink": "false"}).text = (
            f"urn:hecavex-radar:event:{event['id']}"
        )
        occurred = cast(datetime, _timestamp(event["occurredAt"]))
        ET.SubElement(item, "pubDate").text = format_datetime(occurred, usegmt=True)
        ET.SubElement(item, "category").text = event["type"]
        ET.SubElement(item, "description").text = _event_summary(event)
    body = cast(
        bytes,
        ET.tostring(rss, encoding="utf-8", xml_declaration=True, short_empty_elements=True),
    )
    return body + b"\n"


def _json_feed_bytes(
    artifact: EventArtifact,
    *,
    title: str = "HECAVEX Radar changes",
    home_page_url: str = "/changes/",
    feed_url: str = "/data/events.feed.json",
) -> bytes:
    value = {
        "version": "https://jsonfeed.org/version/1.1",
        "title": title,
        "home_page_url": _public_url(home_page_url),
        "feed_url": _public_url(feed_url),
        "language": "en",
        "items": [
            {
                "id": f"urn:hecavex-radar:event:{event['id']}",
                "url": _public_url(event["signalPath"]),
                "title": _event_title(event),
                "content_text": _event_summary(event),
                "date_published": event["occurredAt"],
                "tags": [event["type"], event["brand"]],
            }
            for event in artifact["events"]
        ],
    }
    return _json_bytes(value)


def build_event_feeds(
    history_events: Iterable[Mapping[str, object]],
    snapshot: Mapping[str, object],
    generated_at: str,
    review: Mapping[str, object] | None = None,
) -> EventFeedBundle:
    """Build deterministic 30-day public event and syndication artifacts.

    Candidate URLs are deliberately not accepted. Feed items contain a canonical
    defanged domain and an internal ``/signals/<id>/`` path only.
    """

    now = _timestamp(generated_at)
    if now is None:
        raise ValueError("generated_at must be a canonical UTC millisecond timestamp.")
    snapshot_first_seen = _snapshot_first_seen(snapshot)
    validated: list[Mapping[str, object]] = []
    history_identifiers: set[str] = set()
    for value in history_events:
        if len(validated) >= MAXIMUM_HISTORY_EVENTS:
            raise ValueError(f"Refusing more than {MAXIMUM_HISTORY_EVENTS} history events.")
        if not _valid_history_event(value):
            raise ValueError("The history input contains an invalid event.")
        source_identifier = cast(str, value["eventId"])
        if source_identifier in history_identifiers:
            raise ValueError("The history input contains a duplicate event ID.")
        history_identifiers.add(source_identifier)
        observed = cast(datetime, _timestamp(value["observedAt"]))
        if observed > now:
            raise ValueError("The history input contains an event after generated_at.")
        validated.append(value)

    cutoff = now - timedelta(days=WINDOW_DAYS)
    candidates = _classify_events(validated, snapshot_first_seen) + _retraction_events(review)
    if any(cast(datetime, _timestamp(event["occurredAt"])) > now for event in candidates):
        raise ValueError("An event-feed input contains an event after generated_at.")
    in_window = [
        event
        for event in candidates
        if (occurred := _timestamp(event["occurredAt"])) is not None and cutoff <= occurred <= now
    ]
    unique = {event["id"]: event for event in in_window}
    ordered = sorted(
        unique.values(), key=lambda event: (event["occurredAt"], event["id"]), reverse=True
    )
    selected = ordered[:MAXIMUM_FEED_EVENTS]
    artifact: EventArtifact = {
        "schemaVersion": 1,
        "dataset": "radar-events",
        "generatedAt": generated_at,
        "window": {
            "days": WINDOW_DAYS,
            "from": _timestamp_text(cutoff),
            "to": generated_at,
        },
        "totalAvailable": len(ordered),
        "truncated": len(ordered) > len(selected),
        "events": selected,
    }
    event_json = _json_bytes(artifact)
    atom = _atom_bytes(artifact)
    rss = _rss_bytes(artifact)
    json_feed = _json_feed_bytes(artifact)
    limits = (
        ("event JSON", event_json, MAXIMUM_EVENT_JSON_BYTES),
        ("Atom feed", atom, MAXIMUM_SYNDICATION_BYTES),
        ("RSS feed", rss, MAXIMUM_SYNDICATION_BYTES),
        ("JSON Feed", json_feed, MAXIMUM_SYNDICATION_BYTES),
    )
    for label, body, maximum in limits:
        if len(body) > maximum:
            raise ValueError(f"The generated {label} exceeds its {maximum}-byte publication limit.")
    return EventFeedBundle(artifact, event_json, atom, rss, json_feed)


def _brand_slug(value: str) -> str:
    ascii_value = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode("ascii")
    slug = "-".join(re.findall(r"[a-z0-9]+", ascii_value.lower()))[:64].strip("-")
    if slug:
        return slug
    return "brand-" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def build_brand_event_feeds(
    artifact: EventArtifact,
    brands: Iterable[str],
) -> list[BrandFeedBundle]:
    """Build deterministic per-brand syndication views of the global event window."""

    safe_brands = sorted(
        {
            safe
            for brand in brands
            for safe in [_safe_brand(brand)]
            if safe is not None
        },
        key=lambda value: (value.casefold(), value),
    )
    if len(safe_brands) > MAXIMUM_BRAND_FEEDS:
        raise ValueError(f"Refusing more than {MAXIMUM_BRAND_FEEDS} per-brand event feeds.")
    base_slugs: dict[str, list[str]] = {}
    for brand in safe_brands:
        base_slugs.setdefault(_brand_slug(brand), []).append(brand)

    bundles: list[BrandFeedBundle] = []
    for brand in safe_brands:
        base_slug = _brand_slug(brand)
        slug = base_slug
        if len(base_slugs[base_slug]) > 1:
            suffix = hashlib.sha256(brand.encode("utf-8")).hexdigest()[:8]
            slug = f"{base_slug[:55].rstrip('-')}-{suffix}"
        selected_events = [event for event in artifact["events"] if event["brand"] == brand]
        brand_artifact = cast(
            EventArtifact,
            {
                **artifact,
                "totalAvailable": len(selected_events),
                "truncated": False,
                "events": selected_events,
            },
        )
        title = f"HECAVEX Radar changes: {brand}"
        hub_path = f"/brands/{slug}/"
        feed_root = f"/data/brands/{slug}"
        bundles.append(
            BrandFeedBundle(
                brand=brand,
                slug=slug,
                event_count=len(selected_events),
                atom=_atom_bytes(
                    brand_artifact,
                    title=title,
                    identifier=f"urn:hecavex-radar:brand-events:{slug}",
                    home_page_url=hub_path,
                    feed_url=f"{feed_root}/events.atom.xml",
                ),
                rss=_rss_bytes(brand_artifact, title=title, channel_path=hub_path),
                json_feed=_json_feed_bytes(
                    brand_artifact,
                    title=title,
                    home_page_url=hub_path,
                    feed_url=f"{feed_root}/events.feed.json",
                ),
            )
        )
    return bundles


def _read_json(path: Path) -> Mapping[str, object]:
    try:
        if path.stat().st_size > MAXIMUM_INPUT_BYTES:
            raise ValueError(f"Input JSON exceeds {MAXIMUM_INPUT_BYTES} bytes: {path}")
        value: Any = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise ValueError(f"Required event-feed input is missing: {path}") from error
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"Event-feed input is not valid UTF-8 JSON: {path}") from error
    if not isinstance(value, dict):
        raise ValueError(f"Event-feed input must be a JSON object: {path}")
    return cast(Mapping[str, object], value)


def read_recent_history_events(history_root: str | Path, generated_at: str) -> list[Mapping[str, object]]:
    now = _timestamp(generated_at)
    if now is None:
        raise ValueError("generated_at must be a canonical UTC millisecond timestamp.")
    first_day = (now - timedelta(days=WINDOW_DAYS)).date()
    events: list[Mapping[str, object]] = []
    for offset in range((now.date() - first_day).days + 1):
        day = first_day + timedelta(days=offset)
        path = Path(history_root) / "daily" / day.isoformat() / "events.ndjson"
        events.extend(read_event_file(path))
        if len(events) > MAXIMUM_HISTORY_EVENTS:
            raise ValueError(f"Refusing more than {MAXIMUM_HISTORY_EVENTS} recent history events.")
    return events


def build_event_feeds_from_files(
    history_root: str | Path,
    snapshot_path: str | Path,
    *,
    generated_at: str | None = None,
    review_path: str | Path | None = None,
) -> EventFeedBundle:
    snapshot = _read_json(Path(snapshot_path))
    effective_generated_at = generated_at
    if effective_generated_at is None:
        candidate = snapshot.get("lastSuccessfulSyncAt")
        if not isinstance(candidate, str):
            raise ValueError("The Radar snapshot does not provide lastSuccessfulSyncAt.")
        effective_generated_at = candidate
    review = _read_json(Path(review_path)) if review_path is not None else None
    events = read_recent_history_events(history_root, effective_generated_at)
    return build_event_feeds(events, snapshot, effective_generated_at, review)


def _atomic_write(path: Path, body: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=path.parent, prefix=f".{path.name}.", suffix=".tmp", delete=False
        ) as handle:
            temporary = Path(handle.name)
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise


def write_event_feeds(output_directory: str | Path, bundle: EventFeedBundle) -> dict[str, Path]:
    output = Path(output_directory)
    paths = {
        "events": output / "events.json",
        "atom": output / "events.atom.xml",
        "rss": output / "events.rss.xml",
        "jsonFeed": output / "events.feed.json",
    }
    bodies = {
        "events": bundle.event_json,
        "atom": bundle.atom,
        "rss": bundle.rss,
        "jsonFeed": bundle.json_feed,
    }
    for name, path in paths.items():
        _atomic_write(path, bodies[name])
    return paths
