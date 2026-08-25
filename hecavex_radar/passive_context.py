"""Temporal passive context and change journal for published Radar candidates.

Inputs are the existing bounded DNS/RDAP collector state and existing public
URLScan-result metadata.  The only additional network service contacted here
is RIPEstat.  Candidate hosts are never requested.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import tempfile
import time
from collections.abc import Callable, Mapping
from contextlib import suppress
from datetime import UTC, date, datetime, timedelta
from http.client import HTTPMessage
from pathlib import Path
from typing import IO, Any, cast
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .domain_context import DNS_TYPES
from .domain_context import read_state as read_domain_context
from .models import RadarSignal, RawDomainIntelligence
from .safety import (
    clean_text,
    defang_domains_in_text,
    defang_host,
    refang,
    safe_reference_url,
    stable_id,
)
from .urlscan import read_recent_urlscan, read_recent_urlscan_intelligence

RIPE_HOST = "stat.ripe.net"
RIPE_ROOT = f"https://{RIPE_HOST}/data"
DEFAULT_STATE_PATH = "data/enrichment/passive-context.json"
DEFAULT_JOURNAL_ROOT = "data/history/context"
MAXIMUM_RESPONSE_BYTES = 2 * 1024 * 1024
MAXIMUM_STATE_BYTES = 4 * 1024 * 1024
MAXIMUM_BASELINES = 2_500
MAXIMUM_CACHE_ENTRIES = 5_000
MAXIMUM_EVENTS_PER_RUN = 200
MAXIMUM_EVENTS_PER_DAY = 5_000
MAXIMUM_JOURNAL_BYTES = 10 * 1024 * 1024
MAXIMUM_COMPONENT_BYTES = 16 * 1024
MAXIMUM_RUN_SECONDS = 600
DNS_REFERENCE = "https://cloudflare-dns.com/dns-query"
RDAP_REFERENCE = "https://data.iana.org/rdap/dns.json"
URLSCAN_REFERENCE = "https://urlscan.io/"

JsonRequester = Callable[[str, str], Any]


class _SameHostRedirectHandler(HTTPRedirectHandler):
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
            or destination.hostname != RIPE_HOST
            or destination.username is not None
            or destination.password is not None
            or destination.port is not None
        ):
            raise HTTPError(request.full_url, code, "RIPEstat returned an unsafe redirect.", headers, file_pointer)
        return super().redirect_request(request, file_pointer, code, message, headers, destination.geturl())


def _request_json(url: str, expected_host: str) -> Any:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != expected_host
        or expected_host != RIPE_HOST
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
        or parsed.fragment
    ):
        raise ValueError("Passive context request target is not allowlisted.")
    request = Request(  # noqa: S310 - scheme and host are enforced above.
        url,
        headers={"Accept": "application/json", "User-Agent": "hecavex-radar/0.2 (+https://radar.hecavex.com/)"},
        method="GET",
    )
    opener = build_opener(_SameHostRedirectHandler())
    try:
        with opener.open(request, timeout=30) as response:  # noqa: S310 - allowlisted HTTPS request.
            length = response.headers.get("Content-Length")
            if length and length.isdecimal() and int(length) > MAXIMUM_RESPONSE_BYTES:
                raise ValueError("RIPEstat response is too large.")
            body = response.read(MAXIMUM_RESPONSE_BYTES + 1)
    except (HTTPError, URLError, TimeoutError, OSError) as error:
        raise RuntimeError("RIPEstat request failed.") from error
    if len(body) > MAXIMUM_RESPONSE_BYTES:
        raise ValueError("RIPEstat response is too large.")
    try:
        return json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("RIPEstat returned invalid JSON.") from error


def _timestamp(value: datetime) -> str:
    aware = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    return aware.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError:
        return None
    return parsed if _timestamp(parsed) == value else None


def _bounded(value: str | None, fallback: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value) if value else fallback
    except ValueError:
        parsed = fallback
    return min(maximum, max(minimum, parsed))


def _enabled(value: str | None, *, default: bool = False) -> bool:
    if value is None or not value.strip():
        return default
    return value.strip().casefold() in {"1", "true", "yes", "on"}


def _bounded_path(value: str | Path, *, expected: str, directory: bool = False) -> Path:
    repository = Path(os.path.abspath(Path.cwd()))
    if _is_linklike(repository):
        raise ValueError("Passive context refuses a symlinked repository root.")
    raw = Path(value)
    target = Path(os.path.abspath(repository / raw if not raw.is_absolute() else raw))
    allowed = Path(os.path.abspath(repository / expected))
    if target != allowed or (not directory and target.name != Path(expected).name):
        raise ValueError(f"Passive context path must be exactly {expected}.")
    _reject_symlink_components(target, repository)
    return target


def _is_linklike(path: Path) -> bool:
    """Treat Windows junctions as links as well as ordinary symlinks."""

    return path.is_symlink() or path.is_junction()


def _reject_symlink_components(target: Path, repository: Path | None = None) -> None:
    root = repository or Path(os.path.abspath(Path.cwd()))
    candidate = Path(os.path.abspath(target))
    if not candidate.is_relative_to(root):
        raise ValueError("Passive context path escapes the repository.")
    if _is_linklike(root):
        raise ValueError("Passive context refuses a symlinked repository root.")
    current = root
    for part in candidate.relative_to(root).parts:
        current /= part
        if _is_linklike(current):
            raise ValueError(f"Passive context refuses symlinked path component {current.name}.")


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _component(value: object) -> object:
    body = _canonical_json(value)
    if len(body) > MAXIMUM_COMPONENT_BYTES:
        raise ValueError("Passive context component exceeds 16 KiB.")
    return value


def _component_hash(value: object) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _safe_text(value: object, maximum: int = 240) -> str | None:
    text = clean_text(value, maximum)
    return clean_text(defang_domains_in_text(text), maximum) if text else None


def _canonical_ip(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return str(ipaddress.ip_address(refang(value)))
    except ValueError:
        return None


def _asn(value: object) -> int | None:
    if isinstance(value, str):
        candidate = value.upper().removeprefix("AS")
        value = int(candidate) if candidate.isdecimal() else None
    return value if type(value) is int and 0 < value <= 4_294_967_295 else None


def _rpki_context(prefix: str, asn: int, requester: JsonRequester) -> dict[str, object] | None:
    url = f"{RIPE_ROOT}/rpki-validation/data.json?{urlencode({'resource': f'AS{asn}', 'prefix': prefix})}"
    payload = requester(url, RIPE_HOST)
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, dict):
        raise ValueError("RIPEstat RPKI response has an unexpected shape.")
    status = data.get("status")
    if status not in {"valid", "invalid_asn", "invalid_length", "unknown"}:
        return None
    return {"status": status, "checkedAsn": asn, "checkedPrefix": prefix}


def _routing_context(ip: str, requester: JsonRequester, *, include_rpki: bool) -> dict[str, object]:
    url = f"{RIPE_ROOT}/prefix-overview/data.json?{urlencode({'resource': ip})}"
    payload = requester(url, RIPE_HOST)
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, dict):
        raise ValueError("RIPEstat prefix response has an unexpected shape.")
    resource = data.get("resource")
    try:
        prefix = str(ipaddress.ip_network(resource, strict=False)) if isinstance(resource, str) else None
    except ValueError:
        prefix = None
    raw_asns = data.get("asns")
    asns: list[int] = []
    holders: list[str] = []
    if isinstance(raw_asns, list):
        for raw in raw_asns[:16]:
            if isinstance(raw, dict):
                number = _asn(raw.get("asn"))
                holder = _safe_text(raw.get("holder"), 160)
            else:
                number = _asn(raw)
                holder = None
            if number is not None and number not in asns:
                asns.append(number)
            if holder and holder not in holders:
                holders.append(holder)
    announced = data.get("announced") if type(data.get("announced")) is bool else None
    context: dict[str, object] = {
        "ipAddress": defang_host(ip),
        "prefix": prefix.replace(".", "[.]") if prefix else None,
        "announced": announced,
        "asns": asns,
        "holders": holders,
        "rpki": None,
    }
    if include_rpki and prefix and asns:
        context["rpki"] = _rpki_context(prefix, asns[0], requester)
    return context


def _urlscan_snapshot(
    value: RawDomainIntelligence,
    signal: RadarSignal | None = None,
) -> dict[str, object]:
    page = value.page if isinstance(value.page, dict) else {}
    network = value.network if isinstance(value.network, dict) else {}
    assessment = value.assessment if isinstance(value.assessment, dict) else {}
    certificate = value.certificate if isinstance(value.certificate, dict) else {}
    raw_fingerprints = certificate.get("fingerprints")
    fingerprints = raw_fingerprints if isinstance(raw_fingerprints, dict) else {}
    reference = safe_reference_url(signal.get("referenceUrl")) if signal is not None else None
    hashes = signal.get("hashes", []) if signal is not None else []
    primary_hashes = sorted(
        {
            digest.lower()
            for digest in hashes[:8]
            if isinstance(digest, str)
            and len(digest) == 64
            and all(character in "0123456789abcdefABCDEF" for character in digest)
        }
    )[:2]
    certificate_sha256 = fingerprints.get("sha256")
    if not (
        isinstance(certificate_sha256, str)
        and len(certificate_sha256) == 64
        and all(character in "0123456789abcdefABCDEF" for character in certificate_sha256)
    ):
        certificate_sha256 = None
    snapshot = {
        "observedAt": _timestamp(parsed) if (parsed := _parse_timestamp(value.observed_at)) is not None else None,
        "referenceUrl": reference or URLSCAN_REFERENCE,
        "pageTitle": _safe_text(page.get("title"), 300),
        "httpStatus": page.get("httpStatus") if type(page.get("httpStatus")) is int else None,
        "ipAddress": (
            defang_host(ip) if (ip := _canonical_ip(network.get("ipAddress"))) is not None else None
        ),
        "asn": _asn(network.get("asn")),
        "asnDescription": _safe_text(network.get("asnDescription"), 200),
        "redirectedToDomain": _safe_text(assessment.get("redirectedToDomain"), 253),
        "certificateIssuer": _safe_text(certificate.get("issuer"), 240),
        "certificateNotBefore": (
            _timestamp(parsed) if (parsed := _parse_timestamp(certificate.get("notBefore"))) is not None else None
        ),
        "certificateNotAfter": (
            _timestamp(parsed) if (parsed := _parse_timestamp(certificate.get("notAfter"))) is not None else None
        ),
        "primaryHtmlSha256": primary_hashes,
        "certificateFingerprintSha256": certificate_sha256.lower() if certificate_sha256 else None,
    }
    return cast(dict[str, object], _component(snapshot))


def _changed_fields(before: Mapping[str, object], after: Mapping[str, object]) -> list[str]:
    return sorted(key for key in set(before) | set(after) if before.get(key) != after.get(key))


def _resolves(value: Mapping[str, object]) -> bool:
    return any(isinstance(value.get(field), list) and bool(value[field]) for field in ("a", "aaaa", "cname"))


def _dns_values(value: Mapping[str, object], field: str) -> list[object]:
    answers = value.get(field)
    return cast(list[object], answers) if isinstance(answers, list) else []


def _semantic_changes(
    component: str,
    before: Mapping[str, object],
    after: Mapping[str, object],
) -> list[tuple[str, list[str]]]:
    """Return explicit material changes while ignoring collection-time-only drift."""

    changes: list[tuple[str, list[str]]] = []
    if component == "dns":
        resolution_fields = [
            field
            for field in ("a", "aaaa", "cname")
            if _dns_values(before, field) != _dns_values(after, field)
        ]
        before_resolves = _resolves(before)
        after_resolves = _resolves(after)
        if resolution_fields and before_resolves != after_resolves:
            changes.append(("first-resolving" if after_resolves else "stopped-resolving", resolution_fields))
        else:
            for field in resolution_fields:
                changes.append((f"dns-{field}-changed", [field]))
        for field in ("ns", "mx"):
            if _dns_values(before, field) != _dns_values(after, field):
                changes.append((f"dns-{field}-changed", [field]))
    elif component == "rdap":
        for field, change_type in (
            ("registrar", "rdap-registrar-changed"),
            ("statuses", "rdap-status-changed"),
            ("expiresAt", "rdap-expiry-changed"),
        ):
            if before.get(field) != after.get(field):
                changes.append((change_type, [field]))
    elif component == "urlscan":
        for field, change_type in (
            ("pageTitle", "urlscan-title-changed"),
            ("redirectedToDomain", "urlscan-redirect-changed"),
            ("httpStatus", "urlscan-http-status-changed"),
            ("ipAddress", "urlscan-ip-changed"),
            ("asn", "urlscan-asn-changed"),
            ("primaryHtmlSha256", "urlscan-primary-html-sha256-changed"),
            ("certificateFingerprintSha256", "urlscan-certificate-fingerprint-changed"),
        ):
            if before.get(field) != after.get(field):
                changes.append((change_type, [field]))
        certificate_fields = [
            field
            for field in (
                "certificateFingerprintSha256",
                "certificateIssuer",
                "certificateNotBefore",
                "certificateNotAfter",
            )
            if before.get(field) != after.get(field)
        ]
        before_has_certificate = any(before.get(field) is not None for field in certificate_fields)
        after_has_certificate = any(after.get(field) is not None for field in certificate_fields)
        if certificate_fields and before_has_certificate and after_has_certificate:
            changes.append(("certificate-reissued", certificate_fields))
    return changes


def _event(
    signal_id: str,
    domain: str,
    observed_at: str,
    component: str,
    change_type: str,
    changed_fields: list[str],
    source_observed_at: str,
    source_reference: str,
    before: Mapping[str, object],
    after: Mapping[str, object],
) -> dict[str, object]:
    previous_hash = _component_hash(before)
    current_hash = _component_hash(after)
    event_id = _event_id(
        signal_id,
        observed_at,
        component,
        change_type,
        changed_fields,
        previous_hash,
        current_hash,
    )
    return {
        "schemaVersion": 2,
        "dataset": "radar-context-change",
        "eventId": event_id,
        "signalId": signal_id,
        "domain": domain,
        "observedAt": observed_at,
        "sourceObservedAt": source_observed_at,
        "sourceReference": source_reference,
        "component": component,
        "changeType": change_type,
        "changedFields": changed_fields,
        "previousHash": previous_hash,
        "currentHash": current_hash,
        "before": dict(before),
        "after": dict(after),
    }


def _event_id(
    signal_id: str,
    observed_at: str,
    component: str,
    change_type: str,
    changed_fields: list[str],
    previous_hash: str,
    current_hash: str,
) -> str:
    material = (
        f"{signal_id}\n{observed_at}\n{component}\n{change_type}\n"
        f"{','.join(changed_fields)}\n{previous_hash}\n{current_hash}"
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def _valid_event(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "schemaVersion",
        "dataset",
        "eventId",
        "signalId",
        "domain",
        "observedAt",
        "sourceObservedAt",
        "sourceReference",
        "component",
        "changeType",
        "changedFields",
        "previousHash",
        "currentHash",
        "before",
        "after",
    }:
        return False
    signal_id = value["signalId"]
    domain = value["domain"]
    observed_at = value["observedAt"]
    source_observed_at = value["sourceObservedAt"]
    component = value["component"]
    change_type = value["changeType"]
    fields = value["changedFields"]
    before = value["before"]
    after = value["after"]
    if (
        value["schemaVersion"] != 2
        or value["dataset"] != "radar-context-change"
        or not isinstance(signal_id, str)
        or len(signal_id) != 20
        or any(character not in "0123456789abcdef" for character in signal_id)
        or not isinstance(domain, str)
        or stable_id(domain.lower()) != signal_id
        or not isinstance(observed_at, str)
        or (observed := _parse_timestamp(observed_at)) is None
        or not isinstance(source_observed_at, str)
        or (source_observed := _parse_timestamp(source_observed_at)) is None
        or source_observed > observed + timedelta(minutes=5)
        or not isinstance(component, str)
        or not isinstance(change_type, str)
        or not isinstance(fields, list)
        or not fields
        or len(fields) > 32
        or len(fields) != len(set(cast(list[object], fields)))
        or not all(isinstance(field, str) for field in fields)
        or not isinstance(before, dict)
        or not isinstance(after, dict)
        or len(_canonical_json(before)) > MAXIMUM_COMPONENT_BYTES
        or len(_canonical_json(after)) > MAXIMUM_COMPONENT_BYTES
        or (change_type, cast(list[str], fields)) not in _semantic_changes(component, before, after)
    ):
        return False
    reference = value["sourceReference"]
    expected_reference = {"dns": DNS_REFERENCE, "rdap": RDAP_REFERENCE}.get(component)
    if not isinstance(reference, str) or (
        reference != expected_reference
        and not (
            component == "urlscan"
            and (reference == URLSCAN_REFERENCE or safe_reference_url(reference) == reference)
        )
    ):
        return False
    previous_hash = _component_hash(before)
    current_hash = _component_hash(after)
    return bool(
        value["previousHash"] == previous_hash
        and value["currentHash"] == current_hash
        and value["eventId"]
        == _event_id(
            signal_id,
            observed_at,
            component,
            change_type,
            cast(list[str], fields),
            previous_hash,
            current_hash,
        )
    )


def _empty_state(now: datetime) -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "dataset": "passive-context-state",
        "generatedAt": _timestamp(now),
        "cursor": 0,
        "baselines": [],
        "ripeCache": [],
        "latestRun": None,
    }


def _valid_state(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "schemaVersion",
        "dataset",
        "generatedAt",
        "cursor",
        "baselines",
        "ripeCache",
        "latestRun",
    }:
        return False
    baselines = value["baselines"]
    cache = value["ripeCache"]
    latest = value["latestRun"]
    if (
        value["schemaVersion"] != 1
        or value["dataset"] != "passive-context-state"
        or _parse_timestamp(value["generatedAt"]) is None
        or type(value["cursor"]) is not int
        or not 0 <= value["cursor"] <= MAXIMUM_BASELINES
        or not isinstance(baselines, list)
        or len(baselines) > MAXIMUM_BASELINES
        or not isinstance(cache, list)
        or len(cache) > MAXIMUM_CACHE_ENTRIES
    ):
        return False
    for row in baselines:
        if (
            not isinstance(row, dict)
            or set(row) != {"signalId", "domain", "observedAt", "components"}
            or not isinstance(row["signalId"], str)
            or len(row["signalId"]) != 20
            or not isinstance(row["domain"], str)
            or _parse_timestamp(row["observedAt"]) is None
            or not isinstance(row["components"], dict)
            or not set(row["components"]).issubset({"dns", "rdap", "urlscan", "routing"})
            or any(
                len(_canonical_json(component)) > MAXIMUM_COMPONENT_BYTES
                for component in row["components"].values()
            )
        ):
            return False
    for row in cache:
        if (
            not isinstance(row, dict)
            or set(row) != {"ipAddress", "fetchedAt", "expiresAt", "context"}
            or _canonical_ip(row["ipAddress"]) is None
            or _parse_timestamp(row["fetchedAt"]) is None
            or _parse_timestamp(row["expiresAt"]) is None
            or not isinstance(row["context"], dict)
        ):
            return False
    if latest is None:
        return True
    fields = ("signalsConsidered", "routeQueries", "cacheHits", "eventsWritten", "failures")
    return (
        isinstance(latest, dict)
        and set(latest) == {
            "startedAt",
            "endedAt",
            "outcome",
            *fields,
            "rpkiEnabled",
        }
        and _parse_timestamp(latest["startedAt"]) is not None
        and _parse_timestamp(latest["endedAt"]) is not None
        and latest["outcome"] in {"completed", "partial", "failed", "empty"}
        and all(type(latest[field]) is int and 0 <= latest[field] <= 2_000_000_000 for field in fields)
        and type(latest["rpkiEnabled"]) is bool
    )


def read_state(path: str | Path = DEFAULT_STATE_PATH, *, now: datetime | None = None) -> dict[str, Any]:
    target = _bounded_path(path, expected=DEFAULT_STATE_PATH)
    try:
        if target.stat().st_size > MAXIMUM_STATE_BYTES:
            raise ValueError("Passive context state exceeds 4 MiB.")
        value: object = json.loads(target.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return _empty_state(now or datetime.now(UTC))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("Passive context state is unreadable.") from error
    if not _valid_state(value):
        raise ValueError("Passive context state has an invalid contract.")
    return cast(dict[str, Any], value)


def write_state(value: dict[str, Any], path: str | Path = DEFAULT_STATE_PATH) -> Path:
    if not _valid_state(value):
        raise ValueError("Refusing to write invalid passive context state.")
    target = _bounded_path(path, expected=DEFAULT_STATE_PATH)
    body = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if len(body.encode("utf-8")) > MAXIMUM_STATE_BYTES:
        raise ValueError("Refusing to write passive context state larger than 4 MiB.")
    target.parent.mkdir(parents=True, exist_ok=True)
    _reject_symlink_components(target)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=target.parent,
            prefix=f".{target.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(0o600)
        _reject_symlink_components(target)
        os.replace(temporary, target)
    except Exception:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise
    return target


def _journal_path(root: str | Path, day: date) -> Path:
    journal_root = _bounded_path(root, expected=DEFAULT_JOURNAL_ROOT, directory=True)
    target = journal_root / day.isoformat() / "events.ndjson"
    _reject_symlink_components(target)
    return target


def _write_events(events: list[dict[str, object]], root: str | Path, day: date) -> int:
    target = _journal_path(root, day)
    existing: dict[str, dict[str, object]] = {}
    try:
        if target.stat().st_size > MAXIMUM_JOURNAL_BYTES:
            raise ValueError("Passive context journal exceeds 10 MiB.")
        for line_number, line in enumerate(target.read_text(encoding="utf-8").splitlines(), start=1):
            try:
                row: object = json.loads(
                    line,
                    parse_constant=lambda value: (_ for _ in ()).throw(
                        ValueError(f"Non-finite JSON value {value}.")
                    ),
                )
            except (json.JSONDecodeError, ValueError) as error:
                raise ValueError(f"Passive context journal line {line_number} is malformed.") from error
            if not _valid_event(row):
                raise ValueError(f"Passive context journal line {line_number} violates its contract.")
            event_id = cast(str, cast(dict[str, object], row)["eventId"])
            if event_id in existing:
                raise ValueError("Passive context journal contains a duplicate event ID.")
            existing[event_id] = cast(dict[str, object], row)
    except FileNotFoundError:
        pass
    if not events:
        return 0
    original_ids = set(existing)
    for event in events[:MAXIMUM_EVENTS_PER_RUN]:
        if not _valid_event(event):
            raise ValueError("Refusing to write an invalid passive context event.")
        event_id = cast(str, event["eventId"])
        if event_id in existing:
            if existing[event_id] != event:
                raise ValueError("Passive context journal event ID collides with different content.")
            continue
        existing[event_id] = event
    ordered = sorted(
        existing.values(),
        key=lambda row: (cast(str, row.get("observedAt", "")), cast(str, row.get("eventId", ""))),
        reverse=True,
    )[:MAXIMUM_EVENTS_PER_DAY]
    body = "".join(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n" for row in ordered)
    if len(body.encode("utf-8")) > MAXIMUM_JOURNAL_BYTES:
        raise ValueError("Passive context journal exceeds 10 MiB.")
    target.parent.mkdir(parents=True, exist_ok=True)
    _reject_symlink_components(target)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=target.parent,
            prefix=f".{target.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(0o600)
        _reject_symlink_components(target)
        os.replace(temporary, target)
    except Exception:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise
    return sum(event_id not in original_ids for event_id in existing)


def _read_journal_snapshot(target: Path) -> bytes | None:
    _reject_symlink_components(target)
    try:
        if target.stat().st_size > MAXIMUM_JOURNAL_BYTES:
            raise ValueError("Passive context journal exceeds 10 MiB.")
        return target.read_bytes()
    except FileNotFoundError:
        return None


def _restore_journal_snapshot(target: Path, previous: bytes | None) -> None:
    _reject_symlink_components(target)
    if previous is None:
        target.unlink(missing_ok=True)
        with suppress(OSError):
            target.parent.rmdir()
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    _reject_symlink_components(target)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=target.parent,
            prefix=f".{target.name}.rollback.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(previous)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(0o600)
        _reject_symlink_components(target)
        os.replace(temporary, target)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _prune_journal(root: str | Path, *, today: date, retention_days: int) -> None:
    journal_root = _bounded_path(root, expected=DEFAULT_JOURNAL_ROOT, directory=True)
    try:
        directories = list(journal_root.iterdir())
    except FileNotFoundError:
        return
    cutoff = today - timedelta(days=retention_days)
    for directory in directories:
        if _is_linklike(directory):
            raise ValueError("Passive context journal contains a symlinked partition.")
        if not directory.is_dir():
            continue
        try:
            partition = date.fromisoformat(directory.name)
        except ValueError:
            continue
        if partition >= cutoff:
            continue
        event_file = directory / "events.ndjson"
        _reject_symlink_components(event_file)
        try:
            event_file.unlink(missing_ok=True)
        except OSError:
            continue
        try:
            directory.rmdir()
        except OSError:
            # Unknown files are never removed by the bounded journal pruner.
            continue


def refresh(
    requester: JsonRequester = _request_json,
    *,
    now: datetime | None = None,
    state_path: str | Path = DEFAULT_STATE_PATH,
    journal_root: str | Path = DEFAULT_JOURNAL_ROOT,
) -> dict[str, object]:
    started = (now or datetime.now(UTC)).astimezone(UTC)
    deadline = time.monotonic() + _bounded(
        os.environ.get("PASSIVE_CONTEXT_RUN_BUDGET_SECONDS"),
        480,
        30,
        MAXIMUM_RUN_SECONDS,
    )
    per_run = _bounded(os.environ.get("PASSIVE_CONTEXT_PER_RUN"), 20, 1, 100)
    cache_hours = _bounded(os.environ.get("PASSIVE_CONTEXT_CACHE_HOURS"), 24, 1, 168)
    lookback = _bounded(os.environ.get("PASSIVE_CONTEXT_URLSCAN_DAYS"), 14, 1, 90)
    retention_days = _bounded(os.environ.get("PASSIVE_CONTEXT_JOURNAL_DAYS"), 60, 30, 90)
    allow_urlscan_redistribution = _enabled(
        os.environ.get("URLSCAN_DERIVED_REDISTRIBUTION_CONFIRMED"),
        default=False,
    )
    include_rpki = _enabled(os.environ.get("PASSIVE_CONTEXT_RPKI_ENABLED"), default=False)
    state = read_state(state_path, now=started)
    domain_state = read_domain_context(now=started)
    raw_records = cast(list[dict[str, Any]], domain_state["records"])
    baseline_index = {
        cast(str, row["signalId"]): cast(dict[str, Any], row)
        for row in cast(list[dict[str, object]], state["baselines"])
    }
    intelligence = (
        read_recent_urlscan_intelligence("data/urlscan", lookback, started, maximum=MAXIMUM_BASELINES)
        if allow_urlscan_redistribution
        else []
    )
    urlscan_by_domain = {item.domain: item for item in intelligence}
    urlscan_signals = (
        read_recent_urlscan("data/urlscan", lookback, started, maximum=MAXIMUM_BASELINES)
        if allow_urlscan_redistribution
        else []
    )
    urlscan_signal_by_domain = {
        refang(signal["domain"]): signal
        for signal in sorted(urlscan_signals, key=lambda item: item["lastSeen"])
    }
    cache_index = {
        cast(str, row["ipAddress"]): cast(dict[str, Any], row)
        for row in cast(list[dict[str, object]], state["ripeCache"])
        if (expires := _parse_timestamp(row.get("expiresAt"))) is not None and expires > started
    }
    if raw_records:
        cursor = cast(int, state["cursor"]) % len(raw_records)
        selected = [
            raw_records[(cursor + offset) % len(raw_records)]
            for offset in range(min(per_run, len(raw_records)))
        ]
        state["cursor"] = (cursor + len(selected)) % len(raw_records)
    else:
        selected = []
        state["cursor"] = 0
    live_ids = {cast(str, row["signalId"]) for row in raw_records}
    baseline_index = {key: row for key, row in baseline_index.items() if key in live_ids}
    if not allow_urlscan_redistribution:
        for row in baseline_index.values():
            components = row.get("components")
            if isinstance(components, dict):
                components.pop("urlscan", None)
    events: list[dict[str, object]] = []
    route_queries = 0
    cache_hits = 0
    failures = 0
    for record in selected:
        if time.monotonic() >= deadline:
            failures += 1
            break
        signal_id = cast(str, record["signalId"])
        domain = cast(str, record["domain"])
        previous = baseline_index.get(signal_id)
        components = dict(cast(dict[str, object], previous.get("components", {}))) if previous else {}
        updates: dict[str, dict[str, object]] = {}
        dns = record.get("dns")
        if isinstance(dns, dict) and dns.get("queriesCompleted") == len(DNS_TYPES):
            updates["dns"] = cast(
                dict[str, object],
                _component({**dict(dns), "observedAt": record["observedAt"]}),
            )
        registration = record.get("registration")
        if isinstance(registration, dict):
            updates["rdap"] = cast(
                dict[str, object],
                _component({**dict(registration), "observedAt": record["observedAt"]}),
            )
        raw_domain = refang(domain)
        urlscan = urlscan_by_domain.get(raw_domain) if allow_urlscan_redistribution else None
        if urlscan is not None:
            updates["urlscan"] = _urlscan_snapshot(urlscan, urlscan_signal_by_domain.get(raw_domain))

        candidate_ips: list[str] = []
        if isinstance(dns, dict):
            for field in ("a", "aaaa"):
                values = dns.get(field)
                if isinstance(values, list):
                    candidate_ips.extend(ip for raw in values if (ip := _canonical_ip(raw)) is not None)
        if (
            urlscan is not None
            and isinstance(urlscan.network, dict)
            and (ip := _canonical_ip(urlscan.network.get("ipAddress"))) is not None
        ):
            candidate_ips.append(ip)
        ip = next(iter(dict.fromkeys(candidate_ips)), None)
        if ip is not None:
            cache_key = defang_host(ip)
            cached = cache_index.get(cache_key)
            if cached is not None:
                cache_hits += 1
                updates["routing"] = cast(dict[str, object], cached["context"])
            else:
                try:
                    routing = _routing_context(ip, requester, include_rpki=include_rpki)
                    route_queries += 1
                    updates["routing"] = routing
                    cache_index[cache_key] = {
                        "ipAddress": cache_key,
                        "fetchedAt": _timestamp(started),
                        "expiresAt": _timestamp(started + timedelta(hours=cache_hours)),
                        "context": routing,
                    }
                except Exception:
                    failures += 1
        for name, after in updates.items():
            raw_before = components.get(name)
            if isinstance(raw_before, dict):
                if raw_before == after:
                    continue
                before: Mapping[str, object] = raw_before
                semantic_changes = _semantic_changes(name, before, after)
            elif name == "dns" and _resolves(after):
                # The first complete DNS baseline is itself a lifecycle
                # observation when the candidate already resolves. A first
                # non-resolving baseline remains silent.
                before = {}
                resolving_fields = [
                    field
                    for field in ("a", "aaaa", "cname")
                    if isinstance(after.get(field), list) and bool(after[field])
                ]
                semantic_changes = [("first-resolving", resolving_fields)]
            else:
                continue
            source_observed_at = after.get("observedAt")
            if not isinstance(source_observed_at, str) or _parse_timestamp(source_observed_at) is None:
                source_observed_at = _timestamp(started)
            source_reference = {
                "dns": DNS_REFERENCE,
                "rdap": RDAP_REFERENCE,
                "urlscan": after.get("referenceUrl", URLSCAN_REFERENCE),
            }.get(name)
            if not isinstance(source_reference, str):
                continue
            for change_type, fields in semantic_changes:
                if len(events) >= MAXIMUM_EVENTS_PER_RUN:
                    break
                events.append(
                    _event(
                        signal_id,
                        domain,
                        _timestamp(started),
                        name,
                        change_type,
                        fields,
                        source_observed_at,
                        source_reference,
                        before,
                        after,
                    )
                )
        components.update(updates)
        baseline_index[signal_id] = {
            "signalId": signal_id,
            "domain": domain,
            "observedAt": _timestamp(started),
            "components": components,
        }
    ended = datetime.now(UTC) if now is None else started
    if not selected:
        outcome = "empty"
    elif failures and len(selected) <= failures:
        outcome = "failed"
    elif failures:
        outcome = "partial"
    else:
        outcome = "completed"
    journal_target = _journal_path(journal_root, started.date())
    previous_journal = _read_journal_snapshot(journal_target)
    journal_mutated = bool(events)
    try:
        events_written = _write_events(events, journal_root, started.date())
        latest = {
            "startedAt": _timestamp(started),
            "endedAt": _timestamp(ended),
            "outcome": outcome,
            "signalsConsidered": len(selected),
            "routeQueries": route_queries,
            "cacheHits": cache_hits,
            "eventsWritten": events_written,
            "failures": failures,
            "rpkiEnabled": include_rpki,
        }
        state.update(
            {
                "generatedAt": _timestamp(ended),
                "baselines": sorted(baseline_index.values(), key=lambda row: (row["domain"], row["signalId"]))[
                    :MAXIMUM_BASELINES
                ],
                "ripeCache": sorted(cache_index.values(), key=lambda row: row["expiresAt"], reverse=True)[
                    :MAXIMUM_CACHE_ENTRIES
                ],
                "latestRun": latest,
            }
        )
        write_state(state, state_path)
    except Exception:
        if journal_mutated:
            _restore_journal_snapshot(journal_target, previous_journal)
        raise
    _prune_journal(journal_root, today=started.date(), retention_days=retention_days)
    print(
        f"Passive context {outcome}: {len(selected)} signals, {route_queries} RIPEstat queries, "
        f"{events_written} change events.",
        flush=True,
    )
    return latest


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Refresh bounded temporal passive context for Radar candidates.")
    parser.add_argument("--state", default=os.environ.get("PASSIVE_CONTEXT_STATE", DEFAULT_STATE_PATH))
    parser.add_argument("--journal", default=os.environ.get("PASSIVE_CONTEXT_JOURNAL", DEFAULT_JOURNAL_ROOT))
    return parser


def main(arguments: list[str] | None = None) -> int:
    options = _parser().parse_args(arguments)
    try:
        result = refresh(state_path=options.state, journal_root=options.journal)
    except Exception as error:
        print(f"Passive context failed before safe publication: {type(error).__name__}", flush=True)
        return 1
    return 0 if result["outcome"] in {"completed", "partial", "empty"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
