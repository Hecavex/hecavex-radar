from __future__ import annotations

import ipaddress
import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from urllib.parse import urlsplit
from uuid import NAMESPACE_URL, UUID, uuid5

from .provenance import normalize_reason_codes
from .safety import clean_text, parse_and_defang_url, refang, safe_reference_url, stable_id

STIX_CYBER_OBSERVABLE_NAMESPACE = UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
RADAR_STIX_NAMESPACE = uuid5(NAMESPACE_URL, "https://radar.hecavex.com/data/radar.stix.json")
UTC_MILLISECONDS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
SIGNAL_ID = re.compile(r"^[a-f0-9]{20}$")
SIGNAL_STATUSES = frozenset({"active", "suspected", "offline", "mitigated", "unknown"})
ALLOWED_SOURCES = frozenset({"CertStream", "URLScan", "HECAVEX"})
MAXIMUM_STIX_SIGNALS = 25_000
MAXIMUM_STIX_OBJECTS = MAXIMUM_STIX_SIGNALS * 2
MAXIMUM_STIX_BUNDLE_BYTES = 2 * 1024 * 1024


def _timestamp(value: object, field: str) -> tuple[str, datetime]:
    if not isinstance(value, str) or not UTC_MILLISECONDS.fullmatch(value):
        raise ValueError(f"Radar STIX export requires a canonical {field} timestamp.")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise ValueError(f"Radar STIX export received an invalid {field} timestamp.") from error
    canonical = parsed.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    if canonical != value:
        raise ValueError(f"Radar STIX export requires {field} to be normalized to UTC.")
    return value, parsed


def _domain_value(signal: dict[str, object]) -> str:
    raw_domain = signal.get("domain")
    raw_url = signal.get("url")
    if not isinstance(raw_domain, str) or not isinstance(raw_url, str):
        raise ValueError("Radar STIX export requires a domain and a defanged URL for every signal.")
    parsed_domain = parse_and_defang_url(f"https://{refang(raw_domain)}")
    parsed_url = parse_and_defang_url(refang(raw_url))
    if (
        parsed_domain is None
        or parsed_url is None
        or parsed_domain.display_domain != raw_domain
        or parsed_url.display_domain != raw_domain
    ):
        raise ValueError("Radar STIX export rejected a non-canonical or mismatched domain.")
    hostname = urlsplit(parsed_domain.key).hostname
    if hostname is None or hostname != hostname.lower() or len(hostname) > 253:
        raise ValueError("Radar STIX export rejected an invalid DNS name.")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise ValueError("Radar STIX export publishes domain-name observables only, not IP addresses.")
    labels = hostname.split(".")
    if len(labels) < 2 or any(not DNS_LABEL.fullmatch(label) for label in labels):
        raise ValueError("Radar STIX export rejected an invalid DNS name.")
    return hostname


def _domain_id(domain: str) -> str:
    # STIX 2.1 SCO identifiers use the OASIS namespace and the canonical JSON
    # form of their ID-contributing properties. Domain Name contributes value.
    canonical_properties = json.dumps(
        {"value": domain},
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return f"domain-name--{uuid5(STIX_CYBER_OBSERVABLE_NAMESPACE, canonical_properties)}"


def _observed_data_id(signal_id: str, first_seen: str) -> str:
    return f"observed-data--{uuid5(RADAR_STIX_NAMESPACE, f'observed-data:{signal_id}:{first_seen}')}"


def _clean_sources(value: object) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= 10:
        raise ValueError("Radar STIX export requires between one and ten sources per signal.")
    raw_sources = cast(list[object], value)
    sources: list[str] = []
    for raw_source in raw_sources:
        cleaned = clean_text(raw_source, 80)
        if cleaned is None or cleaned != raw_source or cleaned not in ALLOWED_SOURCES:
            raise ValueError("Radar STIX export rejected an invalid source name.")
        sources.append(cleaned)
    if len(set(sources)) != len(sources):
        raise ValueError("Radar STIX export rejected duplicate source names.")
    return sorted(sources)


def _external_references(signal: dict[str, object], sources: list[str]) -> list[dict[str, str]]:
    reference_url = signal.get("referenceUrl")
    safe_url = safe_reference_url(reference_url) if reference_url is not None else None
    if reference_url is not None and safe_url != reference_url:
        raise ValueError("Radar STIX export rejected an unsafe external reference.")
    if "URLScan" not in sources or safe_url is None:
        return []
    return [{"source_name": "URLScan", "url": safe_url}]


def _observed_data(
    signal: dict[str, object],
    *,
    domain: str,
    domain_id: str,
    generated_at: str,
    generated_at_value: datetime,
) -> dict[str, object]:
    signal_id = signal.get("id")
    display_domain = signal.get("domain")
    if (
        not isinstance(signal_id, str)
        or not SIGNAL_ID.fullmatch(signal_id)
        or not isinstance(display_domain, str)
        or signal_id != stable_id(display_domain.lower())
    ):
        raise ValueError("Radar STIX export rejected an invalid signal identifier.")
    first_seen, first_seen_value = _timestamp(signal.get("firstSeen"), "firstSeen")
    last_seen, last_seen_value = _timestamp(signal.get("lastSeen"), "lastSeen")
    if first_seen_value > last_seen_value or last_seen_value > generated_at_value:
        raise ValueError("Radar STIX export rejected an impossible observation interval.")

    sources = _clean_sources(signal.get("sources"))
    status = signal.get("status")
    if not isinstance(status, str) or status not in SIGNAL_STATUSES:
        raise ValueError("Radar STIX export rejected an invalid status.")
    score = signal.get("confidence")
    if isinstance(score, bool) or not isinstance(score, int) or not 0 <= score <= 100:
        raise ValueError("Radar STIX export rejected an invalid matching score.")
    brand = signal.get("brand")
    if brand is not None and (not isinstance(brand, str) or clean_text(brand, 120) != brand):
        raise ValueError("Radar STIX export rejected an invalid brand name.")

    observed: dict[str, object] = {
        "type": "observed-data",
        "spec_version": "2.1",
        # Including Radar's first-seen time keeps created stable for normal
        # updates while giving a corrected backfilled interval a new STIX ID.
        "id": _observed_data_id(signal_id, first_seen),
        "created": first_seen,
        "modified": generated_at,
        # This SDO models one latest observation. Radar's merged interval is
        # retained separately below rather than overstating an event count.
        "first_observed": last_seen,
        "last_observed": last_seen,
        "number_observed": 1,
        "object_refs": [domain_id],
        "x_hecavex_com_signal_id": signal_id,
        "x_hecavex_com_sources": sources,
        "x_hecavex_com_status": status,
        # Radar confidence is a matching/ranking score, not STIX confidence,
        # probability, attribution, or a maliciousness verdict.
        "x_hecavex_com_matching_score": score,
        "x_hecavex_com_observation_only": True,
        "x_hecavex_com_radar_first_seen": first_seen,
        "x_hecavex_com_radar_last_seen": last_seen,
    }
    external_references = _external_references(signal, sources)
    if external_references:
        observed["external_references"] = external_references
    if brand is not None:
        observed["x_hecavex_com_brand"] = brand
    reason_codes = signal.get("reasonCodes")
    if reason_codes is not None:
        if not isinstance(reason_codes, list) or len(reason_codes) > 16:
            raise ValueError("Radar STIX export rejected invalid reason codes.")
        reasons = normalize_reason_codes(cast(list[object], reason_codes))
        if reasons != reason_codes:
            raise ValueError("Radar STIX export rejected non-canonical reason codes.")
        if reasons:
            observed["x_hecavex_com_reason_codes"] = reasons

    # Keep the refanged observable only in the standard Domain Name SCO. The
    # export intentionally omits URL paths, screenshots, host strings, and any
    # other field that could carry credentials or unsafe unstructured content.
    if domain != refang(display_domain):
        raise ValueError("Radar STIX export rejected a domain normalization mismatch.")
    return observed


def build_stix_bundle(snapshot: object) -> dict[str, object]:
    if not isinstance(snapshot, dict):
        raise ValueError("Radar STIX export requires a snapshot object.")
    payload = cast(dict[str, object], snapshot)
    if payload.get("schemaVersion") != 1 or payload.get("dataset") != "live":
        raise ValueError("Radar STIX export supports only the validated live snapshot schema.")
    generated_at, generated_at_value = _timestamp(payload.get("generatedAt"), "generatedAt")
    raw_signals = payload.get("signals")
    if not isinstance(raw_signals, list) or len(raw_signals) > MAXIMUM_STIX_SIGNALS:
        raise ValueError("Radar STIX export exceeded its bounded signal count.")

    objects: list[dict[str, object]] = []
    object_ids: list[str] = []
    seen_domains: set[str] = set()
    seen_signal_ids: set[str] = set()
    normalized_signals: list[tuple[str, dict[str, object]]] = []
    for raw_signal in cast(list[object], raw_signals):
        if not isinstance(raw_signal, dict):
            raise ValueError("Radar STIX export rejected a non-object signal.")
        signal = cast(dict[str, object], raw_signal)
        domain = _domain_value(signal)
        signal_id = signal.get("id")
        if domain in seen_domains or not isinstance(signal_id, str) or signal_id in seen_signal_ids:
            raise ValueError("Radar STIX export rejected a duplicate domain or signal identifier.")
        seen_domains.add(domain)
        seen_signal_ids.add(signal_id)
        normalized_signals.append((domain, signal))

    for domain, signal in sorted(normalized_signals, key=lambda item: (item[0], str(item[1].get("id", "")))):
        domain_id = _domain_id(domain)
        observed = _observed_data(
            signal,
            domain=domain,
            domain_id=domain_id,
            generated_at=generated_at,
            generated_at_value=generated_at_value,
        )
        domain_object: dict[str, object] = {
            "type": "domain-name",
            "spec_version": "2.1",
            "id": domain_id,
            "value": domain,
        }
        objects.extend((domain_object, observed))
        object_ids.extend((domain_id, cast(str, observed["id"])))

    if len(objects) > MAXIMUM_STIX_OBJECTS:
        raise ValueError("Radar STIX export exceeded its bounded object count.")
    bundle_key = json.dumps(
        {"generated_at": generated_at, "object_ids": object_ids},
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return {
        "type": "bundle",
        "id": f"bundle--{uuid5(RADAR_STIX_NAMESPACE, bundle_key)}",
        "objects": objects,
    }


def write_stix_bundle(snapshot: object, output: str | Path) -> Path:
    repository = Path.cwd().resolve()
    public_data = (repository / "public" / "data").resolve()
    target = (repository / output).resolve()
    if target.parent != public_data or target.suffix.lower() != ".json":
        raise ValueError("RADAR_STIX_OUTPUT must be a JSON file directly under public/data/.")
    bundle = build_stix_bundle(snapshot)
    body = json.dumps(bundle, ensure_ascii=False, indent=2) + "\n"
    if len(body.encode("utf-8")) > MAXIMUM_STIX_BUNDLE_BYTES:
        raise RuntimeError("Refusing to publish a STIX bundle larger than 2 MiB.")

    temporary = target.with_name(f"{target.name}.tmp")
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        temporary.write_text(body, encoding="utf-8", newline="\n")
        temporary.chmod(0o600)
        os.replace(temporary, target)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return target
