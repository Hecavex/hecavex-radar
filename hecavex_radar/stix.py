from __future__ import annotations

import ipaddress
import json
import os
import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from urllib.parse import urlsplit
from uuid import NAMESPACE_URL, UUID, uuid5

from .provenance import normalize_reason_codes
from .review import valid_admission_source
from .safety import clean_text, parse_and_defang_url, refang, safe_reference_url, stable_id

STIX_CYBER_OBSERVABLE_NAMESPACE = UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
RADAR_STIX_NAMESPACE = uuid5(NAMESPACE_URL, "https://radar.hecavex.com/data/radar.stix.json")
RADAR_REVIEWED_STIX_NAMESPACE = uuid5(NAMESPACE_URL, "https://radar.hecavex.com/data/radar-reviewed.stix.json")
RADAR_IDENTITY_ID = f"identity--{uuid5(NAMESPACE_URL, 'https://radar.hecavex.com/#publisher')}"
TLP_CLEAR_MARKING_ID = "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"
UTC_MILLISECONDS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
SIGNAL_ID = re.compile(r"^[a-f0-9]{20}$")
SIGNAL_STATUSES = frozenset({"active", "suspected", "offline", "mitigated", "unknown"})
ALLOWED_SOURCES = frozenset({"CertStream", "URLScan", "HECAVEX"})
MAXIMUM_STIX_SIGNALS = 25_000
MAXIMUM_STIX_OBJECTS = MAXIMUM_STIX_SIGNALS * 2
MAXIMUM_REVIEWED_STIX_OBJECTS = 1 + (MAXIMUM_STIX_SIGNALS * 2)
MAXIMUM_STIX_BUNDLE_BYTES = 2 * 1024 * 1024
EVIDENCE_TIERS = frozenset({"name-only", "corroborated", "reviewed"})
REVIEW_STATES = frozenset(
    {
        "unreviewed",
        "needs-review",
        "confirmed-suspicious",
        "false-positive",
        "benign-brand-reference",
        "inconclusive",
    }
)
LT_RELEVANCE = frozenset({"lithuanian-targeting", "lithuanian-brand-relevance", "global-brand-reference", "unknown"})


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
    legacy_score = signal.get("confidence")
    score = signal.get("matchScore", legacy_score)
    if isinstance(score, bool) or not isinstance(score, int) or not 0 <= score <= 100:
        raise ValueError("Radar STIX export rejected an invalid matching score.")
    if legacy_score is not None and legacy_score != score:
        raise ValueError("Radar STIX export rejected conflicting legacy and current matching scores.")
    evidence_tier = signal.get("evidenceTier", "name-only")
    review_state = signal.get("reviewState", "unreviewed")
    lt_relevance = signal.get("ltRelevance", "lithuanian-brand-relevance")
    if evidence_tier not in EVIDENCE_TIERS or review_state not in REVIEW_STATES or lt_relevance not in LT_RELEVANCE:
        raise ValueError("Radar STIX export rejected invalid semantic state.")
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
        "x_hecavex_com_evidence_tier": evidence_tier,
        "x_hecavex_com_review_state": review_state,
        "x_hecavex_com_lt_relevance": lt_relevance,
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
    if payload.get("schemaVersion") != 2 or payload.get("dataset") != "live":
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


def _indicator_id(signal_id: str, reviewed_at: str) -> str:
    # Corrections and retractions keep reviewedAt and therefore version the
    # same object. A later fresh confirmation starts a new lifecycle.
    return f"indicator--{uuid5(RADAR_REVIEWED_STIX_NAMESPACE, f'indicator:{signal_id}:{reviewed_at}')}"


def _sighting_id(indicator_id: str) -> str:
    return f"sighting--{uuid5(RADAR_REVIEWED_STIX_NAMESPACE, f'sighting:{indicator_id}')}"


def _radar_identity() -> dict[str, object]:
    return {
        "type": "identity",
        "spec_version": "2.1",
        "id": RADAR_IDENTITY_ID,
        "created": "2026-08-25T00:00:00.000Z",
        "modified": "2026-08-25T00:00:00.000Z",
        "name": "HECAVEX Radar",
        "identity_class": "organization",
    }


def _reviewed_indicator(assessment: dict[str, object]) -> dict[str, object] | None:
    state = assessment.get("reviewState")
    revoked = assessment.get("revoked")
    if state != "confirmed-suspicious" and revoked is not True:
        return None
    signal_id = assessment.get("signalId")
    display_domain = assessment.get("domain")
    brand = assessment.get("brand")
    if (
        not isinstance(signal_id, str)
        or not SIGNAL_ID.fullmatch(signal_id)
        or not isinstance(display_domain, str)
        or signal_id != stable_id(display_domain.lower())
        or not isinstance(brand, str)
        or clean_text(brand, 120) != brand
    ):
        raise ValueError("Reviewed STIX export rejected invalid assessment identity.")
    parsed = parse_and_defang_url(f"https://{refang(display_domain)}")
    if parsed is None or parsed.display_domain != display_domain:
        raise ValueError("Reviewed STIX export rejected a non-canonical domain.")
    domain = urlsplit(parsed.key).hostname
    if domain is None or len(domain.split(".")) < 2:
        raise ValueError("Reviewed STIX export rejected an invalid domain.")
    reviewed_at, reviewed_value = _timestamp(assessment.get("reviewedAt"), "reviewedAt")
    modified_at, modified_value = _timestamp(assessment.get("modifiedAt"), "modifiedAt")
    if reviewed_value > modified_value:
        raise ValueError("Reviewed STIX export rejected an impossible review interval.")
    if not valid_admission_source(
        assessment.get("admissionSource"),
        signal_id=signal_id,
        domain=display_domain,
        brand=brand,
        reviewed_at=reviewed_at,
    ):
        raise ValueError("Reviewed STIX export requires verified public-observation admission provenance.")
    expires_at, expires_value = _timestamp(assessment.get("expiresAt"), "expiresAt")
    if expires_value <= reviewed_value:
        raise ValueError("Reviewed STIX export requires expiry after first confirmation.")
    evidence = assessment.get("evidenceCodes")
    reason = assessment.get("dispositionReason")
    lt_relevance = assessment.get("ltRelevance")
    confidence = assessment.get("analystConfidence")
    if (
        not isinstance(evidence, list)
        or not evidence
        or evidence != sorted(set(evidence))
        or not all(isinstance(item, str) and clean_text(item, 80) == item for item in evidence)
        or not isinstance(reason, str)
        or clean_text(reason, 80) != reason
        or lt_relevance not in LT_RELEVANCE
        or type(revoked) is not bool
        or (confidence is not None and (type(confidence) is not int or not 0 <= confidence <= 100))
    ):
        raise ValueError("Reviewed STIX export rejected invalid assessment metadata.")
    indicator: dict[str, object] = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": _indicator_id(signal_id, reviewed_at),
        "created_by_ref": RADAR_IDENTITY_ID,
        "created": reviewed_at,
        "modified": modified_at,
        "revoked": revoked,
        "name": f"HECAVEX Radar reviewed phishing domain: {domain}",
        "indicator_types": ["malicious-activity"],
        "pattern": f"[domain-name:value = '{domain}']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": reviewed_at,
        "valid_until": expires_at,
        "object_marking_refs": [TLP_CLEAR_MARKING_ID],
        "x_hecavex_com_signal_id": signal_id,
        "x_hecavex_com_brand": brand,
        "x_hecavex_com_review_state": state,
        "x_hecavex_com_disposition_reason": reason,
        "x_hecavex_com_evidence_codes": evidence,
        "x_hecavex_com_lt_relevance": lt_relevance,
    }
    if confidence is not None:
        indicator["confidence"] = confidence
    return indicator


def _observation_index(observation_history: object, generated_at: datetime) -> dict[str, dict[str, object]]:
    raw_signals: object
    if isinstance(observation_history, Mapping):
        raw_signals = observation_history.get("signals")
    else:
        raw_signals = observation_history
    if not isinstance(raw_signals, Sequence) or isinstance(raw_signals, (str, bytes)):
        raise ValueError("Reviewed STIX sightings require a signal sequence or a history object.")
    if len(raw_signals) > MAXIMUM_STIX_SIGNALS:
        raise ValueError("Reviewed STIX sightings exceeded the bounded signal count.")
    indexed: dict[str, dict[str, object]] = {}
    for raw in raw_signals:
        if not isinstance(raw, Mapping):
            raise ValueError("Reviewed STIX sightings rejected a non-object observation summary.")
        signal_id = raw.get("id")
        display_domain = raw.get("domain")
        if (
            not isinstance(signal_id, str)
            or not SIGNAL_ID.fullmatch(signal_id)
            or not isinstance(display_domain, str)
            or signal_id != stable_id(display_domain.lower())
        ):
            raise ValueError("Reviewed STIX sightings rejected an invalid signal identity.")
        parsed = parse_and_defang_url(f"https://{refang(display_domain)}")
        if parsed is None or parsed.display_domain != display_domain:
            raise ValueError("Reviewed STIX sightings rejected a non-canonical domain.")
        first_seen, first_value = _timestamp(raw.get("firstSeen"), "firstSeen")
        last_seen, last_value = _timestamp(raw.get("lastSeen"), "lastSeen")
        if first_value > last_value or last_value > generated_at:
            raise ValueError("Reviewed STIX sightings rejected an impossible observation interval.")
        raw_count = raw.get("observationCount", 1)
        if type(raw_count) is not int or not 1 <= raw_count <= 999_999_999:
            raise ValueError("Reviewed STIX sightings rejected an invalid observation count.")
        existing = indexed.get(signal_id)
        if existing is not None and existing["domain"] != display_domain:
            raise ValueError("Reviewed STIX sightings rejected a conflicting signal identity.")
        if existing is None:
            indexed[signal_id] = {
                "domain": display_domain,
                "firstSeen": first_seen,
                "lastSeen": last_seen,
                "count": raw_count,
            }
            continue
        indexed[signal_id] = {
            "domain": display_domain,
            "firstSeen": min(cast(str, existing["firstSeen"]), first_seen),
            "lastSeen": max(cast(str, existing["lastSeen"]), last_seen),
            "count": max(cast(int, existing["count"]), raw_count),
        }
    return indexed


def _reviewed_sighting(
    indicator: Mapping[str, object],
    observation: Mapping[str, object],
) -> dict[str, object]:
    indicator_id = cast(str, indicator["id"])
    signal_id = cast(str, indicator["x_hecavex_com_signal_id"])
    first_seen = cast(str, observation["firstSeen"])
    last_seen = cast(str, observation["lastSeen"])
    created = cast(str, indicator["created"])
    modified = max(cast(str, indicator["modified"]), last_seen, created)
    return {
        "type": "sighting",
        "spec_version": "2.1",
        "id": _sighting_id(indicator_id),
        "created_by_ref": RADAR_IDENTITY_ID,
        "created": created,
        "modified": modified,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "count": cast(int, observation["count"]),
        "sighting_of_ref": indicator_id,
        "object_marking_refs": [TLP_CLEAR_MARKING_ID],
        "x_hecavex_com_signal_id": signal_id,
        "x_hecavex_com_observation_scope": "public-history-summary",
    }


def build_reviewed_stix_bundle(
    assessments: object,
    generated_at: str,
    observation_history: object | None = None,
) -> dict[str, object]:
    _, generated_value = _timestamp(generated_at, "generatedAt")
    if not isinstance(assessments, (list, tuple)) or len(assessments) > MAXIMUM_STIX_SIGNALS:
        raise ValueError("Reviewed STIX export exceeded its bounded assessment count.")
    indicators: list[dict[str, object]] = []
    seen_ids: set[str] = set()
    for raw in assessments:
        if not isinstance(raw, dict):
            raise ValueError("Reviewed STIX export rejected a non-object assessment.")
        indicator = _reviewed_indicator(cast(dict[str, object], raw))
        if indicator is None:
            continue
        identifier = cast(str, indicator["id"])
        if identifier in seen_ids:
            raise ValueError("Reviewed STIX export rejected a duplicate indicator.")
        seen_ids.add(identifier)
        indicators.append(indicator)
    indicators.sort(key=lambda item: cast(str, item["id"]))
    sightings: list[dict[str, object]] = []
    if observation_history is not None:
        observations = _observation_index(observation_history, generated_value)
        for indicator in indicators:
            signal_id = cast(str, indicator["x_hecavex_com_signal_id"])
            observation = observations.get(signal_id)
            if observation is None:
                continue
            indicator_domain = cast(str, indicator["pattern"])[len("[domain-name:value = '") : -2]
            observed_domain = refang(cast(str, observation["domain"]))
            if indicator_domain != observed_domain:
                raise ValueError("Reviewed STIX sightings rejected an indicator/history domain mismatch.")
            sightings.append(_reviewed_sighting(indicator, observation))
    sightings.sort(key=lambda item: cast(str, item["id"]))
    objects = [_radar_identity(), *indicators, *sightings]
    if len(objects) > MAXIMUM_REVIEWED_STIX_OBJECTS:
        raise ValueError("Reviewed STIX export exceeded its bounded object count.")
    bundle_key = json.dumps(
        {"generated_at": generated_at, "object_ids": [item["id"] for item in objects]},
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return {
        "type": "bundle",
        "id": f"bundle--{uuid5(RADAR_REVIEWED_STIX_NAMESPACE, bundle_key)}",
        "objects": objects,
    }


def write_reviewed_stix_bundle(
    assessments: object,
    generated_at: str,
    output: str | Path,
    observation_history: object | None = None,
) -> Path:
    repository = Path.cwd().resolve()
    public_data = (repository / "public" / "data").resolve()
    target = (repository / output).resolve()
    if target.parent != public_data or target.suffix.lower() != ".json":
        raise ValueError("RADAR_REVIEWED_STIX_OUTPUT must be a JSON file directly under public/data/.")
    bundle = build_reviewed_stix_bundle(assessments, generated_at, observation_history)
    body = json.dumps(bundle, ensure_ascii=False, indent=2) + "\n"
    if len(body.encode("utf-8")) > MAXIMUM_STIX_BUNDLE_BYTES:
        raise RuntimeError("Refusing to publish a reviewed STIX bundle larger than 2 MiB.")
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
