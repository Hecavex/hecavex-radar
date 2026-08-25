"""Reviewed-only MISP sharing and official-domain warning-list outputs."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import cast
from urllib.parse import urlsplit
from uuid import UUID, uuid5

from .brands import BrandRegistry, normalize_domain
from .safety import parse_and_defang_url, refang, stable_id

MISP_NAMESPACE = UUID("f2dd344d-2e73-5f17-9bd0-9db06d2f1390")
MISP_EVENT_UUID = str(uuid5(MISP_NAMESPACE, "hecavex-radar-reviewed-domain-feed"))
MISP_ORGANISATION_UUID = str(uuid5(MISP_NAMESPACE, "hecavex-organisation"))
MAXIMUM_MISP_ATTRIBUTES = 2_500
EMPTY_EVENT_TIMESTAMP = datetime(2026, 8, 26, tzinfo=UTC)


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


def _reviewed_attributes(assessments: object, generated_at: str) -> list[dict[str, object]]:
    generated = _parse_timestamp(generated_at)
    if generated is None:
        raise ValueError("MISP sharing requires a canonical generatedAt timestamp.")
    if not isinstance(assessments, list) or len(assessments) > MAXIMUM_MISP_ATTRIBUTES:
        raise ValueError("MISP sharing exceeded the bounded assessment count.")
    attributes: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    for raw in assessments:
        if not isinstance(raw, dict):
            raise ValueError("MISP sharing rejected a non-object assessment.")
        review_state = raw.get("reviewState")
        revoked = raw.get("revoked")
        if review_state != "confirmed-suspicious" and revoked is not True:
            continue
        expires_at = _parse_timestamp(raw.get("expiresAt"))
        reviewed_at = _parse_timestamp(raw.get("reviewedAt"))
        modified_at = _parse_timestamp(raw.get("modifiedAt"))
        display_domain = raw.get("domain")
        signal_id = raw.get("signalId")
        brand = raw.get("brand")
        evidence = raw.get("evidenceCodes")
        confidence = raw.get("analystConfidence")
        if expires_at is None or type(revoked) is not bool:
            raise ValueError("MISP sharing rejected invalid confirmed-review metadata.")
        deleted = revoked or expires_at <= generated
        if (
            reviewed_at is None
            or modified_at is None
            or reviewed_at > modified_at
            or not isinstance(display_domain, str)
            or not isinstance(signal_id, str)
            or signal_id != stable_id(display_domain.lower())
            or not isinstance(brand, str)
            or not isinstance(evidence, list)
            or not evidence
            or evidence != sorted(set(evidence))
            or not all(isinstance(item, str) and 1 <= len(item) <= 80 for item in evidence)
            or (confidence is not None and (type(confidence) is not int or not 0 <= confidence <= 100))
        ):
            raise ValueError("MISP sharing rejected invalid confirmed-review metadata.")
        transition_at = max(modified_at, expires_at) if deleted and not revoked else modified_at
        parsed = parse_and_defang_url(f"https://{refang(display_domain)}")
        domain = (
            urlsplit(parsed.key).hostname
            if parsed is not None and parsed.display_domain == display_domain
            else None
        )
        if domain is None or normalize_domain(domain) != domain:
            raise ValueError("MISP sharing rejected a non-canonical reviewed domain.")
        identity = (signal_id, cast(str, raw["reviewedAt"]))
        if identity in seen:
            raise ValueError("MISP sharing rejected a duplicate reviewed lifecycle.")
        seen.add(identity)
        attribute: dict[str, object] = {
            "uuid": str(uuid5(MISP_NAMESPACE, f"attribute:{identity[0]}:{identity[1]}")),
            "type": "domain",
            "category": "Network activity",
            # Confirmation authorizes public sharing, not automatic blocking or
            # detection use in a downstream MISP instance.
            "to_ids": False,
            "distribution": "3",
            "value": domain,
            "comment": (
                f"HECAVEX Radar reviewed {brand} impersonation lifecycle; "
                f"review expires {raw['expiresAt']}. Signal {signal_id}."
            ),
            "timestamp": str(int(transition_at.timestamp())),
            "Tag": [
                {"name": "tlp:clear"},
                {
                    "name": (
                        "hecavex:review-state=retracted"
                        if revoked
                        else "hecavex:review-state=expired"
                        if deleted
                        else "hecavex:review-state=confirmed-suspicious"
                    )
                },
                {"name": "hecavex:scope=lithuania"},
            ],
        }
        if confidence is not None:
            attribute["comment"] = f"{attribute['comment']} Analyst confidence {confidence}/100."
        if deleted:
            attribute["deleted"] = True
            attribute["comment"] = f"{attribute['comment']} This is a deletion tombstone, not an active indicator."
        attributes.append(attribute)
    return sorted(attributes, key=lambda row: (cast(str, row["value"]), cast(str, row["uuid"])))


def build_misp_feed(assessments: object, generated_at: str) -> tuple[dict[str, object], dict[str, object]]:
    generated = _parse_timestamp(generated_at)
    if generated is None:
        raise ValueError("MISP sharing requires a canonical generatedAt timestamp.")
    attributes = _reviewed_attributes(assessments, generated_at)
    lifecycle = (
        datetime.fromtimestamp(max(int(cast(str, attribute["timestamp"])) for attribute in attributes), tz=UTC)
        if attributes
        else EMPTY_EVENT_TIMESTAMP
    )
    event: dict[str, object] = {
        "Event": {
            "uuid": MISP_EVENT_UUID,
            "info": "HECAVEX Radar analyst-reviewed phishing domains",
            "date": lifecycle.date().isoformat(),
            "timestamp": str(int(lifecycle.timestamp())),
            "analysis": "2",
            "threat_level_id": "2",
            "published": bool(attributes),
            "distribution": "3",
            "Orgc": {"name": "HECAVEX", "uuid": MISP_ORGANISATION_UUID},
            "Tag": [
                {"name": "tlp:clear"},
                {"name": "hecavex:feed=reviewed-only"},
            ],
            "Attribute": attributes,
        }
    }
    # MISP discovers feed events exclusively through manifest.json. Keeping the
    # manifest empty until at least one active review exists prevents an empty
    # placeholder event from being offered to downstream instances.
    manifest: dict[str, object] = {}
    if attributes:
        event_bytes = (json.dumps(event, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        manifest[MISP_EVENT_UUID] = {
            "Orgc": {"name": "HECAVEX", "uuid": MISP_ORGANISATION_UUID},
            "date": lifecycle.date().isoformat(),
            "info": "HECAVEX Radar analyst-reviewed phishing domains",
            "analysis": "2",
            "threat_level_id": "2",
            "timestamp": str(int(lifecycle.timestamp())),
            "integrity:sha256": hashlib.sha256(event_bytes).hexdigest(),
        }
    return manifest, event


def build_official_domain_warninglist(registry: BrandRegistry) -> dict[str, object]:
    domains = sorted(
        {
            domain
            for entry in registry.entries
            for raw in entry.official_domains
            if (domain := normalize_domain(raw)) is not None
        }
    )
    if not domains:
        raise ValueError("Official-domain warning list cannot be empty.")
    version = int(registry.reviewed_at.replace("-", ""))
    return {
        "name": "HECAVEX reviewed official domains for Lithuania-facing brands",
        "version": version,
        "description": (
            "Reviewed first-party domains used to suppress official infrastructure during Radar triage. "
            "A match is an allow-list warning, not proof that surrounding content is benign."
        ),
        "type": "hostname",
        "matching_attributes": ["domain", "hostname", "url", "domain|ip"],
        "list": domains,
    }
