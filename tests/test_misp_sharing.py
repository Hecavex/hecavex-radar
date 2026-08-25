from __future__ import annotations

import hashlib
import json
from typing import cast
from uuid import UUID

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

from hecavex_radar.brands import BrandEntry, BrandRegistry
from hecavex_radar.public_schemas import MISP_EVENT_SCHEMA, MISP_MANIFEST_SCHEMA, MISP_WARNINGLIST_SCHEMA
from hecavex_radar.safety import stable_id
from hecavex_radar.sharing import (
    MISP_EVENT_UUID,
    MISP_ORGANISATION_UUID,
    build_misp_feed,
    build_official_domain_warninglist,
)

GENERATED_AT = "2026-08-26T12:00:00.000Z"
DOMAIN = "vinted-login[.]example"


def assessment(**updates: object) -> dict[str, object]:
    value: dict[str, object] = {
        "signalId": stable_id(DOMAIN),
        "domain": DOMAIN,
        "brand": "Vinted",
        "reviewState": "confirmed-suspicious",
        "reviewedAt": "2026-08-26T10:00:00.000Z",
        "modifiedAt": "2026-08-26T10:05:00.000Z",
        "expiresAt": "2026-09-26T10:00:00.000Z",
        "evidenceCodes": ["certificate-transparency", "urlscan-page"],
        "analystConfidence": 88,
        "revoked": False,
    }
    value.update(updates)
    return value


def registry() -> BrandRegistry:
    return BrandRegistry(
        scope="test",
        reviewed_at="2026-08-26",
        entries=[
            BrandEntry(
                brand="Vinted",
                last_reviewed_at="2026-08-26",
                aliases=["vinted"],
                fuzzy_aliases=["vinted"],
                excluded_terms=[],
                excluded_domains=[],
                category="marketplace",
                official_domains=["vinted.lt", "vinted.com", "vinted.lt"],
                sources=["https://www.vinted.lt/"],
            )
        ],
    )


def test_empty_review_set_is_an_unindexed_unpublished_event() -> None:
    manifest, event = build_misp_feed([], GENERATED_AT)

    assert manifest == {}
    assert event["Event"]["published"] is False  # type: ignore[index]
    assert event["Event"]["Attribute"] == []  # type: ignore[index]
    Draft202012Validator(MISP_MANIFEST_SCHEMA).validate(manifest)
    Draft202012Validator(MISP_EVENT_SCHEMA).validate(event)


def test_reviewed_feed_matches_static_manifest_and_event_contract() -> None:
    manifest, event = build_misp_feed([assessment()], GENERATED_AT)
    event_row = cast(dict[str, object], event["Event"])
    entry = cast(dict[str, object], manifest[MISP_EVENT_UUID])

    assert UUID(MISP_EVENT_UUID).version == 5
    assert UUID(MISP_ORGANISATION_UUID).version == 5
    assert event_row["Orgc"] == {"name": "HECAVEX", "uuid": MISP_ORGANISATION_UUID}
    assert entry["Orgc"] == event_row["Orgc"]
    assert "name" not in entry
    assert "uuid" not in entry
    assert event_row["published"] is True
    attributes = cast(list[dict[str, object]], event_row["Attribute"])
    assert all(attribute["to_ids"] is False for attribute in attributes)

    serialized = (json.dumps(event, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    assert entry["integrity:sha256"] == hashlib.sha256(serialized).hexdigest()
    Draft202012Validator(MISP_MANIFEST_SCHEMA).validate(manifest)
    Draft202012Validator(MISP_EVENT_SCHEMA).validate(event)


def test_reviewed_feed_does_not_churn_while_assessments_are_unchanged() -> None:
    first = build_misp_feed([assessment()], "2026-08-26T12:00:00.000Z")
    later = build_misp_feed([assessment()], "2026-08-27T12:00:00.000Z")

    assert first == later


def test_expired_and_revoked_reviews_are_deletion_tombstones() -> None:
    expired = assessment(expiresAt="2026-08-26T11:59:59.000Z")
    revoked = assessment(revoked=True)

    for candidate in (expired, revoked):
        manifest, event = build_misp_feed([candidate], GENERATED_AT)
        assert MISP_EVENT_UUID in manifest
        attributes = event["Event"]["Attribute"]  # type: ignore[index]
        assert len(attributes) == 1
        assert attributes[0]["deleted"] is True
        assert attributes[0]["to_ids"] is False


def test_expiry_tombstone_advances_feed_once_then_remains_deterministic() -> None:
    candidate = assessment(expiresAt="2026-08-26T12:30:00.000Z")

    before_manifest, before_event = build_misp_feed([candidate], "2026-08-26T12:00:00.000Z")
    after_manifest, after_event = build_misp_feed([candidate], "2026-08-26T13:00:00.000Z")
    later_manifest, later_event = build_misp_feed([candidate], "2026-08-27T13:00:00.000Z")

    before_row = cast(dict[str, object], before_manifest[MISP_EVENT_UUID])
    after_row = cast(dict[str, object], after_manifest[MISP_EVENT_UUID])
    before_attributes = cast(list[dict[str, object]], before_event["Event"]["Attribute"])  # type: ignore[index]
    after_attributes = cast(list[dict[str, object]], after_event["Event"]["Attribute"])  # type: ignore[index]

    assert "deleted" not in before_attributes[0]
    assert after_attributes[0]["deleted"] is True
    assert int(cast(str, after_row["timestamp"])) > int(cast(str, before_row["timestamp"]))
    assert after_manifest == later_manifest
    assert after_event == later_event


def test_official_domain_warninglist_is_sorted_unique_and_hostname_scoped() -> None:
    warninglist = build_official_domain_warninglist(registry())

    assert warninglist["type"] == "hostname"
    assert warninglist["list"] == ["vinted.com", "vinted.lt"]
    assert warninglist["matching_attributes"] == ["domain", "hostname", "url", "domain|ip"]
    Draft202012Validator(MISP_WARNINGLIST_SCHEMA).validate(warninglist)
