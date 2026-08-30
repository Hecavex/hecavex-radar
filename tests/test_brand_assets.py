from __future__ import annotations

import json
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from hecavex_radar.brand_assets import (
    _extract_official_assets,
    _read_state,
    _reviewed_official_domains,
)
from hecavex_radar.brands import BrandEntry, BrandRegistry


def _entry(brand: str, domains: list[str]) -> BrandEntry:
    alias = brand.casefold().replace(" ", "")
    return BrandEntry(
        brand=brand,
        last_reviewed_at="2026-08-30",
        aliases=[alias],
        fuzzy_aliases=[alias],
        excluded_terms=[],
        excluded_domains=[],
        category="test",
        official_domains=domains,
        sources=[f"https://{domains[0]}/"],
    )


def test_asset_baseline_rotates_across_every_reviewed_official_domain() -> None:
    registry = BrandRegistry(
        scope="test",
        reviewed_at="2026-08-30",
        entries=[
            _entry("Example One", ["example.lt", "example.com"]),
            _entry("Example Two", ["example-two.lt"]),
        ],
    )

    domains = _reviewed_official_domains(registry)

    assert [(item.brand, item.domain) for item in domains] == [
        ("Example One", "example.lt"),
        ("Example One", "example.com"),
        ("Example Two", "example-two.lt"),
    ]
    assert all(item.entry.brand == item.brand for item in domains)


def test_state_reconciles_cursor_when_official_domain_coverage_expands() -> None:
    registry = BrandRegistry(
        scope="test",
        reviewed_at="2026-08-30",
        entries=[_entry("Example", ["example.lt", "example.com", "example.eu"])],
    )
    state = {
        "schemaVersion": 1,
        "dataset": "urlscan-official-brand-assets",
        "generatedAt": "2026-08-30T10:00:00.000Z",
        "configured": False,
        "budgetDay": "2026-08-30",
        "searchRequests": 0,
        "resultRequests": 0,
        "officialCursor": 1,
        "assetCursor": 0,
        "officialCount": 2,
        "eligibleAssetCount": 0,
        "selectedOfficialDomains": 2,
        "selectedAssetHashes": 0,
        "lastOutcome": "skipped-not-configured",
        "lastRunSearchRequests": 0,
        "lastRunResultRequests": 0,
        "assets": [],
        "hashOwners": [],
        "blockedHashes": [],
    }

    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        target = root / "official-brand-assets.json"
        target.write_text(json.dumps(state), encoding="utf-8")
        with patch("hecavex_radar.brand_assets._state_path", return_value=target):
            reconciled = _read_state(root, registry, datetime(2026, 8, 30, 10, 1, tzinfo=UTC))

    assert reconciled is not None
    assert reconciled["officialCount"] == 3
    assert reconciled["officialCursor"] == 1
    assert reconciled["selectedOfficialDomains"] == 2


def test_asset_extraction_accepts_a_brands_second_reviewed_domain() -> None:
    entry = _entry("Example", ["example.lt", "example.com"])
    official = _reviewed_official_domains(
        BrandRegistry(scope="test", reviewed_at="2026-08-30", entries=[entry])
    )[1]
    digest = "a" * 64
    detail = {
        "task": {"time": "2026-08-30T10:00:00.000Z"},
        "page": {"url": "https://www.example.com/"},
        "data": {
            "requests": [
                {
                    "type": "Script",
                    "request": {"request": {"url": "https://static.example.com/app.js"}},
                    "response": {
                        "hash": digest,
                        "response": {
                            "url": "https://static.example.com/app.js",
                            "mimeType": "application/javascript",
                            "status": 200,
                            "encodedDataLength": 512,
                        },
                    },
                }
            ]
        },
    }

    observations = _extract_official_assets(
        detail,
        official,
        "00000000-0000-4000-8000-000000000001",
        datetime(2026, 8, 30, 10, 1, tzinfo=UTC),
    )

    assert len(observations) == 1
    assert observations[0].brand == "Example"
    assert observations[0].official_domain == "example.com"
    assert observations[0].resource_type == "javascript"
    assert observations[0].sha256 == digest
