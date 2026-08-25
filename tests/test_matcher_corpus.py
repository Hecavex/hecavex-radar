from __future__ import annotations

import json
from pathlib import Path

from hecavex_radar.brands import UNICODE_SECURITY_PROFILE, load_brand_registry, score_domain
from hecavex_radar.provenance import reason_codes_from_match

ROOT = Path(__file__).resolve().parents[1]


def test_versioned_matcher_corpus() -> None:
    corpus = json.loads((ROOT / "data" / "matcher" / "lithuanian-brands-v1.json").read_text(encoding="utf-8"))
    registry = load_brand_registry(ROOT / "data" / "brands-lt.json")

    assert corpus["schemaVersion"] == 1
    assert corpus["unicodeProfile"]["uts46"] == UNICODE_SECURITY_PROFILE["uts46"]
    assert corpus["unicodeProfile"]["uts39"] == UNICODE_SECURITY_PROFILE["uts39"]
    assert len({case["id"] for case in corpus["cases"]}) == len(corpus["cases"])

    for case in corpus["cases"]:
        result = score_domain(case["domain"], registry)
        expected = case["expected"]
        if not expected["matched"]:
            assert result is None, case["id"]
            assert expected["rejectionReason"]
            continue
        assert result is not None, case["id"]
        assert result.brand == expected["brand"], case["id"]
        minimum, maximum = expected["scoreBand"]
        assert minimum <= result.confidence <= maximum, case["id"]
        reason_codes = set(reason_codes_from_match(result.reasons))
        assert set(expected["reasonCodes"]) <= reason_codes, (case["id"], result.reasons)


def test_every_brand_has_an_independent_review_date() -> None:
    registry = load_brand_registry(ROOT / "data" / "brands-lt.json")
    assert len(registry.entries) == 46
    assert all(entry.last_reviewed_at for entry in registry.entries)
