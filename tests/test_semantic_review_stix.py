from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

from hecavex_radar.brands import BrandEntry, BrandRegistry
from hecavex_radar.models import RawSignal
from hecavex_radar.normalize import merge_signals, prepare_signal
from hecavex_radar.review import (
    PublicReviewPolicy,
    build_public_export,
    read_review_events,
    record_review_event,
    review_state,
)
from hecavex_radar.stix import RADAR_IDENTITY_ID, TLP_CLEAR_MARKING_ID, build_reviewed_stix_bundle

ROOT = Path(__file__).resolve().parent
FIXTURE = json.loads((ROOT / "fixtures/semantic-signals.json").read_text(encoding="utf-8"))


def registry() -> BrandRegistry:
    return BrandRegistry(
        scope="test",
        reviewed_at="2026-08-25",
        entries=[
            BrandEntry(
                brand="Vinted",
                last_reviewed_at="2026-08-25",
                aliases=["vinted"],
                fuzzy_aliases=["vinted"],
                excluded_terms=[],
                excluded_domains=[],
                category="marketplace",
                official_domains=["vinted.com", "vinted.lt"],
                sources=["https://www.vinted.com/"],
            )
        ],
    )


def signal(source: str = "CertStream") -> dict[str, object]:
    prepared = prepare_signal(
        RawSignal(
            url=FIXTURE["url"],
            source=source,
            first_seen=FIXTURE["firstSeen"],
            last_seen=FIXTURE["lastSeen"],
            status="suspected",
            brand=FIXTURE["brand"],
            confidence=96,
            reason_codes=["brand-exact-token", "suspicious-context", "different-tld"],
        ),
        "2026-08-25T12:00:00.000Z",
    )
    if prepared is None:  # pragma: no cover - fixed valid fixture
        raise RuntimeError("Semantic test fixture did not normalize.")
    return prepared


class SemanticSignalTests(unittest.TestCase):
    def test_new_fields_do_not_turn_match_score_into_a_verdict(self) -> None:
        prepared = signal()
        self.assertEqual(prepared["matchScore"], 96)
        self.assertEqual(prepared["confidence"], prepared["matchScore"])
        self.assertEqual(prepared["evidenceTier"], "name-only")
        self.assertEqual(prepared["reviewState"], "unreviewed")
        self.assertEqual(prepared["ltRelevance"], "lithuanian-brand-relevance")

    def test_second_source_is_corroboration_not_confirmation(self) -> None:
        merged = merge_signals([signal("CertStream"), signal("URLScan")], 10)
        self.assertEqual(merged[0]["evidenceTier"], "corroborated")
        self.assertEqual(merged[0]["reviewState"], "unreviewed")


class ReviewLedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.database = Path(temporary.name) / "review.sqlite3"

    def _confirm(self) -> None:
        record_review_event(
            self.database,
            action="confirm",
            domain=FIXTURE["domain"],
            brand=FIXTURE["brand"],
            reason_code="credential-phishing",
            recorded_at="2026-08-25T12:00:00.000Z",
            reviewed_at="2026-08-25T12:00:00.000Z",
            review_state="confirmed-suspicious",
            evidence_codes=["certificate-transparency", "urlscan-page"],
            expires_at="2026-09-25T12:00:00.000Z",
            lt_relevance="lithuanian-targeting",
            analyst_confidence=85,
            note="Private and never exported",
        )

    def test_append_only_ledger_exports_bounded_positive_assessment(self) -> None:
        self._confirm()
        events = read_review_events(self.database)
        exported = build_public_export(
            review_state(events),
            registry(),
            "2026-08-25T12:01:00.000Z",
        )
        self.assertEqual(exported["schemaVersion"], 2)
        self.assertEqual(exported["assessments"][0]["reviewState"], "confirmed-suspicious")
        self.assertEqual(exported["assessments"][0]["analystConfidence"], 85)
        self.assertNotIn("note", exported["assessments"][0])

        with closing(sqlite3.connect(self.database)) as connection, self.assertRaises(sqlite3.IntegrityError):
            connection.execute("UPDATE review_events SET action = 'retract'")

    def test_expired_confirmation_returns_to_needs_review(self) -> None:
        self._confirm()
        assessment = build_public_export(
            review_state(read_review_events(self.database)),
            registry(),
            "2026-09-26T12:00:00.000Z",
        )["assessments"][0]
        prepared = signal()
        PublicReviewPolicy((), (), (assessment,)).apply_assessments([prepared], datetime(2026, 9, 26, tzinfo=UTC))
        self.assertEqual(prepared["reviewState"], "needs-review")
        self.assertEqual(prepared["evidenceTier"], "reviewed")
        self.assertEqual(prepared["ltRelevance"], "lithuanian-targeting")

    def test_correction_keeps_indicator_identity_and_retraction_revokes(self) -> None:
        self._confirm()
        confirmed = build_public_export(
            review_state(read_review_events(self.database)),
            registry(),
            "2026-08-25T12:01:00.000Z",
        )["assessments"][0]
        first_bundle = build_reviewed_stix_bundle([confirmed], "2026-08-25T12:01:00.000Z")
        first_indicator = next(item for item in first_bundle["objects"] if item["type"] == "indicator")

        record_review_event(
            self.database,
            action="correct",
            domain=FIXTURE["domain"],
            brand=FIXTURE["brand"],
            reason_code="brand-impersonation",
            recorded_at="2026-08-25T13:00:00.000Z",
            reviewed_at="2026-08-25T12:00:00.000Z",
            review_state="confirmed-suspicious",
            evidence_codes=["certificate-transparency", "screenshot", "urlscan-page"],
            expires_at="2026-10-25T12:00:00.000Z",
            lt_relevance="lithuanian-targeting",
            analyst_confidence=90,
        )
        corrected = build_public_export(
            review_state(read_review_events(self.database)),
            registry(),
            "2026-08-25T13:01:00.000Z",
        )["assessments"][0]
        second_bundle = build_reviewed_stix_bundle([corrected], "2026-08-25T13:01:00.000Z")
        second_indicator = next(item for item in second_bundle["objects"] if item["type"] == "indicator")
        self.assertEqual(first_indicator["id"], second_indicator["id"])
        self.assertEqual(second_indicator["modified"], "2026-08-25T13:00:00.000Z")
        self.assertEqual(second_indicator["created_by_ref"], RADAR_IDENTITY_ID)
        self.assertEqual(second_indicator["object_marking_refs"], [TLP_CLEAR_MARKING_ID])

        record_review_event(
            self.database,
            action="retract",
            domain=FIXTURE["domain"],
            brand=FIXTURE["brand"],
            reason_code="incorrect-assessment",
            recorded_at="2026-08-25T14:00:00.000Z",
            reviewed_at="2026-08-25T12:00:00.000Z",
            review_state="inconclusive",
            evidence_codes=["certificate-transparency", "screenshot", "urlscan-page"],
            expires_at="2026-10-25T12:00:00.000Z",
            lt_relevance="lithuanian-targeting",
            analyst_confidence=90,
        )
        retracted = build_public_export(
            review_state(read_review_events(self.database)),
            registry(),
            "2026-08-25T14:01:00.000Z",
        )["assessments"][0]
        third_bundle = build_reviewed_stix_bundle([retracted], "2026-08-25T14:01:00.000Z")
        third_indicator = next(item for item in third_bundle["objects"] if item["type"] == "indicator")
        self.assertEqual(first_indicator["id"], third_indicator["id"])
        self.assertTrue(third_indicator["revoked"])

    def test_fresh_confirmation_preserves_revoked_indicator_lifecycle(self) -> None:
        self._confirm()
        record_review_event(
            self.database,
            action="retract",
            domain=FIXTURE["domain"],
            brand=FIXTURE["brand"],
            reason_code="incorrect-assessment",
            recorded_at="2026-08-25T14:00:00.000Z",
            reviewed_at="2026-08-25T12:00:00.000Z",
            review_state="inconclusive",
            evidence_codes=["certificate-transparency", "urlscan-page"],
            expires_at="2026-09-25T12:00:00.000Z",
            lt_relevance="lithuanian-targeting",
            analyst_confidence=85,
        )
        record_review_event(
            self.database,
            action="confirm",
            domain=FIXTURE["domain"],
            brand=FIXTURE["brand"],
            reason_code="credential-phishing",
            recorded_at="2026-08-26T09:00:00.000Z",
            reviewed_at="2026-08-26T09:00:00.000Z",
            review_state="confirmed-suspicious",
            evidence_codes=["certificate-transparency", "screenshot"],
            expires_at="2026-09-26T09:00:00.000Z",
            lt_relevance="lithuanian-targeting",
            analyst_confidence=90,
        )

        exported = build_public_export(
            review_state(read_review_events(self.database)),
            registry(),
            "2026-08-26T09:01:00.000Z",
        )
        self.assertEqual(len(exported["assessments"]), 2)
        self.assertNotEqual(exported["assessments"][0]["id"], exported["assessments"][1]["id"])

        bundle = build_reviewed_stix_bundle(exported["assessments"], "2026-08-26T09:01:00.000Z")
        indicators = [item for item in bundle["objects"] if item["type"] == "indicator"]
        self.assertEqual(len(indicators), 2)
        indicators_by_created = {item["created"]: item for item in indicators}
        self.assertTrue(indicators_by_created["2026-08-25T12:00:00.000Z"]["revoked"])
        self.assertFalse(indicators_by_created["2026-08-26T09:00:00.000Z"]["revoked"])

        prepared = signal()
        PublicReviewPolicy((), (), tuple(exported["assessments"])).apply_assessments(
            [prepared], datetime(2026, 8, 26, 9, 1, tzinfo=UTC)
        )
        self.assertEqual(prepared["reviewState"], "confirmed-suspicious")
        self.assertEqual(prepared["ltRelevance"], "lithuanian-targeting")

    def test_reviewed_indicator_has_a_public_history_sighting_when_available(self) -> None:
        self._confirm()
        assessment = build_public_export(
            review_state(read_review_events(self.database)),
            registry(),
            "2026-08-25T12:01:00.000Z",
        )["assessments"][0]
        history_signal = signal()
        history = {
            "signals": [
                {
                    "id": history_signal["id"],
                    "domain": history_signal["domain"],
                    "firstSeen": "2026-08-25T10:00:00.000Z",
                    "lastSeen": "2026-08-25T10:05:00.000Z",
                    "observationCount": 3,
                }
            ]
        }

        bundle = build_reviewed_stix_bundle(
            [assessment],
            "2026-08-25T12:01:00.000Z",
            history,
        )
        indicator = next(item for item in bundle["objects"] if item["type"] == "indicator")
        sighting = next(item for item in bundle["objects"] if item["type"] == "sighting")
        self.assertEqual(sighting["sighting_of_ref"], indicator["id"])
        self.assertEqual(sighting["first_seen"], "2026-08-25T10:00:00.000Z")
        self.assertEqual(sighting["last_seen"], "2026-08-25T10:05:00.000Z")
        self.assertEqual(sighting["count"], 3)
        self.assertEqual(sighting["created_by_ref"], RADAR_IDENTITY_ID)


if __name__ == "__main__":
    unittest.main()
