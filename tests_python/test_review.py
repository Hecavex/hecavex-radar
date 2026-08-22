import json
import sqlite3
from pathlib import Path

import pytest
from pytest import MonkeyPatch

import hecavex_radar.review as review_module
from hecavex_radar.brands import load_brand_registry, score_domain
from hecavex_radar.review import (
    PROJECT_ROOT,
    LocalReviewState,
    _database_path,
    _public_output_path,
    build_public_export,
    export_public_review,
    load_public_review,
    main,
    read_review_events,
    record_review_event,
    review_state,
)

NOW = "2026-08-22T09:00:00.000Z"
DOMAIN = "secure-swedbank-login.example"


def test_private_database_boundary_is_independent_of_working_directory(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    external = tmp_path / "private" / "review.sqlite3"
    unrelated = tmp_path / "unrelated"
    unrelated.mkdir()

    for working_directory in (PROJECT_ROOT, PROJECT_ROOT.parent, unrelated):
        monkeypatch.chdir(working_directory)
        assert _database_path(external) == external.resolve()
        with pytest.raises(ValueError, match="outside the Git repository"):
            _database_path(PROJECT_ROOT / "private-review.sqlite3")


def test_public_export_boundary_is_independent_of_working_directory(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    monkeypatch.setattr(review_module, "PROJECT_ROOT", repository.resolve())
    expected = (repository / "data/review/decisions.json").resolve()
    unrelated = tmp_path / "unrelated"
    unrelated.mkdir()

    for working_directory in (repository, repository.parent, unrelated):
        monkeypatch.chdir(working_directory)
        assert _public_output_path("data/review/decisions.json") == expected
        assert _public_output_path(expected) == expected
        with pytest.raises(ValueError, match="below data/review"):
            _public_output_path(tmp_path / "outside.json")


def test_cli_loads_repository_configuration_outside_repository(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    unrelated = tmp_path / "unrelated"
    unrelated.mkdir()
    database = tmp_path / "private/review.sqlite3"
    monkeypatch.chdir(unrelated)

    result = main(
        [
            "--database",
            str(database),
            "false-positive",
            DOMAIN,
            "--reason",
            "lexical-collision",
        ]
    )

    assert result == 0
    assert review_state(read_review_events(database)).false_positives[DOMAIN].brand == "Swedbank"


def test_private_review_ledger_is_append_only_and_restore_is_derived_state(tmp_path: Path) -> None:
    database = tmp_path / "private" / "review.sqlite3"
    first = record_review_event(
        database,
        action="false-positive",
        domain=DOMAIN,
        brand="Swedbank",
        scope="exact",
        reason_code="lexical-collision",
        note="Private explanation with case context",
        recorded_at=NOW,
    )
    record_review_event(
        database,
        action="restore",
        domain=DOMAIN,
        recorded_at="2026-08-22T10:00:00.000Z",
    )

    events = read_review_events(database)
    assert len(events) == 2
    assert events[0] == first
    assert review_state(events).false_positives == {}
    with sqlite3.connect(database) as connection, pytest.raises(sqlite3.DatabaseError, match="append-only"):
        connection.execute("DELETE FROM review_events")


def test_sanitized_export_never_contains_private_notes(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    registry = load_brand_registry()
    repository = tmp_path / "repository"
    repository.mkdir()
    monkeypatch.setattr(review_module, "PROJECT_ROOT", repository.resolve())
    monkeypatch.chdir(repository)
    database = tmp_path / "private" / "review.sqlite3"
    record_review_event(
        database,
        action="false-positive",
        domain=DOMAIN,
        brand="Swedbank",
        scope="exact",
        reason_code="lexical-collision",
        note="analyst identity and private evidence",
        recorded_at=NOW,
    )

    target, payload, changed = export_public_review(database, registry=registry, generated_at=NOW)
    body = target.read_text(encoding="utf-8")

    assert changed
    assert len(payload["suppressions"]) == 1
    assert "private evidence" not in body
    assert "note" not in body
    assert load_public_review(target.relative_to(repository), registry=registry).suppresses(
        "secure-swedbank-login[.]example", "Swedbank"
    )


def test_manual_candidate_must_match_brand_and_cannot_inflate_confidence(tmp_path: Path) -> None:
    registry = load_brand_registry()
    candidate_domain = "swedbank-auth.lt"
    match = score_domain(candidate_domain, registry)
    assert match is not None
    assert match.confidence < 100
    database = tmp_path / "review.sqlite3"
    event = record_review_event(
        database,
        action="add",
        domain=candidate_domain,
        url=f"https://{candidate_domain}",
        brand="Swedbank",
        confidence=match.confidence,
        reason_code="manual-observation",
        recorded_at=NOW,
    )
    payload = build_public_export(
        LocalReviewState(false_positives={}, allowlists={}, candidates={candidate_domain: event}),
        registry,
        NOW,
    )
    assert payload["candidates"][0]["confidence"] == match.confidence

    inflated = record_review_event(
        database,
        action="add",
        domain=candidate_domain,
        url=f"https://{candidate_domain}",
        brand="Swedbank",
        confidence=match.confidence + 1,
        reason_code="manual-observation",
        recorded_at="2026-08-22T09:00:01.000Z",
    )
    rejected = build_public_export(
        LocalReviewState(false_positives={}, allowlists={}, candidates={candidate_domain: inflated}),
        registry,
        NOW,
    )
    assert rejected["candidates"] == []


def test_public_export_rejects_cross_brand_candidate(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    registry = load_brand_registry()
    repository = tmp_path / "repository"
    target = repository / "data/review/public-decisions.json"
    target.parent.mkdir(parents=True)
    monkeypatch.setattr(review_module, "PROJECT_ROOT", repository.resolve())
    monkeypatch.chdir(repository)
    event = record_review_event(
        tmp_path / "private/review.sqlite3",
        action="add",
        domain=DOMAIN,
        url=f"https://{DOMAIN}",
        brand="Swedbank",
        confidence=80,
        reason_code="manual-observation",
        recorded_at=NOW,
    )
    payload = build_public_export(
        LocalReviewState(false_positives={}, allowlists={}, candidates={DOMAIN: event}),
        registry,
        NOW,
    )
    payload["candidates"][0]["brand"] = "Revolut"
    target.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="schema version 1"):
        load_public_review("data/review/public-decisions.json", registry=registry)


def test_public_export_rejects_suppression_with_wrong_brand(tmp_path: Path) -> None:
    registry = load_brand_registry()
    event = record_review_event(
        tmp_path / "review.sqlite3",
        action="false-positive",
        domain="revolut-login.com",
        brand="Swedbank",
        scope="exact",
        reason_code="wrong-brand",
        recorded_at=NOW,
    )
    with pytest.raises(ValueError, match="conflicts with current brand evidence"):
        build_public_export(
            LocalReviewState(
                false_positives={"revolut-login.com": event},
                allowlists={},
                candidates={},
            ),
            registry,
            NOW,
        )
