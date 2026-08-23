import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest
from pytest import MonkeyPatch

from hecavex_radar import certstream_archive
from hecavex_radar.certstream_archive import (
    append_candidates,
    candidate_from_match,
    read_attempt_file,
    read_candidate_file,
    read_recent_candidates,
    record_successful_attempt,
    vilnius_date,
)
from hecavex_radar.models import CandidateMatch, CertStreamCandidate


def test_uses_vilnius_calendar_date() -> None:
    assert vilnius_date(datetime(2026, 8, 21, 20, 59, 59, tzinfo=UTC)) == "2026-08-21"
    assert vilnius_date(datetime(2026, 8, 21, 21, 0, 0, tzinfo=UTC)) == "2026-08-22"


def test_writes_defanged_ndjson_and_deduplicates(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    root = Path("data/certstream")
    candidate = candidate_from_match(
        CandidateMatch(
            domain="secure-swedbank.example",
            registrable_domain="secure-swedbank.example",
            brand="Swedbank",
            confidence=92,
            reasons=["brand text match: swedbank"],
        ),
        datetime(2026, 8, 21, 21, 30, tzinfo=UTC),
    )
    assert append_candidates(root, [candidate, candidate]) == 1
    assert append_candidates(root, [candidate]) == 0
    archive = (root / "2026-08-22" / "domains.ndjson").read_text(encoding="utf-8")
    assert "secure-swedbank[.]example" in archive
    assert "secure-swedbank.example" not in archive
    recent = read_recent_candidates(root, 1, datetime(2026, 8, 22, 10, tzinfo=UTC))
    assert len(recent) == 1


def test_successful_empty_window_creates_an_explicit_daily_partition(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    root = Path("data/certstream")
    started = datetime(2026, 8, 21, 20, 58, tzinfo=UTC)
    ended = datetime(2026, 8, 21, 21, 2, tzinfo=UTC)

    path = record_successful_attempt(
        root,
        collector_started_at=started,
        ended_at=ended,
        expected_listening_seconds=240,
        listening_seconds=240.002,
        messages=80_000,
        dns_names=145_000,
        matches=0,
        new_records=0,
        outcome="healthy-empty",
    )
    assert path == tmp_path / root / "2026-08-22" / "attempts.ndjson"
    assert not path.with_name("domains.ndjson").exists()
    assert read_attempt_file(path) == [json.loads(path.read_text(encoding="utf-8"))]

    # Replaying the same successful attempt is deterministic and does not add a line.
    record_successful_attempt(
        root,
        collector_started_at=started,
        ended_at=ended,
        expected_listening_seconds=240,
        listening_seconds=240.002,
        messages=80_000,
        dns_names=145_000,
        matches=0,
        new_records=0,
        outcome="healthy-empty",
    )
    assert len(path.read_text(encoding="utf-8").splitlines()) == 1


def test_attempt_partition_rejects_partial_or_inconsistent_windows(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    started = datetime(2026, 8, 21, 10, tzinfo=UTC)
    ended = datetime(2026, 8, 21, 10, 4, tzinfo=UTC)
    with pytest.raises(ValueError, match="invalid CertStream attempt"):
        record_successful_attempt(
            "data/certstream",
            collector_started_at=started,
            ended_at=ended,
            expected_listening_seconds=240,
            listening_seconds=120,
            messages=10,
            dns_names=20,
            matches=0,
            new_records=0,
            outcome="partial",
        )
    with pytest.raises(ValueError, match="invalid CertStream attempt"):
        record_successful_attempt(
            "data/certstream",
            collector_started_at=started,
            ended_at=ended,
            expected_listening_seconds=240,
            listening_seconds=120,
            messages=10,
            dns_names=20,
            matches=1,
            new_records=0,
            outcome="healthy-empty",
        )
    assert not Path("data/certstream").exists()


def test_stops_before_daily_record_and_byte_limits(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    observed = datetime(2026, 8, 21, 10, tzinfo=UTC)
    first = candidate_from_match(CandidateMatch("one.example", "one.example", "One", 80, ["test"]), observed)
    second = candidate_from_match(CandidateMatch("two.example", "two.example", "Two", 80, ["test"]), observed)
    encoded_size = len((json.dumps(first, ensure_ascii=False, separators=(",", ":")) + "\n").encode())
    monkeypatch.setattr(certstream_archive, "MAXIMUM_ARCHIVE_RECORDS", 2)
    monkeypatch.setattr(certstream_archive, "MAXIMUM_ARCHIVE_BYTES", encoded_size + 1)
    assert append_candidates("data/certstream", [first, second]) == 1
    path = Path("data/certstream/2026-08-21/domains.ndjson")
    assert path.stat().st_size <= encoded_size + 1

    monkeypatch.setattr(certstream_archive, "MAXIMUM_ARCHIVE_BYTES", 25 * 1024 * 1024)
    monkeypatch.setattr(certstream_archive, "MAXIMUM_ARCHIVE_RECORDS", 1)
    assert append_candidates("data/certstream", [second]) == 0


def test_reader_accepts_only_closed_bounded_canonical_records(tmp_path: Path) -> None:
    candidate = candidate_from_match(
        CandidateMatch("secure-swedbank.example", "secure-swedbank.example", "Swedbank", 92, ["test"]),
        datetime(2026, 8, 21, 10, tzinfo=UTC),
    )
    variants: list[Any] = []
    for field, value in [
        ("domain", "secure-swedbank.example"),
        ("registrableDomain", "other[.]example"),
        ("id", "0" * 20),
        ("observedAt", "2026-08-21T10:00:00Z"),
        ("confidence", 101),
        ("confidence", True),
        ("brand", " " * 4),
        ("brand", "x" * 121),
        ("reasons", []),
        ("reasons", ["x" * 241]),
    ]:
        invalid = dict(candidate)
        invalid[field] = value
        variants.append(invalid)
    variants.extend(({**candidate, "extra": "public"}, {**candidate, "_private": "secret"}))

    path = tmp_path / "2026-08-21" / "domains.ndjson"
    path.parent.mkdir(parents=True)
    path.write_text(
        "\n".join(json.dumps(value, separators=(",", ":")) for value in [candidate, *variants]) + "\n",
        encoding="utf-8",
    )
    assert read_candidate_file(path) == [candidate]


def test_reader_rejects_candidate_in_wrong_vilnius_partition(tmp_path: Path) -> None:
    candidate = candidate_from_match(
        CandidateMatch("secure-swedbank.example", "secure-swedbank.example", "Swedbank", 92, ["test"]),
        datetime(2026, 8, 21, 21, 30, tzinfo=UTC),
    )
    wrong_partition = tmp_path / "2026-08-21" / "domains.ndjson"
    wrong_partition.parent.mkdir(parents=True)
    wrong_partition.write_text(json.dumps(candidate) + "\n", encoding="utf-8")
    assert read_candidate_file(wrong_partition) == []


def test_writer_rejects_private_or_extra_candidate_fields(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    candidate = candidate_from_match(
        CandidateMatch("secure-swedbank.example", "secure-swedbank.example", "Swedbank", 92, ["test"]),
        datetime(2026, 8, 21, 10, tzinfo=UTC),
    )
    private = cast(CertStreamCandidate, {**candidate, "_private": "secret"})
    with pytest.raises(ValueError, match="invalid CertStream candidate"):
        append_candidates("data/certstream", [private])
    assert not Path("data/certstream").exists()


def test_append_recovers_an_invalid_partial_final_line(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    root = Path("data/certstream")
    observed = datetime(2026, 8, 21, 10, tzinfo=UTC)
    first = candidate_from_match(CandidateMatch("one.example", "one.example", "One", 80, ["test"]), observed)
    second = candidate_from_match(CandidateMatch("two.example", "two.example", "Two", 80, ["test"]), observed)
    assert append_candidates(root, [first]) == 1
    path = root / "2026-08-21" / "domains.ndjson"
    with path.open("ab") as stream:
        stream.write(b'{"schemaVersion":1,"_private":"unfinished')

    assert append_candidates(root, [second]) == 1
    body = path.read_bytes()
    assert body.endswith(b"\n")
    assert b"unfinished" not in body
    assert read_candidate_file(path) == [first, second]


def test_append_preserves_a_valid_unterminated_final_record(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    root = Path("data/certstream")
    observed = datetime(2026, 8, 21, 10, tzinfo=UTC)
    first = candidate_from_match(CandidateMatch("one.example", "one.example", "One", 80, ["test"]), observed)
    second = candidate_from_match(CandidateMatch("two.example", "two.example", "Two", 80, ["test"]), observed)
    assert append_candidates(root, [first]) == 1
    path = root / "2026-08-21" / "domains.ndjson"
    path.write_bytes(path.read_bytes().removesuffix(b"\n"))

    assert append_candidates(root, [second]) == 1
    assert read_candidate_file(path) == [first, second]
