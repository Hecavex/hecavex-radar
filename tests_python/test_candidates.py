import json
from datetime import UTC, datetime
from pathlib import Path

from pytest import MonkeyPatch

from hecavex_radar import candidates
from hecavex_radar.candidates import append_candidates, candidate_from_match, read_recent_candidates, vilnius_date
from hecavex_radar.models import CandidateMatch


def test_uses_vilnius_calendar_date() -> None:
    assert vilnius_date(datetime(2026, 8, 21, 20, 59, 59, tzinfo=UTC)) == "2026-08-21"
    assert vilnius_date(datetime(2026, 8, 21, 21, 0, 0, tzinfo=UTC)) == "2026-08-22"


def test_writes_defanged_ndjson_and_deduplicates(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    root = Path("data/candidates")
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


def test_stops_before_daily_record_and_byte_limits(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    observed = datetime(2026, 8, 21, 10, tzinfo=UTC)
    first = candidate_from_match(CandidateMatch("one.example", "one.example", "One", 80, ["test"]), observed)
    second = candidate_from_match(CandidateMatch("two.example", "two.example", "Two", 80, ["test"]), observed)
    encoded_size = len((json.dumps(first, ensure_ascii=False, separators=(",", ":")) + "\n").encode())
    monkeypatch.setattr(candidates, "MAXIMUM_ARCHIVE_RECORDS", 2)
    monkeypatch.setattr(candidates, "MAXIMUM_ARCHIVE_BYTES", encoded_size + 1)
    assert append_candidates("data/candidates", [first, second]) == 1
    path = Path("data/candidates/2026-08-21/domains.ndjson")
    assert path.stat().st_size <= encoded_size + 1

    monkeypatch.setattr(candidates, "MAXIMUM_ARCHIVE_BYTES", 25 * 1024 * 1024)
    monkeypatch.setattr(candidates, "MAXIMUM_ARCHIVE_RECORDS", 1)
    assert append_candidates("data/candidates", [second]) == 0
