from __future__ import annotations

import json
import os
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from .models import CandidateMatch, CertStreamCandidate
from .safety import defang_host, stable_id

VILNIUS = ZoneInfo("Europe/Vilnius")
MAXIMUM_ARCHIVE_BYTES = 25 * 1024 * 1024
MAXIMUM_ARCHIVE_RECORDS = 25_000


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def vilnius_date(value: datetime) -> str:
    return _aware(value).astimezone(VILNIUS).date().isoformat()


def candidate_from_match(match: CandidateMatch, observed_at: datetime) -> CertStreamCandidate:
    observed = _aware(observed_at).astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return {
        "schemaVersion": 1,
        "id": stable_id(match.domain),
        "observedAt": observed,
        "indicatorType": "domain",
        "domain": defang_host(match.domain),
        "registrableDomain": defang_host(match.registrable_domain),
        "source": "CertStream",
        "brand": match.brand,
        "confidence": match.confidence,
        "reasons": match.reasons,
    }


def _bounded_root(value: str | Path) -> Path:
    repository = Path.cwd().resolve()
    root = (repository / value).resolve()
    if root == repository or not root.is_relative_to(repository):
        raise ValueError("CERTSTREAM_ARCHIVE_ROOT must stay inside the repository.")
    return root


def _candidate_path(root: str | Path, day: str) -> Path:
    try:
        date.fromisoformat(day)
    except ValueError as error:
        raise ValueError("Invalid candidate archive date.") from error
    return _bounded_root(root) / day / "domains.ndjson"


def _is_candidate(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and value.get("schemaVersion") == 1
        and value.get("indicatorType") == "domain"
        and value.get("source") == "CertStream"
        and all(
            isinstance(value.get(field), str) for field in ("id", "observedAt", "domain", "registrableDomain", "brand")
        )
        and isinstance(value.get("confidence"), int)
        and not isinstance(value.get("confidence"), bool)
        and isinstance(value.get("reasons"), list)
        and all(isinstance(reason, str) for reason in value["reasons"])
    )


def read_candidate_file(path: Path, maximum: int = MAXIMUM_ARCHIVE_RECORDS) -> list[CertStreamCandidate]:
    try:
        if path.stat().st_size > MAXIMUM_ARCHIVE_BYTES:
            raise ValueError(f"Candidate archive exceeds 25 MiB: {path.relative_to(Path.cwd())}")
        body = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    records: list[CertStreamCandidate] = []
    for line in body.splitlines():
        if not line.strip():
            continue
        try:
            value: Any = json.loads(line)
        except json.JSONDecodeError:
            continue
        if _is_candidate(value):
            records.append(value)
        if len(records) >= maximum:
            break
    return records


class CandidateArchiveWriter:
    def __init__(self, root: str | Path) -> None:
        self._root = root
        self._known_by_day: dict[str, set[str]] = {}

    def append(self, records: list[CertStreamCandidate]) -> int:
        groups: dict[str, list[CertStreamCandidate]] = {}
        for record in records:
            observed = datetime.fromisoformat(record["observedAt"].replace("Z", "+00:00"))
            groups.setdefault(vilnius_date(observed), []).append(record)

        written = 0
        for day, candidates in groups.items():
            path = _candidate_path(self._root, day)
            known = self._known_by_day.get(day)
            if known is None:
                known = {candidate["id"] for candidate in read_candidate_file(path, maximum=MAXIMUM_ARCHIVE_RECORDS)}
                self._known_by_day[day] = known
            existing_records = len(known)
            unique: list[CertStreamCandidate] = []
            for candidate in candidates:
                if candidate["id"] not in known:
                    known.add(candidate["id"])
                    unique.append(candidate)
            if not unique:
                continue
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                existing_size = path.stat().st_size if path.exists() else 0
                remaining_records = max(0, MAXIMUM_ARCHIVE_RECORDS - existing_records)
                lines: list[str] = []
                projected_size = existing_size
                for candidate in unique[:remaining_records]:
                    line = json.dumps(candidate, ensure_ascii=False, separators=(",", ":")) + "\n"
                    line_size = len(line.encode("utf-8"))
                    if projected_size + line_size > MAXIMUM_ARCHIVE_BYTES:
                        break
                    lines.append(line)
                    projected_size += line_size
                if not lines:
                    continue
                descriptor = os.open(path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
                with os.fdopen(descriptor, "a", encoding="utf-8", newline="\n") as stream:
                    stream.writelines(lines)
                written += len(lines)
            except OSError:
                for candidate in unique:
                    known.discard(candidate["id"])
                raise
        return written


def append_candidates(root: str | Path, records: list[CertStreamCandidate]) -> int:
    return CandidateArchiveWriter(root).append(records)


def read_recent_candidates(
    root: str | Path,
    lookback_days: int,
    now: datetime,
    maximum: int = 25_000,
) -> list[CertStreamCandidate]:
    archive_root = _bounded_root(root)
    try:
        directories = sorted(
            (entry.name for entry in archive_root.iterdir() if entry.is_dir() and _valid_day(entry.name)),
            reverse=True,
        )
    except FileNotFoundError:
        return []
    today = _aware(now).astimezone(VILNIUS).date()
    permitted = {(today - timedelta(days=offset)).isoformat() for offset in range(lookback_days)}
    results: list[CertStreamCandidate] = []
    for day in (value for value in directories if value in permitted):
        remaining = maximum - len(results)
        if remaining <= 0:
            break
        results.extend(read_candidate_file(_candidate_path(root, day), remaining))
    return results


def _valid_day(value: str) -> bool:
    try:
        return date.fromisoformat(value).isoformat() == value
    except ValueError:
        return False
