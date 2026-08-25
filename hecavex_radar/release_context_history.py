"""Add bounded passive-context history to a weekly Radar release package."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Any, cast

from .brands import normalize_domain
from .passive_context import _valid_event as valid_context_event
from .safety import defang_host, refang

DEFAULT_JOURNAL_ROOT = "data/history/context"
MAXIMUM_PARTITIONS = 90
MAXIMUM_EVENTS = 100_000
MAXIMUM_EVENT_BYTES = 64 * 1024
MAXIMUM_PARTITION_BYTES = 10 * 1024 * 1024
MAXIMUM_CONTEXT_BYTES = 64 * 1024 * 1024
MAXIMUM_MANIFEST_BYTES = 8 * 1024 * 1024
MAXIMUM_RELEASE_FILES = 10_000
MAXIMUM_RELEASE_BYTES = 128 * 1024 * 1024
TAG = re.compile(r"^radar-data-(\d{4})-W(0[1-9]|[1-4]\d|5[0-3])$")
SHA256 = re.compile(r"^[a-f\d]{64}$")


@dataclass(frozen=True)
class ContextHistorySummary:
    """Counts for the context-history part of a release."""

    events: int
    partitions: int
    files: int
    bytes: int


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(path))


def _is_linklike(path: Path) -> bool:
    return path.is_symlink() or path.is_junction()


def _reject_linklike_path(repository: Path, target: Path) -> None:
    repository = _absolute(repository)
    target = _absolute(target)
    if not target.is_relative_to(repository):
        raise ValueError("Release history path escapes the repository.")
    if _is_linklike(repository):
        raise ValueError("Release history refuses a linked repository root.")
    current = repository
    for part in target.relative_to(repository).parts:
        current /= part
        if _is_linklike(current):
            raise ValueError(f"Release history refuses linked path component {current.name}.")


def _regular_file(repository: Path, path: Path, *, maximum_bytes: int) -> bytes:
    _reject_linklike_path(repository, path)
    try:
        stat = path.stat()
    except FileNotFoundError as error:
        raise ValueError(f"Required release file is missing: {path.name}.") from error
    if not path.is_file() or stat.st_size > maximum_bytes:
        raise ValueError(f"Release file is invalid or exceeds its byte limit: {path.name}.")
    resolved_repository = repository.resolve(strict=True)
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise ValueError(f"Required release file cannot be resolved: {path.name}.") from error
    if not resolved.is_relative_to(resolved_repository):
        raise ValueError(f"Release file escapes the repository: {path.name}.")
    payload = path.read_bytes()
    if len(payload) != stat.st_size:
        raise ValueError(f"Release file changed while it was being read: {path.name}.")
    return payload


def _json_object(payload: bytes, *, label: str) -> dict[str, Any]:
    try:
        text = payload.decode("utf-8")
        value: Any = json.loads(
            text,
            parse_constant=lambda raw: (_ for _ in ()).throw(ValueError(f"Non-finite JSON value {raw}.")),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError(f"{label} is not strict UTF-8 JSON.") from error
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain one JSON object.")
    return value


def _timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        return None
    canonical = parsed.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return parsed.astimezone(UTC) if canonical == value else None


def _plain_int(value: object, *, minimum: int, maximum: int) -> int | None:
    return value if type(value) is int and minimum <= value <= maximum else None


def _manifest_files(
    repository: Path,
    package_root: Path,
    manifest: Mapping[str, Any],
) -> list[dict[str, object]]:
    limits = manifest.get("limits")
    if not isinstance(limits, dict):
        raise ValueError("Release manifest has invalid global limits.")
    maximum_files = _plain_int(limits.get("maximumFiles"), minimum=1, maximum=MAXIMUM_RELEASE_FILES)
    maximum_bytes = _plain_int(limits.get("maximumBytes"), minimum=1, maximum=MAXIMUM_RELEASE_BYTES)
    if maximum_files is None or maximum_bytes is None:
        raise ValueError("Release manifest exceeds the supported global limits.")
    raw_files = manifest.get("files")
    if not isinstance(raw_files, list) or len(raw_files) > maximum_files:
        raise ValueError("Release manifest file inventory is invalid.")
    rows: list[dict[str, object]] = []
    seen: set[str] = set()
    total = 0
    for raw in raw_files:
        if not isinstance(raw, dict) or set(raw) != {"path", "bytes", "sha256"}:
            raise ValueError("Release manifest contains an invalid file row.")
        raw_path = raw.get("path")
        size = _plain_int(raw.get("bytes"), minimum=0, maximum=maximum_bytes)
        digest = raw.get("sha256")
        if not isinstance(raw_path, str):
            raise ValueError("Release manifest contains a non-string file path.")
        relative = PurePosixPath(raw_path)
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or raw_path != relative.as_posix()
            or not relative.parts
            or relative.parts[0] != "data"
            or raw_path in seen
            or size is None
            or not isinstance(digest, str)
            or not SHA256.fullmatch(digest)
        ):
            raise ValueError(f"Release manifest contains an unsafe file row: {raw_path!r}.")
        payload = _regular_file(
            repository,
            package_root.joinpath(*relative.parts),
            maximum_bytes=maximum_bytes,
        )
        if len(payload) != size or hashlib.sha256(payload).hexdigest() != digest:
            raise ValueError(f"Release package file does not match its manifest: {raw_path}.")
        seen.add(raw_path)
        total += len(payload)
        if total > maximum_bytes:
            raise ValueError("Release package exceeds its manifest byte limit.")
        rows.append({"path": raw_path, "bytes": size, "sha256": digest})
    return rows


def _verify_package_inventory(repository: Path, package_root: Path, expected: set[str]) -> None:
    _reject_linklike_path(repository, package_root)
    if not package_root.is_dir():
        raise ValueError("Weekly release package root is missing.")
    actual: set[str] = set()
    for path in package_root.rglob("*"):
        _reject_linklike_path(repository, path)
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError("Weekly release package contains a non-regular entry.")
        relative = path.relative_to(package_root).as_posix()
        if relative != "RELEASE-MANIFEST.json":
            actual.add(relative)
    if actual != expected:
        raise ValueError("Weekly release package inventory does not match its manifest.")


def _valid_defanged_identity(row: Mapping[str, object]) -> bool:
    domain = row.get("domain")
    if not isinstance(domain, str):
        return False
    normalized = normalize_domain(refang(domain))
    return normalized is not None and domain == defang_host(normalized)


def _partition_payload(
    repository: Path,
    path: Path,
    partition: date,
    anchor: datetime,
    *,
    allow_urlscan: bool,
    seen_event_ids: set[str],
    counters: dict[str, int],
) -> tuple[bytes, int]:
    payload = _regular_file(repository, path, maximum_bytes=MAXIMUM_PARTITION_BYTES)
    counters["sourceBytes"] += len(payload)
    if counters["sourceBytes"] > MAXIMUM_CONTEXT_BYTES:
        raise ValueError("Context history exceeds its aggregate source byte limit.")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"Context partition {partition} is not strict UTF-8.") from error
    lines = text.splitlines()
    if not lines:
        raise ValueError(f"Context partition {partition} is empty.")
    included: list[dict[str, object]] = []
    for line_number, line in enumerate(lines, start=1):
        encoded_line = line.encode("utf-8")
        if not line.strip() or len(encoded_line) > MAXIMUM_EVENT_BYTES:
            raise ValueError(f"Context partition {partition} line {line_number} is blank or oversized.")
        counters["sourceEvents"] += 1
        if counters["sourceEvents"] > MAXIMUM_EVENTS:
            raise ValueError("Context history exceeds its aggregate event limit.")
        try:
            raw: Any = json.loads(
                line,
                parse_constant=lambda value: (_ for _ in ()).throw(
                    ValueError(f"Non-finite JSON value {value}.")
                ),
            )
        except (json.JSONDecodeError, ValueError) as error:
            raise ValueError(f"Context partition {partition} line {line_number} is malformed.") from error
        if not valid_context_event(raw) or not isinstance(raw, dict) or not _valid_defanged_identity(raw):
            raise ValueError(f"Context partition {partition} line {line_number} violates the event contract.")
        observed_at = _timestamp(raw.get("observedAt"))
        if (
            observed_at is None
            or observed_at.date() != partition
            or observed_at > anchor + timedelta(minutes=5)
            or observed_at < anchor - timedelta(days=MAXIMUM_PARTITIONS)
        ):
            raise ValueError(f"Context partition {partition} line {line_number} is outside the release window.")
        event_id = cast(str, raw["eventId"])
        if event_id in seen_event_ids:
            raise ValueError("Context history contains a duplicate event ID.")
        seen_event_ids.add(event_id)
        if raw.get("component") == "urlscan" and not allow_urlscan:
            continue
        included.append(cast(dict[str, object], raw))
    included.sort(key=lambda row: (cast(str, row["observedAt"]), cast(str, row["eventId"])))
    output = b"".join(
        (
            json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
        ).encode("utf-8")
        for row in included
    )
    return output, len(included)


def _history_files(
    repository: Path,
    anchor: datetime,
    *,
    allow_urlscan: bool,
) -> tuple[list[tuple[dict[str, object], bytes]], ContextHistorySummary]:
    journal_root = repository / DEFAULT_JOURNAL_ROOT
    _reject_linklike_path(repository, journal_root)
    if not journal_root.exists():
        return [], ContextHistorySummary(events=0, partitions=0, files=0, bytes=0)
    if not journal_root.is_dir():
        raise ValueError("Context history root is not a directory.")
    entries = list(journal_root.iterdir())
    if len(entries) > MAXIMUM_PARTITIONS:
        raise ValueError("Context history contains more than 90 date partitions.")
    selected: list[tuple[date, Path]] = []
    first_date = anchor.date() - timedelta(days=MAXIMUM_PARTITIONS - 1)
    for entry in entries:
        _reject_linklike_path(repository, entry)
        if not entry.is_dir():
            raise ValueError("Context history root may contain only ISO-date directories.")
        try:
            partition = date.fromisoformat(entry.name)
        except ValueError as error:
            raise ValueError("Context history contains a non-ISO-date partition.") from error
        if entry.name != partition.isoformat() or partition > anchor.date():
            raise ValueError("Context history contains a non-canonical or future partition.")
        children = list(entry.iterdir())
        for child in children:
            _reject_linklike_path(repository, child)
        if len(children) != 1 or children[0].name != "events.ndjson" or not children[0].is_file():
            raise ValueError(f"Context history partition {entry.name} has an invalid inventory.")
        if partition >= first_date:
            selected.append((partition, children[0]))
    artifacts: list[tuple[dict[str, object], bytes]] = []
    seen_event_ids: set[str] = set()
    counters = {"sourceBytes": 0, "sourceEvents": 0}
    included_events = 0
    included_bytes = 0
    included_partitions = 0
    for partition, source in sorted(selected):
        output, count = _partition_payload(
            repository,
            source,
            partition,
            anchor,
            allow_urlscan=allow_urlscan,
            seen_event_ids=seen_event_ids,
            counters=counters,
        )
        if not output:
            continue
        relative = PurePosixPath("history", "context", partition.isoformat(), "events.ndjson")
        digest = hashlib.sha256(output).hexdigest()
        artifacts.append(
            ({"path": relative.as_posix(), "bytes": len(output), "sha256": digest}, output)
        )
        included_events += count
        included_bytes += len(output)
        included_partitions += 1
    return artifacts, ContextHistorySummary(
        events=included_events,
        partitions=included_partitions,
        files=len(artifacts),
        bytes=included_bytes,
    )


def _atomic_write(path: Path, payload: bytes) -> None:
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def package_context_history(
    tag: str,
    *,
    repository: Path | None = None,
    allow_urlscan: bool = False,
) -> ContextHistorySummary:
    """Validate and add up to 90 days of context history to a release package."""

    tag_match = TAG.fullmatch(tag)
    if tag_match is None:
        raise ValueError("Weekly release tag is invalid.")
    try:
        datetime.fromisocalendar(int(tag_match.group(1)), int(tag_match.group(2)), 1)
    except ValueError as error:
        raise ValueError("Weekly release tag names an invalid ISO week.") from error
    root = _absolute(repository or Path.cwd())
    _reject_linklike_path(root, root)
    package_root = root / "_release" / "stage" / tag
    package_manifest = package_root / "RELEASE-MANIFEST.json"
    standalone_manifest = root / "_release" / "assets" / f"{tag}.manifest.json"
    package_payload = _regular_file(root, package_manifest, maximum_bytes=MAXIMUM_MANIFEST_BYTES)
    standalone_payload = _regular_file(root, standalone_manifest, maximum_bytes=MAXIMUM_MANIFEST_BYTES)
    if package_payload != standalone_payload:
        raise ValueError("Weekly release manifest copies disagree before context packaging.")
    manifest = _json_object(package_payload, label="Weekly release manifest")
    if (
        manifest.get("schemaVersion") != 1
        or manifest.get("dataset") != "hecavex-radar-weekly-release"
        or manifest.get("tag") != tag
        or manifest.get("releaseWeek") != tag.removeprefix("radar-data-")
    ):
        raise ValueError("Weekly release manifest identity is invalid.")
    anchor = _timestamp(manifest.get("snapshotGeneratedAt"))
    if anchor is None:
        raise ValueError("Weekly release manifest has an invalid snapshot timestamp.")
    existing = _manifest_files(root, package_root, manifest)
    _verify_package_inventory(root, package_root, {cast(str, row["path"]) for row in existing})
    context_artifacts, summary = _history_files(
        root,
        anchor,
        allow_urlscan=allow_urlscan,
    )
    limits = cast(dict[str, object], manifest["limits"])
    maximum_files = cast(int, limits["maximumFiles"])
    maximum_bytes = cast(int, limits["maximumBytes"])
    context_rows = [row for row, _payload in context_artifacts]
    combined = sorted(existing + context_rows, key=lambda row: cast(str, row["path"]))
    combined_bytes = sum(cast(int, row["bytes"]) for row in combined)
    if len(combined) > maximum_files or combined_bytes > maximum_bytes:
        raise ValueError("Context history would exceed the weekly release global caps.")
    for row, payload in context_artifacts:
        relative = PurePosixPath(cast(str, row["path"]))
        destination = package_root.joinpath(*relative.parts)
        _reject_linklike_path(root, destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        _reject_linklike_path(root, destination)
        destination.write_bytes(payload)
    manifest["files"] = combined
    manifest["contextHistory"] = {
        "schemaVersion": 2,
        "dataset": "radar-context-change",
        "anchoredAt": cast(str, manifest["snapshotGeneratedAt"]),
        "retentionDays": MAXIMUM_PARTITIONS,
        "urlscanDerivedIncluded": allow_urlscan,
        "partitions": summary.partitions,
        "events": summary.events,
        "bytes": summary.bytes,
    }
    manifest_payload = (
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n"
    ).encode("utf-8")
    if len(manifest_payload) > MAXIMUM_MANIFEST_BYTES:
        raise ValueError("Weekly release manifest exceeds its byte limit after context packaging.")
    _atomic_write(package_manifest, manifest_payload)
    _atomic_write(standalone_manifest, manifest_payload)
    _verify_package_inventory(root, package_root, {cast(str, row["path"]) for row in combined})
    return summary


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Add bounded context history to a weekly Radar release.")
    parser.add_argument("--tag", required=True)
    return parser


def main(arguments: list[str] | None = None) -> int:
    options = _parser().parse_args(arguments)
    allow_urlscan = os.environ.get("URLSCAN_DERIVED_REDISTRIBUTION_CONFIRMED") == "true"
    try:
        summary = package_context_history(options.tag, allow_urlscan=allow_urlscan)
    except (OSError, ValueError) as error:
        print(f"Context history packaging failed: {error}")
        return 1
    print(
        "Added validated context history to the weekly release: "
        f"{summary.events} events in {summary.partitions} partitions."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
