from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, TypedDict, cast

from .models import RadarSignal, RawSignal
from .normalize import merge_signals, prepare_signal

MAXIMUM_EXPORT_SIGNALS = 2_500
MAXIMUM_EXPORT_BYTES = 20 * 1024 * 1024
MAXIMUM_SNAPSHOT_BYTES = 512 * 1024
BACKING_SOURCES = frozenset({"CertStream", "URLScan"})
ALLOWED_INPUT_SOURCES = BACKING_SOURCES | {"HECAVEX"}


class HecavexCandidateExport(TypedDict):
    schemaVersion: Literal[1]
    dataset: Literal["hecavex-candidates"]
    generatedAt: str
    disposition: Literal["potential"]
    signals: list[RadarSignal]


def _timestamp(value: datetime) -> str:
    aware = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    return aware.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _string(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _number(value: object) -> float | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            return float(value)
        except OverflowError:
            return None
    return None


def _strings(value: object) -> list[str] | None:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        return None
    return list(value)


def _candidate(signal: RadarSignal, now: str) -> RadarSignal | None:
    raw_sources = _strings(signal.get("sources"))
    if not raw_sources:
        return None
    sources = set(raw_sources)
    if not sources.issubset(ALLOWED_INPUT_SOURCES):
        return None
    backing = sorted(sources & BACKING_SOURCES)
    if not backing:
        return None

    url = _string(signal.get("url"))
    if not url:
        return None
    raw_hashes = _strings(signal.get("hashes"))
    prepared = prepare_signal(
        RawSignal(
            url=url,
            source=backing[0],
            first_seen=_string(signal.get("firstSeen")),
            last_seen=_string(signal.get("lastSeen")),
            status=_string(signal.get("status")),
            brand=_string(signal.get("brand")),
            country=_string(signal.get("country")),
            host=_string(signal.get("host")),
            screenshot_url=_string(signal.get("screenshotUrl")),
            reference_url=_string(signal.get("referenceUrl")),
            hashes=raw_hashes,
            confidence=_number(signal.get("confidence")),
        ),
        now,
    )
    if prepared is None:
        return None
    prepared["sources"] = backing
    return prepared


def _encoded(payload: HecavexCandidateExport) -> bytes:
    return (
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _fit_size(payload: HecavexCandidateExport) -> HecavexCandidateExport:
    if len(_encoded(payload)) <= MAXIMUM_EXPORT_BYTES:
        return payload

    signals = payload["signals"]
    lower = 0
    upper = len(signals)
    while lower < upper:
        middle = (lower + upper + 1) // 2
        candidate: HecavexCandidateExport = {**payload, "signals": signals[:middle]}
        if len(_encoded(candidate)) <= MAXIMUM_EXPORT_BYTES:
            lower = middle
        else:
            upper = middle - 1

    bounded: HecavexCandidateExport = {**payload, "signals": signals[:lower]}
    if len(_encoded(bounded)) > MAXIMUM_EXPORT_BYTES:
        raise ValueError("HECAVEX candidate export metadata exceeds the 20 MiB limit.")
    return bounded


def build_hecavex_candidates(
    signals: list[RadarSignal],
    generated_at: datetime | None = None,
) -> HecavexCandidateExport:
    timestamp = _timestamp(generated_at or datetime.now(UTC))
    candidates = [candidate for signal in signals if (candidate := _candidate(signal, timestamp))]
    payload: HecavexCandidateExport = {
        "schemaVersion": 1,
        "dataset": "hecavex-candidates",
        "generatedAt": timestamp,
        "disposition": "potential",
        "signals": merge_signals(candidates, MAXIMUM_EXPORT_SIGNALS),
    }
    return _fit_size(payload)


def _bounded_output_path(value: str | Path) -> Path:
    repository = Path.cwd().resolve()
    ignored_root = (repository / "data" / "hecavex").resolve()
    requested = Path(value)
    target = (requested if requested.is_absolute() else repository / requested).resolve()
    if target == ignored_root or not target.is_relative_to(ignored_root):
        raise ValueError("HECAVEX candidate export path must stay inside data/hecavex/.")
    return target


def write_hecavex_candidates(
    output: str | Path,
    signals: list[RadarSignal],
    generated_at: datetime | None = None,
) -> Path:
    """Atomically write a local, defanged candidate handoff with no network side effects."""
    target = _bounded_output_path(output)
    body = _encoded(build_hecavex_candidates(signals, generated_at))
    if len(body) > MAXIMUM_EXPORT_BYTES:
        raise ValueError("HECAVEX candidate export exceeds the 20 MiB limit.")

    target.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=target.parent,
            prefix=f".{target.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(0o600)
        os.replace(temporary, target)
    except Exception:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise
    return target


def _snapshot_path(value: str | Path) -> Path:
    repository = Path.cwd().resolve()
    allowed = (repository / "public" / "data").resolve()
    requested = Path(value)
    target = (requested if requested.is_absolute() else repository / requested).resolve()
    if target == allowed or not target.is_relative_to(allowed):
        raise ValueError("Radar snapshot input must stay below public/data/.")
    return target


def read_snapshot_signals(value: str | Path) -> list[RadarSignal]:
    path = _snapshot_path(value)
    try:
        if path.stat().st_size > MAXIMUM_SNAPSHOT_BYTES:
            raise ValueError("Radar snapshot exceeds 512 KiB.")
        payload: object = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise ValueError(f"Radar snapshot does not exist: {path}") from error
    except json.JSONDecodeError as error:
        raise ValueError("Radar snapshot is invalid JSON.") from error
    if (
        not isinstance(payload, dict)
        or payload.get("schemaVersion") != 2
        or payload.get("dataset") != "live"
        or not isinstance(payload.get("signals"), list)
        or len(payload["signals"]) > 25_000
        or not all(isinstance(signal, dict) for signal in payload["signals"])
    ):
        raise ValueError("Radar snapshot does not match the live snapshot boundary.")
    return cast(list[RadarSignal], payload["signals"])


def export_snapshot_handoff(
    snapshot: str | Path = "public/data/radar.json",
    output: str | Path = "data/hecavex/pivot-candidates.json",
) -> Path:
    """Create the private, git-ignored analyst handoff from a local public snapshot."""

    return write_hecavex_candidates(output, read_snapshot_signals(snapshot))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="hecavex-handoff",
        description="Export passive Radar candidates to the private git-ignored analyst handoff.",
    )
    parser.add_argument("--input", default="public/data/radar.json", help="Live snapshot below public/data/.")
    parser.add_argument(
        "--output",
        default="data/hecavex/pivot-candidates.json",
        help="Private output below the git-ignored data/hecavex/ boundary.",
    )
    args = parser.parse_args(argv)
    try:
        target = export_snapshot_handoff(args.input, args.output)
        payload = json.loads(target.read_text(encoding="utf-8"))
        print(f"Prepared {len(payload['signals'])} defanged pivot candidates at {target}.")
        return 0
    except (OSError, ValueError) as error:
        print(f"Candidate handoff failed: {error}", file=sys.stderr)
        return 1


def run() -> None:
    raise SystemExit(main())


if __name__ == "__main__":
    run()
