from __future__ import annotations

import json
import math
import os
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from .feeds import (
    fetch_hecavex,
    fetch_openphish,
    fetch_phishtank,
    fetch_vmray,
    load_certstream,
    skipped_sources,
)
from .models import FeedResult, RadarSignal, RadarSource
from .normalize import merge_signals, prepare_signal


def _enabled(value: str | None) -> bool:
    return bool(value and value.strip().lower() == "true")


def _enabled_by_default(value: str | None) -> bool:
    return value is None or _enabled(value)


def _bounded_integer(value: str | None, fallback: int, minimum: int, maximum: int) -> int:
    if not value or not value.strip():
        return fallback
    try:
        parsed = int(value)
    except ValueError:
        return fallback
    return min(maximum, max(minimum, parsed))


def _output_path() -> Path:
    repository = Path.cwd().resolve()
    target = (repository / os.environ.get("RADAR_OUTPUT", "public/data/radar.json")).resolve()
    if target == repository or not target.is_relative_to(repository):
        raise ValueError("RADAR_OUTPUT must stay inside the repository.")
    return target


def _existing_signal_count(target: Path) -> int | None:
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return None
    if (
        not isinstance(payload, dict)
        or payload.get("schemaVersion") != 1
        or payload.get("dataset") != "live"
        or not isinstance(payload.get("signals"), list)
    ):
        return None
    return len(payload["signals"])


def _validate_snapshot_size(count: int, target: Path) -> None:
    if _enabled(os.environ.get("RADAR_ALLOW_SMALL_SNAPSHOT")):
        return
    minimum = _bounded_integer(os.environ.get("RADAR_MIN_SIGNALS"), 1, 0, 25_000)
    retained_percent = _bounded_integer(os.environ.get("RADAR_MIN_RETAINED_PERCENT"), 25, 0, 100)
    previous = _existing_signal_count(target)
    required = max(minimum, math.ceil(previous * retained_percent / 100) if previous is not None else 0)
    if count < required:
        previous_note = f"; previous live snapshot contains {previous}" if previous is not None else ""
        raise RuntimeError(
            f"Refusing to publish {count} signals because at least {required} are required{previous_note}. "
            "Set RADAR_ALLOW_SMALL_SNAPSHOT=true only for an intentional reset."
        )


def _run_feed(label: str, operation: Callable[[], FeedResult]) -> FeedResult | None:
    try:
        result = operation()
        print(f"{label}: {len(result.signals)} records", flush=True)
        return result
    except Exception as error:
        message = str(error).splitlines()[0] if str(error) else type(error).__name__
        print(f"{label}: unavailable ({message})", file=sys.stderr, flush=True)
        return None


def synchronize() -> Path:
    now = datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    results: list[FeedResult] = []
    source_states = skipped_sources()
    attempted_sources: set[str] = set()

    phishtank_key = os.environ.get("PHISHTANK_APP_KEY", "").strip() or None
    phishtank_enabled = bool(phishtank_key or _enabled(os.environ.get("PHISHTANK_ENABLED")))
    if phishtank_enabled and _enabled(os.environ.get("PHISHTANK_REQUIRE_APP_KEY")) and not phishtank_key:
        raise RuntimeError("PHISHTANK_APP_KEY is required for scheduled automated downloads.")
    if phishtank_enabled:
        attempted_sources.add("PhishTank")
        user_agent = (
            os.environ.get("PHISHTANK_USER_AGENT", "").strip() or "hecavex-radar/0.1 (+https://radar.hecavex.com)"
        )
        result = _run_feed("PhishTank", lambda: fetch_phishtank(now, phishtank_key, user_agent))
        if result:
            results.append(result)

    if _enabled(os.environ.get("OPENPHISH_ENABLED")):
        if not _enabled(os.environ.get("OPENPHISH_ACCEPT_TERMS")):
            next(source for source in source_states if source["name"] == "OpenPhish")["note"] = "Terms not accepted"
        else:
            attempted_sources.add("OpenPhish")
            result = _run_feed("OpenPhish", lambda: fetch_openphish(now))
            if result:
                results.append(result)

    if _enabled_by_default(os.environ.get("CERTSTREAM_ARCHIVE_ENABLED")):
        attempted_sources.add("CertStream")
        lookback_days = _bounded_integer(os.environ.get("RADAR_CT_LOOKBACK_DAYS"), 7, 1, 90)
        archive_root = os.environ.get("CERTSTREAM_ARCHIVE_ROOT", "").strip() or "data/candidates"
        result = _run_feed("CertStream", lambda: load_certstream(now, archive_root, lookback_days))
        if result:
            results.append(result)

    if _enabled(os.environ.get("VMRAY_ENABLED")):
        if not _enabled(os.environ.get("VMRAY_ACCEPT_TERMS")):
            next(source for source in source_states if source["name"] == "VMRay")["note"] = "Terms not accepted"
        else:
            attempted_sources.add("VMRay")
            pages = _bounded_integer(os.environ.get("VMRAY_PAGES"), 1, 1, 5)
            result = _run_feed("VMRay", lambda: fetch_vmray(now, pages))
            if result:
                results.append(result)

    hecavex_url = os.environ.get("HECAVEX_FEED_URL", "").strip()
    if hecavex_url:
        attempted_sources.add("HECAVEX")
        result = _run_feed("HECAVEX", lambda: fetch_hecavex(now, hecavex_url, os.environ.get("HECAVEX_FEED_TOKEN")))
        if result:
            results.append(result)

    if not results:
        raise RuntimeError("No feed completed. Configure at least one source before running the synchronizer.")

    screenshot_hosts = [
        host.strip().lower()
        for host in os.environ.get("RADAR_SCREENSHOT_HOSTS", "urlscan.io").split(",")
        if host.strip()
    ]
    prepared: list[RadarSignal] = []
    for result in results:
        for raw_signal in result.signals:
            signal = prepare_signal(raw_signal, now, screenshot_hosts)
            if signal:
                prepared.append(signal)

    sources: list[RadarSource] = []
    for source in source_states:
        completed = next((result for result in results if result.source["name"] == source["name"]), None)
        if completed:
            sources.append(completed.source)
        elif source["name"] in attempted_sources:
            sources.append(
                {
                    **source,
                    "fetchedAt": now,
                    "state": "partial",
                    "note": "Unavailable during this sync",
                }
            )
        else:
            sources.append(source)

    maximum = _bounded_integer(os.environ.get("RADAR_MAX_SIGNALS"), 2500, 1, 25_000)
    merged = merge_signals(prepared, maximum)
    target = _output_path()
    _validate_snapshot_size(len(merged), target)
    snapshot = {
        "schemaVersion": 1,
        "dataset": "live",
        "generatedAt": now,
        "signals": merged,
        "sources": sources,
    }
    temporary = target.with_name(f"{target.name}.tmp")
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    os.replace(temporary, target)
    print(f"Published {len(merged)} defanged signals to {target.relative_to(Path.cwd())}.", flush=True)
    return target


def main() -> int:
    try:
        synchronize()
        return 0
    except Exception as error:
        print(f"Sync failed: {error}", file=sys.stderr)
        return 1


def run() -> None:
    raise SystemExit(main())


if __name__ == "__main__":
    run()
