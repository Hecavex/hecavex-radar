from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from .brands import load_brand_registry
from .coverage_ledger import build_brand_coverage, read_bounded_json, read_recent_certstream_candidates
from .review_queue import build_review_queue


def _render(value: dict[str, object]) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2) + "\n"


def _canonical_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00").astimezone(UTC)
    except ValueError:
        return None
    canonical = parsed.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return parsed if canonical == value else None


def generate_quality_artifacts(root: Path, *, check: bool) -> None:
    snapshot = read_bounded_json(root / "public/data/radar.json", 512 * 1024)
    reviews = read_bounded_json(root / "data/review/public-decisions.json", 2 * 1024 * 1024)
    ct_state = read_bounded_json(root / "data/ct-search/state.json", 8 * 1024 * 1024)
    asset_state = read_bounded_json(root / "data/urlscan/official-brand-assets.json", 8 * 1024 * 1024)
    hunt_state = read_bounded_json(root / "data/urlscan/hunt-state.json", 2 * 1024 * 1024)
    snapshot_timestamp = _canonical_timestamp(snapshot.get("generatedAt"))
    if snapshot_timestamp is None:
        raise ValueError("The public Radar snapshot has no canonical generatedAt timestamp.")
    source_timestamps = [snapshot_timestamp]
    source_timestamps.extend(
        parsed
        for value in (
            reviews.get("generatedAt"),
            ct_state.get("generatedAt"),
            asset_state.get("generatedAt"),
            hunt_state.get("generatedAt"),
        )
        if (parsed := _canonical_timestamp(value)) is not None
    )
    generated_at = max(source_timestamps).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    matcher_corpus = read_bounded_json(root / "data/matcher/lithuanian-brands-v1.json", 2 * 1024 * 1024)
    artifacts = {
        root / "data/review/review-queue.json": build_review_queue(
            snapshot,
            reviews,
            generated_at=generated_at,
        ),
        root / "data/coverage/brand-coverage.json": build_brand_coverage(
            load_brand_registry(root / "data/brands-lt.json"),
            ct_state=ct_state,
            certstream_candidates=read_recent_certstream_candidates(root / "data/certstream", generated_at),
            asset_state=asset_state,
            hunt_state=hunt_state,
            review_export=reviews,
            matcher_corpus=matcher_corpus,
            generated_at=generated_at,
        ),
    }
    stale: list[str] = []
    for path, artifact in artifacts.items():
        expected = _render(artifact)
        if check:
            if not path.is_file() or path.read_text(encoding="utf-8") != expected:
                stale.append(path.relative_to(root).as_posix())
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(expected, encoding="utf-8")
    if stale:
        raise ValueError(f"Quality artifacts are missing or stale: {', '.join(stale)}")
    action = "Verified" if check else "Wrote"
    print(f"{action} {len(artifacts)} deterministic quality artifacts.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate or verify deterministic Radar quality artifacts.")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--check", action="store_true")
    options = parser.parse_args(argv)
    generate_quality_artifacts(cast(Path, options.root).resolve(), check=cast(bool, options.check))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
