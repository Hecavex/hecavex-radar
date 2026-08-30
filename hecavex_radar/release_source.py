"""Materialize a bounded, data-only release source from one Git commit."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path, PurePosixPath

SOURCE_SHA = re.compile(r"^[0-9a-f]{40}$")
ALLOWED_PREFIXES = ("public/data/", "data/history/context/")
MAXIMUM_FILES = 20_000
MAXIMUM_FILE_BYTES = 16 * 1024 * 1024
MAXIMUM_TOTAL_BYTES = 192 * 1024 * 1024


def _git(repository: Path, *arguments: str) -> bytes:
    git = shutil.which("git")
    if git is None:
        raise ValueError("Git is required to read the selected release source.")
    try:
        result = subprocess.run(  # noqa: S603 - fixed executable and argument vector, never a shell.
            [git, "-C", str(repository), *arguments],
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError as error:
        message = error.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(message or "Git could not read the requested release source.") from error
    return result.stdout


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(path))


def materialize_release_source(repository: Path, source_sha: str, output: Path) -> tuple[int, int]:
    """Copy only bounded publication data blobs from ``source_sha`` into ``output``."""

    repository = _absolute(repository)
    output = _absolute(output)
    if SOURCE_SHA.fullmatch(source_sha) is None:
        raise ValueError("Release source must be a full lowercase 40-character commit SHA.")
    if not repository.is_dir() or repository.is_symlink() or repository.is_junction():
        raise ValueError("Trusted release-tool repository is missing or linked.")
    if output.exists():
        raise ValueError("Release-source output must not already exist.")
    if output.parent.is_symlink() or output.parent.is_junction():
        raise ValueError("Release-source output parent must not be linked.")

    _git(repository, "cat-file", "-e", f"{source_sha}^{{commit}}")
    listing = _git(
        repository,
        "ls-tree",
        "-rlz",
        "--full-tree",
        source_sha,
        "--",
        "public/data",
        "data/history/context",
    )
    raw_entries = [entry for entry in listing.split(b"\0") if entry]
    if not raw_entries or len(raw_entries) > MAXIMUM_FILES:
        raise ValueError("Release source has an empty or oversized data-only inventory.")

    entries: list[tuple[str, str, int]] = []
    seen: set[str] = set()
    total_bytes = 0
    for raw_entry in raw_entries:
        try:
            metadata, raw_path = raw_entry.split(b"\t", 1)
            mode, object_type, object_id, raw_size = metadata.decode("ascii").split(" ", 3)
            path_text = raw_path.decode("utf-8")
            size = int(raw_size)
        except (UnicodeDecodeError, ValueError) as error:
            raise ValueError("Release source contains an unreadable Git tree entry.") from error
        relative = PurePosixPath(path_text)
        if (
            mode != "100644"
            or object_type != "blob"
            or not any(path_text.startswith(prefix) for prefix in ALLOWED_PREFIXES)
            or relative.is_absolute()
            or ".." in relative.parts
            or relative.as_posix() != path_text
            or path_text in seen
            or size < 0
            or size > MAXIMUM_FILE_BYTES
        ):
            raise ValueError(f"Release source contains an unsafe data entry: {path_text!r}.")
        seen.add(path_text)
        total_bytes += size
        if total_bytes > MAXIMUM_TOTAL_BYTES:
            raise ValueError("Release source exceeds its aggregate byte limit.")
        entries.append((path_text, object_id, size))

    if "public/data/feed-manifest.json" not in seen:
        raise ValueError("Release source is missing its feed manifest.")

    output.mkdir(parents=False)
    output_root = output.resolve(strict=True)
    for path_text, object_id, expected_size in sorted(entries):
        payload = _git(repository, "cat-file", "blob", object_id)
        if len(payload) != expected_size:
            raise ValueError(f"Release source blob size changed: {path_text}.")
        destination = output.joinpath(*PurePosixPath(path_text).parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        resolved_parent = destination.parent.resolve(strict=True)
        if not resolved_parent.is_relative_to(output_root):
            raise ValueError(f"Release source entry escapes its output root: {path_text}.")
        with destination.open("xb") as handle:
            handle.write(payload)
    return len(entries), total_bytes


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Materialize bounded historical release data.")
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--output", required=True, type=Path)
    return parser


def main(arguments: list[str] | None = None) -> int:
    options = _parser().parse_args(arguments)
    try:
        files, total_bytes = materialize_release_source(
            options.repository,
            options.source_sha,
            options.output,
        )
    except (OSError, ValueError) as error:
        print(f"Release-source materialization failed: {error}", file=sys.stderr)
        return 1
    print(f"Materialized {files} trusted data blobs ({total_bytes} bytes).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
