from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from hecavex_radar.release_source import materialize_release_source


def _git(repository: Path, *arguments: str, input_payload: bytes | None = None) -> str:
    git = shutil.which("git")
    assert git is not None
    result = subprocess.run(  # noqa: S603 - test helper uses a fixed executable without a shell.
        [git, "-C", str(repository), *arguments],
        input=input_payload,
        check=True,
        capture_output=True,
    )
    return result.stdout.decode("ascii").strip()


def _repository(root: Path) -> tuple[Path, str]:
    repository = root / "repository"
    repository.mkdir()
    _git(repository, "init", "--quiet")
    _git(repository, "config", "user.name", "Radar Test")
    _git(repository, "config", "user.email", "radar@example.invalid")
    manifest = repository / "public" / "data" / "feed-manifest.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(json.dumps({"generatedAt": "2026-08-26T12:00:00.000Z"}), encoding="utf-8")
    history = repository / "data" / "history" / "context" / "2026-08-26" / "events.ndjson"
    history.parent.mkdir(parents=True)
    history.write_text('{"eventId":"test"}\n', encoding="utf-8")
    historical_code = repository / "hecavex_radar" / "payload.py"
    historical_code.parent.mkdir()
    historical_code.write_text("raise RuntimeError('must never execute')\n", encoding="utf-8")
    _git(repository, "add", ".")
    _git(repository, "commit", "--quiet", "-m", "fixture")
    return repository, _git(repository, "rev-parse", "HEAD")


def test_materializer_copies_only_bounded_data_blobs(tmp_path: Path) -> None:
    repository, source_sha = _repository(tmp_path)
    output = tmp_path / "release-source"

    files, total_bytes = materialize_release_source(repository, source_sha, output)

    assert files == 2
    assert total_bytes > 0
    assert (output / "public/data/feed-manifest.json").is_file()
    assert (output / "data/history/context/2026-08-26/events.ndjson").is_file()
    assert not (output / "hecavex_radar").exists()


def test_materializer_rejects_a_link_in_the_data_tree(tmp_path: Path) -> None:
    repository, _ = _repository(tmp_path)
    object_id = _git(repository, "hash-object", "-w", "--stdin", input_payload=b"feed-manifest.json")
    _git(
        repository,
        "update-index",
        "--add",
        "--cacheinfo",
        f"120000,{object_id},public/data/linked-manifest.json",
    )
    _git(repository, "commit", "--quiet", "-m", "linked fixture")
    source_sha = _git(repository, "rev-parse", "HEAD")

    with pytest.raises(ValueError, match="unsafe data entry"):
        materialize_release_source(repository, source_sha, tmp_path / "release-source")


def test_materializer_requires_a_new_output_directory(tmp_path: Path) -> None:
    repository, source_sha = _repository(tmp_path)
    output = tmp_path / "release-source"
    output.mkdir()

    with pytest.raises(ValueError, match="must not already exist"):
        materialize_release_source(repository, source_sha, output)
