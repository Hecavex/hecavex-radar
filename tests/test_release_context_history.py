from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from hecavex_radar import release_context_history
from hecavex_radar.passive_context import DNS_REFERENCE, URLSCAN_REFERENCE, _event
from hecavex_radar.release_context_history import package_context_history
from hecavex_radar.safety import stable_id

TAG = "radar-data-2026-W35"
ANCHOR = "2026-08-26T12:00:00.000Z"
PARTITION = "2026-08-26"
DOMAIN = "login[.]example"
SIGNAL_ID = stable_id(DOMAIN.lower())


def _dns_event() -> dict[str, object]:
    before: dict[str, object] = {"a": [], "aaaa": [], "cname": [], "ns": [], "mx": []}
    after: dict[str, object] = {
        "a": ["192[.]0[.]2[.]10"],
        "aaaa": [],
        "cname": [],
        "ns": [],
        "mx": [],
    }
    return _event(
        SIGNAL_ID,
        DOMAIN,
        "2026-08-26T10:00:00.000Z",
        "dns",
        "first-resolving",
        ["a"],
        "2026-08-26T10:00:00.000Z",
        DNS_REFERENCE,
        before,
        after,
    )


def _urlscan_event() -> dict[str, object]:
    return _event(
        SIGNAL_ID,
        DOMAIN,
        "2026-08-26T11:00:00.000Z",
        "urlscan",
        "urlscan-title-changed",
        ["pageTitle"],
        "2026-08-26T10:55:00.000Z",
        URLSCAN_REFERENCE,
        {"pageTitle": "Old title"},
        {"pageTitle": "New title"},
    )


def _encoded_rows(rows: list[dict[str, object]]) -> bytes:
    return b"".join(
        (json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        for row in rows
    )


def _fixture(
    root: Path,
    rows: list[dict[str, object]] | None = None,
    *,
    limits: dict[str, int] | None = None,
) -> dict[str, Path]:
    package_root = root / "_release" / "stage" / TAG
    assets_root = root / "_release" / "assets"
    journal = root / "data" / "history" / "context" / PARTITION / "events.ndjson"
    package_root.joinpath("data").mkdir(parents=True)
    assets_root.mkdir(parents=True)
    journal.parent.mkdir(parents=True)
    publication = b'{"dataset":"test"}\n'
    publication_path = package_root / "data" / "radar.json"
    publication_path.write_bytes(publication)
    manifest: dict[str, Any] = {
        "schemaVersion": 1,
        "dataset": "hecavex-radar-weekly-release",
        "releaseWeek": "2026-W35",
        "tag": TAG,
        "sourceRepository": "Hecavex/hecavex-radar",
        "sourceCommit": "a" * 40,
        "snapshotGeneratedAt": ANCHOR,
        "archiveRoot": TAG,
        "limits": limits or {"maximumFiles": 10_000, "maximumBytes": 128 * 1024 * 1024},
        "files": [
            {
                "path": "data/radar.json",
                "bytes": len(publication),
                "sha256": hashlib.sha256(publication).hexdigest(),
            }
        ],
    }
    manifest_payload = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    package_manifest = package_root / "RELEASE-MANIFEST.json"
    standalone_manifest = assets_root / f"{TAG}.manifest.json"
    package_manifest.write_bytes(manifest_payload)
    standalone_manifest.write_bytes(manifest_payload)
    journal.write_bytes(_encoded_rows(rows if rows is not None else [_dns_event()]))
    return {
        "package": package_root,
        "journal": journal,
        "package_manifest": package_manifest,
        "standalone_manifest": standalone_manifest,
    }


def _published_rows(paths: dict[str, Path]) -> list[dict[str, object]]:
    output = paths["package"] / "history" / "context" / PARTITION / "events.ndjson"
    return [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]


def test_release_history_is_deterministic_and_inventory_hashes_match(tmp_path: Path) -> None:
    first = _fixture(tmp_path / "one", [_urlscan_event(), _dns_event()])
    second = _fixture(tmp_path / "two", [_urlscan_event(), _dns_event()])

    first_summary = package_context_history(TAG, repository=tmp_path / "one", allow_urlscan=True)
    second_summary = package_context_history(TAG, repository=tmp_path / "two", allow_urlscan=True)

    assert first_summary == second_summary
    assert first_summary.events == 2
    first_output = first["package"] / "history" / "context" / PARTITION / "events.ndjson"
    second_output = second["package"] / "history" / "context" / PARTITION / "events.ndjson"
    assert first_output.read_bytes() == second_output.read_bytes()
    assert first["package_manifest"].read_bytes() == second["package_manifest"].read_bytes()
    manifest = json.loads(first["package_manifest"].read_text(encoding="utf-8"))
    assert first["package_manifest"].read_bytes() == first["standalone_manifest"].read_bytes()
    assert manifest["contextHistory"] == {
        "anchoredAt": ANCHOR,
        "bytes": first_output.stat().st_size,
        "dataset": "radar-context-change",
        "events": 2,
        "partitions": 1,
        "retentionDays": 90,
        "schemaVersion": 2,
        "urlscanDerivedIncluded": True,
    }
    inventory = {row["path"]: row for row in manifest["files"]}
    row = inventory[f"history/context/{PARTITION}/events.ndjson"]
    assert row["bytes"] == first_output.stat().st_size
    assert row["sha256"] == hashlib.sha256(first_output.read_bytes()).hexdigest()


def test_urlscan_history_is_excluded_without_explicit_permission(tmp_path: Path) -> None:
    paths = _fixture(tmp_path, [_urlscan_event(), _dns_event()])

    summary = package_context_history(TAG, repository=tmp_path, allow_urlscan=False)

    assert summary.events == 1
    assert [row["component"] for row in _published_rows(paths)] == ["dns"]
    manifest = json.loads(paths["package_manifest"].read_text(encoding="utf-8"))
    assert manifest["contextHistory"]["urlscanDerivedIncluded"] is False


@pytest.mark.parametrize("failure", ["malformed", "blank", "hash"])
def test_malformed_or_tampered_history_is_rejected(tmp_path: Path, failure: str) -> None:
    event = _dns_event()
    paths = _fixture(tmp_path, [event])
    if failure == "malformed":
        paths["journal"].write_bytes(b"{not-json}\n")
    elif failure == "blank":
        paths["journal"].write_bytes(_encoded_rows([event]) + b"\n")
    else:
        event["currentHash"] = "0" * 64
        paths["journal"].write_bytes(_encoded_rows([event]))

    with pytest.raises(ValueError, match="malformed|blank or oversized|event contract"):
        package_context_history(TAG, repository=tmp_path)


def test_duplicate_event_ids_are_rejected(tmp_path: Path) -> None:
    event = _dns_event()
    _fixture(tmp_path, [event, event])

    with pytest.raises(ValueError, match="duplicate event ID"):
        package_context_history(TAG, repository=tmp_path)


def _symlink_or_skip(target: Path, link: Path, *, target_is_directory: bool) -> None:
    try:
        link.symlink_to(target, target_is_directory=target_is_directory)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"Filesystem symlink creation is unavailable: {error}")


@pytest.mark.parametrize("kind", ["root", "partition", "file"])
def test_linked_history_roots_partitions_and_files_are_rejected(tmp_path: Path, kind: str) -> None:
    paths = _fixture(tmp_path, [_dns_event()])
    context = tmp_path / "data" / "history" / "context"
    partition = context / PARTITION
    external = tmp_path / "external"
    external.mkdir()
    if kind == "root":
        paths["journal"].unlink()
        partition.rmdir()
        context.rmdir()
        external_partition = external / PARTITION
        external_partition.mkdir()
        (external_partition / "events.ndjson").write_bytes(_encoded_rows([_dns_event()]))
        _symlink_or_skip(external, context, target_is_directory=True)
    elif kind == "partition":
        paths["journal"].unlink()
        partition.rmdir()
        external_partition = external / PARTITION
        external_partition.mkdir()
        (external_partition / "events.ndjson").write_bytes(_encoded_rows([_dns_event()]))
        _symlink_or_skip(external_partition, partition, target_is_directory=True)
    else:
        paths["journal"].unlink()
        external_file = external / "events.ndjson"
        external_file.write_bytes(_encoded_rows([_dns_event()]))
        _symlink_or_skip(external_file, paths["journal"], target_is_directory=False)

    with pytest.raises(ValueError, match="linked path component"):
        package_context_history(TAG, repository=tmp_path)


def test_partition_and_global_release_bounds_are_enforced(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _fixture(
        tmp_path,
        [_dns_event()],
        limits={"maximumFiles": 1, "maximumBytes": 128 * 1024 * 1024},
    )
    with pytest.raises(ValueError, match="global caps"):
        package_context_history(TAG, repository=tmp_path)
    assert not (paths["package"] / "history").exists()

    other = tmp_path / "other"
    other_paths = _fixture(other, [_dns_event()])
    monkeypatch.setattr(release_context_history, "MAXIMUM_PARTITION_BYTES", 16)
    with pytest.raises(ValueError, match="byte limit"):
        package_context_history(TAG, repository=other)
    assert not (other_paths["package"] / "history").exists()


def test_package_inventory_drift_is_rejected(tmp_path: Path) -> None:
    paths = _fixture(tmp_path, [_dns_event()])
    unexpected = paths["package"] / "data" / "unexpected.json"
    unexpected.write_text("{}\n", encoding="utf-8")

    with pytest.raises(ValueError, match="inventory"):
        package_context_history(TAG, repository=tmp_path)
