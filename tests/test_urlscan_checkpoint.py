from __future__ import annotations

import copy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from hecavex_radar import urlscan_checkpoint
from hecavex_radar.urlscan import _BudgetedRequester
from hecavex_radar.urlscan_checkpoint import SearchCheckpointStore, SearchUnavailable, _sort_token

QUERY = "task.visibility:public AND date:>now-7d AND domain:example"


def _result(number: int) -> dict[str, object]:
    identifier = f"00000000-0000-0000-0000-{number:012x}"
    return {
        "_id": identifier,
        "sort": [number],
        "task": {"uuid": identifier, "visibility": "public"},
    }


class _PagedProvider:
    def __init__(self) -> None:
        self.starts: list[int] = []

    def __call__(self, url: str, _key: str) -> dict[str, object]:
        query = parse_qs(urlsplit(url).query)
        size = int(query["size"][0])
        after = int(query.get("search_after", ["-1"])[0])
        start = after + 1
        self.starts.append(start)
        return {
            "results": [_result(index) for index in range(start, min(start + size, 250))],
            # URLScan's has_more flag is about its 10k search ceiling, not
            # ordinary page continuation. Pagination must still continue.
            "has_more": False,
            "total": 250,
        }


def test_total_drives_multi_run_backlog_when_has_more_is_false(
    tmp_path: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    path = "data/urlscan/search-checkpoints.json"
    provider = _PagedProvider()
    start = datetime(2026, 8, 26, 10, tzinfo=UTC)

    first = SearchCheckpointStore.load(path, now=start)
    assert len(first.search(QUERY, 100, "unused", provider, backlog_pages=1)) == 100
    row = next(iter(first.state["queries"].values()))
    assert row["nextSearchAfter"] == [99]
    assert row["complete"] is False
    first.commit()

    second = SearchCheckpointStore.load(path, now=start + timedelta(hours=1))
    assert len(second.search(QUERY, 100, "unused", provider, backlog_pages=1)) == 200
    row = next(iter(second.state["queries"].values()))
    assert row["nextSearchAfter"] == [199]
    assert row["backlogResultsSeen"] == 200
    assert row["complete"] is False
    second.commit()

    third = SearchCheckpointStore.load(path, now=start + timedelta(hours=2))
    assert len(third.search(QUERY, 100, "unused", provider, backlog_pages=1)) == 150
    row = next(iter(third.state["queries"].values()))
    assert row["nextSearchAfter"] is None
    assert row["backlogResultsSeen"] == 250
    assert row["complete"] is True
    assert provider.starts == [0, 0, 100, 0, 200]


def test_unperformed_search_does_not_mutate_or_complete_checkpoint(
    tmp_path: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    path = "data/urlscan/search-checkpoints.json"
    now = datetime(2026, 8, 26, 10, tzinfo=UTC)
    store = SearchCheckpointStore.load(path, now=now)
    store.search(QUERY, 100, "unused", _PagedProvider(), backlog_pages=1)
    store.commit()

    interrupted = SearchCheckpointStore.load(path, now=now + timedelta(hours=1))
    before = copy.deepcopy(interrupted.state)

    def unavailable(_url: str, _key: str) -> object:
        raise SearchUnavailable("budget exhausted")

    assert interrupted.search(QUERY, 100, "unused", unavailable, backlog_pages=1) == []
    assert interrupted.state == before
    assert interrupted.dirty is False


def test_budgeted_requester_uses_explicit_search_exhaustion_signal() -> None:
    requester = _BudgetedRequester(
        lambda _url, _key: pytest.fail("provider must not be called"),
        search_used=1,
        result_used=0,
        daily_search_cap=1,
        daily_result_cap=10,
        run_search_cap=10,
        run_result_cap=10,
    )
    with pytest.raises(SearchUnavailable):
        requester("https://urlscan.io/api/v1/search/?q=test", "unused")
    assert requester.exhausted is True


@pytest.mark.parametrize(
    "token",
    [
        [float("nan")],
        [float("inf")],
        [float("-inf")],
        ["2026-08-26,10:00:00"],
        ["2026-08-26\n10:00:00"],
        ["2026-08-26\t10:00:00"],
    ],
)
def test_search_after_rejects_nonfinite_or_unsafe_components(token: list[object]) -> None:
    assert _sort_token(token) is None


def test_search_after_accepts_conservative_provider_components() -> None:
    assert _sort_token([1724666400000, "2026-08-26T10:00:00.000Z", 1.25]) == [
        1724666400000,
        "2026-08-26T10:00:00.000Z",
        1.25,
    ]


def _directory_symlink_or_skip(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=True)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"directory symlinks are unavailable: {error}")


def _file_symlink_or_skip(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"file symlinks are unavailable: {error}")


def test_checkpoint_rejects_symlinked_repository_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_root = tmp_path / "real-root"
    real_root.mkdir()
    linked_root = tmp_path / "linked-root"
    _directory_symlink_or_skip(linked_root, real_root)
    monkeypatch.setattr(urlscan_checkpoint.os, "getcwd", lambda: str(linked_root))

    with pytest.raises(ValueError, match="repository root"):
        urlscan_checkpoint._bounded_path("data/urlscan/search-checkpoints.json")


def test_checkpoint_rejects_symlinked_allowed_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "data").mkdir()
    external_directory = tmp_path / "outside-urlscan"
    external_directory.mkdir()
    _directory_symlink_or_skip(tmp_path / "data/urlscan", external_directory)

    with pytest.raises(ValueError, match="symlinked path component"):
        SearchCheckpointStore.load("data/urlscan/search-checkpoints.json", now=datetime.now(UTC))


def test_checkpoint_commit_rejects_target_replaced_with_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    store = SearchCheckpointStore.load("data/urlscan/search-checkpoints.json", now=datetime.now(UTC))
    target = tmp_path / "data/urlscan/search-checkpoints.json"
    target.parent.mkdir(parents=True)
    external_file = tmp_path / "outside-checkpoint.json"
    external_file.write_text("do not touch\n", encoding="utf-8")
    _file_symlink_or_skip(target, external_file)

    with pytest.raises(ValueError, match="symlinked path component"):
        store.commit()
    assert external_file.read_text(encoding="utf-8") == "do not touch\n"
