from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from http.client import HTTPMessage
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from pytest import MonkeyPatch, raises

from hecavex_radar import urlscan
from hecavex_radar.brands import load_brand_registry

NOW = datetime(2026, 8, 21, 10, tzinfo=UTC)
UUID = "11111111-1111-1111-1111-111111111111"


def test_hunt_seed_inputs_use_an_exact_rolling_window_and_public_snapshot(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    registry_path = Path(__file__).parents[1] / "data" / "brands-lt.json"
    registry = load_brand_registry(registry_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("URLSCAN_RADAR_SEEDS_ENABLED", "true")
    monkeypatch.setenv("URLSCAN_RADAR_SNAPSHOT", "public/data/radar.json")
    monkeypatch.setenv("URLSCAN_CT_SEEDS_ENABLED", "true")
    monkeypatch.setenv("URLSCAN_INTELLIGENCE_SEEDS_ENABLED", "false")
    monkeypatch.setenv("URLSCAN_LOOKBACK_DAYS", "7")
    monkeypatch.setenv("URLSCAN_CT_LOOKBACK_DAYS", "7")

    def candidate(domain: str, observed: datetime) -> dict[str, object]:
        return {"domain": domain.replace(".", "[.]"), "observedAt": urlscan._timestamp(observed)}

    monkeypatch.setattr(
        urlscan,
        "read_recent_candidates",
        lambda *_args, **_kwargs: [
            candidate("secure-swedbank-cutoff.example", NOW - timedelta(days=7)),
            candidate("secure-swedbank-old.example", NOW - timedelta(days=7, milliseconds=1)),
            candidate("secure-swedbank-near.example", NOW + timedelta(minutes=5)),
            candidate("secure-swedbank-future.example", NOW + timedelta(minutes=5, milliseconds=1)),
        ],
    )
    snapshot = tmp_path / "public" / "data" / "radar.json"
    snapshot.parent.mkdir(parents=True)
    snapshot.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "dataset": "live",
                "generatedAt": urlscan._timestamp(NOW),
                "signals": [
                    {
                        "domain": "secure-swedbank-radar[.]example",
                        "brand": "Swedbank",
                        "confidence": 90,
                        "lastSeen": urlscan._timestamp(NOW - timedelta(hours=1)),
                    },
                    {
                        "domain": "secure-swedbank-stale[.]example",
                        "brand": "Swedbank",
                        "confidence": 90,
                        "lastSeen": urlscan._timestamp(NOW - timedelta(days=8)),
                    },
                    {
                        "domain": "swedbank[.]lt",
                        "brand": "Swedbank",
                        "confidence": 100,
                        "lastSeen": urlscan._timestamp(NOW),
                    },
                    {
                        "domain": "secure-swedbank-conflict[.]example",
                        "brand": "Revolut",
                        "confidence": 90,
                        "lastSeen": urlscan._timestamp(NOW),
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    seeds = urlscan._load_hunt_seeds(registry, NOW)

    assert {seed.domain for seed in seeds} == {
        "secure-swedbank-cutoff.example",
        "secure-swedbank-near.example",
        "secure-swedbank-radar.example",
    }
    assert seeds == sorted(seeds, key=lambda seed: (-seed.confidence, seed.domain, seed.brand))


def test_radar_snapshot_seed_path_cannot_escape_the_repository(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    registry_path = Path(__file__).parents[1] / "data" / "brands-lt.json"
    registry = load_brand_registry(registry_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("URLSCAN_RADAR_SEEDS_ENABLED", "true")
    monkeypatch.setenv("URLSCAN_RADAR_SNAPSHOT", "../radar.json")

    with raises(ValueError, match="inside the repository"):
        urlscan._load_radar_snapshot_seeds(registry, NOW, 7)


def test_rotating_seed_window_is_deterministic_bounded_and_complete() -> None:
    seeds = [urlscan._HuntSeed(f"candidate-{index}.example", "Swedbank", 90) for index in range(12)]
    cursor = 0
    observed: list[str] = []

    for _run in range(12):
        selected, cursor = urlscan._rotating_seed_window(seeds, cursor, 12, 50)
        assert len(selected) == 1
        observed.append(selected[0].domain)

    assert observed == [seed.domain for seed in seeds]
    assert cursor == 0
    assert urlscan._rotating_seed_window([], 20, 12, 50) == ([], 0)
    assert urlscan._rotating_seed_window(seeds, 13, 12, 50)[0] == [seeds[1]]


def test_hunt_progress_queries_only_the_current_seed_shard(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv("URLSCAN_TITLE_DETAIL_LIMIT", "0")
    monkeypatch.setenv("URLSCAN_HASH_PIVOT_LIMIT", "0")
    seeds = [urlscan._HuntSeed(f"secure-swedbank-{index}.example", "Swedbank", 90) for index in range(12)]
    monkeypatch.setattr(urlscan, "_load_hunt_seeds", lambda *_args: seeds)
    exact_queries: list[str] = []

    def requester(request_url: str, _api_key: str) -> object:
        parsed = urlsplit(request_url)
        if parsed.path == "/api/v1/search/":
            query = parse_qs(parsed.query)["q"][0]
            if 'task.domain.keyword:"secure-swedbank-' in query:
                exact_queries.append(query)
            return {"results": []}
        raise AssertionError("No result detail was expected")

    progress = urlscan._HuntProgress()
    assert (
        urlscan.hunt_urlscan(
            "test-key",
            NOW,
            requester=requester,
            registry=load_brand_registry(),
            seed_cursor=0,
            seed_rotation_shards=12,
            seeds_per_run=50,
            progress=progress,
        )
        == []
    )
    assert len(exact_queries) == 1
    assert 'task.domain.keyword:"secure-swedbank-0.example"' in exact_queries[0]
    assert 'task.domain.keyword:"secure-swedbank-1.example"' not in exact_queries[0]
    assert (progress.candidate_count, progress.selected_candidates, progress.candidate_cursor) == (
        12,
        1,
        1,
    )


def test_budgeted_requester_is_passive_and_enforces_independent_caps() -> None:
    calls: list[str] = []

    def delegate(request_url: str, _api_key: str) -> object:
        calls.append(request_url)
        return {"results": []} if "/search/" in request_url else {"task": {}}

    requester = urlscan._BudgetedRequester(
        delegate,
        search_used=0,
        result_used=0,
        daily_search_cap=5,
        daily_result_cap=5,
        run_search_cap=1,
        run_result_cap=1,
    )
    search = f"{urlscan.SEARCH_ENDPOINT}?q=task.visibility%3Apublic"
    result = f"{urlscan.RESULT_ENDPOINT}/{UUID}/"
    assert requester(search, "secret") == {"results": []}
    assert requester(search, "secret") == {"results": []}
    assert requester(result, "secret") == {"task": {}}
    assert requester(result, "secret") == {}
    assert calls == [search, result]
    assert requester.exhausted is True
    assert (requester.run_search_requests, requester.run_result_requests) == (1, 1)

    for forbidden in (
        "https://urlscan.io/api/v1/scan/",
        "https://urlscan.io/api/v1/result/not-a-uuid/",
        f"https://urlscan.io/api/v1/result/{UUID}/?x=1",
        "https://candidate.example/",
        "http://urlscan.io/api/v1/search/",
        "https://urlscan.io:443/api/v1/search/",
    ):
        with raises(ValueError):
            requester(forbidden, "secret")
    assert calls == [search, result]


def test_budgeted_requester_counts_only_returned_responses() -> None:
    calls = 0

    def failing(_request_url: str, _api_key: str) -> object:
        nonlocal calls
        calls += 1
        raise RuntimeError("network failed")

    requester = urlscan._BudgetedRequester(
        failing,
        search_used=0,
        result_used=0,
        daily_search_cap=10,
        daily_result_cap=10,
        run_search_cap=10,
        run_result_cap=10,
    )
    with raises(RuntimeError):
        requester(f"{urlscan.SEARCH_ENDPOINT}?q=task.visibility%3Apublic", "secret")
    assert calls == 1
    assert requester.search_used == 0
    assert requester.run_search_requests == 0


def test_successful_final_provider_response_is_counted_and_processed() -> None:
    payload = {"results": [{"task": {"visibility": "public"}}]}

    def final_response(_request_url: str, _api_key: str) -> object:
        raise urlscan._URLScanRateLimitError(
            "window exhausted",
            successful_response=True,
            payload=payload,
        )

    requester = urlscan._BudgetedRequester(
        final_response,
        search_used=0,
        result_used=0,
        daily_search_cap=10,
        daily_result_cap=10,
        run_search_cap=10,
        run_result_cap=10,
    )

    assert requester(f"{urlscan.SEARCH_ENDPOINT}?q=task.visibility%3Apublic", "secret") == payload
    assert requester.search_used == 1
    assert requester.provider_exhausted is True
    assert requester(f"{urlscan.SEARCH_ENDPOINT}?q=task.visibility%3Apublic", "secret") == {"results": []}

    limited = urlscan._BudgetedRequester(
        lambda *_args: (_ for _ in ()).throw(urlscan._URLScanRateLimitError("HTTP 429")),
        search_used=0,
        result_used=0,
        daily_search_cap=10,
        daily_result_cap=10,
        run_search_cap=10,
        run_result_cap=10,
    )
    assert limited(f"{urlscan.SEARCH_ENDPOINT}?q=task.visibility%3Apublic", "secret") == {"results": []}
    assert limited.search_used == 0
    assert limited.provider_exhausted is True


def test_unperformed_exact_search_does_not_advance_the_candidate_cursor(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setenv("URLSCAN_TITLE_DETAIL_LIMIT", "0")
    monkeypatch.setenv("URLSCAN_HASH_PIVOT_LIMIT", "0")
    seeds = [urlscan._HuntSeed(f"secure-swedbank-{index}.example", "Swedbank", 90) for index in range(12)]
    monkeypatch.setattr(urlscan, "_load_hunt_seeds", lambda *_args: seeds)
    requester = urlscan._BudgetedRequester(
        lambda *_args: (_ for _ in ()).throw(AssertionError("budgeted request escaped")),
        search_used=1,
        result_used=0,
        daily_search_cap=1,
        daily_result_cap=10,
        run_search_cap=10,
        run_result_cap=10,
    )
    progress = urlscan._HuntProgress()

    assert (
        urlscan.hunt_urlscan(
            "test-key",
            NOW,
            requester=requester,
            registry=load_brand_registry(),
            seed_cursor=0,
            seed_rotation_shards=12,
            seeds_per_run=50,
            progress=progress,
        )
        == []
    )
    assert progress.candidate_cursor == 0
    assert requester.run_search_requests == 0


def test_hunt_state_round_trip_has_an_exact_non_sensitive_contract(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    state = urlscan._state_for_run(
        NOW,
        configured=True,
        outcome="completed",
        search_requests=10,
        result_requests=20,
        candidate_cursor=2,
        candidate_count=12,
        selected_candidates=1,
        last_search_requests=3,
        last_result_requests=4,
    )
    urlscan.write_urlscan_hunt_state("data/urlscan", state)

    loaded = urlscan.read_urlscan_hunt_state("data/urlscan")
    assert loaded == state
    assert set(loaded or {}) == urlscan.HUNT_STATE_FIELDS
    body = (tmp_path / "data" / "urlscan" / "hunt-state.json").read_text(encoding="utf-8")
    assert "secret" not in body
    assert "candidate.example" not in body

    invalid = {**state, "searchRequests": True}
    with raises(ValueError, match="invalid contract"):
        urlscan.write_urlscan_hunt_state("data/urlscan", invalid)
    invalid_outcome = {**state, "configured": False}
    with raises(ValueError, match="invalid contract"):
        urlscan.write_urlscan_hunt_state("data/urlscan", invalid_outcome)
    with raises(ValueError, match="inside the repository"):
        urlscan.write_urlscan_hunt_state("../outside", state)


def test_missing_key_resets_the_utc_daily_ledger_but_preserves_rotation(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    current = datetime.now(UTC)
    previous = urlscan._state_for_run(
        current - timedelta(days=1),
        configured=True,
        outcome="completed",
        search_requests=100,
        result_requests=200,
        candidate_cursor=3,
        candidate_count=12,
        selected_candidates=1,
        last_search_requests=5,
        last_result_requests=6,
    )
    urlscan.write_urlscan_hunt_state("data/urlscan", previous)

    monkeypatch.setenv("URLSCAN_ARCHIVE_ROOT", "data/urlscan")
    monkeypatch.delenv("URLSCAN_API_KEY", raising=False)
    monkeypatch.setattr(
        urlscan,
        "_request_json",
        lambda *_args: (_ for _ in ()).throw(AssertionError("network call")),
    )

    assert urlscan.main() == 0
    state = urlscan.read_urlscan_hunt_state("data/urlscan")
    assert state is not None
    assert state["budgetDay"] == current.date().isoformat()
    assert (state["searchRequests"], state["resultRequests"]) == (0, 0)
    assert (state["candidateCursor"], state["candidateCount"]) == (3, 12)


def test_main_records_configured_request_counts_without_exposing_the_key(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("URLSCAN_ARCHIVE_ROOT", "data/urlscan")
    monkeypatch.setenv("URLSCAN_API_KEY", "never-write-this-key")
    calls: list[str] = []

    def delegate(request_url: str, _api_key: str) -> object:
        calls.append(request_url)
        return {"results": []}

    def fake_hunt(
        _api_key: str,
        _now: datetime,
        requester: object,
        **kwargs: object,
    ) -> list[object]:
        assert kwargs["seed_rotation_shards"] == 1
        assert kwargs["seeds_per_run"] == 250
        progress = kwargs["progress"]
        assert isinstance(progress, urlscan._HuntProgress)
        progress.candidate_count = 12
        progress.selected_candidates = 1
        progress.candidate_cursor = 1
        assert callable(requester)
        requester(f"{urlscan.SEARCH_ENDPOINT}?q=task.visibility%3Apublic", "never-write-this-key")
        return []

    monkeypatch.setattr(urlscan, "_request_json", delegate)
    monkeypatch.setattr(urlscan, "hunt_urlscan", fake_hunt)
    monkeypatch.setattr(urlscan, "write_urlscan_archive", lambda *_args, **_kwargs: 0)

    assert urlscan.main() == 0
    state = urlscan.read_urlscan_hunt_state("data/urlscan")
    assert state is not None
    assert state["lastOutcome"] == "completed"
    assert state["lastRunSearchRequests"] == 1
    assert state["candidateCursor"] == 1
    body = (tmp_path / "data" / "urlscan" / "hunt-state.json").read_text(encoding="utf-8")
    assert "never-write-this-key" not in body
    assert len(calls) == 1


def test_rate_limit_header_parser_recognizes_an_exhausted_window() -> None:
    headers = HTTPMessage()
    headers["X-Rate-Limit-Remaining"] = "minute=119; hour=999; day=0"
    assert urlscan._rate_limit_headers_exhausted(headers) is True


def test_requester_carries_the_last_successful_payload_from_an_exhausted_window(
    monkeypatch: MonkeyPatch,
) -> None:
    payload = {"results": [{"task": {"visibility": "public"}}]}

    class Response:
        def __init__(self) -> None:
            self.headers = HTTPMessage()
            self.headers["X-Rate-Limit-Remaining"] = "minute=0"

        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, _maximum: int) -> bytes:
            return json.dumps(payload).encode()

    class Opener:
        def open(self, _request: object, timeout: int) -> Response:
            assert timeout == 45
            return Response()

    monkeypatch.setattr(urlscan, "build_opener", lambda *_args: Opener())

    with raises(urlscan._URLScanRateLimitError) as error:
        urlscan._request_json(urlscan.SEARCH_ENDPOINT, "secret")
    assert error.value.successful_response is True
    assert error.value.payload == payload
