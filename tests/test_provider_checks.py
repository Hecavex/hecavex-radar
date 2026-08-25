from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from hecavex_radar.provider_checks import (
    GOOGLE_HOST,
    VIRUSTOTAL_HOST,
    _empty_safe_browsing_cache,
    _markdown,
    _parser,
    _read_safe_browsing_cache,
    _safe_browsing,
    check_signal,
)
from hecavex_radar.safety import defang_host, stable_id


def _snapshot(path: Path, domain: str = "support-vinted.ph") -> str:
    display = defang_host(domain)
    signal_id = stable_id(display.lower())
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "schemaVersion": 2,
                "dataset": "live",
                "signals": [
                    {
                        "id": signal_id,
                        "domain": display,
                        "url": f"hxxps://{display}",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return signal_id


def test_provider_check_is_ephemeral_and_score_free(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    signal_id = _snapshot(tmp_path / "public/data/radar.json")
    calls: list[tuple[str, str, dict[str, str]]] = []

    def requester(url: str, host: str, headers: dict[str, str]) -> tuple[int, Any]:
        calls.append((url, host, headers))
        if host == GOOGLE_HOST:
            return 200, {
                "threats": [{"url": "https://support-vinted.ph/", "threatTypes": ["SOCIAL_ENGINEERING"]}],
                "cacheDuration": "300.1s",
            }
        if host == VIRUSTOTAL_HOST:
            return 200, {
                "data": {
                    "attributes": {
                        "last_analysis_date": 1_787_699_000,
                        "last_analysis_stats": {
                            "malicious": 4,
                            "suspicious": 1,
                            "harmless": 2,
                            "undetected": 80,
                            "timeout": 0,
                        },
                    }
                }
            }
        raise AssertionError("Unexpected provider")

    result = check_signal(
        signal_id,
        google_key="google-secret",
        virustotal_key="vt-secret",
        requester=requester,
        now=datetime(2026, 8, 26, 10, tzinfo=UTC),
        safe_browsing_cache=_empty_safe_browsing_cache(),
    )

    assert result["candidate"] == "hxxps://support-vinted[.]ph"
    assert "matchScore" not in json.dumps(result)
    assert result["providers"]["googleSafeBrowsing"]["status"] == "match"  # type: ignore[index]
    assert result["providers"]["virusTotal"]["lastAnalysisStats"]["malicious"] == 4  # type: ignore[index]
    assert len(calls) == 2
    assert calls[0][1] == GOOGLE_HOST and "google-secret" in calls[0][0]
    assert calls[1][1] == VIRUSTOTAL_HOST and calls[1][2] == {"x-apikey": "vt-secret"}
    assert list(tmp_path.rglob("*provider*")) == []

    markdown = _markdown(result)
    assert "support-vinted[.]ph" in markdown
    assert "malicious=4" in markdown
    assert "google-secret" not in markdown and "vt-secret" not in markdown


def test_provider_check_rejects_legacy_live_snapshot_schema(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    signal_id = _snapshot(tmp_path / "public/data/radar.json")
    payload = json.loads((tmp_path / "public/data/radar.json").read_text(encoding="utf-8"))
    payload["schemaVersion"] = 1
    (tmp_path / "public/data/radar.json").write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="unsupported contract"):
        check_signal(signal_id, now=datetime(2026, 8, 26, 10, tzinfo=UTC))


def test_provider_check_rejects_arbitrary_signal_input(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    _snapshot(tmp_path / "public/data/radar.json")
    with pytest.raises(ValueError, match="20 lowercase hexadecimal"):
        check_signal("../../arbitrary-host")


def test_public_action_summary_is_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", "public-actions-summary.md")
    options = _parser().parse_args(["--signal-id", "a" * 20])
    assert options.summary == ""


def test_safe_browsing_caches_matches_and_no_matches_until_provider_expiry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    signal_id = _snapshot(tmp_path / "public/data/radar.json")
    cache = _empty_safe_browsing_cache()
    calls = 0

    def requester(_url: str, host: str, _headers: dict[str, str]) -> tuple[int, Any]:
        nonlocal calls
        assert host == GOOGLE_HOST
        calls += 1
        return 200, {"threats": [], "cacheDuration": "60s"}

    first = check_signal(
        signal_id,
        google_key="google-secret",
        requester=requester,
        now=datetime(2026, 8, 26, 10, tzinfo=UTC),
        safe_browsing_cache=cache,
    )
    second = check_signal(
        signal_id,
        google_key="google-secret",
        requester=requester,
        now=datetime(2026, 8, 26, 10, 0, 30, tzinfo=UTC),
        safe_browsing_cache=cache,
    )
    third = check_signal(
        signal_id,
        google_key="google-secret",
        requester=requester,
        now=datetime(2026, 8, 26, 10, 1, 1, tzinfo=UTC),
        safe_browsing_cache=cache,
    )

    assert first["providers"]["googleSafeBrowsing"]["cacheStatus"] == "refreshed"  # type: ignore[index]
    assert second["providers"]["googleSafeBrowsing"]["cacheStatus"] == "hit"  # type: ignore[index]
    assert third["providers"]["googleSafeBrowsing"]["cacheStatus"] == "refreshed"  # type: ignore[index]
    assert calls == 2


def test_safe_browsing_refuses_a_new_query_before_eviction_of_unexpired_results() -> None:
    cache = _empty_safe_browsing_cache()
    calls = 0
    now = datetime(2026, 8, 26, 10, tzinfo=UTC)

    def requester(_url: str, _host: str, _headers: dict[str, str]) -> tuple[int, Any]:
        nonlocal calls
        calls += 1
        return 200, {"threats": [], "cacheDuration": "3600s"}

    for index in range(7):
        _safe_browsing(f"brand-{index}.example", "key", requester, cache, now)

    with pytest.raises(ValueError, match="cache is full"):
        _safe_browsing("eighth.example", "key", requester, cache, now)
    assert calls == 7


def _symlink_or_skip(link: Path, target: Path, *, directory: bool) -> None:
    try:
        link.symlink_to(target, target_is_directory=directory)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"Symbolic links are unavailable on this platform: {error}")


def test_safe_browsing_cache_rejects_a_symlinked_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "provider-check-cache.json").write_text(
        json.dumps(_empty_safe_browsing_cache()),
        encoding="utf-8",
    )
    _symlink_or_skip(tmp_path / ".radar-local", outside, directory=True)

    with pytest.raises(ValueError, match="symbolic link"):
        _read_safe_browsing_cache()


def test_safe_browsing_cache_rejects_a_symlinked_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    cache_root = tmp_path / ".radar-local"
    cache_root.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps(_empty_safe_browsing_cache()), encoding="utf-8")
    _symlink_or_skip(cache_root / "provider-check-cache.json", outside, directory=False)

    with pytest.raises(ValueError, match="symbolic link"):
        _read_safe_browsing_cache()
