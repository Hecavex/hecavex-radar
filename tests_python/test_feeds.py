import pytest
from pytest import MonkeyPatch

from hecavex_radar import feeds
from hecavex_radar.feeds import parse_vmray_page


def test_vmray_parser_extracts_urls_and_ignores_other_indicators() -> None:
    body = """
      <div class="reportContainer">
        <div class="title">https://login.example.test/a?token=secret&amp;next=1</div>
        <div class="dateString">2026-08-21T09:30:00Z</div>
        <div class="name">URL</div>
      </div>
      <div class="reportContainer">
        <div class="title">example.test</div>
        <div class="dateString">2026-08-21T09:30:00Z</div>
        <div class="name">Domain</div>
      </div>
    """
    signals = parse_vmray_page(body, "2026-08-21T10:00:00Z")
    assert len(signals) == 1
    assert signals[0].url == "https://login.example.test/a?token=secret&next=1"
    assert signals[0].source == "VMRay"
    assert signals[0].confidence == 90
    assert signals[0].last_seen == "2026-08-21T10:00:00Z"


def test_vmray_layout_changes_fail_the_source(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(feeds, "fetch_text", lambda *_args, **_kwargs: "<html><p>Changed layout</p></html>")
    with pytest.raises(ValueError, match="report-card layout"):
        feeds.fetch_vmray("2026-08-21T10:00:00Z", 1)


def test_hecavex_export_rejects_an_unexpected_payload(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(feeds, "fetch_text", lambda *_args, **_kwargs: '{"unexpected": []}')
    with pytest.raises(ValueError, match="unexpected payload"):
        feeds.fetch_hecavex("2026-08-21T10:00:00Z", "https://feed.example.test/radar.json")
