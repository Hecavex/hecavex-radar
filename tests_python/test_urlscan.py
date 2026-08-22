from __future__ import annotations

import json
from datetime import UTC, datetime
from http.client import HTTPMessage
from io import BytesIO
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request

from pytest import CaptureFixture, MonkeyPatch, raises

from hecavex_radar import urlscan
from hecavex_radar.brands import load_brand_registry
from hecavex_radar.models import BrandEvidence, RadarSignal
from hecavex_radar.safety import stable_id
from hecavex_radar.seeds import IntelligenceSeed, SeedLoadResult
from hecavex_radar.urlscan import hunt_urlscan, read_recent_urlscan, write_urlscan_archive

NOW = datetime(2026, 8, 21, 10, tzinfo=UTC)
UUID_DOMAIN = "11111111-1111-1111-1111-111111111111"
UUID_TITLE = "22222222-2222-2222-2222-222222222222"
UUID_PIVOT = "33333333-3333-3333-3333-333333333333"
UUID_REDIRECT = "55555555-5555-5555-5555-555555555555"
PRIMARY_HASH = "a" * 64
TITLE_HASH = "b" * 64
OTHER_HASH = "d" * 64


def _signal(
    domain: str,
    sources: list[str],
    *,
    brand: str = "Swedbank",
    hashes: list[str] | None = None,
    evidence: list[BrandEvidence] | None = None,
) -> RadarSignal:
    display_domain = domain.replace(".", "[.]")
    signal: RadarSignal = {
        "id": stable_id(display_domain.lower()),
        "url": f"hxxps://{display_domain}",
        "domain": display_domain,
        "firstSeen": "2026-08-21T09:00:00.000Z",
        "lastSeen": "2026-08-21T09:00:00.000Z",
        "sources": sources,
        "status": "suspected",
        "brand": brand,
        "country": None,
        "host": None,
        "screenshotUrl": None,
        "referenceUrl": None,
        "hashes": hashes or [],
        "confidence": 85,
    }
    signal["brandEvidence"] = evidence or ["domain"]
    return signal


def _disable_seed_inputs(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv("URLSCAN_CT_SEEDS_ENABLED", "false")
    monkeypatch.setenv("URLSCAN_INTELLIGENCE_SEEDS_ENABLED", "false")


def test_main_skips_cleanly_without_optional_api_key(
    monkeypatch: MonkeyPatch,
    capsys: CaptureFixture[str],
) -> None:
    monkeypatch.delenv("URLSCAN_API_KEY", raising=False)

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("missing-key skip must not hunt or mutate the archive")

    monkeypatch.setattr(urlscan, "hunt_urlscan", forbidden)
    monkeypatch.setattr(urlscan, "write_urlscan_archive", forbidden)

    assert urlscan.main() == 0
    output = capsys.readouterr().out
    assert "hunt skipped" in output
    assert "CertStream candidates remain eligible" in output


def _summary(uuid: str, url: str, title: str = "") -> dict[str, object]:
    return {
        "_id": uuid,
        "task": {
            "uuid": uuid,
            "url": url,
            "time": "2026-08-21T09:00:00.000Z",
            "visibility": "public",
        },
        "page": {"url": url, "title": title},
    }


def _detail(uuid: str, url: str, title: str, digest: str) -> dict[str, object]:
    return {
        "task": {
            "uuid": uuid,
            "url": url,
            "time": "2026-08-21T09:00:00.000Z",
            "visibility": "public",
        },
        "page": {
            "url": url,
            "title": title,
            "country": "LT",
            "asn": "AS64500",
            "asnname": "Example host",
            "ip": "192.0.2.1",
        },
        "verdicts": {
            "urlscan": {
                "malicious": True,
                "score": 10,
                "categories": ["phishing"],
                "brands": [{"name": "Swedbank"}],
            }
        },
        "lists": {"hashes": [digest, "c" * 64]},
        "data": {
            "requests": [
                {
                    "request": {"request": {"url": url}},
                    "response": {
                        "hash": digest,
                        "response": {
                            "url": url,
                            "status": 200,
                            "mimeType": "text/html",
                            "encodedDataLength": 2048,
                        },
                    },
                }
            ]
        },
    }


def _set_primary_status(detail: dict[str, object], status: int) -> None:
    data = detail["data"]
    assert isinstance(data, dict)
    requests = data["requests"]
    assert isinstance(requests, list)
    request = requests[0]
    assert isinstance(request, dict)
    response = request["response"]
    assert isinstance(response, dict)
    metadata = response["response"]
    assert isinstance(metadata, dict)
    metadata["status"] = status


def _requester(url: str, api_key: str) -> object:
    assert api_key == "test-key"
    parsed = urlsplit(url)
    if parsed.path == "/api/v1/search/":
        query = parse_qs(parsed.query)["q"][0]
        assert "task.visibility:public" in query
        if "task.domain.keyword" in query:
            return {
                "results": [
                    _summary(UUID_DOMAIN, "https://secure-swedbank-login.example/account"),
                    {
                        "_id": UUID_REDIRECT,
                        "task": {
                            "uuid": UUID_REDIRECT,
                            "url": "https://secure-swedbank-redirect.example/",
                            "time": "2026-08-21T09:00:00.000Z",
                            "visibility": "public",
                        },
                        "page": {"url": "https://www.swedbank.lt/", "title": "Swedbank"},
                    },
                    _summary("44444444-4444-4444-4444-444444444444", "https://www.swedbank.lt/"),
                ]
            }
        if "page.title.keyword" in query:
            return {"results": [_summary(UUID_TITLE, "https://unrelated.example/", "Swedbank secure login")]}
        if f"hash:{PRIMARY_HASH}" in query:
            return {"results": [_summary(UUID_PIVOT, "https://shared-kit.example/login", "Account login")]}
        return {"results": []}
    if parsed.path == f"/api/v1/result/{UUID_DOMAIN}/":
        return _detail(
            UUID_DOMAIN,
            "https://secure-swedbank-login.example/account",
            "Swedbank secure login",
            PRIMARY_HASH,
        )
    if parsed.path == f"/api/v1/result/{UUID_TITLE}/":
        return _detail(UUID_TITLE, "https://unrelated.example/", "Swedbank secure login", TITLE_HASH)
    if parsed.path == f"/api/v1/result/{UUID_PIVOT}/":
        return _detail(UUID_PIVOT, "https://shared-kit.example/login", "Account login", PRIMARY_HASH)
    if parsed.path == f"/api/v1/result/{UUID_REDIRECT}/":
        detail = _detail(UUID_REDIRECT, "https://www.swedbank.lt/", "Swedbank", "d" * 64)
        detail["task"] = {
            "uuid": UUID_REDIRECT,
            "url": "https://secure-swedbank-redirect.example/",
            "time": "2026-08-21T09:00:00.000Z",
            "visibility": "public",
        }
        return detail
    raise AssertionError(f"Unexpected URLScan request: {parsed.path}")


def test_hunts_domains_titles_and_exact_primary_hash_pivots(monkeypatch: MonkeyPatch) -> None:
    _disable_seed_inputs(monkeypatch)
    monkeypatch.setenv("URLSCAN_MIN_CONFIDENCE", "80")
    signals = hunt_urlscan("test-key", NOW, requester=_requester, registry=load_brand_registry())

    assert len(signals) == 3
    assert {signal["brand"] for signal in signals} == {"Swedbank"}
    assert all(signal["sources"] == ["URLScan"] for signal in signals)
    assert all((signal.get("referenceUrl") or "").startswith("https://urlscan.io/result/") for signal in signals)
    assert all(
        signal["screenshotUrl"] is not None
        and signal["screenshotUrl"].startswith("https://urlscan.io/screenshots/")
        for signal in signals
    )
    assert all("https://" not in signal["url"] for signal in signals)
    assert all(signal["firstSeen"] == "2026-08-21T09:00:00.000Z" for signal in signals)
    assert all(signal["lastSeen"] == "2026-08-21T09:00:00.000Z" for signal in signals)
    assert all(signal["status"] == "suspected" for signal in signals)
    assert all("c" * 64 not in signal["hashes"] for signal in signals)
    assert all(signal.get("brandEvidence") for signal in signals)
    pivot = next(signal for signal in signals if signal["domain"] == "shared-kit[.]example")
    assert PRIMARY_HASH in pivot["hashes"]
    assert "primary-html-sha256" in pivot["brandEvidence"]


def test_search_refuses_a_query_without_the_public_visibility_clause() -> None:
    requested = False

    def requester(_request_url: str, _api_key: str) -> object:
        nonlocal requested
        requested = True
        return {"results": []}

    with raises(ValueError, match="restricted to public scans"):
        urlscan._search("date:>now-7d AND hash:" + PRIMARY_HASH, 10, "test-key", requester)

    assert requested is False


def test_search_rejects_non_public_and_missing_visibility_before_detail_fetch(
    monkeypatch: MonkeyPatch,
) -> None:
    _disable_seed_inputs(monkeypatch)
    monkeypatch.setenv("URLSCAN_TITLE_DETAIL_LIMIT", "0")
    public_uuid = "66666666-6666-6666-6666-666666666666"
    unlisted_uuid = "77777777-7777-7777-7777-777777777777"
    private_uuid = "88888888-8888-8888-8888-888888888888"
    missing_uuid = "99999999-9999-9999-9999-999999999999"
    detail_requests: list[str] = []

    unlisted = _summary(unlisted_uuid, "https://secure-swedbank-unlisted.example/")
    private = _summary(private_uuid, "https://secure-swedbank-private.example/")
    missing = _summary(missing_uuid, "https://secure-swedbank-missing.example/")
    for summary, visibility in ((unlisted, "unlisted"), (private, "private")):
        task = summary["task"]
        assert isinstance(task, dict)
        task["visibility"] = visibility
    missing_task = missing["task"]
    assert isinstance(missing_task, dict)
    del missing_task["visibility"]

    def requester(request_url: str, api_key: str) -> object:
        assert api_key == "test-key"
        parsed = urlsplit(request_url)
        if parsed.path == "/api/v1/search/":
            query = parse_qs(parsed.query)["q"][0]
            assert "task.visibility:public" in query
            if "task.domain.keyword" in query:
                return {
                    "results": [
                        unlisted,
                        private,
                        missing,
                        _summary(public_uuid, "https://secure-swedbank-public.example/"),
                    ]
                }
            return {"results": []}
        detail_requests.append(parsed.path)
        if parsed.path == f"/api/v1/result/{public_uuid}/":
            return _detail(
                public_uuid,
                "https://secure-swedbank-public.example/",
                "Swedbank secure login",
                PRIMARY_HASH,
            )
        raise AssertionError(f"Non-public summary reached detail retrieval: {parsed.path}")

    signals = hunt_urlscan("test-key", NOW, requester=requester, registry=load_brand_registry())

    assert [signal["domain"] for signal in signals] == ["secure-swedbank-public[.]example"]
    assert detail_requests == [f"/api/v1/result/{public_uuid}/"]


def test_detail_rejects_non_public_and_missing_visibility(monkeypatch: MonkeyPatch) -> None:
    _disable_seed_inputs(monkeypatch)
    monkeypatch.setenv("URLSCAN_TITLE_DETAIL_LIMIT", "0")
    cases = (
        ("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "unlisted"),
        ("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "private"),
        ("cccccccc-cccc-cccc-cccc-cccccccccccc", None),
    )
    urls = {
        uuid: f"https://secure-swedbank-{index}.example/"
        for index, (uuid, _visibility) in enumerate(cases, start=1)
    }
    detail_requests: list[str] = []

    def requester(request_url: str, api_key: str) -> object:
        assert api_key == "test-key"
        parsed = urlsplit(request_url)
        if parsed.path == "/api/v1/search/":
            query = parse_qs(parsed.query)["q"][0]
            assert "task.visibility:public" in query
            return {
                "results": [_summary(uuid, urls[uuid]) for uuid, _visibility in cases]
                if "task.domain.keyword" in query
                else []
            }
        detail_requests.append(parsed.path)
        for uuid, visibility in cases:
            if parsed.path != f"/api/v1/result/{uuid}/":
                continue
            detail = _detail(uuid, urls[uuid], "Swedbank secure login", PRIMARY_HASH)
            task = detail["task"]
            assert isinstance(task, dict)
            if visibility is None:
                del task["visibility"]
            else:
                task["visibility"] = visibility
            return detail
        raise AssertionError(f"Unexpected URLScan request: {parsed.path}")

    signals = hunt_urlscan("test-key", NOW, requester=requester, registry=load_brand_registry())

    assert signals == []
    assert detail_requests == [f"/api/v1/result/{uuid}/" for uuid, _visibility in cases]


def test_urlscan_redirects_never_leave_exact_https_origin() -> None:
    handler = urlscan._UrlscanRedirectHandler()
    request = Request(
        "https://urlscan.io/api/v1/search/",
        headers={"api-key": "secret"},
    )
    redirected = handler.redirect_request(
        request,
        BytesIO(),
        302,
        "Found",
        HTTPMessage(),
        "/api/v1/result/11111111-1111-1111-1111-111111111111/",
    )

    assert redirected is not None
    assert redirected.full_url.startswith("https://urlscan.io/")
    assert redirected.get_header("Api-key") == "secret"

    for destination in (
        "https://attacker.example/collect",
        "//attacker.example/collect",
        "http://urlscan.io/api/v1/search/",
        "https://urlscan.io.attacker.example/api/v1/search/",
        "https://urlscan.io:443/api/v1/search/",
    ):
        with raises(HTTPError):
            handler.redirect_request(
                request,
                BytesIO(),
                302,
                "Found",
                HTTPMessage(),
                destination,
            )


def test_detail_rate_limit_and_access_errors_stop_the_hunt(
    monkeypatch: MonkeyPatch,
) -> None:
    _disable_seed_inputs(monkeypatch)
    monkeypatch.setenv("URLSCAN_TITLE_DETAIL_LIMIT", "0")
    api_key = "super-secret-api-key"
    cases: tuple[tuple[int, type[RuntimeError], str], ...] = (
        (429, urlscan._URLScanRateLimitError, "URLScan rate limit reached (HTTP 429)."),
        (
            401,
            urlscan._URLScanAccessError,
            "URLScan API authentication or authorization failed (HTTP 401).",
        ),
        (
            403,
            urlscan._URLScanAccessError,
            "URLScan API authentication or authorization failed (HTTP 403).",
        ),
    )

    def run_case(
        status: int,
        error_type: type[RuntimeError],
        expected_message: str,
    ) -> None:
        calls: list[str] = []

        class FailingOpener:
            def open(self, request: Request, timeout: int) -> None:
                assert timeout == 45
                raise HTTPError(
                    request.full_url,
                    status,
                    "upstream response containing sensitive data",
                    HTTPMessage(),
                    BytesIO(b"sensitive upstream body"),
                )

        monkeypatch.setattr(urlscan, "build_opener", lambda *_args: FailingOpener())

        def requester(request_url: str, request_api_key: str) -> object:
            assert request_api_key == api_key
            calls.append(request_url)
            parsed = urlsplit(request_url)
            if parsed.path == "/api/v1/search/":
                return {
                    "results": [
                        _summary(UUID_DOMAIN, "https://secure-swedbank-login.example/"),
                        _summary(UUID_REDIRECT, "https://secure-swedbank-help.example/"),
                    ]
                }
            return urlscan._request_json(request_url, request_api_key)

        with raises(error_type) as error:
            hunt_urlscan(api_key, NOW, requester=requester, registry=load_brand_registry())

        assert str(error.value) == expected_message
        assert api_key not in str(error.value)
        assert [urlsplit(call).path for call in calls] == [
            "/api/v1/search/",
            f"/api/v1/result/{UUID_DOMAIN}/",
        ]

    for case in cases:
        run_case(*case)


def test_rejects_hash_pivot_when_digest_is_only_a_resource(monkeypatch: MonkeyPatch) -> None:
    _disable_seed_inputs(monkeypatch)
    monkeypatch.setenv("URLSCAN_HASH_PIVOT_LIMIT", "1")

    def requester(request_url: str, api_key: str) -> object:
        parsed = urlsplit(request_url)
        if parsed.path == f"/api/v1/result/{UUID_PIVOT}/":
            detail = _detail(UUID_PIVOT, "https://shared-kit.example/login", "Swedbank login", OTHER_HASH)
            detail["lists"] = {"hashes": [PRIMARY_HASH, OTHER_HASH]}
            return detail
        return _requester(request_url, api_key)

    signals = hunt_urlscan("test-key", NOW, requester=requester, registry=load_brand_registry())

    assert all(signal["domain"] != "shared-kit[.]example" for signal in signals)


def test_rejects_primary_hash_pivot_with_wrong_brand(monkeypatch: MonkeyPatch) -> None:
    _disable_seed_inputs(monkeypatch)
    monkeypatch.setenv("URLSCAN_HASH_PIVOT_LIMIT", "1")

    def requester(request_url: str, api_key: str) -> object:
        parsed = urlsplit(request_url)
        if parsed.path == f"/api/v1/result/{UUID_PIVOT}/":
            detail = _detail(
                UUID_PIVOT,
                "https://secure-revolut-login.example/",
                "Revolut secure login",
                PRIMARY_HASH,
            )
            detail["verdicts"] = {
                "urlscan": {
                    "malicious": True,
                    "score": 10,
                    "categories": ["phishing"],
                    "brands": [{"name": "Revolut"}],
                }
            }
            return detail
        return _requester(request_url, api_key)

    signals = hunt_urlscan("test-key", NOW, requester=requester, registry=load_brand_registry())

    assert all(signal["domain"] != "shared-kit[.]example" for signal in signals)


def test_primary_html_hash_requires_successful_http_response(
    monkeypatch: MonkeyPatch,
) -> None:
    _disable_seed_inputs(monkeypatch)
    monkeypatch.setenv("URLSCAN_TITLE_DETAIL_LIMIT", "0")
    queries: list[str] = []

    def requester(request_url: str, api_key: str) -> object:
        assert api_key == "test-key"
        parsed = urlsplit(request_url)
        if parsed.path == "/api/v1/search/":
            query = parse_qs(parsed.query)["q"][0]
            queries.append(query)
            if "task.domain.keyword" in query:
                return {
                    "results": [
                        _summary(
                            UUID_DOMAIN,
                            "https://secure-swedbank-login.example/",
                        )
                    ]
                }
            return {"results": []}
        if parsed.path == f"/api/v1/result/{UUID_DOMAIN}/":
            detail = _detail(
                UUID_DOMAIN,
                "https://secure-swedbank-login.example/",
                "Swedbank login",
                PRIMARY_HASH,
            )
            _set_primary_status(detail, 404)
            return detail
        raise AssertionError(f"Unexpected URLScan request: {parsed.path}")

    signals = hunt_urlscan("test-key", NOW, requester=requester, registry=load_brand_registry())

    assert len(signals) == 1
    assert signals[0]["hashes"] == []
    assert all(f"hash:{PRIMARY_HASH}" not in query for query in queries)


def test_exactly_enriches_current_certstream_seed(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv("URLSCAN_CT_SEEDS_ENABLED", "true")
    monkeypatch.setenv("URLSCAN_INTELLIGENCE_SEEDS_ENABLED", "false")
    captured_roots: list[str] = []
    queries: list[str] = []

    def candidate_reader(root: str, *_args: object, **_kwargs: object) -> list[dict[str, object]]:
        captured_roots.append(root)
        return [
            {
                "schemaVersion": 1,
                "id": "1" * 20,
                "observedAt": "2026-08-21T08:30:00.000Z",
                "indicatorType": "domain",
                "domain": "secure-swedbank-login[.]example",
                "registrableDomain": "secure-swedbank-login[.]example",
                "source": "CertStream",
                "brand": "Swedbank",
                "confidence": 100,
                "reasons": ["brand text match: swedbank"],
            }
        ]

    monkeypatch.setattr(urlscan, "read_recent_candidates", candidate_reader)

    def requester(request_url: str, api_key: str) -> object:
        assert api_key == "test-key"
        parsed = urlsplit(request_url)
        if parsed.path == "/api/v1/search/":
            query = parse_qs(parsed.query)["q"][0]
            queries.append(query)
            if 'task.domain.keyword:"secure-swedbank-login.example"' in query:
                return {
                    "results": [
                        _summary(UUID_REDIRECT, "https://prefix-secure-swedbank-login.example/account"),
                        _summary(UUID_DOMAIN, "https://secure-swedbank-login.example/account"),
                    ]
                }
            return {"results": []}
        if parsed.path == f"/api/v1/result/{UUID_DOMAIN}/":
            detail = _detail(
                UUID_DOMAIN,
                "https://secure-swedbank-login.example/account",
                "Account",
                PRIMARY_HASH,
            )
            detail["verdicts"] = {
                "urlscan": {"malicious": False, "score": 0, "categories": [], "brands": []}
            }
            return detail
        raise AssertionError(f"Unexpected URLScan request: {parsed.path}")

    signals = hunt_urlscan("test-key", NOW, requester=requester, registry=load_brand_registry())

    assert captured_roots == ["data/certstream"]
    assert any('page.domain.keyword:"secure-swedbank-login.example"' in query for query in queries)
    assert len(signals) == 1
    assert signals[0]["sources"] == ["URLScan"]
    assert signals[0]["status"] == "suspected"
    assert signals[0]["firstSeen"] == "2026-08-21T09:00:00.000Z"
    assert signals[0]["lastSeen"] == "2026-08-21T09:00:00.000Z"
    assert signals[0]["hashes"] == [PRIMARY_HASH]
    assert all(f"hash:{PRIMARY_HASH}" not in query for query in queries)


def test_transient_seed_is_attributed_only_to_urlscan(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setenv("URLSCAN_CT_SEEDS_ENABLED", "false")
    monkeypatch.setenv("URLSCAN_INTELLIGENCE_SEEDS_ENABLED", "true")
    seed = IntelligenceSeed(
        domain="secure-swedbank-login.example",
        brand="Swedbank",
        confidence=90,
    )
    monkeypatch.setattr(
        urlscan,
        "load_intelligence_seeds",
        lambda _registry: SeedLoadResult([seed], configured=1, completed=1, failed=0),
    )

    def requester(request_url: str, api_key: str) -> object:
        assert api_key == "test-key"
        parsed = urlsplit(request_url)
        if parsed.path == "/api/v1/search/":
            query = parse_qs(parsed.query)["q"][0]
            if 'task.domain.keyword:"secure-swedbank-login.example"' in query:
                return {
                    "results": [
                        _summary(UUID_DOMAIN, "https://secure-swedbank-login.example/")
                    ]
                }
            return {"results": []}
        if parsed.path == f"/api/v1/result/{UUID_DOMAIN}/":
            return _detail(
                UUID_DOMAIN,
                "https://secure-swedbank-login.example/",
                "Swedbank secure login",
                PRIMARY_HASH,
            )
        raise AssertionError(f"Unexpected URLScan request: {parsed.path}")

    signals = hunt_urlscan("test-key", NOW, requester=requester, registry=load_brand_registry())

    assert len(signals) == 1
    assert signals[0]["sources"] == ["URLScan"]


def test_generic_malicious_is_suspected_and_empty_hash_is_not_published(monkeypatch: MonkeyPatch) -> None:
    _disable_seed_inputs(monkeypatch)
    empty_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def requester(request_url: str, api_key: str) -> object:
        assert api_key == "test-key"
        parsed = urlsplit(request_url)
        if parsed.path == "/api/v1/search/":
            query = parse_qs(parsed.query)["q"][0]
            if "task.domain.keyword" in query:
                return {"results": [_summary(UUID_DOMAIN, "https://secure-swedbank-login.example/")]}
            return {"results": []}
        if parsed.path == f"/api/v1/result/{UUID_DOMAIN}/":
            detail = _detail(
                UUID_DOMAIN,
                "https://secure-swedbank-login.example/",
                "Swedbank login",
                empty_hash,
            )
            detail["verdicts"] = {
                "urlscan": {
                    "malicious": True,
                    "score": 10,
                    "categories": ["malware"],
                    "brands": [{"name": "Swedbank"}],
                }
            }
            return detail
        raise AssertionError(f"Unexpected URLScan request: {parsed.path}")

    signals = hunt_urlscan("test-key", NOW, requester=requester, registry=load_brand_registry())

    assert len(signals) == 1
    assert signals[0]["status"] == "suspected"
    assert signals[0]["hashes"] == []


def test_urlscan_mapping_rejects_multi_brand_redirects_and_verdicts() -> None:
    registry = load_brand_registry()
    summary = _summary(UUID_DOMAIN, "https://secure-swedbank-login.example/")
    summary["page"] = {
        "url": "https://secure-revolut-login.example/",
        "title": "Account login",
    }
    assert urlscan._summary_match(summary, registry, 80) is None

    detail = _detail(
        UUID_DOMAIN,
        "https://secure-swedbank-login.example/",
        "Account login",
        PRIMARY_HASH,
    )
    verdicts = detail["verdicts"]
    assert isinstance(verdicts, dict)
    provider_verdict = verdicts["urlscan"]
    assert isinstance(provider_verdict, dict)
    provider_verdict["brands"] = [
        {"name": "Swedbank"},
        {"name": "Revolut"},
    ]
    assert urlscan._verdict_brand(detail, registry) is None


def test_writes_daily_defanged_archive(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    _disable_seed_inputs(monkeypatch)
    monkeypatch.chdir(tmp_path)
    registry_path = Path(__file__).parents[1] / "data" / "brands-lt.json"
    registry = load_brand_registry(registry_path)
    signals = hunt_urlscan("test-key", NOW, requester=_requester, registry=registry)
    signal = next(item for item in signals if item["domain"] == "secure-swedbank-login[.]example")

    assert write_urlscan_archive("data/urlscan", [signal], NOW, registry) == 1
    archive = tmp_path / "data" / "urlscan" / "2026-08-21" / "signals.ndjson"
    body = archive.read_text(encoding="utf-8")
    assert "secure-swedbank-login.example" not in body
    assert "secure-swedbank-login[.]example" in body
    assert '"schemaVersion":2' in body
    assert '"hashType":"primary-html-sha256"' in body
    assert '"brandEvidence":["domain","title","verdict"]' in body
    assert write_urlscan_archive("data/urlscan", [signal], NOW, registry) == 0
    assert read_recent_urlscan("data/urlscan", 1, NOW, registry=registry) == [signal]


def test_v2_archive_requires_typed_evidence_and_rechecks_domain_matches(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    registry_path = Path(__file__).parents[1] / "data" / "brands-lt.json"
    registry = load_brand_registry(registry_path)
    stale_domain = _signal("random.example", ["URLScan"], evidence=["domain"])
    title_backed = _signal("shared-kit.example", ["URLScan"], evidence=["title"])
    untyped = _signal("untyped.example", ["URLScan"])
    del untyped["brandEvidence"]
    archive = tmp_path / "data" / "urlscan" / "2026-08-21" / "signals.ndjson"
    archive.parent.mkdir(parents=True)
    archive.write_text(
        "\n".join(
            json.dumps(
                {
                    "schemaVersion": 2,
                    "hashType": "primary-html-sha256",
                    **value,
                }
            )
            for value in (stale_domain, title_backed, untyped)
        )
        + "\n",
        encoding="utf-8",
    )

    records = read_recent_urlscan("data/urlscan", 1, NOW, registry=registry)

    assert len(records) == 1
    assert records[0]["domain"] == "shared-kit[.]example"
    assert records[0]["brandEvidence"] == ["title"]


def test_archive_rejects_private_fields_mixed_sources_and_unsafe_screenshots(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    registry_path = Path(__file__).parents[1] / "data" / "brands-lt.json"
    registry = load_brand_registry(registry_path)
    metadata = {"schemaVersion": 2, "hashType": "primary-html-sha256"}
    archive = tmp_path / "data" / "urlscan" / "2026-08-21" / "signals.ndjson"
    archive.parent.mkdir(parents=True)
    archive.write_text(
        "\n".join(
            json.dumps(value)
            for value in (
                {
                    **metadata,
                    **_signal("shared-kit.example", ["URLScan"], evidence=["title"]),
                },
                {
                    **metadata,
                    **_signal("shared-private.example", ["URLScan"], evidence=["title"]),
                    "seedProvider": "private-enrichment",
                },
                {
                    **metadata,
                    **_signal(
                        "shared-source.example",
                        ["URLScan", "TransientFeed"],
                        evidence=["title"],
                    ),
                },
                {
                    **metadata,
                    **_signal("shared-image.example", ["URLScan"], evidence=["title"]),
                    "screenshotUrl": "https://urlscan.io/api/v1/result/private.png",
                },
                {
                    **metadata,
                    **_signal("shared-active.example", ["URLScan"], evidence=["title"]),
                    "status": "active",
                },
            )
        )
        + "\n",
        encoding="utf-8",
    )

    records = read_recent_urlscan("data/urlscan", 1, NOW, registry=registry)

    assert [record["domain"] for record in records] == ["shared-kit[.]example"]
    assert records[0]["sources"] == ["URLScan"]
    assert "seedProvider" not in records[0]


def test_archive_requires_stable_domain_id_and_canonical_utc_timestamps(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    registry_path = Path(__file__).parents[1] / "data" / "brands-lt.json"
    registry = load_brand_registry(registry_path)
    valid = _signal("shared-kit.example", ["URLScan"], evidence=["title"])
    wrong_id = _signal("shared-id.example", ["URLScan"], evidence=["title"])
    wrong_id["id"] = "0" * 20
    noncanonical_first = _signal(
        "shared-first.example",
        ["URLScan"],
        evidence=["title"],
    )
    noncanonical_first["firstSeen"] = "2026-08-21T09:00:00Z"
    noncanonical_last = _signal(
        "shared-last.example",
        ["URLScan"],
        evidence=["title"],
    )
    noncanonical_last["lastSeen"] = "2026-08-21T12:00:00.000+03:00"
    archive = tmp_path / "data" / "urlscan" / "2026-08-21" / "signals.ndjson"
    archive.parent.mkdir(parents=True)
    archive.write_text(
        "\n".join(
            json.dumps(
                {
                    "schemaVersion": 2,
                    "hashType": "primary-html-sha256",
                    **value,
                }
            )
            for value in (valid, wrong_id, noncanonical_first, noncanonical_last)
        )
        + "\n",
        encoding="utf-8",
    )

    records = read_recent_urlscan("data/urlscan", 1, NOW, registry=registry)

    assert [record["domain"] for record in records] == ["shared-kit[.]example"]
    assert records[0]["id"] == stable_id("shared-kit[.]example")
    assert records[0]["firstSeen"] == "2026-08-21T09:00:00.000Z"
    assert records[0]["lastSeen"] == "2026-08-21T09:00:00.000Z"


def test_stale_rows_do_not_consume_recent_archive_limit(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    registry_path = Path(__file__).parents[1] / "data" / "brands-lt.json"
    registry = load_brand_registry(registry_path)
    metadata = {"schemaVersion": 2, "hashType": "primary-html-sha256"}
    newest = tmp_path / "data" / "urlscan" / "2026-08-21" / "signals.ndjson"
    older = tmp_path / "data" / "urlscan" / "2026-08-20" / "signals.ndjson"
    older_signal = _signal("shared-kit.example", ["URLScan"], evidence=["title"])
    older_signal["firstSeen"] = "2026-08-20T09:00:00.000Z"
    older_signal["lastSeen"] = "2026-08-20T09:00:00.000Z"
    newest.parent.mkdir(parents=True)
    older.parent.mkdir(parents=True)
    newest.write_text(
        json.dumps(
            {
                **metadata,
                **_signal("random.example", ["URLScan"], evidence=["domain"]),
            }
        )
        + "\n",
        encoding="utf-8",
    )
    older.write_text(
        json.dumps(
            {
                **metadata,
                **older_signal,
            }
        )
        + "\n",
        encoding="utf-8",
    )

    records = read_recent_urlscan(
        "data/urlscan",
        2,
        NOW,
        maximum=1,
        registry=registry,
    )

    assert [record["domain"] for record in records] == ["shared-kit[.]example"]


def test_future_timestamps_are_rejected_and_purged_on_rewrite(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    registry_path = Path(__file__).parents[1] / "data" / "brands-lt.json"
    registry = load_brand_registry(registry_path)
    near_future = _signal("future.example", ["URLScan"], evidence=["title"])
    near_future["firstSeen"] = "2026-08-21T11:00:00.000Z"
    near_future["lastSeen"] = "2026-08-21T11:00:00.000Z"
    impossible = _signal("impossible.example", ["URLScan"], evidence=["title"])
    impossible["firstSeen"] = "9999-01-01T00:00:00.000Z"
    impossible["lastSeen"] = "9999-01-01T00:00:00.000Z"
    archive = tmp_path / "data" / "urlscan" / "2026-08-21" / "signals.ndjson"
    archive.parent.mkdir(parents=True)
    archive.write_text(
        "\n".join(
            json.dumps(
                {
                    "schemaVersion": 2,
                    "hashType": "primary-html-sha256",
                    **value,
                }
            )
            for value in (near_future, impossible)
        )
        + "\n",
        encoding="utf-8",
    )

    assert read_recent_urlscan("data/urlscan", 1, NOW, registry=registry) == []
    assert write_urlscan_archive("data/urlscan", [], NOW, registry) == 0
    assert archive.read_text(encoding="utf-8") == ""


def test_legacy_archive_is_not_republished_without_explicit_review(
    tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    registry_path = Path(__file__).parents[1] / "data" / "brands-lt.json"
    registry = load_brand_registry(registry_path)
    signal = _signal(
        "secure-swedbank-login.example",
        ["URLScan"],
        hashes=["a" * 64],
    )
    weak = _signal("bigbank.net", ["URLScan"], brand="Bigbank", hashes=["b" * 64])
    unconfirmed = _signal("service-revolut.example", ["URLScan"], brand="Revolut")
    archive = tmp_path / "data" / "urlscan" / "2026-08-21" / "signals.ndjson"
    archive.parent.mkdir(parents=True)
    archive.write_text(
        "\n".join(
            json.dumps({"schemaVersion": 1, **value})
            for value in (signal, weak, unconfirmed)
        )
        + "\n",
        encoding="utf-8",
    )

    records = read_recent_urlscan("data/urlscan", 1, NOW, registry=registry)

    assert records == []
