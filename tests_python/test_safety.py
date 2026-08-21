import re

from hecavex_radar.safety import defang_host, parse_and_defang_url, safe_screenshot_url, stable_id


def test_defangs_host_and_removes_query_and_fragment() -> None:
    result = parse_and_defang_url("https://Login.Example.test/reset?token=victim-secret#continue")
    assert result is not None
    assert result.key == "https://login.example.test/reset"
    assert result.display_url == "hxxps://login[.]example[.]test/reset"
    assert result.display_domain == "login[.]example[.]test"


def test_accepts_already_defanged_input() -> None:
    result = parse_and_defang_url("hxxp://login[.]example[.]test/path")
    assert result is not None
    assert result.display_url == "hxxp://login[.]example[.]test/path"


def test_rejects_dangerous_schemes_and_credentials() -> None:
    assert parse_and_defang_url("javascript:alert(1)") is None
    assert parse_and_defang_url("https://user:password@example.test/login") is None
    assert parse_and_defang_url("file:///etc/passwd") is None


def test_defangs_ip_addresses() -> None:
    assert defang_host("192.0.2.4") == "192[.]0[.]2[.]4"
    assert defang_host("2001:db8::4") == "2001[:]db8[:][:]4"


def test_only_accepts_https_screenshots_on_allowed_hosts() -> None:
    assert (
        safe_screenshot_url("https://urlscan.io/screenshots/example.png", ["urlscan.io"])
        == "https://urlscan.io/screenshots/example.png"
    )
    assert safe_screenshot_url("https://images.attacker.test/example.png", ["urlscan.io"]) is None
    assert safe_screenshot_url("http://urlscan.io/screenshots/example.png", ["urlscan.io"]) is None


def test_creates_stable_non_revealing_identifiers() -> None:
    identifier = stable_id("https://example.test/path")
    assert re.fullmatch(r"[a-f0-9]{20}", identifier)
    assert identifier == stable_id("https://example.test/path")


def test_redacts_nested_urls_and_sensitive_path_segments() -> None:
    nested = parse_and_defang_url("https://redirect.example.test/href=https://target.example/login")
    sensitive = parse_and_defang_url(
        "https://login.example.test/reset/person@example.test/0123456789abcdef0123456789abcdef"
    )
    assert nested is not None and sensitive is not None
    assert nested.display_url == "hxxps://redirect[.]example[.]test/href=embedded-url-redacted"
    assert "target.example" not in nested.display_url
    assert sensitive.display_url == "hxxps://login[.]example[.]test/reset/redacted/redacted"
