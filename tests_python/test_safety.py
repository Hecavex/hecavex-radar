import re

from hecavex_radar.safety import (
    clean_text,
    defang_host,
    parse_and_defang_url,
    safe_reference_url,
    safe_screenshot_url,
    stable_id,
)


def test_strips_unicode_format_controls_from_public_text() -> None:
    cleaned = clean_text("Hosting \u202ereversed.exe\u202c\u200b label", 160)

    assert cleaned == "Hosting reversed.exe label"
    assert cleaned is not None
    assert all(character not in cleaned for character in ("\u202e", "\u202c", "\u200b"))


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


def test_only_accepts_canonical_urlscan_screenshots() -> None:
    screenshot = "https://urlscan.io/screenshots/11111111-1111-1111-1111-111111111111.png"
    assert (
        safe_screenshot_url(screenshot)
        == screenshot
    )
    assert (
        safe_screenshot_url(f"{screenshot}?token=private#fragment")
        == screenshot
    )
    assert safe_screenshot_url("https://images.attacker.test/example.png") is None
    assert safe_screenshot_url("https://cdn.urlscan.io/screenshots/example.png") is None
    assert safe_screenshot_url("http://urlscan.io/screenshots/example.png") is None
    assert safe_screenshot_url("https://urlscan.io:444/screenshots/example.png") is None
    assert safe_screenshot_url("https://urlscan.io/screenshots/example.png") is None
    assert safe_screenshot_url("https://urlscan.io/api/v1/screenshots/example.png") is None
    assert safe_screenshot_url(f"{screenshot}/extra") is None


def test_only_accepts_fixed_urlscan_report_links() -> None:
    report = "https://urlscan.io/result/11111111-1111-1111-1111-111111111111/"
    assert safe_reference_url(report) == report
    assert safe_reference_url(report.rstrip("/")) == report
    assert safe_reference_url("https://attacker.example/result/11111111-1111-1111-1111-111111111111/") is None
    assert safe_reference_url(f"{report}?redirect=https://attacker.example") is None


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


def test_redacts_public_identifier_and_phone_like_path_segments() -> None:
    result = parse_and_defang_url(
        "https://login.example.test/login/"
        "11111111-1111-1111-1111-111111111111/"
        "+37061234567/123456789/Abcdefghijklmnopqrstuv1234?secret=value#continue"
    )
    ordinary = parse_and_defang_url("https://login.example.test/login/20260821")

    assert result is not None and ordinary is not None
    assert result.display_url == (
        "hxxps://login[.]example[.]test/login/redacted/redacted/redacted/redacted"
    )
    assert ordinary.display_url == "hxxps://login[.]example[.]test/login/20260821"


def test_redacts_sensitive_key_value_and_matrix_path_segments() -> None:
    uuid = "11111111-1111-1111-1111-111111111111"
    phone = "37061234567"
    opaque_value = "Abcdefghijklmnopqrstuv1234"
    key_value = parse_and_defang_url(
        f"https://login.example.test/id={uuid}/phone={phone}/token={opaque_value}"
    )
    matrix = parse_and_defang_url(
        f"https://login.example.test/login;id={uuid}/phone;{phone}/token;{opaque_value}"
    )
    ordinary = parse_and_defang_url("https://login.example.test/page=login/mode;preview")

    assert key_value is not None and matrix is not None and ordinary is not None
    assert key_value.display_url == "hxxps://login[.]example[.]test/redacted/redacted/redacted"
    assert matrix.display_url == "hxxps://login[.]example[.]test/redacted/redacted/redacted"
    assert ordinary.display_url == "hxxps://login[.]example[.]test/page=login/mode;preview"
    for private_value in (uuid, phone, opaque_value):
        assert private_value not in key_value.display_url
        assert private_value not in matrix.display_url


def test_sensitive_keys_redact_nonempty_lowercase_and_short_values() -> None:
    private_values = {
        "token": "abcdefghijklmnopqrstuvwx",
        "session": "a" * 32,
        "auth": "continue",
        "key": "value",
        "code": "1234",
        "email": "person@example.test",
        "phone": "1234",
        "user": "alice",
        "account": "current",
        "id": "7",
    }
    path = "/".join(f"{key}={value}" for key, value in private_values.items())
    result = parse_and_defang_url(f"https://login.example.test/{path}/auth;continue")

    assert result is not None
    assert result.display_url == "hxxps://login[.]example[.]test/" + "/".join(
        ["redacted"] * 11
    )
    for private_value in private_values.values():
        assert private_value not in result.display_url


def test_sensitive_keys_redact_values_in_following_path_segments() -> None:
    private_routes = {
        "token": "abcdefghijklmnopqrstuvwx",
        "session": "abcdefghijklmnopqrstuvwxyzabcdef",
        "user": "alice",
        "id": "7",
    }

    for key, private_value in private_routes.items():
        result = parse_and_defang_url(f"https://login.example.test/{key}/{private_value}")

        assert result is not None
        assert result.display_url == f"hxxps://login[.]example[.]test/{key}/redacted"
        assert private_value not in result.display_url

    ordinary = parse_and_defang_url("https://login.example.test/page/login")
    assert ordinary is not None
    assert ordinary.display_url == "hxxps://login[.]example[.]test/page/login"


def test_redacts_long_lowercase_opaque_segments_but_keeps_short_slugs() -> None:
    opaque = "abcdefghijklmnopqrstuvwx"
    sensitive = parse_and_defang_url(f"https://login.example.test/reset/{opaque}")
    ordinary = parse_and_defang_url("https://login.example.test/help/update-password")

    assert sensitive is not None and ordinary is not None
    assert sensitive.display_url == "hxxps://login[.]example[.]test/reset/redacted"
    assert opaque not in sensitive.display_url
    assert ordinary.display_url == "hxxps://login[.]example[.]test/help/update-password"


def test_repeatedly_decodes_paths_before_privacy_redaction() -> None:
    sensitive_values = [
        "person%2540example.test",
        "%2533%2537%2530%2536%2531%2532%2533%2534%2535%2536%2537",
        "token%253Dalice",
        "%25252525252540",
    ]

    for value in sensitive_values:
        result = parse_and_defang_url(f"https://login.example.test/reset/{value}")

        assert result is not None
        assert result.display_url == "hxxps://login[.]example[.]test/reset/redacted"

    ordinary = parse_and_defang_url("https://login.example.test/help/update%20password")
    assert ordinary is not None
    assert ordinary.display_url == "hxxps://login[.]example[.]test/help/update%20password"
