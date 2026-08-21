from __future__ import annotations

import hashlib
import ipaddress
import re
import unicodedata
from urllib.parse import quote, unquote, urlsplit, urlunsplit

from .models import SafeUrl

SCHEME = re.compile(r"^[a-z][a-z\d+.-]*://", re.IGNORECASE)
NESTED_URL = re.compile(r"(?:https?|hxxps?)://", re.IGNORECASE)
DOMAIN_IN_TEXT = re.compile(
    r"(?<![a-z\d.-])(?:[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?\.)+[a-z]{2,63}(?![a-z\d.-])",
    re.IGNORECASE,
)
HEX_TOKEN = re.compile(r"[a-f\d]{32,}", re.IGNORECASE)
TOKEN_CHARACTERS = re.compile(r"[a-z\d_-]+", re.IGNORECASE)
MAXIMUM_PUBLIC_PATH_SEGMENT = 64


def clean_text(value: object, maximum_length: int) -> str | None:
    if not isinstance(value, str):
        return None
    without_controls = "".join(" " if unicodedata.category(char) == "Cc" else char for char in value)
    cleaned = " ".join(without_controls.split()).strip()
    return cleaned[:maximum_length] if cleaned else None


def refang(value: str) -> str:
    value = re.sub(r"^hxxps:", "https:", value, flags=re.IGNORECASE)
    value = re.sub(r"^hxxp:", "http:", value, flags=re.IGNORECASE)
    return value.replace("[.]", ".").replace("[:]", ":")


def defang_host(hostname: str) -> str:
    without_brackets = hostname[1:-1] if hostname.startswith("[") and hostname.endswith("]") else hostname
    return without_brackets.replace(":", "[:]") if ":" in without_brackets else without_brackets.replace(".", "[.]")


def defang_domains_in_text(value: str) -> str:
    return DOMAIN_IN_TEXT.sub(lambda match: defang_host(match.group(0)), value)


def _sensitive_path_segment(value: str) -> bool:
    if "@" in value or len(value) > MAXIMUM_PUBLIC_PATH_SEGMENT or HEX_TOKEN.fullmatch(value):
        return True
    if len(value) < 48 or not TOKEN_CHARACTERS.fullmatch(value):
        return False
    character_groups = sum(
        bool(pattern.search(value)) for pattern in (re.compile(r"[a-z]"), re.compile(r"[A-Z]"), re.compile(r"\d"))
    )
    return character_groups >= 2


def _display_path(value: str) -> str:
    if not value or value == "/":
        return ""
    decoded = unquote(value[:2048], errors="replace")
    nested = NESTED_URL.search(decoded)
    if nested:
        decoded = f"{decoded[: nested.start()]}embedded-url-redacted"
    segments = ["redacted" if _sensitive_path_segment(segment) else segment for segment in decoded.split("/")]
    defanged = defang_domains_in_text("/".join(segments))
    return quote(defanged, safe="/%:@!$&'()*+,;=-._~[]")


def _ascii_hostname(hostname: str) -> str | None:
    try:
        ipaddress.ip_address(hostname)
        return hostname.lower()
    except ValueError:
        pass
    try:
        normalized = hostname.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    return normalized if normalized and len(normalized) <= 253 else None


def parse_and_defang_url(value: str) -> SafeUrl | None:
    cleaned = clean_text(refang(value), 4096)
    if not cleaned:
        return None
    candidate = cleaned if SCHEME.match(cleaned) else f"https://{cleaned}"
    try:
        parsed = urlsplit(candidate)
        port = parsed.port
    except ValueError:
        return None
    if parsed.scheme.lower() not in {"http", "https"} or parsed.username is not None or parsed.password is not None:
        return None
    if not parsed.hostname:
        return None
    hostname = _ascii_hostname(parsed.hostname)
    if not hostname:
        return None

    scheme = parsed.scheme.lower()
    display_scheme = "hxxps" if scheme == "https" else "hxxp"
    key_path = "" if parsed.path == "/" else quote(parsed.path[:2048], safe="/%:@!$&'()*+,;=-._~")
    display_path = _display_path(parsed.path)
    port_text = f":{port}" if port is not None else ""
    key_host = f"[{hostname}]" if ":" in hostname else hostname
    display_domain = defang_host(hostname)
    return SafeUrl(
        key=f"{scheme}://{key_host}{port_text}{key_path}",
        display_url=f"{display_scheme}://{display_domain}{port_text}{display_path}",
        display_domain=display_domain,
    )


def stable_id(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:20]


def safe_screenshot_url(value: object, allowed_hosts: list[str]) -> str | None:
    cleaned = clean_text(value, 2048)
    if not cleaned:
        return None
    try:
        parsed = urlsplit(cleaned)
    except ValueError:
        return None
    if (
        parsed.scheme.lower() != "https"
        or parsed.username is not None
        or parsed.password is not None
        or not parsed.hostname
    ):
        return None
    hostname = parsed.hostname.lower()
    if not any(hostname == host or hostname.endswith(f".{host}") for host in allowed_hosts):
        return None
    return urlunsplit(("https", parsed.netloc, parsed.path, parsed.query, ""))


def safe_feed_url(value: str) -> str:
    parsed = urlsplit(value)
    local = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme != "https" and not (parsed.scheme == "http" and local):
        raise ValueError("Feed URLs must use HTTPS (HTTP is allowed only for localhost development).")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Feed URLs must not contain credentials.")
    return value
