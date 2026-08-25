"""Ephemeral, maintainer-triggered provider checks for one published signal.

This module intentionally does not write to Radar's public data tree. Google
Safe Browsing and VirusTotal are optional analyst context, not collection
sources, match-score inputs, or benign verdicts. Detailed output is written
only when a private summary path is passed explicitly; the public Actions
workflow discards provider results after validating the request.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from http.client import HTTPMessage
from pathlib import Path
from typing import IO, Any, cast
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .brands import normalize_domain
from .safety import defang_host, refang, stable_id

GOOGLE_HOST = "safebrowsing.googleapis.com"
VIRUSTOTAL_HOST = "www.virustotal.com"
DEFAULT_SNAPSHOT_PATH = "public/data/radar.json"
DEFAULT_SAFE_BROWSING_CACHE = ".radar-local/provider-check-cache.json"
MAXIMUM_SNAPSHOT_BYTES = 512 * 1024
MAXIMUM_RESPONSE_BYTES = 512 * 1024
MAXIMUM_CACHE_BYTES = 1024 * 1024
# One URL lookup may return 64 bounded expression URLs. Seven worst-case
# entries remain below the strict 1 MiB private-cache boundary.
MAXIMUM_CACHE_ENTRIES = 7
SIGNAL_ID = re.compile(r"^[a-f\d]{20}$")
PROTOBUF_DURATION = re.compile(r"^(?P<seconds>\d{1,10})(?:\.(?P<fraction>\d{1,9}))?s$")

JsonRequester = Callable[[str, str, dict[str, str]], tuple[int, Any]]


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(
        self,
        request: Request,
        file_pointer: IO[bytes],
        code: int,
        message: str,
        headers: HTTPMessage,
        new_url: str,
    ) -> Request | None:
        destination = urlsplit(urljoin(request.full_url, new_url))
        raise HTTPError(
            request.full_url,
            code,
            f"Provider redirect to {destination.hostname or 'an unknown host'} was refused.",
            headers,
            file_pointer,
        )


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError:
        return None
    return parsed if _timestamp(parsed) == value else None


def _cache_path(path: str | Path) -> Path:
    requested = Path(path)
    if requested.is_absolute() or requested.as_posix() != DEFAULT_SAFE_BROWSING_CACHE:
        raise ValueError(f"Safe Browsing cache path must be exactly {DEFAULT_SAFE_BROWSING_CACHE}.")
    repository = Path.cwd()
    if repository.is_symlink() or repository.is_junction():
        raise ValueError("Safe Browsing cache repository root must not be a symbolic link.")
    resolved_repository = repository.resolve(strict=True)
    target = repository.joinpath(*requested.parts)
    cursor = repository
    for part in requested.parts:
        cursor /= part
        if cursor.is_symlink() or cursor.is_junction():
            raise ValueError("Safe Browsing cache path must not contain a symbolic link.")
    for parent in (repository, target.parent):
        if parent.exists() and not parent.is_dir():
            raise ValueError("Safe Browsing cache parent must be a directory.")
    if target.exists() and not target.is_file():
        raise ValueError("Safe Browsing cache target must be a regular file.")
    resolved_target = target.resolve(strict=False)
    if not resolved_target.is_relative_to(resolved_repository):
        raise ValueError("Safe Browsing cache path escapes the repository.")
    return target


def _valid_cached_threats(value: object) -> bool:
    if not isinstance(value, list) or len(value) > 64:
        return False
    for threat in value:
        if not isinstance(threat, dict) or set(threat) != {"url", "threatTypes"}:
            return False
        url = threat["url"]
        types = threat["threatTypes"]
        parsed = urlsplit(url) if isinstance(url, str) and len(url) <= 2_048 else None
        if (
            parsed is None
            or parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or not url.isascii()
            or any(ord(character) < 32 or ord(character) == 127 for character in url)
            or parsed.username is not None
            or parsed.password is not None
            or not isinstance(types, list)
            or len(types) > 16
            or types != sorted(set(types))
            or not all(isinstance(item, str) and re.fullmatch(r"[A-Z][A-Z0-9_]{1,63}", item) for item in types)
        ):
            return False
    return True


def _empty_safe_browsing_cache() -> dict[str, object]:
    return {"schemaVersion": 1, "dataset": "private-safe-browsing-cache", "entries": []}


def _valid_safe_browsing_cache(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != {"schemaVersion", "dataset", "entries"}:
        return False
    entries = value["entries"]
    if value["schemaVersion"] != 1 or value["dataset"] != "private-safe-browsing-cache":
        return False
    if not isinstance(entries, list) or len(entries) > MAXIMUM_CACHE_ENTRIES:
        return False
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"url", "checkedAt", "expiresAt", "threats"}:
            return False
        url = entry["url"]
        checked = _parse_timestamp(entry["checkedAt"])
        expires = _parse_timestamp(entry["expiresAt"])
        if (
            not isinstance(url, str)
            or len(url) > 2_048
            or url in seen
            or checked is None
            or expires is None
            or expires <= checked
            or not _valid_cached_threats(entry["threats"])
        ):
            return False
        seen.add(url)
    return True


def _read_safe_browsing_cache(path: str | Path = DEFAULT_SAFE_BROWSING_CACHE) -> dict[str, object]:
    target = _cache_path(path)
    try:
        if target.stat().st_size > MAXIMUM_CACHE_BYTES:
            raise ValueError("Safe Browsing cache exceeds 1 MiB.")
        value: object = json.loads(target.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return _empty_safe_browsing_cache()
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("Safe Browsing cache is unreadable.") from error
    if not _valid_safe_browsing_cache(value):
        raise ValueError("Safe Browsing cache has an invalid contract.")
    return cast(dict[str, object], value)


def _write_safe_browsing_cache(
    value: dict[str, object],
    path: str | Path = DEFAULT_SAFE_BROWSING_CACHE,
) -> None:
    if not _valid_safe_browsing_cache(value):
        raise ValueError("Refusing to write an invalid Safe Browsing cache.")
    body = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if len(body.encode("utf-8")) > MAXIMUM_CACHE_BYTES:
        raise ValueError("Refusing to write a Safe Browsing cache larger than 1 MiB.")
    target = _cache_path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target = _cache_path(path)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=target.parent,
            prefix=f".{target.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)
        os.chmod(target, 0o600)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _duration(value: object) -> timedelta:
    match = PROTOBUF_DURATION.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        raise ValueError("Google Safe Browsing omitted a valid cacheDuration.")
    seconds = int(match.group("seconds"))
    fraction = match.group("fraction") or ""
    # Round fractional seconds upward so the client never expires a result
    # earlier than the provider instructed.
    if fraction and any(character != "0" for character in fraction):
        seconds += 1
    if not 1 <= seconds <= 315_360_000:
        raise ValueError("Google Safe Browsing returned an unsupported cacheDuration.")
    return timedelta(seconds=seconds)


def _request_json(url: str, expected_host: str, headers: dict[str, str]) -> tuple[int, Any]:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != expected_host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
        or parsed.fragment
    ):
        raise ValueError("Provider request target is not allowlisted.")
    request = Request(  # noqa: S310 - scheme and host are fixed and validated above.
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "hecavex-radar/0.2 (+https://radar.hecavex.com/)",
            **headers,
        },
        method="GET",
    )
    opener = build_opener(_NoRedirectHandler())
    try:
        with opener.open(request, timeout=30) as response:  # noqa: S310 - fixed allowlisted hosts only.
            status = response.status
            body = response.read(MAXIMUM_RESPONSE_BYTES + 1)
    except HTTPError as error:
        # Never include the requested URL: Google authenticates in its query string.
        if error.code == 404:
            return 404, None
        raise RuntimeError(f"{expected_host} returned HTTP {error.code}.") from error
    except URLError as error:
        raise RuntimeError(f"{expected_host} request failed.") from error
    if len(body) > MAXIMUM_RESPONSE_BYTES:
        raise ValueError(f"{expected_host} response exceeded the size limit.")
    try:
        return status, json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{expected_host} returned invalid JSON.") from error


def _load_signal(signal_id: str, snapshot_path: str | Path = DEFAULT_SNAPSHOT_PATH) -> tuple[str, str]:
    if SIGNAL_ID.fullmatch(signal_id) is None:
        raise ValueError("Signal ID must be exactly 20 lowercase hexadecimal characters.")
    repository = Path.cwd().resolve()
    expected = (repository / DEFAULT_SNAPSHOT_PATH).resolve()
    target = (
        (repository / snapshot_path).resolve()
        if not Path(snapshot_path).is_absolute()
        else Path(snapshot_path).resolve()
    )
    if target != expected:
        raise ValueError(f"Snapshot path must be exactly {DEFAULT_SNAPSHOT_PATH}.")
    try:
        if target.stat().st_size > MAXIMUM_SNAPSHOT_BYTES:
            raise ValueError("Radar snapshot exceeds the size limit.")
        payload: object = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("Radar snapshot is unavailable or invalid.") from error
    if (
        not isinstance(payload, dict)
        or payload.get("schemaVersion") != 2
        or payload.get("dataset") != "live"
        or not isinstance(payload.get("signals"), list)
    ):
        raise ValueError("Radar snapshot has an unsupported contract.")
    for value in payload["signals"][:25_000]:
        if not isinstance(value, dict) or value.get("id") != signal_id:
            continue
        display_domain = value.get("domain")
        domain = normalize_domain(refang(display_domain)) if isinstance(display_domain, str) else None
        display_url = value.get("url")
        if (
            domain is None
            or not isinstance(display_url, str)
            or not display_url.startswith(("hxxp://", "hxxps://"))
            or stable_id(defang_host(domain).lower()) != signal_id
        ):
            break
        return domain, display_url
    raise ValueError("Signal ID is not present in the current public snapshot.")


def _safe_browsing(
    domain: str,
    api_key: str,
    requester: JsonRequester,
    cache: dict[str, object],
    now: datetime,
) -> dict[str, object]:
    if not _valid_safe_browsing_cache(cache):
        raise ValueError("Google Safe Browsing requires a valid private cache.")
    queried_url = f"https://{domain}/"
    entries = cache["entries"]
    if not isinstance(entries, list):
        raise ValueError("Google Safe Browsing cache entries are invalid.")
    entries[:] = [
        entry
        for entry in entries
        if isinstance(entry, dict)
        and (expires := _parse_timestamp(entry.get("expiresAt"))) is not None
        and expires > now
    ]
    active = next(
        (
            entry
            for entry in entries
            if isinstance(entry, dict)
            and entry.get("url") == queried_url
            and (expires := _parse_timestamp(entry.get("expiresAt"))) is not None
            and expires > now
        ),
        None,
    )
    cache_status = "hit"
    if active is None:
        if len(entries) >= MAXIMUM_CACHE_ENTRIES:
            raise ValueError("Google Safe Browsing private cache is full until an entry expires.")
        query = urlencode({"key": api_key, "urls": queried_url})
        status, payload = requester(f"https://{GOOGLE_HOST}/v5/urls:search?{query}", GOOGLE_HOST, {})
        if status != 200 or not isinstance(payload, dict):
            raise ValueError("Google Safe Browsing returned an unexpected response.")
        raw_threats = payload.get("threats", [])
        if not isinstance(raw_threats, list) or len(raw_threats) > 64:
            raise ValueError("Google Safe Browsing returned an unexpected threat list.")
        normalized_threats: list[dict[str, object]] = []
        for threat in raw_threats:
            if not isinstance(threat, dict):
                raise ValueError("Google Safe Browsing returned an invalid threat entry.")
            threat_url = threat.get("url")
            raw_types = threat.get("threatTypes")
            types = (
                sorted(
                    {
                        item
                        for item in raw_types
                        if isinstance(item, str) and re.fullmatch(r"[A-Z][A-Z0-9_]{1,63}", item)
                    }
                )
                if isinstance(raw_types, list)
                else []
            )
            normalized = {"url": threat_url, "threatTypes": types}
            if not _valid_cached_threats([normalized]):
                raise ValueError("Google Safe Browsing returned an invalid threat entry.")
            normalized_threats.append(normalized)
        checked_at = _timestamp(now)
        expires_at = _timestamp(now + _duration(payload.get("cacheDuration")))
        entries[:] = [entry for entry in entries if isinstance(entry, dict) and entry.get("url") != queried_url]
        entries.append(
            {
                "url": queried_url,
                "checkedAt": checked_at,
                "expiresAt": expires_at,
                "threats": normalized_threats,
            }
        )
        entries.sort(key=lambda entry: str(entry["expiresAt"]))
        active = entries[-1] if entries and entries[-1].get("url") == queried_url else next(
            entry for entry in entries if entry.get("url") == queried_url
        )
        cache_status = "refreshed"

    threats = active.get("threats") if isinstance(active, dict) else None
    if not _valid_cached_threats(threats):
        raise ValueError("Google Safe Browsing cache contains invalid threat information.")
    threat_types: set[str] = set()
    for threat in cast(list[object], threats):
        if not isinstance(threat, dict):
            raise ValueError("Google Safe Browsing cache contains invalid threat information.")
        raw_types = threat["threatTypes"]
        if not isinstance(raw_types, list):
            raise ValueError("Google Safe Browsing cache contains invalid threat information.")
        threat_types.update(cast(list[str], raw_types))
    return {
        "status": "match" if threat_types else "no-match",
        "threatTypes": sorted(threat_types),
        "cacheStatus": cache_status,
        "cacheExpiresAt": active["expiresAt"],
        "semantics": "A no-match is unknown, not a benign verdict. This result is not retained by Radar.",
        "attribution": "Google Safe Browsing",
    }


def _virus_total(
    domain: str,
    api_key: str,
    requester: JsonRequester,
) -> dict[str, object]:
    endpoint = f"https://{VIRUSTOTAL_HOST}/api/v3/domains/{quote(domain, safe='')}"
    status, payload = requester(endpoint, VIRUSTOTAL_HOST, {"x-apikey": api_key})
    if status == 404:
        return {
            "status": "not-found",
            "semantics": "No provider record is unknown, not a benign verdict. This result is not retained by Radar.",
            "attribution": "VirusTotal",
        }
    if status != 200 or not isinstance(payload, dict):
        raise ValueError("VirusTotal returned an unexpected response.")
    data = payload.get("data")
    attributes = data.get("attributes") if isinstance(data, dict) else None
    stats = attributes.get("last_analysis_stats") if isinstance(attributes, dict) else None
    if not isinstance(stats, dict):
        raise ValueError("VirusTotal omitted last-analysis statistics.")
    allowed = ("malicious", "suspicious", "harmless", "undetected", "timeout")
    normalized_stats: dict[str, int] = {}
    for name in allowed:
        count = stats.get(name, 0)
        if type(count) is not int or not 0 <= count <= 10_000:
            raise ValueError("VirusTotal returned invalid analysis statistics.")
        normalized_stats[name] = count
    last_analysis = attributes.get("last_analysis_date") if isinstance(attributes, dict) else None
    checked_at = None
    if type(last_analysis) is int and 0 <= last_analysis <= 4_102_444_800:
        checked_at = _timestamp(datetime.fromtimestamp(last_analysis, tz=UTC))
    return {
        "status": "available",
        "lastAnalysisStats": normalized_stats,
        "lastAnalysisAt": checked_at,
        "semantics": (
            "Provider-engine counts are context only and do not change Radar's match score or publication state."
        ),
        "attribution": "VirusTotal",
    }


def check_signal(
    signal_id: str,
    *,
    google_key: str = "",
    virustotal_key: str = "",
    requester: JsonRequester = _request_json,
    now: datetime | None = None,
    safe_browsing_cache: dict[str, object] | None = None,
) -> dict[str, object]:
    domain, display_url = _load_signal(signal_id)
    checked_at = now or datetime.now(UTC)
    providers: dict[str, object] = {}
    if google_key:
        if safe_browsing_cache is None:
            raise ValueError("Google Safe Browsing requires a private expiry cache.")
        providers["googleSafeBrowsing"] = _safe_browsing(
            domain,
            google_key,
            requester,
            safe_browsing_cache,
            checked_at,
        )
    else:
        providers["googleSafeBrowsing"] = {"status": "not-configured"}
    if virustotal_key:
        providers["virusTotal"] = _virus_total(domain, virustotal_key, requester)
    else:
        providers["virusTotal"] = {"status": "not-configured"}
    return {
        "schemaVersion": 1,
        "dataset": "ephemeral-analyst-provider-check",
        "checkedAt": _timestamp(checked_at),
        "signalId": signal_id,
        "candidate": display_url,
        "providers": providers,
        "retention": "Not written to Radar data or committed to Git.",
    }


def _markdown(result: dict[str, object]) -> str:
    providers = result["providers"]
    if not isinstance(providers, dict):
        raise ValueError("Provider result has an unexpected shape.")
    lines = [
        "## Ephemeral analyst provider check",
        "",
        f"- Signal: `{result['signalId']}`",
        f"- Candidate: `{result['candidate']}`",
        f"- Checked: `{result['checkedAt']}`",
        "- Retention: not added to Radar data or Git",
        "- Semantics: provider context only; no score, status, or suppression changes",
        "",
    ]
    for label, key in (("Google Safe Browsing", "googleSafeBrowsing"), ("VirusTotal", "virusTotal")):
        value = providers.get(key)
        value = value if isinstance(value, dict) else {"status": "invalid"}
        lines.extend((f"### {label}", "", f"- Status: `{value.get('status', 'unknown')}`"))
        if key == "googleSafeBrowsing" and isinstance(value.get("threatTypes"), list):
            threat_types = value["threatTypes"]
            lines.append(f"- Threat types: `{', '.join(threat_types) if threat_types else 'none returned'}`")
            if isinstance(value.get("cacheExpiresAt"), str):
                lines.append(f"- Private cache expires: `{value['cacheExpiresAt']}`")
        if key == "virusTotal" and isinstance(value.get("lastAnalysisStats"), dict):
            stats = value["lastAnalysisStats"]
            lines.append("- Last-analysis counts: " + ", ".join(f"`{name}={count}`" for name, count in stats.items()))
        if isinstance(value.get("lastAnalysisAt"), str):
            lines.append(f"- Last analysis: `{value['lastAnalysisAt']}`")
        if isinstance(value.get("semantics"), str):
            lines.append(f"- Boundary: {value['semantics']}")
        lines.append("")
    return "\n".join(lines)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run an ephemeral provider check for one published Radar signal.")
    parser.add_argument("--signal-id", required=True)
    parser.add_argument(
        "--summary",
        default="",
        help="Optional private Markdown output path. Public Actions must leave this empty.",
    )
    parser.add_argument(
        "--safe-browsing-cache",
        default=DEFAULT_SAFE_BROWSING_CACHE,
        help="Private expiry cache required when GOOGLE_SAFE_BROWSING_API_KEY is configured.",
    )
    return parser


def main(arguments: list[str] | None = None) -> int:
    options = _parser().parse_args(arguments)
    google_key = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    cache = _read_safe_browsing_cache(options.safe_browsing_cache) if google_key else None
    cache_before = json.dumps(cache, sort_keys=True) if cache is not None else None
    try:
        result = check_signal(
            options.signal_id,
            google_key=google_key,
            virustotal_key=os.environ.get("VIRUSTOTAL_API_KEY", "").strip(),
            safe_browsing_cache=cache,
        )
        markdown = _markdown(result)
        if options.summary:
            summary_path = Path(options.summary)
            summary_path.parent.mkdir(parents=True, exist_ok=True)
            with summary_path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(markdown + "\n")
        print(f"Completed ephemeral provider checks for signal {options.signal_id}.", flush=True)
        return 0
    except (RuntimeError, ValueError) as error:
        print(f"Provider check failed: {error}", flush=True)
        return 1
    finally:
        if cache is not None and json.dumps(cache, sort_keys=True) != cache_before:
            _write_safe_browsing_cache(cache, options.safe_browsing_cache)


if __name__ == "__main__":
    raise SystemExit(main())
