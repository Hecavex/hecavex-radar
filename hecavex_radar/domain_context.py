"""Bounded DNS and RDAP context for already-published Radar candidates.

This collector performs DNS-over-HTTPS and RDAP requests only.  It never sends
HTTP traffic to a candidate host, executes page content, or stores registrant
personal data.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import tempfile
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from http.client import HTTPMessage
from pathlib import Path
from typing import IO, Any, cast
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

import tldextract

from .brands import normalize_domain
from .models import SignalDomainContextRecord
from .safety import clean_text, defang_domains_in_text, defang_host, refang, stable_id

DOH_HOST = "cloudflare-dns.com"
DOH_ROOT = f"https://{DOH_HOST}/dns-query"
IANA_HOST = "data.iana.org"
IANA_BOOTSTRAP = f"https://{IANA_HOST}/rdap/dns.json"
DEFAULT_STATE_PATH = "data/enrichment/domain-context.json"
DEFAULT_SNAPSHOT_PATH = "public/data/radar.json"
MAXIMUM_RESPONSE_BYTES = 2 * 1024 * 1024
MAXIMUM_STATE_BYTES = 4 * 1024 * 1024
MAXIMUM_RECORDS = 2_500
MAXIMUM_ANSWERS_PER_TYPE = 12
DNS_TYPES = ("A", "AAAA", "CNAME", "NS", "MX")
TYPE_CODES = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "AAAA": 28}
UTC_MILLISECONDS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
SLUG = re.compile(r"^[a-z\d]+(?:-[a-z\d]+)*$")
SIGNAL_ID = re.compile(r"^[a-f\d]{20}$")
EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)

JsonRequester = Callable[[str, str], Any]


class _SameHostRedirectHandler(HTTPRedirectHandler):
    def __init__(self, hostname: str) -> None:
        self._hostname = hostname
        super().__init__()

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
        if (
            code not in {301, 302, 303, 307, 308}
            or destination.scheme != "https"
            or destination.hostname != self._hostname
            or destination.username is not None
            or destination.password is not None
            or destination.port is not None
        ):
            raise HTTPError(
                request.full_url,
                code,
                "Enrichment returned an unapproved redirect.",
                headers,
                file_pointer,
            )
        return super().redirect_request(request, file_pointer, code, message, headers, destination.geturl())


def _bounded_integer(value: str | None, fallback: int, minimum: int, maximum: int) -> int:
    if not value or not value.strip():
        return fallback
    try:
        parsed = int(value)
    except ValueError:
        return fallback
    return min(maximum, max(minimum, parsed))


def _timestamp(value: datetime) -> str:
    candidate = value.astimezone(UTC) if value.tzinfo is not None else value.replace(tzinfo=UTC)
    return candidate.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip() or len(value) > 48:
        return None
    candidate = value.strip().replace(" ", "T")
    try:
        parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _canonical_timestamp(value: object) -> str | None:
    parsed = _parse_timestamp(value)
    return _timestamp(parsed) if parsed is not None else None


def _safe_path(value: str | Path, expected: str) -> Path:
    repository = Path.cwd().resolve()
    target = (repository / value).resolve() if not Path(value).is_absolute() else Path(value).resolve()
    allowed = (repository / expected).resolve()
    if target != allowed:
        raise ValueError(f"Path must be exactly {expected}.")
    return target


def _request_json(url: str, expected_host: str) -> Any:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != expected_host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
        or parsed.fragment
    ):
        raise ValueError("Enrichment request target is not allowlisted.")
    opener = build_opener(_SameHostRedirectHandler(expected_host))
    if expected_host == DOH_HOST:
        accept = "application/dns-json"
    elif expected_host == IANA_HOST:
        accept = "application/json"
    else:
        accept = "application/rdap+json, application/json"
    request = Request(  # noqa: S310 - scheme and host are enforced above
        url,
        headers={
            "Accept": accept,
            "User-Agent": "hecavex-radar/0.2 (+https://radar.hecavex.com/)",
        },
        method="GET",
    )
    try:
        with opener.open(request, timeout=30) as response:  # noqa: S310 - scheme and host are enforced above
            content_length = response.headers.get("Content-Length")
            if content_length and int(content_length) > MAXIMUM_RESPONSE_BYTES:
                raise ValueError("Enrichment response exceeds 2 MiB.")
            body = response.read(MAXIMUM_RESPONSE_BYTES + 1)
    except HTTPError as error:
        if error.code == 404:
            return None
        raise RuntimeError(f"Enrichment endpoint returned HTTP {error.code}.") from error
    except URLError as error:
        raise RuntimeError("Enrichment request failed.") from error
    if len(body) > MAXIMUM_RESPONSE_BYTES:
        raise ValueError("Enrichment response exceeds 2 MiB.")
    try:
        return json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Enrichment endpoint returned invalid JSON.") from error


def _snapshot_signals(path: str | Path) -> list[tuple[str, str]]:
    target = _safe_path(path, DEFAULT_SNAPSHOT_PATH)
    try:
        if target.stat().st_size > 512 * 1024:
            raise ValueError("Radar snapshot exceeds 512 KiB.")
        payload: object = json.loads(target.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("Radar snapshot is unreadable.") from error
    if (
        not isinstance(payload, dict)
        or payload.get("schemaVersion") != 2
        or payload.get("dataset") != "live"
        or not isinstance(payload.get("signals"), list)
    ):
        raise ValueError("Radar snapshot has an unsupported contract.")
    signals: list[tuple[str, str]] = []
    for item in payload["signals"][:MAXIMUM_RECORDS]:
        if not isinstance(item, dict):
            continue
        identifier = item.get("id")
        display_domain = item.get("domain")
        domain = normalize_domain(refang(display_domain)) if isinstance(display_domain, str) else None
        if (
            not isinstance(identifier, str)
            or SIGNAL_ID.fullmatch(identifier) is None
            or domain is None
            or identifier != stable_id(defang_host(domain).lower())
        ):
            continue
        signals.append((identifier, domain))
    return sorted(set(signals))


def _bootstrap_services(value: object) -> dict[str, str]:
    if not isinstance(value, dict) or not isinstance(value.get("services"), list):
        raise ValueError("IANA RDAP bootstrap has an unexpected shape.")
    services: dict[str, str] = {}
    for raw in value["services"]:
        if (
            not isinstance(raw, list)
            or len(raw) != 2
            or not isinstance(raw[0], list)
            or not isinstance(raw[1], list)
        ):
            continue
        endpoint = next((item for item in raw[1] if isinstance(item, str) and item.startswith("https://")), None)
        if endpoint is None:
            continue
        parsed = urlsplit(endpoint)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port is not None
        ):
            continue
        for suffix in raw[0]:
            if isinstance(suffix, str) and re.fullmatch(r"[a-z\d-]{2,63}", suffix.lower()):
                services[suffix.lower()] = endpoint
    if not services:
        raise ValueError("IANA RDAP bootstrap contains no usable services.")
    return services


def _dns_value(record_type: str, value: object) -> str | None:
    if not isinstance(value, str) or not value.strip() or len(value) > 512:
        return None
    raw = value.strip()
    if record_type in {"A", "AAAA"}:
        try:
            return defang_host(str(ipaddress.ip_address(raw)))
        except ValueError:
            return None
    if record_type == "MX":
        parts = raw.split(maxsplit=1)
        if len(parts) != 2 or not parts[0].isdigit():
            return None
        normalized = normalize_domain(parts[1].removesuffix("."))
        return f"{int(parts[0])} {defang_host(normalized)}" if normalized is not None else None
    normalized = normalize_domain(raw.removesuffix("."))
    return defang_host(normalized) if normalized is not None else None


def _dns_context(domain: str, requester: JsonRequester) -> dict[str, object]:
    records: dict[str, list[str]] = {record_type.lower(): [] for record_type in DNS_TYPES}
    ttl_values: list[int] = []
    successful = 0
    for record_type in DNS_TYPES:
        url = f"{DOH_ROOT}?{urlencode({'name': domain, 'type': record_type})}"
        payload = requester(url, DOH_HOST)
        status = payload.get("Status") if isinstance(payload, dict) else None
        if not isinstance(payload, dict) or type(status) is not int or status not in {0, 3}:
            continue
        successful += 1
        answers = payload.get("Answer")
        if not isinstance(answers, list):
            continue
        for answer in answers[:MAXIMUM_ANSWERS_PER_TYPE]:
            if not isinstance(answer, dict) or answer.get("type") != TYPE_CODES[record_type]:
                continue
            normalized = _dns_value(record_type, answer.get("data"))
            if normalized is not None and normalized not in records[record_type.lower()]:
                records[record_type.lower()].append(normalized)
            ttl = answer.get("TTL")
            if type(ttl) is int and 0 <= ttl <= 2_147_483_647:
                ttl_values.append(ttl)
    if successful == 0:
        raise RuntimeError("DNS context returned no completed queries.")
    return {**records, "minimumTtl": min(ttl_values) if ttl_values else None, "queriesCompleted": successful}


def _safe_registrar(value: object) -> str | None:
    text = clean_text(value, 160)
    return clean_text(defang_domains_in_text(text), 160) if text else None


def _vcard_name(value: object) -> str | None:
    if not isinstance(value, list) or len(value) != 2 or value[0] != "vcard" or not isinstance(value[1], list):
        return None
    for item in value[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
            return _safe_registrar(item[3])
    return None


def _registration_context(value: object) -> dict[str, object] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError("RDAP response has an unexpected shape.")
    dates: dict[str, datetime] = {}
    events = value.get("events")
    actions = {
        "registration": "registeredAt",
        "last changed": "updatedAt",
        "expiration": "expiresAt",
    }
    if isinstance(events, list):
        for event in events[:32]:
            if not isinstance(event, dict):
                continue
            field = actions.get(str(event.get("eventAction", "")).casefold())
            timestamp = _parse_timestamp(event.get("eventDate"))
            if not field or timestamp is None:
                continue
            previous = dates.get(field)
            if previous is None or (field == "registeredAt" and timestamp < previous) or (
                field != "registeredAt" and timestamp > previous
            ):
                dates[field] = timestamp
    registrar = None
    entities = value.get("entities")
    if isinstance(entities, list):
        for entity in entities[:32]:
            if not isinstance(entity, dict) or not isinstance(entity.get("roles"), list):
                continue
            if "registrar" in entity["roles"]:
                registrar = _vcard_name(entity.get("vcardArray"))
                if registrar:
                    break
    statuses: list[str] = []
    raw_statuses = value.get("status")
    if isinstance(raw_statuses, list):
        for raw in raw_statuses[:16]:
            cleaned = clean_text(raw, 64)
            slug = re.sub(r"[^a-z\d]+", "-", cleaned.casefold()).strip("-") if cleaned else ""
            if slug and SLUG.fullmatch(slug) and slug not in statuses:
                statuses.append(slug)
    context: dict[str, object] = {
        "registrar": registrar,
        "registeredAt": _timestamp(dates["registeredAt"]) if "registeredAt" in dates else None,
        "updatedAt": _timestamp(dates["updatedAt"]) if "updatedAt" in dates else None,
        "expiresAt": _timestamp(dates["expiresAt"]) if "expiresAt" in dates else None,
        "statuses": statuses,
    }
    return context if any(value for value in context.values()) else None


def _rdap_context(domain: str, services: dict[str, str], requester: JsonRequester) -> dict[str, object] | None:
    extracted = EXTRACT(domain)
    registered_domain = normalize_domain(extracted.top_domain_under_public_suffix) or domain
    suffix = registered_domain.rsplit(".", 1)[-1]
    base = services.get(suffix)
    if base is None:
        return None
    parsed = urlsplit(base)
    if not parsed.hostname:
        return None
    endpoint = base.rstrip("/") + "/domain/" + quote(registered_domain, safe="")
    context = _registration_context(requester(endpoint, parsed.hostname))
    if context is not None:
        context["domain"] = defang_host(registered_domain)
    return context


def _empty_state(now: datetime) -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "dataset": "domain-context",
        "generatedAt": _timestamp(now),
        "cursor": 0,
        "latestRun": None,
        "records": [],
    }


def _is_string_list(value: object, maximum: int) -> bool:
    return isinstance(value, list) and len(value) <= maximum and all(
        isinstance(item, str) and 0 < len(item) <= 512 for item in value
    )


def _canonical_defanged_domain(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = normalize_domain(refang(value))
    return normalized if normalized is not None and defang_host(normalized) == value else None


def _valid_record(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "signalId", "domain", "observedAt", "dns", "registration"
    }:
        return False
    domain = normalize_domain(refang(value["domain"])) if isinstance(value["domain"], str) else None
    dns = value["dns"]
    registration = value["registration"]
    if (
        not isinstance(value["signalId"], str)
        or SIGNAL_ID.fullmatch(value["signalId"]) is None
        or domain is None
        or defang_host(domain) != value["domain"]
        or stable_id(value["domain"].lower()) != value["signalId"]
        or _parse_timestamp(value["observedAt"]) is None
        or not isinstance(dns, dict)
        or set(dns) != {"a", "aaaa", "cname", "ns", "mx", "minimumTtl", "queriesCompleted"}
        or not all(
            _is_string_list(dns[field], MAXIMUM_ANSWERS_PER_TYPE)
            for field in ("a", "aaaa", "cname", "ns", "mx")
        )
        or (
            dns["minimumTtl"] is not None
            and (type(dns["minimumTtl"]) is not int or not 0 <= dns["minimumTtl"] <= 2_147_483_647)
        )
        or type(dns["queriesCompleted"]) is not int
        or not 0 <= dns["queriesCompleted"] <= len(DNS_TYPES)
    ):
        return False
    if registration is None:
        return True
    allowed_registration_fields = {"registrar", "registeredAt", "updatedAt", "expiresAt", "statuses"}
    if not isinstance(registration, dict) or not set(registration).issubset(
        allowed_registration_fields | {"domain"}
    ) or not allowed_registration_fields.issubset(registration):
        return False
    registration_domain = registration.get("domain")
    return (
        (registration_domain is None or _canonical_defanged_domain(registration_domain) is not None)
        and (registration["registrar"] is None or isinstance(registration["registrar"], str))
        and all(
            registration[field] is None or _parse_timestamp(registration[field]) is not None
            for field in ("registeredAt", "updatedAt", "expiresAt")
        )
        and _is_string_list(registration["statuses"], 16)
    )


def _valid_state(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "schemaVersion", "dataset", "generatedAt", "cursor", "latestRun", "records"
    }:
        return False
    records = value["records"]
    latest = value["latestRun"]
    if (
        value["schemaVersion"] != 1
        or value["dataset"] != "domain-context"
        or _parse_timestamp(value["generatedAt"]) is None
        or type(value["cursor"]) is not int
        or not 0 <= value["cursor"] <= MAXIMUM_RECORDS
        or not isinstance(records, list)
        or len(records) > MAXIMUM_RECORDS
        or not all(_valid_record(record) for record in records)
    ):
        return False
    if latest is None:
        return True
    return (
        isinstance(latest, dict)
        and set(latest) == {"startedAt", "endedAt", "outcome", "attempted", "completed"}
        and _parse_timestamp(latest["startedAt"]) is not None
        and _parse_timestamp(latest["endedAt"]) is not None
        and latest["outcome"] in {"completed", "partial", "failed", "empty"}
        and type(latest["attempted"]) is int
        and type(latest["completed"]) is int
        and 0 <= latest["completed"] <= latest["attempted"] <= MAXIMUM_RECORDS
    )


def read_state(path: str | Path = DEFAULT_STATE_PATH, *, now: datetime | None = None) -> dict[str, Any]:
    target = _safe_path(path, DEFAULT_STATE_PATH)
    try:
        if target.stat().st_size > MAXIMUM_STATE_BYTES:
            raise ValueError("Domain context exceeds 4 MiB.")
        value: object = json.loads(target.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return _empty_state(now or datetime.now(UTC))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("Domain context is unreadable.") from error
    if not _valid_state(value):
        raise ValueError("Domain context has an invalid contract.")
    return cast(dict[str, Any], value)


def public_records(
    path: str | Path = DEFAULT_STATE_PATH,
    *,
    now: datetime | None = None,
    retention_days: int | None = None,
) -> dict[str, SignalDomainContextRecord]:
    """Return current, contract-validated records suitable for public sidecars."""

    current = (now or datetime.now(UTC)).astimezone(UTC)
    keep_days = retention_days if retention_days is not None else _bounded_integer(
        os.environ.get("DOMAIN_CONTEXT_RETENTION_DAYS"), 14, 1, 90
    )
    cutoff = current - timedelta(days=keep_days)
    future_limit = current + timedelta(minutes=5)
    records: dict[str, SignalDomainContextRecord] = {}
    for record in read_state(path, now=current)["records"]:
        observed_at = _parse_timestamp(record["observedAt"])
        if observed_at is None or observed_at < cutoff or observed_at > future_limit:
            continue
        records[record["signalId"]] = cast(SignalDomainContextRecord, dict(record))
    return records


def write_state(value: dict[str, Any], path: str | Path = DEFAULT_STATE_PATH) -> Path:
    if not _valid_state(value):
        raise ValueError("Refusing to write invalid domain context.")
    target = _safe_path(path, DEFAULT_STATE_PATH)
    body = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if len(body.encode("utf-8")) > MAXIMUM_STATE_BYTES:
        raise ValueError("Refusing to write domain context larger than 4 MiB.")
    target.parent.mkdir(parents=True, exist_ok=True)
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
        temporary.chmod(0o600)
        os.replace(temporary, target)
    except Exception:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise
    return target


def collect(
    requester: JsonRequester = _request_json,
    *,
    now: datetime | None = None,
    state_path: str | Path = DEFAULT_STATE_PATH,
    snapshot_path: str | Path = DEFAULT_SNAPSHOT_PATH,
    per_run: int | None = None,
    retention_days: int | None = None,
) -> dict[str, Any]:
    started = (now or datetime.now(UTC)).astimezone(UTC)
    run_deadline = time.monotonic() + _bounded_integer(
        os.environ.get("DOMAIN_CONTEXT_RUN_BUDGET_SECONDS"), 600, 60, 660
    )
    state = read_state(state_path, now=started)
    signals = _snapshot_signals(snapshot_path)
    live_ids = {identifier for identifier, _domain in signals}
    keep_days = retention_days if retention_days is not None else _bounded_integer(
        os.environ.get("DOMAIN_CONTEXT_RETENTION_DAYS"), 14, 1, 90
    )
    cutoff = started - timedelta(days=keep_days)
    records = {
        record["signalId"]: record
        for record in state["records"]
        if record["signalId"] in live_ids and cast(datetime, _parse_timestamp(record["observedAt"])) >= cutoff
    }
    limit = per_run or _bounded_integer(os.environ.get("DOMAIN_CONTEXT_PER_RUN"), 20, 1, 100)
    if signals:
        cursor = state["cursor"] % len(signals)
        selected = [signals[(cursor + offset) % len(signals)] for offset in range(min(limit, len(signals)))]
        state["cursor"] = (cursor + len(selected)) % len(signals)
    else:
        selected = []
        state["cursor"] = 0

    services: dict[str, str] = {}
    bootstrap_error = False
    if selected:
        try:
            services = _bootstrap_services(requester(IANA_BOOTSTRAP, IANA_HOST))
        except Exception:
            bootstrap_error = True
    completed = 0
    failures: list[str] = []
    if bootstrap_error:
        failures.append("RdapBootstrap")
    for identifier, domain in selected:
        if time.monotonic() >= run_deadline:
            failures.append("RunBudget")
            break
        try:
            dns = _dns_context(domain, requester)
            registration = None if bootstrap_error else _rdap_context(domain, services, requester)
            records[identifier] = {
                "signalId": identifier,
                "domain": defang_host(domain),
                "observedAt": _timestamp(started),
                "dns": dns,
                "registration": registration,
            }
            completed += 1
            queries_completed = cast(int, dns["queriesCompleted"])
            if queries_completed < len(DNS_TYPES):
                failures.append("DnsPartial")
        except Exception as error:
            failures.append(type(error).__name__)
            continue
    attempted = len(selected)
    if attempted == 0:
        outcome = "empty"
    elif completed == attempted and not failures:
        outcome = "completed"
    elif completed:
        outcome = "partial"
    else:
        outcome = "failed"
    ended = datetime.now(UTC) if now is None else started
    state.update(
        {
            "generatedAt": _timestamp(ended),
            "latestRun": {
                "startedAt": _timestamp(started),
                "endedAt": _timestamp(ended),
                "outcome": outcome,
                "attempted": attempted,
                "completed": completed,
            },
            "records": sorted(
                records.values(),
                key=lambda record: (record["domain"], record["signalId"]),
            )[:MAXIMUM_RECORDS],
        }
    )
    write_state(state, state_path)
    if failures:
        print(f"Domain context encountered {len(failures)} bounded request or parsing failures.", flush=True)
    print(f"Domain context {outcome}: {completed}/{attempted} candidates refreshed.", flush=True)
    return cast(dict[str, Any], state["latestRun"])


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Refresh bounded DNS and RDAP context for public Radar candidates.")
    parser.add_argument("--state", default=os.environ.get("DOMAIN_CONTEXT_PATH", DEFAULT_STATE_PATH))
    parser.add_argument("--snapshot", default=os.environ.get("RADAR_OUTPUT", DEFAULT_SNAPSHOT_PATH))
    return parser


def main(arguments: list[str] | None = None) -> int:
    options = _parser().parse_args(arguments)
    try:
        result = collect(state_path=options.state, snapshot_path=options.snapshot)
    except Exception as error:
        print(f"Domain context failed before state publication: {type(error).__name__}", flush=True)
        return 1
    return 0 if result["outcome"] in {"completed", "partial", "empty"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
