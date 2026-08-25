"""Bounded public intelligence sidecars for one Radar signal at a time."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import tempfile
from collections.abc import Iterable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal, cast

import tldextract

from .brands import normalize_domain
from .models import (
    AssessmentDetail,
    CertificateDetail,
    CertificateFingerprints,
    NetworkDetail,
    PageDetail,
    RadarSignal,
    RawDomainIntelligence,
    SignalContextChange,
    SignalDetail,
    SignalDomainContext,
    SignalDomainContextRecord,
    SignalObservation,
)
from .safety import (
    clean_text,
    defang_domains_in_text,
    defang_host,
    refang,
    safe_reference_url,
    stable_id,
)

DETAIL_SOURCES = frozenset({"CertStream", "URLScan"})
MAXIMUM_DETAIL_BYTES = 16 * 1024
MAXIMUM_DETAIL_SET_BYTES = 3 * 1024 * 1024
MAXIMUM_OBSERVATIONS = 2
MAXIMUM_SAN_SAMPLES = 12
MAXIMUM_SAN_COUNT = 500
MAXIMUM_CONTEXT_CHANGES = 6
MAXIMUM_CONTEXT_JOURNAL_BYTES = 10 * 1024 * 1024
MAXIMUM_CONTEXT_EVENTS_READ = 5_000
EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]{1,64}@[a-z\d.-]{1,253}", re.IGNORECASE)
SCHEME = re.compile(r"\bhttps?://", re.IGNORECASE)
SLUG = re.compile(r"^[a-z\d]+(?:-[a-z\d]+)*$")
DETAIL_ID = re.compile(r"^[a-f\d]{20}$")
DETAIL_PREFIX = re.compile(r"^[a-f\d]{2}$")
EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)
CONTEXT_CHANGE_COMPONENTS = {
    "first-resolving": "dns",
    "stopped-resolving": "dns",
    "dns-a-changed": "dns",
    "dns-aaaa-changed": "dns",
    "dns-cname-changed": "dns",
    "dns-ns-changed": "dns",
    "dns-mx-changed": "dns",
    "rdap-registrar-changed": "rdap",
    "rdap-status-changed": "rdap",
    "rdap-expiry-changed": "rdap",
    "urlscan-title-changed": "urlscan",
    "urlscan-redirect-changed": "urlscan",
    "urlscan-http-status-changed": "urlscan",
    "urlscan-ip-changed": "urlscan",
    "urlscan-asn-changed": "urlscan",
    "urlscan-primary-html-sha256-changed": "urlscan",
    "urlscan-certificate-fingerprint-changed": "urlscan",
    "certificate-reissued": "urlscan",
}
CONTEXT_CHANGE_FIELDS = {
    "first-resolving": frozenset({"a", "aaaa", "cname"}),
    "stopped-resolving": frozenset({"a", "aaaa", "cname"}),
    "dns-a-changed": frozenset({"a"}),
    "dns-aaaa-changed": frozenset({"aaaa"}),
    "dns-cname-changed": frozenset({"cname"}),
    "dns-ns-changed": frozenset({"ns"}),
    "dns-mx-changed": frozenset({"mx"}),
    "rdap-registrar-changed": frozenset({"registrar"}),
    "rdap-status-changed": frozenset({"statuses"}),
    "rdap-expiry-changed": frozenset({"expiresAt"}),
    "urlscan-title-changed": frozenset({"pageTitle"}),
    "urlscan-redirect-changed": frozenset({"redirectedToDomain"}),
    "urlscan-http-status-changed": frozenset({"httpStatus"}),
    "urlscan-ip-changed": frozenset({"ipAddress"}),
    "urlscan-asn-changed": frozenset({"asn"}),
    "urlscan-primary-html-sha256-changed": frozenset({"primaryHtmlSha256"}),
    "urlscan-certificate-fingerprint-changed": frozenset({"certificateFingerprintSha256"}),
    "certificate-reissued": frozenset(
        {
            "certificateFingerprintSha256",
            "certificateIssuer",
            "certificateNotBefore",
            "certificateNotAfter",
        }
    ),
}
CONTEXT_SOURCES = {
    "dns": ("Cloudflare DNS", "https://cloudflare-dns.com/dns-query"),
    "rdap": ("RDAP", "https://data.iana.org/rdap/dns.json"),
    "urlscan": ("URLScan", "https://urlscan.io/"),
}


@dataclass(frozen=True, slots=True)
class NormalizedIntelligence:
    signal_id: str
    domain: str
    observation: SignalObservation


def _timestamp(value: object, fallback: str | None = None) -> str | None:
    candidate = value if isinstance(value, str) and value.strip() else fallback
    if not candidate:
        return None
    try:
        parsed = datetime.fromisoformat(candidate.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _safe_text(value: object, maximum: int) -> str | None:
    text = clean_text(value, maximum * 2)
    if not text:
        return None
    text = EMAIL.sub("[email redacted]", text).replace("@", "[at]")
    text = SCHEME.sub(lambda match: "hxxps://" if match.group(0).lower().startswith("https") else "hxxp://", text)
    return clean_text(defang_domains_in_text(text), maximum)


def _page(value: object) -> PageDetail | None:
    if not isinstance(value, dict):
        return None
    title = _safe_text(value.get("title"), 160)
    status_value = value.get("httpStatus")
    if isinstance(status_value, str) and status_value.isdecimal():
        status_value = int(status_value)
    status = (
        status_value
        if isinstance(status_value, int) and not isinstance(status_value, bool) and 100 <= status_value <= 599
        else None
    )
    return {"title": title, "httpStatus": status} if title is not None or status is not None else None


def _asn(value: object) -> int | None:
    if isinstance(value, str):
        candidate = value.strip().upper().removeprefix("AS")
        value = int(candidate) if candidate.isdecimal() else None
    return value if isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 4_294_967_295 else None


def _ip(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return defang_host(str(ipaddress.ip_address(refang(value.strip()))))
    except ValueError:
        return None


def _network(value: object) -> NetworkDetail | None:
    if not isinstance(value, dict):
        return None
    ip_address = _ip(value.get("ipAddress"))
    asn = _asn(value.get("asn"))
    description = _safe_text(value.get("asnDescription"), 160)
    registry = _safe_text(value.get("asnRegistry"), 32)
    if all(item is None for item in (ip_address, asn, description, registry)):
        return None
    return {
        "ipAddress": ip_address,
        "asn": asn,
        "asnDescription": description,
        "asnRegistry": registry,
    }


def _assessment(value: object, source: str, domain: str) -> AssessmentDetail | None:
    if source != "URLScan" or not isinstance(value, dict):
        return None
    raw_score = value.get("urlscanVerdictScore")
    score = (
        raw_score
        if isinstance(raw_score, int) and not isinstance(raw_score, bool) and -100 <= raw_score <= 100
        else None
    )
    raw_categories = value.get("urlscanCategories")
    categories: list[str] = []
    if isinstance(raw_categories, list):
        for raw in raw_categories[:8]:
            cleaned = clean_text(raw, 32)
            slug = cleaned.lower().replace("_", "-").replace(" ", "-") if cleaned else ""
            if slug and SLUG.fullmatch(slug) and slug not in categories:
                categories.append(slug)
    raw_redirected = value.get("redirectedToDomain")
    redirected = normalize_domain(raw_redirected) if isinstance(raw_redirected, str) else None
    redirected_domain = defang_host(redirected) if redirected and redirected != domain else None
    return (
        {
            "urlscanVerdictScore": score,
            "urlscanCategories": categories,
            "redirectedToDomain": redirected_domain,
        }
        if score is not None or categories or redirected_domain is not None
        else None
    )


def _registrable(domain: str) -> str:
    extracted = EXTRACT(domain)
    return f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else domain


def _certificate_name(value: object, maximum: int = 253) -> str | None:
    text = _safe_text(value, maximum)
    if not text:
        return None
    raw = refang(text)
    wildcard = raw.startswith("*.")
    normalized = normalize_domain(raw)
    if normalized is not None:
        return f"*[.]{defang_host(normalized)}" if wildcard else defang_host(normalized)
    return None


def _hex(value: object, length: int | None = None, maximum: int = 80) -> str | None:
    if not isinstance(value, str):
        return None
    compact = re.sub(r"[\s:]", "", value).lower()
    if not compact or len(compact) > maximum or not re.fullmatch(r"[a-f\d]+", compact):
        return None
    return compact if length is None or len(compact) == length else None


def _certificate(value: object, domain: str) -> CertificateDetail | None:
    if not isinstance(value, dict):
        return None
    country_value = clean_text(value.get("countryName"), 8)
    country = country_value.upper() if country_value and re.fullmatch(r"[A-Za-z]{2}", country_value) else None
    issuer = _safe_text(value.get("issuer"), 200)
    common_name = _certificate_name(value.get("commonName"))
    not_before = _timestamp(value.get("notBefore"))
    not_after = _timestamp(value.get("notAfter"))
    if not_before and not_after and not_before > not_after:
        not_before = None
        not_after = None

    candidate_registrable = _registrable(domain)
    raw_names = value.get("subjectAltNames")
    names: list[str] = []
    total = value.get("subjectAltNameCount")
    if not isinstance(total, int) or isinstance(total, bool) or not 0 <= total <= MAXIMUM_SAN_COUNT:
        total = len(raw_names) if isinstance(raw_names, list) else 0
    if isinstance(raw_names, list):
        for raw_name in raw_names:
            if not isinstance(raw_name, str):
                continue
            wildcard = raw_name.strip().startswith("*.")
            normalized = normalize_domain(refang(raw_name))
            if normalized is None or _registrable(normalized) != candidate_registrable:
                continue
            display = f"*[.]{defang_host(normalized)}" if wildcard else defang_host(normalized)
            if display not in names:
                names.append(display)
            if len(names) >= MAXIMUM_SAN_SAMPLES:
                break
    total = max(len(names), min(total, MAXIMUM_SAN_COUNT))

    raw_fingerprints = value.get("fingerprints")
    fingerprints: CertificateFingerprints = {
        "md5": _hex(raw_fingerprints.get("md5"), length=32, maximum=32) if isinstance(raw_fingerprints, dict) else None,
        "sha1": (
            _hex(raw_fingerprints.get("sha1"), length=40, maximum=40)
            if isinstance(raw_fingerprints, dict)
            else None
        ),
        "sha256": (
            _hex(raw_fingerprints.get("sha256"), length=64, maximum=64)
            if isinstance(raw_fingerprints, dict)
            else None
        ),
    }
    serial = _hex(value.get("serialNumberHex"), maximum=80)
    if all(
        item is None
        for item in (
            country,
            issuer,
            common_name,
            not_before,
            not_after,
            serial,
            fingerprints["md5"],
            fingerprints["sha1"],
            fingerprints["sha256"],
        )
    ) and not names:
        return None
    return {
        "countryName": country,
        "issuer": issuer,
        "commonName": common_name,
        "notBefore": not_before,
        "notAfter": not_after,
        "subjectAltNames": names,
        "subjectAltNameCount": total,
        "serialNumberHex": serial,
        "fingerprints": fingerprints,
    }


def normalize_intelligence(
    raw: RawDomainIntelligence,
    now: str,
) -> NormalizedIntelligence | None:
    domain = normalize_domain(refang(raw.domain))
    source = clean_text(raw.source, 40)
    observed_at = _timestamp(raw.observed_at, now)
    now_value = _timestamp(now)
    if domain is None or source not in DETAIL_SOURCES or observed_at is None or now_value is None:
        return None
    maximum_observed = (
        datetime.fromisoformat(now_value.replace("Z", "+00:00")) + timedelta(minutes=5)
    ).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    if observed_at > maximum_observed:
        observed_at = now_value
    page = _page(raw.page) if source != "CertStream" else None
    network = _network(raw.network) if source != "CertStream" else None
    assessment = _assessment(raw.assessment, source, domain)
    certificate = _certificate(raw.certificate, domain)
    if page is None and network is None and assessment is None and certificate is None:
        return None
    observation: SignalObservation = {
        "source": cast(Literal["CertStream", "URLScan"], source),
        "observedAt": observed_at,
        "page": page,
        "network": network,
        "assessment": assessment,
        "certificate": certificate,
    }
    return NormalizedIntelligence(
        signal_id=stable_id(defang_host(domain).lower()),
        domain=defang_host(domain),
        observation=observation,
    )


def archive_record(raw: RawDomainIntelligence, now: str) -> dict[str, object] | None:
    normalized = normalize_intelligence(raw, now)
    if normalized is None:
        return None
    return {
        "schemaVersion": 1,
        "dataset": "signal-intelligence",
        "signalId": normalized.signal_id,
        "domain": normalized.domain,
        "observation": normalized.observation,
    }


def raw_from_archive_record(value: object, now: str) -> RawDomainIntelligence | None:
    if not isinstance(value, dict) or set(value) != {
        "schemaVersion", "dataset", "signalId", "domain", "observation"
    }:
        return None
    observation = value.get("observation")
    if (
        value.get("schemaVersion") != 1
        or value.get("dataset") != "signal-intelligence"
        or not isinstance(value.get("signalId"), str)
        or not isinstance(value.get("domain"), str)
        or not isinstance(observation, dict)
        or set(observation) != {
            "source", "observedAt", "page", "network", "assessment", "certificate"
        }
    ):
        return None
    raw = RawDomainIntelligence(
        domain=cast(str, value["domain"]),
        source=cast(str, observation.get("source")),
        observed_at=cast(str | None, observation.get("observedAt")),
        page=cast(dict[str, object] | None, observation.get("page")),
        network=cast(dict[str, object] | None, observation.get("network")),
        assessment=cast(dict[str, object] | None, observation.get("assessment")),
        certificate=cast(dict[str, object] | None, observation.get("certificate")),
    )
    normalized = normalize_intelligence(raw, now)
    expected = archive_record(raw, now)
    return raw if normalized and expected == value and normalized.signal_id == value["signalId"] else None


def _encoded(detail: SignalDetail) -> bytes:
    return (json.dumps(detail, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")


def _context_component_sha256(value: object) -> str:
    body = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    if len(body) > 16 * 1024:
        raise ValueError("Context journal component exceeds 16 KiB.")
    return hashlib.sha256(body).hexdigest()


def _context_event_id(
    signal_id: str,
    observed_at: str,
    component: str,
    change_type: str,
    changed_fields: list[str],
    previous_hash: str,
    current_hash: str,
) -> str:
    material = (
        f"{signal_id}\n{observed_at}\n{component}\n{change_type}\n"
        f"{','.join(changed_fields)}\n{previous_hash}\n{current_hash}"
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def _context_resolves(value: Mapping[str, object]) -> bool:
    return any(isinstance(value.get(field), list) and bool(value[field]) for field in ("a", "aaaa", "cname"))


def _context_dns_values(value: Mapping[str, object], field: str) -> list[object]:
    answers = value.get(field)
    return cast(list[object], answers) if isinstance(answers, list) else []


def _expected_context_changes(
    component: str,
    before: Mapping[str, object],
    after: Mapping[str, object],
) -> list[tuple[str, list[str]]]:
    changes: list[tuple[str, list[str]]] = []
    if component == "dns":
        resolution_fields = [
            field
            for field in ("a", "aaaa", "cname")
            if _context_dns_values(before, field) != _context_dns_values(after, field)
        ]
        before_resolves = _context_resolves(before)
        after_resolves = _context_resolves(after)
        if resolution_fields and before_resolves != after_resolves:
            changes.append(("first-resolving" if after_resolves else "stopped-resolving", resolution_fields))
        else:
            for field in resolution_fields:
                changes.append((f"dns-{field}-changed", [field]))
        for field in ("ns", "mx"):
            if _context_dns_values(before, field) != _context_dns_values(after, field):
                changes.append((f"dns-{field}-changed", [field]))
    elif component == "rdap":
        for field, change_type in (
            ("registrar", "rdap-registrar-changed"),
            ("statuses", "rdap-status-changed"),
            ("expiresAt", "rdap-expiry-changed"),
        ):
            if before.get(field) != after.get(field):
                changes.append((change_type, [field]))
    elif component == "urlscan":
        for field, change_type in (
            ("pageTitle", "urlscan-title-changed"),
            ("redirectedToDomain", "urlscan-redirect-changed"),
            ("httpStatus", "urlscan-http-status-changed"),
            ("ipAddress", "urlscan-ip-changed"),
            ("asn", "urlscan-asn-changed"),
            ("primaryHtmlSha256", "urlscan-primary-html-sha256-changed"),
            ("certificateFingerprintSha256", "urlscan-certificate-fingerprint-changed"),
        ):
            if before.get(field) != after.get(field):
                changes.append((change_type, [field]))
        certificate_fields = [
            field
            for field in (
                "certificateFingerprintSha256",
                "certificateIssuer",
                "certificateNotBefore",
                "certificateNotAfter",
            )
            if before.get(field) != after.get(field)
        ]
        before_has_certificate = any(before.get(field) is not None for field in certificate_fields)
        after_has_certificate = any(after.get(field) is not None for field in certificate_fields)
        if certificate_fields and before_has_certificate and after_has_certificate:
            changes.append(("certificate-reissued", certificate_fields))
    return changes


def _is_linklike(path: Path) -> bool:
    return path.is_symlink() or path.is_junction()


def _reject_context_journal_links(target: Path, repository: Path) -> None:
    if _is_linklike(repository):
        raise ValueError("Context journal refuses a symlinked repository root.")
    if not target.is_relative_to(repository):
        raise ValueError("Context journal path escapes the repository.")
    current = repository
    for part in target.relative_to(repository).parts:
        current /= part
        if _is_linklike(current):
            raise ValueError(f"Context journal refuses symlinked path component {current.name}.")


def load_recent_context_changes(
    root: str | Path,
    generated_at: str,
    *,
    retention_days: int = 60,
    allow_urlscan_redistribution: bool = False,
) -> dict[str, list[dict[str, object]]]:
    """Load a bounded, public-safe projection of the private change journal."""

    repository = Path(os.path.abspath(Path.cwd()))
    allowed = Path(os.path.abspath(repository / "data/history/context"))
    requested = Path(root)
    journal_root = Path(os.path.abspath(requested if requested.is_absolute() else repository / requested))
    if journal_root != allowed:
        raise ValueError("Context journal must be data/history/context.")
    _reject_context_journal_links(journal_root, repository)
    generated = _timestamp(generated_at)
    if generated is None:
        raise ValueError("Context journal generation time is invalid.")
    generated_time = datetime.fromisoformat(generated.replace("Z", "+00:00"))
    retention = min(90, max(30, retention_days))
    cutoff = generated_time - timedelta(days=retention)
    grouped: dict[str, list[dict[str, object]]] = {}
    observed = 0
    seen_event_ids: set[str] = set()
    for offset in range(retention):
        partition = (generated_time.date() - timedelta(days=offset)).isoformat()
        path = journal_root / partition / "events.ndjson"
        _reject_context_journal_links(path, repository)
        try:
            if path.stat().st_size > MAXIMUM_CONTEXT_JOURNAL_BYTES:
                raise ValueError("Context journal partition exceeds 10 MiB.")
            lines = path.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            continue
        if observed + len(lines) > MAXIMUM_CONTEXT_EVENTS_READ:
            raise ValueError("Context journal exceeds the bounded event-read limit.")
        for line_number, line in enumerate(lines, start=1):
            observed += 1
            try:
                row: Any = json.loads(
                    line,
                    parse_constant=lambda value: (_ for _ in ()).throw(
                        ValueError(f"Non-finite JSON value {value}.")
                    ),
                )
            except (json.JSONDecodeError, ValueError) as error:
                raise ValueError(
                    f"Context journal {partition} line {line_number} is malformed."
                ) from error
            if not isinstance(row, dict):
                raise ValueError(f"Context journal {partition} line {line_number} is not an object.")
            event_id = row.get("eventId")
            signal_id = row.get("signalId")
            domain = row.get("domain")
            observed_at = _timestamp(row.get("observedAt"))
            source_observed_at = _timestamp(row.get("sourceObservedAt"))
            source_reference = row.get("sourceReference")
            component = row.get("component")
            change_type = row.get("changeType")
            fields = row.get("changedFields")
            previous_hash = row.get("previousHash")
            current_hash = row.get("currentHash")
            before = row.get("before")
            after = row.get("after")
            if (
                set(row) != {
                    "schemaVersion",
                    "dataset",
                    "eventId",
                    "signalId",
                    "domain",
                    "observedAt",
                    "sourceObservedAt",
                    "sourceReference",
                    "component",
                    "changeType",
                    "changedFields",
                    "previousHash",
                    "currentHash",
                    "before",
                    "after",
                }
                or row.get("schemaVersion") != 2
                or row.get("dataset") != "radar-context-change"
                or not isinstance(event_id, str)
                or not re.fullmatch(r"[a-f\d]{32}", event_id)
                or not isinstance(signal_id, str)
                or not DETAIL_ID.fullmatch(signal_id)
                or not isinstance(domain, str)
                or stable_id(domain.lower()) != signal_id
                or observed_at is None
                or row.get("observedAt") != observed_at
                or not cutoff
                <= datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
                <= generated_time + timedelta(minutes=5)
                or source_observed_at is None
                or row.get("sourceObservedAt") != source_observed_at
                or not cutoff
                <= datetime.fromisoformat(source_observed_at.replace("Z", "+00:00"))
                <= datetime.fromisoformat(observed_at.replace("Z", "+00:00")) + timedelta(minutes=5)
                or not isinstance(change_type, str)
                or CONTEXT_CHANGE_COMPONENTS.get(change_type) != component
                or not isinstance(fields, list)
                or not 1 <= len(fields) <= 32
                or len(fields) != len(set(cast(list[object], fields)))
                or not all(
                    isinstance(field, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9]{0,63}", field)
                    for field in fields
                )
                or not set(cast(list[str], fields)).issubset(CONTEXT_CHANGE_FIELDS.get(change_type, frozenset()))
                or not isinstance(previous_hash, str)
                or not re.fullmatch(r"[a-f\d]{64}", previous_hash)
                or not isinstance(current_hash, str)
                or not re.fullmatch(r"[a-f\d]{64}", current_hash)
                or not isinstance(before, dict)
                or not isinstance(after, dict)
            ):
                raise ValueError(f"Context journal {partition} line {line_number} violates its contract.")
            try:
                computed_previous_hash = _context_component_sha256(before)
                computed_current_hash = _context_component_sha256(after)
            except (TypeError, ValueError) as error:
                raise ValueError(
                    f"Context journal {partition} line {line_number} has an invalid bounded component."
                ) from error
            if previous_hash != computed_previous_hash or current_hash != computed_current_hash:
                raise ValueError(f"Context journal {partition} line {line_number} has a hash mismatch.")
            if (
                change_type,
                cast(list[str], fields),
            ) not in _expected_context_changes(cast(str, component), before, after):
                raise ValueError(f"Context journal {partition} line {line_number} has invalid change semantics.")
            expected_event_id = _context_event_id(
                signal_id,
                observed_at,
                cast(str, component),
                change_type,
                cast(list[str], fields),
                previous_hash,
                current_hash,
            )
            if event_id != expected_event_id:
                raise ValueError(f"Context journal {partition} line {line_number} has an invalid event ID.")
            if event_id in seen_event_ids:
                raise ValueError("Context journal contains a duplicate event ID.")
            seen_event_ids.add(event_id)
            expected_source, expected_reference = CONTEXT_SOURCES[cast(str, component)]
            if not isinstance(source_reference, str) or (
                source_reference != expected_reference
                and not (
                    component == "urlscan"
                    and safe_reference_url(source_reference) == source_reference
                )
            ):
                raise ValueError(f"Context journal {partition} line {line_number} has an unsafe source reference.")
            raw_primary_hashes = after.get("primaryHtmlSha256") if component == "urlscan" else []
            primary_hashes = (
                raw_primary_hashes
                if isinstance(raw_primary_hashes, list)
                and len(raw_primary_hashes) <= 2
                and len(raw_primary_hashes) == len(set(cast(list[object], raw_primary_hashes)))
                and all(
                    isinstance(digest, str) and re.fullmatch(r"[a-f\d]{64}", digest)
                    for digest in raw_primary_hashes
                )
                else None
            )
            certificate_sha256 = after.get("certificateFingerprintSha256") if component == "urlscan" else None
            if primary_hashes is None or not (
                certificate_sha256 is None
                or (isinstance(certificate_sha256, str) and re.fullmatch(r"[a-f\d]{64}", certificate_sha256))
            ):
                raise ValueError(f"Context journal {partition} line {line_number} has invalid evidence hashes.")
            if component == "urlscan" and not allow_urlscan_redistribution:
                continue
            grouped.setdefault(signal_id, []).append(
                {
                    "eventId": event_id,
                    "domain": domain,
                    "observedAt": observed_at,
                    "sourceObservedAt": source_observed_at,
                    "sourceReference": source_reference,
                    "component": component,
                    "changeType": change_type,
                    "changedFields": sorted(cast(list[str], fields)),
                    "previousSha256": previous_hash,
                    "currentSha256": current_hash,
                    "primaryHtmlSha256": primary_hashes,
                    "certificateSha256": certificate_sha256,
                    "sourceName": expected_source,
                }
            )
    for signal_id, rows in grouped.items():
        grouped[signal_id] = sorted(
            rows,
            key=lambda row: (cast(str, row["observedAt"]), cast(str, row["eventId"])),
            reverse=True,
        )[:MAXIMUM_CONTEXT_CHANGES]
    return grouped


def build_signal_details(
    signals: list[RadarSignal],
    intelligence: Iterable[RawDomainIntelligence],
    generated_at: str,
    domain_context: Mapping[str, SignalDomainContextRecord] | None = None,
    context_changes: Mapping[str, list[dict[str, object]]] | None = None,
) -> dict[str, SignalDetail]:
    live = {signal["id"]: signal for signal in signals}
    grouped: dict[str, dict[str, SignalObservation]] = {}
    domains: dict[str, str] = {}
    for raw in intelligence:
        normalized = normalize_intelligence(raw, generated_at)
        if normalized is None:
            continue
        signal = live.get(normalized.signal_id)
        if (
            signal is None
            or signal["domain"] != normalized.domain
            or normalized.observation["source"] not in signal["sources"]
        ):
            continue
        source = normalized.observation["source"]
        current = grouped.setdefault(normalized.signal_id, {}).get(source)
        if current is None or normalized.observation["observedAt"] > current["observedAt"]:
            grouped[normalized.signal_id][source] = normalized.observation
            domains[normalized.signal_id] = normalized.domain

    details: dict[str, SignalDetail] = {}
    published_bytes = 0
    for signal in signals:
        signal_id = signal["id"]
        by_source = grouped.get(signal_id)
        context_record = (domain_context or {}).get(signal_id)
        raw_changes = (context_changes or {}).get(signal_id, [])
        if context_record is not None and context_record["domain"] != signal["domain"]:
            context_record = None
        if by_source is None and context_record is None and not raw_changes:
            continue
        observations = sorted(
            by_source.values() if by_source is not None else [],
            key=lambda item: (item["observedAt"], item["source"]),
            reverse=True,
        )
        detail: SignalDetail = {
            "schemaVersion": 1,
            "dataset": "signal-detail",
            "signalId": signal_id,
            "domain": domains.get(signal_id, signal["domain"]),
            "generatedAt": generated_at,
            "observations": observations[:MAXIMUM_OBSERVATIONS],
        }
        if context_record is not None:
            context: SignalDomainContext = {
                "observedAt": context_record["observedAt"],
                "dns": context_record["dns"],
                "registration": context_record["registration"],
            }
            detail["domainContext"] = context
        changes: list[SignalContextChange] = []
        for raw_change in raw_changes[:MAXIMUM_CONTEXT_CHANGES]:
            component = cast(Literal["dns", "rdap", "urlscan"], raw_change["component"])
            changes.append(
                {
                    "eventId": cast(str, raw_change["eventId"]),
                    "observedAt": cast(str, raw_change["observedAt"]),
                    "component": component,
                    "changeType": cast(Any, raw_change["changeType"]),
                    "changedFields": cast(list[str], raw_change["changedFields"]),
                    "source": {
                        "name": cast(Any, raw_change["sourceName"]),
                        "observedAt": cast(str, raw_change["sourceObservedAt"]),
                        "referenceUrl": cast(str, raw_change["sourceReference"]),
                    },
                    "evidence": {
                        "previousSha256": cast(str, raw_change["previousSha256"]),
                        "currentSha256": cast(str, raw_change["currentSha256"]),
                        "primaryHtmlSha256": cast(list[str], raw_change["primaryHtmlSha256"]),
                        "certificateSha256": cast(str | None, raw_change["certificateSha256"]),
                    },
                }
            )
        if changes:
            detail["contextChanges"] = changes
        detail_bytes = len(_encoded(detail))
        if detail_bytes <= MAXIMUM_DETAIL_BYTES and published_bytes + detail_bytes <= MAXIMUM_DETAIL_SET_BYTES:
            details[signal_id] = detail
            published_bytes += detail_bytes
    return details


def _detail_root(value: str | Path) -> Path:
    repository = Path.cwd().resolve()
    allowed = (repository / "public" / "data" / "signals").resolve()
    requested = Path(value)
    target = (requested if requested.is_absolute() else repository / requested).resolve()
    if target != allowed:
        raise ValueError("RADAR_DETAIL_ROOT must be public/data/signals.")
    return target


def write_signal_details(root: str | Path, details: dict[str, SignalDetail]) -> set[str]:
    target_root = _detail_root(root)
    target_root.mkdir(parents=True, exist_ok=True)
    expected: set[Path] = set()
    prepared: list[tuple[SignalDetail, bytes, Path]] = []
    aggregate_bytes = 0
    for signal_id, detail in details.items():
        if not DETAIL_ID.fullmatch(signal_id) or detail["signalId"] != signal_id:
            raise ValueError("Refusing to publish an invalid signal-detail identifier.")
        body = _encoded(detail)
        if len(body) > MAXIMUM_DETAIL_BYTES:
            raise ValueError("Refusing to publish a signal detail larger than 16 KiB.")
        aggregate_bytes += len(body)
        if aggregate_bytes > MAXIMUM_DETAIL_SET_BYTES:
            raise ValueError("Refusing to publish signal details larger than 3 MiB in aggregate.")
        path = target_root / signal_id[:2] / f"{signal_id}.json"
        expected.add(path.resolve())
        prepared.append((detail, body, path))

    for detail, body, path in prepared:
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            existing_body = path.read_bytes()
            if existing_body == body:
                continue
            if len(existing_body) <= MAXIMUM_DETAIL_BYTES:
                existing: object = json.loads(existing_body)
                if (
                    isinstance(existing, dict)
                    and set(existing).issubset(
                        {
                            "schemaVersion",
                            "dataset",
                            "signalId",
                            "domain",
                            "generatedAt",
                            "observations",
                            "domainContext",
                            "contextChanges",
                        }
                    )
                    and {
                        "schemaVersion",
                        "dataset",
                        "signalId",
                        "domain",
                        "generatedAt",
                        "observations",
                    }.issubset(existing)
                    and _timestamp(existing.get("generatedAt")) == existing.get("generatedAt")
                    and cast(str, existing.get("generatedAt")) <= detail["generatedAt"]
                    and existing.get("schemaVersion") == detail["schemaVersion"]
                    and existing.get("dataset") == detail["dataset"]
                    and existing.get("signalId") == detail["signalId"]
                    and existing.get("domain") == detail["domain"]
                    and existing.get("observations") == detail["observations"]
                    and existing.get("domainContext") == detail.get("domainContext")
                    and existing.get("contextChanges") == detail.get("contextChanges")
                ):
                    continue
        except FileNotFoundError:
            pass
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
        temporary: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                dir=path.parent,
                prefix=f".{path.name}.",
                suffix=".tmp",
                delete=False,
            ) as handle:
                temporary = Path(handle.name)
                handle.write(body)
                handle.flush()
                os.fsync(handle.fileno())
            temporary.chmod(0o600)
            os.replace(temporary, path)
        except Exception:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
            raise

    for directory in target_root.iterdir():
        if not directory.is_dir() or not DETAIL_PREFIX.fullmatch(directory.name):
            continue
        for path in directory.iterdir():
            if (
                path.is_file()
                and DETAIL_ID.fullmatch(path.stem)
                and path.suffix == ".json"
                and path.resolve() not in expected
            ):
                path.unlink()
        with suppress(OSError):
            directory.rmdir()
    return set(details)
