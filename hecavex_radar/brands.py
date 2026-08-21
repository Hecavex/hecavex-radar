from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import tldextract

from .models import CandidateMatch

LABEL = re.compile(r"^[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?$", re.IGNORECASE)
EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)
SUSPICIOUS_WORDS = {
    "account",
    "auth",
    "bank",
    "client",
    "confirm",
    "delivery",
    "invoice",
    "login",
    "mobile",
    "online",
    "parcel",
    "pay",
    "payment",
    "secure",
    "security",
    "signin",
    "support",
    "update",
    "verify",
    "wallet",
}
LOOKALIKES = str.maketrans(
    {
        "а": "a",
        "с": "c",
        "е": "e",
        "і": "i",
        "ј": "j",
        "о": "o",
        "р": "p",
        "ѕ": "s",
        "х": "x",
        "у": "y",
        "α": "a",
        "β": "b",
        "ε": "e",
        "ζ": "z",
        "η": "h",
        "ι": "i",
        "κ": "k",
        "μ": "m",
        "ν": "n",
        "ο": "o",
        "ρ": "p",
        "τ": "t",
        "χ": "x",
    }
)


@dataclass(frozen=True, slots=True)
class BrandEntry:
    brand: str
    aliases: list[str]
    category: str
    official_domains: list[str]
    sources: list[str]


@dataclass(frozen=True, slots=True)
class BrandRegistry:
    scope: str
    reviewed_at: str
    entries: list[BrandEntry]


def _strings(value: object) -> list[str] | None:
    if not isinstance(value, list) or not value or not all(isinstance(item, str) and item.strip() for item in value):
        return None
    return [item.strip() for item in value]


def normalize_domain(value: str) -> str | None:
    without_wildcard = re.sub(r"^\*\.", "", value.strip(), count=1).removesuffix(".").lower()
    try:
        ascii_domain = without_wildcard.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    labels = ascii_domain.split(".")
    if not ascii_domain or len(ascii_domain) > 253 or ":" in ascii_domain or len(labels) < 2:
        return None
    if any(not LABEL.fullmatch(label) for label in labels):
        return None
    return ascii_domain


def load_brand_registry(path: Path | None = None) -> BrandRegistry:
    target = path or Path.cwd() / "data" / "brands-lt.json"
    payload: Any = json.loads(target.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("schemaVersion") != 1:
        raise ValueError("Brand registry has an invalid top-level shape.")
    if not isinstance(payload.get("scope"), str) or not isinstance(payload.get("reviewedAt"), str):
        raise ValueError("Brand registry metadata is invalid.")
    raw_entries = payload.get("entries")
    if not isinstance(raw_entries, list):
        raise ValueError("Brand registry entries are invalid.")

    entries: list[BrandEntry] = []
    seen_aliases: dict[str, str] = {}
    seen_domains: dict[str, str] = {}
    for index, raw in enumerate(raw_entries, start=1):
        if (
            not isinstance(raw, dict)
            or not isinstance(raw.get("brand"), str)
            or not isinstance(raw.get("category"), str)
        ):
            raise ValueError(f"Brand registry entry {index} is invalid.")
        aliases = _strings(raw.get("aliases"))
        official = _strings(raw.get("officialDomains"))
        sources = _strings(raw.get("sources"))
        normalized_official = [domain for item in official or [] if (domain := normalize_domain(item))]
        if not aliases or not normalized_official or not sources:
            raise ValueError(f"Brand registry entry {index} is invalid.")
        brand = raw["brand"].strip()
        if not brand or not raw["category"].strip():
            raise ValueError(f"Brand registry entry {index} is invalid.")
        for source in sources:
            parsed_source = urlsplit(source)
            if parsed_source.scheme != "https" or not parsed_source.hostname or parsed_source.username is not None:
                raise ValueError(f"Brand registry entry {index} has an unsafe source URL.")
        for alias in aliases:
            canonical_alias = _canonical(alias)
            owner = seen_aliases.get(canonical_alias)
            if not canonical_alias or (owner is not None and owner != brand):
                raise ValueError(f"Brand registry alias {alias!r} is ambiguous.")
            seen_aliases[canonical_alias] = brand
        for domain in normalized_official:
            owner = seen_domains.get(domain)
            if owner is not None and owner != brand:
                raise ValueError(f"Official domain {domain!r} belongs to multiple entries.")
            seen_domains[domain] = brand
        entries.append(
            BrandEntry(
                brand=brand,
                aliases=aliases,
                category=raw["category"].strip(),
                official_domains=normalized_official,
                sources=sources,
            )
        )
    return BrandRegistry(scope=payload["scope"], reviewed_at=payload["reviewedAt"], entries=entries)


def _canonical(value: str) -> str:
    translated = unicodedata.normalize("NFKD", value).translate(LOOKALIKES).lower()
    return "".join(
        character
        for character in translated
        if not unicodedata.combining(character) and character.isascii() and character.isalnum()
    )


def _edit_distance(left: str, right: str) -> int:
    if left == right:
        return 0
    if abs(len(left) - len(right)) > 2:
        return 3
    previous = list(range(len(right) + 1))
    for left_index, left_character in enumerate(left, start=1):
        current = [left_index]
        for right_index, right_character in enumerate(right, start=1):
            current.append(
                min(
                    current[right_index - 1] + 1,
                    previous[right_index] + 1,
                    previous[right_index - 1] + (left_character != right_character),
                )
            )
        previous = current
    return previous[-1]


def _is_official(domain: str, official_domains: set[str]) -> bool:
    return any(domain == official or domain.endswith(f".{official}") for official in official_domains)


def _registrable_domain(domain: str) -> str:
    extracted = EXTRACT(domain)
    if not extracted.suffix:
        return domain
    return f"{extracted.domain}.{extracted.suffix}"


def score_domain(value: str, registry: BrandRegistry) -> CandidateMatch | None:
    domain = normalize_domain(value)
    if not domain:
        return None
    official_domains = {domain for entry in registry.entries for domain in entry.official_domains}
    if _is_official(domain, official_domains):
        return None

    registrable_domain = _registrable_domain(domain)
    try:
        unicode_domain = domain.encode("ascii").decode("idna")
    except UnicodeError:
        unicode_domain = domain
    label_parts = [part for label in unicode_domain.split(".")[:-1] for part in label.split("-")]
    canonical_parts = [part for value in label_parts if (part := _canonical(value))]
    candidate_text = _canonical(" ".join(unicode_domain.split(".")[:-1]))
    suspicious = [part for part in canonical_parts if part in SUSPICIOUS_WORDS]
    best: CandidateMatch | None = None

    for entry in registry.entries:
        base = 0
        match_reason = ""
        for raw_alias in entry.aliases:
            alias = _canonical(raw_alias)
            if not alias:
                continue
            exact_part = alias in canonical_parts
            if len(alias) <= 4:
                if exact_part and base < 70:
                    base = 70
                    match_reason = f"exact short brand token: {raw_alias}"
                continue
            if (exact_part or alias in candidate_text) and base < 72:
                base = 72
                match_reason = f"brand text match: {raw_alias}"
            closest = min((_edit_distance(alias, part) for part in canonical_parts), default=3)
            permitted = 2 if len(alias) >= 8 else 1 if len(alias) >= 5 else 0
            if permitted and 0 < closest <= permitted and base < 68:
                base = 68
                match_reason = f"brand lookalike (edit distance {closest}): {raw_alias}"
        if base == 0:
            continue

        confidence = base
        reasons = [match_reason]
        if suspicious:
            confidence += 15
            reasons.append(f"suspicious token: {', '.join(dict.fromkeys(suspicious))}")
        if "xn--" in domain:
            confidence += 10
            reasons.append("internationalized domain (punycode)")
        official_tlds = {official.rsplit(".", 1)[-1] for official in entry.official_domains}
        if registrable_domain.rsplit(".", 1)[-1] not in official_tlds:
            confidence += 5
            reasons.append("different top-level domain from registry")
        if domain.count("-") >= 2:
            confidence += 5
            reasons.append("multiple hyphens")

        result = CandidateMatch(
            domain=domain,
            registrable_domain=registrable_domain,
            brand=entry.brand,
            confidence=min(100, confidence),
            reasons=reasons,
        )
        if (
            best is None
            or result.confidence > best.confidence
            or (result.confidence == best.confidence and result.brand < best.brand)
        ):
            best = result
    return best
