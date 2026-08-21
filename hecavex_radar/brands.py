from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import tldextract

from .models import CandidateMatch

LABEL = re.compile(r"^[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?$", re.IGNORECASE)
EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)
SUSPICIOUS_WORDS = {
    "access",
    "account",
    "atnaujinti",
    "auth",
    "bankas",
    "billing",
    "bank",
    "card",
    "cards",
    "claim",
    "client",
    "confirm",
    "delivery",
    "deposit",
    "draudimas",
    "identity",
    "invoice",
    "klientas",
    "kortele",
    "login",
    "mokejimas",
    "mobile",
    "online",
    "parcel",
    "password",
    "pay",
    "payment",
    "paskyra",
    "patvirtinti",
    "portal",
    "prisijungimas",
    "prisijungti",
    "refund",
    "saskaita",
    "secure",
    "security",
    "sekimas",
    "service",
    "shipment",
    "signin",
    "siunta",
    "support",
    "track",
    "tracking",
    "update",
    "verify",
    "wallet",
}
KNOWN_CT_REWRITE_SUFFIXES = {
    "admin-mcas-df.ms",
    "admin-mcas-gov-df.ms",
    "admin-mcas-gov-df.us",
    "admin-mcas-gov.ms",
    "admin-mcas-gov.us",
    "admin-mcas.ms",
    "admin-rs-mcas-df.ms",
    "admin-rs-mcas.ms",
    "mcas-df.ms",
    "mcas-gov-df.ms",
    "mcas-gov-df.us",
    "mcas-gov.ms",
    "mcas-gov.us",
    "mcas.ms",
    "rs-mcas-df.ms",
    "rs-mcas.ms",
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
    fuzzy_aliases: list[str]
    excluded_terms: list[str]
    excluded_domains: list[str]
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


def _optional_strings(value: object) -> list[str] | None:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
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
    scope = payload.get("scope")
    reviewed_at = payload.get("reviewedAt")
    if not isinstance(scope, str) or not scope.strip() or not isinstance(reviewed_at, str):
        raise ValueError("Brand registry metadata is invalid.")
    try:
        if date.fromisoformat(reviewed_at).isoformat() != reviewed_at:
            raise ValueError
    except ValueError as error:
        raise ValueError("Brand registry reviewedAt must be a valid YYYY-MM-DD date.") from error
    raw_entries = payload.get("entries")
    if not isinstance(raw_entries, list):
        raise ValueError("Brand registry entries are invalid.")

    entries: list[BrandEntry] = []
    seen_brands: set[str] = set()
    seen_aliases: dict[str, str] = {}
    seen_domains: dict[str, str] = {}
    seen_excluded_domains: set[str] = set()
    for index, raw in enumerate(raw_entries, start=1):
        if (
            not isinstance(raw, dict)
            or not isinstance(raw.get("brand"), str)
            or not isinstance(raw.get("category"), str)
        ):
            raise ValueError(f"Brand registry entry {index} is invalid.")
        aliases = _strings(raw.get("aliases"))
        fuzzy_aliases = _optional_strings(raw.get("fuzzyAliases"))
        excluded_terms = _optional_strings(raw.get("excludedTerms"))
        excluded_domains = _optional_strings(raw.get("excludedDomains"))
        official = _strings(raw.get("officialDomains"))
        sources = _strings(raw.get("sources"))
        normalized_official = [domain for item in official or [] if (domain := normalize_domain(item))]
        normalized_excluded = [
            domain for item in excluded_domains or [] if (domain := normalize_domain(item))
        ]
        if (
            not aliases
            or fuzzy_aliases is None
            or excluded_terms is None
            or excluded_domains is None
            or len(normalized_official) != len(official or [])
            or len(normalized_excluded) != len(excluded_domains)
            or not normalized_official
            or not sources
        ):
            raise ValueError(f"Brand registry entry {index} is invalid.")
        if any(not _canonical(term) for term in excluded_terms):
            raise ValueError(f"Brand registry entry {index} has an invalid excluded term.")
        brand = raw["brand"].strip()
        if not brand or not raw["category"].strip():
            raise ValueError(f"Brand registry entry {index} is invalid.")
        normalized_lists = (
            [alias.casefold() for alias in aliases],
            [term.casefold() for term in excluded_terms],
            normalized_official,
            normalized_excluded,
            [source.casefold() for source in sources],
        )
        if any(len(values) != len(set(values)) for values in normalized_lists):
            raise ValueError(f"Brand registry entry {index} contains duplicate values.")
        if set(normalized_official).intersection(normalized_excluded):
            raise ValueError(f"Brand registry entry {index} overlaps official and excluded domains.")
        if set(normalized_official).intersection(seen_excluded_domains) or set(normalized_excluded).intersection(
            seen_domains
        ):
            raise ValueError("Brand registry overlaps official and excluded domains.")
        if set(normalized_excluded).intersection(seen_excluded_domains):
            raise ValueError(f"Brand registry entry {index} contains duplicate excluded domains.")
        brand_key = brand.casefold()
        if brand_key in seen_brands:
            raise ValueError(f"Brand registry entry {index} duplicates a brand.")
        seen_brands.add(brand_key)
        aliases_by_canonical = {_canonical(alias): alias for alias in aliases}
        normalized_fuzzy: list[str] = []
        seen_fuzzy: set[str] = set()
        for fuzzy_alias in fuzzy_aliases:
            canonical_fuzzy = _canonical(fuzzy_alias)
            fuzzy_parts = [
                part for item in re.split(r"[\s._-]+", fuzzy_alias) if (part := _canonical(item))
            ]
            if (
                canonical_fuzzy not in aliases_by_canonical
                or canonical_fuzzy in seen_fuzzy
                or len(fuzzy_parts) != 1
                or len(canonical_fuzzy) < 5
            ):
                raise ValueError(f"Brand registry entry {index} has an invalid fuzzy alias.")
            seen_fuzzy.add(canonical_fuzzy)
            normalized_fuzzy.append(fuzzy_alias.strip())
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
            if owner is not None:
                raise ValueError(f"Official domain {domain!r} belongs to multiple entries.")
            seen_domains[domain] = brand
        seen_excluded_domains.update(normalized_excluded)
        entries.append(
            BrandEntry(
                brand=brand,
                aliases=aliases,
                fuzzy_aliases=normalized_fuzzy,
                excluded_terms=excluded_terms,
                excluded_domains=normalized_excluded,
                category=raw["category"].strip(),
                official_domains=normalized_official,
                sources=sources,
            )
        )
    return BrandRegistry(scope=scope, reviewed_at=reviewed_at, entries=entries)


def _canonical(value: str) -> str:
    translated = unicodedata.normalize("NFKD", value).translate(LOOKALIKES).lower()
    return "".join(
        character
        for character in translated
        if not unicodedata.combining(character) and character.isascii() and character.isalnum()
    )


def _edit_distance(left: str, right: str) -> int:
    """Return restricted Damerau-Levenshtein distance for short DNS tokens."""
    if left == right:
        return 0
    if abs(len(left) - len(right)) > 2:
        return 3
    previous_previous: list[int] | None = None
    previous = list(range(len(right) + 1))
    for left_index, left_character in enumerate(left, start=1):
        current = [left_index]
        for right_index, right_character in enumerate(right, start=1):
            distance = min(
                current[right_index - 1] + 1,
                previous[right_index] + 1,
                previous[right_index - 1] + (left_character != right_character),
            )
            if (
                previous_previous is not None
                and left_index > 1
                and right_index > 1
                and left_character == right[right_index - 2]
                and left[left_index - 2] == right_character
            ):
                distance = min(distance, previous_previous[right_index - 2] + 1)
            current.append(distance)
        previous_previous = previous
        previous = current
    return previous[-1]


def _is_official(domain: str, official_domains: set[str]) -> bool:
    return any(domain == official or domain.endswith(f".{official}") for official in official_domains)


def is_suppressed_domain(value: str, registry: BrandRegistry) -> bool:
    domain = normalize_domain(value)
    if not domain:
        return True
    reviewed = {
        candidate
        for entry in registry.entries
        for candidate in [*entry.official_domains, *entry.excluded_domains]
    }
    return _is_official(domain, reviewed) or _is_official(domain, KNOWN_CT_REWRITE_SUFFIXES)


def is_brand_collision(value: str, brand: str, registry: BrandRegistry) -> bool:
    """Return true when a reviewed exclusion contradicts a proposed brand mapping."""
    domain = normalize_domain(value)
    entry = next((candidate for candidate in registry.entries if candidate.brand == brand), None)
    if not domain or entry is None:
        return True
    grouped_parts = _label_parts(domain)
    candidate_parts = {part for group in grouped_parts for part in group}
    candidate_parts.update("".join(group) for group in grouped_parts)
    excluded = {_canonical(term) for term in entry.excluded_terms}
    return bool(excluded.intersection(candidate_parts))


def _registrable_domain(domain: str) -> str:
    extracted = EXTRACT(domain)
    if not extracted.suffix:
        return domain
    return f"{extracted.domain}.{extracted.suffix}"


def _alias_parts(value: str) -> list[str]:
    return [part for item in re.split(r"[\s._-]+", value) if (part := _canonical(item))]


def _label_groups(domain: str) -> list[tuple[list[str], bool]]:
    labels = domain.split(".")
    suffix = EXTRACT(domain).suffix
    suffix_labels = len(suffix.split(".")) if suffix else 1
    meaningful_labels = labels[:-suffix_labels] if len(labels) > suffix_labels else labels
    groups: list[tuple[list[str], bool]] = []
    for label in meaningful_labels:
        try:
            decoded_label = label.encode("ascii").decode("idna")
        except UnicodeError:
            decoded_label = label
        parts = [part for item in decoded_label.split("-") if (part := _canonical(item))]
        groups.append((parts, label.startswith("xn--")))
    return groups


def _label_parts(domain: str) -> list[list[str]]:
    return [parts for parts, _ in _label_groups(domain)]


def _domain_hyphen_count(domain: str) -> int:
    return sum(label.removeprefix("xn--").count("-") for label in domain.split("."))


def _contains_sequence(parts: list[str], sequence: list[str]) -> bool:
    if not sequence or len(sequence) > len(parts):
        return False
    return any(parts[index : index + len(sequence)] == sequence for index in range(len(parts) - len(sequence) + 1))


def _context_words(parts: list[str], alias_parts: set[str]) -> list[str]:
    return [part for part in parts if part in SUSPICIOUS_WORDS and part not in alias_parts]


def _suspicious_affix(token: str, alias: str) -> str | None:
    if token.startswith(alias) and token != alias:
        suffix = token[len(alias) :]
        if suffix in SUSPICIOUS_WORDS:
            return suffix
    if token.endswith(alias) and token != alias:
        prefix = token[: -len(alias)]
        if prefix in SUSPICIOUS_WORDS:
            return prefix
    return None


def resolve_brand_name(value: str | None, registry: BrandRegistry) -> str | None:
    if not value or not (candidate := _canonical(value)):
        return None
    for entry in registry.entries:
        names = [entry.brand, *entry.aliases]
        if any(_canonical(name) == candidate for name in names):
            return entry.brand
    return None


def match_brand_text(value: str | None, registry: BrandRegistry) -> str | None:
    if not value:
        return None
    tokens = [part for item in re.split(r"[^\w]+", value) if (part := _canonical(item))]
    matches: list[tuple[int, str]] = []
    for entry in registry.entries:
        for alias in entry.aliases:
            parts = _alias_parts(alias)
            compact = "".join(parts)
            if len(compact) >= 5 and _contains_sequence(tokens, parts):
                matches.append((len(compact), entry.brand))
    matched_brands = {brand for _, brand in matches}
    if len(matched_brands) != 1:
        return None
    return matched_brands.pop()


def score_domain(value: str, registry: BrandRegistry) -> CandidateMatch | None:
    domain = normalize_domain(value)
    if not domain:
        return None
    if is_suppressed_domain(domain, registry):
        return None

    registrable_domain = _registrable_domain(domain)
    label_groups = _label_groups(domain)
    grouped_parts = [parts for parts, _ in label_groups]
    punycode_labels = [is_punycode for _, is_punycode in label_groups]
    canonical_parts = [part for group in grouped_parts for part in group]
    label_compacts = ["".join(group) for group in grouped_parts]
    suspicious = [part for part in canonical_parts if part in SUSPICIOUS_WORDS]
    matches: list[CandidateMatch] = []

    for entry in registry.entries:
        excluded = {_canonical(term) for term in entry.excluded_terms}
        fuzzy_aliases = {_canonical(alias) for alias in entry.fuzzy_aliases}
        if excluded.intersection(canonical_parts) or excluded.intersection(label_compacts):
            continue
        base = 0
        match_reason = ""
        matched_alias_parts: list[str] = []
        attached_context: list[str] = []
        matched_punycode = False
        for raw_alias in entry.aliases:
            alias_parts = _alias_parts(raw_alias)
            alias = "".join(alias_parts)
            if not alias or not alias_parts:
                continue
            exact_groups = [
                index for index, group in enumerate(grouped_parts) if _contains_sequence(group, alias_parts)
            ]
            if len(alias) <= 4:
                has_context = any(_context_words(grouped_parts[index], set(alias_parts)) for index in exact_groups)
                local_punycode = any(punycode_labels[index] for index in exact_groups)
                if exact_groups and (has_context or local_punycode) and base < 70:
                    base = 70
                    match_reason = f"exact short brand token: {raw_alias}"
                    matched_alias_parts = alias_parts
                    matched_punycode = local_punycode
                continue
            if exact_groups:
                exact_context = list(
                    dict.fromkeys(
                        word
                        for index in exact_groups
                        for word in _context_words(grouped_parts[index], set(alias_parts))
                    )
                )
                local_punycode = any(punycode_labels[index] for index in exact_groups)
                if (exact_context or local_punycode) and base < 80:
                    base = 80
                    match_reason = f"brand text match: {raw_alias}"
                    matched_alias_parts = alias_parts
                    attached_context = exact_context
                    matched_punycode = local_punycode
                continue

            affix = next(
                (
                    (context, index)
                    for index, group in enumerate(grouped_parts)
                    for token in group
                    if (context := _suspicious_affix(token, alias)) is not None
                ),
                None,
            )
            if affix is not None and base < 78:
                context, group_index = affix
                base = 78
                match_reason = f"brand text with suspicious affix: {raw_alias}"
                matched_alias_parts = alias_parts
                attached_context = [context]
                matched_punycode = punycode_labels[group_index]

            # Attackers frequently split a brand across hyphen-delimited pieces.
            # Fold only one DNS label and require the remaining prefix or suffix
            # to be exactly one reviewed threat word. This is intentionally not
            # a general substring or caller-supplied regular-expression match.
            split_affix = next(
                (
                    (context, index)
                    for index, group in enumerate(grouped_parts)
                    if len(group) >= 2
                    and (context := _suspicious_affix("".join(group), alias)) is not None
                ),
                None,
            )
            if len(alias) > 4 and split_affix is not None and base < 78:
                context, group_index = split_affix
                base = 78
                match_reason = f"brand text split across label: {raw_alias}"
                matched_alias_parts = alias_parts
                attached_context = [context]
                matched_punycode = punycode_labels[group_index]

            # Fuzzy evidence is intentionally narrow: one edit (including one
            # adjacent transposition) in a single-word alias, plus a threat word
            # in the same DNS label (or punycode).
            if _canonical(raw_alias) not in fuzzy_aliases or len(alias_parts) != 1 or len(alias) < 5:
                continue
            for group_index, group in enumerate(grouped_parts):
                fuzzy_context = _context_words(group, set(alias_parts))
                if not fuzzy_context and not punycode_labels[group_index]:
                    continue
                alias_digits = "".join(character for character in alias if character.isdigit())
                fuzzy_parts = [
                    part
                    for part in group
                    if part not in SUSPICIOUS_WORDS
                    and (
                        not alias_digits
                        or "".join(character for character in part if character.isdigit()) == alias_digits
                    )
                ]
                closest = min(
                    (_edit_distance(alias, part) for part in fuzzy_parts),
                    default=3,
                )
                if closest == 1 and base < 68:
                    base = 68
                    match_reason = f"brand lookalike (edit distance {closest}): {raw_alias}"
                    matched_alias_parts = alias_parts
                    attached_context = fuzzy_context
                    matched_punycode = punycode_labels[group_index]
        if base == 0:
            continue

        confidence = base
        reasons = [match_reason]
        effective_suspicious = [part for part in suspicious if part not in set(matched_alias_parts)]
        effective_suspicious.extend(attached_context)
        effective_suspicious = list(dict.fromkeys(effective_suspicious))
        if effective_suspicious:
            confidence += 15
            reasons.append(f"suspicious token: {', '.join(effective_suspicious)}")
        if matched_punycode:
            confidence += 10
            reasons.append("internationalized domain (punycode)")
        official_tlds = {official.rsplit(".", 1)[-1] for official in entry.official_domains}
        if registrable_domain.rsplit(".", 1)[-1] not in official_tlds:
            confidence += 5
            reasons.append("different top-level domain from registry")
        if _domain_hyphen_count(domain) >= 2:
            confidence += 5
            reasons.append("multiple hyphens")

        result = CandidateMatch(
            domain=domain,
            registrable_domain=registrable_domain,
            brand=entry.brand,
            confidence=min(100, confidence),
            reasons=reasons,
        )
        matches.append(result)
    return matches[0] if len(matches) == 1 else None
