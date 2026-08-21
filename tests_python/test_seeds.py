from __future__ import annotations

from pathlib import Path

from pytest import MonkeyPatch

import hecavex_radar.brands as brand_module
import hecavex_radar.seeds as seed_module
from hecavex_radar.brands import BrandRegistry, load_brand_registry, score_domain
from hecavex_radar.models import CandidateMatch
from hecavex_radar.seeds import (
    CERTPL_URL,
    IntelligenceSeed,
    SeedObservation,
    build_intelligence_seeds,
    load_intelligence_seeds,
    parse_text_feed,
)

REGISTRY_PATH = Path(__file__).parents[1] / "data" / "brands-lt.json"


def test_builds_only_lithuanian_brand_seeds() -> None:
    registry = load_brand_registry(REGISTRY_PATH)
    seeds = build_intelligence_seeds(
        [
            SeedObservation("https://secure-swedbank-login.example/a"),
            SeedObservation("secure-swedbank-login.example"),
            SeedObservation("https://sberbank-login.example/"),
            SeedObservation("https://www.swedbank.lt/"),
            SeedObservation("https://unrelated.example/"),
        ],
        registry,
    )

    by_domain = {seed.domain: seed for seed in seeds}
    assert set(by_domain) == {"secure-swedbank-login.example"}
    assert by_domain["secure-swedbank-login.example"].confidence == 100


def test_prefilter_preserves_current_exact_fuzzy_and_punycode_matches() -> None:
    registry = load_brand_registry(REGISTRY_PATH)
    alias_domains = [
        f"secure-{'-'.join(alias.casefold().split())}.example"
        for entry in registry.entries
        for alias in entry.aliases
    ]
    domains = [
        *alias_domains,
        "swedbannk-auth.example",
        "swdbank-auth.example",
        "swedbonk-auth.example",
        "telr2-support.example",
        "xn--wedbank-iog.example",
        "secure-revolut-swedbank-login.example",
        "sberbank-login.example",
        "unrelated.example",
    ]
    observations = [SeedObservation(domain) for domain in domains]

    expected: dict[tuple[str, str], IntelligenceSeed] = {}
    for domain in domains:
        match = score_domain(domain, registry)
        if match is not None and match.confidence >= 80:
            expected[(domain, match.brand)] = IntelligenceSeed(
                domain=domain,
                brand=match.brand,
                confidence=match.confidence,
            )

    actual = build_intelligence_seeds(observations, registry, maximum=10_000)
    assert actual == sorted(
        expected.values(),
        key=lambda seed: (-seed.confidence, seed.domain, seed.brand),
    )
    assert {seed.domain for seed in actual}.issuperset(
        {
            "swedbannk-auth.example",
            "swdbank-auth.example",
            "swedbonk-auth.example",
            "telr2-support.example",
            "xn--wedbank-iog.example",
        }
    )


def test_prefilter_avoids_full_scoring_for_unrelated_bulk_rows(
    monkeypatch: MonkeyPatch,
) -> None:
    registry = load_brand_registry(REGISTRY_PATH)
    observations = [SeedObservation(f"n{index:08d}.example") for index in range(20_000)]
    observations.extend(
        [
            SeedObservation("secure-swedbank-login.example"),
            SeedObservation("swedbannk-auth.example"),
            SeedObservation("xn--wedbank-iog.example"),
        ]
    )
    score_calls = 0

    def counted_score(value: str, candidate_registry: BrandRegistry) -> CandidateMatch | None:
        nonlocal score_calls
        score_calls += 1
        return score_domain(value, candidate_registry)

    monkeypatch.setattr(seed_module, "score_domain", counted_score)
    seeds = build_intelligence_seeds(observations, registry)

    assert {seed.domain for seed in seeds} == {
        "secure-swedbank-login.example",
        "swedbannk-auth.example",
        "xn--wedbank-iog.example",
    }
    assert score_calls == 3


def test_prefilter_uses_the_authoritative_lookalike_canonicalization(
    monkeypatch: MonkeyPatch,
) -> None:
    # The production table currently contains Unicode homoglyphs. Extending it
    # here with common digit substitutions proves the prefilter cannot drift if
    # the authoritative table gains additional reviewed mappings.
    monkeypatch.setattr(
        brand_module,
        "LOOKALIKES",
        {
            **brand_module.LOOKALIKES,
            ord("0"): "o",
            ord("1"): "i",
        },
    )
    registry = load_brand_registry(REGISTRY_PATH)
    assert next(entry for entry in registry.entries if entry.brand == "Revolut").fuzzy_aliases == []
    assert next(entry for entry in registry.entries if entry.brand == "Vinted").fuzzy_aliases == []
    domains = ["rev0lut-login.example", "v1nted-login.example"]
    expected = [score_domain(domain, registry) for domain in domains]
    assert all(match is not None for match in expected)

    score_calls = 0

    def counted_score(value: str, candidate_registry: BrandRegistry) -> CandidateMatch | None:
        nonlocal score_calls
        score_calls += 1
        return score_domain(value, candidate_registry)

    monkeypatch.setattr(seed_module, "score_domain", counted_score)
    seeds = build_intelligence_seeds(
        [SeedObservation(domain) for domain in domains],
        registry,
    )

    assert [(seed.domain, seed.brand) for seed in seeds] == [
        ("rev0lut-login.example", "Revolut"),
        ("v1nted-login.example", "Vinted"),
    ]
    assert score_calls == 2


def test_plain_domain_parser_ignores_comments_and_blank_lines() -> None:
    lines = parse_text_feed(b"# comment\r\nsecure-bank.example\r\n\r\n! metadata\r\n")
    assert [value.indicator for value in lines] == ["secure-bank.example"]


def test_loader_is_transient_bounded_and_uses_the_certpl_active_domain_list(
    monkeypatch: MonkeyPatch,
) -> None:
    registry = load_brand_registry(REGISTRY_PATH)
    monkeypatch.setenv("PHISHDESTROY_SEED_ENABLED", "true")
    monkeypatch.setenv("CERTPL_SEED_ENABLED", "true")
    monkeypatch.setenv("INTELLIGENCE_SEED_LIMIT", "1")

    requested: list[tuple[str, dict[str, str], tuple[str, ...]]] = []

    def fetcher(url: str, headers: dict[str, str], hosts: tuple[str, ...]) -> bytes:
        requested.append((url, headers, hosts))
        return b"secure-swedbank-login.example\nsecure-seb-login.example\n"

    result = load_intelligence_seeds(registry, fetcher)
    assert result.configured == 2
    assert result.completed == 2
    assert result.failed == 0
    assert len(result.seeds) == 1
    assert len(requested) == 2
    assert CERTPL_URL == "https://hole.cert.pl/domains/v2/domains.txt"
    certpl_request = next(request for request in requested if request[0] == CERTPL_URL)
    assert certpl_request[1] == {
        "Accept": "text/plain",
        "User-Agent": "hecavex-radar/0.1",
    }
    assert certpl_request[2] == ("hole.cert.pl",)
