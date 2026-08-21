import json
from pathlib import Path

import pytest

from hecavex_radar.brands import (
    is_brand_collision,
    load_brand_registry,
    match_brand_text,
    resolve_brand_name,
    score_domain,
)


def test_suppresses_official_domains_and_subdomains() -> None:
    registry = load_brand_registry()
    assert score_domain("swedbank.lt", registry) is None
    assert score_domain("login.swedbank.lt", registry) is None
    assert score_domain("checkout.swedbankpay.com", registry) is None
    assert score_domain("internetbank.swedbank.ee", registry) is None
    assert score_domain("www.swedbank.lv", registry) is None
    assert score_domain("www.swedbank.se", registry) is None
    assert score_domain("www.revolut.com", registry) is None
    assert score_domain("www.bta.ee", registry) is None
    assert score_domain("www.bite.lv", registry) is None
    assert score_domain("tracking.dpd.lv", registry) is None
    assert score_domain("www.ergo.ee", registry) is None
    assert score_domain("www.gjensidige.lv", registry) is None
    assert score_domain("www.ignitis.fi", registry) is None
    assert score_domain("www.lidl.ee", registry) is None
    assert score_domain("www.luminor.ee", registry) is None
    assert score_domain("www.luminor.lv", registry) is None
    assert score_domain("www.maxima.ee", registry) is None
    assert score_domain("www.maxima.lv", registry) is None
    assert score_domain("www.rimi.ee", registry) is None
    assert score_domain("www.rimi.lv", registry) is None
    assert score_domain("www.smartposti.ee", registry) is None
    assert score_domain("www.seb.ee", registry) is None
    assert score_domain("www.seb.lv", registry) is None
    assert score_domain("www.seb.se", registry) is None
    assert score_domain("td4.sap.telia.io", registry) is None
    assert score_domain("www.vinted.co.uk", registry) is None
    assert score_domain("www.vintedpay.com", registry) is None
    assert score_domain("c83-254-220-254.bredband.tele2.se", registry) is None
    assert score_domain("dev-ciptracker.tele2.kz", registry) is None
    assert score_domain("revolut.me", registry) is None
    assert score_domain("www.telia.fi", registry) is None


def test_suppresses_reviewed_legitimate_namesake_domains() -> None:
    registry = load_brand_registry()
    assert score_domain("elektrum.com.pl", registry) is None
    assert score_domain("shop.elektrum.com.pl", registry) is None


def test_does_not_match_short_brand_inside_unrelated_word() -> None:
    assert score_domain("sebastian.example.com", load_brand_registry()) is None
    assert score_domain("urban.example.com", load_brand_registry()) is None


def test_rejects_observed_lexical_false_positives() -> None:
    registry = load_brand_registry()
    false_positives = [
        "sberbank.example.com",
        "auth.example.maximo.com",
        "www.bigbang.repair",
        "nextcryptorevolution.com",
        "api.timetopartea.com",
        "policies.tikfans-api.com",
        "express-check.com",
        "smartpostbd.com",
        "seb-team.pl",
        "multi-bite.com",
        "whm.iki.sendsend.ru",
        "dhl-eu.rossum.cloud",
        "autogroup-tele-support.4compute.workers.dev",
    ]
    for domain in false_positives:
        assert score_domain(domain, registry) is None, domain


def test_rejects_documented_microsoft_ct_rewrite_domains() -> None:
    registry = load_brand_registry()
    assert score_domain("vinted.co.uk.admin-mcas.ms", registry) is None
    assert score_domain("vinted.co.uk.mcas-df.ms", registry) is None


def test_matches_complete_short_brand_token() -> None:
    result = score_domain("seb-login.example.com", load_brand_registry())
    assert result is not None
    assert result.brand == "SEB"
    assert result.confidence == 85

    urbo = score_domain("urbo-secure.example.com", load_brand_registry())
    assert urbo is not None
    assert urbo.brand == "Urbo"


def test_matches_close_typo_and_explains_score() -> None:
    result = score_domain("swedbannk-auth.example.com", load_brand_registry())
    assert result is not None
    assert result.brand == "Swedbank"
    assert result.confidence == 83
    assert "edit distance 1" in " ".join(result.reasons)


def test_requires_context_for_fuzzy_match() -> None:
    registry = load_brand_registry()
    assert score_domain("swedbannk.example.com", registry) is None
    assert score_domain("login.swedbannk.example.com", registry) is None

    result = score_domain("login-swedbannk.example.com", registry)
    assert result is not None
    assert result.brand == "Swedbank"


def test_preserves_digits_in_fuzzy_brand_matches() -> None:
    registry = load_brand_registry()
    assert score_domain("tele-support.example.com", registry) is None
    result = score_domain("telr2-support.example.com", registry)
    assert result is not None
    assert result.brand == "Tele2"


def test_matches_exact_brand_without_arbitrary_substrings() -> None:
    registry = load_brand_registry()
    result = score_domain("secure-revolut.example.com", registry)
    assert result is not None
    assert result.brand == "Revolut"
    assert score_domain("christianrevolutionary.com", registry) is None


def test_exact_long_alias_requires_same_label_context_or_punycode() -> None:
    registry = load_brand_registry()
    for domain in [
        "bigbank.net",
        "telia.example",
        "policija.example",
        "migracija.example",
        "itella.example",
        "ruta.revolut.team",
        "vps.luminor.pro",
        "vinted.id61932.com",
        "login.swedbank.example",
    ]:
        assert score_domain(domain, registry) is None, domain

    assert score_domain("service-revolut.example", registry) is not None
    assert score_domain("cards-revolut.example", registry) is not None
    assert score_domain("prisijungti-swedbank.example", registry) is not None
    punycode = score_domain("xn--wedbank-iog.example", registry)
    assert punycode is not None
    assert punycode.brand == "Swedbank"
    assert "multiple hyphens" not in punycode.reasons


def test_punycode_evidence_does_not_cross_dns_labels() -> None:
    registry = load_brand_registry()
    assert score_domain("revolut.xn--bcher-kva.example", registry) is None
    assert score_domain("swedbannk.xn--bcher-kva.example", registry) is None


def test_fuzzy_matching_is_limited_to_reviewed_aliases() -> None:
    registry = load_brand_registry()
    false_positives = [
        "minted-login.example",
        "hinted-login.example",
        "tinted-login.example",
        "vented-login.example",
        "luminar-login.example",
        "ignites-login.example",
        "melia-login.example",
        "delia-login.example",
        "helia-login.example",
        "sora-login.example",
        "maximal-login.example",
        "uniparks-login.example",
    ]
    for domain in false_positives:
        assert score_domain(domain, registry) is None, domain

    assert score_domain("swedbannk-auth.example", registry) is not None
    assert score_domain("telr2-support.example", registry) is not None


def test_rejects_social_noise_and_ambiguous_multi_brand_matches() -> None:
    registry = load_brand_registry()
    for domain in ["sociacta.example", "sociacta-login.example", "socialacta.example"]:
        assert score_domain(domain, registry) is None
    assert score_domain("secure-revolut-swedbank-login.example", registry) is None
    assert match_brand_text("Swedbank and Revolut secure login", registry) is None


def test_normalizes_wildcard_certificate_names() -> None:
    result = score_domain("*.secure-omniva.example", load_brand_registry())
    assert result is not None
    assert result.brand == "Omniva"


def test_registry_has_unique_domains_aliases_and_https_sources() -> None:
    registry = load_brand_registry()
    domains = [domain for entry in registry.entries for domain in entry.official_domains]
    excluded_domains = [domain for entry in registry.entries for domain in entry.excluded_domains]
    aliases = [alias.casefold() for entry in registry.entries for alias in entry.aliases]
    assert len(domains) == len(set(domains))
    assert len(excluded_domains) == len(set(excluded_domains))
    assert not set(domains).intersection(excluded_domains)
    assert len(aliases) == len(set(aliases))
    assert all(source.startswith("https://") for entry in registry.entries for source in entry.sources)
    fuzzy = {entry.brand: entry.fuzzy_aliases for entry in registry.entries if entry.fuzzy_aliases}
    assert fuzzy == {"Swedbank": ["swedbank"], "Tele2": ["tele2"]}


def test_registry_rejects_unreviewed_fuzzy_aliases(tmp_path: Path) -> None:
    payload = json.loads(Path("data/brands-lt.json").read_text(encoding="utf-8"))
    payload["entries"][0]["fuzzyAliases"] = ["not-an-alias"]
    target = tmp_path / "brands.json"
    target.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="invalid fuzzy alias"):
        load_brand_registry(target)


def test_registry_rejects_invalid_official_domains(tmp_path: Path) -> None:
    payload = json.loads(Path("data/brands-lt.json").read_text(encoding="utf-8"))
    payload["entries"][0]["officialDomains"].append("https://not-a-domain.example/path")
    target = tmp_path / "brands.json"
    target.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="entry 1 is invalid"):
        load_brand_registry(target)


def test_registry_rejects_official_and_excluded_domain_overlap(tmp_path: Path) -> None:
    payload = json.loads(Path("data/brands-lt.json").read_text(encoding="utf-8"))
    payload["entries"][0]["excludedDomains"] = [payload["entries"][0]["officialDomains"][0]]
    target = tmp_path / "brands.json"
    target.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="overlaps official and excluded domains"):
        load_brand_registry(target)


@pytest.mark.parametrize("field", ["aliases", "excludedTerms", "officialDomains", "sources"])
def test_registry_rejects_duplicate_values(field: str, tmp_path: Path) -> None:
    payload = json.loads(Path("data/brands-lt.json").read_text(encoding="utf-8"))
    payload["entries"][0][field].append(payload["entries"][0][field][0])
    target = tmp_path / "brands.json"
    target.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate values"):
        load_brand_registry(target)


@pytest.mark.parametrize("reviewed_at", ["not-a-date", "2026-8-21", "2026-02-30"])
def test_registry_rejects_malformed_review_date(reviewed_at: str, tmp_path: Path) -> None:
    payload = json.loads(Path("data/brands-lt.json").read_text(encoding="utf-8"))
    payload["reviewedAt"] = reviewed_at
    target = tmp_path / "brands.json"
    target.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="valid YYYY-MM-DD"):
        load_brand_registry(target)


def test_registry_covers_documented_lithuanian_impersonation_targets() -> None:
    registry = load_brand_registry()
    brands = {entry.brand for entry in registry.entries}
    assert {"Elektrum", "LP EXPRESS", "Skelbiu.lt", "SmartPosti", "Urbo"} <= brands
    assert len(registry.entries) >= 45


def test_resolves_only_exact_reviewed_brand_names_and_title_tokens() -> None:
    registry = load_brand_registry()
    assert resolve_brand_name("swedbank", registry) == "Swedbank"
    assert resolve_brand_name("Sberbank", registry) is None
    assert match_brand_text("Swedbank secure login", registry) == "Swedbank"
    assert match_brand_text("A revolution in payments", registry) is None
    assert is_brand_collision("sberbank-login.example", "Swedbank", registry)
    assert not is_brand_collision("secure-swedbank-login.example", "Swedbank", registry)
