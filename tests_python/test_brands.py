from hecavex_radar.brands import load_brand_registry, score_domain


def test_suppresses_official_domains_and_subdomains() -> None:
    registry = load_brand_registry()
    assert score_domain("swedbank.lt", registry) is None
    assert score_domain("login.swedbank.lt", registry) is None
    assert score_domain("www.revolut.com", registry) is None


def test_does_not_match_short_brand_inside_unrelated_word() -> None:
    assert score_domain("sebastian.example.com", load_brand_registry()) is None
    assert score_domain("urban.example.com", load_brand_registry()) is None


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


def test_normalizes_wildcard_certificate_names() -> None:
    result = score_domain("*.secure-omniva.example", load_brand_registry())
    assert result is not None
    assert result.brand == "Omniva"


def test_registry_has_unique_domains_aliases_and_https_sources() -> None:
    registry = load_brand_registry()
    domains = [domain for entry in registry.entries for domain in entry.official_domains]
    aliases = [alias.casefold() for entry in registry.entries for alias in entry.aliases]
    assert len(domains) == len(set(domains))
    assert len(aliases) == len(set(aliases))
    assert all(source.startswith("https://") for entry in registry.entries for source in entry.sources)


def test_registry_covers_documented_lithuanian_impersonation_targets() -> None:
    registry = load_brand_registry()
    brands = {entry.brand for entry in registry.entries}
    assert {"Elektrum", "LP EXPRESS", "Skelbiu.lt", "SmartPosti", "Urbo"} <= brands
    assert len(registry.entries) >= 45
