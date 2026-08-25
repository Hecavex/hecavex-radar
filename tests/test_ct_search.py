from __future__ import annotations

from datetime import UTC, datetime

from hecavex_radar.brands import BrandEntry, BrandRegistry, score_domain
from hecavex_radar.certstream_archive import CandidateArchiveWriter, candidate_from_match, read_recent_candidates
from hecavex_radar.ct_search import build_queries, parse_row, poll, read_state


def _registry() -> BrandRegistry:
    return BrandRegistry(
        scope="test registry",
        reviewed_at="2026-08-25",
        entries=[
            BrandEntry(
                brand="Swedbank",
                aliases=["swedbank"],
                fuzzy_aliases=["swedbank"],
                excluded_terms=["sberbank"],
                excluded_domains=[],
                category="banking",
                official_domains=["swedbank.lt"],
                sources=["https://www.swedbank.lt/"],
            )
        ],
    )


def test_parse_crt_sh_row_normalizes_public_certificate_fields() -> None:
    row = parse_row(
        {
            "id": 42,
            "entry_timestamp": "2026-08-25T10:30:00Z",
            "name_value": "secure-swedbank-login.com\n*.secure-swedbank-login.com",
            "common_name": "secure-swedbank-login.com",
            "issuer_name": "Example CA",
            "not_before": "2026-08-25T10:00:00Z",
            "not_after": "2026-11-23T10:00:00Z",
            "serial_number": "AA:10",
        }
    )

    assert row is not None
    assert row.identifier == 42
    assert row.domains == ("secure-swedbank-login.com",)
    assert row.certificate is not None
    assert row.certificate.serial_number_hex == "aa10"


def test_checkpoint_prevents_duplicate_archive_records(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    now = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)
    payload = [
        {
            "id": 100,
            "entry_timestamp": "2026-08-25T11:55:00Z",
            "name_value": "secure-swedbank-login.com",
            "common_name": "secure-swedbank-login.com",
            "issuer_name": "Example CA",
            "not_before": "2026-08-25T11:50:00Z",
            "not_after": "2026-11-23T11:50:00Z",
            "serial_number": "10",
        }
    ]

    first = poll(
        lambda _url: payload,
        now=now,
        registry=_registry(),
        queries_per_run=1,
        rows_per_query=10,
        bootstrap_days=7,
    )
    second = poll(
        lambda _url: payload,
        now=now,
        registry=_registry(),
        queries_per_run=1,
        rows_per_query=10,
        bootstrap_days=7,
    )

    assert first["newRecords"] == 1
    assert second["newRecords"] == 0
    assert read_state()["queries"]["brand:swedbank"]["lastId"] == 100
    archived = read_recent_candidates("data/certstream", 7, now)
    assert len(archived) == 1
    assert archived[0]["domain"] == "secure-swedbank-login[.]com"


def test_query_builder_avoids_short_global_brand_term() -> None:
    registry = BrandRegistry(
        scope="test",
        reviewed_at="2026-08-25",
        entries=[
            BrandEntry(
                brand="BTA",
                aliases=["bta", "bta draudimas"],
                fuzzy_aliases=[],
                excluded_terms=[],
                excluded_domains=[],
                category="insurance",
                official_domains=["bta.lt"],
                sources=["https://www.bta.lt/"],
            )
        ],
    )

    queries = build_queries(registry)
    assert [(query.brand, query.term) for query in queries] == [("BTA", "btadraudimas")]


def test_late_indexed_row_inside_overlap_is_replayed(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    now = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)
    first_payload = [
        {
            "id": 100,
            "entry_timestamp": "2026-08-25T11:55:00Z",
            "name_value": "secure-swedbank-login.com",
        }
    ]
    poll(lambda _url: first_payload, now=now, registry=_registry(), queries_per_run=1, rows_per_query=10)
    late_payload = [
        {
            "id": 99,
            "entry_timestamp": "2026-08-25T11:54:00Z",
            "name_value": "verify-swedbank-account.com",
        },
        *first_payload,
    ]
    replay = poll(lambda _url: late_payload, now=now, registry=_registry(), queries_per_run=1, rows_per_query=10)

    assert replay["newRecords"] == 1
    assert {item["domain"] for item in read_recent_candidates("data/certstream", 7, now)} == {
        "secure-swedbank-login[.]com",
        "verify-swedbank-account[.]com",
    }


def test_backlog_is_partial_and_resumes_before_rotation(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    now = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)
    payload = [
        {
            "id": identifier,
            "entry_timestamp": f"2026-08-25T11:5{identifier}:00Z",
            "name_value": f"secure-swedbank-{identifier}.com",
        }
        for identifier in (1, 2, 3)
    ]

    first = poll(lambda _url: payload, now=now, registry=_registry(), queries_per_run=1, rows_per_query=1)
    second = poll(lambda _url: payload, now=now, registry=_registry(), queries_per_run=1, rows_per_query=1)

    assert first["outcome"] == "partial"
    assert first["queriesBacklogged"] == 1
    assert second["outcome"] == "partial"
    assert read_state()["queries"]["brand:swedbank"]["lastId"] == 2
    assert read_state()["queryCursor"] == 0


def test_live_and_checkpoint_discovery_lineage_can_share_one_day(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    now = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)
    registry = _registry()
    match = score_domain("secure-swedbank-login.com", registry)
    assert match is not None
    writer = CandidateArchiveWriter("data/certstream")
    assert writer.append([candidate_from_match(match, now, collection_method="certstream-live")]) == 1

    result = poll(
        lambda _url: [
            {
                "id": 100,
                "entry_timestamp": "2026-08-25T12:00:00Z",
                "name_value": "secure-swedbank-login.com",
            }
        ],
        now=now,
        registry=registry,
        queries_per_run=1,
        rows_per_query=10,
    )
    archived = read_recent_candidates("data/certstream", 7, now)

    assert result["newRecords"] == 1
    assert {item.get("collectionMethod") for item in archived} == {"certstream-live", "ct-search-api"}
