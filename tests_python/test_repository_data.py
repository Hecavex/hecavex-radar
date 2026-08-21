from pathlib import Path

from hecavex_radar.brands import load_brand_registry
from hecavex_radar.certstream_archive import read_candidate_file
from hecavex_radar.urlscan import _reviewed_archive_signal, read_urlscan_file


def _record_lines(path: Path) -> int:
    return sum(bool(line.strip()) for line in path.read_text(encoding="utf-8").splitlines())


def test_every_checked_in_certstream_record_passes_the_current_contract() -> None:
    for path in Path("data/certstream").glob("????-??-??/domains.ndjson"):
        assert len(read_candidate_file(path)) == _record_lines(path), path


def test_every_checked_in_urlscan_record_passes_current_contract_and_review() -> None:
    registry = load_brand_registry()
    for path in Path("data/urlscan").glob("????-??-??/signals.ndjson"):
        records = read_urlscan_file(path)
        assert len(records) == _record_lines(path), path
        assert all(_reviewed_archive_signal(record, registry) for record in records), path
