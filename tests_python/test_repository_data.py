import base64
import hashlib
import re
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


def test_reader_facing_documentation_routes_are_canonical_and_discoverable() -> None:
    methodology = Path("methodology/index.html").read_text(encoding="utf-8")
    documentation = Path("docs/index.html").read_text(encoding="utf-8")
    sitemap = Path("public/sitemap.xml").read_text(encoding="utf-8")

    assert '<link rel="canonical" href="https://radar.hecavex.com/methodology/"' in methodology
    assert '<link rel="canonical" href="https://radar.hecavex.com/docs/"' in documentation
    assert "https://radar.hecavex.com/methodology/" in sitemap
    assert "https://radar.hecavex.com/docs/" in sitemap


def test_root_json_ld_hash_matches_the_content_security_policy() -> None:
    root = Path("index.html").read_text(encoding="utf-8")
    match = re.search(r'<script type="application/ld\+json">(.*?)</script>', root, re.DOTALL)
    assert match is not None
    digest = base64.b64encode(hashlib.sha256(match.group(1).encode()).digest()).decode()
    assert f"'sha256-{digest}'" in root
    assert '"license":"https://radar.hecavex.com/docs/#data-terms"' in match.group(1)


def test_certstream_workflow_commits_candidates_and_health_atomically() -> None:
    workflow = Path(".github/workflows/collect-certstream.yml").read_text(encoding="utf-8")
    deploy = Path(".github/workflows/deploy-pages.yml").read_text(encoding="utf-8")

    assert "python -m hecavex_radar.collection_health begin" in workflow
    assert "python -m hecavex_radar.collection_health finalize" in workflow
    assert "git add -- data/certstream public/data/collection-health.json" in workflow
    assert "if: always() && steps.health.outcome == 'success'" in workflow
    assert "CERTSTREAM_INSTALL_OUTCOME: ${{ steps.dependencies.outcome }}" in workflow
    assert "CERTSTREAM_PREPARE_OUTCOME: ${{ steps.source.outcome }}" in workflow
    assert "CERTSTREAM_COLLECTOR_OUTCOME: ${{ steps.collector.outcome }}" in workflow
    assert "actions: write" not in workflow
    assert "gh workflow run deploy-pages.yml" not in workflow
    assert 'workflows: ["CI"]' in deploy
    assert "Sync radar snapshot" not in deploy
