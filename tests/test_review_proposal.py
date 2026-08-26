from __future__ import annotations

from pathlib import Path

import pytest

from hecavex_radar.brands import BrandEntry, BrandRegistry
from hecavex_radar.review_proposal import ProposalInput, build_proposal, write_proposal


def _registry() -> BrandRegistry:
    return BrandRegistry(
        scope="test",
        reviewed_at="2026-08-26",
        entries=[
            BrandEntry(
                brand="Vinted",
                last_reviewed_at="2026-08-26",
                aliases=["vinted"],
                fuzzy_aliases=["vinted"],
                excluded_terms=[],
                excluded_domains=[],
                category="marketplace",
                official_domains=["vinted.lt"],
                sources=["https://www.vinted.lt/"],
            )
        ],
    )


def _input(**changes: str | None) -> ProposalInput:
    values: dict[str, str | None] = {
        "action": "false-positive",
        "issue_number": "42",
        "repository": "Hecavex/radar.hecavex.com",
        "brand": "Vinted",
        "subject": "support-vinted[.]example",
        "reason": "unrelated-name-collision",
        "scope": "exact",
        "signal_id": "0123456789abcdefabcd",
    }
    values.update(changes)
    return ProposalInput(**values)  # type: ignore[arg-type]


def test_build_proposal_contains_only_controlled_sanitized_fields() -> None:
    proposal = build_proposal(
        _input(),
        _registry(),
        created_at="2026-08-26T10:00:00.000Z",
    )
    assert proposal["issueReference"] == "https://github.com/Hecavex/radar.hecavex.com/issues/42"
    assert proposal["subject"] == "support-vinted[.]example"
    assert proposal["state"] == "proposed"
    assert "note" not in proposal


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("subject", "support-vinted.example"),
        ("subject", "https://support-vinted[.]example"),
        ("subject", "support-vinted[.]example;echo-test"),
        ("signal_id", "../../unsafe"),
        ("issue_number", "42; env"),
        ("repository", "Hecavex/radar.hecavex.com/extra"),
        ("brand", "Not registered"),
        ("reason", "free-form-reason"),
    ],
)
def test_build_proposal_rejects_untrusted_or_uncontrolled_values(field: str, value: str) -> None:
    with pytest.raises(ValueError):
        build_proposal(_input(**{field: value}), _registry(), created_at="2026-08-26T10:00:00.000Z")


def test_write_proposal_stays_in_review_proposal_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    proposal = build_proposal(_input(), _registry(), created_at="2026-08-26T10:00:00.000Z")
    output = tmp_path / "data" / "review" / "proposals" / "42.json"
    write_proposal(output, proposal)
    assert output.is_file()
    with pytest.raises(ValueError):
        write_proposal(tmp_path / "outside.json", proposal)
