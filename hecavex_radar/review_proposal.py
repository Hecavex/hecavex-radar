from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from .brands import BrandRegistry, load_brand_registry

SIGNAL_ID: Final = re.compile(r"^[a-f\d]{20}$")
DEFANGED_DOMAIN: Final = re.compile(
    r"^(?:[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?\[\.\])+(?:xn--)?[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?$",
    re.IGNORECASE,
)
ISSUE_NUMBER: Final = re.compile(r"^[1-9]\d{0,8}$")
REPOSITORY: Final = re.compile(r"^[A-Za-z\d_.-]{1,100}/[A-Za-z\d_.-]{1,100}$")

ACTIONS: Final = frozenset(
    {"false-positive", "missed-candidate", "official-domain-correction", "removal-request"}
)
SCOPES: Final = frozenset({"exact", "subdomains"})
REASONS: Final = {
    "false-positive": frozenset(
        {
            "unrelated-name-collision",
            "official-or-authorized-domain",
            "benign-brand-reference",
            "shared-hosting-or-platform",
            "incorrect-brand-mapping",
            "insufficient-evidence",
        }
    ),
    "missed-candidate": frozenset(
        {
            "certificate-transparency-record",
            "public-urlscan-report",
            "public-provider-advisory",
            "public-brand-advisory",
            "other-public-passive-source",
        }
    ),
    "official-domain-correction": frozenset(
        {
            "add-official-domain",
            "remove-official-domain",
            "add-reviewed-exclusion",
        }
    ),
    "removal-request": frozenset(
        {
            "remove-current-candidate",
            "retract-reviewed-assessment",
            "remove-screenshot-or-derived-artifact",
            "correct-public-metadata",
        }
    ),
}


@dataclass(frozen=True, slots=True)
class ProposalInput:
    action: str
    issue_number: str
    repository: str
    brand: str
    subject: str
    reason: str
    scope: str
    signal_id: str | None = None


def _timestamp(now: datetime | None = None) -> str:
    value = (now or datetime.now(UTC)).astimezone(UTC)
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _brand(value: str, registry: BrandRegistry) -> str:
    candidate = value.strip()
    if candidate not in {entry.brand for entry in registry.entries}:
        raise ValueError("Brand must exactly match a reviewed registry entry.")
    return candidate


def _defanged_subject(value: str) -> str:
    candidate = value.strip().lower()
    if not 4 <= len(candidate) <= 253 or not DEFANGED_DOMAIN.fullmatch(candidate):
        raise ValueError("Subject must be one bounded, fully defanged domain.")
    if "." in candidate.replace("[.]", "") or "://" in candidate or "@" in candidate:
        raise ValueError("Subject contains a live or unsafe indicator form.")
    return candidate


def build_proposal(
    proposal: ProposalInput,
    registry: BrandRegistry,
    *,
    created_at: str | None = None,
) -> dict[str, object]:
    if proposal.action not in ACTIONS:
        raise ValueError("Unknown proposal action.")
    if not ISSUE_NUMBER.fullmatch(proposal.issue_number):
        raise ValueError("Issue number is invalid.")
    if not REPOSITORY.fullmatch(proposal.repository):
        raise ValueError("Repository identifier is invalid.")
    if proposal.reason not in REASONS[proposal.action]:
        raise ValueError("Reason is not valid for this proposal action.")
    if proposal.scope not in SCOPES:
        raise ValueError("Review scope must be exact or subdomains.")
    if proposal.signal_id is not None and not SIGNAL_ID.fullmatch(proposal.signal_id):
        raise ValueError("Signal ID must be 20 lowercase hexadecimal characters.")
    if proposal.action in {"false-positive", "removal-request"} and proposal.signal_id is None:
        raise ValueError("This proposal action requires a public Radar signal ID.")

    timestamp = created_at or _timestamp()
    try:
        parsed = datetime.fromisoformat(timestamp.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise ValueError("Proposal timestamp is invalid.") from error
    if parsed.isoformat(timespec="milliseconds").replace("+00:00", "Z") != timestamp:
        raise ValueError("Proposal timestamp must be canonical UTC with milliseconds.")

    result: dict[str, object] = {
        "schemaVersion": 1,
        "dataset": "radar-review-proposal",
        "createdAt": timestamp,
        "action": proposal.action,
        "issueReference": f"https://github.com/{proposal.repository}/issues/{proposal.issue_number}",
        "brand": _brand(proposal.brand, registry),
        "subject": _defanged_subject(proposal.subject),
        "reasonCode": proposal.reason,
        "scope": proposal.scope,
        "state": "proposed",
        "semantics": "Sanitized proposal only; it is not a review decision and cannot publish or scan a candidate.",
    }
    if proposal.signal_id is not None:
        result["signalId"] = proposal.signal_id
    return result


def write_proposal(path: Path, proposal: dict[str, object]) -> None:
    resolved = path.resolve()
    proposal_root = (Path.cwd() / "data" / "review" / "proposals").resolve()
    if proposal_root not in resolved.parents or resolved.suffix != ".json":
        raise ValueError("Review proposals must stay below data/review/proposals as JSON files.")
    resolved.parent.mkdir(parents=True, exist_ok=True)
    resolved.write_text(json.dumps(proposal, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create one validated, sanitized Radar review proposal.")
    parser.add_argument("--action", required=True, choices=sorted(ACTIONS))
    parser.add_argument("--issue-number", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--brand", required=True)
    parser.add_argument("--subject", required=True)
    parser.add_argument("--reason", required=True)
    parser.add_argument("--scope", required=True, choices=sorted(SCOPES))
    parser.add_argument("--signal-id")
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args(argv)
    registry = load_brand_registry()
    proposal = build_proposal(
        ProposalInput(
            action=options.action,
            issue_number=options.issue_number,
            repository=options.repository,
            brand=options.brand,
            subject=options.subject,
            reason=options.reason,
            scope=options.scope,
            signal_id=options.signal_id or None,
        ),
        registry,
    )
    write_proposal(options.output, proposal)
    print(f"Created sanitized proposal {options.output}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
