from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal, NotRequired, TypedDict

SignalStatus = Literal["active", "suspected", "offline", "mitigated", "unknown"]
SourceState = Literal["healthy", "partial", "skipped"]
BrandEvidence = Literal["domain", "title", "verdict", "primary-html-sha256"]
ReasonCode = Literal[
    "brand-domain-match",
    "brand-title-match",
    "provider-verdict",
    "primary-html-hash-pivot",
    "brand-exact-token",
    "brand-joined-affix",
    "brand-split-token",
    "brand-lookalike-edit",
    "suspicious-context",
    "punycode",
    "different-tld",
    "multiple-hyphens",
    "hecavex-public-export",
    "manual-review",
    "first-publication",
    "source-status-change",
]


@dataclass(slots=True)
class RawSignal:
    url: str
    source: str
    first_seen: str | None = None
    last_seen: str | None = None
    status: str | None = None
    brand: str | None = None
    country: str | None = None
    host: str | None = None
    screenshot_url: str | None = None
    reference_url: str | None = None
    hashes: list[str] | None = None
    confidence: float | None = None
    reason_codes: Sequence[str] | None = None


class RadarSource(TypedDict):
    name: str
    homepage: str
    fetchedAt: str | None
    records: int
    state: SourceState
    note: str | None


class RadarSignal(TypedDict):
    id: str
    url: str
    domain: str
    firstSeen: str
    lastSeen: str
    sources: list[str]
    status: SignalStatus
    brand: str | None
    country: str | None
    host: str | None
    screenshotUrl: str | None
    referenceUrl: NotRequired[str | None]
    hashes: NotRequired[list[str]]
    brandEvidence: NotRequired[list[BrandEvidence]]
    reasonCodes: NotRequired[list[ReasonCode]]
    confidence: int


@dataclass(slots=True)
class SourceResult:
    source: RadarSource
    signals: list[RawSignal]


@dataclass(frozen=True, slots=True)
class SafeUrl:
    key: str
    display_url: str
    display_domain: str


@dataclass(frozen=True, slots=True)
class CandidateMatch:
    domain: str
    registrable_domain: str
    brand: str
    confidence: int
    reasons: list[str]


class CertStreamCandidate(TypedDict):
    schemaVersion: Literal[1]
    id: str
    observedAt: str
    indicatorType: Literal["domain"]
    domain: str
    registrableDomain: str
    source: Literal["CertStream"]
    brand: str
    confidence: int
    reasons: list[str]
