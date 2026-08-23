# Architecture

This document describes the production architecture behind the HECAVEX-operated service at [radar.hecavex.com](https://radar.hecavex.com). Radar uses a Python collection and validation pipeline with a static React/TypeScript viewer; it is not a reusable application architecture or self-hosting guide.

| Input | Gate before publication | Public label |
| --- | --- | --- |
| CertStream certificate names | Current Lithuanian brand matcher, confidence threshold, and daily archive validation | `CertStream` |
| Existing URLScan reports | Passive searches, automated same-brand evidence checks, official-domain suppression, and report validation | `URLScan` |
| Configured HECAVEX public export | HTTPS fetch, public schema validation, and shared brand/safety checks | `HECAVEX` |
| Transient intelligence seeds | Exact URLScan lookup only; seeds are neither archived nor published | None |

## Runtime

CertStream and URLScan collection write independent daily archives. Every CertStream workflow attempt also atomically replaces one bounded `public/data/collection-health.json` document with actual attempt timing and aggregate counts; it never contains certificate names or unpublished candidates. `python -m hecavex_radar.sync` validates the archives together with an optional HECAVEX export and sanitized review decisions, then merges, limits, sorts, and atomically replaces `public/data/radar.json`. A qualifying CertStream observation becomes a `suspected` dashboard row even when URLScan has no report; URLScan can add a report, screenshot, hashes, and hosting metadata later but is never a publication gate for that row.

URLScan is an optional passive enricher scheduled at minute 37 every two hours. Each search is limited to existing public reports from the rolling previous seven days. Every run attempts the complete bounded set of at most 250 recent CertStream, Radar-snapshot, and transient discovery candidates. A deterministic cursor preserves progress when an operator lowers the per-run selection or a request budget interrupts that set. Result retrieval remains passive: Radar neither submits a scan nor visits a candidate host.

Each material hunter state transition atomically replaces `data/urlscan/hunt-state.json`, and the workflow stages `data/urlscan/` even when the hunter ultimately reports failure. The fixed, bounded ledger contains only configuration state, UTC budget counters, a numeric cursor, candidate counts, timestamps, and an outcome; it contains no API key or candidate domain. If the credential is absent, the hunter makes no API request, records `configured: false` and `skipped-not-configured`, and exits successfully. Repeated identical unconfigured runs in the same UTC day remain visible in Actions history but do not rewrite the timestamp-only ledger or create empty commits. A failed or rate-limited refresh remains observable without removing, treating as benign, or downgrading an independently qualifying CertStream candidate.

Synchronization also assigns deterministic event IDs to accepted observations and explicit status changes. Daily history partitions are append-only inside a 30-day default detail window. Older partitions compact into a bounded two-year summary; the public projection is `public/data/history.json`. Absence from a later source window does not generate a transition. The scheduled writer commits the live snapshot and history artifacts in one Git commit.

Private review is a separate trust boundary. `hecavex-review` keeps an append-only SQLite ledger outside the repository. An operator must explicitly export active decisions into `data/review/public-decisions.json`; only that strict, defanged schema is consumed by synchronization. Private notes, analyst identity, and raw evidence never cross the export boundary.

Pages builds the committed dashboard together with reader-facing `/history/`, `/methodology/`, and `/docs/` pages. The browser has no backend API, login, or database. HECAVEX feed URLs require HTTPS in production and cannot contain credentials or an explicit port. HTTP is accepted on `localhost`, `127.0.0.1`, or `::1` at the default port only for maintainer tests.

## Certificate Transparency coverage

The current GitHub Actions listener samples CertStream for four minutes twice per hour. It is a low-latency discovery input, not continuous or replayable coverage. The public health file makes late, empty, partial, and failed sampled windows visible; it does not recover events outside a listening window. [ADR 0001](decisions/0001-ct-coverage.md) selects checkpointed CT-log or API polling and backfill as the durable Stage 02 source while retaining CertStream for latency.

## Safety boundaries

- All certificates, reports, archives, seeds, and configured exports are untrusted input and are normalized and validated before use.
- Collection is passive. CertStream supplies certificate names and URLScan supplies existing reports; Radar does not visit candidate hosts or submit URLs for scanning.
- URLScan request budgets default to 25 searches and 100 result retrievals per run, and 900 searches and 8,000 result retrievals per UTC day. These conservative local limits remain below the published provider quotas. Only successful responses increment the local ledger; HTTP 429 stops the run without further requests.
- Indicators remain defanged text. References are canonical URLScan result URLs; screenshots use HTTPS on exactly `urlscan.io`—never a subdomain—and contain no credentials, explicit port, query string, or fragment. Published hashes are SHA-256 values for the primary HTML document.
- Only the sync stage writes the public snapshot. Publication is guarded against invalid or unexpectedly small output, and one unavailable optional source does not erase healthy-source data.
- History event identity excludes mutable scoring explanations, so a registry wording or score change cannot turn one source observation into multiple events. Brand conflicts are rejected before history publication.
- An operator review addition must independently pass the current public domain matcher. Its confidence cannot exceed that matcher, its status is always `suspected`, and a suppression takes precedence over an addition.
- Collection health uses a strict fixed-field schema, a 32 KiB limit, and atomic replacement of one file. It exposes aggregate counters and timing only, so attempts do not create an unbounded telemetry archive.
- HECAVEX integration accepts a deliberately limited public export. Private detector features, evidence graphs, analyst notes, user data, credentials, and internal history stay outside this repository.
