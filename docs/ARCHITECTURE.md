# Architecture

HECAVEX Radar is a Python collection and validation pipeline with a static React/TypeScript viewer.

| Input | Gate before publication | Public label |
| --- | --- | --- |
| CertStream certificate names | Current Lithuanian brand matcher, confidence threshold, and daily archive validation | `CertStream` |
| Existing URLScan reports | Passive searches, automated same-brand evidence checks, official-domain suppression, and report validation | `URLScan` |
| Configured HECAVEX public export | HTTPS fetch, public schema validation, and shared brand/safety checks | `HECAVEX` |
| Transient intelligence seeds | Exact URLScan lookup only; seeds are neither archived nor published | None |

## Runtime

CertStream and URLScan collection write independent daily archives. Every CertStream workflow attempt also atomically replaces one bounded `public/data/collection-health.json` document with actual attempt timing and aggregate counts; it never contains certificate names or unpublished candidates. `python -m hecavex_radar.sync` validates the archives together with an optional HECAVEX export and sanitized review decisions, then merges, limits, sorts, and atomically replaces `public/data/radar.json`. A qualifying CertStream observation becomes a `suspected` dashboard row even when URLScan has no report; URLScan can add a report, screenshot, hashes, and hosting metadata later but is never a publication gate for that row.

Synchronization also assigns deterministic event IDs to accepted observations and explicit status changes. Daily history partitions are append-only inside a 30-day default detail window. Older partitions compact into a bounded two-year summary; the public projection is `public/data/history.json`. Absence from a later source window does not generate a transition. The scheduled writer commits the live snapshot and history artifacts in one Git commit.

Private review is a separate trust boundary. `hecavex-review` keeps an append-only SQLite ledger outside the repository. An operator must explicitly export active decisions into `data/review/public-decisions.json`; only that strict, defanged schema is consumed by synchronization. Private notes, analyst identity, and raw evidence never cross the export boundary.

Pages builds the committed dashboard together with reader-facing `/history/`, `/methodology/`, and `/docs/` pages. The browser has no backend API, login, or database. HECAVEX feed URLs require HTTPS in production and cannot contain credentials or an explicit port. For local development only, HTTP is accepted on `localhost`, `127.0.0.1`, or `::1` at the default port.

## Certificate Transparency coverage

The current GitHub Actions listener samples CertStream for four minutes twice per hour. It is a low-latency discovery input, not continuous or replayable coverage. The public health file makes late, empty, partial, and failed sampled windows visible; it does not recover events outside a listening window. [ADR 0001](decisions/0001-ct-coverage.md) selects checkpointed CT-log or API polling and backfill as the durable Stage 02 source while retaining CertStream for latency.

## Safety boundaries

- All certificates, reports, archives, seeds, and configured exports are untrusted input and are normalized and validated before use.
- Collection is passive. CertStream supplies certificate names and URLScan supplies existing reports; Radar does not visit candidate hosts or submit URLs for scanning.
- Indicators remain defanged text. References are canonical URLScan result URLs; screenshots use HTTPS on exactly `urlscan.io`—never a subdomain—and contain no credentials, explicit port, query string, or fragment. Published hashes are SHA-256 values for the primary HTML document.
- Only the sync stage writes the public snapshot. Publication is guarded against invalid or unexpectedly small output, and one unavailable optional source does not erase healthy-source data.
- History event identity excludes mutable scoring explanations, so a registry wording or score change cannot turn one source observation into multiple events. Brand conflicts are rejected before history publication.
- A local review addition must independently pass the current public domain matcher. Its confidence cannot exceed that matcher, its status is always `suspected`, and a suppression takes precedence over an addition.
- Collection health uses a strict fixed-field schema, a 32 KiB limit, and atomic replacement of one file. It exposes aggregate counters and timing only, so attempts do not create an unbounded telemetry archive.
- HECAVEX integration accepts a deliberately limited public export. Private detector features, evidence graphs, analyst notes, user data, credentials, and internal history stay outside this repository.
