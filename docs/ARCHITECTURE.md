# Architecture

HECAVEX Radar is a Python collection and validation pipeline with a static React/TypeScript viewer.

| Input | Gate before publication | Public label |
| --- | --- | --- |
| CertStream certificate names | Current Lithuanian brand matcher, confidence threshold, and daily archive validation | `CertStream` |
| Existing URLScan reports | Passive searches, automated same-brand evidence checks, official-domain suppression, and report validation | `URLScan` |
| Configured HECAVEX public export | HTTPS fetch, public schema validation, and shared brand/safety checks | `HECAVEX` |
| Transient intelligence seeds | Exact URLScan lookup only; seeds are neither archived nor published | None |

## Runtime

CertStream and URLScan collection write independent daily archives. `python -m hecavex_radar.sync` validates those archives together with an optional HECAVEX export, then merges, limits, sorts, and atomically replaces `public/data/radar.json`. A qualifying CertStream observation becomes a `suspected` dashboard row even when URLScan has no report; URLScan can add a report, screenshot, hashes, and hosting metadata later but is never a publication gate for that row. The scheduled snapshot writer commits the snapshot so the next run has the real prior-publication baseline; Pages builds the committed dashboard together with reader-facing `/methodology/` and `/docs/` pages. The browser has no backend API, login, or database. HECAVEX feed URLs require HTTPS in production and cannot contain credentials or an explicit port. For local development only, HTTP is accepted on `localhost`, `127.0.0.1`, or `::1` at the default port.

## Safety boundaries

- All certificates, reports, archives, seeds, and configured exports are untrusted input and are normalized and validated before use.
- Collection is passive. CertStream supplies certificate names and URLScan supplies existing reports; Radar does not visit candidate hosts or submit URLs for scanning.
- Indicators remain defanged text. References are canonical URLScan result URLs; screenshots use HTTPS on exactly `urlscan.io`—never a subdomain—and contain no credentials, explicit port, query string, or fragment. Published hashes are SHA-256 values for the primary HTML document.
- Only the sync stage writes the public snapshot. Publication is guarded against invalid or unexpectedly small output, and one unavailable optional source does not erase healthy-source data.
- HECAVEX integration accepts a deliberately limited public export. Private detector features, evidence graphs, analyst notes, user data, credentials, and internal history stay outside this repository.
