# HECAVEX Radar

HECAVEX Radar is a public, read-only dashboard for recently observed potential phishing domains and URLs targeting Lithuanian brands. The dashboard requires no account and is intended for [radar.hecavex.com](https://radar.hecavex.com).

The Python pipeline samples Certificate Transparency candidates, hunts existing URLScan reports, accepts an optional configured HECAVEX public export, and builds a static JSON snapshot. Every input passes automated schema, safety, and Lithuanian-brand validation before publication. The React application renders that snapshot without an application server or database; the primary dashboard explanation, methodology, and documentation are also prerendered for no-JavaScript access and indexing.

## Scope

- Public source labels are limited to CertStream, URLScan, and configured HECAVEX exports.
- Indicators are defanged before publication. Query strings, fragments, credentials, and sensitive-looking path data are excluded.
- CertStream matches are leads, not confirmation of phishing. Every match that passes the public brand rules and configured confidence threshold is published as `suspected`; URLScan evidence is not required. The collector reads certificate names and never visits candidate hosts.
- URLScan hunting is optional enrichment and passive corroboration: it searches existing public reports and never submits or opens a candidate URL. Missing, unlisted, or private scan visibility rejects that URLScan observation, not an independently qualifying CertStream candidate.
- Screenshots and evidence links are URLScan-only. Opening evidence may contact `urlscan.io`, but never the observed host.
- The public brand registry and matching rules are independent of HECAVEX's private collectors, detection logic, and internal case history.
- The scheduled CertStream collector listens for four minutes twice per hour: at most 192 minutes, or 13.3% of a day, if every run starts and completes. It is sampled live coverage, not a daily snapshot or replay. A bounded public health artifact reports the latest attempt's actual timing, input counts, result, schedule delay, last success, and freshness without retaining raw certificate names.
- HECAVEX Radar is maintained as best-effort public research and provides no monitoring, response, notification, takedown, availability, or coverage SLA.

The dashboard provides search, filtering, pagination, first/last-seen timestamps, target brand, hosting metadata, confidence scores on a 0-100 scale, URLScan references and screenshots, primary HTML SHA-256 evidence, and controlled publication-reason codes when available. A confidence score is a ranking aid, not a probability. A separate [candidate history](https://radar.hecavex.com/history/) retains bounded observation provenance without interpreting disappearance as a lifecycle change.

## Repository layout

| Path | Purpose |
| --- | --- |
| `hecavex_radar/` | Python collectors, matching, normalization, and snapshot publisher |
| `src/` | Static React dashboard |
| `data/brands-lt.json` | Reviewed Lithuanian brand and official-domain registry |
| `data/certstream/` | Date-partitioned, defanged CT candidates |
| `data/urlscan/` | Date-partitioned, automatically validated URLScan observations |
| `data/history/` | Deterministic daily history events and bounded compacted summary |
| `data/review/` | Sanitized, explicitly exported review decisions only |
| `public/data/radar.json` | Checked-in dashboard snapshot |
| `public/data/history.json` | Checked-in, bounded public history view |
| `public/data/collection-health.json` | Latest bounded CertStream attempt health; no raw candidates |

## Local development

Requirements: Python 3.12 or newer, Node.js 22.22.2+ on the Node 22 LTS line (or Node 24.15+), and pnpm 10.

```sh
python -m pip install -e ".[dev]"
corepack enable
pnpm install
pnpm dev
```

The development server reads the checked-in snapshot at `http://localhost:5173`.

Run the Python stages independently as needed:

```sh
python -m hecavex_radar.collect_certstream
python -m hecavex_radar.urlscan
python -m hecavex_radar.sync
```

Private false-positive review is deliberately separate from the website and Git repository. The CLI creates an append-only SQLite ledger in the operating system's local application-data directory:

```sh
hecavex-review false-positive secure-swedbank-login.example --reason lexical-collision --note "private context"
hecavex-review restore secure-swedbank-login.example
hecavex-review add secure-swedbank-login.example --brand Swedbank
hecavex-review remove secure-swedbank-login.example
hecavex-review list
hecavex-review export
```

Only `export` writes a file in the repository, and that file contains sanitized active decisions rather than notes or analyst identity. See [Private review workflow](docs/REVIEW-WORKFLOW.md) before using subtree allowlists.

The URLScan hunter uses `URLSCAN_API_KEY` when it is present in the process environment. Without a key it reports a successful optional-source skip; independently qualifying CertStream candidates remain eligible and synchronization continues. The CertStream collector uses a four-minute window by default and can use a monitored endpoint through `CERTSTREAM_URL`. Collector and publisher settings are listed in [`.env.example`](.env.example); the application reads environment variables directly and does not load that file automatically.

## Brand registry

[`data/brands-lt.json`](data/brands-lt.json) contains reviewed aliases, official domains, optional collision exclusions, and supporting links. It is intentionally limited to brands relevant to Lithuania. Additions and corrections should cite authoritative sources; complete official-domain coverage is important because official domains and their subdomains are suppressed before scoring.

Matching behavior is documented in [Detection rules](docs/DETECTION.md).

## Verification

```sh
pnpm check
```

This runs Python and frontend linting, type checks, unit tests, the production build, built-link and fragment validation, HTML and metadata checks, CSP-enforced hydration and delayed-refresh checks, serious accessibility checks, no-JavaScript checks, and real-browser overflow and keyboard-navigation checks at 320, 360, 390, 768, 1024, and 1280 pixels. Chrome, Chromium, or Microsoft Edge is required for the browser verification.

## Documentation

- [Public methodology](https://radar.hecavex.com/methodology/)
- [Public core documentation](https://radar.hecavex.com/docs/)
- [Architecture](docs/ARCHITECTURE.md)
- [Public data contract](docs/DATA-CONTRACT.md)
- [Candidate history](docs/HISTORY.md)
- [Private review workflow](docs/REVIEW-WORKFLOW.md)
- [Performance budgets](docs/PERFORMANCE.md)
- [Data sources](docs/DATA-SOURCES.md)
- [Deployment](docs/DEPLOYMENT.md)
- [CT coverage decision](docs/decisions/0001-ct-coverage.md)
- [Data licensing and attribution](DATA-LICENSE.md)
- [Third-party production notices](public/THIRD-PARTY-NOTICES.txt)
- [Security policy](SECURITY.md)

The software is licensed under the [Apache License 2.0](LICENSE). Third-party data and screenshots retain their own terms.
