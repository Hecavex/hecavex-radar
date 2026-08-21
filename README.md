# HECAVEX Radar

HECAVEX Radar is a public, read-only dashboard for recently observed potential phishing domains and URLs targeting Lithuanian brands. The dashboard requires no account and is intended for [radar.hecavex.com](https://radar.hecavex.com).

The Python pipeline collects Certificate Transparency candidates, hunts existing URLScan reports, accepts an optional configured HECAVEX public export, and builds a static JSON snapshot. Every input passes automated schema, safety, and Lithuanian-brand validation before publication. The React application renders that snapshot without an application server or database.

## Scope

- Public source labels are limited to CertStream, URLScan, and configured HECAVEX exports.
- Indicators are defanged before publication. Query strings, fragments, credentials, and sensitive-looking path data are excluded.
- CertStream matches are leads, not confirmation of phishing. The collector reads certificate names and never visits candidate hosts.
- URLScan hunting is passive: it searches existing public reports and never submits or opens a candidate URL. Missing, unlisted, or private scan visibility is rejected.
- Screenshots and evidence links are URLScan-only. Opening evidence may contact `urlscan.io`, but never the observed host.
- The public brand registry and matching rules are independent of HECAVEX's private collectors, detection logic, and history.

The dashboard provides search, filtering, pagination, first/last-seen timestamps, target brand, hosting metadata, confidence scores on a 0-100 scale, URLScan references and screenshots, and primary HTML SHA-256 evidence when available. A confidence score is a ranking aid, not a probability.

## Repository layout

| Path | Purpose |
| --- | --- |
| `hecavex_radar/` | Python collectors, matching, normalization, and snapshot publisher |
| `src/` | Static React dashboard |
| `data/brands-lt.json` | Reviewed Lithuanian brand and official-domain registry |
| `data/certstream/` | Date-partitioned, defanged CT candidates |
| `data/urlscan/` | Date-partitioned, automatically validated URLScan observations |
| `public/data/radar.json` | Checked-in dashboard snapshot |

## Local development

Requirements: Python 3.12 or newer, Node.js 22.12 or newer, and pnpm 10.

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

The URLScan hunter requires `URLSCAN_API_KEY` in the process environment. The CertStream collector uses a four-minute window by default and can use a monitored endpoint through `CERTSTREAM_URL`. Collector and publisher settings are listed in [`.env.example`](.env.example); the application reads environment variables directly and does not load that file automatically.

## Brand registry

[`data/brands-lt.json`](data/brands-lt.json) contains reviewed aliases, official domains, optional collision exclusions, and supporting links. It is intentionally limited to brands relevant to Lithuania. Additions and corrections should cite authoritative sources; complete official-domain coverage is important because official domains and their subdomains are suppressed before scoring.

Matching behavior is documented in [Detection rules](docs/DETECTION.md).

## Verification

```sh
pnpm check
```

This runs Python and frontend linting, type checks, tests, and the production build.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Public data contract](docs/DATA-CONTRACT.md)
- [Data sources](docs/DATA-SOURCES.md)
- [Deployment](docs/DEPLOYMENT.md)
- [Data licensing and attribution](DATA-LICENSE.md)
- [Third-party production notices](public/THIRD-PARTY-NOTICES.txt)
- [Security policy](SECURITY.md)

The software is licensed under the [Apache License 2.0](LICENSE). Third-party data and screenshots retain their own terms.
