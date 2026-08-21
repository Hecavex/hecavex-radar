# HECAVEX Radar

HECAVEX Radar is a public, login-free dashboard for recently observed potential phishing URLs and domains. It combines approved feeds with an open Certificate Transparency heuristic, defangs every indicator, and exposes no private collector, proprietary detector, private history, or credential.

The intended public URL is **[radar.hecavex.com](https://radar.hecavex.com)**.

## Technology boundary

The complete data pipeline is Python 3.12: feed downloads, CertStream collection, Lithuanian-brand matching, normalization, daily archives, and snapshot publishing. The static dashboard remains React/TypeScript because GitHub Pages and a visitor's browser cannot execute Python. It only reads the JSON file produced by Python; there is no application server, login, or database.

## What it includes

- URL/domain, first and last seen, source, status, targeted brand, country/host, confidence, and approved screenshots when available.
- Full-text search, source/status/brand/country/confidence filters, and pagination.
- CertStream, PhishTank, opt-in OpenPhish and VMRay, plus a generic HECAVEX public-export adapter.
- A public Lithuanian brand/domain registry and explainable, independently written matching rules.
- Date-partitioned CertStream candidate archives such as `data/candidates/2026-08-21/domains.ndjson`.
- GitHub Pages deployment, a bounded GitHub collector, and a continuous Docker collector.
- A checked-in, defanged live snapshot generated from approved public sources; tests and fixtures continue to use reserved names.

Certificate issuance is only a lead. A CT match is labeled `suspected`; the collector never visits the hostname and does not know a full URL path, page contents, or whether the host is malicious.

## Safety boundary

The browser never requests an observed URL. The Python publisher converts `http(s)` to `hxxp(s)`, converts hostname dots to `[.]`, drops query strings and fragments, redacts nested URLs and sensitive-looking path segments, rejects unsafe schemes and user credentials, and caps the current snapshot. Screenshot URLs must use explicitly allowed HTTPS hosts.

The open heuristic in [`hecavex_radar/brands.py`](hecavex_radar/brands.py) is separate from the private project. This repository must not receive internal collectors, proprietary detection logic, private HECAVEX history, API keys, or deployment credentials.

## Local setup

Requirements: Python 3.12+, Node.js 22.12+, and pnpm 10. Python owns the pipeline; Node is only needed to develop or build the browser dashboard.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
corepack enable
pnpm install
pnpm dev
```

Open `http://localhost:5173` to see the current checked-in snapshot.

## Collect and publish locally

The easiest continuous setup is the self-contained Docker composition:

```powershell
docker compose -f compose.collector.yml up --build -d
docker compose -f compose.collector.yml logs -f
```

Compose starts the pinned `certstream-server-rust` 1.5.3 image and the Python collector, so it does not depend on a community public websocket. Its CT cursor is persisted under `./data/certstream-state` (git-ignored), while `./data/candidates` keeps the public archives.

If you already operate a monitored WSS endpoint, run the Python collector directly. It runs continuously by default and stops with `Ctrl+C`:

```powershell
$env:CERTSTREAM_URL = "wss://your-certstream.example/domains-only"
$env:CERTSTREAM_DURATION_SECONDS = "0"
python -m hecavex_radar.collect_certstream
```

For a short check, set `CERTSTREAM_DURATION_SECONDS` to `60`. A new Europe/Vilnius calendar day automatically creates a new folder. The same domain is written at most once per day.

In another terminal, build the current dashboard snapshot from configured feeds and recent archive days, then start Vite:

```powershell
$env:PHISHTANK_ENABLED = "true"
python -m hecavex_radar.sync
pnpm dev
```

Anonymous PhishTank access is suitable only for occasional local checks. Scheduled deployments require `PHISHTANK_APP_KEY`. VMRay and OpenPhish remain off until you explicitly accept their current terms in the environment; see [data sources](docs/DATA-SOURCES.md). Run the sync command whenever you want to refresh `public/data/radar.json`.

The publisher refuses an empty or sharply reduced update so a temporary source failure cannot replace the last good dashboard. Set `RADAR_ALLOW_SMALL_SNAPSHOT=true` only when intentionally resetting the dataset.

## Brand registry

[`data/brands-lt.json`](data/brands-lt.json) is a reviewed seed list, not a claim of completeness. Each entry has aliases, known official domains, and source links. Add missing official domains through a pull request: exact official domains and all their subdomains are suppressed before similarity scoring, so maintaining this list directly reduces false positives.

## Verification

With the virtual environment active:

```powershell
pnpm check
```

This runs Ruff, strict mypy and TypeScript checks, Python and component tests, and a production build. Third-party terms, [data licensing](DATA-LICENSE.md), and [deployment settings](docs/DEPLOYMENT.md) are documented separately.

Copyright (c) 2026 HECAVEX. Licensed under the [Apache License 2.0](LICENSE).
