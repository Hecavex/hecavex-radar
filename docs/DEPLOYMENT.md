# Deployment

This is the HECAVEX maintainer runbook for the production service at [radar.hecavex.com](https://radar.hecavex.com), not a general self-hosting guide. The service is published through GitHub Pages. Scheduled workflows maintain the checked-in archives and public snapshot; deployment builds only those reviewed repository files.

## Pages

The repository's Pages source must be **GitHub Actions**. [`.github/workflows/deploy-pages.yml`](../.github/workflows/deploy-pages.yml) verifies the frontend, builds the dashboard, `/history/`, `/methodology/`, and `/docs/` into `dist/`, and deploys only after successful CI for the current `main` commit. This single CI gate covers source changes, collection-health publications, and changed public datasets; superseded CI completions do not deploy stale content. URLScan archive-only commits wait for the hourly snapshot sync instead of deploying an unchanged dashboard.

[`sync-radar.yml`](../.github/workflows/sync-radar.yml) validates the configured inputs each hour and commits the live snapshot, retained public history, and history partitions together when they change. Persisting `public/data/radar.json`, `public/data/history.json`, and `data/history/` in one commit keeps the current view and reproducible observation trail aligned. Live-snapshot retention and sharp-drop protection compare against the actual previous publication rather than an artifact-only copy. The Pages job has no collector credentials and never changes data.

The publisher compares new output with rows seen during the previous 30 days and refuses an unexpected sharp reduction. Older rows no longer block a legitimate empty snapshot. For a deliberate reset of recent data, manually dispatch **Sync radar snapshot** with **Allow this run to bypass the snapshot-size guard** enabled. The override applies only to that manual run.

## Automation

| Workflow | Schedule or trigger | Output | Required access |
| --- | --- | --- | --- |
| `ci.yml` | Pull requests and relevant pushes to `main` | Lint, type checks, tests, production build | Repository read |
| `collect-certstream.yml` | `2,32 * * * *` and manual dispatch | Atomic commit of `data/certstream/<date>/domains.ndjson` and bounded `public/data/collection-health.json` | Repository contents write |
| `hunt-urlscan.yml` | `37 3,15 * * *` and manual dispatch | `data/urlscan/<date>/signals.ndjson` | Optional `URLSCAN_API_KEY`; repository contents write |
| `sync-radar.yml` | `17 * * * *` and manual dispatch | Persistent live snapshot, candidate history, and compacted history summary | Optional HECAVEX secrets; repository contents write |
| `deploy-pages.yml` | Successful CI for the current `main` commit | GitHub Pages artifact | `pages: write` and `id-token: write` |

Cron schedules use UTC. Each CertStream run samples a four-minute window; it is not continuous collection. The two archive writers and snapshot writer share one concurrency group so their pull/rebase/push sequences cannot run at the same time. They commit changes directly to `main`, so repository rules must allow normal GitHub Actions bot pushes while still blocking force-pushes and branch deletion.

Python 3.12 automation installs reviewed, SHA-256-locked dependency sets from [`requirements/`](../requirements/). Scheduled writers use the minimal runtime lock; CI uses the development-tool superset. The checked-out package is then installed without resolving additional dependencies or creating an unconstrained build environment.

Frontend verification also enforces deterministic first-party gzip and total-output budgets documented in [`PERFORMANCE.md`](PERFORMANCE.md). The check uses built files only and has no network-performance dependency.

The CertStream job initializes health before installing collector dependencies, lets setup and collection failures reach a finalizer, and stages the daily archive and health document in one commit. A failed or no-input attempt is therefore published before the job reports failure. Every successful window appends one bounded aggregate row to its Vilnius-day `attempts.ndjson`; zero matches still produce that dated partition, while `domains.ndjson` appears only when candidates exist. Hard runner cancellation, platform outage before checkout, or a rejected push cannot be recorded by a workflow that no longer has execution or write access. The latest-health document replaces one fixed path and is capped at 32 KiB; daily attempt rows contain no raw certificate names or candidates.

## Required configuration

Store credentials as repository secrets and feature switches as repository variables.

| Setting | Kind | Required when | Purpose |
| --- | --- | --- | --- |
| `URLSCAN_API_KEY` | Secret | Optional | Authenticates passive URLScan search and result retrieval. Without it, the URLScan job exits successfully without network access or archive changes; CertStream publication and synchronization continue. Confirm that the account and plan permit the intended automated and public use. |
| `CERTSTREAM_URL` | Secret or variable | Optional | Uses an externally managed WSS endpoint instead of the workflow's temporary local CertStream server; the secret takes precedence. |
| `HECAVEX_ENABLED` | Variable | Optional | Set to `true` to include the configured HECAVEX export in snapshot synchronization. |
| `HECAVEX_FEED_URL` | Secret | `HECAVEX_ENABLED=true` | Production HTTPS endpoint implementing the [public data contract](DATA-CONTRACT.md). The HTTP loopback exception exists only for maintainer tests. |
| `HECAVEX_FEED_TOKEN` | Secret | Optional with HECAVEX | Read-only bearer token for the HECAVEX endpoint. |
| `PHISHDESTROY_SEED_ENABLED`, `CERTPL_SEED_ENABLED` | Variables | Optional | Set either to `false` to disable that transient URLScan seed adapter. Seeds never publish directly or appear as source labels. |
| `RADAR_HISTORY_DETAIL_DAYS` | Variable | Optional | Detailed daily history retention, 30 days by default and bounded from 7 to 90. |
| `RADAR_HISTORY_SUMMARY_DAYS` | Variable | Optional | Compacted history retention, 730 days by default and bounded from 30 to 3,650. |
| `RADAR_HISTORY_MAX_SIGNALS` | Variable | Optional | Public history row cap, 5,000 by default and bounded from 1 to 25,000. |

The private false-positive review ledger is not a deployment input and must remain outside the repository. An operator may deliberately export its sanitized active decisions to `data/review/public-decisions.json`; synchronization rejects malformed, oversized, future-dated, duplicate, or cross-brand decisions. See [`REVIEW-WORKFLOW.md`](REVIEW-WORKFLOW.md).

Public screenshot URLs must be hosted on exactly `urlscan.io`, regardless of which source supplied the observation. Tuning limits, lookback windows, and other bounded defaults are documented in [`.env.example`](../.env.example) and the relevant [workflow files](../.github/workflows/).

Before HECAVEX enables or changes URLScan collection on the live service, operators must review the current [URLScan Terms of Service](https://urlscan.io/terms/) and obtain any permission required for the intended display or redistribution of report metadata and screenshots. An API key proves authentication, not redistribution permission.

## Custom domain

[`public/CNAME`](../public/CNAME) declares `radar.hecavex.com`. The Pages custom domain must match it, with this DNS record:

```text
Type: CNAME
Name: radar
Target: hecavex.github.io
```

Verify `hecavex.com` in the owning GitHub account or organization and retain GitHub's `_github-pages-challenge-*` TXT record. This protects the custom domain if repository or Pages configuration changes. Enable HTTPS after GitHub completes its DNS and certificate checks.
