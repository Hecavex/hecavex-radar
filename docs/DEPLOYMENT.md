# Deployment

HECAVEX Radar is a static GitHub Pages site. Scheduled workflows maintain the checked-in archives and public snapshot; deployment only builds those reviewed repository files.

## Pages

The repository's Pages source must be **GitHub Actions**. [`.github/workflows/deploy-pages.yml`](../.github/workflows/deploy-pages.yml) verifies the frontend, builds the dashboard, `/methodology/`, and `/docs/` into `dist/`, and deploys them after successful CI on `main`, after a successful snapshot sync, or by manual dispatch.

[`sync-radar.yml`](../.github/workflows/sync-radar.yml) validates the configured inputs each hour and commits a changed `public/data/radar.json`. Persisting the snapshot means retention and sharp-drop protection compare against the actual previous publication rather than an artifact-only copy. The Pages job has no collector credentials and never changes data.

The publisher compares new output with rows seen during the previous 30 days and refuses an unexpected sharp reduction. Older rows no longer block a legitimate empty snapshot. For a deliberate reset of recent data, manually dispatch **Sync radar snapshot** with **Allow this run to bypass the snapshot-size guard** enabled. The override applies only to that manual run.

## Automation

| Workflow | Schedule or trigger | Output | Required access |
| --- | --- | --- | --- |
| `ci.yml` | Pull requests and relevant pushes to `main` | Lint, type checks, tests, production build | Repository read |
| `collect-certstream.yml` | `2,32 * * * *` and manual dispatch | Atomic commit of `data/certstream/<date>/domains.ndjson` and bounded `public/data/collection-health.json` | Repository contents write |
| `hunt-urlscan.yml` | `37 3,15 * * *` and manual dispatch | `data/urlscan/<date>/signals.ndjson` | `URLSCAN_API_KEY`; repository contents write |
| `sync-radar.yml` | `17 * * * *` and manual dispatch | Persistent `public/data/radar.json` | Optional HECAVEX secrets; repository contents write |
| `deploy-pages.yml` | Successful CI on `main`, successful snapshot sync, and manual dispatch | GitHub Pages artifact | `pages: write` and `id-token: write` |

Cron schedules use UTC. Each CertStream run samples a four-minute window; it is not continuous collection. The two archive writers and snapshot writer share one concurrency group so their pull/rebase/push sequences cannot run at the same time. They commit changes directly to `main`, so repository rules must allow normal GitHub Actions bot pushes while still blocking force-pushes and branch deletion.

The CertStream job initializes health before installing collector dependencies, lets setup and collection failures reach a finalizer, and stages the daily candidate archive and health document in one commit. A failed or no-input attempt is therefore published before the job reports failure. Hard runner cancellation, platform outage before checkout, or a rejected push cannot be recorded by a workflow that no longer has execution or write access. The health document replaces one fixed path and is capped at 32 KiB; it does not create per-attempt files or expose raw candidates.

## Required configuration

Store credentials as repository secrets and feature switches as repository variables.

| Setting | Kind | Required when | Purpose |
| --- | --- | --- | --- |
| `URLSCAN_API_KEY` | Secret | URLScan workflow enabled | Authenticates passive URLScan search and result retrieval. Confirm that the account and plan permit the intended automated and public use. |
| `CERTSTREAM_URL` | Secret or variable | Optional | Uses an externally managed WSS endpoint instead of the workflow's temporary local CertStream server; the secret takes precedence. |
| `HECAVEX_ENABLED` | Variable | Optional | Set to `true` to include the configured HECAVEX export in snapshot synchronization. |
| `HECAVEX_FEED_URL` | Secret | `HECAVEX_ENABLED=true` | Production HTTPS endpoint implementing the [public data contract](DATA-CONTRACT.md). The HTTP loopback exception is for local development only. |
| `HECAVEX_FEED_TOKEN` | Secret | Optional with HECAVEX | Read-only bearer token for the HECAVEX endpoint. |
| `PHISHDESTROY_SEED_ENABLED`, `CERTPL_SEED_ENABLED` | Variables | Optional | Set either to `false` to disable that transient URLScan seed adapter. Seeds never publish directly or appear as source labels. |

Public screenshot URLs must be hosted on exactly `urlscan.io`, regardless of which source supplied the observation. Tuning limits, lookback windows, and other bounded defaults are documented in [`.env.example`](../.env.example) and the relevant [workflow files](../.github/workflows/).

Before enabling URLScan collection for a public or commercial deployment, review the current [URLScan Terms of Service](https://urlscan.io/terms/) and obtain any permission required for the intended display or redistribution of report metadata and screenshots. An API key proves authentication, not redistribution permission.

## Custom domain

[`public/CNAME`](../public/CNAME) declares `radar.hecavex.com`. The Pages custom domain must match it, with this DNS record:

```text
Type: CNAME
Name: radar
Target: hecavex.github.io
```

Verify `hecavex.com` in the owning GitHub account or organization and retain GitHub's `_github-pages-challenge-*` TXT record. This protects the custom domain if repository or Pages configuration changes. Enable HTTPS after GitHub completes its DNS and certificate checks.
