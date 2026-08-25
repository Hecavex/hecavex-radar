# Deployment

This is the HECAVEX maintainer runbook for the production service at [radar.hecavex.com](https://radar.hecavex.com), not a general self-hosting guide. The service is published through GitHub Pages. Scheduled workflows maintain the checked-in archives and public snapshot; deployment builds only those reviewed repository files.

## Pages

The repository's Pages source must be **GitHub Actions**. [`.github/workflows/deploy-pages.yml`](../.github/workflows/deploy-pages.yml) verifies the frontend, builds the dashboard, `/history/`, `/methodology/`, and `/docs/` into `dist/`, and deploys after successful CI for a code commit, after a successful snapshot sync that changed live/history/detail data, or after a finalized CertStream run committed changed public collection health. A collector workflow may report failure after committing its bounded failure record; that trusted data-only completion is still eligible to publish the health change. These paths use GitHub's `workflow_run` event because publisher commits made with the workflow token do not recursively trigger push workflows. Every path runs the same frontend checks before deployment. A changed-path gate rejects any current `main` revision containing code or configuration not validated by the triggering run. No-change data runs do not deploy redundant content, and URLScan archive-only commits wait for the next snapshot sync.

[`sync-radar.yml`](../.github/workflows/sync-radar.yml) validates the configured inputs each hour. Every successful run advances `lastSuccessfulSyncAt` in the live snapshot, even when the observations are unchanged; `generatedAt` advances only for a material data or source-state change. Changed history projections, partitions, and bounded per-signal sidecars are committed in the same transaction. Persisting `public/data/radar.json`, `public/data/history.json`, `public/data/signals/`, and `data/history/` together keeps the current view, optional detail declarations, and reproducible observation trail aligned. Live-snapshot retention and sharp-drop protection compare against the actual previous publication rather than an artifact-only copy. The Pages job has no collector credentials and never changes data.

The publisher compares new output with rows seen during the previous 30 days and refuses an unexpected sharp reduction. Older rows no longer block a legitimate empty snapshot. For a deliberate reset of recent data, manually dispatch **Sync radar snapshot** with **Allow this run to bypass the snapshot-size guard** enabled. The override applies only to that manual run.

## Automation

| Workflow | Schedule or trigger | Output | Required access |
| --- | --- | --- | --- |
| `ci.yml` | Pull requests and relevant pushes to `main` | Lint, type checks, production build, and static-site verification | Repository read |
| `collect-certstream.yml` | `8,23,38,53 * * * *` and manual dispatch | Atomic commit of `data/certstream/<date>/domains.ndjson` and bounded `public/data/collection-health.json` | Repository contents write |
| `hunt-urlscan.yml` | `37 */2 * * *` and manual dispatch | Bounded `data/urlscan/hunt-state.json` and validated `data/urlscan/<date>/signals.ndjson` | Optional `URLSCAN_API_KEY`; repository contents write |
| `hunt-brand-assets.yml` | `47 3,15 * * *` and manual dispatch | Credential-free official favicon/JavaScript hash state and independently qualified URLScan observations | Optional `URLSCAN_API_KEY`; repository contents write |
| `sync-radar.yml` | `17 * * * *` and manual dispatch | Persistent live snapshot, per-signal sidecars, candidate history, and compacted history summary | Optional HECAVEX secrets; repository contents write |
| `deploy-pages.yml` | Successful code CI, material snapshot sync, or changed CertStream health publication | Verified GitHub Pages artifact | `pages: write` and `id-token: write` |

Cron schedules use UTC. Each CertStream run samples an eight-minute window at 08, 23, 38, and 53 minutes past the hour; even if all 96 daily runs start and complete, this is at most 768 minutes, or 53.3% of a day, not continuous collection. CertStream runs use their own serialized concurrency group so two live listeners cannot overlap. The URLScan archive writer and snapshot writer retain the shared archive-writer group. Scheduled and manual writer runs are pinned to `main`. Because CertStream can finish beside another writer, every writer uses a bounded pull/rebase/push retry; an exhausted retry remains a failed observable workflow rather than silently discarding the runner's result. Repository rules must allow normal GitHub Actions bot pushes while still blocking force-pushes and branch deletion.

Python 3.12 automation installs reviewed, SHA-256-locked dependency sets from [`requirements/`](../requirements/). Scheduled writers use the minimal runtime lock; CI uses the development-tool superset. The checked-out package is then installed without resolving additional dependencies or creating an unconstrained build environment.

Frontend verification also enforces deterministic first-party gzip and total-output budgets documented in [`PERFORMANCE.md`](PERFORMANCE.md). The check uses built files only and has no network-performance dependency.

The CertStream job initializes health before installing collector dependencies, lets setup and collection failures reach a finalizer, and stages the daily archive and health document in one commit. A failed or no-input attempt is therefore published before the job reports failure. Every successful window appends one bounded aggregate row to its Vilnius-day `attempts.ndjson`; zero matches still produce that dated partition, while `domains.ndjson` appears only when candidates exist. A changed public health document triggers a verified Pages deployment so the four-per-hour measurement is not held until the hourly snapshot build. Hard runner cancellation, platform outage before checkout, or an exhausted push retry cannot be recorded by a workflow that no longer has execution or write access. The latest-health document replaces one fixed path and is capped at 32 KiB; daily attempt rows contain no raw certificate names or candidates.

The URLScan job treats the hunter and state publication as separate steps. The commit step always stages `data/urlscan/`, including state written before a hunter failure, and a final step then propagates a hunt or publication failure to the workflow result. An absent secret is not a failure: the hunter performs no request, records `configured: false` and `skipped-not-configured` with the current attempt time, and exits successfully. A later identical skip therefore refreshes the credential-free state timestamp and can create a state-only commit. Runner cancellation, an outage before checkout, or a rejected push has the same unavoidable observability limit described above.

## Required configuration

Store credentials as repository secrets and feature switches as repository variables.

| Setting | Kind | Required when | Purpose |
| --- | --- | --- | --- |
| `HECAVEX_ANALYTICS_TOKEN` | Variable | Production Pages deployment | Public Cloudflare Web Analytics site token injected once per HTML page. An empty local or CI build omits the DNT-aware loader; the production deployment gate rejects an empty token or missing beacon. |
| `URLSCAN_API_KEY` | Secret | Optional | Authenticates passive URLScan search and result retrieval. Without it, the job makes no API request, records an explicit successful skip in `hunt-state.json`, and continues. Confirm that the account and plan permit the intended automated and public use. |
| `URLSCAN_RADAR_SEEDS_ENABLED`, `URLSCAN_RADAR_SNAPSHOT`, `URLSCAN_RADAR_SEED_LIMIT` | Variables | Optional | Include at most 250 current Radar rows observed in the rolling previous seven days as bounded exact-search seeds; enabled by default with `public/data/radar.json`. |
| `URLSCAN_SEED_ROTATION_SHARDS`, `URLSCAN_SEEDS_PER_RUN` | Variables | Optional | Attempt the complete bounded seed set in one slice, selecting at most 250 seeds per run by default. Operators can lower these values; the cursor then preserves progress. |
| `URLSCAN_DAILY_SEARCH_CAP`, `URLSCAN_DAILY_RESULT_CAP` | Variables | Optional | Conservative UTC-day request guards: 900 successful searches and 8,000 successful result retrievals by default. |
| `URLSCAN_RUN_SEARCH_CAP`, `URLSCAN_RUN_RESULT_CAP` | Variables | Optional | Conservative per-run guards: 25 successful searches and 100 successful result retrievals by default. |
| `URLSCAN_ASSET_*` | Variables | Optional | Bounds the twice-daily official-domain rotation, 30-day public-report lookback, retained favicon/JavaScript hash pivots, and separate 80-search/400-result UTC-day ledger. Defaults are listed in `.env.example`. |
| `CERTSTREAM_URL` | Secret or variable | Optional | Uses an externally managed WSS endpoint instead of the workflow's temporary local CertStream server; the secret takes precedence. |
| `HECAVEX_ENABLED` | Variable | Optional | Set to `true` to include the configured HECAVEX export in snapshot synchronization. |
| `HECAVEX_FEED_URL` | Secret | `HECAVEX_ENABLED=true` | Production HTTPS endpoint implementing the [public data contract](DATA-CONTRACT.md). The HTTP loopback exception exists only for local maintainer validation. |
| `HECAVEX_FEED_TOKEN` | Secret | Optional with HECAVEX | Read-only bearer token for the HECAVEX endpoint. |
| `PHISHDESTROY_SEED_ENABLED`, `CERTPL_SEED_ENABLED` | Variables | Optional | Set either to `false` to disable that transient URLScan seed adapter. Seeds never publish directly or appear as source labels. |
| `RADAR_HISTORY_DETAIL_DAYS` | Variable | Optional | Detailed daily history retention, 30 days by default and bounded from 7 to 90. |
| `RADAR_HISTORY_SUMMARY_DAYS` | Variable | Optional | Compacted history retention, 730 days by default and bounded from 30 to 3,650. |
| `RADAR_HISTORY_MAX_SIGNALS` | Variable | Optional | Public history row cap, 5,000 by default and bounded from 1 to 25,000. |

The private false-positive review ledger is not a deployment input and must remain outside the repository. An operator may deliberately export its sanitized active decisions to `data/review/public-decisions.json`; synchronization rejects malformed, oversized, future-dated, duplicate, or cross-brand decisions. See [`REVIEW-WORKFLOW.md`](REVIEW-WORKFLOW.md).

Public screenshot URLs must be hosted on exactly `urlscan.io`, regardless of which source supplied the observation. Tuning limits, lookback windows, and other bounded defaults are documented in [`.env.example`](../.env.example) and the relevant [workflow files](../.github/workflows/).

The URLScan guards remain below the provider's published fixed-window quotas. The checked-in counters measure only successful responses observed by the hunter and are not a substitute for URLScan account usage. HTTP 429 stops further requests safely. Search queries are limited to the rolling previous seven days; each two-hour run attempts all currently bounded candidates, with cursor resumption if a lowered cap or budget interrupts the set. Radar calls only the public search and result endpoints, never scan submission or a candidate site.

Scheduled and manual URLScan dispatches share the same persisted UTC-day counters. A default scheduled run can issue at most 25 searches and 100 result retrievals, below the provider's 120-per-minute limits; the twelve scheduled runs total at most 300 and 1,200 respectively before lower practical query counts, below both the local daily guards and provider daily quotas. The two-hour schedule places no more than one scheduled run in an hour. Manual dispatches are serialized by the archive-writer concurrency group and consume the same daily budget; operators must not use manual dispatch as a way to burst provider windows.

Before HECAVEX enables or changes URLScan collection on the live service, operators must review the current [URLScan Terms of Service](https://urlscan.io/terms/) and obtain any permission required for the intended display or redistribution of report metadata and screenshots. An API key proves authentication, not redistribution permission.

## Custom domain

[`public/CNAME`](../public/CNAME) declares `radar.hecavex.com`. The Pages custom domain must match it, with this DNS record:

```text
Type: CNAME
Name: radar
Target: hecavex.github.io
```

Verify `hecavex.com` in the owning GitHub account or organization and retain GitHub's `_github-pages-challenge-*` TXT record. This protects the custom domain if repository or Pages configuration changes. Enable HTTPS after GitHub completes its DNS and certificate checks.
