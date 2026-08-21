# Deploying `radar.hecavex.com`

The repository contains three workflows: CI, a bounded CertStream collector, and an hourly snapshot/Pages deployment.

## 1. Create the public repository

Create a public GitHub repository named `hecavex-radar`, add it as this folder's `origin`, and push `main`. In **Settings → Pages**, select **GitHub Actions** as the source.

Before pointing DNS, verify `hecavex.com` under the owning GitHub account or organization in **Settings → Pages** and keep GitHub's `_github-pages-challenge-*` TXT record in DNS. After the first successful Pages deployment, set the repository's custom domain to `radar.hecavex.com`. A `CNAME` file inside an artifact does not replace this account/repository configuration when deploying with GitHub Actions.

The CertStream workflow needs **Settings → Actions → General → Workflow permissions → Read and write permissions** because it commits daily archive updates. If `main` protection blocks the Actions bot, allow that bot to bypass only for this data workflow or run the continuous collector and push archives through your normal review path.

## 2. Configure repository variables

| Variable | Suggested value | Purpose |
| --- | --- | --- |
| `RADAR_SYNC_ENABLED` | `true` | Rebuild the snapshot during the hourly deployment. |
| `CERTSTREAM_URL` | empty | Optional monitored WSS override. Empty starts the pinned CT server inside each runner. |
| `CERTSTREAM_MIN_CONFIDENCE` | `65` | Public heuristic threshold, bounded to 1–100. |
| `RADAR_CT_LOOKBACK_DAYS` | `7` | Daily archives included in the current dashboard. |
| `VMRAY_ENABLED` | `false` | Enable only after terms review. |
| `VMRAY_ACCEPT_TERMS` | `false` | Explicit deployer acknowledgement. |
| `VMRAY_PAGES` | `1` | Public pages to parse, bounded to 1–5. |
| `OPENPHISH_ENABLED` | `false` | Enable only after terms review. |
| `OPENPHISH_ACCEPT_TERMS` | `false` | Explicit deployer acknowledgement. |
| `PHISHTANK_USER_AGENT` | `hecavex-radar/<GitHub account>` | Identifies automated downloads. |
| `PHISHTANK_ENABLED` | `true` | Enables PhishTank; scheduled automation also requires its application-key secret. |
| `RADAR_MAX_SIGNALS` | `2500` | Current snapshot cap. |
| `RADAR_MIN_SIGNALS` | `100` | Reject a suspiciously empty publication. |
| `RADAR_MIN_RETAINED_PERCENT` | `25` | Reject a result smaller than this percentage of the last live snapshot. |
| `RADAR_SCREENSHOT_HOSTS` | `urlscan.io` | Approved HTTPS screenshot hosts. |

Add credentials only as repository secrets:

| Secret | Purpose |
| --- | --- |
| `PHISHTANK_APP_KEY` | Required for the hourly automated PhishTank download. |
| `CERTSTREAM_URL` | Optional private/tokenized WSS endpoint; overrides the same-named variable. |
| `HECAVEX_FEED_URL` | Dedicated HTTPS public-export endpoint. |
| `HECAVEX_FEED_TOKEN` | Optional read-only bearer token. |

Set `PHISHTANK_APP_KEY` before enabling hourly synchronization. Run **Collect CertStream candidates** manually first. With no URL override, it starts the pinned open-source CT server inside the runner. It then listens for four minutes, requires at least one stream message, writes `data/candidates/<Vilnius date>/domains.ndjson`, and commits only when it found new candidates. It runs every five minutes. A silent endpoint deliberately fails the job instead of pretending collection succeeded.

GitHub explicitly treats scheduled starts as best effort: high load can delay or drop runs, and five minutes is the shortest interval. The per-run CT server starts near the current log tail, so this remains sampling rather than guaranteed coverage. Use the persistent Docker service for uninterrupted collection:

```powershell
docker compose -f compose.collector.yml up --build -d
```

Do not run GitHub and Docker writers against the same checkout simultaneously.

## 3. Configure DNS

The repository contains `public/CNAME` as deployment metadata, but the custom domain must still be set in GitHub Pages. At Hostinger, keep exactly one non-proxied record for this host and remove any conflicting `A` or `AAAA` record:

```text
Type: CNAME
Name: radar
Target: hecavex.github.io
TTL: 300 (or Hostinger's default)
```

Wait for GitHub's DNS check and TLS certificate provisioning, then enable **Enforce HTTPS**. If Cloudflare proxies the record, start with DNS-only mode until GitHub finishes domain and certificate verification.

## 4. Operational boundaries

- Review candidate archives before treating any record as confirmed phishing.
- Maintain all known official brand domains in `data/brands-lt.json` to reduce false positives.
- Restrict who can update Actions secrets, workflow files, and `main`.
- Never print indicators or secrets in CI logs; the included scripts log counts only.
- Keep HECAVEX credentials read-only and scoped to the public export.
- Review third-party data terms and screenshot providers periodically.

The viewer itself has no sessions, accounts, forms, write endpoints, database, or server runtime.
