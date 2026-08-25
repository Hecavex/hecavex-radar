# HECAVEX Radar

This repository is the operational source and public change record for [radar.hecavex.com](https://radar.hecavex.com), a HECAVEX-operated, read-only research service for recently observed potential phishing domains and URLs targeting Lithuanian brands.

It is not presented as a starter site, downloadable product, self-hosting package, or general-purpose phishing platform. The public source supports transparency, reproducible data handling, and review of the live service. The production service, its schedules, source access, review decisions, domain, and publication process are maintained by HECAVEX.

## Live service

- [Radar dashboard](https://radar.hecavex.com/) — current validated candidate observations
- [Candidate history](https://radar.hecavex.com/history/) — bounded observation provenance and explicit source transitions
- [Methodology](https://radar.hecavex.com/methodology/) — collection, matching, publication, and limitation disclosures
- [Technical reference](https://radar.hecavex.com/docs/) — schemas, operations, security boundaries, and data terms

Radar combines sampled live Certificate Transparency observations, bounded checkpointed searches of the public `crt.sh` index, passive searches of existing public URLScan reports, and an optional deliberately limited HECAVEX public export. For already published candidates it can add point-in-time DNS-over-HTTPS and RDAP context without requesting the candidate webpage. The Python pipeline validates every accepted record and defangs the dashboard and history artifacts. One STIX 2.1 projection carries observations; a second carries only explicitly reviewed, time-bounded Indicators. The React interface renders the static artifacts without an application server, account system, public write path, or database connection.

## Publication and safety boundaries

- Public source labels are limited to CertStream, URLScan, and HECAVEX. The HECAVEX label represents either a configured sanitized service export or an explicitly accepted sanitized local review candidate; `discoveredVia` distinguishes those paths.
- Dashboard and history indicators are defanged before publication. Credentials, query strings, fragments, and sensitive-looking path data are excluded.
- The observation-only STIX 2.1 distribution is the deliberate exception to display defanging: it contains raw domain-name observables only, with no URL paths or TLP marking. The separate reviewed Indicator distribution applies the standard TLP:CLEAR marking to deliberately exported confirmations. That marking does not relicense source evidence. Treat values in either feed as untrusted data and do not browse, resolve, scan, or block them without independent review.
- CertStream matches are research leads, not confirmation of phishing. Qualifying records are published as `suspected`; the collector reads certificate names and never visits candidate hosts.
- The hourly `crt.sh` poller replays a bounded set of reviewed brand-keyword searches from persisted per-query cursors. It improves recovery within those declared queries but is not complete CT-log collection and does not support a global coverage claim.
- URLScan is optional passive corroboration. Radar searches existing public reports and never submits or opens a candidate URL. Missing or non-public scan visibility does not suppress an independently qualifying CertStream record.
- DNS and RDAP enrichment runs only for current published candidates. It stores defanged DNS answers and limited registrar, lifecycle, and status fields; it does not retrieve a candidate page or retain registrant contact data. Missing context is unknown, not benign.
- Screenshots and evidence links are URLScan-only. Opening evidence may contact `urlscan.io`, never the observed host.
- The public registry and matcher are separate from HECAVEX private collectors, proprietary detection logic, and internal case history.
- `matchScore` is a ranking aid, not a probability, verdict, analyst confidence, or actor attribution. `confidence` remains only as a deprecated equal alias during consumer migration.
- Radar is best-effort public research. It provides no monitoring, notification, response, takedown, coverage, availability, or service-level guarantee.

## Operating model

The service is published through reviewed GitHub Actions workflows. Cron schedules are UTC and may start late.

| Operation | Schedule or trigger | Service artifact |
| --- | --- | --- |
| CertStream sample | `8,23,38,53 * * * *` | Defanged candidate archive and latest bounded collection-health record |
| CT keyword search | `43 * * * *` | Per-brand query checkpoints and qualifying rows in the shared CT candidate archive |
| URLScan hunt | `37 */2 * * *` | Bounded hunt-state ledger and validated daily archive when the optional source is configured |
| Official asset pivot | `47 3,15 * * *` | Stable first-party favicon/JavaScript hashes and independently qualified public URLScan observations |
| DNS and RDAP context | `13 1,7,13,19 * * *` | Rotating, 14-day point-in-time context for published candidates |
| Snapshot synchronization | `17 * * * *` | Live snapshot, observation and reviewed STIX 2.1 projections, retained history, and compacted history summary |
| Site deployment | Successful code CI, material snapshot sync, or changed CertStream health | Static production pages for `radar.hecavex.com` |

The scheduled CertStream listener runs for eight minutes four times per hour: at most 768 minutes, or 53.3% of a day, if every run starts and completes. It is sampled live coverage, not a continuous listener, daily replay, or durable CT source. GitHub Actions can start late, drop a scheduled event, or fail, so actual listening time can be substantially lower. The dashboard publishes the latest attempt's actual timing, aggregate counts, outcome, schedule delay, last success, and freshness without retaining raw certificate names.

The separate hourly `crt.sh` job rotates through six reviewed brand queries by default, processes at most 500 result rows per query, and bootstraps no more than seven days of indexed results. Each query keeps a numeric result-ID checkpoint but also replays up to 50 prior rows inside a 1,000-ID overlap so a modest late-indexing reorder is not silently skipped. A query with more new rows than the current cap is marked partial and resumed before normal rotation continues. Accepted matches use the same matcher and date-partitioned CT archive as the live listener; both discovery methods can be retained for one domain on the same day. These safeguards do not prove that `crt.sh` indexed every certificate, that every Lithuanian brand name is queryable, or that Radar covered every public CT log. [ADR 0001](docs/decisions/0001-ct-coverage.md) distinguishes this useful indexed replay from complete log-index coverage.

Four times per day, a credential-free context job rotates through up to 20 current published candidates. It asks Cloudflare's DNS-over-HTTPS endpoint for A, AAAA, CNAME, NS, and MX answers and discovers the relevant RDAP service from IANA's bootstrap registry. RDAP is queried at the registrable parent and the defanged queried scope is retained so subdomain context is not mistaken for a separate registration. Records older than 14 days or no longer present in the current snapshot are removed. Only defanged answers, minimum observed TTL, registrar, registration/update/expiry times, and status codes can reach the optional signal-detail sidecar and aggregate health. This context can support bounded related-observation edges, but neither shared infrastructure nor registration metadata attributes an operator or proves maliciousness.

The URLScan workflow runs at minute 37 every two hours. Each run attempts exact passive lookups for the complete bounded set of at most 250 candidates observed during the rolling previous seven days, subject to conservative request budgets. A deterministic cursor preserves progress only when an operator lowers the per-run selection or a request budget interrupts the set. The hunter performs only searches of existing public reports and retrieval of public result documents: it does not submit scans or visit candidate hosts. A missing `URLSCAN_API_KEY` is a successful, explicit skip with no API request. The checked-in hunt-state ledger records configuration, UTC budget counters, cursor progress, and the latest outcome, but no credential or candidate domain.

At 03:47 and 15:47 UTC, a second passive URLScan job rotates through each brand's reviewed main website. It retains bounded first-party favicon and JavaScript SHA-256 hashes only after support from two distinct public scans, rejects hashes known to be shared by multiple registry brands within the retained collision ledger, and uses them only to discover public reports. A matching candidate still needs independent same-brand domain or provider-verdict evidence before it can enter the URLScan archive; title evidence also requires a URLScan phishing verdict. No official page, asset, or candidate is fetched directly.

The hunt-state file is workflow evidence, not bootstrap configuration: its first checked-in value and later transitions must come from a scheduled or manually dispatched GitHub Actions run, never from locally generated placeholder output. Snapshot synchronization maps an unconfigured hunt to a public `skipped` source state while retaining previously validated URLScan observations; it does not recast absence of enrichment as benign evidence.

## Public service artifacts

| Path | Role in `radar.hecavex.com` |
| --- | --- |
| `public/data/radar.json` | Current checked and bounded dashboard snapshot |
| `public/data/radar.stix.json` | Current observation-only STIX 2.1 Bundle; raw domain-name observables, not a verdict or TAXII endpoint |
| `public/data/radar-reviewed.stix.json` | Analyst-reviewed STIX 2.1 Indicators with explicit expiry and revocation semantics; not an automated blocklist |
| `public/data/radar.index.json` and `radar-shards/` | Complete accepted newest-first signal set in independently hashed 256 KiB shards |
| `public/data/history.json` | Bounded public candidate-history projection |
| `public/data/collection-health.json` | Latest bounded CertStream attempt health; no raw candidates |
| `public/data/pipeline-health.json` | Sanitized 24-hour and seven-day collection, screening, enrichment, and publication aggregates |
| `public/data/changes.json` | Aggregate first-publication, reobservation, and status-change view |
| `public/data/related-observations.json` | Typed shared-evidence associations with explicit non-attribution semantics |
| `public/data/feed-manifest.json` and `*.sha256` | Generator revision, copied source `fetchedAt` timestamps, counts, artifact lengths, and release-integrity digests for the atomic hourly release |
| `public/data/schemas/` | Versioned Draft 2020-12 schemas used by the publisher and CI |
| `public/data/signals/` | Lazy, per-signal CertStream/URLScan evidence and optional DNS/RDAP context; 16 KiB each and 3 MiB in aggregate |
| `data/brands-lt.json` | Reviewed Lithuanian brand and official-domain registry |
| `data/certstream/` | Date-partitioned successful sample metadata and defanged CT candidates |
| `data/ct-search/` | Bounded `crt.sh` provider state, rotating query cursor, and per-brand result checkpoints; no unpublished domain names |
| `data/enrichment/` | Rotating, credential-free DNS/RDAP context for current published candidates; 14-day default retention |
| `data/urlscan/` | Date-partitioned validated URLScan observations, bounded detail context, and credential-free hunt and official-asset state |
| `data/history/` | Deterministic daily events and compacted history summary |
| `data/review/public-decisions.json` | Explicitly exported, sanitized review decisions only |

Public snapshots and their schemas are documented in the [data contract](docs/DATA-CONTRACT.md). Third-party observations and screenshots remain subject to their source terms; see [data licensing and attribution](DATA-LICENSE.md).

The four-per-hour `collection-health.json` document is intentionally outside the hourly release manifest and checksum set because it is replaced and deployed by the independent CertStream workflow. Its synchronized, bounded aggregate appears in `pipeline-health.json`. This prevents a newer health measurement from making an otherwise atomic hourly manifest stale.

## HECAVEX maintenance

Repository changes are evaluated against the live service's safety, provenance, accessibility, and publication guarantees. Collector credentials remain in GitHub Actions secrets. Private false-positive notes and analyst identity remain outside Git; only an intentional sanitized export can enter the public pipeline.

The optional private pivot handoff is local-only. `hecavex-handoff` exports current passive CertStream/URLScan-backed rows to the git-ignored `data/hecavex/` boundary without making a network request. Analysts can review that file, record an accepted candidate with `hecavex-review add`, and intentionally export only sanitized decisions. See the [private review workflow](docs/REVIEW-WORKFLOW.md).

Brand additions and corrections belong in [`data/brands-lt.json`](data/brands-lt.json) and must cite authoritative sources. Complete official-domain coverage is important because official domains and their subdomains are suppressed before scoring. Matching and correction rules are documented in [Detection and brand matching](docs/DETECTION.md) and the [Private review workflow](docs/REVIEW-WORKFLOW.md).

The main implementation areas are:

| Path | Maintained responsibility |
| --- | --- |
| `hecavex_radar/` | Collectors, matching, normalization, review boundary, history, and publication |
| `src/` | Static production interface and prerendered public pages |
| `.github/workflows/` | Collection, synchronization, verification, and Pages publication |
| `requirements/` | Reviewed, hash-locked Python automation environments |

Maintainers run the complete repository gate before production changes:

```sh
pnpm check
```

That gate covers Python and frontend linting and type checks; the production build; links, fragments, metadata, CSP, hydration, and no-JavaScript behavior; serious accessibility findings; responsive overflow; and keyboard navigation. The pinned toolchains and maintainer-only environment preparation are recorded in [the change policy](CONTRIBUTING.md) and [deployment runbook](docs/DEPLOYMENT.md).

## Documentation index

- [Architecture](docs/ARCHITECTURE.md)
- [Public data contract](docs/DATA-CONTRACT.md)
- [Data sources and provenance](docs/DATA-SOURCES.md)
- [Detection and brand matching](docs/DETECTION.md)
- [Candidate history](docs/HISTORY.md)
- [Private review workflow](docs/REVIEW-WORKFLOW.md)
- [Deployment and schedules](docs/DEPLOYMENT.md)
- [Performance budgets](docs/PERFORMANCE.md)
- [Data licensing and attribution](DATA-LICENSE.md)
- [Security policy](SECURITY.md)

Original software and documentation are licensed under the [Apache License 2.0](LICENSE). That license does not relicense third-party data, screenshots, trademarks, or source material, and it does not designate modified copies as a HECAVEX-operated service.
