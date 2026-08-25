# HECAVEX Radar

This repository is the operational source and public change record for [radar.hecavex.com](https://radar.hecavex.com), a HECAVEX-operated, read-only research service for recently observed potential phishing domains and URLs targeting Lithuanian brands.

It is not presented as a starter site, downloadable product, self-hosting package, or general-purpose phishing platform. The public source supports transparency, reproducible data handling, and review of the live service. The production service, its schedules, source access, review decisions, domain, and publication process are maintained by HECAVEX.

## Live service

- [Radar dashboard](https://radar.hecavex.com/) — current validated candidate observations
- [Candidate history](https://radar.hecavex.com/history/) — bounded observation provenance and explicit source transitions
- [Methodology](https://radar.hecavex.com/methodology/) — collection, matching, publication, and limitation disclosures
- [Technical reference](https://radar.hecavex.com/docs/) — schemas, operations, security boundaries, and data terms

Radar combines sampled Certificate Transparency observations, passive searches of existing public URLScan reports, and an optional deliberately limited HECAVEX public export. The Python pipeline validates and defangs every accepted record before producing bounded static JSON artifacts. The React interface renders those artifacts without an application server, account system, public write path, or database connection.

## Publication and safety boundaries

- Public source labels are limited to CertStream, URLScan, and configured HECAVEX exports.
- Indicators are defanged before publication. Credentials, query strings, fragments, and sensitive-looking path data are excluded.
- CertStream matches are research leads, not confirmation of phishing. Qualifying records are published as `suspected`; the collector reads certificate names and never visits candidate hosts.
- URLScan is optional passive corroboration. Radar searches existing public reports and never submits or opens a candidate URL. Missing or non-public scan visibility does not suppress an independently qualifying CertStream record.
- Screenshots and evidence links are URLScan-only. Opening evidence may contact `urlscan.io`, never the observed host.
- The public registry and matcher are separate from HECAVEX private collectors, proprietary detection logic, and internal case history.
- A confidence score is a ranking aid, not a probability, verdict, or actor attribution.
- Radar is best-effort public research. It provides no monitoring, notification, response, takedown, coverage, availability, or service-level guarantee.

## Operating model

The service is published through reviewed GitHub Actions workflows. Cron schedules are UTC and may start late.

| Operation | Schedule or trigger | Service artifact |
| --- | --- | --- |
| CertStream sample | `8,23,38,53 * * * *` | Defanged candidate archive and latest bounded collection-health record |
| URLScan hunt | `37 */2 * * *` | Bounded hunt-state ledger and validated daily archive when the optional source is configured |
| Official asset pivot | `47 3,15 * * *` | Stable first-party favicon/JavaScript hashes and independently qualified public URLScan observations |
| Snapshot synchronization | `17 * * * *` | Live snapshot, retained history, and compacted history summary |
| Site deployment | Successful code CI, material snapshot sync, or changed CertStream health | Static production pages for `radar.hecavex.com` |

The scheduled CertStream listener runs for eight minutes four times per hour: at most 768 minutes, or 53.3% of a day, if every run starts and completes. It is sampled live coverage, not a continuous listener, daily replay, or durable CT source. GitHub Actions can start late, drop a scheduled event, or fail, so actual listening time can be substantially lower. The dashboard publishes the latest attempt's actual timing, aggregate counts, outcome, schedule delay, last success, and freshness without retaining raw certificate names. The accepted plan for durable checkpointed CT coverage is recorded in [ADR 0001](docs/decisions/0001-ct-coverage.md).

The URLScan workflow runs at minute 37 every two hours. Each run attempts exact passive lookups for the complete bounded set of at most 250 candidates observed during the rolling previous seven days, subject to conservative request budgets. A deterministic cursor preserves progress only when an operator lowers the per-run selection or a request budget interrupts the set. The hunter performs only searches of existing public reports and retrieval of public result documents: it does not submit scans or visit candidate hosts. A missing `URLSCAN_API_KEY` is a successful, explicit skip with no API request. The checked-in hunt-state ledger records configuration, UTC budget counters, cursor progress, and the latest outcome, but no credential or candidate domain.

At 03:47 and 15:47 UTC, a second passive URLScan job rotates through each brand's reviewed main website. It retains bounded first-party favicon and JavaScript SHA-256 hashes only after support from two distinct public scans, rejects hashes known to be shared by multiple registry brands within the retained collision ledger, and uses them only to discover public reports. A matching candidate still needs independent same-brand domain or provider-verdict evidence before it can enter the URLScan archive; title evidence also requires a URLScan phishing verdict. No official page, asset, or candidate is fetched directly.

The hunt-state file is workflow evidence, not bootstrap configuration: its first checked-in value and later transitions must come from a scheduled or manually dispatched GitHub Actions run, never from locally generated placeholder output. Snapshot synchronization maps an unconfigured hunt to a public `skipped` source state while retaining previously validated URLScan observations; it does not recast absence of enrichment as benign evidence.

## Public service artifacts

| Path | Role in `radar.hecavex.com` |
| --- | --- |
| `public/data/radar.json` | Current checked and bounded dashboard snapshot |
| `public/data/history.json` | Bounded public candidate-history projection |
| `public/data/collection-health.json` | Latest bounded CertStream attempt health; no raw candidates |
| `public/data/signals/` | Lazy, per-signal CertStream/URLScan context; 16 KiB each and 3 MiB in aggregate |
| `data/brands-lt.json` | Reviewed Lithuanian brand and official-domain registry |
| `data/certstream/` | Date-partitioned successful sample metadata and defanged CT candidates |
| `data/urlscan/` | Date-partitioned validated URLScan observations, bounded detail context, and credential-free hunt and official-asset state |
| `data/history/` | Deterministic daily events and compacted history summary |
| `data/review/public-decisions.json` | Explicitly exported, sanitized review decisions only |

Public snapshots and their schemas are documented in the [data contract](docs/DATA-CONTRACT.md). Third-party observations and screenshots remain subject to their source terms; see [data licensing and attribution](DATA-LICENSE.md).

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
