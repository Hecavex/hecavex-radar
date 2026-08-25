# Data sources and provenance

These are the sources and provenance boundaries of the HECAVEX-operated [radar.hecavex.com](https://radar.hecavex.com) service. Source operators define their own access, attribution, rate, and redistribution terms. Apache-2.0 licenses original Radar software, not third-party data or HECAVEX operation.

## CertStream and Certificate Transparency

CertStream emits Certificate Transparency log updates over a websocket. The collector reads certificate DNS names, rejects official domains, applies the public Lithuanian-brand heuristic, and archives only matching defanged domains. It does not retrieve or browse those domains.

- [CertStream documentation](https://certstream.dev/docs.html)
- [CertStream architecture](https://certstream.dev/architecture.html)
- [`reloading01/certstream-server-rust`](https://github.com/reloading01/certstream-server-rust), the server used by the scheduled workflow
- [certstream-server-rust MIT license](https://github.com/reloading01/certstream-server-rust/blob/main/LICENSE)

The production workflow starts a digest-pinned `certstream-server-rust` container and connects to its runner-local lite stream unless HECAVEX configures a monitored `CERTSTREAM_URL`. The lite stream omits DER and certificate chains while retaining the leaf fields needed for bounded public context. Maintainer diagnostic invocations without that setting use the compatibility endpoint at `wss://certstream.calidog.io/`; that behavior is not the service's durable collection design. Certificate issuance is not proof of phishing, so CT records remain `suspected`.

For a qualifying hostname, Radar may retain only the leaf subject country and normalized common name, issuer text, validity period, serial, fingerprints already present in the stream, and up to 12 same-registrable certificate names. It does not calculate absent fingerprints or retain DER, chains, extensions, certificate links, unrelated SANs, email addresses, or live URLs. All retained names and indicator-like text are sanitized and defanged before the public candidate archive is written.

The interim GitHub Actions sampler is scheduled at 08, 23, 38, and 53 minutes past each UTC hour for an eight-minute window. If all 96 daily runs start and complete, that is at most 768 listening minutes, or 53.3% of a day. GitHub Actions can delay or drop scheduled events, so the configured ceiling is not observed coverage.

Each scheduled attempt replaces [`public/data/collection-health.json`](../public/data/collection-health.json) with its actual start, end, websocket listening seconds, messages, DNS names, matches, newly archived records, outcome, scheduling delay, and last successful window. The file retains only the latest attempt and aggregate counters. Every successful window is also recorded in the day's bounded `attempts.ndjson`, so a zero-match window has an explicit dated partition. Neither artifact exposes certificate names, and neither can establish coverage between sampled windows.

The public registry is [`data/brands-lt.json`](../data/brands-lt.json). Official domains, subdomains, and reviewed `excludedDomains` are suppressed before scoring. See [Detection rules](DETECTION.md) for matching and archive revalidation.

## URLScan

At minute 37 every two hours, the scheduled hunter uses URLScan's authenticated search and result APIs to inspect already-existing public reports from the rolling previous seven days. Every search includes `task.visibility:public`, and both the search summary and result detail must independently report public visibility; missing, unlisted, or private visibility is rejected. The hunter performs bounded brand-domain queries, exact-domain queries for at most 250 recent CT, recent Radar-snapshot, and transient discovery seeds, stricter title checks, and a small number of exact primary HTML response SHA-256 pivots. Each run attempts the complete bounded candidate set; a deterministic cursor preserves progress only when an operator lowers the per-run selection or a request budget interrupts it.

Automated validation requires a result to independently support the same Lithuanian brand; an input seed alone is never published. Official brand domains and subdomains are suppressed. Arbitrary resource hashes and hostname-wide allow-listing are deliberately excluded because both create broad false positives.

- [URLScan Search API](https://docs.urlscan.io/pages/search-api-reference)
- [URLScan API overview](https://urlscan.io/docs/api/)
- [URLScan result format](https://urlscan.io/docs/result/)
- [URLScan quotas](https://docs.urlscan.io/apis/urlscan-openapi/generic)

URLScan credentials belong only in a process environment or the `URLSCAN_API_KEY` GitHub Actions secret. The hunter performs public search and result retrieval only: it does not submit scans, visit candidate sites, or store the credential in repository data. If the secret is absent, it makes no API request and records an explicit successful skip.

Accepted public results can also contribute a bounded page title and HTTP status, IP and autonomous-system context, URLScan's own verdict score/categories, and the limited TLS fields exposed for the same final hostname. A submitted candidate that independently matches the registry remains the indicator when the scan redirects, including when the destination is official; final-page hosting, screenshot, page, or TLS data is not assigned to that candidate. The defanged final hostname is retained as redirect context because redirects can be conditional or part of cloaking, not as a benign verdict. Provider assessment remains separate from Radar confidence. Page bodies, response content, extracted emails, cookies, request headers, and Google Safe Browsing state are not published.

The local UTC ledger defaults to no more than 25 search and 100 result requests per run, and 900 search and 8,000 result requests per day. These are intentionally below URLScan's published fixed-window quotas and are scheduling safeguards, not the provider's billing record. Only successful responses increment the local counters. A provider HTTP 429 stops further requests safely; the outcome remains visible for the next snapshot synchronization. API use and published metadata remain subject to URLScan's terms and quotas.

The twelve scheduled runs can therefore issue at most 300 searches and 1,200 result retrievals per UTC day, with at most one scheduled run in an hour. Manual dispatches share the persisted daily counters, run under the same serialized writer group, and must not be used to burst provider windows.

`data/urlscan/hunt-state.json` persists the numeric progress cursor, bounded candidate counts, UTC request counters, configuration state, timestamps, and latest outcome. It contains neither keys nor domains. The state distinguishes a completed attempt, local budget exhaustion, failure, and an unconfigured successful skip without rewriting historical observations.

### Official first-party asset pivots

A separate passive URLScan job runs at 03:47 and 15:47 UTC. It rotates through the first reviewed `officialDomains` value for each registry brand, querying official sites one at a time so a high-volume brand cannot crowd other brands out of a combined result page. It retrieves only existing public URLScan reports and derives SHA-256 hashes only for successful first-party favicon and JavaScript responses. It never downloads an asset directly, submits a scan, or contacts a candidate host. Reports without a valid observation time, and observations older than 45 days, are not allowed to refresh the asset state.

An asset becomes pivot-eligible only while the same digest has timestamped support from at least two distinct public scans of a reviewed official site inside the 45-day evidence window. Within the retained collision ledger, hash ownership is remembered separately from the per-brand pivot shortlist, so a common library or icon learned for different brands in different runs remains blocked even when one copy falls outside a brand's top hashes. This memory is deliberately bounded rather than exhaustive: older entries can be evicted when an entry cap is reached. Active assets, retained pruned-hash ownership, and retained shared-hash tombstones expire from their latest official scan observation after 45 days. The state is bounded to three favicon and ten JavaScript pivot hashes per brand, 600 pruned ownership entries, 300 shared-hash tombstones, three timestamped supporting scans per asset, and 512 KiB overall at `data/urlscan/official-brand-assets.json`.

An exact hash match is discovery evidence only. Before publication, the candidate's public result document must contain the same typed resource hash and independently identify the same brand through the candidate-domain matcher or URLScan brand verdict. A matching page title qualifies only when URLScan also classifies the result as phishing. Conflicting brand evidence is rejected. When a submitted candidate redirects to an official page, the submitted hostname remains the candidate and the final hostname is retained only as redirect context; official destination metadata cannot qualify or enrich the candidate. The hash itself is not written as brand evidence and cannot make an otherwise unqualified row publishable.

The twice-daily job has its own conservative UTC ledger: at most 40 searches and 100 result retrievals per run, and 80 searches and 400 result retrievals per day. By default, it rotates 20 official domains and up to 12 eligible hashes per run. With the registry's maximum 598 per-brand pivot slots, two daily runs complete a hash-search rotation in less than 25 days, inside the default 30-day public-report lookback. Request exhaustion advances only work actually attempted. These counters do not contain an API key and remain below the separate provider-wide account quota; operators must still consider the request use of the two-hour URLScan hunt.

The state records whether the optional key was configured and the latest completed, budget-limited, failed, or safely skipped outcome. Snapshot synchronization folds this credential-free status into the existing URLScan source note; it does not create another public source label.

## Transient discovery seeds

Discovery lists are processed in memory, filtered through the Lithuania registry, and capped before they can trigger exact passive URLScan lookups. They are not copied into `data/`, do not create dashboard rows, and never appear as public source labels. The adapters use [PhishDestroy Primary Active](https://github.com/phishdestroy/destroylist) and CERT Polska's [active-domain text list](https://hole.cert.pl/domains/v2/domains.txt); their upstream license and processing conditions still apply.

The published observation source is URLScan, while discovery-input attribution remains documented in [Data licensing and attribution](../DATA-LICENSE.md).

## HECAVEX public export

The optional HECAVEX service input must use a deliberately limited public-export endpoint following the [public data contract](DATA-CONTRACT.md). Records pass the same automated schema, safety, and brand-scope checks as other inputs. The production feed requires HTTPS; the HTTP loopback exception exists only for local maintainer validation. The export must not expose a private dashboard, database, collector API, detector output, credentials, or internal case history.

The repository default is explicitly disabled (`HECAVEX_ENABLED=false`). Radar does not ship or infer an endpoint or token. Until HECAVEX provisions a deliberately public, read-only export and configures the documented variable and secret, the dashboard reports this source as not configured and continues with the other sources.

## Screenshots

Screenshots are optional and URLScan-only. The publisher accepts HTTPS URLs on exactly `urlscan.io`, removes query strings and fragments, and rejects credentials, non-default ports, and subdomains. The dashboard loads a screenshot only when requested and never embeds or contacts the observed site.
