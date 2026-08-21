# Data sources and provenance

Source operators define their own access, attribution, rate, and redistribution terms. Apache-2.0 licenses this software, not third-party data.

## CertStream and Certificate Transparency

CertStream emits Certificate Transparency log updates over a websocket. The collector reads certificate DNS names, rejects official domains, applies the public Lithuanian-brand heuristic, and archives only matching defanged domains. It does not retrieve or browse those domains.

- [CertStream documentation](https://certstream.dev/docs.html)
- [CertStream architecture](https://certstream.dev/architecture.html)
- [`reloading01/certstream-server-rust`](https://github.com/reloading01/certstream-server-rust), the server used by the scheduled workflow
- [certstream-server-rust MIT license](https://github.com/reloading01/certstream-server-rust/blob/main/LICENSE)

Without `CERTSTREAM_URL`, the local CLI uses the compatibility endpoint at `wss://certstream.calidog.io/`. The scheduled workflow instead starts a digest-pinned `certstream-server-rust` container and connects to its runner-local domains-only stream. Long-running collectors should set `CERTSTREAM_URL` to a monitored WSS endpoint. Certificate issuance is not proof of phishing, so CT records remain `suspected`.

The public registry is [`data/brands-lt.json`](../data/brands-lt.json). Official domains, subdomains, and reviewed `excludedDomains` are suppressed before scoring. See [Detection rules](DETECTION.md) for matching and archive revalidation.

## URLScan

The scheduled hunter uses URLScan's authenticated search and result APIs to inspect already-existing public reports. Every search includes `task.visibility:public`, and both the search summary and result detail must independently report public visibility; missing, unlisted, or private visibility is rejected. The hunter performs bounded brand-domain queries, exact-domain queries for recent CT and transient discovery seeds, stricter title checks, and a small number of exact primary HTML response SHA-256 pivots. Automated validation requires a result to independently support the same Lithuanian brand; an input seed alone is never published. Official brand domains and subdomains are suppressed. Arbitrary resource hashes and hostname-wide allow-listing are deliberately excluded because both create broad false positives.

- [URLScan Search API](https://docs.urlscan.io/pages/search-api-reference)
- [URLScan API overview](https://urlscan.io/docs/api/)
- [URLScan result format](https://urlscan.io/docs/result/)
- [URLScan quotas](https://docs.urlscan.io/apis/urlscan-openapi/generic)

URLScan credentials belong only in a process environment or GitHub Actions secret. The hunter does not submit scans or contact candidate sites. API use and published metadata remain subject to URLScan's terms and quotas.

## Transient discovery seeds

Discovery lists are processed in memory, filtered through the Lithuania registry, and capped before they can trigger exact passive URLScan lookups. They are not copied into `data/`, do not create dashboard rows, and never appear as public source labels. The adapters use [PhishDestroy Primary Active](https://github.com/phishdestroy/destroylist) and CERT Polska's [active-domain text list](https://hole.cert.pl/domains/v2/domains.txt); their upstream license and processing conditions still apply.

The published observation source is URLScan, while discovery-input attribution remains documented in [Data licensing and attribution](../DATA-LICENSE.md).

## HECAVEX public export

HECAVEX is optional and must use a deliberately limited public-export endpoint following the [public data contract](DATA-CONTRACT.md). Records pass the same automated schema, safety, and brand-scope checks as other inputs. Production feed URLs require HTTPS; HTTP is accepted only on a loopback host for local development. The export must not expose a private dashboard, database, collector API, detector output, credentials, or private history.

## Screenshots

Screenshots are optional and URLScan-only. The publisher accepts HTTPS URLs on exactly `urlscan.io`, removes query strings and fragments, and rejects credentials, non-default ports, and subdomains. The dashboard loads a screenshot only when requested and never embeds or contacts the observed site.
