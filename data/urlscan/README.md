# URLScan daily archive

The production Radar service's passive hunter writes reviewed, defanged observations to
`YYYY-MM-DD/signals.ndjson` using the Europe/Vilnius calendar date.

At minute 37 every two hours, the hunter searches only existing public URLScan
reports and retrieves public result documents. It does not submit scans, visit
candidate hosts, or directly browse suspicious URLs. Searches are date-limited
to the rolling previous seven days. Each run attempts the complete bounded set
of at most 250 recent CertStream, Radar-snapshot, and transient discovery
candidates. A deterministic cursor preserves progress if an operator lowers the
per-run selection or a request budget interrupts that set.

`hunt-state.json` is a bounded operational ledger for the UTC daily request
budget and interrupted-set progress. It contains aggregate counters, a numeric cursor,
candidate counts, configuration state, timestamps, and the latest outcome. It
contains no API key or candidate domain. If `URLSCAN_API_KEY` is absent, the
hunter makes no API call, records `configured: false` with a successful
`skipped-not-configured` outcome, and leaves existing observations intact.
Repeated identical skips during the same UTC day do not rewrite the ledger or
create timestamp-only commits; each invocation remains visible in Actions history.

Internal defaults cap search calls at 25 per run and 900 per UTC day, and result
retrieval at 100 per run and 8,000 per UTC day. These are conservative guardrails
below URLScan's published quotas, not provider billing counters. Only successful
responses increment the local ledger; HTTP 429 stops further requests safely.

Each daily file is capped at 2,500 records and 20 MiB; report links and screenshots
are restricted to `https://urlscan.io`.

Accepted result context is written separately to `YYYY-MM-DD/intelligence.ndjson`.
It contains only the bounded, defanged page, network, provider-assessment, and TLS
fields used to build lazy public signal sidecars. Response bodies, request headers,
cookies, and extracted emails are not archived.

At 03:47 and 15:47 UTC, `hunt-brand-assets.yml` uses existing public result
documents for the reviewed main domain of each Lithuanian brand. It derives only
successful first-party favicon and JavaScript SHA-256 values and never fetches an
official asset, visits a candidate, or submits a scan. A hash needs timestamped
support from two public official-site scans inside 45 days before it can be used
as a pivot. A matching report is archived only when its candidate hostname or
URLScan brand verdict independently supports the same brand; title-only evidence
also requires a URLScan phishing verdict. A submitted non-official candidate is
retained across a redirect; the defanged final hostname is context only, and the
destination's host data or screenshot is not attributed to the candidate.

`official-brand-assets.json` is the credential-free operational state for that
job. It retains bounded active pivot assets, ownership entries for hashes pruned
from a brand's shortlist, shared-hash tombstones, UTC quota counters, cursors,
configuration state, and the latest outcome. Ownership and tombstones prevent a
common library or icon learned in separate runs from later appearing unique while
that collision remains in the bounded retained ledger. Older ownership and
tombstone entries can be evicted when their caps are reached. The file is capped
at 512 KiB and contains no API key or candidate domain.

The daily signal schema v2 requires typed `brandEvidence` and stores only
primary-HTML SHA-256 values. A hash may record pivot provenance but cannot bind
a result to a brand by itself. Version 1 and untyped legacy records are ignored;
resource hashes from asset discovery are not copied into public signal rows.
