# Public data contract

This contract governs the artifacts published by [radar.hecavex.com](https://radar.hecavex.com). The service's Python publisher is the normative producer of public data: it normalizes, scopes, and defangs every accepted observation before writing a snapshot. The browser checks the snapshot version and structure before rendering it; that structural check is not a substitute for producer-side validation.

## Public snapshot

The dashboard reads `public/data/radar.json` with this top-level shape:

```json
{
  "schemaVersion": 1,
  "dataset": "live",
  "generatedAt": "2026-08-21T09:15:00.000Z",
  "signals": [],
  "sources": []
}
```

`generatedAt` is the UTC publication time. Public timestamps use canonical `YYYY-MM-DDTHH:mm:ss.sssZ` form. Before publication, observations and retained rows are checked against the current Lithuanian brand registry. Official or suppressed hosts, observations without a resolved registry brand, reviewed exclusions, and conflicting brand/domain mappings are dropped. The complete public snapshot is capped at 512 KiB; the publisher fails instead of truncating when the cap is exceeded.

### Signal fields

Each signal represents one normalized host. Observations of different paths on that host share one public row.

| Field | Type | Notes |
| --- | --- | --- |
| `id` | string | First 20 hexadecimal characters of SHA-256 over the normalized defanged hostname. |
| `url` | string | Defanged HTTP(S) indicator; userinfo is rejected, query and fragment are removed, and nested URLs and sensitive path segments are redacted. |
| `domain` | string | Defanged normalized hostname. |
| `firstSeen` | UTC timestamp | Canonical millisecond form; invalid or missing input becomes the normalized `lastSeen`, and it is never later than `lastSeen`. |
| `lastSeen` | UTC timestamp | Canonical millisecond form; invalid or missing input becomes the UTC publication time. |
| `sources` | string[] | Deduplicated observation providers: `CertStream`, `URLScan`, or `HECAVEX`. Discovery-seed lineage is not included. |
| `status` | enum | `active`, `suspected`, `offline`, `mitigated`, or `unknown`. |
| `brand` | string or null | Registry-resolved claimed target, not attribution. |
| `country` | string or null | Hosting observation, not actor location. |
| `host` | string or null | Provider/ASN text or a defanged address. |
| `screenshotUrl` | string or null | Optional HTTPS URL on exactly `urlscan.io`, never a subdomain. Credentials and explicit ports are rejected; query and fragment are removed before publication. |
| `referenceUrl` | string or null | Optional canonical `https://urlscan.io/result/<uuid>/` report URL. |
| `hashes` | string[] | Up to eight unique, lowercase, non-empty SHA-256 hashes of primary HTML response bodies. |
| `reasonCodes` | string[] (optional) | Up to 16 controlled public provenance labels. They explain automated acceptance inputs; they are not verdicts or private detector features. |
| `confidence` | integer | Rounded and clamped to 0-100. The viewer displays it as a score out of 100, never as a percentage or probability. |

When signals merge, the publisher unions sources and hashes, keeps the earliest `firstSeen` and latest `lastSeen`, selects the most specific safe path, and keeps the highest confidence. Conflicting non-null brands for one host invalidate the merged row. Status comes from the observation with the newest `lastSeen`; only observations at the same time use the tie-break order `active`, `suspected`, `unknown`, `offline`, then `mitigated`. The newest non-null country, host, screenshot, and reference metadata wins. The final list is newest-first and capped by `RADAR_MAX_SIGNALS`.

### Source fields

The top-level `sources` array reports the state of each supported public source.

| Field | Type | Notes |
| --- | --- | --- |
| `name` | string | `CertStream`, `URLScan`, or `HECAVEX`. |
| `homepage` | string | Fixed provider homepage paired with `name`; arbitrary source links are rejected by the viewer. |
| `fetchedAt` | UTC timestamp or null | Canonical millisecond form for the current successful archive/feed load, current failed-attempt time, or previous successful load when recent rows are retained. |
| `records` | non-negative integer | Accepted records represented for that source, not a lifetime total. |
| `state` | enum | `healthy`, `partial`, or `skipped`. |
| `note` | string or null | Short public collection or retention note. |

`partial` means an attempted source was unavailable or only retained recent rows remain. `skipped` means the source was not configured for that publication.
For archive-backed inputs, `healthy` confirms that the publisher loaded and validated the available archive; it is not an upstream collector-uptime or freshness guarantee.

## CertStream collection health

The dashboard separately reads `public/data/collection-health.json`. This is operational evidence for the latest sampled CertStream attempt, not a signal source and not a candidate archive:

```json
{
  "schemaVersion": 1,
  "dataset": "certstream-collection-health",
  "generatedAt": "2026-08-21T19:17:53.656Z",
  "expectedIntervalSeconds": 1800,
  "staleAfterSeconds": 5400,
  "lastSuccessAt": "2026-08-21T19:17:53.656Z",
  "freshness": {
    "status": "current",
    "referenceAt": "2026-08-21T19:17:53.656Z",
    "ageSeconds": 0
  },
  "latestAttempt": {
    "startedAt": "2026-08-21T19:13:30.000Z",
    "collectorStartedAt": "2026-08-21T19:13:43.649Z",
    "endedAt": "2026-08-21T19:17:53.656Z",
    "trigger": "schedule",
    "scheduledFor": "2026-08-21T19:02:00.000Z",
    "scheduleStatus": "delayed",
    "delaySeconds": 690,
    "expectedListeningSeconds": 240,
    "listeningSeconds": 240.0,
    "messages": 89532,
    "dnsNames": 160340,
    "matches": 0,
    "newRecords": 0,
    "connectionAttempts": 1,
    "connections": 1,
    "outcome": "healthy-empty",
    "summary": "Input was processed successfully; no candidate matched the publication heuristic."
  }
}
```

`startedAt` and `endedAt` bound the actual workflow attempt. `collectorStartedAt` is null when collector setup fails. `listeningSeconds` is the accumulated time with an open websocket, excluding setup, retry waits, and connection closing. `messages` counts valid JSON stream messages, `dnsNames` counts extracted certificate DNS names, `matches` counts qualifying heuristic matches before archive deduplication, and `newRecords` counts unique rows appended to the daily archive. None of these fields contains a domain, URL, certificate, candidate ID, or detector payload.

Collection outcomes are independent of scheduling timeliness:

| `outcome` | Meaning |
| --- | --- |
| `healthy-empty` | A bounded window completed with usable DNS-name input and at least 90% of its expected listening time, but no candidate matched. |
| `healthy-matches` | The same healthy-window conditions passed and one or more candidates matched. |
| `no-input` | A connection opened, but no certificate DNS names were received. |
| `partial` | Some usable input was processed, but the window was interrupted, failed, or accumulated less than 90% of expected listening time. |
| `failed` | The workflow could not establish or complete a usable collector connection. |

`scheduleStatus` is `scheduled`, `delayed`, `manual`, or `unknown`. A scheduled attempt becomes `delayed` when its actual start is more than `CERTSTREAM_DELAY_THRESHOLD_SECONDS` after the most recent configured slot; the default threshold is 300 seconds. Delay does not replace the collection outcome, so a delayed run can still be accurately described as healthy-empty, no-input, partial, or failed.

`lastSuccessAt` advances only for `healthy-empty` or `healthy-matches`. The producer records freshness relative to that timestamp at write time; the viewer recalculates it against its current clock using `staleAfterSeconds`. The scheduled workflow atomically replaces this one file on every finalizable attempt. Its schema has an exact fixed field set, its writer caps it at 32 KiB, and it retains no attempt history, preventing per-run file growth. A hard runner cancellation or platform failure before the finalizer and git push cannot be made observable by the stopped workflow.

Before the first instrumented workflow completes, the checked-in bootstrap document uses `latestAttempt: null`, `lastSuccessAt: null`, and unavailable freshness. This is intentionally different from synthesizing metrics from an older configured duration or incomplete logs. Normal workflow output always replaces `latestAttempt` with the complete fixed-field object above.

## Archive formats

Archive files are newline-delimited JSON and use the Europe/Vilnius calendar date.

### CertStream

`data/certstream/YYYY-MM-DD/domains.ndjson` stores one candidate per normalized domain per Vilnius day:

```json
{
  "schemaVersion": 1,
  "id": "8eaf01bd355d5f450e81",
  "observedAt": "2026-08-21T09:15:00.000Z",
  "indicatorType": "domain",
  "domain": "secure-brand[.]example",
  "registrableDomain": "secure-brand[.]example",
  "source": "CertStream",
  "brand": "Example Brand",
  "confidence": 95,
  "reasons": ["brand text match: example brand", "suspicious token: secure"]
}
```

The archive `id` hashes the normalized refanged domain, unlike the public snapshot ID, which hashes the defanged hostname. IDs from different artifact types are therefore not join keys. A daily CertStream file is capped at 25,000 valid records and 25 MiB. Reasons contain only contributions from the open heuristic.

### URLScan

`data/urlscan/YYYY-MM-DD/signals.ndjson` stores public signal fields plus:

```json
{
  "schemaVersion": 2,
  "hashType": "primary-html-sha256",
  "brandEvidence": ["domain", "primary-html-sha256"]
}
```

Each complete record remains defanged and uses the same host-based ID namespace as the public snapshot. `brandEvidence` is a non-empty, duplicate-free list containing only `domain`, `title`, `verdict`, or `primary-html-sha256`, and at least one of the first three values is required. The hash label records supplemental pivot provenance; it is not brand evidence by itself.

A current hostname match must agree with the declared brand. When the hostname no longer matches, only a row backed by title or verdict evidence may remain, and it must still resolve to a current registry brand and pass suppression and collision checks. Before a row can enter the archive, its URLScan search summary and result detail must both identify the scan as public; missing, unlisted, or private visibility is rejected. Version 1 rows and legacy version 2 rows without typed evidence are rejected. References use the canonical URLScan result path, screenshots use the fixed URLScan policy, and resource or empty-body hashes are rejected. A daily file is capped at 2,500 records and 20 MiB.

### Candidate history

`data/history/daily/YYYY-MM-DD/events.ndjson` uses UTC partitions and stores exact-schema, defanged events. An event has:

| Field | Type | Notes |
| --- | --- | --- |
| `schemaVersion` | integer | Always `1`. |
| `eventId` | string | First 32 hexadecimal characters of SHA-256 over the immutable event identity fields. |
| `signalId` | string | Same host-based ID namespace as the public live snapshot. |
| `eventType` | enum | `observation` or `status-transition`. |
| `observedAt` | UTC timestamp | Source observation boundary or explicit transition time. |
| `domain` | string | Canonical defanged hostname. |
| `brand` | string | One current registry-resolved target. |
| `sources` | string[] | One or more supported public sources. |
| `status` | enum | Same values as the live snapshot. |
| `previousStatus` | enum or null | Set only for a status transition; null for observation events and first publication. |
| `confidence` | integer | Score recorded with the event; not part of event identity. |
| `reasonCodes` | string[] | Controlled public provenance labels; not part of event identity. |

Event identity includes schema version, signal ID, event type, observation time, sources, status, and previous status. It deliberately excludes confidence and reason wording so replaying one observation after a scoring change cannot create a second event. Daily files are capped at 10,000 events and 8 MiB; invalid, duplicate, oversized, or over-cap input fails closed instead of being skipped or truncated.

After the detail window, events compact into `data/history/summary.json`. The public `public/data/history.json` projection exposes `id`, `domain`, `brand`, `firstSeen`, `lastSeen`, `observationCount`, `sources`, `latestStatus`, `reasonCodes`, and up to 16 typed `statusTransitions`. Private review suppressions and current brand rules are re-applied before every projection. The complete projection is capped at 512 KiB and fails closed rather than truncating. See [Candidate history](HISTORY.md) for retention limits.

## HECAVEX input and operator handoff

### Configured source input

A configured HECAVEX endpoint may return an array of signal objects or `{ "signals": [...] }`:

```json
{
  "signals": [
    {
      "url": "https://suspicious.example/path?private=value",
      "firstSeen": "2026-08-21T08:05:00Z",
      "lastSeen": "2026-08-21T09:15:00Z",
      "status": "suspected",
      "brand": "Example Brand",
      "country": "LT",
      "host": "Example Hosting / AS64500",
      "screenshotUrl": "https://urlscan.io/screenshots/11111111-1111-1111-1111-111111111111.png",
      "referenceUrl": "https://urlscan.io/result/11111111-1111-1111-1111-111111111111/",
      "hashType": "primary-html-sha256",
      "hashes": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
      "confidence": 78
    }
  ]
}
```

`indicator` or `domain` may replace `url`, and existing defanged values are accepted. Accepted aliases are `first_seen`, `last_seen`, `brandTargeted`, `brand_targeted`, `hosting`, `screenshot_url`, `reference_url`, `confidenceScore`, and `confidence_score`. Hashes are accepted only when `hashType` is `primary-html-sha256`. Any supplied `source` is ignored; accepted rows are attributed to `HECAVEX`.

Missing or unrecognized status becomes `unknown`; missing or invalid confidence becomes `50`. Timestamp normalization follows the public rules above. A syntactically valid row may still be dropped by Lithuanian registry scoping.

The feed URL must use HTTPS, omit credentials, and use the default port. HTTP is accepted only from `localhost`, `127.0.0.1`, or `::1` for maintainer tests; production service workflows require HTTPS.

### Operator candidate handoff

When `HECAVEX_CANDIDATE_OUTPUT` names a file below `data/hecavex/`, synchronization atomically writes a git-ignored document with `schemaVersion: 1`, `dataset: "hecavex-candidates"`, `generatedAt`, `disposition: "potential"`, and `signals`.

The handoff is limited to 2,500 signals and 20 MiB. It includes only defanged public fields backed by CertStream or URLScan; HECAVEX-only observations and discovery-seed provenance are excluded. This is an operator-workstation file export for private review. It performs no HTTP upload and uses no credentials.

## Sanitized review decisions

`data/review/public-decisions.json` is the only operator-review artifact accepted by synchronization. It has `schemaVersion: 1`, dataset `radar-review-decisions`, a canonical UTC `generatedAt`, and two bounded arrays:

- `suppressions` contain a deterministic decision ID, defanged domain, `exact` or `subdomains` scope, optional resolved brand, and one controlled correction reason.
- `candidates` contain a deterministic decision ID, public signal ID, defanged URL and domain, observation time, current matcher-resolved brand, confidence no greater than the matcher score, and controlled reason codes including `manual-review`.

Both arrays are capped at 2,500 records and the file is capped at 2 MiB. Duplicate IDs, unsafe values, future timestamps, cross-brand candidates, unrecognized reasons, or candidates that no longer pass the current matcher make synchronization fail. A manual candidate is always attributed to `HECAVEX` and normalized to `suspected`. The private SQLite event ledger and its notes are outside this contract and must never be committed.

## Deliberately excluded

- Userinfo, query parameters, fragments, cookies, page content, and credentials.
- Private observation IDs, analyst identities, internal endpoints, and unbounded or event-level collection telemetry. The aggregate latest-attempt health fields documented above are deliberately public.
- Detector features, model versions, proprietary rules, evidence graphs, and case data.
- Discovery-seed provider names and raw seed records.
- Internal HECAVEX case history.
