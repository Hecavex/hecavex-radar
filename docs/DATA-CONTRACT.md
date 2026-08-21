# Public data contract

The Python publisher is the normative producer of public data. It normalizes, scopes, and defangs every accepted observation before writing a snapshot. The browser checks the snapshot version and structure before rendering it; that structural check is not a substitute for producer-side validation.

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

`generatedAt` is the UTC publication time. Public timestamps use canonical `YYYY-MM-DDTHH:mm:ss.sssZ` form. Before publication, observations and retained rows are checked against the current Lithuanian brand registry. Official or suppressed hosts, observations without a resolved registry brand, reviewed exclusions, and conflicting brand/domain mappings are dropped.

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

## HECAVEX input and local handoff

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

The feed URL must use HTTPS, omit credentials, and use the default port. HTTP is accepted only from `localhost`, `127.0.0.1`, or `::1` for local development; production and GitHub Actions deployments require HTTPS.

### Local candidate handoff

When `HECAVEX_CANDIDATE_OUTPUT` names a file below `data/hecavex/`, synchronization atomically writes a git-ignored document with `schemaVersion: 1`, `dataset: "hecavex-candidates"`, `generatedAt`, `disposition: "potential"`, and `signals`.

The handoff is limited to 2,500 signals and 20 MiB. It includes only defanged public fields backed by CertStream or URLScan; HECAVEX-only observations and discovery-seed provenance are excluded. This is a local file export for private review. It performs no HTTP upload and uses no credentials.

## Deliberately excluded

- Userinfo, query parameters, fragments, cookies, page content, and credentials.
- Private observation IDs, analyst identities, internal endpoints, and collection telemetry.
- Detector features, model versions, proprietary rules, evidence graphs, and case data.
- Discovery-seed provider names and raw seed records.
- Private HECAVEX history.
