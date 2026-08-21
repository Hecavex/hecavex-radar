# Public data contract

The current snapshot schema is version 1. A HECAVEX publication endpoint may return either an array of signal objects or `{ "signals": [...] }`.

```json
{
  "signals": [
    {
      "url": "https://suspicious.example/path?private=value",
      "firstSeen": "2026-08-21T08:05:00Z",
      "lastSeen": "2026-08-21T09:15:00Z",
      "source": "HECAVEX",
      "status": "suspected",
      "brand": "Example Brand",
      "country": "LT",
      "host": "Example Hosting · AS64500",
      "screenshotUrl": "https://urlscan.io/screenshots/example.png",
      "confidence": 78
    }
  ]
}
```

Snake-case aliases are accepted for timestamps, targeted brand, screenshot, and confidence. `indicator` or `domain` may be used in place of `url`. Existing defanged inputs are accepted.

## Published fields

| Field | Type | Notes |
| --- | --- | --- |
| `id` | string | Truncated SHA-256 of the normalized scheme, host, port, and path. |
| `url` | string | Defanged; query and fragment removed; nested URLs and sensitive-looking path segments redacted. |
| `domain` | string | Defanged hostname. |
| `firstSeen` / `lastSeen` | ISO 8601 | Invalid values fall back to the publication time. |
| `sources` | string[] | Deduplicated observation sources. |
| `status` | enum | `active`, `suspected`, `offline`, `mitigated`, or `unknown`. |
| `brand` | string or null | Claimed target, not attribution. |
| `country` | string or null | Hosting observation, not actor location. |
| `host` | string or null | Provider/ASN or a defanged address. |
| `screenshotUrl` | string or null | HTTPS and on the configured allow-list. |
| `confidence` | integer | Clamped to 0–100; supplied by a feed or the documented open CT heuristic. |

## Daily CertStream archive

The collector writes newline-delimited JSON to `data/candidates/YYYY-MM-DD/domains.ndjson`, using the Europe/Vilnius calendar date. Each line has this bounded schema:

```json
{"schemaVersion":1,"id":"8eaf...","observedAt":"2026-08-21T09:15:00.000Z","indicatorType":"domain","domain":"secure-brand[.]example","registrableDomain":"secure-brand[.]example","source":"CertStream","brand":"Example Brand","confidence":87,"reasons":["brand text match: example brand","suspicious token: secure"]}
```

Domains are defanged before disk write. `id` is a truncated SHA-256 of the normalized domain. A domain is stored once per Vilnius day. Each daily file is capped at 25,000 valid records and 25 MiB. Reasons expose the open rule contributions; they contain no private model output.

## Deliberately excluded

- Query parameters, fragments, userinfo, cookies, page content, and credentials.
- Private observation IDs, analyst identities, internal source endpoints, and collection telemetry.
- Detector features, model versions, proprietary rules, evidence graphs, and case data.
- Private HECAVEX history. The separate CT archive contains only newly collected public certificate candidates under the schema above.

The export endpoint should return only already-approved public observations. A bearer token protects machine-to-machine reads; it does not create a login requirement for dashboard visitors.
