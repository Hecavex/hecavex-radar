# Architecture

HECAVEX Radar has two public-data stages and one static viewer:

```text
CertStream websocket
        │
        ▼
open LT brand matcher ── defanged NDJSON ── data/candidates/YYYY-MM-DD/
                                                  │
PhishTank / OpenPhish / VMRay / HECAVEX export ───┤
                                                  ▼
                                      validate / merge / cap
                                                  │
                                                  ▼
                                     public/data/radar.json
                                                  │
                                                  ▼
                                      static React dashboard
```

The collector can run in bounded GitHub Actions windows or continuously in Docker. Both execute `python -m hecavex_radar.collect_certstream`, load the same public registry, use the same heuristic, and write the same schema. Feed adapters and snapshot publication also run in Python; React/TypeScript is limited to the static browser viewer.

## Trust boundaries

1. Certificate events, third-party feeds, public archive files, and the HECAVEX export are untrusted input.
2. The collector processes DNS names only. It does not resolve, connect to, or screenshot candidate hosts.
3. `python -m hecavex_radar.sync` is the only path from source data to the dashboard snapshot.
4. `public/data/radar.json` contains the complete current dashboard dataset. No browser API or database exists.
5. The React application validates schema version 1 before rendering.
6. Suspicious indicators are text only. Screenshot URLs must pass an HTTPS host allow-list.

The HECAVEX export is a narrow publication interface, not access to the private research system. It must not expose detector features, evidence graphs, analyst notes, user data, internal IDs, or private history.

## Failure behavior

The CertStream client reconnects with bounded exponential backoff, pings the socket, flushes periodically, and flushes again on `SIGINT`, `SIGTERM`, or the bounded deadline. Malformed events are ignored. An interrupted NDJSON line is ignored by snapshot publication.

Each snapshot source is isolated. A failed source is marked partial when another source succeeds. Output is written to a temporary file and renamed only after the full snapshot is ready. Before replacement, minimum-count and retained-percentage guards compare the new result with the last live snapshot. The snapshot is capped by `RADAR_MAX_SIGNALS`, sorted by `lastSeen`, and rebuilt from the configured recent window.
