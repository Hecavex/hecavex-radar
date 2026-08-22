# Candidate history

Radar history answers two narrow questions: when did the public pipeline accept an observation for this host, and when did a supported source explicitly change its status? It is not a reputation database and does not infer current liveness.

## Event identity

Each history event has a 32-character identifier derived from its signal ID, event type, observation time, sources, status, and previous status. Mutable confidence values and explanatory labels are not part of the identity. Replaying an unchanged source archive therefore cannot increase the observation count, even if registry wording or scoring changes later.

The 20-character `signalId` uses the same normalized defanged-host namespace as `public/data/radar.json`. Cross-brand observations for one signal ID are rejected rather than merged.

Two event types exist:

- `observation` records a validated first-seen or last-seen boundary from an accepted source record.
- `status-transition` records first publication or an explicit change from one supported status to another.

CertStream and URLScan always supply `suspected`. Only a validated HECAVEX input can supply `active`, `offline`, or `mitigated`. A host disappearing from recent archives creates no event.

## Retention and compaction

Daily detail lives at `data/history/daily/YYYY-MM-DD/events.ndjson` in UTC partitions. A file is capped at 10,000 events and 8 MiB. Detail is kept for 30 days by default. Invalid JSON, invalid events, duplicate IDs, or an exceeded cap fail synchronization instead of being skipped or truncated.

After the detail window, events compact into `data/history/summary.json`. The summary keeps first and last observation time, a bounded observation count, source and reason unions, latest explicit status, up to 16 transitions, and up to 64 recent event IDs per host. It is capped at 25,000 hosts and 12 MiB. Entries expire after 730 days by default. Git retains the committed history of partitions removed from the working tree.

`compactedThrough` is a closed UTC-day watermark. If an already compacted partition reappears through source replay, it is discarded without changing counts. Late observations dated on or before that watermark require an intentional history rebuild from Git archives; normal synchronization does not reopen compacted days.

`public/data/history.json` is a bounded projection of the compacted summary and retained detail. It is revalidated against the current brand registry and sanitized review decisions on every synchronization. The default row cap is 5,000 hosts, while a separate 512 KiB publication cap ensures the static deployment remains bounded. Synchronization fails instead of silently truncating when either limit is exceeded.

Configuration:

| Variable | Default | Range |
| --- | ---: | ---: |
| `RADAR_HISTORY_DETAIL_DAYS` | 30 | 7-90 |
| `RADAR_HISTORY_SUMMARY_DAYS` | 730 | 30-3,650 |
| `RADAR_HISTORY_MAX_SIGNALS` | 5,000 | 1-25,000 |
| `RADAR_HISTORY_ROOT` | `data/history` | repository-relative |
| `RADAR_HISTORY_OUTPUT` | `public/data/history.json` | repository-relative |

Running synchronization twice over unchanged inputs must leave the live snapshot, daily events, compacted summary, and public history byte-for-byte unchanged.
