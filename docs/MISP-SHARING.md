# MISP sharing

Radar generates a static MISP feed at `/data/misp/` and an official-domain warning list at
`/data/misp-warninglists/hecavex-official-domains/list.json`.

The reviewed feed is disabled by default (`RADAR_MISP_FEED_ENABLED=false`). Keep it disabled
until a current MISP 2.5 instance has passed update and deletion-tombstone acceptance tests.
The official-domain warning list is independent and remains available.

The feed is deliberately narrower than the dashboard. Active values come only from unexpired
`confirmed-suspicious` analyst assessments. Automated candidates and inconclusive reviews are
excluded. Expired or explicitly retracted lifecycles are represented only as `deleted: true`
tombstones so an enabled downstream feed can remove a value it previously received. Every exported Attribute is a `domain`, is
marked `tlp:clear`, and has `to_ids` set to `false`. Confirmation permits public sharing; it
does not silently authorize a downstream IDS or blocking decision.

`manifest.json` follows the MISP static-feed layout: its keys are event UUIDs and the matching
event is stored as `<uuid>.json` in the same directory. Event, organisation, and attribute
UUIDs are deterministic. Each non-empty manifest row includes `integrity:sha256` for the exact
pretty-printed event file. When no qualifying review exists, the manifest is `{}` and the
placeholder event is unpublished and unindexed, so a feed fetch offers no empty event.

The warning list contains the reviewed first-party domains in `data/brands-lt.json`. Its
`hostname` matcher applies to `domain`, `hostname`, `url`, and `domain|ip` MISP attributes. A
warning-list hit is a false-positive/allow-list warning, not proof that a page or subdomain is
benign. MISP does not consume this file as an ordinary feed: an operator must install it as a
custom warning list (a directory containing `list.json`) and enable it on the instance.

Stable public entry points are:

- <https://radar.hecavex.com/data/misp/manifest.json> for reviewed feed discovery; and
- <https://radar.hecavex.com/data/misp-warninglists/hecavex-official-domains/list.json> for the warning-list document.

The browser-only <https://radar.hecavex.com/reporting/> utility is separate. It can prepare a
bounded local evidence manifest for one active reviewed confirmation, but it cannot create a
review, change the MISP feed, contact a candidate, or submit content to MISP.

Radar CI tests a strict repository-local compatibility profile for the event, manifest, and
warning-list artifacts, including deterministic identifiers and exact event-file integrity.
Validation against a pinned upstream MISP 2.5 schema and a real MISP database import remain
operational acceptance checks, including proof that same-UUID tombstones remove an imported
attribute. The repository does not claim that its local schema replaces MISP's importer
behavior, which is why the feed activation gate defaults to false.

References:

- <https://www.misp-standard.org/formats/core/#manifest>
- <https://github.com/MISP/MISP/blob/2.5/format/2.5/schema.json>
- <https://github.com/MISP/misp-warninglists>
