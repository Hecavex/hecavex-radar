# Candidate history

The synchronizer writes deterministic, defanged observation and status-transition events below `daily/YYYY-MM-DD/events.ndjson`. Re-running synchronization over the same source observations produces the same event IDs and does not append duplicates.

Daily detail is append-only inside its retention window. After `RADAR_HISTORY_DETAIL_DAYS`, validated events are compacted into `summary.json` and the working-tree daily partition is removed. Summary entries expire after `RADAR_HISTORY_SUMMARY_DAYS`, and both detail and summary have hard record and byte caps. Git history still records prior committed partitions.

Absence from a later snapshot never creates an `offline` or `mitigated` event. A status transition exists only when a supported source explicitly supplies a different state. CertStream and URLScan observations remain `suspected`.
