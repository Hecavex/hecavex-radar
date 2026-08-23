# URLScan daily archive

The production Radar service's passive hunter writes reviewed, defanged observations to
`YYYY-MM-DD/signals.ndjson` using the Europe/Vilnius calendar date.

Only existing URLScan results are searched. The service does not submit or
directly browse suspicious URLs. Each daily file is capped at 2,500 records and
20 MiB; report links and screenshots are restricted to `https://urlscan.io`.
Schema v2 requires typed `brandEvidence` and stores only primary-HTML SHA-256
values. A hash may record pivot provenance but cannot bind a result to a brand
by itself. Version 1 and untyped legacy records are ignored; resource hashes
are discarded.
