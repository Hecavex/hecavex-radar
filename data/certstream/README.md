# CertStream archive

The production Radar collector creates `YYYY-MM-DD/domains.ndjson` only when the current precision rules accept at least one Certificate Transparency observation for the operated service. Empty days intentionally have no file.

Archived candidates are re-evaluated against the current Lithuanian brand registry and matching rules before publication, so corrected false positives disappear automatically.
