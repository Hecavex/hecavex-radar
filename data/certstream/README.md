# CertStream archive

The production Radar collector records each successful sampled window in `YYYY-MM-DD/attempts.ndjson`, using the Europe/Vilnius date on which the attempt ended. A successful zero-match window therefore still creates a dated partition. The attempt row contains only bounded aggregate counts and timing; it does not contain certificate names.

`YYYY-MM-DD/domains.ndjson` is created only when the current precision rules accept at least one Certificate Transparency observation. Its absence means that no candidate was archived in the successful windows recorded for that partition. It does not mean that the entire day's Certificate Transparency stream was observed or that no qualifying certificate existed outside those sampled windows.

Archived candidates are re-evaluated against the current Lithuanian brand registry and matching rules before publication, so corrected false positives disappear automatically.
