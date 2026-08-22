# Sanitized review decisions

`public-decisions.json` is the only analyst-review artifact consumed by the public pipeline. It contains bounded, defanged suppressions and manually observed candidates that still pass the current public brand matcher. It contains no analyst identity, private note, credential, or raw evidence.

The private append-only SQLite ledger is created outside this Git repository by `hecavex-review`. Exporting is an explicit second step; recording a local decision does not modify this directory or publish anything.

See [Private review workflow](../../docs/REVIEW-WORKFLOW.md) for operating instructions and the public schema.
