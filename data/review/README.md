# Sanitized review decisions

`public-decisions.json` is the only analyst-review artifact consumed by the production `radar.hecavex.com` pipeline. It contains bounded, defanged suppressions, manually observed candidates that still pass the current public brand matcher, and explicitly exported analyst assessments. Assessment evidence is represented only by controlled category codes; the file contains no analyst identity, private note, credential, or raw evidence.

The private append-only SQLite ledger is created outside this Git repository by the HECAVEX operator tool `hecavex-review`. Exporting is an explicit second step; recording a workstation decision does not modify this directory or publish anything.

See [Private review workflow](../../docs/REVIEW-WORKFLOW.md) for operating instructions and the public schema.
