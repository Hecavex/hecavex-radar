# Sanitized review decisions

`review-queue.json` is a deterministic worklist balanced across source, brand, score band, evidence tier, reason code, and candidate age. It contains public signal identifiers and facets only. The queue is not a random sample and must not be treated as a phishing-prevalence estimate.

`public-decisions.json` is the only analyst-review artifact consumed by the production `radar.hecavex.com` pipeline. It contains bounded, defanged suppressions, manually observed candidates that still pass the current public brand matcher, and explicitly exported dated positive, negative, inconclusive, correction, and retraction assessments. Every assessment carries an immutable integrity-checked admission envelope copied from an exact already-published current or retained signal. Assessment evidence is represented only by controlled category codes; the file contains no analyst identity, private note, credential, or raw evidence.

The private append-only SQLite ledger is created outside this Git repository by the HECAVEX operator tool `hecavex-review`. Exporting is an explicit second step; recording a workstation decision does not modify this directory or publish anything.

See [Private review workflow](../../docs/REVIEW-WORKFLOW.md) for operating instructions and the public schema.
