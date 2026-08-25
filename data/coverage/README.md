# Brand coverage ledger

`brand-coverage.json` makes a zero-signal result interpretable for every reviewed brand. It records registry review state, bounded CT and CertStream activity, URLScan asset support, review outcomes, and matcher-corpus coverage.

The ledger describes collection and review coverage, not phishing prevalence. It contains no secret query, analyst identity, raw provider response, or private review note.

Per-brand CT fields are derived from each persisted query outcome and result-ID cursor. A `partial` outcome is backlog; a query with no run timestamp is separately reported as never attempted. Neither state is called complete CT coverage. URLScan's hunt cursor describes a shared scheduler, so it appears once under `globalCollectorState` and is not attributed to every brand.
