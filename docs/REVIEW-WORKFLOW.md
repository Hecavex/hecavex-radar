# Private review workflow

This is an operator-only HECAVEX maintenance workflow for corrections to [radar.hecavex.com](https://radar.hecavex.com). False-positive review is intentionally kept on an operator workstation; the public service remains read-only and contains no administration endpoint, authentication system, private notes, or direct write path.

## Storage boundary

`hecavex-review` creates an append-only SQLite database outside the Git repository. On Windows the default is `%LOCALAPPDATA%\HECAVEX\Radar\review.sqlite3`; on Linux it follows `XDG_DATA_HOME` or `~/.local/share`. Set `RADAR_REVIEW_DB` or pass `--database` to use another path. Paths inside the repository are rejected against the installed project root, independent of the current working directory.

The review CLI is a checkout-local HECAVEX operator tool, not a public administration product. Maintainers install this repository in editable mode (`python -m pip install -e ".[dev]"`) so its canonical project root, registry, snapshot, and sanitized-export directory remain the checked-out files. A standalone wheel install is not supported for review operations because its module path would point into `site-packages` rather than an operator checkout.

The event table has database triggers that reject updates and deletes. Restore, unallowlist, and remove operations append compensating events. Private notes are stored only in this database and are omitted from normal listings.

Back up this database as private working material. Do not put it in Git, a publicly shared folder, an issue, or a CI artifact.

Initialize or verify the empty ledger before the first review:

```sh
hecavex-review init
```

This command creates only the schema and append-only triggers at the private path. It does not add a decision or modify a public artifact.

## Commands

Create a private pivot queue from the current published snapshot without performing any network request:

```sh
hecavex-handoff
```

The command writes `data/hecavex/pivot-candidates.json`. That directory is git-ignored and the output contains only bounded, defanged rows backed by CertStream or public URLScan evidence. Review it locally; do not commit it. A candidate selected after analysis must still pass the current public matcher before `hecavex-review add` accepts it.

Record an exact false positive and later restore it:

```sh
hecavex-review false-positive secure-swedbank-login.example --reason lexical-collision --note "private case context"
hecavex-review restore secure-swedbank-login.example
```

Maintain an allowlist:

```sh
hecavex-review allowlist legitimate.example --scope exact --reason legitimate-domain
hecavex-review allowlist official.example --scope subdomains --reason official-domain --yes
hecavex-review unallowlist official.example
```

Add or remove a manually observed candidate:

```sh
hecavex-review add secure-swedbank-login.example --brand Swedbank
hecavex-review remove secure-swedbank-login.example
```

An addition must independently pass the current public matcher. The CLI infers the matching brand, clamps confidence to the public score, and fixes status to `suspected`. Missing URLScan evidence is allowed; it is not converted into either benign or malicious evidence.

Record a time-bounded positive assessment only after examining evidence outside the public dashboard:

```sh
hecavex-review confirm support-vinted.ph \
  --reason credential-phishing \
  --evidence certificate-transparency \
  --evidence urlscan-page \
  --lt-relevance lithuanian-targeting \
  --analyst-confidence 85 \
  --expires-at 2026-09-25T12:00:00.000Z \
  --note "private evidence references"
```

`confirm` is the only action that can create an active `confirmed-suspicious` assessment and make the row eligible for the separate reviewed STIX Indicator feed. It requires a future expiry, a controlled disposition reason, and at least one controlled evidence code. The evidence code states what the analyst used; raw screenshots, case notes, identities, and evidence values stay private. `--analyst-confidence`, when supplied, is separate from the automated domain `matchScore`.

Correct public assessment metadata without changing its stable Indicator identity:

```sh
hecavex-review correct support-vinted.ph \
  --reason brand-impersonation \
  --evidence certificate-transparency \
  --evidence screenshot \
  --evidence urlscan-page \
  --expires-at 2026-10-25T12:00:00.000Z
```

A correction preserves the first confirmation time and advances the public modification time. It must replace at least one public field. When evidence no longer supports the Indicator, append a retraction instead of deleting history:

```sh
hecavex-review retract support-vinted.ph --reason incorrect-assessment --note "private correction context"
```

Retraction produces the same STIX Indicator ID with `revoked: true`. That terminal lifecycle remains in the sanitized export. A later `confirm` starts a new lifecycle with a new Indicator ID; it does not remove or un-revoke the earlier object. If a review never supported confirmation, record it as inconclusive:

```sh
hecavex-review inconclusive support-vinted.ph \
  --reason insufficient-evidence \
  --evidence certificate-transparency
```

After a confirmation expires, the dashboard presents it as `needs-review`; expiry is not silently represented as a false positive or STIX revocation. Renew an active assessment before expiry with `correct --expires-at ...`. An already expired assessment must be confirmed again so the new explicit review boundary is recorded.

Inspect active state, then export:

```sh
hecavex-review list
hecavex-review list --events
hecavex-review export
```

Recording a decision never edits the repository. `export` is the only command that writes `data/review/public-decisions.json`. Relative export paths are resolved below the installed project's canonical `data/review/` directory, so the same command is safe and predictable when invoked from another working directory. Absolute export paths are accepted only inside that directory.

## Export review

Before committing an export:

1. Inspect `git diff -- data/review/public-decisions.json`.
2. Confirm every indicator is defanged and every brand is correct.
3. Confirm subtree scope is necessary; prefer exact scope.
4. Search the diff for private notes, names, credentials, tokens, email addresses, and case references.
5. Run `pnpm check`.

The public file contains only deterministic decision IDs, defanged domains and URLs, scope, resolved brand, controlled reason and evidence codes, observation/review/expiry times, matcher and optional analyst scores, Lithuanian relevance, and explicit review/revocation state. Synchronization fails closed if the file is malformed, cross-brand, future-dated, oversized, duplicated, or inconsistent with the current matcher. Inspect `public/data/radar-reviewed.stix.json` as part of the publication diff whenever an assessment changes.
