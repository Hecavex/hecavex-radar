# Private review workflow

This is an operator-only HECAVEX maintenance workflow for corrections to [radar.hecavex.com](https://radar.hecavex.com). False-positive review is intentionally kept on an operator workstation; the public service remains read-only and contains no administration endpoint, authentication system, private notes, or direct write path.

## Storage boundary

`hecavex-review` creates an append-only SQLite database outside the Git repository. On Windows the default is `%LOCALAPPDATA%\HECAVEX\Radar\review.sqlite3`; on Linux it follows `XDG_DATA_HOME` or `~/.local/share`. Set `RADAR_REVIEW_DB` or pass `--database` to use another path. Paths inside the repository are rejected against the installed project root, independent of the current working directory.

The review CLI is a checkout-local HECAVEX operator tool, not a public administration product. Maintainers install this repository in editable mode (`python -m pip install -e ".[dev]"`) so its canonical project root, registry, snapshot, and sanitized-export directory remain the checked-out files. A standalone wheel install is not supported for review operations because its module path would point into `site-packages` rather than an operator checkout.

The event table has database triggers that reject updates and deletes. Restore, unallowlist, and remove operations append compensating events. Private notes are stored only in this database and are omitted from normal listings.

Back up this database as private working material. Do not put it in Git, a publicly shared folder, an issue, or a CI artifact.

## Commands

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

The public file contains only deterministic decision IDs, defanged domains and URLs, scope, resolved brand, controlled reason code, observation time, bounded confidence, and controlled publication-reason codes. Synchronization fails closed if the file is malformed, cross-brand, future-dated, oversized, duplicated, or inconsistent with the current matcher.
