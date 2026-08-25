# Weekly dataset releases

HECAVEX publishes one point-in-time Radar dataset package for each ISO week. These releases complement the live hourly files; they do not expand Radar's sampled collection coverage or turn a candidate into a maliciousness verdict.

## Release contract

[`release-weekly-dataset.yml`](../.github/workflows/release-weekly-dataset.yml) runs at 06:29 UTC each Monday and can also be dispatched by a maintainer. A successful run creates the tag `radar-data-YYYY-Www` at the exact checked-out `main` commit and publishes three assets:

| Asset | Purpose |
| --- | --- |
| `radar-data-YYYY-Www.tar.gz` | Reproducible archive of the checked-in static public data tree |
| `radar-data-YYYY-Www.manifest.json` | Source commit, snapshot timestamp, exclusion statement, and SHA-256 digest and byte length for every packaged file |
| `SHA256SUMS` | Download verification for the archive and standalone manifest |

The archive contains the canonical public dataset beneath a tag-named root: artifacts and checksum sidecars declared by the validated feed manifest, the feed manifest and its checksum, index-declared shards, and signal sidecars explicitly declared available by the snapshot. It excludes `public/data/collection-health.json`: that bounded latest-attempt document is replaced independently of the synchronized snapshot and would misrepresent an atomic weekly cut. Its last synchronized aggregate remains available in `pipeline-health.json`.

Before packaging, the workflow compares that reference-derived allowlist with every regular file below `public/data/`. A missing file, unexpected file, symlink, unsafe path, digest or length mismatch, or more than 10,000 files or 128 MiB fails the release. This prevents a stale or accidental public-data file from being preserved in an immutable archive.

The package timestamp and file order are normalized. Building twice from the same checkout must produce the same archive bytes; the workflow performs that comparison before uploading anything.

## One-time repository control

Release immutability is enforced by GitHub at repository level and is not enabled by the workflow.

1. In the repository settings, under **Releases**, enable **Release immutability**. The protection applies only to future releases.
2. Add the repository variable `RADAR_IMMUTABLE_RELEASES_CONFIRMED` with the exact value `true`.
3. Dispatch **Release weekly radar dataset** once or wait for the next Monday run.

The variable is an intentional operator gate, not proof of the setting. After publishing, the workflow queries the release API and fails unless GitHub reports `immutable: true`. Do not set the variable before the repository control is active.

GitHub locks the published tag and release assets when immutability is enabled and creates its own release attestation. The workflow also generates a separate SLSA-style provenance attestation for the archive and standalone manifest with the fully pinned official `actions/attest` action. No additional secret is required; the job uses short-lived OIDC and the repository workflow token.

## Idempotency and recovery

- An existing published and immutable tag for the current ISO week is verified and treated as a successful no-op.
- An interrupted draft can be refreshed only when it targets the same source commit. Unexpected assets block publication.
- A same-week draft targeting a different commit is never overwritten. A maintainer must inspect and deliberately resolve that draft before retrying.
- The workflow attaches every asset to a draft, generates the provenance attestation, and only then publishes. This follows GitHub's immutable-release publication guidance.
- Dataset releases are not marked as the repository's latest software release.

If a run reports that a published release is not immutable, stop later releases, correct the repository setting, and review that mutable release before retrying. Immutability cannot be applied retroactively.

## Consumer verification

After downloading all three assets into one directory:

```sh
sha256sum --check SHA256SUMS
gh attestation verify radar-data-YYYY-Www.tar.gz --repo Hecavex/hecavex-radar
gh attestation verify radar-data-YYYY-Www.manifest.json --repo Hecavex/hecavex-radar
```

The checksum establishes byte integrity. The GitHub attestation binds those bytes to the repository workflow and source revision. Neither mechanism validates third-party observations or changes the terms in [`DATA-LICENSE.md`](../DATA-LICENSE.md).
