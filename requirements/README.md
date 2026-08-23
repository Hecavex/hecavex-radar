# Production Python automation locks

These files support HECAVEX's scheduled `radar.hecavex.com` workflows and CI; they are not a general installation matrix.

The two hash-locked requirement sets target Python 3.12 on the Ubuntu GitHub Actions runners:

- `automation-runtime-py312.lock` is the minimal environment used by scheduled collectors and the snapshot publisher.
- `automation-ci-py312.lock` adds linting, type-checking, and test tools for CI.

The checked-out HECAVEX Radar package is installed separately with dependency resolution and build isolation disabled. Its direct and build dependencies are therefore supplied by the reviewed lock before the package is built.

To refresh a lock, run `uv pip compile` 0.12.5 with `--python-version 3.12`, `--python-platform x86_64-unknown-linux-gnu`, and `--generate-hashes`, then run `pip-audit` against both resulting files and the full project checks. Keep the `.in` files and `pyproject.toml` aligned in the same change.
