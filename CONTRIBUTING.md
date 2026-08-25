# HECAVEX Radar change policy

This repository maintains the production service at [radar.hecavex.com](https://radar.hecavex.com). It is not a starter template or supported self-hosting product. HECAVEX reviews changes according to the live service's safety, provenance, privacy, accessibility, and operational requirements.

Corrections to published data, brand mappings, documentation, or accessibility can be reported through an issue when they contain no sensitive material. Large behavioral or data-contract proposals should be discussed before implementation. Vulnerabilities, credentials, victim data, and sensitive indicators must follow the private process in [SECURITY.md](SECURITY.md).

## Change requirements

1. Keep the public service read-only and static. Do not add accounts, submissions, browser-side indicator requests, or an administration endpoint.
2. Never commit live credentials, private collector code, proprietary scoring logic, internal HECAVEX history, analyst notes, or victim data. Public defanged observations may use only the documented archive schemas.
3. Preserve passive collection boundaries: Radar reads certificate names and existing public URLScan reports; it does not visit candidate hosts or submit URLs for scanning.
4. Use reserved `.test`, `.example`, and documentation IP ranges in examples and validation data.
5. Run the complete gate before a change is approved: `pnpm check`.

## Maintainer environment

Local execution exists only to develop and verify changes destined for the HECAVEX-operated service. It does not reproduce production source access, schedules, private review state, DNS, or HECAVEX operation.

The maintained toolchains are Python 3.12, Node.js 22.22.2 or newer on the supported lines in `package.json`, and pnpm 10. After creating an isolated Python environment:

```sh
python -m pip install -e ".[dev]"
corepack enable
pnpm install
pnpm check
```

The application and Python tools read process environment variables directly; `.env.example` is an operator reference and is not loaded automatically. Never copy credentials into tracked files.

Contributions to original repository code and documentation are accepted under the Apache License 2.0. HECAVEX branding and operation of the production service are separate from that software license.
