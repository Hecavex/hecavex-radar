# Performance budgets

These budgets protect the production experience at [radar.hecavex.com](https://radar.hecavex.com). The HECAVEX maintainer gate, `pnpm check`, builds the service and measures its checked-in first-party output with deterministic level-9 gzip compression, catching asset and data growth without depending on a network, Lighthouse, or a variable benchmark connection.

The Python publisher separately limits each public live/history JSON artifact to 512 KiB uncompressed and the expanded STIX 2.1 projection to 2 MiB. Lazy signal-detail sidecars are limited to 16 KiB each and 3 MiB for the complete published set. The build gate cross-checks every `detailAvailable` signal against its exact sidecar path, rejects missing and orphan files, validates the bounded schemas, proves that STIX contains exactly one Domain Name and one linked Observed Data object per live row, and measures the complete generated tree against the total-output budget.

| Artifact | Budget | 2026-08-30 baseline |
| --- | ---: | ---: |
| Each HTML entry | 512 KiB gzip | 40,954 bytes gzip |
| Each JavaScript file | 225 KiB gzip | 62,520 bytes gzip |
| Each stylesheet | 48 KiB gzip | 13,119 bytes gzip |
| All JavaScript and CSS combined | 320 KiB gzip | 185,387 bytes gzip |
| Each public JSON data file | 1 MiB gzip | 15,695 bytes gzip |
| Each signal-detail sidecar | 16 KiB raw | 2,450 bytes raw |
| All signal-detail sidecars | 3 MiB raw | 160,915 bytes raw across 125 files |
| STIX 2.1 Bundle | 2 MiB raw | 171,807 bytes raw |
| Entire uncompressed `dist/` tree | 32 MiB | 16,166,392 bytes |

The verifier also reports a bounded-artifact scenario that replaces the current live, history, STIX, hydration HTML, and sidecar sizes with their accepted limits while retaining other generated output at measured size. Its current estimate is 25,038,436 bytes. This is diagnostic rather than a maximum-capacity proof because the number and size of prerendered signal and brand pages can grow independently. The measured 32 MiB complete-tree gate is authoritative. It was raised because permanent bilingual records deliberately grow the static Pages artifact; per-file and compressed asset gates remain the visitor-facing performance controls.

Baseline measured on 2026-08-30 with the checked-in datasets and level-9 gzip:

| Measurement | Current |
| --- | ---: |
| Entire uncompressed `dist/` tree | 16,166,392 bytes |
| Largest HTML (`lt/pokyciai/index.html`) | 40,954 bytes gzip |
| Largest JavaScript (`assets/styles-BvMHKSJ_.js`) | 62,520 bytes gzip |
| Largest stylesheet (`assets/styles-NREVqccT.css`) | 13,119 bytes gzip |
| All JavaScript and CSS | 185,387 bytes gzip |
| Largest public JSON (`data/radar.stix.json`) | 15,695 bytes gzip |
| Signal-detail sidecars | 160,915 bytes across 125 files |
| Bounded-artifact scenario | 25,038,436 bytes |

Hashed asset names may change when their content changes; the verification output records the current largest file on every run. The scenario counts the current hydration HTML plus three encoded bytes for every possible input byte. Sidecars are fetched only when requested and are not embedded into HTML, so it replaces their current measured bytes with the 3 MiB set allowance rather than counting both. The separately measured complete `dist/` tree must always remain below 32 MiB.

The HTML allowance covers the no-JavaScript, safely encoded snapshot used for hydration. The combined script/style gate is the primary interaction-cost guard. Font files remain covered by the total-output budget and separate integrity/size checks.

A budget increase requires a written reason in the change that introduces it. Prefer reducing data bootstrap size, splitting non-critical code, or removing unused assets before raising a threshold. These file-size gates complement the existing keyboard, responsive overflow, CSP, serious WCAG, and no-JavaScript checks; they do not claim to measure field Core Web Vitals.
