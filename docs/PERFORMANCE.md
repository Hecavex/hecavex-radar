# Performance budgets

These budgets protect the production experience at [radar.hecavex.com](https://radar.hecavex.com). The HECAVEX maintainer gate, `pnpm check`, builds the service and measures its checked-in first-party output with deterministic level-9 gzip compression, catching asset and data growth without depending on a network, Lighthouse, or a variable benchmark connection.

The Python publisher separately limits each public live/history JSON artifact to 512 KiB uncompressed and the expanded STIX 2.1 projection to 2 MiB. Lazy signal-detail sidecars are limited to 16 KiB each and 3 MiB for the complete published set. The build gate cross-checks every `detailAvailable` signal against its exact sidecar path, rejects missing and orphan files, validates the bounded schemas, proves that STIX contains exactly one Domain Name and one linked Observed Data object per live row, and confirms that all maximum artifacts plus fixed site assets fit the total-output budget.

| Artifact | Budget | 2026-08-25 baseline |
| --- | ---: | ---: |
| Each HTML entry | 512 KiB gzip | 12,879 bytes gzip |
| Each JavaScript file | 225 KiB gzip | 61,461 bytes gzip |
| Each stylesheet | 48 KiB gzip | 9,540 bytes gzip |
| All JavaScript and CSS combined | 320 KiB gzip | 106,096 bytes gzip |
| Each public JSON data file | 1 MiB gzip | 3,281 bytes gzip |
| Each signal-detail sidecar | 16 KiB raw | 884 bytes raw |
| All signal-detail sidecars | 3 MiB raw | 8,994 bytes raw across 12 files |
| STIX 2.1 Bundle | 2 MiB raw | 24,713 bytes raw |
| Entire uncompressed `dist/` tree | 11 MiB | 1,062,137 bytes |

The conservative proof replaces the current live, history, STIX, hydration HTML, and sidecar sizes with their maximum accepted values while retaining only fixed assets at measured size. This remains below the 11 MiB complete-output ceiling and is checked on every build.

Baseline measured on 2026-08-25 with the checked-in datasets and level-9 gzip:

| Measurement | Current |
| --- | ---: |
| Entire uncompressed `dist/` tree | 1,062,137 bytes |
| Largest HTML (`index.html`) | 12,879 bytes gzip |
| Largest JavaScript (`assets/styles-CaLSV8c2.js`) | 61,461 bytes gzip |
| Largest stylesheet (`assets/styles-C4TkEW3t.css`) | 9,540 bytes gzip |
| All JavaScript and CSS | 106,096 bytes gzip |
| Largest public JSON (`data/radar.json`) | 3,281 bytes gzip |
| Signal-detail sidecars | 8,994 bytes across 12 files |
| Proven output with live, history, STIX, and all sidecars at their caps | 10,435,503 bytes |

Hashed asset names may change when their content changes; the verification output records the current largest file on every run. The maximum proof conservatively counts the current hydration HTML plus three encoded bytes for every possible input byte. Sidecars are fetched only when requested and are not embedded into HTML, so the proof replaces their current measured bytes with the 3 MiB set allowance rather than counting both. Accepted public artifacts therefore cannot deterministically exceed the 11 MiB tree budget with the current fixed assets.

The HTML allowance covers the no-JavaScript, safely encoded snapshot used for hydration. The combined script/style gate is the primary interaction-cost guard. Font files remain covered by the total-output budget and separate integrity/size checks.

A budget increase requires a written reason in the change that introduces it. Prefer reducing data bootstrap size, splitting non-critical code, or removing unused assets before raising a threshold. These file-size gates complement the existing keyboard, responsive overflow, CSP, serious WCAG, and no-JavaScript checks; they do not claim to measure field Core Web Vitals.
