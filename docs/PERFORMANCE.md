# Performance budgets

These budgets protect the production experience at [radar.hecavex.com](https://radar.hecavex.com). The HECAVEX maintainer gate, `pnpm check`, builds the service and measures its checked-in first-party output with deterministic level-9 gzip compression, catching asset and data growth without depending on a network, Lighthouse, or a variable benchmark connection.

The Python publisher separately limits each public live/history JSON artifact to 512 KiB uncompressed. Lazy signal-detail sidecars are limited to 16 KiB each and 3 MiB for the complete published set. The build gate cross-checks every `detailAvailable` signal against its exact sidecar path, rejects missing and orphan files, validates the bounded schema, and proves that the two maximum hydrated artifacts, the maximum sidecar set, and fixed site assets still fit the total-output budget.

| Artifact | Budget | 2026-08-25 baseline |
| --- | ---: | ---: |
| Each HTML entry | 512 KiB gzip | 10,437 bytes gzip |
| Each JavaScript file | 225 KiB gzip | 61,461 bytes gzip |
| Each stylesheet | 48 KiB gzip | 9,218 bytes gzip |
| All JavaScript and CSS combined | 320 KiB gzip | 103,764 bytes gzip |
| Each public JSON data file | 1 MiB gzip | 2,038 bytes gzip |
| Each signal-detail sidecar | 16 KiB raw | 0 bytes (no sidecars in baseline) |
| All signal-detail sidecars | 3 MiB raw | 0 bytes (no sidecars in baseline) |
| Entire uncompressed `dist/` tree | 8 MiB | 953,458 bytes |

With both live/history artifacts at their maximum accepted 512 KiB raw size and the sidecar set at its 3 MiB limit, the conservative prerender expansion proof is 8,278,524 bytes. This remains below the 8 MiB complete-output ceiling and is checked on every build.

Baseline measured on 2026-08-25 with the checked-in datasets and level-9 gzip:

| Measurement | Current |
| --- | ---: |
| Entire uncompressed `dist/` tree | 953,458 bytes |
| Largest HTML (`docs/index.html`) | 10,437 bytes gzip |
| Largest JavaScript (`assets/styles-Di5b9uHI.js`) | 61,461 bytes gzip |
| Largest stylesheet (`assets/styles-DX-_2j_H.css`) | 9,218 bytes gzip |
| All JavaScript and CSS | 103,764 bytes gzip |
| Largest public JSON (`data/radar.json`) | 2,038 bytes gzip |
| Signal-detail sidecars | 0 bytes |
| Proven output with both public artifacts and all sidecars at their caps | 8,278,524 bytes |

Hashed asset names may change when their content changes; the verification output records the current largest file on every run. The maximum proof conservatively counts the current hydration HTML plus three encoded bytes for every possible input byte. Sidecars are fetched only when requested and are not embedded into HTML, so the proof replaces their current measured bytes with the 3 MiB set allowance rather than counting both. Accepted public artifacts therefore cannot deterministically exceed the 8 MiB tree budget with the current fixed assets.

The HTML allowance covers the no-JavaScript, safely encoded snapshot used for hydration. The combined script/style gate is the primary interaction-cost guard. Font files remain covered by the total-output budget and separate integrity/size checks.

A budget increase requires a written reason in the change that introduces it. Prefer reducing data bootstrap size, splitting non-critical code, or removing unused assets before raising a threshold. These file-size gates complement the existing keyboard, responsive overflow, CSP, serious WCAG, and no-JavaScript checks; they do not claim to measure field Core Web Vitals.
