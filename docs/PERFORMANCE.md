# Performance budgets

`pnpm check` builds the production site and measures its checked-in first-party output with deterministic level-9 gzip compression. These budgets catch asset and data growth without depending on a network, a Lighthouse service, or a variable test connection.

The Python publisher separately limits each public live/history JSON artifact to 512 KiB uncompressed. The build gate verifies that those two maximum artifacts, their worst-case percent-encoded hydration copies, and the current fixed site assets still fit the total-output budget.

| Artifact | Budget | 2026-08-22 baseline |
| --- | ---: | ---: |
| Each HTML entry | 512 KiB gzip | 9,323 bytes gzip |
| Each JavaScript file | 225 KiB gzip | 61,178 bytes gzip |
| Each stylesheet | 48 KiB gzip | 8,115 bytes gzip |
| All JavaScript and CSS combined | 320 KiB gzip | 98,068 bytes gzip |
| Each public JSON data file | 1 MiB gzip | 1,580 bytes gzip |
| Entire uncompressed `dist/` tree | 8 MiB | 901,795 bytes |

With both live/history artifacts at their maximum accepted 512 KiB raw size, the conservative prerender expansion proof
is 5,086,068 bytes. This remains below the 8 MiB complete-output ceiling and is checked on every build.

Baseline measured on 2026-08-22 with the checked-in datasets and level-9 gzip:

| Measurement | Current |
| --- | ---: |
| Entire uncompressed `dist/` tree | 901,795 bytes |
| Largest HTML (`docs/index.html`) | 9,323 bytes gzip |
| Largest JavaScript (`assets/styles-DI2iS-cD.js`) | 61,178 bytes gzip |
| Largest stylesheet (`assets/styles-CKysED8U.css`) | 8,115 bytes gzip |
| All JavaScript and CSS | 98,068 bytes gzip |
| Largest public JSON (`data/radar.json`) | 1,580 bytes gzip |
| Proven output with both public artifacts at the 512 KiB cap | 5,086,068 bytes |

Hashed asset names may change when their content changes; the verification output records the current largest file on every run. The maximum proof conservatively counts the current hydration HTML plus three encoded bytes for every possible input byte, so accepted public artifacts cannot deterministically exceed the 8 MiB tree budget with the current fixed assets.

The HTML allowance covers the no-JavaScript, safely encoded snapshot used for hydration. The combined script/style gate is the primary interaction-cost guard. Font files remain covered by the total-output budget and separate integrity/size checks.

A budget increase requires a written reason in the change that introduces it. Prefer reducing data bootstrap size, splitting non-critical code, or removing unused assets before raising a threshold. These file-size gates complement the existing keyboard, responsive overflow, CSP, serious WCAG, and no-JavaScript checks; they do not claim to measure field Core Web Vitals.
