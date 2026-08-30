# Performance budgets

These budgets protect the production experience at [radar.hecavex.com](https://radar.hecavex.com). The HECAVEX maintainer gate, `pnpm check`, builds the service and measures its checked-in first-party output with deterministic level-9 gzip compression, catching asset and data growth without depending on a network, Lighthouse, or a variable benchmark connection.

The Python publisher separately limits each public live/history JSON artifact to 512 KiB uncompressed and the expanded STIX 2.1 projection to 2 MiB. Lazy signal-detail sidecars are limited to 16 KiB each and 3 MiB for the complete published set. The build gate cross-checks every `detailAvailable` signal against its exact sidecar path, rejects missing and orphan files, validates the bounded schemas, proves that STIX contains exactly one Domain Name and one linked Observed Data object per live row, and measures the complete generated tree against the total-output budget.

| Artifact | Budget | 2026-08-30 baseline |
| --- | ---: | ---: |
| Each HTML entry | 512 KiB gzip | 41,719 bytes gzip |
| Each JavaScript file | 225 KiB gzip | 62,520 bytes gzip |
| Each stylesheet | 48 KiB gzip | 13,119 bytes gzip |
| All JavaScript and CSS combined | 320 KiB gzip | 186,064 bytes gzip |
| Each public JSON data file | 1 MiB gzip | 16,088 bytes gzip |
| Each signal-detail sidecar | 16 KiB raw | 2,450 bytes raw |
| All signal-detail sidecars | 3 MiB raw | 163,337 bytes raw across 128 files |
| STIX 2.1 Bundle | 2 MiB raw | 175,943 bytes raw |
| Entire uncompressed `dist/` tree | 32 MiB | 16,475,175 bytes |

The verifier partitions every byte in the production tree exactly once into four raw deployment-capacity classes. Bilingual signal pages receive 12 MiB, bilingual brand pages 4 MiB, the data-heavy changes, trends, associations, tools, and dataset route pairs 8 MiB, and every remaining file 8 MiB. The four ceilings sum exactly to the authoritative 32 MiB tree gate. Consequently, new signals, brands, routes, and larger embedded bootstraps consume a finite checked allocation instead of escaping a fixed-file estimate; any tree that passes all four class ceilings is proven to fit the deployment gate even as dynamic page counts grow.

Baseline measured on 2026-08-30 with the checked-in datasets and level-9 gzip:

| Measurement | Current |
| --- | ---: |
| Entire uncompressed `dist/` tree | 16,475,175 bytes |
| Largest HTML (`lt/pokyciai/index.html`) | 41,719 bytes gzip |
| Largest JavaScript (`assets/styles-BvMHKSJ_.js`) | 62,520 bytes gzip |
| Largest stylesheet (`assets/styles-NREVqccT.css`) | 13,119 bytes gzip |
| All JavaScript and CSS | 186,064 bytes gzip |
| Largest public JSON (`data/radar.stix.json`) | 16,088 bytes gzip |
| Signal-detail sidecars | 163,337 bytes across 128 files |
| Signal-page capacity | 7,773,715 / 12,582,912 bytes |
| Brand-page capacity | 1,882,642 / 4,194,304 bytes |
| Paired static-data page capacity | 3,591,805 / 8,388,608 bytes |
| Remaining-output capacity | 3,227,013 / 8,388,608 bytes |

Hashed asset names may change when their content changes; the verification output records the current largest file on every run. Sidecars are fetched only when requested and are not embedded into HTML, while every generated page and sidecar still belongs to exactly one raw capacity class. The separately measured complete `dist/` tree must also remain below 32 MiB.

The HTML allowance covers the no-JavaScript, safely encoded snapshot used for hydration. The combined script/style gate is the primary interaction-cost guard. Font files remain covered by the total-output budget and separate integrity/size checks.

A budget increase requires a written reason in the change that introduces it. Prefer reducing data bootstrap size, splitting non-critical code, or removing unused assets before raising a threshold. These file-size gates complement the existing keyboard, responsive overflow, CSP, serious WCAG, and no-JavaScript checks; they do not claim to measure field Core Web Vitals.
