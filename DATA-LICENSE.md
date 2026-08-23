# Data licensing and attribution

The Apache License 2.0 covers original HECAVEX Radar software and documentation. It does not relicense third-party data, trademarks, screenshots, or source material, and it does not designate modified copies as a HECAVEX-operated service.

Records published by [radar.hecavex.com](https://radar.hecavex.com) use only the source labels CertStream, URLScan, and HECAVEX, and the snapshot includes those source homepages. Third-party discovery lists are transient search inputs: they cannot create a dashboard row, are not copied into the archives, and are never relabeled as HECAVEX. HECAVEX operators remain responsible for the current access, attribution, redistribution, and rate-limit terms of every enabled service input.

## Source-specific notes

- **Certificate Transparency / CertStream:** certificate observations are public CT facts. The Radar matcher and collector are Apache-2.0. The scheduled workflow runs [`reloading01/certstream-server-rust`](https://github.com/reloading01/certstream-server-rust), which is separately distributed under the [MIT license](https://github.com/reloading01/certstream-server-rust/blob/main/LICENSE); CT-log software and services retain their own terms.
- **URLScan:** report metadata, screenshots, and hashes remain subject to URLScan's terms and depicted-site rights. Before enabling or changing URLScan publication on the live service, HECAVEX must confirm that the account and plan permit the intended automated access, display, and redistribution; an API key alone does not grant those rights.
- **[PhishDestroy Primary Active](https://github.com/phishdestroy/destroylist):** used only as a transient discovery seed under its [MIT license](https://github.com/phishdestroy/destroylist/blob/main/LICENSE). Copyright (c) 2019 PhishDestroy. Raw list rows are not copied; a domain may appear later only after independent URLScan validation.
- **[CERT Polska Warning List](https://hole.cert.pl/):** used only as a transient discovery seed under the processing permission stated in its [public API specification](https://hole.cert.pl/schema/certpl_lista_ostrzezen_api_v2.pdf). Raw list rows are not copied; a domain may appear later only after independent URLScan validation.
- **HECAVEX export:** only observations from an explicitly configured public export may enter this repository, and every row is automatically validated before publication. The exporter remains responsible for excluding private history, proprietary evidence, credentials, and personal data.
- **Screenshots:** remain subject to URLScan's terms and depicted-site rights. The publisher accepts screenshots only from HTTPS on exactly `urlscan.io`, never a subdomain.

Brand names and domains in `data/brands-lt.json` identify their owners and do not imply endorsement. Each registry entry must cite an authoritative public source.

To report a false positive, sensitive path value, attribution problem, or removal request, email [info@hecavex.com](mailto:info@hecavex.com).
