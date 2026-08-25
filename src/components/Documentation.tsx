const signalFields = [
  ["id", "string", "First 20 hexadecimal characters of SHA-256 over the normalized defanged hostname."],
  ["url", "string", "Defanged HTTP(S) indicator. Userinfo is rejected; query and fragment are removed; unsafe paths are redacted."],
  ["domain", "string", "Defanged normalized hostname."],
  ["firstSeen", "UTC timestamp", "Earliest accepted observation in canonical millisecond form."],
  ["lastSeen", "UTC timestamp", "Latest accepted observation in canonical millisecond form."],
  ["sources", "string[]", "Deduplicated providers: CertStream, URLScan, or HECAVEX."],
  ["status", "enum", "active, suspected, offline, mitigated, or unknown."],
  ["brand", "string | null", "Registry-resolved claimed target; this is not actor attribution."],
  ["country", "string | null", "Hosting observation, not an actor location."],
  ["host", "string | null", "Provider/ASN text or a defanged address."],
  ["screenshotUrl", "string | null", "Optional HTTPS screenshot on exactly urlscan.io."],
  ["referenceUrl", "string | null", "Optional canonical public URLScan result URL."],
  ["hashes", "string[]", "Up to eight lowercase SHA-256 hashes of primary HTML response bodies."],
  ["reasonCodes", "string[]", "Controlled publication reasons; provenance labels, not proof or a verdict."],
  ["detailAvailable", "true (optional)", "Declares one validated same-origin detail sidecar for this signal."],
  ["confidence", "integer", "Rounded and clamped score from 0 to 100; not a probability."],
] as const;

const workflows = [
  ["Continuous integration", "Pull requests and relevant pushes", "Lint, type checks, production build, and site verification"],
  ["CertStream collection", "08, 23, 38, and 53 minutes past each UTC hour", "Candidate archive and latest public attempt health"],
  ["URLScan hunt", "37 minutes past every second UTC hour", "Bounded hunt state and Vilnius-date validated archive"],
  ["Snapshot synchronization", "17 minutes past each UTC hour", "Validated live snapshot and candidate history"],
  ["Pages deployment", "Verified code or changed public snapshot/health", "Static GitHub Pages artifact"],
] as const;

const settings = [
  ["URLSCAN_API_KEY", "Secret", "Required only for passive URLScan search and result retrieval."],
  ["URLSCAN_RADAR_SEEDS_ENABLED", "Variable", "Includes bounded recent snapshot rows in the rolling seven-day candidate set."],
  ["URLSCAN_SEED_ROTATION_SHARDS", "Variable", "Uses one complete bounded candidate slice by default; operators may lower the slice."],
  ["URLSCAN_SEEDS_PER_RUN", "Variable", "Selects no more than 250 exact-domain seeds per run by default."],
  ["URLSCAN_DAILY_SEARCH_CAP", "Variable", "Conservative local UTC-day search guard; 900 successful responses by default."],
  ["URLSCAN_DAILY_RESULT_CAP", "Variable", "Conservative local UTC-day result guard; 8,000 successful responses by default."],
  ["URLSCAN_RUN_SEARCH_CAP / URLSCAN_RUN_RESULT_CAP", "Variables", "Per-run guards of 25 searches and 100 result retrievals by default."],
  ["CERTSTREAM_URL", "Secret or variable", "Optional monitored WSS endpoint; otherwise the scheduled workflow starts its pinned temporary source."],
  ["HECAVEX_ENABLED", "Variable", "Enables the optional configured public HECAVEX export."],
  ["HECAVEX_FEED_URL", "Secret", "Required with HECAVEX enabled; production endpoints must use HTTPS."],
  ["HECAVEX_FEED_TOKEN", "Secret", "Optional read-only bearer credential for the configured export."],
  ["RADAR_HISTORY_DETAIL_DAYS", "Variable", "Detailed event retention; 30 days by default, bounded from 7 to 90."],
  ["RADAR_HISTORY_SUMMARY_DAYS", "Variable", "Compacted history retention; 730 days by default, bounded from 30 to 3,650."],
  ["RADAR_HISTORY_MAX_SIGNALS", "Variable", "Maximum public history rows; 5,000 by default, bounded from 1 to 25,000."],
] as const;

const sourceStates = [
  ["healthy", "The snapshot publisher read that source archive successfully. Zero records is a valid empty result."],
  ["partial", "The latest archive refresh was incomplete. A shown timestamp can identify the previous successful read, and recent rows may be retained."],
  ["skipped", "An optional deployment input was not configured or attempted."],
] as const;

export function Documentation() {
  return (
    <article className="docs-content" aria-labelledby="documentation-title">
      <header className="docs-heading">
        <div>
          <p className="eyebrow">Core documentation</p>
          <h1 id="documentation-title">HECAVEX Radar technical reference</h1>
        </div>
        <p>
          Architecture, source behavior, public schemas, operating requirements, and data terms for the HECAVEX-operated
          service at radar.hecavex.com. Detection methodology is documented separately on the{" "}
          <a href="/methodology/">Methodology page</a>.
        </p>
      </header>

      <nav className="docs-toc" aria-label="Documentation sections">
        <span>Contents</span>
        <div>
          <a href="#architecture">Architecture</a>
          <a href="#sources">Sources</a>
          <a href="#public-data">Public data</a>
          <a href="#data-contract">Data contract</a>
          <a href="#history-review">History and review</a>
          <a href="#operations">Operations</a>
          <a href="#security">Security</a>
          <a href="#data-terms">Data terms</a>
        </div>
      </nav>

      <section className="docs-section" id="architecture" aria-labelledby="architecture-title">
        <div className="docs-section-heading">
          <p className="eyebrow">Architecture</p>
          <h2 id="architecture-title">Python pipeline, static viewer</h2>
          <p>The browser has no application server, account system, or database connection.</p>
        </div>
        <ol className="docs-flow" aria-label="Radar data flow">
          <li>
            <span>01</span>
            <h3>Collect</h3>
            <p>Bounded Python collectors read passive certificate events and existing public reports.</p>
          </li>
          <li>
            <span>02</span>
            <h3>Archive</h3>
            <p>Validated, defanged source observations are stored in date-partitioned NDJSON.</p>
          </li>
          <li>
            <span>03</span>
            <h3>Synchronize</h3>
            <p>The publisher revalidates, scopes, merges, limits, sorts, and atomically writes live, detail, and history data.</p>
          </li>
          <li>
            <span>04</span>
            <h3>Render</h3>
            <p>A static React application validates the snapshot structure and renders read-only controls.</p>
          </li>
        </ol>
        <div className="docs-callout">
          <strong>Publication boundary</strong>
          <p>
            Only synchronization writes the public snapshot. An unavailable optional source cannot erase healthy-source
            data, and an unexpected sharp reduction is blocked unless an operator explicitly authorizes a reset.
          </p>
        </div>
      </section>

      <section className="docs-section" id="sources" aria-labelledby="sources-title">
        <div className="docs-section-heading">
          <p className="eyebrow">Sources and provenance</p>
          <h2 id="sources-title">Three public observation labels</h2>
          <p>
            Only normalized observations that pass the publication boundary become dashboard rows. Transient search hints
            can trigger investigation, but cannot create or label a row by themselves.
          </p>
        </div>
        <div className="docs-card-grid">
          <article>
            <span>Certificate names and bounded leaf metadata</span>
            <h3>CertStream</h3>
            <p>
              Emits Certificate Transparency updates over a websocket. Radar reads DNS names, rejects official domains,
              applies its public matcher, and archives qualifying candidates without retrieving those domains. The lite
              stream can add sanitized validity, issuer, fingerprint, and same-registrable certificate-name context.
            </p>
            <a href="https://certstream.dev/docs.html">Provider documentation</a>
          </article>
          <article>
            <span>Existing public scans</span>
            <h3>URLScan</h3>
            <p>
              Authenticated passive searches require public visibility in both the search summary and result detail.
              Queries cover the rolling previous seven days. Exact-domain, brand, title, and primary-document hash pivots
              remain bounded and independently validated. Accepted reports can add same-host page, network, provider-score,
              and TLS context; Radar never submits a scan or visits a candidate host.
            </p>
            <a href="https://urlscan.io/docs/api/">Provider documentation</a>
          </article>
          <article>
            <span>Optional service input</span>
            <h3>HECAVEX</h3>
            <p>
              A deliberately limited public JSON export can be configured over HTTPS. Every record passes the same
              normalization, brand scope, evidence, timestamp, and size checks before it can appear publicly.
            </p>
            <a href="https://hecavex.com/">HECAVEX</a>
          </article>
          <article>
            <span>Search hints only</span>
            <h3>Transient discovery inputs</h3>
            <p>
              Bounded third-party lists are processed in memory and can trigger exact passive URLScan lookups. Raw rows
              are not archived, do not publish directly, and never appear as public source labels.
            </p>
            <a href="#data-terms">Attribution and terms</a>
          </article>
        </div>
        <div className="docs-callout">
          <strong>Coverage is intentionally incomplete</strong>
          <p>
            CertStream observation is sampled. URLScan is queried only for existing public reports; no result is unknown,
            not benign, and does not suppress an independently qualifying CertStream candidate. HECAVEX is optional.
            None of these inputs provides a continuous-monitoring guarantee.
          </p>
        </div>
      </section>

      <section className="docs-section" id="public-data" aria-labelledby="public-data-title">
        <div className="docs-section-heading">
          <p className="eyebrow">Public data catalogue</p>
          <h2 id="public-data-title">Deliberately published datasets</h2>
          <p>
            These resources are intended for defensive use and public retrieval. Candidate links remain defanged; raw
            provider inputs, credentials, private observations, and quarantined material are not part of this catalogue.
          </p>
        </div>
        <div className="docs-card-grid">
          <article>
            <span>Current snapshot · JSON</span>
            <h3>Radar signal snapshot</h3>
            <p>
              The generated dashboard input contains the current schema version, generation time, bounded recent signals,
              and per-source archive-read state. It is crawlable because it is advertised as the Dataset distribution.
            </p>
            <a href="/data/radar.json">Open public radar.json</a>
          </article>
          <article>
            <span>Retained history · JSON</span>
            <h3>Candidate history</h3>
            <p>
              A bounded projection of accepted observation boundaries and explicit source status transitions. A missing
              row never means benign, and disappearance from a current archive does not create an offline event.
            </p>
            <a href="/data/history.json">Open public history.json</a>
          </article>
          <article>
            <span>Reviewed registry · JSON</span>
            <h3>Lithuanian brand registry</h3>
            <p>
              Reviewed aliases, opt-in fuzzy aliases, official domains, collision exclusions, and supporting references
              used by the public matcher. Repository history records changes and review context.
            </p>
            <a href="https://github.com/Hecavex/hecavex-radar/blob/main/data/brands-lt.json">Open the registry</a>
          </article>
          <article>
            <span>Latest attempt · JSON</span>
            <h3>CertStream collection health</h3>
            <p>
              Actual start, end, websocket listening seconds, aggregate input and match counts, outcome, schedule delay,
              last success, and freshness. It contains no certificate names or unpublished candidates.
            </p>
            <a href="/data/collection-health.json">Open public collection-health.json</a>
          </article>
          <article>
            <span>Lazy context · JSON</span>
            <h3>Per-signal detail sidecars</h3>
            <p>
              A live row can declare one exact same-origin sidecar containing at most one latest CertStream and URLScan
              context record. The viewer fetches it only when evidence is opened; each file is 16 KiB or less and the
              complete set is capped at 3 MiB.
            </p>
          </article>
        </div>
        <div className="docs-callout">
          <strong>Freshness</strong>
          <p>
            Consumers must read <code>lastSuccessfulSyncAt</code> for publisher health, <code>generatedAt</code> for the
            latest material data change, and each source&apos;s <code>fetchedAt</code> and <code>state</code>. A source timestamp
            is an archive-read time. CertStream connection evidence is reported separately in the bounded
            collection-health document and still does not prove continuous coverage.
          </p>
        </div>
      </section>

      <section className="docs-section" id="data-contract" aria-labelledby="contract-title">
        <div className="docs-section-heading">
          <p className="eyebrow">Public data contract</p>
          <h2 id="contract-title">Snapshot schema version 1</h2>
          <p>The Python publisher is normative; browser validation is an additional structural check.</p>
        </div>
        <pre className="docs-code" aria-label="Public snapshot example" tabIndex={0}><code>{`{
  "schemaVersion": 1,
  "dataset": "live",
  "generatedAt": "2026-08-21T09:15:00.000Z",
  "lastSuccessfulSyncAt": "2026-08-21T10:17:00.000Z",
  "signals": [],
  "sources": []
}`}</code></pre>
        <p className="docs-copy">
          Public timestamps use canonical UTC millisecond form. Before publication, retained and newly collected rows are
          checked against the current Lithuanian brand registry; official hosts, unresolved brands, exclusions, and
          conflicting brand mappings are dropped.
        </p>
        <h3 className="docs-subheading">Signal fields</h3>
        <div className="docs-table-wrap" role="region" aria-label="Signal field reference" tabIndex={0}>
          <table className="docs-table">
            <thead><tr><th scope="col">Field</th><th scope="col">Type</th><th scope="col">Meaning</th></tr></thead>
            <tbody>
              {signalFields.map(([field, type, meaning]) => (
                <tr key={field}><th scope="row"><code>{field}</code></th><td>{type}</td><td>{meaning}</td></tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="docs-card-grid docs-archive-grid">
          <article>
            <span>Archive schema 1</span>
            <h3>CertStream NDJSON</h3>
            <p>
              Stored under <code>data/certstream/YYYY-MM-DD/domains.ndjson</code>. Each row carries observed time,
              defanged and registrable domains, brand, confidence, and bounded public scoring reasons.
            </p>
          </article>
          <article>
            <span>Archive schema 2</span>
            <h3>URLScan NDJSON</h3>
            <p>
              Stored under <code>data/urlscan/YYYY-MM-DD/signals.ndjson</code>. Typed brand evidence can be domain, title,
              verdict, or supplemental primary-HTML-hash provenance; a hash alone cannot bind a brand.
            </p>
          </article>
          <article>
            <span>Operational state schema 1</span>
            <h3>URLScan hunt state</h3>
            <p>
              <code>data/urlscan/hunt-state.json</code> records aggregate UTC counters, cursor progress, configuration,
              timestamps, and outcome. It contains no key, domain, or result payload.
            </p>
          </article>
          <article>
            <span>Optional input</span>
            <h3>HECAVEX JSON</h3>
            <p>
              Accepts an array or an object containing <code>signals</code>. Alternate common field names are normalized,
              supplied source labels are ignored, and hashes require explicit primary-HTML SHA-256 typing.
            </p>
          </article>
          <article>
            <span>History schema 1</span>
            <h3>Candidate event NDJSON</h3>
            <p>
              Stored under <code>data/history/daily/YYYY-MM-DD/events.ndjson</code>. Stable event IDs make replay
              idempotent; older detail compacts into a bounded summary without inventing status changes.
            </p>
          </article>
          <article>
            <span>Detail schema 1</span>
            <h3>Signal detail JSON</h3>
            <p>
              Stored below <code>public/data/signals/&lt;prefix&gt;/&lt;id&gt;.json</code>. Exact fields contain bounded,
              defanged page, network, URLScan assessment, redirect-destination, and certificate context only for a current
              live signal. Cross-domain destination metadata is never attributed to the submitted candidate.
            </p>
          </article>
        </div>
        <div className="docs-callout">
          <strong>Merge rules</strong>
          <p>
            One public row represents one normalized host. The publisher unions sources and hashes, keeps earliest and
            latest timestamps, selects the most specific safe path, keeps the highest confidence, and rejects conflicting brands.
          </p>
        </div>
      </section>

      <section className="docs-section" id="history-review" aria-labelledby="history-review-title">
        <div className="docs-section-heading">
          <p className="eyebrow">History and corrections</p>
          <h2 id="history-review-title">Reproducible public trail, private analyst notes</h2>
          <p>
            Radar separates the public candidate record from the operator&apos;s private review material. Neither side can
            turn a matching score into a malicious verdict.
          </p>
        </div>
        <div className="docs-card-grid">
          <article>
            <span>Stable identity</span>
            <h3>Replay does not inflate counts</h3>
            <p>
              Signal IDs derive from normalized hosts. Event IDs derive from immutable observation and transition fields,
              so rerunning unchanged archives cannot add another observation when scoring language changes.
            </p>
          </article>
          <article>
            <span>Bounded retention</span>
            <h3>Detail compacts, boundaries remain</h3>
            <p>
              Daily event partitions retain 30 days by default. Older detail compacts into a two-year summary containing
              first and last observation time, bounded counts, source and reason unions, and explicit transitions.
            </p>
          </article>
          <article>
            <span>Operator trust boundary</span>
            <h3>Private notes never enter Git</h3>
            <p>
              The HECAVEX review CLI writes an append-only SQLite ledger outside this repository. Only an intentional,
              sanitized export of active suppressions and independently matching manual candidates can reach sync.
            </p>
          </article>
        </div>
        <div className="docs-callout">
          <strong>Unknown remains unknown</strong>
          <p>
            A CertStream candidate remains eligible when URLScan has no public result. Manual additions must still match
            the current registry, cannot cross brands, cannot exceed the matcher score, and publish only as suspected.
          </p>
        </div>
        <p className="docs-copy">
          Browse the <a href="/history/">retained candidate trail</a>. Repository operators can review the complete
          retention and operator-export contracts in{" "}
          <a href="https://github.com/Hecavex/hecavex-radar/blob/main/docs/HISTORY.md">HISTORY.md</a> and{" "}
          <a href="https://github.com/Hecavex/hecavex-radar/blob/main/docs/REVIEW-WORKFLOW.md">REVIEW-WORKFLOW.md</a>.
        </p>
      </section>

      <section className="docs-section" id="operations" aria-labelledby="operations-title">
        <div className="docs-section-heading">
          <p className="eyebrow">Operations and deployment</p>
          <h2 id="operations-title">Scheduled GitHub Pages publication</h2>
          <p>Schedules are UTC and can start late. Manual dispatch remains available for collection and synchronization.</p>
        </div>
        <div className="docs-table-wrap" role="region" aria-label="Workflow schedule" tabIndex={0}>
          <table className="docs-table">
            <thead><tr><th scope="col">Workflow</th><th scope="col">Trigger</th><th scope="col">Result</th></tr></thead>
            <tbody>
              {workflows.map(([name, trigger, result]) => (
                <tr key={name}><th scope="row">{name}</th><td>{trigger}</td><td>{result}</td></tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="docs-callout docs-warning-callout">
          <strong>Scheduled does not mean observed</strong>
          <p>
            CertStream is scheduled for 96 eight-minute windows per day: 768 minutes, or at most 53.3% of wall-clock time.
            Actions can start late, drop a schedule, or fail. The dashboard reads actual timing, aggregate counts, outcome, schedule delay,
            last success, and freshness from <a href="/data/collection-health.json">collection-health.json</a>; those fields
            remain separate from archive-read state in <code>radar.json</code>.
          </p>
        </div>
        <div className="docs-callout">
          <strong>Bounded passive URLScan retrieval</strong>
          <p>
            At minute 37 every two hours, Radar attempts exact lookups for all bounded seven-day candidates (at most
            250), while a deterministic cursor preserves progress after an operator-lowered selection or budget stop.
            Defaults permit at most 25 searches and 100 result retrievals per run, and 900 and 8,000 respectively per
            UTC day. Only successful responses enter the local ledger; HTTP 429 ends requests safely. A missing secret
            makes no API call and records a successful <code>skipped-not-configured</code> state.
          </p>
        </div>
        <h3 className="docs-subheading">Source-state semantics</h3>
        <div className="docs-table-wrap" role="region" aria-label="Source state semantics" tabIndex={0}>
          <table className="docs-table">
            <thead><tr><th scope="col">State</th><th scope="col">What it establishes</th></tr></thead>
            <tbody>
              {sourceStates.map(([state, meaning]) => (
                <tr key={state}><th scope="row"><code>{state}</code></th><td>{meaning}</td></tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="docs-copy">
          Historical healthy-empty example: a successful run reviewed under the earlier four-minute configuration on 21 August 2026 listened for 240 seconds and processed
          83,875 messages containing 146,591 DNS names, with zero qualifying matches. That is evidence of one healthy
          empty run—not continuous coverage. The dashboard now presents the latest bounded attempt directly; repository
          operators can still inspect complete execution logs in{" "}
          <a href="https://github.com/Hecavex/hecavex-radar/actions/workflows/collect-certstream.yml">GitHub Actions</a>.
        </p>
        <h3 className="docs-subheading">Repository configuration</h3>
        <div className="docs-table-wrap" role="region" aria-label="Repository configuration" tabIndex={0}>
          <table className="docs-table">
            <thead><tr><th scope="col">Setting</th><th scope="col">Kind</th><th scope="col">Purpose</th></tr></thead>
            <tbody>
              {settings.map(([name, kind, purpose]) => (
                <tr key={name}><th scope="row"><code>{name}</code></th><td>{kind}</td><td>{purpose}</td></tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="docs-operations-grid">
          <article>
            <span>Maintainer gate</span>
            <h3>Every production change is verified</h3>
            <p>
              HECAVEX maintains pinned Python, Node.js, pnpm, and browser-check toolchains. The complete gate covers linting,
              types, the production build, accessibility, CSP, no-JavaScript output, and responsive behavior.
            </p>
          </article>
          <article>
            <span>Custom domain</span>
            <h3>radar.hecavex.com</h3>
            <p>
              GitHub Pages uses a CNAME record named <code>radar</code> pointing to <code>hecavex.github.io</code>. The
              organization domain-verification TXT record should remain in DNS, and HTTPS is enabled after validation.
            </p>
          </article>
          <article>
            <span>Safety controls</span>
            <h3>Untrusted input throughout</h3>
            <p>
              Credentials stay in Actions secrets, workflow permissions are minimal, external Actions are commit-pinned,
              output paths are repository-bounded, and source/archive sizes and record counts are capped.
            </p>
          </article>
        </div>
        <div className="docs-callout">
          <strong>Durable CT coverage decision</strong>
          <p>
            Stage 02 will use checkpointed CT-log/API polling and backfill as the durable coverage source, while retaining
            CertStream for low-latency discovery. The current sampled workflow remains in place until that implementation
            passes the documented acceptance checks. Read the{" "}
            <a href="https://github.com/Hecavex/hecavex-radar/blob/main/docs/decisions/0001-ct-coverage.md">
              architecture decision record
            </a>.
          </p>
        </div>
      </section>

      <section className="docs-section" id="security" aria-labelledby="security-title">
        <div className="docs-section-heading">
          <p className="eyebrow">Security and maintenance</p>
          <h2 id="security-title">Maintained on a best-effort basis</h2>
          <p>
            Radar is a HECAVEX-operated public research service, not a 24/7 SOC, incident-response service,
            brand-monitoring contract, notification service, takedown provider, or availability SLA.
          </p>
        </div>
        <div className="docs-card-grid">
          <article>
            <span>Maintenance state</span>
            <h3>Active · best effort</h3>
            <p>
              Automated workflows publish when their validation gates pass. Source-panel state and snapshot timestamps
              expose what the current data can establish; workflow history remains the operational source of truth.
            </p>
            <a href="https://github.com/Hecavex/hecavex-radar/actions">Review workflow history</a>
          </article>
          <article>
            <span>Responsible reporting</span>
            <h3>Security and sensitive data</h3>
            <p>
              Do not open a public issue for vulnerabilities, credentials, victim data, or sensitive indicators. Use the
              published security contact and avoid contacting a suspected phishing host while reproducing a problem.
            </p>
            <a href="/.well-known/security.txt">Open security.txt</a>
          </article>
          <article>
            <span>Data quality</span>
            <h3>False positives and corrections</h3>
            <p>
              Report a mistaken listing, brand mapping, unsafe value, attribution issue, or removal request by email. A
              listing is always a research lead rather than a public accusation.
            </p>
            <a href="mailto:info@hecavex.com?subject=HECAVEX%20Radar%20false%20positive">Report a false positive</a>
          </article>
          <article>
            <span>Service source</span>
            <h3>Auditable public change record</h3>
            <p>
              Source, workflows, registry references, and issue history are public for transparency. Accepted
              production changes must preserve defanging, passive collection boundaries, provenance, and publication rules.
            </p>
            <a href="https://github.com/Hecavex/hecavex-radar">Review the service source</a>
          </article>
          <article id="privacy-analytics">
            <span>Privacy and analytics</span>
            <h3>Cookieless performance measurement</h3>
            <p>
              Radar uses Cloudflare Web Analytics to measure page views and browser performance. Its beacon does not set
              or read cookies or browser storage, and the loader stops when the browser sends a Do Not Track preference.
              Radar sends no custom analytics events and does not serialize signal rows, indicator text, table searches,
              filter values, or unpublished CTI data into analytics payloads.
            </p>
            <a href="https://hecavex.com/en/privacy/">Read the HECAVEX privacy notice</a>
          </article>
        </div>
      </section>

      <section className="docs-section" id="data-terms" aria-labelledby="terms-title">
        <div className="docs-section-heading">
          <p className="eyebrow">Data terms and attribution</p>
          <h2 id="terms-title">Software licensing does not relicense data</h2>
          <p>
            Apache License 2.0 covers original Radar software and documentation. Third-party observations, trademarks,
            screenshots, and source material retain their own rights and conditions.
          </p>
        </div>
        <div className="docs-terms-list">
          <article>
            <h3>Certificate Transparency</h3>
            <p>Certificate observations are public CT facts. The scheduled server component retains its separate MIT license and upstream terms.</p>
          </article>
          <article>
            <h3>URLScan</h3>
            <p>Report metadata, screenshots, and hashes remain subject to URLScan terms and depicted-site rights. Authentication does not itself grant redistribution rights.</p>
            <a href="https://urlscan.io/terms/">URLScan terms</a>
          </article>
          <article>
            <h3>PhishDestroy</h3>
            <p>Primary Active is used only as a transient discovery seed under its MIT license. Raw list rows are not copied into Radar archives.</p>
            <a href="https://github.com/phishdestroy/destroylist">Upstream project</a>
          </article>
          <article>
            <h3>CERT Polska</h3>
            <p>The active Warning List is used only as a transient discovery seed under the processing permission stated by its public API specification.</p>
            <a href="https://hole.cert.pl/">Warning List</a>
          </article>
          <article>
            <h3>HECAVEX export</h3>
            <p>The exporter remains responsible for excluding internal case history, proprietary evidence, credentials, personal data, and material it cannot publish.</p>
          </article>
          <article>
            <h3>Brand registry</h3>
            <p>Names and domains identify their owners and do not imply endorsement. Registry entries cite authoritative public sources.</p>
          </article>
        </div>
        <p className="docs-contact">
          Report a false positive, sensitive value, attribution problem, or removal request to{" "}
          <a href="mailto:info@hecavex.com">info@hecavex.com</a>.
        </p>
      </section>
    </article>
  );
}
