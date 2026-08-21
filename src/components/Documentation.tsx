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
  ["confidence", "integer", "Rounded and clamped score from 0 to 100; not a probability."],
] as const;

const workflows = [
  ["Continuous integration", "Pull requests and relevant pushes", "Lint, type checks, tests, and production build"],
  ["CertStream collection", "02 and 32 minutes past each UTC hour", "Vilnius-date CertStream candidate archive"],
  ["URLScan hunt", "03:37 and 15:37 UTC", "Vilnius-date validated URLScan archive"],
  ["Snapshot synchronization", "17 minutes past each UTC hour", "Validated public radar.json snapshot"],
  ["Pages deployment", "After verified main changes or manual dispatch", "Static GitHub Pages artifact"],
] as const;

const settings = [
  ["URLSCAN_API_KEY", "Secret", "Required only for passive URLScan search and result retrieval."],
  ["CERTSTREAM_URL", "Secret or variable", "Optional monitored WSS endpoint; otherwise the scheduled workflow starts its pinned temporary source."],
  ["HECAVEX_ENABLED", "Variable", "Enables the optional configured public HECAVEX export."],
  ["HECAVEX_FEED_URL", "Secret", "Required with HECAVEX enabled; production endpoints must use HTTPS."],
  ["HECAVEX_FEED_TOKEN", "Secret", "Optional read-only bearer credential for the configured export."],
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
          Architecture, source behavior, public schemas, operating requirements, and data terms for the open-source
          Radar deployment. Detection methodology is documented separately on the{" "}
          <a href="/methodology/">Methodology page</a>.
        </p>
      </header>

      <nav className="docs-toc" aria-label="Documentation sections">
        <span>Contents</span>
        <div>
          <a href="#architecture">Architecture</a>
          <a href="#sources">Sources</a>
          <a href="#data-contract">Data contract</a>
          <a href="#operations">Operations</a>
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
            <p>The publisher revalidates, scopes, merges, limits, sorts, and atomically writes radar.json.</p>
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
          <p>Discovery inputs can trigger investigation, but they cannot create or label a dashboard row by themselves.</p>
        </div>
        <div className="docs-card-grid">
          <article>
            <span>Certificate names</span>
            <h3>CertStream</h3>
            <p>
              Emits Certificate Transparency updates over a websocket. Radar reads DNS names, rejects official domains,
              applies its public matcher, and archives qualifying candidates without retrieving those domains.
            </p>
            <a href="https://certstream.dev/docs.html">Provider documentation</a>
          </article>
          <article>
            <span>Existing public scans</span>
            <h3>URLScan</h3>
            <p>
              Authenticated passive searches require public visibility in both the search summary and result detail.
              Exact-domain, brand, title, and primary-document hash pivots remain bounded and independently validated.
            </p>
            <a href="https://urlscan.io/docs/api/">Provider documentation</a>
          </article>
          <article>
            <span>Optional deployment input</span>
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
      </section>

      <section className="docs-section" id="data-contract" aria-labelledby="contract-title">
        <div className="docs-section-heading">
          <p className="eyebrow">Public data contract</p>
          <h2 id="contract-title">Snapshot schema version 1</h2>
          <p>The Python publisher is normative; browser validation is an additional structural check.</p>
        </div>
        <pre className="docs-code" aria-label="Public snapshot example"><code>{`{
  "schemaVersion": 1,
  "dataset": "live",
  "generatedAt": "2026-08-21T09:15:00.000Z",
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
            <span>Optional input</span>
            <h3>HECAVEX JSON</h3>
            <p>
              Accepts an array or an object containing <code>signals</code>. Alternate common field names are normalized,
              supplied source labels are ignored, and hashes require explicit primary-HTML SHA-256 typing.
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

      <section className="docs-section" id="operations" aria-labelledby="operations-title">
        <div className="docs-section-heading">
          <p className="eyebrow">Operations and deployment</p>
          <h2 id="operations-title">Scheduled GitHub Pages publication</h2>
          <p>Schedules are UTC and can start late. Manual dispatch remains available for collection, sync, and deployment.</p>
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
            <span>Local development</span>
            <h3>Python 3.12 · Node 22.12 · pnpm 10</h3>
            <pre className="docs-code"><code>{`python -m pip install -e ".[dev]"
corepack enable
pnpm install
pnpm dev
pnpm check`}</code></pre>
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
            <p>The exporter remains responsible for excluding private history, proprietary evidence, credentials, personal data, and material it cannot publish.</p>
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
