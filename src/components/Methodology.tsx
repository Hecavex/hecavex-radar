const steps = [
  {
    number: "01",
    title: "Observe",
    body: "Read passive public observations from Certificate Transparency, existing public URLScan reports, and an optional configured HECAVEX export.",
  },
  {
    number: "02",
    title: "Match",
    body: "Compare hostnames with a reviewed Lithuanian-brand registry while suppressing official domains and known lexical collisions.",
  },
  {
    number: "03",
    title: "Validate",
    body: "Require one unambiguous brand, current evidence, safe fields, and the relevant confidence threshold before publication.",
  },
  {
    number: "04",
    title: "Publish",
    body: "Defang accepted indicators, mark public observations as suspected, merge duplicate hosts, and write a static JSON snapshot.",
  },
] as const;

const matchingRules = [
  "Normalize the hostname, then reject malformed input, reviewed official domains, excluded domains, and their subdomains.",
  "Match an alias as a complete hyphen-delimited token or complete token sequence within one DNS label. Suspicious context must normally occur in that same label.",
  "Allow narrowly joined forms such as a reviewed suspicious prefix or suffix attached directly to a sufficiently long brand alias.",
  "Apply opt-in restricted Damerau–Levenshtein matching only to reviewed single-word fuzzy aliases, with the same suspicious-context requirement.",
  "Reject excluded terms, multi-brand evidence, and any declared brand that conflicts with the current hostname match.",
] as const;

const publicFields = [
  ["Indicator", "A normalized, defanged domain or URL. Credentials, query strings, fragments, and unsafe path data are removed."],
  ["Timeline", "First-seen and last-seen timestamps from accepted observations, normalized to UTC."],
  ["Source", "CertStream, URLScan, or a configured HECAVEX public export. Multiple observations can merge into one host row."],
  ["Status", "CertStream and URLScan rows remain suspected. Active, offline, or mitigated lifecycle states require a configured HECAVEX observation."],
  ["Target", "Exactly one brand resolved through the current reviewed registry and collision checks."],
  ["Evidence", "Optional URLScan report, screenshot, primary-document SHA-256 hashes, host summary, and country metadata."],
  ["Confidence", "An integer ranking score from 0 to 100. It orders evidence strength; it is not a probability or verdict."],
] as const;

export function Methodology() {
  return (
    <section className="methodology-section" id="methodology" aria-labelledby="methodology-title">
      <header className="methodology-heading">
        <div>
          <p className="eyebrow">Methodology</p>
          <h1 id="methodology-title">How a signal reaches Radar</h1>
        </div>
        <p>
          HECAVEX Radar is a passive, explainable screening pipeline for possible phishing and impersonation relevant
          to Lithuania. It favors precision over volume and never treats one automated signal as proof of malicious intent.
        </p>
      </header>

      <nav className="methodology-toc" aria-label="Methodology sections">
        <span>On this page</span>
        <div>
          <a href="#pipeline">Pipeline</a>
          <a href="#collection">Collection</a>
          <a href="#matching">Brand matching</a>
          <a href="#publication">Publication</a>
          <a href="#limitations">Limits and safety</a>
        </div>
      </nav>

      <section className="methodology-detail" id="pipeline" aria-labelledby="pipeline-title">
        <div className="methodology-section-heading">
          <p className="eyebrow">Pipeline</p>
          <h2 id="pipeline-title">Four bounded stages</h2>
          <p>Every published row follows the same normalization, brand-scoping, safety, and merge path.</p>
        </div>
        <ol className="methodology-steps" aria-label="Publication stages">
          {steps.map((step) => (
            <li key={step.number}>
              <span>{step.number}</span>
              <h3>{step.title}</h3>
              <p>{step.body}</p>
            </li>
          ))}
        </ol>
      </section>

      <section className="methodology-detail" id="collection" aria-labelledby="collection-title">
        <div className="methodology-section-heading">
          <p className="eyebrow">Collection</p>
          <h2 id="collection-title">Passive observations only</h2>
          <p>Radar does not browse a candidate host, submit it for scanning, or turn a defanged indicator into a live link.</p>
        </div>
        <div className="methodology-source-grid">
          <article>
            <span>Certificate Transparency</span>
            <h3>CertStream</h3>
            <p>
              Scheduled collection listens to live certificate events for four minutes per run, normally twice per hour.
              Each DNS name is scored independently and qualifying matches are stored in Europe/Vilnius daily archives.
            </p>
            <p>
              This is live sampling, not a complete daily certificate dump. Events outside the listening windows are not
              replayed or backfilled by the current collector.
            </p>
          </article>
          <article>
            <span>Existing public reports</span>
            <h3>URLScan</h3>
            <p>
              Radar searches already-existing public results using exact candidate domains, reviewed brand terms, page
              titles, and tightly bounded primary-HTML SHA-256 pivots. It never submits a new scan.
            </p>
            <p>
              Search summaries and result details must both report public visibility. URLScan can enrich CertStream with
              screenshots, hashes, and hosting metadata, but it is not required for a qualifying CertStream row.
            </p>
          </article>
          <article>
            <span>Optional configured input</span>
            <h3>HECAVEX export</h3>
            <p>
              A deployment may configure a bounded HTTPS JSON export. Supplied source labels are ignored; accepted rows
              are attributed to HECAVEX and must pass the same brand, URL, timestamp, and evidence validation.
            </p>
            <p>
              Internal collectors, proprietary detection logic, analyst notes, credentials, and private historical data
              are outside this public project and its data contract.
            </p>
          </article>
        </div>
      </section>

      <section className="methodology-detail" id="matching" aria-labelledby="matching-title">
        <div className="methodology-section-heading">
          <p className="eyebrow">Brand matching</p>
          <h2 id="matching-title">Conservative by construction</h2>
          <p>
            The public registry records reviewed aliases, fuzzy aliases, official domains, exclusions, and collision terms
            for brands relevant to Lithuania. Registry entries cannot supply executable regular expressions.
          </p>
        </div>
        <ol className="methodology-rule-list">
          {matchingRules.map((rule, index) => (
            <li key={rule}>
              <span>{String(index + 1).padStart(2, "0")}</span>
              <p>{rule}</p>
            </li>
          ))}
        </ol>
        <div className="methodology-note">
          <strong>Scoring threshold</strong>
          <p>
            Different top-level domains, multiple hyphens, suspicious words, and punycode can increase a score only after
            valid brand evidence exists. The default CertStream and URLScan domain threshold is 80/100.
          </p>
        </div>
      </section>

      <section className="methodology-detail" id="publication" aria-labelledby="publication-title">
        <div className="methodology-section-heading">
          <p className="eyebrow">Publication</p>
          <h2 id="publication-title">What the dashboard exposes</h2>
          <p>
            The hourly publisher revalidates recent archives against the current registry, merges compatible observations,
            limits output, and atomically replaces one static snapshot.
          </p>
        </div>
        <dl className="methodology-field-list">
          {publicFields.map(([term, description]) => (
            <div key={term}>
              <dt>{term}</dt>
              <dd>{description}</dd>
            </div>
          ))}
        </dl>
        <div className="methodology-note">
          <strong>Merge behavior</strong>
          <p>
            One row represents one observed host. Merging keeps the earliest first-seen value, latest last-seen value,
            union of sources and hashes, most specific safe path, and highest confidence. Conflicting non-null brands
            invalidate the merged row.
          </p>
        </div>
      </section>

      <section className="methodology-detail" id="limitations" aria-labelledby="limitations-title">
        <div className="methodology-section-heading">
          <p className="eyebrow">Limits and safety</p>
          <h2 id="limitations-title">Read the signals as leads</h2>
          <p>Coverage gaps and missing enrichment are expected. Neither a listing nor an absence from Radar is a verdict.</p>
        </div>
        <div className="methodology-boundaries">
          <article>
            <p className="eyebrow">Interpretation</p>
            <h3>A lead, not attribution</h3>
            <p>
              A row indicates possible phishing or impersonation. It does not prove malicious intent, current liveness,
              ownership, attribution, compromise, or that a person has interacted with the domain.
            </p>
          </article>
          <article>
            <p className="eyebrow">Coverage</p>
            <h3>Intentionally incomplete</h3>
            <p>
              CertStream is sampled rather than continuous, URLScan exposes only existing public reports, and some metadata
              is optional. Missing URLScan evidence does not make a candidate safe or prevent a CertStream candidate from appearing.
            </p>
          </article>
          <article>
            <p className="eyebrow">Browsing safety</p>
            <h3>Indicators stay defanged</h3>
            <p>
              The dashboard never links to observed hosts. Evidence controls can contact exactly urlscan.io after a user
              chooses to open them; report and screenshot URLs are validated before publication.
            </p>
          </article>
          <article>
            <p className="eyebrow">Corrections</p>
            <h3>Rules are re-applied</h3>
            <p>
              Archived observations are checked against the current registry during synchronization, so corrected brand
              mappings and official-domain additions remove stale false positives from later snapshots.
            </p>
          </article>
        </div>
        <p className="methodology-report">
          Believe a listing is incorrect?{" "}
          <a href="mailto:info@hecavex.com?subject=HECAVEX%20Radar%20false%20positive">Report a false positive</a>.
        </p>
      </section>
    </section>
  );
}
