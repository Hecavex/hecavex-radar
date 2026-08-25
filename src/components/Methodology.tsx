const steps = [
  {
    number: "01",
    title: "Observe",
    body: "Read passive public observations from Certificate Transparency, existing public URLScan reports, and deliberately sanitized HECAVEX inputs.",
  },
  {
    number: "02",
    title: "Match",
    body: "Compare hostnames with a reviewed Lithuanian-brand registry while suppressing official domains and known lexical collisions.",
  },
  {
    number: "03",
    title: "Validate",
    body: "Require one unambiguous brand, current evidence, safe fields, and the relevant match-score threshold before publication.",
  },
  {
    number: "04",
    title: "Publish",
    body: "Defang dashboard indicators, mark public observations as suspected, merge duplicate hosts, and project normalized domain observations into the static STIX 2.1 feed.",
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
  ["Source", "CertStream, URLScan, or HECAVEX. Controlled discovery lineage distinguishes configured service exports from explicit sanitized review candidates."],
  ["Status", "CertStream and URLScan rows remain suspected. Active, offline, or mitigated lifecycle states require a configured HECAVEX observation."],
  ["Target", "Exactly one brand resolved through the current reviewed registry and collision checks."],
  ["Evidence", "Separate name-only, corroborated, and analyst-reviewed tiers, with controlled discovery and corroboration lineage."],
  ["Context", "Optional public URLScan evidence plus bounded point-in-time DNS and RDAP registration context. Missing context remains unknown."],
  ["Match score", "An integer rule score from 0 to 100. It ranks matcher strength; it is not probability, analyst confidence, or a verdict."],
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
          <a href="#history">History</a>
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
              Scheduled collection listens to live certificate events for eight minutes per run, normally four times per hour.
              Each DNS name is scored independently and qualifying matches are stored in Europe/Vilnius daily archives.
            </p>
            <p>
              That schedule provides at most 768 listening minutes per day, or 53.3% of wall-clock time. It is live
              sampling, not a daily certificate dump: events outside successful listening windows are not replayed or
              backfilled by the current collector. Actions can start late, drop a schedule, or fail, so actual observation can be lower.
            </p>
          </article>
          <article>
            <span>Checkpointed CT search</span>
            <h3>Bounded keyword replay</h3>
            <p>
              An hourly crt.sh search rotates across reviewed brand terms and persists one numeric cursor per query. It
              bootstraps only a bounded recent window, rechecks a limited overlap for late indexing, resumes an explicit
              backlog before rotation, re-applies the same matcher, and retains discovery lineage in the CT archive.
            </p>
            <p>
              This can recover indexed results missed by a live sample, but it is not an enumeration of every CT log.
              Provider availability, indexing, result limits, and the deliberately bounded query set remain coverage limits.
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
            <span>Deliberately sanitized input</span>
            <h3>HECAVEX</h3>
            <p>
              A deployment may configure a bounded HTTPS JSON export. Supplied source labels are ignored; accepted rows
              are attributed to HECAVEX and must pass the same brand, URL, timestamp, and evidence validation.
            </p>
            <p>
              An operator can also deliberately export one sanitized local review candidate. The public
              <code> discoveredVia</code> value distinguishes that path from the service export. Internal collectors,
              proprietary detection logic, analyst notes, credentials, and private historical data remain outside this project.
            </p>
          </article>
          <article>
            <span>Published-candidate context</span>
            <h3>DNS and RDAP</h3>
            <p>
              Four times daily, Radar rotates through already-published candidates using DNS-over-HTTPS and the IANA RDAP
              bootstrap. RDAP is requested for the registrable parent and that defanged scope remains visible. It never
              requests the candidate webpage or executes its content.
            </p>
            <p>
              Sidecars may expose defanged DNS answers, minimum TTL, registrar, lifecycle dates, and statuses. Registrant
              identities are excluded, records expire after a bounded retention window, and shared infrastructure is association, not attribution.
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
            limits output, and writes the dashboard snapshot and its observation-only STIX 2.1 projection from the same
            accepted signal set.
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
            union of sources and hashes, most specific safe path, and highest match score. Conflicting non-null brands
            invalidate the merged row.
          </p>
        </div>
        <p className="methodology-report">
          The static <a href="/data/radar.stix.json">STIX 2.1 pull feed</a> contains raw domain-name observables for
          potential or suspected candidates. The separate <a href="/data/radar-reviewed.stix.json">reviewed feed</a> can
          contain only explicit, expiring analyst confirmations. Neither feed is a TAXII endpoint, automatic blocklist,
          maliciousness verdict for unreviewed rows, or attribution claim.
        </p>
      </section>

      <section className="methodology-detail" id="history" aria-labelledby="history-method-title">
        <div className="methodology-section-heading">
          <p className="eyebrow">History and review</p>
          <h2 id="history-method-title">Append observations; infer nothing from absence</h2>
          <p>
            Each accepted source observation receives a deterministic event ID. Replaying the same archives therefore
            produces the same event rather than inflating observation counts.
          </p>
        </div>
        <div className="methodology-boundaries">
          <article>
            <p className="eyebrow">Detailed trail</p>
            <h3>Thirty-day event window</h3>
            <p>
              Daily, defanged NDJSON partitions are append-only during the configured detail window. Older events compact
              into a bounded signal summary, which is retained for two years by default.
            </p>
          </article>
          <article>
            <p className="eyebrow">Status provenance</p>
            <h3>Only explicit transitions</h3>
            <p>
              CertStream and URLScan remain suspected. A transition to active, offline, or mitigated is recorded only when
              a supported HECAVEX observation supplies it. Falling outside a lookback window creates no transition.
            </p>
          </article>
          <article>
            <p className="eyebrow">Corrections</p>
            <h3>Private notes stay private</h3>
            <p>
              HECAVEX operator review uses an append-only database outside Git. Only explicitly exported, defanged suppressions and
              candidates reach the public pipeline; analyst notes and identities are never included.
            </p>
          </article>
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
              Live CertStream is sampled, the checkpointed CT search is provider-indexed and bounded, URLScan exposes only
              existing public reports, and context is optional. Missing evidence does not make a candidate safe or prevent
              an independently qualifying CT candidate from appearing.
            </p>
          </article>
          <article>
            <p className="eyebrow">Redirects and cloaking</p>
            <h3>A redirect is behavior, not clearance</h3>
            <p>
              A submitted candidate remains the indicator when a public URLScan report redirects elsewhere. Radar records
              the defanged destination as context, but does not assign that destination&apos;s host data or screenshot to the
              candidate. Different visitors can receive different content or redirects.
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
          <article>
            <p className="eyebrow">Service boundary</p>
            <h3>Best effort, no SLA</h3>
            <p>
              HECAVEX operates Radar as best-effort public research. It is not continuous brand monitoring, victim
              notification, incident response, takedown, or an availability or response commitment.
            </p>
          </article>
          <article>
            <p className="eyebrow">Operational evidence</p>
            <h3>Snapshot state has limits</h3>
            <p>
              Source timestamps show archive reads performed by the publisher. The separate public collection-health
              document reports actual timing, aggregate counts, late starts, outcome, last success, and freshness for only
              the latest CertStream attempt. Rolling pipeline health also reports sanitized CT-search and DNS/RDAP run
              summaries; none of these artifacts proves complete global coverage.
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
