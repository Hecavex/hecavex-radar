import { ChevronDown, Clock3, SearchX, ShieldCheck } from "lucide-react";

import { CollectionHealth } from "./CollectionHealth.tsx";

export function CollectionDisclosure() {
  return (
    <section className="collection-disclosure" aria-labelledby="collection-disclosure-title">
      <div className="collection-disclosure-heading">
        <div>
          <p className="eyebrow">Coverage disclosure</p>
          <h2 id="collection-disclosure-title">Sampled discovery, not continuous monitoring</h2>
        </div>
        <p>
          Radar is best-effort public research—not comprehensive coverage, monitoring, notification, takedown, or an
          incident-response service.
        </p>
      </div>
      <div className="collection-disclosure-grid">
        <article>
          <Clock3 aria-hidden="true" />
          <div>
            <h3>192 scheduled minutes per day</h3>
            <p>
              The CertStream workflow is scheduled 48 times daily for four minutes: at most 13.3% of a day. GitHub Actions
              may start late or fail, so actual connection time can be lower. The latest measured attempt is shown below.
            </p>
          </div>
        </article>
        <article>
          <SearchX aria-hidden="true" />
          <div>
            <h3>Missing URLScan evidence is unknown</h3>
            <p>
              URLScan enrichment is limited to existing public reports. No result is not a benign verdict and does not
              suppress an independently qualifying certificate candidate.
            </p>
          </div>
        </article>
        <article>
          <ShieldCheck aria-hidden="true" />
          <div>
            <h3>Signals are leads</h3>
            <p>
              A row and its 0–100 matching score are neither proof nor probability of malicious intent. Review the source,
              evidence, timing, and limitations before acting.
            </p>
          </div>
        </article>
      </div>
      <details className="collection-health-disclosure">
        <summary>
          <span>
            <strong>Latest CertStream attempt telemetry</strong>
            <small>Actual timing, input counts, schedule state, and freshness</small>
          </span>
          <span className="collection-health-toggle-label">View details</span>
          <ChevronDown aria-hidden="true" />
        </summary>
        <CollectionHealth />
      </details>
      <p className="collection-disclosure-links">
        <a href="/methodology/#collection">Collection methodology</a>
        <a href="/docs/#operations">Schedules and source-state semantics</a>
      </p>
    </section>
  );
}
