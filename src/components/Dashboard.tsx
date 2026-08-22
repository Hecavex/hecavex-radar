import { Activity, ArrowDown, Database, Globe2, Radar, ShieldAlert, Target } from "lucide-react";
import { useMemo, useState } from "react";

import { dashboardMetrics, filterSignals, topGroups } from "../lib/dashboard.ts";
import { formatNumber, formatRelativeTime } from "../lib/format.ts";
import type { Filters, RadarSnapshot } from "../types.ts";
import { DEFAULT_FILTERS } from "../lib/dashboard.ts";
import { CollectionDisclosure } from "./CollectionDisclosure.tsx";
import { DistributionPanel } from "./DistributionPanel.tsx";
import { FilterBar } from "./FilterBar.tsx";
import { SignalTable } from "./SignalTable.tsx";
import { SourcePanel } from "./SourcePanel.tsx";

const metrics = [
  { key: "total", label: "Recent signals", icon: Database },
  { key: "active", label: "Observed active", icon: Activity },
  { key: "highConfidence", label: "High score", icon: ShieldAlert },
  { key: "brands", label: "Brands targeted", icon: Target },
  { key: "countries", label: "Countries seen", icon: Globe2 },
] as const;

export function Dashboard({ snapshot, now = Date.now() }: { snapshot: RadarSnapshot; now?: number }) {
  const [filters, setFilters] = useState<Filters>(DEFAULT_FILTERS);
  const summary = useMemo(() => dashboardMetrics(snapshot), [snapshot]);
  const filteredSignals = useMemo(() => filterSignals(snapshot.signals, filters), [snapshot.signals, filters]);
  const topBrands = useMemo(() => topGroups(snapshot.signals, "brand"), [snapshot.signals]);
  const topCountries = useMemo(() => topGroups(snapshot.signals, "country"), [snapshot.signals]);
  const ageMs = now - new Date(snapshot.generatedAt).getTime();
  const isStale = ageMs > 2 * 60 * 60 * 1000;

  return (
    <main id="main-content">
      <section className="hero" aria-labelledby="radar-title">
        <div className="hero-grid" aria-hidden="true" />
        <div className="hero-copy">
          <p className="eyebrow"><Radar /> Open threat intelligence</p>
          <h1 id="radar-title">Potential phishing.<br /><span>Recently observed.</span></h1>
          <p className="hero-intro">
            A public, read-only view of potential phishing URLs and domains observed through CertStream, URLScan,
            and configured HECAVEX exports. Dangerous links are never clickable.
          </p>
          <div className="hero-actions">
            <a className="hero-action-primary" href="#signals">
              <ArrowDown aria-hidden="true" /> Browse {formatNumber(summary.total)} recent signals
            </a>
            <a href="/methodology/">Read the methodology</a>
          </div>
        </div>
        <div className={`freshness-card ${isStale ? "stale" : "fresh"}`}>
          <span className="live-dot" aria-hidden="true" />
          <div>
            <small>{isStale ? "Published snapshot delayed" : "Published snapshot current"}</small>
            <strong>{formatRelativeTime(snapshot.generatedAt, now)}</strong>
            <span>Generated {new Date(snapshot.generatedAt).toLocaleString("en-GB", { timeZone: "UTC" })} UTC</span>
          </div>
        </div>
      </section>

      <section className="metric-grid" aria-label="Radar summary">
        {metrics.map(({ key, label, icon: Icon }) => (
          <article className="metric-card" key={key}>
            <Icon aria-hidden="true" />
            <span>{label}</span>
            <strong>{formatNumber(summary[key])}</strong>
          </article>
        ))}
      </section>

      <section className="signal-section" id="signals" aria-labelledby="signals-title">
        <div className="section-heading">
          <div>
            <p className="eyebrow">Signal stream</p>
            <h2 id="signals-title">Recently seen indicators</h2>
          </div>
          <p><strong>{formatNumber(filteredSignals.length)}</strong> matching {formatNumber(snapshot.signals.length)} total</p>
        </div>
        <FilterBar signals={snapshot.signals} filters={filters} onChange={setFilters} />
        <SignalTable signals={filteredSignals} now={now} />
      </section>

      <section className="context-section" aria-labelledby="context-title">
        <div className="section-heading context-heading">
          <div>
            <p className="eyebrow">Snapshot context</p>
            <h2 id="context-title">Where these signals came from</h2>
          </div>
          <p>Publication inputs and the current distribution of reviewed rows.</p>
        </div>
        <div className="overview-grid">
          <SourcePanel sources={snapshot.sources} now={now} />
          <DistributionPanel title="Top targeted brands" data={topBrands} emptyLabel="No brand data" />
          <DistributionPanel title="Observed geography" data={topCountries} emptyLabel="No country data" />
        </div>
      </section>

      <CollectionDisclosure />
    </main>
  );
}
