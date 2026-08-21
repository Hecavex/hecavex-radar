import { Activity, Database, Globe2, Radar, ShieldAlert, Target } from "lucide-react";
import { useMemo, useState } from "react";

import { dashboardMetrics, filterSignals, topGroups } from "../lib/dashboard";
import { formatNumber, formatRelativeTime } from "../lib/format";
import type { Filters, RadarSnapshot } from "../types";
import { DEFAULT_FILTERS } from "../lib/dashboard";
import { DistributionPanel } from "./DistributionPanel";
import { FilterBar } from "./FilterBar";
import { SignalTable } from "./SignalTable";
import { SourcePanel } from "./SourcePanel";

const metrics = [
  { key: "total", label: "Recent signals", icon: Database },
  { key: "active", label: "Observed active", icon: Activity },
  { key: "highConfidence", label: "High confidence", icon: ShieldAlert },
  { key: "brands", label: "Brands targeted", icon: Target },
  { key: "countries", label: "Countries seen", icon: Globe2 },
] as const;

export function Dashboard({ snapshot }: { snapshot: RadarSnapshot }) {
  const [filters, setFilters] = useState<Filters>(DEFAULT_FILTERS);
  const summary = useMemo(() => dashboardMetrics(snapshot), [snapshot]);
  const filteredSignals = useMemo(() => filterSignals(snapshot.signals, filters), [snapshot.signals, filters]);
  const topBrands = useMemo(() => topGroups(snapshot.signals, "brand"), [snapshot.signals]);
  const topCountries = useMemo(() => topGroups(snapshot.signals, "country"), [snapshot.signals]);
  const ageMs = Date.now() - new Date(snapshot.generatedAt).getTime();
  const isStale = ageMs > 2 * 60 * 60 * 1000;

  return (
    <main id="main-content">
      <section className="hero" aria-labelledby="radar-title">
        <div className="hero-grid" aria-hidden="true" />
        <div className="hero-copy">
          <p className="eyebrow"><Radar /> Open threat intelligence</p>
          <h1 id="radar-title">Potential phishing.<br /><span>Recently observed.</span></h1>
          <p className="hero-intro">
            A public, read-only view of phishing URLs and domains seen across community feeds and approved HECAVEX
            exports. Dangerous links are never clickable.
          </p>
        </div>
        <div className={`freshness-card ${isStale ? "stale" : "fresh"}`}>
          <span className="live-dot" aria-hidden="true" />
          <div>
            <small>{snapshot.dataset === "demo" ? "Demo dataset" : isStale ? "Snapshot delayed" : "Feed current"}</small>
            <strong>{formatRelativeTime(snapshot.generatedAt)}</strong>
            <span>Generated {new Date(snapshot.generatedAt).toLocaleString("en-GB", { timeZone: "UTC" })} UTC</span>
          </div>
        </div>
      </section>

      {snapshot.dataset === "demo" && (
        <div className="demo-banner" role="status">
          <strong>Demo mode</strong>
          <span>These reserved <code>.test</code> indicators show the interface before live feeds are configured.</span>
        </div>
      )}

      <section className="metric-grid" aria-label="Radar summary">
        {metrics.map(({ key, label, icon: Icon }) => (
          <article className="metric-card" key={key}>
            <Icon aria-hidden="true" />
            <span>{label}</span>
            <strong>{formatNumber(summary[key])}</strong>
          </article>
        ))}
      </section>

      <section className="overview-grid" aria-label="Feed overview">
        <SourcePanel sources={snapshot.sources} />
        <DistributionPanel title="Top targeted brands" data={topBrands} emptyLabel="No brand data" />
        <DistributionPanel title="Observed geography" data={topCountries} emptyLabel="No country data" />
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
        <SignalTable signals={filteredSignals} />
      </section>
    </main>
  );
}
