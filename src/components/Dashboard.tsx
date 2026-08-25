import { Activity, ArrowDown, Database, Globe2, Radar, ShieldAlert, Target } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import {
  controlledFilterSearch,
  dashboardMetrics,
  filterSignals,
  filtersFromSearch,
  sortSignals,
  topGroups,
} from "../lib/dashboard.ts";
import { formatDateTime, formatNumber, formatRelativeTime } from "../lib/format.ts";
import type { Filters, RadarSnapshot } from "../types.ts";
import { DEFAULT_FILTERS } from "../lib/dashboard.ts";
import { CollectionDisclosure } from "./CollectionDisclosure.tsx";
import { DistributionPanel } from "./DistributionPanel.tsx";
import { ExportActions } from "./ExportActions.tsx";
import { FilterBar } from "./FilterBar.tsx";
import { PipelineHealthPanel } from "./PipelineHealthPanel.tsx";
import { RelatedObservationsPanel } from "./RelatedObservations.tsx";
import { SignalTable } from "./SignalTable.tsx";
import { SourcePanel } from "./SourcePanel.tsx";
import { StixFeedPanel } from "./StixFeedPanel.tsx";
import { WhatChanged } from "./WhatChanged.tsx";

const metrics = [
  { key: "total", label: "Recent signals", icon: Database },
  { key: "active", label: "Observed active", icon: Activity },
  { key: "highConfidence", label: "High match score", icon: ShieldAlert },
  { key: "brands", label: "Potential brand matches", icon: Target },
  { key: "countries", label: "Hosting countries observed", icon: Globe2 },
] as const;

export function Dashboard({ snapshot, now = Date.now() }: { snapshot: RadarSnapshot; now?: number }) {
  const [filters, setFilters] = useState<Filters>(DEFAULT_FILTERS);
  const [urlStateReady, setUrlStateReady] = useState(false);
  const summary = useMemo(() => dashboardMetrics(snapshot), [snapshot]);
  const filteredSignals = useMemo(
    () => sortSignals(filterSignals(snapshot.signals, filters, now), filters.sort),
    [snapshot.signals, filters, now],
  );
  const topBrands = useMemo(() => topGroups(snapshot.signals, "brand"), [snapshot.signals]);
  const topCountries = useMemo(() => topGroups(snapshot.signals, "country"), [snapshot.signals]);
  const syncAgeMs = Math.max(0, now - new Date(snapshot.lastSuccessfulSyncAt).getTime());
  const isStale = syncAgeMs > 2 * 60 * 60 * 1000;

  useEffect(() => {
    const updateFromLocation = () => {
      setFilters((current) => ({ ...filtersFromSearch(window.location.search, snapshot.signals), query: current.query }));
      setUrlStateReady(true);
    };
    updateFromLocation();
    window.addEventListener("popstate", updateFromLocation);
    return () => window.removeEventListener("popstate", updateFromLocation);
  }, [snapshot.signals]);

  useEffect(() => {
    if (!urlStateReady) return;
    const query = controlledFilterSearch(filters);
    const nextUrl = `${window.location.pathname}${query ? `?${query}` : ""}${window.location.hash}`;
    window.history.replaceState(null, "", nextUrl);
  }, [filters, urlStateReady]);

  const updateFacet = (key: "brand" | "source" | "country", value: string) => {
    setFilters((current) => ({ ...current, [key]: value }));
  };

  const showRecentSignal = (signal: RadarSnapshot["signals"][number]) => {
    setFilters({ ...DEFAULT_FILTERS, timeRange: "24h" });
    window.setTimeout(() => document.getElementById(`signal-${signal.id}`)?.scrollIntoView({ block: "center" }), 0);
  };

  const showRelatedSignal = (signal: RadarSnapshot["signals"][number]) => {
    setFilters(DEFAULT_FILTERS);
    window.setTimeout(() => document.getElementById(`signal-${signal.id}`)?.scrollIntoView({ block: "center" }), 0);
  };

  return (
    <main id="main-content">
      <section className="hero" aria-labelledby="radar-title">
        <div className="hero-grid" aria-hidden="true" />
        <div className="hero-copy">
          <p className="eyebrow"><Radar /> Open threat intelligence</p>
          <h1 id="radar-title">Potential phishing.<br /><span>Recently observed.</span></h1>
          <p className="hero-intro">
            A public, read-only view of potential phishing URLs and domains observed through CertStream, URLScan,
            and sanitized HECAVEX inputs. Dangerous links are never clickable.
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
            <small>{isStale ? "Snapshot sync delayed" : "Snapshot sync current"}</small>
            <strong>Checked {formatRelativeTime(snapshot.lastSuccessfulSyncAt, now)}</strong>
            <span>Last successful sync {formatDateTime(snapshot.lastSuccessfulSyncAt)} UTC</span>
            <span>Data last changed {formatRelativeTime(snapshot.generatedAt, now)} / {formatDateTime(snapshot.generatedAt)} UTC</span>
          </div>
        </div>
      </section>

      <section className="metric-grid radar-metrics" aria-label="Radar summary">
        {metrics.map(({ key, label, icon: Icon }) => (
          <article className="metric-card" key={key}>
            <Icon aria-hidden="true" />
            <span>{label}</span>
            <strong>{formatNumber(summary[key])}</strong>
          </article>
        ))}
      </section>

      <WhatChanged signals={snapshot.signals} now={now} onSelect={showRecentSignal} />

      <section className="signal-section" id="signals" aria-labelledby="signals-title">
        <div className="section-heading">
          <div>
            <p className="eyebrow">Signal stream</p>
            <h2 id="signals-title">Recently seen candidates</h2>
          </div>
          <div className="signal-heading-actions">
            <p><strong>{formatNumber(filteredSignals.length)}</strong> matching {formatNumber(snapshot.signals.length)} total</p>
            <ExportActions signals={filteredSignals} snapshotGeneratedAt={snapshot.generatedAt} />
          </div>
        </div>
        <FilterBar signals={snapshot.signals} filters={filters} onChange={setFilters} />
        <SignalTable
          signals={filteredSignals}
          now={now}
          snapshotGeneratedAt={snapshot.generatedAt}
          onFacet={updateFacet}
        />
      </section>

      <RelatedObservationsPanel signals={snapshot.signals} onSelect={showRelatedSignal} />

      <StixFeedPanel />

      <PipelineHealthPanel />

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
          <DistributionPanel title="Potential brand matches" data={topBrands} emptyLabel="No brand data" />
          <DistributionPanel title="Hosting countries observed" data={topCountries} emptyLabel="No country data" />
        </div>
      </section>

      <CollectionDisclosure />
    </main>
  );
}
