import { Activity, ArrowDown, ArrowRight, Clock3, Database, Radar, ShieldCheck, Waypoints } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { controlledFilterSearch, dashboardMetrics, DEFAULT_FILTERS, filterSignals, filtersFromSearch, sortSignals } from "../lib/dashboard.ts";
import { formatDateTime, formatNumber, formatRelativeTime } from "../lib/format.ts";
import type { Filters, RadarSnapshot } from "../types.ts";
import { CollectionDisclosure } from "./CollectionDisclosure.tsx";
import { ExportActions } from "./ExportActions.tsx";
import { FilterBar } from "./FilterBar.tsx";
import { SignalTable } from "./SignalTable.tsx";

export function Dashboard({ snapshot, now = Date.now() }: { snapshot: RadarSnapshot; now?: number }) {
  const [filters, setFilters] = useState<Filters>(DEFAULT_FILTERS);
  const [urlStateReady, setUrlStateReady] = useState(false);
  const summary = useMemo(() => dashboardMetrics(snapshot), [snapshot]);
  const filteredSignals = useMemo(() => sortSignals(filterSignals(snapshot.signals, filters, now), filters.sort), [snapshot.signals, filters, now]);
  const syncAgeMs = Math.max(0, now - Date.parse(snapshot.lastSuccessfulSyncAt));
  const isStale = syncAgeMs > 2 * 60 * 60 * 1000;
  const dayAgo = now - 86_400_000;
  const newToday = snapshot.signals.filter((signal) => Date.parse(signal.firstSeen) >= dayAgo).length;
  const reobservedToday = snapshot.signals.filter((signal) => Date.parse(signal.firstSeen) < dayAgo && Date.parse(signal.lastSeen) >= dayAgo).length;

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
    window.history.replaceState(null, "", `${window.location.pathname}${query ? `?${query}` : ""}${window.location.hash}`);
  }, [filters, urlStateReady]);

  const updateFacet = (key: "brand" | "source" | "country", value: string) => setFilters((current) => ({ ...current, [key]: value }));

  return (
    <main id="main-content">
      <section className="hero radar-hero" aria-labelledby="radar-title">
        <div className="hero-grid" aria-hidden="true" />
        <div className="hero-copy">
          <p className="eyebrow"><Radar aria-hidden="true" /> Open threat intelligence · Lithuania</p>
          <h1 id="radar-title">Phishing signals.<br /><span>Observed, not assumed.</span></h1>
          <p className="hero-intro">Defanged potential phishing and impersonation domains discovered through sampled Certificate Transparency, URLScan, and sanitized HECAVEX inputs. Every row is a lead, never a verdict.</p>
          <div className="hero-actions"><a className="hero-action-primary" href="#signals"><ArrowDown aria-hidden="true" /> Browse {formatNumber(summary.total)} candidates</a><a href="/methodology/">How collection works</a></div>
        </div>
        <aside className={`freshness-card ${isStale ? "stale" : "fresh"}`} aria-label="Snapshot freshness">
          <span className="live-dot" aria-hidden="true" />
          <div><small>{isStale ? "Snapshot sync delayed" : "Snapshot current"}</small><strong>{formatRelativeTime(snapshot.lastSuccessfulSyncAt, now)}</strong><span>Last successful sync {formatDateTime(snapshot.lastSuccessfulSyncAt)} UTC</span><span>Data changed {formatRelativeTime(snapshot.generatedAt, now)}</span></div>
        </aside>
      </section>

      <section className="activity-strip" aria-label="Current Radar activity">
        <div><Database aria-hidden="true" /><span>Current candidates</span><strong>{formatNumber(summary.total)}</strong></div>
        <div><Clock3 aria-hidden="true" /><span>First published 24h</span><strong>{formatNumber(newToday)}</strong></div>
        <div><Activity aria-hidden="true" /><span>Reobserved 24h</span><strong>{formatNumber(reobservedToday)}</strong></div>
        <div><ShieldCheck aria-hidden="true" /><span>Potential brands</span><strong>{formatNumber(summary.brands)}</strong></div>
        <a href="/changes/"><span>Full event record</span><strong>Changes <ArrowRight aria-hidden="true" /></strong></a>
      </section>

      <section className="signal-section" id="signals" aria-labelledby="signals-title">
        <div className="section-heading">
          <div><p className="eyebrow">Current signal window</p><h2 id="signals-title">Recently observed candidates</h2></div>
          <div className="signal-heading-actions"><p><strong>{formatNumber(filteredSignals.length)}</strong> matching {formatNumber(snapshot.signals.length)}</p><ExportActions signals={filteredSignals} snapshotGeneratedAt={snapshot.generatedAt} /></div>
        </div>
        <FilterBar signals={snapshot.signals} filters={filters} onChange={setFilters} />
        <SignalTable signals={filteredSignals} now={now} snapshotGeneratedAt={snapshot.generatedAt} onFacet={updateFacet} />
      </section>

      <section className="radar-route-grid" aria-label="Explore Radar">
        <a href="/changes/"><Clock3 aria-hidden="true" /><span><strong>Changes</strong><small>New, reobserved, changed, or retracted</small></span><ArrowRight aria-hidden="true" /></a>
        <a href="/trends/"><Activity aria-hidden="true" /><span><strong>Trends and quality</strong><small>Counts shown beside collector coverage</small></span><ArrowRight aria-hidden="true" /></a>
        <a href="/associations/"><Waypoints aria-hidden="true" /><span><strong>Associations</strong><small>Inspect bounded shared evidence</small></span><ArrowRight aria-hidden="true" /></a>
        <a href="/tools/"><ShieldCheck aria-hidden="true" /><span><strong>Local IOC check</strong><small>Compare values without uploading them</small></span><ArrowRight aria-hidden="true" /></a>
      </section>

      <CollectionDisclosure />
    </main>
  );
}
