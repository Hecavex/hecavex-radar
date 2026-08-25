import { Activity, Archive, CalendarClock, Database, Download, ExternalLink, FileCheck2, GitCompareArrows, RadioTower, Rss, ShieldCheck, Waypoints } from "lucide-react";

import { AssociationExplorer } from "./components/AssociationExplorer.tsx";
import { BrowserIocChecker } from "./components/BrowserIocChecker.tsx";
import { SiteFooter } from "./components/SiteFooter.tsx";
import { SiteHeader } from "./components/SiteHeader.tsx";
import { formatDateTime } from "./lib/format.ts";
import { signalPath } from "./lib/signalRoutes.ts";
import type { DailyTrendRow, StaticPageData, StaticPageKind } from "./lib/staticPageBootstrap.ts";

function PageShell({ currentPage, children }: { currentPage: StaticPageKind; children: React.ReactNode }) {
  return <div className="site-shell"><SiteHeader currentPage={currentPage} /><main className="content-page intelligence-page" id="main-content">{children}</main><SiteFooter /></div>;
}

function ArtifactHero({ eyebrow, title, description, icon: Icon }: { eyebrow: string; title: string; description: string; icon: typeof Activity }) {
  return <header className="artifact-hero"><div><p className="eyebrow"><Icon aria-hidden="true" /> {eyebrow}</p><h1>{title}</h1></div><p>{description}</p></header>;
}

export function ChangesPage({ data }: { data: StaticPageData }) {
  const typeLabels = { "first-publication": "First publication", reobservation: "Reobserved", "status-change": "Status changed", retraction: "Assessment retracted" } as const;
  return <PageShell currentPage="changes">
    <ArtifactHero icon={CalendarClock} eyebrow="30-day event record" title="What changed" description="A durable event-level view of new publications, later observations, status changes, and explicit analyst retractions. This is publication activity, not a measure of phishing prevalence." />
    <section className="feed-strip" aria-label="Change feeds"><div><Rss aria-hidden="true" /><span>Subscribe without polling the full snapshot</span></div><a href="/data/events.atom.xml">Atom</a><a href="/data/events.rss.xml">RSS</a><a href="/data/events.feed.json">JSON Feed</a><a href="/data/events.json">Event JSON</a></section>
    <section className="event-section" aria-labelledby="events-title"><div className="section-heading"><div><p className="eyebrow">Publication log</p><h2 id="events-title">Recent events</h2></div><p><strong>{data.events.events.length}</strong> shown · {data.events.window.days}-day window</p></div>
      <ol className="event-list">{data.events.events.map((event) => <li key={event.id}><time dateTime={event.occurredAt}>{formatDateTime(event.occurredAt)} UTC</time><span className={`event-type ${event.type}`}>{typeLabels[event.type]}</span><div><a href={signalPath(event.signalId)}>{event.domain}</a><span>{event.brand} · {event.sources.join(", ")}</span></div>{event.type === "status-change" ? <small>{event.previousStatus} → {event.status}</small> : null}</li>)}</ol>
      {!data.events.events.length ? <p className="empty-copy">No event falls inside the current public window.</p> : null}
    </section>
    <section className="related-route-card"><div><p className="eyebrow"><Archive aria-hidden="true" /> Retained archive</p><h2>Need the full candidate timeline?</h2><p>The history view preserves bounded first-seen, last-seen, observation counts and status transitions beyond this feed window.</p></div><a href="/history/">Open candidate history →</a></section>
  </PageShell>;
}

function CoverageBar({ row, maximum }: { row: DailyTrendRow; maximum: number }) {
  const coverage = row.collectorCoverage.listeningCoveragePercent ?? 0;
  return <article className="trend-row"><time dateTime={row.date}>{row.date}</time><div className="trend-bars"><progress className="discovery" max={Math.max(1, maximum)} value={row.discovery.uniqueSignals} title={`${row.discovery.uniqueSignals} unique signals`}>{row.discovery.uniqueSignals}</progress><progress className="coverage" max={100} value={coverage} title={`${coverage}% listening coverage`}>{coverage}%</progress></div><strong>{row.discovery.uniqueSignals}</strong><small>{coverage}% coverage</small></article>;
}

function Counts({ values, empty = "No values in the public sample" }: { values: Record<string, number>; empty?: string }) {
  const entries = Object.entries(values);
  return entries.length ? <ul className="facet-counts">{entries.slice(0, 12).map(([label, value]) => <li key={label}><span>{label}</span><strong>{value}</strong></li>)}</ul> : <p className="empty-copy">{empty}</p>;
}

export function TrendsPage({ data }: { data: StaticPageData }) {
  const maximum = Math.max(0, ...data.trends.series.map((row) => row.discovery.uniqueSignals));
  const current = data.trends.series.at(-1);
  return <PageShell currentPage="trends">
    <ArtifactHero icon={Activity} eyebrow="Coverage-aware measurements" title="Discovery trends and review quality" description="Radar publishes its own activity beside collector coverage. The charts describe what this sampled pipeline saw and published. They do not estimate all Lithuanian phishing." />
    <section className="trend-boundary"><RadioTower aria-hidden="true" /><div><strong>Coverage travels with every count</strong><p>{data.trends.semantics}</p></div></section>
    <section className="trend-section"><div className="section-heading"><div><p className="eyebrow">Sparse UTC series</p><h2>Daily discovery</h2></div><a href="/data/daily-trends.json">Download JSON</a></div><div className="trend-legend"><span><i className="discovery" /> unique signals</span><span><i className="coverage" /> listening coverage</span></div><div className="trend-chart">{data.trends.series.map((row) => <CoverageBar key={row.date} row={row} maximum={maximum} />)}</div><p className="boundary-note">{data.trends.seriesSemantics} {data.trends.omittedZeroDays} zero days are omitted.</p></section>
    <section className="quality-grid"><article><p className="eyebrow">Current recorded day</p><h2>{current?.date ?? data.trends.to}</h2><dl><div><dt>Unique signals</dt><dd>{current?.discovery.uniqueSignals ?? 0}</dd></div><div><dt>First publications</dt><dd>{current?.discovery.firstPublications ?? 0}</dd></div><div><dt>Reobservations</dt><dd>{current?.discovery.reobservations ?? 0}</dd></div><div><dt>Healthy attempts</dt><dd>{current?.collectorCoverage.healthyAttempts ?? 0}</dd></div></dl></article><article><p className="eyebrow">Analyst sample</p><h2>Review coverage</h2><dl><div><dt>Eligible signals</dt><dd>{data.quality.reviewCoverage.eligiblePublishedSignals}</dd></div><div><dt>Assessed</dt><dd>{data.quality.reviewCoverage.assessedSignals}</dd></div><div><dt>Coverage</dt><dd>{data.quality.reviewCoverage.percent ?? "Unavailable"}{data.quality.reviewCoverage.percent !== null ? "%" : ""}</dd></div><div><dt>Median latency</dt><dd>{data.quality.reviewLatencyHours.median ?? "Unavailable"}{data.quality.reviewLatencyHours.median !== null ? "h" : ""}</dd></div></dl></article><article className="quality-warning"><p className="eyebrow">Precision</p><h2>Not supportable yet</h2><p>{data.quality.precision.reason}</p></article></section>
    <section className="quality-facets"><article><h3>Review outcomes</h3><Counts values={data.quality.reviewSample.outcomes} /></article><article><h3>Evidence in reviewed sample</h3><Counts values={data.quality.reviewSample.byEvidence} /></article><article><h3>Current exclusions</h3><Counts values={data.quality.currentExclusions.byReason} /></article></section>
  </PageShell>;
}

export function AssociationsPage({ data }: { data: StaticPageData }) {
  return <PageShell currentPage="associations"><ArtifactHero icon={Waypoints} eyebrow="Evidence graph" title="Published associations" description="Inspect every bounded relationship Radar can support from shared hashes, certificates, redirects, network context, and DNS. Association never means attribution." /><AssociationExplorer signals={data.snapshot.signals} artifact={data.related} /></PageShell>;
}

export function ToolsPage({ data }: { data: StaticPageData }) {
  return <PageShell currentPage="tools"><ArtifactHero icon={ShieldCheck} eyebrow="Browser-only defensive utility" title="Check your indicators locally" description="Compare domains, URLs, and hashes with Radar's current and retained public records. The comparison happens in browser memory; submitted values are never sent to HECAVEX." /><BrowserIocChecker signals={data.snapshot.signals} history={data.history} /></PageShell>;
}

const downloads = [
  ["Current defanged snapshot", "/data/radar.json", "JSON"],
  ["Current snapshot index", "/data/radar.index.json", "JSON"],
  ["Observation bundle", "/data/radar.stix.json", "STIX 2.1"],
  ["Reviewed indicators and sightings", "/data/radar-reviewed.stix.json", "STIX 2.1"],
  ["Event record", "/data/events.json", "JSON"],
  ["Daily coverage-aware trends", "/data/daily-trends.json", "JSON"],
  ["Public review quality", "/data/quality-metrics.json", "JSON"],
  ["Association graph", "/data/related-observations.json", "JSON"],
  ["Release manifest", "/data/feed-manifest.json", "JSON"],
] as const;

export function DatasetPage({ data }: { data: StaticPageData }) {
  return <PageShell currentPage="dataset"><ArtifactHero icon={Database} eyebrow="Public data catalogue" title="Radar dataset distributions" description="Machine-readable, bounded defensive research artifacts with schemas, checksums, retention semantics, and explicit safety limits." />
    <section className="dataset-summary"><div><span>Snapshot generated</span><strong>{formatDateTime(data.snapshot.generatedAt)} UTC</strong></div><div><span>Current signals</span><strong>{data.snapshot.signals.length}</strong></div><div><span>History records</span><strong>{data.history.signals.length}</strong></div><div><span>Event window</span><strong>{data.events.window.days} days</strong></div></section>
    <section className="download-grid" aria-label="Dataset downloads">{downloads.map(([title, href, format]) => <a href={href} key={href}><FileCheck2 aria-hidden="true" /><span><strong>{title}</strong><small>{format}</small></span><Download aria-hidden="true" /></a>)}</section>
    <section className="dataset-explanation"><article><p className="eyebrow">Integrity</p><h2>Verify before use</h2><p>Every canonical artifact has a SHA-256 sidecar and appears in the release manifest. Weekly release archives are attested through GitHub when the scheduled release succeeds.</p><a href="https://github.com/Hecavex/hecavex-radar/releases" target="_blank" rel="noreferrer noopener">Weekly releases <ExternalLink aria-hidden="true" /></a></article><article><p className="eyebrow"><GitCompareArrows aria-hidden="true" /> Semantics</p><h2>Signals, not verdicts</h2><p>Defanged dashboard rows are discovery leads. Only the reviewed STIX distribution contains analyst-confirmed Indicators. Missing rows, enrichment, or review are unknown.</p><a href="/docs/#data-contract">Read the data contract →</a></article></section>
  </PageShell>;
}

export function StaticPage({ kind, data }: { kind: StaticPageKind; data: StaticPageData }) {
  if (kind === "changes") return <ChangesPage data={data} />;
  if (kind === "trends") return <TrendsPage data={data} />;
  if (kind === "associations") return <AssociationsPage data={data} />;
  if (kind === "tools") return <ToolsPage data={data} />;
  return <DatasetPage data={data} />;
}
