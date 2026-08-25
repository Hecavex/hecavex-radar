import { AlertTriangle, Archive, Clock3, RefreshCw, Search, ShieldCheck } from "lucide-react";
import { useEffect, useState } from "react";

import { SiteHeader } from "../components/SiteHeader.tsx";
import { loadSnapshot } from "../lib/data.ts";
import { loadHistory } from "../lib/historyData.ts";
import { signalPath } from "../lib/signalRoutes.ts";
import type { RadarHistory, RadarSnapshot } from "../types.ts";
import { LtFooter } from "./LtFooter.tsx";
import { formatDateTimeLt, formatNumberLt, formatRelativeTimeLt, statusLt } from "./formatLt.ts";

type Props = { initialSnapshot?: RadarSnapshot; initialHistory?: RadarHistory; initialNow?: number };
type State =
  | { status: "loading" }
  | { status: "ready"; snapshot: RadarSnapshot; history: RadarHistory; now: number }
  | { status: "error"; message: string };

export function LtChangesPage({ initialSnapshot, initialHistory, initialNow }: Props = {}) {
  const [state, setState] = useState<State>(initialSnapshot && initialHistory
    ? { status: "ready", snapshot: initialSnapshot, history: initialHistory, now: initialNow ?? Date.now() }
    : { status: "loading" });
  const [query, setQuery] = useState("");

  useEffect(() => {
    if (initialSnapshot && initialHistory) return;
    const controller = new AbortController();
    void Promise.all([loadSnapshot(controller.signal), loadHistory(controller.signal)])
      .then(([snapshot, history]) => setState({ status: "ready", snapshot, history, now: Date.now() }))
      .catch((error: unknown) => {
        if (!controller.signal.aborted) setState({ status: "error", message: error instanceof Error ? error.message : "Nežinoma duomenų klaida." });
      });
    return () => controller.abort();
  }, [initialHistory, initialSnapshot]);

  return (
    <div className="site-shell">
      <SiteHeader currentPage="changes" language="lt" alternateHref="/changes/" />
      {state.status === "loading" && <main className="state-page" id="main-content" aria-live="polite"><Archive className="state-icon pulse" aria-hidden="true" /><p className="eyebrow">Skaitomas archyvas</p><h1>Kraunama signalų istorija</h1></main>}
      {state.status === "error" && <main className="state-page" id="main-content" aria-live="assertive"><AlertTriangle className="state-icon danger" aria-hidden="true" /><p className="eyebrow">Istorija nepasiekiama</p><h1>Nepavyko įkelti pokyčių</h1><p>{state.message}</p></main>}
      {state.status === "ready" && <LtChangesContent snapshot={state.snapshot} history={state.history} now={state.now} query={query} setQuery={setQuery} />}
      <LtFooter />
    </div>
  );
}

function LtChangesContent({ snapshot, history, now, query, setQuery }: { snapshot: RadarSnapshot; history: RadarHistory; now: number; query: string; setQuery: (value: string) => void }) {
  const cutoff = now - 86_400_000;
  const newSignals = snapshot.signals.filter((signal) => Date.parse(signal.firstSeen) >= cutoff);
  const reobserved = snapshot.signals.filter((signal) => Date.parse(signal.firstSeen) < cutoff && Date.parse(signal.lastSeen) >= cutoff);
  const transitions = history.signals.flatMap((signal) => signal.statusTransitions.map((transition) => ({ signal, transition }))).filter(({ transition }) => Date.parse(transition.observedAt) >= cutoff);
  const normalized = query.trim().toLocaleLowerCase("lt");
  const records = history.signals
    .filter((signal) => !normalized || `${signal.domain} ${signal.brand} ${signal.sources.join(" ")}`.toLocaleLowerCase("lt").includes(normalized))
    .sort((left, right) => Date.parse(right.lastSeen) - Date.parse(left.lastSeen));

  return <main id="main-content" className="lt-changes-page">
    <section className="lt-page-heading">
      <div><p className="eyebrow"><RefreshCw aria-hidden="true" /> Pokyčių žurnalas</p><h1>Kas pasikeitė radare</h1></div>
      <p>Chronologinė pirmų publikacijų, pakartotinių stebėjimų ir aiškiai šaltinio praneštų būsenos pokyčių suvestinė. Dingimas iš dabartinio sąrašo savaime nieko neįrodo.</p>
    </section>
    <section className="lt-stat-strip" aria-label="Pastarųjų 24 valandų pokyčiai">
      <div><Clock3 aria-hidden="true" /><span>Nauji signalai</span><strong>{formatNumberLt(newSignals.length)}</strong></div>
      <div><RefreshCw aria-hidden="true" /><span>Pakartotinai stebėti</span><strong>{formatNumberLt(reobserved.length)}</strong></div>
      <div><ShieldCheck aria-hidden="true" /><span>Būsenos pokyčiai</span><strong>{formatNumberLt(transitions.length)}</strong></div>
      <div><Archive aria-hidden="true" /><span>Istorijoje</span><strong>{formatNumberLt(history.signals.length)}</strong></div>
    </section>
    <section className="lt-changes-preview" aria-labelledby="lt-day-title">
      <header className="section-heading"><div><p className="eyebrow">24 valandų langas</p><h2 id="lt-day-title">Naujausia veikla</h2></div><a href="/data/events.json">Mašininiai įvykių duomenys</a></header>
      <div className="lt-change-columns">
        <article><h3>Pirmos publikacijos</h3>{newSignals.slice(0, 8).map((signal) => <a key={signal.id} href={signalPath(signal, "lt")}><code>{signal.domain}</code><span>{signal.brand ?? "Neklasifikuota"} · {formatRelativeTimeLt(signal.firstSeen, now)}</span></a>)}{!newSignals.length && <p>Naujų publikacijų šiame lange nėra.</p>}</article>
        <article><h3>Pakartotiniai stebėjimai</h3>{reobserved.slice(0, 8).map((signal) => <a key={signal.id} href={signalPath(signal, "lt")}><code>{signal.domain}</code><span>{signal.brand ?? "Neklasifikuota"} · {formatRelativeTimeLt(signal.lastSeen, now)}</span></a>)}{!reobserved.length && <p>Pakartotinių stebėjimų šiame lange nėra.</p>}</article>
      </div>
    </section>
    <section className="lt-history-index" aria-labelledby="lt-history-title">
      <header className="section-heading"><div><p className="eyebrow">Išsaugotas pėdsakas</p><h2 id="lt-history-title">Kandidatų istorija</h2></div><p>Detalės: {history.detailRetentionDays} d. · suvestinė: {history.summaryRetentionDays} d.</p></header>
      <label className="lt-search"><Search aria-hidden="true" /><span className="sr-only">Ieškoti istorijoje</span><input type="search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Domenas, prekių ženklas arba šaltinis..." /></label>
      <div className="lt-history-list">{records.slice(0, 100).map((signal) => <article key={signal.id}>
        <div><a href={signalPath(signal.id, "lt")}><code>{signal.domain}</code></a><span>{signal.brand} · {signal.sources.join(" · ")}</span></div>
        <div><strong>{statusLt[signal.latestStatus]}</strong><span>{signal.observationCount} steb. · paskutinis {formatRelativeTimeLt(signal.lastSeen, now)}</span></div>
        <details><summary>Provenencija</summary><p>Pirmas: {formatDateTimeLt(signal.firstSeen)}</p><p>Paskutinis: {formatDateTimeLt(signal.lastSeen)}</p><p>Taisyklės: {signal.reasonCodes.join(", ")}</p></details>
      </article>)}</div>
      {!records.length && <div className="empty-state"><h3>Atitinkančių istorijos įrašų nėra</h3></div>}
    </section>
  </main>;
}
