import { AlertTriangle, ArrowDown, Clock3, Database, Search, ShieldCheck } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { signalEvidenceTier, signalMatchScore } from "../lib/dashboard.ts";
import { signalPath } from "../lib/signalRoutes.ts";
import type { RadarSignal, RadarSnapshot, SignalStatus } from "../types.ts";
import { formatDateTimeLt, formatNumberLt, formatRelativeTimeLt, statusLt } from "./formatLt.ts";

const PAGE_SIZE = 12;

type LtFilters = {
  query: string;
  status: SignalStatus | "all";
  brand: string;
};

const INITIAL_FILTERS: LtFilters = { query: "", status: "all", brand: "all" };

function evidenceLabel(signal: RadarSignal): string {
  const tier = signalEvidenceTier(signal);
  if (tier === "reviewed") return "peržiūrėta analitiko";
  if (tier === "corroborated") return "patvirtinta papildomu šaltiniu";
  return "tik pavadinimo signalas";
}

export function LtRadarOverview({ snapshot, now = Date.now() }: { snapshot: RadarSnapshot; now?: number }) {
  const [filters, setFilters] = useState<LtFilters>(INITIAL_FILTERS);
  const [page, setPage] = useState(1);
  const brands = useMemo(
    () => [...new Set(snapshot.signals.map((signal) => signal.brand).filter((value): value is string => Boolean(value)))].sort(),
    [snapshot.signals],
  );
  const visible = useMemo(() => {
    const query = filters.query.trim().toLocaleLowerCase("lt");
    return snapshot.signals
      .filter((signal) => (
        (filters.status === "all" || signal.status === filters.status) &&
        (filters.brand === "all" || signal.brand === filters.brand) &&
        (!query || `${signal.domain} ${signal.brand ?? ""} ${signal.host ?? ""}`.toLocaleLowerCase("lt").includes(query))
      ))
      .sort((left, right) => Date.parse(right.lastSeen) - Date.parse(left.lastSeen));
  }, [filters, snapshot.signals]);
  const pages = Math.max(1, Math.ceil(visible.length / PAGE_SIZE));
  const pageSignals = visible.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);
  const lastDay = snapshot.signals.filter((signal) => now - Date.parse(signal.lastSeen) <= 86_400_000).length;
  const corroborated = snapshot.signals.filter((signal) => signalEvidenceTier(signal) !== "name-only").length;

  useEffect(() => setPage(1), [filters]);
  useEffect(() => setPage((current) => Math.min(current, pages)), [pages]);

  return (
    <main id="main-content" className="lt-radar-page">
      <section className="lt-radar-hero" aria-labelledby="lt-radar-title">
        <div>
          <p className="eyebrow"><ShieldCheck aria-hidden="true" /> Vieši grėsmių signalai Lietuvai</p>
          <h1 id="lt-radar-title">Galimos apsimetimo svetainės.<br /><span>Neseniai pastebėtos.</span></h1>
          <p>
            Viešas, tik skaitymui skirtas galimų sukčiavimo domenų ir URL vaizdas. Rodomi adresai yra
            neutralizuoti, o automatinis atitikimas nėra kenkėjiškumo nuosprendis.
          </p>
          <div className="hero-actions">
            <a className="hero-action-primary" href="#signalai"><ArrowDown aria-hidden="true" /> Peržiūrėti signalus</a>
            <a href="/lt/metodologija/">Kaip veikia atranka</a>
          </div>
        </div>
        <aside className="lt-freshness" aria-label="Duomenų šviežumas">
          <Clock3 aria-hidden="true" />
          <span>Paskutinis sėkmingas sinchronizavimas</span>
          <strong>{formatRelativeTimeLt(snapshot.lastSuccessfulSyncAt, now)}</strong>
          <small>{formatDateTimeLt(snapshot.lastSuccessfulSyncAt)} Lietuvos laiku</small>
        </aside>
      </section>

      <section className="lt-stat-strip" aria-label="Dabartinė suvestinė">
        <div><Database aria-hidden="true" /><span>Dabartinių signalų</span><strong>{formatNumberLt(snapshot.signals.length)}</strong></div>
        <div><Clock3 aria-hidden="true" /><span>Stebėta per 24 val.</span><strong>{formatNumberLt(lastDay)}</strong></div>
        <div><ShieldCheck aria-hidden="true" /><span>Su papildomu kontekstu</span><strong>{formatNumberLt(corroborated)}</strong></div>
        <div><AlertTriangle aria-hidden="true" /><span>Galimų prekių ženklų</span><strong>{formatNumberLt(brands.length)}</strong></div>
      </section>

      <section className="lt-signal-section" id="signalai" aria-labelledby="lt-signals-title">
        <header className="section-heading">
          <div><p className="eyebrow">Signalų srautas</p><h2 id="lt-signals-title">Neseniai pastebėti kandidatai</h2></div>
          <p><strong>{formatNumberLt(visible.length)}</strong> iš {formatNumberLt(snapshot.signals.length)}</p>
        </header>
        <div className="lt-filter-bar">
          <label className="lt-search"><Search aria-hidden="true" /><span className="sr-only">Ieškoti</span><input type="search" value={filters.query} onChange={(event) => setFilters({ ...filters, query: event.target.value })} placeholder="Domenas, prekių ženklas arba priegloba..." /></label>
          <label><span className="sr-only">Būsena</span><select value={filters.status} onChange={(event) => setFilters({ ...filters, status: event.target.value as LtFilters["status"] })}><option value="all">Visos būsenos</option>{Object.entries(statusLt).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label>
          <label><span className="sr-only">Prekių ženklas</span><select value={filters.brand} onChange={(event) => setFilters({ ...filters, brand: event.target.value })}><option value="all">Visi galimi prekių ženklai</option>{brands.map((brand) => <option key={brand}>{brand}</option>)}</select></label>
          {(filters.query || filters.status !== "all" || filters.brand !== "all") && <button type="button" onClick={() => setFilters(INITIAL_FILTERS)}>Išvalyti filtrus</button>}
        </div>

        {pageSignals.length ? (
          <div className="table-panel"><div className="table-scroll" role="region" aria-label="Galimi sukčiavimo signalai" tabIndex={0}>
            <table className="lt-signal-table">
              <thead><tr><th scope="col">Kandidatas</th><th scope="col">Galimas taikinys</th><th scope="col">Įrodymai</th><th scope="col">Priegloba</th><th scope="col">Laikas</th></tr></thead>
              <tbody>{pageSignals.map((signal) => <tr key={signal.id}>
                <td data-label="Kandidatas"><a className="lt-signal-link" href={signalPath(signal, "lt")}><code>{signal.url}</code></a><span>{signal.domain}</span></td>
                <td data-label="Galimas taikinys"><strong>{signal.brand ?? "Neklasifikuota"}</strong><span>{signal.sources.join(" · ")}</span></td>
                <td data-label="Įrodymai"><span className={`status-pill ${signal.status}`}><i aria-hidden="true" />{statusLt[signal.status]}</span><strong>{signalMatchScore(signal)}/100</strong><small>{evidenceLabel(signal)}</small></td>
                <td data-label="Priegloba"><strong>{signal.host ?? "Nežinoma"}</strong><span>{signal.country ?? "Šalis nežinoma"}</span></td>
                <td data-label="Laikas"><time dateTime={signal.lastSeen}>{formatRelativeTimeLt(signal.lastSeen, now)}</time><span title={formatDateTimeLt(signal.firstSeen)}>Pirmą kartą {formatRelativeTimeLt(signal.firstSeen, now)}</span></td>
              </tr>)}</tbody>
            </table>
          </div><div className="pagination"><p>Rodoma <strong>{(page - 1) * PAGE_SIZE + 1}–{Math.min(page * PAGE_SIZE, visible.length)}</strong> iš {visible.length}</p><div><button type="button" disabled={page === 1} onClick={() => setPage((value) => value - 1)}>Ankstesnis</button><span>Puslapis <strong>{page}</strong> iš {pages}</span><button type="button" disabled={page === pages} onClick={() => setPage((value) => value + 1)}>Kitas</button></div></div></div>
        ) : <div className="empty-state"><h3>Atitinkančių signalų nėra</h3><p>Pakeiskite paiešką arba filtrus.</p></div>}
      </section>

      <aside className="lt-boundary-note">
        <strong>Svarbi riba</strong>
        <p>Trūkstamas URLScan rezultatas nereiškia, kad domenas saugus. Peradresavimas taip pat nėra klaidingo teigiamo rezultato įrodymas: turinys gali priklausyti nuo lankytojo, laiko ar maskavimo taisyklių.</p>
      </aside>
    </main>
  );
}
