import { ExternalLink, Search, ShieldCheck } from "lucide-react";
import { useMemo, useState } from "react";

import { SiteHeader } from "../components/SiteHeader.tsx";
import { brandEntries, brandPath, brandRegistryReviewedAt, defangDomain } from "../lib/brandRegistry.ts";
import { LtFooter } from "./LtFooter.tsx";
import { categoryLt, formatNumberLt } from "./formatLt.ts";

const categories = [...new Set(brandEntries.map((entry) => entry.category))].sort();

export function LtBrandRegistryPage() {
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState("all");
  const filtered = useMemo(() => {
    const needle = query.trim().toLocaleLowerCase("lt");
    return brandEntries.filter((entry) => (
      (category === "all" || entry.category === category) &&
      (!needle || [entry.brand, entry.category, ...entry.aliases, ...(entry.fuzzyAliases ?? []), ...entry.officialDomains]
        .some((value) => value.toLocaleLowerCase("lt").includes(needle)))
    ));
  }, [category, query]);
  const domainCount = new Set(brandEntries.flatMap((entry) => entry.officialDomains)).size;

  return <div className="site-shell">
    <SiteHeader currentPage="brands" language="lt" alternateHref="/brands/" />
    <main id="main-content" className="lt-brand-page">
      <section className="lt-page-heading">
        <div><p className="eyebrow"><ShieldCheck aria-hidden="true" /> Vieša aptikimo apimtis</p><h1>Peržiūrėtas Lietuvos prekių ženklų registras</h1></div>
        <p>Radaras tikrina sertifikatų vardus ir viešas skenavimo ataskaitas pagal šį ribotą registrą. Įtraukimas reiškia tik aptikimo apimtį. Jis nereiškia, kad prekių ženklas buvo atakuotas.</p>
      </section>
      <section className="lt-stat-strip" aria-label="Registro suvestinė">
        <div><span>Peržiūrėti prekių ženklai</span><strong>{formatNumberLt(brandEntries.length)}</strong></div>
        <div><span>Oficialūs domenai</span><strong>{formatNumberLt(domainCount)}</strong></div>
        <div><span>Kategorijos</span><strong>{formatNumberLt(categories.length)}</strong></div>
        <div><span>Registras peržiūrėtas</span><strong>{brandRegistryReviewedAt}</strong></div>
      </section>
      <section className="lt-registry-boundaries">
        <header><p className="eyebrow">Kaip interpretuoti</p><h2>Ką valdo šis registras</h2></header>
        <dl>
          <div><dt>Pavadinimai</dt><dd>Tikslūs ir atskirai įjungti apytiksliai pavadinimai gali pradėti atitikimą tik tada, kai domeno kontekstas taip pat atitinka taisykles.</dd></div>
          <div><dt>Oficialūs domenai</dt><dd>Teisėtos svetainės ir jų subdomenai atmetami dar prieš skaičiuojant atitiktį.</dd></div>
          <div><dt>Išimtys</dt><dd>Patikrinti žodžių sutapimai mažina numatomus klaidingus teigiamus rezultatus, bet neslepia bendros infrastruktūros.</dd></div>
          <div><dt>Šaltiniai</dt><dd>Pirmosios šalies nuorodos pagrindžia tapatybę ir oficialių domenų aprėptį. Jos nėra įrodymas prieš kandidatą.</dd></div>
        </dl>
      </section>
      <section className="lt-registry" aria-labelledby="lt-registry-title">
        <header className="section-heading"><div><p className="eyebrow">Dabartinis registras</p><h2 id="lt-registry-title">Prekių ženklai ir oficialios svetainės</h2></div><p><strong>{filtered.length}</strong> iš {brandEntries.length}</p></header>
        <p className="lt-registry-scope">Tai vieša, peržiūrima prekių ženklų, kuriais dažnai apsimetama Lietuvoje, pradinė apimtis. Registras nėra baigtinis.</p>
        <div className="lt-filter-bar">
          <label className="lt-search"><Search aria-hidden="true" /><span className="sr-only">Ieškoti registre</span><input type="search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Prekių ženklas, pavadinimas arba oficialus domenas..." /></label>
          <label><span className="sr-only">Kategorija</span><select value={category} onChange={(event) => setCategory(event.target.value)}><option value="all">Visos kategorijos</option>{categories.map((value) => <option key={value} value={value}>{categoryLt[value] ?? value}</option>)}</select></label>
        </div>
        <div className="lt-brand-grid">{filtered.map((entry) => <article key={entry.brand}>
          <header><div><a href={brandPath(entry.brand, "lt")}><h3>{entry.brand}</h3></a><span>{categoryLt[entry.category] ?? entry.category}</span></div><a href={entry.sources[0]} target="_blank" rel="noreferrer noopener" aria-label={`${entry.brand} pirmosios šalies šaltinis`}><ExternalLink aria-hidden="true" /></a></header>
          <dl><div><dt>Oficialūs domenai</dt><dd>{entry.officialDomains.map((domain) => <code key={domain}>{defangDomain(domain)}</code>)}</dd></div><div><dt>Atpažįstami pavadinimai</dt><dd>{entry.aliases.map((alias) => <code key={alias}>{alias}</code>)}</dd></div>{entry.fuzzyAliases?.length ? <div><dt>Riboti apytiksliai pavadinimai</dt><dd>{entry.fuzzyAliases.map((alias) => <code key={alias}>{alias}</code>)}</dd></div> : null}</dl>
          <a className="lt-brand-detail" href={brandPath(entry.brand, "lt")}>Atverti prekių ženklo veiklą →</a>
        </article>)}</div>
        {!filtered.length && <div className="empty-state"><h3>Registro įrašų nerasta</h3><p>Pakeiskite paiešką arba kategoriją.</p></div>}
      </section>
    </main>
    <LtFooter />
  </div>;
}
