import { ChevronDown, Clock3, SearchX, ShieldCheck } from "lucide-react";

import { CollectionHealth } from "./CollectionHealth.tsx";
import type { SiteLanguage } from "./SiteHeader.tsx";

export function CollectionDisclosure({ language = "en" }: { language?: SiteLanguage }) {
  const lt = language === "lt";

  return (
    <section className="collection-disclosure" aria-labelledby="collection-disclosure-title">
      <div className="collection-disclosure-heading">
        <div>
          <p className="eyebrow">{lt ? "Aprėpties ribos" : "Coverage disclosure"}</p>
          <h2 id="collection-disclosure-title">
            {lt ? "Atrankinis aptikimas, o ne nuolatinė stebėsena" : "Sampled discovery, not continuous monitoring"}
          </h2>
        </div>
        {lt ? (
          <p>
            Radaras yra geriausių pastangų principu vykdomas viešas tyrimas. Jis neužtikrina išsamios aprėpties ir
            neteikia stebėsenos, pranešimų, turinio pašalinimo ar reagavimo į incidentus paslaugų.
          </p>
        ) : (
          <p>
            Radar is best-effort public research—not comprehensive coverage, monitoring, notification, takedown, or an
            incident-response service.
          </p>
        )}
      </div>
      <div className="collection-disclosure-grid">
        <article>
          <Clock3 aria-hidden="true" />
          <div>
            <h3>{lt ? "768 suplanuotos minutės per parą" : "768 scheduled minutes per day"}</h3>
            {lt ? (
              <p>
                CertStream darbo eiga suplanuota 96 kartus per parą po aštuonias minutes, daugiausia 53,3 % paros.
                GitHub Actions gali pradėti vėliau, praleisti suplanuotą paleidimą arba nepavykti, todėl faktinis ryšio
                laikas gali būti trumpesnis. Naujausias išmatuotas bandymas rodomas toliau.
              </p>
            ) : (
              <p>
                The CertStream workflow is scheduled 96 times daily for eight minutes: at most 53.3% of a day. GitHub
                Actions may start late, drop a schedule, or fail, so actual connection time can be lower. The latest
                measured attempt is shown below.
              </p>
            )}
          </div>
        </article>
        <article>
          <SearchX aria-hidden="true" />
          <div>
            <h3>{lt ? "Kai URLScan duomenų nėra, būsena lieka nežinoma" : "Missing URLScan evidence is unknown"}</h3>
            {lt ? (
              <p>
                URLScan papildymas apsiriboja jau esamomis viešomis ataskaitomis. Rezultato nebuvimas nėra saugumo
                patvirtinimas ir neslopina nepriklausomai kriterijus atitinkančio sertifikato kandidato.
              </p>
            ) : (
              <p>
                URLScan enrichment is limited to existing public reports. No result is not a benign verdict and does not
                suppress an independently qualifying certificate candidate.
              </p>
            )}
          </div>
        </article>
        <article>
          <ShieldCheck aria-hidden="true" />
          <div>
            <h3>{lt ? "Signalai yra tyrimo kryptys" : "Signals are leads"}</h3>
            {lt ? (
              <p>
                Eilutė ir jos 0–100 atitikties balas neįrodo kenkėjiškų ketinimų ir nėra jų tikimybė. Prieš imdamiesi
                veiksmų įvertinkite šaltinį, įrodymus, laiką ir apribojimus.
              </p>
            ) : (
              <p>
                A row and its 0–100 matching score are neither proof nor probability of malicious intent. Review the
                source, evidence, timing, and limitations before acting.
              </p>
            )}
          </div>
        </article>
      </div>
      <details className="collection-health-disclosure">
        <summary>
          <span>
            <strong>{lt ? "Naujausio CertStream bandymo telemetrija" : "Latest CertStream attempt telemetry"}</strong>
            <small>
              {lt
                ? "Faktinis laikas, įvesties kiekiai, tvarkaraščio būsena ir šviežumas"
                : "Actual timing, input counts, schedule state, and freshness"}
            </small>
          </span>
          <span className="collection-health-toggle-label">{lt ? "Rodyti informaciją" : "View details"}</span>
          <ChevronDown aria-hidden="true" />
        </summary>
        <CollectionHealth language={language} />
      </details>
      <p className="collection-disclosure-links">
        <a href={lt ? "/lt/metodologija/#rinkimas" : "/methodology/#collection"}>
          {lt ? "Duomenų rinkimo metodologija" : "Collection methodology"}
        </a>
        <a href="/docs/#operations">
          {lt ? "Tvarkaraščiai ir šaltinių būsenų reikšmės" : "Schedules and source-state semantics"}
        </a>
      </p>
    </section>
  );
}
