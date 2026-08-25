const flow = [
  ["01", "Surinkti", "Riboti Python rinktuvai skaito pasyvius sertifikatų įvykius ir jau paskelbtas viešas ataskaitas."],
  ["02", "Archyvuoti", "Patikrinti ir neutralizuoti stebėjimai saugomi pagal datą suskirstytuose NDJSON failuose."],
  ["03", "Sinchronizuoti", "Leidėjas iš naujo patikrina, apriboja, sujungia ir atominiu būdu įrašo viešus duomenis."],
  ["04", "Atvaizduoti", "Statinė React sąsaja patikrina suvestinės struktūrą ir pateikia tik skaitymui skirtus vaizdus."],
] as const;

const sources = [
  ["CertStream", "Atrankinis tiesioginis Certificate Transparency įvykių klausymas suplanuotais langais.", "Dalis įvykių už klausymosi langų gali būti nepastebėta."],
  ["Ribota CT paieška", "Kontroliniais taškais paremta crt.sh paieška pagal peržiūrėtus prekių ženklų terminus.", "Indeksavimas, užklausų ribos ir ribotas terminų rinkinys mažina aprėptį."],
  ["URLScan", "Tik jau egzistuojančių viešų rezultatų paieška ir viešų detalių gavimas.", "Radaras nepateikia naujo skenavimo; rezultato nebuvimas nėra saugumo požymis."],
  ["HECAVEX", "Pasirinktinė, aiškiai sukonfigūruota ir prieš skelbimą neutralizuota vieša įvestis.", "Vidiniai šaltiniai, analitiko užrašai ir privati istorija nėra skelbiami."],
  ["DNS ir RDAP", "Ribotas jau paskelbtų kandidatų domeno ir registracijos kontekstas.", "Bendra infrastruktūra yra sąsaja, o ne savininko ar veikėjo priskyrimas."],
] as const;

const fields = [
  ["id", "Deterministinis 20 šešioliktainių simbolių signalo identifikatorius."],
  ["url / domain", "Normalizuotas ir neutralizuotas HTTP(S) indikatorius bei domenas; prisijungimo duomenys, užklausos ir fragmentai pašalinami."],
  ["firstSeen / lastSeen", "Ankstyviausias ir vėliausias priimto stebėjimo laikas UTC."],
  ["sources", "Pasikartojimų neturintis šaltinių sąrašas: CertStream, URLScan arba HECAVEX."],
  ["status", "Gyvavimo ciklo būsena; automatizuoti CertStream ir URLScan įrašai lieka įtariami."],
  ["brand", "Pagal registrą nustatytas galimas prekių ženklas, o ne grėsmės veikėjo priskyrimas."],
  ["country / host", "Stebėtas prieglobos kontekstas, o ne operatoriaus vieta ar tapatybė."],
  ["matchScore", "0–100 taisyklių atitikimo balas; ne tikimybė, pasitikėjimas ar kenkėjiškumo nuosprendis."],
  ["evidenceTier", "Tik pavadinimo, papildomai patvirtintas arba analitiko peržiūrėtas įrodymų lygis."],
  ["reasonCodes", "Kontroliuojamos įtraukimo priežastys ir kilmės žymos, o ne įrodymai apie ketinimą."],
] as const;

const operations = [
  ["CertStream rinkimas", "08, 23, 38 ir 53 minutę kiekvieną UTC valandą", "Kandidatų archyvas ir naujausio bandymo būklė"],
  ["Kontroliniais taškais paremta CT paieška", "43 minutę kiekvieną UTC valandą", "Peržiūrėtų terminų žymekliai ir CT kandidatai"],
  ["URLScan paieška", "37 minutę kas antrą UTC valandą", "Ribota paieškos būsena ir vieši rezultatai"],
  ["DNS ir RDAP kontekstas", "01:13, 07:13, 13:13 ir 19:13 UTC", "Jau paskelbtų kandidatų ribotas kontekstas"],
  ["Suvestinės sinchronizavimas", "17 minutę kiekvieną UTC valandą", "Dabartinė suvestinė, detalės ir istorija"],
] as const;

export function LtDocumentation() {
  return <article className="docs-content" aria-labelledby="documentation-title">
    <header className="docs-heading">
      <div><p className="eyebrow">Pagrindinė dokumentacija</p><h1 id="documentation-title">HECAVEX Radaro techninis žinynas</h1></div>
      <p>Architektūra, šaltinių veikimas, viešos schemos, eksploatavimo ribos ir duomenų sąlygos, taikomos HECAVEX prižiūrimai paslaugai radar.hecavex.com. Aptikimo metodika atskirai aprašyta <a href="/lt/metodologija/">metodologijos puslapyje</a>.</p>
    </header>

    <nav className="docs-toc" aria-label="Dokumentacijos skyriai"><span>Turinys</span><div>
      <a href="#architektura">Architektūra</a><a href="#saltiniai">Šaltiniai</a><a href="#viesi-duomenys">Vieši duomenys</a><a href="#stix">STIX</a><a href="#duomenu-sutartis">Duomenų sutartis</a><a href="#istorija">Istorija</a><a href="#veikimas">Veikimas</a><a href="#saugumas">Saugumas</a><a href="#duomenu-salygos">Duomenų sąlygos</a>
    </div></nav>

    <section className="docs-section" id="architektura"><div className="docs-section-heading"><p className="eyebrow">Architektūra</p><h2>Python duomenų srautas, statinė sąsaja</h2><p>Naršyklė neturi programų serverio, paskyrų sistemos ar tiesioginio ryšio su duomenų baze.</p></div>
      <ol className="docs-flow" aria-label="Radaro duomenų srautas">{flow.map(([number, title, body]) => <li key={number}><span>{number}</span><h3>{title}</h3><p>{body}</p></li>)}</ol>
      <div className="docs-callout"><strong>Skelbimo riba</strong><p>Tik sinchronizavimo procesas rašo viešą suvestinę. Neprieinamas pasirinktinis šaltinis negali ištrinti sveikų šaltinių duomenų, o netikėtas staigus sumažėjimas sustabdo skelbimą.</p></div>
    </section>

    <section className="docs-section" id="saltiniai"><div className="docs-section-heading"><p className="eyebrow">Šaltiniai</p><h2>Ką kiekvienas šaltinis gali pagrįsti</h2><p>Šaltinio etiketė aprašo stebėjimo kilmę. Ji nereiškia patvirtinto kenkėjiškumo.</p></div>
      <div className="docs-table-wrap" role="region" aria-label="Duomenų šaltinių semantika" tabIndex={0}><table className="docs-table"><thead><tr><th>Šaltinis</th><th>Naudojimas</th><th>Aprėpties riba</th></tr></thead><tbody>{sources.map(([name, use, limit]) => <tr key={name}><th scope="row">{name}</th><td>{use}</td><td>{limit}</td></tr>)}</tbody></table></div>
    </section>

    <section className="docs-section" id="viesi-duomenys"><div className="docs-section-heading"><p className="eyebrow">Vieši duomenys</p><h2>Vienas skelbimo rinkinys, keli vaizdai</h2><p>Skydelis, istorija, įvykių žurnalas, STIX ir atsisiunčiami JSON failai kuriami iš tos pačios patikrintos publikavimo ribos.</p></div>
      <div className="docs-card-grid"><article><h3>Dabartinė suvestinė</h3><p>Ribotas naujausių priimtų kandidatų vaizdas. Eilutės neutralizuotos ir nėra automatinis blokavimo sąrašas.</p><a href="/data/radar.json">Atverti radar.json</a></article><article><h3>Išsaugota istorija</h3><p>Pirmo ir paskutinio stebėjimo laikas, stebėjimų skaičius ir tik aiškiai užfiksuoti būsenos pokyčiai.</p><a href="/history/">Atverti istoriją anglų kalba</a></article><article><h3>Įvykių žurnalas</h3><p>Pirmosios publikacijos, pakartotiniai stebėjimai, būsenos pokyčiai ir aiškūs atšaukimai.</p><a href="/lt/pokyciai/">Atverti pokyčius</a></article></div>
    </section>

    <section className="docs-section" id="stix"><div className="docs-section-heading"><p className="eyebrow">STIX 2.1</p><h2>Stebėjimai atskirti nuo patvirtintų indikatorių</h2><p>Vieša projekcija nėra TAXII paslauga ir nėra skirta automatiniam blokavimui.</p></div>
      <div className="docs-card-grid"><article><h3>Stebėjimų rinkinys</h3><p><code>radar.stix.json</code> pateikia galimų arba įtariamų domenų vardų stebėjimus su aiškiomis ribomis.</p><a href="/data/radar.stix.json">Atsisiųsti STIX stebėjimus</a></article><article><h3>Peržiūrėtas rinkinys</h3><p><code>radar-reviewed.stix.json</code> gali turėti tik aiškiai ir laikinai analitiko patvirtintus indikatorius.</p><a href="/data/radar-reviewed.stix.json">Atsisiųsti peržiūrėtą STIX</a></article></div>
    </section>

    <section className="docs-section" id="duomenu-sutartis"><div className="docs-section-heading"><p className="eyebrow">Duomenų sutartis</p><h2>Stabilūs viešos suvestinės laukai</h2><p>Trūkstama pasirenkama reikšmė reiškia nežinomybę, o ne neigiamą išvadą.</p></div>
      <div className="docs-table-wrap" role="region" aria-label="Viešos suvestinės laukų žinynas" tabIndex={0}><table className="docs-table"><thead><tr><th>Laukas</th><th>Reikšmė</th></tr></thead><tbody>{fields.map(([term, description]) => <tr key={term}><th scope="row"><code>{term}</code></th><td>{description}</td></tr>)}</tbody></table></div>
    </section>

    <section className="docs-section" id="istorija"><div className="docs-section-heading"><p className="eyebrow">Istorija ir peržiūra</p><h2>Įvykiai pridedami, o nebuvimas neinterpretuojamas</h2><p>Pakartotinai apdorojant tuos pačius archyvus deterministiniai įvykių ID neleidžia dirbtinai didinti skaičių.</p></div>
      <div className="docs-card-grid"><article><h3>Detalus laikotarpis</h3><p>Pagal datą suskirstyti įvykiai numatytą laiką lieka detalūs, vėliau sutraukiami į ribotą signalo istoriją.</p></article><article><h3>Būsenos kilmė</h3><p>Dingimas iš naujausio lango nesukuria būsenos pokyčio. Aktyvi, nepasiekiama ar suvaldyta būsena reikalauja palaikomo aiškaus stebėjimo.</p></article><article><h3>Analitiko peržiūra</h3><p>Vidiniai užrašai ir tapatybės lieka už Git ribų. Viešai pateikiami tik sąmoningai eksportuoti ir neutralizuoti sprendimai.</p></article></div>
    </section>

    <section className="docs-section" id="veikimas"><div className="docs-section-heading"><p className="eyebrow">Veikimas</p><h2>Suplanuoti darbai ir jų vieši rezultatai</h2><p>Grafikas aprašo numatytą pradžią, o ne garantuotą nenutrūkstamą aprėptį.</p></div>
      <div className="docs-table-wrap" role="region" aria-label="Suplanuoti Radaro darbai" tabIndex={0}><table className="docs-table"><thead><tr><th>Darbas</th><th>Grafikas</th><th>Viešas rezultatas</th></tr></thead><tbody>{operations.map(([name, schedule, result]) => <tr key={name}><th scope="row">{name}</th><td>{schedule}</td><td>{result}</td></tr>)}</tbody></table></div>
    </section>

    <section className="docs-section" id="saugumas"><div className="docs-section-heading"><p className="eyebrow">Saugumas</p><h2>Neutrali, tik skaitymui skirta vieša sąsaja</h2><p>Radaro puslapiai nevykdo kandidatų turinio ir nepaverčia neutralizuotų indikatorių tiesioginėmis nuorodomis.</p></div>
      <div className="docs-card-grid"><article><h3>Įvesties ribos</h3><p>Vieši duomenys tikrinami pagal schemą, dydžio ribas, leidžiamus protokolus ir kontroliuojamas reikšmes.</p></article><article><h3>Išorinės nuorodos</h3><p>Įrodymų nuorodos leidžiamos tik į patikrintus viešus URLScan išteklius ir atveriamos tik naudotojui pasirinkus.</p></article><article><h3>Vietinis IOC įrankis</h3><p>Įklijuotos reikšmės ir failai apdorojami naršyklės atmintyje, neįkeliami į HECAVEX ir išnyksta atnaujinus ar užvėrus puslapį.</p></article></div>
    </section>

    <section className="docs-section" id="duomenu-salygos"><div className="docs-section-heading"><p className="eyebrow">Duomenų sąlygos</p><h2>Gynybinis tyrimas, ne reputacijos paslauga</h2><p>Duomenys skelbiami geriausiomis pastangomis ir be stebėjimo, pranešimo, reagavimo, pašalinimo ar pasiekiamumo SLA.</p></div>
      <div className="docs-callout"><strong>Naudokite kaip tyrimo kryptį</strong><p>Įtraukimas neįrodo kenkėjiškumo, o nebuvimas neįrodo saugumo. Prieš blokavimą ar viešą teiginį patikrinkite šaltinį, laiką, kontekstą ir įrodymų lygį.</p></div>
      <p className="methodology-report">Apie galimą klaidingą teigiamą rezultatą praneškite adresu <a href="mailto:info@hecavex.com?subject=HECAVEX%20Radar%20klaidingas%20teigiamas%20rezultatas">info@hecavex.com</a>, nurodydami signalo ID ir patikrinamą pagrindimą.</p>
    </section>
  </article>;
}
