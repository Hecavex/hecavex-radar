import { SiteHeader } from "../components/SiteHeader.tsx";
import { LtFooter } from "./LtFooter.tsx";

const stages = [
  ["01", "Stebėti", "Pasyviai skaityti viešus sertifikatų įvykius, viešas URLScan ataskaitas ir aiškiai paruoštas HECAVEX įvestis."],
  ["02", "Sulyginti", "Lyginti domenus su peržiūrėtu Lietuvos prekių ženklų registru, atmetant oficialius domenus ir žinomas žodžių kolizijas."],
  ["03", "Patikrinti", "Reikalauti vieno nedviprasmiško prekių ženklo, pakankamos taisyklių atitikties ir saugių viešų laukų."],
  ["04", "Paskelbti", "Neutralizuoti adresus, sujungti to paties domeno stebėjimus ir išsaugoti aiškią kilmę bei neapibrėžtumą."],
] as const;

export function LtMethodologyPage() {
  return <div className="site-shell">
    <SiteHeader currentPage="methodology" language="lt" alternateHref="/methodology/" />
    <main id="main-content" className="lt-methodology-page">
      <section className="lt-page-heading">
        <div><p className="eyebrow">Metodologija</p><h1>Kaip signalas patenka į Radarą</h1></div>
        <p>HECAVEX Radaras yra pasyvi, paaiškinama galimų phishing ir apsimetimo svetainių atranka, orientuota į Lietuvą. Tikslumas svarbiau už kiekį, o vienas automatinis signalas niekada nelaikomas kenkėjiško ketinimo įrodymu.</p>
      </section>
      <nav className="lt-methodology-toc" aria-label="Metodologijos skyriai"><span>Šiame puslapyje</span><div><a href="#procesas">Procesas</a><a href="#rinkimas">Duomenų rinkimas</a><a href="#atitikimas">Atitikimas</a><a href="#skelbimas">Skelbimas</a><a href="#istorija">Istorija</a><a href="#ribos">Ribos ir saugumas</a></div></nav>
      <section id="procesas" className="lt-method-section"><header><p className="eyebrow">Procesas</p><h2>Keturi riboti etapai</h2></header><ol className="lt-method-steps">{stages.map(([number, title, body]) => <li key={number}><span>{number}</span><h3>{title}</h3><p>{body}</p></li>)}</ol></section>
      <section id="rinkimas" className="lt-method-section"><header><p className="eyebrow">Duomenų rinkimas</p><h2>Tik pasyvūs vieši stebėjimai</h2><p>Radaras neatveria kandidato svetainės, nesiunčia jos aktyviam skenavimui ir nepaverčia neutralizuoto adreso paspaudžiama nuoroda.</p></header><div className="lt-method-grid">
        <article><h3>CertStream</h3><p>Suplanuotas rinktuvas trumpais langais klausosi gyvų Certificate Transparency įvykių. Tai atranka, o ne dienos sertifikatų kopija: įvykiai už sėkmingo klausymosi lango nėra automatiškai atkuriami.</p></article>
        <article><h3>Ribota CT paieška</h3><p>Kontroliniu tašku paremta crt.sh paieška rotuoja per peržiūrėtus terminus ir gali atkurti dalį gyvo srauto praleistų įrašų. Paslaugos indeksavimas ir užklausų ribos vis tiek riboja aprėptį.</p></article>
        <article><h3>URLScan</h3><p>Ieškomos tik jau egzistuojančios viešos ataskaitos. Radaras pats naujo skenavimo nepateikia. Rezultatas gali suteikti puslapio pavadinimą, ekrano kopiją, maišos reikšmę ar prieglobos kontekstą.</p></article>
        <article><h3>DNS ir RDAP</h3><p>Jau paskelbti kandidatai rotuojant papildomi ribotu DNS ir registracijos kontekstu. Tai ryšys laike, o ne infrastruktūros savininko ar grėsmės veikėjo priskyrimas.</p></article>
      </div></section>
      <section id="atitikimas" className="lt-method-section"><header><p className="eyebrow">Prekių ženklų atitikimas</p><h2>Konservatyvios taisyklės</h2></header><ol className="lt-rule-list">
        <li><span>01</span><p>Normalizuoti domeną, atmesti netinkamą įvestį, oficialius domenus, peržiūrėtas išimtis ir jų subdomenus.</p></li>
        <li><span>02</span><p>Ieškoti tikslaus pavadinimo kaip pilno brūkšneliais atskirto elemento; įtartinas kontekstas paprastai turi būti tame pačiame DNS segmente.</p></li>
        <li><span>03</span><p>Ribotą Damerau ir Levenshtein atstumą taikyti tik atskirai patvirtintiems vieno žodžio pavadinimams ir tik su papildomu kontekstu.</p></li>
        <li><span>04</span><p>Atmesti kelių prekių ženklų konfliktus bei deklaruotą ženklą, nesutampantį su dabartiniu domeno įrodymu.</p></li>
      </ol><aside className="lt-method-note"><strong>Atitikties balas nėra tikimybė</strong><p>0–100 balas rikiuoja taisyklių stiprumą. Jis nėra analitiko pasitikėjimas, kenkėjiškumo tikimybė ar blokavimo rekomendacija.</p></aside></section>
      <section id="skelbimas" className="lt-method-section"><header><p className="eyebrow">Skelbimas</p><h2>Ką rodo viešas vaizdas</h2></header><dl className="lt-method-fields">
        <div><dt>Kandidatas</dt><dd>Normalizuotas ir neutralizuotas domenas arba URL. Prisijungimo duomenys, užklausos ir nesaugūs keliai pašalinami.</dd></div><div><dt>Laikas</dt><dd>Pirmo ir paskutinio priimto stebėjimo laikas UTC; sąsajoje jis gali būti rodomas Lietuvos laiku.</dd></div><div><dt>Šaltinis</dt><dd>CertStream, URLScan arba aiškiai paruošta HECAVEX įvestis su atskirta aptikimo ir patvirtinimo kilme.</dd></div><div><dt>Būsena</dt><dd>CertStream ir URLScan kandidatai lieka įtariami. Gyvavimo ciklo būsena keičiama tik gavus aiškų patikimo šaltinio signalą.</dd></div><div><dt>Įrodymai</dt><dd>Atskirti tik pavadinimo, papildomu šaltiniu patvirtinti ir analitiko peržiūrėti lygiai.</dd></div><div><dt>Kontekstas</dt><dd>Pasirinktinai pateikiama vieša URLScan, ribota DNS, RDAP ir sertifikato informacija. Trūkstamas kontekstas lieka nežinomas.</dd></div>
      </dl></section>
      <section id="istorija" className="lt-method-section"><header><p className="eyebrow">Istorija ir peržiūra</p><h2>Nebuvimas nėra būsena</h2></header><div className="lt-method-grid"><article><h3>Detali įvykių seka</h3><p>Kiekvienas priimtas stebėjimas gauna deterministinį įvykio ID. Pakartotinis tų pačių archyvų apdorojimas nedidina skaičiaus dirbtinai.</p></article><article><h3>Tik aiškūs pokyčiai</h3><p>Domeno dingimas iš naujausios suvestinės nereiškia, kad jis nepasiekiamas, suvaldytas ar teisėtas. Tokios išvados iš nebuvimo nedaromos.</p></article></div></section>
      <section id="ribos" className="lt-method-section"><header><p className="eyebrow">Ribos ir saugumas</p><h2>Signalai skirti tyrimui, ne automatiniam blokavimui</h2></header><div className="lt-limit-grid"><article><strong>Aprėptis nepilna</strong><p>Gyvo sertifikatų srauto klausoma tik suplanuotais langais, o papildomos paieškos yra ribotos. Nulinis rezultatas nėra saugumo garantija.</p></article><article><strong>Peradresavimas nėra išteisinimas</strong><p>Turinys gali keistis pagal lankytoją, laiką, geografinę vietą ar maskavimo taisykles. Peradresuojantis domenas gali likti tyrimo kandidatu.</p></article><article><strong>Bendra infrastruktūra nėra priskyrimas</strong><p>IP, ASN, registratorius, sertifikatas ar failo maiša padeda sieti stebėjimus, bet patys savaime neįrodo vieno operatoriaus.</p></article><article><strong>Pataisymai priimami</strong><p>Klaidingą teigiamą rezultatą galima pranešti el. paštu, nurodant signalo ID ir patikrinamą pagrindimą.</p></article></div><p className="lt-method-report">Visa techninė duomenų sutartis, saugos ribos ir šaltinių būsenų semantika pateikta <a href="/docs/">angliškoje techninėje dokumentacijoje</a>.</p></section>
    </main>
    <LtFooter />
  </div>;
}
