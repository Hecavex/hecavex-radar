import type { SiteLanguage } from "./SiteHeader.tsx";

export function SiteFooter({ language = "en" }: { language?: SiteLanguage }) {
  const lt = language === "lt";
  const links = lt
    ? [
        ["Tyrimai", "https://hecavex.com/lt/tyrimai/"],
        ["Radaras", "/lt/"],
        ["Pokyčiai", "/lt/pokyciai/"],
        ["Prekių ženklai", "/lt/prekes-zenklai/"],
        ["Tendencijos", "/trends/"],
        ["Sąsajos", "/associations/"],
        ["Įrankiai", "/tools/"],
        ["Duomenys", "/dataset/"],
        ["Metodologija", "/lt/metodologija/"],
        ["Dokumentacija", "/docs/"],
        ["Saugumas", "/.well-known/security.txt"],
        ["Pataisymai", "mailto:info@hecavex.com?subject=HECAVEX%20Radar%20klaidingas%20teigiamas%20rezultatas"],
        ["Privatumas", "https://hecavex.com/lt/privatumas/"],
        ["Duomenų sąlygos", "/docs/#data-terms"],
      ]
    : [
        ["Research", "https://hecavex.com/en/research/"],
        ["Radar", "/"],
        ["Changes", "/changes/"],
        ["Brands", "/brands/"],
        ["Trends", "/trends/"],
        ["Associations", "/associations/"],
        ["Tools", "/tools/"],
        ["Dataset", "/dataset/"],
        ["Methodology", "/methodology/"],
        ["Docs", "/docs/"],
        ["Security", "/.well-known/security.txt"],
        ["Corrections", "mailto:info@hecavex.com?subject=HECAVEX%20Radar%20false%20positive"],
        ["Privacy", "https://hecavex.com/en/privacy/"],
        ["Data terms", "/docs/#data-terms"],
      ];

  return (
    <footer className="site-footer">
      <div className="footer-inner">
        <div className="footer-brand">
          <strong>RADAR</strong>
          <span>{lt ? <>Viešas gynybinis <a href="https://hecavex.com/lt/">HECAVEX</a> tyrimas. Signalai yra tyrimo kryptys, o ne priskyrimas ar kenkėjiškumo įrodymas.</> : <>Public defensive research by <a href="https://hecavex.com/en/">HECAVEX</a>. Signals are leads, not attribution or proof of malicious intent.</>}</span>
          <span>{lt ? "Aktyviai prižiūrima geriausiomis pastangomis · be paskyrų · be slapukų analitika" : "Active, best-effort maintenance · Apache-2.0 software · no accounts · cookieless Cloudflare Web Analytics"}</span>
        </div>
        <nav aria-label={lt ? "Poraštė" : "Footer"}>
          {links.map(([label, href]) => <a href={href} key={href}>{label}</a>)}
        </nav>
      </div>
    </footer>
  );
}
