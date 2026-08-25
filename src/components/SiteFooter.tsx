import type { SiteLanguage } from "./SiteHeader.tsx";

export function SiteFooter({ language = "en" }: { language?: SiteLanguage }) {
  const lt = language === "lt";
  return (
    <footer className="site-footer">
      <div className="footer-inner">
        <div className="footer-brand">
          <strong>RADAR</strong>
          <span>{lt ? "Viešas gynybinis HECAVEX tyrimas. Signalai yra tyrimo kryptys, o ne priskyrimas ar kenkėjiškumo įrodymas." : <>Public defensive research by <a href="https://hecavex.com/en/">HECAVEX</a>. Signals are leads, not attribution or proof of malicious intent.</>}</span>
          <span>{lt ? "Aktyviai prižiūrima geriausiomis pastangomis · be paskyrų · be slapukų analitika" : "Active, best-effort maintenance · Apache-2.0 software · no accounts · cookieless Cloudflare Web Analytics"}</span>
        </div>
        <nav aria-label="Footer">
          <a href={lt ? "https://hecavex.com/lt/tyrimai/" : "https://hecavex.com/en/research/"}>Research</a>
          <a href={lt ? "/lt/" : "/"}>Radar</a><a href="/changes/">Changes</a><a href="/brands/">Brands</a><a href="/trends/">Trends</a><a href="/associations/">Associations</a><a href="/tools/">Tools</a><a href="/dataset/">Dataset</a><a href="/methodology/">Methodology</a><a href="/docs/">Docs</a><a href="/.well-known/security.txt">Security</a><a href="mailto:info@hecavex.com?subject=HECAVEX%20Radar%20false%20positive">Corrections</a><a href="https://hecavex.com/en/privacy/">Privacy</a><a href="/docs/#data-terms">Data terms</a>
        </nav>
      </div>
    </footer>
  );
}
