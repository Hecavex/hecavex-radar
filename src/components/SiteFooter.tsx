export function SiteFooter() {
  return (
    <footer className="site-footer">
      <div className="footer-inner">
        <div className="footer-brand">
          <strong>RADAR</strong>
          <span>
            Public defensive research by <a href="https://hecavex.com/en/">HECAVEX</a>. Signals are leads, not
            attribution or proof of malicious intent.
          </span>
          <span>Active, best-effort maintenance · Apache-2.0 software · no accounts · cookieless Cloudflare Web Analytics</span>
        </div>
        <nav aria-label="Footer">
          <a href="https://hecavex.com/en/research/">Research</a>
          <a href="/">Radar</a>
          <a href="https://apt.hecavex.com/">APT Notes</a>
          <a href="https://labs.hecavex.com/">Labs</a>
          <a href="https://labs.hecavex.com/data/">Data</a>
          <a href="/history/">History</a>
          <a href="/methodology/">Methodology</a>
          <a href="/docs/">Docs</a>
          <a href="/.well-known/security.txt">Security</a>
          <a href="mailto:info@hecavex.com?subject=HECAVEX%20Radar%20false%20positive">Corrections</a>
          <a href="https://hecavex.com/en/privacy/">Privacy</a>
          <a href="/docs/#data-terms">Data terms</a>
          <a href="/THIRD-PARTY-NOTICES.txt">Notices</a>
        </nav>
      </div>
    </footer>
  );
}
