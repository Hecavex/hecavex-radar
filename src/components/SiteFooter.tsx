import { ShieldCheck } from "lucide-react";

export function SiteFooter() {
  return (
    <footer className="site-footer">
      <div>
        <ShieldCheck aria-hidden="true" />
        <p>
          Indicators are defanged and provided for defensive research. A listing is a signal, not attribution or proof
          of malicious intent. Viewing evidence may contact URLScan; the suspicious site is never contacted.
        </p>
      </div>
      <div className="footer-meta">
        <nav aria-label="Radar resources">
          <a href="https://hecavex.com/">HECAVEX</a>
          <a href="https://apt.hecavex.com/">APT Notes</a>
          <a href="https://labs.hecavex.com/">Labs</a>
          <a href="/">Radar</a>
          <a href="/methodology/">Methodology</a>
          <a href="/docs/">Documentation</a>
        </nav>
        <p>
          Software: Apache-2.0 · <a href="/docs/#data-terms">Data terms &amp; attribution</a> ·{" "}
          <a href="/THIRD-PARTY-NOTICES.txt">Third-party notices</a> · No first-party analytics · No accounts ·{" "}
          <a href="mailto:info@hecavex.com?subject=HECAVEX%20Radar%20false%20positive">Report a false positive</a>
        </p>
      </div>
    </footer>
  );
}
