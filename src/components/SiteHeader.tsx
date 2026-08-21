import { Code2, Menu, X } from "lucide-react";

export type SitePage = "radar" | "methodology" | "documentation" | "data";

type NavigationProps = {
  currentPage: SitePage;
  className: string;
  label: string;
};

function Navigation({ currentPage, className, label }: NavigationProps) {
  return (
    <nav className={className} aria-label={label}>
      <a href="https://hecavex.com/en/research/">Research</a>
      <a href="/" aria-current={currentPage === "radar" ? "page" : undefined}>Radar</a>
      <a href="https://apt.hecavex.com/">APT Notes</a>
      <a href="https://labs.hecavex.com/">Labs</a>
      <a href="https://labs.hecavex.com/data/">Data</a>
      <a href="/methodology/" aria-current={currentPage === "methodology" ? "page" : undefined}>
        Methodology
      </a>
      <a href="/docs/" aria-current={currentPage === "documentation" ? "page" : undefined}>
        Docs
      </a>
      <a
        className="source-link"
        href="https://github.com/Hecavex/hecavex-radar"
        target="_blank"
        rel="noreferrer"
      >
        <Code2 aria-hidden="true" />
        Source
      </a>
    </nav>
  );
}

export function SiteHeader({ currentPage }: { currentPage: SitePage }) {
  return (
    <header className="site-header">
      <a className="brand" href="/" aria-label="HECAVEX Radar home">
        <img src="/hecavex-mark.svg" alt="" width="42" height="42" />
        <span>
          <strong>HECAVEX</strong>
          <small>Public threat radar</small>
        </span>
      </a>
      <Navigation currentPage={currentPage} className="desktop-navigation" label="HECAVEX projects" />
      <details className="mobile-navigation">
        <summary>
          <Menu className="menu-open-icon" aria-hidden="true" />
          <X className="menu-close-icon" aria-hidden="true" />
          <span>Menu</span>
        </summary>
        <Navigation currentPage={currentPage} className="mobile-navigation-links" label="HECAVEX projects" />
      </details>
    </header>
  );
}
