import { Code2 } from "lucide-react";

export type SitePage = "radar" | "methodology" | "documentation";

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
      <nav aria-label="Primary navigation">
        <a className="portfolio-link" href="https://hecavex.com/">HECAVEX</a>
        <a className="portfolio-link" href="https://apt.hecavex.com/">APT Notes</a>
        <a className="portfolio-link" href="https://labs.hecavex.com/">Labs</a>
        <a className="signals-link" href={currentPage === "radar" ? "#signals" : "/#signals"}>Signals</a>
        <a className="methodology-nav-link" href="/methodology/" aria-current={currentPage === "methodology" ? "page" : undefined}>
          Methodology
        </a>
        <a className="docs-nav-link" href="/docs/" aria-current={currentPage === "documentation" ? "page" : undefined}>
          Docs
        </a>
        <a
          className="source-link"
          href="https://github.com/hecavex/hecavex-radar"
          target="_blank"
          rel="noreferrer"
        >
          <Code2 aria-hidden="true" />
          Source
        </a>
      </nav>
    </header>
  );
}
