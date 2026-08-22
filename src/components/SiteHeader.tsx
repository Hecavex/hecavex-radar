import { Code2, Menu, X } from "lucide-react";
import { useEffect, useRef, useState } from "react";

export type SitePage = "radar" | "history" | "methodology" | "documentation";

const portfolioNavigation = [
  { label: "Research", href: "https://hecavex.com/en/research/", current: false },
  { label: "Radar", href: "/", current: true },
  { label: "APT Notes", href: "https://apt.hecavex.com/", current: false },
  { label: "Labs", href: "https://labs.hecavex.com/", current: false },
  { label: "Data", href: "https://labs.hecavex.com/data/", current: false },
] as const;

const productNavigation = [
  { label: "Overview", href: "/", page: "radar" },
  { label: "History", href: "/history/", page: "history" },
  { label: "Methodology", href: "/methodology/", page: "methodology" },
  { label: "Docs", href: "/docs/", page: "documentation" },
] as const;

function PortfolioNavigation({ className, onNavigate }: { className: string; onNavigate?: () => void }) {
  return (
    <nav className={className} aria-label="HECAVEX projects">
      {portfolioNavigation.map((item) => (
        <a key={item.label} href={item.href} aria-current={item.current ? "page" : undefined} onClick={onNavigate}>
          {item.label}
        </a>
      ))}
    </nav>
  );
}

function ProductNavigation(
  { currentPage, className, onNavigate }: { currentPage: SitePage; className: string; onNavigate?: () => void },
) {
  return (
    <nav className={className} aria-label="Radar sections">
      {productNavigation.map((item) => (
        <a
          key={item.label}
          href={item.href}
          aria-current={currentPage === item.page ? "page" : undefined}
          onClick={onNavigate}
        >
          {item.label}
        </a>
      ))}
    </nav>
  );
}

function SourceLink({ className, onNavigate }: { className?: string; onNavigate?: () => void }) {
  return (
    <a
      className={className ? `source-link ${className}` : "source-link"}
      href="https://github.com/Hecavex/hecavex-radar"
      target="_blank"
      rel="noreferrer"
      onClick={onNavigate}
    >
      <Code2 aria-hidden="true" />
      Source
    </a>
  );
}

export function SiteHeader({ currentPage }: { currentPage: SitePage }) {
  const navigationRef = useRef<HTMLDetailsElement>(null);
  const [navigationOpen, setNavigationOpen] = useState(false);

  useEffect(() => {
    const closeOnEscape = (event: KeyboardEvent) => {
      const navigation = navigationRef.current;
      if (event.key !== "Escape" || !navigation?.open) return;
      navigation.open = false;
      setNavigationOpen(false);
      navigation.querySelector<HTMLElement>("summary")?.focus({ preventScroll: true });
    };
    document.addEventListener("keydown", closeOnEscape);
    return () => document.removeEventListener("keydown", closeOnEscape);
  }, []);

  const closeNavigation = () => {
    if (!navigationRef.current) return;
    navigationRef.current.open = false;
    setNavigationOpen(false);
  };

  return (
    <header className="site-header" data-portfolio-shell="v1">
      <div className="network-bar">
        <a className="brand" href="https://hecavex.com/en/" aria-label="HECAVEX Research">
          <img src="/hecavex-mark.svg" alt="" width="36" height="36" />
          <span className="brand-copy">
            <strong>HECAVEX</strong>
            <small>Radar / public threat signals</small>
          </span>
        </a>

        <PortfolioNavigation className="portfolio-navigation" />

        <details
          className="mobile-navigation"
          data-mobile-navigation
          ref={navigationRef}
          onToggle={(event) => setNavigationOpen(event.currentTarget.open)}
        >
          <summary aria-label={navigationOpen ? "Close navigation menu" : "Open navigation menu"}>
            <Menu className="menu-open-icon" aria-hidden="true" />
            <X className="menu-close-icon" aria-hidden="true" />
            <span>Menu</span>
          </summary>
          <div className="mobile-navigation-panel">
            <div className="mobile-navigation-column">
              <span className="navigation-label">Radar</span>
              <ProductNavigation
                currentPage={currentPage}
                className="mobile-product-navigation"
                onNavigate={closeNavigation}
              />
              <SourceLink className="mobile-source-link" onNavigate={closeNavigation} />
            </div>
            <div className="mobile-navigation-column">
              <span className="navigation-label">HECAVEX network</span>
              <PortfolioNavigation className="mobile-portfolio-navigation" onNavigate={closeNavigation} />
            </div>
          </div>
        </details>
      </div>

      <div className="product-bar">
        <a className="product-identity" href="/">
          <strong>Radar</strong>
          <span>Potential phishing infrastructure</span>
        </a>
        <ProductNavigation currentPage={currentPage} className="product-navigation" />
        <div className="header-utility">
          <SourceLink />
        </div>
      </div>
    </header>
  );
}
