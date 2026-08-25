import { ArrowLeft, BookOpenText, History, Languages } from "lucide-react";

import { SiteFooter } from "./components/SiteFooter.tsx";
import { SiteHeader } from "./components/SiteHeader.tsx";

export function NotFoundPage() {
  return (
    <div className="site-shell">
      <SiteHeader currentPage="not-found" />
      <main className="not-found-page" id="main-content">
        <section className="not-found-hero" aria-labelledby="not-found-title">
          <div className="not-found-copy">
            <p className="eyebrow">404 / Route unavailable</p>
            <h1 id="not-found-title">This route has no signal.</h1>
            <p>
              The address may be incomplete, mistyped, or tied to a record that is no longer published. Radar does not
              redirect missing records because an absent page should stay visibly absent.
            </p>
            <div className="hero-actions">
              <a className="hero-action-primary" href="/"><ArrowLeft aria-hidden="true" /> Return to Radar</a>
              <a href="/history/"><History aria-hidden="true" /> Browse signal history</a>
            </div>
          </div>
          <aside className="not-found-status" aria-label="Missing route status">
            <strong>404</strong>
            <span>NOT FOUND</span>
            <p>No candidate status or verdict can be inferred from a missing route.</p>
          </aside>
        </section>

        <nav className="not-found-routes" aria-label="Useful Radar routes">
          <a href="/methodology/"><BookOpenText aria-hidden="true" /><span><strong>Methodology</strong><small>How candidates are collected and screened</small></span></a>
          <a href="/lt/"><Languages aria-hidden="true" /><span><strong>Lietuviškai</strong><small>Atverti lietuvišką radaro versiją</small></span></a>
        </nav>
      </main>
      <SiteFooter />
    </div>
  );
}
