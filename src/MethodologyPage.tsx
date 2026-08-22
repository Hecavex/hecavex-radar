import { Methodology } from "./components/Methodology.tsx";
import { SiteFooter } from "./components/SiteFooter.tsx";
import { SiteHeader } from "./components/SiteHeader.tsx";

export function MethodologyPage() {
  return (
    <div className="site-shell">
      <SiteHeader currentPage="methodology" />
      <main className="content-page" id="main-content">
        <Methodology />
      </main>
      <SiteFooter />
    </div>
  );
}
