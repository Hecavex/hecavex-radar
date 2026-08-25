import { Methodology } from "../components/Methodology.tsx";
import { SiteHeader } from "../components/SiteHeader.tsx";
import { LtFooter } from "./LtFooter.tsx";

export function LtMethodologyPage() {
  return (
    <div className="site-shell">
      <SiteHeader currentPage="methodology" language="lt" alternateHref="/methodology/" />
      <main id="main-content" className="content-page">
        <Methodology language="lt" />
      </main>
      <LtFooter />
    </div>
  );
}
