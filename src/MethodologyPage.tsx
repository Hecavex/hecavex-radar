import { Methodology } from "./components/Methodology";
import { SiteFooter } from "./components/SiteFooter";
import { SiteHeader } from "./components/SiteHeader";

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
