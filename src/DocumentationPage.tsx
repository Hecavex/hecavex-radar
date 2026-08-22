import { Documentation } from "./components/Documentation.tsx";
import { SiteFooter } from "./components/SiteFooter.tsx";
import { SiteHeader } from "./components/SiteHeader.tsx";

export function DocumentationPage() {
  return (
    <div className="site-shell">
      <SiteHeader currentPage="documentation" />
      <main className="content-page" id="main-content">
        <Documentation />
      </main>
      <SiteFooter />
    </div>
  );
}
