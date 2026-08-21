import { Documentation } from "./components/Documentation";
import { SiteFooter } from "./components/SiteFooter";
import { SiteHeader } from "./components/SiteHeader";

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
