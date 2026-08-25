import { Documentation } from "./components/Documentation.tsx";
import { SiteFooter } from "./components/SiteFooter.tsx";
import { SiteHeader } from "./components/SiteHeader.tsx";

export function DocumentationPage({ language = "en" }: { language?: "en" | "lt" }) {
  const lt = language === "lt";
  return (
    <div className="site-shell">
      <SiteHeader currentPage="documentation" language={language} alternateHref={lt ? "/docs/" : "/lt/dokumentacija/"} />
      <main className="content-page" id="main-content">
        <Documentation language={language} />
      </main>
      <SiteFooter language={language} />
    </div>
  );
}
