import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

import { parseSnapshot } from "../src/lib/data";
import { parseHistory } from "../src/lib/historyData";
import { decodeSnapshotBootstrap, encodeSnapshotBootstrap } from "../src/lib/snapshotBootstrap";
import { renderPrerenderedPage, type PrerenderPage } from "../src/prerender";

const snapshot = parseSnapshot(JSON.parse(readFileSync(resolve("public/data/radar.json"), "utf8")));
const history = await parseHistory(JSON.parse(readFileSync(resolve("public/data/history.json"), "utf8")));

const pages: Array<{ page: PrerenderPage; path: string; title: string; marker: string }> = [
  { page: "radar", path: "index.html", title: "HECAVEX Radar · Public phishing signals", marker: "Sampled discovery, not continuous monitoring" },
  { page: "history", path: "history/index.html", title: "Candidate history | HECAVEX Radar", marker: "Candidate history" },
  { page: "methodology", path: "methodology/index.html", title: "Methodology · HECAVEX Radar", marker: "How a signal reaches Radar" },
  { page: "documentation", path: "docs/index.html", title: "Documentation · HECAVEX Radar", marker: "HECAVEX Radar technical reference" },
];

describe("prerendered pages", () => {
  it.each(pages)("renders meaningful static HTML for $page", ({ page, marker }) => {
    const document = new DOMParser().parseFromString(
      renderPrerenderedPage(page, snapshot, Date.now(), history),
      "text/html",
    );
    expect(document.querySelector("header.site-header")).not.toBeNull();
    expect(document.querySelector('header.site-header[data-portfolio-shell="v1"]')).not.toBeNull();
    expect(document.querySelector('.brand[href="https://hecavex.com/en/"]')).not.toBeNull();
    expect(document.querySelectorAll(".portfolio-navigation a")).toHaveLength(5);
    expect(document.querySelectorAll(".product-navigation a")).toHaveLength(4);
    expect(document.querySelector(".header-utility .source-link")).not.toBeNull();
    expect(document.querySelector("main#main-content")).not.toBeNull();
    expect(document.querySelector("footer.site-footer")).not.toBeNull();
    expect(document.body.textContent).toContain(marker);
    expect(document.body.textContent).not.toContain("Enable JavaScript");
  });

  it.each(pages)("keeps same-page fragments resolvable for $page", ({ page }) => {
    const document = new DOMParser().parseFromString(
      renderPrerenderedPage(page, snapshot, Date.now(), history),
      "text/html",
    );
    for (const anchor of document.querySelectorAll<HTMLAnchorElement>('a[href^="#"]')) {
      expect(document.getElementById(decodeURIComponent(anchor.hash.slice(1))), anchor.outerHTML).not.toBeNull();
    }
  });

  it("renders the dashboard deterministically for hydration", () => {
    const renderedAt = Date.parse("2026-08-21T17:05:00.000Z");
    expect(renderPrerenderedPage("radar", snapshot, renderedAt)).toBe(
      renderPrerenderedPage("radar", snapshot, renderedAt),
    );
  });

  it("round-trips a safely attribute-encoded validated bootstrap", () => {
    const hostileText = '"><script>alert(1)</script>&';
    const hostileSnapshot = structuredClone(snapshot);
    hostileSnapshot.sources[0]!.note = hostileText;
    const renderedAt = Date.parse("2026-08-21T17:05:00.000Z");
    const encoded = encodeSnapshotBootstrap(hostileSnapshot, renderedAt);

    expect(encoded).not.toMatch(/[<>&"]/u);
    expect(decodeSnapshotBootstrap(encoded)).toEqual({ snapshot: hostileSnapshot, renderedAt });
  });
});

describe("entry metadata", () => {
  it.each(pages)("provides canonical, social, structured, and CSP metadata for $path", ({ path, title }) => {
    const document = new DOMParser().parseFromString(readFileSync(resolve(path), "utf8"), "text/html");
    expect(document.title).toBe(title);
    expect(document.querySelector('meta[name="description"]')?.getAttribute("content")?.length).toBeGreaterThan(50);
    expect(document.querySelector('link[rel="canonical"]')?.getAttribute("href")).toMatch(/^https:\/\/radar\.hecavex\.com\//);
    expect(document.querySelector('meta[property="og:image"]')?.getAttribute("content")).toMatch(/^https:\/\//);
    expect(document.querySelector('meta[name="twitter:card"]')?.getAttribute("content")).toBe("summary_large_image");

    const jsonLd = document.querySelector<HTMLScriptElement>('script[type="application/ld+json"]');
    expect(jsonLd).not.toBeNull();
    expect(() => JSON.parse(jsonLd!.textContent ?? "")).not.toThrow();

    const digest = createHash("sha256").update(jsonLd!.textContent ?? "", "utf8").digest("base64");
    expect(document.querySelector('meta[http-equiv="Content-Security-Policy"]')?.getAttribute("content")).toContain(
      `'sha256-${digest}'`,
    );
  });

  it("allows the advertised JSON distribution while excluding other data paths", () => {
    const robots = readFileSync(resolve("public/robots.txt"), "utf8");
    expect(robots).toContain("Allow: /data/radar.json");
    expect(robots).toContain("Allow: /data/history.json");
    expect(robots).toContain("Disallow: /data/");
  });
});
