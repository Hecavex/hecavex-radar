import { fileURLToPath } from "node:url";
import { readFileSync } from "node:fs";

import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

const snapshotPath = fileURLToPath(new URL("./public/data/radar.json", import.meta.url));
type PrerenderPage = "radar" | "methodology" | "documentation";

function staticPagePlugin() {
  return {
    name: "hecavex-static-pages",
    transformIndexHtml: {
      order: "pre" as const,
      async handler(html: string, context: { path: string }) {
        const pages: Record<string, PrerenderPage> = {
          "/index.html": "radar",
          "/": "radar",
          "/methodology/index.html": "methodology",
          "/methodology/": "methodology",
          "/docs/index.html": "documentation",
          "/docs/": "documentation",
        };
        const page = pages[context.path];
        if (!page) return html;

        const [{ parseSnapshot }, { encodeSnapshotBootstrap }, { renderPrerenderedPage }] = await Promise.all([
          import("./src/lib/data"),
          import("./src/lib/snapshotBootstrap"),
          import("./src/prerender"),
        ]);
        const snapshot = parseSnapshot(JSON.parse(readFileSync(snapshotPath, "utf8")));
        const renderedAt = Date.now();
        const staticMarkup = renderPrerenderedPage(page, snapshot, renderedAt);
        const root = '<div id="root"></div>';
        if (!html.includes(root)) throw new Error(`Missing static-render root in ${context.path}`);
        const bootstrap = page === "radar" ? ` data-radar-bootstrap="${encodeSnapshotBootstrap(snapshot, renderedAt)}"` : "";
        return html.replace(root, `<div id="root"${bootstrap}>${staticMarkup}</div>`);
      },
    },
  };
}

export default defineConfig({
  plugins: [staticPagePlugin(), react()],
  build: {
    rollupOptions: {
      input: {
        radar: fileURLToPath(new URL("./index.html", import.meta.url)),
        methodology: fileURLToPath(new URL("./methodology/index.html", import.meta.url)),
        documentation: fileURLToPath(new URL("./docs/index.html", import.meta.url)),
      },
    },
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./tests/setup.ts"],
    pool: "threads",
    maxWorkers: 1,
  },
});
