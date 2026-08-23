import { fileURLToPath } from "node:url";
import { readFileSync } from "node:fs";

import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

const snapshotPath = fileURLToPath(new URL("./public/data/radar.json", import.meta.url));
const historyPath = fileURLToPath(new URL("./public/data/history.json", import.meta.url));
const cloudflareAnalyticsScript = "https://static.cloudflareinsights.com/beacon.min.js";
const cloudflareAnalyticsToken = process.env.HECAVEX_ANALYTICS_TOKEN?.trim() ?? "";
if (cloudflareAnalyticsToken && !/^[a-f\d]{32}$/i.test(cloudflareAnalyticsToken)) {
  throw new Error("HECAVEX_ANALYTICS_TOKEN must be a 32-character hexadecimal Cloudflare site token.");
}
const cloudflareAnalyticsLoader =
  `(()=>{if(navigator.doNotTrack==="1"||window.doNotTrack==="1")return;` +
  `const token=document.currentScript?.dataset.hecavexAnalyticsToken;if(!token)return;` +
  `const beacon=document.createElement("script");beacon.type="module";beacon.src="${cloudflareAnalyticsScript}";` +
  `beacon.dataset.cfBeacon=JSON.stringify({token});document.head.appendChild(beacon)})();`;
type PrerenderPage = "radar" | "history" | "methodology" | "documentation";

function cloudflareWebAnalyticsPlugin() {
  return {
    name: "hecavex-cloudflare-web-analytics",
    transformIndexHtml() {
      if (!cloudflareAnalyticsToken) return [];
      return [
        {
          tag: "script",
          attrs: { "data-hecavex-analytics-token": cloudflareAnalyticsToken },
          children: cloudflareAnalyticsLoader,
          injectTo: "body" as const,
        },
      ];
    },
  };
}

function staticPagePlugin() {
  return {
    name: "hecavex-static-pages",
    transformIndexHtml: {
      order: "pre" as const,
      async handler(html: string, context: { path: string }) {
        const pages: Record<string, PrerenderPage> = {
          "/index.html": "radar",
          "/": "radar",
          "/history/index.html": "history",
          "/history/": "history",
          "/methodology/index.html": "methodology",
          "/methodology/": "methodology",
          "/docs/index.html": "documentation",
          "/docs/": "documentation",
        };
        const page = pages[context.path];
        if (!page) return html;

        const [
          { parseSnapshot },
          { parseHistory },
          { encodeSnapshotBootstrap },
          { encodeHistoryBootstrap },
          { renderPrerenderedPage },
        ] = await Promise.all([
          import("./src/lib/data.ts"),
          import("./src/lib/historyData.ts"),
          import("./src/lib/snapshotBootstrap.ts"),
          import("./src/lib/historyBootstrap.ts"),
          import("./src/prerender.ts"),
        ]);
        const snapshot = parseSnapshot(JSON.parse(readFileSync(snapshotPath, "utf8")));
        const history = await parseHistory(JSON.parse(readFileSync(historyPath, "utf8")));
        const renderedAt = Date.parse(page === "history" ? history.generatedAt : snapshot.lastSuccessfulSyncAt);
        const staticMarkup = renderPrerenderedPage(page, snapshot, renderedAt, history);
        const root = '<div id="root"></div>';
        if (!html.includes(root)) throw new Error(`Missing static-render root in ${context.path}`);
        const bootstrap = page === "radar"
          ? ` data-radar-bootstrap="${encodeSnapshotBootstrap(snapshot, renderedAt)}"`
          : page === "history"
            ? ` data-history-bootstrap="${encodeHistoryBootstrap(history, renderedAt)}"`
            : "";
        return html.replace(root, `<div id="root"${bootstrap}>${staticMarkup}</div>`);
      },
    },
  };
}

export default defineConfig({
  plugins: [staticPagePlugin(), cloudflareWebAnalyticsPlugin(), react()],
  build: {
    rollupOptions: {
      input: {
        radar: fileURLToPath(new URL("./index.html", import.meta.url)),
        history: fileURLToPath(new URL("./history/index.html", import.meta.url)),
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
