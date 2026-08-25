import { createElement } from "react";
import { renderToString } from "react-dom/server";

import { App } from "./App.tsx";
import { BrandScopePage } from "./BrandScopePage.tsx";
import { DocumentationPage } from "./DocumentationPage.tsx";
import { HistoryApp } from "./HistoryApp.tsx";
import { MethodologyPage } from "./MethodologyPage.tsx";
import type { RadarHistory, RadarSnapshot } from "./types.ts";

export type PrerenderPage = "radar" | "history" | "brands" | "methodology" | "documentation";

export function renderPrerenderedPage(
  page: PrerenderPage,
  snapshot: RadarSnapshot,
  renderedAt = Date.now(),
  history?: RadarHistory,
): string {
  if (page === "radar") {
    return renderToString(
      createElement<{ initialSnapshot?: RadarSnapshot; initialNow?: number }>(App, {
        initialSnapshot: snapshot,
        initialNow: renderedAt,
      }),
    );
  }
  if (page === "history") {
    if (!history) throw new Error("History data is required to prerender the history page.");
    return renderToString(
      createElement<{ initialHistory?: RadarHistory; initialNow?: number }>(HistoryApp, {
        initialHistory: history,
        initialNow: renderedAt,
      }),
    );
  }
  if (page === "methodology") {
    return renderToString(createElement(MethodologyPage));
  }
  if (page === "brands") {
    return renderToString(createElement(BrandScopePage));
  }
  return renderToString(createElement(DocumentationPage));
}
