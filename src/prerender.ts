import { createElement } from "react";
import { renderToString } from "react-dom/server";

import { App } from "./App.tsx";
import { DocumentationPage } from "./DocumentationPage.tsx";
import { MethodologyPage } from "./MethodologyPage.tsx";
import type { RadarSnapshot } from "./types.ts";

export type PrerenderPage = "radar" | "methodology" | "documentation";

export function renderPrerenderedPage(
  page: PrerenderPage,
  snapshot: RadarSnapshot,
  renderedAt = Date.now(),
): string {
  if (page === "radar") {
    return renderToString(
      createElement<{ initialSnapshot?: RadarSnapshot; initialNow?: number }>(App, {
        initialSnapshot: snapshot,
        initialNow: renderedAt,
      }),
    );
  }
  if (page === "methodology") {
    return renderToString(createElement(MethodologyPage));
  }
  return renderToString(createElement(DocumentationPage));
}
