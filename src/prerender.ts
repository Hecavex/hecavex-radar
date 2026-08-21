import { createElement } from "react";
import { renderToString } from "react-dom/server";

import { App } from "./App";
import { DocumentationPage } from "./DocumentationPage";
import { MethodologyPage } from "./MethodologyPage";
import type { RadarSnapshot } from "./types";

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
