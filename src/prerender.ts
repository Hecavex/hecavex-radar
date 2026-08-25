import { createElement } from "react";
import { renderToString } from "react-dom/server";

import { App } from "./App.tsx";
import { BrandScopePage } from "./BrandScopePage.tsx";
import { DocumentationPage } from "./DocumentationPage.tsx";
import { HistoryApp } from "./HistoryApp.tsx";
import { MethodologyPage } from "./MethodologyPage.tsx";
import { BrandActivityPage } from "./BrandActivityPage.tsx";
import { SignalPage } from "./SignalPage.tsx";
import { StaticPage } from "./StaticPages.tsx";
import type { BrandPageData, SignalPageData } from "./lib/pageBootstrap.ts";
import type { StaticPageData, StaticPageKind } from "./lib/staticPageBootstrap.ts";
import { LtBrandRegistryPage } from "./lt/LtBrandRegistryPage.tsx";
import { LtChangesPage } from "./lt/LtChangesPage.tsx";
import { LtMethodologyPage } from "./lt/LtMethodologyPage.tsx";
import { LtRadarApp } from "./lt/LtRadarApp.tsx";
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

export function renderStaticPage(kind: StaticPageKind, data: StaticPageData): string {
  return renderToString(createElement(StaticPage, { kind, data }));
}

export function renderSignalPage(data: SignalPageData): string {
  return renderToString(createElement(SignalPage, { data }));
}

export function renderBrandPage(data: BrandPageData): string {
  return renderToString(createElement(BrandActivityPage, { data }));
}

export function renderLithuanianPage(
  page: "radar" | "changes" | "brands" | "methodology",
  snapshot: RadarSnapshot,
  history: RadarHistory,
  renderedAt: number,
): string {
  if (page === "radar") {
    return renderToString(createElement<{ initialSnapshot?: RadarSnapshot; initialNow?: number }>(LtRadarApp, { initialSnapshot: snapshot, initialNow: renderedAt }));
  }
  if (page === "changes") {
    return renderToString(createElement<{ initialSnapshot?: RadarSnapshot; initialHistory?: RadarHistory; initialNow?: number }>(LtChangesPage, { initialSnapshot: snapshot, initialHistory: history, initialNow: renderedAt }));
  }
  if (page === "brands") return renderToString(createElement(LtBrandRegistryPage));
  return renderToString(createElement(LtMethodologyPage));
}
