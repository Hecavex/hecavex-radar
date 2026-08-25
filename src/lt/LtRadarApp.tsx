import { AlertTriangle, RadioTower } from "lucide-react";
import { useEffect, useState } from "react";

import { SiteHeader } from "../components/SiteHeader.tsx";
import { loadSnapshot } from "../lib/data.ts";
import type { RadarSnapshot } from "../types.ts";
import { LtFooter } from "./LtFooter.tsx";
import { LtRadarOverview } from "./LtRadarOverview.tsx";

type LoadState =
  | { status: "loading" }
  | { status: "ready"; snapshot: RadarSnapshot; renderedAt: number }
  | { status: "error"; message: string };

export function LtRadarApp({ initialSnapshot, initialNow }: { initialSnapshot?: RadarSnapshot; initialNow?: number } = {}) {
  const [state, setState] = useState<LoadState>(initialSnapshot
    ? { status: "ready", snapshot: initialSnapshot, renderedAt: initialNow ?? Date.now() }
    : { status: "loading" });

  useEffect(() => {
    const controller = new AbortController();
    void loadSnapshot(controller.signal)
      .then((snapshot) => setState({ status: "ready", snapshot, renderedAt: Date.now() }))
      .catch((error: unknown) => {
        if (!controller.signal.aborted) setState({ status: "error", message: error instanceof Error ? error.message : "Nežinoma duomenų klaida." });
      });
    return () => controller.abort();
  }, []);

  return (
    <div className="site-shell">
      <SiteHeader currentPage="radar" language="lt" alternateHref="/" />
      {state.status === "loading" && <main className="state-page" id="main-content" aria-live="polite"><RadioTower className="state-icon pulse" aria-hidden="true" /><p className="eyebrow">Gaunama suvestinė</p><h1>Kraunami naujausi signalai</h1></main>}
      {state.status === "error" && <main className="state-page" id="main-content" aria-live="assertive"><AlertTriangle className="state-icon danger" aria-hidden="true" /><p className="eyebrow">Duomenys nepasiekiami</p><h1>Nepavyko įkelti radaro suvestinės</h1><p>{state.message}</p></main>}
      {state.status === "ready" && <LtRadarOverview snapshot={state.snapshot} now={state.renderedAt} />}
      <LtFooter />
    </div>
  );
}
