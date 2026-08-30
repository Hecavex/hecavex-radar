import { AlertTriangle, RadioTower } from "lucide-react";
import { useEffect, useState } from "react";

import { Dashboard } from "./components/Dashboard.tsx";
import { SiteFooter } from "./components/SiteFooter.tsx";
import { SiteHeader } from "./components/SiteHeader.tsx";
import { loadSnapshot } from "./lib/data.ts";
import type { RadarSnapshot } from "./types.ts";

type LoadState =
  | { status: "loading" }
  | { status: "ready"; snapshot: RadarSnapshot; renderedAt: number; refreshError: string | null }
  | { status: "error"; message: string };

export function App(
  { initialSnapshot, initialNow }: { initialSnapshot?: RadarSnapshot; initialNow?: number } = {},
) {
  const [state, setState] = useState<LoadState>(
    initialSnapshot
      ? { status: "ready", snapshot: initialSnapshot, renderedAt: initialNow ?? Date.now(), refreshError: null }
      : { status: "loading" },
  );

  useEffect(() => {
    const controller = new AbortController();
    void loadSnapshot(controller.signal)
      .then((snapshot) => setState({ status: "ready", snapshot, renderedAt: Date.now(), refreshError: null }))
      .catch((error: unknown) => {
        if (!controller.signal.aborted) {
          const message = error instanceof Error ? error.message : "Unknown data error.";
          setState((current) => current.status === "ready"
            ? { ...current, renderedAt: Date.now(), refreshError: message }
            : { status: "error", message });
        }
      });
    return () => controller.abort();
  }, []);

  return (
    <div className="site-shell">
      <SiteHeader currentPage="radar" />

      {state.status === "loading" && (
        <main className="state-page" id="main-content" aria-live="polite">
          <RadioTower className="state-icon pulse" aria-hidden="true" />
          <p className="eyebrow">Receiving snapshot</p>
          <h1>Loading recent signals</h1>
        </main>
      )}

      {state.status === "error" && (
        <main className="state-page" id="main-content" aria-live="assertive">
          <AlertTriangle className="state-icon danger" aria-hidden="true" />
          <p className="eyebrow">Data unavailable</p>
          <h1>The radar snapshot could not be loaded</h1>
          <p>{state.message}</p>
          <button className="button" type="button" onClick={() => window.location.reload()}>
            Try again
          </button>
        </main>
      )}

      {state.status === "ready" && (
        <Dashboard snapshot={state.snapshot} now={state.renderedAt} refreshError={state.refreshError} />
      )}

      <SiteFooter />
    </div>
  );
}
