import { AlertTriangle, Code2, RadioTower, ShieldCheck } from "lucide-react";
import { useEffect, useState } from "react";

import { Dashboard } from "./components/Dashboard";
import { loadSnapshot } from "./lib/data";
import type { RadarSnapshot } from "./types";

type LoadState =
  | { status: "loading" }
  | { status: "ready"; snapshot: RadarSnapshot }
  | { status: "error"; message: string };

export function App() {
  const [state, setState] = useState<LoadState>({ status: "loading" });

  useEffect(() => {
    const controller = new AbortController();
    void loadSnapshot(controller.signal)
      .then((snapshot) => setState({ status: "ready", snapshot }))
      .catch((error: unknown) => {
        if (!controller.signal.aborted) {
          setState({ status: "error", message: error instanceof Error ? error.message : "Unknown data error." });
        }
      });
    return () => controller.abort();
  }, []);

  return (
    <div className="site-shell">
      <header className="site-header">
        <a className="brand" href="/" aria-label="HECAVEX Radar home">
          <img src="/hecavex-mark.svg" alt="" width="42" height="42" />
          <span>
            <strong>HECAVEX</strong>
            <small>Public threat radar</small>
          </span>
        </a>
        <nav aria-label="Primary navigation">
          <a href="#signals">Signals</a>
          <a href="#methodology">Methodology</a>
          <a
            className="source-link"
            href="https://github.com/hecavex/hecavex-radar"
            target="_blank"
            rel="noreferrer"
          >
            <Code2 aria-hidden="true" />
            Source
          </a>
        </nav>
      </header>

      {state.status === "loading" && (
        <main className="state-page" aria-live="polite">
          <RadioTower className="state-icon pulse" aria-hidden="true" />
          <p className="eyebrow">Receiving snapshot</p>
          <h1>Loading recent signals</h1>
        </main>
      )}

      {state.status === "error" && (
        <main className="state-page" aria-live="assertive">
          <AlertTriangle className="state-icon danger" aria-hidden="true" />
          <p className="eyebrow">Data unavailable</p>
          <h1>The radar snapshot could not be loaded</h1>
          <p>{state.message}</p>
          <button className="button" type="button" onClick={() => window.location.reload()}>
            Try again
          </button>
        </main>
      )}

      {state.status === "ready" && <Dashboard snapshot={state.snapshot} />}

      <footer className="site-footer" id="methodology">
        <div>
          <ShieldCheck aria-hidden="true" />
          <p>
            Indicators are defanged and provided for defensive research. A listing is a signal, not attribution or proof
            of malicious intent.
          </p>
        </div>
        <p>
          Apache-2.0 · No tracking · No accounts ·{" "}
          <a href="mailto:info@hecavex.com?subject=HECAVEX%20Radar%20false%20positive">Report a false positive</a>
        </p>
      </footer>
    </div>
  );
}
