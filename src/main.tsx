import { StrictMode } from "react";
import { createRoot, hydrateRoot } from "react-dom/client";

import { App } from "./App";
import { decodeSnapshotBootstrap } from "./lib/snapshotBootstrap";
import "./styles.css";

const root = document.getElementById("root");
if (!root) throw new Error("Missing Radar application root.");

const bootstrap = root.dataset.radarBootstrap;
if (bootstrap) {
  const { snapshot, renderedAt } = decodeSnapshotBootstrap(bootstrap);
  hydrateRoot(
    root,
    <StrictMode>
      <App initialSnapshot={snapshot} initialNow={renderedAt} />
    </StrictMode>,
  );
  delete root.dataset.radarBootstrap;
  root.dataset.hydrated = "true";
} else {
  root.replaceChildren();
  createRoot(root).render(
    <StrictMode>
      <App />
    </StrictMode>,
  );
  root.dataset.hydrated = "client-rendered";
}
