import { StrictMode } from "react";
import { createRoot, hydrateRoot } from "react-dom/client";

import "../styles.css";
import "./ltPages.css";
import { LtChangesPage } from "./LtChangesPage.tsx";
import { decodeLtChangesBootstrap } from "./ltBootstrap.ts";

const root = document.getElementById("root");
if (!root) throw new Error("Nerastas pokyčių programos elementas.");
const bootstrap = root.dataset.ltChangesBootstrap;
if (bootstrap) {
  void decodeLtChangesBootstrap(bootstrap).then(({ snapshot, history, renderedAt }) => {
    hydrateRoot(root, <StrictMode><LtChangesPage initialSnapshot={snapshot} initialHistory={history} initialNow={renderedAt} /></StrictMode>);
    delete root.dataset.ltChangesBootstrap;
    root.dataset.hydrated = "true";
  });
} else {
  root.replaceChildren();
  createRoot(root).render(<StrictMode><LtChangesPage /></StrictMode>);
  root.dataset.hydrated = "client-rendered";
}
