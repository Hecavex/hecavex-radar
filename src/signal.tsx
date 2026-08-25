import { StrictMode } from "react";
import { hydrateRoot } from "react-dom/client";

import { SignalPage } from "./SignalPage.tsx";
import { decodeSignalPageBootstrap } from "./lib/pageBootstrap.ts";
import "./styles.css";

const root = document.getElementById("root");
if (!root?.dataset.pageBootstrap) throw new Error("Missing signal page bootstrap.");
hydrateRoot(root, <StrictMode><SignalPage data={decodeSignalPageBootstrap(root.dataset.pageBootstrap)} /></StrictMode>);
delete root.dataset.pageBootstrap;
root.dataset.hydrated = "true";
