import { StrictMode } from "react";
import { hydrateRoot } from "react-dom/client";

import "../styles.css";
import { LtMethodologyPage } from "./LtMethodologyPage.tsx";

const root = document.getElementById("root");
if (!root) throw new Error("Nerastas metodologijos puslapio elementas.");
hydrateRoot(root, <StrictMode><LtMethodologyPage /></StrictMode>);
root.dataset.hydrated = "true";
