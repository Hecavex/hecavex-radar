import { StrictMode } from "react";
import { hydrateRoot } from "react-dom/client";

import "../styles.css";
import "./ltPages.css";
import { LtBrandRegistryPage } from "./LtBrandRegistryPage.tsx";

const root = document.getElementById("root");
if (!root) throw new Error("Nerastas prekių ženklų registro elementas.");
hydrateRoot(root, <StrictMode><LtBrandRegistryPage /></StrictMode>);
root.dataset.hydrated = "true";
