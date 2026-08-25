import { StrictMode } from "react";
import { hydrateRoot } from "react-dom/client";

import { BrandScopePage } from "./BrandScopePage";
import "./styles.css";

const root = document.getElementById("root");
if (!root) throw new Error("Missing brand-scope application root.");

hydrateRoot(
  root,
  <StrictMode>
    <BrandScopePage />
  </StrictMode>,
);
root.dataset.hydrated = "true";
