import { StrictMode } from "react";
import { hydrateRoot } from "react-dom/client";

import { MethodologyPage } from "./MethodologyPage";
import "./styles.css";

const root = document.getElementById("root");
if (!root) throw new Error("Missing methodology application root.");

hydrateRoot(
  root,
  <StrictMode>
    <MethodologyPage />
  </StrictMode>,
);
root.dataset.hydrated = "true";
