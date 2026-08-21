import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { MethodologyPage } from "./MethodologyPage";
import "./styles.css";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <MethodologyPage />
  </StrictMode>,
);
