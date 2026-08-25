import { StrictMode } from "react";
import { hydrateRoot } from "react-dom/client";

import { NotFoundPage } from "./NotFoundPage.tsx";
import "./styles.css";

const root = document.getElementById("root");
if (!root) throw new Error("Missing not-found page root.");

hydrateRoot(root, <StrictMode><NotFoundPage /></StrictMode>);
root.dataset.hydrated = "true";
