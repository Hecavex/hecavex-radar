import { StrictMode } from "react";
import { hydrateRoot } from "react-dom/client";

import { BrandActivityPage } from "./BrandActivityPage.tsx";
import { decodeBrandPageBootstrap } from "./lib/pageBootstrap.ts";
import "./styles.css";

const root = document.getElementById("root");
if (!root?.dataset.pageBootstrap) throw new Error("Missing brand page bootstrap.");
hydrateRoot(root, <StrictMode><BrandActivityPage data={decodeBrandPageBootstrap(root.dataset.pageBootstrap)} /></StrictMode>);
delete root.dataset.pageBootstrap;
root.dataset.hydrated = "true";
