import { fileURLToPath } from "node:url";

import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react()],
  build: {
    rollupOptions: {
      input: {
        radar: fileURLToPath(new URL("./index.html", import.meta.url)),
        methodology: fileURLToPath(new URL("./methodology/index.html", import.meta.url)),
        documentation: fileURLToPath(new URL("./docs/index.html", import.meta.url)),
      },
    },
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./tests/setup.ts"],
    pool: "threads",
    maxWorkers: 1,
  },
});
