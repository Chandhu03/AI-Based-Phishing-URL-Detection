import { resolve } from "node:path";
import { defineConfig } from "vite";

// Two static pages; no framework, no runtime dependencies.
export default defineConfig({
  build: {
    rollupOptions: {
      input: {
        main: resolve(import.meta.dirname, "index.html"),
        research: resolve(import.meta.dirname, "research/index.html"),
      },
    },
  },
});
