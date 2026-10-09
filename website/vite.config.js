import { resolve } from "node:path";
import { defineConfig } from "vite";

// Two static pages; no framework, no runtime dependencies.
export default defineConfig({
  build: {
    rollupOptions: {
      input: {
        main: resolve(import.meta.dirname, "index.html"),
        research: resolve(import.meta.dirname, "research/index.html"),
        // Cloudflare Pages serves dist/404.html with a 404 status for unknown
        // paths. Without it, Pages falls back to index.html with a 200 status.
        notFound: resolve(import.meta.dirname, "404.html"),
      },
    },
  },
});
