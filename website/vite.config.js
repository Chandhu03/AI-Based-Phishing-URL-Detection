import { resolve } from "node:path";
import { defineConfig } from "vite";
import { researchMetrics } from "./scripts/research-metrics.mjs";

const page = (p) => resolve(import.meta.dirname, p);

// Static multi-page build: the public site (/, /research/, /trust/) and the
// local-first analyst workspace (/app/). No server code, no runtime fetches.
export default defineConfig({
  // Multi-page: unknown paths 404 in dev as they do on Pages, instead of
  // Vite's default SPA fallback to index.html.
  appType: "mpa",
  esbuild: { jsx: "automatic", jsxImportSource: "preact" },
  plugins: [researchMetrics()],
  build: {
    target: "es2022",
    rollupOptions: {
      input: {
        main: page("index.html"),
        research: page("research/index.html"),
        trust: page("trust/index.html"),
        app: page("app/index.html"),
        // Cloudflare Pages serves dist/404.html with a 404 status for unknown
        // paths. Without it, Pages falls back to index.html with a 200 status.
        notFound: page("404.html"),
      },
    },
  },
});
