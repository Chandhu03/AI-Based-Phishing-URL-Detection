import { useEffect, useState } from "preact/hooks";

// Hash routes keep the static host simple (no rewrite rules) and never put
// analysed URLs in the address bar: only record ids appear in routes.
const ROUTES = [
  ["overview", /^\/overview$/],
  ["analyze", /^\/analyze$/],
  ["analyses", /^\/analyses$/],
  ["analysis", /^\/analyses\/([\w-]+)$/],
  ["investigations", /^\/investigations$/],
  ["investigation", /^\/investigations\/([\w-]+)$/],
  ["indicators", /^\/indicators$/],
  ["engine", /^\/engine$/],
  ["settings", /^\/settings$/],
];

export function parseRoute(hash) {
  const path = (hash || "").replace(/^#/, "") || "/overview";
  for (const [name, re] of ROUTES) {
    const m = re.exec(path);
    if (m) return { name, id: m[1] ?? null, path };
  }
  return { name: "not-found", id: null, path };
}

export function useRoute() {
  const [route, setRoute] = useState(() => parseRoute(location.hash));
  useEffect(() => {
    const on = () => setRoute(parseRoute(location.hash));
    addEventListener("hashchange", on);
    return () => removeEventListener("hashchange", on);
  }, []);
  return route;
}

export const navigate = (path) => {
  location.hash = path;
};
