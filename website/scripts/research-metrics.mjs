// Vite plugin: fill research numbers in HTML from the committed evaluation
// reports, so published figures can never drift from their source.
//
//   {{m:engine:/test/engine_shipped/phiusiil_test/roc_auc|f3}}
//
// Source keys map to phase3/reports files; the path is a JSON pointer.
// Formats: f2/f3/f4 (fixed decimals), pct0/pct1 (percentage), int (grouped),
// id (an identifier such as a model id: letters, digits, ".", "_", "-" only).
// A missing file, path or format fails the build.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const ROOT = resolve(import.meta.dirname, "..", "..", "phase3", "reports");
const SOURCES = { phase3: "metrics.json", engine: "engine/metrics.json", sites: "engine/site_metrics.json", data: "data_stats.json" };
const TOKEN = /\{\{m:(\w+):([^|}]+)\|(\w+)\}\}/g;

export function pointer(obj, path) {
  return path.split("/").slice(1).reduce((o, key) => (o == null ? undefined : o[key.replace(/~1/g, "/").replace(/~0/g, "~")]), obj);
}

export function format(value, fmt) {
  if (fmt === "id") {
    // Inserted into HTML as-is, so only identifier characters are allowed.
    if (typeof value !== "string" || !/^[\w.-]{1,100}$/.test(value)) throw new Error(`not an identifier: ${value}`);
    return value;
  }
  if (typeof value !== "number" || !Number.isFinite(value)) throw new Error(`not a number: ${value}`);
  const m = /^(f|pct)(\d)$/.exec(fmt);
  if (m) return m[1] === "f" ? value.toFixed(Number(m[2])) : `${(value * 100).toFixed(Number(m[2]))}%`;
  if (fmt === "int") return Math.round(value).toLocaleString("en-US");
  throw new Error(`unknown format ${fmt}`);
}

export function fillMetrics(html, load = (file) => JSON.parse(readFileSync(resolve(ROOT, file), "utf8"))) {
  const cache = {};
  return html.replace(TOKEN, (_, src, path, fmt) => {
    if (!SOURCES[src]) throw new Error(`unknown metrics source "${src}"`);
    cache[src] ??= load(SOURCES[src]);
    const value = pointer(cache[src], path);
    if (value === undefined) throw new Error(`metric ${src}:${path} not found`);
    return format(value, fmt);
  });
}

export function researchMetrics() {
  return {
    name: "securemind-research-metrics",
    transformIndexHtml: { order: "pre", handler: (html) => fillMetrics(html) },
  };
}
