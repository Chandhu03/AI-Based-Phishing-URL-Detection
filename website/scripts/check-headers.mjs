// Verify that a deployed host serves the security headers in public/_headers.
//
//   node scripts/check-headers.mjs https://<branch>.<project>.pages.dev
//
// Reads the expected headers from public/_headers (so the check can never
// drift from the configuration), requests "/", "/research/" and one hashed
// asset, and reports every missing or different header. Exits non-zero on
// any failure. It only sends HEAD/GET requests to the host you name.
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

export function parseHeadersFile(text) {
  const rules = [];
  let current = null;
  for (const raw of text.split(/\r?\n/)) {
    if (!raw.trim() || raw.trimStart().startsWith("#")) continue;
    if (!/^\s/.test(raw)) {
      current = { pattern: raw.trim(), headers: {} };
      rules.push(current);
    } else if (current) {
      const i = raw.indexOf(":");
      current.headers[raw.slice(0, i).trim().toLowerCase()] = raw.slice(i + 1).trim();
    }
  }
  return rules;
}

function matches(pattern, path) {
  const re = new RegExp(`^${pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*")}$`);
  return re.test(path);
}

export function expectedFor(rules, path) {
  const out = {};
  for (const rule of rules) if (matches(rule.pattern, path)) Object.assign(out, rule.headers);
  return out;
}

// Markup a CDN or host can inject into HTML (Cloudflare Email Obfuscation,
// Web Analytics, Rocket Loader). The built pages contain none of these, so
// finding one means the host is rewriting responses.
const INJECTIONS = [
  [/\/cdn-cgi\//, "Cloudflare /cdn-cgi/ script or link (Email Obfuscation or similar)"],
  [/cloudflareinsights\.com|data-cf-beacon/, "Cloudflare Web Analytics beacon"],
  [/__cf_email__/, "Cloudflare email obfuscation markup"],
  [/rocket-loader|data-cfasync/, "Cloudflare Rocket Loader"],
];

export function findInjections(html) {
  return INJECTIONS.filter(([re]) => re.test(html)).map(([, what]) => what);
}

// A browser-like Accept header: some hosts inject only into responses for browsers.
const HTML_REQUEST = { redirect: "manual", headers: { accept: "text/html,application/xhtml+xml" } };
const HTML_PAGES = ["/", "/research/", "/trust/", "/app/"];

export async function check(base, rules, fetchImpl = fetch) {
  const failures = [];
  const home = await fetchImpl(new URL("/", base), HTML_REQUEST);
  const html = await home.text();
  function compareHeaders(path, res) {
    for (const [name, value] of Object.entries(expectedFor(rules, path))) {
      const got = res.headers.get(name);
      if (got === null) failures.push(`${path}: missing ${name}`);
      else if (got !== value) failures.push(`${path}: ${name} differs\n    expected: ${value}\n    got:      ${got}`);
    }
  }
  const asset = (html.match(/\/assets\/[\w.-]+\.(?:js|css)/) || [])[0];
  const paths = [...HTML_PAGES, ...(asset ? [asset] : [])];
  if (!asset) failures.push("could not find a hashed asset on the homepage");
  for (const path of paths) {
    const res = path === "/" ? home : await fetchImpl(new URL(path, base), HTML_REQUEST);
    if (res.status !== 200) failures.push(`${path}: HTTP ${res.status}`);
    if (HTML_PAGES.includes(path)) {
      const body = path === "/" ? html : await res.text();
      for (const what of findInjections(body)) failures.push(`${path}: served HTML contains ${what}; turn the feature off for this zone`);
    }
    compareHeaders(path, res);
  }
  // An unknown path must be a real 404 (not the homepage with 200) and must
  // still carry the security headers.
  const missingPath = "/__securemind-404-check__/";
  const notFound = await fetchImpl(new URL(missingPath, base), { redirect: "manual" });
  if (notFound.status !== 404) failures.push(`${missingPath}: expected HTTP 404, got ${notFound.status}`);
  compareHeaders(missingPath, notFound);
  paths.push(`${missingPath} (expects 404)`);
  return { paths, failures };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const base = process.argv[2];
  if (!base || !/^https:\/\//.test(base)) {
    console.error("usage: node scripts/check-headers.mjs https://<preview-host>");
    process.exit(2);
  }
  const rules = parseHeadersFile(await readFile(new URL("../public/_headers", import.meta.url), "utf8"));
  const { paths, failures } = await check(base, rules);
  console.log(`checked ${paths.join(", ")} on ${base}`);
  if (failures.length) {
    for (const f of failures) console.log(`FAIL ${f}`);
    process.exit(1);
  }
  console.log("PASS: every header from public/_headers is served exactly");
}
