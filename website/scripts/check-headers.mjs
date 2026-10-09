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

export async function check(base, rules, fetchImpl = fetch) {
  const failures = [];
  const home = await fetchImpl(new URL("/", base), { redirect: "manual" });
  const html = await home.text();
  const asset = (html.match(/\/assets\/[\w.-]+\.(?:js|css)/) || [])[0];
  const paths = ["/", "/research/", ...(asset ? [asset] : [])];
  if (!asset) failures.push("could not find a hashed asset on the homepage");
  for (const path of paths) {
    const res = path === "/" ? home : await fetchImpl(new URL(path, base), { redirect: "manual" });
    if (res.status !== 200) failures.push(`${path}: HTTP ${res.status}`);
    for (const [name, value] of Object.entries(expectedFor(rules, path))) {
      const got = res.headers.get(name);
      if (got === null) failures.push(`${path}: missing ${name}`);
      else if (got !== value) failures.push(`${path}: ${name} differs\n    expected: ${value}\n    got:      ${got}`);
    }
  }
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
