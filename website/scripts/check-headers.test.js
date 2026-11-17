import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import test from "node:test";
import { check, expectedFor, findInjections, parseHeadersFile } from "./check-headers.mjs";

const rules = parseHeadersFile(await readFile(new URL("../public/_headers", import.meta.url), "utf8"));

test("_headers parses into the expected rules", () => {
  assert.deepEqual(rules.map((r) => r.pattern), ["/*", "/assets/*"]);
  const all = expectedFor(rules, "/");
  for (const name of ["content-security-policy", "x-content-type-options", "x-frame-options", "referrer-policy",
    "permissions-policy", "strict-transport-security", "cross-origin-opener-policy"]) {
    assert.ok(all[name], `missing ${name}`);
  }
  assert.match(all["content-security-policy"], /script-src 'self'/);
  assert.match(all["content-security-policy"], /connect-src 'none'/);
  assert.match(all["content-security-policy"], /frame-ancestors 'none'/);
  assert.ok(!/unsafe-inline|unsafe-eval/.test(all["content-security-policy"]));
  assert.ok(expectedFor(rules, "/assets/main-x.js")["cache-control"].includes("immutable"));
  assert.equal(expectedFor(rules, "/")["cache-control"], undefined);
});

test("every _headers line is within Cloudflare's 2,000-character limit", async () => {
  const text = await readFile(new URL("../public/_headers", import.meta.url), "utf8");
  assert.ok(text.split(/\r?\n/).every((l) => l.length <= 2000));
  assert.ok(rules.length <= 100);
});

async function serve(dropHeader, { soft404 = false, inject = "", weak404 = false } = {}) {
  const known = new Set(["/", "/research/", "/trust/", "/app/", "/assets/main-abc.js"]);
  const server = createServer((req, res) => {
    const headers = { "content-type": "text/html", ...expectedFor(rules, req.url) };
    if (dropHeader) delete headers[dropHeader];
    if (weak404 && !known.has(req.url)) headers["content-security-policy"] = "default-src *";
    res.writeHead(known.has(req.url) || soft404 ? 200 : 404, headers);
    res.end(`<script type="module" src="/assets/main-abc.js"></script>${inject}`);
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return { server, base: `http://127.0.0.1:${server.address().port}` };
}

test("check() passes when the host serves every configured header", async () => {
  const { server, base } = await serve(null);
  try {
    const { paths, failures } = await check(base, rules);
    assert.deepEqual(paths, ["/", "/research/", "/trust/", "/app/", "/assets/main-abc.js", "/__securemind-404-check__/ (expects 404)"]);
    assert.deepEqual(failures, []);
  } finally { server.close(); }
});

test("check() reports a missing header", async () => {
  const { server, base } = await serve("content-security-policy");
  try {
    const { failures } = await check(base, rules);
    assert.ok(failures.some((f) => f.includes("missing content-security-policy")));
  } finally { server.close(); }
});

test("check() reports a soft 404 (unknown path served with 200)", async () => {
  const { server, base } = await serve(null, { soft404: true });
  try {
    const { failures } = await check(base, rules);
    assert.ok(failures.some((f) => f.includes("expected HTTP 404, got 200")));
  } finally { server.close(); }
});

test("findInjections recognises host-injected markup and nothing in clean HTML", () => {
  assert.deepEqual(findInjections('<a href="mailto:a@b.c">a@b.c</a><script type="module" src="/assets/x.js"></script>'), []);
  assert.equal(findInjections('<script defer src="https://static.cloudflareinsights.com/beacon.min.js" data-cf-beacon="{}"></script>').length, 1);
  assert.equal(findInjections('<a href="/cdn-cgi/l/email-protection#ab"><span class="__cf_email__">[email&#160;protected]</span></a>').length, 2);
});

test("check() fails when the host injects scripts into HTML", async () => {
  const { server, base } = await serve(null, { inject: '<script src="/cdn-cgi/scripts/5c5dd728/cloudflare-static/email-decode.min.js"></script>' });
  try {
    const { failures } = await check(base, rules);
    assert.ok(failures.some((f) => f.includes("/cdn-cgi/")));
  } finally { server.close(); }
});

test("the policy quoted on the trust page is the policy actually served", async () => {
  const page = await readFile(new URL("../trust/index.html", import.meta.url), "utf8");
  const quoted = /<p class="csp">([^<]+)<\/p>/.exec(page)?.[1].replace(/&#39;|&apos;/g, "'");
  assert.equal(quoted, expectedFor(rules, "/")["content-security-policy"]);
  assert.match(quoted, /trusted-types 'none'/);
});

test("check() compares every header on the 404 page, not only that a policy exists", async () => {
  const { server, base } = await serve(null, { weak404: true });
  try {
    const { failures } = await check(base, rules);
    assert.ok(failures.some((f) => f.startsWith("/__securemind-404-check__/: content-security-policy differs")), failures.join("\n"));
  } finally { server.close(); }
});
