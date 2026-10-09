import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import test from "node:test";
import { check, expectedFor, parseHeadersFile } from "./check-headers.mjs";

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

async function serve(dropHeader) {
  const server = createServer((req, res) => {
    const headers = { "content-type": "text/html", ...expectedFor(rules, req.url) };
    if (dropHeader) delete headers[dropHeader];
    res.writeHead(200, headers);
    res.end('<script type="module" src="/assets/main-abc.js"></script>');
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return { server, base: `http://127.0.0.1:${server.address().port}` };
}

test("check() passes when the host serves every configured header", async () => {
  const { server, base } = await serve(null);
  try {
    const { paths, failures } = await check(base, rules);
    assert.deepEqual(paths, ["/", "/research/", "/assets/main-abc.js"]);
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
