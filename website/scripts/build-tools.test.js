import assert from "node:assert/strict";
import test from "node:test";
import { fillMetrics, format, pointer } from "./research-metrics.mjs";

const data = { engine: { test: { a: { roc_auc: 0.91555, n: 35816, "at_app_default_0.5": { recall: 0.1316 } } } } };
const load = (file) => (file === "engine/metrics.json" ? data.engine : (() => { throw new Error(`no ${file}`); })());

test("metric tokens are replaced from the report files", () => {
  assert.equal(fillMetrics("<b>{{m:engine:/test/a/roc_auc|f3}}</b> of {{m:engine:/test/a/n|int}}", load), "<b>0.916</b> of 35,816");
  assert.equal(fillMetrics("{{m:engine:/test/a/at_app_default_0.5/recall|pct1}}", load), "13.2%");
});

test("missing metrics, unknown sources and bad formats fail the build", () => {
  assert.throws(() => fillMetrics("{{m:engine:/test/b/roc_auc|f3}}", load), /not found/);
  assert.throws(() => fillMetrics("{{m:nope:/x|f3}}", load), /unknown metrics source/);
  assert.throws(() => format(0.5, "weird"), /unknown format/);
  assert.throws(() => format("0.5", "f2"), /not a number/);
  assert.equal(format("url-host-ea3f55ce1c18faa2", "id"), "url-host-ea3f55ce1c18faa2");
  assert.throws(() => format("<b>x</b>", "id"), /not an identifier/);
  assert.equal(pointer({ "a/b": 1 }, "/a~1b"), 1);
});

test("serve-dist refuses traversal outside dist", async () => {
  const { resolvePath } = await import("./serve-dist.mjs");
  assert.equal(resolvePath("/..%2fdist-other%2fx"), null);
  assert.equal(resolvePath("/../package.json"), null);
});

test("credentials are masked before rejected input is echoed", async () => {
  const { maskCredentials } = await import("../src/engine/defang.js");
  assert.equal(maskCredentials("ftp://admin:secret@h/x"), "ftp://•••@h/x");
  assert.equal(maskCredentials("hxxp://user:hunter2[at]evil.example/ x"), "http://•••@evil.example/ x");
  assert.equal(maskCredentials("user:hunter2@evil.example"), "•••@evil.example");
});
