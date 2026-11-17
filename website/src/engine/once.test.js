import assert from "node:assert/strict";
import test from "node:test";
import { onceUnlessFailed } from "./once.js";

test("a successful load runs once; a failed load is retried on the next call", async () => {
  let calls = 0;
  const load = onceUnlessFailed(async () => {
    calls++;
    if (calls === 1) throw new Error("offline");
    return "rules";
  });
  await assert.rejects(load(), /offline/);
  assert.equal(await load(), "rules");
  assert.equal(await load(), "rules");
  assert.equal(calls, 2);
});

test("concurrent callers share one load", async () => {
  let calls = 0;
  const load = onceUnlessFailed(async () => ++calls);
  assert.deepEqual(await Promise.all([load(), load()]), [1, 1]);
});
