import assert from "node:assert/strict";
import test from "node:test";
import { analyzeUrl } from "../engine/analyze.js";
import { FINDING_NAMES } from "../engine/finding-names.js";
import { PSL_COMMIT, RULES } from "../engine/generated/psl-rules.js";
import { PublicSuffixList } from "../engine/psl.js";
import { duration } from "./format.js";
import { alertsToCsv, reportToMarkdown } from "./io.js";
import { createMemoryStore } from "./stores.js";
import { createWorkspace, WorkspaceError } from "./workspace.js";

const psl = new PublicSuffixList(RULES, PSL_COMMIT);
let clock = Date.parse("2026-11-01T08:00:00Z");
const now = () => new Date((clock += 60_000));
let n = 0;
const fresh = () => createWorkspace(createMemoryStore(), { now, newId: () => `rp-${++n}` });
const item = (u, extra = {}) => ({ report: analyzeUrl(u, { psl, now }), source: "user-report", ...extra });

test("the period report counts intake, outcomes, lures, cases and indicators from stored records", async () => {
  const ws = fresh();
  const { created } = await ws.queueAlerts([
    item("http://paypal.com.secure-account.tk/login"), item("http://paypal.com.secure-account.tk/login"), item("http://secure-account.tk/paypal/signin", { source: "mail-filter" }),
    item("https://www.example.org/docs"),
  ]);
  const [lure, second, plain] = created;
  await ws.closeAlerts([plain.id], { disposition: "false-positive" });
  const { investigation } = await ws.escalateAlert(lure.id, { playbookId: "credential-phishing" });
  await ws.setTaskDone(investigation.id, investigation.tasks[0].id, true);
  await ws.closeAlerts([second.id], { disposition: "true-positive" });
  await ws.upsertIndicator({ type: "domain", value: "secure-account.tk", investigationId: investigation.id });

  const r = await ws.report({ days: 7 });
  assert.equal(r.alerts.queued, 3);
  assert.equal(r.alerts.reports, 4, "the repeat counts as a report");
  assert.deepEqual(r.alerts.bySource, { "user-report": 2, "mail-filter": 1 });
  assert.equal(r.alerts.escalated, 1);
  assert.equal(r.alerts.metrics.closedRecent, 2);
  assert.equal(r.alerts.metrics.falsePositiveRate, 0.5);
  assert.deepEqual(r.topLures, [{ domain: "secure-account.tk", alerts: 2, reports: 3 }], "the plain link is not a lure");
  assert.equal(r.investigations.opened, 1);
  assert.deepEqual(r.investigations.checklist, { done: 1, total: 7 });
  assert.equal(r.indicators.recorded, 1);
  assert.ok(r.topFindings.length > 0);

  // A later window excludes all of it.
  clock += 30 * 864e5;
  const later = await ws.report({ days: 7 });
  assert.equal(later.alerts.queued, 0);
  assert.deepEqual(later.topLures, []);
  await assert.rejects(ws.report({ days: 0 }), WorkspaceError);
  await assert.rejects(ws.report({ days: 1.5 }), WorkspaceError);
});

test("closing an investigation in the period counts once, however often its status changed", async () => {
  const ws = fresh();
  const inv = await ws.createInvestigation({ title: "Case" });
  await ws.updateInvestigation(inv.id, { status: "closed" });
  await ws.updateInvestigation(inv.id, { status: "investigating" });
  await ws.updateInvestigation(inv.id, { status: "closed" });
  assert.equal((await ws.report({ days: 7 })).investigations.closed, 1);
});

test("the report export defangs every domain and states its method", async () => {
  const ws = fresh();
  await ws.queueAlerts([item("http://paypal.com.secure-account.tk/login")]);
  const out = reportToMarkdown(await ws.report({ days: 30 }), FINDING_NAMES, new Date("2026-12-01T00:00:00Z"));
  for (const h of ["## Alert queue", "## Top lure domains (high risk or suspicious)", "## Investigations", "## Indicators", "## Method"]) assert.ok(out.includes(h), h);
  assert.match(out, /\| `secure-account\[\.\]tk` \| 1 \| 1 \|/);
  assert.equal(out.match(/[a-z0-9-]\.(?:tk|com|org|example)\b/gi), null, "no live domain");
});

test("the alert CSV is defanged and formula-safe", async () => {
  const ws = fresh();
  const { created } = await ws.queueAlerts([item("http://paypal.com.secure-account.tk/login", { externalId: "=HYPERLINK(\"x\")", reporter: "+1 555", source: "@siem" })]);
  const csv = alertsToCsv(created);
  const [head, row] = csv.trim().split("\r\n");
  assert.ok(head.startsWith("queued,severity,status,disposition,verdict,url_defanged"));
  assert.match(row, /hxxp:\/\/paypal\[\.\]com\[\.\]secure-account\[\.\]tk\/login/);
  assert.match(row, /"'=HYPERLINK\(""x""\)"/);
  assert.match(row, /,'\+1 555,/);
  assert.match(row, /,'@siem,/);
  assert.ok(!/http:\/\//.test(csv));
});

test("durations read naturally", () => {
  assert.deepEqual([null, 20_000, 12 * 60_000, 5 * 3600_000, 72 * 3600_000].map(duration), ["—", "under 1 min", "12 min", "5 h", "3 days"]);
});
