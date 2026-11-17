import assert from "node:assert/strict";
import test from "node:test";
import { analyzeUrl } from "../engine/analyze.js";
import { PSL_COMMIT, RULES } from "../engine/generated/psl-rules.js";
import { PublicSuffixList } from "../engine/psl.js";
import { exportBackup, importBackup, parseBackup } from "./io.js";
import { createMemoryStore } from "./stores.js";
import { createWorkspace, isIntact, MAX_RULES, WorkspaceError } from "./workspace.js";

const psl = new PublicSuffixList(RULES, PSL_COMMIT);
let clock = Date.parse("2026-11-12T08:00:00Z");
const now = () => new Date((clock += 60_000));
let n = 0;
const newId = () => `r-${++n}`;
const fresh = () => createWorkspace(createMemoryStore(), { now, newId });
const report = (u) => analyzeUrl(u, { psl, now });
const item = (u, extra = {}) => ({ report: report(u), source: "user-report", ...extra });
const reanalyze = (u, at) => analyzeUrl(u, { psl, now: () => new Date(at) });

const SAFE = "https://www.example.org/docs";
const LURE = "http://paypal.com.secure-account.tk/login";

test("a close rule closes matching new alerts at intake, names itself, and folds repeats", async () => {
  const ws = fresh();
  const rule = await ws.createRule({ name: "Vendor docs", field: "domain", value: "EXAMPLE.org.", action: "close", disposition: "benign" });
  assert.deepEqual(rule.match, { field: "domain", value: "example.org" }, "values are normalised");
  const first = await ws.queueAlerts([item(SAFE), item("https://paypa1.com/signin")]);
  assert.equal(first.closedByRule, 1);
  const closed = first.created.find((a) => a.host === "www.example.org");
  assert.equal(closed.status, "closed");
  assert.equal(closed.disposition, "benign");
  assert.equal(closed.closedByRule, rule.id);
  assert.equal(closed.history.at(-1).detail, "Closed as benign by rule “Vendor docs”");
  assert.ok(isIntact("alerts", closed));

  // Fifty more reports of the same link: one alert, one analysis.
  const again = await ws.queueAlerts(Array.from({ length: 50 }, () => item(SAFE)));
  assert.equal(again.created.length, 0);
  assert.equal(again.merged, 50);
  assert.equal((await ws.getAlert(closed.id)).occurrences, 51);
  assert.equal((await ws.listAnalyses()).length, 2);
  const [r] = await ws.listRules();
  assert.equal(r.hits, 1, "repeats folded into the closed alert do not re-run the rule");
  const queued = (await ws.activity()).filter((e) => e.kind === "alert.queued"); // newest first
  assert.match(queued.at(-1).summary, /^Queued 2 alerts; 1 closed by queue rules$/);
});

test("a close rule never closes a link judged high risk or suspicious; it says so", async () => {
  const ws = fresh();
  await ws.createRule({ name: "Allow the lure domain", field: "domain", value: "secure-account.tk", action: "close", disposition: "false-positive" });
  const { created: [al], closedByRule } = await ws.queueAlerts([item(LURE)]);
  assert.equal(closedByRule, 0);
  assert.equal(al.status, "new");
  assert.match(al.history.at(-1).detail, /^Matched rule “Allow the lure domain”; not closed, because the link was judged high risk$/);
});

test("severity rules, rule order, switching off, and deletion", async () => {
  const ws = fresh();
  const a = await ws.createRule({ name: "Payroll lures are critical", field: "host", value: "paypal.com.secure-account.tk", action: "severity", severity: "critical" });
  await ws.createRule({ name: "Later rule never wins", field: "domain", value: "secure-account.tk", action: "severity", severity: "low" });
  let { created: [al] } = await ws.queueAlerts([item(LURE)]);
  assert.equal(al.severity, "critical", "the oldest matching rule wins");
  assert.match(al.history.at(-1).detail, /high → critical by rule/);
  await ws.closeAlerts([al.id], { disposition: "true-positive" });
  await ws.setRuleEnabled(a.id, false);
  ({ created: [al] } = await ws.queueAlerts([item(LURE)]));
  assert.equal(al.severity, "low", "a switched-off rule is skipped");
  await ws.deleteRule(a.id);
  assert.equal((await ws.listRules()).length, 1);
  await assert.rejects(ws.deleteRule(a.id), /not found/);
});

test("source rules match the intake source exactly", async () => {
  const ws = fresh();
  await ws.createRule({ name: "Sandbox tests", field: "source", value: "sandbox", action: "close", disposition: "duplicate" });
  const { created } = await ws.queueAlerts([item(SAFE, { source: "sandbox" }), item("https://www.example.com/", { source: "Sandbox2" })]);
  assert.deepEqual(created.map((x) => x.status), ["closed", "new"]);
});

test("rules are validated: exact values only, safe dispositions, no shared platforms, capped", async () => {
  const ws = fresh();
  const bad = [
    [{ name: "", field: "host", value: "a.example", action: "close", disposition: "benign" }, /needs a name/],
    [{ name: "x".repeat(81), field: "host", value: "a.example", action: "close", disposition: "benign" }, /at most 80/],
    [{ name: "Regex", field: "host", value: ".*", action: "close", disposition: "benign" }, /not a valid host/],
    [{ name: "Pattern", field: "regex", value: "a", action: "close", disposition: "benign" }, /unknown rule field/],
    [{ name: "TP", field: "host", value: "a.example", action: "close", disposition: "true-positive" }, /only as benign/],
    [{ name: "Shared", field: "domain", value: "sharepoint.com", action: "close", disposition: "benign" }, /anyone can publish on sharepoint\.com/],
    [{ name: "Sev", field: "host", value: "a.example", action: "severity", severity: "urgent" }, /unknown severity/],
    [{ name: "Act", field: "host", value: "a.example", action: "delete" }, /unknown rule action/],
  ];
  for (const [input, err] of bad) await assert.rejects(ws.createRule(input), err, JSON.stringify(input));
  // A host rule on a shared platform is allowed: it names one known address.
  await ws.createRule({ name: "Our tenant", field: "host", value: "corp.sharepoint.com", action: "close", disposition: "benign" });
  await ws.createRule({ name: "Raise shared", field: "domain", value: "sharepoint.com", action: "severity", severity: "high" });
  for (let i = 2; i < MAX_RULES; i++) await ws.createRule({ name: `r${i}`, field: "host", value: `h${i}.example`, action: "severity", severity: "low" });
  await assert.rejects(ws.createRule({ name: "one more", field: "host", value: "z.example", action: "severity", severity: "low" }), WorkspaceError);
});

test("rule-closed alerts are counted apart and kept out of the queue medians", async () => {
  const ws = fresh();
  await ws.createRule({ name: "Docs", field: "domain", value: "example.org", action: "close", disposition: "false-positive" });
  const { created } = await ws.queueAlerts([item(SAFE), item("https://paypa1.com/signin")]);
  const manual = created.find((a) => a.status === "new");
  await ws.closeAlerts([manual.id], { disposition: "true-positive" });
  const m = await ws.alertMetrics();
  assert.equal(m.closedByRule, 1);
  assert.equal(m.closedRecent, 1);
  assert.equal(m.falsePositiveRate, 0, "the rule's false-positive close is not the analyst's");
  assert.ok(m.timeToClose > 0);

  // Reopened and closed by an analyst, it counts as analyst work.
  const ruled = created.find((a) => a.closedByRule);
  await ws.reopenAlert(ruled.id);
  assert.equal((await ws.getAlert(ruled.id)).closedByRule, null);
});

test("a backup restores rules switched off; a shared-domain close rule cannot be switched on", async () => {
  const source = fresh();
  const rule = await source.createRule({ name: "Docs", field: "domain", value: "example.org", action: "close", disposition: "benign" });
  await source.queueAlerts([item(SAFE)]);
  const backup = await exportBackup(source.store);
  backup.records.rules.push(
    { ...backup.records.rules[0], id: "evil-1", match: { field: "domain", value: "sharepoint.com" } },
    { ...backup.records.rules[0], id: "bad-1", match: { field: "host", value: "not a host" } },
    { ...backup.records.rules[0], id: "bad-2", action: { type: "close", disposition: "true-positive" } },
  );
  const ws = fresh();
  const counts = await importBackup(ws.store, parseBackup(JSON.stringify(backup), reanalyze));
  assert.equal(counts.rejected, 2);
  const rules = await ws.listRules();
  assert.deepEqual(rules.map((r) => [r.id, r.enabled]), [[rule.id, false], ["evil-1", false]]);
  await assert.rejects(ws.setRuleEnabled("evil-1", true), /anyone can publish on sharepoint\.com/);
  await ws.setRuleEnabled(rule.id, true);
  const [al] = await ws.listAlerts();
  assert.equal(al.closedByRule, rule.id, "the alert keeps which rule closed it");
});
