import assert from "node:assert/strict";
import test from "node:test";
import { analyzeUrl } from "../engine/analyze.js";
import { PSL_COMMIT, RULES } from "../engine/generated/psl-rules.js";
import { PublicSuffixList } from "../engine/psl.js";
import { loadDemoWorkspace } from "./demo.js";
import { exportBackup, ImportError, importBackup, MAX_ALERT_IMPORT, parseAlertFile, parseBackup } from "./io.js";
import { createMemoryStore } from "./stores.js";
import { createWorkspace, isIntact, WorkspaceError } from "./workspace.js";

const psl = new PublicSuffixList(RULES, PSL_COMMIT);
let clock = Date.parse("2026-11-01T09:00:00Z");
const now = () => new Date((clock += 60_000)); // every timestamp is one minute later
let n = 0;
const newId = () => `al-${++n}`;
const analyze = (u) => analyzeUrl(u, { psl, now });
const reanalyze = (u, at) => analyzeUrl(u, { psl, now: () => new Date(at) });
const fresh = (store = createMemoryStore()) => createWorkspace(store, { now, newId });
const item = (url, extra = {}) => ({ report: analyze(url), source: "user-report", ...extra });

const LURE = "http://paypal.com.secure-account.tk/login";
const PLAIN = "https://www.example.org/docs";

test("queueing saves the analysis, takes severity from the verdict, and folds repeats into one alert", async () => {
  const ws = fresh();
  const { created, merged } = await ws.queueAlerts([item(LURE, { reporter: "a@corp.example", externalId: "INC-1" }), item(PLAIN), item(LURE)]);
  assert.equal(created.length, 2);
  assert.equal(merged, 1, "the repeat inside one batch is merged too");
  const lure = created.find((a) => a.host === "paypal.com.secure-account.tk");
  assert.equal(lure.severity, "high");
  assert.equal(lure.status, "new");
  assert.equal(lure.occurrences, 2);
  assert.deepEqual(lure.history.map((h) => h.action), ["created", "repeat"]);
  assert.equal((await ws.getAnalysis(lure.analysisId)).verdict, "high-risk");
  assert.equal(created.find((a) => a !== lure).severity, "low");
  assert.equal((await ws.listAnalyses()).length, 2, "a repeat does not save another analysis");
  assert.equal((await ws.activity()).filter((e) => e.kind === "alert.queued").length, 1);

  // Once closed, the same link starts a new alert.
  await ws.closeAlerts([lure.id], { disposition: "true-positive" });
  const again = await ws.queueAlerts([item(LURE)]);
  assert.equal(again.created.length, 1);
  assert.notEqual(again.created[0].id, lure.id);
});

test("a bad item queues nothing: invalid reports and over-long fields are rejected, never cut", async () => {
  const ws = fresh();
  await assert.rejects(ws.queueAlerts([item(LURE), { report: analyze("javascript:alert(1)") }]), WorkspaceError);
  await assert.rejects(ws.queueAlerts([item(LURE, { reporter: "x".repeat(201) })]), /too long/);
  await assert.rejects(ws.queueAlerts([item(LURE, { externalId: "y".repeat(121) })]), /too long/);
  assert.equal((await ws.listAlerts()).length, 0);
  assert.equal((await ws.listAnalyses()).length, 0);
});

test("triage, severity, close and reopen keep an auditable history", async () => {
  const ws = fresh();
  const { created: [a, b] } = await ws.queueAlerts([item(LURE), item("https://paypa1.com/signin")]);
  const [t] = await ws.triageAlerts([a.id, a.id]);
  assert.equal(t.status, "triage");
  assert.ok(t.triagedAt);
  assert.deepEqual(await ws.triageAlerts([a.id]), [], "only new alerts move to triage");

  await ws.setAlertSeverity(a.id, "critical");
  await ws.setAlertSeverity(a.id, "critical"); // no-op: no history entry
  await assert.rejects(ws.setAlertSeverity(a.id, "urgent"), WorkspaceError);

  await assert.rejects(ws.closeAlerts([a.id], { disposition: "maybe" }), /disposition/);
  await assert.rejects(ws.closeAlerts([a.id], { disposition: "benign", comment: "z".repeat(1001) }), /too long/);
  await assert.rejects(ws.closeAlerts([a.id, "missing"], { disposition: "benign" }), /not found/);
  assert.equal((await ws.getAlert(a.id)).status, "triage", "a failed bulk close changes nothing");

  const closed = await ws.closeAlerts([a.id, b.id], { disposition: "false-positive", comment: "Internal test page" });
  assert.equal(closed.length, 2);
  const got = await ws.getAlert(b.id);
  assert.equal(got.disposition, "false-positive");
  assert.ok(got.triagedAt && got.closedAt, "closing straight from new counts as triaged");
  assert.deepEqual(await ws.closeAlerts([b.id], { disposition: "benign" }), [], "a closed alert keeps its disposition");

  const reopened = await ws.reopenAlert(a.id);
  assert.equal(reopened.status, "triage");
  assert.equal(reopened.disposition, null);
  assert.deepEqual(reopened.history.map((h) => h.action), ["created", "triage", "severity", "closed", "reopened"]);
  assert.ok(isIntact("alerts", reopened));
});

test("escalation opens or joins an investigation, and deletes cascade without dangling links", async () => {
  const ws = fresh();
  const { created: [a, b] } = await ws.queueAlerts([item(LURE, { externalId: "INC-7" }), item("http://3232235777/bank/login")]);
  const { alert, investigation } = await ws.escalateAlert(a.id);
  assert.equal(alert.status, "escalated");
  assert.equal(investigation.priority, "high", "the case starts at the alert's severity");
  assert.match(investigation.title, /^Alert: paypal\[\.\]com/);
  assert.match(investigation.summary, /INC-7/);
  assert.deepEqual(investigation.analysisIds, [a.analysisId]);
  assert.deepEqual(investigation.history.map((h) => h.action), ["created", "linked", "alert"]);

  await ws.escalateAlert(b.id, { investigationId: investigation.id });
  assert.equal((await ws.getInvestigation(investigation.id)).analysisIds.length, 2);
  await assert.rejects(ws.escalateAlert(b.id, { investigationId: "nope" }), /not found/);

  await ws.closeAlerts([b.id], { disposition: "true-positive" });
  await assert.rejects(ws.escalateAlert(b.id), /reopen/);
  assert.equal((await ws.reopenAlert(b.id)).status, "escalated", "reopening keeps the case link");

  await ws.deleteAnalysis(a.analysisId);
  assert.equal((await ws.getAlert(a.id)).analysisId, null);
  await ws.deleteInvestigation(investigation.id);
  for (const id of [a.id, b.id]) {
    const al = await ws.getAlert(id);
    assert.equal(al.status, "triage");
    assert.equal(al.investigationId, null);
    assert.ok(isIntact("alerts", al));
  }
  await ws.deleteAlerts([a.id]);
  await assert.rejects(ws.getAlert(a.id), /not found/);
  assert.ok(await ws.getAnalysis(b.analysisId), "deleting an alert keeps its analysis");
});

test("the queue sorts by status, severity and age, filters, searches and pages", async () => {
  const ws = fresh();
  const { created } = await ws.queueAlerts([
    item(PLAIN, { source: "siem" }), item(LURE, { reporter: "pat@corp.example" }), item("https://paypa1.com/signin"), item("https://example.com/a"),
  ]);
  await ws.closeAlerts([created[3].id], { disposition: "benign" });
  const all = await ws.listAlerts();
  assert.deepEqual(all.map((a) => a.status), ["new", "new", "new", "closed"]);
  assert.equal(all[0].severity, "high");
  assert.equal((await ws.listAlerts({ status: "open" })).length, 3);
  assert.equal((await ws.listAlerts({ status: "closed" })).length, 1);
  assert.equal((await ws.listAlerts({ severity: "low", status: "open" })).length, 1);
  assert.equal((await ws.listAlerts({ query: "PAT@corp" }))[0].id, created[1].id, "search covers the reporter");
  assert.equal((await ws.listAlerts({ query: "siem" }))[0].id, created[0].id, "and the source");
  const page = await ws.listAlerts({ offset: 99, limit: 3 });
  assert.deepEqual([page.offset, page.items.length, page.total], [3, 1, 4], "past the end shows the last page");
});

test("queue metrics: backlog, dispositions, median time to triage and to close", async () => {
  const ws = fresh();
  const { created: [a, b, c] } = await ws.queueAlerts([item(LURE), item(PLAIN), item("https://paypa1.com/signin")]);
  await ws.triageAlerts([a.id]);
  await ws.closeAlerts([b.id], { disposition: "false-positive" });
  await ws.closeAlerts([a.id], { disposition: "true-positive" });
  const m = await ws.alertMetrics({ days: 30 });
  assert.equal(m.total, 3);
  assert.equal(m.open, 1);
  assert.equal(m.openBySeverity.medium + m.openBySeverity.high + m.openBySeverity.low, 1);
  assert.equal(m.oldestOpen, c.createdAt);
  assert.equal(m.closedRecent, 2);
  assert.equal(m.falsePositiveRate, 0.5);
  assert.deepEqual(m.byDisposition, { "true-positive": 1, benign: 0, "false-positive": 1, duplicate: 0 });
  assert.ok(m.timeToTriage > 0 && m.timeToClose >= m.timeToTriage);
  const empty = await fresh().alertMetrics();
  assert.equal(empty.falsePositiveRate, null);
  assert.equal(empty.timeToClose, null);
});

test("alerts survive a backup round trip; older backups without alerts still restore", async () => {
  const source = fresh();
  const { created: [a, b] } = await source.queueAlerts([item(LURE, { reporter: "r@corp.example" }), item(PLAIN)]);
  const { investigation } = await source.escalateAlert(a.id);
  const longComment = `${"c".repeat(999)}!`;
  await source.closeAlerts([b.id], { disposition: "benign", comment: longComment });
  const backup = await exportBackup(source.store);

  const ws = fresh();
  const counts = await importBackup(ws.store, parseBackup(JSON.stringify(backup), reanalyze));
  assert.equal(counts.rejected, 0);
  const restored = await ws.getAlert(a.id);
  assert.equal(restored.status, "escalated");
  assert.equal(restored.investigationId, investigation.id);
  assert.equal(restored.reporter, "r@corp.example");
  const closedB = await ws.getAlert(b.id);
  assert.equal(closedB.disposition, "benign");
  assert.equal(closedB.history.at(-1).detail, `benign: ${longComment}`, "a full-length close comment survives the round trip uncut");

  // A backup made before alerts existed has no "alerts" section.
  const old = structuredClone(backup);
  delete old.records.alerts;
  const ws2 = fresh();
  await importBackup(ws2.store, parseBackup(JSON.stringify(old), reanalyze));
  assert.equal((await ws2.listAlerts()).length, 0);
  assert.equal((await ws2.listInvestigations()).length, 1);
});

test("a tampered backup cannot forge an alert's verdict or leave it escalated to a missing case", async () => {
  const source = fresh();
  const { created: [a] } = await source.queueAlerts([item(LURE)]);
  await source.escalateAlert(a.id);
  const backup = await exportBackup(source.store);
  const al = backup.records.alerts[0];
  Object.assign(al, { verdict: "no-strong-indicators", host: "bank.example", registrableDomain: "bank.example" });
  backup.records.investigations = []; // the case is missing
  backup.records.alerts.push(
    { ...al, id: "bad-1", status: "closed", disposition: "whatever", closedAt: al.createdAt },
    { ...al, id: "bad-2", reporter: "x".repeat(201) },
    { ...al, id: "bad-3", url: "javascript:alert(1)" },
    { ...al, id: "bad-4", history: [{ at: al.createdAt, action: "pwned", detail: "x" }], occurrences: -5 },
  );
  const ws = fresh();
  const counts = await importBackup(ws.store, parseBackup(JSON.stringify(backup), reanalyze));
  assert.equal(counts.rejected, 3);
  const got = await ws.getAlert(a.id);
  assert.equal(got.verdict, "high-risk", "the verdict comes from re-analysis");
  assert.equal(got.host, "paypal.com.secure-account.tk");
  assert.equal(got.status, "triage");
  assert.equal(got.investigationId, null);
  const four = await ws.getAlert("bad-4");
  assert.equal(four.occurrences, 1);
  assert.deepEqual(four.history, []);
});

test("alert files: text, CSV and JSON; long fields rejected; size and count capped", () => {
  const text = parseAlertFile("﻿hxxp://evil[.]example/login\n\n  https://example.org/  \n");
  assert.equal(text.format, "text");
  assert.deepEqual(text.items.map((i) => i.input), ["hxxp://evil[.]example/login", "https://example.org/"]);

  const csv = parseAlertFile(`Source,URL,External_ID,Reporter\nproofpoint,"https://a.example/x,y",'=HYPERLINK(1),pat@corp.example\nsiem,,X,\nsiem,https://b.example/,${"r".repeat(121)},`);
  assert.equal(csv.format, "CSV");
  assert.deepEqual(csv.items, [{ input: "https://a.example/x,y", source: "proofpoint", externalId: "=HYPERLINK(1)", reporter: "pat@corp.example" }]);
  assert.equal(csv.rejected, 2, "an empty link and an over-long reference are rejected");

  const json = parseAlertFile(JSON.stringify({ alerts: [{ URL: "https://c.example/", Ref: "T-1" }, "https://d.example/", 42, { url: "https://e.example/", source: ["x"] }, { url: "https://f.example/", id: 1234 }] }));
  assert.equal(json.format, "JSON");
  assert.deepEqual(json.items.map((i) => [i.input, i.externalId]), [["https://c.example/", "T-1"], ["https://d.example/", ""], ["https://f.example/", "1234"]]);
  assert.equal(json.rejected, 2, "a bare number and a non-text source are rejected; a numeric ticket id is kept as text");

  assert.throws(() => parseAlertFile("{nope"), ImportError);
  assert.throws(() => parseAlertFile('{"a":1}'), ImportError);
  assert.throws(() => parseAlertFile(Array.from({ length: MAX_ALERT_IMPORT + 1 }, (_, i) => `https://s${i}.example/`).join("\n")), /limit per import/);
  assert.throws(() => parseAlertFile("x".repeat(5 * 1024 * 1024 + 1)), /5 MB/);
});

test("a damaged alert is set aside and removable; a failed commit queues nothing", async () => {
  const store = createMemoryStore();
  const ws = fresh(store);
  await ws.queueAlerts([item(LURE)]);
  await store.put("alerts", { id: "broken", status: "closed", disposition: null });
  assert.equal((await ws.listAlerts()).length, 1);
  assert.deepEqual(await ws.damaged(), [{ store: "alerts", id: "broken" }]);
  assert.equal(await ws.removeDamaged(), 1);

  const failing = createWorkspace({ ...createMemoryStore(), commit: async () => { throw new Error("QuotaExceededError"); } }, { now, newId });
  await assert.rejects(failing.queueAlerts([item(LURE)]), /QuotaExceededError/);
  assert.equal((await failing.listAlerts()).length, 0);
});

test("the demo queue shows each state and is removed with the other demo records", async () => {
  const ws = fresh();
  const own = (await ws.queueAlerts([item("https://my-own.example/")])).created[0];
  const demo = await loadDemoWorkspace(ws, analyze);
  assert.equal(demo.alerts, 8);
  const m = await ws.alertMetrics();
  assert.equal(m.byStatus.escalated, 1);
  assert.equal(m.byStatus.closed, 1);
  await ws.removeDemoData();
  assert.deepEqual((await ws.listAlerts()).map((a) => a.id), [own.id]);
  assert.ok(await ws.getAnalysis(own.analysisId), "the analyst's own alert keeps its analysis");
});
