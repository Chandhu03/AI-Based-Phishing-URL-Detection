import assert from "node:assert/strict";
import test from "node:test";
import { analyzeUrl } from "../engine/analyze.js";
import { PSL_COMMIT, RULES } from "../engine/generated/psl-rules.js";
import { PublicSuffixList } from "../engine/psl.js";
import { exportBackup, importBackup, investigationToMarkdown, parseBackup } from "./io.js";
import { PLAYBOOKS } from "./playbooks.js";
import { createMemoryStore } from "./stores.js";
import { createWorkspace, isIntact, WorkspaceError } from "./workspace.js";

const psl = new PublicSuffixList(RULES, PSL_COMMIT);
let clock = Date.parse("2026-11-10T08:00:00Z");
const now = () => new Date((clock += 60_000));
let n = 0;
const newId = () => `pb-${++n}`;
const fresh = (store = createMemoryStore()) => createWorkspace(store, { now, newId });
const reanalyze = (u, at) => analyzeUrl(u, { psl, now: () => new Date(at) });

test("every playbook is well formed: unique ids, short single-line steps", () => {
  assert.equal(new Set(PLAYBOOKS.map((p) => p.id)).size, PLAYBOOKS.length);
  for (const p of PLAYBOOKS) {
    assert.match(p.id, /^[a-z-]+$/);
    assert.ok(p.steps.length >= 5);
    assert.equal(new Set(p.steps).size, p.steps.length, `${p.id} has duplicate steps`);
    for (const step of p.steps) assert.ok(step.length <= 200 && !/[\r\n]/.test(step), step);
  }
});

test("applying a playbook adds its steps once, with history", async () => {
  const ws = fresh();
  const inv = await ws.createInvestigation({ title: "Lure" });
  const steps = PLAYBOOKS[0].steps.length;
  let got = await ws.applyPlaybook(inv.id, "credential-phishing");
  assert.equal(got.tasks.length, steps);
  assert.ok(got.tasks.every((t) => t.done === false && t.playbook === "credential-phishing"));
  got = await ws.applyPlaybook(inv.id, "credential-phishing");
  assert.equal(got.tasks.length, steps, "applying again adds nothing");
  got = await ws.applyPlaybook(inv.id, "malware-delivery");
  assert.ok(got.tasks.length < steps + PLAYBOOKS[1].steps.length, "steps the case already has are not repeated");
  assert.deepEqual(got.history.filter((h) => h.action === "playbook").map((h) => h.detail), [
    `Credential phishing: ${steps} steps added`, "Credential phishing: 0 steps added", `Malware attachment or download: ${got.tasks.length - steps} steps added`,
  ]);
  await assert.rejects(ws.applyPlaybook(inv.id, "nope"), WorkspaceError);
});

test("steps are ticked, reopened, added and removed with an auditable history", async () => {
  const ws = fresh();
  const inv = await ws.createInvestigation({ title: "Case" });
  let got = await ws.addTask(inv.id, "  Call the bank  ");
  const [task] = got.tasks;
  assert.equal(task.text, "Call the bank");
  got = await ws.setTaskDone(inv.id, task.id, true);
  assert.equal(got.tasks[0].done, true);
  assert.ok(got.tasks[0].doneAt);
  await ws.setTaskDone(inv.id, task.id, true); // no change, no history
  got = await ws.setTaskDone(inv.id, task.id, false);
  assert.equal(got.tasks[0].doneAt, null);
  got = await ws.deleteTask(inv.id, task.id);
  assert.deepEqual(got.tasks, []);
  assert.deepEqual(got.history.filter((h) => h.action === "task").map((h) => h.detail), [
    "Added: Call the bank", "Done: Call the bank", "Reopened: Call the bank", "Removed: Call the bank",
  ]);
  await assert.rejects(ws.addTask(inv.id, "   "), /empty/);
  await assert.rejects(ws.addTask(inv.id, "x".repeat(201)), /at most 200/);
  await assert.rejects(ws.setTaskDone(inv.id, "missing", true), /not found/);
  for (let i = 0; i < 100; i++) await ws.addTask(inv.id, `step ${i}`);
  await assert.rejects(ws.addTask(inv.id, "one too many"), /at most 100/);
  await assert.rejects(ws.applyPlaybook(inv.id, "credential-phishing"), /at most 100/);
  assert.equal((await ws.getInvestigation(inv.id)).tasks.length, 100, "a rejected playbook adds nothing");
});

test("an investigation saved before checklists existed is intact and can take one", async () => {
  const store = createMemoryStore();
  const ws = fresh(store);
  const at = "2026-10-01T10:00:00.000Z";
  const old = { id: "old-1", title: "Old case", summary: "", status: "open", priority: "high", tags: [], notes: [], analysisIds: [], indicatorIds: [], createdAt: at, updatedAt: at, history: [] };
  await store.put("investigations", old);
  assert.ok(isIntact("investigations", old));
  const got = await ws.applyPlaybook("old-1", "payment-fraud");
  assert.equal(got.tasks.length, PLAYBOOKS.find((p) => p.id === "payment-fraud").steps.length);
});

test("escalating an alert can start the case with a playbook", async () => {
  const ws = fresh();
  const report = analyzeUrl("http://paypal.com.secure-account.tk/login", { psl, now });
  const { created: [al] } = await ws.queueAlerts([{ report, source: "user-report" }]);
  const { investigation } = await ws.escalateAlert(al.id, { playbookId: "credential-phishing" });
  assert.equal(investigation.tasks.length, PLAYBOOKS[0].steps.length);
  assert.deepEqual(investigation.history.map((h) => h.action), ["created", "linked", "playbook", "alert"]);
  const other = (await ws.queueAlerts([{ report: analyzeUrl("https://paypa1.com/signin", { psl, now }) }])).created[0];
  await assert.rejects(ws.escalateAlert(other.id, { playbookId: "nope" }), /unknown playbook/);
  assert.equal((await ws.getAlert(other.id)).status, "new", "a failed escalation changes nothing");
  assert.equal((await ws.listInvestigations()).length, 1);
});

test("checklists survive backups; tampered steps are dropped, older backups restore", async () => {
  const source = fresh();
  const inv = await source.createInvestigation({ title: "Case" });
  await source.applyPlaybook(inv.id, "brand-impersonation");
  const [first] = (await source.getInvestigation(inv.id)).tasks;
  await source.setTaskDone(inv.id, first.id, true);
  const backup = await exportBackup(source.store);
  backup.records.investigations[0].tasks.push(
    { id: "t-long", text: "x".repeat(201), done: false },
    { id: "t-bad", text: "ok", done: "yes" },
    { id: first.id, text: "duplicate id", done: false },
  );
  const ws = fresh();
  await importBackup(ws.store, parseBackup(JSON.stringify(backup), reanalyze));
  const got = await ws.getInvestigation(inv.id);
  assert.equal(got.tasks.length, PLAYBOOKS.find((p) => p.id === "brand-impersonation").steps.length);
  assert.equal(got.tasks[0].done, true);
  assert.equal(got.tasks[0].doneAt, first.doneAt ?? got.tasks[0].doneAt);
  assert.ok(got.history.some((h) => h.action === "playbook"), "playbook history is restored");

  delete backup.records.investigations[0].tasks;
  const ws2 = fresh();
  await importBackup(ws2.store, parseBackup(JSON.stringify(backup), reanalyze));
  assert.deepEqual((await ws2.getInvestigation(inv.id)).tasks, []);
});

test("the case report includes the checklist with progress", async () => {
  const ws = fresh();
  const inv = await ws.createInvestigation({ title: "Case" });
  await ws.addTask(inv.id, "Block evil.example at the proxy");
  const [t] = (await ws.addTask(inv.id, "Notify reporters")).tasks;
  await ws.setTaskDone(inv.id, t.id, true);
  const out = investigationToMarkdown(await ws.getInvestigation(inv.id), [], []);
  assert.match(out, /## Response checklist\n1 of 2 steps done\.\n\n- \[x\] Block evil\[\.\]example at the proxy \(done /);
  assert.match(out, /- \[ \] Notify reporters$/m);
});
