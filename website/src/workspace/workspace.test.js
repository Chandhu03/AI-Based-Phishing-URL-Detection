import assert from "node:assert/strict";
import test from "node:test";
import { analyzeUrl } from "../engine/analyze.js";
import { PSL_COMMIT, RULES } from "../engine/generated/psl-rules.js";
import { PublicSuffixList } from "../engine/psl.js";
import { loadDemoWorkspace } from "./demo.js";
import {
  analysisToMarkdown, csvCell, exportBackup, ImportError, importBackup, indicatorsToCsv, indicatorsToStix,
  defangText, investigationToMarkdown, MAX_IMPORT_BYTES, parseBackup, parseBackupInChunks, parseIndicatorFile,
} from "./io.js";
import { createMemoryStore } from "./stores.js";
import { createWorkspace, indicatorsFromAnalysis, normalizeIndicator, normalizeTags, WorkspaceError } from "./workspace.js";

const psl = new PublicSuffixList(RULES, PSL_COMMIT);
let clock = Date.parse("2026-03-01T12:00:00Z");
const now = () => new Date((clock += 1000));
let n = 0;
const newId = () => `id-${++n}`;
const analyze = (u) => analyzeUrl(u, { psl, now });
const fresh = () => createWorkspace(createMemoryStore(), { now, newId });

test("saving an analysis records verdict, host and an activity event", async () => {
  const ws = fresh();
  const a = await ws.saveAnalysis(analyze("http://paypal.com.secure-account.tk/login"));
  assert.equal(a.verdict, "high-risk");
  assert.equal(a.registrableDomain, "secure-account.tk");
  assert.equal((await ws.activity()).length, 1);
  await assert.rejects(ws.saveAnalysis({ ok: false }), WorkspaceError);
});

test("investigation lifecycle keeps an auditable history", async () => {
  const ws = fresh();
  const inv = await ws.createInvestigation({ title: "  Lure  ", priority: "high", tags: "Phish, phish ,x" });
  assert.equal(inv.title, "Lure");
  assert.deepEqual(inv.tags, ["phish", "x"]);
  await ws.updateInvestigation(inv.id, { status: "investigating", priority: "critical" });
  await ws.addNote(inv.id, "first note");
  const a = await ws.saveAnalysis(analyze("https://paypa1.com/"));
  await ws.linkAnalysis(inv.id, a.id);
  await ws.linkAnalysis(inv.id, a.id);
  const got = await ws.getInvestigation(inv.id);
  assert.deepEqual(got.history.map((h) => h.action), ["created", "status", "priority", "note", "linked"]);
  assert.deepEqual(got.analysisIds, [a.id]);
  await assert.rejects(ws.updateInvestigation(inv.id, { status: "nope" }), WorkspaceError);
  await assert.rejects(ws.createInvestigation({ title: "   " }), WorkspaceError);
  await assert.rejects(ws.addNote(inv.id, " "), WorkspaceError);
});

test("summary and tag edits are recorded; no-op edits are not", async () => {
  const ws = fresh();
  const inv = await ws.createInvestigation({ title: "Edits", tags: ["a"] });
  await ws.updateInvestigation(inv.id, { summary: "New summary", tags: "a, b" });
  await ws.updateInvestigation(inv.id, { summary: "New summary", tags: ["b", "a"] });
  const got = await ws.getInvestigation(inv.id);
  assert.deepEqual(got.history.map((h) => h.action), ["created", "summary", "tags"]);
});

test("linking an analysis brings its recorded indicators into the case", async () => {
  const ws = fresh();
  const a = await ws.saveAnalysis(analyze("http://paypal.com.secure-account.tk/login"));
  for (const c of indicatorsFromAnalysis(a.report)) await ws.upsertIndicator({ ...c, analysisId: a.id });
  const inv = await ws.createInvestigation({ title: "Case" });
  await ws.linkAnalysis(inv.id, a.id);
  const got = await ws.getInvestigation(inv.id);
  assert.equal(got.indicatorIds.length, indicatorsFromAnalysis(a.report).length);
  for (const id of got.indicatorIds) assert.ok((await ws.getIndicator(id)).investigationIds.includes(inv.id));
  await ws.unlinkAnalysis(inv.id, a.id);
  assert.equal((await ws.getInvestigation(inv.id)).history.at(-1).action, "unlinked");
});

test("deleting an analysis unlinks it from investigations", async () => {
  const ws = fresh();
  const inv = await ws.createInvestigation({ title: "t" });
  const a = await ws.saveAnalysis(analyze("https://example.com/"));
  await ws.linkAnalysis(inv.id, a.id);
  await ws.deleteAnalysis(a.id);
  assert.deepEqual((await ws.getInvestigation(inv.id)).analysisIds, []);
});

test("indicators are de-duplicated, validated and linked both ways", async () => {
  const ws = fresh();
  const inv = await ws.createInvestigation({ title: "t" });
  await ws.upsertIndicator({ type: "domain", value: "Evil.Example", investigationId: inv.id, tags: ["a"] });
  const again = await ws.upsertIndicator({ type: "domain", value: "evil.example", confidence: "high", tags: ["b"] });
  assert.equal(again.id, "domain:evil.example");
  assert.equal(again.sightings, 2);
  assert.equal(again.confidence, "high");
  assert.deepEqual(again.tags, ["a", "b"]);
  assert.deepEqual((await ws.getInvestigation(inv.id)).indicatorIds, ["domain:evil.example"]);
  await assert.rejects(ws.upsertIndicator({ type: "domain", value: "not a domain" }), WorkspaceError);
  await assert.rejects(ws.upsertIndicator({ type: "file", value: "x" }), WorkspaceError);
  await ws.upsertIndicator({ type: "hostname", value: "login.evil.example" });
  assert.deepEqual((await ws.relatedIndicators("domain:evil.example")).map((i) => i.id), ["hostname:login.evil.example"]);
});

test("indicator normalisation", () => {
  assert.equal(normalizeIndicator("ipv4", "256.1.1.1"), null);
  assert.equal(normalizeIndicator("ipv4", "10.0.0.1"), "10.0.0.1");
  assert.equal(normalizeIndicator("url", "javascript:alert(1)"), null);
  assert.deepEqual(normalizeTags(Array(30).fill(0).map((_, i) => `t${i}`)).length, 20);
});

test("indicators derived from an analysis cover url, host and domain", () => {
  const r = analyze("https://login.evil.example.co.uk/x");
  assert.deepEqual(indicatorsFromAnalysis(r).map((i) => `${i.type}:${i.value}`),
    ["url:https://login.evil.example.co.uk/x", "hostname:login.evil.example.co.uk", "domain:example.co.uk"]);
});

test("overview counts come only from stored records", async () => {
  const ws = fresh();
  let o = await ws.overview();
  assert.equal(o.totals.analyses, 0);
  assert.equal(o.hasDemo, false);
  await loadDemoWorkspace(ws, analyze);
  o = await ws.overview();
  assert.ok(o.totals.analyses >= 7);
  assert.equal(o.hasDemo, true);
  assert.equal(Object.values(o.byVerdict).reduce((x, y) => x + y, 0), o.recentAnalyses);
  await ws.removeDemoData();
  o = await ws.overview();
  assert.deepEqual(o.totals, { analyses: 0, investigations: 0, indicators: 0 });
});

const reanalyze = (url, at) => analyzeUrl(url, { psl, now: () => new Date(at) });

test("backup round-trip adds new records and never overwrites existing ones", async () => {
  const ws = fresh();
  await loadDemoWorkspace(ws, analyze);
  const backup = await exportBackup(ws.store);
  const target = fresh();
  const counts = await importBackup(target.store, parseBackup(JSON.stringify(backup), reanalyze));
  assert.ok(counts.added > 10);
  assert.equal(counts.rejected, 0);
  const again = await importBackup(target.store, parseBackup(JSON.stringify(backup), reanalyze));
  assert.equal(again.added, 0);
  assert.throws(() => parseBackup("{", reanalyze), ImportError);
  assert.throws(() => parseBackup(JSON.stringify({ format: "other" }), reanalyze), ImportError);
  assert.throws(() => parseBackup(JSON.stringify({ format: "securemind.workspace/1", records: null }), reanalyze), ImportError);
});

test("a tampered backup cannot forge verdicts or inject malformed records", async () => {
  const ws = fresh();
  await loadDemoWorkspace(ws, analyze);
  const backup = await exportBackup(ws.store);
  const t = structuredClone(backup);
  const a = t.records.analyses[0];
  a.report = { ok: true, url: a.input, verdict: { level: "safe", label: "Safe — verified clean", reasons: [], limits: [] }, indicators: [] };
  a.verdict = "safe";
  t.records.analyses.push({ id: "weird", createdAt: "2026-01-01T00:00:00Z", url: { not: "a string" }, verdict: "x", report: { ok: true, indicators: [] } });
  t.records.activity.push({ id: "bad-date", at: "x", kind: "k" });
  t.records.indicators.push({ id: "zzz", type: "domain", value: "evil.example", confidence: "bogus", firstSeen: "2026-01-01T00:00:00Z", lastSeen: "2026-01-01T00:00:00Z" });
  t.records.indicators.push({ id: "x", type: "domain", value: "<script>", confidence: "high", firstSeen: "", lastSeen: "" });
  t.records.investigations.push({ ...backup.records.investigations[0], id: "bad", status: "pwned" });
  t.records.investigations.push({ ...backup.records.investigations[0], id: "obj", title: { x: 1 } });
  const parsed = parseBackup(JSON.stringify(t), reanalyze);
  const rebuilt = parsed.records.analyses.find((r) => r.id === a.id);
  assert.notEqual(rebuilt.report.verdict.label, "Safe — verified clean");
  assert.equal(rebuilt.verdict, rebuilt.report.verdict.level);
  for (const [store, id] of [["analyses", "weird"], ["indicators", "zzz"], ["indicators", "x"], ["investigations", "bad"], ["investigations", "obj"]]) {
    assert.ok(!parsed.records[store].some((r) => r.id === id), `${store}/${id} should be rejected`);
  }
  assert.equal(parsed.rejected, 5);
  assert.equal(parsed.records.activity.length, 0, "activity entries are never imported");
  // Existing records are kept even if the import claims to be newer.
  const target = fresh();
  await target.store.put("indicators", { ...backup.records.indicators[0], confidence: "low" });
  const newer = structuredClone(backup);
  newer.records.indicators[0].lastSeen = "2099-01-01T00:00:00Z";
  newer.records.indicators[0].confidence = "high";
  await importBackup(target.store, parseBackup(JSON.stringify(newer), reanalyze));
  assert.equal((await target.store.get("indicators", backup.records.indicators[0].id)).confidence, "low");
});

// Regression: a backup indicator without tags/sources/arrays used to be stored
// as-is, and CSV export then failed with "Cannot read properties of undefined
// (reading 'join')". Imports are now rebuilt, so every export must work.
test("sparse backup records import into a complete shape that every export accepts", async () => {
  const sparse = { id: "domain:evil.example", type: "domain", value: "evil.example", firstSeen: "2026-11-13T00:00:00Z" };
  const inv = { id: "case-1", title: "Sparse", status: "open", priority: "medium", createdAt: "2026-11-13T00:00:00Z" };
  const text = JSON.stringify({ format: "securemind.workspace/1", records: { indicators: [sparse], investigations: [inv] } });
  const ws = fresh();
  assert.deepEqual(await importBackup(ws.store, parseBackup(text, reanalyze)), { added: 2, skipped: 0, repaired: 0, rejected: 0 });
  const inds = await ws.listIndicators();
  assert.match(indicatorsToCsv(inds), /^domain,evil\.example,medium,,/m);
  assert.equal(indicatorsToStix(inds).objects.filter((o) => o.type === "indicator").length, 1);
  assert.match(investigationToMarkdown(await ws.getInvestigation("case-1"), [], inds), /Tags: none/);
});

test("indicator imports are capped", () => {
  const many = Array.from({ length: 5001 }, (_, i) => `198.51.${Math.floor(i / 250)}.${i % 250}`).join("\n");
  assert.throws(() => parseIndicatorFile(many), ImportError);
});

test("CSV export neutralises formulas and quotes fields", () => {
  assert.equal(csvCell("=HYPERLINK(\"x\")"), "\"'=HYPERLINK(\"\"x\"\")\"");
  assert.equal(csvCell("-1"), "'-1");
  assert.equal(csvCell("a,b"), "\"a,b\"");
  const csv = indicatorsToCsv([{ type: "domain", value: "evil.example", confidence: "high", tags: ["x"], firstSeen: "t", lastSeen: "t", sightings: 1, sources: ["analyst"] }], { defanged: true });
  assert.match(csv, /evil\[\.\]example/);
});

test("STIX export round-trips through the importer", () => {
  const inds = [
    { type: "domain", value: "evil.example", stixId: "indicator--1", confidence: "high", tags: ["t"], firstSeen: "2026-01-01T00:00:00Z", note: "" },
    { type: "url", value: "https://evil.example/a'b", stixId: "indicator--2", confidence: "low", tags: [], firstSeen: "2026-01-01T00:00:00Z", note: "" },
    { type: "ipv4", value: "192.0.2.1", stixId: "indicator--3", confidence: "medium", tags: [], firstSeen: "2026-01-01T00:00:00Z", note: "" },
  ];
  const bundle = indicatorsToStix(inds);
  assert.equal(bundle.objects[1].pattern, "[url:value = 'https://evil.example/a\\'b']");
  const back = parseIndicatorFile(JSON.stringify(bundle));
  assert.deepEqual(back.items.map((i) => `${i.type}:${i.value}:${i.confidence}`),
    ["domain:evil.example:high", "url:https://evil.example/a'b:low", "ipv4:192.0.2.1:medium"]);
});

test("plain-text and CSV indicator import accept defanged values and reject junk", () => {
  const t = parseIndicatorFile("hxxps://evil[.]example/x\n198.51.100.7\nnot an indicator\nexample[.]net");
  assert.deepEqual(t.items.map((i) => i.type), ["url", "ipv4", "domain"]);
  assert.equal(t.rejected, 1);
  const c = parseIndicatorFile("type,value,confidence,tags\ndomain,evil[.]example,high,a;b\nfile,x,high,\n");
  assert.equal(c.format, "CSV");
  assert.deepEqual(c.items[0], { type: "domain", value: "evil.example", confidence: "high", tags: ["a", "b"] });
  assert.equal(c.rejected, 1);
});

test("Markdown reports defang URLs and escape analyst text", async () => {
  const r = analyze("http://paypal.com.secure-account.tk/login");
  const text = analysisToMarkdown(r);
  assert.match(text, /hxxp:\/\/paypal\[\.\]com/);
  assert.ok(!text.includes("http://paypal.com"));
  const ws = fresh();
  const inv = await ws.createInvestigation({ title: "<b>x</b>" });
  await ws.addNote(inv.id, "[click](javascript:alert(1))");
  const out = investigationToMarkdown(await ws.getInvestigation(inv.id), [], []);
  assert.ok(out.includes("\\<b\\>x\\</b\\>"));
  assert.ok(out.includes("\\[click\\](javascript:alert(1))"));
});

test("Markdown export cannot be broken out of by encoded newlines and defangs hosts in prose", () => {
  const r = analyze("https://example.com/%0A%0A%23%20Verdict%3A%20Safe%0A-%20https%3A%2F%2Fevil.example%2Fpay%0A%0Ainvoice.exe");
  const text = analysisToMarkdown(r);
  assert.ok(!/^# Verdict: Safe/m.test(text));
  assert.ok(!text.includes("https://evil.example"));
  const p = analyze("http://paypal.com.secure-account.tk/login?next=https://evil-two.example/");
  const md = analysisToMarkdown(p);
  assert.ok(!/\bsecure-account\.tk\b/.test(md), "registrable domain must be defanged everywhere");
  assert.ok(!/evil-two\.example/.test(md));
});

// Regression: restore used to re-analyse the cleaned-up URL, so login text,
// disguised IPs, rewritten hosts and a missing scheme were lost and verdicts
// changed. Restore now re-analyses the masked input as written.
test("backup round-trip preserves verdicts and evidence for tricky link shapes", async () => {
  const links = [
    "https://admin:hunter2@example.com/",
    "https://accounts.google.com@example.org/",
    "http://3232235777/bank/login",
    "http://0x7f.1/x",
    "example.com/login",
    "http://ｅｘａｍｐｌｅ.com/",
    "hxxp://paypal[.]com[.]secure-account[.]tk/login",
  ];
  const ws = fresh();
  for (const l of links) await ws.saveAnalysis(analyze(l));
  const backup = await exportBackup(ws.store);
  const text = JSON.stringify(backup);
  assert.ok(!/hunter2|admin|accounts\.google/.test(text), "login text must never be exported");
  assert.ok(backup.records.analyses.every((a) => a.report === undefined), "reports are not exported");
  const parsed = parseBackup(text, reanalyze);
  for (const before of backup.records.analyses) {
    const original = (await ws.getAnalysis(before.id)).report;
    const after = parsed.records.analyses.find((a) => a.id === before.id).report;
    const ids = (r) => r.indicators.map((i) => i.id).sort();
    assert.equal(after.verdict.level, original.verdict.level, before.input);
    assert.deepEqual(ids(after), ids(original), before.input);
  }
});

test("a backup of 1,500 analyses stays far below the import size limit", async () => {
  const ws = fresh();
  const r = analyze("http://paypal.com.secure-account.tk/login");
  for (let i = 0; i < 1500; i++) await ws.saveAnalysis(r);
  const size = JSON.stringify(await exportBackup(ws.store)).length;
  assert.ok(size < MAX_IMPORT_BYTES / 2, `backup is ${size} bytes`);
});

test("backup ids must be strings and history actions must be known", () => {
  const inv = { title: "T", status: "open", priority: "medium", createdAt: "2026-11-13T00:00:00Z",
    history: [{ at: "2026-11-13T00:00:00Z", action: "note\n# Forged\n![](http://198.51.100.7/p)", detail: "x" }, { at: "2026-11-13T00:00:00Z", action: "created", detail: "ok" }] };
  const text = JSON.stringify({ format: "securemind.workspace/1", records: {
    investigations: [{ ...inv, id: null }, { ...inv, id: 123 }, { ...inv, id: "ok-1" }],
  } });
  const parsed = parseBackup(text, reanalyze);
  assert.deepEqual(parsed.records.investigations.map((r) => r.id), ["ok-1"]);
  assert.equal(parsed.rejected, 2);
  assert.deepEqual(parsed.records.investigations[0].history.map((h) => h.action), ["created"]);
});

test("indicator values are validated like the analyser: no truncation, no invisible characters, real IPv6", () => {
  assert.equal(normalizeIndicator("url", `https://example.com/${"a".repeat(2100)}`), null);
  assert.equal(normalizeIndicator("url", "https://exa‮mple.com/"), null);
  assert.equal(normalizeIndicator("url", "https://ex​ample.com/"), null);
  assert.equal(normalizeIndicator("url", "https://аpple.com/x"), "https://xn--pple-43d.com/x");
  assert.equal(normalizeIndicator("ipv6", "::::"), null);
  assert.equal(normalizeIndicator("ipv6", "deadbeef:"), null);
  assert.equal(normalizeIndicator("ipv6", "2001:DB8:0:0::1"), "2001:db8::1");
});

test("STIX objects with non-string patterns or labels are skipped, not fatal", () => {
  const bundle = { type: "bundle", id: "bundle--x", objects: [
    { type: "indicator", pattern: { evil: true } },
    { type: "indicator", pattern: "[domain-name:value = 'evil.example']", labels: { x: 1 } },
  ] };
  const r = parseIndicatorFile(JSON.stringify(bundle));
  assert.equal(r.rejected, 1);
  assert.deepEqual(r.items, [{ type: "domain", value: "evil.example", confidence: "medium", tags: [] }]);
});

test("CSV export guards each joined tag and source against formulas", () => {
  const csv = indicatorsToCsv([{ type: "domain", value: "a.example", confidence: "low", tags: ["x", "=HYPERLINK(1)"], firstSeen: "t", lastSeen: "t", sightings: 1, sources: ["@SUM(1)"] }]);
  assert.match(csv, /x;'=HYPERLINK\(1\)/);
  assert.match(csv, /,'@SUM\(1\)\r\n$/);
});

test("prose defanging covers hosts and IPv4, leaves ordinary text, and runs in linear time", () => {
  assert.equal(defangText("see evil.example and 198.51.100.7, e.g. version 2.0"), "see evil[.]example and 198[.]51[.]100[.]7, e.g. version 2.0");
  assert.equal(defangText("пример.рф"), "пример[.]рф");
  const t = performance.now();
  defangText(`${"a.".repeat(500000)}1`);
  assert.ok(performance.now() - t < 500, "defangText must stay linear");
});

test("removing demo records keeps the analyst's own data and its links intact", async () => {
  const ws = fresh();
  await loadDemoWorkspace(ws, analyze);
  const demoInd = (await ws.listIndicators()).find((i) => i.demo);
  const mine = await ws.createInvestigation({ title: "Mine" });
  await ws.upsertIndicator({ type: demoInd.type, value: demoInd.value, investigationId: mine.id }); // real sighting of a demo value
  const demoCase = (await ws.listInvestigations()).find((i) => i.demo);
  const myInd = await ws.upsertIndicator({ type: "domain", value: "mine.example", investigationId: demoCase.id });
  await ws.removeDemoData();
  assert.ok(await ws.getIndicator(demoInd.id), "indicator also recorded by the analyst is kept");
  assert.deepEqual((await ws.getInvestigation(mine.id)).indicatorIds, [demoInd.id]);
  assert.deepEqual((await ws.getIndicator(myInd.id)).investigationIds, [], "links to deleted demo cases are removed");
  assert.equal((await ws.listAnalyses()).filter((a) => a.demo).length, 0);
});

test("a rejected update writes nothing, and concurrent edits are not lost", async () => {
  const ws = fresh();
  const inv = await ws.createInvestigation({ title: "Race" });
  const before = (await ws.activity(50)).length;
  await assert.rejects(ws.updateInvestigation(inv.id, { status: "closed", priority: "bogus" }), WorkspaceError);
  assert.equal((await ws.getInvestigation(inv.id)).status, "open");
  assert.equal((await ws.activity(50)).length, before);
  await Promise.all([ws.updateInvestigation(inv.id, { status: "investigating" }), ws.updateInvestigation(inv.id, { priority: "high" }), ws.addNote(inv.id, "n")]);
  const got = await ws.getInvestigation(inv.id);
  assert.equal(got.status, "investigating");
  assert.equal(got.priority, "high");
  assert.equal(got.notes.length, 1);
});

// ------------------------------------------------------------ data integrity
test("the memory store commits all operations or none", async () => {
  const store = createMemoryStore();
  await store.put("analyses", { id: "keep" });
  await assert.rejects(store.commit([
    { type: "put", store: "analyses", record: { id: "new" } },
    { type: "delete", store: "analyses", id: "keep" },
    { type: "explode", store: "analyses", id: "x" },
  ]));
  assert.deepEqual((await store.list("analyses")).map((r) => r.id), ["keep"]);
});

/** A store whose transactions always fail, as when IndexedDB is out of quota. */
function failingStore(base = createMemoryStore()) {
  return { ...base, commit: async () => { throw new Error("QuotaExceededError"); }, put: async () => { throw new Error("put must not be used"); } };
}

test("a restore that fails part-way leaves the workspace exactly as it was", async () => {
  const source = fresh();
  await loadDemoWorkspace(source, analyze);
  const parsed = parseBackup(JSON.stringify(await exportBackup(source.store)), reanalyze);
  const base = createMemoryStore();
  const ws = createWorkspace(base, { now, newId });
  await ws.createInvestigation({ title: "Mine" });
  const before = JSON.stringify(await exportBackup(base, new Date(0)));
  await assert.rejects(importBackup(failingStore(base), parsed), /QuotaExceededError/);
  assert.equal(JSON.stringify(await exportBackup(base, new Date(0))), before);
});

test("restore drops links to records that do not exist and keeps the rest", async () => {
  const source = fresh();
  const a = await source.saveAnalysis(analyze("http://paypal.com.secure-account.tk/login"));
  const inv = await source.createInvestigation({ title: "Case" });
  await source.upsertIndicator({ type: "domain", value: "secure-account.tk", analysisId: a.id, investigationId: inv.id });
  await source.linkAnalysis(inv.id, a.id);
  const backup = await exportBackup(source.store);
  backup.records.investigations[0].analysisIds.push("missing-analysis");
  backup.records.investigations[0].indicatorIds.push("domain:missing.example");
  backup.records.indicators[0].investigationIds.push("missing-case");
  const ws = fresh();
  await importBackup(ws.store, parseBackup(JSON.stringify(backup), reanalyze));
  const got = await ws.getInvestigation(inv.id);
  assert.deepEqual(got.analysisIds, [a.id]);
  assert.deepEqual(got.indicatorIds, ["domain:secure-account.tk"]);
  assert.deepEqual((await ws.getIndicator("domain:secure-account.tk")).investigationIds, [inv.id]);
});

test("damaged records are set aside, reported, repairable by restore and removable", async () => {
  const source = fresh();
  const inv = await source.createInvestigation({ title: "Good copy" });
  const backup = await exportBackup(source.store);
  const ws = fresh();
  await ws.saveAnalysis(analyze("https://example.com/"));
  await ws.store.put("investigations", { id: inv.id, title: 42, notes: "x" });
  await ws.store.put("analyses", { id: "broken", url: "https://x.example/", report: null });
  await ws.store.put("indicators", { id: "domain:a.example", type: "domain", value: "a.example" });
  // Lists, overview and activity keep working and simply leave the damaged records out.
  assert.equal((await ws.listInvestigations()).length, 0);
  assert.equal((await ws.listAnalyses()).length, 1);
  assert.equal((await ws.overview()).totals.analyses, 1);
  await assert.rejects(ws.getInvestigation(inv.id), /damaged/);
  assert.deepEqual((await ws.damaged()).map((d) => `${d.store}:${d.id}`).sort(),
    ["analyses:broken", `investigations:${inv.id}`, "indicators:domain:a.example"].sort());
  // A restore replaces a damaged record with the backup's valid copy.
  const counts = await importBackup(ws.store, parseBackup(JSON.stringify(backup), reanalyze), new Date(0));
  assert.equal(counts.repaired, 1);
  assert.equal((await ws.getInvestigation(inv.id)).title, "Good copy");
  assert.equal(await ws.removeDamaged(), 2);
  assert.deepEqual(await ws.damaged(), []);
  assert.equal((await ws.activity(1))[0].kind, "workspace.repaired");
});

test("multi-record changes are atomic: one invalid indicator records nothing", async () => {
  const ws = fresh();
  await assert.rejects(ws.upsertIndicators([
    { type: "domain", value: "first.example" },
    { type: "ipv4", value: "999.1.1.1" },
  ]), WorkspaceError);
  assert.equal((await ws.listIndicators()).length, 0);
  assert.equal((await ws.activity()).length, 0);
  // A link into a missing investigation also writes nothing.
  await assert.rejects(ws.upsertIndicator({ type: "domain", value: "x.example", investigationId: "nope" }), WorkspaceError);
  assert.equal((await ws.listIndicators()).length, 0);
  // Saving a batch with an unsuccessful report saves none of it.
  await assert.rejects(ws.saveAnalyses([analyze("https://example.com/"), { ok: false }]), WorkspaceError);
  assert.equal((await ws.listAnalyses()).length, 0);
});

test("a failed transaction during a change leaves every record untouched", async () => {
  const base = createMemoryStore();
  const ws = createWorkspace(base, { now, newId });
  const inv = await ws.createInvestigation({ title: "Case" });
  const a = await ws.saveAnalysis(analyze("https://example.com/"));
  await ws.linkAnalysis(inv.id, a.id);
  const broken = createWorkspace(failingStore(base), { now, newId });
  await assert.rejects(broken.deleteAnalysis(a.id));
  assert.deepEqual((await ws.getInvestigation(inv.id)).analysisIds, [a.id]);
  assert.ok(await ws.getAnalysis(a.id));
});

test("analysis history pages, filters, searches by host and deletes in bulk", async () => {
  const ws = fresh();
  const urls = Array.from({ length: 30 }, (_, i) => `https://site${i}.example/`);
  const saved = await ws.saveAnalyses(urls.map((u) => analyze(u)));
  await ws.saveAnalysis(analyze("http://paypal.com.secure-account.tk/login"));
  const page1 = await ws.listAnalyses({ limit: 25 });
  assert.equal(page1.total, 31);
  assert.equal(page1.items.length, 25);
  const page2 = await ws.listAnalyses({ limit: 25, offset: 25 });
  assert.equal(page2.items.length, 6);
  // Past the end: the last page, not an empty one.
  assert.equal((await ws.listAnalyses({ limit: 25, offset: 500 })).offset, 25);
  assert.equal((await ws.listAnalyses({ verdict: "high-risk" })).length, 1);
  assert.equal((await ws.listAnalyses({ query: "SITE1" })).length, 11);
  const inv = await ws.createInvestigation({ title: "Case" });
  await ws.linkAnalysis(inv.id, saved[0].id);
  assert.equal(await ws.deleteAnalyses([saved[0].id, saved[1].id, saved[1].id]), 2);
  assert.equal((await ws.listAnalyses()).length, 29);
  assert.deepEqual((await ws.getInvestigation(inv.id)).analysisIds, []);
});

// ------------------------------------------------------------ interoperability
test("STIX round trip keeps host names apart from domains, the STIX id and the note", async () => {
  const uuid = () => crypto.randomUUID();
  const ws = createWorkspace(createMemoryStore(), { now, newId: uuid });
  await ws.upsertIndicator({ type: "hostname", value: "login.evil.example", note: "Seen in a payroll lure", tags: ["lure"] });
  await ws.upsertIndicator({ type: "domain", value: "evil.example" });
  const original = await ws.listIndicators();
  const bundle = indicatorsToStix(original);
  assert.ok(bundle.objects.every((o) => o.modified >= o.created));
  assert.ok(!("labels" in bundle.objects.find((o) => o.pattern.includes("'evil.example'"))), "empty labels are omitted");
  const { items } = parseIndicatorFile(JSON.stringify(bundle));
  const target = createWorkspace(createMemoryStore(), { now, newId: uuid });
  await target.upsertIndicators(items);
  for (const o of original) {
    const back = await target.getIndicator(o.id);
    assert.equal(back.type, o.type);
    assert.equal(back.stixId, o.stixId);
    assert.equal(back.note, o.note);
    assert.deepEqual(back.tags, o.tags);
  }
});

test("indicator normalisation: canonical IPs, punycode hosts, no ambiguous forms", () => {
  assert.equal(normalizeIndicator("ipv4", "010.0.0.1"), null, "leading zeros are octal to browsers");
  assert.equal(normalizeIndicator("ipv4", "10.0.0.1"), "10.0.0.1");
  assert.equal(normalizeIndicator("ipv6", "[2001:DB8:0:0::1]"), "2001:db8::1");
  assert.equal(normalizeIndicator("domain", "Bücher.de."), "xn--bcher-kva.de");
  assert.equal(normalizeIndicator("hostname", "WWW.Example.COM."), "www.example.com");
  assert.equal(normalizeIndicator("domain", "1.2.3.44"), null, "an IP address is not a domain");
  assert.equal(normalizeIndicator("domain", "bad@bücher.de"), null);
});

test("CSV files with a byte-order mark import like any other", () => {
  const { items, format } = parseIndicatorFile("\uFEFFtype,value,confidence\r\nhostname,login.evil.example,high\r\n");
  assert.equal(format, "CSV");
  assert.deepEqual(items, [{ type: "hostname", value: "login.evil.example", confidence: "high", tags: [] }]);
});

// ------------------------------------------------------------ security review regressions
test("CSV cells with an inner ';' or tab are quoted, and formulas after spaces are neutralised", () => {
  assert.equal(csvCell("http://a.example/x;=1+1;"), '"http://a.example/x;=1+1;"');
  assert.equal(csvCell(" =1+1"), "' =1+1");
  assert.equal(csvCell("a\tb"), '"a\tb"');
  const csv = indicatorsToCsv([{ type: "url", value: "http://a.example/x;=1+1;", confidence: "high", tags: ["ok;=hyperlink(a1);x", " =2"],
    firstSeen: "t", lastSeen: "t", sightings: 1, sources: ["import: feed;=1+1;.csv"] }]);
  const row = csv.split("\r\n")[1];
  // Split as a ";"-locale spreadsheet would, honouring quotes: no field may start a formula.
  const fields = row.match(/("([^"]|"")*"|[^;,]*)/g).filter(Boolean);
  for (const f of fields) assert.ok(!/^\s*[=+@]/.test(f), `unguarded field: ${f}`);
  assert.match(row, /' =2/);
});

test("Markdown prose cannot carry a live scheme link", () => {
  assert.equal(defangText("see http://0x5d.0xb8d822/payload"), "see hxxp://0x5d.0xb8d822/payload");
  assert.equal(defangText("HTTPS://evil.example/x and ftp://files.example"), "HxxPS://evil[.]example/x and fxp://files[.]example");
});

test("restored links between cases and indicators must agree on both sides; duplicate notes are dropped", async () => {
  const at = "2026-11-13T00:00:00Z";
  const text = JSON.stringify({
    format: "securemind.workspace/1",
    records: {
      investigations: [{ id: "i1", title: "Case", status: "open", priority: "low", createdAt: at, indicatorIds: ["domain:a.example"],
        notes: [{ id: "n1", at, body: "first" }, { id: "n1", at, body: "copy" }] },
      { id: "i2", title: "Other", status: "open", priority: "low", createdAt: at, indicatorIds: [] }],
      indicators: [
        { id: "domain:a.example", type: "domain", value: "a.example", firstSeen: at, investigationIds: ["i1"] },
        { id: "domain:b.example", type: "domain", value: "b.example", firstSeen: at, investigationIds: ["i2"] },
      ],
    },
  });
  const ws = fresh();
  await importBackup(ws.store, parseBackup(text, reanalyze));
  assert.deepEqual((await ws.getInvestigation("i1")).indicatorIds, ["domain:a.example"], "agreed link kept");
  assert.deepEqual((await ws.getIndicator("domain:b.example")).investigationIds, [], "one-sided link dropped");
  assert.deepEqual((await ws.getInvestigation("i1")).notes.map((x) => x.body), ["first"]);
});

test("large restores are chunked, give the same result, and are capped", async () => {
  const at = "2026-11-13T00:00:00Z";
  const analyses = Array.from({ length: 600 }, (_, i) => ({ id: `a${i}`, createdAt: at, input: `https://site${i}.example/` }));
  const text = JSON.stringify({ format: "securemind.workspace/1", records: { analyses } });
  const progress = [];
  const chunked = await parseBackupInChunks(text, reanalyze, (done, total) => progress.push([done, total]));
  assert.deepEqual(progress, [[250, 600], [500, 600]]);
  assert.equal(JSON.stringify(chunked), JSON.stringify(parseBackup(text, reanalyze)));
  const tooMany = JSON.stringify({ format: "securemind.workspace/1", records: { analyses: Array.from({ length: 10001 }, () => ({})) } });
  assert.throws(() => parseBackup(tooMany, reanalyze), /up to 10,000/);
});

test("the investigation report holds analyses with evidence, an indicator table, notes, history and method", async () => {
  const ws = fresh();
  await loadDemoWorkspace(ws, analyze);
  const [inv] = await ws.listInvestigations();
  const analyses = await Promise.all(inv.analysisIds.map((id) => ws.getAnalysis(id)));
  const indicators = await Promise.all(inv.indicatorIds.map((id) => ws.getIndicator(id)));
  const out = investigationToMarkdown(inv, analyses, indicators, new Date("2026-11-14T00:00:00Z"));
  for (const heading of ["## Summary", "## Findings at a glance", "## Analyses", "## Indicators", "## Notes", "## History", "## Method and limits"]) {
    assert.ok(out.includes(`\n${heading}\n`), heading);
  }
  assert.match(out, /^### 1\. High risk: `hxxp/m);
  assert.match(out, /^\| domain \| `[^`]+\[\.\][^`]+` \| high \|/m);
  assert.match(out, /Report generated: 2026-11-14T00:00:00\.000Z/);
  assert.match(out, /Analysed with engine 2\.0\.0/);
  // No live host or scheme anywhere outside the defanged forms.
  assert.ok(!/https?:\/\//.test(out));
});

test("restoring a case keeps its link to an indicator that is already in the workspace", async () => {
  const source = fresh();
  const inv = await source.createInvestigation({ title: "Case" });
  await source.upsertIndicator({ type: "domain", value: "x.example", investigationId: inv.id });
  const backup = await exportBackup(source.store);
  const ws = fresh();
  await ws.upsertIndicator({ type: "domain", value: "x.example", confidence: "low" }); // the analyst's own copy
  await importBackup(ws.store, parseBackup(JSON.stringify(backup), reanalyze));
  assert.deepEqual((await ws.getInvestigation(inv.id)).indicatorIds, ["domain:x.example"]);
  const ind = await ws.getIndicator("domain:x.example");
  assert.deepEqual(ind.investigationIds, [inv.id], "back-link appended");
  assert.equal(ind.confidence, "low", "nothing else in the existing record changes");
});
