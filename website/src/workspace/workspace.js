// Workspace domain logic: analyses, investigations, indicators and the
// activity log. Pure business rules over a storage adapter (stores.js), so
// every rule is unit-tested without a browser.

import { defang, refang } from "../engine/defang.js";
import { VERDICTS } from "../engine/verdict.js";
import { readUrl } from "../engine/url-anatomy.js";
import { playbookById } from "./playbooks.js";
import { STORES } from "./stores.js";

export const INVESTIGATION_STATUSES = Object.freeze(["open", "investigating", "contained", "closed"]);
export const PRIORITIES = Object.freeze(["low", "medium", "high", "critical"]);
export const INDICATOR_TYPES = Object.freeze(["url", "domain", "hostname", "ipv4", "ipv6"]);
export const CONFIDENCE = Object.freeze(["low", "medium", "high"]);
// Alert queue: "new" waits for an analyst, "triage" is being looked at,
// "escalated" became (part of) an investigation, "closed" carries a disposition.
export const ALERT_STATUSES = Object.freeze(["new", "triage", "escalated", "closed"]);
export const DISPOSITIONS = Object.freeze(["true-positive", "benign", "false-positive", "duplicate"]);
// Queue rules: a match on one exact field, and one action. No patterns.
export const RULE_FIELDS = Object.freeze(["url", "host", "domain", "source"]);
/** Dispositions a rule may close with; a rule can never declare a true positive. */
export const RULE_DISPOSITIONS = Object.freeze(["benign", "false-positive", "duplicate"]);
export const MAX_RULES = 50;
/**
 * Registrable domains where anyone can publish pages or files: a domain rule
 * that closes their alerts would hide phishing hosted there. Use a host or
 * URL rule for a specific, known-good address instead.
 */
export const SHARED_DOMAINS = Object.freeze(["google.com", "googleusercontent.com", "sharepoint.com", "onedrive.com", "1drv.ms", "live.com",
  "office.com", "microsoft.com", "dropbox.com", "dropboxusercontent.com", "box.com", "wetransfer.com", "notion.so", "notion.site", "canva.com",
  "github.com", "gitlab.com", "amazonaws.com", "cloudfront.net", "azureedge.net", "windows.net", "firebaseapp.com", "web.app", "weebly.com",
  "wixsite.com", "squarespace.com", "webflow.io", "typeform.com", "jotform.com", "forms.gle",
  "ipfs.io", "pages.dev", "workers.dev", "netlify.app", "vercel.app", "herokuapp.com", "glitch.me", "replit.app", "blogspot.com", "wordpress.com"]);
export const LIMITS = Object.freeze({ title: 200, summary: 4000, note: 10000, tag: 40, tags: 20, value: 2048, source: 60, externalId: 120, reporter: 200, comment: 1000, task: 200, tasks: 100, ruleName: 80 });

export class WorkspaceError extends Error {}

/** Largest file accepted by any import (backups and indicator files). */
export const MAX_IMPORT_BYTES = 5 * 1024 * 1024;

const clean = (text, max) => String(text ?? "").replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "").trim().slice(0, max);

export function normalizeTags(tags) {
  const list = Array.isArray(tags) ? tags : String(tags ?? "").split(",");
  return [...new Set(list.map((t) => clean(t, LIMITS.tag).toLowerCase()).filter(Boolean))].slice(0, LIMITS.tags);
}

/** Canonical form and type check for an indicator value. Returns null when invalid. */
export function normalizeIndicator(type, value) {
  const v = clean(value, Infinity);
  if (!v || v.length > LIMITS.value) return null; // reject, never truncate
  switch (type) {
    case "url": {
      // The analyser's own policy and parser, with an explicit http(s)
      // scheme; stored as the browser's canonical form (IDN hosts in
      // punycode) without login details, as analyses store links.
      if (!/^https?:\/\//i.test(v)) return null;
      const read = readUrl(v);
      return read.ok && read.url.href.length <= LIMITS.value ? read.url.href : null;
    }
    case "domain":
    case "hostname": {
      // One trailing dot (the DNS root) is dropped; international names are
      // stored in punycode, as the analyser and browsers store them.
      let host = v.replace(/\.$/, "");
      if (/[^\x21-\x7e]/.test(host)) {
        if (/[\s\p{Cc}\p{Cf}/\\?#@:[\]%]/u.test(host)) return null;
        try {
          host = new URL(`http://${host}/`).hostname;
        } catch {
          return null;
        }
      }
      return /^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/i.test(host) ? host.toLowerCase() : null;
    }
    case "ipv4":
      // Dotted decimal only. Leading zeros are rejected: browsers read
      // "010.0.0.1" as octal (8.0.0.1) while people usually mean 10.0.0.1.
      return /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/.test(v) ? v : null;
    case "ipv6": {
      const bare = v.replace(/^\[(.*)\]$/, "$1");
      if (!/^[0-9a-f:.]+$/i.test(bare) || !bare.includes(":")) return null;
      try {
        // The URL parser gives the canonical RFC 5952 text (lowercase, "::" compression).
        return new URL(`http://[${bare}]/`).hostname.slice(1, -1);
      } catch {
        return null;
      }
    }
    default:
      return null;
  }
}

/** Classify a free-text value as an indicator type, accepting defanged forms. */
export function classifyIndicator(raw) {
  const v = refang(raw);
  for (const type of ["url", "ipv4", "ipv6", "domain"]) {
    const n = normalizeIndicator(type, v);
    if (n) return { type, value: n };
  }
  return null;
}

/** Indicators an analyst would typically record from one analysis. */
export function indicatorsFromAnalysis(report) {
  const f = report.facts;
  const out = [{ type: "url", value: report.url }];
  if (f.isIp) out.push({ type: f.ipVersion === 6 ? "ipv6" : "ipv4", value: f.host });
  else {
    out.push({ type: "hostname", value: f.host });
    if (f.registrableDomain && f.registrableDomain !== f.host) out.push({ type: "domain", value: f.registrableDomain });
  }
  return out;
}

const VERDICT_SEVERITY = { "high-risk": "high", suspicious: "medium", inconclusive: "low", "no-strong-indicators": "low" };
const VERDICT_LEVELS = Object.freeze(Object.keys(VERDICT_SEVERITY));

// ------------------------------------------------------------ damaged records
// Records can be damaged by browser extensions, edits in developer tools or
// older builds. A damaged record is set aside (listed in Settings, removable
// there) instead of breaking every page that lists its store.
const isStr = (v) => typeof v === "string";
const strs = (v) => Array.isArray(v) && v.every(isStr);
const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const INTACT = {
  analyses: (r) => isStr(r.id) && isStr(r.createdAt) && isStr(r.url) && isStr(r.host) && VERDICT_LEVELS.includes(r.verdict)
    && isObj(r.report) && r.report.ok === true && isObj(r.report.facts) && isObj(r.report.verdict) && r.report.verdict.level === r.verdict
    && strs(r.report.verdict.reasons) && Array.isArray(r.report.indicators)
    && r.report.indicators.every((i) => isObj(i) && isStr(i.id) && isStr(i.severity) && isStr(i.title))
    && Array.isArray(r.report.segments ?? []),
  investigations: (r) => isStr(r.id) && isStr(r.title) && isStr(r.summary) && INVESTIGATION_STATUSES.includes(r.status) && PRIORITIES.includes(r.priority)
    && strs(r.tags) && strs(r.analysisIds) && strs(r.indicatorIds) && isStr(r.createdAt) && isStr(r.updatedAt)
    && Array.isArray(r.notes) && r.notes.every((x) => isObj(x) && isStr(x.id) && isStr(x.at) && isStr(x.body))
    && Array.isArray(r.history) && r.history.every((h) => isObj(h) && isStr(h.at) && isStr(h.action) && isStr(h.detail))
    // Records from before checklists have no tasks field; they are intact.
    && (r.tasks === undefined || (Array.isArray(r.tasks) && r.tasks.every((t) => isObj(t) && isStr(t.id) && isStr(t.text) && typeof t.done === "boolean"))),
  indicators: (r) => isStr(r.id) && INDICATOR_TYPES.includes(r.type) && isStr(r.value) && r.id === `${r.type}:${r.value}`
    && CONFIDENCE.includes(r.confidence) && strs(r.tags) && strs(r.sources) && strs(r.analysisIds) && strs(r.investigationIds)
    && isStr(r.firstSeen) && isStr(r.lastSeen) && Number.isFinite(r.sightings) && isStr(r.stixId) && isStr(r.note ?? ""),
  activity: (r) => isStr(r.id) && isStr(r.at) && isStr(r.kind) && isStr(r.summary),
  rules: (r) => isStr(r.id) && isStr(r.name) && typeof r.enabled === "boolean" && isStr(r.createdAt) && isStr(r.updatedAt)
    && isObj(r.match) && RULE_FIELDS.includes(r.match.field) && isStr(r.match.value)
    && isObj(r.action) && ((r.action.type === "close" && RULE_DISPOSITIONS.includes(r.action.disposition)) || (r.action.type === "severity" && PRIORITIES.includes(r.action.severity)))
    && Number.isInteger(r.hits) && (r.lastHitAt === null || isStr(r.lastHitAt)),
  alerts: (r) => isStr(r.id) && isStr(r.createdAt) && isStr(r.updatedAt) && isStr(r.lastSeen) && Number.isInteger(r.occurrences) && r.occurrences > 0
    && isStr(r.url) && isStr(r.host) && VERDICT_LEVELS.includes(r.verdict) && PRIORITIES.includes(r.severity) && ALERT_STATUSES.includes(r.status)
    && isStr(r.source) && isStr(r.externalId) && isStr(r.reporter)
    && (r.status === "closed" ? DISPOSITIONS.includes(r.disposition) && isStr(r.closedAt) : r.disposition === null)
    && (r.status === "escalated" ? isStr(r.investigationId) : r.investigationId === null || isStr(r.investigationId))
    && (r.analysisId === null || isStr(r.analysisId)) && (r.triagedAt === null || isStr(r.triagedAt))
    && (r.closedByRule === undefined || r.closedByRule === null || isStr(r.closedByRule))
    && Array.isArray(r.history) && r.history.every((h) => isObj(h) && isStr(h.at) && isStr(h.action) && isStr(h.detail)),
};
/** True when a stored record has every field the workspace reads. */
export const isIntact = (s, r) => isObj(r) && INTACT[s](r);

/**
 * @param {ReturnType<import('./stores.js').createMemoryStore>} store
 * @param {{now?: () => Date, newId?: () => string}} [opts]
 */
export function createWorkspace(store, { now = () => new Date(), newId = () => crypto.randomUUID() } = {}) {
  const ts = () => now().toISOString();
  const intactList = async (s) => (await store.list(s)).filter((r) => isIntact(s, r));

  /**
   * A unit of work: reads go through a cache, writes are collected and
   * committed in one transaction, so a change that touches several records
   * either lands completely or not at all.
   */
  function begin() {
    const cache = new Map();
    const listed = new Map(); // store -> keys of its records, once read
    const ops = new Map();
    const key = (s, id) => `${s}\u0000${typeof id}\u0000${String(id)}`;
    const u = {
      async get(s, id) {
        const k = key(s, id);
        if (!cache.has(k)) {
          const r = await store.get(s, id);
          cache.set(k, isIntact(s, r) ? r : null);
        }
        return cache.get(k);
      },
      async must(s, id) {
        const r = await u.get(s, id);
        if (!r) throw new WorkspaceError(`${s.slice(0, -1)} not found`);
        return r;
      },
      /**
       * Intact records of a store, as this unit of work currently sees them.
       * The store is read once per unit of work (a bulk delete would otherwise
       * re-read it for every record).
       */
      async list(s) {
        if (!listed.has(s)) {
          const keys = new Set();
          for (const r of await intactList(s)) {
            const k = key(s, r.id);
            if (!cache.has(k)) cache.set(k, r);
            keys.add(k);
          }
          listed.set(s, keys);
        }
        return [...listed.get(s)].map((k) => cache.get(k)).filter(Boolean);
      },
      put(s, record) {
        listed.get(s)?.add(key(s, record.id));
        cache.set(key(s, record.id), record);
        ops.set(key(s, record.id), { type: "put", store: s, record });
        return record;
      },
      del(s, id) {
        cache.set(key(s, id), null);
        ops.set(key(s, id), { type: "delete", store: s, id });
      },
      log(kind, ref, summary) {
        u.put("activity", { id: newId(), at: ts(), kind, ref, summary: clean(summary, 300) });
      },
      commit: () => store.commit([...ops.values()]),
    };
    return u;
  }
  /** Run fn(unit) and commit its writes atomically; returns fn's result. */
  async function atomic(fn) {
    const u = begin();
    const result = await fn(u);
    await u.commit();
    return result;
  }
  async function must(s, id) {
    const record = await store.get(s, id);
    if (!isIntact(s, record)) throw new WorkspaceError(record ? `${s.slice(0, -1)} is damaged and cannot be opened` : `${s.slice(0, -1)} not found`);
    return record;
  }

  function stageAnalysis(u, report, demo) {
    if (!report?.ok) throw new WorkspaceError("only successful analyses can be saved");
    const record = u.put("analyses", {
      id: newId(), createdAt: ts(), demo,
      url: report.url, input: report.input ?? report.url, host: report.facts.host, registrableDomain: report.facts.registrableDomain,
      verdict: report.verdict.level, indicatorCount: report.indicators.filter((i) => i.severity !== "info").length,
      probability: report.model?.probability ?? null, report,
    });
    u.log("analysis.saved", { type: "analysis", id: record.id }, `Analysed ${defang(record.host)} — ${report.verdict.label}`);
    return record;
  }
  async function stageDeleteAnalysis(u, id) {
    u.del("analyses", id);
    for (const s of ["investigations", "indicators"]) {
      for (const r of await u.list(s)) {
        if (!r.analysisIds.includes(id)) continue;
        r.analysisIds = r.analysisIds.filter((x) => x !== id);
        u.put(s, r);
      }
    }
    // An alert keeps its link, host and verdict; only the full report goes.
    for (const al of await u.list("alerts")) {
      if (al.analysisId !== id) continue;
      al.analysisId = null;
      u.put("alerts", al);
    }
  }
  async function stageDeleteInvestigation(u, id) {
    u.del("investigations", id);
    for (const ind of await u.list("indicators")) {
      if (!ind.investigationIds.includes(id)) continue;
      ind.investigationIds = ind.investigationIds.filter((x) => x !== id);
      u.put("indicators", ind);
    }
    // An escalated alert whose case is gone goes back to triage, not into limbo.
    for (const al of await u.list("alerts")) {
      if (al.investigationId !== id) continue;
      const at = ts();
      al.investigationId = null;
      if (al.status === "escalated") {
        al.status = "triage";
        al.history.push({ at, action: "unlinked", detail: "Its investigation was deleted; back in triage" });
      }
      al.updatedAt = at;
      u.put("alerts", al);
    }
  }
  function stageInvestigation(u, { title, summary = "", priority = "medium", tags = [], demo = false }) {
    const t = clean(title, LIMITS.title);
    if (!t) throw new WorkspaceError("an investigation needs a title");
    if (!PRIORITIES.includes(priority)) throw new WorkspaceError("unknown priority");
    const at = ts();
    const record = u.put("investigations", {
      id: newId(), title: t, summary: clean(summary, LIMITS.summary), status: "open", priority, tags: normalizeTags(tags),
      notes: [], tasks: [], analysisIds: [], indicatorIds: [], demo, createdAt: at, updatedAt: at,
      history: [{ at, action: "created", detail: `Opened with ${priority} priority` }],
    });
    u.log("investigation.created", { type: "investigation", id: record.id }, `Opened “${t}”`);
    return record;
  }
  /** Add a playbook's steps that the case does not already have (matched by text). */
  function stageApplyPlaybook(u, inv, playbookId) {
    const book = playbookById(playbookId);
    if (!book) throw new WorkspaceError("unknown playbook");
    inv.tasks ??= [];
    const have = new Set(inv.tasks.map((t) => t.text));
    const fresh = book.steps.filter((text) => !have.has(text));
    if (inv.tasks.length + fresh.length > LIMITS.tasks) throw new WorkspaceError(`an investigation holds at most ${LIMITS.tasks} checklist steps`);
    const at = ts();
    for (const text of fresh) inv.tasks.push({ id: newId(), text, done: false, doneAt: null, playbook: book.id });
    inv.history.push({ at, action: "playbook", detail: `${book.name}: ${fresh.length} step${fresh.length === 1 ? "" : "s"} added` });
    inv.updatedAt = at;
    return u.put("investigations", inv);
  }
  /** Change one checklist step; fn returns the history detail, or false for no change. */
  function stageTask(u, inv, taskId, fn) {
    const task = (inv.tasks ?? []).find((t) => t.id === taskId);
    if (!task) throw new WorkspaceError("checklist step not found");
    const at = ts();
    const detail = fn(task, at);
    if (detail === false) return inv;
    inv.history.push({ at, action: "task", detail: detail.length > 120 ? `${detail.slice(0, 119)}…` : detail });
    inv.updatedAt = at;
    return u.put("investigations", inv);
  }
  async function stageLinkAnalysis(u, id, analysisId) {
    const inv = await u.must("investigations", id);
    const analysis = await u.must("analyses", analysisId);
    if (inv.analysisIds.includes(analysisId)) return inv;
    inv.analysisIds.push(analysisId);
    inv.history.push({ at: ts(), action: "linked", detail: `Analysis of ${defang(analysis.host)}` });
    // Indicators already recorded from this analysis join the case too.
    for (const ind of await u.list("indicators")) {
      if (!ind.analysisIds.includes(analysisId) || inv.indicatorIds.includes(ind.id)) continue;
      inv.indicatorIds.push(ind.id);
      if (!ind.investigationIds.includes(id)) ind.investigationIds.push(id);
      u.put("indicators", ind);
    }
    inv.updatedAt = ts();
    return u.put("investigations", inv);
  }
  /**
   * Queue one analysed link as an alert. A link that already has an alert
   * still in the queue (not closed) is counted on that alert instead: one
   * phishing wave reported by fifty people is one alert seen fifty times.
   */
  /** The first enabled rule (oldest first) whose field equals the alert's. */
  async function matchingRule(u, alert) {
    const rules = (await u.list("rules")).filter((r) => r.enabled).sort((a, b) => a.createdAt.localeCompare(b.createdAt));
    const value = { url: alert.url, host: alert.host, domain: alert.registrableDomain, source: alert.source };
    return rules.find((r) => value[r.match.field] === r.match.value) ?? null;
  }
  /** Apply a rule to a new alert. A close rule never closes an alert judged high risk or suspicious. */
  function applyRule(u, rule, alert, at) {
    rule.hits += 1;
    rule.lastHitAt = at;
    u.put("rules", rule);
    const name = `“${rule.name}”`;
    if (rule.action.type === "severity") {
      if (alert.severity !== rule.action.severity) {
        alert.history.push({ at, action: "rule", detail: `Severity ${alert.severity} → ${rule.action.severity} by rule ${name}` });
        alert.severity = rule.action.severity;
      }
      return "severity";
    }
    if (alert.verdict === "high-risk" || alert.verdict === "suspicious") {
      alert.history.push({ at, action: "rule", detail: `Matched rule ${name}; not closed, because the link was judged ${VERDICT_LABEL[alert.verdict]}` });
      return "held";
    }
    Object.assign(alert, { status: "closed", disposition: rule.action.disposition, closedAt: at, triagedAt: at, closedByRule: rule.id });
    alert.history.push({ at, action: "rule", detail: `Closed as ${rule.action.disposition} by rule ${name}` });
    return "closed";
  }
  async function stageAlert(u, { report, source = "manual", externalId = "", reporter = "", demo = false }) {
    if (!report?.ok) throw new WorkspaceError("only analysed links can be queued");
    const src = clean(source, Infinity);
    const ext = clean(externalId, Infinity);
    const who = clean(reporter, Infinity);
    // Reject, never truncate: a cut reference or reporter would point at the wrong thing.
    if (src.length > LIMITS.source || ext.length > LIMITS.externalId || who.length > LIMITS.reporter) throw new WorkspaceError("an alert field is too long");
    const at = ts();
    const from = [src || "manual", ext && `ref ${ext}`, who && `reported by ${who}`].filter(Boolean).join(", ");
    // A link already in the queue counts as a repeat; so does one a rule already closed (no new alert or analysis).
    const open = (await u.list("alerts")).find((a) => a.url === report.url && (a.status !== "closed" || a.closedByRule));
    if (open) {
      open.occurrences += 1;
      open.lastSeen = at;
      open.updatedAt = at;
      open.demo = open.demo && demo;
      open.history.push({ at, action: "repeat", detail: `Seen again (${from})` });
      u.put("alerts", open);
      return { alert: open, merged: true, rule: null };
    }
    const analysis = stageAnalysis(u, report, demo);
    const alert = u.put("alerts", {
      id: newId(), createdAt: at, updatedAt: at, lastSeen: at, occurrences: 1, demo,
      url: report.url, host: report.facts.host, registrableDomain: report.facts.registrableDomain, verdict: report.verdict.level,
      analysisId: analysis.id, severity: VERDICT_SEVERITY[report.verdict.level], status: "new", disposition: null,
      investigationId: null, triagedAt: null, closedAt: null, closedByRule: null, source: src || "manual", externalId: ext, reporter: who,
      history: [{ at, action: "created", detail: `Queued from ${from}` }],
    });
    const rule = await matchingRule(u, alert);
    return { alert, merged: false, rule: rule ? applyRule(u, rule, alert, at) : null };
  }
  /** Read alerts and run fn on each that exists; missing ids are an error, so a bulk action never half-applies. */
  async function eachAlert(u, ids, fn) {
    const at = ts();
    const out = [];
    for (const id of new Set(ids)) {
      const al = await u.must("alerts", id);
      if (fn(al, at) === false) continue;
      al.updatedAt = at;
      out.push(u.put("alerts", al));
    }
    return out;
  }
  async function stageDeleteIndicator(u, id) {
    u.del("indicators", id);
    for (const inv of await u.list("investigations")) {
      if (!inv.indicatorIds.includes(id)) continue;
      inv.indicatorIds = inv.indicatorIds.filter((x) => x !== id);
      u.put("investigations", inv);
    }
  }
  async function stageIndicator(u, { type, value, confidence = "medium", tags = [], source = "analyst", analysisId = null, investigationId = null, note = "", demo = false, stixId = null }) {
    if (!INDICATOR_TYPES.includes(type)) throw new WorkspaceError("unknown indicator type");
    if (!CONFIDENCE.includes(confidence)) throw new WorkspaceError("unknown confidence");
    const v = normalizeIndicator(type, value);
    if (!v) throw new WorkspaceError(`that is not a valid ${type}`);
    const id = `${type}:${v}`;
    const at = ts();
    const existing = await u.get("indicators", id);
    const ind = existing ?? {
      id, type, value: v, stixId: STIX_INDICATOR_ID.test(stixId ?? "") ? stixId : `indicator--${newId()}`, confidence, tags: [], sources: [],
      analysisIds: [], investigationIds: [], note: "", firstSeen: at, lastSeen: at, sightings: 0, demo,
    };
    ind.lastSeen = at;
    ind.sightings += 1;
    ind.demo = ind.demo && demo; // recorded again as real data: no longer demo-only
    if (existing) ind.confidence = CONFIDENCE.indexOf(confidence) > CONFIDENCE.indexOf(ind.confidence) ? confidence : ind.confidence;
    ind.tags = normalizeTags([...ind.tags, ...normalizeTags(tags)]);
    const src = clean(source, 120);
    if (src && !ind.sources.includes(src)) ind.sources.push(src);
    if (analysisId && !ind.analysisIds.includes(analysisId)) ind.analysisIds.push(analysisId);
    if (investigationId) {
      const inv = await u.must("investigations", investigationId);
      if (!ind.investigationIds.includes(investigationId)) ind.investigationIds.push(investigationId);
      if (!inv.indicatorIds.includes(id)) {
        inv.indicatorIds.push(id);
        inv.history.push({ at, action: "indicator", detail: `${type} ${defang(v)}` });
        inv.updatedAt = at;
        u.put("investigations", inv);
      }
    }
    if (note) ind.note = clean(note, LIMITS.note);
    u.put("indicators", ind);
    if (!existing) u.log("indicator.added", { type: "indicator", id }, `Recorded ${type} ${defang(v)}`);
    return ind;
  }

  const api = {
    store,

    // ------------------------------------------------------------ analyses
    saveAnalysis: (report, { demo = false } = {}) => atomic((u) => stageAnalysis(u, report, demo)),
    /** Save several analyses in one transaction (batch results). */
    saveAnalyses: (reports, { demo = false } = {}) => atomic((u) => reports.map((r) => stageAnalysis(u, r, demo))),
    /**
     * Analyses newest first. With `limit`, returns one page:
     * { items, total, offset }, where total counts every match.
     */
    async listAnalyses({ verdict, query, demo, offset = 0, limit } = {}) {
      const q = query?.trim().toLowerCase();
      const all = (await intactList("analyses"))
        .filter((a) => (!verdict || a.verdict === verdict) && (demo === undefined || !!a.demo === demo)
          && (!q || a.url.toLowerCase().includes(q) || a.host.toLowerCase().includes(q)))
        .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
      return limit === undefined ? all : pageOf(all, offset, limit);
    },
    getAnalysis: (id) => must("analyses", id),
    deleteAnalysis: (id) => atomic((u) => stageDeleteAnalysis(u, id)),
    /** Delete several analyses and every link to them, all or nothing. */
    deleteAnalyses: (ids) => atomic(async (u) => {
      const unique = [...new Set(ids)];
      for (const id of unique) await stageDeleteAnalysis(u, id);
      u.log("analysis.deleted", null, `Deleted ${unique.length} ${unique.length === 1 ? "analysis" : "analyses"}`);
      return unique.length;
    }),

    // ------------------------------------------------------------ investigations
    createInvestigation: (input) => atomic((u) => stageInvestigation(u, input)),
    updateInvestigation(id, patch) {
      // Validate the whole patch first, so a rejected change writes nothing.
      if (patch.status !== undefined && !INVESTIGATION_STATUSES.includes(patch.status)) return Promise.reject(new WorkspaceError("unknown status"));
      if (patch.priority !== undefined && !PRIORITIES.includes(patch.priority)) return Promise.reject(new WorkspaceError("unknown priority"));
      if (patch.title !== undefined && !clean(patch.title, LIMITS.title)) return Promise.reject(new WorkspaceError("an investigation needs a title"));
      return atomic(async (u) => {
        const inv = await u.must("investigations", id);
        const at = ts();
        if (patch.title !== undefined) {
          const t = clean(patch.title, LIMITS.title);
          if (t !== inv.title) inv.history.push({ at, action: "renamed", detail: t });
          inv.title = t;
        }
        if (patch.summary !== undefined) {
          const summary = clean(patch.summary, LIMITS.summary);
          if (summary !== inv.summary) inv.history.push({ at, action: "summary", detail: "Summary edited" });
          inv.summary = summary;
        }
        if (patch.status !== undefined && patch.status !== inv.status) {
          inv.history.push({ at, action: "status", detail: `${inv.status} → ${patch.status}` });
          inv.status = patch.status;
          u.log("investigation.status", { type: "investigation", id }, `“${inv.title}” is now ${inv.status}`);
        }
        if (patch.priority !== undefined && patch.priority !== inv.priority) {
          inv.history.push({ at, action: "priority", detail: `${inv.priority} → ${patch.priority}` });
          inv.priority = patch.priority;
        }
        if (patch.tags !== undefined) {
          const tags = normalizeTags(patch.tags);
          if ([...tags].sort().join() !== [...inv.tags].sort().join()) inv.history.push({ at, action: "tags", detail: tags.length ? tags.join(", ") : "Tags cleared" });
          inv.tags = tags;
        }
        inv.updatedAt = at;
        return u.put("investigations", inv);
      });
    },
    addNote(id, text) {
      const body = clean(text, LIMITS.note);
      if (!body) return Promise.reject(new WorkspaceError("a note cannot be empty"));
      return atomic(async (u) => {
        const inv = await u.must("investigations", id);
        const at = ts();
        inv.notes.push({ id: newId(), at, body });
        inv.history.push({ at, action: "note", detail: body.length > 80 ? `${body.slice(0, 79)}…` : body });
        inv.updatedAt = at;
        return u.put("investigations", inv);
      });
    },
    // ------------------------------------------------------------ checklists
    applyPlaybook: (id, playbookId) => atomic(async (u) => stageApplyPlaybook(u, await u.must("investigations", id), playbookId)),
    addTask(id, text) {
      const t = clean(text, Infinity);
      if (!t) return Promise.reject(new WorkspaceError("a checklist step cannot be empty"));
      if (t.length > LIMITS.task) return Promise.reject(new WorkspaceError(`a checklist step is at most ${LIMITS.task} characters`));
      return atomic(async (u) => {
        const inv = await u.must("investigations", id);
        inv.tasks ??= [];
        if (inv.tasks.length >= LIMITS.tasks) throw new WorkspaceError(`an investigation holds at most ${LIMITS.tasks} checklist steps`);
        const at = ts();
        inv.tasks.push({ id: newId(), text: t, done: false, doneAt: null, playbook: null });
        inv.history.push({ at, action: "task", detail: `Added: ${t.length > 110 ? `${t.slice(0, 109)}…` : t}` });
        inv.updatedAt = at;
        return u.put("investigations", inv);
      });
    },
    setTaskDone: (id, taskId, done) => atomic(async (u) => stageTask(u, await u.must("investigations", id), taskId, (task, at) => {
      if (task.done === !!done) return false;
      task.done = !!done;
      task.doneAt = task.done ? at : null;
      return `${task.done ? "Done" : "Reopened"}: ${task.text}`;
    })),
    deleteTask: (id, taskId) => atomic(async (u) => {
      const inv = await u.must("investigations", id);
      return stageTask(u, inv, taskId, (task) => {
        inv.tasks = inv.tasks.filter((t) => t.id !== taskId);
        return `Removed: ${task.text}`;
      });
    }),
    deleteNote: (id, noteId) => atomic(async (u) => {
      const inv = await u.must("investigations", id);
      inv.notes = inv.notes.filter((n) => n.id !== noteId);
      inv.history.push({ at: ts(), action: "note-removed", detail: "A note was removed" });
      return u.put("investigations", inv);
    }),
    linkAnalysis: (id, analysisId) => atomic((u) => stageLinkAnalysis(u, id, analysisId)),
    unlinkAnalysis: (id, analysisId) => atomic(async (u) => {
      const inv = await u.must("investigations", id);
      if (!inv.analysisIds.includes(analysisId)) return inv;
      inv.analysisIds = inv.analysisIds.filter((x) => x !== analysisId);
      inv.history.push({ at: ts(), action: "unlinked", detail: "An analysis was removed from the case" });
      inv.updatedAt = ts();
      return u.put("investigations", inv);
    }),
    async listInvestigations({ status, query, tag } = {}) {
      const q = query?.toLowerCase();
      return (await intactList("investigations"))
        .filter((i) => (!status || i.status === status) && (!tag || i.tags.includes(tag))
          && (!q || i.title.toLowerCase().includes(q) || i.summary.toLowerCase().includes(q)))
        .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
    },
    getInvestigation: (id) => must("investigations", id),
    deleteInvestigation: (id) => atomic((u) => stageDeleteInvestigation(u, id)),

    // ------------------------------------------------------------ indicators
    upsertIndicator: (input) => atomic((u) => stageIndicator(u, input)),
    /** Record several indicators in one transaction: one invalid item writes nothing. */
    upsertIndicators: (items) => atomic(async (u) => {
      const out = [];
      for (const it of items) out.push(await stageIndicator(u, it));
      return out;
    }),
    updateIndicator: (id, { confidence, tags, note }) => atomic(async (u) => {
      if (confidence !== undefined && !CONFIDENCE.includes(confidence)) throw new WorkspaceError("unknown confidence");
      const ind = await u.must("indicators", id);
      if (confidence !== undefined) ind.confidence = confidence;
      if (tags !== undefined) ind.tags = normalizeTags(tags);
      if (note !== undefined) ind.note = clean(note, LIMITS.note);
      return u.put("indicators", ind);
    }),
    async listIndicators({ type, query, tag } = {}) {
      const q = query?.toLowerCase();
      return (await intactList("indicators"))
        .filter((i) => (!type || i.type === type) && (!tag || i.tags.includes(tag)) && (!q || i.value.toLowerCase().includes(q)))
        .sort((a, b) => b.lastSeen.localeCompare(a.lastSeen));
    },
    getIndicator: (id) => must("indicators", id),
    deleteIndicator: (id) => atomic((u) => stageDeleteIndicator(u, id)),
    /** Indicators that share a registrable domain or host with this one. */
    async relatedIndicators(id) {
      const ind = await must("indicators", id);
      const key = (i) => (i.type === "url" ? hostOf(i.value) : i.value);
      const mine = key(ind);
      return (await intactList("indicators")).filter((o) => o.id !== id && mine && (key(o) === mine
        || key(o)?.endsWith(`.${mine}`) || mine.endsWith(`.${key(o)}`)));
    },

    // ------------------------------------------------------------ queue rules
    /**
     * Add a queue rule. It applies to alerts queued from now on, never to
     * alerts already in the queue.
     * @param {{name: string, field: string, value: string, action: "close"|"severity", disposition?: string, severity?: string}} input
     */
    createRule({ name, field, value, action, disposition, severity }) {
      const n = clean(name, Infinity);
      if (!n) return Promise.reject(new WorkspaceError("a rule needs a name"));
      if (n.length > LIMITS.ruleName) return Promise.reject(new WorkspaceError(`a rule name is at most ${LIMITS.ruleName} characters`));
      if (!RULE_FIELDS.includes(field)) return Promise.reject(new WorkspaceError("unknown rule field"));
      const v = field === "source" ? clean(value, Infinity) : normalizeIndicator(field === "host" ? "hostname" : field, refang(String(value ?? "")));
      if (!v || (field === "source" && v.length > LIMITS.source)) return Promise.reject(new WorkspaceError(`that is not a valid ${field === "domain" ? "registrable domain" : field}`));
      let act;
      if (action === "close") {
        if (!RULE_DISPOSITIONS.includes(disposition)) return Promise.reject(new WorkspaceError("a rule can close only as benign, false positive or duplicate"));
        if (field === "domain" && SHARED_DOMAINS.includes(v)) {
          return Promise.reject(new WorkspaceError(`anyone can publish on ${v}, so a domain rule must not close its alerts; use a host or URL rule for a known address`));
        }
        act = { type: "close", disposition };
      } else if (action === "severity") {
        if (!PRIORITIES.includes(severity)) return Promise.reject(new WorkspaceError("unknown severity"));
        act = { type: "severity", severity };
      } else return Promise.reject(new WorkspaceError("unknown rule action"));
      return atomic(async (u) => {
        if ((await u.list("rules")).length >= MAX_RULES) throw new WorkspaceError(`at most ${MAX_RULES} rules`);
        const at = ts();
        const rule = u.put("rules", { id: newId(), name: n, enabled: true, match: { field, value: v }, action: act, hits: 0, lastHitAt: null, createdAt: at, updatedAt: at });
        u.log("rule.created", null, `Rule “${n}” added`);
        return rule;
      });
    },
    setRuleEnabled: (id, enabled) => atomic(async (u) => {
      const rule = await u.must("rules", id);
      if (rule.enabled === !!enabled) return rule;
      if (enabled && rule.action.type === "close" && rule.match.field === "domain" && SHARED_DOMAINS.includes(rule.match.value)) {
        throw new WorkspaceError(`anyone can publish on ${rule.match.value}, so a domain rule must not close its alerts; delete this rule`);
      }
      rule.enabled = !!enabled;
      rule.updatedAt = ts();
      u.log("rule.changed", null, `Rule “${rule.name}” ${rule.enabled ? "switched on" : "switched off"}`);
      return u.put("rules", rule);
    }),
    deleteRule: (id) => atomic(async (u) => {
      const rule = await u.must("rules", id);
      u.del("rules", id);
      u.log("rule.deleted", null, `Rule “${rule.name}” deleted`);
    }),
    /** Rules in the order they are tried (oldest first). */
    listRules: async () => (await intactList("rules")).sort((a, b) => a.createdAt.localeCompare(b.createdAt)),
    /**
     * Hosts that analysts closed as benign or false positive at least
     * `minimum` times (separate alerts), never judged high risk or suspicious
     * and not yet covered by a host or domain rule. Suggestions only:
     * nothing is created until the analyst confirms.
     */
    async ruleSuggestions({ minimum = 2 } = {}) {
      const [alerts, rules] = await Promise.all([intactList("alerts"), intactList("rules")]);
      const covered = new Set(rules.flatMap((r) => (r.match.field === "host" || r.match.field === "domain" ? [`${r.match.field}:${r.match.value}`] : [])));
      const byHost = new Map();
      const risky = new Set(alerts.filter((a) => a.verdict === "high-risk" || a.verdict === "suspicious").map((a) => a.host));
      for (const a of alerts) {
        if (a.status !== "closed" || a.closedByRule || !RULE_DISPOSITIONS.includes(a.disposition)) continue;
        if (risky.has(a.host) || covered.has(`host:${a.host}`) || covered.has(`domain:${a.registrableDomain}`)) continue;
        const e = byHost.get(a.host) ?? { host: a.host, alerts: 0, dispositions: {} };
        e.alerts += 1;
        e.dispositions[a.disposition] = (e.dispositions[a.disposition] ?? 0) + 1;
        byHost.set(a.host, e);
      }
      return [...byHost.values()].filter((e) => e.alerts >= minimum)
        .map((e) => ({ host: e.host, alerts: e.alerts, disposition: Object.entries(e.dispositions).sort((a, b) => b[1] - a[1])[0][0] }))
        .sort((a, b) => b.alerts - a.alerts || a.host.localeCompare(b.host))
        .slice(0, 10);
    },

    // ------------------------------------------------------------ alert queue
    /**
     * Queue analysed links as alerts in one transaction: one bad item queues nothing.
     * @param {Array<{report, source?, externalId?, reporter?}>} items
     */
    queueAlerts: (items, { demo = false } = {}) => atomic(async (u) => {
      const results = [];
      for (const it of items) results.push(await stageAlert(u, { ...it, demo }));
      const created = results.filter((r) => !r.merged).map((r) => r.alert);
      const merged = results.length - created.length;
      const closedByRule = results.filter((r) => r.rule === "closed").length;
      if (results.length) {
        u.log("alert.queued", null, `Queued ${created.length} alert${created.length === 1 ? "" : "s"}${merged ? `; ${merged} seen again` : ""}${closedByRule ? `; ${closedByRule} closed by queue rules` : ""}`);
      }
      return { created, merged, closedByRule };
    }),
    /** Move new alerts into triage; alerts past "new" are left as they are. */
    triageAlerts: (ids) => atomic((u) => eachAlert(u, ids, (al, at) => {
      if (al.status !== "new") return false;
      al.status = "triage";
      al.triagedAt = at;
      al.history.push({ at, action: "triage", detail: "Triage started" });
    })),
    setAlertSeverity(id, severity) {
      if (!PRIORITIES.includes(severity)) return Promise.reject(new WorkspaceError("unknown severity"));
      return atomic(async (u) => (await eachAlert(u, [id], (al, at) => {
        if (al.severity === severity) return false;
        al.history.push({ at, action: "severity", detail: `${al.severity} → ${severity}` });
        al.severity = severity;
      }))[0] ?? u.must("alerts", id));
    },
    /** Close alerts with a disposition; already-closed alerts keep theirs. */
    closeAlerts(ids, { disposition, comment = "" }) {
      if (!DISPOSITIONS.includes(disposition)) return Promise.reject(new WorkspaceError("choose a disposition"));
      const why = clean(comment, Infinity);
      if (why.length > LIMITS.comment) return Promise.reject(new WorkspaceError("the comment is too long"));
      return atomic(async (u) => {
        const closed = await eachAlert(u, ids, (al, at) => {
          if (al.status === "closed") return false;
          al.status = "closed";
          al.disposition = disposition;
          al.closedAt = at;
          al.closedByRule = null;
          al.triagedAt ??= at;
          al.history.push({ at, action: "closed", detail: why ? `${disposition}: ${why}` : disposition });
        });
        if (closed.length) u.log("alert.closed", null, `Closed ${closed.length} alert${closed.length === 1 ? "" : "s"} as ${disposition}`);
        return closed;
      });
    },
    reopenAlert: (id) => atomic(async (u) => (await eachAlert(u, [id], (al, at) => {
      if (al.status !== "closed") return false;
      al.history.push({ at, action: "reopened", detail: `Reopened (was ${al.disposition})` });
      al.status = al.investigationId ? "escalated" : "triage";
      al.disposition = null;
      al.closedAt = null;
      al.closedByRule = null;
    }))[0] ?? u.must("alerts", id)),
    /**
     * Escalate an alert to an existing investigation, or to a new one opened
     * with the alert's severity. Its analysis joins the case.
     */
    escalateAlert: (id, { investigationId = null, title = "", playbookId = null } = {}) => atomic(async (u) => {
      const al = await u.must("alerts", id);
      if (al.status === "closed") throw new WorkspaceError("reopen the alert before escalating it");
      if (al.status === "escalated" && investigationId && al.investigationId === investigationId) {
        return { alert: al, investigation: await u.must("investigations", investigationId) }; // already there: no duplicate history
      }
      const inv = investigationId
        ? await u.must("investigations", investigationId)
        : stageInvestigation(u, {
          title: clean(title, LIMITS.title) || `Alert: ${defang(al.host)}`,
          summary: `Escalated from the alert queue (${al.source}${al.externalId ? `, ref ${al.externalId}` : ""}).`,
          priority: al.severity, tags: ["alert"], demo: al.demo,
        });
      if (al.analysisId && await u.get("analyses", al.analysisId)) await stageLinkAnalysis(u, inv.id, al.analysisId);
      if (playbookId) stageApplyPlaybook(u, inv, playbookId);
      const at = ts();
      inv.history.push({ at, action: "alert", detail: `Escalated alert for ${defang(al.host)}` });
      inv.updatedAt = at;
      u.put("investigations", inv);
      al.status = "escalated";
      al.investigationId = inv.id;
      al.triagedAt ??= at;
      al.updatedAt = at;
      al.history.push({ at, action: "escalated", detail: `To “${inv.title}”` });
      u.put("alerts", al);
      u.log("alert.escalated", { type: "investigation", id: inv.id }, `Escalated ${defang(al.host)} to “${inv.title}”`);
      return { alert: al, investigation: inv };
    }),
    /** Delete alerts only: their analyses and investigations stay. */
    deleteAlerts: (ids) => atomic(async (u) => {
      const unique = [...new Set(ids)];
      for (const id of unique) u.del("alerts", id);
      u.log("alert.deleted", null, `Deleted ${unique.length} alert${unique.length === 1 ? "" : "s"}`);
      return unique.length;
    }),
    /**
     * The queue: status first (new, triage, escalated, closed), then most
     * severe, then oldest. `status: "open"` means new or in triage.
     */
    async listAlerts({ status, severity, query, offset = 0, limit } = {}) {
      const q = query?.trim().toLowerCase();
      const all = (await intactList("alerts"))
        .filter((a) => (!status || (status === "open" ? ALERT_OPEN.has(a.status) : a.status === status)) && (!severity || a.severity === severity)
          && (!q || [a.url, a.host, a.source, a.externalId, a.reporter].some((x) => x.toLowerCase().includes(q))))
        .sort((a, b) => ALERT_STATUSES.indexOf(a.status) - ALERT_STATUSES.indexOf(b.status)
          || PRIORITIES.indexOf(b.severity) - PRIORITIES.indexOf(a.severity) || a.createdAt.localeCompare(b.createdAt));
      return limit === undefined ? all : pageOf(all, offset, limit);
    },
    getAlert: (id) => must("alerts", id),
    /** The next open alert in queue order after this one (wrapping), or null when no other is open. */
    async nextOpenAlert(id) {
      const open = await api.listAlerts({ status: "open" });
      if (!open.length) return null;
      const i = open.findIndex((a) => a.id === id);
      const next = i === -1 ? open[0] : open[(i + 1) % open.length];
      return next.id === id ? null : next;
    },
    /** Queue health for the last `days`: backlog, dispositions, and median times to triage and to close (ms). */
    async alertMetrics({ days = 30 } = {}) {
      const since = new Date(now().getTime() - days * 864e5).toISOString();
      const alerts = await intactList("alerts");
      const open = alerts.filter((a) => ALERT_OPEN.has(a.status));
      // Alerts closed by a queue rule are not analyst work: they are counted
      // apart and kept out of the medians and the false-positive rate.
      const byRule = alerts.filter((a) => a.status === "closed" && a.closedByRule && a.closedAt >= since);
      const closed = alerts.filter((a) => a.status === "closed" && !a.closedByRule && a.closedAt >= since);
      const span = (from, to) => Date.parse(to) - Date.parse(from);
      return {
        days,
        total: alerts.length,
        byStatus: Object.fromEntries(ALERT_STATUSES.map((s) => [s, alerts.filter((a) => a.status === s).length])),
        open: open.length,
        openBySeverity: Object.fromEntries(PRIORITIES.map((p) => [p, open.filter((a) => a.severity === p).length])),
        oldestOpen: open.reduce((min, a) => (!min || a.createdAt < min ? a.createdAt : min), null),
        closedRecent: closed.length,
        closedByRule: byRule.length,
        byDisposition: Object.fromEntries(DISPOSITIONS.map((d) => [d, closed.filter((a) => a.disposition === d).length])),
        falsePositiveRate: closed.length ? closed.filter((a) => a.disposition === "false-positive").length / closed.length : null,
        timeToTriage: median(alerts.filter((a) => a.triagedAt && !a.closedByRule && a.triagedAt >= since).map((a) => span(a.createdAt, a.triagedAt))),
        timeToClose: median(closed.map((a) => span(a.createdAt, a.closedAt))),
      };
    },

    // ------------------------------------------------------------ overview
    async activity(limit = 20) {
      return (await intactList("activity")).sort((a, b) => b.at.localeCompare(a.at)).slice(0, limit);
    },
    /**
     * A period report for the last `days`: alert intake and outcomes, response
     * times, top lure domains, case and checklist progress, indicators. Every
     * figure is computed from stored records; nothing is estimated.
     */
    async report({ days = 7 } = {}) {
      if (!Number.isInteger(days) || days < 1 || days > 366) throw new WorkspaceError("a report covers 1 to 366 days");
      const until = now().toISOString();
      const since = new Date(now().getTime() - days * 864e5).toISOString();
      const inWindow = (t) => t && t >= since && t <= until;
      const [alerts, investigations, indicators, analyses] = await Promise.all(["alerts", "investigations", "indicators", "analyses"].map(intactList));
      const queued = alerts.filter((a) => inWindow(a.createdAt));
      const count = (list, key) => list.reduce((m, x) => ((m[key(x)] = (m[key(x)] ?? 0) + 1), m), {});
      const lures = {};
      for (const a of queued) {
        if (a.verdict !== "high-risk" && a.verdict !== "suspicious") continue;
        const d = a.registrableDomain ?? a.host;
        lures[d] ??= { domain: d, alerts: 0, reports: 0 };
        lures[d].alerts += 1;
        lures[d].reports += a.occurrences;
      }
      const statusChanges = investigations.flatMap((i) => i.history.filter((h) => h.action === "status" && inWindow(h.at)).map((h) => ({ i, to: h.detail.split("→").pop().trim() })));
      const open = investigations.filter((i) => i.status !== "closed");
      const tasks = open.flatMap((i) => i.tasks ?? []);
      const findings = {};
      for (const a of analyses.filter((x) => inWindow(x.createdAt))) {
        for (const ind of a.report.indicators) if (ind.severity !== "info") findings[ind.id] = (findings[ind.id] ?? 0) + 1;
      }
      return {
        days, since, until,
        alerts: {
          queued: queued.length,
          reports: queued.reduce((n, a) => n + a.occurrences, 0),
          bySource: count(queued, (a) => a.source),
          byVerdict: count(queued, (a) => a.verdict),
          escalated: alerts.filter((a) => a.history.some((h) => h.action === "escalated" && inWindow(h.at))).length,
          metrics: await api.alertMetrics({ days }),
        },
        topLures: Object.values(lures).sort((a, b) => b.reports - a.reports || b.alerts - a.alerts || a.domain.localeCompare(b.domain)).slice(0, 10),
        investigations: {
          opened: investigations.filter((i) => inWindow(i.createdAt)).length,
          closed: new Set(statusChanges.filter((c) => c.to === "closed").map((c) => c.i.id)).size,
          open: open.length,
          openByPriority: Object.fromEntries(PRIORITIES.map((p) => [p, open.filter((i) => i.priority === p).length])),
          checklist: { done: tasks.filter((t) => t.done).length, total: tasks.length },
        },
        indicators: {
          recorded: indicators.filter((i) => inWindow(i.firstSeen)).length,
          byType: Object.fromEntries(INDICATOR_TYPES.map((t) => [t, indicators.filter((i) => i.type === t && inWindow(i.firstSeen)).length])),
        },
        topFindings: Object.entries(findings).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, 8),
      };
    },
    async overview({ days = 30 } = {}) {
      const since = new Date(now().getTime() - days * 864e5).toISOString();
      const [analyses, investigations, indicators, alerts] = await Promise.all(STORES_FOR_OVERVIEW.map(intactList));
      const recent = analyses.filter((a) => a.createdAt >= since);
      const byVerdict = Object.fromEntries(VERDICT_LEVELS.map((v) => [v, recent.filter((a) => a.verdict === v).length]));
      const perDay = [];
      for (let d = Math.min(days, 14) - 1; d >= 0; d--) {
        const day = new Date(now().getTime() - d * 864e5).toISOString().slice(0, 10);
        perDay.push({ day, count: analyses.filter((a) => a.createdAt.startsWith(day)).length });
      }
      const indicatorCounts = {};
      for (const i of analyses.flatMap((a) => a.report.indicators)) if (i.severity !== "info") indicatorCounts[i.id] = (indicatorCounts[i.id] || 0) + 1;
      return {
        days,
        totals: { analyses: analyses.length, investigations: investigations.length, indicators: indicators.length, alerts: alerts.length },
        openAlerts: alerts.filter((a) => ALERT_OPEN.has(a.status))
          .sort((a, b) => PRIORITIES.indexOf(b.severity) - PRIORITIES.indexOf(a.severity) || a.createdAt.localeCompare(b.createdAt)),
        recentAnalyses: recent.length,
        byVerdict,
        perDay,
        openInvestigations: investigations.filter((i) => i.status !== "closed")
          .sort((a, b) => PRIORITIES.indexOf(b.priority) - PRIORITIES.indexOf(a.priority) || b.updatedAt.localeCompare(a.updatedAt)),
        indicatorsByType: Object.fromEntries(INDICATOR_TYPES.map((t) => [t, indicators.filter((i) => i.type === t).length])),
        topFindings: Object.entries(indicatorCounts).sort((a, b) => b[1] - a[1]).slice(0, 6),
        hasDemo: [...analyses, ...investigations, ...indicators, ...alerts].some((r) => r.demo),
        recent: [...analyses].sort((a, b) => b.createdAt.localeCompare(a.createdAt)).slice(0, 8),
      };
    },
    severityForVerdict: (level) => VERDICT_SEVERITY[level],

    // ------------------------------------------------------------ maintenance
    /** Records that fail the shape check: [{store, id}] (id as text, for display). */
    async damaged() {
      const out = [];
      for (const s of STORES) {
        for (const r of await store.list(s)) if (!isIntact(s, r)) out.push({ store: s, id: String(r?.id ?? "(no id)"), key: r?.id });
      }
      return out.map(({ store: s, id }) => ({ store: s, id }));
    },
    async removeDamaged() {
      const ops = [];
      for (const s of STORES) {
        for (const r of await store.list(s)) if (!isIntact(s, r) && r?.id !== undefined) ops.push({ type: "delete", store: s, id: r.id });
      }
      if (!ops.length) return 0;
      const n = ops.length;
      ops.push({ type: "put", store: "activity", record: { id: newId(), at: ts(), kind: "workspace.repaired", ref: null, summary: `Removed ${n} damaged record${n === 1 ? "" : "s"}` } });
      await store.commit(ops);
      return n;
    },
    removeDemoData: () => atomic(async (u) => {
      // Through the same staging as the delete methods, so links from the
      // analyst's own records to demo records are cleaned up too.
      for (const r of await u.list("alerts")) if (r.demo) u.del("alerts", r.id);
      for (const r of await u.list("analyses")) if (r.demo) await stageDeleteAnalysis(u, r.id);
      for (const r of await u.list("investigations")) if (r.demo) await stageDeleteInvestigation(u, r.id);
      for (const r of await u.list("indicators")) if (r.demo) await stageDeleteIndicator(u, r.id);
      u.log("workspace.demo-removed", null, "Removed demo records");
    }),
    async clearAll() {
      await store.clear();
    },
    /** Run fn(store) in the same queue as every other change (used by restore). */
    exclusive: (fn) => fn(store),
  };

  // Changes are read-modify-write, so they run one at a time: two quick
  // edits (or a restore during an edit) can no longer overwrite each other.
  let tail = Promise.resolve();
  const serial = (fn) => (...args) => {
    const run = tail.then(() => fn(...args));
    tail = run.catch(() => {});
    return run;
  };
  const ws = { ...api };
  for (const k of MUTATIONS) ws[k] = serial(api[k]);
  return ws;
}

/** One page of a sorted list: { items, total, offset }. Past the end (after deleting the last page), the last page. */
function pageOf(all, offset, limit) {
  const last = Math.max(0, Math.floor((all.length - 1) / limit) * limit);
  const start = Math.min(Math.max(0, offset), last);
  return { items: all.slice(start, start + limit), total: all.length, offset: start };
}

const median = (xs) => {
  if (!xs.length) return null;
  const s = [...xs].sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
};
const ALERT_OPEN = new Set(["new", "triage"]);
const VERDICT_LABEL = Object.fromEntries(Object.entries(VERDICTS).map(([k, v]) => [k, v.label.toLowerCase()]));

const STIX_INDICATOR_ID = /^indicator--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const STORES_FOR_OVERVIEW = ["analyses", "investigations", "indicators", "alerts"];
const MUTATIONS = ["saveAnalysis", "saveAnalyses", "deleteAnalysis", "deleteAnalyses", "createInvestigation", "updateInvestigation",
  "addNote", "deleteNote", "linkAnalysis", "unlinkAnalysis", "deleteInvestigation", "upsertIndicator", "upsertIndicators",
  "updateIndicator", "deleteIndicator", "applyPlaybook", "addTask", "setTaskDone", "deleteTask", "queueAlerts", "triageAlerts", "setAlertSeverity", "closeAlerts", "reopenAlert",
  "escalateAlert", "deleteAlerts", "createRule", "setRuleEnabled", "deleteRule", "removeDamaged", "removeDemoData", "clearAll", "exclusive"];

function hostOf(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}
