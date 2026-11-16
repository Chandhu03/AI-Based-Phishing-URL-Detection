// Workspace domain logic: analyses, investigations, indicators and the
// activity log. Pure business rules over a storage adapter (stores.js), so
// every rule is unit-tested without a browser.

import { defang, refang } from "../engine/defang.js";
import { STORES } from "./stores.js";

export const INVESTIGATION_STATUSES = Object.freeze(["open", "investigating", "contained", "closed"]);
export const PRIORITIES = Object.freeze(["low", "medium", "high", "critical"]);
export const INDICATOR_TYPES = Object.freeze(["url", "domain", "hostname", "ipv4", "ipv6"]);
export const CONFIDENCE = Object.freeze(["low", "medium", "high"]);
export const LIMITS = Object.freeze({ title: 200, summary: 4000, note: 10000, tag: 40, tags: 20, value: 2048 });

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
      // Same rules as the analyser: no whitespace or invisible format
      // characters (bidi, zero-width), http(s) only; stored as the browser's
      // canonical form (IDN hosts in punycode).
      if (!/^https?:\/\//i.test(v) || /[\s\p{Cc}\p{Cf}]/u.test(v)) return null;
      try {
        const href = new URL(v).href;
        return href.length <= LIMITS.value ? href : null;
      } catch {
        return null;
      }
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
export const VERDICT_LEVELS = Object.freeze(Object.keys(VERDICT_SEVERITY));

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
    && Array.isArray(r.history) && r.history.every((h) => isObj(h) && isStr(h.at) && isStr(h.action) && isStr(h.detail)),
  indicators: (r) => isStr(r.id) && INDICATOR_TYPES.includes(r.type) && isStr(r.value) && r.id === `${r.type}:${r.value}`
    && CONFIDENCE.includes(r.confidence) && strs(r.tags) && strs(r.sources) && strs(r.analysisIds) && strs(r.investigationIds)
    && isStr(r.firstSeen) && isStr(r.lastSeen) && Number.isFinite(r.sightings) && isStr(r.stixId) && isStr(r.note ?? ""),
  activity: (r) => isStr(r.id) && isStr(r.at) && isStr(r.kind) && isStr(r.summary),
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
  }
  async function stageDeleteInvestigation(u, id) {
    u.del("investigations", id);
    for (const ind of await u.list("indicators")) {
      if (!ind.investigationIds.includes(id)) continue;
      ind.investigationIds = ind.investigationIds.filter((x) => x !== id);
      u.put("indicators", ind);
    }
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
      if (limit === undefined) return all;
      // Past the end (for example after deleting the last page): show the last page.
      const last = Math.max(0, Math.floor((all.length - 1) / limit) * limit);
      const start = Math.min(Math.max(0, offset), last);
      return { items: all.slice(start, start + limit), total: all.length, offset: start };
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
    createInvestigation({ title, summary = "", priority = "medium", tags = [], demo = false }) {
      const t = clean(title, LIMITS.title);
      if (!t) return Promise.reject(new WorkspaceError("an investigation needs a title"));
      if (!PRIORITIES.includes(priority)) return Promise.reject(new WorkspaceError("unknown priority"));
      const at = ts();
      const record = {
        id: newId(), title: t, summary: clean(summary, LIMITS.summary), status: "open", priority, tags: normalizeTags(tags),
        notes: [], analysisIds: [], indicatorIds: [], demo, createdAt: at, updatedAt: at,
        history: [{ at, action: "created", detail: `Opened with ${priority} priority` }],
      };
      return atomic((u) => {
        u.put("investigations", record);
        u.log("investigation.created", { type: "investigation", id: record.id }, `Opened “${t}”`);
        return record;
      });
    },
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
    deleteNote: (id, noteId) => atomic(async (u) => {
      const inv = await u.must("investigations", id);
      inv.notes = inv.notes.filter((n) => n.id !== noteId);
      inv.history.push({ at: ts(), action: "note-removed", detail: "A note was removed" });
      return u.put("investigations", inv);
    }),
    linkAnalysis: (id, analysisId) => atomic(async (u) => {
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
    }),
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

    // ------------------------------------------------------------ overview
    async activity(limit = 20) {
      return (await intactList("activity")).sort((a, b) => b.at.localeCompare(a.at)).slice(0, limit);
    },
    async overview({ days = 30 } = {}) {
      const since = new Date(now().getTime() - days * 864e5).toISOString();
      const [analyses, investigations, indicators] = await Promise.all(STORES_FOR_OVERVIEW.map(intactList));
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
        totals: { analyses: analyses.length, investigations: investigations.length, indicators: indicators.length },
        recentAnalyses: recent.length,
        byVerdict,
        perDay,
        openInvestigations: investigations.filter((i) => i.status !== "closed")
          .sort((a, b) => PRIORITIES.indexOf(b.priority) - PRIORITIES.indexOf(a.priority) || b.updatedAt.localeCompare(a.updatedAt)),
        indicatorsByType: Object.fromEntries(INDICATOR_TYPES.map((t) => [t, indicators.filter((i) => i.type === t).length])),
        topFindings: Object.entries(indicatorCounts).sort((a, b) => b[1] - a[1]).slice(0, 6),
        hasDemo: [...analyses, ...investigations, ...indicators].some((r) => r.demo),
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

const STIX_INDICATOR_ID = /^indicator--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const STORES_FOR_OVERVIEW = ["analyses", "investigations", "indicators"];
const MUTATIONS = ["saveAnalysis", "saveAnalyses", "deleteAnalysis", "deleteAnalyses", "createInvestigation", "updateInvestigation",
  "addNote", "deleteNote", "linkAnalysis", "unlinkAnalysis", "deleteInvestigation", "upsertIndicator", "upsertIndicators",
  "updateIndicator", "deleteIndicator", "removeDamaged", "removeDemoData", "clearAll", "exclusive"];

export function hostOf(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}
