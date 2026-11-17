// Import and export: workspace backups, indicator lists (CSV, STIX 2.1,
// plain text) and Markdown reports. Imports are treated as untrusted input:
// size-capped, schema-checked and re-validated record by record.

import { defang, refang } from "../engine/defang.js";
import { LIMITS as VERDICT_LIMITS } from "../engine/verdict.js";
import { playbookById } from "./playbooks.js";
import { STORES } from "./stores.js";
import { ALERT_STATUSES, classifyIndicator, RULE_DISPOSITIONS, RULE_FIELDS, CONFIDENCE, DISPOSITIONS, INDICATOR_TYPES, INVESTIGATION_STATUSES, isIntact, LIMITS, MAX_IMPORT_BYTES, normalizeIndicator, normalizeTags, PRIORITIES } from "./workspace.js";

// Loaded on demand by the UI (import, export and reports only).
export { classifyIndicator, MAX_IMPORT_BYTES };

export const BACKUP_FORMAT = "securemind.workspace/1";

export class ImportError extends Error {}

// ------------------------------------------------------------ backups
/**
 * Analyses are exported without their report: restore re-runs the engine on
 * the stored input anyway, and reports make up about 90% of a backup's size.
 */
export async function exportBackup(store, now = new Date()) {
  const records = {};
  for (const s of STORES) records[s] = await store.list(s);
  records.analyses = records.analyses.map(({ report, ...rest }) => ({ ...rest, input: rest.input ?? report?.input ?? rest.url }));
  return { format: BACKUP_FORMAT, exportedAt: now.toISOString(), records };
}

const MAX_IMPORT_RECORDS = 20000;
const MAX_IMPORT_ANALYSES = 10000;
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;
const ID_RE = /^[\w-]{1,100}$/;
const ID = { test: (v) => typeof v === "string" && ID_RE.test(v) };
const STIX_ID = /^indicator--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

const str = (v, max) => (typeof v === "string" ? v.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "").slice(0, max) : "");
const iso = (v) => (typeof v === "string" && ISO.test(v) && !Number.isNaN(Date.parse(v)) ? v : null);
const ids = (v, re = ID_RE, max = 1000) => (Array.isArray(v) ? [...new Set(v.filter((x) => typeof x === "string" && re.test(x)))].slice(0, max) : []);
const INDICATOR_ID = /^(url|domain|hostname|ipv4|ipv6):.{1,2048}$/s;

/**
 * Rebuild one record per store from untrusted backup data. Nothing is copied
 * through unchecked: analyses are re-analysed from their URL by the current
 * engine, so a backup cannot carry a forged verdict or report.
 */
const REBUILD = {
  analyses(r, analyze) {
    const createdAt = iso(r.createdAt);
    // Older backups have no `input`; their cleaned-up url is the best available.
    const source = typeof r.input === "string" ? r.input : r.url;
    if (!ID.test(r.id) || !createdAt || typeof source !== "string") return null;
    const report = analyze(source, createdAt);
    if (!report?.ok) return null;
    return {
      id: r.id, createdAt, demo: r.demo === true, url: report.url, input: report.input, host: report.facts.host,
      registrableDomain: report.facts.registrableDomain, verdict: report.verdict.level,
      indicatorCount: report.indicators.filter((i) => i.severity !== "info").length,
      probability: report.model?.probability ?? null, report,
    };
  },
  investigations(r) {
    const createdAt = iso(r.createdAt);
    const updatedAt = iso(r.updatedAt) ?? createdAt;
    const title = str(r.title, 200).trim();
    if (!ID.test(r.id) || !createdAt || !title || !INVESTIGATION_STATUSES.includes(r.status) || !PRIORITIES.includes(r.priority)) return null;
    const notes = (Array.isArray(r.notes) ? r.notes : []).slice(0, 2000)
      .map((n) => ({ id: str(n?.id, 100), at: iso(n?.at), body: str(n?.body, 10000) }))
      .filter((n, i, all) => ID.test(n.id) && n.at && n.body.trim() && all.findIndex((m) => m.id === n.id) === i);
    const history = (Array.isArray(r.history) ? r.history : []).slice(0, 5000)
      .map((h) => ({ at: iso(h?.at), action: str(h?.action, 40), detail: str(h?.detail, 300) }))
      .filter((h) => h.at && HISTORY_ACTIONS.has(h.action));
    // Checklist steps: over-long or malformed steps are dropped, never cut.
    const tasks = (Array.isArray(r.tasks) ? r.tasks : []).slice(0, LIMITS.tasks)
      .filter((t, i, all) => t && ID.test(t.id) && typeof t.text === "string" && t.text.trim() && t.text.length <= LIMITS.task
        && typeof t.done === "boolean" && all.findIndex((x) => x?.id === t.id) === i)
      .map((t) => ({
        id: t.id, text: str(t.text, LIMITS.task).trim(), done: t.done, doneAt: t.done ? iso(t.doneAt) : null,
        playbook: playbookById(t.playbook) ? t.playbook : null,
      }));
    return {
      id: r.id, title, summary: str(r.summary, 4000), status: r.status, priority: r.priority, tags: normalizeTags(Array.isArray(r.tags) ? r.tags.filter((t) => typeof t === "string") : []),
      notes, tasks, history, analysisIds: ids(r.analysisIds), indicatorIds: ids(r.indicatorIds, INDICATOR_ID),
      demo: r.demo === true, createdAt, updatedAt,
    };
  },
  indicators(r) {
    if (!INDICATOR_TYPES.includes(r.type)) return null;
    const value = normalizeIndicator(r.type, typeof r.value === "string" ? r.value : "");
    const firstSeen = iso(r.firstSeen);
    const lastSeen = iso(r.lastSeen) ?? firstSeen;
    if (!value || r.id !== `${r.type}:${value}` || !firstSeen) return null;
    const sightings = Number.isInteger(r.sightings) && r.sightings > 0 ? Math.min(r.sightings, 1e6) : 1;
    return {
      id: r.id, type: r.type, value, stixId: STIX_ID.test(r.stixId) ? r.stixId : `indicator--${crypto.randomUUID()}`,
      confidence: CONFIDENCE.includes(r.confidence) ? r.confidence : "medium",
      tags: normalizeTags(Array.isArray(r.tags) ? r.tags.filter((t) => typeof t === "string") : []),
      sources: (Array.isArray(r.sources) ? r.sources : []).map((x) => str(x, 120)).filter(Boolean).slice(0, 50),
      analysisIds: ids(r.analysisIds), investigationIds: ids(r.investigationIds), note: str(r.note, 10000),
      firstSeen, lastSeen, sightings, demo: r.demo === true,
    };
  },
  /**
   * Queue rules act without an analyst, so a backup could carry one that
   * silently closes alerts. They are restored switched off and validated like
   * new rules; the shared-domain guard applies when one is switched on.
   */
  rules(r) {
    const createdAt = iso(r.createdAt);
    const name = typeof r.name === "string" && r.name.trim().length <= LIMITS.ruleName ? str(r.name, LIMITS.ruleName).trim() : "";
    const m = r.match;
    const a = r.action;
    if (!ID.test(r.id) || !createdAt || !name || !m || !RULE_FIELDS.includes(m.field) || typeof m.value !== "string") return null;
    const value = m.field === "source" ? (m.value.length <= LIMITS.source ? str(m.value, LIMITS.source).trim() : "") : normalizeIndicator(m.field === "host" ? "hostname" : m.field, m.value);
    if (!value) return null;
    const action = a?.type === "close" && RULE_DISPOSITIONS.includes(a.disposition) ? { type: "close", disposition: a.disposition }
      : a?.type === "severity" && PRIORITIES.includes(a.severity) ? { type: "severity", severity: a.severity } : null;
    if (!action) return null;
    return {
      id: r.id, name, enabled: false, match: { field: m.field, value }, action, createdAt, updatedAt: iso(r.updatedAt) ?? createdAt,
      hits: Number.isInteger(r.hits) && r.hits >= 0 ? Math.min(r.hits, 1e9) : 0, lastHitAt: iso(r.lastHitAt),
    };
  },
  /** The link is re-analysed, so a backup cannot set an alert's verdict or host. Links to other records are checked on import. */
  alerts(r, analyze) {
    const createdAt = iso(r.createdAt);
    if (!ID.test(r.id) || !createdAt || typeof r.url !== "string" || !ALERT_STATUSES.includes(r.status) || !PRIORITIES.includes(r.severity)) return null;
    const report = analyze(r.url, createdAt);
    if (!report?.ok || report.url !== r.url) return null;
    const closed = r.status === "closed";
    const closedAt = closed ? iso(r.closedAt) : null;
    if (closed && (!DISPOSITIONS.includes(r.disposition) || !closedAt)) return null;
    // Over-long fields reject the record; they are never cut.
    const field = (v, max) => (typeof v === "string" && v.length <= max ? str(v, max).trim() : null);
    const [source, externalId, reporter] = [field(r.source, LIMITS.source), field(r.externalId ?? "", LIMITS.externalId), field(r.reporter ?? "", LIMITS.reporter)];
    if (!source || externalId === null || reporter === null) return null;
    return {
      id: r.id, createdAt, updatedAt: iso(r.updatedAt) ?? createdAt, lastSeen: iso(r.lastSeen) ?? createdAt,
      occurrences: Number.isInteger(r.occurrences) && r.occurrences > 0 ? Math.min(r.occurrences, 1e6) : 1, demo: r.demo === true,
      url: report.url, host: report.facts.host, registrableDomain: report.facts.registrableDomain, verdict: report.verdict.level,
      analysisId: ID.test(r.analysisId) ? r.analysisId : null, severity: r.severity, status: r.status,
      disposition: closed ? r.disposition : null, investigationId: ID.test(r.investigationId) ? r.investigationId : null,
      triagedAt: iso(r.triagedAt), closedAt, closedByRule: closed && ID.test(r.closedByRule) ? r.closedByRule : null, source, externalId, reporter,
      history: (Array.isArray(r.history) ? r.history : []).slice(0, 5000)
        .map((h) => ({ at: iso(h?.at), action: str(h?.action, 40), detail: str(h?.detail, ALERT_HISTORY_DETAIL) }))
        .filter((h) => h.at && ALERT_HISTORY_ACTIONS.has(h.action)),
    };
  },
};
const HISTORY_ACTIONS = new Set(["created", "renamed", "summary", "status", "priority", "tags", "note", "note-removed", "linked", "unlinked", "indicator", "alert", "playbook", "task"]);
const ALERT_HISTORY_ACTIONS = new Set(["created", "repeat", "triage", "severity", "closed", "reopened", "escalated", "unlinked", "rule"]);
// The longest detail written: a close with a 1,000-character comment.
const ALERT_HISTORY_DETAIL = 1100;

/**
 * Parse and validate a backup. `analyze(url, isoDate)` re-runs the engine on
 * every imported analysis. Throws ImportError with a reason the user can act on.
 * @returns {{records: Record<string, object[]>, rejected: number}}
 */
export function parseBackup(text, analyze) {
  const steps = parseSteps(text, analyze);
  for (;;) {
    const { done, value } = steps.next();
    if (done) return value;
  }
}

/**
 * The same as parseBackup, but yields to the page between chunks of
 * re-analysis and reports progress, so a large restore never freezes the tab.
 * @param {(done: number, total: number, store: string) => void} [onProgress]
 */
export async function parseBackupInChunks(text, analyze, onProgress = () => {}) {
  const steps = parseSteps(text, analyze);
  for (;;) {
    const { done, value } = steps.next();
    if (done) return value;
    onProgress(value.done, value.total, value.store);
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
}

const CHUNK = 250;

function* parseSteps(text, analyze) {
  if (text.length > MAX_IMPORT_BYTES) throw new ImportError("The file is larger than 5 MB.");
  let data;
  try {
    data = JSON.parse(text.replace(/^\uFEFF/, ""));
  } catch {
    throw new ImportError("The file is not valid JSON.");
  }
  if (data?.format !== BACKUP_FORMAT || !data.records || typeof data.records !== "object" || Array.isArray(data.records)) {
    throw new ImportError("This is not a SecureMind workspace backup.");
  }
  const records = {};
  let rejected = 0;
  let total = 0;
  for (const s of STORES) {
    // The activity log is not restored: its entries are free text a file could
    // forge. Restoring adds one entry of its own instead.
    if (s === "activity") {
      records[s] = [];
      continue;
    }
    const list = data.records[s] ?? [];
    if (!Array.isArray(list)) throw new ImportError(`The “${s}” section is malformed.`);
    total += list.length;
    if (total > MAX_IMPORT_RECORDS) throw new ImportError(`The backup holds more than ${MAX_IMPORT_RECORDS.toLocaleString("en-US")} records.`);
    // Every analysis is stored with its full report (a few KB each).
    if (s === "analyses" && list.length > MAX_IMPORT_ANALYSES) {
      throw new ImportError(`The backup holds ${list.length.toLocaleString("en-US")} analyses; one restore accepts up to ${MAX_IMPORT_ANALYSES.toLocaleString("en-US")}.`);
    }
    records[s] = [];
    for (const [i, r] of list.entries()) {
      const rebuilt = r && typeof r === "object" ? REBUILD[s](r, analyze) : null;
      if (rebuilt) records[s].push(rebuilt);
      else rejected++;
      // Analyses and alerts are re-analysed: yield between chunks of either.
      if ((s === "analyses" || s === "alerts") && (i + 1) % CHUNK === 0 && i + 1 < list.length) yield { store: s, done: i + 1, total: list.length };
    }
  }
  return { records, rejected };
}

/**
 * Merge a parsed backup in one transaction: either every new record lands or
 * none does. Records with new ids are added; intact existing records are never
 * overwritten, while a damaged record with the same id is replaced by the
 * backup's valid copy. Links are kept only when their target exists after the
 * restore, so a backup cannot leave dangling references.
 */
export async function importBackup(store, parsed, now = new Date()) {
  const counts = { added: 0, skipped: 0, repaired: 0, rejected: parsed.rejected };
  const add = {};
  const known = {};
  const intactNow = {};
  for (const s of STORES) {
    const current = new Map((await store.list(s)).map((r) => [r?.id, r]));
    intactNow[s] = [...current.values()].filter((r) => isIntact(s, r));
    const seen = new Set();
    add[s] = [];
    for (const record of parsed.records[s]) {
      const old = current.get(record.id);
      if (seen.has(record.id) || (old && isIntact(s, old))) {
        counts.skipped++;
        continue;
      }
      if (old) counts.repaired++;
      seen.add(record.id);
      add[s].push(record);
    }
    known[s] = new Set([...[...current.entries()].filter(([, r]) => isIntact(s, r)).map(([id]) => id), ...seen]);
  }
  const keep = (list, s) => list.filter((id) => known[s].has(id));
  // An investigation-indicator link is kept only when both records state it,
  // in this workspace or in the backup (the backup's copy counts even when an
  // intact copy is already here and is not replaced).
  const pairs = (side) => {
    const out = new Set();
    for (const r of [...intactNow[side], ...parsed.records[side]]) {
      for (const other of side === "investigations" ? r.indicatorIds : r.investigationIds) {
        out.add(side === "investigations" ? `${r.id}\u0000${other}` : `${other}\u0000${r.id}`);
      }
    }
    return out;
  };
  const fromCases = pairs("investigations");
  const fromIndicators = pairs("indicators");
  const agreed = (invId, indId) => fromCases.has(`${invId}\u0000${indId}`) && fromIndicators.has(`${invId}\u0000${indId}`);
  for (const inv of add.investigations) {
    inv.analysisIds = keep(inv.analysisIds, "analyses");
    inv.indicatorIds = keep(inv.indicatorIds, "indicators").filter((id) => agreed(inv.id, id));
  }
  for (const ind of add.indicators) {
    ind.analysisIds = keep(ind.analysisIds, "analyses");
    ind.investigationIds = keep(ind.investigationIds, "investigations").filter((id) => agreed(id, ind.id));
  }
  for (const al of add.alerts) {
    if (al.analysisId && !known.analyses.has(al.analysisId)) al.analysisId = null;
    if (al.investigationId && !known.investigations.has(al.investigationId)) al.investigationId = null;
    // Escalated to a case that is not here: back to triage, as when a case is deleted.
    if (al.status === "escalated" && !al.investigationId) al.status = "triage";
  }
  // An intact record already here gains the back-link of an agreed link to a
  // restored record (appended; nothing else in it changes).
  const linkedBack = new Map();
  const backLink = (side, id, field, otherId) => {
    const existing = intactNow[side].find((r) => r.id === id);
    if (!existing || existing[field].includes(otherId)) return;
    const copy = linkedBack.get(`${side}\u0000${id}`) ?? { ...existing, [field]: [...existing[field]] };
    copy[field].push(otherId);
    linkedBack.set(`${side}\u0000${id}`, copy);
  };
  for (const inv of add.investigations) for (const id of inv.indicatorIds) backLink("indicators", id, "investigationIds", inv.id);
  for (const ind of add.indicators) for (const id of ind.investigationIds) backLink("investigations", id, "indicatorIds", ind.id);
  const ops = STORES.flatMap((s) => add[s].map((record) => ({ type: "put", store: s, record })));
  counts.added = ops.length - counts.repaired;
  for (const [k, record] of linkedBack) ops.push({ type: "put", store: k.split("\u0000")[0], record });
  ops.push({
    type: "put", store: "activity",
    record: {
      id: `restore-${now.getTime()}`, at: now.toISOString(), kind: "backup.restored", ref: null,
      summary: `Backup restored: ${counts.added} added, ${counts.repaired} repaired, ${counts.skipped} already present, ${counts.rejected} rejected`,
    },
  });
  await store.commit(ops);
  return counts;
}

// ------------------------------------------------------------ alert intake
export const MAX_ALERT_IMPORT = 500;
const ALERT_COLUMNS = { url: ["url", "link"], source: ["source"], externalId: ["external_id", "externalid", "ref", "id"], reporter: ["reporter", "reported_by"] };

/**
 * Parse links to queue as alerts: a JSON array (or {alerts: [...]}) of
 * objects or strings, CSV with a url column, or plain text with one link per
 * line. Each item is {input, source, externalId, reporter}; the UI analyses
 * the links (never fetching them) before queueing. A row with a field over
 * its limit is rejected, never truncated.
 * @returns {{items: object[], rejected: number, format: string}}
 */
export function parseAlertFile(text) {
  if (text.length > MAX_IMPORT_BYTES) throw new ImportError("The file is larger than 5 MB.");
  const trimmed = text.replace(/^﻿/, "").trim();
  let rows;
  let format;
  if (trimmed.startsWith("[") || trimmed.startsWith("{")) {
    let data;
    try {
      data = JSON.parse(trimmed);
    } catch {
      throw new ImportError("The file looks like JSON but cannot be parsed.");
    }
    const list = Array.isArray(data) ? data : data?.alerts;
    if (!Array.isArray(list)) throw new ImportError("A JSON alert file holds an array, or an object with an “alerts” array.");
    const field = (o, names) => {
      const key = Object.keys(o).find((k) => names.includes(k.toLowerCase()));
      // Ticket ids are often numbers.
      return key === undefined ? undefined : Number.isFinite(o[key]) ? String(o[key]) : o[key];
    };
    rows = list.map((o) => (typeof o === "string" ? { url: o }
      : o && typeof o === "object" && !Array.isArray(o) ? Object.fromEntries(Object.entries(ALERT_COLUMNS).map(([f, names]) => [f, field(o, names)]))
        : null));
    format = "JSON";
  } else {
    const lines = trimmed.split(/\r?\n/).filter((l) => l.trim());
    const header = lines.length ? parseCsvLine(lines[0]).map((h) => h.trim().toLowerCase()) : [];
    const col = Object.fromEntries(Object.entries(ALERT_COLUMNS).map(([f, names]) => [f, header.findIndex((h) => names.includes(h))]));
    if (col.url !== -1) {
      rows = lines.slice(1).map((line) => {
        const cells = parseCsvLine(line);
        // Undo the formula guard this app's own CSV exports add.
        return Object.fromEntries(Object.entries(col).map(([f, i]) => [f, i === -1 ? "" : (cells[i] ?? "").replace(/^'(?=[=+\-@])/, "")]));
      });
      format = "CSV";
    } else {
      rows = lines.map((l) => ({ url: l }));
      format = "text";
    }
  }
  if (rows.length > MAX_ALERT_IMPORT) {
    throw new ImportError(`The file holds ${rows.length.toLocaleString("en-US")} alerts; the limit per import is ${MAX_ALERT_IMPORT}. Split the file.`);
  }
  const fits = (v, max) => v === undefined || v === null || (typeof v === "string" && v.trim().length <= max);
  const items = [];
  let rejected = 0;
  for (const r of rows) {
    if (!r || typeof r.url !== "string" || !r.url.trim() || !fits(r.source, LIMITS.source) || !fits(r.externalId, LIMITS.externalId) || !fits(r.reporter, LIMITS.reporter)) {
      rejected++;
      continue;
    }
    items.push({ input: r.url.trim(), source: r.source?.trim() ?? "", externalId: r.externalId?.trim() ?? "", reporter: r.reporter?.trim() ?? "" });
  }
  return { items, rejected, format };
}

// ------------------------------------------------------------ indicators
// A cell is a formula when it starts with one of these, after any spaces.
const FORMULA_START = /^\s*[=+\-@\t\r]/;

/**
 * Neutralise spreadsheet formulas (CSV injection) and quote per RFC 4180.
 * Cells containing ";" or a tab are quoted too: spreadsheets in locales that
 * separate fields with ";" would otherwise split them, and a part such as
 * "=1+1" would start a new, unguarded cell.
 */
export function csvCell(value) {
  let s = String(value ?? "");
  if (FORMULA_START.test(s)) s = `'${s}`;
  return /[",;\t\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export function indicatorsToCsv(indicators, { defanged = false } = {}) {
  const head = ["type", "value", "confidence", "tags", "first_seen", "last_seen", "sightings", "sources"];
  // Joined lists are guarded item by item: "x;=HYPERLINK(...)" is a formula
  // in spreadsheets that use ";" as their separator.
  const list = (xs) => xs.map((x) => (FORMULA_START.test(x) ? `'${x}` : x)).join(";");
  const rows = indicators.map((i) => [i.type, defanged ? defang(i.value) : i.value, i.confidence, list(i.tags), i.firstSeen, i.lastSeen, i.sightings, list(i.sources)]);
  return [head, ...rows].map((r) => r.map(csvCell).join(",")).join("\r\n") + "\r\n";
}

const STIX_PATTERN = { url: "url:value", domain: "domain-name:value", hostname: "domain-name:value", ipv4: "ipv4-addr:value", ipv6: "ipv6-addr:value" };
const STIX_CONFIDENCE = { low: 15, medium: 50, high: 85 };

// STIX has one cyber-observable for both a registrable domain and a host
// name (domain-name). The workspace type travels in a custom property, which
// STIX 2.1 allows with an "x_" prefix; other tools ignore it.
const STIX_TYPE_PROPERTY = "x_securemind_indicator_type";

export function indicatorsToStix(indicators, now = new Date()) {
  const created = now.toISOString();
  return {
    type: "bundle",
    id: `bundle--${crypto.randomUUID()}`,
    objects: indicators.map((i) => ({
      type: "indicator",
      spec_version: "2.1",
      id: i.stixId,
      created: i.firstSeen,
      // `modified` may not precede `created`.
      modified: created > i.firstSeen ? created : i.firstSeen,
      name: `${i.type} ${defang(i.value)}`,
      pattern: `[${STIX_PATTERN[i.type]} = '${i.value.replace(/\\/g, "\\\\").replace(/'/g, "\\'")}']`,
      pattern_type: "stix",
      valid_from: i.firstSeen,
      confidence: STIX_CONFIDENCE[i.confidence],
      ...(i.tags.length ? { labels: i.tags } : {}),
      ...(i.note ? { description: i.note } : {}),
      [STIX_TYPE_PROPERTY]: i.type,
    })),
  };
}


/**
 * Parse an indicator file: STIX 2.1 bundle (JSON), CSV with a type,value
 * header, or plain text with one value per line.
 * @returns {{items: Array<{type,value,confidence,tags}>, rejected: number, format: string}}
 */
const MAX_INDICATOR_IMPORT = 5000;

export function parseIndicatorFile(text) {
  if (text.length > MAX_IMPORT_BYTES) throw new ImportError("The file is larger than 5 MB.");
  const result = parseIndicatorText(text);
  if (result.items.length > MAX_INDICATOR_IMPORT) {
    throw new ImportError(`The file holds ${result.items.length.toLocaleString("en-US")} indicators; the limit per import is ${MAX_INDICATOR_IMPORT.toLocaleString("en-US")}. Split the file.`);
  }
  return result;
}

function parseIndicatorText(text) {
  // Spreadsheet programs often start CSV files with a byte-order mark.
  const trimmed = text.replace(/^\uFEFF/, "").trim();
  const items = [];
  let rejected = 0;
  if (trimmed.startsWith("{")) {
    let bundle;
    try {
      bundle = JSON.parse(trimmed);
    } catch {
      throw new ImportError("The file looks like JSON but cannot be parsed.");
    }
    if (bundle?.type !== "bundle" || !Array.isArray(bundle.objects)) throw new ImportError("Only STIX 2.1 bundles are supported for JSON.");
    for (const o of bundle.objects) {
      if (o?.type !== "indicator") continue;
      const m = /^\[(url|domain-name|ipv4-addr|ipv6-addr):value\s*=\s*'((?:[^'\\]|\\.)*)'\]$/.exec(typeof o.pattern === "string" ? o.pattern.trim() : "");
      let type = m && { url: "url", "domain-name": "domain", "ipv4-addr": "ipv4", "ipv6-addr": "ipv6" }[m[1]];
      if (type === "domain" && o[STIX_TYPE_PROPERTY] === "hostname") type = "hostname";
      const value = m && normalizeIndicator(type, m[2].replace(/\\(.)/g, "$1"));
      if (!value) {
        rejected++;
        continue;
      }
      const c = Number(o.confidence);
      // No confidence in the object means unknown: medium, as for CSV and text imports.
      const confidence = o.confidence === undefined ? "medium" : c >= 70 ? "high" : c >= 30 ? "medium" : "low";
      const tags = normalizeTags(Array.isArray(o.labels) ? o.labels.filter((t) => typeof t === "string") : []);
      items.push({
        type, value, confidence, tags,
        ...(STIX_ID.test(o.id) ? { stixId: o.id } : {}),
        ...(typeof o.description === "string" && o.description.trim() ? { note: str(o.description, 10000) } : {}),
      });
    }
    return { items, rejected, format: "STIX 2.1" };
  }
  const lines = trimmed.split(/\r?\n/).filter((l) => l.trim());
  const header = lines[0]?.toLowerCase().split(",").map((h) => h.trim());
  if (header?.includes("type") && header.includes("value")) {
    const [ti, vi, ci, gi] = ["type", "value", "confidence", "tags"].map((h) => header.indexOf(h));
    for (const line of lines.slice(1)) {
      const cells = parseCsvLine(line);
      const type = cells[ti]?.trim();
      const value = INDICATOR_TYPES.includes(type) && normalizeIndicator(type, refang(cells[vi]?.replace(/^'/, "") ?? ""));
      if (!value) {
        rejected++;
        continue;
      }
      const confidence = CONFIDENCE.includes(cells[ci]) ? cells[ci] : "medium";
      items.push({ type, value, confidence, tags: normalizeTags((cells[gi] ?? "").split(";")) });
    }
    return { items, rejected, format: "CSV" };
  }
  for (const line of lines) {
    const hit = classifyIndicator(line.trim());
    if (hit) items.push({ ...hit, confidence: "medium", tags: [] });
    else rejected++;
  }
  return { items, rejected, format: "text" };
}

function parseCsvLine(line) {
  const out = [];
  let cur = "";
  let quoted = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quoted) {
      if (c === '"' && line[i + 1] === '"') (cur += '"'), i++;
      else if (c === '"') quoted = false;
      else cur += c;
    } else if (c === '"') quoted = true;
    else if (c === ",") out.push(cur), (cur = "");
    else cur += c;
  }
  out.push(cur);
  return out;
}

// ------------------------------------------------------------ reports
const oneLine = (s) => String(s ?? "").replace(/[\r\n\u2028\u2029]+/g, " ");
/**
 * Defang host names and IPv4 addresses inside prose so chat tools do not
 * auto-link them: a dot between a letter or digit and a label of two or more
 * characters, or between IPv4 octets, becomes "[.]". Linear time: the earlier
 * host-matching pattern backtracked quadratically on long dotted text.
 */
export const defangText = (s) => String(s ?? "")
  .replace(/\b(h)tt(ps?):\/\//gi, "$1xx$2://")
  .replace(/\bftp:\/\//gi, "fxp://")
  .replace(/([\p{L}\p{N}-])\.(?=xn--|\p{L}[\p{L}\p{N}-]*[\p{L}\p{N}])/gu, "$1[.]")
  .replace(/\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g, "$1[.]$2[.]$3[.]$4");
const md = (s) => defangText(oneLine(s).replace(/([\\`*_[\]<>#|])/g, "\\$1"));
const code = (s) => `\`${defangText(oneLine(s)).replace(/`/g, "ˋ")}\``;

export function analysisToMarkdown(report) {
  const lines = [
    `# URL analysis: ${report.verdict.label}`,
    "",
    `- URL (defanged): ${code(defang(report.url))}`,
    `- Registrable domain: ${code(defang(report.facts.registrableDomain ?? report.facts.host))}`,
    `- Analysed: ${report.analyzedAt} with engine ${report.engine.version}${report.engine.modelId ? `, model ${report.engine.modelId}` : ""}`,
    `- Model estimate: ${report.model ? `${(report.model.probability * 100).toFixed(1)}% (band: ${report.verdict.band})` : SKIP_REASON[report.modelSkipped] ?? "not available"}`,
    "",
    "## Why",
    ...report.verdict.reasons.map((r) => `- ${md(r)}`),
    "",
    "## Indicators",
    ...(report.indicators.length
      ? report.indicators.map((i) => `- **${i.severity}** · ${md(i.title)} — ${md(i.detail)} (evidence: ${code(i.evidence)})`)
      : ["- None found in the link text."]),
    "",
    "## Limits",
    ...VERDICT_LIMITS.map((l) => `- ${l}`),
    "",
  ];
  return lines.join("\n");
}

const VERDICT_ORDER = ["high-risk", "suspicious", "inconclusive", "no-strong-indicators"];
const SKIP_REASON = { "ip-address": "not used (IP address)", "nonstandard-idn": "not used (characters outside IDNA2008)" };
// Inside a GFM table a "|" ends the cell even within a code span.
const cell = (s) => s.replace(/\|/g, "\\|");

/**
 * A self-contained case report: summary, every linked analysis with its
 * evidence, the indicator table, notes, history, and how the analyses were
 * made. Every host and URL is defanged and analyst text is escaped.
 */
export function investigationToMarkdown(inv, analyses, indicators, now = new Date()) {
  const byVerdict = VERDICT_ORDER.map((v) => [v, analyses.filter((a) => a.verdict === v)]).filter(([, list]) => list.length);
  const engines = [...new Set(analyses.map((a) => `${a.report.engine.version}${a.report.engine.modelId ? `, model ${a.report.engine.modelId}` : ", no model"}, Public Suffix List ${String(a.report.engine.pslCommit).slice(0, 10)}`))];
  const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;
  return [
    `# Investigation: ${md(inv.title)}`,
    "",
    `- Status: ${inv.status} · Priority: ${inv.priority}`,
    `- Opened: ${inv.createdAt} · Last updated: ${inv.updatedAt}`,
    inv.tags.length ? `- Tags: ${inv.tags.map(md).join(", ")}` : "- Tags: none",
    `- Contents: ${plural(analyses.length, "analysis", "analyses")}, ${plural(indicators.length, "indicator", "indicators")}, ${plural(inv.notes.length, "note", "notes")}`,
    `- Report generated: ${now.toISOString()}`,
    "",
    "## Summary",
    md(inv.summary) || "_No summary._",
    "",
    "## Findings at a glance",
    ...(byVerdict.length
      ? byVerdict.map(([v, list]) => `- ${list[0].report.verdict.label}: ${list.length}`)
      : ["- No analyses linked."]),
    "",
    "## Analyses",
    ...(analyses.length ? analyses.flatMap((a, i) => {
      const r = a.report;
      const findings = r.indicators.filter((x) => x.severity !== "info");
      return [
        `### ${i + 1}. ${r.verdict.label}: ${code(defang(a.url))}`,
        "",
        `- Registrable domain: ${code(defang(a.registrableDomain ?? a.host))}`,
        `- Analysed: ${r.analyzedAt}`,
        `- Model estimate: ${r.model ? `${(r.model.probability * 100).toFixed(1)}% (band: ${r.verdict.band})` : SKIP_REASON[r.modelSkipped] ?? "not available"}`,
        `- Why: ${r.verdict.reasons.map(md).join("; ") || "—"}`,
        ...(findings.length ? ["- Indicators:", ...findings.map((x) => `  - **${x.severity}** · ${md(x.title)} (evidence: ${code(x.evidence)})`)] : ["- Indicators: none in the link text"]),
        "",
      ];
    }) : ["- None linked.", ""]),
    "## Indicators",
    ...(indicators.length ? [
      "| Type | Value (defanged) | Confidence | Sightings | First seen | Last seen | Tags |",
      "| --- | --- | --- | --- | --- | --- | --- |",
      ...indicators.map((x) => `| ${x.type} | ${cell(code(defang(x.value)))} | ${x.confidence} | ${x.sightings} | ${x.firstSeen} | ${x.lastSeen} | ${x.tags.map(md).join(", ") || "—"} |`),
    ] : ["- None recorded."]),
    "",
    "## Response checklist",
    ...((inv.tasks ?? []).length
      ? [`${inv.tasks.filter((t) => t.done).length} of ${inv.tasks.length} steps done.`, "", ...inv.tasks.map((t) => `- [${t.done ? "x" : " "}] ${md(t.text)}${t.done && t.doneAt ? ` (done ${t.doneAt})` : ""}`)]
      : ["_No checklist._"]),
    "",
    "## Notes",
    ...(inv.notes.length ? inv.notes.flatMap((n) => [`### ${n.at}`, "", md(n.body), ""]) : ["_No notes._", ""]),
    "## History",
    ...inv.history.map((h) => `- ${h.at} — ${md(h.action)}: ${md(h.detail)}`),
    "",
    "## Method and limits",
    ...(engines.length ? engines.map((e) => `- Analysed with engine ${e}.`) : []),
    ...VERDICT_LIMITS.map((l) => `- ${l}`),
    "",
    "_Generated by SecureMind Labs from a local workspace. Indicator values are defanged._",
    "",
  ].join("\n");
}

/**
 * A reported-email triage report: sender and authentication facts, findings,
 * every link with its verdict, and attachments (never opened). Addresses,
 * hosts and links are defanged; message text is escaped.
 * @param {object} email   parseEmail() result
 * @param {Array<{link: object, report: object}>} links  each extracted link with its analysis (report.ok false when rejected)
 */
export function emailToMarkdown(email, links, now = new Date()) {
  const addr = (a) => (a?.address ? `${a.name ? `${md(a.name)} ` : ""}${code(defang(a.address))}` : "—");
  const auth = email.auth ? ["spf", "dkim", "dmarc"].map((k) => `${k.toUpperCase()} ${email.auth[k] ?? "absent"}`).join(" · ") : "no Authentication-Results header";
  return [
    `# Reported email: ${md(email.subject || "(no subject)")}`,
    "",
    `- From: ${addr(email.from)}`,
    `- Reply-To: ${email.replyTo.length ? email.replyTo.map(addr).join(", ") : "—"}`,
    `- Return-Path: ${addr(email.returnPath)}`,
    `- Date: ${md(email.date || "—")}`,
    `- Message-ID: ${email.messageId ? code(email.messageId) : "—"}`,
    `- Authentication: ${auth}${email.auth ? ` (added by ${code(email.auth.server || "an unnamed server")}; trust it only if that is your own mail server)` : ""}`,
    `- Received hops: ${email.received}`,
    ...(email.wrapper ? [`- Reported by: ${addr(email.wrapper.from)} (forwarded as an attachment)`] : []),
    `- Report generated: ${now.toISOString()}`,
    "",
    "## Findings",
    ...(email.findings.length ? email.findings.map((f) => `- **${f.severity}** · ${md(f.title)} — ${md(f.detail)}${f.evidence ? ` (evidence: ${code(f.evidence)})` : ""}`) : ["- None."]),
    "",
    "## Links",
    ...(links.length ? [
      "| Verdict | Link (defanged) | Link text |",
      "| --- | --- | --- |",
      ...links.map(({ link, report }) => `| ${report.ok ? report.verdict.label : "Rejected"} | ${cell(code(defang(report.ok ? report.url : link.url)))} | ${cell(md(link.text || "—"))} |`),
    ] : ["- None found."]),
    "",
    "## Attachments (not opened)",
    ...(email.attachments.length ? email.attachments.map((a) => `- ${code(a.filename)} · ${md(a.contentType)} · ${a.size.toLocaleString("en-US")} ${a.size === 1 ? "byte" : "bytes"}`) : ["- None."]),
    "",
    "## Method and limits",
    "- The message was read as text in the browser: HTML was not rendered, remote content was not loaded, attachments were not opened and links were not visited.",
    "- Authentication results are copied from the receiving server's header; they are only as trustworthy as that server.",
    ...VERDICT_LIMITS.map((l) => `- ${l}`),
    "",
    "_Generated by SecureMind Labs. Links and addresses are defanged._",
    "",
  ].join("\n");
}
