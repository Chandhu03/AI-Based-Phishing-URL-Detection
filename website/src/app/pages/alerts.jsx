import { useEffect, useRef, useState } from "preact/hooks";
import { defang } from "../../engine/defang.js";
import { VERDICTS } from "../../engine/verdict.js";
import { duration } from "../../workspace/format.js";
import { PLAYBOOKS } from "../../workspace/playbooks.js";
import { ALERT_STATUSES, DISPOSITIONS, PRIORITIES } from "../../workspace/workspace.js";
import { Dialog, Empty, IndicatorList, PageHeader, Specimen, Time, Verdict } from "../components.jsx";
import { useAction, useApp, useData } from "../context.js";
import { download, stamp } from "../download.js";
import { navigate } from "../router.js";

const PAGE_SIZE = 25;
export const ALERT_STATUS_LABEL = { new: "New", triage: "In triage", escalated: "Escalated", closed: "Closed" };
const DISPOSITION_LABEL = { "true-positive": "True positive", benign: "Benign (expected activity)", "false-positive": "False positive", duplicate: "Duplicate" };
const HISTORY_LABEL = {
  created: "Queued", repeat: "Repeat", triage: "Triage", severity: "Severity", closed: "Closed",
  reopened: "Reopened", escalated: "Escalated", unlinked: "Unlinked", rule: "Rule",
};
const cap = (s) => s[0].toUpperCase() + s.slice(1);
const io = () => import("../../workspace/io.js");
const focusTitle = () => document.querySelector("[data-page-title]")?.focus();


// Filters and page survive a visit to an alert and back within the session.
let remembered = { status: "open", severity: "", query: "", offset: 0 };

/** The alert queue: intake, filters, bulk triage and closing, and queue health. */
export function Alerts() {
  const { ws } = useApp();
  const act = useAction();
  const [status, setStatus] = useState(remembered.status);
  const [severity, setSeverity] = useState(remembered.severity);
  const [query, setQuery] = useState(remembered.query);
  const [offset, setOffset] = useState(remembered.offset);
  const [selected, setSelected] = useState(() => new Set());
  const [disposition, setDisposition] = useState("");
  const [intake, setIntake] = useState(false);
  const statusLine = useRef(null);
  const { data } = useData(() => ws.listAlerts({ status: status || undefined, severity: severity || undefined, query, offset, limit: PAGE_SIZE }), [status, severity, query, offset]);
  const { data: m } = useData(() => ws.alertMetrics({ days: 30 }));

  useEffect(() => { remembered = { status, severity, query, offset: data?.offset ?? offset }; }, [status, severity, query, offset, data]);

  const filter = (set) => (e) => {
    set(e.currentTarget.value);
    setOffset(0);
    setSelected(new Set());
  };
  const page = data?.items ?? [];
  const total = data?.total ?? 0;
  const start = data?.offset ?? 0;
  const allOnPage = page.length > 0 && page.every((a) => selected.has(a.id));
  const toggle = (id) => setSelected((s) => {
    const next = new Set(s);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    return next;
  });
  async function bulk(fn, success) {
    if (await act(fn, success) !== undefined) {
      setSelected(new Set());
      statusLine.current?.focus();
    }
  }
  const ids = [...selected];
  const filtered = Boolean(query || severity || status !== "open");

  return (
    <>
      <PageHeader title="Alert queue" description="Links reported for review. Triage each one: close it with a disposition, or escalate it to an investigation. Links are analysed here and never opened.">
        <a class="btn btn-secondary" href="#/alerts/rules">Queue rules</a>
        <button type="button" class="btn btn-quiet" disabled={!total} onClick={async () => {
          const all = await ws.listAlerts({ status: status || undefined, severity: severity || undefined, query });
          download(`alerts-${stamp()}.csv`, (await io()).alertsToCsv(all), "text/csv");
        }}>Export CSV</button>
        <button type="button" class="btn btn-primary" onClick={() => setIntake(true)}>Add alerts</button>
      </PageHeader>

      {m && (
        <section class="panel" aria-labelledby="qm-title">
          <h2 id="qm-title" class="section-title">Queue health, last {m.days} days</h2>
          <dl class="kpis">
            <div><dt>Open</dt><dd>{m.open}</dd></div>
            <div><dt>Open, high or critical</dt><dd>{m.openBySeverity.high + m.openBySeverity.critical}</dd></div>
            <div><dt>Oldest open</dt><dd>{m.oldestOpen ? <Time iso={m.oldestOpen} /> : "—"}</dd></div>
            <div><dt>Median time to triage</dt><dd>{duration(m.timeToTriage)}</dd></div>
            <div><dt>Median time to close</dt><dd>{duration(m.timeToClose)}</dd></div>
            <div><dt>Closed by analysts</dt><dd>{m.closedRecent}</dd></div>
            <div><dt>Closed by rules</dt><dd>{m.closedByRule}</dd></div>
            <div><dt>False positives</dt><dd>{m.falsePositiveRate == null ? "—" : `${Math.round(m.falsePositiveRate * 100)}%`}</dd></div>
          </dl>
        </section>
      )}

      <div class="filters" role="search">
        <label class="field"><span class="field-label">Search</span>
          <input spellcheck={false} class="input input-mono" type="search" value={query} onInput={filter(setQuery)} placeholder="Link, source, reporter or reference" />
        </label>
        <label class="field"><span class="field-label">Status</span>
          <select class="select" value={status} onChange={filter(setStatus)}>
            <option value="open">Open (new and in triage)</option>
            {ALERT_STATUSES.map((s) => <option key={s} value={s}>{ALERT_STATUS_LABEL[s]}</option>)}
            <option value="">Any status</option>
          </select>
        </label>
        <label class="field"><span class="field-label">Severity</span>
          <select class="select" value={severity} onChange={filter(setSeverity)}>
            <option value="">Any severity</option>
            {[...PRIORITIES].reverse().map((p) => <option key={p} value={p}>{cap(p)}</option>)}
          </select>
        </label>
      </div>

      {data && total === 0 ? (
        <Empty title={filtered ? "No alerts match these filters." : m?.total ? "No open alerts." : "The queue is empty."}>
          <p>{filtered ? "Clear the search or choose another status." : m?.total ? "Everything has been triaged. Choose another status to see escalated or closed alerts." : "Add reported links with “Add alerts”: paste them, or import a CSV, JSON or text file."}</p>
        </Empty>
      ) : (
        <section class="panel" aria-label="Alerts">
          <div class="panel-head list-head">
            <p id="alert-status" class="list-status" tabIndex={-1} ref={statusLine} aria-live="polite">
              {data ? `Showing ${start + 1}–${start + page.length} of ${total.toLocaleString("en-US")}` : "Loading…"}
              {selected.size > 0 && ` · ${selected.size} selected`}
            </p>
            <div class="row">
              <label class="check-all">
                <input type="checkbox" checked={allOnPage} disabled={!page.length} onChange={() => setSelected((sel) => {
                  const next = new Set(sel);
                  for (const a of page) allOnPage ? next.delete(a.id) : next.add(a.id);
                  return next;
                })} /> Select page
              </label>
              <button type="button" class="btn btn-secondary btn-sm" disabled={!selected.size} onClick={() => bulk(() => ws.triageAlerts(ids), "Triage started.")}>Start triage</button>
              <label class="visually-hidden" for="bulk-disposition">Disposition</label>
              <select id="bulk-disposition" class="select" value={disposition} onChange={(e) => setDisposition(e.currentTarget.value)}>
                <option value="">Close as…</option>
                {DISPOSITIONS.map((d) => <option key={d} value={d}>{DISPOSITION_LABEL[d]}</option>)}
              </select>
              <button type="button" class="btn btn-secondary btn-sm" disabled={!selected.size || !disposition}
                onClick={() => bulk(() => ws.closeAlerts(ids, { disposition }), "Alerts closed.")}>Close selected</button>
            </div>
          </div>
          <div class="table-wrap">
            <table class="table table-select table-cards">
              <caption class="visually-hidden">Alerts</caption>
              <thead>
                <tr>
                  <th scope="col" class="cell-check"><span class="visually-hidden">Selected</span></th>
                  <th scope="col">Severity</th><th scope="col">Link (defanged)</th><th scope="col">Verdict</th><th scope="col">Source</th><th scope="col">Seen</th><th scope="col">Queued</th><th scope="col">Status</th>
                </tr>
              </thead>
              <tbody>
                {page.map((a) => (
                  <tr key={a.id} class={selected.has(a.id) ? "is-selected" : undefined}>
                    <td class="cell-check"><input type="checkbox" checked={selected.has(a.id)} onChange={() => toggle(a.id)} aria-label={`Select the alert for ${defang(a.host)}`} /></td>
                    <td><span class="prio" data-prio={a.severity}>{a.severity}</span></td>
                    <td class="mono cell-url"><a href={`#/alerts/${a.id}`}>{defang(a.url)}</a> {a.demo && <span class="demo-flag">Demo</span>}</td>
                    <td><Verdict level={a.verdict} label={VERDICTS[a.verdict].label} /></td>
                    <td data-label="Source">{a.source}</td>
                    <td class="num" data-label="Seen">{a.occurrences}×</td>
                    <td class="muted" data-label="Queued"><Time iso={a.createdAt} /></td>
                    <td data-label="Status">{ALERT_STATUS_LABEL[a.status]}{a.disposition && <span class="muted"> · {DISPOSITION_LABEL[a.disposition]}</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {total > PAGE_SIZE && (
            <nav class="pager" aria-label="Pages">
              <button type="button" class="btn btn-secondary btn-sm" disabled={start === 0} onClick={() => { setOffset(Math.max(0, start - PAGE_SIZE)); statusLine.current?.focus(); }}>Previous</button>
              <span class="muted">Page {Math.floor(start / PAGE_SIZE) + 1} of {Math.ceil(total / PAGE_SIZE)}</span>
              <button type="button" class="btn btn-secondary btn-sm" disabled={start + PAGE_SIZE >= total} onClick={() => { setOffset(start + PAGE_SIZE); statusLine.current?.focus(); }}>Next</button>
            </nav>
          )}
        </section>
      )}

      <Dialog open={intake} title="Add alerts" onClose={() => setIntake(false)}>
        <AlertIntake onDone={() => { setIntake(false); statusLine.current?.focus(); }} />
      </Dialog>
    </>
  );
}

/** Paste or import reported links; each is analysed locally, then queued in one transaction. */
function AlertIntake({ onDone }) {
  const { ws, engine, toast } = useApp();
  const act = useAction();
  const [form, setForm] = useState({ links: "", source: "user-report", reporter: "" });
  const [busy, setBusy] = useState(false);
  const set = (k) => (e) => setForm({ ...form, [k]: e.currentTarget.value });

  async function queue(text) {
    if (busy) return;
    setBusy(true);
    try {
      const { parseAlertFile } = await io();
      let parsed;
      try {
        parsed = parseAlertFile(text);
      } catch (err) {
        toast(err.message, "error");
        return;
      }
      let rejected = parsed.rejected;
      const items = [];
      for (const it of parsed.items) {
        const report = engine.analyze(it.input);
        if (!report.ok) {
          rejected++;
          continue;
        }
        items.push({ report, source: it.source || form.source.trim() || "manual", externalId: it.externalId, reporter: it.reporter || form.reporter.trim() });
      }
      if (!items.length) {
        toast(`No valid links found${rejected ? `; ${rejected} rejected` : ""}.`, "error");
        return;
      }
      const result = await act(() => ws.queueAlerts(items));
      if (!result) return;
      toast(`${result.created.length} queued${result.merged ? `, ${result.merged} seen again` : ""}${result.closedByRule ? `, ${result.closedByRule} closed by queue rules` : ""}${rejected ? `, ${rejected} rejected` : ""}.`);
      onDone();
    } finally {
      setBusy(false);
    }
  }

  return (
    <form class="stack" onSubmit={(e) => { e.preventDefault(); queue(form.links); }}>
      <label class="field"><span class="field-label">Reported links, one per line</span>
        <textarea spellcheck={false} class="textarea input-mono" rows={6} value={form.links} onInput={set("links")} placeholder={"hxxps://login.example[.]com/verify\nhttps://second.example/"} />
      </label>
      <p class="field-hint">Defanged links are accepted. You can also paste CSV with a url column (source, external_id and reporter are optional) or a JSON array.</p>
      <div class="form-row">
        <label class="field"><span class="field-label">Source</span><input spellcheck={false} class="input" maxLength={60} value={form.source} onInput={set("source")} /></label>
        <label class="field"><span class="field-label">Reported by (optional)</span><input spellcheck={false} class="input" maxLength={200} value={form.reporter} onInput={set("reporter")} /></label>
      </div>
      <div class="row">
        <button class="btn btn-primary" type="submit" disabled={!engine.ready || busy || !form.links.trim()}>{busy ? "Queueing…" : "Queue alerts"}</button>
        <label class="btn btn-secondary file-btn">Import file<input type="file" name="alert-file" accept=".txt,.csv,.json,text/plain,text/csv,application/json" disabled={!engine.ready || busy}
          onChange={async (e) => {
            const file = e.currentTarget.files?.[0];
            e.currentTarget.value = "";
            if (file) await queue(await file.text());
          }} /></label>
      </div>
    </form>
  );
}

export function AlertDetail({ id }) {
  const { ws } = useApp();
  const act = useAction();
  const { data, loading } = useData(async () => {
    const alert = await ws.getAlert(id).catch(() => null);
    if (!alert) return null;
    const [analysis, investigation, cases, next] = await Promise.all([
      alert.analysisId ? ws.getAnalysis(alert.analysisId).catch(() => null) : null,
      alert.investigationId ? ws.getInvestigation(alert.investigationId).catch(() => null) : null,
      ws.listInvestigations(),
      ws.nextOpenAlert(alert.id),
    ]);
    return { alert, analysis, investigation, cases: cases.filter((c) => c.status !== "closed"), next };
  }, [id]);
  const [disposition, setDisposition] = useState("");
  const [comment, setComment] = useState("");
  const [target, setTarget] = useState("");
  const [playbook, setPlaybook] = useState("");

  if (loading && !data) return <PageHeader title="Alert" />;
  if (!data) return <PageHeader title="Alert not found" description="It may have been deleted from this workspace." />;
  const { alert: a, analysis, investigation, cases, next } = data;
  const run = async (fn, success) => {
    const done = await act(fn, success);
    if (done !== undefined) focusTitle(); // the button that ran it may be gone now
    return done;
  };

  return (
    <>
      <PageHeader title={`Alert: ${defang(a.host)}`} description={`${ALERT_STATUS_LABEL[a.status]}${a.disposition ? ` as ${DISPOSITION_LABEL[a.disposition].toLowerCase()}` : ""}. Queued from ${a.source}${a.reporter ? `, reported by ${a.reporter}` : ""}.`}>
        <button type="button" class="btn btn-danger btn-sm" onClick={async () => {
          if (confirm("Delete this alert? Its analysis and any investigation are kept.") && await act(() => ws.deleteAlerts([a.id]), "Alert deleted.")) navigate("/alerts");
        }}>Delete</button>
      </PageHeader>

      <div class="case-bar">
        <div class="field field-inline">
          <label class="field-label" for="alert-severity">Severity</label>
          <select id="alert-severity" class="select" value={a.severity} onChange={(e) => act(() => ws.setAlertSeverity(a.id, e.currentTarget.value), "Severity updated.")}>
            {PRIORITIES.map((p) => <option key={p} value={p}>{cap(p)}</option>)}
          </select>
        </div>
        <span>{ALERT_STATUS_LABEL[a.status]}</span>
        {a.externalId && <span class="muted small">Ref <code>{a.externalId}</code></span>}
        <span class="muted small">Seen {a.occurrences}× · first <Time iso={a.createdAt} />, last <Time iso={a.lastSeen} /></span>
        <span class="spacer" />
        {next ? <a class="btn btn-secondary btn-sm" href={`#/alerts/${next.id}`}>Next open alert<span class="visually-hidden">: {defang(next.host)}</span></a>
          : <span class="muted small">No other open alerts</span>}
        {a.demo && <span class="demo-flag">Demo</span>}
      </div>

      <div class="case-grid">
        <div class="stack">
          <section class="panel" aria-labelledby="aa-title">
            <h2 id="aa-title" class="section-title">Decide</h2>
            <div class="stack">
            {a.status === "new" && (
              <div class="row"><button type="button" class="btn btn-secondary" onClick={() => run(() => ws.triageAlerts([a.id]), "Triage started.")}>Start triage</button></div>
            )}
            {a.status === "closed" ? (
              <div class="row"><button type="button" class="btn btn-secondary" onClick={() => run(() => ws.reopenAlert(a.id), "Alert reopened.")}>Reopen</button></div>
            ) : (
              <>
                <form class="stack" onSubmit={async (e) => {
                  e.preventDefault();
                  if (await run(() => ws.closeAlerts([a.id], { disposition, comment }), "Alert closed.")) setComment("");
                }}>
                  <div class="form-row">
                    <label class="field"><span class="field-label">Disposition</span>
                      <select class="select" required value={disposition} onChange={(e) => setDisposition(e.currentTarget.value)}>
                        <option value="">Choose…</option>
                        {DISPOSITIONS.map((d) => <option key={d} value={d}>{DISPOSITION_LABEL[d]}</option>)}
                      </select>
                    </label>
                  </div>
                  <label class="field"><span class="field-label">Comment (optional)</span>
                    <textarea spellcheck={false} class="textarea" maxLength={1000} value={comment} onInput={(e) => setComment(e.currentTarget.value)} />
                  </label>
                  <div class="row"><button class="btn btn-primary" type="submit" disabled={!disposition}>Close alert</button></div>
                </form>
                <form class="stack" onSubmit={async (e) => {
                  e.preventDefault();
                  const r = await act(() => ws.escalateAlert(a.id, { investigationId: target || null, playbookId: playbook || null }), "Alert escalated.");
                  if (r) navigate(`/investigations/${r.investigation.id}`);
                }}>
                  <label class="field"><span class="field-label">Escalate to</span>
                    <select class="select" value={target} onChange={(e) => setTarget(e.currentTarget.value)}>
                      <option value="">A new investigation ({a.severity} priority)</option>
                      {cases.map((c) => <option key={c.id} value={c.id}>{c.title}</option>)}
                    </select>
                  </label>
                  <label class="field"><span class="field-label">Playbook (optional)</span>
                    <select class="select" value={playbook} onChange={(e) => setPlaybook(e.currentTarget.value)}>
                      <option value="">None</option>
                      {PLAYBOOKS.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
                    </select>
                  </label>
                  <div class="row"><button class="btn btn-secondary" type="submit">Escalate</button></div>
                </form>
              </>
            )}
            {investigation && <p>Investigation: <a href={`#/investigations/${investigation.id}`}>{investigation.title}</a></p>}
            </div>
          </section>

          <section class="panel" aria-labelledby="an-title">
            <div class="panel-head">
              <h2 id="an-title" class="section-title">Analysis</h2>
              {analysis && <a href={`#/analyses/${analysis.id}`}>Full analysis</a>}
            </div>
            {analysis ? (
              <>
                <p><Verdict level={analysis.verdict} label={analysis.report.verdict.label} /></p>
                <Specimen segments={analysis.report.segments} large={false} />
                <IndicatorList indicators={analysis.report.indicators} />
              </>
            ) : (
              <p class="muted">The saved analysis was deleted. The link was <code>{defang(a.url)}</code>, judged {VERDICTS[a.verdict].label.toLowerCase()} when queued.</p>
            )}
          </section>
        </div>
        <section class="panel" aria-labelledby="ah-title">
          <h2 id="ah-title" class="section-title">History</h2>
          <ol class="timeline">
            {[...a.history].reverse().map((h, i) => <li key={i}><span><strong>{HISTORY_LABEL[h.action] ?? h.action} </strong>{h.detail}</span><Time iso={h.at} /></li>)}
          </ol>
        </section>
      </div>
    </>
  );
}
