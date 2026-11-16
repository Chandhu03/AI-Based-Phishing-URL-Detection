import { useState } from "preact/hooks";
import { defang } from "../../engine/defang.js";
import { INVESTIGATION_STATUSES, PRIORITIES } from "../../workspace/workspace.js";
import { Dialog, Empty, PageHeader, Time, Verdict } from "../components.jsx";
import { useAction, useApp, useData } from "../context.js";
import { download, stamp } from "../download.js";
import { navigate } from "../router.js";

const STATUS_LABEL = { open: "Open", investigating: "Investigating", contained: "Contained", closed: "Closed" };

export function Investigations() {
  const { ws } = useApp();
  const [status, setStatus] = useState("");
  const [query, setQuery] = useState("");
  const [creating, setCreating] = useState(false);
  const { data: list = [] } = useData(() => ws.listInvestigations({ status: status || undefined, query: query || undefined }), [status, query]);

  return (
    <>
      <PageHeader title="Investigations" description="Cases group analyses, indicators and notes. They live in this browser; export a report to share one.">
        <button type="button" class="btn btn-primary" onClick={() => setCreating(true)}>New investigation</button>
      </PageHeader>
      <div class="filters" role="search">
        <label class="field">
          <span class="field-label">Search</span>
          <input spellcheck={false} class="input" type="search" value={query} placeholder="Title or summary" onInput={(e) => setQuery(e.currentTarget.value)} />
        </label>
        <label class="field">
          <span class="field-label">Status</span>
          <select aria-label="Status" class="select" value={status} onChange={(e) => setStatus(e.currentTarget.value)}>
            <option value="">Any status</option>
            {INVESTIGATION_STATUSES.map((s) => <option key={s} value={s}>{STATUS_LABEL[s]}</option>)}
          </select>
        </label>
      </div>
      {list.length === 0 ? (
        <Empty title={query || status ? "No investigations match these filters." : "No investigations yet."}>
          <p>Start one here, or from any analysis with “Add to investigation”.</p>
        </Empty>
      ) : (
        <div class="table-wrap">
          <table class="table">
            <thead><tr><th scope="col">Title</th><th scope="col">Priority</th><th scope="col">Status</th><th scope="col">Analyses</th><th scope="col">Indicators</th><th scope="col">Updated</th></tr></thead>
            <tbody>
              {list.map((c) => (
                <tr key={c.id}>
                  <td><a href={`#/investigations/${c.id}`}>{c.title}</a> {c.demo && <span class="demo-flag">Demo</span>}
                    {c.tags.length > 0 && <div class="tags">{c.tags.map((t) => <span key={t} class="tag">{t}</span>)}</div>}</td>
                  <td><span class="prio" data-prio={c.priority}>{c.priority}</span></td>
                  <td>{STATUS_LABEL[c.status]}</td>
                  <td class="num">{c.analysisIds.length}</td>
                  <td class="num">{c.indicatorIds.length}</td>
                  <td class="muted"><Time iso={c.updatedAt} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <Dialog open={creating} title="New investigation" onClose={() => setCreating(false)}>
        <InvestigationForm onDone={(inv) => { setCreating(false); if (inv) navigate(`/investigations/${inv.id}`); }} />
      </Dialog>
    </>
  );
}

const HISTORY_LABEL = {
  created: "", renamed: "Renamed", summary: "Summary", status: "Status", priority: "Priority", tags: "Tags",
  note: "Note", "note-removed": "Note removed", linked: "Linked", unlinked: "Unlinked", indicator: "Indicator",
};

function InvestigationForm({ onDone }) {
  const { ws } = useApp();
  const act = useAction();
  const [form, setForm] = useState({ title: "", summary: "", priority: "medium", tags: "" });
  const set = (k) => (e) => setForm({ ...form, [k]: e.currentTarget.value });
  return (
    <form class="stack" onSubmit={async (e) => {
      e.preventDefault();
      const inv = await act(() => ws.createInvestigation(form), "Investigation created.");
      if (inv) onDone(inv); // on failure keep the dialog and what was typed
    }}>
      <label class="field"><span class="field-label">Title</span><input spellcheck={false} class="input" required maxLength={200} value={form.title} onInput={set("title")} /></label>
      <label class="field"><span class="field-label">Summary</span><textarea spellcheck={false} class="textarea" maxLength={4000} value={form.summary} onInput={set("summary")} /></label>
      <div class="form-row">
        <label class="field"><span class="field-label">Priority</span>
          <select aria-label="Priority" class="select" value={form.priority} onChange={set("priority")}>{PRIORITIES.map((p) => <option key={p} value={p}>{p[0].toUpperCase() + p.slice(1)}</option>)}</select>
        </label>
        <label class="field"><span class="field-label">Tags</span><input spellcheck={false} class="input" value={form.tags} onInput={set("tags")} placeholder="comma, separated" /></label>
      </div>
      <div class="row"><button class="btn btn-primary" type="submit">Create investigation</button></div>
    </form>
  );
}

export function InvestigationDetail({ id }) {
  const { ws } = useApp();
  const act = useAction();
  const { data, loading } = useData(async () => {
    const inv = await ws.getInvestigation(id).catch(() => null);
    if (!inv) return null;
    const analyses = (await Promise.all(inv.analysisIds.map((a) => ws.getAnalysis(a).catch(() => null)))).filter(Boolean);
    const indicators = (await Promise.all(inv.indicatorIds.map((i) => ws.getIndicator(i).catch(() => null)))).filter(Boolean);
    return { inv, analyses, indicators };
  }, [id]);
  const [note, setNote] = useState("");
  const [editing, setEditing] = useState(false);

  if (loading && !data) return <PageHeader title="Investigation" />;
  if (!data) return <PageHeader title="Investigation not found" description="It may have been deleted from this workspace." />;
  const { inv, analyses, indicators } = data;

  return (
    <>
      <PageHeader title={inv.title} description={inv.summary || "No summary yet."}>
        <button type="button" class="btn btn-secondary btn-sm" onClick={() => setEditing(true)}>Edit</button>
        <button type="button" class="btn btn-quiet btn-sm" onClick={async () => download(`investigation-${stamp()}.md`, (await import("../../workspace/io.js")).investigationToMarkdown(inv, analyses, indicators), "text/markdown")}>Export report</button>
        <button type="button" class="btn btn-danger btn-sm" onClick={async () => {
          if (confirm(`Delete “${inv.title}”? Linked analyses and indicators are kept.`) && await act(() => ws.deleteInvestigation(inv.id).then(() => true), "Investigation deleted.")) navigate("/investigations");
        }}>Delete</button>
      </PageHeader>

      <div class="case-bar">
        <div class="field field-inline">
          <label class="field-label" for="case-status">Status</label>
          <select id="case-status" class="select" value={inv.status} onChange={(e) => act(() => ws.updateInvestigation(inv.id, { status: e.currentTarget.value }), "Status updated.")}>
            {INVESTIGATION_STATUSES.map((s) => <option key={s} value={s}>{STATUS_LABEL[s]}</option>)}
          </select>
        </div>
        <div class="field field-inline">
          <label class="field-label" for="case-priority">Priority</label>
          <select id="case-priority" class="select" value={inv.priority} onChange={(e) => act(() => ws.updateInvestigation(inv.id, { priority: e.currentTarget.value }), "Priority updated.")}>
            {PRIORITIES.map((p) => <option key={p} value={p}>{p[0].toUpperCase() + p.slice(1)}</option>)}
          </select>
        </div>
        <div class="tags">{inv.tags.map((t) => <span key={t} class="tag">{t}</span>)} {inv.demo && <span class="demo-flag">Demo</span>}</div>
        <span class="spacer" />
        <span class="muted small">Opened <Time iso={inv.createdAt} /></span>
      </div>

      <div class="case-grid">
        <div class="stack">
          <section class="panel" aria-labelledby="ca-title">
            <div class="panel-head"><h2 id="ca-title" class="section-title">Analyses <span class="count">{analyses.length}</span></h2><a href="#/analyze">Analyse a link</a></div>
            {analyses.length === 0 ? <p class="muted">Add analyses from any report with “Add to investigation”.</p> : (
              <ul class="list">
                {analyses.map((a) => (
                  <li key={a.id}>
                    <Verdict level={a.verdict} label={a.report.verdict.label} />
                    <a class="list-main mono" href={`#/analyses/${a.id}`}>{defang(a.url)}</a>
                    <button type="button" class="btn btn-quiet btn-sm" onClick={() => act(() => ws.unlinkAnalysis(inv.id, a.id), "Analysis removed from the investigation.")}>Remove<span class="visually-hidden"> analysis of {defang(a.host)} from this investigation</span></button>
                  </li>
                ))}
              </ul>
            )}
          </section>
          <section class="panel" aria-labelledby="ci-title">
            <div class="panel-head"><h2 id="ci-title" class="section-title">Indicators <span class="count">{indicators.length}</span></h2><a href="#/indicators">All indicators</a></div>
            {indicators.length === 0 ? <p class="muted">Record indicators from an analysis, or add them on the Indicators page.</p> : (
              <ul class="list">
                {indicators.map((i) => <li key={i.id}><span class="check-type">{i.type}</span><code class="list-main">{defang(i.value)}</code><span class="muted">{i.confidence}</span></li>)}
              </ul>
            )}
          </section>
          <section class="panel" aria-labelledby="cn-title">
            <h2 id="cn-title" class="section-title">Notes <span class="count">{inv.notes.length}</span></h2>
            <form class="stack" onSubmit={async (e) => {
              e.preventDefault();
              if (await act(() => ws.addNote(inv.id, note), "Note added.")) {
                setNote("");
                document.getElementById("note-input")?.focus(); // the submit button is now disabled
              }
            }}>
              <label class="field"><span class="visually-hidden">New note</span>
                <textarea id="note-input" spellcheck={false} class="textarea" value={note} maxLength={10000} placeholder="What did you find? Notes are plain text." onInput={(e) => setNote(e.currentTarget.value)} />
              </label>
              <div class="row"><button class="btn btn-secondary btn-sm" type="submit" disabled={!note.trim()}>Add note</button></div>
            </form>
            <ol class="notes">
              {[...inv.notes].reverse().map((n) => (
                <li key={n.id} class="note">
                  <div class="note-head"><Time iso={n.at} /><button type="button" class="btn btn-quiet btn-sm" onClick={() => { if (confirm("Delete this note? This cannot be undone.")) act(() => ws.deleteNote(inv.id, n.id), "Note deleted."); }}>Delete<span class="visually-hidden"> note</span></button></div>
                  <p class="note-body">{n.body}</p>
                </li>
              ))}
            </ol>
          </section>
        </div>
        <section class="panel" aria-labelledby="ch-title">
          <h2 id="ch-title" class="section-title">History</h2>
          <ol class="timeline">
            {[...inv.history].reverse().map((h, i) => <li key={i}><span>{(HISTORY_LABEL[h.action] ?? h.action) && <strong>{HISTORY_LABEL[h.action] ?? h.action} </strong>}{h.detail}</span><Time iso={h.at} /></li>)}
          </ol>
        </section>
      </div>

      <Dialog open={editing} title="Edit investigation" onClose={() => setEditing(false)}>
        <EditForm inv={inv} onDone={() => setEditing(false)} />
      </Dialog>
    </>
  );
}

function EditForm({ inv, onDone }) {
  const { ws } = useApp();
  const act = useAction();
  const [form, setForm] = useState({ title: inv.title, summary: inv.summary, tags: inv.tags.join(", ") });
  const set = (k) => (e) => setForm({ ...form, [k]: e.currentTarget.value });
  return (
    <form class="stack" onSubmit={async (e) => {
      e.preventDefault();
      if (await act(() => ws.updateInvestigation(inv.id, form), "Investigation updated.")) onDone();
    }}>
      <label class="field"><span class="field-label">Title</span><input spellcheck={false} class="input" required maxLength={200} value={form.title} onInput={set("title")} /></label>
      <label class="field"><span class="field-label">Summary</span><textarea spellcheck={false} class="textarea" maxLength={4000} value={form.summary} onInput={set("summary")} /></label>
      <label class="field"><span class="field-label">Tags</span><input spellcheck={false} class="input" value={form.tags} onInput={set("tags")} /></label>
      <div class="row"><button class="btn btn-primary" type="submit">Save changes</button></div>
    </form>
  );
}
