import { useEffect, useRef, useState } from "preact/hooks";
import { defang } from "../../engine/defang.js";
import { VERDICTS } from "../../engine/verdict.js";
import { Empty, PageHeader, Time, Verdict } from "../components.jsx";
import { useAction, useApp, useData } from "../context.js";

const PAGE_SIZE = 25;

// Filters and page survive a visit to an analysis and back within the session.
let remembered = { query: "", verdict: "", offset: 0 };

/** Every saved analysis: search, filter by verdict, page through, delete. */
export function Analyses() {
  const { ws } = useApp();
  const act = useAction();
  const [query, setQuery] = useState(remembered.query);
  const [verdict, setVerdict] = useState(remembered.verdict);
  const [offset, setOffset] = useState(remembered.offset);
  const [selected, setSelected] = useState(() => new Set());
  const [deleting, setDeleting] = useState(false);
  const status = useRef(null);
  const search = useRef(null);
  const refocus = useRef(false);
  const { data } = useData(() => ws.listAnalyses({ query, verdict: verdict || undefined, offset, limit: PAGE_SIZE }), [query, verdict, offset]);

  useEffect(() => { remembered = { query, verdict, offset: data?.offset ?? offset }; }, [query, verdict, offset, data]);
  // After a delete, focus the list status, or the search field when nothing is left
  // (the status line is gone then, and focus would fall to the page body).
  useEffect(() => {
    if (!refocus.current || !data) return;
    refocus.current = false;
    (data.total ? status.current : search.current)?.focus();
  }, [data]);

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
  const go = (to) => {
    setOffset(to);
    status.current?.focus();
  };

  async function removeSelected() {
    if (deleting || !selected.size) return;
    const n = selected.size;
    if (!confirm(`Delete ${n} ${n === 1 ? "analysis" : "analyses"} from this workspace? Investigations that link to ${n === 1 ? "it" : "them"} will lose the link.`)) return;
    setDeleting(true);
    const done = await act(() => ws.deleteAnalyses([...selected]), `${n} ${n === 1 ? "analysis" : "analyses"} deleted.`);
    setDeleting(false);
    if (done !== undefined) {
      setSelected(new Set());
      refocus.current = true;
    }
  }

  const filtered = Boolean(query || verdict);
  return (
    <>
      <PageHeader title="Analyses" description="Every analysis saved in this browser, newest first. Search covers the link and its host.">
        <a class="btn btn-primary" href="#/analyze">Analyse links</a>
      </PageHeader>
      <div class="filters" role="search">
        <label class="field"><span class="field-label">Search</span>
          <input spellcheck={false} ref={search} class="input input-mono" type="search" value={query} onInput={filter(setQuery)} placeholder="login.example" />
        </label>
        <label class="field"><span class="field-label">Verdict</span>
          <select class="select" value={verdict} onChange={filter(setVerdict)}>
            <option value="">All verdicts</option>
            {Object.entries(VERDICTS).map(([v, { label }]) => <option key={v} value={v}>{label}</option>)}
          </select>
        </label>
      </div>
      {data && total === 0 ? (
        <Empty title={filtered ? "No analyses match these filters." : "No analyses saved yet."}>
          <p>{filtered ? "Clear the search or choose another verdict." : "Analyse a link and choose “Save to workspace”, or save a whole batch at once."}</p>
        </Empty>
      ) : (
        <section class="panel" aria-label="Saved analyses">
          <div class="panel-head list-head">
            <p id="list-status" class="list-status" tabIndex={-1} ref={status} aria-live="polite">
              {data ? `Showing ${start + 1}–${start + page.length} of ${total.toLocaleString("en-US")}` : "Loading…"}
              {selected.size > 0 && ` · ${selected.size} selected`}
            </p>
            <div class="row">
              {/* Outside the table, so it stays visible in the phone card layout. */}
              <label class="check-all">
                <input type="checkbox" checked={allOnPage} disabled={!page.length} onChange={() => setSelected((sel) => {
                  const next = new Set(sel);
                  for (const a of page) allOnPage ? next.delete(a.id) : next.add(a.id);
                  return next;
                })} /> Select page
              </label>
              {selected.size > 0 && <button type="button" class="btn btn-quiet btn-sm" onClick={() => setSelected(new Set())}>Clear selection</button>}
              <button type="button" class="btn btn-danger btn-sm" disabled={!selected.size} aria-disabled={deleting ? "true" : undefined} onClick={removeSelected}>
                {deleting ? "Deleting…" : "Delete selected"}
              </button>
            </div>
          </div>
          <div class="table-wrap">
            <table class="table table-select table-cards">
              <caption class="visually-hidden">Saved analyses</caption>
              <thead>
                <tr>
                  <th scope="col" class="cell-check"><span class="visually-hidden">Selected</span></th>
                  <th scope="col">Verdict</th><th scope="col">Link (defanged)</th><th scope="col">Indicators</th><th scope="col">Model</th><th scope="col">Saved</th>
                </tr>
              </thead>
              <tbody>
                {page.map((a) => (
                  <tr key={a.id} class={selected.has(a.id) ? "is-selected" : undefined}>
                    <td class="cell-check">
                      <input type="checkbox" checked={selected.has(a.id)} onChange={() => toggle(a.id)} aria-label={`Select the analysis of ${defang(a.host)}`} />
                    </td>
                    <td><Verdict level={a.verdict} label={a.report.verdict.label} /></td>
                    <td class="mono cell-url">
                      <a href={`#/analyses/${a.id}`}>{defang(a.url)}</a> {a.demo && <span class="demo-flag">Demo</span>}
                    </td>
                    <td class="num" data-label="Indicators">{a.indicatorCount}</td>
                    <td class="num" data-label="Model">{a.probability == null ? <span class="muted">Not scored</span> : `${(a.probability * 100).toFixed(0)}%`}</td>
                    <td class="muted" data-label="Saved"><Time iso={a.createdAt} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {total > PAGE_SIZE && (
            <nav class="pager" aria-label="Pages">
              <button type="button" class="btn btn-secondary btn-sm" disabled={start === 0} onClick={() => go(Math.max(0, start - PAGE_SIZE))}>Newer</button>
              <span class="muted">Page {Math.floor(start / PAGE_SIZE) + 1} of {Math.ceil(total / PAGE_SIZE)}</span>
              <button type="button" class="btn btn-secondary btn-sm" disabled={start + PAGE_SIZE >= total} onClick={() => go(start + PAGE_SIZE)}>Older</button>
            </nav>
          )}
        </section>
      )}
    </>
  );
}
