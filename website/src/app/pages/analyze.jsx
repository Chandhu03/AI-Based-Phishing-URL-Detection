import { useEffect, useRef, useState } from "preact/hooks";
import { splitBatch } from "../../engine/analyze.js";
import { defang, maskCredentials } from "../../engine/defang.js";
import { PageHeader, Verdict } from "../components.jsx";
import { useAction, useApp, useData } from "../context.js";
import { download, stamp } from "../download.js";
import { AnalysisReport } from "../report.jsx";
import { navigate } from "../router.js";

const EXAMPLES = [
  ["Brand in a subdomain", "http://paypal.com.secure-account.tk/login"],
  ["Look-alike letters", "https://xn--pple-43d.com/id"],
  ["Disguised IP", "http://3232235777/bank/login"],
  ["Ordinary link", "https://www.example.org/docs?page=2"],
];

// The current, unsaved analysis survives navigation within the session only.
let lastReport = null;
let lastSaved = null;

/** Single-URL form used on Overview and Analyze. */
export function QuickAnalyze({ onResult }) {
  const { engine } = useApp();
  const [value, setValue] = useState("");
  const [error, setError] = useState("");

  function run(raw) {
    const r = engine.analyze(raw);
    if (!r.ok) {
      setError(r.message);
      return;
    }
    setError("");
    lastReport = r;
    if (onResult) onResult(r);
    else navigate("/analyze");
  }

  return (
    <form class="qa" noValidate onSubmit={(e) => { e.preventDefault(); run(value); }}>
      <label class="visually-hidden" for="qa-input">Link to analyse</label>
      <div class="qa-row">
        <input id="qa-input" class="input input-mono" type="text" inputMode="url" autoComplete="off" autoCapitalize="off"
          spellcheck={false} maxLength={2049} placeholder="Paste a link, e.g. hxxps://login.example[.]com/verify"
          value={value} aria-invalid={error ? "true" : undefined} aria-describedby="qa-help qa-error"
          onInput={(e) => { setValue(e.currentTarget.value); if (error) setError(""); }} />
        <button class="btn btn-primary" type="submit" disabled={!engine.ready}>{engine.ready ? "Analyse" : "Loading engine…"}</button>
      </div>
      <p id="qa-help" class="field-hint">Defanged links are accepted. The link is analysed in this browser and never opened or sent.</p>
      <p id="qa-error" class="field-error" role="alert" hidden={!error}>{error}</p>
      <div class="chips" role="group" aria-label="Examples">
        {EXAMPLES.map(([label, url]) => (
          <button key={url} type="button" class="chip" disabled={!engine.ready} onClick={() => { setValue(url); run(url); }}>{label}</button>
        ))}
      </div>
    </form>
  );
}

export function Analyze() {
  const [mode, setMode] = useState("single");
  const [report, setReport] = useState(lastReport);
  const [saved, setSaved] = useState(lastSaved);
  const fresh = useRef(false);

  // Move focus to a new result so keyboard and screen-reader users land on it.
  useEffect(() => {
    if (!fresh.current) return;
    fresh.current = false;
    document.getElementById("report-verdict")?.focus();
  }, [report]);

  const onSaved = (rec) => { lastSaved = rec; setSaved(rec); };

  return (
    <>
      <PageHeader title="Analyse links" description="Parse a link the way a browser does, then check it for deception techniques. Nothing is fetched." />
      <div class="tabs" role="group" aria-label="Analysis mode">
        <button type="button" aria-pressed={mode === "single"} class="tab" onClick={() => setMode("single")}>One link</button>
        <button type="button" aria-pressed={mode === "batch"} class="tab" onClick={() => setMode("batch")}>Many links</button>
      </div>
      {mode === "single" ? (
        <div class="stack">
          <section class="panel"><QuickAnalyze onResult={(r) => { fresh.current = true; lastSaved = null; setReport(r); setSaved(null); }} /></section>
          {report && <AnalysisReport key={report.analyzedAt} report={report} saved={saved} onSaved={onSaved} />}
        </div>
      ) : (
        <Batch />
      )}
    </>
  );
}

const BATCH_LIMIT = 500;

function Batch() {
  const { engine, ws } = useApp();
  const act = useAction();
  const [text, setText] = useState("");
  const [rows, setRows] = useState(null);
  const [truncated, setTruncated] = useState(false);
  const [saveState, setSaveState] = useState("idle"); // idle | saving | saved
  const title = useRef(null);

  function run(e) {
    e.preventDefault();
    const { items, truncated: cut } = splitBatch(text, BATCH_LIMIT);
    setTruncated(cut);
    setSaveState("idle");
    setRows(items.map((raw) => ({ raw, r: engine.analyze(raw) })));
  }

  useEffect(() => { if (rows) title.current?.focus(); }, [rows]);

  async function saveAll() {
    if (saveState !== "idle" || !ok.length) return;
    setSaveState("saving");
    const done = await act(() => ws.saveAnalyses(ok.map((x) => x.r)), `${ok.length} ${ok.length === 1 ? "analysis" : "analyses"} saved.`);
    setSaveState(done ? "saved" : "idle");
  }

  const ok = rows?.filter((x) => x.r.ok) ?? [];
  const order = { "high-risk": 0, suspicious: 1, inconclusive: 2, "no-strong-indicators": 3 };
  const sorted = [...(rows ?? [])].sort((a, b) => (a.r.ok ? order[a.r.verdict.level] : 4) - (b.r.ok ? order[b.r.verdict.level] : 4));

  return (
    <div class="stack">
      <form class="panel stack" onSubmit={run}>
        <div class="field">
          <label class="field-label" for="batch-input">Links, one per line</label>
          <textarea id="batch-input" class="textarea input-mono" rows={8} value={text} spellcheck={false} aria-describedby="batch-help" maxLength={BATCH_LIMIT * 2100}
            onInput={(e) => setText(e.currentTarget.value)}
            placeholder={"https://example.com/login\nhxxp://paypal[.]com[.]secure-account[.]tk/"} />
          <span id="batch-help" class="field-hint">Up to {BATCH_LIMIT} links per run. Each is analysed locally; nothing is saved until you choose to.</span>
        </div>
        <div class="row"><button class="btn btn-primary" type="submit" disabled={!engine.ready || !text.trim()}>Analyse all</button></div>
      </form>
      {rows && (
        <section class="panel" aria-labelledby="batch-title">
          <div class="panel-head">
            <h2 id="batch-title" class="section-title" tabIndex={-1} ref={title}>{rows.length} {rows.length === 1 ? "link" : "links"} · {ok.length} analysed · {rows.length - ok.length} rejected</h2>
            <div class="row">
              <button type="button" class="btn btn-secondary btn-sm" aria-disabled={saveState !== "idle" || !ok.length ? "true" : undefined} onClick={saveAll}>
                {saveState === "saved" ? "Saved to workspace" : saveState === "saving" ? "Saving…" : "Save all to workspace"}
              </button>
              <button type="button" class="btn btn-quiet btn-sm" disabled={!ok.length}
                onClick={() => download(`batch-${stamp()}.json`, JSON.stringify(ok.map((x) => x.r), null, 2), "application/json")}>Export JSON</button>
            </div>
          </div>
          {truncated && <p class="field-error">Only the first {BATCH_LIMIT} lines were analysed.</p>}
          <div class="table-wrap">
            <table class="table table-cards">
              <caption class="visually-hidden">Batch results, most serious first</caption>
              <thead><tr><th scope="col">Verdict</th><th scope="col">Link (defanged)</th><th scope="col">Top indicator or reason</th></tr></thead>
              <tbody>
                {sorted.map(({ raw, r }, i) => (
                  <tr key={i}>
                    <td>{r.ok ? <Verdict level={r.verdict.level} label={r.verdict.label} /> : <span class="muted">Rejected</span>}</td>
                    <td class="mono cell-url">{r.ok ? defang(r.url) : defang(maskCredentials(raw.slice(0, 200)).slice(0, 120))}</td>
                    <td data-label={r.ok ? "Top indicator" : "Reason"}>{r.ok ? (r.indicators.find((x) => x.severity !== "info")?.title ?? <span class="muted">None</span>) : <span class="muted">{r.message}</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  );
}

export function AnalysisDetail({ id }) {
  const { ws } = useApp();
  const act = useAction();
  const { data: rec, loading } = useData(() => ws.getAnalysis(id).catch(() => null), [id]);
  if (loading && rec === undefined) return <PageHeader title="Analysis" />;
  if (rec === null) return <PageHeader title="Analysis not found" description="It may have been deleted from this workspace." />;
  return (
    <>
      <PageHeader title={rec.registrableDomain ?? rec.host} description={`Saved analysis of ${defang(rec.url)}`}>
        <button type="button" class="btn btn-danger btn-sm" onClick={async () => {
          if (!confirm("Delete this analysis from the workspace? Investigations that link to it will lose the link.")) return;
          if (await act(() => ws.deleteAnalysis(rec.id).then(() => true), "Analysis deleted.")) navigate("/analyses");
        }}>Delete analysis</button>
      </PageHeader>
      <AnalysisReport report={rec.report} saved={rec} />
    </>
  );
}
