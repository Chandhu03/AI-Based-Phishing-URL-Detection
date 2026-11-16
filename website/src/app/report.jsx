import { useRef, useState } from "preact/hooks";
import { defang } from "../engine/defang.js";
import { indicatorsFromAnalysis } from "../workspace/workspace.js";
import { Dialog, Facts, IndicatorList, Limits, ModelMeter, Specimen, SpecimenKey, Verdict } from "./components.jsx";
import { useAction, useApp, useData } from "./context.js";
import { download, stamp } from "./download.js";
import { navigate } from "./router.js";

/** The full analysis report. `saved` is the stored record, when there is one. */
export function AnalysisReport({ report, saved = null, onSaved }) {
  const { ws, toast, engine } = useApp();
  const act = useAction();
  const [dialog, setDialog] = useState(null);
  const caseBtn = useRef(null);

  async function ensureSaved() {
    if (saved) return saved;
    const rec = await act(() => ws.saveAnalysis(report), "Analysis saved to this workspace.");
    if (rec) onSaved?.(rec);
    return rec;
  }

  async function copyDefanged() {
    try {
      await navigator.clipboard.writeText(defang(report.url));
      toast("Defanged URL copied.");
    } catch {
      toast("Copy is blocked in this browser. Select the defanged value in the facts list instead.", "error");
    }
  }

  return (
    <article class="report" aria-labelledby="report-verdict">
      <header class="report-head">
        <div class="report-verdict" id="report-verdict" tabIndex={-1}>
          <Verdict level={report.verdict.level} label={report.verdict.label} />
          {saved?.demo && <span class="demo-flag">Demo</span>}
        </div>
        <Specimen segments={report.segments} />
        <SpecimenKey segments={report.segments} />
      </header>

      <div class="report-grid">
        <section class="report-why" aria-labelledby="why-title">
          <h2 id="why-title" class="section-title">Why this verdict</h2>
          <ul class="reasons">{report.verdict.reasons.map((r) => <li key={r}>{r}</li>)}</ul>
          <ModelMeter model={report.model} band={report.verdict.band} skipped={report.modelSkipped ?? (report.facts.isIp ? "ip-address" : null)}
            failed={!report.model && !report.modelSkipped && !report.facts.isIp && engine.modelFailed} />
        </section>
        <section class="report-facts" aria-labelledby="facts-title">
          <h2 id="facts-title" class="section-title">How a browser reads it</h2>
          <Facts report={report} />
        </section>
      </div>

      <section aria-labelledby="ind-title">
        <h2 id="ind-title" class="section-title">Indicators <span class="count">{report.indicators.filter((i) => i.severity !== "info").length}</span></h2>
        <IndicatorList indicators={report.indicators} />
      </section>

      <section aria-labelledby="limits-title" class="report-limits">
        <h2 id="limits-title" class="section-title">What this analysis cannot tell you</h2>
        <Limits />
      </section>

      <footer class="report-actions">
        {!saved && <button type="button" class="btn btn-primary" onClick={async () => { if (await ensureSaved()) caseBtn.current?.focus(); }}>Save to workspace</button>}
        <button type="button" ref={caseBtn} class="btn btn-secondary" onClick={() => setDialog("case")}>Add to investigation</button>
        <button type="button" class="btn btn-secondary" onClick={() => setDialog("ioc")}>Record indicators</button>
        <span class="spacer" />
        <button type="button" class="btn btn-quiet" onClick={copyDefanged}>Copy defanged URL</button>
        <button type="button" class="btn btn-quiet" onClick={async () => download(`analysis-${stamp()}.md`, (await import("../workspace/io.js")).analysisToMarkdown(report), "text/markdown")}>Export Markdown</button>
        <button type="button" class="btn btn-quiet" onClick={() => download(`analysis-${stamp()}.json`, JSON.stringify(report, null, 2), "application/json")}>Export JSON</button>
      </footer>
      <p class="report-meta muted">
        Engine {report.engine.version} · {report.engine.modelId ? `model ${report.engine.modelId}` : report.modelSkipped || report.facts.isIp ? "model not used for this host" : "no model"} · Public Suffix List {report.engine.pslCommit.slice(0, 10)} · analysed in this browser
      </p>

      <Dialog open={dialog === "case"} title="Add to investigation" onClose={() => setDialog(null)}>
        <AddToCase ensureSaved={ensureSaved} report={report} done={() => setDialog(null)} />
      </Dialog>
      <Dialog open={dialog === "ioc"} title="Record indicators" onClose={() => setDialog(null)}>
        <RecordIndicators ensureSaved={ensureSaved} report={report} done={() => setDialog(null)} />
      </Dialog>
    </article>
  );
}

function AddToCase({ ensureSaved, report, done }) {
  const { ws } = useApp();
  const act = useAction();
  const { data: cases = [] } = useData(() => ws.listInvestigations());
  const open = cases.filter((c) => c.status !== "closed");
  const [choice, setChoice] = useState("new");
  const [title, setTitle] = useState(`${report.verdict.label}: ${report.facts.registrableDomain ?? report.facts.host}`);

  async function submit(e) {
    e.preventDefault();
    const rec = await ensureSaved();
    if (!rec) return;
    const inv = await act(async () => {
      const target = choice === "new"
        ? await ws.createInvestigation({ title, priority: ws.severityForVerdict(report.verdict.level) })
        : await ws.getInvestigation(choice);
      return ws.linkAnalysis(target.id, rec.id);
    }, "Analysis added to the investigation.");
    if (inv) {
      done();
      navigate(`/investigations/${inv.id}`);
    }
  }

  return (
    <form class="stack" onSubmit={submit}>
      <fieldset class="choice">
        <legend class="field-label">Investigation</legend>
        <label class="radio"><input type="radio" name="case" value="new" checked={choice === "new"} onChange={() => setChoice("new")} /> Start a new investigation</label>
        {open.map((c) => (
          <label key={c.id} class="radio"><input type="radio" name="case" value={c.id} checked={choice === c.id} onChange={() => setChoice(c.id)} /> {c.title} <span class="muted">({c.status})</span></label>
        ))}
      </fieldset>
      {choice === "new" && (
        <label class="field">
          <span class="field-label">Title</span>
          <input spellcheck={false} class="input" value={title} maxLength={200} required onInput={(e) => setTitle(e.currentTarget.value)} />
        </label>
      )}
      <div class="row"><button class="btn btn-primary" type="submit">Add analysis</button></div>
    </form>
  );
}

function RecordIndicators({ ensureSaved, report, done }) {
  const { ws } = useApp();
  const act = useAction();
  const candidates = indicatorsFromAnalysis(report);
  const [picked, setPicked] = useState(() => new Set(candidates.filter((c) => c.type !== "url").map((c) => c.type)));
  const [confidence, setConfidence] = useState(report.verdict.level === "high-risk" ? "high" : "medium");
  const [tags, setTags] = useState("");

  async function submit(e) {
    e.preventDefault();
    const rec = await ensureSaved();
    if (!rec) return;
    const chosen = candidates.filter((c) => picked.has(c.type));
    const ok = await act(async () => {
      await ws.upsertIndicators(chosen.map((c) => ({ ...c, confidence, tags, source: "analysis", analysisId: rec.id })));
      return true;
    }, `${chosen.length} indicator${chosen.length === 1 ? "" : "s"} recorded.`);
    if (ok) done();
  }

  return (
    <form class="stack" onSubmit={submit}>
      <fieldset class="choice">
        <legend class="field-label">Values to record</legend>
        {candidates.map((c) => (
          <label key={c.type} class="check">
            <input type="checkbox" checked={picked.has(c.type)} onChange={(e) => {
              const next = new Set(picked);
              e.currentTarget.checked ? next.add(c.type) : next.delete(c.type);
              setPicked(next);
            }} />
            <span class="check-type">{c.type}</span> <code class="check-value">{defang(c.value)}</code>
          </label>
        ))}
      </fieldset>
      <div class="form-row">
        <label class="field">
          <span class="field-label">Confidence</span>
          <select aria-label="Confidence" class="select" value={confidence} onChange={(e) => setConfidence(e.currentTarget.value)}>
            <option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option>
          </select>
        </label>
        <label class="field">
          <span class="field-label">Tags</span>
          <input spellcheck={false} class="input" value={tags} placeholder="credential-phishing, payroll" onInput={(e) => setTags(e.currentTarget.value)} />
          <span class="field-hint">Separate tags with commas.</span>
        </label>
      </div>
      <div class="row"><button class="btn btn-primary" type="submit" disabled={picked.size === 0}>Record {picked.size} indicator{picked.size === 1 ? "" : "s"}</button></div>
    </form>
  );
}
