import { useState } from "preact/hooks";
import { defang } from "../../engine/defang.js";
import { classifyIndicator, CONFIDENCE, INDICATOR_TYPES, MAX_IMPORT_BYTES } from "../../workspace/workspace.js";

const io = () => import("../../workspace/io.js");
import { Dialog, Empty, PageHeader, Time } from "../components.jsx";
import { useAction, useApp, useData } from "../context.js";
import { download, readFile, stamp } from "../download.js";

export function Indicators() {
  const { ws, toast } = useApp();
  const act = useAction();
  const [type, setType] = useState("");
  const [query, setQuery] = useState("");
  const [dialog, setDialog] = useState(null);
  const [selected, setSelected] = useState(null);
  const { data: list = [] } = useData(() => ws.listIndicators({ type: type || undefined, query: query.toLowerCase() || undefined }), [type, query]);

  async function importFile(e) {
    const file = e.currentTarget.files?.[0];
    e.currentTarget.value = "";
    if (!file) return;
    try {
      const { items, rejected, format } = (await io()).parseIndicatorFile(await readFile(file, MAX_IMPORT_BYTES));
      const skipped = rejected ? `; ${rejected} ${rejected === 1 ? "entry was" : "entries were"} not valid and ${rejected === 1 ? "was" : "were"} skipped` : "";
      if (!items.length) {
        toast(`No indicators found in ${file.name}${skipped}. Use one value per line, a CSV with type and value columns, or a STIX 2.1 bundle.`, "error");
        return;
      }
      // One transaction: if any item fails, nothing from the file is recorded.
      await act(() => ws.upsertIndicators(items.map((it) => ({ ...it, source: `import: ${file.name}`.slice(0, 120) }))), `Imported ${items.length} indicator${items.length === 1 ? "" : "s"} from ${format}${skipped}.`);
    } catch (err) {
      toast(err.message, "error");
    }
  }

  return (
    <>
      <PageHeader title="Indicators" description="Domains, hosts, IP addresses and URLs you have recorded, with where each came from. Enrichment from external sources is not connected.">
        <button type="button" class="btn btn-primary" onClick={() => setDialog("add")}>Add indicator</button>
        <label class="btn btn-secondary file-btn">Import<input type="file" accept=".txt,.csv,.json,text/plain,text/csv,application/json" onChange={importFile} /></label>
        <button type="button" class="btn btn-quiet" disabled={!list.length} onClick={async () => download(`indicators-${stamp()}.csv`, (await io()).indicatorsToCsv(list, { defanged: true }), "text/csv")}>Export CSV (defanged)</button>
        <button type="button" class="btn btn-quiet" disabled={!list.length} onClick={async () => download(`indicators-${stamp()}.stix.json`, JSON.stringify((await io()).indicatorsToStix(list), null, 2), "application/json")}>Export STIX 2.1</button>
      </PageHeader>
      <div class="filters" role="search">
        <label class="field"><span class="field-label">Search</span><input spellcheck={false} class="input input-mono" type="search" value={query} onInput={(e) => setQuery(e.currentTarget.value)} placeholder="evil.example" /></label>
        <label class="field"><span class="field-label">Type</span>
          <select aria-label="Type" class="select" value={type} onChange={(e) => setType(e.currentTarget.value)}>
            <option value="">All types</option>{INDICATOR_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
        </label>
      </div>
      {list.length === 0 ? (
        <Empty title={query || type ? "No indicators match these filters." : "No indicators recorded yet."}>
          <p>Record them from an analysis, add one by hand, or import a text, CSV or STIX 2.1 file.</p>
        </Empty>
      ) : (
        <div class="table-wrap">
          <table class="table">
            <thead><tr><th scope="col">Type</th><th scope="col">Value (defanged)</th><th scope="col">Confidence</th><th scope="col">Sightings</th><th scope="col">Last seen</th><th scope="col">Sources</th><th scope="col"><span class="visually-hidden">Actions</span></th></tr></thead>
            <tbody>
              {list.map((i) => (
                <tr key={i.id}>
                  <td><span class="check-type">{i.type}</span></td>
                  <td class="mono cell-url">{defang(i.value)} {i.demo && <span class="demo-flag">Demo</span>}
                    {i.tags.length > 0 && <div class="tags">{i.tags.map((t) => <span key={t} class="tag">{t}</span>)}</div>}</td>
                  <td>{i.confidence}</td>
                  <td class="num">{i.sightings}</td>
                  <td class="muted"><Time iso={i.lastSeen} /></td>
                  <td class="muted small">{i.sources.join(", ")}</td>
                  <td><button type="button" class="btn btn-quiet btn-sm" onClick={() => setSelected(i.id)}>Details<span class="visually-hidden"> for {defang(i.value)}</span></button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <Dialog open={dialog === "add"} title="Add indicator" onClose={() => setDialog(null)}><AddIndicator done={() => setDialog(null)} /></Dialog>
      <Dialog open={!!selected} title="Indicator" onClose={() => setSelected(null)}>{selected && <IndicatorDetail id={selected} done={() => setSelected(null)} />}</Dialog>
    </>
  );
}

function AddIndicator({ done }) {
  const { ws } = useApp();
  const act = useAction();
  const [value, setValue] = useState("");
  const [confidence, setConfidence] = useState("medium");
  const [tags, setTags] = useState("");
  const guess = value.trim() ? classifyIndicator(value.trim()) : null;
  return (
    <form class="stack" onSubmit={async (e) => {
      e.preventDefault();
      if (guess && await act(() => ws.upsertIndicator({ ...guess, confidence, tags, source: "analyst" }), "Indicator recorded.")) done();
    }}>
      <label class="field"><span class="field-label">Value</span>
        <input spellcheck={false} class="input input-mono" value={value} required aria-invalid={value.trim() && !guess ? "true" : undefined} onInput={(e) => setValue(e.currentTarget.value)} placeholder="evil[.]example or 198.51.100.7" aria-describedby="add-type" />
        <span id="add-type" class={guess || !value.trim() ? "field-hint" : "field-error"}>{!value.trim() ? "A URL, domain, IPv4 or IPv6 address. Defanged values are accepted." : guess ? `Recognised as ${guess.type}: ${guess.value}` : "Not recognised as a URL, domain or IP address."}</span>
      </label>
      <div class="form-row">
        <label class="field"><span class="field-label">Confidence</span>
          <select aria-label="Confidence" class="select" value={confidence} onChange={(e) => setConfidence(e.currentTarget.value)}>{CONFIDENCE.map((c) => <option key={c} value={c}>{c}</option>)}</select>
        </label>
        <label class="field"><span class="field-label">Tags</span><input spellcheck={false} class="input" value={tags} onInput={(e) => setTags(e.currentTarget.value)} /></label>
      </div>
      <div class="row"><button class="btn btn-primary" type="submit" disabled={!guess}>Record indicator</button></div>
    </form>
  );
}

function IndicatorDetail({ id, done }) {
  const { ws } = useApp();
  const act = useAction();
  // After a delete the dialog may reload once more before it closes: a missing
  // indicator is "nothing to show", not a page error.
  const { data } = useData(async () => {
    const ind = await ws.getIndicator(id).catch(() => null);
    return ind && { ind, related: await ws.relatedIndicators(id) };
  }, [id]);
  const [note, setNote] = useState(null);
  if (!data) return null;
  const { ind, related } = data;
  return (
    <div class="stack">
      <p class="mono">{defang(ind.value)}</p>
      <dl class="facts">
        <div><dt>Type</dt><dd>{ind.type}</dd></div>
        <div><dt>First seen</dt><dd><Time iso={ind.firstSeen} /></dd></div>
        <div><dt>Last seen</dt><dd><Time iso={ind.lastSeen} /></dd></div>
        <div><dt>Sources</dt><dd>{ind.sources.join(", ") || "—"}</dd></div>
        <div><dt>Analyses</dt><dd>{ind.analysisIds.length ? ind.analysisIds.map((a, n) => <a key={a} href={`#/analyses/${a}`} onClick={done}>#{n + 1} </a>) : "—"}</dd></div>
        <div><dt>Investigations</dt><dd>{ind.investigationIds.length ? ind.investigationIds.map((c, n) => <a key={c} href={`#/investigations/${c}`} onClick={done}>#{n + 1} </a>) : "—"}</dd></div>
        <div><dt>STIX id</dt><dd class="mono small">{ind.stixId}</dd></div>
      </dl>
      <label class="field"><span class="field-label">Confidence</span>
        <select aria-label="Confidence" class="select" value={ind.confidence} onChange={(e) => act(() => ws.updateIndicator(id, { confidence: e.currentTarget.value }), "Confidence updated.")}>
          {CONFIDENCE.map((c) => <option key={c} value={c}>{c}</option>)}
        </select>
      </label>
      <label class="field"><span class="field-label">Analyst note</span>
        <textarea spellcheck={false} class="textarea" value={note ?? ind.note} onInput={(e) => setNote(e.currentTarget.value)} />
      </label>
      {related.length > 0 && (
        <section><h3 class="field-label">Related by domain</h3>
          <ul class="list">{related.map((r) => <li key={r.id}><span class="check-type">{r.type}</span><code class="list-main">{defang(r.value)}</code></li>)}</ul>
        </section>
      )}
      <div class="row">
        <button type="button" class="btn btn-primary btn-sm" disabled={note === null} onClick={() => act(() => ws.updateIndicator(id, { note }), "Note saved.")}>Save note</button>
        <span class="spacer" />
        <button type="button" class="btn btn-danger btn-sm" onClick={async () => {
          if (!confirm("Delete this indicator? It is also removed from any investigations.")) return;
          if (await act(() => ws.deleteIndicator(id).then(() => true), "Indicator deleted.")) done();
        }}>Delete indicator</button>
      </div>
    </div>
  );
}
