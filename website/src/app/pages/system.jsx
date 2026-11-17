import { useEffect, useState } from "preact/hooks";
import { BRANDS } from "../../engine/brands.js";
import { MAX_IMPORT_BYTES } from "../../workspace/workspace.js";

const io = () => import("../../workspace/io.js");
import { PageHeader } from "../components.jsx";
import { useAction, useApp, useData } from "../context.js";
import { download, readFile, stamp } from "../download.js";

const pct = (x) => (x == null ? "—" : `${(x * 100).toFixed(1)}%`);

/** What the detection engine is, how it was evaluated, and what it is not. */
export function Engine() {
  const { engine } = useApp();
  const ev = engine.scorer?.evaluation;
  return (
    <>
      <PageHeader title="Detection engine" description="How verdicts are made, which model is loaded, and how well it measured on research data." />
      <div class="engine-grid">
        <section class="panel" aria-labelledby="pipe-title">
          <h2 id="pipe-title" class="section-title">Pipeline</h2>
          <ol class="steps">
            <li><strong>Parse.</strong> The browser’s own URL parser, with a strict policy: http and https only, no control or bidirectional characters, 2,048 characters at most.</li>
            <li><strong>Locate the owner.</strong> The registrable domain is found with the Public Suffix List bundled with the app, commit <code>{engine.pslCommit.slice(0, 10)}</code>.</li>
            <li><strong>Check for deception.</strong> Rules look for hidden login text, disguised IPs, look-alike characters, brand misuse ({BRANDS.length} reference brands), embedded redirects and more. Each rule cites its evidence.</li>
            <li><strong>Score the host.</strong> A character n-gram model estimates how closely the host resembles phishing hosts in public datasets.</li>
            <li><strong>Decide.</strong> High risk, Suspicious, Inconclusive, or No strong indicators observed. The engine never reports a link as safe.</li>
          </ol>
        </section>
        <section class="panel" aria-labelledby="model-title">
          <h2 id="model-title" class="section-title">Loaded model</h2>
          {!engine.scorer ? (
            <p class="muted">{engine.modelFailed
              ? "The bundled model did not match its SHA-256 id, so it was not loaded. Verdicts use indicators only. Rebuild the site from a clean checkout."
              : "No model artifact is bundled in this build. Verdicts use indicators only."}</p>
          ) : (
            <>
              <dl class="facts">
                <div><dt>Model</dt><dd class="mono">{engine.scorer.id}</dd></div>
                <div><dt>Integrity</dt><dd>SHA-256 of the weights, calibration and thresholds checked on load</dd></div>
                <div><dt>Input</dt><dd>Hostname only (one leading “www.” removed)</dd></div>
                <div><dt>Elevated from</dt><dd>{pct(engine.scorer.thresholds.elevated)}</dd></div>
                <div><dt>High from</dt><dd>{pct(engine.scorer.thresholds.high)}</dd></div>
              </dl>
              {ev && <EvalTables ev={ev} />}
            </>
          )}
        </section>
        <section class="panel span-2" aria-labelledby="lim-title">
          <h2 id="lim-title" class="section-title">Research results are not field performance</h2>
          <p>Every number above comes from held-out domains in two public research datasets. Real traffic differs: new campaigns, compromised legitimate sites and link shorteners are all under-represented there. Treat the model as one piece of evidence beside the indicators and your own judgement. The full method is on the <a href="/research/">research page</a>.</p>
        </section>
      </div>
    </>
  );
}

const SET_NAMES = { phiusiil_test: "PhiUSIIL, held-out domains", hannousse_test: "Hannousse, held-out domains" };
const MODEL_NAMES = { engine_shipped: "This model", baseline_A_host_phiusiil: "Earlier hostname model", reference_demo_model: "Original demo model" };

function EvalTables({ ev }) {
  const sets = Object.entries(ev.test ?? {});
  if (!sets.length) return null;
  return (
    <div class="stack">
      {sets.map(([set, models]) => (
        <div class="table-wrap" key={set}>
          <table class="table table-compact table-cards">
            <caption>{SET_NAMES[set] ?? set} · {models.engine_shipped?.n?.toLocaleString()} URLs</caption>
            <thead><tr><th scope="col">Model</th><th scope="col">ROC-AUC</th><th scope="col">PR-AUC</th><th scope="col">Caught at “high”</th><th scope="col">False alarms at “high”</th></tr></thead>
            <tbody>
              {Object.entries(models).map(([name, m]) => (
                <tr key={name} class={name === "engine_shipped" ? "row-strong" : ""}>
                  <th scope="row">{MODEL_NAMES[name] ?? name}</th>
                  <td class="num" data-label="ROC-AUC">{m.roc_auc?.toFixed(3) ?? "—"}</td>
                  <td class="num" data-label="PR-AUC">{m.pr_auc?.toFixed(3) ?? "—"}</td>
                  <td class="num" data-label="Caught at “high”">{pct(m.high?.recall)}</td>
                  <td class="num" data-label="False alarms at “high”">{pct(m.high?.fpr)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ))}
      <p class="field-hint">Thresholds were set on a validation split that is about 95% PhiUSIIL, which is why false alarms at “high” are higher on Hannousse. Expect them to be higher again on everyday traffic. Dataset files are verified by SHA-256; licences: {Object.values(ev.datasets ?? {}).map((d) => d.license).join(", ")}.</p>
    </div>
  );
}

export function Settings() {
  const { ws, storageKind, theme, setTheme, toast, engine } = useApp();
  const act = useAction();
  const [estimate, setEstimate] = useState(null);
  const [persisted, setPersisted] = useState(null);
  const [restoring, setRestoring] = useState(null); // null | progress text
  const { data: damaged = [] } = useData(() => ws.damaged());

  useEffect(() => {
    navigator.storage?.estimate?.().then(setEstimate).catch(() => {});
    navigator.storage?.persisted?.().then(setPersisted).catch(() => {});
  }, []);

  async function restore(e) {
    const file = e.currentTarget.files?.[0];
    e.currentTarget.value = "";
    if (!file) return;
    if (restoring !== null) return;
    try {
      if (!engine.ready) throw new Error("The analysis engine is still loading. Try again in a moment.");
      setRestoring("Reading the backup…");
      // Analyses are re-run by the current engine; nothing in the file is trusted as-is.
      const { importBackup, parseBackupInChunks } = await io();
      const parsed = await parseBackupInChunks(await readFile(file, MAX_IMPORT_BYTES), (url, at) => engine.analyzeAt(url, at),
        (done, total, store) => setRestoring(`Re-checking ${store}: ${done.toLocaleString("en-US")} of ${total.toLocaleString("en-US")}…`));
      setRestoring("Saving…");
      // One transaction: a failure here leaves the workspace exactly as it was.
      const c = await act(() => ws.exclusive((store) => importBackup(store, parsed)));
      if (c) {
        toast(`Backup merged: ${c.added} added${c.repaired ? `, ${c.repaired} damaged records replaced` : ""}, ${c.skipped} already present${c.rejected ? `, ${c.rejected} invalid records skipped` : ""}.`);
      }
    } catch (err) {
      toast(err.message, "error");
    } finally {
      setRestoring(null);
    }
  }

  return (
    <>
      <PageHeader title="Settings" description="Appearance and the data this browser keeps." />
      <div class="settings">
        <section class="panel" aria-labelledby="ap-title">
          <h2 id="ap-title" class="section-title">Appearance</h2>
          <fieldset class="choice choice-row">
            <legend class="field-label">Theme</legend>
            {[["system", "Match system"], ["light", "Light"], ["dark", "Dark"]].map(([v, l]) => (
              <label key={v} class="radio"><input type="radio" name="theme" value={v} checked={theme === v} onChange={() => setTheme(v)} /> {l}</label>
            ))}
          </fieldset>
        </section>
        <section class="panel" aria-labelledby="data-title">
          <h2 id="data-title" class="section-title">Workspace data</h2>
          <dl class="facts">
            <div><dt>Stored in</dt><dd>{storageKind === "indexeddb" ? "This browser (IndexedDB)" : "Memory only — IndexedDB is unavailable, so data is lost when the tab closes"}</dd></div>
            <div><dt>Synchronised</dt><dd>No. There is no server; other browsers and devices cannot see this workspace.</dd></div>
            <div><dt>Space used</dt><dd>{estimate ? `${(estimate.usage / 1024).toFixed(0)} KB of ${(estimate.quota / 1048576).toFixed(0)} MB available` : "Not reported by this browser"}</dd></div>
            <div><dt>Protected from cleanup</dt><dd>{persisted === null ? "Unknown" : persisted ? "Yes" : "No — the browser may clear it under storage pressure"}</dd></div>
          </dl>
          <div class="row">
            {persisted === false && <button type="button" class="btn btn-secondary btn-sm" onClick={async () => setPersisted(await navigator.storage.persist())}>Ask to keep data</button>}
            <button type="button" class="btn btn-secondary btn-sm" onClick={async () => download(`securemind-workspace-${stamp()}.json`, JSON.stringify(await (await io()).exportBackup(ws.store)), "application/json")}>Export backup</button>
            <label class="btn btn-secondary btn-sm file-btn" aria-disabled={restoring !== null ? "true" : undefined}>
              Restore backup<input type="file" name="backup-file" accept=".json,application/json" onChange={restore} disabled={restoring !== null} />
            </label>
          </div>
          <p class="field-hint" role="status">{restoring ?? ""}</p>
          <p class="field-hint">Backups contain every analysis, note and indicator in plain JSON. Store them as carefully as the investigations themselves. Restoring adds records that are not already here; analyses are re-checked by the current engine.</p>
        </section>
        <section class="panel" aria-labelledby="health-title">
          <h2 id="health-title" class="section-title" tabIndex={-1}>Workspace health</h2>
          {damaged.length === 0 ? (
            <p class="muted">Every stored record passed its check.</p>
          ) : (
            <>
              <p>{damaged.length} stored {damaged.length === 1 ? "record is" : "records are"} damaged and hidden from the lists. This can happen after editing storage by hand, a browser extension or an interrupted older version.</p>
              <ul class="list small">
                {damaged.slice(0, 8).map((d) => <li key={`${d.store}:${d.id}`}><span class="check-type">{d.store}</span><span class="mono list-main">{d.id.slice(0, 80)}</span></li>)}
              </ul>
              {damaged.length > 8 && <p class="muted small">…and {damaged.length - 8} more.</p>}
              <p class="field-hint">Restoring a backup that holds a good copy replaces a damaged record. Export a backup first if you want to keep the damaged data for inspection.</p>
              <div class="row">
                <button type="button" class="btn btn-secondary btn-sm" onClick={() => {
                  if (confirm(`Remove ${damaged.length} damaged ${damaged.length === 1 ? "record" : "records"}? This cannot be undone.`)) {
                    act(() => ws.removeDamaged(), "Damaged records removed.").then(() => document.getElementById("health-title")?.focus());
                  }
                }}>Remove damaged records</button>
              </div>
            </>
          )}
        </section>
        <section class="panel panel-danger" aria-labelledby="dz-title">
          <h2 id="dz-title" class="section-title">Delete workspace</h2>
          <p>Removes every analysis, investigation, indicator and activity record from this browser. Export a backup first if you may need them.</p>
          <div class="row">
            <button type="button" class="btn btn-danger" onClick={() => {
              if (confirm("Delete the entire workspace from this browser? This cannot be undone.")) act(() => ws.clearAll(), "Workspace deleted.");
            }}>Delete all workspace data</button>
          </div>
        </section>
      </div>
    </>
  );
}
