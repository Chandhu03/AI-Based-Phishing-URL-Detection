import { useState } from "preact/hooks";
import { defang } from "../../engine/defang.js";
import { FINDING_NAMES } from "../../engine/finding-names.js";
import { VERDICTS } from "../../engine/verdict.js";
import { duration } from "../../workspace/format.js";
import { Empty, PageHeader } from "../components.jsx";
import { useApp, useData } from "../context.js";
import { download, stamp } from "../download.js";

const PERIODS = [7, 30, 90];
const io = () => import("../../workspace/io.js");
const pct = (x) => (x == null ? "—" : `${Math.round(x * 100)}%`);
const entries = (obj, label = (k) => k) => Object.entries(obj).filter(([, n]) => n).map(([k, n]) => `${label(k)} ${n}`).join(" · ") || "none";

let rememberedDays = 7;

/** Period report: what came in, how it was handled, how fast, and what is still open. */
export function Reports() {
  const { ws } = useApp();
  const [days, setDays] = useState(rememberedDays);
  const { data: r } = useData(() => ws.report({ days }), [days]);

  async function exportCsv() {
    const all = await ws.listAlerts();
    const inPeriod = all.filter((a) => a.createdAt >= r.since);
    download(`alerts-${stamp()}.csv`, (await io()).alertsToCsv(inPeriod), "text/csv");
  }

  return (
    <div class="stack">
      <PageHeader title="Reports" description="Figures counted from this workspace's records for the period. Export the report to share it; domains are defanged.">
        <label class="field field-inline"><span class="field-label">Period</span>
          <select class="select" value={days} onChange={(e) => { rememberedDays = Number(e.currentTarget.value); setDays(rememberedDays); }}>
            {PERIODS.map((d) => <option key={d} value={d}>Last {d} days</option>)}
          </select>
        </label>
        <button type="button" class="btn btn-secondary" disabled={!r} onClick={async () => download(`soc-report-${stamp()}.md`, (await io()).reportToMarkdown(r, FINDING_NAMES), "text/markdown")}>Export report</button>
        <button type="button" class="btn btn-quiet" disabled={!r?.alerts.queued} onClick={exportCsv}>Export alerts CSV</button>
      </PageHeader>

      {r && (
        <>
          <section class="panel" aria-labelledby="rp-q">
            <h2 id="rp-q" class="section-title">Alert queue</h2>
            <dl class="kpis">
              <div><dt>Alerts queued</dt><dd>{r.alerts.queued}</dd></div>
              <div><dt>Reports, with repeats</dt><dd>{r.alerts.reports}</dd></div>
              <div><dt>Escalated</dt><dd>{r.alerts.escalated}</dd></div>
              <div><dt>Closed by analysts</dt><dd>{r.alerts.metrics.closedRecent}</dd></div>
              <div><dt>Closed by rules</dt><dd>{r.alerts.metrics.closedByRule}</dd></div>
              <div><dt>Median time to triage</dt><dd>{duration(r.alerts.metrics.timeToTriage)}</dd></div>
              <div><dt>Median time to close</dt><dd>{duration(r.alerts.metrics.timeToClose)}</dd></div>
              <div><dt>False positives</dt><dd>{pct(r.alerts.metrics.falsePositiveRate)}</dd></div>
            </dl>
            <p class="muted small">By source: {entries(r.alerts.bySource)}. By verdict when queued: {entries(r.alerts.byVerdict, (k) => VERDICTS[k]?.label ?? k)}.</p>
          </section>

          <div class="overview-pair">
            <section class="panel" aria-labelledby="rp-l">
              <h2 id="rp-l" class="section-title">Top lure domains</h2>
              {r.topLures.length === 0 ? <p class="muted">No high-risk or suspicious alerts in this period.</p> : (
                <table class="table table-compact">
                  <caption class="visually-hidden">Registrable domains of high-risk or suspicious alerts, by reports</caption>
                  <thead><tr><th scope="col">Registrable domain</th><th scope="col">Alerts</th><th scope="col">Reports</th></tr></thead>
                  <tbody>{r.topLures.map((l) => <tr key={l.domain}><td class="mono">{defang(l.domain)}</td><td class="num">{l.alerts}</td><td class="num">{l.reports}</td></tr>)}</tbody>
                </table>
              )}
            </section>
            <section class="panel" aria-labelledby="rp-f">
              <h2 id="rp-f" class="section-title">Most frequent findings</h2>
              {r.topFindings.length === 0 ? <p class="muted">No analyses saved in this period.</p> : (
                <table class="table table-compact">
                  <caption class="visually-hidden">Indicator types in analyses saved in the period</caption>
                  <tbody>{r.topFindings.map(([id, n]) => <tr key={id}><th scope="row">{FINDING_NAMES[id] ?? id}</th><td class="num">{n}</td></tr>)}</tbody>
                </table>
              )}
            </section>
          </div>

          <section class="panel" aria-labelledby="rp-i">
            <h2 id="rp-i" class="section-title">Investigations and indicators</h2>
            <dl class="kpis">
              <div><dt>Investigations opened</dt><dd>{r.investigations.opened}</dd></div>
              <div><dt>Investigations closed</dt><dd>{r.investigations.closed}</dd></div>
              <div><dt>Open now</dt><dd>{r.investigations.open}</dd></div>
              <div><dt>Checklist steps done</dt><dd>{r.investigations.checklist.total ? `${r.investigations.checklist.done}/${r.investigations.checklist.total}` : "—"}</dd></div>
              <div><dt>Indicators recorded</dt><dd>{r.indicators.recorded}</dd></div>
            </dl>
            <p class="muted small">Open by priority: {entries(r.investigations.openByPriority)}. Indicators by type: {entries(r.indicators.byType)}.</p>
          </section>
          {r.alerts.queued === 0 && r.investigations.opened === 0 && r.indicators.recorded === 0 && (
            <Empty title="Nothing recorded in this period."><p>Choose a longer period, or load the demo workspace from the Overview.</p></Empty>
          )}
        </>
      )}
    </div>
  );
}
