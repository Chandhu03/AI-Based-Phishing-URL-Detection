import { useState } from "preact/hooks";
import { defang } from "../../engine/defang.js";
import { DayColumns, VerdictBars } from "../charts.jsx";
import { Empty, PageHeader, Time, Verdict } from "../components.jsx";
import { useAction, useApp, useData } from "../context.js";
import { QuickAnalyze } from "./analyze.jsx";
import { FINDING_NAMES } from "../../engine/finding-names.js";

const TYPE_NAMES = {
  url: ["URL", "URLs"], domain: ["domain", "domains"], hostname: ["host name", "host names"],
  ipv4: ["IPv4 address", "IPv4 addresses"], ipv6: ["IPv6 address", "IPv6 addresses"],
};
const focusTitle = () => document.querySelector("[data-page-title]")?.focus();

export function Overview() {
  const { ws, engine } = useApp();
  const act = useAction();
  const { data: o } = useData(() => ws.overview({ days: 30 }));
  const { data: activity = [] } = useData(() => ws.activity(8));
  const [loadingDemo, setLoadingDemo] = useState(false);

  async function loadDemo() {
    if (loadingDemo) return;
    setLoadingDemo(true);
    await act(async () => (await import("../../workspace/demo.js")).loadDemoWorkspace(ws, engine.analyze), "Demo workspace loaded.");
    setLoadingDemo(false);
    focusTitle();
  }

  if (!o) return <PageHeader title="Overview" />;
  const empty = Object.values(o.totals).every((n) => n === 0);

  return (
    <>
      <PageHeader title="Overview" description="Everything here comes from this browser’s workspace. Nothing is synchronised or shared." />
      {o.hasDemo && (
        <div class="banner" role="note">
          <p>This workspace contains demo records, marked <span class="demo-flag">Demo</span>. They are example analyses, not observed activity.</p>
          <button type="button" class="btn btn-secondary btn-sm" onClick={async () => { await act(() => ws.removeDemoData(), "Demo records removed."); focusTitle(); }}>Remove demo records</button>
        </div>
      )}

      <section class="panel panel-analyze" aria-labelledby="qa-title">
        <h2 id="qa-title" class="section-title">Analyse a link</h2>
        <QuickAnalyze />
      </section>

      {empty ? (
        <Empty title="Your workspace is empty.">
          <p>Analyse a link to begin, or load a demo workspace to see how investigations and indicators fit together. Demo records are clearly marked and can be removed in one step.</p>
          <div class="row">
            <a class="btn btn-primary" href="#/analyze">Analyse links</a>
            <button type="button" class="btn btn-secondary" disabled={!engine.ready} aria-disabled={loadingDemo ? "true" : undefined} onClick={loadDemo}>
              {loadingDemo ? "Loading demo…" : "Load demo workspace"}
            </button>
          </div>
        </Empty>
      ) : (
        <div class="overview-grid">
          <div class="overview-main">
            <div class="overview-pair">
          <section class="panel" aria-labelledby="v-title">
            <div class="panel-head">
              <h2 id="v-title" class="section-title">Verdicts, last {o.days} days</h2>
              <p class="figure">{o.recentAnalyses}<span> analyses</span></p>
            </div>
            <VerdictBars byVerdict={o.byVerdict} />
          </section>
          <section class="panel" aria-labelledby="d-title">
            <div class="panel-head">
              <h2 id="d-title" class="section-title">Analyses per day, last {o.perDay.length} days</h2>
              <p class="figure">{o.totals.analyses}<span> saved in total</span></p>
            </div>
            <DayColumns perDay={o.perDay} />
          </section>
            </div>
          <section class="panel" aria-labelledby="r-title">
            <div class="panel-head">
              <h2 id="r-title" class="section-title">Recent analyses</h2>
              <a href="#/analyses">All analyses</a>
            </div>
            <div class="table-wrap">
            <table class="table">
              <thead><tr><th scope="col">Verdict</th><th scope="col">Registrable domain</th><th scope="col">Indicators</th><th scope="col">Saved</th></tr></thead>
              <tbody>
                {o.recent.map((a) => (
                  <tr key={a.id}>
                    <td><Verdict level={a.verdict} label={a.report.verdict.label} /></td>
                    <td><a class="mono" href={`#/analyses/${a.id}`}>{a.registrableDomain ?? a.host}</a> {a.demo && <span class="demo-flag">Demo</span>}</td>
                    <td class="num">{a.indicatorCount}</td>
                    <td class="muted"><Time iso={a.createdAt} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
            </div>
          </section>
          </div>
          <div class="overview-side">
          <section class="panel" aria-labelledby="q-title">
            <div class="panel-head">
              <h2 id="q-title" class="section-title">Alert queue</h2>
              <a href="#/alerts">Open the queue</a>
            </div>
            {o.openAlerts.length === 0 ? <p class="muted">No open alerts.</p> : (
              <>
                <p class="figure">{o.openAlerts.length}<span> open</span></p>
                <ul class="list">
                  {o.openAlerts.slice(0, 5).map((a) => (
                    <li key={a.id}>
                      <span class="prio" data-prio={a.severity}>{a.severity}</span>
                      <a href={`#/alerts/${a.id}`} class="list-main mono">{defang(a.host)}</a>
                      <span class="muted">{a.occurrences}×</span>
                    </li>
                  ))}
                </ul>
              </>
            )}
          </section>
          <section class="panel" aria-labelledby="c-title">
            <div class="panel-head">
              <h2 id="c-title" class="section-title">Open investigations</h2>
              <a href="#/investigations">All investigations</a>
            </div>
            {o.openInvestigations.length === 0 ? <p class="muted">No open investigations.</p> : (
              <ul class="list">
                {o.openInvestigations.slice(0, 5).map((c) => (
                  <li key={c.id}>
                    <a href={`#/investigations/${c.id}`} class="list-main">{c.title}</a>
                    <span class="prio" data-prio={c.priority}>{c.priority}</span>
                    <span class="muted">{c.status}</span>
                  </li>
                ))}
              </ul>
            )}
          </section>
          <section class="panel" aria-labelledby="f-title">
            <div class="panel-head"><h2 id="f-title" class="section-title">Most frequent findings</h2></div>
            {o.topFindings.length === 0 ? <p class="muted">No indicators found in saved analyses yet.</p> : (
              <table class="table table-compact">
                <caption class="visually-hidden">Indicator types across saved analyses</caption>
                <tbody>{o.topFindings.map(([id, n]) => <tr key={id}><th scope="row">{FINDING_NAMES[id] ?? id}</th><td class="num">{n}</td></tr>)}</tbody>
              </table>
            )}
            <p class="muted small">Indicators recorded: {Object.entries(o.indicatorsByType).filter(([, n]) => n).map(([t, n]) => `${n} ${(TYPE_NAMES[t] ?? [t, t])[n === 1 ? 0 : 1]}`).join(", ") || "none"}.</p>
          </section>
          <section class="panel" aria-labelledby="a-title">
            <div class="panel-head"><h2 id="a-title" class="section-title">Activity</h2></div>
            <ol class="timeline">
              {activity.map((e) => <li key={e.id}><span>{e.summary}</span><Time iso={e.at} /></li>)}
            </ol>
          </section>
          </div>
        </div>
      )}
    </>
  );
}
