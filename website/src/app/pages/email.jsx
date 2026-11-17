import { useEffect, useRef, useState } from "preact/hooks";
import { defang } from "../../engine/defang.js";
import { EMAIL_LIMITS, parseEmail } from "../../engine/email.js";
import { LIMITS } from "../../workspace/workspace.js";
import { IndicatorList, PageHeader, Verdict } from "../components.jsx";
import { useAction, useApp } from "../context.js";
import { download, stamp } from "../download.js";

// The open message survives navigation within the session only; it is never stored.
let last = null;

const AUTH_LABEL = { pass: "pass", fail: "fail", softfail: "soft fail", neutral: "neutral", none: "none", temperror: "temporary error", permerror: "permanent error" };
const authLevel = (v) => (v === "pass" ? "ok" : ["fail", "softfail", "permerror"].includes(v) ? "bad" : "unknown");
const order = { "high-risk": 0, suspicious: 1, inconclusive: 2, "no-strong-indicators": 3 };

function Address({ a }) {
  if (!a?.address) return <span class="muted">—</span>;
  return <span>{a.name && <>{a.name} </>}<code>{defang(a.address)}</code></span>;
}

/** Open a reported message, see its sender, authentication, links and attachments, and queue its links. */
export function Email() {
  const { engine, ws, toast } = useApp();
  const act = useAction();
  const [source, setSource] = useState("");
  const [state, setState] = useState(last); // { email, links, queued }
  const [error, setError] = useState("");
  const [reporter, setReporter] = useState(last?.email.wrapper?.from?.address ?? "");
  const title = useRef(null);
  const fresh = useRef(false);

  useEffect(() => {
    last = state;
    if (state && fresh.current) {
      fresh.current = false;
      title.current?.focus();
    }
  }, [state]);

  function open(text) {
    const email = parseEmail(text, { psl: engine.psl });
    if (!email.ok) {
      setError(email.message);
      return;
    }
    setError("");
    const links = email.links.map((link) => ({ link, report: engine.analyze(link.url) }))
      .sort((a, b) => (a.report.ok ? order[a.report.verdict.level] : 4) - (b.report.ok ? order[b.report.verdict.level] : 4));
    fresh.current = true;
    setReporter(email.wrapper?.from?.address ?? "");
    setState({ email, links, queued: false });
  }

  async function queue() {
    const ok = state.links.filter((x) => x.report.ok);
    if (!ok.length || state.queued) return;
    const who = reporter.trim();
    if (who.length > LIMITS.reporter) {
      toast("The reporter is too long.", "error");
      return;
    }
    const ref = state.email.messageId.length <= LIMITS.externalId ? state.email.messageId : "";
    const result = await act(() => ws.queueAlerts(ok.map(({ report }) => ({ report, source: "reported-email", externalId: ref, reporter: who }))));
    if (!result) return;
    toast(`${result.created.length} queued${result.merged ? `, ${result.merged} seen again` : ""}${result.closedByRule ? `, ${result.closedByRule} closed by queue rules` : ""}.`);
    setState({ ...state, queued: true });
  }

  const e = state?.email;
  const analysed = state?.links.filter((x) => x.report.ok) ?? [];
  return (
    <div class="stack">
      <PageHeader title="Reported email" description="Open a message someone reported (.eml) to check who sent it, what the receiving server's authentication said, and where its links lead. It is read as text: nothing in it is rendered, opened or fetched, and the message is not stored." />
      <section class="panel stack" aria-labelledby="em-open">
        <h2 id="em-open" class="section-title">Open a message</h2>
        <div class="row">
          <label class="btn btn-primary file-btn">Open .eml file<input type="file" name="email-file" accept=".eml,.txt,message/rfc822,text/plain" disabled={!engine.ready}
            onChange={async (ev) => {
              const file = ev.currentTarget.files?.[0];
              ev.currentTarget.value = "";
              if (!file) return;
              if (file.size > EMAIL_LIMITS.bytes) {
                setError("The message is larger than 5 MB.");
                return;
              }
              open(await file.text());
            }} /></label>
          {!engine.ready && <span class="muted">Loading engine…</span>}
        </div>
        <form class="stack" onSubmit={(ev) => { ev.preventDefault(); open(source); }}>
          <label class="field"><span class="field-label">Or paste the message source (headers and body)</span>
            <textarea spellcheck={false} class="textarea input-mono" rows={5} value={source} maxLength={EMAIL_LIMITS.bytes}
              aria-invalid={error ? "true" : undefined} aria-describedby="em-error" onInput={(ev) => { setSource(ev.currentTarget.value); if (error) setError(""); }} />
          </label>
          <p id="em-error" class="field-error" role="alert" hidden={!error}>{error}</p>
          <div class="row"><button class="btn btn-secondary" type="submit" disabled={!engine.ready || !source.trim()}>Analyse message</button></div>
        </form>
      </section>

      {e && (
        <div class="stack">
          <section class="panel" aria-labelledby="em-title">
            <div class="panel-head">
              <h2 id="em-title" class="section-title" tabIndex={-1} ref={title}>{e.subject || "(no subject)"}</h2>
              <button type="button" class="btn btn-quiet btn-sm" onClick={async () => download(`reported-email-${stamp()}.md`, (await import("../../workspace/io.js")).emailToMarkdown(e, state.links), "text/markdown")}>Export report</button>
            </div>
            <dl class="facts">
              <div><dt>From</dt><dd><Address a={e.from} /></dd></div>
              <div><dt>Reply-To</dt><dd>{e.replyTo.length ? e.replyTo.map((a, i) => <span key={i}>{i > 0 && ", "}<Address a={a} /></span>) : <span class="muted">—</span>}</dd></div>
              <div><dt>Return-Path</dt><dd><Address a={e.returnPath} /></dd></div>
              <div><dt>Date</dt><dd>{e.date || "—"}</dd></div>
              <div><dt>Message-ID</dt><dd class="mono">{e.messageId || "—"}</dd></div>
              <div><dt>Received hops</dt><dd>{e.received}</dd></div>
              {e.wrapper && <div><dt>Reported by</dt><dd><Address a={e.wrapper.from} /> <span class="muted">(forwarded as an attachment)</span></dd></div>}
            </dl>
            <ul class="auth" aria-label="Authentication results from the receiving server">
              {["spf", "dkim", "dmarc"].map((k) => {
                const v = e.auth?.[k] ?? null;
                return <li key={k} data-level={authLevel(v)}><strong>{k.toUpperCase()}</strong> {v ? AUTH_LABEL[v] ?? v : "absent"}</li>;
              })}
            </ul>
            <p class="muted small">{e.auth
              ? <>Results added by <code>{e.auth.server || "an unnamed server"}</code>. Trust them only if that is your own mail server: a sender can write this header too.</>
              : "The message has no Authentication-Results header, so SPF, DKIM and DMARC outcomes are unknown."}</p>
          </section>

          <section class="panel" aria-labelledby="em-findings">
            <h2 id="em-findings" class="section-title">Findings <span class="count">{e.findings.filter((f) => f.severity !== "info").length}</span></h2>
            <IndicatorList indicators={e.findings} />
          </section>

          <section class="panel" aria-labelledby="em-links">
            <div class="panel-head">
              <h2 id="em-links" class="section-title">Links <span class="count">{state.links.length}</span></h2>
              <div class="row">
                <label class="field field-inline"><span class="field-label">Reported by</span>
                  <input spellcheck={false} class="input" maxLength={LIMITS.reporter} value={reporter} onInput={(ev) => setReporter(ev.currentTarget.value)} placeholder="optional" />
                </label>
                <button type="button" class="btn btn-primary btn-sm" disabled={!analysed.length || state.queued} onClick={queue}>
                  {state.queued ? "Queued as alerts" : `Queue ${analysed.length} ${analysed.length === 1 ? "link" : "links"} as alerts`}
                </button>
              </div>
            </div>
            {state.links.length === 0 ? <p class="muted">No web links were found in the message.</p> : (
              <div class="table-wrap">
                <table class="table table-cards">
                  <caption class="visually-hidden">Links in the message, most serious first</caption>
                  <thead><tr><th scope="col">Verdict</th><th scope="col">Link (defanged)</th><th scope="col">Link text</th><th scope="col">Top indicator</th></tr></thead>
                  <tbody>
                    {state.links.map(({ link, report }, i) => (
                      <tr key={i}>
                        <td>{report.ok ? <Verdict level={report.verdict.level} label={report.verdict.label} /> : <span class="muted">Rejected</span>}</td>
                        <td class="mono cell-url">{defang(report.ok ? report.url : link.url.slice(0, 200))}</td>
                        <td data-label="Link text">{link.text || <span class="muted">—</span>}</td>
                        <td data-label="Top indicator">{report.ok ? (report.indicators.find((x) => x.severity !== "info")?.title ?? <span class="muted">None</span>) : <span class="muted">{report.message}</span>}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          <section class="panel" aria-labelledby="em-att">
            <h2 id="em-att" class="section-title">Attachments <span class="count">{e.attachments.length}</span></h2>
            {e.attachments.length === 0 ? <p class="muted">None.</p> : (
              <>
                <p class="muted small">Listed only. Attachments are never opened or saved here.</p>
                <ul class="list">
                  {e.attachments.map((a, i) => <li key={i}><code class="list-main">{a.filename}</code><span class="muted">{a.contentType} · {a.size.toLocaleString("en-US")} {a.size === 1 ? "byte" : "bytes"}</span></li>)}
                </ul>
              </>
            )}
          </section>

          <details class="panel">
            <summary>All headers ({e.headers.length})</summary>
            <dl class="facts headers">
              {e.headers.map((h, i) => <div key={i}><dt>{h.name}</dt><dd class="mono">{h.value}</dd></div>)}
            </dl>
          </details>
        </div>
      )}
    </div>
  );
}
