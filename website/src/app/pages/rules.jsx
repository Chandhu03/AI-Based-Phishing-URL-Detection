import { useState } from "preact/hooks";
import { defang } from "../../engine/defang.js";
import { LIMITS, PRIORITIES, RULE_DISPOSITIONS, SHARED_DOMAINS } from "../../workspace/workspace.js";
import { Empty, PageHeader, Time } from "../components.jsx";
import { useAction, useApp, useData } from "../context.js";

const FIELD_LABEL = { url: "URL is exactly", host: "Host is exactly", domain: "Registrable domain is", source: "Source is" };
const DISPOSITION_LABEL = { benign: "benign", "false-positive": "false positive", duplicate: "duplicate" };
/** A rule name for a suggested host, within the name limit (an ellipsis marks a shortened host). */
const suggestionName = (host) => {
  const name = `Known good: ${host}`;
  return name.length <= LIMITS.ruleName ? name : `${name.slice(0, LIMITS.ruleName - 1)}…`;
};
const describeAction = (a) => (a.type === "close" ? `Close as ${DISPOSITION_LABEL[a.disposition]}` : `Set severity to ${a.severity}`);

/** Queue rules: exact-match automation applied once, when an alert is queued. */
export function Rules() {
  const { ws } = useApp();
  const act = useAction();
  const { data: rules = [] } = useData(() => ws.listRules());
  const { data: suggestions = [] } = useData(() => ws.ruleSuggestions());
  const [form, setForm] = useState({ name: "", field: "host", value: "", action: "close", disposition: "benign", severity: "high" });
  const set = (k) => (e) => setForm({ ...form, [k]: e.currentTarget.value });
  const shared = form.action === "close" && form.field === "domain" && SHARED_DOMAINS.includes(form.value.trim().toLowerCase().replace(/\.$/, ""));

  return (
    <div class="stack">
      <PageHeader title="Queue rules" description="Rules act when an alert is queued, never on alerts already in the queue. Each matches one exact value; the oldest matching rule wins. A rule never closes a link judged high risk or suspicious.">
        <a class="btn btn-secondary" href="#/alerts">Back to the queue</a>
      </PageHeader>

      <section class="panel stack" aria-labelledby="rule-new">
        <h2 id="rule-new" class="section-title">Add a rule</h2>
        <form class="stack" onSubmit={async (e) => {
          e.preventDefault();
          if (await act(() => ws.createRule(form), "Rule added.")) setForm({ ...form, name: "", value: "" });
        }}>
          <div class="form-row">
            <label class="field"><span class="field-label">Name</span><input spellcheck={false} class="input" required maxLength={LIMITS.ruleName} value={form.name} onInput={set("name")} placeholder="Vendor newsletter" /></label>
            <label class="field"><span class="field-label">When</span>
              <select class="select" value={form.field} onChange={set("field")}>
                {Object.entries(FIELD_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
              </select>
            </label>
          </div>
          <label class="field"><span class="field-label">Value</span>
            <input spellcheck={false} class="input input-mono" required maxLength={LIMITS.value} value={form.value} onInput={set("value")}
              placeholder={{ url: "https://news.vendor.example/issue", host: "news.vendor.example", domain: "vendor.example", source: "sandbox" }[form.field]} />
          </label>
          <div class="form-row">
            <label class="field"><span class="field-label">Then</span>
              <select class="select" value={form.action} onChange={set("action")}>
                <option value="close">Close the alert</option>
                <option value="severity">Set its severity</option>
              </select>
            </label>
            {form.action === "close" ? (
              <label class="field"><span class="field-label">Disposition</span>
                <select class="select" value={form.disposition} onChange={set("disposition")}>
                  {RULE_DISPOSITIONS.map((d) => <option key={d} value={d}>{DISPOSITION_LABEL[d]}</option>)}
                </select>
              </label>
            ) : (
              <label class="field"><span class="field-label">Severity</span>
                <select class="select" value={form.severity} onChange={set("severity")}>
                  {[...PRIORITIES].reverse().map((p) => <option key={p} value={p}>{p}</option>)}
                </select>
              </label>
            )}
          </div>
          {form.action === "close" && form.field === "domain" && (
            <p class={shared ? "field-error" : "field-hint"} role={shared ? "alert" : undefined}>
              {shared
                ? `Anyone can publish on ${form.value.trim()}, so a domain rule cannot close its alerts. Use a host or URL rule for a known address.`
                : "A domain rule closes alerts for every host under that domain. Do not use it for platforms where anyone can publish pages or files."}
            </p>
          )}
          <div class="row"><button class="btn btn-primary" type="submit" disabled={shared}>Add rule</button></div>
        </form>
      </section>

      {suggestions.length > 0 && (
        <section class="panel stack" aria-labelledby="rule-suggest">
          <h2 id="rule-suggest" class="section-title">Suggested from your closes</h2>
          <p class="muted small">Hosts that analysts closed as benign, false positive or duplicate more than once, never judged high risk or suspicious. A host rule closes only that exact host. Nothing is added until you choose to.</p>
          <ul class="list">
            {suggestions.map((sg) => (
              <li key={sg.host}>
                <code class="list-main">{defang(sg.host)}</code>
                <span class="muted">closed {sg.alerts}× as {DISPOSITION_LABEL[sg.disposition]}</span>
                <button type="button" class="btn btn-secondary btn-sm" onClick={() => act(() => ws.createRule({
                  name: suggestionName(sg.host), field: "host", value: sg.host, action: "close", disposition: sg.disposition,
                }), "Rule added.")}>Add rule<span class="visually-hidden"> for {defang(sg.host)}</span></button>
              </li>
            ))}
          </ul>
        </section>
      )}

      {rules.length === 0 ? (
        <Empty title="No queue rules yet."><p>Every alert waits for an analyst until you add one.</p></Empty>
      ) : (
        <section class="panel" aria-labelledby="rule-list">
          <h2 id="rule-list" class="section-title">Rules, in the order they are tried</h2>
          <div class="table-wrap">
            <table class="table table-cards">
              <thead><tr><th scope="col">Name</th><th scope="col">When</th><th scope="col">Then</th><th scope="col">Matched</th><th scope="col">On</th><th scope="col"><span class="visually-hidden">Actions</span></th></tr></thead>
              <tbody>
                {rules.map((r) => (
                  <tr key={r.id}>
                    <td>{r.name}</td>
                    <td data-label="When">{FIELD_LABEL[r.match.field]} <code>{r.match.field === "source" ? r.match.value : defang(r.match.value)}</code></td>
                    <td data-label="Then">{describeAction(r.action)}</td>
                    <td data-label="Matched">{r.hits}×{r.lastHitAt && <span class="muted"> · last <Time iso={r.lastHitAt} /></span>}</td>
                    <td data-label="On">
                      <label class="check-all"><input type="checkbox" checked={r.enabled} onChange={(e) => act(() => ws.setRuleEnabled(r.id, e.currentTarget.checked), e.currentTarget.checked ? "Rule switched on." : "Rule switched off.")} />
                        <span class="visually-hidden">Rule “{r.name}” is on</span></label>
                    </td>
                    <td><button type="button" class="btn btn-quiet btn-sm" onClick={() => { if (confirm(`Delete the rule “${r.name}”?`)) act(() => ws.deleteRule(r.id), "Rule deleted."); }}>Delete<span class="visually-hidden"> rule {r.name}</span></button></td>
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
