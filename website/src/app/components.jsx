import { useEffect, useId, useRef } from "preact/hooks";
import { defang } from "../engine/defang.js";
import { LIMITS } from "../engine/verdict.js";

const PART_LABELS = {
  scheme: "Scheme", credentials: "Hidden login text", subdomain: "Subdomain", domain: "Registrable domain",
  suffix: "Public suffix", port: "Port", path: "Path", query: "Query", fragment: "Fragment",
};

export function Verdict({ level, label }) {
  return <span class="verdict" data-level={level}>{label}</span>;
}

export function Severity({ sev }) {
  return <span class="sev" data-sev={sev}>{sev}</span>;
}

export function Specimen({ segments, large = true }) {
  return (
    <p class={`specimen${large ? "" : " specimen-sm"}`} role="group" aria-label="The link split into its parts">
      {segments.map((s, i) => <span key={i} class={`seg seg-${s.part}`} title={PART_LABELS[s.part]}>{s.text}</span>)}
    </p>
  );
}

export function SpecimenKey({ segments }) {
  const parts = new Set(segments.map((s) => s.part));
  return (
    <ul class="specimen-key" aria-label="Colour key">
      {parts.has("credentials") && <li><i class="key-cred" />Hidden login text</li>}
      {parts.has("subdomain") && <li><i class="key-sub" />Subdomain (chosen by the domain owner)</li>}
      {parts.has("domain") && <li><i class="key-domain" />Registrable domain (who you would visit)</li>}
      {parts.has("suffix") && <li><i class="key-suffix" />Public suffix</li>}
    </ul>
  );
}

/** Calibrated model estimate with the artifact's operating thresholds marked. */
const SKIPPED = {
  "ip-address": "The hostname model does not score IP addresses; the verdict uses indicators only.",
  "nonstandard-idn": "The host uses characters outside the domain name standard, which the model never saw in training; the verdict uses indicators only.",
};

export function ModelMeter({ model, band, skipped = null, failed = false }) {
  if (!model) {
    return <p class="muted">{SKIPPED[skipped] ?? (failed ? "The bundled model failed its integrity check and was not loaded; the verdict uses indicators only." : null) ?? "The model estimate is not available in this build; the verdict uses indicators only."}</p>;
  }
  const pct = (x) => `${(x * 100).toFixed(1)}%`;
  return (
    <figure class="meter" data-band={band}>
      <figcaption class="meter-head">
        <span>Model estimate</span>
        <strong class="meter-value" data-band={band}>{pct(model.probability)}</strong>
      </figcaption>
      <div class="meter-track" role="img" aria-label={`Model estimate ${pct(model.probability)}; elevated from ${pct(model.thresholds.elevated)}, high from ${pct(model.thresholds.high)}`}>
        <span class="meter-zone meter-elevated" style={{ left: pct(model.thresholds.elevated), width: pct(model.thresholds.high - model.thresholds.elevated) }} />
        <span class="meter-zone meter-high" style={{ left: pct(model.thresholds.high), width: pct(1 - model.thresholds.high) }} />
        <span class="meter-mark" style={{ left: pct(model.probability) }} />
      </div>
      {band === "not-used" && (
        <p class="meter-note"><strong>Not used for this verdict:</strong> the registrable domain is on the reference list of official brand domains, where the hostname model is known to over-score.</p>
      )}
      <p class="meter-note">
        How closely the host name resembles phishing hosts in two public research datasets. Elevated from {pct(model.thresholds.elevated)}, high from {pct(model.thresholds.high)}; those thresholds gave 5% and 1% false alarms on research validation data, and more on everyday traffic.
      </p>
    </figure>
  );
}

export function IndicatorList({ indicators }) {
  const shown = indicators.filter((i) => i.severity !== "info");
  const notes = indicators.filter((i) => i.severity === "info");
  return (
    <div class="indicators">
      {shown.length === 0 && <p class="muted">No indicators were found in the link text.</p>}
      <ol class="ind-list">
        {shown.map((i) => (
          <li key={i.id} class="ind" data-sev={i.severity}>
            <Severity sev={i.severity} />
            <div>
              <p class="ind-title">{i.title}</p>
              <p class="ind-detail">{i.detail}</p>
              <p class="ind-evidence"><span class="muted">Evidence</span> <code>{i.evidence}</code></p>
            </div>
          </li>
        ))}
      </ol>
      {notes.length > 0 && (
        <ul class="ind-notes">
          {notes.map((i) => <li key={i.id}><strong>{i.title}.</strong> {i.detail}</li>)}
        </ul>
      )}
    </div>
  );
}

export function Facts({ report }) {
  const f = report.facts;
  const rows = [
    ["Registrable domain", f.registrableDomain ?? (f.isIp ? "— (IP address)" : "— (host is a public suffix)")],
    ["Host", f.displayHost === f.host ? f.host : `${f.displayHost} (registered as ${f.host})`],
    ["Subdomain", f.subdomain || "none"],
    ["Public suffix", f.publicSuffix ?? "—"],
    ["Scheme", f.schemeExplicit ? f.scheme : "not given (analysed as http)"],
    ["Port", f.port ?? "default"],
    ["Defanged", defang(report.url)],
  ];
  return (
    <dl class="facts">
      {rows.map(([k, v]) => <div key={k}><dt>{k}</dt><dd class={k === "Defanged" || k === "Host" ? "mono" : ""}>{v}</dd></div>)}
    </dl>
  );
}

export function Limits() {
  return (
    <ul class="limits">
      {LIMITS.map((l) => <li key={l}>{l}</li>)}
    </ul>
  );
}

export function PageHeader({ title, description, children }) {
  return (
    <header class="page-head">
      <div>
        <h1 class="page-title" tabIndex={-1} data-page-title>{title}</h1>
        {description && <p class="page-desc">{description}</p>}
      </div>
      {children && <div class="page-actions">{children}</div>}
    </header>
  );
}

export function Empty({ title, children }) {
  return (
    <div class="empty">
      <h2 class="empty-title">{title}</h2>
      {children}
    </div>
  );
}

export function Time({ iso }) {
  const d = new Date(iso);
  if (!iso || Number.isNaN(d.getTime())) return null;
  return <time dateTime={iso} title={d.toISOString()}>{d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", hourCycle: "h23" })}</time>;
}

/** Native <dialog> with focus management handled by the browser. */
export function Dialog({ open, title, onClose, children }) {
  const ref = useRef(null);
  const titleId = useId();
  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) d.showModal();
    if (!open && d.open) d.close();
  }, [open]);
  return (
    <dialog ref={ref} class="dialog" aria-labelledby={titleId} onClose={onClose} onCancel={onClose}>
      <div class="dialog-head">
        <h2 id={titleId}>{title}</h2>
        <button type="button" class="btn btn-quiet btn-sm" onClick={onClose}>Close</button>
      </div>
      <div class="dialog-body">{open && children}</div>
    </dialog>
  );
}
