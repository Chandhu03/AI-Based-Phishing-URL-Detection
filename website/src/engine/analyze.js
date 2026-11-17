// The analysis service: one entry point used by the workspace, the public
// site and the batch CLI. It parses, derives indicators, scores the host with
// the bundled model and decides a qualified verdict. It never performs
// network I/O; the PSL and model are bundled modules.

import { maskUserinfo, refang } from "./defang.js";
import { detectIndicators, SEVERITIES } from "./indicators.js";
import { dissect } from "./url-anatomy.js";
import { decideVerdict } from "./verdict.js";

const ENGINE_VERSION = "2.0.0";

const SEVERITY_ORDER = Object.fromEntries(SEVERITIES.map((s, i) => [s, i]));

/**
 * Analyse one URL string.
 * @param {string} raw            untrusted input; defanged forms are accepted
 * @param {{psl: object, scorer?: object|null, now?: () => Date}} deps
 * @returns {{ok:false, code:string, message:string} | object}
 */
export function analyzeUrl(raw, { psl, scorer = null, now = () => new Date() }) {
  const input = typeof raw === "string" ? refang(raw) : raw;
  const facts = dissect(input, psl);
  if (!facts.ok) return facts;

  const indicators = detectIndicators(facts).sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  let model = null;
  let modelError = null;
  // The model was trained on host names that pass IDNA2008. IP addresses
  // (local addresses scored "high") and names outside IDNA2008 are outside
  // what it measured, so they are not scored.
  const modelSkipped = facts.isIp ? "ip-address" : facts.idnaProblem ? "nonstandard-idn" : null;
  if (scorer && !modelSkipped) {
    try {
      const s = scorer.score(facts.host);
      model = { id: scorer.id, probability: s.probability, logit: s.logit, text: s.text, thresholds: scorer.thresholds };
    } catch {
      modelError = "The model could not score this host.";
    }
  }
  const verdict = decideVerdict(indicators, model, { skipped: modelSkipped });

  return {
    ok: true,
    url: facts.href,
    // The link as written, with login text masked: re-analysing it reproduces
    // this report (used to rebuild analyses from a backup).
    input: maskUserinfo(input),
    analyzedAt: now().toISOString(),
    engine: { version: ENGINE_VERSION, modelId: model?.id ?? null, pslCommit: psl.commit ?? "unknown" },
    facts: {
      scheme: facts.scheme,
      schemeExplicit: facts.schemeExplicit,
      host: facts.host,
      displayHost: facts.displayHost,
      registrableDomain: facts.registrableDomain,
      publicSuffix: facts.publicSuffix,
      subdomain: facts.subdomain,
      isIp: facts.isIp,
      ipVersion: facts.ipVersion,
      port: facts.port,
      path: facts.path,
      query: facts.query,
      fragment: facts.fragment,
      hasCredentials: facts.hasCredentials,
      idnaProblem: facts.idnaProblem,
    },
    segments: facts.segments,
    indicators,
    model,
    modelSkipped,
    modelError,
    verdict,
  };
}

/** Split pasted text into candidate URLs, one per line. */
export function splitBatch(text, limit = 500) {
  const items = String(text)
    .split(/[\r\n]+/)
    .map((l) => l.trim())
    .filter(Boolean);
  return { items: items.slice(0, limit), truncated: items.length > limit };
}
