// Runtime for the exported hashed character n-gram logistic regression
// ("securemind.charngram-logreg/1"). Reproduces scikit-learn's
// HashingVectorizer(analyzer="char", alternate_sign=False, norm="l2") followed
// by LogisticRegression, then Platt calibration. The model artifact is
// produced by `phase3/run.py engine`; golden vectors check parity.

import { murmurhash3_32 } from "./murmurhash3.js";
import { onceUnlessFailed } from "./once.js";

export const MODEL_FORMAT = "securemind.charngram-logreg/1";
const encoder = new TextEncoder();

/** Text the HOST-view model sees: the hostname minus one leading "www.". */
export function hostText(hostname) {
  return hostname.startsWith("www.") && hostname.split(".").length - 1 >= 2 ? hostname.slice(4) : hostname;
}

function bucket(h, nFeatures) {
  // sklearn: abs(-2**31) overflows; it maps that single value explicitly.
  if (h === -2147483648) return (2147483647 - (nFeatures - 1)) % nFeatures;
  return Math.abs(h) % nFeatures;
}

/** Character n-grams over code points, as Python slices a str. */
export function charNgrams(text, [minN, maxN]) {
  const cps = Array.from(text.replace(/\s\s+/gu, " "));
  const out = [];
  for (let n = minN; n <= Math.min(maxN, cps.length); n++) {
    for (let i = 0; i + n <= cps.length; i++) out.push(cps.slice(i, i + n).join(""));
  }
  return out;
}

function decodeCoefficients(model) {
  const bin = atob(model.coefBase64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  const view = new DataView(bytes.buffer);
  const coef = new Float64Array(model.nFeatures);
  const width = model.coefEncoding === "int8" ? 1 : 2;
  if (bytes.length !== model.nFeatures * width) throw new Error("model coefficients have the wrong length");
  for (let i = 0; i < model.nFeatures; i++) {
    const q = width === 1 ? view.getInt8(i) : view.getInt16(i * 2, true);
    coef[i] = q * model.coefScale;
  }
  return coef;
}

/**
 * Build a scorer from a model artifact. Throws on an unknown format so a
 * mismatched artifact can never silently produce numbers.
 */
export function createScorer(model) {
  if (!model || model.format !== MODEL_FORMAT) throw new Error("unsupported model format");
  if (model.hash !== "murmurhash3_32/seed0/abs-mod" || model.norm !== "l2" || model.analyzer !== "char") {
    throw new Error("unsupported model settings");
  }
  const coef = decodeCoefficients(model);
  const { a, b } = model.calibration;

  function logit(text) {
    const counts = new Map();
    for (const gram of charNgrams(text, model.ngramRange)) {
      const idx = bucket(murmurhash3_32(encoder.encode(gram), 0), model.nFeatures);
      counts.set(idx, (counts.get(idx) || 0) + 1);
    }
    let norm = 0;
    for (const c of counts.values()) norm += c * c;
    norm = Math.sqrt(norm);
    let z = model.intercept;
    if (norm > 0) for (const [idx, c] of counts) z += (c / norm) * coef[idx];
    return z;
  }

  return {
    id: model.id,
    thresholds: model.thresholds,
    evaluation: model.evaluation,
    logit,
    /** Calibrated probability that the host resembles phishing hosts in the training data. */
    score(hostname) {
      const text = hostText(hostname);
      const z = logit(text);
      return { text, logit: z, probability: 1 / (1 + Math.exp(-(a * z + b))) };
    },
  };
}

// Fields that decide every score. The model id is the SHA-256 of these
// fields in the canonical form below, computed identically by the Python
// exporter (phase3/src/phishlab/engine.py: canonical, model_identity).
export const SCORING_FIELDS = Object.freeze(["format", "view", "analyzer", "ngramRange", "nFeatures", "lowercase", "norm", "hash",
  "intercept", "coefEncoding", "coefScale", "coefBase64", "calibration", "thresholds"]);

// Python json.dumps(ensure_ascii=True) escapes every UTF-16 unit above U+007F.
const jsonAscii = (s) => JSON.stringify(s).replace(/[\u0080-\uffff]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);

/** Keys sorted, strings as ASCII JSON, numbers as their IEEE-754 binary64 bits. */
export function canonical(value) {
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    const view = new DataView(new ArrayBuffer(8));
    view.setFloat64(0, value);
    return `0x${[...new Uint8Array(view.buffer)].map((b) => b.toString(16).padStart(2, "0")).join("")}`;
  }
  if (typeof value === "string") return jsonAscii(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((k) => `${jsonAscii(k)}:${canonical(value[k])}`).join(",")}}`;
  }
  throw new TypeError(`cannot canonicalise ${typeof value}`);
}

/** { id, sha256 } derived from the artifact's scoring fields. */
export async function modelIdentity(model) {
  const missing = SCORING_FIELDS.filter((f) => !(f in model));
  if (missing.length) throw new Error(`model metadata lacks ${missing.join(", ")}`);
  const text = canonical(Object.fromEntries(SCORING_FIELDS.map((f) => [f, model[f]])));
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  const sha256 = [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
  return { id: `url-host-${sha256.slice(0, 16)}`, sha256 };
}

/** Build a scorer only if the artifact matches its content-addressed id. */
export async function verifiedScorer(model) {
  const { id, sha256 } = await modelIdentity(model);
  if (model.id !== id || model.sha256 !== sha256) throw new Error("the model artifact does not match its id");
  return createScorer(model);
}

/**
 * Lazily import the bundled artifact (a same-origin module; no fetch) and
 * verify it. Resolves to null when no artifact is bundled, so the platform
 * still works with indicators alone and says so; rejects when the artifact
 * fails its integrity check. Browser/Vite only.
 */
export const loadModel = onceUnlessFailed(() => {
  const load = import.meta.glob("./models/url-host-model.js")["./models/url-host-model.js"];
  return load ? load().then(({ MODEL }) => verifiedScorer(MODEL)) : Promise.resolve(null);
});
