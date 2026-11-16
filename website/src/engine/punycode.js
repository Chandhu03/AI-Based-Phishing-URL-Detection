// Minimal RFC 3492 Punycode decoder, used only to *display* internationalised
// labels ("xn--...") the way a reader would see them. Returns null for input
// that is not valid Punycode.

const BASE = 36, TMIN = 1, TMAX = 26, SKEW = 38, DAMP = 700, INITIAL_BIAS = 72, INITIAL_N = 128;

function adapt(delta, numPoints, first) {
  delta = first ? Math.floor(delta / DAMP) : delta >> 1;
  delta += Math.floor(delta / numPoints);
  let k = 0;
  while (delta > ((BASE - TMIN) * TMAX) >> 1) {
    delta = Math.floor(delta / (BASE - TMIN));
    k += BASE;
  }
  return k + Math.floor(((BASE - TMIN + 1) * delta) / (delta + SKEW));
}

function digitValue(cp) {
  if (cp >= 48 && cp <= 57) return cp - 22; // 0-9 -> 26-35
  if (cp >= 65 && cp <= 90) return cp - 65; // A-Z
  if (cp >= 97 && cp <= 122) return cp - 97; // a-z
  return BASE;
}

export function decodePunycode(input) {
  const output = [];
  const basicEnd = input.lastIndexOf("-");
  for (let j = 0; j < Math.max(basicEnd, 0); j++) {
    if (input.charCodeAt(j) >= 0x80) return null;
    output.push(input.charCodeAt(j));
  }
  let n = INITIAL_N, bias = INITIAL_BIAS, i = 0;
  for (let index = basicEnd > 0 ? basicEnd + 1 : 0; index < input.length;) {
    const oldi = i;
    for (let w = 1, k = BASE; ; k += BASE) {
      if (index >= input.length) return null;
      const digit = digitValue(input.charCodeAt(index++));
      if (digit >= BASE) return null;
      i += digit * w;
      const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
      if (digit < t) break;
      w *= BASE - t;
      if (w > 0x7fffffff) return null;
    }
    const length = output.length + 1;
    bias = adapt(i - oldi, length, oldi === 0);
    n += Math.floor(i / length);
    i %= length;
    if (n > 0x10ffff) return null;
    output.splice(i++, 0, n);
  }
  return String.fromCodePoint(...output);
}

// Decode every "xn--" label of an ASCII hostname for display.
export function toUnicodeHost(asciiHost) {
  return asciiHost
    .split(".")
    .map((label) => {
      if (!label.startsWith("xn--")) return label;
      const decoded = decodePunycode(label.slice(4));
      return decoded ?? label;
    })
    .join(".");
}

// Code points IDNA2008 (RFC 5891/5892) permits in a label, approximated with
// Unicode properties: lowercase or caseless letters, combining marks and
// decimal digits that are stable under NFKC and lowercasing. Symbols, emoji,
// punctuation, fractions and compatibility forms are excluded. The joiners
// and the few punctuation marks IDNA2008 allows only in context are excluded
// too, so this check is slightly stricter than the standard.
const PVALID = /^[\p{Ll}\p{Lo}\p{Lm}\p{Mn}\p{Mc}\p{Nd}]$/u;
// Disallowed although their general category looks allowed: RFC 5892
// "OldHangulJamo" (conjoining jamo; precomposed syllables are fine) and the
// combining marks for symbols, which the IDNA2008 tables list as DISALLOWED.
const DISALLOWED_MARKS = /^[\u1100-\u11ff\ua960-\ua97f\ud7b0-\ud7ff\u20d0-\u20ff]$/u;
// Cherokee case-folds to its capital letters, so IDNA2008 keeps those.
const CHEROKEE_CAPITAL = /^[\u13a0-\u13f5]$/u;

// RFC 5893 bidi rule, with bidi classes approximated by script: right-to-left
// letters (R, AL), Arabic-Indic digits (AN), European digits (EN) and
// non-spacing marks (NSM). Applied to labels that contain RTL characters, as
// Python's idna does.
const RTL = /[\p{Script=Arabic}\p{Script=Hebrew}\p{Script=Syriac}\p{Script=Thaana}\p{Script=Nko}\p{Script=Samaritan}\p{Script=Mandaic}\p{Script=Adlam}\p{Script=Hanifi_Rohingya}\p{Script=Mende_Kikakui}]/u;
const bidiClass = (ch) => {
  if (/^[\u0660-\u0669\u066b\u066c]$/u.test(ch)) return "AN";
  if (/^[0-9\u06f0-\u06f9]$/u.test(ch)) return "EN";
  if (/^[\p{Mn}\p{Me}]$/u.test(ch)) return "NSM";
  if (ch === "-") return "ES";
  if (RTL.test(ch)) return "R";
  return "L";
};
function bidiProblem(u) {
  const classes = [...u].map(bidiClass);
  if (!classes.some((c) => c === "R" || c === "AN")) return false;
  if (classes[0] !== "R") return true;
  if (classes.includes("L")) return true;
  if (classes.includes("EN") && classes.includes("AN")) return true;
  const last = classes.filter((c) => c !== "NSM").at(-1);
  return !["R", "EN", "AN"].includes(last);
}

/**
 * Why an ASCII (punycode) host is not a valid IDNA2008 name, or null. Browsers
 * follow the more permissive UTS #46 rules, so they open hosts such as emoji
 * names that domain registries and Python's strict "idna" codec reject.
 */
export function idnaProblem(asciiHost) {
  for (const label of asciiHost.split(".")) {
    if (!/^xn--/i.test(label)) continue;
    const u = label.length > 4 && !label.endsWith("-") ? decodePunycode(label.slice(4).toLowerCase()) : null;
    if (!u) return "invalid-punycode";
    if (u.normalize("NFC") !== u) return "not-normalised";
    if (/^\p{M}/u.test(u) || u.startsWith("-") || u.endsWith("-") || u.slice(2, 4) === "--") return "invalid-label-form";
    for (const ch of u) {
      if (ch === "-" || /^[a-z0-9]$/.test(ch)) continue;
      if (CHEROKEE_CAPITAL.test(ch)) continue;
      if (DISALLOWED_MARKS.test(ch)) return "disallowed-character";
      if (!PVALID.test(ch) || ch.normalize("NFKC").toLowerCase() !== ch) return "disallowed-character";
    }
    if (bidiProblem(u)) return "mixed-direction";
  }
  return null;
}
