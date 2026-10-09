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
