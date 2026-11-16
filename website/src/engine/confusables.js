// Look-alike folding for homograph and typosquat checks.
//
// `skeleton()` maps characters that render like Latin letters to those
// letters. The table is a focused subset of Unicode's confusables data
// (UTS #39) for Cyrillic, Greek and Armenian letters that imitate a-z, plus
// common ASCII substitutions used in typosquats. It is deliberately small:
// it only needs to fold the label being compared, never to render text.

const MAP = new Map(Object.entries({
  // Cyrillic
  "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
  "і": "i", "ј": "j", "ԁ": "d", "һ": "h", "ӏ": "l", "ѕ": "s", "ԛ": "q",
  "ԝ": "w", "ɡ": "g", "в": "b", "к": "k", "м": "m", "н": "h", "т": "t",
  "ь": "b", "ї": "i", "ґ": "r",
  // Greek
  "ο": "o", "α": "a", "ν": "v", "ρ": "p", "ι": "i", "κ": "k", "τ": "t",
  "υ": "u", "ω": "w", "ε": "e", "η": "n", "χ": "x",
  // Armenian
  "օ": "o", "ո": "n", "ս": "u", "հ": "h", "զ": "q", "ց": "g",
  // Latin extended look-alikes
  "ı": "i", "ɩ": "i", "ǀ": "l", "ɑ": "a", "ø": "o", "đ": "d",
}));

const ASCII_SUBSTITUTIONS = [
  ["rn", "m"], ["vv", "w"], ["cl", "d"], ["0", "o"], ["1", "l"], ["3", "e"], ["5", "s"], ["$", "s"], ["@", "a"],
];

/** Fold confusable non-Latin characters and strip accents. */
export function skeleton(text) {
  let out = "";
  for (const ch of text.normalize("NFKD")) {
    if (/\p{M}/u.test(ch)) continue;
    out += MAP.get(ch) ?? ch.toLowerCase();
  }
  return out;
}

/** Additionally fold common ASCII typosquat substitutions. */
export function asciiFold(text) {
  let out = skeleton(text);
  for (const [from, to] of ASCII_SUBSTITUTIONS) out = out.split(from).join(to);
  return out;
}

/** Optimal-string-alignment distance (Levenshtein plus adjacent swaps), capped. */
export function editDistance(a, b, cap = 3) {
  if (Math.abs(a.length - b.length) > cap) return cap + 1;
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...new Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
    }
  }
  return d[a.length][b.length];
}
