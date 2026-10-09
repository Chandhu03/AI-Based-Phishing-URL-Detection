// Public Suffix List lookup (https://github.com/publicsuffix/list/wiki/Format).
// Exception rules win; otherwise the longest matching rule (wildcards
// included) prevails; "*" is the default. ICANN and PRIVATE sections are both
// used, so hosts on shared platforms (e.g. name.github.io) group by owner.

export class PublicSuffixList {
  constructor(rules) {
    this.exact = new Set();
    this.wildcard = new Set();
    this.exception = new Set();
    for (const rule of rules) {
      if (rule.startsWith("!")) this.exception.add(rule.slice(1));
      else if (rule.startsWith("*.")) this.wildcard.add(rule.slice(2));
      else this.exact.add(rule);
    }
  }

  // Public suffix of an ASCII (punycode), lowercase hostname.
  publicSuffix(host) {
    const labels = host.split(".");
    const n = labels.length;
    let best = 1;
    for (let i = 0; i < n; i++) {
      const name = labels.slice(i).join(".");
      if (this.exception.has(name)) return labels.slice(i + 1).join(".");
      const k = n - i;
      if (this.exact.has(name) && k > best) best = k;
      if (i > 0 && this.wildcard.has(name) && k + 1 > best) best = k + 1;
    }
    return labels.slice(n - best).join(".");
  }

  // eTLD+1, or null when the host is itself a public suffix or malformed.
  registrableDomain(host) {
    const h = String(host).toLowerCase().replace(/\.$/, "");
    if (!h || h.startsWith(".") || h.includes("..")) return null;
    const suffix = this.publicSuffix(h);
    if (h === suffix) return null;
    const rest = h.slice(0, -suffix.length - 1);
    return `${rest.slice(rest.lastIndexOf(".") + 1)}.${suffix}`;
  }
}

let cached;
// Lazily load the ~150 kB rule set the first time it is needed (same-origin
// module request; the submitted URL is never part of that request).
export async function loadPsl() {
  if (!cached) {
    cached = import("./generated/psl-rules.js").then(({ RULES }) => new PublicSuffixList(RULES));
  }
  return cached;
}
