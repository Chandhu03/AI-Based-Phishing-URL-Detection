// Public Suffix List lookup (https://github.com/publicsuffix/list/wiki/Format).
// Exception rules win; otherwise the longest matching rule (wildcards
// included) prevails; "*" is the default. ICANN and PRIVATE sections are both
// used, so hosts on shared platforms (e.g. name.github.io) group by owner.

import { onceUnlessFailed } from "./once.js";

export class PublicSuffixList {
  /** @param {string[]} rules  @param {string|null} [commit] PSL commit the rules come from */
  constructor(rules, commit = null) {
    this.commit = commit;
    this.exact = new Set();
    this.wildcard = new Set();
    this.exception = new Set();
    for (const rule of rules) {
      if (rule.startsWith("!")) this.exception.add(rule.slice(1));
      else if (rule.startsWith("*.")) this.wildcard.add(rule.slice(2));
      else this.exact.add(rule);
    }
  }

  // Split a valid ASCII (punycode), lowercase hostname without a trailing dot
  // (as dissect() produces) into its public suffix and its registrable domain
  // (eTLD+1), which is null when the host is itself a public suffix.
  split(host) {
    const labels = host.split(".");
    const n = labels.length;
    let best = 1;
    for (let i = 0; i < n; i++) {
      const name = labels.slice(i).join(".");
      if (this.exception.has(name)) {
        best = n - i - 1;
        break;
      }
      const k = n - i;
      if (this.exact.has(name) && k > best) best = k;
      if (i > 0 && this.wildcard.has(name) && k + 1 > best) best = k + 1;
    }
    return {
      publicSuffix: labels.slice(n - best).join("."),
      registrableDomain: best < n ? labels.slice(n - best - 1).join(".") : null,
    };
  }
}

// Lazily load the ~150 kB rule set the first time it is needed (same-origin
// module request; the submitted URL is never part of that request).
export const loadPsl = onceUnlessFailed(() =>
  import("./generated/psl-rules.js").then(({ RULES, PSL_COMMIT }) => new PublicSuffixList(RULES, PSL_COMMIT)));
