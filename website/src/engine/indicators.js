// Explainable risk indicators computed from a dissected URL (url-anatomy.js).
// Every indicator states the evidence it found in the link text. None of
// them looks anything up or visits the link.
//
// Severity is the weight an indicator carries in verdict.js:
//   high   - a construction whose usual purpose is to deceive
//   medium - common in phishing, but with legitimate uses
//   low    - weak on its own; meaningful in combination
//   info   - context for the analyst, never raises the verdict

import { BRAND_LABELS, BRANDS, LURE_WORDS, SHARED_HOSTING_SUFFIXES, SHORTENERS, WORD_TOKENS, officialBrandFor } from "./brands.js";
import { asciiFold, editDistance, skeleton } from "./confusables.js";

export const SEVERITIES = Object.freeze(["high", "medium", "low", "info"]);

const HOST_KEYWORDS = ["login", "signin", "logon", "verify", "verification", "secure", "account", "update", "confirm",
  "wallet", "password", "unlock", "recover", "billing", "auth", "webscr", "suspend", "validate"];
const PATH_CREDENTIAL_WORDS = /(log-?in|sign-?in|logon|password|passwd|verify|account|auth|credential|wallet|ssn|banking)/i;
const DOWNLOAD_EXTENSIONS = /\.(exe|scr|msi|bat|cmd|com|pif|hta|js|jse|vbs|vbe|wsf|ps1|jar|apk|dmg|pkg|iso|img|vhd|lnk|zip|rar|7z|docm|xlsm|pptm)$/i;
const FREE_TLDS = new Set(["tk", "ml", "ga", "cf", "gq"]);
const DOMAIN_LIKE_LABELS = new Set(["com", "net", "org", "gov", "edu", "co", "io", "info", "biz"]);
const REDIRECT_PARAM = /^(url|uri|u|redirect|redirect_uri|redirect_url|redir|next|dest|destination|continue|return|returnurl|return_to|goto|target|link|out|to)$/i;

function make(id, severity, category, title, detail, evidence) {
  return { id, severity, category, title, detail, evidence };
}

function hostEndsWith(host, suffix) {
  return host === suffix || host.endsWith(`.${suffix}`);
}

/**
 * Whether a brand token occurs in a host label. Distinctive tokens match as
 * substrings. Word-like tokens (see WORD_TOKENS) match only as the whole
 * label, next to a lure word ("applesupport", "myapple"), or as a hyphen- or
 * digit-separated piece in a label that also has a lure piece
 * ("apple-id-verify"); "pineapple", "purchase" and "apple-pie-recipes" do not.
 */
export function labelHasToken(label, token) {
  if (!WORD_TOKENS.has(token)) return label.includes(token);
  if (label === token) return true;
  const pieces = label.split(/[-\d]+/).filter(Boolean);
  const isLure = (w) => LURE_WORDS.includes(w);
  return pieces.some((p, i) => {
    if (p === token) return pieces.some((q, j) => j !== i && isLure(q));
    for (let k = p.indexOf(token); k !== -1; k = p.indexOf(token, k + 1)) {
      const left = p.slice(0, k);
      const right = p.slice(k + token.length);
      const leftOk = left === "" || LURE_WORDS.some((w) => left.endsWith(w));
      const rightOk = right === "" || LURE_WORDS.some((w) => right.startsWith(w));
      if (leftOk && rightOk && (left || right)) return true;
    }
    return false;
  });
}

function brandFindings(f, out, userContent) {
  if (!f.registrableDomain) return;
  // On a domain a brand operates, that brand's own name is expected; other
  // brands' names are still checked. On user-content hosts of that domain
  // (SharePoint sites, Google Sites...) anyone can publish, so the operator's
  // name in the subdomain or path is checked too; only the registrable label,
  // which is the operator's own, is skipped.
  const operator = officialBrandFor(f.registrableDomain);
  const official = userContent ? null : operator;
  const where = userContent ? `a user-hosted site on ${f.registrableDomain}, where anyone can publish` : null;
  const regLabel = f.registrableDomain.slice(0, -(f.publicSuffix.length + 1));
  const regDisplay = (f.decodedHost ?? f.displayHost).split(".").slice(-f.registrableDomain.split(".").length)[0] ?? regLabel;
  const subLabels = f.subdomain ? f.subdomain.split(".") : [];
  const seen = new Set(official ? [official.id] : []);

  for (const brand of BRANDS) {
    for (const token of brand.tokens) {
      if (seen.has(brand.id)) break;
      if (subLabels.some((l) => labelHasToken(l, token))) {
        seen.add(brand.id);
        out.push(make("brand-in-subdomain", "high", "impersonation", `${brand.name} name used in a subdomain`,
          where
            ? `“${token}” appears in the subdomain of ${where}. The name does not mean ${brand.name} runs this site.`
            : `“${token}” appears in the subdomain, but the site is ${f.registrableDomain}, which is not a domain ${brand.name} uses. Anyone who owns ${f.registrableDomain} can choose any subdomain.`,
          f.subdomain));
      } else if (brand.id === operator?.id) {
        continue; // the registrable label is the operator's own name
      } else if (regLabel === token) {
        seen.add(brand.id);
        // amazon.com.mx, dhl.fr: most likely a regional site the curated list
        // lacks, so it is noted, not weighed like paypal.xyz.
        const country = /^[a-z]{2}$/.test(f.publicSuffix.split(".").pop());
        out.push(make("brand-unlisted-domain", country ? "low" : "medium", "impersonation", `${brand.name} name on a domain it is not known to use`,
          country
            ? `The registrable domain ${f.registrableDomain} is the brand name on a country suffix. It may be a regional ${brand.name} site missing from the reference list; check it before trusting it.`
            : `The registrable domain ${f.registrableDomain} matches the brand name, but it is not in the reference list of ${brand.name} domains. Brands rarely operate on unexpected suffixes.`,
          f.registrableDomain));
      } else if (labelHasToken(regLabel, token)) {
        seen.add(brand.id);
        out.push(make("brand-in-domain", "high", "impersonation", `${brand.name} name combined with other words`,
          `The domain ${f.registrableDomain} embeds “${token}” with other text. ${brand.name}’s known domains do not include it.`,
          f.registrableDomain));
      }
    }
  }

  if (operator) {
    if (userContent) pathBrandFinding(f, out, seen, where);
    return;
  }
  // Homograph: the displayed label folds to a brand name but is not it.
  const folded = skeleton(regDisplay);
  const homograph = BRAND_LABELS.find(({ label }) => folded === label && regDisplay !== label);
  if (homograph && !seen.has(homograph.brand.id)) {
    seen.add(homograph.brand.id);
    out.push(make("homograph", "high", "impersonation", `Look-alike of ${homograph.brand.name}`,
      `“${regDisplay}” uses characters that look like “${homograph.label}” but are different letters. It is registered as ${f.registrableDomain}.`,
      f.registrableDomain));
    return;
  }

  // Typosquat: a near miss of a brand name (character swaps or substitutions).
  if (/^[a-z0-9-]+$/.test(regLabel)) {
    const plain = regLabel.replace(/-/g, "");
    const fold = asciiFold(plain);
    // Hyphen-separated pieces too: "amaz0n-orders" hides "amaz0n" next to other words.
    const pieces = regLabel.split("-").filter((p) => p.length >= 5);
    for (const { label, brand } of BRAND_LABELS) {
      if (seen.has(brand.id) || plain === label || label.length < 5) continue;
      const limit = label.length >= 9 ? 2 : 1;
      const piece = pieces.find((p) => p !== label && asciiFold(p) === label);
      if (piece || (label.length >= 6 && (fold === label || editDistance(plain, label, limit) <= limit))) {
        seen.add(brand.id);
        out.push(make("typosquat", "medium", "impersonation", `Near-miss spelling of ${brand.name}`,
          `“${piece ?? regLabel}” differs from “${label}” by a character or two. Typo domains catch people who misread or mistype.`,
          f.registrableDomain));
        break;
      }
    }
  }

  pathBrandFinding(f, out, seen, null);
}

// Brand only in the path or query: weaker, but common in credential lures.
function pathBrandFinding(f, out, seen, where) {
  const pathAndQuery = `${f.path}${f.query}`.toLowerCase();
  for (const brand of BRANDS) {
    if (seen.has(brand.id)) continue;
    const token = brand.tokens.find((t) => t.length >= 5 && pathAndQuery.includes(t));
    if (token) {
      out.push(make("brand-in-path", "low", "impersonation", `${brand.name} named in the path`,
        where
          ? `“${token}” appears after the domain, on ${where}.`
          : `“${token}” appears after the domain, on ${f.registrableDomain}, which ${brand.name} is not known to use.`, token));
      break;
    }
  }
}

/**
 * @param {object} f  successful result of dissect()
 * @returns {Array<{id:string,severity:string,category:string,title:string,detail:string,evidence:string}>}
 */
export function detectIndicators(f) {
  const out = [];
  const host = f.host;

  const official = officialBrandFor(f.registrableDomain);
  const userContent = SHARED_HOSTING_SUFFIXES.some((s) => hostEndsWith(host, s));
  if (official && !userContent) {
    out.push(make("official-domain", "info", "context", `Domain listed for ${official.name}`,
      `${f.registrableDomain} is in the reference list of domains ${official.name} operates, so the model estimate is not used to raise the verdict. Pages on legitimate domains can still be abused (open redirects, user-hosted content).`,
      f.registrableDomain));
  }

  if (f.hasCredentials) {
    out.push(make("credentials", "high", "obfuscation", "Text before an @ hides the destination",
      `Everything before the @ is treated as login details, not as the address. The browser would go to ${f.displayHost}.`,
      "•••@"));
  }

  if (f.isIp) {
    out.push(make("ip-host", "medium", "infrastructure", "Raw IP address instead of a domain",
      f.ipKind
        ? `The host is an IP address on a ${f.ipKind} network range, which normally refers to your own device or local network rather than a public site.`
        : "Organisations rarely send people to a bare IP address; it also avoids domain-based reputation and certificate checks.",
      f.ipVersion === 6 ? `[${host}]` : host));
    if (f.rewritten && f.ipVersion === 4) {
      out.push(make("ip-disguised", "high", "obfuscation", "IP address written in a disguised form",
        `Written as “${f.writtenHost}”, which browsers read as ${host}.`, f.writtenHost));
    }
  } else if (f.rewritten) {
    out.push(make("host-rewritten", "medium", "obfuscation", "Host changed by the browser’s normalisation",
      `Written as “${f.writtenHost}”; browsers read it as ${host}.`, f.writtenHost));
  }

  // Checks read the decoded host; text shown to the analyst uses displayHost,
  // which stays encoded when the name is outside IDNA2008.
  const decoded = f.decodedHost ?? f.displayHost;
  if (f.idnaProblem) {
    const hidden = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u.test(decoded);
    out.push(hidden
      ? make("idn-nonstandard", "medium", "obfuscation", "Hidden formatting characters in the host",
        "The name decodes to invisible or text-reordering characters (such as a right-to-left override), which can make it display as a different name. The international domain name standard IDNA2008 forbids them. It is shown in its encoded form, and the model was not used for it.",
        host)
      : make("idn-nonstandard", "low", "obfuscation", "Characters outside the domain name standard",
        "Browsers accept this name, but it uses characters (such as symbols or emoji) that the international domain name standard IDNA2008 does not allow and most registries refuse. It is shown in its encoded form, and the model was not used for it.",
        host));
  }
  if (!f.isIp && decoded !== host) {
    const mixed = decoded.split(".").some((label) => {
      const scripts = ["Latin", "Cyrillic", "Greek", "Armenian"].filter((s) => new RegExp(`\\p{Script=${s}}`, "u").test(label));
      return scripts.length > 1;
    });
    out.push(make("idn", "low", "obfuscation", "International characters in the host",
      f.idnaProblem
        ? `Registered as ${host}. Shown encoded here because it decodes to characters outside the domain name standard.`
        : `Displayed as “${f.displayHost}”, registered as ${host}.`, f.displayHost));
    if (mixed) {
      // Invisible and reordering characters are listed by code point only.
      const foreign = [...new Set([...decoded].filter((c) => /[^\x00-\x7f]/.test(c)))].slice(0, 6)
        .map((c) => `${/[\p{Cc}\p{Cf}\p{Z}]/u.test(c) ? "" : `“${c}” `}U+${c.codePointAt(0).toString(16).toUpperCase().padStart(4, "0")}`);
      out.push(make("mixed-script", "high", "obfuscation", "Mixed alphabets in one name",
        `One label mixes alphabets, a standard look-alike technique. Non-Latin characters: ${foreign.join(", ")}.`, f.displayHost));
    }
  }

  brandFindings(f, out, userContent);

  if (f.subdomain) {
    const labels = f.subdomain.split(".");
    if (labels.some((l) => DOMAIN_LIKE_LABELS.has(l)) && labels.length >= 2) {
      out.push(make("domain-in-subdomain", "medium", "obfuscation", "A full domain name inside the subdomain",
        `“${f.subdomain}” reads like a complete domain, but it sits in front of ${f.registrableDomain}, the real site.`, f.subdomain));
    }
    if (labels.length >= 4) {
      out.push(make("deep-subdomain", "low", "structure", "Deeply nested subdomain",
        `${labels.length} subdomain levels push the real domain to the end, where it is easy to miss.`, f.subdomain));
    }
  }

  if (!f.isIp && f.registrableDomain) {
    // Only the registrable label: "login.example.com" is an ordinary subdomain,
    // but "secure-login-update.com" was registered to look like one.
    const regLabel = f.registrableDomain.split(".")[0];
    // Hyphen and keyword checks read the label as displayed: the "xn--"
    // prefix of an internationalised name is encoding, not a hyphen.
    const shownLabel = (f.decodedHost ?? f.displayHost).split(".").slice(-f.registrableDomain.split(".").length)[0] ?? regLabel;
    const hits = HOST_KEYWORDS.filter((k) => regLabel.includes(k));
    if (hits.length && !officialBrandFor(f.registrableDomain)) {
      out.push(make("host-keywords", "low", "structure", "Account or urgency words in the domain name",
        `The registered name ${f.registrableDomain} contains ${hits.map((k) => `“${k}”`).join(", ")}. Organisations seldom register domains built from these words.`, hits.join(", ")));
    }
    if ((shownLabel.match(/-/g) || []).length >= 3) {
      out.push(make("hyphenated-domain", "low", "structure", "Heavily hyphenated domain",
        `${f.registrableDomain} strings several words together, a pattern common in throwaway domains.`, f.registrableDomain));
    }
    const tld = f.publicSuffix.split(".").pop();
    if (FREE_TLDS.has(tld)) {
      out.push(make("free-tld", "low", "infrastructure", `Domain under .${tld}`,
        `.${tld} was offered for free registration for years and is disproportionately present in abuse reports.`, `.${tld}`));
    }
  }

  const shortener = SHORTENERS.find((s) => hostEndsWith(host, s));
  if (shortener) {
    out.push(make("shortener", "low", "infrastructure", "Link shortener hides the destination",
      `${shortener} forwards to another address. SecureMind does not follow links, so the final destination is unknown.`, shortener));
  }
  const shared = SHARED_HOSTING_SUFFIXES.find((s) => hostEndsWith(host, s));
  if (shared) {
    const owner = host === shared ? "the path after the host name" : `“${host.slice(0, -(shared.length + 1))}”`;
    out.push(make("shared-hosting", "low", "infrastructure", "Hosted on a shared platform",
      `Any account holder can publish under ${shared}. The content belongs to whoever controls ${owner}, not to the platform.`, shared));
  }

  if (!f.schemeExplicit) {
    out.push(make("no-scheme", "info", "transport", "No scheme given",
      "Analysed as http://. Whether the real link uses https cannot be known from what was entered.", "—"));
  } else if (f.scheme === "http" && PATH_CREDENTIAL_WORDS.test(`${f.path}${f.query}`)) {
    out.push(make("http-credential-path", "medium", "transport", "Sign-in style path over unencrypted http",
      "The path suggests a sign-in or account page, but the link does not use https.", f.path));
  }

  if (f.port && f.port !== { http: "80", https: "443" }[f.scheme]) {
    out.push(make("port", "low", "infrastructure", "Non-standard port", `The link targets port ${f.port}.`, `:${f.port}`));
  }

  const redirects = [];
  for (const [key, value] of new URLSearchParams(f.query)) {
    // Browsers treat "\" like "/" in http(s) URLs, so "/\evil" is "//evil".
    const m = /^(?:https?:)?[/\\]{2}([^/\\?#]+)/i.exec(value);
    if (!m) continue;
    const targetHost = m[1].slice(m[1].lastIndexOf("@") + 1).toLowerCase().replace(/:\d*$/, "");
    if (REDIRECT_PARAM.test(key) || !hostEndsWith(targetHost, f.registrableDomain || host)) {
      redirects.push(`${safeText(key).slice(0, 40)}=${safeText(maskUserinfo(m[1]))}`);
    }
  }
  if (redirects.length) {
    out.push(make("embedded-url", "medium", "structure", "Another address embedded in the link",
      `${redirects.join(", ")}. Links like this can forward to a different site, sometimes through an open redirect on a trusted domain.`, redirects.join(" ")));
  }

  if (f.path.includes("//") || f.path.includes("@")) {
    out.push(make("path-tricks", "low", "obfuscation", "Misleading characters in the path",
      "The path contains “//” or “@”, which can make a link appear to point elsewhere.", f.path));
  }
  const encoded = (`${f.path}${f.query}`.match(/%[0-9a-f]{2}/gi) || []).length;
  if (encoded >= 10 || /%25[0-9a-f]{2}/i.test(f.path + f.query)) {
    out.push(make("heavy-encoding", "low", "obfuscation", "Heavily percent-encoded",
      `${encoded} encoded characters${/%25/i.test(f.path + f.query) ? ", including double encoding," : ""} obscure what the link contains.`, `${encoded} sequences`));
  }
  const file = decodeURIComponentSafe(f.path.split("/").pop() || "");
  if (DOWNLOAD_EXTENSIONS.test(file)) {
    out.push(make("download", "medium", "content", "Points to a downloadable file type",
      `“${file}” is a file type that can run code or carry an installer.`, file));
  }
  if (f.href.length > 120) {
    out.push(make("long-url", "info", "structure", "Long link",
      `${f.href.length} characters; the real domain may be pushed out of view on small screens.`, `${f.href.length} chars`));
  }
  return out;
}

// Decoded text can reintroduce characters the parser policy rejects (newlines,
// bidi overrides). Replace them before quoting decoded text as evidence.
const UNSAFE_TEXT = /[\p{Cc}\p{Cf}]/gu;
function safeText(s) {
  return String(s).replace(UNSAFE_TEXT, "�");
}

function decodeURIComponentSafe(s) {
  try {
    return safeText(decodeURIComponent(s));
  } catch {
    return safeText(s);
  }
}

// Never quote login details from a URL embedded in the link.
function maskUserinfo(authority) {
  return authority.includes("@") ? `•••@${authority.slice(authority.lastIndexOf("@") + 1)}` : authority;
}
