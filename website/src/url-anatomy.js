// URL dissection: how a browser reads a link, computed entirely locally.
//
// This module states facts about the URL string (structure, the registrable
// domain, disguised hosts, embedded credentials, look-alike characters). It
// never fetches, resolves or opens the URL, and it never produces a safety
// verdict, score or probability.
//
// The acceptance policy mirrors the app's Python validator
// (securemind/url_validation.py): http/https only, no silent https
// assumption, control/bidi characters, whitespace and backslashes rejected,
// 2,048-character limit, and error messages that never echo the input.

import { toUnicodeHost } from "./punycode.js";

export const MAX_URL_LENGTH = 2048;

export const ERROR_MESSAGES = Object.freeze({
  empty: "Enter a URL to dissect.",
  too_long: `That URL is longer than ${MAX_URL_LENGTH} characters, which this tool does not analyse.`,
  control_chars: "The URL contains hidden or control characters, which are not allowed.",
  whitespace: "The URL contains spaces or other whitespace, which are not allowed.",
  backslash: "The URL contains a backslash, which browsers treat inconsistently. Use forward slashes.",
  scheme_not_allowed: "Only http and https web addresses can be dissected.",
  malformed: "That does not look like a well-formed web address.",
  missing_host: "The URL has no host name.",
  invalid_port: "The URL has an invalid port number.",
  invalid_host: "The URL has an invalid host name.",
});

const SCHEME_RE = /^[A-Za-z][A-Za-z0-9+.-]*$/;
const SCHEME_COLON_RE = /^([A-Za-z][A-Za-z0-9+.-]*):/;
const LABEL_RE = /^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?$/;
const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const DEFAULT_PORTS = { http: "80", https: "443" };

function fail(code) {
  return { ok: false, code, message: ERROR_MESSAGES[code] };
}

// Split the authority exactly as written, before the browser rewrites it:
// host text (IPv6 keeps its brackets) and the raw ":port" text, if any.
function splitAuthority(toParse) {
  const authority = toParse.slice(toParse.indexOf("://") + 3).split(/[/?#]/, 1)[0];
  const hostPort = authority.slice(authority.lastIndexOf("@") + 1);
  const cut = hostPort.startsWith("[") ? hostPort.indexOf("]") + 1 : hostPort.indexOf(":");
  const end = cut > 0 ? cut : hostPort.length;
  return { host: hostPort.slice(0, end), port: hostPort.slice(end) };
}

function ipv4Kind(ip) {
  const [a, b] = ip.split(".").map(Number);
  if (a === 127) return "loopback";
  if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return "private";
  if (a === 169 && b === 254) return "link-local";
  if (a === 100 && b >= 64 && b <= 127) return "shared";
  if (a === 0) return "unspecified";
  return null;
}

function ipv6Kind(ip) {
  const h = ip.toLowerCase();
  if (h === "::1") return "loopback";
  if (/^f[cd]/.test(h)) return "private";
  if (/^fe[89ab]/.test(h)) return "link-local";
  return null;
}

const SCRIPTS = [
  ["Latin", /\p{Script=Latin}/u],
  ["Cyrillic", /\p{Script=Cyrillic}/u],
  ["Greek", /\p{Script=Greek}/u],
  ["Armenian", /\p{Script=Armenian}/u],
];

function scriptsIn(text) {
  return SCRIPTS.filter(([, re]) => re.test(text)).map(([name]) => name);
}

/**
 * Dissect a URL. `psl` is a PublicSuffixList (see psl.js).
 * Returns { ok: false, code, message } or { ok: true, ...facts }.
 */
export function dissect(raw, psl) {
  if (typeof raw !== "string") return fail("malformed");
  if (raw.length > MAX_URL_LENGTH) return fail("too_long");
  const s = raw.trim();
  if (!s) return fail("empty");
  if (/[\p{Cc}\p{Cf}]/u.test(s)) return fail("control_chars");
  if (/\s/u.test(s)) return fail("whitespace");
  if (s.includes("\\")) return fail("backslash");

  // Scheme detection. Never assume https.
  let scheme;
  let schemeExplicit = true;
  let toParse = s;
  const sep = s.indexOf("://");
  if (sep !== -1 && !/[/?#]/.test(s.slice(0, sep))) {
    const text = s.slice(0, sep);
    if (!SCHEME_RE.test(text)) return fail("malformed");
    scheme = text.toLowerCase();
    if (scheme !== "http" && scheme !== "https") return fail("scheme_not_allowed");
  } else {
    const m = SCHEME_COLON_RE.exec(s);
    if (m && !/^\d/.test(s.slice(m[0].length))) {
      return fail(["http", "https"].includes(m[1].toLowerCase()) ? "malformed" : "scheme_not_allowed");
    }
    scheme = "http";
    schemeExplicit = false;
    toParse = `http://${s}`;
  }

  // Check the written host and port before parsing so errors are specific.
  const written = splitAuthority(toParse);
  if (!written.host && !written.port) return fail("missing_host");
  if (written.port.length > 1 && (!/^:\d+$/.test(written.port) || Number(written.port.slice(1)) > 65535)) {
    return fail("invalid_port");
  }

  let url;
  try {
    url = new URL(toParse);
  } catch {
    return fail("malformed");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return fail("scheme_not_allowed");
  if (!url.hostname) return fail("missing_host");
  if (url.port === "0") return fail("invalid_port");

  if (written.host.includes("%")) return fail("invalid_host");

  const isIpv6 = url.hostname.startsWith("[");
  const host = (isIpv6 ? url.hostname.slice(1, -1) : url.hostname).replace(/\.$/, "");
  const ipv4 = !isIpv6 && IPV4_RE.test(host);
  const isIp = isIpv6 || ipv4;

  if (!isIp) {
    const labels = host.split(".");
    if (host.length > 253 || labels.some((l) => l.length < 1 || l.length > 63 || !LABEL_RE.test(l))) {
      return fail("invalid_host");
    }
  }

  const writtenNorm = written.host.toLowerCase().replace(/\.$/, "");
  const display = isIp ? host : toUnicodeHost(host);
  // "Rewritten" means the browser changed the host into something a reader
  // would not recognise from the original text (disguised IPs, fullwidth or
  // otherwise mapped characters). Plain IDN encoding is reported separately.
  const rewritten = writtenNorm !== (isIpv6 ? `[${host}]` : host) && writtenNorm !== display.toLowerCase();
  const registrable = isIp ? null : psl.registrableDomain(host);
  const suffix = isIp ? null : psl.publicSuffix(host);
  const subdomain = registrable && host.length > registrable.length ? host.slice(0, -registrable.length - 1) : "";
  const hasCredentials = Boolean(url.username || url.password);
  // Never carry embedded login details into any output field.
  const safeUrl = new URL(url.href);
  safeUrl.username = "";
  safeUrl.password = "";
  const port = url.port || null;
  const facts = {
    ok: true,
    scheme,
    schemeExplicit,
    host,
    displayHost: display,
    writtenHost: written.host,
    rewritten,
    isIp,
    ipVersion: isIp ? (isIpv6 ? 6 : 4) : null,
    registrableDomain: registrable,
    publicSuffix: suffix,
    subdomain,
    subdomainLabels: subdomain ? subdomain.split(".").length : 0,
    hasCredentials,
    port,
    path: url.pathname,
    query: url.search,
    fragment: url.hash,
    href: safeUrl.href,
  };
  facts.segments = buildSegments(facts, isIpv6);
  facts.observations = observe(facts, url, isIpv6);
  return facts;
}

function buildSegments(f, isIpv6) {
  const seg = [{ part: "scheme", text: `${f.scheme}://` }];
  if (f.hasCredentials) seg.push({ part: "credentials", text: "•••@" });
  if (f.isIp) {
    seg.push({ part: "domain", text: isIpv6 ? `[${f.host}]` : f.host });
  } else {
    if (f.subdomain) seg.push({ part: "subdomain", text: `${f.subdomain}.` });
    if (f.registrableDomain) {
      const label = f.registrableDomain.slice(0, -f.publicSuffix.length - 1);
      seg.push({ part: "domain", text: label });
      seg.push({ part: "suffix", text: `.${f.publicSuffix}` });
    } else {
      seg.push({ part: "suffix", text: f.host });
    }
  }
  if (f.port) seg.push({ part: "port", text: `:${f.port}` });
  if (f.path && f.path !== "/") seg.push({ part: "path", text: f.path });
  if (f.query) seg.push({ part: "query", text: f.query });
  if (f.fragment) seg.push({ part: "fragment", text: f.fragment });
  return seg;
}

function observe(f, url, isIpv6) {
  const out = [];
  const add = (id, level, title, detail) => out.push({ id, level, title, detail });

  if (!f.schemeExplicit) {
    add("no-scheme", "info", "No scheme was given",
      "Analysed as http://. Whether the real link uses https cannot be known from what was entered.");
  } else if (f.scheme === "http") {
    add("http", "info", "Unencrypted connection",
      "This link uses http://, so traffic to the site would not be encrypted. Many phishing pages use https too, so https alone is not reassurance.");
  }

  if (f.hasCredentials) {
    add("credentials", "notable", "Text before an @ sign",
      `Everything before the @ is treated as login details, not as the destination. The browser would go to ${f.displayHost}. (The hidden text is not shown here.)`);
  }

  if (f.isIp) {
    const kind = f.ipVersion === 4 ? ipv4Kind(f.host) : ipv6Kind(f.host);
    add("ip-host", "notable", "Raw IP address instead of a domain name",
      kind ? `The host is an IP address on a ${kind} network range, which normally refers to your own device or local network.`
        : "Legitimate public services rarely ask people to visit a bare IP address.");
    if (f.rewritten && f.ipVersion === 4) {
      add("ip-disguised", "notable", "IP address written in a disguised form",
        `It was written as “${f.writtenHost}”, which browsers read as ${f.host}.`);
    }
  } else if (f.rewritten) {
    add("host-rewritten", "notable", "Host rewritten by the browser",
      `It was written as “${f.writtenHost}”; browsers normalise it to ${f.host}.`);
  }

  if (!f.isIp && f.displayHost !== f.host) {
    const mixed = f.displayHost.split(".").some((label) => scriptsIn(label).length > 1);
    add("idn", "notable", "International characters in the host",
      `Shown to readers as “${f.displayHost}” but registered as ${f.host}. Characters from other alphabets can imitate familiar names.`);
    if (mixed) {
      add("mixed-script", "notable", "Mixed alphabets in one label",
        "A single part of the name mixes alphabets (for example Latin and Cyrillic), a common look-alike technique.");
    }
  }

  if (f.registrableDomain && f.subdomain) {
    add("registrable", f.subdomainLabels >= 2 ? "notable" : "info", `The site is ${f.registrableDomain}`,
      `“${f.subdomain}” is a subdomain chosen by whoever controls ${f.registrableDomain}. Familiar names appearing there say nothing about who owns the site.`);
  } else if (!f.isIp && !f.registrableDomain) {
    add("no-registrable", "info", "Host is itself a public suffix",
      `${f.host} is a shared suffix (like a top-level domain) rather than an individually owned domain.`);
  }

  if (f.port && f.port !== DEFAULT_PORTS[f.scheme]) {
    add("port", "info", "Non-standard port", `The link targets port ${f.port} instead of the usual ${DEFAULT_PORTS[f.scheme]}.`);
  }

  const embedded = [];
  for (const [key, value] of url.searchParams) {
    if (/^(?:https?:)?\/\//i.test(value) || /^https?%3a/i.test(value)) embedded.push(key);
  }
  if (embedded.length) {
    add("embedded-url", "info", "Another web address inside the link",
      `The query parameter${embedded.length > 1 ? "s" : ""} ${embedded.map((k) => `“${k}”`).join(", ")} contain${embedded.length > 1 ? "" : "s"} a URL. Links like this can forward you to a different site.`);
  }
  if (url.pathname.includes("//") || url.pathname.includes("@")) {
    add("path-tricks", "info", "Unusual characters in the path",
      "The path contains “//” or “@”, which can make a link look like it points somewhere else.");
  }
  if (f.href.length > 100) {
    add("long", "info", "Long URL", `${f.href.length} characters. Long links can push the real domain out of view on small screens.`);
  }
  return out;
}
