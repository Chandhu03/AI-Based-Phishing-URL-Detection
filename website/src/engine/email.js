// Reported-email analysis: parse a raw message (.eml, RFC 5322 / MIME) and
// report facts an analyst checks first: who it claims to be from, where
// replies go, what the receiving server's authentication checks said, which
// links it carries (and whether their visible text matches), and which
// attachments it has. It reads text only. HTML is never rendered or parsed by
// the browser (scanned as text), remote content is never loaded, attachments
// are never opened, and links are returned for the URL analyser, never fetched.

import { BRANDS, officialBrandFor } from "./brands.js";

export const EMAIL_LIMITS = Object.freeze({ bytes: 5 * 1024 * 1024, parts: 200, depth: 6, links: 200, headers: 500, anchorText: 200 });

const RISKY_EXTENSIONS = new Set(["exe", "scr", "com", "bat", "cmd", "pif", "msi", "msix", "appx", "js", "jse", "vbs", "vbe", "wsf", "wsh", "hta", "ps1",
  "lnk", "iso", "img", "vhd", "vhdx", "one", "html", "htm", "shtml", "xhtml", "svg", "jar", "reg", "cpl", "chm", "xll", "docm", "xlsm", "pptm", "dotm", "xlam"]);
const ARCHIVE_EXTENSIONS = new Set(["zip", "rar", "7z", "gz", "tar", "cab", "arj", "ace", "z"]);
const DOCUMENT_EXTENSIONS = new Set(["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "jpg", "jpeg", "png", "gif"]);

// ------------------------------------------------------------ headers
function splitHeadersAndBody(text) {
  const m = /\r?\n\r?\n/.exec(text);
  return m ? [text.slice(0, m.index), text.slice(m.index + m[0].length)] : [text, ""];
}

/** Unfold and split header lines: [{name, value}] in message order (raw values). */
function parseHeaderBlock(block) {
  const out = [];
  for (const line of block.split(/\r?\n/)) {
    if (/^[ \t]/.test(line) && out.length) {
      out[out.length - 1].value += ` ${line.trim()}`;
      continue;
    }
    const i = line.indexOf(":");
    if (i <= 0) continue;
    const name = line.slice(0, i).trim();
    if (!/^[\x21-\x39\x3b-\x7e]+$/.test(name)) continue;
    out.push({ name, value: line.slice(i + 1).trim() });
    if (out.length >= EMAIL_LIMITS.headers) break;
  }
  return out;
}

const header = (headers, name) => headers.find((h) => h.name.toLowerCase() === name)?.value ?? null;
const allHeaders = (headers, name) => headers.filter((h) => h.name.toLowerCase() === name).map((h) => h.value);

function decodeBytes(bytes, charset) {
  try {
    return new TextDecoder(charset || "utf-8").decode(bytes);
  } catch {
    return new TextDecoder("utf-8").decode(bytes); // unknown charset label
  }
}

function base64Bytes(s) {
  const clean = s.replace(/[^A-Za-z0-9+/]/g, "");
  const padded = clean + "=".repeat((4 - (clean.length % 4)) % 4);
  try {
    const bin = atob(padded.length % 4 === 1 ? padded.slice(0, -1) : padded);
    return Uint8Array.from(bin, (c) => c.charCodeAt(0));
  } catch {
    return new Uint8Array();
  }
}

const utf8 = new TextEncoder();
function qpBytes(s, header = false) {
  const src = header ? s.replace(/_/g, " ") : s.replace(/=\r?\n/g, "");
  const out = [];
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (c === "=" && /^[0-9A-Fa-f]{2}$/.test(src.slice(i + 1, i + 3))) {
      out.push(parseInt(src.slice(i + 1, i + 3), 16));
      i += 2;
    } else if (src.charCodeAt(i) < 0x80) out.push(src.charCodeAt(i));
    else for (const b of utf8.encode(c)) out.push(b); // 8-bit text that was not encoded
  }
  return Uint8Array.from(out);
}

/** RFC 2047 encoded words; whitespace between adjacent encoded words is dropped. */
export function decodeWords(value) {
  return String(value ?? "")
    .replace(/(=\?[^?\s]+\?[BbQq]\?[^?\s]*\?=)\s+(?==\?[^?\s]+\?[BbQq]\?[^?\s]*\?=)/g, "$1")
    .replace(/=\?([^?\s]+)\?([BbQq])\?([^?\s]*)\?=/g, (_, charset, enc, data) => {
      const bytes = enc.toUpperCase() === "B" ? base64Bytes(data) : qpBytes(data, true);
      return decodeBytes(bytes, charset.split("*")[0]);
    });
}

/** Strip control and bidirectional-override characters from text that will be shown. */
const visible = (s, max = 1000) => String(s ?? "").replace(/[\p{Cc}\p{Cf}]/gu, " ").replace(/\s+/g, " ").trim().slice(0, max);

/** Parse "Name <addr@host>" (the first address). Display name decoded; address lowercased domain. */
export function parseAddress(value) {
  if (!value) return null;
  const v = decodeWords(value);
  // Quoted display names are blanked before looking for the address, so
  // "Bank <it@bank.example>" <x@evil.example> yields x@evil.example (the spoof trick).
  const masked = v.replace(/"(?:[^"\\]|\\.)*"/g, (q) => " ".repeat(q.length));
  const angle = /<([^<>\s]+@[^<>\s]+)>/.exec(masked);
  const bare = angle ? null : /([^\s<>",;]+@[^\s<>",;]+)/.exec(masked);
  const found = angle ?? bare;
  const address = found ? v.slice(found.index + (angle ? 1 : 0), found.index + (angle ? 1 : 0) + found[1].length).replace(/^mailto:/i, "") : "";
  if (!address.includes("@")) return { name: visible(v, 200), address: null, domain: null };
  const name = angle ? visible(v.slice(0, angle.index).replace(/^\s*"|"\s*$/g, "").replace(/\\(.)/g, "$1"), 200) : "";
  const at = address.lastIndexOf("@");
  return { name, address: visible(address, 320), domain: address.slice(at + 1).toLowerCase().replace(/[>.]+$/, "") };
}

/** Split an address list on commas outside quoted names. */
function addressList(value) {
  const v = String(value ?? "");
  const masked = v.replace(/"(?:[^"\\]|\\.)*"/g, (q) => " ".repeat(q.length));
  const out = [];
  let start = 0;
  for (let i = 0; i <= masked.length; i++) {
    if (i === masked.length || masked[i] === ",") {
      if (v.slice(start, i).trim()) out.push(v.slice(start, i));
      start = i + 1;
    }
  }
  return out.slice(0, 50).map(parseAddress).filter((a) => a?.address);
}

function params(value) {
  const out = {};
  const [type, ...rest] = String(value ?? "").split(";");
  for (const p of rest) {
    const i = p.indexOf("=");
    if (i === -1) continue;
    let k = p.slice(0, i).trim().toLowerCase();
    let v = p.slice(i + 1).trim().replace(/^"(.*)"$/s, "$1");
    if (k.endsWith("*")) {
      // RFC 2231 extended value: charset'language'percent-encoded (only the first section names the charset).
      k = k.slice(0, -1);
      const m = /^([^']*)'[^']*'(.*)$/.exec(v);
      v = decodeBytes(percentBytes(m ? m[2] : v), m?.[1] || "utf-8");
    }
    k = k.replace(/\*\d+$/, ""); // RFC 2231 continuations: name*0, name*1, …
    out[k] = (out[k] ?? "") + v;
  }
  return { type: type.trim().toLowerCase(), params: out };
}

function percentBytes(s) {
  const out = [];
  for (let i = 0; i < s.length; i++) {
    if (s[i] === "%" && /^[0-9A-Fa-f]{2}$/.test(s.slice(i + 1, i + 3))) {
      out.push(parseInt(s.slice(i + 1, i + 3), 16));
      i += 2;
    } else out.push(s.charCodeAt(i) & 0xff);
  }
  return Uint8Array.from(out);
}

// ------------------------------------------------------------ MIME tree
/**
 * Walk a MIME entity. Collects text and HTML bodies, attachments and nested
 * messages. Caps parts and depth so a hostile message cannot exhaust the tab.
 */
function walk(headers, body, state, depth) {
  if (state.parts >= EMAIL_LIMITS.parts || depth > EMAIL_LIMITS.depth) {
    state.truncated = true;
    return;
  }
  state.parts++;
  const ct = params(header(headers, "content-type") || "text/plain");
  const disp = params(header(headers, "content-disposition") || "");
  const cte = (header(headers, "content-transfer-encoding") || "").trim().toLowerCase();
  const filename = visible(decodeWords(disp.params.filename ?? ct.params.name ?? ""), 255);

  if (ct.type.startsWith("multipart/") && ct.params.boundary) {
    const boundary = `--${ct.params.boundary}`;
    const pieces = body.split(/\r?\n/);
    let current = null;
    for (const line of pieces) {
      if (line.startsWith(boundary)) {
        if (current) {
          const [h, b] = splitHeadersAndBody(current.join("\n"));
          walk(parseHeaderBlock(h), b, state, depth + 1);
        }
        if (line.startsWith(`${boundary}--`)) {
          current = null;
          break;
        }
        current = [];
      } else if (current) current.push(line);
    }
    if (current?.length) {
      const [h, b] = splitHeadersAndBody(current.join("\n"));
      walk(parseHeaderBlock(h), b, state, depth + 1);
    }
    return;
  }

  const bytes = cte === "base64" ? base64Bytes(body) : cte === "quoted-printable" ? qpBytes(body) : null;
  if (ct.type === "message/rfc822") {
    const inner = bytes ? decodeBytes(bytes, "utf-8") : body;
    state.messages.push(inner);
    return;
  }
  const isAttachment = disp.type === "attachment" || (filename && !ct.type.startsWith("text/"));
  if (isAttachment || !(ct.type === "text/plain" || ct.type === "text/html")) {
    const size = bytes ? bytes.length : body.length;
    state.attachments.push({ filename: filename || "(no name)", contentType: visible(ct.type, 100) || "application/octet-stream", size });
    return;
  }
  const text = bytes ? decodeBytes(bytes, ct.params.charset) : body;
  (ct.type === "text/html" ? state.html : state.text).push(text);
}

// ------------------------------------------------------------ links
const ENTITIES = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " " };
const decodeEntities = (s) => s.replace(/&(#x[0-9a-f]{1,6}|#\d{1,7}|[a-z]{2,8});/gi, (m, e) => {
  if (e[0] === "#") {
    const n = e[1] === "x" || e[1] === "X" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
    return n > 0 && n <= 0x10ffff ? String.fromCodePoint(n) : m;
  }
  return ENTITIES[e.toLowerCase()] ?? m;
});
const URL_IN_TEXT = /\b(?:https?|hxxps?):\/\/[^\s<>"'`]+/gi;
const trimTrailing = (u) => u.replace(/[.,;:!?)\]}>'"]+$/, "");

/** Host written in a piece of visible text that looks like a link or domain ("www.bank.com", "https://bank.com/x"). */
function hostInText(text) {
  const m = /^(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,63})(?:[/:?#]|$)/i.exec(text.trim());
  return m ? m[1].toLowerCase().replace(/^www\./, "") : null;
}
function hostOfHref(href) {
  try {
    return new URL(href.replace(/^hxxp/i, "http")).hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return null;
  }
}

/** Links in HTML (href of a, area) with their visible text; scanned as text, never parsed into a document. */
function linksFromHtml(html, add) {
  // One pass over the a/area tags: an opening <a> stays pending until its
  // </a> (or the next <a>), so every character is visited a bounded number of times.
  const tag = /<(\/?)(a|area)\b([^>]*)>/gi;
  let open = null;
  const flush = (end) => {
    if (!open) return;
    const inner = html.slice(open.at, Math.min(end, open.at + 4000)).replace(/<[^>]*>/g, " ");
    add(open.href, visible(decodeEntities(inner), EMAIL_LIMITS.anchorText), "html");
    open = null;
  };
  let m;
  while ((m = tag.exec(html))) {
    if (m[1]) {
      if (m[2].toLowerCase() === "a") flush(m.index);
      continue;
    }
    flush(m.index);
    const attr = /\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(m[3]);
    if (!attr) continue;
    const href = decodeEntities((attr[1] ?? attr[2] ?? attr[3]).trim());
    if (m[2].toLowerCase() === "area") add(href, "", "html");
    else open = { href, at: tag.lastIndex };
  }
  flush(html.length);
  for (const u of decodeEntities(html.replace(/<[^>]*>/g, " ")).match(URL_IN_TEXT) ?? []) add(trimTrailing(u), "", "html-text");
}

// ------------------------------------------------------------ findings
const AUTH_RE = /\b(spf|dkim|dmarc)\s*=\s*([a-z]+)/gi;

/** Results from the topmost Authentication-Results header (the one the receiving server added last). */
function authResults(headers) {
  const value = header(headers, "authentication-results");
  if (!value) return null;
  const out = { spf: null, dkim: null, dmarc: null, server: visible(value.split(";")[0], 120) };
  for (const [, k, v] of value.matchAll(AUTH_RE)) {
    const key = k.toLowerCase();
    if (!out[key]) out[key] = v.toLowerCase();
  }
  return out;
}

function registrable(domain, psl) {
  if (!domain) return null;
  const d = domain.toLowerCase().replace(/\.$/, "");
  if (!psl || !/^[a-z0-9.-]+$/.test(d)) return d;
  try {
    return psl.split(d).registrableDomain ?? d;
  } catch {
    return d;
  }
}

function extensionsOf(name) {
  const parts = name.toLowerCase().split(".");
  return parts.length > 1 ? parts.slice(1) : [];
}

function findingsFor(msg, psl) {
  const out = [];
  const add = (id, severity, title, detail, evidence = "") => out.push({ id, severity, title, detail, evidence: visible(evidence, 300) });
  const fromDomain = registrable(msg.from?.domain, psl);

  const auth = msg.auth;
  if (!auth) {
    add("no-auth-results", "info", "No authentication results", "The message has no Authentication-Results header, so SPF, DKIM and DMARC outcomes are unknown. It may have been saved before delivery or forwarded inline.");
  } else {
    const failed = ["spf", "dkim", "dmarc"].filter((k) => ["fail", "softfail", "permerror"].includes(auth[k]));
    if (auth.dmarc === "fail") add("dmarc-fail", "high", "DMARC failed", "The receiving server reports that the message failed DMARC for the sender's domain: it did not prove it came from that domain.", `dmarc=${auth.dmarc}`);
    else if (failed.length) add("auth-fail", "medium", "Sender authentication failed", `The receiving server reports ${failed.map((k) => `${k.toUpperCase()} ${auth[k]}`).join(", ")}.`, failed.map((k) => `${k}=${auth[k]}`).join(" "));
    if (!auth.dmarc || auth.dmarc === "none") add("dmarc-none", "low", "No DMARC result", "The sender's domain was not checked against a DMARC policy, so the From address is not verified.", `dmarc=${auth.dmarc ?? "absent"}`);
  }

  if (msg.from?.name) {
    const shown = /([^\s<>"]+@[^\s<>"]+)/.exec(msg.from.name)?.[1];
    if (shown && registrable(shown.split("@").pop(), psl) !== fromDomain) {
      add("display-name-address", "high", "Display name shows another address", `The sender's name shows ${shown}, but the message comes from ${msg.from.address}.`, msg.from.name);
    }
    const words = ` ${msg.from.name.toLowerCase().replace(/[^\p{L}\p{N}]+/gu, " ")} `;
    const brand = BRANDS.find((b) => [b.name.toLowerCase(), ...b.tokens].some((t) => words.includes(` ${t.replace(/[^\p{L}\p{N}]+/gu, " ")} `)));
    if (brand && officialBrandFor(fromDomain) !== brand) {
      add("display-name-brand", "medium", `${brand.name} named, but sent from another domain`, `The sender's name mentions ${brand.name}, but ${fromDomain ?? "the sending domain"} is not a domain ${brand.name} uses.`, msg.from.name);
    }
  }
  const replyDomains = msg.replyTo.map((a) => registrable(a.domain, psl)).filter(Boolean);
  const otherReply = replyDomains.find((d) => d !== fromDomain);
  if (fromDomain && otherReply) add("reply-to-mismatch", "medium", "Replies go to another domain", `Replies go to ${otherReply}, not to the sender's domain ${fromDomain}.`, msg.replyTo.map((a) => a.address).join(", "));
  const rp = registrable(msg.returnPath?.domain, psl);
  if (fromDomain && rp && rp !== fromDomain) add("return-path-mismatch", "low", "Bounce address on another domain", `Bounces go to ${rp}. Mailing services do this legitimately; with other signals it can indicate spoofing.`, msg.returnPath.address);

  const mismatched = msg.links.filter((l) => l.textHost && l.host && l.textHost !== l.host && !l.host.endsWith(`.${l.textHost}`));
  if (mismatched.length) {
    const l = mismatched[0];
    add("link-text-mismatch", "high", "Link text names a different site", `${mismatched.length === 1 ? "A link shows" : `${mismatched.length} links show`} one address but lead${mismatched.length === 1 ? "s" : ""} to another, for example text “${l.text}” leading to ${l.host}. Newsletters sometimes do this for click tracking; a sign-in or payment link that does it is a classic lure.`, l.text);
  }
  const scripted = msg.rawHrefs.filter((h) => /^\s*(javascript|data|vbscript):/i.test(h));
  if (scripted.length) add("script-link", "high", "Script or data link", "A link runs code or carries an embedded document instead of opening a web page.", scripted[0].slice(0, 80));

  for (const a of msg.attachments) {
    const exts = extensionsOf(a.filename);
    const last = exts.at(-1);
    if (exts.length >= 2 && DOCUMENT_EXTENSIONS.has(exts.at(-2)) && (RISKY_EXTENSIONS.has(last) || ARCHIVE_EXTENSIONS.has(last))) {
      add("double-extension", "high", "Attachment disguised by a double extension", `“${a.filename}” looks like a .${exts.at(-2)} file but is a .${last} file.`, a.filename);
    } else if (RISKY_EXTENSIONS.has(last)) {
      add("risky-attachment", "high", "Attachment type often used to deliver attacks", `“${a.filename}” is a .${last} file. ${["html", "htm", "shtml", "xhtml", "svg"].includes(last) ? "HTML and SVG attachments can show a fake sign-in page offline." : "It can run code when opened."}`, a.filename);
    } else if (ARCHIVE_EXTENSIONS.has(last)) {
      add("archive-attachment", "medium", "Archive attachment", `“${a.filename}” is an archive; archives hide their contents from mail filters.`, a.filename);
    }
  }
  if (msg.truncated) add("truncated", "info", "Message partly read", `The message has more than ${EMAIL_LIMITS.parts} parts or nests deeper than ${EMAIL_LIMITS.depth} levels; the rest was not read.`);
  if (msg.linksTruncated) add("links-truncated", "info", "Many links", `Only the first ${EMAIL_LIMITS.links} distinct links were collected.`);
  const order = { high: 0, medium: 1, low: 2, info: 3 };
  return out.sort((a, b) => order[a.severity] - order[b.severity]);
}

// ------------------------------------------------------------ entry point
function parseOne(raw, psl) {
  const [head, body] = splitHeadersAndBody(raw);
  const headers = parseHeaderBlock(head);
  const state = { parts: 0, text: [], html: [], attachments: [], messages: [], truncated: false };
  walk(headers, body, state, 0);

  const links = [];
  const rawHrefs = [];
  const seen = new Map();
  let linksTruncated = false;
  const add = (href, text, source) => {
    if (!/^(?:https?|hxxps?):\/\//i.test(href)) {
      if (source === "html" && rawHrefs.length < 50) rawHrefs.push(href);
      return;
    }
    const key = href;
    if (seen.has(key)) {
      const l = seen.get(key);
      if (!l.text && text) Object.assign(l, { text, textHost: hostInText(text) });
      return;
    }
    if (links.length >= EMAIL_LIMITS.links) {
      linksTruncated = true;
      return;
    }
    const l = { url: href.slice(0, 2048), text, textHost: text ? hostInText(text) : null, host: hostOfHref(href), source };
    seen.set(key, l);
    links.push(l);
  };
  for (const h of state.html) linksFromHtml(h, add);
  for (const t of state.text) for (const u of t.match(URL_IN_TEXT) ?? []) add(trimTrailing(u), "", "text");

  const msg = {
    subject: visible(decodeWords(header(headers, "subject")), 300),
    date: visible(header(headers, "date"), 100),
    messageId: visible(header(headers, "message-id"), 300),
    from: parseAddress(header(headers, "from")),
    replyTo: addressList(header(headers, "reply-to")),
    returnPath: parseAddress(header(headers, "return-path")),
    auth: authResults(headers),
    received: allHeaders(headers, "received").length,
    headers: headers.map((h) => ({ name: visible(h.name, 80), value: visible(decodeWords(h.value), 2000) })),
    links,
    rawHrefs,
    attachments: state.attachments,
    linksTruncated,
    truncated: state.truncated,
    bodyChars: state.text.reduce((n, t) => n + t.length, 0) + state.html.reduce((n, t) => n + t.length, 0),
  };
  msg.findings = findingsFor(msg, psl);
  delete msg.rawHrefs;
  msg.nested = state.messages.slice(0, 3);
  return msg;
}

/**
 * Parse a raw email. When the message carries an attached message (a user's
 * "report phishing" forward), the attached one is analysed as the reported
 * email and the outer one is returned as `wrapper`.
 * @param {string} raw
 * @param {{psl?: {split: (host: string) => {registrableDomain: string|null}}}} [deps]
 */
export function parseEmail(raw, { psl = null } = {}) {
  if (typeof raw !== "string") return { ok: false, message: "The file could not be read as text." };
  if (raw.length > EMAIL_LIMITS.bytes) return { ok: false, message: "The message is larger than 5 MB." };
  const text = raw.replace(/^﻿/, "");
  const [head] = splitHeadersAndBody(text);
  const headers = parseHeaderBlock(head);
  if (!headers.some((h) => ["from", "subject", "received", "message-id", "content-type"].includes(h.name.toLowerCase()))) {
    return { ok: false, message: "This does not look like an email message: it has no From, Subject, Received, Message-ID or Content-Type header." };
  }
  const outer = parseOne(text, psl);
  if (outer.nested.length) {
    const inner = parseOne(outer.nested[0], psl);
    if (inner.from || inner.subject) {
      const { nested: _n, ...rest } = inner;
      const { nested: _o, ...wrapper } = outer;
      return { ok: true, ...rest, wrapper: { from: wrapper.from, subject: wrapper.subject, date: wrapper.date } };
    }
  }
  const { nested: _n, ...rest } = outer;
  return { ok: true, ...rest, wrapper: null };
}
