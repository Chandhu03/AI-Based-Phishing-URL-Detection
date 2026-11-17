import assert from "node:assert/strict";
import test from "node:test";
import { emailToMarkdown } from "../workspace/io.js";
import { analyzeUrl } from "./analyze.js";
import { decodeWords, EMAIL_LIMITS, parseAddress, parseEmail } from "./email.js";
import { PSL_COMMIT, RULES } from "./generated/psl-rules.js";
import { PublicSuffixList } from "./psl.js";

const psl = new PublicSuffixList(RULES, PSL_COMMIT);
const b64 = (s) => Buffer.from(s, "utf8").toString("base64").replace(/.{76}/g, "$&\r\n");
const ids = (r) => r.findings.map((f) => f.id);

const LURE = [
  "Return-Path: <bounce@mailer.bulk-sender.example>",
  "Authentication-Results: mx.corp.example; spf=softfail smtp.mailfrom=bulk-sender.example; dkim=none; dmarc=fail header.from=paypal.com",
  "Received: from mailer.bulk-sender.example (203.0.113.9) by mx.corp.example",
  "Received: from internal by mailer.bulk-sender.example",
  'From: "PayPal Service <service@paypal.com>" <alerts@secure-paypa1.example>',
  "Reply-To: billing@collect-payments.example",
  "To: pat@corp.example",
  "Subject: =?UTF-8?B?WW91ciBhY2NvdW50IGlzIGxpbWl0ZWQg4pqg?= =?UTF-8?Q?_act_now?=",
  "Date: Mon, 16 Nov 2026 09:12:00 +0000",
  "Message-ID: <abc123@secure-paypa1.example>",
  "MIME-Version: 1.0",
  'Content-Type: multipart/mixed; boundary="mix"',
  "",
  "--mix",
  'Content-Type: multipart/alternative; boundary="alt"',
  "",
  "--alt",
  "Content-Type: text/plain; charset=utf-8",
  "Content-Transfer-Encoding: base64",
  "",
  b64("Sign in at https://www.paypal.com.account-review.example/login. Thanks."),
  "--alt",
  "Content-Type: text/html; charset=iso-8859-1",
  "Content-Transfer-Encoding: quoted-printable",
  "",
  '<p>Caf=E9 &amp; more</p><a href=3D"https://www.paypal.com.account-review.example/login?u=3D1&amp;x=3D2">www.paypal=',
  '.com</a> <a href=3D"https://www.paypal.com/help">PayPal help</a> <a href=3D"javascript:alert(1)">x</a> <a href=3D"mailto:a@b.example">mail</a>',
  "--alt--",
  "--mix",
  "Content-Type: application/octet-stream",
  "Content-Disposition: attachment; filename*=UTF-8''Rechnung%C3%BC.pdf.html",
  "Content-Transfer-Encoding: base64",
  "",
  b64("<html>fake sign-in</html>"),
  "--mix",
  'Content-Type: application/zip; name="docs.zip"',
  "Content-Transfer-Encoding: base64",
  "",
  b64("PK..."),
  "--mix--",
  "",
].join("\r\n");

test("a credential lure: sender, authentication, links and attachments are all read", () => {
  const r = parseEmail(LURE, { psl });
  assert.equal(r.ok, true);
  assert.equal(r.subject, "Your account is limited ⚠ act now");
  assert.deepEqual(r.from, { name: "PayPal Service <service@paypal.com>", address: "alerts@secure-paypa1.example", domain: "secure-paypa1.example" });
  assert.equal(r.replyTo[0].domain, "collect-payments.example");
  assert.equal(r.returnPath.domain, "mailer.bulk-sender.example");
  assert.deepEqual([r.auth.spf, r.auth.dkim, r.auth.dmarc], ["softfail", "none", "fail"]);
  assert.equal(r.received, 2);
  assert.equal(r.messageId, "<abc123@secure-paypa1.example>");

  assert.deepEqual(r.links.map((l) => l.url), [
    "https://www.paypal.com.account-review.example/login?u=1&x=2",
    "https://www.paypal.com/help",
    "https://www.paypal.com.account-review.example/login",
  ]);
  assert.equal(r.links[0].text, "www.paypal.com", "soft line break in quoted-printable is joined");
  assert.deepEqual(r.attachments.map((a) => a.filename), ["Rechnungü.pdf.html", "docs.zip"]);

  for (const id of ["dmarc-fail", "display-name-address", "display-name-brand", "reply-to-mismatch", "return-path-mismatch", "link-text-mismatch", "script-link", "double-extension", "archive-attachment"]) {
    assert.ok(ids(r).includes(id), id);
  }
  assert.equal(r.findings[0].severity, "high", "most serious first");
  assert.equal(r.wrapper, null);
});

test("an ordinary message raises no sender or link findings", () => {
  const r = parseEmail([
    "Authentication-Results: mx.corp.example; spf=pass smtp.mailfrom=news.example.org; dkim=pass header.d=example.org; dmarc=pass header.from=example.org",
    "From: Example News <news@example.org>",
    "Reply-To: help@support.example.org",
    "Return-Path: <bounce@mail.example.org>",
    "Subject: Monthly update",
    "Content-Type: text/html; charset=utf-8",
    "",
    '<a href="https://www.example.org/news">www.example.org</a> <a href="https://mail.example.org/x">Read more</a>',
  ].join("\n"), { psl });
  assert.equal(r.ok, true);
  assert.deepEqual(r.findings, [], "subdomains of the sender's registrable domain are the same organisation");
  assert.equal(r.links.length, 2);
});

test("a user's 'report phishing' forward: the attached message is the one analysed", () => {
  const inner = ["From: IT Desk <it@helpdesk-reset.example>", "Subject: Password expires today", "Content-Type: text/plain", "", "Reset: https://helpdesk-reset.example/r"].join("\r\n");
  const outer = [
    "From: Pat <pat@corp.example>", "Subject: FW: Password expires today", 'Content-Type: multipart/mixed; boundary="b"', "",
    "--b", "Content-Type: text/plain", "", "Is this real? https://intranet.corp.example/", "--b", "Content-Type: message/rfc822", "", inner, "--b--",
  ].join("\r\n");
  const r = parseEmail(outer, { psl });
  assert.equal(r.subject, "Password expires today");
  assert.equal(r.from.address, "it@helpdesk-reset.example");
  assert.deepEqual(r.links.map((l) => l.url), ["https://helpdesk-reset.example/r"]);
  assert.equal(r.wrapper.from.address, "pat@corp.example");
  assert.ok(ids(r).includes("no-auth-results"));
});

test("headers: folding, encoded words, addresses", () => {
  assert.equal(decodeWords("=?ISO-8859-1?Q?Andr=E9?= =?ISO-8859-1?Q?_Pirard?="), "André Pirard");
  assert.equal(decodeWords("=?unknown-charset?B?aGk=?="), "hi");
  assert.equal(parseAddress("plain@example.com").domain, "example.com");
  assert.equal(parseAddress('"Doe, Jane" <JANE@Example.COM>').domain, "example.com");
  assert.equal(parseAddress("undisclosed-recipients:;").address, null);
  const r = parseEmail('Subject: a\r\n  folded\r\n\tline\r\nFrom: x@y.example\r\nReply-To: "Doe, Jane" <jane@a.example>, b@b.example\r\n\r\nbody');
  assert.equal(r.subject, "a folded line");
  assert.deepEqual(r.replyTo.map((a) => [a.name, a.address]), [["Doe, Jane", "jane@a.example"], ["", "b@b.example"]], "commas inside quoted names do not split");
});

test("control and direction-override characters never reach displayed fields", () => {
  const r = parseEmail("From: =?UTF-8?Q?Bank=E2=80=AE?= <a@b.example>\r\nSubject: Hi\u0007there\r\n\r\n");
  assert.equal(r.from.name, "Bank");
  assert.equal(r.subject, "Hi there");
});

test("input that is not an email, or is too large, is rejected with a reason", () => {
  assert.equal(parseEmail("just some text").ok, false);
  assert.equal(parseEmail(42).ok, false);
  assert.match(parseEmail(`Subject: x\r\n\r\n${"a".repeat(EMAIL_LIMITS.bytes)}`).message, /5 MB/);
});

test("hostile structure is capped: parts, depth, links", () => {
  let nested = "Content-Type: text/plain\r\n\r\nend";
  for (let i = 0; i < 20; i++) nested = `Content-Type: multipart/mixed; boundary="n${i}"\r\n\r\n--n${i}\r\n${nested}\r\n--n${i}--`;
  const deep = parseEmail(`Subject: deep\r\n${nested}`);
  assert.ok(ids(deep).includes("truncated"));

  const many = Array.from({ length: 300 }, (_, i) => `--p\r\nContent-Type: text/plain\r\n\r\nhttps://s${i}.example/`).join("\r\n");
  const wide = parseEmail(`Subject: wide\r\nContent-Type: multipart/mixed; boundary="p"\r\n\r\n${many}\r\n--p--`);
  assert.ok(ids(wide).includes("truncated"));
  assert.ok(wide.links.length <= EMAIL_LIMITS.links);

  const links = Array.from({ length: 400 }, (_, i) => `https://l${i}.example/`).join(" ");
  const lots = parseEmail(`Subject: links\r\nContent-Type: text/plain\r\n\r\n${links}`);
  assert.equal(lots.links.length, EMAIL_LIMITS.links);
  assert.ok(ids(lots).includes("links-truncated"));
});

test("pathological HTML is scanned in linear time", () => {
  const html = `<a href="https://x.example/">${"<a ".repeat(200000)}`;
  const t = performance.now();
  const r = parseEmail(`Subject: x\r\nContent-Type: text/html\r\n\r\n${html}${"<b>".repeat(200000)}`);
  assert.ok(performance.now() - t < 3000, `took ${Math.round(performance.now() - t)} ms`);
  assert.equal(r.links[0].url, "https://x.example/");
});

test("risky attachment types and the forms links take in plain text", () => {
  const r = parseEmail([
    "From: a@b.example", "Subject: x", 'Content-Type: multipart/mixed; boundary="z"', "",
    "--z", "Content-Type: text/plain", "", "Go to hxxps://evil.example/a), or (https://evil.example/b).", "",
    "--z", 'Content-Disposition: attachment; filename="invoice.iso"', "Content-Type: application/octet-stream", "", "x",
    "--z", 'Content-Disposition: attachment; filename="report.pdf"', "Content-Type: application/pdf", "", "x",
    "--z--",
  ].join("\r\n"));
  assert.deepEqual(r.links.map((l) => l.url), ["hxxps://evil.example/a", "https://evil.example/b"]);
  assert.ok(ids(r).includes("risky-attachment"));
  assert.equal(r.findings.filter((f) => f.id.endsWith("attachment")).length, 1, "a plain PDF is not flagged");
});

test("a brand word inside another word is not a brand claim", () => {
  const r = parseEmail("From: Applebee's Rewards <news@applebees.example>\r\nSubject: x\r\n\r\n", { psl });
  assert.ok(!ids(r).includes("display-name-brand"));
});

test("the email report defangs every address and link and escapes message text", () => {
  const email = parseEmail(LURE, { psl });
  const links = email.links.map((link) => ({ link, report: analyzeUrl(link.url, { psl }) }));
  const out = emailToMarkdown(email, links, new Date("2026-11-17T00:00:00Z"));
  for (const h of ["## Findings", "## Links", "## Attachments (not opened)", "## Method and limits"]) assert.ok(out.includes(h), h);
  assert.match(out, /DMARC fail/);
  assert.match(out, /alerts\[@\]secure-paypa1\[\.\]example/);
  assert.ok(!/https?:\/\//.test(out), "no live scheme anywhere");
  const live = out.match(/[a-z0-9-]\.(?:com|example|html|zip)\b/gi);
  assert.equal(live, null, `no live host or file name anywhere: ${live}`);
});
