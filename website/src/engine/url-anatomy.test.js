import assert from "node:assert/strict";
import test from "node:test";
import { PSL_COMMIT, RULES } from "./generated/psl-rules.js";
import { PublicSuffixList } from "./psl.js";
import { detectIndicators } from "./indicators.js";
import { readFileSync } from "node:fs";
import { MAX_URL_LENGTH, dissect } from "./url-anatomy.js";

const psl = new PublicSuffixList(RULES, PSL_COMMIT);
const d = (raw) => dissect(raw, psl);
// Findings come from the indicator rules, which read these facts.
const findings = (r) => detectIndicators(r);
const ids = (r) => findings(r).map((o) => o.id);

// ------------------------------------------------------------ rejection policy
for (const [raw, code] of [
  ["", "empty"],
  ["   ", "empty"],
  [`example.com/${"x".repeat(MAX_URL_LENGTH)}`, "too_long"],
  ["javascript:alert(1)", "scheme_not_allowed"],
  ["JaVaScRiPt:alert(1)", "scheme_not_allowed"],
  ["data:text/html,<script>x</script>", "scheme_not_allowed"],
  ["file:///C:/secrets.txt", "scheme_not_allowed"],
  ["ftp://example.com/x", "scheme_not_allowed"],
  ["mailto:a@example.com", "scheme_not_allowed"],
  ["https://", "missing_host"],
  ["http:/example.com", "malformed"],
  ["https:example.com", "malformed"],
  ["https://exa\u202Emple.com", "control_chars"],
  ["https://exa\u200Bmple.com", "control_chars"],
  ["https://example.com/a\nb", "control_chars"],
  ["https://exam ple.com", "whitespace"],
  ["https://evil.com\\@good.example", "backslash"],
  ["https://example.com:99999/", "invalid_port"],
  ["https://example.com:abc/", "invalid_port"],
  ["https://example.com:0/", "invalid_port"],
  ["https://%65vil.com/", "invalid_host"],
  ["https://a..b.com/", "invalid_host"],
  [`https://${"a".repeat(64)}.com/`, "invalid_host"],
  ["https://exa!mple.com/", "invalid_host"],
  ["<img src=x onerror=alert(1)>", "whitespace"],
]) {
  test(`rejects ${JSON.stringify(raw.slice(0, 40))} as ${code}`, () => {
    const r = d(raw);
    assert.equal(r.ok, false);
    assert.equal(r.code, code);
    assert.ok(r.message);
  });
}

// Cases shared with the Python validator (tests/test_url_parity_cases.py).
// A `js` entry is an intentional, explained difference: hosts outside
// IDNA2008 that some URL parsers accept. Where this runtime's parser rejects
// one, the result must be Python's.
const SHARED = JSON.parse(readFileSync(new URL("../../../tests/fixtures/url_cases.json", import.meta.url), "utf8")).cases;
for (const c of SHARED) {
  test(`shared case ${JSON.stringify(c.url).slice(0, 50)}`, () => {
    const r = d(c.url);
    const expected = c.js && r.ok ? c.js : c;
    if (expected.error) {
      assert.equal(r.code, expected.error);
      return;
    }
    assert.equal(r.ok, true, r.code);
    assert.equal(r.host, expected.host);
    if ("idnaProblem" in expected) assert.equal(r.idnaProblem, expected.idnaProblem);
    if ("ip_obfuscated" in c) assert.equal(r.rewritten, c.ip_obfuscated);
  });
}

test("error messages never echo the input", () => {
  for (const raw of ["javascript:alert('PAYLOAD')", "https://PAYLOAD\u202E.com", "https://exam PAYLOAD.com"]) {
    assert.ok(!d(raw).message.includes("PAYLOAD"));
  }
});

test("accepts exactly the length limit and rejects one more character", () => {
  const base = "https://example.com/";
  assert.equal(d(base + "a".repeat(MAX_URL_LENGTH - base.length)).ok, true);
  assert.equal(d(base + "a".repeat(MAX_URL_LENGTH - base.length + 1)).code, "too_long");
});

test("rejects non-string input", () => {
  assert.equal(d(undefined).ok, false);
  assert.equal(d(42).ok, false);
});

// ------------------------------------------------------------ scheme handling
test("never assumes https for a bare domain", () => {
  const r = d("  example.com/login  ");
  assert.equal(r.ok, true);
  assert.equal(r.scheme, "http");
  assert.equal(r.schemeExplicit, false);
  assert.ok(ids(r).includes("no-scheme"));
  assert.ok(!ids(r).includes("http"));
});

test("bare host with a port is not mistaken for a scheme", () => {
  const r = d("example.org:8443/login");
  assert.equal(r.ok, true);
  assert.equal(r.host, "example.org");
  assert.equal(r.port, "8443");
  assert.ok(ids(r).includes("port"));
});

test("mixed-case scheme and host are normalised", () => {
  const r = d("HTTPS://WWW.EXAMPLE.COM/Path");
  assert.equal(r.scheme, "https");
  assert.equal(r.host, "www.example.com");
  assert.equal(r.path, "/Path");
  assert.equal(r.rewritten, false);
});

test("a scheme-less URL with a URL in its query is still scheme-less", () => {
  const r = d("example.com/r?u=https://other.example");
  assert.equal(r.host, "example.com");
  assert.ok(ids(r).includes("embedded-url"));
});

// ------------------------------------------------------------ registrable domain
test("brand names left of the registrable domain are identified as subdomain", () => {
  const r = d("https://login.paypal.com.account-verify.co.uk/session");
  assert.equal(r.registrableDomain, "account-verify.co.uk");
  assert.equal(r.subdomain, "login.paypal.com");
  assert.equal(r.subdomainLabels, 3);
  assert.ok(ids(r).includes("brand-in-subdomain"));
});

test("shared hosting platforms group by owner (private PSL section)", () => {
  assert.equal(d("https://victim-login.github.io/").registrableDomain, "victim-login.github.io");
});

test("segments reconstruct the canonical URL", () => {
  for (const raw of ["https://a.b.example.co.uk:8443/p/q?x=1#f", "http://user:pw@login.evil.tk/x", "https://[2001:db8::1]/"]) {
    const r = d(raw);
    const joined = r.segments.map((s) => s.text).join("");
    // href never contains credentials; the segments show a fixed marker instead.
    assert.ok(!r.href.includes("@"));
    const expected = r.hasCredentials ? r.href.replace("://", "://•••@") : r.href;
    assert.equal(joined.replace(/\/$/, ""), expected.replace(/\/$/, ""));
  }
});

// ------------------------------------------------------------ deceptive constructions
test("credentials are flagged but never revealed", () => {
  const r = d("https://paypal.com:SECRETPW@evil.tk/login");
  assert.equal(r.ok, true);
  assert.equal(r.host, "evil.tk");
  assert.equal(r.hasCredentials, true);
  const text = JSON.stringify(r);
  assert.ok(!text.includes("SECRETPW"), "password must not appear in any output");
  assert.ok(r.segments.some((s) => s.part === "credentials" && s.text === "•••@"));
  assert.ok(ids(r).includes("credentials"));
});

for (const [raw, canonical] of [
  ["http://3232235777/x", "192.168.1.1"],
  ["http://0xC0A80101/", "192.168.1.1"],
  ["http://0300.0250.1.1/", "192.168.1.1"],
  ["http://127.1/", "127.0.0.1"],
  ["http://\uff11\uff12\uff17.\uff10.\uff10.\uff11/", "127.0.0.1"],
]) {
  test(`disguised IPv4 ${JSON.stringify(raw)} is revealed as ${canonical}`, () => {
    const r = d(raw);
    assert.equal(r.isIp, true);
    assert.equal(r.host, canonical);
    assert.ok(ids(r).includes("ip-host") && ids(r).includes("ip-disguised"));
  });
}

test("a plainly written IP is not called disguised; private ranges are explained", () => {
  const r = d("http://192.168.1.100/chase/login");
  assert.ok(ids(r).includes("ip-host"));
  assert.ok(!ids(r).includes("ip-disguised"));
  assert.match(findings(r).find((o) => o.id === "ip-host").detail, /private/);
});

test("IPv6 hosts are recognised", () => {
  const r = d("http://[::1]:8080/");
  assert.equal(r.isIp, true);
  assert.equal(r.ipVersion, 6);
  assert.match(findings(r).find((o) => o.id === "ip-host").detail, /loopback/);
});

test("IPv6 written in long or zero-padded form is notation, not a disguise", () => {
  for (const raw of ["http://[0:0:0:0:0:0:0:1]/", "http://[2001:0db8::1]/"]) {
    assert.ok(!ids(d(raw)).includes("ip-disguised"), raw);
  }
});

test("punycode look-alike is decoded and mixed alphabets are flagged", () => {
  const r = d("https://xn--pple-43d.com/login");
  assert.equal(r.host, "xn--pple-43d.com");
  assert.equal(r.displayHost, "\u0430pple.com");
  assert.ok(ids(r).includes("idn"));
  assert.ok(!ids(r).includes("host-rewritten"));
});

test("Unicode input is encoded to punycode and flagged", () => {
  const r = d("https://\u0440\u0430\u0443\u0440\u0430l.com/");
  assert.ok(r.host.startsWith("xn--"));
  assert.ok(ids(r).includes("idn") && ids(r).includes("mixed-script"));
});

test("fullwidth letters are reported as a browser rewrite", () => {
  const r = d("https://\uff45\uff58\uff41\uff4d\uff50\uff4c\uff45.com/");
  assert.equal(r.host, "example.com");
  assert.ok(ids(r).includes("host-rewritten"));
});

test("trailing dot is tolerated and removed", () => {
  const r = d("https://example.com./");
  assert.equal(r.host, "example.com");
  assert.equal(r.registrableDomain, "example.com");
});

test("an ordinary https URL produces no notable findings", () => {
  const r = d("https://www.example.org/docs?page=2");
  assert.equal(r.ok, true);
  assert.deepEqual(findings(r).filter((o) => o.severity !== "info" && o.severity !== "low"), []);
});

test("output never contains a verdict, score or probability field", () => {
  const r = d("http://login.paypal.com.evil.tk/verify");
  for (const key of ["verdict", "score", "probability", "confidence", "risk", "safe", "malicious"]) {
    assert.ok(!(key in r), `unexpected field ${key}`);
  }
  const text = findings(r).map((o) => `${o.title} ${o.detail}`).join(" ").toLowerCase();
  for (const word of ["phishing detected", "is safe", "malicious", "% confidence"]) {
    assert.ok(!text.includes(word), `verdict-like wording: ${word}`);
  }
});
