import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import test from "node:test";
import { analyzeUrl, splitBatch } from "./analyze.js";
import { BRANDS, officialBrandFor } from "./brands.js";
import { asciiFold, editDistance, skeleton } from "./confusables.js";
import { defang, refang } from "./defang.js";
import { PSL_COMMIT, RULES } from "./generated/psl-rules.js";
import { canonical, charNgrams, createScorer, hostText, modelIdentity, verifiedScorer } from "./model.js";
import { murmurhash3_32 } from "./murmurhash3.js";
import { PublicSuffixList } from "./psl.js";
import { decideVerdict, modelBand, VERDICTS } from "./verdict.js";

const psl = new PublicSuffixList(RULES, PSL_COMMIT);
const run = (raw, scorer = null) => analyzeUrl(raw, { psl, scorer, now: () => new Date("2026-01-01T00:00:00Z") });
// URL parsers differ on names outside IDNA2008: Node 22 rejects invalid or
// disallowed xn-- labels that Chrome and Node 24 accept, and Chrome rejects
// some that Node accepts. Rejecting such a host is also safe (it is never
// scored); it must then be reported as an IDN problem.
const rejectedByThisRuntime = (url, r) => {
  if (URL.canParse(url)) return false;
  assert.equal(r.ok, false, url);
  assert.equal(r.code, "invalid_idn", url);
  return true;
};
const ids = (r) => r.indicators.map((i) => i.id);

// ------------------------------------------------------------ murmurhash parity
// Reference values from sklearn.utils.murmurhash3_32(s.encode("utf-8"), seed=0).
const MURMUR = [["", 0], ["a", 1009084850], ["ab", -1681926305], ["abc", -1277324294], ["abcd", 1139631978],
  ["abcde", -392455434], ["pay", 948311561], ["paypal-login", 880822966], ["xn--pple-43d", 92333550],
  ["é", 269551495], ["日本語", -1515949417], ["😀x", 1914495294]];
for (const [text, expected] of MURMUR) {
  test(`murmurhash3_32(${JSON.stringify(text)}) matches scikit-learn`, () => {
    assert.equal(murmurhash3_32(new TextEncoder().encode(text), 0), expected);
  });
}

test("char n-grams follow Python code-point slicing", () => {
  assert.deepEqual(charNgrams("abcd", [3, 5]), ["abc", "bcd", "abcd"]);
  assert.deepEqual(charNgrams("ab", [3, 5]), []);
  assert.deepEqual(charNgrams("a😀bc", [3, 3]), ["a😀b", "😀bc"]);
});

test("host text strips one leading www. only when the host has two or more dots", () => {
  assert.equal(hostText("www.example.com"), "example.com");
  assert.equal(hostText("www.com"), "www.com");
  assert.equal(hostText("www.www.example.com"), "www.example.com");
});

test("scorer rejects unknown artifacts", () => {
  assert.throws(() => createScorer({ format: "other" }));
  assert.throws(() => createScorer(null));
});

const GOLDEN = new URL("./models/url-host-model.golden.json", import.meta.url);
const ARTIFACT = new URL("./models/url-host-model.js", import.meta.url);
// The model is part of the product: a missing artifact must fail CI, not skip.
test("bundled model reproduces the Python golden vectors", async () => {
  assert.ok(existsSync(GOLDEN) && existsSync(ARTIFACT), "model artifact or golden vectors missing; run phase3/run.py engine");
  const { MODEL } = await import(ARTIFACT.href);
  const scorer = createScorer(MODEL);
  const golden = JSON.parse(readFileSync(GOLDEN, "utf8"));
  assert.equal(golden.model_id, MODEL.id, "golden vectors belong to a different model");
  const vectors = golden.vectors;
  assert.ok(vectors.length >= 300, "expected at least 300 golden vectors");
  for (const v of vectors) {
    const r = run(v.url);
    assert.ok(r.ok, `the browser parser rejects ${v.url}`);
    // Scored directly: the analyser itself skips the model for IP hosts.
    const s = scorer.score(r.facts.host);
    assert.equal(s.text, v.text, `host text for ${v.url}`);
    assert.ok(Math.abs(s.logit - v.logit) < 1e-9, `logit for ${v.url}: ${s.logit} vs ${v.logit}`);
    assert.ok(Math.abs(s.probability - v.probability) < 1e-9, `probability for ${v.url}`);
  }
});

const MODEL_ARTIFACT = existsSync(ARTIFACT) ? createScorer((await import(ARTIFACT.href)).MODEL) : null;
const withModel = (raw) => run(raw, MODEL_ARTIFACT);

test("ordinary domains that contain brand words are not brand impersonation", () => {
  for (const u of ["https://purchase.com/", "https://laws.com/", "https://pineapple.com/", "https://www.interactive.com/",
    "https://news.paws.org/", "https://drawsome.co.uk/", "https://outlookindia.com/", "https://cityofchase.gov/", "https://apple-pie-recipes.com/", "https://chasewood-apartments.com/"]) {
    const ids = run(u).indicators.map((i) => i.id);
    assert.ok(!ids.some((id) => id.startsWith("brand-")), `${u}: ${ids}`);
  }
  for (const u of ["https://apple-id-verify.com/", "https://chase-online.net/", "https://chase-bank-alert.com/", "https://myapple.support/", "https://applesupport.help/", "https://aws-console-login.com/", "https://apple.evil.example/", "https://dhl-parcel-redelivery.com/"]) {
    assert.ok(run(u).indicators.some((i) => ["brand-in-domain", "brand-unlisted-domain", "brand-in-subdomain"].includes(i.id)), u);
  }
});

test("IP hosts are not scored by the hostname model and local ranges are explained", () => {
  for (const u of ["http://127.0.0.1:5173/app/", "https://192.168.1.1/admin", "https://203.0.113.9/"]) {
    const r = withModel(u);
    assert.equal(r.model, null, u);
    assert.notEqual(r.verdict.level, "high-risk", u);
  }
  assert.match(run("https://192.168.1.1/").indicators.find((i) => i.id === "ip-host").detail, /private/);
});

test("brand names on user-content hosts of the brand's own domain are still checked", () => {
  assert.ok(run("https://microsoft-account-verify.sharepoint.com/").indicators.some((i) => i.id === "brand-in-subdomain"));
  assert.ok(run("https://contoso.sharepoint.com/paypal/signin").indicators.some((i) => i.id === "brand-in-path"));
  assert.ok(run("https://sites.google.com/view/gmail-verify").indicators.some((i) => i.id === "brand-in-path"));
  assert.ok(!run("https://contoso.sharepoint.com/").indicators.some((i) => i.id.startsWith("brand-")));
});

test("embedded addresses: look-alike suffixes and backslash forms are caught", () => {
  const has = (u) => run(u).indicators.some((i) => i.id === "embedded-url");
  assert.ok(has("https://example.com/?x=https://notexample.com/"));
  assert.ok(has("https://example.com/?x=/%5Cevil.example/"), "encoded backslash form");
  assert.ok(!has("https://example.com/?x=https://www.example.com/a"));
});

// ------------------------------------------------------------ look-alikes
test("skeleton folds Cyrillic look-alikes; asciiFold folds digit swaps", () => {
  assert.equal(skeleton("раураl"), "paypal");
  assert.equal(asciiFold("paypa1"), "paypal");
  assert.equal(asciiFold("rnicrosoft"), "microsoft");
});

test("edit distance counts adjacent swaps as one edit", () => {
  assert.equal(editDistance("paypal", "paypla"), 1);
  assert.equal(editDistance("netflix", "netfliks", 3), 2);
});

test("brand reference data is well-formed", () => {
  for (const b of BRANDS) {
    assert.ok(b.tokens.every((t) => t === t.toLowerCase()));
    for (const d of b.domains) assert.equal(psl.split(d).registrableDomain, d, `${d} must be a registrable domain`);
  }
  assert.equal(officialBrandFor("paypal.com").id, "paypal");
});

// ------------------------------------------------------------ indicators
const CASES = [
  ["http://paypal.com.secure-account.tk/login", ["brand-in-subdomain", "domain-in-subdomain", "free-tld", "http-credential-path"], "high-risk"],
  ["https://login.microsoftonline.com/common/oauth2", [], "no-strong-indicators"],
  ["https://www.paypal.com/signin", [], "no-strong-indicators"],
  ["https://paypal-secure-login.com/", ["brand-in-domain", "host-keywords"], "high-risk"],
  ["https://paypa1.com/", ["typosquat"], "suspicious"],
  ["https://xn--pple-43d.com/", ["idn", "homograph"], "high-risk"],
  ["http://3232235777/bank", ["ip-host", "ip-disguised"], "high-risk"],
  ["http://192.0.2.10/login", ["ip-host", "http-credential-path"], "high-risk"],
  ["https://user:pw@evil.example/", ["credentials"], "high-risk"],
  ["https://bit.ly/3abcd", ["shortener"], "inconclusive"],
  ["https://example.org/r?url=https://evil.example/", ["embedded-url"], "suspicious"],
  ["https://cdn.example.com/files/invoice.pdf.exe", ["download"], "suspicious"],
  ["https://victim-login.github.io/", ["shared-hosting", "host-keywords"], "inconclusive"],
  ["https://www.example.org/docs?page=2", [], "no-strong-indicators"],
];
for (const [url, expected, level] of CASES) {
  test(`indicators for ${url}`, () => {
    const r = run(url);
    assert.equal(r.ok, true);
    for (const id of expected) assert.ok(ids(r).includes(id), `${id} missing; got ${ids(r)}`);
    if (!expected.length) assert.deepEqual(r.indicators.filter((i) => i.severity !== "info"), []);
    assert.equal(r.verdict.level, level);
  });
}

test("the xn-- prefix of an internationalised name is not counted as hyphens", () => {
  const r = run("https://xn--pple-43d.com/");
  assert.ok(!ids(r).includes("hyphenated-domain"));
  assert.match(r.indicators.find((i) => i.id === "mixed-script").detail, /U\+0430/);
  assert.ok(ids(run("https://secure-paypal-account-update.com/")).includes("hyphenated-domain"));
});

test("user-content domains of listed brands are not treated as the brand's own site", () => {
  for (const url of ["https://paypal-account-verify.sharepoint.com/sites/paypal/login.html",
    "https://dl.dropboxusercontent.com/s/x/paypal-login.html", "https://sites.google.com/view/paypal-account-verify/login"]) {
    const r = run(url);
    assert.ok(!ids(r).includes("official-domain"), url);
    assert.ok(ids(r).includes("shared-hosting"), url);
  }
  // On a brand's own domain, another brand's name is still checked.
  assert.ok(ids(run("https://paypal-login.microsoft.com/")).some((id) => id.startsWith("brand-")));
});

test("decoded evidence cannot carry control or bidi characters, and embedded credentials are masked", () => {
  const d = run("https://example.com/x/%E2%80%AEexe.pdf%E2%80%AC.exe");
  const ev = d.indicators.find((i) => i.id === "download").evidence;
  assert.ok(!/[\u202a-\u202e\u2066-\u2069]/.test(ev));
  const q = run("https://example.com/?next=https://admin:hunter2@evil.example/");
  assert.ok(!JSON.stringify(q.indicators).includes("hunter2"));
});

test("defanged input is accepted", () => {
  const r = run("hxxp://paypal[.]com[.]secure-account[.]tk/login");
  assert.equal(r.ok, true);
  assert.equal(r.facts.registrableDomain, "secure-account.tk");
});

test("credentials never appear in any analysis output", () => {
  const r = run("https://paypal.com:SECRETPW@evil.tk/login");
  assert.ok(!JSON.stringify(r).includes("SECRETPW"));
});

test("rejected input returns the dissector's fixed error", () => {
  const r = run("javascript:alert(1)");
  assert.equal(r.ok, false);
  assert.equal(r.code, "scheme_not_allowed");
});

// ------------------------------------------------------------ verdict policy
const T = { high: 0.9, elevated: 0.6 };
const ind = (...sev) => sev.map((s, i) => ({ id: `x${i}`, severity: s, title: `t${i}` }));
for (const [indicators, p, level] of [
  [ind("high"), 0.01, "high-risk"],
  [ind("medium"), 0.95, "high-risk"],
  [ind("medium", "medium"), 0.7, "high-risk"],
  [ind("medium", "medium"), 0.1, "suspicious"],
  [ind("medium"), 0.1, "suspicious"],
  [ind(), 0.95, "suspicious"],
  [ind(), 0.7, "inconclusive"],
  [ind("low", "low"), 0.1, "inconclusive"],
  [ind("low"), 0.1, "no-strong-indicators"],
  [ind("info", "info", "info"), 0.1, "no-strong-indicators"],
]) {
  test(`verdict ${level} for [${indicators.map((i) => i.severity)}] at p=${p}`, () => {
    assert.equal(decideVerdict(indicators, { probability: p, thresholds: T }).level, level);
  });
}

test("a listed brand domain is not escalated by the model alone, but rules still apply", () => {
  const listed = [{ id: "official-domain", severity: "info", title: "listed" }];
  const v = decideVerdict(listed, { probability: 0.99, thresholds: T });
  assert.equal(v.level, "no-strong-indicators");
  assert.equal(v.band, "not-used");
  const withRedirect = decideVerdict([...listed, ...ind("medium")], { probability: 0.99, thresholds: T });
  assert.equal(withRedirect.level, "suspicious");
  const r = run("https://github.com/");
  assert.ok(ids(r).includes("official-domain"));
});

test("verdict labels never claim safety", () => {
  for (const { label } of Object.values(VERDICTS)) assert.ok(!/safe|clean|benign/i.test(label));
  assert.equal(modelBand(null), "unavailable");
  assert.match(decideVerdict([], null).reasons.join(" "), /not available/);
});

test("defang and refang round-trip", () => {
  const url = "https://login.example.co.uk/a@b";
  assert.equal(defang(url), "hxxps://login[.]example[.]co[.]uk/a[@]b");
  assert.equal(refang(defang(url)), url);
});

test("refang reads [at] as @ only before the path; text in a path or query is kept", () => {
  assert.equal(refang("hxxp://paypal.com[at]evil[.]example/login"), "http://paypal.com@evil.example/login");
  assert.equal(refang("user[at]example[.]com"), "user@example.com");
  assert.equal(refang("https://example.com/files/report[at]2024.pdf?by=team[AT]x"), "https://example.com/files/report[at]2024.pdf?by=team[AT]x");
  assert.equal(refang("https://example.com/a[@]b"), "https://example.com/a@b", "this platform's own form is refanged anywhere");
});

test("batch splitting caps the number of items", () => {
  const { items, truncated } = splitBatch("a\n\n b \r\nc", 2);
  assert.deepEqual(items, ["a", "b"]);
  assert.equal(truncated, true);
});

test("digit-swapped brand names next to other words are near-miss spellings", () => {
  for (const u of ["https://amaz0n-orders.com/", "https://faceb00k-security.com/", "https://paypa1-billing.net/"]) {
    assert.ok(run(u).indicators.some((i) => i.id === "typosquat"), u);
  }
  for (const u of ["https://blogger-tools.com/", "https://hello-world.org/"]) {
    assert.ok(!run(u).indicators.some((i) => i.id === "typosquat"), u);
  }
});

test("published per-site metrics describe the bundled model", async () => {
  const { MODEL } = await import(ARTIFACT.href);
  const sites = JSON.parse(readFileSync(new URL("../../../phase3/reports/engine/site_metrics.json", import.meta.url), "utf8"));
  assert.equal(sites.model_id, MODEL.id, "re-run phase3/run.py engine-sites after exporting a model");
});

test("a brand's name on a country suffix is noted as low, on a generic suffix as medium", () => {
  const sev = (u) => run(u).indicators.find((i) => i.id === "brand-unlisted-domain")?.severity;
  assert.equal(sev("https://www.spotify.com.ar/"), "low");
  assert.equal(sev("https://www.dhl.fr/"), "low");
  assert.equal(sev("https://paypal.xyz/"), "medium");
  assert.notEqual(run("https://www.spotify.com.ar/").verdict.level, "high-risk");
});

test("the model id is the SHA-256 of its scoring fields, computed as the Python exporter does", async () => {
  const { MODEL } = await import(ARTIFACT.href);
  // Same vector as phase3/tests/test_engine.py::test_canonical_matches_browser.
  assert.equal(canonical({ b: [1, true, "é"], a: 0.1, n: 65536 }),
    '{"a":0x3fb999999999999a,"b":[0x3ff0000000000000,true,"\\u00e9"],"n":0x40f0000000000000}');
  const { id, sha256 } = await modelIdentity(MODEL);
  assert.equal(MODEL.id, id);
  assert.equal(MODEL.sha256, sha256);
  assert.ok((await verifiedScorer(MODEL)).score("example.com").probability > 0);
  // Any change to what decides a score is caught before the model is used.
  for (const change of [{ intercept: MODEL.intercept + 1e-12 }, { thresholds: { ...MODEL.thresholds, high: 0.5 } }, { coefBase64: `${MODEL.coefBase64[0] === "B" ? "C" : "B"}${MODEL.coefBase64.slice(1)}` }]) {
    await assert.rejects(verifiedScorer({ ...MODEL, ...change }), /does not match its id/);
  }
  // Evaluation metadata is not part of the identity.
  assert.equal((await modelIdentity({ ...MODEL, evaluation: {} })).id, MODEL.id);
});

test("hosts outside IDNA2008 are flagged and not scored, as the Python pipeline drops them", () => {
  for (const [url, problem] of [
    ["https://\u{1F4A9}.la/", "disallowed-character"], // emoji
    ["https://pay\u00a3pal.com/", "disallowed-character"], // currency symbol
    ["https://pay\u00bepal.com/", "disallowed-character"], // fraction, becomes 3\u20444
    ["https://xn--a.com/", "disallowed-character"], // decodes to the control character U+0080
    ["https://pay\u0871pal.com/", "mixed-direction"], // Arabic letter inside a Latin label
    ["https://\u1100x.example/", "disallowed-character"], // a conjoining Hangul jamo that does not compose
  ]) {
    const r = run(url, MODEL_ARTIFACT);
    if (rejectedByThisRuntime(url, r)) continue;
    assert.equal(r.ok, true, url);
    assert.equal(r.facts.idnaProblem, problem, url);
    assert.equal(r.model, null, url);
    assert.equal(r.modelSkipped, "nonstandard-idn", url);
    assert.ok(r.indicators.some((i) => i.id === "idn-nonstandard"), url);
  }
  for (const url of ["https://b\u00fccher.de/", "https://xn--mgbh0fb.xn--kgbechtv/", "https://\u0645\u062b\u0627\u06441.example/",
    "https://\u13a2\u13a3.example/", "https://xn--fiq228c.xn--55qx5d.cn/", "https://www.example.com/"]) {
    const r = run(url, MODEL_ARTIFACT);
    assert.equal(r.facts.idnaProblem, null, url);
    assert.equal(r.modelSkipped, null, url);
    if (MODEL_ARTIFACT) assert.ok(r.model, url);
  }
  assert.equal(run("http://192.168.1.1/", MODEL_ARTIFACT).modelSkipped, "ip-address");
});

test("official country domains and frequently impersonated brands are recognised; look-alikes are not", () => {
  for (const url of ["https://amazon.com.mx/", "https://www.google.co.in/", "https://www.ebay.com.au/", "https://www.hsbc.com.hk/",
    "https://www.apple.com.cn/", "https://shopify.com/", "https://proton.me/", "https://protonmail.com/", "https://cash.app/"]) {
    const r = run(url, MODEL_ARTIFACT);
    assert.ok(r.indicators.some((i) => i.id === "official-domain"), url);
    assert.equal(r.verdict.level, "no-strong-indicators", url);
  }
  for (const url of ["https://shopify-login.example/", "http://cashapp-support.xyz/", "https://protonmail.secure-login.tk/"]) {
    assert.equal(run(url, MODEL_ARTIFACT).verdict.level, "high-risk", url);
  }
  // Shops on myshopify.com belong to their merchants, not to Shopify.
  const shop = run("https://acme.myshopify.com/", MODEL_ARTIFACT);
  assert.ok(!shop.indicators.some((i) => i.id === "official-domain"));
  assert.ok(shop.indicators.some((i) => i.id === "shared-hosting"));
});

test("masking login text is linear on long pasted lines", async () => {
  const { maskCredentials } = await import("./defang.js");
  const start = performance.now();
  maskCredentials("a".repeat(200_000));
  assert.ok(performance.now() - start < 500, "masking 200,000 characters took too long");
  assert.equal(maskCredentials("http://user:pw@host.example/a@b x@y"), "http://•••@host.example/•••@b •••@y"); // any run ending in @ is masked
});

test("a host with hidden formatting characters is shown encoded, never decoded", () => {
  // xn--lapyap-9l0c decodes to U+202E (right-to-left override) + "lapyap".
  const url = "https://xn--lapyap-9l0c.com/";
  const r = run(url);
  if (rejectedByThisRuntime(url, r)) return;
  assert.equal(r.facts.displayHost, "xn--lapyap-9l0c.com");
  assert.ok(r.indicators.some((i) => i.id === "idn-nonstandard"));
  for (const i of r.indicators) assert.ok(!/[\u202a-\u202e\u2066-\u2069]/.test(`${i.title} ${i.detail} ${i.evidence}`), i.id);
});

test("when the model is set aside, the verdict reasons say why instead of 'not available'", () => {
  const ip = run("http://192.168.1.1/", MODEL_ARTIFACT).verdict.reasons.join(" ");
  assert.doesNotMatch(ip, /not available/);
  assert.doesNotMatch(run("https://xn--ls8h.la/", MODEL_ARTIFACT).verdict.reasons.join(" "), /not available/);
  assert.match(decideVerdict([], null, { skipped: "nonstandard-idn" }).reasons.join(" "), /outside the domain name standard/);
  assert.match(decideVerdict([], null, { skipped: "ip-address" }).reasons.join(" "), /does not score IP addresses/);
});

test("look-alike checks still run on hosts outside IDNA2008; hidden formatting is medium", () => {
  // Cyrillic "а" in "apple" plus a currency sign: outside IDNA2008 and a mixed-script look-alike.
  const mixed = run("https://\u0430pple\u00a3.com/", MODEL_ARTIFACT);
  assert.ok(mixed.indicators.some((i) => i.id === "mixed-script" && i.severity === "high"));
  assert.equal(mixed.verdict.level, "high-risk");
  // A right-to-left override hidden in the name.
  const rloUrl = "https://xn--lapyap-9l0c.com/";
  const rlo = run(rloUrl, MODEL_ARTIFACT);
  if (!rejectedByThisRuntime(rloUrl, rlo)) {
    assert.equal(rlo.indicators.find((i) => i.id === "idn-nonstandard").severity, "medium");
    assert.equal(rlo.verdict.level, "suspicious");
  }
  // Writing a name in Unicode is not a "rewrite" just because it is shown encoded.
  assert.ok(!run("https://pay\u00a3pal.com/").indicators.some((i) => i.id === "host-rewritten"));
});
