import assert from "node:assert/strict";
import test from "node:test";
import { PSL_COMMIT, RULES } from "./generated/psl-rules.js";
import { PublicSuffixList } from "./psl.js";
import { decodePunycode, toUnicodeHost } from "./punycode.js";

const psl = new PublicSuffixList(RULES);

// A subset of the official vectors from tests/test_psl.txt at PSL_COMMIT
// (public domain), in ASCII form as the browser's URL parser produces it.
const OFFICIAL = [
  ["example.com", "example.com"], ["www.example.com", "example.com"], ["com", null],
  ["example.example", "example.example"], ["b.example.example", "example.example"],
  ["biz", null], ["domain.biz", "domain.biz"], ["a.b.domain.biz", "domain.biz"],
  ["uk.com", null], ["example.uk.com", "example.uk.com"], ["b.example.uk.com", "example.uk.com"],
  ["test.ac", "test.ac"], ["mm", null], ["c.mm", null], ["b.c.mm", "b.c.mm"], ["a.b.c.mm", "b.c.mm"],
  ["jp", null], ["test.jp", "test.jp"], ["www.test.jp", "test.jp"], ["ac.jp", null],
  ["test.ac.jp", "test.ac.jp"], ["kyoto.jp", null], ["test.kyoto.jp", "test.kyoto.jp"],
  ["ide.kyoto.jp", null], ["b.ide.kyoto.jp", "b.ide.kyoto.jp"], ["c.kobe.jp", null],
  ["b.c.kobe.jp", "b.c.kobe.jp"], ["city.kobe.jp", "city.kobe.jp"], ["www.city.kobe.jp", "city.kobe.jp"],
  ["ck", null], ["test.ck", null], ["b.test.ck", "b.test.ck"], ["www.ck", "www.ck"],
  ["us", null], ["test.us", "test.us"], ["ak.us", null], ["test.ak.us", "test.ak.us"],
  ["k12.ak.us", null], ["test.k12.ak.us", "test.k12.ak.us"],
  ["xn--85x722f.com.cn", "xn--85x722f.com.cn"], ["xn--55qx5d.cn", null],
  ["xn--85x722f.xn--55qx5d.cn", "xn--85x722f.xn--55qx5d.cn"],
];

test(`PSL @ ${PSL_COMMIT.slice(0, 12)} has the expected rule count`, () => {
  assert.equal(RULES.length, 10336);
});

for (const [host, expected] of OFFICIAL) {
  test(`registrableDomain(${host}) = ${expected}`, () => {
    assert.equal(psl.registrableDomain(host), expected);
  });
}

test("malformed hosts have no registrable domain", () => {
  for (const h of ["", ".example.com", "a..b.com"]) assert.equal(psl.registrableDomain(h), null);
});

// RFC 3492 section 7.1 sample strings and common IDNs.
for (const [puny, unicode] of [
  ["egbpdaj6bu4bxfgehfvwxn", "ليهمابتكلموشعربي؟"],
  ["ihqwcrb4cv8a8dqg056pqjye", "他们为什么不说中文"],
  ["bcher-kva", "bücher"],
  ["mnchen-3ya", "münchen"],
  ["pple-43d", "аpple"],
]) {
  test(`decodePunycode(${puny})`, () => assert.equal(decodePunycode(puny), unicode));
}

test("invalid punycode returns null and leaves the label unchanged for display", () => {
  assert.equal(decodePunycode("ÿ"), null);
  assert.equal(toUnicodeHost("xn--zz!.com"), "xn--zz!.com");
});
