# Security and privacy notes

## Data flow

- **Analysis runs in the browser.** Input is parsed by the browser's `URL`
  parser, checked against a bundled Public Suffix List and scored by a bundled
  model. No code path fetches, resolves or opens a submitted link.
- **Network access is blocked by policy.** The CSP sets `connect-src 'none'`
  and `form-action 'none'`; after the page's own same-origin scripts, styles,
  fonts and data modules load, the page cannot make requests.
- **Storage is local.** Analyses, investigations, indicators and the activity
  log live in IndexedDB for this origin and browser profile. The theme
  preference uses `localStorage`. There are no cookies.
- **Exports are explicit.** Reports, backups and indicator files are created
  as Blobs and saved only when the user chooses to.
- **No analytics, trackers, third-party scripts or fonts.** Fonts are
  self-hosted (IBM Plex, OFL). The Cloudflare zone features that inject
  scripts must stay off (see `DEPLOYMENT.md` §2).

## Threat model

| Threat | Control | Verified by |
|---|---|---|
| XSS through a crafted link, note, tag or imported file | All rendering via Preact text nodes or `textContent`; no `innerHTML`, `dangerouslySetInnerHTML` or `eval`; CSP `script-src 'self'`, no inline script or style | Unit tests; e2e tests with markup payloads under the production CSP |
| Analysis causes a request (SSRF, tracking, DNS) | No fetch in the engine; `connect-src 'none'` | e2e asserts no request contains the analysed host |
| Misleading normalisation (IDN, mixed script, encoded IPs, `user@host`, backslashes) | Explicit input policy; differences between written and parsed form reported as indicators | `engine/url-anatomy.test.js`, `engine/engine.test.js` |
| Credential leakage | Login text before `@` is never stored in output fields, reports, backups or exports; rejected input is echoed only with every `…@` run masked | Unit tests assert the password never appears |
| Malicious imports (backup, CSV, STIX, text) | 5 MB, 20,000-record and 10,000-analysis caps (re-analysis runs in chunks so the page stays responsive); ids must be strings; every record rebuilt field by field (types, ISO dates, enums, id format, known history actions); analyses re-run by the current engine from the link as written (login text masked), so a file cannot carry a forged verdict and a restore reproduces the original evidence; activity entries are never imported (a restore logs one entry of its own); intact existing records are never overwritten (a damaged one is replaced by the backup's valid copy; an intact one only gains a missing back-link to a restored case or indicator); links between cases and indicators are kept only when both sides state them, in the workspace or in the backup, and the target exists; duplicate note ids are dropped; indicator values validated like the analyser (no invisible characters, no truncation, real IPv6); 5,000 indicators per import | `workspace/workspace.test.js` |
| Partial writes (failed restore, quota, crash mid-change) | Every change that touches several records, every restore and every indicator import is one IndexedDB transaction across the affected stores: it lands completely or not at all; changes run one at a time | Unit tests with a store whose transactions fail |
| Damaged stored data | Every record read is shape-checked; damaged records are left out of lists and counts, listed in Settings → Workspace health and removable there; a per-page error boundary remains as a last resort | Unit and e2e tests that write damaged records directly |
| Spreadsheet formula injection | CSV cells, and each item inside joined tag and source lists, starting with `= + - @` (or tab/CR, after optional spaces) are prefixed with `'`; cells containing `,` `;` tab, quotes or line breaks are quoted, so `;`-separated locales cannot split a cell into an unguarded formula | Unit tests |
| Accidental clicks from reports | URLs and host names defanged in Markdown reports (including prose, where `http://` and `ftp://` schemes are also broken), history, activity, the indicator table and its CSV export; JSON and STIX exports are raw by design (machine formats) | Unit tests |
| Report or evidence spoofing through encoded text | Hosts outside IDNA2008 (emoji, symbols, hidden formatting such as U+202E) are shown in their `xn--` form, never decoded; host and link text is bidi-isolated in the UI; decoded path and query text has control and bidi characters replaced; Markdown output is single-line per field and escaped; credentials in embedded URLs are masked | Unit tests |
| Brand-hosted user content mistaken for the brand | SharePoint, Google Sites/Docs, Dropbox, cloud storage and similar are classed as shared hosting, so the brand context never suppresses the model or brand checks there | Unit tests |
| Resource exhaustion | 2,048-character URL limit enforced in code; 500 links per batch in the UI with a matching text limit; capped edit distance; credential masking is linear time | Unit tests (200,000-character line) |
| Tampered model or rule data | Generated from pinned, SHA-256-verified sources; shipped as code-free data modules; the model id is the SHA-256 of every field that decides a score, and the browser, CLI and Python tools refuse an artifact that does not match it; JS/Python parity test | `engine.test.js` (golden vectors, identity, tampering), `test_engine.py` |
| DOM injection sinks | CSP `require-trusted-types-for 'script'` with `trusted-types 'none'`: the browser rejects string assignments to script sinks, and no script can create a policy to get around it | e2e under the production CSP |
| Clickjacking, MIME sniffing, referrer leaks | `frame-ancestors 'none'`, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy` | `check-headers` against the deployed host |
| Host rewrites HTML | `check-headers` fails on `/cdn-cgi/`, Web Analytics beacon or Rocket Loader markup, and compares every header on the 404 page too | `check-headers.test.js` |
| Text sent to spellcheck services | Fields that hold links, hosts, notes or indicators set `spellcheck="false"` (browser cloud spellcheck, when a user enables it, would otherwise send their text off the device) | Code review |

Not in scope: an attacker with access to the browser profile can read the
workspace; exported backups are plain JSON and must be stored carefully.

## Dependencies

- **Runtime:** `preact` 10.29.8 and the `@fontsource` IBM Plex packages
  (fonts only), pinned exactly.
- **Development:** `vite` 6.4.5, `@playwright/test` 1.64.1, pinned exactly by
  `package-lock.json`. `npm audit`: 0 vulnerabilities (2026-11-12). CI fails
  on moderate or higher.
- **Bundled data:** Public Suffix List (MPL-2.0, licence in
  `src/engine/generated/PSL-LICENSE.txt`) and the model artifact
  (`src/engine/models/`, trained on CC BY 4.0 datasets; see `/research/`).

## Reporting a problem

Email founder@securemindlabs.com (also published at
`/.well-known/security.txt`). Please do not include live credentials or
private URLs.
