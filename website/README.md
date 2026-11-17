# SecureMind Labs platform (website/)

A local-first phishing-link investigation platform, served as static files
from Cloudflare Pages. There is no application server: analysis, storage
and reporting all run in the visitor's browser.

| Path | What it is |
|---|---|
| `/` | Public homepage with a live, local analysis of one link |
| `/research/` | How the detection model was trained and evaluated (figures generated at build time) |
| `/trust/` | Privacy and security: data flow, enforced controls, threat model, disclosure |
| `/app/` | The analyst workspace: Overview, Alert queue, Analyse (one or many links), Analyses, Investigations, Indicators, Detection engine, Settings |

## Capabilities

- **Analysis.** Strict parsing with the browser's URL parser; the registrable
  domain from a pinned Public Suffix List; over twenty explainable indicators
  (hidden credentials, disguised IPs, look-alike and mixed-script hosts, brand
  misuse and typosquats, embedded redirects, shorteners, shared hosting,
  downloadable files and more); a hostname model; a qualified verdict:
  *High risk*, *Suspicious*, *Inconclusive* or *No strong indicators observed*.
  Never "safe".
- **Alert queue.** Reported links arrive by paste or file (text, CSV with a
  `url` column and optional `source`, `external_id`, `reporter`, or JSON; up
  to 500 per import, all or nothing). Each is analysed locally and queued with
  a severity from its verdict; a link already open in the queue counts as a
  repeat instead of a new alert. Alerts move new → in triage → closed (true
  positive, benign, false positive or duplicate) or escalated to a new or
  existing investigation, which receives the analysis. Bulk triage and close,
  a full history per alert, and queue health for the last 30 days: backlog,
  oldest open alert, median time to triage and to close, false-positive rate.
- **Analyses.** Every saved analysis with search (link or host), a verdict
  filter, pages of 25 and bulk deletion that also removes links to it.
- **Investigations.** Status, priority, tags, notes, linked analyses and
  indicators, a full history, and a Markdown case report (each analysis with
  its evidence, an indicator table, notes, history, and the engine, model and
  Public Suffix List versions used; URLs defanged).
- **Indicators.** URL, domain, hostname, IPv4 and IPv6 with confidence,
  sources, sightings and relationships by domain; import and export as text,
  CSV (formula-safe) or STIX 2.1 (host names and domains, STIX ids and notes
  survive a round trip).
- **Workspace data.** IndexedDB in this browser only; JSON backup and
  all-or-nothing restore; damaged-record detection and repair; one-step deletion. An optional demo workspace is flagged as demo
  data everywhere and removable.

## Architecture

```
src/
  engine/       Pure, DOM-free analysis service (also used by the CLI and tests)
    url-anatomy.js   input policy + parsing facts      psl.js, punycode.js
    indicators.js    rule-based evidence               brands.js, confusables.js
    model.js         hashed char n-gram logistic regression runtime (+ murmurhash3.js)
    verdict.js       qualified verdict policy           analyze.js  entry point
    models/          generated model artifact + Python golden vectors
    generated/       generated Public Suffix List rules
  workspace/    Domain logic over a storage adapter (IndexedDB or memory), import/export
  app/          Preact workspace UI (hash routes; record ids only, never URLs)
  site/         Public-site script and styles
  ui/           Design tokens, base styles, theme preference
scripts/        Build/test tooling (PSL generator, header checker, metrics plugin, static server, CLI)
e2e/            Playwright tests against the production build and headers
```

Design decisions that matter for maintenance:

1. **No server, by design.** Analysing in the browser means a submitted link
   never leaves the device, which the CSP (`connect-src 'none'`) enforces.
   It also removes hosting cost and an API attack surface. The trade-off:
   no shared workspace and no enrichment. A future server module (for
   example a team workspace or opt-in enrichment) must keep the engine as the
   single source of analysis logic and get its own threat model.
2. **One engine, three consumers.** The workspace, the homepage and
   `npm run analyze` all call `analyzeUrl()`; rules are never duplicated in UI
   code.
3. **Model as data.** The model is trained in Python (`phase3/`, `run.py engine`)
   and exported as a code-free module; `engine.test.js` checks the JavaScript
   scores against Python golden vectors to 1e-9. Retraining means re-running
   the export, never editing numbers. The model sees hosts as
   `securemind/url_validation.py` normalises them, so `url-anatomy.js` and
   that validator are both tested against `../tests/fixtures/url_cases.json`
   (same host, same error code); the few intentional differences are listed
   there with the reason.
4. **Published numbers are generated.** `scripts/research-metrics.mjs` fills
   `{{m:source:/json/pointer|format}}` tokens from `../phase3/reports/` at build
   time and fails the build if a value is missing.
5. **All-or-nothing changes.** Workspace changes are staged in a unit of work
   (`workspace.js`: `begin`/`atomic`) and committed with `store.commit(ops)`,
   one IndexedDB transaction across every store touched. Restores and imports
   use the same commit. Changes are queued so they never interleave.
6. **Damaged data is contained.** `isIntact(store, record)` checks every
   record on read; lists and counts skip failures, Settings lists and removes
   them, and a restore can replace them.
7. **Content-addressed model.** The model id is `url-host-` plus the first 16
   hex digits of the SHA-256 of its scoring fields (`canonical()` in both
   `model.js` and `phase3/src/phishlab/engine.py`); the loader rejects an
   artifact whose content does not match.
8. **Preact for the workspace only.** The public pages stay static HTML with a
   small script; the stateful workspace uses Preact (about 10 kB) rather than
   hand-built DOM code.

## Develop, test, build

Requires Node.js 22 or newer. From `website/`:

```powershell
npm ci --ignore-scripts   # exact versions from package-lock.json; no install scripts
npm test                  # unit tests: engine, workspace, import/export, tooling
npm run dev               # http://localhost:5173 (workspace at /app/)
npm run build             # -> dist/ (needs ../phase3/reports for research figures)
npm run test:e2e          # Playwright against dist/ with production headers (uses installed Chrome)
npm run analyze -- urls.txt > results.jsonl   # batch analysis from the command line, offline
```

`npm run test:e2e` serves `dist/` through `scripts/serve-dist.mjs`, which
applies `public/_headers` exactly as Cloudflare Pages does. Set
`PW_CHANNEL=""` to use Playwright's bundled Chromium instead of Chrome.

## Updating data

- **Public Suffix List:** `npm run psl:update` (pinned commit, SHA-256 verified).
- **Model:** from the repository root, `phase3/run.py engine` (see
  `phase3/README.md`). It rewrites `src/engine/models/*` and
  `phase3/reports/engine/*` (including the per-site metrics in
  `site_metrics.json`); commit them together. A unit test fails if the
  published per-site metrics belong to a different model.
- **Brand reference list:** `src/engine/brands.js`. Every listed domain must
  be a registrable domain (a unit test enforces it).

Deployment, preview checks and the Cloudflare zone settings are in
[`DEPLOYMENT.md`](DEPLOYMENT.md); security notes are in [`SECURITY.md`](SECURITY.md).

## Known limitations

- **Local only.** One browser profile holds the workspace; there is no
  sharing, sync or server-side backup. Exported backups are plain JSON.
- **Restore size.** One restore accepts up to 10,000 analyses (each is
  re-analysed and stored with its full report). Lists read the whole store;
  measured with 3,001 analyses, Overview and Analyses render in about
  0.1–0.2 s on a desktop machine. Much larger workspaces would need indexes.
- **Brand list coverage.** `brands.js` covers about 40 brands and their main
  country domains. A brand or country domain that is missing gets a
  low-severity "brand on a domain it is not known to use" note, and the model
  estimate is used as usual.
- **Model false positives.** The hostname model scores some legitimate,
  unlisted hosts high (examples: `ipfs.io`, random `*.example` names). Treat
  "Suspicious" from the model alone as a prompt to look, not a finding.
- **IDN edge cases.** The IDNA2008 check approximates the standard's tables
  with Unicode properties; on 8,660 fuzzed hosts it disagrees with Python's
  `idna` on 4 (characters that browsers map to `_`).
- **STIX.** Import reads simple `[type:value = '...']` patterns only;
  compound patterns are skipped and counted as rejected.
