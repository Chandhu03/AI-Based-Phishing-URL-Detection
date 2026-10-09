# SecureMind Labs website

Static two-page site for SecureMind Labs: a homepage with an in-browser
**URL dissector**, and `/research/`, which reports the Phase 3 evaluation.
It uses Vite and vanilla JavaScript, with no runtime dependencies and no
backend.

## What it does, and what it does not

| Capability | Where it runs | Status |
|---|---|---|
| URL dissector: scheme, registrable domain via the Public Suffix List, subdomains, disguised IPs, hidden credentials, look-alike (IDN) characters, embedded redirect URLs | This site, in the visitor's browser | Live |
| Machine-learning phishing prediction | The separate Streamlit demo at https://securemind-ai.streamlit.app/ | Research demo, running the original prototype model |
| Phase 3 candidate models | Not deployed | Experimental |

The dissector reports **facts about the URL string**. It never fetches,
resolves or opens the URL, never produces a verdict, score or probability,
and never sends the input anywhere. Its acceptance policy mirrors the app's
Python validator (`securemind/url_validation.py` in the research checkout):
- http and https only, with no silent https assumption
- control and bidi characters, whitespace and backslashes rejected
- a 2,048-character limit
- error messages that never echo the input

### Architecture decision: why the site does not call a model

Options considered:
1. **Keep the dissector local and link to the Streamlit demo** (chosen).
2. Add an inference API for the existing model.
3. Port a Phase 3 model to the browser.

Options 2 and 3 were rejected for now, for these reasons:
- **The live model is a weak public endpoint.** It was trained on synthetic
  URLs, and at its default threshold it catches 10.6% of phishing on held-out
  PhiUSIIL domains (see `/research/`).
- **The Phase 3 candidate is not approved for production.** Its
  cross-dataset results are weak (ROC-AUC 0.741).
- **An API would need serious infrastructure.** That means hosting, rate
  limiting, logging policy and a threat model.

A future API must analyse the submitted *string only* and must never fetch
it.

## Develop, test, build

Requires Node.js 22 or newer. From `website/`:

```powershell
npm ci                 # exact versions from package-lock.json
npm test               # 103 unit tests: dissector policy, PSL vectors, Punycode, header checker
npm run dev            # http://localhost:5173
npm run build          # -> dist/ (two HTML pages, hashed assets)
npm run preview        # serves dist/ at http://localhost:4173
```

| Path | Purpose |
|---|---|
| `index.html`, `research/index.html` | The two pages. All content is static HTML, so the site is readable without JavaScript |
| `src/url-anatomy.js` | Dissection logic (pure, unit-tested) |
| `src/psl.js`, `src/generated/psl-rules.js` | Public Suffix List lookup. Rules are loaded lazily, as a same-origin module, on the first dissection |
| `src/punycode.js` | RFC 3492 decoder, used for display only |
| `src/render.js`, `src/main.js` | DOM rendering (`textContent` only) and page wiring |
| `public/_headers` | Security headers for Cloudflare Pages |
| `public/og.png`, `favicon.svg`, `robots.txt`, `sitemap.xml` | Social card, icon and crawler files |
| `scripts/build-psl.mjs` | Regenerates the PSL module from a pinned commit, verified by SHA-256 (`npm run psl:update`) |
| `scripts/check-headers.mjs` | Checks a deployed host serves exactly the headers in `public/_headers` (`npm run check:headers -- <url>`) |
| `DEPLOYMENT.md` | Cloudflare Pages settings, preview checklist, DNS/mail protection, rollback |

### Research numbers

Every metric on `/research/` comes from the Phase 3 outputs
(`phase3/reports/metrics.json` and `data_stats.json` in the research
checkout). Those files are **not yet in the public repository**. Publishing
them is a launch prerequisite, so that every number can be checked.

If the evaluation is re-run, update the pages from those files. Do not
retype numbers from memory.

## Deployment (prepared, not performed)

Cloudflare Pages: root directory `website`, build command
`npm ci && npm test && npm run build`, output `dist`, Node 22 (from
`.node-version`). The full preview checklist, the production-domain steps
that protect the Microsoft 365 mail records, and the rollback steps are in
[`DEPLOYMENT.md`](DEPLOYMENT.md). After a preview deploys, check the live
security headers with:

```powershell
npm run check:headers -- https://<preview-host>
```
