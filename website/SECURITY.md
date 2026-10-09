# Website security and privacy notes

## Data flow

- **The dissector runs entirely in the browser.** The input is parsed with
  the browser's `URL` parser and a bundled Public Suffix List.
- **No network request contains it.** The input never appears in any
  request, the address bar, a cookie or browser storage.
- **One same-origin request.** On the first dissection only, the browser
  loads the hashed same-origin file `/assets/psl-rules-*.js`, which contains
  no user data.
- **No analytics, cookies, trackers, third-party scripts, fonts or images.**
- **No-JavaScript fallback.** The URL field has no `name` attribute, so
  submitting the form without JavaScript sends nothing (verified in a
  browser).
- **External links** go to the Streamlit demo, GitHub and DOI pages. They
  open only when the user clicks, and use `rel="noopener noreferrer"`. The
  Streamlit demo is a separate application with its own hosting; this site
  does not control it.
- **Hosting logs.** The hosting provider may keep standard access logs of
  page requests. Those requests never contain the dissected URL.

## Threat model (what the code defends against)

| Threat | Control | Verified by |
|---|---|---|
| XSS via a crafted URL | All output via `textContent` or `createElement`; no `innerHTML` or `eval`; CSP `script-src 'self'` with no inline scripts | Unit tests; browser journeys with markup payloads; production CSP enforced in the journeys with no violations |
| Misleading normalisation (silent https; disguised IPs; fullwidth or IDN hosts; `user@host` tricks; backslash ambiguity) | Explicit policy plus observations that reveal what the browser would actually do | `src/url-anatomy.test.js` |
| Credential exposure | Embedded login text is never displayed or returned; the output URL has credentials removed | A unit test checks that no output contains the password |
| Resource abuse via huge input | 2,048-character limit, enforced in code, not only by `maxlength` | Unit test and browser test |
| Fake capability or verdict | No score, verdict or probability fields; wording tests | Unit test |
| Clickjacking, MIME sniffing, referrer leaks | `_headers`: `frame-ancestors 'none'`, `X-Frame-Options`, `nosniff`, `Referrer-Policy` | Static review. Must be confirmed on the deployed host (see README) |

`_headers` applies only on the production host (Cloudflare Pages). Neither
`vite dev` nor `vite preview` sends these headers.

## Dependencies

- **Runtime:** none.
- **Development:** `vite` only, pinned by `package-lock.json`. `npm audit`
  reports 0 vulnerabilities, verified 2026-10-09.
- **Bundled data:** the Public Suffix List (MPL-2.0; licence in
  `src/generated/PSL-LICENSE.txt`) is pinned to a commit and its SHA-256 is
  verified when regenerated.

## Reporting a problem

Email founder@securemindlabs.com. Please do not include live credentials or
private URLs.
