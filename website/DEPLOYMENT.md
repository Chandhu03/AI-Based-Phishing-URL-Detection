# Deploying the platform (Cloudflare Pages)

Status (verified 2026-11-17 from outside): `securemindlabs.com` is served by
Cloudflare Pages from `main` (merge `293fa35`, PR #3); `www` and `http://`
redirect to `https://securemindlabs.com/`. Email Address Obfuscation and Web
Analytics are off for the zone and `npm run check:headers` passes. Every step
below is an owner action.

## 1. Pages project settings

| Setting | Value |
|---|---|
| Source | GitHub repository `Chandhu03/AI-Based-Phishing-URL-Detection` |
| Production branch | `main` |
| Preview branches | Custom branches, include `launch/*` (previews are public by default) |
| Root directory | `website` |
| Framework preset | None |
| Build command | `npm ci --ignore-scripts && npm test && npm run build` |
| Build output directory | `dist` |
| Node.js version | 22: `NODE_VERSION=22` (Production and Preview) plus `website/.node-version` |
| Other environment variables | None. The platform has no secrets |
| Functions | None. `_headers` does not apply to Pages Functions, and there are none |

- **The build reads `../phase3/reports/`.** Research figures on `/` and
  `/research/` are generated from those committed JSON files; a missing value
  fails the build. Pages clones the whole repository, so this works with the
  root directory set to `website`.
- **Why the build runs the tests:** a failing engine, workspace or tooling
  test stops the deployment.
- **What gets published:** five HTML entry points (`/`, `/research/`,
  `/trust/`, `/app/`, `404.html`), hashed assets, `_headers`,
  `/.well-known/security.txt`, `robots.txt`, `sitemap.xml`, `og.png`, `favicon.svg`.
- **Headers Pages adds itself:** `Access-Control-Allow-Origin: *` on static
  files (harmless: public data, no cookies) and `x-robots-tag: noindex` on
  previews.

## 2. Cloudflare zone settings that must stay off

These features rewrite HTML on the proxied custom domain. The 2026-11
reconnaissance found the first two **on** in production; they inject code
that is not in the repository, contradict the site's "no analytics"
statement, and log a CSP error on every page.

| Feature (dashboard location) | Required state |
|---|---|
| Web Analytics automatic setup (Analytics & Logs → Web Analytics, or the Pages project's Web Analytics toggle) | Off |
| Scrape Shield → Email Address Obfuscation | Off |
| Speed → Rocket Loader | Off |
| Zaraz | Off / no tools |

`npm run check:headers -- https://securemindlabs.com` fails while any of
these inject markup. The browser check in §3 is the definitive test,
because some injections only happen for real browsers.

## 3. Preview checklist (on `https://<branch>.<project>.pages.dev`)

From `website/`:

1. `npm run check:headers -- https://<preview-host>` prints `PASS`. It checks
   every header in `public/_headers` on `/`, `/research/`, `/trust/`, `/app/`
   and a hashed asset, a real 404 for an unknown path (carrying the same
   headers, compared exactly), and the absence of host-injected scripts.
2. In a browser with DevTools open:
   - **No console errors** on `/`, `/research/`, `/trust/`, `/app/`.
   - **Engine page** (`/app/#/engine`) shows the model id `url-host-ea3f55ce1c18faa2`
     and the integrity line; the sidebar says "Engine and model loaded".
   - **Homepage:** analyse `http://paypal.com.secure-account.tk/login`; the
     verdict is High risk and the Network tab shows only same-origin files.
   - **Workspace:** analyse a link, save it, add it to an investigation, add
     a note, record indicators, reload: everything is still there. Settings
     → Delete all workspace data empties it.
   - **Alert queue:** add two reported links (one twice), start triage, close
     one with a disposition, escalate the other: the investigation holds its
     analysis and the overview shows no open alerts.
   - **Keyboard:** Tab from the top: the skip link comes first and every
     control shows a focus ring.
3. At 375 px wide: no sideways scrolling; the menus open and close.

The same journeys run automatically in `npm run test:e2e`.

## 4. DNS and mail (owner actions, separate from the site)

`securemindlabs.com` uses Cloudflare DNS with Microsoft 365 mail. Export the
zone before any change and keep mail records byte-for-byte unchanged unless
the change below is the intent.

Recommended, from the 2026-11 reconnaissance:

- **DKIM:** enable it in Microsoft 365 and publish the `selector1` and
  `selector2` CNAMEs it shows (none resolved at the time of checking).
- **DMARC:** publish `_dmarc` TXT, starting with
  `v=DMARC1; p=none; rua=mailto:<reporting address>`, then move to
  `quarantine`/`reject` once reports are clean.
- **CAA:** restrict issuance to the certificate authorities Cloudflare uses.
- **DNSSEC:** enable it in Cloudflare (a DS record at the registrar follows
  automatically when Cloudflare is the registrar).
- **HSTS on `www`:** the `www` redirect currently has no HSTS header; enable
  HSTS at the zone (without `includeSubDomains` unless every subdomain,
  including `autodiscover`, is HTTPS-only).

## 5. Release steps

1. Merge the reviewed branch into `main` through a pull request; CI must be
   green (Python tests and audits, Phase 3 tests, website unit tests, build,
   end-to-end tests, npm audit).
2. Pages builds `main`. Run the §3 checklist on the production URL.
3. Existing visitors' workspaces live in each browser. A release that
   raises the workspace schema (`DB_VERSION` in `src/workspace/stores.js`)
   upgrades them in place on the next visit; a tab of the previous build that
   is still open delays the upgrade, and the new tab says so until it closes.

## 6. Rollback

- **A bad build:** Pages → Deployments → the last good deployment → Rollback.
- **Across a schema change:** a build with a lower `DB_VERSION` cannot open a
  workspace that a newer build has upgraded (version 2 added the alert queue).
  The rolled-back app then shows "Temporary workspace" and keeps nothing; the
  data stays in the browser, untouched, and is readable again once a build
  with the newer schema is deployed. Prefer rolling forward with a fix.
- **A domain problem:** Pages → Custom domains → remove the domain (this
  removes only the record Pages added); restore anything else from the zone export.
- **Mail problems:** compare the zone with the export and restore the mail
  records exactly.
