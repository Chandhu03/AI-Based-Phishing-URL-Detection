# Deploying the website (Cloudflare Pages)

Status: **prepared, not performed.** Every step below is an owner action. Do
nothing here until the reconciled repository is on GitHub.

## 1. Pages project settings

| Setting | Value |
|---|---|
| Source | GitHub repository `Chandhu03/AI-Based-Phishing-URL-Detection` |
| Production branch | `main` |
| Root directory | `website` |
| Framework preset | None |
| Build command | `npm ci && npm test && npm run build` |
| Build output directory | `dist` |
| Node.js version | 22, from `website/.node-version`. The Pages v3 image defaults to 22.16.0 |
| Environment variables | None. The site has no secrets |
| Functions | None. `_headers` does not apply to Pages Functions, and the site has none |

- **Why the build runs the tests:** the build fails if any of the 103 unit
  tests fail, so a broken dissector is never published.
- **What gets published:** `public/_headers` is copied to `dist/_headers`,
  where Pages applies it to every response, including `*.pages.dev` previews.

## 2. Preview checklist (on `https://<branch>.<project>.pages.dev`)

Run these from `website/` on your machine:

1. **Headers:** `npm run check:headers -- https://<preview-host>`.
   - It reads `public/_headers` and requests `/`, `/research/` and a hashed
     asset.
   - It must print `PASS`.
   - It fails if any header is missing or differs.
2. **Pages return 200:** `/`, `/research/`, `/research` (should redirect to
   `/research/`), `/robots.txt`, `/sitemap.xml`, `/og.png`, `/favicon.svg`.
3. **In a browser,** with the developer tools Console and Network tabs open:
   - **No errors:** no console errors, and no CSP violation reports.
   - **Normal input:** dissect `http://paypal.com.secure-account.tk/login`.
     - The result shows registrable domain `secure-account.tk`.
     - The Network tab shows only `psl-rules-*.js`, and no request contains
       the URL.
   - **Rejected input:** `javascript:alert(1)` shows "Only http and https…".
   - **Keyboard:** Tab from the top. The skip link appears first, and every
     control shows a focus ring.
4. **On a phone, or at 375 px width:** the menu opens and closes, Escape
   closes it, and nothing scrolls sideways.
5. **External links:** each link marked ↗ opens the right site in a new tab.
   The demo link goes to `https://securemind-ai.streamlit.app/`.
6. **Social preview:** paste the preview URL into a link-preview checker.
   The `og:image` points at `securemindlabs.com`, so it renders only after
   step 3.

## 3. Production domain (only after the preview passes)

`securemindlabs.com` uses Cloudflare DNS (the registrar is Cloudflare).
Microsoft 365 mail for `chandhu@` and `founder@` depends on records in the
same zone.

1. **Back up the zone first:** DNS → Records → Export. Save the file; it is
   your rollback reference.
2. **Note the mail records,** which must remain byte-for-byte unchanged:
   - `MX`
   - the SPF `TXT` (`v=spf1 …`)
   - `selector1._domainkey` and `selector2._domainkey` (`CNAME`)
   - `_dmarc` (`TXT`), if present
   - `autodiscover` (`CNAME`)
   - any `MS=` verification `TXT`
3. **Connect the domain:** Pages → project → Custom domains → add
   `securemindlabs.com`.
   - Pages proposes a single apex `CNAME` to `<project>.pages.dev`,
     proxied and flattened.
   - Review that it adds exactly that one record and changes nothing else
     before confirming.
   - If an apex `A` or `AAAA` record already exists, stop and review it.
     Do not delete records you have not identified.
4. **Optional `www`:** add `www.securemindlabs.com` as a second custom
   domain. Then redirect it to the apex with a single redirect rule, because
   `_redirects` cannot match on hostnames.
5. **Turn off features that alter HTML** on the zone, or verify they do not
   break the page. They apply only on the proxied custom domain, not on
   `pages.dev`:
   - Rocket Loader
   - Automatic HTTPS Rewrites (harmless here)
   - Email Address Obfuscation (rewrites the `mailto:` link)
   - Web Analytics auto-injection or Zaraz. These would add third-party
     scripts that the CSP blocks, and they contradict the site's "no
     analytics" statement.
6. **After DNS settles:**
   - Run `npm run check:headers -- https://securemindlabs.com`.
   - Send mail to and from `founder@securemindlabs.com`, and confirm the
     message headers show `spf=pass` and `dkim=pass`.
   - Re-export the zone and diff it against the backup. The only change
     should be the Pages record or records.

**HSTS** is `max-age=31536000` without `includeSubDomains` or `preload`. It
covers only the hosts that serve this site; mail hosts are unaffected. Do not
add `preload` without a separate decision.

## 4. Rollback

- **A bad site build:** Pages → Deployments → choose the last good
  deployment → Rollback.
- **A domain problem:** Pages → Custom domains → remove the domain. This
  removes only the record Pages added. Restore anything else from the zone
  export.
- **Mail problems after any change:** compare the zone against the export
  and restore the mail records exactly.
