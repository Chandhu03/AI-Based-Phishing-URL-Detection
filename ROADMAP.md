# Roadmap: from phishing-link workspace to SOC platform

SecureMind Labs is growing from a single-analyst phishing-link workspace into
a small security operations (SOC) platform. This file records the order of
work and the decisions that gate it. It is a plan, not a promise. Each step
ships only when its tests, the CI gate and the security controls in
`website/SECURITY.md` hold.

## Principles that do not change

- **A link under investigation is never fetched, resolved or opened** by the
  platform. Analysis reads the string only.
- **Nothing leaves the browser without an explicit, visible choice.** Today
  the policy enforces this (`connect-src 'none'`). Any future network feature
  is opt-in, named in the UI and documented on `/trust/`.
- **Every verdict cites its evidence**, and the platform never calls a link
  "safe".
- **Changes are all or nothing**, imports are untrusted input, and exports
  defang every URL.

## Done

| Step | What shipped |
|---|---|
| Analysis engine | Parser, Public Suffix List, more than 20 indicators, hostname model, qualified verdicts |
| Case work | Investigations with history and reports; indicators with STIX 2.1 and CSV |
| Workspace safety | Atomic changes, damaged-record repair, verified backups and restores |
| **Alert queue (phase 1)** | Intake by paste or file, repeat folding, severity from verdict, triage → disposition or escalation, bulk actions, queue-health metrics (median time to triage and to close, false-positive rate) |

## Next, inside the local-first design (no backend needed)

1. **Reported-email intake.** Drop a `.eml` file reported by a user. The
   platform would parse its headers (From, Reply-To and Return-Path
   mismatches, the SPF, DKIM and DMARC results in `Authentication-Results`,
   the `Received` chain). It would extract every link from the text and HTML
   parts without rendering the HTML or loading remote content, then queue one
   alert per email, with its links analysed.
   - Risk: parsing hostile MIME.
   - Mitigation: size caps, no HTML rendering, and parser fuzz tests.
2. **Playbooks.** Each investigation type would get a checklist, for example
   *credential phish*: block the domain, reset exposed accounts, notify the
   reporters. The investigation history would record each completed step.
3. **Queue rules.** Local rules that act on intake, for example "registrable
   domain is on the allow-list → close as benign" or "brand plus a free TLD →
   critical". Every automatic action is recorded in the alert's history.
4. **Reporting.** A weekly queue report (volumes, dispositions, time to
   triage and close, top lure domains), exported as Markdown and CSV with
   values defanged.

## Gated on an owner decision: a backend

Teams need shared queues, assignment, accounts, a feed that pushes alerts in
(from a mail gateway or a SIEM webhook) and reputation enrichment. Each needs
a server, and a server changes the trust promise on `/trust/` ("nothing is
sent").

**Decision required before any work starts:**
- hosting and cost;
- the authentication model (SSO);
- where alerts and reporter data live, and the retention policy;
- a threat model for an internet-facing ingest API;
- whether enrichment may send *indicators* (never the analysed URL's
  content) to third parties.

Until that decision is made, the platform stays local-first.

**If approved,** the intended shape is:
- **One engine.** The server runs the same `src/engine` and must never fetch
  the links it analyses.
- **Ingest API.** Authenticated, rate-limited, size-capped and idempotent by
  external id.
- **Shared alert queue.** Assignment and per-analyst metrics.
- **Opt-in enrichment.** Behind a per-workspace switch, listed on `/trust/`.
