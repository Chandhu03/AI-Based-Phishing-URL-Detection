// Optional demonstration workspace. Every record it creates is flagged
// `demo: true`, shown with a "Demo" marker, and removable in one action.
// The analyses are produced by the real engine from the example links below;
// nothing here is a recorded incident or real-world statistic.

const DEMO_URLS = Object.freeze([
  "http://paypal.com.secure-account.tk/login",
  "https://xn--pple-43d.com/id/verify",
  "http://3232235777/bank/login",
  "https://example.org/r?url=https://login.example-payroll.top/",
  "https://bit.ly/3demo-link",
  "https://victim-login.github.io/microsoft/",
  "https://www.example.com/docs/getting-started",
  "https://paypa1.com/signin",
]);

export async function loadDemoWorkspace(ws, analyze) {
  // Every example link arrives as a user report in the alert queue, which
  // also saves its analysis.
  const reports = DEMO_URLS.map((url) => analyze(url)).filter((r) => r.ok);
  const { created: alerts } = await ws.queueAlerts(reports.map((report, i) => ({ report, source: "user-report", reporter: `demo-user-${i + 1}@example.com` })), { demo: true });
  const saved = await Promise.all(alerts.map((a) => ws.getAnalysis(a.analysisId)));
  const inv = await ws.createInvestigation({
    title: "Demo: payroll credential lure",
    summary: "Demonstration case built from example links. Shows linking analyses, recording indicators and keeping notes.",
    priority: "high",
    tags: ["demo", "credential-phishing"],
    demo: true,
  });
  for (const a of saved.filter((a) => a.verdict === "high-risk").slice(0, 3)) {
    await ws.linkAnalysis(inv.id, a.id);
    await ws.upsertIndicator({ type: "domain", value: a.registrableDomain ?? a.host, confidence: "high", source: "demo", analysisId: a.id, investigationId: inv.id, tags: ["demo"], demo: true })
      .catch(() => ws.upsertIndicator({ type: "url", value: a.url, confidence: "high", source: "demo", analysisId: a.id, investigationId: inv.id, tags: ["demo"], demo: true }));
  }
  await ws.addNote(inv.id, "Example note: the brand appears only in the subdomain; the registrable domain is unrelated.");
  await ws.updateInvestigation(inv.id, { status: "investigating" });
  // Queue states to show: one alert escalated to the case, one closed as benign, the rest waiting.
  const lure = alerts.find((a) => a.verdict === "high-risk");
  if (lure) await ws.escalateAlert(lure.id, { investigationId: inv.id });
  const ordinary = alerts.find((a) => a.verdict === "no-strong-indicators");
  if (ordinary) await ws.closeAlerts([ordinary.id], { disposition: "benign", comment: "Vendor documentation link." });
  return { analyses: saved.length, alerts: alerts.length, investigationId: inv.id };
}
