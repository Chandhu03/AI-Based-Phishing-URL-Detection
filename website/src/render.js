// DOM rendering for dissection results. Every user-derived string is set via
// textContent; no HTML is ever parsed from input.

const PART_LABELS = {
  scheme: "Scheme",
  credentials: "Hidden login text",
  subdomain: "Subdomain",
  domain: "Registrable domain",
  suffix: "Public suffix",
  port: "Port",
  path: "Path",
  query: "Query",
  fragment: "Fragment",
};

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function row(dl, term, value, valueClass) {
  const wrap = el("div");
  wrap.append(el("dt", "", term), el("dd", valueClass || "", value));
  dl.append(wrap);
}

export function renderFacts(container, facts) {
  container.replaceChildren();

  const head = el("div", "result-head");
  head.append(el("h3", "result-title", "How a browser reads this link"));
  const notable = facts.observations.filter((o) => o.level === "notable").length;
  head.append(el("p", "result-count", notable
    ? `${notable} notable ${notable === 1 ? "observation" : "observations"}`
    : "No notable observations"));
  container.append(head);

  // Anatomy strip
  const anatomy = el("p", "anatomy anatomy-result");
  anatomy.setAttribute("aria-label", "The link, split into its parts");
  for (const seg of facts.segments) {
    const span = el("span", `seg seg-${seg.part}`, seg.text);
    span.title = PART_LABELS[seg.part];
    anatomy.append(span);
  }
  container.append(anatomy);

  // Key facts
  const dl = el("dl", "facts");
  if (facts.isIp) {
    row(dl, "Destination", `${facts.host} (IP address)`, "fact-strong");
  } else if (facts.registrableDomain) {
    row(dl, "Registrable domain", facts.registrableDomain, "fact-strong");
    row(dl, "Full host", facts.displayHost === facts.host ? facts.host : `${facts.displayHost} (registered as ${facts.host})`);
  } else {
    row(dl, "Host", facts.host, "fact-strong");
  }
  row(dl, "Scheme", facts.schemeExplicit ? facts.scheme : "not given (analysed as http)");
  if (facts.port) row(dl, "Port", facts.port);
  container.append(dl);

  // Observations
  if (facts.observations.length) {
    const list = el("ul", "observations");
    const ordered = [...facts.observations].sort((a, b) => (a.level === "notable" ? 0 : 1) - (b.level === "notable" ? 0 : 1));
    for (const o of ordered) {
      const li = el("li", `obs obs-${o.level}`);
      const badge = el("span", "obs-badge", o.level === "notable" ? "Notable" : "Note");
      const body = el("div", "obs-body");
      body.append(el("p", "obs-title", o.title), el("p", "obs-detail", o.detail));
      li.append(badge, body);
      list.append(li);
    }
    container.append(list);
  }

  const foot = el("p", "result-foot");
  foot.append("This is a reading of the link’s structure, not a safety verdict. An ordinary-looking link can still be malicious. ");
  const link = el("a", "", "How well do our models detect phishing?");
  link.href = "/research/";
  foot.append(link);
  container.append(foot);
  return notable;
}
