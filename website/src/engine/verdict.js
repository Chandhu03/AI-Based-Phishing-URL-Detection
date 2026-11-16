// Combine indicators and the model estimate into a qualified verdict.
//
// The verdict never says "safe": the absence of indicators in a link's text
// says nothing about the page behind it. The policy is deliberately simple
// and fully explained, so an analyst can always see why a level was chosen.

export const VERDICTS = Object.freeze({
  "high-risk": { label: "High risk", rank: 3 },
  suspicious: { label: "Suspicious", rank: 2 },
  inconclusive: { label: "Inconclusive", rank: 1 },
  "no-strong-indicators": { label: "No strong indicators observed", rank: 0 },
});

export const LIMITS = Object.freeze([
  "Only the text of the link was analysed. The destination was not visited, resolved or looked up.",
  "A link with no indicators can still lead to a malicious page; attackers also use clean-looking domains and compromised sites.",
  "The model estimate reflects similarity to phishing hosts in public research datasets, not a measurement of this specific site.",
]);

/** Model band from calibrated probability and the artifact's thresholds. */
export function modelBand(model) {
  if (!model) return "unavailable";
  if (model.probability >= model.thresholds.high) return "high";
  if (model.probability >= model.thresholds.elevated) return "elevated";
  return "low";
}

/**
 * @param {Array<{severity:string,id:string,title:string}>} indicators
 * @param {{probability:number, thresholds:{high:number, elevated:number}}|null} model
 */
export function decideVerdict(indicators, model, { skipped = null } = {}) {
  const by = (s) => indicators.filter((i) => i.severity === s);
  const high = by("high");
  const medium = by("medium");
  const low = by("low");
  // On a domain in the brand reference list, the host-only model has nothing
  // to add (its n-grams resemble phishing that imitates that very brand).
  const listed = indicators.some((i) => i.id === "official-domain");
  const band = listed && model ? "low" : modelBand(model);
  const hidesDestination = indicators.some((i) => i.id === "shortener");
  const reasons = [];
  let level;

  if (high.length) {
    level = "high-risk";
    reasons.push(...high.map((i) => i.title));
  } else if (band === "high" && medium.length) {
    level = "high-risk";
    reasons.push("The model places this host in its high band", ...medium.map((i) => i.title));
  } else if (medium.length >= 2 && band !== "low") {
    level = "high-risk";
    reasons.push(...medium.map((i) => i.title), `The model estimate is ${band}`);
  } else if (medium.length || band === "high") {
    level = "suspicious";
    if (band === "high") reasons.push("The model places this host in its high band");
    reasons.push(...medium.map((i) => i.title));
  } else if (band === "elevated" || low.length >= 2 || hidesDestination) {
    level = "inconclusive";
    if (band === "elevated") reasons.push("The model estimate is elevated");
    if (hidesDestination) reasons.push("The final destination is hidden by a link shortener");
    if (low.length >= 2) reasons.push(`${low.length} weak indicators together`);
  } else {
    level = "no-strong-indicators";
    reasons.push(low.length ? "Only one weak indicator was found" : "No indicators were found in the link text");
    if (band === "unavailable") {
      reasons.push(skipped === "ip-address" ? "The hostname model does not score IP addresses"
        : skipped === "nonstandard-idn" ? "The model does not score names outside the domain name standard"
          : "The model was not available for this analysis");
    }
  }
  if (listed) reasons.push("The domain is in the brand reference list, so the model estimate was not used");

  return { level, label: VERDICTS[level].label, band: listed && model ? "not-used" : band, reasons, limits: LIMITS };
}
