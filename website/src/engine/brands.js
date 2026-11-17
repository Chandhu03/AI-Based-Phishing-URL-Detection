// Curated reference list of frequently impersonated brands and the
// registrable domains they operate. Maintained by hand from each brand's own
// public sites; it is a detection aid, not an authority on ownership.
//
// Rules for entries:
// * `tokens` are lowercase ASCII words that, appearing in a host, suggest the
//   brand. Keep them specific (no generic words such as "mail" or "bank").
// * `domains` are registrable domains (eTLD+1) the brand actually uses. A host
//   whose registrable domain is listed is treated as the brand's own.
// Review this list when adding brands; false "official" entries hide abuse.

export const BRANDS = Object.freeze([
  { id: "paypal", name: "PayPal", tokens: ["paypal"], domains: ["paypal.com", "paypal.me", "paypalobjects.com"] },
  { id: "apple", name: "Apple", tokens: ["apple", "icloud", "appleid"], domains: ["apple.com", "icloud.com", "apple.co", "apple.com.cn"] },
  { id: "microsoft", name: "Microsoft", tokens: ["microsoft", "office365", "outlook", "onedrive", "sharepoint", "msonline"], domains: ["microsoft.com", "live.com", "office.com", "outlook.com", "microsoftonline.com", "sharepoint.com", "onedrive.com", "office365.com", "msn.com", "windows.net", "azure.com", "bing.com", "skype.com", "xbox.com"] },
  { id: "google", name: "Google", tokens: ["google", "gmail"], domains: ["google.com", "gmail.com", "youtube.com", "googleusercontent.com", "gstatic.com", "goo.gl", "google.co.uk", "google.ca", "google.de", "google.fr",
    "google.com.au", "google.co.in", "google.co.jp", "google.com.br", "google.es", "google.it", "google.nl", "google.com.mx", "google.pl",
    "google.co.za", "google.com.sg", "google.ie", "google.be", "google.ch", "google.at", "google.se", "google.com.tr", "google.co.nz", "google.com.hk"] },
  { id: "amazon", name: "Amazon", tokens: ["amazon", "aws"], domains: ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.ca", "amazon.fr", "amazon.in", "amazon.co.jp", "amazon.com.au", "amazonaws.com", "amazon.es", "amazon.it", "a2z.com",
    "amazon.com.mx", "amazon.com.br", "amazon.nl", "amazon.se", "amazon.pl", "amazon.com.tr", "amazon.ae", "amazon.sa", "amazon.sg", "amazon.eg"] },
  { id: "netflix", name: "Netflix", tokens: ["netflix"], domains: ["netflix.com", "nflxext.com", "nflximg.net"] },
  { id: "facebook", name: "Facebook", tokens: ["facebook", "fb-login"], domains: ["facebook.com", "fb.com", "fb.me", "meta.com", "fbcdn.net"] },
  { id: "instagram", name: "Instagram", tokens: ["instagram"], domains: ["instagram.com", "cdninstagram.com"] },
  { id: "whatsapp", name: "WhatsApp", tokens: ["whatsapp"], domains: ["whatsapp.com", "whatsapp.net", "wa.me"] },
  { id: "linkedin", name: "LinkedIn", tokens: ["linkedin"], domains: ["linkedin.com", "lnkd.in", "licdn.com"] },
  { id: "x", name: "X (Twitter)", tokens: ["twitter"], domains: ["twitter.com", "x.com", "t.co", "twimg.com"] },
  { id: "dropbox", name: "Dropbox", tokens: ["dropbox"], domains: ["dropbox.com", "dropboxusercontent.com", "db.tt"] },
  { id: "docusign", name: "DocuSign", tokens: ["docusign"], domains: ["docusign.com", "docusign.net"] },
  { id: "adobe", name: "Adobe", tokens: ["adobe"], domains: ["adobe.com", "adobelogin.com", "adobe.io", "acrobat.com"] },
  { id: "dhl", name: "DHL", tokens: ["dhl"], domains: ["dhl.com", "dhl.de", "dhl.co.uk"] },
  { id: "fedex", name: "FedEx", tokens: ["fedex"], domains: ["fedex.com"] },
  { id: "ups", name: "UPS", tokens: ["ups-delivery", "upsdelivery"], domains: ["ups.com"] },
  { id: "usps", name: "USPS", tokens: ["usps"], domains: ["usps.com"] },
  { id: "chase", name: "Chase", tokens: ["chase"], domains: ["chase.com", "jpmorganchase.com"] },
  { id: "wellsfargo", name: "Wells Fargo", tokens: ["wellsfargo"], domains: ["wellsfargo.com", "wf.com"] },
  { id: "bankofamerica", name: "Bank of America", tokens: ["bankofamerica"], domains: ["bankofamerica.com", "bofa.com"] },
  { id: "citi", name: "Citi", tokens: ["citibank"], domains: ["citi.com", "citibank.com"] },
  { id: "hsbc", name: "HSBC", tokens: ["hsbc"], domains: ["hsbc.com", "hsbc.co.uk", "hsbc.ca", "hsbc.com.hk", "hsbc.com.au", "hsbc.com.mx", "hsbc.fr", "hsbc.co.in", "hsbc.com.sg", "hsbc.ae"] },
  { id: "rbc", name: "RBC Royal Bank", tokens: ["rbcroyal", "royalbank"], domains: ["rbc.com", "rbcroyalbank.com"] },
  { id: "td", name: "TD Bank", tokens: ["tdbank", "tdcanada"], domains: ["td.com", "tdbank.com"] },
  { id: "interac", name: "Interac", tokens: ["interac"], domains: ["interac.ca"] },
  { id: "coinbase", name: "Coinbase", tokens: ["coinbase"], domains: ["coinbase.com"] },
  { id: "binance", name: "Binance", tokens: ["binance"], domains: ["binance.com"] },
  { id: "metamask", name: "MetaMask", tokens: ["metamask"], domains: ["metamask.io"] },
  { id: "steam", name: "Steam", tokens: ["steampowered", "steamcommunity"], domains: ["steampowered.com", "steamcommunity.com"] },
  { id: "github", name: "GitHub", tokens: ["github"], domains: ["github.com"] },
  { id: "yahoo", name: "Yahoo", tokens: ["yahoo"], domains: ["yahoo.com", "yahoo.co.jp", "yimg.com"] },
  { id: "ebay", name: "eBay", tokens: ["ebay"], domains: ["ebay.com", "ebay.co.uk", "ebay.de", "ebay.ca", "ebayimg.com",
    "ebay.com.au", "ebay.fr", "ebay.it", "ebay.es", "ebay.at", "ebay.ch", "ebay.ie", "ebay.nl", "ebay.be", "ebay.pl", "ebay.com.hk", "ebay.com.sg"] },
  { id: "irs", name: "IRS", tokens: ["irs-gov", "irsgov"], domains: ["irs.gov"] },
  { id: "craservices", name: "Canada Revenue Agency", tokens: ["canada-revenue", "cra-arc"], domains: ["canada.ca", "cra-arc.gc.ca"] },
  { id: "zoom", name: "Zoom", tokens: ["zoom-us", "zoomus"], domains: ["zoom.us", "zoom.com", "zoomgov.com"] },
  { id: "spotify", name: "Spotify", tokens: ["spotify"], domains: ["spotify.com", "spotifycdn.com"] },
  // Added after the model alone rated their own sites Suspicious; all three
  // are common phishing targets. Shops on myshopify.com are listed as shared
  // hosting below, not as Shopify's own site.
  { id: "shopify", name: "Shopify", tokens: ["shopify"], domains: ["shopify.com"] },
  { id: "proton", name: "Proton", tokens: ["protonmail"], domains: ["proton.me", "protonmail.com", "protonmail.ch", "pm.me"] },
  { id: "cashapp", name: "Cash App", tokens: ["cashapp"], domains: ["cash.app"] },
]);

/**
 * Tokens that are ordinary words or very short ("apple" in pineapple, "chase"
 * in purchase, "aws" in laws). They count only as a whole label or next to a
 * lure word such as "login" or "support" (see labelHasToken).
 */
export const WORD_TOKENS = new Set(["apple", "aws", "outlook", "chase", "interac", "adobe", "dhl", "usps", "ebay", "hsbc", "yahoo"]);
export const LURE_WORDS = ["login", "signin", "logon", "verify", "verification", "secure", "security", "account", "update",
  "confirm", "wallet", "password", "unlock", "recover", "billing", "auth", "support", "service", "help", "online", "my",
  "pay", "id", "team", "center", "centre", "mail", "web", "portal", "alert", "notice", "official", "customer", "access", "bank", "banking", "signon", "sso",
  "parcel", "package", "delivery", "redelivery", "tracking", "track", "shipping", "shipment", "order", "orders", "refund", "invoice"];

/** Brand tokens used for look-alike comparison (hyphen-free, length >= 4). */
export const BRAND_LABELS = Object.freeze(
  BRANDS.flatMap((brand) => brand.tokens.filter((t) => !t.includes("-") && t.length >= 4).map((label) => ({ label, brand }))),
);

const OFFICIAL = new Map(BRANDS.flatMap((b) => b.domains.map((d) => [d, b])));

/** The brand that operates this registrable domain, if listed. */
export function officialBrandFor(registrableDomain) {
  return registrableDomain ? OFFICIAL.get(registrableDomain) || null : null;
}

// Shared platforms where the leftmost label is chosen by any account holder.
// The PSL already treats most of these as public suffixes; the list lets the
// analysis say so in words. Sources: each platform's own documentation.
export const SHARED_HOSTING_SUFFIXES = Object.freeze([
  "github.io", "gitlab.io", "pages.dev", "workers.dev", "netlify.app", "vercel.app", "web.app",
  "firebaseapp.com", "blogspot.com", "wordpress.com", "wixsite.com", "weebly.com", "glitch.me",
  "herokuapp.com", "azurewebsites.net", "appspot.com", "onrender.com", "fly.dev", "repl.co",
  "ngrok.io", "ngrok-free.app", "trycloudflare.com", "000webhostapp.com", "webflow.io", "framer.app",
  "sites.google.com", "s3.amazonaws.com", "amazonaws.com", "r2.dev", "surge.sh", "carrd.co",
  // User-content domains run by large brands: anyone can publish there.
  "myshopify.com", "ipfs.io", "dweb.link",
  "sharepoint.com", "blob.core.windows.net", "web.core.windows.net", "googleusercontent.com",
  "dropboxusercontent.com", "storage.googleapis.com", "docs.google.com", "forms.gle", "1drv.ms",
]);

// Link shorteners: the real destination cannot be known without following the
// link, which this platform never does.
export const SHORTENERS = Object.freeze([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly",
  "shorturl.at", "tiny.cc", "rb.gy", "t.ly", "s.id", "v.gd", "bl.ink", "lnkd.in", "qrco.de", "short.io",
]);
