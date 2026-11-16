// Defanging makes an indicator safe to paste into tickets and chat without
// creating a clickable link: "https://evil.example/x" -> "hxxps://evil[.]example/x".

export function defang(value) {
  return String(value)
    .replace(/^http(s?):\/\//i, (_, s) => `hxxp${s}://`)
    .replace(/\./g, "[.]")
    .replace(/@/g, "[@]");
}

/**
 * Hide possible login text before echoing input that was not analysed (for
 * example a rejected line): every run of text ending in "@" is masked, with
 * or without a scheme, after refanging so "[at]" forms are caught too.
 */
export function maskCredentials(value) {
  // Each run is consumed once (with an optional trailing "@"), so this is
  // linear; "[^...]+@" alone rescanned from every start of a long line.
  return refang(value).replace(/[^\s/?#@]+@?/g, (run) => (run.endsWith("@") ? "•••@" : run));
}

/**
 * Replace the login part of a URL's authority (everything before its last
 * "@") with "•••", keeping the rest exactly as written. The masked form still
 * parses with login text, so re-analysing it gives the same evidence.
 */
export function maskUserinfo(url) {
  const m = /^((?:[a-z][a-z0-9+.-]*:)?\/\/)?([^/?#]*)/i.exec(String(url));
  const [whole, prefix = "", authority] = m;
  const at = authority.lastIndexOf("@");
  return at === -1 ? String(url) : `${prefix}•••${authority.slice(at)}${String(url).slice(whole.length)}`;
}

/**
 * Undo common defanging. "[@]" (this platform's own form) becomes "@"
 * anywhere; the e-mail convention "[at]" only before the path, where it can
 * stand for "@". In a path or query "[at]" is ordinary text and is kept.
 */
export function refang(value) {
  const s = String(value)
    .trim()
    .replace(/^hxxp(s?):\/\//i, (_, sec) => `http${sec}://`)
    .replace(/\[\.\]|\(\.\)|\{\.\}/g, ".")
    .replace(/\[@\]/g, "@")
    .replace(/\[:\]/g, ":");
  const head = /^(?:[a-z][a-z0-9+.-]*:)?(?:\/\/)?[^/?#]*/i.exec(s)[0];
  return head.replace(/\[at\]/gi, "@") + s.slice(head.length);
}
