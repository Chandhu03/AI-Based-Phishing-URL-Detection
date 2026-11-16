// Serve dist/ with the security headers from public/_headers applied the way
// Cloudflare Pages applies them, including the real 404 page. Used by the
// end-to-end tests so they run under the production CSP. Local use only.
//
//   node scripts/serve-dist.mjs [port]
import { createReadStream, existsSync, readFileSync, statSync } from "node:fs";
import { createServer } from "node:http";
import { extname, join, normalize, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { expectedFor, parseHeadersFile } from "./check-headers.mjs";

const ROOT = resolve(fileURLToPath(new URL("../dist", import.meta.url)));
const TYPES = {
  ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml", ".png": "image/png", ".woff2": "font/woff2", ".woff": "font/woff", ".txt": "text/plain; charset=utf-8",
  ".xml": "application/xml", ".json": "application/json",
};

export function resolvePath(urlPath) {
  let p = decodeURIComponent(urlPath.split("?")[0]);
  if (p.endsWith("/")) p += "index.html";
  const full = normalize(join(ROOT, p));
  if (full !== ROOT && !full.startsWith(ROOT + sep)) return null; // path traversal
  if (existsSync(full) && statSync(full).isFile()) return full;
  const asDir = join(full, "index.html");
  if (existsSync(asDir)) return { redirect: `${urlPath.split("?")[0]}/` };
  return null;
}

export function startServer(port = 4317) {
  const rules = parseHeadersFile(readFileSync(join(ROOT, "_headers"), "utf8"));
  const server = createServer((req, res) => {
    let target = null;
    let path = "/";
    try {
      path = new URL(req.url, "http://x").pathname;
      target = resolvePath(path);
    } catch {
      target = null;
    }
    const headers = expectedFor(rules, path);
    if (target?.redirect) {
      res.writeHead(308, { ...headers, location: target.redirect });
      return res.end();
    }
    const file = target ?? join(ROOT, "404.html");
    res.writeHead(target ? 200 : 404, { ...headers, "content-type": TYPES[extname(file)] ?? "application/octet-stream" });
    createReadStream(file).pipe(res);
  });
  return new Promise((ok) => server.listen(port, "127.0.0.1", () => ok(server)));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const port = Number(process.argv[2] || 4317);
  await startServer(port);
  console.log(`serving dist/ with production headers on http://127.0.0.1:${port}`);
}
