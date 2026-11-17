// Analyse URLs from the command line with the same engine the workspace uses.
// Offline: nothing is fetched. Reads one URL per line from a file or stdin and
// writes JSON Lines (one analysis per line) to stdout.
//
//   npm run analyze -- urls.txt > results.jsonl
//   type urls.txt | npm run analyze -- --summary
import { readFileSync } from "node:fs";
import { analyzeUrl, splitBatch } from "../src/engine/analyze.js";
import { defang, maskCredentials } from "../src/engine/defang.js";
import { PSL_COMMIT, RULES } from "../src/engine/generated/psl-rules.js";
import { verifiedScorer } from "../src/engine/model.js";
import { MODEL } from "../src/engine/models/url-host-model.js";
import { PublicSuffixList } from "../src/engine/psl.js";

const args = process.argv.slice(2);
const summary = args.includes("--summary");
const file = args.find((a) => !a.startsWith("--"));
const text = readFileSync(file ?? 0, "utf8");
const { items, truncated } = splitBatch(text, 100_000);

const psl = new PublicSuffixList(RULES, PSL_COMMIT);
const scorer = await verifiedScorer(MODEL); // refuses an artifact that does not match its SHA-256 id
const counts = {};
for (const raw of items) {
  const r = analyzeUrl(raw, { psl, scorer });
  if (!r.ok) {
    counts.rejected = (counts.rejected || 0) + 1;
    if (!summary) process.stdout.write(`${JSON.stringify({ ok: false, input: defang(maskCredentials(raw.slice(0, 300)).slice(0, 200)), code: r.code })}\n`);
    continue;
  }
  counts[r.verdict.level] = (counts[r.verdict.level] || 0) + 1;
  if (summary) process.stdout.write(`${r.verdict.label.padEnd(30)} ${defang(r.url)}\n`);
  else process.stdout.write(`${JSON.stringify(r)}\n`);
}
process.stderr.write(`analysed ${items.length}${truncated ? " (truncated)" : ""}: ${JSON.stringify(counts)}\n`);
