#!/usr/bin/env node
// Builds registry-index.json.gz (the offline lookup discover.mjs uses) from a registry dump with one
// {server, _meta} JSON object per line, as engine/results/dev-registry-full.ndjson. Run on each registry refresh.
//
//   node build-index.mjs --registry ../../engine/results/dev-registry-full.ndjson --snapshot 2026-10-04 [--out registry-index.json.gz]
import fs from "node:fs";
import path from "node:path";
import readline from "node:readline";
import zlib from "node:zlib";
import { fileURLToPath } from "node:url";
import { buildIndex, validIndex } from "./registry-index.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const arg = (k) => { const i = process.argv.indexOf(k); return i > 0 ? process.argv[i + 1] : undefined; };
const registry = arg("--registry"), snapshot = arg("--snapshot");
const out = path.resolve(arg("--out") ?? path.join(here, "registry-index.json.gz"));
if (!registry || !/^\d{4}-\d{2}-\d{2}$/.test(snapshot ?? "")) { console.error("usage: node build-index.mjs --registry <ndjson> --snapshot YYYY-MM-DD [--out file]"); process.exit(2); }

const rows = [];
let bad = 0;
for await (const line of readline.createInterface({ input: fs.createReadStream(registry), crlfDelay: Infinity })) {
  if (!line) continue;
  try { rows.push(JSON.parse(line)); } catch { bad++; }
}
const index = buildIndex(rows, snapshot);
if (!validIndex(index) || index.servers < 1) throw new Error("built index is not valid");
fs.writeFileSync(out, zlib.gzipSync(JSON.stringify(index), { level: 9 }));
const one = (o) => Object.values(o).filter((v) => typeof v === "string").length;
console.log(JSON.stringify({ rowsRead: rows.length, unparseableLines: bad, servers: index.servers, packageKeys: Object.keys(index.packages).length, packageKeysOneServer: one(index.packages), remoteKeys: Object.keys(index.remotes).length, remoteKeysOneServer: one(index.remotes), hosts: index.hosts.length, bytes: fs.statSync(out).size, out: path.relative(process.cwd(), out) }));
