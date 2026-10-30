// Feature #17 as a package: what would be published, that it can run as an installed command, and the claim the page
// makes ("sends nothing anywhere") checked against the shipped source.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(fs.readFileSync(path.join(here, "package.json"), "utf8"));
const read = (f) => fs.readFileSync(path.join(here, f), "utf8");
const node = (args, opts = {}) => spawnSync(process.execPath, args, { encoding: "utf8", ...opts });

test("package.json: name, bin, files and engine are consistent with what is on disk", () => {
  assert.equal(pkg.name, "protocolprobe-discover");
  assert.match(pkg.version, /^\d+\.\d+\.\d+$/);
  assert.equal(pkg.type, "module");
  assert.deepEqual(Object.keys(pkg.bin), [pkg.name]);
  assert.equal(pkg.engines.node, ">=18");
  assert.equal(pkg.license, "ISC");
  assert.match(read("LICENSE"), /^ISC License\n/);
  for (const f of pkg.files) assert.ok(fs.existsSync(path.join(here, f)), `${f} listed in files but missing`);
  assert.ok(read(pkg.bin[pkg.name]).startsWith("#!/usr/bin/env node\n"), "the bin file needs a node shebang");
  assert.equal(pkg.dependencies, undefined, "no runtime dependencies");
  assert.equal(pkg.scripts?.postinstall ?? pkg.scripts?.install ?? pkg.scripts?.preinstall, undefined, "no install-time scripts");
});

test("what would be published: exactly the whitelist, small, no tests or fixtures, no planted secret markers", () => {
  const r = spawnSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], { cwd: here, encoding: "utf8", shell: process.platform === "win32" });
  assert.equal(r.status, 0, r.stderr);
  const info = JSON.parse(r.stdout)[0];
  const names = info.files.map((f) => f.path).sort();
  assert.deepEqual(names, [...pkg.files, "package.json"].sort());
  assert.ok(info.size < 1_000_000, `tarball ${info.size} bytes`);
  for (const f of names.filter((n) => /\.(mjs|json|md)$|^LICENSE$/.test(n))) assert.equal(/LEAK|ghp_[A-Za-z0-9]{8}|AKIA[A-Z0-9]{8}|sk-[A-Za-z0-9]{8}/.test(read(f)), false, `${f} carries a secret-looking string`);
});

test("sends nothing anywhere: the shipped source imports no network, process or dynamic-code module", () => {
  const ALLOWED = new Set(["node:fs", "node:os", "node:path", "node:zlib", "node:url"]);
  for (const f of ["discover.mjs", "lib.mjs", "registry-index.mjs"]) {
    const src = read(f);
    const imports = [...src.matchAll(/^import\s[^;]*?from\s*["']([^"']+)["'];?\s*$/gm)].map((m) => m[1]);
    assert.ok(imports.length > 0 || f === "registry-index.mjs", `${f}: no import found (the check would pass vacuously)`);
    for (const spec of imports) assert.ok(ALLOWED.has(spec) || spec.startsWith("./"), `${f} imports ${spec}`);
    assert.equal(/^\s*import\s*\(/m.test(src) || /[^\w.]import\s*\(/.test(src.replace(/\/\/.*$/gm, "")), false, `${f} uses a dynamic import`);
    for (const bad of [/\bfetch\s*\(/, /\bXMLHttpRequest\b/, /\bchild_process\b/, /\brequire\s*\(/, /\beval\s*\(/, /new Function\s*\(/, /\bprocess\.env\.(?!APPDATA\b)/]) assert.equal(bad.test(src), false, `${f} matches ${bad}`);
  }
});

test("runs as a command: --version, --help, a bad flag, and through a symlink (how npm installs a bin)", () => {
  const bin = path.join(here, pkg.bin[pkg.name]);
  assert.equal(node([bin, "--version"]).stdout.trim(), pkg.version);
  const h = node([bin, "--help"]);
  assert.equal(h.status, 0);
  assert.match(h.stdout, /protocolprobe-discover/);
  const bad = node([bin, "--nope"]);
  assert.equal(bad.status, 2);
  assert.match(bad.stderr, /unknown argument: --nope/);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ppdisc-link-"));
  const link = path.join(dir, "protocolprobe-discover");
  try { fs.symlinkSync(bin, link); } catch (e) { if (e.code === "EPERM" || e.code === "EACCES") return; throw e; }   // Windows without symlink rights
  assert.equal(node([link, "--version"]).stdout.trim(), pkg.version, "a symlinked bin printed nothing");
});

test("isMain compares real paths: a path that reaches the file through a link still counts, anything else does not", async () => {
  const { isMain } = await import("./discover.mjs");
  const url = new URL("./discover.mjs", import.meta.url).href;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ppdisc-junction-"));
  const via = path.join(dir, "linked");
  fs.symlinkSync(here, via, "junction");                       // a directory link works without special rights on Windows
  assert.equal(isMain(path.join(via, "discover.mjs"), url), true);
  assert.equal(isMain(path.join(here, "discover.mjs"), url), true);
  assert.equal(isMain(path.join(here, "lib.mjs"), url), false);
  assert.equal(isMain(path.join(dir, "missing.mjs"), url), false);
  assert.equal(isMain(undefined, url), false);
});
