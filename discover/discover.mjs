#!/usr/bin/env node
// ProtocolProbe shadow-MCP discovery (feature #17): lists the MCP servers configured on THIS machine, and which ones
// Claude Desktop has started (its per-server log files). Runs locally, reads config files only, sends nothing
// anywhere, needs no install.
//
//   node discover.mjs                      user-level configs + the current directory's project configs
//   node discover.mjs --dir ../a --dir b   project configs in these directories too
//   node discover.mjs --json               machine-readable output (same fields)
//
// Never printed (see lib.mjs): env and header values, command arguments, URL userinfo/query/fragment, URL path
// segments that are not plain words, anything that looks like a credential. Home paths are shown as "~".
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import zlib from "node:zlib";
import { fileURLToPath } from "node:url";
import { claudeDesktopLogDir, describe, entriesOf, looksSecret, projectLocations, ranFromLogNames, stripJsonc, userLocations, vscodeProfilesDir } from "./lib.mjs";
import { validIndex } from "./registry-index.mjs";

/** A server or log name that looks like a credential is replaced, in both text and JSON output. */
// a name a person picked ("Context7") stays visible; one that looks like a credential, or has a single word of 25+
// characters (a token used as a label), is replaced
const safeName = (n) => (looksSecret(n, { name: true }) || String(n).split(/[-_. ]/).some((w) => w.length > 24) ? "(name not shown: looks like a credential)" : String(n));
const STALE_DAYS = 60; // the registry is refreshed monthly; two months old is worth a warning
const INDEX_FILE =path.join(path.dirname(fileURLToPath(import.meta.url)), "registry-index.json.gz");

/** The offline registry snapshot, or null (with the reason) when it is missing or not the shape this code reads. */
export function loadIndex(file = INDEX_FILE) {
  try {
    const x = JSON.parse(zlib.gunzipSync(fs.readFileSync(file)).toString("utf8"));
    if (!validIndex(x)) return { index: null, why: "registry snapshot file is not in the expected format" };
    return { index: { ...x, hostSet: new Set(x.hosts) } };
  } catch (e) { return { index: null, why: e.code === "ENOENT" ? "registry snapshot file not found" : "registry snapshot file could not be read" }; }
}
const isDir = (p) => { try { return fs.statSync(p).isDirectory(); } catch { return false; } };

export function scan({ platform = process.platform, home = os.homedir(), appData = process.env.APPDATA, dirs = [process.cwd()], index: given, now = new Date() } = {}) {
  const loaded = given === undefined ? loadIndex() : { index: given };
  const index = loaded.index;
  // a registry snapshot ages: servers published after it show as "not found". Say so once it is old.
  const ageDays = index ? Math.floor((now - new Date(`${index.snapshot}T00:00:00Z`)) / 86400000) : null;
  const tilde = (p) => {
    const h = path.resolve(home);
    const same = platform === "win32" ? p.toLowerCase().startsWith(h.toLowerCase()) : p.startsWith(h);
    return same && (p.length === h.length || /[\\/]/.test(p[h.length])) ? "~" + p.slice(h.length) : p;
  };
  const locations = [...userLocations({ platform, home, appData })];
  for (const l of [...locations]) {
    if (l.key === "servers" && l.scope === "user") {
      const pdir = vscodeProfilesDir(l.file);
      let subs = [];
      try { subs = fs.readdirSync(pdir).filter((n) => isDir(path.join(pdir, n))); } catch {}
      for (const s of subs) locations.push({ ...l, scope: `user (profile ${s})`, file: path.join(pdir, s, "mcp.json") });
    }
  }
  const warnings = loaded.why ? [`${loaded.why}: servers are not matched against the registry and remote hosts are shortened`] : [];
  if (ageDays !== null && ageDays > STALE_DAYS) warnings.push(`the registry snapshot is ${ageDays} days old (${index.snapshot}): servers published since then show as "not found"`);
  for (const d of dirs) {
    const abs = path.resolve(d);
    if (!isDir(abs)) { warnings.push(`--dir ${tilde(abs)} is not a directory; skipped`); continue; }
    locations.push(...projectLocations(abs));
  }
  // the same file can be reached twice (e.g. --dir ~ finds ~/.cursor/mcp.json again): read it once
  const seen = new Set();
  const unique = locations.filter((l) => { const k = path.resolve(l.file).toLowerCase(); if (seen.has(k)) return false; seen.add(k); return true; });

  const files = [], servers = [];
  for (const l of unique) {
    const shown = { ...l, file: tilde(l.file) };
    let text;
    try { text = fs.readFileSync(l.file, "utf8"); } catch (e) { files.push({ ...shown, status: e.code === "ENOENT" || e.code === "ENOTDIR" ? "absent" : "unreadable" }); continue; }
    let json;
    try { json = JSON.parse(stripJsonc(text)); } catch { files.push({ ...shown, status: "not valid JSON" }); continue; }
    const entries = entriesOf(json, l.key);
    files.push({ ...shown, status: "read", servers: entries.length });
    for (const e of entries) servers.push({ client: l.client, scope: e.project ? `local (${tilde(platform === "win32" ? String(e.project).replace(/\//g, "\\") : String(e.project))})` : l.scope, file: shown.file, name: safeName(e.name), ...describe(e.def, index) });
  }

  let ran = null;
  const logDir = claudeDesktopLogDir({ platform, home, appData });
  if (logDir) {
    try { ran = { dir: tilde(logDir), servers: ranFromLogNames(fs.readdirSync(logDir)).map(safeName) }; } catch { ran = { dir: tilde(logDir), servers: null }; }
  }
  return { scannedAt: new Date().toISOString(), platform, registrySnapshot: index ? { snapshot: index.snapshot, servers: index.servers } : null, warnings, files, servers, claudeDesktopStarted: ran };
}

/**
 * Control characters in names from a config file are shown escaped, never raw: terminal escapes, newlines, line
 * separators, and text-direction controls (a right-to-left override can visually reverse a line).
 */
const CTRL = new RegExp("[\\u0000-\\u001f\\u007f-\\u009f\\u2028\\u2029\\u200e\\u200f\\u202a-\\u202e\\u2066-\\u2069]", "g");
const clean = (v) => String(v).replace(CTRL, (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"));

/** One line about the registry match; "not listed" is a statement about the snapshot, not about the server. */
function registryLine(m) {
  if (m.state === "listed") return `registry: listed as ${m.name} → ${m.url}`;
  if (m.state === "several") return `registry: shared by ${m.count} registry entries (not guessed which)`;
  return "registry: not found in the snapshot (it may be newer, unpublished, or not a registry server; this says nothing about its safety)";
}

export function render(r) {
  const lines = [];
  lines.push(`MCP servers configured on this machine (${r.platform}, ${r.scannedAt})`);
  lines.push("Nothing was sent anywhere. Not shown: env and header values, command arguments, URL queries, path segments that");
  lines.push("are not plain words, and anything that looks like a credential. Remote hosts are shortened unless the registry lists them.");
  if (r.registrySnapshot) lines.push(`Matched offline (no network) against the official MCP registry as of ${clean(r.registrySnapshot.snapshot)} (${r.registrySnapshot.servers} servers).`);
  for (const w of r.warnings ?? []) lines.push(`warning: ${clean(w)}`);
  lines.push("");
  lines.push(`Config files checked: ${r.files.length} (read ${r.files.filter((f) => f.status === "read").length}, absent ${r.files.filter((f) => f.status === "absent").length}, problem ${r.files.filter((f) => !["read", "absent"].includes(f.status)).length})`);
  for (const f of r.files.filter((f) => f.status !== "absent")) lines.push(`  ${f.status === "read" ? `${f.servers} server(s)` : f.status.toUpperCase()}  ${clean(f.client)} · ${clean(f.scope)} · ${clean(f.file)}`);
  lines.push("");
  lines.push(`Servers: ${r.servers.length}`);
  for (const s of r.servers) {
    const what = s.remote && s.package ? `${s.package.runner} ${s.package.name} → remote ${s.remote}` : s.remote ? `remote ${s.remote}` : s.package ? `${s.package.runner} ${s.package.name}` : s.command ? `command "${s.command}" (${s.args} argument${s.args === 1 ? "" : "s"})` : "command or URL not shown";
    const extra = [s.transport, s.envVars ? `env vars: ${s.envNames.join(", ") || s.envVars}${s.envNames.length && s.envNames.length < s.envVars ? ` (+${s.envVars - s.envNames.length} not shown)` : ""}` : null, s.headers ? `${s.headers} header(s)` : null, s.disabled ? "disabled" : null].filter(Boolean).join(" · ");
    lines.push(`  ${clean(s.name)}  —  ${clean(what)}`);
    lines.push(`      ${clean(s.client)} · ${clean(s.scope)} · ${clean(extra)}`);
    if (s.registry) lines.push(`      ${clean(registryLine(s.registry))}`);
  }
  const st = r.claudeDesktopStarted;
  if (st) {
    lines.push("");
    lines.push(st.servers ? `Claude Desktop has started (a log file exists): ${st.servers.length ? st.servers.map(clean).join(", ") : "none"}` : `Claude Desktop logs: not found (${clean(st.dir)})`);
  }
  lines.push("");
  lines.push("A listed server's page shows what ProtocolProbe checked and what it did not: https://protocolprobe.com/mcp/servers/");
  return lines.join("\n");
}

export const USAGE = "usage: protocolprobe-discover [--dir <project>]... [--json] | --help | --version";

/** The package's own version (package.json ships next to this file), or null if it cannot be read. */
export function version() {
  try { return JSON.parse(fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), "package.json"), "utf8")).version ?? null; } catch { return null; }
}

export function parseArgs(argv) {
  const dirs = [];
  let json = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--help" || a === "-h") return { help: true };
    if (a === "--version" || a === "-v") return { version: true };
    if (a === "--json") json = true;
    else if (a === "--dir") {
      const v = argv[i + 1];
      if (v === undefined || v.startsWith("--")) return { error: "--dir needs a directory" };
      dirs.push(v); i++;
    } else return { error: `unknown argument: ${a}` };
  }
  return { dirs, json };
}

/**
 * True when this file is the program being run. Compared by real path: an installed command (npm's bin link) reaches this
 * file through a symlink, and comparing the raw argv[1] with the module URL would then print nothing at all.
 */
export function isMain(argv1 = process.argv[1], url = import.meta.url) {
  try { return !!argv1 && fs.realpathSync(argv1) === fs.realpathSync(fileURLToPath(url)); } catch { return false; }
}

if (isMain()) {
  const a = parseArgs(process.argv.slice(2));
  if (a.error) { console.error(`${a.error}\n${USAGE}`); process.exit(2); }
  if (a.help) {
    console.log(`${USAGE}\n\nLists the MCP servers configured on this machine (Claude Desktop, Claude Code, Cursor, VS Code) and, offline, which are in the\nofficial MCP registry. Reads config files only; sends nothing anywhere; never prints env/header values or arguments.\n  --dir <project>  also read that project's .mcp.json, .cursor/mcp.json and .vscode/mcp.json (default: the current directory)\n  --json           machine-readable output`);
  } else if (a.version) {
    console.log(version() ?? "unknown");
  } else {
    const r = scan({ dirs: a.dirs.length ? a.dirs : [process.cwd()] });
    console.log(a.json ? JSON.stringify(r, null, 2) : render(r));
  }
}
