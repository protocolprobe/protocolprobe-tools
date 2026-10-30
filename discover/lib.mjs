// Feature #17, shadow-MCP discovery: which MCP servers are configured (and, for Claude Desktop, which actually ran) on
// THIS machine. Pure functions here (unit-tested); file access is in discover.mjs.
//
// Privacy rules (CLAUDE.md, "Org-wide shadow-MCP discovery"): nothing is sent anywhere; secrets never leave the config
// file. Never output env values, header values, raw arguments, URL query strings or URL userinfo: config files hold
// API keys in all of those places. Only names, counts, the command's base name, a package name recognised from a
// known runner pattern, and a remote URL's origin + path are reported.
//
// Locations and formats, each read from the vendor's own documentation on 2026-10-10 (Claude Desktop from the
// project's research log, verified with a real probe on 2026-10-03):
//   Claude Desktop  macOS ~/Library/Application Support/Claude/claude_desktop_config.json,
//                   Windows %APPDATA%\Claude\claude_desktop_config.json; logs ~/Library/Logs/Claude, %APPDATA%\Claude\logs
//                   (one mcp-server-NAME.log per server that was started)                  key "mcpServers"
//   Claude Code     ~/.claude.json: "mcpServers" (user scope) and "projects"[path]."mcpServers" (local scope);
//                   <project>/.mcp.json (project scope)                                     code.claude.com/docs/en/mcp
//   Cursor          ~/.cursor/mcp.json, <project>/.cursor/mcp.json                          cursor.com/docs/context/mcp
//   VS Code         <project>/.vscode/mcp.json (key "servers"); user mcp.json in the user profile folder
//                   (%APPDATA%\Code\User, ~/Library/Application Support/Code/User, ~/.config/Code/User, and
//                   profiles/<id>/ under each); ~/.copilot/mcp-config.json (key "mcpServers")
//                                                       code.visualstudio.com/docs/copilot/customization/mcp-servers

import path from "node:path";
import { matchPackage, matchRemote, normPackage, remoteKey } from "./registry-index.mjs";

/** Every user-level file to look at, for one platform and home directory (paths only; nothing is read here). */
export function userLocations({ platform, home, appData }) {
  const L = [];
  const add = (client, scope, file, key) => L.push({ client, scope, file, key });
  if (platform === "darwin") add("Claude Desktop", "user", path.join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"), "mcpServers");
  if (platform === "win32" && appData) add("Claude Desktop", "user", path.join(appData, "Claude", "claude_desktop_config.json"), "mcpServers");
  add("Claude Code", "user + local", path.join(home, ".claude.json"), "claude.json");
  add("Cursor", "user", path.join(home, ".cursor", "mcp.json"), "mcpServers");
  add("VS Code / Copilot", "user", path.join(home, ".copilot", "mcp-config.json"), "mcpServers");
  for (const product of ["Code", "Code - Insiders"]) {
    const userDir = platform === "win32" ? (appData ? path.join(appData, product, "User") : null)
      : platform === "darwin" ? path.join(home, "Library", "Application Support", product, "User")
      : path.join(home, ".config", product, "User");
    if (userDir) add(product === "Code" ? "VS Code" : "VS Code Insiders", "user", path.join(userDir, "mcp.json"), "servers");
  }
  return L;
}

/** VS Code profile folders hold their own mcp.json (scanned by the caller when the folder exists). */
export function vscodeProfilesDir(userMcpFile) {
  return path.join(path.dirname(userMcpFile), "profiles");
}

/** Claude Desktop's log folder (servers that were actually started leave mcp-server-NAME.log). */
export function claudeDesktopLogDir({ platform, home, appData }) {
  if (platform === "darwin") return path.join(home, "Library", "Logs", "Claude");
  if (platform === "win32" && appData) return path.join(appData, "Claude", "logs");
  return null;
}

/** Project-level files inside one project directory. */
export function projectLocations(dir) {
  return [
    // .mcp.json is read by Claude Code and, per its docs, by VS Code too
    { client: "Claude Code / VS Code", scope: "project", file: path.join(dir, ".mcp.json"), key: "mcpServers" },
    { client: "Cursor", scope: "project", file: path.join(dir, ".cursor", "mcp.json"), key: "mcpServers" },
    { client: "VS Code", scope: "project", file: path.join(dir, ".vscode", "mcp.json"), key: "servers" },
  ];
}

/** Server entries from a parsed config file: [{ name, def, project? }]. ~/.claude.json has two places. */
export function entriesOf(json, key) {
  const out = [];
  const take = (obj, project) => {
    if (!obj || typeof obj !== "object" || Array.isArray(obj)) return;
    for (const [name, def] of Object.entries(obj)) if (def && typeof def === "object") out.push({ name, def, ...(project ? { project } : {}) });
  };
  if (key === "claude.json") {
    take(json?.mcpServers);
    if (json?.projects && typeof json.projects === "object") for (const [p, v] of Object.entries(json.projects)) take(v?.mcpServers, p);
  } else take(json?.[key]);
  return out;
}

// Known runners: which flags take NO value and which take ONE value. If any other flag appears before the first
// positional argument, we cannot know whether that positional is the package or a flag's value, so nothing is
// reported (independent review, 2026-10-10: unlisted flags such as `uvx --refresh-package X` or
// `docker run --hostname X` otherwise turned their value into the "package").
const RUNNERS = {
  npx: { sub: null, bare: ["-y", "--yes", "--no", "-q", "--quiet", "--no-install", "--ignore-existing", "--prefer-online", "--prefer-offline"], valued: ["-p", "--package", "-c", "--call"] },
  bunx: { sub: null, bare: ["--bun"], valued: [] },
  pnpm: { sub: "dlx", bare: ["-s", "--silent"], valued: ["--package"] },
  uvx: { sub: null, bare: ["-q", "--quiet", "--offline", "--refresh", "--isolated", "--no-cache", "-v", "--verbose"], valued: ["--from", "--with", "--python", "-p", "--index", "--index-url", "--extra-index-url", "--refresh-package", "--with-requirements", "--with-editable", "--env-file"] },
  pipx: { sub: "run", bare: ["--no-cache", "--verbose", "-q", "--quiet"], valued: ["--spec", "--python", "--index-url", "--pip-args"] },
  docker: { sub: "run", bare: ["-i", "-t", "-it", "-ti", "--rm", "-d", "--init", "--privileged", "--interactive", "--tty", "--detach", "--read-only"],
    valued: ["-e", "--env", "--env-file", "-v", "--volume", "--name", "-p", "--publish", "--network", "--net", "-w", "--workdir", "-u", "--user", "--mount",
      "--entrypoint", "--platform", "-l", "--label", "--label-file", "--add-host", "-h", "--hostname", "--dns", "--cap-add", "--cap-drop", "-m", "--memory",
      "--cpus", "--log-opt", "--log-driver", "--device", "--security-opt", "--tmpfs", "--ulimit", "--restart", "--pull", "--gpus", "--ipc", "--pid", "--shm-size"] },
};
function firstPositional(a, { bare, valued }) {
  for (let i = 0; i < a.length; i++) {
    const x = a[i];
    if (!x.startsWith("-")) return x;
    if (x.includes("=") && valued.some((f) => x.startsWith(f + "="))) continue; // --flag=value: value stays inside, not printed
    if (valued.includes(x)) { i++; continue; }
    if (bare.includes(x)) continue;
    return null; // a flag we do not know: the next argument may be its value
  }
  return null;
}
// a package or image name: letters, digits and @ / . _ - : (version tags allowed); anything else is not reported
const PKG_RE = /^@?[a-z0-9][a-z0-9._-]*(\/[a-z0-9][a-z0-9._-]*)*(@[a-z0-9._^~<>=-]+)?(:[a-z0-9._-]+)?$/i;
/**
 * Strings that look like credentials are never reported, even where a name is expected. For names a person picked
 * (server, command and env names: "Context7", "Neo4jMemory") the mixed-case rule needs 16+ characters; URL path
 * segments and package names go through plainName(), which is stricter.
 */
export function looksSecret(x, { name = false } = {}) {
  const s = String(x);
  if (/^(ghp_|gho_|ghu_|ghs_|github_pat_|sk-|sk_|pk_|rk_|xox[abprs]-|AIza|AKIA|ASIA|eyJ)/i.test(s)) return true;
  if (/(ghp_|gho_|github_pat_|xox[abprs]-|AIza|AKIA)[A-Za-z0-9_-]{8,}/.test(s)) return true; // a known prefix inside
  return s.split(/[\/@:._~-]/).some((part) =>
    (part.length >= 20 && /[a-z]/i.test(part) && /\d/.test(part)) ||                         // long letter-and-digit run
    /^[0-9a-f]{12,}$/i.test(part) ||                                                         // hex string
    (part.length >= (name ? 16 : 8) && /[a-z]/.test(part) && /[A-Z]/.test(part) && /\d/.test(part))); // mixed case + digit
}

/**
 * A "plain name": short lower-case words joined by . _ - ~ (an optional leading @), as real package names and URL
 * path words look. Random tokens fail it (mixed case, a word over 16 characters, many digits, hex).
 */
export function plainName(x) {
  const s = String(x);
  if (!/^@?[a-z0-9]+([._~-][a-z0-9]+)*$/.test(s) || looksSecret(s)) return false;
  // words up to 16 characters; longer ones (e.g. "modelcontextprotocol") only up to 24 and letters only
  return s.replace(/^@/, "").split(/[._~-]/).every((w) => w.length <= 16 || (w.length <= 24 && /^[a-z]+$/.test(w)))
    && (s.match(/\d/g) ?? []).length <= 8;
}

/**
 * The command's base name, only when the command is a plain program or a path to one. A command string that also
 * carries arguments ("npx -y pkg --token=…", "node C:\srv\server.js --key=…") is never printed.
 */
export function commandName(cmd) {
  if (typeof cmd !== "string") return null;
  const c = cmd.trim();
  const cut = Math.max(c.lastIndexOf("/"), c.lastIndexOf("\\"));
  const dir = cut >= 0 ? c.slice(0, cut) : "", base = (cut >= 0 ? c.slice(cut + 1) : c).replace(/\.(exe|cmd|bat|ps1|sh)$/i, "");
  if (/\s-|\s--/.test(dir) || /\s/.test(base)) return null; // arguments in the string
  return /^[\w.+-]{1,64}$/.test(base) && !looksSecret(base, { name: true }) ? base : null;
}

/** The package a known runner starts, or null. Never returns an argument that does not look like a package name. */
export function packageOf(def) {
  const cmd = commandName(def.command)?.toLowerCase();
  const r = cmd ? RUNNERS[cmd] : null;
  if (!r || !Array.isArray(def.args)) return null;
  let args = def.args.map(String);
  if (r.sub) { if (args[0] !== r.sub) return null; args = args.slice(1); }
  const pick = firstPositional(args, r);
  if (!pick || !PKG_RE.test(pick) || pick.length > 214 || looksSecret(pick)) return null;
  const nameOnly = pick.replace(/^(@?[^@]+)@.*$/, "$1").replace(/:[^/]*$/, ""); // without @version or :tag
  return nameOnly.split("/").every((part) => plainName(part)) ? { runner: cmd, name: pick } : null;
}

const TRANSPORTS = ["stdio", "http", "streamable-http", "sse", "ws"];

/**
 * A remote URL reduced to its origin and a path in which every segment that is not a plain word is replaced by "*"
 * (tokens are sometimes put in the path). No userinfo, query or fragment. A URL built from variables (`${…}`) is
 * not shown at all. null when it is not a valid http(s)/ws(s) URL.
 */
export function safeRemote(url, hosts = null, listed = null) {
  const raw = String(url);
  if (raw.includes("${")) return "(URL built from variables)";
  try {
    const u = new URL(raw);
    if (!["http:", "https:", "ws:", "wss:"].includes(u.protocol)) return null;
    // a URL the registry itself lists is public: its path is shown as written. Any other path keeps only the generic
    // endpoint words below; every other segment is "*" (a lower-case token cannot be told apart from a word)
    const key = remoteKey(raw);
    const isListed = !!listed && key !== null && Object.hasOwn(listed, key);
    const segs = u.pathname.split("/").map((seg) => (seg === "" || isListed || PATH_WORDS.has(seg) ? seg : "*"));
    return `${u.protocol}//${shownHost(u, hosts)}${segs.join("/")}`;
  } catch { return null; }
}

// generic endpoint words that carry no account or secret; anything else in an unlisted URL's path is shown as "*"
const PATH_WORDS = new Set(["mcp", "sse", "api", "v1", "v2", "v3", "http", "stream", "streamable", "streamable-http", "message", "messages", "rpc", "server", "servers", "tools", "public", "beta", "events", "ws", "socket", "jsonrpc"]);

/**
 * The URL `mcp-remote` is started with (npx mcp-remote https://… --header …). It is an argument, so it is never shown
 * as written: only its shortened form and its registry match are reported, through the same rules as a "url" entry.
 * null for any other program, or when no URL follows the package.
 */
export function remoteArgOf(def) {
  const pkg = packageOf(def);
  if (!pkg || normPackage("npm", pkg.name) !== "mcp-remote" || !Array.isArray(def.args)) return null;
  const args = def.args.map(String), i = args.indexOf(pkg.name);
  const url = i < 0 ? undefined : args.slice(i + 1).find((a) => /^(https?|wss?):\/\//i.test(a));
  return url ?? null;
}

/**
 * A host is shown whole only when it is a public host the registry itself lists, an IP address, a single-label name
 * (localhost) or a bare two-label domain. Any other host keeps only its last two labels ("*.supabase.co"): per-account
 * hosts are sometimes the credential (project references, tunnel ids), and a letters-only token cannot be told apart
 * from a word. A label that itself looks like a credential is replaced by "*" even in a two-label domain.
 */
export function shownHost(u, hosts) {
  const name = u.hostname.toLowerCase(), port = u.port ? `:${u.port}` : "";
  if (u.hostname.startsWith("[") || /^\d{1,3}(\.\d{1,3}){3}$/.test(name) || !name.includes(".")) return u.host;
  if (hosts?.has(name)) return u.host;
  const labels = name.split(".");
  const tail = labels.slice(-2).map((l) => (looksSecret(l) || (l.length >= 12 && /\d/.test(l) && /[a-z]/.test(l)) ? "*" : l)); // the URL parser lower-cases hosts, so the mixed-case rule cannot see a token: 12+ characters of letters and digits is hidden
  return (labels.length > 2 ? "*." : "") + tail.join(".") + port;
}

/**
 * An environment variable name is shown only in the conventional shape: upper case, digits and underscores, every
 * word short (GITHUB_PERSONAL_ACCESS_TOKEN). A lower-case or long single-word name could be a credential used as a
 * key, so it is only counted.
 */
export function conventionalEnvName(k) {
  const s = String(k);
  return /^[A-Z][A-Z0-9_]{0,63}$/.test(s) && !looksSecret(s, { name: true }) && s.split("_").every((w) => w.length <= 14);
}

/** One reportable server: names, counts and recognised identifiers only. */
export function describe(def, index = null) {
  const url = def.url ?? def.serverUrl;
  const declared = typeof def.type === "string" ? def.type.toLowerCase() : null;
  const isWs = typeof url === "string" && /^wss?:/i.test(url);
  const transport = declared ? (TRANSPORTS.includes(declared) ? declared : "other") : url ? (isWs ? "ws" : "http") : def.command ? "stdio" : "unknown";
  const plainObj = (o) => o && typeof o === "object" && !Array.isArray(o);
  const viaRemote = url ? null : remoteArgOf(def);              // `npx mcp-remote <url>`: the package AND the remote it points at
  const target = url ?? viaRemote;
  return {
    transport,
    command: url ? null : commandName(def.command),
    package: url ? null : packageOf(def),
    remote: target ? safeRemote(target, index ? index.hostSet : null, index ? index.remotes : null) : null,
    // an offline lookup against the registry snapshot (public data only: it matches, it never prints the config's value)
    registry: target ? matchRemote(target, index) : matchPackage(packageOf(def), index),
    args: Array.isArray(def.args) ? def.args.length : typeof def.args === "string" ? 1 : 0,
    envVars: plainObj(def.env) ? Object.keys(def.env).length : 0,
    envNames: plainObj(def.env) ? Object.keys(def.env).filter(conventionalEnvName) : [],
    headers: plainObj(def.headers) ? Object.keys(def.headers).length : 0,
    disabled: def.disabled === true,
  };
}

/** Server names Claude Desktop started at some point: a log file mcp-server-NAME.log exists (logs persist). */
export function ranFromLogNames(names) {
  return [...new Set(names.map((n) => /^mcp-server-(.+)\.log$/.exec(n)?.[1]).filter(Boolean))].sort();
}

/** JSON with comments and trailing commas (VS Code writes JSONC) → plain JSON text. Strings are left untouched. */
export function stripJsonc(text) {
  text = String(text).replace(/^﻿/, "");
  try { JSON.parse(text); return text; } catch {} // plain JSON: no character-by-character pass (large ~/.claude.json)
  let out = "", i = 0, inStr = false;
  while (i < text.length) {
    const c = text[i], n = text[i + 1];
    if (inStr) {
      out += c;
      if (c === "\\") { out += n ?? ""; i += 2; continue; }
      if (c === '"') inStr = false;
      i++; continue;
    }
    if (c === '"') { inStr = true; out += c; i++; continue; }
    if (c === "/" && n === "/") { while (i < text.length && text[i] !== "\n") i++; continue; }
    if (c === "/" && n === "*") { i += 2; while (i < text.length && !(text[i] === "*" && text[i + 1] === "/")) i++; i += 2; continue; }
    out += c; i++;
  }
  // trailing commas before } or ] (outside strings: strings were copied verbatim, so re-scan with the same state machine)
  let res = "", s = false;
  for (let j = 0; j < out.length; j++) {
    const c = out[j];
    if (s) { res += c; if (c === "\\") { res += out[++j] ?? ""; } else if (c === '"') s = false; continue; }
    if (c === '"') { s = true; res += c; continue; }
    if (c === ",") { let k = j + 1; while (k < out.length && /\s/.test(out[k])) k++; if (out[k] === "}" || out[k] === "]") continue; }
    res += c;
  }
  return res.replace(/^﻿/, "");
}
