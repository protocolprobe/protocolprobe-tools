#!/usr/bin/env node
// Self-test: the engine's checks against an MCP server YOU run: one this tool starts on THIS machine (--stdio), or, from 0.2.0,
// your own Streamable HTTP server at a URL, after you prove you control that exact URL (--url).
//
// This is the narrow "operator tests their own server" lane. The owner reopened it on 2026-10-14 (docs/design/permission-records.md
// kept it out until then), limited to what is below. It is NOT the third-party lane: that one is cli.js with permission records.
//
//   node selftest.mjs --i-own-this-server [--allow-mutating] [--allow-fuzzing] [--out report.json]
//                     [--connect-timeout <seconds>] [--max-time <seconds>] --stdio <command> [args...]
//   node selftest.mjs --i-own-this-server [same options] [--new-proof] --url <https://your.server/mcp>
//
// --url (0.2.0; owner decisions D1-D7 and D10 of 2026-10-19, docs/design/domain-proof-assessment.md), all in src/remote-proof.js
// and tested in test/selftest-remote.test.js:
//   - the first run makes a one-time value (256 random bits), bound to the exact URL (scheme, host, port, path, query), keeps
//     only its hash on this machine, prints it, connects to nothing and exits 3;
//   - the next run, within 30 minutes, connects and reads the server's initialize `instructions`; the value must be there on a
//     line of its own, on the same connection that then runs the checks. Then it is deleted (single use) and the checks run.
//     Otherwise nothing runs and the exit code is 4 (missing, wrong, expired, redirected, needs a credential);
//   - no redirect is ever followed; the host is resolved once and every connection goes to those addresses;
//   - https for any host, http only for this machine (localhost, 127.0.0.1, ::1); Streamable HTTP only (no SSE).
//   - a server that needs a credential (0.3.0, owner decision D6): the operator supplies their own, ONLY through an
//     environment variable (--bearer-env VAR, --header-env Name=VAR; there is no option that takes a value). It is sent only
//     to the exact proven URL (pinnedFetch scope 'exact'), never to OAuth metadata or to the unauthenticated probe; it is
//     never printed, written to --out or stored (every output path of --url goes through the exact-value redaction). The
//     proof is unchanged and is read on the credentialed session. A refused credential is exit 4, with no value shown.
//   - it shows control of what the server at that URL answers, not of the platform under it; it stops accidents and casual
//     misuse, not someone who changes this open-source code (D4).
//
// Limits, all enforced in code (test/selftest.test.js checks each one):
//   - with --stdio, a command that carries a non-local http(s) address (for example a proxy such as
//     `npx mcp-remote https://...`) is refused, so the stdio lane cannot be pointed at someone else's server by another route.
//     A remote server is tested only with --url, after the proof.
//   - --i-own-this-server is required on every run (a typed statement, never stored).
//   - dim 6 (calls tools that look like they change data) needs --allow-mutating; dim 7 (sends wrong-type, oversized and
//     missing input) needs --allow-fuzzing. Without the flag each is recorded NOT-TESTED, never as a pass.
//   - nothing is sent anywhere: the result is printed here and written to --out on this machine only.
//   - the score is "N of M checks passed" over checks that RAN, always with what did not run (see checkScore).
//   - the server is started with the SDK's minimal default environment plus one planted canary value, so your own
//     environment variables are not handed to it.
//   - time limits (0.1.1, from the 2026-10-19 field check, docs/selftest-field-check-2026-10-19.md): the connect limit
//     includes the first `npx`/`uvx` download, so it is 180 s by default (60 s before: 5 of 50 field runs stopped at 60 s, 4
//     of them with install output as their last lines; the slowest full run took 82 s). A whole run stops at --max-time
//     (600 s by default; one field run hung with no output until the 240 s outer limit).
//   - when the server cannot start, the last lines of its error output are printed as whole lines, bounded, with the canary
//     and secret-looking values hidden, plus a hint only for causes we reproduced or saw verbatim in the field check.
//   - through a proxy (0.1.2): a command that names a known stdio-to-HTTP proxy (KNOWN_PROXIES) or carries a local http(s)
//     address is treated as proxied, and checks 4 and 11 (and 5 and 10 when no local address is given) are N-A with their
//     reason, never a pass. 0.1.1 counted dim 4 as passed through `npx mcp-remote http://localhost:...` for a server that
//     returns its whole environment (the canary was in the proxy's environment, not the server's).
//   - in CI (0.4.0, test/selftest-sarif.test.js): --fail-on-finding exits 5 when a check needs attention (0 otherwise, as
//     before; 1-4 keep their meaning); --sarif writes SARIF 2.1.0 for GitHub code scanning (src/sarif.js), through the same
//     redaction as --out.
//   - API pre-check (0.5.0, owner 2026-10-26; src/api-rules.js, test/selftest-api-rules.test.js): after the tool list is read,
//     the acceptance rules we measured for Anthropic's, OpenAI's and Google's APIs (2026-10-25/26) are run on it OFFLINE (no
//     network, no model call) and printed per vendor. It is not a check: not in the score, not in SARIF, never exit 5.

import fs from 'node:fs';
import path from 'node:path';
import { createContext, openSession } from './src/session.js';
import { runAllDims } from './src/dims.js';
import { buildReport } from './src/report.js';
import {
  canonicalTarget, ProofStore, defaultStateDir, proofInInstructions, resolveTarget, pinnedFetch, classifyConnectFailure,
  httpStatusOf, PROOF_TTL_MS, LINE_PREFIX, ENV_NAME, checkHeaderName, credentialsFromEnv, secretForms, redactExact,
} from './src/remote-proof.js';
import { unauthenticatedProbeText } from './src/dims.js';
import { buildSarif, sarifAnchor } from './src/sarif.js';
import { checkApiRules, apiRuleLines, toApiTools } from './src/api-rules.js';

const USAGE = `usage: node selftest.mjs --i-own-this-server [--allow-mutating] [--allow-fuzzing] [--out report.json]
                         [--fail-on-finding] [--sarif report.sarif [--sarif-anchor <file>]]
                         [--connect-timeout <seconds>] [--max-time <seconds>] --stdio <command> [args...]
       node selftest.mjs --i-own-this-server [same options] [--new-proof] [--bearer-env VAR] [--header-env Name=VAR]...
                         --url <https://your.server/path>
  --stdio            start your server on this machine with this command line (everything after it)
  --url              your own Streamable HTTP server; tested only after it returns a one-time value in its instructions
                     (https, or http on this machine only; cannot be combined with --stdio)
  --new-proof        with --url: discard the pending value for this URL and make a new one
  --bearer-env VAR   with --url: send "Authorization: Bearer <value of the environment variable VAR>", to that URL only
  --header-env N=VAR with --url: send the header N with the value of the environment variable VAR (repeatable)
                     (a credential is read only from the environment, never from the command line; never shown or stored)
  --connect-timeout  seconds the server may take to start and answer, including a first npx/uvx download (default 180, 5-3600)
  --max-time         seconds after which the whole run stops, with no result (default 600, 10-86400, longer than --connect-timeout)
  --fail-on-finding  exit 5 when a check needs attention (VULNERABLE or FOUND), so a CI job fails; the result is printed as usual
  --sarif <path>     also write the result as SARIF 2.1.0 (for GitHub code scanning), on this machine only
  --sarif-anchor <f> the repository file SARIF results point at (default with --stdio: the first file in the command)
exit codes: 0 result printed · 1 could not start/connect, or --max-time · 2 refused arguments
            5 (--fail-on-finding) result printed, and at least one check needs attention
            3 (--url) proof value made: add it to your server's instructions, run again
            4 (--url) refused: proof not shown, or your server refused the credential you supplied`;
export const EXIT = { OK: 0, FAILED: 1, USAGE: 2, PROOF_ISSUED: 3, PROOF_REFUSED: 4, FINDINGS: 5 };
const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);
export const DEFAULT_CONNECT_S = 180;
export const DEFAULT_MAX_S = 600;

// Any http(s) address inside the command line must be this machine. Returns the first offending address, or null.
export function remoteAddressIn(argv) {
  for (const a of argv) {
    for (const m of String(a).matchAll(/\bhttps?:\/\/([^\s/'"?#]+)/gi)) {
      const host = m[1].replace(/^[^@]*@/, '').replace(/:\d+$/, '').toLowerCase();
      if (!LOOPBACK.has(host)) return m[0];
    }
  }
  return null;
}

// The first local http(s) address in the command line, or null (the only kind parseArgs lets through).
export function loopbackAddressIn(argv) {
  for (const a of argv) {
    for (const m of String(a).matchAll(/\bhttps?:\/\/([^\s/'"?#]+)/gi)) {
      const host = m[1].replace(/^[^@]*@/, '').replace(/:\d+$/, '').toLowerCase();
      if (LOOPBACK.has(host)) return m[0];
    }
  }
  return null;
}

// Programs that are themselves a stdio MCP server relaying to an HTTP (or SSE) MCP server. Through one of them, the process
// this tool starts is the proxy, not your server (see localOnlyNA in src/dims.js). Each name was read on its registry page
// on 2026-10-19 (npm view / pypi.org JSON): npm mcp-remote ("Remote proxy for Model Context Protocol, allowing local-only
// clients to connect to remote servers"), npm supergateway ("Run MCP stdio servers over SSE, Streamable HTTP or visa
// versa"), PyPI mcp-proxy ("proxies requests to a remote MCP server over streamable HTTP or SSE"; the npm package of the
// same name only serves a stdio server over HTTP, the other direction), npm @pyroprompts/mcp-stdio-to-streamable-http-adapter
// ("runs as stdio, wrapping a Streamable HTTP server"; it takes its URL from an environment variable, so no address shows).
// An unknown proxy, or a wrapper script around one, is not detected: the README and DISCLOSURE say so.
export const KNOWN_PROXIES = ['mcp-remote', 'supergateway', 'mcp-proxy', '@pyroprompts/mcp-stdio-to-streamable-http-adapter', 'mcp-stdio-to-streamable-http-adapter'];

// The known proxy named in the command line, or null. It looks at the command and at every argument, as a whole word and
// as a package spec or path: `mcp-remote`, `mcp-remote@0.14.3`, `--package=mcp-remote`, `--from mcp-proxy`,
// `mcp-proxy==0.13.0`, `C:\...\node_modules\.bin\mcp-remote.cmd`, `node_modules/mcp-remote/dist/proxy.js`.
export function knownProxyIn(argv) {
  const plain = s => s.toLowerCase()
    .replace(/^--?[a-z-]+=/, '') // --package=x
    .replace(/(?<=.)@[^@/]*$/, '') // name@version (not the @ of a scope)
    .replace(/(?:==|>=|<=|~=|!=|<|>|\[).*$/, '') // pip specs and extras
    .replace(/\.(?:cmd|exe|bat|ps1|js|mjs|cjs)$/, '');
  for (const a of argv) {
    const parts = String(a).split(/[\\/]/);
    for (let i = 0; i < parts.length; i++) {
      const one = plain(parts[i]);
      const scoped = i + 1 < parts.length && parts[i].startsWith('@') ? plain(`${parts[i]}/${parts[i + 1]}`) : null;
      for (const c of [scoped, one]) if (c && KNOWN_PROXIES.includes(c)) return c;
    }
  }
  return null;
}

// Is the server reached through a proxy? A known proxy named in the command, or a local http(s) address in it (a stdio
// server that merely takes a local URL as a setting is caught too: that only switches checks off, it never adds a pass).
export function proxyIn(argv) {
  const name = knownProxyIn(argv);
  const address = loopbackAddressIn(argv);
  return name || address ? { name, address } : null;
}

// `env` (default process.env): where --bearer-env / --header-env read their values. Error messages name a variable, never
// a value.
export function parseArgs(argv, env = process.env) {
  const o = { own: false, mutating: false, fuzzing: false, out: null, command: null, args: [], url: null, newProof: false, target: null, connectS: DEFAULT_CONNECT_S, maxS: DEFAULT_MAX_S, credentials: null, failOnFinding: false, sarif: null, sarifAnchor: null, anchor: null };
  const credSpecs = [];
  // the argument must be the NAME of an environment variable; when it is not one it may be the credential itself, so it is
  // never echoed back
  const envName = (flag, v) => {
    if (!ENV_NAME.test(v ?? '')) throw new Error(`${flag} needs the NAME of an environment variable that holds the value (letters, digits and _), not the value itself; the argument given is not shown`);
    return v;
  };
  const seconds = (flag, v, min, max) => {
    if (!/^\d+$/.test(v ?? '') || Number(v) < min || Number(v) > max) throw new Error(`${flag} needs whole seconds from ${min} to ${max}`);
    return Number(v);
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--i-own-this-server') o.own = true;
    else if (a === '--allow-mutating') o.mutating = true;
    else if (a === '--allow-fuzzing') o.fuzzing = true;
    else if (a === '--out') { o.out = argv[++i]; if (!o.out) throw new Error('--out needs a file path'); }
    else if (a === '--fail-on-finding') o.failOnFinding = true;
    else if (a === '--sarif') { o.sarif = argv[++i]; if (!o.sarif || o.sarif.startsWith('--')) throw new Error('--sarif needs a file path'); }
    else if (a === '--sarif-anchor') { o.sarifAnchor = argv[++i]; if (!o.sarifAnchor || o.sarifAnchor.startsWith('--')) throw new Error('--sarif-anchor needs a file path'); }
    else if (a === '--connect-timeout') o.connectS = seconds(a, argv[++i], 5, 3600);
    else if (a === '--max-time') o.maxS = seconds(a, argv[++i], 10, 86400);
    else if (a === '--url') { o.url = argv[++i]; if (!o.url || o.url.startsWith('--')) throw new Error('--url needs the address of your MCP server'); }
    else if (a === '--new-proof') o.newProof = true;
    else if (a === '--bearer-env') {
      if (credSpecs.some(c => c.bearer)) throw new Error('--bearer-env is given twice');
      credSpecs.push({ header: 'Authorization', variable: envName(a, argv[++i]), bearer: true });
    } else if (a === '--header-env') {
      const v = argv[++i];
      const eq = typeof v === 'string' ? v.indexOf('=') : -1;
      if (eq <= 0) throw new Error('--header-env needs Header-Name=VARIABLE (the NAME of an environment variable that holds the value); the argument given is not shown');
      const header = v.slice(0, eq);
      try { checkHeaderName(header); } catch (e) { throw new Error(`--header-env: ${e.message}`); }
      credSpecs.push({ header, variable: envName('--header-env', v.slice(eq + 1)), bearer: false });
    }
    else if (a === '--stdio') {
      o.command = argv[i + 1];
      o.args = argv.slice(i + 2);
      if (!o.command) throw new Error('--stdio needs a command');
      break;
    } else throw new Error(`unknown argument: ${a}`);
  }
  if (o.url && o.command) throw new Error('--url and --stdio cannot be combined: test either a server this tool starts (--stdio) or your own server at a URL (--url)');
  if (!o.command && !o.url) throw new Error('--stdio <command> or --url <url> is required');
  if (!o.own) throw new Error('--i-own-this-server is required: this tool is only for a server you run and are responsible for');
  if (o.newProof && !o.url) throw new Error('--new-proof is used only with --url');
  if (o.sarifAnchor && !o.sarif) throw new Error('--sarif-anchor is used only with --sarif');
  if (o.sarif) o.anchor = sarifAnchor({ anchor: o.sarifAnchor, argv: o.url ? [] : [o.command, ...o.args] });
  if (credSpecs.length && !o.url) throw new Error('--bearer-env and --header-env are used only with --url: a server this tool starts with --stdio is given no headers');
  if (o.url) {
    try { o.target = canonicalTarget(o.url); } catch (e) { throw new Error(`refused: ${e.message}`); }
  } else {
    const remote = remoteAddressIn([o.command, ...o.args]);
    if (remote) throw new Error(`refused: the command carries a non-local address (${remote}). With --stdio this tool tests only a server running on this machine; a server at a URL is tested with --url, after you prove you control it`);
  }
  // the connect limit must end first, so a slow start is always reported as a start problem with the server's own output
  if (o.maxS <= o.connectS) throw new Error(`--max-time (${o.maxS}) must be longer than --connect-timeout (${o.connectS})`);
  if (credSpecs.length) {
    try { o.credentials = credentialsFromEnv(credSpecs, env).credentials; } catch (e) { throw new Error(`refused: ${e.message}`); }
  }
  return o;
}

// Values that must never be printed back: the planted canary and anything shaped like a secret in the server's own output.
// It errs toward hiding: a hidden harmless value costs nothing, a printed key is a leak.
const NAMED_SECRET = /\b([A-Za-z0-9_.-]*(?:key|token|secret|passw(?:or)?d|pwd|credential|authorization|cookie|session)[A-Za-z0-9_.-]*)(["']?\s*[=:]\s*)(?!\[redacted\])(?!(?:Bearer|Basic)\b)(?:"[^"]*"|'[^']*'|\S+)/gi;
// Shapes of well-known key formats, hidden wherever they appear.
const SECRET_SHAPES = /\b(?:sk-[A-Za-z0-9_-]{16,}|sk_(?:live|test)_[A-Za-z0-9]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|xox[abprs]-[A-Za-z0-9-]{10,}|glpat-[A-Za-z0-9_-]{20,}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})/g;
export function redact(text, secrets = []) {
  let t = String(text ?? '');
  for (const v of secrets) if (v) t = t.split(v).join('[redacted]');
  return t
    .replace(/\b(Bearer|Basic)\s+[A-Za-z0-9._~+\/=-]{6,}/gi, '$1 [redacted]')
    .replace(NAMED_SECRET, '$1$2[redacted]')
    .replace(/\b([a-z][a-z0-9+.-]*:\/\/[^\s:@\/]+):[^\s@\/]+@/gi, '$1:[redacted]@') // password inside a URL
    .replace(SECRET_SHAPES, '[redacted]');
}

// The last lines the server printed on its error output: whole lines, at most n of them, each at most `width` characters.
// (0.1.0 printed the last 600 characters, cut mid-line, and lost the end when the output passed 64 KB.)
export function lastLines(text, n = 20, width = 300) {
  return String(text ?? '').replace(/\r/g, '').split('\n').map(l => l.trimEnd()).filter(Boolean).slice(-n)
    .map(l => (l.length > width ? `${l.slice(0, width)}...` : l));
}

// Hints, each backed by evidence (test/selftest.test.js holds the strings): either reproduced on this machine with a real
// tool and our own fixture, or the exact text seen in the 2026-10-19 field check. A cause with neither has no hint. A hint
// is a likely reading of the server's own output, not a diagnosis; that output is always printed above it.
export function startHints(message, stderrTail, { connectS = DEFAULT_CONNECT_S, argv = [] } = {}) {
  const t = String(stderrTail ?? '');
  // our own limit ("connect timeout after N ms") or the SDK's request limit ("Request timed out"), both at --connect-timeout
  const timedOut = /connect timeout after|Request timed out/i.test(String(message ?? ''));
  const h = [];
  // reproduced: our py-fastmcp.py fixture under `mcp>=2`; seen verbatim 3 times in the field check
  if (/No module named 'mcp\.server\.fastmcp'/.test(t))
    h.push("Python: the code imports FastMCP, which the `mcp` package renamed to MCPServer in 2.x. Pin `mcp<2` in the server's dependencies, or move to `from mcp.server.mcpserver import MCPServer`.");
  // seen verbatim in the field check (npm 10) and reproduced as a warning (npm 11) with our own package declaring a Node it cannot have.
  // npm only warns: the field check could not prove it was the cause, so the hint says "may".
  const engine = /EBADENGINE[\s\S]*?required: \{ node: '([^']+)' \}[\s\S]*?current: \{ node: '([^']+)'/i.exec(t);
  if (engine) h.push(`Node: npm warned that a package declares Node ${engine[1]}, and this machine has ${engine[2]}. That may be why it did not start: try a Node version that matches.`);
  // seen verbatim in the field check (npm 10) and reproduced with our own package declaring os ["darwin"] (npm 11)
  if (/EBADPLATFORM/.test(t)) h.push('npm EBADPLATFORM: a package declares that it does not support this operating system, so npm did not install it.');
  // both reproduced with our own local Python packages through uvx, and both seen verbatim in the field check
  const exe = /An executable named `([^`]+)` is not provided by package `([^`]+)`/.exec(t);
  if (exe) h.push(`uvx: package \`${exe[2]}\` has no command named \`${exe[1]}\`; uvx listed the commands it has above. Run \`uvx --from <the package> <one of those commands>\`.`);
  else if (/does not provide any executables/.test(t)) h.push('uvx: this package declares no command to run. Start it the way its own instructions say (for example with `python -m <module>`).');
  // reproduced on Windows with a command name that does not exist
  if (/is not recognized as an internal or external command/.test(t)) h.push('The command was not found: check its name and that it is on your PATH.');
  // reproduced with our hang-init fixture; 5 of 50 field runs stopped at the old 60 s limit
  if (timedOut) h.push(`It did not answer within ${connectS} s, and that time includes a first npx/uvx download. Run the server's command once by itself so the download finishes, then run this again, or pass a longer --connect-timeout.`);
  // reproduced with our own uv project: `uv run server.py` started from the project folder fails here (the server starts in
  // a throwaway folder, so uv does not find the project and falls back to whatever Python it finds); `--directory .` works
  const cmd = path.basename(String(argv[0] ?? '')).toLowerCase();
  if ((cmd === 'uv' || cmd === 'uv.exe') && argv[1] === 'run' && !argv.some(a => /^--(directory|project|no-project)(=|$)/.test(String(a))))
    h.push('uv run: this tool starts your server in a temporary folder, so `uv run` does not find your project there. Name the project folder: `uv run --directory <your project folder> ...` (for example `--directory .`).');
  // reproduced with our crash-start fixture (Node) and a Python import of a module that is not installed
  if (!h.length && /ERR_MODULE_NOT_FOUND|Cannot find module|Cannot find package|ModuleNotFoundError: No module named/.test(t)) h.push('A module the server needs is missing: check that its dependencies are installed.');
  return h;
}

const lastLabel = n => (n === 1 ? 'last line' : `last ${n} lines`);

export function startFailureText(message, stderrTail, opts = {}) {
  const tail = redact(stderrTail, opts.secrets);
  const lines = lastLines(tail);
  const out = [`could not start or connect to your server: ${redact(String(message ?? '').slice(0, 400), opts.secrets)}`];
  out.push(lines.length ? `${lastLabel(lines.length)} your server printed on its error output (values that look like secrets are hidden):\n${lines.map(l => `  | ${l}`).join('\n')}` : 'your server printed nothing on its error output.');
  for (const h of startHints(message, tail, opts)) out.push(`hint: ${h}`);
  return `${out.join('\n')}\n`;
}

// The engine starts the server inside a throwaway probe directory (that is what dim 10 measures against), so a path the
// user typed relative to their own folder (`node ./dist/server.js`) would not be found. An argument that names an existing
// file or folder relative to where the command was run is made absolute; anything else is left exactly as typed.
export function absolutizeExisting(argv, cwd = process.cwd()) {
  return argv.map((a, i) => {
    if (typeof a !== 'string' || a === '' || a.startsWith('-') || /^[a-z][a-z0-9+.-]*:/i.test(a) || path.isAbsolute(a)) return a;
    if (i === 0 && !/[\\/]/.test(a)) return a; // a bare command name (node, npx, python) comes from PATH
    const abs = path.resolve(cwd, a);
    return fs.existsSync(abs) ? abs : a;
  });
}

// The permit function runAllDims asks for each tool-calling check. Safe-shaped checks (dims 3, 5, 10) run by default.
export function makePermit({ mutating, fuzzing }) {
  const on = recordId => ({ allowed: true, recordId, reason: null });
  const off = flag => ({ allowed: false, recordId: null, reason: `not-enabled: pass ${flag} to run this check` });
  return check => {
    if (check === 'dim6') return mutating ? on('self-test') : off('--allow-mutating');
    if (check === 'dim7') return fuzzing ? on('self-test') : off('--allow-fuzzing');
    if (['dim3', 'dim5', 'dim10'].includes(check)) return on('self-test');
    return off('(unknown check)');
  };
}

const SHOWN = new Set(['VULNERABLE', 'FOUND']);

// The self-test score (owner decision 2026-10-14; the CLI only, never the site, where most checks cannot run).
// It counts ONLY checks that ran with real evidence (score.js buckets, including its dependent-evidence rule), so a check
// that did not run can never raise it, and what did not run is always printed next to it. Not counted:
//   - dims 1 and 3: the tool list and plain tool calls are facts, not pass/fail checks;
//   - a check the server gave nothing to exercise ("could not be exercised"): not applicable, never a pass.
// VULNERABLE and FOUND both count as "needs attention" (FOUND is a heuristic match to review, not a proven problem).
const NOT_A_CHECK = new Set([1, 3]);
// `observed` are the raw dims (they carry the note; the assessment's dims do not).
// A check that cannot run because the server is not the process started here (through a proxy, or over HTTP with --url;
// src/dims.js localOnlyNA) is not applicable and never counted, like any N-A, but it is listed by name with its reason,
// because the same check WOULD apply to the server run directly. Proxy rows go to notThroughProxy, HTTP rows to notOverHttp.
export function checkScore(assessment, observed) {
  const noteOf = new Map((observed ?? []).map(d => [d.dimension, d.note ?? '']));
  const localOnly = new Map((observed ?? []).filter(d => d.status === 'N-A' && d.evidence?.localOnly).map(d => [d.dimension, d]));
  const dims = assessment.dims.filter(d => !NOT_A_CHECK.has(d.dimension));
  const notExercised = d => d.bucket === 'EVIDENCE' && d.status === 'NOT-OBSERVED' && /could not be exercised/.test(noteOf.get(d.dimension) ?? '');
  const ran = dims.filter(d => d.bucket === 'EVIDENCE' && !notExercised(d));
  const attention = ran.filter(d => SHOWN.has(d.status));
  const notRun = dims.filter(d => d.bucket === 'BLOCKED');
  const passed = ran.length - attention.length;
  const notHere = dims.filter(d => d.bucket === 'INAPPLICABLE' && localOnly.has(d.dimension))
    .map(d => ({ dimension: d.dimension, name: d.name, reason: localOnly.get(d.dimension).evidence.reason, via: localOnly.get(d.dimension).evidence.localOnly }));
  const strip = ({ via, ...d }) => d;
  return {
    passed, ran: ran.length, applicable: ran.length + notRun.length,
    percent: ran.length ? Math.round((100 * passed) / ran.length) : null,
    needsAttention: attention.map(d => ({ dimension: d.dimension, name: d.name, status: d.status })),
    // a check switched off by a missing flag says which flag (the gate's generic wording is about third-party permission)
    notRun: notRun.map(d => {
      const flag = /not-enabled: pass (--[a-z-]+)/.exec(d.reason ?? '')?.[1];
      return { dimension: d.dimension, name: d.name, reason: flag ? `off by default: pass ${flag} to run it` : d.reason };
    }),
    notThroughProxy: notHere.filter(d => d.via !== 'http').map(strip),
    ...(notHere.some(d => d.via === 'http') ? { notOverHttp: notHere.filter(d => d.via === 'http').map(strip) } : {}),
    notApplicable: dims.length - ran.length - notRun.length - notHere.length,
    complete: notRun.length === 0,
  };
}

export function scoreLines(s) {
  const proxyNA = s.notThroughProxy ?? [];
  const httpNA = s.notOverHttp ?? [];
  const these = n => (n === 1 ? 'this check' : 'these checks');
  const proxyLines = [
    ...(proxyNA.length
      ? [...proxyNA.map(d => `Not applicable through the proxy, not counted: ${d.dimension} ${d.name}`),
        `To run ${these(proxyNA.length)}, start your server directly with --stdio, if it can run in stdio mode.`]
      : []),
    ...(httpNA.length
      ? [...httpNA.map(d => `Not applicable over HTTP, not counted: ${d.dimension} ${d.name}`),
        `To run ${these(httpNA.length)}, start your server on this machine with --stdio, if it can run in stdio mode.`]
      : []),
  ];
  if (!s.ran) return ['Score: none - no check could run with evidence, so there is nothing to score.', ...proxyLines];
  const lines = [`Score: ${s.passed} of ${s.ran} checks passed (${s.percent}%)${s.complete ? '' : ` - PARTIAL: ${s.notRun.length} of ${s.applicable} applicable checks did not run`}`];
  if (s.needsAttention.length) lines.push(`Needs attention: ${s.needsAttention.map(d => `${d.dimension} ${d.name} (${d.status})`).join(', ')}`);
  for (const d of s.notRun) lines.push(`Not run, not counted: ${d.dimension} ${d.name} - ${d.reason}`);
  lines.push(...proxyLines);
  lines.push(`Not applicable to this server: ${s.notApplicable} checks.`);
  return lines;
}

export function proxyLine(proxy) {
  const what = proxy.name ? `the command runs ${proxy.name}${proxy.address ? `, with the local address ${proxy.address}` : ''}` : `the command carries the local address ${proxy.address}`;
  return `through a proxy: ${what}, so the process this tool starts may not be your server. Checks that need your server to be that process are not applicable (listed below). A proxy or wrapper script not named here is not detected.`;
}

// What every SARIF message passes through: the exact-value scrub of the operator's credential FIRST, then the pattern
// redaction (canary, secret shapes). The other order lets a pattern hide only part of a credential (`Bearer abcdefgh!ijkl`
// -> `Bearer [redacted]!ijkl`), and the exact scrub then no longer finds the whole value (independent review, 2026-10-19).
export const sarifRedactor = (scrub, canary) => s => redact(scrub(s), [canary]);

// The published package's version (package.json next to this file in protocolprobe-selftest), or null when run from the
// engine folder, whose package.json is not the published one.
function packageVersion() {
  try {
    const p = JSON.parse(fs.readFileSync(new URL('./package.json', import.meta.url), 'utf8'));
    return p.name === 'protocolprobe-selftest' ? p.version : null;
  } catch { return null; }
}

// Run the checks on an open session and print the result (shared by --stdio and --url). Returns the exit code.
// `overall` resolves to 'max-time' when --max-time is reached: the checks still running are abandoned, the server is
// stopped (stdio) or the connection closed (URL), the message is printed, and nothing else is printed or written.
// `scrub` (--url with a credential): applied to the --out file as a whole (out and err are already scrubbed by the caller).
// `facts(dims)`: extra lines printed under the table (the unauthenticated-probe fact when a credential was supplied).
async function runChecks({ session, target, ctx, o, overall, out, err, heading, observedTarget, startedAt, t0, stopped, scrub = s => s, facts = () => [] }) {
  const permit = makePermit(o);
  const checks = runAllDims(session, target, ctx, { readOnly: false, permit, keepToolList: true });
  checks.catch(() => {}); // abandoned after max-time: its later failure (the server is gone) must not surface
  const first = await Promise.race([checks, overall]);
  if (first === 'max-time') {
    const tail = lastLines(redact(session.stderrTail, [ctx.canary]), 10);
    await session.close();
    err(`stopped: the run took longer than --max-time ${o.maxS} s. ${stopped} and no result was written. `
      + 'Each tool call may take up to 20 s, so a server with many slow tools can need a longer --max-time.\n');
    if (tail.length) err(`${lastLabel(tail.length)} your server printed on its error output (values that look like secrets are hidden):\n${tail.map(l => `  | ${l}`).join('\n')}\n`);
    return EXIT.FAILED;
  }
  const { inventory, dims, toolList, toolListError } = first;
  const observation = { engine: 'mcp-runtime-engine@0.1.0', sdk: '@modelcontextprotocol/sdk@1.32.0', target: observedTarget, startedAt, durationMs: Date.now() - t0, outcome: 'tested', mode: 'self-test', inventory, dims };
  const report = buildReport([observation], { mode: 'self-test', environment: 'local', startedAt });

  for (const l of heading) out(`${l}\n`);
  out(`tools ${inventory.tools} · resources ${inventory.resources} · prompts ${inventory.prompts}\n\n`);
  // a check made N-A because the server is not the process started here shows its reason on its own line
  for (const d of dims) {
    const note = d.note ?? (d.evidence?.localOnly ? d.evidence.reason : null);
    out(`${String(d.dimension).padStart(2)}  ${d.name.padEnd(28)} ${d.status}${note ? `  - ${note}` : ''}\n`);
  }
  const extra = facts(dims);
  if (extra.length) out(`\n${extra.join('\n')}\n`);
  const score = checkScore(report.results[0].assessment, dims);
  report.results[0].selftestScore = score;
  out(`\n${scoreLines(score).join('\n')}\n`);
  out('The score counts only checks that ran. A check that did not run says nothing about that behaviour. This is not a certificate of safety.\n');
  // offline, after the list was read; never part of the score, the SARIF file or the exit code
  const apiRules = toolListError ? null : checkApiRules(toApiTools(toolList));
  report.results[0].apiRulesPrecheck = apiRules ?? { notRun: 'the tool list could not be read' };
  out(`\n${apiRuleLines(apiRules, { listed: !!apiRules }).join('\n')}\n`);
  if (o.out) {
    fs.mkdirSync(path.dirname(path.resolve(o.out)), { recursive: true });
    fs.writeFileSync(o.out, scrub(JSON.stringify(report, null, 2)));
    out(`written to ${o.out} (this machine only)\n`);
  }
  if (o.sarif) {
    const sarif = buildSarif({ dims, score, anchor: o.anchor, version: packageVersion(), redact: sarifRedactor(scrub, ctx.canary) });
    fs.mkdirSync(path.dirname(path.resolve(o.sarif)), { recursive: true });
    fs.writeFileSync(o.sarif, scrub(JSON.stringify(sarif, null, 2)));
    out(`SARIF written to ${o.sarif} (this machine only)${o.anchor.uri ? `, results point at ${o.anchor.uri}` : `; ${o.anchor.none}`}\n`);
  }
  if (o.failOnFinding && score.needsAttention.length) {
    const n = score.needsAttention.length;
    out(`exit code 5 (--fail-on-finding): ${n} check${n === 1 ? ' needs' : 's need'} attention\n`);
    return EXIT.FINDINGS;
  }
  return EXIT.OK;
}

// `deps` exists for the tests only (no command-line option reaches it): stateDir, now, resolveAddrs, ca, env.
export async function main(argv, { out = s => process.stdout.write(s), err = s => process.stderr.write(s), deps = {} } = {}) {
  let o;
  try { o = parseArgs(argv, deps.env ?? process.env); } catch (e) { err(`${e.message}\n${USAGE}\n`); return EXIT.USAGE; }
  if (o.url) return mainUrl(o, { out, err, deps });

  const [command, ...cmdArgs] = absolutizeExisting([o.command, ...o.args]);
  // through a proxy, the checks that need the server to be the process started here are N-A (src/dims.js localOnlyNA)
  const proxy = proxyIn([o.command, ...o.args]);
  const target = { kind: 'stdio', command, args: cmdArgs, env: {}, server: { name: 'self-test' }, ...(proxy ? { proxy } : {}) };
  const startedAt = new Date().toISOString();
  const t0 = Date.now();
  const ctx = await createContext();
  let session;
  // Overall limit, counted from the start (so it includes the connect time, which always ends first: --max-time must be
  // longer).
  let timer;
  const overall = new Promise(res => { timer = setTimeout(() => res('max-time'), o.maxS * 1000); });
  try {
    try { session = await openSession(target, ctx, { connectTimeoutMs: o.connectS * 1000 }); }
    catch (e) { err(startFailureText(e?.message ?? e, e?.stderrTail ?? e?.stderr, { connectS: o.connectS, secrets: [ctx.canary], argv: [o.command, ...o.args] })); return EXIT.FAILED; }
    return await runChecks({
      session, target, ctx, o, overall, out, err, t0, startedAt, stopped: 'Your server was stopped',
      heading: [`self-test of: ${[o.command, ...o.args].join(' ')}`, ...(proxy ? [proxyLine(proxy)] : [])],
      observedTarget: { server: target.server, kind: 'stdio', command: o.command, args: o.args, ...(proxy ? { proxy } : {}) },
    });
  } finally {
    clearTimeout(timer);
    await session?.close();
    await ctx.dispose();
  }
}

const utc = ms => `${new Date(ms).toISOString().slice(0, 16).replace('T', ' ')} UTC`;

// What to print when a proof is refused (exit 4). Never the server's response body: only what it means.
const REFUSALS = {
  missing: `its instructions do not carry a ${LINE_PREFIX} line. Add the line you were given, on a line of its own, deploy, and run the same command again`,
  'not-own-line': `its instructions mention ${LINE_PREFIX} but not on a line of its own. Put the line you were given on a line by itself`,
  'wrong-value': `its instructions carry a ${LINE_PREFIX} line with a different value (an older one?). Use the value from the last run that printed one, or run with --new-proof for a fresh value`,
};

function redirectText(e) {
  for (let x = e, i = 0; x && i < 5; x = x.cause, i++) if (x.proofReason === 'redirect') return x.message;
  return /the server answered 3\d\d redirect[^.)]*/.exec(String(e?.message))?.[0] ?? 'the server answered with a redirect';
}

// --url: the proof of control, then the same checks as --stdio over the SAME connection (src/remote-proof.js).
async function mainUrl(o, { out: rawOut, err: rawErr, deps }) {
  // Every line this run prints, and the --out file, pass through the exact-value redaction of the operator's credential
  // (as is, JSON-escaped, URL-encoded): a server may echo the header back in its instructions, a tool result or an error.
  const forms = secretForms(o.credentials ? o.credentials.secrets() : []);
  const scrub = s => redactExact(s, forms);
  const out = s => rawOut(scrub(s));
  const err = s => rawErr(scrub(s));
  const canon = o.target;
  const cred = o.credentials; // null, or names + values (src/remote-proof.js Credentials: shows names only)
  const credNames = cred ? cred.names.map(n => n.header) : [];
  const store = new ProofStore(deps.stateDir ?? defaultStateDir(), { now: deps.now ?? (() => Date.now()) });
  const refuse = text => { err(`refused, no test ran: ${text}\n`); return EXIT.PROOF_REFUSED; };
  const cannotWrite = e => { err(`could not write ${store.file}: ${e.code ?? e.message}\n`); return EXIT.FAILED; };
  try { if (o.newProof) store.remove(canon.key); } catch (e) { return cannotWrite(e); }
  const found = store.find(canon.key);
  if (store.warning) err(`note: ${store.warning}\n`);

  if (found.state === 'expired') {
    try { store.remove(canon.key); } catch (e) { return cannotWrite(e); }
    return refuse(`the proof value for ${canon.href} expired at ${utc(Date.parse(found.record.expiresAt))} (a value is valid for ${PROOF_TTL_MS / 60000} minutes). Run the same command again for a new value.`);
  }
  if (found.state === 'none') {
    let issued;
    try { issued = store.issue(canon.key); } catch (e) { return cannotWrite(e); }
    out([
      `proof needed: before this tool tests ${canon.href}, show that you control the server at that exact URL.`,
      '  1. Add this line, on a line of its own, to your MCP server\'s instructions (the `instructions` text it returns at initialize):',
      '',
      `       ${issued.line}`,
      '',
      `  2. Deploy that change, then run the same command again within ${PROOF_TTL_MS / 60000} minutes (before ${utc(Date.parse(issued.record.expiresAt))}).`,
      'The value works once, and only for this exact URL (scheme, host, port, path and query). Remove the line after the test.',
      `Nothing was sent: this run made no connection. Only a hash of the value is kept, on this machine (${store.file}).`,
      '',
    ].join('\n'));
    return EXIT.PROOF_ISSUED;
  }

  // A pending value: resolve the host once and pin every connection of this run to those addresses.
  let addresses;
  try { addresses = await resolveTarget(canon, deps.resolveAddrs); } catch (e) {
    if (e.proofReason === 'http-not-local') return refuse(e.message);
    err(`could not connect: ${e.message}. No test ran.\n`);
    return EXIT.FAILED;
  }
  // the credential goes into the session fetch only (exact URL); the metadata fetch and the unauthenticated probe get none
  const sessionFetch = pinnedFetch({ canon, addresses, scope: 'exact', ca: deps.ca, credentials: cred });
  const discoveryFetch = pinnedFetch({ canon, addresses, scope: 'origin', ca: deps.ca });
  const target = { kind: 'http', url: canon.href, headers: {}, transportType: 'streamable-http', server: { name: 'self-test' }, ...(cred ? { credentialHeaders: credNames } : {}) };
  const startedAt = new Date().toISOString();
  const t0 = Date.now();
  const ctx = await createContext();
  let session;
  let timer;
  const overall = new Promise(res => { timer = setTimeout(() => res('max-time'), o.maxS * 1000); });
  try {
    try { session = await openSession(target, ctx, { connectTimeoutMs: o.connectS * 1000, fetch: sessionFetch, discoveryFetch }); } catch (e) {
      const kind = classifyConnectFailure(e);
      if (kind === 'redirect') return refuse(`${canon.href}: ${redirectText(e)}. Redirects are not followed, so the test can only run against the exact URL you proved. Run the command with the URL your server really answers on.`);
      const said = httpStatusOf(e) ? `HTTP ${httpStatusOf(e)}` : 'the server said so at initialize';
      if (kind === 'auth' && cred) return refuse(`your server refused the credential you supplied (${said}; sent as ${credNames.join(', ')} to ${canon.href}). Check that the environment variable holds a valid credential for this server; its value is not shown.`);
      if (kind === 'auth') return refuse(`${canon.href} needs a credential (${said}). Supply your own with --bearer-env <VARIABLE> or --header-env <Header-Name>=<VARIABLE>: the value is read from that environment variable and sent only to this URL.`);
      const status = httpStatusOf(e);
      // the response body is never printed: an HTTP error shows its status only
      const why = status
        ? `the server answered HTTP ${status}${status === 404 || status === 405 ? ' (this version speaks Streamable HTTP only, not the older SSE transport; check the path)' : ''}`
        : redact(String(e?.message ?? e).slice(0, 300), [ctx.canary, ...forms]);
      err(`could not connect to ${canon.href}: ${why}. No test ran.\n`);
      return EXIT.FAILED;
    }
    const verdict = proofInInstructions(session.client.getInstructions(), found.record);
    if (!verdict.ok) return refuse(`${canon.href} answered, but ${REFUSALS[verdict.reason]}.`);
    store.remove(canon.key); // single use: spent before any check runs, so a crash mid-test cannot leave it reusable
    return await runChecks({
      session, target, ctx, o, overall, out, err, t0, startedAt, stopped: 'The connection was closed', scrub,
      heading: [
        `self-test of: ${canon.href}`,
        `proof: ${canon.href} returned this run's one-time value in its instructions at ${utc(Date.now())}, on the connection used for the checks below (address ${addresses.join(', ')}, no redirect). The value is now used up; you can remove the line.`,
        ...(cred ? [`credential: ${cred.names.map(n => `${n.header} (from the environment variable ${n.variable})`).join(', ')} was sent with every request of this session, to ${canon.href} only; not to OAuth metadata and not to the probe without credentials. Its value is not printed, written or stored.`] : []),
        'This shows you control what the server at this URL answers. It is not a statement that the server is safe.',
      ],
      facts: dims => {
        if (!cred) return [];
        const d14 = dims.find(d => d.dimension === 14);
        if (!d14?.evidence || !('unauthenticatedConnect' in d14.evidence)) return ['Without your credential: not checked (the probe without credentials did not run).'];
        return [`Without your credential: ${unauthenticatedProbeText(d14.evidence.unauthenticatedConnect, d14.evidence.challenge)}.`];
      },
      observedTarget: { server: target.server, kind: 'http', url: canon.href, transportType: 'streamable-http', proof: { method: 'mcp-instructions', addresses }, ...(cred ? { credentials: cred.toJSON() } : {}) },
    });
  } finally {
    clearTimeout(timer);
    await session?.close();
    await ctx.dispose();
    sessionFetch.close();
    discoveryFetch.close();
  }
}

import { fileURLToPath } from 'node:url';
// Started as a command: compare real paths, because npm installs a bin as a symlink (argv[1] is the link, import.meta.url
// the real file) and a plain comparison would make the command silently do nothing.
const real = p => { try { return fs.realpathSync(p); } catch { return path.resolve(p); } };
if (process.argv[1] && real(process.argv[1]) === real(fileURLToPath(import.meta.url))) {
  main(process.argv.slice(2)).then(code => process.exit(code));
}
