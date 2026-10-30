// Proof of control for a remote self-test (protocolprobe-selftest 0.2.0, phase 1 of docs/design/domain-proof-assessment.md).
//
// The operator may test their OWN Streamable HTTP MCP server by URL only after that exact URL has returned a one-time value
// in its MCP `instructions` (the initialize result). Owner decisions D1-D7, D10 (2026-10-19): the CLI on the operator's
// machine only, method (c) only (no DNS, no well-known file), dim 16 stays off. 0.3.0 (D6): the operator may supply their
// own credential from an environment variable, sent only to the exact proven URL (Credentials and pinnedFetch below).
//
// Binding rules, each enforced here or in selftest.mjs and each tested (test/selftest-remote.test.js):
//   1. exact URL: the value is bound to the canonical URL (scheme, lower-case host, explicit port, path AND query); a pending
//      value is looked up by that key only, and its stored hash includes the key;
//   2. fresh: the value expires PROOF_TTL_MS after it was issued;
//   3. single use: after a successful proof the value is deleted, before any check runs;
//   4. no redirect, of any kind: every 3xx answer is an error, never followed (the SDK 1.32 follows same-origin redirects by
//      default; with this fetch it never sees one);
//   5. same connection: the value is read from the initialize of the session that then runs the checks, and every request of
//      that session must be for the exact proven URL;
//   6. pinned address: the host is resolved ONCE, before the first request; every connection of the run (the session and the
//      OAuth metadata reads of dims 14-18) goes to those addresses, so a DNS change during the run is not followed;
//   7. http only for this machine: http is accepted for localhost / 127.0.0.1 / ::1, and then every resolved address must be
//      a loopback address. https is accepted for any host and its certificate is checked against the host NAME as usual.
// It shows control of what the server at that URL answers, not of the platform under it, and it is an accident and casual
// misuse barrier, not enforcement: this code is open source and can be changed (DISCLOSURE, owner decision D4).
//
// Stored on this machine (stateDir): for each pending URL only { url, valueSha256, createdAt, expiresAt }. The value itself is
// printed once and never stored; nothing here is a secret.

import crypto from 'node:crypto';
import dns from 'node:dns';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { Readable } from 'node:stream';
import { isAuthError } from './auth-signals.js';

// 30 minutes from issue to proof. Long enough to add one line, redeploy and run the command again (deploy times were NOT
// measured; when it runs out, --new-proof gives a fresh value). Short, because the proof stands for a deliberate action now:
// a value left pending for days could authorize a run after the server has changed hands. CA/B BR 3.2.2.4.18 allows a
// Random Value 30 DAYS, but that is for a certificate request, not an action that follows within minutes.
export const PROOF_TTL_MS = 30 * 60 * 1000;
export const LINE_PREFIX = 'protocolprobe-proof=';
const VALUE_BYTES = 32; // 256 bits; RFC 8555 8.3 asks at least 128 bits, CA/B BR at least 112
const STATE_FILE = 'pending-proofs.json';
export const LOOPBACK_NAMES = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);

export class ProofRefused extends Error {
  constructor(reason, message) { super(message); this.proofReason = reason; }
}

const bare = h => String(h).replace(/^\[|\]$/g, '').toLowerCase();

// The canonical key of a URL: scheme, lower-case host (punycode, as WHATWG URL gives it), explicit port, path and query.
export function urlKey(u) {
  const port = u.port || (u.protocol === 'https:' ? '443' : '80');
  return `${u.protocol}//${u.hostname.toLowerCase()}:${port}${u.pathname}${u.search}`;
}

// Parse and check the --url value. Throws ProofRefused('bad-url' | 'http-not-local').
export function canonicalTarget(input) {
  let u;
  try { u = new URL(String(input)); } catch { throw new ProofRefused('bad-url', `not a valid URL: ${String(input).slice(0, 200)}`); }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new ProofRefused('bad-url', `only https:// (or http:// on this machine) is accepted, not ${u.protocol}`);
  if (u.username || u.password) throw new ProofRefused('bad-url', 'a user name or password in the URL is refused (this version sends no credentials)');
  if (u.hash) throw new ProofRefused('bad-url', 'a #fragment is refused: it is never sent to the server, so it cannot be part of what is proven');
  if (u.protocol === 'http:' && !LOOPBACK_NAMES.has(u.hostname.toLowerCase()))
    throw new ProofRefused('http-not-local', `http:// is accepted only for this machine (localhost, 127.0.0.1, ::1); use https:// for ${u.hostname}`);
  return { key: urlKey(u), href: u.href, scheme: u.protocol, host: u.hostname.toLowerCase(), port: Number(u.port || (u.protocol === 'https:' ? 443 : 80)), origin: u.origin };
}

export function isLoopbackAddress(a) {
  if (net.isIPv4(a)) return a.split('.')[0] === '127';
  if (net.isIPv6(a)) return a === '::1' || /^::ffff:127\./i.test(a) || /^0:0:0:0:0:0:0:1$/.test(a);
  return false;
}

// ---- pending values, kept on this machine ----

export function defaultStateDir(env = process.env, platform = process.platform) {
  if (env.PROTOCOLPROBE_SELFTEST_STATE_DIR) return env.PROTOCOLPROBE_SELFTEST_STATE_DIR;
  if (platform === 'win32') return path.join(env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local'), 'protocolprobe-selftest');
  if (platform === 'darwin') return path.join(os.homedir(), 'Library', 'Application Support', 'protocolprobe-selftest');
  return path.join(env.XDG_STATE_HOME || path.join(os.homedir(), '.local', 'state'), 'protocolprobe-selftest');
}

export const hashValue = (key, value) => crypto.createHash('sha256').update(`${key}\n${value}`).digest('hex');

export class ProofStore {
  constructor(dir, { now = () => Date.now() } = {}) { this.dir = dir; this.file = path.join(dir, STATE_FILE); this.now = now; this.warning = null; }

  load() {
    let data;
    try { data = JSON.parse(fs.readFileSync(this.file, 'utf8')); } catch (e) {
      if (e.code !== 'ENOENT') this.warning = `the file of pending proof values (${this.file}) could not be read and is started again (${e.code ?? 'not JSON'})`;
      return {};
    }
    return data && typeof data.pending === 'object' && data.pending ? data.pending : {};
  }

  save(pending) {
    const now = this.now();
    // only pending, unexpired values are kept
    const keep = Object.fromEntries(Object.entries(pending).filter(([, r]) => Date.parse(r.expiresAt) > now));
    fs.mkdirSync(this.dir, { recursive: true });
    const tmp = `${this.file}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, `${JSON.stringify({ version: 1, pending: keep }, null, 2)}\n`, { mode: 0o600 });
    fs.renameSync(tmp, this.file);
  }

  // { state: 'none' } | { state: 'expired', record } | { state: 'pending', record }
  find(key) {
    const record = this.load()[key];
    if (!record || record.url !== key) return { state: 'none' };
    return Date.parse(record.expiresAt) > this.now() ? { state: 'pending', record } : { state: 'expired', record };
  }

  issue(key) {
    const value = `pp1-${crypto.randomBytes(VALUE_BYTES).toString('base64url')}`;
    const t = this.now();
    const record = { url: key, valueSha256: hashValue(key, value), createdAt: new Date(t).toISOString(), expiresAt: new Date(t + PROOF_TTL_MS).toISOString() };
    const pending = this.load();
    pending[key] = record;
    this.save(pending);
    return { value, line: `${LINE_PREFIX}${value}`, record };
  }

  remove(key) {
    const pending = this.load();
    if (!(key in pending)) return false;
    delete pending[key];
    this.save(pending);
    return true;
  }
}

// Does the server's initialize `instructions` carry the pending value, on a line of its own?
// { ok: true } | { ok: false, reason: 'missing' | 'not-own-line' | 'wrong-value' }
export function proofInInstructions(instructions, record) {
  const lines = String(instructions ?? '').split(/\r?\n/).map(l => l.trim());
  const values = lines.filter(l => l.startsWith(LINE_PREFIX)).map(l => l.slice(LINE_PREFIX.length).trim());
  if (values.some(v => hashValue(record.url, v) === record.valueSha256)) return { ok: true };
  if (values.length) return { ok: false, reason: 'wrong-value' };
  if (lines.some(l => l.includes(LINE_PREFIX))) return { ok: false, reason: 'not-own-line' };
  return { ok: false, reason: 'missing' };
}

// ---- resolve once, then connect only to those addresses ----

export async function defaultResolveAddrs(host) {
  const h = bare(host);
  if (net.isIP(h)) return [h];
  const r = await dns.promises.lookup(h, { all: true, verbatim: true });
  return r.map(x => x.address);
}

// Resolve the host once. For http (this machine only) every address must be loopback.
export async function resolveTarget(canon, resolveAddrs = defaultResolveAddrs) {
  let addrs;
  try { addrs = [...new Set(await resolveAddrs(canon.host))]; } catch (e) { throw new ProofRefused('no-address', `could not resolve ${canon.host}: ${e?.code ?? e?.message ?? e}`); }
  if (!addrs.length || addrs.some(a => !net.isIP(a))) throw new ProofRefused('no-address', `could not resolve ${canon.host}`);
  if (canon.scheme === 'http:' && !addrs.every(isLoopbackAddress))
    throw new ProofRefused('http-not-local', `${canon.host} resolved to ${addrs.join(', ')}, which is not only this machine; http:// is accepted only for this machine`);
  return addrs;
}

// ---- operator-supplied credentials (0.3.0, owner decision D6) ----
//
// The operator may give their OWN server's credential, read ONLY from an environment variable (a value typed on the command
// line would stay in shell history and be visible in the process list): --bearer-env VAR sends "Authorization: Bearer
// <VAR's value>", --header-env Name=VAR sends "Name: <VAR's value>". Rules, each enforced here or in selftest.mjs and tested
// (test/selftest-remote.test.js):
//   - the values go ONLY into the session fetch below (scope 'exact'), so only to the exact proven URL, at the pinned address,
//     never on a redirect (none is followed), never to OAuth metadata (same origin or not: those documents are public by
//     design, RFC 9728 / RFC 8414, and a host may serve other people's apps on other paths of the same origin, so the
//     credential stays with the one URL the proof covers), and never to the unauthenticated probe of dims 14-15;
//   - never printed, never written to --out, never stored in the proof state file (the exact values are redacted from every
//     output path in selftest.mjs, and Credentials below shows names only if it is ever printed or turned into JSON).

// Header names: an RFC 9110 token. Refused: names that frame or route the HTTP message (Host, Content-Length,
// Transfer-Encoding, Expect), hop-by-hop headers (RFC 9110 7.6.1: Connection, Keep-Alive, Proxy-Connection, TE, Trailer,
// Upgrade, Proxy-Authenticate, Proxy-Authorization), cookies (Cookie, Set-Cookie: a cookie is a browser session, not a
// credential an operator hands to a test tool), and the headers the MCP transport itself sets (Content-Type, Accept,
// Mcp-Session-Id, Mcp-Protocol-Version, Last-Event-ID): overriding one would change the protocol or the session the proof
// was read on.
const TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
export const REFUSED_HEADERS = new Set([
  'host', 'content-length', 'transfer-encoding', 'expect',
  'connection', 'keep-alive', 'proxy-connection', 'te', 'trailer', 'trailers', 'upgrade', 'proxy-authenticate', 'proxy-authorization',
  'cookie', 'set-cookie',
  'content-type', 'accept', 'mcp-session-id', 'mcp-protocol-version', 'last-event-id',
]);
export const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
// A value shorter than this is refused: every output path hides the exact value, and a very short one cannot be hidden
// without hiding ordinary text too (and is no real credential).
export const MIN_SECRET_LENGTH = 8;

export class CredentialRefused extends Error {}

// Throws CredentialRefused (never with a value in the message) when the name may not be sent.
export function checkHeaderName(name) {
  const n = String(name ?? '');
  if (!TOKEN.test(n)) throw new CredentialRefused('a header name must be a valid HTTP token (letters, digits and !#$%&\'*+.^_`|~-, no spaces or colons)');
  if (REFUSED_HEADERS.has(n.toLowerCase())) throw new CredentialRefused(`the header ${n} cannot be set with --header-env: it frames the HTTP message, is hop-by-hop, is a cookie, or is set by the MCP transport itself`);
  return n;
}

// Operator credentials, read from the environment. Only the names are ever shown; the values live in a private field, and
// toJSON / util.inspect give the names only, so a stray JSON.stringify or console.log cannot print a value.
export class Credentials {
  #values;
  #extra;
  constructor(entries, extraSecrets = []) {
    // entries: [{ header (as typed), variable, value }]; extraSecrets: more strings to hide (the bare token of a bearer)
    this.#values = entries.map(e => ({ ...e }));
    this.#extra = [...extraSecrets];
    Object.freeze(this);
  }
  get size() { return this.#values.length; }
  // [{ header, variable }] - what may be shown
  get names() { return this.#values.map(({ header, variable }) => ({ header, variable })); }
  // lower-case header name -> value, for the session fetch only
  headers() { return Object.fromEntries(this.#values.map(e => [e.header.toLowerCase(), e.value])); }
  // the exact values (and the bare token of a bearer: a server may echo it without "Bearer "), for the redaction list only
  secrets() { return [...new Set([...this.#values.map(e => e.value), ...this.#extra])]; }
  toJSON() { return { headers: this.names.map(n => n.header), source: 'environment' }; }
  [Symbol.for('nodejs.util.inspect.custom')]() { return `Credentials(${this.names.map(n => `${n.header} from $${n.variable}`).join(', ')})`; }
}

// specs: [{ header, variable, bearer }] as parsed from the command line. Reads each variable from `env`; throws
// CredentialRefused naming the variable (never its value) when it is missing, empty, too short or not sendable.
export function credentialsFromEnv(specs, env = process.env) {
  const seen = new Set();
  const entries = specs.map(s => {
    const header = checkHeaderName(s.header);
    if (seen.has(header.toLowerCase())) {
      throw new CredentialRefused(header.toLowerCase() === 'authorization' && specs.some(x => x.bearer)
        ? '--bearer-env already sets the Authorization header; do not also give it with --header-env'
        : `the header ${header} is given twice`);
    }
    seen.add(header.toLowerCase());
    const raw = env[s.variable];
    if (raw === undefined || raw === '') throw new CredentialRefused(`the environment variable ${s.variable} (named by ${s.bearer ? '--bearer-env' : '--header-env'}) is not set or is empty`);
    const v = String(raw);
    // a header value is visible ASCII with inner spaces (RFC 9110 field-value); a control character would split the header
    if (!/^[\x21-\x7e](?:[\x20-\x7e]*[\x21-\x7e])?$/.test(v)) throw new CredentialRefused(`the value of ${s.variable} cannot be sent as a header: it must be printable ASCII, with no line break and no space at either end (its value is not shown)`);
    if (v.length < MIN_SECRET_LENGTH) throw new CredentialRefused(`the value of ${s.variable} is shorter than ${MIN_SECRET_LENGTH} characters; this tool hides the exact value in everything it prints and writes, and a value that short cannot be hidden reliably (its value is not shown)`);
    if (s.bearer) {
      if (/^bearer\s/i.test(v)) throw new CredentialRefused(`the value of ${s.variable} starts with "Bearer "; put only the token in it (--bearer-env adds "Bearer ")`);
      if (/\s/.test(v)) throw new CredentialRefused(`the value of ${s.variable} contains a space; a bearer token has none (use --header-env Authorization=${s.variable} to send a whole header value)`);
    }
    return { header, variable: s.variable, value: s.bearer ? `Bearer ${v}` : v, raw: v };
  });
  return { credentials: new Credentials(entries.map(({ header, variable, value }) => ({ header, variable, value })), entries.filter(e => e.raw !== e.value).map(e => e.raw)) };
}

// Every form in which an exact value may come back in text this tool prints or writes: as is, as it appears inside a JSON
// string, and URL-encoded. (Other encodings, for example base64 of the value, are not recognised: README and DISCLOSURE.)
export function secretForms(values) {
  const out = new Set();
  for (const v of values ?? []) {
    if (!v) continue;
    out.add(v);
    out.add(JSON.stringify(v).slice(1, -1));
    out.add(encodeURIComponent(v));
  }
  // longest first, so a shorter form inside a longer one does not leave a piece of the longer one
  return [...out].filter(Boolean).sort((a, b) => b.length - a.length);
}

export function redactExact(text, forms) {
  let t = String(text ?? '');
  for (const f of forms ?? []) if (f) t = t.split(f).join('[redacted]');
  return t;
}

// A fetch (the subset the MCP SDK 1.32 transport and engine/src/oauth.js use) over node:http / node:https that:
//   - connects only to `addresses` (resolved once; its own lookup never asks DNS again);
//   - checks the TLS certificate against the host NAME (https.Agent sets servername from the host), as a normal fetch would;
//   - refuses every redirect (any 3xx is an error, never followed);
//   - refuses any request outside `scope`: 'exact' = the proven URL only (the MCP session), 'origin' = the proven origin only
//     (the OAuth metadata reads of dims 14-18).
//   - `credentials` (0.3.0): the operator's headers, added to every request; accepted ONLY with scope 'exact', so they can
//     reach nothing but the proven URL (the scope check above runs first, and a refused request sends nothing).
// Node's global fetch offers no DNS hook without the undici package (a new dependency), hence this small client.
export function pinnedFetch({ canon, addresses, scope = 'exact', ca, credentials = null } = {}) {
  if (credentials && scope !== 'exact') throw new TypeError('pinned fetch: credentials are sent only to the exact proven URL (scope "exact")');
  const credHeaders = credentials ? credentials.headers() : {};
  const host = bare(canon.host);
  const list = addresses.map(a => ({ address: a, family: net.isIPv6(a) ? 6 : 4 }));
  const lookup = (name, opts, cb) => {
    if (typeof opts === 'function') { cb = opts; opts = {}; }
    if (bare(name) !== host) { cb(Object.assign(new Error(`refused: no lookup for ${name}`), { code: 'ENOTFOUND' })); return; }
    if (opts?.all) cb(null, list.map(x => ({ ...x })));
    else cb(null, list[0].address, list[0].family);
  };
  const tls = canon.scheme === 'https:';
  const mod = tls ? https : http;
  const agent = new mod.Agent({ keepAlive: true, ...(ca ? { ca } : {}) });
  const f = async (input, init = {}) => {
    const u = new URL(typeof input === 'string' || input instanceof URL ? input : input.url);
    const inScope = scope === 'exact' ? urlKey(u) === canon.key : u.protocol === canon.scheme && bare(u.hostname) === host && Number(u.port || (tls ? 443 : 80)) === canon.port;
    if (!inScope) throw new ProofRefused('outside-proven-url', `refused: a request to ${u.origin}${u.pathname} is outside the proven URL`);
    const headers = {};
    new Headers(init.headers ?? (typeof input === 'object' && input.headers ? input.headers : undefined)).forEach((v, k) => { headers[k] = v; });
    for (const [k, v] of Object.entries(credHeaders)) headers[k] = v; // Headers.forEach gives lower-case names, as these are
    const method = String(init.method ?? 'GET').toUpperCase();
    const body = init.body ?? null;
    if (body !== null && typeof body !== 'string' && !(body instanceof Uint8Array)) throw new TypeError('pinned fetch: the body must be a string or bytes');
    if (init.signal?.aborted) throw init.signal.reason ?? new Error('aborted');
    return new Promise((resolve, reject) => {
      const req = mod.request({ hostname: host, port: canon.port, path: `${u.pathname}${u.search}`, method, headers, agent, lookup, ...(init.signal ? { signal: init.signal } : {}) });
      req.once('error', reject);
      req.once('response', res => {
        const status = res.statusCode;
        if (status >= 300 && status < 400) {
          res.resume();
          let to = '(no location)';
          try { const l = new URL(res.headers.location, u); to = `${l.origin}${l.pathname}`; } catch { /* keep the placeholder */ }
          reject(new ProofRefused('redirect', `the server answered ${status} redirect to ${to}`));
          return;
        }
        const h = new Headers();
        for (let i = 0; i < res.rawHeaders.length; i += 2) {
          try { h.append(res.rawHeaders[i], res.rawHeaders[i + 1]); } catch { /* a header the Headers class refuses is dropped */ }
        }
        const noBody = method === 'HEAD' || [204, 205, 304].includes(status);
        if (noBody) res.resume();
        const response = new Response(noBody ? null : Readable.toWeb(res), { status, statusText: res.statusMessage ?? '', headers: h });
        Object.defineProperty(response, 'url', { value: u.href });
        resolve(response);
      });
      if (body !== null) req.end(body); else req.end();
    });
  };
  f.close = () => agent.destroy();
  f.scope = scope;
  return f;
}

// Which failure of the proof connection is this? 'redirect' | 'auth' | 'outside' | null (an ordinary connect failure).
export function classifyConnectFailure(err) {
  const all = [];
  for (let e = err, i = 0; e && i < 5; e = e.cause, i++) all.push(e);
  if (all.some(e => e?.proofReason === 'redirect') || /the server answered 3\d\d redirect/.test(String(err?.message))) return 'redirect';
  if (all.some(e => e?.proofReason === 'outside-proven-url')) return 'outside';
  const status = httpStatusOf(err);
  if (status === 401 || status === 403) return 'auth';
  // the server answered (an HTTP status or a JSON-RPC error code) with a message that says a credential is needed, e.g.
  // "MCP error -32001: Authentication required" at initialize. A network error (string code) is never read as auth.
  if (typeof err?.code === 'number' && isAuthError(String(err?.message ?? ''))) return 'auth';
  return null;
}

// The HTTP status of an SDK transport error (StreamableHTTPError carries it as a numeric code), else null. A JSON-RPC error
// code (negative) is not an HTTP status.
export function httpStatusOf(err) {
  const c = err?.code;
  return typeof c === 'number' && c >= 100 && c <= 599 ? c : null;
}
