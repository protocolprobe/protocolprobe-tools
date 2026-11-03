// One test session against one target: set up controlled context, connect with
// sampling/elicitation/roots declared, and record every server->client message.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import { StringDecoder } from 'node:string_decoder';
import { pathToFileURL } from 'node:url';
import { withIdentity } from './identity.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';
import {
  CreateMessageRequestSchema, ElicitRequestSchema, ListRootsRequestSchema, LoggingMessageNotificationSchema,
} from '@modelcontextprotocol/sdk/types.js';

const STDERR_CAP = 64 * 1024;
// The head above is what the checks search (dim 4 looks for the canary). The tail is kept separately for error messages:
// a big `npx`/`uvx` install prints more than 64 KB, and the real reason a server failed is in its LAST lines.
const STDERR_TAIL = 16 * 1024;

// Keep the last `cap` characters, starting at a whole line when it was cut (an error message shows whole lines only).
export function keepTail(tail, cap = STDERR_TAIL) {
  if (tail.length <= cap) return tail;
  const t = tail.slice(-cap);
  const nl = t.indexOf('\n');
  return nl >= 0 && nl < t.length - 1 ? t.slice(nl + 1) : t;
}

// Stopping a stdio server on Windows. A command such as `npx` or a `.cmd` file runs inside cmd.exe, and the SDK's close
// stops only that cmd.exe, so a server that keeps running after its input closes was left running (measured 2026-10-19 with
// our own fixture through `npx --package <our tarball>` and through a .cmd file: npx, cmd.exe and the server stayed).
// So on Windows: close the server's input, as the SDK does, wait up to `graceMs` for it to exit, and if it has not, end its
// whole process tree (taskkill /T /F) while cmd.exe still links it, before the SDK's own kill (which comes 2 s after the
// input closes). After a failed connect there is no grace (graceMs 0): the SDK may already have closed the input itself.
// Elsewhere (Linux, macOS) this does nothing and the SDK close runs unchanged.
export async function stopStdioTree(child, { graceMs = 2000 } = {}) {
  if (process.platform !== 'win32' || !child || typeof child.pid !== 'number' || child.exitCode !== null || child.signalCode !== null) return;
  const closed = new Promise(r => child.once('close', () => r(true)));
  let timer;
  if (graceMs > 0) {
    try { child.stdin?.end(); } catch { /* already closed */ }
    const done = await Promise.race([closed, new Promise(r => { timer = setTimeout(() => r(false), graceMs); })]);
    clearTimeout(timer);
    if (done || child.exitCode !== null) return;
  }
  const taskkill = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'taskkill.exe');
  await new Promise(r => {
    const k = spawn(taskkill, ['/pid', String(child.pid), '/T', '/F'], { stdio: 'ignore', windowsHide: true });
    k.once('error', () => r()); // taskkill missing: the SDK close below still runs
    k.once('exit', () => r());
  });
  await Promise.race([closed, new Promise(r => { timer = setTimeout(r, 2000); })]);
  clearTimeout(timer);
}

export async function createContext() {
  const id = crypto.randomBytes(6).toString('hex');
  // realpath.native: on Windows os.tmpdir() can be an 8.3 short path (C:UsersSULTAN~1...),
  // while servers canonicalise to the long form and then reject our paths as "outside".
  const workdir = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-probe-root-')));
  const outsideDir = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-probe-outside-')));
  const probeFile = path.join(workdir, 'probe.txt');
  const outsideMarker = `OUTSIDE-ROOT-MARKER-${id}`;
  const outsideFile = path.join(outsideDir, 'outside.txt');
  fs.writeFileSync(probeFile, `mcp probe file ${id}\n`);
  fs.writeFileSync(outsideFile, `${outsideMarker}\n`);

  // Real local listener: SSRF reachability is decided by whether it actually got hit.
  const hits = [];
  const listener = http.createServer((req, res) => {
    hits.push({ method: req.method, url: req.url, at: Date.now(), ua: req.headers['user-agent'] ?? null });
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end(`listener-response-${id}`);
  });
  await new Promise(r => listener.listen(0, '127.0.0.1', r));
  const port = listener.address().port;

  return {
    id,
    canaryName: 'CANARY_TEST_SECRET',
    canary: `CANARY-${id}-sk-live-${crypto.randomBytes(8).toString('hex')}`,
    workdir, probeFile, outsideDir, outsideFile, outsideMarker,
    listenerUrl: `http://127.0.0.1:${port}/probe-${id}`,
    listenerHits: hits,
    async dispose() {
      await new Promise(r => listener.close(r));
      for (const d of [workdir, outsideDir]) {
        try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
      }
    },
  };
}

function substitutePlaceholders(value, ctx) {
  return String(value)
    .replaceAll('{WORKDIR}', ctx.workdir)
    .replaceAll('{PROBE_FILE}', ctx.probeFile);
}

// What the client tells a server that asks for its roots (docs/legal C2, 2026-11-03): a stdio server we start in a sandbox gets the
// sandbox's own probe folder (dim 10 needs it); a remote server gets none, so a path on the machine that runs the read (it can hold a user
// name) is never sent to a third party.
export const rootsFor = (target, ctx) => (target.kind === 'http' ? [] : [{ uri: pathToFileURL(ctx.workdir).href, name: 'probe-root' }]);

// Follow 3xx manually so the redirect chain is recorded as evidence and no
// configured headers are carried to a different origin.
export async function resolveRedirects(url, headers = {}, maxHops = 5) {
  const chain = [];
  let current = new URL(url);
  for (let hop = 0; hop < maxHops; hop++) {
    let res;
    try {
      res = await fetch(current, {
        method: 'POST', redirect: 'manual',
        headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', ...withIdentity(headers) },
        body: JSON.stringify({ jsonrpc: '2.0', id: 0, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'mcp-runtime-engine-redirect-probe', version: '0.1.0' } } }),
        signal: AbortSignal.timeout(15000),
      });
    } catch (e) {
      return { finalUrl: current.href, chain, error: String(e?.cause?.message ?? e?.message ?? e) };
    }
    await res.body?.cancel().catch(() => {});
    const loc = res.headers.get('location');
    if (res.status < 300 || res.status >= 400 || !loc) return { finalUrl: current.href, chain };
    const next = new URL(loc, current);
    if (next.protocol !== 'https:' && next.protocol !== 'http:') {
      chain.push({ from: current.href, to: next.href, status: res.status, refused: 'non-http(s) scheme' });
      return { finalUrl: current.href, chain, error: `redirect to non-http(s) scheme ${next.protocol}` };
    }
    chain.push({ from: current.href, to: next.href, status: res.status, crossOrigin: next.origin !== current.origin });
    if (next.origin !== current.origin) headers = {};
    current = next;
  }
  return { finalUrl: current.href, chain, error: `more than ${maxHops} redirects` };
}

function makeTransport(target, ctx, url, headers, fetchFn) {
  if (target.kind === 'stdio') {
    return new StdioClientTransport({
      command: target.command,
      args: (target.args ?? []).map(a => substitutePlaceholders(a, ctx)),
      env: { ...Object.fromEntries(Object.entries(target.env ?? {}).map(([k, v]) => [k, substitutePlaceholders(v, ctx)])), [ctx.canaryName]: ctx.canary },
      cwd: ctx.workdir,
      stderr: 'pipe',
    });
  }
  const requestInit = { headers: withIdentity(headers) };
  // a given fetch (the remote self-test's pinned, no-redirect fetch: src/remote-proof.js) carries every request of the session
  const viaFetch = fetchFn ? { fetch: fetchFn } : {};
  return target.transportType === 'sse'
    ? new SSEClientTransport(new URL(url), { requestInit, ...viaFetch })
    : new StreamableHTTPClientTransport(new URL(url), { requestInit, ...viaFetch });
}

// `fetch` (HTTP only): every request of the session goes through it, and a redirect is NEVER followed by the engine's own
// fallback below (the remote self-test proves one exact URL; src/remote-proof.js pinnedFetch refuses every 3xx).
// `discoveryFetch` (HTTP only): kept on the session for the OAuth metadata reads of dims 14-18 (src/dims.js httpAuthDims).
export async function openSession(target, ctx, { connectTimeoutMs = 120000, fetch: fetchFn = null, discoveryFetch = null } = {}) {
  const events = [];
  const record = (type, payload) => events.push({ type, at: Date.now(), payload });
  let stderr = '';
  let stderrTail = '';
  let closed = null;

  const client = new Client(
    { name: 'mcp-runtime-engine', version: '0.1.0' },
    { capabilities: { sampling: {}, elicitation: { form: {}, url: {} }, roots: { listChanged: true } } },
  );

  client.setRequestHandler(CreateMessageRequestSchema, async req => {
    record('sampling', req.params);
    return { role: 'assistant', model: 'mcp-runtime-engine-stub', stopReason: 'endTurn', content: { type: 'text', text: 'stub sampling response' } };
  });
  client.setRequestHandler(ElicitRequestSchema, async req => {
    record('elicitation', req.params);
    return { action: 'decline' };
  });
  client.setRequestHandler(ListRootsRequestSchema, async () => {
    record('roots-list', null);
    return { roots: rootsFor(target, ctx) };
  });
  client.setNotificationHandler(LoggingMessageNotificationSchema, n => record('log', n.params));
  client.fallbackNotificationHandler = async n => record('notification', { method: n.method, params: n.params });

  const connection = { requestedUrl: target.url ?? null, finalUrl: target.url ?? null, redirectChain: [] };
  let transport = makeTransport(target, ctx, target.url, target.headers ?? {}, fetchFn);

  let child = null; // the stdio server's process, kept from its start (the SDK forgets it as soon as its own close begins)
  const attach = t => {
    if (t instanceof StdioClientTransport) {
      const start = t.start.bind(t);
      t.start = async () => { try { await start(); } finally { child = t._process ?? null; } }; // SDK 1.32.0 (pinned) field
    }
    // one decoder per stream, so a character split across two chunks is not garbled
    const dec = new StringDecoder('utf8');
    if (t.stderr) t.stderr.on('data', d => {
      const s = dec.write(d);
      if (stderr.length < STDERR_CAP) stderr += s;
      stderrTail = keepTail(stderrTail + s);
    });
    t.onclose = () => { closed ??= Date.now(); };
  };
  attach(transport);

  const connect = t => {
    let timer;
    return Promise.race([
      // Pass our timeout to the SDK too: without it the SDK's own initialize request gives up at its 60 s default
      // (DEFAULT_REQUEST_TIMEOUT_MSEC), so a slow `npx`/`uvx` install surfaced as "Request timed out" even though our
      // budget was longer - found 2026-10-09 behind 5,081 package "connect-failed" results.
      client.connect(t, { timeout: connectTimeoutMs }),
      new Promise((_, rej) => { timer = setTimeout(() => rej(new Error(`connect timeout after ${connectTimeoutMs}ms`)), connectTimeoutMs); }),
    ]).finally(() => clearTimeout(timer));
  };

  const started = Date.now();
  try {
    await connect(transport);
  } catch (err) {
    const msg = String(err?.message ?? err);
    // SDK 1.32 default redirectPolicy is 'same-origin': cross-origin redirects fail.
    if (target.kind === 'http' && !fetchFn && /redirect/i.test(msg)) {
      const r = await resolveRedirects(target.url, target.headers ?? {});
      connection.redirectChain = r.chain;
      if (r.error || r.finalUrl === target.url) throw Object.assign(err, { redirect: r });
      connection.finalUrl = r.finalUrl;
      await transport.close().catch(() => {});
      const crossOrigin = r.chain.some(h => h.crossOrigin);
      transport = makeTransport(target, ctx, r.finalUrl, crossOrigin ? {} : (target.headers ?? {}));
      attach(transport);
      closed = null;
      await connect(transport);
    } else {
      await stopStdioTree(child, { graceMs: 0 }).catch(() => {});
      await transport.close().catch(() => {});
      err.stderr = stderr;
      err.stderrTail = stderrTail;
      throw err;
    }
  }
  connection.connectMs = Date.now() - started;

  return {
    client, transport, events, connection, discoveryFetch,
    get stderr() { return stderr; },
    get stderrTail() { return stderrTail; },
    get closedAt() { return closed; },
    async close() {
      await stopStdioTree(child).catch(() => {});
      await client.close().catch(() => {});
    },
  };
}
