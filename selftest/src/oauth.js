// Read-only OAuth discovery for HTTP targets (dims 14-18).
// Raw fetch on purpose: SDK 1.32.0's OAuthMetadataSchema rejects javascript:/data:/vbscript:
// at parse time (verified 2026-10-04), so going through the SDK would throw away exactly
// the evidence dim 18 needs. Only GETs of public .well-known documents are made.

import { buildDiscoveryUrls } from '@modelcontextprotocol/sdk/client/auth.js';
import { withIdentity } from './identity.js';

const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);

// Spec (Security Best Practices): only https, or http for loopback.
// A field that is absent, null or empty publishes no URL and is not checked (returns null): before 2026-10-10 a JSON
// null was read as an "unparseable URL" and scored VULNERABLE (10 of the 14 raw dim-18 results; step 9 review).
// A value that is not an absolute URL is malformed metadata, reported separately and never VULNERABLE: it is not a
// URL outside the allowlist, it is not a URL at all.
export function schemeVerdict(value) {
  if (value === null || value === undefined || value === '') return null;
  let u;
  try { u = new URL(String(value)); } catch { return { value, ok: false, malformed: true, why: 'not an absolute URL' }; }
  if (u.protocol === 'https:') return { value, ok: true };
  if (u.protocol === 'http:' && LOOPBACK.has(u.hostname)) return { value, ok: true, why: 'http allowed for loopback' };
  return { value, ok: false, why: `scheme ${u.protocol}${u.protocol === 'http:' ? ' to non-loopback host' : ''}` };
}

// GET a .well-known document, following http(s) redirects manually (max 5 hops) so a
// redirecting host (e.g. sh.inference.ac -> api.inference.sh) still yields its metadata.
// The redirect chain is recorded; a redirect to a non-http(s) scheme is refused, not followed.
async function getJson(url, fetchFn = fetch) {
  const requested = String(url);
  let current = requested;
  const redirectChain = [];
  try {
    for (let hop = 0; hop <= 5; hop++) {
      const res = await fetchFn(current, { headers: withIdentity({ accept: 'application/json' }), redirect: 'manual', signal: AbortSignal.timeout(10000) });
      if (res.status >= 300 && res.status < 400) {
        const loc = res.headers.get('location');
        await res.body?.cancel().catch(() => {});
        if (!loc) return { url: current, requested, status: res.status, redirectChain, redirectNoLocation: true };
        let next;
        try { next = new URL(loc, current); } catch { return { url: current, requested, status: res.status, redirectChain, badLocation: loc }; }
        if (next.protocol !== 'http:' && next.protocol !== 'https:') {
          return { url: current, requested, status: res.status, redirectChain, refusedRedirectTo: next.href, refusedScheme: next.protocol };
        }
        redirectChain.push({ from: current, to: next.href, status: res.status });
        current = next.href;
        continue;
      }
      if (!res.ok) { await res.body?.cancel().catch(() => {}); return { url: current, requested, status: res.status, redirectChain: redirectChain.length ? redirectChain : undefined }; }
      const text = await res.text();
      const ev = { url: current, requested, status: res.status, ...(redirectChain.length ? { redirectChain } : {}) };
      try { return { ...ev, json: JSON.parse(text) }; }
      catch { return { ...ev, notJson: true }; }
    }
    return { url: current, requested, redirectChain, error: 'too many redirects (>5)' };
  } catch (e) {
    return { url: current, requested, redirectChain: redirectChain.length ? redirectChain : undefined, error: String(e?.cause?.message ?? e?.message ?? e) };
  }
}

// The JSON-RPC answer (id 0) in the body of a 2xx initialize response, JSON or SSE, read up to 64 KB and stopped as soon as
// it is found: { result: true } | { error: { code, message } } | { unread: why }. A server may refuse an initialize without a
// credential with HTTP 200 and a JSON-RPC error (seen on the registry; test fixture `authFailure: 'jsonrpc'`), so the status
// alone does not say the session was accepted (0.3.0; before, every 2xx was read as "accepted without credentials").
async function initializeAnswer(res, max = 64 * 1024) {
  const reader = res.body?.getReader?.();
  if (!reader) return { unread: 'no body' };
  const sse = /text\/event-stream/i.test(res.headers.get('content-type') ?? '');
  const dec = new TextDecoder();
  let text = '';
  const find = () => {
    const candidates = sse ? text.split(/\r?\n/).filter(l => l.startsWith('data:')).map(l => l.slice(5).trim()) : [text];
    for (const c of candidates) {
      let m;
      try { m = JSON.parse(c); } catch { continue; }
      for (const x of Array.isArray(m) ? m : [m]) {
        if (!x || x.jsonrpc !== '2.0' || x.id !== 0) continue;
        if (x.error) return { error: { code: x.error.code ?? null, message: String(x.error.message ?? '').slice(0, 200) } };
        if ('result' in x) return { result: true };
      }
    }
    return null;
  };
  try {
    while (text.length < max) {
      const { done, value } = await reader.read();
      if (value) text += dec.decode(value, { stream: true });
      const a = find();
      if (a) return a;
      if (done) return { unread: 'no JSON-RPC answer in the body' };
    }
    return { unread: `no JSON-RPC answer in the first ${max} bytes` };
  } catch (e) {
    return { unread: String(e?.cause?.message ?? e?.message ?? e).slice(0, 120) };
  } finally {
    reader.cancel().catch(() => {});
  }
}

// 401 probe: does the MCP endpoint demand auth, and does it point at resource metadata? Sent with NO credential header, so
// it also tells whether the server opens a session without one (dims.js acceptedWithoutCredentials).
export async function probeAuthChallenge(serverUrl, { fetchFn = fetch } = {}) {
  try {
    const res = await fetchFn(serverUrl, {
      method: 'POST', redirect: 'manual',
      headers: withIdentity({ 'content-type': 'application/json', accept: 'application/json, text/event-stream' }),
      body: JSON.stringify({ jsonrpc: '2.0', id: 0, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'mcp-runtime-engine-auth-probe', version: '0.1.0' } } }),
      signal: AbortSignal.timeout(10000),
    });
    const rpc = res.status >= 200 && res.status < 300 ? await initializeAnswer(res) : (await res.body?.cancel().catch(() => {}), null);
    const www = res.headers.get('www-authenticate');
    const m = www && /resource_metadata="([^"]+)"/i.exec(www);
    return { status: res.status, wwwAuthenticate: www, resourceMetadataUrl: m?.[1] ?? null, ...(rpc ? { rpc } : {}) };
  } catch (e) {
    return { error: String(e?.cause?.message ?? e?.message ?? e) };
  }
}

// `fetchFn` / `originOnly` (the remote self-test, src/remote-proof.js): every read goes through the given fetch (pinned
// address, no redirect), and a document on ANOTHER origin (a resource_metadata URL or an authorization server elsewhere,
// for example an identity provider) is not fetched at all: the proof covers the server's own origin only. Each such URL is
// listed in `skipped`.
export async function discover(serverUrl, challenge, { fetchFn = fetch, originOnly = false } = {}) {
  const u = new URL(serverUrl);
  const skipped = [];
  const allowed = url => {
    if (!originOnly) return true;
    let o;
    try { o = new URL(url).origin; } catch { o = null; }
    if (o === u.origin) return true;
    skipped.push({ url: String(url), reason: 'another origin: not covered by the proof, not fetched' });
    return false;
  };
  const prmCandidates = [
    challenge?.resourceMetadataUrl,
    u.pathname && u.pathname !== '/' ? `${u.origin}/.well-known/oauth-protected-resource${u.pathname.replace(/\/$/, '')}` : null,
    `${u.origin}/.well-known/oauth-protected-resource`,
  ].filter(Boolean);

  const fetched = [];
  let prm = null;
  for (const c of prmCandidates) {
    if (!allowed(c)) continue;
    const r = await getJson(c, fetchFn);
    fetched.push({ url: r.url, status: r.status ?? null, error: r.error ?? null, ...(r.redirectChain ? { redirectChain: r.redirectChain } : {}) });
    if (r.json) { prm = r.json; break; }
  }

  const asUrls = Array.isArray(prm?.authorization_servers) && prm.authorization_servers.length
    ? prm.authorization_servers
    : [`${u.origin}/`];

  let asMeta = null, asFrom = null;
  for (const as of asUrls.slice(0, 2)) {
    let urls;
    try { urls = buildDiscoveryUrls(as); } catch { continue; }
    for (const d of urls) {
      if (!allowed(d.url)) continue;
      const r = await getJson(d.url, fetchFn);
      fetched.push({ url: r.url, status: r.status ?? null, error: r.error ?? null, ...(r.redirectChain ? { redirectChain: r.redirectChain } : {}) });
      if (r.json) { asMeta = r.json; asFrom = r.url; break; }
    }
    if (asMeta) break;
  }

  // Every server-supplied URL a client might open or call during auth.
  const checked = [];
  const check = (field, v) => { const r = schemeVerdict(v); if (r) checked.push({ field, ...r }); };
  for (const a of prm?.authorization_servers ?? []) check('authorization_servers[]', a);
  for (const f of ['authorization_endpoint', 'token_endpoint', 'registration_endpoint', 'revocation_endpoint', 'userinfo_endpoint']) check(f, asMeta?.[f]);

  return {
    protectedResourceMetadata: prm,
    authorizationServerMetadataFrom: asFrom,
    authorizationServerMetadata: asMeta ? pick(asMeta, ['issuer', 'authorization_endpoint', 'token_endpoint', 'registration_endpoint', 'scopes_supported', 'code_challenge_methods_supported']) : null,
    fetched,
    checked,
    ...(skipped.length ? { skipped } : {}),
  };
}

/**
 * Dim 18 verdict from the checked list: VULNERABLE only for a URL outside the https / loopback-http allowlist;
 * malformed values alone give INFO; nothing checked gives N-A. Used by the live run AND to re-score stored results.
 */
export function dim18Status(checked) {
  const real = (checked ?? []).filter(c => c.value !== null && c.value !== undefined && c.value !== '');
  if (!real.length) return { status: 'N-A', label: null, note: 'no URL published in the OAuth metadata — nothing to check' };
  const isMalformed = (c) => c.malformed || (!c.ok && /unparseable/.test(c.why ?? '')); // older results lack the flag
  const bad = real.filter(c => !c.ok && !isMalformed(c));
  if (bad.length) return { status: 'VULNERABLE', label: 'confirmed-vulnerable', note: 'server-published OAuth metadata contains a URL outside the https / loopback-http allowlist the spec requires' };
  if (real.some(isMalformed)) return { status: 'INFO', label: null, note: 'OAuth metadata has values that are not absolute URLs (malformed); no URL is outside the https / loopback-http allowlist' };
  return { status: 'CLEAN', label: 'confirmed-safe', note: 'all server-published OAuth URLs are https (or loopback http)' };
}

/** Re-score a stored dim-18 result with the current rule (no network): same evidence, corrected status. */
export function rescoreDim18(dim) {
  if (!dim || dim.dimension !== 18 || !Array.isArray(dim.evidence?.checked)) return dim;
  const v = dim18Status(dim.evidence.checked);
  if (v.status === dim.status) return dim;
  return { ...dim, status: v.status, label: v.label, note: v.note, rescored: { from: dim.status, rule: 'dim18-2026-10-10' } };
}

function pick(o, keys) {
  return Object.fromEntries(keys.filter(k => o[k] !== undefined).map(k => [k, o[k]]));
}
