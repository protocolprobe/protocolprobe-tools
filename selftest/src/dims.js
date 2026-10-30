// The 18 dimension slots. Every slot is ATTEMPTED on every target; the observed
// outcome decides the status (no upfront applicability filtering).
//
// status: INFO | CLEAN | VULNERABLE | FOUND | TRIGGERED | NOT-OBSERVED | N-A |
//         HARNESS-ERROR | INCONCLUSIVE | NOT-TESTABLE
// label (CLAUDE.md): confirmed-vulnerable | confirmed-safe | candidate | null

import { buildArgs, wrongTypeValue } from './args.js';
import { scanText, isMutating, urlParams, pathParams, SENSITIVE_FIELD, STACK_TRACE, classifyFailures } from './patterns.js';
import { dim18Status, discover, probeAuthChallenge } from './oauth.js';
import { isAuthError } from './auth-signals.js';

const CALL_TIMEOUT_MS = 20000;

const NAMES = {
  1: 'tool-list', 2: 'description-poisoning', 3: 'real-execution', 4: 'canary-leak', 5: 'ssrf',
  6: 'write-without-confirmation', 7: 'error-handling', 8: 'sampling', 9: 'elicitation-sensitive-data',
  10: 'root-boundary', 11: 'logging-side-channel', 12: 'audience-hiding', 13: 'fake-assistant-turn',
  14: 'token-passthrough', 15: 'token-audience-validation', 16: 'open-redirect', 17: 'confused-deputy',
  18: 'oauth-url-scheme',
};

const result = (dimension, status, label, evidence, note) =>
  ({ dimension, name: NAMES[dimension], status, label, evidence, ...(note ? { note } : {}) });

const textOf = v => JSON.stringify(v ?? null);
const truncate = (s, n = 300) => (s && s.length > n ? `${s.slice(0, n)}…[+${s.length - n}]` : s);

async function paginate(fn, key) {
  const items = [];
  let cursor;
  for (let i = 0; i < 20; i++) {
    const page = await fn(cursor ? { cursor } : undefined);
    items.push(...(page[key] ?? []));
    cursor = page.nextCursor;
    if (!cursor) break;
  }
  return items;
}

// ---------- shared state built while running ----------

function makeRunner(session, ctx) {
  const transcript = []; // every response we got back, for canary scanning
  async function call(tool, args, purpose) {
    const before = session.events.length;
    const t0 = Date.now();
    let out;
    try {
      const res = await session.client.callTool({ name: tool.name, arguments: args }, undefined, { timeout: CALL_TIMEOUT_MS });
      out = { ok: true, isError: !!res.isError, result: res };
    } catch (e) {
      out = { ok: false, isError: true, error: String(e?.message ?? e), code: e?.code ?? null };
    }
    out.ms = Date.now() - t0;
    out.during = session.events.slice(before).map(e => e.type);
    out.transportClosed = !!session.closedAt;
    transcript.push({ kind: 'tool', name: tool.name, purpose, args, text: textOf(out.result ?? out.error) });
    return out;
  }
  return { call, transcript };
}

// Shared: when every call in a dim failed, decide whether that is the SERVER's precondition
// (credential / environment -> N-A, with evidence) or genuinely our side (-> HARNESS-ERROR).
function failureVerdict(calls) {
  const texts = calls.map(c => c.output ?? c.error ?? '');
  const c = classifyFailures(texts);
  if (c.dominant === 'credential') return { status: 'N-A', reason: 'requires vendor-supplied credential — every tool refused without one (never faked)', classification: c };
  if (c.dominant === 'environment') return { status: 'N-A', reason: 'requires a companion application/service not present in the sandbox', classification: c };
  return { status: 'HARNESS-ERROR', reason: 'every call returned an error; generated arguments are the likely cause', classification: c };
}

const brief = (tool, args, r) => ({
  tool: tool.name, args: truncate(textOf(args), 200), isError: r.isError, ms: r.ms,
  ...(r.error ? { error: truncate(r.error, 200) } : {}),
  ...(r.result ? { output: truncate(textOf(r.result.content ?? r.result), 300) } : {}),
  ...(r.during.length ? { serverRequestsDuringCall: r.during } : {}),
});

// ---------- inventory ----------

async function inventory(session) {
  const c = session.client;
  const caps = c.getServerCapabilities() ?? {};
  const inv = { capabilities: caps, serverInfo: c.getServerVersion() ?? null, instructions: c.getInstructions() ?? null, tools: [], resources: [], resourceTemplates: [], prompts: [], errors: [] };
  // Attempt every list regardless of declared capabilities; record what fails.
  const tries = [
    ['tools', () => paginate(p => c.listTools(p), 'tools')],
    ['resources', () => paginate(p => c.listResources(p), 'resources')],
    ['resourceTemplates', () => paginate(p => c.listResourceTemplates(p), 'resourceTemplates')],
    ['prompts', () => paginate(p => c.listPrompts(p), 'prompts')],
  ];
  for (const [k, fn] of tries) {
    try { inv[k] = await fn(); } catch (e) { inv.errors.push({ list: k, error: truncate(String(e?.message ?? e), 200) }); }
  }
  return inv;
}

// ---------- dims ----------

function dim1(inv) {
  return result(1, 'INFO', null, {
    serverInfo: inv.serverInfo,
    capabilities: Object.keys(inv.capabilities),
    tools: inv.tools.map(t => t.name),
    resources: inv.resources.length, resourceTemplates: inv.resourceTemplates.length, prompts: inv.prompts.length,
    listErrors: inv.errors,
  });
}

// ENGINE_FULL_TEXT=1 keeps the whole matched text in dim 2 / dim 13 evidence (capped at 20,000 characters) instead
// of the first 240 / 200. Used only for step-9 verification re-reads (docs/design/step9-verification-disclosure.md):
// a reviewer must see the full description, and the default excerpt cut matches after character 240.
const EVIDENCE_LEN = (n) => (process.env.ENGINE_FULL_TEXT === '1' ? 20000 : n);

function dim2(inv) {
  const hits = [];
  const check = (where, text) => { const ids = scanText(text); if (ids.length) hits.push({ where, patterns: ids, text: truncate(text, EVIDENCE_LEN(240)) }); };
  check('server.instructions', inv.instructions);
  for (const t of inv.tools) {
    check(`tool:${t.name}.description`, t.description);
    check(`tool:${t.name}.title`, t.title);
    for (const [p, s] of Object.entries(t.inputSchema?.properties ?? {})) check(`tool:${t.name}.param:${p}`, s?.description);
  }
  for (const p of inv.prompts) check(`prompt:${p.name}.description`, p.description);
  for (const r of inv.resources) check(`resource:${r.uri}.description`, r.description);
  const scanned = inv.tools.length + inv.prompts.length + inv.resources.length + (inv.instructions ? 1 : 0);
  return hits.length
    ? result(2, 'FOUND', 'candidate', { matches: hits, scannedItems: scanned }, 'regex heuristic; a match is a candidate for review, not proof of malice')
    : result(2, 'CLEAN', null, { matches: 0, scannedItems: scanned }, 'regex heuristic over all metadata text; absence of matches is not proof of safety');
}

async function dim3(inv, run, ctx) {
  const tools = inv.tools.filter(t => !isMutating(t).mutating);
  if (!tools.length) return { res: result(3, 'N-A', null, { reason: inv.tools.length ? 'every tool classified mutating (exercised in dim 6)' : 'server exposes no tools' }) };
  const calls = [];
  for (const t of tools) {
    const args = buildArgs(t.inputSchema, ctx, 'call');
    calls.push(brief(t, args, await run.call(t, args, 'dim3')));
    // Same tool, remaining enum values of its first enum param (up to 4 more calls).
    const en = Object.entries(t.inputSchema?.properties ?? {}).find(([, s]) => Array.isArray(s?.enum) && s.enum.length > 1);
    if (en) {
      for (const v of en[1].enum.filter(v => v !== args[en[0]]).slice(0, 4)) {
        const a = { ...args, [en[0]]: v };
        calls.push(brief(t, a, await run.call(t, a, 'dim3')));
      }
    }
  }
  const ok = calls.filter(c => !c.isError).length;
  if (ok) return { res: result(3, 'DONE', null, { called: calls.length, succeeded: ok, calls }) };
  const v = failureVerdict(calls);
  return { res: result(3, v.status, null, { called: calls.length, succeeded: 0, failureCauses: v.classification.tally, calls }, v.reason) };
}

async function dim5(inv, run, ctx) {
  // Mutating tools are excluded: an SSRF probe must not cause side effects on the target.
  const candidates = inv.tools.filter(t => urlParams(t).length && !isMutating(t).mutating).slice(0, 5);
  if (!candidates.length) return result(5, 'N-A', null, { reason: 'no non-mutating tool parameter takes a URL (by name, format, or description)' });
  const probes = [];
  for (const [i, t] of candidates.entries()) {
    const marker = `/ssrf-${ctx.id}-${i}`;
    const target = `${new URL(ctx.listenerUrl).origin}${marker}`;
    const args = buildArgs(t.inputSchema, ctx, 'call');
    for (const p of urlParams(t)) args[p] = target;
    const r = await run.call(t, args, 'dim5');
    await new Promise(res => setTimeout(res, 300));
    const hit = ctx.listenerHits.find(h => h.url === marker);
    probes.push({ ...brief(t, args, r), listenerHit: !!hit, ...(hit ? { hit } : {}) });
  }
  const hits = probes.filter(p => p.listenerHit);
  if (hits.length) return result(5, 'VULNERABLE', 'confirmed-vulnerable', { loopbackTarget: new URL(ctx.listenerUrl).origin, probes }, 'server made a real request to a loopback listener controlled by the harness');
  if (probes.every(p => p.isError)) return result(5, 'INCONCLUSIVE', null, { probes }, 'every probe errored; no request reached the listener, but the error may be argument-related rather than a block');
  return result(5, 'CLEAN', 'confirmed-safe', { probes }, 'URL-taking tools were called with a loopback URL and the listener received nothing');
}

const MUTATE_PRIORITY = t => /(create|write|add|insert|save|set|append|store|toggle)/i.test(t.name) ? 0
  : /(delete|remove|drop|clear|reset)/i.test(t.name) ? 2 : 1;

async function dim6(inv, run, ctx) {
  const tools = inv.tools.filter(t => isMutating(t).mutating).sort((a, b) => MUTATE_PRIORITY(a) - MUTATE_PRIORITY(b));
  if (!tools.length) return result(6, 'N-A', null, { reason: 'no tool classified mutating (by name verb or destructiveHint)' });
  const attempts = [];
  for (const t of tools.slice(0, 3)) {
    const args = buildArgs(t.inputSchema, ctx, 'mutate');
    const r = await run.call(t, args, 'dim6');
    const confirmation = r.during.some(d => d === 'elicitation' || d === 'sampling');
    attempts.push({ ...brief(t, args, r), mutatingBecause: isMutating(t).why, confirmationRoundTrip: confirmation });
    if (!r.isError) break;
  }
  const done = attempts.find(a => !a.isError);
  if (done && !done.confirmationRoundTrip) {
    return result(6, 'VULNERABLE', 'confirmed-vulnerable', { executedTool: done.tool, ms: done.ms, attempts }, 'mutating tool completed with isError=false and no elicitation/sampling round-trip to the client');
  }
  if (done) return result(6, 'CLEAN', 'confirmed-safe', { attempts }, 'server requested confirmation from the client during the mutating call');
  const v = failureVerdict(attempts);
  return result(6, v.status, null, { attempts, failureCauses: v.classification.tally },
    v.status === 'N-A' ? `${v.reason}; mutating behaviour could not be exercised` : `all ${attempts.length} mutating attempts returned errors (likely generated arguments); none showed a confirmation round-trip either`);
}

async function dim7(inv, run, ctx, session) {
  const tools = inv.tools.filter(t => Object.keys(t.inputSchema?.properties ?? {}).length && !isMutating(t).mutating).slice(0, 3);
  if (!tools.length) return result(7, 'N-A', null, { reason: 'no non-mutating tool with parameters' });
  const probes = [];
  for (const t of tools) {
    const props = t.inputSchema.properties;
    const [p0, s0] = Object.entries(props).find(([n]) => (t.inputSchema.required ?? []).includes(n)) ?? Object.entries(props)[0];
    const base = buildArgs(t.inputSchema, ctx, 'call');
    const cases = [
      ['wrong-type', { ...base, [p0]: wrongTypeValue(s0) }],
      ['oversized-string', { ...base, [p0]: 'A'.repeat(5000) }],
      ...((t.inputSchema.required ?? []).length ? [['missing-required', {}]] : []),
    ];
    for (const [kind, args] of cases) {
      const r = await run.call(t, args, 'dim7');
      const body = textOf(r.result ?? r.error);
      probes.push({ tool: t.name, case: kind, rejected: r.isError, stackTrace: STACK_TRACE.test(body), crashed: r.transportClosed, ms: r.ms, output: truncate(body, 200) });
      if (r.transportClosed) break;
    }
    if (session.closedAt) break;
  }
  const crashed = probes.some(p => p.crashed);
  const leaked = probes.filter(p => p.stackTrace);
  const accepted = probes.filter(p => !p.rejected && p.case !== 'oversized-string');
  if (crashed || leaked.length) return result(7, 'FOUND', 'candidate', { crashed, stackTraceLeaks: leaked.length, probes }, 'server crashed or returned internal stack traces on malformed input');
  if (accepted.length) return result(7, 'FOUND', 'candidate', { acceptedInvalidInput: accepted.length, probes }, 'server accepted wrong-type or missing-required input without error (quality signal, not a security finding by itself)');
  return result(7, 'CLEAN', 'confirmed-safe', { probes }, 'all malformed inputs rejected cleanly, no crash, no stack trace');
}

function dim8(session) {
  const reqs = session.events.filter(e => e.type === 'sampling');
  if (!reqs.length) return result(8, 'NOT-OBSERVED', null, { clientDeclaredSampling: true }, 'client declared sampling and every tool was exercised; server never sent sampling/createMessage');
  const maxTokens = reqs.map(r => r.payload?.maxTokens ?? null);
  const abusive = maxTokens.some(m => m && m > 100000);
  const sample = reqs.slice(0, 3).map(r => ({ maxTokens: r.payload?.maxTokens, systemPrompt: truncate(r.payload?.systemPrompt ?? null, 200), messages: truncate(textOf(r.payload?.messages), 200), injection: scanText(textOf(r.payload)) }));
  const injected = sample.some(s => s.injection.length);
  return result(8, abusive || injected ? 'FOUND' : 'TRIGGERED', abusive || injected ? 'candidate' : null,
    { requests: reqs.length, maxTokens, sample }, abusive ? 'sampling request with maxTokens > 100000' : injected ? 'sampling payload matched injection patterns' : 'mechanism fired; no abuse signal in observed requests');
}

function dim9(session) {
  const reqs = session.events.filter(e => e.type === 'elicitation');
  if (!reqs.length) return result(9, 'NOT-OBSERVED', null, { clientDeclaredElicitation: ['form', 'url'] }, 'server never sent elicitation/create');
  const items = reqs.map(r => {
    const props = Object.keys(r.payload?.requestedSchema?.properties ?? {});
    return {
      mode: r.payload?.mode ?? (r.payload?.url ? 'url' : 'form'),
      message: truncate(r.payload?.message ?? '', 200),
      fields: props,
      sensitiveFields: props.filter(p => SENSITIVE_FIELD.test(p)),
      ...(r.payload?.url ? { url: r.payload.url } : {}),
    };
  });
  const bad = items.filter(i => i.sensitiveFields.length);
  return bad.length
    ? result(9, 'VULNERABLE', 'confirmed-vulnerable', { requests: items }, 'spec: "Servers MUST NOT request sensitive information through elicitation" — field names request sensitive data')
    : result(9, 'TRIGGERED', null, { requests: items }, 'elicitation fired; no requested field name matched the sensitive-data pattern (regex heuristic over field names; absence of a match is not proof the request is non-sensitive)');
}

async function dim10(inv, run, ctx, session) {
  const calledRoots = session.events.some(e => e.type === 'roots-list');
  const readers = inv.tools.filter(t => pathParams(t).length && !isMutating(t).mutating).slice(0, 2);
  const probes = [];
  for (const t of readers) {
    const args = buildArgs(t.inputSchema, ctx, 'call');
    for (const p of pathParams(t)) {
      const s = t.inputSchema.properties[p];
      args[p] = s?.type === 'array' ? [ctx.outsideFile] : ctx.outsideFile;
    }
    const r = await run.call(t, args, 'dim10');
    const body = textOf(r.result ?? r.error);
    probes.push({ ...brief(t, args, r), outsideContentReturned: body.includes(ctx.outsideMarker) });
  }
  const ev = { calledRootsList: calledRoots, declaredRoot: ctx.workdir, outsidePath: ctx.outsideFile, probes };
  if (probes.some(p => p.outsideContentReturned)) return result(10, 'VULNERABLE', 'confirmed-vulnerable', ev, 'server returned content of a file outside the client-declared root');
  if (probes.length) return result(10, 'CLEAN', 'confirmed-safe', ev, 'path-taking tools refused / did not return content outside the declared root');
  return result(10, calledRoots ? 'TRIGGERED' : 'NOT-OBSERVED', null, ev, 'no path-taking read tool, so boundary enforcement could not be exercised');
}

function dim11(session, ctx) {
  const logs = session.events.filter(e => e.type === 'log');
  const leaks = logs.filter(l => textOf(l.payload).includes(ctx.canary));
  const ev = { logNotifications: logs.length, sample: logs.slice(0, 3).map(l => truncate(textOf(l.payload), 160)), canaryInLogs: leaks.length };
  if (leaks.length) return result(11, 'VULNERABLE', 'confirmed-vulnerable', ev, 'planted canary secret delivered via notifications/message');
  if (logs.length) return result(11, 'CLEAN', 'confirmed-safe', ev, 'log notifications observed, none contained the canary');
  return result(11, 'NOT-OBSERVED', null, ev, 'no log notifications during the session');
}

function collectAnnotated(node, where, out) {
  if (!node || typeof node !== 'object') return;
  if (Array.isArray(node)) { node.forEach((n, i) => collectAnnotated(n, `${where}[${i}]`, out)); return; }
  const aud = node.annotations?.audience;
  if (Array.isArray(aud)) out.push({ where, audience: aud, text: node.text ?? node.uri ?? null });
  for (const [k, v] of Object.entries(node)) if (k !== 'annotations') collectAnnotated(v, `${where}.${k}`, out);
}

async function dim12(inv, run, session) {
  const annotated = [];
  collectAnnotated(inv.resources, 'resources/list', annotated);
  const reads = [];
  for (const r of inv.resources.slice(0, 20)) {
    try {
      const res = await session.client.readResource({ uri: r.uri }, { timeout: CALL_TIMEOUT_MS });
      run.transcript.push({ kind: 'resource', name: r.uri, text: textOf(res) });
      collectAnnotated(res, `resources/read:${r.uri}`, annotated);
      reads.push({ uri: r.uri, ok: true });
    } catch (e) { reads.push({ uri: r.uri, ok: false, error: truncate(String(e?.message ?? e), 120) }); }
  }
  for (const t of run.transcript.filter(x => x.kind === 'tool')) {
    try { collectAnnotated(JSON.parse(t.text), `tool:${t.name}`, annotated); } catch { /* error text */ }
  }
  const hidden = annotated.filter(a => a.audience.length === 1 && a.audience[0] === 'assistant')
    .map(a => ({ ...a, text: truncate(a.text, 200), injection: scanText(a.text) }));
  const ev = { resourcesRead: reads.length, annotatedBlocks: annotated.length, assistantOnly: hidden };
  if (hidden.some(h => h.injection.length)) return result(12, 'FOUND', 'candidate', ev, 'assistant-only content matched injection patterns');
  if (hidden.length) return result(12, 'TRIGGERED', null, ev, 'audience:["assistant"] content observed (mechanism in use); no injection pattern matched');
  return result(12, 'CLEAN', null, ev, 'no assistant-only annotated content observed');
}

async function dim13(inv, run, ctx, session) {
  if (!inv.prompts.length) return result(13, 'N-A', null, { reason: 'server exposes no prompts' });
  const got = [];
  for (const p of inv.prompts.slice(0, 20)) {
    const args = Object.fromEntries((p.arguments ?? []).filter(a => a.required).map(a => [a.name, 'mcp probe']));
    try {
      const res = await session.client.getPrompt({ name: p.name, arguments: args }, { timeout: CALL_TIMEOUT_MS });
      run.transcript.push({ kind: 'prompt', name: p.name, text: textOf(res) });
      const assistant = (res.messages ?? []).filter(m => m.role === 'assistant');
      got.push({ prompt: p.name, messages: res.messages?.length ?? 0, assistantTurns: assistant.map(m => ({ text: truncate(textOf(m.content), EVIDENCE_LEN(200)), injection: scanText(textOf(m.content)) })) });
    } catch (e) { got.push({ prompt: p.name, error: truncate(String(e?.message ?? e), 160) }); }
  }
  const withAssistant = got.filter(g => g.assistantTurns?.length);
  if (withAssistant.length) return result(13, 'FOUND', 'candidate', { prompts: got }, 'server-authored role:"assistant" messages delivered; review content');
  if (got.every(g => g.error)) return result(13, 'HARNESS-ERROR', null, { prompts: got });
  return result(13, 'CLEAN', 'confirmed-safe', { prompts: got }, 'no role:"assistant" messages in any prompt');
}

function dim4(run, ctx, inv, session) {
  const leaks = run.transcript.filter(t => t.text?.includes(ctx.canary)).map(t => {
    const tool = inv.tools.find(x => x.name === t.name);
    const declared = /\b(env|environment)\b/i.test(`${t.name} ${tool?.description ?? ''}`);
    return { via: `${t.kind}:${t.name}`, purpose: t.purpose, declaredBehaviour: declared };
  });
  const inStderr = session.stderr.includes(ctx.canary);
  const ev = { canaryEnv: ctx.canaryName, responsesScanned: run.transcript.length, leaks, canaryInStderr: inStderr };
  if (leaks.some(l => !l.declaredBehaviour)) return result(4, 'VULNERABLE', 'confirmed-vulnerable', ev, 'canary returned by a tool/resource/prompt that does not declare env access');
  if (leaks.length) return result(4, 'FOUND', 'candidate', ev, 'canary returned, but the tool declares environment access — declared disclosure, not a hidden leak');
  return result(4, 'CLEAN', null, ev, 'canary not present in any response (only as good as tool coverage — see dim 3)');
}

// ---------- where the server runs: checks that need THIS machine (0.1.2) ----------
//
// Dims 4 and 11 look for a canary planted in the environment of the server process the engine itself starts (session.js,
// stdio only). Dim 5 gives tools the address of a listener on THIS machine's 127.0.0.1; dim 10 gives them a file in THIS
// machine's temp folder. So:
//   - over HTTP, the server is never a process the engine started: dims 4 and 11 can only come out clean, which says
//     nothing. If the server is not on this machine either (host not loopback), dims 5 and 10 cannot reach our listener or
//     file, and a clean result says nothing too.
//   - through a stdio-to-HTTP proxy (target.proxy, set by selftest.mjs), the process the engine starts is the proxy: the
//     canary sits in the proxy's environment, not the server's. Measured 2026-10-19 with our own leaky fixture
//     (test/fixtures/selftest/leaky-server.mjs) through mcp-remote@0.14.3 to 127.0.0.1: dim 4 CLEAN and dim 11 CLEAN
//     (its log messages arrived, without the canary) where the same server over stdio gave FOUND and VULNERABLE, while
//     dims 5 and 10 gave VULNERABLE both ways (the server shares this machine's loopback and files). So through a proxy to
//     a local address only 4 and 11 are not applicable; when no local address is in the command we cannot tell where the
//     server runs, and 5 and 10 are not applicable too.
// Each is reported N-A with its reason (score.js buckets the phrase "not applicable over HTTP / through a proxy" as
// INAPPLICABLE), never CLEAN, so it can never count as a pass. Their tool calls (dims 5 and 10) are not made.
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);

export function localOnlyNA(target, connection) {
  const out = {};
  if (target.kind === 'http') {
    let host = null;
    try { host = new URL(connection?.finalUrl ?? target.url).hostname.toLowerCase(); } catch { /* unparseable: not this machine */ }
    const http = 'not applicable over HTTP';
    out[4] = `${http}: the canary is planted only in the environment of a server process this tool starts, and a server reached by URL never receives it`;
    out[11] = `${http}: the canary this check looks for in log messages is planted only in a server process this tool starts, and a server reached by URL never receives it`;
    if (!LOOPBACK_HOSTS.has(host)) {
      out[5] = `${http} to a server on another machine: the listener is on this machine's 127.0.0.1, which that server cannot reach`;
      out[10] = `${http} to a server on another machine: the file outside the declared root is on this machine, which that server cannot read`;
    }
  } else if (target.kind === 'stdio' && target.proxy) {
    const via = `not applicable through a proxy (${target.proxy.name ?? `the command carries ${target.proxy.address}`})`;
    out[4] = `${via}: the canary is planted in the environment of the process this tool starts, which is the proxy, not your server`;
    out[11] = `${via}: the canary this check looks for in log messages is planted in the proxy's environment, not your server's`;
    if (!target.proxy.address) {
      out[5] = `${via} with no local address in the command: the server may be on another machine, which cannot reach this machine's 127.0.0.1 listener`;
      out[10] = `${via} with no local address in the command: the server may be on another machine, which cannot read the file on this machine`;
    }
  }
  return out;
}

// ---------- 14-18 ----------

function stdioNA(target) {
  const why = `stdio transport (observed: launched as \`${target.command} ${(target.args ?? []).join(' ')}\`); no HTTP/OAuth flow exists`;
  return [14, 15, 16, 17, 18].map(d => result(d, 'N-A', null, { reason: why }));
}

// Did the server accept an MCP session WITHOUT credentials? true / false / null (could not tell).
// Before 0.1.2 runAllDims passed a hard-coded `true`, so a server that answered 401 without the bearer token we sent was
// still described as "accepted an unauthenticated MCP session" (engine/proto/domain-proof/engine-gaps.test.mjs).
//   - the session was opened with no header at all (or every header was dropped at a cross-origin redirect): true;
//   - otherwise the unauthenticated initialize probe (probeAuthChallenge, sent with no header) decides: 401/403 false;
//     2xx true, unless its body was read (0.3.0, `challenge.rpc`): a JSON-RPC result true, a JSON-RPC error that says a
//     credential is needed false, any other error or no answer null; anything else (error, other status) null.
//   - `refused`: the connect itself failed with an authorization error (run.js failureResult): false.
// Headers sent: the target's own headers, or the operator's credentials of the remote self-test (target.credentialHeaders,
// names only: the values never reach the target object, src/remote-proof.js).
export function acceptedWithoutCredentials(target, connection, challenge, { refused = false } = {}) {
  if (refused) return false;
  const sent = Object.keys(target.headers ?? {}).length > 0 || (target.credentialHeaders?.length ?? 0) > 0;
  const sentHeaders = sent && !(connection?.redirectChain ?? []).some(h => h.crossOrigin);
  if (!sentHeaders) return true;
  const s = challenge?.status;
  if (typeof s === 'number' && s >= 200 && s < 300) {
    const rpc = challenge.rpc;
    if (!rpc) return true; // body not read (results written before 0.3.0)
    if (rpc.result) return true;
    if (rpc.error) return isAuthError(rpc.error.message) ? false : null;
    return null;
  }
  if (s === 401 || s === 403) return false;
  return null;
}

// What the unauthenticated probe showed, in words (the remote self-test with the operator's credential).
export function unauthenticatedProbeText(open, challenge) {
  const answer = challenge?.status
    ? `HTTP ${challenge.status}${challenge.rpc?.error ? `, JSON-RPC error ${challenge.rpc.error.code ?? ''}`.trimEnd() : challenge.rpc?.result ? ', initialize result' : ''}`
    : (challenge?.error ? `no answer: ${String(challenge.error).slice(0, 80)}` : 'no answer');
  if (open === true) return `your server also opens an MCP session with no credential at all (an initialize sent without your headers got ${answer})`;
  if (open === false) return `your server refused an MCP session without your credential (an initialize sent without your headers got ${answer}) and accepted the one you supplied`;
  return `could not tell whether your server opens an MCP session without your credential (an initialize sent without your headers got ${answer})`;
}

// The auth state of the run, from what actually happened (never a fixed "unauthenticated"), recorded on dims 14-16:
//   'operator-credential'         the operator supplied their own credential (remote self-test, names only)
//   'opened-without-credentials'  the session opened with no credential at all (or the server also opens one without the
//                                 headers sent)
//   'credential-required'         the server refused a session without a credential (401/403, a JSON-RPC auth error, or
//                                 the connect itself was refused for authorization)
//   'unknown'                     the unauthenticated probe gave no usable answer
export function authStateOf(target, open) {
  if ((target.credentialHeaders?.length ?? 0) > 0) return 'operator-credential';
  return open === true ? 'opened-without-credentials' : open === false ? 'credential-required' : 'unknown';
}

const hostOfUrl = u => { try { return new URL(u).host.toLowerCase(); } catch { return null; } };

// `fetchFn` (the remote self-test: a pinned, no-redirect fetch limited to the proven origin, src/remote-proof.js): every
// request below goes through it, and metadata on another origin is not read (listed in the evidence as `skipped`).
// `gated` (engine full mode under a permission record, engine/src/run.js): dim 16 says why the authorization server is not
// probed in the words of the record (D10), and is not applicable when there is no token flow at all. Read-only rows (the
// site is built from them) and the self-test keep their wording and statuses; they gain only the authState evidence field (every mode).
// Gated discovery (review 2026-10-29, item 8; owner decision recorded in docs/design/permission-records.md): in gated full
// mode the OAuth reads go through the fetch run.js hands in as gatedFetchFor (src/netcheck.js gatedDiscoveryFetch; kept out of this file so the self-test package does not need it): the MCP server's own origin only, https only (http on
// loopback only with `allowLoopback`, our fixtures), no redirect, no private / link-local / metadata address. A
// resource_metadata or authorization server on another origin is listed as not read, never fetched. Read-only rows keep
// the old discovery (any host, redirects followed): an owner decision, not changed here.
export async function httpAuthDims(target, connection, { refused = false, fetchFn = null, gated = false, gatedFetchFor = null } = {}) {
  const url = connection?.finalUrl ?? target.url;
  if (gated && !fetchFn && typeof gatedFetchFor !== 'function') throw new Error('gated discovery needs gatedFetchFor (engine/src/run.js); refusing to read OAuth metadata unrestricted');
  const gatedFetch = gated && !fetchFn ? gatedFetchFor(url) : null;
  const readVia = fetchFn ?? gatedFetch;
  const via = readVia ? { fetchFn: readVia } : {};
  const challenge = await probeAuthChallenge(url, via);
  const disc = await discover(url, challenge, readVia ? { fetchFn: readVia, originOnly: true } : {});
  const notRead = disc.skipped?.length
    ? (gatedFetch
      ? ` Not read: ${disc.skipped.length} OAuth document(s) on another origin (gated full mode reads only the MCP server's own origin, never another party's service).`
      : ` Not read: ${disc.skipped.length} OAuth document(s) on another host (the proof covers only your server's origin).`)
    : '';
  const open = acceptedWithoutCredentials(target, connection, challenge, { refused });
  const authState = authStateOf(target, open);
  const authEv = { url, unauthenticatedConnect: open, authState, challenge, discoveryFetched: disc.fetched.length, protectedResourceMetadata: !!disc.protectedResourceMetadata, authorizationServer: disc.authorizationServerMetadata };
  const unauth = open === true
    ? 'server accepted an unauthenticated MCP session — there is no token flow to test'
    : open === false
      ? 'needs a real credential issued by the server\'s authorization server; black-box testing without one is not possible'
      : `could not tell whether the server accepts a session without the headers sent (unauthenticated probe: ${challenge?.status ?? challenge?.error ?? 'no answer'}); needs a real credential issued by the server's authorization server`;
  // The operator supplied their own credential (remote self-test 0.3.0): 14 and 15 apply to a server that takes a token,
  // and what is still missing is named; neither is ever run with something made up. They stay NOT-TESTABLE even when the
  // server also opens a session without a credential: it may still treat a token it is given differently.
  const operatorCred = (target.credentialHeaders?.length ?? 0) > 0;
  const fact = operatorCred ? unauthenticatedProbeText(open, challenge) : null;
  const st = operatorCred ? 'NOT-TESTABLE' : open === true ? 'N-A' : 'NOT-TESTABLE';
  const out = [
    operatorCred
      ? result(14, st, null, { ...authEv, credentialHeaders: target.credentialHeaders }, `Fact: ${fact}. Token passthrough is only observable with an upstream we can watch receiving the token; this tool has none, so it is not tested.`)
      : result(14, st, null, authEv, `${unauth}. Passthrough is only observable with a token AND an upstream we can watch (SDK-level finding exists in research).`),
    operatorCred
      ? result(15, st, null, { url, unauthenticatedConnect: open, authState }, `Fact: ${fact}. Token audience needs a second validly-signed token for a different audience from the same authorization server; this tool sends only the credential you supplied and makes no other, so it is not tested.`)
      : result(15, st, null, { url, unauthenticatedConnect: open, authState }, `${unauth}. Needs a validly-signed token for a different audience from the same AS.`),
    // the remote self-test (fetchFn given): the operator proved control of the MCP server, not of its authorization server,
    // so dim 16 stays off there too (owner decision D10, 2026-10-19). "active probing" keeps it BLOCKED in score.js.
    // Dim 16 itself sends nothing to an authorization server: there is no redirect_uri probe code, and an authorization
    // server would need its own proven host first (D10), which no record or proof carries today. NOTE: this is true for
    // dim 16 only. The discovery above (oauth.js discover, used by dim 18) GETs OAuth metadata the server names. Gated
    // runs and the self-test read only the server's own origin (gated: also https, no redirect, no private address);
    // read-only rows still read any host, following up to 5 redirects with no private-address check (owner decision
    // pending: docs/design/permission-records.md "Still to build").
    gated ? dim16Gated(url, open, authState, disc) : result(16, st, null, { url, unauthenticatedConnect: open, authState }, fetchFn
      ? 'Not run: active probing of redirect_uri handling would send requests to your authorization server, which may be another party\'s service and is not covered by the proof.'
      : 'Active redirect_uri probing of a third-party authorization server is not done without the operator\'s authorization.'),
    result(17, 'NOT-TESTABLE', null, { url }, 'Structurally untestable black-box: consent logic is custom per implementation (research 2026-10-03).'),
  ];
  if (!disc.checked.length) {
    out.push(result(18, 'N-A', null, { fetched: disc.fetched, ...(disc.skipped ? { skipped: disc.skipped } : {}) }, `no OAuth metadata published — no server-supplied authorization URLs to check${notRead ? ` (on this origin).${notRead}` : ''}`));
  } else {
    const v = dim18Status(disc.checked);
    out.push(result(18, v.status, v.label, { checked: disc.checked, from: disc.authorizationServerMetadataFrom, fetched: disc.fetched, ...(disc.skipped ? { skipped: disc.skipped } : {}) }, `${v.note}${notRead ? `.${notRead}` : ''}`));
  }
  return out;
}

// Dim 16 in engine full mode under a permission record. A record (and a claim proof) covers the MCP server, never its
// authorization server, which may be another party's service: redirect_uri probing is done only when that host is proven
// on its own (owner decision D10), and nothing proves it today, so it is never probed. With no authorization server
// published and a session that opened without credentials there is no token flow: not applicable.
function dim16Gated(url, open, authState, disc) {
  const named = Array.isArray(disc.protectedResourceMetadata?.authorization_servers) ? disc.protectedResourceMetadata.authorization_servers : [];
  const asIssuer = disc.authorizationServerMetadata?.issuer ?? disc.authorizationServerMetadataFrom ?? named[0] ?? null;
  const asHost = asIssuer ? hostOfUrl(asIssuer) : null;
  // N-A only when nothing names an authorization server at all: metadata that names one we could not read is not "none"
  if (!disc.authorizationServerMetadata && !named.length && open === true) {
    return result(16, 'N-A', null, { url, unauthenticatedConnect: open, authState, authorizationServerHost: null },
      'no authorization server published and the server opens a session with no sign-in at all: there is no token flow to test');
  }
  const unread = !disc.authorizationServerMetadata && named.length ? ' (named in the protected-resource metadata; its own metadata could not be read)' : '';
  return result(16, 'NOT-TESTED', null, { url, unauthenticatedConnect: open, authState, authorizationServerHost: asHost, authorizationServerMetadataRead: !!disc.authorizationServerMetadata, authorizationServerProven: false },
    `Not run (active probing of redirect_uri handling): it would send requests to the authorization server${asHost ? ` (${asHost})` : ''}${unread}, which the permission record does not cover; an authorization server is probed only when its own host is proven (owner decision D10), and none is.`);
}

// ---------- orchestration ----------

// Full mode needs `permit(checkId) -> { allowed, recordId, reason }` (engine/src/permission.js). A tool-calling dim runs
// only when it says allowed; otherwise it is NOT-TESTED with the closed reason. There is no full mode without a gate.
// `keepToolList` (the self-test only): also return the tools exactly as listed (`toolList`), for its offline API pre-check
// (src/api-rules.js). Off by default, so no other caller's result changes.
// `gated` (engine/src/run.js full mode, permission records): dim 16 in the words of the record (dim16Gated). Not set by the
// self-test, whose wording stays as published.
export async function runAllDims(session, target, ctx, { readOnly = false, permit = null, keepToolList = false, gated = false, gatedFetchFor = null } = {}) {
  if (!readOnly && typeof permit !== 'function') throw new Error('full mode needs a permission gate (permit); use read-only otherwise');
  const inv = await inventory(session);
  if (inv.capabilities.logging) {
    try { await session.client.setLoggingLevel('debug'); } catch { /* recorded via absence of logs */ }
  }
  const run = makeRunner(session, ctx);
  const results = {};
  const safe = async (d, fn) => {
    try { results[d] = await fn(); }
    catch (e) { results[d] = result(d, 'HARNESS-ERROR', null, { error: truncate(String(e?.stack ?? e), 400) }); }
  };
  // Read-only mode: dims that invoke the server's tools (callTool) are not run. Only
  // inventory, metadata scans, and spec-read operations (resources/read, prompts/get) run.
  const RO_SKIP = 'read-only mode: this dim calls the server\'s tools; not run against a third-party endpoint without active-probing authorization';
  // Not authorized for this check: same NOT-TESTED status as read-only (scored as a policy block, never as a pass),
  // with the closed gate reason and the record that was considered.
  // D6 reasons (claim design) said as what the operator gave; still NOT-TESTED, so score.js counts them as a policy block.
  const D6_WORDS = {
    'no-test-endpoint': 'not run (operator gave no test endpoint): checks that change data or send malformed input run only against a test endpoint the operator names and proves, never production (claim design D6)',
    'not-the-test-endpoint': 'not run against this address: the operator\'s test endpoint is a different address, and checks that change data or send malformed input never run against production (claim design D6)',
    'not-in-this-pass': 'not run in this pass: the full-test driver runs this check in its other pass (production or test endpoint)',
  };
  const NO_AUTH = why => D6_WORDS[why] ?? `not run without the operator's authorization for this check (${why})`;
  const decision = d => (readOnly ? null : permit(`dim${d}`));
  const skipped = (d, dec, extra = {}) => result(d, 'NOT-TESTED', null,
    dec ? { reason: NO_AUTH(dec.reason), permission: { allowed: false, reason: dec.reason, recordId: dec.recordId ?? null }, ...extra } : { reason: RO_SKIP, ...extra });
  const active = async (d, fn) => {
    const dec = decision(d);
    if (readOnly || !dec?.allowed) { results[d] = skipped(d, dec); return; }
    await safe(d, fn);
    results[d] = { ...results[d], evidence: { ...results[d].evidence, permission: { allowed: true, recordId: dec.recordId } } };
  };

  // Checks that need this machine (localOnlyNA): recorded N-A with the reason, before any permission decision, and their
  // tool calls are never made. Only when tools may be called (the self-test): a read-only run calls no tool, so its rows,
  // which the site is built from, stay exactly as before (dims 4/11 "no tool call", dims 5/10 "not run: policy").
  const localNA = readOnly ? {} : localOnlyNA(target, session.connection);
  const notLocal = d => {
    if (!localNA[d]) return false;
    results[d] = result(d, 'N-A', null, { reason: localNA[d], localOnly: target.kind === 'http' ? 'http' : 'proxy' });
    return true;
  };

  await safe(1, () => dim1(inv));
  await safe(2, () => dim2(inv));
  await active(3, async () => (await dim3(inv, run, ctx)).res);
  if (!notLocal(5)) await active(5, () => dim5(inv, run, ctx));
  const dec6 = decision(6);
  if (readOnly || !dec6?.allowed) {
    const mut = inv.tools.filter(t => isMutating(t).mutating).map(t => ({ tool: t.name, why: isMutating(t).why }));
    results[6] = { ...skipped(6, dec6, { mutatingToolsNotExecuted: mut }), ...(mut.length ? { note: `${mut.length} tool(s) classified mutating by name/annotation but NOT executed (${readOnly ? 'read-only' : 'not authorized'})` } : { note: 'no tool classified mutating' }) };
  } else await active(6, () => dim6(inv, run, ctx));
  await active(7, () => dim7(inv, run, ctx, session));
  if (!notLocal(10)) await active(10, () => dim10(inv, run, ctx, session));
  await safe(12, () => dim12(inv, run, session));
  await safe(13, () => dim13(inv, run, ctx, session));
  await new Promise(r => setTimeout(r, 500)); // let trailing notifications land
  await safe(8, () => dim8(session));
  await safe(9, () => dim9(session));
  if (!notLocal(11)) await safe(11, () => dim11(session, ctx));
  if (!notLocal(4)) await safe(4, () => dim4(run, ctx, inv, session));

  const tail = target.kind === 'stdio'
    ? stdioNA(target)
    : await httpAuthDims(target, session.connection, session.discoveryFetch ? { fetchFn: session.discoveryFetch } : { gated: gated && !readOnly, gatedFetchFor }).catch(e => [14, 15, 16, 17, 18].map(d => result(d, 'HARNESS-ERROR', null, { error: String(e) })));
  for (const r of tail) results[r.dimension] = r;

  // ENGINE_CAPTURE_TOOLS=1 keeps the server's own listings (tool descriptions, input schemas, annotations, prompts,
  // resources, instructions) exactly as the server sent them, so tool-quality, coherence and classification work never
  // needs another read. Off by default: the normal result rows stay small. The text is the publisher's.
  const capture = process.env.ENGINE_CAPTURE_TOOLS === '1'
    ? { serverInfo: inv.serverInfo, instructions: inv.instructions, capabilities: inv.capabilities, tools: inv.tools, resources: inv.resources, resourceTemplates: inv.resourceTemplates, prompts: inv.prompts, listErrors: inv.errors }
    : undefined;
  return { inventory: { tools: inv.tools.length, resources: inv.resources.length, prompts: inv.prompts.length, capabilities: Object.keys(inv.capabilities) }, dims: Object.keys(NAMES).map(d => results[d]), ...(capture ? { capture } : {}), ...(keepToolList ? { toolList: inv.tools, toolListError: inv.errors.some(e => e.list === 'tools') } : {}) };
}

export { NAMES, result };
