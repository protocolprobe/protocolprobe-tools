// Evidence-backed scoring. Design: docs/scoring-model.md (signed off 2026-10-04).
//
// Non-negotiables encoded here:
//   1. No single 0-100 safety score, and no letter grade. The headline is a categorical verdict;
//      coverage travels with it as a plain fraction PLUS the reason it is not higher.
//   2. BLOCKED never reads as a pass, and is never counted in a "passed N checks" tally.
//   3. Dependent-evidence rule: a dim whose verdict presupposes activity we never achieved is
//      BLOCKED, not CLEAN. This is the rule that takes quickbooks-mcp from an apparent 9/12 to a
//      true 2/12 — see the guard test in test/engine.test.js, which must not be weakened.
//   4. The passing verdict is scoped ("NO FINDINGS (core checks exercised)"), never a bare "clean",
//      and it names what was not exercised.
//   5. UNPROVEN is split by cause: our own policy vs the vendor's credential wall. One is a
//      statement about us, the other about the server.

const DIMS = 18;

// Structurally cannot apply to this server vs. applicable-but-we-could-not-test.
// "not applicable over HTTP / through a proxy": dims 4, 5, 10, 11 when the server is not the process the engine started
// (dims.js localOnlyNA, scoring model 1.1.0). Checked after CREDENTIAL/POLICY/ENVIRONMENT, so its wording avoids those words.
const STRUCTURAL = /stdio transport|no HTTP\/OAuth flow|no tool classified mutating|every tool classified mutating|exposes no prompts|exposes no tools|no non-mutating tool|no path-taking|there is no token flow to test|no OAuth metadata published|no URL published in the OAuth metadata|not applicable over HTTP|not applicable through a proxy/i;
const POLICY = /read-only mode|without the operator'?s? authorization|active probing/i;
const CREDENTIAL = /credential|requires authorization|no credential supplied|needs a real credential/i;
const ENVIRONMENT = /companion application|not present in the sandbox/i;

// What each dim's verdict presupposes. 'tool' = at least one successful tool call;
// 'read' = a successful tool call OR a resource/prompt read (the dim inspects returned content).
// Dims 1, 2, 13-18 are independent: inventory, metadata text, transport and published OAuth facts.
const BASIS = { 3: 'tool', 4: 'tool', 5: 'tool', 6: 'tool', 7: 'tool', 8: 'tool', 9: 'tool', 10: 'tool', 11: 'tool', 12: 'read' };

const AFFIRMATIVE = new Set(['CLEAN', 'NOT-OBSERVED', 'INFO', 'DONE', 'TRIGGERED']);
const OBSERVED_BAD = new Set(['VULNERABLE', 'FOUND']);

// Count tool calls that actually executed, across every dim that records calls.
export function countSuccessfulToolCalls(result) {
  let n = 0;
  for (const d of result.dims ?? []) {
    const e = d.evidence ?? {};
    for (const arr of [e.calls, e.attempts, e.probes]) {
      if (Array.isArray(arr)) n += arr.filter(c => c && c.isError === false).length;
    }
  }
  return n;
}

export function countReads(result) {
  const d12 = (result.dims ?? []).find(d => d.dimension === 12);
  const d13 = (result.dims ?? []).find(d => d.dimension === 13);
  const reads = d12?.evidence?.resourcesRead ?? 0;
  const prompts = Array.isArray(d13?.evidence?.prompts) ? d13.evidence.prompts.filter(p => !p.error).length : 0;
  return reads + prompts;
}

function blockedCause(why) {
  if (CREDENTIAL.test(why)) return 'credential';
  if (POLICY.test(why)) return 'policy';
  if (ENVIRONMENT.test(why)) return 'environment';
  return 'harness';
}

/**
 * Bucket one dim: EVIDENCE (we observed it) / BLOCKED (applicable, untested) /
 * INAPPLICABLE (structurally cannot apply). Applies the dependent-evidence rule.
 */
export function bucketDim(dim, { toolCalls, reads }) {
  const why = `${dim.evidence?.reason ?? ''} ${dim.note ?? ''}`;
  if (dim.status === 'BROKEN-DEPENDENCY') return { bucket: 'BLOCKED', cause: 'broken-dependency', reason: dim.note ?? 'package does not install cleanly' };
  if (dim.status === 'N-A') {
    if (CREDENTIAL.test(why) || POLICY.test(why) || ENVIRONMENT.test(why)) return { bucket: 'BLOCKED', cause: blockedCause(why), reason: why.trim() };
    if (STRUCTURAL.test(why)) return { bucket: 'INAPPLICABLE', reason: why.trim() };
    return { bucket: 'BLOCKED', cause: 'harness', reason: why.trim() || 'not applicable, reason unrecorded' };
  }
  if (['NOT-TESTABLE', 'NOT-TESTED', 'HARNESS-ERROR', 'INCONCLUSIVE'].includes(dim.status)) {
    return { bucket: 'BLOCKED', cause: dim.status === 'NOT-TESTED' ? 'policy' : blockedCause(why), reason: why.trim() || dim.status };
  }
  // Observing bad behaviour is always an observation — never downgraded.
  if (OBSERVED_BAD.has(dim.status)) return { bucket: 'EVIDENCE' };
  if (AFFIRMATIVE.has(dim.status)) {
    const need = BASIS[dim.dimension];
    const satisfied = !need || (need === 'tool' ? toolCalls > 0 : toolCalls > 0 || reads > 0);
    if (!satisfied) {
      return { bucket: 'BLOCKED', cause: 'no-basis', unsupported: true,
        reason: need === 'tool' ? 'unsupported: no tool call succeeded, so this verdict has no behavioural basis'
                                : 'unsupported: nothing was read or called, so this verdict has no behavioural basis' };
    }
    return { bucket: 'EVIDENCE' };
  }
  return { bucket: 'BLOCKED', cause: 'harness', reason: dim.status };
}

// CLEAN-equivalent requires these to have real evidence. Dim 5 is deliberately EXCLUDED:
// INCONCLUSIVE is common and unattributable, and a core set that makes everything UNPROVEN
// communicates nothing. The passing verdict is therefore scoped, never a bare "clean".
export const CORE_STDIO = [2, 3, 4, 6, 7];
export const CORE_REMOTE = [2, 3, 4, 6, 7, 18];

/**
 * The open-server fact is a FINDING, not connection metadata: a server that hands an anonymous
 * client its inventory — mutating tools included — should say so in the verdict line.
 */
export function exposureFindings(result) {
  const out = [];
  if (result.target?.kind !== 'http' || result.outcome !== 'tested') return out;
  // Since 2026-10-19 dim 14 records whether the session really needed no credential (dims.js acceptedWithoutCredentials):
  // false (the server answers 401/403 without the headers we sent) or null (could not tell) is not a zero-credential
  // session. Rows written before that carry the old hard-coded true and are read as before.
  const d14 = (result.dims ?? []).find(d => d.dimension === 14);
  if (d14?.evidence && 'unauthenticatedConnect' in d14.evidence && d14.evidence.unauthenticatedConnect !== true) return out;
  const tools = result.inventory?.tools ?? 0;
  const d6 = (result.dims ?? []).find(d => d.dimension === 6);
  const mutating = (d6?.evidence?.mutatingToolsNotExecuted ?? []).map(m => m.tool);
  const mutatingCount = mutating.length || (d6?.status === 'VULNERABLE' ? 1 : 0);
  out.push({
    id: 'unauthenticated-access',
    severity: mutatingCount > 0 ? 'high' : 'medium',
    confirmed: true,
    summary: mutatingCount > 0
      ? `accepted an MCP session with ZERO credentials and exposed ${tools} tools, ${mutatingCount} of them state-changing`
      : `accepted an MCP session with ZERO credentials and exposed ${tools} tools`,
    evidence: { url: result.target.url, tools, mutatingTools: mutating, resources: result.inventory?.resources ?? 0, prompts: result.inventory?.prompts ?? 0 },
  });
  return out;
}

const DISPLAY = {
  VULNERABLE: 'VULNERABLE',
  EXPOSED: 'EXPOSED (unauthenticated)',
  DEFECTIVE: 'DEFECTIVE',
  // "we never got a session" is a different statement from "we got a session but could not test
  // these dims" — found by auditing the real data, where 35 connect-failures were sharing the
  // UNPROVEN verdict with 9 genuinely-tested-but-blocked servers.
  UNREACHABLE: 'UNREACHABLE (no session established)',
  'UNPROVEN-CREDENTIAL': 'UNPROVEN (credential-gated)',
  // Worded as OUR deliberate choice, not a coverage failure: we decided (CLAUDE.md, 2026-10-04)
  // not to probe third-party servers without the operator's authorization. This is a permanent
  // structural share of the catalogue, so the label must not imply the server resisted testing.
  'UNPROVEN-POLICY': 'NOT PROBED (policy: no operator authorization)',
  'UNPROVEN-ENVIRONMENT': 'UNPROVEN (environment)',
  // Say so when the gap is OURS rather than the server's — the reader is owed that distinction.
  'UNPROVEN-HARNESS': 'UNPROVEN (harness error — our side)',
  'UNPROVEN-OTHER': 'UNPROVEN',
  'NO-FINDINGS': 'NO FINDINGS (core checks exercised)',
};

// Outcomes where no MCP session was ever established, so there is nothing to have covered.
const NO_SESSION = new Set(['connect-failed', 'timeout', 'not-run']);

export function scoreResult(result) {
  const toolCalls = countSuccessfulToolCalls(result);
  const reads = countReads(result);
  const dims = (result.dims ?? []).map(d => ({ dimension: d.dimension, name: d.name, status: d.status, ...bucketDim(d, { toolCalls, reads }) }));

  const count = k => dims.filter(d => d.bucket === k).length;
  const evidence = count('EVIDENCE'), blocked = count('BLOCKED'), inapplicable = count('INAPPLICABLE');
  const applicable = evidence + blocked;

  const confirmed = (result.dims ?? []).filter(d => d.status === 'VULNERABLE')
    .map(d => ({ id: `dim${d.dimension}`, dimension: d.dimension, name: d.name, severity: 'high', confirmed: true, summary: d.note ?? d.name, evidence: d.evidence }));
  const candidates = (result.dims ?? []).filter(d => d.status === 'FOUND')
    .map(d => ({ id: `dim${d.dimension}`, dimension: d.dimension, name: d.name, severity: 'review', confirmed: false, summary: d.note ?? d.name, evidence: d.evidence }));
  const exposure = exposureFindings(result);

  const core = result.target?.kind === 'http' ? CORE_REMOTE : CORE_STDIO;
  const coreMissing = core
    .map(c => dims.find(d => d.dimension === c))
    .filter(d => d && d.bucket === 'BLOCKED')
    .map(d => ({ dimension: d.dimension, name: d.name, cause: d.cause, reason: d.reason }));

  // Verdict precedence: observed dim failures first, then anonymous exposure of state-changing
  // tools, then "cannot run at all", then "we did not prove it", then the scoped pass.
  let verdict;
  if (confirmed.length) verdict = 'VULNERABLE';
  else if (exposure.some(e => e.severity === 'high')) verdict = 'EXPOSED';
  else if (['broken-dependency', 'not-executable'].includes(result.outcome)) verdict = 'DEFECTIVE';
  // A server that demanded authorization is credential-gated, not unreachable.
  else if (result.outcome === 'auth-required') verdict = 'UNPROVEN-CREDENTIAL';
  else if (NO_SESSION.has(result.outcome)) {
    // an unlaunchable target whose blocker is a missing secret is credential-gated, not unreachable
    const why = `${result.reason ?? ''} ${result.dims?.[0]?.evidence?.reason ?? ''}`;
    verdict = CREDENTIAL.test(why) ? 'UNPROVEN-CREDENTIAL' : 'UNREACHABLE';
  } else if (coreMissing.length) {
    const causes = new Set(coreMissing.map(c => c.cause));
    verdict = causes.has('credential') ? 'UNPROVEN-CREDENTIAL'
      : causes.has('policy') ? 'UNPROVEN-POLICY'
      : causes.has('environment') ? 'UNPROVEN-ENVIRONMENT'
      : causes.has('harness') ? 'UNPROVEN-HARNESS'
      : 'UNPROVEN-OTHER';
  } else verdict = 'NO-FINDINGS';

  const blockingReasons = [...new Map(dims.filter(d => d.bucket === 'BLOCKED' && d.reason).map(d => [d.reason, { cause: d.cause, reason: d.reason, dims: [] }])).values()];
  for (const d of dims.filter(x => x.bucket === 'BLOCKED' && x.reason)) blockingReasons.find(b => b.reason === d.reason)?.dims.push(d.dimension);

  return {
    verdict, verdictLabel: DISPLAY[verdict],
    // A plain fraction with its cause attached cannot be mistaken for a safety grade; a letter can.
    coverage: { exercised: evidence, applicable, inapplicable, of: DIMS, text: `${evidence} of ${applicable} applicable dims exercised${inapplicable ? ` · ${inapplicable} inapplicable` : ''}` },
    findings: { confirmed, candidates, exposure },
    coreMissing, blockingReasons, basis: { successfulToolCalls: toolCalls, reads },
    dims,
  };
}

// One-line verdict for listings. Coverage is ALWAYS attached — never a bare verdict.
export function verdictLine(result) {
  const s = scoreResult(result);
  const name = result.target?.server?.name ?? result.target?.url ?? result.target?.identifier ?? 'unknown';
  const lead = s.findings.exposure.find(e => e.severity === 'high') ?? s.findings.confirmed[0];
  return `${name} — ${s.verdictLabel} · ${s.coverage.text}${lead ? ` · ${lead.summary}` : ''}`;
}

// Bumped whenever bucketing, the core set, verdict precedence or labels change, so any saved
// assessment can be traced to the model that produced it (and re-derived with rescore()).
// 1.1.0 (2026-10-19): "not applicable over HTTP / through a proxy" is INAPPLICABLE (dims 4, 5, 10, 11; dims.js localOnlyNA).
export const SCORING_MODEL_VERSION = '1.1.0';
