// Result serialisation, format v1.
//
// Two properties are expensive to retrofit, so they are structural here:
//
//  1. RAW EVIDENCE AND COMPUTED VERDICT ARE SEPARATE. Each entry has `observation` (exactly what
//     the engine saw) and `assessment` (what the scoring model concluded). A change to the scoring
//     model is re-applied to already-saved runs with `rescore()` — no sandbox time, and the original
//     observation date is preserved. Nothing in `observation` may be derived from scoring.
//  2. EVERY RESULT HAS AN EXPLICIT IDENTITY. `targetKey` (reverse-DNS server name + version) tracks
//     the same server across runs; `observationId` adds the run timestamp to identify one run of it.
//     Score history and "most improved" depend on these being explicit, never inferred.
//
// The envelope carries `formatVersion` so old files stay readable when this changes, and
// `scoringModel` so an assessment can always be traced to the model that produced it.

import { scoreResult, SCORING_MODEL_VERSION } from './score.js';

export const FORMAT_VERSION = 1;

// Reverse-DNS registry name when we have one; otherwise the remote host, or the package id.
function serverName(target) {
  const n = target?.server?.name;
  if (n && n !== 'adhoc' && n !== 'fixture') return n;
  if (target?.url) { try { return new URL(target.url).host; } catch { return String(target.url); } }
  return target?.identifier ?? target?.command ?? 'unknown';
}

// The version we tested. Prefer the pinned package version; fall back to what the server reported.
function versionOf(observation) {
  const declared = observation.target?.version;
  if (declared) return String(declared);
  const reported = observation.dims?.find(d => d.dimension === 1)?.evidence?.serverInfo?.version;
  return reported ? String(reported) : null;
}

export function identityOf(observation, runAt) {
  const name = serverName(observation.target);
  const version = versionOf(observation);
  const targetKey = `${name}@${version ?? 'unversioned'}`;
  const at = observation.startedAt ?? runAt ?? null;
  return {
    targetKey,
    observationId: `${targetKey}#${at ?? 'unknown-time'}`,
    serverName: name,
    version,
    registryType: observation.target?.registryType ?? null,
    identifier: observation.target?.identifier ?? null,
    transport: observation.target?.kind ?? null,
    url: observation.target?.url ?? null,
    observedAt: at,
  };
}

/**
 * Wrap raw engine results in the versioned envelope, attaching one assessment per observation.
 * `results` are the untouched objects returned by runTarget().
 */
export function buildReport(results, { mode = 'full', environment = 'local', startedAt, finishedAt } = {}) {
  const runAt = startedAt ?? new Date().toISOString();
  const first = results[0] ?? {};
  return {
    formatVersion: FORMAT_VERSION,
    scoringModel: SCORING_MODEL_VERSION,
    engine: first.engine ?? null,
    sdk: first.sdk ?? null,
    run: { startedAt: runAt, finishedAt: finishedAt ?? new Date().toISOString(), mode, environment, targets: results.length },
    results: results.map(observation => ({
      identity: identityOf(observation, runAt),
      observation,                       // raw, never derived from scoring
      assessment: assess(observation),   // derived, always reproducible from `observation`
    })),
  };
}

function assess(observation) {
  const s = scoreResult(observation);
  return { scoringModel: SCORING_MODEL_VERSION, ...s };
}

/**
 * Re-apply the CURRENT scoring model to an already-saved report. This is the whole point of keeping
 * the two separate: no re-running, and the original observation date is kept.
 */
export function rescore(report) {
  const entries = toEntries(report);
  return {
    ...(isEnvelope(report) ? report : { formatVersion: FORMAT_VERSION, run: { startedAt: null, mode: 'unknown', environment: 'unknown', targets: entries.length } }),
    formatVersion: FORMAT_VERSION,
    scoringModel: SCORING_MODEL_VERSION,
    rescoredAt: new Date().toISOString(),
    results: entries.map(e => ({ identity: e.identity, observation: e.observation, assessment: assess(e.observation) })),
  };
}

export const isEnvelope = x => !!x && !Array.isArray(x) && typeof x === 'object' && 'formatVersion' in x;

// Accept either the v1 envelope or a legacy bare array of engine results, so files written before
// this format stay readable.
function toEntries(parsed) {
  if (isEnvelope(parsed)) {
    if (parsed.formatVersion > FORMAT_VERSION) throw new Error(`report formatVersion ${parsed.formatVersion} is newer than this engine supports (${FORMAT_VERSION})`);
    return (parsed.results ?? []).map(r => ({ identity: r.identity ?? identityOf(r.observation ?? r, parsed.run?.startedAt), observation: r.observation ?? r, assessment: r.assessment }));
  }
  const arr = Array.isArray(parsed) ? parsed : [parsed];
  return arr.map(o => ({ identity: identityOf(o), observation: o, assessment: undefined }));
}

/** Read a results file in any supported shape and return the raw observations. */
export function readObservations(text) {
  return toEntries(JSON.parse(text)).map(e => e.observation);
}

/** Read a results file and return {identity, observation, assessment} entries. */
export function readEntries(text) {
  return toEntries(JSON.parse(text));
}
