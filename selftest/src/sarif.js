// SARIF 2.1.0 report of a self-test run (selftest.mjs --sarif), for GitHub code scanning and other SARIF readers.
//
// Fields follow GitHub's "SARIF support for code scanning" page (docs.github.com, read 2026-10-19): $schema, version 2.1.0,
// runs[].tool.driver.name and .rules[] (each rule: id, shortDescription.text, fullDescription.text, help.text), results[]
// with ruleId, level and message.text. GitHub displays a result only with a location (artifactLocation.uri, a path relative
// to the repository root, and a region): a self-test finding is about the running server, not a line of code, so every
// result points at one file the operator names (--sarif-anchor) or, with --stdio, the first file in the command that sits
// under the current folder (the server's own entry file), at line 1. Without either, results carry no location: the file
// is still valid SARIF, and the command says that GitHub will not display them.
//
// Only checks that need attention become results (VULNERABLE = error, FOUND = warning: FOUND is a heuristic match to
// review, not a proven problem). Passed, not-run and not-applicable checks are not results; the score summary, with what
// did not run, is in runs[0].properties. Every message passes through the caller's redaction.
import fs from 'node:fs';
import path from 'node:path';

// The check titles and meanings shown on protocolprobe.com (site/src/lib/server-wording.ts CHECKS); a test keeps them equal.
export const CHECK_TEXT = {
  1: ['Inventory', 'Reads the declared tools, resources and prompts.'],
  2: ['Hidden instructions', 'Looks for hidden instructions in tool descriptions.'],
  3: ['Real execution', 'Calls a tool and checks what really happens.'],
  4: ['Secret leak', 'Plants a fake secret and checks whether it leaks.'],
  5: ['Internal addresses', 'Checks whether a tool can be steered to internal addresses.'],
  6: ['Unconfirmed changes', 'Checks whether tools that change data act without asking.'],
  7: ['Bad input', 'Sends bad input and watches how the server answers.'],
  8: ['Model requests', "Checks whether the server asks the client's model to act for it."],
  9: ['Sensitive questions', 'Checks whether the server asks users for sensitive data.'],
  10: ['Folder boundary', 'Checks whether the server reaches outside the folders it was given.'],
  11: ['Log leaks', 'Checks whether log messages carry data they should not.'],
  12: ['Hidden content', 'Checks resources that hide content from the user.'],
  13: ['Fake assistant turns', "Checks prompts that pose as the assistant's own words."],
  14: ['Token passthrough', "Checks whether the server forwards a user's token to other services."],
  15: ['Token audience', 'Checks whether tokens meant for another service are accepted.'],
  16: ['Sign-in redirect', 'Checks the sign-in redirect for abuse.'],
  17: ['Consent handling', 'Checks consent handling when one service acts for another.'],
  18: ['Sign-in metadata', 'Checks the published sign-in metadata for unsafe URLs.'],
};

export const SARIF_SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json';
export const ruleId = (dimension, name) => `protocolprobe/${dimension}-${name}`;
const LEVEL = { VULNERABLE: 'error', FOUND: 'warning' };

// The repository-relative anchor for result locations: --sarif-anchor if given (must be a file under cwd), else with
// --stdio the first command argument that is an existing file under cwd. Returns { uri } or { none: reason }.
export function sarifAnchor({ anchor, argv = [], cwd = process.cwd() }) {
  const under = (p) => {
    const abs = path.resolve(cwd, p);
    const rel = path.relative(cwd, abs);
    if (!rel || rel.startsWith('..') || path.isAbsolute(rel)) return null;
    try { if (!fs.statSync(abs).isFile()) return null; } catch { return null; }
    // a URI reference: each segment percent-encoded (a space or # in a file name would otherwise make it invalid)
    return rel.split(path.sep).map(encodeURIComponent).join('/');
  };
  if (anchor) {
    const uri = under(anchor);
    if (!uri) throw new Error(`--sarif-anchor must name an existing file inside the current folder (${anchor} is not one)`);
    return { uri };
  }
  const args = argv.slice(1);
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    // a URL-like argument is skipped, but not a Windows path ("C:\..." also starts with a letter and a colon); so is the
    // value of an option (`--env-file .env`, `--config cfg.json`), which is a setting, not the server's own file
    const prev = args[i - 1];
    if (typeof a !== 'string' || a.startsWith('-') || (!path.isAbsolute(a) && /^[a-z][a-z0-9+.-]*:/i.test(a))) continue;
    if (typeof prev === 'string' && prev.startsWith('-') && !prev.includes('=')) continue;
    const uri = under(a);
    if (uri) return { uri };
  }
  return { none: 'no file to point at: pass --sarif-anchor <a file in this repository, for example your server\'s entry file> so GitHub code scanning can display the results' };
}

// `dims`: the observed dims (status, name, note); `score`: checkScore(); `anchor`: sarifAnchor(); `version`: the package
// version or null; `redact`: applied to every message. The tested command line is NOT put in the file: it is meant to be
// uploaded, and a key typed on the command line (`--api-key abc`) is not always recognisable as one.
export function buildSarif({ dims, score, anchor, version, redact = (s) => s }) {
  const attention = new Set(score.needsAttention.map((d) => d.dimension));
  const rules = Object.entries(CHECK_TEXT).map(([n, [title, meaning]]) => {
    const name = dims.find((d) => d.dimension === Number(n))?.name ?? title.toLowerCase().replace(/\s+/g, '-');
    return {
      id: ruleId(n, name),
      name: title.replace(/\s+/g, ''),
      shortDescription: { text: title },
      fullDescription: { text: meaning },
      help: { text: `${meaning} The self-test runs this check against a server you run yourself. See https://protocolprobe.com/docs/selftest` },
      helpUri: 'https://protocolprobe.com/docs/selftest',
    };
  });
  const results = dims.filter((d) => attention.has(d.dimension)).map((d) => ({
    ruleId: ruleId(d.dimension, d.name),
    level: LEVEL[d.status] ?? 'warning',
    message: { text: redact(`${CHECK_TEXT[d.dimension]?.[0] ?? d.name}: ${d.status}${d.note ? ` - ${d.note}` : ''}`) },
    ...(anchor.uri ? { locations: [{ physicalLocation: { artifactLocation: { uri: anchor.uri }, region: { startLine: 1 } } }] } : {}),
  }));
  return {
    $schema: SARIF_SCHEMA,
    version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'protocolprobe-selftest', informationUri: 'https://protocolprobe.com/docs/selftest', ...(version ? { semanticVersion: version } : {}), rules } },
      invocations: [{ executionSuccessful: true }],
      results,
      properties: {
        score: { passed: score.passed, ran: score.ran, applicable: score.applicable, complete: score.complete },
        notRun: score.notRun.map((d) => `${d.dimension} ${d.name}: ${d.reason}`),
        note: 'Only checks that need attention are results. The score counts only checks that ran; it is not a certificate of safety.',
      },
    }],
  };
}
