// Offline API pre-check for the self-test (owner-approved 2026-10-26): runs the acceptance rules we MEASURED for three AI
// vendors' APIs on the operator's own tool list, after the server has listed it. No network, no model call, nothing sent:
// pure functions over the list (test/selftest-api-rules.test.js).
//
// Source of every rule: the cross-LLM run (docs/design/cross-llm.md), in which the tool lists of 22,725 public MCP servers
// were sent to each API on 2026-10-25/26, and the adapters' static pre-checks (src/llm-anthropic.js, src/llm-openai.js,
// src/llm-gemini.js predictRejections, with the docs pages their comments cite, read 2026-10-25). The adapters import
// vendor code and are not in the published package, so the rules are ported here; the test compares the two on the same
// lists and names every place they differ on purpose:
//   - OpenAI duplicate names: the adapter predicts a refusal "to be seen in the pilot"; measured 2026-10-26, OpenAI's API
//     answered 25 of the 30 lists with two tools of the same name, so it is NOT a rule here.
//   - OpenAI name length: the docs page says "maximum length of 64"; the API's own message gives the pattern
//     '^[a-zA-Z0-9_-]+$' with no length, and it answered 3 lists with a longer name, so only the pattern is a rule here.
//   - OpenAI top level: the measured message also names 'enum', 'const' and 'not' (7 lists refused), added here.
//   - OpenAI \p{...} patterns: measured (19 lists, "... is not a 'regex'."), added here.
//   - Gemini top-level anyOf: the adapter marks it SUSPECTED; measured, Google's API answered 131 such lists: NOT a rule.
//   - Gemini duplicate names and tuple-style `items`: Google's API answered such lists only with the bare "Request contains
//     an invalid argument." (30 and 34 of 135 lists; no list it answered had either). A measured association, not a reason
//     Google gave: they are reported with that basis, never as Google's rule.
// A list none of these rules match can still be refused: say "none of the measured rules matched (not a guarantee)".

export const API_RULES_MEASURED = '2026-10-25/26';
export const API_VENDORS = [
  { id: 'anthropic', label: 'Anthropic' },
  { id: 'openai', label: 'OpenAI' },
  { id: 'gemini', label: 'Google' },
];

const isObj = v => v !== null && typeof v === 'object' && !Array.isArray(v);

// A schema position walk (only keywords that hold subschemas, never data such as `default`, `examples` or `enum` values).
function someSchema(s, test, depth = 0) {
  if (!isObj(s) || depth > 64) return false;
  if (test(s)) return true;
  const kids = [
    ...['properties', 'patternProperties', '$defs', 'definitions', 'dependentSchemas'].flatMap(k => (isObj(s[k]) ? Object.values(s[k]) : [])),
    ...['anyOf', 'oneOf', 'allOf', 'prefixItems'].flatMap(k => (Array.isArray(s[k]) ? s[k] : [])),
    ...(Array.isArray(s.items) ? s.items : [s.items]),
    s.additionalProperties, s.additionalItems, s.not, s.if, s.then, s.else, s.contains, s.propertyNames, s.unevaluatedProperties, s.unevaluatedItems,
  ];
  return kids.some(k => someSchema(k, test, depth + 1));
}

// Each rule: { id, text, basis, per: 'tool' | 'list', test }. `text` completes "may be refused by <Vendor>'s API: ...".
// per 'tool': test(tool, ctx) -> boolean, the tool is named. per 'list': test(tools) -> null | detail string.
const dupNames = tools => {
  const seen = new Set(), dup = [];
  for (const t of tools) {
    if (seen.has(t.name) && !dup.includes(t.name)) dup.push(t.name);
    seen.add(t.name);
  }
  return dup;
};
const SEEN = (n, day = '2026-10-25') => `seen in its refusals of ${n} public tool list${n === 1 ? '' : 's'} (${day})`;

export const API_RULES = {
  anthropic: [
    { id: 'name-pattern', per: 'tool', text: "a tool name must match ^[a-zA-Z0-9_-]{1,128}$",
      basis: `${SEEN(173)}; its docs page read on 2026-10-25 states the same rule`,
      test: t => typeof t.name !== 'string' || !/^[a-zA-Z0-9_-]{1,128}$/.test(t.name) },
    { id: 'duplicate-names', per: 'tool', text: 'two tools have the same name', basis: SEEN(29),
      test: (t, c) => c.dup.includes(t.name) },
    { id: 'schema-top-level-combinator', per: 'tool', text: 'the input schema has oneOf, allOf or anyOf at its top level', basis: SEEN(267),
      test: t => isObj(t.input_schema) && ['oneOf', 'allOf', 'anyOf'].some(k => Object.hasOwn(t.input_schema, k)) },
    { id: 'property-key-pattern', per: 'tool', text: 'a top-level property name must match ^[a-zA-Z0-9_.-]{1,64}$', basis: SEEN(4),
      test: t => isObj(t.input_schema?.properties) && Object.keys(t.input_schema.properties).some(k => !/^[a-zA-Z0-9_.-]{1,64}$/.test(k)) },
    { id: 'schema-not-object', per: 'tool', text: "the input schema is not of type 'object'",
      basis: "from the type its SDK (1.3.0) gives a tool's input schema; not seen in a refusal in our run",
      test: t => !isObj(t.input_schema) || t.input_schema.type !== 'object' },
  ],
  openai: [
    { id: 'name-pattern', per: 'tool', text: "a tool name must match ^[a-zA-Z0-9_-]+$", basis: SEEN(167),
      test: t => typeof t.name !== 'string' || !/^[a-zA-Z0-9_-]+$/.test(t.name) },
    { id: 'schema-top-level', per: 'tool', text: "the input schema must have type 'object' and no oneOf, anyOf, allOf, enum, const or not at its top level", basis: SEEN(262),
      test: t => isObj(t.input_schema) && (t.input_schema.type !== 'object' || ['oneOf', 'anyOf', 'allOf', 'enum', 'const', 'not'].some(k => Object.hasOwn(t.input_schema, k))) },
    { id: 'over-128-tools', per: 'list', text: 'more than 128 tools in one request', basis: SEEN(171),
      test: tools => (tools.length > 128 ? `the list has ${tools.length} tools` : null) },
    { id: 'unicode-class-pattern', per: 'tool', text: 'a pattern in the input schema uses a \\p{...} Unicode class, which the API did not read as a regex', basis: SEEN(19),
      test: t => someSchema(t.input_schema, s => typeof s.pattern === 'string' && /\\[pP]\{/.test(s.pattern)) },
  ],
  gemini: [
    { id: 'name-pattern', per: 'tool', text: 'a tool name must be letters, digits, _ . : or -, at most 128 characters',
      basis: 'stated on its docs page read on 2026-10-25, and in the message of its refusals (2026-10-25/26)',
      test: t => typeof t.name !== 'string' || !/^[A-Za-z0-9_.:-]{1,128}$/.test(t.name) },
    { id: 'name-start', per: 'tool', text: 'a tool name must start with a letter or an underscore',
      // 4 of the 7 Gemini name refusals: the other 3 names broke the character set (name-pattern above), not the first character
      basis: `${SEEN(4, '2026-10-25/26')}; its docs page read on 2026-10-25 states no rule for the first character`,
      test: t => typeof t.name === 'string' && /^[A-Za-z0-9_.:-]{1,128}$/.test(t.name) && !/^[A-Za-z_]/.test(t.name) },
    { id: 'duplicate-names', per: 'tool', text: 'two tools have the same name',
      basis: "association only: in our run (2026-10-25/26) its API answered all 30 such lists with \"Request contains an invalid argument.\" without naming the cause",
      test: (t, c) => c.dup.includes(t.name) },
    { id: 'tuple-items', per: 'tool', text: 'the input schema has tuple-style items (an array of schemas)',
      basis: "association only: in our run (2026-10-25/26) its API answered 34 such lists with \"Request contains an invalid argument.\" without naming the cause, and answered none that had it",
      test: t => someSchema(t.input_schema, s => Array.isArray(s.items)) },
  ],
};

/** MCP tools (as listed: {name, inputSchema}) -> the shape the rules read ({name, input_schema}). */
export function toApiTools(mcpTools) {
  return (Array.isArray(mcpTools) ? mcpTools : []).map(t => ({ name: t?.name, input_schema: t?.inputSchema ?? t?.input_schema }));
}

/**
 * Run every vendor's rules on one tool list. -> { measured, vendors: [{ vendor, label, matches: [{ rule, text, basis,
 * tools: [names], detail }] }] }. A rule is listed once per vendor, with every tool it matched (in list order).
 */
export function checkApiRules(apiTools) {
  const tools = Array.isArray(apiTools) ? apiTools : [];
  const ctx = { dup: dupNames(tools) };
  return {
    measured: API_RULES_MEASURED,
    vendors: API_VENDORS.map(({ id, label }) => ({
      vendor: id, label,
      matches: API_RULES[id].flatMap(r => {
        if (r.per === 'list') {
          const detail = r.test(tools);
          return detail ? [{ rule: r.id, text: r.text, basis: r.basis, tools: [], detail }] : [];
        }
        const names = [];
        for (const t of tools) if (r.test(t, ctx) && !names.includes(t.name)) names.push(t.name);
        return names.length ? [{ rule: r.id, text: r.text, basis: r.basis, tools: names, detail: null }] : [];
      }),
    })),
  };
}

// A tool name as printed: as is when it is plain visible ASCII, else JSON-quoted (control characters, spaces, very long).
const shown = n => (typeof n === 'string' && /^[\x21-\x7E]{1,128}$/.test(n) ? n : n == null ? '(no name)' : JSON.stringify(String(n).slice(0, 128)));
function toolsPart(names, max = 3) {
  if (names.length === 1) return `tool ${shown(names[0])}`;
  const first = names.slice(0, max).map(shown).join(', ');
  return names.length > max ? `tools ${first} and ${names.length - max} more` : `tools ${first}`;
}

/** The printed lines (one or more per vendor, in the fixed order), the header and the closing note. */
export function apiRuleLines(result, { listed = true } = {}) {
  const head = 'Tool list pre-check, three AI vendors\' APIs (offline: no network and no model call; nothing was sent to any vendor):';
  if (!listed) return [head, '  not run: the tool list could not be read from your server.'];
  const lines = [head];
  for (const v of result.vendors) {
    if (!v.matches.length) { lines.push(`  ${v.label}: none of the measured rules matched (not a guarantee)`); continue; }
    for (const m of v.matches) lines.push(`  ${v.label}: may be refused by ${v.label}'s API: ${m.text} (${m.detail ?? toolsPart(m.tools)})`);
    for (const b of [...new Set(v.matches.map(m => `${m.text}: ${m.basis}`))]) lines.push(`      basis - ${b}`);
  }
  lines.push(`The rules are those we measured on ${result.measured} by sending public MCP tool lists to each API, plus what the docs pages we read said. An API can have other rules and can change them. This is not part of the score above, and --fail-on-finding does not count it.`);
  return lines;
}
