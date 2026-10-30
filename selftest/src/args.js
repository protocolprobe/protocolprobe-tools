// Build tool arguments from a tool's own inputSchema.
// Earlier runs lost results because a generic "test" string was passed everywhere
// (invalid SQL, nonexistent paths). Here values come from the schema first
// (default/enum/const/examples), then from a small set of name hints bound to
// real things the harness controls (a real file in WORKDIR, the local listener URL).

const SQL_PARAM = /(sql|query)/i;

function hintedString(name, desc, ctx, purpose) {
  const n = name.toLowerCase();
  const d = (desc ?? '').toLowerCase();
  if (/(url|uri|link|href|endpoint)/.test(n) || /\burl\b/.test(d)) return ctx.listenerUrl;
  if (/(path|file|dir|folder)/.test(n)) return /dir|folder/.test(n) ? ctx.workdir : ctx.probeFile;
  if (SQL_PARAM.test(n)) return purpose === 'mutate'
    ? 'CREATE TABLE IF NOT EXISTS mcp_probe (id INTEGER)'
    : 'SELECT 1';
  if (/email/.test(n)) return 'probe@example.com';
  if (/(name|title|key|id|entity)/.test(n)) return 'mcp_probe';
  return 'mcp probe';
}

export function valueFor(name, schema = {}, ctx, purpose = 'call', depth = 0) {
  if (schema.const !== undefined) return schema.const;
  if (schema.default !== undefined) return schema.default;
  if (Array.isArray(schema.enum) && schema.enum.length) return schema.enum[0];
  if (Array.isArray(schema.examples) && schema.examples.length) return schema.examples[0];
  const alt = schema.anyOf ?? schema.oneOf;
  if (Array.isArray(alt) && alt.length) return valueFor(name, alt.find(a => a.type !== 'null') ?? alt[0], ctx, purpose, depth);
  const type = Array.isArray(schema.type) ? schema.type.find(t => t !== 'null') : schema.type;
  switch (type) {
    case 'number': return schema.minimum ?? 1;
    case 'integer': return schema.minimum ?? 1;
    case 'boolean': return false;
    case 'array': {
      if (depth > 3) return [];
      const min = Math.max(1, schema.minItems ?? 1);
      return Array.from({ length: min }, () => valueFor(name, schema.items ?? { type: 'string' }, ctx, purpose, depth + 1));
    }
    case 'object': return depth > 3 ? {} : buildArgs(schema, ctx, purpose, depth + 1);
    default: return hintedString(name, schema.description, ctx, purpose);
  }
}

// Fill required props always. Two real cases from the E2B package run (2026-10-04) that an
// only-`required` filler gets wrong:
//   - either-or schemas: `anyOf`/`oneOf` at the object level carry the real requirement
//     (e.g. personae `click`: "must provide either ref or text"), so take the first branch's.
//   - schemas with NO `required` at all: sending {} makes the server reject the call, so seed
//     the first property to send something meaningful.
export function buildArgs(schema = {}, ctx, purpose = 'call', depth = 0) {
  const props = schema.properties ?? {};
  const required = new Set(schema.required ?? []);

  // Object-level alternatives: adopt the first branch's required names (and its props).
  const branches = schema.anyOf ?? schema.oneOf;
  if (Array.isArray(branches) && branches.length) {
    const branch = branches.find(b => (b?.required ?? []).length || b?.properties) ?? branches[0];
    for (const n of branch?.required ?? []) required.add(n);
    for (const [name, s] of Object.entries(branch?.properties ?? {})) if (!props[name]) props[name] = s;
  }

  const names = Object.keys(props);
  if (!required.size && names.length) required.add(names[0]);

  const out = {};
  for (const [name, s] of Object.entries(props)) {
    if (required.has(name)) out[name] = valueFor(name, s, ctx, purpose, depth);
  }
  return out;
}

// Pick a value of the wrong JSON type for a param (dim 7).
export function wrongTypeValue(schema = {}) {
  const type = Array.isArray(schema.type) ? schema.type[0] : schema.type;
  switch (type) {
    case 'string': return 12345;
    case 'number': case 'integer': return 'not-a-number';
    case 'boolean': return 'not-a-boolean';
    case 'array': return 'not-an-array';
    case 'object': return 'not-an-object';
    default: return { unexpected: true };
  }
}
