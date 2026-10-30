// Heuristic patterns. Every match produced from these is reported as a CANDIDATE,
// never as confirmed — regex over text is not proof of intent.

// Dim 2: text in tool/prompt/resource metadata that is directed at the model, not the user.
export const INJECTION_PATTERNS = [
  { id: 'ignore-instructions', re: /\b(ignore|disregard|forget)\b.{0,30}\b(previous|prior|above|all|earlier)\b.{0,20}\b(instructions?|rules|prompts?)\b/i },
  { id: 'important-tag', re: /<\s*(IMPORTANT|SYSTEM|INSTRUCTIONS?)\s*>/i },
  { id: 'hide-from-user', re: /\b(do not|don't|never)\b.{0,20}\b(tell|mention|inform|reveal|show)\b.{0,20}\b(the )?user\b/i },
  { id: 'system-override', re: /\b(system (prompt|override|message)|you are now|new instructions)\b/i },
  { id: 'sensitive-path', re: /(~\/\.ssh|id_rsa|\.aws\/credentials|\/etc\/passwd|\.env\b)/i },
  { id: 'cross-tool-directive', re: /\bbefore (using|calling) (this|any other) tool\b/i },
];

export function scanText(text) {
  if (!text) return [];
  return INJECTION_PATTERNS.filter(p => p.re.test(text)).map(p => p.id);
}

// Dim 6: tool names/annotations that suggest a state change.
export const MUTATING_NAME = /(^|[_\-.])(write|create|delete|remove|update|insert|set|add|move|rename|edit|put|drop|append|patch|modify|toggle|save|upload|post|send|clear|reset|store)([_\-.]|$)/i;

export function isMutating(tool) {
  const a = tool.annotations ?? {};
  if (a.readOnlyHint === true) return { mutating: false, why: 'annotations.readOnlyHint=true (self-declared, untrusted)' };
  if (a.destructiveHint === true) return { mutating: true, why: 'annotations.destructiveHint=true' };
  if (MUTATING_NAME.test(tool.name)) return { mutating: true, why: `name matches mutating verb` };
  return { mutating: false, why: 'no mutating signal' };
}

// Dim 5: params that take a URL.
const URL_PARAM_NAME = /(url|uri|link|href|endpoint|webhook|callback|source|data|address|location)/i;
export function urlParams(tool) {
  const props = tool.inputSchema?.properties ?? {};
  return Object.entries(props)
    .filter(([name, s]) =>
      s?.format === 'uri' || s?.format === 'url' ||
      (s?.type === 'string' || !s?.type) && (URL_PARAM_NAME.test(name) || /\b(url|uri|https?:)/i.test(s?.description ?? '')))
    .map(([name]) => name);
}

// Dims 7/10: params that take a filesystem path.
const PATH_PARAM_NAME = /(path|file|dir|folder|filename)/i;
export function pathParams(tool) {
  const props = tool.inputSchema?.properties ?? {};
  return Object.entries(props)
    .filter(([name, s]) => (s?.type === 'string' || s?.type === 'array') && PATH_PARAM_NAME.test(name))
    .map(([name]) => name);
}

// Dim 9: elicitation field names asking for sensitive data (spec: servers MUST NOT).
export const SENSITIVE_FIELD = /(password|passwd|passcode|api[_\-]?key|secret|token|ssn|social.?security|credit.?card|card.?number|cvv|cvc|\bpin\b|private.?key|seed.?phrase|mnemonic)/i;

// Why did a tool call fail? Measured over the 155 failing calls in the E2B package run
// (2026-10-04): 57% were the server refusing for lack of a vendor credential, ~35% an
// environment precondition (a companion app/service that isn't present), and only ~7% a real
// argument problem. Calling the first two HARNESS-ERROR blames our harness for the server's
// own precondition, so they are classified separately and reported as N-A.
export const CREDENTIAL_REFUSAL = /(인증이 필요|토큰|auth(entication|oriz\w+)?[ _-]?(required|needed|failed)|not authenticated|unauthori[sz]ed|(credential|token|api[ _-]?key|wallet|secret)s?[^.;}\n]{0,30}(not )?(configured|not set|missing|required|provided)|(no|missing|without)[^.;}\n]{0,25}(credential|token|api[ _-]?key|wallet)|[A-Z][A-Z0-9_]{3,}_(TOKEN|KEY|SECRET|CREDENTIALS?)|not logged in|please (log ?in|sign ?in|configure|authenticate)|run the \w*authenticate)/i;

// A local companion app / daemon / discovery file the sandbox legitimately doesn't have.
export const ENV_PRECONDITION = /(未找到运行中的应用|缺少发现文件|no running (app|application|instance)|discovery file|is not running|could not connect to (the )?(local|desktop|companion)|ECONNREFUSED .*(127\.0\.0\.1|localhost)|socket .*not found|daemon .*not running)/i;

export const ARG_VALIDATION = /(invalid arguments|validation error|required property|must be|expected|invalid option|is not allowed|unrecognized key|zoderror|invalid_type|missing required|invalid input|需要提供)/i;

// Dominant cause across a set of failed call bodies.
export function classifyFailures(texts) {
  const tally = { credential: 0, environment: 0, argument: 0, unknown: 0 };
  for (const t of texts) {
    if (!t) continue;
    if (CREDENTIAL_REFUSAL.test(t)) tally.credential++;
    else if (ENV_PRECONDITION.test(t)) tally.environment++;
    else if (ARG_VALIDATION.test(t)) tally.argument++;
    else tally.unknown++;
  }
  const total = Object.values(tally).reduce((a, b) => a + b, 0);
  if (!total) return { dominant: 'unknown', tally, total };
  const dominant = Object.entries(tally).sort((a, b) => b[1] - a[1])[0][0];
  return { dominant, tally, total };
}

// A published package that cannot even import because it did not pin the MCP SDK and a new SDK
// major changed the API. Real signatures captured in E2B (2026-10-04) after the Python SDK 2.x
// renamed FastMCP -> MCPServer. This is the PACKAGE's defect, not our harness's, so it gets its
// own first-class status (BROKEN-DEPENDENCY) rather than being lumped into our failures.
export const DEPENDENCY_BREAKAGE = [
  { id: 'py-mcp-fastmcp-renamed', re: /No module named ['"]mcp\.server\.fastmcp['"]|renamed to MCPServer|pin ['"]mcp<2['"]/i },
  { id: 'py-mcp-server-api-changed', re: /['"]Server['"] object has no attribute ['"](list_tools|call_tool|list_resources|list_prompts)['"]/i },
  { id: 'py-mcp-import-error', re: /ImportError: cannot import name ['"](FastMCP|Server|MCPServer)['"] from ['"]mcp[.\w]*['"]/i },
  { id: 'js-sdk-export-missing', re: /does not provide an export named ['"](Server|McpServer|StdioServerTransport)['"]|Cannot find module ['"]@modelcontextprotocol\/sdk/i },
];

export function detectDependencyBreakage(text) {
  if (!text) return null;
  const hit = DEPENDENCY_BREAKAGE.find(p => p.re.test(text));
  return hit ? hit.id : null;
}

// Dim 7: stack traces / internal detail in error output.
export const STACK_TRACE = /(\n\s+at .+\(.+:\d+:\d+\)|Traceback \(most recent call last\)|File ".+", line \d+)/;
