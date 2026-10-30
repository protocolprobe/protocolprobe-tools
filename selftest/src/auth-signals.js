// Does an error from an HTTP MCP server say "you need a credential"? Moved here unchanged from run.js (2026-10-19) so the
// self-test package (tools/selftest) can use it without the rest of run.js; run.js re-exports it.

// An HTTP MCP server can signal "needs a credential" as an HTTP 401/403 OR as a JSON-RPC /
// JSON error body after the transport connected. Real examples observed on the registry
// (2026-10-04): "invalid or missing MCP token", "Missing authentication token",
// "missing authorization header", "invalid_token", "Missing bearer token", "invalid_api_key",
// "Invalid or expired connector token", "Authorization required. Bearer token missing."
// Deliberately NOT matched: bare "invalid_request" (ambiguous), 5xx, protocol-version
// mismatches, DNS/fetch failures — those are genuine connect failures, not auth gating.
const AUTH_SIGNALS = [
  /\b40[13]\b/,
  /unauthori[sz]ed|forbidden|unauthenticated|not authenticated/i,
  /authentication (required|token)|authoriz(ation|ed) (required|header)/i,
  /\bsign[\s-]?in\b|\blog[\s-]?in\b|\bsign up\b|\bconnect via oauth\b/i,
  // a credential noun (authorization/bearer/token/api key/access token/mcp key/credential) sitting next
  // to a lack/validity word (missing/invalid/expired/revoked/required/no), in either order.
  /\b(missing|invalid|expired|revoked|required|no)\b[^.;{}\n]{0,40}\b(authoriz(ation|ed)|authentication|bearer|(api|access|mcp|connector|bearer)[_\s-]?(key|token)|token|credentials?)\b/i,
  /\b(authoriz(ation|ed)|authentication|bearer|(api|access|mcp|connector|bearer)[_\s-]?(key|token)|token|credentials?)\b[^.;{}\n]{0,40}\b(missing|invalid|expired|revoked|required)\b/i,
  /(key|token)[_\s-]required/i, // COMPANY_MCP_KEY_REQUIRED, TOKEN_REQUIRED (underscores block \b)
  /"error"\s*:\s*"(invalid_token|invalid_api_key|invalid_grant|unauthorized_client|access_denied)"/i,
  /invalid_api_key|invalid_token\b/i,
  /\bcl[eé] api manquante\b/i, // French: "API key missing" (observed on a real registry server)
];
export function isAuthError(message) {
  const m = String(message ?? '');
  return AUTH_SIGNALS.some(re => re.test(m));
}
