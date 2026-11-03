// How the engine names itself to the servers it reads (docs/legal, 2026-11-03): one User-Agent with a contact, so an operator who
// sees a request in a log can tell who sent it and write to us. Nothing else is added; a header the caller sets itself wins.
export const USER_AGENT = 'ProtocolProbe/1.0 (+https://protocolprobe.com; hello@protocolprobe.com)';

/** A copy of `headers` with our User-Agent unless a user-agent header (any case) is already there. */
export function withIdentity(headers = {}) {
  return Object.keys(headers).some((k) => k.toLowerCase() === 'user-agent') ? { ...headers } : { 'user-agent': USER_AGENT, ...headers };
}
