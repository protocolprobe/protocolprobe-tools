// Offline match of what is configured on a machine against the official MCP registry (feature #17).
// The index is a snapshot built from the registry data we already hold (build-index.mjs); matching never touches the
// network, so using it cannot send anything anywhere. Pure functions here (unit-tested); the file is read in discover.mjs.
//
// What is matched: a package a known runner starts (npm / PyPI / OCI image) and a remote URL's host + path. A key that
// belongs to exactly one registry server maps to its name; a key shared by several is stored as their count and shown
// as "several", never guessed.

export const INDEX_FORMAT = 1;
// registry server names look like "io.github.owner/name"; anything else is not stored or shown
const SERVER_NAME_RE = /^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/;

/** The runner → package ecosystem a recognised package belongs to. */
export const ECOSYSTEM = { npx: "npm", bunx: "npm", pnpm: "npm", uvx: "pypi", pipx: "pypi", docker: "oci" };

/** Package name without version or tag, in the form the registry spells it. null when there is nothing to match. */
export function normPackage(ecosystem, name) {
  let s = String(name).trim();
  if (!s) return null;
  if (ecosystem === "npm") return s.replace(/^(@?[^@]+)@.*$/, "$1").toLowerCase();
  if (ecosystem === "pypi") return s.replace(/@.*$/, "").toLowerCase().replace(/[-_.]+/g, "-");
  if (ecosystem === "oci") {
    s = s.replace(/@sha256:[0-9a-f]+$/i, "").replace(/:[^/]*$/, "").toLowerCase();
    return s.replace(/^(index\.)?docker\.io\//, "").replace(/^library\//, "");
  }
  return null;
}

/** host + path of a remote URL, lower-case host, no query or fragment, no trailing slash. null if not a valid URL. */
export function remoteKey(url) {
  try {
    const u = new URL(String(url));
    if (!["http:", "https:", "ws:", "wss:"].includes(u.protocol)) return null;
    return u.host.toLowerCase() + u.pathname.replace(/\/+$/, "");
  } catch { return null; }
}

/** Build the index from registry rows ({server, _meta}); only the latest version of each server counts. */
export function buildIndex(rows, snapshot) {
  const packages = new Map(), remotes = new Map(), hosts = new Set();
  let servers = 0;
  const add = (map, key, name) => { if (!key) return; (map.get(key) ?? map.set(key, new Set()).get(key)).add(name); };
  for (const r of rows) {
    const s = r?.server;
    if (!s || typeof s.name !== "string" || !SERVER_NAME_RE.test(s.name)) continue;
    if (r._meta?.["io.modelcontextprotocol.registry/official"]?.isLatest === false) continue;
    servers++;
    for (const p of s.packages ?? []) {
      const eco = p.registryType;
      if (!["npm", "pypi", "oci"].includes(eco) || typeof p.identifier !== "string") continue;
      const n = normPackage(eco, p.identifier);
      if (n) add(packages, `${eco}:${n}`, s.name);
    }
    for (const x of s.remotes ?? []) {
      const k = remoteKey(x?.url);
      if (!k) continue;
      add(remotes, k, s.name);
      hosts.add(k.split("/")[0].replace(/:\d+$/, ""));
    }
  }
  const flat = (m) => Object.fromEntries([...m].sort(([a], [b]) => (a < b ? -1 : 1)).map(([k, v]) => [k, v.size === 1 ? [...v][0] : v.size]));
  return { format: INDEX_FORMAT, snapshot, source: "official MCP registry, latest version of each server", servers, packages: flat(packages), remotes: flat(remotes), hosts: [...hosts].sort() };
}

/** True for an index object of the shape this code reads (a corrupt or foreign file must not be trusted). */
export function validIndex(x) {
  const plain = (o) => o && typeof o === "object" && !Array.isArray(o);
  return plain(x) && x.format === INDEX_FORMAT && typeof x.snapshot === "string" && Number.isInteger(x.servers) && plain(x.packages) && plain(x.remotes) && Array.isArray(x.hosts);
}

const result = (v) => (typeof v === "string" ? { state: "listed", name: v, url: `https://protocolprobe.com/mcp/servers/${v}` } : { state: "several", count: v });

/** Registry match for a recognised package ({runner, name}) or a remote URL; null when there is nothing to match. */
export function matchPackage(pkg, index) {
  if (!index || !pkg) return null;
  const eco = ECOSYSTEM[pkg.runner], n = eco ? normPackage(eco, pkg.name) : null;
  if (!n) return null;
  const v = Object.hasOwn(index.packages, `${eco}:${n}`) ? index.packages[`${eco}:${n}`] : undefined;
  return v === undefined ? { state: "not-listed" } : result(v);
}
export function matchRemote(url, index) {
  if (!index) return null;
  const k = remoteKey(url);
  if (!k) return null;
  const v = Object.hasOwn(index.remotes, k) ? index.remotes[k] : undefined;
  return v === undefined ? { state: "not-listed" } : result(v);
}
