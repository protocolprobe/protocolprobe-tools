// Shared by the discovery tests: a tiny registry of our own, so tests never depend on the shipped snapshot.
import { buildIndex } from "./registry-index.mjs";

export const REG = [
  { server: { name: "io.github.acme/gh", packages: [{ registryType: "npm", identifier: "@scope/gh-mcp" }] } },
  { server: { name: "io.github.acme/time", packages: [{ registryType: "pypi", identifier: "Mcp_Server.Time" }] } },
  { server: { name: "io.github.acme/img", packages: [{ registryType: "oci", identifier: "docker.io/img/x:1" }] } },
  { server: { name: "io.github.acme/dup1", packages: [{ registryType: "npm", identifier: "shared-mcp" }] } },
  { server: { name: "io.github.acme/dup2", packages: [{ registryType: "npm", identifier: "shared-mcp" }] } },
  { server: { name: "com.smithery/server", remotes: [{ type: "streamable-http", url: "https://server.smithery.ai/@smithery/server/mcp/" }] } },
  { server: { name: "io.github.old/gone", packages: [{ registryType: "npm", identifier: "old-mcp" }] }, _meta: { "io.modelcontextprotocol.registry/official": { isLatest: false } } },
  { server: { name: "not a valid name", packages: [{ registryType: "npm", identifier: "bad-name-mcp" }] } },
];
export const testIndex = () => { const i = buildIndex(REG, "2026-01-01"); return { ...i, hostSet: new Set(i.hosts) }; };
