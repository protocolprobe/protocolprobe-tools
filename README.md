# ProtocolProbe tools

Three small tools from [ProtocolProbe](https://protocolprobe.com), a directory of dated facts about MCP (Model Context Protocol)
servers, with tools for the people who run them. The first two run on **your own machine** and send nothing to ProtocolProbe; the
third is an MCP server that reads ProtocolProbe's public API. All three are published on npm under the ISC licence.

| tool | what it does | npm |
|---|---|---|
| [`selftest`](selftest) | Runs ProtocolProbe's MCP security checks against **an MCP server you run**: a local stdio server, or your own Streamable HTTP server after it proves you control that exact URL. Results stay on your machine. | [`protocolprobe-selftest`](https://www.npmjs.com/package/protocolprobe-selftest) |
| [`discover`](discover) | Lists the MCP servers configured on this machine and, offline, which ones are in the official MCP registry. Reads config files only, sends nothing anywhere, never prints secrets. | [`protocolprobe-discover`](https://www.npmjs.com/package/protocolprobe-discover) |
| [`mcp`](mcp) | A read-only MCP server over ProtocolProbe's public API, for an AI client: the nine record checks of a registry server, server names by topic, the registry size and the daily registry changes. No key. The names you ask about are sent to protocolprobe.com. Facts from public records, not a rating. | [`protocolprobe-mcp`](https://www.npmjs.com/package/protocolprobe-mcp) |

```
npx protocolprobe-discover
npx protocolprobe-selftest --i-own-this-server --stdio node ./dist/server.js
```

The MCP server is added to an MCP client's server list (where that list lives depends on the client):

```json
{ "mcpServers": { "protocolprobe": { "command": "npx", "args": ["-y", "protocolprobe-mcp"] } } }
```

Read each tool's own README before running it. `selftest` is dual-use (two of its checks are off unless you turn them on)
and only for servers you own: see [selftest/DISCLOSURE](selftest/DISCLOSURE).

## Questions, ideas, problems

- Questions and ideas: [Discussions](../../discussions)
- A bug or a wrong result: [open an issue](../../issues/new/choose) (say the tool, its version, your Node version and
  what you ran; **never paste tokens, keys or the one-time proof value**)
- A security problem in these tools: see [SECURITY.md](SECURITY.md)

## About this repository

This repository holds the published source of the three tools, copied from ProtocolProbe's main (private) repository at each
release. The tools' tests live with the rest of the engine there, so they are not in this copy. Pull requests are welcome;
a change accepted here is carried back by the maintainers.

The directory, the data and the research behind it are at [protocolprobe.com](https://protocolprobe.com).
