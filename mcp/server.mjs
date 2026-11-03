#!/usr/bin/env node
// protocolprobe-mcp: stdio MCP server over ProtocolProbe's public API. Read-only, no key. See README.md.
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { buildServer, createClient, resolveBase } from "./lib.mjs";

let base;
try {
  base = resolveBase(process.env.PROTOCOLPROBE_API);
} catch (e) {
  process.stderr.write(`${e.message}\n`);
  process.exit(1);
}

await buildServer(createClient({ base })).connect(new StdioServerTransport());
