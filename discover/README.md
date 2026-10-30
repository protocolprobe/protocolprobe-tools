# ProtocolProbe discovery (feature #17)

Lists the MCP servers configured on **this machine**, and which ones Claude Desktop has started. Zero dependencies
(Node 18+; tests also pass on Node 18.20.8), reads config files only, **sends nothing anywhere**.

```
npx protocolprobe-discover                      # once published; from a checkout: node discover.mjs
npx protocolprobe-discover --dir ../app --dir . # project configs in these directories too
npx protocolprobe-discover --json               # same fields, machine-readable
npx protocolprobe-discover --help | --version
```

In a repository checkout only (not in the published package):

```
node --test discover.test.mjs registry-match.test.mjs package.test.mjs   # tests (20)
node build-index.mjs --registry <registry dump.ndjson> --snapshot YYYY-MM-DD   # rebuild the registry snapshot (each registry refresh)
```

## Match against the official MCP registry (offline)

For every package a known runner starts (npm, PyPI, OCI image) and every remote URL, it looks the server up in
`registry-index.json.gz`, a snapshot of the official registry (latest version of each server) built by
`build-index.mjs`. The lookup is local: **no network call is made**. The output says `registry: listed as <name> →
https://protocolprobe.com/mcp/servers/<name>` (that page shows what we checked and what we did not), `shared by N
registry entries` when a key belongs to several (never guessed), or `not found in the snapshot` (the server may be
newer, unpublished or not a registry server; this says nothing about its safety). A local script or an unrecognised
command is not matched. The snapshot date is printed in the output; the file is regenerated on each registry refresh.

Measured on the 2026-10-28 snapshot (51,834 servers): 18,014 package keys, 97.3% belong to exactly one server; 34,132
remote host+path keys, 99.8% belong to exactly one. **Not everything people run is in it:** the reference servers
`@modelcontextprotocol/server-filesystem`, `-server-memory` and `mcp-server-sqlite-npx` are not registry packages, so they
show `not found`. Only latest versions count: a package whose only registry row is an old version is not listed.

## What it never shows

Config files hold API keys in env values, header values, command arguments, URL queries and sometimes URL paths.
The rule is: **if a value is not known to be safe, it is not shown, only counted.**

- Never shown: env and header values; a remote host that the registry does not list is shortened to its last two
  labels (`*.supabase.co`), and a label of 12+ letters-and-digits is replaced; env variable names that are not in the
  conventional upper-case shape (they are counted); a server name with a single word of 25+ characters; command arguments; URL userinfo, query and fragment; a URL built from
  variables (`${…}`); every URL path segment except generic endpoint words (`mcp`, `sse`, `api`, `v1`, …, see
  `PATH_WORDS` in lib.mjs), shown as `*`, unless the registry lists that exact URL (then the public path is shown); package
  names that are not "plain names" (short lower-case words joined by `.` `_` `-` `~`, optional leading `@`; mixed
  case, hex, many digits or long words fail); a command string that carries its own arguments (`"npx -y pkg --token=…"`); a package name when an
  unknown flag comes before it (its value could be next); server and log names that look like a credential (`ghp_`,
  `sk-`, `AKIA`, JWTs, long letter-and-digit runs, hex, mixed case with digits), replaced by
  "(name not shown: looks like a credential)".
- Shown: server name, client and scope, transport (one of stdio/http/streamable-http/sse/ws, else "other"), the
  command's base name, a package name from a known runner (`npx`, `bunx`, `pnpm dlx`, `uvx`, `pipx run`,
  `docker run`) when every flag before it is known, a remote URL's origin and plain path, counts of arguments, env
  variables and headers, and env variable **names**. Paths under your home folder are shown as `~`. Control
  characters in names from a config file are escaped, so a config cannot rewrite the terminal output.
- Tested with config files full of fake secrets in every place an independent review found (2026-10-10): none appears
  in the text or JSON output. Re-checked 2026-10-14 with 13 more planted secrets (arguments, env, headers, URL
  userinfo/query/fragment, docker `-e`, uv index URL, `mcp-remote --header`, names): none appears, and the two paths
  that did pass (a letters-only per-account host, a lower-case env name) are closed and have tests. 15 tests;
  19 of 21 code mutations of the 2026-10-14 code are caught; the two not caught change no output (a guard that cannot be
  reached because package keys always carry an `npm:`/`pypi:`/`oci:` prefix, and a URL check that a second check repeats). Run on Windows only; macOS and Linux
  paths are asserted, not run.

## Where it looks (from each vendor's documentation, read 2026-10-10)

| client | files | key |
|---|---|---|
| Claude Desktop | macOS `~/Library/Application Support/Claude/claude_desktop_config.json`, Windows `%APPDATA%\Claude\claude_desktop_config.json`; logs `~/Library/Logs/Claude`, `%APPDATA%\Claude\logs` (`mcp-server-NAME.log`) | `mcpServers` |
| Claude Code | `~/.claude.json` (user scope, and `projects[path]` local scope), `<project>/.mcp.json` (also read by VS Code) | `mcpServers` |
| Cursor | `~/.cursor/mcp.json`, `<project>/.cursor/mcp.json` | `mcpServers` |
| VS Code | `<project>/.vscode/mcp.json`; user `mcp.json` in the profile folder (`%APPDATA%\Code\User`, `~/Library/Application Support/Code/User`, `~/.config/Code/User`, plus `profiles/<id>/`; also `Code - Insiders`); `~/.copilot/mcp-config.json` | `servers` (`mcpServers` for the Copilot file) |

Sources: code.claude.com/docs/en/mcp · cursor.com/docs/context/mcp ·
code.visualstudio.com/docs/copilot/customization/mcp-servers · code.visualstudio.com/docs/configure/profiles.
The Claude Desktop paths come from the project's research log (real probe, 2026-10-03).

## Limits (stated, not hidden)

- Only these clients and locations. Not seen: other clients, enterprise-managed files (`managed-mcp.json`), Claude
  Code plugin servers and its approve/disable lists in `.claude/settings.json` (so a `.mcp.json` server is listed
  even if it was rejected), `CLAUDE_CONFIG_DIR` and `$COPILOT_HOME` relocations, VS Code devcontainer and remote
  configs, VS Code's discovery of Claude Desktop servers, and servers started outside a config file. Claude Desktop
  extensions and the Store build's storage were not checked.
- Project configs are found only in the directories you pass (default: the current one); it does not search the disk.
- "Started" evidence exists only for Claude Desktop, and log files persist: a server listed there was started at some
  point, not necessarily now.
- The VS Code default-profile location (`…/Code/User/mcp.json`) is inferred from VS Code's profile-folder docs; the
  user-level file is documented as "in your user profile folder".
- The secret heuristics are conservative but not perfect. What can still pass: a credential used as the whole
  registrable domain with fewer than 12 characters; a server name a person picked that is shorter than 25 characters per word (names
  like `Context7` or `Neo4jMemory` stay visible); a project folder name inside a `local (~project)` scope. Hosts and
  env names were tightened on 2026-10-14 after a letters-only per-account host and a lower-case env name passed.
- `npx mcp-remote <url>` is read as a remote: the URL that follows the package is shortened and matched by the same rules
  as a `url` entry (never shown as written, headers ignored). Other programs' arguments are never read.
- The registry snapshot ages. After 60 days the output warns that newer servers show as "not found"; rebuild it with
  `build-index.mjs` on each registry refresh (docs/FUTURE-TASKS.md section 6).
- Over-redaction (safe side, nothing leaks): upper-case path segments (`/MCP` → `/*`), mixed-case package names
  (`Flask-MCP`), `==` version pins (`mcp-proxy==0.8.2`) and images from a registry with a port
  (`localhost:5000/my-mcp`) are not shown as packages or path words.
- Speed: a plain-JSON file of 44.5 MB parses in about 0.24 s; a JSON-with-comments file (VS Code) of the same size
  would take about 12.5 s (measured). Real VS Code files are small.
- Tested on Windows against fixture files in every layout (and macOS/Linux paths by assertion); on this machine only
  `~/.claude.json` existed (0 servers).
