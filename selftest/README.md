# protocolprobe-selftest

Runs ProtocolProbe's MCP server checks against **an MCP server you run**, from your own machine: a server this command
starts (`--stdio`), or, from 0.2.0, **your own Streamable HTTP server at a URL** (`--url`), after the server proves you
control that exact URL.

```
npx protocolprobe-selftest --i-own-this-server --stdio node ./dist/server.js
npx protocolprobe-selftest --i-own-this-server --allow-mutating --allow-fuzzing --out report.json --stdio node ./dist/server.js
npx protocolprobe-selftest --i-own-this-server --url https://mcp.example.com/mcp
npx protocolprobe-selftest --i-own-this-server --bearer-env MY_MCP_TOKEN --url https://mcp.example.com/mcp
```

Python (needs [uv](https://docs.astral.sh/uv/)):

```
npx protocolprobe-selftest --i-own-this-server --stdio uv run --directory . server.py
npx protocolprobe-selftest --i-own-this-server --stdio uvx your-package
```

(From a checkout: `node selftest.mjs ...`. Everything after `--stdio` is your server's command line.) The server is started
in a temporary folder, so keep `--directory .` with `uv run`: a plain `uv run server.py` does not find your project there.

## A server at a URL (`--url`, 0.2.0)

Only your own server, and only after a one-time proof:

1. Run the command with `--url`. It connects to nothing. It prints a line such as
   `protocolprobe-proof=pp1-...` and exits with code 3.
2. Add that line, **on a line of its own**, to your MCP server's instructions (the `instructions` text the server returns
   at initialize; in the official SDKs it is a server option, for example `new McpServer(info, { instructions })` in
   TypeScript). Deploy.
3. Run the same command again **within 30 minutes**. It connects, reads the instructions, and if the line is there it runs
   the checks on that same connection. Then the value is used up: remove the line.

Rules (each is enforced and tested):

- the value works **once**, and only for the **exact URL** it was made for: scheme, host, port, path and query. Another
  path, query or port gets its own new value;
- after **30 minutes** it expires (`--new-proof` discards a pending value and makes a fresh one);
- **no redirect is followed**, same-origin or not: use the URL your server really answers on;
- the host name is **resolved once**; every connection of the run goes to that address, so a DNS change during the run is
  not followed. https certificates are still checked against the host name;
- `https://` for any host; `http://` only for this machine (`localhost`, `127.0.0.1`, `::1`);
- **no token or header is sent unless you give one** (0.3.0, below). A server that needs a credential (HTTP 401/403, or an
  "authentication required" error at initialize) and gets none is refused with a message and not tested;
- **Streamable HTTP only**, not the older SSE transport;
- only a hash of the value is kept, in a small file on your machine (Windows `%LOCALAPPDATA%\protocolprobe-selftest`, macOS
  `~/Library/Application Support/protocolprobe-selftest`, elsewhere `$XDG_STATE_HOME` or `~/.local/state`; set
  `PROTOCOLPROBE_SELFTEST_STATE_DIR` to choose another folder, for example in CI). The value itself is not stored, so it
  cannot be printed again: use `--new-proof`.

Exit codes: `0` result printed · `1` could not start or connect, or `--max-time` · `2` refused arguments · `3` proof value
made (add it, run again) · `4` refused, proof not shown (missing, wrong value, not on its own line, expired, redirect,
credential needed), or your server refused the credential you supplied. On 1, 2 and 4 no check runs · `5` (0.4.0, only
with `--fail-on-finding`) result printed, and at least one check needs attention (`VULNERABLE` or `FOUND`).

### In CI (0.4.0)

```bash
npx protocolprobe-selftest --i-own-this-server --fail-on-finding --sarif selftest.sarif --stdio node ./dist/server.js
```

`--fail-on-finding` makes the job fail (exit 5) when a check needs attention; without it the exit code is 0 whatever the
result, as before. `--sarif` also writes the result as SARIF 2.1.0, which GitHub code scanning reads (upload it with the
`github/codeql-action/upload-sarif` action). Only checks that need attention become SARIF results (`VULNERABLE` = error,
`FOUND` = warning, a heuristic match to review); the score and what did not run are in `runs[0].properties`. A finding is
about the running server, not a line of code, so every result points at line 1 of one file: `--sarif-anchor <file>`, or by
default the first file in your `--stdio` command that is inside the current folder (not the value of an option such as
`--env-file .env`). With neither, the results carry no location: the file is still valid SARIF, but GitHub does not display
them. The path is relative to the folder you run the command in, so run it from the repository root. The file is written on
your machine only, and does not include your command line (a key typed on it might not be recognised as one).

In a GitHub Actions workflow, a step that exits 5 stops the steps after it, so give the upload step `if: always()`; otherwise
the SARIF is not uploaded in exactly the case where there are findings.

### A server that needs a credential (0.3.0)

Give your own credential through an **environment variable**, never on the command line (there is no option that takes
the value: shell history and the process list would keep it):

```
# bash: read it without echo and without putting it in your history, then run
read -rs MY_MCP_TOKEN && export MY_MCP_TOKEN
npx protocolprobe-selftest --i-own-this-server --bearer-env MY_MCP_TOKEN --url https://mcp.example.com/mcp
# a custom header instead
npx protocolprobe-selftest --i-own-this-server --header-env X-Api-Key=MY_API_KEY --url https://mcp.example.com/mcp
```

In CI, set the variable from the CI's secret store. Anything else that sets an environment variable works too; avoid
typing the value itself into a command line, which your shell may keep in its history.

- `--bearer-env VAR` sends `Authorization: Bearer <value of VAR>` (put only the token in VAR). `--header-env Name=VAR`
  sends the header `Name` with the value of `VAR`; it can be given more than once. Only with `--url`.
- A variable that is missing or empty, a value shorter than 8 characters, or a value with a line break is refused (exit 2),
  naming the variable, never showing the value. If you type something that is not a variable name, it is not echoed.
- Header names must be valid HTTP tokens. Refused: `Host`, `Content-Length`, `Transfer-Encoding`, `Expect`, `Connection`,
  `Keep-Alive`, `Proxy-Connection`, `TE`, `Trailer`, `Upgrade`, `Proxy-Authenticate`, `Proxy-Authorization`, `Cookie`,
  `Set-Cookie`, and the headers the MCP transport sets itself (`Content-Type`, `Accept`, `Mcp-Session-Id`,
  `Mcp-Protocol-Version`, `Last-Event-ID`).
- The credential is sent **only to the exact proven URL**, with every request of the session that reads the proof and runs
  the checks (including initialize). It is **not** sent on a redirect (none is followed), **not** to OAuth metadata, even on
  the same host (those documents are public by design, and another app may live on another path of the same host), and
  **not** to one extra initialize sent without credentials, which tells you, as a fact, whether your server also opens a
  session with no credential at all ("Without your credential: ...").
- It is **never printed, never written to `--out`, never stored** in the proof file. Its exact value (as is, JSON-escaped
  and URL-encoded) is replaced by `[redacted]` in everything this tool prints and writes, also when your server repeats it
  in an error, its instructions or a tool result. Not recognised: the value in another form (for example base64-encoded).
- The proof is still required: a credential shows you are a user of the service, not that you run it.
- If your server refuses it: `refused, no test ran: your server refused the credential you supplied (HTTP 401; ...)`, exit 4.
- Checks 14 (token passthrough) and 15 (token audience) become `NOT-TESTABLE` with what is still missing: 14 needs an
  upstream service we can watch receive the token, 15 a second token issued for another audience. This tool has neither and
  makes up neither. Check 16 is never run.

**What the proof is, and is not.** It stops accidents and casual misuse: nobody can make someone else's server return a fresh
random value. It is **not enforcement**: this tool is open source and can be changed to skip it, and other tools connect to
any URL with no proof. It shows that you control what the server at that URL answers, **not** that you control the platform
under it, and not that the platform's terms allow testing. A server that puts other people's text into its instructions, or
a gateway that passes on another server's instructions, could be proven by someone who does not run it. Use `--url` only for
a server you operate or are authorised to test.

**Over HTTP, fewer checks apply.** The server is not a process this command starts:

- checks 4 (secret leak) and 11 (log leak) are `N-A`: the fake secret they look for is planted only in a process this
  command starts. They are listed under the score as "Not applicable over HTTP, not counted";
- checks 5 (requests to a URL it is given) and 10 (reads outside the folder it was given) use a listener and files on this
  machine: they run for `localhost` / `127.0.0.1` / `::1`, and are `N-A` for any other host;
- checks 14-16 are `N-A` for a server that accepts a session without credentials and was given none; with your credential
  they are `NOT-TESTABLE` (above). OAuth metadata for check 18 is read only on your server's origin, without your
  credential; an authorization server on another host is not contacted. Check 16 never probes anything.

## Through a proxy (`--stdio`)

Through a stdio-to-HTTP proxy (for example `--stdio npx mcp-remote http://localhost:3000/mcp`) the process this command
starts is the proxy, not your server. For a local HTTP server, use `--url http://localhost:3000/mcp` instead, or start it in
stdio mode if its framework allows. Through a proxy:

- checks 4 (secret leak) and 11 (log leak) are `N-A`: the fake secret they look for is planted in the proxy's environment,
  never in your server's. They are listed under the score as "Not applicable through the proxy, not counted";
- checks 5 and 10 still run when the command carries the local address, because your server shares this machine's network
  and files. With a known proxy and no local address in the command they are `N-A` too.

A command is treated as going through a proxy when it names `mcp-remote`, `supergateway`, `mcp-proxy` or
`@pyroprompts/mcp-stdio-to-streamable-http-adapter`, or carries a local `http(s)` address (a server that only takes a local
URL as a setting is treated the same way: two checks are lost, none is wrongly passed). **A proxy not on that list, or a
wrapper script around one, is not detected**, and then checks 4 and 11 can come out clean without meaning anything. The same
is true for a server inside a container or virtual machine (for example `docker run -i ...`): its environment, network and
files are not this machine's. That case was not tested. With `--stdio`, a command that carries a non-local address is refused.

0.1.1 counted check 4 as passed through `mcp-remote` for a server that returns its whole environment; 0.1.2 fixes that.

## What it does

Connects to your server as an MCP client, lists its tools, resources and prompts, calls tools, and prints one line per check
(18 checks, the same engine ProtocolProbe uses). Checks that do not apply say `N-A` with the reason.

| flag | meaning |
|---|---|
| `--i-own-this-server` | required on every run: you run this server and are responsible for testing it |
| `--stdio <command...>` | start your server on this machine with this command line (everything after it) |
| `--url <url>` | your own Streamable HTTP server, after the proof above; cannot be combined with `--stdio` |
| `--new-proof` | with `--url`: discard the pending value for this URL and make a new one |
| `--bearer-env VAR` | with `--url`: send `Authorization: Bearer <value of the environment variable VAR>` to that URL only |
| `--header-env Name=VAR` | with `--url`: send the header `Name` with the value of `VAR` to that URL only (repeatable) |
| `--allow-mutating` | also run check 6: calls tools that look like they change data. They may really change data |
| `--allow-fuzzing` | also run check 7: sends wrong-type, oversized and missing-required input |
| `--out file.json` | also write the full report to this file (on your machine) |
| `--fail-on-finding` | (0.4.0) exit 5 when a check needs attention, so a CI job fails |
| `--sarif file.sarif` | (0.4.0) also write the result as SARIF 2.1.0, for GitHub code scanning (on your machine) |
| `--sarif-anchor <file>` | (0.4.0) the repository file SARIF results point at (default: the first file in the `--stdio` command inside the current folder) |
| `--connect-timeout <s>` | seconds your server may take to start (or answer) and connect, including a first `npx`/`uvx` download (default 180, 5-3600) |
| `--max-time <s>` | the whole run stops after this many seconds: your server is stopped or the connection closed, exit code 1, no result and no `--out` file (default 600, 10-86400, must be longer than `--connect-timeout`) |

Without the two `--allow-*` flags, checks 6 and 7 are reported `NOT-TESTED`, never as a pass.

If a stdio server does not start, the command prints the last 20 lines of its error output (whole lines; the planted canary
and values that look like secrets are hidden) and a hint for a few causes we reproduced or saw, for example a Python server
written for `mcp` 1.x running with 2.x, a wrong `uvx` command name, or a connect timeout during a first download (run the
server's command once by itself, or raise `--connect-timeout`). For a URL, an HTTP error shows its status only.

## API pre-check of your tool list (0.5.0)

After your server lists its tools, the command also runs, **offline** (no network, no model call, nothing sent to any
vendor), the rules we measured for what three AI vendors' APIs accept in a tool list, and prints one line per vendor:

```
Tool list pre-check, three AI vendors' APIs (offline: no network and no model call; nothing was sent to any vendor):
  Anthropic: none of the measured rules matched (not a guarantee)
  OpenAI: may be refused by OpenAI's API: more than 128 tools in one request (the list has 682 tools)
      basis - more than 128 tools in one request: seen in its refusals of 171 public tool lists (2026-10-25)
  Google: may be refused by Google's API: a tool name must start with a letter or an underscore (tool 3d_render)
      basis - ...
```

The rules come from our own run of 2026-10-25/26, in which the tool lists of 22,725 public MCP servers were sent to
Anthropic's, OpenAI's and Google's APIs, and from the vendors' docs pages we read on 2026-10-25. Each line says what it rests
on: a refusal message we saw, a docs page, or (for two Google rules) only an association, where Google's API answered with
a bare "Request contains an invalid argument." that names no cause. An API can have other rules and can change them, so
"none of the measured rules matched" is not a guarantee. The pre-check is not one of the 18 checks: it is not in the score,
not in the SARIF file, and `--fail-on-finding` does not count it. With `--out` it is in the report as `apiRulesPrecheck`.

## What it will not do

- Test a URL without the proof, or follow a redirect.
- Take a credential on the command line, send it anywhere but the exact proven URL, or print, write or store it.
- Send anything to ProtocolProbe or anyone else. The report is printed and, with `--out`, written locally. No account, no
  upload. ProtocolProbe runs and hosts nothing for this command.
- Count a check that did not run. The score is `N of M checks passed` over checks that **ran**; anything switched off or
  blocked is listed under it as "Not run, not counted" and the score is marked PARTIAL. No letter grade. Example:
  `Score: 7 of 8 checks passed (88%)` / `Needs attention: 6 write-without-confirmation (VULNERABLE)`. This is not a
  certificate of safety.
- Hand your environment variables to a stdio server: it starts with the SDK's minimal default environment plus one planted
  canary value (that is how check 4 looks for secret leaks).

## Limit

The proof is an accident and casual-misuse barrier, not enforcement (see above). The `--stdio` address check reads `http(s)`
addresses in the command line only: a wrapper script that reaches someone else's server is not detected, and neither is a
proxy that is not on the list above. Use it only on servers you own or have permission to test. See `DISCLOSURE`.

The code is the engine from <https://protocolprobe.com>, copied unchanged. ISC licence.
