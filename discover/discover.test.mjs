// Feature #17 discovery: formats per vendor docs, JSONC, runner recognition, and above all: no secret ever printed.
// Every leak path found by the independent review (2026-10-10) is a fixture here.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { testIndex } from "./test-support.mjs";
import { claudeDesktopLogDir, commandName, describe, entriesOf, looksSecret, packageOf, ranFromLogNames, safeRemote, stripJsonc, userLocations } from "./lib.mjs";
import { parseArgs, render, scan } from "./discover.mjs";

const w = (f, s) => { fs.mkdirSync(path.dirname(f), { recursive: true }); fs.writeFileSync(f, s); };

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ppdisc-"));
  const home = path.join(root, "home"), appData = path.join(root, "appdata"), proj = path.join(root, "proj");
  w(path.join(appData, "Claude", "claude_desktop_config.json"), JSON.stringify({ mcpServers: {
    fs: { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem", String.raw`C:\Users\me\LEAK_PRIVATEDIR`] },
    gh: { command: String.raw`C:\Program Files\nodejs\npx.cmd`, args: ["-y", "@scope/gh-mcp@1.2.0", "--token=LEAK_ARGTOKEN"], env: { GITHUB_TOKEN: "LEAK_ENVVAL1", API_KEY: "LEAK_ENVVAL2", ghp_LEAKENVNAME1234567890: "" } },
    oneline: { command: "npx -y pkg --token=LEAK_CMDSPACE" },
    nodeinline: { command: String.raw`node C:\x\server.js --key=LEAK_CMDPATH` },
    positional: { command: "npx", args: ["ghp_LEAKPOSITIONAL1234567"] },
    refresh: { command: "uvx", args: ["--refresh-package", "LEAK_UVXREFRESH", "mcp-server-time"] },
    unknownflag: { command: "uvx", args: ["--some-new-flag", "LEAK_UNKNOWNFLAG", "pkg"] },
    dockhost: { command: "docker", args: ["run", "--hostname", "LEAK_DHOST", "--add-host", "LEAKADD:10.0.0.1", "-e", "T=LEAK_DENV", "--env=K=LEAK_DENV2", "img/x:1"] },
    weirdtype: { type: "http LEAK_TYPE", url: "https://ok.example/mcp" },
    ctrl: { command: "node", args: [] },
  } }));
  // a name with terminal escapes and a newline that would forge an output line
  const cfg = JSON.parse(fs.readFileSync(path.join(appData, "Claude", "claude_desktop_config.json"), "utf8"));
  cfg.mcpServers["evil\u001b[2K\u001b[1A\r\n  fake — remote https://ok.example/"] = { command: "node" };
  cfg.mcpServers["name‮evil"] = { command: "node" };                                  // right-to-left override
  cfg.mcpServers["LEAKNAMEghp_abc123def456ghi789jkl"] = { command: "node" };              // credential as a name
  cfg.mcpServers.shortpath = { type: "sse", url: "https://h.example/mcp/s/kP3xQ9mZtRwLbYvL/sse" };
  cfg.mcpServers.hexpath = { type: "http", url: "https://h.example/mcp/deadbeefcafebabe" };
  cfg.mcpServers.mixedpkg = { command: "npx", args: ["-y", "kP3xQ9mZtR7wLbYv"] };
  cfg.mcpServers.smithery = { type: "http", url: "https://server.smithery.ai/@smithery/server/mcp" };
  cfg.mcpServers.dated = { type: "http", url: "https://h.example/mcp/2025-06-18" };
  w(path.join(appData, "Claude", "claude_desktop_config.json"), JSON.stringify(cfg));
  w(path.join(appData, "Claude", "logs", "mcp-server-fs.log"), "x");
  w(path.join(appData, "Claude", "logs", "mcp.log"), "x");
  w(path.join(appData, "Claude", "logs", "mcp-server-LEAKLOGghp_abc123def456ghi789jkl.log"), "x");
  w(path.join(home, ".claude.json"), JSON.stringify({ mcpServers: {
      remote1: { type: "http", url: "https://user:LEAK_USERINFO@api.example.com/mcp?key=LEAK_QUERY#LEAK_FRAG", headers: { Authorization: "Bearer LEAK_HEADER" } },
      zap: { type: "sse", url: "https://actions.zapier.com/mcp/sk-ak-LEAKURLPATH123456789/sse" },
      varurl: { type: "http", url: "${API_BASE_URL:-https://api.example.com}/mcp?k=LEAK_VARURL" },
      wsurl: { serverUrl: "wss://h.example/socket" },
    },
    projects: { [path.join(home, "work", "app").split(path.sep).join("/")]: { mcpServers: { py: { command: "uvx", args: ["--from", "git+https://LEAK_GITURL", "mcp-server-time"], env: { TZ_KEY: "LEAK_ENVVAL3" } } } } } }));
  w(path.join(home, ".cursor", "mcp.json"), JSON.stringify({ mcpServers: { dock: { command: "docker", args: ["run", "-i", "--rm", "-e", "TOKEN=LEAK_DOCKENV", "ghcr.io/acme/mcp:1.0"], disabled: true } } }));
  w(path.join(home, ".copilot", "mcp-config.json"), JSON.stringify({ mcpServers: { cop: { command: "node" } } }));
  w(path.join(appData, "Code", "User", "mcp.json"), "\uFEFF// user servers\n{ \"servers\": { \"vs\": { \"type\": \"sse\", \"url\": \"https://h.example/sse\", \"headers\": { \"X-Api-Key\": \"LEAK_HDR2\" }, }, }, }");
  w(path.join(appData, "Code - Insiders", "User", "mcp.json"), JSON.stringify({ servers: { ins: { command: "node" } } }));
  w(path.join(appData, "Code", "User", "profiles", "abc1", "mcp.json"), `{ "servers": { "inprofile": { "command": "node", "args": ["server.js", "--key", "LEAK_PROFILEARG"] } } }`);
  w(path.join(proj, ".mcp.json"), JSON.stringify({ mcpServers: { projsrv: { command: "pnpm", args: ["dlx", "some-mcp"] } } }));
  w(path.join(proj, ".vscode", "mcp.json"), "{ not json");
  return { home, appData, proj };
}
const run = (f, dirs) => scan({ platform: "win32", home: f.home, appData: f.appData, dirs: dirs ?? [f.proj], index: testIndex(), now: new Date("2026-01-15T00:00:00Z") });

test("no secret appears anywhere in the text or JSON output (every leak path from the review)", () => {
  const f = fixture();
  const r = run(f);
  for (const out of [render(r), JSON.stringify(r)]) {
    const leaks = out.match(/LEAK[A-Z0-9_]*/g);
    assert.equal(leaks, null, `leaked: ${leaks}`);
    assert.equal(/ghp_|sk-ak-|git\+https/.test(out), false, "credential-looking text leaked");
  }
  const text = render(r);
  assert.equal(/\u001b|\r|‮/.test(text), false, "raw control characters printed");
  for (const out of [text, JSON.stringify(r)]) for (const t of ["kP3xQ9mZtRwLbYvL", "deadbeefcafebabe", "kP3xQ9mZtR7wLbYv"]) assert.equal(out.includes(t), false, `token ${t}`);
  assert.equal(text.split("\n").some((l) => l.startsWith("  fake")), false, "a forged output line");
});

test("finds servers in every documented location (Windows layout)", () => {
  const f = fixture();
  const r = run(f);
  const names = new Set(r.servers.map((s) => s.name));
  for (const n of ["fs", "gh", "remote1", "zap", "varurl", "wsurl", "py", "dock", "cop", "vs", "ins", "inprofile", "projsrv"]) assert.ok(names.has(n), n);
  assert.equal(r.servers.find((s) => s.name === "py").scope, `local (~${path.sep}work${path.sep}app)`);
  assert.equal(r.servers.find((s) => s.name === "projsrv").client, "Claude Code / VS Code");
  assert.equal(r.files.find((x) => x.file.endsWith(path.join(".vscode", "mcp.json"))).status, "not valid JSON");
  assert.ok(r.files.every((x) => !x.file.includes(f.home)), "home path shown as ~");
  assert.deepEqual(r.claudeDesktopStarted.servers, ["(name not shown: looks like a credential)", "fs"]);
  const by = Object.fromEntries(r.servers.map((s) => [s.name, s]));
  assert.equal(by.smithery.remote, "https://server.smithery.ai/@smithery/server/mcp");   // legit paths stay readable
  assert.equal(by.dated.remote, "https://h.example/mcp/*");                              // an unlisted URL keeps only generic endpoint words
  assert.equal(by.shortpath.remote, "https://h.example/mcp/*/*/sse");
  assert.equal(by.hexpath.remote, "https://h.example/mcp/*");
  assert.equal(by.mixedpkg.package, null);
});

test("recognised packages, safe remotes and transports; everything else only as counts", () => {
  const by = Object.fromEntries(run(fixture()).servers.map((s) => [s.name, s]));
  assert.deepEqual(by.fs.package, { runner: "npx", name: "@modelcontextprotocol/server-filesystem" });
  assert.deepEqual(by.gh.package, { runner: "npx", name: "@scope/gh-mcp@1.2.0" });
  assert.equal(by.gh.command, "npx");
  assert.deepEqual(by.gh.envNames.sort(), ["API_KEY", "GITHUB_TOKEN"]);
  assert.equal(by.gh.envVars, 3);
  assert.equal(by.oneline.command, null);
  assert.equal(by.nodeinline.command, null);
  assert.equal(by.positional.package, null);
  assert.deepEqual(by.refresh.package, { runner: "uvx", name: "mcp-server-time" });
  assert.equal(by.unknownflag.package, null);
  assert.equal(by.dockhost.package?.name, "img/x:1");
  assert.deepEqual(by.dock.package, { runner: "docker", name: "ghcr.io/acme/mcp:1.0" });
  assert.equal(by.dock.disabled, true);
  assert.deepEqual(by.py.package, { runner: "uvx", name: "mcp-server-time" });
  assert.deepEqual(by.projsrv.package, { runner: "pnpm", name: "some-mcp" });
  assert.equal(by.inprofile.package, null);
  assert.equal(by.inprofile.args, 3);
  assert.equal(by.weirdtype.transport, "other");
  assert.equal(by.remote1.remote, "https://*.example.com/mcp");        // a host the registry does not list is shortened
  assert.equal(by.remote1.headers, 1);
  assert.equal(by.zap.remote, "https://*.zapier.com/mcp/*/sse");
  assert.equal(by.varurl.remote, "(URL built from variables)");
  assert.equal(by.wsurl.transport, "ws");
  assert.equal(by.wsurl.remote, "wss://h.example/socket");
});

test("locations per platform (exact paths) and the Claude Desktop log folder", () => {
  const mac = userLocations({ platform: "darwin", home: "/Users/u" }).map((l) => l.file.split(path.sep).join("/"));
  assert.ok(mac.includes("/Users/u/Library/Application Support/Claude/claude_desktop_config.json"));
  assert.ok(mac.includes("/Users/u/Library/Application Support/Code/User/mcp.json"));
  assert.ok(mac.includes("/Users/u/Library/Application Support/Code - Insiders/User/mcp.json"));
  assert.ok(mac.includes("/Users/u/.copilot/mcp-config.json"));
  const lin = userLocations({ platform: "linux", home: "/home/u" }).map((l) => l.file.split(path.sep).join("/"));
  assert.ok(lin.includes("/home/u/.config/Code/User/mcp.json"));
  assert.ok(lin.includes("/home/u/.claude.json") && lin.includes("/home/u/.cursor/mcp.json"));
  assert.equal(userLocations({ platform: "linux", home: "/home/u" }).some((l) => l.client === "Claude Desktop"), false);
  assert.equal(claudeDesktopLogDir({ platform: "darwin", home: "/Users/u" }).split(path.sep).join("/"), "/Users/u/Library/Logs/Claude");
  assert.equal(claudeDesktopLogDir({ platform: "linux", home: "/home/u" }), null);
});

test("unit pieces: JSONC, secrets heuristics, runners, remotes, log names, CLI, dedupe", () => {
  assert.deepEqual(JSON.parse(stripJsonc('{ // c\n "a": "x // not \\" a comment", /* b */ "b": [1,2,], }')), { a: 'x // not " a comment', b: [1, 2] });
  assert.deepEqual(JSON.parse(stripJsonc("\uFEFF{\"a\":1}")), { a: 1 });
  for (const s of ["ghp_abc", "sk-live-x", "AKIAXXXX", "eyJhbGciOi", "abc123def456ghi789jkl0"]) assert.equal(looksSecret(s), true, s);
  for (const s of ["@modelcontextprotocol/server-filesystem", "mcp-server-time", "ghcr.io/acme/mcp:1.0", "GITHUB_TOKEN"]) assert.equal(looksSecret(s), false, s);
  // common server names a person picked stay visible; a random mixed-case token of 16+ still does not
  for (const s of ["Context7", "Neo4jMemory", "MongoDB4", "GitHub2024", "Win11Tools", "myServer1", "Ubuntu2204"]) assert.equal(looksSecret(s, { name: true }), false, s);
  assert.equal(looksSecret("kP3xQ9mZtRwLbYvL", { name: true }), true);
  assert.equal(looksSecret("Neo4jMemory"), true); // strict mode (paths, packages) still hides it
  assert.equal(commandName(String.raw`C:\Program Files\nodejs\npx.cmd`), "npx");
  assert.equal(commandName("npx -y @scope/pkg"), null);
  assert.equal(packageOf({ command: "npx", args: ["-y", "--token=abc"] }), null);
  assert.equal(packageOf({ command: "npx", args: ["https://evil/x?k=1"] }), null);
  assert.equal(packageOf({ command: "python", args: ["server.py"] }), null);
  assert.equal(packageOf({ command: "npx", args: ["a".repeat(215)] }), null);
  assert.equal(safeRemote("file:///etc/passwd"), null);
  assert.equal(safeRemote("not a url"), null);
  assert.deepEqual(ranFromLogNames(["mcp-server-a.log", "mcp.log", "mcp-server-a.log", "other.txt"]), ["a"]);
  assert.equal(describe({ url: "https://x.example/m" }).transport, "http");
  assert.deepEqual(entriesOf({ projects: { p: { mcpServers: { a: {}, bad: "x" } } }, mcpServers: { b: {} } }, "claude.json").map((e) => e.name), ["b", "a"]);
  assert.deepEqual(parseArgs(["--dir", "a", "--json"]), { dirs: ["a"], json: true });
  assert.ok(parseArgs(["--dir", "--json"]).error);
  assert.ok(parseArgs(["-j"]).error);
  // the same file reached twice is read once; a --dir that is not a directory is reported
  const f = fixture();
  const r = run(f, [f.proj, f.proj, f.home, path.join(f.proj, "nope")]);
  assert.equal(r.servers.filter((s) => s.name === "projsrv").length, 1);
  assert.equal(r.servers.filter((s) => s.name === "dock").length, 1);
  assert.equal(r.warnings.length, 1);
});
