// Feature #17: the offline registry match, host shortening, env-name and name rules added 2026-10-14 after the deep check
// (a letters-only per-account host and a lower-case credential-like env name both passed the first version).
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import zlib from "node:zlib";
import { buildIndex, matchPackage, matchRemote, normPackage, remoteKey } from "./registry-index.mjs";
import { conventionalEnvName, describe, safeRemote, shownHost } from "./lib.mjs";
import { loadIndex, render, scan } from "./discover.mjs";
import { REG, testIndex } from "./test-support.mjs";

const w = (f, s) => { fs.mkdirSync(path.dirname(f), { recursive: true }); fs.writeFileSync(f, s); };
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), "ppdisc-r-"));

test("hosts: shown whole only when the registry lists them, else shortened; a per-account host token never prints", () => {
  const hosts = new Set(["server.smithery.ai"]);
  const h = (u, set = hosts) => shownHost(new URL(u), set);
  assert.equal(h("https://server.smithery.ai/x"), "server.smithery.ai");
  assert.equal(h("https://abcdefghijklmnopqrst.supabase.co/mcp"), "*.supabase.co");   // a letters-only project reference
  assert.equal(h("https://a.b.c.example.com:8443/m"), "*.example.com:8443");
  assert.equal(h("https://example.com/m"), "example.com");                            // a bare two-label domain
  assert.equal(h("https://localhost:3000/m"), "localhost:3000");
  assert.equal(h("http://127.0.0.1:8080/m"), "127.0.0.1:8080");
  assert.equal(h("http://[::1]:8080/m"), "[::1]:8080");
  assert.equal(h("https://kP3xQ9mZtR7wLbYv2.io/m"), "*.io");                          // a token as the whole domain label
  assert.equal(h("https://tok.en.xyz.example.org/m", null), "*.example.org");         // no registry hosts at all
  assert.equal(safeRemote("https://abcdefghijklmnopqrst.supabase.co/mcp?project_ref=SECRETREF"), "https://*.supabase.co/mcp");
});

test("env names: only the conventional upper-case shape is listed; lower-case and long single words are counted only", () => {
  for (const k of ["GITHUB_PERSONAL_ACCESS_TOKEN", "API_KEY", "TZ", "OPENAI_API_KEY"]) assert.equal(conventionalEnvName(k), true, k);
  for (const k of ["lowercasesecretnamethatisakey", "ABCDEFGHIJKLMNOPQRSTUVWX", "ghp_LEAKENVNAME1234567890", "1BAD", "", "Mixed_Case", "A".repeat(65)]) assert.equal(conventionalEnvName(k), false, k);
  const d = describe({ command: "node", env: { API_KEY: "x", lowercasesecretnamethatisakey: "y", ABCDEFGHIJKLMNOPQRSTUVWX: "z" } });
  assert.deepEqual(d.envNames, ["API_KEY"]);
  assert.equal(d.envVars, 3);
});

test("server names a person picked stay visible; a single 25+ character word is hidden in text and JSON", () => {
  const home = path.join(tmp(), "home");
  w(path.join(home, ".claude.json"), JSON.stringify({ mcpServers: { "My-Server_2": { command: "node" }, abcdefghijklmnopqrstuvwxyzabc: { command: "node" }, "ok name": { command: "node" } } }));
  const r = scan({ platform: "linux", home, dirs: [], index: null });
  const names = r.servers.map((s) => s.name);
  assert.ok(names.includes("My-Server_2") && names.includes("ok name"));
  for (const out of [render(r), JSON.stringify(r)]) assert.equal(out.includes("abcdefghijklmnopqrstuvwxyzabc"), false);
});

test("registry index: latest version only, valid names, npm/PyPI/OCI keys normalised; shared keys are counted, never guessed", () => {
  const i = buildIndex(REG, "2026-01-01");
  assert.equal(i.servers, 6);                                              // the non-latest row and the invalid name do not count
  assert.equal(i.packages["npm:@scope/gh-mcp"], "io.github.acme/gh");
  assert.equal(i.packages["pypi:mcp-server-time"], "io.github.acme/time");  // PEP 503 spelling
  assert.equal(i.packages["oci:img/x"], "io.github.acme/img");              // docker.io/ and the tag removed
  assert.equal(i.packages["npm:shared-mcp"], 2);
  assert.equal("npm:old-mcp" in i.packages, false);
  assert.equal("npm:bad-name-mcp" in i.packages, false);
  assert.equal(i.remotes["server.smithery.ai/@smithery/server/mcp"], "com.smithery/server");  // trailing slash dropped
  assert.deepEqual(i.hosts, ["server.smithery.ai"]);
  assert.equal(normPackage("npm", "@Scope/Pkg@1.2.3"), "@scope/pkg");
  assert.equal(normPackage("oci", "ghcr.io/a/b@sha256:abc123"), "ghcr.io/a/b");
  assert.equal(normPackage("oci", "library/nginx:latest"), "nginx");
  assert.equal(remoteKey("https://H.Example:8443/a/b/?k=SECRET#f"), "h.example:8443/a/b");
  assert.equal(remoteKey("file:///x"), null);
  assert.equal(normPackage("cargo", "x"), null);
});

test("matching: listed, several, not-listed, null when nothing can be matched; prototype keys never match", () => {
  const i = testIndex();
  assert.deepEqual(matchPackage({ runner: "npx", name: "@scope/gh-mcp@1.2.0" }, i), { state: "listed", name: "io.github.acme/gh", url: "https://protocolprobe.com/mcp/servers/io.github.acme/gh" });
  assert.equal(matchPackage({ runner: "uvx", name: "mcp-server-time" }, i).name, "io.github.acme/time");
  assert.equal(matchPackage({ runner: "docker", name: "img/x:1" }, i).name, "io.github.acme/img");
  assert.deepEqual(matchPackage({ runner: "npx", name: "shared-mcp" }, i), { state: "several", count: 2 });
  assert.deepEqual(matchPackage({ runner: "npx", name: "unknown-mcp" }, i), { state: "not-listed" });
  assert.deepEqual(matchPackage({ runner: "npx", name: "constructor" }, i), { state: "not-listed" });
  assert.equal(matchPackage(null, i), null);
  assert.equal(matchPackage({ runner: "npx", name: "x" }, null), null);
  assert.equal(matchRemote("https://server.smithery.ai/@smithery/server/mcp?token=SECRET", i).name, "com.smithery/server");
  assert.deepEqual(matchRemote("https://other.example/mcp", i), { state: "not-listed" });
  assert.equal(matchRemote("not a url", i), null);
  assert.deepEqual(matchRemote("http://constructor/", i), { state: "not-listed" });   // a one-label host named like an Object property
});

test("output carries the registry line and snapshot; no secret leaks through the match; a missing or foreign index degrades safely", () => {
  const root = tmp(), home = path.join(root, "home");
  w(path.join(home, ".claude.json"), JSON.stringify({ mcpServers: {
    gh: { command: "npx", args: ["-y", "@scope/gh-mcp", "--token=LEAKARG"], env: { GITHUB_TOKEN: "LEAKENV" } },
    nolist: { command: "npx", args: ["-y", "unknown-mcp"] },
    sm: { url: "https://user:LEAKUSER@server.smithery.ai/@smithery/server/mcp?key=LEAKQ" },
    script: { command: "node", args: ["server.js", "--key=LEAKSCRIPT"] },
  } }));
  const r = scan({ platform: "linux", home, dirs: [], index: testIndex() });
  const text = render(r), by = Object.fromEntries(r.servers.map((s) => [s.name, s]));
  assert.ok(text.includes("registry: listed as io.github.acme/gh → https://protocolprobe.com/mcp/servers/io.github.acme/gh"));
  assert.ok(text.includes("registry: listed as com.smithery/server"));
  assert.ok(text.includes("as of 2026-01-01 (6 servers)"));
  assert.ok(text.includes("not found in the snapshot") && text.includes("says nothing about its safety"));
  assert.equal(by.script.registry, null);                                  // a local script is not matched
  assert.equal(/LEAK[A-Z]*/.test(text + JSON.stringify(r)), false);
  const none = scan({ platform: "linux", home, dirs: [], index: null });
  assert.equal(none.registrySnapshot, null);
  assert.ok(none.servers.every((s) => s.registry === null));
  assert.equal(render(none).includes("registry:"), false);
  // a missing, corrupt or foreign-format snapshot file: no match, a warning, never a crash
  const miss = loadIndex(path.join(root, "nope.json.gz")); assert.equal(miss.index, null); assert.match(miss.why, /not found/);
  const bad = path.join(root, "bad.json.gz"); fs.writeFileSync(bad, "not gzip");
  assert.match(loadIndex(bad).why, /could not be read/);
  const wrong = path.join(root, "wrong.json.gz"); fs.writeFileSync(wrong, zlib.gzipSync(JSON.stringify({ format: 99 })));
  assert.match(loadIndex(wrong).why, /expected format/);
  const hostile = path.join(root, "hostile.json.gz");
  fs.writeFileSync(hostile, zlib.gzipSync(JSON.stringify({ ...buildIndex(REG, "2026-01-01"), packages: [] })));
  assert.match(loadIndex(hostile).why, /expected format/);
});

test("paths: a URL the registry lists is shown as written; any other keeps only generic endpoint words", () => {
  const i = testIndex();
  const s = (u) => safeRemote(u, i.hostSet, i.remotes);
  assert.equal(s("https://server.smithery.ai/@smithery/server/mcp?k=SECRET"), "https://server.smithery.ai/@smithery/server/mcp");
  assert.equal(s("https://x.example.com/mcp/tokenwordlowercaseonly/sse"), "https://*.example.com/mcp/*/sse");
  assert.equal(s("https://example.com/acme-team/prod/v1/mcp"), "https://example.com/*/*/v1/mcp");
  assert.equal(s("https://example.com/"), "https://example.com/");
  assert.equal(safeRemote("https://example.com/abc"), "https://example.com/*");            // no registry at all
});

test("npx mcp-remote <url>: the URL argument is shortened and matched, never shown as written; other programs' arguments stay hidden", () => {
  const i = testIndex();
  const d = (args, command = "npx") => describe({ command, args }, i);
  const a = d(["-y", "mcp-remote", "https://user:LEAKU@server.smithery.ai/@smithery/server/mcp?key=LEAKQ", "--header", "Authorization:Bearer LEAKH"]);
  assert.equal(a.remote, "https://server.smithery.ai/@smithery/server/mcp");
  assert.equal(a.registry.name, "com.smithery/server");
  assert.deepEqual(a.package, { runner: "npx", name: "mcp-remote" });
  const b = d(["mcp-remote@latest", "https://abcdefghijklmnop.supabase.co/x/LEAKPATH?k=LEAKQ2", "--transport", "sse-only"]);
  assert.equal(b.remote, "https://*.supabase.co/*/*");
  assert.deepEqual(b.registry, { state: "not-listed" });
  assert.equal(d(["mcp-remote"]).remote, null);                                         // no URL after the package
  assert.equal(d(["-y", "mcp-remote", "--header", "X-Url:https://leak.example.com/LEAKH2"]).remote, null);   // a header that contains a URL is not the URL
  assert.equal(d(["-y", "other-pkg", "https://x.example.com/a?k=LEAKX"]).remote, null);      // only mcp-remote is read this way
  assert.equal(d(["server.js", "https://x.example.com/a?k=LEAKX"], "node").remote, null);
  assert.equal(JSON.stringify([a, b]).includes("LEAK"), false);
  const text = render({ platform: "linux", scannedAt: "t", warnings: [], files: [], servers: [{ name: "r", client: "c", scope: "s", ...a }], claudeDesktopStarted: null, registrySnapshot: null });
  assert.ok(text.includes("npx mcp-remote → remote https://server.smithery.ai/@smithery/server/mcp"));
});

test("an old registry snapshot is reported; a fresh one is not; a future-dated one never crashes", () => {
  const idx = testIndex();   // snapshot 2026-01-01
  const at = (day) => scan({ platform: "linux", home: tmp(), dirs: [], index: idx, now: new Date(`${day}T00:00:00Z`) }).warnings;
  assert.deepEqual(at("2026-02-15"), []);
  assert.equal(at("2026-04-01").length, 1);
  assert.match(at("2026-04-01")[0], /90 days old \(2026-01-01\).*"not found"/);
  assert.deepEqual(at("2025-12-01"), []);
});

test("the shipped snapshot loads in the expected shape and matches real registry entries", () => {
  const { index, why } = loadIndex();
  assert.equal(why, undefined);
  assert.ok(index.servers > 30000 && /^\d{4}-\d{2}-\d{2}$/.test(index.snapshot));
  assert.deepEqual(Object.keys(index).sort(), ["format", "hostSet", "hosts", "packages", "remotes", "servers", "snapshot", "source"]);
  assert.equal(matchPackage({ runner: "npx", name: "@upstash/context7-mcp" }, index).name, "io.github.upstash/context7");
  assert.equal(matchRemote("https://api.inference.sh/mcp?x=1", index).name, "ac.inference.sh/mcp");
  // names in the snapshot are registry names only (they are printed): no spaces, no control characters
  assert.ok(Object.values({ ...index.packages, ...index.remotes }).every((v) => typeof v === "number" || /^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/.test(v)));
});
