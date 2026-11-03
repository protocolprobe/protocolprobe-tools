// Run by hand: node contract.live.mjs. NOT part of npm test. The real server over stdio against the live API,
// paced 1.5 s between requests. About 12 live requests per run. Not shipped in the package.
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { fileURLToPath } from "node:url";

const BASE = "https://protocolprobe.com/api/v1";
const PACE_MS = 1500;
const wait = () => new Promise((r) => setTimeout(r, PACE_MS));
const BANNED = /\b(grades?|scores?|safe|unsafe|secure|verified|certified|trusted|approved|pass|audit)\b/i;
let requests = 0;

const transport = new StdioClientTransport({ command: process.execPath, args: [fileURLToPath(new URL("./server.mjs", import.meta.url))], env: {}, stderr: "pipe" });
let stderr = "";
const client = new Client({ name: "contract-live", version: "0" });
await client.connect(transport);
transport.stderr?.on("data", (d) => { stderr += d; });

async function tool(name, args, liveRequests) {
  await wait();
  const t0 = Date.now();
  const r = await client.callTool({ name, arguments: args });
  requests += liveRequests;
  const txt = r.content?.[0]?.text ?? "";
  return { ms: Date.now() - t0, isError: !!r.isError, txt, bytes: txt.length, blocks: r.content?.length };
}
async function direct(path) {
  await wait();
  requests++;
  const res = await fetch(BASE + path, { headers: { accept: "application/json", "user-agent": "protocolprobe-mcp-contract-live" } });
  return { status: res.status, json: await res.json() };
}
let okCount = 0, failCount = 0;
const check = (label, cond, extra = "") => { console.log(`  ${cond ? "ok  " : "FAIL"} ${label}${extra ? "  [" + extra + "]" : ""}`); cond ? okCount++ : failCount++; };
const noRatingWords = (s) => !BANNED.test(s.replaceAll("not a security rating", ""));

const tools = (await client.listTools()).tools;
console.log("tools:", tools.map((t) => t.name).join(", "));
check("four tools, all read-only annotated", tools.length === 4 && tools.every((t) => t.annotations?.readOnlyHint === true && t.annotations?.destructiveHint === false && t.annotations?.idempotentHint === true && t.annotations?.openWorldHint === true));

let r = await tool("get_record_checks", { namespace: "io.github.upstash", name: "context7" }, 1);
let j = JSON.parse(r.txt);
const live = await direct("/servers/io.github.upstash/context7");
const rc = j.recordChecks;
check("1  real record returns, nine checks", !r.isError && rc.checks.length === 9, `${r.ms} ms, ${r.bytes} bytes`);
check("2  counts add up", rc.met + rc.checks.filter((c) => c.state === "not-met").length === rc.of && rc.met + rc.checks.filter((c) => c.state === "not-met").length + rc.notApplicable + rc.notChecked === 9, `met ${rc.met} of ${rc.of}, n/a ${rc.notApplicable}, not checked ${rc.notChecked}`);
check("3  same id and state as the API, check by check", live.status === 200 && live.json.server.recordChecks.checks.length === rc.checks.length && live.json.server.recordChecks.checks.every((c, i) => c.id === rc.checks[i].id && c.state === rc.checks[i].state));
check("4  page link, asOf, attribution and note present; no rating words", /^https:\/\/protocolprobe\.com\/mcp\/servers\//.test(j.page) && j.asOf && typeof j.asOf === "object" && /CC BY 4\.0/.test(j.attribution) && /not a security rating/.test(j.note) && noRatingWords(j.note + j.attribution));

r = await tool("get_record_checks", { namespace: "io.github.nope", name: "does-not-exist" }, 1);
check("5  unknown server: plain error, not a crash", r.isError && r.txt === "No record for io.github.nope/does-not-exist. The registry name must be exact.", r.txt);

r = await tool("get_record_checks", { namespace: "a/b", name: ".." }, 0);
check("6  bad characters refused before any request", r.isError === true);

r = await tool("get_record_checks", { namespace: "io.github.github", name: "github-mcp-server" }, 1);
j = JSON.parse(r.txt);
check("7  a second real server", !r.isError && j.server === "io.github.github/github-mcp-server" && j.recordChecks.of >= 1, `met ${j.recordChecks?.met} of ${j.recordChecks?.of}`);

r = await tool("get_registry_summary", {}, 1);
j = JSON.parse(r.txt);
const meta = await direct("/meta");
check("8  summary equals the API", !r.isError && Number.isInteger(j.servers) && j.servers > 1000 && j.servers === meta.json.catalogue.servers && j.registrySnapshot === meta.json.catalogue.registrySnapshot && /^\d{4}-\d{2}-\d{2}$/.test(j.registrySnapshot) && j.topics.length >= 10 && j.topics.every((t) => typeof t.topic === "string" && Number.isInteger(t.servers)) && j.entriesWithAtLeastOneRecordCheckNotMet?.of > 1000, `servers ${j.servers}, snapshot ${j.registrySnapshot}, ${j.topics.length} topics, ${r.ms} ms, ${r.bytes} bytes`);
const topic = j.topics[0].topic;

r = await tool("list_servers_by_topic", { topic }, 1);
let lj = JSON.parse(r.txt);
check("9  a topic from the summary lists exact names", !r.isError && lj.topic === topic && lj.returned === 50 && lj.onThisPage === 500 && lj.hasMore === true && lj.servers.every((s) => /^[^/\s]+\/[^/\s]+$/.test(s)), `topic ${topic}: returned ${lj.returned} of ${lj.onThisPage} on this page`);

r = await tool("list_servers_by_topic", { page: 1, limit: 5 }, 1);
lj = JSON.parse(r.txt);
check("10 page 1 of all servers, limit 5", !r.isError && lj.topic === null && lj.returned === 5 && lj.servers.length === 5, `${r.ms} ms`);

r = await tool("list_servers_by_topic", { topic: "no-such-topic" }, 1);
check("11 unknown topic: API message plus pointer to get_registry_summary", r.isError && /get_registry_summary/.test(r.txt), r.txt);

r = await tool("get_recent_registry_changes", { days: 3 }, 1);
j = JSON.parse(r.txt);
const ch = await direct("/changes");
const apiDates = ch.json.registry.map((x) => x.date).sort().reverse().slice(0, 3);
check("12 changes: latest 3 days, newest first, equal to the API", !r.isError && j.registry.length === 3 && j.registry.every((x, i) => x.date === apiDates[i]) && j.registry.every((x) => typeof x.totals.servers === "number" && typeof x.counts.new === "number"), j.registry.map((x) => `${x.date} +${x.counts.new}`).join(", "));
check("13 changes: no free text (only date, previousSnapshot, totals, counts)", j.registry.every((x) => Object.keys(x).join() === "date,previousSnapshot,totals,counts"));

check("14 the server wrote nothing to stderr", stderr === "", JSON.stringify(stderr));
console.log(`\n${okCount} ok, ${failCount} failed; live requests this run: about ${requests}`);
await client.close();
process.exit(failCount ? 1 : 0);
