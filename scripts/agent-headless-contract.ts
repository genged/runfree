// The pinned-tool headless contract (headless-run spec §3.1 "Hypothesis" and
// §5 "Contract", plan Task 16). `runfree run` assumes, for each pinned agent
// tool, that its headless argv is accepted, that it reads the prompt from a
// stdin file and ends at EOF, that it prints the event stream the host parser
// reads (`packages/cli/src/runtime/headless-agent-output.ts`), and that a
// failed model request never reads as success. A tool update that changed
// any of this would otherwise show only as runs that end `unverified`, or,
// worse, as a false success.
//
// Each probe runs the exact argv Runfree mints (from the built-in agent
// descriptors), with the prompt file as stdin, against a loopback fake model
// server inside the same throwaway container as the --session-id contract
// (`agent-session-id-contract.ts`, security review F1/F6): `--network none`,
// no host environment, placeholder credentials. Codex gets extra top-level
// `-c` flags that point it at the fake server (Codex otherwise waits for the
// network without end). The captured stdout comes back base64-encoded and the
// host classifies it with the real parser and outcome rule; parsing hostile
// output on the host is the same bounded code a real run uses.

import { randomUUID } from "node:crypto";
import path from "node:path";

import { builtinAgent, type BuiltinAgentDescriptor } from "../packages/cli/src/agents.ts";
import { createHeadlessOutputParser, decideHeadlessOutcome } from "../packages/cli/src/runtime/headless-agent-output.ts";
import type { ContractRunner } from "./agent-session-id-contract.ts";

export const HEADLESS_CONTRACT_AGENTS = ["claude", "codex", "pi"] as const;
export type HeadlessContractAgent = (typeof HEADLESS_CONTRACT_AGENTS)[number];
export type HeadlessContractCase = `${HeadlessContractAgent}-${"ok" | "fail"}`;

/** The reply the fake model server gives; the final message must be exactly this. */
export const HEADLESS_CONTRACT_REPLY = "runfree-headless-contract-ok";
/** Loopback only; the container has no other network. */
export const HEADLESS_CONTRACT_PORT = 47_831;
/** Per-case cap on the captured stdout sent back to the host. */
export const HEADLESS_CONTRACT_OUTPUT_CAP_BYTES = 4 * 1024 * 1024;

const UUID_TOKEN = "\u0000uuid\u0000";

/**
 * Top-level Codex flags that route it to the fake server with no retries.
 * They go before the descriptor's own flags; `-c` is repeatable.
 */
const CODEX_PROBE_ARGS = [
  "-c",
  `model_providers.probe={name="probe",base_url="http://127.0.0.1:${HEADLESS_CONTRACT_PORT}/v1",env_key="OPENAI_API_KEY",wire_api="responses",request_max_retries=0,stream_max_retries=0,supports_websockets=false}`,
  "-c",
  "model_provider=probe",
] as const;

function requireHeadlessDescriptor(agent: HeadlessContractAgent): BuiltinAgentDescriptor & {
  headless: NonNullable<BuiltinAgentDescriptor["headless"]>;
} {
  const descriptor = builtinAgent(agent);
  if (!descriptor?.headless) throw new Error(`built-in agent ${agent} has no headless mode`);
  return descriptor as BuiltinAgentDescriptor & { headless: NonNullable<BuiltinAgentDescriptor["headless"]> };
}

/**
 * The argv each probe runs: the tool by name on PATH (the image's Runfree
 * launchers, or the rebuilt locked tools), the descriptor's direct-launch
 * args, the host-chosen id where the agent takes one, then its headless args:
 * the same order `createBuiltinSessionHeadlessLaunchTarget` mints.
 */
export function headlessContractArgv(agent: HeadlessContractAgent): string[] {
  const descriptor = requireHeadlessDescriptor(agent);
  return [
    path.posix.basename(descriptor.directLaunch.path),
    ...(agent === "codex" ? CODEX_PROBE_ARGS : []),
    ...descriptor.directLaunch.args,
    ...(descriptor.launchConversationIdFlag ? [descriptor.launchConversationIdFlag, UUID_TOKEN] : []),
    ...descriptor.headless.args,
  ];
}

function shellWord(value: string): string {
  if (value === UUID_TOKEN) return '"$U"';
  return `'${value.replaceAll("'", "'\\''")}'`;
}

// The fake model server, as plain ES5-style JavaScript so it embeds in the
// script without escapes: no backslashes, backticks, or dollar signs.
// argv: mode (anthropic | openai | fail), ready file, seen file, marker.
const FAKE_MODEL_SERVER = `
var http = require("http");
var fs = require("fs");
var mode = process.argv[2];
var readyFile = process.argv[3];
var seenFile = process.argv[4];
var marker = process.argv[5];
var NL = String.fromCharCode(10);
var REPLY = "${HEADLESS_CONTRACT_REPLY}";
function sse(res, events) {
  res.writeHead(200, { "content-type": "text/event-stream" });
  events.forEach(function (event) {
    res.write("event: " + event.type + NL + "data: " + JSON.stringify(event) + NL + NL);
  });
  res.end();
}
function anthropic(res, model) {
  sse(res, [
    { type: "message_start", message: { id: "msg_probe", type: "message", role: "assistant", model: model, content: [], stop_reason: null, stop_sequence: null, usage: { input_tokens: 1, output_tokens: 0 } } },
    { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } },
    { type: "content_block_delta", index: 0, delta: { type: "text_delta", text: REPLY } },
    { type: "content_block_stop", index: 0 },
    { type: "message_delta", delta: { stop_reason: "end_turn", stop_sequence: null }, usage: { output_tokens: 1 } },
    { type: "message_stop" }
  ]);
}
function openai(res) {
  var item = { type: "message", id: "msg_probe", role: "assistant", status: "completed", content: [{ type: "output_text", text: REPLY, annotations: [] }] };
  sse(res, [
    { type: "response.created", response: { id: "resp_probe" } },
    { type: "response.output_item.done", output_index: 0, item: item },
    { type: "response.completed", response: { id: "resp_probe", output: [item], usage: { input_tokens: 1, output_tokens: 1, total_tokens: 2, input_tokens_details: { cached_tokens: 0 }, output_tokens_details: { reasoning_tokens: 0 } } } }
  ]);
}
http.createServer(function (req, res) {
  var chunks = [];
  req.on("data", function (chunk) { chunks.push(chunk); });
  req.on("end", function () {
    var body = Buffer.concat(chunks).toString("utf8");
    if (body.indexOf(marker) !== -1) fs.writeFileSync(seenFile, "seen");
    if (req.method !== "POST") { res.writeHead(200, { "content-type": "application/json" }); res.end("{}"); return; }
    if (mode === "fail") {
      res.writeHead(400, { "content-type": "application/json" });
      res.end(JSON.stringify({ type: "error", error: { type: "invalid_request_error", message: "runfree contract probe" } }));
      return;
    }
    var model = "probe-model";
    try { model = JSON.parse(body).model || model; } catch (error) {}
    if (mode === "openai") openai(res); else anthropic(res, model);
  });
}).listen(${HEADLESS_CONTRACT_PORT}, "127.0.0.1", function () { fs.writeFileSync(readyFile, "ready"); });
`;

// Pi reads its provider from its own agent dir; the probe provider speaks the
// Anthropic Messages API at the fake server.
const PI_MODELS_JSON = JSON.stringify({
  providers: {
    probe: {
      baseUrl: `http://127.0.0.1:${HEADLESS_CONTRACT_PORT}`,
      api: "anthropic-messages",
      apiKey: "placeholder",
      models: [{ id: "probe-model" }],
    },
  },
});
const PI_SETTINGS_JSON = JSON.stringify({ defaultProvider: "probe", defaultModel: "probe-model" });

const SERVER_MODE: Readonly<Record<HeadlessContractAgent, "anthropic" | "openai">> = {
  claude: "anthropic",
  codex: "openai",
  pi: "anthropic",
};

/**
 * POSIX sh, run as `sh -c SCRIPT sh <uuid>` like the --session-id contract.
 * For each agent and each server mode (`ok`, `fail`) it starts the fake
 * server, runs the agent's exact headless argv with the prompt file as stdin
 * under `timeout`, and prints one `case=<c> status=<n> prompt=<seen|unseen>`
 * line, then the captured stdout as base64 between `begin=<c>` and `end=<c>`.
 * No `-e`: every case runs and reports.
 *
 * Review F6: `run()` holds the only `env -i`; every agent call shares that
 * scrubbed environment and placeholder credentials.
 */
export function agentHeadlessContractScript(): string {
  const probes = HEADLESS_CONTRACT_AGENTS.flatMap((agent) =>
    (["ok", "fail"] as const).map((kind) => {
      const mode = kind === "ok" ? SERVER_MODE[agent] : "fail";
      return `probe ${agent}-${kind} ${mode} ${headlessContractArgv(agent).map(shellWord).join(" ")}`;
    }));
  return `
set -u
U="$1"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
cat > "$T/fake-model.js" <<'RUNFREE_FAKE_MODEL'
${FAKE_MODEL_SERVER}
RUNFREE_FAKE_MODEL
printf 'Reply with one word. runfree headless contract probe %s\\n' "$U" > "$T/prompt"
printf '{"mcpServers":{}}\\n' > "$T/mcp.json"
run() {
  env -i "PATH=$PATH" "HOME=$D/home" "CLAUDE_CONFIG_DIR=$D/home/.claude" "RUNFREE_CLAUDE_MCP_CONFIG=$T/mcp.json" \\
    ANTHROPIC_API_KEY=placeholder "ANTHROPIC_BASE_URL=http://127.0.0.1:${HEADLESS_CONTRACT_PORT}" DISABLE_AUTOUPDATER=1 \\
    OPENAI_API_KEY=placeholder "CODEX_HOME=$D/codex" \\
    "PI_CODING_AGENT_DIR=$D/pi" PI_SKIP_VERSION_CHECK=1 PI_TELEMETRY=0 "$@"
}
probe() {
  c="$1"; mode="$2"; shift 2
  D="$T/$c"
  mkdir -p "$D/home" "$D/codex" "$D/pi" "$D/work"
  printf '%s\\n' '${PI_MODELS_JSON}' > "$D/pi/models.json"
  printf '%s\\n' '${PI_SETTINGS_JSON}' > "$D/pi/settings.json"
  node "$T/fake-model.js" "$mode" "$D/ready" "$D/seen" "$U" >"$D/server.log" 2>&1 &
  srv=$!
  i=0
  while [ ! -f "$D/ready" ] && [ "$i" -lt 100 ]; do i=$((i + 1)); sleep 0.1; done
  (cd "$D/work" && run timeout 90 "$@" <"$T/prompt" >"$D/stdout" 2>"$D/stderr")
  st=$?
  kill "$srv" 2>/dev/null; wait "$srv" 2>/dev/null
  seen=unseen
  [ -f "$D/seen" ] && seen=seen
  echo "case=$c status=$st prompt=$seen"
  echo "begin=$c"
  head -c ${HEADLESS_CONTRACT_OUTPUT_CAP_BYTES} "$D/stdout" | base64
  echo "end=$c"
  [ "$st" -eq 0 ] || head -c 2000 "$D/stderr" >&2
}
${probes.join("\n")}
exit 0
`;
}

export type HeadlessContractCaseReport = Readonly<{
  status: number;
  promptSeen: boolean;
  stdout: Buffer;
}>;

const CASE_LINE = /^case=([a-z]+-(?:ok|fail)) status=(\d{1,3}) prompt=(seen|unseen)$/;

/** Reads the script's report; a case that is missing or malformed is absent from the map. */
export function parseHeadlessContractReport(stdout: string): Map<string, HeadlessContractCaseReport> {
  const reports = new Map<string, HeadlessContractCaseReport>();
  const lines = stdout.split("\n");
  for (let index = 0; index < lines.length; index += 1) {
    const match = CASE_LINE.exec(lines[index] ?? "");
    if (!match) continue;
    const [, name = "", status = "", seen = ""] = match;
    if (lines[index + 1] !== `begin=${name}`) continue;
    const end = lines.indexOf(`end=${name}`, index + 2);
    if (end === -1) continue;
    const encoded = lines.slice(index + 2, end).join("");
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(encoded)) continue;
    reports.set(name, { status: Number(status), promptSeen: seen === "seen", stdout: Buffer.from(encoded, "base64") });
    index = end;
  }
  return reports;
}

/**
 * The host-side check of one case; returns the problems found (none means it
 * holds). An `ok` case must exit 0, have sent the stdin prompt to the model,
 * and be a success with exactly the fake reply as its final message. A
 * `fail` case must have sent the prompt and must never be a success.
 */
export function checkHeadlessContractCase(
  agent: HeadlessContractAgent,
  kind: "ok" | "fail",
  report: HeadlessContractCaseReport | undefined,
): string[] {
  const name = `${agent}-${kind}`;
  if (!report) return [`${name}: no report`];
  const problems: string[] = [];
  if (!report.promptSeen) problems.push(`${name}: the model request did not carry the stdin prompt`);
  const parser = createHeadlessOutputParser(requireHeadlessDescriptor(agent).headless.outputFormat);
  parser.push(report.stdout);
  parser.endStream();
  const parsed = parser.result();
  const outcome = decideHeadlessOutcome({ agentStatus: report.status, streamsDrained: true, parser: parsed });
  if (kind === "ok") {
    if (report.status !== 0) problems.push(`${name}: exit ${report.status}, expected 0`);
    if (outcome.outcome !== "success") problems.push(`${name}: outcome ${outcome.outcome}, expected success`);
    if (parsed.finalMessage !== HEADLESS_CONTRACT_REPLY) {
      problems.push(`${name}: final message ${JSON.stringify(parsed.finalMessage?.slice(0, 200))}, expected ${JSON.stringify(HEADLESS_CONTRACT_REPLY)}`);
    }
  } else if (outcome.outcome === "success" || outcome.exitCode === 0) {
    problems.push(`${name}: a failed model request gave outcome ${outcome.outcome} (exit ${outcome.exitCode})`);
  }
  return problems;
}

const MAX_REPORTED_OUTPUT = 4000;

/** Mints a uuid, runs the script, and requires every case to hold. */
export function assertAgentHeadlessContract(run: ContractRunner): void {
  const { status, stdout, stderr } = run(agentHeadlessContractScript(), randomUUID());
  const reports = parseHeadlessContractReport(stdout);
  const problems = HEADLESS_CONTRACT_AGENTS.flatMap((agent) =>
    (["ok", "fail"] as const).flatMap((kind) => checkHeadlessContractCase(agent, kind, reports.get(`${agent}-${kind}`))));
  if (status !== 0) problems.push(`contract script exit ${status}`);
  if (problems.length === 0) return;
  throw new Error(`headless contract failed (${problems.join("; ")}):\n${stderr.slice(0, MAX_REPORTED_OUTPUT)}`);
}
