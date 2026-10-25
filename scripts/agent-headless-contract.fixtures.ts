// Test fixtures for the headless agent-tool contract (plan Task 16): event
// streams in the shapes recorded on 2026-10-25 from the pinned Claude
// 2.1.280, Codex 0.156.1, and Pi 0.87.1 run offline against a loopback fake
// model server (long fields trimmed), and a builder for the contract script's
// report. Used by `agent-headless-contract.test.ts` and
// `update-agent-tools.test.ts`; nothing here runs an agent.

import { HEADLESS_CONTRACT_AGENTS, HEADLESS_CONTRACT_REPLY, type HeadlessContractAgent } from "./agent-headless-contract.ts";

function jsonLines(events: readonly unknown[]): string {
  return events.map((event) => `${JSON.stringify(event)}\n`).join("");
}

const SESSION = "3f1c2b9e-8a4d-4c1e-9f2a-0b6d7e8f9a10";

const PI_USAGE = { input: 1, output: 1, cacheRead: 0, cacheWrite: 0, totalTokens: 2, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } };

function piAssistant(fields: Readonly<Record<string, unknown>>): Record<string, unknown> {
  return {
    role: "assistant",
    content: [{ type: "text", text: HEADLESS_CONTRACT_REPLY }],
    api: "anthropic-messages",
    provider: "probe",
    model: "probe-model",
    usage: PI_USAGE,
    stopReason: "stop",
    timestamp: 1792943025928,
    ...fields,
  };
}

function piStream(assistant: Record<string, unknown>): string {
  const user = { role: "user", content: [{ type: "text", text: "Reply with one word." }], timestamp: 1792943025920 };
  return jsonLines([
    { type: "session", version: 3, id: SESSION, timestamp: "2026-10-25T15:43:45.920Z", cwd: "/tmp/work" },
    { type: "agent_start" },
    { type: "turn_start" },
    { type: "message_end", message: user },
    { type: "message_end", message: assistant },
    { type: "turn_end", message: assistant, toolResults: [] },
    { type: "agent_end", messages: [user, assistant], willRetry: false },
    { type: "agent_settled" },
  ]);
}

const PROBE_ERROR = "{\"type\":\"error\",\"error\":{\"type\":\"invalid_request_error\",\"message\":\"runfree contract probe\"}}";

/** Recorded-shape stdout and exit status per agent, for a served reply and for a 400. */
export const RECORDED_HEADLESS_STREAMS: Readonly<Record<HeadlessContractAgent, Readonly<{
  ok: Readonly<{ status: number; stdout: string }>;
  fail: Readonly<{ status: number; stdout: string }>;
}>>> = {
  claude: {
    ok: {
      status: 0,
      stdout: jsonLines([
        { type: "system", subtype: "init", session_id: SESSION },
        { type: "assistant", message: { role: "assistant", content: [{ type: "text", text: HEADLESS_CONTRACT_REPLY }] }, session_id: SESSION },
        { stop_reason: "end_turn", session_id: SESSION, is_error: false, num_turns: 1, subtype: "success", result: HEADLESS_CONTRACT_REPLY, type: "result" },
      ]),
    },
    fail: {
      status: 1,
      stdout: jsonLines([
        { type: "system", subtype: "init", session_id: SESSION },
        { is_error: true, subtype: "success", api_error_status: 400, result: "API Error: 400 runfree contract probe", type: "result" },
      ]),
    },
  },
  codex: {
    ok: {
      status: 0,
      stdout: jsonLines([
        { type: "thread.started", thread_id: "01a173ba-8959-7542-bbcc-85d56970fbb1" },
        { type: "turn.started" },
        { type: "item.completed", item: { id: "item_0", type: "agent_message", text: HEADLESS_CONTRACT_REPLY } },
        { type: "turn.completed", usage: { input_tokens: 1, cached_input_tokens: 0, output_tokens: 1, reasoning_output_tokens: 0 } },
      ]),
    },
    fail: {
      status: 1,
      stdout: jsonLines([
        { type: "thread.started", thread_id: "01a173ba-540e-78f0-828e-1bd1197e2b0a" },
        { type: "turn.started" },
        { type: "error", message: PROBE_ERROR },
        { type: "turn.failed", error: { message: PROBE_ERROR } },
      ]),
    },
  },
  pi: {
    ok: { status: 0, stdout: piStream(piAssistant({})) },
    // Pi JSON mode exits 0 after a failed request.
    fail: {
      status: 0,
      stdout: piStream(piAssistant({ content: [], stopReason: "error", errorMessage: "400 runfree contract probe" })),
    },
  },
};

export type HeadlessReportCase = Readonly<{ status: number; promptSeen?: boolean; stdout: string }>;

/** The contract script's report text for the given cases (default: the recorded streams). */
export function headlessContractReport(
  overrides: Readonly<Partial<Record<string, HeadlessReportCase | null>>> = {},
): string {
  const lines: string[] = [];
  for (const agent of HEADLESS_CONTRACT_AGENTS) {
    for (const kind of ["ok", "fail"] as const) {
      const name = `${agent}-${kind}`;
      const override = overrides[name];
      if (override === null) continue;
      const value = override ?? RECORDED_HEADLESS_STREAMS[agent][kind];
      const seen = override?.promptSeen ?? true;
      lines.push(`case=${name} status=${value.status} prompt=${seen ? "seen" : "unseen"}`, `begin=${name}`);
      // `base64` wraps at 76 columns; the parser must join the lines.
      const encoded = Buffer.from(value.stdout).toString("base64");
      for (let offset = 0; offset < encoded.length; offset += 76) lines.push(encoded.slice(offset, offset + 76));
      lines.push(`end=${name}`);
    }
  }
  return `${lines.join("\n")}\n`;
}
