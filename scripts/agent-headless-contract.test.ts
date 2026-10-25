import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { describe, expect, test } from "vitest";

import {
  CLAUDE_STREAM_JSON_RESULT_EVENT,
  CODEX_EXEC_JSON_EVENTS,
  PI_JSON_AGENT_END_EVENT,
} from "../packages/cli/src/runtime/headless-agent-output.ts";
import {
  agentHeadlessContractScript,
  assertAgentHeadlessContract,
  checkHeadlessContractCase,
  HEADLESS_CONTRACT_AGENTS,
  HEADLESS_CONTRACT_PORT,
  HEADLESS_CONTRACT_REPLY,
  headlessContractArgv,
  parseHeadlessContractReport,
} from "./agent-headless-contract.ts";
import { headlessContractReport, RECORDED_HEADLESS_STREAMS } from "./agent-headless-contract.fixtures.ts";
import type { ContractRunner } from "./agent-session-id-contract.ts";

// Headless-run spec §5 "Contract", plan Task 16. The Docker-backed run is a
// live gate (`make test-runtime-core`, `pnpm run update:agent-tools`); this
// file proves the script text, the report parse, and the host-side
// classification of recorded output, with no Docker.

function report(name: string, value: { status: number; promptSeen?: boolean; stdout: string }) {
  return { status: value.status, promptSeen: value.promptSeen ?? true, stdout: Buffer.from(value.stdout) };
}

describe("agentHeadlessContractScript", () => {
  const script = agentHeadlessContractScript();

  test("is syntactically valid POSIX sh", () => {
    const result = childProcess.spawnSync("sh", ["-n", "-c", script, "sh", "placeholder-uuid"], { encoding: "utf8" });
    expect(result.status, `${result.stdout}${result.stderr}`).toBe(0);
  });

  test("every env -i call goes through the script's own run() wrapper (review F6)", () => {
    expect(script.match(/env -i/g)).toHaveLength(1);
  });

  test("the embedded fake server needs no shell or template escapes", () => {
    const server = script.slice(script.indexOf("<<'RUNFREE_FAKE_MODEL'"), script.lastIndexOf("RUNFREE_FAKE_MODEL"));
    expect(server).not.toMatch(/[\\`$]/);
    expect(server).toContain(`listen(${HEADLESS_CONTRACT_PORT}, "127.0.0.1"`);
  });

  test("probes each agent with the exact argv Runfree mints, and the prompt only on stdin", () => {
    const UUID = "\u0000uuid\u0000";
    expect(headlessContractArgv("claude")).toEqual([
      "claude", "--dangerously-skip-permissions", "--add-dir", "/runfree/inbox", "--session-id", UUID,
      "-p", "--output-format", "stream-json", "--verbose",
    ]);
    // Codex: the probe's top-level `-c` routing flags, then Runfree's own argv.
    const codex = headlessContractArgv("codex");
    expect(codex.slice(0, 1)).toEqual(["codex"]);
    expect(codex.slice(5)).toEqual([
      "-c", "check_for_update_on_startup=false", "--dangerously-bypass-approvals-and-sandbox", "exec", "--json", "-",
    ]);
    expect(codex.slice(1, 5).filter((_, index) => index % 2 === 0)).toEqual(["-c", "-c"]);
    expect(headlessContractArgv("pi")).toEqual(["pi", "--session-id", UUID, "--mode", "json", "-p"]);
    for (const agent of HEADLESS_CONTRACT_AGENTS) {
      for (const kind of ["ok", "fail"]) expect(script).toContain(`probe ${agent}-${kind} `);
    }
    expect(script).toContain("<\"$T/prompt\"");
    expect(script).toContain("'--session-id' \"$U\"");
  });
});

describe("parseHeadlessContractReport", () => {
  test("reads every case, joining base64 lines", () => {
    const reports = parseHeadlessContractReport(headlessContractReport());
    expect([...reports.keys()]).toEqual(["claude-ok", "claude-fail", "codex-ok", "codex-fail", "pi-ok", "pi-fail"]);
    expect(reports.get("pi-fail")).toMatchObject({ status: 0, promptSeen: true });
    expect(reports.get("codex-ok")?.stdout.toString()).toBe(RECORDED_HEADLESS_STREAMS.codex.ok.stdout);
  });

  test("drops a case without its end marker, with bad base64, or with a malformed case line", () => {
    const text = [
      "case=claude-ok status=0 prompt=seen", "begin=claude-ok", "e30=",
      "case=codex-ok status=0 prompt=seen", "begin=codex-ok", "not base64!", "end=codex-ok",
      "case=pi-ok status=zero prompt=seen", "begin=pi-ok", "e30=", "end=pi-ok",
      "case=pi-fail status=0 prompt=seen", "e30=", "end=pi-fail",
    ].join("\n");
    expect(parseHeadlessContractReport(text).size).toBe(0);
  });
});

describe("checkHeadlessContractCase", () => {
  test.each(HEADLESS_CONTRACT_AGENTS)("the recorded %s streams hold", (agent) => {
    expect(checkHeadlessContractCase(agent, "ok", report("ok", RECORDED_HEADLESS_STREAMS[agent].ok))).toEqual([]);
    expect(checkHeadlessContractCase(agent, "fail", report("fail", RECORDED_HEADLESS_STREAMS[agent].fail))).toEqual([]);
  });

  test("a Pi failed request exits 0 and still holds only because the parser reads it as not success", () => {
    expect(RECORDED_HEADLESS_STREAMS.pi.fail.status).toBe(0);
    const asSuccess = RECORDED_HEADLESS_STREAMS.pi.ok.stdout;
    expect(checkHeadlessContractCase("pi", "fail", report("fail", { status: 0, stdout: asSuccess })))
      .toEqual(["pi-fail: a failed model request gave outcome success (exit 0)"]);
  });

  test("an ok case that did not send the stdin prompt fails", () => {
    expect(checkHeadlessContractCase("codex", "ok", report("ok", { ...RECORDED_HEADLESS_STREAMS.codex.ok, promptSeen: false })))
      .toEqual(["codex-ok: the model request did not carry the stdin prompt"]);
  });

  test("an ok case with a nonzero exit or another final message fails", () => {
    expect(checkHeadlessContractCase("claude", "ok", report("ok", { ...RECORDED_HEADLESS_STREAMS.claude.ok, status: 2 })))
      .toEqual(expect.arrayContaining(["claude-ok: exit 2, expected 0", "claude-ok: outcome failed, expected success"]));
    const other = RECORDED_HEADLESS_STREAMS.codex.ok.stdout.replace(HEADLESS_CONTRACT_REPLY, "something else");
    expect(checkHeadlessContractCase("codex", "ok", report("ok", { status: 0, stdout: other })))
      .toEqual([`codex-ok: final message "something else", expected "${HEADLESS_CONTRACT_REPLY}"`]);
  });

  // A tool update that renamed an event field the parser reads must fail the
  // contract (it would make every real run `unverified`).
  const UNVERIFIED = /outcome unverified, expected success/;
  test.each([
    ["claude", `"${CLAUDE_STREAM_JSON_RESULT_EVENT.isErrorField}":false`, "\"isError\":false", UNVERIFIED],
    ["codex", `"${CODEX_EXEC_JSON_EVENTS.turnCompletedType}"`, "\"turn.done\"", UNVERIFIED],
    // Codex success does not need an agent message; the reply check catches it.
    ["codex", `"${CODEX_EXEC_JSON_EVENTS.agentMessageItemType}"`, "\"assistant_message\"", /codex-ok: final message undefined/],
    ["pi", `"${PI_JSON_AGENT_END_EVENT.willRetryField}":false`, "\"retrying\":false", UNVERIFIED],
    ["pi", `"${PI_JSON_AGENT_END_EVENT.stopReasonField}":"stop"`, "\"stopReason\":\"end_turn\"", UNVERIFIED],
  ] as const)("%s output with %s renamed fails the ok case", (agent, from, to, problem) => {
    const stdout = RECORDED_HEADLESS_STREAMS[agent].ok.stdout.replaceAll(from, to);
    expect(stdout).not.toBe(RECORDED_HEADLESS_STREAMS[agent].ok.stdout);
    expect(checkHeadlessContractCase(agent, "ok", report("ok", { status: 0, stdout })).join("; ")).toMatch(problem);
  });

  test("a missing case fails", () => {
    expect(checkHeadlessContractCase("pi", "ok", undefined)).toEqual(["pi-ok: no report"]);
  });
});

describe("assertAgentHeadlessContract", () => {
  test("passes on the recorded report and hands the runner a uuid", () => {
    let seen = "";
    const run: ContractRunner = (_script, uuid) => {
      seen = uuid;
      return { status: 0, stdout: headlessContractReport(), stderr: "" };
    };
    expect(() => assertAgentHeadlessContract(run)).not.toThrow();
    expect(seen).toMatch(/^[0-9a-f-]{36}$/);
  });

  test("names every failing case", () => {
    const run: ContractRunner = () => ({
      status: 0,
      stdout: headlessContractReport({ "codex-fail": null, "pi-fail": { status: 0, stdout: RECORDED_HEADLESS_STREAMS.pi.ok.stdout } }),
      stderr: "",
    });
    expect(() => assertAgentHeadlessContract(run)).toThrow(/codex-fail: no report; pi-fail: a failed model request gave outcome success/);
  });

  test("a nonzero script exit fails even with a good report", () => {
    const run: ContractRunner = () => ({ status: 3, stdout: headlessContractReport(), stderr: "npm rebuild failed" });
    expect(() => assertAgentHeadlessContract(run)).toThrow(/contract script exit 3[\s\S]*npm rebuild failed/);
  });
});

// The script run end to end on the host with stub agents in place of the
// pinned tools: each stub reads its stdin, posts it to the script's fake
// model server, and prints a recorded stream for the answer it got. This
// proves the script's plumbing (server start, stdin prompt, capture, base64
// report), not the tools; the tools are proven by the Docker gate.
const hasCoreutilsTimeout = childProcess.spawnSync("sh", ["-c", "command -v timeout"]).status === 0;

describe.skipIf(!hasCoreutilsTimeout)("agentHeadlessContractScript with stub agents", () => {
  function stubBin(behavior: "faithful" | "ignore-stdin" | "always-success"): string {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-headless-contract-bin-"));
    const streams = JSON.stringify(RECORDED_HEADLESS_STREAMS);
    for (const agent of HEADLESS_CONTRACT_AGENTS) {
      fs.writeFileSync(path.join(dir, agent), [
        "#!/usr/bin/env node",
        `const streams = ${streams}[${JSON.stringify(agent)}];`,
        `const behavior = ${JSON.stringify(behavior)};`,
        "const chunks = [];",
        "process.stdin.on('data', (chunk) => chunks.push(chunk));",
        "process.stdin.on('end', () => {",
        "  const body = behavior === 'ignore-stdin' ? 'no prompt' : Buffer.concat(chunks).toString();",
        `  const request = require('http').request({ host: '127.0.0.1', port: ${HEADLESS_CONTRACT_PORT}, method: 'POST', path: '/v1/x' }, (response) => {`,
        "    response.resume();",
        "    const result = response.statusCode === 200 || behavior === 'always-success' ? streams.ok : streams.fail;",
        "    process.stdout.write(result.stdout);",
        "    process.exitCode = result.status;",
        "  });",
        "  request.end(body);",
        "});",
      ].join("\n"), { mode: 0o755 });
    }
    return dir;
  }

  function runScript(binDir: string): ContractRunner {
    return (script, uuid) => {
      const result = childProcess.spawnSync("sh", ["-c", script, "sh", uuid], {
        encoding: "utf8",
        env: { PATH: `${binDir}:${process.env.PATH ?? ""}` },
        timeout: 60_000,
      });
      return { status: result.status ?? 1, stdout: result.stdout, stderr: result.stderr };
    };
  }

  test("faithful stubs pass the contract", () => {
    const binDir = stubBin("faithful");
    try {
      expect(() => assertAgentHeadlessContract(runScript(binDir))).not.toThrow();
    } finally {
      fs.rmSync(binDir, { recursive: true, force: true });
    }
  }, 60_000);

  test("stubs that ignore the stdin prompt fail every case", () => {
    const binDir = stubBin("ignore-stdin");
    try {
      expect(() => assertAgentHeadlessContract(runScript(binDir))).toThrow(/claude-ok: the model request did not carry the stdin prompt/);
    } finally {
      fs.rmSync(binDir, { recursive: true, force: true });
    }
  }, 60_000);

  test("stubs that report success for a failed request fail the fail cases", () => {
    const binDir = stubBin("always-success");
    try {
      expect(() => assertAgentHeadlessContract(runScript(binDir)))
        .toThrow(/claude-fail: a failed model request gave outcome success[\s\S]*pi-fail: a failed model request gave outcome success/);
    } finally {
      fs.rmSync(binDir, { recursive: true, force: true });
    }
  }, 60_000);
});
