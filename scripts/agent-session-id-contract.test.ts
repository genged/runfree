import childProcess from "node:child_process";

import { afterEach, describe, expect, test, vi } from "vitest";

import {
  AGENT_SESSION_ID_CONTRACT_SCRIPT,
  CONTRACT_NODE_IMAGE,
  assertAgentSessionIdContract,
  imageContractRunner,
  lockedToolsContractRunner,
  type ContractRunner,
} from "./agent-session-id-contract.ts";

const OK_RESULT = {
  status: 0,
  stdout: "claude-transcript=ok\nclaude-resume-refused=ok\npi-session-id=ok\npi-resume-refused=ok\n",
  stderr: "",
};

afterEach(() => {
  vi.restoreAllMocks();
});

describe("AGENT_SESSION_ID_CONTRACT_SCRIPT", () => {
  test("is syntactically valid POSIX sh", () => {
    const result = childProcess.spawnSync("sh", ["-n", "-c", AGENT_SESSION_ID_CONTRACT_SCRIPT, "sh", "placeholder-uuid"], {
      encoding: "utf8",
    });
    expect(result.status, `${result.stdout}${result.stderr}`).toBe(0);
  });

  test("every env -i call goes through the script's own run() wrapper", () => {
    // Review F6: a bare `env -i` call outside `run` could regress the one
    // quoted prefix every claude/pi invocation shares.
    expect(AGENT_SESSION_ID_CONTRACT_SCRIPT.match(/env -i/g)).toHaveLength(1);
  });
});

describe("CONTRACT_NODE_IMAGE", () => {
  test("is node:22 pinned by digest, never an unpinned tag", () => {
    expect(CONTRACT_NODE_IMAGE).toMatch(/^node:22[^@]*@sha256:[0-9a-f]{64}$/);
  });
});

describe("assertAgentSessionIdContract", () => {
  test("passes when all four contract lines report ok", () => {
    const run: ContractRunner = () => OK_RESULT;
    expect(() => assertAgentSessionIdContract(run)).not.toThrow();
  });

  test("passes the minted uuid through to the runner", () => {
    let seenUuid = "";
    const run: ContractRunner = (_script, uuid) => {
      seenUuid = uuid;
      return OK_RESULT;
    };
    assertAgentSessionIdContract(run);
    expect(seenUuid).toMatch(/^[0-9a-f-]{36}$/);
  });

  test("throws and names the failing line when one case reports missing", () => {
    const run: ContractRunner = () => ({
      status: 0,
      stdout: "claude-transcript=missing\nclaude-resume-refused=ok\npi-session-id=ok\npi-resume-refused=ok\n",
      stderr: "",
    });
    expect(() => assertAgentSessionIdContract(run)).toThrow(/claude-transcript=missing/);
  });

  test("throws on a nonzero exit even with no recognizable output", () => {
    const run: ContractRunner = () => ({ status: 1, stdout: "", stderr: "" });
    expect(() => assertAgentSessionIdContract(run)).toThrow();
  });

  test("throws with the full output cut to 4000 characters", () => {
    const run: ContractRunner = () => ({ status: 1, stdout: "x".repeat(5000), stderr: "" });
    try {
      assertAgentSessionIdContract(run);
      throw new Error("expected assertAgentSessionIdContract to throw");
    } catch (error) {
      expect(error).toBeInstanceOf(Error);
      expect((error as Error).message.length).toBeLessThanOrEqual(4000 + 200);
    }
  });
});

describe("imageContractRunner", () => {
  test("spawns docker with the full capability floor and no mount", () => {
    const spy = vi.spyOn(childProcess, "spawnSync").mockReturnValue({
      status: 0,
      stdout: "ok",
      stderr: "",
      pid: 1,
      output: [],
      signal: null,
    });

    imageContractRunner("runfree-agent:test")("script-body", "uuid-1");

    expect(spy).toHaveBeenCalledTimes(1);
    const [command, args, options] = spy.mock.calls[0] as [string, string[], childProcess.SpawnSyncOptions];
    expect(command).toBe("docker");
    expect(args).toEqual(
      expect.arrayContaining([
        "--network", "none",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--user", "1000:1000",
      ]),
    );
    expect(args).toContain("runfree-agent:test");
    expect(args.filter((arg) => arg === "-v")).toHaveLength(0);
    expect(args).toEqual(expect.arrayContaining(["-c", "script-body", "sh", "uuid-1"]));

    const env = options.env as Record<string, string | undefined>;
    for (const forbidden of ["HOME", "HTTP_PROXY", "ANTHROPIC_API_KEY", "NPM_TOKEN"]) {
      expect(env).not.toHaveProperty(forbidden);
    }
  });
});

describe("lockedToolsContractRunner", () => {
  test("mounts exactly the tools dir and pins CONTRACT_NODE_IMAGE", () => {
    const spy = vi.spyOn(childProcess, "spawnSync").mockReturnValue({
      status: 0,
      stdout: "ok",
      stderr: "",
      pid: 1,
      output: [],
      signal: null,
    });

    lockedToolsContractRunner("/tmp/agent-tools-xyz")("script-body", "uuid-2");

    expect(spy).toHaveBeenCalledTimes(1);
    const [command, args, options] = spy.mock.calls[0] as [string, string[], childProcess.SpawnSyncOptions];
    expect(command).toBe("docker");
    expect(args).toEqual(
      expect.arrayContaining([
        "--network", "none",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--user", "1000:1000",
      ]),
    );
    const volumeFlags = args.flatMap((arg, index) => (arg === "-v" ? [args[index + 1]] : []));
    expect(volumeFlags).toEqual(["/tmp/agent-tools-xyz:/opt/t"]);
    expect(args).toContain(CONTRACT_NODE_IMAGE);
    expect(args).not.toContain("runfree-agent:test");

    const env = options.env as Record<string, string | undefined>;
    for (const forbidden of ["HOME", "HTTP_PROXY", "ANTHROPIC_API_KEY", "NPM_TOKEN"]) {
      expect(env).not.toHaveProperty(forbidden);
    }
  });

  test("the probe script is only run after npm rebuild succeeds", () => {
    const spy = vi.spyOn(childProcess, "spawnSync").mockReturnValue({
      status: 0,
      stdout: "ok",
      stderr: "",
      pid: 1,
      output: [],
      signal: null,
    });

    lockedToolsContractRunner("/tmp/agent-tools-xyz")("script-body", "uuid-2");

    const args = spy.mock.calls[0]?.[1] as string[];
    const cIndex = args.indexOf("-c");
    const combined = args[cIndex + 1] ?? "";
    expect(combined).toContain("npm rebuild --prefix /opt/t --omit=dev");
    expect(combined).toContain("script-body");
    expect(combined.indexOf("npm rebuild")).toBeLessThan(combined.indexOf("script-body"));
  });
});

describe("Docker unavailable", () => {
  test("an ENOENT spawn failure throws the no-Docker message, for both runners", () => {
    const enoent = Object.assign(new Error("spawn docker ENOENT"), { code: "ENOENT" });
    vi.spyOn(childProcess, "spawnSync").mockReturnValue({
      status: null,
      stdout: "",
      stderr: "",
      pid: 0,
      output: [],
      signal: null,
      error: enoent,
    });

    expect(() => imageContractRunner("runfree-agent:test")("script-body", "uuid-3")).toThrow(
      /the --session-id contract needs Docker; run make test-runtime-core on a Docker host, or pass --no-contract/,
    );
    expect(() => lockedToolsContractRunner("/tmp/agent-tools-xyz")("script-body", "uuid-3")).toThrow(
      /the --session-id contract needs Docker; run make test-runtime-core on a Docker host, or pass --no-contract/,
    );
  });
});
