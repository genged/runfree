import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, test, vi } from "vitest";

import {
  AGENT_SESSION_ID_CONTRACT_SCRIPT,
  CONTRACT_NODE_IMAGE,
  assertAgentSessionIdContract,
  dockerServerCpuArch,
  imageContractRunner,
  lockedToolsContractRunner,
  mapDockerServerArchToNpmCpu,
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

  test("gives the image's claude launcher an MCP config it creates itself", () => {
    // The image's `claude` is the Runfree launcher, which always passes
    // `--mcp-config "${RUNFREE_CLAUDE_MCP_CONFIG:-/runfree/mcp/claude.json}"`.
    // A bare `docker run` of the image has no /runfree mount, so real claude
    // exited "MCP config file not found" before writing the transcript
    // (live failure, 2026-10-07). These stubs keep that one behavior.
    const binDir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-contract-bin-"));
    try {
      fs.writeFileSync(path.join(binDir, "claude"), [
        "#!/bin/sh",
        // The default stands in for /runfree/mcp/claude.json, which a bare
        // image lacks; this sandbox may itself be a session that has it.
        'config="${RUNFREE_CLAUDE_MCP_CONFIG:-/nonexistent/runfree/mcp/claude.json}"',
        '[ -f "$config" ] || { echo "MCP config file not found: $config" >&2; exit 1; }',
        'for a in "$@"; do [ "$a" = "--resume" ] && { echo "--session-id can only be used with --continue or --resume" >&2; exit 1; }; done',
        'id=""; prev=""; for a in "$@"; do [ "$prev" = "--session-id" ] && id="$a"; prev="$a"; done',
        'mkdir -p "$CLAUDE_CONFIG_DIR/projects/work" && : > "$CLAUDE_CONFIG_DIR/projects/work/$id.jsonl"',
        "sleep 30",
      ].join("\n"), { mode: 0o755 });
      fs.writeFileSync(path.join(binDir, "pi"), [
        "#!/bin/sh",
        'for a in "$@"; do [ "$a" = "--resume" ] && { echo "--session-id cannot be combined with --resume" >&2; exit 1; }; done',
        'id=""; prev=""; for a in "$@"; do [ "$prev" = "--session-id" ] && id="$a"; prev="$a"; done',
        'echo "Warning: No project session found with id \'$id\'; creating a new session with that id." >&2',
        "exit 1",
      ].join("\n"), { mode: 0o755 });
      const result = childProcess.spawnSync(
        "sh",
        ["-c", AGENT_SESSION_ID_CONTRACT_SCRIPT, "sh", "11111111-2222-4333-8444-555555555555"],
        { encoding: "utf8", env: { PATH: `${binDir}:${process.env.PATH ?? ""}` }, timeout: 30_000 },
      );
      expect(result.stdout, result.stderr).toBe(OK_RESULT.stdout);
    } finally {
      fs.rmSync(binDir, { recursive: true, force: true });
    }
  }, 40_000);
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

  // Review finding 2: lockedToolsContractRunner's `npm rebuild` now sends its
  // own output to stderr (`1>&2`) instead of `/dev/null`, specifically so a
  // rebuild failure (`exit 3`) is not a cause-less error. This proves the
  // consumer side of that fix: stderr text reaches the thrown error.
  test("a rebuild failure (exit 3) with its output on stderr carries that output in the thrown error", () => {
    const run: ContractRunner = () => ({
      status: 3,
      stdout: "",
      stderr: "npm error could not determine executable to run for claude-code-linux-arm64\n",
    });
    expect(() => assertAgentSessionIdContract(run)).toThrow(
      /npm error could not determine executable to run for claude-code-linux-arm64/,
    );
  });
});

describe("mapDockerServerArchToNpmCpu", () => {
  test.each([
    ["x86_64", "x64"],
    ["amd64", "x64"],
    ["aarch64", "arm64"],
    ["arm64", "arm64"],
  ] as const)("maps docker's %s to npm's --cpu=%s", (serverArch, npmCpu) => {
    expect(mapDockerServerArchToNpmCpu(serverArch)).toBe(npmCpu);
  });

  test("refuses an architecture it does not recognize", () => {
    expect(() => mapDockerServerArchToNpmCpu("riscv64")).toThrow(/unsupported Docker server architecture/);
  });
});

describe("dockerServerCpuArch", () => {
  test("resolves the mapped --cpu value from `docker version`", () => {
    const spy = vi.spyOn(childProcess, "spawnSync").mockReturnValue({
      status: 0,
      stdout: "aarch64\n",
      stderr: "",
      pid: 1,
      output: [],
      signal: null,
    });

    expect(dockerServerCpuArch()).toBe("arm64");
    const [command, args] = spy.mock.calls[0] as [string, string[]];
    expect(command).toBe("docker");
    expect(args).toEqual(["version", "--format", "{{.Server.Arch}}"]);
  });

  test("a failing `docker version` (daemon unreachable, etc.) is treated like no usable Docker", () => {
    vi.spyOn(childProcess, "spawnSync").mockReturnValue({
      status: 1,
      stdout: "",
      stderr: "error during connect: ...\n",
      pid: 1,
      output: [],
      signal: null,
    });

    expect(() => dockerServerCpuArch()).toThrow(/could not determine the Docker server architecture/);
  });

  test("a missing Docker CLI throws the same no-Docker message every other call here throws", () => {
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

    expect(() => dockerServerCpuArch()).toThrow(
      /the --session-id contract needs Docker; run make test-runtime-core on a Docker host, or pass --no-contract/,
    );
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

  // Review finding 2: a rebuild failure must not be silently discarded.
  test("a rebuild failure's output goes to stderr, not /dev/null", () => {
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
    const combined = args[args.indexOf("-c") + 1] ?? "";
    expect(combined).toContain("npm rebuild --prefix /opt/t --omit=dev 1>&2 || exit 3");
    expect(combined).not.toContain("/dev/null");
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
