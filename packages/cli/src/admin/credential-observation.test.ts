import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { isTokenName } from "@runfree/runtime-contracts/network-policy";
import type { CaptureResult } from "../runtime/types.ts";
import {
  CREDENTIAL_OBSERVATION_BATCH_HEADER,
  CREDENTIAL_OBSERVATION_SECTION_MAX_BYTES,
  type CredentialObservationDocker,
  type ProxyObservationPaths,
  type ProxyObservationSection,
  credentialObservationBatchScript,
  lockedHeldTokenNames,
  observeCredentialRuntime,
  parseCredentialObservationBatch,
  parseProxyValidationMarker,
  proxyTokenStoreGeneration,
  splitTrailingStartedAt,
} from "./credential-observation.ts";

let tmp: string;
let paths: ProxyObservationPaths;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "credential-observation-"));
  paths = {
    validationMarker: path.join(tmp, "run", "runfree-runtime-validation.json"),
    firewallStatus: path.join(tmp, "status", "firewall.json"),
    requestProxyStatus: path.join(tmp, "status", "request-proxy", "request-proxy.json"),
    secretDir: path.join(tmp, "secrets"),
  };
  for (const file of [paths.validationMarker, paths.firewallStatus, paths.requestProxyStatus]) {
    fs.mkdirSync(path.dirname(file), { recursive: true });
  }
  fs.mkdirSync(paths.secretDir, { recursive: true });
});

afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

const ALL_SECTIONS: readonly ProxyObservationSection[] = ["validation-marker", "firewall-status", "request-proxy-status", "held-token-names"];
const STARTED_AT = "2026-06-18T00:00:00.000000000Z";
const RESTARTED_AT = "2026-06-18T00:00:01.000000000Z";

// The real script, run by the host's POSIX shell against a scratch tree laid
// out like the proxy's: the bytes the parser sees are the bytes a proxy emits.
function runScript(sections: readonly ProxyObservationSection[]): string {
  const result = childProcess.spawnSync("/bin/sh", ["-c", credentialObservationBatchScript(sections, paths)], { encoding: "utf8" });
  expect(result.status, result.stderr).toBe(0);
  return result.stdout;
}

function frame(...sections: string[]): string {
  return `${CREDENTIAL_OBSERVATION_BATCH_HEADER}\n${sections.join("")}end\n`;
}

function present(name: string, text: string): string {
  return `${name} present ${Buffer.byteLength(text)}\n${text}\n`;
}

type DockerCall = Readonly<{ kind: "exec" | "inspect"; args: readonly unknown[] }>;

function fakeDocker(input: Readonly<{
  exec?: (command: readonly string[]) => CaptureResult;
  startedAt?: () => CaptureResult;
}>): { docker: CredentialObservationDocker; calls: DockerCall[] } {
  const calls: DockerCall[] = [];
  const docker = {
    exec: (containerId: string, command: readonly string[], exec?: unknown) => {
      calls.push({ kind: "exec", args: [containerId, command, exec] });
      if (input.exec) return input.exec(command);
      const result = childProcess.spawnSync("/bin/sh", ["-c", String(command.at(-1))], { encoding: "utf8" });
      return { status: result.status ?? 1, stdout: result.stdout, stderr: result.stderr };
    },
    inspect: (refs: readonly string[], query?: unknown) => {
      calls.push({ kind: "inspect", args: [refs, query] });
      return input.startedAt ? input.startedAt() : { status: 0, stdout: `${STARTED_AT}\n`, stderr: "" };
    },
  } as unknown as CredentialObservationDocker;
  return { docker, calls };
}

function writeMarker(value: unknown = { proofVersion: 4, proxyId: "proxy-id" }): string {
  const text = `${JSON.stringify(value)}\n`;
  fs.writeFileSync(paths.validationMarker, text);
  return text;
}

describe("credential observation batch script", () => {
  test("one exec emits every requested section exactly once, with held names and never a token value", () => {
    const marker = writeMarker();
    fs.writeFileSync(paths.firewallStatus, '{"generation":"g1","rulesetVerified":true}\n');
    fs.writeFileSync(paths.requestProxyStatus, '{"generation":"g1"}\n');
    fs.writeFileSync(path.join(paths.secretDir, "github"), "ghp_value_that_must_not_leave");
    fs.writeFileSync(path.join(paths.secretDir, "github.tmp"), "ghp_partial_value");

    const stdout = runScript(ALL_SECTIONS);

    expect(stdout).not.toContain("ghp_value_that_must_not_leave");
    expect(stdout).not.toContain("ghp_partial_value");
    const parsed = parseCredentialObservationBatch(stdout, ALL_SECTIONS);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.sections.get("validation-marker")).toEqual({ state: "present", text: marker });
    expect(parsed.sections.get("held-token-names")).toEqual({ state: "present", text: "github\ngithub.tmp\n" });
  });

  test("an absent file and an unlistable secret directory are reported, not mistaken for empty", () => {
    fs.rmSync(paths.secretDir, { recursive: true });
    const parsed = parseCredentialObservationBatch(runScript(["validation-marker", "held-token-names"]), ["validation-marker", "held-token-names"]);
    expect(parsed).toEqual({ ok: true, sections: new Map([
      ["validation-marker", { state: "absent" }],
      ["held-token-names", { state: "unreadable" }],
    ]) });
  });

  test("trailing newlines and multibyte content keep their exact byte length", () => {
    writeMarker({ note: "café" });
    fs.appendFileSync(paths.validationMarker, "\n\n");
    const parsed = parseCredentialObservationBatch(runScript(["validation-marker"]), ["validation-marker"]);
    expect(parsed.ok && parsed.sections.get("validation-marker")).toEqual({ state: "present", text: fs.readFileSync(paths.validationMarker, "utf8") });
  });

  test("a section list naming a section twice is refused before any exec", () => {
    expect(() => credentialObservationBatchScript(["validation-marker", "validation-marker"], paths)).toThrow(/names a section twice/);
  });
});

describe("credential observation batch parser", () => {
  const requested: readonly ProxyObservationSection[] = ["validation-marker", "held-token-names"];

  test.each([
    ["a missing section", frame(present("validation-marker", "{}")), "missing section held-token-names"],
    ["a duplicate section", frame(present("validation-marker", "{}"), present("validation-marker", "{}"), present("held-token-names", "")), "duplicate section validation-marker"],
    ["an unrequested section", frame(present("validation-marker", "{}"), present("held-token-names", ""), present("firewall-status", "{}")), "unrequested section firewall-status"],
    ["a truncated section", `${CREDENTIAL_OBSERVATION_BATCH_HEADER}\nvalidation-marker present 40\n{"proofVersion":4}`, "truncated section validation-marker"],
    ["a missing end trailer", `${CREDENTIAL_OBSERVATION_BATCH_HEADER}\n${present("validation-marker", "{}")}${present("held-token-names", "")}`, "truncated batch: no end trailer"],
    ["a length shorter than the bytes", `${CREDENTIAL_OBSERVATION_BATCH_HEADER}\nvalidation-marker present 1\n{}\n${present("held-token-names", "")}end\n`, "truncated section validation-marker"],
    ["bytes after the trailer", `${frame(present("validation-marker", "{}"), present("held-token-names", ""))}extra\n`, "bytes after the end trailer"],
    ["an unknown version", frame(present("validation-marker", "{}"), present("held-token-names", "")).replace(" 1\n", " 2\n"), "missing or unsupported batch header"],
    ["an absent section carrying bytes", frame("validation-marker absent 2\n{}\n", present("held-token-names", "")), "section validation-marker is absent but carries bytes"],
    ["an oversized section", frame(`validation-marker present ${CREDENTIAL_OBSERVATION_SECTION_MAX_BYTES + 1}\n`), "section validation-marker exceeds its bound"],
  ])("refuses %s as a whole", (_label, stdout, reason) => {
    expect(parseCredentialObservationBatch(stdout, requested)).toEqual({ ok: false, reason });
  });
});

describe("observeCredentialRuntime", () => {
  test("binds every section to one incarnation and derives the generation every earlier CLI derived", () => {
    const markerText = writeMarker();
    fs.writeFileSync(path.join(paths.secretDir, "github"), "value");
    const { docker, calls } = fakeDocker({});

    const result = observeCredentialRuntime({
      phase: "preparation", proxyId: "proxy-id", sections: ["validation-marker", "held-token-names"], paths, docker, isTokenName, before: STARTED_AT,
    });

    expect(result.kind).toBe("observed");
    if (result.kind !== "observed") return;
    const marker = parseProxyValidationMarker(markerText);
    expect(result.observation.storeGeneration).toBe(proxyTokenStoreGeneration("proxy-id", STARTED_AT, marker.fingerprint));
    expect([...result.observation.heldTokenNames ?? []]).toEqual(["github"]);
    // One root exec for every file, one incarnation reading after it.
    expect(calls.map((call) => call.kind)).toEqual(["exec", "inspect"]);
    expect(calls[0].args[2]).toEqual({ user: "0:0" });
  });

  test("a same-ID restart between the before reading and the batch is a mismatch, not evidence", () => {
    writeMarker();
    const { docker } = fakeDocker({ startedAt: () => ({ status: 0, stdout: `${RESTARTED_AT}\n`, stderr: "" }) });
    const result = observeCredentialRuntime({
      phase: "locked-sync", proxyId: "proxy-id", sections: ["validation-marker", "held-token-names"], paths, docker, isTokenName, before: STARTED_AT,
    });
    expect(result).toEqual({ kind: "mismatch", reason: "the proxy restarted while its credential runtime was observed" });
  });

  test("a malformed or failed incarnation reading makes the observation unavailable", () => {
    writeMarker();
    for (const answer of [
      { status: 1, stdout: "", stderr: "no such container" },
      { status: 0, stdout: "<no value>\n", stderr: "" },
      { status: 0, stdout: `${STARTED_AT}\n${STARTED_AT}\n`, stderr: "" },
    ]) {
      const { docker } = fakeDocker({ startedAt: () => answer });
      const result = observeCredentialRuntime({ phase: "locked-sync", proxyId: "proxy-id", sections: ["validation-marker"], paths, docker, isTokenName, before: STARTED_AT });
      expect(result.kind).toBe("unavailable");
    }
  });

  test("a failed exec or a malformed batch is unavailable and reads no incarnation", () => {
    for (const exec of [
      (): CaptureResult => ({ status: 1, stdout: "", stderr: "exec failed" }),
      (): CaptureResult => ({ status: 0, stdout: `${CREDENTIAL_OBSERVATION_BATCH_HEADER}\n`, stderr: "" }),
    ]) {
      const { docker, calls } = fakeDocker({ exec });
      const result = observeCredentialRuntime({ phase: "preparation", proxyId: "proxy-id", sections: ["validation-marker"], paths, docker, isTokenName, before: STARTED_AT });
      expect(result.kind).toBe("unavailable");
      expect(calls.map((call) => call.kind)).toEqual(["exec"]);
    }
  });

  test("a grouped after-reading may refuse the runtime with its own validation message", () => {
    writeMarker();
    const { docker, calls } = fakeDocker({});
    const result = observeCredentialRuntime({
      phase: "locked-sync", proxyId: "proxy-id", sections: ["validation-marker"], paths, docker, isTokenName, before: STARTED_AT,
      after: (sections) => sections.validationMarker ? { kind: "refused", message: "stale marker" } : { kind: "unavailable", reason: "no marker" },
    });
    expect(result).toEqual({ kind: "refused", message: "stale marker" });
    expect(calls.map((call) => call.kind)).toEqual(["exec"]);
  });

  test("an absent marker yields an observation without a store generation", () => {
    const { docker } = fakeDocker({});
    const result = observeCredentialRuntime({ phase: "locked-sync", proxyId: "proxy-id", sections: ["validation-marker"], paths, docker, isTokenName, before: STARTED_AT });
    expect(result.kind === "observed" && result.observation.storeGeneration).toBeUndefined();
    expect(result.kind === "observed" && result.observation.validationMarker).toBeUndefined();
  });

  test("consumer acknowledgements are parsed with the shared status contract", () => {
    writeMarker();
    fs.writeFileSync(paths.firewallStatus, '{"generation":"g1","controlGeneration":"c1","policyGeneration":"g1","rulesetVerified":true}\n');
    fs.writeFileSync(paths.requestProxyStatus, "not json\n");
    const { docker } = fakeDocker({});
    const result = observeCredentialRuntime({
      phase: "locked-sync", proxyId: "proxy-id", sections: ["validation-marker", "firewall-status", "request-proxy-status"], paths, docker, isTokenName, before: STARTED_AT,
    });
    expect(result.kind === "observed" && result.observation.firewallStatus).toMatchObject({ controlGeneration: "c1", policyGeneration: "g1", rulesetVerified: true });
    expect(result.kind === "observed" && result.observation.requestProxyStatus).toBeUndefined();
  });
});

describe("phase separation", () => {
  test("preparation evidence is never write authority for a locked sync", () => {
    expect(() => lockedHeldTokenNames({ phase: "preparation", heldTokenNames: new Set(["github"]) })).toThrow(/not write authority/);
    expect([...lockedHeldTokenNames({ phase: "locked-sync", heldTokenNames: new Set(["github"]) }) ?? []]).toEqual(["github"]);
  });
});

describe("grouped inspect rows", () => {
  test("splits the trailing StartedAt field only from a row of the exact shape", () => {
    expect(splitTrailingStartedAt(`true\t${STARTED_AT}`, 1)).toEqual({ head: "true", startedAt: STARTED_AT });
    expect(splitTrailingStartedAt("true\t", 1)).toEqual({ head: "true", startedAt: undefined });
    expect(splitTrailingStartedAt("true", 1)).toBeUndefined();
    expect(splitTrailingStartedAt(`a\tb\t${STARTED_AT}`, 1)).toBeUndefined();
  });
});
