import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test } from "vitest";

import {
  createHelperRun,
  EphemeralHelperUnconfirmedError,
  helperRunsRoot,
  parseHelperIntent,
  readHelperCid,
  reclaimHelperRun,
  reclaimHelperRunResidue,
  validateEphemeralHelperRemovalCandidate,
  type EphemeralHelperFence,
  type HelperRun,
  type HelperRunIntent,
} from "./ephemeral-helper-residue.ts";
import type { CaptureResult, RuntimeIO } from "./types.ts";

const PROJECT_ID = "0123456789ab";
const OTHER_PROJECT_ID = "ba9876543210";
const NETWORK_ID = "c".repeat(64);
const HELPER_ID = "a".repeat(64);
const OTHER_ID = "b".repeat(64);
const NONCE = "d".repeat(32);
const IMAGE_TAG = "runfree-agent:abc";
const IMAGE_ID = `sha256:${"e".repeat(64)}`;

let stateDir: string;

beforeEach(() => {
  stateDir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "runfree-helper-residue-")));
});

afterEach(() => {
  fs.rmSync(stateDir, { recursive: true, force: true });
});

function intent(overrides: Partial<HelperRunIntent> = {}): HelperRunIntent {
  return {
    v: 1,
    projectId: PROJECT_ID,
    purpose: "deny-probe",
    image: IMAGE_TAG,
    network: NETWORK_ID,
    ip: "172.30.0.19",
    nonce: NONCE,
    createdAt: "2026-09-24T12:00:00.000Z",
    ...overrides,
  } as HelperRunIntent;
}

function helperLabels(overrides: Record<string, string | undefined> = {}): Record<string, string> {
  const labels: Record<string, string | undefined> = {
    "io.runfree.managed": "true",
    "io.runfree.container-role": "ephemeral-helper",
    "io.runfree.lifecycle-owner": "utility",
    "io.runfree.label-schema": "1",
    "io.runfree.project-id": PROJECT_ID,
    "io.runfree.helper-purpose": "deny-probe",
    "io.runfree.helper-run": NONCE,
    // An image LABEL is inherited into Config.Labels; it must not matter.
    "maintainer": "someone",
    ...overrides,
  };
  return Object.fromEntries(Object.entries(labels).filter((entry): entry is [string, string] => entry[1] !== undefined));
}

type Inspect = Record<string, unknown>;

function helperInspect(overrides: {
  id?: string;
  labels?: Record<string, string>;
  configImage?: string;
  image?: string;
  networkMode?: string;
  networks?: Record<string, unknown>;
  status?: string;
} = {}): Inspect {
  return {
    Id: overrides.id ?? HELPER_ID,
    Image: overrides.image ?? IMAGE_ID,
    Config: { Image: overrides.configImage ?? IMAGE_TAG, Labels: overrides.labels ?? helperLabels() },
    HostConfig: { NetworkMode: overrides.networkMode ?? NETWORK_ID, AutoRemove: true },
    State: { Status: overrides.status ?? "running" },
    NetworkSettings: {
      Networks: overrides.networks ?? {
        "runfree-0123456789ab_agent_internal": {
          NetworkID: NETWORK_ID,
          IPAddress: "172.30.0.19",
          IPAMConfig: { IPv4Address: "172.30.0.19" },
        },
      },
    },
  };
}

type Call = { kind: "docker"; args: string[]; timeout?: number; killSignal?: unknown } | { kind: "assertHeld" };

/**
 * A small Docker double over a container table. Every call is logged beside
 * every lock assertion, so tests can prove ordering (fence around each call)
 * and the absence of `rm`.
 */
function fakeDocker(initial: Inspect[] = []) {
  const containers = new Map<string, Inspect>(initial.map((entry) => [entry.Id as string, entry]));
  const calls: Call[] = [];
  const hooks: {
    ps?: (args: string[]) => CaptureResult | undefined;
    inspect?: (id: string) => CaptureResult | undefined;
    imageInspect?: (image: string) => CaptureResult | undefined;
    rm?: (id: string) => CaptureResult | undefined;
    list?: (args: string[]) => CaptureResult | undefined;
  } = {};
  let lockThrowsAt: number | undefined;
  let assertions = 0;
  const ok = (stdout = ""): CaptureResult => ({ status: 0, stdout, stderr: "" });
  const capture = (command: string, args: string[], options: { timeout?: number; killSignal?: unknown } = {}): CaptureResult => {
    expect(command).toBe("docker");
    calls.push({ kind: "docker", args, timeout: options.timeout, killSignal: options.killSignal });
    if (args[0] === "ps") {
      const idFilter = args.find((arg) => arg.startsWith("id="));
      if (idFilter) {
        const hooked = hooks.ps?.(args);
        if (hooked) return hooked;
        const id = idFilter.slice(3);
        return ok(containers.has(id) ? `${id}\n` : "");
      }
      const hooked = hooks.list?.(args);
      if (hooked) return hooked;
      const labelFilters = args.filter((arg) => arg.startsWith("label=")).map((arg) => arg.slice(6));
      const matching = [...containers.values()].filter((entry) => {
        const labels = ((entry.Config as { Labels?: Record<string, string> }).Labels) ?? {};
        return labelFilters.every((filter) => {
          const [key, ...value] = filter.split("=");
          return labels[key] === value.join("=");
        });
      });
      return ok(matching.map((entry) => `${entry.Id as string}\n`).join(""));
    }
    if (args[0] === "container" && args[1] === "inspect") {
      const hooked = hooks.inspect?.(args[2]);
      if (hooked) return hooked;
      const entry = containers.get(args[2]);
      return entry ? ok(JSON.stringify([entry])) : { status: 1, stdout: "[]", stderr: `Error: No such container: ${args[2]}` };
    }
    if (args[0] === "image" && args[1] === "inspect") {
      const hooked = hooks.imageInspect?.(args.at(-1) as string);
      if (hooked) return hooked;
      return ok(`${IMAGE_ID}\n`);
    }
    if (args[0] === "rm" && args[1] === "-f") {
      const hooked = hooks.rm?.(args[2]);
      if (hooked) return hooked;
      containers.delete(args[2]);
      return ok(`${args[2]}\n`);
    }
    throw new Error(`unexpected docker call: ${args.join(" ")}`);
  };
  const fence = (): EphemeralHelperFence => ({
    lifecycleLock: {
      assertHeld: () => {
        assertions += 1;
        calls.push({ kind: "assertHeld" });
        if (lockThrowsAt !== undefined && assertions >= lockThrowsAt) throw new Error("project lifecycle lock was lost");
      },
    },
    containmentIO: { capture } as unknown as RuntimeIO,
    stateDir,
  });
  return {
    containers,
    calls,
    hooks,
    fence,
    docker: () => calls.filter((call): call is Extract<Call, { kind: "docker" }> => call.kind === "docker"),
    rmCalls: () => calls.filter((call) => call.kind === "docker" && call.args[0] === "rm"),
    /** Throw from the Nth assertHeld on (1-based). */
    loseLockAt: (nth: number) => { lockThrowsAt = nth; },
  };
}

const NO_WAIT = { sleep: () => {}, pollDeadlineMs: 0 } as const;

function runWithCid(run: HelperRun, content: string | undefined): void {
  if (content !== undefined) fs.writeFileSync(path.join(run.directory, "cid"), content);
}

describe("helper-run records", () => {
  test("createHelperRun makes a 0700 run directory with an exclusive 0600 intent", () => {
    const run = createHelperRun(stateDir, intent());
    expect(path.dirname(run.directory)).toBe(helperRunsRoot(stateDir));
    expect(path.basename(run.directory)).toMatch(/^run-[A-Za-z0-9]{6}$/u);
    expect(fs.statSync(run.directory).mode & 0o777).toBe(0o700);
    const intentPath = path.join(run.directory, "intent.json");
    expect(fs.statSync(intentPath).mode & 0o777).toBe(0o600);
    expect(parseHelperIntent(fs.readFileSync(intentPath, "utf8"))).toEqual(intent());
    expect(run.cidFile).toBe(path.join(run.directory, "cid"));
  });

  test("createHelperRun refuses a symlinked helper-runs root", () => {
    const elsewhere = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-helper-elsewhere-"));
    try {
      fs.symlinkSync(elsewhere, helperRunsRoot(stateDir));
      expect(() => createHelperRun(stateDir, intent())).toThrow(/helper-runs/u);
      expect(fs.readdirSync(elsewhere)).toEqual([]);
    } finally {
      fs.rmSync(elsewhere, { recursive: true, force: true });
    }
  });

  test.each([
    ["not json", "{"],
    ["an unknown field", JSON.stringify({ ...intent(), extra: true })],
    ["a missing nonce", JSON.stringify({ ...intent(), nonce: undefined })],
    ["a bad nonce", JSON.stringify({ ...intent(), nonce: "D".repeat(32) })],
    ["another version", JSON.stringify({ ...intent(), v: 2 })],
    ["a bad project id", JSON.stringify({ ...intent(), projectId: "nope" })],
    ["an unknown purpose", JSON.stringify({ ...intent(), purpose: "exfiltrate" })],
    ["an image with whitespace", JSON.stringify({ ...intent(), image: "a b" })],
    ["a short network id", JSON.stringify({ ...intent(), network: "abc" })],
    ["a networked intent without an address", JSON.stringify({ ...intent(), ip: undefined })],
    ["an address outside the helper block", JSON.stringify({ ...intent(), ip: "172.30.0.20" })],
    ["an address on a network-less intent", JSON.stringify({ ...intent(), network: "none" })],
    ["a non-date createdAt", JSON.stringify({ ...intent(), createdAt: "yesterday" })],
    ["an array", "[]"],
  ])("parseHelperIntent refuses %s", (_name, text) => {
    expect(() => parseHelperIntent(text)).toThrow();
  });

  test("parseHelperIntent accepts a network-less intent", () => {
    const none = intent({ network: "none", ip: undefined, purpose: "trust-bundle" });
    const { ip: _ip, ...withoutIp } = none;
    expect(parseHelperIntent(JSON.stringify(withoutIp))).toEqual(withoutIp);
  });

  test("readHelperCid classifies absent, empty, exact, and tampered cidfiles", () => {
    const run = createHelperRun(stateDir, intent());
    expect(readHelperCid(run.directory)).toEqual({ kind: "absent" });
    runWithCid(run, "");
    expect(readHelperCid(run.directory)).toEqual({ kind: "empty" });
    runWithCid(run, HELPER_ID);
    expect(readHelperCid(run.directory)).toEqual({ kind: "id", id: HELPER_ID });
    runWithCid(run, `${HELPER_ID}\n`);
    expect(readHelperCid(run.directory)).toEqual({ kind: "id", id: HELPER_ID });
    runWithCid(run, `${HELPER_ID}\n\n`);
    expect(readHelperCid(run.directory).kind).toBe("tampered");
    runWithCid(run, "z".repeat(64));
    expect(readHelperCid(run.directory).kind).toBe("tampered");
    expect(readHelperCid(run.directory, { expectedUid: (process.getuid?.() ?? 0) + 1 }).kind).toBe("tampered");
  });
});

describe("validateEphemeralHelperRemovalCandidate", () => {
  const expected = { id: HELPER_ID, imageId: IMAGE_ID };

  test("accepts the exact helper this intent created", () => {
    expect(validateEphemeralHelperRemovalCandidate(helperInspect(), intent(), expected)).toBeUndefined();
  });

  test("accepts a created-but-never-started networked helper with no network id yet", () => {
    expect(validateEphemeralHelperRemovalCandidate(helperInspect({
      status: "created",
      networks: { internal: { NetworkID: "", IPAddress: "", IPAMConfig: { IPv4Address: "172.30.0.19" } } },
    }), intent(), expected)).toBeUndefined();
  });

  test("accepts a network-less helper", () => {
    expect(validateEphemeralHelperRemovalCandidate(helperInspect({
      labels: helperLabels({ "io.runfree.helper-purpose": "trust-bundle" }),
      networkMode: "none",
      networks: { none: { NetworkID: "f".repeat(64), IPAddress: "" } },
    }), intent({ purpose: "trust-bundle", network: "none", ip: undefined }), expected)).toBeUndefined();
  });

  test("does not depend on inherited Compose labels (an image can carry them)", () => {
    expect(validateEphemeralHelperRemovalCandidate(helperInspect({
      labels: helperLabels({ "com.docker.compose.project": "anything" }),
    }), intent(), expected)).toBeUndefined();
  });

  test("an image-id intent compares the immutable image id on the crash path too", () => {
    const byId = intent({ image: IMAGE_ID });
    expect(validateEphemeralHelperRemovalCandidate(helperInspect({ configImage: IMAGE_ID }), byId, { id: HELPER_ID }))
      .toBeUndefined();
    expect(validateEphemeralHelperRemovalCandidate(helperInspect({ configImage: IMAGE_ID, image: `sha256:${"9".repeat(64)}` }), byId, { id: HELPER_ID }))
      .toMatch(/image/u);
  });

  test("a tag intent on the crash path authorizes by the reference string alone", () => {
    expect(validateEphemeralHelperRemovalCandidate(helperInspect({ image: `sha256:${"9".repeat(64)}` }), intent(), { id: HELPER_ID }))
      .toBeUndefined();
  });

  const labelCases: [string, Record<string, string | undefined>][] = [
    ["io.runfree.managed", { "io.runfree.managed": undefined }],
    ["io.runfree.managed changed", { "io.runfree.managed": "false" }],
    ["io.runfree.container-role", { "io.runfree.container-role": undefined }],
    ["io.runfree.container-role changed", { "io.runfree.container-role": "session-agent" }],
    ["io.runfree.lifecycle-owner", { "io.runfree.lifecycle-owner": undefined }],
    ["io.runfree.lifecycle-owner changed", { "io.runfree.lifecycle-owner": "compose" }],
    ["io.runfree.label-schema", { "io.runfree.label-schema": undefined }],
    ["io.runfree.label-schema changed", { "io.runfree.label-schema": "2" }],
    ["io.runfree.project-id", { "io.runfree.project-id": undefined }],
    ["another project's id", { "io.runfree.project-id": OTHER_PROJECT_ID }],
    ["io.runfree.helper-purpose", { "io.runfree.helper-purpose": undefined }],
    ["another purpose", { "io.runfree.helper-purpose": "dependency-prep" }],
    ["io.runfree.helper-run", { "io.runfree.helper-run": undefined }],
    ["another run's nonce", { "io.runfree.helper-run": "f".repeat(32) }],
  ];
  test.each(labelCases)("refuses a missing or changed label: %s", (_name, override) => {
    expect(validateEphemeralHelperRemovalCandidate(helperInspect({ labels: helperLabels(override) }), intent(), expected))
      .toMatch(/label/u);
  });

  test.each([
    ["another id", helperInspect({ id: OTHER_ID })],
    ["a short id", helperInspect({ id: "abc" })],
    ["a wrong Config.Image", helperInspect({ configImage: "runfree-agent:other" })],
    ["an image id other than the resolved one", helperInspect({ image: `sha256:${"9".repeat(64)}` })],
    ["two network attachments", helperInspect({ networks: {
      a: { NetworkID: NETWORK_ID, IPAddress: "172.30.0.19", IPAMConfig: { IPv4Address: "172.30.0.19" } },
      b: { NetworkID: "f".repeat(64), IPAddress: "172.31.0.2" },
    } })],
    ["no network attachment", helperInspect({ networks: {} })],
    ["another network mode", helperInspect({ networkMode: "f".repeat(64) })],
    ["another network id", helperInspect({ networks: { a: { NetworkID: "f".repeat(64), IPAddress: "172.30.0.19", IPAMConfig: { IPv4Address: "172.30.0.19" } } } })],
    ["an empty network id while running", helperInspect({ networks: { a: { NetworkID: "", IPAddress: "172.30.0.19", IPAMConfig: { IPv4Address: "172.30.0.19" } } } })],
    ["another pinned address", helperInspect({ networks: { a: { NetworkID: NETWORK_ID, IPAddress: "172.30.0.18", IPAMConfig: { IPv4Address: "172.30.0.18" } } } })],
    ["a dynamic address with no IPAM pin", helperInspect({ networks: { a: { NetworkID: NETWORK_ID, IPAddress: "172.30.0.19" } } })],
    ["an IPAM pin that disagrees with the live address", helperInspect({ networks: { a: { NetworkID: NETWORK_ID, IPAddress: "172.30.0.25", IPAMConfig: { IPv4Address: "172.30.0.19" } } } })],
    ["not an object", "nope" as unknown as Inspect],
  ])("refuses %s", (_name, inspect) => {
    expect(validateEphemeralHelperRemovalCandidate(inspect, intent(), expected)).toBeTypeOf("string");
  });

  test("refuses a network-less intent whose container is attached somewhere", () => {
    expect(validateEphemeralHelperRemovalCandidate(helperInspect({
      labels: helperLabels({ "io.runfree.helper-purpose": "trust-bundle" }),
      networkMode: "none",
    }), intent({ purpose: "trust-bundle", network: "none", ip: undefined }), expected)).toBeTypeOf("string");
  });
});

describe("reclaimHelperRun", () => {
  test("removes a timed-out helper by exact id with the lock asserted around every call", () => {
    const docker = fakeDocker([helperInspect()]);
    const run = createHelperRun(stateDir, intent());
    runWithCid(run, HELPER_ID);

    expect(reclaimHelperRun(run, docker.fence(), "same-process", NO_WAIT)).toBe("removed");

    expect(docker.docker().map((call) => call.args.slice(0, 2).join(" "))).toEqual([
      "ps --all",
      "container inspect",
      "image inspect",
      "rm -f",
      "ps --all",
    ]);
    expect(docker.rmCalls()).toEqual([expect.objectContaining({ args: ["rm", "-f", HELPER_ID] })]);
    // assertHeld immediately before and after every Docker call: one on
    // entry, then a bracket pair around each of the five calls, then one
    // before the directory is removed.
    expect(docker.calls.map((call) => (call.kind === "docker" ? call.args[0] : "held"))).toEqual([
      "held",
      "held", "ps", "held",
      "held", "container", "held",
      "held", "image", "held",
      "held", "rm", "held",
      "held", "ps", "held",
      "held",
    ]);
    for (const call of docker.docker()) {
      expect(call.killSignal).toBe("SIGKILL");
      expect(call.timeout).toBeGreaterThan(0);
      expect(call.timeout).toBeLessThanOrEqual(10_000);
    }
    expect(docker.docker().find((call) => call.args[0] === "image")?.args).toEqual(["image", "inspect", "--format", "{{.Id}}", IMAGE_TAG]);
    expect(fs.existsSync(run.directory)).toBe(false);
  });

  test("an empty inventory proves the helper already gone: directory removed, no inspect, no rm", () => {
    const docker = fakeDocker();
    const run = createHelperRun(stateDir, intent());
    runWithCid(run, HELPER_ID);
    expect(reclaimHelperRun(run, docker.fence(), "same-process", NO_WAIT)).toBe("absent");
    expect(docker.docker().map((call) => call.args[0])).toEqual(["ps"]);
    expect(fs.existsSync(run.directory)).toBe(false);
  });

  test("the crash path never resolves a tag to an image id", () => {
    const docker = fakeDocker([helperInspect({ image: `sha256:${"9".repeat(64)}` })]);
    const run = createHelperRun(stateDir, intent());
    runWithCid(run, HELPER_ID);
    expect(reclaimHelperRun(run, docker.fence(), "crash", NO_WAIT)).toBe("removed");
    expect(docker.docker().some((call) => call.args[0] === "image")).toBe(false);
  });

  test("an image-id intent needs no image inspection on either path", () => {
    const docker = fakeDocker([helperInspect({ configImage: IMAGE_ID })]);
    const run = createHelperRun(stateDir, intent({ image: IMAGE_ID }));
    runWithCid(run, HELPER_ID);
    expect(reclaimHelperRun(run, docker.fence(), "same-process", NO_WAIT)).toBe("removed");
    expect(docker.docker().some((call) => call.args[0] === "image")).toBe(false);
  });

  // Every refusal below keeps the directory (the next `up` retries it), makes
  // no rm, and reports the helper unconfirmed.
  function expectUnconfirmed(run: HelperRun, docker: ReturnType<typeof fakeDocker>, mode: "same-process" | "crash" = "same-process"): EphemeralHelperUnconfirmedError {
    let caught: unknown;
    try {
      reclaimHelperRun(run, docker.fence(), mode, NO_WAIT);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(EphemeralHelperUnconfirmedError);
    expect(fs.existsSync(run.directory)).toBe(true);
    return caught as EphemeralHelperUnconfirmedError;
  }

  test.each([
    ["the inventory names another id", (docker: ReturnType<typeof fakeDocker>) => { docker.hooks.ps = () => ({ status: 0, stdout: `${OTHER_ID}\n`, stderr: "" }); }],
    ["the inventory names two ids", (docker: ReturnType<typeof fakeDocker>) => { docker.hooks.ps = () => ({ status: 0, stdout: `${HELPER_ID}\n${OTHER_ID}\n`, stderr: "" }); }],
    ["the inventory fails", (docker: ReturnType<typeof fakeDocker>) => { docker.hooks.ps = () => ({ status: 124, stdout: "", stderr: "", timedOut: true }); }],
    ["the inventory answers with stderr", (docker: ReturnType<typeof fakeDocker>) => { docker.hooks.ps = () => ({ status: 0, stdout: "", stderr: "Cannot connect to the Docker daemon" }); }],
    ["the inspection names another id", (docker: ReturnType<typeof fakeDocker>) => { docker.hooks.inspect = () => ({ status: 0, stdout: JSON.stringify([helperInspect({ id: OTHER_ID })]), stderr: "" }); }],
    ["the inspection returns two containers", (docker: ReturnType<typeof fakeDocker>) => { docker.hooks.inspect = () => ({ status: 0, stdout: JSON.stringify([helperInspect(), helperInspect()]), stderr: "" }); }],
    ["the inspection is malformed", (docker: ReturnType<typeof fakeDocker>) => { docker.hooks.inspect = () => ({ status: 0, stdout: "{", stderr: "" }); }],
    ["the inspection fails", (docker: ReturnType<typeof fakeDocker>) => { docker.hooks.inspect = () => ({ status: 125, stdout: "", stderr: "boom" }); }],
    ["the image cannot be resolved", (docker: ReturnType<typeof fakeDocker>) => { docker.hooks.imageInspect = () => ({ status: 1, stdout: "", stderr: "No such image" }); }],
    ["the image resolves to another id", (docker: ReturnType<typeof fakeDocker>) => { docker.hooks.imageInspect = () => ({ status: 0, stdout: `sha256:${"9".repeat(64)}\n`, stderr: "" }); }],
  ])("refuses without rm when %s", (_name, arrange) => {
    const docker = fakeDocker([helperInspect()]);
    arrange(docker);
    const run = createHelperRun(stateDir, intent());
    runWithCid(run, HELPER_ID);
    expectUnconfirmed(run, docker);
    expect(docker.rmCalls()).toEqual([]);
    expect(docker.containers.has(HELPER_ID)).toBe(true);
  });

  test.each([
    ["a label is missing", helperInspect({ labels: helperLabels({ "io.runfree.helper-run": undefined }) })],
    ["another project's id", helperInspect({ labels: helperLabels({ "io.runfree.project-id": OTHER_PROJECT_ID }) })],
    ["another purpose", helperInspect({ labels: helperLabels({ "io.runfree.helper-purpose": "trust-bundle" }) })],
    ["a wrong Config.Image", helperInspect({ configImage: "runfree-agent:other" })],
    ["an image id other than the resolved one", helperInspect({ image: `sha256:${"9".repeat(64)}` })],
    ["two network attachments", helperInspect({ networks: {
      a: { NetworkID: NETWORK_ID, IPAddress: "172.30.0.19", IPAMConfig: { IPv4Address: "172.30.0.19" } },
      b: { NetworkID: "f".repeat(64), IPAddress: "172.31.0.2" },
    } })],
    ["another network mode", helperInspect({ networkMode: "f".repeat(64) })],
    ["another pinned address", helperInspect({ networks: { a: { NetworkID: NETWORK_ID, IPAddress: "172.30.0.18", IPAMConfig: { IPv4Address: "172.30.0.18" } } } })],
  ])("refuses without rm when the inspected container has %s", (_name, inspect) => {
    const docker = fakeDocker([inspect]);
    const run = createHelperRun(stateDir, intent());
    runWithCid(run, HELPER_ID);
    const error = expectUnconfirmed(run, docker);
    expect(docker.rmCalls()).toEqual([]);
    expect(error.message).toContain("runfree up");
    expect(error.message).toContain("runfree destroy --force");
  });

  test("the lock lost before the first call makes zero Docker calls", () => {
    const docker = fakeDocker([helperInspect()]);
    docker.loseLockAt(1);
    const run = createHelperRun(stateDir, intent());
    runWithCid(run, HELPER_ID);
    expectUnconfirmed(run, docker);
    expect(docker.docker()).toEqual([]);
  });

  test("the lock lost after the inspection makes no rm", () => {
    const docker = fakeDocker([helperInspect()]);
    // 1 on entry, 2/3 around ps, 4/5 around inspect -> lost right after it.
    docker.loseLockAt(5);
    const run = createHelperRun(stateDir, intent());
    runWithCid(run, HELPER_ID);
    expectUnconfirmed(run, docker);
    expect(docker.rmCalls()).toEqual([]);
  });

  test("the lock lost right after rm is reported unconfirmed and keeps the directory", () => {
    const docker = fakeDocker([helperInspect()]);
    const run = createHelperRun(stateDir, intent());
    runWithCid(run, HELPER_ID);
    let seen = 0;
    const base = docker.fence();
    const fence: EphemeralHelperFence = {
      ...base,
      lifecycleLock: {
        assertHeld: () => {
          base.lifecycleLock.assertHeld();
          seen += docker.rmCalls().length > 0 ? 1 : 0;
          if (seen > 0) throw new Error("project lifecycle lock was lost");
        },
      },
    };
    expect(() => reclaimHelperRun(run, fence, "same-process", NO_WAIT)).toThrow(EphemeralHelperUnconfirmedError);
    expect(docker.rmCalls()).toHaveLength(1);
    expect(fs.existsSync(run.directory)).toBe(true);
  });

  test("the next lock holder reclaims what a lost lock left behind", () => {
    const docker = fakeDocker([helperInspect()]);
    docker.loseLockAt(5);
    const run = createHelperRun(stateDir, intent());
    runWithCid(run, HELPER_ID);
    expectUnconfirmed(run, docker);

    const next = fakeDocker([helperInspect()]);
    expect(reclaimHelperRunResidue(next.fence(), PROJECT_ID, NO_WAIT)).toBe(1);
    expect(next.rmCalls()).toEqual([expect.objectContaining({ args: ["rm", "-f", HELPER_ID] })]);
    expect(fs.existsSync(run.directory)).toBe(false);
  });

  test.each([
    ["a symlink", (run: HelperRun) => { fs.symlinkSync(path.join(run.directory, "intent.json"), path.join(run.directory, "cid")); }],
    ["66 bytes", (run: HelperRun) => { fs.writeFileSync(path.join(run.directory, "cid"), `${HELPER_ID}\n\n`); }],
    ["non-hex", (run: HelperRun) => { fs.writeFileSync(path.join(run.directory, "cid"), "z".repeat(64)); }],
    ["a directory", (run: HelperRun) => { fs.mkdirSync(path.join(run.directory, "cid")); }],
  ])("a cidfile that is %s is refused with zero Docker calls", (_name, arrange) => {
    const docker = fakeDocker([helperInspect()]);
    const run = createHelperRun(stateDir, intent());
    arrange(run);
    const error = expectUnconfirmed(run, docker);
    expect(docker.docker()).toEqual([]);
    expect(error.message).toContain("runfree destroy --force");
  });

  test("a cidfile owned by another uid is refused with zero Docker calls", () => {
    const docker = fakeDocker([helperInspect()]);
    const run = createHelperRun(stateDir, intent());
    runWithCid(run, HELPER_ID);
    expect(() => reclaimHelperRun(run, docker.fence(), "same-process", { ...NO_WAIT, expectedUid: (process.getuid?.() ?? 0) + 1 }))
      .toThrow(EphemeralHelperUnconfirmedError);
    expect(docker.docker()).toEqual([]);
    expect(fs.existsSync(run.directory)).toBe(true);
  });

  test("rm fails and the helper is still present: unconfirmed, naming destroy --force", () => {
    const docker = fakeDocker([helperInspect()]);
    docker.hooks.rm = () => ({ status: 1, stdout: "", stderr: "daemon busy" });
    const run = createHelperRun(stateDir, intent());
    runWithCid(run, HELPER_ID);
    const error = expectUnconfirmed(run, docker);
    expect(error.message).toContain("runfree destroy --force");
    expect(error.message).toContain(HELPER_ID);
  });

  test("rm fails but the helper is gone (Docker's own --rm won the race): success", () => {
    const docker = fakeDocker([helperInspect()]);
    docker.hooks.rm = (id) => {
      docker.containers.delete(id);
      return { status: 1, stdout: "", stderr: `Error: No such container: ${id}` };
    };
    const run = createHelperRun(stateDir, intent());
    runWithCid(run, HELPER_ID);
    expect(reclaimHelperRun(run, docker.fence(), "same-process", NO_WAIT)).toBe("removed");
    expect(fs.existsSync(run.directory)).toBe(false);
  });

  test("the absence re-check is polled before the removal is called unconfirmed", () => {
    const docker = fakeDocker([helperInspect()]);
    // rm returns, but the daemon only finishes removing on the third look.
    let looks = 0;
    docker.hooks.rm = () => ({ status: 0, stdout: `${HELPER_ID}\n`, stderr: "" });
    docker.hooks.ps = (args) => {
      if (docker.rmCalls().length === 0) return undefined;
      looks += 1;
      return { status: 0, stdout: looks >= 3 ? "" : `${args.find((arg) => arg.startsWith("id="))?.slice(3)}\n`, stderr: "" };
    };
    const run = createHelperRun(stateDir, intent());
    runWithCid(run, HELPER_ID);
    const sleeps: number[] = [];
    expect(reclaimHelperRun(run, docker.fence(), "same-process", { sleep: (ms) => sleeps.push(ms), pollDeadlineMs: 5_000 }))
      .toBe("removed");
    expect(looks).toBe(3);
    expect(sleeps.length).toBe(2);
  });

  test("the absence poll is bounded", () => {
    const docker = fakeDocker([helperInspect()]);
    docker.hooks.rm = () => ({ status: 0, stdout: "", stderr: "" });
    const run = createHelperRun(stateDir, intent());
    runWithCid(run, HELPER_ID);
    let now = 0;
    expect(() => reclaimHelperRun(run, docker.fence(), "same-process", {
      sleep: (ms) => { now += ms; },
      now: () => now,
      pollDeadlineMs: 1_000,
    })).toThrow(EphemeralHelperUnconfirmedError);
    const looks = docker.docker().filter((call) => call.args[0] === "ps").length;
    expect(looks).toBeGreaterThan(1);
    expect(looks).toBeLessThan(20);
  });

  describe("with no cidfile id", () => {
    test.each([["absent", undefined], ["empty (the normal crash state)", ""]])(
      "a %s cidfile lists this run's helpers by project, role, purpose, and nonce",
      (_name, content) => {
        const docker = fakeDocker([helperInspect()]);
        const run = createHelperRun(stateDir, intent());
        runWithCid(run, content);
        expect(reclaimHelperRun(run, docker.fence(), "same-process", NO_WAIT)).toBe("removed");
        const listing = docker.docker()[0];
        expect(listing.args).toEqual([
          "ps", "--all", "--quiet", "--no-trunc",
          "--filter", `label=io.runfree.project-id=${PROJECT_ID}`,
          "--filter", "label=io.runfree.container-role=ephemeral-helper",
          "--filter", "label=io.runfree.helper-purpose=deny-probe",
          "--filter", `label=io.runfree.helper-run=${NONCE}`,
        ]);
        expect(docker.rmCalls()).toEqual([expect.objectContaining({ args: ["rm", "-f", HELPER_ID] })]);
        expect(fs.existsSync(run.directory)).toBe(false);
      },
    );

    test("an empty listing proves absence and removes the directory with no rm", () => {
      const docker = fakeDocker();
      const run = createHelperRun(stateDir, intent());
      expect(reclaimHelperRun(run, docker.fence(), "crash", NO_WAIT)).toBe("absent");
      expect(docker.rmCalls()).toEqual([]);
      expect(fs.existsSync(run.directory)).toBe(false);
    });

    test("a pre-change helper or another run's helper is never listed or removed", () => {
      const docker = fakeDocker([
        helperInspect({ id: OTHER_ID, labels: helperLabels({ "io.runfree.helper-run": undefined }) }),
        helperInspect({ id: "c".repeat(64), labels: helperLabels({ "io.runfree.helper-run": "f".repeat(32) }) }),
      ]);
      const run = createHelperRun(stateDir, intent());
      expect(reclaimHelperRun(run, docker.fence(), "crash", NO_WAIT)).toBe("absent");
      expect(docker.rmCalls()).toEqual([]);
      expect(docker.containers.size).toBe(2);
    });

    test("a listed candidate that fails the proof is not removed", () => {
      const docker = fakeDocker([helperInspect({ configImage: "runfree-agent:other" })]);
      const run = createHelperRun(stateDir, intent());
      expectUnconfirmed(run, docker, "crash");
      expect(docker.rmCalls()).toEqual([]);
    });

    test("a listing with a non-id line is a contradiction", () => {
      const docker = fakeDocker();
      docker.hooks.list = () => ({ status: 0, stdout: "not-an-id\n", stderr: "" });
      const run = createHelperRun(stateDir, intent());
      expectUnconfirmed(run, docker, "crash");
      expect(docker.rmCalls()).toEqual([]);
    });
  });
});

describe("reclaimHelperRunResidue", () => {
  test("no helper-runs directory costs no Docker call and no lock assertion", () => {
    const docker = fakeDocker();
    expect(reclaimHelperRunResidue(docker.fence(), PROJECT_ID, NO_WAIT)).toBe(0);
    expect(docker.calls).toEqual([]);
  });

  test("an empty helper-runs directory costs no Docker call", () => {
    const docker = fakeDocker();
    fs.mkdirSync(helperRunsRoot(stateDir), { mode: 0o700 });
    expect(reclaimHelperRunResidue(docker.fence(), PROJECT_ID, NO_WAIT)).toBe(0);
    expect(docker.docker()).toEqual([]);
  });

  test("a crashed run's helper is removed and its directory cleared", () => {
    const docker = fakeDocker([helperInspect()]);
    const run = createHelperRun(stateDir, intent());
    runWithCid(run, HELPER_ID);
    expect(reclaimHelperRunResidue(docker.fence(), PROJECT_ID, NO_WAIT)).toBe(1);
    expect(docker.rmCalls()).toEqual([expect.objectContaining({ args: ["rm", "-f", HELPER_ID] })]);
    expect(fs.readdirSync(helperRunsRoot(stateDir))).toEqual([]);
  });

  test("a run directory with no intent yet (crash before the write) is removed with no Docker call", () => {
    const docker = fakeDocker();
    fs.mkdirSync(path.join(helperRunsRoot(stateDir), "run-AbC123"), { recursive: true, mode: 0o700 });
    expect(reclaimHelperRunResidue(docker.fence(), PROJECT_ID, NO_WAIT)).toBe(0);
    expect(docker.docker()).toEqual([]);
    expect(fs.readdirSync(helperRunsRoot(stateDir))).toEqual([]);
  });

  test.each([
    ["an unparsable intent", (dir: string) => { fs.writeFileSync(path.join(dir, "intent.json"), "{"); }],
    ["another project's intent", (dir: string) => { fs.writeFileSync(path.join(dir, "intent.json"), JSON.stringify(intent({ projectId: OTHER_PROJECT_ID }))); }],
    ["a symlinked intent", (dir: string) => {
      fs.writeFileSync(path.join(dir, "..", "..", "decoy.json"), JSON.stringify(intent()));
      fs.symlinkSync(path.join(dir, "..", "..", "decoy.json"), path.join(dir, "intent.json"));
    }],
    ["a cidfile with no intent", (dir: string) => { fs.writeFileSync(path.join(dir, "cid"), HELPER_ID); }],
  ])("%s is refused before any Docker call, naming destroy --force, and every directory is kept", (_name, arrange) => {
    const docker = fakeDocker([helperInspect()]);
    // A valid residue beside the bad one must not be acted on either.
    const good = createHelperRun(stateDir, intent());
    runWithCid(good, HELPER_ID);
    const bad = path.join(helperRunsRoot(stateDir), "run-Zzz999");
    fs.mkdirSync(bad, { mode: 0o700 });
    arrange(bad);
    expect(() => reclaimHelperRunResidue(docker.fence(), PROJECT_ID, NO_WAIT)).toThrow(/runfree destroy --force/u);
    expect(docker.docker()).toEqual([]);
    expect(fs.existsSync(bad)).toBe(true);
    expect(fs.existsSync(good.directory)).toBe(true);
  });

  test("a symlinked run directory is refused before any Docker call", () => {
    const docker = fakeDocker([helperInspect()]);
    const elsewhere = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-helper-elsewhere-"));
    try {
      fs.writeFileSync(path.join(elsewhere, "intent.json"), JSON.stringify(intent()));
      fs.writeFileSync(path.join(elsewhere, "cid"), HELPER_ID);
      fs.mkdirSync(helperRunsRoot(stateDir), { mode: 0o700 });
      fs.symlinkSync(elsewhere, path.join(helperRunsRoot(stateDir), "run-AbC123"));
      expect(() => reclaimHelperRunResidue(docker.fence(), PROJECT_ID, NO_WAIT)).toThrow(/runfree destroy --force/u);
      expect(docker.docker()).toEqual([]);
      expect(fs.existsSync(path.join(elsewhere, "intent.json"))).toBe(true);
    } finally {
      fs.rmSync(elsewhere, { recursive: true, force: true });
    }
  });

  test("a symlinked helper-runs root is refused before any Docker call", () => {
    const docker = fakeDocker();
    const elsewhere = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-helper-elsewhere-"));
    try {
      fs.symlinkSync(elsewhere, helperRunsRoot(stateDir));
      expect(() => reclaimHelperRunResidue(docker.fence(), PROJECT_ID, NO_WAIT)).toThrow(/runfree destroy --force/u);
      expect(docker.docker()).toEqual([]);
    } finally {
      fs.rmSync(elsewhere, { recursive: true, force: true });
    }
  });

  test("an unexpected entry in helper-runs is refused before any Docker call", () => {
    const docker = fakeDocker();
    fs.mkdirSync(helperRunsRoot(stateDir), { mode: 0o700 });
    fs.writeFileSync(path.join(helperRunsRoot(stateDir), "stray"), "x");
    expect(() => reclaimHelperRunResidue(docker.fence(), PROJECT_ID, NO_WAIT)).toThrow(/runfree destroy --force/u);
    expect(docker.docker()).toEqual([]);
  });

  test("an unconfirmed residue keeps its directory, and a later reclaim clears it once Docker shows it absent", () => {
    const run = createHelperRun(stateDir, intent());
    runWithCid(run, HELPER_ID);
    const hung = fakeDocker([helperInspect()]);
    hung.hooks.rm = () => ({ status: 124, stdout: "", stderr: "", timedOut: true });
    expect(() => reclaimHelperRunResidue(hung.fence(), PROJECT_ID, NO_WAIT)).toThrow(EphemeralHelperUnconfirmedError);
    expect(fs.existsSync(run.directory)).toBe(true);

    const recovered = fakeDocker();
    expect(reclaimHelperRunResidue(recovered.fence(), PROJECT_ID, NO_WAIT)).toBe(1);
    expect(recovered.rmCalls()).toEqual([]);
    expect(fs.existsSync(run.directory)).toBe(false);
  });
});
