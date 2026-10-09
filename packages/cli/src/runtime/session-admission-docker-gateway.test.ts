import { describe, expect, test, vi } from "vitest";

import type { SessionContainerForegroundChild } from "./session-container-start.ts";
import { createSessionAdmissionDockerGateway } from "./session-admission-docker-gateway.ts";
import { createOperationHistogram } from "./operation-histogram.ts";
import type { RuntimeIO } from "./types.ts";

function runtimeIo(): RuntimeIO {
  return {
    run: vi.fn(() => 0),
    capture: vi.fn(() => ({ status: 0, stdout: "", stderr: "" })),
    commandExists: vi.fn(() => true),
    confirm: vi.fn(() => true),
    admin: vi.fn(async () => 0),
  };
}

describe("session admission Docker gateway", () => {
  test("counts Docker capture, run, and foreground spawn exactly once", () => {
    const io = runtimeIo();
    const child = {} as SessionContainerForegroundChild;
    const foregroundSpawner = vi.fn(() => child);
    const gateway = createSessionAdmissionDockerGateway({ io, foregroundSpawner });

    expect(gateway.dockerOperationCount()).toBe(0);
    gateway.io.capture("docker", ["container", "inspect", "id"]);
    gateway.io.run("docker", ["container", "stop", "id"]);
    expect(gateway.foregroundSpawner("docker", ["container", "start", "--attach", "id"], {
      env: {},
      shell: false,
      stdio: "inherit",
    })).toBe(child);

    expect(gateway.dockerOperationCount()).toBe(3);
    expect(io.capture).toHaveBeenCalledWith("docker", ["container", "inspect", "id"], undefined);
    expect(io.run).toHaveBeenCalledWith("docker", ["container", "stop", "id"], undefined);
    expect(foregroundSpawner).toHaveBeenCalledTimes(1);
  });

  test("does not count non-Docker work or availability checks", () => {
    const io = runtimeIo();
    const gateway = createSessionAdmissionDockerGateway({
      io,
      foregroundSpawner: vi.fn(() => ({} as SessionContainerForegroundChild)),
    });

    gateway.io.capture("git", ["status"]);
    gateway.io.run("node", ["helper.cjs"]);
    gateway.io.commandExists("docker");

    expect(gateway.dockerOperationCount()).toBe(0);
  });

  test("counts failed Docker operations and exposes a read-only monotonic total", () => {
    const io = runtimeIo();
    vi.mocked(io.capture).mockReturnValue({ status: 1, stdout: "", stderr: "failed" });
    const gateway = createSessionAdmissionDockerGateway({
      io,
      foregroundSpawner: vi.fn(() => {
        throw new Error("spawn failed");
      }),
    });

    expect(gateway.io.capture("docker", ["info"]).status).toBe(1);
    expect(() => gateway.foregroundSpawner("docker", ["container", "start"], {
      env: {},
      shell: false,
      stdio: "inherit",
    })).toThrow("spawn failed");
    expect(gateway.dockerOperationCount()).toBe(2);
  });

  test("records every counted docker op into an operation histogram when timings are on", () => {
    const io = runtimeIo();
    const histogram = createOperationHistogram();
    const gateway = createSessionAdmissionDockerGateway({
      io,
      histogram,
      foregroundSpawner: vi.fn(() => ({} as SessionContainerForegroundChild)),
    });

    gateway.io.capture("docker", ["container", "inspect", "x"]);
    gateway.io.capture("docker", ["exec", "--user", "0:0", "-i", "p", "node", "-e", "s"]);
    gateway.io.run("docker", ["container", "stop", "x"]);
    gateway.foregroundSpawner("docker", ["container", "start", "--attach", "x"], {
      env: {},
      shell: false,
      stdio: "inherit",
    });
    gateway.io.capture("git", ["status"]);

    const snapshot = histogram.snapshot();
    expect(Object.fromEntries(Object.entries(snapshot).map(([category, bucket]) => [category, bucket.count]))).toEqual({
      "docker container inspect": 1,
      "docker container start": 1,
      "docker container stop": 1,
      "docker exec": 1,
    });
    // The categories account for exactly the operations the gateway counts.
    const categorized = Object.values(snapshot).reduce((sum, bucket) => sum + bucket.count, 0);
    expect(categorized).toBe(gateway.dockerOperationCount());
    expect(gateway.dockerOperationCount()).toBe(4);
  });

  test("records a failed or throwing docker op once, like the count", () => {
    const io = runtimeIo();
    vi.mocked(io.capture).mockImplementation(() => {
      throw new Error("budget ended");
    });
    const histogram = createOperationHistogram();
    const gateway = createSessionAdmissionDockerGateway({
      io,
      histogram,
      foregroundSpawner: vi.fn(() => {
        throw new Error("spawn failed");
      }),
    });

    expect(() => gateway.io.capture("docker", ["container", "inspect", "x"])).toThrow("budget ended");
    expect(() => gateway.foregroundSpawner("docker", ["container", "start"], {
      env: {},
      shell: false,
      stdio: "inherit",
    })).toThrow("spawn failed");
    const snapshot = histogram.snapshot();
    expect(snapshot["docker container inspect"]?.count).toBe(1);
    expect(snapshot["docker container start"]?.count).toBe(1);
    expect(gateway.dockerOperationCount()).toBe(2);
  });

  test("does not record argv or env", () => {
    const io = runtimeIo();
    const histogram = createOperationHistogram();
    const proxyId = "a".repeat(64);
    const gateway = createSessionAdmissionDockerGateway({
      io,
      histogram,
      foregroundSpawner: vi.fn(() => ({} as SessionContainerForegroundChild)),
    });

    gateway.io.capture("docker", ["exec", "--user", "0:0", "-i", proxyId, "node", "-e", "secret-script"], {
      env: { RUNFREE_SECRET: "token-value" },
    });

    const serialized = JSON.stringify(histogram.snapshot()) + histogram.lines().join("\n");
    for (const forbidden of ["node", "-e", proxyId, "secret-script", "token-value", "RUNFREE_SECRET"]) {
      expect(serialized).not.toContain(forbidden);
    }
  });
  test("counts and records a Docker captureAsync call once, over its whole run", async () => {
    const io = runtimeIo();
    const captureAsync = vi.fn(async () => {
      await new Promise((resolve) => setTimeout(resolve, 20));
      return { status: 0, stdout: "x", stderr: "" };
    });
    io.captureAsync = captureAsync;
    const histogram = createOperationHistogram();
    const gateway = createSessionAdmissionDockerGateway({
      io,
      histogram,
      foregroundSpawner: vi.fn(() => ({} as SessionContainerForegroundChild)),
    });

    const pending = gateway.io.captureAsync?.("docker", ["container", "inspect", "x"], { timeout: 5 });
    // Counted when the call starts, not when it settles.
    expect(gateway.dockerOperationCount()).toBe(1);
    await expect(pending).resolves.toEqual({ status: 0, stdout: "x", stderr: "" });
    await gateway.io.captureAsync?.("git", ["status"]);
    expect(captureAsync).toHaveBeenCalledWith("docker", ["container", "inspect", "x"], { timeout: 5 });
    expect(captureAsync).toHaveBeenCalledWith("git", ["status"], undefined);
    expect(gateway.dockerOperationCount()).toBe(1);
    const bucket = histogram.snapshot()["docker container inspect"];
    expect(bucket?.count).toBe(1);
    expect(bucket?.totalMs).toBeGreaterThanOrEqual(15);
  });

  test("a rejected Docker captureAsync call is counted and recorded once", async () => {
    const io = runtimeIo();
    io.captureAsync = vi.fn(async () => { throw new Error("budget ended"); });
    const histogram = createOperationHistogram();
    const gateway = createSessionAdmissionDockerGateway({
      io,
      histogram,
      foregroundSpawner: vi.fn(() => ({} as SessionContainerForegroundChild)),
    });
    await expect(gateway.io.captureAsync?.("docker", ["ps"])).rejects.toThrow("budget ended");
    expect(gateway.dockerOperationCount()).toBe(1);
    expect(histogram.snapshot()["docker ps"]?.count).toBe(1);
  });

  test("exposes no captureAsync when the inner IO has none", () => {
    const gateway = createSessionAdmissionDockerGateway({
      io: runtimeIo(),
      foregroundSpawner: vi.fn(() => ({} as SessionContainerForegroundChild)),
    });
    expect("captureAsync" in gateway.io).toBe(false);
  });
});
