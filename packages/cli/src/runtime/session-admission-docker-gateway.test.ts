import { describe, expect, test, vi } from "vitest";

import type { SessionContainerForegroundChild } from "./session-container-start.ts";
import { createSessionAdmissionDockerGateway } from "./session-admission-docker-gateway.ts";
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
});
