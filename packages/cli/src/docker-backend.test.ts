import type childProcess from "node:child_process";

import { describe, expect, test } from "vitest";

import {
  classifyDockerBackend,
  composeProfilesFor,
  detectDockerBackend,
  hostServiceRelayModeFor,
  HOST_SERVICE_BACKEND_REFUSAL,
  parseDockerBackendInfo,
  type DockerBackendHost,
  type DockerBackendInfo,
} from "./docker-backend.ts";
import type { CaptureResult } from "./runtime/types.ts";

const linuxHost: DockerBackendHost = { platform: "linux", hostname: "builder", kernelRelease: "6.12.94+" };
const engineInfo: DockerBackendInfo = { operatingSystem: "Debian GNU/Linux 13 (trixie)", name: "builder", kernelVersion: "6.12.94+", rootless: false };
const desktopInfo: DockerBackendInfo = { operatingSystem: "Docker Desktop", name: "docker-desktop", kernelVersion: "6.10.14-linuxkit", rootless: false };

describe("classifyDockerBackend (C5)", () => {
  test("a local Docker Desktop is docker-desktop on any platform, with no relay", () => {
    for (const [platform, endpoint] of [
      ["darwin", "unix:///Users/me/.docker/run/docker.sock"],
      ["linux", "unix:///home/me/.docker/desktop/docker.sock"],
      ["win32", "npipe:////./pipe/dockerDesktopLinuxEngine"],
    ] as const) {
      const backend = classifyDockerBackend(desktopInfo, endpoint, { ...linuxHost, platform });
      expect(backend).toEqual({ kind: "docker-desktop" });
      expect(hostServiceRelayModeFor(backend)).toBe("none");
    }
  });

  test.each([
    ["a remote Docker Desktop over TCP", "tcp://10.0.0.5:2376", "is not a local socket"],
    ["a remote Docker Desktop over SSH", "ssh://me@mac.example", "is not a local socket"],
    ["a Docker Desktop on a remote named pipe", "npipe:////build-host/pipe/docker_engine", "is not a local socket"],
    ["a Docker Desktop with an unreadable endpoint", undefined, "could not be read"],
  ])("%s is unsupported with the clear message", (_label, endpoint, detail) => {
    for (const platform of ["darwin", "linux"] as const) {
      const backend = classifyDockerBackend(desktopInfo, endpoint, { ...linuxHost, platform });
      expect(backend.kind).toBe("unsupported");
      expect(backend.kind === "unsupported" ? backend.reason : "").toContain(HOST_SERVICE_BACKEND_REFUSAL);
      expect(backend.kind === "unsupported" ? backend.reason : "").toContain(detail);
      expect(hostServiceRelayModeFor(backend)).toBe("none");
    }
  });

  test("a local Engine on Linux is docker-engine, with the relay", () => {
    const backend = classifyDockerBackend(engineInfo, "unix:///var/run/docker.sock", linuxHost);
    expect(backend).toEqual({ kind: "docker-engine" });
    expect(hostServiceRelayModeFor(backend)).toBe("engine-relay");
    expect(composeProfilesFor("engine-relay")).toBe("host-relay");
    expect(composeProfilesFor("none")).toBe("");
  });

  test.each([
    ["OrbStack on macOS", { ...engineInfo, operatingSystem: "OrbStack", name: "orbstack" }, "unix:///Users/me/.orbstack/run/docker.sock", { ...linuxHost, platform: "darwin" as const }, "not Docker Desktop"],
    ["Colima on macOS", { ...engineInfo, operatingSystem: "Ubuntu 24.04 LTS", name: "colima" }, "unix:///Users/me/.colima/default/docker.sock", { ...linuxHost, platform: "darwin" as const }, "not Docker Desktop"],
    ["a remote daemon over TCP", engineInfo, "tcp://10.0.0.5:2376", linuxHost, "not a local unix socket"],
    ["a remote daemon over SSH", engineInfo, "ssh://builder@remote", linuxHost, "not a local unix socket"],
    ["an unreadable endpoint", engineInfo, undefined, linuxHost, "could not be read"],
    ["rootless Docker", { ...engineInfo, rootless: true }, "unix:///run/user/1000/docker.sock", linuxHost, "rootless"],
    ["a daemon in a VM on a local socket", { ...engineInfo, name: "colima" }, "unix:///home/me/.colima/docker.sock", linuxHost, "not this host"],
    ["a daemon on another kernel", { ...engineInfo, kernelVersion: "6.1.0" }, "unix:///var/run/docker.sock", linuxHost, "not this host"],
  ])("%s is unsupported with the clear message", (_label, info, endpoint, host, detail) => {
    const backend = classifyDockerBackend(info, endpoint, host);
    expect(backend.kind).toBe("unsupported");
    expect(backend.kind === "unsupported" ? backend.reason : "").toContain(HOST_SERVICE_BACKEND_REFUSAL);
    expect(backend.kind === "unsupported" ? backend.reason : "").toContain(detail);
    expect(hostServiceRelayModeFor(backend)).toBe("none");
  });

  test("no daemon identity is unsupported, never guessed", () => {
    expect(classifyDockerBackend(undefined, "unix:///var/run/docker.sock", linuxHost)).toMatchObject({ kind: "unsupported" });
  });
});

describe("parseDockerBackendInfo", () => {
  test("reads the operating system, name, kernel, and the rootless security option", () => {
    expect(parseDockerBackendInfo(JSON.stringify({
      OperatingSystem: "Ubuntu 24.04 LTS",
      Name: "host",
      KernelVersion: "6.8.0",
      SecurityOptions: ["name=seccomp,profile=builtin", "name=rootless", "name=cgroupns"],
    }))).toEqual({ operatingSystem: "Ubuntu 24.04 LTS", name: "host", kernelVersion: "6.8.0", rootless: true });
  });

  test.each([["not json"], [JSON.stringify([])], [JSON.stringify({ Name: "x", KernelVersion: "1" })], [JSON.stringify({ OperatingSystem: "x", Name: "y", KernelVersion: "z", SecurityOptions: "bad" })]])(
    "malformed info is undefined: %s",
    (stdout) => {
      expect(parseDockerBackendInfo(stdout)).toBeUndefined();
    },
  );
});

describe("detectDockerBackend", () => {
  function io(results: Record<string, CaptureResult>): { capture: (command: string, args: string[], options?: childProcess.SpawnSyncOptions) => CaptureResult; calls: string[][] } {
    const calls: string[][] = [];
    return {
      calls,
      capture: (_command, args) => {
        calls.push(args);
        return results[args[0] ?? ""] ?? { status: 1, stdout: "", stderr: "unexpected" };
      },
    };
  }
  const info = (value: Record<string, unknown>): CaptureResult => ({ status: 0, stdout: JSON.stringify(value), stderr: "" });

  test("Desktop reads the current context endpoint and is docker-desktop only on a local socket", () => {
    const fake = io({
      info: info({ OperatingSystem: "Docker Desktop", Name: "docker-desktop", KernelVersion: "6.10" }),
      context: { status: 0, stdout: "\"unix:///Users/me/.docker/run/docker.sock\"\n", stderr: "" },
    });
    expect(detectDockerBackend({ env: {} }, fake, { platform: "darwin", host: linuxHost })).toEqual({ kind: "docker-desktop" });
    expect(fake.calls).toEqual([["info", "--format", "{{json .}}"], ["context", "inspect", "--format", "{{json .Endpoints.docker.Host}}"]]);
  });

  test.each([["tcp://10.0.0.5:2376"], ["ssh://me@mac.example"]])("a remote Desktop through DOCKER_HOST %s is unsupported", (dockerHost) => {
    const fake = io({ info: info({ OperatingSystem: "Docker Desktop", Name: "docker-desktop", KernelVersion: "6.10" }) });
    const backend = detectDockerBackend({ env: { DOCKER_HOST: dockerHost } }, fake, { platform: "darwin", host: linuxHost });
    expect(backend).toMatchObject({ kind: "unsupported" });
    expect(backend.kind === "unsupported" ? backend.reason : "").toContain(HOST_SERVICE_BACKEND_REFUSAL);
    expect(fake.calls).toHaveLength(1);
  });

  test("Engine on Linux reads the current context endpoint", () => {
    const fake = io({
      info: info({ OperatingSystem: "Debian", Name: "builder", KernelVersion: "6.12.94+" }),
      context: { status: 0, stdout: "\"unix:///var/run/docker.sock\"\n", stderr: "" },
    });
    expect(detectDockerBackend({ env: {} }, fake, { platform: "linux", host: linuxHost })).toEqual({ kind: "docker-engine" });
    expect(fake.calls[1]).toEqual(["context", "inspect", "--format", "{{json .Endpoints.docker.Host}}"]);
  });

  test("DOCKER_HOST decides the endpoint without a context read", () => {
    const fake = io({ info: info({ OperatingSystem: "Debian", Name: "builder", KernelVersion: "6.12.94+" }) });
    expect(detectDockerBackend({ env: { DOCKER_HOST: "tcp://10.0.0.5:2375" } }, fake, { platform: "linux", host: linuxHost }))
      .toMatchObject({ kind: "unsupported" });
    expect(fake.calls).toHaveLength(1);
  });

  test("a supplied info answer is reused, and a failed info call is unsupported", () => {
    const reused = io({});
    expect(detectDockerBackend({ env: { DOCKER_HOST: "unix:///var/run/docker.sock" } }, reused, {
      platform: "darwin",
      host: linuxHost,
      infoStdout: JSON.stringify({ OperatingSystem: "Docker Desktop", Name: "docker-desktop", KernelVersion: "6" }),
    })).toEqual({ kind: "docker-desktop" });
    expect(reused.calls).toEqual([]);
    expect(detectDockerBackend({ env: {} }, io({}), { platform: "linux", host: linuxHost })).toMatchObject({ kind: "unsupported" });
  });
});
