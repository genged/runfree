import path from "node:path";

import { describe, expect, it } from "vitest";

import {
  dockerContextMetaPath,
  type DockerEndpointFs,
  parseUnixDockerHost,
  resolveDockerEndpoint,
} from "./docker-endpoint.ts";

const HOME = "/home/u";
const CONFIG_DIR = path.join(HOME, ".docker");

function fakeFs(files: Record<string, string>, dirs: readonly string[] = []): DockerEndpointFs {
  return {
    readFile: (filePath) => files[filePath],
    exists: (filePath) => filePath in files || dirs.includes(filePath),
    passwdHome: () => "/home/passwd",
  };
}

function contextMeta(name: string, host: string, extra: Record<string, unknown> = {}, configDir = CONFIG_DIR): Record<string, string> {
  return {
    [dockerContextMetaPath(configDir, name)]: JSON.stringify({ Name: name, Metadata: {}, Endpoints: { docker: { Host: host, SkipTLSVerify: false, ...extra } } }),
  };
}

describe("resolveDockerEndpoint", () => {
  it("uses a unix DOCKER_HOST as is", () => {
    expect(resolveDockerEndpoint({ HOME, DOCKER_HOST: "unix:///x.sock" }, fakeFs({}))).toEqual({ kind: "unix", socketPath: "/x.sock", context: "default" });
  });

  it.each([
    ["tcp://127.0.0.1:2375"],
    ["ssh://user@host"],
    ["fd://"],
    ["npipe:////./pipe/docker_engine"],
    ["unix://relative.sock"],
    ["unix:///a/../b.sock"],
    ["unix:///a//b.sock"],
    [" unix:///x.sock"],
    ["unix:///x.sock?x=1"],
  ])("falls back to the CLI for DOCKER_HOST=%s", (host) => {
    expect(resolveDockerEndpoint({ HOME, DOCKER_HOST: host }, fakeFs({})).kind).toBe("cli");
  });

  it.each(["DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "DOCKER_API_VERSION", "DOCKER_CUSTOM_HEADERS"])("falls back to the CLI when %s is set", (name) => {
    const fsx = fakeFs({}, ["/var/run/docker.sock"]);
    fsx.exists = () => true;
    expect(resolveDockerEndpoint({ HOME, DOCKER_HOST: "unix:///x.sock", [name]: "1" }, fsx).kind).toBe("cli");
  });

  it("falls back to the CLI when DOCKER_HOST and DOCKER_CONTEXT are both set", () => {
    const fsx = fakeFs(contextMeta("orb", "unix:///orb.sock"));
    expect(resolveDockerEndpoint({ HOME, DOCKER_HOST: "unix:///x.sock", DOCKER_CONTEXT: "orb" }, fsx))
      .toEqual({ kind: "cli", reason: "DOCKER_HOST and DOCKER_CONTEXT are both set" });
  });

  it("reads DOCKER_CONTEXT from the context store under DOCKER_CONFIG", () => {
    const fsx = fakeFs(contextMeta("desktop-linux", "unix:///Users/u/.docker/run/docker.sock", {}, "/cfg"));
    expect(resolveDockerEndpoint({ DOCKER_CONFIG: "/cfg", DOCKER_CONTEXT: "desktop-linux" }, fsx))
      .toEqual({ kind: "unix", socketPath: "/Users/u/.docker/run/docker.sock", context: "desktop-linux" });
  });

  it("reads currentContext from config.json", () => {
    const fsx = fakeFs({
      [path.join(CONFIG_DIR, "config.json")]: JSON.stringify({ currentContext: "orbstack" }),
      ...contextMeta("orbstack", "unix:///home/u/.orbstack/run/docker.sock"),
    });
    expect(resolveDockerEndpoint({ HOME }, fsx)).toEqual({ kind: "unix", socketPath: "/home/u/.orbstack/run/docker.sock", context: "orbstack" });
  });

  it("uses the passwd home when HOME is unset, as the CLI does", () => {
    const fsx = fakeFs({
      "/home/passwd/.docker/config.json": JSON.stringify({ currentContext: "c1" }),
      ...contextMeta("c1", "unix:///c1.sock", {}, "/home/passwd/.docker"),
    });
    expect(resolveDockerEndpoint({}, fsx)).toMatchObject({ kind: "unix", socketPath: "/c1.sock" });
  });

  it("DOCKER_CONTEXT wins over config.json currentContext", () => {
    const fsx = fakeFs({
      [path.join(CONFIG_DIR, "config.json")]: JSON.stringify({ currentContext: "aa" }),
      ...contextMeta("aa", "unix:///a.sock"),
      ...contextMeta("bb", "unix:///b.sock"),
    });
    expect(resolveDockerEndpoint({ HOME, DOCKER_CONTEXT: "bb" }, fsx)).toMatchObject({ socketPath: "/b.sock" });
  });

  it.each([
    ["missing", {}, "Docker context x1 has no metadata"],
    ["malformed", { [dockerContextMetaPath(CONFIG_DIR, "x1")]: "{nope" }, "is malformed"],
    ["not an object", { [dockerContextMetaPath(CONFIG_DIR, "x1")]: "[]" }, "is not a JSON object"],
    ["naming another context", { [dockerContextMetaPath(CONFIG_DIR, "x1")]: JSON.stringify({ Name: "x2", Endpoints: { docker: { Host: "unix:///x.sock" } } }) }, "metadata names another context"],
    ["without a docker endpoint", { [dockerContextMetaPath(CONFIG_DIR, "x1")]: JSON.stringify({ Name: "x1", Endpoints: {} }) }, "Docker context has no docker endpoint"],
    ["with a tcp host", contextMeta("x1", "tcp://1.2.3.4:2376"), "Docker context endpoint is not a unix socket"],
    ["with an ssh host", contextMeta("x1", "ssh://me@box"), "Docker context endpoint is not a unix socket"],
    ["with SkipTLSVerify", contextMeta("x1", "unix:///x.sock", { SkipTLSVerify: true }), "Docker context sets SkipTLSVerify"],
  ])("falls back to the CLI for context metadata %s", (_label, files, reason) => {
    const resolved = resolveDockerEndpoint({ HOME, DOCKER_CONTEXT: "x1" }, fakeFs(files));
    expect(resolved).toEqual({ kind: "cli", reason: expect.stringContaining(reason) });
  });

  it("allows an empty HttpHeaders object in config.json", () => {
    const fsx = fakeFs({ [path.join(CONFIG_DIR, "config.json")]: JSON.stringify({ HttpHeaders: {} }) }, ["/var/run/docker.sock"]);
    expect(resolveDockerEndpoint({ HOME }, fsx)).toEqual({ kind: "unix", socketPath: "/var/run/docker.sock", context: "default" });
  });

  it("falls back to the CLI when the context has TLS material", () => {
    const tlsDir = path.join(path.dirname(path.dirname(path.dirname(dockerContextMetaPath(CONFIG_DIR, "x1")))), "tls",
      path.basename(path.dirname(dockerContextMetaPath(CONFIG_DIR, "x1"))));
    expect(resolveDockerEndpoint({ HOME, DOCKER_CONTEXT: "x1" }, fakeFs(contextMeta("x1", "unix:///x.sock"), [tlsDir])).kind).toBe("cli");
  });

  it("falls back to the CLI for an invalid context name", () => {
    expect(resolveDockerEndpoint({ HOME, DOCKER_CONTEXT: "../x" }, fakeFs({})).kind).toBe("cli");
  });

  it("uses /var/run/docker.sock for the default context only when it exists", () => {
    expect(resolveDockerEndpoint({ HOME }, fakeFs({}, ["/var/run/docker.sock"])))
      .toEqual({ kind: "unix", socketPath: "/var/run/docker.sock", context: "default" });
    expect(resolveDockerEndpoint({ HOME }, fakeFs({})).kind).toBe("cli");
    expect(resolveDockerEndpoint({ HOME, DOCKER_CONTEXT: "default" }, fakeFs({}, ["/var/run/docker.sock"])).kind).toBe("unix");
  });

  it.each([
    ["malformed", "{"],
    ["not an object", "42"],
    ["with HttpHeaders", JSON.stringify({ HttpHeaders: { "X-Meta": "1" } })],
    ["with a non-string currentContext", JSON.stringify({ currentContext: 3 })],
  ])("falls back to the CLI for a config.json %s", (_label, text) => {
    const fsx = fakeFs({ [path.join(CONFIG_DIR, "config.json")]: text }, ["/var/run/docker.sock"]);
    expect(resolveDockerEndpoint({ HOME }, fsx).kind).toBe("cli");
  });

  it("falls back to the CLI when config.json cannot be read", () => {
    const fsx = fakeFs({}, ["/var/run/docker.sock"]);
    fsx.readFile = () => {
      throw new Error("EACCES");
    };
    expect(resolveDockerEndpoint({ HOME }, fsx).kind).toBe("cli");
  });

  it("falls back to the CLI for a relative DOCKER_CONFIG", () => {
    expect(resolveDockerEndpoint({ DOCKER_CONFIG: "cfg" }, fakeFs({}, ["/var/run/docker.sock"])).kind).toBe("cli");
  });

  it("reads nothing but the environment and the user's Docker config", () => {
    const read: string[] = [];
    const files = contextMeta("x1", "unix:///x.sock");
    const fsx: DockerEndpointFs = {
      readFile: (filePath) => {
        read.push(filePath);
        return files[filePath];
      },
      exists: (filePath) => {
        read.push(filePath);
        return false;
      },
      passwdHome: () => undefined,
    };
    // Reaches the end of the context path: config, metadata, and TLS probe.
    expect(resolveDockerEndpoint({ HOME, DOCKER_CONTEXT: "x1" }, fsx)).toMatchObject({ kind: "unix", socketPath: "/x.sock" });
    expect(read).toHaveLength(3);
    expect(read.every((filePath) => filePath.startsWith(`${CONFIG_DIR}/`))).toBe(true);
  });
});

describe("parseUnixDockerHost", () => {
  it("accepts only canonical absolute unix socket paths", () => {
    expect(parseUnixDockerHost("unix:///var/run/docker.sock")).toBe("/var/run/docker.sock");
    expect(parseUnixDockerHost("unix:///var/run/")).toBeUndefined();
    expect(parseUnixDockerHost("unix://")).toBeUndefined();
    expect(parseUnixDockerHost("unix:///a b.sock")).toBeUndefined();
  });
});
