import { describe, expect, it } from "vitest";

import { matchDockerApiRoute } from "./routes.ts";

const ID = "a".repeat(64);
const route = (args: string[], hasInput = false) => matchDockerApiRoute(args, { hasInput });

describe("matchDockerApiRoute", () => {
  it.each([
    [["container", "inspect", ID], { kind: "inspect", object: "container", refs: [ID], template: "raw" }],
    [["container", "inspect", "runfree-x-proxy-1", ID], { kind: "inspect", object: "container", refs: ["runfree-x-proxy-1", ID], template: "raw" }],
    [["container", "inspect", "--format", "{{.Id}}", ID], { kind: "inspect", object: "container", refs: [ID], template: "id" }],
    [["container", "inspect", "--format", "{{.State.Running}}", ID], { kind: "inspect", object: "container", refs: [ID], template: "state-running" }],
    [["inspect", ID, "proxy"], { kind: "inspect", object: "container", refs: [ID, "proxy"], template: "raw", typeless: true }],
    [["image", "inspect", "runfree/agent:1.2", `sha256:${"b".repeat(64)}`], { kind: "inspect", object: "image", refs: ["runfree/agent:1.2", `sha256:${"b".repeat(64)}`], template: "raw" }],
    [["image", "inspect", "--format", "{{.Id}}", `ghcr.io/x/y@sha256:${"c".repeat(64)}`], { kind: "inspect", object: "image", refs: [`ghcr.io/x/y@sha256:${"c".repeat(64)}`], template: "id" }],
    [["network", "inspect", "runfree_x_internal"], { kind: "inspect", object: "network", refs: ["runfree_x_internal"], template: "raw" }],
    [["volume", "inspect", "v1", "v2"], { kind: "inspect", object: "volume", refs: ["v1", "v2"], template: "raw" }],
  ])("routes %j", (args, expected) => {
    expect(route(args)).toEqual(expected);
  });

  it("routes quiet container listings with label, name, id, and network filters", () => {
    expect(route(["ps", "-aq", "--no-trunc", "--filter", "label=a=b", "--filter", "label=c", "--filter", "name=^x$"]))
      .toEqual({ kind: "ps", all: true, noTrunc: true, filters: { label: ["a=b", "c"], name: ["^x$"] } });
    expect(route(["ps", "--all", "--quiet", "--filter", `id=${ID}`])).toEqual({ kind: "ps", all: true, noTrunc: false, filters: { id: [ID] } });
    expect(route(["container", "ls", "-q"])).toEqual({ kind: "ps", all: false, noTrunc: false, filters: {} });
  });

  it("routes the non-TTY exec shapes with an exact container id", () => {
    expect(route(["exec", "--user", "0:0", "-i", ID, "node", "-e", "s", "a1"], true))
      .toEqual({ kind: "exec", user: "0:0", interactive: true, containerId: ID, cmd: ["node", "-e", "s", "a1"] });
    expect(route(["exec", ID, "sh", "-c", "cat x"])).toEqual({ kind: "exec", interactive: false, containerId: ID, cmd: ["sh", "-c", "cat x"] });
    expect(route(["exec", "-i", "--user", "1000:1000", ID, "true"])).toEqual({ kind: "exec", user: "1000:1000", interactive: true, containerId: ID, cmd: ["true"] });
    // Everything after the container is the command, flags included.
    expect(route(["exec", ID, "ls", "-t", "--user", "x"])).toMatchObject({ cmd: ["ls", "-t", "--user", "x"] });
  });

  it.each([
    [["container", "create", "x"]],
    [["run", "--rm", "img"]],
    [["compose", "ps"]],
    [["start", ID]],
    [["rm", "-f", ID]],
    [["info"]],
    [["network", "ls", "-q"]],
    [["container", "inspect"]],
    [["container", "inspect", "--size", ID]],
    [["container", "inspect", "-f", "{{.Id}}", ID]],
    [["container", "inspect", "--format={{.Id}}", ID]],
    [["container", "inspect", "--format", "{{json .Config.Labels}}", ID]],
    [["container", "inspect", "--format", "{{ .State.Running }}", ID]],
    [["inspect", "--type", "container", ID]],
    [["inspect", "--format", "{{.Id}}", ID]],
    [["image", "inspect", "--format", "{{.State.Running}}", "img"]],
    [["network", "inspect", "--format", "{{.Id}}", "n"]],
    [["network", "inspect", "--verbose", "n"]],
    [["container", "inspect", "../../images/x"]],
    [["container", "inspect", "x/y"]],
    [["container", "inspect", "x?force=1"]],
    [["container", "inspect", "x#y"]],
    [["container", "inspect", "-x"]],
    [["container", "inspect", "x%2F"]],
    [["image", "inspect", "a/../b"]],
    [["image", "inspect", "a//b"]],
    [["image", "inspect", "a?b"]],
    [["image", "inspect", "a b"]],
    [["volume", "inspect", ""]],
    [["ps"]],
    [["ps", "-a"]],
    [["ps", "-aq", "--format", "{{.ID}}"]],
    [["ps", "-aq", "--filter", "status=running"]],
    [["ps", "-aq", "--filter", "label"]],
    [["ps", "-aq", "--filter"]],
    [["ps", "-aq", "--filter", "label= a"]],
    [["ps", "-aq", "--filter", "Label=a"]],
    [["ps", "-aq", "--filter=label=a"]],
    [["ps", "-aq", "-n", "1"]],
    [["ps", "-aq", "--last", "1"]],
    [["ps", "-aq", "--size"]],
    [["exec", "-t", ID, "sh"]],
    [["exec", "-it", ID, "sh"]],
    [["exec", "-d", ID, "sh"]],
    [["exec", "-e", "A=1", ID, "sh"]],
    [["exec", "-w", "/", ID, "sh"]],
    [["exec", "--privileged", ID, "sh"]],
    [["exec", "-u", "0", ID, "sh"]],
    [["exec", "--user", "root", ID, "sh"]],
    [["exec", "--user", "0:0", "--user", "0:0", ID, "sh"]],
    [["exec", "--user=0:0", ID, "sh"]],
    [["exec", "runfree-x-proxy-1", "sh"]],
    [["exec", ID.slice(0, 12), "sh"]],
    [["exec", ID.toUpperCase(), "sh"]],
    [["exec", ID]],
    [["exec", ID, "sh", "a\u0000b"]],
  ])("leaves %j on the CLI", (args) => {
    expect(route(args)).toBeUndefined();
  });

  it("leaves input-bearing calls on the CLI unless they are an interactive exec", () => {
    expect(route(["exec", ID, "cat"], true)).toBeUndefined();
    expect(route(["container", "inspect", ID], true)).toBeUndefined();
    expect(route(["exec", "-i", ID, "cat"], true)).toMatchObject({ kind: "exec", interactive: true });
  });
});
