import { beforeEach, describe, expect, test } from "vitest";

import { captureDockerListing, dockerListingLabel, renderDockerListing } from "./docker-listing.ts";
import type { CaptureResult, RuntimeIO } from "./types.ts";
import { flushWarnings, pendingWarningsForTest } from "../warnings.ts";

function io(result: CaptureResult, seen: string[][] = []): RuntimeIO {
  return {
    capture(command, args) {
      expect(command).toBe("docker");
      seen.push(args);
      return result;
    },
    run: () => { throw new Error("listings must not mutate Docker state"); },
    commandExists: () => true,
    confirm: () => true,
    admin: async () => { throw new Error("listings must not sync credentials"); },
  };
}

beforeEach(() => flushWarnings());

describe("captureDockerListing", () => {
  test("appends the JSON format and parses one object per line", () => {
    const seen: string[][] = [];
    const listing = captureDockerListing(io({
      status: 0,
      stdout: [
        JSON.stringify({ Names: "a", Status: "Up 2 minutes", Ports: "127.0.0.1:3000->8080/tcp, [::1]:3000->8080/tcp" }),
        JSON.stringify({ Names: "b", Status: "Exited (0)", Ports: "" }),
        "",
      ].join("\n"),
      stderr: "",
    }, seen), ["ps", "-a", "--filter", "name=^/a$"], {}, "containers");
    expect(seen).toEqual([["ps", "-a", "--filter", "name=^/a$", "--format", "{{json .}}"]]);
    expect(listing).toEqual({
      status: 0,
      rows: [
        { Names: "a", Status: "Up 2 minutes", Ports: "127.0.0.1:3000->8080/tcp, [::1]:3000->8080/tcp" },
        { Names: "b", Status: "Exited (0)", Ports: "" },
      ],
    });
    expect(pendingWarningsForTest()).toEqual([]);
  });

  test("an empty listing is zero rows, not an error", () => {
    expect(captureDockerListing(io({ status: 0, stdout: "\n", stderr: "" }), ["network", "ls"], {}, "networks"))
      .toEqual({ status: 0, rows: [] });
  });

  test("a failed docker command warns with its stderr and returns its status", () => {
    const listing = captureDockerListing(io({ status: 1, stdout: "", stderr: "permission denied\n" }), ["ps"], {}, "containers");
    expect(listing).toEqual({ status: 1, rows: [] });
    expect(pendingWarningsForTest().map((event) => event.message)).toEqual(["could not list Docker containers: permission denied"]);
  });

  test("a line that is not a JSON object fails closed instead of rendering a partial table", () => {
    const listing = captureDockerListing(io({
      status: 0,
      stdout: `${JSON.stringify({ Names: "a" })}\nnot json\n`,
      stderr: "",
    }), ["ps"], {}, "containers");
    expect(listing).toEqual({ status: 1, rows: [] });
    expect(pendingWarningsForTest().map((event) => event.message))
      .toEqual(["could not parse Docker containers listing: line 2 is not a JSON object"]);
  });

  test("a JSON array or scalar line is rejected the same way", () => {
    expect(captureDockerListing(io({ status: 0, stdout: "[1]\n", stderr: "" }), ["ps"], {}, "containers").status).toBe(1);
    expect(captureDockerListing(io({ status: 0, stdout: "null\n", stderr: "" }), ["ps"], {}, "containers").status).toBe(1);
  });

  test("non-string field values are stringified so every cell is text", () => {
    const listing = captureDockerListing(io({ status: 0, stdout: '{"Names":"a","Size":12,"Labels":null}\n', stderr: "" }), ["ps"], {}, "containers");
    expect(listing.rows).toEqual([{ Names: "a", Size: "12", Labels: "" }]);
  });
});

describe("dockerListingLabel", () => {
  test("reads one label out of the comma-joined Labels field", () => {
    const row = { Labels: "com.docker.compose.service=proxy,io.runfree.runtime-digest=sha256:abc,com.docker.compose.project.config_files=a.yml,b.yml" };
    expect(dockerListingLabel(row, "com.docker.compose.service")).toBe("proxy");
    expect(dockerListingLabel(row, "io.runfree.runtime-digest")).toBe("sha256:abc");
    expect(dockerListingLabel(row, "missing")).toBeUndefined();
  });

  test("tolerates an absent or empty Labels field", () => {
    expect(dockerListingLabel({}, "x")).toBeUndefined();
    expect(dockerListingLabel({ Labels: "" }, "x")).toBeUndefined();
  });
});

describe("renderDockerListing", () => {
  test("renders selected fields through the shared terminal table", () => {
    const table = renderDockerListing(
      [
        { label: "NAME", value: (row) => row.Names },
        { label: "STATUS", value: (row) => row.Status },
        { label: "SERVICE", value: (row) => dockerListingLabel(row, "com.docker.compose.service") ?? "-" },
      ],
      [
        { Names: "proj-proxy-1", Status: "Up 2 minutes", Labels: "com.docker.compose.service=proxy" },
        { Names: "x", Status: "Exited (0)", Labels: "" },
      ],
    );
    expect(table).toBe([
      "NAME          STATUS        SERVICE",
      "proj-proxy-1  Up 2 minutes  proxy",
      "x             Exited (0)    -",
    ].join("\n"));
  });
});
