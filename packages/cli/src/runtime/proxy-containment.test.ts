import { expect, test, vi } from "vitest";
import { containExactOwnedProxy, observeExactProxy } from "./proxy-containment.ts";
import type { CaptureResult } from "./types.ts";

const proxyId = "a".repeat(64);
const subject = { proxyId, projectId: "b".repeat(12), composeProject: `runfree-${"b".repeat(12)}` };
const captureResult = (stdout: string, status = 0): CaptureResult => ({ status, stdout, stderr: "" });

test("failed inventory grants neither absence nor containment authority; fresh retry can contain only the exact proxy", () => {
  let available = false;
  let running = true;
  const capture = vi.fn((_command: string, args: string[]): CaptureResult => {
    if (args[0] === "ps") return captureResult(available ? proxyId : "", available ? 0 : 124);
    if (args[0] === "container") return captureResult(JSON.stringify([{ Id: proxyId, State: { Running: running }, Config: { Labels: {
      "io.runfree.project-id": subject.projectId, "io.runfree.container-role": "proxy",
      "com.docker.compose.project": subject.composeProject, "com.docker.compose.service": "proxy",
    } } }]));
    if (args[0] === "stop" && args.at(-1) === proxyId) { running = false; return captureResult(proxyId); }
    throw new Error(`unexpected effect: ${args.join(" ")}`);
  });
  const input = { ...subject, io: { capture }, assertAuthority: () => undefined };
  expect(() => containExactOwnedProxy(input)).toThrow("inventory is unavailable");
  expect(running).toBe(true);
  expect(capture).toHaveBeenCalledTimes(1);
  available = true;
  containExactOwnedProxy(input);
  expect(running).toBe(false);
  expect(capture.mock.calls.filter(([, args]) => args[0] === "stop")).toEqual([["docker", ["stop", "--time", "5", proxyId], expect.anything()]]);
  expect(capture.mock.calls.some(([, args]) => args.includes("down") || args[0] === "rm" || args[0] === "volume")).toBe(false);
});

test("successful empty inventory proves absence; fence loss never runs compensation", () => {
  const capture = vi.fn(() => captureResult(""));
  const authority = vi.fn(() => undefined);
  const input = { ...subject, io: { capture }, assertAuthority: authority };
  expect(observeExactProxy(input)).toBeUndefined();
  authority.mockImplementation(() => { throw new Error("fence lost"); });
  expect(() => containExactOwnedProxy(input)).toThrow("fence lost");
  expect(capture).toHaveBeenCalledTimes(1);
});

test("a different returned identity cannot be stopped", () => {
  const capture = vi.fn(() => captureResult("c".repeat(64)));
  expect(() => containExactOwnedProxy({ ...subject, io: { capture }, assertAuthority: () => undefined })).toThrow("another identity");
  expect(capture).toHaveBeenCalledTimes(1);
});

const ownedLabels: Record<string, string> = {
  "io.runfree.project-id": subject.projectId, "io.runfree.container-role": "proxy",
  "com.docker.compose.project": subject.composeProject, "com.docker.compose.service": "proxy",
};

test.each(Object.keys(ownedLabels))("the expected id under a foreign %s is never stopped", (label) => {
  const capture = vi.fn((_command: string, args: string[]): CaptureResult => {
    if (args[0] === "ps") return captureResult(proxyId);
    if (args[0] === "container") return captureResult(JSON.stringify([{ Id: proxyId, State: { Running: true },
      Config: { Labels: { ...ownedLabels, [label]: "someone-else" } } }]));
    throw new Error(`unexpected effect: ${args.join(" ")}`);
  });
  expect(() => containExactOwnedProxy({ ...subject, io: { capture }, assertAuthority: () => undefined })).toThrow("ownership does not match");
  expect(capture.mock.calls.some(([, args]) => args[0] === "stop")).toBe(false);
});
