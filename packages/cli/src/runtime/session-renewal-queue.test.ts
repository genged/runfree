import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, expect, test, vi } from "vitest";
import { enqueueSessionRenewal, sessionRenewalQueueHead, SESSION_RENEWAL_WAIT_BUDGET_MS } from "./session-renewal-queue.ts";

const owner = vi.hoisted(() => ({ state: "alive" as "alive" | "unknown" | "dead" }));
vi.mock("./session-record-liveness.ts", () => ({ sessionRecordOwnerLiveness: () => owner.state }));
const roots: string[] = [];
function root(): string { const value = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-renewal-queue-")); roots.push(value); return value; }
afterEach(() => { for (const directory of roots.splice(0)) fs.rmSync(directory, { recursive: true, force: true }); });

test.each(["alive", "unknown"] as const)("clock steps cannot discard a queued %s owner's priority", (liveness) => {
  owner.state = liveness;
  const stateDir = root();
  const now = Date.now();
  const renewal = enqueueSessionRenewal(stateDir, now);
  const file = path.join(stateDir, "session-renewal-queue", renewal.ticket);
  const before = fs.readFileSync(file, "utf8");
  for (const observed of [now - 60_000, now + 86_400_000, now + SESSION_RENEWAL_WAIT_BUDGET_MS]) {
    expect(sessionRenewalQueueHead(stateDir, observed)).toBe(renewal.ticket);
    expect(fs.readFileSync(file, "utf8")).toBe(before);
  }
  // The requesting manager's cancellation/deadline path explicitly releases
  // its exact ticket, without interpreting a clock adjustment as owner death.
  renewal.release();
  expect(sessionRenewalQueueHead(stateDir, now)).toBeUndefined();
});

test("a crashed request is reclaimed only with dead-owner evidence, allowing the next renewal", () => {
  owner.state = "dead";
  const stateDir = root();
  const now = Date.now();
  const crashed = enqueueSessionRenewal(stateDir, now - SESSION_RENEWAL_WAIT_BUDGET_MS);
  const next = enqueueSessionRenewal(stateDir, now);
  expect(sessionRenewalQueueHead(stateDir, now)).toBe(next.ticket);
  expect(fs.existsSync(path.join(stateDir, "session-renewal-queue", crashed.ticket))).toBe(false);
  next.release();
  expect(sessionRenewalQueueHead(stateDir, now)).toBeUndefined();
});

test("invalid ticket identity refuses acquisition until its exact host entry is repaired", () => {
  const stateDir = root();
  const now = Date.now();
  const renewal = enqueueSessionRenewal(stateDir, now);
  const file = path.join(stateDir, "session-renewal-queue", renewal.ticket);
  const original = fs.readFileSync(file, "utf8");
  fs.writeFileSync(file, JSON.stringify({ ticket: renewal.ticket, hostPid: 0 }));
  expect(() => sessionRenewalQueueHead(stateDir, now)).toThrow("repair the host scheduling entry");
  expect(fs.existsSync(file)).toBe(true);
  fs.writeFileSync(file, original);
  expect(sessionRenewalQueueHead(stateDir, now)).toBe(renewal.ticket);
  renewal.release();
});
