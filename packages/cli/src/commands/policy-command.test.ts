import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import type { DesiredNetworkPolicyJson } from "@runfree/runtime-contracts/desired-network-policy";
import type { ControlActivationResult } from "../control/activation.ts";
import type { ControlApprovalRead } from "../control/approval-read.ts";
import type { DesiredPolicyCandidate } from "../control/candidates.ts";
import {
  type ControlStatus,
  type NetworkPolicyReview,
  type PolicyHostExplanation,
} from "../control/status.ts";
import { networkControlSubject } from "../control/subjects.ts";
import { projectInfo } from "../config.ts";
import type { RuntimeContext } from "../runtime/types.ts";
import { CliError } from "../errors.ts";
import { nodeRuntimeIO } from "../runtime.ts";
import { runCommandApp } from "./app.ts";
import type { RunfreeCommandContext } from "./context.ts";
import { formatPolicyStatusTable, type PolicyStatusRow } from "./policy.ts";

// Every mocked collaborator is a direct module-boundary import of policy.ts
// (status/workflow/activation and the host IO). Each seam records its call
// arguments and is armed per test; an unarmed call fails loudly rather than
// silently falling through to the real, filesystem-backed implementation.
// `../control/review-render.ts` is deliberately NOT mocked: the policy
// approve review body is real output a reviewer actually reads before
// consenting, so these tests exercise the genuine renderer end to end.
const seams = vi.hoisted(() => ({
  status: { calls: [] as unknown[][], impl: undefined as undefined | ((...args: unknown[]) => unknown) },
  review: { calls: [] as unknown[][], impl: undefined as undefined | ((...args: unknown[]) => unknown) },
  host: { calls: [] as unknown[][], impl: undefined as undefined | ((...args: unknown[]) => unknown) },
  approve: { calls: [] as unknown[][], impl: undefined as undefined | ((...args: unknown[]) => unknown) },
  requireUsable: { calls: [] as unknown[][], impl: undefined as undefined | ((...args: unknown[]) => unknown) },
  activate: { calls: [] as unknown[][], impl: undefined as undefined | ((...args: unknown[]) => unknown) },
  confirm: { calls: [] as unknown[][], result: true },
  isInteractive: false,
}));

function armed(seam: { calls: unknown[][]; impl: undefined | ((...args: unknown[]) => unknown) }, label: string) {
  return (...args: unknown[]) => {
    seam.calls.push(args);
    if (!seam.impl) throw new Error(`${label} seam is not armed for this test`);
    return seam.impl(...args);
  };
}

vi.mock("../control/status.ts", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../control/status.ts")>();
  return {
    ...actual,
    inspectControlStatus: armed(seams.status, "inspectControlStatus"),
    inspectNetworkPolicyReview: armed(seams.review, "inspectNetworkPolicyReview"),
    inspectPolicyHost: armed(seams.host, "inspectPolicyHost"),
  };
});

vi.mock("../control/workflow.ts", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../control/workflow.ts")>();
  return {
    ...actual,
    approveNetworkControl: armed(seams.approve, "approveNetworkControl"),
    requireUsableApprovalSelection: armed(seams.requireUsable, "requireUsableApprovalSelection"),
  };
});

vi.mock("../control/activation.ts", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../control/activation.ts")>();
  return {
    ...actual,
    activateApprovedControlsAfterMutation: armed(seams.activate, "activateApprovedControlsAfterMutation"),
  };
});

vi.mock("../runtime.ts", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../runtime.ts")>();
  return {
    ...actual,
    nodeRuntimeIO: {
      ...actual.nodeRuntimeIO,
      confirm: (...args: unknown[]) => {
        seams.confirm.calls.push(args);
        return seams.confirm.result;
      },
      isInteractive: () => seams.isInteractive,
    },
  };
});

afterEach(() => {
  for (const seam of [seams.status, seams.review, seams.host, seams.approve, seams.requireUsable, seams.activate]) {
    seam.calls.length = 0;
    seam.impl = undefined;
  }
  seams.confirm.calls.length = 0;
  seams.confirm.result = true;
  seams.isInteractive = false;
  vi.restoreAllMocks();
});

function fakeRuntimeContext(): RuntimeContext {
  return { projectRoot: "/fake/project", project: {}, runtimeRoot: "/fake/runtime", env: {} } as unknown as RuntimeContext;
}

function baseContext(overrides: Partial<RunfreeCommandContext> = {}): RunfreeCommandContext {
  const unavailable = (name: string) => () => {
    throw new Error(`${name}() must not be called`);
  };
  return {
    env: {},
    projectRoot: "/fake/project",
    commandName: "policy",
    invocationCwd: "/fake",
    assets: () => ({ runtimeDir: "/fake/runtime" }) as unknown as ReturnType<RunfreeCommandContext["assets"]>,
    templatesDir: unavailable("templatesDir"),
    projectInfo: () => ({ paths: {} }) as unknown as ReturnType<RunfreeCommandContext["projectInfo"]>,
    ensureProject: unavailable("ensureProject"),
    adminContext: unavailable("adminContext"),
    sourceAdminContext: unavailable("sourceAdminContext"),
    runtimeContext: () => fakeRuntimeContext(),
    ...overrides,
  };
}

function printedLines(spy: { mock: { calls: unknown[][] } }): string[] {
  return spy.mock.calls.map((call) => String(call[0]));
}

const neverDelegate = async (): Promise<number> => 0;

describe("runfree policy status", () => {
  test("marks only the layer/subject rows whose approved digest matches the selected one as active, and hides a valid approval record", async () => {
    const status: ControlStatus = {
      layers: {
        project: { desiredDigest: "sha256:proj-desired", approvedDigest: "sha256:proj-approved", drift: "approved" },
        local: { desiredDigest: "sha256:local-desired", approvedDigest: "sha256:local-approved", drift: "approved" },
      },
      subjects: {
        runtimeIsolation: { desiredDigest: "sha256:rt-desired", approvedDigest: "sha256:rt-approved", drift: "approved" },
        imageBuild: { drift: "absent" },
      },
      approvalRead: "valid",
      approvalSetDigest: "sha256:set",
      proxyLive: true,
      converged: {
        controlGeneration: "gen-1",
        requestProxy: { controlGeneration: "gen-1" },
        firewall: { controlGeneration: "gen-1" },
      } as ControlStatus["converged"],
      active: {
        controlGeneration: "gen-1",
        policyGeneration: "pg-1",
        selectedSubjects: {
          "network-project": "sha256:proj-approved",
          // Deliberately mismatched: the local layer is approved, but the
          // currently selected effective generation picked a different
          // digest (e.g. project was re-approved after selection). It must
          // stay "approved", not fall back to "active".
          "network-local": "sha256:some-other-selected-digest",
          "runtime-isolation": "sha256:rt-approved",
        },
      },
    };
    seams.status.impl = () => status;
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const rc = fakeRuntimeContext();

    await runCommandApp(baseContext({ runtimeContext: () => rc }), ["policy", "status"], neverDelegate);

    expect(seams.status.calls).toEqual([[rc, nodeRuntimeIO]]);
    const expectedRows: PolicyStatusRow[] = [
      { label: "project", desiredDigest: "sha256:proj-desired", approvedDigest: "sha256:proj-approved", state: "active" },
      { label: "checkout-local", desiredDigest: "sha256:local-desired", approvedDigest: "sha256:local-approved", state: "approved" },
      { label: "runtime", desiredDigest: "sha256:rt-desired", approvedDigest: "sha256:rt-approved", state: "active" },
      { label: "image", desiredDigest: undefined, approvedDigest: undefined, state: "absent" },
    ];
    const lines = printedLines(log);
    expect(lines[0]).toBe("Network policy");
    expect(lines[1]).toBe(formatPolicyStatusTable(expectedRows));
    expect(lines).toContain("approval set: sha256:set");
    expect(lines).toContain("effective policy generation: gen-1");
    expect(lines).toContain("network policy payload generation: pg-1");
    expect(lines).toContain("proxy request: gen-1");
    expect(lines).toContain("proxy firewall: gen-1 (ruleset verified)");
    expect(lines.some((line) => line.startsWith("approval record:"))).toBe(false);
    expect(lines).toHaveLength(7);
  });

  test("reports pending/invalid/absent drift rows, an unacknowledged proxy, and every optional error line for a non-valid approval record", async () => {
    const status: ControlStatus = {
      layers: {
        project: { desiredDigest: "sha256:proj2", drift: "pending" },
        local: { drift: "invalid" },
      },
      subjects: {
        runtimeIsolation: { drift: "invalid" },
        imageBuild: { drift: "absent" },
      },
      approvalRead: "corrupt",
      proxyLive: false,
      desiredError: "boom-desired",
      approvalError: "boom-approval",
      activeError: "boom-active",
      convergenceError: "boom-convergence",
    };
    seams.status.impl = () => status;
    const log = vi.spyOn(console, "log").mockImplementation(() => {});

    await runCommandApp(baseContext(), ["policy", "status"], neverDelegate);

    const expectedRows: PolicyStatusRow[] = [
      { label: "project", desiredDigest: "sha256:proj2", approvedDigest: undefined, state: "pending" },
      { label: "checkout-local", desiredDigest: undefined, approvedDigest: undefined, state: "invalid" },
      { label: "runtime", desiredDigest: undefined, approvedDigest: undefined, state: "invalid" },
      { label: "image", desiredDigest: undefined, approvedDigest: undefined, state: "absent" },
    ];
    const lines = printedLines(log);
    expect(lines[1]).toBe(formatPolicyStatusTable(expectedRows));
    expect(lines).toContain("approval set: none");
    expect(lines).toContain("effective policy generation: none");
    expect(lines).toContain("proxy request: unacknowledged");
    expect(lines).toContain("proxy firewall: unacknowledged");
    expect(lines).not.toContain("proxy firewall: unacknowledged (ruleset verified)");
    expect(lines).toContain("desired error: boom-desired");
    expect(lines).toContain("approval record: corrupt");
    expect(lines).toContain("approval error: boom-approval");
    expect(lines).toContain("effective error: boom-active");
    expect(lines).toContain("convergence error: boom-convergence");
    expect(lines.some((line) => line.startsWith("network policy payload generation:"))).toBe(false);
  });

  test("suppresses the approval record line for a 'missing' record, same as a 'valid' one", async () => {
    const status: ControlStatus = {
      layers: {
        project: { drift: "absent" },
        local: { drift: "absent" },
      },
      subjects: {
        runtimeIsolation: { drift: "absent" },
        imageBuild: { drift: "absent" },
      },
      approvalRead: "missing",
      proxyLive: false,
    };
    seams.status.impl = () => status;
    const log = vi.spyOn(console, "log").mockImplementation(() => {});

    await runCommandApp(baseContext(), ["policy", "status"], neverDelegate);

    const lines = printedLines(log);
    expect(lines.some((line) => line.startsWith("approval record:"))).toBe(false);
    expect(lines.some((line) => line.startsWith("approval error:"))).toBe(false);
    expect(lines).toContain("approval set: none");
    expect(lines).toContain("proxy request: unacknowledged");
    expect(lines).toContain("proxy firewall: unacknowledged");
  });
});

describe("runfree policy explain", () => {
  test("renders allowlisted host semantics, defaults, approvals, and pending changes", async () => {
    const explanation: PolicyHostExplanation = {
      host: "example.com",
      desired: {
        allowlisted: true,
        hostSources: ["project:policy"],
        requestRule: { methods: ["GET", "POST"], pathPrefixes: ["/api"], gitPush: "write", graphql: { endpoints: ["/graphql"], writeOps: "mutation" } },
        requestSource: "project:policy",
        writeAction: "ask",
        credentials: ["TOKEN_A"],
      },
      effective: {
        allowlisted: false,
        hostSources: [],
        writeAction: "deny",
        credentials: [],
      },
      approvals: { project: { digest: "sha256:p", mechanism: "interactive", approvedAt: "2026-01-01T00:00:00.000Z" } },
      effectiveApprovals: { local: { digest: "sha256:l", mechanism: "digest-command" } },
      pendingChanges: ["host semantics are newly desired"],
    };
    seams.host.impl = () => explanation;
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const rc = fakeRuntimeContext();

    await runCommandApp(baseContext({ runtimeContext: () => rc }), ["policy", "explain", "example.com"], neverDelegate);

    expect(seams.host.calls).toEqual([[rc, nodeRuntimeIO, "example.com"]]);
    expect(printedLines(log)).toEqual([
      "example.com",
      "desired: allowlisted",
      "  host sources: project:policy",
      "  request source: project:policy",
      "  methods: GET, POST",
      "  paths: /api",
      "  git push: write",
      '  graphql: {"endpoints":["/graphql"],"writeOps":"mutation"}',
      "  writes: ask",
      "  credentials: TOKEN_A",
      "approved: unavailable",
      "effective: not allowlisted",
      "  host sources: none",
      "  request source: none",
      "  methods: unrestricted",
      "  paths: unrestricted",
      "  git push: not specially restricted",
      "  graphql: none",
      "  writes: deny",
      "  credentials: none",
      "current project approval: sha256:p (interactive, 2026-01-01T00:00:00.000Z)",
      "effective project approval: none",
      "current local approval: none",
      "effective local approval: sha256:l (digest-command)",
      "pending changes:",
      "  - host semantics are newly desired",
    ]);
  });

  test("reports unavailable views, a desired capture error, and no pending changes", async () => {
    const explanation: PolicyHostExplanation = {
      host: "example.org",
      desiredError: "policy capture failed",
      approvals: {},
      effectiveApprovals: {},
      pendingChanges: [],
    };
    seams.host.impl = () => explanation;
    const log = vi.spyOn(console, "log").mockImplementation(() => {});

    await runCommandApp(baseContext(), ["policy", "explain", "example.org"], neverDelegate);

    expect(printedLines(log)).toEqual([
      "example.org",
      "desired: unavailable",
      "  error: policy capture failed",
      "approved: unavailable",
      "effective: unavailable",
      "current project approval: none",
      "effective project approval: none",
      "current local approval: none",
      "effective local approval: none",
      "pending changes:",
      "  none",
    ]);
  });
});

describe("runfree policy diff", () => {
  function sampleReview(): NetworkPolicyReview {
    return {
      diffs: [
        {
          scope: "project",
          classification: "approval-required",
          desiredDigest: "sha256:d1",
          approvedDigest: "sha256:a1",
          reasons: ["r1"],
          changes: ["c1"],
        },
        {
          scope: "local",
          classification: "unchanged",
          desiredDigest: "sha256:d2",
          reasons: [],
          changes: [],
        },
      ],
      policies: {},
    };
  }

  test("prints scope, classification, digests, reasons, and changes as text", async () => {
    seams.review.impl = () => sampleReview();
    const log = vi.spyOn(console, "log").mockImplementation(() => {});

    await runCommandApp(baseContext(), ["policy", "diff"], neverDelegate);

    expect(printedLines(log)).toEqual([
      "project: approval-required",
      "  desired:  sha256:d1",
      "  approved: sha256:a1",
      "  - r1",
      "  * c1",
      "local: unchanged",
      "  desired:  sha256:d2",
      "  approved: none",
    ]);
  });

  test("--json prints the raw diff array instead of the text rendering", async () => {
    const review = sampleReview();
    seams.review.impl = () => review;
    const log = vi.spyOn(console, "log").mockImplementation(() => {});

    await runCommandApp(baseContext(), ["policy", "diff", "--json"], neverDelegate);

    expect(log).toHaveBeenCalledTimes(1);
    expect(log).toHaveBeenCalledWith(JSON.stringify(review.diffs, null, 2));
  });

  test("passes the --project and --local scope flags through to the inspector", async () => {
    seams.review.impl = () => sampleReview();
    vi.spyOn(console, "log").mockImplementation(() => {});

    await runCommandApp(baseContext(), ["policy", "diff", "--project"], neverDelegate);
    await runCommandApp(baseContext(), ["policy", "diff", "--local"], neverDelegate);

    expect(seams.review.calls[0]?.[2]).toBe("project");
    expect(seams.review.calls[1]?.[2]).toBe("local");
  });
});

describe("runfree policy review", () => {
  test("prints each diff plus the canonical desired policy JSON only for scopes that have one", async () => {
    const review: NetworkPolicyReview = {
      diffs: [
        { scope: "project", classification: "unapproved", desiredDigest: "sha256:d1", reasons: ["no baseline"], changes: [] },
        { scope: "local", classification: "unchanged", desiredDigest: "sha256:d2", reasons: [], changes: [] },
      ],
      policies: { project: { version: 2, hosts: ["example.com"] } as NetworkPolicyReview["policies"]["project"] },
    };
    seams.review.impl = () => review;
    const log = vi.spyOn(console, "log").mockImplementation(() => {});

    await runCommandApp(baseContext(), ["policy", "review"], neverDelegate);

    expect(printedLines(log)).toEqual([
      "project: unapproved",
      "  desired:  sha256:d1",
      "  approved: none",
      "  - no baseline",
      JSON.stringify(review.policies.project, null, 2),
      "local: unchanged",
      "  desired:  sha256:d2",
      "  approved: none",
    ]);
  });
});

describe("runfree policy approve", () => {
  test("the digest-command path approves the named scope and prints the approved digest", async () => {
    const digest = `sha256:${"a".repeat(64)}`;
    seams.requireUsable.impl = (): ControlApprovalRead => ({ kind: "missing" }) as ControlApprovalRead;
    seams.approve.impl = () => ({
      subjects: { "network-project": { digest: "sha256:approved-project-digest", mechanism: "digest-command", approvedAt: "2026-01-01T00:00:00.000Z" } },
    });
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const rc = fakeRuntimeContext();

    await runCommandApp(
      baseContext({ runtimeContext: () => rc }),
      ["policy", "approve", "--project", "--subject-digest", digest],
      neverDelegate,
    );

    expect(seams.requireUsable.calls).toEqual([[rc, nodeRuntimeIO]]);
    expect(seams.approve.calls).toEqual([[rc, nodeRuntimeIO, "network-project", { expectedDigest: digest, mechanism: "digest-command" }]]);
    expect(printedLines(log)).toEqual(["approved network-project: sha256:approved-project-digest"]);
  });

  test("requires exactly one of --project or --local before reaching the runtime context", async () => {
    await expect(runCommandApp(baseContext(), ["policy", "approve"], neverDelegate))
      .rejects.toThrow("requires exactly one of --project or --local");
    expect(seams.requireUsable.calls).toEqual([]);
    expect(seams.approve.calls).toEqual([]);
  });

  test("a non-interactive run without --subject-digest is refused before any collaborator runs", async () => {
    seams.isInteractive = false;
    await expect(runCommandApp(baseContext(), ["policy", "approve", "--project"], neverDelegate))
      .rejects.toThrow("non-interactive policy approval requires --subject-digest sha256:...");
    expect(seams.requireUsable.calls).toEqual([]);
    expect(seams.approve.calls).toEqual([]);
  });

  describe("the interactive path", () => {
    // These two tests exercise the real `desiredPolicyReviewLines` renderer
    // (no mock on `../control/review-render.ts`), so the review body a
    // reviewer actually reads before answering the confirm prompt is the
    // genuine one. `readApprovedNetworkPolicy` reads from
    // `runtime.projectRoot`/`runtime.project`, so these need a real
    // filesystem project, not the `/fake/project` stub the other tests use.
    let root: string;

    beforeEach(() => {
      root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-policy-command-test-"));
      fs.mkdirSync(path.join(root, ".runfree"));
      fs.writeFileSync(path.join(root, ".runfree", "network-policy.json"), `{"version":2,"hosts":["example.com"]}`);
    });

    afterEach(() => {
      fs.rmSync(root, { recursive: true });
    });

    function realRuntimeContext(): RuntimeContext {
      const env = {};
      return { projectRoot: root, project: projectInfo(root, env), runtimeRoot: path.join(root, "runtime"), env };
    }

    test("renders the real review body, asks to confirm, and forwards an affirmative answer", async () => {
      seams.isInteractive = true;
      seams.requireUsable.impl = (): ControlApprovalRead => ({ kind: "missing" }) as ControlApprovalRead;
      seams.confirm.result = true;
      const rc = realRuntimeContext();
      const policy: DesiredNetworkPolicyJson = { version: 2, hosts: ["example.com"] };
      const subject = networkControlSubject("network-local", policy);
      let observedConfirmResult: unknown;
      seams.approve.impl = (...args: unknown[]) => {
        const input = args[3] as { confirm?: (candidate: unknown, subject: unknown, owners: unknown) => boolean };
        const candidate = { project: policy, local: policy } as unknown as DesiredPolicyCandidate;
        observedConfirmResult = input.confirm?.(candidate, subject, undefined);
        return { subjects: { "network-local": { digest: subject.digest, mechanism: "interactive", approvedAt: "2026-01-01T00:00:00.000Z" } } };
      };
      const log = vi.spyOn(console, "log").mockImplementation(() => {});

      await runCommandApp(baseContext({ runtimeContext: () => rc }), ["policy", "approve", "--local"], neverDelegate);

      expect(seams.approve.calls[0]?.[2]).toBe("network-local");
      expect((seams.approve.calls[0]?.[3] as { mechanism: string }).mechanism).toBe("interactive");
      expect(seams.confirm.calls).toEqual([["Approve exact policy? [y/N] "]]);
      expect(observedConfirmResult).toBe(true);
      expect(printedLines(log)).toEqual([
        "scope: local",
        "subject: network-local",
        `subject digest: ${subject.digest}`,
        "canonical desired policy:",
        JSON.stringify(policy, null, 2),
        "This approval applies only to this exact canonical policy input.",
        `approved network-local: ${subject.digest}`,
      ]);
    });

    test("a negative answer propagates false back to the collaborator, and nothing is reported approved", async () => {
      seams.isInteractive = true;
      seams.requireUsable.impl = (): ControlApprovalRead => ({ kind: "missing" }) as ControlApprovalRead;
      seams.confirm.result = false;
      const rc = realRuntimeContext();
      const policy: DesiredNetworkPolicyJson = { version: 2, hosts: [] };
      const subject = networkControlSubject("network-project", policy);
      let observedConfirmResult: unknown;
      seams.approve.impl = (...args: unknown[]) => {
        const input = args[3] as { confirm?: (candidate: unknown, subject: unknown, owners: unknown) => boolean };
        const candidate = { project: policy, local: policy } as unknown as DesiredPolicyCandidate;
        observedConfirmResult = input.confirm?.(candidate, subject, undefined);
        // Stand in for the real collaborator's refusal once its confirm
        // callback answers no; nothing in policy.ts proceeds past this call.
        if (observedConfirmResult === false) throw new Error("approval was not confirmed");
        return { subjects: {} };
      };
      const log = vi.spyOn(console, "log").mockImplementation(() => {});

      await expect(
        runCommandApp(baseContext({ runtimeContext: () => rc }), ["policy", "approve", "--project"], neverDelegate),
      ).rejects.toThrow("approval was not confirmed");

      expect(observedConfirmResult).toBe(false);
      expect(printedLines(log)).toEqual([
        "scope: project",
        "subject: network-project",
        `subject digest: ${subject.digest}`,
        "canonical desired policy:",
        JSON.stringify(policy, null, 2),
        "This approval applies only to this exact canonical policy input.",
      ]);
    });
  });
});

describe("runfree policy use-approved", () => {
  test("a converged activation prints the selected generation and that the firewall ruleset was verified", async () => {
    const activation: ControlActivationResult = { kind: "converged", controlGeneration: "gen-7" };
    seams.activate.impl = () => activation;
    const log = vi.spyOn(console, "log").mockImplementation(() => {});

    await runCommandApp(baseContext(), ["policy", "use-approved"], neverDelegate);

    expect(seams.activate.calls[0]?.[2]).toEqual({ recoverInvalidActive: true });
    expect(printedLines(log)).toEqual([
      "selected approved effective policy generation: gen-7",
      "convergence: request proxy and verified firewall acknowledged",
    ]);
  });

  test("a selected (not yet converged) activation reports convergence as pending", async () => {
    const activation: ControlActivationResult = { kind: "selected", controlGeneration: "gen-8" };
    seams.activate.impl = () => activation;
    const log = vi.spyOn(console, "log").mockImplementation(() => {});

    await runCommandApp(baseContext(), ["policy", "use-approved"], neverDelegate);

    expect(printedLines(log)).toEqual([
      "selected approved effective policy generation: gen-8",
      "convergence: pending until a proxy runtime is live",
    ]);
  });

  test("a deferred activation raises a CliError naming the reason instead of printing anything", async () => {
    const activation: ControlActivationResult = { kind: "deferred", reason: "controls are not fully approved yet" };
    seams.activate.impl = () => activation;
    const log = vi.spyOn(console, "log").mockImplementation(() => {});

    await expect(runCommandApp(baseContext(), ["policy", "use-approved"], neverDelegate))
      .rejects.toMatchObject({
        constructor: CliError,
        message: "no effective policy generation was selected: controls are not fully approved yet",
      });
    expect(log).not.toHaveBeenCalled();
  });

  test("a waiting activation (proxy from another build) raises the same typed refusal shape", async () => {
    const activation: ControlActivationResult = { kind: "waiting", reason: "the running proxy is from another Runfree build" };
    seams.activate.impl = () => activation;

    await expect(runCommandApp(baseContext(), ["policy", "use-approved"], neverDelegate))
      .rejects.toMatchObject({
        constructor: CliError,
        message: "no effective policy generation was selected: the running proxy is from another Runfree build",
      });
  });
});
