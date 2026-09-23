import { describe, expect, test } from "vitest";

import {
  SESSION_NAMED_VOLUME_INSPECT_MAX_BYTES,
  assertSessionNamedVolumeProof,
  sessionNamedVolumeExpectations,
  sessionNamedVolumeInspectRequest,
  validateSessionNamedVolumeInspect,
} from "./session-named-volume-proof.ts";
import {
  SESSION_TEST_PROJECT as PROJECT,
  sessionContainerCreatePlanFixture,
} from "./session-container.test-harness.ts";
import type { SessionContainerCreatePlan } from "./session-container-template.ts";

function digest(character: string): string {
  return `sha256:${character.repeat(64)}`;
}

function volume(logicalName: string): string {
  return `${PROJECT.composeProject}_${logicalName}`;
}

function plan(): SessionContainerCreatePlan {
  return sessionContainerCreatePlanFixture();
}

function inspect(value: SessionContainerCreatePlan): Record<string, unknown>[] {
  return sessionNamedVolumeExpectations(value).map((expected) => ({
    CreatedAt: "2026-08-08T12:00:00Z",
    Driver: "local",
    Labels: {
      "com.docker.compose.config-hash": digest("f"),
      "com.docker.compose.project": PROJECT.composeProject,
      "com.docker.compose.version": "2.39.1",
      "com.docker.compose.volume": expected.logicalName,
    },
    Mountpoint: `/var/lib/docker/volumes/${expected.name}/_data`,
    Name: expected.name,
    Options: null,
    Scope: "local",
  })).reverse();
}

describe("session named-volume inspection proof", () => {
  test("inspects only exact physical names and returns a canonical proof", () => {
    const value = plan();
    const request = sessionNamedVolumeInspectRequest(value);
    expect(request).toEqual({
      executable: "docker",
      args: ["volume", "inspect", ...request.exactNames],
      exactNames: [
        volume("runfree-commandhistory"),
        volume("runfree-deps-0123456789ab-node-modules"),
        volume("runfree-deps-0123456789ab-pnpm-store"),
      ],
    });

    const proof = validateSessionNamedVolumeInspect(JSON.stringify(inspect(value)), value);
    expect(proof.composeProject).toBe(PROJECT.composeProject);
    expect(proof.volumes.map((entry) => entry.name)).toEqual(request.exactNames);
    expect(proof.volumes).toEqual(expect.arrayContaining([
      expect.objectContaining({
        logicalName: "runfree-commandhistory",
        targets: ["/commandhistory"],
      }),
      expect.objectContaining({
        logicalName: "runfree-deps-0123456789ab-node-modules",
        targets: ["/runfree/git-layout/0123456789ab/worktrees/payments/node_modules"],
      }),
    ]));
    expect(() => assertSessionNamedVolumeProof(value, proof)).not.toThrow();
  });

  test("rejects forged and cross-session proof objects", () => {
    const value = plan();
    const proof = validateSessionNamedVolumeInspect(JSON.stringify(inspect(value)), value);
    const forged = JSON.parse(JSON.stringify(proof)) as unknown;

    expect(() => assertSessionNamedVolumeProof(value, forged)).toThrow("was not minted");
    expect(() => assertSessionNamedVolumeProof(plan(), proof)).toThrow("different session plan");
  });

  test.each([
    ["anonymous volume", "4c0f88616f4b2e56797bdaf6989b1434"],
    ["logical rather than physical name", "runfree-commandhistory"],
    ["different Compose project", "runfree-fedcba987654_runfree-commandhistory"],
  ])("rejects a %s before constructing Docker argv", (_label, source) => {
    const value = plan();
    const forged = {
      ...value,
      mounts: value.mounts.map((mount) => mount.type === "volume"
        ? { ...mount, source }
        : mount),
    } as unknown as SessionContainerCreatePlan;
    expect(() => sessionNamedVolumeInspectRequest(forged)).toThrow("was not minted");
  });

  test("rejects independently supplied environment and mount projections", () => {
    const value = plan();
    for (const forged of [
      { ...value, environment: { ...value.environment, RUNFREE_CONTAINER: "forged" } },
      { ...value, mounts: value.mounts.slice(1) },
    ] as unknown as SessionContainerCreatePlan[]) {
      expect(() => sessionNamedVolumeInspectRequest(forged)).toThrow("was not minted");
      expect(() => validateSessionNamedVolumeInspect(JSON.stringify(inspect(value)), forged))
        .toThrow("was not minted");
    }
  });

  test("rejects missing, extra, duplicate, and misnamed inspection records", () => {
    const value = plan();
    const valid = inspect(value);
    const cases = [
      valid.slice(1),
      [...valid, {
        ...valid[0],
        Name: volume("runfree-unexpected-secret-store"),
        Labels: {
          ...(valid[0].Labels as Record<string, string>),
          "com.docker.compose.volume": "runfree-unexpected-secret-store",
        },
      }],
      [valid[0], valid[0], valid[2]],
      valid.map((entry, index) => index === 0 ? { ...entry, Name: volume("runfree-wrong") } : entry),
    ];
    for (const evidence of cases) {
      expect(() => validateSessionNamedVolumeInspect(JSON.stringify(evidence), value)).toThrow();
    }
  });

  test.each([
    ["project label", (entry: Record<string, any>) => { entry.Labels["com.docker.compose.project"] = "runfree-fedcba987654"; }],
    ["volume label", (entry: Record<string, any>) => { entry.Labels["com.docker.compose.volume"] = "wrong"; }],
    ["missing labels", (entry: Record<string, any>) => { entry.Labels = null; }],
    ["remote driver", (entry: Record<string, any>) => { entry.Driver = "nfs"; }],
    ["global scope", (entry: Record<string, any>) => { entry.Scope = "global"; }],
    ["host bind driver option", (entry: Record<string, any>) => {
      entry.Options = { type: "none", o: "bind", device: "/host/secrets" };
    }],
    ["relative mountpoint", (entry: Record<string, any>) => { entry.Mountpoint = "relative/path"; }],
  ])("rejects changed %s without accepting additional filesystem authority", (_label, mutate) => {
    const value = plan();
    const evidence = inspect(value) as Record<string, any>[];
    mutate(evidence[0]);
    expect(() => validateSessionNamedVolumeInspect(JSON.stringify(evidence), value)).toThrow();
  });

  test("rejects two logical volumes backed by one physical mountpoint", () => {
    const value = plan();
    const evidence = inspect(value) as Record<string, any>[];
    evidence[1].Mountpoint = evidence[0].Mountpoint;
    expect(() => validateSessionNamedVolumeInspect(JSON.stringify(evidence), value))
      .toThrow("share one physical mountpoint");
  });

  test("strictly bounds and parses Docker inspection evidence", () => {
    const value = plan();
    expect(() => validateSessionNamedVolumeInspect(
      `[${" ".repeat(SESSION_NAMED_VOLUME_INSPECT_MAX_BYTES)}]`,
      value,
    )).toThrow("size limit");
    expect(() => validateSessionNamedVolumeInspect(
      '[{"Name":"first","Name":"second"}]',
      value,
    )).toThrow("malformed named-volume inspection JSON");
  });
});
