import { describe, expect, test } from "vitest";

import { createSessionImageDeclarationProof } from "./session-image-declarations.ts";
import { createSessionLaunchTarget } from "./session-launch.ts";
import {
  sessionNamedVolumeExpectations,
  validateSessionNamedVolumeInspect,
  type SessionNamedVolumeProof,
} from "./session-named-volume-proof.ts";
import {
  assertSessionContainerAttachCommand,
  executeSessionDockerCommand,
  parseCreatedSessionContainerId,
  SESSION_CONTAINER_STOP_SIGNAL,
  sessionContainerAttachCommand,
  sessionContainerCreateCommand,
  sessionContainerInspectCommand,
  sessionContainerObservedExited,
  sessionContainerObservedExitStatus,
  sessionContainerStartAttachCommand,
  sessionNetworkInspectCommand,
  type SessionContainerAttachIdentity,
  type SessionDockerCommand,
} from "./session-container-docker.ts";
import {
  effectiveControlPlaneFixture,
  SESSION_TEST_PROJECT,
  sessionAgentMaterializationFixture,
  sessionContainerRecordFixture,
  sessionContainerTemplateFixture,
  sessionGenerationFixture,
} from "./session-container.test-harness.ts";
import {
  bindSessionContainerTemplateGenerationV2,
  createSessionContainerCreatePlan,
  type SessionContainerCreatePlan,
} from "./session-container-template.ts";
import {
  transitionBoundAllocatedSessionContainerToProvisioningRunningV2,
  transitionProvisioningRunningSessionContainerToAttachedV2,
  transitionSessionContainerToRevokingV2,
  type SessionContainerRecordV2,
} from "./session-containers.ts";

const PROJECT = SESSION_TEST_PROJECT;
const CONTAINER_ID = "3".repeat(64);
const NETWORK_ID = "8".repeat(64);

function allocated(): SessionContainerRecordV2 {
  return sessionContainerRecordFixture({
    overrides: {
      sessionIncarnation: "1".repeat(64),
      sessionPrincipal: "2".repeat(64),
      displayName: "payments refactor",
      hostPid: 1234,
      createdAt: "2026-08-05T12:00:00.000Z",
    },
  });
}

function boundAllocated(): SessionContainerRecordV2 {
  return sessionContainerRecordFixture({
    containerId: CONTAINER_ID,
    overrides: {
      sessionIncarnation: "1".repeat(64),
      sessionPrincipal: "2".repeat(64),
      displayName: "payments refactor",
      hostPid: 1234,
      createdAt: "2026-08-05T12:00:00.000Z",
    },
  });
}

function provisioningRunning(): SessionContainerRecordV2 {
  return transitionBoundAllocatedSessionContainerToProvisioningRunningV2(boundAllocated(), {
    admittedAt: "2026-08-05T12:00:01.000Z",
    leaseGeneration: "a".repeat(32),
    leaseExpiresAt: "2026-08-05T12:02:01.000Z",
  });
}

function revoking(): SessionContainerRecordV2 {
  return transitionSessionContainerToRevokingV2(provisioningRunning());
}

function attached(): SessionContainerRecordV2 {
  return transitionProvisioningRunningSessionContainerToAttachedV2(provisioningRunning());
}

/** The same session admitted from a non-interactive launch (no TTY, no stdin). */
function nonInteractiveAttached(): SessionContainerRecordV2 {
  const bound = sessionContainerRecordFixture({
    containerId: CONTAINER_ID,
    overrides: {
      sessionIncarnation: "1".repeat(64),
      sessionPrincipal: "2".repeat(64),
      displayName: "payments refactor",
      hostPid: 1234,
      createdAt: "2026-08-05T12:00:00.000Z",
      interactive: false,
      tty: false,
    },
  });
  return transitionProvisioningRunningSessionContainerToAttachedV2(
    transitionBoundAllocatedSessionContainerToProvisioningRunningV2(bound, {
      admittedAt: "2026-08-05T12:00:01.000Z",
      leaseGeneration: "a".repeat(32),
      leaseExpiresAt: "2026-08-05T12:02:01.000Z",
    }),
  );
}

function attachIdentity(record: SessionContainerRecordV2): SessionContainerAttachIdentity {
  return {
    projectId: record.projectId,
    composeProject: record.composeProject,
    sessionIncarnation: record.sessionIncarnation,
    containerId: CONTAINER_ID,
    interactive: record.interactive,
  };
}

function createPlan(record: SessionContainerRecordV2 = allocated()): SessionContainerCreatePlan {
  const { target, generation } = sessionGenerationFixture();
  const template = bindSessionContainerTemplateGenerationV2(sessionContainerTemplateFixture(), target);
  const launch = createSessionLaunchTarget({
    path: record.launchPath,
    args: record.launchArgs,
    interactive: record.interactive,
    tty: record.tty,
  });
  const imageDeclarationProof = createSessionImageDeclarationProof({
    image: {
      architecture: "amd64",
      id: record.selectedAgentImageId,
      labels: {},
      os: "linux",
      volumes: [],
      environment: { IMAGE_DEFAULT: "retained" },
    },
    selectedAgentImageId: record.selectedAgentImageId,
    mounts: template.mounts,
    environment: template.environment,
  });
  return createSessionContainerCreatePlan({
    expectedProject: PROJECT,
    template,
    generationTarget: target,
    sessionAgentGeneration: generation,
    sessionAgentMaterialization: sessionAgentMaterializationFixture({ generation }),
    effectiveControlPlane: effectiveControlPlaneFixture({ target }),
    launch,
    imageDeclarationProof,
    record,
    runfreeVersion: "0.3.0",
  });
}

function optionValue(args: readonly string[], option: string): string | undefined {
  const index = args.indexOf(option);
  return index < 0 ? undefined : args[index + 1];
}

function namedVolumeProof(plan: SessionContainerCreatePlan): SessionNamedVolumeProof {
  const inspection = sessionNamedVolumeExpectations(plan).map((expected) => ({
    CreatedAt: "2026-08-05T11:59:00.000Z",
    Driver: "local",
    Labels: {
      "com.docker.compose.config-hash": `sha256:${"f".repeat(64)}`,
      "com.docker.compose.project": PROJECT.composeProject,
      "com.docker.compose.version": "2.39.1",
      "com.docker.compose.volume": expected.logicalName,
    },
    Mountpoint: `/var/lib/docker/volumes/${expected.name}/_data`,
    Name: expected.name,
    Options: null,
    Scope: "local",
  }));
  return validateSessionNamedVolumeInspect(JSON.stringify(inspection), plan);
}

describe("typed session-container Docker operations", () => {
  test("creates stopped from the selected image with exact network, launch, and confinement", () => {
    const plan = createPlan();
    const command = sessionContainerCreateCommand(plan, namedVolumeProof(plan));

    expect(command.args.slice(0, 4)).toEqual([
      "container",
      "create",
      "--name",
      plan.record.containerName,
    ]);
    expect(optionValue(command.args, "--network")).toBe(plan.effectiveControlPlane.networkIds.agentInternal);
    expect(optionValue(command.args, "--ip")).toBe(plan.record.sourceIp);
    expect(optionValue(command.args, "--restart")).toBe("no");
    expect(optionValue(command.args, "--workdir")).toBe(plan.template.workingDirectory);
    expect(optionValue(command.args, "--entrypoint")).toBe(plan.launch.path);
    expect(command.args).toContain("--no-healthcheck");
    expect(command.args).toContain("--interactive");
    expect(command.args).toContain("--tty");
    expect(command.args).toContain(SESSION_CONTAINER_STOP_SIGNAL);
    expect(command.args).not.toContain("--init");
    expect(command.args).not.toContain("--publish");
    expect(command.args).not.toContain("--add-host");

    const imageIndex = command.args.lastIndexOf(plan.record.selectedAgentImageId);
    expect(imageIndex).toBeGreaterThan(0);
    expect(command.args.slice(imageIndex + 1)).toEqual(plan.launch.args);
    expect(command.args).not.toContain(plan.record.selectedAgentImageRef);
    expect(command.args.filter((argument) => argument === "--env"))
      .toHaveLength(Object.keys(plan.environment).length);
    expect(command.args.indexOf("HTTPS_PROXY=http://172.31.90.10:8080"))
      .toBeLessThan(command.args.indexOf("TERM=xterm-256color"));
    expect(command.args.filter((argument) => argument === "--cap-drop")).toHaveLength(2);
    expect(command.args.some((argument) => argument.startsWith("com.docker.compose."))).toBe(false);
    expect(command.args.some((argument) => argument.includes(plan.record.sessionPrincipal))).toBe(false);
    expect(command.args).toContain("type=bind,src=/host/runfree/state/payments/proxy-ca/public,dst=/etc/proxy-ca,readonly");
    expect(command.args).toContain(
      "type=volume,src=runfree-0123456789ab_runfree-commandhistory,dst=/commandhistory,volume-nocopy",
    );

    const serialized = JSON.stringify(command.args);
    expect(serialized).not.toMatch(/docker exec|idle-v1|session-supervisor|finaliz/u);
    expect(command.args).not.toContain("connect");
    const alreadyCreatedPlan = createPlan(sessionContainerRecordFixture({
      containerId: CONTAINER_ID,
    }));
    expect(() => sessionContainerCreateCommand(alreadyCreatedPlan, namedVolumeProof(alreadyCreatedPlan)))
      .toThrow("already has");
  });

  test("rejects forged environment and mount plans before a Docker effect", () => {
    let dockerCalls = 0;
    const execute = () => {
      dockerCalls += 1;
      return 0;
    };
    const valid = createPlan();
    const forged = [
      { ...valid, environment: { ...valid.environment, HTTPS_PROXY: "http://attacker:8080" } },
      { ...valid, mounts: [
        ...valid.mounts,
        { type: "bind", source: "/var/run/docker.sock", target: "/workspace/socket", readOnly: false, noCopy: false },
      ] },
    ] as unknown as SessionContainerCreatePlan[];
    for (const candidate of forged) {
      expect(() => executeSessionDockerCommand(sessionContainerCreateCommand(candidate, namedVolumeProof(valid)), execute))
        .toThrow("was not minted");
    }
    expect(dockerCalls).toBe(0);
  });

  test("rejects forged and wrong-session named-volume proofs before a Docker effect", () => {
    let dockerCalls = 0;
    const execute = () => {
      dockerCalls += 1;
      return 0;
    };
    const plan = createPlan();
    const proof = namedVolumeProof(plan);
    const forged = { ...proof } as unknown as SessionNamedVolumeProof;
    const otherPlan = createPlan(sessionContainerRecordFixture({
      overrides: { sessionIncarnation: "6".repeat(64) },
    }));

    expect(() => executeSessionDockerCommand(sessionContainerCreateCommand(plan, forged), execute))
      .toThrow("was not minted");
    expect(() => executeSessionDockerCommand(
      sessionContainerCreateCommand(plan, namedVolumeProof(otherPlan)),
      execute,
    )).toThrow("different session plan");
    expect(dockerCalls).toBe(0);
  });

  test("starts only from the exact durable provisioning-running record", () => {
    expect(parseCreatedSessionContainerId(`${CONTAINER_ID}\n`)).toBe(CONTAINER_ID);
    expect(() => parseCreatedSessionContainerId("short-id\n")).toThrow("exact Docker object id");
    expect(sessionContainerInspectCommand(allocated(), PROJECT, CONTAINER_ID).args).toEqual([
      "container",
      "inspect",
      CONTAINER_ID,
    ]);

    const record = provisioningRunning();
    const start = sessionContainerStartAttachCommand(record, PROJECT);
    expect(start.args).toEqual([
      "container",
      "start",
      "--attach",
      "--interactive",
      CONTAINER_ID,
    ]);
    expect(start.effect).toBe("start-attach-session-container");
    expect(start.exactTarget).toBe(CONTAINER_ID);
    expect(start.args).not.toContain("exec");
    expect(start.args).not.toContain("connect");
    // Rejection happens before any Docker effect: the state gate refuses a
    // record that has not durably reached provisioning-running, and one that
    // has already left it.
    expect(() => sessionContainerStartAttachCommand(boundAllocated(), PROJECT)).toThrow("allocated");
    expect(() => sessionContainerStartAttachCommand(revoking(), PROJECT)).toThrow("revoking");
  });

  test("re-attaches the exact attached container, binding stdin only for an interactive record", () => {
    const record = attached();
    const command = sessionContainerAttachCommand(record, PROJECT);
    expect(command.args).toEqual([
      "container",
      "attach",
      CONTAINER_ID,
    ]);
    expect(command.effect).toBe("attach-session-container");
    expect(command.exactTarget).toBe(CONTAINER_ID);
    // Never a second start, an exec, or a network change: re-attaching is the
    // one thing this command may do to an already running container.
    expect(command.args).not.toContain("start");
    expect(command.args).not.toContain("exec");
    expect(command.args).not.toContain("connect");
    // `docker container attach` binds the caller's stdin by default, so a
    // session that was never launched interactively must say so explicitly.
    expect(sessionContainerAttachCommand(nonInteractiveAttached(), PROJECT).args).toEqual([
      "container",
      "attach",
      "--no-stdin",
      CONTAINER_ID,
    ]);
    // Refused before any Docker effect: only a session that durably reached
    // `attached` may be re-attached, and only under its own project.
    expect(() => sessionContainerAttachCommand(provisioningRunning(), PROJECT)).toThrow("provisioning-running");
    expect(() => sessionContainerAttachCommand(boundAllocated(), PROJECT)).toThrow("allocated");
    expect(() => sessionContainerAttachCommand(revoking(), PROJECT)).toThrow("revoking");
    expect(() => sessionContainerAttachCommand(record, {
      projectId: "ffffffffffff",
      composeProject: "runfree-ffffffffffff",
    })).toThrow(/project/i);
  });

  test("refuses an attach command that is unsealed or names another lifecycle identity", () => {
    const record = attached();
    const command = sessionContainerAttachCommand(record, PROJECT);
    expect(() => assertSessionContainerAttachCommand(command, attachIdentity(record))).not.toThrow();

    const forged = {
      executable: "docker",
      args: ["container", "attach", CONTAINER_ID],
      effect: "attach-session-container",
      exactTarget: CONTAINER_ID,
    } as unknown as SessionDockerCommand;
    expect(() => assertSessionContainerAttachCommand(forged, attachIdentity(record))).toThrow("unsealed");
    // A sealed command of another effect is not an attach command either.
    expect(() => assertSessionContainerAttachCommand(
      sessionContainerStartAttachCommand(provisioningRunning(), PROJECT),
      attachIdentity(record),
    )).toThrow("unsealed");

    for (const drift of [
      { containerId: "5".repeat(64) },
      { sessionIncarnation: "9".repeat(64) },
      { projectId: "ffffffffffff" },
      { composeProject: "runfree-ffffffffffff" },
      { interactive: false },
    ]) {
      expect(() => assertSessionContainerAttachCommand(command, {
        ...attachIdentity(record),
        ...drift,
      })).toThrow("different lifecycle identity");
    }
  });

  test("inspects the exact selected network without a post-start connect operation", () => {
    expect(sessionNetworkInspectCommand(NETWORK_ID).args).toEqual(["network", "inspect", NETWORK_ID]);
    expect(() => sessionNetworkInspectCommand("short-id")).toThrow("exact Docker object id");
  });

  test("sessionContainerObservedExited answers true only for the exact, provably stopped container", () => {
    const exited = (state: Record<string, unknown>, id: string = CONTAINER_ID): string =>
      JSON.stringify([{ Id: id, State: state }]);
    expect(sessionContainerObservedExited(exited({ Running: false, Status: "exited" }), CONTAINER_ID)).toBe(true);
    expect(sessionContainerObservedExited(exited({ Running: false, Status: "dead" }), CONTAINER_ID)).toBe(true);
    // Fail closed: running, restarting, a different container, or any parse
    // deviation keeps today's SIGTERM+grace stop path.
    expect(sessionContainerObservedExited(exited({ Running: true, Status: "running" }), CONTAINER_ID)).toBe(false);
    expect(sessionContainerObservedExited(exited({ Running: false, Restarting: true }), CONTAINER_ID)).toBe(false);
    expect(sessionContainerObservedExited(exited({ Running: false }, "9".repeat(64)), CONTAINER_ID)).toBe(false);
    expect(sessionContainerObservedExited(JSON.stringify([]), CONTAINER_ID)).toBe(false);
    expect(sessionContainerObservedExited("not json", CONTAINER_ID)).toBe(false);
    expect(sessionContainerObservedExited(JSON.stringify([{ Id: CONTAINER_ID }]), CONTAINER_ID)).toBe(false);
    expect(() => sessionContainerObservedExited("[]", "short-id")).toThrow("exact Docker object id");
  });

  test("sessionContainerObservedExitStatus reports a status only for a proved exit that carries one", () => {
    const exited = (state: Record<string, unknown>, id: string = CONTAINER_ID): string =>
      JSON.stringify([{ Id: id, State: state }]);
    expect(sessionContainerObservedExitStatus(exited({ Running: false, Status: "exited", ExitCode: 42 }), CONTAINER_ID)).toBe(42);
    expect(sessionContainerObservedExitStatus(exited({ Running: false, Status: "exited", ExitCode: 0 }), CONTAINER_ID)).toBe(0);
    expect(sessionContainerObservedExitStatus(exited({ Running: false, Status: "dead", ExitCode: 137 }), CONTAINER_ID)).toBe(137);
    // Fail closed: `undefined` means "not proved", never "exited 0". A running
    // or restarting container, a different container, a missing or
    // out-of-range status, and any parse deviation all answer `undefined`.
    expect(sessionContainerObservedExitStatus(exited({ Running: true, Status: "running", ExitCode: 0 }), CONTAINER_ID)).toBeUndefined();
    expect(sessionContainerObservedExitStatus(exited({ Running: false, Restarting: true, ExitCode: 1 }), CONTAINER_ID)).toBeUndefined();
    expect(sessionContainerObservedExitStatus(exited({ Running: false, ExitCode: 1 }, "9".repeat(64)), CONTAINER_ID)).toBeUndefined();
    expect(sessionContainerObservedExitStatus(exited({ Running: false, Status: "exited" }), CONTAINER_ID)).toBeUndefined();
    expect(sessionContainerObservedExitStatus(exited({ Running: false, ExitCode: "1" }), CONTAINER_ID)).toBeUndefined();
    expect(sessionContainerObservedExitStatus(exited({ Running: false, ExitCode: -1 }), CONTAINER_ID)).toBeUndefined();
    expect(sessionContainerObservedExitStatus(exited({ Running: false, ExitCode: 256 }), CONTAINER_ID)).toBeUndefined();
    expect(sessionContainerObservedExitStatus(exited({ Running: false, ExitCode: 1.5 }), CONTAINER_ID)).toBeUndefined();
    expect(sessionContainerObservedExitStatus("not json", CONTAINER_ID)).toBeUndefined();
    expect(() => sessionContainerObservedExitStatus("[]", "short-id")).toThrow("exact Docker object id");
  });

  test("rejects mismatched exact container targets before execution", () => {
    let dockerCalls = 0;
    expect(() => executeSessionDockerCommand(
      sessionContainerInspectCommand(boundAllocated(), PROJECT, "5".repeat(64)),
      () => { dockerCalls += 1; },
    )).toThrow("different container id");
    expect(dockerCalls).toBe(0);
  });

  test("rejects structurally forged Docker commands at the execution boundary", () => {
    let dockerCalls = 0;
    const forged = {
      executable: "docker",
      args: ["container", "rm", "attacker-selected"],
      effect: "remove-session-container",
      exactTarget: "attacker-selected",
    } as unknown as SessionDockerCommand;
    expect(() => executeSessionDockerCommand(forged, () => { dockerCalls += 1; })).toThrow("unvalidated");
    expect(dockerCalls).toBe(0);
  });
});
