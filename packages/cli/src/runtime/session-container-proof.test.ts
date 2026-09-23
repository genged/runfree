import { describe, expect, test } from "vitest";

import {
  AGENT_PROJECT_IMAGE_ROLE,
  AGENT_RUNTIME_IMAGE_ROLE,
  PROJECT_ID_LABEL,
  RUNFREE_DIGEST_SCHEMA_LABEL,
  RUNFREE_DIGEST_SCHEMA_VERSION,
  RUNFREE_IMAGE_INPUT_DIGEST_LABEL,
  RUNFREE_IMAGE_ROLE_LABEL,
  RUNFREE_MANAGED_IMAGE_LABEL,
  RUNFREE_VERSION_LABEL,
} from "./constants.ts";
import {
  SESSION_CONTAINER_CAPABILITY_DROPS,
  SESSION_CONTAINER_RESTART_POLICY,
  SESSION_CONTAINER_SECURITY_OPTIONS,
  SESSION_CONTAINER_STOP_SIGNAL,
  SESSION_CONTAINER_USER,
} from "./session-container-contract.ts";
import {
  assertSessionContainerProof,
  SESSION_CONTAINER_INSPECT_MAX_BYTES,
  SessionContainerNotRunningYetError,
  type SessionContainerProofPhase,
  validateSessionContainerInspect,
} from "./session-container-proof.ts";
import {
  sessionContainerCreatePlanFixture,
  sessionContainerRecordFixture,
} from "./session-container.test-harness.ts";
import {
  SESSION_TEST_DOCKER_STARTED_AT,
  SESSION_TEST_NETWORK_ENDPOINT_ID,
} from "./session-container.test-harness.ts";
import type { SessionContainerCreatePlan } from "./session-container-template.ts";
import type { SessionContainerRecordV2 } from "./session-containers.ts";
import { SESSION_ENTRY_PATH } from "./session-launch.ts";
import {
  SESSION_CONTAINER_LABELS,
  sessionContainerLabels,
} from "./session-containers.ts";

const CONTAINER_ID = "1".repeat(64);

type MutableInspect = Array<Record<string, any>>;

// `pi` is the built-in whose direct launch takes no arguments, which is the
// case where Docker reports a null command rather than an empty array.
const EMPTY_ARGV_LAUNCH = { launchPath: "/usr/local/bin/pi", launchArgs: Object.freeze([]) } as const;

function plan(overrides?: Partial<SessionContainerRecordV2>): SessionContainerCreatePlan {
  return sessionContainerCreatePlanFixture({
    containerId: CONTAINER_ID,
    ...(overrides
      ? { record: sessionContainerRecordFixture({ containerId: CONTAINER_ID, overrides }) }
      : {}),
  });
}

function declaredVolumes(value: SessionContainerCreatePlan): Record<string, object> | null {
  return value.imageDeclarationProof.declaredVolumeTargets.length === 0
    ? null
    : Object.fromEntries(value.imageDeclarationProof.declaredVolumeTargets.map((target) => [target, {}]));
}

function inspect(value: SessionContainerCreatePlan, options: { running?: boolean } = {}): MutableInspect {
  const running = options.running ?? false;
  const imageRole = value.sessionAgentMaterialization.selectedAgentImageKind === "project"
    ? AGENT_PROJECT_IMAGE_ROLE
    : AGENT_RUNTIME_IMAGE_ROLE;
  const networkName = `${value.expectedProject.composeProject}_agent_internal`;
  const networkKey = running ? networkName : value.effectiveControlPlane.networkIds.agentInternal;
  return [{
    Id: value.record.containerId,
    Name: `/${value.record.containerName}`,
    Image: value.record.selectedAgentImageId,
    Path: value.record.launchPath,
    Args: [...value.record.launchArgs],
    Config: {
      Image: value.record.selectedAgentImageId,
      User: SESSION_CONTAINER_USER,
      Entrypoint: [value.record.launchPath],
      Cmd: [...value.record.launchArgs],
      StopSignal: SESSION_CONTAINER_STOP_SIGNAL,
      WorkingDir: value.template.workingDirectory,
      OpenStdin: value.record.interactive,
      Tty: value.record.tty,
      Healthcheck: { Test: ["NONE"] },
      Volumes: declaredVolumes(value),
      Env: Object.entries(value.imageDeclarationProof.mergedEnvironment)
        .map(([name, entry]) => `${name}=${entry}`),
      Labels: {
        ...sessionContainerLabels(value.record, value.runfreeVersion),
        [RUNFREE_MANAGED_IMAGE_LABEL]: "true",
        [RUNFREE_IMAGE_ROLE_LABEL]: imageRole,
        [RUNFREE_DIGEST_SCHEMA_LABEL]: RUNFREE_DIGEST_SCHEMA_VERSION,
        [RUNFREE_IMAGE_INPUT_DIGEST_LABEL]: value.record.selectedAgentImageInputDigest,
        [PROJECT_ID_LABEL]: value.record.projectId,
        [RUNFREE_VERSION_LABEL]: value.runfreeVersion,
        "project.label": "allowed-inherited-metadata",
      },
    },
    HostConfig: {
      NetworkMode: value.effectiveControlPlane.networkIds.agentInternal,
      Privileged: false,
      Init: false,
      AutoRemove: false,
      PublishAllPorts: false,
      RestartPolicy: { Name: SESSION_CONTAINER_RESTART_POLICY, MaximumRetryCount: 0 },
      CapAdd: null,
      CapDrop: [...SESSION_CONTAINER_CAPABILITY_DROPS],
      SecurityOpt: [...SESSION_CONTAINER_SECURITY_OPTIONS],
      PortBindings: {},
      ExtraHosts: null,
      Devices: [],
      DeviceRequests: null,
      Binds: null,
      Dns: [],
      DnsOptions: [],
      DnsSearch: [],
      Links: null,
      VolumesFrom: null,
      Mounts: value.mounts.map((mount) => ({
        Type: mount.type,
        Source: mount.source,
        Target: mount.target,
        ReadOnly: mount.readOnly,
        VolumeOptions: mount.type === "volume" ? { NoCopy: mount.noCopy } : null,
      })),
    },
    Mounts: value.mounts.map((mount) => ({
      Type: mount.type,
      ...(mount.type === "volume"
        ? { Name: mount.source, Source: `/var/lib/docker/volumes/${mount.source}/_data` }
        : { Source: mount.source }),
      Destination: mount.target,
      RW: !mount.readOnly,
    })),
    State: {
      Running: running,
      Status: running ? "running" : "created",
      Pid: running ? 4242 : 0,
      StartedAt: running ? SESSION_TEST_DOCKER_STARTED_AT : "0001-01-01T00:00:00Z",
      Dead: false,
      Paused: false,
      Restarting: false,
      OOMKilled: false,
      Error: "",
      ExitCode: 0,
    },
    NetworkSettings: {
      Networks: {
        [networkKey]: {
          NetworkID: running ? value.effectiveControlPlane.networkIds.agentInternal : "",
          EndpointID: running ? SESSION_TEST_NETWORK_ENDPOINT_ID : "",
          IPAddress: running ? value.record.sourceIp : "",
          IPAMConfig: {
            IPv4Address: value.record.sourceIp,
          },
          GlobalIPv6Address: "",
        },
      },
    },
  }];
}

/** Removes the keys Docker would omit: `false`, `0`, `null`, `[]`, and `{}`. */
function stripZeroValues(section: Record<string, any>): void {
  for (const [name, entry] of Object.entries(section)) {
    const zero = entry === false
      || entry === 0
      || entry === null
      || (Array.isArray(entry) && entry.length === 0)
      || (entry !== null && typeof entry === "object" && !Array.isArray(entry) && Object.keys(entry).length === 0);
    if (zero) delete section[name];
  }
}

function expectNonTransientRunningFailure(
  source: string,
  value: SessionContainerCreatePlan,
): void {
  let caught: unknown;
  try {
    validateSessionContainerInspect(source, value, { kind: "active-running" });
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(Error);
  expect(caught).not.toBeInstanceOf(SessionContainerNotRunningYetError);
}

describe("session container live inspection proof", () => {
  test("accepts the exact selected-image running contract and seals the proof", () => {
    const value = plan();
    const proof = validateSessionContainerInspect(
      JSON.stringify(inspect(value, { running: true })),
      value,
      { kind: "provisioning-running" },
    );
    expect(proof).toMatchObject({
      phase: "provisioning-running",
      projectId: value.record.projectId,
      sessionIncarnation: value.record.sessionIncarnation,
      sessionPrincipal: value.record.sessionPrincipal,
      containerId: CONTAINER_ID,
      imageId: value.record.selectedAgentImageId,
      networkId: value.effectiveControlPlane.networkIds.agentInternal,
      running: true,
      sourceIp: value.record.sourceIp,
      dockerPid: 4242,
      dockerStartedAt: SESSION_TEST_DOCKER_STARTED_AT,
      networkEndpointId: SESSION_TEST_NETWORK_ENDPOINT_ID,
    });
    expect(Object.isFrozen(proof)).toBe(true);
    expect(() => assertSessionContainerProof(
      proof,
      value.record,
      "provisioning-running",
      value.effectiveControlPlane.networkIds.agentInternal,
    )).not.toThrow();
    expect(() => assertSessionContainerProof(
      { ...proof },
      value.record,
      "provisioning-running",
      value.effectiveControlPlane.networkIds.agentInternal,
    )).toThrow("was not minted");
    expect(() => assertSessionContainerProof(
      proof,
      value.record,
      "active-running",
      value.effectiveControlPlane.networkIds.agentInternal,
    ))
      .toThrow("different lifecycle authority");
    expect(() => assertSessionContainerProof(
      proof,
      { ...value.record, sessionIncarnation: "f".repeat(64) },
      "provisioning-running",
      value.effectiveControlPlane.networkIds.agentInternal,
    )).toThrow("different lifecycle authority");

    for (const phase of [
      { kind: "provisioning-running" },
      { kind: "active-running" },
    ] as const) {
      expect(validateSessionContainerInspect(
        JSON.stringify(inspect(value, { running: true })),
        value,
        phase,
      )).toMatchObject({
        phase: phase.kind,
        containerId: CONTAINER_ID,
        imageId: value.record.selectedAgentImageId,
        running: true,
        sourceIp: value.record.sourceIp,
        dockerPid: 4242,
        dockerStartedAt: SESSION_TEST_DOCKER_STARTED_AT,
        networkEndpointId: SESSION_TEST_NETWORK_ENDPOINT_ID,
      });
    }
  });

  // The fixture models an idealized inspect payload. These three encodings are
  // what a real daemon actually returns for a container created by
  // `sessionContainerCreateCommand`, and each one previously read as a
  // violated contract: `HostConfig.Init` is an optional bool pointer that is
  // omitted entirely when no `--init` was requested, capability names come back
  // in the kernel's `CAP_`-prefixed spelling rather than the spelling that was
  // requested, and overriding the entrypoint with no trailing operands
  // serializes `Config.Cmd` as null instead of an empty array.
  test("accepts the encodings a real daemon uses for the same contract", () => {
    const value = plan();

    const withoutInit = inspect(value, { running: true });
    delete withoutInit[0].HostConfig.Init;
    expect(() => validateSessionContainerInspect(
      JSON.stringify(withoutInit),
      value,
      { kind: "provisioning-running" },
    )).not.toThrow();

    const prefixedCapabilities = inspect(value, { running: true });
    prefixedCapabilities[0].HostConfig.CapDrop = SESSION_CONTAINER_CAPABILITY_DROPS
      .map((capability) => `CAP_${capability}`);
    expect(() => validateSessionContainerInspect(
      JSON.stringify(prefixedCapabilities),
      value,
      { kind: "provisioning-running" },
    )).not.toThrow();

    // Docker Desktop relays a bind through its file-sharing layer and names the
    // same directory under a `/host_mnt` prefix in both mount views.
    const relayedBind = inspect(value, { running: true });
    for (const mounts of [relayedBind[0].HostConfig.Mounts, relayedBind[0].Mounts]) {
      for (const entry of mounts) {
        if (entry.Type === "bind") entry.Source = `/host_mnt${entry.Source}`;
      }
    }
    expect(() => validateSessionContainerInspect(
      JSON.stringify(relayedBind),
      value,
      { kind: "provisioning-running" },
    )).not.toThrow();

    // The general rule rather than one field at a time: Docker omits any field
    // carrying its zero value, and which fields those are shifts between
    // releases. Dropping every zero-valued key from the container's own
    // description must leave the same container, so this is what keeps the next
    // daemon upgrade from reading as a violated contract. `State` and
    // `NetworkSettings` are deliberately left intact — a missing running state
    // or network attachment is absence of evidence, not a zero value.
    const zeroValued = inspect(value, { running: true });
    for (const section of [zeroValued[0].Config, zeroValued[0].HostConfig]) {
      stripZeroValues(section);
    }
    for (const mounts of [zeroValued[0].HostConfig.Mounts, zeroValued[0].Mounts]) {
      for (const entry of mounts) stripZeroValues(entry);
    }
    expect(() => validateSessionContainerInspect(
      JSON.stringify(zeroValued),
      value,
      { kind: "provisioning-running" },
    )).not.toThrow();

    const argvFree = plan(EMPTY_ARGV_LAUNCH);
    expect(argvFree.record.launchArgs).toEqual([]);
    const nullCommand = inspect(argvFree, { running: true });
    nullCommand[0].Config.Cmd = null;
    nullCommand[0].Args = null;
    expect(() => validateSessionContainerInspect(
      JSON.stringify(nullCommand),
      argvFree,
      { kind: "provisioning-running" },
    )).not.toThrow();
  });

  // The normalized comparisons above must not become "anything goes": a
  // canonicalized capability set is still an exact set, and a null command is
  // only ever the encoding of an empty argv.
  test.each([
    ["canonicalized capability drop set", (evidence: MutableInspect) => {
      evidence[0].HostConfig.CapDrop = ["CAP_NET_ADMIN"];
    }],
    ["canonicalized capability drop addition", (evidence: MutableInspect) => {
      evidence[0].HostConfig.CapDrop = [
        ...SESSION_CONTAINER_CAPABILITY_DROPS.map((capability) => `CAP_${capability}`),
        "CAP_SYS_ADMIN",
      ];
    }],
    ["dropped non-empty command", (evidence: MutableInspect) => { evidence[0].Config.Cmd = null; }],
    ["dropped non-empty effective args", (evidence: MutableInspect) => { evidence[0].Args = null; }],
    ["relayed-prefix host mount source", (evidence: MutableInspect) => {
      const bind = evidence[0].HostConfig.Mounts
        .find((entry: Record<string, any>) => entry.Type === "bind");
      bind.Source = `/host_mnt${bind.Source}/escaped`;
    }],
    ["relayed-prefix volume mount source", (evidence: MutableInspect) => {
      const volume = evidence[0].HostConfig.Mounts
        .find((entry: Record<string, any>) => entry.Type === "volume");
      volume.Source = `/host_mnt${volume.Source}`;
    }],
  ])("still rejects a changed %s", (_label, mutate) => {
    const value = plan();
    expect(value.record.launchArgs.length).toBeGreaterThan(0);
    const evidence = inspect(value, { running: true });
    mutate(evidence);
    expect(() => validateSessionContainerInspect(
      JSON.stringify(evidence),
      value,
      { kind: "provisioning-running" },
    )).toThrow();
    expectNonTransientRunningFailure(JSON.stringify(evidence), value);
  });

  test("pins the session entry as Path and refuses a container running the inner agent directly", () => {
    // Activation-gate design D3/D6: the typed target names the image's entry
    // with the agent launch as argv, and the running proof holds Docker's
    // effective `Path`/`Args` to exactly that. A container whose first
    // process is the agent itself (the entry skipped, or a project image that
    // re-pointed the entrypoint) is not the container that was planned.
    const innerPath = "/usr/local/bin/codex";
    const innerArgs = ["-c", "check_for_update_on_startup=false", "--dangerously-bypass-approvals-and-sandbox"];
    const value = plan({ launchPath: SESSION_ENTRY_PATH, launchArgs: Object.freeze([innerPath, ...innerArgs]) });
    expect(value.launch.path).toBe(SESSION_ENTRY_PATH);
    expect(value.launch.args[0]).toBe(innerPath);

    const evidence = inspect(value, { running: true });
    expect(evidence[0].Path).toBe(SESSION_ENTRY_PATH);
    expect(evidence[0].Args).toEqual([innerPath, ...innerArgs]);
    const proof = validateSessionContainerInspect(JSON.stringify(evidence), value, { kind: "provisioning-running" });
    expect(proof.phase).toBe("provisioning-running");

    const direct = inspect(value, { running: true });
    direct[0].Path = innerPath;
    direct[0].Args = [...innerArgs];
    expect(() => validateSessionContainerInspect(JSON.stringify(direct), value, { kind: "provisioning-running" }))
      .toThrow("effective Path/Args differ from the exact launch contract");
  });

  test.each([
    ["selected immutable image", (evidence: MutableInspect) => { evidence[0].Image = `sha256:${"f".repeat(64)}`; }],
    ["effective launch path", (evidence: MutableInspect) => { evidence[0].Path = "/project/entrypoint"; }],
    ["effective launch args", (evidence: MutableInspect) => { evidence[0].Args = ["project-default"]; }],
    ["configured image", (evidence: MutableInspect) => { evidence[0].Config.Image = "mutable:latest"; }],
    ["entrypoint", (evidence: MutableInspect) => { evidence[0].Config.Entrypoint = ["/project/entrypoint"]; }],
    ["command", (evidence: MutableInspect) => { evidence[0].Config.Cmd = ["project-default"]; }],
    ["stop signal", (evidence: MutableInspect) => { evidence[0].Config.StopSignal = "SIGKILL"; }],
    ["working directory", (evidence: MutableInspect) => { evidence[0].Config.WorkingDir = "/tmp"; }],
    ["interactive mode", (evidence: MutableInspect) => { evidence[0].Config.OpenStdin = false; }],
    ["TTY mode", (evidence: MutableInspect) => { evidence[0].Config.Tty = false; }],
    ["healthcheck", (evidence: MutableInspect) => { evidence[0].Config.Healthcheck = { Test: ["CMD", "project-probe"] }; }],
    ["image volume declaration", (evidence: MutableInspect) => { evidence[0].Config.Volumes = { "/unaccounted": {} }; }],
    ["environment", (evidence: MutableInspect) => {
      const index = evidence[0].Config.Env.findIndex((entry: string) => entry.startsWith("HTTPS_PROXY="));
      evidence[0].Config.Env[index] = "HTTPS_PROXY=http://attacker:8080";
    }],
    ["extra environment", (evidence: MutableInspect) => { evidence[0].Config.Env.push("ATTACKER=1"); }],
    ["selected-image label", (evidence: MutableInspect) => {
      evidence[0].Config.Labels[RUNFREE_IMAGE_INPUT_DIGEST_LABEL] = `sha256:${"f".repeat(64)}`;
    }],
    ["session identity label", (evidence: MutableInspect) => {
      evidence[0].Config.Labels[SESSION_CONTAINER_LABELS.selectedAgentImageId] = `sha256:${"f".repeat(64)}`;
    }],
    ["unknown Runfree label", (evidence: MutableInspect) => {
      evidence[0].Config.Labels["io.runfree.unexpected"] = "attacker-controlled";
    }],
    ["Compose label", (evidence: MutableInspect) => {
      evidence[0].Config.Labels["com.docker.compose.project"] = "forged";
    }],
    ["network mode", (evidence: MutableInspect) => { evidence[0].HostConfig.NetworkMode = "bridge"; }],
    ["init wrapper", (evidence: MutableInspect) => { evidence[0].HostConfig.Init = true; }],
    ["auto-remove", (evidence: MutableInspect) => { evidence[0].HostConfig.AutoRemove = true; }],
    ["restart policy", (evidence: MutableInspect) => { evidence[0].HostConfig.RestartPolicy.Name = "always"; }],
    ["restart count", (evidence: MutableInspect) => { evidence[0].HostConfig.RestartPolicy.MaximumRetryCount = 1; }],
    ["user", (evidence: MutableInspect) => { evidence[0].Config.User = "root"; }],
    ["privileged mode", (evidence: MutableInspect) => { evidence[0].HostConfig.Privileged = true; }],
    ["capability add", (evidence: MutableInspect) => { evidence[0].HostConfig.CapAdd = ["NET_ADMIN"]; }],
    ["capability drop", (evidence: MutableInspect) => { evidence[0].HostConfig.CapDrop = ["NET_ADMIN"]; }],
    ["security option", (evidence: MutableInspect) => { evidence[0].HostConfig.SecurityOpt = []; }],
    ["published port", (evidence: MutableInspect) => {
      evidence[0].HostConfig.PortBindings = { "8080/tcp": [{ HostPort: "8080" }] };
    }],
    ["publish-all", (evidence: MutableInspect) => { evidence[0].HostConfig.PublishAllPorts = true; }],
    ["host gateway", (evidence: MutableInspect) => {
      evidence[0].HostConfig.ExtraHosts = ["host.docker.internal:host-gateway"];
    }],
    ["device", (evidence: MutableInspect) => { evidence[0].HostConfig.Devices = [{ PathOnHost: "/dev/null" }]; }],
    ["device request", (evidence: MutableInspect) => { evidence[0].HostConfig.DeviceRequests = [{ Count: -1 }]; }],
    ["legacy bind mount channel", (evidence: MutableInspect) => { evidence[0].HostConfig.Binds = ["/:/host"]; }],
    ["volumes-from mount channel", (evidence: MutableInspect) => { evidence[0].HostConfig.VolumesFrom = ["other"]; }],
    ["custom DNS", (evidence: MutableInspect) => { evidence[0].HostConfig.Dns = ["8.8.8.8"]; }],
    ["dead process state", (evidence: MutableInspect) => { evidence[0].State.Dead = true; }],
    ["unexpected health state", (evidence: MutableInspect) => { evidence[0].State.Health = { Status: "starting" }; }],
    ["runtime mount", (evidence: MutableInspect) => { evidence[0].Mounts[0].RW = !evidence[0].Mounts[0].RW; }],
    ["host mount", (evidence: MutableInspect) => {
      evidence[0].HostConfig.Mounts[0].ReadOnly = !evidence[0].HostConfig.Mounts[0].ReadOnly;
    }],
    ["mount nocopy", (evidence: MutableInspect) => {
      const mount = evidence[0].HostConfig.Mounts.find((entry: Record<string, any>) => entry.Type === "volume");
      mount.VolumeOptions.NoCopy = !mount.VolumeOptions.NoCopy;
    }],
  ])("rejects a changed %s before the selected container is trusted", (_label, mutate) => {
    const value = plan();
    const evidence = inspect(value, { running: true });
    mutate(evidence);
    expect(() => validateSessionContainerInspect(
      JSON.stringify(evidence),
      value,
      { kind: "provisioning-running" },
    )).toThrow();
    expectNonTransientRunningFailure(JSON.stringify(evidence), value);
  });

  test("rejects extra, missing, wrong, and IPv6 network attachments", () => {
    const value = plan();
    const networkKey = `${value.expectedProject.composeProject}_agent_internal`;
    for (const mutate of [
      (evidence: MutableInspect) => { evidence[0].NetworkSettings.Networks = {}; },
      (evidence: MutableInspect) => {
        evidence[0].NetworkSettings.Networks.extra = {
          NetworkID: "3".repeat(64),
          IPAddress: "172.31.90.21",
          IPAMConfig: { IPv4Address: "172.31.90.21", IPv6Address: "" },
          GlobalIPv6Address: "",
        };
      },
      (evidence: MutableInspect) => {
        evidence[0].NetworkSettings.Networks[networkKey].NetworkID = "3".repeat(64);
      },
      (evidence: MutableInspect) => {
        evidence[0].NetworkSettings.Networks[networkKey].IPAddress = "172.31.90.21";
      },
      (evidence: MutableInspect) => {
        evidence[0].NetworkSettings.Networks[networkKey].IPAMConfig.IPv4Address = "172.31.90.21";
      },
      (evidence: MutableInspect) => {
        evidence[0].NetworkSettings.Networks[networkKey].IPAMConfig.IPv6Address = "fd00::20";
      },
      (evidence: MutableInspect) => {
        evidence[0].NetworkSettings.Networks[networkKey].IPAMConfig.LinkLocalIPs = ["169.254.10.20"];
      },
      (evidence: MutableInspect) => {
        evidence[0].NetworkSettings.Networks[networkKey].IPAMConfig.Unexpected = "accepted-by-Docker";
      },
      (evidence: MutableInspect) => {
        evidence[0].NetworkSettings.Networks[networkKey].GlobalIPv6Address = "fd00::20";
      },
    ]) {
      const evidence = inspect(value, { running: true });
      mutate(evidence);
      expect(() => validateSessionContainerInspect(
        JSON.stringify(evidence),
        value,
        { kind: "provisioning-running" },
      )).toThrow();
      expectNonTransientRunningFailure(JSON.stringify(evidence), value);
    }
  });

  test.each([
    ["requested IPv4", (network: Record<string, any>) => { network.IPAMConfig.IPv4Address = "172.31.90.21"; }],
    ["requested IPv6", (network: Record<string, any>) => { network.IPAMConfig.IPv6Address = "fd00::20"; }],
  ])("rejects a changed %s on an otherwise-running endpoint", (_label, mutate) => {
    const value = plan();
    const networkName = `${value.expectedProject.composeProject}_agent_internal`;
    const running = inspect(value, { running: true });
    mutate(running[0].NetworkSettings.Networks[networkName]);
    expect(() => validateSessionContainerInspect(
      JSON.stringify(running),
      value,
      { kind: "provisioning-running" },
    )).toThrow("requested network identity differs");
  });

  test("requires the live endpoint address on every minted proof", () => {
    const value = plan();
    const networkName = `${value.expectedProject.composeProject}_agent_internal`;
    const running = inspect(value, { running: true });
    running[0].NetworkSettings.Networks[networkName].IPAddress = "";
    expect(() => validateSessionContainerInspect(
      JSON.stringify(running),
      value,
      { kind: "provisioning-running" },
    )).toThrow("running session container network identity differs");
  });

  test.each([
    ["missing start time", (evidence: MutableInspect) => { delete evidence[0].State.StartedAt; }, /state inspection is malformed/i],
    ["zero start time", (evidence: MutableInspect) => { evidence[0].State.StartedAt = "0001-01-01T00:00:00Z"; }, /start time is malformed/i],
    ["non-exact start time", (evidence: MutableInspect) => { evidence[0].State.StartedAt = "Sat, 08 Aug 2026 12:00:05 GMT"; }, /start time is malformed/i],
    ["missing endpoint id", (evidence: MutableInspect) => {
      const networkName = `${plan().expectedProject.composeProject}_agent_internal`;
      delete evidence[0].NetworkSettings.Networks[networkName].EndpointID;
    }, /endpoint id must be an exact Docker object id/i],
    ["malformed endpoint id", (evidence: MutableInspect) => {
      const networkName = `${plan().expectedProject.composeProject}_agent_internal`;
      evidence[0].NetworkSettings.Networks[networkName].EndpointID = "short";
    }, /endpoint id must be an exact Docker object id/i],
  ])("rejects a running proof with %s", (_label, mutate, error) => {
    const value = plan();
    const running = inspect(value, { running: true });
    mutate(running);
    expect(() => validateSessionContainerInspect(
      JSON.stringify(running),
      value,
      { kind: "provisioning-running" },
    )).toThrow(error);
  });

  test("accepts every bounded running endpoint representation emitted by supported Docker backends", () => {
    const value = plan();
    const networkId = value.effectiveControlPlane.networkIds.agentInternal;
    const networkName = `${value.expectedProject.composeProject}_agent_internal`;
    const variants: MutableInspect[] = [];

    for (const linkLocalIPs of [null, []]) {
      const evidence = inspect(value, { running: true });
      evidence[0].NetworkSettings.Networks[networkName].IPAMConfig.LinkLocalIPs = linkLocalIPs;
      variants.push(evidence);
    }
    const keyedById = inspect(value, { running: true });
    keyedById[0].NetworkSettings.Networks[networkId] = keyedById[0].NetworkSettings.Networks[networkName];
    delete keyedById[0].NetworkSettings.Networks[networkName];
    variants.push(keyedById);
    const explicitEmptyIpv6 = inspect(value, { running: true });
    explicitEmptyIpv6[0].NetworkSettings.Networks[networkName].IPAMConfig.IPv6Address = "";
    variants.push(explicitEmptyIpv6);

    for (const evidence of variants) {
      expect(() => validateSessionContainerInspect(
        JSON.stringify(evidence),
        value,
        { kind: "provisioning-running" },
      )).not.toThrow();
    }
  });

  test("rejects oversized inspect output before attempting JSON parsing", () => {
    const value = plan();
    const oversizedMalformedJson = "{".repeat(SESSION_CONTAINER_INSPECT_MAX_BYTES + 1);
    expect(() => validateSessionContainerInspect(
      oversizedMalformedJson,
      value,
      { kind: "provisioning-running" },
    )).toThrow("inspection exceeds the size limit");
  });

  test.each([
    { kind: "provisioning-running" },
    { kind: "active-running" },
  ] as const)("classifies an exact created container as transient for $kind", (phase) => {
    const value = plan();
    expect(() => validateSessionContainerInspect(
      JSON.stringify(inspect(value)),
      value,
      phase,
    )).toThrow(SessionContainerNotRunningYetError);
  });

  test.each([
    ["exited", (evidence: MutableInspect) => { evidence[0].State.Status = "exited"; }],
    ["dead", (evidence: MutableInspect) => { evidence[0].State.Dead = true; }],
    ["restarting", (evidence: MutableInspect) => { evidence[0].State.Restarting = true; }],
    ["OOM-killed", (evidence: MutableInspect) => { evidence[0].State.OOMKilled = true; }],
    ["errored", (evidence: MutableInspect) => { evidence[0].State.Error = "runtime failure"; }],
    ["nonzero exit", (evidence: MutableInspect) => { evidence[0].State.ExitCode = 137; }],
    ["malformed", (evidence: MutableInspect) => { delete evidence[0].State.Pid; }],
  ])("does not classify a %s process state as transient", (_label, mutate) => {
    const value = plan();
    const evidence = inspect(value);
    mutate(evidence);
    expectNonTransientRunningFailure(JSON.stringify(evidence), value);
  });

  test("rejects non-running Docker state mismatches", () => {
    const value = plan();
    const cases: Array<{
      evidence: MutableInspect;
      phase: SessionContainerProofPhase;
    }> = [
      { evidence: inspect(value), phase: { kind: "provisioning-running" } },
      { evidence: inspect(value, { running: true }), phase: { kind: "provisioning-running" } },
      { evidence: inspect(value, { running: true }), phase: { kind: "active-running" } },
    ];
    cases[0].evidence[0].State.Status = "paused";
    cases[1].evidence[0].State.Pid = 0;
    cases[2].evidence[0].State.Status = "exited";
    for (const entry of cases) {
      expect(() => validateSessionContainerInspect(
        JSON.stringify(entry.evidence),
        value,
        entry.phase,
      )).toThrow();
    }
  });

  test("accepts allowed inherited metadata and environment ordering", () => {
    const value = plan();
    const evidence = inspect(value, { running: true });
    evidence[0].Config.Env.reverse();
    evidence[0].Config.Labels["project.custom-label"] = "untrusted-but-inert";
    expect(() => validateSessionContainerInspect(
      JSON.stringify(evidence),
      value,
      { kind: "provisioning-running" },
    )).not.toThrow();
  });

  test("rejects independently supplied environment and mount projections", () => {
    const value = plan();
    for (const forged of [
      { ...value, environment: { ...value.environment, HTTPS_PROXY: "http://attacker:8080" } },
      { ...value, mounts: value.mounts.slice(1) },
    ] as unknown as SessionContainerCreatePlan[]) {
      expect(() => validateSessionContainerInspect(
        JSON.stringify(inspect(value, { running: true })),
        forged,
        { kind: "provisioning-running" },
      )).toThrow("was not minted");
    }
  });

  test("rejects an unknown proof phase", () => {
    const value = plan();
    expect(() => validateSessionContainerInspect(
      JSON.stringify(inspect(value)),
      value,
      { kind: "unexpected" } as never,
    )).toThrow("proof phase is invalid");
  });
});
