import type * as childProcess from "node:child_process";

import type { ProjectInfo } from "../config.ts";
import type { RuntimeNetwork } from "../network.ts";
import type { TokenResolutionReceipt } from "../token-resolution.ts";
import type { DependencyOverlayPlan } from "./dependency-overlays.ts";
import type { RuntimeComponentState } from "./component-state.ts";
import type { ControlPlaneGenerationV2, RuntimeGenerationTargetV2 } from "./component-state-v2.ts";
import type { GitRepositoryShape, RuntimeGitLayoutPlan } from "./git-layout.ts";

export type { TokenResolutionReceipt } from "../token-resolution.ts";

// Schema-v1 composite component identity. Post-cutover this is container-label
// migration evidence only (legacy runtimes met by a current binary); startup
// validation proofs bind the schema-v2 control-plane generation instead, so a
// session-only input change cannot invalidate control-plane authority.
export type RuntimeValidationComponents = Pick<RuntimeComponentState,
  | "digestSchemaVersion"
  | "selectedAgentImageInputDigest"
  | "proxyImageInputDigest"
  | "topologyDigest"
  | "runtimeGenerationDigest">;

export type RuntimeContext = {
  projectRoot: string;
  project: ProjectInfo;
  runtimeRoot: string;
  baseRuntimeRoot?: string;
  agentImage?: string;
  runtimeComponents?: RuntimeComponentState;
  runtimeGenerationV2?: RuntimeGenerationTargetV2;
  dependencyOverlayPlan?: DependencyOverlayPlan;
  dependencyOverlayPlanChanged?: boolean;
  gitRepositoryShape?: GitRepositoryShape;
  gitLayoutPlan?: RuntimeGitLayoutPlan;
  gitLayoutPlanChanged?: boolean;
  validatedRuntime?: {
    // The exact schema-v2 control-plane generation the validation covered.
    // Deliberately excludes session-agent inputs: sessions are attested by
    // admission, and a template or agent-image roll must not turn a proved
    // control plane stale.
    components: ControlPlaneGenerationV2;
    contractHash?: string;
    mcpOAuthCallbackPort: number;
    mcpOAuthCallbackTopologyVersion: 2;
    projectId: string;
    proofVersion?: 4;
    proxyId: string;
  };
  env?: NodeJS.ProcessEnv;
  network?: RuntimeNetwork;
};

export type CaptureResult = {
  status: number;
  stdout: string;
  stderr: string;
};

// The fixed set of internal admin actions the runtime issues in-process. The
// orchestration builds these typed intents at the call site (no argv strings),
// and the executor dispatches each straight to the typed admin enforcement. See
// the spec's "Programmatic callers speak intent, not strings."
export type RuntimeAdminIntent =
  | { kind: "converge-proxy-policy" }
  | { kind: "ensure-agent-service"; id: string; quiet: boolean }
  | { kind: "token-sync"; verbose: boolean }
  | { kind: "prepare-token-sources" }
  | { kind: "prepare" };

export type PiProviderChoice = "agent-codex" | "agent-claude" | "configure" | "custom";
export type PiProviderOption = Readonly<{ label: string; value: PiProviderChoice }>;

export type RuntimeIO = {
  prepareTokenSources?(context: RuntimeContext): Promise<void>;
  admitPreparedTokenSources?(context: RuntimeContext): void;
  clearPreparedTokenSources?(context: RuntimeContext): void;
  run(command: string, args: string[], options?: childProcess.SpawnSyncOptions): number;
  capture(command: string, args: string[], options?: childProcess.SpawnSyncOptions): CaptureResult;
  commandExists(command: string, options?: childProcess.SpawnSyncOptions): boolean;
  confirm(question: string): boolean;
  choosePiProvider?: (options: readonly PiProviderOption[]) => PiProviderChoice | undefined;
  isInteractive?: () => boolean;
  admin(intent: RuntimeAdminIntent, context: RuntimeContext): Promise<number>;
  startTokenAutoRefresh?: (context: RuntimeContext, receipts?: TokenResolutionReceipt[]) => { stop: () => void };
  takeTokenResolutionReceipts?: () => TokenResolutionReceipt[];
};

export type ComposeContainer = {
  id: string;
  networks: string[];
};

export type DockerPortBinding = {
  HostIp?: string;
  HostPort?: string;
};

export type DockerPortBindings = Record<string, DockerPortBinding[] | null | undefined>;

export type DockerContainerInspect = {
  Config?: {
    Cmd?: string[] | null;
    Entrypoint?: string[] | string | null;
    Env?: string[] | null;
    Image?: string;
    Labels?: Record<string, string> | null;
    User?: string;
  };
  Id?: string;
  Image?: string;
  Name?: string;
  State?: {
    Error?: string;
    ExitCode?: number;
    OOMKilled?: boolean;
    Running?: boolean;
    Status?: string;
  };
  HostConfig?: {
    AutoRemove?: boolean;
    Binds?: string[] | null;
    CapAdd?: string[] | null;
    CapDrop?: string[] | null;
    NetworkMode?: string;
    PidsLimit?: number;
    PortBindings?: DockerPortBindings | null;
    Privileged?: boolean;
    ReadonlyRootfs?: boolean;
    SecurityOpt?: string[] | null;
    Tmpfs?: Record<string, string> | null;
  };
  Mounts?: Array<{
    Destination?: string;
    Mode?: string;
    Name?: string;
    Propagation?: string;
    RW?: boolean;
    Source?: string;
    Type?: string;
  }> | null;
  NetworkSettings?: {
    Networks?: Record<string, { NetworkID?: string; Gateway?: string; IPAddress?: string; GlobalIPv6Address?: string }>;
    Ports?: DockerPortBindings | null;
  };
};

export type DockerNetworkInspect = {
  Attachable?: boolean;
  ConfigFrom?: { Network?: string };
  ConfigOnly?: boolean;
  Driver?: string;
  EnableIPv4?: boolean;
  Id?: string;
  Ingress?: boolean;
  Labels?: Record<string, string>;
  Containers?: Record<string, { Name?: string; IPv4Address?: string }>;
  EnableIPv6?: boolean;
  IPAM?: {
    Config?: Array<{
      AuxiliaryAddresses?: Record<string, string> | null;
      Gateway?: string;
      IPRange?: string;
      Subnet?: string;
    }>;
    Driver?: string;
    Options?: Record<string, string> | null;
  };
  Internal?: boolean;
  Name?: string;
  Options?: Record<string, unknown>;
  Scope?: string;
};

export type RuntimeContainer = {
  id: string;
  service: string;
  composeProject?: string;
  imageRef?: string;
  projectId?: string;
  digestSchemaVersion?: string;
  agentImageInputDigest?: string;
  proxyImageInputDigest?: string;
  topologyDigest?: string;
  /** @deprecated Legacy digest-schema containers only. */
  runtimeDigest?: string;
  running?: boolean;
};

export type ActiveAgentSession = {
  agentCommand?: string;
  command: string;
  containerTty: string;
  hostTermProgram?: string;
  hostTty?: string;
  name: string;
  sessionId?: string;
  startedAt?: string;
  processCount: number;
  /** The host status stamp's `aliveUntil`, when the heartbeat owner reports `served`. */
  servedUntil?: string;
  /** The host status stamp's `lastHeartbeatAt`, when the heartbeat owner reports `retrying`. */
  notServedSince?: string;
};

export type SessionProcess = {
  command: string;
  pid: number;
  score: number;
};

export type SessionMetadata = {
  id: string;
  projectRoot: string;
  composeProject: string;
  command: string;
  name: string;
  agentCommand?: string;
  hostPid: number;
  // The boot `hostPid` was recorded on, when the platform can prove one. Absent
  // in metadata written before this field existed, and on platforms with no
  // boot identity; readers must fall back to a PID-only check there.
  //
  // Host process identity is persisted as independent, optional, platform-
  // tagged sibling fields rather than as one nested `hostProcessIdentity`
  // record, because the probes behind them succeed and fail independently: a
  // Linux host can expose `/proc/sys/kernel/random/boot_id` while `hidepid`
  // hides `/proc/<pid>/stat`, and a macOS host can answer `sysctl` while `ps`
  // fails. A record with two required members can only say "both or neither",
  // which forces a writer holding one proof to discard it; a nested record with
  // two optional members spells "nothing known" two ways (absent, and `{}`).
  // Independent optional siblings have exactly one encoding per knowledge
  // state, and absence is the single spelling of "cannot prove" that
  // `recordedOnPreviousBoot(undefined)` already answers `false` for.
  //
  // The consequence to preserve: the process-start half of identity — which
  // makes PID reuse *within* one boot decidable, and which
  // `hostSessionProcessAlive` still lacks — lands as one more optional sibling
  // (`hostProcessStart?: string`, `linux:<jiffies>` / `darwin:<epoch-ms>`), not
  // as a reshaping of this record. Each stamp carries its own platform tag so
  // values from different platforms and different sources can never compare
  // equal, which is the safety the grouping record would otherwise have
  // provided. Combining the two is a reader policy, not a record shape: a
  // differing boot is decisive alone, while a differing process start is
  // decisive only once the boot is known equal, because a `/proc` start time is
  // measured in jiffies since boot.
  hostBootId?: string;
  hostProcessStart?: string;
  // Present only for sessions launched as per-session containers through the
  // admission path: the exact Docker container name the lifecycle record bound.
  // For those sessions `id` equals the lifecycle record's `sessionId`, which is
  // the durable correlation; this field is display/diagnostic provenance, not
  // an identity readers may trust on its own.
  sessionContainerName?: string;
  // The exact conversation an admission-path resume launch was started for,
  // host-validated at launch time. If the host dies during the resumed
  // session, this lineage makes the surviving evidence an exact-resume item
  // for the same conversation rather than a less precise picker item.
  resumeConversationId?: string;
  hostInbox: string;
  containerInbox: string;
  hostParentPid?: number;
  hostTty?: string;
  termProgram?: string;
  termProgramVersion?: string;
  termSessionId?: string;
  itermSessionId?: string;
  wtSession?: string;
  startedAt: string;
  lastSeenAt: string;
  endedAt?: string;
  exitStatus?: number;
  outcome?: "interrupted";
};
