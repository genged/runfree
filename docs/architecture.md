# Architecture

Runfree is a local runtime manager for sandboxed coding-agent sessions. Docker Compose owns the trusted per-project proxy and networks. Each command runs in an untrusted direct session container.

## ASCII Diagrams

### Runtime Topology

```text
HOST
+--------------------------------------------------------------------------------+
| Project root                                                                   |
|   source tree                                                                  |
|   .runfree/runfree.json                                                        |
|   .runfree/network-policy.json                                                 |
|   .runfree/image/Dockerfile (optional)                                         |
|                                                                                |
| runfree CLI                                                                    |
|   - blocks incompatible runtime changes while sessions are active              |
|   - records exact approvals and compiles immutable effective controls          |
|   - resolves host-owned credential sources                                     |
|   - materializes embedded runtime assets                                       |
|   - starts Docker Compose project runfree-<project-id>                         |
|   - admits, renews, and revokes per-session containers                         |
|                                                                                |
| XDG config/state/data                                                          |
|   approvals, effective controls, sources, sessions, proxy CA, runtime assets    |
+--------------------------------------+-----------------------------------------+
                                       |
                                       v
DOCKER: project runfree-<project-id>
+--------------------------------------------------------------------------------+
| session containers (untrusted,         proxy (Compose, trusted boundary)       |
|  one per agent process, not Compose)   +-----------------------------------+   |
| +------------------------------------+ | root firewall (nftables sets)     |   |
| | /workspace project bind mount      | | request proxy uid 1001 on :8080   |   |
| | .runfree is untrusted desired input| | host-owned effective controls     |   |
| | Claude / Codex / Pi / shell tools  | | root-owned session files          |   |
| | placeholders or OAuth handles only | | credential injection              |   |
| | own source IP .20+ = session id    | | denial, audit, approval records   |   |
| +------------------------------------+ +-----------------+-----------------+   |
|   | ... more sessions                                    |                     |
|   |                                                      |                     |
|   +------ agent_internal (internal: true, no egress) ----+                     |
|   |                                                      | proxy_egress        |
|   +-- ingress forwarders (optional: VNC, forward,        v                     |
|       MCP OAuth callback) to host loopback only    upstream HTTPS/WSS hosts    |
+--------------------------------------------------------------------------------+
```

### Policy And Credential Flow

```text
host user
  |
  | runfree credential source add / credential set-source / service enable
  v
runfree CLI on host
  |
  +--> serializes control changes under the project lifecycle lock
  |      (typed desired-policy mutations run beside live sessions, no pause;
  |       lifecycle rebuild/destroy and startup capture defer to live sessions)
  +--> validates typed intent and desired-policy contracts
  +--> records an exact host-owned approval
  +--> compiles and selects paired immutable network/OAuth controls
  +--> records host-owned credential source metadata outside the project
  |
  | runfree credential sync
  v
host-owned source command/env/1Password/JWT/stdin
  |
  | resolved secret value, never written into agent env
  v
proxy-only token state
  |
  v
agent request --> proxy strips inbound auth headers --> policy allow? --> token inject? --> upstream
                 |                                  |
                 |                                  +--> deny before upstream/token read
                 +--> agent sees placeholders or OAuth handles, not real tokens
```

### Write Approval Flow

```text
agent request
  |
  v
proxy request classifier
  |
  +--> read-class request -------------------------------> upstream if otherwise allowed
  |
  +--> write-class request
          |
          +--> writeAction=allow ------------------------> upstream if otherwise allowed
          +--> writeAction=deny -------------------------> synthetic denial
          +--> writeAction=ask
                    |
                    v
              pending approval record in proxy-side state
                    |
                    | runfree approvals --watch / runfree approve <id>
                    v
              host-owned decision record
                    |
                    +--> approve ------------------------> upstream
                    +--> deny or timeout ----------------> synthetic denial
```

### Runtime Asset Pipeline

```text
canonical runtime sources
  |
  +--> packages/agent-runtime/agent/
  +--> packages/proxy/src/ and packages/proxy/Dockerfile
  +--> packages/cli/templates/
  |
  | pnpm run build:runtime
  v
dist/runtime/**
  |
  | pnpm run generate:assets
  v
packages/cli/src/embedded-assets.generated.ts
  |
  | runfree CLI materializes current version
  v
XDG data runtime asset directory
  |
  v
Docker Compose files, Dockerfiles, proxy bundle, templates used by runfree up
```

## Design Principles

1. **The agent container is untrusted.** It can read and edit the mounted project, including desired `.runfree` input, run tools, and make requests through configured proxy variables, but it cannot select approvals, publish effective controls, or read real service tokens.
2. **The proxy is the egress and credential boundary.** Network decisions and credential injection happen in the proxy before upstream connection and before any token value is read for injection.
3. **Runtime authority is host-owned.** Project desired policy is inert until host-side review selects exact subject digests and publishes an immutable effective generation.
4. **Project policy is explicit.** `.runfree/network-policy.json` is desired policy v2: exact direct hosts plus complete service, request, write-action, and credential-destination intent. There are no wildcard hosts.
5. **Runtime state is per project.** Docker resources, generated agent state, proxy CA material, token sync state, and session metadata are scoped by the project id.

## Main Components

### Host CLI

The TypeScript CLI lives under `packages/cli/src/`. It is responsible for:

- parsing typed yargs commands;
- creating `.runfree/runfree.json`;
- validating and safely writing desired `.runfree/network-policy.json`;
- capturing stable candidates, recording exact approvals, and publishing
  paired immutable effective network/OAuth controls under XDG state;
- managing services, hosts, tokens, host-owned sources, MCP approvals, and diagnostics;
- materializing embedded runtime assets into the XDG data/state directories;
- starting, rebuilding, stopping, and destroying Docker Compose resources.

Command modules under `packages/cli/src/commands/` build typed intents. Shared enforcement lives under `packages/cli/src/admin/`, `packages/cli/src/runtime*`, and runtime contract packages.

### Agent Container

The `agent` service is the workspace where Claude Code, Codex, Pi, shells, build tools, package managers, MCP clients, and project commands run. The project is mounted at `/workspace`.

The default project config runs agent CLIs in their less-restrictive native modes because Runfree supplies the outer container/proxy boundary:

```json
{
  "agents": {
    "default": "claude",
    "claude": { "command": "claude --dangerously-skip-permissions --add-dir /runfree/inbox" },
    "codex": { "command": "codex -c check_for_update_on_startup=false --dangerously-bypass-approvals-and-sandbox" },
    "pi": { "command": "pi" }
  }
}
```

`.runfree/` is ordinary writable project content visible through `/workspace`.
It is desired input, never a trusted runtime mount. Runtime-generated per-agent
config, effective environment, and state are mounted from Runfree-owned
locations rather than from host-wide home directories.

### Proxy Container

The `proxy` service is the trusted network boundary. It enforces:

- exact-host HTTPS/WSS allowlisting;
- request methods and request path prefixes;
- Git push classification and optional denial;
- operation-aware read/write classification for declared endpoints;
- GraphQL query/mutation classification for declared GraphQL paths;
- write actions: `allow`, `ask`, or `deny`;
- credential header stripping and proxy-managed credential injection;
- OAuth handle mediation;
- structured denial logs for `runfree doctor`.

The proxy reads a stable read-only XDG effective-control parent. Its strict
`active.json` selects one generation containing paired network and OAuth
policy; direct project policy and independent OAuth mounts are absent. The
proxy also reads proxy-side token state. It does not rely on agent environment
variables as an enforcement mechanism.

### Runtime Contracts

Shared policy types and validators live under `packages/runtime-contracts/src/`.
Desired policy v2 is a strict authoring contract; the compiler emits the
narrow effective proxy contract, which intentionally has no desired-only
`version` or `services` fields. The CLI and proxy share effective network,
OAuth mediation, write-approval, status, and generation contracts.

### Embedded Runtime Assets

Canonical runtime source lives in:

- `packages/agent-runtime/agent/` for agent-side runtime files, including the
  session entry (`session-entry.sh`) that gates the agent's start on
  activation, and `packages/agent-runtime/src/` for the TypeScript readiness
  probe it runs, compiled by `tsc` into `agent/session-ready-probe.cjs`;
- `packages/proxy/src/` and `packages/proxy/Dockerfile` for the proxy;
- `packages/cli/templates/` for initial project templates.

`pnpm run build:runtime` assembles `dist/runtime/**`. `pnpm run generate:assets` embeds those assets into `packages/cli/src/embedded-assets.generated.ts`. The CLI materializes the embedded version into an XDG data directory before starting Docker Compose.

Both the path set and the file mode of every runtime asset are declared in `RUNTIME_ASSET_DESCRIPTORS` (`scripts/build-runtime.ts`), and the build applies the declared mode rather than inheriting one from the source file or from a freshly created file's umask. Assets are `0644` except the host helper `agent/inspect-active-sessions.sh`, which is `0755`; the agent image chmods its own copied scripts. This keeps the assembled tree — and the component input digests taken over it — a pure function of the repository, so the same commit yields the same embedded manifest on any machine. `assertGeneratedRuntimeManifest` rejects a generated tree whose modes, paths, or Dockerfile sources drift from the declaration.

Embedded runtime identity is component-specific. Agent-image inputs, proxy-image inputs, rendered topology, and host helpers have separate SHA-256 identities. The fixed control plane and session-agent template have separate immutable v2 materializations under XDG state. Each session materialization contains its canonical template artifact and binds that artifact's hash. Atomic selection records distinguish the validated control plane from the desired materialization for new sessions.

Do not edit generated runtime assets by hand.

## Project Files And State

| Location | Owner | Purpose |
| --- | --- | --- |
| `.runfree/runfree.json` | project | config version, agents, and non-network runtime options |
| `.runfree/network-policy.json` | project | writable desired policy v2; direct hosts and complete service/request/credential intent |
| `.runfree/network-policy.local.json` | project (ignored) | writable checkout-local desired overlay |
| `.runfree/image/Dockerfile` | project | optional project image extension over `RUNFREE_BASE_IMAGE` |
| XDG config root | host | host-owned sources and user-defined service definitions |
| XDG data root | host | materialized runtime assets |
| XDG state root | host | approvals, immutable effective controls, runtime generations, sessions, agent state, token sync state, proxy CA material |
| Docker volumes | Docker | dependency overlays, runtime volumes |
| Docker Compose project | Docker | fixed `proxy`, networks, and named volumes; session agents are direct containers |

The project id is a stable hash of the resolved project path. `runfree project-id --compose-name` prints the Docker Compose project name.

## Generation Families

Runfree has more than one content-addressed "generation", and they are
different authority families. Always name the family; the bare phrase
"control generation" is ambiguous and retired from docs and specs.

| Family | Serialized key | What it identifies | Source |
| --- | --- | --- | --- |
| Effective policy generation | `controlGeneration` | The compiled, immutable host/proxy policy generation built from approved `.runfree/` desired policy: network policy, OAuth mediation policy, agent environment, runtime control. | `packages/cli/src/control/effective.ts` |
| Control plane generation | `controlPlaneGenerationDigest` | The runtime control plane a session binds to: proxy image, Compose topology, and admission contract epoch. | `packages/cli/src/runtime/component-state-v2.ts` |
| Temporary access generation | (reserved) | Session-scoped temporary network access records; designed, not yet built. | — |

The serialized keys are frozen wire and never renamed; code identifiers and
prose say "effective policy generation" for the first family so it cannot be
confused with the control plane family. A live policy change advances the
effective policy generation only — it neither invalidates held session
admission authority nor implies a control plane replacement.

## Runtime Lifecycle

A typical `runfree` invocation does the following:

1. Resolve the project root and read `.runfree/runfree.json`.
2. Refuse a pre-v4 config or a removed legacy key with the remedy (move
   `.runfree` aside and run `runfree init`); nothing repairs or migrates it.
3. For built-in Claude/Codex launches, review any missing credentialless
   operational service without overwriting stricter user write rules.
4. If a per-session agent is active, reuse the verified selected effective
   controls without reading desired project input. Otherwise, capture strict
   desired project and checkout-local candidates.
5. Select exact approved network, runtime-isolation, and project-image subjects;
   non-interactive authority expansion fails with the exact approval command.
6. Compile and atomically select an immutable host/proxy effective policy generation,
   including paired network/OAuth policy and generated agent environment.
7. Materialize embedded assets, compute component-specific runtime identities,
   and classify the narrowest safe runtime upgrade.
8. Build missing input-addressed images and publish an immutable runtime
   materialization before changing live containers.
9. Create or update the proxy-only Compose control plane, validate topology and component identity, and
   prove request-proxy/firewall acknowledgement of the selected control.
10. Resolve approved credential sources and converge proxy-only values.
11. Create an admitted session container for the requested command; on exit, print blocked-host feedback
    unless `--quiet` is used.

When `up` or a launch starts the runtime under the project lifecycle lock, and when `runtime reload-policy --force` restores admission, Runfree first sweeps ephemeral helpers that a dead CLI left behind, when the host helper marker says one may exist. It removes this project's helper-labeled containers before any new helper runs or any session is admitted (see [Ephemeral Helpers](#ephemeral-helpers)).

Agent-image or session-template changes select a new desired session materialization. Existing sessions keep their exact image and template until they end. New sessions use the new materialization without replacing the proxy.

A compatible proxy change starts a deny-all candidate, revalidates each live session, rewrites each host lifecycle record with the candidate's control plane generation digest, and publishes the project's session eligibility into the candidate before it selects it. Nothing is republished on the sessions' behalf: each surviving session's own next heartbeat writes its file into the candidate. An incompatible admission epoch or control-plane topology blocks the rolling change while sessions remain. Explicit rebuild keeps its confirmation contract.

The compatible active-session restart path is enabled: a compatible proxy replacement rolls under live sessions through the durable rebind transaction, and only incompatible admission-epoch or control-plane topology changes wait for sessions to drain. Recovery of an already-started durable rebind resumes under its lifecycle-lock fence.

A surviving session's launch process rebinds its own held authority after that transaction completes. Before each heartbeat it compares its held proxy container ID and control plane generation digest with the durable selection, and on a change it adopts exactly one completed compatible rebind of its own session — the durable candidate selection plus its registry record advanced only by the rebind writer's fields — and then beats and revokes against the new proxy. Any other divergence between held and durable authority refuses before any durable write, and the next launch reclaims the residue.

Startup mints one in-memory `PreparedRuntime` after durable selection and live proof agree. Public launches consume that exact authority once. A changed container or selection causes one bounded re-prepare attempt. Credential sync occurs only after this prepared authority exists.

Cleanup uses exact references from selections, lifecycle records, direct containers, and pending rebind state. The proxy's own session files are not a reference source; they gate the whole pass instead, so a session file no lifecycle record claims or a listing the host could not read stops the cleanup. It removes only inspected zero-reference image IDs and materialization paths. Ambiguous containers or unsafe state files stop cleanup. `runfree status` and verbose startup show effective, desired, retained, and pending generations.

`runfree rebuild` recreates the runtime while preserving Compose volumes and
local images. Under its operator confirmation and project lifecycle lock, it
first validates the pending control-plane rebind journal — the one lifecycle
journal that still exists — and identifies runtime-owned ingress
forwarders and pre-ingress VNC sidecars by their complete Docker shape and
immutable image identity. After all refusal gates pass, it removes those
utilities and drains every exact direct session held by the registry or that
validated journal: records become revoking, this project's session files are
deleted from the still-running proxy, proxy
consumers stop, exact record-bound session containers are removed, and Compose
is torn down. It then clears the stale live-container selection and removes the
pending control-plane rebind journal and exact
revoking lifecycle records, in that order. Each authority-changing file
replacement or removal is durable at its containing directory before the next
step starts. A repeated rebuild can therefore resume after any final-state
boundary.
Unreadable or unclaimed evidence is refused with
`runfree destroy --force` as the explicit remedy. `runfree stop` stops
services. `runfree destroy` destroys the whole project runtime under the
project lifecycle lock. Plain destroy proves ordinary utility ownership before
the unclaimed-container refusal gate. After every refusal gate passes, it
revokes recorded session authority file-first, stops the proxy, and removes
session containers by exact record-bound or validated-
journal-bound ID (they are not Compose resources and Compose teardown cannot
see them), runs the Compose
teardown for services, volumes, local images, and orphans, and removes the
effective live-container selection, the rebind journal, and exact records in
the same final order. It deletes this project's session files from the proxy
before the records that reserve their addresses are touched. Live sessions and unclaimed containers carrying the
project’s `io.runfree.project-id` label are refused or only reported unless
`--force` is given. Forced destroy bypasses strict utility ownership cleanup so
malformed utility residue cannot block the explicit project-label residue
sweep. That sweep still stops and removes only the full Docker IDs it enumerates.
Afterward, Runfree removes the ingress bridge only if it carries the minted
ownership labels, its full network ID is exact, and Docker proves it has no
endpoints.

Ingress forwarder replacement or teardown uses the same utility ownership
rule as rebuild. The teardown proof is four facts: the candidate carries this
project's exact project label, its role label names the expected utility role,
its inspected immutable image ID equals Docker's resolved ID for the pinned
ingress image, and removal addresses the inspected full container ID. Names
discover candidates but authorize nothing, and runtime shape is creation
authority rather than deletion authority. The managed ingress host bridge
uses a versioned name and carries minted project and network-role ownership
labels. Runfree validates those labels and the exact full network ID before an
effect and removes the bridge only by that ID. A foreign-labeled lookalike is
refused without a Docker mutation. Runfree still inspects a new bridge for its
complete local-bridge shape before it starts a listener, removing an
unsupported new bridge by Docker's returned full ID, and validates every
endpoint on the current managed bridge before it removes a forwarder or the
bridge. Partial or conflicting ownership labels are always
refused. Containers or networks from retired sidecar generations carry no
recognition: they are refused as unclaimed residue rather than recognized,
and only the explicit forced sweep removes them.

Config version 4 is the desired/effective cutover.

### Session Admission

The runtime admits one agent process per container, each with its own address
on `agent_internal`, and this is the launch path. Every public command —
`runfree claude`/`codex`/`pi`, `runfree shell`, `runfree resume`, and
`runfree mcp auth` — reaches it through `session-public-launch.ts`; the
pre-cutover shared long-lived agent no longer exists. See
[Security](security.md) for the identity and proof model and for what it does
not establish.

Three participants hold the state, and they can disagree only after a crash:

| Holder | State | What it decides |
| --- | --- | --- |
| Proxy (root tmpfs) | `/run/runfree-sessions/sessions/<sessionKey>.json` and `eligibility.json`, root-owned `0644` | whether an address is served right now |
| Proxy (root tmpfs) | per-IP assignment and two consumer acknowledgements under `ip-reuse/` | whether old IP authority has drained before container creation |
| Host (XDG state) | per-session lifecycle records, plus one advisory heartbeat status stamp per session | which address is reserved, and who owns the session |
| Docker | the session container itself | what can still send packets |

The host is the only writer of the proxy files, through one pinned
`docker exec --user 0:0` channel with a digest of the exact payload
([publisher](../packages/cli/src/runtime/session-file-publisher.ts)). Creating
an eligible file admits, rewriting it renews, and deleting it revokes.
Heartbeats do not wait for acknowledgements. New container creation first
waits for an IP fence. A kernel lock and exact prior-state check exclude stale
executors. Retirement requires root firewall exclusion, kernel TCP drain, then fresh
acknowledgements from both consumers. The root-owned assignment remains bound
to the new session key. See [IP Reuse Fence](#ip-reuse-fence).

The root proxy process runs two independent loops. A 100 ms, single-flight,
level-triggered admission loop reads only the root-owned session files, the
eligibility file, IP assignments, local time, and the `session_ipv4` set. It never loads
policy, resolves DNS, handles audit state, or performs upstream I/O. The
existing maintenance loop separately reloads effective policy, resolves
allowed-host addresses, and maintains the allowed and audit sets. A blocked DNS
lookup therefore cannot delay admission, expiry, or revocation, and concurrent
ticks coalesce into one pass over the current directory contents.

The uid-1001 request proxy runs the same rule on its own 100 ms loop over its
own observation map, and serves each connection from the map that loop built
rather than re-reading the directory per connection
([validity rule](../packages/proxy/src/session-file-validity.ts),
[scanner](../packages/proxy/src/session-files.ts)). Neither consumer reads the
other's decision. Their target cadence is 100 ms, but scheduling can delay
either process. Container creation waits for explicit retirement proof and
does not assume a maximum consumer delay.

Proxy startup clears the session and IP assignment directories and removes the eligibility file,
recreates the nftables table, and verifies `session_ipv4` empty before
readiness. Authority returns when the host republishes eligibility and each
surviving session's next heartbeat rewrites its file.

Lifecycle state lives in host-owned records under the per-project XDG state
directory, and the driver's ladder is:

1. **Preflight** binds the exact runtime generation target (control plane plus
   session agent), effective control plane,
   session template, launch target, and image declarations under the project
   lifecycle lock, refuses while a control-plane rebind journal is pending, and
   reconciles the three lists (below) before anything is allocated.
2. **Allocate** picks a source IP the current internal-network baseline does
   not already hold and that no proxy session file named, and writes the
   `allocated` record.
3. **Fence and start** first retires old IP authority through the barrier
   described above. It then creates the container with exact argv, user,
   capability drops, mounts, `--restart no`, and a static address, then starts it
   attached — which is where Docker assigns the address and refuses a
   duplicate. A crash anywhere here leaves one inert record-and-container pair
   the next reconcile reclaims exactly. The container's first process is the
   base image's session entry
   (`/usr/local/libexec/runfree/session-entry`), with the agent launch as its
   argv; it polls the request proxy with the exact readiness request and does
   not exec the agent until the proxy answers `200 active`.
4. **Prove running** takes one post-start inspection, held byte-exact to the
   create plan — image, entrypoint and argv, user, capability drops,
   no-new-privileges, restart policy, every mount and its flags, environment,
   labels, and attachment to exactly one internal network at exactly the
   allocated address. It is the whole admission's only shape proof, and the
   session file's renewal anchor (process id, start time, network endpoint) is
   a projection of it.
5. **Activate** writes the session file and advances the record to `attached`.
   This is the first step that widens what the container may do; within one
   consumer loop the firewall admits the address, the readiness probe gets
   `200 active`, and the agent execs. A failure after the write deletes the
   file again rather than leaving authority behind.
6. **Await completion** releases the lifecycle lock and runs the heartbeat for
   the life of the attached process.
7. **Teardown** stamps the record terminal, deletes the file, disconnects,
   stops, removes the container, and only then removes the record.

The project lifecycle lock covers steps 1–5 and teardown. It is released once
the session is `attached`; it is not held for the interactive process lifetime.
The foreground admission driver requires a `SessionLockManager`; it has no
raw-lock or optional lock-lease input that can retain the project lock across
the attached wait ([driver](../packages/cli/src/runtime/session-admission-driver.ts)).

Image builds, build approvals, and credential-source resolution finish before
startup takes the lifecycle lock. Startup and explicit reload bound held
subprocess work to 90 seconds and refuse acquisition after about 60 seconds.
Prepared credential values must be admitted within 120 seconds of preparation
and used within a further 120 seconds; expired or changed preparation refuses
before a credential write. Ordinary session-file heartbeats take no lock.

**Heartbeat.** Every 30 s while the foreground runs, the owner adopts a
completed compatible rebind if the durable selection changed, inspects the
container, and rewrites its file with a fresh nonce and
`aliveUntil = inspectedAt + lease`. Inspection and write are one sealed
function ([heartbeat](../packages/cli/src/runtime/session-file-heartbeat.ts)),
so no file can be written without a same-call inspection whose answer supplied
its identity fields. Consecutive failures back off from 1 s, doubling to a 30 s
cap with ±20 % jitter. An ordinary beat takes no lifecycle lock at all, so one
session's slowness cannot delay another session's admission or renewal. An
unavailable observation skips the write and lets the previous file run down its
own lease; an inspection that proves a different incarnation, address, network
endpoint, a stopped container, or Docker's definitive "no such container"
deletes the file at once. No beat outcome ends the agent process — the loop's
only power is over this session's file, and an unrenewed file lapses on its
own.

Each beat also rewrites an advisory host status stamp
([stamp](../packages/cli/src/runtime/session-host-status.ts)) recording the
last heartbeat, the granted `aliveUntil`, and whether the last beat was served
or is retrying. The durable record's lease freezes at admission. Lease or
stamp expiry removes no live owner's reservation. Automatic reclamation
requires positive owner-death evidence; unknown owner liveness preserves the
record. A later positive death observation permits the normal cleanup path.

If the attached stream ends, the driver inspects before concluding: the same
anchored incarnation still running means the *view* was lost, and the driver
re-attaches (at most three times in a rolling 60 s window, signals forwarded as
on the original attach, `--no-stdin` for a session that was not launched
interactively). Reaching the cap never ends a proven-running session; the beat
keeps running and reports the container's own exit when it happens.

**Revoke** is one ordered, idempotent sequence shared by the launch owner and
by reconcile ([teardown](../packages/cli/src/runtime/session-file-teardown.ts)):
terminal stamp, delete the file, disconnect, stop with the SIGTERM grace,
remove with `--force`, delete the record, clear the stamp. The file goes first
because it is the authority; the record goes last because it is what reserves
the address. A file delete this host could not perform stops the sequence
there and keeps the record, so the address stays reserved until a later pass
finishes the job. The next container cannot reuse the address until the IP
fence verifies old kernel sockets and consumer authority are gone. Teardown
latency is not a security guard.

**Reconcile** runs at every launch preflight and at `runfree up`, under the
same held lock as the allocation that follows
([reconcile](../packages/cli/src/runtime/session-reconcile.ts)): delete proxy
files no lifecycle record claims, tear down records whose owner is provably
dead, stop and remove session containers no record claims, leave records whose
owner cannot be proved either way (reported, with `runfree destroy --force` as
the named remedy), and republish eligibility from what survived. The proxy's
own listing is the only view of the files, so a listing the host could not read
refuses the launch — naming `runfree up` as the retry — instead of allocating
over files it cannot see. Every address a well-formed file named is handed to
the allocator as reserved, filtered to the pool's own `/24` because the
allocator refuses a reserved address outside its subnet.

`runfree sessions` runs the same observation in report mode: no lock, no
writes, no Docker effects.

**Compatible proxy replacement** uses a schema-v2 rebind journal with eight
forward phases: `prepared`, `proxy-started-deny-all`, `sessions-revalidated`,
`records-rebound`, `eligibility-published`, `control-selected`,
`tokens-synced`, `complete`. Each candidate attempt and participant batch has a
separate revision; exact batch inputs or outputs permit replay; changed records
require a new proved batch; candidate creation carries reserved transaction and
attempt labels so an interrupted creation is discoverable. The record-rebinding
phases stay because the launch baseline refuses any record whose control plane
generation digest differs from the durable selection. `eligibility-published`
publishes into the candidate *before* the selection flips, because a proxy
holding no eligibility file serves nothing. The predecessor proxy is gone from
the moment the candidate is created, in the first phase, so surviving sessions
are unserved from there until each one's next heartbeat adopts the new durable
selection and writes into the candidate — up to one cadence plus adoption,
with no poke and no pre-selected candidate
([rebind coordinator](../packages/cli/src/runtime/control-plane-rebind-coordinator.ts)).

Recovery shares one project-wide allowance of 120 seconds and at most two proxy
creations. Ordinary launches cannot reset it. Use `runfree runtime recover` to
resume a pending transaction, or `runfree runtime recover --retry` to authorize a
new allowance after repair. Retired effect receipts remain in content-addressed
host archives. Recovery preserves the existing session network, CA pair, OAuth
volume, and agent processes. It never replays application writes. A stopped owned
candidate can be removed only after exact inspection; unavailable observations
preserve resources. A recovery that retries a transient observation and then
fails reports the last observation, which carries the first as its `cause`: the
classification that selects a remedy stays the most recent one, and the
observation that started the failure is not discarded with it
([journal](../packages/cli/src/runtime/control-plane-rebind.ts),
[trust receipts](../packages/cli/src/runtime/rebind-trust-receipt.ts),
[containment](../packages/cli/src/runtime/proxy-containment.ts)).

`runfree stop` and `runfree runtime reload-policy` require `--force` when live
or unprovable owners remain, when a control-plane rebind journal is pending, or
when any record carries a terminal host status stamp. Reload of the same proxy
container republishes eligibility, re-proves every surviving session, and lets
the heartbeats refill the session files; when no record can still hold
authority it proves `session_ipv4` empty from the live kernel set before
reporting success. Compatible replacement uses its own transaction
authorization ([disruption guard](../packages/cli/src/runtime/session-disruption.ts),
[restart restoration](../packages/cli/src/runtime/startup.ts)).

Runtime lifecycle commands use bounded lock acquisition retries so they do not
fail on a heartbeat's brief adoption critical section. The durable
`session-renewal-queue/` directory under the project state root holds the
lock-priority tickets for that critical section — its name predates the
heartbeat and no longer describes a renewal: nothing renews under the lock, and
a ticket only lets a waiting session's adoption be served before a fresh
lifecycle acquisition. Tickets grant no lease and no lock ownership; clock
changes cannot discard a live or unknown requester's priority; aged tickets
require proved requester death for automatic reclamation, and otherwise the
requester releases them or the operator repairs the host queue. Startup,
adoption, and explicit reload subprocesses share a 90-second budget within each
held lock span. These are refusal limits, not measured restoration guarantees;
host suspension and filesystem stalls can exceed them
([queue](../packages/cli/src/runtime/session-renewal-queue.ts),
[operation budget](../packages/cli/src/runtime/lifecycle-operation-budget.ts)).

A proved proxy boundary violation permits exact proxy containment under the
lifecycle fence. A failed observation does not authorize Compose teardown.
Containment refuses a container that has the expected 64-hex id but not this
project's id, container-role, and Compose project/service labels. Failed
containment reports unconfirmed safety and stops recovery. Candidate creation
checks the retained network, CA certificate/key identity, and exact project
OAuth volume before it mounts them into the approved proxy image. Existing
sockets and in-flight OAuth exchanges can end; recovery does not replay them.

A record with a terminal host status stamp is an interrupted teardown, not a
session. Plain destroy's record scan excludes it; the session-listing gate
still protects alive or unknown owners. Positive owner-death evidence permits
normal cleanup; for an uncertain owner, `destroy --force` reclaims it.

A project whose control-plane materialization predates the admission contract
cannot be read: `runfree up` refuses with an invalid-component-evidence error
and names `runfree rebuild`. A pre-cutover rebind journal stopped at a retired
acknowledgement phase reads as unreadable evidence; its remedy is
`runfree destroy --force`.

Rebuild confirmation enumerates live per-session lifecycle records. The
post-confirmation check rejects only a newly appeared session; a session exit
or a changing child-process count does not invalidate the confirmation.

Image builds and credential prompts run before startup takes the lifecycle lock.
Startup recaptures configuration, approval, image identities, and the effective
selection before committing the prepared inputs. Credential admission recaptures
the required source set and named-source fingerprints before proxy disruption.
Credential writes recheck the
exact proxy, token-store generation, effective policy, and pending recovery receipt
([startup](../packages/cli/src/runtime/startup.ts),
[credential sync](../packages/cli/src/admin/admin-core.ts)).

Docker attaches a network endpoint at container start rather than at create, so
allocation proves the baseline and the requested address rather than an
endpoint; the exact endpoint identity is bound by the running proof in step 4
and re-proved by every heartbeat.

Session addresses come from a fixed pool inside the internal `/24`, starting at
host `.20` and bounded by the session-container concurrency cap. The low
addresses are not part of that pool. `.10` is the proxy. `.11` and `.12` are
recorded in the per-project `runtime-network.json` but hold no container in the
current topology: `.11` is still used as the target of the proxy's
internal-route probe, and `.12` is unused. Both stay reserved rather than
reclaimed because reclaiming them would change the approved network subject
and the topology digest, forcing every project through re-approval and
recreation for no gain. Any container occupying either address is an unknown
participant and fails session allocation closed.

`make test-live-session-admission-docker-desktop` and its OrbStack counterpart
run the standalone admission tranches against a real daemon. Each built-in
agent is admitted, proved and revoked by a successful admission slice
somewhere in the negative tranche, which rotates the agent across the probes it
already runs rather than repeating one built-in.

Unexpected CLI failures render bounded nested `AggregateError.errors` and
`Error.cause` name/message chains while retaining only the top-level stack.
Expected `CliError` and `AdminExit` behavior is unchanged.

#### Session File Contract

```text
/run/runfree-sessions/sessions/<sessionKey>.json    root-owned 0644  (one per session)
/run/runfree-sessions/eligibility.json              root-owned 0644  (one per proxy)
/run/runfree-sessions/ip-reuse/requests/<ip>.json   root-owned 0644  (IP fence state)
```

A session file carries:

- identity: project, session key, session id and incarnation, source IP,
  container id, internal network id;
- bindings: control plane generation digest, admission contract epoch,
  selected agent image ID, session-agent generation digest;
- display fields for the approval prompt;
- renewal fields: a fresh random `nonce` on every write, the `inspectedAt` of
  the Docker inspection that authorized the write, and
  `aliveUntil = inspectedAt + lease`.

The wire contract is
[session-file.ts](../packages/runtime-contracts/src/session-file.ts). The
parse is exact. It refuses an unknown key, a missing key, a file name that is
not the embedded `sessionKey`, a payload over 8 KiB, and an `aliveUntil` more
than the five-minute maximum lease after `inspectedAt`. The lease is anchored
to the inspection, not to the write, so `docker exec` latency cannot extend
the time between proof and authority.

Every write, delete, and read is one pinned
`docker exec --user 0:0 -i <exact proxy id> node -e <sealed script>` argv. A
sha256 of the exact stdin bytes is a separate argument. There is no shell and
no interpolated path. The script proves the parent directory is root-owned and
not group- or other-writable, writes a temp file with `O_EXCL|O_NOFOLLOW`,
fsyncs it, renames it, fsyncs the directory, and reads the result back. The
uid-1001 request proxy reads the files and cannot write them. The root
firewall checks the owner uid, not the gid.

The eligibility file names the project, control plane generation digest,
admission contract epoch, internal network id, and the agent materializations
that may be admitted. The host publishes it:

- after the control plane is selected and proven, at `runfree up` and at launch;
- after a same-container proxy restart (the restart empties the directory);
- from every reconcile;
- into a rebind candidate before the durable selection flips.

Publication is idempotent. The host records the bytes it last published
against the proxy container ID and its Docker `StartedAt`. Identical bytes cost
no `docker exec`, and a restarted proxy with the same id is always
republished.

**Dual-clock validity.** Each consumer uses the file's wall deadline and a
monotonic bound of `min(aliveUntil − guest now, five minutes)`. The monotonic
bound is fixed when a given `nonce` is first observed, so replayed bytes extend
neither clock. A new `nonce` is a new observation. If a new `nonce` replaces
an observation that had already expired, the session is served again only
after its old sockets and grants are destroyed. A rewrite that only advances
the lease keeps established sockets and grants. Any change to the bound
identity destroys them.

**Clock caveats.** `performance.now()` is `CLOCK_MONOTONIC`. It does not
advance while the Docker VM is suspended. The wall deadline does elapse, so
after a long host sleep the proxy drops the session on wake and the next
heartbeat re-admits it within seconds. A guest wall clock that is ahead of the
host by more than the lease minus the cadence makes every file expired on
arrival, and the session is not served. A guest clock that is behind keeps a
file valid for longer, but the monotonic bound still caps it at five minutes.
Keep the cadence at or below one third of the lease.

#### Readiness Entry

The container's first process is the base image's `session-entry`, and the
agent launch is its argv. The entry sends one exact readiness request to the
request proxy and execs the agent only on `200` with body `active`:

```text
before the session file   firewall drops the connection   probe: connect failure
admitted, not yet served  request proxy answers 403        probe retries
file served               200 "active"                     entry execs the agent
```

The readiness answer is local. It forwards nothing, resolves nothing, and
grants nothing. The wait bound is `RUNFREE_SESSION_ENTRY_TIMEOUT_MS` (60 s),
rendered by the host. An entry that gives up exits 111. The container stops,
that code becomes the launch exit status, and normal teardown reclaims the
file, container, and record. The entry is cooperation, not enforcement. A
project image may replace it; it then loses only start ordering.

#### IP Reuse Fence

A new container must not inherit authority from an old session on the same
address. Before Docker creates the container, the host runs this barrier under
the lifecycle lock:

```text
host                                   proxy (root firewall + request proxy)
 |  read current assignment for <ip>
 |  write "draining" + nonce1 + new key --> both consumers exclude <ip>
 |                                          firewall verifies nft set excludes <ip>
 |  <-- firewall ack nonce1 --------------
 |  ss -K old TCP sockets to proxy port
 |  ss query: require zero remaining
 |  write nonce2 -----------------------> request proxy drops old mapping,
 |                                        grants, and accepted sockets
 |  <-- ack nonce2 from both -------------
 |  write "ready" (bound to new key)
 |  docker create / start
```

- The executor takes a kernel `flock` on the root-owned IP-assignment
  directory and requires that the assignment still matches the exact bytes
  the host read. It holds the lock through retirement and publication, so a
  delayed exec cannot replace a later assignment. A lock timeout refuses
  creation; retry is safe.
- The ingress listener binds IPv4 explicitly, so the IPv4 `ss` query covers
  it. Linux can keep unaccepted sockets after `ss -K`; the request proxy keeps
  destroying sockets from draining addresses, and the host retries the query
  until its deadline. TIME_WAIT entries carry no stream and do not block reuse.
- The retained assignment binds the IP to the new session key for the proxy
  lifetime. A delayed old session file cannot regain authority.
- A failed fence leaves the address draining and refuses creation. A later
  launch writes a new nonce and repeats the barrier.
- Missing or unsafe assignment directories deny all membership. Proxy startup
  clears assignments together with session authority.

See [publisher](../packages/cli/src/runtime/session-file-publisher.ts),
[assignment reader](../packages/proxy/src/session-ip-reuse.ts), and the
[negative live tests](../tests/runtime/live/session-admission-negative.live.test.ts).

#### Admission Proofs

- A proof exists only if `validateSessionContainerInspect` minted it from an
  exact `docker container inspect`. A private registry holds it by identity,
  so a caller cannot construct or copy one.
- Every consumer re-checks that the proof names this project, session
  incarnation, principal, container, image, control plane and session-agent
  generation digests, source IP, and internal network. A proof that is too old
  cannot authorize an effect.
- The one post-start inspection holds the container to the create plan
  exactly. The session file's renewal anchor (process id, start time, network
  endpoint) is a projection of that inspection.
- The proof reads Docker's answer through one normalization layer. Absent
  zero-value fields resolve to the planned zero value, `CAP_` capability names
  are canonicalized, and Docker Desktop `/host_mnt` bind sources are mapped
  back. The comparison stays exact across daemon releases.
- Between container start and the session file, nothing names the session.
  Its address is in no kernel set and the request proxy refuses it. Docker
  refuses a duplicate static address at start. Taking a session's address
  would need Docker daemon access, which the agent does not have.

#### Ephemeral Helpers

Startup runs the direct-egress deny probes, the trust-bundle render, and
dependency-volume preparation as short `--rm` containers on the untrusted
project agent image ([ephemeral-helper.ts](../packages/cli/src/runtime/ephemeral-helper.ts)).

- **Bounded, under the lock.** A helper starts only while the project lifecycle
  lock is held, with `--pull never` and hardened flags. The Docker client is
  SIGKILLed at the helper timeout: 30 s for the deny probes, 120 s otherwise.
  The lifecycle operation budget can clamp this further.
- **Marked on the host.** Before the spawn, each run writes
  `helpers-pending.json` into the host project state directory. A clean exit
  clears it with no Docker call. The agent has no mount of this path. The
  marker grants nothing; it only tells the next lock holder to sweep.
- **Swept by label under the lock.** After an unclean exit, and at the next
  lock acquisition when the marker is present, Runfree lists containers with
  this project's id and the `ephemeral-helper` role, runs `docker rm --force`
  on them, and polls until the listing is empty. Helpers run only while the
  lock is held, so any helper a lock holder sees is residue. A run that finds
  a marker another lock span left sweeps before it spawns. Every container
  Runfree creates sets its role and project labels explicitly, and an explicit
  label overrides an inherited image `LABEL`, so a project image cannot make a
  session look like a helper. A listing that fails or times out never counts
  as empty; a warning on stderr does not refuse, because stdout is validated
  id by id. An unconfirmed sweep keeps the marker, refuses the launch, and
  names `runfree up` and `runfree destroy --force`.
- **Sweep time.** The sweep runs under the lock but outside the operation
  budget, with fixed per-call bounds: about 15 s, plus up to 2 s for the last
  listing.
- **Crash residue.** A marker left by a CLI that died is swept when `up` or a
  launch starts the runtime, and when `runtime reload-policy --force` restores
  admission, before any new helper runs or any session is admitted.
- **Late create (accepted).** If the Docker client dies while its create
  request is in flight, the daemon can still create the container after the
  sweep found none. The marker is kept for 180 s after the killed client, or
  after the spawn when the CLI died, and every lock holder in that window
  sweeps again. A killed client's container stays `created`, with no network
  endpoint. If only the CLI process died, its orphaned `docker run` client
  has no timeout and can still start the helper, even after the window: the
  firewall drops that unadmitted source, and a later deny probe that needs its
  address fails closed. A wall-clock jump can end the window early, and
  `destroy` clears the marker; a container created after that needs
  `runfree destroy --force`.
- **Label minting (accepted).** A process with Docker socket access can put
  the helper labels on another container, which the sweep then removes. The
  agent has no Docker socket, and the Docker daemon is trusted. Two Runfree
  state roots driving the same project path (a development setup, or two users
  on one Docker daemon) do not share the lock, so one can sweep the other's
  running helper; that run then fails closed. A project Dockerfile can put the
  helper labels on legacy-builder intermediate containers, so a concurrent
  sweep can fail another CLI's in-progress build (BuildKit, the default,
  creates no such containers).

The deny-probe helper sits in the agent position on `agent_internal`, so it
gets a pinned address from the reserved block `.13`–`.19`, outside the session
pool (`.20` and up). It skips the proxy, agent, and callback addresses, the
gateway, and every attached address. When the block is exhausted, the probes
fail as not run, and the refusal names `runfree forward stop` and
`runfree destroy --force`. The session-file publisher and the IP fence refuse
any address outside the session pool.

A Docker call that times out or is killed never reads as success
([spawn-status.ts](../packages/cli/src/runtime/spawn-status.ts)): timeout maps
to 124, other spawn errors to 125, a signal to 128 + N. An empty listing from a
timed-out `docker ps` is never proof of absence.

#### Utility Participants

The internal network may also hold ingress forwarders (MCP OAuth callback,
VNC, `runfree forward`). They are one-way host-to-agent transport sidecars on
a loopback-only host bridge plus `agent_internal`. They are not credential or
authorization boundaries. Runfree rejects unknown peers and checks each
forwarder's command, networks, loopback publication, mounts, user,
capabilities, and writable state. The MCP OAuth callback forwarder must target
a live session address.

Before it admits a session beside a forwarder, the host rechecks that shape,
the resolved immutable image ID, and the exact internal and host network IDs
under the lifecycle lock. The network baseline reserves the forwarder address;
it grants no session-file authority. A failed utility proof is reclaimed by
repairing or stopping the forwarder, or by `runfree destroy --force`.

### Interrupted Session Recovery

Interactive attaches write host-owned session evidence under the per-project
XDG state directory. A clean exit consumes that evidence; a nonzero exit,
Docker disconnect, host kill, or reboot preserves it. Records carry boot and
process-start identity so a reused PID cannot make abandoned work look active.

`runfree resume --list` and `--json` scan bounded fixed state directories for
the current project without contacting Docker or mutating state. `--all`
explicitly expands the scan across projects; repeatable `--agent <agent>`
filters the resulting inventory by exact agent ID. Selecting a recovery item
revalidates its project mapping and exact live container session, acquires an
exclusive host-owned claim, starts the normal validated runtime, and launches a
descriptor-owned Claude or Codex resume argv. Failure releases only the claim;
successful exit fingerprint-checks and consumes only the selected evidence.

Claude registry files are untrusted agent state. Recovery reads only bounded,
regular, single-link files from fixed directories, with no-follow open and
inode checks, validates conversation ids before building argv, and sanitizes
display strings. It never touches conversation transcripts. `--agent` filters
only; it grants no resume authority.

Host updates to the writable Codex state use a fixed-file operation at the
mount root. It rejects symlinks, hard links, special files, oversized files,
and concurrent changes, creates the new file with no-follow and exclusive-open
flags, and replaces `config.toml` by rename. An unsafe entry is left in place
for manual recovery.

## Network Policy Model

The public file is strict desired policy v2. It is reviewable project input,
not the proxy's runtime policy. Legacy v1 policy is not converted.

```json
{
  "version": 2,
  "hosts": ["api.github.com"],
  "requests": {
    "api.github.com": {
      "methods": ["GET", "HEAD", "OPTIONS"],
      "pathPrefixes": ["/repos/"],
      "writeAction": "ask"
    }
  },
  "tokens": {
    "github": {
      "description": "GitHub token",
      "credentials": [
        { "host": "api.github.com", "header": "Authorization", "scheme": "bearer" }
      ]
    }
  }
}
```

The direct allowlist is exact hostnames only. `services` entries, when present,
contain the complete pinned resolved semantics that were reviewed: definition
digest, revision, selected exclusions/write mode, hosts, requests, token
destinations, and OAuth topology. The compiler overlays project and
checkout-local desired layers, expands services, rejects ownership conflicts,
and emits the narrow effective policy. Token values remain separate host-owned
inputs and are streamed only to proxy-side state after convergence.

Write action precedence is:

1. per-host `requests.<host>.writeAction`;
2. merged desired-policy `writeApproval` (or a one-run host override);
3. built-in default `ask`.

For a small fixed set of first-party AI hosts (`IDENTITY_ACCEPT_ENCODING_HOSTS`
in the proxy), streaming-shaped requests are forwarded with identity
`Accept-Encoding` so intercepted event streams stay parseable. This changes
response compression only, never authorization.

For onboarding, `runfree up --audit-network` permits non-allowlisted HTTPS hosts for a short window and records what would have been blocked. `runfree audit report` suggests exact `runfree host add` commands but does not edit policy.

### Proxy Enforcement Details

The request proxy is [mockttp](../packages/proxy/package.json) running as the
unprivileged `runfree-proxy` user (uid 1001). Checks run in this order
([policy.ts](../packages/proxy/src/policy.ts)):

```text
host allowlist -> request shape -> write class -> write action -> credential -> OAuth -> upstream
```

A request that fails a step reads no token, does no OAuth mediation, and
opens no upstream connection. One exception: for a non-read request to a
declared GraphQL endpoint on an `ask`/`deny` host, and for MCP POST/DELETE,
the proxy reads the request body locally before the shape check, because
classification needs it.

**Request shape.**

- Denials carry `x-runfree-blocked: method-not-allowed`, `path-not-allowed`,
  `git-push-denied`, `write-denied`, or a `write-approval-*` reason.
- On method-ruled hosts, and on any host whose write action is not `allow`,
  the proxy strips `X-HTTP-Method-Override`, `X-HTTP-Method`, and
  `X-Method-Override`.
- On path-ruled hosts, the path is decoded up to five times. Encoded dot,
  slash, or backslash, a literal `\`, `//`, `..`, `..;param`, or a malformed
  encoding fails closed, so the proxy and the origin cannot disagree about
  the path.
- WebSocket upgrades are checked as GET.

**Write classification.** Anything not proven a read is a write. In order:
WebSocket upgrades (under `ask`/`deny`), a method-override header, git push,
`writePathPrefixes`, a GraphQL body that is not a pure query, and methods
other than GET/HEAD/OPTIONS. `readPathPrefixes` and the git upload-pack
exemption make some POSTs reads; path confusion cancels those exemptions. MCP
tool calls are classified by operation policy.

**Holds.** Under `ask` the proxy holds the request for
`runtime.writeApprovalHoldSeconds` (default 120 s, range 5–300 s), with at
most 16 holds. Without an attached approver (a root-owned heartbeat less than
45 s old for the current approval epoch), the answer is an immediate 403.
Pending records are in a uid-1001 0700 directory. Decision files, control
files, and the heartbeat must be root-owned, and the host writes them with a
root `docker exec`, so neither the agent nor the proxy process can approve
itself. Approval ids are single-use. An approved request re-runs the full
policy check. A policy change cancels holds that no longer pass. Mockttp
cannot hold a WebSocket upgrade, so WSS approval is deny-then-retry, matched
by a request-scoped grant.

**Denial feedback.** A denied 443 CONNECT is terminated with one static
`blocked.invalid` certificate and answered with a synthetic 403 that names the
host and the `runfree host add` (or `host rules`, `approvals --watch`)
remedy. At most 32 denied tunnels run at once; past that, and for non-443
CONNECT, the answer is a raw pre-TLS 403. Idle denied tunnels close after 5 s.
A certificate-validating client sees a TLS error, not the body, but the proxy
still records a `proxy-denial:` event for `runfree doctor` and the session-end
summary ([denial.ts](../packages/proxy/src/denial.ts)). Events are coalesced
to 10 per minute per host and reason. Logs carry the path only: no query, no
body, no credential values.

**Audit mode.** `runfree up --audit-network[=<d>]` (default 60 min, maximum
8 h) relaxes only the host allowlist. HTTPS-only, 443-only, and DNS answer
classification still apply. Audited hosts get no token injection, and
configured credential headers are stripped (except on WSS upgrades; see
[security.md](security.md#residual-risks)). Shape rules and write
classification do not apply to audited hosts. The host writes the audit
marker with a root `docker exec` into a root-owned directory. The request
proxy and the firewall use one clamp,
`min(expiresAt, min(enabledAt, proxyNow) + 8h)`, so a skewed clock cannot
extend the window. Audited IPs go to `audit_ipv4` (256 by default). At expiry
or `runfree audit off`, audited IPs that are not also allowed move to
`audit_draining_ipv4`, whose drop rule sits above the established-connection
accept, so in-flight audited uploads are cut.

**Firewall.** The root supervisor programs one nftables table
([nftables.ts](../packages/proxy/src/firewall/nftables.ts)):

```text
input   :8080 accepted only from @session_ipv4
output  default drop; allow loopback, established, TCP 443 to @allowed_ipv4
        (and @audit_ipv4 in audit mode) on the egress interface
dns     uid 1001 port 53 rejected before Docker DNS rewrite
ipv6    loopback only
```

The supervisor resolves allowed hosts and rejects loopback, private,
link-local, CGNAT, documentation, benchmark, multicast, reserved, broadcast,
and runtime-subnet answers before they reach `allowed_ipv4` or the resolver
snapshot. The request proxy answers `dns.lookup` only from that snapshot and
does no DNS of its own.

**Process hardening.** The proxy container adds `NET_ADMIN` and drops
`NET_RAW`. The root entrypoint starts the server through `setpriv` as uid/gid
1001 with no supplementary groups, no inheritable or ambient capabilities,
`NET_ADMIN`/`NET_RAW` removed from the bounding set, and `no_new_privs`, and
checks this at runtime ([entrypoint.ts](../packages/proxy/src/entrypoint.ts)).
If the Docker backend picks the internal interface as the default route, the
entrypoint replaces it with the egress gateway, and the host verifies the
route ([route.ts](../packages/proxy/src/firewall/route.ts)).

**Agent container.** Session containers run as uid/gid 1000, with
`no-new-privileges` and `NET_ADMIN`/`NET_RAW` dropped. The agent trusts the
proxy CA through a bundle the host renders with an ephemeral helper into the
read-only `/etc/proxy-ca` mount; `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, and
similar variables point at it. The agent never needs root to install trust.

**Runtime inputs lock.**
[runtime-inputs.lock.json](../packages/agent-runtime/runtime-inputs.lock.json)
pins base images by digest, exact apt package versions, and release artifact
checksums. A missing or malformed lock fails before any build. The apt sources
are the live Ubuntu archives, not snapshots, so transitive apt dependencies
can still drift without a lock change.

### Checkout Binding

Each approvals record is scoped to a checkout by the project scope, the config
generation, and a checkout binding: the root's resolved path and inode. The
volume device number is recorded for diagnosis and never compared, so a reboot
that renumbers the volume keeps every approval.

The binding is a scope key, not an authorization. Approved subjects are content
digests of the policy bytes, isolation fields, and image build inputs, so any
change to approved content forces a review by itself. The inode adds only a
consent hint for a directory replaced at the same path. Limits (accepted):

- It does not cover per-project Claude, Codex, and Pi state. Those mounts are
  keyed on path only, so a replacement checkout at the same path inherits them.
- It sees the directory, not its contents. A branch checkout, `git pull`, or
  agent edit keeps the same inode.
- It is void when the project root is a filesystem mount root (dedicated
  volume, CI workspace volume, loopback image, bind-mounted checkout). A new
  filesystem gives its root a fixed inode, so the binding is path only.

A different volume at the same path, or a reused inode, keeps approvals.
Where an inode is unstable, the cost is one review. A binding that does not
hold shows the normal policy review before any build, credential resolution,
or attach. The old record is copied aside, not replaced in place.

### Desired-Policy Mutation Beside Live Sessions

The typed desired-policy mutations (`host add`/`remove`/`rules`, service and
credential mutations, and the `init` wizard and pre-launch operational-service
review that call them) run while sessions are live, with no pause or restart.
Under the project lifecycle lock they:

```text
capture candidate -> verify against approved base -> atomic replace file
  -> re-read -> require exact match to planned candidate -> approve candidate
```

**Invariant: a live desired-policy mutation approves the exact in-memory
candidate it re-read and verified under the lock, never a fresh read of the
worktree file.** Approval is content-addressed: clean bytes go into a
digest-keyed snapshot store, and publication consumes the snapshot. An agent
edit in any window is refused, or stays inert unapproved drift that the next
transaction rejects. Any new caller of `withQuiescedProject` with
`allowLiveSessions` must keep this chain. Extend
[desired-mutation-drift-guard.test.ts](../packages/cli/src/control/desired-mutation-drift-guard.test.ts)
for proof.

All other control transactions (lifecycle rebuild/destroy, `runfree init`
image rebuild, startup capture) still defer while a session is
active. A concurrent launch reuses the selected effective generation and
reads no desired input.

Generation publication also accepts a host-only effective network policy
substitution (`effectiveNetworkPolicy` on `publishEffectivePolicyGeneration`),
used by host flows such as MCP projection. Project input cannot reach it. The
request proxy and the nftables supervisor consume the selected generation
independently. Activation waits for both status files and a verified firewall
ruleset before credential convergence. Invalid generations keep the previous
authority. `--no-reload` on host, credential, and service mutations changes
desired input only and leaves the selected generation unchanged.

### Write Approval Grants

| Scope | Lifetime |
| --- | --- |
| `session` (no `--ttl`) | until that session's authority ends |
| `session --ttl <d>` | `<d>`; the CLI rejects more than 8 h, the proxy clamps to 8 h |
| `request` | 5 min; readmits once any write with the same `(host, method, path, category)` |
| `deny` / `deny-session` | no expiry; cleared only by `runfree approvals --clear-deny` |

- **Subject.** The subject is the session, keyed by its source IP. A grant is
  dropped when that session's authority is revoked or it ends.
- **Two clocks.** Each positive grant records a wall-clock and a monotonic
  origin and expires when either bound is used up, checked at use time. A
  wall-clock step back cannot extend it. A host sleep (monotonic clock stops)
  cannot extend it. A forward wall jump expires it early.
- **Clearing denies.** `--clear-deny` writes a root-minted, schema-validated
  control record naming the proxy's current deny nonce. The proxy rotates the
  nonce whenever negative authority changes, so a stale clear revokes nothing.
  Clearing returns to *ask*, never to allow. A deny shadows broader allows, so
  a clear drops standing grants of both signs and lists them first. A
  session-wide deny drops that session's positive grants but keeps narrower
  denies.
- **Restart.** Grants, denies, pending holds, and unexported audit observations
  are lost on proxy-process restart; the restart reports this. Each process
  mints a new approval epoch. Decisions, control messages, and watcher
  heartbeats must name it, and decisions must name an exact pending hold
  ([approval manager](../packages/proxy/src/approvals.ts),
  [host writer](../packages/cli/src/runtime/approvals.ts)).
- **Policy activation.** A new effective generation drops positive grants
  whose host rules changed. It never drops denies. Policy activation is not a
  hidden second revocation path. Where a host moves to `allow`, the deny is
  dormant and returns to effect if the host goes back to `ask`.

## Credentials

Credential values never need to enter the agent environment.

Supported source types include:

- host environment variables;
- 1Password secret refs;
- host-owned commands such as `gh auth token`;
- stdin for one-shot setup;
- generated JWT sources;
- service-specific OAuth seed material.

The host CLI records the source and syncs resolved values into proxy-only token state. The proxy strips conflicting inbound credential headers and injects configured headers only for matching hosts and optional path prefixes. OAuth-backed services expose agent-visible handles, while token material remains mediated by the proxy.

## Services

Services are named host bundles. Curated services live in `scripts/services.ts`; user-defined services use `user-*` ids and are stored under the Runfree XDG config root. Credentialless `agent-claude` and `agent-codex` services cover native subscription/login traffic and are distinct from the credential-bearing `anthropic` and `openai` API-key services.

A service may declare `parameters`: non-secret inputs it needs beside its
secrets (an OAuth client id today). Each parameter has a stable key, an agent
env name, and a description; `service enable` resolves every one from
`--param`, the 1Password item field, the host env var, the recorded value, or a
TTY prompt, refuses before any write when one is missing, and records the value
in the host-owned control-inputs agent env. Anything that must stay out of the
agent container is a credential or an OAuth seed, never a parameter.

Enabling a service writes one complete, self-contained entry to desired policy
v2. It does not leave service authority in `runfree.json`. Credential source
bindings remain host-owned. Broad multi-tenant hosts are called out before
enable and can be excluded with `--skip-broad` or `--skip-host`.

`runfree service diff` compares the approved resolved entry with the current
curated or user definition, prints the full semantic before/after change and
authority classification, and changes desired state only with `--apply`.

## MCP Model

Runfree imports supported Claude and Codex MCP entries into sanitized per-agent config at runtime. Claude receives a dedicated read-only config and Runfree-managed launches use Claude's strict MCP mode, so passive project `.mcp.json` content is not activated without Runfree approval. This is startup-consent behavior, not containment of code already executing in the agent; proxy policy remains the egress and credential boundary.

- Host/user/local MCP entries can be inspected with `runfree mcp list` and `runfree mcp explain`.
- Project `.mcp.json` and `.codex/config.toml` entries are imported only after `runfree mcp approve`.
- Static headers require a host-owned credential source.
- OAuth login runs through `runfree mcp auth` or `runfree mcp approve --login` inside a validated runtime.
- Side-effecting MCP tool calls use the same write-approval posture as outbound writes and can be governed with `runfree mcp rules`.

## Dependency Overlays

Dependency overlays mount common dependency directories and caches from Runfree-owned Docker volumes. This keeps generated dependency artifacts container-owned and reduces host artifact drift.

Use:

```bash
runfree deps plan
runfree deps install
runfree deps doctor
runfree deps reset --force
```

The default runtime config uses `dependencyOverlays: "auto"`.

## Project Image Customization

`runfree image init` creates `.runfree/image/Dockerfile` and configures `runtime.agent.build`. Project Dockerfiles extend `RUNFREE_BASE_IMAGE`; full image overrides are not supported. Wide build contexts require explicit host-state approval with `runfree image approve-context`.

Project image builds run before the sandbox exists, on the host Docker daemon
with normal build networking. Runfree stages narrow `.runfree/image` contexts
itself after it rejects symlinks, hard links, special files, and context
escapes. The narrow-context approval subject is the staged manifest (file bytes
and modes), the Dockerfile, and the normalized build config. Embedded runtime
identity (base image, version arguments) is outside the subject: a Runfree
upgrade rebuilds without a new prompt. Builds use only a stored snapshot that
re-verifies byte-for-byte against the approved manifest. A snapshot that fails
verification is never built; the launch warns and asks again over freshly
staged bytes. Older releases cannot read these approval records; a downgrade
needs re-approval.

A project image may replace the base image's session entry (`/usr/local/libexec/runfree/session-entry`). What it loses is only the start ordering: the agent may then send before activation and be refused, exactly as the proxy refuses any pre-activation request. Authority is unchanged, and the running proof still holds the container to the entry path. See [Readiness Entry](#readiness-entry).

## Optional Side Features

- `runfree inbox paste` imports a macOS clipboard image into the read-only `/runfree/inbox` mount and prints its container path. The legacy `runfree paste-image` alias remains available with a deprecation warning.
- `runfree resume` inventories and resumes interrupted Claude or Codex sessions; Pi evidence is listed but Pi has no resume command.
- `runfree vnc` starts an x11vnc session in the agent and forwards it through a loopback-only sidecar for headed UI workflows.
- `runfree forward` opens a loopback-only host port forward into the agent through a labeled, pinned-image ingress forwarder; `runfree forward status` lists open forwards.
- `runfree git repair-worktree-links` repairs host Git worktree metadata to use relative links.

## Development And Verification

For normal TypeScript changes:

```bash
pnpm check
pnpm typecheck
pnpm test
```

For runtime, proxy, firewall, mount, or credential-boundary changes, also run on a Docker-capable host:

```bash
make test-runtime-core
```

Before a release, or for lifecycle, recovery, upgrade, or cleanup changes, run
the full `make test-runtime` (or `make test-all`).
