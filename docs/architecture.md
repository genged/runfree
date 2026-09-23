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
|                                                                                |
| XDG config/state/data                                                          |
|   approvals, effective controls, sources, sessions, proxy CA, runtime assets    |
+--------------------------------------+-----------------------------------------+
                                       |
                                       v
DOCKER COMPOSE: runfree-<project-id>
+--------------------------------------------------------------------------------+
| agent (untrusted)                         proxy (trusted boundary)              |
| +------------------------------------+    +-----------------------------------+  |
| | /workspace project bind mount      |    | HTTPS/WSS proxy on :8080          |  |
| | .runfree is untrusted desired input|    | host-owned effective controls     |  |
| | Claude / Codex / Pi / shell tools  |    | request and write classification  |  |
| | placeholders or OAuth handles only |    | credential injection              |  |
| +------------------------------------+    | denial, audit, approval records    |  |
|        |                                 +------------------+----------------+  |
|        | agent_internal network only                        | proxy_egress      |
|        | no direct Internet path                            v                   |
+--------+--------------------------------------------- upstream HTTPS/WSS hosts --+
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
- creating or migrating `.runfree/runfree.json`;
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
2. Require explicit migration for an older config; ordinary runtime commands do
   not repair project control paths.
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
to the new session key. See [IP reuse](security.md#per-session-admission).

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
subprocess work to 90 seconds and refuse acquisition after 120 seconds.
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

## Network Policy Model

The public file is strict desired policy v2. It is reviewable project input,
not the proxy's runtime policy. Legacy v1 policy is converted only by explicit
config-v4 migration.

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

For onboarding, `runfree up --audit-network` permits non-allowlisted HTTPS hosts for a short window and records what would have been blocked. `runfree audit report` suggests exact `runfree host add` commands but does not edit policy.

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

A project image may replace the base image's session entry (`/usr/local/libexec/runfree/session-entry`). What it loses is only the start ordering: the agent may then send before activation and be refused, exactly as the proxy refuses any pre-activation request. Authority is unchanged, and the running proof still holds the container to the entry path. See `docs/security.md`, "Per-Session Admission".

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
make test-runtime
# or
make test-all
```
