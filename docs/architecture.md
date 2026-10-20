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
3. **Runtime authority is host-owned.** Project desired policy is inert until host-side review selects exact subject digests and publishes an immutable effective policy generation.
4. **Project policy is explicit.** `.runfree/network-policy.json` is desired policy: exact direct hosts plus complete service, request, write-action, and credential-destination intent. There are no wildcard hosts.
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

#### Docker Access

Runfree does every Docker operation by running the user's Docker CLI. It
never opens the Docker socket itself, so it reaches the same daemon, Docker
context, and credential helpers as the user's own `docker` command, and it
uses Compose, image builds, and terminal attach from that CLI unchanged.
Docker command lines are built in one place, and a static check fails the
build when Docker command text appears anywhere else in the CLI.

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
It is desired input, never a trusted runtime mount.

The host writes the agent's global Git config and mounts it read-only. It
carries the host user's Git name and email, makes worktrees and the mounted
roots usable inside the container, and rewrites common SSH remotes for
GitHub and GitLab to HTTPS, so Git traffic goes through the proxy, which
attaches the service credential. The rewrite is routing, not enforcement: the
agent can change it, and SSH has no route out either way. Host Git never
reads this file, and the repository's own Git config is not changed. Other
per-agent config, effective environment, and state are mounted from
Runfree-owned locations rather than from host-wide home directories.

### Proxy Container

The `proxy` service is the trusted network boundary. It enforces:

- exact-host HTTPS/WSS allowlisting;
- request methods and request path prefixes;
- Git push classification and optional denial;
- operation-aware read/write classification for declared endpoints;
- GraphQL query/mutation classification for declared GraphQL paths;
- write actions: `allow`, `ask`, or `deny`;
- credential header stripping and proxy-managed credential injection,
  including credentials limited to Git or Git LFS traffic;
- OAuth handle mediation;
- plain TCP pass-through to approved [host services](#host-services), and
  nothing else under the reserved `runfree.internal` name;
- structured denial logs for `runfree doctor`.

The proxy reads one selected effective policy generation, which pairs network
and OAuth policy, from a read-only host-state mount. It never reads project
policy directly. It also reads proxy-side token state. It does not rely on
agent environment variables as an enforcement mechanism.

### Runtime Contracts

The CLI and proxy share one set of policy types and validators. Desired
policy is a strict authoring format; the host compiles it into a narrower
effective policy, which is the only form the proxy reads. Both the CLI and the
proxy refuse unknown keys in either form, so an older reader cannot silently
skip a field it does not know. The same shared contracts cover OAuth
mediation, write approval, status, and generations.

### Embedded Runtime Assets

Canonical runtime source lives in:

- `packages/agent-runtime/` for agent-side runtime files: the session entry
  that holds the agent's start until the proxy activates the session, the
  readiness probe it runs, and the host-service relay it starts;
- `packages/proxy/` for the proxy and its Dockerfile;
- `packages/cli/templates/` for initial project templates.

`pnpm run build:runtime` assembles `dist/runtime/**`. `pnpm run generate:assets` embeds those assets into `packages/cli/src/embedded-assets.generated.ts`. The CLI materializes the embedded version into an XDG data directory before starting Docker Compose.

The build declares the path and file mode of every runtime asset instead of inheriting them from the checkout or the umask. The assembled tree, and the component digests taken over it, are therefore a pure function of the repository: the same commit yields the same embedded manifest on any machine. The build refuses a generated tree whose modes, paths, or Dockerfile sources drift from the declaration.

Embedded runtime identity is component-specific. Agent-image inputs, proxy-image inputs, rendered topology, and host helpers have separate SHA-256 identities. The fixed control plane and session-agent template have separate immutable v2 materializations under XDG state. Each session materialization contains its canonical template artifact and binds that artifact's hash. Atomic selection records distinguish the validated control plane from the desired materialization for new sessions.

Do not edit generated runtime assets by hand.

## Project Files And State

| Location | Owner | Purpose |
| --- | --- | --- |
| `.runfree/runfree.json` | project | config version, agents, and non-network runtime options |
| `.runfree/network-policy.json` | project | writable desired policy; direct hosts and complete service/request/credential intent |
| `.runfree/network-policy.local.json` | project (ignored) | writable checkout-local desired overlay |
| `.runfree/image/Dockerfile` | project | optional project image extension over `RUNFREE_BASE_IMAGE` |
| XDG config root | host | host-owned sources and user-defined service definitions |
| XDG data root | host | materialized runtime assets |
| XDG state root | host | approvals, immutable effective controls, runtime generations, sessions, agent state, token sync state, proxy CA material |
| XDG state root, shared by all projects | host | registry of every project's approved host-service ports; see [Host Services](#host-services) |
| Docker volumes | Docker | dependency overlays, runtime volumes |
| Docker Compose project | Docker | fixed `proxy`, networks, and named volumes; session agents are direct containers |

The project id is a stable hash of the resolved project path. `runfree project-id --compose-name` prints the Docker Compose project name.

## Generation Families

Runfree has more than one content-addressed "generation", and they are
different authority families. Always name the family; the bare phrase
"control generation" is ambiguous and retired from docs and specs.

| Family | Serialized key | What it identifies |
| --- | --- | --- |
| Effective policy generation | `controlGeneration` | The compiled, immutable host/proxy policy generation built from approved `.runfree/` desired policy: network policy, OAuth mediation policy, agent environment, runtime control. |
| Control plane generation | `controlPlaneGenerationDigest` | The runtime control plane a session binds to: proxy image, Compose topology, and admission contract epoch. |
| Temporary access generation | (reserved) | Session-scoped temporary network access records; designed, not yet built. |

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

A warm session launch can skip the full runtime validation. After a full
validation, Runfree records a fingerprint of the validated runtime in host
state: the proxy instance, both networks, the other participants on the
internal network (such as port and VNC forwarders), images, volumes, both
generation families, the firewall ruleset's shape, CA material, the Docker
daemon, and the VM boot. It records one only when the session reconcile that
follows found nothing to repair, any restore of surviving sessions finished,
the proxy did not restart during the run, and no ephemeral helper is
attached. A later launch with the same runtime plan and selected control plane
re-reads that evidence fresh, re-runs the same topology, capability, route,
firewall, and security-contract checks over it, and skips the rest of full
validation only on an exact, recent match. The skipped part includes the
agent-position deny probes; [security.md](security.md) says what that leaves
unproven. A Docker daemon with live-restore never takes this path. Any
mismatch deletes the fingerprint and validates fully. `runfree up` always
validates fully, and `stop`, `destroy`, and `rebuild` delete the fingerprint.
A launch also skips image cleanup when nothing that cleanup depends on has
changed since the last completed pass.

When other sessions are live, a fingerprint match is not enough, because it
does not cover those sessions. The launch then also checks, under the
lifecycle lock and against one proxy instance, that every peer is accounted
for: each lifecycle record is attached, bound to the selected control plane,
and owned by a process proved alive; the container listing, each peer's own
running proof, the proxy's session files, the firewall's session set, and the
IP assignments all agree; and every other participant on the internal network
is a peer's callback forwarder or a recorded forwarder. An owner that can be
proved neither alive nor dead is a miss. Any miss takes the full validation,
reconcile, and restore. On a match the startup reconcile still runs, and the
restore of surviving sessions is skipped only when that reconcile found
nothing to repair and the proxy and registry are unchanged since the check.
Otherwise the launch refuses before credential sync and asks for a retry,
which validates fully. The check never restores, republishes, or renews a
peer: a peer whose owner dies afterwards keeps its access only until its
session file expires, and the reconcile tears it down.

Startup creates one in-memory prepared runtime after durable selection and live proof agree. Public launches consume that exact authority once. A changed container or selection causes one bounded re-prepare attempt. Credential sync occurs only after this prepared authority exists.

Cleanup uses exact references from selections, lifecycle records, direct containers, and pending rebind state. The proxy's own session files are not a reference source; they gate the whole pass instead, so a session file no lifecycle record claims or a listing the host could not read stops the cleanup. It removes only inspected zero-reference image IDs and materialization paths. Ambiguous containers or unsafe state files stop cleanup. `runfree status` and verbose startup show effective, desired, retained, and pending generations.

`runfree rebuild` recreates the runtime while keeping Compose volumes and
local images. It runs under operator confirmation and the project lifecycle
lock. It first checks any pending control-plane rebind and identifies
Runfree's own ingress forwarders and older VNC sidecars by their full Docker
shape and exact image. Only after every refusal check passes does it remove
those utilities and end every session the registry or the pending rebind
names: it marks their records revoking, deletes their session files from the
still-running proxy, stops the proxy's consumers, removes the session
containers, and tears down Compose. It then clears the stale runtime
selection, the pending rebind, and the revoking records, in that order. Each
step is durable before the next starts, so a repeated rebuild can resume after
an interruption. Unreadable or unclaimed evidence is refused with
`runfree destroy --force` as the explicit remedy.

`runfree stop` stops services. When nothing is left to stop or Compose tears
down cleanly, no lifecycle record or rebind journal remains, and Docker proves
the selected proxy and both networks are gone, stop also forgets the stale
runtime selection, so the next start begins fresh instead of trying to rebind
to networks that no longer exist. Without that proof it keeps the selection;
when the state or Docker cannot answer, it warns and names `runfree destroy`.

`runfree destroy` destroys the whole project runtime under the project
lifecycle lock. It first proves which utilities Runfree owns; then, without
`--force`, it refuses (or only reports) live sessions and unclaimed containers
carrying this project's label. After every refusal check passes, it revokes
session authority file first, stops the proxy, removes session containers by
the exact IDs their records or the pending rebind name (they are not Compose
resources, so Compose cannot see them), and runs the Compose teardown for
services, volumes, local images, and orphans. It then removes the project's
leftover session volumes that Compose keeps because no service uses them
(dependency caches, and an old command-history volume on older projects),
matched by this project's exact label and name and never forced. Last it
removes the runtime selection, the rebind journal, and the records, in the
same order as rebuild. Session files leave the proxy before the records that
reserve their addresses are touched. Forced destroy skips the strict utility
ownership check, so malformed utility leftovers cannot block its sweep of
containers carrying the project label; the sweep still removes only the exact
Docker IDs it found. Afterward, Runfree removes the ingress bridge only if it
carries Runfree's ownership labels, its full network ID is exact, and Docker
proves it has no endpoints.

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
`runfree mcp auth` — reaches it through one shared launch path; the
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
`docker exec --user 0:0` channel with a digest of the exact payload. Creating
an eligible file admits, rewriting it renews, and deleting it revokes.
Heartbeats do not wait for acknowledgements. New container creation first
waits for an IP fence. A kernel lock and exact prior-state check exclude stale
executors. Retirement requires root firewall exclusion, kernel TCP drain, then fresh
acknowledgements from both consumers. The root-owned assignment remains bound
to the new session key. See [IP Reuse Fence](#ip-reuse-fence).

The proxy has two consumers of these files: the root firewall and the
unprivileged request proxy. Each applies the same validity rule on its own
loop, and neither reads the other's decision. The firewall's admission loop
reads only the session files, the eligibility file, the IP assignments, the
clock, and its own session address set. It never loads policy, resolves DNS,
or makes upstream connections; a separate maintenance loop does that, so a
slow DNS lookup cannot delay admission, expiry, or revocation. The request
proxy serves each connection from the view its own loop last built.

Each loop runs soon after one of these files changes, and also on a short
fixed interval. The change notice only makes a pass come sooner and grants
nothing. The interval is what notices a lease running out, and it covers a
missed notice. A scan that catches the host in the middle of a file replace
reads the file again instead of dropping it. Scheduling can still delay
either consumer, so container creation waits for explicit retirement proof
and does not assume a maximum consumer delay.

Proxy startup clears the session and IP assignment directories and removes the eligibility file,
recreates the nftables table, and verifies `session_ipv4` empty before
readiness. Authority returns when the host republishes eligibility and each
surviving session's next heartbeat rewrites its file.

Lifecycle state lives in host-owned records in the project's state
directory. A launch moves through these steps:

1. **Preflight** pins the exact runtime it launches into (control plane,
   session template, launch target, and images) under the project lifecycle
   lock, refuses while a control-plane rebind is pending, and reconciles
   leftover state (below) before it allocates anything.
2. **Allocate** picks a source IP that no current participant on the
   internal network and no proxy session file holds, and records it.
3. **Fence and start** first retires any old authority on that IP (see
   [IP Reuse Fence](#ip-reuse-fence)). It then creates the container from an
   exact plan (command, user, dropped capabilities, mounts, no restart, and a
   static address) and starts it. Docker assigns the address at start and
   refuses a duplicate. A crash here leaves one inert record and container,
   which the next reconcile removes. Docker's init is the container's first
   process. Its child, the base image's session entry, holds the agent back
   until the proxy serves the session (see [Readiness Entry](#readiness-entry)).
   When the session needs an MCP OAuth callback, its forwarder is set up
   beside this step. It joins the internal network only after the running
   proof, so it cannot take the session's address first. See
   [Session MCP OAuth Callbacks](#session-mcp-oauth-callbacks).
4. **Prove running** inspects the started container once and requires it to
   match the create plan exactly, including one internal network at the
   allocated address. This is the admission's only shape proof, and the
   session file's identity comes from it.
5. **Activate** writes the session file. This is the first step that widens
   what the container may do: the firewall admits the address, the readiness
   check succeeds, and the entry starts the agent. A failure after the write
   deletes the file again rather than leaving authority behind.
6. **Await handoff** keeps the lifecycle lock until the Docker daemon's
   process listing shows that the entry has started the agent. A proxy
   replacement therefore cannot land between the grant and the start and
   leave the entry waiting on a proxy that no longer serves it. The wait is
   short and bounded; when it runs out, that launch goes on without this
   ordering. The process list is under the container's control, so it decides
   only when the launch reports `attached`. It grants nothing.
7. **Await completion** releases the lifecycle lock and runs the heartbeat for
   the life of the attached process.
8. **Teardown** marks the record terminal, deletes the file, disconnects,
   stops, and removes the container, and only then removes the record. After
   a normal exit that Docker confirms, it skips the disconnect and the stop
   (see **Revoke** below).

The lifecycle lock covers steps 1–6 and teardown. It is released once the
session is `attached`; it is not held for the interactive session.

**Lock handoff.** A `runfree claude`, `codex`, `pi`, `shell`, or
`runfree mcp auth` launch can keep the lock that startup took and hand it
straight to admission, with what startup proved under it: the proxy
instance, the lifecycle registry, and how its reconcile left the project's
sessions. This needs a credential sync that read no credential source under
the lock (a warm launch reads none; a cold launch reads them all before it
takes the lock) and a startup that finished quickly. Otherwise startup
releases the lock, syncs credentials the ordinary way, and admission takes
the lock itself and runs its full preflight. With a handoff, admission skips
the repeated reconcile only when the registry and the proxy instance are
unchanged. It still checks quarantined and unfinished records, reads a fresh
network baseline, fences the address, and proves the started container.
`runfree up` and `runfree resume` never hand off.

A warm launch can also skip startup's reconcile when the project holds no
session state. Every view, taken under the held lock, must agree: the
proxy's session-file listing is empty, the internal network holds only the
proxy and ingress forwarders, the lifecycle registry is empty, and a
host-wide container listing shows nothing that looks like one of this
project's sessions. A view that cannot be read never counts as empty. The
result is single-use and bound to that proxy instance and lock holder; a
copy, a second use, or any mismatch sends admission through its full
preflight.

A launch plans its whole hold of the lock to end before the time other
commands wait for the lock runs out, so in ordinary use a concurrent command
gets the lock instead of failing. Fault cases can still take longer: a slow
IP fence or session-file write, cleanup after a failed admission, or a hung
Docker call. Then the waiting command defers with a retry instruction, and
nothing is admitted or removed because of it.

Image builds, build approvals, and credential-source resolution finish before
startup takes the lifecycle lock. Startup and explicit reload bound held
subprocess work to 90 seconds and refuse acquisition after about 60 seconds.
Prepared credential values must be admitted within 120 seconds of preparation
and used within a further 120 seconds; expired or changed preparation refuses
before a credential write. Ordinary session-file heartbeats take no lock.

**Heartbeat.** Every 30 s while the foreground runs, the owner adopts a
completed compatible rebind if the durable selection changed, inspects the
container, and rewrites its file with a fresh nonce and
`aliveUntil = inspectedAt + lease`. Inspection and write are one sealed step,
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

Each beat also rewrites an advisory host status stamp recording the
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

**Revoke** is one ordered sequence, safe to repeat, shared by the launch owner
and by reconcile: mark the record terminal, delete the file, disconnect, stop,
remove the container, delete the record, clear the status stamp. The file
goes first because it is the authority; the record goes last because it
reserves the address. If this host cannot delete the file, the sequence stops
there and keeps the record, so the address stays reserved until a later pass
finishes the job. The launch reports one refusal naming `runfree up`, and
peers still read the record as cleanup in progress. After a normal exit, the
launch owner skips the disconnect and the stop only when Docker confirms that
the admitted container instance has exited with that status and will not
restart. Any other answer, and every reconcile, keeps the full sequence. The
next container cannot reuse the address until the IP fence proves old kernel
sockets and consumer authority are gone. Teardown speed is not a security
guard.

**Reconcile** runs under the same held lock as the allocation that follows:
at every launch preflight (for a lock handoff, in the startup that handed the
lock over, unless that startup proved the project holds no session state) and
at `runfree up`. It deletes proxy files no lifecycle record claims, tears down
records whose owner is provably dead, removes session containers no record
claims, keeps records whose owner cannot be proved either way (reported, with
`runfree destroy --force` as the remedy), and republishes eligibility from
what survived. The proxy's own listing is the only view of the files, so a
listing the host could not read refuses the launch, naming `runfree up`,
instead of allocating over files it cannot see. Every address a well-formed
file names is reserved from allocation.

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
with no poke and no pre-selected candidate.

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
observation that started the failure is not discarded with it.

`runfree stop` and `runfree runtime reload-policy` require `--force` when live
or unprovable owners remain, when a control-plane rebind journal is pending, or
when any record carries a terminal host status stamp. Reload of the same proxy
container republishes eligibility, re-proves every surviving session, and lets
the heartbeats refill the session files; when no record can still hold
authority it proves `session_ipv4` empty from the live kernel set before
reporting success. Compatible replacement uses its own transaction
authorization.

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
host suspension and filesystem stalls can exceed them.

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

The usual cause is a Docker daemon that dies under a live session: the owner
marks its record, cannot delete the session file, keeps the record, and
exits, and the restarted daemon has stopped both the session container and the
proxy. The next start finishes that teardown under the lifecycle lock, before
it plans the runtime. It needs Docker to prove that the owner is dead, that
the session container is absent or stopped, and that no proxy can still serve
the session file (a running proxy deletes it the ordinary way; a stopped one
holds none, because session files live in its memory). Anything Docker cannot
prove refuses with the reason and the remedy: retry once Docker answers or
the owner exits, `runfree destroy --force` for an owner that cannot be proved
dead, or `runfree rebuild` for a container that is still running.

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
exact proxy, token-store generation, effective policy, and pending recovery receipt.

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

The live admission tests admit, prove, and revoke each built-in agent against
a real Docker daemon (see [Testing](testing.md)).

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

The parse is exact. It refuses an unknown key, a missing key, a file name that is
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

The container's first process is Docker's init. Its child, the first process
the project image controls, is the base image's session entry, with the agent
launch as its arguments. The entry asks the request proxy whether the session
is served and starts the agent only when the answer is `active`:

```text
before the session file   firewall drops the connection   probe: connect failure
admitted, not yet served  request proxy answers 403        probe retries
file served               200 "active"                     entry execs the agent
```

The readiness answer is local. It forwards nothing, resolves nothing, and
grants nothing. An entry that waits too long gives up and exits; the container
stops, that code becomes the launch's exit status, and normal teardown
reclaims the file, container, and record. The launch reports the session
`attached` only after the entry has started the agent. The entry is
cooperation, not enforcement. A project image may replace it; it then loses
only start ordering, and a replacement that never hands off delays its own
`attached` report by the short handoff wait.

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
  creation; retry is safe. A launch that took over startup's lock compares
  against the assignments startup read under that same lock and proxy
  instance.
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
project agent image.

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

A Docker call that times out or is killed never reads as success: timeout maps
to 124, other spawn errors to 125, a signal to 128 + N. An empty listing from a
timed-out `docker ps` is never proof of absence.

#### Utility Participants

The internal network may also hold ingress forwarders (MCP OAuth callback,
VNC, `runfree forward`). They are one-way host-to-agent transport sidecars on
a loopback-only host bridge plus `agent_internal`. They are not credential or
authorization boundaries. Runfree rejects unknown peers and checks each
forwarder's command, networks, loopback publication, mounts, user,
capabilities, and writable state. The allocator never hands out an address
that any ingress forwarder still targets.

The [host-service relay](#host-services) is not a participant. It is a
process inside the session container, bound to that session's loopback, with
no address, network, or authority of its own. Its traffic reaches the proxy
from the session's own source IP and is admitted as that session.

#### Session MCP OAuth Callbacks

When an approved MCP server can use OAuth, every launched session (agent,
shell, resume, or `mcp auth`) gets its own OAuth callback path. The path is
ready before the session is activated, so no client starts without it:

```text
host 127.0.0.1:P -> forwarder (bound to session S) -> S's address:P
                 -> in-session bridge (forwarder only) -> S's 127.0.0.1:P
```

- **Port.** Each session takes a free host loopback port from a small block
  that Runfree keeps for callbacks, starting with the project's first port.
- **Setup.** The host port is reserved while the container starts. The rest
  of the path (the forwarder's link to the session, the bridge, and a check of
  the whole path) is set up after the container is proven running and before
  the session file is written. If any part fails, the launch first waits for
  every step it started, then removes what it created and fails with a retry
  instruction.
- **Binding.** Each forwarder is created bound to one session. Runfree
  accepts a forwarder only while that session is running at the address the
  forwarder targets. A forwarder without a binding, from an older release, is
  refused.
- **Clients.** The bridge tells the session its port, and the Claude and
  Codex launchers pass it to the client, also for `codex mcp login` in a
  shell. Generated agent config names no shared callback port, so nothing
  overrides the session's own port.
- **Teardown.** A session's forwarder is removed after its session file and
  before its record, so the session's address is never freed while a route
  to it remains. Before an orphan session container that no record claims is
  removed, its forwarders are removed first. If that fails, the container and
  its address stay for the next reconcile, and `runfree destroy --force` is
  the remedy.
- **Reclaim.** When a check refuses because of a leftover forwarder whose
  session is gone (for example after a killed launcher), Runfree removes that
  forwarder under the lifecycle lock and checks again. A forwarder whose state
  cannot be read is never treated as dead.

Sessions without an OAuth-capable server get no callback path.

Before it admits a session beside a forwarder, the host checks again, under
the lifecycle lock, that the forwarder has the expected shape, image, and
networks. The network baseline keeps the forwarder's address out of use; it
grants no session-file authority. A forwarder that fails this check is
repaired or stopped, or the project is reset with `runfree destroy --force`.

### Interrupted Session Recovery

When a session ends badly (Docker stops, the host client is killed, or the
machine restarts), the host keeps a record of it in the project's own state
directory. A clean exit removes the record. Each record says which process
and which boot started the session, so a reused process ID cannot make
abandoned work look active. For Claude and Pi, the host chooses the
conversation id before the agent starts and passes it to the agent, so the
record names the exact conversation without trusting anything the agent
writes. The record also notes which terminal started the session; that
information stays on the host and never reaches the session container.

`runfree resume` reads these records without contacting Docker. When exactly
one Claude or Pi record clearly belongs to the current terminal, it asks one
question: resume, not now, or forget it. Otherwise it shows a picker, with
this terminal's sessions first. Codex cannot take a conversation id from the
host, so a Codex session is matched to its conversation by time; those
matches are only labelled rows in the picker, never the one question.
Starting an agent never asks about interrupted sessions.

Choosing a session takes a host-owned claim on that conversation, checks the
session again, and starts it as a new, normally admitted session; the old
container is never reused. Claims are per conversation: several terminals
can resume different conversations at the same time, but two can never
resume the same one. A claim whose owner is gone is cleared, and one whose
owner cannot be identified stops blocking after a while. When the resumed
session ends cleanly, the old record and everything linked to the same
conversation is marked done. If Docker stops again, the new record replaces
the old one. If the resume fails before the session starts, the record stays
for the next `runfree resume`. "Forget it" marks the record done without
starting anything, and refuses while another terminal holds a claim on it.

Files the agent writes, such as Claude's session list and Codex's history,
are untrusted. Recovery reads them only from fixed places, within limits,
never follows links, and cannot be stalled by a special file. Names taken
from them are cleaned, labelled as agent-reported, and never the default
choice. The limits are listed in [security.md](security.md).

Host updates to the writable Codex state refuse links, special files,
oversized files, and concurrent changes, and replace the configuration file
in one step. An unsafe entry is left in place for manual recovery.

## Network Policy Model

The public file is strict desired policy. It is reviewable project input,
not the proxy's runtime policy. Legacy v1 policy is not converted.

The version changes only when an older reader would misread the content.
Runfree writes the lowest version that can hold the content, so most
projects stay on version 2; git credential destinations need version 3.
Older releases refuse a newer file instead of dropping fields they do not
know. The exact triggers are in [cli.md](cli.md#network-policy).

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

For a small fixed set of first-party AI hosts, streaming-shaped requests are
forwarded with identity `Accept-Encoding` so intercepted event streams stay
parseable. This changes response compression only, never authorization.

For onboarding, `runfree up --audit-network` permits non-allowlisted HTTPS hosts for a short window and records what would have been blocked. `runfree audit report` suggests exact `runfree host add` commands but does not edit policy.

### Proxy Enforcement Details

The request proxy is mockttp running as the unprivileged `runfree-proxy`
user (uid 1001). Checks run in this order:

```text
host allowlist -> request shape -> write class -> write action -> credential -> OAuth -> upstream
```

A request that fails a step reads no token, does no OAuth mediation, and
opens no upstream connection. One exception: when a request's class depends
on its body (a non-read request to a declared GraphQL endpoint, an MCP call,
or a POST to a recorded OAuth endpoint), the proxy reads the body locally
before the shape check.

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
other than GET/HEAD/OPTIONS. Some POSTs are reads: `readPathPrefixes`, git
fetches on hosts that declare git handling, and Git LFS download batches
where the host's policy mediates Git LFS (see
[security.md](security.md#git-over-https)). Path confusion cancels those
exemptions. MCP tool calls are classified by operation policy.

**OAuth protocol reads.** On an `ask` host (never `deny`), an OAuth login,
refresh, or client registration POST runs without approval only when the
OAuth mediator proves it is an exchange it mediates for exactly one MCP
server: the endpoint is one that `mcp enable` recorded for that server, no
other provider would mediate it, the body holds only the protocol's own
fields, and the server's rate limit is not spent. Anything else on the host
stays a write. Every write rule above runs first, and the mediator checks the
match again before it swaps any handle, so a token response never reaches the
agent unmediated. The exact rules are in [security.md](security.md#mcp).

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
CONNECT, the answer is a raw pre-TLS 403. The one non-443 CONNECT that can
pass is an exact approved [host service](#host-services) pair. Idle denied
tunnels close after 5 s.
A certificate-validating client sees a TLS error, not the body, but the proxy
still records a `proxy-denial:` event for `runfree doctor` and the session-end
summary. Events are coalesced
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

**Firewall.** The root supervisor programs one nftables table:

```text
input   :8080 accepted only from @session_ipv4
output  default drop; allow loopback, established, TCP 443 to @allowed_ipv4
        (and @audit_ipv4 in audit mode) on the egress interface
        allow TCP to approved host-service pairs (<gateway> . <port>) for
        uid 1001 only; drop any other port on a pinned gateway, above the
        established accept
dns     uid 1001 port 53 rejected before Docker DNS rewrite
ipv6    loopback only
```

The supervisor resolves allowed hosts and rejects loopback, private,
link-local, CGNAT, documentation, benchmark, multicast, reserved, broadcast,
and runtime-subnet answers before they reach `allowed_ipv4` or the resolver
snapshot. The request proxy answers `dns.lookup` only from that snapshot and
does no DNS of its own. The host-service gateway never enters the allow set
or the snapshot, so an allowlisted host that resolves to it is still refused.

**Process hardening.** The proxy container adds `NET_ADMIN` and drops
`NET_RAW`. The root entrypoint starts the server through `setpriv` as uid/gid
1001 with no supplementary groups, no inheritable or ambient capabilities,
`NET_ADMIN`/`NET_RAW` removed from the bounding set, and `no_new_privs`, and
checks this at runtime.
If the Docker backend picks the internal interface as the default route, the
entrypoint replaces it with the egress gateway, and the host verifies the
route.

**Agent container.** Session containers run as uid/gid 1000, with
`no-new-privileges` and `NET_ADMIN`/`NET_RAW` dropped. The agent trusts the
proxy CA through a bundle the host renders with an ephemeral helper into the
read-only `/etc/proxy-ca` mount; `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, and
similar variables point at it. The agent never needs root to install trust.

**Runtime inputs lock.** The runtime inputs lock pins base images by digest, exact apt package versions, and release artifact
checksums. A missing or malformed lock fails before any build. The apt sources
are the live Ubuntu archives, not snapshots, so transitive apt dependencies
can still drift without a lock change.

### Host Services

A host service is a TCP service on the Docker Desktop host's loopback that the
agent may reach, such as a dev server, a database, or a device bridge on
`127.0.0.1:<port>`. The host approves it per project, by name and port, and
the approval persists in desired policy like an allowed host:

```json
{
  "version": 2,
  "hosts": [],
  "hostServices": {
    "devserver": { "target": "host-loopback", "port": 3000 }
  }
}
```

The target is a fixed keyword, never a hostname; only the host's loopback is
supported. Ports that belong to Docker or to Runfree itself are refused. Adding
a service or changing its port is a widening and always needs host review;
removing one is a reduction. The name `runfree.internal` and every name under
it are reserved for host services, so no other policy, rule, service, or MCP
host can use them.

Data path:

```text
agent client: connects to 127.0.0.1:3000             (client unchanged)
   v
session relay on 127.0.0.1:3000 (routing only, no authority)
   | CONNECT devserver.runfree.internal:3000 to the proxy
   v
proxy (admitted sessions only)
   exact approved name and port?  no -> refused, nothing dialled
   gateway known for this policy? no -> refused
   dial the pinned gateway; on success, an opaque byte splice
   v
firewall: only the request proxy may reach the gateway's approved ports
   v
Docker Desktop host gateway -> host 127.0.0.1:<port>
```

The proxy refuses before any dial, DNS lookup, or audit record, on every port
and in every mode. The splice is opaque: no TLS interception, request rules,
header stripping, credential injection, or write approval apply inside it. The
proxy caps how many splices a session and the whole proxy may hold. Each
splice belongs to its session, so ending or fencing the session (see
[IP reuse fence](#ip-reuse-fence)) cuts it.

**Session relay.** Many clients (database drivers, gRPC libraries, custom
tools) ignore proxy variables, so each session starts a small relay in the
background. It listens on the same port numbers as the host services, on the
session's own loopback only, and forwards each connection to the proxy. It runs
as the agent user with no added authority, and peer sessions cannot reach it.
The relay is best effort: if it cannot start or cannot take a port, the session
still starts, without that service. The list of services comes from the host,
fixed when the session starts, so a service added mid-session appears in the
next session.

**Gateway address.** The proxy learns the host gateway address from Docker,
never from DNS. The root firewall supervisor checks it, pins the first valid
address for the life of the proxy, and hands it to the request proxy. If the
address later changes or becomes invalid, host services stop: open splices are
cut, new connections refuse with a named cause, and `runfree rebuild` is the
way back. Right after any policy reload, new host-service connections refuse
briefly until the supervisor publishes the gateway for the new effective
policy generation; open splices are not affected.

**Revocation.** When a service is removed, or the gateway changes or is
withdrawn, two consumers cut it independently. The request proxy closes the
affected splices. The firewall drops packets to the old pair at once, and keeps
dropping any traffic to a pinned gateway on a pair that is no longer approved,
from any user and even for a flow the request proxy did not track. Each
consumer cuts before it reports the new effective policy generation, and
activation waits for both, so `runfree host-service remove` reports the change
as live only after both have cut.

**Port admission and the registry.** Before any approval is written, Runfree
checks that a host process, not a Docker Desktop published container port, is
listening on the port where the gateway can reach it. This runs on every host
approval path that adds or re-ports a host service, not only
`runfree host-service add`, and the review names the process it found. Every
launch and `runfree status` repeat the check and warn, without blocking, when
the listener is gone, changed, or owned by Docker Desktop.

A host-wide registry records which ports each project uses for host services.
Other projects' `runfree forward` and `runfree vnc` refuse those ports, and
MCP callback ports avoid them; several projects may share one host service.
`runfree host-service list --repair` rebuilds the registry, and refuses rather
than writes an incomplete one when a known project's state cannot be read.

`runfree doctor` and the session-end summary report host-service denials on
their own, not as missing hosts, and suggest `runfree host-service add` only
for a request it would accept.

**Host-side proof.** Each launch's topology proof checks the gateway entry and
that the firewall's approved pairs match the effective policy. A full launch
also probes that the agent cannot reach the gateway, and that inside the proxy
only the request proxy can, and only on approved ports.

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
transaction rejects. Every new live mutation path must keep this chain, and
its drift-guard test proves it.

All other control transactions (lifecycle rebuild/destroy, `runfree init`
image rebuild, startup capture) still defer while a session is
active. A concurrent launch reuses the selected effective policy generation and
reads no desired input.

Host flows such as MCP projection may also publish a host-only substitute for
the effective network policy; project input cannot reach it. The request proxy
and the firewall supervisor consume the selected effective policy generation
independently, and activation waits for both, with a verified firewall
ruleset, before credentials converge. An invalid effective policy generation
keeps the previous authority. `--no-reload` on host, credential, and service
mutations changes desired input only and leaves the selected effective policy
generation unchanged.

**Same-build fence.** A proxy from another Runfree build could misread an
effective policy generation this CLI publishes, so a policy command publishes
only to a proxy of its own build. A proxy of another build is replaced first,
on the effective policy generation already selected, or the change waits when
it cannot be replaced. A release that leaves the proxy unchanged needs no
replacement. Outcomes and remedies are in
[security.md](security.md#older-readers).

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
  heartbeats must name it, and decisions must name an exact pending hold.
- **Policy activation.** A new effective policy generation drops positive grants
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

A credential destination names a host, a header, and how the token is written
into it: as a Bearer token, as the raw value, or as HTTP Basic with a fixed,
non-secret username, which is what git over HTTPS expects. A destination can be
narrowed by a path prefix, by a protocol scope, or both.

A protocol scope names a kind of request the proxy recognizes itself: git
smart HTTP (fetch and push) or the Git LFS API. No request is both, and a
request the proxy cannot classify for certain gets no credential. A Git LFS
scope also lets a proven LFS download pass as a read. The `github` service
uses both scopes; the `gitlab` service uses only git smart HTTP, because
GitLab's LFS answer carries a token that can push. New kinds are added only
for public wire protocols the proxy can recognize reliably; a vendor's own
endpoints use a path prefix or a request rule instead.

When several destinations of one host match a request, the proxy picks the
most specific, and policy that could tie is refused. Because the choice is per
host, any change to the destinations of a host that has more than one needs
host approval. The exact rules are in
[cli.md](cli.md#user-defined-services) and
[security.md](security.md#git-over-https).

Sources are read on the host, never while the lifecycle lock is held.
`runfree up`, a cold start, and a replaced proxy read every source first.
A warm session launch may reuse a value the proxy already holds, but only when a host receipt
shows that value is current and recently read; otherwise it reads the source as
before. Reuse never makes a value look newer than its last read. Right after
the launch, a background watcher re-reads every source, so a value rotated or
revoked at its source reaches the proxy seconds after the launch. A definitive
read failure removes the held value; a transient one keeps it, for a bounded
time, until the next launch reads the source interactively. When the session
ends, the watcher stops reading and writing; a write already in progress
completes, and a write with an unknown outcome is never followed by a removal.

## Services

Services are named host bundles. Curated services live in `scripts/services.ts`; user-defined services use `user-*` ids and are stored under the Runfree XDG config root. Credentialless `agent-claude` and `agent-codex` services cover native subscription/login traffic and are distinct from the credential-bearing `anthropic` and `openai` API-key services.

A service may declare `parameters`: non-secret inputs it needs beside its
secrets (an OAuth client id today). Each parameter has a stable key, an agent
env name, and a description; `service enable` resolves every one from
`--param`, the 1Password item field, the host env var, the recorded value, or a
TTY prompt, refuses before any write when one is missing, and records the value
in the host-owned control-inputs agent env. Anything that must stay out of the
agent container is a credential or an OAuth seed, never a parameter.

Enabling a service writes one complete, self-contained entry to desired
policy, using the newer policy format only when the entry needs it (the
`github` and `gitlab` git destinations do). It does not leave service authority
in `runfree.json`. Credential source bindings remain host-owned. Broad
multi-tenant hosts are called out before enable and can be excluded with
`--skip-broad` or `--skip-host`.

`runfree service diff` compares the approved resolved entry with the current
curated or user definition, prints the full semantic before/after change and
authority classification, and changes desired state only with `--apply`.
This is the only way an enabled entry moves to a newer revision; it keeps the
choices made when the entry was enabled.

## MCP Model

Runfree imports supported Claude and Codex MCP entries into sanitized per-agent config at runtime. Claude receives a dedicated read-only config and Runfree-managed launches use Claude's strict MCP mode, so passive project `.mcp.json` content is not activated without Runfree approval. This is startup-consent behavior, not containment of code already executing in the agent; proxy policy remains the egress and credential boundary.

- Host/user/local MCP entries can be inspected with `runfree mcp list` and `runfree mcp explain`.
- Project `.mcp.json` and `.codex/config.toml` entries are imported only after `runfree mcp enable` approves them.
- Static headers require a host-owned credential source. A remote HTTP MCP server, and any OAuth address it configures, must use HTTPS and a hostname. An entry that names an IP address or plain HTTP is refused at import, so MCP never adds an IP address to policy. Refused entries are listed with their reason.
- A loopback HTTP MCP server (`http://127.0.0.1:<port>`) imports without credentials, headers, helpers, or OAuth, and only a short list of plain settings passes through. It adds nothing to policy. Inside the session it reaches only a process in that session, unless the host approved a host service on that port; Runfree shows which applies and warns at launch when nothing on the host backs it. Approving the host service is a separate widening. Other loopback forms such as `localhost` are refused.
- Server names are checked before Runfree derives any identifier from them: a name must be one the agent's own `mcp add` accepts. Names that would collide are skipped, except that a user or local server keeps its name over colliding project entries. Names and quoted config text are printed with control characters escaped.
- OAuth login works from any session: every session with an OAuth-capable approved server gets its own loopback callback path ([Session MCP OAuth Callbacks](#session-mcp-oauth-callbacks)). `runfree mcp auth` is a shortcut that launches a session and prints the login steps; `runfree mcp enable` runs it after enabling on a terminal.
- `runfree mcp enable` combines the approval, the credential source, and the server's OAuth hosts in one review. OAuth hosts come from a careful host-side discovery request or from `--oauth-host`. They are kept in host-owned project state, tied to the reviewed server config, and added to the effective policy only, never to desired policy. A discovered host gets only the paths the server's OAuth flow needs, and the proxy mediates the token endpoints recorded for that server alone, which also lets those exchanges pass as reads (see [Proxy Enforcement Details](#proxy-enforcement-details)). `runfree mcp revoke` removes exactly the hosts that `enable` added.
- `runfree mcp revoke` also clears the proxy's OAuth state for the server: its handles, the tokens behind them, and the issuers and endpoints the proxy found. Revoke first records a fresh marker for the server on the host; the proxy discards state that carries an older marker before it applies the next policy, and refuses stale state at use. Revoke reports the state as cleared only when the running proxy confirms it. The proxy also bounds how much OAuth state it keeps per server.
- Side-effecting MCP tool calls use the same write-approval posture as outbound writes and can be governed with `runfree mcp rules`. This covers HTTPS MCP servers, whose calls pass the proxy. STDIO servers and loopback HTTP servers do not pass the proxy, so their calls are not write-governed and `runfree mcp rules` refuses them.

### Codex Desktop Built-ins

Runfree never runs an imported STDIO command on the host and never mounts a
host executable: a STDIO command that is a host path is skipped with a warning.
The Codex Desktop app writes two built-in servers, `node_repl` and Computer
Use, into the shared `~/.codex/config.toml`. They work only inside that app, so
Runfree recognizes them by their app-bundled commands and skips them quietly.
They are never written into the generated agent config and never approved;
`runfree mcp list` shows them as `skipped`. Any other entry, even one with
the same name, keeps the normal STDIO rules.

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
- `runfree resume` inventories and resumes interrupted Claude, Codex, or Pi sessions.
- `runfree vnc` starts an x11vnc session in the agent and forwards it through a loopback-only sidecar for headed UI workflows.
- `runfree forward` opens a loopback-only host port forward into the agent through a labeled, pinned-image ingress forwarder; `runfree forward status` lists open forwards.
- `runfree host-service` approves agent access to a TCP service on the host's loopback, carried by the session relay and an opaque proxy splice; see [Host Services](#host-services).
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
