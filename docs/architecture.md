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

Runtime assets (agent-side files such as the session entry and its readiness
probe, the proxy and its Dockerfile, and project templates) are built from
canonical sources and embedded in the CLI, as the
[pipeline diagram](#runtime-asset-pipeline) shows. The build is reproducible:
the same commit yields the same embedded assets and component digests on any
machine. The CLI materializes the embedded version into XDG data before it
starts Docker Compose, and the agent image, proxy image, topology, and session
template each have their own identity, so a change to one does not replace
the others. Do not edit generated runtime assets by hand.

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
"control generation" is ambiguous.

| Family | Serialized key | What it identifies |
| --- | --- | --- |
| Effective policy generation | `controlGeneration` | The compiled, immutable host/proxy policy generation built from approved `.runfree/` desired policy: network policy, OAuth mediation policy, agent environment, runtime control. |
| Control plane generation | `controlPlaneGenerationDigest` | The runtime control plane a session binds to: proxy image, Compose topology, and admission contract epoch. |
| Temporary access generation | (reserved) | Session-scoped temporary network access records; designed, not yet built. |

A live policy change advances the
effective policy generation only — it neither invalidates held session
admission authority nor implies a control plane replacement.

## Runtime Lifecycle

A typical `runfree` invocation does the following:

1. Resolve the project root and read `.runfree/runfree.json`.
2. Refuse a config below version 4 or a removed key with the remedy (move
   `.runfree` aside and run `runfree init`); nothing migrates it.
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

When `up` or a launch starts the runtime under the project lifecycle lock, and
when `runtime reload-policy --force` restores admission, Runfree first removes
any ephemeral helpers a dead CLI left behind, before any new helper runs or
any session is admitted (see [Ephemeral Helpers](#ephemeral-helpers)).

Agent-image or session-template changes select a new desired session materialization. Existing sessions keep their exact image and template until they end. New sessions use the new materialization without replacing the proxy.

A compatible proxy change rolls under live sessions: Runfree starts a
deny-all candidate proxy, revalidates each live session, rebinds its host
record to the candidate, and publishes the project's session eligibility into
the candidate before selecting it. Nothing is republished on the sessions'
behalf; each surviving session's launch process notices the new selection
before its next heartbeat, adopts exactly one completed rebind of its own
session, and writes its file into the new proxy. Any other divergence refuses
before a durable write. An incompatible admission epoch or control-plane
topology waits for sessions to drain. See
[Compatible proxy replacement](#session-admission) below.

A warm session launch can skip part of full validation. After a full
validation that left nothing to repair, Runfree records a fingerprint of the
validated runtime (proxy instance, networks, other internal-network
participants, images, volumes, both generation families, firewall shape, CA,
daemon, and VM boot). A later launch re-reads that evidence fresh, re-runs the
topology, capability, route, firewall, and contract checks, and skips the rest
only on an exact match. When other sessions are live, the launch must also
account for every peer in one proxy instance, or it validates fully. Any
mismatch validates fully; `runfree up` always does. What the skipped probes
leave unproven is in [security.md](security.md#what-runfree-does-not-prove).

Startup creates one in-memory prepared runtime after durable selection and live proof agree. Public launches consume that exact authority once. A changed container or selection causes one bounded re-prepare attempt. Credential sync occurs only after this prepared authority exists.

Cleanup uses exact references from selections, lifecycle records, direct
containers, and pending rebind state, and removes only inspected
zero-reference images and materializations. A session file no record claims,
an unreadable listing, an ambiguous container, or an unsafe state file stops
the pass. `runfree status` and verbose startup show effective, desired,
retained, and pending generations.

`runfree rebuild` recreates the runtime while keeping Compose volumes and
local images, under operator confirmation and the project lifecycle lock. The
confirmation lists live sessions; only a session that appears after it
invalidates it. After every refusal check passes, rebuild removes Runfree's
own ingress forwarders, ends every session, and tears the runtime down in an
order that is safe to interrupt: a repeated rebuild resumes where the last one
stopped.
Unreadable or unclaimed evidence is refused with `runfree destroy --force` as
the remedy.

`runfree stop` stops services. When Docker proves the selected proxy and both
networks are gone and no session state remains, it also forgets the runtime
selection so the next start begins fresh; otherwise it keeps the selection and
warns.

`runfree destroy` removes the whole project runtime under the lifecycle lock.
Without `--force` it refuses live sessions and unclaimed containers carrying
this project's label. It tears down in the same safe order as rebuild, and
also removes the session containers (which Compose does not own), volumes,
and local images.

Teardown of utilities and networks, forced or not, removes only exact Docker
IDs that Runfree inspected and proved it owns. Names and runtime shape
discover candidates but authorize nothing.

### Session Admission

The runtime admits one agent process per container, each with its own address
on `agent_internal`. Every public command (`runfree claude`/`codex`/`pi`,
`runfree shell`, `runfree resume`, and `runfree mcp auth`) reaches it through
one shared launch path. See [Security](security.md#sessions) for the identity
and proof model and for what it does not establish.

Three participants hold the state, and they can disagree only after a crash:

| Holder | State | What it decides |
| --- | --- | --- |
| Proxy (root tmpfs) | one session file per session, plus one eligibility file | whether an address is served right now |
| Proxy (root tmpfs) | per-address assignment and the two consumers' acknowledgements | whether old address authority has drained before container creation |
| Host (XDG state) | per-session lifecycle records, plus an advisory heartbeat status stamp | which address is reserved, and who owns the session |
| Docker | the session container itself | what can still send packets |

The host is the only writer of the proxy files. Creating an eligible session
file admits, rewriting it renews, and deleting it revokes. The proxy has two
consumers of these files, the root firewall and the unprivileged request
proxy. Each applies the same validity rule on its own loop, and neither
trusts the other's decision. The firewall's admission loop never loads
policy, resolves DNS, or connects upstream, so a slow lookup cannot delay
admission, expiry, or revocation. A file change makes each loop run sooner but
grants nothing; a short fixed interval notices expiring leases and missed
notices. Scheduling can still delay either consumer, so container creation
waits for explicit retirement proof (the [IP Reuse Fence](#ip-reuse-fence))
rather than assuming a maximum delay.

Proxy startup clears all session authority and verifies the firewall's session
set is empty before readiness. Authority returns when the host republishes
eligibility and each surviving session's next heartbeat rewrites its file.

A launch moves through these steps:

1. **Preflight** pins the exact runtime it launches into (control plane,
   session template, launch target, and images) under the project lifecycle
   lock, refuses while a control-plane rebind is pending, and reconciles
   leftover state (below) before it allocates anything.
2. **Allocate** picks a source address that no current participant on the
   internal network and no proxy session file holds, and records it. Session
   addresses come from a pool kept apart from the proxy and helper addresses
   (see [Sessions](security.md#sessions)), and any unknown container on the
   network fails allocation closed.
3. **Fence and start** first retires any old authority on that address (see
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
6. **Await handoff** keeps the lifecycle lock, for a short bounded wait, until
   the Docker daemon's process listing shows that the entry has started the
   agent, so a proxy replacement cannot land between the grant and the start.
   The process list is under the container's control, so it decides only when
   the launch reports `attached`. It grants nothing.
7. **Await completion** releases the lifecycle lock and runs the heartbeat for
   the life of the attached process.
8. **Teardown** revokes the session (see **Revoke** below).

The lifecycle lock covers steps 1–6 and teardown. It is not held for the
interactive session.

**Lock handoff and budgets.** A warm agent, shell, or `mcp auth` launch can
hand the lock startup took straight to admission, with what startup proved
under it; admission then skips only the repeated reconcile, and only when the
registry and proxy instance are unchanged. It still fences the address and
proves the container. A warm launch can also skip startup's reconcile when
every view, read under the held lock, shows no session state; an unreadable
view never counts as empty. A launch plans its lock hold to end before other
commands stop waiting for the lock, and image builds and credential-source
reads finish before the lock is taken. Ordinary heartbeats take no lock. The
bounds are in [security.md](security.md#lifecycle).

**Heartbeat.** While the foreground runs, the owner periodically adopts a
completed compatible rebind if the durable selection changed, inspects the
container, and rewrites its session file. Inspection and write are one sealed
step, so no file is written without a same-call inspection. A beat takes no
lifecycle lock, so one session's slowness cannot delay another's. An
unavailable observation skips the write and lets the previous file run down
its own lease; an inspection that proves a different container, address, or
endpoint, or a stopped or missing container, deletes the file at once. No beat
outcome ends the agent process: the loop's only power is over this session's
file.

Each beat also rewrites an advisory host status stamp. Lease or stamp expiry
removes no live owner's reservation: automatic reclamation requires positive
owner-death evidence, and unknown owner liveness preserves the record.

If the attached stream ends while the same container is still running, only
the *view* was lost, and the driver re-attaches a bounded number of times.
Reaching the bound never ends a proven-running session.

**Revoke** is one ordered, repeatable sequence shared by the launch owner and
reconcile: mark the record terminal, delete the session file, disconnect,
stop, and remove the container, then delete the record and the status stamp.
The file goes first because it is the authority; the record goes last because
it reserves the address. If the file cannot be deleted, the sequence stops and
keeps the record until a later pass finishes. After a normal exit that Docker
confirms exactly, the owner skips the disconnect and stop. Teardown speed is
not a security guard: the next container cannot reuse the address until the
IP fence proves the old authority gone.

**Reconcile** runs under the same held lock as the allocation that follows, at
every launch preflight (or in the startup that handed over the lock) and at
`runfree up`. It deletes proxy files no lifecycle record claims, tears down
records whose owner is provably dead, removes session containers no record
claims, keeps records whose owner cannot be proved either way (reported, with
`runfree destroy --force` as the remedy), and republishes eligibility from
what survived. A file listing the host could not read refuses the launch
rather than allocating over files it cannot see. `runfree sessions` runs the
same observation in report mode: no lock, no writes, no Docker effects.

**Compatible proxy replacement** is a durable, resumable transaction under
the lifecycle lock. Eligibility is published into the candidate before the
selection flips, because a proxy without it serves nothing. The old proxy is
gone once the candidate is created, so surviving sessions are unserved until
each one's next heartbeat adopts the new selection and writes into the
candidate. Recovery has a bounded project-wide allowance that ordinary
launches cannot reset. Use `runfree runtime recover` to resume a pending
transaction, or `runfree runtime recover --retry` to authorize a new allowance
after repair. Recovery preserves the session network, CA pair, OAuth volume,
and agent processes, never replays application writes, and preserves
resources when an observation is unavailable.

A proved proxy boundary violation permits exact proxy containment under the
lifecycle lock; a failed observation never authorizes Compose teardown, and a
containment that fails reports unconfirmed safety and stops recovery. Open
sockets and in-flight OAuth exchanges can end and are not replayed.

A record with a terminal host status stamp is an interrupted teardown, not a
session; the usual cause is a Docker daemon that died under a live session.
The next start finishes it when Docker can prove it safe, and otherwise
refuses with the remedy (see [security.md](security.md#lifecycle)).

#### Session File Contract

Only the host writes session files, through a root-only channel into a
root-owned proxy directory; the request proxy can read them but not write
them. A session file names the session's identity (project, session,
incarnation, address, container, network), its bindings (control plane
generation, admission contract epoch, images), and its lease. The lease is
anchored to the Docker inspection that authorized the write, not to the write
itself, so write latency cannot extend the time between proof and authority.
The parse is exact, and a malformed or contradictory file serves nobody. The
host also publishes one eligibility file per proxy, naming what may be
admitted, after the control plane is selected, after a proxy restart, from
every reconcile, and into a rebind candidate before the selection flips.

**Dual-clock validity.** Each consumer bounds a file by both its wall-clock
deadline and the proxy's own monotonic clock, fixed when a given write is
first observed, so replayed bytes extend neither. A rewrite that only advances
the lease keeps established sockets and grants; a changed identity destroys
them, and a session whose lease had lapsed is served again only after its old
sockets and grants are gone.

**Clock caveats.** The monotonic clock does not advance while the Docker VM is
suspended, but the wall deadline does, so after a long host sleep the proxy
drops the session on wake and the next heartbeat re-admits it within seconds.
A guest wall clock that is ahead of the host by more than the lease minus the
cadence makes every file expired on arrival, and the session is not served. A
guest clock that is behind keeps a file valid for longer, but the monotonic
bound still caps it at the maximum lease.

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

The barrier refuses to proceed if the assignment changed since the host read
it. The retained assignment binds the address to the new session key for the
proxy's lifetime, so a delayed old session file cannot regain authority. A
failed fence leaves the address draining and refuses creation; a later launch
repeats the barrier. Missing or unsafe assignment state denies all membership.

#### Admission Proofs

- **No file, no authority.** Between container start and the session file,
  nothing names the session: its address is in no kernel set and the request
  proxy refuses it. Docker refuses a duplicate static address, and taking a
  session's address would need Docker daemon access, which the agent does not
  have.
- A proof exists only when the host minted it from an exact Docker inspection,
  and a caller cannot construct or copy one. Every consumer re-checks that it
  names this project, session, container, images, generations, address, and
  network, and a proof that is too old authorizes nothing.
- The one post-start inspection holds the container to the create plan
  exactly, and the session file's renewal anchor is a projection of it. The
  comparison stays exact across Docker daemon releases.

#### Ephemeral Helpers

Startup runs the direct-egress deny probes, the trust-bundle render, and
dependency-volume preparation as short `--rm` containers on the untrusted
project agent image.

- **Bounded, under the lock.** A helper starts only while the project
  lifecycle lock is held, with hardened flags and a hard timeout.
- **Marked on the host.** Before the spawn, each run writes a marker into
  host project state, which the agent cannot see; a clean exit clears it. The
  marker grants nothing; it only tells the next lock holder to sweep.
- **Swept by label under the lock.** After an unclean exit, and at the next
  lock acquisition when the marker is present, Runfree removes this project's
  helper-labeled containers and confirms none remain. Helpers run only while
  the lock is held, so any helper a lock holder sees is residue. Every
  container Runfree creates sets its own role and project labels, which
  override any image label, so a project image cannot make a session look like
  a helper. An unconfirmed sweep keeps the marker and refuses the launch.
- **Late create (accepted).** If the Docker client dies mid-create, the daemon
  can still create the helper after a sweep found none. The marker is kept for
  a while so later lock holders sweep again; such a container stays `created`
  with no network endpoint, and an orphaned client that does start it is
  dropped by the firewall as an unadmitted source.
- **Label minting (accepted).** A process with Docker socket access can put
  the helper labels on another container, which the sweep then removes. The
  agent has no Docker socket, and the Docker daemon is trusted. Two Runfree
  state roots driving the same project path do not share the lock, so one can
  sweep the other's running helper; that run then fails closed.

The deny-probe helper sits in the agent position on `agent_internal`, with an
address from a small reserved block below the session pool.

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
  forwarder targets. A forwarder without a binding is refused.
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
not the proxy's runtime policy.

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

The request proxy runs as an unprivileged user inside the proxy container.
Checks run in this order:

```text
host allowlist -> request shape -> write class -> write action -> credential -> OAuth -> upstream
```

A request that fails a step reads no token, does no OAuth mediation, and
opens no upstream connection. One exception: when a request's class depends
on its body (a non-read request to a declared GraphQL endpoint, an MCP call,
or a POST to a recorded OAuth endpoint), the proxy reads the body locally
before the shape check.

**Request shape.** On hosts with method or path rules, the proxy enforces the
allowed methods and path prefixes, strips method-override headers, and refuses
any path the proxy and the origin could read differently (encoded separators,
dot segments, malformed encodings). WebSocket upgrades are checked as GET.
Denials name their reason in a response header.

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

**Holds.** Under `ask` the proxy holds the request for a bounded time while a
host approver decides; with no approver attached, it refuses at once. The
pending record is proxy-side, but decisions come only from root-owned files
the host writes, so neither the agent nor the proxy process can approve
itself. An approved request re-runs the full policy check. A WebSocket upgrade
cannot be held, so WSS approval is deny-then-retry, matched by a
request-scoped grant.

**Denial feedback.** A denied HTTPS CONNECT is answered inside the tunnel with
a synthetic 403 that names the host and the remedy (`runfree host add`,
`host rules`, or `approvals --watch`). A certificate-validating client sees a
TLS error instead, but the proxy still records the denial for `runfree doctor`
and the session-end summary. Logs carry the path only: no query, no body, no
credential values.

**Audit mode.** `runfree up --audit-network` relaxes only the host allowlist,
for a bounded window that a skewed clock cannot extend. HTTPS-only, port 443,
and DNS answer checks still apply; audited hosts get no token injection, and
configured credential headers are stripped (except on WSS upgrades; see
[security.md](security.md#residual-risks)). At expiry or `runfree audit off`,
in-flight audited connections are cut.

**Firewall.** A root supervisor in the proxy container programs one nftables
table: only admitted session addresses reach the request proxy, outbound
traffic is dropped except HTTPS to the resolved addresses of allowed hosts and
the approved host-service pairs, the request proxy cannot use DNS itself, and
IPv6 is loopback only. The supervisor resolves allowed hosts and drops private,
loopback, link-local, and other non-public answers before they reach the allow
set or the resolver snapshot the request proxy answers from. The host-service
gateway never enters either, so an allowlisted host that resolves to it is
still refused.

**Process hardening.** The proxy container's root entrypoint keeps the
network-admin capability only for the firewall, and starts the request proxy
as its unprivileged user with every capability and privilege escalation
removed, checking this at runtime. The host also verifies the proxy's default
route.

**Agent container.** Session containers run unprivileged with network
capabilities dropped (see [security.md](security.md#agent-container)). The
agent trusts the proxy CA through a bundle the host renders into a read-only
mount, so the agent never needs root to install trust.

**Runtime inputs lock.** The runtime inputs lock pins base images by digest,
exact apt package versions, and release artifact checksums. A missing or
malformed lock fails before any build.

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
supported. Adding a service or changing its port is a widening and always
needs host review; removing one is a reduction. The name `runfree.internal`
and every name under it are reserved for host services.

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
header stripping, credential injection, or write approval apply inside it.
Each splice belongs to its session, so ending or fencing the session (see
[IP reuse fence](#ip-reuse-fence)) cuts it.

**Session relay.** Many clients (database drivers, gRPC libraries, custom
tools) ignore proxy variables, so each session starts a small relay on its
own loopback, on the same port numbers as the host services, that forwards
each connection to the proxy. It runs as the agent user with no added
authority, and peer sessions cannot reach it. The service list is fixed when
the session starts.

**Gateway address.** The proxy learns the host gateway address from Docker,
never from DNS. The root firewall supervisor checks it, pins the first valid
address for the life of the proxy, and hands it to the request proxy. If the
address later changes or becomes invalid, host services stop until
`runfree rebuild`.

**Revocation.** When a service is removed, or the gateway changes or is
withdrawn, two consumers cut it independently. The request proxy closes the
affected splices. The firewall drops packets to the old pair at once, and keeps
dropping any traffic to a pinned gateway on a pair that is no longer approved,
from any user and even for a flow the request proxy did not track. Each
consumer cuts before it reports the new effective policy generation, and
activation waits for both, so `runfree host-service remove` reports the change
as live only after both have cut.

Port admission, the cross-project port registry, and the commands are in
[cli.md](cli.md#host-services); limits and per-launch proofs are in
[security.md](security.md#network).

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
into it (Bearer, raw, or HTTP Basic with a fixed non-secret username, which is
what git over HTTPS expects). It can be narrowed by a path prefix, by a
protocol scope the proxy recognizes itself (git smart HTTP or the Git LFS
API), or both. A request the proxy cannot classify for certain gets no
credential. When several destinations of one host match, the proxy picks the
most specific, and policy that could tie is refused. The rules are in
[cli.md](cli.md#user-defined-services) and
[security.md](security.md#git-over-https).

Sources are read on the host, never while the lifecycle lock is held.
`runfree up`, a cold start, and a replaced proxy read every source first. A
warm session launch may reuse a value the proxy already holds when a host
receipt shows it is current; right after the launch, a background watcher
re-reads every source, so a value rotated or revoked at its source reaches the
proxy seconds later. The reuse and failure rules are in
[security.md](security.md#credentials).

## Services

Services are named host bundles. Curated services live in `scripts/services.ts`; user-defined services use `user-*` ids and are stored under the Runfree XDG config root. Credentialless `agent-claude` and `agent-codex` services cover native subscription/login traffic and are distinct from the credential-bearing `anthropic` and `openai` API-key services.

A service may declare `parameters`: non-secret inputs it needs beside its
secrets (an OAuth client id today), which `service enable` resolves and
records in the host-owned agent environment. Anything that must stay out of
the agent container is a credential or an OAuth seed, never a parameter.

Enabling a service writes one complete, self-contained entry to desired
policy. It does not leave service authority in `runfree.json`. Credential
source bindings remain host-owned. Broad multi-tenant hosts are called out
before enable and can be excluded. `runfree service diff` is the only way an
enabled entry moves to a newer revision; it shows the full semantic change and
keeps the choices made when the entry was enabled.

## MCP Model

Runfree imports supported Claude and Codex MCP entries into sanitized per-agent config at runtime. Claude receives a dedicated read-only config and Runfree-managed launches use Claude's strict MCP mode, so passive project `.mcp.json` content is not activated without Runfree approval. This is startup-consent behavior, not containment of code already executing in the agent; proxy policy remains the egress and credential boundary.

- Project `.mcp.json` and `.codex/config.toml` entries are imported only after `runfree mcp enable` approves them, in one review that also covers the credential source and the server's OAuth hosts. OAuth hosts live in host-owned project state and the effective policy only, never in desired policy; the proxy mediates the token endpoints recorded for that server alone (see [Proxy Enforcement Details](#proxy-enforcement-details)). `runfree mcp revoke` removes exactly those hosts and clears the proxy's OAuth state for the server.
- Remote HTTP servers must use HTTPS and a hostname, so MCP never adds an IP address to policy. A loopback HTTP server (`http://127.0.0.1:<port>`) imports without credentials, headers, helpers, or OAuth and adds nothing to policy; it reaches the host only through a separately approved host service.
- OAuth login works from any session: every session with an OAuth-capable approved server gets its own loopback callback path ([Session MCP OAuth Callbacks](#session-mcp-oauth-callbacks)).
- Side-effecting tool calls on HTTPS servers follow write approval (`runfree mcp rules`). STDIO and loopback HTTP servers do not pass the proxy, so their calls are not write-governed.

### Codex Desktop Built-ins

Runfree never runs an imported STDIO command on the host and never mounts a
host executable. The Codex Desktop app's built-in servers (`node_repl` and
Computer Use), which work only inside that app, are recognized by their
app-bundled commands and skipped; `runfree mcp list` shows them as `skipped`.

## Dependency Overlays

Dependency overlays mount common dependency directories and caches from Runfree-owned Docker volumes. This keeps generated dependency artifacts container-owned and reduces host artifact drift. The default is `dependencyOverlays: "auto"`; the `runfree deps` commands are in [cli.md](cli.md#dependency-overlays).

## Project Image Customization

`runfree image init` creates `.runfree/image/Dockerfile`. Project Dockerfiles extend `RUNFREE_BASE_IMAGE`; full image overrides are not supported. Wide build contexts require explicit host-state approval with `runfree image approve-context`.

Project image builds run before the sandbox exists, on the host Docker daemon
with normal build networking. Runfree stages narrow `.runfree/image` contexts
itself after it rejects symlinks, hard links, special files, and context
escapes. The narrow-context approval subject is the staged manifest (file bytes
and modes), the Dockerfile, and the normalized build config. Embedded runtime
identity (base image, version arguments) is outside the subject: a Runfree
upgrade rebuilds without a new prompt. Builds use only a stored snapshot that
re-verifies byte-for-byte against the approved manifest. A snapshot that fails
verification is never built; the launch warns and asks again over freshly
staged bytes.

A project image may replace the base image's session entry. What it loses is only the start ordering: the agent may then send before activation and be refused, exactly as the proxy refuses any pre-activation request. Authority is unchanged. See [Readiness Entry](#readiness-entry).

## Optional Side Features

- `runfree inbox paste` imports a macOS clipboard image into the read-only `/runfree/inbox` mount and prints its container path.
- `runfree resume` inventories and resumes interrupted Claude, Codex, or Pi sessions.
- `runfree vnc` starts an x11vnc session in the agent and forwards it through a loopback-only sidecar for headed UI workflows.
- `runfree forward` opens a loopback-only host port forward into the agent through a labeled, pinned-image ingress forwarder.
- `runfree host-service` approves agent access to a TCP service on the host's loopback; see [Host Services](#host-services).
- `runfree git repair-worktree-links` repairs host Git worktree metadata to use relative links.

## Development And Verification

The checks to run before a change are in [CONTRIBUTING.md](../CONTRIBUTING.md),
and what each test layer proves is in [testing.md](testing.md).
