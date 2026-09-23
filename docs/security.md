# Security

Runfree is security-sensitive local developer tooling. Its central assumption is simple: **the coding agent is untrusted, and the proxy is the trust boundary for outbound HTTPS/WSS and proxy-managed credentials**.

This document is the public security model for Runfree. For reporting vulnerabilities, see [`../SECURITY.md`](../SECURITY.md).

## Security Goals

Runfree aims to:

- keep real service credentials out of the agent container;
- prevent agent-authored desired policy from widening effective runtime authority;
- route outbound HTTPS/WSS through a policy-enforcing proxy;
- block direct agent egress around the proxy by Docker topology and runtime checks;
- enforce exact-host allowlists and optional request-shape rules;
- classify and hold side-effecting outbound writes when configured as `ask`;
- import MCP config only through host-owned approval and sanitized runtime generation;
- make denials visible through session summaries, proxy logs, and `runfree doctor`.

## Threat Model

### Trusted

- the host user who runs `runfree` commands;
- the Runfree CLI and its embedded runtime assets;
- the proxy container and proxy-side token state;
- host credential helpers selected by the user, such as `gh`, `op`, or custom source commands;
- Docker Desktop / OrbStack and the host OS.

### Untrusted

- prompts, model output, and tool calls inside the agent session;
- project code executed by the agent;
- project-controlled files such as `.mcp.json`, `.codex/config.toml`, package scripts, test scripts, and dependency install hooks;
- network responses from allowed hosts;
- VNC display contents and clipboard data when optional VNC forwarding is used.

### In Scope

- prompt injection that asks an agent to exfiltrate a token;
- a project script attempting direct internet access;
- a malicious project MCP descriptor requesting credentials or tool access;
- a confused-deputy request to an allowlisted host using a proxy-managed credential;
- a request that should be read-only but uses a write method or write operation;
- project files attempting symlink or hard-link attacks against host-side `.runfree` writes.

### Out Of Scope

- a malicious Docker daemon, host OS, shell profile, or credential helper;
- kernel/container escape vulnerabilities;
- malicious code intentionally run by the host user outside Runfree;
- guarantees that an allowed request is semantically safe for the upstream service;
- VM-grade isolation for arbitrary hostile native code.

## Trust Boundary

```text
host Runfree CLI ── starts/validates ── Docker Compose
      │                                  │
      │                                  ├─ agent: untrusted /workspace execution
      │                                  │       └─ proxy env vars, no real service tokens
      │                                  │
      │                                  └─ proxy: trusted policy + credential boundary
      │                                          └─ upstream HTTPS/WSS after policy allow
      │
      └─ host-owned sources: env, 1Password, commands, stdin, JWT, OAuth seed material
```

The agent can request network access only through the configured proxy path.
The proxy performs allowlist, request-rule, write-action, and
credential-injection decisions from a host-owned selected effective generation.
Desired policy is writable project input; approval, compilation, selection, and
token-source resolution happen on the host.

### Runtime Participants And Identity

Each agent process runs in its own session container with its own address on the internal network. That source IP is a network-admission identity for the proxy firewall and the request proxy, not a user or session identity: it says which container is speaking, not which user or which prompt. The firewall accepts new proxy ingress only from addresses the host has admitted, and the request proxy resolves a request's principal from the same admitted address, so a write-approval grant takes that session as its subject. `source-ip-v1` is the only identity mode: the proxy refuses to start without complete session-identity configuration, and there is no runtime-wide grant subject.

The internal network may also contain declared utility roles. The MCP OAuth callback and VNC forwarders are narrow transport sidecars, not credential or authorization boundaries. Runfree rejects unknown peers; each recognized role has constrained launch behavior and live shape checks for its command, networks, loopback publication, mounts, user, capabilities, and writable state as applicable. The MCP OAuth callback forwarder must target a live session address, so a stale or hardwired target is rejected rather than silently forwarded.

Before admitting beside an ingress forwarder, the host rechecks that shape,
the resolved immutable image ID, and the exact internal and host network IDs
under the lifecycle lock. The network baseline reserves the forwarder's
address; it grants no session-file authority. Only that inspected utility is
excluded from the session orphan refusal, and conflicts with session records
still refuse. A failed utility proof is reclaimed by repairing or stopping the
forwarder, or by `runfree destroy --force` for a whole-project reset.

### Per-Session Admission

Runfree admits one agent process per container, each with its own address on
the internal network. **This is the launch path.** Every public command —
`runfree claude`/`codex`/`pi`, `runfree shell`, `runfree resume`, and `runfree
mcp auth` — reaches it through `session-public-launch.ts`, and the pre-cutover
shared long-lived agent container no longer exists.

A session's identity is its source IP on the internal network, allocated from a
fixed pool inside the subnet after excluding every address the current network
baseline already holds. That is a network-admission identity: it says which
container is speaking, not which user or which prompt. It is the subject of
write-approval grants, and revoking a session's authority drops the grants
keyed to it. One caveat on proof: the live suites prove admission-set
separation between sessions, but session-scoped approval-grant separation —
that one session's grant cannot be redeemed by another live session — has
unit-level proof only, with no live test yet (the code notes the same limit in
`session-admission-probe.ts`).

**A root-owned session file grants a bounded lease; an IP assignment constrains its owner.**

```text
/run/runfree-sessions/sessions/<sessionKey>.json   root:root 0644
/run/runfree-sessions/eligibility.json             root:root 0644
/run/runfree-sessions/ip-reuse/requests/<ip>.json   root:root 0644
```

Creating an eligible session file admits, rewriting it renews, and deleting it
revokes. Ordinary heartbeats do not wait for either consumer. Before creating a
container, the host fences its IP address and waits for both consumers to
retire old authority. A retained IP assignment permits only the new session
key; it cannot grant a lease by itself.

The file carries the session's identity (project, session key, session id and
incarnation, source IP, container id, internal network id), the bindings it must
be eligible under (control plane generation digest, admission contract epoch,
selected agent image ID and session-agent generation digest), the display fields
the approval prompt needs, and three renewal fields — a fresh random `nonce` on
every write, the `inspectedAt` of the Docker inspection that authorized that
write, and `aliveUntil = inspectedAt + lease`. The wire contract is
`packages/runtime-contracts/src/session-file.ts`, and the parse is exact: an
unknown key, a missing required key, a file whose name is not its own embedded
`sessionKey`, a payload over 8 KiB, or an `aliveUntil` more than the five-minute
maximum lease past `inspectedAt` are all refused. Because `aliveUntil` is
anchored to the inspection rather than to the write, `docker exec` latency
cannot stretch the gap between proving a container and granting it authority.

The host is the only writer. Every write, delete, and read runs as one pinned
`docker exec --user 0:0 -i <exact proxy id> node -e <sealed script>` argv with a
sha256 of the exact stdin bytes as a separate argument
(`session-file-publisher.ts`): no shell, no interpolated path, and a payload the
host did not digest is refused before any open. The script proves the parent
directory is root-owned and not group/other-writable, writes a temp file in the
destination directory with `O_EXCL|O_NOFOLLOW`, fsyncs it, renames, fsyncs the
directory, and reads the result back. The agent container has no Docker socket
and no mount of that directory; the uid-1001 request proxy reads the files and
can never write one.

Eligibility is the sibling root-owned file. It names the project, the control
plane generation digest, the admission contract epoch, the internal network id,
and the agent materializations that may be admitted. A proxy holding no
eligibility file serves nothing.

These are the required security invariants, and each is enforced in code rather
than by ordering alone:

1. **No authority without a host-written file.** An address is served only while
   a root-owned, well-formed file names it, the file is eligible, its
   `aliveUntil` is in the future on both proxy clocks, and no other file claims
   the same address. An unreadable root, eligibility file, or sessions directory
   serves nothing (`session-files.ts`, `session-file-validity.ts`).
2. **Dead-host bound.** A host that stops writing loses that session's authority
   within the five-minute maximum lease of its last write, on the proxy's own
   clocks.
3. **No address reuse under an existing record or file.** An address is
   allocated only from the pool minus every address a lifecycle record, a
   reserved entry, or a live network attachment holds. Teardown deletes the
   proxy file first and the host record last; a failed file delete stops the
   sequence and keeps the record; reconcile sweeps orphan files before any
   allocation in the same critical section, and every address a proxy file
   named — deleted or not — is passed to the allocator as reserved.
4. **Identity is re-confirmed on every heartbeat, and a proven mismatch
   revokes.** One sealed function inspects and writes; an inspection that
   *proves* a different process id, start time, network endpoint, address, or a
   container that is not running — including Docker's definitive "no such
   container" for the pinned id — deletes the file at once. An *unavailable*
   inspection deletes nothing.
5. **Both consumers read one source.** The request proxy and the root firewall
   derive membership from the same files with the same rule on their own 100 ms
   loops, each over its own observation map, so neither consumes the other's
   decision. Scheduling can delay either loop; IP reuse waits for explicit proof.
6. **Per-session write approvals and prompt routing are unchanged.** Grants stay
   keyed by session key and are dropped when the file is removed or expires.
7. **Peers never mutate a live-owner session.** Reconciliation acts only on
   records whose owning host process is provably dead.
8. **Fail closed on contradiction.** Two files claiming one address (neither is
   served), a file whose project or control-plane bindings do not match the
   proxy's, a malformed file, or a file whose name and embedded key disagree:
   none of the parties involved is served.
9. **Eligibility is published, and absent eligibility serves nothing.** The host
   publishes it on proxy start and restore, from every launch's reconcile, and
   on rebind to the candidate before the selection flips. Ordering is widen
   before new session files, narrow after old files are gone.
10. **No write without a same-call inspect.** `inspectAndWriteSessionFile`
    (`session-file-heartbeat.ts`) performs the inspection and the write, and
    copies the written identity fields from the inspected answer; nothing else
    can produce a session file.
11. **Launches keep working across a compatible rebind.** The rebind keeps its
    host-side `sessions-revalidated` and `records-rebound` phases so every host
    record carries the new control plane generation digest before any launch
    reads the network baseline, and each driver's next heartbeat adopts the
    durable selection before it writes.

Both consumers run level-triggered 100 ms loops inside the proxy container. The
root firewall's loop reads only the session files, the eligibility file, local
time, and nftables session-set state, and it is the only runtime writer for
`session_ipv4`; policy loading, DNS, audit maintenance, and upstream I/O live in
a separate scheduler, so external latency cannot extend a lease or delay
revocation. The request proxy's loop rebuilds an in-memory served map and
answers every connection from that map instead of re-reading the directory per
connection, so admission is at most one loop stale. Validity is the dual-clock
rule: the wall deadline comes from the file and the monotonic bound is
`min(aliveUntil − guest now, five minutes)` fixed at the first observation of a
given `nonce`, so identical bytes replayed later extend neither clock, and a
rewrite with a new `nonce` is a new observation whatever its stamp order says.
A session whose new `nonce` supersedes an observation that had already elapsed
is served again only after its previous sockets and grants are destroyed.

Both loops target a 100 ms cadence. Process scheduling and kernel operations
can delay them, so this is not a maximum revocation time. Address reuse does
not depend on that interval or on Docker teardown taking longer than it.
The host completes an explicit IP fence before creating the next container.

Admission itself is a fixed ladder under the project lifecycle lock: reconcile,
allocate an address and write the `allocated` lifecycle record, fence the IP, create the
container with a static address and `--restart no` and start it attached, take
one post-start inspection as the running proof, then write the session file and
advance the record to `attached`. The lock is released once the file is written;
the attached wait holds no lock.

**The readiness probe waits for this session to become active.** The
container's first process is not the agent but a Runfree-owned entry program
shipped in the base agent image (`session-entry`, with its
`session-ready-probe`). The typed launch target names the entry as the
container's `Path` and carries the agent launch as its `Args`. The entry polls
the request proxy with one exact readiness request and execs the agent only on
`200` with the body `active`. Before the session file exists the firewall drops
that connection outright, which the probe reports as its connect-failure exit
code; a peer the firewall has already admitted but whose file the request proxy
has not yet observed is refused `403`; and the probe gets `200` once the file is
served. There is no intermediate "registered, provisioning" answer, and the
retired `204` is gone. The readiness
answer is produced locally before any admission record is minted or session
socket registered: it forwards nothing, resolves nothing, and grants nothing the
peer does not already hold. The entry is cooperation, not proof: it exists so no
client's first request lands in the pre-admission window. A project image may
replace it, which changes only start ordering — enforcement remains the firewall
session set and the guard's source-IP identity check. The entry's wait bound is
host-rendered into the pinned session environment
(`RUNFREE_SESSION_ENTRY_TIMEOUT_MS`, 60 s), and it is the only admission-failure
path: an entry that gives up exits 111, the container stops, that becomes the
launch's exit status, and the ordinary teardown reclaims the file, container,
and record.

**Renewal is a heartbeat, and no step of it can revoke, pause, or wedge a live
session.** While the attached process runs, the launch owner beats every 30 s:
adopt a completed compatible rebind if the durable selection changed, inspect
the container, and rewrite the file with a fresh nonce and a lease anchored to
that inspection. Consecutive failures back off from 1 s, doubling to a 30 s cap
with ±20 % jitter. A beat takes no lifecycle lock at all unless it finds a
rebind to adopt, so one session's slowness cannot delay another session's
admission or renewal, and there is no whole-registry critical section to
serialize against. An *unavailable* observation (timeout, daemon error,
unreadable answer, failed exec) skips the write and retries; the last file
simply runs down its own lease. A *proven* mismatch deletes the file at once,
which bounds a wrong container on an admitted address to one cadence plus one
consumer loop. Neither outcome ends the agent process: the loop's only power is
over this session's file, so a session whose heartbeat is failing keeps running
unserved rather than being killed.

Each beat also rewrites a host-side status stamp under the project state
directory (`session-host-status.ts`) recording the last heartbeat, the granted
`aliveUntil`, and whether the last beat was served or is retrying. The stamp is
advisory. The durable lifecycle record's lease freezes at admission. Neither
that deadline nor a stale or missing stamp proves that its owner is dead.
Automatic reclamation requires positive owner-death evidence: a missing
process or a changed boot/process-start identity. An alive or unknown owner
keeps its record and IP reservation. Lease expiry removes proxy authority;
it does not authorize destruction of the agent container. Explicit owner
teardown remains available. See [liveness](../packages/cli/src/runtime/session-record-liveness.ts).

If the `docker start --attach` stream ends, the driver inspects before it
concludes anything. The same anchored incarnation still running means the view
was lost, not the session: the driver re-attaches with `docker container
attach`, at most three times in a rolling 60 s window. Signals are forwarded
exactly as on the original attach, so Ctrl-C still reaches the agent, and a
session that was not launched interactively is re-attached with `--no-stdin` so
this host's stdin never appears on its input. Reaching the cap never destroys a
process this host has just proved running: the driver stops replacing the view,
keeps beating, and waits for the container's own exit, which the next
inspections report as an exit status. An inspection that proves the container
exited yields that exit status; one that proves a different container tears the
session down; one that cannot be made yields nothing at all and the next beat
asks again.

**Revocation is ordered, and the order is load-bearing.** Under the lock the
owner writes a terminal marker into its host status stamp, deletes the session
file, disconnects the network endpoint, stops the container with its SIGTERM
grace, removes it with `--force`, and only then removes the lifecycle record and
clears the stamp (`session-file-teardown.ts`). Every step is idempotent and safe
to repeat. A file delete this host could not perform stops the sequence at once:
no stop, no removal, and above all no record removal, because the record is what
reserves the session's address. The reclamation is the same call run again — by
this owner's second cleanup pass, or by the next launch's reconcile once this
owner is gone. A successor must complete the IP fence below before Docker
creates its container. Teardown duration is not part of that security proof.

**IP reuse has an explicit retirement barrier.** Under the lifecycle lock,
the host writes a root-owned `draining` assignment with a fresh nonce and the
new session key. Before this write, the host reads the existing assignment.
The executor takes a kernel `flock` on the root-owned IP-assignment directory
and requires that the assignment still matches those exact bytes. It holds
that lock through retirement and publication. A delayed Docker exec cannot
replace a later assignment or drain its connections. Executor exit releases
the lock; a timed-out lock acquisition refuses creation and can be retried.
The existing util-linux package provides [flock](https://man7.org/linux/man-pages/man1/flock.1.html).
Both consumers exclude the draining address. The root supervisor
acknowledges only after it verifies the nftables set excludes the address.
The host then kills old incoming TCP sockets for that address and proxy port
with `ss -K`, and requires a second `ss` query to report none remaining.
Linux can retain unaccepted sockets after the kill command. The request proxy
continues to accept and destroy sockets for draining addresses. The host
retries the kernel query within its deadline and refuses if sockets remain.
The ingress listener binds IPv4 explicitly, so its connections are included
in the IPv4 kernel query. A successful kill command alone is insufficient.
TIME_WAIT entries carry no
application stream and do not block reuse.

After the kernel drain, the host writes a second fresh nonce. It waits for
both consumers to acknowledge it. The request proxy first removes the old
session mapping, grants, and every accepted socket from that IP, including
incomplete CONNECT requests. Identity is fixed at accept time. Only then does
the host publish `ready` and create the new container. The retained assignment
binds the IP to that session key for the proxy lifetime, so a delayed old
session file cannot regain authority or conflict with the new owner's file.

A failed fence leaves the address draining and refuses container creation.
A later launch replaces the nonce and repeats the same barrier. Missing or
unsafe assignment directories deny all membership. Proxy startup clears
assignments together with session authority and old connections. Surviving
sessions can then restore through freshly inspected files; every new container
still passes the fence. Kernel draining runs in the pinned host exec, outside
the root lease loop, so its delay cannot stall other sessions' expiry.
See [publisher](../packages/cli/src/runtime/session-file-publisher.ts),
[assignment reader](../packages/proxy/src/session-ip-reuse.ts), and
[negative live tests](../tests/runtime/live/session-admission-negative.live.test.ts).

**Every launch reconciles three lists before it allocates an address**
(`session-reconcile.ts`), inside the same held lock as the allocation: proxy
session files with no lifecycle record are deleted first, records whose owner is
provably dead are torn down through the shared ordered teardown, session
containers no record claims are stopped and removed, and eligibility is
republished from what survived. The proxy's own listing is the only view of the
files, so a listing that cannot be read is not "no files": the launch refuses
before allocating and names `runfree up` as the retry. A dead owner's teardown
blocked at the file delete keeps its record on purpose — the address stays
reserved — and names `runfree up` to retry or `runfree destroy --force` if the
file will not go away. A record whose owner can be proved neither alive nor dead
is reported and left exactly as it is, with `runfree destroy --force` as the
named remedy; its file expires on its own lease. The addresses a reconcile
reserves are filtered to the pool's own `/24` before they reach the allocator,
because the allocator refuses a reserved address outside its subnet and a file
left behind by an earlier network would otherwise become a permanent launch
refusal.

Two clock caveats are inherent to the dual-clock rule, and both are parity with
the previous design rather than new. The monotonic clock both consumers use is
`performance.now()`, which is `CLOCK_MONOTONIC` and does not advance while the
Docker VM is suspended: it therefore neither expires a lease during a host sleep
nor extends one across it. The file's wall deadline does elapse, so after a long
sleep the proxy drops the session on wake, destroys its sockets and grants, and
the next heartbeat re-admits it within seconds — a few seconds offline is the
whole observable effect of sleep. Separately, a guest wall clock that *leads*
the host by more than the lease minus the cadence makes a session unservable,
because every file the host writes is already expired when the proxy reads it; a
guest clock that lags is harmless to availability — it can only hold a file
valid for as much longer as it lags, and the monotonic bound taken at first
observation still caps that at the five-minute maximum lease. The lease stays
five minutes and the cadence stays at or below a third of it.

Eligibility is published at every point that could change the admitted set:
after the control plane is selected and proven at `runfree up` and at launch, on
a same-container proxy restart (which recreates the session directory and takes
`eligibility.json` with it), from every reconcile, and during a compatible
rebind to the candidate container before the durable selection flips. The
publication is idempotent: the exact bytes last published are recorded against
the proxy container ID *and* its Docker `StartedAt`, because an in-place restart
keeps the id and empties the directory, so identical bytes cost no `docker exec`
while a restarted proxy is always republished to.

A compatible proxy replacement stops the predecessor when the candidate is
created — the first phase of the rebind transaction, several phases before
`control-selected` — so the unserved window for surviving sessions begins there
and ends when each session's next heartbeat adopts the new durable selection and
writes into the candidate. There is no pre-selected candidate and no poke: the
accepted cost is up to one heartbeat cadence plus adoption per session, never a
teardown. A proxy restart of any kind clears the session directory and begins
deny-all; the host republishes eligibility and the heartbeats refill the files.
When no surviving record can still hold authority, `runfree up` proves
`session_ipv4` empty from the live kernel set rather than assuming the loop ran.

An explicit rebuild is a destructive recovery boundary. Compose cannot see
direct session containers, so rebuild drains them under the project lifecycle
lock before it recreates the proxy. It first validates the pending control-plane
rebind journal — the only lifecycle journal that still exists — then identifies
only ingress forwarders that carry this project's exact minted labels and whose
inspected immutable image ID equals Docker's resolved ID for the pinned ingress
image. It identifies these forwarders before the unclaimed-container gate, but
removes them only after every refusal gate passes. Any other residue —
including containers from retired sidecar generations — is never recognized: it
hits the unclaimed-container refusal and fails closed, naming the manual remedy.
It then marks durable records revoking, deletes this project's session files
from the still-running proxy, stops every named proxy consumer, removes only
exact registry-bound or validated-journal-bound session containers, and
completes Compose teardown. It clears the effective live-container selection,
then removes the control-plane rebind journal, then removes exact revoking
lifecycle records only after those effects succeed. Each file publication and
removal is followed by a parent-directory fsync. A failure retains
non-authorizing evidence for retry; unreadable or unclaimed evidence requires
the separate `destroy --force` authority.

Utility teardown applies the same ownership proof outside rebuild. The proof
is four facts: the project label matches, the role label matches the expected
utility role, the inspected immutable image ID equals Docker's resolved ID for
the pinned ingress image, and removal addresses the inspected full container
ID. Names discover candidates but authorize nothing; runtime shape is creation
authority, not deletion authority. A candidate missing any fact — including
partial or conflicting labels — is left untouched and causes refusal. The
managed ingress host bridge uses a versioned name and is inspected for its
exact full network ID, minted project and role labels, and exact endpoint IDs
before Runfree removes it; Runfree still inspects a new bridge for its
complete local-bridge shape before it starts a listener, refusing and removing
an unsupported shape by the full ID returned by Docker, and validates all
current bridge endpoints before a removal effect. An invalid current endpoint
causes refusal before any removal. The accepted residual is a same-host writer
that mints Runfree's labels onto a container running the pinned image;
realistic writers of those labels are Runfree itself and the operator, and the
Docker daemon is trusted. Containers or networks from retired sidecar generations carry no
recognition and no deletion authority: they are refused as unclaimed residue,
and the remedy is the explicit `destroy --force` sweep.

Destroy applies the same rule to the same evidence. Plain destroy validates the
pending rebind journal and utility ownership before its live-session and
unclaimed-container refusal gates, and deletes this project's session files from
the proxy while it can still answer — before the record that reserves each
address is touched. Utility removal remains deferred until all refusals pass.
`destroy --force` can remove an unreadable exact journal path after the proxy,
sessions, and Compose runtime are gone. Forced destroy bypasses strict utility
ownership cleanup so malformed or unclaimed utility residue reaches the explicit
project-label stop and removal sweep. Normal destroy continues to require the
four-fact utility ownership proof. After the forced sweep, Runfree removes only
an empty ingress bridge whose minted ownership labels and exact full network ID
prove it is ours. It retains a foreign-labeled or still-attached bridge. It
validates the journal parent tree before any teardown effect, then validates it
again at removal. Both paths clear the effective live-container selection first,
then the journal, then exact lifecycle records. Validated journal-held container
IDs participate in ordinary destroy's pre-effect ownership gate and exact
removal set. A record carrying a terminal host status stamp is an interrupted
teardown rather than a session: plain destroy's own record scan excludes it,
while the independent session-listing gate still protects alive or unknown
owners. Positive owner-death evidence permits normal cleanup. For an uncertain
owner, explicit `destroy --force` can reclaim the interrupted teardown. Ownership proof never becomes permission for non-forced
live teardown.

Admission authority still arrives through proof rather than through the previous
step having been reached:

- A proof exists only if `validateSessionContainerInspect` minted it from an
  exact `docker container inspect`. It is held by identity in a private
  registry, so a caller cannot construct or copy one, and it carries the
  lifecycle record it describes and the moment it was taken.
- Every consumer re-checks that the proof names this project, session
  incarnation, principal, container, image, control plane and session-agent
  generation digests, source IP, and internal network. A proof from another session cannot be substituted, and a
  proof too old to describe the container it names cannot authorize an effect.
- The container's shape is held to the create plan exactly, by one post-start
  inspection that is the whole admission's only shape proof: image, entrypoint
  and argv, user, dropped capabilities, `no-new-privileges`, restart policy,
  every mount and its read-only and no-copy flags, the environment, the labels,
  and attachment to exactly one internal network at exactly the allocated
  address. There is no separate stopped-container inspection or pre-start
  network re-read to keep consistent with it.
- The session file's renewal anchor is a projection of that same inspection —
  the three mutable running-identity fields (process id, start time, network
  endpoint) every later heartbeat re-proves — so holding it costs no extra
  inspection and cannot describe a different moment.

The container starts before the proxy learns its address. Between start and the
session file nothing anywhere names the session: its address is in no kernel
session set, and the request proxy refuses it as an unknown peer. Docker
reserves the static address at start and refuses a duplicate there, and the
single post-start inspection then holds the container to exactly one internal
network at exactly the allocated address, so claiming a session's address would
require Docker daemon access, which is outside the threat model, and the session
container has no Docker socket.

Writing the file is the one step that widens what the container may do: before
it the session holds no traffic authority, and within one consumer loop after it
the session may use the ordinary proxy path. Renewal never changes the bound
container identity, so the proxy preserves established sockets and session
grants across a rewrite that only advances the lease. It still destroys them on
expiry, revocation, removal, or any change to that identity. The host and the
proxy share one five-minute maximum lease, so proxy monotonic enforcement cannot
expire an otherwise eligible file early.

`runfree stop` and `runfree runtime reload-policy` still require `--force` while
live or unprovable owners remain, while a control-plane rebind journal is
pending, or while any record carries a terminal host status stamp — a record
mid-teardown is exactly the transition those commands must not interrupt.
Startup builds and credential-source resolution happen before the lifecycle
lock. Held startup/reload subprocess work has a 90-second budget, and lock
acquisition refuses after 120 seconds. Prepared credential values expire 120
seconds after preparation and again 120 seconds after admission; an expired or
changed preparation refuses before any credential write. File heartbeats run
independently of that lock.

Destructive runtime confirmation reads durable per-session lifecycle records,
not short-lived host display metadata. Startup, destroy, and control quiesce
retry bounded lifecycle-lock contention, so a heartbeat's brief adoption
critical section cannot become a spurious command failure.

What this does **not** prove is anything observed from inside the container. An
earlier design ran a trusted probe binary in the session container to attest
that PID 1 was the unprivileged agent with no capabilities, and that a denied
host was actually denied from within. That probe has been removed, so the
container's shape is now established entirely by host-side Docker inspection.
Inspection proves what the daemon was asked to create and reports as running;
it does not observe the process from the inside.

The proof also reads Docker's inspection through one normalization layer,
because a daemon spells the same container differently across releases: fields
carrying their zero value may be absent, capabilities come back in the kernel's
`CAP_` form, and Docker Desktop names a relayed bind source under `/host_mnt`.
Absence resolves to the zero value the plan asked for, and re-spellings are
canonicalized, so the comparison stays exact without a daemon upgrade reading
as a violated contract.

### Runtime Generation Integrity

Runfree does not use the release version or one monolithic digest as live proof. The fixed control plane and session-agent template have separate v2 generations. A session materialization stores the exact canonical template and binds its byte hash. Existing session records bind their immutable materialization and image ID.

Before credential resolution, startup verifies the selected control plane, desired session materialization, canonical template, exact proxy identity, and live validation proof. It then mints an opaque in-memory `PreparedRuntime`. Public launch paths can consume this authority once. They cannot reconstruct it from mutable context or durable files. Selection drift, proxy replacement, proof drift, or reuse fails before session creation. One retry may repeat full preparation after a stale-state error.

A compatible proxy replacement begins with a candidate that holds no session files at all, and the predecessor is gone from the moment the candidate is created. Runfree re-inspects every retained session, rewrites each host lifecycle record with the candidate's control plane generation digest, re-proves those sessions, and publishes the project's session eligibility into the candidate — all before the durable selection flips to it, because a proxy holding no eligibility serves nothing and the first heartbeat after the flip must find one that already knows this project's admission bindings. Nothing is republished on the sessions' behalf and nothing is acknowledged: each surviving session's own next heartbeat writes its file into the candidate. Failed participant observations preserve live or unknown owners. Only owner intent or proved death permits ordinary revocation and teardown. An incompatible epoch or topology remains blocked while sessions are live.

This active-session restart path is enabled: a compatible proxy replacement proceeds while sessions are active through the durable rebind transaction above, and only an incompatible admission epoch or control-plane topology change waits for sessions to drain. Startup resumes an already-started rebind transaction rather than abandoning it, because durable partial authority left behind would wedge recovery.

A surviving session's client process adopts that rebind itself. Before each beat it compares its held proxy container ID and control plane generation digest with the durable selection; while they match it takes no lifecycle lock at all. When they differ it takes the lock once and adopts exactly one completed compatible rebind of its own session: same project, epoch, control topology, and agent-internal network, plus a registry record that differs from the held one only in the rebind writer's fields. The create plan is rebuilt from durable artifacts against the candidate, and the sealed foreground and liveness anchors advance through the same rebind-shape assert. Any other identity change refuses adoption before any durable write. A rebind still in flight, a contended lifecycle lock, and an unschedulable adoption are all conditions the session outlives: the beat still writes into the proxy it holds, which fails closed — if the replacement really happened, that write fails and the file lapses on its own lease — and the agent process is never ended over any of them. The accepted cost of a compatible replacement is therefore up to one heartbeat cadence plus adoption of unserved time per surviving session; there is no poke and no pre-selected candidate. Exact owner exit can remove its own record and container during replacement without publishing anything through the old proxy ([adoption](../packages/cli/src/runtime/session-admission-rebind-adoption.ts), [driver](../packages/cli/src/runtime/session-admission-driver.ts)).

The rebind journal is the one lifecycle journal that survives. It records candidate attempts, exact batch inputs, fixed publication
timestamps, and a shared 120-second/two-creation allowance. An ordinary retry
cannot replenish it. After repair, `runfree runtime recover --retry` explicitly
authorizes another allowance. Current candidate proof and credential
reconciliation remain required. Valid legacy journals migrate atomically and
retain their original bytes; malformed or contradictory state refuses mutation
([rebind journal](../packages/cli/src/runtime/control-plane-rebind.ts)).

A failed observation does not authorize Compose teardown. A proved proxy boundary
violation permits exact proxy containment under the lifecycle fence. Containment
is identity- and ownership-exact: it refuses a container that carries the
expected 64-hex id but not this project's id, container-role, and Compose
project/service labels, so a foreign container reusing an expected id is never
stopped. Failed containment reports unconfirmed safety and stops recovery. Candidate creation
checks the retained network, CA certificate/key identity, and exact project OAuth
volume before exposing their mounts to the approved proxy image. Existing sockets
and in-flight OAuth exchanges can end; recovery does not replay them
([containment](../packages/cli/src/runtime/proxy-containment.ts),
[creation inventory](../packages/cli/src/runtime/control-plane-rebind-docker.ts),
[trust receipt](../packages/cli/src/runtime/rebind-trust-receipt.ts)).

Garbage collection retains every exact reference from desired and effective selections, lifecycle records, direct containers, and a pending control-plane rebind transaction. The proxy's own session files are not a retention source — a listing entry names no image to retain — so they gate the whole pass instead: every served file must map to a lifecycle record this scan already counted, or nothing is pruned. It removes only exact inspected image IDs and materialization paths. It does not use force, broad tags, or globs. Unknown managed-looking containers, a session file no lifecycle record claims, a session-file listing the host could not read, failed Docker inspection, unsafe links, and malformed retained state stop cleanup.

A project whose durable control-plane materialization predates this admission
contract cannot be read at all: its manifest lacks the required session
admission source field, so `runfree up` refuses with an invalid-component-
evidence error and names `runfree rebuild`, which materializes and selects the
control plane again. A pre-cutover rebind journal stopped at one of the two
retired consumer-acknowledgement phases no longer parses either, so it reads as
unreadable evidence and `runfree destroy --force` is its named remedy.

## Network Enforcement

Desired network policy is stored at `.runfree/network-policy.json`. The proxy
does not mount or read that file. It reads a strict `active.json` under a narrow
read-only XDG effective-control mount, then loads paired network and OAuth
artifacts from the named immutable generation.

Key properties:

- hosts are exact normalized hostnames;
- wildcard hosts are not supported;
- optional request rules can restrict HTTP methods and path prefixes;
- Git pushes can be denied or classified as writes;
- declared GraphQL endpoints classify queries as reads and mutations as writes;
- write-class requests can be allowed, denied, or held for approval;
- audit mode is time-boxed and explicit.

A request must pass the proxy policy before the proxy connects upstream. Denied CONNECT requests get in-tunnel feedback naming the blocked host where possible, and structured denial events feed `runfree doctor`.

One transport detail is hard-coded rather than policy: for a small fixed set of first-party AI hosts (`IDENTITY_ACCEPT_ENCODING_HOSTS` in the proxy), streaming-shaped requests are forwarded with identity `Accept-Encoding` so intercepted event streams stay parseable. This affects response compression only, never authorization.

`runfree up --audit-network[=<duration>]` is intentionally loud: it permits non-allowlisted HTTPS hosts for a bounded discovery window, logs what was observed, and never edits policy. Use `runfree audit report` to review suggestions, then `runfree audit off`.

One audit-mode residual: audited (non-allowlisted) WSS upgrades cannot have configured credential headers stripped, because the WebSocket passthrough mirrors the client's raw upgrade headers and exposes no header transform. A configured credential header the agent sends on an audited WSS upgrade is forwarded as-is. Enforce-mode WSS to allowlisted hosts is unaffected.

A second audit-mode residual: in enforce mode the kernel audit sets must be empty, and the only component that verifies it is the proxy itself. Its firewall supervisor refuses to report a verified ruleset while `audit_ipv4` or `audit_draining_ipv4` holds elements. The host-side nftables proof validates set shape — name, type, and the absence of interval or wildcard flags — and never set membership, so this invariant rests on a check the proxy performs on its own firewall rather than on independent host verification. A replacement proxy is unaffected either way: its audit marker and spool are per-container tmpfs, so a new container starts in enforce mode with empty sets. The proxy is the trust boundary and a trusted component, so this is a defense-in-depth gap, not a path an agent can reach ([firewall verification](../packages/proxy/src/firewall/route.ts), [host nftables proof](../packages/cli/src/proxy-nftables-proof.ts)).

### Policy Visibility And Convergence

Desired policy is reviewable input, not an integrity boundary. Because the
project root is writable, the agent can edit `.runfree/network-policy.json`.
Such edits are inert: they change nothing until a host-side transaction
captures, verifies, and approves exact bytes. Runfree captures strict bounded
candidates and compares their exact subject digests with host-owned approvals.
Unknown fields, duplicate keys, oversize input, unsafe paths, incomplete
service semantics, and authority expansion without exact approval fail closed.

#### What The Checkout Binding Is And Is Not

Each approvals record is scoped to a checkout by three stored observations: the
project scope, the config generation, and a checkout binding of the root's
resolved path and inode. The volume's device number is recorded for diagnosis
and **never compared**, so a reboot that renumbers the volume preserves every
approval — no prompt, no rebuild, and no new effective policy generation.

This binding is a scope key, not an authorization. The approved subjects are
content digests of the policy bytes, the isolation fields, and the image build
inputs, so any change to what was approved already forces a review on its own.
Path scope is separately established by the record's location under the project
hash. What the inode adds is exactly one thing: a consent hint for a directory
replaced at the same path. Three limits bound it, and all three are accepted
rather than worked around:

- It does not cover per-project Claude, Codex, and Pi state. Those mounts are
  keyed on the path alone, so a replacement checkout at the same path inherits
  them, including any native project-scoped login state.
- It sees the container, not the contents. An in-place branch checkout, a `git
  pull`, or an agent edit keeps the same root inode.
- **It is void when the project root is itself a filesystem mount root.** A new
  filesystem gives its root directory a deterministic inode, and path resolution
  passes through neither bind mounts nor firmlinks — so a dedicated source
  volume, a CI workspace volume at a fixed path, a loopback image, or a
  bind-mounted checkout presents the same observation for every volume mounted
  there. For those layouts the binding is path alone.

A different volume mounted at the same resolved path can present the same inode,
and a deleted inode can be reused; those cases retain approvals, and Runfree
does not claim to distinguish them. Inode persistence is a filesystem property,
not a guarantee: where an inode is unstable the cost is one review, never a
wedge. A binding that does not hold renders the ordinary policy review before
any build, credential resolution, or attach, and the superseded record is copied
aside rather than replaced in place.

The typed desired-policy mutations (`host add`/`remove`/`rules`, service and
credential mutations) run while per-session agents are live, without pausing
or restarting any container. They are also reached indirectly — by the `init`
wizard and by the operational-service review that precedes a built-in launch —
so this set, not just operator-typed commands, is what may mutate desired
policy beside a live session. Their agent-drift guarantee is the transaction
chain, proven under the project lifecycle lock: capture the candidate, verify
it against the approved base, atomically replace the file, re-read and require
an exact match to the planned candidate, then approve. **Invariant: a live
desired-policy mutation MUST approve the exact in-memory candidate it re-read
and verified under the lock — never a fresh read of the worktree file.**
Approval is content-addressed (the clean bytes are published into a
digest-keyed snapshot store) and publication consumes the snapshot, so an
agent edit in any window is refused or left as inert unapproved drift that the
next transaction rejects. Review checklist: any new live-mutation caller of
`withQuiescedProject` with `allowLiveSessions` must carry this same
re-read exact-match chain; the four-window guard test
(`packages/cli/src/control/desired-mutation-drift-guard.test.ts`) is the
proof shape to extend.

Every other control transaction keeps the live-session refusal: lifecycle
rebuild/destroy (`runfree init` migration, image rebuild) and the startup
capture defer while a per-session agent is active. A concurrent launch reuses
the verified selected effective generation without reading desired project
input or publishing new authority.

Project and checkout-local desired layers compile into one effective policy.
Generation publication also accepts a host-only effective-network-policy
substitution (the `effectiveNetworkPolicy` input to
`publishEffectivePolicyGeneration`), used by trusted host flows such as MCP
projection; it is host code, never reachable from project input. The request
proxy and nftables supervisor consume that same selected generation
independently. Activation waits for both level-triggered status files, requires
the firewall to report a verified ruleset, and only then permits
receipt-gated credential convergence. Invalid or incomplete generations retain
the previous effective authority. `--no-reload` is an activation barrier: it
changes desired input but deliberately leaves the selected effective generation
unchanged until a later approved activation.

The generated agent environment also belongs to the selected immutable XDG
generation. Project `.runfree/config/agent.env` is ignored, and the agent has no
mount or path to host approval/effective state.

## Credential Handling

Runfree separates credential policy from credential values.

- Desired credential policy in `.runfree/network-policy.json` says which credential may be injected into which host/header/path; only its approved compiled mapping reaches the effective generation. The persisted field remains named `tokens` for compatibility.
- Credential source config is host-owned and can point at an env var, 1Password ref, host command, stdin value, JWT source, or service OAuth seed material.
- `runfree credential sync` resolves sources on the host and streams values into proxy-side state.
- The agent receives placeholders or OAuth handles, not real token values.
- The proxy strips conflicting inbound credential headers and injects configured credentials only after policy allows the request.

Do not put real service tokens in agent environment variables, project files, `.runfree/runfree.json`, or `.runfree/network-policy.json`.

Built-in Claude and Codex launches automatically ensure credentialless exact-host operational services. Those services do not install proxy credential mappings or read credential sources, but any process in the agent container can use their allowed hosts. Existing `ask` or `deny` host rules are preserved instead of silently widened.

## Write Approval

Runfree classifies outbound requests as read or write. Write action can be:

- `allow`: write proceeds after other policy checks;
- `ask`: write is held for a host-side decision;
- `deny`: write is blocked.

The built-in default is `ask` unless a host or project default says otherwise. AI provider endpoints in the initial template use explicit `writeAction: "allow"` because normal agent operation requires POST requests to model APIs.

Useful commands:

```bash
runfree approvals --watch
runfree approvals --clear-deny
runfree approve <id>
runfree approve <id> --deny
runfree host rules <host> --write allow|ask|deny
```

Approvals are host-side decisions. Wider approval scopes are explicit flags on `runfree approve`.

Approval grants carry an explicit subject and lifetime:

- The subject is the authenticated session. With source-IP session identity in effect, a `session`-scoped grant applies only to the session that requested it — keyed by that session's source IP, not shared across the runtime — and it is dropped when that session's authority is revoked or the session ends. CLI prompts and `runfree status` name the session rather than the whole runtime.
- Positive grants are bounded: a `session` grant without an explicit TTL lasts until that session's authority ends (revocation or session exit — the proxy drops its grants with its sockets), `ttl` for the requested duration clamped to eight hours, and `request` for five minutes. A `request` grant is not literally "the one held request": it readmits, once, any write matching the same bounded `(host, method, path, category)` shape, which is what lets a denied-then-approved WebSocket reconnect on its own schedule. All three are listed in `runfree status` with their remaining time. A lifetime is a duration, and measuring one needs a clock that neither jumps nor freezes; no single clock available here has both properties. The wall clock can be stepped backward (an NTP correction after sleep), which would re-base a deadline and hand a grant a fresh lifetime. The monotonic clock does not advance while the host is suspended, so closing a laptop would preserve a grant across the sleep. Each grant therefore records both origins and expires when *either* bound is exhausted, re-checked at use time. Extending a grant would require corrupting both clocks in the same direction at once, which no single event does. A forward wall-clock jump expires a grant early; that is deliberate, and costs a re-prompt rather than granting anything.
- Negative authority does not expire on its own, because denying is fail-closed. It is always listed in `runfree status`, and it is revoked through the same root-owned channel that created it: `runfree approvals --clear-deny` writes a root-minted, schema-validated control record naming the proxy's current deny nonce. The proxy rotates that nonce whenever negative authority changes, so a stale or replayed clear cannot revoke a deny the operator never saw. The agent container has no access to that channel.
- Remembered denials and positive grants reset on proxy-process restart. Under `ask` policy, later writes ask again. Restart/replacement reports that reset and the loss of pending requests and unexported audit observations. Each server process creates a fresh approval epoch. Decisions, control messages, and watcher heartbeats must name that epoch; decisions must also name an exact currently pending hold. Old requests are never reconstructed ([approval manager](../packages/proxy/src/approvals.ts), [root startup](../packages/proxy/src/entrypoint.ts), [host writer](../packages/cli/src/runtime/approvals.ts)).
- Clearing returns to *asking*, never to a standing allow. A deny grant shadows any broader allow underneath it, so a clear drops standing grants of both signs and itemizes what it revokes first. For the same reason, a session-wide deny drops that session's positive grants but preserves narrower denies.
- Activating an approved policy change never revokes negative authority. A new
  effective generation drops positive grants whose host rules changed, but
  leaves denies of every scope in force until `runfree
  approvals --clear-deny`. Editing desired policy alone changes no grants or
  runtime authority. Policy activation is a different channel from an approval
  decision, and making it a silent second revocation path is the same
  "authority changes where nobody can see it" problem this design exists to
  close. Where a host's posture widens to `allow` the deny is already dormant,
  because the write short-circuits before any grant is consulted, so keeping it
  costs nothing and correctly restores the operator's decision if that host
  returns to `ask`.

## MCP Security

MCP servers can expose powerful tools. Runfree treats project MCP descriptors as project-controlled input.

- Host/user/local MCP entries can be listed and explained.
- Project entries from `.mcp.json` and `.codex/config.toml` are imported only after `runfree mcp approve`.
- Runfree-managed Claude launches use a dedicated read-only approved config with strict MCP mode. This prevents passive project descriptors from activating at startup; it does not prevent untrusted code already running in the agent from invoking another binary or config.
- Static headers require a host-owned credential source; real static secrets are not copied into agent config.
- OAuth login runs through a validated runtime using `runfree mcp auth` or `runfree mcp approve --login`.
- MCP tool calls can be governed by operation policy and approve-on-write rules.

Use:

```bash
runfree mcp list
runfree mcp explain claude <server>
runfree mcp approve claude <server> --from-source <source>
runfree mcp rules claude <server> --tool <tool> --write ask
```

## Host Filesystem Safety

Project-controlled paths such as `.runfree/` are treated carefully by host-side
writers. Safe filesystem helpers reject symlinks, hard links, and special files
before replacing policy/config files. The agent may edit `.runfree` through the
ordinary project mount, but no trusted runtime consumer reads authority or
generated environment from it.

Runfree does not mount host-wide secrets or home configuration into the agent. Intended exceptions are per-project generated agent state, sanitized per-agent config, generated Git identity, dependency overlay volumes, and explicitly imported runtime assets. Claude, Codex, and Pi state mounts are writable and may contain their native project-scoped login or subscription state; compromised code in the agent must be assumed able to read or alter that state. This is separate from proxy-managed service credentials, which remain proxy-side.

Trusted host updates to the writable Codex state use a fixed-file, mount-root
operation. The operation rejects symbolic links, hard links, special files,
oversized files, and changes detected during the update. It creates a new file
with no-follow and exclusive-open flags, then replaces `config.toml` by rename.
An unsafe entry is left in place for narrow manual recovery.

Host-triggered clipboard imports are copied into per-project XDG state and exposed through the exact read-only `/runfree/inbox` mount. The mount lives outside `/workspace`, so it does not create project files or appear in project Git status. The agent-visible path and environment variable are routing conveniences; the Docker read-only mount and startup security-contract probe enforce the write boundary.

Interrupted-session recovery treats Claude registry files as untrusted agent
state. It reads only bounded regular single-link files from fixed directories,
uses no-follow open and inode checks, validates conversation identifiers before
argv construction, and sanitizes display strings. Offline listing defaults to
the current project; cross-project enumeration requires explicit `--all`.
Repeatable `--agent` values only filter the resulting inventory; they grant no
resume authority. Listing never calls Docker or mutates state. Resume requires fresh project and liveness validation,
an exclusive host-owned claim, and exact container-session or PID/start-time
proof before runtime startup or token sync. Failed recovery preserves evidence;
successful recovery deletes only the fingerprinted primary evidence and never
touches conversation transcripts.

## Pre-Sandbox Project Image Builds

A configured project agent image is built before the Runfree agent/proxy boundary has been validated, using the trusted host Docker daemon and its normal build networking. The build can therefore read its selected context and communicate without Runfree proxy enforcement.

Runfree automatically stages only narrow `.runfree/image` contexts after rejecting symlinks, hard links, special files, and context escapes. Wider project contexts remain live host inputs and require explicit project-scoped approval through `runfree image approve-context`. Review project Dockerfiles and wide-context approvals as host-side security decisions; later sandbox validation cannot constrain effects that occurred during the build.

The narrow-context approval subject covers only project-controlled inputs: the exact staged manifest (file bytes and modes), the Dockerfile, and the normalized build config. Embedded runtime identity (base image, injected version arguments) is deliberately outside the subject; it moves only the image input digest, so a runfree upgrade rebuilds the project image without re-prompting, while any change to the staged bytes still invalidates the approval. Builds consume only a stored snapshot that re-verifies byte-for-byte against the approved manifest. A same-digest snapshot that fails verification is never built; the launch warns, re-prompts over freshly staged bytes, and the new approval replaces the corrupt snapshot. Older runfree releases cannot read post-split approval records; downgrading across the split requires re-approving (or deleting) the project's control approval state.

## Release And Platform Status

Public release artifacts for 0.5.0 are `darwin-arm64` only, and the supported host is Apple Silicon macOS with Docker Desktop. Intel macOS, Linux, and OrbStack are outside the supported beta: they may build and run, and building is not the same as supporting. A target is claimed only with recorded acceptance evidence on it.

The release pipeline gates on unit tests only. It publishes the signed archive after checking it against the hash recorded by the signing job; it does not run the packaged CLI end-to-end scenarios against that archive.

`make test-runtime` is still not a GitHub-hosted release gate. The live runtime security suite needs a Docker host and is run manually; which tranches ran for a given release candidate, on which backend and OS versions, belongs in that candidate's acceptance dossier. A release whose dossier does not record it has not proved it.

## Verification Checklist For Security-Sensitive Changes

Run at least:

```bash
pnpm check
pnpm typecheck
pnpm test
```

For Docker, proxy, firewall, mount, credential, CA, token, MCP runtime, or sandbox changes, also run:

```bash
make test-runtime
# or
make test-all
```

Security-sensitive tests should prove rejection before the sensitive side effect, such as before upstream connection, credential injection, policy mutation, or filesystem write.

## Residual Risk

Runfree reduces the default blast radius for local coding agents, but allowed hosts and approved writes still matter. If you allow a broad multi-tenant host, authorize a credential-bearing service, or approve a write, the upstream service may still perform the requested action. Review policy changes and approval prompts as security decisions.
