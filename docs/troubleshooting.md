# Troubleshooting

Runfree refuses rather than guesses. Most of what looks like a failure is a
refusal with a named remedy, so read the last line of the message first: it says
what did not happen, and usually names the command that fixes it.

## A request was blocked

The agent sees a 403 naming the host, and the session prints a blocked-host
summary on exit.

```bash
runfree doctor
```

`doctor` reads structured proxy denial events, groups them by host with request
counts, and prints the exact `runfree host add` or `runfree host rules` command
that would allow each one. A denial caused by a request rule rather than the
allowlist gets a method-widening suggestion instead.

To watch as it happens:

```bash
runfree logs proxy --verbose
```

Before allowing a host, decide whether you want the agent to reach it. A blocked
request is the boundary working.

## Policy edits had no effect

Editing `.runfree/network-policy.json` changes *desired* policy. Nothing changes
at runtime until a host-owned approval selects a compiled effective policy generation.

```bash
runfree policy status     # desired, approved, and selected identities
runfree policy diff       # what drifted from the approval
runfree policy review     # canonical desired policy and its authority
runfree policy approve    # approve exactly one desired subject
runfree policy use-approved
```

That separation is deliberate: the agent can write the desired file, and writing
it must not grant network authority. See
[`security.md`](security.md#trust-boundary).

## A policy change is saved but not applied (proxy from another build)

A policy command (`host`, `host-service`, `credential`, `service`, `mcp`, or
`policy use-approved`) publishes an effective policy generation only to a
proxy built from the same release as the CLI. After an upgrade or downgrade,
the running proxy can be from another build (a missing image-input label
counts as another build). What happens then:

| Situation | What happens | Remedy |
| --- | --- | --- |
| The runtime can be replaced compatibly | The command warns that running sessions lose network access for up to one heartbeat (30 s) plus adoption, replaces the proxy as `runfree up` does on the effective policy generation already selected, and publishes only after the new proxy's label matches. It refuses before any Docker work if the runtime isolation settings or desired policy differ from the approved controls. | None if it succeeds. If the replacement fails, the change is saved but not applied and the selection is unchanged; fix the reported cause and rerun the command. |
| Active sessions use an incompatible admission epoch or control-plane topology | The change is saved and reported as not applied. | Wait for the sessions to end, then run `runfree policy use-approved`; or run `runfree rebuild` now. |
| A session launch beside live sessions | The launch never replaces the proxy; it reports the change as waiting. | Run `runfree up`, then `runfree policy use-approved`. |
| A proxy of another build appears while the change is being published | The previous selection is restored and the command fails. | Retry the command. |

See [Older Readers](security.md#older-readers) for why the check exists.

## A host cannot be removed

`runfree host remove` refuses a host something still references. Usually a
service owns it.

```bash
runfree host explain <host>    # who holds this host and why
runfree service explain <id>
runfree service disable <id>   # removes the service's hosts unless still required
```

`service disable` leaves a host you added yourself with `runfree host add`,
because that is a separate authority. Remove that one afterwards.

## The runtime will not start

```bash
runfree status       # containers and audit state for this project
runfree resources    # every Runfree Docker resource for this project
```

Common cases:

- **An unclaimed container.** A container with this project's label that
  Runfree does not recognize hits the unclaimed-container refusal. `runfree rebuild` is the remedy;
  `runfree destroy` is the heavier one.
- **A live session blocks the operation.** `runfree stop` and
  `runfree runtime reload-policy` refuse while sessions are live. Close the
  sessions, or pass `--force` once you know what it ends.
- **Docker is not reachable.** Runfree needs Docker Desktop running with Docker
  Compose. Check `docker version` first.
- **A warm launch asks for a retry.** `the session state changed during a warm
  launch; retry the command to validate the runtime fully` (or `a lifecycle
  record appeared during a warm launch; ...`) means another session changed
  while this launch checked it. Run the same command again; the retry
  validates the runtime fully.
- **The launch exits 111.** The session entry did not see the proxy activate
  the session in time, so it stopped and teardown removed it. Run the command
  again; if it repeats, check `runfree status` and `runfree logs proxy`.
- **Docker died under a live session.** The next start finishes the
  interrupted teardown only when Docker can prove it safe; otherwise it
  refuses. Retry once Docker answers or the owning `runfree` process has
  exited. Use `runfree destroy --force` when the owner cannot be proved dead,
  or `runfree rebuild` when the session container is still running.
- **`runfree stop` kept the control-plane selection.** If stop warns `could not
  prove the stopped runtime's proxy and networks are gone, so its
  control-plane selection was kept` and the next start refuses, run
  `runfree destroy`.

## Leftover helpers could not be confirmed removed

```text
runfree error: ephemeral helpers could not be confirmed removed (...); run `runfree up` to retry, or `runfree destroy --force` to reset the project
```

Startup runs short-lived helper containers (deny probes, CA bundle render,
dependency preparation). If an earlier run died while one was active, the next
`up`, launch, or `runtime reload-policy --force` removes them before it admits
any session. This refusal means that cleanup could not prove they are gone:
Docker was slow or a listing failed. Nothing was started.

```bash
runfree up                 # retry; usually enough once Docker is responsive
runfree destroy --force    # reset the project runtime if it keeps failing
```

`destroy --force` ends live sessions. See
[Ephemeral Helpers](architecture.md#ephemeral-helpers) for the mechanism.

## No free helper address

```text
runfree error: ... denial probe did not run: no free ephemeral-helper address in 172.x.y.13-.19 on agent_internal; close port forwards with `runfree forward stop`, remove any other container holding those addresses, or run `runfree destroy --force`
```

The startup deny-probe helper takes an address from a reserved block,
`.13`–`.19` on `agent_internal`, outside the session pool. Port forwards and
other containers attached to that network can fill the block. Startup refuses
rather than let the helper use a session address.

```bash
runfree forward status
runfree forward stop
runfree resources          # other containers on this project's networks
runfree up
```

If the message says a pinned address `is already in use` instead, another
container holds that one address. Retry `runfree up`; if a container Runfree
does not own holds it, remove that container or run `runfree destroy --force`.

## Startup is slow

`RUNFREE_TIMINGS=1` prints one `timing:` line per lifecycle phase to stderr,
plus a `startup-ops` count and total time for each kind of subprocess:

```bash
RUNFREE_TIMINGS=1 runfree up 2>&1 | grep 'timing:'
```

The categories name the command and Docker subcommand only, never
arguments, ids, or output, so the lines are safe to paste into an issue.

The first start after an upgrade that changes the agent image inputs
rebuilds the image and is expected to be slow.

## A host service is refused or unreachable

`runfree host-service add` checks the port before it writes any policy:

| Refusal | Remedy |
| --- | --- |
| `port <port> is refused: ...` | The port is Docker's, Runfree's own, or in Runfree's MCP callback block. Run the service on another port. |
| `no process listens on 127.0.0.1:<port>` | Start the service on the host first. |
| `no visible listener on 127.0.0.1:<port> or *:<port> (found: ...)` | The service listens only on another address, such as `[::1]`. Bind it to `127.0.0.1`. |
| `127.0.0.1:<port> is owned by Docker Desktop (a published container port)` | A container publishes the port. A container is not a host service; stop publishing the port or use another one. |

After approval, `runfree status` warns when the service drifts:
`host service <name> (127.0.0.1:<port>): no listener`, `owned by Docker
Desktop`, or `listener changed to <command>`. Restart the service, or remove
and add it again to approve the new process.

A service added while a session runs appears only in the next session. If
`runfree status` shows `host-service gateway: unavailable (...)`, every host
service stays refused until `runfree rebuild`, which ends every session. If
another project's `runfree forward` or `runfree vnc` refuses a port because the
host-service registry is corrupt, run:

```bash
runfree host-service list --repair
```

If the repair names a project whose state cannot be read, repair or destroy
that project, or remove its state directory when the checkout is gone, then
run the repair again.

`runfree doctor` reports host-service denials apart from host denials:
`host-service-not-configured` suggests `runfree host-service add` when the
name and port are valid, and `host-service-unavailable` or
`host-service-capacity` point to `runfree status`.

See [Host Services](cli.md#host-services).

## Host Git is too old or missing

Runfree needs host Git 2.48 or newer for full worktree support (see
[Git worktrees](cli.md#git-worktrees)). Upgrading Git fixes every message
below; on Ubuntu, `sudo add-apt-repository ppa:git-core/ppa && sudo apt install git`.

| Message | What to do |
| --- | --- |
| `host Git <version> is older than 2.48: Git worktrees created inside the sandbox will make this repository unreadable to host Git; ...` | A warning; the launch continues. Do not create worktrees inside the sandbox until you upgrade. |
| `host Git <version> is older than 2.48 and cannot read this repository, which uses relative worktree links; ...` | A warning; the repository already uses relative links, so host Git cannot read it now. Upgrade. |
| `host Git not found: Git worktrees created inside the sandbox will make this repository unreadable to host Git older than 2.48; ...` | A warning for a non-Git project. Install Git 2.48 or newer. |
| `host Git not found: Runfree needs Git to check this repository's worktree layout; ...` | A refusal in a Git repository, before any state is written. Install Git. |
| `this Git worktree layout requires host Git >= 2.48 (found <version>); remove or move the nested worktree ...` | Remove or move the nested worktree (`git worktree remove <path>`), or upgrade. |
| `this Git worktree layout requires host Git >= 2.48 (found <version>); run runfree from the main checkout ...` | Run Runfree from the main checkout, or upgrade. |
| `repairing worktree links requires host Git >= 2.48 (found <version>); upgrade Git` | Upgrade, then run `runfree git repair-worktree-links` again. |

The same refusals apply to commands that write checkout-local policy, such as
`runfree init`, and to a running runtime that finds its Git layout changed
(a reused launch, a proxy restart, or dependency overlay planning). On Git
2.48+ an unsupported layout instead names the repair command to run on the
host from the main checkout.

## A write is being held

With approve-on-write active, an outbound write waits for a host-side decision.
Run `runfree approvals --watch` to stay attached as the approver, and
`runfree approvals --clear-deny` to bring back prompts you told Runfree to stop.
The rest of the flow is in [Approve-On-Write](cli.md#approve-on-write).

## An interrupted session will not resume

`runfree resume` refuses before it starts anything, so a refusal never leaves
a half-started session.

| Message | Cause | Remedy |
| --- | --- | --- |
| `another terminal is resuming this session` | Another terminal holds the claim on this conversation. | Use that terminal. If its process is gone, the claim clears on a later `runfree resume`. |
| `the session record changed; run runfree resume again` | The record changed after the list was read. | Run `runfree resume` again. |
| `a runtime lifecycle change is in progress; run runfree resume again` | Another Runfree command is starting, stopping, or repairing the runtime. | Wait for it, then run `runfree resume` again. |
| `runfree resume cannot claim this session: the host boot id or this process's start time could not be read ...` | Runfree could not identify its own process, so it cannot keep two terminals from resuming the same conversation. | Run it again. If it repeats, check that `ps` works in this shell. |
| `... is no longer valid: the Codex conversation match changed` | The Codex history changed after the picker was built. | Run `runfree resume` again and choose from the new list. |

If a resume fails after you chose to resume it, the same question appears the
next time. Choose "Forget it" to stop being asked about that session; it
starts nothing and only marks the record done.

## Git over HTTPS fails

| Condition | What happens |
| --- | --- |
| No `github` or `gitlab` token stored | The request goes out anonymously, with any agent `Authorization` removed. Public fetches work; private fetches and pushes get 401 from the provider. |
| Token expired or revoked | 401 from the provider. Refresh the source, then run `runfree credential sync`. |
| Token cannot reach the repository | 403 or 404 from the provider. |
| Push refused by policy or approval | The proxy refuses with `git-push-denied`, `write-denied`, or a `write-approval-*` reason, before any upstream connection or token read. |
| Path the proxy cannot read unambiguously | No credential is attached; write classification is unchanged. |
| Agent points a remote back at SSH | The connection fails; the sandbox has no SSH egress. |
| Service enabled at an older revision | Git requests carry no proxy credential, so private fetches and pushes get 401. Run `runfree service diff --apply`. |

See [Git over HTTPS and SSH remotes](cli.md#git-over-https-and-ssh-remotes).

## An MCP login waits for approval

On an `ask` host, an MCP login or refresh normally passes as an OAuth protocol
read. If one waits for approval and the denial says:

```text
This OAuth token request names a client metadata URL as its client_id that
Runfree does not recognize. ...
```

the client sent a URL `client_id` other than the published Claude Code or
Codex one. The issuer would fetch that URL, so the request counts as a write.
The denial does not repeat the URL. Approve it with `runfree approve <id>` only
if you expect that client. See [MCP](cli.md#mcp).

## Credentials are not reaching the proxy

```bash
runfree credential status
runfree credential sync --verbose
```

The real token is resolved on the host and held by the proxy. If the agent sees
a placeholder, that is correct. An empty or stale value usually means the host
source failed: run the source command yourself and check it prints a token.

A native Claude or Codex login is a different thing and does not appear here.
See the login steps in [the README](../README.md#3-run-an-agent).

## Dependencies behave oddly inside the container

Dependency directories live in Runfree-owned volumes, not in the host checkout.
Start with `runfree deps doctor`, then see
[Dependency Overlays](cli.md#dependency-overlays).

## Still stuck

- `runfree help <topic>` has task guides for network, credentials, services,
  MCP, dependencies, images, and diagnostics.
- [`cli.md`](cli.md) is the full command reference.
- To find the hosts a project needs, see
  [Audit network discovery](cli.md#audit-network-discovery). Audit mode widens
  what the agent can reach while it is on; close it with `runfree audit off`.
- Bugs and feature requests go to GitHub Issues with the version, host and
  Docker versions, the command, and a sanitized reproduction.
- A suspected vulnerability goes to private reporting, never a public issue. See
  [`../SECURITY.md`](../SECURITY.md).
