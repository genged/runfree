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
at runtime until a host-owned approval selects a compiled effective generation.

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

- **An unclaimed container.** A leftover container from an older Runfree layout
  hits the unclaimed-container refusal. `runfree rebuild` is the remedy;
  `runfree destroy` is the heavier one.
- **A live session blocks the operation.** `runfree stop` and
  `runfree runtime reload-policy` refuse while sessions are live. Close the
  sessions, or pass `--force` once you know what it ends.
- **Docker is not reachable.** Runfree needs Docker Desktop running with Docker
  Compose. Check `docker version` first.

## The config is refused as pre-v4

```text
runfree error: .runfree/runfree.json uses config version 3, which this release no longer migrates
  move .runfree aside and run `runfree init` to create a current configuration, then re-add hosts and services
```

Since 0.5.1, a `.runfree/runfree.json` below version 4, or one that still has
the removed `agent`, `paths`, or `project.*` keys (other than `project.name`),
is refused by every command, `init` included. Only pre-release installs can
have one: 0.5.0 already wrote version 4. The refusal happens before anything is
written.

```bash
mv .runfree .runfree.pre-v4
runfree init
runfree host add <host>        # re-add what the old policy allowed
```

Use `.runfree.pre-v4/network-policy.json` as the list of hosts and services to
re-add, then delete the old directory.

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
arguments, ids, or output, so the lines are safe to paste into an issue. The first start after an
upgrade that changes the agent image inputs rebuilds the image and is expected
to be slow.

## A write is being held

With approve-on-write active, an outbound write waits for a host-side decision.

```bash
runfree approvals            # what is held
runfree approvals --watch    # stay attached as the approver
runfree approve <id>
runfree approve <id> --deny
```

If you told Runfree to stop asking and want the prompts back:

```bash
runfree approvals --clear-deny
```

## Credentials are not reaching the proxy

```bash
runfree credential status
runfree credential sync --verbose
```

The real token is resolved on the host and held by the proxy. If the agent sees
a placeholder, that is correct. An empty or stale value usually means the host
source failed: run the source command yourself and check it prints a token.

A native Claude or Codex login is a different thing and does not appear here.
See [`whats-new-0.5.0.md`](whats-new-0.5.0.md#authentication-routes).

## Dependencies behave oddly inside the container

Dependency directories live in Runfree-owned volumes, not in the host checkout.

```bash
runfree deps plan       # what is mounted where
runfree deps doctor     # drift and host artifact risks
runfree deps install
runfree deps reset      # remove the volumes and start over
```

## Discovering what a project actually needs

For a trusted onboarding task, audit mode records non-allowlisted hosts instead
of denying them, for a bounded window:

```bash
runfree up --audit-network=30m
runfree audit status
runfree audit report          # suggested host add commands; never edits policy
runfree audit off
```

Audit mode widens what the agent can reach while it is on. Use it deliberately
and close it when you are done; `runfree audit off` severs in-flight audited
connections immediately.

## Still stuck

- `runfree help <topic>` has task guides for network, credentials, services,
  MCP, dependencies, images, and diagnostics.
- [`cli.md`](cli.md) is the full command reference.
- Bugs and feature requests go to GitHub Issues with the version, host and
  Docker versions, the command, and a sanitized reproduction.
- A suspected vulnerability goes to private reporting, never a public issue. See
  [`../SECURITY.md`](../SECURITY.md).
