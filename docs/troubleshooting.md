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
