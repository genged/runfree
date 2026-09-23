# What's New in Runfree 0.5.0

0.5.0 is the initial Runfree release.

The concise release body is [`release-notes/0.5.0.md`](release-notes/0.5.0.md).
This page carries the detail: what is supported, what was measured, and where
the proof stops.

## What Runfree does

Runfree gives one project a local trust boundary for coding agents:

- Claude Code, Codex, or Pi runs in a per-session Docker container with the
  project at `/workspace`.
- Direct egress from that container is blocked by Docker topology. Outbound
  HTTPS/WSS goes through a Runfree proxy container.
- The proxy enforces an exact-hostname allowlist plus per-host request rules,
  and injects proxy-managed service credentials only after a request is allowed.
- Desired policy lives in the repository at `.runfree/network-policy.json` and
  is inert until a host-owned approval selects a compiled effective policy
  generation. The agent cannot approve its own policy.

[`architecture.md`](architecture.md) has the runtime model;
[`security.md`](security.md) has the threat model.

## Supported platform

| | 0.5.0 |
| --- | --- |
| Host | Apple Silicon macOS |
| Container backend | Docker Desktop with Docker Compose |
| Published archive | `runfree-0.5.0-darwin-arm64.tar.gz`, ad-hoc signed, not notarized |
| Install | Homebrew tap, or `scripts/install.sh` |
| Support | Latest release only, best effort, no response-time commitment |

## Authentication routes

Three separate things are called "credentials" in Runfree, and they get
different protection:

1. **Native agent login.** `claude` and `codex` log in with their own accounts.
   Runfree enables a credentialless operational service for each so the login
   and model hosts are allowed without configuring token injection. That login
   state lives in per-project agent state, inside the agent's reach. It is not
   behind the proxy's credential boundary.
2. **Pi provider setup.** Pi needs its provider configured explicitly. Nothing
   is enabled for it implicitly.
3. **Proxy-managed service credentials.** `runfree credential source add` plus
   `runfree service enable --from-source` keeps the real token on the host and
   in proxy-only memory. The agent sees a placeholder or a
   `runfree_oauth_*` handle.

Only the third is protected from a compromised agent. Do not read "credentials
stay out of the container" as covering a native Claude or Codex login.

## Installing

```bash
brew install genged/tap/runfree
# or
curl -fsSL https://raw.githubusercontent.com/genged/runfree/main/scripts/install.sh | bash
```

The install script needs `bash`, not `sh`: it uses bash arrays, and piping a
script into an interpreter ignores its shebang.

## Uninstalling

Removing the binary does not remove runtime state. See
[`cli.md`](cli.md#uninstalling-and-cleaning-up).

## Known limitations

- The agent can write anything in the project directory, including `.git`.
  Runfree bounds the network, not the working tree.
- Native agent login state is reachable from the agent container.
- An allowed host stays allowed. Policy controls destination and request shape;
  it does not inspect what an agent decides to send to an allowed destination.
- Project image builds run on the host Docker daemon before the sandbox exists.
- Audit mode widens what is observed and is a discovery tool for trusted
  onboarding, not a safe default.
- A proxy replacement has a bounded interval in which no proxy serves requests.
  Live sessions keep their identity across it and adopt the new proxy at their
  next lease renewal; requests attempted inside that window fail rather than
  being queued.
- Docker and the host are trusted. Runfree is not a VM boundary.
