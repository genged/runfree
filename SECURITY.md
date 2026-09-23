# Security Policy

## Supported Versions

Runfree is a security-sensitive beta. The latest release is the only supported
line for security fixes; there is no LTS policy and no backporting to earlier
versions. Fixes ship as a new release, because published release assets are
immutable and are never replaced in place.

| Version | Supported |
| --- | --- |
| 0.5.x | Yes, latest patch only |

Support is best effort. There is no response-time commitment, including for
security reports. That is a statement of capacity, not of priority: security
reports are what gets looked at first.

## Reporting a Vulnerability

Please do **not** open a public issue for a suspected vulnerability. Use GitHub
private vulnerability reporting instead:

<https://github.com/genged/runfree/security/advisories/new>

Include as much of the following as you can without sharing secrets:

- Runfree version and install path.
- Host OS and Docker backend/version.
- The agent command you ran.
- Sanitized `.runfree/runfree.json` and relevant policy snippets.
- Sanitized denial, proxy, or runtime logs.
- Reproduction steps and expected vs. actual behavior.

Do not send real tokens, full environment dumps, or unredacted logs. A
reproduction that needs a credential can describe the credential's shape and
scope instead.

## What Counts

In scope, roughly in order of severity:

- Anything that lets the agent container read a proxy-managed credential.
- Anything that lets the agent container reach a host that policy does not
  allow, or bypass the proxy.
- Anything that lets the agent container change effective policy, approvals, or
  other host-owned state.
- Host filesystem writes outside the project through Runfree's own host-side
  paths.

Known and documented, so not a vulnerability report by itself: the agent can
write anywhere in the project directory including `.git`; native Claude and
Codex login state lives inside the agent's reach; an allowed host stays allowed
for whatever the agent chooses to send it; project image builds run before the
sandbox exists; Docker and the host are trusted. These are described in
[`docs/security.md`](docs/security.md). A concrete way to turn one of them into
something worse than documented is very much in scope.

## Security Boundary Summary

Runfree treats the agent container as untrusted. The proxy container is the
trust boundary for outbound HTTPS/WSS policy enforcement and proxy-managed
credentials. Real proxy-managed service tokens must never be placed in the
agent container; agent-visible env vars are placeholders or OAuth handles.
Project policy lives under `.runfree/`, with `.runfree/network-policy.json` as
the fixed network and credential policy path.

For the detailed threat model and local verification commands, see
[`docs/security.md`](docs/security.md). For runtime enforcement internals, see
[`docs/architecture.md`](docs/architecture.md).
