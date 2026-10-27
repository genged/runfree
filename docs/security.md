# Security

Runfree runs a coding agent in Docker. One rule is behind every design
choice:

> **The agent is untrusted. The proxy is the trust boundary** for outbound
> HTTPS/WSS and for proxy-managed credentials.

This page is for users who want to know what Runfree protects and what it
does not. Each topic has a short card. The exact rules, with IDs such as
`NET-1`, are in [security-rules.md](security-rules.md). The mechanics are in
[architecture.md](architecture.md). To report a vulnerability, see
[SECURITY.md](../SECURITY.md).

## Goals

Runfree must:

1. Keep real service credentials out of the agent container.
2. Stop the agent from widening its own authority. The agent can edit desired
   policy, but only a copy that the host approves takes effect.
3. Send all outbound HTTPS/WSS through a proxy that enforces policy.
4. Block direct egress with Docker topology and a firewall, not with
   environment variables.
5. Allow exact hosts only, with optional method and path rules.
6. Hold a write request for a host decision when policy says `ask`.
7. Import project MCP config only after host approval.
8. Show denials in session summaries, proxy logs, and `runfree doctor`.

## Threat Model

**Assets:** proxy-managed tokens, host secrets, host-owned approvals and
effective policy, the proxy CA private key, and host files outside the
project.

| Trusted | Untrusted |
| --- | --- |
| The host user who runs `runfree` | Prompts, model output, and tool calls in the agent |
| The Runfree CLI and its embedded runtime assets | Project code and scripts that the agent runs |
| The proxy container and its token state | Project files: `.runfree/`, `.mcp.json`, `.codex/config.toml`, package and install hooks |
| Credential helpers that the user picks (`gh`, `op`, custom commands) | Responses from allowed hosts |
| Docker Desktop, the Docker daemon, and the host OS | VNC display content and clipboard data |

**In scope:**

- A prompt injection that asks the agent to leak a token.
- A project script that tries to reach the internet directly.
- A malicious project MCP descriptor that asks for credentials or tools.
- A confused-deputy request to an allowed host that carries a proxy
  credential.
- A write sent where policy expects a read.
- Symlink or hard-link attacks on host-side writes under `.runfree/`.

**Out of scope:**

- A malicious Docker daemon, host OS, shell profile, or credential helper.
- Kernel or container escape.
- Code that the user runs on the host outside Runfree.
- Whether an allowed request is safe for the upstream service.
- VM-grade isolation of hostile native code.

## Trust Boundary

```text
 HOST (trusted)
 +--------------------------------------------------------------------+
 | runfree CLI                         XDG state (agent cannot see)   |
 |  - approves exact policy bytes       - approvals, effective policy |
 |  - resolves credential sources       - session lifecycle records   |
 |  - admits and revokes sessions       - proxy CA private key        |
 +------------|-------------------------------------------------------+
              | docker exec (root, pinned)      credential values
              v                                        |
 +---------------------------------+   +---------------v--------------+
 | session container (UNTRUSTED)   |   | proxy container (TRUSTED)    |
 |  /workspace  read-write         |   |  root firewall (nftables)    |
 |  agent state read-write         |   |  request proxy (uid 1001)    |
 |  /runfree/inbox read-only       |   |  tokens on proxy-only tmpfs  |
 |  CA cert only (no key)          |   |  session files (root-owned)  |
 |  placeholders, no real tokens   |   |  pinned host-service gateway |
 |  host-service relay (loopback)  |   |                              |
 +---------------|-----------------+   +------|---------------|-------+
                 |   agent_internal            |               |
                 +---- (internal: true) -------+          proxy_egress
                     no route to internet                      |
                                                               v
                                   allowed HTTPS/WSS hosts; approved ports
                                   on the host's loopback (uid 1001 only)
```

- Each agent process runs in its own session container on `agent_internal`.
  That network has no route to the internet.
- Only the proxy is on both `agent_internal` and `proxy_egress`.
- Ingress forwarders (VNC, `runfree forward`, the MCP OAuth callback) connect
  the host loopback to a session. They carry bytes in one direction. They are
  not an authority boundary. See
  [Utility Participants](architecture.md#utility-participants).
- A host service carries the agent to an approved port on the host's
  loopback. The session relay holds no authority:
  - The proxy admits only an exact approved `<name>.runfree.internal:<port>`
    pair.
  - The proxy splices that pair to the pinned Docker Desktop gateway.
  - The firewall lets only the request proxy's uid 1001 reach that pair.

  See [Host Services](architecture.md#host-services).
- Proxy environment variables only route cooperative clients. They are not
  enforcement.

## What Stops What

| Agent does | Result | Stopped by |
| --- | --- | --- |
| `curl https://attacker.example` | 403 in tunnel, no DNS lookup | proxy allowlist |
| Connects straight to an IP, skipping the proxy | no route | `agent_internal` has no egress; firewall |
| `printenv`, `cat /proc/self/environ` | placeholders only | tokens live in proxy tmpfs |
| Sets a header that a configured credential uses | header stripped, real value injected | proxy header strip |
| `cat ~/.ssh/id_rsa`, `~/.aws/credentials` | file not found | not mounted |
| `cat /etc/proxy-ca/*.key` | file not found | key mounted only in proxy |
| Edits `.runfree/network-policy.json` | no effect | host approval of exact bytes |
| Adds or re-ports a `hostServices` entry | no effect; never auto-approved | host review of every widening |
| Connects to an approved host service at `127.0.0.1:<port>` | **allowed**, opaque bytes to the host port | `runfree host-service add` approval only |
| CONNECTs to an unapproved `<name>.runfree.internal:<port>` | raw 403, no dial | proxy name and port pair check |
| Configures a loopback HTTP MCP (`http://127.0.0.1:<port>`) on an unapproved port | no host reach | proxy name and port pair check; uid 1001-only firewall rule |
| Gives a loopback HTTP MCP a header, helper, or OAuth setting | entry skipped | loopback MCP config allowlist |
| Sends an OAuth token or registration request to an endpoint the proxy does not mediate, on a host only MCP records allow | 403 `oauth-endpoint-not-mediated`, no upstream connect, no approval prompt | proxy grant check ([`MCP-9`](security-rules.md#mcp)) |
| Names `github.com` or another host where other logins pass as an MCP server's token endpoint | refused at `mcp enable` and at every launch | MCP host rule ([`MCP-8`](security-rules.md#mcp)) |
| Dials the host gateway IP directly | no route | `agent_internal` has no egress; uid 1001-only firewall rule |
| POSTs to an allowed host under `ask` | held for a host decision | write approval |
| `git push` to `github.com` or `gitlab.com` with the service's token stored | held under `ask`; once approved, it **succeeds with your token** | write approval; `--deny-git-push` |
| Uses an allowed token for a wrong purpose | **allowed** | token scope and request rules only |
| Runs arbitrary code in the project | **allowed** | bounded by mounts and proxy |
| Writes a fake Claude registry entry or Codex rollout file | labeled, non-default row in its own project's resume picker | sanitized display; never the default cursor or the one question; a resume still goes through normal admission |
| Sets terminal-multiplexer env vars hoping to match a host session | no effect | terminal ids are read only from the host launcher's own environment, never read from or forwarded into the container |

## What You Decide

The agent cannot widen its own authority. Only you can, from the host. Each
row below is a security decision.

```text
 agent asks  --->  you approve on the host  --->  agent gets more power
 (edits policy,    (review, approve, add,          (a host, a token,
  sends a write)    enable)                         a write, a port)
```

| You run or approve | The agent gets | Keep it narrow |
| --- | --- | --- |
| `runfree host add <host>`, or a desired-policy change at review | Requests to that host, and a channel for data to leave | Add exact hosts only; use `--skip-broad` for multi-tenant hosts |
| A credential binding (`credential add`, `service enable --from-…`) | Use of the token on its destinations, within the token's scope | Bind a fine-grained, read-only token where the provider has one |
| A held write, with `runfree approve` | The write goes out with your token | Read what is held; use `--deny-git-push` or `host rules` to refuse a class |
| `service enable --allow-write`, or a `--write allow` host rule | Writes to that host without a prompt | Keep the default `ask` posture |
| `runfree mcp enable` | The MCP server's tools, and its OAuth hosts | Approve only servers you would run yourself |
| `runfree host-service add` | An opaque tunnel to a port on your host's loopback | Approve only services the agent may use freely |
| `runfree forward`, `runfree vnc` | Content that renders in your browser or viewer | Treat it as untrusted agent output |
| `runfree up --audit-network` | Hosts outside the allowlist, for a bounded time | Use it to discover hosts, then turn it off |
| `runfree image approve-context` | A project image build with host Docker networking, before the sandbox exists | Review the Dockerfile and the build context |

## Core Rules

Each card below says what a topic protects, what you decide, and its limits.
The exact rules are in [security-rules.md](security-rules.md). A change must
not break a rule.

### Network

This keeps the agent from reaching any host that policy does not allow. The
agent has no route out. All its traffic goes through the proxy.

```text
 agent (no route out)       proxy                         internet
 CONNECT host:443   ---->  exact host on the list?  yes -> allowed host
                           method, path, write OK?
                           no  -> 403, no DNS, no token read
 other port         ---->  raw 403 (except an approved host service)
                           firewall: only TCP 443 to the allowed set
```

| Traffic | What happens |
| --- | --- |
| HTTPS to an allowed host | Goes out through the proxy, after request rules. |
| HTTPS to any other host | 403 in the tunnel, before any DNS lookup. |
| Plain HTTP, or a port other than 443 | Refused. |
| An approved host service | An opaque TCP tunnel to one port on the host's loopback. |
| Audit mode | Allows hosts not on the list for a bounded time, 443 only. |

You decide:

- Each host you allow. Hosts are exact names, with no wildcards.
- Each host service. Adding one, or changing its port or target, needs your
  review.
- Audit mode. `runfree up --audit-network` turns it on for 60 min by default
  and 8 h at most.

Limits:

- Inside a host-service tunnel, no request rules, write approval, or
  credential injection apply.
- In audit mode, request shape rules and write classification do not apply
  to audited hosts.
- Proxy environment variables only route cooperative clients. The firewall
  and the network topology are the enforcement.

The rules are in [Network rules](security-rules.md#network) (`NET-1` to
`NET-9`). The commands are in [cli.md](cli.md#network-policy).

### Policy

This protects your network authority. The agent can edit desired policy, but
only a copy that you approve takes effect.

```text
 .runfree/network-policy.json   (agent can edit; no effect)
        |
        v
 you approve the exact bytes  -->  effective policy  -->  proxy
                                   (host-owned, read-only to the proxy)
```

- The proxy never reads the project file.
- Unknown fields, duplicate keys, and authority growth without approval are
  refused.
- If a new effective policy generation is invalid, the proxy keeps the
  previous policy.
- `.runfree/config/agent.env` is ignored. The agent environment comes from
  approved policy.

You decide:

- Each policy change, when you approve it.
- A `host rules` setting on a service host. It can narrow the service's
  methods and paths. It can also loosen the write action.

Limits:

- A setting that loosens the write action gives the agent more power. Runfree
  warns about it, but it does not refuse it.

The rules are in [Policy rules](security-rules.md#policy) (`POL-1` to
`POL-8`).

### Credentials

This protects your real tokens. The agent never holds one. The proxy adds
the token to an allowed request.

```text
 host source  --credential sync-->  proxy tmpfs
 (env, 1Password, command, ...)         |
                                        v
 agent (placeholder only) --request--> proxy: allowed? --> add token --> upstream
                                              no --> deny, no token read
```

- The agent sees a placeholder or a `runfree_oauth_*` handle, never the
  value.
- Real tokens never go into the agent environment or project files.
- The proxy CA private key is mounted only into the proxy.
- A value revoked at its source is dropped at the next read. A short outage,
  such as a locked vault, keeps the last good value.

You decide:

- Which source each credential comes from. The source config is host-owned.
- How broad each token is. Runfree checks host, method, and path, not the
  token's scope.

Limits:

- A token can do anything its scope allows on the hosts where the proxy adds
  it.
- A Google service-account key removed from 1Password can stay in use for
  up to 4 hours plus one JWT lifetime. Delete the key in Google Cloud IAM to
  stop it at once.

The rules are in [Credentials rules](security-rules.md#credentials) (`CRED-1`
to `CRED-6`).

### Git Over HTTPS

This protects your git token. The agent runs git with no token. The proxy
adds the token only to git requests that it recognizes.

```text
 agent (no token)            proxy                            provider
 git fetch / clone  ---->  read:  add the token now  ---->  github.com,
 git push           ---->  write: wait for approval  ---->  gitlab.com, ...
                           (or refuse: --deny-git-push)
 other paths        ---->  no git token
```

| Request | What happens |
| --- | --- |
| Fetch, clone | A read. The proxy adds the token. |
| Push | A write. Under `ask`, it waits for `runfree approve`. After approval, it goes out with your token. |
| Git LFS download | A read only where the service mediates LFS, and only if the proxy proves that the body is a download. |
| Git LFS upload or lock | A write. |
| Any other path on the host | No git token. |

You decide:

- Which token you bind. It reaches every repository that it can access. Use
  a fine-grained token.
- Each push. To refuse pushes outright, run
  `runfree host rules <host> --deny-git-push`.

Limits:

- `--deny-git-push` does not stop a Git LFS upload. It also does not stop a
  push through the provider's REST or GraphQL API.
- A Git LFS answer can carry provider credentials. They reach the agent.
- The SSH-to-HTTPS rewrite is routing only. SSH has no route out.

The rules are in [Git over HTTPS rules](security-rules.md#git-over-https)
(`GIT-1` to `GIT-10`). The commands are in
[cli.md](cli.md#git-over-https-and-ssh-remotes).

### Older Readers

This protects policy from a reader that does not know its newest fields. An
older reader refuses new policy. It never drops a field and widens access.

```text
 newer policy --> teammate's older CLI  --> refuses the file
              --> proxy of another build --> replaced first, or change saved unapplied
              --> older proxy (race)     --> refuses it, keeps the last valid policy
```

| Reader | What happens |
| --- | --- |
| Older CLI, newer desired file | Refuses the file, for example `version must be 2`. |
| Running proxy of another build | The CLI replaces the proxy first, or saves the change unapplied and names the remedy. |
| Older proxy that reads a newer generation | Refuses it and keeps its last valid policy. |
| Older CLI after a downgrade | Cannot read project-image build-context approvals. Approve them again. |

You decide:

- When the team moves to a release that reads the new version. Until then,
  older CLIs refuse the committed file.

Limits:

- The cost of a mismatch is availability, not authority. A refused policy
  stops the older reader's change; it does not widen access.

The rules are in [Older Readers rules](security-rules.md#older-readers)
(`OLD-1` to `OLD-4`).

### Sessions

This keeps each agent process separate and makes sure that only an admitted
session can send traffic. A session's identity is its source IP on
`agent_internal`. It tells which container speaks, not which user or prompt.

```text
 host                                    proxy
 inspect container --> session file -->  firewall + request proxy
 every 30 s: inspect and rewrite         serve the IP while the file is valid
 host stops writing                      IP stops within 5 minutes
 session ends: delete file first         IP no longer served
```

| If | Then |
| --- | --- |
| No valid session file names the IP | The proxy drops the traffic. |
| Two files claim one IP, or a file is bad | The proxy serves nobody involved. |
| The host stops writing heartbeats | The lease ends within five minutes. |
| An IP goes to a new container | The host first proves that the old owner is gone. |
| The host cannot read a listing | It does not count the listing as empty. |

Limits:

- The identity is a network identity. It does not tell which user or prompt
  made a request.
- A peer whose owner process dies keeps access until its session file
  expires, at most five minutes.
- Runfree checks session shape only with host-side `docker inspect`. That
  shows what Docker created, not what the process does.

The rules are in [Sessions rules](security-rules.md#sessions) (`SESS-1` to `SESS-13`).

### Write Approval

This protects your upstream accounts from writes that you did not agree to.
The proxy puts each request in one of two classes: read or write. A request
that the proxy cannot prove is a read is a write.

```text
 agent                    proxy                            you (host)
 GET, fetch   ---->  read:  forward
 POST, push   ---->  write: hold  ------------------->  runfree approvals --watch
                            |                           approve / deny
                            +-- no approver: 403 at once
                            +-- no decision in time: 403
```

| Write action | What happens to a write |
| --- | --- |
| `ask` (the default) | It waits for your decision. |
| `allow` | It goes out. AI provider hosts in the initial template use `allow`. |
| `deny` | It is refused. |

You decide:

- Each held write, or a grant for a request, a time, or the session.
- A deny. It stays until you run `runfree approvals --clear-deny`.

Limits:

- A headless run (`runfree run`) never holds. Its `ask` writes are denied.
- Host-service tunnels, mediated OAuth exchanges, and STDIO or loopback MCP
  servers do not pass write approval.
- An approved write goes out with the real credential.

The rules are in [Write Approval rules](security-rules.md#write-approval)
(`WRITE-1` to `WRITE-8`).

### MCP

This protects your host and your OAuth tokens from MCP servers that a project
names. A project MCP entry does nothing until you approve it. The proxy keeps
real OAuth tokens; the agent gets `runfree_oauth_…` handles.

```text
 .mcp.json / .codex/config.toml
        |  runfree mcp enable  (one host-side review)
        v
 approved MCP record  --->  agent config (read-only)
        |
 agent: MCP call, Bearer handle  --->  proxy: handle -> real token  --->  MCP host
 agent: token request            --->  mediated endpoint? yes: forward
                                       no, on a guarded host: 403
                                       oauth-endpoint-not-mediated
```

| Server kind | Passes the proxy | Write approval |
| --- | --- | --- |
| HTTPS | Yes | Yes (`runfree mcp rules`) |
| STDIO, in the agent container | No | No |
| Loopback HTTP (`http://127.0.0.1:<port>`) | No | No; it reaches the host only through `runfree host-service add` |

You decide:

- Each server, at `runfree mcp enable`. The review shows its OAuth hosts and
  where the tokens go.
- Discovery calls. Runfree contacts a project-named host only after you
  agree.
- Each MCP tool call under `ask`.
- `runfree mcp revoke`. It removes the server's hosts and clears its OAuth
  state.

Limits:

- No imported descriptor starts a host process. STDIO commands run in the
  agent container.
- A server cannot claim a credential host, a curated host, or another
  server's host.
- Strict MCP mode stops passive descriptors only. Code that already runs in
  the agent can start another binary.
- A login that you run by hand on a broadly allowed host can still return
  real tokens to the agent ([Residual Risks](#residual-risks)).

The rules are in [MCP rules](security-rules.md#mcp) (`MCP-1` to `MCP-11`).

### Agent Container

This protects the host from the agent process. The container is the
sandbox. The agent runs as an ordinary user, with no way to gain privileges.

```text
 agent CLI (uid 1000, own sandbox off)
   |  setuid binary          -> no-new-privileges: no gain
   |  raw socket, change net -> NET_ADMIN, NET_RAW dropped
   |  reach PID 1            -> same uid 1000: no gain
   |  trust the proxy CA     -> read-only bundle; no root needed
   v
 nothing inside the container is a boundary; the mounts and proxy are
```

| Agent tries | Result |
| --- | --- |
| Gain root through a setuid binary | Fails: `no-new-privileges` |
| Open a raw socket or change the network | Fails: `NET_ADMIN` and `NET_RAW` dropped |
| Take over PID 1 | Gains nothing: it runs as the same uid 1000 |
| Connect to a helper on 127.0.0.1 | Open. The helper must authenticate its callers |

You decide:

- What your project image puts in the container. It can change PID 1, which
  costs only the fast stop.

Limits:

- Loopback inside the container is open. A helper that trusts 127.0.0.1
  trusts the agent.
- Agent CLIs run with their own permission prompts off.
- A downgrade while sessions from a newer release are live is not supported.
  Run `runfree destroy --force` first.

The rules are in [Agent Container rules](security-rules.md#agent-container)
(`AGENT-1` to `AGENT-5`).

### Host Files

This protects files on your host. The agent sees only the project and a few
named mounts. Host code treats every file that the agent can write as
hostile.

```text
 host                                  session container
 project tree  <---- read-write ---->  /workspace
 .runfree/     host writes: no links, no special files
 ~/.ssh, ~/.aws, home config   X       not mounted
 agent state   <---- read as hostile input, with budgets
 headless run prompt  ------------->   read-only inbox
```

| Mounted into the agent | Not mounted |
| --- | --- |
| The project, read-write | Host-wide secrets |
| Per-project agent state and sanitized per-agent config | Home config, such as `~/.ssh` or `~/.aws` |
| Generated Git identity | Host terminal identifiers (never forwarded) |
| Dependency volumes and the read-only inbox | The host state directory of `runfree run` |

Limits:

- The agent can read and change the whole project, including `.git`.
- Resume rows built from agent-written files are labeled "Claude reported"
  or "Codex match". They are never the default choice.
- The result of a headless run with malformed agent output is unverified,
  never a success.

The rules are in [Host Files rules](security-rules.md#host-files)
(`FILE-1` to `FILE-5`).

### Lifecycle

This protects you from leftover authority. A crash, a timeout, or a
concurrent command must not leave a session that can still reach the proxy.
Cleanup must not delete anything that Runfree does not own.

```text
 start ---> lock ---> launch ---> agent runs ---> agent exits ---> teardown
              |          |                                           |
        bounded wait   active within 60 s,            revoke first, release last;
        (1 minute)     or exit 111                    remove only exact inspected IDs
```

| Situation | What Runfree does |
| --- | --- |
| A Docker call times out | Never counts as success. An empty listing does not prove absence |
| A teardown was interrupted | The next start finishes it only on Docker's proof |
| A command waits too long for the lock | It defers with a retry instruction. Nothing is done on its behalf |
| Runfree cannot prove a state | It refuses and names `runfree up` or `runfree destroy --force` |

You decide:

- `runfree stop --force` or `runtime reload-policy --force` while sessions
  are live or unknown.
- `runfree destroy --force` to reset the project when Runfree cannot prove
  that a session owner is dead.

Limits:

- The lock limits are refusal limits, not restoration guarantees. Host
  suspension and filesystem stalls can exceed them.
- Names find cleanup candidates but authorize nothing. A container with
  partial or conflicting labels is refused, and it can need manual action.

The rules are in [Lifecycle rules](security-rules.md#lifecycle) (`LIFE-1` to
`LIFE-12`).

## What Runfree Does Not Prove

These are limits of the checks that Runfree runs at launch. The limits of the
test suite are in [testing.md](testing.md#proof-limits).

- **Nothing from inside the container.** Runfree checks session shape only
  with host-side `docker inspect`. That shows what the daemon created. It
  does not show what the process does.
- **Agent-position egress on every launch.** A warm launch skips some probes
  when its warm-proof fingerprint matches:
  - It does not run the agent-position deny probes, the server-UID denial
    probes, or the root DNS probe.
  - Beside live peer sessions, no probe runs for each peer.
  - The skipped proof is bound to the proxy instance, networks, images,
    ruleset shape, daemon, and VM boot.
- **When a fingerprint is recorded.** Runfree records a fingerprint only when
  all of these are true:
  - The next reconcile found nothing to repair.
  - Any restore of surviving sessions finished.
  - The proxy did not restart.
  - No ephemeral helper is attached.
- **When a fingerprint stops matching.** `stop`, `destroy`, and `rebuild`
  delete it. A warm proof older than 24 hours never matches. A Docker daemon
  with live-restore on always validates fully. `runfree up` always runs every
  probe.
- **Audit set emptiness.** In enforce mode, only the proxy's own firewall
  supervisor checks that the audit set is empty. The host proof checks the
  set's shape, not its members.

## Residual Risks

These are the 10 known risks with the most impact, worst first.

| Risk | Worst case | You can |
| --- | --- | --- |
| An approved push goes out with your real token, and the token reaches every repository it can access. | The agent changes any repository the token reaches. | Use fine-grained tokens. Keep pushes under `ask`, or use `--deny-git-push`. |
| An allowed host gets what the agent sends. Runfree checks host, method, and path, not intent or content. | The agent does anything the token allows there. Data leaves, for example in a permitted `GET` query. | Use narrow tokens. Allow only the hosts that the work needs. Add method and path rules. |
| A host-service tunnel is opaque, and it reaches whatever holds the approved port on your loopback. | The agent uses the host service freely, or reaches a process that took over the port. | Approve only services that you would let the agent use freely. When you stop a service, remove its approval with `runfree host-service remove <name>`. |
| A loopback MCP entry reaches a host process when a host service holds its port, even one that you add later. | The agent's tool calls run outside the sandbox, with no write approval. | Before you approve, read the reach that `runfree mcp explain` shows. Review host-service ports before you add them. |
| The OAuth callback page renders in your browser on `localhost`. | A compromised session sends data out through your browser, or reaches other localhost services. | Open callback URLs only for logins that you started. |
| A login on a broadly allowed host is not mediated when no MCP record names its token endpoint. | Real OAuth tokens reach the agent. | Keep OAuth hosts MCP-only. Allow broad hosts only on purpose. Record MCP servers with `runfree mcp enable`. |
| An approved hostile MCP server claims another login at a broadly allowed issuer that is not curated. | That login gets a handle that works at the hostile server's MCP host. | Approve an `ALREADY ALLOWED` claim only if the address belongs to the same service. |
| `--deny-git-push` blocks only the git push endpoint. | The agent pushes through the provider's REST or GraphQL API. | Add method rules on the API host. |
| Content from `runfree forward` and VNC reaches your unsandboxed browser or viewer. | Hostile agent output runs in your browser or viewer. | Treat it as untrusted. Use a maintained viewer and the default random password. |
| Audit mode allows hosts that are not on the list, for a time window. | The agent reaches any host during the window. | Use `up --audit-network` only on purpose. |

Approving a write, allowing a broad host, or adding a credential gives the
agent real power upstream. Treat each one as a security decision.

All risks, grouped by topic, are in [security-rules.md](security-rules.md#residual-risks).

## Platform Status

Only Apple Silicon macOS with Docker Desktop is supported; see
[Supported Release Shape](project-brief.md#supported-release-shape).

## Verification

The commands to run for each kind of change are in [testing.md](testing.md)
and [CONTRIBUTING.md](../CONTRIBUTING.md).

Security tests must prove the rejection happens **before** the side effect:
before DNS lookup, upstream connect, credential injection, policy change, or
file write. Each new fail-closed refusal needs a test for the refusal and a
test for its recovery path.
