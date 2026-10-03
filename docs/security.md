# Security

Runfree runs a coding agent in Docker. The rule behind every design choice:

> **The agent is untrusted. The proxy is the trust boundary** for outbound
> HTTPS/WSS and for proxy-managed credentials.

This page is the security model: what Runfree protects, from whom, the rules
the code must keep, and the risks that remain. The mechanics are in
[architecture.md](architecture.md). To report a vulnerability, see
[SECURITY.md](../SECURITY.md).

## Goals

Runfree must:

1. Keep real service credentials out of the agent container.
2. Stop the agent from widening its own authority. The agent can edit desired
   policy, but only a host-approved copy takes effect.
3. Send all outbound HTTPS/WSS through a proxy that enforces policy.
4. Block direct egress with Docker topology and a firewall, not with
   environment variables.
5. Allow exact hosts only, with optional method and path rules.
6. Hold write requests for a host decision when policy says `ask`.
7. Import project MCP config only after host approval.
8. Show denials in session summaries, proxy logs, and `runfree doctor`.

## Threat Model

**Assets:** proxy-managed tokens, host secrets, host-owned approvals and
effective policy, the proxy CA private key, and host files outside the project.

| Trusted | Untrusted |
| --- | --- |
| The host user who runs `runfree` | Prompts, model output, and tool calls in the agent |
| The Runfree CLI and its embedded runtime assets | Project code and scripts the agent runs |
| The proxy container and its token state | Project files: `.runfree/`, `.mcp.json`, `.codex/config.toml`, package and install hooks |
| Credential helpers the user picks (`gh`, `op`, custom commands) | Responses from allowed hosts |
| Docker Desktop, the Docker daemon, and the host OS | VNC display content and clipboard data |

**In scope:**

- A prompt injection that asks the agent to leak a token.
- A project script that tries to reach the internet directly.
- A malicious project MCP descriptor that asks for credentials or tools.
- A confused-deputy request to an allowed host that carries a proxy credential.
- A write sent where policy expects a read.
- Symlink or hard-link attacks on host-side writes under `.runfree/`.

**Out of scope:**

- A malicious Docker daemon, host OS, shell profile, or credential helper.
- Kernel or container escape.
- Code the user runs on the host outside Runfree.
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
 |  placeholders, no real tokens   |   |                              |
 +---------------|-----------------+   +------|---------------|-------+
                 |   agent_internal            |               |
                 +---- (internal: true) -------+          proxy_egress
                     no route to internet                      |
                                                               v
                                                  allowed HTTPS/WSS hosts
```

- Each agent process runs in its own session container on `agent_internal`.
  That network has no internet route. Only the proxy is also on
  `proxy_egress`.
- Ingress forwarders (VNC, `runfree forward`, MCP OAuth callback) connect the
  host loopback to a session. They are one-way transport, not an authority
  boundary. See [Utility Participants](architecture.md#utility-participants).
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
| POSTs to an allowed host under `ask` | held for a host decision | write approval |
| Uses an allowed token for a wrong purpose | **allowed** | token scope and request rules only |
| Runs arbitrary code in the project | **allowed** | bounded by mounts and proxy |

## Core Rules

Each rule says what must stay true. Changes must not break a rule. Links
point to the mechanism.

### Network

1. The proxy checks policy **before** DNS lookup, credential read, OAuth
   mediation, and upstream connect. Plain HTTP, hosts not on the list, raw
   tunnels, method or path violations, and unapproved writes stop there.
2. Hosts are exact names. No wildcards.
3. The root firewall allows traffic to a destination only if it is in the DNS
   allow set built from the same policy generation as the request proxy.
4. Denied CONNECT requests get feedback in the tunnel. Denials go to
   `runfree doctor`.

Order, hardening, and firewall rules:
[Proxy Enforcement Details](architecture.md#proxy-enforcement-details).

### Policy

1. `.runfree/network-policy.json` is desired input. The agent can edit it.
   Its edits do nothing until a host transaction captures, verifies, and
   approves the exact bytes.
2. The proxy never reads the project file. It reads an immutable effective
   generation from a read-only XDG mount.
3. Unknown fields, duplicate keys, oversize input, unsafe paths, and any
   authority growth without exact approval fail closed.
4. A mutation that runs beside live sessions approves the exact candidate it
   re-read under the lock, never a fresh read of the file.
   See [Desired-Policy Mutation](architecture.md#desired-policy-mutation-beside-live-sessions).
5. Invalid or incomplete generations keep the previous effective policy.
6. The project `.runfree/config/agent.env` is ignored. The agent environment
   comes from the selected effective generation.

### Credentials

```text
host source (env, 1Password, command, stdin, JWT, OAuth seed)
   | runfree credential sync  (host resolves)
   v
proxy-only tmpfs  --->  proxy strips agent auth headers
                        policy allows?  --no-->  deny, no token read
                            | yes
                            v
                        inject credential  --->  upstream
agent sees: placeholder or runfree_oauth_* handle only
```

1. Real tokens never go into the agent environment, project files,
   `.runfree/runfree.json`, or `.runfree/network-policy.json`.
2. Desired policy (`tokens`) says which credential may go to which host,
   header, and path. The source config that says where the value comes from
   is host-owned.
3. Credential writes happen only after the runtime is validated and a
   prepared runtime exists. Prepared values expire after 120 s. No source is
   read while the lifecycle lock is held.
4. A warm launch may reuse a proxy-held value without re-reading its source,
   only while a host receipt proves it current and its last read is under 15
   minutes old; the launch's watcher re-reads every source right after the
   launch. A source revoked at its origin (a definitive read failure) is
   therefore dropped seconds after a warm launch, not before it. A source that
   cannot be read for a transient or unclassified reason (a locked vault, a
   prompt the detached watcher cannot show) keeps the held value, bounded by
   the keep-last-good age, until the next launch reads it interactively.
   `runfree credential sync` always re-reads.
5. The proxy CA private key is mounted only into the proxy.

### Sessions

A session's identity is its source IP on `agent_internal`. This is a network
identity: it says which container is speaking, not which user or prompt.
`source-ip-v1` is the only mode; the proxy refuses to start without it.

```text
host: allocate IP -> fence IP -> create+start container -> inspect once
                                                              |
      <- heartbeat every 30 s: inspect, rewrite file  <- write session file
                                                              |
proxy: firewall + request proxy read the file (on change; 100 ms backstop) -> serve IP
```

1. **No file, no traffic.** An IP is served only while a root-owned,
   well-formed, eligible, unexpired session file names it and no other file
   claims it. Only the host writes these files.
2. **No write without inspection.** Each write comes from a Docker inspection
   in the same call. A proven identity mismatch deletes the file at once. An
   inspection that fails deletes nothing.
3. **Bounded lease.** A host that stops writing loses the session within the
   five-minute maximum lease, on the proxy's own clocks.
4. **Both consumers read the same files.** The firewall and the request proxy
   decide on their own, with the same rule. Neither trusts the other.
5. **No IP reuse without a fence.** Before a new container gets an old IP,
   the host proves both consumers dropped the old owner and the kernel has no
   old sockets. See [IP Reuse Fence](architecture.md#ip-reuse-fence).
6. **Fail closed on contradiction.** Two files for one IP, wrong bindings, a
   bad file, or a name/key mismatch: nobody involved is served.
7. **Peers never touch a live owner.** Reconcile acts only on records whose
   owner process is proven dead. Unknown means keep.
8. **Revoke file first, record last.** The record reserves the IP, so it goes
   last. A failed file delete stops teardown.
9. **Heartbeats never kill the agent.** They control only the session file.

Mechanics: [Session Admission](architecture.md#session-admission).

### Write Approval

A request is a read or a write. The write action is `allow`, `deny`, or `ask`.
The default is `ask`. AI provider hosts in the initial template use `allow`
because the agent must POST to model APIs.

1. Decisions are made on the host (`runfree approvals --watch`,
   `runfree approve <id>`).
2. A grant belongs to one session. It ends when that session's authority ends.
3. Positive grants have a lifetime (`request` 5 min, `ttl` up to 8 h). Each
   grant expires on the wall clock or the monotonic clock, whichever runs out
   first, so a clock step or host sleep cannot extend it.
4. Denies do not expire. Only `runfree approvals --clear-deny` removes them,
   through a root-owned channel that the agent cannot reach. Clearing goes
   back to `ask`, never to `allow`.
5. Activating new policy never removes a deny.

Details: [Write Approval Grants](architecture.md#write-approval-grants).

### MCP

1. Project entries from `.mcp.json` and `.codex/config.toml` load only after
   `runfree mcp approve`.
2. Claude gets a read-only approved config with strict MCP mode. This stops
   passive project descriptors at startup. It does not stop code already
   running in the agent from starting another binary or config.
3. Static headers need a host-owned credential source.
4. HTTP MCP tool calls follow the write-approval rules (`runfree mcp rules`).
   STDIO MCP servers run inside the agent container; their calls do not pass
   the proxy, so `runfree mcp rules` refuses them.
5. No imported MCP descriptor starts a host process. Local STDIO commands run
   only in the agent container; a host-path command is skipped. Codex Desktop
   built-ins (`node_repl`, `computer-use`) are skipped and never enter the
   generated agent config.
6. **Each session owns its OAuth callback path.** When an approved MCP server
   can use OAuth, every session gets its own loopback port, forwarder, and
   in-session bridge before it starts. The forwarder is bound to that session
   and removed before the session's record releases its address, and before
   an orphan session container that no record claims is removed. The bridge
   accepts only its forwarder. The port is a routing value, not an
   authorization secret: the client keeps state, PKCE, and issuer checks.
7. `runfree mcp enable` adds OAuth hosts only after one host-side review.
   Discovery contacts a project-named host only after the user agrees, on a
   terminal, and only public, checked addresses over a pinned HTTPS
   connection. It adds a host only when valid metadata names a token endpoint
   the proxy mediates for that server. The hosts live in host-owned state, not
   in desired policy, and stop applying when the reviewed server config
   changes. `runfree mcp revoke` removes exactly them.
8. **Revoke clears the proxy's OAuth state for the server.** Revoke first
   saves a new random state epoch for the server in host-owned state. Every
   policy publishes an epoch for each MCP OAuth server. The proxy stamps
   handles and discovered endpoints with it, deletes state from any other
   epoch before it applies a policy, and refuses a stale handle at use. A
   token response from an exchange that started before the revoke is
   blocked, not stored. The clear works when no proxy runs (it happens at the
   next start). Revoke says "cleared" only when the running proxy confirmed
   the exact policy generation. A damaged or missing epoch record clears the
   OAuth state of every MCP server.
9. **Protocol reads are exact.** On an `ask` host, a POST is a read, with no
   approval, only when its exact path (no normalization, query, or encoding)
   is a token or registration endpoint that `mcp enable` recorded for one
   server, the proxy mediates it for that server alone, and the body is a
   plain login, refresh, or loopback-only client registration with no field
   an issuer may fetch at a URL the agent chose: a URL-valued `client_id`
   must equal, byte for byte, a pinned agent client metadata URL (Claude
   Code's or Codex's published document), and no `resource` may name another
   host. Each server gets at most 30 a minute. Everything else
   on the host stays a write. A request that selected the unmediated proxy
   rule while its endpoint became mediated is refused, so a token never
   reaches the agent unmediated. This covers the token and registration
   POSTs only: an authorization GET with a URL `client_id` to an issuer host
   the project allows broadly (`--oauth-host`, desired policy, or the MCP
   host itself) is an ordinary read, and an issuer that supports client ID
   metadata documents may fetch that URL.

### Agent Container

1. The agent runs as uid 1000 with `no-new-privileges`, and `NET_ADMIN` and
   `NET_RAW` dropped.
2. **Localhost inside the agent is not a trust boundary.** Dev tools need
   loopback TCP, so it stays open. A helper in or near the agent namespace
   must authenticate its callers (capability, nonce, Unix socket permissions).
   It must never treat "came from 127.0.0.1" as authorization.
3. Agent CLIs run with their own sandbox off (`--dangerously-skip-permissions`,
   `--dangerously-bypass-approvals-and-sandbox`). The container is the
   sandbox, so agent-side permission rules add nothing to it.
4. **Docker's init is PID 1, not a boundary.** A session container is created
   with `--init`, so PID 1 is Docker's `docker-init` (tini) and the session
   entry, then the agent, is its child. The init forwards the stop signal, so
   `docker stop` reaches a live agent at once (exit 143 when the agent dies
   of the signal; an agent that handles it exits with its own status) instead
   of waiting out the stop timeout for a PID 1 that ignores SIGTERM. It runs as the same
   uid 1000 with the same capabilities and `no-new-privileges`, so the agent
   gains nothing by reaching it. Its bind mount is added by the daemon and is
   outside the inspection proof; a project image can make PID 1 something
   else, which costs only the fast stop. Project `TINI_*` variables
   (`TINI_SUBREAPER`, `TINI_KILL_PROCESS_GROUP`, `TINI_VERBOSITY`) are honored:
   none changes identity, capabilities, mounts, or network, and Docker's
   SIGKILL after the stop timeout is the real stop bound. The engine must ship
   Docker's init (`docker-init`); Docker Desktop and Docker Engine packages
   do. Without it, the container fails to start, the daemon's error
   is shown, and nothing is left behind.
   The init is recorded in each session's stored template: a session started
   by an older release keeps its template, runs without the init, and is
   proven that way (across proxy replacements too) until it ends.
   Downgrading Runfree while sessions from a newer release are live is not
   supported: run `runfree destroy --force` first.

### Host Files

1. Host writes under project paths reject symlinks, hard links, and special
   files (`safe-fs.ts`).
2. No host-wide secrets or home config are mounted into the agent.
   Intended exceptions: per-project agent state, sanitized per-agent config,
   generated Git identity, dependency volumes, and the read-only inbox.
3. Host code treats agent-writable state (Codex config, Claude session
   registry) as hostile input: bounded, no-follow, single-link reads.

### Lifecycle

1. Every refusal names its recovery command: `runfree up` to retry,
   `runfree destroy --force` to reset the project.
2. A Docker call that times out never counts as success. An empty listing
   after a timeout does not prove absence.
3. Cleanup and teardown remove containers and images only by exact inspected
   ID with proven ownership labels. Names find candidates; they authorize
   nothing.
4. `runfree stop` and `runtime reload-policy` need `--force` while live or
   unknown sessions, a pending rebind, or an interrupted teardown exist.
5. A start finishes an interrupted teardown only on Docker's proof: the owner
   is dead, the session container is absent or stopped, and no proxy can
   serve the session file. The record goes only after Docker proves the
   container absent. Anything Docker cannot prove keeps the record and refuses
   with the reason and its remedy.
6. The Docker Engine API transport contacts only the daemon the Docker CLI
   would contact, over a local Unix socket, and only with the fixed read and
   exec requests its routes build. No argv value, project file, or agent
   output selects the socket, the method, or the endpoint. An answer it
   cannot give exactly as the CLI would goes to the CLI, and a started exec
   is never re-run. It is on by default; `RUNFREE_DOCKER_TRANSPORT=cli`
   keeps every call on the Docker CLI. See
   [Docker Access](architecture.md#docker-access).

## What Runfree Does Not Prove

- **Nothing from inside the container.** Session shape is proven by host-side
  `docker inspect` only. That shows what the daemon created, not what the
  process does.
- **Agent-position egress on every launch.** A warm launch whose warm-proof
  fingerprint matches does not re-run the agent-position deny probes, the
  server-UID denial probes, or the root DNS probe. It re-validates the
  topology, capabilities, routes, nftables ruleset, and security contract from
  fresh evidence, and binds the rest to the proxy instance, networks, images,
  ruleset shape, daemon, and VM boot. `runfree up` always runs every probe.
- **Guest clock lag** is not tested live. The live fixture cannot shift the
  Docker VM clock. The rule that a lagging clock cannot extend a lease has
  unit tests only.
- **Audit set emptiness** in enforce mode is checked only by the proxy's own
  firewall supervisor. The host proof checks set shape, not members.
- **The release pipeline** runs the Test workflow's checks (static, unit,
  templates, packaged offline E2E), not the live runtime suite. `make test-runtime` needs a
  Docker host and runs by hand. A release has proven it only if its
  acceptance record says so.

## Residual Risks

- **The OAuth callback page reaches the host browser.** An eligible session
  answers its own callback URL, and the operator's browser renders that answer
  on `localhost`. A compromised session can use the page to send data out
  through the browser, or to reach other localhost services with same-site
  requests. This is the same channel `runfree forward` and `runfree vnc` open,
  but it exists in every eligible session. Open callback URLs only for logins
  you started.
- **A callback forwarder that dies mid-session frees its address.** The
  forwarder's `agent_internal` address is dynamic. If the forwarder exits while
  its session runs, that address can go to a later session, which then passes
  the bridge's peer check. It can only reach the first session's loopback
  callback listener, which still checks OAuth state. The host port is also
  freed and could be taken by another project; PKCE stops the code from being
  redeemed there.

Accepted, known risks:

| Risk | Why it remains |
| --- | --- |
| Allowed hosts can be misused within their token scope | Runfree checks host, method, and path, not intent. Use narrow tokens first |
| A permitted GET can carry data out in its query | Shape rules limit which requests pass, not their content |
| `gitPush: "deny"` blocks only the git push endpoint | Pushes can still go through the provider's REST/GraphQL API; add method rules there |
| The agent can read and change the whole project, including `.git` | The project mount is read-write by design |
| Native Claude, Codex, and Pi login state is readable by agent code | Agents need it to log in; it is per project |
| Credentialless operational services (`agent-claude`, `agent-codex`) are open to any process in the agent | The user confirms them at launch; they carry no proxy credential |
| Project image builds run before the sandbox exists | The build uses host Docker networking; review Dockerfiles and wide contexts (`runfree image approve-context`) |
| `mcp enable` discovery tells the named host that you ran it (your IP and the time) | It asks first for project entries and sends no credentials; `--no-discover` makes no call |
| An `--oauth-host` host is allowed like `host add`, and a request rule path prefix also admits sub-paths the proxy does not mediate (for example `/oauth/token/`) | The user named the host; discovered hosts get exact-endpoint rules, and a sub-path or an unrecorded endpoint still follows write approval |
| Login, refresh, and client registration at a recorded, mediated endpoint run without approval | The issuer was reviewed at `mcp enable`; bodies are limited to the protocol's own fields and 16 KiB, responses become handles, and each server gets 30 a minute. The agent can still register a client with a loopback redirect or send its own authorization code |
| Audit mode allows non-listed hosts for a time window | It is explicit (`up --audit-network`) and never edits policy |
| Audited WSS upgrades pass configured credential headers as-is | The WebSocket passthrough cannot rewrite upgrade headers; enforce mode is not affected |
| Checkout binding cannot tell apart volumes mounted at the same path | It is a scope key, not an authority; see [Checkout Binding](architecture.md#checkout-binding) |
| A helper container can be created after the CLI dies | It stays in `created` state with no network; see [Ephemeral Helpers](architecture.md#ephemeral-helpers) |
| Helper cleanup selects containers by label | Only a Docker-socket holder can mint the labels; the agent has none |
| A same-host writer can mint Runfree labels on a pinned-image container | That needs Docker socket access; the Docker daemon is trusted |
| VNC viewers parse display data from the agent | Use a maintained viewer and the default random password |
| Transitive apt packages in runtime images can drift | The lock pins direct packages, but the apt sources are live archives |
| Homebrew installs trust the tap formula and release assets | Use fully qualified installs; check checksums for script installs |

Approving a write, allowing a broad host, or adding a credential gives the
agent real power upstream. Treat each one as a security decision.

## Platform Status

The only supported host is Apple Silicon macOS with Docker Desktop. The only
release artifact is `darwin-arm64`. Intel macOS and Linux can work, but they
are not supported. OrbStack is not tested or supported.

## Verification

For every change:

```bash
pnpm check
pnpm typecheck
pnpm test
```

For security-sensitive changes, also run `make test-security` (focused unit
tests).

For Docker, proxy, firewall, mount, credential, CA, token, MCP runtime, or
sandbox changes, also run on a Docker host:

```bash
make test-runtime-core   # trust-boundary live proofs
```

Before a release, run the full `make test-runtime` (core and extended).

Security tests must prove the rejection happens **before** the side effect:
before DNS lookup, upstream connect, credential injection, policy change, or
file write. Each new fail-closed refusal needs a test for the refusal and a
test for its recovery path.
