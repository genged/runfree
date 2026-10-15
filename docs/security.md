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
  That network has no internet route. Only the proxy is also on
  `proxy_egress`.
- Ingress forwarders (VNC, `runfree forward`, MCP OAuth callback) connect the
  host loopback to a session. They are one-way transport, not an authority
  boundary. See [Utility Participants](architecture.md#utility-participants).
- Host services carry the agent to an approved port on the host's loopback.
  The session relay holds no authority: the proxy admits only an exact
  approved `<name>.runfree.internal:<port>` pair and splices it to the pinned
  Docker Desktop gateway, and the firewall lets only the request proxy's
  uid 1001 reach that pair. See [Host Services](architecture.md#host-services).
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
| Dials the host gateway IP directly | no route | `agent_internal` has no egress; uid 1001-only firewall rule |
| POSTs to an allowed host under `ask` | held for a host decision | write approval |
| `git push` to `github.com` or `gitlab.com` with the service's token stored | held under `ask`; once approved, it **succeeds with your token** | write approval; `--deny-git-push` |
| Uses an allowed token for a wrong purpose | **allowed** | token scope and request rules only |
| Runs arbitrary code in the project | **allowed** | bounded by mounts and proxy |
| Writes a fake Claude registry entry or Codex rollout file | labeled, non-default row in its own project's resume picker | sanitized display; never the default cursor or the one question; a resume still goes through normal admission |
| Sets terminal-multiplexer env vars hoping to match a host session | no effect | terminal ids are read only from the host launcher's own environment, never read from or forwarded into the container |

## Core Rules

Each rule says what must stay true. Changes must not break a rule. Links
point to the mechanism.

### Network

1. The proxy checks policy **before** DNS lookup, credential read, OAuth
   mediation, and upstream connect. Plain HTTP, hosts not on the list, raw
   tunnels other than an approved host service, method or path violations,
   and unapproved writes stop there.
2. Hosts are exact names. No wildcards.
3. The root firewall allows traffic to a destination only if it is in the DNS
   allow set built from the same policy generation as the request proxy, or
   is an approved host-service pair (rule 6).
4. Denied CONNECT requests get feedback in the tunnel. Denials go to
   `runfree doctor`.
5. `runfree.internal` and every name under it are reserved. Every hostname
   validator refuses them, and the proxy classifies them first, on every
   port and in every mode, before any DNS lookup, audit spool write, or dial.
6. Host services are opaque TCP tunnels, approved per exact name and port by
   the host. No request rules, write approval, or credential injection apply
   inside them. The firewall allows the pinned gateway and approved port
   pairs to the request proxy's uid 1001 only; root and the agent get no path
   to them. The gateway comes from the daemon's `extra_hosts` entry, never
   from DNS, and never enters the DNS allow set. A removal, and a gateway
   change or withdrawal, is cut by two independent consumers: the request
   proxy destroys open splices immediately, and the firewall drops every
   packet, from any uid, to a gateway it pinned on a pair that is not
   currently approved, above the established-connection accept and with no
   time limit. A port is admitted (a visible listener on `127.0.0.1` or `*`,
   not Docker Desktop) on every host approval path, not only at
   `host-service add`. IP-literal CONNECT hosts are never audit-passed, and
   policy hosts cannot be IP literals.

Order, hardening, and firewall rules:
[Proxy Enforcement Details](architecture.md#proxy-enforcement-details).

### Policy

1. `.runfree/network-policy.json` is desired input. The agent can edit it.
   Its edits do nothing until a host transaction captures, verifies, and
   approves the exact bytes.
2. The proxy never reads the project file. It reads an immutable effective
   generation from a read-only XDG mount.
3. Unknown fields, duplicate keys, oversize input, unsafe paths, and any
   authority growth without exact approval fail closed. The CLI and the proxy
   refuse unknown keys in every object of both desired and effective policy;
   only maps keyed by name (hosts, tokens) take arbitrary keys.
4. A mutation that runs beside live sessions approves the exact candidate it
   re-read under the lock, never a fresh read of the file.
   See [Desired-Policy Mutation](architecture.md#desired-policy-mutation-beside-live-sessions).
5. Invalid or incomplete generations keep the previous effective policy.
6. The project `.runfree/config/agent.env` is ignored. The agent environment
   comes from the selected effective policy generation.
7. A policy an older reader would misread never reaches one. Desired policy
   is version 3 only when it uses a field older releases do not know (see
   [Older Readers](#older-readers)); those releases refuse it. A CLI applies
   policy only to a proxy built from its own embedded assets.

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
   `runfree credential sync` always re-reads. Stopping a read is never a read
   failure: when the session exits, its parent disappears, or Ctrl-C or
   another signal stops the watcher or a one-shot sync, nothing more is
   written, removed or recorded. A write or removal that completed before the
   stop stands, and the receipt and status for it may be stale until the next
   pass. The watcher ends the providers it started (SIGTERM, then SIGKILL
   after 2 s) and starts no further read. A proxy token write replaces the
   held value only when the whole value arrived, and each write uses its own
   temporary file. A write whose client was killed (any signal, or its time
   bound) has an unknown outcome, and the token is not removed for it. An
   ordinary sync drops the token's receipt, so the next sync reads the source
   again. Under a launch's held lock, the launch defers instead: the receipt
   stays as it was, and the launch's fallback source-truth sync writes the
   token again from the value read before the lock.
5. The proxy CA private key is mounted only into the proxy.

### Git Over HTTPS

The `github` service (revision 3) adds two Basic destinations on
`github.com`: `protocol: "git-http"` for git smart HTTP and
`protocol: "git-lfs"` for the Git LFS batch and lock API. The `gitlab` service
(revision 2) adds only the `git-http` one on `gitlab.com`; Git LFS is not
mediated there (rule 6). Commands and the supported remote forms are in
[Git over HTTPS and SSH remotes](cli.md#git-over-https-and-ssh-remotes).

1. **Token reach grows.** The `github` token was injected on
   `api.github.com` and `raw.githubusercontent.com`; the `gitlab` token on
   `gitlab.com/api/`. The `github` token now also reaches git smart HTTP and
   Git LFS, and the `gitlab` token git smart HTTP, on every repository the
   token can access. Use a fine-grained token limited to the
   repositories the agent needs. The `protocol` scope limits which requests
   carry the token, not which repositories: `api.github.com` still carries the
   `github` token on every path.
2. **An approved push succeeds.** Before, a push from the sandbox had no
   credential and failed at the provider. Now a push that write approval
   allows goes out with your token, so approving a git push is a real
   decision. Write approval is the effective control. The default write
   posture is `ask`; `--deny-git-push` refuses pushes before any connection
   or token read.
3. **The credential is attached only to recognized git requests.** The
   request must be one of the listed method and path forms, with no path
   confusion; the raw path and its decoded form must both end with the plain
   endpoint, and the decoded path must hold no NUL. Ref discovery needs
   exactly one `service` query parameter, spelled literally; a parameter whose
   decoded, case-folded name is `service` counts toward that one. These are
   never git requests:
   - a `POST` endpoint (fetch, push, LFS batch, LFS lock) with any query
     string. Git and git-lfs send none, and an origin that merges query
     parameters over the body (GitLab is a Rails application) would act on a
     query the proxy never read, such as `?operation=upload` on a download
     batch;
   - a ref discovery query that contains a `;`. Some origins also split a
     query on `;` and could read a second `service` the proxy never counted.
     Push detection treats such a query as a push;
   - a path whose first segment decodes to `api` in any case, or that has a
     segment that is exactly `-`. GitLab serves its REST API under `/api/`
     and other routes behind `/-/`, where a last segment can be any name
     (`…/repository/files/git-upload-pack` is a file API). A `github.com`
     owner named `api` is excluded too: the matcher does not guess per
     provider. Dots and whitespace at either end of the first segment are
     ignored for this check, so `%20api` and `.api` count as `api`;
   - a path with a segment that starts with whitespace after decoding. An
     origin that trims it could route the request somewhere other than the
     path the matcher read.

   Anything else on the host gets no credential, and its write classification
   is unchanged. A `git-http` destination matches only git smart-HTTP
   requests and a `git-lfs` destination only Git LFS requests; no request is
   both.
4. **Agent `Authorization` is removed on `github.com`.** Before, `github.com`
   had no credential destination, so an agent-supplied `Authorization` went
   upstream. Now it is stripped on every `github.com` path and replaced on git
   requests, as on every host with a credential destination. One exception,
   shared with every such host: a value shaped like a Runfree OAuth handle is
   kept for the OAuth mediator. A `Bearer runfree_oauth_…` value must then be
   a live handle of this project for this resource, or the request is refused
   before any connection. A `Basic` value whose password has the handle shape
   is forwarded unchanged on any path, and no token is injected for that
   request. The stored token is never exposed this way; the agent can only
   send its own value.
5. **Git LFS download batches are reads where LFS is mediated.** The batch
   endpoint takes `POST` for both download and upload. On a host with a git
   handling rule (`gitPush`) and a `git-lfs` destination that matches the
   request, under `ask` or `deny`, a batch request is a read only when the
   proxy proves its body is a download:
   - exactly `POST` on a recognized `…/info/lfs/objects/batch` path, with an
     empty query;
   - one `Content-Type` of `application/vnd.git-lfs+json` (a `charset`, if
     present, must be UTF-8), no content encoding other than identity, and
     one `Content-Length` of at most 64 KiB that equals the body length;
   - a body that decodes as strict UTF-8 with no byte order mark and parses
     as JSON with no duplicate key at any depth;
   - a top-level object with exactly one key that folds to `operation`,
     spelled `operation`, whose value is `"download"`.

   Anything else is a write: an upload, a malformed or oversized body, a
   second `Operation`-like key, a missing length, every `POST` lock request,
   and every batch request on a host with no `git-lfs` destination that
   matches the request path. The `GET` lock listing is a read like any `GET`,
   and on `github.com` it carries the `git-lfs` credential. A held request is
   re-checked without its body, so it stays a write.

   A git handling rule alone does not make a download a read. The built-in
   `bitbucket` service declares one on `bitbucket.org` but has no `git-lfs`
   destination (it has no credential there), so every LFS batch request to
   `bitbucket.org`, a public download included, waits for approval under
   `ask`. The same holds on `gitlab.com` (rule 6) and on any host given a git
   rule by hand, such as with `runfree host rules <host> --deny-git-push`.

   The git fetch exemption is narrow in the same way: only `POST` on a
   recognized `…/git-upload-pack` path, with at least one repository segment
   before it, an empty query, and none of the excluded paths in rule 3, is a
   read.
6. **Object transfer credentials reach the agent; Git LFS on `gitlab.com` is
   not mediated.** A batch response gives per-object action URLs and may give
   headers with credentials issued by the provider. They pass to the agent
   unchanged, and they are not the stored token. Runfree accepts GitHub's as
   server-issued; their exact scope and lifetime are not verified. GitLab's
   answer to a user's batch request carries `Authorization: Basic` with a
   project-wide LFS token that is valid for hours and can push. Had the
   download batch been a read, the agent could have taken that token without
   approval and pushed from outside the sandbox, past write approval and
   `--deny-git-push`. So the `gitlab` service has no `git-lfs` destination:
   an LFS request to `gitlab.com` gets no credential, every batch request
   there is a write, and a private GitLab LFS fetch fails. The transfer
   itself goes to the action host and follows that host's policy; on a host
   with an `Authorization` destination, an agent-sent `Authorization` is
   stripped there like any other.
7. **GitLab forwards anonymously without a token.** The `gitlab` token now
   allows anonymous forwarding, as `github` already did. With no token stored,
   `gitlab.com` requests go out with `Authorization` stripped, so public
   clones work. This is per token: `/api/` requests with no token also go out
   anonymously instead of being refused, and GitLab answers private calls
   with 401.
8. **Redirects are not followed.** The proxy passes a redirect response to
   the agent unchanged. Git follows it as a new proxied request, which gets
   the credentials of the new host's policy, if any. The injected value never
   reaches the agent, so the agent cannot carry it to another host.
9. **The protocol tier is host-wide.** When any `protocol` destination of a
   host matches a request, only `protocol` destinations are injected on it.
   A destination without `protocol` on another header of the same host is
   not injected on a recognized git request.
10. **Changes to a host with several destinations need approval.** The proxy
    picks a destination per host, so on a host with more than one
    credential destination, narrowing, scoping, or removing one of them can
    make another token's destination win for requests that used to get the
    changed one. Any change to such a host's destinations therefore needs
    host approval; removing every destination of the host still applies
    without review. Scoping a destination to `git-lfs` also needs approval,
    because it turns on the LFS download read rule for that host.

The SSH-to-HTTPS rewrite in the sandbox Git config is routing, not
enforcement. The agent can remove it; SSH still has no route out.

### Older Readers

A newer policy can meet an older reader: a teammate's older CLI reading the
committed `.runfree/network-policy.json`, a downgraded CLI, or, after an
upgrade, a proxy still running the previous build.

- Desired policy becomes version 3 only when it uses `basic`, `username`,
  `protocol`, or two destinations for one host and header. Runfree releases
  without version 3 refuse such a file with `version must be 2`, so they
  cannot drop a `protocol` scope and inject on the whole host. A file without
  those fields stays version 2, with an unchanged digest.
- An effective policy generation is published only to a proxy of the same
  build. Before it publishes and selects an effective policy generation, a
  policy command (`host`, `host-service`, `credential`, `service`, `mcp`, and
  `policy use-approved`) compares the running proxy's image-input label with
  the proxy this CLI embeds. A
  missing label counts as another build. On a mismatch:
  - if the runtime can be replaced compatibly, the command prints that
    running sessions lose network access for up to one heartbeat (30 s) plus
    adoption, replaces the proxy as `runfree up` does, then applies the
    change; a failed replacement stops with the change saved but not applied;
  - if active sessions use an incompatible admission epoch or control-plane
    topology, the change is saved and reported as not applied, with the
    remedy: wait for the sessions to end, then `runfree policy use-approved`,
    or `runfree rebuild` now;
  - a session launch beside live sessions never replaces the proxy; it
    reports the change as waiting and names `runfree up`, then
    `runfree policy use-approved`.

  If a proxy of another build appears while the effective policy generation is published, the
  previous selection is restored and the command fails, asking for a retry.
- Runtime startup does not use this check. A normal start beside live
  sessions joins their effective policy generation and publishes nothing,
  but a start that publishes approved policy beside live sessions can let a
  proxy from an older release read the new effective policy generation. Such
  a proxy refuses an effective policy generation that uses the new fields,
  because the digest it recomputes does not match the published manifest, and it keeps its last
  valid policy. The cost is availability, not authority.

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
10. **A skipped reconcile needs absolute evidence.** A warm launch skips the
    startup reconcile only when an empty session-file listing, the internal
    network's participants, an empty lifecycle registry, and one host-wide
    container listing all show no session state. Unreadable is never empty:
    a listing that fails, times out, or has a malformed row reconciles.
11. **A skipped restore needs every peer accounted for.** A warm launch beside
    live sessions skips the restore of surviving sessions only after an exact
    judgement that every peer and every internal-network participant is
    accounted for in one proxy incarnation, and only while that sealed,
    one-shot judgement still binds after a startup reconcile that found
    nothing to repair. Otherwise the launch refuses and the retry validates
    fully. Warm evidence never restores, republishes, or renews a peer.

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
   `runfree mcp enable`.
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
   registry, Codex rollout and session-index files) as hostile input. Which
   directory it opens is fixed (the Claude registry) or computed only from
   the host's own session timestamps (a Codex day directory); it never
   discovers a directory by listing `sessions/` or any year or month
   directory. Inside every directory it does open, every entry, whether or
   not its name matches, counts against an entry budget and a time limit;
   entries that match are opened without following links or blocking, and
   count against file and byte budgets. Rows built from it (a
   Claude-registry name, a Codex time-matched thread) are sanitized, labeled
   ("Claude reported", "Codex match"), and never the resume prompt's default
   row or its one-question path.
4. Terminal identifiers used to match a resumable session to the terminal
   that started it (`TERM_SESSION_ID`, `ITERM_SESSION_ID`, `TMUX_PANE`, and
   similar) are captured only from the host launcher's own environment. They
   are never forwarded into a session container's environment.

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
6. Every Docker call a launch started settles before cleanup or lock release.
   When one step fails while another, such as the callback reservation, is
   still running, the launch waits for it under the lifecycle lock before it
   removes anything or releases the lock.

## What Runfree Does Not Prove

- **Nothing from inside the container.** Session shape is proven by host-side
  `docker inspect` only. That shows what the daemon created, not what the
  process does.
- **Agent-position egress on every launch.** A warm launch whose warm-proof
  fingerprint matches does not re-run the agent-position deny probes, the
  server-UID denial probes, or the root DNS probe. It re-validates the
  topology, capabilities, routes, nftables ruleset, and security contract from
  fresh evidence, and binds the rest to the proxy instance, networks, images,
  ruleset shape, daemon, and VM boot. The probes are skipped the same way
  beside live peer sessions: no probe runs per peer. Instead each peer is
  re-proved by its own running proof over a fresh inspect (capabilities
  dropped, one network, its exact address) and by exact agreement of the
  registry, the container inventory, the proxy's session files, the kernel
  session set, the request proxy's generation, and the IP assignments, and any
  participant that is not an accounted peer, a peer's own callback forwarder,
  or a recorded forwarder sends the launch to the full validation. `runfree up`
  always runs every probe.
- **Guest clock lag** is not tested live. The live fixture cannot shift the
  Docker VM clock. The rule that a lagging clock cannot extend a lease has
  unit tests only.
- **Audit set emptiness** in enforce mode is checked only by the proxy's own
  firewall supervisor. The host proof checks set shape, not members.
- **Git provider behavior** is proven only by a gated live tranche that needs
  provider credentials and is not part of `make test-runtime` (see
  [testing.md](testing.md)). That GitHub accepts the token as the Basic
  password with username `x-access-token`, and GitLab with `oauth2`, is
  proven only for the token types that run uses.
- **Older readers** are proven against the frozen policy readers of v0.5.2
  only, replayed as source in a unit test, not by running an old binary.
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
- **Two state roots on one project path share one runtime.** The project id
  and the Compose project come from the project path, so two state roots for
  one path (for example `scripts/dev-runfree.sh` without a scratch
  `--workspace`) share one proxy, one network, and one project id, but each
  has its own lifecycle registry and lock. Either root's reconcile can remove
  the other's session files and containers. A warm-empty skip refuses while
  the other root has a session file in the proxy, a session container, or a
  session on `agent_internal`; it cannot see the other root's records.

Accepted, known risks:

| Risk | Why it remains |
| --- | --- |
| Allowed hosts can be misused within their token scope | Runfree checks host, method, and path, not intent. Use narrow tokens first |
| A permitted GET can carry data out in its query | Shape rules limit which requests pass, not their content |
| `gitPush: "deny"` blocks only the git push endpoint | Pushes can still go through the provider's REST/GraphQL API; add method rules there |
| The `github` and `gitlab` tokens reach git on every repository they can access | `protocol` (`git-http`, `git-lfs`) limits which requests carry them, not which repositories; use fine-grained tokens and keep pushes under `ask` |
| An agent `Basic` value whose password looks like a Runfree OAuth handle passes the `Authorization` strip | It is the agent's own value, and no token is injected for that request; the stored token is not exposed |
| Git LFS action credentials from `github.com` reach the agent | They are issued by GitHub, not the stored token; Runfree accepts them as server-issued and does not verify their scope or lifetime |
| Git LFS on `gitlab.com` is not mediated | GitLab's batch response carries a project-wide LFS token that can push; LFS batch requests there are writes with no credential, so a private GitLab LFS fetch fails |
| A user-defined git host has no git handling rule | Fetches and LFS batches there are writes and wait under `ask`; a push is a plain write, not a git push |
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
| A host-service tunnel is opaque | No content audit, request rules, or write approval apply inside it; approve only services you would let the agent use freely |
| An approved host service's own authentication and bugs are reachable from the agent | Every session in the project gets whatever the approved service allows its clients to do, for example full read and write on a local database or full control of a device bridge |
| Host-service access is per project, not per session | Approval persists like an allowed host and applies to every session of the project |
| Whatever holds an approved port on the host's loopback is reachable | If the approved service stops and another process takes the port, the agent reaches that process. The gateway reaches every host loopback listener, including root services, IDE servers, and other containers' published ports; the refused ports and the owner check at approval cover only the known dangerous cases. A root-owned listener is invisible to the unprivileged `lsof`, so it is refused only as "no visible listener", never identified |
| A publication that appears on an approved port mid-session stays reachable; the next launch or `runfree status` only warns | Another project's `forward` and `vnc` refuse registered ports. A third-party publication on an approved port is reported by the next launch or `runfree status` owner check, which warns but neither refuses nor cuts |
| A host gateway address change, or a withdrawn gateway, stops host services until `runfree rebuild` | Two independent cuts act at once: the request proxy destroys every open splice to the old or withdrawn address, and the firewall drops every flow to a gateway it pinned whose pair is not currently approved, for as long as that holds. New CONNECTs refuse with the named cause; `runfree rebuild` re-pins and drains every session |
| The permanent firewall cut covers only gateways pinned by the running supervisor | The pinned-gateway set is in memory and the ruleset install recreates it empty, so a proxy restart forgets earlier gateways. A restart also recreates the whole table, so no earlier flow is accepted by it; the cut matters only within one supervisor lifetime |
| New host-service CONNECTs refuse for about 2 s after any policy reload | The request proxy dials only when the gateway file names its current effective policy generation; until the supervisor republishes the file on its next maintenance pass, a new CONNECT refuses with `host-service-unavailable`. Open splices are not affected |

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
