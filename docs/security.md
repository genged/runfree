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
| Configures a loopback HTTP MCP (`http://127.0.0.1:<port>`) on an unapproved port | no host reach | proxy name and port pair check; uid 1001-only firewall rule |
| Gives a loopback HTTP MCP a header, helper, or OAuth setting | entry skipped | loopback MCP config allowlist |
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
2. Hosts are exact names. No wildcards, and no IP literals; an IP-literal
   CONNECT host is never audit-passed.
3. The root firewall allows traffic to a destination only if it is in the DNS
   allow set built from the same policy generation as the request proxy, or
   is an approved host-service pair (rule 6). Input to the proxy port `:8080`
   is accepted only from the admitted session set. Output is default drop
   except loopback, established flows, and TCP 443 to the allowed (and, in
   audit mode, audited) sets on the egress interface. Uid 1001 DNS on port 53
   is rejected before Docker's DNS rewrite, and IPv6 is loopback only. The
   supervisor drops loopback, private, link-local, CGNAT, documentation,
   benchmark, multicast, reserved, broadcast, and runtime-subnet DNS answers;
   the request proxy answers `dns.lookup` only from the supervisor's snapshot
   and does no DNS of its own.
4. Denied CONNECT requests get feedback in the tunnel: a denied 443 CONNECT
   gets one static `blocked.invalid` certificate and a synthetic 403. At most
   32 denied tunnels run at once and idle ones close after 5 s; past that cap,
   and for any non-443 CONNECT other than an exact approved host-service pair,
   the answer is a raw pre-TLS 403. Denials go to `runfree doctor`;
   `proxy-denial:` events are coalesced to 10 per minute per host and reason.
5. `runfree.internal` and every name under it are reserved. Every hostname
   validator refuses them, and the proxy classifies them first, on every
   port and in every mode, before any DNS lookup, audit spool write, or dial.
6. **Host services are opaque TCP tunnels** to the host's loopback, approved
   per exact name and port. Adding one, or changing its port or target,
   always needs host review; only a removal applies without it. No request
   rules, write approval, or credential injection apply inside them.
   - Only the request proxy's uid 1001 can reach the pinned gateway's
     approved pairs; root and the agent get no path to them. The gateway comes
     from the daemon's `extra_hosts` entry, never from DNS, never enters the
     DNS allow set, and must be one private (RFC 1918) IPv4 address that is
     not loopback, link-local, a runtime subnet, or a proxy address. Until a
     valid gateway is read, and while the firewall cannot update its
     host-service sets, host services refuse with a named cause.
   - A removal, gateway change, or withdrawn gateway is cut by two independent
     consumers: the request proxy destroys open splices, and the firewall
     drops every packet, from any uid, to a gateway it pinned on a pair that is
     not currently approved, above the established accept, for the
     supervisor's lifetime.
   - A port is admitted (a visible listener on `127.0.0.1` or `*`, not Docker
     Desktop) on every host approval path. A dial that fails or takes more
     than 5 s is refused before the proxy answers 200. Caps: 32 splices per
     session, 256 in all, 64 pending dials; a refusal at a cap clears as
     splices close. If the in-session relay cannot bind an approved port, it
     skips that service with a warning and the session still starts; a later
     process that wants the port gets `EADDRINUSE`.
   - Each launch proves the proxy's host-gateway entry and that the
     firewall's host-service pairs equal the effective policy. A full
     validation also proves that the agent cannot reach the gateway, that root
     in the proxy cannot reach an approved port, and that the request proxy
     cannot reach an unapproved one.

   Mechanism: [Host Services](architecture.md#host-services).
7. **Request shape fails closed.** On method-ruled hosts, and on any host
   whose write action is not `allow`, the proxy strips
   `X-HTTP-Method-Override`, `X-HTTP-Method`, and `X-Method-Override`. On
   path-ruled hosts the path is decoded up to five times, and an encoded dot,
   slash, or backslash, a literal `\`, `//`, `..`, `..;param`, or a malformed
   encoding fails closed. WebSocket upgrades are checked as GET. Denials carry
   `x-runfree-blocked: method-not-allowed`, `path-not-allowed`,
   `git-push-denied`, `write-denied`, or a `write-approval-*` reason.
8. **Audit mode is bounded.** It defaults to 60 min, at most 8 h, and is
   HTTPS-only and 443-only; shape rules and write classification do not
   apply to audited hosts. The host writes the audit marker with a root
   `docker exec` into a root-owned directory, and the request proxy and
   firewall share one clamp, `min(expiresAt, min(enabledAt, proxyNow) + 8h)`,
   so a skewed clock cannot extend it. Audited addresses go to `audit_ipv4`
   (256 by default). At expiry or `audit off`, audited addresses not also
   allowed move to `audit_draining_ipv4`, whose drop rule sits above the
   established accept, so in-flight audited uploads are cut.
9. **The request proxy holds no privilege.** The proxy container adds
   `NET_ADMIN` and drops `NET_RAW`. The root entrypoint starts the request
   proxy via `setpriv` as uid/gid 1001 with no supplementary groups, no
   inheritable or ambient capabilities, `NET_ADMIN`/`NET_RAW` removed from the
   bounding set, and `no_new_privs`, and checks this at runtime. If the Docker
   backend makes the internal interface the default route, the entrypoint
   replaces it with the egress gateway, and the host verifies the route.

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
   only maps keyed by name (hosts, tokens) take arbitrary keys. Desired
   policy version 1 is refused, not converted.
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
   prepared runtime exists. Prepared values must be admitted within 120 s of
   preparation and used within a further 120 s. No source is read while the
   lifecycle lock is held. Before committing, startup recaptures
   configuration, approval, image identities, and the effective selection;
   credential admission recaptures the required source set and named-source
   fingerprints before any proxy disruption; and each credential write
   rechecks the exact proxy, token-store generation, effective policy, and
   pending recovery receipt.
4. **A held value is reused only while provably current.** A warm launch may
   reuse a proxy-held value without re-reading its source only under a
   current host receipt whose last read is under 15 minutes old; the launch's
   watcher re-reads every source right after the launch, and
   `runfree credential sync` always re-reads. A definitive read failure (the
   source was revoked at its origin) drops the value. A transient or
   unclassified failure (a locked vault, a prompt the watcher cannot show)
   keeps it, bounded by the keep-last-good age. Stopping a read (session exit,
   Ctrl-C, or another signal) is never a failure: nothing more is written,
   removed, or recorded. A write replaces the held value only when the whole
   value arrived, and a write with an unknown outcome (its client was killed)
   never removes the token. A deferred sync under a launch's lock follows
   [Lifecycle](#lifecycle) rule 10.
5. The proxy CA private key is mounted only into the proxy.

### Git Over HTTPS

The `github` service (revision 3) adds two Basic destinations on
`github.com`: `protocol: "git-http"` for git smart HTTP and
`protocol: "git-lfs"` for the Git LFS batch and lock API. The `gitlab` service
(revision 2) adds only the `git-http` one on `gitlab.com`; Git LFS is not
mediated there (rule 6). Commands and the supported remote forms are in
[Git over HTTPS and SSH remotes](cli.md#git-over-https-and-ssh-remotes). New
`protocol` scopes are added only for public wire protocols the proxy can
recognize reliably; a vendor's own endpoints use a path prefix or a request
rule instead.

1. **Token reach covers git.** The `github` token is injected on
   `api.github.com`, `raw.githubusercontent.com`, and git smart HTTP and Git
   LFS on `github.com`; the `gitlab` token on `gitlab.com/api/` and git smart
   HTTP. Both reach every repository the token can access, so use a
   fine-grained token limited to the repositories the agent needs. The
   `protocol` scope limits which requests carry the token, not which
   repositories: `api.github.com` still carries the `github` token on every
   path.
2. **An approved push succeeds.** A push that write approval allows goes out
   with your token, so approving a git push is a real decision. Write
   approval is the effective control. The default write posture is `ask`;
   `--deny-git-push` refuses pushes before any connection or token read.
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
4. **Agent `Authorization` is removed on `github.com`.** It is stripped on
   every `github.com` path and replaced on git requests, as on every host
   with a credential destination. One exception,
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
7. **GitLab forwards anonymously without a token.** With no `gitlab` token
   stored, `gitlab.com` requests, `/api/` included, go out with
   `Authorization` stripped, so public clones work and private calls get 401.
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
  `protocol`, or two destinations for one host and header. Releases without
  version 3 refuse such a file (`version must be 2`), so they cannot drop a
  `protocol` scope and inject on the whole host. Any other file stays version
  2, with an unchanged digest.
- An effective policy generation is published only to a proxy of the same
  build. Policy commands compare the running proxy's image-input label (a
  missing label counts as another build) with the proxy this CLI embeds; on a
  mismatch they either replace the proxy compatibly before publishing or save
  the change unapplied and name the remedy (see
  [troubleshooting.md](troubleshooting.md)).
- The identity check is not serialized with a concurrent runtime start by
  another build, and a runtime start that publishes approved policy beside
  live sessions can let an older-release proxy read the new effective policy
  generation. Every older reader refuses one that uses the new fields (the
  digest it recomputes does not match the manifest) and keeps its last valid
  policy. The cost is availability, not authority.
- Older releases cannot read project-image build-context approval records; a
  downgrade needs re-approval.

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
   claims it. Only the host writes these files. The parse refuses an unknown
   or missing key, a file name that is not the embedded session key, a
   payload over 8 KiB, and a lease end more than five minutes after the
   authorizing inspection. Each write proves the parent directory is
   root-owned and not group- or other-writable, and does not follow links;
   the root firewall checks the file's owner uid, not its gid.
2. **No write without inspection.** Each write comes from a Docker inspection
   in the same call. A proven identity mismatch deletes the file at once. An
   inspection that fails deletes nothing.
3. **Bounded lease.** A host that stops writing loses the session within the
   five-minute maximum lease, on the proxy's own clocks. The heartbeat
   cadence stays at or below one third of the lease, so a guest clock skew of
   up to the lease minus the cadence still serves sessions.
4. **Both consumers read the same files.** The firewall and the request proxy
   decide on their own, with the same rule. Neither trusts the other.
5. **No IP reuse without a fence.** Before a new container gets an old IP,
   the host proves both consumers dropped the old owner and the kernel has no
   old sockets. The fence executor holds a kernel lock on the root-owned
   assignment directory and requires the assignment to still match the exact
   bytes the host read, so a delayed executor cannot replace a later
   assignment; a lock timeout refuses creation, and a retry is safe. A launch
   that took over startup's lock compares against what startup read under
   that lock and proxy instance. During the fence the request proxy keeps
   destroying sockets from draining addresses (Linux can keep unaccepted
   sockets after the kill), and the host retries the zero-sockets query until
   its deadline; the ingress listener binds IPv4 so that query covers it, and
   TIME_WAIT entries carry no stream and do not block reuse. See
   [IP Reuse Fence](architecture.md#ip-reuse-fence).
6. **Fail closed on contradiction.** Two files for one IP, wrong bindings, a
   bad file, or a name/key mismatch: nobody involved is served.
7. **Peers never touch a live owner.** Reconcile acts only on records whose
   owner process is proven dead. Unknown means keep.
8. **Revoke file first, record last.** The record reserves the IP, so it goes
   last. A failed file delete stops teardown.
9. **Heartbeats never kill the agent.** They control only the session file.
10. **Unreadable is never empty.** A warm launch skips the startup reconcile
    only when every listing it relies on reads empty; a listing that fails,
    times out, or has a malformed row reconciles. The warm-empty result is
    single-use and bound to one proxy instance and lock holder; a copy, a
    second use, or a mismatch runs full preflight. Startup hands its lock to
    admission only after a credential sync that read no source under the lock
    and a startup that finished quickly; `runfree up` and `runfree resume`
    never hand off.
11. **Warm evidence never restores or renews a peer.** A warm launch beside
    live sessions skips the restore only when every peer is accounted for in
    one proxy incarnation; a peer owner proved neither alive nor dead is a
    miss, and the launch validates fully. A peer whose owner dies afterwards
    keeps access only until its session file expires and reconcile tears it
    down.
12. **Addresses are allocated only from the session pool.** Session
    addresses start at `.20`, bounded by the session-concurrency cap; `.10` is
    the proxy and `.11`/`.12` are reserved. A container on a low reserved
    address is an unknown participant and fails allocation closed. The
    deny-probe helper takes a pinned address from `.13`–`.19`, skipping the
    proxy, agent, callback, gateway, and attached addresses; when that block
    is exhausted the probes fail as not run. The
    session-file publisher and the IP fence refuse any address outside the
    pool. Every address a well-formed session file names is reserved, and a
    session-file listing the host cannot read refuses the launch.
13. **Re-attach is bounded but never ends a session.** When the attached
    stream ends while the same incarnation still runs, the driver re-attaches
    at most three times in a rolling 60 s window; reaching the cap does not
    end the session.

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
6. **Holds are bounded and host-decided.** A hold lasts
   `runtime.writeApprovalHoldSeconds` (default 120 s, range 5–300 s), at most
   16 at once. Without an attached approver (a root-owned heartbeat under
   45 s old for the current approval epoch) the answer is an immediate 403.
   Pending records live in a uid-1001 0700 directory; decision files, control
   files, and the approver heartbeat must be root-owned and are written by
   the host with a root `docker exec`. Approval ids are single-use, an
   approved request re-runs the full policy check, and a policy change
   cancels holds that no longer pass.

Details: [Write Approval Grants](architecture.md#write-approval-grants).

### MCP

1. Project entries from `.mcp.json` and `.codex/config.toml` load only after
   `runfree mcp enable`.
2. Claude gets a read-only approved config with strict MCP mode. This stops
   passive project descriptors at startup. It does not stop code already
   running in the agent from starting another binary or config.
3. Static headers need a host-owned credential source. An HTTPS MCP endpoint,
   OAuth metadata URL, and OAuth token endpoint must name a hostname; an entry
   where any of them names an IP address is skipped. An OAuth metadata URL or
   token endpoint that is not `https:` is skipped too, because it would send the
   OAuth exchange outside the proxy's mediation.
4. HTTPS MCP tool calls follow the write-approval rules (`runfree mcp rules`).
   STDIO MCP servers and loopback HTTP MCP servers (`http://127.0.0.1:<port>`)
   do not pass the proxy, so write approval does not apply and `runfree mcp
   rules` refuses them. A loopback entry carries no credentials or OAuth and
   adds nothing to policy: a header, helper, or OAuth key skips it. Whether
   its port reaches the host is decided only by `runfree host-service add`.
5. No imported MCP descriptor starts a host process. Local STDIO commands run
   only in the agent container; a host-path command is skipped. Codex Desktop
   built-ins (`node_repl`, `computer-use`) are skipped and never enter the
   generated agent config. Only their exact app-bundled commands identify
   them; any other entry, even one with the same name, keeps the normal STDIO
   rules.
6. **Each session owns its OAuth callback path.** When an approved MCP server
   can use OAuth, every session gets its own loopback port, forwarder, and
   in-session bridge before it starts. The forwarder is bound to that session
   and removed before the session's record releases its address, and before
   an orphan session container that no record claims is removed. The bridge
   accepts only its forwarder. The port is a routing value, not an
   authorization secret: the client keeps state, PKCE, and issuer checks.
7. `runfree mcp enable` adds OAuth hosts only after one host-side review, and
   only when valid metadata names a token endpoint the proxy mediates for
   that server. Discovery of a project-named host runs only after the user
   agrees on a terminal: plain HTTPS GETs from the host, with no credentials,
   cookies, proxy, or redirects, to public, checked addresses over a pinned
   connection, with strict time and size limits. Unless something else allows
   it, a discovered host is limited to GET, HEAD, OPTIONS, and POST on paths
   under `/.well-known` or its recorded OAuth endpoint paths. The browser
   sign-in page opens on the host and is never allowlisted. The hosts live in
   host-owned state, not desired policy, stop applying when the reviewed
   server config changes, and `runfree mcp revoke` removes exactly them. A
   damaged record grants nothing. An endpoint that two servers record is not
   mediated statically for either and follows write approval.
8. **Revoke clears the proxy's OAuth state for the server.** It saves a new
   state epoch for the server (see [MCP Model](architecture.md#mcp-model));
   the proxy refuses a stale handle at use and blocks, not stores, a token
   response from an exchange that started before the revoke. With no proxy
   running, the clear happens at the next start. Revoke says "cleared" only
   when the running proxy confirmed the exact policy generation. A damaged or
   missing epoch record clears the OAuth state of every MCP server. A rotated
   refresh token retires the handle it replaced. Each server keeps at most
   256 token handles and 32 registration handles, evicting expired access
   handles first and never the newest refresh handle; past 1024 exchanges in
   flight, a new one is refused rather than evicting another.
9. **Protocol reads are exact.** On an `ask` host, a POST is a read, with no
   approval, only when its exact path (no normalization, query, or encoding)
   is a token or registration endpoint that `mcp enable` recorded for one
   server, the proxy mediates it for that server alone, and the body is a
   plain login, refresh, or loopback-only client registration with no field
   an issuer may fetch at a URL the agent chose: a URL-valued `client_id`
   must equal, byte for byte, a pinned agent client metadata URL (Claude
   Code's or Codex's published document), and no `resource` may name another
   host. The body must be identity-encoded and declare its length, at most
   16 KiB. Each server gets at most 30 a minute, counted only for requests that
   pass every other check. The live `mcp-enable` tranche checks that each
   pinned client metadata URL appears in the pinned agent binary, so a vendor
   change fails the gate. Everything else
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
4. **Docker's init is PID 1, not a boundary.** Session containers run with
   `--init`. The init runs as the same uid 1000 with the same capabilities
   and `no-new-privileges`, so the agent gains nothing by reaching it. Its
   bind mount is added by the daemon and is outside the inspection proof. A
   project image can make PID 1 something else, which costs only the fast
   stop. Project `TINI_*` variables are honored; none changes identity,
   capabilities, mounts, or network. Downgrading Runfree while sessions from
   a newer release are live is not supported: run `runfree destroy --force`
   first.
5. The agent trusts the proxy CA through a bundle an ephemeral helper renders
   into the read-only `/etc/proxy-ca` mount (`SSL_CERT_FILE`,
   `NODE_EXTRA_CA_CERTS`, and similar point at it), so the agent never needs
   root to install trust.

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
   - `rebuild` and `destroy` revoke first and release last: records become
     revoking, the session files leave the still-running proxy, then the
     proxy, session containers, and Compose resources go, and only then the
     runtime selection, pending rebind, and records. A session's file always
     leaves the proxy before the record that reserves its address. Each step
     is durable before the next, so an interrupted run resumes.
   - Forced `destroy` skips the strict utility-ownership check, so malformed
     utility leftovers cannot block its sweep of project-labeled containers,
     but it still removes only the exact Docker IDs it found. Leftover session
     volumes go only when they carry this project's exact label and name,
     never forced. The ingress bridge goes only if it carries Runfree's
     ownership labels, its full network ID is exact, and Docker proves it has
     no endpoints.
   - Ingress forwarder teardown needs this project's exact project label, the
     expected role label, an inspected image ID equal to Docker's resolved ID
     for the pinned ingress image, and removal by the inspected full container
     ID. A foreign-labeled bridge lookalike is refused with no Docker
     mutation, and partial or conflicting labels are always refused. A new
     bridge is inspected for its full local-bridge shape before a listener
     starts, and every endpoint is validated before a forwarder or the bridge
     is removed.
4. `runfree stop` and `runtime reload-policy` need `--force` while live or
   unknown sessions, a pending rebind, or an interrupted teardown exist. A
   reload of the same proxy container republishes eligibility and re-proves
   every surviving session; when no record can still hold authority, it
   proves the firewall's session set empty from the live kernel set before
   reporting success.
5. A start finishes an interrupted teardown only on Docker's proof: the owner
   is dead, the session container is absent or stopped, and no proxy can
   serve the session file. The record goes only after Docker proves the
   container absent. Anything Docker cannot prove keeps the record and refuses
   with the reason and its remedy. Plain `destroy`'s record scan skips
   records with a terminal status stamp (interrupted teardowns);
   `destroy --force` reclaims one whose owner cannot be proved dead.
6. Every Docker call a launch started settles before cleanup or lock release.
   When one step fails while another, such as the callback reservation, is
   still running, the launch waits for it under the lifecycle lock before it
   removes anything or releases the lock.
7. **Lock holds are bounded.** Other commands wait up to one minute for the
   lifecycle lock. A launch plans its continuous hold at 50 s or less,
   including a wait of at most 10 s for the session entry to hand off to the
   agent. Fault paths (the IP fence, a slow first session-file write, cleanup
   after a failed admission, or a hung Docker call) can run past the minute;
   a waiting command then defers with a retry instruction, and nothing is
   admitted or removed on its behalf. If the handoff wait ends first, a proxy
   replacement can land before the agent starts, and the entry falls back to
   its own timeout. Startup and explicit reload bound held subprocess work to
   90 s per lock span (shared with heartbeat adoption) and refuse lock
   acquisition after about 60 s. These are refusal limits, not restoration
   guarantees: host suspension and filesystem stalls can exceed them.
   Heartbeat adoption's lock-priority tickets grant no lease and no lock
   ownership; a clock change cannot discard a live or unknown requester's
   priority, and an aged ticket is reclaimed automatically only on proved
   requester death.
8. **A session that is never activated stops itself.** If the session entry
   does not see the proxy report the session active within 60 s, it exits
   111; the launch exits 111 and normal teardown removes the session.
9. **The short teardown after a normal exit needs exact proof.** After the
   agent exits with a code, the owner skips the network disconnect and stop
   only when one inspection shows the same container and start time, exited
   with that code, not restarting or paused, with restart policy `no`. Any
   other answer, and every reconcile, runs the full revoke.
10. **A deferred credential sync removes nothing.** When a launch's locked
    credential sync defers (stale or changed preparation, busy lock, proxy not
    ready, failed write, or spent allowance), it removes no proxy credential
    and writes no receipt; the ordinary sync runs after the lock is released.
    If neither the session-file delete nor the terminal stamp succeeds, the
    record is marked revoking, so peers never read it as a live session.
11. **Proxy recovery is bounded and checked.** Compatible-replacement
    recovery shares one project-wide allowance of 120 s and at most two proxy
    creations, which ordinary launches cannot reset
    (`runtime recover --retry` grants a new one). A stopped owned candidate is
    removed only after exact inspection. Candidate creation checks the
    retained network, the CA certificate and key identity, and the exact
    project OAuth volume before mounting them into the approved proxy image.
    Containment refuses a container whose ID looks right but lacks this
    project's id, container-role, and Compose project and service labels.
12. **Ephemeral helpers are bounded.** Helpers run with `--pull never`; the
    Docker client is killed at 30 s for the deny probes and 120 s for other
    helpers, or earlier if the lifecycle budget is shorter. The helper sweep
    runs under the lock, bounded at about 15 s plus up to 2 s for the last
    listing. A listing that fails or times out never counts as empty, and an
    unconfirmed sweep refuses, naming `runfree up` and
    `runfree destroy --force`. See
    [Ephemeral Helpers](architecture.md#ephemeral-helpers).

## What Runfree Does Not Prove

- **Nothing from inside the container.** Session shape is proven by host-side
  `docker inspect` only. That shows what the daemon created, not what the
  process does.
- **Agent-position egress on every launch.** A warm launch whose warm-proof
  fingerprint matches does not re-run the agent-position deny probes, the
  server-UID denial probes, or the root DNS probe, and beside live peer
  sessions no probe runs per peer; it binds the skipped proof to the proxy
  instance, networks, images, ruleset shape, daemon, and VM boot. A
  fingerprint is recorded only when the following reconcile found nothing to
  repair, any restore of surviving sessions finished, the proxy did not
  restart, and no ephemeral helper is attached; `stop`, `destroy`, and
  `rebuild` delete it. A warm proof older than 24 hours never matches, and a
  Docker daemon with live-restore enabled always validates fully.
  `runfree up` always runs every probe.
- **Docker command lines outside the client module.** The static check that
  keeps Docker command lines in one module sees only literal `docker` strings
  outside its reviewed allowlist. It does not see command lines built from a
  parameter, or new ones added inside an allowlisted file.
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
- **A loopback MCP server reached through a host service runs on the host.**
  When an approved host service holds the port of a loopback HTTP MCP entry,
  the agent's tool calls run in that host process, outside the sandbox, and
  no write approval applies. Reach is evaluated at each launch and review,
  not pinned by the MCP approval digest: a later `runfree host-service add` on
  the same port makes an approved, container-local entry reach the host. An
  OAuth flow that a loopback server advertises at run time is not mediated;
  its tokens land in the agent's own state.

Accepted, known risks:

| Risk | Why it remains |
| --- | --- |
| Allowed hosts can be misused within their token scope | Runfree checks host, method, and path, not intent. Use narrow tokens first |
| A permitted GET can carry data out in its query | Shape rules limit which requests pass, not their content |
| `gitPush: "deny"` blocks only the git push endpoint | Pushes can still go through the provider's REST/GraphQL API; add method rules there |
| The `github` and `gitlab` tokens reach git on every repository they can access | Use fine-grained tokens and keep pushes under `ask` ([Git rule 1](#git-over-https)) |
| An agent `Basic` value with a handle-shaped password passes the `Authorization` strip | It is the agent's own value; no token is injected (Git rule 4) |
| Git LFS action credentials from `github.com` reach the agent | Server-issued, not the stored token; scope and lifetime unverified (Git rule 6) |
| Git LFS on `gitlab.com` is not mediated | Its batch token can push, so batches there are credentialless writes (Git rule 6) |
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
| A helper container can be created after the CLI dies | After a killed Docker client the helper marker is kept for 180 s and every lock holder in that window sweeps again, but an orphaned `docker run` client of a dead CLI has no timeout and can start the helper later. The firewall drops that unadmitted source, and a later deny probe that needs its address fails closed. A wall-clock jump can end the window early; `destroy` clears the marker, and a container created after that needs `runfree destroy --force` |
| A concurrent helper sweep can fail another CLI's in-progress build | A project Dockerfile can put the helper labels on legacy-builder intermediate containers; BuildKit, the default, creates none |
| Helper cleanup selects containers by label | Only a Docker-socket holder can mint the labels; the agent has none |
| A same-host writer can mint Runfree labels on a pinned-image container | That needs Docker socket access; the Docker daemon is trusted |
| Content served through `runfree forward` renders in the user's unsandboxed browser, outside the proxy | Treat it as untrusted agent output |
| VNC viewers parse display data from the agent | Use a maintained viewer and the default random password |
| Transitive apt packages in runtime images can drift | The runtime inputs lock pins base images by digest, exact direct apt package versions, and release artifact checksums (a missing or malformed lock fails before any build), but the apt sources are live archives |
| Homebrew installs trust the tap formula and release assets | Use fully qualified installs; check checksums for script installs |
| A host-service tunnel is opaque | No content audit, request rules, or write approval apply inside it; approve only services you would let the agent use freely |
| An approved host service's own authentication and bugs are reachable from the agent | Every session in the project gets whatever the approved service allows its clients to do, for example full read and write on a local database or full control of a device bridge |
| Host-service access is per project, not per session | Approval persists like an allowed host and applies to every session of the project |
| Whatever holds an approved port on the host's loopback is reachable | If the approved service stops and another process takes the port, the agent reaches that process. The gateway reaches every host loopback listener, including root services, IDE servers, and other containers' published ports; the refused ports and the owner check at approval cover only the known dangerous cases. A root-owned listener is invisible to the unprivileged `lsof`, so it is refused only as "no visible listener", never identified |
| A publication that appears on an approved port mid-session stays reachable; the next launch or `runfree status` only warns | Another project's `forward` and `vnc` refuse registered ports. A third-party publication on an approved port is reported by the next launch or `runfree status` owner check, which warns but neither refuses nor cuts |
| A host gateway address change, or a withdrawn gateway, stops host services until `runfree rebuild` | Both consumers cut at once ([Network](#network) rule 6); new CONNECTs refuse with the named cause; `runfree rebuild` re-pins and drains every session |
| The permanent firewall cut covers only gateways pinned by the running supervisor | The pinned set is in memory; a proxy restart forgets it but also recreates the whole table, so no earlier flow survives |
| Host-service splices have no idle timeout | Both legs use TCP keepalive, so a dead peer is found, but an idle open splice stays open until either side or a removal closes it |
| Two `runfree mcp revoke` runs at the same moment, with no proxy running, can lose one clear | The epoch store has no lock; run that revoke again |
| New host-service CONNECTs refuse for about 2 s after any policy reload | The request proxy dials only when the gateway file names its current effective policy generation; until the supervisor republishes the file on its next maintenance pass, a new CONNECT refuses with `host-service-unavailable`. Open splices are not affected |

Approving a write, allowing a broad host, or adding a credential gives the
agent real power upstream. Treat each one as a security decision.

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
