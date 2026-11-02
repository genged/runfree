# Security Rules

This page lists the rules that the code must keep. A change must not break a
rule. [security.md](security.md) explains the security model for users. This
page is for reviewers and contributors.

## How to read a rule

Each rule has an ID, such as `GIT-5`, and the same shape:

```text
### GIT-5. The guarantee, in one sentence.

- The facts, one on each line.

Why:      the attack or failure that the rule stops.
Enforced: the function in the code that keeps the rule.
Tests:    where the rule is tested.
```

The rule text gives the guarantee and the limits that a reviewer must know.
The exact checks (parsing, encodings, order of steps) are in the function
that the Enforced line names.

| Topic | Rules |
| --- | --- |
| [Common rules](#common-rules) | `R-1` to `R-3` |
| [Network](#network) | `NET-1` to `NET-9` |
| [Policy](#policy) | `POL-1` to `POL-8` |
| [Credentials](#credentials) | `CRED-1` to `CRED-6` |
| [Git Over HTTPS](#git-over-https) | `GIT-1` to `GIT-10` |
| [Older Readers](#older-readers) | `OLD-1` to `OLD-4` |
| [Sessions](#sessions) | `SESS-1` to `SESS-13` |
| [Write Approval](#write-approval) | `WRITE-1` to `WRITE-8` |
| [MCP](#mcp) | `MCP-1` to `MCP-11` |
| [Agent Container](#agent-container) | `AGENT-1` to `AGENT-5` |
| [Host Files](#host-files) | `FILE-1` to `FILE-5` |
| [Lifecycle](#lifecycle) | `LIFE-1` to `LIFE-12` |
| [Residual Risks](#residual-risks) | Known risks, by topic |

## Common rules

These three rules apply everywhere. The other rules cite them and do not
repeat them.

### R-1. Refuse before side effects.

If the proxy or the host CLI refuses something, it refuses early. No DNS
lookup, upstream connection, token read, OAuth state write, policy write, or
file write happens first.

### R-2. Unreadable means refuse.

If Runfree cannot read, parse, or prove a value that a security decision
needs, it takes the safe answer. It refuses, treats the request as a write,
or keeps the last valid state.

### R-3. The host decides.

The agent can ask, but only the host user and the host CLI can widen
authority. Anything that the agent can write is input, never authority.

## Words

| Word | Meaning |
| --- | --- |
| approver | The host process that decides holds: `runfree approvals --watch`. It is attached while its heartbeat is under 45 s old. |
| audit mode | A time-limited mode that lets unlisted hosts through. |
| blocked endpoint | A named endpoint that no server mediates. |
| claim | A server's use of an OAuth host or endpoint. |
| colliding endpoint | An endpoint that two servers claim. Neither gets it. |
| curated host | A host of any curated service, enabled or not. |
| desired policy | `.runfree/network-policy.json`. It needs your approval to take effect. |
| destination | Where the proxy adds a credential: host, header, scheme, scope. |
| discovered host | An OAuth host that `mcp enable` found in server metadata. |
| effective policy generation | The approved, fixed policy. The proxy reads only this. |
| endpoint host | A host that a record names and that serves an MCP endpoint. |
| ephemeral helper, helper | A short-lived container for one task. |
| fence | A check before IP reuse that the old owner is gone. |
| gateway | The Docker daemon's host-gateway address: Docker Desktop's path to the host loopback, or on Docker Engine the address the host relay binds. |
| git handling rule | The `gitPush` rule. A fetch is a read; a push is a git push. |
| `git-lfs` destination | A destination that matches only Git LFS batch and lock requests. |
| grant, deny | A host decision that lets later writes through, or refuses them. |
| grant shape | A query or body with `grant_type`, `refresh_token`, `redirect_uris`, or `code` with `code_verifier`. |
| handle | A `runfree_oauth_…` stand-in for a real token. The proxy keeps the token. |
| headless session | An unwatched session that `runfree run` starts. |
| heartbeat | The host's inspect-and-write that renews the lease every 30 s. |
| held token | A credential value in the proxy's memory-only storage. |
| hold | A write under `ask` that waits for a host decision. |
| host service | An approved tunnel from the agent to one host loopback port. |
| lease | The life of a session file: at most 5 min after inspection. |
| lifecycle lock | The per-project lock that start, launch, stop, rebuild, and destroy take. |
| MCP record | The host record that `mcp enable` writes for one server. |
| mediated endpoint | An OAuth endpoint where the proxy swaps handles and tokens. |
| older reader | An older CLI or proxy that reads newer policy. |
| peer | Another live session of the same project. |
| read, write | The two request classes. An unproven read is a write. |
| reconcile | The host's cleanup of state whose owner is dead. |
| record | The host's lifecycle record of a session. It reserves its IP. |
| record-only host | A host that only MCP records allow. |
| request proxy | The unprivileged proxy process (uid 1001) that reads requests. |
| session | One agent process in its own container, with one source IP. |
| session file | A root-owned proxy file that names one session's IP. |
| source | Where the host reads a credential, such as 1Password. |
| warm launch | A launch that reuses a running runtime. |
| write action | A host's answer to writes: `allow`, `deny`, or `ask` (default). |

## Network

The agent has no route out. All its traffic goes through the request proxy
([details](architecture.md#proxy-enforcement-details)).

```text
 agent (agent_internal, no route out)
   |  CONNECT host:port
   v
 request proxy (uid 1001, no privilege)              NET-9
   1. a runfree.internal name?  -> host-service check   NET-5, NET-6
   2. port 443 and an exact allowed host?  no -> 403    NET-2, NET-4
   3. method, path, and write rules?       no -> 403    NET-7
   4. only now: credential read, DNS, connect           NET-1
   v
 firewall: drop all, except TCP 443 to the allowed set  NET-3, NET-8
   v
 allowed HTTPS/WSS host
```

### NET-1. The proxy checks policy before it does anything else for a request.

- The proxy refuses plain HTTP, an unlisted host, and a raw tunnel that is
  not an approved host service.
- It refuses a forbidden method or path, and an unapproved write. `R-1`
  applies.

Enforced: [policy.ts](../packages/proxy/src/policy.ts) `beforeAllowedRequest`, [server.ts](../packages/proxy/src/server.ts) `classifyConnect`  
Tests: [server-core.test.ts](../packages/proxy/src/server-core.test.ts).

### NET-2. Hosts are exact names.

- Policy has no wildcard hosts and no IP addresses.
- Audit mode also refuses a CONNECT to an IP address.

Why: a wildcard or address reaches hosts that you did not name.

Enforced: [network-policy.ts](../packages/runtime-contracts/src/network-policy.ts) `validateNetworkPolicy`

### NET-3. The firewall lets traffic out only to the allowed addresses.

- A host-service pair is an approved `<name>.runfree.internal:<port>` name
  and the host port that it reaches.
- The firewall process is the root process in the proxy container; it owns
  the firewall rules and does all DNS lookups.
- The firewall drops all outbound traffic, except TCP 443 to allowed hosts
  and approved host-service pairs (`NET-6`).
- Only admitted sessions can connect to the proxy port.
- The root firewall process does all DNS. It drops answers in private,
  loopback, and internal ranges.

Why: the firewall still stops a compromised request proxy.

Enforced: [nftables.ts](../packages/proxy/src/firewall/nftables.ts) `renderRuleset`, [supervisor.ts](../packages/proxy/src/firewall/supervisor.ts) `classifyResolvedIpv4`  
Tests: [nftables.test.ts](../packages/proxy/src/firewall/nftables.test.ts), [supervisor.test.ts](../packages/proxy/src/firewall/supervisor.test.ts).

### NET-4. A denied connection gets a clear refusal, within fixed limits.

- A denied 443 CONNECT gets a 403 in the tunnel, with the reason.
- At most 32 denied tunnels stay open, each for 5 s idle. Past that cap, and
  on other ports, the agent gets a raw 403.
- Logs keep at most 10 events per minute for each host and reason.

Why: denials must not use up proxy resources.

Enforced: [server.ts](../packages/proxy/src/server.ts) `adoptDeniedTunnel`, [denial.ts](../packages/proxy/src/denial.ts)  
Tests: [server-tunnels.test.ts](../packages/proxy/src/server-tunnels.test.ts), [denial.test.ts](../packages/proxy/src/denial.test.ts).

### NET-5. The name `runfree.internal` is reserved.

- Every hostname check refuses `runfree.internal` and names under it.
- The proxy handles them first, in every mode, with no audit record.

Enforced: [server.ts](../packages/proxy/src/server.ts) `classifyConnect`, [network-policy.ts](../packages/runtime-contracts/src/network-policy.ts)  
Tests: [network-policy.test.ts](../packages/runtime-contracts/src/network-policy.test.ts), [server-host-services.test.ts](../packages/proxy/src/server-host-services.test.ts).

### NET-6. A host service reaches exactly one approved port on the host.

- You approve an exact name and port, where a host process listens. A new
  service, port, or target needs review.
- The tunnel carries raw bytes, with no request rules, write approval, or
  credentials.
- Only the request proxy (uid 1001) can reach the port.
- The gateway is the private IPv4 address from the Docker daemon, never from
  DNS. If it is invalid, host services refuse.
- A removal or a gateway change cuts open tunnels.
- The proxy path is the same on every backend. On Docker Desktop the host
  gateway reaches the host's loopback itself. On a local Docker Engine on
  Linux the host relay does: it listens only on the gateway address, for
  approved ports only, accepts only the proxy's egress IP, and forwards to
  `127.0.0.1:<port>`. A removed port stops listening, but the relay never
  closes an open tunnel: revocation is the proxy's two cuts on every
  backend, with no third cut. Every validation, warm launches included,
  proves the relay: exactly one on Engine with its hardened shape and the
  plan's addresses as its environment, and none on Desktop. Other backends,
  a Docker Desktop reached over TCP or SSH included, refuse
  `host-service add`.
- On Docker Engine the relay runs as a non-root user with no capabilities,
  so `host-service add` refuses a port below the host's
  `net.ipv4.ip_unprivileged_port_start`. If that value cannot be read, it
  refuses every port. Docker Desktop has no such limit.
- The relay is a script run by the proxy image's Node: no new image or
  dependency, and the same trust as the proxy image.
- Limits: 32 tunnels per session, 256 in all, 64 pending, and 5 s to
  connect.

Why: the rule keeps this hole in the sandbox to one port.

Enforced: [host-service-tunnel.ts](../packages/proxy/src/host-service-tunnel.ts) `createHostServiceTunnels`, [host-service-gateway.ts](../packages/proxy/src/firewall/host-service-gateway.ts) `validateHostServiceGateway`, [nftables.ts](../packages/proxy/src/firewall/nftables.ts) `renderHostServiceSetUpdate`, [host-relay.ts](../packages/proxy/src/host-relay.ts) `createHostRelay`, [host-relay-topology.ts](../packages/cli/src/runtime/host-relay-topology.ts) `hostRelayTopologyIssues`  
Tests: [host-service-tunnel.test.ts](../packages/proxy/src/host-service-tunnel.test.ts), [server-host-services.test.ts](../packages/proxy/src/server-host-services.test.ts), [host-service-gateway.test.ts](../packages/proxy/src/firewall/host-service-gateway.test.ts), [host-relay.test.ts](../packages/proxy/src/host-relay.test.ts), [host-relay-topology.test.ts](../packages/cli/src/runtime/host-relay-topology.test.ts).

### NET-7. If the proxy cannot read a request's shape clearly, it refuses the request.

- On a host with method rules, the proxy removes method-override headers.
- On a host with path rules, the proxy decodes the path fully first. It
  refuses an encoded slash or dot, `..`, `//`, or bad encoding.
- A WebSocket upgrade counts as a `GET`.
- The `x-runfree-blocked` header names the denial reason.

Why: an origin can read a request differently.

Enforced: [policy.ts](../packages/proxy/src/policy.ts) `hasPathConfusion`, `hasMethodOverrideHeader`, `assertAllowedRequestShape`  
Tests: [policy.test.ts](../packages/proxy/src/policy.test.ts).

### NET-8. Audit mode has a time limit that a clock change cannot extend.

- Only the host turns on audit mode. It lets unlisted hosts through on 443.
- It lasts 60 min by default, and 8 h at most.
- Audited hosts skip request rules and write approval.
- The proxy and the firewall share one end time. Then the firewall cuts
  audited connections.

Why: an audit window must not outlive your request.

Enforced: [audit.ts](../packages/proxy/src/audit.ts) `effectiveAuditExpiryMs`, [nftables.ts](../packages/proxy/src/firewall/nftables.ts) `renderAuditTeardown`  
Tests: [audit.test.ts](../packages/proxy/src/audit.test.ts), [supervisor.test.ts](../packages/proxy/src/firewall/supervisor.test.ts).

### NET-9. The request proxy has no privilege.

- It runs as uid 1001 with no extra groups or capabilities. It cannot gain
  `NET_ADMIN`, `NET_RAW`, or other privilege.
- It checks this at start and stops on any mismatch.
- The host checks that the proxy's default route uses the egress network.

Why: a compromised request proxy must not change the firewall.

Enforced: [entrypoint.ts](../packages/proxy/src/entrypoint.ts) `serverPrivilegeDropArgs`, `waitForServerPrivilegeProofOrKill`, [route.ts](../packages/proxy/src/firewall/route.ts) `ensureDefaultRoute`  
Tests: [entrypoint.test.ts](../packages/proxy/src/entrypoint.test.ts), [route.test.ts](../packages/proxy/src/firewall/route.test.ts).

## Policy

The agent can edit desired policy. Only a copy that you approve takes effect.

```text
 .runfree/network-policy.json      desired policy (the agent can edit it)
   |
   v
 host CLI reads the exact bytes, checks them, and you approve them    POL-1, POL-3
   |
   v
 effective policy generation       read-only to the proxy            POL-2, POL-5
   |
   v
 proxy
```

### POL-1. Desired policy has no effect until you approve its exact bytes.

- The agent can edit `.runfree/network-policy.json`. An edit does nothing by
  itself.
- A host transaction reads the file, checks it, and approves those exact
  bytes.
- `R-3` applies.

Enforced: [approvals.ts](../packages/cli/src/control/approvals.ts) `approveNetworkCandidate`  
Tests: [desired-mutation-drift-guard.test.ts](../packages/cli/src/control/desired-mutation-drift-guard.test.ts).

### POL-2. The proxy never reads the project file.

- The proxy reads only the effective policy generation.
- The effective policy generation comes from host state, through a read-only
  mount.

Tests: [effective.test.ts](../packages/cli/src/control/effective.test.ts).

### POL-3. Runfree refuses policy input that it does not fully understand.

- Runfree refuses unknown fields, duplicate keys, oversize input, and unsafe
  paths.
- Runfree refuses any growth in authority that you did not approve.
- Only maps keyed by name, such as hosts and tokens, accept any key.
- Runfree refuses desired policy version 1. It does not convert it.

Why: a field that a reader does not know could carry authority that the
reader then ignores or misreads.

Enforced: [desired-network-policy.ts](../packages/runtime-contracts/src/desired-network-policy.ts) `validateDesiredNetworkPolicy`  
Tests: [policy-strict-keys.property.test.ts](../packages/cli/src/control/policy-strict-keys.property.test.ts), [desired-network-policy.test.ts](../packages/runtime-contracts/src/desired-network-policy.test.ts).

### POL-4. A change made beside live sessions approves the exact file that it read under the lock.

- The CLI reads the file again under the lifecycle lock.
- It approves that copy. It never reads the file a second time to approve
  it.
- The mechanism is in
  [Desired-Policy Mutation](architecture.md#desired-policy-mutation-beside-live-sessions).

Why: the agent can change the file between the read and the approval.

Tests: [desired-mutation-drift-guard.test.ts](../packages/cli/src/control/desired-mutation-drift-guard.test.ts).

### POL-5. If a new effective policy generation is invalid or incomplete, the proxy keeps the previous one.

- `R-2` applies.

Tests: [server-core.test.ts](../packages/proxy/src/server-core.test.ts), [server-mcp-effective.test.ts](../packages/proxy/src/server-mcp-effective.test.ts).

### POL-6. The agent environment comes only from the effective policy generation.

- Runfree ignores the project file `.runfree/config/agent.env`.

Why: the agent can write project files, so they must not set its
environment.

Tests: [config.test.ts](../packages/cli/src/config.test.ts).

### POL-7. An older reader never gets policy that it would misread.

- Desired policy uses a newer version only when it holds a field that older
  releases do not know. Those releases refuse the file (`OLD-1`).
- The CLI applies policy only to a proxy of its own build (`OLD-2`).

Tests: [old-reader.test.ts](../packages/cli/src/control/old-reader.test.ts).

### POL-8. A `host rules` setting can narrow a service, but never add a host or a request class.

- The setting lives in the service entry, as `selection.hostRules`.
- It applies only to a host that the service already allows.
- It can set only methods, path prefixes, the write action, and
  `gitPush: "deny"`.
- If the service sets methods or path prefixes, the setting can only narrow
  them. Runfree refuses a broader setting before any write.
- `gitPush: "deny"` works only on a host where the service has git handling.
- The setting can loosen the write action, as `host rules --write allow` can
  on any host. Runfree then warns on each `service enable`,
  `service configure`, and `service diff --apply`.
- `service disable` never removes a rule that you set to restrict a host.

Why: the service decides what each request is, such as a GraphQL mutation or
a git fetch. A setting must not change that, or a write could pass as a read.

Enforced: [service-mutation.ts](../packages/cli/src/control/service-mutation.ts) `assertServiceHostRulesFit`, `weakerHostWriteSettingWarnings`, [desired-network-policy.ts](../packages/runtime-contracts/src/desired-network-policy.ts) `serviceHostRuleNarrowingIssues`  
Tests: [service-mutation.test.ts](../packages/cli/src/control/service-mutation.test.ts), [host-rule-owner.test.ts](../packages/cli/src/control/host-rule-owner.test.ts).

## Credentials

The agent never holds a real token. The host reads each credential and gives
it to the proxy. The proxy adds it to allowed requests. A placeholder is a
fake value that the agent sees in place of a real token.

```text
 HOST                                    PROXY
 source (env, 1Password, command,  -->   proxy-only tmpfs
 JWT, service account, OAuth seed)             |
                                               v
 AGENT: placeholder or handle  --request-->  allowed?  no  -> deny, no token read
                                               yes -> add the credential -> upstream
```

### CRED-1. Real tokens never go anywhere that the agent can read.

- A real token never goes into the agent environment.
- A real token never goes into project files, including
  `.runfree/runfree.json` and `.runfree/network-policy.json`.

### CRED-2. Desired policy says where a credential may go. Host config says where it comes from.

- Desired policy (`tokens`) names the host, header, and path for each
  credential.
- The source config is host-owned. The agent cannot change it.

Why: the agent can edit desired policy, but it must not choose what secret
the host reads.

### CRED-3. The host writes a credential only into the runtime that it checked.

- The host writes a credential only into a prepared runtime that it
  validated.
- A prepared value must be admitted within 120 s, then used within a further
  120 s.
- The host reads no source while it holds the lifecycle lock.
- Before each write, the host checks again that the proxy, its token store,
  and the effective policy did not change.

Why: a value must not land in a proxy or a policy that changed after the host
read the value.

Enforced: [admin-core.ts](../packages/cli/src/admin/admin-core.ts) `admitPreparedRuntimeTokenSources`  
Tests: [admin-token-policy.test.ts](../scripts/admin-token-policy.test.ts), [proxy-token-write.test.ts](../packages/cli/src/admin/proxy-token-write.test.ts).

### CRED-4. The proxy keeps a token only while its source still gives it.

- A warm launch can reuse a held token without a new source read. The last
  read must be less than 15 minutes old.
- Right after the launch, a watcher reads every source again.
  `runfree credential sync` always reads every source again.

| Result of a source read | The held token |
| --- | --- |
| The source says the token is revoked | Removed |
| A short failure, such as a locked vault | Kept, for a limited time |
| You stop the read (exit, Ctrl-C) | Unchanged. This is not a failure. |
| A write that did not finish, or whose outcome is unknown | Unchanged |

- A sync that a launch defers follows [`LIFE-10`](#lifecycle).

Why: a token revoked at its source must stop working. A short outage must
not remove a good token.

Enforced: [admin-core.ts](../packages/cli/src/admin/admin-core.ts) `keepLastGoodReceipt`, `classifyOnePasswordFailure`  
Tests: [admin-token-policy.test.ts](../scripts/admin-token-policy.test.ts), [credential-cancellation.test.ts](../packages/cli/src/admin/credential-cancellation.test.ts).

### CRED-5. Only the proxy gets the proxy CA private key.

Why: with the key, the agent could read or forge the proxy's TLS traffic.

Tests: [runtime-topology.live.test.ts](../tests/runtime/live/runtime-topology.live.test.ts).

### CRED-6. A Google service-account key stays on the host.

- The host reads the key from 1Password only to sign a token. It never
  stores the key, in any file or log.
- The signed token lives at most 1 hour. It goes only to the proxy.
- The source pins the service account's email. A changed 1Password item
  cannot switch to another account.
- The host sets the scope from a fixed list. The agent cannot set it.
- If a step fails after the key is read, the held token is removed.
- An error message names the bad field. It never shows the key.
- The watcher keeps the key in memory for at most 4 hours. So a key removed
  from 1Password stops within 4 hours plus one token lifetime.
- If you delete the key in Google Cloud IAM, it stops at once.
- A token's scope does not make a host read-only. Host rules do
  ([`NET-1`](#network), [`NET-7`](#network)).

Enforced: [google-service-account.ts](../packages/cli/src/admin/google-service-account.ts) `parseGoogleServiceAccountKeyJson`, `signGoogleServiceAccountJwt`  
Tests: [google-service-account.test.ts](../packages/cli/src/admin/google-service-account.test.ts), [admin-token-policy.test.ts](../scripts/admin-token-policy.test.ts).

## Git Over HTTPS

The commands are in
[Git over HTTPS and SSH remotes](cli.md#git-over-https-and-ssh-remotes). A new
`protocol` scope is only for a public wire protocol that the proxy can
recognize reliably. A vendor's own endpoints use a path prefix or a request
rule.

```text
 agent: git fetch, git push, git lfs
   |
   v
 proxy
   1. Is the host allowed?                    no  -> 403
   2. Is it a recognized git request? GIT-3   no  -> no git credential
   3. Read or write?
        fetch               -> read
        push                -> git push write
        LFS download batch  -> read only if the body proves it (GIT-5)
   4. A write? --deny-git-push refuses; write approval holds (GIT-2)
   5. Remove the agent's Authorization (GIT-4); add the token (GIT-9)
   |
   v
 provider (a redirect goes back unchanged, GIT-8)
```

`R-1` applies to steps 1 to 4. The commands are in
[cli.md](cli.md#git-over-https-and-ssh-remotes).

### GIT-1. A git token reaches every repository that the token can access.

- The `protocol` scope limits which requests carry the token, not which
  repositories.
- A destination without `protocol` carries the token on every path it
  matches.

Why: the proxy cannot see a token's repositories. Use a fine-grained token.

### GIT-2. An approved push goes out with your token.

- Under the default `ask`, a push waits for `runfree approve`.
- `--deny-git-push` refuses a push, but not a Git LFS upload. An upload is an
  ordinary write.

Why: approving a push is a real decision.

Enforced: [policy.ts](../packages/proxy/src/policy.ts) `classifyWrite`, `isGitPushPath`  
Tests: [server-git-http.test.ts](../packages/proxy/src/server-git-http.test.ts).

### GIT-3. The proxy adds a git credential only to a recognized git request.

- A `git-http` destination matches only git smart-HTTP requests: ref
  discovery, fetch, and push.
- The request must match the request table in cli.md, with no ambiguity
  after decoding.
- `git-http` matches only smart-HTTP requests. `git-lfs` matches only LFS
  requests.
- Other requests get no git credential, and keep their write class.

These are never git requests:

| Request | Why |
| --- | --- |
| A `POST` endpoint with a query | An origin could act on a query that the proxy did not read. |
| Ref discovery with `;`, or not exactly one `service` | An origin could read a second `service`. A `;` query counts as a push. |
| A first segment `api`, or a `-` segment | Origins serve APIs under `/api/` and `/-/`. |
| A segment that starts with whitespace after decoding | A trimming origin could route elsewhere. |

Why: the credential can push, so it goes only to requests that the proxy read.

Enforced: [policy.ts](../packages/proxy/src/policy.ts) `gitHttpRequestKind`, `gitRequestProtocol`  
Tests: [policy.test.ts](../packages/proxy/src/policy.test.ts).

### GIT-4. The proxy removes the agent's `Authorization` on a credential host.

- On a host with an `Authorization` destination, the proxy removes the
  agent's value on every path. It adds its own where a destination matches.
- The proxy keeps an OAuth handle for the mediator. It refuses a `Bearer`
  handle that is not live for this project and resource.
- A `Basic` password with the handle shape goes out unchanged, with no token.

Why: the header cannot expose or replace the stored token.

Tests: [server-git-http.test.ts](../packages/proxy/src/server-git-http.test.ts).

### GIT-5. A Git LFS batch request is a read only if its body proves a download.

- Under `ask` or `deny`, the host needs a git handling rule and a matching
  `git-lfs` destination.
- The body must be at most 64 KiB, unambiguous, and ask for `"download"`
  only.
- Other batch and `POST` lock requests are writes. `R-2` applies.
- A held request is rechecked without its body, so it stays a write.
- The `GET` lock listing is a read, with the `git-lfs` credential.
- A fetch is a read only on a recognized `…/git-upload-pack` path with no
  query.

Why: a download answer can carry provider credentials (`GIT-6`). So the read
rule must never admit an upload.

Enforced: [lfs-classify.ts](../packages/proxy/src/lfs-classify.ts) `classifyLfsBatchRequest`, [policy.ts](../packages/proxy/src/policy.ts) `lfsMediatedRequest`  
Tests: [lfs-classify.test.ts](../packages/proxy/src/lfs-classify.test.ts), [server-lfs.test.ts](../packages/proxy/src/server-lfs.test.ts).

### GIT-6. Object transfer credentials reach the agent.

- A host has mediated LFS if it has a git handling rule and a `git-lfs`
  destination.
- A batch answer can carry provider credentials. The proxy passes them
  unchanged, with no limit on scope or lifetime.
- If a provider's batch answer holds a credential that can push, its service
  has no `git-lfs` destination. There, every batch request is a write, and a
  private LFS fetch fails.
- The transfer follows the action host's policy, including `GIT-4`.

Why: a mediated download batch is a read (`GIT-5`). The agent gets these
credentials with no approval.

### GIT-7. A service can send requests without a token.

- If a service allows it and no token is stored, requests go out with no
  `Authorization`. Private calls get 401.
- `runfree service explain <id>` shows whether a service does this.

Tests: [policy.test.ts](../packages/proxy/src/policy.test.ts).

### GIT-8. The proxy does not follow redirects.

- A redirect goes to the agent unchanged. Git follows it as a new request,
  under the new host's policy.

Why: the agent never sees the injected value, so it cannot carry it away.

Tests: [server-git-http.test.ts](../packages/proxy/src/server-git-http.test.ts).

### GIT-9. If a `protocol` destination matches, the proxy adds only `protocol` destinations.

- This holds for the whole host, across headers.

Enforced: [policy.ts](../packages/proxy/src/policy.ts) `selectedCredentialMappings`  
Tests: [policy.test.ts](../packages/proxy/src/policy.test.ts).

### GIT-10. A change to a host with more than one destination needs approval.

- The proxy picks one destination per request, so a change can make another
  token win.
- So any change there needs approval, except removing every destination.
- Scoping to `git-lfs` needs approval, because it turns on `GIT-5`.

Enforced: [comparator.ts](../packages/cli/src/control/comparator.ts) `compareCompiledAuthority`  
Tests: [comparator.test.ts](../packages/cli/src/control/comparator.test.ts).

## Older Readers

A newer policy can reach an older reader: a teammate's older CLI, a
downgraded CLI, or a proxy that still runs the previous build. An older
reader must refuse what it cannot read. It must never drop a field and allow
more.

```text
 newer policy
   +--> older CLI reads the desired file      --> refuses it            OLD-1
   +--> proxy of another build                --> replaced, or the
   |                                              change waits           OLD-2
   +--> older proxy reads the effective
        policy generation (rare race)         --> refuses it, keeps
                                                  its last valid policy  OLD-3
```

### OLD-1. Desired policy uses a newer version only when an older reader would misread it.

- The fields that raise the version are listed in
  [cli.md](cli.md#network-policy).
- A release that does not know that version refuses the file.
- So an older release cannot drop a `protocol` scope or a `--deny-git-push`
  setting, and then allow more.
- A file without those fields keeps the lowest version and the same digest.

Enforced: [desired-network-policy.ts](../packages/runtime-contracts/src/desired-network-policy.ts) `validateDesiredNetworkPolicy`  
Tests: [old-reader.test.ts](../packages/cli/src/control/old-reader.test.ts), [desired-network-policy.test.ts](../packages/runtime-contracts/src/desired-network-policy.test.ts).

### OLD-2. The CLI applies policy only to a proxy of its own build.

- A policy command compares the running proxy's build label with the proxy
  that this CLI contains. A missing label counts as another build.
- If they differ, the command replaces the proxy first. Or it saves the
  change without applying it, and names the fix (see
  [troubleshooting.md](troubleshooting.md)).

Enforced: [activation.ts](../packages/cli/src/control/activation.ts) `fenceProxyFromAnotherBuild`  
Tests: [activation.test.ts](../packages/cli/src/control/activation.test.ts).

### OLD-3. If an older proxy reads a newer effective policy generation, it keeps its last valid policy.

- This can happen in a race. The `OLD-2` check does not lock out a runtime
  start by another build at the same moment.
- The older proxy sees fields that it does not know. The digest it computes
  does not match, so it refuses the new effective policy generation.

Why: the race can cost availability, but it never gives more authority.

Tests: [old-reader.test.ts](../packages/cli/src/control/old-reader.test.ts).

### OLD-4. After a downgrade, you must approve project-image build contexts again.

- Older releases cannot read the approval records for project-image build
  contexts.

## Sessions

A session's identity is its source IP on `agent_internal` (mode
`source-ip-v1`). It names a container, not a user or a prompt. See
[Session Admission](architecture.md#session-admission).

```text
 HOST                                         PROXY
 pick an IP from the pool, fence it (SESS-5, SESS-12)
 inspect the container, write the file  --->  serve the IP (SESS-1, SESS-4)
 every 30 s: inspect, renew the lease   --->  (SESS-3)
 end: delete the file, then the record  --->  stop serving (SESS-8)
```

### SESS-1. The proxy serves an IP only while a valid session file names it.

- Only the host writes session files, in a root-only directory. The agent
  cannot make one.
- The proxy refuses a file that is malformed, expired, or over 8 KiB.
- A lease ends at most five minutes after the inspection that authorized it.

Enforced: [session-file.ts](../packages/runtime-contracts/src/session-file.ts) `parseSessionFileV1`, [session-files.ts](../packages/proxy/src/session-files.ts) `scanSessionFiles`  
Tests: [session-file.test.ts](../packages/runtime-contracts/src/session-file.test.ts), [session-files.test.ts](../packages/proxy/src/session-files.test.ts), [session-file-publisher.test.ts](../packages/cli/src/runtime/session-file-publisher.test.ts)

### SESS-2. The host writes a session file only after a Docker inspection in the same call.

If the inspection shows a different container, the host deletes the file. If
the inspection fails, the host deletes nothing.

Enforced: [session-file-heartbeat.ts](../packages/cli/src/runtime/session-file-heartbeat.ts) `inspectAndWriteSessionFile`  
Tests: [session-file-heartbeat.test.ts](../packages/cli/src/runtime/session-file-heartbeat.test.ts)

### SESS-3. A session ends within five minutes after the host stops writing.

The proxy measures the lease on its own clocks. The heartbeat runs every
30 s, so a guest clock error up to the lease minus 30 s does not stop a
session.

Enforced: [session-file-registry.ts](../packages/proxy/src/session-file-registry.ts) `SessionFileRegistry`  
Tests: [session-file-registry.test.ts](../packages/proxy/src/session-file-registry.test.ts)

### SESS-4. The firewall and the request proxy each decide from the same files.

Neither trusts the other, so a fault in one does not open the other.

Enforced: [session-file-validity.ts](../packages/proxy/src/session-file-validity.ts) `servedSessionFiles`

### SESS-5. An IP goes to a new container only after a fence.

- The fence proves that the firewall and the request proxy dropped the old
  owner. It also proves that no kernel socket is open for the IP.
- A delayed fence cannot replace a later assignment of the same IP.
- If the fence lock times out, the host does not create the container. A
  retry is safe.

See [IP Reuse Fence](architecture.md#ip-reuse-fence).

Enforced: [session-file-publisher.ts](../packages/cli/src/runtime/session-file-publisher.ts) `sessionIpReuseFenceCommand`, [session-ip-reuse.ts](../packages/proxy/src/session-ip-reuse.ts) `SessionIpAssignments`  
Tests: [session-ip-reuse.test.ts](../packages/cli/src/runtime/session-ip-reuse.test.ts), [session-file-registry.test.ts](../packages/proxy/src/session-file-registry.test.ts)

### SESS-6. If the session state contradicts itself, the proxy serves no session involved.

Examples: two files for one IP, wrong bindings, or a file name that does not
match its session key. The proxy does not guess (`R-2`).

Enforced: [session-files.ts](../packages/proxy/src/session-files.ts) `scanSessionFiles`  
Tests: [session-files.test.ts](../packages/proxy/src/session-files.test.ts)

### SESS-7. Reconcile never touches the session of a live owner.

Reconcile acts only on a record whose owner process is dead. If the owner's
state is unknown, it keeps the record.

Enforced: [session-reconcile.ts](../packages/cli/src/runtime/session-reconcile.ts) `reconcileSessions`  
Tests: [session-reconcile.test.ts](../packages/cli/src/runtime/session-reconcile.test.ts)

### SESS-8. Teardown deletes the session file first and the record last.

If the file delete fails, teardown stops. So an IP is never free while a
file can still give it access.

Enforced: [session-file-teardown.ts](../packages/cli/src/runtime/session-file-teardown.ts) `teardownSessionRecord`  
Tests: [session-file-teardown.test.ts](../packages/cli/src/runtime/session-file-teardown.test.ts)

### SESS-9. A heartbeat never stops the agent.

It controls only the session file.

Enforced: [session-file-heartbeat.ts](../packages/cli/src/runtime/session-file-heartbeat.ts) `inspectAndWriteSessionFile`

### SESS-10. An unreadable listing never counts as empty.

- A warm launch skips the startup reconcile only if every listing it needs
  reads empty. A failed, slow, or bad listing runs reconcile (`R-2`).
- An "empty" result is good for one use, proxy instance, and lock holder.
- Startup hands its lock to admission only after a quick startup that read
  no credential source under the lock. `runfree up` and `runfree resume`
  never hand it off.

Enforced: [warm-empty-session-state.ts](../packages/cli/src/runtime/warm-empty-session-state.ts) `proveWarmEmptySessionState`  
Tests: [warm-empty-session-state.test.ts](../packages/cli/src/runtime/warm-empty-session-state.test.ts), [session-admission-driver.test.ts](../packages/cli/src/runtime/session-admission-driver.test.ts)

### SESS-11. A warm launch never restores or renews a peer.

- A warm launch beside live peers skips the restore only if it accounts for
  every peer in one proxy instance. If a peer's owner is not surely alive or
  dead, the launch runs the full checks.
- If a peer's owner dies later, the peer keeps access only until its session
  file expires.

Enforced: [warm-peer-proof.ts](../packages/cli/src/runtime/warm-peer-proof.ts) `tryWarmPeerValidation`  
Tests: [warm-peer-proof.test.ts](../packages/cli/src/runtime/warm-peer-proof.test.ts)

### SESS-12. The host gives sessions addresses only from the session pool.

- Addresses: `.10` the proxy, `.11`–`.12` reserved, `.13`–`.19` the
  deny-probe helper, `.20` and up sessions.
- If an unknown container holds a reserved address, the host refuses to
  allocate.
- The host never gives out an address that a session file names. If it
  cannot read the files, it refuses the launch.
- The file writer and the IP fence refuse any address outside the pool.

Enforced: [session-container-reconciliation.ts](../packages/cli/src/runtime/session-container-reconciliation.ts) `allocateSessionSourceIp`  
Tests: [session-ip-reuse.test.ts](../packages/cli/src/runtime/session-ip-reuse.test.ts), [network.test.ts](../packages/cli/src/network.test.ts)

### SESS-13. Re-attach is limited, but it never ends a session.

If the attached stream ends while the session runs, the host attaches again,
at most three times in 60 s. At that limit, the session keeps running.

Enforced: [session-admission-driver.ts](../packages/cli/src/runtime/session-admission-driver.ts)  
Tests: [session-admission-driver.test.ts](../packages/cli/src/runtime/session-admission-driver.test.ts)

## Write Approval

The grant details are in
[Write Approval Grants](architecture.md#write-approval-grants).

```text
 agent: a write (POST, PUT, DELETE, ...)
   |
   v
 headless session? (WRITE-7)    yes -> 403, no hold
 a deny matches?   (WRITE-4)    yes -> 403
 a grant matches?  (WRITE-3)    yes -> forward
 16 holds, or no approver?      yes -> 403 at once (WRITE-6)
   |
   v
 hold, 120 s by default
   +-- host approves -> check the full policy again -> forward
   +-- host denies, or no decision in time           -> 403
```

### WRITE-1. The host makes every decision.

- The host user decides with `runfree approvals --watch` or
  `runfree approve <id>`.
- `R-3` applies.

Tests: [approvals.test.ts](../packages/proxy/src/approvals.test.ts).

### WRITE-2. A grant belongs to one session.

- A grant ends when the authority of its session ends.

Tests: [approvals.test.ts](../packages/proxy/src/approvals.test.ts).

### WRITE-3. A grant has a lifetime.

- A `request` grant lasts 5 min.
- A `ttl` grant lasts 8 h at most.
- A grant ends on the wall clock or on the monotonic clock, whichever ends
  first.

Why: a clock step or a host sleep cannot extend a grant.

Tests: [approvals.test.ts](../packages/proxy/src/approvals.test.ts).

### WRITE-4. A deny does not expire.

- Only `runfree approvals --clear-deny` removes a deny.
- The clear uses a root-owned channel that the agent cannot reach.
- A clear goes back to `ask`, never to `allow`.

Tests: [approvals.test.ts](../packages/proxy/src/approvals.test.ts), [runtime/approvals.test.ts](../packages/cli/src/runtime/approvals.test.ts).

### WRITE-5. New policy never removes a deny.

Tests: [approvals.test.ts](../packages/proxy/src/approvals.test.ts).

### WRITE-6. Holds are bounded, and only the host decides them.

- A hold lasts `runtime.writeApprovalHoldSeconds`: 120 s by default, from 5
  to 300 s.
- At most 16 holds exist at one time.
- If no approver is attached, the answer is 403 at once.
- The agent cannot write a decision. Decision files and the approver
  heartbeat must be root-owned, and the host writes them.
- An approval id works once.
- The proxy checks an approved request against the full policy again.
- A policy change cancels the holds that no longer pass.

Why: a hold cannot pile up, and the agent cannot approve its own write.

Enforced: [approvals.ts](../packages/proxy/src/approvals.ts) `createWriteApprovalManager`  
Tests: [approvals.test.ts](../packages/proxy/src/approvals.test.ts), [server-approvals.test.ts](../packages/proxy/src/server-approvals.test.ts).

### WRITE-7. A headless session never holds a write.

- A session that `runfree run` starts has a headless mark in its root-owned
  session file.
- The mark arrives in the same write that admits the session. So no request
  comes before it.
- The mark never comes from the container.
- If a headless session sends an `ask` write, the proxy refuses it at once
  with `write-approval-headless-denied`.
- There is no hold and no pending record. A grant cannot let the write
  through.
- A WebSocket retry also makes no hold.
- `runfree run` counts these denials in its result.
- If a proxy does not know the mark, it refuses the session file. So the
  run fails closed.
- The `run` preflight warns early. The proxy enforces the rule.

Why: nobody can answer a hold in a headless run.

Enforced: [approvals.ts](../packages/proxy/src/approvals.ts) `createWriteApprovalManager`  
Tests: [approvals.test.ts](../packages/proxy/src/approvals.test.ts), [headless-write-posture.test.ts](../packages/cli/src/runtime/headless-write-posture.test.ts).

### WRITE-8. Some authority does not pass write approval.

- These do not pass write approval: host-service tunnels, mediated OAuth
  exchanges, and STDIO or loopback MCP servers.
- A headless run allows them. Its record lists them under
  `uncheckedAuthority`.

Enforced: [headless-run-record.ts](../packages/cli/src/runtime/headless-run-record.ts) `createRunRecord`  
Tests: [headless-run-record.test.ts](../packages/cli/src/runtime/headless-run-record.test.ts).

## MCP

The model is in [MCP OAuth Mediation](architecture.md#mcp-oauth-mediation).
The commands are in [cli.md](cli.md#mcp).

```text
 agent (MCP client)            proxy                              upstream
 1. GET /.well-known/...  ---> discovered host: metadata paths only ---> issuer
 2. sign-in page opens on the HOST, never in the sandbox
 3. callback: host port -> session forwarder -> session bridge
 4. POST token endpoint   ---> mediated endpoint?
                                 yes: handles -> real values      ---> issuer
                                 no, grant shape: 403 (MCP-9)
    <--- real tokens become handles (runfree_oauth_...)
 5. MCP call with a handle ---> handle -> real token              ---> MCP host
```

What the proxy does on each kind of OAuth target:

| Target | Grant-shaped request | Body scan | Unreadable body | Reply | WebSocket upgrade |
| --- | --- | --- | --- | --- | --- |
| mediated endpoint | Handles become real values | Exact protocol shape (`MCP-11`) | Refused | Read; tokens become handles | Refused |
| record-only host | Refused | Deep | Refused | Streamed | Refused |
| blocked or colliding endpoint | Refused | Deep | Refused | Read; blocked if it carries a token | Refused |
| other path on that host | Refused | Deep | Scanned, up to 256 KiB | Streamed | Refused if the query is grant-shaped |
| endpoint host | Refused | Top-level keys | Scanned, up to 256 KiB | Streamed | Refused if the query is grant-shaped |

- If nothing else allows a discovered host, it takes only GET, HEAD, OPTIONS,
  and POST. These must be under `/.well-known` or on recorded endpoint paths.

### MCP-1. Entries in `.mcp.json` and `.codex/config.toml` load only after `runfree mcp enable`.

Tests: [admin-mcp.test.ts](../scripts/admin-mcp.test.ts).

### MCP-2. Claude gets a read-only approved config in strict MCP mode.

- Strict mode stops passive project descriptors. It does not stop code in
  the agent from starting another binary.

Tests: [mcp.test.ts](../packages/cli/src/runtime/mcp.test.ts).

### MCP-3. An MCP entry must name hostnames and use HTTPS for OAuth.

- If an MCP or OAuth URL names an IP address or is not `https:`, the entry
  is skipped.
- Static headers need a host-owned credential source.

Why: a plain-HTTP OAuth URL sends the exchange past the mediator.

Tests: [mcp-url.test.ts](../packages/cli/src/runtime/mcp-url.test.ts).

### MCP-4. Only HTTPS MCP tool calls pass write approval.

- STDIO and loopback HTTP servers (`http://127.0.0.1:<port>`) do not pass the
  proxy. `runfree mcp rules` refuses them.
- If a loopback entry has a credential, header, helper, or OAuth, it is
  skipped.
- Only `runfree host-service add` decides whether a loopback port reaches the
  host.

Tests: [mcp-loopback.test.ts](../packages/cli/src/runtime/mcp-loopback.test.ts).

### MCP-5. No imported MCP descriptor starts a host process.

- STDIO commands run only in the agent container. A host-path command is
  skipped.
- The Codex Desktop built-ins `node_repl` and `computer-use` are skipped.
  Only the exact command that the app bundles counts as a built-in.

Tests: [mcp-desktop-builtins.test.ts](../packages/cli/src/runtime/mcp-desktop-builtins.test.ts).

### MCP-6. Each session owns its OAuth callback path.

- Each session gets its own loopback port, forwarder, and bridge before it
  starts. The bridge accepts only its own forwarder.
- The forwarder goes before the session's address is released, or before an
  unclaimed session container is removed.
- The port is routing, not a secret. The client checks state, PKCE, and
  issuer.

Enforced: [session-callback-ingress.ts](../packages/cli/src/runtime/session-callback-ingress.ts) `removeSessionMcpCallbackIngress`, `removeOrphanSessionMcpCallbackIngress`  
Tests: [session-mcp-callback.test.ts](../packages/cli/src/runtime/session-mcp-callback.test.ts), [session-callback-ingress.test.ts](../packages/cli/src/runtime/session-callback-ingress.test.ts).

### MCP-7. `runfree mcp enable` adds OAuth hosts only after one host-side review.

- It adds a host only if valid metadata names a token endpoint there.
- Discovery runs only after you agree. It sends plain GETs to public
  addresses, with no credentials, cookies, or redirects.
- A token endpoint on another host needs metadata that the MCP server named.
  The review labels it `token endpoint on another host`.
- The hosts live in host-owned state. They stop applying when the reviewed
  config changes. `runfree mcp revoke` removes them.
- A damaged record grants nothing (`R-2`).

Why: an OAuth host is a place where tokens go. You see each one first.

Enforced: [mcp-discovery.ts](../packages/cli/src/admin/mcp-discovery.ts) `discoverMcpOAuthHosts`  
Tests: [mcp-discovery.test.ts](../packages/cli/src/admin/mcp-discovery.test.ts), [admin-mcp.test.ts](../scripts/admin-mcp.test.ts).

### MCP-8. An MCP server cannot claim a host where the tokens of another login pass.

The proxy refuses a claim on these targets:

- a credential destination or a curated host;
- a host of another MCP server, or another provider's OAuth endpoint.

The server's own MCP host is exempt.

| When | A refused claim |
| --- | --- |
| `mcp enable` | Stops the command before discovery or any write. |
| Each launch | Is dropped with a warning; its endpoints become blocked endpoints. |
| Run time | Is not recorded; an endpoint that two providers claim becomes a colliding endpoint. |

- If you already allow the host, the claim is allowed. The review says
  `ALREADY ALLOWED`. The proxy then mediates only the exact endpoint.

Why: a server that claims another login's endpoint would receive its tokens.

Enforced: [mcp-oauth-projection.ts](../packages/cli/src/runtime/mcp-oauth-projection.ts) `filterClaims`  
Tests: [mcp-oauth-projection.test.ts](../packages/cli/src/runtime/mcp-oauth-projection.test.ts), [oauth-mediation-cross-host.test.ts](../packages/proxy/src/oauth-mediation-cross-host.test.ts).

### MCP-9. A login that the proxy does not mediate never leaves for a guarded target.

- The proxy refuses a grant-shaped request to any target in the table above,
  with `oauth-endpoint-not-mediated`.
- The check covers path variants, such as `/oauth/token/`.
- The check makes no approval prompt.
- If the OAuth policy is invalid, record-only hosts keep this rule. Every
  other allowlisted host refuses a readable grant shape.

Why: a token that leaves outside mediation comes back as a real token.

Enforced: [oauth-mediation.ts](../packages/proxy/src/oauth-mediation.ts) `unmediatedRequestRefusalFor`, `webSocketUpgradeRefusal`; [oauth-grant-shape.ts](../packages/proxy/src/oauth-grant-shape.ts) `classifyGrantShape`  
Tests: [oauth-grant-shape.test.ts](../packages/proxy/src/oauth-grant-shape.test.ts), [server-oauth-unmediated.test.ts](../packages/proxy/src/server-oauth-unmediated.test.ts).

### MCP-10. A revoke clears the proxy's OAuth state for the server.

- A state epoch is a value that the host saves for each MCP server.
- A revoke saves a new state epoch. The proxy then refuses every older handle
  and every token reply from an older exchange.
- If no proxy runs, the clear happens at the next start.
- A damaged or missing epoch record clears every MCP server (`R-2`).
- Each server keeps at most 256 token and 32 registration handles. Past 1024
  exchanges in flight, a new one is refused.
- A server shared by both agents has one login. If its owner changes, every
  member is cleared, with a warning.

Why: after a revoke, no handle that the agent kept may work.

Enforced: [oauth-mediation.ts](../packages/proxy/src/oauth-mediation.ts) `OAuthMediator`  
Tests: [oauth-mediation-state-epoch.test.ts](../packages/proxy/src/oauth-mediation-state-epoch.test.ts), [mcp-oauth-clear.test.ts](../packages/cli/src/admin/mcp-oauth-clear.test.ts), [mcp-share-group-store.test.ts](../packages/cli/src/runtime/mcp-share-group-store.test.ts).

### MCP-11. An OAuth protocol read is exact.

On an `ask` host, a POST is a read only if all of these are true:

- Its exact path is a recorded endpoint that the proxy mediates for one
  server.
- The body is a plain login, a refresh, or a loopback-only registration, at
  most 16 KiB.
- A URL `client_id` equals, byte for byte, the pinned metadata URL of Claude
  Code or Codex.
- The server has made fewer than 30 protocol reads this minute.

Everything else stays a write. A host with credential injection has no
protocol reads.

Why: a login must not wait for approval, but nothing else may pass as one.

Enforced: [oauth-protocol-read.ts](../packages/proxy/src/oauth-protocol-read.ts) `protocolReadBodyAllowed`, `ProtocolReadRateLimiter`  
Tests: [oauth-protocol-read.test.ts](../packages/proxy/src/oauth-protocol-read.test.ts), [mcp-enable.live.test.ts](../tests/runtime/live/mcp-enable.live.test.ts).

## Agent Container

```text
 session container
 +---------------------------------------------------+
 | PID 1: Docker init, uid 1000            (AGENT-4) |
 |   +-- agent CLI, uid 1000               (AGENT-1) |
 |         no-new-privileges                         |
 |         NET_ADMIN and NET_RAW dropped             |
 |         the CLI's own sandbox is off    (AGENT-3) |
 | loopback TCP: open, not trusted         (AGENT-2) |
 | /etc/proxy-ca: read-only CA bundle      (AGENT-5) |
 +---------------------------------------------------+
```

### AGENT-1. The agent runs as uid 1000 with no extra privileges.

- The session container sets `no-new-privileges`.
- The session container drops `NET_ADMIN` and `NET_RAW`.

Why: without these capabilities, the agent cannot change the firewall or
send raw packets.

Enforced: [session-container-contract.ts](../packages/cli/src/runtime/session-container-contract.ts) `SESSION_CONTAINER_CAPABILITY_DROPS`, checked by [session-container-proof.ts](../packages/cli/src/runtime/session-container-proof.ts)  
Tests: [session-container-template.test.ts](../packages/cli/src/runtime/session-container-template.test.ts)

### AGENT-2. Localhost inside the agent is not a trust boundary.

- Loopback TCP stays open, because dev tools need it.
- A helper in or near the agent namespace authenticates its callers. It uses
  a capability, a nonce, or Unix socket permissions.
- A helper never accepts "came from 127.0.0.1" as authorization.

Why: any process that the agent starts can connect to loopback.

### AGENT-3. Agent CLIs run with their own sandbox off.

- The agent CLIs run with `--dangerously-skip-permissions` or
  `--dangerously-bypass-approvals-and-sandbox`.

Why: the container is the sandbox. Permission rules in the agent CLI add
nothing to it.

Enforced: [agents.ts](../packages/cli/src/agents.ts)

### AGENT-4. Docker's init is PID 1, but it is not a boundary.

- Session containers run with `--init`.
- The init runs as uid 1000, with the same capabilities and
  `no-new-privileges`. So the agent gains nothing when it reaches the init.
- The daemon adds the bind mount of the init. The inspection proof does not
  cover that mount.
- A project image can make PID 1 something else. The only cost is the fast
  stop.
- Runfree honors project `TINI_*` variables. None of them changes identity,
  capabilities, mounts, or network.
- Runfree does not support a downgrade while sessions from a newer release
  run. Run `runfree destroy --force` first.

Enforced: [session-container-template.ts](../packages/cli/src/runtime/session-container-template.ts) `sessionContainerTemplateInit`

### AGENT-5. The agent trusts the proxy CA without root.

- An ephemeral helper writes a CA bundle into the read-only `/etc/proxy-ca`
  mount.
- `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, and similar variables point at the
  bundle.

Why: the agent never needs root to install trust.

Enforced: [ca-bundle.ts](../packages/cli/src/runtime/ca-bundle.ts) `ensureAgentCaBundle`  
Tests: [ca-bundle.test.ts](../packages/cli/src/runtime/ca-bundle.test.ts)

## Host Files

```text
 HOST                                            SESSION CONTAINER
 .runfree/ writes: no links, no special files     (FILE-1)
 ~/.ssh, ~/.aws, home config  ------X------  not mounted   (FILE-2)
 host reads agent-writable state  <-------  agent writes it (FILE-3)
 terminal identifiers  ------X------  never forwarded       (FILE-4)
 headless run prompt  ------------->  read-only inbox       (FILE-5)
```

### FILE-1. Host writes under project paths reject symlinks, hard links, and special files.

Why: the agent can replace a project path with a link to a host file.

Enforced: [safe-fs.ts](../packages/cli/src/safe-fs.ts) `safeReplaceProjectFile`, `ensureSafeProjectDir`  
Tests: [safe-fs.test.ts](../packages/cli/src/safe-fs.test.ts)

### FILE-2. Runfree mounts no host-wide secrets and no home config into the agent.

These are the only exceptions:

- per-project agent state
- sanitized per-agent config
- generated Git identity
- dependency volumes
- the read-only inbox

### FILE-3. Host code treats agent-writable state as hostile input.

- Agent-writable state is Codex config, the Claude session registry, and
  Codex rollout and session-index files.
- Host code opens only fixed directories, or directories that it derives
  from its own session timestamps. It never lists `sessions/` to find one.
- Every directory entry counts against an entry budget and a time limit.
- Host code opens a file without following links and without blocking. Each
  file counts against file and byte budgets.
- Rows built from this state are sanitized and labeled "Claude reported" or
  "Codex match".
- These rows are never the default row of the resume prompt.

Why: the agent can write any content, names, and links into this state.

Enforced: [codex-rollouts.ts](../packages/cli/src/runtime/codex-rollouts.ts) `scanCodexThreads`, [resume-selection.ts](../packages/cli/src/runtime/resume-selection.ts) `sanitizeAgentText`  
Tests: [codex-rollouts.test.ts](../packages/cli/src/runtime/codex-rollouts.test.ts), [resume-selection.test.ts](../packages/cli/src/runtime/resume-selection.test.ts)

### FILE-4. Runfree reads terminal identifiers only from the host launcher's own environment.

- Runfree never forwards a terminal identifier into a session container.

Why: the agent cannot set a terminal identifier to match another session.

Enforced: [terminal-identity.ts](../packages/cli/src/runtime/terminal-identity.ts) `captureTerminalIdentity`  
Tests: [terminal-identity.test.ts](../packages/cli/src/runtime/terminal-identity.test.ts), [session-container-template.test.ts](../packages/cli/src/runtime/session-container-template.test.ts)

### FILE-5. A headless run writes nothing into the project tree.

- `runfree run` reads the prompt file with a size limit. It does not follow
  a link or open a special file.
- It copies the prompt only into the read-only inbox, and deletes the copy at
  the end.
- Its run record and lock are in host state, which no session mounts.
- Runfree parses the agent's output as hostile input, with line and size
  limits.
- If the output is malformed, the result is unverified, never a success.
- A headless session records no terminal identity. `runfree resume` never
  offers it.

Why: the agent can race a host write into the agent's own tree.

Enforced: [headless-prompt.ts](../packages/cli/src/runtime/headless-prompt.ts) `readPromptFileBounded`, `writeInboxPrompt`  
Tests: [headless-run.test.ts](../packages/cli/src/runtime/headless-run.test.ts), [headless-prompt.test.ts](../packages/cli/src/runtime/headless-prompt.test.ts)

## Lifecycle

Every command that starts or stops the runtime takes the lifecycle lock.

### LIFE-1. Every refusal names its recovery command.

`runfree up` retries, and `runfree destroy --force` resets the project. A
refusal never leaves you stuck.

### LIFE-2. A Docker call that times out never counts as success.

After a timeout, an empty listing does not prove that nothing exists
(`R-2`).

### LIFE-3. Cleanup removes containers and images only by exact inspected ID, with this project's ownership labels.

- A name finds a candidate, but it authorizes nothing. A lookalike with
  foreign, partial, or conflicting labels is refused.
- `rebuild` and `destroy` revoke first and release last. Each step is
  durable, so an interrupted run continues where it stopped.
- `destroy --force` skips the strict helper-ownership check. It still
  removes only the exact IDs that it found.

Why: Runfree never removes what another project or user owns.

Enforced: [destroy.ts](../packages/cli/src/runtime/destroy.ts) `runFencedProjectDestroy`, [ingress-forwarder-ownership.ts](../packages/cli/src/runtime/ingress-forwarder-ownership.ts) `removeValidatedIngressForwarders`  
Tests: [destroy.test.ts](../packages/cli/src/runtime/destroy.test.ts), [ingress-forwarder.test.ts](../packages/cli/src/runtime/ingress-forwarder.test.ts)

### LIFE-4. `runfree stop` and `runtime reload-policy` need `--force` while a session can still hold authority.

- This applies to live or unknown sessions, a pending rebind, or an
  interrupted teardown.
- A reload of the same proxy checks every surviving session again.
- If no record can hold authority, the reload succeeds only if the
  firewall's live session set is empty.

Enforced: [runtime.ts](../packages/cli/src/runtime.ts) `stopRuntime`

### LIFE-5. A start finishes an interrupted teardown only on Docker's proof.

- The proof: the owner is dead, the container is absent or stopped, and no
  proxy can serve the session file.
- The record goes only after Docker shows the container is absent.
- Otherwise Runfree keeps the record and refuses. `destroy --force`
  reclaims it.

Enforced: [destroy.ts](../packages/cli/src/runtime/destroy.ts) `runFencedProjectDestroy`  
Tests: [destroy.test.ts](../packages/cli/src/runtime/destroy.test.ts)

### LIFE-6. Every Docker call of a launch settles before cleanup or lock release.

If one step fails while another runs, the launch waits for it. Meanwhile it
keeps the lock and removes nothing. So a late Docker call cannot create
something after cleanup.

### LIFE-7. Lock holds have limits.

| Limit | Value |
| --- | --- |
| Other commands wait for the lifecycle lock | up to 1 minute |
| One launch holds the lock | 50 s or less |
| Startup and reload get the lock | or refuse after about 60 s |
| Startup and reload subprocess work, per lock hold | 90 s |

- A fault, a suspended host, or a stalled disk can exceed these limits. Then
  a waiting command stops with a retry instruction, and admits and removes
  nothing.
- A heartbeat waits with a priority ticket. The ticket gives no lease and no
  lock. Only a dead requester's ticket is removed. A clock change cannot
  remove a live requester's ticket.

Enforced: [launch-lock-hold.ts](../packages/cli/src/runtime/launch-lock-hold.ts), [session-renewal-queue.ts](../packages/cli/src/runtime/session-renewal-queue.ts) `enqueueSessionRenewal`  
Tests: [session-renewal-queue.test.ts](../packages/cli/src/runtime/session-renewal-queue.test.ts)

### LIFE-8. A session that the proxy never activates stops itself.

If the proxy does not report the session active within 60 s, the session
exits with code 111. Normal teardown removes it.

Enforced: [session-entry.sh](../packages/agent-runtime/agent/session-entry.sh)  
Tests: [session-entry.test.ts](../scripts/session-entry.test.ts)

### LIFE-9. The short teardown after a normal exit needs exact proof.

- After the agent exits, the host can skip the disconnect and the stop.
- One inspection must show the same container and start time, the exit code,
  no restart or pause, and restart policy `no`.
- Any other answer, and every reconcile, runs the full revoke.

Enforced: [session-file-teardown.ts](../packages/cli/src/runtime/session-file-teardown.ts) `proveSessionContainerExited`  
Tests: [session-file-teardown.test.ts](../packages/cli/src/runtime/session-file-teardown.test.ts)

### LIFE-10. A deferred credential sync removes nothing.

- A sync inside a launch can defer, for example on a busy lock. It then
  removes no proxy credential and writes no receipt. The normal sync runs
  later.
- If a session file delete and its terminal stamp both fail, Runfree marks
  the record revoking. So a peer never reads it as live.

Why: a deferred sync must not look like a revoked credential.

### LIFE-11. Proxy recovery is limited and checked.

- Compatible-proxy recovery has one allowance per project: 120 s and at most
  two new proxies. Only `runtime recover --retry` resets it.
- A new proxy gets the network, the CA identity, and the OAuth volume. Runfree
  first checks that each one carries this project's labels.

Why: recovery cannot loop forever or adopt another project's state.

Enforced: [control-plane-rebind-recovery.ts](../packages/cli/src/runtime/control-plane-rebind-recovery.ts)

### LIFE-12. Short-lived helpers have time limits.

- Helpers never pull an image (`--pull never`).
- Runfree stops a deny probe at 30 s and other helpers at 120 s.
- The helper cleanup runs under the lock and takes about 15 s at most. If it
  cannot confirm its result, it refuses and names `runfree up` and
  `runfree destroy --force` (`R-2`).

See [Ephemeral Helpers](architecture.md#ephemeral-helpers).

Enforced: [ephemeral-helper.ts](../packages/cli/src/runtime/ephemeral-helper.ts) `runEphemeralHelper`  
Tests: [ephemeral-helper.test.ts](../packages/cli/src/runtime/ephemeral-helper.test.ts)

## Residual Risks

These risks remain. Risks that you cannot reduce are in
[Accepted by design](#accepted-by-design). Each approval, broad host, or
credential is a security decision.

### Network risks

| Risk | Worst case | You can |
| --- | --- | --- |
| Runfree checks host, method, and path, not intent. | The agent misuses the token, or sends data out in a `GET` query. | Use narrow tokens and few hosts. |
| Audit mode allows unlisted hosts for a time window. It never edits policy. | The agent reaches any host then. | Use `up --audit-network` only on purpose. |

### Git over HTTPS risks

| Risk | Worst case | You can |
| --- | --- | --- |
| A git token reaches every repository that it can access. | An approved push changes any of them. | Use fine-grained tokens. Keep pushes under `ask` ([`GIT-1`](#git-over-https)). |
| `gitPush: "deny"` blocks only the git push endpoint. | The agent pushes through the provider's REST or GraphQL API. | Add method rules on the API host. |
| A user-defined git host has no git handling rule. | Fetches and LFS batches wait under `ask`. A push is a plain write, not a git push. | Use a curated service where one exists. |

### Agent container risks

| Risk | Worst case | You can |
| --- | --- | --- |
| `runfree forward` and VNC show agent content on your host. | Hostile content hits your browser or viewer. | Use a maintained viewer and the random password. |
| Any agent process can use an enabled operational service. | Agent code reaches the service's hosts within its request rules, not just through the named agent CLI. | Confirm them at launch. They carry no proxy credential; see `runfree service explain <id>`. |

### MCP risks

| Risk | Worst case | You can |
| --- | --- | --- |
| Each eligible session answers an OAuth callback on `localhost` in your browser. | The session sends data through your browser, or reaches other localhost services with same-site requests. | Open only callbacks of logins that you started. |
| A host service on a loopback MCP entry's port makes the entry reach the host, even if added later. The MCP approval does not pin reach. | Tool calls run on the host, with no write approval. | Read the reach in `runfree mcp explain`. Runfree checks it at each launch and review. |
| A loopback server starts an OAuth flow at run time. | The proxy does not mediate it. Tokens land in the agent. | Use loopback servers that need no OAuth. |
| `mcp enable` discovery contacts the named host. | The host learns your IP address and the time. | Use `--no-discover`. Discovery sends no credentials. |
| On a broadly allowed host, only exact recorded endpoints are mediated. The grant scan covers only record-only hosts and hosts with a blocked or colliding endpoint. A later `host add` gives no new warning. | A login at another path, such as `/oauth/token/`, returns real tokens. | Keep OAuth hosts MCP-only ([`MCP-9`](#mcp)). |
| A hostile server claims another login at a broad, non-curated issuer. | That login's handle works at the hostile server. | Approve an `ALREADY ALLOWED` claim only for the same service. |
| An endpoint on a shared login host (Entra, Okta) captures every login at that URL. | Other apps there stop working in the sandbox. | Read the review warning. |
| Revoking one agent does not end a shared login. | The other agent keeps logging in until the next launch. | Revoke for both agents, then launch. |
| Login, refresh, and registration at a mediated endpoint need no approval. | The agent registers its own client. | Review the issuer. Bodies: 16 KiB, 30 a minute. |
| Two parallel `runfree mcp revoke` runs with no proxy can lose one clear. | One server keeps its OAuth state. | Run that revoke again. |

### Host services risks

| Risk | Worst case | You can |
| --- | --- | --- |
| A host-service tunnel is opaque. | Every session gets what the service allows. | Approve only services the agent may use freely. |
| The agent reaches whatever holds an approved port. The gateway reaches every host loopback listener, including root services and IDE servers. | Another process takes the port. A root-owned listener is refused only as "no visible listener". | Run `runfree host-service remove <name>` for a stopped service. |
| A new publication on an approved port stays reachable. | The agent reaches it. | Watch the `runfree status` warning. |
| A gateway change or withdrawal stops host services ([`NET-6`](#network)). | Host services fail. | Run `runfree rebuild`. |
| Host-service splices have no idle timeout. | An idle splice stays open. | Remove the service. |
| On Docker Engine the host relay is a process on the host network namespace. It parses nothing and binds only the gateway address. It runs on the proxy image's Node, so it shares that image's trust and update path. | A relay bug exposes approved ports to other containers on the host. A compromised proxy image also compromises the relay. | Keep the relay's shape, which topology proves; remove unused services. |
| On Docker Engine the relay binds without root or capabilities. | `host-service add` refuses a port below `net.ipv4.ip_unprivileged_port_start`, and refuses every port if that value cannot be read. | Use a port at or above the sysctl, or lower it on the host. |
| On Docker Engine a service on `0.0.0.0:<port>` is served directly, not relayed. | It is also reachable from the LAN and from other containers, as it was before Runfree. | Bind the service to `127.0.0.1`. |
| On Docker Engine the relay holds `<gateway>:<port>`. | A new wildcard bind of that port on the host fails. | Remove the service, or bind the new listener to `127.0.0.1`. |
| On Docker Engine a default-deny INPUT host firewall (ufw, firewalld) blocks the proxy's egress network. | Host services time out. | Allow the egress network to reach the gateway address. |
| New host-service connections fail for about 2 s after a reload. On Docker Engine this includes the relay binding a newly added port (a watch plus a 250 ms poll). | `host-service-unavailable`. | Retry. |

### Sessions and lifecycle risks

| Risk | Worst case | You can |
| --- | --- | --- |
| Two state roots on one project path share one runtime. | Either root's reconcile removes the other's sessions. | Give development runs a scratch `--workspace`. |
| A dead CLI's `docker run` can start a helper later. Lock holders sweep again for 180 s, but the client has no timeout. | It runs outside any lock; the firewall drops it. | Run `runfree destroy --force`. |
| A helper sweep can fail a legacy-builder build in progress. | A build fails. | Use BuildKit, the default. |

### Supply chain risks

| Risk | Worst case | You can |
| --- | --- | --- |
| Image builds run before the sandbox. | A build step uses host networking. | Review the Dockerfile and wide contexts (`runfree image approve-context`). |
| Homebrew trusts the tap and release assets. | A changed asset installs. | Check checksums. |

### Accepted by design

- **Audited WSS upgrades keep credential headers.** The passthrough cannot
  rewrite upgrade headers.
- **A handle-shaped `Basic` password passes the strip.** It is the agent's own
  value ([`GIT-4`](#git-over-https)).
- **Git LFS action credentials reach the agent.** They are provider-issued,
  not the stored token ([`GIT-6`](#git-over-https)).
- **The agent can change the whole project, including `.git`.** The project
  mount is read-write.
- **Agent code can read native agent login state.** It is per project.
- **A `/.well-known` `GET` query reaches a discovered host.** It is the same
  channel out as on any discovered host.
- **The grant check matches only standard OAuth fields.** The agent holds the
  code and verifier, so it chooses the shape.
- **Bodies over 256 KiB skip the grant scan on endpoint hosts.** Ordinary
  traffic there can be large.
- **Audited hosts do not refuse grants while the OAuth policy is invalid.**
  Audited hosts are outside policy.
- **Host-service access is per project.** The approval applies to every
  session.
- **The permanent firewall cut covers only pinned gateways.** A proxy restart
  recreates the whole table.
- **A dead callback forwarder frees its address.** OAuth state and PKCE still
  stop a captured code.
- **Checkout binding cannot tell apart volumes at the same path.** It is a
  scope key, not an authority ([Checkout Binding](architecture.md#checkout-binding)).
- **Helper cleanup selects containers by label.** Only a Docker socket holder
  can mint labels.
- **A same-host Docker user can mint Runfree labels.** The Docker daemon is
  trusted.
- **Transitive apt packages can drift.** The apt archives are live.
