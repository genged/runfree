# What's New in Runfree 0.7.0

0.7.0 adds headless runs, request rules on service hosts, a Google Search
Console service, and MCP OAuth token endpoints on another host. Config version
4 is the same as in [0.6.0](whats-new-0.6.0.md). `.runfree/network-policy.json`
gains a version 4, written only when its content needs it. The platform,
install routes, and support terms are the same as in
[0.5.0](whats-new-0.5.0.md).

The concise release body is [`release-notes/0.7.0.md`](release-notes/0.7.0.md).
This page has the detail.

## Headless runs

`runfree run` runs one agent turn without a terminal: from a launchd job, a
script, or a detached tmux pane. It starts a normal per-session container
through the same admission path as `runfree claude`, and the agent works on
the live project folder.

```bash
runfree --workspace ~/proj run claude --prompt-file task.md --timeout 30m
runfree run codex --prompt-file task.md
runfree run pi --prompt-file task.md --accept-denied-writes
```

- Runfree sets each agent's headless mode and reads its JSON event stream to
  decide the result. An agent that exits 0 without a final success ends
  unverified (1), not as success.
- The prompt reaches the agent as its stdin, never on its command line. The
  container has no TTY and no open stdin.
- A run never prompts. A step that needs an answer, such as a policy approval,
  a service review, or a locked credential source, refuses with 65.
- A headless session has no approver, so the proxy denies an `ask` write at
  once instead of holding it. Before the launch, `run` prints one warning with
  the counts of hosts and MCP endpoints that can resolve to `ask`, and lists
  them in `run.json` under `askExposure`. The run starts either way.
  Interactive sessions still ask. A run that succeeds with denied writes exits
  68 unless you pass `--accept-denied-writes`.
- One run at a time per project: a second run exits 66. `--timeout` and
  signals exit 67.
- Each run keeps a record on the host only, under the project's state
  directory: the raw transcript, stderr, the final message, and `run.json`.
  No session can read it.
- `runfree resume` never offers a headless run's conversation.

Use a launchd `LaunchAgent` to schedule runs on macOS; cron is not supported.
See [Headless runs](cli.md#headless-runs) and
[Scheduling on macOS](cli.md#scheduling-on-macos).

## Request rules on service hosts

`runfree host rules <host>` now works on a host that an enabled service
allows. The setting is stored with the service and laid over the service's
rule, so `service diff --apply` and a re-enable keep it, and
`service disable` removes it.

```bash
runfree host rules github.com --deny-git-push
runfree host rules api.github.com --write deny
runfree host rules github.com                       # the enforced rule and its owner
runfree host rules github.com --clear
```

- Only permission fields can be set: `--method`, `--request-path-prefix`,
  `--read-only`, `--deny-git-push`, and `--write`. The service's
  classification fields stay. On an OAuth token host, your setting can only
  narrow the service's methods and paths.
- `--deny-git-push` is accepted only on a host where the service handles git.
- `host rules` without set flags prints the enforced rule, its owner, the
  service rule, and your setting. A set or `--clear` prints the rule before
  and after.
- A `--write` setting weaker than the service's write mode warns at
  `service enable`, `service configure`, and `service diff --apply`.
- An older direct rule on a service host still replaces the service's whole
  rule. A set there is refused and names `runfree host rules <host> --clear`.

See [Manage hosts](cli.md#manage-hosts) and
[A host rule on a service host is refused](troubleshooting.md#a-host-rule-on-a-service-host-is-refused).

## Google Search Console

The new `google-search-console` service calls the Search Console API with a
bearer token that the host makes from a Google service account. A new
`google-service-account` credential source signs the account's JWT on the
host; the key JSON stays in 1Password and never reaches the proxy or the
container.

```bash
runfree credential source add google-service-account gsc \
  --key-json-from-1password op://vault/gsc-sa/credential.json \
  --scope https://www.googleapis.com/auth/webmasters.readonly
runfree service explain google-search-console
```

- `add` checks the key and signs a test JWT before it saves the source, and
  pins the key's `client_email`.
- `credential sync --watch` keeps the parsed key in memory for at most 4
  hours.
- Search Analytics queries are `POST` requests, so under the default rule
  each one asks for approval. To keep the API read-only without a prompt per
  query, allow only `GET` and `POST` under its API paths; the proxy then
  refuses `PUT` and `DELETE` (site and sitemap changes) and the `/batch`
  endpoint, whatever the token's scope:

  ```bash
  runfree host rules searchconsole.googleapis.com --method GET --method POST \
    --request-path-prefix /webmasters/v3 --request-path-prefix /v1 --write allow
  ```

  The rule works only for Domain properties (`sc-domain:example.com`).

See [Host-owned sources](cli.md#host-owned-sources) and
`runfree service explain google-search-console` for the setup steps.

## MCP OAuth endpoints on another host

A server's OAuth metadata can put its token endpoint on another host than the
MCP endpoint. `runfree mcp enable` now accepts such an endpoint when the
server's own metadata names it, labels it in the review, and the proxy
mediates logins there. The agent never sees the real tokens.

- The proxy refuses an OAuth token or registration request that it does not
  mediate on a host that only MCP records allow, before the request leaves.
  An OAuth-guarded WebSocket upgrade is refused the same way, with the same
  explanation and remedy.
- `runfree doctor` and the session summary name this refusal and point at
  `runfree mcp enable` or `runfree mcp revoke`, not at `runfree host add`.
- `--oauth-host` adds a host as given. The proxy mediates a token or
  registration endpoint there only when the server's OAuth metadata names it.
- A login's client registration with `application_type: native` no longer
  waits for write approval.

See [OAuth hosts on another host](cli.md#oauth-hosts-on-another-host).

## Smaller improvements

- `runfree service explain <id>` prints any service's hosts, credential
  destinations, OAuth seeds, parameters, and setup notes, whether or not it is
  enabled. See [Services](cli.md#services).
- Directories under the agent's home that only hold Runfree's mount targets,
  such as `~/.local/share/pnpm` and `~/.pi`, are owned by the agent, not root.
  pnpm can now install a pinned pnpm version in the sandbox.
- The agent image ships Claude Code 2.1.310, Codex 0.164.0, Pi 1.4.0, and uv
  0.13.5, on a refreshed Ubuntu base.
- Dependencies with published security advisories are upgraded.

## Breaking changes

- `runfree mcp enable` no longer runs the OAuth login after it enables a
  server. It prints the `runfree mcp auth` command. Pass `--login` to run the
  login at once. `--no-login` is still accepted and does nothing.
- `runfree service explain` prints text by default. Scripts that parsed its
  JSON need `--json`.

## Upgrade notes

- **Desired policy version 4.** Runfree writes
  `.runfree/network-policy.json` as version 4 only when a service entry holds
  a `host rules` setting. Runfree 0.6.x refuses a version 4 file with
  `version must be one of: 2, 3`, so upgrade everyone who shares the project
  before you commit one. `runfree host rules <host> --clear` takes the file
  back to the lower version. See [Network Policy](cli.md#network-policy).
- **Running sessions block the proxy replacement.** The proxy's admission
  contract changed, so a new proxy cannot adopt sessions started by 0.6.x.
  End them before the first start, or run `runfree rebuild`.
- **Unmediated OAuth requests are refused.** A token or registration request
  to a host that only `runfree mcp enable` records allow is refused unless
  the proxy mediates it. If a login that worked before now fails, run
  `runfree mcp enable` again with discovery.
- **Image rebuild.** The agent and proxy image inputs changed, so the first
  start rebuilds the images and is slow.
