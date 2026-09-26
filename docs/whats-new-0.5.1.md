# What's New in Runfree 0.5.1

0.5.1 hardens the startup path and removes the pre-release config migration.
The platform, install routes, and support terms are unchanged from
[0.5.0](whats-new-0.5.0.md).

The concise release body is [`release-notes/0.5.1.md`](release-notes/0.5.1.md).
This page has the detail.

## Breaking change: pre-v4 configs are refused

0.5.0 shipped config version 4, so only pre-release installs can hold an older
`.runfree/runfree.json`. Runfree no longer migrates those configs. Every
command, `runfree init` included, refuses:

- a `version` below 4;
- the removed top-level `agent` or `paths` keys;
- any `project.*` key other than `project.name`.

The config is read before runtime assets are materialized, so the refusal
writes nothing to the project or to XDG state. The error names the remedy:

```text
.runfree/runfree.json uses config version 3, which this release no longer migrates
move .runfree aside and run `runfree init` to create a current configuration, then re-add hosts and services
```

To start over, keep the old directory for reference and re-add what you need:

```bash
mv .runfree .runfree.pre-v4
runfree init
runfree host add api.github.com --read-only
runfree
```

Configs written by 0.5.0 are already version 4 and need nothing.

## Security fixes

### Deny-probe helper address

Startup runs direct-egress deny probes in a short-lived helper container on the
project agent image, attached to `agent_internal` in the agent's position.
In 0.5.0 that helper got whatever address Docker picked, and nothing kept it
out of the session pool (`.20` and up). A helper holding a session address
would be served by the proxy as that session.

The helper now gets a pinned address from a reserved block, `.13`–`.19`,
highest first. It skips the proxy, agent, and callback addresses, the gateway,
and any address already attached. When no address in the block is free, the
probes fail as not run before any `docker run`, and the refusal names the
remedies:

```bash
runfree forward stop
runfree destroy --force
```

As defense in depth, the session-file heartbeat and the IP reuse fence refuse
any source address outside the session pool before any Docker call.

### Docker calls that time out fail closed

`spawnSync` can report exit status 0 with an `ETIMEDOUT` error when a child
ignores SIGTERM and exits later. 0.5.0 read that as success with empty output,
so proxy containment checks, rebind inventory, and policy activation could read
a timed-out `docker ps` as "no containers". Status codes are now reserved:

| Outcome | Status |
| --- | --- |
| Timeout | 124 |
| Other spawn error (for example `ENOENT`, output overrun) | 125 |
| Killed by signal N | 128 + N |

A timed-out listing is never proof of absence, and a timed-out `git config` or
`git ls-files` no longer reads as "not set" or "not tracked".

### Bounded and swept startup helpers

Startup runs three kinds of short `--rm` helpers on the untrusted project agent
image: the deny probes, the CA trust-bundle render, and dependency-volume
preparation. In 0.5.1:

- A helper runs only while the project lifecycle lock is held, with
  `--pull never`.
- The Docker client is SIGKILLed at the helper bound: 30 s for deny probes,
  120 s otherwise. The lifecycle operation budget can shorten it.
- Before each spawn, Runfree writes `helpers-pending.json` into the host
  project state directory. The agent has no mount of that path. A clean exit
  clears it without a Docker call.
- If the marker is present when the lock is next taken (by `up`, a launch, or
  `runtime reload-policy --force`), Runfree removes this project's containers
  with the `ephemeral-helper` role label and waits until the listing is empty.
  This happens before any new helper runs or any session is admitted.
- A sweep that cannot confirm the helpers are gone keeps the marker and refuses
  the launch. Retry with `runfree up`, or reset the project with
  `runfree destroy --force`. A successful `destroy` clears the marker.

The known residuals (a create request still in flight when the client is
killed, and a Docker-socket holder minting the helper labels) are listed under
[Ephemeral Helpers](architecture.md#ephemeral-helpers).

## Faster startup and teardown

These changes remove Docker calls without changing what is checked:

- The egress-source proof at startup reads the batched route inspection it
  already has instead of running its own.
- The proxy validation marker is read only when verbose output needs it.
- On macOS, the CLI probes its own process start time once instead of on
  every host identity check.
- Token sync fences the proxy directly before each side effect, not at the top
  of every token iteration. A warm three-token watch run drops from 16 to 12
  marker reads. Tests replace the proxy's token store after a write and prove
  no later removal or receipt write happens.
- The exit denial summary uses the proxy id resolved before the session ran.
- `destroy` stops running project containers in one `docker container stop`
  call, chunked at 64 ids, and falls back to per-id stops only for a chunk
  that fails.

`RUNFREE_TIMINGS=1` now also prints a per-category count and total time for
every subprocess startup runs. Categories are the Docker subcommand only, never
arguments, ids, or output:

```bash
RUNFREE_TIMINGS=1 runfree up 2>&1 | grep 'timing: startup-ops'
```

```text
timing: startup-ops docker exec count=14 total=...ms
```

## Smaller improvements

- The proxy inspect during readiness has the same time bound as eligibility
  publication.
- A container refused at start because its address is in use is diagnosed from
  the Docker CLI's own status 125 and the daemon's stderr only. The helper's
  stdout never selects that diagnosis.
- [`security.md`](security.md) is rewritten as a short rule set. Mechanism
  detail moved into [`architecture.md`](architecture.md).

## For contributors

- The live Docker suite has two tiers. `make test-runtime-core` proves the
  trust boundary and is the gate for runtime, proxy, firewall, mount, and
  credential changes. `make test-runtime-extended` covers recovery, upgrades,
  load, and optional features. `make test-runtime` still runs both and is the
  release gate. A live file not listed as core in
  `tests/runtime/live/tiers.ts` runs as extended.
- Tests and `pnpm typecheck` now read `packages/runtime-contracts/src` too, so
  a source edit no longer waits for `pnpm build:runtime` to be tested. CI runs
  the static and unit gates before the runtime build.
- Live proxy probes judge a response by which component answered, not by the
  HTTP status alone.

```bash
make test-runtime-core
```

## Upgrading

1. End live sessions, then upgrade the binary:

   ```bash
   brew upgrade genged/tap/runfree
   # or
   curl -fsSL https://raw.githubusercontent.com/genged/runfree/main/scripts/install.sh | bash
   ```

2. If a project still has a pre-v4 config, follow
   [the breaking change steps](#breaking-change-pre-v4-configs-are-refused).
3. Start the project as usual. The agent image inputs changed, so the first
   start builds a new agent image and takes longer than a warm start.

   ```bash
   runfree
   ```

4. If the first start refuses because it cannot confirm leftover helpers are
   gone, run `runfree up` again, or `runfree destroy --force` to reset the
   project runtime.

The known limitations listed for [0.5.0](whats-new-0.5.0.md#known-limitations)
still apply.
