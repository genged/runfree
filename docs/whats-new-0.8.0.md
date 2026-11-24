# What's New in Runfree 0.8.0

0.8.0 adds Linux with Docker Engine as a supported platform, 1Password
connection sources for runs that must never prompt, and several lifecycle
fixes. Config version 4 is the same as in [0.6.0](whats-new-0.6.0.md), and
`.runfree/network-policy.json` versions are the same as in
[0.7.0](whats-new-0.7.0.md).

The concise release body is [`release-notes/0.8.0.md`](release-notes/0.8.0.md).
This page has the detail.

## Linux with Docker Engine

Linux on arm64 and x64 with native Docker Engine and Docker Compose is now
supported, next to Apple Silicon macOS with Docker Desktop.

```bash
curl -fsSL https://raw.githubusercontent.com/genged/runfree/main/scripts/install.sh | bash
```

- The release publishes `linux-arm64` and `linux-x64` binaries next to
  `darwin-arm64`, with SHA-256 checksums. The Linux binaries are not signed.
- The binaries need glibc. The install script refuses a musl system, such as
  Alpine, before it downloads; build from source there.
- [Host services](cli.md#host-services-on-linux) work on a local, rootful
  Docker Engine through one more container, the host relay. It forwards from
  the Docker gateway to the host's loopback and accepts only the project's
  proxy. `runfree up`, `down`, `destroy`, and `rebuild` manage it. Rootless
  Docker and remote daemons refuse `runfree host-service add`.
- On every backend, `host-service add` now refuses a port that a container
  publishes, and `runfree status` and each launch warn when a container
  publishes an approved port later.

See [Install](../README.md#1-install) and
[Supported Release Shape](project-brief.md#supported-release-shape).

## 1Password connection sources

A `1password` connection source logs in to 1Password with a service account,
so a read never asks a person: no desktop-app unlock, no Touch ID, no
approval dialog. Connection sources need macOS, because the login is kept in
the macOS login Keychain.

```bash
runfree credential source 1password automation
runfree credential set-source github --from-1password op://Automation/github/token --via automation --replace-source
runfree credential source check automation
runfree credential source login automation
```

- `credential source 1password <name>` reads the token with hidden input, or
  from stdin with `--token-stdin`. It checks the token with 1Password, prints
  the vaults the account can read, and only then saves it.
- `--via <connection>` names the connection that a binding reads through. It
  works on `credential set-source`, `credential add`, `service enable`, and
  `mcp enable`, for an `op://` reference or for the 1Password key of a `jwt`
  or `google-service-account` source.
- Each read gives the token only to the `op` process, with a minimal host
  environment, in Runfree's host config directory. The token never reaches
  the project, the agent, the proxy, or a log.
- `credential source login <name>` rotates the token and keeps every binding
  that reads through the source.
- Runfree checks whether the login Keychain is locked before it starts
  `security`, so a sync or a run on a locked Mac fails at once and does not
  open an unlock dialog.
- A service account reads only the vaults it was granted, not a personal
  vault such as Private. Put the items a run needs in a shared vault.
- The Keychain item trusts `/usr/bin/security`, so any process that runs as
  your macOS user can read the token without a prompt. See
  [Credentials](security.md#credentials).

See [1Password connection sources](cli.md#1password-connection-sources).

## Runs that never prompt

`runfree run` now reads only credential sources that cannot ask a person:
environment variables, and 1Password references or signing keys read through
a connection source. It refuses a 1Password desktop-app read and every
command source with exit 65, before the prompt copy, Docker, or any
credential read. Each refusal prints the fix:

```text
runfree error: run refused (65): github uses the 1Password app, which may ask
    fix: runfree credential set-source github --from-1password op://<vault>/<item>/<field> --via automation --replace-source
runfree error: the headless run did not start
```

- Before the launch, `run` also checks each connection login once with
  1Password. A locked Keychain, a missing login, or a refused login exits 65.
- The same rule holds for every read inside the run, including the run's
  credential watcher. A Keychain or 1Password failure after the launch keeps
  the proxy's last good value, so a screen lock does not stop a run.
- `runfree credential status` shows for each binding whether a run can read
  it.

See [Headless runs](cli.md#headless-runs).

## Headless runs end after the final event

A background job that the agent started, such as a dev server, can keep the
agent running after its turn ends. When the agent's last output closes its
turn and the agent has not exited 30 seconds later, Runfree stops its
container. The run keeps the result of that final event, so a final success
exits 0. `run.json` records `stoppedAfterFinalEvent`, and the summary prints
a note. Runfree keeps the newest 200 run records.

See [Headless runs](cli.md#headless-runs) and
[A headless run stays in `runfree sessions` after its result](troubleshooting.md#a-headless-run-stays-in-runfree-sessions-after-its-result).

## Smaller improvements

- Ctrl-C, SIGTERM, or a closed terminal (SIGHUP) stops and tears down an
  attached `runfree claude`, `codex`, `pi`, or `shell` session, then exits
  130, 143, or 129. A second signal stops the container at once.
- A session started by an older Runfree keeps running after a CLI upgrade.
  A session also keeps running when the kernel kills one of its child
  processes for lack of memory. See
  [Session Admission](architecture.md#session-admission).
- Runfree writes `.runfree/network-policy.json` and
  `.runfree/network-policy.local.json` indented, with fields in a fixed
  order. A one-host change shows as a few changed lines. Approval reads the
  parsed policy, so a reformatted file needs no new approval.
- `credential status` and `credential source show` print `1password` in
  place of an `op://` reference. Pass `--show-refs` to print it.
- `credential set-source` saves the binding and reports `proxy sync: pending`
  when the proxy does not run the current policy yet. A sync that keeps a
  stale value says which tokens stayed stale.
- `service enable` explains a token name that a direct token in the other
  policy layer already uses, and names the commands that resolve it.
- A launch warns when the proxy withholds the host-service gateway, and names
  `runfree rebuild`.
- `mcp enable` of a server whose OAuth hosts changed starts new OAuth state
  for that server.
- `runfree runtime recover --retry` re-proves a recovery candidate at once.
- A torn runtime generation pointer no longer blocks `runfree destroy
  --force`.
- A wide image build context rebuilds only when the Dockerfile changes. Run
  `runfree rebuild` after you change a file that the Dockerfile copies in.
  See [Project Agent Image](cli.md#project-agent-image).
- The agent image ships Claude Code 2.1.322, Codex 0.167.2, and Pi 1.5.2, on
  a refreshed Ubuntu base.

## Breaking changes

- **Pi needs the `agent-pi` service.** Each Pi launch first reviews the new
  credentialless `agent-pi` service, which allows Pi's read-only model
  catalog. An interactive launch offers it. `runfree run pi` and other
  non-interactive launches refuse until you run
  `runfree service enable agent-pi`. Model-provider access is still separate.
- **Runs refuse sources that may ask.** A scheduled `runfree run` that read
  1Password through the desktop app or used a command source now exits 65.
  Add a connection source and rebind with `--via`, or use an environment
  variable source.

## Upgrade notes

- **Connection bindings need 0.8.0.** A binding saved with `--via` is stored
  in a form that Runfree 0.7.x refuses, so 0.7.x cannot silently turn it into
  a desktop-app read. Before a downgrade, rebind it without `--via`.
- **One-time policy diff.** The first command that writes
  `.runfree/network-policy.json` rewrites the whole file in the new indented
  format. The content and its approval do not change.
- **Image rebuild.** The agent and proxy image inputs changed, so the first
  start rebuilds the images and is slow.
