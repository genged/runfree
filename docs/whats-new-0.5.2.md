# What's New in Runfree 0.5.2

0.5.2 fixes the release process. It does not change runtime behavior. The CLI
commands, proxy, agent image sources, config version 4, and
`.runfree/network-policy.json` format are the same as in
[0.5.1](whats-new-0.5.1.md). The platform, install routes, and support terms
are the same as in [0.5.0](whats-new-0.5.0.md).

The concise release body is [`release-notes/0.5.2.md`](release-notes/0.5.2.md).
This page has the detail.

## Why this release exists

The release commit and its `v<version>` tag are pushed together. Because of
this, the per-commit Test workflow cannot pass on the release commit before the
tag exists. In 0.5.1 the release lane gated on `make test-unit` only. The
v0.5.1 commit passed the unit tests, and the release was published. Then Test
failed on that commit: Biome's unused-variable rule found a `releaseTargets`
declaration in `scripts/release-contract.test.ts` that nothing read any more.

0.5.2 removes that variable and closes the gap in two places: in CI and before
the tag.

## Release lane runs the full verification

`.github/workflows/release-lane.yml` no longer has its own `unit-tests` job.
Its new `verify` job calls `.github/workflows/verify.yml`, the same reusable
workflow that the Test workflow calls on every main commit. It runs at the
resolved release SHA:

```yaml
verify:
  name: Verify
  needs: [resolve, prepare]
  if: needs.prepare.outputs.ready == 'true'
  uses: ./.github/workflows/verify.yml
  with:
    ref: ${{ needs.resolve.outputs.sha }}
    artifact-namespace: ${{ needs.resolve.outputs.tag }}
```

`build-macos` and `publish` now depend on `verify`. A release commit that fails
static checks, unit tests, template validation, or the offline packaged E2E
lane is not built, signed, or published. Test and Release use one workflow
file, so their checks cannot drift apart.

The live Docker runtime suite is still not part of the release pipeline.
[`security.md`](security.md) states this limit. `make test-runtime` needs a
Docker host and runs by hand. A release has proven it only if its acceptance
record says so.

## `make test-release`: the pre-tag gate

`make test-release` runs the checks that the Test workflow runs on a release
commit, so a maintainer can find a failure before the tag exists:

```bash
make test-release
```

It is equal to:

```bash
make test-static test-unit test-templates test-cli-e2e
```

It needs the Docker CLI (for Compose template validation) and Bun (for the
packaged binary). It does not need a Docker daemon, and it does not run the
live runtime suite. The embedded-asset freshness check is left out, because the
release regenerates and commits the assets itself. `make help` lists the new
target, and [`testing.md`](testing.md) describes it.

## Smaller improvements

- The E2E scenarios LH-09, LH-12, and LH-23 in
  `e2e/support/scenario-program.ts` changed from `Implemented-failing` to
  `Partial`. The defects they tracked are fixed, and their tests still assert
  the original invariants:
  - LH-09: a second unchanged `service enable --no-reload` leaves owned state
    unchanged.
  - LH-12: the packaged live lifecycle passed managed-session liveness on
    Docker Desktop on 2026-09-18.
  - LH-23: `inbox clean --all` keeps a forged hard link.

  They are `Partial` and not `Implemented`, because PTY cases and the Docker
  inbox mount are still not proved. No scenario is `Implemented-failing` now.
- The offline packaged E2E lane has 24 tests. All 24 passed on 2026-09-26
  (`make test-cli-e2e`, 7 files).
- [`testing.md`](testing.md) and [`security.md`](security.md) now describe the
  release gate as it is.

To see the scenario program report, run the offline lane:

```bash
make test-cli-e2e
```

## Breaking changes

None. Commands, flags, config, policy, and runtime state are unchanged.

## Upgrading

1. End live sessions, then upgrade the binary:

   ```bash
   brew upgrade genged/tap/runfree
   # or
   curl -fsSL https://raw.githubusercontent.com/genged/runfree/main/scripts/install.sh | bash
   ```

2. Start the project as usual:

   ```bash
   runfree
   ```

No runtime source changed. If a project Dockerfile under `.runfree/image/`
references the `RUNFREE_VERSION` build argument, the new version changes the
image input, and the first start builds that image again.

The known limitations listed for [0.5.0](whats-new-0.5.0.md#known-limitations)
still apply.

## For contributors

Run `make test-release` before you push a release commit and its tag. The CI
release lane runs the same checks, but a local run finds a failure before the
tag is public.
