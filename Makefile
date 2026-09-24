SHELL := /bin/bash

.PHONY: help test test-all test-static test-unit test-agent test-proxy test-security test-templates test-cli-e2e test-cli-e2e-live test-runtime test-runtime-smoke test-runtime-live test-runtime-live-topology test-runtime-live-managed-launch test-runtime-live-egress test-runtime-live-connect-guard test-runtime-live-request-shape test-runtime-live-audit test-runtime-live-allowlist test-runtime-live-policy-mutation test-runtime-live-helper-reclaim test-live-session-admission-docker-desktop test-live-session-admission-orbstack test-live-session-admission-negative-docker-desktop test-live-session-admission-negative-orbstack test-live-session-admission-attached-docker-desktop test-live-session-admission-attached-orbstack test-live-session-renewal-docker-desktop test-live-session-renewal-orbstack test-live-session-independence-docker-desktop test-live-session-independence-orbstack test-live-session-admission-crash-docker-desktop test-live-session-admission-crash-orbstack test-live-session-admission-drift-docker-desktop test-live-session-admission-drift-orbstack reclaim-runtime-sandbox reclaim-runtime-sandbox-apply test-watch

help:
	@printf '%s\n' \
		'Targets:' \
		'  make test                 Static checks + Vitest suites' \
		'  make test-all             All static, unit, template, live runtime, and packaged offline/live tests (TEST_RUNTIME_BACKEND)' \
		'  make test-static          Syntax/config checks only' \
		'  make test-unit            All Vitest suites' \
		'  make test-agent           Runfree bootstrap Vitest suite' \
		'  make test-proxy           Proxy Vitest suite' \
		'  make test-security        Security-sensitive Vitest suites' \
		'  make test-templates       Docker Compose template validation' \
		'  make test-cli-e2e         Build dist/runfree and run packaged CLI scenarios' \
		'  make test-cli-e2e-live    Build dist/runfree and run its real-Docker lifecycle scenario' \
		'  make test-runtime         Run the whole live runtime security suite: every *.live.test.ts (TEST_RUNTIME_BACKEND, default docker-desktop)' \
		'                            Files run 4 at a time; TEST_RUNTIME_WORKERS=1 makes it serial on a memory-tight host' \
		'  make test-runtime-smoke   One live tranche (runtime-topology: one fixture, one session, 24 read-only proofs) as a per-commit Docker check' \
		'  make test-runtime-live    Run the migrated non-admission live tranches only (TEST_RUNTIME_BACKEND, default docker-desktop)' \
		'  make test-runtime-live-<tranche>  One migrated tranche: topology|managed-launch|egress|connect-guard|request-shape|audit|allowlist|policy-mutation' \
		'  make test-runtime-live-helper-reclaim  Ephemeral-helper tranche: bounded runs, exact-id reclaim, the pinned helper address' \
		'  make test-live-session-admission-docker-desktop  Run every standalone admission tranche on Docker Desktop' \
		'  make test-live-session-admission-orbstack  Run every standalone admission tranche on OrbStack' \
		'  make test-live-session-admission-negative-<backend>  Negative refusal tranche only' \
		'  make test-live-session-admission-attached-<backend>  Attached authority/consumer tranche only' \
		'  make test-live-session-renewal-<backend>  Renewal availability under sustained contention only' \
		'  make test-live-session-independence-<backend>       Session-independence replacement cases only' \
		'  make test-live-session-admission-crash-<backend>     Crash/recovery tranche only' \
		'  make test-live-session-admission-drift-<backend>     Mid-lifecycle drift tranche only' \
		'  make reclaim-runtime-sandbox  List Docker resources left by kept live runs' \
		'  make reclaim-runtime-sandbox-apply  Remove what reclaim-runtime-sandbox lists' \
		'  make test-watch           Vitest watch mode'

test: test-static test-unit

# The backend the live runtime suite runs on when folded into test-all.
# Docker Desktop is the gating backend for Item 4 (maintainer decision,
# 2026-08-14); OrbStack is deferred past the cutover and gates nothing, but
# TEST_RUNTIME_BACKEND=orbstack still selects it here.
TEST_RUNTIME_BACKEND ?= docker-desktop

# test-runtime runs the entire runtime-live project (every *.live.test.ts,
# admission tranches included), so it is the whole live gate on its own.
test-all: test test-templates test-runtime test-cli-e2e test-cli-e2e-live

test-static:
	@# Every tracked script, discovered rather than listed: a hand-maintained
	@# list silently stops covering whatever was added after it. `bash -n a b`
	@# parses only `a` and turns the rest into positional parameters, so each
	@# file also needs its own invocation. The empty check keeps a failed
	@# discovery from passing as "nothing to check".
	@scripts="$$(git ls-files -- '*.sh')"; \
	test -n "$$scripts" || { echo 'test-static: found no tracked shell scripts; the syntax gate would pass vacuously' >&2; exit 1; }; \
	for script in $$scripts; do \
		echo "syntax: $$script"; \
		case "$$(head -n 1 "$$script")" in \
			*bash) bash -n "$$script" || exit 1 ;; \
			*) sh -n "$$script" && bash -n "$$script" || exit 1 ;; \
		esac; \
	done
	@scripts="$$(git ls-files -- '*.cjs' '*.mjs')"; \
	test -n "$$scripts" || { echo 'test-static: found no tracked standalone Node scripts; the parse gate would pass vacuously' >&2; exit 1; }; \
	for script in $$scripts; do echo "parse: $$script"; node --check "$$script" || exit 1; done
	pnpm exec tsx scripts/check-test-inventory.ts
	@# Spec-citation drift gate (evolution-strategy A4). No-ops on public
	@# checkouts without local/specs; never passes vacuously when specs exist.
	pnpm exec tsx scripts/check-spec-citations.ts
	@# Generation-family terminology gate (output contract D8): user-visible
	@# strings name the family, never a bare "generation".
	pnpm exec tsx scripts/check-terminology.ts
	@# Public-documentation gate: every relative link and heading anchor must
	@# resolve in a clone that has no local/ records.
	pnpm exec tsx scripts/check-public-docs.ts
	@# Published release notes are fixed. No-ops in a checkout without release
	@# tags, and says so rather than reporting a pass.
	pnpm exec tsx scripts/check-release-notes-frozen.ts
	@if rg -n --glob '!**/container-inventory.ts' --glob '!**/*.test.ts' -- 'label=com\.docker\.compose\.' packages/cli/src; then \
		echo 'Compose-label enumeration filters must go through runtime/container-inventory.ts; a hand-written filter silently selects the wrong container set' >&2; \
		exit 1; \
	fi
	@# `$$` is make's escape for one literal `$`, so rg receives the regex
	@# `label=(\$\{PROJECT_ID_LABEL\}|io\.runfree\.project-id)=` — both branches
	@# are mutation-verified to catch a planted filter (constant and spelled-out).
	@if rg -n --glob '!**/container-inventory.ts' --glob '!**/images.ts' --glob '!**/*.test.ts' -- 'label=(\$$\{PROJECT_ID_LABEL\}|io\.runfree\.project-id)=' packages/cli/src; then \
		echo 'project-id label filters must go through runtime/container-inventory.ts (images.ts keeps its image-scope filters)' >&2; \
		exit 1; \
	fi
	pnpm check
	pnpm typecheck
	jq empty package.json packages/proxy/package.json packages/cli/templates/network-policy.json packages/agent-runtime/runtime-inputs.lock.json

# The live and packaged-E2E projects exist whenever their variables are set, and
# a variable given on the make command line reaches every recipe's environment:
# `make test-all TEST_RUNTIME_BACKEND=...` would otherwise run the whole live
# suite here and again in test-runtime. Their own targets run them.
test-unit:
	env -u TEST_RUNTIME_BACKEND -u RUNFREE_E2E_ARTIFACT -u RUNFREE_E2E_DOCKER_HOST pnpm test

test-agent:
	pnpm exec vitest run scripts/installable-cli-admin.test.ts scripts/installable-cli-help.test.ts scripts/installable-cli-init.test.ts scripts/installable-cli-intent.test.ts scripts/installable-cli-runtime.test.ts scripts/installable-cli-wrapper.test.ts

test-proxy:
	pnpm exec vitest run packages/proxy/src/policy.test.ts

# A filter matching no file is not an error to Vitest: the run reports green over
# whatever else matched, so scripts/check-test-inventory.ts asserts every path
# named in this file still exists.
test-security:
	pnpm exec vitest run scripts/admin-mcp.test.ts scripts/admin-token-policy.test.ts packages/cli/src/runtime.test.ts packages/cli/src/proxy-nftables-proof.test.ts packages/proxy/src/policy.test.ts packages/proxy/src/server-core.test.ts packages/proxy/src/server-guard.test.ts packages/proxy/src/server-tunnels.test.ts packages/proxy/src/server-provenance.test.ts packages/proxy/src/server-approvals.test.ts packages/proxy/src/server-session-identity.test.ts packages/proxy/src/server-mcp.test.ts packages/proxy/src/server-oauth.test.ts packages/proxy/src/server-graphql.test.ts packages/proxy/src/firewall/nftables.test.ts packages/proxy/src/firewall/env.test.ts packages/proxy/src/firewall/command.test.ts packages/proxy/src/firewall/supervisor.test.ts packages/proxy/src/entrypoint.test.ts

test-templates:
	pnpm build:runtime
	pnpm exec tsx scripts/validate-runtime-compose.ts

.PHONY: test-cli-e2e-build

# Share one fresh artifact per make invocation, including standalone E2E runs.
# Phony so an existing binary never substitutes for building the current tree.
test-cli-e2e-build:
	pnpm run build:bin

test-cli-e2e: test-cli-e2e-build
	RUNFREE_E2E_ARTIFACT="$(CURDIR)/dist/runfree" scripts/run-cli-e2e.sh --no-build

test-cli-e2e-live: test-cli-e2e-build
	RUNFREE_E2E_ARTIFACT="$(CURDIR)/dist/runfree" TEST_RUNTIME_BACKEND=$(TEST_RUNTIME_BACKEND) scripts/run-cli-e2e.sh --no-build --live

# The live runtime security proof: the whole runtime-live project — every
# *.live.test.ts, session-admission tranches included. Replaces the retired
# tests/runtime/sandbox.sh (which was pre-flip: it exec'd into the removed shared
# `agent` service). Each describe block provisions and destroys its own runtime;
# override the backend with `make test-runtime TEST_RUNTIME_BACKEND=orbstack`.
# Use the narrower targets below to iterate on one tranche.
#
# Files run four at a time (`TEST_RUNTIME_WORKERS`, default 4 — see
# vitest.config.ts). Four concurrent runtimes are four proxies and their
# sessions: on a host short of memory, or one already swapping, run
# `make test-runtime TEST_RUNTIME_WORKERS=1` for the one-at-a-time behaviour
# every live measurement before 2026-09-21 was taken under.
test-runtime:
	TEST_RUNTIME_BACKEND=$(TEST_RUNTIME_BACKEND) pnpm exec vitest run --project runtime-live

# The smoke tier: one live tranche on a Docker host in a few minutes, meant to
# run per commit so drift between the CLI and the live fixture surfaces in
# hours rather than at the next full gate. runtime-topology is the pick because
# it is the widest proof per unit time — one fixture, one standing session, and
# the read-only topology/capability, egress-containment, and CONNECT-guard
# tranches — and its fixture is the seeded sandbox project the other ported
# tranches share, so a fixture-level break shows here first. It is a subset of
# `test-runtime`, not a substitute: runtime, proxy, firewall, network, or
# credential changes still need the full gate.
test-runtime-smoke:
	TEST_RUNTIME_BACKEND=$(TEST_RUNTIME_BACKEND) pnpm exec vitest run --project runtime-live runtime-topology

# Standalone live tranches, provisioning their own minimal fixture instead of
# running behind the cumulative sandbox.
#
# These two targets run every `*.live.test.ts` under tests/runtime: the negative
# tranche, the crash tranche, and the drift tranche. Each describe block
# provisions and destroys its own runtime, so this is several full builds. Use
# the per-tranche targets below while iterating on one of them.
test-live-session-admission-docker-desktop:
	TEST_RUNTIME_BACKEND=docker-desktop pnpm exec vitest run --project runtime-live

test-live-session-admission-orbstack:
	TEST_RUNTIME_BACKEND=orbstack pnpm exec vitest run --project runtime-live

# Negative only: unknown participant, capability drop and its mutation, address
# conflict at start, and convergence after a proxy restart.
test-live-session-admission-negative-docker-desktop:
	TEST_RUNTIME_BACKEND=docker-desktop pnpm exec vitest run --project runtime-live session-admission-negative

test-live-session-admission-negative-orbstack:
	TEST_RUNTIME_BACKEND=orbstack pnpm exec vitest run --project runtime-live session-admission-negative

# Drift only: the world changes under a paused lifecycle (address taken before
# start, second network attached after start, address reuse identity).
test-live-session-admission-drift-docker-desktop:
	TEST_RUNTIME_BACKEND=docker-desktop pnpm exec vitest run --project runtime-live session-admission-drift

test-live-session-admission-drift-orbstack:
	TEST_RUNTIME_BACKEND=orbstack pnpm exec vitest run --project runtime-live session-admission-drift

# Attached only: an activated session's authority is exactly its source IP in
# both paired consumers, and drift after the running proof is refused by lease
# renewal. One of the three files the old single attached tranche was split
# into; `attached-support.ts` holds what they share.
test-live-session-admission-attached-docker-desktop:
	TEST_RUNTIME_BACKEND=docker-desktop pnpm exec vitest run --project runtime-live session-admission-attached

test-live-session-admission-attached-orbstack:
	TEST_RUNTIME_BACKEND=orbstack pnpm exec vitest run --project runtime-live session-admission-attached

# Renewal availability only: every short-lease session renewing under sustained
# competing launches.
test-live-session-renewal-docker-desktop:
	TEST_RUNTIME_BACKEND=docker-desktop pnpm exec vitest run --project runtime-live session-admission-renewal

test-live-session-renewal-orbstack:
	TEST_RUNTIME_BACKEND=orbstack pnpm exec vitest run --project runtime-live session-admission-renewal

# The session-independence replacement cases only: sessions surviving a
# compatible proxy replacement (L5), a candidate whose allowed destination IPs
# changed between the checks (L6), and containment after a proved boundary
# violation (L3). Its own file since the attached tranche was split, so the
# ramp-heavy replacement case no longer needs a name filter to run without the
# authority tranche ahead of it. RUNFREE_LIVE_REPLACEMENT_SESSIONS overrides
# how many sessions that case carries across the replacement.
test-live-session-independence-docker-desktop:
	TEST_RUNTIME_BACKEND=docker-desktop pnpm exec vitest run --project runtime-live session-independence

test-live-session-independence-orbstack:
	TEST_RUNTIME_BACKEND=orbstack pnpm exec vitest run --project runtime-live session-independence

# Session entry gate negative only: a project image whose entry sends before
# activation is refused as a provisioning peer, and the runtime still admits.
# The gate's positive (first request succeeds) and reclaim (entry timeout)
# cases run in the attached tranche, because only the production launch
# activates.
test-live-session-entry-gate-docker-desktop:
	TEST_RUNTIME_BACKEND=docker-desktop pnpm exec vitest run --project runtime-live session-entry-gate

test-live-session-entry-gate-orbstack:
	TEST_RUNTIME_BACKEND=orbstack pnpm exec vitest run --project runtime-live session-entry-gate

# Crash only: SIGKILL at each lifecycle transition, then recovery to empty.
# No transition is skipped: preflight reclaims records whose owning host process
# is gone, which is what the after-start transition needed.
test-live-session-admission-crash-docker-desktop:
	TEST_RUNTIME_BACKEND=docker-desktop pnpm exec vitest run --project runtime-live session-admission-crash

test-live-session-admission-crash-orbstack:
	TEST_RUNTIME_BACKEND=orbstack pnpm exec vitest run --project runtime-live session-admission-crash

# The migrated non-admission live runtime security tranches (topology, managed
# launch, egress containment, CONNECT guard, request shape, audit mode,
# empty-allowlist lifecycle) — the ones ported off the retired
# tests/runtime/sandbox.sh. This is a subset of `make test-runtime` (which also
# runs the admission tranches); use it to iterate on the ported security proof.
# The three read-only tranches (topology, egress containment, CONNECT guard)
# share one provisioned fixture and one standing session inside
# tests/runtime/live/runtime-topology.live.test.ts; the per-tranche targets
# below select their describe blocks with -t. Other tranches provision and
# destroy their own runtime. Backend is $(TEST_RUNTIME_BACKEND) (default
# docker-desktop); override with `make test-runtime-live TEST_RUNTIME_BACKEND=orbstack`.
test-runtime-live:
	TEST_RUNTIME_BACKEND=$(TEST_RUNTIME_BACKEND) pnpm exec vitest run --project runtime-live \
		runtime-topology managed-launch request-shape audit-mode allowlist-lifecycle live-policy-mutation

test-runtime-live-topology:
	TEST_RUNTIME_BACKEND=$(TEST_RUNTIME_BACKEND) pnpm exec vitest run --project runtime-live runtime-topology -t "runtime topology and capability floor"

test-runtime-live-managed-launch:
	TEST_RUNTIME_BACKEND=$(TEST_RUNTIME_BACKEND) pnpm exec vitest run --project runtime-live managed-launch

test-runtime-live-egress:
	TEST_RUNTIME_BACKEND=$(TEST_RUNTIME_BACKEND) pnpm exec vitest run --project runtime-live runtime-topology -t "egress containment"

test-runtime-live-connect-guard:
	TEST_RUNTIME_BACKEND=$(TEST_RUNTIME_BACKEND) pnpm exec vitest run --project runtime-live runtime-topology -t "pre-TLS CONNECT guard"

test-runtime-live-request-shape:
	TEST_RUNTIME_BACKEND=$(TEST_RUNTIME_BACKEND) pnpm exec vitest run --project runtime-live request-shape

test-runtime-live-audit:
	TEST_RUNTIME_BACKEND=$(TEST_RUNTIME_BACKEND) pnpm exec vitest run --project runtime-live audit-mode

test-runtime-live-allowlist:
	TEST_RUNTIME_BACKEND=$(TEST_RUNTIME_BACKEND) pnpm exec vitest run --project runtime-live allowlist-lifecycle

test-runtime-live-policy-mutation:
	TEST_RUNTIME_BACKEND=$(TEST_RUNTIME_BACKEND) pnpm exec vitest run --project runtime-live live-policy-mutation

# Ephemeral helpers only: a normal up pins the deny-probe helper in .13-.19 and
# leaves no residue; a hung helper is SIGKILLed at a test-shortened bound and
# removed by exact id; a CLI killed mid-helper leaves residue the next lock
# holder reclaims; an exhausted helper block refuses with its remedies. It also
# checks the daemon behaviour the removal proof assumes (image id, IPAM pin,
# network id, cidfile shape, address-in-use status). Its own fixture; the full
# path keeps the filter checked by scripts/check-test-inventory.ts.
test-runtime-live-helper-reclaim:
	TEST_RUNTIME_BACKEND=$(TEST_RUNTIME_BACKEND) pnpm exec vitest run --project runtime-live tests/runtime/live/ephemeral-helper-reclaim.live.test.ts

reclaim-runtime-sandbox:
	tests/runtime/reclaim-sandbox-runtimes.sh

reclaim-runtime-sandbox-apply:
	tests/runtime/reclaim-sandbox-runtimes.sh --apply

test-watch:
	pnpm run test:watch
