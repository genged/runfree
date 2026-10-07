# Writing Runfree Documentation

This page is the standard for Runfree's public documentation: the README,
`CONTRIBUTING.md`, `SECURITY.md`, and everything under `docs/`. It says which
page owns which topic, how to write for the people who read them, and which of
these rules `make test` enforces.

## Who reads what

Three groups read these pages, and each page is written for one of them:

- People installing and using Runfree read the README, [cli.md](cli.md),
  [team-workflow.md](team-workflow.md), and
  [troubleshooting.md](troubleshooting.md). They want the command to run and
  what it changes.
- People deciding whether to trust Runfree read [security.md](security.md),
  [architecture.md](architecture.md), and `SECURITY.md`. They want the
  mechanism, its limits, and the proof.
- Contributors read `CONTRIBUTING.md`, [testing.md](testing.md), and
  [project-brief.md](project-brief.md).

## Which page owns which topic

Each topic has one owning page. Other pages link to it instead of restating it,
so a change only has to be documented once.

| Page | Owns |
| --- | --- |
| `README.md` | What Runfree is, install, the quickstart, and the link to the current release's "what's new" page |
| [cli.md](cli.md) | Every command, flag, and default; output conventions; config and policy file formats as a user edits them |
| [architecture.md](architecture.md) | How the CLI, proxy, and agent container fit together; lifecycle, state, generation families, policy and credential models |
| [security.md](security.md) | The threat model, trust boundary, what stops what, residual risks, and what the tests do and do not prove |
| `SECURITY.md` | Supported versions, how to report a vulnerability, and a short boundary summary that links to security.md |
| [team-workflow.md](team-workflow.md) | What a team commits under `.runfree/`, and how policy and service changes are reviewed |
| [troubleshooting.md](troubleshooting.md) | Symptoms, the error text a user sees, and the remedy for each |
| [testing.md](testing.md) | What each test layer proves and where its proof stops |
| [project-brief.md](project-brief.md) | The problem, product model, audience, release shape, and source map |
| `CONTRIBUTING.md` | Setup, the checks to run before a pull request, review expectations, and this standard's place in it |
| `AGENTS.md` | Instructions for coding agents working on this repository: the source map and project rules |
| [index.md](index.md) | The table of contents for `docs/` |
| `docs/release-notes/<version>.md` | The GitHub release body for one version |
| `docs/whats-new-<version>.md` | The detailed page for one version |

When a change is user-visible (a command, flag, default, output line, error
message, exit code, policy or config field), update the owning page in the
same pull request. If nothing needs to change, say why in the pull request.

## How to write it

Write the fact a reader can act on. "`runfree host add` writes the host to
`.runfree/network-policy.json` and reloads the proxy" is useful; "Runfree makes
managing hosts easy" is not.

- Name things the way the code does. Use the command, flag, and file names
  exactly, in code formatting.
- Always say which generation family you mean: effective policy generation
  or control plane generation, never a bare "generation" (see
  [Generation Families](architecture.md#generation-families)).
- Say what Runfree does not do as plainly as what it does. A security claim
  states its limit next to it.
- Show commands as complete lines in a fenced `bash` block. Placeholders use
  `<angle-brackets>`; optional parts use `[brackets]`.
- Link to source files with relative links when the reader may want the
  mechanism, except in architecture.md (see below). Never link into
  `local/`, which is not published.
- Write [architecture.md](architecture.md) as a high-level explanation, not a
  detailed design. Say what each part does, what it trusts, and what happens
  across the lifecycle, in plain words. Leave out source paths, function and
  type names, field names, constants, limits, and step-by-step algorithms; the
  code and its tests own those. Name a source file only when the idea cannot
  be explained without it. Exact commands and flags stay in
  [cli.md](cli.md); security limits and proof stay in
  [security.md](security.md).
- Keep each page's existing heading style.

## Release documents

Each release has two documents, written before the release is tagged and never
changed after:

- `docs/release-notes/<version>.md` is the GitHub release body: one paragraph,
  then a bulleted list of the important changes and any compatibility or
  upgrade warning.
- `docs/whats-new-<version>.md` is the detailed page: runnable examples for
  user-visible changes, smaller improvements, breaking changes, and upgrade
  notes. The README links the current one.

They describe their own release, so the checks below that compare docs with
today's command surface skip them.

## What the checks enforce

`make test` (static checks plus unit tests) fails when:

- a relative link or heading anchor does not resolve in a fresh clone
  (`scripts/check-public-docs.ts`);
- a `runfree ...` example in a fenced block or an inline code span does not
  parse under the current command set (`scripts/emitted-commands.test.ts`); an
  inline span may name a command without its arguments, a fenced line may not;
- a page uses a bare generation phrase (`scripts/check-terminology.ts`); a
  phrase in double quotes is treated as a mention of the term, not a use;
- a published release note has changed since its tag
  (`scripts/check-release-notes-frozen.ts`).

Everything else on this page (ownership, accuracy, whether a change is
documented at all) is checked in review.
