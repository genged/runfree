---
name: runfree-dependency-changes
description: Use before adding or changing a Runfree dependency, language, toolchain, or TypeScript execution and compilation strategy.
user-invocable: false
metadata:
  internal: true
---

- Use pnpm and Node 22. Do not switch package managers.
- Keep dependencies deliberate. The repo intentionally runs TypeScript directly
  with `tsx` for scripts and compiles the proxy only for generated runtime
  packaging; `tsc --noEmit` is the normal static gate.
- Ask before adding a dependency, and ask before introducing a new language or
  toolchain; a new language is the higher bar. When a dependency may be
  warranted, search for trusted options and present a choice rather than
  picking one. Prefer TypeScript and the Node already in the agent and proxy
  images.
