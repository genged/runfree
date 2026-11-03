---
name: runfree-runtime-packaging
description: Use when changing proxy runtime sources, generated runtime assets, embedded assets, or the proxy Docker build context.
user-invocable: false
metadata:
  internal: true
---

- Do not edit `packages/cli/src/embedded-assets.generated.ts` by hand. Change
  canonical runtime/package sources, run `pnpm run build:runtime`, then run
  `pnpm run generate:assets`.
- Proxy runtime source is canonical under `packages/proxy/src/`. The generated
  runtime Docker context under `dist/runtime/proxy/` is assembled by
  `scripts/build-runtime.ts`; the proxy Dockerfile lives at
  `packages/proxy/Dockerfile`.
