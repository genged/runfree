#!/usr/bin/env node

// Builds one pinned test Git from its verified kernel.org tarball.
//
//   tsx scripts/build-git.ts <version> [--install] [--output <file.tar.gz>] [--verify-signature]
//
// --install puts it in ~/.cache/runfree-dev/git/<version>/ for local test runs
// (`make test-git-build GIT=<version>`). --output writes a release asset (the
// build-git-binaries workflow). Needs cc and make; on macOS, the Xcode
// command-line tools.

import { buildPinnedGit } from "./git-bins.ts";

function main(argv: string[]): void {
  const version = argv.find((arg) => !arg.startsWith("--"));
  const outputIndex = argv.indexOf("--output");
  const outputArchive = outputIndex >= 0 ? argv[outputIndex + 1] : undefined;
  const known = new Set(["--install", "--output", "--verify-signature"]);
  const unknown = argv.filter((arg, index) => arg.startsWith("--") && !known.has(arg) && argv[index - 1] !== "--output");
  if (!version || unknown.length > 0 || (outputIndex >= 0 && !outputArchive)) {
    console.error("usage: tsx scripts/build-git.ts <version> [--install] [--output <file.tar.gz>] [--verify-signature]");
    process.exit(2);
  }
  buildPinnedGit({
    version,
    outputArchive,
    installToCache: argv.includes("--install"),
    verifySignature: argv.includes("--verify-signature"),
  });
}

try {
  main(process.argv.slice(2));
} catch (error) {
  console.error(`build-git: ${(error as Error).message}`);
  process.exit(1);
}
