import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import { buildAll } from "./build-test-bundles.ts";

let tmp: string;

function executable(filePath: string, content: string): void {
  fs.writeFileSync(filePath, content, { mode: 0o755 });
}

beforeEach(() => {
  tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "runfree-test-bundles-")));
});

afterEach(() => {
  vi.restoreAllMocks();
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe("test bundle setup", () => {
  test("falls back to tsx with bunw's first stderr line when bunw cannot provide Bun", () => {
    const bunw = path.join(tmp, "bunw");
    executable(
      bunw,
      "#!/bin/sh\necho 'bunw: cannot read https://registry.example/@oven/bun-x/1.3.14: curl exit 6' >&2\necho 'bunw: no Bun was run.' >&2\nexit 1\n",
    );
    const outfile = path.join(tmp, "out", "stale.mjs");
    fs.mkdirSync(path.dirname(outfile));
    fs.writeFileSync(outfile, "stale bundle");
    const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);

    buildAll([{ entry: path.join(tmp, "entry.ts"), outfile, external: [] }], bunw);

    expect(fs.existsSync(outfile)).toBe(false);
    const written = stderr.mock.calls.map(([chunk]) => String(chunk)).join("");
    expect(written).toBe(
      "test bundles: ./bunw could not provide the declared Bun (bunw: cannot read https://registry.example/@oven/bun-x/1.3.14: curl exit 6); subprocess tests will spawn through tsx (slower)\n",
    );
  });

  test("builds with the Bun in bunw's directory, not the Bun on PATH", () => {
    const binDir = path.join(tmp, "declared-bin");
    fs.mkdirSync(binDir);
    // The fake Bun writes its marker to the staging --outfile it is given.
    executable(
      path.join(binDir, "bun"),
      '#!/bin/sh\nfor arg in "$@"; do case "$arg" in --outfile=*) printf declared > "${arg#--outfile=}" ;; esac; done\n',
    );
    const bunw = path.join(tmp, "bunw");
    executable(bunw, `#!/bin/sh\n[ "$1" = --print-bin-dir ] || exit 2\necho '${binDir}'\n`);
    const outfile = path.join(tmp, "out", "bundle.mjs");

    buildAll([{ entry: path.join(tmp, "entry.ts"), outfile, external: [] }], bunw);

    expect(fs.readFileSync(outfile, "utf8")).toBe("declared");
  });

  test("a bundle build failure with the declared Bun still fails the run", () => {
    const binDir = path.join(tmp, "declared-bin");
    fs.mkdirSync(binDir);
    executable(path.join(binDir, "bun"), "#!/bin/sh\necho 'cannot bundle' >&2\nexit 1\n");
    const bunw = path.join(tmp, "bunw");
    executable(bunw, `#!/bin/sh\necho '${binDir}'\n`);

    expect(() =>
      buildAll([{ entry: path.join(tmp, "entry.ts"), outfile: path.join(tmp, "out", "b.mjs"), external: [] }], bunw),
    ).toThrow(/test bundle build failed[\s\S]*cannot bundle/);
  });
});
