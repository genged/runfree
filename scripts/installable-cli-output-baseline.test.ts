// Characterization baseline for the CLI output contract (spec P0).
//
// These snapshots record what the CLI prints today — stream, exit code, and
// line order — for the commands the output-contract phases touch, plus the
// agent-visible proxy denial bodies. They are not a statement that the text
// is right: later phases change it on purpose, and the snapshot diff is the
// attributable record of exactly what changed. Update with `vitest -u` only
// alongside the phase that intends the change.
import { describe, expect, test } from "vitest";

import { DENIAL_REASONS, syntheticDenialBody, type DenialReason } from "../packages/proxy/src/denial.ts";
import { runCliInProject, tmp, tmpBase } from "./installable-cli.test-harness.ts";

type Transcript = { status: number | null; stdout: string; stderr: string };

const ISO_TIMESTAMP = /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z/g;
const DIGEST = /sha256:[0-9a-f]{12,64}…?/g;
const CONTROL_GENERATION = /\b[0-9a-f]{64}\b/g;

function normalize(text: string): string {
  return text
    .split(tmp).join("<project>")
    .split(tmpBase).join("<tmp>")
    .replace(ISO_TIMESTAMP, "<ts>")
    .replace(DIGEST, "sha256:<digest>")
    .replace(CONTROL_GENERATION, "<hex>");
}

function transcript(args: string[]): Transcript {
  const result = runCliInProject(args);
  return { status: result.status, stdout: normalize(result.stdout), stderr: normalize(result.stderr) };
}

function initProject(): void {
  const init = runCliInProject(["init"]);
  expect(init.status, init.stderr).toBe(0);
}

describe("output baseline: command transcripts", () => {
  test("init on a fresh project", () => {
    expect(transcript(["init"])).toMatchSnapshot();
  });

  test("bare group command", () => {
    initProject();
    expect(transcript(["host"])).toMatchSnapshot();
  });

  test("unknown command", () => {
    initProject();
    expect(transcript(["bogus-command"])).toMatchSnapshot();
  });

  test("unknown flag before a mutation", () => {
    initProject();
    expect(transcript(["host", "add", "flag.example", "--bogus"])).toMatchSnapshot();
  });

  test("post-init dead zone reads", () => {
    initProject();
    expect(transcript(["host", "list"])).toMatchSnapshot();
    expect(transcript(["service", "list"])).toMatchSnapshot();
    expect(transcript(["credential", "status"])).toMatchSnapshot();
    expect(transcript(["policy", "status"])).toMatchSnapshot();
  });

  test("policy mutation before the first start", () => {
    initProject();
    expect(transcript(["host", "add", "pre.example"])).toMatchSnapshot();
    expect(transcript(["host", "rules", "pre.example", "--read-only", "--no-reload"])).toMatchSnapshot();
    expect(transcript(["host", "rules", "pre.example"])).toMatchSnapshot();
  });

  test("removed command shims", () => {
    initProject();
    expect(transcript(["source", "add", "x"])).toMatchSnapshot();
    expect(transcript(["domain", "add", "x"])).toMatchSnapshot();
  });

  test("credential add rejects the inert --no-sync flag", () => {
    initProject();
    expect(transcript(["credential", "add", "tok", "--host", "api.example.com", "--from-env", "TOKEN_ENV", "--no-sync"])).toMatchSnapshot();
  });

  test("update placeholder", () => {
    expect(transcript(["update"])).toMatchSnapshot();
  });
});

describe("output baseline: proxy denial bodies", () => {
  const RULE = { methods: ["GET", "HEAD"] as const, pathPrefixes: ["/api/"], gitPush: "deny" as const, writeAction: "ask" as const };

  test("every denial reason renders a stable body", () => {
    const bodies: Record<string, string> = {};
    for (const reason of DENIAL_REASONS as readonly DenialReason[]) {
      bodies[reason] = syntheticDenialBody("api.example.com", reason, {
        method: "POST",
        path: "/api/v1/things?token=secret",
        allowedMethods: RULE.methods,
        allowedPathPrefixes: RULE.pathPrefixes,
        rule: { methods: [...RULE.methods], pathPrefixes: RULE.pathPrefixes, gitPush: RULE.gitPush, writeAction: RULE.writeAction },
      });
    }
    expect(bodies).toMatchSnapshot();
  });

  test("unparseable host body", () => {
    expect(syntheticDenialBody("bad host", "host-not-allowlisted")).toMatchSnapshot();
  });
});
