import * as childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { PassThrough } from "node:stream";
import { afterEach, describe, expect, test } from "vitest";

import { createHeadlessOutputParser } from "./headless-agent-output.ts";
import { createHeadlessForegroundSpawner, type HeadlessPipedChild } from "./headless-foreground.ts";
import {
  createHeadlessRunId,
  createRunRecord,
  HEADLESS_RUN_ID_PATTERN,
  summaryLines,
  type HeadlessRunJson,
  HEADLESS_RUN_RECORD_RETENTION,
} from "./headless-run-record.ts";

// Headless-run spec §3.4: the run record lives only under
// `<stateDir>/runs/<runId>/`, transcript.jsonl is the agent's stdout
// byte-for-byte, and Runfree writes nothing into the project tree.

const RUN_ID = "run-20261025T101500Z-0a1b2c3d";
const temps: string[] = [];

function tempDir(prefix: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  temps.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of temps.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

function layout() {
  const root = tempDir("runfree-run-record-");
  const projectRoot = path.join(root, "project");
  const stateDir = path.join(root, "state", "projects", "abc");
  fs.mkdirSync(projectRoot, { recursive: true });
  fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  return { root, projectRoot, stateDir };
}

function runJson(overrides: Partial<HeadlessRunJson> = {}): HeadlessRunJson {
  return {
    v: 1,
    runId: RUN_ID,
    agent: "claude",
    startedAt: "2026-10-25T10:15:00.000Z",
    endedAt: "2026-10-25T10:16:00.000Z",
    agentStatus: 0,
    outcome: "success",
    exitCode: 0,
    teardown: "confirmed",
    sessionId: "session-1",
    containerId: "a".repeat(64),
    headlessDenials: 0,
    acceptDeniedWrites: false,
    uncheckedAuthority: { hostServices: [], oauthExchanges: [], localMcpServers: [], unreadable: [] },
    askExposure: null,
    streamsDrained: true,
    reattached: false,
    transcriptBytes: 0,
    transcriptTruncated: false,
    stderrTruncated: false,
    malformedLines: 0,
    ...overrides,
  };
}

function treeSnapshot(dir: string): string[] {
  const entries: string[] = [];
  const walk = (current: string): void => {
    for (const name of fs.readdirSync(current).sort()) {
      const full = path.join(current, name);
      const stat = fs.lstatSync(full);
      entries.push(`${path.relative(dir, full)}:${stat.mode}:${stat.size}:${stat.mtimeMs}`);
      if (stat.isDirectory()) walk(full);
    }
  };
  walk(dir);
  return entries;
}

describe("run ids", () => {
  test("format is run-YYYYMMDDTHHMMSSZ-<8 hex> in UTC", () => {
    const id = createHeadlessRunId(new Date("2026-10-25T10:15:07.123Z"), () => Buffer.from([0x0a, 0x1b, 0x2c, 0x3d]));
    expect(id).toBe("run-20261025T101507Z-0a1b2c3d");
    expect(HEADLESS_RUN_ID_PATTERN.test(createHeadlessRunId())).toBe(true);
  });
});

describe("createRunRecord", () => {
  test("creates the private run directory and keeps the transcript byte-for-byte", () => {
    const { projectRoot, stateDir } = layout();
    const record = createRunRecord(stateDir, RUN_ID, { projectRoot });
    expect(record.dir).toBe(path.join(stateDir, "runs", RUN_ID));
    const bytes = Buffer.from([0x7b, 0x7d, 0x0a, 0xff, 0xfe, 0x00, 0xc3, 0x0a]);
    record.appendTranscript(bytes.subarray(0, 3));
    record.appendTranscript(bytes.subarray(3));
    record.appendStderr(Buffer.from("agent stderr\n"));
    record.finalize(runJson({ transcriptBytes: record.transcriptBytes() }), { finalMessage: "done" });
    expect(fs.readFileSync(path.join(record.dir, "transcript.jsonl"))).toEqual(bytes);
    expect(fs.readFileSync(path.join(record.dir, "stderr.log"), "utf8")).toBe("agent stderr\n");
    expect(fs.readFileSync(path.join(record.dir, "result.md"), "utf8")).toBe("done\n");
    expect(fs.statSync(record.dir).mode & 0o777).toBe(0o700);
    expect(fs.statSync(path.join(stateDir, "runs")).mode & 0o777).toBe(0o700);
    for (const name of ["transcript.jsonl", "stderr.log", "result.md", "run.json"]) {
      expect(fs.statSync(path.join(record.dir, name)).mode & 0o777).toBe(0o600);
    }
  });

  test("run.json round-trips", () => {
    const { projectRoot, stateDir } = layout();
    const record = createRunRecord(stateDir, RUN_ID, { projectRoot });
    const run = runJson({ agentStatus: null, outcome: "unverified", exitCode: 1, headlessDenials: null, sessionId: undefined });
    record.finalize(run, {});
    const parsed = JSON.parse(fs.readFileSync(path.join(record.dir, "run.json"), "utf8"));
    expect(parsed).toEqual(JSON.parse(JSON.stringify(run)));
    expect(parsed).not.toHaveProperty("sessionId");
    expect(fs.readFileSync(path.join(record.dir, "result.md"), "utf8")).toBe("");
  });

  test("bytes past the transcript cap are dropped and marked", () => {
    const { projectRoot, stateDir } = layout();
    const record = createRunRecord(stateDir, RUN_ID, { projectRoot, transcriptCapBytes: 5 });
    record.appendTranscript(Buffer.from("abc"));
    record.appendTranscript(Buffer.from("defgh"));
    record.appendTranscript(Buffer.from("ij"));
    expect(record.transcriptBytes()).toBe(5);
    expect(record.transcriptTruncated()).toBe(true);
    record.finalize(runJson(), {});
    expect(fs.readFileSync(path.join(record.dir, "transcript.jsonl"), "utf8")).toBe("abcde");
  });

  test("an existing run directory is refused before any write", () => {
    const { projectRoot, stateDir } = layout();
    const dir = path.join(stateDir, "runs", RUN_ID);
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    expect(() => createRunRecord(stateDir, RUN_ID, { projectRoot })).toThrow("run record");
    expect(fs.readdirSync(dir)).toEqual([]);
  });

  test("a pre-planted transcript symlink is refused and its target untouched", () => {
    const { root, projectRoot, stateDir } = layout();
    const dir = path.join(stateDir, "runs", RUN_ID);
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const target = path.join(root, "victim.txt");
    fs.writeFileSync(target, "keep");
    fs.symlinkSync(target, path.join(dir, "transcript.jsonl"));
    expect(() => createRunRecord(stateDir, RUN_ID, { projectRoot })).toThrow("run record");
    expect(fs.readFileSync(target, "utf8")).toBe("keep");
  });

  test("a symlinked runs directory is refused before any write", () => {
    const { root, projectRoot, stateDir } = layout();
    const elsewhere = path.join(root, "elsewhere");
    fs.mkdirSync(elsewhere);
    fs.symlinkSync(elsewhere, path.join(stateDir, "runs"));
    expect(() => createRunRecord(stateDir, RUN_ID, { projectRoot })).toThrow("run record");
    expect(fs.readdirSync(elsewhere)).toEqual([]);
  });

  test("a runs directory that is a file is refused", () => {
    const { projectRoot, stateDir } = layout();
    fs.writeFileSync(path.join(stateDir, "runs"), "");
    expect(() => createRunRecord(stateDir, RUN_ID, { projectRoot })).toThrow("run record");
  });

  test.each(["../escape", "run-1", `${RUN_ID}/x`, ""])("a malformed run id %j is refused before any write", (runId) => {
    const { projectRoot, stateDir } = layout();
    expect(() => createRunRecord(stateDir, runId, { projectRoot })).toThrow("run id");
    expect(fs.existsSync(path.join(stateDir, "runs"))).toBe(false);
  });

  test("a state directory inside the project is refused before any write", () => {
    const { projectRoot } = layout();
    const before = treeSnapshot(projectRoot);
    const stateDir = path.join(projectRoot, "state");
    expect(() => createRunRecord(stateDir, RUN_ID, { projectRoot })).toThrow("outside the project");
    expect(treeSnapshot(projectRoot)).toEqual(before);
  });

  test("Runfree's own stderr is teed into stderr.log until finalize", () => {
    const { projectRoot, stateDir } = layout();
    const record = createRunRecord(stateDir, RUN_ID, { projectRoot });
    const stream = new PassThrough();
    const seen: string[] = [];
    stream.on("data", (chunk: Buffer) => seen.push(chunk.toString()));
    record.startStderrTee(stream as unknown as NodeJS.WriteStream);
    stream.write("runfree: warning\n");
    record.finalize(runJson(), {});
    stream.write("after\n");
    expect(fs.readFileSync(path.join(record.dir, "stderr.log"), "utf8")).toBe("runfree: warning\n");
    expect(seen.join("")).toBe("runfree: warning\nafter\n");
  });

  test("finalize runs once; later appends are ignored", () => {
    const { projectRoot, stateDir } = layout();
    const record = createRunRecord(stateDir, RUN_ID, { projectRoot });
    record.finalize(runJson(), {});
    expect(() => record.appendTranscript(Buffer.from("late"))).not.toThrow();
    expect(() => record.finalize(runJson(), {})).toThrow("already finalized");
    expect(fs.readFileSync(path.join(record.dir, "transcript.jsonl"), "utf8")).toBe("");
  });
});

describe("summaryLines", () => {
  const dir = "/state/runs/run-20261025T101500Z-0a1b2c3d";

  test("prints the final message and the record path", () => {
    expect(summaryLines({ run: runJson(), finalMessage: "All done.", recordDir: dir }))
      .toEqual(["All done.", `run record: ${dir}`]);
  });

  test("prints a note without a final message, the denial warning, and the teardown warning", () => {
    expect(summaryLines({
      run: runJson({ headlessDenials: 3, teardown: "unconfirmed", outcome: "unverified", exitCode: 1 }),
      recordDir: dir,
    })).toEqual([
      "(no final message from the agent; outcome: unverified)",
      "warning: 3 writes were denied (headless)",
      "warning: the session container stop was not confirmed; the run lock is kept until it is gone",
      `run record: ${dir}`,
    ]);
  });

  test("one denial reads singular and an unknown count is named", () => {
    expect(summaryLines({ run: runJson({ headlessDenials: 1 }), finalMessage: "ok", recordDir: dir }))
      .toContain("warning: 1 write was denied (headless)");
    expect(summaryLines({ run: runJson({ headlessDenials: null }), finalMessage: "ok", recordDir: dir }))
      .toContain("warning: the headless write denials could not be counted");
  });

  test("a run refused before launch says it did not start, not that the agent sent nothing", () => {
    const lines = summaryLines({ run: runJson({ outcome: "refused", exitCode: 65, teardown: "not-started", headlessDenials: null }), recordDir: dir });
    expect(lines).toEqual(["(the run did not start; outcome: refused)", `run record: ${dir}`]);
  });

  test("a skipped run says it did not start", () => {
    const lines = summaryLines({ run: runJson({ outcome: "skipped", teardown: "not-started", headlessDenials: null }), recordDir: dir });
    expect(lines[0]).toBe("(the run did not start; outcome: skipped)");
  });
});

describe("capture into the record", () => {
  test("a real child's binary stdout lands byte-for-byte and nothing is written under the project", async () => {
    const { projectRoot, stateDir } = layout();
    fs.mkdirSync(path.join(projectRoot, ".runfree"));
    fs.writeFileSync(path.join(projectRoot, ".runfree", "runfree.json"), "{}\n");
    fs.writeFileSync(path.join(projectRoot, "README.md"), "hello\n");
    const before = treeSnapshot(projectRoot);

    const payload = Buffer.concat([
      Buffer.from(`${JSON.stringify({ type: "system" })}\n`),
      Buffer.from([0xff, 0xfe, 0x0a]),
      Buffer.from(`${JSON.stringify({ type: "result", subtype: "success", is_error: false, result: "fin" })}\n`),
    ]);
    const record = createRunRecord(stateDir, RUN_ID, { projectRoot });
    const parser = createHeadlessOutputParser("claude-stream-json");
    const capture = createHeadlessForegroundSpawner({
      stdout: (chunk) => {
        record.appendTranscript(chunk);
        parser.push(chunk);
      },
      stderr: (chunk) => record.appendStderr(chunk),
      stdoutEnded: () => parser.endStream(),
    }, {
      // Stands in for `docker`: the real spawn path with the child's cwd in
      // the project, as the agent's would be.
      spawnProcess: (_executable, _args, options) => childProcess.spawn(process.execPath, [
        "-e",
        `process.stdout.write(Buffer.from(${JSON.stringify(payload.toString("base64"))}, "base64")); process.stderr.write("e\\n");`,
      ], { env: options.env, stdio: [...options.stdio], cwd: projectRoot }) as unknown as HeadlessPipedChild,
    });
    const child = capture.spawn("docker", ["start", "--attach", "c1"], { shell: false, stdio: "inherit", env: { ...process.env } as Record<string, string> });
    await new Promise((resolve) => child.once("exit", resolve));
    const { drained } = await capture.drain(10_000);
    expect(drained).toBe(true);
    const result = parser.result();
    record.finalize(runJson({ transcriptBytes: record.transcriptBytes(), malformedLines: result.malformedLines }), {
      finalMessage: result.finalMessage,
    });
    const lines = summaryLines({ run: runJson(), finalMessage: result.finalMessage, recordDir: record.dir });

    expect(fs.readFileSync(path.join(record.dir, "transcript.jsonl"))).toEqual(payload);
    expect(fs.readFileSync(path.join(record.dir, "stderr.log"), "utf8")).toBe("e\n");
    expect(result).toMatchObject({ complete: true, finalSuccess: true, finalMessage: "fin", malformedLines: 1 });
    expect(lines.at(-1)).toBe(`run record: ${record.dir}`);
    expect(path.relative(projectRoot, record.dir).startsWith("..")).toBe(true);
    expect(treeSnapshot(projectRoot)).toEqual(before);
  });
});

describe("run record retention", () => {
  test("creating a record removes the oldest records past the retention and nothing else", () => {
    const { projectRoot, stateDir } = layout();
    const runsDir = path.join(stateDir, "runs");
    fs.mkdirSync(runsDir, { mode: 0o700 });
    const ids: string[] = [];
    for (let index = 0; index < HEADLESS_RUN_RECORD_RETENTION + 4; index += 1) {
      const stamp = new Date(Date.UTC(2026, 0, 1, 0, 0, index)).toISOString().replace(/\.\d{3}Z$/, "Z").replace(/[-:]/g, "");
      const id = `run-${stamp}-${index.toString(16).padStart(8, "0")}`;
      ids.push(id);
      fs.mkdirSync(path.join(runsDir, id), { mode: 0o700 });
      fs.writeFileSync(path.join(runsDir, id, "run.json"), "{}\n");
    }
    // Not run records: a stray file and a directory outside the id shape stay.
    fs.writeFileSync(path.join(runsDir, "notes.txt"), "keep\n");
    fs.mkdirSync(path.join(runsDir, "scratch"));

    const newest = "run-20260301T000000Z-0000ffff";
    const record = createRunRecord(stateDir, newest, { projectRoot });
    record.finalize(runJson({ runId: newest }), {});

    const remaining = fs.readdirSync(runsDir).sort();
    expect(remaining).toContain("notes.txt");
    expect(remaining).toContain("scratch");
    const records = remaining.filter((name) => name.startsWith("run-"));
    expect(records).toHaveLength(HEADLESS_RUN_RECORD_RETENTION);
    expect(records).toContain(newest);
    // The five oldest are gone, the rest kept in order.
    for (const id of ids.slice(0, 5)) expect(records).not.toContain(id);
    for (const id of ids.slice(5)) expect(records).toContain(id);
  });
});
