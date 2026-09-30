import { describe, expect, it } from "vitest";

import { demuxDockerStream, formatRawInspect, goJsonIndent, truncateId } from "./format.ts";
import { frame } from "./fake-engine.test-harness.ts";

describe("goJsonIndent", () => {
  it("indents like Go's json.Indent with a four-space indent", () => {
    const src = Buffer.from('{"Id":"abc","Empty":{},"List":[],"Nested":{"A":[1,2.50,-3e2,true,null]},"S":"x"}\n');
    expect(goJsonIndent(src).toString()).toBe([
      "{",
      '    "Id": "abc",',
      '    "Empty": {},',
      '    "List": [],',
      '    "Nested": {',
      '        "A": [',
      "            1,",
      "            2.50,",
      "            -3e2,",
      "            true,",
      "            null",
      "        ]",
      "    },",
      '    "S": "x"',
      "}",
    ].join("\n"));
  });

  it("copies every byte inside a string unchanged: escapes, spaces, punctuation, UTF-8", () => {
    const src = Buffer.from('{"k":"a\\u003cb\\u003e \\"q\\" {x}: [y], \\\\","u":"é😀"}');
    expect(goJsonIndent(src).toString()).toBe('{\n    "k": "a\\u003cb\\u003e \\"q\\" {x}: [y], \\\\",\n    "u": "é😀"\n}');
  });

  it("drops insignificant whitespace, including whitespace around empty containers", () => {
    expect(goJsonIndent(Buffer.from(' [ { } , [ ] , { "a" : 1 } ]')).toString()).toBe('[\n    {},\n    [],\n    {\n        "a": 1\n    }\n]');
  });

  it("agrees with JSON.stringify(…, 4) wherever JavaScript would not re-escape or reformat", () => {
    const samples: unknown[] = [
      { Id: "0".repeat(64), State: { Running: true, Pid: 42, Health: null }, Mounts: [], Labels: {}, NetworkSettings: { Networks: { a: { IPAddress: "10.0.0.2", Aliases: ["x", "y"] } } } },
      [[], [[]], [{}], { a: [{ b: {} }] }],
      "plain",
      12,
    ];
    for (const sample of samples) {
      expect(goJsonIndent(Buffer.from(JSON.stringify(sample))).toString()).toBe(JSON.stringify(sample, null, 4));
    }
  });
});

describe("formatRawInspect", () => {
  it("joins raw bodies into one indented array with a trailing newline, as the CLI's inspector does", () => {
    const out = formatRawInspect([Buffer.from('{"Id":"a"}\n'), Buffer.from('{"Id":"b"}\n')]).toString();
    expect(out).toBe('[\n    {\n        "Id": "a"\n    },\n    {\n        "Id": "b"\n    }\n]\n');
  });

  it("prints [] for no objects", () => {
    expect(formatRawInspect([]).toString()).toBe("[]\n");
  });
});

describe("truncateId", () => {
  it("matches stringid.TruncateID", () => {
    expect(truncateId("0123456789abcdef0123")).toBe("0123456789ab");
    expect(truncateId("sha256:0123456789abcdef")).toBe("0123456789ab");
    expect(truncateId("short")).toBe("short");
  });
});

describe("demuxDockerStream", () => {
  it("splits stdout and stderr frames in order, stdin frames counting as stdout", () => {
    const stream = Buffer.concat([frame(1, "out1 "), frame(2, "err1 "), frame(0, "in "), frame(1, "out2"), frame(2, "err2"), frame(1, "")]);
    const result = demuxDockerStream(stream);
    expect(result).toEqual({ ok: true, stdout: Buffer.from("out1 in out2"), stderr: Buffer.from("err1 err2") });
  });

  it("keeps binary payloads byte-exact", () => {
    const payload = Buffer.from([0, 1, 2, 0xff, 0xfe, 0x0a]);
    const result = demuxDockerStream(frame(1, payload));
    expect(result.ok && result.stdout.equals(payload)).toBe(true);
  });

  it("refuses a system-error frame, an unknown stream type, and truncated frames", () => {
    expect(demuxDockerStream(frame(3, "boom"))).toEqual({ ok: false, reason: "error from daemon in stream: boom" });
    expect(demuxDockerStream(frame(7, "x")).ok).toBe(false);
    expect(demuxDockerStream(frame(1, "abcdef").subarray(0, 10)).ok).toBe(false);
    expect(demuxDockerStream(Buffer.from([1, 0, 0])).ok).toBe(false);
  });

  it("accepts an empty stream as empty output", () => {
    expect(demuxDockerStream(Buffer.alloc(0))).toEqual({ ok: true, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) });
  });
});
