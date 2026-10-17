import { describe, expect, test, vi } from "vitest";

import { LFS_BATCH_BODY_CAP_BYTES, classifyLfsBatchBodyText, classifyLfsBatchRequest } from "./lfs-classify.ts";

const LFS_TYPE = "application/vnd.git-lfs+json";

function classify(body: string | Buffer, headers: Record<string, string | string[] | undefined> = {}, options: { contentLength?: string | null } = {}) {
  const bytes = typeof body === "string" ? Buffer.from(body, "utf8") : body;
  const readBody = vi.fn(async () => bytes);
  const contentLength = options.contentLength === undefined ? String(bytes.length) : options.contentLength;
  return {
    readBody,
    verdict: classifyLfsBatchRequest({
      headers: {
        "content-type": LFS_TYPE,
        ...(contentLength === null ? {} : { "content-length": contentLength }),
        ...headers,
      },
      readBody,
    }),
  };
}

const DOWNLOAD = JSON.stringify({
  operation: "download",
  transfers: ["basic"],
  ref: { name: "refs/heads/main" },
  objects: [{ oid: "a".repeat(64), size: 123 }],
  hash_algo: "sha256",
});

describe("Git LFS batch body classification (T10)", () => {
  test("a bounded, unambiguous download batch is a read", async () => {
    await expect(classify(DOWNLOAD).verdict).resolves.toBe("download");
    await expect(classify(DOWNLOAD, { "content-type": `${LFS_TYPE}; charset=utf-8` }).verdict).resolves.toBe("download");
    await expect(classify(DOWNLOAD, { "content-type": "Application/VND.Git-LFS+JSON" }).verdict).resolves.toBe("download");
    await expect(classify(DOWNLOAD, { "content-encoding": "identity" }).verdict).resolves.toBe("download");
  });

  test("upload, unknown, and non-string operations are writes", async () => {
    for (const operation of ["upload", "Download", "download ", "", null, 1, ["download"], { download: true }]) {
      await expect(classify(JSON.stringify({ operation, objects: [] })).verdict, JSON.stringify(operation)).resolves.toBe("write");
    }
    await expect(classify(JSON.stringify({ objects: [] })).verdict).resolves.toBe("write");
  });

  test("duplicate or case-folded operation keys are writes", () => {
    const bodies = [
      '{"operation":"download","operation":"upload"}',
      '{"operation":"download","operation":"download"}',
      '{"operation":"upload","operation":"download"}',
      // An escaped spelling of the same key is still a duplicate.
      '{"operation":"download","operati\\u006fn":"upload"}',
      '{"Operation":"upload","operation":"download"}',
      '{"operation":"download","OPERATION":"upload"}',
      '{"Operation":"download"}',
      // A duplicate anywhere in the document fails the strict parse.
      '{"operation":"download","objects":[{"oid":"a","oid":"b"}]}',
    ];
    for (const body of bodies) expect(classifyLfsBatchBodyText(body), body).toBe("write");
  });

  test("malformed, non-object, and BOM-prefixed bodies are writes", async () => {
    for (const body of ["not-json", "{", '{"operation":"download"} trailing', '["download"]', '"download"', "null", "", `\uFEFF${DOWNLOAD}`]) {
      await expect(classify(body).verdict, JSON.stringify(body)).resolves.toBe("write");
    }
    // Invalid UTF-8 fails the fatal decoder.
    const invalid = Buffer.concat([Buffer.from('{"operation":"download","x":"'), Buffer.from([0xff, 0xfe]), Buffer.from('"}')]);
    await expect(classify(invalid).verdict).resolves.toBe("write");
  });

  test("oversized bodies and declared lengths are writes, and an over-cap length never reads the body", async () => {
    const padded = JSON.stringify({ operation: "download", objects: [], pad: "a".repeat(LFS_BATCH_BODY_CAP_BYTES) });
    await expect(classify(padded).verdict).resolves.toBe("write");
    const declared = classify(DOWNLOAD, {}, { contentLength: String(LFS_BATCH_BODY_CAP_BYTES + 1) });
    await expect(declared.verdict).resolves.toBe("write");
    expect(declared.readBody).not.toHaveBeenCalled();
    // At the cap exactly is allowed.
    const base = JSON.stringify({ operation: "download", pad: "" });
    const atCap = JSON.stringify({ operation: "download", pad: "a".repeat(LFS_BATCH_BODY_CAP_BYTES - Buffer.byteLength(base)) });
    expect(Buffer.byteLength(atCap)).toBe(LFS_BATCH_BODY_CAP_BYTES);
    await expect(classify(atCap).verdict).resolves.toBe("download");
  });

  test("a missing, malformed, repeated, or mismatched Content-Length is a write", async () => {
    for (const contentLength of [null, "", "abc", "-1", "1e3", " 10", "0x10", "1234567"]) {
      const result = classify(DOWNLOAD, {}, { contentLength });
      await expect(result.verdict, String(contentLength)).resolves.toBe("write");
      expect(result.readBody).not.toHaveBeenCalled();
    }
    const length = String(Buffer.byteLength(DOWNLOAD));
    await expect(classify(DOWNLOAD, { "content-length": [length, length] }, { contentLength: null }).verdict).resolves.toBe("write");
    // Truncated or padded relative to the declared length.
    await expect(classify(DOWNLOAD, {}, { contentLength: String(Buffer.byteLength(DOWNLOAD) + 1) }).verdict).resolves.toBe("write");
    await expect(classify(DOWNLOAD, {}, { contentLength: String(Buffer.byteLength(DOWNLOAD) - 1) }).verdict).resolves.toBe("write");
  });

  test("a wrong content type is a write, before the body is read", async () => {
    for (const contentType of ["application/json", "text/plain", "application/vnd.git-lfs", `${LFS_TYPE}x`, `${LFS_TYPE}; charset=latin1`, ""]) {
      const result = classify(DOWNLOAD, { "content-type": contentType });
      await expect(result.verdict, contentType).resolves.toBe("write");
      expect(result.readBody).not.toHaveBeenCalled();
    }
    await expect(classify(DOWNLOAD, { "content-type": [LFS_TYPE, LFS_TYPE] }).verdict).resolves.toBe("write");
  });

  test("any non-identity content encoding is a write, before the body is read", async () => {
    for (const encoding of ["gzip", "br", "deflate", "identity, gzip", ""]) {
      const result = classify(DOWNLOAD, { "content-encoding": encoding });
      await expect(result.verdict, encoding).resolves.toBe("write");
      expect(result.readBody).not.toHaveBeenCalled();
    }
  });

  test("an unreadable or undecodable body is a write", async () => {
    const throwing = classifyLfsBatchRequest({
      headers: { "content-type": LFS_TYPE, "content-length": String(Buffer.byteLength(DOWNLOAD)) },
      readBody: async () => {
        throw new Error("decode failed");
      },
    });
    await expect(throwing).resolves.toBe("write");
    const absent = classifyLfsBatchRequest({
      headers: { "content-type": LFS_TYPE, "content-length": String(Buffer.byteLength(DOWNLOAD)) },
      readBody: async () => undefined,
    });
    await expect(absent).resolves.toBe("write");
  });

  test("a lock request body is a write: only the exact download batch is a read", () => {
    // Lock create/verify/unlock bodies carry no operation field.
    expect(classifyLfsBatchBodyText(JSON.stringify({ path: "a.bin", ref: { name: "refs/heads/main" } }))).toBe("write");
    expect(classifyLfsBatchBodyText(JSON.stringify({ force: true }))).toBe("write");
  });
});
