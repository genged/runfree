// lfs-classify.ts — conservative Git LFS batch request classification.
//
// The Git LFS batch endpoint (POST …/info/lfs/objects/batch) serves both
// downloads and uploads; the body's `operation` field says which. The proxy
// decides one bit: a provably unambiguous download (read) versus everything
// else (write). The guardrails mirror graphql-classify.ts, and are stricter:
//
// - media type `application/vnd.git-lfs+json` (parameters allowed; a charset
//   parameter, if present, must be utf-8);
// - identity content encoding only (the proxy never decompresses);
// - a single, plain-digit Content-Length that is present, at most
//   LFS_BATCH_BODY_CAP_BYTES, and equal to the buffered body length;
// - fatal UTF-8 decode of the bytes mockttp forwards (no BOM stripping);
// - strict JSON with no duplicate key at any depth (parseJsonStrict);
// - a top-level object whose only key equal to `operation` under case folding
//   is spelled exactly `operation` and whose value is the string "download".
//
// Anything else — including `"upload"`, a case-folded `Operation` beside
// `operation`, malformed or truncated bodies, and a missing length — is a
// write. Lock requests never reach this classifier: only the batch endpoint
// has a read exemption.
import { isRecord } from "@runfree/runtime-contracts/primitives";

import { parseJsonStrict } from "./mcp-classify.js";

export const LFS_BATCH_BODY_CAP_BYTES = 64 * 1024;

const LFS_MEDIA_TYPE = "application/vnd.git-lfs+json";

export type LfsBodyClass = "download" | "write";

export type LfsBatchRequestInput = {
  headers: Record<string, string | string[] | undefined> | undefined;
  // Returns the buffered, content-decoded request body. Only called after
  // every header check passes.
  readBody: () => Promise<Buffer | undefined>;
};

// The header's single value, or undefined when it is absent, repeated, or not
// a string. Header names compare case-insensitively.
function singleHeader(
  headers: Record<string, string | string[] | undefined> | undefined,
  name: string,
): { present: false } | { present: true; value: string | undefined } {
  if (!headers) return { present: false };
  const values: unknown[] = [];
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() !== name) continue;
    if (Array.isArray(value)) values.push(...value);
    else if (value !== undefined) values.push(value);
  }
  if (values.length === 0) return { present: false };
  if (values.length > 1 || typeof values[0] !== "string") return { present: true, value: undefined };
  return { present: true, value: values[0] };
}

function lfsMediaTypeAllowed(contentType: string): boolean {
  const [mediaType, ...parameters] = contentType.split(";");
  if (mediaType.trim().toLowerCase() !== LFS_MEDIA_TYPE) return false;
  for (const parameter of parameters) {
    const separator = parameter.indexOf("=");
    if (separator === -1) continue;
    const name = parameter.slice(0, separator).trim().toLowerCase();
    if (name !== "charset") continue;
    const value = parameter.slice(separator + 1).trim().replace(/^"(.*)"$/u, "$1").toLowerCase();
    if (value !== "utf-8" && value !== "utf8") return false;
  }
  return true;
}

// ASCII case folding (what D-6 names), plus the full Unicode lowercase so a
// decoder with wider folding cannot read a key this check let through.
function foldsToOperation(key: string): boolean {
  const ascii = key.replace(/[A-Z]/gu, (char) => char.toLowerCase());
  return ascii === "operation" || key.toLowerCase() === "operation" || key.toUpperCase().toLowerCase() === "operation";
}

// Pure classification of an already-decoded body. Exported for unit tests.
export function classifyLfsBatchBodyText(bodyText: string): LfsBodyClass {
  const parsed = parseJsonStrict(bodyText);
  if (parsed.reason !== undefined || !isRecord(parsed.value)) return "write";
  const operationKeys = Object.keys(parsed.value).filter(foldsToOperation);
  if (operationKeys.length !== 1 || operationKeys[0] !== "operation") return "write";
  return parsed.value.operation === "download" ? "download" : "write";
}

export async function classifyLfsBatchRequest(input: LfsBatchRequestInput): Promise<LfsBodyClass> {
  const contentType = singleHeader(input.headers, "content-type");
  if (!contentType.present || contentType.value === undefined || !lfsMediaTypeAllowed(contentType.value)) return "write";

  const contentEncoding = singleHeader(input.headers, "content-encoding");
  if (contentEncoding.present && contentEncoding.value?.trim().toLowerCase() !== "identity") return "write";

  const contentLength = singleHeader(input.headers, "content-length");
  if (!contentLength.present || contentLength.value === undefined || !/^\d{1,6}$/u.test(contentLength.value)) return "write";
  const declaredLength = Number(contentLength.value);
  if (declaredLength > LFS_BATCH_BODY_CAP_BYTES) return "write";

  let body: Buffer | undefined;
  try {
    body = await input.readBody();
  } catch {
    return "write";
  }
  if (body === undefined || body.length !== declaredLength) return "write";

  let bodyText: string;
  try {
    bodyText = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(body);
  } catch {
    return "write";
  }
  return classifyLfsBatchBodyText(bodyText);
}
