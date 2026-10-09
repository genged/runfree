import { isRecord } from "@runfree/runtime-contracts/primitives";
// graphql-classify.ts — conservative GraphQL read/write classification.
//
// The only body parsing in the proxy, and only for POSTs to a host's declared
// `graphql.endpoints`. The proxy decides one bit — provably-pure-query (read)
// versus everything else (write) — with the industry guardrails: a hard size
// cap enforced before parsing, no decompression, and "unknown => write" for
// batched arrays, persisted-query/hash-only requests, and anything the
// conservative scanner cannot prove.

export const GRAPHQL_BODY_CAP_BYTES = 256 * 1024;

export type GraphqlBodyClass = "read" | "write";

export type GraphqlRequestBodyInput = {
  // Lowercased content-type header value (may carry parameters).
  contentType: string | undefined;
  // Any content-encoding means a compressed body: classified write unparsed.
  contentEncoding: string | undefined;
  // Declared request size, when the client sent one.
  contentLength: number | undefined;
  bodyText: string | undefined;
  capBytes?: number;
};

function isGraphqlLineTerminator(char: string | undefined): boolean {
  return char === "\n" || char === "\r";
}

// Strips string literals (block and regular, with escapes) and #-comments so
// keyword scanning cannot be confused by "mutation" appearing inside a string
// argument. Throws nothing. Returns undefined for a string the GraphQL lexer
// rejects (unterminated, or a regular string crossing a line terminator):
// stripping it would hide the rest of the document, which a lenient server
// might still run.
//
// A comment ends at any GraphQL line terminator (`\n`, `\r`, `\r\n`), not only
// `\n`: `{ a } # c\rmutation { x }` is a query and a mutation.
export function stripGraphqlStringsAndComments(document: string): string | undefined {
  let output = "";
  let index = 0;
  while (index < document.length) {
    const char = document[index];
    if (document.startsWith('"""', index)) {
      const end = document.indexOf('"""', index + 3);
      if (end === -1) return undefined;
      index = end + 3;
      continue;
    }
    if (char === '"') {
      index += 1;
      while (document[index] !== '"') {
        if (index >= document.length || isGraphqlLineTerminator(document[index])) return undefined;
        if (document[index] === "\\") {
          if (index + 1 >= document.length || isGraphqlLineTerminator(document[index + 1])) return undefined;
          index += 2;
          continue;
        }
        index += 1;
      }
      index += 1;
      continue;
    }
    if (char === "#") {
      while (index < document.length && !isGraphqlLineTerminator(document[index])) index += 1;
      continue;
    }
    output += char;
    index += 1;
  }
  return output;
}

// Classification is read ONLY IF the document is non-empty and provably free
// of mutation/subscription operations. Executing a mutation requires the
// top-level `mutation` keyword, so a keyword scan over the string-stripped
// document is sufficient and conservative: aliases and fragments cannot
// smuggle a write without the keyword, and any appearance of the keyword —
// even in a shape the scanner does not fully understand — classifies write.
export function classifyGraphqlDocument(document: string): GraphqlBodyClass {
  const stripped = stripGraphqlStringsAndComments(document);
  if (stripped === undefined || stripped.trim() === "") return "write";
  if (/(^|[^A-Za-z0-9_])(mutation|subscription)([^A-Za-z0-9_]|$)/.test(stripped)) return "write";
  return "read";
}


export function classifyGraphqlRequestBody(input: GraphqlRequestBodyInput): GraphqlBodyClass {
  const capBytes = input.capBytes ?? GRAPHQL_BODY_CAP_BYTES;

  // Compressed bodies are never decompressed or parsed (a decompression bomb
  // must not be classifiable as a read), and an absent or over-cap body —
  // including a declared length above the cap, which covers transport-level
  // truncation — fails closed as a write before any parsing.
  if (input.contentEncoding !== undefined && input.contentEncoding.trim() !== "" && input.contentEncoding.trim() !== "identity") {
    return "write";
  }
  if (input.contentLength !== undefined && input.contentLength > capBytes) return "write";
  if (input.bodyText === undefined) return "write";
  if (Buffer.byteLength(input.bodyText, "utf8") > capBytes) return "write";
  if (input.contentLength !== undefined && Buffer.byteLength(input.bodyText, "utf8") < input.contentLength) {
    // The buffered text is shorter than the declared body: truncated.
    return "write";
  }

  const contentType = (input.contentType ?? "").split(";", 1)[0].trim();
  if (contentType === "application/graphql") {
    return classifyGraphqlDocument(input.bodyText);
  }
  if (contentType !== "application/json") return "write";

  let parsed: unknown;
  try {
    parsed = JSON.parse(input.bodyText) as unknown;
  } catch {
    return "write";
  }
  // Batched operation arrays and non-object payloads classify write.
  if (!isRecord(parsed)) return "write";
  // Automatic-Persisted-Query / hash-only requests reference a document the
  // proxy cannot see: write.
  if (isRecord(parsed.extensions) && parsed.extensions.persistedQuery !== undefined) return "write";
  if (typeof parsed.query !== "string") return "write";
  return classifyGraphqlDocument(parsed.query);
}
