import { describe, expect, test } from "vitest";

import {
  GRAPHQL_BODY_CAP_BYTES,
  classifyGraphqlDocument,
  classifyGraphqlRequestBody,
  stripGraphqlStringsAndComments,
} from "./graphql-classify.ts";

function jsonBody(document: string, extra: Record<string, unknown> = {}): string {
  return JSON.stringify({ query: document, ...extra });
}

function classifyJson(body: string, overrides: Partial<Parameters<typeof classifyGraphqlRequestBody>[0]> = {}) {
  return classifyGraphqlRequestBody({
    contentType: "application/json",
    contentEncoding: undefined,
    contentLength: Buffer.byteLength(body),
    bodyText: body,
    ...overrides,
  });
}

describe("GraphQL document classification (conservative, fail-closed)", () => {
  test("pure queries — named, shorthand, with fragments and variables — classify read", () => {
    expect(classifyGraphqlDocument("query Viewer { viewer { login } }")).toBe("read");
    expect(classifyGraphqlDocument("{ viewer { login } }")).toBe("read");
    expect(classifyGraphqlDocument(`
      query Repos($first: Int!) { repositories(first: $first) { ...repoFields } }
      fragment repoFields on Repository { name }
    `)).toBe("read");
  });

  test("mutations and subscriptions classify write wherever the keyword appears", () => {
    expect(classifyGraphqlDocument("mutation { createIssue { id } }")).toBe("write");
    expect(classifyGraphqlDocument("subscription { issueUpdated { id } }")).toBe("write");
    // Mixed documents: one query plus one mutation is still a write.
    expect(classifyGraphqlDocument("query A { viewer { login } } mutation B { deleteRepo }")).toBe("write");
    // Weird whitespace/comment shapes stay writes.
    expect(classifyGraphqlDocument("# harmless\n  mutation\n{ x }")).toBe("write");
  });

  test("keywords inside strings and comments never poison a query; identifiers do not false-positive", () => {
    expect(stripGraphqlStringsAndComments('query { search(text: "mutation") { id } }')).not.toContain("mutation");
    expect(classifyGraphqlDocument('query { search(text: "run a mutation") { id } }')).toBe("read");
    expect(classifyGraphqlDocument('query { field(arg: """block mutation text""") { id } }')).toBe("read");
    expect(classifyGraphqlDocument("# mutation in a comment\nquery { viewer { id } }")).toBe("read");
    // "mutationRate" is an identifier, not the operation keyword.
    expect(classifyGraphqlDocument("query { mutationRate }")).toBe("read");
  });

  test("empty or unterminated documents classify write", () => {
    expect(classifyGraphqlDocument("")).toBe("write");
    expect(classifyGraphqlDocument('"unterminated string')).toBe("write");
  });
});

describe("GraphQL request body classification (MED-5 guardrails)", () => {
  test("a JSON query document classifies read; mutation classifies write", () => {
    expect(classifyJson(jsonBody("query { viewer { login } }"))).toBe("read");
    expect(classifyJson(jsonBody("mutation { createIssue { id } }"))).toBe("write");
  });

  test("application/graphql raw documents classify by content", () => {
    const raw = (body: string) => classifyGraphqlRequestBody({
      contentType: "application/graphql; charset=utf-8",
      contentEncoding: undefined,
      contentLength: Buffer.byteLength(body),
      bodyText: body,
    });
    expect(raw("query { viewer { login } }")).toBe("read");
    expect(raw("mutation { createIssue { id } }")).toBe("write");
  });

  test("batched arrays, persisted-query requests, and missing documents classify write", () => {
    expect(classifyJson(JSON.stringify([{ query: "query { a }" }, { query: "query { b }" }]))).toBe("write");
    expect(classifyJson(jsonBody("query { a }", {
      extensions: { persistedQuery: { sha256Hash: "abc", version: 1 } },
    }))).toBe("write");
    expect(classifyJson(JSON.stringify({ operationName: "A" }))).toBe("write");
    expect(classifyJson("not-json")).toBe("write");
  });

  test("oversize, truncated, compressed, and non-GraphQL content types classify write before parsing", () => {
    const bigDocument = jsonBody(`query { ${"a ".repeat(GRAPHQL_BODY_CAP_BYTES)} }`);
    expect(classifyJson(bigDocument)).toBe("write");
    // Declared length above the cap: write without reading the body.
    expect(classifyJson(jsonBody("query { a }"), { contentLength: GRAPHQL_BODY_CAP_BYTES + 1 })).toBe("write");
    // Buffered text shorter than the declared length: truncated.
    expect(classifyJson(jsonBody("query { a }"), { contentLength: 10_000 })).toBe("write");
    expect(classifyJson(jsonBody("query { a }"), { contentEncoding: "gzip" })).toBe("write");
    expect(classifyJson(jsonBody("query { a }"), { contentType: "text/plain" })).toBe("write");
    expect(classifyJson(jsonBody("query { a }"), { bodyText: undefined })).toBe("write");
  });
});
