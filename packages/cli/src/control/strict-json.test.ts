import { describe, expect, test } from "vitest";

import { parseStrictJson } from "./strict-json.ts";

describe("strict JSON parser", () => {
  test("parses valid JSON without changing JSON semantics", () => {
    const source = String.raw`{"unicode":"\u0061","array":[true,false,null,-1.2e3]}`;
    expect(parseStrictJson(source)).toEqual(JSON.parse(source));
  });

  test("rejects duplicate decoded keys at any depth", () => {
    expect(() => parseStrictJson(String.raw`{"key":1,"\u006bey":2}`)).toThrow("duplicate object key");
    expect(() => parseStrictJson(`{"outer":{"key":1,"key":2}}`)).toThrow("duplicate object key");
  });

  test("rejects malformed and excessively nested input", () => {
    expect(() => parseStrictJson(`{"key":1,}`)).toThrow("expected string");
    expect(() => parseStrictJson(`{"key":\u00a01}`)).toThrow();
    expect(() => parseStrictJson(`1e999`)).toThrow("finite range");
    expect(() => parseStrictJson(`${"[".repeat(66)}null${"]".repeat(66)}`)).toThrow("nesting exceeds 64");
  });
});
