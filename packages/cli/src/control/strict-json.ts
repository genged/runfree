export const STRICT_JSON_MAX_DEPTH = 64;

export class StrictJsonError extends Error {
  constructor(message: string, offset: number) {
    super(`invalid JSON at byte ${offset}: ${message}`);
    this.name = "StrictJsonError";
  }
}

export function parseStrictJson(source: string, maxDepth = STRICT_JSON_MAX_DEPTH): unknown {
  let offset = 0;

  const fail = (message: string): never => {
    throw new StrictJsonError(message, Buffer.byteLength(source.slice(0, offset)));
  };
  const whitespace = (): void => {
    while (offset < source.length && " \t\r\n".includes(source[offset] ?? "")) offset += 1;
  };
  const string = (): string => {
    const start = offset;
    if (source[offset] !== '"') fail("expected string");
    offset += 1;
    while (offset < source.length) {
      const character = source[offset];
      if (character === '"') {
        offset += 1;
        try {
          const parsed = JSON.parse(source.slice(start, offset));
          if (typeof parsed !== "string") fail("expected string");
          return parsed;
        } catch {
          return fail("malformed string");
        }
      }
      if (character === "\\") {
        offset += 2;
      } else {
        if ((character?.codePointAt(0) ?? 0) < 0x20) fail("unescaped control character in string");
        offset += 1;
      }
    }
    return fail("unterminated string");
  };
  const value = (depth: number): unknown => {
    whitespace();
    if (depth > maxDepth) fail(`nesting exceeds ${maxDepth}`);
    const character = source[offset];
    if (character === '"') return string();
    if (character === "{") {
      offset += 1;
      whitespace();
      const result: Record<string, unknown> = {};
      const keys = new Set<string>();
      if (source[offset] === "}") {
        offset += 1;
        return result;
      }
      while (offset < source.length) {
        whitespace();
        const key = string();
        if (keys.has(key)) fail(`duplicate object key ${JSON.stringify(key)}`);
        keys.add(key);
        whitespace();
        if (source[offset] !== ":") fail("expected colon after object key");
        offset += 1;
        Object.defineProperty(result, key, {
          value: value(depth + 1),
          configurable: true,
          enumerable: true,
          writable: true,
        });
        whitespace();
        if (source[offset] === "}") {
          offset += 1;
          return result;
        }
        if (source[offset] !== ",") fail("expected comma between object entries");
        offset += 1;
      }
      fail("unterminated object");
    }
    if (character === "[") {
      offset += 1;
      whitespace();
      const result: unknown[] = [];
      if (source[offset] === "]") {
        offset += 1;
        return result;
      }
      while (offset < source.length) {
        result.push(value(depth + 1));
        whitespace();
        if (source[offset] === "]") {
          offset += 1;
          return result;
        }
        if (source[offset] !== ",") fail("expected comma between array entries");
        offset += 1;
      }
      fail("unterminated array");
    }
    for (const [literal, parsed] of [["true", true], ["false", false], ["null", null]] as const) {
      if (source.startsWith(literal, offset)) {
        offset += literal.length;
        return parsed;
      }
    }
    const number = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(source.slice(offset))?.[0];
    if (number !== undefined) {
      offset += number.length;
      const parsed = JSON.parse(number) as number;
      if (!Number.isFinite(parsed)) fail("number is outside the finite range");
      return parsed;
    }
    fail("expected a JSON value");
  };

  const parsed = value(0);
  whitespace();
  if (offset !== source.length) fail("unexpected trailing content");
  return parsed;
}
