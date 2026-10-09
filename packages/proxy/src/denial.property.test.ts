// Property tests for the denial display helpers (spec Phase 6, P6.4).
//
// These helpers bound the request host, path, and method before they reach a
// denial body, an event line, or a pending approval record that the host
// prints. The input is the agent's request, so any string is possible.
import fc from "fast-check";
import { describe, expect, test } from "vitest";

import { propertyParameters } from "../../../tests/support/property.ts";
import { DENIAL_PATH_LIMIT, displayHostname, displayMethod, safePathname } from "./denial.ts";

// C0 and C1 controls (ESC included) and the Unicode bidi overrides, embeddings,
// isolates, and marks.
const TERMINAL_UNSAFE = /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/u;

const requestText = fc.string({
  unit: fc.oneof(
    fc.constantFrom("\u001b", "\u009b", "\u0007", "\u0000", "\t", "\n", "\r", "\u202e", "\u2066", "\u200e", "%", "/", ".", "?", "#", "\\"),
    fc.string({ unit: "binary", minLength: 1, maxLength: 1 }),
  ),
  maxLength: 80,
});

describe("denial display helpers", () => {
  test("P6.4: the host, path, and method helpers never return terminal control or bidi characters", () => {
    fc.assert(
      fc.property(requestText, requestText, requestText, (host, rawPath, method) => {
        expect(displayHostname(host)).not.toMatch(TERMINAL_UNSAFE);
        expect(displayMethod(method)).not.toMatch(TERMINAL_UNSAFE);
        expect(displayMethod(method).length).toBeLessThanOrEqual(16);
        for (const url of [rawPath, `/${rawPath}`, `https://placeholder.invalid/${rawPath}`]) {
          const pathname = safePathname(url);
          if (pathname === undefined) continue;
          expect(pathname).not.toMatch(TERMINAL_UNSAFE);
          expect(pathname.length).toBeLessThanOrEqual(DENIAL_PATH_LIMIT);
        }
      }),
      propertyParameters(),
    );
  });
});
