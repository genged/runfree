import { describe, expect, test } from "vitest";

import {
  admittedToUnresolvableHost,
  answeredByUpstream,
  countAdmittedEvents,
  curlProbeCommand,
  parseProbeAnswer,
} from "./proxy-answer.ts";

const CONNECT = "HTTP/1.1 200 Connection established\r\n\r\n";

describe("parseProbeAnswer", () => {
  test("a proxy denial is read from the header, whatever the code", () => {
    const output = `${CONNECT}HTTP/1.1 403 Forbidden\r\nx-runfree-blocked: missing-admission-record\r\n\r\n\nrunfree-probe-http-code=403\n`;
    const answer = parseProbeAnswer(output);
    expect(answer).toEqual({ code: "403", blocked: "missing-admission-record" });
    expect(answeredByUpstream(answer)).toBe(false);
    expect(admittedToUnresolvableHost(answer)).toBe(false);
  });

  test("an upstream 403 without the header is the upstream's answer", () => {
    const output = `${CONNECT}HTTP/2 403\r\nx-ratelimit-remaining: 0\r\n\r\n\nrunfree-probe-http-code=403\n`;
    expect(answeredByUpstream(parseProbeAnswer(output))).toBe(true);
  });

  test("only the last response's headers count after a retry", () => {
    const output = [
      `${CONNECT}HTTP/1.1 403 Forbidden\r\nx-runfree-blocked: host-not-allowlisted\r\n\r\n`,
      `${CONNECT}HTTP/1.1 200 OK\r\ncontent-type: text/html\r\n\r\n`,
      "\nrunfree-probe-http-code=200\n",
    ].join("");
    expect(parseProbeAnswer(output)).toEqual({ code: "200" });
  });

  test("the proxy's upstream-failure 502 is admission to an unresolvable host, not an upstream answer", () => {
    const answer = parseProbeAnswer(`${CONNECT}HTTP/1.1 502 Bad Gateway\r\n\r\n\nrunfree-probe-http-code=502\n`);
    expect(admittedToUnresolvableHost(answer)).toBe(true);
    expect(answeredByUpstream(answer)).toBe(false);
  });

  test("no response at all is neither", () => {
    const answer = parseProbeAnswer("curl: (28) Operation timed out\n\nrunfree-probe-http-code=000\n");
    expect(answer).toEqual({ code: "000" });
    expect(answeredByUpstream(answer)).toBe(false);
    expect(admittedToUnresolvableHost(answer)).toBe(false);
  });

  test("a recorded code overrides the marker for saved stub headers", () => {
    expect(parseProbeAnswer(`${CONNECT}HTTP/1.1 502 Bad Gateway\r\n\r\n`, "502\n")).toEqual({ code: "502" });
  });
});

describe("curlProbeCommand", () => {
  test("renders the flags the parser relies on and quotes the URL", () => {
    const command = curlProbeCommand("https://h.invalid/it's", { method: "POST", maxTimeSeconds: 10, retries: 2, insecure: true });
    expect(command).toBe(
      "curl -sS -k --retry 2 --retry-delay 1 --retry-all-errors --max-time 10 -X POST -D - -o /dev/null"
        + " -w '\\nrunfree-probe-http-code=%{http_code}\\n' 'https://h.invalid/it'\\''s'",
    );
  });
});

describe("countAdmittedEvents", () => {
  test("counts only admitted events for the exact host", () => {
    const logs = [
      'proxy-request: {"v":1,"event":"admitted","host":"a.invalid"}',
      'proxy-request: {"v":1,"event":"passthrough_abort","host":"a.invalid"}',
      'proxy-request: {"v":1,"event":"admitted","host":"b.invalid"}',
      '2026-09-25T00:00:00Z proxy-request: {"v":1,"event":"admitted","host":"a.invalid"}',
      "proxy-request: {truncated",
    ].join("\n");
    expect(countAdmittedEvents(logs, "a.invalid")).toBe(2);
  });
});
