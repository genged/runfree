// Who answered a request the agent sent through the proxy.
//
// Live probes used to assert a bare HTTP code, which conflates three parties:
// the proxy's own denials, the proxy's upstream-failure answer, and whatever a
// public upstream chose to say (GitHub answers an exhausted unauthenticated
// rate limit with 403, indistinguishable from a denial by code alone). The
// proxy marks every denial it synthesizes with `x-runfree-blocked`, so the
// header — not the code — says whether the proxy refused.
//
// Two kinds of probe build on that:
//   - Decision probes target an allowlisted `.invalid` host (RFC 6761, never
//     resolves). The proxy's decision is the whole subject; an admitted
//     request comes back as the proxy's upstream-failure 502 and is logged as
//     an `admitted` event. No public service is involved.
//   - End-to-end probes target a real public host because their subject
//     includes the firewall's resolved-IP sets and the proxy's real egress.
//     They pass on any answer the upstream itself gave, so an upstream's
//     rate limit or error page cannot fail them.
//
// A local HTTPS upstream cannot replace the public host: the firewall refuses
// private, loopback and runtime-subnet answers for allowlisted hosts
// (`classifyResolvedIpv4`), which is the SSRF guard working as designed.

import { docker, dockerOrThrow } from "./docker.ts";

/** What the proxy answers an admitted request whose upstream it cannot reach. */
export const PROXY_UPSTREAM_FAILURE_CODE = "502";

export type ProbeAnswer = Readonly<{
  /** The final HTTP status curl saw, or `000` when no response arrived. */
  code: string;
  /** The proxy's denial reason when the proxy itself refused the request. */
  blocked?: string;
}>;

export type CurlProbeOptions = Readonly<{
  method?: string;
  maxTimeSeconds: number;
  /** Retries transient failures; an upstream's 408/429/5xx is retried too. */
  retries?: number;
  insecure?: boolean;
}>;

const CODE_MARKER = "runfree-probe-http-code=";

/**
 * A curl command whose output `parseProbeAnswer` reads: the response headers
 * of every response on stdout (the body is discarded), then the final code.
 */
export function curlProbeCommand(url: string, options: CurlProbeOptions): string {
  const flags = ["-sS"];
  if (options.insecure) flags.push("-k");
  if (options.retries !== undefined) flags.push("--retry", String(options.retries), "--retry-delay", "1", "--retry-all-errors");
  flags.push("--max-time", String(options.maxTimeSeconds));
  if (options.method !== undefined) flags.push("-X", options.method);
  return `curl ${flags.join(" ")} -D - -o /dev/null -w '\\n${CODE_MARKER}%{http_code}\\n' '${url.replaceAll("'", "'\\''")}'`;
}

/**
 * Reads a `curlProbeCommand` output, or the headers a stub saved with
 * `curl -D` plus the code it recorded. Only the last response's headers count:
 * the CONNECT response and any retried attempt come before it.
 */
export function parseProbeAnswer(output: string, recordedCode?: string): ProbeAnswer {
  const lines = output.split(/\r?\n/u);
  const reversed = [...lines].reverse();
  const code = recordedCode?.trim()
    ?? reversed.find((line) => line.startsWith(CODE_MARKER))?.slice(CODE_MARKER.length).trim()
    ?? "000";
  const fromEnd = reversed.findIndex((line) => /^HTTP\/\S+ \d{3}/u.test(line));
  const lastStatus = fromEnd < 0 ? -1 : lines.length - 1 - fromEnd;
  const blocked = lastStatus < 0
    ? undefined
    : lines.slice(lastStatus + 1)
      .find((line) => line.toLowerCase().startsWith("x-runfree-blocked:"))
      ?.slice("x-runfree-blocked:".length)
      .trim();
  return { code, ...(blocked !== undefined ? { blocked } : {}) };
}

/**
 * The upstream itself answered: a real HTTP status that the proxy neither
 * synthesized as a denial nor produced for an unreachable upstream.
 */
export function answeredByUpstream(answer: ProbeAnswer): boolean {
  return answer.blocked === undefined && /^[1-5]\d\d$/u.test(answer.code) && answer.code !== PROXY_UPSTREAM_FAILURE_CODE;
}

/**
 * The proxy admitted and forwarded a request to an unresolvable host: no
 * denial, and the upstream-failure answer rather than any other.
 */
export function admittedToUnresolvableHost(answer: ProbeAnswer): boolean {
  return answer.blocked === undefined && answer.code === PROXY_UPSTREAM_FAILURE_CODE;
}

const PROXY_VERBOSE_MARKER_DIR = "/run/runfree-proxy-verbose";

/**
 * Turns on the proxy's verbose request logging until `disable` is called. The
 * proxy writes `admitted` events only while a marker file exists in its
 * verbose directory; each caller uses its own marker name so overlapping
 * windows do not end each other.
 */
export function enableProxyVerboseLogging(proxyId: string, marker: string): Readonly<{ disable(): void }> {
  dockerOrThrow("enable proxy verbose logging", [
    "exec", "--user", "0:0", proxyId, "sh", "-c",
    `mkdir -p ${PROXY_VERBOSE_MARKER_DIR} && touch ${PROXY_VERBOSE_MARKER_DIR}/${marker}`,
  ]);
  return {
    disable: () => {
      docker(["exec", "--user", "0:0", proxyId, "rm", "-f", `${PROXY_VERBOSE_MARKER_DIR}/${marker}`]);
    },
  };
}

/**
 * Counts the proxy's structured `admitted` events for `host`. The proxy logs
 * them only while verbose logging is on (`enableProxyVerboseLogging`). Compare
 * counts across a probe rather than filtering by time, so host/daemon clock
 * skew cannot let an earlier event count as the probe's.
 */
export function proxyAdmittedEventCount(proxyId: string, host: string): number {
  return countAdmittedEvents(dockerOrThrow("proxy logs", ["logs", proxyId]), host);
}

export function countAdmittedEvents(logs: string, host: string): number {
  const prefix = "proxy-request: ";
  let count = 0;
  for (const line of logs.split("\n")) {
    const at = line.indexOf(prefix);
    if (at < 0) continue;
    try {
      const event = JSON.parse(line.slice(at + prefix.length)) as { event?: unknown; host?: unknown };
      if (event.event === "admitted" && event.host === host) count += 1;
    } catch {
      // A line that is not one whole event is not an admission.
    }
  }
  return count;
}
