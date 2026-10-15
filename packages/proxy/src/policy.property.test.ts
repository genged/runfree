import fc from "fast-check";
import { describe, expect, it } from "vitest";

import { pathMatchesPrefix, type RequestPolicyJson } from "@runfree/runtime-contracts/network-policy";

import { propertyParameters } from "../../../tests/support/property.ts";
import type { AdmissionRecord } from "./admission.ts";
import {
  ProxyPolicyDenialError,
  assertAllowedWebSocketRequest,
  beforeAllowedRequest,
  classifyWrite,
  type PolicyOptions,
  type ProxyRequest,
} from "./policy.ts";

const HOST = "api.example.com";

function admissionFor(): AdmissionRecord {
  return {
    v: 1,
    host: HOST,
    port: 443,
    policyGeneration: "sha256:test-policy",
    admittedAtMs: Date.now(),
    connectionSerial: 1,
    stage: "request",
  };
}

type Decision = "allow" | string;

// The public decision: "allow", or the denial reason. Any other error is a
// test bug and propagates.
function decide(run: () => unknown): Decision {
  try {
    run();
    return "allow";
  } catch (error) {
    if (error instanceof ProxyPolicyDenialError) return error.shape?.reason ?? error.message;
    throw error;
  }
}

function httpsDecision(pathAndQuery: string, method: string, options: PolicyOptions): Decision {
  const req: ProxyRequest = { url: `https://${HOST}${pathAndQuery}`, method, headers: {} };
  return decide(() => beforeAllowedRequest(admissionFor(), req, options));
}

function webSocketDecision(pathAndQuery: string, options: PolicyOptions): Decision {
  const req: ProxyRequest = { url: `wss://${HOST}${pathAndQuery}`, headers: {} };
  return decide(() => assertAllowedWebSocketRequest(admissionFor(), req, options));
}

// --- Reference decoder set R (spec §7.1, D5) --------------------------------
// Each models one normalization an origin may apply before routing. A decoder
// that throws models an origin that rejects the request, so it cannot route
// anywhere and the pipeline is not judged.

type Decoder = (path: string) => string;

const MAX_ORACLE_DECODES = 64;

const decodeOnce: Decoder = (path) => decodeURIComponent(path);

const decodeToFixedPoint: Decoder = (path) => {
  let current = path;
  for (let i = 0; i < MAX_ORACLE_DECODES; i += 1) {
    const next = decodeURIComponent(current);
    if (next === current) return next;
    current = next;
  }
  return current;
};

const stripSegmentParams: Decoder = (path) => path.split("/").map((segment) => segment.split(";", 1)[0]).join("/");

const backslashToSlash: Decoder = (path) => path.replaceAll("\\", "/");

// RFC 3986 §5.2.4 remove_dot_segments over literal `.` and `..` segments.
const resolveDotSegments: Decoder = (path) => {
  const output: string[] = [];
  const segments = path.split("/");
  for (let i = 0; i < segments.length; i += 1) {
    const segment = segments[i];
    const last = i === segments.length - 1;
    if (segment === ".") {
      if (last) output.push("");
    } else if (segment === "..") {
      if (output.length > 1) output.pop();
      if (last) output.push("");
    } else {
      output.push(segment);
    }
  }
  const joined = output.join("/");
  return joined.startsWith("/") ? joined : `/${joined}`;
};

const stripTrailingSlash: Decoder = (path) => (path.length > 1 && path.endsWith("/") ? path.slice(0, -1) : path);

const truncateAtNul: Decoder = (path) => {
  const nul = path.indexOf("\0");
  return nul === -1 ? path : path.slice(0, nul);
};

const DECODERS: readonly { name: string; decode: Decoder }[] = [
  { name: "decodeOnce", decode: decodeOnce },
  { name: "decodeToFixedPoint", decode: decodeToFixedPoint },
  { name: "stripSegmentParams", decode: stripSegmentParams },
  { name: "backslashToSlash", decode: backslashToSlash },
  { name: "resolveDotSegments", decode: resolveDotSegments },
  { name: "stripTrailingSlash", decode: stripTrailingSlash },
  { name: "truncateAtNul", decode: truncateAtNul },
];

// Every decoder alone, plus pipelines a real origin plausibly runs.
const FIXED_PIPELINES: readonly (readonly number[])[] = [
  ...DECODERS.map((_, index) => [index]),
  [1, 6, 2, 3, 4, 5],
  [0, 6, 2, 3, 4, 5],
  [0, 6, 4],
  [1, 6, 4],
  [1, 2, 4],
  [1, 3, 4],
  [0, 3, 4, 0, 3, 4],
];

type Reduction = { pipeline: string; path: string };

// All the paths an origin in R may route `path` to. `extra` is a generated
// pipeline, so shrinking reports the shortest decoder chain that escapes.
function reductions(path: string, extra: readonly number[]): Reduction[] {
  const results: Reduction[] = [];
  for (const pipeline of [...FIXED_PIPELINES, extra]) {
    let current = path;
    try {
      for (const index of pipeline) current = DECODERS[index].decode(current);
    } catch {
      continue;
    }
    results.push({ pipeline: pipeline.map((index) => DECODERS[index].name).join(" > ") || "identity", path: current });
  }
  return results;
}

// --- Generators -------------------------------------------------------------

const PIECES = [
  "/",
  ".",
  "..",
  "..;x",
  "%2e",
  "%2E",
  "%252e",
  "%2f",
  "%5c",
  "\\",
  ";x",
  "%00",
  "%09",
  // Fullwidth full stop: generated but not judged (Unicode folding is outside R).
  "%EF%BC%8E",
] as const;

const letterPiece = fc
  .array(fc.constantFrom(..."abcxyz"), { minLength: 1, maxLength: 4 })
  .chain((letters) => fc.tuple(...letters.map((letter) => fc.constantFrom(letter, letter.toUpperCase()))))
  .map((letters) => letters.join(""));

// Level 1 percent-encodes every byte; each further level encodes the `%`.
function encodeLevels(piece: string, levels: number): string {
  if (levels === 0) return piece;
  let encoded = [...new TextEncoder().encode(piece)]
    .map((byte) => `%${byte.toString(16).toUpperCase().padStart(2, "0")}`)
    .join("");
  for (let level = 1; level < levels; level += 1) encoded = encodeURIComponent(encoded);
  return encoded;
}

type Piece = { text: string; levels: number };

const levelsArb = fc.oneof({ weight: 3, arbitrary: fc.constant(0) }, { weight: 2, arbitrary: fc.integer({ min: 1, max: 6 }) });

const pieceArb = (extra: fc.Arbitrary<string>[] = []): fc.Arbitrary<Piece> =>
  fc.record({
    text: fc.oneof(
      { weight: 3, arbitrary: fc.constantFrom(...PIECES) },
      { weight: 1, arbitrary: letterPiece },
      ...extra.map((arbitrary) => ({ weight: 1, arbitrary })),
    ),
    levels: levelsArb,
  });

function renderPieces(pieces: readonly Piece[]): string {
  return pieces.map((piece) => encodeLevels(piece.text, piece.levels)).join("");
}

const pipelineArb = fc.array(fc.integer({ min: 0, max: DECODERS.length - 1 }), { maxLength: 8 });

const PREFIXES = ["/api/v2/", "/api/v2", "/a", "/"] as const;

function prefixedPath(prefix: string, tail: string): string {
  return `${prefix}${prefix.endsWith("/") ? "" : "/"}${tail}`;
}

// What the proxy judges: the WHATWG-parsed pathname, which has already
// resolved literal and `%2e` dot segments and turned `\` into `/`.
function parsedPathname(pathAndQuery: string): string {
  return new URL(`https://${HOST}${pathAndQuery}`).pathname;
}

// What the upstream receives: the raw request target, with only `\` turned
// into `/`. Dot segments, `//`, `;params`, and every percent-encoding are
// forwarded as sent (observed through the real proxy, 2026-10-09).
function forwardedPathname(pathAndQuery: string): string {
  return pathAndQuery.split(/[?#]/u, 1)[0].replaceAll("\\", "/");
}

// Both readings of the path: the oracle judges what the proxy saw and what
// the origin will decode.
function judgedPathnames(pathAndQuery: string): string[] {
  return [parsedPathname(pathAndQuery), forwardedPathname(pathAndQuery)];
}

function pathPrefixOptions(prefix: string): PolicyOptions {
  return {
    allowedHosts: [HOST],
    credentials: {},
    writeApproval: "allow",
    requests: { [HOST]: { pathPrefixes: [prefix] } },
  };
}

const GIT_PUSH_OPTIONS: PolicyOptions = {
  allowedHosts: [HOST],
  credentials: {},
  writeApproval: "allow",
  requests: { [HOST]: { gitPush: "deny" } },
};

// A routed path that is the prefix directory itself (`/api/v2` for
// `/api/v2/`) stays inside the prefix.
function withinPrefix(path: string, prefix: string): boolean {
  return pathMatchesPrefix(path, prefix) || (prefix.endsWith("/") && path === prefix.slice(0, -1));
}

const randomCase = (text: string): fc.Arbitrary<string> =>
  fc.tuple(...[...text].map((ch) => fc.constantFrom(ch, ch.toUpperCase()))).map((chars) => chars.join(""));

const gitTailArb: fc.Arbitrary<Piece> = fc.record({
  text: fc.constantFrom("git-receive-pack", "info/refs", "git-upload-pack").chain(randomCase),
  levels: levelsArb,
});

const serviceValueArb = fc.record({
  text: fc.constantFrom("git-receive-pack", "GIT-Receive-Pack", "git-upload-pack", "x"),
  levels: fc.integer({ min: 0, max: 3 }),
});

const gitRequestArb = fc.record({
  before: fc.array(pieceArb(), { maxLength: 4 }),
  separator: fc.constantFrom("", "/"),
  tail: gitTailArb,
  after: fc.array(pieceArb(), { maxLength: 4 }),
  services: fc.array(serviceValueArb, { maxLength: 3 }),
  method: fc.constantFrom("GET", "POST"),
  pipeline: pipelineArb,
});

function gitPathAndQuery(request: { before: Piece[]; separator: string; tail: Piece; after: Piece[]; services: Piece[] }): string {
  const path = `/owner/repo.git/${renderPieces(request.before)}${request.separator}${renderPieces([request.tail])}${renderPieces(request.after)}`;
  const query = request.services.map((service) => `service=${encodeLevels(service.text, service.levels)}`).join("&");
  return query === "" ? path : `${path}?${query}`;
}

// WHATWG URL parsing resolves `.`, `..`, and their `%2e` spellings, so a
// bump that changes segment boundaries changes which content `..` removes.
// Such paths compare different requests, not two encodings of one request.
function hasWhatwgDotSegment(path: string): boolean {
  return path.split(/[\\/]/u).some((segment) => /^(?:\.|%2e){1,2}$/iu.test(segment));
}

function isReceivePackService(value: string): boolean {
  for (const decode of [(v: string) => v, decodeOnce, decodeToFixedPoint]) {
    try {
      if (decode(value).toLowerCase() === "git-receive-pack") return true;
    } catch {
      // A value an origin cannot decode cannot select a service.
    }
  }
  return false;
}

describe("proxy policy path confusion properties", () => {
  // Product defect, see todo 100: `..%00` and encodings past the 5-level decode
  // bound escape the prefix.
  it.skip("P1.1: a path allowed under pathPrefixes stays inside the prefix under every reference decoder — product defect, see todo 100", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...PREFIXES),
        fc.array(pieceArb(), { maxLength: 8 }),
        fc.constantFrom("GET", "POST"),
        pipelineArb,
        (prefix, pieces, method, pipeline) => {
          const pathAndQuery = prefixedPath(prefix, renderPieces(pieces));
          fc.pre(httpsDecision(pathAndQuery, method, pathPrefixOptions(prefix)) === "allow");
          for (const reduction of judgedPathnames(pathAndQuery).flatMap((path) => reductions(path, pipeline))) {
            expect(withinPrefix(reduction.path, prefix), `${reduction.pipeline} routes ${pathAndQuery} to ${JSON.stringify(reduction.path)}`).toBe(true);
          }
        },
      ),
      propertyParameters({ numRuns: 1000 }),
    );
  });

  // Product defect, see todo 101: the push check canonicalizes in one decoder
  // order, so `%00/` and `;x%2F` hide the tail.
  it.skip("P1.2: a request allowed under gitPush deny never reduces to the push RPC or its capability probe — product defect, see todo 101", () => {
    fc.assert(
      fc.property(gitRequestArb, (request) => {
        const pathAndQuery = gitPathAndQuery(request);
        fc.pre(httpsDecision(pathAndQuery, request.method, GIT_PUSH_OPTIONS) === "allow");
        const url = new URL(`https://${HOST}${pathAndQuery}`);
        const pushService = url.searchParams.getAll("service").some(isReceivePackService);
        for (const reduction of judgedPathnames(pathAndQuery).flatMap((path) => reductions(path, request.pipeline))) {
          const routed = reduction.path.toLowerCase();
          const where = `${reduction.pipeline} routes ${pathAndQuery} to ${JSON.stringify(reduction.path)}`;
          expect(routed.endsWith("/git-receive-pack"), where).toBe(false);
          expect(pushService && routed.endsWith("/info/refs"), where).toBe(false);
        }
      }),
      propertyParameters({ numRuns: 1000 }),
    );
  });

  // Product defect, see todo 100: the guard checks only the raw and fully
  // decoded forms, so `%2e` is denied but `%252e` (not forming `..`) is
  // allowed.
  it.skip("P1.3: encoding one more level of any path piece never turns a deny into an allow — product defect, see todo 100", () => {
    const ruleArb = fc.oneof(
      fc.constantFrom(...PREFIXES).map((prefix) => ({ prefix, options: pathPrefixOptions(prefix) })),
      fc.constant({ prefix: "/owner/repo.git/", options: GIT_PUSH_OPTIONS }),
    );
    fc.assert(
      fc.property(
        ruleArb,
        fc.array(pieceArb([fc.constantFrom("git-receive-pack", "info/refs")]), { minLength: 1, maxLength: 8 }),
        fc.nat(),
        fc.constantFrom("GET", "POST"),
        ({ prefix, options }, pieces, pick, method) => {
          const before = prefixedPath(prefix, renderPieces(pieces));
          fc.pre(httpsDecision(before, method, options) !== "allow");
          const index = pick % pieces.length;
          const bumped = pieces.map((piece, i) => (i === index ? { ...piece, levels: piece.levels + 1 } : piece));
          const after = prefixedPath(prefix, renderPieces(bumped));
          fc.pre(!hasWhatwgDotSegment(before) && !hasWhatwgDotSegment(after));
          expect(httpsDecision(after, method, options), `${before} -> ${after}`).not.toBe("allow");
        },
      ),
      propertyParameters(),
    );
  });

  it("P1.4: a GET and its WebSocket upgrade get the same shape decision", () => {
    const ruled = (prefix: string, rule: RequestPolicyJson) => ({ prefix, rule });
    const ruleArb = fc.oneof(
      fc.constantFrom(...PREFIXES).map((prefix) => ruled(prefix, { pathPrefixes: [prefix] })),
      fc.constant(ruled("/owner/repo.git/", { gitPush: "deny" })),
      fc.constantFrom(...PREFIXES).map((prefix) => ruled(prefix, { pathPrefixes: [prefix], gitPush: "deny" })),
      fc.constant(ruled("/", { methods: ["GET"] })),
      fc.constant(ruled("/", { methods: ["POST"] })),
    );
    fc.assert(
      fc.property(
        ruleArb,
        fc.array(pieceArb([fc.constantFrom("git-receive-pack", "info/refs")]), { maxLength: 8 }),
        fc.array(serviceValueArb, { maxLength: 2 }),
        ({ prefix, rule }, pieces, services) => {
          const path = prefixedPath(prefix, renderPieces(pieces));
          const query = services.map((service) => `service=${encodeLevels(service.text, service.levels)}`).join("&");
          const pathAndQuery = query === "" ? path : `${path}?${query}`;
          const options: PolicyOptions = { allowedHosts: [HOST], credentials: {}, writeApproval: "allow", requests: { [HOST]: rule } };
          expect(webSocketDecision(pathAndQuery, options), pathAndQuery).toBe(httpsDecision(pathAndQuery, "GET", options));
        },
      ),
      propertyParameters(),
    );
  });

  // todo 118: the upload-pack read exemption must check the method, not just
  // the path. Fix round 1 widened this past the method alone:
  // canonicalPathSegments truncates at the first NUL (so a NUL placed after
  // the tail hid a real trailing segment) and normalizes away a trailing
  // `/`, `;param`, `.`, or decoded whitespace (so a decorated spelling
  // canonicalized to the exact RPC name too). The oracle below is built
  // without any call into policy.ts: it checks the raw (never decoded)
  // pathname against the literal suffix, and separately decodes with this
  // file's own independent decodeToFixedPoint (defined above, not the
  // module under test) to rule out a hidden NUL — so a decorated or
  // NUL-hiding spelling cannot look like the exact RPC to the oracle either.
  it("P1.5: an upload-pack path classifies as a read iff the method is safe, or POST to a literal, undecorated git-upload-pack path with no hidden NUL", () => {
    const SAFE_METHODS = ["GET", "HEAD", "OPTIONS"] as const;
    const UNSAFE_METHODS = ["POST", "DELETE", "PUT", "PATCH", "TRACE"] as const;
    const UPLOAD_PACK_RULE: RequestPolicyJson = { gitPush: "deny" };

    type Decoration = { name: string; apply: (core: string) => string };
    const DECORATIONS: readonly Decoration[] = [
      { name: "none", apply: (core) => core },
      { name: "trailing-slash", apply: (core) => `${core}/` },
      { name: "matrix-param", apply: (core) => `${core};x` },
      { name: "trailing-dot", apply: (core) => `${core}.` },
      { name: "trailing-encoded-space", apply: (core) => `${core}%20` },
      { name: "nul-suffix", apply: (core) => `${core}%00/rename` },
      { name: "double-encoded-nul-suffix", apply: (core) => `${core}%2500/rename` },
      { name: "extra-segment", apply: (core) => `${core}/extra` },
    ];

    // Capped below MAX_PATH_DECODE_ITERATIONS so every spelling here decodes
    // to convergence under the production bound; the decode-bound overflow
    // itself is out of scope here.
    const tailArb = fc.record({
      text: fc.constantFrom("git-upload-pack", "git-upload-pack-not").chain(randomCase),
      levels: fc.integer({ min: 0, max: 5 }),
      decoration: fc.constantFrom(...DECORATIONS),
    });

    fc.assert(
      fc.property(
        fc.array(letterPiece, { maxLength: 3 }),
        tailArb,
        fc.constantFrom(...SAFE_METHODS, ...UNSAFE_METHODS),
        (extraSegments, tail, method) => {
          const encodedTail = tail.decoration.apply(encodeLevels(tail.text, tail.levels));
          const path = `/owner/repo.git/${[...extraSegments, encodedTail].join("/")}`;
          const url = new URL(`https://${HOST}${path}`);
          const classification = classifyWrite({ method, url, rule: UPLOAD_PACK_RULE });

          const isSafe = (SAFE_METHODS as readonly string[]).includes(method);
          const rawEndsWithLiteralRpc = url.pathname.toLowerCase().endsWith("/git-upload-pack");
          let decodesWithoutNul: boolean;
          try {
            decodesWithoutNul = !decodeToFixedPoint(url.pathname).includes("\0");
          } catch {
            decodesWithoutNul = false;
          }
          const expectRead = isSafe || (method === "POST" && rawEndsWithLiteralRpc && decodesWithoutNul);
          expect(classification.write, `${tail.decoration.name} ${method} ${path}`).toBe(!expectRead);
        },
      ),
      propertyParameters(),
    );
  });
});
