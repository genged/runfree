import net from "node:net";
import tls from "node:tls";
import { afterEach, beforeAll, describe, expect, test } from "vitest";

import { AdmissionRegistry, type AdmissionObservation, type AdmissionRecord } from "./admission.ts";
import { createMockttpAdapter, generateProxyCA, type MockttpAdapter } from "./mockttp-adapter.ts";
import type { ProxyRequest } from "./policy.ts";

// These tests drive createMockttpAdapter over real loopback sockets and assert
// what the agent side sees on the wire plus the arguments of the adapter's
// callbacks. Upstream is never contacted: every admitted rule answers from its
// own beforeRequest, and every unadmitted path is refused by the adapter.

const SAFETY_MS = 3_000;
const MISSING_BODY = "missing admission";
const BLOCKED_WS_BODY = "blocked by agent proxy policy\nconnection did not pass the Runfree CONNECT admission boundary\n";

let ca: { cert: string; key: string };

beforeAll(async () => {
  ca = await generateProxyCA();
});

type Harness = {
  adapter: MockttpAdapter;
  admissions: AdmissionRegistry;
  missing: ProxyRequest[];
  missingWebSockets: ProxyRequest[];
  proxyAuthRefusals: number;
  sni: AdmissionObservation[];
  stop(): Promise<void>;
};

const openTlsSockets: tls.TLSSocket[] = [];
const openSockets: net.Socket[] = [];
const runningHarnesses: Harness[] = [];

async function destroyAndAwaitClose(sockets: net.Socket[]): Promise<void> {
  await Promise.all(sockets.map(async (socket) => {
    if (socket.closed) return;
    const closed = new Promise<void>((resolve) => socket.once("close", () => resolve()));
    socket.destroy();
    await closed;
  }));
}

// Runs on the pass and the fail path. Destroying a net socket while the
// client TLS wrapper on it is still open crashes the worker (SIGSEGV) on
// Node 22, so a failed assertion would hide every later test. Close the TLS
// wrappers first, then their sockets, and stop the adapters only after every
// client socket has closed.
afterEach(async () => {
  await destroyAndAwaitClose(openTlsSockets.splice(0));
  await destroyAndAwaitClose(openSockets.splice(0));
  await Promise.all(runningHarnesses.splice(0).map(async (harness) => await harness.stop()));
});

async function bounded<T>(promise: Promise<T>, label: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => reject(new Error(`safety timeout: ${label}`)), SAFETY_MS);
  });
  try {
    return await Promise.race([promise, timeout]);
  } finally {
    clearTimeout(timer);
  }
}

function missingAdmissionResponse(_request: ProxyRequest) {
  return {
    response: {
      statusCode: 403,
      headers: { "content-length": String(MISSING_BODY.length) },
      body: MISSING_BODY,
    },
  };
}

function reply(statusCode: number, body: string) {
  return { response: { statusCode, headers: { "content-length": String(body.length) }, body } };
}

async function harness(
  configure: (adapter: MockttpAdapter, state: Harness) => Promise<void> = async () => {},
  missingResponse: (request: ProxyRequest) => ReturnType<typeof missingAdmissionResponse> = missingAdmissionResponse,
): Promise<Harness> {
  const admissions = new AdmissionRegistry();
  const state = {
    admissions,
    missing: [] as ProxyRequest[],
    missingWebSockets: [] as ProxyRequest[],
    proxyAuthRefusals: 0,
    sni: [] as AdmissionObservation[],
  } as Harness;
  const adapter = await createMockttpAdapter({
    admissions,
    cert: ca.cert,
    key: ca.key,
    missingAdmissionResponse: (request) => {
      state.missing.push(request);
      return missingResponse(request);
    },
    onMissingWebSocket: (request) => {
      state.missingWebSockets.push(request);
    },
    onProxyAuthRefused: () => {
      state.proxyAuthRefusals += 1;
    },
    onSniObservation: (observation) => {
      state.sni.push(observation);
    },
  });
  state.adapter = adapter;
  let stopped = false;
  state.stop = async () => {
    if (stopped) return;
    stopped = true;
    await adapter.stop();
  };
  await configure(adapter, state);
  await adapter.start();
  runningHarnesses.push(state);
  return state;
}

// Buffers everything a socket delivers so a test can read one HTTP response at
// a time on a keep-alive connection, or everything up to the close.
class Wire {
  #buffer: Buffer = Buffer.alloc(0);
  #closed = false;
  #error: Error | undefined;
  #wake: (() => void) | undefined;

  constructor(readonly socket: net.Socket) {
    socket.on("data", (chunk: Buffer) => {
      this.#buffer = Buffer.concat([this.#buffer, chunk]);
      this.#wake?.();
    });
    socket.on("error", (error) => {
      this.#error = error;
      this.#wake?.();
    });
    socket.on("close", () => {
      this.#closed = true;
      this.#wake?.();
    });
  }

  async #until<T>(take: (buffer: Buffer, closed: boolean) => T | undefined, label: string): Promise<T> {
    return await bounded((async () => {
      for (;;) {
        const taken = take(this.#buffer, this.#closed);
        if (taken !== undefined) return taken;
        if (this.#error) throw this.#error;
        if (this.#closed) throw new Error(`connection closed before ${label}`);
        await new Promise<void>((resolve) => {
          this.#wake = resolve;
        });
      }
    })(), label);
  }

  // One response framed by content-length (or by the close when absent).
  async response(): Promise<{ head: string; status: string; headers: Array<[string, string]>; body: string }> {
    return await this.#until((buffer, closed) => {
      const end = buffer.indexOf("\r\n\r\n");
      if (end < 0) return undefined;
      const head = buffer.subarray(0, end).toString("latin1");
      const [status = "", ...lines] = head.split("\r\n");
      const headers = lines.map((line): [string, string] => {
        const colon = line.indexOf(":");
        return [line.slice(0, colon).toLowerCase(), line.slice(colon + 1).trim()];
      });
      const length = headers.find(([name]) => name === "content-length")?.[1];
      const bodyStart = end + 4;
      const bodyEnd = length === undefined ? (closed ? buffer.length : undefined) : bodyStart + Number(length);
      if (bodyEnd === undefined || buffer.length < bodyEnd) return undefined;
      this.#buffer = buffer.subarray(bodyEnd);
      return { head, status, headers, body: buffer.subarray(bodyStart, bodyEnd).toString("utf8") };
    }, "a full response");
  }

  async everythingUntilClose(): Promise<string> {
    return await this.#until((buffer, closed) => (closed ? buffer.toString("utf8") : undefined), "the close");
  }
}

async function openClient(adapter: MockttpAdapter): Promise<net.Socket> {
  const socket = net.connect(adapter.port, "127.0.0.1");
  openSockets.push(socket);
  await bounded(new Promise<void>((resolve, reject) => {
    socket.once("connect", resolve);
    socket.once("error", reject);
  }), "client connect");
  return socket;
}

async function readConnectHead(socket: net.Socket): Promise<string> {
  return await bounded(new Promise<string>((resolve, reject) => {
    let buffered = Buffer.alloc(0);
    const onData = (chunk: Buffer) => {
      buffered = Buffer.concat([buffered, chunk]);
      const end = buffered.indexOf("\r\n\r\n");
      if (end < 0) return;
      socket.off("data", onData);
      socket.off("error", reject);
      // Nothing may follow the CONNECT answer before the client speaks TLS.
      expect(buffered.length).toBe(end + 4);
      resolve(buffered.subarray(0, end).toString("latin1"));
    };
    socket.on("data", onData);
    socket.once("error", reject);
  }), "CONNECT answer");
}

type Tunnel = { socket: net.Socket; connectHead: string; record: AdmissionRecord | undefined };

// Opens a CONNECT tunnel. The admission record is bound to the client port
// before CONNECT is written, as the guard does in production.
async function connectTunnel(
  state: Harness,
  host: string,
  options: { bind?: boolean; proxyAuthorization?: string; identity?: Parameters<AdmissionRegistry["mint"]>[2] } = {},
): Promise<Tunnel> {
  const socket = await openClient(state.adapter);
  let record: AdmissionRecord | undefined;
  if (options.bind !== false) {
    record = state.admissions.mint(host, "g1", options.identity);
    state.admissions.bind(socket.localPort ?? 0, record);
  }
  socket.write([
    `CONNECT ${host}:443 HTTP/1.1`,
    `Host: ${host}:443`,
    ...(options.proxyAuthorization ? [`Proxy-Authorization: ${options.proxyAuthorization}`] : []),
    "",
    "",
  ].join("\r\n"));
  return { socket, connectHead: await readConnectHead(socket), record };
}

async function startTls(socket: net.Socket, servername: string): Promise<tls.TLSSocket> {
  const secure = tls.connect({ socket, servername, rejectUnauthorized: false });
  openTlsSockets.push(secure);
  await bounded(new Promise<void>((resolve, reject) => {
    secure.once("secureConnect", resolve);
    secure.once("error", reject);
  }), "TLS handshake");
  return secure;
}

const TLS_CUT = "Client network socket disconnected before secure TLS connection was established";

// For a handshake the adapter must refuse. A handshake that completes anyway
// is reported, and afterEach closes the live connection.
async function tlsOutcome(socket: net.Socket, servername: string): Promise<string> {
  return await startTls(socket, servername).then(() => "handshake completed", (error: Error) => error.message);
}

async function admittedTls(state: Harness, host: string, options: Parameters<typeof connectTunnel>[2] = {}) {
  const tunnel = await connectTunnel(state, host, options);
  expect(tunnel.connectHead).toBe("HTTP/1.1 200 OK");
  const secure = await startTls(tunnel.socket, host);
  return { ...tunnel, secure, wire: new Wire(secure) };
}

function get(path: string, host: string, extra: string[] = []): string {
  return [`GET ${path} HTTP/1.1`, `Host: ${host}`, ...extra, "", ""].join("\r\n");
}

const WS_UPGRADE_HEADERS = [
  "Upgrade: websocket",
  "Connection: Upgrade",
  "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
  "Sec-WebSocket-Version: 13",
];

type RuleLog = { matched: Array<[AdmissionRecord, ProxyRequest]>; handled: Array<[AdmissionRecord, ProxyRequest]> };

// The policy shape server.ts registers: a matching rule first, then a
// catch-all with no matcher that must still refuse unadmitted requests.
async function policyRules(adapter: MockttpAdapter, log: RuleLog, catchAll: RuleLog): Promise<void> {
  await adapter.forAnyRequest()
    .matching((admission, request) => {
      log.matched.push([admission, request]);
      return true;
    })
    .always()
    .thenPassThrough({
      beforeRequest: (admission, request) => {
        log.handled.push([admission, request]);
        return reply(299, "ok");
      },
    });
  await adapter.forAnyRequest()
    .always()
    .thenPassThrough({
      beforeRequest: (admission, request) => {
        catchAll.handled.push([admission, request]);
        return reply(298, "catch-all");
      },
    });
}

function ruleLog(): RuleLog {
  return { matched: [], handled: [] };
}

describe("createMockttpAdapter admission boundary", () => {
  test("B1: an admitted request reaches the matcher and beforeRequest with its record", async () => {
    const log = ruleLog();
    const catchAll = ruleLog();
    const state = await harness(async (adapter) => await policyRules(adapter, log, catchAll));
    const { record, secure, wire } = await admittedTls(state, "api.example.test");

    secure.write(get("/v1/thing", "api.example.test"));
    const response = await wire.response();

    expect(response.status).toBe("HTTP/1.1 299 unknown");
    expect(response.body).toBe("ok");
    expect(state.sni).toEqual([{ kind: "admitted", record: { ...record, stage: "sni" } }]);
    expect(log.matched).toHaveLength(1);
    expect(log.handled).toHaveLength(1);
    for (const [admission] of [...log.matched, ...log.handled]) {
      expect(admission).toMatchObject({
        host: "api.example.test",
        stage: "request",
        connectionSerial: record?.connectionSerial,
      });
    }
    expect(log.handled[0]?.[1].url).toBe("https://api.example.test/v1/thing");
    expect(catchAll.handled).toEqual([]);
    expect(state.missing).toEqual([]);
  });

  test("B2: an unadmitted plain request never reaches a matcher and falls to mockttp's 503", async () => {
    const log = ruleLog();
    const state = await harness(async (adapter) => {
      await adapter.forAnyRequest()
        .matching((admission, request) => {
          log.matched.push([admission, request]);
          return true;
        })
        .always()
        .thenPassThrough({ beforeRequest: (admission, request) => {
          log.handled.push([admission, request]);
          return reply(299, "ok");
        } });
    });
    const socket = await openClient(state.adapter);
    const wire = new Wire(socket);

    socket.write(get("http://example.invalid/x", "example.invalid", ["Connection: close"]));
    const response = await wire.response();

    expect(response.status).toBe("HTTP/1.1 503 Request for unmocked endpoint");
    expect(response.body).toContain("No rules were found matching this request.");
    expect(response.body).toContain("pass the request through to the target host, always (seen 0)");
    expect(log).toEqual({ matched: [], handled: [] });
    expect(state.missing).toEqual([]);
  });

  test("B2: a catch-all rule answers an unadmitted plain request with missingAdmissionResponse, even on a bound port", async () => {
    const catchAll = ruleLog();
    const state = await harness(async (adapter) => {
      await adapter.forAnyRequest()
        .always()
        .thenPassThrough({ beforeRequest: (admission, request) => {
          catchAll.handled.push([admission, request]);
          return reply(299, "ok");
        } });
    });
    const socket = await openClient(state.adapter);
    // A guard-minted binding without a TLS observation does not admit a
    // plain-HTTP request on that port.
    state.admissions.bind(socket.localPort ?? 0, state.admissions.mint("example.invalid", "g1"));
    const wire = new Wire(socket);

    socket.write(get("http://example.invalid/x", "example.invalid", ["Connection: close"]));
    const response = await wire.response();

    expect(response.status).toBe("HTTP/1.1 403 Forbidden");
    expect(response.body).toBe(MISSING_BODY);
    expect(state.missing.map((request) => request.url)).toEqual(["http://example.invalid/x"]);
    expect(catchAll.handled).toEqual([]);
  });

  test("B3: TLS whose SNI disagrees with the CONNECT host is cut before any request", async () => {
    const log = ruleLog();
    const catchAll = ruleLog();
    const state = await harness(async (adapter) => await policyRules(adapter, log, catchAll));
    const tunnel = await connectTunnel(state, "api.example.test");
    expect(tunnel.connectHead).toBe("HTTP/1.1 200 OK");

    expect(await tlsOutcome(tunnel.socket, "evil.example.test")).toBe(TLS_CUT);

    expect(state.sni).toEqual([{ kind: "host-mismatch", record: tunnel.record, observedHost: "evil.example.test" }]);
    expect(log).toEqual({ matched: [], handled: [] });
    expect(catchAll.handled).toEqual([]);
    expect(state.missing).toEqual([]);
  });

  for (const variant of ["never bound", "released"] as const) {
    test(`B4: TLS on a CONNECT whose port was ${variant} is cut before any request`, async () => {
      const log = ruleLog();
      const catchAll = ruleLog();
      const state = await harness(async (adapter) => await policyRules(adapter, log, catchAll));
      const tunnel = await connectTunnel(state, "api.example.test", { bind: variant !== "never bound" });
      if (variant === "released" && tunnel.record) {
        state.admissions.release(tunnel.socket.localPort ?? 0, tunnel.record.connectionSerial);
      }

      // The adapter does not gate CONNECT itself (the guard in front of it
      // does); its refusal lands on the TLS ClientHello.
      expect(tunnel.connectHead).toBe("HTTP/1.1 200 OK");
      expect(await tlsOutcome(tunnel.socket, "api.example.test")).toBe(TLS_CUT);

      expect(state.sni).toEqual([{ kind: "missing" }]);
      expect(log).toEqual({ matched: [], handled: [] });
      expect(catchAll.handled).toEqual([]);
      expect(state.missing).toEqual([]);
    });
  }

  for (const revocation of ["revokeSession", "release"] as const) {
    test(`B5: ${revocation} mid-connection refuses the next request on the same TLS connection`, async () => {
      const log = ruleLog();
      const catchAll = ruleLog();
      const state = await harness(async (adapter) => await policyRules(adapter, log, catchAll));
      const sessionBinding = { sessionKey: "session-b5" } as NonNullable<AdmissionRecord["sessionBinding"]>;
      const { record, secure, socket, wire } = await admittedTls(state, "api.example.test", { identity: { sessionBinding } });

      secure.write(get("/one", "api.example.test"));
      const first = await wire.response();
      expect(first.status).toBe("HTTP/1.1 299 unknown");
      expect(log.handled.map(([admission]) => admission.connectionSerial)).toEqual([record?.connectionSerial]);

      if (revocation === "revokeSession") {
        expect(state.admissions.revokeSession("session-b5")).toBe(1);
      } else {
        state.admissions.release(socket.localPort ?? 0, record?.connectionSerial ?? 0);
      }
      secure.write(get("/two", "api.example.test"));
      const second = await wire.response();

      expect(second.status).toBe("HTTP/1.1 403 Forbidden");
      expect(second.body).toBe(MISSING_BODY);
      expect(state.missing.map((request) => request.url)).toEqual(["https://api.example.test/two"]);
      expect(log.matched).toHaveLength(1);
      expect(log.handled).toHaveLength(1);
      expect(catchAll.handled).toEqual([]);
    });
  }

  test("B6: revalidateAdmission accepts only the current binding of the request's own connection", async () => {
    const seen: Array<{ admission: AdmissionRecord; request: ProxyRequest; revalidated: AdmissionRecord | undefined }> = [];
    const revalidatedOnMissing: Array<AdmissionRecord | undefined> = [];
    let adapterRef: MockttpAdapter | undefined;
    const state = await harness(async (adapter) => {
      adapterRef = adapter;
      await adapter.forAnyRequest()
        .always()
        .thenPassThrough({
          beforeRequest: (admission, request) => {
            seen.push({ admission, request, revalidated: adapter.revalidateAdmission(admission, request) });
            return reply(299, "ok");
          },
        });
    }, (request) => {
      const first = seen[0];
      if (first && adapterRef) revalidatedOnMissing.push(adapterRef.revalidateAdmission(first.admission, request));
      return missingAdmissionResponse(request);
    });
    const a = await admittedTls(state, "a.example.test");
    const b = await admittedTls(state, "b.example.test");

    a.secure.write(get("/one", "a.example.test"));
    expect((await a.wire.response()).status).toBe("HTTP/1.1 299 unknown");
    b.secure.write(get("/one", "b.example.test"));
    expect((await b.wire.response()).status).toBe("HTTP/1.1 299 unknown");

    const [onA, onB] = seen;
    if (!onA || !onB) throw new Error("both admitted requests must reach beforeRequest");
    expect(onA.revalidated?.connectionSerial).toBe(a.record?.connectionSerial);
    expect(onB.revalidated?.connectionSerial).toBe(b.record?.connectionSerial);
    // A record never revalidates against another connection's request.
    expect(state.adapter.revalidateAdmission(onA.admission, onB.request)).toBeUndefined();
    // A request without the adapter's trusted serial never revalidates.
    expect(state.adapter.revalidateAdmission(onA.admission, { remotePort: 1 } as never)).toBeUndefined();

    // Replace A's binding on the same port with a newly minted record.
    state.admissions.bind(a.socket.localPort ?? 0, state.admissions.mint("a.example.test", "g2"));
    expect(state.adapter.revalidateAdmission(onA.admission, onA.request)).toBeUndefined();
    a.secure.write(get("/two", "a.example.test"));
    const second = await a.wire.response();

    expect(second.status).toBe("HTTP/1.1 403 Forbidden");
    expect(revalidatedOnMissing).toEqual([undefined]);
    expect(seen).toHaveLength(2);
  });

  test("B7: agent-authored Proxy-Authorization metadata is refused and never becomes a tag", async () => {
    const tags: string[][] = [];
    let bothCompleted!: () => void;
    const completed = new Promise<void>((resolve) => {
      bothCompleted = resolve;
    });
    const log = ruleLog();
    const catchAll = ruleLog();
    const state = await harness(async (adapter) => {
      await policyRules(adapter, log, catchAll);
      await adapter.on<{ tags: string[] }>("request", (request) => {
        tags.push(request.tags);
        if (tags.length === 2) bothCompleted();
      });
    });
    const metadata = Buffer.from(JSON.stringify({ tags: ["agent-authored"] })).toString("base64url");

    const tagged = await admittedTls(state, "api.example.test", { proxyAuthorization: `Basic metadata:${metadata}` });
    expect(state.proxyAuthRefusals).toBe(1);
    tagged.secure.write(get("/x", "api.example.test"));
    expect((await tagged.wire.response()).status).toBe("HTTP/1.1 299 unknown");

    const plain = await admittedTls(state, "api.example.test");
    plain.secure.write(get("/y", "api.example.test"));
    expect((await plain.wire.response()).status).toBe("HTTP/1.1 299 unknown");

    await bounded(completed, "completed request events");
    expect(state.proxyAuthRefusals).toBe(1);
    expect(log.handled).toHaveLength(2);
    expect(tags.flat().filter((tag) => tag.includes("agent-authored"))).toEqual([]);
  });

  for (const withPolicyMatcher of [false, true]) {
    test(`B8: an unadmitted WebSocket upgrade gets the full 403 explanation${withPolicyMatcher ? " before any policy matcher" : ""}`, async () => {
      const matched: ProxyRequest[] = [];
      const state = await harness(async (adapter) => {
        if (!withPolicyMatcher) return;
        await adapter.forAnyWebSocket()
          .matching((_admission, request) => {
            matched.push(request);
            return true;
          })
          .always()
          .thenPassThrough();
      });
      const socket = await openClient(state.adapter);
      const wire = new Wire(socket);

      socket.write(get("http://ws.invalid/sock", "ws.invalid", WS_UPGRADE_HEADERS));

      expect(await wire.everythingUntilClose()).toBe([
        "HTTP/1.1 403 Forbidden",
        "content-type: text/plain; charset=utf-8",
        "x-runfree-blocked: missing-admission-record",
        "content-length: 93",
        "connection: close",
        "",
        BLOCKED_WS_BODY,
      ].join("\r\n"));
      expect(BLOCKED_WS_BODY).toHaveLength(93);
      expect(state.missingWebSockets.map((request) => request.url)).toEqual(["ws://ws.invalid/sock"]);
      expect(matched).toEqual([]);
    });
  }

  test("B9: an admitted WebSocket refused by a rule gets one framing and the full body over TLS", async () => {
    const matched: Array<[AdmissionRecord, ProxyRequest]> = [];
    const state = await harness(async (adapter) => {
      await adapter.forAnyWebSocket()
        .matching((admission, request) => {
          matched.push([admission, request]);
          return true;
        })
        .always()
        .thenRejectConnection(451, "Blocked", { "x-a": "1", "Content-Length": "999", "Connection": "keep-alive" }, "why\n");
    });
    const { record, secure, wire } = await admittedTls(state, "ws.example.test");

    secure.write(get("/sock", "ws.example.test", WS_UPGRADE_HEADERS));

    expect(await wire.everythingUntilClose()).toBe(
      "HTTP/1.1 451 Blocked\r\nx-a: 1\r\ncontent-length: 4\r\nconnection: close\r\n\r\nwhy\n",
    );
    expect(matched.map(([admission]) => admission.connectionSerial)).toEqual([record?.connectionSerial]);
    expect(state.missingWebSockets).toEqual([]);
  });

  test("B10: two adapters route observations to their own callbacks and outlive each other", async () => {
    const logA = ruleLog();
    const logB = ruleLog();
    const a = await harness(async (adapter) => await policyRules(adapter, logA, ruleLog()));
    const b = await harness(async (adapter) => await policyRules(adapter, logB, ruleLog()));

    const onA = await admittedTls(a, "a.example.test");
    onA.secure.write(get("/a", "a.example.test"));
    expect((await onA.wire.response()).status).toBe("HTTP/1.1 299 unknown");
    expect(a.sni.map((observation) => observation.kind)).toEqual(["admitted"]);
    expect(b.sni).toEqual([]);

    await a.stop();
    const onB = await admittedTls(b, "b.example.test");
    onB.secure.write(get("/b", "b.example.test"));
    expect((await onB.wire.response()).status).toBe("HTTP/1.1 299 unknown");
    expect(b.sni).toEqual([{ kind: "admitted", record: { ...onB.record, stage: "sni" } }]);
    expect(a.sni).toHaveLength(1);
    expect(logB.handled.map(([admission]) => admission.host)).toEqual(["b.example.test"]);
    expect(logA.handled.map(([admission]) => admission.host)).toEqual(["a.example.test"]);
  });
});
