import { createRequire } from "node:module";
import net from "node:net";
import tls from "node:tls";
import * as mockttp from "mockttp";
import { getCA } from "mockttp/dist/util/certificates";

import { AdmissionRegistry, type AdmissionRecord, type AdmissionObservation } from "./admission.js";
import type { ProxyRequest } from "./policy.js";

const require = createRequire(import.meta.url);
const tlsClientHello = require("read-tls-client-hello") as typeof import("read-tls-client-hello");
const trustedAdmissionSerial = Symbol("runfree.trusted-admission-serial");

type TrustedSocketMetadata = Record<PropertyKey, unknown> & {
  [trustedAdmissionSerial]?: number;
};

type SocketExtensionsModule = { SocketMetadata: symbol };
type SocketMetadataModule = {
  getSocketMetadataFromProxyAuth: (socket: unknown, proxyAuth: string | undefined) => unknown;
};
type RequestUtilsModule = {
  buildInitiatedRequest: (request: unknown) => object;
  waitForCompletedRequest: (request: unknown) => Promise<object>;
};
type RawRequest = ProxyRequest & {
  [trustedAdmissionSerial]?: number;
  socket?: Record<PropertyKey, unknown>;
};

type AdapterContext = {
  admissions: AdmissionRegistry;
  onProxyAuthRefused: () => void;
  onSniObservation: (observation: AdmissionObservation) => void;
};

const contextsByListeningPort = new Map<number, AdapterContext>();
let securityPatchesInstalled = false;
let socketMetadataKey: symbol;

export class MockttpAdapterContractError extends Error {}

function loadMockttpInternals(): {
  metadata: SocketMetadataModule;
  requestUtils: RequestUtilsModule;
  socketExtensions: SocketExtensionsModule;
} {
  try {
    return {
      metadata: require("mockttp/dist/util/socket-metadata") as SocketMetadataModule,
      requestUtils: require("mockttp/dist/util/request-utils") as RequestUtilsModule,
      socketExtensions: require("mockttp/dist/util/socket-extensions") as SocketExtensionsModule,
    };
  } catch (error) {
    throw new MockttpAdapterContractError(`cannot load pinned mockttp adapter internals: ${String(error)}`);
  }
}

function serialFromOngoingRequest(request: unknown): number | undefined {
  if (request === null || typeof request !== "object") return undefined;
  const socket = (request as RawRequest).socket;
  if (socket === undefined) return undefined;
  const metadata = socket[socketMetadataKey];
  if (metadata === null || typeof metadata !== "object") return undefined;
  const serial = (metadata as TrustedSocketMetadata)[trustedAdmissionSerial];
  return typeof serial === "number" ? serial : undefined;
}

function attachTrustedSerial(request: object, serial: number | undefined): object {
  if (serial === undefined) return request;
  Object.defineProperty(request, trustedAdmissionSerial, {
    configurable: false,
    enumerable: true,
    value: serial,
    writable: false,
  });
  return request;
}

function installSecurityPatches(): void {
  const { metadata, requestUtils, socketExtensions } = loadMockttpInternals();
  if (typeof metadata.getSocketMetadataFromProxyAuth !== "function") {
    throw new MockttpAdapterContractError("mockttp proxy-auth metadata parser has an unexpected shape");
  }
  if (typeof socketExtensions.SocketMetadata !== "symbol") {
    throw new MockttpAdapterContractError("mockttp SocketMetadata key has an unexpected shape");
  }
  if (typeof requestUtils.buildInitiatedRequest !== "function"
    || typeof requestUtils.waitForCompletedRequest !== "function") {
    throw new MockttpAdapterContractError("mockttp request mapping has an unexpected shape");
  }
  socketMetadataKey = socketExtensions.SocketMetadata;

  if (securityPatchesInstalled) return;
  securityPatchesInstalled = true;

  // The header channel is closed at its sole interpreter. Existing trusted
  // metadata is preserved, but no agent-authored value is parsed or merged.
  metadata.getSocketMetadataFromProxyAuth = (socket: unknown, proxyAuth: string | undefined): unknown => {
    if (proxyAuth && socket !== null && typeof socket === "object") {
      const localPort = (socket as { localPort?: number }).localPort;
      contextsByListeningPort.get(localPort ?? -1)?.onProxyAuthRefused();
    }
    return socket !== null && typeof socket === "object"
      ? (socket as Record<PropertyKey, unknown>)[socketMetadataKey]
      : undefined;
  };

  // mockttp deliberately removes the socket before exposing a request. Carry
  // the adapter-owned serial across that mapping on a private symbol; it never
  // enters tags, destination, headers, logs, or any agent-visible channel.
  const originalBuildInitiatedRequest = requestUtils.buildInitiatedRequest;
  requestUtils.buildInitiatedRequest = (request: unknown): object => {
    return attachTrustedSerial(originalBuildInitiatedRequest(request), serialFromOngoingRequest(request));
  };
  const originalWaitForCompletedRequest = requestUtils.waitForCompletedRequest;
  requestUtils.waitForCompletedRequest = async (request: unknown): Promise<object> => {
    return attachTrustedSerial(
      await originalWaitForCompletedRequest(request),
      serialFromOngoingRequest(request),
    );
  };

  const originalReadTlsClientHello = tlsClientHello.readTlsClientHello;
  if (typeof originalReadTlsClientHello !== "function") {
    throw new MockttpAdapterContractError("TLS ClientHello parser has an unexpected shape");
  }
  // mockttp reads this CommonJS export at call time. Wrapping that exact
  // parser observes each ClientHello once without adding a second parser.
  (tlsClientHello as { readTlsClientHello: typeof originalReadTlsClientHello }).readTlsClientHello = async (socket) => {
    const hello = await originalReadTlsClientHello(socket);
    const networkSocket = socket as net.Socket & Record<PropertyKey, unknown>;
    const context = contextsByListeningPort.get(networkSocket.localPort ?? -1);
    if (!context) return hello;
    const sni = tlsClientHello.getExtensionData(hello, "sni")?.serverName;
    const observation = context.admissions.observeTls(networkSocket.remotePort, sni);
    context.onSniObservation(observation);
    if (observation.kind !== "admitted") {
      socket.destroy();
      throw new MockttpAdapterContractError(
        observation.kind === "host-mismatch"
          ? `CONNECT host ${observation.record.host} disagrees with TLS SNI ${observation.observedHost}`
          : "TLS connection has no guard-minted admission record",
      );
    }
    const existing = networkSocket[socketMetadataKey];
    const trusted: TrustedSocketMetadata = existing !== null && typeof existing === "object"
      ? { ...(existing as Record<PropertyKey, unknown>) }
      : {};
    trusted[trustedAdmissionSerial] = observation.record.connectionSerial;
    networkSocket[socketMetadataKey] = trusted;
    return hello;
  };
}

export async function generateProxyCA(): Promise<{ cert: string; key: string }> {
  return await mockttp.generateCACertificate();
}

export async function generateProxyLeaf(
  ca: { cert: string; key: string },
  hostname: string,
): Promise<{ ca: string; cert: string; key: string }> {
  const issuer = await getCA(ca);
  return await issuer.generateCertificate(hostname);
}

export type MockttpAdapterSelfTestMutations = {
  destinationHost?: (value: string | undefined) => string | undefined;
  leafSubjectAltName?: (value: string | undefined) => string | undefined;
  remotePort?: (value: number | undefined) => number | undefined;
  sealTargetExists?: (value: boolean) => boolean;
  trustedSerial?: (value: number | undefined) => number | undefined;
};

export class MockttpAdapterSelfTestError extends Error {}

async function readUntil(socket: net.Socket | tls.TLSSocket, delimiter: string): Promise<Buffer> {
  const target = Buffer.from(delimiter);
  return await new Promise((resolve, reject) => {
    let buffered = Buffer.alloc(0);
    const cleanup = () => {
      socket.off("data", onData);
      socket.off("error", onError);
      socket.off("end", onEnd);
    };
    const onData = (chunk: Buffer) => {
      buffered = Buffer.concat([buffered, chunk]);
      if (!buffered.includes(target)) return;
      cleanup();
      resolve(buffered);
    };
    const onError = (error: Error) => {
      cleanup();
      reject(error);
    };
    const onEnd = () => {
      cleanup();
      reject(new Error(`connection ended before ${JSON.stringify(delimiter)}`));
    };
    socket.on("data", onData);
    socket.once("error", onError);
    socket.once("end", onEnd);
  });
}

/**
 * Pins the dependency behaviours Runfree's boundary relies on. This runs on a
 * throwaway loopback server before the public guard is made ready; any failure
 * aborts startup with no agent-reachable listener and no credential sync.
 */
export async function runMockttpAdapterSelfTest(options: {
  cert: string;
  key: string;
  mutations?: MockttpAdapterSelfTestMutations;
}): Promise<void> {
  installSecurityPatches();
  const hostname = "runfree-adapter-self-test.invalid";
  const registry = new AdmissionRegistry();
  const raw = mockttp.getLocal({ https: { cert: options.cert, key: options.key } });
  let socket: net.Socket | undefined;
  let tlsSocket: tls.TLSSocket | undefined;
  let listeningPort: number | undefined;
  try {
    await raw.forAnyRequest().thenReply(204, "");
    const observedRequest = new Promise<mockttp.CompletedRequest>((resolve) => {
      void raw.on("request", resolve);
    });
    await raw.start();
    listeningPort = raw.port;
    contextsByListeningPort.set(listeningPort, {
      admissions: registry,
      onProxyAuthRefused: () => {},
      onSniObservation: () => {},
    });

    socket = net.connect({ host: "127.0.0.1", port: listeningPort });
    await new Promise<void>((resolve, reject) => {
      socket?.once("connect", resolve);
      socket?.once("error", reject);
    });
    const clientPort = socket.localPort;
    if (clientPort === undefined) throw new Error("self-test client has no local port");
    const admission = registry.mint(hostname, "sha256:self-test");
    registry.bind(clientPort, admission);
    const metadataCredential = Buffer.from(JSON.stringify({ tags: ["agent-authored-self-test"] }))
      .toString("base64url");
    socket.write([
      `CONNECT ${hostname}:443 HTTP/1.1`,
      `Host: ${hostname}:443`,
      `Proxy-Authorization: Basic metadata:${metadataCredential}`,
      "",
      "",
    ].join("\r\n"));
    const connectHead = (await readUntil(socket, "\r\n\r\n")).toString("latin1");
    if (!/^HTTP\/1\.1 200\b/.test(connectHead)) {
      throw new Error(`self-test CONNECT was not admitted: ${connectHead.split("\r\n", 1)[0]}`);
    }

    tlsSocket = tls.connect({ socket, servername: hostname, rejectUnauthorized: false });
    await new Promise<void>((resolve, reject) => {
      tlsSocket?.once("secureConnect", resolve);
      tlsSocket?.once("error", reject);
    });
    const peer = tlsSocket.getPeerCertificate();
    tlsSocket.write([
      "GET /adapter-self-test HTTP/1.1",
      `Host: ${hostname}`,
      "Connection: close",
      "",
      "",
    ].join("\r\n"));
    await readUntil(tlsSocket, "\r\n\r\n");
    const request = await observedRequest;

    const remotePort = options.mutations?.remotePort?.(request.remotePort) ?? request.remotePort;
    if (remotePort !== clientPort) {
      throw new Error(`remotePort propagation failed: expected ${clientPort}, got ${String(remotePort)}`);
    }
    const destinationHost = options.mutations?.destinationHost?.(request.destination?.hostname)
      ?? request.destination?.hostname;
    if (destinationHost !== hostname) {
      throw new Error(`tunnel destination propagation failed: expected ${hostname}, got ${String(destinationHost)}`);
    }
    const sealTargetExists = options.mutations?.sealTargetExists?.(true) ?? true;
    if (!sealTargetExists || request.tags.includes("socket-metadata:agent-authored-self-test")) {
      throw new Error("proxy-auth socket metadata seal failed");
    }
    const subjectAltName = options.mutations?.leafSubjectAltName?.(peer.subjectaltname)
      ?? peer.subjectaltname;
    if (subjectAltName !== `DNS:${hostname}`) {
      throw new Error(`leaf SAN contract failed: expected one DNS name, got ${String(subjectAltName)}`);
    }
    const observedSerial = options.mutations?.trustedSerial?.(requestSerial(request)) ?? requestSerial(request);
    const resolved = registry.resolveRequest(remotePort, observedSerial);
    if (resolved?.connectionSerial !== admission.connectionSerial) {
      throw new Error("trusted socket admission serial did not survive request mapping");
    }
  } catch (error) {
    throw new MockttpAdapterSelfTestError(`mockttp adapter self-test failed: ${String(error)}`);
  } finally {
    tlsSocket?.destroy();
    socket?.destroy();
    if (listeningPort !== undefined) contextsByListeningPort.delete(listeningPort);
    await raw.stop().catch(() => {});
  }
}

type MissingAdmissionResponse = {
  response: { statusCode: number; headers?: Record<string, string>; body?: string };
};

type RequestRuleOptions = {
  beforeRequest?: (admission: AdmissionRecord, request: ProxyRequest) => unknown;
  beforeResponse?: (response: unknown, request: ProxyRequest) => unknown;
};

export type AdmittedRequestRuleBuilder = {
  matching(matcher: (admission: AdmissionRecord, request: ProxyRequest) => boolean | Promise<boolean>): AdmittedRequestRuleBuilder;
  always(): AdmittedRequestRuleBuilder;
  thenPassThrough(options: RequestRuleOptions): Promise<unknown>;
};

export type AdmittedWebSocketRuleBuilder = {
  matching(matcher: (admission: AdmissionRecord, request: ProxyRequest) => boolean | Promise<boolean>): AdmittedWebSocketRuleBuilder;
  always(): AdmittedWebSocketRuleBuilder;
  thenPassThrough(): Promise<unknown>;
  thenRejectConnection(
    statusCode: number,
    statusMessage: string,
    headers?: Record<string, string>,
    body?: string,
  ): Promise<unknown>;
};

export type MockttpAdapter = {
  readonly port: number;
  start(): Promise<void>;
  stop(): Promise<void>;
  on<T>(event: string, listener: (event: T) => void | Promise<void>): Promise<void>;
  forAnyRequest(): AdmittedRequestRuleBuilder;
  forAnyWebSocket(): AdmittedWebSocketRuleBuilder;
  revalidateAdmission(admission: AdmissionRecord, request: ProxyRequest): AdmissionRecord | undefined;
};

function requestSerial(request: ProxyRequest): number | undefined {
  const serial = (request as RawRequest)[trustedAdmissionSerial];
  return typeof serial === "number" ? serial : undefined;
}

export async function createMockttpAdapter(options: {
  admissions: AdmissionRegistry;
  cert: string;
  key: string;
  missingAdmissionResponse: (request: ProxyRequest) => MissingAdmissionResponse;
  onMissingWebSocket: (request: ProxyRequest) => void;
  onProxyAuthRefused: () => void;
  onSniObservation: (observation: AdmissionObservation) => void;
}): Promise<MockttpAdapter> {
  installSecurityPatches();
  const raw = mockttp.getLocal({ https: { cert: options.cert, key: options.key } });
  let registeredPort: number | undefined;

  const resolveAdmission = (request: ProxyRequest): AdmissionRecord | undefined => {
    return options.admissions.resolveRequest(request.remotePort, requestSerial(request));
  };

  const wrapRequestBuilder = (builder: mockttp.RequestRuleBuilder): AdmittedRequestRuleBuilder => {
    const wrapped: AdmittedRequestRuleBuilder = {
      matching(matcher) {
        builder.matching((request) => {
          const admission = resolveAdmission(request);
          return admission !== undefined && matcher(admission, request);
        });
        return wrapped;
      },
      always() {
        builder.always();
        return wrapped;
      },
      async thenPassThrough(ruleOptions) {
        return await builder.thenPassThrough({
          beforeRequest: async (request: ProxyRequest) => {
            const admission = resolveAdmission(request);
            if (!admission) return options.missingAdmissionResponse(request);
            return await ruleOptions.beforeRequest?.(admission, request);
          },
          ...(ruleOptions.beforeResponse ? { beforeResponse: ruleOptions.beforeResponse } : {}),
        } as never);
      },
    };
    return wrapped;
  };

  const wrapWebSocketBuilder = (builder: mockttp.WebSocketRuleBuilder): AdmittedWebSocketRuleBuilder => {
    const wrapped: AdmittedWebSocketRuleBuilder = {
      matching(matcher) {
        builder.matching((request) => {
          const admission = resolveAdmission(request);
          return admission !== undefined && matcher(admission, request);
        });
        return wrapped;
      },
      always() {
        builder.always();
        return wrapped;
      },
      async thenPassThrough() {
        return await builder.thenPassThrough();
      },
      async thenRejectConnection(statusCode, statusMessage, headers, body) {
        return await builder.thenRejectConnection(statusCode, statusMessage, headers, body);
      },
    };
    return wrapped;
  };

  // This first always-rule makes missing admission a property of the adapter
  // boundary. No caller can accidentally register a WebSocket policy matcher
  // that sees an unadmitted request.
  await raw.forAnyWebSocket()
    .matching((request) => {
      if (resolveAdmission(request) !== undefined) return false;
      options.onMissingWebSocket(request);
      return true;
    })
    .always()
    .thenRejectConnection(
      403,
      "Forbidden",
      {
        "content-type": "text/plain; charset=utf-8",
        "x-runfree-blocked": "missing-admission-record",
      },
      "blocked by agent proxy policy\nconnection did not pass the Runfree CONNECT admission boundary\n",
    );

  return {
    get port() {
      return raw.port;
    },
    async start() {
      await raw.start();
      registeredPort = raw.port;
      contextsByListeningPort.set(registeredPort, {
        admissions: options.admissions,
        onProxyAuthRefused: options.onProxyAuthRefused,
        onSniObservation: options.onSniObservation,
      });
    },
    async stop() {
      if (registeredPort !== undefined) contextsByListeningPort.delete(registeredPort);
      await raw.stop();
    },
    async on(event, listener) {
      const subscribe = raw.on as unknown as (
        eventName: string,
        callback: (value: unknown) => void | Promise<void>,
      ) => Promise<void>;
      await subscribe.call(raw, event, listener as (value: unknown) => void | Promise<void>);
    },
    forAnyRequest() {
      return wrapRequestBuilder(raw.forAnyRequest());
    },
    forAnyWebSocket() {
      return wrapWebSocketBuilder(raw.forAnyWebSocket());
    },
    revalidateAdmission(admission, request) {
      const current = resolveAdmission(request);
      return current?.connectionSerial === admission.connectionSerial ? current : undefined;
    },
  };
}
