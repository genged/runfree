// host-service-tunnel.ts — opaque splices from an admitted session to an
// approved host service behind the pinned Docker Desktop gateway.
//
// See local/specs/2026-10-03-host-services-design.md ("Data path",
// "Revocation", "Limits"). The guard in server.ts has already classified the
// CONNECT: the authority is exactly `<name>.runfree.internal:<port>` and the
// effective policy approves that pair. This module owns everything after that
// decision:
//
// - The gateway address comes only from the root-written gateway status file
//   (`readGateway`), read on every admit, and is used only when the file names
//   the policy generation the guard classified against. The request proxy
//   never resolves a name for it (uid 1001 has no DNS).
// - Every refusal (gateway unavailable, cap reached, dial failed or timed out)
//   happens before the client sees a 200. The 200 is written only after the
//   upstream TCP connect succeeds.
// - The splice is opaque: no TLS interception, no header handling, no
//   credential injection, and no payload inspection.
// - Each splice is tied to its client socket, so session revoke and the
//   IP-reuse fence (which destroy client sockets) cut it; `cutRemoved` cuts
//   the splices of entries that left the effective policy, and
//   `cutForGateway` cuts the splices whose pinned gateway was withdrawn or
//   changed (Revocation, request-proxy consumer).

import net from "node:net";
import type { HostServicesJson } from "@runfree/runtime-contracts/host-services";
import type { HostServiceGatewayStatus } from "@runfree/runtime-contracts/proxy-status";
import type { DenialReason } from "./denial.js";

export type HostServiceAdmitInput = {
  clientSocket: net.Socket;
  sessionKey: string;
  name: string;
  port: number;
  policyGeneration: string;
  remainder: Buffer;
  reject: (reason: string, denial: DenialReason) => void;
};

export type HostServiceTunnels = {
  admit(input: HostServiceAdmitInput): void;
  cutRemoved(next: Readonly<HostServicesJson>): number;
  cutAll(): number;
  cutForGateway(gateway: HostServiceGatewayStatus | undefined): HostServiceGatewayCut;
  spliceCounts(): Record<string, number>;
};

// `reason` is present iff `count > 0`.
export type HostServiceGatewayCut = { count: number; reason?: string };

export type HostServiceTunnelOptions = {
  readGateway: () => HostServiceGatewayStatus | undefined;
  maxPerSession: number;
  maxGlobal: number;
  maxPendingDials: number;
  dialTimeoutMs: number;
  connect?: typeof net.connect;
};

const KEEPALIVE_INITIAL_DELAY_MS = 30_000;

type Splice = {
  name: string;
  port: number;
  sessionKey: string;
  // The IP literal this splice was dialled to, from the gateway status that
  // admitted it.
  gatewayIp: string;
  client: net.Socket;
  upstream: net.Socket;
  pending: boolean;
};

export function createHostServiceTunnels(options: HostServiceTunnelOptions): HostServiceTunnels {
  const connect = options.connect ?? net.connect;
  const splices = new Set<Splice>();
  const perSession = new Map<string, number>();
  let pendingDials = 0;

  function cut(splice: Splice): void {
    splice.client.destroy();
    splice.upstream.destroy();
  }

  function untrack(splice: Splice): void {
    if (!splices.delete(splice)) return;
    if (splice.pending) pendingDials -= 1;
    const remaining = (perSession.get(splice.sessionKey) ?? 1) - 1;
    if (remaining > 0) perSession.set(splice.sessionKey, remaining);
    else perSession.delete(splice.sessionKey);
  }

  function admit(input: HostServiceAdmitInput): void {
    const { clientSocket } = input;
    const gateway = options.readGateway();
    if (gateway === undefined || gateway.policyGeneration !== input.policyGeneration || gateway.gatewayIp === undefined) {
      const detail = gateway === undefined
        ? "the host-service gateway status is missing or invalid"
        : gateway.policyGeneration !== input.policyGeneration
          ? "the host-service gateway status names another effective policy generation"
          : `the host-service gateway is unavailable: ${gateway.unavailableReason ?? "unknown reason"}`;
      input.reject(`host-service-unavailable: ${detail}`, "host-service-unavailable");
      return;
    }
    if ((perSession.get(input.sessionKey) ?? 0) >= options.maxPerSession) {
      input.reject("host-service-capacity: the per-session host-service splice limit is reached", "host-service-capacity");
      return;
    }
    if (splices.size >= options.maxGlobal) {
      input.reject("host-service-capacity: the global host-service splice limit is reached", "host-service-capacity");
      return;
    }
    if (pendingDials >= options.maxPendingDials) {
      input.reject("host-service-capacity: too many host-service dials are pending", "host-service-capacity");
      return;
    }

    // The guard removed its data listener; hold later client bytes until the
    // splice pipes them, so nothing sent before the 200 is dropped.
    clientSocket.pause();
    const upstream = connect({ host: gateway.gatewayIp, port: input.port, family: 4 });
    const splice: Splice = {
      name: input.name,
      port: input.port,
      sessionKey: input.sessionKey,
      gatewayIp: gateway.gatewayIp,
      client: clientSocket,
      upstream,
      pending: true,
    };
    splices.add(splice);
    pendingDials += 1;
    perSession.set(input.sessionKey, (perSession.get(input.sessionKey) ?? 0) + 1);

    upstream.setTimeout(options.dialTimeoutMs);
    upstream.setKeepAlive(true, KEEPALIVE_INITIAL_DELAY_MS);
    clientSocket.setKeepAlive(true, KEEPALIVE_INITIAL_DELAY_MS);

    // Refused before the 200: the reject callback answers the client with a
    // raw 403. Set once, so a timeout followed by an error answers only once.
    let refused = false;
    const refuseBeforeConnect = (detail: string) => {
      if (!splice.pending || refused) return;
      refused = true;
      untrack(splice);
      upstream.destroy();
      if (clientSocket.destroyed) return;
      input.reject(`host-service-unavailable: ${detail}`, "host-service-unavailable");
    };

    upstream.once("timeout", () => {
      if (splice.pending) refuseBeforeConnect("the host service did not accept the connection in time");
    });
    upstream.on("error", (error: NodeJS.ErrnoException) => {
      if (splice.pending) {
        refuseBeforeConnect(`the host service refused the connection (${error.code ?? "error"})`);
        return;
      }
      cut(splice);
    });
    clientSocket.on("error", () => cut(splice));
    clientSocket.once("close", () => {
      untrack(splice);
      upstream.destroy();
    });
    upstream.once("close", () => {
      untrack(splice);
      // After a refusal the reject callback owns the client's 403 and close.
      if (!refused) clientSocket.destroy();
    });
    upstream.once("connect", () => {
      if (!splices.has(splice) || clientSocket.destroyed) {
        upstream.destroy();
        return;
      }
      splice.pending = false;
      pendingDials -= 1;
      // No idle timeout once connected: gRPC streams are long-lived.
      upstream.setTimeout(0);
      clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (input.remainder.length > 0) upstream.write(input.remainder);
      clientSocket.pipe(upstream);
      upstream.pipe(clientSocket);
      clientSocket.resume();
    });
  }

  return {
    admit,
    cutRemoved(next) {
      let count = 0;
      for (const splice of Array.from(splices)) {
        if (next[splice.name]?.port === splice.port) continue;
        count += 1;
        untrack(splice);
        cut(splice);
      }
      return count;
    },
    cutAll() {
      const all = Array.from(splices);
      for (const splice of all) {
        untrack(splice);
        cut(splice);
      }
      return all.length;
    },
    // The policyGeneration the status names is deliberately ignored here. The
    // supervisor republishes the file for every effective policy generation,
    // so a short skew against the proxy's policy is normal; a reload's
    // removals are cut by `cutRemoved`. Only a withdrawn gateway or a changed
    // address cuts: either one means the dialled address is no longer the
    // pinned, validated gateway.
    cutForGateway(gateway) {
      if (splices.size === 0) return { count: 0 };
      const reason = gateway === undefined
        ? "the host-service gateway status is missing or invalid"
        : gateway.gatewayIp === undefined
          ? `the host-service gateway is unavailable: ${gateway.unavailableReason ?? "unknown reason"}`
          : "the pinned host-service gateway address changed";
      let count = 0;
      for (const splice of Array.from(splices)) {
        if (gateway?.gatewayIp !== undefined && splice.gatewayIp === gateway.gatewayIp) continue;
        count += 1;
        untrack(splice);
        cut(splice);
      }
      return count === 0 ? { count } : { count, reason };
    },
    spliceCounts() {
      const counts: Record<string, number> = {};
      for (const splice of splices) counts[splice.name] = (counts[splice.name] ?? 0) + 1;
      return Object.fromEntries(Object.entries(counts).sort(([left], [right]) => left.localeCompare(right)));
    },
  };
}
