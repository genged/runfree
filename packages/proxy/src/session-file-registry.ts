import { performance } from "node:perf_hooks";

import { type SessionFileV1, type SessionIpAssignment } from "@runfree/runtime-contracts/session-file";
import {
  SESSION_ADMISSION_LEASE_MAX_DURATION_MS,
  isExactSessionSourceIpv4,
  pendingApprovalSession,
  proxySessionStableIdentity,
  type ApprovalRequestSession,
} from "@runfree/runtime-contracts/session-registry";

import { scanSessionFiles, type SessionFileScan } from "./session-files.js";
import { servedSessionFiles, type SessionFileObservation } from "./session-file-validity.js";

// The request path's view of the per-session files. `refresh()` runs on the
// proxy's 100 ms loop and rebuilds the served map; `lookup` answers from that
// map without touching the filesystem (review F11), so admission is at most
// one loop stale instead of one directory read per connection.

export type SessionRegistryRejectionReason =
  | "missing"
  | "invalid"
  | "expired"
  | "registry-unavailable";

/**
 * What the request path learns about one peer address.
 *
 * A served file is the whole of a session's authority, so there is no
 * intermediate state: an address is either served by exactly one currently
 * valid file, or it is refused.
 */
export type SessionRegistryLookup =
  | { kind: "active"; file: SessionFileV1; session: ApprovalRequestSession }
  | { kind: "rejected"; reason: SessionRegistryRejectionReason };

export type SessionFileRegistryOptions = {
  root: string;
  projectId: string;
  ownerUid?: number;
  leaseMaxMs?: number;
  now?: () => number;
  monotonicNowMs?: () => number;
  onSessionInvalidated?: (sessionKey: string, reason: "expired" | "removed" | "replaced") => void;
};

export type SessionFileRegistryRefresh = { kind: "unreadable" } | { kind: "ok"; served: number };

export class SessionFileRegistry {
  readonly #root: string;
  readonly #projectId: string;
  readonly #ownerUid: number;
  readonly #leaseMaxMs: number;
  readonly #now: () => number;
  readonly #monotonicNowMs: () => number;
  readonly #onSessionInvalidated: SessionFileRegistryOptions["onSessionInvalidated"];
  // Invariant 5: this observation map is this consumer's own state. The
  // firewall keeps its own and reaches the same decision independently.
  readonly #observations = new Map<string, SessionFileObservation>();
  readonly #servedIdentities = new Map<string, string>();
  #servedFiles = new Map<string, SessionFileV1>();
  #expiredAddresses = new Set<string>();
  // Fail closed until a refresh proves the state readable: nothing is served
  // before the first loop tick, and an unreadable scan returns to this state.
  #readable = false;

  constructor(options: SessionFileRegistryOptions) {
    this.#root = options.root;
    this.#projectId = options.projectId;
    this.#ownerUid = options.ownerUid ?? 0;
    this.#leaseMaxMs = options.leaseMaxMs ?? SESSION_ADMISSION_LEASE_MAX_DURATION_MS;
    this.#now = options.now ?? (() => Date.now());
    this.#monotonicNowMs = options.monotonicNowMs ?? (() => performance.now());
    this.#onSessionInvalidated = options.onSessionInvalidated;
  }

  refresh(
    blocked: ReadonlySet<string> | "all" = new Set(),
    assignments?: ReadonlyMap<string, SessionIpAssignment>,
  ): SessionFileRegistryRefresh {
    // A throwing scan is fail-closed identically to `{ kind: "unreadable" }`:
    // `scanSessionFiles` is written to report failures as data, but the
    // final `readFileSync` inside it is not wrapped, so a transient I/O
    // error can still throw. This caller must not let that propagate.
    let scan: SessionFileScan;
    try {
      scan = scanSessionFiles({ root: this.#root, ownerUid: this.#ownerUid, projectId: this.#projectId, assignments });
    } catch {
      scan = { kind: "unreadable" };
    }
    if (scan.kind !== "ok") {
      // Invariants 1 and 8: unreadable state serves nothing and ends every
      // live context. Observations are kept — an unreadable scan says nothing
      // about which sessions exist, and clearing them would hand a replayed
      // file a fresh monotonic bound once the state is readable again.
      this.#readable = false;
      this.#servedFiles = new Map();
      this.#expiredAddresses = new Set();
      for (const sessionKey of Array.from(this.#servedIdentities.keys())) {
        this.#onSessionInvalidated?.(sessionKey, "removed");
      }
      this.#servedIdentities.clear();
      return { kind: "unreadable" };
    }

    const { served, expired } = servedSessionFiles(
      scan,
      this.#observations,
      this.#now(),
      this.#monotonicNowMs(),
      this.#leaseMaxMs,
    );
    const expiredKeys = new Set(expired);
    for (const [key, file] of served) {
      const assignment = assignments?.get(file.sourceIp);
      if (blocked === "all" || blocked.has(file.sourceIp)
        || (assignment !== undefined && (assignment.state !== "ready" || assignment.sessionKey !== key))) {
        served.delete(key);
      }
    }
    for (const sessionKey of expiredKeys) {
      if (this.#servedIdentities.has(sessionKey)) this.#onSessionInvalidated?.(sessionKey, "expired");
    }
    for (const sessionKey of this.#servedIdentities.keys()) {
      if (!served.has(sessionKey) && !expiredKeys.has(sessionKey)) this.#onSessionInvalidated?.(sessionKey, "removed");
    }

    const files = new Map<string, SessionFileV1>();
    const identities = new Map<string, string>();
    for (const [sessionKey, file] of served) {
      const identity = proxySessionStableIdentity(file);
      const previous = this.#servedIdentities.get(sessionKey);
      // A heartbeat rewrite is a new nonce for the same container: rotating
      // authority, not a new session. Only a changed stable identity drops
      // sockets and grants, and an expiry already did so above.
      if (previous !== undefined && previous !== identity && !expiredKeys.has(sessionKey)) {
        this.#onSessionInvalidated?.(sessionKey, "replaced");
      }
      identities.set(sessionKey, identity);
      files.set(file.sourceIp, file);
    }
    this.#servedIdentities.clear();
    for (const [sessionKey, identity] of identities) this.#servedIdentities.set(sessionKey, identity);
    this.#servedFiles = files;
    this.#expiredAddresses = new Set(
      Array.from(scan.files.values())
        .filter((file) => !served.has(file.sessionKey))
        .map((file) => file.sourceIp),
    );
    this.#readable = true;
    return { kind: "ok", served: files.size };
  }

  servedAddresses(): ReadonlySet<string> {
    return new Set(this.#servedFiles.keys());
  }

  lookup(sourceIp: string | undefined): SessionRegistryLookup {
    if (sourceIp === undefined || !isExactSessionSourceIpv4(sourceIp)) return { kind: "rejected", reason: "invalid" };
    if (!this.#readable) return { kind: "rejected", reason: "registry-unavailable" };
    const file = this.#servedFiles.get(sourceIp);
    if (!file) {
      // Two files claiming one address are both dropped by the scan, so an
      // ambiguous address reads as missing here.
      return { kind: "rejected", reason: this.#expiredAddresses.has(sourceIp) ? "expired" : "missing" };
    }
    return {
      kind: "active",
      file,
      session: {
        kind: "session",
        sessionKey: file.sessionKey,
        authenticated: true,
        ...pendingApprovalSession(file),
      },
    };
  }
}
