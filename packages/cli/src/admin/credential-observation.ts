// Same-phase credential runtime observations.
//
// A credential sync needs several facts about the exact proxy it writes to:
// its incarnation (container ID + StartedAt), the runtime validation marker,
// the policy consumers' acknowledgements, and the names of the tokens its
// tmpfs holds. They used to be read by one Docker call each. This module reads
// every same-container file one observation needs in one root exec, and
// brackets that exec between two incarnation readings: a proxy restart that
// lands inside the observation (tmpfs wiped, marker kept) is a mismatch, never
// a mix of two incarnations.
//
// Evidence belongs to the phase that observed it. A `preparation` observation
// may only spare a source read; write authority (the held-token set a locked
// sync acts on) comes only from a `locked-sync` observation. The pure parsers
// here hold no ambient admin state; the Docker port is injected.

import { sha256Hex, stableJsonDroppingUndefined as stableJson } from "../strict-primitives.ts";
import { parseGenerationStatusLine, type ParsedGenerationStatus } from "@runfree/runtime-contracts/proxy-status";
import type { DockerClient } from "../runtime/docker-client.ts";

export type CredentialObservationPhase = "preparation" | "locked-sync";

export type ProxyObservationSection =
  | "validation-marker"
  | "firewall-status"
  | "request-proxy-status"
  | "held-token-names";

export type ProxyObservationPaths = Readonly<{
  validationMarker: string;
  firewallStatus: string;
  requestProxyStatus: string;
  secretDir: string;
}>;

export const CREDENTIAL_OBSERVATION_BATCH_HEADER = "runfree-credential-observation 1";

// Every section the proxy writes is a small JSON file or a short name list.
// Anything larger is not a file this protocol reads; refuse it rather than
// buffer it.
export const CREDENTIAL_OBSERVATION_SECTION_MAX_BYTES = 1024 * 1024;

const SECTION_NAMES: ReadonlySet<string> = new Set<ProxyObservationSection>([
  "validation-marker",
  "firewall-status",
  "request-proxy-status",
  "held-token-names",
]);

function shellSingleQuote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

/**
 * The root exec's script. Each requested section is emitted exactly once as
 * `<name> <present|absent|unreadable> <byte length>\n<bytes>\n`, after a
 * versioned header and before an `end` trailer. A file is read once into the
 * shell and measured from that same copy, so a file replaced mid-read can
 * never pair one version's length with another's bytes. The held-token
 * section is a directory listing: names only, never a token value.
 */
export function credentialObservationBatchScript(
  sections: readonly ProxyObservationSection[],
  paths: ProxyObservationPaths,
): string {
  assertSectionList(sections);
  const lines = [
    `printf '%s\\n' ${shellSingleQuote(CREDENTIAL_OBSERVATION_BATCH_HEADER)}`,
    // `x` keeps trailing newlines through command substitution.
    "rf_emit() { rf_v=${2%x}; rf_n=$(printf %s \"$rf_v\" | wc -c); printf '%s present %s\\n' \"$1\" \"$((rf_n))\"; printf '%s\\n' \"$rf_v\"; }",
    "rf_file() { if [ ! -e \"$2\" ]; then printf '%s absent 0\\n\\n' \"$1\"; elif rf_c=$(cat -- \"$2\" && printf x); then rf_emit \"$1\" \"$rf_c\"; else printf '%s unreadable 0\\n\\n' \"$1\"; fi; }",
    "rf_names() { if rf_c=$(ls -1 -- \"$2\" && printf x); then rf_emit \"$1\" \"$rf_c\"; else printf '%s unreadable 0\\n\\n' \"$1\"; fi; }",
  ];
  for (const section of sections) {
    if (section === "held-token-names") lines.push(`rf_names ${section} ${shellSingleQuote(paths.secretDir)}`);
    else lines.push(`rf_file ${section} ${shellSingleQuote(sectionPath(section, paths))}`);
  }
  lines.push("printf 'end\\n'");
  return lines.join("\n");
}

function sectionPath(section: Exclude<ProxyObservationSection, "held-token-names">, paths: ProxyObservationPaths): string {
  if (section === "validation-marker") return paths.validationMarker;
  if (section === "firewall-status") return paths.firewallStatus;
  return paths.requestProxyStatus;
}

function assertSectionList(sections: readonly ProxyObservationSection[]): void {
  if (sections.length === 0) throw new Error("internal: a credential observation batch needs at least one section");
  if (new Set(sections).size !== sections.length) throw new Error("internal: a credential observation batch names a section twice");
}

export type BatchSection =
  | Readonly<{ state: "present"; text: string }>
  | Readonly<{ state: "absent" }>
  | Readonly<{ state: "unreadable" }>;

export type BatchParseResult =
  | Readonly<{ ok: true; sections: ReadonlyMap<ProxyObservationSection, BatchSection> }>
  | Readonly<{ ok: false; reason: string }>;

const SECTION_LINE = /^([a-z-]+) (present|absent|unreadable) (0|[1-9][0-9]{0,8})$/;

/**
 * Parses the batch strictly: the exact header, each requested section exactly
 * once (no duplicates, no unrequested ones), declared lengths that match the
 * bytes, and the `end` trailer as the last line. Anything else, including a
 * truncated stream, is refused as a whole.
 */
export function parseCredentialObservationBatch(
  stdout: string,
  requested: readonly ProxyObservationSection[],
): BatchParseResult {
  const bytes = Buffer.from(stdout, "utf8");
  let offset = 0;
  const readLine = (): string | undefined => {
    const end = bytes.indexOf(0x0a, offset);
    if (end < 0) return undefined;
    const line = bytes.subarray(offset, end).toString("utf8");
    offset = end + 1;
    return line;
  };
  if (readLine() !== CREDENTIAL_OBSERVATION_BATCH_HEADER) return { ok: false, reason: "missing or unsupported batch header" };
  const wanted = new Set<string>(requested);
  const sections = new Map<ProxyObservationSection, BatchSection>();
  while (true) {
    const line = readLine();
    if (line === undefined) return { ok: false, reason: "truncated batch: no end trailer" };
    if (line === "end") break;
    const match = SECTION_LINE.exec(line);
    if (!match) return { ok: false, reason: "malformed section header" };
    const [, name, state, lengthText] = match;
    if (!SECTION_NAMES.has(name) || !wanted.has(name)) return { ok: false, reason: `unrequested section ${name}` };
    const section = name as ProxyObservationSection;
    if (sections.has(section)) return { ok: false, reason: `duplicate section ${name}` };
    const length = Number(lengthText);
    if (length > CREDENTIAL_OBSERVATION_SECTION_MAX_BYTES) return { ok: false, reason: `section ${name} exceeds its bound` };
    if (state !== "present" && length !== 0) return { ok: false, reason: `section ${name} is ${state} but carries bytes` };
    if (offset + length + 1 > bytes.length || bytes[offset + length] !== 0x0a) {
      return { ok: false, reason: `truncated section ${name}` };
    }
    const text = bytes.subarray(offset, offset + length).toString("utf8");
    offset += length + 1;
    sections.set(section, state === "present" ? { state, text } : { state: state as "absent" | "unreadable" });
  }
  if (offset !== bytes.length) return { ok: false, reason: "bytes after the end trailer" };
  for (const name of requested) {
    if (!sections.has(name)) return { ok: false, reason: `missing section ${name}` };
  }
  return { ok: true, sections };
}

/** The marker's parsed record (for validation) and fingerprint (for the store generation). */
export type ProxyValidationMarker = Readonly<{ parsed?: unknown; fingerprint: string }>;

function sha256Json(value: unknown): string {
  return sha256Hex(stableJson(value));
}

/** Byte-compatible with the marker reading every earlier CLI did, so persisted receipts keep their generation. */
export function parseProxyValidationMarker(text: string): ProxyValidationMarker {
  try {
    const parsed = JSON.parse(text) as unknown;
    return { parsed, fingerprint: sha256Json(parsed) };
  } catch {
    return { fingerprint: sha256Json({ raw: text }) };
  }
}

/** The token-store generation: exact proxy ID, incarnation, and validation marker identity. */
export function proxyTokenStoreGeneration(proxyId: string, startedAt: string, validationIdentity: string): string {
  return sha256Json({ proxyId, startedAt, validationIdentity });
}

export function parseHeldTokenNames(text: string, isTokenName: (name: string) => boolean): ReadonlySet<string> {
  return new Set(text.split(/\r?\n/).map((line) => line.trim()).filter((name) => isTokenName(name)));
}

// --- Incarnation readings -----------------------------------------------------

export const STARTED_AT_INSPECT_FIELD = "{{.State.StartedAt}}";

/** A StartedAt value Docker reported, or undefined for an empty or template-miss answer. */
export function validStartedAt(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  if (!trimmed || trimmed === "<no value>" || /\s/.test(trimmed)) return undefined;
  return trimmed;
}

/** Inspect output rows, split on newlines only: an empty trailing field must keep its tab. */
export function inspectOutputRows(stdout: string): string[] {
  return stdout.split(/\r?\n/).filter((line) => line !== "");
}

/**
 * One inspect row of `fieldCount` tab-separated fields followed by the
 * grouped StartedAt field. Returns the leading fields unchanged and the
 * incarnation, or undefined when the row does not have exactly that shape.
 */
export function splitTrailingStartedAt(line: string, fieldCount: number): Readonly<{ head: string; startedAt?: string }> | undefined {
  const fields = line.split("\t");
  if (fields.length !== fieldCount + 1) return undefined;
  return { head: fields.slice(0, fieldCount).join("\t"), startedAt: validStartedAt(fields[fieldCount]) };
}

// --- The observation ------------------------------------------------------------

export type CredentialObservationDocker = Pick<DockerClient, "exec" | "inspect">;

export type ObservedSections = Readonly<{
  /** Undefined when the marker file is absent or unreadable. */
  validationMarker?: ProxyValidationMarker;
  firewallStatus?: ParsedGenerationStatus;
  requestProxyStatus?: ParsedGenerationStatus;
  /** Undefined when the secret directory could not be listed: never evidence of absence. */
  heldTokenNames?: ReadonlySet<string>;
}>;

export type AfterIncarnation =
  | Readonly<{ kind: "started"; startedAt: string }>
  | Readonly<{ kind: "refused"; message: string }>
  | Readonly<{ kind: "unavailable"; reason: string }>;

export type CredentialObservationInput = Readonly<{
  phase: CredentialObservationPhase;
  proxyId: string;
  sections: readonly ProxyObservationSection[];
  paths: ProxyObservationPaths;
  docker: CredentialObservationDocker;
  isTokenName: (name: string) => boolean;
  /**
   * The incarnation seen before the batch: from an inspect grouped with the
   * caller's own validation, or the baseline an earlier observation of the
   * same phase proved.
   */
  before: string;
  /**
   * The incarnation after the batch. Omitted: one StartedAt inspect. A caller
   * that already inspects the container after the batch (its validation) may
   * group the reading there instead, and may refuse the runtime.
   */
  after?: (sections: ObservedSections) => AfterIncarnation;
}>;

export type CredentialObservation = ObservedSections & Readonly<{
  phase: CredentialObservationPhase;
  proxyId: string;
  startedAt: string;
  /** Present only with a readable marker. */
  storeGeneration?: string;
}>;

export type CredentialObservationResult =
  | Readonly<{ kind: "observed"; observation: CredentialObservation }>
  | Readonly<{ kind: "unavailable"; reason: string }>
  | Readonly<{ kind: "mismatch"; reason: string }>
  | Readonly<{ kind: "refused"; message: string }>;

/** One bounded root exec reading the requested sections; no incarnation reading of its own. */
export function readProxyObservationSections(input: Readonly<{
  proxyId: string;
  sections: readonly ProxyObservationSection[];
  paths: ProxyObservationPaths;
  docker: CredentialObservationDocker;
  isTokenName: (name: string) => boolean;
}>): Readonly<{ ok: true; sections: ObservedSections }> | Readonly<{ ok: false; reason: string }> {
  const script = credentialObservationBatchScript(input.sections, input.paths);
  const result = input.docker.exec(input.proxyId, ["sh", "-c", script], { user: "0:0" });
  if (result.status !== 0) return { ok: false, reason: "proxy observation exec failed" };
  const parsed = parseCredentialObservationBatch(result.stdout, input.sections);
  if (!parsed.ok) return { ok: false, reason: parsed.reason };
  const present = (section: ProxyObservationSection): string | undefined => {
    const value = parsed.sections.get(section);
    return value?.state === "present" ? value.text : undefined;
  };
  const marker = present("validation-marker");
  const firewall = present("firewall-status");
  const requestProxy = present("request-proxy-status");
  const held = present("held-token-names");
  return {
    ok: true,
    sections: {
      ...(marker !== undefined ? { validationMarker: parseProxyValidationMarker(marker) } : {}),
      ...(firewall !== undefined ? { firewallStatus: parseGenerationStatusLine(firewall.trim()) } : {}),
      ...(requestProxy !== undefined ? { requestProxyStatus: parseGenerationStatusLine(requestProxy.trim()) } : {}),
      ...(held !== undefined ? { heldTokenNames: parseHeldTokenNames(held, input.isTokenName) } : {}),
    },
  };
}

/**
 * Reads the requested proxy files in one root exec, bracketed by the
 * incarnation the caller saw before it and one reading after it. A different
 * StartedAt after the batch is a mismatch: the container restarted (same ID,
 * fresh tmpfs) while it was being read, so no section of this batch is
 * evidence for either incarnation.
 */
export function observeCredentialRuntime(input: CredentialObservationInput): CredentialObservationResult {
  const read = readProxyObservationSections(input);
  if (!read.ok) return { kind: "unavailable", reason: read.reason };
  const after = input.after
    ? input.after(read.sections)
    : startedAtInspect(input.docker, input.proxyId);
  if (after.kind === "refused") return { kind: "refused", message: after.message };
  if (after.kind === "unavailable") return { kind: "unavailable", reason: after.reason };
  if (after.startedAt !== input.before) {
    return { kind: "mismatch", reason: "the proxy restarted while its credential runtime was observed" };
  }
  const marker = read.sections.validationMarker;
  return {
    kind: "observed",
    observation: {
      ...read.sections,
      phase: input.phase,
      proxyId: input.proxyId,
      startedAt: after.startedAt,
      ...(marker ? { storeGeneration: proxyTokenStoreGeneration(input.proxyId, after.startedAt, marker.fingerprint) } : {}),
    },
  };
}

function startedAtInspect(docker: CredentialObservationDocker, proxyId: string): AfterIncarnation {
  const result = docker.inspect([proxyId], { format: STARTED_AT_INSPECT_FIELD });
  const startedAt = result.status === 0 ? validStartedAt(result.stdout) : undefined;
  return startedAt ? { kind: "started", startedAt } : { kind: "unavailable", reason: "proxy StartedAt could not be inspected" };
}

/**
 * The held-token set a locked sync may act on. Preparation evidence is never
 * write authority, whatever it holds.
 */
export function lockedHeldTokenNames(observation: Pick<CredentialObservation, "phase" | "heldTokenNames">): ReadonlySet<string> | undefined {
  if (observation.phase !== "locked-sync") {
    throw new Error("internal: a preparation observation is not write authority for a locked credential sync");
  }
  return observation.heldTokenNames;
}
