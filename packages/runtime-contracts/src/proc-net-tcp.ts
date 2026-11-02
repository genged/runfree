// Linux `/proc/net/tcp` and `/proc/net/tcp6` parsing (host services on Linux
// Docker Engine).
//
// One parser, two readers: the host CLI's Linux listener probe
// (`packages/cli/src/host-listener-proc.ts`) and the Engine host-service relay
// (`packages/proxy/src/host-relay.ts`), which asks whether a wildcard listener
// already serves a port. It is pure: the callers own the reads and their
// bounds. Any row that does not have the kernel's exact shape fails the whole
// parse, so a caller never acts on a partial table.

export const PROC_NET_TCP_LISTEN_STATE = 0x0a;
export const PROC_NET_TCP_MAX_ROWS = 262_144;

export type ProcNetTcpFamily = 4 | 6;

export type ProcNetTcpSocket = Readonly<{
  family: ProcNetTcpFamily;
  /** Canonical text: dotted quad, or compressed IPv6 (`::`, `::1`, `::ffff:127.0.0.1`). */
  address: string;
  port: number;
  state: number;
  uid: number;
  /** Canonical decimal text of the 64-bit socket inode; `"0"` when the socket has none. */
  inode: string;
}>;

const IPV4_HEX_RE = /^[0-9A-Fa-f]{8}$/u;
const IPV6_HEX_RE = /^[0-9A-Fa-f]{32}$/u;
const PORT_HEX_RE = /^[0-9A-Fa-f]{4}$/u;
const STATE_HEX_RE = /^[0-9A-Fa-f]{2}$/u;
const DECIMAL_RE = /^(0|[1-9][0-9]{0,9})$/u;
const INODE_DECIMAL_RE = /^(0|[1-9][0-9]{0,19})$/u;
const SLOT_RE = /^[0-9]+:$/u;
const QUEUES_RE = /^[0-9A-Fa-f]{8}:[0-9A-Fa-f]{8}$/u;
const TIMER_RE = /^[0-9A-Fa-f]{2}:[0-9A-Fa-f]{8}$/u;
const RETRANSMITS_RE = /^[0-9A-Fa-f]{8}$/u;
const POINTER_RE = /^[0-9A-Fa-f]{8,16}$/u;

// Each 32-bit word of the address is printed in host byte order.
function wordBytes(hex: string, littleEndian: boolean): number[] {
  const bytes = [0, 2, 4, 6].map((offset) => Number.parseInt(hex.slice(offset, offset + 2), 16));
  return littleEndian ? bytes.reverse() : bytes;
}

function ipv4Text(bytes: readonly number[]): string {
  return bytes.join(".");
}

function ipv6Text(bytes: readonly number[]): string {
  const groups: number[] = [];
  for (let index = 0; index < 16; index += 2) groups.push(((bytes[index] ?? 0) << 8) | (bytes[index + 1] ?? 0));
  // IPv4-mapped (::ffff:a.b.c.d): keep the dotted form, as the kernel and
  // every userland tool print it.
  if (groups.slice(0, 5).every((group) => group === 0) && groups[5] === 0xffff) {
    return `::ffff:${ipv4Text(bytes.slice(12))}`;
  }
  let bestStart = -1;
  let bestLength = 0;
  for (let start = 0; start < 8;) {
    if (groups[start] !== 0) {
      start += 1;
      continue;
    }
    let end = start;
    while (end < 8 && groups[end] === 0) end += 1;
    if (end - start > bestLength && end - start >= 2) {
      bestStart = start;
      bestLength = end - start;
    }
    start = end;
  }
  const hex = groups.map((group) => group.toString(16));
  if (bestStart === -1) return hex.join(":");
  const head = hex.slice(0, bestStart).join(":");
  const tail = hex.slice(bestStart + bestLength).join(":");
  return `${head}::${tail}`;
}

function decodeAddress(hex: string, family: ProcNetTcpFamily, littleEndian: boolean): string | undefined {
  if (family === 4) {
    if (!IPV4_HEX_RE.test(hex)) return undefined;
    return ipv4Text(wordBytes(hex, littleEndian));
  }
  if (!IPV6_HEX_RE.test(hex)) return undefined;
  const bytes: number[] = [];
  for (let word = 0; word < 4; word += 1) bytes.push(...wordBytes(hex.slice(word * 8, word * 8 + 8), littleEndian));
  return ipv6Text(bytes);
}

function decimal(value: string | undefined): number | undefined {
  if (value === undefined || !DECIMAL_RE.test(value)) return undefined;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed <= 0xffffffff ? parsed : undefined;
}

const INODE_MAX = 0xffff_ffff_ffff_ffffn;

/**
 * A socket inode is the kernel's `unsigned long` (64-bit), beyond both the
 * 32-bit bound of the other fields and a JS number's exact range. It is kept as
 * its canonical decimal text, the same text `/proc/<pid>/fd` links carry in
 * `socket:[<inode>]`, so owner lookup compares it exactly.
 */
function inodeText(value: string | undefined): string | undefined {
  if (value === undefined || !INODE_DECIMAL_RE.test(value)) return undefined;
  return BigInt(value) <= INODE_MAX ? value : undefined;
}

/**
 * Every socket row of one `/proc/net/tcp` (family 4) or `/proc/net/tcp6`
 * (family 6) table, or the reason the table is not the kernel's shape. The
 * header line is required; a malformed row anywhere fails the whole table.
 */
export function parseProcNetTcp(
  text: string,
  family: ProcNetTcpFamily,
  littleEndian = true,
): ProcNetTcpSocket[] | { error: string } {
  const label = family === 4 ? "/proc/net/tcp" : "/proc/net/tcp6";
  const lines = text.split("\n");
  if (lines.at(-1) === "") lines.pop();
  const header = lines.shift();
  if (header === undefined || !/^\s*sl\s+local_address\s+(?:rem_address|remote_address)\s+st\s/u.test(header)) {
    return { error: `${label} has no header line` };
  }
  if (lines.length > PROC_NET_TCP_MAX_ROWS) return { error: `${label} has more than ${PROC_NET_TCP_MAX_ROWS} rows` };
  const sockets: ProcNetTcpSocket[] = [];
  const endpoint = (value: string | undefined): { address: string; port: number } | undefined => {
    const separator = value?.indexOf(":") ?? -1;
    if (value === undefined || separator === -1 || value.indexOf(":", separator + 1) !== -1) return undefined;
    const portHex = value.slice(separator + 1);
    const address = decodeAddress(value.slice(0, separator), family, littleEndian);
    if (address === undefined || !PORT_HEX_RE.test(portHex)) return undefined;
    return { address, port: Number.parseInt(portHex, 16) };
  };
  for (const [index, line] of lines.entries()) {
    const fields = line.trim().split(/\s+/u);
    // Every row, whatever its state, has at least these twelve fields:
    // sl local rem st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode refcnt sock-pointer ...
    const [slot, local, remote, state, queues, timer, retransmits, uid, timeout, inode, refcount, pointer] = fields;
    const malformed = { error: `${label} row ${index + 1} is malformed` };
    if (fields.length < 12 || slot === undefined || !SLOT_RE.test(slot)) return malformed;
    const localEndpoint = endpoint(local);
    if (localEndpoint === undefined || endpoint(remote) === undefined) return malformed;
    if (state === undefined || !STATE_HEX_RE.test(state)) return malformed;
    if (queues === undefined || !QUEUES_RE.test(queues) || timer === undefined || !TIMER_RE.test(timer)
      || retransmits === undefined || !RETRANSMITS_RE.test(retransmits)) return malformed;
    const parsedUid = decimal(uid);
    const parsedInode = inodeText(inode);
    if (parsedUid === undefined || parsedInode === undefined || decimal(timeout) === undefined || decimal(refcount) === undefined) {
      return malformed;
    }
    if (pointer === undefined || !POINTER_RE.test(pointer)) return malformed;
    sockets.push(Object.freeze({
      family,
      address: localEndpoint.address,
      port: localEndpoint.port,
      state: Number.parseInt(state, 16),
      uid: parsedUid,
      inode: parsedInode,
    }));
  }
  return sockets;
}

/** `0.0.0.0` or `::`: the kernel delivers every local address of the port to it. */
export function isWildcardListenAddress(address: string): boolean {
  return address === "0.0.0.0" || address === "::";
}
