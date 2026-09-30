/**
 * Byte-level reproductions of what the Docker CLI prints for the routed argv
 * shapes. Each function copies one named piece of Docker CLI (Go) behavior;
 * anything these functions cannot reproduce exactly is refused by the router
 * (the call stays on the CLI) rather than approximated here.
 */

const SPACE = 0x20;
const TAB = 0x09;
const LF = 0x0a;
const CR = 0x0d;
const QUOTE = 0x22;
const BACKSLASH = 0x5c;

function appendNewline(out: number[], depth: number): void {
  out.push(LF);
  for (let level = 0; level < depth; level += 1) out.push(SPACE, SPACE, SPACE, SPACE);
}

/**
 * Go's `json.Indent(dst, src, "", "    ")` over a valid JSON document:
 * insignificant whitespace is dropped, every byte inside a string is copied
 * unchanged (no re-escaping, no number reformatting), empty objects and
 * arrays stay `{}` / `[]`, and `:` gets one trailing space. The caller must
 * have proved `src` is valid JSON (Go's scanner would stop at an error).
 */
export function goJsonIndent(src: Uint8Array): Buffer {
  const out: number[] = [];
  let depth = 0;
  let needIndent = false;
  let inString = false;
  let escaped = false;
  for (const c of src) {
    if (inString) {
      out.push(c);
      if (escaped) escaped = false;
      else if (c === BACKSLASH) escaped = true;
      else if (c === QUOTE) inString = false;
      continue;
    }
    if (c === SPACE || c === TAB || c === LF || c === CR) continue;
    if (needIndent && c !== 0x7d && c !== 0x5d) {
      needIndent = false;
      depth += 1;
      appendNewline(out, depth);
    }
    switch (c) {
      case QUOTE:
        inString = true;
        out.push(c);
        break;
      case 0x7b: // {
      case 0x5b: // [
        needIndent = true;
        out.push(c);
        break;
      case 0x2c: // ,
        out.push(c);
        appendNewline(out, depth);
        break;
      case 0x3a: // :
        out.push(c, SPACE);
        break;
      case 0x7d: // }
      case 0x5d: // ]
        if (needIndent) {
          needIndent = false;
        } else {
          depth -= 1;
          appendNewline(out, depth);
        }
        out.push(c);
        break;
      default:
        out.push(c);
    }
  }
  return Buffer.from(out);
}

/**
 * The CLI's default (no `--format`) inspect output: every raw API body joined
 * into one JSON array, indented, plus a newline (cli/command/inspect
 * `jsonInspector.Flush`). No bodies prints `[]\n`, which the router never
 * produces: a routed inspect names at least one object.
 */
export function formatRawInspect(bodies: readonly Uint8Array[]): Buffer {
  if (bodies.length === 0) return Buffer.from("[]\n");
  const parts: Buffer[] = [Buffer.from("[")];
  bodies.forEach((body, index) => {
    parts.push(Buffer.from(body));
    if (index < bodies.length - 1) parts.push(Buffer.from(","));
  });
  parts.push(Buffer.from("]"));
  return Buffer.concat([goJsonIndent(Buffer.concat(parts)), Buffer.from("\n")]);
}

/** github.com/docker/docker/pkg/stringid.TruncateID. */
export function truncateId(id: string): string {
  const colon = id.indexOf(":");
  const bare = colon >= 0 ? id.slice(colon + 1) : id;
  return bare.length > 12 ? bare.slice(0, 12) : bare;
}

export type DemuxedStreams =
  | { ok: true; stdout: Buffer; stderr: Buffer }
  | { ok: false; reason: string };

/**
 * Splits a non-TTY exec stream into stdout and stderr the way the CLI's
 * `stdcopy.StdCopy` does: 8-byte headers `[type, 0, 0, 0, size(uint32 BE)]`,
 * type 0 (stdin) and 1 to stdout, 2 to stderr. A system-error frame (3), an
 * unknown type, or a truncated frame is refused: the CLI reports those as an
 * error, never as a clean answer.
 */
export function demuxDockerStream(stream: Uint8Array): DemuxedStreams {
  const stdout: Buffer[] = [];
  const stderr: Buffer[] = [];
  const buffer = Buffer.from(stream.buffer, stream.byteOffset, stream.byteLength);
  let offset = 0;
  while (offset < buffer.length) {
    if (buffer.length - offset < 8) return { ok: false, reason: "truncated exec stream frame header" };
    const type = buffer[offset];
    const size = buffer.readUInt32BE(offset + 4);
    const start = offset + 8;
    if (buffer.length - start < size) return { ok: false, reason: "truncated exec stream frame" };
    const payload = buffer.subarray(start, start + size);
    if (type === 0 || type === 1) stdout.push(payload);
    else if (type === 2) stderr.push(payload);
    else if (type === 3) return { ok: false, reason: `error from daemon in stream: ${payload.toString("utf8")}` };
    else return { ok: false, reason: `unrecognized exec stream type ${type}` };
    offset = start + size;
  }
  return { ok: true, stdout: Buffer.concat(stdout), stderr: Buffer.concat(stderr) };
}
