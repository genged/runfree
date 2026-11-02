import { describe, expect, test } from "vitest";

import { isWildcardListenAddress, parseProcNetTcp, PROC_NET_TCP_LISTEN_STATE } from "./proc-net-tcp.ts";

const TCP_HEADER = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode";
const TCP6_HEADER = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode";

function row(slot: number, local: string, remote: string, state: string, uid: number, inode: number | string): string {
  return `   ${slot}: ${local} ${remote} ${state} 00000000:00000000 00:00000000 00000000 ${uid} 0 ${inode} 1 0000000000000000 100 0 0 10 0`;
}

describe("parseProcNetTcp", () => {
  test("decodes IPv4 rows in host (little-endian) byte order", () => {
    const text = [
      TCP_HEADER,
      row(0, "0100007F:2A82", "00000000:0000", "0A", 1000, 4242),
      row(1, "00000000:1F90", "00000000:0000", "0A", 0, 77),
      row(2, "0100007F:2A82", "0100007F:D431", "01", 1000, 0),
    ].join("\n");
    expect(parseProcNetTcp(`${text}\n`, 4)).toEqual([
      { family: 4, address: "127.0.0.1", port: 10882, state: PROC_NET_TCP_LISTEN_STATE, uid: 1000, inode: "4242" },
      { family: 4, address: "0.0.0.0", port: 8080, state: PROC_NET_TCP_LISTEN_STATE, uid: 0, inode: "77" },
      { family: 4, address: "127.0.0.1", port: 10882, state: 1, uid: 1000, inode: "0" },
    ]);
  });

  test("decodes IPv6 rows: wildcard, loopback, mapped, and a global address", () => {
    const text = [
      TCP6_HEADER,
      row(0, "00000000000000000000000000000000:2A82", "00000000000000000000000000000000:0000", "0A", 1000, 1),
      row(1, "00000000000000000000000001000000:2A82", "00000000000000000000000000000000:0000", "0A", 1000, 2),
      row(2, "0000000000000000FFFF00000100007F:2A82", "00000000000000000000000000000000:0000", "0A", 1000, 3),
      row(3, "B80D0120000000000000000001000000:2A82", "00000000000000000000000000000000:0000", "0A", 1000, 4),
    ].join("\n");
    const parsed = parseProcNetTcp(text, 6);
    expect(Array.isArray(parsed) ? parsed.map((socket) => socket.address) : parsed).toEqual([
      "::",
      "::1",
      "::ffff:127.0.0.1",
      "2001:db8::1",
    ]);
  });

  test("big-endian hosts print the words in network order", () => {
    const parsed = parseProcNetTcp(`${TCP_HEADER}\n${row(0, "7F000001:2A82", "00000000:0000", "0A", 0, 9)}\n`, 4, false);
    expect(Array.isArray(parsed) ? parsed[0]?.address : parsed).toBe("127.0.0.1");
  });

  test("an empty table with its header is no sockets", () => {
    expect(parseProcNetTcp(`${TCP_HEADER}\n`, 4)).toEqual([]);
  });

  test.each([
    ["no header", row(0, "0100007F:2A82", "00000000:0000", "0A", 0, 1)],
    ["empty text", ""],
    ["short address", `${TCP_HEADER}\n${row(0, "0100007:2A82", "00000000:0000", "0A", 0, 1)}`],
    ["IPv6 width in the IPv4 table", `${TCP_HEADER}\n${row(0, "00000000000000000000000001000000:2A82", "00000000:0000", "0A", 0, 1)}`],
    ["non-hex port", `${TCP_HEADER}\n${row(0, "0100007F:ZZZZ", "00000000:0000", "0A", 0, 1)}`],
    ["non-numeric uid", `${TCP_HEADER}\n   0: 0100007F:2A82 00000000:0000 0A 00000000:00000000 00:00000000 00000000 root 0 1 1`],
    ["truncated row", `${TCP_HEADER}\n   0: 0100007F:2A82 00000000:0000 0A`],
    ["missing slot", `${TCP_HEADER}\n0100007F:2A82 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1 1`],
  ])("a malformed table fails as a whole: %s", (_label, text) => {
    expect(parseProcNetTcp(text, 4)).toMatchObject({ error: expect.any(String) });
  });

  // REVIEW-1 #4: every required field is the kernel's exact shape, so a row
  // such as `garbage:ZZZZ` in the remote column can never authorize a
  // listener through its valid-looking local column.
  const fields = (overrides: Partial<Record<"local" | "remote" | "state" | "queues" | "timer" | "retransmits" | "uid" | "timeout" | "inode" | "rest", string>>): string => {
    const value = {
      local: "0100007F:2A82", remote: "00000000:0000", state: "0A", queues: "00000000:00000000", timer: "00:00000000",
      retransmits: "00000000", uid: "1000", timeout: "0", inode: "4242", rest: "1 0000000000000000 100 0 0 10 0", ...overrides,
    };
    return `${TCP_HEADER}\n   0: ${value.local} ${value.remote} ${value.state} ${value.queues} ${value.timer} ${value.retransmits} ${value.uid} ${value.timeout} ${value.inode} ${value.rest}`;
  };
  test("the field fixture itself parses (a LISTEN row is accepted)", () => {
    expect(parseProcNetTcp(fields({}), 4)).toEqual([{ family: 4, address: "127.0.0.1", port: 10882, state: 10, uid: 1000, inode: "4242" }]);
  });
  // REVIEW-3 #1: a socket inode is the kernel's 64-bit unsigned long. One row
  // above 2^32 must not make the whole table unavailable, and it stays exact.
  test.each(["4294967295", "4294967296", "9007199254740993", "18446744073709551615"])(
    "a 64-bit socket inode parses exactly: %s",
    (inode) => {
      expect(parseProcNetTcp(fields({ inode }), 4)).toEqual([{ family: 4, address: "127.0.0.1", port: 10882, state: 10, uid: 1000, inode }]);
    },
  );
  test("a large inode on an unrelated row does not fail the table", () => {
    const text = [TCP_HEADER, row(0, "0100007F:2A82", "00000000:0000", "0A", 1000, 4242), row(1, "0100007F:1F90", "00000000:0000", "0A", 1000, "4294967296")].join("\n");
    const parsed = parseProcNetTcp(text, 4);
    expect(Array.isArray(parsed) ? parsed.map((socket) => socket.inode) : parsed).toEqual(["4242", "4294967296"]);
  });
  test("a TIME_WAIT row's twelve fields are the kernel's minimum shape", () => {
    expect(parseProcNetTcp(fields({ state: "06", timer: "03:00000F4A", inode: "0", rest: "3 0000000000000000" }), 4)).toHaveLength(1);
  });
  test.each([
    ["garbage remote", { remote: "garbage:ZZZZ" }],
    ["remote without a port", { remote: "00000000" }],
    ["remote with a non-hex port", { remote: "00000000:ZZZZ" }],
    ["remote of the wrong width", { remote: "0000:0000" }],
    ["local with two colons", { local: "0100007F:2A82:0000" }],
    ["remote with two colons", { remote: "00000000:0000:0000" }],
    ["non-hex state", { state: "0Z" }],
    ["three-digit state", { state: "00A" }],
    ["queues without a colon", { queues: "0000000000000000" }],
    ["non-hex queues", { queues: "0000000G:00000000" }],
    ["timer of the wrong shape", { timer: "0:00000000" }],
    ["non-hex retransmits", { retransmits: "0000000X" }],
    ["short retransmits", { retransmits: "0" }],
    ["negative uid", { uid: "-1" }],
    ["non-decimal timeout", { timeout: "x" }],
    ["non-decimal inode", { inode: "0x10" }],
    ["inode above 2^64-1", { inode: "18446744073709551616" }],
    ["inode of 21 digits", { inode: "100000000000000000000" }],
    ["inode with a leading zero", { inode: "04242" }],
    ["negative inode", { inode: "-1" }],
    ["uid above 2^32-1", { uid: "4294967296" }],
    ["no refcount or socket pointer", { rest: "" }],
    ["no socket pointer", { rest: "1" }],
    ["non-hex socket pointer", { rest: "1 zzzzzzzzzzzzzzzz 100 0 0 10 0" }],
    ["non-decimal refcount", { rest: "one 0000000000000000 100 0 0 10 0" }],
  ])("a malformed field fails the whole table: %s", (_label, overrides) => {
    expect(parseProcNetTcp(fields(overrides), 4)).toMatchObject({ error: "/proc/net/tcp row 1 is malformed" });
  });
  test("an IPv6 row needs an IPv6-width remote address", () => {
    const local = "00000000000000000000000001000000:2A82";
    const ipv6Row = (remote: string): string => `${TCP6_HEADER}\n   0: ${local} ${remote} 0A 00000000:00000000 00:00000000 00000000 1000 0 7 1 0000000000000000 100 0 0 10 0`;
    expect(parseProcNetTcp(ipv6Row("00000000000000000000000000000000:0000"), 6)).toHaveLength(1);
    expect(parseProcNetTcp(ipv6Row("00000000:0000"), 6)).toMatchObject({ error: "/proc/net/tcp6 row 1 is malformed" });
  });
});

describe("isWildcardListenAddress", () => {
  test.each([["0.0.0.0", true], ["::", true], ["127.0.0.1", false], ["::1", false], ["::ffff:127.0.0.1", false], ["172.17.0.1", false]])(
    "%s -> %s",
    (address, expected) => {
      expect(isWildcardListenAddress(address)).toBe(expected);
    },
  );
});
