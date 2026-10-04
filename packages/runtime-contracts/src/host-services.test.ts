import { describe, expect, test } from "vitest";

import {
  formatHostServicesEnv, hostServiceAuthority, isReservedRunfreeHostname, parseHostServiceAuthority,
  HOST_SERVICE_MAX_ENTRIES, parseHostServicesEnv, refusedHostServicePortReason, validateHostServices,
} from "./host-services.ts";

describe("reserved suffix", () => {
  test.each(["runfree.internal", "x.runfree.internal", "A.Runfree.Internal", "x.runfree.internal."])("%s is reserved", (h) => {
    expect(isReservedRunfreeHostname(h)).toBe(true);
  });
  test.each(["runfree.internal.example.com", "notrunfree.internal", "api.github.com"])("%s is not reserved", (h) => {
    expect(isReservedRunfreeHostname(h)).toBe(false);
  });
});

describe("authority parsing", () => {
  test("exact service authority", () => {
    expect(parseHostServiceAuthority("idb.runfree.internal:10882")).toEqual({ kind: "service", name: "idb", port: 10882 });
    expect(hostServiceAuthority("idb", 10882)).toBe("idb.runfree.internal:10882");
  });
  test.each([
    "runfree.internal:443", "idb.runfree.internal", "idb.runfree.internal.:10882", "IDB.runfree.internal:10882",
    "a.b.runfree.internal:1", "idb.runfree.internal:0", "idb.runfree.internal:65536", "idb.runfree.internal:01",
    "idb.runfree.internal:abc", "9x.runfree.internal:1",
  ])("%s is malformed under the reserved suffix", (a) => {
    expect(parseHostServiceAuthority(a)).toEqual({ kind: "malformed" });
  });
  test("other hosts are not reserved", () => {
    expect(parseHostServiceAuthority("api.github.com:443")).toEqual({ kind: "not-reserved" });
    expect(parseHostServiceAuthority("api.github.com")).toEqual({ kind: "not-reserved" });
  });
});

describe("refused ports", () => {
  test.each([2375, 2376, 3128, 5901, 47100, 47999, 48099])("%i is refused", (p) => {
    expect(refusedHostServicePortReason(p)).toBeTypeOf("string");
  });
  test.each([10882, 47099, 48100, 6188])("%i is not statically refused", (p) => {
    expect(refusedHostServicePortReason(p)).toBeUndefined();
  });
});

describe("validateHostServices", () => {
  test("accepts host-loopback entries", () => {
    const issues: string[] = [];
    expect(validateHostServices({ idb: { target: "host-loopback", port: 10882 } }, "hostServices", issues)).toEqual({ idb: { target: "host-loopback", port: 10882 } });
    expect(issues).toEqual([]);
  });
  test.each([
    [{ "9x": { target: "host-loopback", port: 1 } }, "name"],
    [{ idb: { target: "address", host: "lab.local", port: 1 } }, "not supported yet"],
    [{ idb: { target: "host-loopback", port: 0 } }, "port"],
    [{ idb: { target: "host-loopback", port: 2375 } }, "refused"],
    [{ idb: { target: "host-loopback", port: 1, extra: true } }, "extra is not a known field"],
    [{ a: { target: "host-loopback", port: 9 }, b: { target: "host-loopback", port: 9 } }, "duplicate port"],
    [[], "object"],
  ])("refuses %j", (raw, needle) => {
    const issues: string[] = [];
    validateHostServices(raw, "hostServices", issues);
    expect(issues.join("\n")).toContain(needle);
  });
});

describe("host-service entry cap", () => {
  const services = (count: number) => Object.fromEntries(Array.from({ length: count }, (_, index) =>
    [`svc${index}`, { target: "host-loopback", port: 20000 + index }]));

  test("accepts exactly the firewall set size", () => {
    const issues: string[] = [];
    expect(Object.keys(validateHostServices(services(HOST_SERVICE_MAX_ENTRIES), "hostServices", issues))).toHaveLength(64);
    expect(issues).toEqual([]);
  });

  test("refuses one entry more than the firewall set holds", () => {
    const issues: string[] = [];
    expect(validateHostServices(services(HOST_SERVICE_MAX_ENTRIES + 1), "hostServices", issues)).toEqual({});
    expect(issues).toEqual(["hostServices has more than 64 entries"]);
  });
});

describe("env list", () => {
  test("round-trips sorted", () => {
    const v = formatHostServicesEnv({ zz: { target: "host-loopback", port: 2 }, aa: { target: "host-loopback", port: 1 } });
    expect(v).toBe("aa:1,zz:2");
    expect(parseHostServicesEnv(v)).toEqual([{ name: "aa", port: 1 }, { name: "zz", port: 2 }]);
  });
  test.each(["", "a", "a:", "a:0", "A:1", "a:1,", "a:1,a:2", "a:1,b:1"])("refuses %j", (v) => {
    expect(() => parseHostServicesEnv(v)).toThrow();
  });
});
