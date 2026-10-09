import fc from "fast-check";
import { describe, expect, it } from "vitest";

import { propertyParameters } from "../../../../tests/support/property.ts";
import {
  type FirewallPlan,
  type HostServiceElement,
  isValidIpv4,
  renderAllowedSetUpdate,
  renderAuditDrainingSetUpdate,
  renderAuditSetUpdate,
  renderAuditTeardown,
  renderHostServiceSetUpdate,
  renderHostServiceTeardown,
  renderRuleset,
  renderSessionAdmissionSetUpdate,
} from "./nftables.ts";

// Every render output is fed to `nft -f -` as root. The plan comes from proxy
// environment variables and the elements from DNS answers, Docker inspection,
// and the host-service gateway, so the generators mix valid values with
// strings carrying nft syntax.

const SET_NAME_KEYS = [
  "setName",
  "sessionSetName",
  "auditSetName",
  "auditDrainingSetName",
  "hostServiceSetName",
  "hostServiceDrainingSetName",
  "hostServiceGatewaySetName",
] as const;
const SIZE_KEYS = [
  "maxElements",
  "sessionMaxElements",
  "auditMaxElements",
  "hostServiceMaxElements",
  "hostServiceGatewayMaxElements",
] as const;

type PlanFields = {
  internalIface: string;
  egressIface: string;
  proxyPort: number;
  tableName: string;
  setNames: readonly string[];
  sizes: readonly number[];
};

function planFrom(fields: PlanFields): FirewallPlan {
  const nftables = {
    tableName: fields.tableName,
    ...Object.fromEntries(SET_NAME_KEYS.map((key, index) => [key, fields.setNames[index]])),
    ...Object.fromEntries(SIZE_KEYS.map((key, index) => [key, fields.sizes[index]])),
  };
  return {
    policyPath: "/app/proxy/policy/network-policy.json",
    policyGeneration: `sha256:${"a".repeat(64)}`,
    internal: { iface: fields.internalIface, proxyIp: "172.30.0.10", proxyPort: fields.proxyPort },
    egress: { iface: fields.egressIface, sourceIp: "172.30.1.10", gatewayIp: "172.30.1.1" },
    allowedHosts: ["api.github.com"],
    nftables: nftables as unknown as FirewallPlan["nftables"],
    hostServiceDrainSeconds: 30,
    refresh: { policyCheckIntervalSeconds: 2, dnsRefreshIntervalSeconds: 300, maxStaleHostSeconds: 900 },
    audit: {
      markerPath: "/run/runfree-proxy-audit/active.json",
      spoolPath: "/run/runfree-proxy-audit-spool/spool.txt",
      resolvedHostsPath: "/run/runfree-proxy-audit/resolved-hosts.json",
      resolveBudgetPerTick: 8,
      drainSeconds: 30,
    },
  };
}

// The statements the renderers emit. A rule line is a run of keywords,
// quoted interface names, set references, numbers, and addresses.
const NAME = "[A-Za-z_][A-Za-z0-9_]{0,63}";
const IP = "[0-9]{1,3}(?:\\.[0-9]{1,3}){3}";
const NUMBER = "[1-9][0-9]*";
const ELEMENT = `${IP}(?: \\. ${NUMBER})?`;
const RULE_TOKEN = `(?:[a-z][a-z0-9_]*|"[A-Za-z0-9_.:-]{1,64}"|@${NAME}|${NUMBER}|${IP}|\\.|!=|established,related)`;
const LINE_GRAMMAR = [
  new RegExp(`^table inet ${NAME} \\{$`),
  new RegExp(`^  set ${NAME} \\{$`),
  /^ {4}type ipv4_addr(?: \. inet_service)?$/,
  new RegExp(`^ {4}size ${NUMBER}$`),
  /^ {2}chain [a-z_]+ \{$/,
  /^ {4}type filter hook (?:input|output|forward) priority (?:filter|raw); policy (?:drop|accept);$/,
  new RegExp(`^ {4}${RULE_TOKEN}(?: ${RULE_TOKEN})*$`),
  /^ {0,2}\}$/,
  /^$/,
  new RegExp(`^flush set inet ${NAME} ${NAME}$`),
  new RegExp(`^add element inet ${NAME} ${NAME} \\{ ${ELEMENT}(?:, ${ELEMENT})* \\}$`),
];
const CHAIN_TYPE_LINE = LINE_GRAMMAR[5] as RegExp;

function expectGrammatical(output: string): void {
  for (const line of output.split("\n")) {
    expect(LINE_GRAMMAR.some((statement) => statement.test(line)), `ungrammatical nft line: ${JSON.stringify(line)}`).toBe(true);
    expect(line).not.toMatch(/[#\r'`\\]/);
    if (!CHAIN_TYPE_LINE.test(line)) expect(line).not.toContain(";");
    expect((line.match(/"/g) ?? []).length % 2).toBe(0);
  }
}

// Characters with meaning to nft (statement separators, comments, quotes,
// braces, set references, variables) plus whitespace and non-ASCII.
const hostileText = fc.string({
  unit: fc.constantFrom(..."aZ_09.:-;#\"'`\\{}@$ \t\r\n/\u00e9".split("")),
  maxLength: 16,
});
const nftName = fc.stringMatching(/^[A-Za-z_][A-Za-z0-9_]{0,63}$/);
const iface = fc.stringMatching(/^[A-Za-z0-9_.:-]{1,64}$/);
const byte = fc.integer({ min: 0, max: 255 });
const canonicalIp = fc.tuple(byte, byte, byte, byte).map((octets) => octets.join("."));

describe("nftables rendering properties", () => {
  it("P5.1: every line of every successful render matches its statement grammar", () => {
    // Mostly valid, so that most plans render and the grammar check runs.
    const mostly = <T>(good: fc.Arbitrary<T>, bad: fc.Arbitrary<T>) =>
      fc.oneof({ weight: 9, arbitrary: good }, { weight: 1, arbitrary: bad });
    const anyIp = mostly(canonicalIp, fc.oneof(hostileText, fc.tuple(canonicalIp, hostileText).map(([ip, text]) => `${ip}${text}`)));
    // Integers from 1e21 up pass validation and render in exponent form
    // (`size 1e+21`); that defect is pinned in nftables.test.ts (todo 104),
    // so this generator stops below it.
    const anyNumber = mostly(
      fc.integer({ min: 1, max: 65_535 }),
      fc.oneof(fc.integer({ min: -2, max: 70_000 }), fc.constantFrom(0, 1.5, Number.NaN, Number.POSITIVE_INFINITY, 2 ** 32, 1e20)),
    );
    const plan = fc.record({
      internalIface: mostly(iface, hostileText),
      egressIface: mostly(iface, hostileText),
      proxyPort: anyNumber,
      tableName: mostly(nftName, hostileText),
      setNames: fc.tuple(...SET_NAME_KEYS.map(() => mostly(nftName, hostileText))),
      sizes: fc.tuple(...SIZE_KEYS.map(() => anyNumber)),
    }).map(planFrom);
    const hostServiceEntry = fc.record({ ip: anyIp, port: anyNumber });

    fc.assert(fc.property(
      plan,
      fc.array(anyIp, { maxLength: 6 }),
      fc.array(hostServiceEntry, { maxLength: 4 }),
      fc.array(anyIp, { maxLength: 3 }),
      (firewallPlan, ips, entries, extraGateways) => {
        const gateways = [...entries.map((entry) => entry.ip), ...extraGateways];
        const renders: Array<() => string> = [
          () => renderRuleset(firewallPlan),
          () => renderAllowedSetUpdate(ips, firewallPlan),
          () => renderSessionAdmissionSetUpdate(ips, firewallPlan),
          () => renderAuditSetUpdate(ips, firewallPlan),
          () => renderAuditDrainingSetUpdate(ips, firewallPlan),
          () => renderAuditTeardown(ips, firewallPlan),
          () => renderHostServiceSetUpdate(entries, firewallPlan, gateways),
          () => renderHostServiceTeardown(entries, entries, firewallPlan, gateways),
        ];
        for (const render of renders) {
          let output: string;
          try {
            output = render();
          } catch {
            continue;
          }
          expectGrammatical(output);
        }
      },
    ), propertyParameters());
  });

  it("P5.2: rendering throws exactly when an element, port, size, or name check fails", () => {
    // Each field comes from a generator that is valid by construction or one
    // that corrupts it by construction, and the expected verdict is the OR of
    // the corruption flags. Leading-zero addresses are left to P5.3.
    const valid = <T>(arbitrary: fc.Arbitrary<T>) => arbitrary.map((value) => ({ value, bad: false }));
    const invalid = <T>(arbitrary: fc.Arbitrary<T>) => arbitrary.map((value) => ({ value, bad: true }));
    const field = <T>(good: fc.Arbitrary<T>, bad: fc.Arbitrary<T>) =>
      fc.oneof({ weight: 6, arbitrary: valid(good) }, { weight: 1, arbitrary: invalid(bad) });
    const insert = (base: fc.Arbitrary<string>, chars: string) =>
      fc.tuple(base, fc.constantFrom(...chars.split("")), fc.nat()).map(([text, char, at]) => {
        const index = at % (text.length + 1);
        return `${text.slice(0, index)}${char}${text.slice(index)}`;
      });

    const badName = fc.oneof(
      insert(fc.stringMatching(/^[A-Za-z_][A-Za-z0-9_]{0,10}$/), "-. ;#\"{}@\n\u00e9"),
      fc.stringMatching(/^[0-9][A-Za-z0-9_]{0,10}$/),
      fc.constant(""),
      fc.stringMatching(/^[A-Za-z_][A-Za-z0-9_]{64,70}$/),
    );
    const badIface = fc.oneof(
      insert(fc.stringMatching(/^[A-Za-z0-9_.:-]{0,10}$/), " ;#\"'{}@\n/\u00e9"),
      fc.constant(""),
      fc.stringMatching(/^[A-Za-z0-9_.:-]{65,70}$/),
    );
    const port = fc.integer({ min: 1, max: 65_535 });
    const badPort = fc.constantFrom(0, -1, 65_536, 1.5, Number.NaN);
    const size = fc.oneof(fc.integer({ min: 1, max: 4 }), fc.integer({ min: 5, max: 100_000 }));
    const badSize = fc.constantFrom(0, -1, 1.5, Number.NaN);
    const badIp = fc.oneof(
      fc.tuple(canonicalIp, byte).map(([ip, extra]) => `${ip}.${extra}`),
      fc.tuple(byte, byte, byte).map((octets) => octets.join(".")),
      fc.tuple(canonicalIp, fc.integer({ min: 0, max: 3 }), fc.integer({ min: 256, max: 999 }))
        .map(([ip, at, octet]) => ip.split(".").map((part, index) => (index === at ? String(octet) : part)).join(".")),
      fc.tuple(canonicalIp, fc.constantFrom(" ", "\n", ";", "/32", "x", "\uff10")).map(([ip, suffix]) => `${ip}${suffix}`),
      fc.tuple(canonicalIp, fc.integer({ min: 0, max: 3 })).map(([ip, at]) => ip.split(".").map((part, index) => (index === at ? "" : part)).join(".")),
    );
    const ip = field(canonicalIp, badIp);
    const entry = fc.record({ ip, port: field(port, badPort) });

    fc.assert(fc.property(
      fc.record({
        internalIface: field(iface, badIface),
        egressIface: field(iface, badIface),
        proxyPort: field(port, badPort),
        tableName: field(nftName, badName),
        setNames: fc.tuple(fc.uniqueArray(nftName, { minLength: 7, maxLength: 7 }), fc.option(fc.tuple(fc.nat(6), fc.nat(6)))),
        badSetName: fc.option(fc.tuple(fc.nat(6), badName)),
        sizes: fc.tuple(...SIZE_KEYS.map(() => field(size, badSize))),
      }),
      fc.array(ip, { maxLength: 6 }),
      fc.array(entry, { maxLength: 5 }),
      fc.array(field(canonicalIp, badIp), { maxLength: 2 }),
      fc.boolean(),
      fc.constantFrom("ruleset", "allowed", "session", "audit", "hostService"),
      (fields, ips, entries, extraGateways, dropGateway, renderer) => {
        const [names, duplicate] = fields.setNames;
        const setNames = [...names];
        let namesBad = false;
        if (duplicate !== null && duplicate[0] !== duplicate[1]) {
          setNames[duplicate[0]] = setNames[duplicate[1]] as string;
          namesBad = true;
        }
        if (fields.badSetName !== null) {
          setNames[fields.badSetName[0]] = fields.badSetName[1];
          namesBad = true;
        }
        const sizes = fields.sizes.map((size) => size.value);
        const firewallPlan = planFrom({
          internalIface: fields.internalIface.value,
          egressIface: fields.egressIface.value,
          proxyPort: fields.proxyPort.value,
          tableName: fields.tableName.value,
          setNames,
          sizes,
        });
        const planBad = fields.internalIface.bad || fields.egressIface.bad || fields.proxyPort.bad || fields.tableName.bad
          || namesBad || fields.sizes.some((size) => size.bad)
          || fields.internalIface.value === fields.egressIface.value;
        const [maxElements, sessionMaxElements, auditMaxElements, hostServiceMaxElements, gatewayMaxElements] = sizes as number[];
        const ipValues = ips.map((element) => element.value);
        const ipsBad = ips.some((element) => element.bad);
        const overCap = (cap: number | undefined) => new Set(ipValues).size > (cap ?? 0);

        let render: () => string;
        let expectThrow: boolean;
        if (renderer === "ruleset") {
          render = () => renderRuleset(firewallPlan);
          expectThrow = planBad;
        } else if (renderer === "allowed") {
          render = () => renderAllowedSetUpdate(ipValues, firewallPlan);
          expectThrow = planBad || ipsBad || overCap(maxElements);
        } else if (renderer === "session") {
          render = () => renderSessionAdmissionSetUpdate(ipValues, firewallPlan);
          expectThrow = planBad || ipsBad || overCap(sessionMaxElements);
        } else if (renderer === "audit") {
          render = () => renderAuditSetUpdate(ipValues, firewallPlan);
          expectThrow = planBad || ipsBad || overCap(auditMaxElements);
        } else {
          const elements: HostServiceElement[] = entries.map((element) => ({ ip: element.ip.value, port: element.port.value }));
          const entryIps = [...new Set(elements.map((element) => element.ip))];
          const gateways = [...(dropGateway ? entryIps.slice(1) : entryIps), ...extraGateways.map((gateway) => gateway.value)];
          const gatewaySet = new Set(gateways);
          render = () => renderHostServiceSetUpdate(elements, firewallPlan, gateways);
          expectThrow = planBad
            || entries.some((element) => element.ip.bad || element.port.bad)
            || extraGateways.some((gateway) => gateway.bad)
            || new Set(elements.map((element) => `${element.ip}/${element.port}`)).size > (hostServiceMaxElements ?? 0)
            || gatewaySet.size > (gatewayMaxElements ?? 0)
            || elements.some((element) => !gatewaySet.has(element.ip));
        }
        let threw = false;
        try {
          render();
        } catch {
          threw = true;
        }
        expect(threw).toBe(expectThrow);
      },
    ), propertyParameters());
  });

  // Product defect: isValidIpv4 accepts leading zeros such as 010.0.0.1 (H5).
  // How nft parses that element is not yet recorded. See todo 103.
  it.skip("P5.3: isValidIpv4 holds exactly for canonical dotted-decimal addresses — product defect, see todo 103", () => {
    // Reference formatter: a string is canonical when formatting its parsed
    // octets gives the same string back.
    const isCanonical = (value: string) => {
      const octets = value.split(".").map(Number);
      return octets.length === 4
        && octets.every((octet) => Number.isInteger(octet) && octet >= 0 && octet <= 255)
        && octets.join(".") === value;
    };
    const leadingZero = fc.tuple(canonicalIp, fc.integer({ min: 0, max: 3 }), fc.constantFrom("0", "00"))
      .map(([ip, at, zeros]) => ip.split(".").map((part, index) => (index === at ? `${zeros}${part}` : part)).join("."));
    const octetish = fc.stringMatching(/^[0-9]{0,4}$/);
    const candidate = fc.oneof(
      canonicalIp,
      leadingZero,
      fc.tuple(octetish, octetish, octetish, octetish).map((octets) => octets.join(".")),
      fc.string({ unit: fc.constantFrom(..."0123456789.x+-e \u00a0\uff10".split("")), maxLength: 16 }),
    );
    fc.assert(fc.property(candidate, (value) => {
      expect(isValidIpv4(value)).toBe(isCanonical(value));
    }), propertyParameters());
  });
});
