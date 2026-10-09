import fc from "fast-check";
import { describe, expect, it } from "vitest";

import { propertyParameters } from "../../../tests/support/property.ts";
import { PolicyValidationError, normalizeHostname, normalizePathPrefix, validateNetworkPolicy } from "./network-policy.ts";

type Outcome = { ok: true; value: string } | { ok: false };

function outcome(normalize: (input: string) => string, input: string): Outcome {
  try {
    return { ok: true, value: normalize(input) };
  } catch {
    return { ok: false };
  }
}

function policyAccepted(raw: unknown): boolean {
  try {
    validateNetworkPolicy(raw);
    return true;
  } catch (error) {
    if (error instanceof PolicyValidationError) return false;
    throw error;
  }
}

// Inputs reach these functions from `.runfree/network-policy.json` and CLI
// arguments, so the generators mix well-formed hosts and prefixes with the
// decorations a user or a hostile project file could add.
const label = fc.oneof(
  fc.stringMatching(/^[a-z0-9](?:[a-z0-9-]{0,8}[a-z0-9])?$/),
  fc.stringMatching(/^[a-z][a-z0-9-]{58,64}$/),
);
const asciiHost = fc.oneof(
  { weight: 4, arbitrary: fc.array(label, { minLength: 2, maxLength: 5 }).map((labels) => labels.join(".")) },
  { weight: 1, arbitrary: fc.array(fc.stringMatching(/^[a-z]{55,63}$/), { minLength: 4, maxLength: 5 }).map((labels) => labels.join(".")) },
);
const whitespace = fc.constantFrom("", " ", "\t", "\n", "\u00a0", "\u2003", "\u3000", "\ufeff");
const decoration = fc.constantFrom(
  (host: string) => host,
  (host: string) => `${host}.`,
  (host: string) => `${host}:443`,
  (host: string) => `https://${host}`,
  (host: string) => `*.${host}`,
  (host: string) => host.replace(".", ".."),
  (host: string) => `${host}/path`,
  (host: string) => host.split(".")[0] ?? host,
);
const caseFlips = fc.infiniteStream(fc.boolean());

function flipAsciiCase(input: string, flips: fc.Stream<boolean>): string {
  const choices = flips.take(input.length)[Symbol.iterator]();
  return [...input].map((char) => (/[a-z]/i.test(char) && choices.next().value
    ? (char === char.toLowerCase() ? char.toUpperCase() : char.toLowerCase())
    : char)).join("");
}

const decoratedHost = fc.tuple(asciiHost, decoration, whitespace, whitespace, caseFlips)
  .map(([host, decorate, before, after, flips]) => `${before}${flipAsciiCase(decorate(host), flips)}${after}`);
const noisyHost = fc.string({
  unit: fc.constantFrom(..."abkz09-._:/*?# \t\u00a0\u212a\u0130\u0131\uff0e\u0430K".split("")),
  maxLength: 40,
});
const hostInput = fc.oneof({ weight: 3, arbitrary: decoratedHost }, { weight: 1, arbitrary: noisyHost });

const pathPrefixInput = fc.oneof(
  fc.string({ unit: fc.constantFrom(..."/a.Z9%?#:* \t\u00a0\0".split("")), maxLength: 24 }),
  fc.tuple(whitespace, fc.stringMatching(/^\/[a-z0-9/._-]{0,20}$/), whitespace).map(([before, path, after]) => `${before}${path}${after}`),
  fc.stringMatching(/^[a-zA-Z][a-zA-Z0-9+.-]{0,6}:\/\/[a-z./]{0,12}$/),
);

// Lookalikes a typed or pasted hostname could carry. Today only the Kelvin
// sign (U+212A) lowercases into [a-z0-9.-]; every other code point outside
// ASCII is refused by the label check.
const NON_ASCII_SPELLINGS: Readonly<Record<string, readonly string[]>> = {
  k: ["\u212a"],
  i: ["\u0130", "\u0131"],
  s: ["\u017f"],
  a: ["\u0430", "\u00e0"],
  o: ["\u043e", "\u00f6"],
  ".": ["\uff0e", "\u3002"],
  "-": ["\u2010", "\u2212"],
  "0": ["\uff10"],
};
const nonAsciiSpelling = fc.tuple(asciiHost, caseFlips, fc.infiniteStream(fc.nat(2)))
  .map(([host, flips, picks]) => {
    const ascii = flipAsciiCase(host, flips);
    const choices = picks.take(ascii.length)[Symbol.iterator]();
    const variant = [...ascii].map((char) => {
      const options = NON_ASCII_SPELLINGS[char.toLowerCase()];
      const pick = choices.next().value ?? 0;
      return options !== undefined && pick < options.length ? (options[pick] ?? char) : char;
    }).join("");
    return { ascii, variant };
  })
  .filter(({ ascii, variant }) => ascii !== variant);

const HOSTNAME_RE = /^[a-z0-9.-]{1,253}$/;
const LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

describe("network policy normalization properties", () => {
  it("P4.1: normalizing twice gives the same result as normalizing once", () => {
    fc.assert(fc.property(hostInput, pathPrefixInput, (host, pathPrefix) => {
      const hostOnce = outcome(normalizeHostname, host);
      if (hostOnce.ok) expect(normalizeHostname(hostOnce.value)).toBe(hostOnce.value);
      const prefixOnce = outcome(normalizePathPrefix, pathPrefix);
      if (prefixOnce.ok) expect(normalizePathPrefix(prefixOnce.value)).toBe(prefixOnce.value);
    }), propertyParameters());
  });

  it("P4.2: every normalized hostname is lowercase ASCII with only valid, non-empty labels", () => {
    fc.assert(fc.property(hostInput, (input) => {
      const result = outcome(normalizeHostname, input);
      if (!result.ok) return;
      expect(result.value).toMatch(HOSTNAME_RE);
      for (const hostLabel of result.value.split(".")) expect(hostLabel).toMatch(LABEL_RE);
    }), propertyParameters());
  });

  it("P4.3: stored-policy validation accepts a host or prefix exactly when it equals its own normalization", () => {
    const reserved = (value: string) => value.toLowerCase().includes("runfree.internal");
    fc.assert(fc.property(hostInput.filter((host) => !reserved(host)), pathPrefixInput, (host, pathPrefix) => {
      const hostResult = outcome(normalizeHostname, host);
      expect(policyAccepted({ hosts: [host] })).toBe(hostResult.ok && hostResult.value === host);

      const prefixResult = outcome(normalizePathPrefix, pathPrefix);
      expect(policyAccepted({
        hosts: ["api.example.com"],
        requests: { "api.example.com": { pathPrefixes: [pathPrefix] } },
      })).toBe(prefixResult.ok && prefixResult.value === pathPrefix);
    }), propertyParameters());
  });

  it("P4.4: a non-ASCII spelling either throws or normalizes like its ASCII spelling", () => {
    fc.assert(fc.property(nonAsciiSpelling, ({ ascii, variant }) => {
      const result = outcome(normalizeHostname, variant);
      if (result.ok) expect(result).toEqual(outcome(normalizeHostname, ascii));
    }), propertyParameters());
  });

  it("P4.4 decision: the Kelvin sign folds to k", () => {
    expect(normalizeHostname("\u212aube.example.com")).toBe("kube.example.com");
  });

  // Not in the spec's P4.1-P4.4: P4.1 and P4.3 cannot see a dropped
  // toLowerCase(), because the label check then refuses uppercase input and
  // both sides of each relation throw. CLI callers rely on case folding.
  it("P4.5: ASCII case does not change the normalization outcome", () => {
    fc.assert(fc.property(hostInput, (input) => {
      const asciiLowercase = input.replace(/[A-Z]/g, (char) => char.toLowerCase());
      expect(outcome(normalizeHostname, input)).toEqual(outcome(normalizeHostname, asciiLowercase));
    }), propertyParameters());
  });
});
