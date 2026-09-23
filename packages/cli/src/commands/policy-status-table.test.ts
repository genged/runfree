import { describe, expect, test } from "vitest";

import { formatPolicyStatusTable } from "./policy.ts";

describe("formatPolicyStatusTable", () => {
  test("aligns source, digest, and state columns by content width", () => {
    const table = formatPolicyStatusTable([
      { label: "project", desiredDigest: "sha256:0123456789abcdef0123456789abcdef", approvedDigest: undefined, state: "unapproved" },
      { label: "checkout-local", desiredDigest: undefined, approvedDigest: undefined, state: "approved" },
      { label: "runtime", desiredDigest: "sha256:abcdefabcdefabcdefabcdefabcdef", approvedDigest: "sha256:abcdefabcdefabcdefabcdefabcdef", state: "active" },
    ]);
    expect(table).toBe([
      "SOURCE          DESIRED                 APPROVED                STATE",
      "project         sha256:01234567…abcdef  none                    unapproved",
      "checkout-local  none                    none                    approved",
      "runtime         sha256:abcdefab…abcdef  sha256:abcdefab…abcdef  active",
    ].join("\n"));
  });

  test("never truncates a label wider than the old fixed column", () => {
    const table = formatPolicyStatusTable([
      { label: "a-very-long-source-label", desiredDigest: undefined, approvedDigest: undefined, state: "approved" },
    ]);
    expect(table.split("\n")[1]).toMatch(/^a-very-long-source-label  none/);
  });
});
