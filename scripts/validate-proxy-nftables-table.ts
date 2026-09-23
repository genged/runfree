import fs from "node:fs";

import { validateProxyNftablesTableJson } from "../packages/cli/src/proxy-nftables-proof.ts";

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    console.error(`missing required environment variable: ${name}`);
    process.exit(2);
  }
  return value;
}

const issues = validateProxyNftablesTableJson({
  rawJson: fs.readFileSync(0, "utf8"),
  internalIface: requiredEnv("RUNFREE_PROXY_INTERNAL_IFACE"),
  egressIface: requiredEnv("RUNFREE_PROXY_EGRESS_IFACE"),
  serverUid: process.env.RUNFREE_PROXY_SERVER_UID,
});

if (issues.length > 0) {
  console.error(issues.map((issue) => `- ${issue}`).join("\n"));
  process.exit(1);
}
