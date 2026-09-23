import dns from "node:dns/promises";

export async function resolveIpv4(host: string, timeoutMs = 5_000): Promise<string[]> {
  let timeout: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      dns.resolve4(host),
      new Promise<never>((_, reject) => {
        timeout = setTimeout(() => reject(new Error(`DNS A lookup timed out for ${host}`)), timeoutMs);
      }),
    ]);
  } finally {
    if (timeout) clearTimeout(timeout);
  }
}
