import { CONTAINER_ROLE_LABEL } from "./container-inventory.ts";
import { PROJECT_ID_LABEL } from "./constants.ts";
import { RuntimeObservationError } from "./observation-failure.ts";
import type { DockerContainerInspect, RuntimeIO } from "./types.ts";

export type ExactProxySubject = Readonly<{
  proxyId: string;
  projectId: string;
  composeProject: string;
}>;

/** A successful inventory proves absence; an unsuccessful inspect never does. */
export function observeExactProxy(input: ExactProxySubject & {
  io: Pick<RuntimeIO, "capture">;
  env?: NodeJS.ProcessEnv;
  assertAuthority(): void;
}): DockerContainerInspect | undefined {
  const fail = (kind: "observation-unavailable" | "identity-contradiction", observation: string): never => {
    throw new RuntimeObservationError({ kind, subject: "proxy", expectedIdentity: input.proxyId,
      phase: "proxy-inventory", observation });
  };
  if (!/^[a-f0-9]{64}$/u.test(input.proxyId)) fail("identity-contradiction", "exact proxy identity is required");
  input.assertAuthority();
  const inventory = input.io.capture("docker", ["ps", "--all", "--quiet", "--no-trunc", "--filter", `id=${input.proxyId}`],
    { env: input.env, timeout: 1000, maxBuffer: 8192 });
  input.assertAuthority();
  if (inventory.status !== 0 || inventory.stderr.trim()) fail("observation-unavailable", "exact proxy inventory is unavailable");
  const ids = inventory.stdout.trim().split(/\s+/u).filter(Boolean);
  if (!ids.length) return undefined;
  if (ids.length !== 1 || ids[0] !== input.proxyId) fail("identity-contradiction", "exact proxy inventory returned another identity");
  const result = input.io.capture("docker", ["container", "inspect", input.proxyId],
    { env: input.env, timeout: 1000, maxBuffer: 1024 * 1024 });
  input.assertAuthority();
  if (result.status !== 0 || result.stderr.trim()) fail("observation-unavailable", "exact proxy inspection is unavailable");
  let parsed: DockerContainerInspect[];
  try { parsed = JSON.parse(result.stdout) as DockerContainerInspect[]; }
  catch { return fail("observation-unavailable", "exact proxy inspection is malformed"); }
  if (!Array.isArray(parsed) || parsed.length !== 1 || parsed[0]?.Id !== input.proxyId) {
    return fail("identity-contradiction", "proxy inspection does not name the expected container");
  }
  const proxy = parsed[0];
  const labels = proxy.Config?.Labels ?? {};
  if (labels[PROJECT_ID_LABEL] !== input.projectId
    || labels[CONTAINER_ROLE_LABEL] !== "proxy"
    || labels["com.docker.compose.project"] !== input.composeProject
    || labels["com.docker.compose.service"] !== "proxy") {
    return fail("identity-contradiction", "proxy ownership does not match the recorded project");
  }
  return proxy;
}

/** Caller supplies durable ownership and a current fence, never just a service name. */
export function containExactOwnedProxy(input: Parameters<typeof observeExactProxy>[0]): void {
  const proxy = observeExactProxy(input);
  if (!proxy || proxy.State?.Running === false) return;
  input.assertAuthority();
  const stopped = input.io.capture("docker", ["stop", "--time", "5", input.proxyId],
    { env: input.env, timeout: 7000, maxBuffer: 8192 });
  input.assertAuthority();
  const observed = observeExactProxy(input);
  if (stopped.status !== 0 || observed?.State?.Running !== false && observed !== undefined) {
    throw new RuntimeObservationError({ kind: "partial-convergence", subject: "proxy", expectedIdentity: input.proxyId,
      phase: "proxy-containment", observation: "proxy safety is unconfirmed; inspect this exact container on the host before recovery" });
  }
}
