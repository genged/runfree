import { checkBeforeSpawn } from "./io-refusal.ts";
import type { RuntimeIO } from "./types.ts";
import { readControlPlaneRebindTransaction } from "./control-plane-rebind.ts";
import { RebindRecoveryExhaustedError } from "./control-plane-rebind-recovery.ts";
import type { SessionContainerProjectIdentity } from "./session-containers.ts";

/** Every blocking Docker operation spends the same persisted allowance. */
export function withRebindBudgetIO(io: RuntimeIO, stateDir: string, project: SessionContainerProjectIdentity, assertAuthority: () => void, explicitRetry = false): RuntimeIO {
  const priorAllowance = readControlPlaneRebindTransaction(stateDir, project)?.recovery?.allowance.number;
  const observationDeadline = performance.now() + 120_000;
  const assertMutationAllowance = (): void => {
    assertAuthority();
    const transaction = readControlPlaneRebindTransaction(stateDir, project);
    if (explicitRetry && transaction?.recovery?.allowance.number === priorAllowance) {
      throw new Error("proxy recovery mutations require the renewed allowance to be durable first");
    }
  };
  const remaining = (): number => {
    assertAuthority();
    const transaction = readControlPlaneRebindTransaction(stateDir, project);
    if (!transaction?.recovery) return 1000;
    const { allowance } = transaction.recovery;
    if (explicitRetry && allowance.number === priorAllowance) {
      const remainingObservation = Math.floor(observationDeadline - performance.now());
      if (remainingObservation > 0) return remainingObservation;
      throw new RebindRecoveryExhaustedError(transaction.transactionId, transaction.phase);
    }
    const now = Date.now();
    const milliseconds = Date.parse(allowance.deadlineAt) - now;
    if (allowance.exhausted || milliseconds <= 0 || now < Date.parse(allowance.lastObservedAt)) {
      throw new RebindRecoveryExhaustedError(transaction.transactionId, transaction.phase);
    }
    return Math.floor(milliseconds);
  };
  return {
    ...io,
    capture(command, args, options = {}) {
      // Captured mutators spend the same durable allowance as run(). Exact
      // defensive stop remains available for proved containment after expiry.
      if (command === "docker" && (["create", "run", "start", "restart", "rm", "cp", "compose"].includes(args[0])
        || args[0] === "container" && ["create", "start", "restart", "rm"].includes(args[1])
        || ["network", "volume"].includes(args[0]) && ["create", "connect", "disconnect", "rm"].includes(args[1]))) checkBeforeSpawn(assertMutationAllowance);
      const budget = checkBeforeSpawn(remaining);
      const result = io.capture(command, args, { ...options, timeout: Math.min(options.timeout ?? budget, budget) });
      remaining();
      return result;
    },
    run(command, args, options = {}) {
      checkBeforeSpawn(assertMutationAllowance);
      const budget = checkBeforeSpawn(remaining);
      const result = io.run(command, args, { ...options, timeout: Math.min(options.timeout ?? budget, budget) });
      remaining();
      return result;
    },
  };
}
