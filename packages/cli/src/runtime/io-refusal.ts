// Marks an error a RuntimeIO wrapper threw *before* delegating a call, so a
// caller that must reclaim what a subprocess may have created can tell "never
// spawned" from "spawned, then refused". Anything unmarked is treated as
// possibly spawned, which is the conservative direction: the caller runs its
// full reclaim instead of assuming nothing exists.

const refusedBeforeSpawn = new WeakSet<object>();

/** Runs a wrapper's pre-delegation check; an error it throws is marked. */
export function checkBeforeSpawn<T>(check: () => T): T {
  try {
    return check();
  } catch (error) {
    if (error !== null && typeof error === "object") refusedBeforeSpawn.add(error);
    throw error;
  }
}

export function wasRefusedBeforeSpawn(error: unknown): boolean {
  return error !== null && typeof error === "object" && refusedBeforeSpawn.has(error);
}
