let observerDockerCalls = 0;
export function countObserverDockerCall(): void { observerDockerCalls += 1; }

/** Phase names contain no credential output. Counts cover this worker's
 * synchronous Docker helpers, not Docker calls inside the launched CLI.
 */
export function startLivePhase(phase: string): () => void {
  const started = performance.now();
  const calls = observerDockerCalls;
  let finished = false;
  return () => {
    if (finished) return;
    finished = true;
    process.stderr.write(`[runtime-live timing] ${JSON.stringify({
      phase, ms: Math.round(performance.now() - started), observerDockerCalls: observerDockerCalls - calls,
    })}\n`);
  };
}
