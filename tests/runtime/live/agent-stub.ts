// Shared project-image stub for live tranches that need a session to stay up.
//
// Extracted from the crash tranche when the attached-authority tranche arrived
// with the identical need, so the two cannot drift apart in what "the launched
// agent" means.

import fs from "node:fs";
import path from "node:path";

import type { LiveFixture } from "./fixture.ts";

/**
 * Replaces the launched agent binary with one that stays up.
 *
 * The driver launches the exact built-in command — `/usr/local/bin/claude` with
 * fixed arguments — and refuses anything else, so the only way to influence what
 * runs inside the session is the project image. The real CLI has no terminal
 * here and exits at once, which the first live attempt at the attached case
 * proved: activation's narrow re-inspect found the container already stopped and
 * failed with "session container is not in exact running state", so the session
 * never reached attached and there was no window to crash in.
 *
 * What runs inside the container is not what these tranches prove. Their
 * subject is the host lifecycle — records, authority, consumers, recovery — and
 * every one of those assertions is about state outside the container. A process
 * that stays up is the honest stand-in for the agent someone is actually typing
 * into, and it makes the earlier crash points more faithful too: a container
 * that survives its own start is the residue a real crash leaves.
 *
 * `exec sleep` rather than a wrapper that forwards arguments: the built-in
 * arguments are meaningless to it, and an argument-forwarding stub would exit
 * exactly as the real binary does.
 *
 * One argument *is* inspected: `--resume`. The crash tranche's resume case
 * needs the resumed foreground process to end on its own so the launch can
 * complete and consume its evidence, while every other case needs the launched
 * agent to stay up long enough to act against. The stub branches on the typed
 * resume argv the driver launches it with, which also makes the branch itself
 * proof that the resume argv reached the container.
 */
export const RESUME_STUB_DIRECTORY = ".runfree-resume-stub";

export function resumeStub(directory = `/workspace/${RESUME_STUB_DIRECTORY}`): string {
  const quoted = `'${directory.replaceAll("'", "'\\''")}'`;
  return `for a in "$@"; do
  if [ "$a" = "--resume" ]; then
    dir=${quoted}
    mkdir -p "$dir"
    : > "$dir/ready"
    i=0
    while [ ! -f "$dir/release" ]; do
      i=$((i + 1))
      if [ "$i" -gt 1800 ]; then echo 'resume stub was not released' >&2; exit 124; fi
      sleep 0.1
    done
    exit 0
  fi
done`;
}

export function stageLongLivedAgentBinary(fixture: LiveFixture): void {
  const imageDir = path.join(fixture.projectRoot, ".runfree", "image");
  fs.writeFileSync(path.join(imageDir, "long-lived-claude.sh"), `#!/bin/sh\n${resumeStub()}\nexec sleep 3600\n`, { mode: 0o755 });
  fs.appendFileSync(path.join(imageDir, "Dockerfile"), [
    "", "USER root", "COPY long-lived-claude.sh /usr/local/bin/claude",
    "RUN chmod 0755 /usr/local/bin/claude", "USER agent", "",
  ].join("\n"));
}

/** Where the first-request stub records its first answer, relative to the project root. */
export const FIRST_REQUEST_RESULT_RELATIVE_PATH = path.join(".runfree-first-request", "result");
/** The allowlisted host the first-request stub sends its first request to. */
export const FIRST_REQUEST_HOST = "api.github.com";
const FIRST_REQUEST_CONTAINER_DIR = "/workspace/.runfree-first-request";
const FIRST_REQUEST_STUB_FILENAME = "first-request-claude.sh";

/**
 * The long-lived stub with one difference: it sends a real request the moment
 * it starts, records the answer, and only then stays up.
 *
 * This is the activation-gate design's positive live proof (T5): the agent's
 * first request is issued by the container's first project-controlled process
 * with no retry, so the recorded code is exactly what a client that connects
 * at start sees. Behind the session entry it lands after activation and is
 * answered by the allowlisted upstream; without the entry it lands in the
 * pre-activation window and is refused 403. The stub stays up afterwards
 * rather than exiting so the attached tranche keeps a session to act on.
 *
 * The result is written to the workspace bind mount, where the host reads it
 * without `docker exec`, and renamed into place so a partial write is never
 * read as an answer.
 */
const FIRST_REQUEST_STUB = `#!/bin/sh
# Live-fixture Claude stand-in. Not a production artifact.
${resumeStub()}
dir="${FIRST_REQUEST_CONTAINER_DIR}"
mkdir -p "$dir"
code="$(curl -sS --max-time 30 -o /dev/null -w '%{http_code}' "https://${FIRST_REQUEST_HOST}/" 2>"$dir/stderr.tmp" || true)"
mv "$dir/stderr.tmp" "$dir/stderr" 2>/dev/null
printf '%s\\n' "$code" > "$dir/result.tmp" && mv "$dir/result.tmp" "$dir/result"
exec sleep 3600
`;

export function stageFirstRequestAgentBinary(fixture: LiveFixture): void {
  const imageDir = path.join(fixture.projectRoot, ".runfree", "image");
  fs.writeFileSync(path.join(imageDir, FIRST_REQUEST_STUB_FILENAME), FIRST_REQUEST_STUB, { mode: 0o755 });
  fs.appendFileSync(
    path.join(imageDir, "Dockerfile"),
    [
      "",
      "USER root",
      `COPY ${FIRST_REQUEST_STUB_FILENAME} /usr/local/bin/claude`,
      "RUN chmod 0755 /usr/local/bin/claude",
      "USER agent",
      "",
    ].join("\n"),
  );
}

/** Where the early-sending entry stub records the proxy's raw answer, relative to the project root. */
export const EARLY_ENTRY_RESPONSE_RELATIVE_PATH = path.join(".runfree-early-entry", "response");
const EARLY_ENTRY_CONTAINER_DIR = "/workspace/.runfree-early-entry";
const EARLY_ENTRY_STUB_FILENAME = "early-session-entry.sh";

/**
 * A project image that replaces the base image's session entry with one that
 * sends at once (activation-gate design T6).
 *
 * A project image may replace the entry; what it loses is only the start
 * ordering, never authority. This stub is the strongest form of that: instead
 * of waiting for activation it sends an ordinary CONNECT to the proxy the
 * moment the container starts, keeps retrying while the firewall still drops
 * the session's packets, records the first answer the proxy gives byte for
 * byte, and then stays up so the running proof and revocation proceed as they
 * would for any session. The raw exchange is done with netcat rather than
 * curl so the guard's own 403 body — not a client's summary of it — is what
 * the test reads.
 */
const EARLY_ENTRY_STUB = `#!/bin/sh
# Live-fixture session-entry stand-in. Not a production artifact: sends before
# activation on purpose.
dir="${EARLY_ENTRY_CONTAINER_DIR}"
mkdir -p "$dir"
i=0
while [ "$i" -lt 240 ]; do
  printf 'CONNECT ${FIRST_REQUEST_HOST}:443 HTTP/1.1\\r\\nHost: ${FIRST_REQUEST_HOST}:443\\r\\nConnection: close\\r\\n\\r\\n' \\
    | nc -w 5 "$PROXY_IP" 8080 > "$dir/response.tmp" 2>/dev/null
  if [ -s "$dir/response.tmp" ]; then
    mv "$dir/response.tmp" "$dir/response"
    break
  fi
  i=$((i + 1))
  sleep 0.5
done
exec sleep 3600
`;

export function stageEarlySendingSessionEntry(fixture: LiveFixture): void {
  const imageDir = path.join(fixture.projectRoot, ".runfree", "image");
  fs.writeFileSync(path.join(imageDir, EARLY_ENTRY_STUB_FILENAME), EARLY_ENTRY_STUB, { mode: 0o755 });
  fs.appendFileSync(
    path.join(imageDir, "Dockerfile"),
    [
      "",
      "USER root",
      `COPY ${EARLY_ENTRY_STUB_FILENAME} /usr/local/libexec/runfree/session-entry`,
      "RUN chmod 0755 /usr/local/libexec/runfree/session-entry",
      "USER agent",
      "",
    ].join("\n"),
  );
}
