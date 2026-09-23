import path from "node:path";

import { builtinAgent, type BuiltinAgentDescriptor } from "../agents.ts";
import { createSessionLaunchTarget, SESSION_ENTRY_PATH, type SessionLaunchTarget } from "./session-launch.ts";

const RESUME_CONVERSATION_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * Wraps a validated inner launch in the image's session entry.
 *
 * Every per-session launch kind (shell, built-in agent, resume) mints through
 * one of the three builders below, and each of them passes here, so the
 * container's first process is always the entry and the agent is always its
 * argv. The entry waits for the proxy to report the session active before it
 * execs the inner launch; without it the agent's first request lands in the
 * pre-activation window and is answered 403 (activation-gate design, 2026-09-03).
 */
function sessionEntryLaunchTarget(inner: Readonly<{ path: string; args: readonly string[] }>): SessionLaunchTarget {
  return createSessionLaunchTarget({
    path: SESSION_ENTRY_PATH,
    args: [inner.path, ...inner.args],
    interactive: true,
    tty: true,
  });
}

function requireExactBuiltin(input: Readonly<{ agentId: string; configuredCommand: string }>): BuiltinAgentDescriptor {
  const descriptor = builtinAgent(input.agentId);
  if (!descriptor) throw new Error(`unknown built-in session agent: ${input.agentId || "<empty>"}`);
  if (input.configuredCommand !== descriptor.defaultCommand) {
    // The refusal is the feature (cutover decision D-3, 2026-08-17): a session
    // container's first process is host-minted validated argv, and a
    // config-authored command is project-controlled input that must never be
    // split or interpreted into that authority. Name everything the operator
    // needs to act: the command found, the one required, and where to change it.
    throw new Error(
      `per-session launch supports only the exact ${descriptor.id} built-in command. This project configures `
      + `"${input.configuredCommand}", but only "${descriptor.defaultCommand}" is representable as validated launch `
      + `argv. Remove agents.${descriptor.id}.command from .runfree/runfree.json (or set it to that default) to `
      + `launch ${descriptor.label}; \`runfree shell\` remains available for custom commands.`,
    );
  }
  return descriptor;
}

/**
 * The agent image's interactive login shell as typed direct-launch authority.
 *
 * `runfree shell` becomes an ordinary per-session launch at the cutover: same
 * container, mounts, environment, admission sequence, and revocation as an
 * agent session, with the login shell as the first project-controlled process.
 * The path is the image's fixed zsh (the agent user's login shell in the
 * Dockerfile), owned here rather than read from anywhere project-controlled.
 * Deliberately independent of the project's configured agent command: the
 * shell is the escape hatch the custom-command refusal points at, so a custom
 * command must never be able to make it unlaunchable.
 */
export function createBuiltinSessionShellLaunchTarget(): SessionLaunchTarget {
  return sessionEntryLaunchTarget({ path: "/usr/bin/zsh", args: ["-il"] });
}

/**
 * Converts only an unchanged Runfree built-in command to typed direct-launch
 * authority. Arbitrary project commands remain shell syntax and must not be
 * split or interpreted for the per-session path.
 */
export function createBuiltinSessionLaunchTarget(input: Readonly<{
  agentId: string;
  configuredCommand: string;
}>): SessionLaunchTarget {
  const descriptor = requireExactBuiltin(input);
  return sessionEntryLaunchTarget(descriptor.directLaunch);
}

/**
 * Mints the typed per-session launch target for resuming an interrupted
 * conversation: the recovery spec's descriptor-owned resume argv, launched
 * directly as the session container's first project-controlled process.
 *
 * Only descriptor-owned argv is representable. A project `resumeCommand` is
 * shell syntax and stays on the shell-evaluated legacy path; it must never be
 * split or interpreted into direct-launch authority. The conversation id is
 * strict-format validated here as well as at the caller, because this is the
 * last host-owned step before the value becomes container argv.
 */
export function createBuiltinSessionResumeLaunchTarget(input: Readonly<{
  agentId: string;
  configuredCommand: string;
  conversationId?: string;
}>): SessionLaunchTarget {
  const descriptor = requireExactBuiltin(input);
  const resume = descriptor.resume;
  if (!resume) throw new Error(`resume is not supported for built-in session agent ${descriptor.id}`);
  let argv: readonly string[];
  if (input.conversationId !== undefined) {
    if (!RESUME_CONVERSATION_ID_PATTERN.test(input.conversationId)) {
      throw new Error(`resume conversation id is not a valid conversation UUID`);
    }
    if (!resume.exactArgvPrefix) {
      throw new Error(`built-in session agent ${descriptor.id} does not support exact conversation resume`);
    }
    argv = [...resume.exactArgvPrefix, input.conversationId.toLowerCase()];
  } else {
    if (!resume.pickerArgv) {
      throw new Error(`built-in session agent ${descriptor.id} does not support picker resume`);
    }
    argv = [...resume.pickerArgv];
  }
  if (argv[0] !== path.posix.basename(descriptor.directLaunch.path)) {
    throw new Error(`built-in session agent ${descriptor.id} resume argv does not name its direct-launch tool`);
  }
  return sessionEntryLaunchTarget({ path: descriptor.directLaunch.path, args: argv.slice(1) });
}
