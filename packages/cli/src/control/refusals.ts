// Typed refusals shared by the control layer and its callers.
//
// A refusal that callers must recognize is a class, never a message substring:
// the pre-`up` "policy saved, activation pending" outcome used to hinge on
// `message.includes(...)` against one of two different strings, so the other
// string escaped as a stack trace after the policy had already been written.

import { CliError } from "../errors.ts";
import type { ControlApprovalRead } from "./approval-read.ts";

/**
 * The approved control set is incomplete (no approved project/local network
 * layer, or no runtime-isolation approval), so no effective policy generation
 * can be compiled yet. Raised by both compile entrypoints; recognized by the
 * post-mutation activation as "saved; applies when the runtime starts".
 */
export class ControlsNotApprovedError extends CliError {
  readonly code = "controls-not-approved" as const;

  // A refusal, so the CLI renders it as one (message and exit status, no
  // stack) when a typed mutation path lets it escape.
  constructor(message: string) {
    super(message, 1);
    this.name = "ControlsNotApprovedError";
  }
}

export function isControlsNotApprovedError(error: unknown): error is ControlsNotApprovedError {
  return error instanceof ControlsNotApprovedError
    || (error instanceof Error && (error as { code?: unknown }).code === "controls-not-approved");
}

/**
 * The saved approvals record exists but carries no authority for this checkout:
 * a binding mismatch, a record predating the current schema, or an unreadable
 * one. Callers route on `read.kind`, never on the message text.
 *
 * The type-only import above keeps this file free of a runtime cycle with
 * `approval-read.ts`, which raises this class.
 */
export class ControlApprovalUnusableError extends CliError {
  readonly code = "control-approval-unusable" as const;
  readonly read: ControlApprovalRead;

  constructor(message: string, read: ControlApprovalRead) {
    super(message, 1);
    this.name = "ControlApprovalUnusableError";
    this.read = read;
  }
}

export function isControlApprovalUnusableError(error: unknown): error is ControlApprovalUnusableError {
  return error instanceof ControlApprovalUnusableError
    || (error instanceof Error && (error as { code?: unknown }).code === "control-approval-unusable");
}
