import { expect, test } from "vitest";

import { CliError } from "../errors.ts";
import { ControlApprovalUnusableError, ControlsNotApprovedError, isControlApprovalUnusableError, isControlsNotApprovedError } from "./refusals.ts";

// A typed mutation path that lets one of these escape must render it as the
// refusal it is (message and exit status), not as an unexpected error with a
// stack trace, so both are CLI errors; the code-based recognizers still hold.
test("control refusals are CLI errors with exit status 1 and their stable codes", () => {
  const notApproved = new ControlsNotApprovedError("approvals are required");
  expect(notApproved).toBeInstanceOf(CliError);
  expect(notApproved.status).toBe(1);
  expect(notApproved.name).toBe("ControlsNotApprovedError");
  expect(isControlsNotApprovedError(notApproved)).toBe(true);

  const unusable = new ControlApprovalUnusableError("binding mismatch", { kind: "binding-mismatch" } as never);
  expect(unusable).toBeInstanceOf(CliError);
  expect(unusable.status).toBe(1);
  expect(isControlApprovalUnusableError(unusable)).toBe(true);
  expect(isControlsNotApprovedError(unusable)).toBe(false);
});
