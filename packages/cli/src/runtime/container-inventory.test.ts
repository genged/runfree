import { describe, expect, test } from "vitest";

import {
  CONTAINER_LABEL_SCHEMA_VERSION,
  CONTAINER_ROLES,
  EPHEMERAL_HELPER_PURPOSES,
  INGRESS_PURPOSES,
  LIFECYCLE_OWNERS,
  composeProjectContainerFilters,
  ephemeralHelperLabelArguments,
  ingressForwarderLabelArguments,
  projectEphemeralHelperFilters,
  ephemeralHelperRunFilters,
  composeProjectNetworkFilters,
  composeProjectVolumeFilters,
  composeServiceContainerFilters,
  corroboratedComposeProjectContainerFilters,
  corroboratedComposeServiceContainerFilters,
  projectImageFilters,
  wholeProjectContainerFilters,
} from "./container-inventory.ts";

const PROJECT_ID = "0123456789ab";
const COMPOSE_PROJECT = "runfree-0123456789ab";

describe("container inventory filters", () => {
  test("each query shape produces exactly its intended filters", () => {
    expect(composeProjectContainerFilters(COMPOSE_PROJECT)).toEqual([
      "--filter",
      `label=com.docker.compose.project=${COMPOSE_PROJECT}`,
    ]);
    expect(composeServiceContainerFilters(COMPOSE_PROJECT, "proxy")).toEqual([
      "--filter",
      `label=com.docker.compose.project=${COMPOSE_PROJECT}`,
      "--filter",
      "label=com.docker.compose.service=proxy",
    ]);
    expect(corroboratedComposeProjectContainerFilters(PROJECT_ID, COMPOSE_PROJECT)).toEqual([
      "--filter",
      `label=io.runfree.project-id=${PROJECT_ID}`,
      "--filter",
      `label=com.docker.compose.project=${COMPOSE_PROJECT}`,
    ]);
    expect(corroboratedComposeServiceContainerFilters(PROJECT_ID, COMPOSE_PROJECT, "agent")).toEqual([
      "--filter",
      `label=io.runfree.project-id=${PROJECT_ID}`,
      "--filter",
      `label=com.docker.compose.project=${COMPOSE_PROJECT}`,
      "--filter",
      "label=com.docker.compose.service=agent",
    ]);
    expect(wholeProjectContainerFilters(PROJECT_ID)).toEqual([
      "--filter",
      `label=io.runfree.project-id=${PROJECT_ID}`,
    ]);
    expect(composeProjectNetworkFilters(COMPOSE_PROJECT)).toEqual([
      "--filter",
      `label=com.docker.compose.project=${COMPOSE_PROJECT}`,
    ]);
    expect(composeProjectVolumeFilters(COMPOSE_PROJECT)).toEqual([
      "--filter",
      `label=com.docker.compose.project=${COMPOSE_PROJECT}`,
    ]);
    expect(projectImageFilters(PROJECT_ID)).toEqual([
      "--filter",
      `label=io.runfree.project-id=${PROJECT_ID}`,
    ]);
  });

  test("accepts an env-overridden Compose project name while refusing unsafe values", () => {
    // RUNFREE_COMPOSE_PROJECT_NAME may replace the runfree-<hash> default with
    // any name Compose itself accepts.
    expect(composeProjectContainerFilters("my_custom-project1")).toEqual([
      "--filter",
      "label=com.docker.compose.project=my_custom-project1",
    ]);
  });

  test("refuses malformed identities before any filter exists", () => {
    // The values interpolate into `docker --filter` arguments, so anything
    // that is not the exact expected shape must fail closed here rather than
    // become a filter that selects the wrong set (or no set, silently).
    expect(() => wholeProjectContainerFilters("")).toThrow("exact project id");
    expect(() => wholeProjectContainerFilters("0123456789AB")).toThrow("exact project id");
    expect(() => wholeProjectContainerFilters("0123456789ab extra")).toThrow("exact project id");
    expect(() => composeProjectContainerFilters("")).toThrow("exact Compose project name");
    expect(() => composeProjectContainerFilters("has space")).toThrow("exact Compose project name");
    expect(() => composeProjectContainerFilters("Upper")).toThrow("exact Compose project name");
    expect(() => composeServiceContainerFilters(COMPOSE_PROJECT, "proxy extra"))
      .toThrow("exact Compose service name");
    expect(() => composeServiceContainerFilters(COMPOSE_PROJECT, ""))
      .toThrow("exact Compose service name");
    expect(() => corroboratedComposeServiceContainerFilters("nothex", COMPOSE_PROJECT, "agent"))
      .toThrow("exact project id");
  });

  test("the taxonomy vocabularies are closed and the schema version is stable", () => {
    // Extending these lists is a design decision, not an edit: ephemeral-helper
    // and the shared utility owner arrived with cutover decision D-5
    // (2026-08-17), the same generalization the approved ingress-forwarder
    // design records.
    // ingress-forwarder joined the roles with the facility build (2026-08-18);
    // ingress purposes are vnc | port | mcp-callback (callback via cutover
    // option C).
    expect([...CONTAINER_ROLES]).toEqual(["agent", "proxy", "mcp-callback-relay", "session-agent", "ephemeral-helper", "ingress-forwarder"]);
    expect([...LIFECYCLE_OWNERS]).toEqual(["compose", "session", "utility"]);
    expect(CONTAINER_LABEL_SCHEMA_VERSION).toBe("1");
    expect([...EPHEMERAL_HELPER_PURPOSES]).toEqual(["deny-probe", "dependency-prep", "trust-bundle"]);
    expect([...INGRESS_PURPOSES]).toEqual(["vnc", "port", "mcp-callback"]);
  });

  test("ingress forwarder labels mint exactly the taxonomy set with a validated purpose", () => {
    expect(ingressForwarderLabelArguments("0123456789ab", "mcp-callback")).toEqual([
      "--label",
      "io.runfree.managed=true",
      "--label",
      "io.runfree.container-role=ingress-forwarder",
      "--label",
      "io.runfree.lifecycle-owner=utility",
      "--label",
      "io.runfree.label-schema=1",
      "--label",
      "io.runfree.project-id=0123456789ab",
      "--label",
      "io.runfree.ingress-purpose=mcp-callback",
    ]);
    expect(() => ingressForwarderLabelArguments("0123456789ab", "nope" as never))
      .toThrow("unknown ingress purpose");
    expect(() => ingressForwarderLabelArguments("bad", "vnc")).toThrow("exact project id");
  });

  test("ephemeral helper labels mint exactly the taxonomy set with a validated purpose and run nonce", () => {
    const nonce = "0123456789abcdef0123456789abcdef";
    expect(ephemeralHelperLabelArguments("0123456789ab", "deny-probe", nonce)).toEqual([
      "--label",
      "io.runfree.managed=true",
      "--label",
      "io.runfree.container-role=ephemeral-helper",
      "--label",
      "io.runfree.lifecycle-owner=utility",
      "--label",
      "io.runfree.label-schema=1",
      "--label",
      "io.runfree.project-id=0123456789ab",
      "--label",
      "io.runfree.helper-purpose=deny-probe",
      "--label",
      `io.runfree.helper-run=${nonce}`,
    ]);
    expect(() => ephemeralHelperLabelArguments("0123456789ab", "anything" as never, nonce))
      .toThrow("unknown ephemeral helper purpose");
    expect(() => ephemeralHelperLabelArguments("nope", "deny-probe", nonce)).toThrow("exact project id");
    for (const bad of ["", "0123456789ABCDEF0123456789ABCDEF", `${nonce}0`, nonce.slice(1), "g".repeat(32)]) {
      expect(() => ephemeralHelperLabelArguments("0123456789ab", "deny-probe", bad)).toThrow("run nonce");
    }
  });

  test("one helper run's enumeration adds the purpose and the exact run nonce", () => {
    const nonce = "0123456789abcdef0123456789abcdef";
    expect(ephemeralHelperRunFilters("0123456789ab", "trust-bundle", nonce)).toEqual([
      "--filter",
      "label=io.runfree.project-id=0123456789ab",
      "--filter",
      "label=io.runfree.container-role=ephemeral-helper",
      "--filter",
      "label=io.runfree.helper-purpose=trust-bundle",
      "--filter",
      `label=io.runfree.helper-run=${nonce}`,
    ]);
    expect(() => ephemeralHelperRunFilters("0123456789ab", "trust-bundle", "")).toThrow("run nonce");
    expect(() => ephemeralHelperRunFilters("0123456789ab", "nope" as never, nonce)).toThrow("unknown ephemeral helper purpose");
    expect(() => ephemeralHelperRunFilters("bad", "trust-bundle", nonce)).toThrow("exact project id");
  });

  test("ephemeral helper enumeration selects by project and role only", () => {
    expect(projectEphemeralHelperFilters("0123456789ab")).toEqual([
      "--filter",
      "label=io.runfree.project-id=0123456789ab",
      "--filter",
      "label=io.runfree.container-role=ephemeral-helper",
    ]);
  });
});
