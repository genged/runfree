import { expect, test } from "vitest";

import {
  AGENT_BASE_IMAGE_ROLE,
  AGENT_PROJECT_IMAGE_ROLE,
  AGENT_RUNTIME_IMAGE_ROLE,
  PROJECT_ID_LABEL,
  RUNFREE_DIGEST_SCHEMA_LABEL,
  RUNFREE_DIGEST_SCHEMA_VERSION,
  RUNFREE_IMAGE_INPUT_DIGEST_LABEL,
  RUNFREE_IMAGE_ROLE_LABEL,
  RUNFREE_MANAGED_IMAGE_LABEL,
  RUNFREE_VERSION_LABEL,
  SELECTED_AGENT_IMAGE_LABEL_NAMES,
} from "./constants.ts";
import { inspectReusableManagedImage, reusableManagedImage } from "./image-identity.ts";

const digest = `sha256:${"a".repeat(64)}`;
const imageId = `sha256:${"f".repeat(64)}`;

function labels(role = AGENT_RUNTIME_IMAGE_ROLE): Record<string, string> {
  return {
    [RUNFREE_MANAGED_IMAGE_LABEL]: "true",
    [RUNFREE_DIGEST_SCHEMA_LABEL]: RUNFREE_DIGEST_SCHEMA_VERSION,
    [RUNFREE_IMAGE_INPUT_DIGEST_LABEL]: digest,
    [RUNFREE_IMAGE_ROLE_LABEL]: role,
  };
}

test("accepts an inspected managed image with exact component identity", () => {
  const docker = {
    inspectImage: () => ({ id: imageId, labels: labels() }),
  };

  expect(reusableManagedImage(docker, "runfree/agent-runtime:test", {
    inputDigest: digest,
    roles: [AGENT_RUNTIME_IMAGE_ROLE],
  })).toBe(true);
  expect(inspectReusableManagedImage(docker, "runfree/agent-runtime:test", {
    inputDigest: digest,
    roles: [AGENT_RUNTIME_IMAGE_ROLE],
  })).toEqual({ id: imageId, labels: labels(), tag: "runfree/agent-runtime:test" });
});

test("defines the closed selected-agent image label namespace", () => {
  expect(SELECTED_AGENT_IMAGE_LABEL_NAMES).toEqual([
    RUNFREE_MANAGED_IMAGE_LABEL,
    RUNFREE_IMAGE_ROLE_LABEL,
    RUNFREE_DIGEST_SCHEMA_LABEL,
    RUNFREE_IMAGE_INPUT_DIGEST_LABEL,
    PROJECT_ID_LABEL,
    RUNFREE_VERSION_LABEL,
  ]);
});

test("accepts the equivalent embedded agent role for a dual-tagged image", () => {
  const docker = {
    inspectImage: () => ({ id: imageId, labels: labels(AGENT_RUNTIME_IMAGE_ROLE) }),
  };

  expect(reusableManagedImage(docker, "runfree/agent-base:test", {
    inputDigest: digest,
    roles: [AGENT_BASE_IMAGE_ROLE, AGENT_RUNTIME_IMAGE_ROLE],
  })).toBe(true);
});

test("carries isolated copies of inspected image declarations", () => {
  const volumes = ["/workspace-cache", "/var/lib/tool-state"];
  const environment = { PATH: "/usr/bin" };
  const docker = {
    inspectImage: () => ({ environment, id: imageId, labels: labels(), volumes }),
  };

  const inspected = inspectReusableManagedImage(docker, "runfree/agent-runtime:test", {
    inputDigest: digest,
    roles: [AGENT_RUNTIME_IMAGE_ROLE],
  });
  expect(inspected?.environment).toEqual(environment);
  expect(inspected?.environment).not.toBe(environment);
  expect(inspected?.volumes).toEqual(volumes);
  expect(inspected?.volumes).not.toBe(volumes);
});

test("requires the exact project identity for project agent images", () => {
  const docker = {
    inspectImage: () => ({
      id: imageId,
      labels: { ...labels(AGENT_PROJECT_IMAGE_ROLE), [PROJECT_ID_LABEL]: "other-project" },
    }),
  };

  expect(reusableManagedImage(docker, "runfree/agent-project:test", {
    inputDigest: digest,
    projectId: "expected-project",
    roles: [AGENT_PROJECT_IMAGE_ROLE],
  })).toBe(false);
});

test.each([
  ["missing inspection", undefined],
  ["unmanaged", { ...labels(), [RUNFREE_MANAGED_IMAGE_LABEL]: "false" }],
  ["legacy schema", { ...labels(), [RUNFREE_DIGEST_SCHEMA_LABEL]: "0" }],
  ["wrong digest", { ...labels(), [RUNFREE_IMAGE_INPUT_DIGEST_LABEL]: `sha256:${"b".repeat(64)}` }],
  ["wrong role", { ...labels(), [RUNFREE_IMAGE_ROLE_LABEL]: AGENT_PROJECT_IMAGE_ROLE }],
] as const)("rejects %s image metadata", (_label, imageLabels) => {
  const docker = {
    inspectImage: () => imageLabels === undefined ? undefined : { id: imageId, labels: imageLabels },
  };

  expect(reusableManagedImage(docker, "runfree/agent-runtime:test", {
    inputDigest: digest,
    roles: [AGENT_RUNTIME_IMAGE_ROLE],
  })).toBe(false);
});

test("rejects a truncated expected digest before inspecting the tag", () => {
  let inspected = false;
  const docker = {
    inspectImage: () => {
      inspected = true;
      return { id: imageId, labels: labels() };
    },
  };

  expect(reusableManagedImage(docker, "runfree/agent-runtime:test", {
    inputDigest: "sha256:abc",
    roles: [AGENT_RUNTIME_IMAGE_ROLE],
  })).toBe(false);
  expect(inspected).toBe(false);
});

test("rejects a tag whose image inspection lacks an immutable image id", () => {
  const docker = {
    inspectImage: () => ({ id: "sha256:short", labels: labels() }),
  };

  expect(inspectReusableManagedImage(docker, "runfree/agent-runtime:test", {
    inputDigest: digest,
    roles: [AGENT_RUNTIME_IMAGE_ROLE],
  })).toBeUndefined();
});
