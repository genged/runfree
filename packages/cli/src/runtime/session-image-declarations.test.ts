import { describe, expect, test } from "vitest";

import {
  assertSessionImageDeclarationProof,
  createSessionImageDeclarationProof,
  type SessionImageDeclarationProof,
} from "./session-image-declarations.ts";
import type { SessionContainerMount } from "./session-container-contract.ts";
import type { DockerImageInspect } from "./docker.ts";

const IMAGE_ID = `sha256:${"a".repeat(64)}`;
const OTHER_IMAGE_ID = `sha256:${"b".repeat(64)}`;
const platform = { architecture: "amd64", os: "linux" } as const;
const mounts: SessionContainerMount[] = [
  { type: "bind", source: "/host/project", target: "/workspace", readOnly: false, noCopy: false },
  { type: "volume", source: "cache", target: "/cache", readOnly: false, noCopy: true },
];
const environment = { HOME: "/home/agent", TERM: "xterm-256color" };

describe("selected session image declaration preflight", () => {
  test("seals exact image volume declarations accounted for by explicit mounts", () => {
    const proof = createSessionImageDeclarationProof({
      image: {
        ...platform,
        id: IMAGE_ID,
        labels: {},
        volumes: ["/workspace", "/cache"],
        environment: { PATH: "/usr/bin", TERM: "image-default" },
      },
      selectedAgentImageId: IMAGE_ID,
      mounts,
      environment,
    });

    expect(proof).toEqual({
      version: 1,
      architecture: "amd64",
      os: "linux",
      selectedAgentImageId: IMAGE_ID,
      declaredVolumeTargets: ["/cache", "/workspace"],
      explicitMounts: [mounts[1], mounts[0]],
      mergedEnvironment: { HOME: "/home/agent", PATH: "/usr/bin", TERM: "xterm-256color" },
    });
    expect(() => assertSessionImageDeclarationProof(proof, { selectedAgentImageId: IMAGE_ID, mounts, environment }))
      .not.toThrow();
  });

  test("rejects unaccounted volumes and image-ID drift before container creation", () => {
    expect(() => createSessionImageDeclarationProof({
      image: { ...platform, id: IMAGE_ID, labels: {}, volumes: ["/project-controlled-anonymous"] },
      selectedAgentImageId: IMAGE_ID,
      mounts,
      environment,
    })).toThrow("unaccounted volumes");
    expect(() => createSessionImageDeclarationProof({
      image: { ...platform, id: OTHER_IMAGE_ID, labels: {}, volumes: [] },
      selectedAgentImageId: IMAGE_ID,
      mounts,
      environment,
    })).toThrow("exact selected image ID");
    expect(() => createSessionImageDeclarationProof({
      image: { ...platform, id: IMAGE_ID, labels: {}, volumes: [] },
      selectedAgentImageId: IMAGE_ID,
      mounts: [
        ...mounts,
        { type: "volume", source: "history", target: "/persistent", readOnly: false, noCopy: false },
      ],
      environment,
    })).toThrow("without nocopy");
  });

  test("rejects malformed image declarations before container creation", () => {
    const images: DockerImageInspect[] = [
      { ...platform, id: IMAGE_ID, labels: {}, volumes: ["relative"] },
      { ...platform, id: IMAGE_ID, labels: {}, volumes: ["/workspace/../escape"] },
      { ...platform, id: IMAGE_ID, labels: {}, volumes: ["/workspace", "/workspace"] },
      { ...platform, id: IMAGE_ID, labels: {}, volumes: [], environment: { "BAD-NAME": "value" } },
      { ...platform, id: IMAGE_ID, labels: {}, volumes: [], environment: { SAFE: "bad\nvalue" } },
    ];
    for (const image of images) {
      expect(() => createSessionImageDeclarationProof({
        image,
        selectedAgentImageId: IMAGE_ID,
        mounts,
        environment,
      })).toThrow();
    }
  });

  test.each([
    { architecture: "s390x", os: "linux" },
    { architecture: "amd64", os: "windows" },
    { architecture: undefined, os: "linux" },
    { architecture: "arm64", os: undefined },
  ])("rejects unsupported or missing image platform $os/$architecture", (unsupported) => {
    expect(() => createSessionImageDeclarationProof({
      image: { ...unsupported, id: IMAGE_ID, labels: {}, volumes: [] },
      selectedAgentImageId: IMAGE_ID,
      mounts,
      environment,
    })).toThrow("platform is unsupported");
  });

  test("rejects structural copies and mount-plan drift at the effect boundary", () => {
    const proof = createSessionImageDeclarationProof({
      image: { ...platform, id: IMAGE_ID, labels: {}, volumes: [] },
      selectedAgentImageId: IMAGE_ID,
      mounts,
      environment,
    });
    expect(() => assertSessionImageDeclarationProof(
      { ...proof } as unknown as SessionImageDeclarationProof,
      { selectedAgentImageId: IMAGE_ID, mounts, environment },
    )).toThrow("canonical preflight");
    expect(() => assertSessionImageDeclarationProof(proof, {
      selectedAgentImageId: IMAGE_ID,
      mounts: mounts.slice(1),
      environment,
    })).toThrow("different create plan");
    expect(() => assertSessionImageDeclarationProof(proof, {
      selectedAgentImageId: IMAGE_ID,
      mounts: mounts.map((mount) => mount.target === "/cache" ? { ...mount, noCopy: false } : mount),
      environment,
    })).toThrow("different create plan");
    expect(() => assertSessionImageDeclarationProof(proof, {
      selectedAgentImageId: IMAGE_ID,
      mounts: mounts.map((mount) => mount.target === "/workspace"
        ? { ...mount, source: "/host/other-project", readOnly: true }
        : mount),
      environment,
    })).toThrow("different create plan");
    expect(() => assertSessionImageDeclarationProof(proof, {
      selectedAgentImageId: IMAGE_ID,
      mounts,
      environment: { ...environment, TERM: "vt100" },
    })).toThrow("different environment plan");
  });
});
