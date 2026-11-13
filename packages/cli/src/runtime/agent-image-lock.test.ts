import fs from "node:fs";
import path from "node:path";

import { expect, test } from "vitest";

import {
  AGENT_IMAGE_REPOSITORY,
  parseAgentImageLock,
  pinnedAgentImage,
  shippedAgentImageLock,
} from "./agent-image-lock.ts";

const INPUT = `sha256:${"1".repeat(64)}`;
const MANIFEST = `sha256:${"a".repeat(64)}`;

test("the shipped lock parses, names the GHCR repository, and is empty", () => {
  const raw = JSON.parse(fs.readFileSync(path.join(import.meta.dirname, "agent-image-lock.json"), "utf8"));
  expect(raw).toEqual({ repository: "ghcr.io/genged/runfree-agent", images: {} });
  const lock = shippedAgentImageLock();
  expect(lock.repository).toBe(AGENT_IMAGE_REPOSITORY);
  expect(lock.images.size).toBe(0);
});

test("a valid lock maps an input digest to a digest-only pull reference", () => {
  const lock = parseAgentImageLock({ repository: AGENT_IMAGE_REPOSITORY, images: { [INPUT]: MANIFEST } });
  expect(pinnedAgentImage(lock, INPUT)).toBe(`ghcr.io/genged/runfree-agent@${MANIFEST}`);
  expect(pinnedAgentImage(lock, `sha256:${"2".repeat(64)}`)).toBeUndefined();
});

test.each([
  ["a foreign repository", { repository: "ghcr.io/attacker/runfree-agent", images: {} }, /repository must be/],
  ["a repository with a tag", { repository: `${AGENT_IMAGE_REPOSITORY}:latest`, images: {} }, /repository must be/],
  ["a missing repository", { images: {} }, /exactly the keys/],
  ["an extra key", { repository: AGENT_IMAGE_REPOSITORY, images: {}, tag: "latest" }, /exactly the keys/],
  ["images as an array", { repository: AGENT_IMAGE_REPOSITORY, images: [] }, /images must be an object/],
  ["a non-object lock", [], /must be a JSON object/],
  ["a null lock", null, /must be a JSON object/],
  ["a tag as manifest", { repository: AGENT_IMAGE_REPOSITORY, images: { [INPUT]: "latest" } }, /malformed manifest digest/],
  ["an uppercase manifest digest", { repository: AGENT_IMAGE_REPOSITORY, images: { [INPUT]: `sha256:${"A".repeat(64)}` } }, /malformed manifest digest/],
  ["a short manifest digest", { repository: AGENT_IMAGE_REPOSITORY, images: { [INPUT]: `sha256:${"a".repeat(63)}` } }, /malformed manifest digest/],
  ["a manifest digest with a suffix", { repository: AGENT_IMAGE_REPOSITORY, images: { [INPUT]: `${MANIFEST}\n` } }, /malformed manifest digest/],
  ["a non-string manifest digest", { repository: AGENT_IMAGE_REPOSITORY, images: { [INPUT]: 1 } }, /malformed manifest digest/],
  ["a malformed input digest", { repository: AGENT_IMAGE_REPOSITORY, images: { "sha256:abc": MANIFEST } }, /malformed input digest/],
  ["a non-sha256 input digest", { repository: AGENT_IMAGE_REPOSITORY, images: { [`sha512:${"1".repeat(64)}`]: MANIFEST } }, /malformed input digest/],
])("the lock parser rejects %s", (_name, value, message) => {
  expect(() => parseAgentImageLock(value)).toThrow(message);
});
