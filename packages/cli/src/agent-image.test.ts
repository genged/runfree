import childProcess from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, test } from "vitest";

import {
  classifyAgentBuildContext,
  effectiveRuntimeDigest,
  hasWideBuildContextApproval,
  agentBaseImageTag,
  agentRuntimeImageTag,
  projectAgentImageTag,
  proxyRuntimeImageTag,
  saveWideBuildContextApproval,
  selectedAgentImageInput,
  stageAgentBuildContext,
  wideBuildContextApprovalPath,
} from "./agent-image.ts";
import { agentDescriptorRuntimeInputs } from "./agents.ts";
import { defaultConfig, type AgentBuildConfig } from "./config.ts";
import { RUNFREE_RUNTIME_DIGEST, RUNFREE_VERSION } from "./embedded-assets.generated.ts";

let tmp: string;

beforeEach(() => {
  tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "runfree-agent-image-tests-")));
});

afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

function writeNarrowImage(): AgentBuildConfig {
  const imageDir = path.join(tmp, ".runfree", "image");
  fs.mkdirSync(path.join(imageDir, "scripts"), { recursive: true });
  fs.writeFileSync(path.join(imageDir, "Dockerfile"), "ARG RUNFREE_BASE_IMAGE\nFROM ${RUNFREE_BASE_IMAGE}\n");
  fs.writeFileSync(path.join(imageDir, ".dockerignore"), "ignored-link\n");
  fs.writeFileSync(path.join(imageDir, "scripts", "setup.sh"), "#!/bin/sh\necho setup\n", { mode: 0o755 });
  fs.chmodSync(path.join(imageDir, "scripts", "setup.sh"), 0o755);
  return {
    context: ".runfree/image",
    dockerfile: ".runfree/image/Dockerfile",
  };
}

function sha256(value: string | Buffer): string {
  return `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;
}

describe("project agent image build context", () => {
  test("effective runtime digest includes built-in agent descriptor inputs", () => {
    const digest = effectiveRuntimeDigest(tmp, defaultConfig());
    const payload = {
      agents: agentDescriptorRuntimeInputs(),
      runtimeDigest: RUNFREE_RUNTIME_DIGEST,
      version: RUNFREE_VERSION,
    };

    expect(digest).toBe(sha256(JSON.stringify(payload)));
  });

  test("classifies only .runfree/image contexts as narrow", () => {
    expect(classifyAgentBuildContext(tmp, {
      context: ".runfree/image",
      dockerfile: ".runfree/image/Dockerfile",
    })).toBe("narrow");
    expect(classifyAgentBuildContext(tmp, {
      context: ".runfree/image/browser",
      dockerfile: ".runfree/image/browser/Dockerfile",
    })).toBe("narrow");
    expect(classifyAgentBuildContext(tmp, {
      context: ".",
      dockerfile: ".runfree/Dockerfile",
    })).toBe("wide");
    expect(classifyAgentBuildContext(tmp, {
      context: ".runfree",
      dockerfile: ".runfree/Dockerfile",
    })).toBe("wide");
  });

  test("selects the embedded component digest without release-version coupling", () => {
    const first = selectedAgentImageInput(tmp, defaultConfig(), {
      embeddedAgentImageInputDigest: `sha256:${"a".repeat(64)}`,
      version: "1.0.0",
    });
    const second = selectedAgentImageInput(tmp, defaultConfig(), {
      embeddedAgentImageInputDigest: `sha256:${"a".repeat(64)}`,
      version: "2.0.0",
    });

    expect(first).toEqual({ digest: `sha256:${"a".repeat(64)}`, kind: "embedded" });
    expect(second).toEqual(first);
  });

  test("narrow project identity changes with context bytes but not an unreferenced release version", () => {
    const build = writeNarrowImage();
    const config = defaultConfig();
    config.runtime.agent = { build };
    const first = selectedAgentImageInput(tmp, config, { version: "1.0.0" });
    const nextVersion = selectedAgentImageInput(tmp, config, { version: "2.0.0" });
    fs.appendFileSync(path.join(tmp, ".runfree", "image", "scripts", "setup.sh"), "echo changed\n");
    const changedContext = selectedAgentImageInput(tmp, config, { version: "2.0.0" });

    expect(first.kind).toBe("project");
    expect(nextVersion.digest).toBe(first.digest);
    expect(changedContext.digest).not.toBe(first.digest);
  });

  test("project identity changes with the embedded agent foundation", () => {
    const build = writeNarrowImage();
    const config = defaultConfig();
    config.runtime.agent = { build };
    const first = selectedAgentImageInput(tmp, config, {
      embeddedAgentImageInputDigest: `sha256:${"a".repeat(64)}`,
    });
    const changedFoundation = selectedAgentImageInput(tmp, config, {
      embeddedAgentImageInputDigest: `sha256:${"b".repeat(64)}`,
    });

    expect(first.kind).toBe("project");
    expect(changedFoundation.kind).toBe("project");
    expect(changedFoundation.digest).not.toBe(first.digest);
  });

  test("legacy injected arguments are detected as exact tokens, including comments", () => {
    const build = writeNarrowImage();
    const dockerfilePath = path.join(tmp, ".runfree", "image", "Dockerfile");
    fs.appendFileSync(dockerfilePath, "# RUNFREE_VERSION remains intentionally volatile\n# XRUNFREE_RUNTIME_DIGEST is not a token\n");
    const config = defaultConfig();
    config.runtime.agent = { build };
    const first = selectedAgentImageInput(tmp, config, { version: "1.0.0", legacyRuntimeDigest: "sha256:first" });
    const second = selectedAgentImageInput(tmp, config, { version: "2.0.0", legacyRuntimeDigest: "sha256:second" });

    expect(first.kind).toBe("project");
    if (first.kind !== "project") throw new Error("expected project image identity");
    expect(first.referencedLegacyInjectedArguments).toEqual([{ name: "RUNFREE_VERSION", value: "1.0.0" }]);
    expect(second.digest).not.toBe(first.digest);
  });

  test("wide project identity fingerprints Dockerfile bytes but preserves the approved limited context contract", () => {
    fs.mkdirSync(path.join(tmp, ".runfree"), { recursive: true });
    fs.writeFileSync(path.join(tmp, ".runfree", "Dockerfile"), "ARG RUNFREE_BASE_IMAGE\nFROM ${RUNFREE_BASE_IMAGE}\n");
    fs.writeFileSync(path.join(tmp, "untracked-context-file"), "first\n");
    const config = defaultConfig();
    config.runtime.agent = { build: { context: ".", dockerfile: ".runfree/Dockerfile" } };
    const first = selectedAgentImageInput(tmp, config);
    fs.writeFileSync(path.join(tmp, "untracked-context-file"), "second\n");
    const contextChanged = selectedAgentImageInput(tmp, config);
    fs.appendFileSync(path.join(tmp, ".runfree", "Dockerfile"), "RUN true\n");
    const dockerfileChanged = selectedAgentImageInput(tmp, config);

    expect(contextChanged.digest).toBe(first.digest);
    expect(dockerfileChanged.digest).not.toBe(first.digest);
  });

  test("component-addressed image tags use full digests and exclude the release version", () => {
    const inputDigest = `sha256:${"a".repeat(64)}`;
    for (const tag of [
      agentBaseImageTag(inputDigest),
      agentRuntimeImageTag(inputDigest),
      proxyRuntimeImageTag(inputDigest),
      projectAgentImageTag(tmp, inputDigest),
    ]) {
      expect(tag).toContain(`sha256-${"a".repeat(64)}`);
      expect(tag).not.toContain(RUNFREE_VERSION);
    }
  });

  test("stages a validated narrow context into Runfree state", () => {
    const build = writeNarrowImage();
    fs.writeFileSync(path.join(tmp, "package.json"), "{}\n");
    const stateDir = path.join(tmp, "state");

    const staged = stageAgentBuildContext(tmp, build, stateDir);

    expect(staged.contextPath).toBe(path.join(stateDir, "build-context"));
    expect(staged.dockerfilePath).toBe(path.join(stateDir, "build-context", "Dockerfile"));
    expect(fs.existsSync(path.join(staged.contextPath, "package.json"))).toBe(false);
    expect(fs.readFileSync(staged.dockerfilePath, "utf8")).toBe("ARG RUNFREE_BASE_IMAGE\nFROM ${RUNFREE_BASE_IMAGE}\n");
    expect(fs.readFileSync(path.join(staged.contextPath, "scripts", "setup.sh"), "utf8")).toBe("#!/bin/sh\necho setup\n");
    expect(fs.statSync(path.join(staged.contextPath, "scripts", "setup.sh")).mode & 0o111).not.toBe(0);
    expect(staged.manifest).toContainEqual(expect.objectContaining({
      path: "Dockerfile",
      type: "file",
      size: Buffer.byteLength("ARG RUNFREE_BASE_IMAGE\nFROM ${RUNFREE_BASE_IMAGE}\n"),
      sha256: sha256("ARG RUNFREE_BASE_IMAGE\nFROM ${RUNFREE_BASE_IMAGE}\n"),
    }));
    expect(staged.manifest).toContainEqual(expect.objectContaining({
      path: "scripts/setup.sh",
      type: "file",
      mode: 0o755,
    }));
  });

  test("rejects a Dockerfile outside the selected context", () => {
    const build = writeNarrowImage();
    fs.writeFileSync(path.join(tmp, ".runfree", "Dockerfile"), "FROM scratch\n");

    expect(() => stageAgentBuildContext(tmp, {
      ...build,
      dockerfile: ".runfree/Dockerfile",
    }, path.join(tmp, "state"))).toThrow("Dockerfile must resolve inside the agent build context");
  });

  test("rejects symlinks even when .dockerignore would exclude them", () => {
    const build = writeNarrowImage();
    fs.writeFileSync(path.join(tmp, "outside-secret"), "secret\n");
    fs.symlinkSync(path.join(tmp, "outside-secret"), path.join(tmp, ".runfree", "image", "ignored-link"));

    expect(() => stageAgentBuildContext(tmp, build, path.join(tmp, "state"))).toThrow("symlink");
  });

  test("rejects hard-linked files in narrow contexts", () => {
    const build = writeNarrowImage();
    fs.writeFileSync(path.join(tmp, "outside-copy"), "shared\n");
    fs.linkSync(path.join(tmp, "outside-copy"), path.join(tmp, ".runfree", "image", "hardlink"));

    expect(() => stageAgentBuildContext(tmp, build, path.join(tmp, "state"))).toThrow("hard link");
  });

  test("rejects special files in narrow contexts when the platform can create them", () => {
    const build = writeNarrowImage();
    const fifoPath = path.join(tmp, ".runfree", "image", "pipe");
    const mkfifo = childProcess.spawnSync("mkfifo", [fifoPath], { stdio: "ignore" });
    if (mkfifo.status !== 0) return;

    expect(() => stageAgentBuildContext(tmp, build, path.join(tmp, "state"))).toThrow("fifo");
  });

  test("wide context approval is stored outside the project and invalidates on Dockerfile changes", () => {
    fs.mkdirSync(path.join(tmp, ".runfree"), { recursive: true });
    const dockerfilePath = path.join(tmp, ".runfree", "Dockerfile");
    fs.writeFileSync(dockerfilePath, "ARG RUNFREE_BASE_IMAGE\nFROM ${RUNFREE_BASE_IMAGE}\n");
    const build: AgentBuildConfig = {
      context: ".",
      dockerfile: ".runfree/Dockerfile",
    };
    const stateDir = path.join(tmp, "state");

    expect(hasWideBuildContextApproval(tmp, build, stateDir)).toBe(false);
    saveWideBuildContextApproval(tmp, build, stateDir);

    expect(hasWideBuildContextApproval(tmp, build, stateDir)).toBe(true);
    expect(wideBuildContextApprovalPath(stateDir)).toBe(path.join(stateDir, "approved-build-contexts.json"));
    expect(fs.existsSync(path.join(tmp, ".runfree", "approved-build-contexts.json"))).toBe(false);

    fs.appendFileSync(dockerfilePath, "RUN echo changed\n");
    expect(hasWideBuildContextApproval(tmp, build, stateDir)).toBe(false);
  });
});
