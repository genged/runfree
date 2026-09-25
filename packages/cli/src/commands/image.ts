// `runfree image <init|approve-context>` — customize the project agent image.
//
// A group command: the app runner shows this usage for bare `runfree image` and
// `runfree image --help`; the yargs spec validates the subcommand and rejects
// unknown flags before any filesystem write or build-context approval.

import type { ArgumentsCamelCase } from "yargs";

import {
  agentBuildConfig,
  classifyAgentBuildContext,
  saveWideBuildContextApproval,
  wideBuildContextApprovalPath,
} from "../agent-image.ts";
import {
  ensureProjectAgentImage,
  type AgentImageInitResult,
  type ProjectInfo,
} from "../config.ts";
import {
  approveNarrowImageBuildCandidate,
  captureNarrowImageBuildCandidate,
  describeNarrowImageBuildCandidate,
  readApprovedNarrowImageBuild,
} from "../control/image-approval.ts";
import { die } from "../errors.ts";
import { withExamples } from "./examples.ts";
import type { CommandModule } from "./types.ts";
import { remedy } from "../remedies.ts";

function printImageInit(projectRoot: string, result: AgentImageInitResult): void {
  console.log(`project: ${projectRoot}`);
  console.log(`agent Dockerfile: ${result.dockerfilePath}`);
  console.log(`agent build: ${result.project.config.runtime.agent?.build?.dockerfile ?? ".runfree/image/Dockerfile"}`);
  if (!result.dockerfileCreated) {
    console.log("agent Dockerfile already exists");
  }
  if (!result.configUpdated) {
    console.log("agent build already configured");
  }
}

function approveImageContext(projectRoot: string, project: ProjectInfo): void {
  const build = agentBuildConfig(project.config);
  if (!build) {
    die(`runtime.agent.build is not configured; run \`${remedy.imageInit()}\` first`);
  }
  if (classifyAgentBuildContext(projectRoot, build) === "narrow") {
    const candidate = captureNarrowImageBuildCandidate(projectRoot, build, project.paths.controlCandidatesDir);
    // Show what is being approved — the same content the interactive prompt
    // shows — before recording the approval.
    let previous: ReturnType<typeof readApprovedNarrowImageBuild>;
    try {
      previous = readApprovedNarrowImageBuild(projectRoot, project);
    } catch {
      previous = undefined;
    }
    for (const line of describeNarrowImageBuildCandidate(candidate, previous, { projectRoot })) console.log(line);
    const { approved } = approveNarrowImageBuildCandidate(
      projectRoot,
      project,
      candidate,
      "typed-host-command",
    );
    console.log("");
    console.log("Docker build runs before the Runfree sandbox and can execute staged files or send them over the network.");
    console.log(`approved exact agent build input: ${approved.subject.digest}`);
    console.log(`approval: ${project.paths.controlApprovalsPath}`);
    return;
  }
  saveWideBuildContextApproval(projectRoot, build, project.paths.stateDir);
  console.log("Docker build runs before the Runfree sandbox and can read files in the approved context or send them over the network.");
  console.log(`approved wide agent build context: ${build.context}`);
  console.log(`agent Dockerfile: ${build.dockerfile}`);
  console.log(`approval: ${wideBuildContextApprovalPath(project.paths.stateDir)}`);
}

type ImageArgs = {
  subcommand: "init" | "approve-context";
};

export const imageCommand: CommandModule = {
  name: "image",
  group: true,
  register: (parser, context, handler) =>
    parser.command(
      "image <subcommand>",
      "Customize the project agent image",
      (cmd) =>
        withExamples(
          cmd.positional("subcommand", {
            choices: ["init", "approve-context"] as const,
            describe: "init: create .runfree/image/Dockerfile and configure runtime.agent.build; approve-context: approve the exact narrow context or a wide-context risk grant in host state",
            demandOption: true,
          }),
          "image",
        ).epilogue(
          "Project Dockerfiles extend RUNFREE_BASE_IMAGE; full image overrides are not supported. Narrow inputs require exact staged approval; wide contexts require an explicit risk grant.",
        ),
      handler(async (argv: ArgumentsCamelCase<ImageArgs>) => {
        if (argv.subcommand === "init") {
          // Validate the config before templatesDir() materializes assets.
          context.projectInfo();
          const result = ensureProjectAgentImage(context.projectRoot, context.templatesDir(), context.env);
          printImageInit(context.projectRoot, result);
          return;
        }
        const project = context.projectInfo();
        approveImageContext(context.projectRoot, project);
      }),
    ),
};
