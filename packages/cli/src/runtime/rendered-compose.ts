import fs from "node:fs";
import path from "node:path";

import { composeAgentStateMounts } from "../agents.ts";
import { inboxMount } from "../inbox.ts";
import { renderRuntimeCompose } from "./compose.ts";
import {
  dependencyOverlayMountsForRoot,
  dependencyOverlayNamedVolumes,
  type DependencyOverlayPlan,
} from "./dependency-overlays.ts";
import type { RuntimeGitLayoutPlan } from "./git-layout.ts";
import { claudeMcpConfigMount, mcpProjectMaskMounts } from "./mcp.ts";
import type { RuntimeContext } from "./types.ts";

export function renderProjectRuntimeCompose(input: {
  context: RuntimeContext;
  dependencyPlan: DependencyOverlayPlan;
  gitLayout: RuntimeGitLayoutPlan;
  sourceRuntimeRoot: string;
}): string {
  const { context, dependencyPlan, gitLayout, sourceRuntimeRoot } = input;
  // The rendered Compose file is the fixed control plane only. Agent
  // environment, project mounts, and the MCP OAuth callback are per-session
  // concerns owned by the session container template and the ingress forwarder;
  // the state mounts and agent volumes are passed only so the render still
  // rejects duplicate or overlapping session mount targets.
  //
  return renderRuntimeCompose(
    fs.readFileSync(path.join(sourceRuntimeRoot, "agent", "compose.yaml"), "utf8"),
    {
      agentStateMounts: composeAgentStateMounts(),
      agentVolumes: [
        inboxMount(),
        claudeMcpConfigMount(context.project),
        ...mcpProjectMaskMounts(context.projectRoot, context.project, gitLayout.containerProjectRoot),
        ...dependencyOverlayMountsForRoot(dependencyPlan, gitLayout.containerProjectRoot),
      ],
      namedVolumes: dependencyOverlayNamedVolumes(dependencyPlan),
      // The rendered control plane names the one admission source; the proxy
      // refuses to start without it.
      proxyEnvironment: { RUNFREE_SESSION_ADMISSION_SOURCE: "files" },
    },
  );
}
