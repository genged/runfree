
import fs from "node:fs";
import path from "node:path";

import {
  canonicalDesiredNetworkPolicy,
  validateDesiredNetworkPolicy,
  type DesiredNetworkPolicyJson,
} from "@runfree/runtime-contracts/desired-network-policy";
import { publishImmutableDirectory } from "../generation-kernel.ts";
import { PROJECT_RUNFREE_PATHS } from "../runfree-consumer-registry.ts";
import { readBoundedProjectJson } from "./project-json.ts";
import { controlDigest, networkControlSubject, type ControlSubject } from "./subjects.ts";
import { sha256Digest as sha256 } from "../strict-primitives.ts";

const CANDIDATE_SCHEMA_VERSION = 1 as const;
const PROJECT_FILE = "network-project.json";
const LOCAL_FILE = "network-local.json";

type CandidateFileRecord = { sha256: string; size: number };
export type DesiredPolicyCandidateManifest = {
  candidateDigest: string;
  files: Record<typeof PROJECT_FILE | typeof LOCAL_FILE, CandidateFileRecord>;
  schemaVersion: typeof CANDIDATE_SCHEMA_VERSION;
  subjects: {
    "network-local": string;
    "network-project": string;
  };
};

export type DesiredPolicyCandidate = {
  directory: string;
  local: DesiredNetworkPolicyJson;
  localSubject: ControlSubject;
  manifest: DesiredPolicyCandidateManifest;
  project: DesiredNetworkPolicyJson;
  projectSubject: ControlSubject;
};


function canonicalFile(policy: DesiredNetworkPolicyJson): string {
  return `${canonicalDesiredNetworkPolicy(policy)}\n`;
}

function immutableDirectoryName(digest: string): string {
  if (!/^sha256:[a-f0-9]{64}$/.test(digest)) throw new Error("candidate digest is malformed");
  return digest.slice("sha256:".length);
}

function buildCandidate(
  project: DesiredNetworkPolicyJson,
  local: DesiredNetworkPolicyJson,
): Omit<DesiredPolicyCandidate, "directory"> {
  const projectSubject = networkControlSubject("network-project", project);
  const localSubject = networkControlSubject("network-local", local);
  const projectContents = canonicalFile(project);
  const localContents = canonicalFile(local);
  const candidateDigest = controlDigest({
    schemaVersion: CANDIDATE_SCHEMA_VERSION,
    subjectType: "desired-policy-candidate",
    subjects: {
      "network-project": projectSubject.digest,
      "network-local": localSubject.digest,
    },
  });
  const manifest: DesiredPolicyCandidateManifest = {
    schemaVersion: CANDIDATE_SCHEMA_VERSION,
    candidateDigest,
    subjects: {
      "network-project": projectSubject.digest,
      "network-local": localSubject.digest,
    },
    files: {
      [PROJECT_FILE]: { sha256: sha256(projectContents), size: Buffer.byteLength(projectContents) },
      [LOCAL_FILE]: { sha256: sha256(localContents), size: Buffer.byteLength(localContents) },
    },
  };
  return { project, local, projectSubject, localSubject, manifest };
}

export function verifyDesiredPolicyCandidate(candidate: DesiredPolicyCandidate): void {
  for (const [fileName, record] of Object.entries(candidate.manifest.files)) {
    const filePath = path.join(candidate.directory, fileName);
    const stat = fs.lstatSync(filePath);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) {
      throw new Error(`candidate payload ${fileName} is not a regular single-link file`);
    }
    const contents = fs.readFileSync(filePath);
    if (contents.length !== record.size || sha256(contents) !== record.sha256) {
      throw new Error(`candidate payload ${fileName} does not match its manifest`);
    }
  }
  // The manifest is fully rederived from the captured policies above, and the
  // digest-named directory binds the subject set; a stored manifest file
  // (written by older releases) is ignored rather than required.
}

export function captureDesiredPolicyCandidate(projectRoot: string, candidateRoot: string): DesiredPolicyCandidate {
  const projectRead = readBoundedProjectJson(projectRoot, PROJECT_RUNFREE_PATHS.networkPolicy);
  if (!projectRead) throw new Error("project network policy is required");
  const localRead = readBoundedProjectJson(projectRoot, PROJECT_RUNFREE_PATHS.networkPolicyLocal, { allowMissing: true });
  const project = validateDesiredNetworkPolicy(projectRead.parsed);
  const local = validateDesiredNetworkPolicy(localRead?.parsed ?? { version: 2, hosts: [] });
  const built = buildCandidate(project, local);
  const name = immutableDirectoryName(built.manifest.candidateDigest);
  const candidate = { ...built, directory: path.join(candidateRoot, name) };
  return publishImmutableDirectory({
    parent: candidateRoot,
    name,
    files: {
      [PROJECT_FILE]: canonicalFile(project),
      [LOCAL_FILE]: canonicalFile(local),
    },
    directoryMode: 0o700,
    fileMode: 0o400,
    parentMode: 0o700,
    tempPrefix: ".candidate-",
    verify: () => {
      verifyDesiredPolicyCandidate(candidate);
      return candidate;
    },
  });
}
