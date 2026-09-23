// init-detect.ts — read-only project detection for the `runfree init` wizard.
//
// The checkout is untrusted at init time. Detection therefore:
// - never executes project code or invokes git;
// - evaluates service file rules with lstat on the project root only (no
//   recursion, no parsing, symlinks are not followed — a symlinked
//   package.json still merely suggests a built-in service, which is harmless);
// - reads `.git/config` only after lstat proves it a regular file, opens it
//   with O_NOFOLLOW, skips it above 64 KiB, and parses it with a minimal INI
//   reader that extracts only `[remote "..."] url` values and ignores
//   include/includeIf/any path-valued directive (honoring include.path would
//   read attacker-pointed host files without invoking git);
// - maps project signals to built-in service ids only; the single exception
//   (git remote hosts) yields exact normalized hostnames that the wizard
//   displays verbatim, caps at 5, labels as repo-derived, and confirms
//   individually, flagging punycode (xn--) labels as possible lookalikes.

import fs from "node:fs";
import path from "node:path";

import { normalizeHostname } from "@runfree/runtime-contracts/network-policy";

import {
  SERVICES,
  type Service,
} from "../../../scripts/services.ts";

const GIT_CONFIG_MAX_BYTES = 64 * 1024;
export const GIT_REMOTE_SUGGESTION_LIMIT = 5;

// Services whose file rules match a directory entry at the project root.
// Existence only: any dirent kind (including symlinks, which are never
// followed) counts, and nothing is opened or parsed.
export function detectFileServices(
  projectRoot: string,
  registry: Record<string, Service> = SERVICES,
): string[] {
  const detected: string[] = [];
  for (const svc of Object.values(registry)) {
    if (svc.neverAutoSuggest === true) continue;
    const fileRules = svc.detect.filter((rule) => rule.kind === "file");
    const matches = fileRules.some((rule) => {
      if (rule.path.includes("/") || rule.path.includes("\\") || rule.path.includes("..")) return false;
      try {
        fs.lstatSync(path.join(projectRoot, rule.path));
        return true;
      } catch {
        return false;
      }
    });
    if (matches) detected.push(svc.id);
  }
  return detected.sort();
}

// Reads .git/config defensively: lstat (never stat) must prove a regular
// file — a symlinked, FIFO, socket, or device .git/config is rejected before
// any open — then the open itself uses O_NOFOLLOW and the size is re-checked
// on the open descriptor. Anything suspicious skips detection silently.
export function readGitConfigText(projectRoot: string): string | undefined {
  const configPath = path.join(projectRoot, ".git", "config");
  let stat: fs.Stats;
  try {
    stat = fs.lstatSync(configPath);
  } catch {
    return undefined;
  }
  if (!stat.isFile()) return undefined;
  if (stat.size > GIT_CONFIG_MAX_BYTES) return undefined;

  let fd: number;
  try {
    fd = fs.openSync(configPath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  } catch {
    return undefined;
  }
  try {
    const openStat = fs.fstatSync(fd);
    if (!openStat.isFile() || openStat.size > GIT_CONFIG_MAX_BYTES) return undefined;
    return fs.readFileSync(fd, "utf8");
  } catch {
    return undefined;
  } finally {
    fs.closeSync(fd);
  }
}

// Minimal INI reader: collects only `url` values inside `[remote "..."]`
// sections. include/includeIf sections and every other directive (notably
// any path-valued one) are ignored, and no referenced file is ever read.
export function parseGitRemoteUrls(text: string): string[] {
  const urls: string[] = [];
  let inRemoteSection = false;
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line === "" || line.startsWith("#") || line.startsWith(";")) continue;
    if (line.startsWith("[")) {
      inRemoteSection = /^\[remote\s+"(?:[^"\\]|\\.)*"\]$/i.test(line);
      continue;
    }
    if (!inRemoteSection) continue;
    const match = /^url\s*=\s*(.+)$/i.exec(line);
    if (!match) continue;
    let value = match[1].trim();
    if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) {
      value = value.slice(1, -1);
    }
    if (value !== "") urls.push(value);
  }
  return urls;
}

// Extracts an exact hostname from a git remote URL only when the form is
// unambiguous; everything else is skipped. URLs carrying userinfo are
// rejected for web-ish schemes (https://github.com@evil.com/... must never
// surface evil.com as "your GitHub remote"); ssh-family URLs may carry a
// bare username (ssh://git@host/...) but never a password. SCP-style remotes
// are accepted only in the canonical user@host:path form. Every candidate is
// re-validated through normalizeHostname.
export function hostFromGitRemoteUrl(url: string): string | undefined {
  const trimmed = url.trim();
  if (trimmed === "") return undefined;

  // Transport-helper remotes (ext::, fd::, ...) are commands, never hosts.
  if (/^[a-z][a-z0-9+.-]*::/i.test(trimmed)) return undefined;

  const schemeMatch = /^([a-z][a-z0-9+.-]*):\/\//i.exec(trimmed);
  if (schemeMatch) {
    const scheme = schemeMatch[1].toLowerCase();
    const sshFamily = scheme === "ssh" || scheme === "git+ssh" || scheme === "ssh+git";
    if (!sshFamily && scheme !== "http" && scheme !== "https" && scheme !== "git" && scheme !== "ftp" && scheme !== "ftps") {
      return undefined;
    }
    let parsed: URL;
    try {
      parsed = new URL(trimmed);
    } catch {
      return undefined;
    }
    if (parsed.password !== "") return undefined;
    if (parsed.username !== "" && !sshFamily) return undefined;
    try {
      return normalizeHostname(parsed.hostname);
    } catch {
      return undefined;
    }
  }

  // SCP-style: accepted only as user@host:path (a bare host:path is
  // ambiguous with local paths and is skipped).
  const scpMatch = /^([A-Za-z0-9._-]+)@([^@:/\\]+):(?!\/\/)\S/.exec(trimmed);
  if (scpMatch) {
    try {
      return normalizeHostname(scpMatch[2]);
    } catch {
      return undefined;
    }
  }

  return undefined;
}

export function hasPunycodeLabel(host: string): boolean {
  return host.split(".").some((label) => label.startsWith("xn--"));
}

export type GitRemoteDetection = {
  // Built-in service ids matched via gitRemoteHost rules.
  serviceIds: string[];
  // Repo-derived exact hostnames matching no built-in service; capped at
  // GIT_REMOTE_SUGGESTION_LIMIT unique hosts so a hostile config cannot
  // flood the plan, flagged when a label is punycode.
  allowHosts: Array<{ host: string; punycode: boolean }>;
  truncated: boolean;
};

export function detectGitRemotes(
  projectRoot: string,
  registry: Record<string, Service> = SERVICES,
): GitRemoteDetection {
  const detection: GitRemoteDetection = { serviceIds: [], allowHosts: [], truncated: false };
  const text = readGitConfigText(projectRoot);
  if (text === undefined) return detection;

  const hosts: string[] = [];
  for (const url of parseGitRemoteUrls(text)) {
    const host = hostFromGitRemoteUrl(url);
    if (host !== undefined && !hosts.includes(host)) hosts.push(host);
  }

  const serviceIds = new Set<string>();
  for (const host of hosts) {
    const matched = Object.values(registry).filter((svc) => svc.neverAutoSuggest !== true
      && svc.detect.some((rule) => rule.kind === "gitRemoteHost" && rule.host === host));
    if (matched.length > 0) {
      for (const svc of matched) serviceIds.add(svc.id);
      continue;
    }
    if (detection.allowHosts.length >= GIT_REMOTE_SUGGESTION_LIMIT) {
      detection.truncated = true;
      continue;
    }
    detection.allowHosts.push({ host, punycode: hasPunycodeLabel(host) });
  }
  detection.serviceIds = Array.from(serviceIds).sort();
  return detection;
}
