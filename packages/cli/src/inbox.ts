import childProcess from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { die } from "./errors.ts";
import type { RuntimeComposeMount } from "./runtime/compose.ts";
import { RUNFREE_RUNTIME_TARGETS } from "./runtime/mount-target-policy.ts";
import { warn } from "./warnings.ts";

export const CONTAINER_INBOX_DIR = RUNFREE_RUNTIME_TARGETS.inbox;
export const MAX_IMPORTED_IMAGE_BYTES = 10 * 1024 * 1024;
export const INBOX_CLEANUP_AGE_MS = 24 * 60 * 60 * 1000;

export const LEGACY_INBOX_FILE_RE = /^clip-\d{4}-\d{2}-\d{2}-\d{6}-[a-f0-9]{4,16}\.png$/;

export type ImportedImage = {
  containerPath: string;
  hostPath: string;
};

export type ImportImageOptions = {
  env?: NodeJS.ProcessEnv;
  hostInbox: string;
  now?: Date;
};

function assertSafeInboxDir(hostInbox: string): void {
  const stat = fs.lstatSync(hostInbox);
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    die(`Runfree inbox must be a normal directory: ${hostInbox}`);
  }
}

function lstatIfPresent(targetPath: string): fs.Stats | undefined {
  try {
    return fs.lstatSync(targetPath);
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return undefined;
    throw error;
  }
}

export function ensureInbox(hostInbox: string, onWarning: (message: string) => void = warn): void {
  const legacyInbox = path.join(path.dirname(hostInbox), "images");
  const inboxStat = lstatIfPresent(hostInbox);
  const legacyStat = lstatIfPresent(legacyInbox);
  if (legacyStat && !inboxStat) {
    if (legacyStat.isDirectory() && !legacyStat.isSymbolicLink()) {
      try {
        fs.renameSync(legacyInbox, hostInbox);
      } catch (error) {
        onWarning(`could not migrate legacy Runfree image inbox ${legacyInbox} to ${hostInbox}: ${error instanceof Error ? error.message : String(error)}`);
      }
    } else {
      onWarning(`legacy Runfree image inbox is not a normal directory; kept at ${legacyInbox}`);
    }
  } else if (legacyStat && inboxStat) {
    onWarning(`legacy Runfree image inbox was kept because the new inbox already exists: ${legacyInbox}`);
  }
  fs.mkdirSync(hostInbox, { recursive: true, mode: 0o700 });
  assertSafeInboxDir(hostInbox);
  fs.chmodSync(hostInbox, 0o700);
}

export function inboxContainerDir(): string {
  return CONTAINER_INBOX_DIR;
}

export function inboxMount(): RuntimeComposeMount {
  return {
    type: "bind",
    source: "${RUNFREE_INBOX_DIR:?RUNFREE_INBOX_DIR is required}",
    target: CONTAINER_INBOX_DIR,
    readOnly: true,
  };
}

export function containerInboxPath(filename: string): string {
  if (!LEGACY_INBOX_FILE_RE.test(filename)) {
    throw new Error(`invalid imported image filename: ${filename || "<empty>"}`);
  }
  return `${CONTAINER_INBOX_DIR}/${filename}`;
}

function randomImageSuffix(env?: NodeJS.ProcessEnv): string {
  const testValue = env?.RUNFREE_TEST_INBOX_RANDOM;
  if (testValue && /^[a-f0-9]{4,16}$/.test(testValue)) return testValue;
  return crypto.randomBytes(2).toString("hex");
}

export function importedImageName(now = new Date(), random = crypto.randomBytes(2)): string {
  const stamp = now.toISOString().slice(0, 19).replace("T", "-").replaceAll(":", "");
  return `clip-${stamp}-${random.toString("hex")}.png`;
}

function looksLikePng(buffer: Buffer): boolean {
  return buffer.length >= 4
    && buffer[0] === 0x89
    && buffer[1] === 0x50
    && buffer[2] === 0x4e
    && buffer[3] === 0x47;
}

function assertImageBuffer(buffer: Buffer, source: string): void {
  if (buffer.length === 0) die(`${source} did not contain image data`);
  if (buffer.length > MAX_IMPORTED_IMAGE_BYTES) {
    die(`clipboard image exceeds ${MAX_IMPORTED_IMAGE_BYTES} bytes: ${buffer.length} bytes`);
  }
  if (!looksLikePng(buffer)) die(`${source} did not contain PNG image data`);
}

function readTestClipboardImage(env: NodeJS.ProcessEnv): Buffer | undefined {
  const source = env.RUNFREE_TEST_CLIPBOARD_IMAGE_PATH;
  if (!source) return undefined;
  const stat = fs.lstatSync(source);
  if (stat.isSymbolicLink() || !stat.isFile()) {
    die(`test clipboard image must be a normal file: ${source}`);
  }
  const buffer = fs.readFileSync(source);
  assertImageBuffer(buffer, "test clipboard image");
  return buffer;
}

const MACOS_CLIPBOARD_SCRIPT = `
on writeDataToFile(theData, outputPath)
  set outFile to open for access (POSIX file outputPath) with write permission
  try
    set eof outFile to 0
    write theData to outFile
  on error errMsg number errNum
    try
      close access outFile
    end try
    error errMsg number errNum
  end try
  close access outFile
end writeDataToFile

on run argv
  set outputPath to item 1 of argv
  try
    set imageData to the clipboard as «class PNGf»
    my writeDataToFile(imageData, outputPath)
    return
  on error
    try
      set tiffPath to outputPath & ".tiff"
      set imageData to the clipboard as «class TIFF»
      my writeDataToFile(imageData, tiffPath)
      do shell script "/usr/bin/sips -s format png " & quoted form of tiffPath & " --out " & quoted form of outputPath & " >/dev/null"
      return
    on error
      try
        set imageFile to the clipboard as «class furl»
        do shell script "/usr/bin/sips -s format png " & quoted form of POSIX path of imageFile & " --out " & quoted form of outputPath & " >/dev/null"
        return
      on error errMsg
        error "clipboard does not contain a PNG, TIFF, or image file URL: " & errMsg
      end try
    end try
  end try
end run
`;

function readMacClipboardImage(env: NodeJS.ProcessEnv): Buffer {
  if (process.platform !== "darwin") {
    die("inbox paste is currently supported on macOS, or in tests with RUNFREE_TEST_CLIPBOARD_IMAGE_PATH");
  }
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-clipboard-"));
  const scriptPath = path.join(tmpDir, "paste-image.applescript");
  const outputPath = path.join(tmpDir, "clipboard.png");
  try {
    fs.writeFileSync(scriptPath, MACOS_CLIPBOARD_SCRIPT, { mode: 0o600 });
    const result = childProcess.spawnSync("osascript", [scriptPath, outputPath], {
      encoding: "utf8",
      env,
    });
    if (result.status !== 0) {
      const detail = `${result.stderr}\n${result.stdout}`.trim();
      die(detail || "clipboard does not contain an image");
    }
    const buffer = fs.readFileSync(outputPath);
    assertImageBuffer(buffer, "clipboard");
    return buffer;
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

function readClipboardImage(env: NodeJS.ProcessEnv): Buffer {
  return readTestClipboardImage(env) ?? readMacClipboardImage(env);
}

export function importImageFromClipboard(options: ImportImageOptions): ImportedImage {
  const env = options.env ?? process.env;
  ensureInbox(options.hostInbox);
  const buffer = readClipboardImage(env);
  const now = options.now ?? new Date();

  for (let attempt = 0; attempt < 10; attempt += 1) {
    const suffix = attempt === 0 ? randomImageSuffix(env) : crypto.randomBytes(2).toString("hex");
    const filename = importedImageName(now, Buffer.from(suffix, "hex"));
    const hostPath = path.join(options.hostInbox, filename);
    try {
      fs.writeFileSync(hostPath, buffer, { mode: 0o600, flag: "wx" });
      return {
        hostPath,
        containerPath: containerInboxPath(filename),
      };
    } catch (error) {
      if (!(error instanceof Error) || !("code" in error) || error.code !== "EEXIST") throw error;
    }
  }

  die("could not allocate a unique image filename");
}

export function cleanupInbox(
  hostInbox: string,
  now = new Date(),
  options: { all?: boolean } = {},
): string[] {
  let entries: string[];
  try {
    entries = fs.readdirSync(hostInbox);
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return [];
    throw error;
  }

  const removed: string[] = [];
  for (const entry of entries) {
    if (!LEGACY_INBOX_FILE_RE.test(entry)) continue;
    const imagePath = path.join(hostInbox, entry);
    const stat = fs.lstatSync(imagePath);
    if (stat.isSymbolicLink() || !stat.isFile() || stat.nlink !== 1) continue;
    if (!options.all && now.getTime() - stat.mtimeMs <= INBOX_CLEANUP_AGE_MS) continue;
    fs.rmSync(imagePath);
    removed.push(imagePath);
  }
  return removed.sort();
}

export function copyTextToHostClipboard(text: string, env: NodeJS.ProcessEnv = process.env): void {
  const error = tryCopyTextToHostClipboard(text, env);
  if (error) die(error);
}

export function tryCopyTextToHostClipboard(text: string, env: NodeJS.ProcessEnv = process.env): string | undefined {
  if (env.RUNFREE_TEST_CLIPBOARD_COPY_ERROR) {
    return env.RUNFREE_TEST_CLIPBOARD_COPY_ERROR;
  }
  if (process.platform !== "darwin") {
    return "--copy currently requires macOS pbcopy";
  }
  const result = childProcess.spawnSync("pbcopy", {
    encoding: "utf8",
    input: text,
    env,
  });
  if (result.status !== 0) {
    const detail = result.stderr?.trim();
    return `could not copy image path to clipboard${detail ? `: ${detail}` : ""}`;
  }
  return undefined;
}
