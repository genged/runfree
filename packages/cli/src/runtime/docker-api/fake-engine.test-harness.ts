import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Worker } from "node:worker_threads";

/**
 * A fake Docker Engine API on a Unix socket in a temp dir, for transport
 * tests. It runs in its own worker thread because the transport blocks the
 * test's thread in `Atomics.wait` for the length of every call.
 *
 * Replies are scripted per `METHOD path` (path without query). A reply is
 * a JSON body with a status and headers, or a behavior: `hang` never answers,
 * `reset` destroys the connection after reading the request. Exec starts are
 * scripted by exec id: the frames to send (in the given chunks), after
 * recording every stdin byte up to the client's half-close.
 */
export type FakeReply = {
  status?: number;
  headers?: Record<string, string>;
  body?: string;
  /** Base64 body; wins over `body`. */
  bodyBase64?: string;
  behavior?: "hang" | "reset";
  /** Serve this many times, then fall through to the next reply in the list. */
  times?: number;
};

export type FakeExecStart = {
  /** Raw stream chunks, base64, written in order after the 101 head. */
  chunks?: string[];
  status?: number;
  body?: string;
  behavior?: "hang" | "reset-after-head";
};

export type FakeEngineScript = {
  replies: Record<string, FakeReply | FakeReply[]>;
  execStarts?: Record<string, FakeExecStart>;
};

export type FakeRequest = {
  method: string;
  url: string;
  headers: Record<string, string | string[] | undefined>;
  body: string;
  /** Exec start only: every stdin byte, base64, and whether the client half-closed. */
  stdinBase64?: string;
  halfClosed?: boolean;
};

const FAKE_ENGINE_SOURCE = String.raw`
"use strict";
const { parentPort, workerData } = require("node:worker_threads");
const http = require("node:http");
let script = workerData.script;
const log = [];
const served = new Map();

function pick(key) {
  const entry = script.replies[key];
  if (!entry) return undefined;
  const list = Array.isArray(entry) ? entry : [entry];
  for (let index = 0; index < list.length; index += 1) {
    const reply = list[index];
    const id = key + "#" + index;
    const count = served.get(id) || 0;
    if (reply.times === undefined || count < reply.times) {
      served.set(id, count + 1);
      return reply;
    }
  }
  return list[list.length - 1];
}

const server = http.createServer((req, res) => {
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", () => {
    const url = req.url;
    const bare = url.split("?")[0];
    log.push({ method: req.method, url, headers: req.headers, body: Buffer.concat(chunks).toString("utf8") });
    const reply = pick(req.method + " " + bare);
    if (!reply) { res.statusCode = 599; res.end("{\"message\":\"unscripted\"}"); return; }
    if (reply.behavior === "hang") return;
    if (reply.behavior === "reset") { req.socket.destroy(); return; }
    res.statusCode = reply.status || 200;
    for (const [name, value] of Object.entries(reply.headers || {})) res.setHeader(name, value);
    res.end(reply.bodyBase64 !== undefined ? Buffer.from(reply.bodyBase64, "base64") : (reply.body || ""));
  });
});

server.on("upgrade", (req, socket, head) => {
  const match = /^\/v[0-9.]+\/exec\/([a-f0-9]+)\/start$/.exec(req.url);
  const bodyChunks = [];
  const stdin = [];
  const entry = { method: req.method, url: req.url, headers: req.headers, body: "", stdinBase64: "", halfClosed: false };
  log.push(entry);
  const start = match && script.execStarts ? script.execStarts[match[1]] : undefined;
  let length = Number(req.headers["content-length"] || 0);
  let buffered = head && head.length ? Buffer.from(head) : Buffer.alloc(0);
  let bodyDone = false;
  const consume = (chunk) => {
    buffered = Buffer.concat([buffered, chunk]);
    if (!bodyDone && buffered.length >= length) {
      entry.body = buffered.subarray(0, length).toString("utf8");
      buffered = buffered.subarray(length);
      bodyDone = true;
      respond();
    }
    if (bodyDone && buffered.length) { stdin.push(buffered); buffered = Buffer.alloc(0); entry.stdinBase64 = Buffer.concat(stdin).toString("base64"); }
  };
  let responded = false;
  const respond = () => {
    if (responded) return;
    responded = true;
    if (!start) { socket.end("HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: 29\r\n\r\n{\"message\":\"No such exec id\"}"); return; }
    if (start.status && start.status !== 101) {
      const body = start.body || "{}";
      socket.end("HTTP/1.1 " + start.status + " Err\r\nContent-Type: application/json\r\nContent-Length: " + Buffer.byteLength(body) + "\r\n\r\n" + body);
      return;
    }
    socket.write("HTTP/1.1 101 UPGRADED\r\nContent-Type: application/vnd.docker.multiplexed-stream\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n");
    if (start.behavior === "hang") return;
    if (start.behavior === "reset-after-head") { setTimeout(() => socket.destroy(), 5); return; }
  };
  socket.on("data", consume);
  socket.on("end", () => {
    entry.halfClosed = true;
    entry.stdinBase64 = Buffer.concat(stdin).toString("base64");
    if (!start || (start.status && start.status !== 101) || start.behavior) return;
    const chunks = (start.chunks || []).map((c) => Buffer.from(c, "base64"));
    let index = 0;
    const next = () => {
      if (index >= chunks.length) { socket.end(); return; }
      socket.write(chunks[index++]);
      setTimeout(next, 2);
    };
    next();
  });
  if (length === 0) { bodyDone = true; respond(); }
  if (buffered.length) consume(Buffer.alloc(0));
});

server.listen(workerData.socketPath, () => parentPort.postMessage({ type: "ready" }));
parentPort.on("message", (message) => {
  if (message.type === "log") parentPort.postMessage({ type: "log", log });
  if (message.type === "script") { script = message.script; served.clear(); parentPort.postMessage({ type: "scripted" }); }
  if (message.type === "close") server.close(() => parentPort.postMessage({ type: "closed" }));
});
`;

export type FakeEngine = {
  socketPath: string;
  dir: string;
  requests(): Promise<FakeRequest[]>;
  setScript(script: FakeEngineScript): Promise<void>;
  close(): Promise<void>;
};

function once<T>(worker: Worker, type: string): Promise<T> {
  return new Promise((resolve, reject) => {
    const onMessage = (message: { type: string } & T) => {
      if (message.type !== type) return;
      worker.off("message", onMessage);
      resolve(message);
    };
    worker.on("message", onMessage);
    worker.once("error", reject);
  });
}

export async function startFakeEngine(script: FakeEngineScript): Promise<FakeEngine> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-fake-engine-"));
  const socketPath = path.join(dir, "docker.sock");
  const worker = new Worker(FAKE_ENGINE_SOURCE, { eval: true, workerData: { socketPath, script } });
  await once(worker, "ready");
  return {
    socketPath,
    dir,
    async requests() {
      const reply = once<{ log: FakeRequest[] }>(worker, "log");
      worker.postMessage({ type: "log" });
      return (await reply).log;
    },
    async setScript(next) {
      const reply = once(worker, "scripted");
      worker.postMessage({ type: "script", script: next });
      await reply;
    },
    async close() {
      const reply = once(worker, "closed");
      worker.postMessage({ type: "close" });
      await Promise.race([reply, new Promise((resolve) => setTimeout(resolve, 500))]);
      await worker.terminate();
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };
}

export const DOCKER_PING: FakeReply = {
  status: 200,
  headers: { "Api-Version": "1.47", Server: "Docker/27.3.1 (linux)", Ostype: "linux", Swarm: "inactive" },
  body: "OK",
};

/** One multiplexed exec stream frame. */
export function frame(type: number, payload: string | Buffer): Buffer {
  const bytes = typeof payload === "string" ? Buffer.from(payload) : payload;
  const header = Buffer.alloc(8);
  header[0] = type;
  header.writeUInt32BE(bytes.length, 4);
  return Buffer.concat([header, bytes]);
}
