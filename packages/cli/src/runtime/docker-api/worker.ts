/**
 * The Engine API worker thread, as CommonJS source evaluated with
 * `new Worker(source, { eval: true })`.
 *
 * It is a string, not a module, so it needs no file on disk in the Bun
 * compiled binary and no loader under tsx or Vitest. It knows nothing about
 * Docker: it performs exactly one HTTP/1.1 exchange per request message over
 * the Unix socket path the main thread names, with the method, path, headers,
 * and body the main thread built, and returns the raw reply bytes. All argv
 * matching, request construction, parsing, and formatting stay on the main
 * thread in typed code.
 *
 * Control block (Int32Array over a SharedArrayBuffer, set by `init`):
 *   [0] completion counter: incremented and notified after every reply
 *   [1] dead flag: set to 1 when the worker thread exits for any reason
 *
 * No keep-alive: each request opens a fresh Unix-socket connection (well
 * under a millisecond), so a daemon-closed idle connection can never turn a
 * request into an ambiguous reset.
 */
export const DOCKER_API_WORKER_SOURCE = `
"use strict";
const { parentPort } = require("node:worker_threads");
const http = require("node:http");

let ctl;
const active = new Map();

function signalDead() {
  if (!ctl) return;
  Atomics.store(ctl, 1, 1);
  Atomics.add(ctl, 0, 1);
  Atomics.notify(ctl, 0);
}
process.on("exit", signalDead);
process.on("uncaughtException", () => {
  signalDead();
  process.exit(1);
});

function reply(id, port, message) {
  if (!active.has(id)) return;
  active.delete(id);
  try {
    port.postMessage(message);
  } catch (error) {
    try { port.postMessage({ kind: "error", code: "EPOSTMESSAGE", phase: "request" }); } catch (_) {}
  }
  try { port.close(); } catch (_) {}
  Atomics.add(ctl, 0, 1);
  Atomics.notify(ctl, 0);
}

function headersOf(res) {
  const out = {};
  for (const [name, value] of Object.entries(res.headers)) {
    if (typeof value === "string") out[name] = value;
    else if (Array.isArray(value)) out[name] = value.join(", ");
  }
  return out;
}

function start(message) {
  const id = message.id;
  const port = message.port;
  const req = message.req;
  const chunks = [];
  let bytes = 0;
  let connected = false;
  let settled = false;
  let upgraded;
  let request;

  const destroy = () => {
    try { if (request) request.destroy(); } catch (_) {}
    try { if (upgraded) upgraded.destroy(); } catch (_) {}
  };
  const done = (result) => {
    if (settled) return;
    settled = true;
    reply(id, port, result);
  };
  const collect = (chunk) => {
    if (settled) return;
    bytes += chunk.length;
    if (bytes > req.maxBytes) {
      done({ kind: "overflow" });
      destroy();
      return;
    }
    chunks.push(chunk);
  };
  const fail = (phase) => (error) => {
    done({ kind: "error", code: (error && error.code) || "EUNKNOWN", phase: connected ? phase : "connect" });
    destroy();
  };

  active.set(id, { abort() { settled = true; destroy(); } });
  try {
    request = http.request({
      socketPath: req.socketPath,
      method: req.method,
      path: req.path,
      headers: req.headers,
      agent: false,
    });
  } catch (error) {
    fail("request")(error);
    return;
  }
  request.on("socket", (socket) => {
    if (!socket.connecting) connected = true;
    else socket.once("connect", () => { connected = true; });
  });
  request.on("error", fail("request"));
  request.on("response", (res) => {
    res.on("data", collect);
    res.on("error", fail("request"));
    res.on("aborted", () => fail("request")({ code: "ECONNRESET" }));
    res.on("end", () => done({
      kind: "response",
      status: res.statusCode,
      headers: headersOf(res),
      body: Buffer.concat(chunks),
    }));
  });
  request.on("upgrade", (res, socket, head) => {
    upgraded = socket;
    if (!req.upgrade) {
      done({ kind: "error", code: "EUNEXPECTEDUPGRADE", phase: "request" });
      destroy();
      return;
    }
    let ended = false;
    socket.on("data", collect);
    socket.on("error", fail("stream"));
    socket.on("end", () => {
      ended = true;
      done({ kind: "upgraded", status: res.statusCode, headers: headersOf(res), body: Buffer.concat(chunks) });
    });
    socket.on("close", () => {
      if (!ended) fail("stream")({ code: "ECONNRESET" });
    });
    if (head && head.length > 0) collect(head);
    if (req.upgrade.stdin && req.upgrade.stdin.byteLength > 0) socket.write(Buffer.from(req.upgrade.stdin));
    socket.end();
  });
  if (req.body) request.write(Buffer.from(req.body));
  request.end();
}

parentPort.on("message", (message) => {
  if (!message || typeof message !== "object") return;
  if (message.type === "init") {
    ctl = message.ctl;
    return;
  }
  if (message.type === "abort") {
    const entry = active.get(message.id);
    if (entry) {
      active.delete(message.id);
      entry.abort();
    }
    return;
  }
  if (message.type === "request") start(message);
});
`;
