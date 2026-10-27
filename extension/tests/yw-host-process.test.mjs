// H1 (spec/05 §10.1): runs the real target/debug/yw-host.exe against a fake yw-app pipe server.
// Missing binary: fails when YW_CHECK=1 (scripts/check.ps1), otherwise the tests are skipped.
// Every case sets YW_TEST_PIPE_NAME to a fresh \\.\pipe\YourWallet.test.h1.<pid>.<n>, so the real
// wallet pipe is never used; the no-server cases disable spawning, so yw-app is never started.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const HOST = fileURLToPath(new URL("../../target/debug/yw-host.exe", import.meta.url));
const ID = readFileSync(new URL("../extension-id.txt", import.meta.url), "utf8").trim();
const ORIGIN = `chrome-extension://${ID}/`;
const goldenText = (name) => readFileSync(new URL(`../native-host/${name}`, import.meta.url), "utf8");
const REQUEST_TEXT = goldenText("v1-request.golden.json");
const RESULT_TEXT = goldenText("v1-response-result.golden.json");
const UNAVAILABLE = JSON.parse(goldenText("v1-unavailable-response.golden.json"));
const HELLO = JSON.parse(goldenText("pipe-hello.golden.json"));
const ACK = JSON.parse(goldenText("pipe-hello-ack.golden.json"));

const missing = !existsSync(HOST);
const skip = missing && process.env.YW_CHECK !== "1" ? "target/debug/yw-host.exe not built" : false;

let nextPipe = 0;
const uniquePipe = () => `\\\\.\\pipe\\YourWallet.test.h1.${process.pid}.${nextPipe++}`;

function frame(payload) {
  const body = Buffer.isBuffer(payload) ? payload : Buffer.from(payload, "utf8");
  const head = Buffer.alloc(4);
  head.writeUInt32LE(body.length);
  return Buffer.concat([head, body]);
}

/** Splits a byte stream into 4-byte-LE-length frames; keeps every raw byte. */
class FrameStream {
  constructor(stream) {
    this.pending = Buffer.alloc(0);
    this.raw = [];
    this.frames = [];
    this.waiters = [];
    stream.on("data", (chunk) => this.push(chunk));
  }

  push(chunk) {
    this.raw.push(chunk);
    this.pending = Buffer.concat([this.pending, chunk]);
    while (this.pending.length >= 4) {
      const length = this.pending.readUInt32LE(0);
      if (this.pending.length < 4 + length) break;
      const body = Buffer.from(this.pending.subarray(4, 4 + length));
      this.pending = this.pending.subarray(4 + length);
      const waiter = this.waiters.shift();
      if (waiter) waiter(body);
      else this.frames.push(body);
    }
  }

  next(ms = 5_000) {
    if (this.frames.length > 0) return Promise.resolve(this.frames.shift());
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`no frame within ${ms} ms`)), ms);
      this.waiters.push((body) => {
        clearTimeout(timer);
        resolve(body);
      });
    });
  }

  bytes() {
    return Buffer.concat(this.raw);
  }
}

function startHost(args, extraEnv) {
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("YW_TEST_")));
  const child = spawn(HOST, args, { env: { ...env, ...extraEnv }, stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
  child.stdin.on("error", () => {});
  const stdout = new FrameStream(child.stdout);
  let stderr = "";
  child.stderr.on("data", (chunk) => { stderr += chunk.toString("utf8"); });
  const closed = new Promise((resolve, reject) => {
    child.on("error", reject);
    child.on("close", (code) => resolve(code));
  });
  return { child, stdout, closed, stderr: () => stderr };
}

/** Fake yw-app: validates the hello shape, then answers the golden hello-ack (or `reply`). */
async function startFakeApp(pipeName, reply = ACK) {
  const server = net.createServer();
  const connection = new Promise((resolve) => {
    server.once("connection", async (socket) => {
      socket.on("error", () => {});
      const app = new FrameStream(socket);
      const helloFrame = await app.next();
      const hello = JSON.parse(helloFrame.toString("utf8"));
      const valid = JSON.stringify(Object.keys(hello)) === JSON.stringify(Object.keys(HELLO))
        && hello.kind === "hello" && hello.protocol === 1 && hello.extensionOrigin === ORIGIN
        && typeof hello.hostVersion === "string" && hello.hostVersion.length >= 1 && hello.hostVersion.length <= 32
        && Number.isInteger(hello.pid) && hello.pid > 0;
      socket.write(frame(JSON.stringify(valid ? reply : { kind: "hello-reject", reason: "origin" })));
      resolve({ socket, app, hello, helloFrame });
    });
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(pipeName, resolve);
  });
  return { server, connection };
}

test("H1 yw-host.exe is built", { skip }, () => {
  assert.equal(missing, false, "target/debug/yw-host.exe missing: cargo build -p yw-host --offline --locked");
});

test("H1 hello format and byte-identical relay in both directions", { skip }, async () => {
  const pipeName = uniquePipe();
  const { server, connection } = await startFakeApp(pipeName);
  try {
    const host = startHost([ORIGIN, "--parent-window=0"], { YW_TEST_PIPE_NAME: pipeName });
    const { socket, app, hello, helloFrame } = await connection;
    assert.deepEqual(Object.keys(hello), Object.keys(HELLO));
    assert.deepEqual(hello, { ...HELLO, hostVersion: hello.hostVersion, extensionOrigin: ORIGIN, pid: host.child.pid });
    assert.match(hello.hostVersion, /^\d+\.\d+\.\d+/u);

    // Chrome → yw-app: the pretty-printed golden and non-JSON bytes pass unchanged.
    const fromChrome = Buffer.concat([frame(REQUEST_TEXT), frame(Buffer.from([0x7b, 0x00, 0xff, 0x0a, 0x7d]))]);
    host.child.stdin.write(fromChrome);
    await app.next();
    await app.next();
    assert.ok(app.bytes().equals(Buffer.concat([frame(helloFrame), fromChrome])));

    // yw-app → Chrome.
    const fromApp = Buffer.concat([frame(RESULT_TEXT), frame("{}")]);
    socket.write(fromApp);
    await host.stdout.next();
    await host.stdout.next();
    assert.ok(host.stdout.bytes().equals(fromApp));

    // yw-app closes the pipe → pipe EOF → exit 0.
    socket.destroy();
    assert.equal(await host.closed, 0);
    assert.equal(host.stderr(), "");
  } finally {
    server.close();
  }
});

test("H1 wrong origin argument exits 2 with no stdout", { skip }, async () => {
  const cases = [[`chrome-extension://${ID}`], [ORIGIN.toUpperCase()], ["chrome-extension://abcdefghijklmnopabcdefghijklmnop/"], []];
  for (const args of cases) {
    const host = startHost(args, { YW_TEST_PIPE_NAME: uniquePipe(), YW_TEST_NO_SPAWN: "1" });
    host.child.stdin.write(frame(REQUEST_TEXT));
    assert.equal(await host.closed, 2, JSON.stringify(args));
    assert.equal(host.stdout.bytes().length, 0);
    assert.match(host.stderr(), /^yw-host: args\r?\n$/u);
  }
});

test("H1 no server with YW_TEST_NO_SPAWN=1 answers one 4900 and exits 3", { skip }, async () => {
  const host = startHost([ORIGIN], { YW_TEST_PIPE_NAME: uniquePipe(), YW_TEST_NO_SPAWN: "1" });
  host.child.stdin.write(frame(REQUEST_TEXT));
  const response = await host.stdout.next(3_000);
  assert.deepEqual(JSON.parse(response.toString("utf8")), UNAVAILABLE);
  assert.equal(await host.closed, 3);
  assert.ok(host.stdout.bytes().equals(frame(response)));
  assert.match(host.stderr(), /^yw-host: unavailable\r?\n$/u);
});

test("H1 no server with browserAutoLaunch false answers 4900 within 2 s and exits 3", { skip }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "yw-host-h1-"));
  try {
    writeFileSync(join(dir, "settings.json"), '{"version":1,"browserAutoLaunch":false}');
    const started = Date.now();
    const host = startHost([ORIGIN], { YW_TEST_PIPE_NAME: uniquePipe(), YW_TEST_DATA_DIR: dir });
    host.child.stdin.write(frame(REQUEST_TEXT));
    const response = await host.stdout.next(2_000);
    assert.ok(Date.now() - started < 2_000);
    assert.deepEqual(JSON.parse(response.toString("utf8")), UNAVAILABLE);
    assert.equal(await host.closed, 3);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("H1 hello-reject switches to UNAVAILABLE", { skip }, async () => {
  const pipeName = uniquePipe();
  const { server, connection } = await startFakeApp(pipeName, { kind: "hello-reject", reason: "protocol" });
  try {
    const host = startHost([ORIGIN], { YW_TEST_PIPE_NAME: pipeName });
    host.child.stdin.write(frame(REQUEST_TEXT));
    const { socket } = await connection;
    const response = await host.stdout.next(3_000);
    assert.deepEqual(JSON.parse(response.toString("utf8")), UNAVAILABLE);
    assert.equal(await host.closed, 3);
    socket.destroy();
  } finally {
    server.close();
  }
});
