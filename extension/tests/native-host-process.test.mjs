import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";
import test from "node:test";

import "../src/shared.js";
import "../src/background-core.js";

const shared = globalThis.__YOUR_WALLET_SHARED__;
const { BackgroundRouter } = globalThis.__YOUR_WALLET_BACKGROUND_CORE__;
const repositoryRoot = fileURLToPath(new URL("../../", import.meta.url));
const cargoExecutable = process.platform === "win32" ? "cargo.exe" : "cargo";
const nativeHostExecutable = process.platform === "win32" ? "native-host.exe" : "native-host";
const MAX_FRAME_BYTES = 1_048_576;

class MessageQueue {
  constructor() {
    this.values = [];
    this.waiters = [];
  }

  push(value) {
    const waiter = this.waiters.shift();
    if (waiter) {
      waiter.resolve(value);
      return;
    }
    this.values.push(value);
  }

  next() {
    const value = this.values.shift();
    if (value !== undefined) {
      return Promise.resolve(value);
    }
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("Headless bridge response timed out.")), 30_000);
      this.waiters.push({
        resolve: (message) => {
          clearTimeout(timer);
          resolve(message);
        }
      });
    });
  }
}

function runCargo(args, captureStdout) {
  return new Promise((resolve, reject) => {
    const child = spawn(cargoExecutable, args, {
      cwd: repositoryRoot,
      env: { ...process.env, CARGO_TERM_COLOR: "never" },
      stdio: ["ignore", captureStdout ? "pipe" : "ignore", "ignore"],
      windowsHide: true
    });
    const chunks = [];
    let totalBytes = 0;
    if (captureStdout) {
      child.stdout.on("data", (chunk) => {
        totalBytes += chunk.length;
        if (totalBytes <= MAX_FRAME_BYTES) {
          chunks.push(chunk);
        }
      });
    }
    child.once("error", () => reject(new Error("Cargo could not start for the headless bridge test.")));
    child.once("close", (code) => {
      if (code !== 0 || totalBytes > MAX_FRAME_BYTES) {
        reject(new Error("Cargo failed while preparing the headless native host."));
        return;
      }
      resolve(Buffer.concat(chunks));
    });
  });
}

async function buildNativeHost() {
  const metadataBytes = await runCargo([
    "metadata", "--offline", "--format-version", "1", "--no-deps"
  ], true);
  let metadata;
  try {
    metadata = JSON.parse(metadataBytes.toString("utf8"));
  } catch (_error) {
    throw new Error("Cargo metadata was invalid for the headless bridge test.");
  }
  if (typeof metadata.target_directory !== "string" || metadata.target_directory.length === 0) {
    throw new Error("Cargo metadata omitted the headless bridge target directory.");
  }
  await runCargo(["build", "--offline", "--locked", "-p", "native-host"], false);
  return path.join(metadata.target_directory, "debug", nativeHostExecutable);
}

function encodeFrame(message) {
  const payload = Buffer.from(JSON.stringify(message), "utf8");
  assert.ok(payload.length > 0 && payload.length <= MAX_FRAME_BYTES);
  const length = Buffer.alloc(4);
  length.writeUInt32LE(payload.length, 0);
  return Buffer.concat([length, payload]);
}

function connectNativeHost(executable, onMessage, onDisconnect) {
  const child = spawn(executable, [], {
    cwd: repositoryRoot,
    stdio: ["pipe", "pipe", "ignore"],
    windowsHide: true
  });
  let buffered = Buffer.alloc(0);
  child.stdout.on("data", (chunk) => {
    buffered = Buffer.concat([buffered, chunk]);
    while (buffered.length >= 4) {
      const length = buffered.readUInt32LE(0);
      assert.ok(length > 0 && length <= MAX_FRAME_BYTES);
      if (buffered.length < 4 + length) {
        return;
      }
      const payload = buffered.subarray(4, 4 + length);
      buffered = buffered.subarray(4 + length);
      onMessage(JSON.parse(payload.toString("utf8")));
    }
  });
  const closed = new Promise((resolve, reject) => {
    child.once("error", () => reject(new Error("The headless native host could not start.")));
    child.once("close", (code, signal) => resolve({ code, signal }));
  });
  child.once("close", () => onDisconnect());
  return {
    child,
    closed,
    transport: Object.freeze({
      send: (message) => child.stdin.write(encodeFrame(message)),
      disconnect: () => child.stdin.end()
    })
  };
}

test("BackgroundRouter keeps one real release-disabled native-host stream alive", {
  timeout: 120_000
}, async (context) => {
  const executable = await buildNativeHost();
  const delivered = new MessageQueue();
  const nativeResponses = [];
  let nativeFactoryCalls = 0;
  let nativeProcess = null;

  const router = new BackgroundRouter({
    profileInstallId: "a".repeat(64),
    sessionId: "b".repeat(64),
    extensionId: "abcdefghijklmnopabcdefghijklmnop",
    randomHex: (() => {
      let nonce = 12;
      return () => (nonce++).toString(16).padStart(64, "0");
    })(),
    now: () => 1_700_000_000_000,
    nativeFactory: ({ onMessage, onDisconnect }) => {
      nativeFactoryCalls += 1;
      nativeProcess = connectNativeHost(executable, (message) => {
        nativeResponses.push(message);
        onMessage(message);
      }, onDisconnect);
      return nativeProcess.transport;
    }
  });

  context.after(() => {
    if (nativeProcess?.child.exitCode === null) {
      nativeProcess.child.stdin.destroy();
      nativeProcess.child.kill();
    }
  });

  const handle = router.attachContent({
    sender: {
      tab: { id: 17, incognito: false },
      frameId: 0,
      documentId: "document-17",
      documentLifecycle: "active",
      origin: "https://dapp.example",
      url: "https://dapp.example/headless"
    },
    postMessage: (message) => delivered.push(message)
  });
  assert.equal((await delivered.next()).kind, "activated");

  for (const [index, requestId] of ["01", "02"].entries()) {
    assert.equal(handle.receive({
      namespace: shared.NAMESPACE,
      version: shared.PROTOCOL_VERSION,
      kind: "request",
      activationNonce: handle.activationNonce,
      id: requestId.repeat(16),
      method: "eth_chainId",
      params: []
    }), true);
    const response = await delivered.next();
    assert.equal(response.kind, "response");
    assert.equal(response.id, requestId.repeat(16));
    assert.equal(response.error.code, 4900);
    assert.equal(nativeResponses[index].sequence, index + 1);
    assert.equal(nativeResponses[index].requestSequence, index + 1);
  }

  assert.equal(nativeFactoryCalls, 1);
  router.shutdown();
  const termination = await nativeProcess.closed;
  assert.deepEqual(termination, { code: 78, signal: null });
});
