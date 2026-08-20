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
const brokerExecutable = process.platform === "win32" ? "broker.exe" : "broker";
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

async function buildBrokerContractPair() {
  const metadataBytes = await runCargo([
    "metadata", "--offline", "--format-version", "1", "--no-deps"
  ], true);
  let metadata;
  try {
    metadata = JSON.parse(metadataBytes.toString("utf8"));
  } catch (_error) {
    throw new Error("Cargo metadata was invalid for the headless Broker contract test.");
  }
  if (typeof metadata.target_directory !== "string" || metadata.target_directory.length === 0) {
    throw new Error("Cargo metadata omitted the headless Broker contract target directory.");
  }
  const targetDirectory = path.join(metadata.target_directory, "broker-ipc-contract-test");
  await runCargo([
    "build", "--offline", "--locked",
    "--target-dir", targetDirectory,
    "-p", "native-host", "-p", "broker",
    "--features", "native-host/broker-ipc-contract-test-hook,broker/ipc-contract-test-hook"
  ], false);
  return Object.freeze({
    nativeHost: path.join(targetDirectory, "debug", nativeHostExecutable),
    broker: path.join(targetDirectory, "debug", brokerExecutable)
  });
}

async function buildWindowsBrokerChannelPair() {
  const metadataBytes = await runCargo([
    "metadata", "--offline", "--format-version", "1", "--no-deps"
  ], true);
  let metadata;
  try {
    metadata = JSON.parse(metadataBytes.toString("utf8"));
  } catch (_error) {
    throw new Error("Cargo metadata was invalid for the Windows Broker channel test.");
  }
  if (typeof metadata.target_directory !== "string" || metadata.target_directory.length === 0) {
    throw new Error("Cargo metadata omitted the Windows Broker channel target directory.");
  }
  const targetDirectory = path.join(metadata.target_directory, "windows-broker-channel-contract-test");
  await runCargo([
    "build", "--offline", "--locked",
    "--target-dir", targetDirectory,
    "-p", "native-host", "-p", "broker",
    "--features",
    "native-host/windows-broker-channel-contract-test-hook,broker/windows-broker-channel-contract-test-hook"
  ], false);
  return Object.freeze({
    nativeHost: path.join(targetDirectory, "debug", nativeHostExecutable),
    broker: path.join(targetDirectory, "debug", brokerExecutable)
  });
}

async function buildReleaseFeaturePair() {
  const metadataBytes = await runCargo([
    "metadata", "--offline", "--format-version", "1", "--no-deps"
  ], true);
  let metadata;
  try {
    metadata = JSON.parse(metadataBytes.toString("utf8"));
  } catch (_error) {
    throw new Error("Cargo metadata was invalid for the release feature gate.");
  }
  if (typeof metadata.target_directory !== "string" || metadata.target_directory.length === 0) {
    throw new Error("Cargo metadata omitted the release feature target directory.");
  }
  const targetDirectory = path.join(metadata.target_directory, "release-feature-gate");
  await runCargo([
    "build", "--release", "--offline", "--locked",
    "--target-dir", targetDirectory,
    "-p", "native-host", "-p", "broker", "--all-features"
  ], false);
  return Object.freeze({
    nativeHost: path.join(targetDirectory, "release", nativeHostExecutable),
    broker: path.join(targetDirectory, "release", brokerExecutable)
  });
}

function runClosedProcess(executable) {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, [], {
      cwd: repositoryRoot,
      env: {},
      stdio: "ignore",
      windowsHide: true
    });
    child.once("error", () => reject(new Error("The release gate executable could not start.")));
    child.once("close", (code, signal) => resolve({ code, signal }));
  });
}

function encodeFrame(message) {
  const payload = Buffer.from(JSON.stringify(message), "utf8");
  assert.ok(payload.length > 0 && payload.length <= MAX_FRAME_BYTES);
  const length = Buffer.alloc(4);
  length.writeUInt32LE(payload.length, 0);
  return Buffer.concat([length, payload]);
}

function connectNativeHost(executable, onMessage, onDisconnect, env = process.env) {
  const child = spawn(executable, [], {
    cwd: repositoryRoot,
    env,
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

test("release all-feature binaries keep both subprocess hooks disabled", {
  timeout: 300_000
}, async (context) => {
  const executables = await buildReleaseFeaturePair();
  assert.deepEqual(await runClosedProcess(executables.broker), { code: 78, signal: null });

  const delivered = new MessageQueue();
  let nativeProcess = null;
  const router = new BackgroundRouter({
    profileInstallId: "a".repeat(64),
    sessionId: "b".repeat(64),
    extensionId: "abcdefghijklmnopabcdefghijklmnop",
    randomHex: (() => {
      let nonce = 70;
      return () => (nonce++).toString(16).padStart(64, "0");
    })(),
    now: () => 1_700_000_000_000,
    nativeFactory: ({ onMessage, onDisconnect }) => {
      nativeProcess = connectNativeHost(
        executables.nativeHost,
        onMessage,
        onDisconnect,
        {}
      );
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
      documentId: "document-release-feature-gate",
      documentLifecycle: "active",
      origin: "https://dapp.example",
      url: "https://dapp.example/release-feature-gate"
    },
    postMessage: (message) => delivered.push(message)
  });
  assert.equal((await delivered.next()).kind, "activated");
  assert.equal(handle.receive({
    namespace: shared.NAMESPACE,
    version: shared.PROTOCOL_VERSION,
    kind: "request",
    activationNonce: handle.activationNonce,
    id: "21".repeat(16),
    method: "eth_chainId",
    params: []
  }), true);
  const response = await delivered.next();
  assert.equal(response.error.code, 4900);
  router.shutdown();
  assert.deepEqual(await nativeProcess.closed, { code: 78, signal: null });
});

test("BackgroundRouter reaches the debug-only secretless Broker over real subprocess IPC", {
  timeout: 120_000
}, async (context) => {
  const executables = await buildBrokerContractPair();
  const delivered = new MessageQueue();
  const nativeProcesses = [];

  const router = new BackgroundRouter({
    profileInstallId: "a".repeat(64),
    sessionId: "b".repeat(64),
    extensionId: "abcdefghijklmnopabcdefghijklmnop",
    randomHex: (() => {
      let nonce = 40;
      return () => (nonce++).toString(16).padStart(64, "0");
    })(),
    now: () => Date.now(),
    nativeFactory: ({ onMessage, onDisconnect }) => {
      const requests = [];
      const responses = [];
      const nativeProcess = connectNativeHost(executables.nativeHost, (message) => {
        responses.push(message);
        onMessage(message);
      }, onDisconnect);
      nativeProcess.requests = requests;
      nativeProcess.responses = responses;
      nativeProcesses.push(nativeProcess);
      return Object.freeze({
        send: (message) => {
          requests.push(message);
          return nativeProcess.transport.send(message);
        },
        disconnect: nativeProcess.transport.disconnect
      });
    }
  });

  context.after(() => {
    for (const nativeProcess of nativeProcesses) {
      if (nativeProcess.child.exitCode === null) {
        nativeProcess.child.stdin.destroy();
        nativeProcess.child.kill();
      }
    }
  });

  const handle = router.attachContent({
    sender: {
      tab: { id: 17, incognito: false },
      frameId: 0,
      documentId: "document-broker-contract",
      documentLifecycle: "active",
      origin: "https://dapp.example",
      url: "https://dapp.example/broker-contract"
    },
    postMessage: (message) => delivered.push(message)
  });
  assert.equal((await delivered.next()).kind, "activated");

  const requests = [
    { id: "31".repeat(16), method: "eth_chainId", params: [] },
    { id: "32".repeat(16), method: "personal_sign", params: ["0x", "0x0000000000000000000000000000000000000000"] },
    { id: "33".repeat(16), method: "eth_chainId", params: [] }
  ];
  for (const request of requests) {
    assert.equal(handle.receive({
      namespace: shared.NAMESPACE,
      version: shared.PROTOCOL_VERSION,
      kind: "request",
      activationNonce: handle.activationNonce,
      ...request
    }), true);
    const response = await delivered.next();
    assert.equal(response.kind, "response");
    assert.equal(response.id, request.id);
    if (request.method === "eth_chainId") {
      assert.equal(response.result, "0xaa36a7");
    } else {
      assert.equal(response.error.code, 4900);
    }
  }

  const firstProcess = nativeProcesses[0];
  assert.equal(nativeProcesses.length, 1);
  assert.deepEqual(firstProcess.responses.map((response) => response.sequence), [1, 2, 3]);
  assert.deepEqual(firstProcess.responses.map((response) => response.requestSequence), [1, 2, 3]);

  const cancelledMessages = [];
  const cancelled = router.attachContent({
    sender: {
      tab: { id: 18, incognito: false },
      frameId: 0,
      documentId: "document-cancelled-contract",
      documentLifecycle: "active",
      origin: "https://dapp.example",
      url: "https://dapp.example/cancelled-contract"
    },
    postMessage: (message) => cancelledMessages.push(message)
  });
  assert.equal(cancelled.receive({
    namespace: shared.NAMESPACE,
    version: shared.PROTOCOL_VERSION,
    kind: "request",
    activationNonce: cancelled.activationNonce,
    id: "34".repeat(16),
    method: "eth_chainId",
    params: []
  }), true);
  cancelled.disconnect("navigation");

  const afterCancel = new MessageQueue();
  const afterCancelHandle = router.attachContent({
    sender: {
      tab: { id: 19, incognito: false },
      frameId: 0,
      documentId: "document-after-cancel",
      documentLifecycle: "active",
      origin: "https://dapp.example",
      url: "https://dapp.example/after-cancel"
    },
    postMessage: (message) => afterCancel.push(message)
  });
  assert.equal((await afterCancel.next()).kind, "activated");
  assert.equal(afterCancelHandle.receive({
    namespace: shared.NAMESPACE,
    version: shared.PROTOCOL_VERSION,
    kind: "request",
    activationNonce: afterCancelHandle.activationNonce,
    id: "35".repeat(16),
    method: "eth_chainId",
    params: []
  }), true);
  const afterCancelResponse = await afterCancel.next();
  assert.equal(afterCancelResponse.result, "0xaa36a7");
  assert.equal(cancelledMessages.some((message) => (
    message.kind === "response" && message.id === "34".repeat(16)
  )), false);
  assert.deepEqual(firstProcess.requests.map((message) => message.sequence), [1, 2, 3, 4, 5, 6]);
  assert.deepEqual(firstProcess.requests.map((message) => message.kind), [
    "request", "request", "request", "request", "cancel", "request"
  ]);
  assert.equal(firstProcess.requests[4].requestSequence, 4);
  assert.deepEqual(firstProcess.responses.map((response) => response.sequence), [1, 2, 3, 4, 5]);
  assert.deepEqual(firstProcess.responses.map((response) => response.requestSequence), [1, 2, 3, 4, 6]);

  const firstSession = firstProcess.requests[0].sessionId;
  router.reconnectNative();
  assert.equal(nativeProcesses.length, 2);
  const firstTermination = await firstProcess.closed;
  assert.deepEqual(firstTermination, { code: 78, signal: null });

  const reconnected = new MessageQueue();
  const reconnectedHandle = router.attachContent({
    sender: {
      tab: { id: 20, incognito: false },
      frameId: 0,
      documentId: "document-reconnected-contract",
      documentLifecycle: "active",
      origin: "https://dapp.example",
      url: "https://dapp.example/reconnected-contract"
    },
    postMessage: (message) => reconnected.push(message)
  });
  assert.equal((await reconnected.next()).kind, "activated");
  assert.equal(reconnectedHandle.receive({
    namespace: shared.NAMESPACE,
    version: shared.PROTOCOL_VERSION,
    kind: "request",
    activationNonce: reconnectedHandle.activationNonce,
    id: "36".repeat(16),
    method: "eth_chainId",
    params: []
  }), true);
  const reconnectedResponse = await reconnected.next();
  assert.equal(reconnectedResponse.result, "0xaa36a7");
  const secondProcess = nativeProcesses[1];
  assert.equal(secondProcess.requests[0].sequence, 1);
  assert.notEqual(secondProcess.requests[0].sessionId, firstSession);
  assert.deepEqual(secondProcess.responses.map((response) => response.sequence), [1]);

  router.shutdown();
  const secondTermination = await secondProcess.closed;
  assert.deepEqual(secondTermination, { code: 78, signal: null });
});

test("Windows native host reaches the exact hidden Broker channel without stdio composition", {
  timeout: 180_000,
  skip: process.platform !== "win32"
}, async (context) => {
  const executables = await buildWindowsBrokerChannelPair();
  const delivered = new MessageQueue();
  let nativeProcess = null;
  const router = new BackgroundRouter({
    profileInstallId: "a".repeat(64),
    sessionId: "b".repeat(64),
    extensionId: "abcdefghijklmnopabcdefghijklmnop",
    randomHex: (() => {
      let nonce = 90;
      return () => (nonce++).toString(16).padStart(64, "0");
    })(),
    now: () => Date.now(),
    nativeFactory: ({ onMessage, onDisconnect }) => {
      nativeProcess = connectNativeHost(executables.nativeHost, onMessage, onDisconnect);
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
      tab: { id: 41, incognito: false },
      frameId: 0,
      documentId: "document-windows-broker-channel",
      documentLifecycle: "active",
      origin: "https://dapp.example",
      url: "https://dapp.example/windows-broker-channel"
    },
    postMessage: (message) => delivered.push(message)
  });
  assert.equal((await delivered.next()).kind, "activated");

  for (const request of [
    { id: "41".repeat(16), method: "eth_chainId", params: [] },
    {
      id: "42".repeat(16),
      method: "personal_sign",
      params: ["0x", "0x0000000000000000000000000000000000000000"]
    }
  ]) {
    assert.equal(handle.receive({
      namespace: shared.NAMESPACE,
      version: shared.PROTOCOL_VERSION,
      kind: "request",
      activationNonce: handle.activationNonce,
      ...request
    }), true);
    const response = await delivered.next();
    assert.equal(response.kind, "response");
    assert.equal(response.id, request.id);
    if (request.method === "eth_chainId") {
      assert.equal(response.result, "0xaa36a7");
    } else {
      assert.equal(response.error.code, 4900);
    }
  }

  router.shutdown();
  assert.deepEqual(await nativeProcess.closed, { code: 78, signal: null });
});
