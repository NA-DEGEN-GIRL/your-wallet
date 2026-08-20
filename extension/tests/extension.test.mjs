import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { fileURLToPath } from "node:url";

await import("../src/shared.js");
await import("../src/content-core.js");
await import("../src/background-core.js");

const shared = globalThis.__YOUR_WALLET_SHARED__;
const { ContentBridge } = globalThis.__YOUR_WALLET_CONTENT_CORE__;
const { BackgroundRouter, deriveSenderContext } = globalThis.__YOUR_WALLET_BACKGROUND_CORE__;

const PROFILE_ID = "a".repeat(64);
const SESSION_ID = "b".repeat(64);
const ACTIVATION_ID = "c".repeat(64);
const CHANNEL_ID = "d".repeat(64);
const EXTENSION_ID = "abcdefghijklmnopabcdefghijklmnop";
const FIRST_PORT_ACTIVATION_ID = "c".padStart(64, "0");
const FIRST_PORT_CHANNEL_ID = "d".padStart(64, "0");
const REQUEST_IDS = Object.freeze({
  "request-1": "01".repeat(16),
  "request-2": "02".repeat(16),
  "spoof-1": "03".repeat(16),
  "real-1": "04".repeat(16),
  "duplicate-1": "05".repeat(16),
  "replay-1": "06".repeat(16),
  "navigation-1": "07".repeat(16),
  "first-1": "08".repeat(16),
  "second-1": "09".repeat(16),
  "third-1": "0a".repeat(16),
  "large-1": "0b".repeat(16),
  "large-native-1": "0c".repeat(16),
  "content-large": "0d".repeat(16),
  "content-normal": "0e".repeat(16),
  "content-1": "0f".repeat(16),
  "content-duplicate": "10".repeat(16)
});

function requestId(label) {
  return REQUEST_IDS[label] || label;
}

function sender(url = "https://dapp.example/account") {
  const parsed = new URL(url);
  return {
    tab: { id: 17, incognito: false },
    frameId: 0,
    documentId: "document-17",
    documentLifecycle: "active",
    origin: parsed.origin,
    url: parsed.href
  };
}

function contentRequest(activationNonce, id, method = "eth_chainId", params = []) {
  return {
    namespace: shared.NAMESPACE,
    version: shared.PROTOCOL_VERSION,
    kind: "request",
    activationNonce,
    id: requestId(id),
    method,
    params
  };
}

function pageRequest(id, method = "eth_chainId", params = []) {
  return {
    namespace: shared.NAMESPACE,
    version: shared.PROTOCOL_VERSION,
    channel: CHANNEL_ID,
    kind: "request",
    id: requestId(id),
    method,
    params
  };
}

class FakeNative {
  constructor() {
    this.connections = [];
  }

  factory = ({ hostName, onMessage, onDisconnect }) => {
    const connection = {
      hostName,
      onMessage,
      onDisconnect,
      sent: [],
      closed: false,
      send(message) {
        if (this.closed) {
          throw new Error("closed");
        }
        this.sent.push(message);
      },
      disconnect() {
        if (!this.closed) {
          this.closed = true;
          onDisconnect();
        }
      }
    };
    this.connections.push(connection);
    return connection;
  };
}

function makeRouter(fakeNative = new FakeNative()) {
  let nonceCounter = 12;
  const router = new BackgroundRouter({
    profileInstallId: PROFILE_ID,
    sessionId: SESSION_ID,
    extensionId: EXTENSION_ID,
    randomHex: () => (nonceCounter++).toString(16).padStart(64, "0"),
    now: () => 1_700_000_000_000,
    nativeFactory: fakeNative.factory
  });
  return { fakeNative, router };
}

function nativeSuccess(nativeRequest, result, sequence = 1) {
  return {
    namespace: shared.NAMESPACE,
    version: shared.PROTOCOL_VERSION,
    role: "native-host",
    kind: "response",
    sessionId: SESSION_ID,
    sequence,
    requestSequence: nativeRequest.sequence,
    activationNonce: nativeRequest.activationNonce,
    requestId: nativeRequest.requestId,
    result
  };
}

test("strict schemas reject context injection and non-JSON parameters", () => {
  const validPage = pageRequest("request-1");
  assert.equal(shared.parsePageRequest(validPage, CHANNEL_ID)?.id, requestId("request-1"));
  assert.equal(shared.parsePageRequest({ ...validPage, context: { origin: "https://spoof.example" } }, CHANNEL_ID), null);
  assert.equal(shared.parsePageRequest({ ...validPage, params: [1n] }, CHANNEL_ID), null);

  const validContent = contentRequest(ACTIVATION_ID, "request-2");
  assert.equal(shared.parseContentRequest(validContent, ACTIVATION_ID)?.id, requestId("request-2"));
  assert.equal(shared.parseContentRequest({ ...validContent, tabId: 999 }, ACTIVATION_ID), null);
  assert.equal(shared.parseContentRequest({ ...validContent, origin: "https://spoof.example" }, ACTIVATION_ID), null);
});

test("method firewall is exact, case-sensitive, and blocks raw or administrative APIs", () => {
  assert.equal(shared.methodRoute("eth_sendTransaction"), "signing");
  assert.equal(shared.methodRoute("personal_sign"), "signing");
  assert.equal(shared.methodRoute("eth_getBalance"), "read");
  assert.equal(shared.methodRoute("wallet_requestPermissions"), "permission");

  for (const blocked of [
    "eth_sign",
    "eth_signTransaction",
    "eth_sendRawTransaction",
    "eth_signTypedData",
    "eth_signTypedData_v1",
    "eth_signTypedData_v3",
    "wallet_sendCalls",
    "wallet_getCallsStatus",
    "wallet_showCallsStatus",
    "eth_decrypt",
    "eth_getEncryptionPublicKey",
    "personal_unlockAccount",
    "admin_peers",
    "debug_traceTransaction",
    "Eth_SendTransaction"
  ]) {
    assert.equal(shared.methodRoute(blocked), null, blocked);
  }
});

test("sender-owned context is top-level HTTPS and cannot be spoofed by page data", () => {
  const { fakeNative, router } = makeRouter();
  const delivered = [];
  const browserSender = {
    ...sender("https://dapp.example/private/path?fixture=value#fragment"),
    browserFamily: "spoof",
    extensionId: "ponmlkjihgfedcbaponmlkjihgfedcba",
    topOrigin: "https://spoof.example",
    frameOrigin: "https://spoof.example",
    channelNonce: "f".repeat(64)
  };
  const handle = router.attachContent({ sender: browserSender, postMessage: (message) => delivered.push(message) });
  assert.equal(handle.activationNonce, FIRST_PORT_ACTIVATION_ID);

  const injected = {
    ...contentRequest(handle.activationNonce, "spoof-1"),
    context: {
      browserFamily: "spoof",
      extensionId: "spoof",
      tabId: 999,
      topOrigin: "https://spoof.example",
      frameOrigin: "https://spoof.example",
      documentLifecycle: "active",
      channelNonce: "0".repeat(64)
    }
  };
  assert.equal(handle.receive(injected), false);
  assert.equal(fakeNative.connections.length, 0);
  assert.equal(delivered.filter((message) => message.id === requestId("spoof-1")).length, 1);

  assert.equal(handle.receive(contentRequest(handle.activationNonce, "real-1")), true);
  const nativeRequest = fakeNative.connections[0].sent[0];
  assert.deepEqual(nativeRequest.context, {
    browserFamily: "chrome",
    extensionId: EXTENSION_ID,
    tabId: 17,
    frameId: 0,
    documentId: "document-17",
    topOrigin: "https://dapp.example",
    frameOrigin: "https://dapp.example",
    documentLifecycle: "active",
    channelNonce: FIRST_PORT_CHANNEL_ID
  });
  assert.equal(Object.prototype.hasOwnProperty.call(nativeRequest.context, "incognito"), false);
  assert.notEqual(nativeRequest.context.channelNonce, handle.activationNonce);
  assert.equal(Object.prototype.hasOwnProperty.call(nativeRequest.context, "url"), false);
  assert.equal(JSON.stringify(nativeRequest.context).includes("private/path"), false);
  assert.equal(JSON.stringify(nativeRequest.context).includes("fixture=value"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(nativeRequest.params, "context"), false);

  const configuration = (value) => ({
    sender: value,
    extensionId: EXTENSION_ID,
    channelNonce: CHANNEL_ID
  });
  assert.throws(() => deriveSenderContext(configuration({ ...sender(), frameId: 2 })), /top-level/u);
  assert.throws(() => deriveSenderContext(configuration(sender("http://dapp.example/"))), /HTTPS/u);
  assert.throws(() => deriveSenderContext(configuration({ ...sender(), origin: "https://spoof.example" })), /HTTPS/u);
  assert.throws(() => deriveSenderContext(configuration({ ...sender(), documentLifecycle: "prerender" })), /top-level/u);
  assert.throws(() => deriveSenderContext(configuration({
    ...sender(),
    tab: { id: 17, incognito: true }
  })), /top-level/u);
  assert.throws(() => deriveSenderContext(configuration({
    ...sender(),
    tab: { id: Number.MAX_SAFE_INTEGER + 1, incognito: false }
  })), /top-level/u);
});

test("duplicate pending request ID yields one response and invalidates the activation", () => {
  const { fakeNative, router } = makeRouter();
  const delivered = [];
  const handle = router.attachContent({ sender: sender(), postMessage: (message) => delivered.push(message) });
  const request = contentRequest(handle.activationNonce, "duplicate-1");

  assert.equal(handle.receive(request), true);
  const nativeRequest = fakeNative.connections[0].sent[0];
  assert.equal(handle.receive(request), false);
  assert.equal(fakeNative.connections[0].sent.some((message) => (
    message.kind === "cancel" && message.requestId === requestId("duplicate-1")
  )), true);
  assert.equal(delivered.filter((message) => message.kind === "response" && message.id === requestId("duplicate-1")).length, 1);
  assert.equal(delivered.some((message) => message.kind === "disconnect"), true);

  fakeNative.connections[0].onMessage(nativeSuccess(nativeRequest, "0x1"));
  assert.equal(delivered.filter((message) => message.kind === "response" && message.id === requestId("duplicate-1")).length, 1);
});

test("a replay after completion never creates a second response", () => {
  const { fakeNative, router } = makeRouter();
  const delivered = [];
  const handle = router.attachContent({ sender: sender(), postMessage: (message) => delivered.push(message) });
  const request = contentRequest(handle.activationNonce, "replay-1");

  assert.equal(handle.receive(request), true);
  const nativeRequest = fakeNative.connections[0].sent[0];
  fakeNative.connections[0].onMessage(nativeSuccess(nativeRequest, "0x1"));
  assert.equal(handle.receive(request), false);
  assert.equal(delivered.filter((message) => message.kind === "response" && message.id === requestId("replay-1")).length, 1);
});

test("content disconnect cancels native work and suppresses late responses", () => {
  const { fakeNative, router } = makeRouter();
  const delivered = [];
  const handle = router.attachContent({ sender: sender(), postMessage: (message) => delivered.push(message) });
  assert.equal(handle.receive(contentRequest(handle.activationNonce, "navigation-1")), true);
  const nativeRequest = fakeNative.connections[0].sent[0];

  handle.disconnect("navigation");
  assert.equal(fakeNative.connections[0].sent.some((message) => (
    message.kind === "cancel" && message.requestId === requestId("navigation-1")
  )), true);
  fakeNative.connections[0].onMessage(nativeSuccess(nativeRequest, "0x1"));
  assert.equal(delivered.some((message) => message.kind === "response" && message.id === requestId("navigation-1")), false);
});

test("native disconnect and reconnect cancel every pending document", () => {
  const { fakeNative, router } = makeRouter();
  const firstMessages = [];
  const secondMessages = [];
  const first = router.attachContent({ sender: sender("https://one.example/"), postMessage: (message) => firstMessages.push(message) });
  const second = router.attachContent({ sender: { ...sender("https://two.example/"), documentId: "document-18" }, postMessage: (message) => secondMessages.push(message) });
  first.receive(contentRequest(first.activationNonce, "first-1"));
  second.receive(contentRequest(second.activationNonce, "second-1"));
  const firstContext = fakeNative.connections[0].sent.find((message) => message.requestId === requestId("first-1")).context;
  const secondContext = fakeNative.connections[0].sent.find((message) => message.requestId === requestId("second-1")).context;
  assert.notEqual(firstContext.channelNonce, secondContext.channelNonce);
  assert.notEqual(firstContext.channelNonce, first.activationNonce);
  assert.notEqual(secondContext.channelNonce, second.activationNonce);

  router.reconnectNative();
  assert.equal(fakeNative.connections.length, 2);
  assert.equal(firstMessages.some((message) => message.kind === "disconnect"), true);
  assert.equal(secondMessages.some((message) => message.kind === "disconnect"), true);

  const thirdMessages = [];
  const third = router.attachContent({ sender: { ...sender("https://three.example/"), documentId: "document-19" }, postMessage: (message) => thirdMessages.push(message) });
  third.receive(contentRequest(third.activationNonce, "third-1"));
  assert.equal(fakeNative.connections[1].sent[0].sequence, 1);
  fakeNative.connections[1].onDisconnect();
  assert.equal(thirdMessages.some((message) => message.kind === "disconnect"), true);
});

test("oversized content and native messages fail closed", () => {
  const { fakeNative, router } = makeRouter();
  const delivered = [];
  const handle = router.attachContent({ sender: sender(), postMessage: (message) => delivered.push(message) });
  const oversized = contentRequest(handle.activationNonce, "large-1", "eth_call", ["x".repeat(shared.MAX_MESSAGE_BYTES)]);
  assert.equal(shared.fitsMessageLimit(oversized), false);
  assert.equal(handle.receive(oversized), false);
  assert.equal(fakeNative.connections.length, 0);
  assert.equal(delivered.filter((message) => message.id === requestId("large-1")).length, 1);

  const secondMessages = [];
  const second = router.attachContent({ sender: { ...sender(), documentId: "document-oversize" }, postMessage: (message) => secondMessages.push(message) });
  second.receive(contentRequest(second.activationNonce, "large-native-1"));
  fakeNative.connections[0].onMessage({ blob: "x".repeat(shared.MAX_MESSAGE_BYTES) });
  assert.equal(secondMessages.some((message) => message.kind === "disconnect"), true);
});

test("content bridge rejects oversized page and background messages", () => {
  const sentToBackground = [];
  const postedToPage = [];
  const bridge = new ContentBridge({
    channelNonce: CHANNEL_ID,
    sendToBackground: (message) => sentToBackground.push(message),
    postToPage: (message) => postedToPage.push(message)
  });
  bridge.activate(ACTIVATION_ID);
  const largePageRequest = pageRequest("content-large", "eth_call", ["x".repeat(shared.MAX_MESSAGE_BYTES)]);
  assert.equal(bridge.receivePage(largePageRequest), false);
  assert.equal(sentToBackground.length, 0);

  assert.equal(bridge.receivePage(pageRequest("content-normal")), true);
  const largeResponse = {
    namespace: shared.NAMESPACE,
    version: shared.PROTOCOL_VERSION,
    kind: "response",
    activationNonce: ACTIVATION_ID,
    id: requestId("content-normal"),
    result: "x".repeat(shared.MAX_MESSAGE_BYTES)
  };
  assert.equal(bridge.receiveBackground(largeResponse), false);
  assert.equal(postedToPage.some((message) => message.id === requestId("content-normal")), false);
});

test("content bridge cancels once and ignores every response after cancellation", () => {
  const sentToBackground = [];
  const postedToPage = [];
  const bridge = new ContentBridge({
    channelNonce: CHANNEL_ID,
    sendToBackground: (message) => sentToBackground.push(message),
    postToPage: (message) => postedToPage.push(message)
  });
  assert.equal(bridge.activate(ACTIVATION_ID), true);
  assert.equal(bridge.receivePage(pageRequest("content-1")), true);
  bridge.cancel("navigation");
  assert.equal(postedToPage.filter((message) => message.kind === "response" && message.id === requestId("content-1")).length, 1);
  assert.equal(postedToPage.filter((message) => message.kind === "disconnect").length, 1);

  const late = {
    namespace: shared.NAMESPACE,
    version: shared.PROTOCOL_VERSION,
    kind: "response",
    activationNonce: ACTIVATION_ID,
    id: requestId("content-1"),
    result: "0x1"
  };
  assert.equal(bridge.receiveBackground(late), false);
  assert.equal(postedToPage.filter((message) => message.kind === "response" && message.id === requestId("content-1")).length, 1);
  assert.equal(sentToBackground.some((message) => message.kind === "disconnect"), true);
});

test("content bridge treats a duplicate page ID as a document-fatal replay", () => {
  const sentToBackground = [];
  const postedToPage = [];
  const bridge = new ContentBridge({
    channelNonce: CHANNEL_ID,
    sendToBackground: (message) => sentToBackground.push(message),
    postToPage: (message) => postedToPage.push(message)
  });
  bridge.activate(ACTIVATION_ID);
  const request = pageRequest("content-duplicate");
  assert.equal(bridge.receivePage(request), true);
  assert.equal(bridge.receivePage(request), false);
  assert.equal(postedToPage.filter((message) => message.kind === "response" && message.id === requestId("content-duplicate")).length, 1);
  assert.equal(postedToPage.some((message) => message.kind === "disconnect"), true);
});

test("manifest is HTTPS-only, top-level-only, and contains only required permissions", async () => {
  const manifestUrl = new URL("../manifest.json", import.meta.url);
  const manifest = JSON.parse(await readFile(manifestUrl, "utf8"));
  assert.deepEqual(manifest.permissions, ["nativeMessaging", "storage"]);
  assert.equal(Object.prototype.hasOwnProperty.call(manifest, "host_permissions"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(manifest, "externally_connectable"), false);
  assert.equal(manifest.content_scripts.length, 2);
  for (const registration of manifest.content_scripts) {
    assert.deepEqual(registration.matches, ["https://*/*"]);
    assert.equal(registration.all_frames, false);
    assert.equal(registration.run_at, "document_start");
  }
});

test("extension sources contain no dynamic-code or HTML injection primitives", async () => {
  const sourceNames = [
    "shared.js",
    "content-core.js",
    "background-core.js",
    "background.js",
    "content.js",
    "provider-main.js"
  ];
  for (const name of sourceNames) {
    const sourceUrl = new URL(`../src/${name}`, import.meta.url);
    const source = await readFile(sourceUrl, "utf8");
    assert.doesNotMatch(source, /\beval\s*\(/u, name);
    assert.doesNotMatch(source, /\bnew\s+Function\b/u, name);
    assert.doesNotMatch(source, /\binnerHTML\b/u, name);
    assert.doesNotMatch(source, /\bimport\s*\(/u, name);
    assert.doesNotMatch(source, /https?:\/\/[^*]/u, name);
  }
});

test("test fixtures avoid credential-shaped material", async () => {
  const testPath = fileURLToPath(import.meta.url);
  const source = await readFile(testPath, "utf8");
  const bannedTerms = new RegExp(["mne", "monic|seed", " phrase|private", " key"].join(""), "iu");
  assert.doesNotMatch(source, bannedTerms);
  assert.doesNotMatch(source, /0x[0-9a-f]{64}/iu);
});
