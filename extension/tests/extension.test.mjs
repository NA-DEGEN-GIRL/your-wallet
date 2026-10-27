import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { fileURLToPath } from "node:url";

await import("../src/shared.js");
await import("../src/background-core.js");

const shared = globalThis.__YOUR_WALLET_SHARED__;
const core = globalThis.__YOUR_WALLET_BACKGROUND_CORE__;
const { BackgroundRouter, deriveSenderContext } = core;

const PROFILE_ID = "a".repeat(64);
const SESSION_ID = "b".repeat(64);
const EXTENSION_ID = "abcdefghijklmnopabcdefghijklmnop";
const START = 1_700_000_000_000;
const CLOSED = { code: 4900, message: "Wallet connection closed." };
const UNAVAILABLE = { code: 4900, message: "Wallet is unavailable." };

function rid(index) {
  return index.toString(16).padStart(32, "0");
}

function address(index) {
  return `0x${index.toString(16).padStart(40, "0")}`;
}

class FakeClock {
  constructor(start = START) {
    this.time = start;
    this.timers = new Map();
    this.nextId = 1;
  }

  now = () => this.time;

  setTimer = (callback, milliseconds) => {
    const id = this.nextId++;
    this.timers.set(id, { callback, due: this.time + milliseconds });
    return id;
  };

  clearTimer = (id) => {
    this.timers.delete(id);
  };

  advance(milliseconds) {
    const target = this.time + milliseconds;
    for (;;) {
      let nextId = null;
      let next = null;
      for (const [id, timer] of this.timers) {
        if (timer.due <= target && (next === null || timer.due < next.due)) {
          nextId = id;
          next = timer;
        }
      }
      if (next === null) {
        break;
      }
      this.timers.delete(nextId);
      this.time = Math.max(this.time, next.due);
      next.callback();
    }
    this.time = target;
  }
}

class FakeNative {
  constructor() {
    this.connections = [];
    this.throwOnConnect = false;
  }

  get last() {
    return this.connections.at(-1);
  }

  factory = ({ hostName, onMessage, onDisconnect }) => {
    if (this.throwOnConnect) {
      throw new Error("Specified native messaging host not found.");
    }
    const connection = {
      hostName,
      sent: [],
      closed: false,
      replySequence: 0,
      send(message) {
        if (this.closed) {
          throw new Error("Attempting to use a disconnected port object");
        }
        this.sent.push(structuredClone(message));
      },
      // Chrome does not fire our own onDisconnect when the extension closes the port.
      disconnect() {
        this.closed = true;
      },
      // The host process exited.
      drop() {
        this.closed = true;
        onDisconnect();
      },
      deliver(message) {
        onMessage(message);
      },
      requests() {
        return this.sent.filter((message) => message.kind === "request");
      },
      reply(request, body, overrides = {}) {
        this.replySequence += 1;
        onMessage({
          namespace: "your-wallet",
          version: 1,
          role: "native-host",
          kind: "response",
          sessionId: request.sessionId,
          sequence: this.replySequence,
          requestSequence: request.sequence,
          activationNonce: request.activationNonce,
          requestId: request.requestId,
          ...body,
          ...overrides
        });
      },
      event(activationNonce, event, payload, overrides = {}) {
        this.replySequence += 1;
        onMessage({
          namespace: "your-wallet",
          version: 1,
          role: "native-host",
          kind: "event",
          sessionId: this.sent[0].sessionId,
          sequence: this.replySequence,
          activationNonce,
          event,
          payload,
          ...overrides
        });
      }
    };
    this.connections.push(connection);
    return connection;
  };
}

function counterRandom(start = 12) {
  let counter = start;
  return () => (counter++).toString(16).padStart(64, "0");
}

function makeRouter({ clock = new FakeClock(), native = new FakeNative(), randomHex = counterRandom() } = {}) {
  const router = new BackgroundRouter({
    profileInstallId: PROFILE_ID,
    extensionId: EXTENSION_ID,
    randomHex,
    now: clock.now,
    setTimer: clock.setTimer,
    clearTimer: clock.clearTimer,
    nativeFactory: native.factory
  });
  return { clock, native, router };
}

function sender(url = "https://dapp.example/account", overrides = {}) {
  const parsed = new URL(url);
  return {
    tab: { id: 17, incognito: false },
    frameId: 0,
    documentId: "document-17",
    documentLifecycle: "active",
    origin: parsed.origin,
    url: parsed.href,
    ...overrides
  };
}

function attach(router, senderValue = sender()) {
  const delivered = [];
  let portClosed = false;
  const handle = router.attachContent({
    sender: senderValue,
    postMessage: (message) => delivered.push(structuredClone(message)),
    disconnect: () => {
      portClosed = true;
    }
  });
  return {
    handle,
    delivered,
    get portClosed() {
      return portClosed;
    },
    request(id, method = "eth_chainId", params = []) {
      return handle.receive({
        namespace: "your-wallet", version: 1, kind: "request", activationNonce: handle.activationNonce, id, method, params
      });
    },
    cancel(id, reason = "page-cancel") {
      return handle.receive({ namespace: "your-wallet", version: 1, kind: "cancel", activationNonce: handle.activationNonce, id, reason });
    },
    responses(id) {
      return delivered.filter((message) => message.kind === "response" && message.id === id);
    },
    lastResponse() {
      return delivered.filter((message) => message.kind === "response").at(-1);
    }
  };
}

test("B1 one activation serves 5,000 sequential requests (no lifetime cap)", () => {
  const { clock, native, router } = makeRouter();
  const doc = attach(router);
  assert.deepEqual(doc.delivered[0], { namespace: "your-wallet", version: 1, kind: "activated", activationNonce: doc.handle.activationNonce });
  for (let index = 1; index <= 5_000; index += 1) {
    clock.advance(25);
    assert.equal(doc.request(rid(index), "eth_blockNumber"), true, `request ${index}`);
    const request = native.last.sent.at(-1);
    assert.equal(request.sequence, index);
    native.last.reply(request, { result: `0x${index.toString(16)}` });
    assert.deepEqual(doc.lastResponse(), {
      namespace: "your-wallet", version: 1, kind: "response", activationNonce: doc.handle.activationNonce, id: rid(index), result: `0x${index.toString(16)}`
    });
  }
  assert.equal(native.connections.length, 1);
  assert.equal(doc.delivered.filter((message) => message.kind === "response" && message.result !== undefined).length, 5_000);
  assert.equal(clock.timers.size, 0);
  assert.equal("MAX_NATIVE_CONNECTION_ATTEMPTS" in core, false);
  assert.equal("MAX_REQUESTS_PER_ACTIVATION" in shared, false);
});

test("B1 native reconnects are unlimited; each connection has a new session and restarts sequence", () => {
  const { clock, native, router } = makeRouter();
  const doc = attach(router);
  const sessions = new Set();
  for (let index = 1; index <= 4_200; index += 1) {
    clock.advance(25);
    assert.equal(doc.request(rid(index)), true, `request ${index}`);
    const connection = native.last;
    const [request] = connection.sent;
    assert.equal(request.sequence, 1);
    sessions.add(request.sessionId);
    connection.reply(request, { result: "0x1" });
    connection.drop();
  }
  assert.equal(native.connections.length, 4_200);
  assert.equal(sessions.size, 4_200);
});

test("B2 token bucket: the 81st immediate request is rate limited and capacity recovers after 1 s", () => {
  const { clock, native, router } = makeRouter();
  const doc = attach(router);
  for (let index = 1; index <= 80; index += 1) {
    assert.equal(doc.request(rid(index)), true, `request ${index}`);
    native.last.reply(native.last.sent.at(-1), { result: "0x1" });
  }
  assert.equal(doc.request(rid(81)), false);
  assert.deepEqual(doc.responses(rid(81))[0].error, { code: -32005, message: "Rate limit exceeded." });
  assert.equal(native.last.sent.length, 80);
  clock.advance(999);
  // 999 ms refilled 39.96 tokens: 39 more requests pass, the 40th does not.
  for (let index = 82; index < 82 + 39; index += 1) {
    assert.equal(doc.request(rid(index)), true, `request ${index}`);
    native.last.reply(native.last.sent.at(-1), { result: "0x1" });
  }
  assert.equal(doc.request(rid(200)), false);
  assert.equal(doc.responses(rid(200))[0].error.message, "Rate limit exceeded.");
  clock.advance(1_000);
  assert.equal(doc.request(rid(201)), true);
  // A second document has its own bucket.
  const other = attach(router, sender("https://other.example/", { documentId: "document-18" }));
  assert.equal(other.request(rid(1)), true);
});

test("B2 pending limits: 64 per document and 512 globally", () => {
  const { native, router } = makeRouter();
  const docs = [];
  for (let index = 0; index < 9; index += 1) {
    docs.push(attach(router, sender(`https://d${index}.example/`, { documentId: `document-${index}` })));
  }
  for (let index = 1; index <= 64; index += 1) {
    assert.equal(docs[0].request(rid(index)), true);
  }
  assert.equal(docs[0].request(rid(65)), false);
  assert.deepEqual(docs[0].responses(rid(65))[0].error, { code: -32005, message: "Too many pending requests." });
  for (let doc = 1; doc < 8; doc += 1) {
    for (let index = 1; index <= 64; index += 1) {
      assert.equal(docs[doc].request(rid(index)), true);
    }
  }
  assert.equal(native.last.requests().length, 512);
  assert.equal(docs[8].request(rid(1)), false);
  assert.deepEqual(docs[8].responses(rid(1))[0].error, { code: -32005, message: "Too many pending requests." });
  native.last.reply(native.last.sent[0], { result: "0x1" });
  assert.equal(docs[8].request(rid(2)), true);
});

test("B3 a duplicate pending id is ignored and the activation stays usable", () => {
  const { native, router } = makeRouter();
  const doc = attach(router);
  assert.equal(doc.request(rid(1)), true);
  assert.equal(doc.request(rid(1)), false);
  assert.equal(native.last.sent.length, 1);
  assert.equal(doc.responses(rid(1)).length, 0);
  assert.equal(doc.delivered.some((message) => message.kind === "disconnect"), false);
  assert.equal(doc.portClosed, false);
  native.last.reply(native.last.sent[0], { result: "0xaa36a7" });
  assert.equal(doc.responses(rid(1)).length, 1);
  // A completed id may be used again (no seen-id history).
  assert.equal(doc.request(rid(1)), true);
  assert.equal(native.last.sent.length, 2);
});

test("B3 malformed content messages are ignored without ending the activation", () => {
  const { native, router } = makeRouter();
  const doc = attach(router);
  const nonce = doc.handle.activationNonce;
  const base = { namespace: "your-wallet", version: 1, kind: "request", activationNonce: nonce, id: rid(1), method: "eth_chainId", params: [] };
  for (const bad of [
    null,
    "text",
    [],
    { ...base, context: { topOrigin: "https://spoof.example" } },
    { ...base, activationNonce: "f".repeat(64) },
    { ...base, id: "XYZ" },
    { ...base, params: "0x" },
    { ...base, version: 2 },
    { namespace: "your-wallet", version: 1, kind: "fatal", activationNonce: nonce },
    { namespace: "your-wallet", version: 1, kind: "cancel", activationNonce: nonce, id: rid(1), reason: "has space" }
  ]) {
    assert.equal(doc.handle.receive(bad), false);
  }
  assert.equal(native.connections.length, 0);
  assert.equal(doc.delivered.length, 1);
  assert.equal(doc.request(rid(2), "wallet_addEthereumChain", [{}]), false);
  assert.deepEqual(doc.responses(rid(2))[0].error, { code: 4200, message: "Unsupported method." });
  assert.equal(native.connections.length, 0);
  assert.equal(doc.request(rid(3)), true);
  assert.equal(native.last.sent[0].params.length, 0);
  assert.equal(Object.hasOwn(native.last.sent[0].params, "context"), false);
  const tooLarge = doc.request(rid(4), "eth_call", ["x".repeat(1_048_000)]);
  assert.equal(tooLarge, false);
  assert.deepEqual(doc.responses(rid(4))[0].error, { code: -32600, message: "Request too large." });
  assert.equal(native.last.sent.length, 1);
  assert.equal(doc.request(rid(5)), true);
  assert.equal(native.last.sent[1].sequence, 2);
});

test("B3 at 128 documents the least recently used idle activation is evicted; none idle closes the new port", () => {
  const { native, router } = makeRouter();
  const docs = [];
  for (let index = 0; index < 128; index += 1) {
    docs.push(attach(router, sender(`https://d${index}.example/`, { documentId: `document-${index}` })));
  }
  // Document 0 is busy, document 1 was used most recently among the idle ones after this.
  docs[0].request(rid(1));
  docs[1].request(rid(1));
  native.last.reply(native.last.sent[1], { result: "0x1" });
  const extra = attach(router, sender("https://extra.example/", { documentId: "document-extra" }));
  assert.notEqual(extra.handle, null);
  assert.equal(docs[2].portClosed, true);
  assert.equal(docs[0].portClosed, false);
  assert.equal(docs[1].portClosed, false);
  assert.equal(docs[2].request(rid(9)), false);
  assert.equal(docs[2].responses(rid(9)).length, 0);

  const full = makeRouter();
  const busy = [];
  for (let index = 0; index < 128; index += 1) {
    const doc = attach(full.router, sender(`https://b${index}.example/`, { documentId: `busy-${index}` }));
    doc.request(rid(1));
    busy.push(doc);
  }
  const rejected = attach(full.router, sender("https://late.example/", { documentId: "late" }));
  assert.equal(rejected.handle, null);
  assert.equal(rejected.delivered.length, 0);
  assert.equal(busy.some((doc) => doc.portClosed), false);
});

test("B4 native protocol violations drop only the native connection; activations survive and reconnect", () => {
  const violations = {
    "frame over limits": (connection, request) => connection.reply(request, { result: JSON.parse(`${"[".repeat(40)}${"]".repeat(40)}`) }),
    "extra key": (connection, request) => connection.reply(request, { result: "0x1" }, { extra: true }),
    "sequence skip": (connection, request) => {
      connection.replySequence += 1;
      connection.reply(request, { result: "0x1" });
    },
    "stale session": (connection, request) => connection.reply(request, { result: "0x1" }, { sessionId: "e".repeat(64) }),
    "unknown kind": (connection, request) => connection.reply(request, { result: "0x1" }, { kind: "hello" }),
    "result and error": (connection, request) => connection.reply(request, { result: "0x1", error: { code: 1, message: "x" } }),
    "bad error object": (connection, request) => connection.reply(request, { error: { code: 4001, message: "" } }),
    "accountsChanged with 17 addresses": (connection, request) => connection.event(request.activationNonce, "accountsChanged",
      Array.from({ length: 17 }, (_, index) => address(index + 1))),
    "chainChanged not canonical": (connection, request) => connection.event(request.activationNonce, "chainChanged", "0x01"),
    "unknown event": (connection, request) => connection.event(request.activationNonce, "connect", { chainId: "0x1" })
  };
  for (const [name, violate] of Object.entries(violations)) {
    const { native, router } = makeRouter();
    const doc = attach(router);
    doc.request(rid(1));
    native.last.reply(native.last.sent[0], { result: "0xaa36a7" });
    doc.request(rid(2), "eth_blockNumber");
    const first = native.last;
    violate(first, first.sent[1]);
    assert.equal(first.closed, true, name);
    assert.deepEqual(doc.responses(rid(2))[0].error, CLOSED, name);
    assert.equal(doc.portClosed, false, name);
    assert.equal(doc.delivered.some((message) => message.kind === "event"), false, name);
    // The connection was healthy, so there is no backoff: the next request reconnects at once.
    assert.equal(doc.request(rid(3)), true, name);
    assert.equal(native.connections.length, 2, name);
    const retry = native.last.sent[0];
    assert.equal(retry.sequence, 1, name);
    assert.notEqual(retry.sessionId, first.sent[0].sessionId, name);
    assert.equal(retry.activationNonce, doc.handle.activationNonce, name);
    native.last.reply(retry, { result: "0x1" });
    assert.equal(doc.responses(rid(3))[0].result, "0x1", name);
  }
});

test("B4 accountsChanged with 16 addresses and chainChanged events are forwarded", () => {
  const { native, router } = makeRouter();
  const doc = attach(router);
  const other = attach(router, sender("https://other.example/", { documentId: "document-18" }));
  doc.request(rid(1));
  const accounts = Array.from({ length: 16 }, (_, index) => address(index + 1));
  native.last.event(doc.handle.activationNonce, "accountsChanged", accounts);
  native.last.event(doc.handle.activationNonce, "chainChanged", "0x2105");
  native.last.event("9".repeat(64), "chainChanged", "0x1");
  assert.deepEqual(doc.delivered.filter((message) => message.kind === "event"), [
    { namespace: "your-wallet", version: 1, kind: "event", activationNonce: doc.handle.activationNonce, event: "accountsChanged", payload: accounts },
    { namespace: "your-wallet", version: 1, kind: "event", activationNonce: doc.handle.activationNonce, event: "chainChanged", payload: "0x2105" }
  ]);
  assert.equal(other.delivered.some((message) => message.kind === "event"), false);
  assert.equal(native.last.closed, false);
});

test("B4 responses need matching activation, request id and requestSequence; onSuspend closes only native", () => {
  const { native, router } = makeRouter();
  const doc = attach(router);
  doc.request(rid(1));
  const [request] = native.last.sent;
  native.last.reply(request, { result: "0xwrong" }, { requestSequence: 7 });
  native.last.reply(request, { result: "0xwrong" }, { requestId: rid(99) });
  assert.equal(doc.responses(rid(1)).length, 0);
  assert.equal(native.last.closed, false);
  native.last.reply(request, { result: "0x1" });
  assert.equal(doc.responses(rid(1))[0].result, "0x1");

  doc.request(rid(2));
  router.closeNative();
  assert.equal(native.last.closed, true);
  assert.deepEqual(doc.responses(rid(2))[0].error, CLOSED);
  assert.equal(doc.portClosed, false);
  assert.equal(doc.request(rid(3)), true);
  assert.equal(native.connections.length, 2);
});

test("B5 deadline timers: eth_blockNumber 60 s, personal_sign 600 s; cancel has the v1-cancel golden shape", async () => {
  const cancelGolden = JSON.parse(await readFile(new URL("../native-host/v1-cancel.golden.json", import.meta.url), "utf8"));
  const scripted = ["c".padStart(64, "0"), "d".padStart(64, "0"), SESSION_ID];
  const fallback = counterRandom(0x100);
  const { clock, native, router } = makeRouter({ randomHex: () => scripted.shift() ?? fallback() });
  const doc = attach(router);
  const requestId = "01".repeat(16);
  doc.request(requestId, "eth_blockNumber");
  const [read] = native.last.sent;
  assert.equal(read.deadlineUnixMs, START + 60_000);
  assert.equal(read.route, "read");
  clock.advance(59_999);
  assert.equal(doc.responses(requestId).length, 0);
  clock.advance(1);
  assert.deepEqual(doc.responses(requestId)[0].error, { code: -32603, message: "Request timed out." });
  const cancel = native.last.sent[1];
  assert.equal(JSON.stringify(cancel), JSON.stringify(cancelGolden));
  // A late answer is dropped without disturbing the connection.
  native.last.reply(read, { result: "0x1" });
  assert.equal(doc.responses(requestId).length, 1);
  assert.equal(native.last.closed, false);

  doc.request(rid(2), "personal_sign", ["0x00", address(1)]);
  const sign = native.last.sent[2];
  assert.equal(sign.route, "signing");
  assert.equal(sign.deadlineUnixMs, clock.now() + 600_000);
  clock.advance(599_999);
  assert.equal(doc.responses(rid(2)).length, 0);
  clock.advance(1);
  assert.deepEqual(doc.responses(rid(2))[0].error, { code: -32603, message: "Request timed out." });
  const signCancel = native.last.sent[3];
  assert.deepEqual(Object.keys(signCancel), Object.keys(cancelGolden));
  assert.deepEqual(signCancel, { ...cancelGolden, sequence: 4, requestId: rid(2), requestSequence: 3 });

  doc.request(rid(3), "eth_requestAccounts");
  assert.equal(native.last.sent[4].deadlineUnixMs, clock.now() + 600_000);
});

test("B5 page cancel and content disconnect forward native cancels and clear deadlines", () => {
  const { clock, native, router } = makeRouter();
  const doc = attach(router);
  doc.request(rid(1), "eth_blockNumber");
  assert.equal(doc.cancel(rid(1)), true);
  const cancel = native.last.sent[1];
  assert.equal(cancel.kind, "cancel");
  assert.equal(cancel.reason, "page-cancel");
  assert.equal(cancel.requestSequence, 1);
  assert.equal(cancel.sequence, 2);
  assert.equal(doc.responses(rid(1)).length, 0);
  assert.equal(doc.cancel(rid(1)), false);
  clock.advance(120_000);
  assert.equal(doc.responses(rid(1)).length, 0);

  doc.request(rid(2), "eth_sendTransaction", [{}]);
  doc.request(rid(3), "eth_call", [{}]);
  doc.handle.receive({ namespace: "your-wallet", version: 1, kind: "disconnect", activationNonce: doc.handle.activationNonce, reason: "document-pagehide" });
  const cancels = native.last.sent.filter((message) => message.kind === "cancel").slice(1);
  assert.deepEqual(cancels.map((message) => [message.requestId, message.reason]), [[rid(2), "document-pagehide"], [rid(3), "document-pagehide"]]);
  assert.equal(doc.request(rid(4)), false);
  assert.equal(clock.timers.size, 0);

  const second = attach(router, sender("https://other.example/", { documentId: "document-18" }));
  second.request(rid(5));
  second.handle.disconnect();
  assert.equal(native.last.sent.at(-1).reason, "content-port-disconnect");
  assert.equal(native.last.sent.at(-1).requestId, rid(5));
});

test("B6 unhealthy native connections back off 1 s, 2 s, 4 s ... capped at 30 s with local 4900", () => {
  const { clock, native, router } = makeRouter();
  const doc = attach(router);
  let id = 0;
  const expectedDelays = [1_000, 2_000, 4_000, 8_000, 16_000, 30_000, 30_000];
  doc.request(rid(++id));
  native.last.drop();
  assert.deepEqual(doc.responses(rid(id))[0].error, CLOSED);
  for (const delay of expectedDelays) {
    clock.advance(delay - 1);
    const connections = native.connections.length;
    doc.request(rid(++id));
    assert.deepEqual(doc.responses(rid(id))[0].error, UNAVAILABLE, `before ${delay}`);
    assert.equal(native.connections.length, connections);
    clock.advance(1);
    assert.equal(doc.request(rid(++id)), true, `at ${delay}`);
    assert.equal(native.connections.length, connections + 1);
    // yw-host UNAVAILABLE answers 4900 and exits: the connection never became healthy.
    native.last.reply(native.last.sent[0], { error: { ...UNAVAILABLE } });
    assert.deepEqual(doc.responses(rid(id))[0].error, UNAVAILABLE);
    native.last.drop();
  }
  // A healthy connection (non-4900 response) resets the failure count.
  clock.advance(30_000);
  doc.request(rid(++id));
  native.last.reply(native.last.sent[0], { error: { code: 4001, message: "User rejected the request." } });
  native.last.drop();
  const connections = native.connections.length;
  assert.equal(doc.request(rid(++id)), true);
  assert.equal(native.connections.length, connections + 1);
  native.last.event(doc.handle.activationNonce, "chainChanged", "0x1");
  native.last.drop();
  assert.equal(doc.request(rid(++id)), true);
  assert.equal(doc.portClosed, false);
});

test("B6 a throwing connectNative answers 4900 Wallet is unavailable and starts backoff", () => {
  const { clock, native, router } = makeRouter();
  const doc = attach(router);
  native.throwOnConnect = true;
  assert.equal(doc.request(rid(1)), false);
  assert.deepEqual(doc.responses(rid(1))[0].error, UNAVAILABLE);
  native.throwOnConnect = false;
  clock.advance(999);
  doc.request(rid(2));
  assert.deepEqual(doc.responses(rid(2))[0].error, UNAVAILABLE);
  assert.equal(native.connections.length, 0);
  clock.advance(1);
  assert.equal(doc.request(rid(3)), true);
  assert.equal(native.connections.length, 1);
  // A send failure is a native disconnect for every pending request.
  doc.request(rid(4));
  native.last.closed = true;
  doc.request(rid(5));
  for (const id of [rid(3), rid(4), rid(5)]) {
    assert.deepEqual(doc.responses(id)[0].error, CLOSED);
  }
});

test("B7 deriveSenderContext follows the spec/05 §2.4 table", () => {
  const configuration = (value) => ({ sender: value, extensionId: EXTENSION_ID, channelNonce: "d".repeat(64) });
  assert.deepEqual({ ...deriveSenderContext(configuration(sender("https://dapp.example/private/path?q=1#f"))) }, {
    browserFamily: "chrome",
    extensionId: EXTENSION_ID,
    tabId: 17,
    frameId: 0,
    documentId: "document-17",
    topOrigin: "https://dapp.example",
    frameOrigin: "https://dapp.example",
    documentLifecycle: "active",
    channelNonce: "d".repeat(64)
  });
  assert.equal(deriveSenderContext(configuration(sender("http://localhost:5173/"))).topOrigin, "http://localhost:5173");
  assert.equal(deriveSenderContext(configuration(sender("http://127.0.0.1/"))).topOrigin, "http://127.0.0.1");
  assert.equal(deriveSenderContext(configuration(sender("https://dapp.example:8443/"))).topOrigin, "https://dapp.example:8443");
  const { origin: _origin, ...withoutOrigin } = sender();
  assert.equal(deriveSenderContext(configuration(withoutOrigin)).topOrigin, "https://dapp.example");

  const rejected = {
    "subframe": { ...sender(), frameId: 2 },
    "http other host": sender("http://dapp.example/"),
    "http IPv6 literal": { ...sender(), url: "http://[::1]:5173/", origin: "http://[::1]:5173" },
    "file": { ...sender(), url: "file:///C:/page.html", origin: "null" },
    "data": { ...sender(), url: "data:text/html,x", origin: "null" },
    "userinfo": { ...sender(), url: "https://user:pass@dapp.example/" },
    "null origin": { ...sender(), url: "about:blank", origin: "null" },
    "origin mismatch": { ...sender(), origin: "https://spoof.example" },
    "incognito": { ...sender(), tab: { id: 17, incognito: true } },
    "prerender lifecycle": { ...sender(), documentLifecycle: "prerender" },
    "missing lifecycle": { ...sender(), documentLifecycle: undefined },
    "unsafe tab id": { ...sender(), tab: { id: Number.MAX_SAFE_INTEGER + 1, incognito: false } },
    "no tab": { ...sender(), tab: undefined },
    "bad document id": { ...sender(), documentId: "doc id" },
    "long url": { ...sender(), url: `https://dapp.example/${"a".repeat(8_192)}` }
  };
  for (const [name, value] of Object.entries(rejected)) {
    assert.throws(() => deriveSenderContext(configuration(value)), Error, name);
    const { router } = makeRouter();
    assert.equal(attach(router, value).handle, null, name);
  }
  assert.throws(() => deriveSenderContext({ ...configuration(sender()), extra: 1 }), Error);
  assert.throws(() => deriveSenderContext({ ...configuration(sender()), extensionId: "chrome-extension-id" }), Error);
});

test("extension sources contain no dynamic-code, network or HTML injection primitives", async () => {
  for (const name of ["shared.js", "content-core.js", "background-core.js", "background.js", "content.js", "provider-main.js"]) {
    const source = await readFile(new URL(`../src/${name}`, import.meta.url), "utf8");
    assert.doesNotMatch(source, /\beval\s*\(/u, name);
    assert.doesNotMatch(source, /\bnew\s+Function\b/u, name);
    assert.doesNotMatch(source, /\binnerHTML\b/u, name);
    assert.doesNotMatch(source, /\bimport\s*\(/u, name);
    assert.doesNotMatch(source, /https?:\/\//u, name);
    assert.doesNotMatch(source, /MAX_REQUESTS|seenIds|respondedIds|MAX_NATIVE_CONNECTION_ATTEMPTS|onConnectExternal|onMessageExternal|"fatal"/u, name);
  }
});

test("test fixtures avoid credential-shaped material", async () => {
  const testPath = fileURLToPath(import.meta.url);
  const source = await readFile(testPath, "utf8");
  const bannedTerms = new RegExp(["mne", "monic|seed", " phrase|private", " key"].join(""), "iu");
  assert.doesNotMatch(source, bannedTerms);
  assert.doesNotMatch(source, /0x[0-9a-f]{64}/iu);
});
