import assert from "node:assert/strict";
import test from "node:test";

import "../src/shared.js";
import "../src/content-core.js";

const shared = globalThis.__YOUR_WALLET_SHARED__;
const { ContentBridge, STATES } = globalThis.__YOUR_WALLET_CONTENT_CORE__;

const CHANNEL = "d".repeat(64);
const ACTIVATION = "c".repeat(64);
const SECOND_ACTIVATION = "e".repeat(64);

function rid(index) {
  return index.toString(16).padStart(32, "0");
}

class FakeClock {
  constructor(start = 1_000_000) {
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

class FakePort {
  constructor() {
    this.sent = [];
    this.messageListeners = [];
    this.disconnectListeners = [];
    this.disconnected = false;
  }

  adapter() {
    return {
      postMessage: (message) => {
        if (this.disconnected) {
          throw new Error("Attempting to use a disconnected port object");
        }
        this.sent.push(structuredClone(message));
      },
      disconnect: () => {
        this.disconnected = true;
      },
      onMessage: (listener) => this.messageListeners.push(listener),
      onDisconnect: (listener) => this.disconnectListeners.push(listener)
    };
  }

  deliver(message) {
    for (const listener of this.messageListeners) {
      listener(message);
    }
  }

  drop() {
    this.disconnected = true;
    for (const listener of this.disconnectListeners) {
      listener();
    }
  }

  activate(activationNonce = ACTIVATION) {
    this.deliver({ namespace: "your-wallet", version: 1, kind: "activated", activationNonce });
  }

  respond(id, result, activationNonce = ACTIVATION) {
    this.deliver({ namespace: "your-wallet", version: 1, kind: "response", activationNonce, id, result });
  }
}

function harness({ connectThrows = false, compatMode, solCompatMode, btcCompatMode } = {}) {
  const clock = new FakeClock();
  const page = [];
  const ports = [];
  let contextValid = true;
  const bridge = new ContentBridge({
    channelNonce: CHANNEL,
    ...(compatMode === undefined ? {} : { compatMode }),
    ...(solCompatMode === undefined ? {} : { solCompatMode }),
    ...(btcCompatMode === undefined ? {} : { btcCompatMode }),
    connectPort: () => {
      if (connectThrows) {
        throw new Error("Extension context invalidated.");
      }
      const port = new FakePort();
      ports.push(port);
      return port.adapter();
    },
    postToPage: (message) => page.push(structuredClone(message)),
    isContextValid: () => contextValid,
    setTimer: clock.setTimer,
    clearTimer: clock.clearTimer,
    now: clock.now
  });
  return {
    bridge,
    clock,
    page,
    ports,
    invalidateContext: () => {
      contextValid = false;
    },
    request: (id, method = "eth_chainId", params = []) => bridge.receivePage({
      namespace: "your-wallet", version: 1, kind: "request", channel: CHANNEL, id, method, params
    }),
    cancel: (id) => bridge.receivePage({ namespace: "your-wallet", version: 1, kind: "cancel", channel: CHANNEL, id }),
    responses: (id) => page.filter((message) => message.kind === "response" && message.id === id)
  };
}

test("C1 no port before the first request; IDLE -> CONNECTING -> ACTIVE keeps queue order", () => {
  const h = harness();
  h.bridge.announce();
  assert.deepEqual(h.page, [{ namespace: "your-wallet", version: 1, kind: "bridge-init", channel: CHANNEL, compatMode: "off", solCompatMode: "off", btcCompatMode: "off" }]);
  h.bridge.receivePage({ namespace: "your-wallet", version: 1, kind: "bridge-request" });
  assert.equal(h.page.filter((message) => message.kind === "bridge-init").length, 2);
  assert.equal(h.ports.length, 0);
  assert.equal(h.bridge.state, STATES.IDLE);

  assert.equal(h.request(rid(1)), true);
  assert.equal(h.ports.length, 1);
  assert.equal(h.bridge.state, STATES.CONNECTING);
  assert.equal(h.request(rid(2), "eth_blockNumber"), true);
  assert.equal(h.request(rid(3), "eth_accounts"), true);
  assert.equal(h.ports[0].sent.length, 0);

  h.ports[0].activate();
  assert.equal(h.bridge.state, STATES.ACTIVE);
  assert.deepEqual(h.ports[0].sent.map((message) => message.id), [rid(1), rid(2), rid(3)]);
  assert.deepEqual(h.ports[0].sent[0], {
    namespace: "your-wallet", version: 1, kind: "request", activationNonce: ACTIVATION, id: rid(1), method: "eth_chainId", params: []
  });
  h.request(rid(4), "net_version");
  assert.equal(h.ports[0].sent.at(-1).id, rid(4));
  assert.equal(h.ports.length, 1);

  h.ports[0].respond(rid(2), "0x10");
  assert.deepEqual(h.responses(rid(2)), [{ namespace: "your-wallet", version: 1, kind: "response", channel: CHANNEL, id: rid(2), result: "0x10" }]);
  // A response for an unknown or already completed id is dropped.
  h.ports[0].respond(rid(2), "0x11");
  h.ports[0].respond(rid(99), "0x11");
  assert.equal(h.responses(rid(2)).length, 1);
  assert.equal(h.responses(rid(99)).length, 0);
  // Events are forwarded only for the two native event names.
  h.ports[0].deliver({ namespace: "your-wallet", version: 1, kind: "event", activationNonce: ACTIVATION, event: "chainChanged", payload: "0xaa36a7" });
  h.ports[0].deliver({ namespace: "your-wallet", version: 1, kind: "event", activationNonce: ACTIVATION, event: "connect", payload: { chainId: "0x1" } });
  h.ports[0].deliver({ namespace: "your-wallet", version: 1, kind: "event", activationNonce: SECOND_ACTIVATION, event: "chainChanged", payload: "0x1" });
  assert.deepEqual(h.page.filter((message) => message.kind === "event"), [
    { namespace: "your-wallet", version: 1, kind: "event", channel: CHANNEL, event: "chainChanged", payload: "0xaa36a7" }
  ]);
});

test("C1 page cancel removes queued work and forwards page-cancel for sent work", () => {
  const h = harness();
  h.request(rid(1));
  h.request(rid(2));
  h.cancel(rid(1));
  h.ports[0].activate();
  assert.deepEqual(h.ports[0].sent.map((message) => message.id), [rid(2)]);
  h.cancel(rid(2));
  assert.deepEqual(h.ports[0].sent.at(-1), {
    namespace: "your-wallet", version: 1, kind: "cancel", activationNonce: ACTIVATION, id: rid(2), reason: "page-cancel"
  });
  h.ports[0].respond(rid(2), "late");
  assert.equal(h.page.filter((message) => message.kind === "response").length, 0);
});

test("C1 duplicate pending id and malformed page messages are ignored without side effects", () => {
  const h = harness();
  h.request(rid(1));
  h.ports[0].activate();
  assert.equal(h.request(rid(1)), false);
  assert.equal(h.ports[0].sent.length, 1);
  assert.equal(h.bridge.receivePage({ namespace: "your-wallet", version: 1, kind: "request", channel: CHANNEL, id: rid(2), method: "eth_chainId", params: [], extra: 1 }), false);
  assert.equal(h.bridge.receivePage({ namespace: "your-wallet", version: 1, kind: "request", channel: "f".repeat(64), id: rid(2), method: "eth_chainId", params: [] }), false);
  assert.equal(h.bridge.receivePage("garbage"), false);
  assert.equal(h.page.filter((message) => message.kind === "response").length, 0);
  h.ports[0].respond(rid(1), "0x1");
  assert.equal(h.responses(rid(1)).length, 1);
  assert.equal(h.bridge.state, STATES.ACTIVE);
});

test("C1 request limits: too large, too many pending, oversized background response", () => {
  const h = harness();
  h.request(rid(1), "eth_call", ["x".repeat(1_048_576)]);
  assert.deepEqual(h.responses(rid(1))[0].error, { code: -32600, message: "Request too large." });
  let deep = [];
  for (let level = 0; level < 40; level += 1) {
    deep = [deep];
  }
  h.request(rid(2), "eth_call", deep);
  assert.deepEqual(h.responses(rid(2))[0].error, { code: -32600, message: "Request too large." });
  assert.equal(h.ports.length, 0);

  for (let index = 10; index < 10 + 64; index += 1) {
    assert.equal(h.request(rid(index)), true);
  }
  h.request(rid(200));
  assert.deepEqual(h.responses(rid(200))[0].error, { code: -32005, message: "Too many pending requests." });
  h.ports[0].activate();
  assert.equal(h.ports[0].sent.length, 64);
  h.ports[0].respond(rid(10), new Array(262_144).fill(0));
  assert.deepEqual(h.responses(rid(10))[0].error, { code: -32603, message: "Response too large." });
});

test("C2 port disconnect fails pending with 4900, returns to IDLE, and the next request reconnects", () => {
  const h = harness();
  h.request(rid(1));
  h.ports[0].activate();
  h.request(rid(2));
  h.ports[0].drop();
  assert.equal(h.bridge.state, STATES.IDLE);
  for (const id of [rid(1), rid(2)]) {
    assert.deepEqual(h.responses(id)[0].error, { code: 4900, message: "Wallet connection closed." });
  }
  assert.equal(h.page.some((message) => message.kind === "disconnect"), false);

  h.clock.advance(250);
  h.request(rid(3));
  assert.equal(h.ports.length, 2);
  h.ports[1].activate(SECOND_ACTIVATION);
  assert.equal(h.ports[1].sent[0].activationNonce, SECOND_ACTIVATION);
  h.ports[1].respond(rid(3), "0xaa36a7", SECOND_ACTIVATION);
  assert.equal(h.responses(rid(3))[0].result, "0xaa36a7");
  // The stale first port can no longer deliver anything.
  h.ports[0].respond(rid(3), "stale");
  assert.equal(h.responses(rid(3)).length, 1);
});

test("C2 a postMessage failure on the port is a transient disconnect", () => {
  const h = harness();
  h.request(rid(1));
  h.ports[0].activate();
  h.ports[0].disconnected = true;
  h.request(rid(2));
  assert.equal(h.bridge.state, STATES.IDLE);
  assert.equal(h.responses(rid(1))[0].error.code, 4900);
  assert.equal(h.responses(rid(2))[0].error.message, "Wallet connection closed.");
});

test("C3 invalid extension context -> DEAD, one page disconnect, then 4900 extension reloaded", () => {
  const h = harness();
  h.request(rid(1));
  h.ports[0].activate();
  h.request(rid(2));
  h.invalidateContext();
  h.ports[0].drop();
  assert.equal(h.bridge.state, STATES.DEAD);
  const reloaded = { code: 4900, message: "Wallet extension was reloaded." };
  assert.deepEqual(h.responses(rid(1))[0].error, reloaded);
  assert.deepEqual(h.responses(rid(2))[0].error, reloaded);
  assert.deepEqual(h.page.filter((message) => message.kind === "disconnect"), [
    { namespace: "your-wallet", version: 1, kind: "disconnect", channel: CHANNEL, error: reloaded }
  ]);
  h.clock.advance(10_000);
  h.request(rid(3));
  assert.deepEqual(h.responses(rid(3))[0].error, reloaded);
  assert.equal(h.ports.length, 1);
  h.bridge.closeForDocument("document-pagehide");
  assert.equal(h.page.filter((message) => message.kind === "disconnect").length, 1);
});

test("C3 connectPort throwing (context invalidated while IDLE) enters DEAD", () => {
  const h = harness({ connectThrows: true });
  h.request(rid(1));
  assert.equal(h.bridge.state, STATES.DEAD);
  assert.equal(h.responses(rid(1))[0].error.message, "Wallet extension was reloaded.");
  assert.equal(h.page.filter((message) => message.kind === "disconnect").length, 1);

  const idle = harness();
  idle.invalidateContext();
  idle.request(rid(2));
  assert.equal(idle.bridge.state, STATES.DEAD);
  assert.equal(idle.ports.length, 0);
  assert.equal(idle.responses(rid(2))[0].error.message, "Wallet extension was reloaded.");
});

test("C4 pagehide/freeze close the activation but leave the bridge IDLE (not DEAD)", () => {
  const h = harness();
  h.request(rid(1));
  h.ports[0].activate();
  h.bridge.closeForDocument("document-pagehide");
  assert.equal(h.bridge.state, STATES.IDLE);
  assert.deepEqual(h.ports[0].sent.at(-1), {
    namespace: "your-wallet", version: 1, kind: "disconnect", activationNonce: ACTIVATION, reason: "document-pagehide"
  });
  assert.equal(h.ports[0].disconnected, true);
  assert.deepEqual(h.responses(rid(1))[0].error, { code: 4900, message: "Wallet connection closed." });
  assert.equal(h.page.some((message) => message.kind === "disconnect"), false);

  // bfcache restore: the next request reconnects.
  h.clock.advance(1_000);
  h.request(rid(2));
  assert.equal(h.ports.length, 2);
  h.ports[1].activate(SECOND_ACTIVATION);
  h.bridge.closeForDocument("document-freeze");
  assert.equal(h.ports[1].sent.at(-1).reason, "document-freeze");
  assert.equal(h.bridge.state, STATES.IDLE);
  // pagehide while IDLE is a no-op.
  assert.equal(h.bridge.closeForDocument("document-pagehide"), false);
});

test("C4 a 5 s connect timeout closes the port and fails the queue with 4900", () => {
  const h = harness();
  h.request(rid(1));
  h.request(rid(2));
  h.clock.advance(4_999);
  assert.equal(h.bridge.state, STATES.CONNECTING);
  assert.equal(h.responses(rid(1)).length, 0);
  h.clock.advance(1);
  assert.equal(h.bridge.state, STATES.IDLE);
  assert.equal(h.ports[0].disconnected, true);
  for (const id of [rid(1), rid(2)]) {
    assert.deepEqual(h.responses(id)[0].error, { code: 4900, message: "Wallet connection closed." });
  }
  // A late activation on the timed-out port is ignored.
  h.ports[0].activate();
  assert.equal(h.bridge.state, STATES.IDLE);
});

test("C4 reconnect waits for the 250 ms minimum interval after the previous open", () => {
  const h = harness();
  h.request(rid(1));
  h.ports[0].activate();
  h.clock.advance(100);
  h.ports[0].drop();
  h.request(rid(2));
  assert.equal(h.bridge.state, STATES.CONNECTING);
  assert.equal(h.ports.length, 1);
  h.clock.advance(149);
  assert.equal(h.ports.length, 1);
  h.clock.advance(1);
  assert.equal(h.ports.length, 2);
  h.ports[1].activate(SECOND_ACTIVATION);
  assert.deepEqual(h.ports[1].sent.map((message) => message.id), [rid(2)]);
});

test("C4 disallowed methods (including wallet_addEthereumChain) get 4200 without connecting", () => {
  const h = harness();
  for (const [index, method] of ["wallet_addEthereumChain", "eth_sign", "eth_sendRawTransaction", "wallet_watchAsset", "foo_bar", "", "eth chainId"].entries()) {
    h.request(rid(index + 1), method);
    assert.deepEqual(h.responses(rid(index + 1))[0].error, { code: 4200, message: "Unsupported method." }, method);
  }
  assert.equal(h.ports.length, 0);
  assert.equal(h.bridge.state, STATES.IDLE);
  assert.equal(shared.methodRoute("wallet_addEthereumChain"), null);
});

// ---------- spec/05 §2.12 compatibility mode delivery (C5) ----------

test("C5 bridge-init carries the document's mode; requests carry compatMode only in compat modes", () => {
  for (const compatMode of ["off", "metamask", "rabby"]) {
    const h = harness({ compatMode });
    h.bridge.announce();
    h.bridge.receivePage({ namespace: "your-wallet", version: 1, kind: "bridge-request" });
    assert.deepEqual(h.page, [
      { namespace: "your-wallet", version: 1, kind: "bridge-init", channel: CHANNEL, compatMode, solCompatMode: "off", btcCompatMode: "off" },
      { namespace: "your-wallet", version: 1, kind: "bridge-init", channel: CHANNEL, compatMode, solCompatMode: "off", btcCompatMode: "off" }
    ], compatMode);
    h.request(rid(1), "eth_requestAccounts");
    h.ports[0].activate();
    const expected = {
      namespace: "your-wallet", version: 1, kind: "request", activationNonce: ACTIVATION, id: rid(1), method: "eth_requestAccounts", params: []
    };
    assert.deepEqual(h.ports[0].sent[0], compatMode === "off" ? expected : { ...expected, compatMode }, compatMode);
    // The background accepts exactly what the bridge sends.
    assert.equal(shared.parseContentMessage(h.ports[0].sent[0], ACTIVATION)?.compatMode, compatMode, compatMode);
  }
  // A page cannot change the mode: page requests with extra keys are dropped.
  const h = harness({ compatMode: "metamask" });
  assert.equal(h.bridge.receivePage({ namespace: "your-wallet", version: 1, kind: "request", channel: CHANNEL, id: rid(2), method: "eth_chainId", params: [], compatMode: "off" }), false);
  assert.equal(h.ports.length, 0);
  for (const compatMode of ["MetaMask", "on", "", null, 1]) {
    assert.throws(() => new ContentBridge({
      channelNonce: CHANNEL, compatMode, connectPort: () => null, postToPage: () => {}, isContextValid: () => true,
      setTimer: () => 0, clearTimer: () => {}, now: () => 0
    }), TypeError, String(compatMode));
  }
  // The default is off.
  const plain = harness();
  plain.bridge.announce();
  assert.equal(plain.page[0].compatMode, "off");
});

test("C6 Solana/Bitcoin modes go to bridge-init and only to requests of their own family", () => {
  const h = harness({ compatMode: "metamask", solCompatMode: "phantom", btcCompatMode: "xverse" });
  h.bridge.announce();
  assert.deepEqual(h.page[0], {
    namespace: "your-wallet", version: 1, kind: "bridge-init", channel: CHANNEL,
    compatMode: "metamask", solCompatMode: "phantom", btcCompatMode: "xverse"
  });
  h.request(rid(1), "eth_chainId");
  h.request(rid(2), "sol_connect");
  h.request(rid(3), "btc_getNetwork");
  h.ports[0].activate();
  assert.deepEqual(h.ports[0].sent.map((message) => message.compatMode), ["metamask", "phantom", "xverse"]);
  for (const message of h.ports[0].sent) {
    assert.notEqual(shared.parseContentMessage(message, ACTIVATION), null);
  }
  // A mode of another family is a malformed content message.
  assert.equal(shared.parseContentMessage({ ...h.ports[0].sent[1], compatMode: "metamask" }, ACTIVATION), null);
  assert.equal(shared.parseContentMessage({ ...h.ports[0].sent[0], compatMode: "phantom" }, ACTIVATION), null);
  for (const [solCompatMode, btcCompatMode] of [["metamask", "off"], ["off", "phantom"], ["Phantom", "off"]]) {
    assert.throws(() => new ContentBridge({
      channelNonce: CHANNEL, solCompatMode, btcCompatMode, connectPort: () => null, postToPage: () => {},
      isContextValid: () => true, setTimer: () => 0, clearTimer: () => {}, now: () => 0
    }), TypeError);
  }
});

test("C6 loadCompatModes reads the three keys and normalizes each", async () => {
  const { loadCompatModes } = globalThis.__YOUR_WALLET_CONTENT_CORE__;
  const clock = new FakeClock();
  const run = (stored) => loadCompatModes({ readStorage: () => Promise.resolve(stored), setTimer: clock.setTimer, clearTimer: clock.clearTimer });
  assert.deepEqual({ ...await run({ compatMode: "rabby", solCompatMode: "phantom", btcCompatMode: "unisat" }) }, { evm: "rabby", sol: "phantom", btc: "unisat" });
  assert.deepEqual({ ...await run({ solCompatMode: "metamask", btcCompatMode: "phantom" }) }, { evm: "off", sol: "off", btc: "off" });
  assert.deepEqual({ ...await loadCompatModes({ readStorage: () => Promise.reject(new Error("x")), setTimer: clock.setTimer, clearTimer: clock.clearTimer }) }, { evm: "off", sol: "off", btc: "off" });
});

test("C5 loadCompatMode reads compatMode once and falls back to off on bad values, errors and timeouts", async () => {
  const { loadCompatMode, MODE_READ_TIMEOUT_MS } = globalThis.__YOUR_WALLET_CONTENT_CORE__;
  assert.equal(MODE_READ_TIMEOUT_MS, 3_000);
  const run = (readStorage, clock = new FakeClock()) => loadCompatMode({ readStorage, setTimer: clock.setTimer, clearTimer: clock.clearTimer });
  for (const [stored, expected] of [
    [{ compatMode: "metamask" }, "metamask"],
    [{ compatMode: "rabby" }, "rabby"],
    [{ compatMode: "off" }, "off"],
    [{}, "off"],
    [{ compatMode: "MetaMask" }, "off"],
    [{ compatMode: 1 }, "off"],
    [{ compatMode: null }, "off"],
    [null, "off"],
    ["metamask", "off"]
  ]) {
    const clock = new FakeClock();
    assert.equal(await run(() => Promise.resolve(stored), clock), expected, JSON.stringify(stored));
    assert.equal(clock.timers.size, 0, "timer cleared");
  }
  assert.equal(await run(() => Promise.reject(new Error("storage unavailable"))), "off");
  assert.equal(await run(() => {
    throw new Error("Extension context invalidated.");
  }), "off");

  // A read that never answers resolves off after 3 s; a late answer is ignored.
  const clock = new FakeClock();
  let late = null;
  const pending = run(() => new Promise((resolve) => {
    late = resolve;
  }), clock);
  let result = null;
  pending.then((mode) => {
    result = mode;
  });
  clock.advance(2_999);
  await Promise.resolve();
  assert.equal(result, null);
  clock.advance(1);
  assert.equal(await pending, "off");
  late({ compatMode: "metamask" });
  await Promise.resolve();
  assert.equal(result, "off");
});
