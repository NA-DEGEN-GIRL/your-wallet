import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test, { afterEach, beforeEach, mock } from "node:test";
import vm from "node:vm";

const source = await readFile(new URL("../src/provider-main.js", import.meta.url), "utf8");
const ORIGIN = "https://dapp.example";
const ANNOUNCE_EVENT = "eip6963:announceProvider";
const REQUEST_EVENT = "eip6963:requestProvider";
const CHANNEL = "ab".repeat(32);
const OTHER_CHANNEL = "cd".repeat(32);

class TestEvent {
  constructor(type) {
    this.type = type;
  }
}

class TestCustomEvent extends TestEvent {
  constructor(type, init = {}) {
    super(type);
    this.detail = init.detail;
  }
}

function createPage({ existingEthereum, lockedUndefinedEthereum = false, randomStart = 0, href = `${ORIGIN}/app`, top } = {}) {
  const listeners = new Map();
  const dispatched = [];
  const posted = [];
  let randomState = randomStart >>> 0;
  const url = new URL(href);
  const page = {
    CustomEvent: TestCustomEvent,
    Event: TestEvent,
    TextEncoder,
    URL,
    // Look the timer functions up at call time so node:test mock.timers can replace them.
    setTimeout: (callback, milliseconds) => setTimeout(callback, milliseconds),
    clearTimeout: (handle) => clearTimeout(handle),
    crypto: {
      // Deterministic LCG (not a wrapping byte counter) so request ids never cycle.
      getRandomValues(bytes) {
        for (let index = 0; index < bytes.length; index += 1) {
          randomState = (Math.imul(randomState, 1_103_515_245) + 12_345) >>> 0;
          bytes[index] = randomState >>> 24;
        }
        return bytes;
      }
    },
    location: { href: url.href, origin: url.origin, protocol: url.protocol, hostname: url.hostname }
  };
  page.addEventListener = (type, listener) => {
    const current = listeners.get(type) ?? new Set();
    current.add(listener);
    listeners.set(type, current);
  };
  page.dispatchEvent = (event) => {
    dispatched.push(event);
    for (const listener of [...(listeners.get(event.type) ?? [])]) {
      listener.call(page, event);
    }
    return true;
  };
  page.postMessage = (message, targetOrigin) => {
    posted.push({ message, targetOrigin });
  };
  if (existingEthereum !== undefined || lockedUndefinedEthereum) {
    Object.defineProperty(page, "ethereum", {
      configurable: false,
      enumerable: true,
      value: existingEthereum,
      writable: false
    });
  }

  const context = vm.createContext(page);
  context.top = top === undefined ? context : top;
  vm.runInContext(source, context, { filename: "provider-main.js" });
  return { context, dispatched, listeners, posted };
}

function announcements(page) {
  return page.dispatched.filter((event) => event.type === ANNOUNCE_EVENT);
}

function providerOf(page) {
  return announcements(page)[0].detail.provider;
}

function dispatchMessage(page, data, { origin } = {}) {
  // Browser messages and provider arguments originate in the page realm. VM
  // tests must preserve both that prototype and the exact `event.source ===
  // window` identity checked by the production bridge.
  page.context.__TEST_MESSAGE_JSON__ = JSON.stringify(data);
  page.context.__TEST_ORIGIN__ = origin;
  vm.runInContext(`
    {
      const event = new Event("message");
      event.source = globalThis;
      event.origin = __TEST_ORIGIN__ ?? location.origin;
      event.data = JSON.parse(__TEST_MESSAGE_JSON__);
      dispatchEvent(event);
    }
  `, page.context);
  delete page.context.__TEST_MESSAGE_JSON__;
  delete page.context.__TEST_ORIGIN__;
}

function pageValue(page, value) {
  return vm.runInContext(`(${JSON.stringify(value)})`, page.context);
}

function bridgeInit(page, channel = CHANNEL) {
  dispatchMessage(page, { namespace: "your-wallet", version: 1, kind: "bridge-init", channel });
}

function respond(page, id, body, channel = CHANNEL) {
  dispatchMessage(page, { namespace: "your-wallet", version: 1, kind: "response", channel, id, ...body });
}

function sendEvent(page, event, payload) {
  dispatchMessage(page, { namespace: "your-wallet", version: 1, kind: "event", channel: CHANNEL, event, payload });
}

function pageDisconnect(page) {
  dispatchMessage(page, {
    namespace: "your-wallet", version: 1, kind: "disconnect", channel: CHANNEL,
    error: { code: 4900, message: "Wallet extension was reloaded." }
  });
}

function requests(page) {
  return page.posted.filter((entry) => entry.message.kind === "request").map((entry) => entry.message);
}

const flush = () => new Promise((resolve) => setImmediate(resolve));

// Every test runs on mocked timers so pending 605 s / 10 s timers never keep the process alive.
beforeEach(() => mock.timers.enable({ apis: ["setTimeout"] }));
afterEach(() => mock.timers.reset());

test("P1 window.ethereum is defined configurable only when absent, with ethereum#initialized", () => {
  const page = createPage();
  const descriptor = Object.getOwnPropertyDescriptor(page.context, "ethereum");
  assert.equal(descriptor.value, providerOf(page));
  assert.equal(descriptor.configurable, true);
  assert.equal(descriptor.enumerable, true);
  assert.equal(descriptor.writable, true);
  assert.equal(page.dispatched.filter((event) => event.type === "ethereum#initialized").length, 1);
  assert.equal("yourWallet" in page.context, false);
  assert.equal(page.dispatched.some((event) => event.type === "yourWallet#initialized"), false);
  // Another wallet may replace it later.
  page.context.ethereum = { other: true };
  assert.deepEqual(page.context.ethereum, { other: true });

  const incumbent = Object.freeze({ request: () => "incumbent" });
  const occupied = createPage({ existingEthereum: incumbent });
  assert.equal(occupied.context.ethereum, incumbent);
  assert.notEqual(providerOf(occupied), incumbent);
  assert.equal(occupied.dispatched.some((event) => event.type === "ethereum#initialized"), false);

  const reserved = createPage({ lockedUndefinedEthereum: true });
  assert.equal(reserved.context.ethereum, undefined);
  assert.equal(announcements(reserved).length, 1);
});

test("P1 announces one frozen EIP-6963 detail with the io.github rdns, page UUIDv4 and local PNG", () => {
  const page = createPage();
  const [announcement] = announcements(page);
  assert.ok(announcement instanceof TestCustomEvent);
  assert.equal(announcements(page).length, 1);
  assert.deepEqual(Object.keys(announcement.detail).sort(), ["info", "provider"]);
  assert.deepEqual(Object.keys(announcement.detail.info).sort(), ["icon", "name", "rdns", "uuid"]);
  assert.match(announcement.detail.info.uuid, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u);
  assert.equal(announcement.detail.info.name, "Your Wallet");
  assert.equal(announcement.detail.info.rdns, "io.github.na-degen-girl.yourwallet");
  assert.match(announcement.detail.info.icon, /^data:image\/png;base64,[A-Za-z0-9+/]+={0,2}$/u);
  const png = Buffer.from(announcement.detail.info.icon.split(",")[1], "base64");
  assert.equal(png.subarray(1, 4).toString("ascii"), "PNG");
  assert.equal(png.readUInt32BE(16), 96);
  assert.equal(png.readUInt32BE(20), 96);
  assert.equal(Object.isFrozen(announcement.detail.info), true);
  assert.equal(Object.isFrozen(announcement.detail), true);
  assert.throws(() => {
    announcement.detail.info.name = "Imitated Wallet";
  }, TypeError);

  // Announce always: every request re-announces the same identity, even when ethereum is taken.
  const second = createPage({ randomStart: 64, existingEthereum: { other: true } });
  assert.notEqual(announcements(second)[0].detail.info.uuid, announcement.detail.info.uuid);
  page.context.dispatchEvent(new TestEvent(REQUEST_EVENT));
  page.context.dispatchEvent(new TestEvent(REQUEST_EVENT));
  assert.equal(announcements(page).length, 3);
  for (const event of announcements(page)) {
    assert.equal(event.detail, announcement.detail);
  }
  second.context.dispatchEvent(new TestEvent(REQUEST_EVENT));
  assert.equal(announcements(second).length, 2);
});

test("P1 a reentrant hostile request cannot recurse announcements", () => {
  const page = createPage();
  const initial = announcements(page)[0];
  let attempted = false;
  page.context.addEventListener(ANNOUNCE_EVENT, () => {
    if (!attempted) {
      attempted = true;
      page.context.dispatchEvent(new TestEvent(REQUEST_EVENT));
    }
  });
  page.context.dispatchEvent(new TestEvent(REQUEST_EVENT));
  const observed = announcements(page);
  assert.equal(observed.length, 2);
  assert.equal(observed[1].detail, initial.detail);
});

test("P1 unsupported pages and subframes install nothing", () => {
  for (const href of ["http://example.com/", "http://[::1]:5173/", "file:///C:/x.html"]) {
    const page = createPage({ href });
    assert.equal(announcements(page).length, 0, href);
    assert.equal("ethereum" in page.context, false, href);
  }
  const frame = createPage({ top: {} });
  assert.equal(announcements(frame).length, 0);
  const local = createPage({ href: "http://localhost:5173/" });
  assert.equal(announcements(local).length, 1);
  assert.equal(local.posted[0].targetOrigin, "http://localhost:5173");
  assert.equal(announcements(createPage({ href: "http://127.0.0.1/" })).length, 1);
});

test("P2 the provider is extensible and its built-in members cannot be overwritten", () => {
  const page = createPage();
  const provider = providerOf(page);
  assert.equal(Object.isExtensible(provider), true);
  assert.equal(Object.isFrozen(provider), false);
  provider.legacyFlag = 1;
  assert.equal(provider.legacyFlag, 1);
  for (const name of [
    "isYourWallet", "isMetaMask", "chainId", "selectedAddress", "isConnected", "request", "enable",
    "on", "addListener", "once", "off", "removeListener", "removeAllListeners", "listenerCount"
  ]) {
    const descriptor = Object.getOwnPropertyDescriptor(provider, name);
    assert.ok(descriptor, name);
    assert.equal(descriptor.configurable, false, name);
    if ("value" in descriptor) {
      assert.equal(descriptor.writable, false, name);
    } else {
      assert.equal(descriptor.set, undefined, name);
    }
    assert.throws(() => {
      provider[name] = () => "forged";
    }, TypeError, name);
    assert.throws(() => Object.defineProperty(provider, name, { value: 1 }), TypeError, name);
  }
  assert.equal(provider.isYourWallet, true);
  assert.equal(provider.isMetaMask, false);
  assert.equal(provider.chainId, null);
  assert.equal(provider.selectedAddress, null);
});

test("P3 EventEmitter API: on/addListener/once/off/removeListener/removeAllListeners/listenerCount", () => {
  const page = createPage();
  const provider = providerOf(page);
  bridgeInit(page);
  const calls = [];
  const a = (value) => calls.push(["a", value]);
  const b = (value) => calls.push(["b", value]);
  const c = (value) => calls.push(["c", value]);
  assert.equal(provider.on("chainChanged", a), provider);
  assert.equal(provider.addListener("chainChanged", b), provider);
  assert.equal(provider.once("chainChanged", c), provider);
  assert.equal(provider.listenerCount("chainChanged"), 3);
  sendEvent(page, "chainChanged", "0x1");
  sendEvent(page, "chainChanged", "0x2");
  assert.deepEqual(calls, [["a", "0x1"], ["b", "0x1"], ["c", "0x1"], ["a", "0x2"], ["b", "0x2"]]);
  assert.equal(provider.listenerCount("chainChanged"), 2);

  assert.equal(provider.off("chainChanged", a), provider);
  assert.equal(provider.removeListener("chainChanged", b), provider);
  assert.equal(provider.listenerCount("chainChanged"), 0);

  // once + off with the original function removes it.
  provider.once("accountsChanged", a);
  assert.equal(provider.listenerCount("accountsChanged"), 1);
  provider.off("accountsChanged", a);
  assert.equal(provider.listenerCount("accountsChanged"), 0);

  // Unknown events register nothing and never throw; non-functions throw TypeError.
  assert.equal(provider.on("data", a), provider);
  assert.equal(provider.on("notification", a), provider);
  assert.equal(provider.listenerCount("data"), 0);
  assert.equal(provider.on("message", a), provider);
  assert.equal(provider.listenerCount("message"), 1);
  assert.throws(() => provider.on("chainChanged", "not a function"), (error) => error.name === "TypeError");
  assert.throws(() => provider.once("chainChanged", null), (error) => error.name === "TypeError");

  provider.on("accountsChanged", a);
  provider.on("connect", b);
  assert.equal(provider.removeAllListeners("accountsChanged"), provider);
  assert.equal(provider.listenerCount("accountsChanged"), 0);
  assert.equal(provider.listenerCount("connect"), 1);
  assert.equal(provider.removeAllListeners(), provider);
  assert.equal(provider.listenerCount("connect"), 0);
  assert.equal(provider.listenerCount("message"), 0);

  // Listener exceptions are isolated.
  const seen = [];
  provider.on("accountsChanged", () => {
    throw new Error("dApp bug");
  });
  provider.on("accountsChanged", (accounts) => seen.push(accounts));
  const account = `0x${"12".repeat(20)}`;
  sendEvent(page, "accountsChanged", [account]);
  assert.equal(JSON.stringify(seen), JSON.stringify([[account]]));
  assert.equal(provider.selectedAddress, account);
  sendEvent(page, "accountsChanged", []);
  assert.equal(provider.selectedAddress, null);
});

test("P4 connect fires once when chainId is first learned; transient 4900 never emits disconnect", async () => {
  const page = createPage();
  const provider = providerOf(page);
  const connects = [];
  const disconnects = [];
  provider.on("connect", (info) => connects.push(info));
  provider.on("disconnect", (error) => disconnects.push(error));
  assert.equal(provider.isConnected(), false);
  bridgeInit(page);
  assert.equal(provider.isConnected(), true);

  const chainPromise = provider.request(pageValue(page, { method: "eth_chainId" }));
  await flush();
  respond(page, requests(page)[0].id, { result: "0xaa36a7" });
  assert.equal(await chainPromise, "0xaa36a7");
  assert.equal(provider.chainId, "0xaa36a7");
  assert.equal(JSON.stringify(connects), JSON.stringify([{ chainId: "0xaa36a7" }]));
  sendEvent(page, "chainChanged", "0x1");
  assert.equal(provider.chainId, "0x1");
  assert.equal(connects.length, 1);

  const transient = provider.request(pageValue(page, { method: "eth_blockNumber", params: [] }));
  await flush();
  respond(page, requests(page)[1].id, { error: { code: 4900, message: "Wallet connection closed." } });
  await assert.rejects(transient, (error) => error.code === 4900 && error.message === "Wallet connection closed.");
  assert.equal(disconnects.length, 0);
  assert.equal(provider.isConnected(), true);

  const accountsPromise = provider.request(pageValue(page, { method: "eth_requestAccounts", params: [] }));
  await flush();
  const account = `0x${"34".repeat(20)}`;
  respond(page, requests(page)[2].id, { result: [account] });
  assert.equal(JSON.stringify(await accountsPromise), JSON.stringify([account]));
  assert.equal(provider.selectedAddress, account);

  const stuck = provider.request(pageValue(page, { method: "eth_accounts", params: [] }));
  await flush();
  pageDisconnect(page);
  pageDisconnect(page);
  await assert.rejects(stuck, (error) => error.code === 4900 && error.message === "Wallet extension was reloaded.");
  assert.equal(disconnects.length, 1);
  assert.equal(disconnects[0].code, 4900);
  assert.equal(disconnects[0].message, "Wallet extension was reloaded.");
  assert.equal(provider.isConnected(), false);
  await assert.rejects(
    provider.request(pageValue(page, { method: "eth_chainId" })),
    (error) => error.code === 4900 && error.message === "Wallet extension was reloaded."
  );
  assert.equal(connects.length, 1);
});

test("P4 a chainChanged event can be the first chainId and emits connect before chainChanged", () => {
  const page = createPage();
  const provider = providerOf(page);
  const order = [];
  provider.on("connect", () => order.push("connect"));
  provider.on("chainChanged", () => order.push("chainChanged"));
  bridgeInit(page);
  sendEvent(page, "chainChanged", "0x3e7");
  sendEvent(page, "chainChanged", "0x1");
  assert.deepEqual(order, ["connect", "chainChanged", "chainChanged"]);
});

test("P4 request validation: method format 4200, params -32602, size -32600, pending -32005", async () => {
  const page = createPage();
  const provider = providerOf(page);
  bridgeInit(page);
  for (const args of [undefined, null, "eth_chainId", { method: 1 }, { method: "" }, { method: "eth chainId" }, { method: "x".repeat(97) }]) {
    await assert.rejects(provider.request(args === undefined || args === null || typeof args === "string" ? args : pageValue(page, args)),
      (error) => error.code === 4200 && error.message === "Unsupported method.");
  }
  await assert.rejects(provider.request(pageValue(page, { method: "eth_call", params: "0x" })),
    (error) => error.code === -32602 && error.message === "Invalid params.");
  await assert.rejects(provider.request(pageValue(page, { method: "personal_sign", params: ["x".repeat(1_048_576)] })),
    (error) => error.code === -32600 && error.message === "Request too large.");
  // The method allowlist is the content script's job: unknown but well-formed names are forwarded.
  void provider.request(pageValue(page, { method: "wallet_addEthereumChain", params: [{}], id: 7, jsonrpc: "2.0" }));
  await flush();
  assert.equal(requests(page)[0].method, "wallet_addEthereumChain");
  assert.deepEqual(Object.keys(requests(page)[0]).sort(), ["channel", "id", "kind", "method", "namespace", "params", "version"]);
  assert.match(requests(page)[0].id, /^[0-9a-f]{32}$/u);
  // Undefined members (common in dApp tx objects) are normalized away by the JSON form.
  void provider.request(vm.runInContext(`({ method: "eth_call", params: [{ to: "0x00", data: undefined }] })`, page.context));
  await flush();
  assert.deepEqual(Object.keys(requests(page)[1].params[0]), ["to"]);
  for (let index = 2; index < 64; index += 1) {
    void provider.request(pageValue(page, { method: "eth_blockNumber" }));
  }
  await flush();
  assert.equal(requests(page).length, 64);
  await assert.rejects(provider.request(pageValue(page, { method: "eth_blockNumber" })),
    (error) => error.code === -32005 && error.message === "Too many pending requests.");
});

test("P5 a 605 s timeout rejects -32603 and posts a page cancel; 604 s is still pending", async () => {
  const page = createPage();
  const provider = providerOf(page);
  bridgeInit(page);
  let settled = false;
  const promise = provider.request(pageValue(page, { method: "personal_sign", params: ["0x00", `0x${"12".repeat(20)}`] }));
  promise.then(() => {
    settled = true;
  }, () => {
    settled = true;
  });
  await flush();
  const [outbound] = requests(page);
  mock.timers.tick(604_000);
  await flush();
  assert.equal(settled, false);
  assert.equal(page.posted.some((entry) => entry.message.kind === "cancel"), false);
  mock.timers.tick(999);
  await flush();
  assert.equal(settled, false);
  mock.timers.tick(1);
  await assert.rejects(promise, (error) => error.code === -32603 && error.message === "Request timed out.");
  const cancels = page.posted.filter((entry) => entry.message.kind === "cancel");
  assert.equal(cancels.length, 1);
  assert.deepEqual({ ...cancels[0].message }, { namespace: "your-wallet", version: 1, kind: "cancel", channel: CHANNEL, id: outbound.id });
  assert.equal(cancels[0].targetOrigin, ORIGIN);
  // A late response is ignored.
  respond(page, outbound.id, { result: "0xsig" });
});

test("P6 bridge-request at start; same-channel bridge-init is accepted again, other channels ignored", async () => {
  const page = createPage();
  const provider = providerOf(page);
  assert.deepEqual({ ...page.posted[0].message }, { namespace: "your-wallet", version: 1, kind: "bridge-request" });
  assert.equal(page.posted[0].targetOrigin, ORIGIN);
  bridgeInit(page);
  bridgeInit(page);
  bridgeInit(page, OTHER_CHANNEL);
  dispatchMessage(page, { namespace: "your-wallet", version: 1, kind: "bridge-init", channel: OTHER_CHANNEL }, { origin: "https://evil.example" });
  const promise = provider.request(pageValue(page, { method: "eth_chainId" }));
  await flush();
  assert.equal(requests(page)[0].channel, CHANNEL);
  // A response on another channel does not complete the request.
  respond(page, requests(page)[0].id, { result: "0x5" }, OTHER_CHANNEL);
  respond(page, requests(page)[0].id, { result: "0x1" });
  assert.equal(await promise, "0x1");
});

test("P6 without a channel a request waits 10 s and then fails 4900; a late bridge-init unblocks waiters", async () => {
  const page = createPage();
  const provider = providerOf(page);
  let settled = false;
  const waiting = provider.request(pageValue(page, { method: "eth_chainId" }));
  waiting.then(() => {
    settled = true;
  }, () => {
    settled = true;
  });
  mock.timers.tick(9_999);
  await flush();
  assert.equal(settled, false);
  mock.timers.tick(1);
  await assert.rejects(waiting, (error) => error.code === 4900 && error.message === "Wallet connection closed.");
  assert.equal(requests(page).length, 0);

  const second = provider.request(pageValue(page, { method: "eth_chainId" }));
  mock.timers.tick(3_000);
  bridgeInit(page);
  await flush();
  assert.equal(requests(page).length, 1);
  respond(page, requests(page)[0].id, { result: "0xaa36a7" });
  assert.equal(await second, "0xaa36a7");
});
