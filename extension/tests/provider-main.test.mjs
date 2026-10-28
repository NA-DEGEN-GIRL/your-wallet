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
const OUR_RDNS = "io.github.na-degen-girl.yourwallet";

class TestEvent {
  constructor(type) {
    this.type = type;
    this.immediatePropagationStopped = false;
  }

  stopImmediatePropagation() {
    this.immediatePropagationStopped = true;
  }
}

class TestCustomEvent extends TestEvent {
  constructor(type, init = {}) {
    super(type);
    this.detail = init.detail;
  }
}

// `foreignEthereum`: another wallet assigned `window.ethereum = value` before us (plain data
// property). `existingEthereum` / `lockedUndefinedEthereum`: a non-configurable, non-writable
// incumbent. `beforeInstall(page)`: anything else to set up before provider-main.js runs.
// `init`: a compatibility mode delivered with bridge-init right after load, or false for none.
function createPage({
  existingEthereum, lockedUndefinedEthereum = false, foreignEthereum, beforeInstall,
  randomStart = 0, href = `${ORIGIN}/app`, top, init = "off"
} = {}) {
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
  // DOM order at the target: capture listeners first, then the others, each in registration
  // order; stopImmediatePropagation ends delivery.
  page.addEventListener = (type, listener, options) => {
    const capture = options === true || (typeof options === "object" && options !== null && options.capture === true);
    const current = listeners.get(type) ?? [];
    if (!current.some((entry) => entry.listener === listener && entry.capture === capture)) {
      current.push({ listener, capture });
    }
    listeners.set(type, current);
  };
  page.removeEventListener = (type, listener, options) => {
    const capture = options === true || (typeof options === "object" && options !== null && options.capture === true);
    listeners.set(type, (listeners.get(type) ?? []).filter((entry) => entry.listener !== listener || entry.capture !== capture));
  };
  page.dispatchEvent = (event) => {
    dispatched.push(event);
    const current = listeners.get(event.type) ?? [];
    for (const entry of [...current.filter((item) => item.capture), ...current.filter((item) => !item.capture)]) {
      entry.listener.call(page, event);
      if (event.immediatePropagationStopped) {
        break;
      }
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
  if (foreignEthereum !== undefined) {
    page.ethereum = foreignEthereum;
  }
  if (beforeInstall) {
    beforeInstall(page);
  }

  const context = vm.createContext(page);
  context.top = top === undefined ? context : top;
  vm.runInContext(source, context, { filename: "provider-main.js" });
  const result = { context, dispatched, listeners, posted };
  if (init !== false) {
    bridgeInit(result, CHANNEL, init);
  }
  return result;
}

function announcements(page) {
  return page.dispatched.filter((event) => event.type === ANNOUNCE_EVENT);
}

function providerOf(page) {
  return announcements(page)[0].detail.provider;
}

// What a dApp listener registered after the provider (the normal page order) receives.
function dappListener(page, { capture = false } = {}) {
  const seen = [];
  page.context.addEventListener(ANNOUNCE_EVENT, (event) => seen.push(event.detail), capture);
  return seen;
}

function foreignAnnouncement(page, rdns, name = rdns, provider = { foreign: rdns }) {
  const detail = Object.freeze({
    info: Object.freeze({ uuid: "00000000-0000-4000-8000-000000000000", name, icon: "data:image/png;base64,AA==", rdns }),
    provider
  });
  page.context.dispatchEvent(new TestCustomEvent(ANNOUNCE_EVENT, { detail }));
  return detail;
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

function bridgeInit(page, channel = CHANNEL, compatMode = "off") {
  dispatchMessage(page, { namespace: "your-wallet", version: 1, kind: "bridge-init", channel, compatMode });
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

function initializedCount(page) {
  return page.dispatched.filter((event) => event.type === "ethereum#initialized").length;
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
  assert.equal(initializedCount(page), 1);
  assert.equal("yourWallet" in page.context, false);
  assert.equal(page.dispatched.some((event) => event.type === "yourWallet#initialized"), false);
  // Another wallet may replace it later.
  page.context.ethereum = { other: true };
  assert.deepEqual(page.context.ethereum, { other: true });

  const incumbent = Object.freeze({ request: () => "incumbent" });
  const occupied = createPage({ existingEthereum: incumbent });
  assert.equal(occupied.context.ethereum, incumbent);
  assert.notEqual(providerOf(occupied), incumbent);
  assert.equal(initializedCount(occupied), 0);

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
  assert.equal(announcement.detail.info.rdns, OUR_RDNS);
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

test("P1 the first announcement waits for the mode in bridge-init; earlier requests are answered then", () => {
  const page = createPage({ init: false });
  assert.equal(announcements(page).length, 0);
  page.context.dispatchEvent(new TestEvent(REQUEST_EVENT));
  page.context.dispatchEvent(new TestEvent(REQUEST_EVENT));
  assert.equal(announcements(page).length, 0);
  // window.ethereum (default rule) is installed at once; only the announcement waits.
  assert.equal(typeof page.context.ethereum.request, "function");
  bridgeInit(page);
  assert.equal(announcements(page).length, 1);
  assert.equal(announcements(page)[0].detail.provider, page.context.ethereum);

  // Without any bridge-init the default identity is announced after 10 s.
  const silent = createPage({ init: false });
  mock.timers.tick(9_999);
  assert.equal(announcements(silent).length, 0);
  mock.timers.tick(1);
  assert.equal(announcements(silent).length, 1);
  assert.equal(announcements(silent)[0].detail.info.rdns, OUR_RDNS);
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
    const page = createPage({ href, init: false });
    mock.timers.tick(10_000);
    assert.equal(announcements(page).length, 0, href);
    assert.equal("ethereum" in page.context, false, href);
    assert.equal(page.posted.length, 0, href);
  }
  const frame = createPage({ top: {}, init: false });
  mock.timers.tick(10_000);
  assert.equal(announcements(frame).length, 0);
  const local = createPage({ href: "http://localhost:5173/", init: false });
  assert.equal(local.posted[0].targetOrigin, "http://localhost:5173");
  dispatchMessage(local, { namespace: "your-wallet", version: 1, kind: "bridge-init", channel: CHANNEL, compatMode: "off" });
  assert.equal(announcements(local).length, 1);
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
    "isYourWallet", "isMetaMask", "isRabby", "_metamask", "chainId", "selectedAddress", "isConnected", "request", "enable",
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
  assert.equal(provider.isRabby, false);
  assert.equal(provider._metamask, undefined);
  assert.equal(provider.chainId, null);
  assert.equal(provider.selectedAddress, null);
});

test("P3 EventEmitter API: on/addListener/once/off/removeListener/removeAllListeners/listenerCount", () => {
  const page = createPage();
  const provider = providerOf(page);
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
  const page = createPage({ init: false });
  const provider = page.context.ethereum;
  const connects = [];
  const disconnects = [];
  provider.on("connect", (info) => connects.push(info));
  provider.on("disconnect", (error) => disconnects.push(error));
  assert.equal(provider.isConnected(), false);
  bridgeInit(page);
  assert.equal(provider.isConnected(), true);
  assert.equal(providerOf(page), provider);

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
  const page = createPage({ init: false });
  const provider = page.context.ethereum;
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
  const page = createPage({ init: false });
  const provider = page.context.ethereum;
  assert.deepEqual({ ...page.posted[0].message }, { namespace: "your-wallet", version: 1, kind: "bridge-request" });
  assert.equal(page.posted[0].targetOrigin, ORIGIN);
  bridgeInit(page);
  bridgeInit(page);
  bridgeInit(page, OTHER_CHANNEL);
  dispatchMessage(page, { namespace: "your-wallet", version: 1, kind: "bridge-init", channel: OTHER_CHANNEL, compatMode: "off" }, { origin: "https://evil.example" });
  const promise = provider.request(pageValue(page, { method: "eth_chainId" }));
  await flush();
  assert.equal(requests(page)[0].channel, CHANNEL);
  // A response on another channel does not complete the request.
  respond(page, requests(page)[0].id, { result: "0x5" }, OTHER_CHANNEL);
  respond(page, requests(page)[0].id, { result: "0x1" });
  assert.equal(await promise, "0x1");
});

test("P6 without a channel a request waits 10 s and then fails 4900; a late bridge-init unblocks waiters", async () => {
  const page = createPage({ init: false });
  const provider = page.context.ethereum;
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

// ---------- spec/05 §2.12 compatibility mode (P7–P11) ----------

test("P7 mode delivery: bridge-init must carry a valid compatMode; the first one settles the document", () => {
  const page = createPage({ init: false });
  const provider = page.context.ethereum;
  // Missing, unknown or differently cased modes are not a valid bridge-init (no channel, no mode).
  dispatchMessage(page, { namespace: "your-wallet", version: 1, kind: "bridge-init", channel: CHANNEL });
  for (const compatMode of ["MetaMask", "on", "", 1, null]) {
    dispatchMessage(page, { namespace: "your-wallet", version: 1, kind: "bridge-init", channel: CHANNEL, compatMode });
  }
  dispatchMessage(page, { namespace: "your-wallet", version: 1, kind: "bridge-init", channel: CHANNEL, compatMode: "metamask", extra: 1 });
  assert.equal(provider.isConnected(), false);
  assert.equal(announcements(page).length, 0);
  assert.equal(provider.isMetaMask, false);

  bridgeInit(page, CHANNEL, "metamask");
  assert.equal(provider.isConnected(), true);
  assert.equal(provider.isMetaMask, true);
  // Later bridge-inits (same channel, another mode) never change the settled mode.
  bridgeInit(page, CHANNEL, "rabby");
  bridgeInit(page, CHANNEL, "off");
  assert.equal(provider.isRabby, false);
  assert.equal(provider.isMetaMask, true);
  page.context.dispatchEvent(new TestEvent(REQUEST_EVENT));
  assert.deepEqual(announcements(page).map((event) => event.detail.info.name), ["MetaMask", "MetaMask"]);

  // After the 10 s fallback the default identity is fixed; a late bridge-init only opens the channel.
  const late = createPage({ init: false });
  mock.timers.tick(10_000);
  bridgeInit(late, CHANNEL, "metamask");
  assert.equal(late.context.ethereum.isConnected(), true);
  assert.equal(late.context.ethereum.isMetaMask, false);
  assert.deepEqual(announcements(late).map((event) => event.detail.info.rdns), [OUR_RDNS]);
});

test("P8 identity flags and EIP-6963 info per mode (getters read the current mode)", () => {
  const expected = {
    off: { isMetaMask: false, isRabby: false, name: "Your Wallet", rdns: OUR_RDNS, metamask: false },
    metamask: { isMetaMask: true, isRabby: false, name: "MetaMask", rdns: "io.metamask", metamask: true },
    rabby: { isMetaMask: true, isRabby: true, name: "Rabby Wallet", rdns: "io.rabby", metamask: true }
  };
  const offIcon = announcements(createPage())[0].detail.info.icon;
  for (const [mode, want] of Object.entries(expected)) {
    const page = createPage({ init: false });
    const provider = page.context.ethereum;
    // Before the mode is known every flag reads as the default.
    assert.equal(provider.isMetaMask, false, mode);
    assert.equal(provider._metamask, undefined, mode);
    bridgeInit(page, CHANNEL, mode);
    assert.equal(provider.isYourWallet, true, mode);
    assert.equal(provider.isMetaMask, want.isMetaMask, mode);
    assert.equal(provider.isRabby, want.isRabby, mode);
    assert.equal(typeof provider._metamask?.isUnlocked, want.metamask ? "function" : "undefined", mode);
    if (want.metamask) {
      assert.equal(Object.isFrozen(provider._metamask), true, mode);
      assert.equal("requestBatch" in provider._metamask, false, mode);
    }
    // Exactly one identity: the compat identity replaces "Your Wallet" (no duplicate entries).
    page.context.dispatchEvent(new TestEvent(REQUEST_EVENT));
    const events = announcements(page);
    assert.equal(events.length, 2, mode);
    for (const event of events) {
      assert.equal(event.detail, events[0].detail, mode);
      assert.equal(event.detail.provider, provider, mode);
      assert.equal(event.detail.info.name, want.name, mode);
      assert.equal(event.detail.info.rdns, want.rdns, mode);
      // Our own PNG, never a third-party logo.
      assert.equal(event.detail.info.icon, offIcon, mode);
      assert.match(event.detail.info.uuid, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u, mode);
    }
    assert.equal(Object.isFrozen(events[0].detail.info), true, mode);
  }
});

test("P9 window.ethereum precedence vs a MetaMask injection before and after ours", () => {
  const metamask = Object.freeze({ isMetaMask: true, request: () => "real metamask" });

  // Compat, MetaMask assigned after us but before the mode arrived: taken back when the mode settles.
  const early = createPage({ init: false });
  const provider = early.context.ethereum;
  early.context.ethereum = metamask;
  assert.equal(early.context.ethereum, metamask);
  bridgeInit(early, CHANNEL, "metamask");
  assert.equal(early.context.ethereum, provider);
  assert.equal(initializedCount(early), 2);
  const descriptor = Object.getOwnPropertyDescriptor(early.context, "ethereum");
  assert.equal(typeof descriptor.get, "function");
  assert.equal(typeof descriptor.set, "function");
  assert.equal(descriptor.configurable, true);
  assert.equal(descriptor.enumerable, true);
  // MetaMask assigning after the mode is known: accepted without throwing (strict mode), ignored.
  early.context.ethereum = metamask;
  vm.runInContext(`"use strict"; globalThis.ethereum = { late: true };`, early.context);
  assert.equal(early.context.ethereum, provider);
  // A configurable redefinition does not throw for the other script; it is reclaimed at the next
  // checkpoint (eip6963:requestProvider, DOMContentLoaded, load).
  for (const checkpoint of [REQUEST_EVENT, "DOMContentLoaded", "load"]) {
    Object.defineProperty(early.context, "ethereum", { value: metamask, configurable: true, writable: true, enumerable: true });
    assert.equal(early.context.ethereum, metamask);
    early.context.dispatchEvent(new TestEvent(checkpoint));
    assert.equal(early.context.ethereum, provider, checkpoint);
  }

  // Compat, MetaMask injected before us (plain assignment): ours after the mode settles.
  for (const mode of ["metamask", "rabby"]) {
    const before = createPage({ foreignEthereum: metamask, init: false });
    assert.equal(before.context.ethereum, metamask);
    assert.equal(initializedCount(before), 0);
    bridgeInit(before, CHANNEL, mode);
    assert.equal(before.context.ethereum, providerOf(before), mode);
    assert.equal(before.context.ethereum.isMetaMask, true, mode);
    assert.equal(initializedCount(before), 1, mode);
  }

  // A wallet that made window.ethereum non-configurable but caches assignments (Rabby style):
  // our provider gets in through its setter.
  let cached;
  const rabbyLike = createPage({
    init: "metamask",
    beforeInstall: (page) => Object.defineProperty(page, "ethereum", {
      configurable: false,
      enumerable: true,
      get: () => cached ?? metamask,
      set: (value) => {
        cached = value;
      }
    })
  });
  assert.equal(rabbyLike.context.ethereum, providerOf(rabbyLike));

  // Non-configurable and not assignable: nothing throws, the incumbent stays, discovery still works.
  const locked = createPage({ existingEthereum: metamask, init: "metamask" });
  assert.equal(locked.context.ethereum, metamask);
  assert.equal(announcements(locked).length, 1);
  assert.equal(announcements(locked)[0].detail.info.rdns, "io.metamask");
  locked.context.dispatchEvent(new TestEvent(REQUEST_EVENT));
  assert.equal(locked.context.ethereum, metamask);

  // Off: unchanged rules. Ours only when absent; a later wallet replaces it; an earlier one stays.
  const off = createPage();
  off.context.ethereum = metamask;
  off.context.dispatchEvent(new TestEvent(REQUEST_EVENT));
  off.context.dispatchEvent(new TestEvent("load"));
  assert.equal(off.context.ethereum, metamask);
  const offBefore = createPage({ foreignEthereum: metamask });
  assert.equal(offBefore.context.ethereum, metamask);
  assert.equal(initializedCount(offBefore), 0);
});

test("P10 EIP-6963 interception: foreign MetaMask/Rabby announcements are hidden only in compat modes", () => {
  const blocked = ["io.metamask", "io.metamask.flask", "io.rabby", "IO.MetaMask"];
  const passing = ["io.coinbase.wallet", "app.phantom", OUR_RDNS, "io.metamask.evil", "com.example"];

  for (const mode of ["metamask", "rabby"]) {
    const page = createPage({ init: mode });
    const seen = dappListener(page);
    const seenCapture = dappListener(page, { capture: true });
    for (const rdns of blocked) {
      foreignAnnouncement(page, rdns);
    }
    for (const rdns of passing) {
      foreignAnnouncement(page, rdns);
    }
    page.context.dispatchEvent(new TestEvent(REQUEST_EVENT));
    const rdnsSeen = seen.map((detail) => detail.info.rdns);
    assert.deepEqual(rdnsSeen, [...passing, mode === "metamask" ? "io.metamask" : "io.rabby"], mode);
    assert.deepEqual(seenCapture.map((detail) => detail.info.rdns), rdnsSeen, mode);
    // The only MetaMask/Rabby entry the dApp sees is ours.
    assert.equal(seen.at(-1).provider, page.context.ethereum, mode);
    // Hostile or odd details never throw and are not blocked.
    const hostile = {};
    Object.defineProperty(hostile, "info", {
      get() {
        throw new Error("hostile getter");
      }
    });
    for (const detail of [hostile, null, undefined, 7, { info: null }, { info: { rdns: 5 } }]) {
      page.context.dispatchEvent(new TestCustomEvent(ANNOUNCE_EVENT, { detail }));
    }
    assert.equal(seen.length, passing.length + 1 + 6, mode);
  }

  // Off: nothing is intercepted.
  const off = createPage();
  const seenOff = dappListener(off);
  for (const rdns of [...blocked, ...passing]) {
    foreignAnnouncement(off, rdns);
  }
  assert.deepEqual(seenOff.map((detail) => detail.info.rdns), [...blocked, ...passing]);

  // Before the mode is known nothing is intercepted either (documented best-effort window).
  const early = createPage({ init: false });
  const seenEarly = dappListener(early);
  foreignAnnouncement(early, "io.metamask");
  bridgeInit(early, CHANNEL, "metamask");
  foreignAnnouncement(early, "io.metamask");
  assert.deepEqual(seenEarly.map((detail) => [detail.info.name, detail.provider === early.context.ethereum]), [
    ["io.metamask", false],
    ["MetaMask", true]
  ]);
});

test("P11 _metamask.isUnlocked() reflects eth_accounts for this origin and never rejects", async () => {
  const page = createPage({ init: "metamask" });
  const provider = providerOf(page);
  const answers = [
    [{ result: [] }, false],
    [{ result: [`0x${"ab".repeat(20)}`] }, true],
    [{ error: { code: 4100, message: "Unauthorized." } }, false],
    [{ result: "not an array" }, false]
  ];
  for (const [index, [body, expected]] of answers.entries()) {
    const unlocked = provider._metamask.isUnlocked();
    await flush();
    const request = requests(page)[index];
    assert.equal(request.method, "eth_accounts");
    assert.equal(JSON.stringify(request.params), "[]");
    respond(page, request.id, body);
    assert.equal(await unlocked, expected, JSON.stringify(body));
  }
  pageDisconnect(page);
  assert.equal(await provider._metamask.isUnlocked(), false);
  // Off mode has no _metamask at all.
  assert.equal(providerOf(createPage())._metamask, undefined);
});
