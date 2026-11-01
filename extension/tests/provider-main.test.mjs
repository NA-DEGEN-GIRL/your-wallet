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
  const reported = [];
  let randomState = randomStart >>> 0;
  const url = new URL(href);
  const page = {
    CustomEvent: TestCustomEvent,
    Event: TestEvent,
    TextEncoder,
    URL,
    // window.reportError: where a throwing legacy callback is reported (spec/05 §2.5).
    reportError: (error) => reported.push(error),
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
  const result = { context, dispatched, listeners, posted, reported };
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

function bridgeInit(page, channel = CHANNEL, compatMode = "off", solCompatMode = "off", btcCompatMode = "off") {
  dispatchMessage(page, { namespace: "your-wallet", version: 1, kind: "bridge-init", channel, compatMode, solCompatMode, btcCompatMode });
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
  bridgeInit(local);
  assert.equal(announcements(local).length, 1);
  assert.equal(announcements(createPage({ href: "http://127.0.0.1/" })).length, 1);
});

test("P2 the provider is extensible and its built-in members cannot be overwritten", () => {
  const page = createPage();
  const provider = providerOf(page);
  const members = [
    "isYourWallet", "isMetaMask", "isRabby", "_metamask", "chainId", "selectedAddress", "isConnected", "request", "enable",
    "send", "sendAsync", "on", "addListener", "once", "off", "removeListener", "removeAllListeners", "listenerCount"
  ];
  // The exact member set (spec/05 §2.5 table, legacy API included).
  assert.deepEqual([...Object.keys(provider)], members);
  assert.equal(Object.isExtensible(provider), true);
  assert.equal(Object.isFrozen(provider), false);
  provider.legacyFlag = 1;
  assert.equal(provider.legacyFlag, 1);
  for (const name of members) {
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

// Security review M4: a page script that posts its own bridge-init (or bridge-claim) cannot take
// the channel once the content script's synchronous bridge-claim was delivered, and cannot move
// it afterwards; requests flow only after bridge-init on the claimed channel.
test("P6 bridge-claim reserves the channel: forged bridge-init/claim from the page are ignored", async () => {
  const page = createPage({ init: false });
  const provider = page.context.ethereum;
  const claim = (channel, extra = {}) => dispatchMessage(page, { namespace: "your-wallet", version: 1, kind: "bridge-claim", channel, ...extra });
  // Malformed claims take nothing.
  claim("AB".repeat(32));
  claim(CHANNEL, { compatMode: "off" });
  claim(CHANNEL);
  // The page's forged claim and bridge-init on another channel lose to the content's claim.
  claim(OTHER_CHANNEL);
  bridgeInit(page, OTHER_CHANNEL, "metamask");
  assert.equal(provider.isConnected(), false);
  assert.equal(provider.isMetaMask, false);
  assert.equal(announcements(page).length, 0);
  // Claimed but not open: a request waits for bridge-init instead of going out.
  const promise = provider.request(pageValue(page, { method: "eth_chainId" }));
  await flush();
  assert.equal(requests(page).length, 0);
  // The content's bridge-init (claimed channel, stored mode) opens the bridge.
  bridgeInit(page, CHANNEL, "rabby");
  assert.equal(provider.isConnected(), true);
  assert.equal(provider.isRabby, true);
  await flush();
  assert.equal(requests(page).length, 1);
  assert.equal(requests(page)[0].channel, CHANNEL);
  respond(page, requests(page)[0].id, { result: "0x1" });
  assert.equal(await promise, "0x1");
  // Later forgeries move neither the channel nor the mode, and responses on them are ignored.
  claim(OTHER_CHANNEL);
  bridgeInit(page, OTHER_CHANNEL, "off");
  const next = provider.request(pageValue(page, { method: "eth_chainId" }));
  await flush();
  assert.equal(requests(page)[1].channel, CHANNEL);
  respond(page, requests(page)[1].id, { result: "0x5" }, OTHER_CHANNEL);
  respond(page, requests(page)[1].id, { result: "0x2" });
  assert.equal(await next, "0x2");
  assert.equal(provider.isRabby, true);
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

// ---------- spec/05 §2.5 legacy API: enable / send / sendAsync (P12) ----------

// JSON round trip into this realm (provider objects come from the page realm).
const plain = (value) => JSON.parse(JSON.stringify(value));
// Errors thrown by the provider belong to the page realm, so match by name.
const isTypeError = (error) => error.name === "TypeError";
const ACCOUNT = `0x${"5a".repeat(20)}`;

function legacyRecorder() {
  const calls = [];
  const callback = (error, response) => calls.push({ error, response });
  return { calls, callback };
}

test("P12 enable() and send(method, params) are request() with the same validation and errors", async () => {
  const page = createPage();
  const provider = providerOf(page);

  const enabled = provider.enable();
  await flush();
  assert.equal(requests(page)[0].method, "eth_requestAccounts");
  assert.equal(JSON.stringify(requests(page)[0].params), "[]");
  respond(page, requests(page)[0].id, { result: [ACCOUNT] });
  assert.equal(JSON.stringify(await enabled), JSON.stringify([ACCOUNT]));
  assert.equal(provider.selectedAddress, ACCOUNT);

  // send(method) / send(method, params) resolve to the raw result.
  const chain = provider.send("eth_chainId");
  assert.equal(typeof chain.then, "function");
  await flush();
  assert.equal(requests(page)[1].method, "eth_chainId");
  assert.equal(JSON.stringify(requests(page)[1].params), "[]");
  respond(page, requests(page)[1].id, { result: "0x1" });
  assert.equal(await chain, "0x1");
  assert.equal(provider.chainId, "0x1");

  const balance = provider.send("eth_getBalance", pageValue(page, [ACCOUNT, "latest"]));
  await flush();
  assert.deepEqual(plain(requests(page)[2]).params, [ACCOUNT, "latest"]);
  respond(page, requests(page)[2].id, { error: { code: 4100, message: "Unauthorized." } });
  await assert.rejects(balance, (error) => error.name === "ProviderRpcError" && error.code === 4100 && error.message === "Unauthorized.");

  // request() validation applies unchanged (no request leaves the page).
  await assert.rejects(provider.send("eth chainId"), (error) => error.code === 4200 && error.message === "Unsupported method.");
  await assert.rejects(provider.send("eth_call", "0x"), (error) => error.code === -32602 && error.message === "Invalid params.");
  await assert.rejects(provider.send("eth_call", () => {}), (error) => error.code === -32602);
  assert.equal(requests(page).length, 3);
});

test("P12 sendAsync / send(payload, cb): JSON-RPC response shapes, id passthrough, asynchronous callback", async () => {
  const page = createPage();
  const provider = providerOf(page);

  const ok = legacyRecorder();
  assert.equal(provider.sendAsync(pageValue(page, { id: 7, jsonrpc: "2.0", method: "eth_getBalance", params: [ACCOUNT, "latest"] }), ok.callback), undefined);
  await flush();
  // Only method and params reach the bridge, as with request().
  assert.deepEqual(Object.keys(requests(page)[0]).sort(), ["channel", "id", "kind", "method", "namespace", "params", "version"]);
  assert.equal(requests(page)[0].method, "eth_getBalance");
  assert.deepEqual(plain(requests(page)[0].params), [ACCOUNT, "latest"]);
  assert.equal(ok.calls.length, 0);
  respond(page, requests(page)[0].id, { result: "0x10" });
  await flush();
  assert.equal(ok.calls.length, 1);
  assert.equal(ok.calls[0].error, null);
  assert.deepEqual(plain(ok.calls[0].response), { id: 7, jsonrpc: "2.0", result: "0x10" });

  // Error: callback(error, { id, jsonrpc, error: { code, message } }), `data` only when present.
  const failed = legacyRecorder();
  provider.sendAsync(pageValue(page, { id: "a", method: "eth_accounts" }), failed.callback);
  const reverted = legacyRecorder();
  provider.sendAsync(pageValue(page, { id: 8, method: "eth_call", params: [{ to: ACCOUNT }] }), reverted.callback);
  await flush();
  respond(page, requests(page)[1].id, { error: { code: 4100, message: "Unauthorized." } });
  respond(page, requests(page)[2].id, { error: { code: 3, message: "execution reverted", data: "0x08c379a0" } });
  await flush();
  assert.equal(failed.calls.length, 1);
  assert.equal(failed.calls[0].error.name, "ProviderRpcError");
  assert.equal(failed.calls[0].error.code, 4100);
  assert.deepEqual(plain(failed.calls[0].response), { id: "a", jsonrpc: "2.0", error: { code: 4100, message: "Unauthorized." } });
  assert.equal("data" in failed.calls[0].response.error, false);
  assert.deepEqual(plain(reverted.calls[0].response), {
    id: 8, jsonrpc: "2.0", error: { code: 3, message: "execution reverted", data: "0x08c379a0" }
  });
  assert.equal(reverted.calls[0].error.data, "0x08c379a0");

  // A local rejection (no I/O) still calls back asynchronously, never inside sendAsync.
  const local = legacyRecorder();
  provider.sendAsync(pageValue(page, { id: 9, method: "eth chainId" }), local.callback);
  assert.equal(local.calls.length, 0);
  await flush();
  assert.equal(local.calls[0].error.code, 4200);
  assert.deepEqual(plain(local.calls[0].response), { id: 9, jsonrpc: "2.0", error: { code: 4200, message: "Unsupported method." } });

  // send(payload, callback) is sendAsync; a missing id passes through as undefined.
  const viaSend = legacyRecorder();
  assert.equal(provider.send(pageValue(page, { method: "net_version" }), viaSend.callback), undefined);
  await flush();
  assert.equal(requests(page)[3].method, "net_version");
  respond(page, requests(page)[3].id, { result: "1" });
  await flush();
  assert.equal(viaSend.calls[0].error, null);
  assert.equal(Object.hasOwn(viaSend.calls[0].response, "id"), true);
  assert.equal(viaSend.calls[0].response.id, undefined);
  assert.deepEqual(plain(viaSend.calls[0].response), { jsonrpc: "2.0", result: "1" });
});

test("P12 sendAsync batch: each element through request(), one callback with ordered responses", async () => {
  const page = createPage();
  const provider = providerOf(page);
  const batch = legacyRecorder();
  provider.sendAsync(pageValue(page, [
    { id: 1, jsonrpc: "2.0", method: "eth_chainId" },
    { id: 2, jsonrpc: "2.0", method: "eth_accounts", params: [] },
    { id: 3, jsonrpc: "2.0", method: "eth chainId" }
  ]), batch.callback);
  await flush();
  // The malformed method is rejected locally (4200) like request(); two requests go out.
  assert.deepEqual(requests(page).map((message) => message.method), ["eth_chainId", "eth_accounts"]);
  // Responses arrive out of order; the batch keeps payload order.
  respond(page, requests(page)[1].id, { error: { code: 4100, message: "Unauthorized." } });
  await flush();
  assert.equal(batch.calls.length, 0);
  respond(page, requests(page)[0].id, { result: "0xaa36a7" });
  await flush();
  assert.equal(batch.calls.length, 1);
  assert.equal(batch.calls[0].error, null);
  assert.deepEqual(plain(batch.calls[0].response), [
    { id: 1, jsonrpc: "2.0", result: "0xaa36a7" },
    { id: 2, jsonrpc: "2.0", error: { code: 4100, message: "Unauthorized." } },
    { id: 3, jsonrpc: "2.0", error: { code: 4200, message: "Unsupported method." } }
  ]);

  // Empty batch → callback(null, []).
  const empty = legacyRecorder();
  provider.sendAsync(pageValue(page, []), empty.callback);
  assert.equal(empty.calls.length, 0);
  await flush();
  assert.equal(empty.calls[0].error, null);
  assert.deepEqual(plain(empty.calls[0].response), []);

  // Every element is validated before anything is sent.
  assert.throws(() => provider.sendAsync(pageValue(page, [{ id: 4, method: "eth_chainId" }, { id: 5 }]), () => {}), isTypeError);
  assert.throws(() => provider.send(pageValue(page, [{ id: 6, method: "eth_chainId" }, null]), () => {}), isTypeError);
  await flush();
  assert.equal(requests(page).length, 2);

  // The pending limit still applies per element (64 in flight, the 65th answers -32005).
  const many = legacyRecorder();
  provider.sendAsync(pageValue(page, Array.from({ length: 65 }, (_, index) => ({ id: index, method: "eth_blockNumber" }))), many.callback);
  await flush();
  const outbound = requests(page).slice(2);
  assert.equal(outbound.length, 64);
  for (const message of outbound) {
    respond(page, message.id, { result: "0x1" });
  }
  await flush();
  const responses = plain(many.calls[0].response);
  assert.equal(responses.length, 65);
  assert.deepEqual(responses[0], { id: 0, jsonrpc: "2.0", result: "0x1" });
  assert.deepEqual(responses[64], { id: 64, jsonrpc: "2.0", error: { code: -32005, message: "Too many pending requests." } });
});

test("P12 synchronous send(payload): eth_accounts, eth_coinbase, net_version from cached state only", () => {
  const page = createPage();
  const provider = providerOf(page);
  const before = page.posted.length;
  const sync = (method) => plain(provider.send(pageValue(page, { id: 1, jsonrpc: "2.0", method })));
  assert.deepEqual(sync("eth_accounts"), { id: 1, jsonrpc: "2.0", result: [] });
  assert.deepEqual(sync("eth_coinbase"), { id: 1, jsonrpc: "2.0", result: null });
  assert.deepEqual(sync("net_version"), { id: 1, jsonrpc: "2.0", result: null });

  sendEvent(page, "accountsChanged", [ACCOUNT]);
  sendEvent(page, "chainChanged", "0xaa36a7");
  assert.deepEqual(sync("eth_accounts"), { id: 1, jsonrpc: "2.0", result: [ACCOUNT] });
  assert.deepEqual(sync("eth_coinbase"), { id: 1, jsonrpc: "2.0", result: ACCOUNT });
  assert.deepEqual(sync("net_version"), { id: 1, jsonrpc: "2.0", result: "11155111" });
  sendEvent(page, "chainChanged", "0x3e7");
  assert.deepEqual(sync("net_version"), { id: 1, jsonrpc: "2.0", result: "999" });
  // The id is passed through; a missing one stays undefined.
  assert.equal(provider.send(pageValue(page, { id: "x", method: "eth_accounts" })).id, "x");
  const noId = provider.send(pageValue(page, { method: "eth_accounts" }));
  assert.equal(Object.hasOwn(noId, "id"), true);
  assert.equal(noId.id, undefined);
  // The returned array is a copy of the cached view.
  provider.send(pageValue(page, { method: "eth_accounts" })).result.push("forged");
  assert.equal(provider.selectedAddress, ACCOUNT);

  // Everything else needs I/O: a plain Error (not an RPC error), nothing sent.
  for (const method of ["eth_chainId", "eth_requestAccounts", "eth_uninstallFilter", "eth_sendTransaction", "personal_sign", "bad method"]) {
    assert.throws(() => provider.send(pageValue(page, { id: 2, method })), (error) => {
      assert.equal(error.constructor.name, "Error", method);
      assert.equal(error.code, undefined, method);
      assert.match(error.message, /eth_accounts, eth_coinbase and net_version/u, method);
      return true;
    });
  }
  assert.equal(page.posted.length, before);
});

test("P12 invalid legacy payloads and callbacks throw TypeError before any request", async () => {
  const page = createPage();
  const provider = providerOf(page);
  const valid = pageValue(page, { id: 1, method: "eth_chainId" });
  for (const callback of [undefined, null, "callback", {}, 1]) {
    assert.throws(() => provider.sendAsync(valid, callback), isTypeError, String(callback));
  }
  const badPayloads = [undefined, null, "eth_chainId", 42, true, pageValue(page, {}), pageValue(page, { method: 1 }), pageValue(page, { method: null })];
  for (const payload of badPayloads) {
    assert.throws(() => provider.sendAsync(payload, () => {}), isTypeError, String(payload));
  }
  // send(): object (or missing) payload without a callback is the synchronous form.
  for (const payload of [undefined, null, 42, pageValue(page, {}), pageValue(page, { method: 1 }), pageValue(page, [{ method: "eth_accounts" }])]) {
    assert.throws(() => provider.send(payload), isTypeError, JSON.stringify(payload));
  }
  assert.throws(() => provider.send(), isTypeError);
  // A string method never throws: request() validation answers with a rejected Promise.
  await assert.rejects(provider.send(""), (error) => error.code === 4200);
  await flush();
  assert.equal(requests(page).length, 0);
});

test("P12 a throwing legacy callback is reported once and never breaks the provider", async () => {
  const page = createPage();
  const provider = providerOf(page);
  let invoked = 0;
  provider.sendAsync(pageValue(page, { id: 1, method: "eth_chainId" }), () => {
    invoked += 1;
    throw new Error("dApp callback bug");
  });
  await flush();
  respond(page, requests(page)[0].id, { result: "0x1" });
  await flush();
  // Called exactly once (not again with an error); the exception goes to window.reportError.
  assert.equal(invoked, 1);
  assert.equal(page.reported.length, 1);
  assert.equal(page.reported[0].message, "dApp callback bug");

  // Same for an error response and for a batch callback.
  provider.sendAsync(pageValue(page, { id: 2, method: "eth chainId" }), () => {
    throw new Error("error path bug");
  });
  provider.sendAsync(pageValue(page, []), () => {
    throw new Error("batch bug");
  });
  await flush();
  assert.deepEqual(page.reported.map((error) => error.message).sort(), ["batch bug", "dApp callback bug", "error path bug"]);

  // The provider keeps working: request() and sendAsync.
  const later = legacyRecorder();
  provider.sendAsync(pageValue(page, { id: 3, method: "eth_blockNumber" }), later.callback);
  const direct = provider.request(pageValue(page, { method: "eth_chainId" }));
  await flush();
  respond(page, requests(page)[1].id, { result: "0x2a" });
  respond(page, requests(page)[2].id, { result: "0x1" });
  assert.equal(await direct, "0x1");
  await flush();
  assert.deepEqual(plain(later.calls[0].response), { id: 3, jsonrpc: "2.0", result: "0x2a" });
  assert.equal(provider.isConnected(), true);

  // Without window.reportError the exception is swallowed (no unhandled rejection).
  const bare = createPage({ beforeInstall: (target) => delete target.reportError });
  const bareProvider = providerOf(bare);
  bareProvider.sendAsync(pageValue(bare, { id: 4, method: "eth chainId" }), () => {
    throw new Error("swallowed");
  });
  await flush();
  assert.equal(bare.reported.length, 0);
  const after = bareProvider.request(pageValue(bare, { method: "eth_chainId" }));
  await flush();
  respond(bare, requests(bare)[0].id, { result: "0x1" });
  assert.equal(await after, "0x1");
});

test("P12 the legacy API exists in every mode (and before the mode is known), non-writable", async () => {
  for (const mode of [false, "off", "metamask", "rabby"]) {
    const page = createPage({ init: mode });
    const provider = page.context.ethereum;
    for (const name of ["enable", "send", "sendAsync"]) {
      const descriptor = Object.getOwnPropertyDescriptor(provider, name);
      assert.equal(typeof descriptor.value, "function", `${mode} ${name}`);
      assert.equal(descriptor.writable, false, `${mode} ${name}`);
      assert.equal(descriptor.configurable, false, `${mode} ${name}`);
    }
    if (mode === false) {
      continue;
    }
    assert.equal(provider.isMetaMask, mode !== "off", mode);
    const result = legacyRecorder();
    provider.sendAsync(pageValue(page, { id: 1, method: "eth_accounts" }), result.callback);
    const sent = provider.send("eth_chainId");
    await flush();
    assert.deepEqual(requests(page).map((message) => message.method), ["eth_accounts", "eth_chainId"], mode);
    respond(page, requests(page)[0].id, { result: [ACCOUNT] });
    respond(page, requests(page)[1].id, { result: "0x1" });
    assert.equal(await sent, "0x1");
    await flush();
    assert.deepEqual(plain(result.calls[0].response), { id: 1, jsonrpc: "2.0", result: [ACCOUNT] });
    assert.deepEqual(plain(provider.send(pageValue(page, { id: 2, method: "eth_coinbase" }))), { id: 2, jsonrpc: "2.0", result: ACCOUNT });
  }
});

// ---------- spec/05 §2.13 Solana / Bitcoin shims (P13–P16) ----------

const SOL_KEY = "FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z";
const SOL_KEY_2 = "4Nd1mBQtrMJVYVfKf2PJy9NZUZdTAsp7D4xWLs4gDB4T";
const SOL_UNSUPPORTED = "이 지갑은 Solana에서 메시지 서명(소유 증명)만 지원합니다";
const BTC_UNSUPPORTED = "이 지갑은 Bitcoin에서 메시지 서명(소유 증명)만 지원합니다";

function lastRequest(page) {
  const all = requests(page);
  return all[all.length - 1];
}

function registeredWallets(page) {
  const wallets = [];
  for (const event of page.dispatched.filter((item) => item.type === "wallet-standard:register-wallet")) {
    event.detail({ register: (wallet) => wallets.push(wallet) });
  }
  return wallets;
}

test("P13 Wallet Standard: 'Your Wallet' in off mode, app-ready answered, features and tx rejection", async () => {
  const page = createPage({ init: false });
  const early = [];
  page.context.dispatchEvent(new TestCustomEvent("wallet-standard:app-ready", { detail: { register: (wallet) => early.push(wallet) } }));
  assert.equal(registeredWallets(page).length, 0, "nothing before the mode is known");
  bridgeInit(page);
  const [wallet] = registeredWallets(page);
  assert.equal(early.length, 1);
  assert.equal(early[0], wallet);
  assert.equal(wallet.name, "Your Wallet");
  assert.equal(wallet.version, "1.0.0");
  assert.match(wallet.icon, /^data:image\/png;base64,/u);
  assert.deepEqual(plain(wallet.chains), ["solana:mainnet", "solana:devnet"]);
  assert.deepEqual(Object.keys(wallet.features).sort(), [
    "solana:signIn", "solana:signMessage", "solana:signTransaction",
    "standard:connect", "standard:disconnect", "standard:events"
  ]);
  assert.deepEqual(plain(wallet.features["solana:signTransaction"].supportedTransactionVersions), ["legacy"]);
  await assert.rejects(wallet.features["solana:signTransaction"].signTransaction({}), (error) => error.code === 4200 && error.message === SOL_UNSUPPORTED);
  // Off modes expose no Phantom, UniSat or Xverse globals.
  for (const name of ["phantom", "solana", "unisat", "XverseProviders", "BitcoinProvider", "btc_providers"]) {
    assert.equal(name in page.context, false, name);
  }
  // A later app-ready is answered at once.
  const late = [];
  page.context.dispatchEvent(new TestCustomEvent("wallet-standard:app-ready", { detail: { register: (item) => late.push(item) } }));
  assert.equal(late[0], wallet);

  const changes = [];
  wallet.features["standard:events"].on("change", (properties) => changes.push(properties.accounts.length));
  const connecting = wallet.features["standard:connect"].connect();
  const connectRequest = lastRequest(page);
  assert.equal(connectRequest.method, "sol_connect");
  assert.equal(JSON.stringify(connectRequest.params), "[]");
  respond(page, connectRequest.id, { result: { publicKey: SOL_KEY } });
  const connected = await connecting;
  assert.equal(connected.accounts[0].address, SOL_KEY);
  assert.equal(connected.accounts[0].publicKey.length, 32);
  assert.deepEqual(changes, [1]);
  // signMessage: the exact bytes as hex, a 64-byte signature back.
  const message = vm.runInContext("new TextEncoder().encode('Prove it')", page.context);
  const signing = wallet.features["solana:signMessage"].signMessage({ account: wallet.accounts[0], message });
  const signRequest = lastRequest(page);
  assert.equal(signRequest.method, "sol_signMessage");
  assert.equal(JSON.stringify(signRequest.params), JSON.stringify([{ publicKey: SOL_KEY, message: Buffer.from("Prove it").toString("hex") }]));
  respond(page, signRequest.id, { result: { publicKey: SOL_KEY, signature: "11".repeat(64) } });
  const [output] = await signing;
  assert.equal(output.signature.length, 64);
  assert.equal(output.signatureType, "ed25519");
  // Another account is refused locally.
  await assert.rejects(
    wallet.features["solana:signMessage"].signMessage({ account: { address: SOL_KEY_2 }, message }),
    (error) => error.code === 4100
  );
  // signIn: the app returns the bytes it built and signed.
  const signingIn = wallet.features["solana:signIn"].signIn(pageValue(page, { statement: "Hi" }));
  const signInRequest = lastRequest(page);
  assert.equal(signInRequest.method, "sol_signIn");
  assert.equal(JSON.stringify(signInRequest.params), JSON.stringify([{ publicKey: SOL_KEY, input: { statement: "Hi" } }]));
  respond(page, signInRequest.id, { result: { publicKey: SOL_KEY, signature: "22".repeat(64), signedMessage: "6869" } });
  const [signedIn] = await signingIn;
  assert.equal(signedIn.account.address, SOL_KEY);
  assert.deepEqual(Array.from(signedIn.signedMessage), [0x68, 0x69]);
  // The wallet locks or the site is disconnected in the app: accounts go away.
  sendEvent(page, "solAccountsChanged", []);
  assert.equal(wallet.accounts.length, 0);
  assert.deepEqual(changes, [1, 0]);
  // Silent connect never throws.
  const silent = wallet.features["standard:connect"].connect(pageValue(page, { silent: true }));
  const silentRequest = lastRequest(page);
  assert.equal(JSON.stringify(silentRequest.params), JSON.stringify([{ onlyIfTrusted: true }]));
  respond(page, silentRequest.id, { error: { code: 4001, message: "User rejected the request." } });
  assert.equal((await silent).accounts.length, 0);
});

test("P14 phantom mode: window.phantom.solana shim, 'Phantom' Wallet Standard name, our icon", async () => {
  const page = createPage({ init: false });
  bridgeInit(page, CHANNEL, "off", "phantom", "off");
  const [wallet] = registeredWallets(page);
  assert.equal(wallet.name, "Phantom");
  const phantom = page.context.phantom.solana;
  assert.equal(page.context.solana, phantom);
  assert.equal(phantom.isPhantom, true);
  assert.equal(phantom.isConnected, false);
  assert.equal(phantom.publicKey, null);
  // Assignments by another wallet are ignored; the accessor stays ours.
  page.context.phantom = { solana: { isPhantom: true, fake: true } };
  assert.equal(page.context.phantom.solana, phantom);
  // onlyIfTrusted on an unconnected site: 4001 without a window.
  const trusted = phantom.connect(pageValue(page, { onlyIfTrusted: true }));
  const trustedRequest = lastRequest(page);
  assert.equal(JSON.stringify(trustedRequest.params), JSON.stringify([{ onlyIfTrusted: true }]));
  respond(page, trustedRequest.id, { error: { code: 4001, message: "User rejected the request." } });
  await assert.rejects(trusted, (error) => error.code === 4001);
  const events = [];
  phantom.on("connect", (key) => events.push(["connect", key.toBase58()]));
  phantom.on("accountChanged", (key) => events.push(["accountChanged", key === null ? null : key.toString()]));
  phantom.on("disconnect", () => events.push(["disconnect"]));
  const connecting = phantom.connect();
  respond(page, lastRequest(page).id, { result: { publicKey: SOL_KEY } });
  const { publicKey } = await connecting;
  assert.equal(publicKey.toBase58(), SOL_KEY);
  assert.equal(publicKey.toJSON(), SOL_KEY);
  assert.equal(publicKey.toBytes().length, 32);
  assert.equal(publicKey.equals(SOL_KEY), true);
  assert.equal(publicKey.equals(phantom.publicKey), true);
  assert.equal(phantom.isConnected, true);
  const message = vm.runInContext("new Uint8Array([1, 2, 3])", page.context);
  const signing = phantom.signMessage(message, "hex");
  const signRequest = lastRequest(page);
  assert.equal(JSON.stringify(signRequest.params), JSON.stringify([{ publicKey: SOL_KEY, message: "010203" }]));
  respond(page, signRequest.id, { result: { publicKey: SOL_KEY, signature: "33".repeat(64) } });
  const signed = await signing;
  assert.equal(signed.signature.length, 64);
  assert.equal(signed.publicKey.toBase58(), SOL_KEY);
  sendEvent(page, "solAccountsChanged", [SOL_KEY_2]);
  sendEvent(page, "solAccountsChanged", []);
  assert.deepEqual(events, [["connect", SOL_KEY], ["accountChanged", SOL_KEY_2], ["disconnect"]]);
  for (const name of ["signTransaction", "signAllTransactions", "signAndSendTransaction", "signAndSendAllTransactions"]) {
    await assert.rejects(phantom[name]({}), (error) => error.code === 4200 && error.message === SOL_UNSUPPORTED, name);
  }
  await assert.rejects(phantom.request(pageValue(page, { method: "signTransaction" })), (error) => error.code === 4200);
  const before = requests(page).length;
  await assert.rejects(phantom.signMessage(message), (error) => error.code === 4100);
  assert.equal(requests(page).length, before, "not connected: refused locally");
});

test("P15 unisat mode: window.unisat accounts, network, message signing; PSBT and sends reject", async () => {
  const page = createPage({ init: false });
  bridgeInit(page, CHANNEL, "off", "off", "unisat");
  assert.equal("XverseProviders" in page.context, false);
  assert.equal(page.context.phantom, undefined);
  const unisat = page.context.unisat;
  const account = { address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", publicKey: `02${"79".repeat(32)}`, purpose: "any", addressType: "p2wpkh" };
  const accounts = unisat.requestAccounts();
  const connect = lastRequest(page);
  assert.equal(connect.method, "btc_requestAccounts");
  assert.equal(JSON.stringify(connect.params), JSON.stringify([{ purposes: ["any"] }]));
  respond(page, connect.id, { result: [account] });
  assert.deepEqual(plain(await accounts), [account.address]);
  assert.equal(await unisat.getPublicKey(), account.publicKey);
  const network = unisat.getNetwork();
  await flush();
  respond(page, lastRequest(page).id, { result: "testnet4" });
  assert.equal(await network, "testnet");
  const chain = unisat.getChain();
  await flush();
  respond(page, lastRequest(page).id, { result: "mainnet" });
  assert.deepEqual(plain(await chain), { enum: "BITCOIN_MAINNET", name: "Bitcoin Mainnet", network: "livenet" });
  const switching = unisat.switchNetwork("testnet");
  await flush();
  respond(page, lastRequest(page).id, { result: "mainnet" });
  await assert.rejects(switching, (error) => error.code === 4200);
  const signing = unisat.signMessage("hello", "bip322-simple");
  await flush();
  const sign = lastRequest(page);
  assert.equal(sign.method, "btc_signMessage");
  assert.equal(JSON.stringify(sign.params), JSON.stringify([{ address: account.address, message: "hello", protocol: "bip322" }]));
  respond(page, sign.id, { result: { address: account.address, signature: "AkcwRA==", messageHash: "00".repeat(32), protocol: "bip322" } });
  assert.equal(await signing, "AkcwRA==");
  await assert.rejects(unisat.signMessage("hello", "schnorr"), (error) => error.code === -32602);
  for (const name of ["signPsbt", "signPsbts", "pushPsbt", "pushTx", "sendBitcoin", "sendInscription", "inscribeTransfer", "getBalance"]) {
    await assert.rejects(unisat[name]("x"), (error) => error.code === 4200 && error.message === BTC_UNSUPPORTED, name);
  }
  const changed = [];
  unisat.on("accountsChanged", (list) => changed.push(plain(list)));
  sendEvent(page, "btcAccountsChanged", []);
  assert.deepEqual(changed, [[]]);
});

test("P16 xverse mode: sats-connect request() shapes, btc_providers entry, unsupported methods", async () => {
  const page = createPage({ init: false });
  bridgeInit(page, CHANNEL, "off", "off", "xverse");
  const provider = page.context.XverseProviders.BitcoinProvider;
  assert.equal(page.context.BitcoinProvider, provider);
  assert.equal("unisat" in page.context, false);
  const entry = page.context.btc_providers.find((item) => item.id === "XverseProviders.BitcoinProvider");
  assert.equal(entry.name, "Xverse Wallet");
  assert.match(entry.icon, /^data:image\/png;base64,/u);
  const info = await provider.request("getInfo", null);
  assert.equal(info.jsonrpc, "2.0");
  assert.equal(typeof info.id, "string");
  assert.equal(info.result.version, "1.0.0");
  const taproot = { address: "bc1pss0zhytly75awhm6x2hhvd5lnzv3vssgrf9axfheq8ldyzn88ges79fler", publicKey: `03${"ab".repeat(32)}`, purpose: "ordinals", addressType: "p2tr" };
  const pending = provider.request("getAccounts", pageValue(page, { purposes: ["payment", "ordinals", "stacks"] }));
  await flush();
  const connect = lastRequest(page);
  assert.equal(JSON.stringify(connect.params), JSON.stringify([{ purposes: ["payment", "ordinals"] }]));
  respond(page, connect.id, { result: [taproot] });
  const accounts = await pending;
  assert.deepEqual(plain(accounts.result), [{ address: taproot.address, publicKey: "ab".repeat(32), purpose: "ordinals", addressType: "p2tr", walletType: "software" }]);
  const signing = provider.request("signMessage", pageValue(page, { address: taproot.address, message: "hi", protocol: "BIP322" }));
  await flush();
  const sign = lastRequest(page);
  assert.equal(JSON.stringify(sign.params), JSON.stringify([{ address: taproot.address, message: "hi", protocol: "bip322" }]));
  respond(page, sign.id, { result: { address: taproot.address, signature: "AUA=", messageHash: "aa".repeat(32), protocol: "bip322" } });
  assert.deepEqual(plain((await signing).result), { signature: "AUA=", messageHash: "aa".repeat(32), address: taproot.address, protocol: "BIP322" });
  const rejected = provider.request("signMessage", pageValue(page, { address: taproot.address, message: "hi" }));
  await flush();
  respond(page, lastRequest(page).id, { error: { code: 4001, message: "User rejected the request." } });
  assert.equal((await rejected).error.code, -32000);
  for (const method of ["signPsbt", "sendTransfer", "runes_transfer", "ord_sendInscriptions"]) {
    const answer = await provider.request(method, pageValue(page, {}));
    assert.equal(answer.error.code, -32001, method);
    assert.equal(answer.error.message, BTC_UNSUPPORTED);
  }
  const network = provider.request("wallet_getNetwork", null);
  await flush();
  respond(page, lastRequest(page).id, { result: "testnet4" });
  assert.equal((await network).result.bitcoin.name, "Testnet4");
  const events = [];
  const unsubscribe = provider.addListener("disconnect", () => events.push("disconnect"));
  assert.equal(typeof unsubscribe, "function");
  provider.addListener("accountChange", (event) => events.push(event.type));
  sendEvent(page, "btcAccountsChanged", [taproot.address]);
  assert.deepEqual(events, ["accountChange"]);
  await assert.rejects(provider.signTransaction("jwt"), (error) => error.code === 4200);
});

test("P1 the provider installs exactly on the v1-origins.golden.json pages (security review L6)", async () => {
  const { cases } = JSON.parse(await readFile(new URL("../native-host/v1-origins.golden.json", import.meta.url), "utf8"));
  for (const { url, ok, note } of cases) {
    const page = createPage({ href: url, init: false });
    assert.equal("ethereum" in page.context, ok, note);
    assert.equal(page.posted.length, ok ? 1 : 0, note);
  }
});
