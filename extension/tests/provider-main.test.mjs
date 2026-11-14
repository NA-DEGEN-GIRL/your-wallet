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
  assert.equal(announcement.detail.info.name, "Your Wallet (EVM)");
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
    off: { isMetaMask: false, isRabby: false, name: "Your Wallet (EVM)", rdns: OUR_RDNS, metamask: false },
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
    // Exactly one identity: the compat identity replaces "Your Wallet (EVM)" (no duplicate entries).
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
// A Phantom `request` method that is not supported (neutral text since 2026-11-12).
const SOL_UNSUPPORTED = "Unsupported method.";
// Fixed English since 2026-11-14 (spec/05 §2.13, §5; Korean before).
const BTC_UNSUPPORTED = "This wallet supports only message signing (proof of ownership) on Bitcoin.";
const BTC_NETWORK_FIXED = "The Bitcoin network can only be changed in the Your Wallet app settings.";

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

test("P13 Wallet Standard: 'Your Wallet (Solana)' in off mode, app-ready answered, features", async () => {
  const page = createPage({ init: false });
  const early = [];
  page.context.dispatchEvent(new TestCustomEvent("wallet-standard:app-ready", { detail: { register: (wallet) => early.push(wallet) } }));
  assert.equal(registeredWallets(page).length, 0, "nothing before the mode is known");
  bridgeInit(page);
  const [wallet] = registeredWallets(page);
  assert.equal(early.length, 1);
  assert.equal(early[0], wallet);
  // Not the EVM announcement's "Your Wallet (EVM)": dApps that merge wallets by name (Uniswap lower-cases
  // and drops a trailing " wallet") must not fold the two into one EVM+Solana entry.
  assert.equal(wallet.name, "Your Wallet (Solana)");
  const mergeKey = (name) => name.toLowerCase().replace(/ wallet$/u, "");
  assert.equal(announcements(page)[0].detail.info.name, "Your Wallet (EVM)");
  assert.notEqual(mergeKey(wallet.name), mergeKey(announcements(page)[0].detail.info.name));
  assert.equal(wallet.version, "1.0.0");
  assert.match(wallet.icon, /^data:image\/png;base64,/u);
  assert.deepEqual(plain(wallet.chains), ["solana:mainnet", "solana:devnet"]);
  assert.deepEqual(Object.keys(wallet.features).sort(), [
    "solana:signAndSendTransaction", "solana:signIn", "solana:signMessage", "solana:signTransaction",
    "standard:connect", "standard:disconnect", "standard:events"
  ]);
  for (const name of ["solana:signTransaction", "solana:signAndSendTransaction"]) {
    assert.equal(wallet.features[name].version, "1.0.0", name);
    assert.deepEqual(plain(wallet.features[name].supportedTransactionVersions), ["legacy", 0], name);
  }
  // Not connected: a transaction input is refused locally.
  await assert.rejects(wallet.features["solana:signTransaction"].signTransaction({}), (error) => error.code === 4100);
  assert.equal(requests(page).length, 0);
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
  assert.deepEqual(plain(connected.accounts[0].features), [
    "solana:signMessage", "solana:signIn", "solana:signTransaction", "solana:signAndSendTransaction"
  ]);
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
  await assert.rejects(phantom.request(pageValue(page, { method: "signPayload" })), (error) => error.code === 4200 && error.message === SOL_UNSUPPORTED);
  const before = requests(page).length;
  await assert.rejects(phantom.signMessage(message), (error) => error.code === 4100);
  assert.equal(requests(page).length, before, "not connected: refused locally");
});

// ---------- spec/05 §2.13 Solana dApp transactions (P13–P14, 2026-11-12) ----------

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function b58(bytes) {
  let value = 0n;
  for (const byte of bytes) {
    value = value * 256n + BigInt(byte);
  }
  let text = "";
  while (value > 0n) {
    text = B58[Number(value % 58n)] + text;
    value /= 58n;
  }
  for (const byte of bytes) {
    if (byte !== 0) {
      break;
    }
    text = `1${text}`;
  }
  return text;
}

const hexOf = (bytes) => Buffer.from(bytes).toString("hex");

// `count` empty signature slots in front of a small message (the provider checks the layout only).
function wireTx(count, message = [count, 0, 1, 2, ...new Array(64).fill(7), 9]) {
  return [count, ...new Array(64 * count).fill(0), ...message];
}

function pageBytes(page, bytes) {
  return vm.runInContext(`new Uint8Array(${JSON.stringify(Array.from(bytes))})`, page.context);
}

// `bytes` with slot `slot` filled with `fill` (what the app answers after signing).
function withSlot(bytes, slot, fill) {
  const out = Array.from(bytes);
  out.fill(fill, 1 + 64 * slot, 1 + 64 * (slot + 1));
  return out;
}

async function solConnectedWallet(page) {
  const [wallet] = registeredWallets(page);
  const connecting = wallet.features["standard:connect"].connect();
  respond(page, lastRequest(page).id, { result: { publicKey: SOL_KEY } });
  await connecting;
  return wallet;
}

test("P13 solana:signTransaction: one input → sol_signTransaction, several → one sol_signAllTransactions", async () => {
  const page = createPage();
  const wallet = await solConnectedWallet(page);
  const sign = wallet.features["solana:signTransaction"].signTransaction;
  const account = wallet.accounts[0];
  const before = requests(page).length;
  assert.deepEqual(plain(await sign()), [], "no input, no request");
  assert.equal(requests(page).length, before);

  // One input: `options` and `chain: undefined` are accepted and never reach the wire.
  const tx = wireTx(2);
  const input = { account, transaction: pageBytes(page, tx), chain: undefined, options: pageValue(page, { minContextSlot: 5 }) };
  const signing = sign(input);
  const wire = lastRequest(page);
  assert.equal(wire.method, "sol_signTransaction");
  assert.equal(JSON.stringify(wire.params), JSON.stringify([{ publicKey: SOL_KEY, transaction: hexOf(tx) }]));
  const signed = withSlot(tx, 1, 0x11);
  respond(page, wire.id, { result: { publicKey: SOL_KEY, signedTransaction: hexOf(signed) } });
  const [output] = await signing;
  assert.deepEqual(Object.keys(output), ["signedTransaction"]);
  assert.deepEqual(Array.from(output.signedTransaction), signed);

  // A chain goes to the wire as given.
  const onDevnet = sign({ account, transaction: pageBytes(page, tx), chain: "solana:devnet" });
  assert.equal(JSON.stringify(lastRequest(page).params), JSON.stringify([{ publicKey: SOL_KEY, transaction: hexOf(tx), chain: "solana:devnet" }]));
  respond(page, lastRequest(page).id, { result: { publicKey: SOL_KEY, signedTransaction: hexOf(withSlot(tx, 0, 0x22)) } });
  await onDevnet;

  // Three inputs: one request (one window, one approval), answers in input order.
  const txs = [wireTx(1), wireTx(2), wireTx(3)];
  const batch = sign(...txs.map((item) => ({ account, transaction: pageBytes(page, item), chain: null })));
  const batchWire = lastRequest(page);
  assert.equal(batchWire.method, "sol_signAllTransactions");
  assert.equal(JSON.stringify(batchWire.params), JSON.stringify([{ publicKey: SOL_KEY, transactions: txs.map(hexOf) }]));
  const answers = txs.map((item, index) => withSlot(item, index, 0x30 + index));
  respond(page, batchWire.id, { result: { publicKey: SOL_KEY, signedTransactions: answers.map(hexOf) } });
  assert.deepEqual(Array.from(await batch, (entry) => Array.from(entry.signedTransaction)), answers);
  assert.equal(requests(page).length, before + 3);
});

test("P13 transaction inputs are checked locally: account 4100, chain and bytes -32602, nothing posted", async () => {
  const page = createPage();
  const wallet = await solConnectedWallet(page);
  const account = wallet.accounts[0];
  const tx = pageBytes(page, wireTx(1));
  const before = requests(page).length;
  for (const name of ["solana:signTransaction", "solana:signAndSendTransaction"]) {
    const call = (...inputs) => (name === "solana:signTransaction"
      ? wallet.features[name].signTransaction(...inputs)
      : wallet.features[name].signAndSendTransaction(...inputs));
    await assert.rejects(call({ account: { address: SOL_KEY_2 }, transaction: tx }), (error) => error.code === 4100, name);
    await assert.rejects(call({ account: null, transaction: tx }), (error) => error.code === 4100, name);
    for (const [label, bad] of [
      ["testnet", { account, transaction: tx, chain: "solana:testnet" }],
      ["chain 1", { account, transaction: tx, chain: 1 }],
      ["plain array", { account, transaction: Array.from(wireTx(1)) }],
      ["1,233 bytes", { account, transaction: pageBytes(page, [1, ...new Array(1232).fill(1)]) }],
      ["zero signatures", { account, transaction: pageBytes(page, [0, 1, 2, 3]) }],
      ["no message", { account, transaction: pageBytes(page, wireTx(2).slice(0, 129)) }],
      ["empty", { account, transaction: pageBytes(page, []) }]
    ]) {
      await assert.rejects(call(bad), (error) => error.code === -32602, `${name} ${label}`);
    }
    await assert.rejects(call(
      { account, transaction: tx, chain: "solana:devnet" },
      { account, transaction: tx, chain: "solana:mainnet" }
    ), (error) => error.code === -32602, `${name} mixed chains`);
    await assert.rejects(call(...new Array(33).fill({ account, transaction: tx })), (error) => error.code === -32602, `${name} 33`);
    await assert.rejects(call(null), (error) => error.code === -32602, `${name} null`);
  }
  assert.equal(requests(page).length, before);
});

test("P13 the app's signed copy may change only one signature slot (else -32603)", async () => {
  const page = createPage();
  const wallet = await solConnectedWallet(page);
  const account = wallet.accounts[0];
  const sign = wallet.features["solana:signTransaction"].signTransaction;
  const tx = wireTx(2);
  const changedMessage = withSlot(tx, 1, 0x11);
  changedMessage[changedMessage.length - 1] ^= 1;
  const twoSlots = withSlot(withSlot(tx, 0, 0x11), 1, 0x22);
  const changedCount = withSlot(tx, 1, 0x11);
  changedCount[0] = 3;
  for (const [label, answer] of [
    ["message byte", hexOf(changedMessage)],
    ["longer", `${hexOf(withSlot(tx, 1, 0x11))}00`],
    ["shorter", hexOf(withSlot(tx, 1, 0x11)).slice(0, -2)],
    ["two slots", hexOf(twoSlots)],
    ["signature count", hexOf(changedCount)],
    ["not hex", "zz"],
    ["missing", undefined]
  ]) {
    const signing = sign({ account, transaction: pageBytes(page, tx) });
    respond(page, lastRequest(page).id, { result: { publicKey: SOL_KEY, signedTransaction: answer } });
    await assert.rejects(signing, (error) => error.code === -32603, label);
  }
  // A batch answer with fewer transactions than asked for.
  const batch = sign({ account, transaction: pageBytes(page, tx) }, { account, transaction: pageBytes(page, tx) });
  respond(page, lastRequest(page).id, { result: { publicKey: SOL_KEY, signedTransactions: [hexOf(withSlot(tx, 1, 0x11))] } });
  await assert.rejects(batch, (error) => error.code === -32603);
});

test("P13 solana:signAndSendTransaction: options normalized, inputs sent one by one, partial failure carries data.signatures", async () => {
  const page = createPage();
  const wallet = await solConnectedWallet(page);
  const account = wallet.accounts[0];
  const send = wallet.features["solana:signAndSendTransaction"].signAndSendTransaction;
  const tx = wireTx(1);
  // Known keys only, aliases folded; maxRetries, mode, foo and undefined values are dropped.
  const sending = send({
    account,
    transaction: pageBytes(page, tx),
    options: vm.runInContext(
      "({ preflightCommitment: 'singleGossip', skipPreflight: true, maxRetries: undefined, mode: 'parallel', foo: 1 })",
      page.context
    ),
    chain: "solana:devnet"
  });
  const wire = lastRequest(page);
  assert.equal(wire.method, "sol_signAndSendTransaction");
  assert.deepEqual(plain(wire.params), [{
    publicKey: SOL_KEY, transaction: hexOf(tx), chain: "solana:devnet",
    options: { skipPreflight: true, preflightCommitment: "confirmed" }
  }]);
  respond(page, wire.id, { result: { publicKey: SOL_KEY, signature: "aa".repeat(64) } });
  const [sent] = await sending;
  assert.deepEqual(Object.keys(sent), ["signature"]);
  assert.deepEqual(Array.from(sent.signature), new Array(64).fill(0xaa));
  // The other aliases, `null` values and unknown commitments.
  for (const [given, expected] of [
    ["({ preflightCommitment: 'recent', maxRetries: 2, commitment: 'finalized' })", { preflightCommitment: "processed" }],
    ["({ preflightCommitment: 'root', minContextSlot: 0 })", { preflightCommitment: "finalized", minContextSlot: 0 }],
    [
      "({ preflightCommitment: 'max', skipPreflight: false, minContextSlot: Number.MAX_SAFE_INTEGER })",
      { skipPreflight: false, preflightCommitment: "finalized", minContextSlot: Number.MAX_SAFE_INTEGER }
    ],
    ["({ preflightCommitment: 'single', skipPreflight: null, minContextSlot: null })", { preflightCommitment: "confirmed" }],
    ["({ preflightCommitment: 'nonsense' })", undefined],
    ["null", undefined]
  ]) {
    const pending = send({ account, transaction: pageBytes(page, tx), options: vm.runInContext(given, page.context) });
    assert.deepEqual(
      plain(lastRequest(page).params),
      [{ publicKey: SOL_KEY, transaction: hexOf(tx), ...(expected === undefined ? {} : { options: expected }) }],
      given
    );
    respond(page, lastRequest(page).id, { result: { publicKey: SOL_KEY, signature: "ab".repeat(64) } });
    await pending;
  }
  const before = requests(page).length;
  for (const options of [
    "({ minContextSlot: -1 })", "({ minContextSlot: 1.5 })", "({ minContextSlot: Number.MAX_SAFE_INTEGER + 1 })",
    "({ minContextSlot: '5' })", "({ skipPreflight: 'yes' })", "('fast')"
  ]) {
    await assert.rejects(
      send({ account, transaction: pageBytes(page, tx), options: vm.runInContext(options, page.context) }),
      (error) => error.code === -32602,
      options
    );
  }
  // A bad second input refuses the whole call before the first is sent.
  await assert.rejects(send(
    { account, transaction: pageBytes(page, tx) },
    { account, transaction: pageBytes(page, tx), options: pageValue(page, { minContextSlot: -1 }) }
  ), (error) => error.code === -32602);
  assert.equal(requests(page).length, before, "bad options are refused before anything is posted");

  // Two inputs: the second goes out only after the first answered; a failure of the second
  // rejects with that error and the first transaction's signature.
  const other = wireTx(1, [1, 0, 0, 1, ...new Array(32).fill(5), ...new Array(32).fill(6), 0]);
  const two = send({ account, transaction: pageBytes(page, tx) }, { account, transaction: pageBytes(page, other) });
  assert.equal(requests(page).length, before + 1);
  respond(page, lastRequest(page).id, { result: { publicKey: SOL_KEY, signature: "01".repeat(64) } });
  await flush();
  assert.equal(requests(page).length, before + 2);
  assert.equal(lastRequest(page).params[0].transaction, hexOf(other));
  respond(page, lastRequest(page).id, { error: { code: 4001, message: "User rejected the request." } });
  await assert.rejects(two, (error) => error.code === 4001
    && error.message === "User rejected the request."
    && JSON.stringify(error.data) === JSON.stringify({ signatures: [b58(new Array(64).fill(1))] }));
  // A failure of the first is passed on as it is, and nothing more is sent.
  const first = send({ account, transaction: pageBytes(page, tx) }, { account, transaction: pageBytes(page, tx) });
  respond(page, lastRequest(page).id, { error: { code: -32002, message: "Transaction pending." } });
  await assert.rejects(first, (error) => error.code === -32002 && error.data === undefined);
  await flush();
  assert.equal(requests(page).length, before + 3);
});

test("P13 M01 half: transaction-shaped bytes through signMessage post only sol_signMessage", async () => {
  const page = createPage();
  const wallet = await solConnectedWallet(page);
  const tx = wireTx(1);
  const before = requests(page).length;
  const signing = wallet.features["solana:signMessage"].signMessage({ account: wallet.accounts[0], message: pageBytes(page, tx) });
  const wire = lastRequest(page);
  assert.equal(wire.method, "sol_signMessage");
  assert.equal(JSON.stringify(wire.params), JSON.stringify([{ publicKey: SOL_KEY, message: hexOf(tx) }]));
  // The app blocks it (M01) and the page gets the rejection; no transaction method went out.
  respond(page, wire.id, { error: { code: 4001, message: "User rejected the request." } });
  await assert.rejects(signing, (error) => error.code === 4001);
  assert.equal(requests(page).length, before + 1);
});

test("P13 signAndSend inputs stay on the checked account: a change between sends → 4100 with data.signatures", async () => {
  const page = createPage();
  const wallet = await solConnectedWallet(page);
  const account = wallet.accounts[0];
  const send = wallet.features["solana:signAndSendTransaction"].signAndSendTransaction;
  const tx = wireTx(1);
  const before = requests(page).length;
  // The account changes while the first send's window is open: the second is not posted under
  // the new key, the first signature comes back in data.
  const changed = send({ account, transaction: pageBytes(page, tx) }, { account, transaction: pageBytes(page, tx) });
  assert.equal(lastRequest(page).params[0].publicKey, SOL_KEY);
  sendEvent(page, "solAccountsChanged", [SOL_KEY_2]);
  respond(page, lastRequest(page).id, { result: { publicKey: SOL_KEY, signature: "0c".repeat(64) } });
  await assert.rejects(changed, (error) => error.code === 4100
    && error.message === "Unauthorized."
    && JSON.stringify(error.data) === JSON.stringify({ signatures: [b58(new Array(64).fill(0x0c))] }));
  await flush();
  assert.equal(requests(page).length, before + 1, "no second sol_signAndSendTransaction");
  // A disconnect in between ends the same way.
  const current = wallet.accounts[0];
  assert.equal(current.address, SOL_KEY_2);
  const dropped = send({ account: current, transaction: pageBytes(page, tx) }, { account: current, transaction: pageBytes(page, tx) });
  assert.equal(lastRequest(page).params[0].publicKey, SOL_KEY_2);
  sendEvent(page, "solAccountsChanged", []);
  respond(page, lastRequest(page).id, { result: { publicKey: SOL_KEY_2, signature: "0d".repeat(64) } });
  await assert.rejects(dropped, (error) => error.code === 4100
    && JSON.stringify(error.data) === JSON.stringify({ signatures: [b58(new Array(64).fill(0x0d))] }));
  await flush();
  assert.equal(requests(page).length, before + 2);
});

// Fake web3.js classes in the page realm: `Tx` (legacy: serialize(options), static from) and
// `VTx` (versioned: `version`, serialize(), static deserialize). Serialize options are recorded.
const PAGE_CLASSES = `
  globalThis.serializeCalls = [];
  globalThis.Tx = class Tx {
    constructor(bytes) { this.bytes = Uint8Array.from(bytes); }
    serialize(options) { serializeCalls.push(options === undefined ? "none" : JSON.stringify(options)); return this.bytes; }
    static from(bytes) { return new Tx(bytes); }
  };
  globalThis.VTx = class VTx {
    constructor(bytes) { this.bytes = Uint8Array.from(bytes); this.version = 0; }
    serialize(options) { serializeCalls.push(options === undefined ? "none" : JSON.stringify(options)); return this.bytes; }
    static deserialize(bytes) { return new VTx(bytes); }
  };
  globalThis.Unsigned = class Unsigned {
    serialize() { throw new Error("Signature verification failed"); }
    static from() { return null; }
  };
  globalThis.NoFactory = class NoFactory {
    serialize() { return new Uint8Array([1, ...new Array(64).fill(0), 1, 0, 1, 2, ...new Array(64).fill(3), 0]); }
  };
`;

async function phantomConnected(page) {
  const phantom = page.context.phantom.solana;
  const connecting = phantom.connect();
  respond(page, lastRequest(page).id, { result: { publicKey: SOL_KEY } });
  await connecting;
  return phantom;
}

function pageTx(page, className, bytes) {
  return vm.runInContext(`new ${className}(${JSON.stringify(Array.from(bytes))})`, page.context);
}

test("P14 phantom transactions: the page's own classes come back, signAll is one approval, sends answer base58", async () => {
  const page = createPage({ init: false });
  bridgeInit(page, CHANNEL, "off", "phantom", "off");
  vm.runInContext(PAGE_CLASSES, page.context);
  const phantom = page.context.phantom.solana;
  // Not connected: refused locally.
  for (const call of [
    () => phantom.signTransaction(pageTx(page, "Tx", wireTx(1))),
    () => phantom.signAllTransactions(vm.runInContext("[]", page.context)),
    () => phantom.signAndSendTransaction(pageTx(page, "Tx", wireTx(1))),
    () => phantom.signAndSendAllTransactions(vm.runInContext("[]", page.context)),
    () => phantom.request(pageValue(page, { method: "signTransaction", params: { message: "2" } }))
  ]) {
    await assert.rejects(call(), (error) => error.code === 4100);
  }
  assert.equal(requests(page).length, 0);
  await phantomConnected(page);

  // Legacy: serialized without requiring or verifying signatures, rebuilt with Tx.from.
  const legacy = wireTx(2);
  const signing = phantom.signTransaction(pageTx(page, "Tx", legacy));
  assert.deepEqual(Array.from(page.context.serializeCalls), [JSON.stringify({ requireAllSignatures: false, verifySignatures: false })]);
  const wire = lastRequest(page);
  assert.equal(JSON.stringify(wire.params), JSON.stringify([{ publicKey: SOL_KEY, transaction: hexOf(legacy) }]));
  respond(page, wire.id, { result: { publicKey: SOL_KEY, signedTransaction: hexOf(withSlot(legacy, 1, 0x55)) } });
  const signed = await signing;
  assert.equal(signed.constructor, page.context.Tx);
  assert.deepEqual(Array.from(signed.bytes), withSlot(legacy, 1, 0x55));

  // Versioned: serialize() as is, rebuilt with VTx.deserialize.
  const versioned = wireTx(1, [0x80, 1, 0, 1, 2, ...new Array(64).fill(7), 0, 0]);
  const signingV0 = phantom.signTransaction(pageTx(page, "VTx", versioned));
  assert.equal(page.context.serializeCalls.at(-1), "none");
  respond(page, lastRequest(page).id, { result: { publicKey: SOL_KEY, signedTransaction: hexOf(withSlot(versioned, 0, 0x66)) } });
  const signedV0 = await signingV0;
  assert.equal(signedV0.constructor, page.context.VTx);
  assert.equal(signedV0.version, 0);

  // Raw bytes stay bytes.
  const raw = phantom.signTransaction(pageBytes(page, legacy));
  respond(page, lastRequest(page).id, { result: { publicKey: SOL_KEY, signedTransaction: hexOf(withSlot(legacy, 0, 0x12)) } });
  assert.deepEqual(Array.from(await raw), withSlot(legacy, 0, 0x12));

  // signAllTransactions: one request, each result in its own class.
  const before = requests(page).length;
  const all = phantom.signAllTransactions(vm.runInContext(`[new Tx(${JSON.stringify(legacy)}), new VTx(${JSON.stringify(versioned)})]`, page.context));
  assert.equal(requests(page).length, before + 1);
  assert.equal(lastRequest(page).method, "sol_signAllTransactions");
  respond(page, lastRequest(page).id, {
    result: { publicKey: SOL_KEY, signedTransactions: [hexOf(withSlot(legacy, 1, 0x01)), hexOf(withSlot(versioned, 0, 0x02))] }
  });
  const [first, second] = await all;
  assert.equal(first.constructor, page.context.Tx);
  assert.equal(second.constructor, page.context.VTx);

  // signAndSendTransaction: base58 signature and key; options as in Wallet Standard.
  const one = wireTx(1);
  const sending = phantom.signAndSendTransaction(pageTx(page, "Tx", one), pageValue(page, { skipPreflight: true, preflightCommitment: "recent", maxRetries: 3 }));
  assert.equal(lastRequest(page).method, "sol_signAndSendTransaction");
  assert.deepEqual(plain(lastRequest(page).params), [{ publicKey: SOL_KEY, transaction: hexOf(one), options: { skipPreflight: true, preflightCommitment: "processed" } }]);
  respond(page, lastRequest(page).id, { result: { publicKey: SOL_KEY, signature: "07".repeat(64) } });
  assert.deepEqual(plain(await sending), { signature: b58(new Array(64).fill(7)), publicKey: SOL_KEY });

  // signAndSendAllTransactions: one by one, every signature in base58.
  const sendingAll = phantom.signAndSendAllTransactions(vm.runInContext(`[new Tx(${JSON.stringify(one)}), new Tx(${JSON.stringify(one)})]`, page.context));
  respond(page, lastRequest(page).id, { result: { publicKey: SOL_KEY, signature: "08".repeat(64) } });
  await flush();
  respond(page, lastRequest(page).id, { result: { publicKey: SOL_KEY, signature: "09".repeat(64) } });
  assert.deepEqual(plain(await sendingAll), { signatures: [b58(new Array(64).fill(8)), b58(new Array(64).fill(9))], publicKey: SOL_KEY });
  // An account change between sends: no send under the new key, 4100 with the first signature.
  const switching = phantom.signAndSendAllTransactions(vm.runInContext(`[new Tx(${JSON.stringify(one)}), new Tx(${JSON.stringify(one)})]`, page.context));
  const sentBefore = requests(page).length;
  sendEvent(page, "solAccountsChanged", [SOL_KEY_2]);
  respond(page, lastRequest(page).id, { result: { publicKey: SOL_KEY, signature: "0a".repeat(64) } });
  await assert.rejects(switching, (error) => error.code === 4100
    && JSON.stringify(error.data) === JSON.stringify({ signatures: [b58(new Array(64).fill(0x0a))] }));
  await flush();
  assert.equal(requests(page).length, sentBefore);
  sendEvent(page, "solAccountsChanged", [SOL_KEY]);

  // A legacy transaction that cannot serialize: -32602 with nothing posted; no factory: -32603.
  const count = requests(page).length;
  await assert.rejects(phantom.signTransaction(vm.runInContext("new Unsigned()", page.context)), (error) => error.code === -32602);
  await assert.rejects(phantom.signTransaction(vm.runInContext("new NoFactory()", page.context)), (error) => error.code === -32603);
  await assert.rejects(phantom.signTransaction(pageValue(page, { serialize: 1 })), (error) => error.code === -32602);
  await assert.rejects(phantom.signAllTransactions(pageTx(page, "Tx", one)), (error) => error.code === -32602);
  assert.equal(requests(page).length, count);
});

test("P14 phantom request(): transaction methods, the deprecated base58 message form and the neutral 4200", async () => {
  const page = createPage({ init: false });
  bridgeInit(page, CHANNEL, "off", "phantom", "off");
  vm.runInContext(PAGE_CLASSES, page.context);
  const phantom = await phantomConnected(page);
  // request({ method: "signTransaction", params: { transaction } }) is signTransaction(tx).
  const tx = wireTx(1);
  const byRequest = phantom.request(vm.runInContext(`({ method: "signTransaction", params: { transaction: new Tx(${JSON.stringify(tx)}) } })`, page.context));
  assert.equal(lastRequest(page).method, "sol_signTransaction");
  respond(page, lastRequest(page).id, { result: { publicKey: SOL_KEY, signedTransaction: hexOf(withSlot(tx, 0, 0x21)) } });
  assert.equal((await byRequest).constructor, page.context.Tx);

  // The message form: base58 message → shortvec(required) ‖ 64·required zero bytes ‖ message.
  const message = [2, 0, 1, 3, ...new Array(96).fill(5), ...new Array(32).fill(6), 0];
  const wrapped = [2, ...new Array(128).fill(0), ...message];
  const legacyForm = phantom.request(pageValue(page, { method: "signTransaction", params: { message: b58(message) } }));
  assert.equal(JSON.stringify(lastRequest(page).params), JSON.stringify([{ publicKey: SOL_KEY, transaction: hexOf(wrapped) }]));
  respond(page, lastRequest(page).id, { result: { publicKey: SOL_KEY, signedTransaction: hexOf(withSlot(wrapped, 1, 0x44)) } });
  assert.deepEqual(plain(await legacyForm), { publicKey: SOL_KEY, signature: b58(new Array(64).fill(0x44)) });
  // Leading zero bytes survive base58 (`1` characters).
  const zeroForm = phantom.request(pageValue(page, { method: "signTransaction", params: { message: b58([1, 0, 0, 0]) } }));
  assert.equal(lastRequest(page).params[0].transaction, hexOf([1, ...new Array(64).fill(0), 1, 0, 0, 0]));
  respond(page, lastRequest(page).id, { result: { publicKey: SOL_KEY, signedTransaction: hexOf(withSlot([1, ...new Array(64).fill(0), 1, 0, 0, 0], 0, 0x49)) } });
  assert.equal((await zeroForm).signature, b58(new Array(64).fill(0x49)));
  // v0: the count is msg[1].
  const v0 = [0x80, 1, 0, 1, 2, ...new Array(64).fill(5), ...new Array(32).fill(6), 0, 0];
  const v0Wire = [1, ...new Array(64).fill(0), ...v0];
  const v0Form = phantom.request(pageValue(page, { method: "signTransaction", params: { message: b58(v0) } }));
  assert.equal(lastRequest(page).params[0].transaction, hexOf(v0Wire));
  respond(page, lastRequest(page).id, { result: { publicKey: SOL_KEY, signedTransaction: hexOf(withSlot(v0Wire, 0, 0x45)) } });
  assert.equal((await v0Form).signature, b58(new Array(64).fill(0x45)));
  // signAllTransactions with `messages`: our signature per message, one request.
  const allForm = phantom.request(pageValue(page, { method: "signAllTransactions", params: { messages: [b58(message), b58(message)] } }));
  assert.equal(lastRequest(page).method, "sol_signAllTransactions");
  respond(page, lastRequest(page).id, {
    result: { publicKey: SOL_KEY, signedTransactions: [hexOf(withSlot(wrapped, 0, 0x46)), hexOf(withSlot(wrapped, 1, 0x47))] }
  });
  assert.deepEqual(plain(await allForm), { publicKey: SOL_KEY, signatures: [b58(new Array(64).fill(0x46)), b58(new Array(64).fill(0x47))] });
  // signAndSendTransaction with a message: signature 0 of the sent transaction.
  const single = [1, 0, 1, 2, ...new Array(64).fill(5), ...new Array(32).fill(6), 0];
  const sendForm = phantom.request(pageValue(page, { method: "signAndSendTransaction", params: { message: b58(single), options: { skipPreflight: true } } }));
  assert.deepEqual(plain(lastRequest(page).params), [{ publicKey: SOL_KEY, transaction: hexOf([1, ...new Array(64).fill(0), ...single]), options: { skipPreflight: true } }]);
  respond(page, lastRequest(page).id, { result: { publicKey: SOL_KEY, signature: "48".repeat(64) } });
  assert.deepEqual(plain(await sendForm), { publicKey: SOL_KEY, signature: b58(new Array(64).fill(0x48)) });

  // Bad messages are refused locally.
  const before = requests(page).length;
  for (const bad of ["", "0OIl", b58([0x81, 1, 0, 0]), b58([0, 0, 0]), b58([0x80, 0, 0]), b58([0x80, 128, 0, 0]), 7]) {
    await assert.rejects(
      phantom.request(pageValue(page, { method: "signTransaction", params: { message: bad } })),
      (error) => error.code === -32602,
      String(bad)
    );
  }
  await assert.rejects(
    phantom.request(pageValue(page, { method: "signTransaction", params: { message: b58([100, ...new Array(1200).fill(1)]) } })),
    (error) => error.code === -32602,
    "too long"
  );
  await assert.rejects(phantom.request(pageValue(page, { method: "signAllTransactions", params: { messages: "x" } })), (error) => error.code === -32602);
  assert.equal(requests(page).length, before);
  await assert.rejects(phantom.request(pageValue(page, { method: "signAndSendAllTransactionsWithMemo" })), (error) => error.code === 4200 && error.message === SOL_UNSUPPORTED);
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
  await assert.rejects(switching, (error) => error.code === 4200 && error.message === BTC_NETWORK_FIXED);
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

// ---------- spec/05 §2.12 MetaMask Connect and metamask_getProviderState (P17–P18) ----------

const MM_CONNECT_MESSAGE = "Your Wallet's MetaMask look-alike mode cannot answer MetaMask Connect, which talks to the MetaMask extension directly. Choose the default or Rabby mode in the Your Wallet extension popup and reload this page.";

// What MetaMask Connect (@metamask/multichain-api-client windowPostMessageTransport) posts to
// MetaMask's content script.
function metaMaskConnectPost(page, body, name = "metamask-multichain-provider", options = {}) {
  dispatchMessage(page, { target: "metamask-contentscript", data: { name, data: body } }, options);
}

function inpageReplies(page) {
  return page.posted.filter((entry) => entry.message.target === "metamask-inpage")
    .map((entry) => ({ targetOrigin: entry.targetOrigin, message: plain(entry.message) }));
}

test("P17 metamask mode refuses MetaMask Connect's substream at once (4200) unless a real MetaMask is present", () => {
  const warnings = [];
  const page = createPage({
    init: "metamask",
    beforeInstall: (target) => {
      target.console = { warn: (...args) => warnings.push(args.join(" ")) };
    }
  });
  metaMaskConnectPost(page, { jsonrpc: "2.0", id: 7, method: "wallet_getSession" });
  metaMaskConnectPost(page, { jsonrpc: "2.0", id: "8", method: "wallet_createSession", params: { optionalScopes: {} } });
  const error = { code: 4200, message: MM_CONNECT_MESSAGE };
  assert.deepEqual(inpageReplies(page), [7, "8"].map((id) => ({
    targetOrigin: ORIGIN,
    message: { target: "metamask-inpage", data: { name: "metamask-multichain-provider", data: { jsonrpc: "2.0", id, error } } }
  })));
  // Nothing reaches the wallet, and the console explains it once.
  assert.equal(requests(page).length, 0);
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /default or Rabby mode/u);
  // Notifications, other substreams, odd ids, other origins and other targets get no answer.
  const before = page.posted.length;
  metaMaskConnectPost(page, { jsonrpc: "2.0", method: "wallet_notify" });
  metaMaskConnectPost(page, { jsonrpc: "2.0", id: 9, method: "metamask_getProviderState" }, "metamask-provider");
  metaMaskConnectPost(page, { jsonrpc: "2.0", id: { nested: 1 }, method: "wallet_getSession" });
  metaMaskConnectPost(page, { jsonrpc: "2.0", id: "x".repeat(129), method: "wallet_getSession" });
  metaMaskConnectPost(page, { jsonrpc: "2.0", id: 10, method: "wallet_getSession" }, undefined, { origin: "https://evil.example" });
  dispatchMessage(page, { target: "metamask-inpage", data: { name: "metamask-multichain-provider", data: { id: 11, method: "x" } } });
  assert.equal(page.posted.length, before);

  // Rabby and the default mode never answer for MetaMask.
  for (const mode of ["rabby", "off"]) {
    const other = createPage({ init: mode });
    metaMaskConnectPost(other, { jsonrpc: "2.0", id: 1, method: "wallet_getSession" });
    assert.deepEqual(inpageReplies(other), [], mode);
  }
  // A real MetaMask announced on the page (hidden from the dApp, still installed): its content
  // script answers, so ours stays silent, whether it announced before or after the mode settled.
  for (const early of [true, false]) {
    const withReal = createPage({ init: early ? false : "metamask" });
    foreignAnnouncement(withReal, "io.metamask", "MetaMask");
    if (early) {
      bridgeInit(withReal, CHANNEL, "metamask");
    }
    metaMaskConnectPost(withReal, { jsonrpc: "2.0", id: 1, method: "wallet_getSession" });
    assert.deepEqual(inpageReplies(withReal), [], String(early));
  }
});

test("P18 metamask_getProviderState is answered in the page in the compat modes from three reads", async () => {
  for (const mode of ["metamask", "rabby"]) {
    const page = createPage({ init: mode });
    const provider = providerOf(page);
    for (const [accounts, unlocked] of [[[ACCOUNT], true], [[], false]]) {
      const before = requests(page).length;
      const state = provider.request(pageValue(page, { method: "metamask_getProviderState" }));
      await flush();
      const sent = requests(page).slice(before);
      assert.deepEqual(sent.map((request) => request.method), ["eth_accounts", "eth_chainId", "net_version"], mode);
      respond(page, sent[0].id, { result: accounts });
      respond(page, sent[1].id, { result: "0x1237" });
      respond(page, sent[2].id, { result: "4663" });
      assert.deepEqual(plain(await state), { accounts, chainId: "0x1237", isUnlocked: unlocked, networkVersion: "4663" }, mode);
    }
    // A failing read rejects with that read's error.
    const failing = provider.request(pageValue(page, { method: "metamask_getProviderState" }));
    await flush();
    for (const request of requests(page).slice(-3)) {
      respond(page, request.id, { error: { code: 4900, message: "Wallet is unavailable." } });
    }
    await assert.rejects(failing, (error) => error.code === 4900);
  }
  // The default mode does not impersonate MetaMask: the call goes out as is (content answers 4200).
  const off = createPage();
  void providerOf(off).request(pageValue(off, { method: "metamask_getProviderState" })).catch(() => {});
  await flush();
  assert.equal(lastRequest(off).method, "metamask_getProviderState");
});
