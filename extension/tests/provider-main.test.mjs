import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

const source = await readFile(new URL("../src/provider-main.js", import.meta.url), "utf8");
const ORIGIN = "https://dapp.example";
const ANNOUNCE_EVENT = "eip6963:announceProvider";
const REQUEST_EVENT = "eip6963:requestProvider";

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

function createPage({ existingEthereum, lockedUndefinedEthereum = false, randomStart = 0 } = {}) {
  const listeners = new Map();
  const dispatched = [];
  const posted = [];
  const timers = new Map();
  let randomByte = randomStart;
  let timerId = 0;
  const page = {
    CustomEvent: TestCustomEvent,
    Event: TestEvent,
    TextEncoder,
    clearTimeout: (id) => timers.delete(id),
    crypto: {
      getRandomValues(bytes) {
        for (let index = 0; index < bytes.length; index += 1) {
          bytes[index] = randomByte & 0xff;
          randomByte += 1;
        }
        return bytes;
      }
    },
    location: { origin: ORIGIN, protocol: "https:" },
    setTimeout(callback, milliseconds) {
      timerId += 1;
      timers.set(timerId, { callback, milliseconds });
      return timerId;
    }
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
  context.top = context;
  vm.runInContext(source, context, { filename: "provider-main.js" });
  return { context, dispatched, listeners, posted };
}

function announcements(page) {
  return page.dispatched.filter((event) => event.type === ANNOUNCE_EVENT);
}

function dispatchMessage(page, data) {
  // Browser messages and provider arguments originate in the page realm. VM
  // tests must preserve both that prototype and the exact `event.source ===
  // window` identity checked by the production bridge.
  page.context.__TEST_MESSAGE_JSON__ = JSON.stringify(data);
  vm.runInContext(`
    {
      const event = new Event("message");
      event.source = globalThis;
      event.origin = location.origin;
      event.data = JSON.parse(__TEST_MESSAGE_JSON__);
      dispatchEvent(event);
    }
  `, page.context);
  delete page.context.__TEST_MESSAGE_JSON__;
}

function pageValue(page, value) {
  return vm.runInContext(`(${JSON.stringify(value)})`, page.context);
}

function activateBridge(page) {
  dispatchMessage(page, {
    namespace: "your-wallet",
    version: 1,
    channel: "ab".repeat(32),
    kind: "bridge-init"
  });
}

test("announces one immutable EIP-6963 provider with a page-scoped UUIDv4 and local PNG", () => {
  const page = createPage();
  const [announcement] = announcements(page);
  assert.ok(announcement instanceof TestCustomEvent);
  assert.equal(announcements(page).length, 1);
  assert.deepEqual(Object.keys(announcement.detail).sort(), ["info", "provider"]);
  assert.deepEqual(Object.keys(announcement.detail.info).sort(), ["icon", "name", "rdns", "uuid"]);
  assert.match(
    announcement.detail.info.uuid,
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u
  );
  assert.equal(announcement.detail.info.name, "Your Wallet");
  assert.equal(announcement.detail.info.rdns, "com.yourwallet");
  assert.match(announcement.detail.info.icon, /^data:image\/png;base64,[A-Za-z0-9+/]+={0,2}$/u);
  assert.doesNotMatch(announcement.detail.info.icon, /svg|https?:/iu);
  const png = Buffer.from(announcement.detail.info.icon.split(",")[1], "base64");
  assert.equal(png.subarray(1, 4).toString("ascii"), "PNG");
  assert.equal(png.readUInt32BE(16), 96);
  assert.equal(png.readUInt32BE(20), 96);
  assert.equal(Object.isFrozen(announcement.detail.info), true);
  assert.equal(Object.isFrozen(announcement.detail.provider), true);
  assert.equal(Object.isFrozen(announcement.detail), true);
  assert.equal(announcement.detail.provider, page.context.yourWallet);
});

test("each page gets a distinct UUID while every request reannounces the exact same identities", () => {
  const first = createPage({ randomStart: 0 });
  const second = createPage({ randomStart: 64 });
  const initial = announcements(first)[0];
  assert.notEqual(initial.detail.info.uuid, announcements(second)[0].detail.info.uuid);

  first.context.dispatchEvent(new TestEvent(REQUEST_EVENT));
  first.context.dispatchEvent(new TestEvent(REQUEST_EVENT));
  const repeated = announcements(first);
  assert.equal(repeated.length, 3);
  for (const event of repeated) {
    assert.equal(event.detail, initial.detail);
    assert.equal(event.detail.info, initial.detail.info);
    assert.equal(event.detail.provider, initial.detail.provider);
    assert.equal(event.detail.info.uuid, initial.detail.info.uuid);
  }
});

test("frozen discovery metadata resists mutation and an existing ethereum provider is never overwritten", () => {
  const incumbent = Object.freeze({ request: () => "incumbent" });
  const page = createPage({ existingEthereum: incumbent });
  const { detail } = announcements(page)[0];
  assert.equal(page.context.ethereum, incumbent);
  assert.notEqual(detail.provider, incumbent);
  assert.throws(() => {
    detail.info.name = "Imitated Wallet";
  }, TypeError);
  assert.throws(() => {
    detail.provider.request = () => Promise.resolve("forged");
  }, TypeError);
  assert.throws(() => {
    detail.info = Object.freeze({});
  }, TypeError);
  assert.equal(detail.info.name, "Your Wallet");

  const reserved = createPage({ lockedUndefinedEthereum: true });
  assert.equal(reserved.context.ethereum, undefined);
  assert.equal(announcements(reserved).length, 1);
  assert.notEqual(announcements(reserved)[0].detail.provider, reserved.context.ethereum);
});

test("a reentrant hostile request cannot recurse announcements or replace discovery state", () => {
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

test("provider request and response semantics remain bound to the existing bridge", async () => {
  const page = createPage();
  const provider = announcements(page)[0].detail.provider;
  activateBridge(page);
  const resultPromise = provider.request(pageValue(page, { method: "eth_chainId", params: [] }));
  await Promise.resolve();
  assert.equal(page.posted.length, 1);
  const outbound = page.posted[0];
  assert.equal(outbound.targetOrigin, ORIGIN);
  assert.equal(outbound.message.method, "eth_chainId");
  assert.equal(JSON.stringify(outbound.message.params), "[]");
  dispatchMessage(page, {
    namespace: "your-wallet",
    version: 1,
    channel: "ab".repeat(32),
    kind: "response",
    id: outbound.message.id,
    result: "0xaa36a7"
  });
  assert.equal(await resultPromise, "0xaa36a7");
  assert.equal(provider.chainId, "0xaa36a7");
  await assert.rejects(
    provider.request(pageValue(page, { method: "eth_sendRawTransaction", params: [] })),
    (error) => error?.code === 4200
  );
});

test("provider event listeners, removal, and selected account updates are unchanged", () => {
  const page = createPage();
  const provider = announcements(page)[0].detail.provider;
  const account = `0x${"12".repeat(20)}`;
  const observed = [];
  const listener = (accounts) => observed.push(accounts);
  assert.equal(provider.on("accountsChanged", listener), provider);
  activateBridge(page);
  dispatchMessage(page, {
    namespace: "your-wallet",
    version: 1,
    channel: "ab".repeat(32),
    kind: "event",
    event: "accountsChanged",
    payload: [account]
  });
  assert.equal(provider.selectedAddress, account);
  assert.equal(JSON.stringify(observed), JSON.stringify([[account]]));
  assert.equal(provider.removeListener("accountsChanged", listener), provider);
  dispatchMessage(page, {
    namespace: "your-wallet",
    version: 1,
    channel: "ab".repeat(32),
    kind: "event",
    event: "accountsChanged",
    payload: []
  });
  assert.equal(provider.selectedAddress, null);
  assert.equal(observed.length, 1);
});
