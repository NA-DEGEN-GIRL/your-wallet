// spec/05 §10.1 E1–E2: compatibility-mode delivery end to end, with the real scripts in two VM
// "worlds" sharing one window.postMessage bus: chrome.storage.local → content.js (ISOLATED) →
// bridge-init → provider-main.js (MAIN) → page request → content port → background router →
// native request envelope `context.compatMode`.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test, { afterEach, beforeEach, mock } from "node:test";
import vm from "node:vm";

await import("../src/shared.js");
await import("../src/background-core.js");
const { BackgroundRouter } = globalThis.__YOUR_WALLET_BACKGROUND_CORE__;

const read = (name) => readFile(new URL(`../src/${name}`, import.meta.url), "utf8");
const SOURCES = {
  main: await read("provider-main.js"),
  isolated: [await read("shared.js"), await read("content-core.js"), await read("content.js")]
};
const ORIGIN = "https://dapp.example";
const EXTENSION_ID = "nnpjlobjgbanccjddghlpaafpohfkeph";
const ACCOUNT = `0x${"5a".repeat(20)}`;

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

const settle = async (turns = 6) => {
  for (let turn = 0; turn < turns; turn += 1) {
    await new Promise((resolve) => setImmediate(resolve));
  }
};

let seed = 1;
function world(extra) {
  const listeners = new Map();
  const documentListeners = new Map();
  const dispatched = [];
  const url = new URL(`${ORIGIN}/login`);
  const global = {
    Event: TestEvent,
    CustomEvent: TestCustomEvent,
    TextEncoder,
    URL,
    setTimeout: (callback, milliseconds) => setTimeout(callback, milliseconds),
    clearTimeout: (handle) => clearTimeout(handle),
    crypto: {
      getRandomValues(bytes) {
        for (let index = 0; index < bytes.length; index += 1) {
          seed = (Math.imul(seed, 1_103_515_245) + 12_345) >>> 0;
          bytes[index] = seed >>> 24;
        }
        return bytes;
      }
    },
    location: { href: url.href, origin: url.origin, protocol: url.protocol, hostname: url.hostname },
    document: {
      addEventListener(type, listener) {
        documentListeners.set(type, [...(documentListeners.get(type) ?? []), listener]);
      }
    },
    ...extra
  };
  global.addEventListener = (type, listener, options) => {
    const capture = options === true || options?.capture === true;
    listeners.set(type, [...(listeners.get(type) ?? []), { listener, capture }]);
  };
  global.dispatchEvent = (event) => {
    dispatched.push(event);
    const current = listeners.get(event.type) ?? [];
    for (const entry of [...current.filter((item) => item.capture), ...current.filter((item) => !item.capture)]) {
      entry.listener.call(global, event);
      if (event.immediatePropagationStopped) {
        break;
      }
    }
    return true;
  };
  const context = vm.createContext(global);
  context.top = context;
  return { context, dispatched, documentListeners };
}

// One document: both worlds see every window.postMessage, asynchronously, each with its own
// `event.source === window` and realm-local data (as Chrome delivers them).
function documentWith(storageGet) {
  const worlds = [];
  const deliver = (message) => {
    const json = JSON.stringify(message);
    setImmediate(() => {
      for (const target of worlds) {
        target.context.__BUS_JSON__ = json;
        vm.runInContext(`{
          const event = new Event("message");
          event.source = globalThis;
          event.origin = location.origin;
          event.data = JSON.parse(__BUS_JSON__);
          dispatchEvent(event);
        }`, target.context);
        delete target.context.__BUS_JSON__;
      }
    });
  };
  const postMessage = (message, targetOrigin) => {
    assert.equal(targetOrigin, ORIGIN);
    deliver(message);
  };
  const storageReads = [];
  const ports = [];
  const main = world({ postMessage });
  const isolated = world({
    postMessage,
    chrome: {
      storage: {
        local: {
          get(key) {
            storageReads.push(key);
            return storageGet(isolated.context);
          }
        }
      },
      runtime: {
        id: EXTENSION_ID,
        lastError: undefined,
        connect({ name }) {
          const port = { name, sent: [], onMessage: [], disconnected: false };
          ports.push(port);
          return {
            postMessage: (message) => port.sent.push(JSON.parse(JSON.stringify(message))),
            disconnect: () => {
              port.disconnected = true;
            },
            onMessage: { addListener: (listener) => port.onMessage.push(listener) },
            onDisconnect: { addListener() {} }
          };
        }
      }
    }
  });
  worlds.push(main, isolated);
  // Manifest order: the MAIN-world provider first, then the ISOLATED scripts.
  vm.runInContext(SOURCES.main, main.context, { filename: "provider-main.js" });
  for (const [index, source] of SOURCES.isolated.entries()) {
    vm.runInContext(source, isolated.context, { filename: `isolated-${index}.js` });
  }
  // The background side: port messages arrive structured-cloned into the worker realm.
  const toContent = (port, message) => {
    const json = JSON.stringify(message);
    isolated.context.__PORT_JSON__ = json;
    const local = vm.runInContext("JSON.parse(__PORT_JSON__)", isolated.context);
    delete isolated.context.__PORT_JSON__;
    for (const listener of port.onMessage) {
      listener(local);
    }
  };
  return { main, isolated, storageReads, ports, toContent };
}

function backgroundFor(port, doc) {
  const native = [];
  let counter = 40;
  const router = new BackgroundRouter({
    profileInstallId: "a".repeat(64),
    extensionId: EXTENSION_ID,
    randomHex: () => (counter++).toString(16).padStart(64, "0"),
    now: () => 1_700_000_000_000,
    setTimer: () => 0,
    clearTimer: () => {},
    nativeFactory: ({ onMessage }) => ({
      send: (message) => native.push({ message: structuredClone(message), onMessage }),
      disconnect() {}
    })
  });
  const handle = router.attachContent({
    sender: {
      tab: { id: 9, incognito: false }, frameId: 0, documentId: "doc-9", documentLifecycle: "active",
      origin: ORIGIN, url: `${ORIGIN}/login`
    },
    postMessage: (message) => doc.toContent(port, message),
    disconnect() {}
  });
  return { handle, native, router };
}

beforeEach(() => mock.timers.enable({ apis: ["setTimeout"] }));
afterEach(() => mock.timers.reset());

test("E1 storage compatMode=metamask reaches the page provider and the native envelope context", async () => {
  const doc = documentWith((context) => Promise.resolve(vm.runInContext(`({ compatMode: "metamask", other: 1 })`, context)));
  const ethereum = doc.main.context.ethereum;
  // At document_start, before the storage read answers: default flags, no announcement yet.
  assert.equal(ethereum.isMetaMask, false);
  assert.equal(doc.main.dispatched.filter((event) => event.type === "eip6963:announceProvider").length, 0);
  await settle();
  assert.equal(JSON.stringify(doc.storageReads), JSON.stringify([["compatMode", "solCompatMode", "btcCompatMode"]]));
  const announced = doc.main.dispatched.filter((event) => event.type === "eip6963:announceProvider");
  assert.equal(announced.length, 1);
  assert.equal(announced[0].detail.info.name, "MetaMask");
  assert.equal(announced[0].detail.info.rdns, "io.metamask");
  assert.equal(doc.main.context.ethereum, ethereum);
  assert.equal(ethereum.isMetaMask, true);
  assert.equal(ethereum.isRabby, false);

  // A MetaMask-only dApp connects through window.ethereum.
  const accounts = ethereum.request(vm.runInContext(`({ method: "eth_requestAccounts" })`, doc.main.context));
  await settle();
  assert.equal(doc.ports.length, 1);
  const port = doc.ports[0];
  assert.equal(port.name, "your-wallet-content-v1");
  const background = backgroundFor(port, doc);
  await settle();
  assert.equal(port.sent.length, 1);
  assert.equal(port.sent[0].compatMode, "metamask");
  background.handle.receive(port.sent[0]);
  assert.equal(background.native.length, 1);
  const { message: envelope, onMessage } = background.native[0];
  assert.equal(envelope.method, "eth_requestAccounts");
  assert.equal(envelope.context.compatMode, "metamask");
  // The approval window still gets the real origin from the sender, never from the page.
  assert.equal(envelope.context.topOrigin, ORIGIN);
  assert.deepEqual(Object.keys(envelope.context).sort(), [
    "browserFamily", "channelNonce", "compatMode", "documentId", "documentLifecycle", "extensionId", "frameId",
    "frameOrigin", "tabId", "topOrigin"
  ]);
  onMessage({
    namespace: "your-wallet", version: 1, role: "native-host", kind: "response", sessionId: envelope.sessionId,
    sequence: 1, requestSequence: envelope.sequence, activationNonce: envelope.activationNonce,
    requestId: envelope.requestId, result: [ACCOUNT]
  });
  await settle();
  assert.equal(JSON.stringify(await accounts), JSON.stringify([ACCOUNT]));
  assert.equal(ethereum.selectedAddress, ACCOUNT);
});

test("E2 a failing storage read means off: Your Wallet identity and no compatMode anywhere", async () => {
  for (const storageGet of [
    () => Promise.reject(new Error("storage unavailable")),
    (context) => Promise.resolve(vm.runInContext(`({ compatMode: "MetaMask" })`, context)),
    () => {
      throw new Error("Extension context invalidated.");
    }
  ]) {
    const doc = documentWith(storageGet);
    await settle();
    const announced = doc.main.dispatched.filter((event) => event.type === "eip6963:announceProvider");
    assert.equal(announced.length, 1);
    assert.equal(announced[0].detail.info.name, "Your Wallet (EVM)");
    const ethereum = doc.main.context.ethereum;
    assert.equal(ethereum.isMetaMask, false);
    void ethereum.request(vm.runInContext(`({ method: "eth_chainId" })`, doc.main.context));
    await settle();
    const port = doc.ports[0];
    const background = backgroundFor(port, doc);
    await settle();
    assert.equal(Object.hasOwn(port.sent[0], "compatMode"), false);
    background.handle.receive(port.sent[0]);
    assert.equal(Object.hasOwn(background.native[0].message.context, "compatMode"), false);
    assert.equal(Object.keys(background.native[0].message.context).length, 9);
  }
});

// The page shares the window and document with content.js: a synthetic `pagehide`/`freeze`
// (isTrusted false) must not tear down the activation and fail the pending requests.
async function activeDocument() {
  const doc = documentWith((context) => Promise.resolve(vm.runInContext("({})", context)));
  await settle();
  const pending = doc.main.context.ethereum.request(vm.runInContext(`({ method: "eth_chainId" })`, doc.main.context));
  pending.catch(() => {});
  await settle();
  const port = doc.ports[0];
  backgroundFor(port, doc);
  await settle();
  assert.equal(port.sent.length, 1);
  assert.equal(port.sent[0].kind, "request");
  return { doc, port };
}

test("E3 untrusted pagehide/freeze from the page are ignored; the browser's own close the activation", async () => {
  const { doc, port } = await activeDocument();
  // Page-dispatched events (isTrusted absent or false).
  vm.runInContext(`dispatchEvent(new Event("pagehide"))`, doc.isolated.context);
  for (const listener of doc.isolated.documentListeners.get("freeze") ?? []) {
    listener({ type: "freeze", isTrusted: false });
  }
  await settle();
  assert.equal(port.sent.length, 1, "no disconnect for synthetic events");
  assert.equal(port.disconnected, false);
  // The browser's `freeze` (trusted) closes the activation.
  for (const listener of doc.isolated.documentListeners.get("freeze") ?? []) {
    listener({ type: "freeze", isTrusted: true });
  }
  assert.equal(port.sent.at(-1).kind, "disconnect");
  assert.equal(port.sent.at(-1).reason, "document-freeze");
  assert.equal(port.disconnected, true);

  const second = await activeDocument();
  vm.runInContext(`{ const event = new Event("pagehide"); event.isTrusted = true; dispatchEvent(event); }`, second.doc.isolated.context);
  assert.equal(second.port.sent.at(-1).kind, "disconnect");
  assert.equal(second.port.sent.at(-1).reason, "document-pagehide");
});

// Security review M4 (spec/05 §2.5): a page script that runs right after document_start and posts
// a forged bridge-init (its own channel, any mode) — and then a `disconnect` on that channel —
// cannot take the bridge: content's synchronous bridge-claim is delivered first, so the provider
// keeps the content's channel and the page's requests still reach the wallet.
test("E4 a page-forged bridge-init before the storage read cannot pre-empt the channel", async () => {
  let answer;
  const doc = documentWith(() => new Promise((resolve) => {
    answer = resolve;
  }));
  const forged = "ee".repeat(32);
  const pagePost = (text) => vm.runInContext(`postMessage(${text}, location.origin)`, doc.main.context);
  pagePost(`({ namespace: "your-wallet", version: 1, kind: "bridge-init", channel: "${forged}", compatMode: "off", solCompatMode: "off", btcCompatMode: "off" })`);
  pagePost(`({ namespace: "your-wallet", version: 1, kind: "bridge-claim", channel: "${forged}" })`);
  await settle();
  const ethereum = doc.main.context.ethereum;
  assert.equal(ethereum.isConnected(), false, "the forged bridge-init did not open the bridge");
  pagePost(`({ namespace: "your-wallet", version: 1, kind: "disconnect", channel: "${forged}", error: { code: 4900, message: "x" } })`);
  // The request waits for the content's bridge-init (the mode read is still outstanding).
  const pending = ethereum.request(vm.runInContext(`({ method: "eth_chainId" })`, doc.main.context));
  await settle();
  assert.equal(doc.ports.length, 0);
  answer(vm.runInContext(`({ compatMode: "metamask" })`, doc.isolated.context));
  await settle();
  assert.equal(ethereum.isConnected(), true);
  assert.equal(ethereum.isMetaMask, true, "the content's stored mode, not the forged one");
  assert.equal(doc.ports.length, 1, "the request reached the content port");
  const port = doc.ports[0];
  const background = backgroundFor(port, doc);
  await settle();
  assert.equal(port.sent.length, 1);
  assert.equal(port.sent[0].method, "eth_chainId");
  background.handle.receive(port.sent[0]);
  const { message: envelope, onMessage } = background.native[0];
  onMessage({
    namespace: "your-wallet", version: 1, role: "native-host", kind: "response", sessionId: envelope.sessionId,
    sequence: 1, requestSequence: envelope.sequence, activationNonce: envelope.activationNonce,
    requestId: envelope.requestId, result: "0xaa36a7"
  });
  await settle();
  assert.equal(await pending, "0xaa36a7");
});
