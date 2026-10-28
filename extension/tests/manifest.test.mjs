import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { extensionIdFromKey } from "../../scripts/extension-key.mjs";

const EXTENSION_ID_FILE = new URL("../extension-id.txt", import.meta.url);
const MATCHES = ["https://*/*", "http://localhost/*", "http://127.0.0.1/*"];
// spec/05 §2.2 app icon (scripts/make-icons.mjs), the same map for the toolbar action.
const ICONS = {
  16: "icons/icon-16.png",
  32: "icons/icon-32.png",
  48: "icons/icon-48.png",
  128: "icons/icon-128.png"
};

// spec/05 §2.2 without `key`.
const EXPECTED_MANIFEST = {
  manifest_version: 3,
  name: "Your Wallet",
  version: "0.3.0",
  description: "Connects web pages to the local Your Wallet app.",
  icons: ICONS,
  minimum_chrome_version: "120",
  incognito: "not_allowed",
  permissions: ["nativeMessaging", "storage"],
  background: { service_worker: "src/background.js", type: "module" },
  // spec/05 §2.12 compatibility-mode popup.
  action: { default_title: "Your Wallet", default_popup: "popup/popup.html", default_icon: ICONS },
  content_scripts: [
    {
      matches: MATCHES,
      js: ["src/provider-main.js"],
      run_at: "document_start",
      all_frames: false,
      world: "MAIN"
    },
    {
      matches: MATCHES,
      js: ["src/shared.js", "src/content-core.js", "src/content.js"],
      run_at: "document_start",
      all_frames: false,
      world: "ISOLATED"
    }
  ]
};

test("M1 manifest equals spec/05 §2.2 and its key yields extension-id.txt", async () => {
  const manifest = JSON.parse(await readFile(new URL("../manifest.json", import.meta.url), "utf8"));
  const { key, ...rest } = manifest;
  assert.deepEqual(rest, EXPECTED_MANIFEST);
  assert.equal(typeof key, "string");
  assert.equal(key.length, 392);
  const idText = await readFile(EXTENSION_ID_FILE, "utf8");
  assert.match(idText, /^[a-p]{32}\n$/u);
  assert.equal(extensionIdFromKey(key), idText.trimEnd());
  for (const forbidden of ["host_permissions", "optional_host_permissions", "optional_permissions", "externally_connectable", "web_accessible_resources", "content_security_policy"]) {
    assert.equal(Object.hasOwn(manifest, forbidden), false, forbidden);
  }
  const packageJson = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
  assert.equal(packageJson.version, manifest.version);
  assert.equal(packageJson.scripts.test, "node --test tests/*.test.mjs");
});

function fakeEvent(name, registrations) {
  return {
    addListener(listener) {
      registrations.push({ name, listener });
    },
    removeListener() {},
    hasListener() {
      return false;
    }
  };
}

function listenerOf(registrations, name) {
  const found = registrations.filter((entry) => entry.name === name);
  assert.equal(found.length, 1, name);
  return found[0].listener;
}

function fakePort(name, sender) {
  const registrations = [];
  const port = {
    name,
    sender,
    posted: [],
    disconnected: false,
    registrations,
    onMessage: fakeEvent("onMessage", registrations),
    onDisconnect: fakeEvent("onDisconnect", registrations),
    postMessage(message) {
      port.posted.push(structuredClone(message));
    },
    disconnect() {
      port.disconnected = true;
    },
    deliver(message) {
      listenerOf(registrations, "onMessage")(message);
    }
  };
  return port;
}

const settle = () => new Promise((resolve) => setImmediate(resolve));

test("M2 background.js registers no external listeners and closes the port when init fails", async () => {
  const registrations = [];
  const storage = new Map();
  let storageFails = true;
  const nativePorts = [];
  globalThis.chrome = {
    runtime: {
      id: "nnpjlobjgbanccjddghlpaafpohfkeph",
      lastError: undefined,
      getURL: (path) => `chrome-extension://nnpjlobjgbanccjddghlpaafpohfkeph/${path}`,
      onConnect: fakeEvent("onConnect", registrations),
      onConnectExternal: fakeEvent("onConnectExternal", registrations),
      onMessage: fakeEvent("onMessage", registrations),
      onMessageExternal: fakeEvent("onMessageExternal", registrations),
      onInstalled: fakeEvent("onInstalled", registrations),
      onStartup: fakeEvent("onStartup", registrations),
      onSuspend: fakeEvent("onSuspend", registrations),
      connectNative(hostName) {
        const port = fakePort(hostName, undefined);
        nativePorts.push(port);
        return port;
      }
    },
    storage: {
      local: {
        async get(key) {
          if (storageFails) {
            throw new Error("storage unavailable");
          }
          return storage.has(key) ? { [key]: storage.get(key) } : {};
        },
        async set(values) {
          for (const [key, value] of Object.entries(values)) {
            storage.set(key, value);
          }
        }
      }
    }
  };
  await import("../src/background.js");

  assert.equal(registrations.filter((entry) => entry.name === "onConnectExternal").length, 0);
  assert.equal(registrations.filter((entry) => entry.name === "onMessageExternal").length, 0);
  assert.equal(registrations.filter((entry) => entry.name === "onMessage").length, 0);
  const onConnect = listenerOf(registrations, "onConnect");
  const onSuspend = listenerOf(registrations, "onSuspend");

  const sender = {
    tab: { id: 3, incognito: false },
    frameId: 0,
    documentId: "doc-3",
    documentLifecycle: "active",
    origin: "http://localhost:5173",
    url: "http://localhost:5173/index.html"
  };

  // Unknown port names are closed immediately.
  const stranger = fakePort("something-else", sender);
  onConnect(stranger);
  assert.equal(stranger.disconnected, true);

  // spec/05 §2.12 popup status: only from the action popup page; before any router exists the
  // answer is "unknown" and nothing touches storage or native messaging.
  const popupSender = {
    id: "nnpjlobjgbanccjddghlpaafpohfkeph",
    url: "chrome-extension://nnpjlobjgbanccjddghlpaafpohfkeph/popup/popup.html",
    origin: "chrome-extension://nnpjlobjgbanccjddghlpaafpohfkeph"
  };
  const popupStatus = async () => {
    const port = fakePort("your-wallet-popup-v1", popupSender);
    onConnect(port);
    await settle();
    await settle();
    assert.equal(port.disconnected, false);
    assert.equal(port.posted.length, 1);
    return port.posted[0];
  };
  assert.deepEqual(await popupStatus(), { namespace: "your-wallet", version: 1, kind: "status", native: "unknown" });
  assert.equal(nativePorts.length, 0);
  for (const forged of [sender, { ...popupSender, tab: { id: 3 } }, { ...popupSender, url: "chrome-extension://nnpjlobjgbanccjddghlpaafpohfkeph/x.html" }]) {
    const port = fakePort("your-wallet-popup-v1", forged);
    onConnect(port);
    await settle();
    assert.equal(port.disconnected, true);
    assert.deepEqual(port.posted, []);
  }

  // Router initialization failure: the port is closed, no `fatal` (or any) message is sent.
  const failed = fakePort("your-wallet-content-v1", sender);
  onConnect(failed);
  await settle();
  await settle();
  assert.equal(failed.disconnected, true);
  assert.deepEqual(failed.posted, []);

  // The next connection retries initialization and works end to end.
  storageFails = false;
  const content = fakePort("your-wallet-content-v1", sender);
  onConnect(content);
  await settle();
  await settle();
  assert.equal(content.disconnected, false);
  assert.equal(content.posted.length, 1);
  assert.equal(content.posted[0].kind, "activated");
  assert.match(storage.get("profileInstallIdV1"), /^[0-9a-f]{64}$/u);
  const { activationNonce } = content.posted[0];
  content.deliver({ namespace: "your-wallet", version: 1, kind: "request", activationNonce, id: "01".repeat(16), method: "eth_chainId", params: [] });
  assert.equal(nativePorts.length, 1);
  assert.equal(nativePorts[0].name, "com.your_wallet.native");
  const [request] = nativePorts[0].posted;
  assert.equal(request.context.topOrigin, "http://localhost:5173");
  assert.equal(request.context.extensionId, "nnpjlobjgbanccjddghlpaafpohfkeph");
  assert.equal(request.profileInstallId, storage.get("profileInstallIdV1"));
  nativePorts[0].deliver({
    namespace: "your-wallet", version: 1, role: "native-host", kind: "response", sessionId: request.sessionId,
    sequence: 1, requestSequence: 1, activationNonce, requestId: "01".repeat(16), result: "0xaa36a7"
  });
  assert.deepEqual(content.posted.at(-1), {
    namespace: "your-wallet", version: 1, kind: "response", activationNonce, id: "01".repeat(16), result: "0xaa36a7"
  });
  // yw-app answered on this native connection: the popup now reports "connected".
  assert.equal((await popupStatus()).native, "connected");
  assert.equal(nativePorts.length, 1);

  // onSuspend closes only the native connection; pending requests get 4900, the content port stays.
  content.deliver({ namespace: "your-wallet", version: 1, kind: "request", activationNonce, id: "02".repeat(16), method: "eth_blockNumber", params: [] });
  onSuspend();
  await settle();
  assert.equal(nativePorts[0].disconnected, true);
  assert.equal(content.disconnected, false);
  assert.deepEqual(content.posted.at(-1).error, { code: 4900, message: "Wallet connection closed." });

  // The content port closing cancels nothing further and does not throw.
  listenerOf(content.registrations, "onDisconnect")();
  assert.equal(registrations.filter((entry) => entry.name === "onConnectExternal" || entry.name === "onMessageExternal").length, 0);
});
