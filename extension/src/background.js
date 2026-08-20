import "./shared.js";
import "./background-core.js";

const shared = globalThis.__YOUR_WALLET_SHARED__;
const core = globalThis.__YOUR_WALLET_BACKGROUND_CORE__;
const PROFILE_INSTALL_ID_KEY = "profileInstallIdV1";
const PROFILE_ID_PATTERN = /^[0-9a-f]{64}$/u;

const profileInstallIdPromise = loadOrCreateProfileInstallId();
const routerPromise = profileInstallIdPromise.then((profileInstallId) => new core.BackgroundRouter({
  profileInstallId,
  sessionId: shared.randomHex(32),
  extensionId: chrome.runtime.id,
  randomHex: (bytes) => shared.randomHex(bytes),
  now: () => Date.now(),
  nativeFactory: createNativeTransport
}));

chrome.runtime.onConnect.addListener((port) => {
  if (port.name !== core.CONTENT_PORT_NAME) {
    port.disconnect();
    return;
  }
  let detached = false;
  let handle = null;

  port.onDisconnect.addListener(() => {
    detached = true;
    void chrome.runtime.lastError;
    if (handle !== null) {
      handle.disconnect("content-port-disconnect");
    }
  });

  void routerPromise.then((router) => {
    if (detached) {
      return;
    }
    handle = router.attachContent({
      sender: port.sender,
      postMessage: (message) => port.postMessage(message)
    });
    port.onMessage.addListener((message) => {
      handle.receive(message);
    });
  }).catch(() => {
    if (!detached) {
      try {
        port.postMessage({
          namespace: shared.NAMESPACE,
          version: shared.PROTOCOL_VERSION,
          kind: "fatal",
          error: shared.rpcError(4900, "Wallet extension initialization failed.")
        });
      } finally {
        port.disconnect();
      }
    }
  });
});

chrome.runtime.onInstalled.addListener(() => {
  void profileInstallIdPromise;
});

if (chrome.runtime.onSuspend) {
  chrome.runtime.onSuspend.addListener(() => {
    void routerPromise.then((router) => router.shutdown());
  });
}

async function loadOrCreateProfileInstallId() {
  const stored = await chrome.storage.local.get(PROFILE_INSTALL_ID_KEY);
  if (PROFILE_ID_PATTERN.test(stored[PROFILE_INSTALL_ID_KEY])) {
    return stored[PROFILE_INSTALL_ID_KEY];
  }
  const generated = shared.randomHex(32);
  await chrome.storage.local.set({ [PROFILE_INSTALL_ID_KEY]: generated });
  const confirmed = await chrome.storage.local.get(PROFILE_INSTALL_ID_KEY);
  if (!PROFILE_ID_PATTERN.test(confirmed[PROFILE_INSTALL_ID_KEY])) {
    throw new Error("Failed to initialize the local wallet profile identifier.");
  }
  return confirmed[PROFILE_INSTALL_ID_KEY];
}

function createNativeTransport({ hostName, onMessage, onDisconnect }) {
  const nativePort = chrome.runtime.connectNative(hostName);
  nativePort.onMessage.addListener(onMessage);
  nativePort.onDisconnect.addListener(() => {
    void chrome.runtime.lastError;
    onDisconnect();
  });
  return Object.freeze({
    send: (message) => nativePort.postMessage(message),
    disconnect: () => nativePort.disconnect()
  });
}
