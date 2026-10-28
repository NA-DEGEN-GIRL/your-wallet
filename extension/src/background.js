import "./shared.js";
import "./background-core.js";

const shared = globalThis.__YOUR_WALLET_SHARED__;
const core = globalThis.__YOUR_WALLET_BACKGROUND_CORE__;
const PROFILE_INSTALL_ID_KEY = "profileInstallIdV1";
const PROFILE_ID_PATTERN = /^[0-9a-f]{64}$/u;
const POPUP_PAGE = "popup/popup.html";

// Router creation is retried on the next content connection if loading the
// profile identifier fails. Connections from other extensions or web pages are
// never accepted: no external-connection or external-message listener exists.
let routerPromise = null;

function getRouter() {
  if (routerPromise === null) {
    const created = loadOrCreateProfileInstallId().then((profileInstallId) => new core.BackgroundRouter({
      profileInstallId,
      extensionId: chrome.runtime.id,
      randomHex: (bytes) => shared.randomHex(bytes),
      now: () => Date.now(),
      setTimer: (callback, milliseconds) => setTimeout(callback, milliseconds),
      clearTimer: (handle) => clearTimeout(handle),
      nativeFactory: createNativeTransport
    }));
    routerPromise = created;
    created.catch(() => {
      if (routerPromise === created) {
        routerPromise = null;
      }
    });
  }
  return routerPromise;
}

chrome.runtime.onConnect.addListener((port) => {
  if (port.name === core.POPUP_PORT_NAME) {
    answerPopup(port);
    return;
  }
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
  port.onMessage.addListener((message) => {
    if (handle !== null) {
      handle.receive(message);
    }
  });

  getRouter().then((router) => {
    if (detached) {
      return;
    }
    handle = router.attachContent({
      sender: port.sender,
      postMessage: (message) => port.postMessage(message),
      disconnect: () => port.disconnect()
    });
    if (handle === null) {
      port.disconnect();
    }
  }).catch(() => {
    // Initialization failed: close the port; the content script treats it as a transient disconnect.
    if (!detached) {
      try {
        port.disconnect();
      } catch (_error) {
        // Already closed.
      }
    }
  });
});

// spec/05 §2.12: the action popup asks once for the observed yw-app connection state. The router
// is not created for this (a status query must not touch storage or native messaging).
function answerPopup(port) {
  if (!core.isPopupSender(port.sender, chrome.runtime.id, chrome.runtime.getURL(POPUP_PAGE))) {
    port.disconnect();
    return;
  }
  const pending = routerPromise === null
    ? Promise.resolve("unknown")
    : routerPromise.then((router) => router.nativeStatus(), () => "unknown");
  pending.then((status) => {
    try {
      port.postMessage(core.popupStatusMessage(status));
    } catch (_error) {
      // The popup closed before the answer.
    }
  });
}

chrome.runtime.onInstalled.addListener(() => {
  getRouter().catch(() => {});
});

if (chrome.runtime.onSuspend) {
  chrome.runtime.onSuspend.addListener(() => {
    if (routerPromise !== null) {
      routerPromise.then((router) => router.closeNative()).catch(() => {});
    }
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
