(function startYourWalletContentBridge(root) {
  "use strict";

  const shared = root.__YOUR_WALLET_SHARED__;
  const contentCore = root.__YOUR_WALLET_CONTENT_CORE__;
  if (!shared || !contentCore || root.top !== root || !shared.isSupportedPageUrl(root.location.href)) {
    return;
  }

  const targetOrigin = root.location.origin;
  const setTimer = (callback, milliseconds) => root.setTimeout(callback, milliseconds);
  const clearTimer = (handle) => root.clearTimeout(handle);

  function connectPort() {
    // Throws when the extension context is invalidated; the bridge then enters DEAD.
    const port = chrome.runtime.connect({ name: shared.CONTENT_PORT_NAME });
    return Object.freeze({
      postMessage: (message) => port.postMessage(message),
      disconnect: () => port.disconnect(),
      onMessage: (listener) => port.onMessage.addListener(listener),
      onDisconnect: (listener) => port.onDisconnect.addListener(() => {
        void chrome.runtime.lastError;
        listener();
      })
    });
  }

  function isContextValid() {
    try {
      return typeof chrome === "object" && chrome !== null && chrome.runtime?.id !== undefined;
    } catch (_error) {
      return false;
    }
  }

  // spec/05 §2.12: the compatibility mode is read once at document_start and handed to the MAIN
  // world in `bridge-init`. The page provider waits for that message (a few ms) before its first
  // EIP-6963 announcement, so no listener is needed until the mode is known: a `bridge-request`
  // posted earlier is answered by the `announce()` below.
  contentCore.loadCompatModes({
    readStorage: () => chrome.storage.local.get([
      shared.COMPAT_MODE_STORAGE_KEY,
      shared.SOL_COMPAT_MODE_STORAGE_KEY,
      shared.BTC_COMPAT_MODE_STORAGE_KEY
    ]),
    setTimer,
    clearTimer
  }).then(start);

  function start(modes) {
    const bridge = new contentCore.ContentBridge({
      channelNonce: shared.randomHex(32),
      compatMode: modes.evm,
      solCompatMode: modes.sol,
      btcCompatMode: modes.btc,
      connectPort,
      postToPage: (message) => root.postMessage(message, targetOrigin),
      isContextValid,
      setTimer,
      clearTimer,
      now: () => Date.now()
    });

    // No `once`: the document can be restored from bfcache and hidden again.
    // `beforeunload` is deliberately ignored because the user may cancel the unload.
    root.addEventListener("message", (event) => {
      if (event.source !== root || event.origin !== targetOrigin) {
        return;
      }
      bridge.receivePage(event.data);
    });
    // Only the browser's own lifecycle events count: the page shares this window and document
    // and could dispatch a synthetic `pagehide`/`freeze` to tear down the activation (and fail
    // every pending request) at will.
    root.addEventListener("pagehide", (event) => {
      if (event.isTrusted === true) {
        bridge.closeForDocument("document-pagehide");
      }
    });
    // Page Lifecycle `freeze` is fired at the Document (non-bubbling), not at the Window.
    root.document.addEventListener("freeze", (event) => {
      if (event.isTrusted === true) {
        bridge.closeForDocument("document-freeze");
      }
    });

    bridge.announce();
  }
}(globalThis));
