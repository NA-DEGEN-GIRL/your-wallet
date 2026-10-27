(function startYourWalletContentBridge(root) {
  "use strict";

  const shared = root.__YOUR_WALLET_SHARED__;
  const contentCore = root.__YOUR_WALLET_CONTENT_CORE__;
  if (!shared || !contentCore || root.top !== root || !shared.isSupportedPageUrl(root.location.href)) {
    return;
  }

  const targetOrigin = root.location.origin;

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

  const bridge = new contentCore.ContentBridge({
    channelNonce: shared.randomHex(32),
    connectPort,
    postToPage: (message) => root.postMessage(message, targetOrigin),
    isContextValid,
    setTimer: (callback, milliseconds) => root.setTimeout(callback, milliseconds),
    clearTimer: (handle) => root.clearTimeout(handle),
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
  root.addEventListener("pagehide", () => bridge.closeForDocument("document-pagehide"));
  // Page Lifecycle `freeze` is fired at the Document (non-bubbling), not at the Window.
  root.document.addEventListener("freeze", () => bridge.closeForDocument("document-freeze"));

  bridge.announce();
}(globalThis));
