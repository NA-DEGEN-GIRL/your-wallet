(function startYourWalletContentBridge(root) {
  "use strict";

  const shared = root.__YOUR_WALLET_SHARED__;
  const contentCore = root.__YOUR_WALLET_CONTENT_CORE__;
  if (!shared || !contentCore || root.top !== root || root.location.protocol !== "https:") {
    return;
  }

  const targetOrigin = root.location.origin;
  const port = chrome.runtime.connect({ name: "your-wallet-content-v1" });
  let portLive = true;
  const bridge = new contentCore.ContentBridge({
    channelNonce: shared.randomHex(32),
    sendToBackground: (message) => {
      if (portLive) {
        try {
          port.postMessage(message);
        } catch (_error) {
          portLive = false;
        }
      }
    },
    postToPage: (message) => root.postMessage(message, targetOrigin)
  });

  function onWindowMessage(event) {
    if (event.source !== root || event.origin !== targetOrigin) {
      return;
    }
    bridge.receivePage(event.data);
  }

  function closeForDocument(reason) {
    if (!portLive) {
      bridge.cancel(reason);
      return;
    }
    bridge.cancel(reason);
    portLive = false;
    try {
      port.disconnect();
    } catch (_error) {
      // The worker may already have stopped; local pending requests are cancelled.
    }
    root.removeEventListener("message", onWindowMessage);
  }

  root.addEventListener("message", onWindowMessage);
  root.addEventListener("pagehide", () => closeForDocument("document-pagehide"), { once: true });
  root.addEventListener("freeze", () => closeForDocument("document-freeze"), { once: true });
  root.addEventListener("beforeunload", () => closeForDocument("document-beforeunload"), { once: true });

  port.onMessage.addListener((message) => {
    if (shared.hasExactKeys(message, ["namespace", "version", "kind", "activationNonce"])
      && message.namespace === shared.NAMESPACE
      && message.version === shared.PROTOCOL_VERSION
      && message.kind === "activated") {
      bridge.activate(message.activationNonce);
      return;
    }
    if (shared.hasExactKeys(message, ["namespace", "version", "kind", "error"])
      && message.kind === "fatal") {
      closeForDocument("worker-initialization-failed");
      return;
    }
    bridge.receiveBackground(message);
  });

  port.onDisconnect.addListener(() => {
    portLive = false;
    void chrome.runtime.lastError;
    bridge.cancel("worker-disconnect");
  });
}(globalThis));
