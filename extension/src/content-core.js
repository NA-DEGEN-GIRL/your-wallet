(function installYourWalletContentCore(root) {
  "use strict";

  if (Object.prototype.hasOwnProperty.call(root, "__YOUR_WALLET_CONTENT_CORE__")) {
    return;
  }

  const shared = root.__YOUR_WALLET_SHARED__;
  if (!shared) {
    throw new Error("Your Wallet shared module was not loaded.");
  }

  class ContentBridge {
    constructor({ channelNonce, sendToBackground, postToPage }) {
      if (!shared.validNonce(channelNonce)) {
        throw new TypeError("Invalid page channel nonce.");
      }
      if (typeof sendToBackground !== "function" || typeof postToPage !== "function") {
        throw new TypeError("Content bridge adapters are required.");
      }
      this.channelNonce = channelNonce;
      this.activationNonce = null;
      this.sendToBackground = sendToBackground;
      this.postToPage = postToPage;
      this.pending = new Set();
      this.seen = new Set();
      this.responded = new Set();
      this.active = false;
    }

    activate(activationNonce) {
      if (this.active || !shared.validNonce(activationNonce)) {
        return false;
      }
      this.activationNonce = activationNonce;
      this.active = true;
      this.postToPage({
        namespace: shared.NAMESPACE,
        version: shared.PROTOCOL_VERSION,
        channel: this.channelNonce,
        kind: "bridge-init"
      });
      return true;
    }

    receivePage(value) {
      if (!this.active || !shared.fitsMessageLimit(value)) {
        return false;
      }
      const request = shared.parsePageRequest(value, this.channelNonce);
      if (!request) {
        return false;
      }
      if (this.seen.has(request.id)) {
        this.cancel("duplicate-request-id");
        return false;
      }
      if (this.seen.size >= shared.MAX_REQUESTS_PER_ACTIVATION) {
        this.respondError(request.id, shared.rpcError(-32005, "Request limit reached for this document."));
        this.cancel("request-limit");
        return false;
      }
      this.seen.add(request.id);
      this.pending.add(request.id);
      const outbound = {
        namespace: shared.NAMESPACE,
        version: shared.PROTOCOL_VERSION,
        kind: "request",
        activationNonce: this.activationNonce,
        id: request.id,
        method: request.method,
        params: request.params
      };
      if (!shared.fitsMessageLimit(outbound)) {
        this.pending.delete(request.id);
        this.respondError(request.id, shared.rpcError(-32600, "Request exceeds the wallet message limit."));
        return false;
      }
      this.sendToBackground(outbound);
      return true;
    }

    receiveBackground(value) {
      if (!this.active || !shared.isPlainObject(value) || !shared.fitsMessageLimit(value)) {
        return false;
      }
      if (value.namespace !== shared.NAMESPACE
        || value.version !== shared.PROTOCOL_VERSION
        || value.activationNonce !== this.activationNonce) {
        return false;
      }
      if (value.kind === "response") {
        return this.receiveResponse(value);
      }
      if (value.kind === "event") {
        return this.receiveEvent(value);
      }
      if (value.kind === "disconnect") {
        if (!shared.hasExactKeys(value, [
          "namespace", "version", "kind", "activationNonce", "error"
        ]) || !validRpcError(value.error)) {
          return false;
        }
        this.cancel("background-disconnect", value.error);
        return true;
      }
      return false;
    }

    receiveResponse(value) {
      const resultShape = shared.hasExactKeys(value, [
        "namespace", "version", "kind", "activationNonce", "id", "result"
      ]);
      const errorShape = shared.hasExactKeys(value, [
        "namespace", "version", "kind", "activationNonce", "id", "error"
      ]);
      if ((!resultShape && !errorShape)
        || !shared.validRequestId(value.id)
        || !this.pending.has(value.id)
        || this.responded.has(value.id)
        || (resultShape && !shared.isJsonValue(value.result))
        || (errorShape && !validRpcError(value.error))) {
        return false;
      }
      this.pending.delete(value.id);
      this.responded.add(value.id);
      const pageMessage = {
        namespace: shared.NAMESPACE,
        version: shared.PROTOCOL_VERSION,
        channel: this.channelNonce,
        kind: "response",
        id: value.id
      };
      if (resultShape) {
        pageMessage.result = value.result;
      } else {
        pageMessage.error = value.error;
      }
      if (!shared.fitsMessageLimit(pageMessage)) {
        delete pageMessage.result;
        pageMessage.error = shared.rpcError(-32603, "Wallet response exceeds the message limit.");
      }
      this.postToPage(pageMessage);
      return true;
    }

    receiveEvent(value) {
      if (!shared.hasExactKeys(value, [
        "namespace", "version", "kind", "activationNonce", "event", "payload"
      ]) || !shared.ALLOWED_EVENTS.has(value.event) || !shared.isJsonValue(value.payload)) {
        return false;
      }
      const pageMessage = {
        namespace: shared.NAMESPACE,
        version: shared.PROTOCOL_VERSION,
        channel: this.channelNonce,
        kind: "event",
        event: value.event,
        payload: value.payload
      };
      if (!shared.fitsMessageLimit(pageMessage)) {
        return false;
      }
      this.postToPage(pageMessage);
      return true;
    }

    respondError(id, error) {
      if (this.responded.has(id)) {
        return false;
      }
      this.responded.add(id);
      this.postToPage({
        namespace: shared.NAMESPACE,
        version: shared.PROTOCOL_VERSION,
        channel: this.channelNonce,
        kind: "response",
        id,
        error
      });
      return true;
    }

    cancel(reason, suppliedError = null) {
      if (!this.active) {
        return;
      }
      this.active = false;
      const error = suppliedError || shared.rpcError(4900, "Wallet connection closed.", { reason });
      for (const id of this.pending) {
        this.respondError(id, error);
      }
      this.pending.clear();
      this.postToPage({
        namespace: shared.NAMESPACE,
        version: shared.PROTOCOL_VERSION,
        channel: this.channelNonce,
        kind: "disconnect",
        error
      });
      this.sendToBackground({
        namespace: shared.NAMESPACE,
        version: shared.PROTOCOL_VERSION,
        kind: "disconnect",
        activationNonce: this.activationNonce,
        reason
      });
    }
  }

  function validRpcError(value) {
    if (!shared.hasExactKeys(value, ["code", "message"], ["data"])) {
      return false;
    }
    return Number.isInteger(value.code)
      && typeof value.message === "string"
      && value.message.length <= 512
      && (!Object.prototype.hasOwnProperty.call(value, "data") || shared.isJsonValue(value.data));
  }

  Object.defineProperty(root, "__YOUR_WALLET_CONTENT_CORE__", {
    configurable: false,
    enumerable: false,
    writable: false,
    value: Object.freeze({ ContentBridge, validRpcError })
  });
}(globalThis));
