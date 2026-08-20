(function installYourWalletBackgroundCore(root) {
  "use strict";

  if (Object.prototype.hasOwnProperty.call(root, "__YOUR_WALLET_BACKGROUND_CORE__")) {
    return;
  }

  const shared = root.__YOUR_WALLET_SHARED__;
  if (!shared) {
    throw new Error("Your Wallet shared module was not loaded.");
  }

  const CONTENT_PORT_NAME = "your-wallet-content-v1";
  const NATIVE_HOST_NAME = "com.your_wallet.native";
  const REQUEST_DEADLINE_MS = 120_000;
  const MAX_ACTIVE_DOCUMENTS = 128;
  const MAX_GLOBAL_PENDING = 1_024;
  const MAX_PENDING_PER_DOCUMENT = 64;
  const MAX_NATIVE_CONNECTION_ATTEMPTS = 4_096;
  const DOCUMENT_ID_PATTERN = /^[A-Za-z0-9._:-]{1,256}$/u;
  const PROFILE_ID_PATTERN = /^[0-9a-f]{64}$/u;
  const EXTENSION_ID_PATTERN = /^[a-p]{32}$/u;
  const CANCEL_REASON_PATTERN = /^[A-Za-z0-9_-]{1,128}$/u;

  class BackgroundRouter {
    constructor({ profileInstallId, sessionId, extensionId, randomHex, now, nativeFactory }) {
      if (!PROFILE_ID_PATTERN.test(profileInstallId)
        || !PROFILE_ID_PATTERN.test(sessionId)
        || !EXTENSION_ID_PATTERN.test(extensionId)
        || typeof randomHex !== "function"
        || typeof now !== "function"
        || typeof nativeFactory !== "function") {
        throw new TypeError("Invalid background router configuration.");
      }
      this.profileInstallId = profileInstallId;
      this.sessionId = sessionId;
      this.extensionId = extensionId;
      this.randomHex = randomHex;
      this.now = now;
      this.nativeFactory = nativeFactory;
      this.activations = new Map();
      this.pending = new Map();
      this.nativeConnection = null;
      this.nativeEpoch = 0;
      this.nativeConnectionAttempts = 0;
      this.lastNativeSequence = 0;
      this.outboundSequence = 0;
      this.issuedPortNonces = new Set([profileInstallId, sessionId]);
    }

    attachContent({ sender, postMessage }) {
      if (typeof postMessage !== "function") {
        throw new TypeError("A content-port sender is required.");
      }
      if (this.activations.size >= MAX_ACTIVE_DOCUMENTS) {
        throw new Error("Active wallet document limit reached.");
      }
      const activationNonce = this.issuePortNonce();
      const channelNonce = this.issuePortNonce();
      const context = deriveSenderContext({
        sender,
        extensionId: this.extensionId,
        channelNonce
      });
      const state = {
        activationNonce,
        channelNonce,
        context,
        live: true,
        pendingIds: new Set(),
        postMessage,
        respondedIds: new Set(),
        seenIds: new Set()
      };
      this.activations.set(activationNonce, state);
      this.postContent(state, {
        namespace: shared.NAMESPACE,
        version: shared.PROTOCOL_VERSION,
        kind: "activated",
        activationNonce
      });
      return Object.freeze({
        activationNonce,
        receive: (message) => this.receiveContent(state, message),
        disconnect: (reason = "content-port-disconnect") => this.detachActivation(state, reason, false)
      });
    }

    receiveContent(state, value) {
      if (!state.live || this.activations.get(state.activationNonce) !== state) {
        return false;
      }
      if (!shared.fitsMessageLimit(value)) {
        const id = shared.isPlainObject(value) && shared.validRequestId(value.id) ? value.id : null;
        if (id !== null && !state.seenIds.has(id)) {
          state.seenIds.add(id);
          this.respondError(state, id, -32600, "Request exceeds the wallet message limit.");
        } else {
          this.detachActivation(state, "oversized-content-message", true);
        }
        return false;
      }
      if (isContentDisconnect(value, state.activationNonce)) {
        this.detachActivation(state, "document-disconnect", false);
        return true;
      }
      const request = shared.parseContentRequest(value, state.activationNonce);
      if (!request) {
        const id = shared.isPlainObject(value) && shared.validRequestId(value.id) ? value.id : null;
        if (id !== null && !state.seenIds.has(id)) {
          state.seenIds.add(id);
          this.respondError(state, id, -32600, "Invalid wallet request envelope.");
        } else {
          this.detachActivation(state, "invalid-content-envelope", true);
        }
        return false;
      }
      if (state.seenIds.has(request.id)) {
        if (state.pendingIds.has(request.id)) {
          const duplicatePending = this.pending.get(requestKey(state.activationNonce, request.id));
          if (duplicatePending) {
            this.sendNativeCancellation(duplicatePending, "replayed-request-id");
          }
          this.respondError(state, request.id, -32600, "Duplicate request identifier.");
        }
        if (state.live) {
          this.detachActivation(state, "replayed-request-id", true);
        }
        return false;
      }
      if (state.seenIds.size >= shared.MAX_REQUESTS_PER_ACTIVATION) {
        state.seenIds.add(request.id);
        this.respondError(state, request.id, -32005, "Request limit reached for this document.");
        this.detachActivation(state, "request-limit", true);
        return false;
      }
      state.seenIds.add(request.id);
      if (this.pending.size >= MAX_GLOBAL_PENDING
        || state.pendingIds.size >= MAX_PENDING_PER_DOCUMENT) {
        this.respondError(state, request.id, -32005, "Too many wallet requests are pending.");
        return false;
      }
      const route = shared.methodRoute(request.method);
      if (route === null) {
        this.respondError(state, request.id, 4200, "Unsupported wallet method.");
        return false;
      }

      try {
        this.ensureNativeConnection();
      } catch (_error) {
        this.respondError(state, request.id, 4900, "Native wallet service is unavailable.");
        return false;
      }

      const issuedAtUnixMs = this.now();
      if (!Number.isSafeInteger(issuedAtUnixMs) || issuedAtUnixMs < 0) {
        this.respondError(state, request.id, -32603, "Wallet clock is unavailable.");
        return false;
      }
      const deadlineUnixMs = issuedAtUnixMs + REQUEST_DEADLINE_MS;
      if (!Number.isSafeInteger(deadlineUnixMs)) {
        this.respondError(state, request.id, -32603, "Wallet request deadline overflowed.");
        return false;
      }
      let sequence;
      try {
        sequence = this.nextOutboundSequenceCandidate();
      } catch (_error) {
        this.respondError(state, request.id, 4900, "Native wallet service is unavailable.");
        return false;
      }
      const nativeRequest = {
        namespace: shared.NAMESPACE,
        version: shared.PROTOCOL_VERSION,
        role: "extension",
        kind: "request",
        sessionId: this.sessionId,
        sequence,
        deadlineUnixMs,
        profileInstallId: this.profileInstallId,
        activationNonce: state.activationNonce,
        requestId: request.id,
        method: request.method,
        params: request.params,
        route,
        context: state.context
      };
      if (!shared.fitsMessageLimit(nativeRequest)) {
        this.respondError(state, request.id, -32600, "Request exceeds the native wallet message limit.");
        return false;
      }
      this.outboundSequence = sequence;
      const pendingKey = requestKey(state.activationNonce, request.id);
      const pending = { state, id: request.id, sequence, deadlineUnixMs };
      state.pendingIds.add(request.id);
      this.pending.set(pendingKey, pending);
      try {
        this.nativeConnection.send(nativeRequest);
      } catch (_error) {
        this.pending.delete(pendingKey);
        state.pendingIds.delete(request.id);
        this.respondError(state, request.id, 4900, "Native wallet service disconnected.");
        this.dropNativeConnection("native-send-failed");
        return false;
      }
      return true;
    }

    ensureNativeConnection() {
      if (this.nativeConnection !== null) {
        return;
      }
      this.openNativeConnection("native-reconnect");
    }

    reconnectNative() {
      this.dropNativeConnection("native-reconnect");
      this.openNativeConnection("native-reconnect");
    }

    openNativeConnection(cancelReason) {
      this.cancelAllPending(cancelReason);
      if (this.nativeConnectionAttempts >= MAX_NATIVE_CONNECTION_ATTEMPTS) {
        throw new Error("Native connection attempt limit reached.");
      }
      if (this.nativeConnectionAttempts !== 0) {
        this.sessionId = this.issuePortNonce();
      }
      this.nativeConnectionAttempts += 1;
      const epoch = this.nativeEpoch + 1;
      this.nativeEpoch = epoch;
      this.lastNativeSequence = 0;
      this.outboundSequence = 0;
      const connection = this.nativeFactory({
        hostName: NATIVE_HOST_NAME,
        onMessage: (message) => {
          if (this.nativeEpoch === epoch) {
            this.receiveNative(message);
          }
        },
        onDisconnect: () => {
          if (this.nativeEpoch === epoch) {
            this.nativeConnection = null;
            this.cancelAllPending("native-disconnect");
          }
        }
      });
      if (!connection || typeof connection.send !== "function") {
        throw new Error("Native transport did not provide a send operation.");
      }
      this.nativeConnection = connection;
    }

    dropNativeConnection(reason) {
      const connection = this.nativeConnection;
      this.nativeEpoch += 1;
      this.nativeConnection = null;
      this.cancelAllPending(reason);
      if (connection && typeof connection.disconnect === "function") {
        try {
          connection.disconnect();
        } catch (_error) {
          // The transport is already unusable; pending work was cancelled above.
        }
      }
    }

    receiveNative(value) {
      if (!shared.fitsMessageLimit(value)
        || !shared.isPlainObject(value)
        || value.namespace !== shared.NAMESPACE
        || value.version !== shared.PROTOCOL_VERSION
        || value.role !== "native-host"
        || value.sessionId !== this.sessionId
        || !Number.isSafeInteger(value.sequence)
        || value.sequence !== this.lastNativeSequence + 1) {
        this.dropNativeConnection("invalid-native-envelope");
        return false;
      }
      this.lastNativeSequence = value.sequence;
      if (value.kind === "response") {
        return this.receiveNativeResponse(value);
      }
      if (value.kind === "event") {
        return this.receiveNativeEvent(value);
      }
      this.dropNativeConnection("unknown-native-message");
      return false;
    }

    receiveNativeResponse(value) {
      const resultShape = shared.hasExactKeys(value, [
        "namespace", "version", "role", "kind", "sessionId", "sequence",
        "requestSequence", "activationNonce", "requestId", "result"
      ]);
      const errorShape = shared.hasExactKeys(value, [
        "namespace", "version", "role", "kind", "sessionId", "sequence",
        "requestSequence", "activationNonce", "requestId", "error"
      ]);
      if ((!resultShape && !errorShape)
        || !PROFILE_ID_PATTERN.test(value.activationNonce)
        || !shared.validRequestId(value.requestId)
        || !Number.isSafeInteger(value.requestSequence)
        || (resultShape && !shared.isJsonValue(value.result))
        || (errorShape && !validRpcError(value.error))) {
        this.dropNativeConnection("invalid-native-response");
        return false;
      }
      const key = requestKey(value.activationNonce, value.requestId);
      const pending = this.pending.get(key);
      if (!pending || pending.sequence !== value.requestSequence || !pending.state.live) {
        return false;
      }
      const receivedAtUnixMs = this.now();
      if (!Number.isSafeInteger(receivedAtUnixMs)
        || receivedAtUnixMs >= pending.deadlineUnixMs) {
        this.pending.delete(key);
        pending.state.pendingIds.delete(pending.id);
        this.respondError(pending.state, pending.id, -32000, "Wallet request timed out.");
        return false;
      }
      this.pending.delete(key);
      pending.state.pendingIds.delete(pending.id);
      if (resultShape) {
        return this.respondResult(pending.state, pending.id, value.result);
      }
      return this.respondWithErrorObject(pending.state, pending.id, value.error);
    }

    receiveNativeEvent(value) {
      if (!shared.hasExactKeys(value, [
        "namespace", "version", "role", "kind", "sessionId", "sequence",
        "activationNonce", "event", "payload"
      ])
        || !PROFILE_ID_PATTERN.test(value.activationNonce)
        || !shared.ALLOWED_EVENTS.has(value.event)
        || !shared.isJsonValue(value.payload)) {
        this.dropNativeConnection("invalid-native-event");
        return false;
      }
      const state = this.activations.get(value.activationNonce);
      if (!state || !state.live) {
        return false;
      }
      return this.postContent(state, {
        namespace: shared.NAMESPACE,
        version: shared.PROTOCOL_VERSION,
        kind: "event",
        activationNonce: state.activationNonce,
        event: value.event,
        payload: value.payload
      });
    }

    respondResult(state, id, result) {
      return this.respond(state, id, { result });
    }

    respondError(state, id, code, message, data) {
      return this.respondWithErrorObject(state, id, shared.rpcError(code, message, data));
    }

    respondWithErrorObject(state, id, error) {
      return this.respond(state, id, { error });
    }

    respond(state, id, body) {
      if (!state.live || state.respondedIds.has(id)) {
        return false;
      }
      const pendingKey = requestKey(state.activationNonce, id);
      this.pending.delete(pendingKey);
      state.pendingIds.delete(id);
      state.respondedIds.add(id);
      const envelope = {
        namespace: shared.NAMESPACE,
        version: shared.PROTOCOL_VERSION,
        kind: "response",
        activationNonce: state.activationNonce,
        id,
        ...body
      };
      if (!shared.fitsMessageLimit(envelope)) {
        delete envelope.result;
        envelope.error = shared.rpcError(-32603, "Wallet response exceeds the message limit.");
      }
      return this.postContent(state, envelope);
    }

    detachActivation(state, reason, notifyContent) {
      if (!state.live) {
        return;
      }
      const cancellationReason = normalizeCancelReason(reason);
      for (const id of state.pendingIds) {
        const key = requestKey(state.activationNonce, id);
        const pending = this.pending.get(key);
        this.pending.delete(key);
        if (pending) {
          this.sendNativeCancellation(pending, cancellationReason);
        }
      }
      state.pendingIds.clear();
      if (notifyContent) {
        this.postContent(state, {
          namespace: shared.NAMESPACE,
          version: shared.PROTOCOL_VERSION,
          kind: "disconnect",
          activationNonce: state.activationNonce,
          error: shared.rpcError(4900, "Wallet connection closed.", { reason: cancellationReason })
        });
      }
      state.live = false;
      this.activations.delete(state.activationNonce);
      this.issuedPortNonces.delete(state.activationNonce);
      this.issuedPortNonces.delete(state.channelNonce);
    }

    cancelAllPending(reason) {
      const cancellationReason = normalizeCancelReason(reason);
      const affected = new Set();
      for (const pending of this.pending.values()) {
        affected.add(pending.state);
      }
      this.pending.clear();
      for (const state of affected) {
        state.pendingIds.clear();
        if (state.live) {
          this.postContent(state, {
            namespace: shared.NAMESPACE,
            version: shared.PROTOCOL_VERSION,
            kind: "disconnect",
            activationNonce: state.activationNonce,
            error: shared.rpcError(4900, "Native wallet connection closed.", {
              reason: cancellationReason
            })
          });
          state.live = false;
          this.activations.delete(state.activationNonce);
          this.issuedPortNonces.delete(state.activationNonce);
          this.issuedPortNonces.delete(state.channelNonce);
        }
      }
    }

    sendNativeCancellation(pending, reason) {
      if (this.nativeConnection === null) {
        return;
      }
      try {
        const sequence = this.nextOutboundSequenceCandidate();
        const message = {
          namespace: shared.NAMESPACE,
          version: shared.PROTOCOL_VERSION,
          role: "extension",
          kind: "cancel",
          sessionId: this.sessionId,
          sequence,
          activationNonce: pending.state.activationNonce,
          requestId: pending.id,
          requestSequence: pending.sequence,
          reason: normalizeCancelReason(reason)
        };
        if (!shared.fitsMessageLimit(message)) {
          this.dropNativeConnection("native-cancel-invalid");
          return;
        }
        this.outboundSequence = sequence;
        this.nativeConnection.send(message);
      } catch (_error) {
        if (this.nativeConnection !== null) {
          this.dropNativeConnection("native-cancel-failed");
        }
      }
    }

    postContent(state, message) {
      if (!shared.fitsMessageLimit(message)) {
        return false;
      }
      try {
        state.postMessage(message);
        return true;
      } catch (_error) {
        if (state.live) {
          this.detachActivation(state, "content-post-failed", false);
        }
        return false;
      }
    }

    nextOutboundSequenceCandidate() {
      if (this.outboundSequence >= Number.MAX_SAFE_INTEGER) {
        this.dropNativeConnection("sequence-exhausted");
        throw new Error("Native message sequence exhausted.");
      }
      return this.outboundSequence + 1;
    }

    issuePortNonce() {
      for (let attempt = 0; attempt < 16; attempt += 1) {
        const candidate = this.randomHex(32);
        if (PROFILE_ID_PATTERN.test(candidate) && !this.issuedPortNonces.has(candidate)) {
          this.issuedPortNonces.add(candidate);
          return candidate;
        }
      }
      throw new Error("Unable to allocate a unique content-port nonce.");
    }

    shutdown() {
      for (const state of [...this.activations.values()]) {
        this.detachActivation(state, "worker-shutdown", true);
      }
      this.dropNativeConnection("worker-shutdown");
    }
  }

  function normalizeCancelReason(reason) {
    return typeof reason === "string" && CANCEL_REASON_PATTERN.test(reason)
      ? reason
      : "invalid-cancel-reason";
  }

  function deriveSenderContext(configuration) {
    if (!shared.hasExactKeys(configuration, ["sender", "extensionId", "channelNonce"])
      || !EXTENSION_ID_PATTERN.test(configuration.extensionId)
      || !PROFILE_ID_PATTERN.test(configuration.channelNonce)) {
      throw new Error("Background-owned browser context configuration is invalid.");
    }
    const { sender, extensionId, channelNonce } = configuration;
    if (!sender || typeof sender !== "object"
      || !sender.tab || !Number.isSafeInteger(sender.tab.id) || sender.tab.id < 0
      || sender.frameId !== 0
      || sender.documentLifecycle !== "active"
      || typeof sender.documentId !== "string"
      || !DOCUMENT_ID_PATTERN.test(sender.documentId)
      || typeof sender.url !== "string"
      || sender.tab.incognito === true
      || sender.url.length > 8_192) {
      throw new Error("Content connection lacks a valid top-level document identity.");
    }
    let parsed;
    try {
      parsed = new URL(sender.url);
    } catch (_error) {
      throw new Error("Content connection URL is invalid.");
    }
    if (parsed.protocol !== "https:"
      || parsed.username !== ""
      || parsed.password !== ""
      || parsed.origin === "null"
      || (typeof sender.origin === "string" && sender.origin !== parsed.origin)) {
      throw new Error("Content connection origin is not an allowed HTTPS origin.");
    }
    return Object.freeze({
      browserFamily: "chrome",
      extensionId,
      tabId: sender.tab.id,
      frameId: 0,
      documentId: sender.documentId,
      topOrigin: parsed.origin,
      frameOrigin: parsed.origin,
      documentLifecycle: "active",
      channelNonce
    });
  }

  function isContentDisconnect(value, activationNonce) {
    return shared.hasExactKeys(value, [
      "namespace", "version", "kind", "activationNonce", "reason"
    ])
      && value.namespace === shared.NAMESPACE
      && value.version === shared.PROTOCOL_VERSION
      && value.kind === "disconnect"
      && value.activationNonce === activationNonce
      && typeof value.reason === "string"
      && value.reason.length <= 128;
  }

  function requestKey(activationNonce, requestId) {
    return `${activationNonce}:${requestId}`;
  }

  function validRpcError(value) {
    return shared.hasExactKeys(value, ["code", "message"], ["data"])
      && Number.isSafeInteger(value.code)
      && typeof value.message === "string"
      && value.message.length > 0
      && value.message.length <= 512
      && (!Object.prototype.hasOwnProperty.call(value, "data") || shared.isJsonValue(value.data));
  }

  Object.defineProperty(root, "__YOUR_WALLET_BACKGROUND_CORE__", {
    configurable: false,
    enumerable: false,
    writable: false,
    value: Object.freeze({
      BackgroundRouter,
      CONTENT_PORT_NAME,
      NATIVE_HOST_NAME,
      REQUEST_DEADLINE_MS,
      MAX_ACTIVE_DOCUMENTS,
      MAX_GLOBAL_PENDING,
      MAX_PENDING_PER_DOCUMENT,
      MAX_NATIVE_CONNECTION_ATTEMPTS,
      deriveSenderContext,
      validRpcError
    })
  });
}(globalThis));
