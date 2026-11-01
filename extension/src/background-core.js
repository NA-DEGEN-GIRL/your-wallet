(function installYourWalletBackgroundCore(root) {
  "use strict";

  if (Object.prototype.hasOwnProperty.call(root, "__YOUR_WALLET_BACKGROUND_CORE__")) {
    return;
  }

  const shared = root.__YOUR_WALLET_SHARED__;
  if (!shared) {
    throw new Error("Your Wallet shared module was not loaded.");
  }

  const CONTENT_PORT_NAME = shared.CONTENT_PORT_NAME;
  const NATIVE_HOST_NAME = "com.your_wallet.native";
  const READ_DEADLINE_MS = 60_000;
  const INTERACTIVE_DEADLINE_MS = 600_000;
  const MAX_ACTIVE_DOCUMENTS = 128;
  const MAX_GLOBAL_PENDING = 512;
  const MAX_PENDING_PER_DOCUMENT = 64;
  const RATE_PER_SECOND = 40;
  const RATE_BURST = 80;
  const NATIVE_BACKOFF_BASE_MS = 1_000;
  const NATIVE_BACKOFF_MAX_MS = 30_000;
  const DEFAULT_DISCONNECT_REASON = "content-port-disconnect";
  const DOCUMENT_ID_PATTERN = /^[A-Za-z0-9._:-]{1,256}$/u;
  const EXTENSION_ID_PATTERN = /^[a-p]{32}$/u;
  const MAX_SENDER_URL_LENGTH = 8_192;
  const NATIVE_RESPONSE_KEYS = Object.freeze([
    "namespace", "version", "role", "kind", "sessionId", "sequence",
    "requestSequence", "activationNonce", "requestId"
  ]);
  const NATIVE_EVENT_KEYS = Object.freeze([
    "namespace", "version", "role", "kind", "sessionId", "sequence",
    "activationNonce", "event", "payload"
  ]);

  const hasOwn = (value, key) => Object.prototype.hasOwnProperty.call(value, key);

  // spec/05 §2.8. One content port = one activation; one native port = one session.
  class BackgroundRouter {
    constructor({ profileInstallId, extensionId, randomHex, now, setTimer, clearTimer, nativeFactory }) {
      if (!shared.isId64(profileInstallId)
        || !EXTENSION_ID_PATTERN.test(extensionId)
        || typeof randomHex !== "function"
        || typeof now !== "function"
        || typeof setTimer !== "function"
        || typeof clearTimer !== "function"
        || typeof nativeFactory !== "function") {
        throw new TypeError("Invalid background router configuration.");
      }
      this.profileInstallId = profileInstallId;
      this.extensionId = extensionId;
      this.randomHex = randomHex;
      this.now = now;
      this.setTimer = setTimer;
      this.clearTimer = clearTimer;
      this.nativeFactory = nativeFactory;
      this.activations = new Map();
      this.issuedNonces = new Set([profileInstallId]);
      this.pendingCount = 0;
      this.useCounter = 0;
      this.native = null;
      this.failures = 0;
      this.nativeRetryAt = 0;
    }

    attachContent({ sender, postMessage, disconnect }) {
      if (typeof postMessage !== "function" || typeof disconnect !== "function") {
        throw new TypeError("Content-port adapters are required.");
      }
      const activationNonce = this.issueNonce();
      const channelNonce = this.issueNonce();
      let context;
      try {
        context = deriveSenderContext({ sender, extensionId: this.extensionId, channelNonce });
      } catch (_error) {
        this.issuedNonces.delete(activationNonce);
        this.issuedNonces.delete(channelNonce);
        return null;
      }
      if (this.activations.size >= MAX_ACTIVE_DOCUMENTS && !this.evictIdleActivation()) {
        this.issuedNonces.delete(activationNonce);
        this.issuedNonces.delete(channelNonce);
        return null;
      }
      const now = this.now();
      const activation = {
        activationNonce,
        channelNonce,
        context,
        postMessage,
        closePort: disconnect,
        pending: new Map(),
        tokens: RATE_BURST,
        tokensAt: Number.isFinite(now) ? now : 0,
        lastUsed: ++this.useCounter,
        live: true
      };
      this.activations.set(activationNonce, activation);
      this.postContent(activation, {
        namespace: shared.NAMESPACE,
        version: shared.PROTOCOL_VERSION,
        kind: "activated",
        activationNonce
      });
      return Object.freeze({
        activationNonce,
        receive: (message) => this.receiveContent(activation, message),
        disconnect: (reason = DEFAULT_DISCONNECT_REASON) => this.detach(activation, reason)
      });
    }

    receiveContent(activation, value) {
      if (!activation.live) {
        return false;
      }
      const message = shared.parseContentMessage(value, activation.activationNonce);
      if (message === null) {
        return false;
      }
      if (message.kind === "request") {
        return this.handleRequest(activation, message);
      }
      if (message.kind === "cancel") {
        return this.cancelRequest(activation, message.id, "page-cancel");
      }
      this.detach(activation, message.reason);
      return true;
    }

    handleRequest(activation, request) {
      if (activation.pending.has(request.id)) {
        return false;
      }
      activation.lastUsed = ++this.useCounter;
      const route = shared.methodRoute(request.method);
      if (route === null) {
        return this.reject(activation, request.id, shared.ERRORS.UNSUPPORTED_METHOD);
      }
      const now = this.now();
      if (!Number.isSafeInteger(now) || now < 0) {
        return this.reject(activation, request.id, shared.ERRORS.INTERNAL);
      }
      if (!this.takeToken(activation, now)) {
        return this.reject(activation, request.id, shared.ERRORS.RATE_LIMITED);
      }
      if (this.pendingCount >= MAX_GLOBAL_PENDING || activation.pending.size >= MAX_PENDING_PER_DOCUMENT) {
        return this.reject(activation, request.id, shared.ERRORS.TOO_MANY_PENDING);
      }
      if (now < this.nativeRetryAt) {
        return this.reject(activation, request.id, shared.ERRORS.UNAVAILABLE);
      }
      const native = this.ensureNative(now);
      if (native === null) {
        return this.reject(activation, request.id, shared.ERRORS.UNAVAILABLE);
      }
      const deadlineMs = route === "read" ? READ_DEADLINE_MS : INTERACTIVE_DEADLINE_MS;
      const sequence = native.outSequence + 1;
      const envelope = {
        namespace: shared.NAMESPACE,
        version: shared.PROTOCOL_VERSION,
        role: "extension",
        kind: "request",
        sessionId: native.sessionId,
        sequence,
        deadlineUnixMs: now + deadlineMs,
        profileInstallId: this.profileInstallId,
        activationNonce: activation.activationNonce,
        requestId: request.id,
        method: request.method,
        params: request.params,
        route,
        // spec/05 §2.12, §6.1: optional display-only `compatMode`, absent in the default mode.
        context: request.compatMode === "off"
          ? activation.context
          : { ...activation.context, compatMode: request.compatMode }
      };
      if (!Number.isSafeInteger(sequence) || !Number.isSafeInteger(envelope.deadlineUnixMs)) {
        return this.reject(activation, request.id, shared.ERRORS.INTERNAL);
      }
      if (!shared.checkJson(envelope, shared.REQUEST_LIMITS)) {
        return this.reject(activation, request.id, shared.ERRORS.REQUEST_TOO_LARGE);
      }
      native.outSequence = sequence;
      const record = { activation, id: request.id, sequence, native, timer: null };
      activation.pending.set(record.id, record);
      this.pendingCount += 1;
      record.timer = this.setTimer(() => this.expire(record), deadlineMs);
      try {
        native.connection.send(envelope);
      } catch (_error) {
        // The native port is unusable: every pending request (this one included) gets 4900.
        this.teardownNative(native, { disconnect: true, countFailure: true });
        return false;
      }
      return true;
    }

    takeToken(activation, now) {
      const elapsed = Math.max(0, now - activation.tokensAt);
      activation.tokens = Math.min(RATE_BURST, activation.tokens + (elapsed * RATE_PER_SECOND) / 1_000);
      activation.tokensAt = now;
      if (activation.tokens < 1) {
        return false;
      }
      activation.tokens -= 1;
      return true;
    }

    ensureNative(now) {
      if (this.native !== null) {
        return this.native;
      }
      const native = {
        connection: null,
        sessionId: this.randomHex(32),
        outSequence: 0,
        lastInSequence: 0,
        healthy: false
      };
      try {
        if (!shared.isId64(native.sessionId)) {
          throw new Error("Invalid native session identifier.");
        }
        const connection = this.nativeFactory({
          hostName: NATIVE_HOST_NAME,
          onMessage: (message) => {
            if (this.native === native) {
              this.receiveNative(native, message);
            }
          },
          onDisconnect: () => {
            if (this.native === native) {
              this.teardownNative(native, { disconnect: false, countFailure: true });
            }
          }
        });
        if (!connection || typeof connection.send !== "function") {
          throw new Error("Native transport did not provide a send operation.");
        }
        native.connection = connection;
      } catch (_error) {
        this.recordFailure(now);
        return null;
      }
      this.native = native;
      return native;
    }

    recordFailure(now) {
      this.failures += 1;
      const delay = Math.min(
        NATIVE_BACKOFF_BASE_MS * 2 ** Math.min(this.failures - 1, 30),
        NATIVE_BACKOFF_MAX_MS
      );
      this.nativeRetryAt = now + delay;
    }

    receiveNative(native, value) {
      if (!validNativeMessage(native, value)) {
        this.teardownNative(native, { disconnect: true, countFailure: true });
        return false;
      }
      native.lastInSequence = value.sequence;
      if (value.kind === "event") {
        native.healthy = true;
        const activation = this.activations.get(value.activationNonce);
        if (!activation || !activation.live) {
          return false;
        }
        return this.postContent(activation, {
          namespace: shared.NAMESPACE,
          version: shared.PROTOCOL_VERSION,
          kind: "event",
          activationNonce: activation.activationNonce,
          event: value.event,
          payload: value.payload
        });
      }
      const isResult = hasOwn(value, "result");
      if (isResult || value.error.code !== 4900) {
        native.healthy = true;
      }
      const activation = this.activations.get(value.activationNonce);
      const record = activation ? activation.pending.get(value.requestId) : undefined;
      if (!record || record.native !== native || record.sequence !== value.requestSequence) {
        return false;
      }
      this.removePending(record);
      return this.respond(activation, record.id, isResult ? { result: value.result } : { error: value.error });
    }

    // Native port gone (Chrome onDisconnect, protocol violation, send failure or suspend).
    // Activations survive; every pending request gets 4900 and the next request reconnects.
    teardownNative(native, { disconnect, countFailure }) {
      if (this.native !== native) {
        return;
      }
      this.native = null;
      if (disconnect && native.connection && typeof native.connection.disconnect === "function") {
        try {
          native.connection.disconnect();
        } catch (_error) {
          // Already closed.
        }
      }
      if (countFailure) {
        if (native.healthy) {
          this.failures = 0;
          this.nativeRetryAt = 0;
        } else {
          this.recordFailure(this.now());
        }
      }
      for (const activation of [...this.activations.values()]) {
        for (const record of [...activation.pending.values()]) {
          if (record.native !== native) {
            continue;
          }
          this.removePending(record);
          this.respond(activation, record.id, { error: shared.ERRORS.CONNECTION_CLOSED });
        }
      }
    }

    expire(record) {
      const { activation } = record;
      if (activation.pending.get(record.id) !== record) {
        return;
      }
      record.timer = null;
      this.removePending(record);
      this.respond(activation, record.id, { error: shared.ERRORS.TIMED_OUT });
      this.sendCancel(record, "deadline");
    }

    cancelRequest(activation, id, reason) {
      const record = activation.pending.get(id);
      if (!record) {
        return false;
      }
      this.removePending(record);
      this.sendCancel(record, reason);
      return true;
    }

    sendCancel(record, reason) {
      const native = this.native;
      if (native === null || record.native !== native) {
        return;
      }
      const sequence = native.outSequence + 1;
      native.outSequence = sequence;
      try {
        native.connection.send({
          namespace: shared.NAMESPACE,
          version: shared.PROTOCOL_VERSION,
          role: "extension",
          kind: "cancel",
          sessionId: native.sessionId,
          sequence,
          activationNonce: record.activation.activationNonce,
          requestId: record.id,
          requestSequence: record.sequence,
          reason
        });
      } catch (_error) {
        this.teardownNative(native, { disconnect: true, countFailure: true });
      }
    }

    removePending(record) {
      if (record.timer !== null) {
        this.clearTimer(record.timer);
        record.timer = null;
      }
      if (record.activation.pending.get(record.id) === record) {
        record.activation.pending.delete(record.id);
        this.pendingCount -= 1;
      }
    }

    // Content `disconnect` message or content port closed: cancel this document's native work.
    detach(activation, reason) {
      if (!activation.live) {
        return;
      }
      activation.live = false;
      this.activations.delete(activation.activationNonce);
      this.issuedNonces.delete(activation.activationNonce);
      this.issuedNonces.delete(activation.channelNonce);
      const cancelReason = shared.isReason(reason) ? reason : DEFAULT_DISCONNECT_REASON;
      for (const record of [...activation.pending.values()]) {
        this.removePending(record);
        this.sendCancel(record, cancelReason);
      }
    }

    evictIdleActivation() {
      let victim = null;
      for (const activation of this.activations.values()) {
        if (activation.pending.size === 0 && (victim === null || activation.lastUsed < victim.lastUsed)) {
          victim = activation;
        }
      }
      if (victim === null) {
        return false;
      }
      this.detach(victim, "document-evicted");
      try {
        victim.closePort();
      } catch (_error) {
        // The port may already be closed.
      }
      return true;
    }

    reject(activation, id, error) {
      this.respond(activation, id, { error });
      return false;
    }

    respond(activation, id, body) {
      if (!activation.live) {
        return false;
      }
      return this.postContent(activation, {
        namespace: shared.NAMESPACE,
        version: shared.PROTOCOL_VERSION,
        kind: "response",
        activationNonce: activation.activationNonce,
        id,
        ...body
      });
    }

    postContent(activation, message) {
      try {
        activation.postMessage(message);
        return true;
      } catch (_error) {
        this.detach(activation, DEFAULT_DISCONNECT_REASON);
        return false;
      }
    }

    issueNonce() {
      for (let attempt = 0; attempt < 16; attempt += 1) {
        const candidate = this.randomHex(32);
        if (shared.isId64(candidate) && !this.issuedNonces.has(candidate)) {
          this.issuedNonces.add(candidate);
          return candidate;
        }
      }
      throw new Error("Unable to allocate a unique nonce.");
    }

    // service worker onSuspend: close only the native connection (activations are kept).
    closeNative() {
      if (this.native !== null) {
        this.teardownNative(this.native, { disconnect: true, countFailure: false });
      }
    }

    // spec/05 §2.12 popup status. Envelope v1 has no ping, so this is what the router last
    // observed; it never opens a native connection (that would launch yw-app):
    // `connected` = open and yw-app answered, `checking` = open, no answer yet,
    // `unavailable` = the last connection failed (backoff), `unknown` = nothing observed.
    nativeStatus() {
      if (this.native !== null) {
        return this.native.healthy ? "connected" : "checking";
      }
      return this.failures > 0 ? "unavailable" : "unknown";
    }
  }

  const NATIVE_STATUSES = Object.freeze(["connected", "checking", "unavailable", "unknown"]);

  // The popup port (spec/05 §2.12) is accepted only from this extension's own action popup page,
  // never from a tab (content scripts can open runtime ports too).
  function isPopupSender(sender, extensionId, popupUrl) {
    return sender !== null
      && typeof sender === "object"
      && sender.id === extensionId
      && sender.tab === undefined
      && typeof popupUrl === "string"
      && sender.url === popupUrl;
  }

  function popupStatusMessage(status) {
    return {
      namespace: shared.NAMESPACE,
      version: shared.PROTOCOL_VERSION,
      kind: "status",
      native: NATIVE_STATUSES.includes(status) ? status : "unknown"
    };
  }

  function validNativeMessage(native, value) {
    if (!shared.checkJson(value, shared.RESPONSE_LIMITS)
      || !shared.isPlainObject(value)
      || value.namespace !== shared.NAMESPACE
      || value.version !== shared.PROTOCOL_VERSION
      || value.role !== "native-host"
      || value.sessionId !== native.sessionId
      || !Number.isSafeInteger(value.sequence)
      || value.sequence !== native.lastInSequence + 1
      || !shared.isId64(value.activationNonce)) {
      return false;
    }
    if (value.kind === "response") {
      const resultShape = shared.hasExactKeys(value, [...NATIVE_RESPONSE_KEYS, "result"]);
      const errorShape = shared.hasExactKeys(value, [...NATIVE_RESPONSE_KEYS, "error"]);
      return (resultShape || (errorShape && shared.validRpcError(value.error)))
        && Number.isSafeInteger(value.requestSequence)
        && value.requestSequence >= 1
        && shared.isId32(value.requestId);
    }
    if (value.kind === "event") {
      return shared.hasExactKeys(value, NATIVE_EVENT_KEYS) && shared.validEvent(value.event, value.payload);
    }
    return false;
  }

  // spec/05 §2.4: origin is derived only from Chrome's port.sender.
  function deriveSenderContext(configuration) {
    if (!shared.hasExactKeys(configuration, ["sender", "extensionId", "channelNonce"])
      || !EXTENSION_ID_PATTERN.test(configuration.extensionId)
      || !shared.isId64(configuration.channelNonce)) {
      throw new Error("Background-owned browser context configuration is invalid.");
    }
    const { sender, extensionId, channelNonce } = configuration;
    if (!sender || typeof sender !== "object"
      || !sender.tab || typeof sender.tab !== "object"
      || !Number.isSafeInteger(sender.tab.id) || sender.tab.id < 0
      || sender.tab.incognito === true
      || sender.frameId !== 0
      || sender.documentLifecycle !== "active"
      || typeof sender.documentId !== "string"
      || !DOCUMENT_ID_PATTERN.test(sender.documentId)) {
      throw new Error("Content connection is not an active top-level document.");
    }
    if (typeof sender.url !== "string"
      || sender.url.length > MAX_SENDER_URL_LENGTH
      || !shared.isSupportedPageUrl(sender.url)) {
      throw new Error("Content connection page is not a supported origin.");
    }
    const { origin } = new URL(sender.url);
    // Chrome sets `sender.origin` for every content-script port since Chrome 80 (the manifest
    // requires 120), so a missing one is refused like a mismatch (security review S7).
    if (typeof sender.origin !== "string" || sender.origin !== origin) {
      throw new Error("Content connection origin does not match its URL.");
    }
    return Object.freeze({
      browserFamily: "chrome",
      extensionId,
      tabId: sender.tab.id,
      frameId: 0,
      documentId: sender.documentId,
      topOrigin: origin,
      frameOrigin: origin,
      documentLifecycle: "active",
      channelNonce
    });
  }

  Object.defineProperty(root, "__YOUR_WALLET_BACKGROUND_CORE__", {
    configurable: false,
    enumerable: false,
    writable: false,
    value: Object.freeze({
      BackgroundRouter,
      CONTENT_PORT_NAME,
      NATIVE_HOST_NAME,
      READ_DEADLINE_MS,
      INTERACTIVE_DEADLINE_MS,
      MAX_ACTIVE_DOCUMENTS,
      MAX_GLOBAL_PENDING,
      MAX_PENDING_PER_DOCUMENT,
      RATE_PER_SECOND,
      RATE_BURST,
      NATIVE_BACKOFF_BASE_MS,
      NATIVE_BACKOFF_MAX_MS,
      NATIVE_STATUSES,
      POPUP_PORT_NAME: shared.POPUP_PORT_NAME,
      deriveSenderContext,
      isPopupSender,
      popupStatusMessage
    })
  });
}(globalThis));
