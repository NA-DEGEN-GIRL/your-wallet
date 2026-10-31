(function installYourWalletContentCore(root) {
  "use strict";

  if (Object.prototype.hasOwnProperty.call(root, "__YOUR_WALLET_CONTENT_CORE__")) {
    return;
  }

  const shared = root.__YOUR_WALLET_SHARED__;
  if (!shared) {
    throw new Error("Your Wallet shared module was not loaded.");
  }

  const MAX_PENDING = 64;
  const CONNECT_TIMEOUT_MS = 5_000;
  const MIN_RECONNECT_INTERVAL_MS = 250;
  // Upper bound for the document_start `chrome.storage.local` read of the compatibility mode
  // (spec/05 §2.12). A read that fails or takes longer falls back to `off`.
  const MODE_READ_TIMEOUT_MS = 3_000;
  const STATES = Object.freeze({
    IDLE: "IDLE",
    CONNECTING: "CONNECTING",
    ACTIVE: "ACTIVE",
    DEAD: "DEAD"
  });

  // spec/05 §2.7. The bridge never touches Chrome APIs directly; content.js supplies adapters.
  class ContentBridge {
    constructor({
      channelNonce, compatMode = "off", solCompatMode = "off", btcCompatMode = "off",
      connectPort, postToPage, isContextValid, setTimer, clearTimer, now
    }) {
      if (!shared.isId64(channelNonce)) {
        throw new TypeError("Invalid page channel nonce.");
      }
      if (!shared.isCompatMode(compatMode)
        || shared.normalizeSolCompatMode(solCompatMode) !== solCompatMode
        || shared.normalizeBtcCompatMode(btcCompatMode) !== btcCompatMode) {
        throw new TypeError("Invalid compatibility mode.");
      }
      for (const adapter of [connectPort, postToPage, isContextValid, setTimer, clearTimer, now]) {
        if (typeof adapter !== "function") {
          throw new TypeError("Content bridge adapters are required.");
        }
      }
      this.channelNonce = channelNonce;
      // Fixed for the document's lifetime: a mode change applies on the next page load.
      this.compatMode = compatMode;
      this.solCompatMode = solCompatMode;
      this.btcCompatMode = btcCompatMode;
      this.connectPort = connectPort;
      this.postToPage = postToPage;
      this.isContextValid = isContextValid;
      this.setTimer = setTimer;
      this.clearTimer = clearTimer;
      this.now = now;
      this.state = STATES.IDLE;
      this.port = null;
      this.portGeneration = 0;
      this.activationNonce = null;
      // id -> { id, method, params, sent }. Queued (not yet sent) entries are also listed in `queue`.
      this.pending = new Map();
      this.queue = [];
      this.connectTimer = null;
      this.delayTimer = null;
      this.lastConnectAt = null;
    }

    announce() {
      this.post({
        kind: "bridge-init",
        compatMode: this.compatMode,
        solCompatMode: this.solCompatMode,
        btcCompatMode: this.btcCompatMode
      });
    }

    receivePage(value) {
      const message = shared.parsePageMessage(value, this.channelNonce);
      if (message === null) {
        return false;
      }
      if (message.kind === "bridge-request") {
        this.announce();
        return true;
      }
      if (message.kind === "cancel") {
        return this.cancelFromPage(message.id);
      }
      return this.requestFromPage(value, message);
    }

    requestFromPage(raw, request) {
      if (this.pending.has(request.id)) {
        return false;
      }
      // Bitcoin off (spec/05 §2.13): no Bitcoin provider is registered, so btc_* never reaches the
      // wallet from this page. Solana off still registers the "Your Wallet" Wallet Standard
      // wallet, so sol_* stays allowed.
      if (shared.methodRoute(request.method) === null
        || (this.btcCompatMode === "off" && shared.methodFamily(request.method) === "btc")) {
        this.respond(request.id, { error: shared.ERRORS.UNSUPPORTED_METHOD });
        return false;
      }
      if (!shared.checkJson(raw, shared.REQUEST_LIMITS)) {
        this.respond(request.id, { error: shared.ERRORS.REQUEST_TOO_LARGE });
        return false;
      }
      if (this.pending.size >= MAX_PENDING) {
        this.respond(request.id, { error: shared.ERRORS.TOO_MANY_PENDING });
        return false;
      }
      if (this.state === STATES.IDLE && !this.contextValid()) {
        this.enterDead();
      }
      if (this.state === STATES.DEAD) {
        this.respond(request.id, { error: shared.ERRORS.EXTENSION_RELOADED });
        return false;
      }
      const entry = { id: request.id, method: request.method, params: request.params, sent: false };
      this.pending.set(entry.id, entry);
      if (this.state === STATES.ACTIVE) {
        this.sendRequest(entry);
        return true;
      }
      this.queue.push(entry);
      if (this.state === STATES.IDLE) {
        this.beginConnect();
      }
      return true;
    }

    cancelFromPage(id) {
      const entry = this.pending.get(id);
      if (!entry || (this.state !== STATES.CONNECTING && this.state !== STATES.ACTIVE)) {
        return false;
      }
      this.pending.delete(id);
      if (!entry.sent) {
        this.queue = this.queue.filter((queued) => queued !== entry);
        return true;
      }
      this.sendToPort({
        namespace: shared.NAMESPACE,
        version: shared.PROTOCOL_VERSION,
        kind: "cancel",
        activationNonce: this.activationNonce,
        id,
        reason: "page-cancel"
      });
      return true;
    }

    beginConnect() {
      this.state = STATES.CONNECTING;
      const elapsed = this.lastConnectAt === null ? Infinity : this.now() - this.lastConnectAt;
      if (elapsed < MIN_RECONNECT_INTERVAL_MS) {
        const generation = this.portGeneration;
        this.delayTimer = this.setTimer(() => {
          this.delayTimer = null;
          if (this.state === STATES.CONNECTING && this.portGeneration === generation && this.port === null) {
            this.openPort();
          }
        }, MIN_RECONNECT_INTERVAL_MS - elapsed);
        return;
      }
      this.openPort();
    }

    openPort() {
      this.lastConnectAt = this.now();
      this.portGeneration += 1;
      const generation = this.portGeneration;
      let port;
      try {
        port = this.connectPort();
      } catch (_error) {
        this.enterDead();
        return;
      }
      this.port = port;
      try {
        port.onMessage((message) => {
          if (this.portGeneration === generation && this.port === port) {
            this.receiveBackground(message);
          }
        });
        port.onDisconnect(() => {
          if (this.portGeneration === generation && this.port === port) {
            this.portClosed();
          }
        });
      } catch (_error) {
        this.enterDead();
        return;
      }
      this.connectTimer = this.setTimer(() => {
        this.connectTimer = null;
        if (this.state === STATES.CONNECTING && this.portGeneration === generation) {
          this.closePort();
          this.failAll(shared.ERRORS.CONNECTION_CLOSED);
          this.state = STATES.IDLE;
        }
      }, CONNECT_TIMEOUT_MS);
    }

    receiveBackground(value) {
      const message = shared.parseBackgroundMessage(value);
      if (message === null) {
        return false;
      }
      if (this.state === STATES.CONNECTING) {
        if (message.kind !== "activated") {
          return false;
        }
        this.activationNonce = message.activationNonce;
        this.state = STATES.ACTIVE;
        this.cancelTimer("connectTimer");
        const queued = this.queue;
        this.queue = [];
        for (const entry of queued) {
          if (this.state !== STATES.ACTIVE) {
            break;
          }
          this.sendRequest(entry);
        }
        return true;
      }
      if (this.state !== STATES.ACTIVE || message.activationNonce !== this.activationNonce) {
        return false;
      }
      if (message.kind === "response") {
        if (!this.pending.has(message.id) || !this.pending.get(message.id).sent) {
          return false;
        }
        this.pending.delete(message.id);
        const body = shared.checkJson(value, shared.RESPONSE_LIMITS)
          ? message.body
          : { error: shared.ERRORS.RESPONSE_TOO_LARGE };
        this.respond(message.id, body);
        return true;
      }
      if (message.kind === "event") {
        if (!shared.checkJson(value, shared.RESPONSE_LIMITS)) {
          return false;
        }
        this.post({ kind: "event", event: message.event, payload: message.payload });
        return true;
      }
      return false;
    }

    // pagehide / freeze: close the activation but stay reusable (bfcache restore reconnects).
    closeForDocument(reason) {
      if (this.state !== STATES.CONNECTING && this.state !== STATES.ACTIVE) {
        return false;
      }
      if (this.state === STATES.ACTIVE && shared.isReason(reason)) {
        this.sendToPort({
          namespace: shared.NAMESPACE,
          version: shared.PROTOCOL_VERSION,
          kind: "disconnect",
          activationNonce: this.activationNonce,
          reason
        });
      }
      this.closePort();
      this.failAll(shared.ERRORS.CONNECTION_CLOSED);
      this.state = STATES.IDLE;
      return true;
    }

    portClosed() {
      this.port = null;
      this.portGeneration += 1;
      this.activationNonce = null;
      this.cancelTimer("connectTimer");
      this.cancelTimer("delayTimer");
      if (!this.contextValid()) {
        this.enterDead();
        return;
      }
      this.failAll(shared.ERRORS.CONNECTION_CLOSED);
      this.state = STATES.IDLE;
    }

    enterDead() {
      if (this.state === STATES.DEAD) {
        return;
      }
      this.closePort();
      this.state = STATES.DEAD;
      this.failAll(shared.ERRORS.EXTENSION_RELOADED);
      this.post({ kind: "disconnect", error: shared.ERRORS.EXTENSION_RELOADED });
    }

    // The mode of the request's family (spec/05 §2.12–§2.13), `off` = no `compatMode` key.
    modeFor(method) {
      const family = shared.methodFamily(method);
      if (family === "sol") return this.solCompatMode;
      if (family === "btc") return this.btcCompatMode;
      return this.compatMode;
    }

    sendRequest(entry) {
      entry.sent = true;
      const mode = this.modeFor(entry.method);
      this.sendToPort({
        namespace: shared.NAMESPACE,
        version: shared.PROTOCOL_VERSION,
        kind: "request",
        activationNonce: this.activationNonce,
        id: entry.id,
        method: entry.method,
        params: entry.params,
        // Display-only note for the yw-app windows (spec/05 §2.12); omitted in the default mode.
        ...(mode === "off" ? {} : { compatMode: mode })
      });
    }

    sendToPort(message) {
      const port = this.port;
      if (port === null) {
        return false;
      }
      try {
        port.postMessage(message);
        return true;
      } catch (_error) {
        if (this.port === port) {
          this.portClosed();
        }
        return false;
      }
    }

    closePort() {
      const port = this.port;
      this.port = null;
      this.portGeneration += 1;
      this.activationNonce = null;
      this.cancelTimer("connectTimer");
      this.cancelTimer("delayTimer");
      if (port !== null) {
        try {
          port.disconnect();
        } catch (_error) {
          // The worker side may already be gone.
        }
      }
    }

    failAll(error) {
      const entries = [...this.pending.values()];
      this.pending.clear();
      this.queue = [];
      for (const entry of entries) {
        this.respond(entry.id, { error });
      }
    }

    respond(id, body) {
      this.post({ kind: "response", id, ...body });
    }

    post(fields) {
      const { kind, ...rest } = fields;
      try {
        this.postToPage({
          namespace: shared.NAMESPACE,
          version: shared.PROTOCOL_VERSION,
          kind,
          channel: this.channelNonce,
          ...rest
        });
      } catch (_error) {
        // The page may be tearing down; nothing else to notify.
      }
    }

    contextValid() {
      try {
        return this.isContextValid() === true;
      } catch (_error) {
        return false;
      }
    }

    cancelTimer(name) {
      if (this[name] !== null) {
        this.clearTimer(this[name]);
        this[name] = null;
      }
    }
  }

  // spec/05 §2.12: reads the stored mode once at document_start. Resolves (never rejects) with a
  // valid mode; a missing or corrupted value, a throwing or rejecting read, or a read slower than
  // MODE_READ_TIMEOUT_MS yields `off`. `readStorage()` returns `chrome.storage.local.get(key)`.
  function loadCompatMode({ readStorage, setTimer, clearTimer, timeoutMs = MODE_READ_TIMEOUT_MS }) {
    return new Promise((resolve) => {
      let settled = false;
      let timer = null;
      const finish = (mode) => {
        if (settled) {
          return;
        }
        settled = true;
        if (timer !== null) {
          clearTimer(timer);
        }
        resolve(mode);
      };
      timer = setTimer(() => {
        timer = null;
        finish("off");
      }, timeoutMs);
      try {
        Promise.resolve(readStorage()).then((stored) => {
          const key = shared.COMPAT_MODE_STORAGE_KEY;
          const value = stored !== null && typeof stored === "object" && Object.prototype.hasOwnProperty.call(stored, key)
            ? stored[key]
            : undefined;
          finish(shared.normalizeCompatMode(value));
        }, () => finish("off"));
      } catch (_error) {
        // Extension context invalidated: the bridge will enter DEAD on the first request anyway.
        finish("off");
      }
    });
  }

  // All three modes at once (spec/05 §2.13): `{ evm, sol, btc }`, each normalized; a failing or
  // slow read gives `off` for all. `readStorage()` returns `chrome.storage.local.get([keys])`.
  function loadCompatModes({ readStorage, setTimer, clearTimer, timeoutMs = MODE_READ_TIMEOUT_MS }) {
    const fallback = Object.freeze({ evm: "off", sol: "off", btc: "off" });
    return new Promise((resolve) => {
      let settled = false;
      let timer = null;
      const finish = (modes) => {
        if (settled) {
          return;
        }
        settled = true;
        if (timer !== null) {
          clearTimer(timer);
        }
        resolve(modes);
      };
      timer = setTimer(() => {
        timer = null;
        finish(fallback);
      }, timeoutMs);
      const read = (stored, key) => (stored !== null && typeof stored === "object"
        && Object.prototype.hasOwnProperty.call(stored, key) ? stored[key] : undefined);
      try {
        Promise.resolve(readStorage()).then((stored) => {
          finish(Object.freeze({
            evm: shared.normalizeCompatMode(read(stored, shared.COMPAT_MODE_STORAGE_KEY)),
            sol: shared.normalizeSolCompatMode(read(stored, shared.SOL_COMPAT_MODE_STORAGE_KEY)),
            btc: shared.normalizeBtcCompatMode(read(stored, shared.BTC_COMPAT_MODE_STORAGE_KEY))
          }));
        }, () => finish(fallback));
      } catch (_error) {
        finish(fallback);
      }
    });
  }

  Object.defineProperty(root, "__YOUR_WALLET_CONTENT_CORE__", {
    configurable: false,
    enumerable: false,
    writable: false,
    value: Object.freeze({
      ContentBridge,
      STATES,
      MAX_PENDING,
      CONNECT_TIMEOUT_MS,
      MIN_RECONNECT_INTERVAL_MS,
      MODE_READ_TIMEOUT_MS,
      loadCompatMode,
      loadCompatModes
    })
  });
}(globalThis));
