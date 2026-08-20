(function installYourWalletProvider(root) {
  "use strict";

  if (root.top !== root || root.location.protocol !== "https:") {
    return;
  }

  const NAMESPACE = "your-wallet";
  const VERSION = 1;
  const MAX_MESSAGE_BYTES = 1_048_576;
  const MAX_REQUESTS = 4_096;
  const MAX_PENDING_REQUESTS = 256;
  const MAX_LISTENERS_PER_EVENT = 64;
  const REQUEST_TIMEOUT_MS = 125_000;
  const EIP6963_ANNOUNCE_EVENT = "eip6963:announceProvider";
  const EIP6963_REQUEST_EVENT = "eip6963:requestProvider";
  const PROVIDER_ICON = "data:image/png;base64,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";
  const targetOrigin = root.location.origin;
  const allowedMethods = new Set([
    "eth_requestAccounts",
    "eth_accounts",
    "eth_chainId",
    "net_version",
    "eth_sendTransaction",
    "personal_sign",
    "eth_signTypedData_v4",
    "wallet_addEthereumChain",
    "wallet_switchEthereumChain",
    "wallet_watchAsset",
    "wallet_requestPermissions",
    "wallet_getPermissions",
    "wallet_getCapabilities",
    "eth_blockNumber",
    "eth_call",
    "eth_estimateGas",
    "eth_feeHistory",
    "eth_gasPrice",
    "eth_getBalance",
    "eth_getBlockByHash",
    "eth_getBlockByNumber",
    "eth_getCode",
    "eth_getLogs",
    "eth_getStorageAt",
    "eth_getTransactionByHash",
    "eth_getTransactionCount",
    "eth_getTransactionReceipt",
    "eth_maxPriorityFeePerGas"
  ]);
  const allowedEvents = new Set(["accountsChanged", "chainChanged", "connect", "disconnect"]);
  const listeners = new Map();
  const pending = new Map();
  let requestCounter = 0;
  let channelNonce = null;
  let connected = false;
  let selectedAddress = null;
  let activeChainId = null;
  let resolveBridge;
  let rejectBridge;
  const bridgeReady = new Promise((resolve, reject) => {
    resolveBridge = resolve;
    rejectBridge = reject;
  });
  const bridgeTimer = root.setTimeout(() => {
    if (channelNonce === null) {
      rejectBridge(new ProviderRpcError(4900, "Wallet bridge did not become available."));
    }
  }, 10_000);

  class ProviderRpcError extends Error {
    constructor(code, message, data) {
      super(message);
      this.name = "ProviderRpcError";
      this.code = code;
      if (data !== undefined) {
        this.data = data;
      }
    }
  }

  const provider = Object.freeze({
    isYourWallet: true,
    isMetaMask: false,
    get chainId() {
      return activeChainId;
    },
    get selectedAddress() {
      return selectedAddress;
    },
    isConnected: () => connected,
    request,
    enable: () => request({ method: "eth_requestAccounts", params: [] }),
    on,
    removeListener
  });
  const providerInfo = Object.freeze({
    uuid: secureRandomUuid(),
    name: "Your Wallet",
    icon: PROVIDER_ICON,
    rdns: "com.yourwallet"
  });
  const providerDetail = Object.freeze({ info: providerInfo, provider });
  let announcingProvider = false;

  defineProvider("yourWallet", provider);
  defineProvider("ethereum", provider);
  root.addEventListener(EIP6963_REQUEST_EVENT, announceProvider);
  announceProvider();
  root.dispatchEvent(new Event("yourWallet#initialized"));
  root.addEventListener("message", receiveBridgeMessage);

  function announceProvider() {
    // A hostile listener can synchronously dispatch another request while an
    // announcement is being delivered. Suppress only that recursive cycle;
    // every later discovery request receives the same immutable page identity.
    if (announcingProvider) {
      return;
    }
    announcingProvider = true;
    try {
      root.dispatchEvent(new CustomEvent(EIP6963_ANNOUNCE_EVENT, {
        detail: providerDetail
      }));
    } finally {
      announcingProvider = false;
    }
  }

  async function request(args) {
    if (!isPlainObject(args)
      || !hasExactKeys(args, ["method"], ["params"])
      || typeof args.method !== "string"
      || !allowedMethods.has(args.method)) {
      throw new ProviderRpcError(4200, "Unsupported wallet method.");
    }
    const params = Object.prototype.hasOwnProperty.call(args, "params") ? args.params : [];
    if ((!Array.isArray(params) && !isPlainObject(params)) || !isJsonValue(params)) {
      throw new ProviderRpcError(-32602, "Wallet request parameters must be JSON object or array values.");
    }
    await bridgeReady;
    if (!connected || channelNonce === null) {
      throw new ProviderRpcError(4900, "Wallet bridge is disconnected.");
    }
    if (requestCounter >= MAX_REQUESTS) {
      throw new ProviderRpcError(-32005, "Request limit reached for this document.");
    }
    if (pending.size >= MAX_PENDING_REQUESTS) {
      throw new ProviderRpcError(-32005, "Too many wallet requests are pending.");
    }
    requestCounter += 1;
    let id = secureRandomHex(16);
    while (pending.has(id)) {
      id = secureRandomHex(16);
    }
    const envelope = {
      namespace: NAMESPACE,
      version: VERSION,
      channel: channelNonce,
      kind: "request",
      id,
      method: args.method,
      params
    };
    if (!fitsMessageLimit(envelope)) {
      throw new ProviderRpcError(-32600, "Request exceeds the wallet message limit.");
    }
    return new Promise((resolve, reject) => {
      const timer = root.setTimeout(() => {
        const entry = pending.get(id);
        if (!entry) {
          return;
        }
        pending.delete(id);
        entry.reject(new ProviderRpcError(-32000, "Wallet request timed out."));
      }, REQUEST_TIMEOUT_MS);
      pending.set(id, { method: args.method, resolve, reject, timer });
      try {
        root.postMessage(envelope, targetOrigin);
      } catch (_error) {
        root.clearTimeout(timer);
        pending.delete(id);
        reject(new ProviderRpcError(4900, "Wallet bridge could not send the request."));
      }
    });
  }

  function on(eventName, listener) {
    if (!allowedEvents.has(eventName) || typeof listener !== "function") {
      throw new TypeError("Unsupported provider event or listener.");
    }
    const eventListeners = listeners.get(eventName) || new Set();
    if (!eventListeners.has(listener) && eventListeners.size >= MAX_LISTENERS_PER_EVENT) {
      throw new TypeError("Wallet provider listener limit reached.");
    }
    eventListeners.add(listener);
    listeners.set(eventName, eventListeners);
    return provider;
  }

  function removeListener(eventName, listener) {
    const eventListeners = listeners.get(eventName);
    if (eventListeners) {
      eventListeners.delete(listener);
      if (eventListeners.size === 0) {
        listeners.delete(eventName);
      }
    }
    return provider;
  }

  function emit(eventName, payload) {
    const eventListeners = listeners.get(eventName);
    if (!eventListeners) {
      return;
    }
    for (const listener of [...eventListeners]) {
      try {
        listener(payload);
      } catch (_error) {
        // A dApp listener must not interrupt provider message processing.
      }
    }
  }

  function receiveBridgeMessage(event) {
    if (event.source !== root
      || event.origin !== targetOrigin
      || !isPlainObject(event.data)
      || !fitsMessageLimit(event.data)) {
      return;
    }
    const message = event.data;
    if (message.kind === "bridge-init") {
      if (!hasExactKeys(message, ["namespace", "version", "channel", "kind"])
        || message.namespace !== NAMESPACE
        || message.version !== VERSION
        || !validNonce(message.channel)
        || channelNonce !== null) {
        return;
      }
      channelNonce = message.channel;
      connected = true;
      root.clearTimeout(bridgeTimer);
      resolveBridge();
      return;
    }
    if (message.namespace !== NAMESPACE
      || message.version !== VERSION
      || message.channel !== channelNonce
      || channelNonce === null) {
      return;
    }
    if (message.kind === "response") {
      receiveResponse(message);
      return;
    }
    if (message.kind === "event") {
      receiveEvent(message);
      return;
    }
    if (message.kind === "disconnect") {
      receiveDisconnect(message);
    }
  }

  function receiveResponse(message) {
    const resultShape = hasExactKeys(message, [
      "namespace", "version", "channel", "kind", "id", "result"
    ]);
    const errorShape = hasExactKeys(message, [
      "namespace", "version", "channel", "kind", "id", "error"
    ]);
    const entry = typeof message.id === "string" ? pending.get(message.id) : null;
    if ((!resultShape && !errorShape) || !entry) {
      return;
    }
    if ((resultShape && !isJsonValue(message.result)) || (errorShape && !validRpcError(message.error))) {
      return;
    }
    pending.delete(message.id);
    root.clearTimeout(entry.timer);
    if (resultShape) {
      updateProviderView(entry.method, message.result);
      entry.resolve(message.result);
    } else {
      entry.reject(toProviderError(message.error));
    }
  }

  function receiveEvent(message) {
    if (!hasExactKeys(message, [
      "namespace", "version", "channel", "kind", "event", "payload"
    ]) || !allowedEvents.has(message.event) || !isJsonValue(message.payload)) {
      return;
    }
    if (message.event === "accountsChanged") {
      selectedAddress = Array.isArray(message.payload) && typeof message.payload[0] === "string"
        ? message.payload[0]
        : null;
    } else if (message.event === "chainChanged" && typeof message.payload === "string") {
      activeChainId = message.payload;
    } else if (message.event === "connect"
      && isPlainObject(message.payload)
      && typeof message.payload.chainId === "string") {
      connected = true;
      activeChainId = message.payload.chainId;
    } else if (message.event === "disconnect") {
      connected = false;
    }
    emit(message.event, message.payload);
  }

  function receiveDisconnect(message) {
    if (!hasExactKeys(message, ["namespace", "version", "channel", "kind", "error"])
      || !validRpcError(message.error)) {
      return;
    }
    connected = false;
    const providerError = toProviderError(message.error);
    for (const entry of pending.values()) {
      root.clearTimeout(entry.timer);
      entry.reject(providerError);
    }
    pending.clear();
    emit("disconnect", providerError);
  }

  function updateProviderView(method, result) {
    if ((method === "eth_accounts" || method === "eth_requestAccounts") && Array.isArray(result)) {
      selectedAddress = typeof result[0] === "string" ? result[0] : null;
    } else if (method === "eth_chainId" && typeof result === "string") {
      activeChainId = result;
    }
  }

  function defineProvider(name, value) {
    if (name in root) {
      return false;
    }
    try {
      Object.defineProperty(root, name, {
        configurable: false,
        enumerable: false,
        writable: false,
        value
      });
      return true;
    } catch (_error) {
      // A page may reserve a non-configurable global before document_start.
      // EIP-6963 discovery remains usable without replacing that property.
      return false;
    }
  }

  function toProviderError(error) {
    return new ProviderRpcError(error.code, error.message, error.data);
  }

  function validRpcError(value) {
    return hasExactKeys(value, ["code", "message"], ["data"])
      && Number.isInteger(value.code)
      && typeof value.message === "string"
      && value.message.length <= 512
      && (!Object.prototype.hasOwnProperty.call(value, "data") || isJsonValue(value.data));
  }

  function isPlainObject(value) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
      return false;
    }
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
  }

  function hasExactKeys(value, required, optional = []) {
    if (!isPlainObject(value)) {
      return false;
    }
    const keys = Object.keys(value);
    const allowed = new Set([...required, ...optional]);
    return keys.length >= required.length
      && keys.length <= required.length + optional.length
      && required.every((key) => Object.prototype.hasOwnProperty.call(value, key))
      && keys.every((key) => allowed.has(key));
  }

  function isJsonValue(value, depth = 0) {
    if (depth > 64) {
      return false;
    }
    if (value === null || typeof value === "string" || typeof value === "boolean") {
      return true;
    }
    if (typeof value === "number") {
      return Number.isFinite(value);
    }
    if (Array.isArray(value)) {
      return value.length <= 10_000 && value.every((entry) => isJsonValue(entry, depth + 1));
    }
    return isPlainObject(value)
      && Object.keys(value).length <= 10_000
      && Object.values(value).every((entry) => isJsonValue(entry, depth + 1));
  }

  function fitsMessageLimit(value) {
    try {
      return new TextEncoder().encode(JSON.stringify(value)).byteLength <= MAX_MESSAGE_BYTES;
    } catch (_error) {
      return false;
    }
  }

  function validNonce(value) {
    return typeof value === "string" && /^[0-9a-f]{64}$/u.test(value);
  }

  function secureRandomHex(byteLength) {
    const bytes = new Uint8Array(byteLength);
    root.crypto.getRandomValues(bytes);
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  }

  function secureRandomUuid() {
    const bytes = new Uint8Array(16);
    root.crypto.getRandomValues(bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const hexadecimal = Array.from(
      bytes,
      (byte) => byte.toString(16).padStart(2, "0")
    ).join("");
    return `${hexadecimal.slice(0, 8)}-${hexadecimal.slice(8, 12)}-${hexadecimal.slice(12, 16)}-${hexadecimal.slice(16, 20)}-${hexadecimal.slice(20)}`;
  }
}(globalThis));
