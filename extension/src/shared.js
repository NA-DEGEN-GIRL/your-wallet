(function installYourWalletShared(root) {
  "use strict";

  if (Object.prototype.hasOwnProperty.call(root, "__YOUR_WALLET_SHARED__")) {
    return;
  }

  const NAMESPACE = "your-wallet";
  const PROTOCOL_VERSION = 1;
  const CONTENT_PORT_NAME = "your-wallet-content-v1";
  const POPUP_PORT_NAME = "your-wallet-popup-v1";
  // spec/05 §2.12 compatibility mode: `chrome.storage.local` key and values. `off` is the default
  // and is never sent on the wire (absence means off).
  const COMPAT_MODE_STORAGE_KEY = "compatMode";
  const COMPAT_MODES = Object.freeze(["off", "metamask", "rabby"]);
  // Solana and Bitcoin compatibility modes (spec/05 §2.13), stored under their own keys. Solana
  // `off` still registers the Wallet Standard "Your Wallet (Solana)"; Bitcoin `off` exposes nothing.
  const SOL_COMPAT_MODE_STORAGE_KEY = "solCompatMode";
  const SOL_COMPAT_MODES = Object.freeze(["off", "phantom"]);
  const BTC_COMPAT_MODE_STORAGE_KEY = "btcCompatMode";
  const BTC_COMPAT_MODES = Object.freeze(["off", "unisat", "xverse"]);
  // Every non-off mode a content→background request may carry, by method family.
  const WIRE_COMPAT_MODES = Object.freeze({
    evm: Object.freeze(["metamask", "rabby"]),
    sol: Object.freeze(["phantom"]),
    btc: Object.freeze(["unisat", "xverse"])
  });
  const MAX_EVENT_SOL_ACCOUNTS = 1;
  const MAX_EVENT_BTC_ADDRESSES = 2;
  const MAX_EVENT_ACCOUNTS = 16;
  const MAX_ERROR_MESSAGE_LENGTH = 512;

  // JSON limits shared with yw-json (spec/05 §2.9). Counting rules must match Rust exactly.
  const REQUEST_LIMITS = Object.freeze({
    maxBytes: 1_048_576,
    maxDepth: 32,
    maxNodes: 8_192,
    maxItems: 4_096
  });
  const RESPONSE_LIMITS = Object.freeze({
    maxBytes: 1_048_576,
    maxDepth: 32,
    maxNodes: 262_144,
    maxItems: 262_144
  });

  // The single JS method table (spec/05 §3.1, order = v1-methods.golden.json).
  const METHOD_ROUTE = Object.freeze(Object.assign(Object.create(null), {
    eth_requestAccounts: "permission",
    eth_accounts: "permission",
    eth_chainId: "permission",
    net_version: "permission",
    wallet_switchEthereumChain: "permission",
    wallet_requestPermissions: "permission",
    wallet_getPermissions: "permission",
    wallet_revokePermissions: "permission",
    web3_clientVersion: "permission",
    // Solana and Bitcoin: connect and message signing only (spec/05 §3.6). No transaction or
    // PSBT method exists on the wire; the page shims reject those locally with 4200.
    sol_connect: "permission",
    sol_disconnect: "permission",
    sol_accounts: "permission",
    btc_requestAccounts: "permission",
    btc_getAccounts: "permission",
    btc_disconnect: "permission",
    btc_getNetwork: "permission",
    eth_blockNumber: "read",
    eth_call: "read",
    eth_estimateGas: "read",
    eth_feeHistory: "read",
    eth_gasPrice: "read",
    eth_maxPriorityFeePerGas: "read",
    eth_getBalance: "read",
    eth_getBlockByHash: "read",
    eth_getBlockByNumber: "read",
    eth_getCode: "read",
    eth_getLogs: "read",
    eth_getStorageAt: "read",
    eth_getTransactionByHash: "read",
    eth_getTransactionCount: "read",
    eth_getTransactionReceipt: "read",
    eth_sendTransaction: "signing",
    personal_sign: "signing",
    eth_signTypedData_v4: "signing",
    sol_signMessage: "signing",
    sol_signIn: "signing",
    btc_signMessage: "signing"
  }));

  const EVENTS = Object.freeze(["accountsChanged", "chainChanged", "solAccountsChanged", "btcAccountsChanged"]);

  // spec/05 §4.7 (yw-core `BrowserOrigin::parse`).
  const MAX_ORIGIN_LENGTH = 256;
  const MAX_HOST_LENGTH = 253;
  const HOST_LABEL_PATTERN = /^[a-z0-9_-]{1,63}$/u;
  const ID64_PATTERN = /^[0-9a-f]{64}$/u;
  const ID32_PATTERN = /^[0-9a-f]{32}$/u;
  const ALL_ZERO_PATTERN = /^0+$/u;
  const METHOD_PATTERN = /^[A-Za-z0-9_]{1,96}$/u;
  const REASON_PATTERN = /^[A-Za-z0-9_-]{1,128}$/u;
  const ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/u;
  const CHAIN_ID_PATTERN = /^0x[1-9a-f][0-9a-f]*$/u;
  const SOL_KEY_PATTERN = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/u;
  const BTC_ADDRESS_PATTERN = /^[A-Za-z0-9]{14,90}$/u;

  const hasOwn = (value, key) => Object.prototype.hasOwnProperty.call(value, key);

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
    if (keys.length < required.length || keys.length > required.length + optional.length) {
      return false;
    }
    const allowed = new Set([...required, ...optional]);
    return required.every((key) => hasOwn(value, key)) && keys.every((key) => allowed.has(key));
  }

  // spec/05 §2.9 — must stay identical to yw-json's counting.
  function checkJson(value, limits) {
    let nodes = 0;
    let items = 0;
    const walk = (v, depth) => {
      if (++nodes > limits.maxNodes) return false;
      if (v === null || typeof v === "boolean") return true;
      if (typeof v === "number") return Number.isFinite(v);
      if (typeof v === "string") return v.isWellFormed();
      if (depth + 1 > limits.maxDepth) return false;
      if (Array.isArray(v)) {
        for (const e of v) if (++items > limits.maxItems || !walk(e, depth + 1)) return false;
        return true;
      }
      if (!isPlainObject(v)) return false;
      for (const k of Object.keys(v)) {
        if (++items > limits.maxItems || ++nodes > limits.maxNodes || !k.isWellFormed()
          || !walk(v[k], depth + 1)) return false;
      }
      return true;
    };
    if (!walk(value, 0)) return false;
    let text;
    try { text = JSON.stringify(value); } catch { return false; }
    return typeof text === "string" && new TextEncoder().encode(text).byteLength <= limits.maxBytes;
  }

  // spec/05 §2.4: https, or http with hostname exactly localhost / 127.0.0.1 (any port), and the
  // serialized origin must pass yw-core `BrowserOrigin::parse` (§4.7): DNS-style labels of
  // [a-z0-9_-]{1,63} (no trailing dot, no empty label), host ≤ 253 bytes, origin ≤ 256 bytes, no
  // port 0. Same rule in provider-main.js (copy); vectors in native-host/v1-origins.golden.json.
  function isSupportedPageUrl(value) {
    let url;
    try {
      url = new URL(String(value));
    } catch (_error) {
      return false;
    }
    if (url.username !== "" || url.password !== "" || url.origin === "null"
      || url.hostname === "" || url.hostname.startsWith("[")
      || url.port === "0" || url.origin.length > MAX_ORIGIN_LENGTH) {
      return false;
    }
    if (url.protocol === "https:") {
      return url.hostname.length <= MAX_HOST_LENGTH
        && url.hostname.split(".").every((label) => HOST_LABEL_PATTERN.test(label));
    }
    return url.protocol === "http:" && (url.hostname === "localhost" || url.hostname === "127.0.0.1");
  }

  function methodRoute(method) {
    if (typeof method !== "string" || !METHOD_PATTERN.test(method) || !hasOwn(METHOD_ROUTE, method)) {
      return null;
    }
    return METHOD_ROUTE[method];
  }

  function isId64(value) {
    return typeof value === "string" && ID64_PATTERN.test(value) && !ALL_ZERO_PATTERN.test(value);
  }

  function isId32(value) {
    return typeof value === "string" && ID32_PATTERN.test(value) && !ALL_ZERO_PATTERN.test(value);
  }

  function isReason(value) {
    return typeof value === "string" && REASON_PATTERN.test(value);
  }

  function isParams(value) {
    return Array.isArray(value) || isPlainObject(value);
  }

  function isCompatMode(value) {
    return typeof value === "string" && COMPAT_MODES.includes(value);
  }

  // Anything that is not one of the three stored values (missing, corrupted) is the default.
  function normalizeCompatMode(value) {
    return isCompatMode(value) ? value : "off";
  }

  function normalizeSolCompatMode(value) {
    return typeof value === "string" && SOL_COMPAT_MODES.includes(value) ? value : "off";
  }

  function normalizeBtcCompatMode(value) {
    return typeof value === "string" && BTC_COMPAT_MODES.includes(value) ? value : "off";
  }

  // `sol` for sol_*, `btc` for btc_*, `evm` for everything else.
  function methodFamily(method) {
    if (typeof method === "string" && method.startsWith("sol_")) return "sol";
    if (typeof method === "string" && method.startsWith("btc_")) return "btc";
    return "evm";
  }

  function isWireCompatMode(value) {
    return typeof value === "string" && Object.values(WIRE_COMPAT_MODES).some((modes) => modes.includes(value));
  }

  // `{ code, message, data? }`, exact keys. `data` is checked by the enclosing checkJson.
  function validRpcError(value) {
    return hasExactKeys(value, ["code", "message"], ["data"])
      && Number.isSafeInteger(value.code)
      && typeof value.message === "string"
      && value.message.length >= 1
      && value.message.length <= MAX_ERROR_MESSAGE_LENGTH;
  }

  function validEvent(event, payload) {
    if (event === "accountsChanged") {
      return Array.isArray(payload)
        && payload.length <= MAX_EVENT_ACCOUNTS
        && payload.every((account) => typeof account === "string" && ADDRESS_PATTERN.test(account));
    }
    if (event === "chainChanged") {
      return typeof payload === "string" && CHAIN_ID_PATTERN.test(payload);
    }
    if (event === "solAccountsChanged") {
      return Array.isArray(payload)
        && payload.length <= MAX_EVENT_SOL_ACCOUNTS
        && payload.every((key) => typeof key === "string" && SOL_KEY_PATTERN.test(key));
    }
    if (event === "btcAccountsChanged") {
      return Array.isArray(payload)
        && payload.length <= MAX_EVENT_BTC_ADDRESSES
        && payload.every((address) => typeof address === "string" && BTC_ADDRESS_PATTERN.test(address));
    }
    return false;
  }

  function hasEnvelope(value) {
    return isPlainObject(value) && value.namespace === NAMESPACE && value.version === PROTOCOL_VERSION;
  }

  // page → content (spec/05 §2.6). Returns null for anything that is not an exact page message.
  function parsePageMessage(value, expectedChannel) {
    if (!hasEnvelope(value)) {
      return null;
    }
    if (value.kind === "bridge-request") {
      return hasExactKeys(value, ["namespace", "version", "kind"]) ? Object.freeze({ kind: "bridge-request" }) : null;
    }
    if (value.kind === "request") {
      if (!hasExactKeys(value, ["namespace", "version", "kind", "channel", "id", "method", "params"])
        || value.channel !== expectedChannel
        || !isId32(value.id)
        || typeof value.method !== "string"
        || !isParams(value.params)) {
        return null;
      }
      return Object.freeze({ kind: "request", id: value.id, method: value.method, params: value.params });
    }
    if (value.kind === "cancel") {
      if (!hasExactKeys(value, ["namespace", "version", "kind", "channel", "id"])
        || value.channel !== expectedChannel
        || !isId32(value.id)) {
        return null;
      }
      return Object.freeze({ kind: "cancel", id: value.id });
    }
    return null;
  }

  // content → background (spec/05 §2.6).
  function parseContentMessage(value, expectedActivationNonce) {
    if (!hasEnvelope(value) || value.activationNonce !== expectedActivationNonce) {
      return null;
    }
    if (value.kind === "request") {
      // `compatMode` is present only in a compatibility mode of the method's family
      // (spec/05 §2.12–§2.13).
      if (!hasExactKeys(value, ["namespace", "version", "kind", "activationNonce", "id", "method", "params"], ["compatMode"])
        || !isId32(value.id)
        || typeof value.method !== "string"
        || !isParams(value.params)
        || (hasOwn(value, "compatMode") && !WIRE_COMPAT_MODES[methodFamily(value.method)].includes(value.compatMode))) {
        return null;
      }
      return Object.freeze({
        kind: "request",
        id: value.id,
        method: value.method,
        params: value.params,
        compatMode: hasOwn(value, "compatMode") ? value.compatMode : "off"
      });
    }
    if (value.kind === "cancel") {
      if (!hasExactKeys(value, ["namespace", "version", "kind", "activationNonce", "id", "reason"])
        || !isId32(value.id)
        || !isReason(value.reason)) {
        return null;
      }
      return Object.freeze({ kind: "cancel", id: value.id, reason: value.reason });
    }
    if (value.kind === "disconnect") {
      if (!hasExactKeys(value, ["namespace", "version", "kind", "activationNonce", "reason"])
        || !isReason(value.reason)) {
        return null;
      }
      return Object.freeze({ kind: "disconnect", reason: value.reason });
    }
    return null;
  }

  // background → content (spec/05 §2.6). Deep JSON limits are checked separately by the caller.
  function parseBackgroundMessage(value) {
    if (!hasEnvelope(value) || !isId64(value.activationNonce)) {
      return null;
    }
    if (value.kind === "activated") {
      return hasExactKeys(value, ["namespace", "version", "kind", "activationNonce"])
        ? Object.freeze({ kind: "activated", activationNonce: value.activationNonce })
        : null;
    }
    if (value.kind === "response") {
      const base = ["namespace", "version", "kind", "activationNonce", "id"];
      if (hasExactKeys(value, [...base, "result"]) && isId32(value.id)) {
        return Object.freeze({ kind: "response", activationNonce: value.activationNonce, id: value.id, body: { result: value.result } });
      }
      if (hasExactKeys(value, [...base, "error"]) && isId32(value.id) && validRpcError(value.error)) {
        return Object.freeze({ kind: "response", activationNonce: value.activationNonce, id: value.id, body: { error: value.error } });
      }
      return null;
    }
    if (value.kind === "event") {
      if (!hasExactKeys(value, ["namespace", "version", "kind", "activationNonce", "event", "payload"])
        || !validEvent(value.event, value.payload)) {
        return null;
      }
      return Object.freeze({ kind: "event", activationNonce: value.activationNonce, event: value.event, payload: value.payload });
    }
    return null;
  }

  function rpcError(code, message) {
    return { code, message };
  }

  function randomHex(byteLength, cryptoObject = root.crypto) {
    if (!cryptoObject || typeof cryptoObject.getRandomValues !== "function") {
      throw new Error("A cryptographically secure random source is required.");
    }
    const bytes = new Uint8Array(byteLength);
    cryptoObject.getRandomValues(bytes);
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  }

  // Exact provider error strings (spec/05 §5).
  const ERRORS = Object.freeze({
    UNSUPPORTED_METHOD: Object.freeze(rpcError(4200, "Unsupported method.")),
    UNAVAILABLE: Object.freeze(rpcError(4900, "Wallet is unavailable.")),
    CONNECTION_CLOSED: Object.freeze(rpcError(4900, "Wallet connection closed.")),
    EXTENSION_RELOADED: Object.freeze(rpcError(4900, "Wallet extension was reloaded.")),
    RATE_LIMITED: Object.freeze(rpcError(-32005, "Rate limit exceeded.")),
    TOO_MANY_PENDING: Object.freeze(rpcError(-32005, "Too many pending requests.")),
    REQUEST_TOO_LARGE: Object.freeze(rpcError(-32600, "Request too large.")),
    INTERNAL: Object.freeze(rpcError(-32603, "Internal error.")),
    TIMED_OUT: Object.freeze(rpcError(-32603, "Request timed out.")),
    RESPONSE_TOO_LARGE: Object.freeze(rpcError(-32603, "Response too large."))
  });

  const api = Object.freeze({
    NAMESPACE,
    PROTOCOL_VERSION,
    CONTENT_PORT_NAME,
    POPUP_PORT_NAME,
    COMPAT_MODE_STORAGE_KEY,
    COMPAT_MODES,
    SOL_COMPAT_MODE_STORAGE_KEY,
    SOL_COMPAT_MODES,
    BTC_COMPAT_MODE_STORAGE_KEY,
    BTC_COMPAT_MODES,
    WIRE_COMPAT_MODES,
    REQUEST_LIMITS,
    RESPONSE_LIMITS,
    METHOD_ROUTE,
    EVENTS,
    ERRORS,
    checkJson,
    hasExactKeys,
    isCompatMode,
    isId32,
    isId64,
    isPlainObject,
    isReason,
    isSupportedPageUrl,
    isWireCompatMode,
    methodFamily,
    methodRoute,
    normalizeBtcCompatMode,
    normalizeCompatMode,
    normalizeSolCompatMode,
    parseBackgroundMessage,
    parseContentMessage,
    parsePageMessage,
    randomHex,
    rpcError,
    validEvent,
    validRpcError
  });

  Object.defineProperty(root, "__YOUR_WALLET_SHARED__", {
    configurable: false,
    enumerable: false,
    writable: false,
    value: api
  });
}(globalThis));
