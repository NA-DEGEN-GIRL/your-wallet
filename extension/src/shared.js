(function installYourWalletShared(root) {
  "use strict";

  if (Object.prototype.hasOwnProperty.call(root, "__YOUR_WALLET_SHARED__")) {
    return;
  }

  const NAMESPACE = "your-wallet";
  const PROTOCOL_VERSION = 1;
  const MAX_MESSAGE_BYTES = 1_048_576;
  const MAX_REQUESTS_PER_ACTIVATION = 4_096;
  const MAX_METHOD_LENGTH = 96;
  const MAX_REQUEST_ID_LENGTH = 32;

  const METHOD_ROUTE = Object.freeze({
    eth_requestAccounts: "permission",
    eth_accounts: "permission",
    eth_chainId: "permission",
    net_version: "permission",
    eth_sendTransaction: "signing",
    personal_sign: "signing",
    eth_signTypedData_v4: "signing",
    wallet_addEthereumChain: "permission",
    wallet_switchEthereumChain: "permission",
    wallet_watchAsset: "permission",
    wallet_requestPermissions: "permission",
    wallet_getPermissions: "permission",
    wallet_getCapabilities: "permission",
    eth_blockNumber: "read",
    eth_call: "read",
    eth_estimateGas: "read",
    eth_feeHistory: "read",
    eth_gasPrice: "read",
    eth_getBalance: "read",
    eth_getBlockByHash: "read",
    eth_getBlockByNumber: "read",
    eth_getCode: "read",
    eth_getLogs: "read",
    eth_getStorageAt: "read",
    eth_getTransactionByHash: "read",
    eth_getTransactionCount: "read",
    eth_getTransactionReceipt: "read",
    eth_maxPriorityFeePerGas: "read"
  });

  const ALLOWED_EVENTS = new Set([
    "accountsChanged",
    "chainChanged",
    "connect",
    "disconnect"
  ]);

  const HEX_NONCE_PATTERN = /^[0-9a-f]{32,128}$/u;
  const REQUEST_ID_PATTERN = /^[0-9a-f]{32}$/u;

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
    return required.every((key) => Object.prototype.hasOwnProperty.call(value, key))
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
    if (!isPlainObject(value) || Object.keys(value).length > 10_000) {
      return false;
    }
    return Object.entries(value).every(([key, entry]) => (
      typeof key === "string" && isJsonValue(entry, depth + 1)
    ));
  }

  function encodedJsonSize(value) {
    let serialized;
    try {
      serialized = JSON.stringify(value);
    } catch (_error) {
      return Number.POSITIVE_INFINITY;
    }
    if (serialized === undefined) {
      return Number.POSITIVE_INFINITY;
    }
    return new TextEncoder().encode(serialized).byteLength;
  }

  function fitsMessageLimit(value) {
    return encodedJsonSize(value) <= MAX_MESSAGE_BYTES;
  }

  function methodRoute(method) {
    if (typeof method !== "string" || method.length === 0 || method.length > MAX_METHOD_LENGTH) {
      return null;
    }
    return Object.prototype.hasOwnProperty.call(METHOD_ROUTE, method)
      ? METHOD_ROUTE[method]
      : null;
  }

  function validRequestId(value) {
    return typeof value === "string"
      && value.length <= MAX_REQUEST_ID_LENGTH
      && REQUEST_ID_PATTERN.test(value);
  }

  function validNonce(value) {
    return typeof value === "string" && HEX_NONCE_PATTERN.test(value);
  }

  function validParams(value) {
    return (Array.isArray(value) || isPlainObject(value)) && isJsonValue(value);
  }

  function parsePageRequest(value, expectedChannel) {
    const required = ["namespace", "version", "channel", "kind", "id", "method", "params"];
    if (!hasExactKeys(value, required)) {
      return null;
    }
    if (value.namespace !== NAMESPACE
      || value.version !== PROTOCOL_VERSION
      || value.channel !== expectedChannel
      || value.kind !== "request"
      || !validRequestId(value.id)
      || !validParams(value.params)) {
      return null;
    }
    return Object.freeze({
      id: value.id,
      method: value.method,
      params: value.params
    });
  }

  function parseContentRequest(value, expectedActivationNonce) {
    const required = ["namespace", "version", "kind", "activationNonce", "id", "method", "params"];
    if (!hasExactKeys(value, required)) {
      return null;
    }
    if (value.namespace !== NAMESPACE
      || value.version !== PROTOCOL_VERSION
      || value.kind !== "request"
      || value.activationNonce !== expectedActivationNonce
      || !validRequestId(value.id)
      || !validParams(value.params)) {
      return null;
    }
    return Object.freeze({
      id: value.id,
      method: value.method,
      params: value.params
    });
  }

  function rpcError(code, message, data) {
    const error = { code, message };
    if (data !== undefined && isJsonValue(data)) {
      error.data = data;
    }
    return error;
  }

  function randomHex(byteLength, cryptoObject = root.crypto) {
    if (!cryptoObject || typeof cryptoObject.getRandomValues !== "function") {
      throw new Error("A cryptographically secure random source is required.");
    }
    const bytes = new Uint8Array(byteLength);
    cryptoObject.getRandomValues(bytes);
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  }

  const api = Object.freeze({
    NAMESPACE,
    PROTOCOL_VERSION,
    MAX_MESSAGE_BYTES,
    MAX_REQUESTS_PER_ACTIVATION,
    ALLOWED_EVENTS,
    encodedJsonSize,
    fitsMessageLimit,
    hasExactKeys,
    isJsonValue,
    isPlainObject,
    methodRoute,
    parseContentRequest,
    parsePageRequest,
    randomHex,
    rpcError,
    validNonce,
    validParams,
    validRequestId
  });

  Object.defineProperty(root, "__YOUR_WALLET_SHARED__", {
    configurable: false,
    enumerable: false,
    writable: false,
    value: api
  });
}(globalThis));
