// Test dApp for M5 (spec/09 §5.7). Results are written with textContent only.
import { keccak256 } from "./keccak.js";

const RDNS = "io.github.na-degen-girl.yourwallet";
const PERMIT2 = "0x000000000022d473030f116ddee9f6b43ac78ba3";
const ECRECOVER = "0x0000000000000000000000000000000000000001";
const SEPOLIA = 11155111;
const MAX_UINT256 = (1n << 256n) - 1n;
const MAX_UINT160 = (1n << 160n) - 1n;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/u;

const logElement = document.getElementById("log");
let provider = null;
let providerSource = null;
let account0 = null;
const eventsAttached = new WeakSet();

// ---------- output ----------
function write(line) {
  const time = new Date().toISOString().slice(11, 23);
  logElement.textContent += `${time} ${line}\n`;
  logElement.scrollTop = logElement.scrollHeight;
}

function show(value) {
  let text;
  try {
    text = JSON.stringify(value);
  } catch {
    text = String(value);
  }
  if (text === undefined) {
    text = String(value);
  }
  return text.length > 400 ? `${text.slice(0, 400)}… (${text.length} chars)` : text;
}

function verdict(label, ok, detail) {
  write(`${label} ${ok ? "PASS" : "CHECK"} ${detail}`);
}

// ---------- provider discovery (EIP-6963 first, then window.ethereum) ----------
window.addEventListener("eip6963:announceProvider", (event) => {
  const detail = event.detail;
  if (!detail || !detail.info || detail.info.rdns !== RDNS || provider !== null) {
    return;
  }
  provider = detail.provider;
  providerSource = `EIP-6963 ${detail.info.name} (${detail.info.rdns})`;
  attachEvents(provider);
  write(`provider: ${providerSource}`);
});
window.dispatchEvent(new Event("eip6963:requestProvider"));

function getProvider() {
  if (provider === null && window.ethereum) {
    provider = window.ethereum;
    providerSource = "window.ethereum";
    attachEvents(provider);
    write("provider: window.ethereum (no EIP-6963 Your Wallet announcement)");
  }
  if (provider === null) {
    throw new Error("no provider found (is the extension loaded and the page allowed?)");
  }
  return provider;
}

function attachEvents(target) {
  if (eventsAttached.has(target) || typeof target.on !== "function") {
    return;
  }
  eventsAttached.add(target);
  target.on("connect", (info) => write(`event connect ${show(info)}`));
  target.on("disconnect", (error) => write(`event disconnect ${error?.code} ${error?.message}`));
  target.on("accountsChanged", (accounts) => {
    account0 = Array.isArray(accounts) && accounts.length > 0 ? accounts[0] : null;
    write(`event accountsChanged ${show(accounts)}`);
  });
  target.on("chainChanged", (chainId) => write(`event chainChanged ${show(chainId)}`));
}

async function rpc(label, method, params, { quiet = false } = {}) {
  const args = params === undefined ? { method } : { method, params };
  try {
    const result = await getProvider().request(args);
    if (!quiet) {
      write(`${label} ${method} -> ${show(result)}`);
    }
    return { ok: true, result };
  } catch (error) {
    const outcome = { ok: false, code: error?.code, message: error?.message, data: error?.data };
    if (!quiet) {
      write(`${label} ${method} -> ERROR ${outcome.code} ${outcome.message}${outcome.data === undefined ? "" : ` data=${show(outcome.data)}`}`);
    }
    return outcome;
  }
}

async function expectCode(label, method, params, code, message) {
  const outcome = await rpc(label, method, params);
  const ok = !outcome.ok && outcome.code === code && (message === undefined || outcome.message === message);
  verdict(label, ok, `${method} expected ${code}${message === undefined ? "" : ` "${message}"`}`);
  return outcome;
}

// ---------- values ----------
function inputValue(id) {
  return document.getElementById(id).value.trim();
}

function recipient() {
  const value = inputValue("recipient");
  if (!ADDRESS.test(value)) {
    throw new Error("enter A1 (wallet account 1 address) in Recipient");
  }
  return value.toLowerCase();
}

function token() {
  const value = inputValue("token");
  if (!ADDRESS.test(value)) {
    throw new Error("Token must be a 0x address");
  }
  return value.toLowerCase();
}

function parseEther(text) {
  const match = /^(\d{1,30})(?:\.(\d{1,18}))?$/u.exec(text);
  if (!match) {
    throw new Error(`invalid ETH amount: ${text}`);
  }
  return BigInt(match[1]) * 10n ** 18n + BigInt((match[2] ?? "").padEnd(18, "0"));
}

async function a0() {
  if (account0 !== null) {
    return account0;
  }
  const outcome = await rpc("A0", "eth_accounts", [], { quiet: true });
  if (outcome.ok && Array.isArray(outcome.result) && outcome.result.length > 0) {
    account0 = outcome.result[0];
  }
  if (account0 === null) {
    throw new Error("not connected: run T01 first");
  }
  return account0;
}

const quantity = (value) => `0x${BigInt(value).toString(16)}`;
const word = (hex) => hex.padStart(64, "0");
const addressWord = (address) => word(address.slice(2).toLowerCase());
const uintWord = (value) => word(BigInt(value).toString(16));

function bytesToHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex) {
  const body = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(body.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(body.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

const utf8Hex = (text) => `0x${bytesToHex(new TextEncoder().encode(text))}`;

function toChecksumAddress(address) {
  const lower = address.slice(2).toLowerCase();
  const hash = bytesToHex(keccak256(new TextEncoder().encode(lower)));
  let out = "0x";
  for (let index = 0; index < 40; index += 1) {
    out += Number.parseInt(hash[index], 16) >= 8 ? lower[index].toUpperCase() : lower[index];
  }
  return out;
}

function randomAlphanumeric(length) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return Array.from(bytes, (byte) => alphabet[byte % alphabet.length]).join("");
}

const sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

// ---------- verification helpers ----------
async function ecrecoverPersonal(label, messageBytes, signature, expected, call = rpc) {
  if (typeof signature !== "string" || !/^0x[0-9a-fA-F]{130}$/u.test(signature)) {
    write(`${label} signature has unexpected shape: ${show(signature)}`);
    return;
  }
  const prefix = new TextEncoder().encode(`\x19Ethereum Signed Message:\n${messageBytes.length}`);
  const preimage = new Uint8Array(prefix.length + messageBytes.length);
  preimage.set(prefix);
  preimage.set(messageBytes, prefix.length);
  const digest = bytesToHex(keccak256(preimage));
  const body = signature.slice(2).toLowerCase();
  const data = `0x${digest}${word(body.slice(128, 130))}${body.slice(0, 64)}${body.slice(64, 128)}`;
  const outcome = await call(label, "eth_call", [{ to: ECRECOVER, data }, "latest"], { quiet: true });
  const recovered = outcome.ok && typeof outcome.result === "string" && outcome.result.length === 66
    ? `0x${outcome.result.slice(-40)}`
    : null;
  verdict(label, recovered !== null && recovered === expected.toLowerCase(), `ecrecover = ${recovered} (A0 ${expected.toLowerCase()})`);
}

async function waitForReceipt(label, hash) {
  if (typeof hash !== "string" || !/^0x[0-9a-f]{64}$/u.test(hash)) {
    return;
  }
  write(`${label} waiting for receipt ${hash}`);
  for (let attempt = 0; attempt < 45; attempt += 1) {
    await sleep(4_000);
    const outcome = await rpc(label, "eth_getTransactionReceipt", [hash], { quiet: true });
    if (outcome.ok && outcome.result) {
      const receipt = outcome.result;
      verdict(label, receipt.status === "0x1", `receipt status=${receipt.status} block=${receipt.blockNumber} gasUsed=${receipt.gasUsed} logs=${receipt.logs?.length}`);
      return;
    }
  }
  write(`${label} no receipt after 180 s`);
}

async function sendTransaction(label, transaction, { wait = true } = {}) {
  const outcome = await rpc(label, "eth_sendTransaction", [transaction]);
  if (outcome.ok && wait) {
    await waitForReceipt(label, outcome.result);
  }
  return outcome;
}

async function wethCall(label, data, value = 0n) {
  return sendTransaction(label, { from: await a0(), to: token(), value: quantity(value), data });
}

// ---------- SIWE (EIP-4361) ----------
function siweMessage({ prefix, uri, address, expiration }) {
  const lines = [
    `${prefix} wants you to sign in with your Ethereum account:`,
    toChecksumAddress(address),
    "",
    "Sign in to the Your Wallet test dApp.",
    "",
    `URI: ${uri}`,
    "Version: 1",
    `Chain ID: ${SEPOLIA}`,
    `Nonce: ${randomAlphanumeric(16)}`,
    `Issued At: ${new Date().toISOString()}`
  ];
  if (expiration) {
    lines.push(`Expiration Time: ${expiration}`);
  }
  return lines.join("\n");
}

async function signSiwe(label, options) {
  const address = await a0();
  const message = siweMessage({ address, ...options });
  write(`${label} message:\n${message}`);
  const outcome = await rpc(label, "personal_sign", [utf8Hex(message), address]);
  if (outcome.ok) {
    await ecrecoverPersonal(label, new TextEncoder().encode(message), outcome.result, address);
  }
  return outcome;
}

// ---------- typed data ----------
function etherMail({ chainId = SEPOLIA, includeChainId = true } = {}) {
  const domainType = [
    { name: "name", type: "string" },
    { name: "version", type: "string" },
    ...(includeChainId ? [{ name: "chainId", type: "uint256" }] : []),
    { name: "verifyingContract", type: "address" }
  ];
  const domain = { name: "Ether Mail", version: "1", verifyingContract: "0xcccccccccccccccccccccccccccccccccccccccc" };
  if (includeChainId) {
    domain.chainId = chainId;
  }
  return {
    types: {
      EIP712Domain: domainType,
      Person: [{ name: "name", type: "string" }, { name: "wallet", type: "address" }],
      Mail: [{ name: "from", type: "Person" }, { name: "to", type: "Person" }, { name: "contents", type: "string" }]
    },
    primaryType: "Mail",
    domain,
    message: {
      from: { name: "Cow", wallet: "0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826" },
      to: { name: "Bob", wallet: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" },
      contents: "Hello, Bob!"
    }
  };
}

async function signTyped(label, typedData) {
  return rpc(label, "eth_signTypedData_v4", [await a0(), JSON.stringify(typedData)]);
}

// ---------- tests ----------
const TESTS = {
  async T01() {
    const outcome = await rpc("T01", "eth_requestAccounts", []);
    if (outcome.ok && Array.isArray(outcome.result)) {
      account0 = outcome.result[0] ?? null;
    }
  },
  async T02() {
    await rpc("T02", "eth_accounts", []);
    await rpc("T02", "wallet_getPermissions", []);
  },
  async T03() {
    const chain = await rpc("T03", "eth_chainId", []);
    const net = await rpc("T03", "net_version", []);
    const client = await rpc("T03", "web3_clientVersion", []);
    verdict("T03", chain.result === "0xaa36a7" && net.result === "11155111" && /^YourWallet\//u.test(client.result ?? ""),
      "expected 0xaa36a7 / 11155111 / YourWallet/<version>");
  },
  async T04() {
    const userChain = inputValue("userChain");
    const sequence = ["0x1", "0x3e7", ...(userChain ? [userChain.toLowerCase()] : []), "0xaa36a7"];
    if (!userChain) {
      write("T04 note: no user chain id entered; skipping that step");
    }
    for (const chainId of sequence) {
      const outcome = await rpc("T04", "wallet_switchEthereumChain", [{ chainId }]);
      verdict("T04", outcome.ok && outcome.result === null, `switch ${chainId} -> null (expect one chainChanged event)`);
    }
    await expectCode("T04", "wallet_switchEthereumChain", [{ chainId: "0x89" }], 4902);
  },
  async T05() {
    await rpc("T05", "wallet_revokePermissions", [{ eth_accounts: {} }]);
    account0 = null;
    const outcome = await rpc("T05", "eth_accounts", []);
    verdict("T05", outcome.ok && Array.isArray(outcome.result) && outcome.result.length === 0, "eth_accounts -> [] (run T01 again)");
  },
  async T06() {
    const address = await a0();
    const block = await rpc("T06", "eth_blockNumber", []);
    await rpc("T06", "eth_getBalance", [address, "latest"]);
    await rpc("T06", "eth_call", [{ to: token(), data: `0x70a08231${addressWord(address)}` }, "latest"]);
    await rpc("T06", "eth_estimateGas", [{ from: address, to: address, value: "0x1" }]);
    await rpc("T06", "eth_feeHistory", ["0x5", "latest", [25, 50, 75]]);
    if (block.ok) {
      const latest = BigInt(block.result);
      const from = latest > 9n ? latest - 9n : 0n;
      await rpc("T06", "eth_getLogs", [{ fromBlock: quantity(from), toBlock: quantity(latest), address: token() }]);
    }
  },
  async T07() {
    await sendTransaction("T07", { from: await a0(), to: recipient(), value: quantity(parseEther(inputValue("amount"))) });
  },
  async T08() {
    await wethCall("T08", "0xd0e30db0", 10n ** 15n);
  },
  async T09() {
    await wethCall("T09", `0xa9059cbb${addressWord(recipient())}${uintWord(5n * 10n ** 14n)}`);
  },
  async T10() {
    await wethCall("T10", `0x095ea7b3${addressWord(PERMIT2)}${uintWord(10n ** 15n)}`);
  },
  async T11() {
    await wethCall("T11", `0x095ea7b3${addressWord(PERMIT2)}${uintWord(MAX_UINT256)}`);
  },
  async T12() {
    await wethCall("T12", `0x095ea7b3${addressWord(recipient())}${uintWord(1n)}`);
  },
  async T13() {
    await wethCall("T13", `0xdeadbeef${"00".repeat(32)}`);
  },
  async T14() {
    const outcome = await wethCall("T14", `0x2e1a7d4d${uintWord(10n ** 30n)}`);
    verdict("T14", !outcome.ok && outcome.code === 4001, "expected rejection 4001 after checking E02/E37 warnings");
  },
  async T15() {
    await expectCode("T15", "eth_sendTransaction",
      [{ from: await a0(), to: recipient(), value: "0x0", authorizationList: [] }], -32602, "Invalid params.");
  },
  async T16() {
    const from = await a0();
    const to = recipient();
    await expectCode("T16 type 0x4", "eth_sendTransaction", [{ from, to, value: "0x0", type: "0x4" }], -32602);
    await expectCode("T16 no to", "eth_sendTransaction", [{ from, value: "0x0" }], -32602);
    await expectCode("T16 chainId 0x1", "eth_sendTransaction", [{ from, to, value: "0x0", chainId: "0x1" }], -32602);
    await expectCode("T16 from A1", "eth_sendTransaction", [{ from: to, to: from, value: "0x0" }], 4100);
  },
  async T17() {
    await sendTransaction("T17", {
      from: await a0(),
      to: recipient(),
      value: quantity(parseEther(inputValue("amount"))),
      maxFeePerGas: "0x1"
    });
  },
  async T18() {
    const address = await a0();
    const text = "Hello, Your Wallet";
    const outcome = await rpc("T18", "personal_sign", [utf8Hex(text), address]);
    if (outcome.ok) {
      await ecrecoverPersonal("T18", new TextEncoder().encode(text), outcome.result, address);
    }
  },
  async T19() {
    const address = await a0();
    const outcome = await rpc("T19", "personal_sign", ["0xff00fe", address]);
    if (outcome.ok) {
      await ecrecoverPersonal("T19", hexToBytes("0xff00fe"), outcome.result, address);
    }
  },
  async T20() {
    await signSiwe("T20", { prefix: `${location.protocol}//${location.host}`, uri: location.origin });
  },
  async T20b() {
    const outcome = await signSiwe("T20b", { prefix: location.host, uri: location.origin });
    verdict("T20b", !outcome.ok, "expected the S02 block (omitted scheme = https, origin is http)");
  },
  async T21() {
    const outcome = await signSiwe("T21", { prefix: "https://evil.example", uri: "https://evil.example" });
    verdict("T21", !outcome.ok, "expected the S01 block (domain mismatch)");
  },
  async T22() {
    const expiration = new Date(Date.now() - 3_600_000).toISOString();
    const outcome = await signSiwe("T22", { prefix: `${location.protocol}//${location.host}`, uri: location.origin, expiration });
    verdict("T22", !outcome.ok, "expected the S04 block (expired)");
  },
  async T23() {
    const owner = await a0();
    const spender = recipient();
    const weth = token();
    const sigDeadline = BigInt(Math.floor(Date.now() / 1000) + 1_800);
    const typedData = {
      types: {
        EIP712Domain: [
          { name: "name", type: "string" },
          { name: "chainId", type: "uint256" },
          { name: "verifyingContract", type: "address" }
        ],
        PermitSingle: [
          { name: "details", type: "PermitDetails" },
          { name: "spender", type: "address" },
          { name: "sigDeadline", type: "uint256" }
        ],
        PermitDetails: [
          { name: "token", type: "address" },
          { name: "amount", type: "uint160" },
          { name: "expiration", type: "uint48" },
          { name: "nonce", type: "uint48" }
        ]
      },
      primaryType: "PermitSingle",
      domain: { name: "Permit2", chainId: SEPOLIA, verifyingContract: PERMIT2 },
      message: {
        details: { token: weth, amount: MAX_UINT160.toString(), expiration: 0, nonce: 0 },
        spender,
        sigDeadline: Number(sigDeadline)
      }
    };
    const outcome = await signTyped("T23", typedData);
    if (!outcome.ok || typeof outcome.result !== "string" || !/^0x[0-9a-fA-F]{130}$/u.test(outcome.result)) {
      return;
    }
    // permit(address owner, PermitSingle permitSingle, bytes signature), selector 0x2b67b570.
    const signature = outcome.result.slice(2).toLowerCase();
    const data = "0x2b67b570"
      + addressWord(owner)
      + addressWord(weth) + uintWord(MAX_UINT160) + uintWord(0n) + uintWord(0n)
      + addressWord(spender) + uintWord(sigDeadline)
      + uintWord(0x100n)
      + uintWord(65n) + signature.padEnd(192, "0");
    const call = await rpc("T23", "eth_call", [{ from: owner, to: PERMIT2, data }, "latest"]);
    verdict("T23", call.ok, "Permit2 permit(owner, PermitSingle, sig) eth_call does not revert");
  },
  async T24() {
    const owner = await a0();
    await signTyped("T24", {
      types: {
        EIP712Domain: [
          { name: "name", type: "string" },
          { name: "version", type: "string" },
          { name: "chainId", type: "uint256" },
          { name: "verifyingContract", type: "address" }
        ],
        Permit: [
          { name: "owner", type: "address" },
          { name: "spender", type: "address" },
          { name: "value", type: "uint256" },
          { name: "nonce", type: "uint256" },
          { name: "deadline", type: "uint256" }
        ]
      },
      primaryType: "Permit",
      domain: { name: "Test Token", version: "1", chainId: SEPOLIA, verifyingContract: token() },
      message: {
        owner,
        spender: PERMIT2,
        value: MAX_UINT256.toString(),
        nonce: 0,
        deadline: Math.floor(Date.now() / 1000) + 3_600
      }
    });
  },
  async T25() {
    await signTyped("T25", etherMail());
  },
  async T26() {
    const outcome = await signTyped("T26", etherMail({ chainId: 1 }));
    verdict("T26", !outcome.ok && outcome.code === -32602, "expected -32602 without a window (domain chainId 1)");
  },
  async T27() {
    await signTyped("T27", etherMail({ includeChainId: false }));
  },
  async T28() {
    const address = account0 ?? "0x0000000000000000000000000000000000000000";
    const cases = [
      ["eth_sign", [address, "0x00"]],
      ["eth_signTransaction", [{ from: address, to: address, value: "0x0" }]],
      ["eth_sendRawTransaction", ["0x00"]],
      ["eth_signTypedData_v3", [address, "{}"]],
      ["wallet_sendCalls", [{ version: "1.0", chainId: "0xaa36a7", from: address, calls: [] }]],
      ["wallet_addEthereumChain", [{
        chainId: "0x89",
        chainName: "Polygon Mainnet",
        nativeCurrency: { name: "POL", symbol: "POL", decimals: 18 },
        rpcUrls: ["https://polygon-rpc.com"],
        blockExplorerUrls: ["https://polygonscan.com"]
      }]],
      ["foo_bar", []]
    ];
    for (const [method, params] of cases) {
      await expectCode("T28", method, params, 4200, "Unsupported method.");
    }
  },
  async T29() {
    const address = account0 ?? "0x0000000000000000000000000000000000000000";
    await expectCode("T29 2 MiB", "personal_sign", [`0x${"61".repeat(1_048_576)}`, address], -32600, "Request too large.");
    let deep = [];
    for (let level = 1; level < 39; level += 1) {
      deep = [deep];
    }
    await expectCode("T29 depth 40", "personal_sign", [deep, address], -32600, "Request too large.");
  },
  async T30() {
    const started = performance.now();
    let succeeded = 0;
    let retries = 0;
    let failures = 0;
    for (let index = 0; index < 5_000; index += 1) {
      for (;;) {
        const outcome = await rpc("T30", "eth_blockNumber", [], { quiet: true });
        if (outcome.ok) {
          succeeded += 1;
          break;
        }
        if (outcome.code === -32005) {
          retries += 1;
          await sleep(250);
          continue;
        }
        failures += 1;
        write(`T30 request ${index + 1} failed: ${outcome.code} ${outcome.message}`);
        break;
      }
      if ((index + 1) % 500 === 0) {
        write(`T30 progress ${index + 1}/5000 (retries ${retries})`);
      }
    }
    const seconds = ((performance.now() - started) / 1000).toFixed(1);
    verdict("T30", succeeded === 5_000, `${succeeded} succeeded, ${failures} failed, ${retries} rate-limit retries, ${seconds} s`);
  },
  async T31() {
    write("T31 sending the T07 transaction; when the approval window opens, close this tab without deciding (expect the window to close within 2 s, no transaction).");
    await sendTransaction("T31", { from: await a0(), to: recipient(), value: quantity(parseEther(inputValue("amount"))) }, { wait: false });
  },
  async T32() {
    const seen = [];
    const listener = (event) => seen.push(event.detail);
    window.addEventListener("eip6963:announceProvider", listener);
    window.dispatchEvent(new Event("eip6963:requestProvider"));
    window.removeEventListener("eip6963:announceProvider", listener);
    const ours = seen.filter((detail) => detail?.info?.rdns === RDNS);
    for (const detail of seen) {
      write(`T32 announce name=${show(detail?.info?.name)} rdns=${show(detail?.info?.rdns)} uuid=${show(detail?.info?.uuid)}`);
    }
    verdict("T32", ours.length === 1, `${seen.length} announcement(s), ${ours.length} with rdns ${RDNS}`);
  }
};

// ---------- MetaMask-only dApp imitation (spec/05 §2.12, spec/09 §5.7 C01–C05) ----------
// Like a dApp that supports only MetaMask: no Your Wallet rdns, only window.ethereum.isMetaMask.
// The picker keeps every EIP-6963 announcement by uuid, as wallet-picker libraries do.
const COMPAT_RDNS = new Set(["io.metamask", "io.metamask.flask", "io.rabby"]);
const pickerEntries = new Map();
window.addEventListener("eip6963:announceProvider", (event) => {
  const detail = event.detail;
  if (detail && detail.info && typeof detail.info.uuid === "string" && !pickerEntries.has(detail.info.uuid)) {
    pickerEntries.set(detail.info.uuid, detail);
  }
});

function ourMode(candidate) {
  if (!candidate || candidate.isYourWallet !== true) {
    return "not Your Wallet";
  }
  if (candidate.isRabby === true) {
    return "rabby";
  }
  return candidate.isMetaMask === true ? "metamask" : "off";
}

function metamaskOnlyProvider(label) {
  const candidate = window.ethereum;
  if (!candidate || candidate.isMetaMask !== true) {
    write(`${label} MetaMask를 찾을 수 없습니다(이 dApp은 MetaMask만 지원). 확장 팝업에서 "MetaMask처럼 보이기"를 고르고 새로고침하세요.`);
    return null;
  }
  return candidate;
}

async function mmRpc(label, method, params, { quiet = false } = {}) {
  const target = metamaskOnlyProvider(label);
  if (target === null) {
    return { ok: false, code: undefined, message: "no MetaMask" };
  }
  try {
    const result = await target.request(params === undefined ? { method } : { method, params });
    if (!quiet) {
      write(`${label} ${method} -> ${show(result)}`);
    }
    return { ok: true, result };
  } catch (error) {
    if (!quiet) {
      write(`${label} ${method} -> ERROR ${error?.code} ${error?.message}`);
    }
    return { ok: false, code: error?.code, message: error?.message };
  }
}

function renderPicker() {
  const container = document.getElementById("picker");
  container.replaceChildren();
  for (const detail of pickerEntries.values()) {
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = `${detail.info.name} (${detail.info.rdns}) 로 연결`;
    button.addEventListener("click", async () => {
      write(`---- picker ${detail.info.name} (${detail.info.rdns})`);
      try {
        const accounts = await detail.provider.request({ method: "eth_requestAccounts" });
        write(`picker eth_requestAccounts -> ${show(accounts)}`);
      } catch (error) {
        write(`picker eth_requestAccounts -> ERROR ${error?.code} ${error?.message}`);
      }
    });
    container.append(button);
  }
}

Object.assign(TESTS, {
  async C01() {
    const candidate = window.ethereum;
    const descriptor = Object.getOwnPropertyDescriptor(window, "ethereum");
    write(`C01 window.ethereum: ${candidate ? "present" : "absent"}; property ${descriptor === undefined ? "none" : "get" in descriptor ? "accessor" : "data"}, configurable=${descriptor?.configurable}`);
    write(`C01 flags isMetaMask=${show(candidate?.isMetaMask)} isRabby=${show(candidate?.isRabby)} isYourWallet=${show(candidate?.isYourWallet)} _metamask.isUnlocked=${typeof candidate?._metamask?.isUnlocked}`);
    const mode = ourMode(candidate);
    write(`C01 Your Wallet mode as seen by the page: ${mode}`);
    if (mode === "metamask" || mode === "rabby") {
      verdict("C01", candidate.isMetaMask === true && typeof candidate._metamask?.isUnlocked === "function",
        `MetaMask-only check passes and the provider is Your Wallet (${mode})`);
    } else if (candidate?.isMetaMask === true) {
      verdict("C01", false, "window.ethereum is another MetaMask-like wallet, not Your Wallet (interception lost; disable the real MetaMask/Rabby)");
    } else {
      verdict("C01", mode === "off", "default mode: isMetaMask is false, so a MetaMask-only dApp would not find a wallet (expected in 기본 mode)");
    }
  },
  async C02() {
    write("C02 expect the yw-app connect window: real origin of this page + badge 호환 모드: MetaMask (or Rabby).");
    const outcome = await mmRpc("C02", "eth_requestAccounts", []);
    if (outcome.ok && Array.isArray(outcome.result) && outcome.result.length > 0) {
      account0 = outcome.result[0];
    }
    verdict("C02", outcome.ok && Array.isArray(outcome.result) && outcome.result.length > 0, "connected through window.ethereum");
  },
  async C03() {
    const accounts = await mmRpc("C03", "eth_requestAccounts", [], { quiet: true });
    if (!accounts.ok || !Array.isArray(accounts.result) || accounts.result.length === 0) {
      write("C03 not connected: run C02 first");
      return;
    }
    const address = accounts.result[0];
    const message = siweMessage({ prefix: `${location.protocol}//${location.host}`, uri: location.origin, address });
    write(`C03 message:\n${message}`);
    const outcome = await mmRpc("C03", "personal_sign", [utf8Hex(message), address]);
    if (outcome.ok) {
      await ecrecoverPersonal("C03", new TextEncoder().encode(message), outcome.result, address, mmRpc);
    }
  },
  async C04() {
    const target = metamaskOnlyProvider("C04");
    if (target === null) {
      return;
    }
    if (typeof target._metamask?.isUnlocked !== "function") {
      verdict("C04", false, "_metamask.isUnlocked is missing");
      return;
    }
    const unlocked = await target._metamask.isUnlocked();
    write(`C04 _metamask.isUnlocked() -> ${show(unlocked)} (true only while connected and yw-app unlocked)`);
    verdict("C04", typeof unlocked === "boolean", "resolves to a boolean");
  },
  async C05() {
    window.dispatchEvent(new Event("eip6963:requestProvider"));
    await sleep(300);
    const entries = [...pickerEntries.values()];
    for (const detail of entries) {
      write(`C05 ${detail.info.name} rdns=${detail.info.rdns} uuid=${detail.info.uuid} isYourWallet=${show(detail.provider?.isYourWallet)} same-as-window.ethereum=${detail.provider === window.ethereum}`);
    }
    renderPicker();
    const mode = ourMode(window.ethereum);
    const compatEntries = entries.filter((detail) => COMPAT_RDNS.has(detail.info.rdns));
    if (mode === "metamask" || mode === "rabby") {
      const expectedRdns = mode === "metamask" ? "io.metamask" : "io.rabby";
      verdict("C05", compatEntries.length === 1 && compatEntries[0].info.rdns === expectedRdns
        && compatEntries[0].provider?.isYourWallet === true && !entries.some((detail) => detail.info.rdns === RDNS),
      `${entries.length} provider(s); exactly one MetaMask/Rabby entry (${expectedRdns}) and it is Your Wallet; no separate Your Wallet entry`);
    } else {
      verdict("C05", entries.filter((detail) => detail.info.rdns === RDNS).length === 1,
        `${entries.length} provider(s); default mode lists Your Wallet (${RDNS}); other wallets are listed unchanged`);
    }
  }
});

for (const button of document.querySelectorAll("button[data-test]")) {
  button.addEventListener("click", async () => {
    const id = button.dataset.test;
    button.disabled = true;
    write(`---- ${id}`);
    try {
      await TESTS[id]();
    } catch (error) {
      write(`${id} aborted: ${error?.message ?? String(error)}`);
    } finally {
      button.disabled = false;
    }
  });
}
document.getElementById("clear").addEventListener("click", () => {
  logElement.textContent = "";
});
write(provider === null
  ? "provider: no EIP-6963 Your Wallet announcement yet (window.ethereum is used on first request if present)"
  : `ready (${providerSource})`);
