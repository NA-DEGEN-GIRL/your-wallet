// Solana section of the test dApp (spec/09 M7-12–M7-14, spec/07 §20). Pure JS, no web3.js: the
// transactions are built by hand from a blockhash typed into the form (copy one from
// `solana block` or an explorer; it is valid for about a minute). The co-signer for the partial
// signature and foreign fee payer cases is a WebCrypto Ed25519 key made in this page. Results
// are written with textContent only.

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const SYSTEM_PROGRAM = new Uint8Array(32);
const MEMO_PROGRAM = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
const RECENT_BLOCKHASHES = "SysvarRecentB1ockHashes11111111111111111111";
const WALLET_NAMES = new Set(["Your Wallet (Solana)", "Phantom"]);

const logElement = document.getElementById("log");
const wallets = [];
let wallet = null;
let account = null;
let coSigner = null;

function write(line) {
  const time = new Date().toISOString().slice(11, 23);
  logElement.textContent += `${time} ${line}\n`;
  logElement.scrollTop = logElement.scrollHeight;
}

function verdict(label, ok, detail) {
  write(`${label} ${ok ? "PASS" : "CHECK"} ${detail}`);
}

function errorText(error) {
  const data = error?.data === undefined ? "" : ` data=${JSON.stringify(error.data)}`;
  return `${error?.code} ${error?.message}${data}`;
}

// ---------- encoding ----------
function b58encode(bytes) {
  let value = 0n;
  for (const byte of bytes) {
    value = value * 256n + BigInt(byte);
  }
  let text = "";
  while (value > 0n) {
    text = B58[Number(value % 58n)] + text;
    value /= 58n;
  }
  for (const byte of bytes) {
    if (byte !== 0) {
      break;
    }
    text = `1${text}`;
  }
  return text;
}

function b58decode(text) {
  let value = 0n;
  for (const character of text) {
    const digit = B58.indexOf(character);
    if (digit < 0) {
      throw new Error(`not base58: ${text}`);
    }
    value = value * 58n + BigInt(digit);
  }
  const bytes = [];
  while (value > 0n) {
    bytes.unshift(Number(value % 256n));
    value /= 256n;
  }
  for (const character of text) {
    if (character !== "1") {
      break;
    }
    bytes.unshift(0);
  }
  return Uint8Array.from(bytes);
}

function key32(text) {
  const bytes = b58decode(text);
  if (bytes.length !== 32) {
    throw new Error(`not a 32-byte key: ${text}`);
  }
  return bytes;
}

function shortvec(length) {
  const out = [];
  let rest = length;
  for (;;) {
    const low = rest & 0x7f;
    rest >>= 7;
    if (rest === 0) {
      out.push(low);
      return out;
    }
    out.push(low | 0x80);
  }
}

function u64le(value) {
  const out = [];
  let rest = BigInt(value);
  for (let index = 0; index < 8; index += 1) {
    out.push(Number(rest & 0xffn));
    rest >>= 8n;
  }
  return out;
}

const sameKey = (left, right) => left.length === right.length && left.every((byte, index) => byte === right[index]);

// ---------- transactions ----------
// A message from `instructions` ({ program, accounts: [{ key, signer, writable }], data }) with
// `payer` first (spec/07 §7: signer-writable, signer-readonly, writable, readonly). `version` 0
// adds the 0x80 prefix and an empty lookup list (no ALT).
function compile({ version, payer, instructions, blockhash }) {
  const metas = [];
  const add = (key, signer, writable) => {
    let meta = metas.find((entry) => sameKey(entry.key, key));
    if (meta === undefined) {
      meta = { key, signer: false, writable: false, order: metas.length };
      metas.push(meta);
    }
    meta.signer ||= signer;
    meta.writable ||= writable;
  };
  add(payer, true, true);
  for (const instruction of instructions) {
    for (const entry of instruction.accounts) {
      add(entry.key, entry.signer, entry.writable);
    }
    add(instruction.program, false, false);
  }
  const rank = (meta) => (meta.signer ? (meta.writable ? 0 : 1) : (meta.writable ? 2 : 3));
  metas.sort((left, right) => rank(left) - rank(right) || left.order - right.order);
  const index = (key) => metas.findIndex((entry) => sameKey(entry.key, key));
  const signers = metas.filter((meta) => meta.signer);
  const out = version === 0 ? [0x80] : [];
  out.push(signers.length, signers.filter((meta) => !meta.writable).length,
    metas.filter((meta) => !meta.signer && !meta.writable).length, ...shortvec(metas.length));
  for (const meta of metas) {
    out.push(...meta.key);
  }
  out.push(...blockhash, ...shortvec(instructions.length));
  for (const instruction of instructions) {
    out.push(index(instruction.program), ...shortvec(instruction.accounts.length),
      ...instruction.accounts.map((entry) => index(entry.key)), ...shortvec(instruction.data.length), ...instruction.data);
  }
  if (version === 0) {
    out.push(0);
  }
  return { message: Uint8Array.from(out), signers: signers.map((meta) => meta.key) };
}

// `shortvec(n) ‖ n signatures ‖ message`; missing signatures are zero.
function wire(compiled, signatures = new Map()) {
  const out = [...shortvec(compiled.signers.length)];
  for (const signer of compiled.signers) {
    out.push(...(signatures.get(b58encode(signer)) ?? new Uint8Array(64)));
  }
  out.push(...compiled.message);
  return Uint8Array.from(out);
}

function memo(text, signer) {
  return {
    program: key32(MEMO_PROGRAM),
    accounts: [{ key: signer, signer: true, writable: false }],
    data: Array.from(new TextEncoder().encode(text))
  };
}

function transfer(from, to, lamports) {
  return {
    program: SYSTEM_PROGRAM,
    accounts: [{ key: from, signer: true, writable: true }, { key: to, signer: false, writable: true }],
    data: [2, 0, 0, 0, ...u64le(lamports)]
  };
}

function blockhash() {
  const text = document.getElementById("solBlockhash").value.trim();
  if (text === "") {
    throw new Error("enter a recent devnet blockhash (solana block / explorer)");
  }
  return key32(text);
}

function recipient() {
  const text = document.getElementById("solRecipient").value.trim();
  return text === "" ? me() : key32(text);
}

function me() {
  if (account === null) {
    throw new Error("not connected: run S01 first");
  }
  return Uint8Array.from(account.publicKey);
}

function simple(version, label) {
  return compile({
    version,
    payer: me(),
    instructions: [memo(`Your Wallet test dApp ${label} ${new Date().toISOString()}`, me())],
    blockhash: blockhash()
  });
}

// ---------- Ed25519 (WebCrypto) ----------
async function ensureCoSigner() {
  if (coSigner === null) {
    const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
    coSigner = { pair, key: raw };
    write(`co-signer ${b58encode(raw)} (this page only)`);
  }
  return coSigner;
}

async function coSign(message) {
  const signer = await ensureCoSigner();
  return new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, signer.pair.privateKey, message));
}

async function verifies(key, message, signature) {
  try {
    const imported = await crypto.subtle.importKey("raw", key, { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify({ name: "Ed25519" }, imported, signature, message);
  } catch {
    return false;
  }
}

// The wallet's answer: same length, every byte outside our slot unchanged, our signature valid.
async function checkSigned(label, compiled, sent, signed) {
  const slot = compiled.signers.findIndex((signer) => sameKey(signer, me()));
  const prefix = shortvec(compiled.signers.length).length;
  const start = prefix + 64 * slot;
  const others = signed.length === sent.length
    && Array.from(signed).every((byte, index) => (index >= start && index < start + 64) || byte === sent[index]);
  const ours = await verifies(me(), compiled.message, signed.slice(start, start + 64));
  verdict(label, others && ours, `slot ${slot} signed and valid=${ours}, other bytes unchanged=${others}, ${signed.length} B`);
}

// ---------- Wallet Standard discovery ----------
window.addEventListener("wallet-standard:register-wallet", (event) => {
  try {
    event.detail({ register: (found) => wallets.push(found) });
  } catch (error) {
    write(`register-wallet failed: ${error?.message}`);
  }
});
window.dispatchEvent(new CustomEvent("wallet-standard:app-ready", { detail: { register: (found) => wallets.push(found) } }));

function solWallet() {
  if (wallet === null) {
    wallet = wallets.find((found) => WALLET_NAMES.has(found.name)) ?? null;
  }
  if (wallet === null) {
    throw new Error(`no Your Wallet (Solana) / Phantom in Wallet Standard (${wallets.map((found) => found.name).join(", ") || "none"})`);
  }
  return wallet;
}

function feature(name) {
  const found = solWallet().features[name];
  if (found === undefined) {
    throw new Error(`${solWallet().name} has no ${name}`);
  }
  return found;
}

async function signOne(label, compiled) {
  const sent = wire(compiled);
  const [output] = await feature("solana:signTransaction").signTransaction({ account, transaction: sent, chain: "solana:devnet" });
  await checkSigned(label, compiled, sent, output.signedTransaction);
  return output.signedTransaction;
}

async function sendOne(label, compiled, options) {
  const sent = wire(compiled);
  const [output] = await feature("solana:signAndSendTransaction").signAndSendTransaction({ account, transaction: sent, chain: "solana:devnet", options });
  const signature = b58encode(output.signature);
  write(`${label} signature ${signature}`);
  write(`${label} explorer https://explorer.solana.com/tx/${signature}?cluster=devnet`);
  verdict(label, output.signature.length === 64, "64-byte signature 0 (the transaction id); check the activity row in the app");
}

function phantom() {
  const candidate = window.phantom?.solana;
  if (!candidate || candidate.isYourWallet !== true) {
    throw new Error("window.phantom.solana is not Your Wallet: choose Phantom처럼 보이기 in the popup and reload");
  }
  return candidate;
}

const SOL_TESTS = {
  async S01() {
    const found = solWallet();
    write(`S01 wallet "${found.name}", chains ${JSON.stringify(found.chains)}, features ${Object.keys(found.features).join(" ")}`);
    write(`S01 versions sign=${JSON.stringify(found.features["solana:signTransaction"]?.supportedTransactionVersions)} send=${JSON.stringify(found.features["solana:signAndSendTransaction"]?.supportedTransactionVersions)}`);
    const { accounts } = await feature("standard:connect").connect();
    account = accounts[0] ?? null;
    verdict("S01", account !== null, `connected ${account?.address}`);
  },
  async S02() {
    write("S02 expect the window: 사이트 거래 서명, Memo decoded, X11 (서명만).");
    await signOne("S02", simple(undefined, "legacy"));
  },
  async S03() {
    write("S03 v0 without lookup tables.");
    await signOne("S03", simple(0, "v0"));
  },
  async S04() {
    write("S04 expect ONE window with 거래 1/3–3/3 (one approval).");
    const list = [simple(undefined, "batch 1"), simple(0, "batch 2"), simple(undefined, "batch 3")];
    const sent = list.map((compiled) => wire(compiled));
    const outputs = await feature("solana:signTransaction").signTransaction(...sent.map((transaction) => ({ account, transaction, chain: "solana:devnet" })));
    for (const [index, output] of outputs.entries()) {
      await checkSigned(`S04 #${index + 1}`, list[index], sent[index], output.signedTransaction);
    }
  },
  async S05() {
    write("S05 the page's co-signer pays the fee and signs first (slot 0); the wallet signs slot 1 (X13). Sign-only: the co-signer has no SOL.");
    const signer = await ensureCoSigner();
    const compiled = compile({ payer: signer.key, instructions: [memo("Your Wallet test dApp partial", me())], blockhash: blockhash() });
    const signature = await coSign(compiled.message);
    const sent = wire(compiled, new Map([[b58encode(signer.key), signature]]));
    const [output] = await feature("solana:signTransaction").signTransaction({ account, transaction: sent });
    await checkSigned("S05", compiled, sent, output.signedTransaction);
    verdict("S05 co-signer", await verifies(signer.key, compiled.message, output.signedTransaction.slice(1, 65)), "the site's signature in slot 0 kept");
  },
  async S06() {
    write("S06 a bad site signature in slot 0: expect X01 (차단), the window cannot approve.");
    const signer = await ensureCoSigner();
    const compiled = compile({ payer: signer.key, instructions: [memo("Your Wallet test dApp bad", me())], blockhash: blockhash() });
    const sent = wire(compiled, new Map([[b58encode(signer.key), new Uint8Array(64).fill(1)]]));
    try {
      await feature("solana:signTransaction").signTransaction({ account, transaction: sent });
      verdict("S06", false, "signed");
    } catch (error) {
      verdict("S06", error?.code === 4001, `rejected ${errorText(error)}`);
    }
  },
  async S07() {
    write("S07 durable nonce (AdvanceNonceAccount first): expect X08 (만료 없음). Sign-only; the nonce account is made up.");
    const signer = await ensureCoSigner();
    const advance = {
      program: SYSTEM_PROGRAM,
      accounts: [
        { key: signer.key, signer: false, writable: true },
        { key: key32(RECENT_BLOCKHASHES), signer: false, writable: false },
        { key: me(), signer: true, writable: false }
      ],
      data: [4, 0, 0, 0]
    };
    const compiled = compile({ payer: me(), instructions: [advance, memo("Your Wallet test dApp nonce", me())], blockhash: blockhash() });
    await signOne("S07", compiled);
    try {
      await feature("solana:signAndSendTransaction").signAndSendTransaction({ account, transaction: wire(compiled) });
      verdict("S07 send", false, "a durable-nonce send was accepted");
    } catch (error) {
      verdict("S07 send", error?.code === -32602, `send refused ${errorText(error)}`);
    }
  },
  async S08() {
    // Another recipient gets 0.001 SOL, above the 890,880-lamport rent-exempt minimum, so a new
    // (never funded) address does not fail preflight with InsufficientFundsForRent.
    const to = recipient();
    const lamports = sameKey(to, me()) ? 1_000 : 1_000_000;
    write(`S08 send: memo + ${lamports.toLocaleString("en-US")} lamports to the recipient (yourself when empty). Expect 서명 후 전송, then the activity row.`);
    const compiled = compile({
      version: 0,
      payer: me(),
      instructions: [transfer(me(), to, lamports), memo("Your Wallet test dApp send", me())],
      blockhash: blockhash()
    });
    await sendOne("S08", compiled, { preflightCommitment: "confirmed" });
  },
  async S09() {
    write("S09 send with skipPreflight (the 전송 방식 field says so).");
    await sendOne("S09", simple(undefined, "skipPreflight"), { skipPreflight: true, maxRetries: 0 });
  },
  async S10() {
    write("S10 transaction bytes through signMessage: expect M01 차단 (the window cannot approve).");
    const sent = wire(simple(undefined, "M01"));
    try {
      await feature("solana:signMessage").signMessage({ account, message: sent });
      verdict("S10", false, "the wallet signed transaction bytes as a message");
    } catch (error) {
      verdict("S10", error?.code === 4001, `rejected ${errorText(error)}`);
    }
  },
  async P01() {
    const target = phantom();
    const { publicKey } = await target.connect();
    account = { publicKey: publicKey.toBytes(), address: publicKey.toBase58() };
    const compiled = simple(undefined, "phantom");
    const sent = wire(compiled);
    const signed = await target.signTransaction(sent);
    await checkSigned("P01 signTransaction", compiled, sent, signed);
  },
  async P02() {
    const target = phantom();
    const result = await target.signAndSendTransaction(wire(simple(undefined, "phantom send")), { skipPreflight: false });
    write(`P02 result ${JSON.stringify(result)}`);
    verdict("P02", typeof result?.signature === "string" && result?.publicKey === b58encode(me()), "{ signature: base58, publicKey: base58 }");
  },
  async P03() {
    const target = phantom();
    const compiled = simple(undefined, "phantom message form");
    const result = await target.request({ method: "signTransaction", params: { message: b58encode(compiled.message) } });
    write(`P03 result ${JSON.stringify(result)}`);
    const ok = typeof result?.signature === "string" && await verifies(me(), compiled.message, b58decode(result.signature));
    verdict("P03", ok && result.publicKey === b58encode(me()), "deprecated { message } form → { publicKey, signature } over the message");
  }
};

for (const button of document.querySelectorAll("button[data-sol-test]")) {
  button.addEventListener("click", async () => {
    const id = button.dataset.solTest;
    button.disabled = true;
    write(`---- ${id}`);
    try {
      await SOL_TESTS[id]();
    } catch (error) {
      write(`${id} aborted: ${error?.code === undefined ? error?.message ?? String(error) : errorText(error)}`);
    } finally {
      button.disabled = false;
    }
  });
}
