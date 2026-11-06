// 개발용 RPC 실측 프로브 (spec/01 §4.7, spec/03 §1.5, spec/09 §2.5)
// - 설정: 환경 변수 YW_RPC_JSON(파일 경로) 또는 %USERPROFILE%\.yw-dev\rpc.json
// - URL·호스트·토큰은 출력하지 않는다. 오류 메시지는 엔드포인트 정보를 가린 뒤 80자까지만 보여준다.
// - 지갑 앱은 이 파일을 쓰지 않는다. check.ps1에 포함하지 않는다(수동 실행).
// 실행: node scripts/probe-rpc.mjs
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { decodeUtf8, isPlainObject, parseStrictJson } from './lib/strict-json.mjs';

const MAX_CONFIG_BYTES = 64 * 1024;
// spec/01 §4.6: compare real paths (symlinks/junctions resolved) so the file cannot live in the repo.
const REPO = fs.realpathSync(path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..'));
const cfgPath = process.env.YW_RPC_JSON || path.join(os.homedir(), '.yw-dev', 'rpc.json');
const insideRepo = (target) => {
  const relative = path.relative(REPO, target);
  return relative === '' || (relative !== '..' && !relative.startsWith('..' + path.sep) && !path.isAbsolute(relative));
};
const cannotRead = () => {
  console.error('설정 파일을 읽을 수 없습니다: rpc.json');
  process.exit(1);
};
let realCfgPath;
try {
  realCfgPath = fs.realpathSync(cfgPath);
} catch {
  cannotRead();
}
if (insideRepo(realCfgPath)) {
  console.error('설정 파일이 저장소 안에 있습니다. 저장소 밖에 두세요.');
  process.exit(1);
}
let cfg;
try {
  const bytes = fs.readFileSync(realCfgPath);
  if (bytes.length > MAX_CONFIG_BYTES) throw new Error('too large');
  cfg = parseStrictJson(decodeUtf8(bytes, 'rpc.json'));   // BOM is stripped by TextDecoder
  if (!isPlainObject(cfg)) throw new Error('not an object');
} catch {
  cannotRead();
}

const secrets = [];
for (const v of Object.values(cfg)) {
  try {
    const u = new URL(v);
    secrets.push(u.host, ...u.pathname.split('/').filter((s) => s.length >= 8));
  } catch { /* ignore */ }
}
const redact = (s) => {
  let t = String(s ?? '');
  for (const x of secrets) if (x) t = t.split(x).join('[redacted]');
  return t.replace(/https?:\/\/\S+/g, '[url]').slice(0, 80);
};

let failures = 0;
const out = (net, probe, ok, kv) => {
  if (!ok) failures++;
  const parts = Object.entries(kv).map(([k, v]) => `${k}=${v}`);
  console.log(`${net.padEnd(16)} ${probe.padEnd(22)} ${ok ? 'ok ' : 'err'} ${parts.join(' ')}`);
};

async function rpc(url, method, params, timeoutMs = 20000) {
  const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method, params });
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), timeoutMs);
  const t0 = Date.now();
  try {
    const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body, signal: ac.signal });
    const ms = Date.now() - t0;
    const text = await r.text();
    let j;
    try { j = JSON.parse(text); } catch { return { http: r.status, ms, parseError: true }; }
    return { http: r.status, ms, result: j.result, error: j.error };
  } catch (e) {
    return { http: 0, ms: Date.now() - t0, transport: e.name === 'AbortError' ? 'timeout' : 'network' };
  } finally {
    clearTimeout(timer);
  }
}

const errKv = (r) => r.transport ? { transport: r.transport }
  : r.parseError ? { http: r.http, body: 'not-json' }
  : { http: r.http, code: r.error?.code ?? '-', msg: JSON.stringify(redact(r.error?.message)) };

const randAddr = () => '0x' + crypto.randomBytes(20).toString('hex');
const hex = (n) => '0x' + BigInt(n).toString(16);
const TRANSFER = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
const EEEE = '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';
const FFFE = '0xfffffffffffffffffffffffffffffffffffffffe';
const REVERT_CODE = '0x63deadbeef6000526004601cfd'; // PUSH4 deadbeef; PUSH1 0; MSTORE; PUSH1 4; PUSH1 28; REVERT

const EVM = [
  { id: 'eip155:1', chainId: '0x1', genesis: '0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3' },
  { id: 'eip155:11155111', chainId: '0xaa36a7', genesis: '0x25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9' },
  { id: 'eip155:999', chainId: '0x3e7', genesis: null },
  // 2026-11-06 built-ins (spec/03 §1.1; QuickNode arbitrum-mainnet / base-mainnet / bsc / robinhood-mainnet).
  { id: 'eip155:42161', chainId: '0xa4b1', genesis: '0x7ee576b35482195fc49205cec9af72ce14f003b9ae69f6ba0faef4514be8b442' },
  { id: 'eip155:8453', chainId: '0x2105', genesis: '0xf712aa9241cc24369b143cf6dce85f0902a9731e70d66818a3a5845b296c73dd', opStack: true },
  { id: 'eip155:56', chainId: '0x38', genesis: '0x0d21840abff46b96c84b2ac9e10e4f5cdaeb5693cb665db62a2f3b02d2d57b5b' },
  { id: 'eip155:4663', chainId: '0x1237', genesis: '0xaad15f3d702aaea00caf3e9bb56395efe9127bc3b31b24921abf1eee3409305c' },
];

// OP-stack GasPriceOracle predeploy (spec/03 §3.4a): getL1Fee(bytes) of a 100-byte sample.
const GAS_PRICE_ORACLE = '0x420000000000000000000000000000000000000F';
const GET_L1_FEE_SAMPLE = '0x49948e0e'
  + (32).toString(16).padStart(64, '0')
  + (100).toString(16).padStart(64, '0')
  + '01'.repeat(100).padEnd(128 * 2, '0');

function summarizeCall(call) {
  const logs = call.logs ?? [];
  const native = logs.filter((l) => l.topics?.[0] === TRANSFER && [EEEE, FFFE].includes(String(l.address).toLowerCase()));
  const emitters = [...new Set(native.map((l) => String(l.address).toLowerCase() === EEEE ? 'eeee' : 'fffe'))];
  return {
    status: call.status,
    gasUsed: call.gasUsed ? BigInt(call.gasUsed).toString() : '-',
    maxUsedGas: call.maxUsedGas ? BigInt(call.maxUsedGas).toString() : '-',
    logs: logs.length,
    nativeEmitter: emitters.join('+') || 'none',
    errCode: call.error?.code ?? '-',
    revertData: call.error?.data ?? (call.status === '0x0' ? call.returnData : '-'),
  };
}

async function probeEvm(net, url, label = net.id) {
  const c = await rpc(url, 'eth_chainId', []);
  out(label, 'eth_chainId', c.result === net.chainId, c.result !== undefined ? { chainId: c.result, ms: c.ms } : errKv(c));
  const g = await rpc(url, 'eth_getBlockByNumber', ['0x0', false]);
  const gh = g.result?.hash;
  out(label, 'genesis', gh !== undefined && (net.genesis === null || gh === net.genesis),
    gh !== undefined ? { hash: gh, expected: net.genesis ?? 'pin-on-first-use', ms: g.ms } : errKv(g));
  const b = await rpc(url, 'eth_getBlockByNumber', ['latest', false]);
  const baseFee = b.result?.baseFeePerGas ? BigInt(b.result.baseFeePerGas) : null;
  out(label, 'latest block', baseFee !== null, baseFee !== null
    ? { number: BigInt(b.result.number).toString(), baseFeeGwei: (Number(baseFee) / 1e9).toFixed(4), gasLimit: BigInt(b.result.gasLimit).toString(), ms: b.ms }
    : errKv(b));
  if (baseFee === null) return;
  if (net.opStack) {
    const l1 = await rpc(url, 'eth_call', [{ to: GAS_PRICE_ORACLE, input: GET_L1_FEE_SAMPLE }, 'latest']);
    const ok = typeof l1.result === 'string' && /^0x[0-9a-f]{64}$/i.test(l1.result);
    out(label, 'getL1Fee(100B)', ok, ok ? { l1FeeWei: BigInt(l1.result).toString(), ms: l1.ms } : errKv(l1));
  }
  const tip = 1_000_000_000n;
  const fees = { maxFeePerGas: hex(baseFee * 2n + tip), maxPriorityFeePerGas: hex(tip) };
  const from = randAddr();
  const fund = { [from]: { balance: hex(10n ** 18n) } };

  const cases = [
    { name: 'sim fresh 1wei', state: fund, call: { from, to: randAddr(), value: '0x1', gas: hex(1_000_000), ...fees } },
    { name: 'sim self 1wei', state: fund, call: { from, to: from, value: '0x1', gas: hex(1_000_000), ...fees } },
    { name: 'sim revert', state: { ...fund, '0x00000000000000000000000000000000000000aa': { code: REVERT_CODE } },
      call: { from, to: '0x00000000000000000000000000000000000000aa', value: '0x0', input: '0x', gas: hex(1_000_000), ...fees } },
    { name: 'sim no-funds', state: {}, call: { from: randAddr(), to: randAddr(), value: hex(10n ** 18n), gas: hex(1_000_000), ...fees } },
    { name: 'sim chainId+type', state: fund, call: { from, to: randAddr(), value: '0x1', gas: hex(1_000_000), ...fees, chainId: net.chainId, type: '0x2' } },
  ];
  for (const k of cases) {
    const payload = { blockStateCalls: [{ stateOverrides: k.state, calls: [k.call] }], traceTransfers: true, validation: true };
    const r = await rpc(url, 'eth_simulateV1', [payload, 'latest'], 30000);
    if (Array.isArray(r.result) && r.result[0]?.calls?.[0]) {
      out(label, k.name, true, { ...summarizeCall(r.result[0].calls[0]), ms: r.ms });
    } else {
      out(label, k.name, false, errKv(r));
    }
  }
}

async function main() {
  for (const net of EVM) {
    const url = cfg[net.id];
    if (!url) { console.log(`${net.id.padEnd(16)} skip`); continue; }
    await probeEvm(net, url);
    if (net.id === 'eip155:999' && /\/evm\/?$/.test(url)) {
      await probeEvm(net, url.replace(/\/evm\/?$/, '/nanoreth'), 'eip155:999/nano');
    }
  }
  const sol = { 'solana:mainnet': '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d', 'solana:devnet': 'EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG' };
  for (const [id, exp] of Object.entries(sol)) {
    if (!cfg[id]) { console.log(`${id.padEnd(16)} skip`); continue; }
    const r = await rpc(cfg[id], 'getGenesisHash', []);
    out(id, 'getGenesisHash', r.result === exp, r.result !== undefined ? { hash: r.result, ms: r.ms } : errKv(r));
  }
  const btc = { 'bitcoin:mainnet': '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f', 'bitcoin:testnet4': '00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043' };
  for (const [id, exp] of Object.entries(btc)) {
    if (!cfg[id]) { console.log(`${id.padEnd(16)} skip`); continue; }
    const r = await rpc(cfg[id], 'getblockhash', [0]);
    out(id, 'getblockhash 0', r.result === exp, r.result !== undefined ? { hash: r.result, ms: r.ms } : errKv(r));
    const i = await rpc(cfg[id], 'getblockchaininfo', []);
    out(id, 'getblockchaininfo', !!i.result, i.result ? { chain: i.result.chain, blocks: i.result.blocks, ms: i.ms } : errKv(i));
    const bb = await rpc(cfg[id], 'bb_getBlockHash', ['0']);
    out(id, 'bb_getBlockHash 0', bb.result !== undefined, bb.result !== undefined ? { result: JSON.stringify(bb.result).slice(0, 80), ms: bb.ms } : errKv(bb));
  }
  // Zcash (spec/12 §4): genesis pin, consensus branch, the address index the app needs, and
  // Blockbook REST under the same endpoint. Read-only calls only (no sendrawtransaction).
  const zec = { 'zcash:mainnet': '00040fe8ec8471911baa1db1266ea15dd06b4a8a5c453883c000b031973dce08', 'zcash:testnet': '05a60a92d99d85997cce3b87616c089f6124d7342af37106edc76126334a2c38' };
  for (const [id, exp] of Object.entries(zec)) {
    if (!cfg[id]) { console.log(`${id.padEnd(16)} skip`); continue; }
    const r = await rpc(cfg[id], 'getblockhash', [0]);
    out(id, 'getblockhash 0', r.result === exp, r.result !== undefined ? { hash: r.result, ms: r.ms } : errKv(r));
    const i = await rpc(cfg[id], 'getblockchaininfo', []);
    out(id, 'getblockchaininfo', !!(i.result && i.result.consensus), i.result ? { chain: i.result.chain, blocks: i.result.blocks, nextblock: i.result.consensus && i.result.consensus.nextblock, ms: i.ms } : errKv(i));
    // A well-known empty-ish address is not needed: an invalid-address error still proves the
    // method exists (-5 / -8), while -32601 means no address index.
    const u = await rpc(cfg[id], 'getaddressutxos', [{ addresses: [] }]);
    out(id, 'getaddressutxos', u.result !== undefined || (u.error && u.error.code !== -32601), u.result !== undefined ? { rows: u.result.length, ms: u.ms } : errKv(u));
  }
  console.log(`summary: ${failures === 0 ? 'all ok' : `${failures} check(s) not ok`}`);
  process.exit(failures === 0 ? 0 : 1);
}
main().catch(() => { console.error('probe failed'); process.exit(1); });
