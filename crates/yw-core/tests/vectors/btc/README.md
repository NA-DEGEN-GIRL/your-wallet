# Bitcoin test data (M8)

Copied byte-for-byte; never edited (spec/09 §1 rule 6). Fetched 2026-10-27.

| File | Source | Commit | License |
|---|---|---|---|
| `key_io_valid.json`, `key_io_invalid.json`, `tx_valid.json`, `tx_invalid.json` | https://github.com/bitcoin/bitcoin/tree/master/src/test/data | `2b5b6fe231ff45a09d9e24411e4420d51ed45cab` (master, 2026-10-26) | MIT (Bitcoin Core `COPYING`) |

`key_io_valid.json` at this commit names its chains `main`, `testnet4`, `signet` and `regtest`
(spec/08 §14.1 maps `testnet4` and `signet` to the testnet4 wallet).

## `esplora/` — live Esplora responses (spec/08 §4.5 E1–E3, spec/09 §5.10 M8-1)

Raw `curl.exe -s -i -H "Accept: application/json" <URL>` output (status line, headers, body),
kept byte-for-byte (`-text` in `.gitattributes`). Recorded 2026-10-27 from the public
mempool.space instances (not secret, no token):

| File | URL |
|---|---|
| `mainnet-block-height-0.http` | `https://mempool.space/api/block-height/0` |
| `testnet4-block-height-0.http` | `https://mempool.space/testnet4/api/block-height/0` |
| `mainnet-tip-height.http` | `https://mempool.space/api/blocks/tip/height` |
| `testnet4-tip-height.http` | `https://mempool.space/testnet4/api/blocks/tip/height` |
| `mainnet-address-used.http` | `https://mempool.space/api/address/bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu` (abandon…about `m/84'/0'/0'/0/0`) |
| `testnet4-address-used.http` | `https://mempool.space/testnet4/api/address/tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl` (abandon…about `m/84'/1'/0'/0/0`) |
| `testnet4-address-unused.http` | `https://mempool.space/testnet4/api/address/tb1q0nadvfv0ystndehjeldlac8alzu06hd05gqd6n` (random 20-byte program) |
| `testnet4-utxo.http` | `https://mempool.space/testnet4/api/address/tb1q0dzcgv7scppjxsnwlzpkt02vlmc5rtr40wyjgr/utxo` (a public address with a few confirmed UTXOs) |
| `testnet4-tx-status-confirmed.http` | `https://mempool.space/testnet4/api/tx/005aa50eb8346e3f199f2b9292049b3eea0dcc4567cb3d45853c11a0b0eb77f1/status` |
| `testnet4-tx-hex.http` | `https://mempool.space/testnet4/api/tx/005aa50eb8346e3f199f2b9292049b3eea0dcc4567cb3d45853c11a0b0eb77f1/hex` (vout 0 pays `tb1q0dzcgv7scppjxsnwlzpkt02vlmc5rtr40wyjgr`, 5,840,453,620,191 sats; §5 verification fixture) |
| `testnet4-tx-status-missing.http` | `https://mempool.space/testnet4/api/tx/05a4e2d0e59fa96e8aa280038aec7e3bc517d12a0bb8c6b7e1b411422446217a/status` (random txid → `{"confirmed":false}`) |
| `testnet4-tx-hex-missing.http` | `https://mempool.space/testnet4/api/tx/05a4e2d0e59fa96e8aa280038aec7e3bc517d12a0bb8c6b7e1b411422446217a/hex` (→ 404) |
| `testnet4-address-mainnet-400.http` | `https://mempool.space/testnet4/api/address/bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu` (mainnet address → 400) |
| `mainnet-block-height-0-trailing-slash.http` | `https://mempool.space/api/block-height/0/` (trailing `/` → 404) |
