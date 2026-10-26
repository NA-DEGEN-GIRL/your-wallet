# Test vector sources

Files are copied byte-for-byte from the sources below (spec/09 §1 rule 6, §3.1). Fetched
2026-10-27 from `raw.githubusercontent.com`; the commit is the latest commit touching the file at
that time.

| File | Source | Commit | License | Notes |
|---|---|---|---|---|
| `bip39_trezor_en.json` | https://github.com/trezor/python-mnemonic/blob/master/vectors.json | `b57a5ad77a981e743f4167ab2f7927a55c1e82a8` | MIT | Lines 1–146 of the original (the `"english"` array, 24 vectors, passphrase `"TREZOR"`) unchanged; the other languages are cut and the object is closed with `    ]` / `}`. |
| `bip32.json` | https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki (`==Test Vectors==`) | `c0644a054fd1568ecbfc9c2b656ad5200b16ff74` | BSD-2-Clause | Seeds, `ext pub`/`ext prv` strings and vector 5 keys/reasons copied verbatim into `{"valid": [{"seed", "chains": [{"path", "xpub", "xprv"}]}], "invalid": [[key, reason]]}`; the only rewrite is the path notation `0<sub>H</sub>` → `0'`. |
| `base58_encode_decode.json` | https://github.com/bitcoin/bitcoin/blob/master/src/test/data/base58_encode_decode.json | `5dd3a0d8a899e4c7263d5b999135f4d7584e1244` | MIT | Unchanged (21 `[hex, base58]` pairs). |

Inline vectors (not files):

| Test | Source | Commit | License |
|---|---|---|---|
| `tests/evm_accounts.rs` ERC-55 addresses | https://github.com/ethereum/ERCs/blob/master/ERCS/erc-55.md (`# Test Cases`) | `8dd085d159cb123f545c272c0d871a5339550e79` | CC0-1.0 |
| `src/bip39/english.txt` (word list, checked by SHA-256 in `src/bip39/tests.rs`) | https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt | `ce1862ac6bcffa1dd20aad858380e51e66e949ea` | BSD-2-Clause |

M2 inline vectors (values transcribed from spec/09 §3.5–§3.8, which records them from the
sources below; this offline session did not re-fetch the sources, so no commit is recorded):

| Test | Source | License |
|---|---|---|
| `src/evm/sign/tests.rs` EVM-V01 EIP-155 example (key `0x46`×32) | https://eips.ethereum.org/EIPS/eip-155 (`Example`) | CC0-1.0 |
| `src/evm/sign/tests.rs` EVM-V02 EIP-1559 (Besu) | ethereumjs `packages/tx/test/testData/eip1559.ts` ("// Source: Besu") | MPL-2.0 |
| `src/evm/sign/tests.rs` EVM-V03 `Some data` | web3.js `accounts.sign` documentation | LGPL-3.0 |
| `src/evm/sign/tests.rs` EVM-V03 `Hello, world!` | MetaMask eth-sig-util `src/personal-sign.test.ts` | ISC |
| `src/evm/sign/tests.rs`, `tests/evm_eip712.rs` Ether Mail | EIPs `assets/eip-712/Example.js` (JSON as in `archive/spec-v2.4:crates/eip712/tests/vectors.rs:6-42`) | CC0-1.0 |
| `tests/evm_consts.rs` selectors, topics, typeHashes, domain separators | computed by the test from the signature strings of spec/09 §3.6–§3.7 | — |
| `crates/yw-app/tests/fixtures/eth_simulateV1/*.response.json` | spec/09 §3.8 S1–S16 shapes; S1h/S3c/S4h/S16 follow the 2026-10-27 probe (`docs/acceptance/probe-20261027.md`) | — |
