# Test vector sources

Files are copied byte-for-byte from the sources below (spec/09 §1 rule 6, §3.1). Fetched
2026-10-27 from `raw.githubusercontent.com`; the commit is the latest commit touching the file at
that time.

| File | Source | Commit | License | Notes |
|---|---|---|---|---|
| `bip39_trezor_en.json` | https://github.com/trezor/python-mnemonic/blob/master/vectors.json | `b57a5ad77a981e743f4167ab2f7927a55c1e82a8` | MIT | Lines 1–146 of the original (the `"english"` array, 24 vectors, passphrase `"TREZOR"`) unchanged; the other languages are cut and the object is closed with `    ]` / `}`. |
| `bip32.json` | https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki (`==Test Vectors==`) | `c0644a054fd1568ecbfc9c2b656ad5200b16ff74` | BSD-2-Clause | Seeds, `ext pub`/`ext prv` strings and vector 5 keys/reasons copied verbatim into `{"valid": [{"seed", "chains": [{"path", "xpub", "xprv"}]}], "invalid": [[key, reason]]}`; the only rewrite is the path notation `0<sub>H</sub>` → `0'`. |
| `base58_encode_decode.json` | https://github.com/bitcoin/bitcoin/blob/master/src/test/data/base58_encode_decode.json | `5dd3a0d8a899e4c7263d5b999135f4d7584e1244` | MIT | Unchanged (21 `[hex, base58]` pairs). |
| `slip10_ed25519.json` (M7) | https://github.com/satoshilabs/slips/blob/master/slip-0010.md (`### Test vector 1 for ed25519`, `### Test vector 2 for ed25519`) | `a00312491693714d9bc1b6e4cb5b2e356e6c511e` | not stated in the document | Seeds and every chain's `fingerprint`/`chain code`/`private`/`public` copied verbatim into `[{"seed", "chains": [{"path", "fingerprint", "chain_code", "private", "public"}]}]` (2 seeds, 12 chains); the only rewrite is the path notation `0<sub>H</sub>` → `0'`. |
| `rfc8032.json` (M7) | https://www.rfc-editor.org/rfc/rfc8032.txt §7.1 (`-----TEST 1`, `2`, `3`, `1024`, `SHA(abc)`) | RFC (immutable) | IETF Trust, BCP 78 | `SECRET KEY`/`PUBLIC KEY`/`MESSAGE`/`SIGNATURE` hex of the five Ed25519 tests, line breaks and spaces removed, into `{"source", "tests": [{"test", "secret_key", "public_key", "message", "signature"}]}`. |

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

M8 Bitcoin data (`btc/`, details and the Esplora recording list in `btc/README.md`):

| File | Source | Commit | License | Notes |
|---|---|---|---|---|
| `btc/key_io_valid.json`, `btc/key_io_invalid.json`, `btc/tx_valid.json`, `btc/tx_invalid.json` | https://github.com/bitcoin/bitcoin/tree/master/src/test/data | `2b5b6fe231ff45a09d9e24411e4420d51ed45cab` | MIT | Unchanged. At this commit `key_io_valid.json` names its chains `main`, `testnet4`, `signet`, `regtest`; `tests/btc_address.rs` maps `testnet4` and `signet` to the testnet4 wallet (spec/08 §14.1 `test`), regtest bech32 (`bcrt`) to `WrongNetwork` and regtest base58 to the testnet4 result. Used by `tests/btc_address.rs`, `tests/btc_tx.rs`, `tests/btc_fuzz_lite.rs`. |
| `btc/esplora/*.http` | public mempool.space Esplora API (URLs in `btc/README.md`) | recorded 2026-10-27 | — (server responses, no token) | Raw `curl -i` output kept byte-for-byte (`-text`). `testnet4-tx-hex.http` (tx `005aa50e…77f1`, vout 0 = 5,840,453,620,191 sats to program `7b458433…ac75`) is the real-world spec/08 §5 fixture of `tests/btc_prevtx.rs` and a `btc_fuzz_lite` seed. |

M8 inline vectors (copied from bitcoin/bips at commit `24e96e870fffaa257b465ce1f0370c14aac588e8`,
fetched 2026-10-27; BSD-2-Clause):

| Test | Source |
|---|---|
| `tests/btc_bech32.rs` string vectors (BIP173 valid 7 / invalid 12, BIP350 valid 7 / invalid 14) and the segwit address lists; `tests/btc_address.rs` BIP350 address vectors (valid 8 / invalid 15) and the spec/08 §14.1 table | https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki (`===Test vectors===`), https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki (`==Test vectors==`) |
| `src/btc/tests.rs` BIP84 account node, `0/0`, `0/1`, `1/0` keys and addresses (`abandon`×11 `about`); testnet4 `m/84'/1'/0'` rows and the 24-word `art` rows are spec/08 §14.1 / spec/09 §3.10 [local] values | https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki (`==Test vectors==`) |
| `src/btc/tests.rs`, `tests/btc_tx.rs`, `tests/btc_fuzz_lite.rs` BIP143 native P2WPKH example (unsigned and signed transactions, hash parts, sighash, private key, signature) | https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki (`=== Native P2WPKH ===`) |
| `src/bip32/tests.rs` `derive_public_child` (CKDpub) | the existing `bip32.json` vectors 1–2 |

Address types (spec/08 §3.5), fetched 2026-10-29; files in `btc/` (commits in `btc/README.md`),
inline values copied from bitcoin/bips at commit `24e96e870fffaa257b465ce1f0370c14aac588e8`
(BSD-2-Clause):

| Test (`src/btc/types_tests.rs`) | Source |
|---|---|
| `bip49_vector` (`uprv`/`upub` body, `0/0` key, key hash, redeem script, `2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2`) | https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki (`==Test vectors==`) |
| `bip84_vector_through_accounts` | https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki (`==Test vectors==`) |
| `bip86_vector` (root/account `xprv`/`xpub`, internal/output keys, scriptPubKeys, addresses) | https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki (`==Test vectors==`) |
| `bip143_p2sh_p2wpkh_vector` | https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki (`=== P2SH-P2WPKH ===`) |
| `bip341_script_pubkey_vectors`, `bip341_key_path_vectors` | `btc/bip341_wallet_test_vectors.json` (bitcoin/bips `bip-0341/wallet-test-vectors.json`) |
| `legacy_sighash_core_vectors` | `btc/sighash.json` (Bitcoin Core `src/test/data/sighash.json`, MIT) |

BIP44 publishes no test vector; `bip44_public_equals_private` checks the path against private
derivation only.
