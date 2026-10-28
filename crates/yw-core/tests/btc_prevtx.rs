//! Previous-transaction verification (spec/08 §5, §14.2; spec/09 §4.4 BTC-N1, BTC-N2): the real
//! testnet4 transaction from the recorded Esplora `/tx/{txid}/hex` response, the amount forgery
//! of CVE-2020-14199 (`TxidMismatch`), a script that is not ours, `vout` out of range, a trailing
//! byte, a non-canonical `CompactSize`, size and zero-value limits, coinbase detection, and the
//! txid taken from the original non-witness bytes.

use yw_core::btc::BTC_MAX_PREV_TX_BYTES;
use yw_core::btc::amount::Sats;
use yw_core::btc::prevtx::{PrevTxError, verify_prev_output};
use yw_core::btc::script::p2wpkh_script_pubkey;
use yw_core::btc::tx::{
    OutPoint, Transaction, TxIn, TxOut, TxParseError, Txid, parse_transaction, serialize, txid,
};
use yw_core::hex;

/// Raw `curl -i` output of `GET /testnet4/api/tx/005aa50e…77f1/hex` (2026-10-27).
const TESTNET4_TX_HEX_HTTP: &[u8] = include_bytes!("vectors/btc/esplora/testnet4-tx-hex.http");
const TESTNET4_TXID: &str = "005aa50eb8346e3f199f2b9292049b3eea0dcc4567cb3d45853c11a0b0eb77f1";
/// vout 0 pays `tb1q0dzcgv7scppjxsnwlzpkt02vlmc5rtr40wyjgr`.
const TESTNET4_PROGRAM: &str = "7b458433d0c04323426ef88365bd4cfef141ac75";
const TESTNET4_VALUE: u64 = 5_840_453_620_191;

/// The HTTP body (after the blank line) decoded from hex.
fn fixture_raw() -> Option<Vec<u8>> {
    let split = TESTNET4_TX_HEX_HTTP
        .windows(4)
        .position(|window| window == b"\r\n\r\n")?;
    let body = core::str::from_utf8(TESTNET4_TX_HEX_HTTP.get(split + 4..)?).ok()?;
    hex::decode(body).ok()
}

fn ours() -> [u8; 22] {
    p2wpkh_script_pubkey(&[0x33; 20])
}

/// A segwit previous transaction paying `ours()` at vout 1 (`value`), plus another output.
fn prev_tx(value: u64) -> Transaction {
    Transaction {
        version: 2,
        inputs: vec![TxIn {
            prevout: OutPoint {
                txid: Txid::from_bytes([0x77; 32]),
                vout: 3,
            },
            script_sig: Vec::new(),
            sequence: 0xffff_fffd,
            witness: vec![vec![0x30; 71], vec![0x02; 33]],
        }],
        outputs: vec![
            TxOut {
                value: Sats::new(50_000).unwrap_or_default(),
                script_pubkey: p2wpkh_script_pubkey(&[0x44; 20]).to_vec(),
            },
            TxOut {
                value: Sats::new(value).unwrap_or_default(),
                script_pubkey: ours().to_vec(),
            },
        ],
        lock_time: 123_456,
    }
}

/// Byte offset of `needle` in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[test]
fn prev_tx_real_testnet4_fixture() {
    let raw = fixture_raw().unwrap();
    assert_eq!(raw.len(), 225);
    let expected_txid = Txid::from_display_hex(TESTNET4_TXID).unwrap();
    assert_eq!(txid(&parse_transaction(&raw).unwrap()), expected_txid);
    let program: [u8; 20] = hex::decode_array(TESTNET4_PROGRAM).unwrap();
    let verified =
        verify_prev_output(&raw, &expected_txid, 0, &p2wpkh_script_pubkey(&program)).unwrap();
    assert_eq!(verified.value.get(), TESTNET4_VALUE);
    assert_eq!(
        verified.outpoint,
        OutPoint {
            txid: expected_txid,
            vout: 0
        }
    );
    assert!(!verified.is_coinbase);
    // vout 1 is a P2PKH output: not our script.
    assert_eq!(
        verify_prev_output(&raw, &expected_txid, 1, &p2wpkh_script_pubkey(&program)),
        Err(PrevTxError::ScriptMismatch)
    );
}

/// CVE-2020-14199: the indexer returns the right txid with one amount byte changed.
#[test]
fn prev_tx_amount_forgery_rejected() {
    let raw = fixture_raw().unwrap();
    let expected_txid = Txid::from_display_hex(TESTNET4_TXID).unwrap();
    let script = p2wpkh_script_pubkey(&hex::decode_array(TESTNET4_PROGRAM).unwrap());
    let at = find(&raw, &TESTNET4_VALUE.to_le_bytes()).unwrap();
    for offset in at..at + 8 {
        let mut forged = raw.clone();
        forged[offset] ^= 0x01;
        // The top byte's low bit lifts the value above MAX_MONEY: rejected by the parser first.
        let expected = if offset == at + 7 {
            PrevTxError::Malformed(TxParseError::ValueTooLarge)
        } else {
            PrevTxError::TxidMismatch
        };
        assert_eq!(
            verify_prev_output(&forged, &expected_txid, 0, &script),
            Err(expected),
            "{offset}"
        );
    }
    // Same with a synthetic transaction: inflate the value of our output.
    let tx = prev_tx(10_000);
    let raw = serialize(&tx, true);
    let expected = txid(&tx);
    let at = find(&raw, &10_000_u64.to_le_bytes()).unwrap();
    let mut forged = raw.clone();
    forged[at + 2] = 0x10;
    let forged_tx = parse_transaction(&forged).unwrap();
    assert!(forged_tx.outputs[1].value.get() > 10_000);
    assert_eq!(
        verify_prev_output(&forged, &expected, 1, &ours()),
        Err(PrevTxError::TxidMismatch)
    );
    assert_eq!(
        verify_prev_output(&raw, &expected, 1, &ours()).map(|v| v.value.get()),
        Ok(10_000)
    );
}

#[test]
fn prev_tx_script_not_ours_rejected() {
    let tx = prev_tx(10_000);
    let raw = serialize(&tx, true);
    let expected = txid(&tx);
    assert_eq!(
        verify_prev_output(&raw, &expected, 0, &ours()),
        Err(PrevTxError::ScriptMismatch)
    );
    assert_eq!(
        verify_prev_output(&raw, &expected, 1, &p2wpkh_script_pubkey(&[0x34; 20])),
        Err(PrevTxError::ScriptMismatch)
    );
    assert!(verify_prev_output(&raw, &expected, 1, &ours()).is_ok());
}

#[test]
fn prev_tx_vout_oob() {
    let tx = prev_tx(10_000);
    let raw = serialize(&tx, true);
    let expected = txid(&tx);
    for vout in [2, 3, u32::MAX] {
        assert_eq!(
            verify_prev_output(&raw, &expected, vout, &ours()),
            Err(PrevTxError::VoutOutOfRange)
        );
    }
}

#[test]
fn prev_tx_trailing_byte() {
    let tx = prev_tx(10_000);
    let mut raw = serialize(&tx, true);
    let expected = txid(&tx);
    raw.push(0);
    assert_eq!(
        verify_prev_output(&raw, &expected, 1, &ours()),
        Err(PrevTxError::Malformed(TxParseError::TrailingBytes))
    );
}

#[test]
fn prev_tx_noncanonical_compactsize() {
    let tx = prev_tx(10_000);
    let raw = serialize(&tx, false);
    let expected = txid(&tx);
    // Output count 2 re-encoded as fd 02 00: same value, different bytes.
    let at = 4 + 1 + 32 + 4 + 1 + 4;
    assert_eq!(raw[at], 2);
    let mut noncanonical = raw[..at].to_vec();
    noncanonical.extend_from_slice(&[0xfd, 0x02, 0x00]);
    noncanonical.extend_from_slice(&raw[at + 1..]);
    assert_eq!(
        verify_prev_output(&noncanonical, &expected, 1, &ours()),
        Err(PrevTxError::Malformed(TxParseError::NonMinimalCompactSize))
    );
    assert!(verify_prev_output(&raw, &expected, 1, &ours()).is_ok());
}

#[test]
fn prev_tx_size_zero_value_and_coinbase() {
    let tx = prev_tx(10_000);
    let raw = serialize(&tx, true);
    let expected = txid(&tx);
    let mut too_large = raw.clone();
    too_large.resize(BTC_MAX_PREV_TX_BYTES + 1, 0);
    assert_eq!(
        verify_prev_output(&too_large, &expected, 1, &ours()),
        Err(PrevTxError::TooLarge)
    );
    let zero = prev_tx(0);
    assert_eq!(
        verify_prev_output(&serialize(&zero, true), &txid(&zero), 1, &ours()),
        Err(PrevTxError::ZeroValue)
    );
    let mut coinbase = prev_tx(10_000);
    coinbase.inputs[0].prevout = OutPoint::COINBASE;
    coinbase.inputs[0].witness.clear();
    coinbase.inputs[0].script_sig = vec![0x03, 0x01, 0x02, 0x03];
    let verified =
        verify_prev_output(&serialize(&coinbase, true), &txid(&coinbase), 1, &ours()).unwrap();
    assert!(verified.is_coinbase);
    assert!(
        !verify_prev_output(&raw, &expected, 1, &ours())
            .unwrap()
            .is_coinbase
    );
}

/// The txid covers the non-witness bytes only: witness changes keep it, so the amount (which is
/// in the non-witness part) is still bound by the hash.
#[test]
fn prev_tx_txid_from_original_non_witness_bytes() {
    let tx = prev_tx(10_000);
    let raw = serialize(&tx, true);
    let expected = txid(&tx);
    let legacy = serialize(&tx, false);
    assert!(verify_prev_output(&legacy, &expected, 1, &ours()).is_ok());
    let at = find(&raw, &[0x30; 71]).unwrap();
    let mut other_witness = raw.clone();
    other_witness[at] = 0x31;
    assert_eq!(
        verify_prev_output(&other_witness, &expected, 1, &ours()).map(|v| v.value.get()),
        Ok(10_000)
    );
    // Any non-witness byte change (here the lock time) breaks the txid.
    let mut other_lock = raw.clone();
    let last = other_lock.len() - 1;
    other_lock[last] ^= 1;
    assert_eq!(
        verify_prev_output(&other_lock, &expected, 1, &ours()),
        Err(PrevTxError::TxidMismatch)
    );
    let wrong = Txid::from_bytes([0; 32]);
    assert_eq!(
        verify_prev_output(&raw, &wrong, 1, &ours()),
        Err(PrevTxError::TxidMismatch)
    );
}
