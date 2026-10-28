//! Transactions (spec/08 §6.4–§6.6, §7.2, §14.1): Bitcoin Core `tx_valid.json` (every
//! serialization parses and re-serializes identically) and `tx_invalid.json` (no panic), commit
//! `2b5b6fe231ff45a09d9e24411e4420d51ed45cab`; the BIP143 native P2WPKH example (bitcoin/bips
//! `bip-0143.mediawiki`, commit `24e96e870fffaa257b465ce1f0370c14aac588e8`: hash parts, sighash,
//! signed transaction round trip, txid, weight, vsize); each strict parser rule; the size
//! estimate and dust tables.

use yw_core::btc::MAX_MONEY;
use yw_core::btc::address::ScriptKind;
use yw_core::btc::amount::Sats;
use yw_core::btc::script::{
    dust_threshold, output_vbytes, p2wpkh_script_code, p2wpkh_script_pubkey, spend_size, spk_len,
};
use yw_core::btc::sighash::{bip143_sighash_p2wpkh, hash_outputs, hash_prevouts, hash_sequence};
use yw_core::btc::tx::{
    OutPoint, Transaction, TxOut, TxParseError, Txid, estimate_vsize, estimate_weight,
    parse_transaction, serialize, sha256d, txid, vsize, weight, wtxid,
};
use yw_core::hex::{self, HexError};
use yw_json::{Limits, Value};

const TX_VALID: &str = include_str!("vectors/btc/tx_valid.json");
const TX_INVALID: &str = include_str!("vectors/btc/tx_invalid.json");

const BIP143_UNSIGNED: &str = "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000";
const BIP143_SIGNED: &str = "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000";

/// Serialized transactions of a Core `tx_*.json` file (comment rows skipped).
fn core_transactions(text: &str) -> Option<Vec<Vec<u8>>> {
    let root = yw_json::parse(text.as_bytes(), &Limits::RESPONSE).ok()?;
    let mut out = Vec::new();
    for entry in root.as_array()? {
        let entry = entry.as_array()?;
        if entry.len() == 1 && entry.first()?.as_str().is_some() {
            continue;
        }
        let serialized = entry.get(1).and_then(Value::as_str)?;
        out.push(hex::decode(serialized).ok()?);
    }
    Some(out)
}

#[test]
fn core_tx_valid_round_trip() {
    let transactions = core_transactions(TX_VALID).unwrap();
    assert!(transactions.len() > 100, "{}", transactions.len());
    for bytes in &transactions {
        let parsed = parse_transaction(bytes);
        assert!(parsed.is_ok(), "{parsed:?}: {}", hex::encode(bytes));
        let tx = parsed.unwrap();
        assert_eq!(&serialize(&tx, true), bytes);
        assert_eq!(txid(&tx), txid(&parse_transaction(bytes).unwrap()));
        assert_eq!(Txid::from_bytes(sha256d(&serialize(&tx, false))), txid(&tx));
    }
}

#[test]
fn core_tx_invalid_no_panic() {
    let transactions = core_transactions(TX_INVALID).unwrap();
    assert!(transactions.len() > 50, "{}", transactions.len());
    let mut parsed = 0;
    for bytes in &transactions {
        if let Ok(tx) = parse_transaction(bytes) {
            assert_eq!(&serialize(&tx, true), bytes);
            parsed += 1;
        }
    }
    // Script-level failures still parse; structural ones (e.g. no outputs) do not.
    assert!(parsed > 0 && parsed < transactions.len());
}

#[test]
fn bip143_native_p2wpkh() {
    let unsigned_bytes = hex::decode(BIP143_UNSIGNED).unwrap();
    let unsigned = parse_transaction(&unsigned_bytes).unwrap();
    assert_eq!(serialize(&unsigned, true), unsigned_bytes);
    assert_eq!(unsigned.version, 1);
    assert_eq!(unsigned.lock_time, 17);
    assert_eq!(unsigned.inputs.len(), 2);
    assert_eq!(unsigned.outputs.len(), 2);
    assert_eq!(unsigned.outputs[0].value.get(), 112_340_000);
    assert_eq!(
        hex::encode(&hash_prevouts(&unsigned)),
        "96b827c8483d4e9b96712b6713a7b68d6e8003a781feba36c31143470b4efd37"
    );
    assert_eq!(
        hex::encode(&hash_sequence(&unsigned)),
        "52b0a642eea2fb7ae638c36f6252b6750293dbe574a806984b8e4d8548339a3b"
    );
    assert_eq!(
        hex::encode(&hash_outputs(&unsigned)),
        "863ef3e1a92afbfdb97f31ad0fc7683ee943e9abcf2501590ff8f6551f47e5e5"
    );
    let program: [u8; 20] = hex::decode_array("1d0f172a0ecb48aee1be1f2687d2963ae33f71a1").unwrap();
    assert_eq!(
        hex::encode(&p2wpkh_script_code(&program)),
        "1976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac"
    );
    let sighash =
        bip143_sighash_p2wpkh(&unsigned, 1, &program, Sats::new(600_000_000).unwrap()).unwrap();
    assert_eq!(
        hex::encode(&sighash),
        "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"
    );
    // A different amount changes the digest (BIP143 commits the input amount).
    assert_ne!(
        bip143_sighash_p2wpkh(&unsigned, 1, &program, Sats::new(600_000_001).unwrap()),
        Some(sighash)
    );

    let signed_bytes = hex::decode(BIP143_SIGNED).unwrap();
    let signed = parse_transaction(&signed_bytes).unwrap();
    assert_eq!(serialize(&signed, true), signed_bytes);
    assert_eq!(signed.inputs[1].witness.len(), 2);
    assert!(signed.inputs[0].witness.is_empty());
    assert_eq!(
        txid(&signed).to_display_hex(),
        "e8151a2af31c368a35053ddd4bdb285a8595c769a3ad83e0fa02314a602d4609"
    );
    // The first (P2PK) input's scriptSig is part of the txid; the witness is not.
    let mut stripped = signed.clone();
    stripped.inputs[1].witness.clear();
    assert_eq!(txid(&stripped), txid(&signed));
    assert_ne!(txid(&signed), txid(&unsigned));
    assert_eq!(
        hex::encode(&wtxid(&signed)),
        "62b709c9126ae7782ea86576b338f39211199d149dced92423df070937386cc3"
    );
    assert_eq!(weight(&signed), 1042);
    assert_eq!(vsize(&signed), 261);
    // No witness: weight = 4 × size.
    assert_eq!(
        weight(&unsigned),
        4 * u64::try_from(unsigned_bytes.len()).unwrap()
    );
    assert_eq!(weight(&stripped), 4 * 233);
}

/// version ‖ [marker flag] ‖ inputs ‖ outputs ‖ [witness] ‖ `lock_time`, from raw parts.
fn assemble(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

const VERSION: [u8; 4] = [2, 0, 0, 0];
const LOCK: [u8; 4] = [0, 0, 0, 0];

fn one_input() -> Vec<u8> {
    let mut out = vec![1];
    out.extend_from_slice(&[0xab; 32]);
    out.extend_from_slice(&[0, 0, 0, 0, 0]); // vout 0, empty scriptSig
    out.extend_from_slice(&[0xfd, 0xff, 0xff, 0xff]);
    out
}

fn output(value: u64) -> Vec<u8> {
    let mut out = value.to_le_bytes().to_vec();
    out.push(22);
    out.extend_from_slice(&p2wpkh_script_pubkey(&[0x11; 20]));
    out
}

fn outputs(values: &[u64]) -> Vec<u8> {
    let mut out = vec![u8::try_from(values.len()).unwrap_or(0)];
    for value in values {
        out.extend(output(*value));
    }
    out
}

/// Every rule of spec/08 §6.5 with a minimal counter-example.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one counter-example per spec/08 §6.5 rule"
)]
fn strict_parser_rules() {
    let legacy = assemble(&[&VERSION, &one_input(), &outputs(&[1_000]), &LOCK]);
    let tx = parse_transaction(&legacy).unwrap();
    assert_eq!(serialize(&tx, true), legacy);
    assert!(!tx.has_witness());
    assert_eq!(wtxid(&tx), txid(&tx).to_bytes());
    let witness = [1, 1, 0x42];
    let segwit = assemble(&[
        &VERSION,
        &[0, 1],
        &one_input(),
        &outputs(&[1_000]),
        &witness,
        &LOCK,
    ]);
    let tx = parse_transaction(&segwit).unwrap();
    assert_eq!(tx.inputs[0].witness, vec![vec![0x42]]);
    assert_eq!(serialize(&tx, true), segwit);
    assert_eq!(serialize(&tx, false), legacy);

    let cases: Vec<(Vec<u8>, TxParseError)> = vec![
        // Non-minimal CompactSize (input count 1 as fd 01 00).
        (
            assemble(&[
                &VERSION,
                &[0xfd, 0x01, 0x00],
                &one_input()[1..],
                &outputs(&[1_000]),
                &LOCK,
            ]),
            TxParseError::NonMinimalCompactSize,
        ),
        (
            assemble(&[&VERSION, &one_input(), &[0xfe, 0x02, 0, 0, 0], &LOCK]),
            TxParseError::NonMinimalCompactSize,
        ),
        (
            assemble(&[
                &VERSION,
                &one_input(),
                &[0xff, 2, 0, 0, 0, 0, 0, 0, 0],
                &LOCK,
            ]),
            TxParseError::NonMinimalCompactSize,
        ),
        // Above 0x0200_0000.
        (
            assemble(&[&VERSION, &[0xfe, 0x01, 0x00, 0x00, 0x02], &LOCK]),
            TxParseError::CompactSizeTooLarge,
        ),
        // Script length (256) above the remaining bytes (10).
        (
            assemble(&[
                &VERSION,
                &[1],
                &[0xab; 32],
                &[0, 0, 0, 0],
                &[0xfd, 0x00, 0x01],
                &[0; 10],
            ]),
            TxParseError::CompactSizeTooLarge,
        ),
        // 3 inputs × 41 bytes do not fit.
        (
            assemble(&[&VERSION, &[3], &one_input()[1..], &outputs(&[1]), &LOCK]),
            TxParseError::CompactSizeTooLarge,
        ),
        // Segwit marker without flag 1.
        (
            assemble(&[&VERSION, &[0, 2], &one_input(), &outputs(&[1]), &LOCK]),
            TxParseError::InvalidSegwitFlag,
        ),
        (
            assemble(&[&VERSION, &[0, 0], &one_input(), &outputs(&[1]), &LOCK]),
            TxParseError::InvalidSegwitFlag,
        ),
        // Segwit form with only empty witnesses.
        (
            assemble(&[&VERSION, &[0, 1], &one_input(), &outputs(&[1]), &[0], &LOCK]),
            TxParseError::EmptyWitnesses,
        ),
        // Segwit form with no inputs.
        (
            assemble(&[&VERSION, &[0, 1, 0], &outputs(&[1]), &LOCK]),
            TxParseError::NoInputs,
        ),
        (
            assemble(&[&VERSION, &one_input(), &[0], &LOCK]),
            TxParseError::NoOutputs,
        ),
        (
            assemble(&[&VERSION, &one_input(), &outputs(&[MAX_MONEY + 1]), &LOCK]),
            TxParseError::ValueTooLarge,
        ),
        (
            assemble(&[&VERSION, &one_input(), &outputs(&[u64::MAX]), &LOCK]),
            TxParseError::ValueTooLarge,
        ),
        (
            assemble(&[&VERSION, &one_input(), &outputs(&[MAX_MONEY, 1]), &LOCK]),
            TxParseError::TotalTooLarge,
        ),
        (
            assemble(&[&VERSION, &one_input(), &outputs(&[1]), &LOCK, &[0]]),
            TxParseError::TrailingBytes,
        ),
        (
            assemble(&[&VERSION, &one_input(), &outputs(&[1]), &LOCK[..3]]),
            TxParseError::Truncated,
        ),
    ];
    for (bytes, expected) in cases {
        assert_eq!(
            parse_transaction(&bytes),
            Err(expected),
            "{}",
            hex::encode(&bytes)
        );
    }
    // MAX_MONEY in one output (or in total) is still accepted.
    let max = assemble(&[&VERSION, &one_input(), &outputs(&[MAX_MONEY]), &LOCK]);
    assert_eq!(parse_transaction(&max).unwrap().outputs[0].value, Sats::MAX);
    // Every strict prefix of a valid transaction is rejected without panicking.
    let signed = hex::decode(BIP143_SIGNED).unwrap();
    for end in 0..signed.len() {
        assert!(parse_transaction(&signed[..end]).is_err(), "{end}");
    }
}

#[test]
fn coinbase_and_outpoints() {
    let mut input = vec![1];
    input.extend_from_slice(&[0; 32]);
    input.extend_from_slice(&[0xff; 4]);
    input.extend_from_slice(&[2, 0x51, 0x00, 0xff, 0xff, 0xff, 0xff]);
    let coinbase =
        parse_transaction(&assemble(&[&VERSION, &input, &outputs(&[50]), &LOCK])).unwrap();
    assert!(coinbase.is_coinbase());
    assert_eq!(coinbase.inputs[0].prevout, OutPoint::COINBASE);
    let normal =
        parse_transaction(&assemble(&[&VERSION, &one_input(), &outputs(&[50]), &LOCK])).unwrap();
    assert!(!normal.is_coinbase());
    let outpoint = OutPoint {
        txid: Txid::from_display_hex(
            "005aa50eb8346e3f199f2b9292049b3eea0dcc4567cb3d45853c11a0b0eb77f1",
        )
        .unwrap(),
        vout: 7,
    };
    assert_eq!(
        outpoint.to_string(),
        "005aa50eb8346e3f199f2b9292049b3eea0dcc4567cb3d45853c11a0b0eb77f1:7"
    );
}

#[test]
fn txid_display_order() {
    let text = "e8151a2af31c368a35053ddd4bdb285a8595c769a3ad83e0fa02314a602d4609";
    let id = Txid::from_display_hex(text).unwrap();
    assert_eq!(id.as_bytes()[0], 0x09);
    assert_eq!(id.as_bytes()[31], 0xe8);
    assert_eq!(id.to_display_hex(), text);
    assert_eq!(id.to_string(), text);
    assert_eq!(format!("{id:?}"), format!("Txid({text})"));
    assert_eq!(
        Txid::from_display_hex(&text.to_ascii_uppercase()),
        Err(HexError::InvalidDigit)
    );
    assert_eq!(
        Txid::from_display_hex(&text[..62]),
        Err(HexError::InvalidLength)
    );
    assert_eq!(
        Txid::from_display_hex(&format!("{text}00")),
        Err(HexError::InvalidLength)
    );
}

/// spec/08 §7.2 examples and the formula's domain.
#[test]
fn size_estimates() {
    assert_eq!(estimate_vsize(1, &[22, 22]), Some(141));
    assert_eq!(estimate_vsize(1, &[22]), Some(110));
    assert_eq!(estimate_vsize(2, &[22, 22]), Some(208));
    assert_eq!(estimate_vsize(3, &[34]), Some(257));
    assert_eq!(estimate_weight(1, &[22]), Some(42 + 271 + 4 * 31));
    assert_eq!(estimate_weight(0, &[22]), None);
    assert_eq!(estimate_weight(1, &[]), None);
    assert_eq!(estimate_weight(253, &[22]), None);
    assert_eq!(estimate_weight(1, &[253]), None);
    assert!(estimate_weight(252, &[22, 34]).is_some());
}

/// spec/08 §6.4 table: scriptPubKey length, output vbytes and dust per kind, and the dust
/// formula `(output + spending input) × 3`.
#[test]
fn script_templates_and_dust() {
    let rows = [
        (ScriptKind::P2pkh([0; 20]), 25, 34, 546),
        (ScriptKind::P2sh([0; 20]), 23, 32, 540),
        (ScriptKind::P2wpkh([0; 20]), 22, 31, 294),
        (ScriptKind::P2wsh([0; 32]), 34, 43, 330),
        (ScriptKind::P2tr([0; 32]), 34, 43, 330),
    ];
    for (kind, length, vbytes, dust) in rows {
        assert_eq!(spk_len(&kind), length);
        assert_eq!(output_vbytes(&kind), vbytes);
        assert_eq!(output_vbytes(&kind), 9 + u64::try_from(length).unwrap());
        assert_eq!(dust_threshold(&kind).get(), dust);
        assert_eq!((output_vbytes(&kind) + spend_size(&kind)) * 3, dust);
        let tx = Transaction {
            version: 2,
            inputs: Vec::new(),
            outputs: vec![TxOut {
                value: Sats::ZERO,
                script_pubkey: yw_core::btc::address::script_pubkey(&kind),
            }],
            lock_time: 0,
        };
        // version 4 + n_in 1 + n_out 1 + lock 4 = 10 bytes around the output.
        assert_eq!(
            serialize(&tx, false).len(),
            10 + usize::try_from(vbytes).unwrap()
        );
    }
    assert_eq!(yw_core::btc::BTC_CHANGE_DUST, 294);
}
