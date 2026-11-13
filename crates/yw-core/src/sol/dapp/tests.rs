//! dApp transactions (spec/07 §20.2–§20.4, spec/09 SOL-N6–N10 core parts): the legacy/v0 parser
//! with every sanitize negative, re-encoding identity and the M01 invariant, signature slots,
//! durable-nonce detection, lookup tables and their resolution, the instruction decoders with
//! exact lengths, and the fee range computed from the message.
#![expect(
    clippy::indexing_slicing,
    reason = "test fixtures index buffers of known length"
)]

use ed25519_dalek::{Signer as _, SigningKey};

use super::alt::{
    AltError, KeyRole, LOOKUP_TABLE_MAX_DATA, LookupTable, ResolvedKeys, full_keys, lookup_tables,
    parse_lookup_table, resolve,
};
use super::decode::{
    ATA_MISMATCH, AtaIx, AuthorityType, CbIx, DecodedIx, MALFORMED, SystemIx, TokenIx, UNRESOLVED,
    decode, decode_message,
};
use super::parse::{
    LookupRef, MessageHeader, SOL_TX_MAX_IX, SolTxError, SolTxMessage, SolTxVersion,
    encode_message_any, parse_message_any, parse_wire_tx,
};
use crate::hex;
use crate::sol::address::{
    ADDRESS_LOOKUP_TABLE_PROGRAM, ATA_PROGRAM, COMPUTE_BUDGET_PROGRAM, ED25519_PRECOMPILE,
    MEMO_PROGRAM_V1, MEMO_PROGRAM_V2, SECP256K1_PRECOMPILE, SECP256R1_PRECOMPILE, STAKE_PROGRAM,
    SYSTEM_PROGRAM, SYSVAR_RECENT_BLOCKHASHES, SolAddress, TOKEN_2022_PROGRAM, TOKEN_PROGRAM,
    program_name,
};
use crate::sol::fee::{DappFeeBounds, dapp_fee_bounds, max_fee};
use crate::sol::message::CompiledIx;
use crate::sol::msgsign::looks_like_transaction;
use crate::sol::pda::associated_token_address;
use crate::sol::shortvec;
use crate::sol::template::{
    set_compute_unit_limit_data, set_compute_unit_price_data, system_transfer_data,
    transfer_checked_data,
};

fn key(byte: u8) -> SolAddress {
    SolAddress::from_bytes([byte; 32])
}

fn addr(text: &str) -> SolAddress {
    SolAddress::parse(text).unwrap()
}

fn ix(program: u8, accounts: &[u8], data: &[u8]) -> CompiledIx {
    CompiledIx {
        program,
        accounts: accounts.to_vec(),
        data: data.to_vec(),
    }
}

/// Encodes a message without validating it (positives and negatives alike).
fn message(
    version: SolTxVersion,
    header: [u8; 3],
    keys: &[SolAddress],
    instructions: Vec<CompiledIx>,
    lookups: Vec<LookupRef>,
) -> Vec<u8> {
    encode_message_any(&SolTxMessage {
        version,
        header: MessageHeader {
            required: header[0],
            readonly_signed: header[1],
            readonly_unsigned: header[2],
        },
        static_keys: keys.to_vec(),
        blockhash: [7; 32],
        instructions,
        lookups,
    })
}

fn legacy(header: [u8; 3], keys: &[SolAddress], instructions: Vec<CompiledIx>) -> Vec<u8> {
    message(SolTxVersion::Legacy, header, keys, instructions, Vec::new())
}

fn lookup(table: u8, writable: &[u8], readonly: &[u8]) -> LookupRef {
    LookupRef {
        table: key(table),
        writable: writable.to_vec(),
        readonly: readonly.to_vec(),
    }
}

/// `shortvec(n) ‖ signatures ‖ message`.
fn wire(signatures: &[[u8; 64]], message: &[u8]) -> Vec<u8> {
    let mut out = shortvec::encode(u16::try_from(signatures.len()).unwrap());
    for signature in signatures {
        out.extend_from_slice(signature);
    }
    out.extend_from_slice(message);
    out
}

/// The solana-sdk `test_sdk_serialize` transaction (spec/07 §17.3; `core/sol/tests.rs`).
fn sdk_tx() -> Vec<u8> {
    hex::decode(concat!(
        "01788aa2b93bd1f19d479d4a830457361c26b4de52403e3d3e162e11cbbb883e2b0b26eb11ef52f08b82d9e3d609f28ddf5e1db86e3e",
        "2057893f8b64dd148904050100010324649efc21a161b93e5963c3faf9bbbdab76f15af80e44dbe73e9d058e1bd27501010104050607",
        "0809090909090909090909090909090909080706050401010102020204050607080901010101010101010101010101010908070605",
        "040202020000000000000000000000000000000000000000000000000000000000000000010202000103010203",
    ))
    .unwrap()
}

/// The `T_SOL` golden message (spec/07 §17.3): limit 450, price 1,000.
fn t_sol_message() -> Vec<u8> {
    hex::decode(concat!(
        "01000204",
        "f036276246a75b9de3349ed42b15e232f6518fc20f5fcd4f1d64e81f9bd258f7",
        "f8029acf5cbcbdd5ac46ec147f3b78a3df6e5022ef0411db2bab650d329a4cd4",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0306466fe5211732ffecadba72c39be7bc8ce5bbc5f7126b2c439b3a40000000",
        "0707070707070707070707070707070707070707070707070707070707070707",
        "03",
        "03000502c2010000",
        "03000903e803000000000000",
        "020200010c0200000040420f0000000000",
    ))
    .unwrap()
}

/// A hand-assembled v0 message with two tables: payer `0x11…`, Memo v2; one Memo instruction
/// over accounts `[0, 2, 3, 4]`; table `0xa1…` loads writable 5 and read-only 0, table `0xa2…`
/// writable 1. Load order: `a1[5]`, `a2[1]` (writable), then `a1[0]`.
fn v0_message() -> Vec<u8> {
    let mut out = vec![0x80, 1, 0, 1, 2];
    out.extend_from_slice(&[0x11; 32]);
    out.extend_from_slice(MEMO_PROGRAM_V2.as_bytes());
    out.extend_from_slice(&[7; 32]);
    out.extend_from_slice(&[1, 1, 4, 0, 2, 3, 4, 2, b'h', b'i']);
    out.push(2);
    out.extend_from_slice(&[0xa1; 32]);
    out.extend_from_slice(&[1, 5, 1, 0]);
    out.extend_from_slice(&[0xa2; 32]);
    out.extend_from_slice(&[1, 1, 0]);
    out
}

/// A lookup table account body.
fn table_data(
    addresses: &[SolAddress],
    authority: Option<SolAddress>,
    last_extended_slot: u64,
    start: u8,
    deactivation_slot: u64,
) -> Vec<u8> {
    let mut data = vec![0_u8; 56];
    data[..4].copy_from_slice(&1_u32.to_le_bytes());
    data[4..12].copy_from_slice(&deactivation_slot.to_le_bytes());
    data[12..20].copy_from_slice(&last_extended_slot.to_le_bytes());
    data[20] = start;
    if let Some(authority) = authority {
        data[21] = 1;
        data[22..54].copy_from_slice(authority.as_bytes());
    } else {
        // Freezing leaves the old authority bytes behind the `None` tag.
        data[22..54].copy_from_slice(&[0xee; 32]);
    }
    for address in addresses {
        data.extend_from_slice(address.as_bytes());
    }
    data
}

/// The two tables of [`v0_message`], last extended at slot 10.
fn v0_tables() -> Vec<(SolAddress, LookupTable)> {
    let a1: Vec<SolAddress> = (0x30..=0x35).map(key).collect();
    let a2 = [key(0x40), key(0x41)];
    vec![
        (
            key(0xa1),
            parse_lookup_table(
                &ADDRESS_LOOKUP_TABLE_PROGRAM,
                &table_data(&a1, Some(key(0x99)), 10, 3, u64::MAX),
            )
            .unwrap(),
        ),
        (
            key(0xa2),
            parse_lookup_table(
                &ADDRESS_LOOKUP_TABLE_PROGRAM,
                &table_data(&a2, None, 10, 0, u64::MAX),
            )
            .unwrap(),
        ),
    ]
}

/// The M01 half of spec/07 §20.2: whatever the dApp parser accepts, the message signer blocks.
fn assert_m01(bytes: &[u8]) {
    assert!(
        parse_wire_tx(bytes).is_ok() || parse_message_any(bytes).is_ok(),
        "not a positive vector"
    );
    assert!(looks_like_transaction(bytes));
}

// ----- parser -------------------------------------------------------------------------------

#[test]
fn legacy_vectors_parse_with_identity() {
    let tx = sdk_tx();
    let parsed = parse_wire_tx(&tx).unwrap();
    assert_eq!(parsed.to_bytes(), tx);
    assert_eq!(parsed.signatures.len(), 1);
    assert_eq!(parsed.message_bytes, tx[65..]);
    let message = &parsed.message;
    assert_eq!(message.version, SolTxVersion::Legacy);
    assert_eq!(
        message.header,
        MessageHeader {
            required: 1,
            readonly_signed: 0,
            readonly_unsigned: 1
        }
    );
    assert_eq!(message.instruction_count(), 1);
    let (program, accounts, data) = message.instruction(0).unwrap();
    assert_eq!(
        (program, accounts, data),
        (
            &message.static_keys[2],
            [0_u8, 1].as_slice(),
            [1_u8, 2, 3].as_slice()
        )
    );
    assert_eq!(message.program_ids(), [message.static_keys[2]]);
    assert_eq!(message.fee_payer(), Some(message.static_keys[0]));
    assert_eq!(message.account_count(), 3);
    assert_eq!(
        (0..4)
            .map(|index| message.is_writable_static(index))
            .collect::<Vec<_>>(),
        [true, true, false, false]
    );
    assert!(message.is_signer(0) && !message.is_signer(1));
    assert_eq!(parse_message_any(&tx[65..]).unwrap(), parsed.message);

    let golden = t_sol_message();
    let parsed = parse_message_any(&golden).unwrap();
    assert_eq!(encode_message_any(&parsed), golden);
    assert_eq!(parsed.program_ids()[2], SYSTEM_PROGRAM);
    let signed = wire(&[[0; 64]], &golden);
    assert_eq!(parse_wire_tx(&signed).unwrap().message, parsed);
    for bytes in [tx.clone(), tx[65..].to_vec(), golden, signed] {
        assert_m01(&bytes);
    }
}

#[test]
fn v0_with_two_tables_parses_in_load_order() {
    let bytes = v0_message();
    let message = parse_message_any(&bytes).unwrap();
    assert_eq!(encode_message_any(&message), bytes);
    assert_eq!(message.version, SolTxVersion::V0);
    assert_eq!(message.static_keys, [key(0x11), MEMO_PROGRAM_V2]);
    assert_eq!(
        message.lookups,
        [lookup(0xa1, &[5], &[0]), lookup(0xa2, &[1], &[])]
    );
    assert_eq!(message.loaded_counts(), (2, 1));
    assert_eq!(message.account_count(), 5);
    assert_eq!(
        (0..6)
            .map(|index| message.is_writable_index(index))
            .collect::<Vec<_>>(),
        [true, false, true, true, false, false]
    );
    assert_eq!(lookup_tables(&message), [key(0xa1), key(0xa2)]);

    let resolved = resolve(&message, &v0_tables(), 11).unwrap();
    assert_eq!(
        resolved,
        ResolvedKeys {
            writable: vec![key(0x35), key(0x41)],
            readonly: vec![key(0x30)],
        }
    );
    let role = |signer, writable, table: Option<u8>| KeyRole {
        signer,
        writable,
        table: table.map(key),
    };
    assert_eq!(
        full_keys(&message, Some(&resolved)),
        [
            (key(0x11), role(true, true, None)),
            (MEMO_PROGRAM_V2, role(false, false, None)),
            (key(0x35), role(false, true, Some(0xa1))),
            (key(0x41), role(false, true, Some(0xa2))),
            (key(0x30), role(false, false, Some(0xa1))),
        ]
    );
    assert_eq!(full_keys(&message, None).len(), 2);
    let short = ResolvedKeys {
        writable: vec![key(0x35)],
        readonly: Vec::new(),
    };
    assert_eq!(full_keys(&message, Some(&short)).len(), 2);
    assert_eq!(
        decode_message(&message, &full_keys(&message, Some(&resolved))),
        [DecodedIx::Memo(b"hi".to_vec())]
    );
    assert_eq!(
        decode_message(&message, &full_keys(&message, None)),
        [DecodedIx::Unknown {
            reason: Some(UNRESOLVED)
        }]
    );

    let signed = wire(&[[0x44; 64]], &bytes);
    let parsed = parse_wire_tx(&signed).unwrap();
    assert_eq!(parsed.message, message);
    assert_eq!(parsed.slot(0), Some(&[0x44; 64]));
    assert_eq!(parsed.slot(1), None);
    assert_m01(&bytes);
    assert_m01(&signed);
    // Every prefix of the transaction is refused.
    for len in 0..signed.len() {
        assert!(parse_wire_tx(&signed[..len]).is_err(), "{len}");
    }
}

#[test]
#[expect(clippy::too_many_lines, reason = "one case per spec/07 §20.2 rule")]
fn sanitize_negatives() {
    let keys = [key(0x11), key(0x12), MEMO_PROGRAM_V1];
    let memo = || vec![ix(2, &[0], b"m")];
    assert!(parse_message_any(&legacy([1, 0, 1], &keys, memo())).is_ok());
    assert_eq!(parse_message_any(&[]), Err(SolTxError::Empty));
    assert_eq!(parse_wire_tx(&[]), Err(SolTxError::Empty));

    // Versions: 0x80 is v0, anything above is refused by its prefix.
    for prefix in [0x81_u8, 0xff] {
        let mut bytes = v0_message();
        bytes[0] = prefix;
        assert_eq!(parse_message_any(&bytes), Err(SolTxError::Version(prefix)));
        assert_eq!(
            parse_wire_tx(&wire(&[[0; 64]], &bytes)),
            Err(SolTxError::Version(prefix))
        );
    }

    // Header inequalities: 1 ≤ required ≤ static, readonly_signed < required,
    // readonly_unsigned ≤ static − required.
    for header in [[0, 0, 1], [4, 0, 0], [1, 1, 1], [1, 0, 3], [2, 0, 2]] {
        assert_eq!(
            parse_message_any(&legacy(header, &keys, memo())),
            Err(SolTxError::Header),
            "{header:?}"
        );
    }
    assert!(parse_message_any(&legacy([2, 1, 1], &keys, memo())).is_ok());

    // More than 256 keys: static count, then static plus loaded.
    let mut many = vec![1, 0, 0];
    many.extend_from_slice(&shortvec::encode(257));
    many.extend_from_slice(&[0; 64]);
    assert_eq!(parse_message_any(&many), Err(SolTxError::TooManyKeys));
    let v0_keys = [key(0x11), MEMO_PROGRAM_V1];
    let filled = |count: u8| {
        let writable: Vec<u8> = (0..count).collect();
        message(
            SolTxVersion::V0,
            [1, 0, 1],
            &v0_keys,
            vec![ix(1, &[0, 255], b"")],
            vec![LookupRef {
                table: key(0xa1),
                writable,
                readonly: Vec::new(),
            }],
        )
    };
    let full = filled(254);
    assert_eq!(parse_message_any(&full).unwrap().account_count(), 256);
    assert_m01(&full);
    assert_eq!(
        parse_message_any(&filled(255)),
        Err(SolTxError::TooManyKeys)
    );

    // Duplicate static key; program index 0 or a loaded key; account index out of range.
    assert_eq!(
        parse_message_any(&legacy(
            [1, 0, 1],
            &[key(0x11), key(0x11), MEMO_PROGRAM_V1],
            memo()
        )),
        Err(SolTxError::DuplicateKey)
    );
    assert_eq!(
        parse_message_any(&legacy([1, 0, 1], &keys, vec![ix(0, &[], b"")])),
        Err(SolTxError::ProgramIndex)
    );
    assert_eq!(
        parse_message_any(&legacy([1, 0, 1], &keys, vec![ix(3, &[], b"")])),
        Err(SolTxError::ProgramIndex)
    );
    let v0 = |instructions, lookups| {
        message(SolTxVersion::V0, [1, 0, 1], &v0_keys, instructions, lookups)
    };
    assert_eq!(
        parse_message_any(&v0(vec![ix(2, &[], b"")], vec![lookup(0xa1, &[0], &[])])),
        Err(SolTxError::ProgramIndex)
    );
    assert_eq!(
        parse_message_any(&legacy([1, 0, 1], &keys, vec![ix(2, &[3], b"")])),
        Err(SolTxError::AccountIndex)
    );
    assert!(parse_message_any(&v0(vec![ix(1, &[2], b"")], vec![lookup(0xa1, &[0], &[])])).is_ok());
    assert_eq!(
        parse_message_any(&v0(vec![ix(1, &[3], b"")], vec![lookup(0xa1, &[0], &[])])),
        Err(SolTxError::AccountIndex)
    );
    assert_eq!(
        parse_message_any(&v0(vec![ix(1, &[], b"")], vec![lookup(0xa1, &[], &[])])),
        Err(SolTxError::EmptyLookup)
    );

    // 64 instructions are accepted, 65 are not.
    let repeated = |count: usize| legacy([1, 0, 1], &keys, vec![ix(2, &[], b""); count]);
    assert!(parse_message_any(&repeated(SOL_TX_MAX_IX)).is_ok());
    assert_m01(&repeated(SOL_TX_MAX_IX));
    assert_eq!(
        parse_message_any(&repeated(SOL_TX_MAX_IX + 1)),
        Err(SolTxError::TooManyInstructions)
    );

    // Trailing bytes after a legacy or v0 message, and after a transaction.
    for mut bytes in [legacy([1, 0, 1], &keys, memo()), v0_message()] {
        bytes.push(0);
        assert_eq!(parse_message_any(&bytes), Err(SolTxError::TrailingBytes));
        assert_eq!(
            parse_wire_tx(&wire(&[[0; 64]], &bytes)),
            Err(SolTxError::TrailingBytes)
        );
    }

    // Signature count: zero, or other than the required signers.
    let body = legacy([1, 0, 1], &keys, memo());
    assert_eq!(
        parse_wire_tx(&wire(&[], &body)),
        Err(SolTxError::SignatureCount)
    );
    assert_eq!(
        parse_wire_tx(&wire(&[[0; 64], [0; 64]], &body)),
        Err(SolTxError::SignatureCount)
    );
    let two = legacy([2, 0, 1], &keys, memo());
    assert_eq!(
        parse_wire_tx(&wire(&[[0; 64]], &two)),
        Err(SolTxError::SignatureCount)
    );
    assert!(parse_wire_tx(&wire(&[[0; 64], [0; 64]], &two)).is_ok());

    // Non-minimal compact-u16 (signature count, key count).
    let mut alias = vec![0x81, 0x00];
    alias.extend_from_slice(&[0; 64]);
    alias.extend_from_slice(&body);
    assert_eq!(parse_wire_tx(&alias), Err(SolTxError::ShortVec));
    let mut alias_keys = vec![1, 0, 1, 0x83, 0x00];
    alias_keys.extend_from_slice(&body[4..]);
    assert_eq!(parse_message_any(&alias_keys), Err(SolTxError::ShortVec));

    // Size limits: 1,233 bytes, a message over 1,232 − 65.
    assert_eq!(parse_wire_tx(&vec![1; 1_233]), Err(SolTxError::TooLarge));
    assert_eq!(
        parse_message_any(&vec![1; 1_168]),
        Err(SolTxError::TooLarge)
    );
    let largest = legacy([1, 0, 1], &keys, vec![ix(2, &[], &vec![0; 1_030])]);
    assert_eq!(largest.len(), 1_167);
    assert!(parse_message_any(&largest).is_ok());

    assert!(
        SolTxError::Version(0x81)
            .to_string()
            .starts_with("사이트 거래 형식이 올바르지 않습니다: ")
    );
}

/// SOL-N6: every single-bit flip of a v0 transaction is refused, or parses to bytes that
/// re-encode identically and are still blocked as a message (M01).
#[test]
fn every_bit_flip_is_rejected_or_identical() {
    let tx = wire(&[[0x44; 64]], &v0_message());
    let mut rejected = 0;
    for index in 0..tx.len() {
        for bit in 0..8 {
            let mut flipped = tx.clone();
            flipped[index] ^= 1 << bit;
            match parse_wire_tx(&flipped) {
                Err(_) => rejected += 1,
                Ok(parsed) => {
                    assert_eq!(parsed.to_bytes(), flipped, "{index}:{bit}");
                    assert!(looks_like_transaction(&flipped), "{index}:{bit}");
                }
            }
        }
    }
    assert!(rejected > 0);
}

#[test]
fn signer_slots_and_foreign_signatures() {
    let payer = SigningKey::from_bytes(&[1; 32]);
    let ours = SigningKey::from_bytes(&[2; 32]);
    let payer_key = SolAddress::from_bytes(payer.verifying_key().to_bytes());
    let our_key = SolAddress::from_bytes(ours.verifying_key().to_bytes());
    let bytes = legacy(
        [2, 0, 2],
        &[payer_key, our_key, key(0x13), MEMO_PROGRAM_V1],
        vec![ix(3, &[0, 1, 2], b"x")],
    );
    let message = parse_message_any(&bytes).unwrap();
    assert_eq!(message.signer_slot(payer_key.as_bytes()), Ok(0));
    assert_eq!(message.signer_slot(our_key.as_bytes()), Ok(1));
    // A non-signer occurrence, or no occurrence, is refused.
    assert_eq!(
        message.signer_slot(key(0x13).as_bytes()),
        Err(SolTxError::NotSigner)
    );
    assert_eq!(
        message.signer_slot(key(0x77).as_bytes()),
        Err(SolTxError::NotSigner)
    );
    assert_eq!(message.fee_payer(), Some(payer_key));

    let unsigned = parse_wire_tx(&wire(&[[0; 64], [0; 64]], &bytes)).unwrap();
    // Sign-only: the other slot may stay empty; a send needs it.
    assert!(unsigned.foreign_signatures_ok(1, false));
    assert!(!unsigned.foreign_signatures_ok(1, true));
    let payer_signature = payer.sign(&bytes).to_bytes();
    let partial = parse_wire_tx(&wire(&[payer_signature, [0; 64]], &bytes)).unwrap();
    assert!(partial.foreign_signatures_ok(1, true));
    let mut forged = payer_signature;
    forged[0] ^= 1;
    let bad = parse_wire_tx(&wire(&[forged, [0; 64]], &bytes)).unwrap();
    assert!(!bad.foreign_signatures_ok(1, false));
    // Our own slot is never judged here.
    assert!(
        parse_wire_tx(&wire(&[payer_signature, [0x55; 64]], &bytes))
            .unwrap()
            .foreign_signatures_ok(1, true)
    );

    // Only our 64 bytes change and the result still parses to the same message.
    let our_signature = ours.sign(&bytes).to_bytes();
    let signed = partial.with_signature(1, &our_signature).unwrap();
    let before = partial.to_bytes();
    assert_eq!(signed.len(), before.len());
    let changed: Vec<usize> = (0..signed.len())
        .filter(|index| signed[*index] != before[*index])
        .collect();
    assert!(changed.iter().all(|index| (65..129).contains(index)));
    let reparsed = parse_wire_tx(&signed).unwrap();
    assert_eq!(reparsed.message_bytes, bytes);
    assert_eq!(reparsed.slot(1), Some(&our_signature));
    assert_eq!(reparsed.slot(0), Some(&payer_signature));
    assert!(reparsed.foreign_signatures_ok(0, true));
    assert!(reparsed.foreign_signatures_ok(1, true));
    assert_eq!(
        partial.with_signature(2, &our_signature),
        Err(SolTxError::NotSigner)
    );
    assert_m01(&signed);
}

// ----- durable nonce, precompiles, ComputeBudget ----------------------------------------------

#[test]
fn durable_nonce_detection() {
    // Keys: payer (writable signer), nonce (writable), RecentBlockhashes (read-only), System.
    let keys = [
        key(0x11),
        key(0x12),
        SYSVAR_RECENT_BLOCKHASHES,
        SYSTEM_PROGRAM,
    ];
    let nonce_of = |instructions: Vec<CompiledIx>| {
        parse_message_any(&legacy([1, 0, 2], &keys, instructions))
            .unwrap()
            .durable_nonce()
    };
    let advance = [4, 0, 0, 0];
    assert_eq!(
        nonce_of(vec![ix(3, &[1, 2, 0], &advance)]),
        Some((1, Some(0)))
    );
    assert_eq!(
        nonce_of(vec![ix(3, &[1, 2, 0], &[4, 0, 0, 0, 0xff])]),
        Some((1, Some(0)))
    );
    assert_eq!(nonce_of(vec![ix(3, &[1], &advance)]), Some((1, None)));
    assert_eq!(nonce_of(vec![ix(3, &[1, 2], &advance)]), Some((1, None)));
    // The decoder needs three accounts; the nonce rule does not.
    assert_eq!(
        decode(&SYSTEM_PROGRAM, &[key(0x12), key(0x13)], &advance),
        DecodedIx::Unknown {
            reason: Some(MALFORMED)
        }
    );
    assert_eq!(nonce_of(vec![ix(3, &[2, 1, 0], &advance)]), None);
    assert_eq!(nonce_of(vec![ix(3, &[], &advance)]), None);
    assert_eq!(nonce_of(vec![ix(2, &[1, 2, 0], &advance)]), None);
    assert_eq!(nonce_of(vec![ix(3, &[1, 2, 0], &[5, 0, 0, 0])]), None);
    assert_eq!(nonce_of(vec![ix(3, &[1, 2, 0], &[4, 0, 0])]), None);
    assert_eq!(
        nonce_of(vec![
            ix(3, &[0, 1], &system_transfer_data(1)),
            ix(3, &[1, 2, 0], &advance),
        ]),
        None
    );
    assert_eq!(nonce_of(vec![]), None);

    // v0: a loaded writable nonce account counts, a loaded read-only one does not.
    let v0 = |accounts: &[u8]| {
        parse_message_any(&message(
            SolTxVersion::V0,
            [1, 0, 1],
            &[key(0x11), SYSTEM_PROGRAM],
            vec![ix(1, accounts, &advance)],
            vec![lookup(0xa1, &[0], &[1])],
        ))
        .unwrap()
        .durable_nonce()
    };
    assert_eq!(v0(&[2, 3]), Some((2, None)));
    assert_eq!(v0(&[3, 2]), None);
}

#[test]
fn precompile_signatures_and_compute_budget_duplicates() {
    let mut ed25519 = vec![2, 0];
    ed25519.extend_from_slice(&[0; 28]);
    let mut secp256k1 = vec![1];
    secp256k1.extend_from_slice(&[0; 11]);
    let keys = [
        key(0x11),
        ED25519_PRECOMPILE,
        SECP256K1_PRECOMPILE,
        COMPUTE_BUDGET_PROGRAM,
    ];
    let parsed = |instructions| parse_message_any(&legacy([1, 0, 3], &keys, instructions)).unwrap();
    let message = parsed(vec![ix(1, &[], &ed25519), ix(2, &[], &secp256k1)]);
    assert_eq!(message.precompile_signatures(), 3);
    assert!(!dapp_fee_bounds(&message).rejected);
    let limit = set_compute_unit_limit_data(1_000);
    let price = set_compute_unit_price_data(5);
    assert!(!dapp_fee_bounds(&parsed(vec![ix(3, &[], &limit), ix(3, &[], &price)])).rejected);
    assert!(dapp_fee_bounds(&parsed(vec![ix(3, &[], &limit), ix(3, &[], &limit)])).rejected);
}

/// The runtime's parse of `ComputeBudget` data (Agave `try_from_slice_unchecked`), not the
/// strict display decoder, sets the fee (2026-11-13 review).
#[test]
fn dapp_fee_bounds_read_compute_budget_like_the_runtime() {
    let keys = [key(0x11), COMPUTE_BUDGET_PROGRAM, SYSTEM_PROGRAM];
    let bounds = |instructions: Vec<CompiledIx>| {
        dapp_fee_bounds(&parse_message_any(&legacy([1, 0, 2], &keys, instructions)).unwrap())
    };
    let exact = |fee: u128| DappFeeBounds {
        low: fee,
        high: fee,
        rejected: false,
    };
    let rejected = DappFeeBounds {
        low: 5_000,
        high: 5_000,
        rejected: true,
    };
    let trailing = |mut data: Vec<u8>| {
        data.push(0xff);
        data
    };
    let transfer = || ix(2, &[0, 0], &system_transfer_data(1));
    // A price with a trailing byte still charges: the display shows Unknown (X02), the fee
    // does not drop to the base fee. Limit 1,400,000 × 10^12 micro-lamports.
    let price = trailing(set_compute_unit_price_data(1_000_000_000_000));
    assert!(matches!(
        decode(&COMPUTE_BUDGET_PROGRAM, &[], &price),
        DecodedIx::Unknown { .. }
    ));
    assert_eq!(
        bounds(vec![
            ix(1, &[], &set_compute_unit_limit_data(1_400_000)),
            ix(1, &[], &price),
            transfer(),
        ]),
        exact(5_000 + 1_400_000_000_000)
    );
    // Without a limit the default units still apply (2 builtins × 3,000).
    assert_eq!(
        bounds(vec![ix(1, &[], &price), transfer()]),
        exact(5_000 + 6_000_000_000)
    );
    // A limit with a trailing byte is that limit, not the default.
    assert_eq!(
        bounds(vec![
            ix(1, &[], &trailing(set_compute_unit_limit_data(1_400_000))),
            ix(1, &[], &set_compute_unit_price_data(1_000_000)),
            transfer(),
        ]),
        exact(5_000 + 1_400_000)
    );
    // A valid heap request and data-size limit, with trailing bytes, change nothing.
    let mut heap = vec![1];
    heap.extend_from_slice(&(32_u32 * 1_024).to_le_bytes());
    let mut size = vec![4];
    size.extend_from_slice(&1_u32.to_le_bytes());
    assert_eq!(
        bounds(vec![
            ix(1, &[], &trailing(heap)),
            ix(1, &[], &trailing(size)),
            transfer()
        ]),
        exact(5_000)
    );
    // What the runtime rejects (no fee; getFeeForMessage answers the base fee): a short field,
    // tag 0 (Unused) or 5, a duplicate kind, a bad heap request, a data-size limit of 0.
    let price = || ix(1, &[], &set_compute_unit_price_data(1_000_000));
    let heap = |bytes: u32| {
        let mut data = vec![1];
        data.extend_from_slice(&bytes.to_le_bytes());
        ix(1, &[], &data)
    };
    for bad in [
        ix(1, &[], &[3, 1, 2, 3, 4, 5, 6, 7]),
        ix(1, &[], &[2, 1, 2, 3]),
        ix(1, &[], &[]),
        ix(1, &[], &[0]),
        ix(1, &[], &[5, 0, 0, 0, 0]),
        price(),
        ix(1, &[], &set_compute_unit_price_data(7)),
        heap(31 * 1_024),
        heap(257 * 1_024),
        heap(32 * 1_024 + 1),
        ix(1, &[], &[4, 0, 0, 0, 0]),
    ] {
        assert_eq!(
            bounds(vec![price(), bad.clone(), transfer()]),
            rejected,
            "{bad:?}"
        );
    }
    assert_eq!(
        bounds(vec![
            ix(1, &[], &set_compute_unit_limit_data(10)),
            price(),
            ix(1, &[], &set_compute_unit_limit_data(10)),
        ]),
        rejected
    );
}

#[test]
fn dapp_fee_bounds_follow_the_runtime() {
    let exact = |fee: u128| DappFeeBounds {
        low: fee,
        high: fee,
        rejected: false,
    };
    // T_SOL golden: one signature, limit 450, price 1,000 → the template formula.
    let golden = parse_message_any(&t_sol_message()).unwrap();
    assert_eq!(
        dapp_fee_bounds(&golden),
        exact(u128::from(max_fee(450, 1_000).unwrap()))
    );

    let keys = [
        key(0x11),
        key(0x12),
        MEMO_PROGRAM_V1,
        COMPUTE_BUDGET_PROGRAM,
        ED25519_PRECOMPILE,
        SYSTEM_PROGRAM,
        STAKE_PROGRAM,
        SECP256R1_PRECOMPILE,
    ];
    let bounds = |header: [u8; 3], instructions: Vec<CompiledIx>| {
        dapp_fee_bounds(&parse_message_any(&legacy(header, &keys, instructions)).unwrap())
    };
    let memo = || ix(2, &[], b"m");
    let transfer = || ix(5, &[0, 1], &system_transfer_data(1));
    let price = ix(3, &[], &set_compute_unit_price_data(1_000_000));
    // No limit: 3,000 per builtin instruction (ComputeBudget itself included), 200,000 for the
    // others (Agave SIMD-0170). The old estimate gave 400,000 here, 3,000 CU too low.
    assert_eq!(
        bounds([1, 0, 6], vec![price.clone(), memo(), memo()]),
        exact(5_000 + 403_000)
    );
    // An honest priority-fee transfer without a limit: 2 × 3,000 CU, not 200,000.
    assert_eq!(
        bounds([1, 0, 6], vec![price.clone(), transfer()]),
        exact(5_000 + 6_000)
    );
    // Capped at 1,400,000; no price, no priority fee whatever the limit.
    let mut eight = vec![price.clone()];
    eight.extend(std::iter::repeat_with(memo).take(8));
    assert_eq!(bounds([1, 0, 6], eight), exact(5_000 + 1_400_000));
    assert_eq!(bounds([1, 0, 6], vec![memo(); 8]), exact(5_000));
    // A migrating builtin (Stake) is 3,000 before its Core BPF feature and 200,000 after it:
    // the range brackets both.
    let stake = bounds([1, 0, 6], vec![price.clone(), ix(6, &[], &[0; 4])]);
    assert_eq!(
        stake,
        DappFeeBounds {
            low: 5_000 + 6_000,
            high: 5_000 + 203_000,
            rejected: false,
        }
    );
    assert!(stake.contains(11_000) && stake.contains(208_000) && stake.contains(100_000));
    assert!(!stake.contains(10_999) && !stake.contains(208_001));
    // With a limit the range is exact again.
    assert_eq!(
        bounds(
            [1, 0, 6],
            vec![
                ix(3, &[], &set_compute_unit_limit_data(50_000)),
                price.clone(),
                ix(6, &[], &[0; 4]),
            ]
        ),
        exact(5_000 + 50_000)
    );
    // A limit above the runtime maximum is capped.
    assert_eq!(
        bounds(
            [1, 0, 6],
            vec![
                ix(3, &[], &set_compute_unit_limit_data(2_000_000)),
                price.clone(),
            ]
        ),
        exact(5_000 + 1_400_000)
    );
    // Two signers plus two Ed25519 and one Secp256r1 precompile signatures; the price rounds
    // up.
    let mut ed25519 = vec![2, 0];
    ed25519.extend_from_slice(&[0; 28]);
    let mut secp256r1 = vec![1, 0];
    secp256r1.extend_from_slice(&[0; 14]);
    assert_eq!(
        bounds(
            [2, 0, 6],
            vec![
                ix(3, &[], &set_compute_unit_limit_data(3)),
                ix(3, &[], &set_compute_unit_price_data(1)),
                ix(4, &[], &ed25519),
                ix(7, &[], &secp256r1),
            ]
        ),
        exact(5 * 5_000 + 1)
    );
    // Without a limit Ed25519 is a builtin (3,000) and Secp256r1 is bracketed.
    assert_eq!(
        bounds(
            [1, 0, 6],
            vec![price, ix(4, &[], &ed25519), ix(7, &[], &secp256r1)]
        ),
        DappFeeBounds {
            low: 4 * 5_000 + 9_000,
            high: 4 * 5_000 + 206_000,
            rejected: false,
        }
    );
}

// ----- lookup tables ----------------------------------------------------------------------------

#[test]
fn lookup_table_layout() {
    let addresses: Vec<SolAddress> = (1..=3).map(key).collect();
    let with = table_data(&addresses, Some(key(0x99)), 77, 2, u64::MAX);
    let table = parse_lookup_table(&ADDRESS_LOOKUP_TABLE_PROGRAM, &with).unwrap();
    assert_eq!(
        table,
        LookupTable {
            deactivation_slot: u64::MAX,
            last_extended_slot: 77,
            last_extended_start: 2,
            authority: Some(key(0x99)),
            addresses: addresses.clone(),
        }
    );
    assert!(!table.is_deactivated());
    let frozen = parse_lookup_table(
        &ADDRESS_LOOKUP_TABLE_PROGRAM,
        &table_data(&addresses, None, 77, 2, 500),
    )
    .unwrap();
    assert_eq!(frozen.authority, None);
    assert!(frozen.is_deactivated());
    // An empty table is a table.
    assert_eq!(
        parse_lookup_table(
            &ADDRESS_LOOKUP_TABLE_PROGRAM,
            &table_data(&[], None, 0, 0, 0)
        )
        .unwrap()
        .addresses,
        []
    );

    assert!(parse_lookup_table(&SYSTEM_PROGRAM, &with).is_none());
    for discriminator in [0_u32, 2] {
        let mut bad = with.clone();
        bad[..4].copy_from_slice(&discriminator.to_le_bytes());
        assert!(parse_lookup_table(&ADDRESS_LOOKUP_TABLE_PROGRAM, &bad).is_none());
    }
    let mut bad_tag = with.clone();
    bad_tag[21] = 2;
    assert!(parse_lookup_table(&ADDRESS_LOOKUP_TABLE_PROGRAM, &bad_tag).is_none());
    for len in [55, with.len() - 1, with.len() + 1] {
        let mut resized = with.clone();
        resized.resize(len, 0);
        assert!(
            parse_lookup_table(&ADDRESS_LOOKUP_TABLE_PROGRAM, &resized).is_none(),
            "{len}"
        );
    }
    let full: Vec<SolAddress> = (0..=255).map(key).collect();
    let largest = table_data(&full, None, 0, 0, u64::MAX);
    assert_eq!(largest.len(), LOOKUP_TABLE_MAX_DATA);
    assert_eq!(
        parse_lookup_table(&ADDRESS_LOOKUP_TABLE_PROGRAM, &largest)
            .unwrap()
            .addresses
            .len(),
        256
    );
    let mut over = largest;
    over.extend_from_slice(&[1; 32]);
    assert!(parse_lookup_table(&ADDRESS_LOOKUP_TABLE_PROGRAM, &over).is_none());
}

#[test]
fn lookup_resolution_rules() {
    let message = parse_message_any(&v0_message()).unwrap();
    let tables = v0_tables();
    // Table a1 was extended at slot 10 from length 3: in slot 10 only indices 0–2 are usable.
    assert_eq!(resolve(&message, &tables, 10), Err(AltError::Index));
    assert!(resolve(&message, &tables, 9).is_ok());
    assert!(resolve(&message, &tables, 11).is_ok());
    assert_eq!(tables[0].1.usable_len(10), 3);
    assert_eq!(tables[0].1.usable_len(11), 6);
    assert_eq!(
        resolve(&message, &tables[..1], 11),
        Err(AltError::Missing(key(0xa2)))
    );
    // A deactivated table still resolves.
    let mut deactivated = tables.clone();
    deactivated[1].1.deactivation_slot = 5;
    assert!(resolve(&message, &deactivated, 11).is_ok());
    // A loaded address equal to a static key, or loaded twice.
    let mut static_dup = tables.clone();
    static_dup[1].1.addresses[1] = key(0x11);
    assert_eq!(resolve(&message, &static_dup, 11), Err(AltError::Duplicate));
    let mut loaded_dup = tables.clone();
    loaded_dup[1].1.addresses[1] = key(0x30);
    assert_eq!(resolve(&message, &loaded_dup, 11), Err(AltError::Duplicate));
    // Out of range.
    let mut short = tables;
    short[1].1.addresses.truncate(1);
    assert_eq!(resolve(&message, &short, 11), Err(AltError::Index));
    // A legacy message loads nothing.
    let legacy_message = parse_message_any(&t_sol_message()).unwrap();
    assert_eq!(
        resolve(&legacy_message, &[], 0),
        Ok(ResolvedKeys::default())
    );
    assert!(
        AltError::Missing(key(1))
            .to_string()
            .contains("조회 테이블")
    );
}

// ----- decoders -----------------------------------------------------------------------------

fn accounts() -> Vec<SolAddress> {
    (1..=8).map(key).collect()
}

fn malformed() -> DecodedIx {
    DecodedIx::Unknown {
        reason: Some(MALFORMED),
    }
}

/// `data` with `min_accounts` decodes to `expected`; one byte more or less, or one account
/// fewer, is `Unknown("형식이 맞지 않음")`.
fn exact(program: &SolAddress, min_accounts: usize, data: &[u8], expected: &DecodedIx) {
    let all = accounts();
    assert_eq!(
        decode(program, &all[..min_accounts], data),
        *expected,
        "{data:02x?}"
    );
    assert_eq!(decode(program, &all, data), *expected, "{data:02x?}");
    let mut longer = data.to_vec();
    longer.push(0);
    assert_eq!(
        decode(program, &all, &longer),
        malformed(),
        "{data:02x?} +1"
    );
    assert_eq!(
        decode(program, &all, &data[..data.len() - 1]),
        malformed(),
        "{data:02x?} -1"
    );
    if min_accounts > 0 {
        assert_eq!(
            decode(program, &all[..min_accounts - 1], data),
            malformed(),
            "{data:02x?} accounts"
        );
    }
}

fn tagged(tag: u32, parts: &[&[u8]]) -> Vec<u8> {
    let mut data = tag.to_le_bytes().to_vec();
    for part in parts {
        data.extend_from_slice(part);
    }
    data
}

fn seed(text: &str) -> Vec<u8> {
    let mut out = u64::try_from(text.len()).unwrap().to_le_bytes().to_vec();
    out.extend_from_slice(text.as_bytes());
    out
}

#[test]
#[expect(clippy::too_many_lines, reason = "one case per System tag 0–12")]
fn system_instructions() {
    let a = accounts();
    let owner = key(0x99);
    let base = key(0x98);
    let amount = 42_u64.to_le_bytes();
    let space = 165_u64.to_le_bytes();
    let system = DecodedIx::System;
    let cases: Vec<(usize, Vec<u8>, DecodedIx)> = vec![
        (
            2,
            tagged(0, &[&amount, &space, owner.as_bytes()]),
            system(SystemIx::CreateAccount {
                from: a[0],
                to: a[1],
                lamports: 42,
                space: 165,
                owner,
            }),
        ),
        (
            1,
            tagged(1, &[owner.as_bytes()]),
            system(SystemIx::Assign {
                account: a[0],
                owner,
            }),
        ),
        (
            2,
            system_transfer_data(42),
            system(SystemIx::Transfer {
                from: a[0],
                to: a[1],
                lamports: 42,
            }),
        ),
        (
            2,
            tagged(
                3,
                &[
                    base.as_bytes(),
                    &seed("vault"),
                    &amount,
                    &space,
                    owner.as_bytes(),
                ],
            ),
            system(SystemIx::CreateAccountWithSeed {
                from: a[0],
                to: a[1],
                base,
                seed: "vault".to_owned(),
                lamports: 42,
                space: 165,
                owner,
            }),
        ),
        (
            5,
            tagged(5, &[&amount]),
            system(SystemIx::WithdrawNonce {
                nonce: a[0],
                to: a[1],
                authority: a[4],
                lamports: 42,
            }),
        ),
        (
            3,
            tagged(6, &[owner.as_bytes()]),
            system(SystemIx::InitializeNonce {
                nonce: a[0],
                authority: owner,
            }),
        ),
        (
            2,
            tagged(7, &[owner.as_bytes()]),
            system(SystemIx::AuthorizeNonce {
                nonce: a[0],
                authority: a[1],
                new_authority: owner,
            }),
        ),
        (
            1,
            tagged(8, &[&space]),
            system(SystemIx::Allocate {
                account: a[0],
                space: 165,
            }),
        ),
        (
            2,
            tagged(9, &[base.as_bytes(), &seed("s"), &space, owner.as_bytes()]),
            system(SystemIx::AllocateWithSeed {
                account: a[0],
                base,
                seed: "s".to_owned(),
                space: 165,
                owner,
            }),
        ),
        (
            2,
            tagged(10, &[base.as_bytes(), &seed(""), owner.as_bytes()]),
            system(SystemIx::AssignWithSeed {
                account: a[0],
                base,
                seed: String::new(),
                owner,
            }),
        ),
        (
            3,
            tagged(11, &[&amount, &seed("시드"), owner.as_bytes()]),
            system(SystemIx::TransferWithSeed {
                from: a[0],
                base: a[1],
                to: a[2],
                lamports: 42,
                seed: "시드".to_owned(),
                owner,
            }),
        ),
        (
            1,
            tagged(12, &[]),
            system(SystemIx::UpgradeNonce { nonce: a[0] }),
        ),
    ];
    for (min_accounts, data, expected) in &cases {
        exact(&SYSTEM_PROGRAM, *min_accounts, data, expected);
        assert!(!expected.is_opaque());
    }
    // AdvanceNonce (4): bytes after the tag are kept, not refused; three accounts needed.
    assert_eq!(
        decode(&SYSTEM_PROGRAM, &a[..3], &tagged(4, &[&[0xff]])),
        system(SystemIx::AdvanceNonce {
            nonce: a[0],
            authority: a[2],
            extra: vec![0xff],
        })
    );
    assert_eq!(
        decode(&SYSTEM_PROGRAM, &a[..3], &tagged(4, &[])),
        system(SystemIx::AdvanceNonce {
            nonce: a[0],
            authority: a[2],
            extra: Vec::new(),
        })
    );
    assert_eq!(decode(&SYSTEM_PROGRAM, &a, &[4, 0, 0]), malformed());
    // Unknown tag; seeds over 32 bytes or not UTF-8.
    assert_eq!(decode(&SYSTEM_PROGRAM, &a, &tagged(13, &[])), malformed());
    assert_eq!(decode(&SYSTEM_PROGRAM, &a, &[]), malformed());
    let long_seed = "x".repeat(33);
    assert_eq!(
        decode(
            &SYSTEM_PROGRAM,
            &a,
            &tagged(10, &[base.as_bytes(), &seed(&long_seed), owner.as_bytes()])
        ),
        malformed()
    );
    let mut binary_seed = 2_u64.to_le_bytes().to_vec();
    binary_seed.extend_from_slice(&[0xff, 0xfe]);
    assert_eq!(
        decode(
            &SYSTEM_PROGRAM,
            &a,
            &tagged(10, &[base.as_bytes(), &binary_seed, owner.as_bytes()])
        ),
        malformed()
    );
}

#[test]
#[expect(clippy::too_many_lines, reason = "one case per Token tag 0–24")]
fn token_instructions() {
    let a = accounts();
    let k9 = key(0x99);
    let k10 = key(0x9a);
    let amount = 1_000_u64.to_le_bytes();
    let with = |tag: u8, parts: &[&[u8]]| {
        let mut data = vec![tag];
        for part in parts {
            data.extend_from_slice(part);
        }
        data
    };
    let some = |address: &SolAddress| {
        let mut out = vec![1];
        out.extend_from_slice(address.as_bytes());
        out
    };
    let cases: Vec<(usize, Vec<u8>, TokenIx)> = vec![
        (
            2,
            with(0, &[&[6], k9.as_bytes(), &some(&k10)]),
            TokenIx::InitializeMint {
                mint: a[0],
                decimals: 6,
                mint_authority: k9,
                freeze_authority: Some(k10),
            },
        ),
        (
            2,
            with(0, &[&[6], k9.as_bytes(), &[0]]),
            TokenIx::InitializeMint {
                mint: a[0],
                decimals: 6,
                mint_authority: k9,
                freeze_authority: None,
            },
        ),
        // @solana/spl-token writes `None` at a fixed width: `0 ‖ 00×32`.
        (
            2,
            with(0, &[&[6], k9.as_bytes(), &[0], &[0; 32]]),
            TokenIx::InitializeMint {
                mint: a[0],
                decimals: 6,
                mint_authority: k9,
                freeze_authority: None,
            },
        ),
        (
            4,
            vec![1],
            TokenIx::InitializeAccount {
                account: a[0],
                mint: a[1],
                owner: a[2],
            },
        ),
        (
            3,
            vec![2, 2],
            TokenIx::InitializeMultisig {
                multisig: a[0],
                m: 2,
            },
        ),
        (
            3,
            with(3, &[&amount]),
            TokenIx::Transfer {
                source: a[0],
                destination: a[1],
                authority: a[2],
                amount: 1_000,
            },
        ),
        (
            3,
            with(4, &[&amount]),
            TokenIx::Approve {
                source: a[0],
                delegate: a[1],
                owner: a[2],
                amount: 1_000,
            },
        ),
        (
            2,
            vec![5],
            TokenIx::Revoke {
                source: a[0],
                owner: a[1],
            },
        ),
        (
            2,
            with(6, &[&[2], &some(&k9)]),
            TokenIx::SetAuthority {
                account: a[0],
                current: a[1],
                kind: AuthorityType::AccountOwner,
                new: Some(k9),
            },
        ),
        (
            2,
            vec![6, 3, 0],
            TokenIx::SetAuthority {
                account: a[0],
                current: a[1],
                kind: AuthorityType::CloseAccount,
                new: None,
            },
        ),
        (
            2,
            with(6, &[&[0, 0], &[0; 32]]),
            TokenIx::SetAuthority {
                account: a[0],
                current: a[1],
                kind: AuthorityType::MintTokens,
                new: None,
            },
        ),
        (
            3,
            with(7, &[&amount]),
            TokenIx::MintTo {
                mint: a[0],
                destination: a[1],
                authority: a[2],
                amount: 1_000,
            },
        ),
        (
            3,
            with(8, &[&amount]),
            TokenIx::Burn {
                account: a[0],
                mint: a[1],
                authority: a[2],
                amount: 1_000,
            },
        ),
        (
            3,
            vec![9],
            TokenIx::CloseAccount {
                account: a[0],
                destination: a[1],
                authority: a[2],
            },
        ),
        (
            3,
            vec![10],
            TokenIx::FreezeAccount {
                account: a[0],
                mint: a[1],
                authority: a[2],
            },
        ),
        (
            3,
            vec![11],
            TokenIx::ThawAccount {
                account: a[0],
                mint: a[1],
                authority: a[2],
            },
        ),
        (
            4,
            transfer_checked_data(1_000, 6),
            TokenIx::TransferChecked {
                source: a[0],
                mint: a[1],
                destination: a[2],
                authority: a[3],
                amount: 1_000,
                decimals: 6,
            },
        ),
        (
            4,
            with(13, &[&amount, &[6]]),
            TokenIx::ApproveChecked {
                source: a[0],
                mint: a[1],
                delegate: a[2],
                owner: a[3],
                amount: 1_000,
                decimals: 6,
            },
        ),
        (
            3,
            with(14, &[&amount, &[6]]),
            TokenIx::MintToChecked {
                mint: a[0],
                destination: a[1],
                authority: a[2],
                amount: 1_000,
                decimals: 6,
            },
        ),
        (
            3,
            with(15, &[&amount, &[6]]),
            TokenIx::BurnChecked {
                account: a[0],
                mint: a[1],
                authority: a[2],
                amount: 1_000,
                decimals: 6,
            },
        ),
        (
            3,
            with(16, &[k9.as_bytes()]),
            TokenIx::InitializeAccount2 {
                account: a[0],
                mint: a[1],
                owner: k9,
            },
        ),
        (1, vec![17], TokenIx::SyncNative { account: a[0] }),
        (
            2,
            with(18, &[k9.as_bytes()]),
            TokenIx::InitializeAccount3 {
                account: a[0],
                mint: a[1],
                owner: k9,
            },
        ),
        (
            2,
            vec![19, 1],
            TokenIx::InitializeMultisig2 {
                multisig: a[0],
                m: 1,
            },
        ),
        (
            1,
            with(20, &[&[9], k9.as_bytes(), &[0]]),
            TokenIx::InitializeMint2 {
                mint: a[0],
                decimals: 9,
                mint_authority: k9,
                freeze_authority: None,
            },
        ),
        (
            1,
            with(20, &[&[9], k9.as_bytes(), &[0], &[0; 32]]),
            TokenIx::InitializeMint2 {
                mint: a[0],
                decimals: 9,
                mint_authority: k9,
                freeze_authority: None,
            },
        ),
        (
            1,
            vec![21],
            TokenIx::GetAccountDataSize {
                mint: a[0],
                extensions: Vec::new(),
            },
        ),
        (
            1,
            vec![22],
            TokenIx::InitializeImmutableOwner { account: a[0] },
        ),
        (
            1,
            with(23, &[&amount]),
            TokenIx::AmountToUiAmount {
                mint: a[0],
                amount: 1_000,
            },
        ),
    ];
    let mut tags = Vec::new();
    for (min_accounts, data, expected) in &cases {
        exact(
            &TOKEN_PROGRAM,
            *min_accounts,
            data,
            &DecodedIx::Token {
                program2022: false,
                ix: expected.clone(),
            },
        );
        assert_eq!(expected.tag(), data[0]);
        tags.push(data[0]);
        assert_eq!(
            decode(&TOKEN_2022_PROGRAM, &a, data),
            DecodedIx::Token {
                program2022: true,
                ix: expected.clone(),
            }
        );
    }
    tags.dedup();
    assert_eq!(tags, (0..=23).collect::<Vec<u8>>());
    // 24 UiAmountToAmount takes the rest as UTF-8 text.
    assert_eq!(
        decode(&TOKEN_PROGRAM, &a[..1], b"\x181.5"),
        DecodedIx::Token {
            program2022: false,
            ix: TokenIx::UiAmountToAmount {
                mint: a[0],
                ui_amount: "1.5".to_owned(),
            },
        }
    );
    assert_eq!(decode(&TOKEN_PROGRAM, &a, &[24, 0xff]), malformed());
    assert_eq!(decode(&TOKEN_PROGRAM, &[], b"\x181.5"), malformed());
    // SetAuthority types beyond the classic four; bad option tags.
    assert_eq!(decode(&TOKEN_PROGRAM, &a, &[6, 4, 0]), malformed());
    assert_eq!(decode(&TOKEN_2022_PROGRAM, &a, &[6, 4, 0]), malformed());
    assert_eq!(decode(&TOKEN_PROGRAM, &a, &[6, 2, 2]), malformed());
    // Only `0` alone or `0 ‖ 00×32` is `None`: no other trailing bytes.
    let mut nonzero = vec![6, 1, 0];
    nonzero.extend_from_slice(k9.as_bytes());
    let mut short = vec![6, 1, 0];
    short.extend_from_slice(&[0; 31]);
    let mut long = vec![6, 1, 0];
    long.extend_from_slice(&[0; 33]);
    let mut one_set = vec![6, 1, 0];
    one_set.extend_from_slice(&[0; 32]);
    one_set[34] = 1;
    for data in [nonzero, short, long, one_set] {
        assert_eq!(decode(&TOKEN_PROGRAM, &a, &data), malformed());
        assert_eq!(decode(&TOKEN_2022_PROGRAM, &a, &data), malformed());
    }
    let mut mint = vec![0, 6];
    mint.extend_from_slice(k9.as_bytes());
    mint.push(0);
    mint.extend_from_slice(&[0; 31]);
    assert_eq!(decode(&TOKEN_PROGRAM, &a, &mint), malformed());
    let mut mint2 = vec![20, 6];
    mint2.extend_from_slice(k9.as_bytes());
    mint2.push(0);
    mint2.extend_from_slice(k10.as_bytes());
    assert_eq!(decode(&TOKEN_PROGRAM, &a, &mint2), malformed());
    // GetAccountDataSize lists extension types only on Token-2022, in whole u16s.
    assert_eq!(
        decode(&TOKEN_2022_PROGRAM, &a[..1], &[21, 7, 0, 14, 0]),
        DecodedIx::Token {
            program2022: true,
            ix: TokenIx::GetAccountDataSize {
                mint: a[0],
                extensions: vec![7, 14],
            },
        }
    );
    assert_eq!(decode(&TOKEN_PROGRAM, &a, &[21, 7, 0]), malformed());
    assert_eq!(decode(&TOKEN_2022_PROGRAM, &a, &[21, 7]), malformed());
    // Tags 25+ are Token-2022 extensions (raw, X02); classic Token has none.
    for tag in [25_u8, 26, 27, 34, 38, 255] {
        let decoded = decode(&TOKEN_2022_PROGRAM, &a[..1], &[tag, 1, 2, 3]);
        assert_eq!(
            decoded,
            DecodedIx::Token {
                program2022: true,
                ix: TokenIx::Extension { tag },
            }
        );
        assert!(decoded.is_opaque());
        assert_eq!(decode(&TOKEN_2022_PROGRAM, &[], &[tag]), decoded);
        assert_eq!(decode(&TOKEN_PROGRAM, &a, &[tag]), malformed());
    }
    assert_eq!(decode(&TOKEN_PROGRAM, &a, &[]), malformed());
}

#[test]
fn ata_instructions() {
    let wallet = addr("HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk");
    let mint = addr("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
    let ata = addr("5N3f1tj9v1vc5TUZ8S7mCAnVmjVKrfnzXWhxLaxyZAgt");
    let payer = key(0x11);
    let create = [payer, ata, wallet, mint, SYSTEM_PROGRAM, TOKEN_PROGRAM];
    for (data, idempotent) in [(&[][..], false), (&[0][..], false), (&[1][..], true)] {
        let decoded = decode(&ATA_PROGRAM, &create, data);
        assert_eq!(
            decoded,
            DecodedIx::Ata(AtaIx::Create {
                payer,
                ata,
                wallet,
                mint,
                token_program: TOKEN_PROGRAM,
                idempotent,
            })
        );
        assert!(!decoded.is_opaque());
    }
    // A token account that is not the derived ATA: raw with its own cause, never blocked here.
    let mut wrong = create;
    wrong[1] = key(0x77);
    let mismatch = decode(&ATA_PROGRAM, &wrong, &[1]);
    assert_eq!(
        mismatch,
        DecodedIx::Unknown {
            reason: Some(ATA_MISMATCH)
        }
    );
    assert!(mismatch.is_opaque());
    // Token-2022 derives another address.
    let mut other_program = create;
    other_program[5] = TOKEN_2022_PROGRAM;
    assert_eq!(decode(&ATA_PROGRAM, &other_program, &[1]), mismatch);
    let mut not_token = create;
    not_token[5] = key(0x77);
    assert_eq!(decode(&ATA_PROGRAM, &not_token, &[1]), malformed());
    let mut not_system = create;
    not_system[4] = key(0x77);
    assert_eq!(decode(&ATA_PROGRAM, &not_system, &[1]), malformed());
    assert_eq!(decode(&ATA_PROGRAM, &create[..5], &[1]), malformed());
    assert_eq!(decode(&ATA_PROGRAM, &create, &[3]), malformed());
    assert_eq!(decode(&ATA_PROGRAM, &create, &[1, 0]), malformed());

    // RecoverNested: nested = ATA(owner_ata, nested_mint), destination = ATA(wallet,
    // nested_mint), owner_ata = ATA(wallet, owner_mint).
    let derive = |owner: &SolAddress, mint: &SolAddress| {
        associated_token_address(owner, &TOKEN_PROGRAM, mint)
            .unwrap()
            .0
    };
    let nested_mint = key(0x22);
    let owner_ata = derive(&wallet, &mint);
    let nested = derive(&owner_ata, &nested_mint);
    let destination = derive(&wallet, &nested_mint);
    let recover = [
        nested,
        nested_mint,
        destination,
        owner_ata,
        mint,
        wallet,
        TOKEN_PROGRAM,
    ];
    assert_eq!(
        decode(&ATA_PROGRAM, &recover, &[2]),
        DecodedIx::Ata(AtaIx::RecoverNested {
            nested,
            nested_mint,
            destination,
            owner_ata,
            owner_mint: mint,
            wallet,
            token_program: TOKEN_PROGRAM,
        })
    );
    let mut swapped = recover;
    swapped.swap(0, 2);
    assert_eq!(decode(&ATA_PROGRAM, &swapped, &[2]), mismatch);
    assert_eq!(decode(&ATA_PROGRAM, &recover[..6], &[2]), malformed());
}

#[test]
fn compute_budget_memo_precompiles_and_unknown() {
    let cb = |data: &[u8], expected: CbIx| {
        exact(
            &COMPUTE_BUDGET_PROGRAM,
            0,
            data,
            &DecodedIx::ComputeBudget(expected),
        );
    };
    let mut heap = vec![1];
    heap.extend_from_slice(&65_536_u32.to_le_bytes());
    cb(&heap, CbIx::RequestHeapFrame(65_536));
    cb(
        &set_compute_unit_limit_data(600),
        CbIx::SetComputeUnitLimit(600),
    );
    cb(
        &set_compute_unit_price_data(1_000),
        CbIx::SetComputeUnitPrice(1_000),
    );
    let mut loaded = vec![4];
    loaded.extend_from_slice(&32_768_u32.to_le_bytes());
    cb(&loaded, CbIx::SetLoadedAccountsDataSizeLimit(32_768));
    // Tag 0 (the removed RequestUnits) and unknown tags.
    assert_eq!(
        decode(&COMPUTE_BUDGET_PROGRAM, &[], &[0, 0, 0, 0, 0, 0, 0, 0, 0]),
        malformed()
    );
    assert_eq!(
        decode(&COMPUTE_BUDGET_PROGRAM, &[], &[5, 0, 0, 0, 0]),
        malformed()
    );
    assert_eq!(decode(&COMPUTE_BUDGET_PROGRAM, &[], &[]), malformed());

    // Memo v1 and v2 keep the raw bytes, text or not.
    for program in [MEMO_PROGRAM_V1, MEMO_PROGRAM_V2] {
        for bytes in [b"hello".as_slice(), &[0xff, 0x00], &[]] {
            let decoded = decode(&program, &accounts(), bytes);
            assert_eq!(decoded, DecodedIx::Memo(bytes.to_vec()));
            assert!(!decoded.is_opaque());
        }
    }

    // Precompiles: the count when the offsets table fits (Ed25519/Secp256r1 2 + 14n, Secp256k1
    // 1 + 11n), else Unknown; a decoded precompile is not opaque.
    for (program, start, entry) in [
        (ED25519_PRECOMPILE, 2, 14),
        (SECP256R1_PRECOMPILE, 2, 14),
        (SECP256K1_PRECOMPILE, 1, 11),
    ] {
        for count in [0_u8, 1, 3] {
            let mut data = vec![count];
            data.resize(start + entry * usize::from(count), 0);
            let decoded = decode(&program, &[], &data);
            assert_eq!(decoded, DecodedIx::Precompile { count }, "{program}");
            assert!(!decoded.is_opaque());
            if count > 0 {
                data.pop();
                assert_eq!(decode(&program, &[], &data), malformed(), "{program}");
            }
        }
        assert_eq!(decode(&program, &[], &[]), malformed());
    }

    // Programs the wallet does not interpret: raw (known ones keep their name).
    for program in [key(0x55), STAKE_PROGRAM, ADDRESS_LOOKUP_TABLE_PROGRAM] {
        let decoded = decode(&program, &accounts(), &[1, 2, 3]);
        assert_eq!(decoded, DecodedIx::Unknown { reason: None });
        assert!(decoded.is_opaque());
    }
    assert_eq!(program_name(&STAKE_PROGRAM), Some("Stake"));
    assert_eq!(program_name(&key(0x55)), None);
}
