//! dApp sends (spec/07 §20.8–§20.10, spec/09 SOL-N14–N16 core parts): the send signer (deadline,
//! pre-sign blockhash and tables, site signatures, card), journal version 3 (layout, round trip
//! with a 256-byte origin and an added mnemonic, every load rejection, flags, activity row, room
//! and pending counts, `core()` of a template-shaped dApp send) and broadcast code 9.
#![expect(
    clippy::indexing_slicing,
    reason = "test fixtures index buffers of known length"
)]

use sha2::{Digest, Sha256};

use super::alt::ResolvedKeys;
use super::parse::parse_wire_tx;
use super::sign::{
    PreSignCheck, SignedSolDappTx, SolTxCardError, SolTxSignError, sign_send, sign_send_card,
    sign_txs,
};
use super::tests_approval::{
    ABOUT, CLUSTER, approval, assert_only_our_slot, ix, key, legacy, nonce_message, site_address,
    site_key, transfer_message, v0_tx, wallet, wire,
};
use super::{SolCommitment, SolSendOptions, SolTxItem, SolTxMode, SolTxPayload};
use crate::approval::{ApprovalKind, MAX_TITLE_BYTES};
use crate::bip32::path::AccountIndex;
use crate::journal::sol::{
    RECORD_VERSION_V3, SOL_DAPP_MAX_PENDING, SOL_DAPP_MAX_PENDING_TOTAL, SOL_JOURNAL_HEADER_LEN,
    SOL_JOURNAL_MAX_BODY_V3, SOL_JOURNAL_MAX_RECORDS, SOL_JOURNAL_ORIGIN_MAX, SolDappMeta,
    SolEntries, SolRecord, SolRecordError, SolTransition, SolTxState, activity_row, apply,
    dapp_flags, has_intent, has_room, pending_dapp_count, pending_dapp_total, pending_for,
    push_record, take_terminal,
};
use crate::journal::{ENTRY_HEADER_LEN, Entry, EntryKind, JournalPlain, MAX_PLAINTEXT};
use crate::slip10::SolKeySource;
use crate::sol::address::{SYSTEM_PROGRAM, SYSVAR_RECENT_BLOCKHASHES, SolAddress, SolCluster};
use crate::sol::broadcast::err;
use crate::sol::message::{encode_message, parse_transaction};
use crate::sol::template::system_transfer_data;
use crate::sol::{SolAsset, SolTransferCore};
use crate::vault::tests::unlocked_with;

const STANDARD: SolKeySource = SolKeySource::Standard(AccountIndex::ZERO);
const APPROVAL_ID: [u8; 16] = [0x5e; 16];
const ORIGIN: &str = "https://dapp.example";

/// A send of the one transaction `tx` with `options`.
fn send_payload(
    public: SolAddress,
    source: SolKeySource,
    tx: &[u8],
    options: SolSendOptions,
) -> SolTxPayload {
    let wire = parse_wire_tx(tx).unwrap();
    let loaded = wire.message.lookups.is_empty().then(ResolvedKeys::default);
    SolTxPayload {
        source,
        public: public.to_bytes(),
        mode: SolTxMode::SignAndSend,
        options,
        items: vec![SolTxItem {
            wire: tx.to_vec(),
            signer_slot: wire.message.signer_slot(public.as_bytes()).unwrap(),
            loaded,
        }],
    }
}

fn check() -> PreSignCheck {
    PreSignCheck {
        blockhash: [7; 32],
        loaded: None,
    }
}

/// The wallet pays; the site pays with its signature in slot 0.
fn site_paid_message() -> Vec<u8> {
    legacy(
        [2, 0, 1],
        &[site_address(), wallet(), SYSTEM_PROGRAM],
        vec![ix(2, &[1, 0], &system_transfer_data(1))],
    )
}

fn signed_send(tx: &[u8], options: SolSendOptions) -> (SolTxPayload, SignedSolDappTx) {
    let vault = unlocked_with(ABOUT);
    let payload = send_payload(wallet(), STANDARD, tx, options);
    let signed = sign_send(
        &vault,
        &approval(payload.clone(), ApprovalKind::SolTransaction),
        1_000,
        2_000,
        &check(),
    )
    .unwrap();
    (payload, signed)
}

fn dapp_record(tx: &[u8], options: SolSendOptions, origin: &str) -> SolRecord {
    let (payload, signed) = signed_send(tx, options);
    SolRecord::new_dapp_pending(
        CLUSTER,
        &payload,
        &APPROVAL_ID,
        origin,
        &signed,
        1_790_000_000_000,
        1_234,
    )
}

/// A 256-byte serialized origin (`https://` + four labels of 62, 62, 62 and 59 letters).
fn longest_origin() -> String {
    let labels = [62, 62, 62, 59].map(|length| "a".repeat(length));
    let origin = format!("https://{}", labels.join("."));
    assert_eq!(origin.len(), SOL_JOURNAL_ORIGIN_MAX);
    assert!(crate::policy::BrowserOrigin::parse(&origin).is_some());
    origin
}

// ----- signer ----------------------------------------------------------------------------------

#[test]
fn send_signs_only_our_slot_with_the_approved_blockhash() {
    let vault = unlocked_with(ABOUT);
    let tx = wire(&transfer_message(), &[]);
    let approved = approval(
        send_payload(wallet(), STANDARD, &tx, SolSendOptions::default()),
        ApprovalKind::SolTransaction,
    );
    // The deadline runs 20 s from the pre-sign answer, inclusive.
    let signed = sign_send(&vault, &approved, 1_000, 21_000, &check()).unwrap();
    assert_only_our_slot(&tx, &signed.tx, &wallet());
    let message = parse_wire_tx(&signed.tx).unwrap().message_bytes;
    assert_eq!(
        parse_wire_tx(&signed.tx).unwrap().message.blockhash,
        [7; 32]
    );
    assert_eq!(signed.tx_id, signed.own_signature);
    assert_eq!(signed.tx[1..65], signed.tx_id);
    assert_eq!(
        signed.message_sha256,
        <[u8; 32]>::from(Sha256::digest(&message))
    );
    assert_eq!(
        sign_send(&vault, &approved, 1_000, 21_001, &check()),
        Err(SolTxSignError::DeadlineExceeded)
    );
    // The pre-sign blockhash must be the transaction's own; it is never replaced.
    let other = PreSignCheck {
        blockhash: [8; 32],
        loaded: None,
    };
    assert_eq!(
        sign_send(&vault, &approved, 1_000, 2_000, &other),
        Err(SolTxSignError::EncodingMismatch)
    );
    // A message without lookups: `None` or the empty set at pre-sign, nothing else.
    let empty = PreSignCheck {
        loaded: Some(ResolvedKeys::default()),
        ..check()
    };
    assert!(sign_send(&vault, &approved, 1_000, 2_000, &empty).is_ok());
    let extra = PreSignCheck {
        loaded: Some(ResolvedKeys {
            writable: vec![key(0x30)],
            readonly: Vec::new(),
        }),
        ..check()
    };
    assert_eq!(
        sign_send(&vault, &approved, 1_000, 2_000, &extra),
        Err(SolTxSignError::TablesChanged)
    );
}

#[test]
fn send_keeps_the_site_signature_and_needs_every_other_slot() {
    let vault = unlocked_with(ABOUT);
    let tx = wire(&site_paid_message(), &[(0, &site_key())]);
    let (_, signed) = signed_send(&tx, SolSendOptions::default());
    assert_only_our_slot(&tx, &signed.tx, &wallet());
    // The site pays: signature 0 (the transaction id) is the site's, ours is slot 1.
    assert_eq!(signed.tx_id, parse_wire_tx(&tx).unwrap().signatures[0]);
    assert_ne!(signed.tx_id, signed.own_signature);
    assert_eq!(signed.tx[65..129], signed.own_signature);
    // The site slot still empty: a send needs it (sign-only would not).
    let unsigned = wire(&site_paid_message(), &[]);
    let missing = approval(
        send_payload(wallet(), STANDARD, &unsigned, SolSendOptions::default()),
        ApprovalKind::SolTransaction,
    );
    assert_eq!(
        sign_send(&vault, &missing, 1_000, 2_000, &check()),
        Err(SolTxSignError::MissingSignature)
    );
    // A site signature that does not verify.
    let mut broken = tx.clone();
    broken[5] ^= 1;
    let broken = approval(
        send_payload(wallet(), STANDARD, &broken, SolSendOptions::default()),
        ApprovalKind::SolTransaction,
    );
    assert_eq!(
        sign_send(&vault, &broken, 1_000, 2_000, &check()),
        Err(SolTxSignError::ForeignSignature)
    );
}

#[test]
fn send_compares_the_tables_and_refuses_other_payloads() {
    let vault = unlocked_with(ABOUT);
    let tx = v0_tx();
    let approved_keys = ResolvedKeys {
        writable: vec![key(0x30)],
        readonly: vec![key(0x31)],
    };
    let mut payload = send_payload(wallet(), STANDARD, &tx, SolSendOptions::default());
    payload.items[0].loaded = Some(approved_keys.clone());
    let approved = approval(payload.clone(), ApprovalKind::SolTransaction);
    let same = PreSignCheck {
        loaded: Some(approved_keys),
        ..check()
    };
    let signed = sign_send(&vault, &approved, 1_000, 2_000, &same).unwrap();
    assert_only_our_slot(&tx, &signed.tx, &wallet());
    let changed = PreSignCheck {
        loaded: Some(ResolvedKeys {
            writable: vec![key(0x31)],
            readonly: vec![key(0x30)],
        }),
        ..check()
    };
    for check in [check(), changed] {
        assert_eq!(
            sign_send(&vault, &approved, 1_000, 2_000, &check),
            Err(SolTxSignError::TablesChanged)
        );
    }
    // An unresolved lookup (an X01 draft) is never sent.
    payload.items[0].loaded = None;
    assert_eq!(
        sign_send(
            &vault,
            &approval(payload, ApprovalKind::SolTransaction),
            1_000,
            2_000,
            &same
        ),
        Err(SolTxSignError::TablesChanged)
    );
    // A durable nonce, two transactions, a sign-only approval or another kind: not a send.
    let simple = wire(&transfer_message(), &[]);
    let nonce = wire(&nonce_message(Vec::new()), &[]);
    let mut two = send_payload(wallet(), STANDARD, &simple, SolSendOptions::default());
    two.items.push(two.items[0].clone());
    let mut sign_only = send_payload(wallet(), STANDARD, &simple, SolSendOptions::default());
    sign_only.mode = SolTxMode::SignOnly;
    for (payload, kind) in [
        (
            send_payload(wallet(), STANDARD, &nonce, SolSendOptions::default()),
            ApprovalKind::SolTransaction,
        ),
        (two, ApprovalKind::SolTransaction),
        (sign_only, ApprovalKind::SolTransaction),
        (
            send_payload(wallet(), STANDARD, &simple, SolSendOptions::default()),
            ApprovalKind::SolMessage,
        ),
    ] {
        assert_eq!(
            sign_send(&vault, &approval(payload, kind), 1_000, 2_000, &check()),
            Err(SolTxSignError::KindMismatch)
        );
    }
    // The other way round: a send approval is not the sign-only signer's.
    assert_eq!(
        sign_txs(
            &vault,
            approval(
                send_payload(wallet(), STANDARD, &simple, SolSendOptions::default()),
                ApprovalKind::SolTransaction
            )
        ),
        Err(SolTxSignError::KindMismatch)
    );
    // A recovery-scan source.
    assert_eq!(
        sign_send(
            &vault,
            &approval(
                send_payload(
                    wallet(),
                    SolKeySource::RawSeed,
                    &simple,
                    SolSendOptions::default()
                ),
                ApprovalKind::SolTransaction
            ),
            1_000,
            2_000,
            &check()
        ),
        Err(SolTxSignError::PolicyMismatch)
    );
}

#[test]
fn card_send_asks_once_after_every_check() {
    use crate::yubikey::CardError;
    use crate::yubikey::apdu::ApduMode;
    use crate::yubikey::sign::sign_sol;
    let (mut card, _vault, card_key) = crate::sol::tests::sol_card();
    card.log.clear();
    let hw = SolKeySource::Hardware(AccountIndex::ZERO);
    let tx = wire(&site_paid_message(), &[(0, &site_key())]);
    let approved = approval(
        send_payload(wallet(), hw, &tx, SolSendOptions::default()),
        ApprovalKind::SolTransaction,
    );
    let mut asked = 0_usize;
    let signed = {
        let mut signer = |message: &[u8]| {
            asked += 1;
            sign_sol(&mut card, ApduMode::Short, &card_key, b"123456", message)
        };
        sign_send_card(&approved, 1_000, 2_000, &check(), &mut signer).unwrap()
    };
    assert_eq!(asked, 1);
    assert!(!card.saw_write());
    assert_only_our_slot(&tx, &signed.tx, &wallet());
    // Refusals before the card is asked.
    let mut never = |_: &[u8]| -> Result<[u8; 64], CardError> { unreachable!("not asked") };
    assert_eq!(
        sign_send_card(&approved, 1_000, 30_000, &check(), &mut never),
        Err(SolTxCardError::Sign(SolTxSignError::DeadlineExceeded))
    );
    let software = approval(
        send_payload(wallet(), STANDARD, &tx, SolSendOptions::default()),
        ApprovalKind::SolTransaction,
    );
    assert_eq!(
        sign_send_card(&software, 1_000, 2_000, &check(), &mut never),
        Err(SolTxCardError::Sign(SolTxSignError::KindMismatch))
    );
    let mut garbage = |_: &[u8]| -> Result<[u8; 64], CardError> { Ok([7; 64]) };
    assert_eq!(
        sign_send_card(&approved, 1_000, 2_000, &check(), &mut garbage),
        Err(SolTxCardError::Sign(SolTxSignError::PostSignVerification))
    );
}

// ----- journal version 3 -----------------------------------------------------------------------

#[test]
fn version_3_layout_and_round_trip() {
    let origin = longest_origin();
    let options = SolSendOptions {
        skip_preflight: true,
        preflight_commitment: Some(SolCommitment::Finalized),
        min_context_slot: Some(9),
    };
    let tx = wire(&transfer_message(), &[]);
    let (payload, signed) = signed_send(&tx, options);
    let record = SolRecord::new_dapp_pending(
        CLUSTER,
        &payload,
        &APPROVAL_ID,
        &origin,
        &signed,
        1_790_000_000_000,
        1_234,
    );
    assert_eq!(record.intent_id, APPROVAL_ID);
    assert_eq!(record.intent_hash, payload.intent_hash(&APPROVAL_ID));
    assert_eq!(record.signature(), signed.tx_id);
    let body = record.encode().unwrap();
    // Header, then public ‖ slot ‖ flags ‖ origin_len ‖ origin ‖ tx.
    let at = SOL_JOURNAL_HEADER_LEN;
    assert_eq!((body[0], body[1], body[4]), (0x02, RECORD_VERSION_V3, 1));
    assert_eq!(&body[29..61], payload.intent_hash(&APPROVAL_ID).as_slice());
    assert_eq!(&body[at..at + 32], wallet().as_bytes().as_slice());
    assert_eq!(body[at + 32], 0);
    assert_eq!(
        body[at + 33],
        dapp_flags::BROADCAST | dapp_flags::FEE_PAYER | dapp_flags::SKIP_PREFLIGHT | (2 << 3)
    );
    assert_eq!(&body[at + 34..at + 36], &256_u16.to_be_bytes());
    assert_eq!(&body[at + 36..at + 36 + 256], origin.as_bytes());
    assert_eq!(&body[at + 36 + 256..], signed.tx.as_slice());
    assert_eq!(SolRecord::decode(&body), Ok(record.clone()));
    assert_eq!(record.send_flags(), Some((true, SolCommitment::Finalized)));
    assert_eq!(record.signer(), Some(wallet()));
    // In the container, beside a damaged body.
    let mut plain = JournalPlain::default();
    push_record(&mut plain, &record).unwrap();
    let plain = JournalPlain::decode(&plain.encode().unwrap()).unwrap();
    assert_eq!(SolEntries::from_plain(&plain).records(), vec![record]);
    assert!(has_intent(&plain, &payload.intent_hash(&APPROVAL_ID)));
    // The site pays, default options: no fee-payer bit, `confirmed`.
    let site_paid = dapp_record(
        &wire(&site_paid_message(), &[(0, &site_key())]),
        SolSendOptions::default(),
        ORIGIN,
    );
    let meta = site_paid.dapp.clone().unwrap();
    assert_eq!((meta.signer_slot, meta.flags), (1, dapp_flags::BROADCAST));
    assert_eq!(
        site_paid.send_flags(),
        Some((false, SolCommitment::Confirmed))
    );
    let body = site_paid.encode().unwrap();
    assert_eq!(SolRecord::decode(&body), Ok(site_paid));
    // `processed` and an explicit `confirmed` (the default's code 0).
    for (commitment, bits) in [
        (SolCommitment::Processed, 1_u8),
        (SolCommitment::Confirmed, 0),
    ] {
        let options = SolSendOptions {
            preflight_commitment: Some(commitment),
            ..SolSendOptions::default()
        };
        let record = dapp_record(&tx, options, ORIGIN);
        assert_eq!(
            record.dapp.as_ref().unwrap().flags,
            dapp_flags::BROADCAST | dapp_flags::FEE_PAYER | (bits << 3)
        );
        assert_eq!(record.send_flags(), Some((false, commitment)));
        assert_eq!(SolRecord::decode(&record.encode().unwrap()), Ok(record));
    }
    // A v0 transaction over a lookup table.
    let v0 = v0_tx();
    let vault = unlocked_with(ABOUT);
    let keys = ResolvedKeys {
        writable: vec![key(0x30)],
        readonly: vec![key(0x31)],
    };
    let mut payload = send_payload(wallet(), STANDARD, &v0, SolSendOptions::default());
    payload.items[0].loaded = Some(keys.clone());
    let signed = sign_send(
        &vault,
        &approval(payload.clone(), ApprovalKind::SolTransaction),
        0,
        0,
        &PreSignCheck {
            loaded: Some(keys),
            ..check()
        },
    )
    .unwrap();
    let record =
        SolRecord::new_dapp_pending(CLUSTER, &payload, &APPROVAL_ID, ORIGIN, &signed, 1, 2);
    assert_eq!(SolRecord::decode(&record.encode().unwrap()), Ok(record));
}

#[test]
fn version_3_of_an_added_mnemonic_carries_the_record_id() {
    use crate::vault::tests::{HARDHAT, HARDHAT_SOL_0, unlocked_with_added};
    let (vault, second) = unlocked_with_added(ABOUT, HARDHAT);
    let added = SolAddress::parse(HARDHAT_SOL_0).unwrap();
    let source = SolKeySource::Mnemonic(second, AccountIndex::ZERO);
    let tx = wire(
        &legacy(
            [1, 0, 1],
            &[added, key(0x22), SYSTEM_PROGRAM],
            vec![ix(2, &[0, 1], &system_transfer_data(1))],
        ),
        &[],
    );
    let payload = send_payload(added, source, &tx, SolSendOptions::default());
    let signed = sign_send(
        &vault,
        &approval(payload.clone(), ApprovalKind::SolTransaction),
        0,
        0,
        &check(),
    )
    .unwrap();
    let record =
        SolRecord::new_dapp_pending(CLUSTER, &payload, &APPROVAL_ID, ORIGIN, &signed, 1, 2);
    let body = record.encode().unwrap();
    let at = SOL_JOURNAL_HEADER_LEN;
    assert_eq!((body[1], body[4]), (RECORD_VERSION_V3, 8));
    assert_eq!(&body[at..at + 16], second.as_bytes());
    assert_eq!(&body[at + 16..at + 48], added.as_bytes().as_slice());
    assert_eq!(body.len(), at + 16 + 36 + ORIGIN.len() + signed.tx.len());
    assert_eq!(SolRecord::decode(&body), Ok(record));
    // The record id is never zero.
    let mut zero = body.clone();
    zero[at..at + 16].fill(0);
    assert_eq!(SolRecord::decode(&zero), Err(SolRecordError::Source));
}

/// The site-paid version 3 record used by the rejection tests (our slot 1, default flags).
fn site_paid_record() -> SolRecord {
    dapp_record(
        &wire(&site_paid_message(), &[(0, &site_key())]),
        SolSendOptions::default(),
        ORIGIN,
    )
}

/// `body` changed by `mutate` fails decoding with `expected`.
fn reject(body: &[u8], mutate: &dyn Fn(&mut Vec<u8>), expected: SolRecordError) {
    let mut bad = body.to_vec();
    mutate(&mut bad);
    assert_eq!(SolRecord::decode(&bad), Err(expected));
}

#[test]
fn version_3_rejections() {
    let body = site_paid_record().encode().unwrap();
    let reject = |mutate: &dyn Fn(&mut Vec<u8>), expected| reject(&body, mutate, expected);
    let at = SOL_JOURNAL_HEADER_LEN;
    let slot_at = at + 32;
    let flags_at = at + 33;
    let tx_at = at + 36 + ORIGIN.len();
    // Header and lengths.
    reject(&|b| b[1] = 4, SolRecordError::Header);
    reject(&|b| b.push(0), SolRecordError::Length);
    reject(&|b| b.truncate(b.len() - 1), SolRecordError::Length);
    reject(&|b| b.truncate(at + 35), SolRecordError::Length);
    reject(
        &|b| b[at + 35] = b[at + 35].wrapping_add(1),
        SolRecordError::Length,
    );
    reject(&|b| b[84] = 1, SolRecordError::Terminal);
    // Version 1 has no dApp part: the length no longer matches.
    reject(&|b| b[1] = 1, SolRecordError::Length);
    // Our key at another slot, or a key that is not a signer.
    reject(&|b| b[slot_at] = 0, SolRecordError::Dapp);
    reject(&|b| b[slot_at] = 2, SolRecordError::Dapp);
    reject(&|b| b[at] ^= 1, SolRecordError::Dapp);
    // Flags: bit 0 clear, bit 1 without slot 0, an undefined bit, commitment 3.
    for flags in [0x00, 0x03, 0x21, 0x81, 0x19] {
        reject(&|b| b[flags_at] = flags, SolRecordError::Dapp);
    }
    // Signatures: ours or the site's broken or zero.
    reject(&|b| b[tx_at + 1 + 64 + 3] ^= 1, SolRecordError::Signature);
    reject(&|b| b[tx_at + 1 + 3] ^= 1, SolRecordError::Signature);
    reject(
        &|b| b[tx_at + 1..tx_at + 65].fill(0),
        SolRecordError::Signature,
    );
    reject(
        &|b| b[tx_at + 65..tx_at + 129].fill(0),
        SolRecordError::Signature,
    );
    // The message changed: no longer what the signatures cover; a trailing byte inside the
    // transaction is a parse error.
    reject(
        &|b| {
            let last = b.len() - 1;
            b[last] ^= 1;
        },
        SolRecordError::Signature,
    );
    reject(
        &|b| {
            b.push(0);
            let tx_len = u16::from_be_bytes([b[87], b[88]]) + 1;
            b[87..89].copy_from_slice(&tx_len.to_be_bytes());
        },
        SolRecordError::DappTx(super::SolTxError::TrailingBytes),
    );
}

#[test]
fn version_3_origin_and_nonce_rejections() {
    let site_paid = site_paid_record();
    let body = site_paid.encode().unwrap();
    let reject = |mutate: &dyn Fn(&mut Vec<u8>), expected| reject(&body, mutate, expected);
    let at = SOL_JOURNAL_HEADER_LEN;
    let tx_at = at + 36 + ORIGIN.len();
    // Origin: empty, not ASCII, a control or a space, 257 bytes.
    reject(
        &|b| {
            b.drain(at + 36..tx_at);
            b[at + 34..at + 36].copy_from_slice(&0_u16.to_be_bytes());
        },
        SolRecordError::Dapp,
    );
    for byte in [0xc3, 0x0a, b' '] {
        reject(&|b| b[at + 40] = byte, SolRecordError::Dapp);
    }
    let mut longer = longest_origin().into_bytes();
    longer.push(b'a');
    reject(
        &|b| {
            b.splice(at + 36..tx_at, longer.iter().copied());
            b[at + 34..at + 36].copy_from_slice(&257_u16.to_be_bytes());
        },
        SolRecordError::Dapp,
    );
    // A 257-byte or non-ASCII origin is refused when encoding too.
    for origin in [
        "a".repeat(SOL_JOURNAL_ORIGIN_MAX + 1),
        "https://é.example".to_owned(),
    ] {
        let mut record = site_paid.clone();
        record.dapp.as_mut().unwrap().origin = origin;
        assert_eq!(record.encode(), Err(SolRecordError::Dapp));
    }
    // A durable-nonce transaction (sign-only can sign one; it is never journaled), also with
    // bytes after the AdvanceNonce tag (spec/07 §19, spec/09 SOL-N15).
    let vault = unlocked_with(ABOUT);
    let trailing = legacy(
        [1, 0, 2],
        &[
            wallet(),
            key(0x44),
            SYSVAR_RECENT_BLOCKHASHES,
            SYSTEM_PROGRAM,
        ],
        vec![ix(3, &[1, 2, 0], &[4, 0, 0, 0, 0xFF])],
    );
    for message in [nonce_message(Vec::new()), trailing] {
        let nonce = wire(&message, &[]);
        let mut sign_only = send_payload(wallet(), STANDARD, &nonce, SolSendOptions::default());
        sign_only.mode = SolTxMode::SignOnly;
        let signed = sign_txs(&vault, approval(sign_only, ApprovalKind::SolTransaction)).unwrap();
        assert!(
            parse_wire_tx(&signed[0])
                .unwrap()
                .message
                .durable_nonce()
                .is_some()
        );
        let nonce_record = SolRecord {
            tx: signed[0].clone(),
            dapp: Some(SolDappMeta {
                signer_slot: 0,
                flags: dapp_flags::BROADCAST | dapp_flags::FEE_PAYER,
                ..site_paid.dapp.clone().unwrap()
            }),
            ..site_paid.clone()
        };
        assert_eq!(
            SolRecord::decode(&nonce_record.encode().unwrap()),
            Err(SolRecordError::Dapp)
        );
    }
}

#[test]
fn version_3_activity_transitions_room_and_counts() {
    let record = dapp_record(
        &wire(&transfer_message(), &[]),
        SolSendOptions::default(),
        ORIGIN,
    );
    assert!(activity_row(crate::lang::Lang::Ko, &record, 0).is_none());
    let mut plain = JournalPlain::default();
    push_record(&mut plain, &record).unwrap();
    let signature = record.signature();
    for (transition, status) in [
        (
            SolTransition::Landed {
                signature,
                slot: 77,
            },
            "succeeded",
        ),
        (
            SolTransition::FailedOnChain {
                signature,
                slot: 78,
                err: err::PROGRAM_INSTRUCTION,
            },
            "failed",
        ),
        (SolTransition::Expired { signature }, "expired"),
    ] {
        let mut copy = plain.clone();
        assert!(apply(&mut copy, &transition));
        let terminal = SolEntries::from_plain(&copy).records().remove(0);
        assert!(terminal.dapp.is_some());
        let row = activity_row(crate::lang::Lang::Ko, &terminal, 9_999).unwrap();
        assert_eq!(row.status, status);
        assert_eq!(row.account, wallet().to_base58());
        assert_eq!(row.tx_id, record.tx_id());
        assert_eq!(
            row.title,
            format!(
                "[{}] 사이트 거래 · {ORIGIN}",
                CLUSTER.display_name_in(crate::lang::Lang::Ko)
            )
        );
        assert_eq!((row.asset.as_str(), row.amount.as_str()), ("native", "0"));
        assert!(row.counterparty.is_empty());
        // `take_terminal` removes it and keeps its row.
        assert_eq!(
            take_terminal(crate::lang::Lang::Ko, &mut copy, 9_999),
            vec![row]
        );
        assert!(copy.entries.is_empty());
    }
    // A long origin is cut to 256 bytes on a character boundary.
    let mut long = record.clone();
    long.state = SolTxState::Landed;
    long.dapp.as_mut().unwrap().origin = longest_origin();
    let title = activity_row(crate::lang::Lang::Ko, &long, 0).unwrap().title;
    assert_eq!(title.len(), MAX_TITLE_BYTES);
    assert!(title.starts_with("[Solana devnet (테스트)] 사이트 거래 · https://aaa"));
    // Pending counts: per (cluster, signer) and in total; template sends do not count, and a
    // dApp send is not a template `Pending` (D20 stays template-only).
    let mut mainnet = record.clone();
    mainnet.cluster = SolCluster::Mainnet;
    let mut other_signer = record.clone();
    other_signer.dapp.as_mut().unwrap().public = [9; 32];
    let mut landed = record.clone();
    landed.state = SolTxState::Landed;
    let records = vec![
        record.clone(),
        record.clone(),
        mainnet,
        other_signer,
        landed,
    ];
    assert_eq!(pending_dapp_count(&records, CLUSTER, &wallet()), 2);
    assert_eq!(
        pending_dapp_count(&records, SolCluster::Mainnet, &wallet()),
        1
    );
    assert_eq!(pending_dapp_count(&records, CLUSTER, &key(9)), 1);
    assert_eq!(pending_dapp_total(&records), 4);
    assert!(pending_for(&records, CLUSTER, &wallet()).is_none());
    assert_eq!((SOL_DAPP_MAX_PENDING, SOL_DAPP_MAX_PENDING_TOTAL), (16, 32));
    assert_eq!(SOL_DAPP_MAX_PENDING_TOTAL * 2, SOL_JOURNAL_MAX_RECORDS);
}

/// A journal whose free plaintext is exactly `free` bytes (EVM entries as filler).
fn journal_with_free(free: usize) -> JournalPlain {
    let mut plain = JournalPlain::default();
    let mut left = MAX_PLAINTEXT - plain.plaintext_len() - free;
    while left > 0 {
        let body = (left - ENTRY_HEADER_LEN).min(crate::journal::MAX_BODY);
        plain.entries.push(Entry {
            kind: EntryKind::Evm,
            body: vec![1; body],
        });
        left -= ENTRY_HEADER_LEN + body;
    }
    assert_eq!(MAX_PLAINTEXT - plain.plaintext_len(), free);
    plain
}

#[test]
fn room_uses_the_version_3_maximum() {
    assert_eq!(SOL_JOURNAL_MAX_BODY_V3, 1_629);
    assert_eq!(EntryKind::Sol.max_body(), SOL_JOURNAL_MAX_BODY_V3);
    let need = ENTRY_HEADER_LEN + SOL_JOURNAL_MAX_BODY_V3;
    assert!(has_room(&journal_with_free(need)));
    assert!(!has_room(&journal_with_free(need - 1)));
    assert!(journal_with_free(need).has_room_for(EntryKind::Sol));
    assert!(!journal_with_free(need - 1).has_room_for(EntryKind::Sol));
}

/// A dApp send whose bytes are exactly a `T_SOL` transfer: version 3 still, `core()` is `None`,
/// so it is never a wallet send (the template `Pending` rule and the address book skip it).
#[test]
fn template_shaped_dapp_send_is_not_a_wallet_send() {
    let core = SolTransferCore {
        from: wallet(),
        to: key(0x22),
        asset: SolAsset::Sol,
        amount: 1_000_000,
        cu_limit: crate::sol::fee::SOL_TRANSFER_CU_LIMIT,
        cu_price_micro: 1_000,
    };
    let mut tx = vec![1_u8];
    tx.extend_from_slice(&[0; 64]);
    tx.extend_from_slice(&encode_message(&core, &[7; 32]));
    let record = dapp_record(&tx, SolSendOptions::default(), ORIGIN);
    assert!(parse_transaction(&record.tx, CLUSTER).is_ok());
    assert_eq!(record.core(), None);
    assert_eq!(record.signer(), Some(wallet()));
    let decoded = SolRecord::decode(&record.encode().unwrap()).unwrap();
    assert_eq!(decoded.core(), None);
    assert!(pending_for(&[decoded], CLUSTER, &wallet()).is_none());
    // The same bytes as a wallet send (version 1) keep their template meaning.
    let template = SolRecord {
        dapp: None,
        ..record
    };
    assert_eq!(template.core(), Some(core));
    assert_eq!(template.signer(), Some(wallet()));
    assert_eq!(template.send_flags(), None);
    let body = template.encode().unwrap();
    assert_eq!(body[1], 1);
    assert_eq!(SolRecord::decode(&body), Ok(template));
}

// ----- broadcast -------------------------------------------------------------------------------

#[test]
fn program_instruction_errors_are_deterministic() {
    assert_eq!(err::PROGRAM_INSTRUCTION, 9);
    assert!(err::is_deterministic(err::PROGRAM_INSTRUCTION));
    assert_eq!(
        err::text_in(9, crate::lang::Lang::Ko),
        "프로그램 명령이 실패했습니다"
    );
    for code in 1..=6 {
        assert!(err::is_deterministic(code));
    }
    for code in [0, 7, 8, 10, err::OTHER] {
        assert!(!err::is_deterministic(code));
    }
    assert_eq!(
        err::text_in(10, crate::lang::Lang::Ko),
        "알 수 없는 거래 오류"
    );
}
