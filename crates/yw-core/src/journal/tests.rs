//! Journal tests: V13 golden (spec/09 §3.13), the container rules (spec/02 §11.7), the EVM record
//! read checks, the §5.2 state table, clean-up and activity mapping (spec/03 §5, EVM-V13), and the
//! nonce rule (§3.6). Adapted from the durable-journal tests of
//! `archive/spec-v2.4:crates/key-agent/src/durable.rs:1732-1940,2087-2157` (in-memory storage,
//! v3 states).
#![expect(
    clippy::indexing_slicing,
    reason = "test fixtures index buffers of known length"
)]

use secp256k1::{Secp256k1, SecretKey};

use super::evm::{
    ActivityStatus, EvmEntries, EvmRecord, FLAG_MANUAL_RESEND, FLAG_RPC_HASH_MISMATCH,
    FLAG_USER_DISCARDED, GroupKey, NonceBlock, ReceiptStatus, RecordError, Role, Transition,
    TxState, apply, apply_to_plain, group_activity, groups, in_flight, latest_candidate, make_room,
    plan_nonce, push_record, room_after_cleanup, take_expired, transfer_summary,
};
use super::{Entry, EntryKind, JournalError, JournalPlain, MAX_ENTRIES, PLAIN_MAGIC};
use crate::error::VaultError;
use crate::evm::abi::erc20_transfer_data;
use crate::evm::address::Address;
use crate::evm::amount::U256;
use crate::evm::risk::E06;
use crate::evm::sign::sign_tx_with;
use crate::evm::tx::Eip1559Tx;
use crate::hex;
use crate::vault::FileKind;

const BESU_SIGNED: &str = "02f86e048203338301284d8301d97c828ae094000000000000000000000000000000000000aaaa8402933bc980c080a00f924cb68412c8f1cfd74d9b581c71eeaf94fff6abdde3e5b02ca6b2931dcf47a07dd1c50027c3e31f8b565e25ce68a5072110f61fce5eee81b195dd51273c2f83";
const BESU_SENDER: [u8; 20] = [
    0xfe, 0x3b, 0x55, 0x7e, 0x8f, 0xb6, 0x2b, 0x89, 0xf4, 0x91, 0x6b, 0x72, 0x1b, 0xe5, 0x5c, 0xeb,
    0x82, 0x8d, 0xbd, 0x73,
];
const BESU_HASH: &str = "2e564c87eb4b40e7f469b2eec5aa5d18b0b46a24e8bf0919439cfb0e8fcae446";
const T0: u64 = 1_790_000_000_000;
const CORRUPT: VaultError = VaultError::SidecarCorrupt(FileKind::Journal);

/// V13 golden: `01 ‖ 0000012e ‖ body` (307 bytes), fixed after the independent decode below passed.
const V13_GOLDEN: &str = concat!(
    "010000012e",
    "0101",
    "0000000000000004",
    "fe3b557e8fb62b89f4916b721be55ceb828dbd73",
    "0000000000000333",
    "01000000",
    "000001a0c4506c00",
    "000001a0c4506c00",
    "0000000000000000",
    "2e564c87eb4b40e7f469b2eec5aa5d18b0b46a24e8bf0919439cfb0e8fcae446",
    "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
    "0000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0006",
    "79772d617070",
    "0005",
    "5b745d2078",
    "00000071",
    "02f86e048203338301284d8301d97c828ae094000000000000000000000000000000000000aaaa8402933bc980c080a00f924cb68412c8f1cfd74d9b581c71eeaf94fff6abdde3e5b02ca6b2931dcf47a07dd1c50027c3e31f8b565e25ce68a5072110f61fce5eee81b195dd51273c2f83",
);

fn h(text: &str) -> Vec<u8> {
    hex::decode(text).unwrap()
}

fn digest_a0() -> [u8; 32] {
    let mut digest = [0_u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = 0xa0 + u8::try_from(index).unwrap();
    }
    digest
}

fn v13_record() -> EvmRecord {
    EvmRecord::new_signed(
        4,
        Address::from_bytes(BESU_SENDER),
        819,
        Role::Original,
        T0,
        digest_a0(),
        "yw-app",
        "[t] x",
        h(BESU_SIGNED),
    )
    .unwrap()
}

#[test]
fn v13_golden_entry_and_independent_decode() {
    let record = v13_record();
    let body = record.encode().unwrap();
    assert_eq!(body.len(), 302);
    let mut plain = JournalPlain::default();
    push_record(&mut plain, &record).unwrap();
    let bytes = plain.encode().unwrap();
    let entry = &bytes[16..];
    assert_eq!(entry.len(), 307);
    // Independent decode by the spec/02 §5.4 framing and the spec/03 §5.1 offset table.
    assert_eq!(&bytes[..8], b"YWJPL003");
    assert_eq!(&bytes[8..10], &[0, 1]);
    assert_eq!(&bytes[10..16], &[0; 6]);
    assert_eq!(entry[0], 0x01);
    assert_eq!(u32::from_be_bytes(entry[1..5].try_into().unwrap()), 302);
    let b = &entry[5..];
    assert_eq!(b[0], 0x01, "record_kind");
    assert_eq!(b[1], 0x01, "record_version");
    assert_eq!(u64::from_be_bytes(b[2..10].try_into().unwrap()), 4);
    assert_eq!(&b[10..30], &BESU_SENDER);
    assert_eq!(u64::from_be_bytes(b[30..38].try_into().unwrap()), 819);
    assert_eq!((b[38], b[39], b[40], b[41]), (1, 0, 0, 0));
    assert_eq!(u64::from_be_bytes(b[42..50].try_into().unwrap()), T0);
    assert_eq!(u64::from_be_bytes(b[50..58].try_into().unwrap()), T0);
    assert_eq!(u64::from_be_bytes(b[58..66].try_into().unwrap()), 0);
    assert_eq!(hex::encode(&b[66..98]), BESU_HASH);
    assert_eq!(&b[98..130], &digest_a0());
    assert_eq!(u64::from_be_bytes(b[130..138].try_into().unwrap()), 0);
    assert_eq!(&b[138..170], &[0; 32]);
    assert_eq!(u16::from_be_bytes(b[170..172].try_into().unwrap()), 6);
    assert_eq!(&b[172..178], b"yw-app");
    assert_eq!(u16::from_be_bytes(b[178..180].try_into().unwrap()), 5);
    assert_eq!(&b[180..185], b"[t] x");
    assert_eq!(u32::from_be_bytes(b[185..189].try_into().unwrap()), 113);
    assert_eq!(&b[189..], h(BESU_SIGNED).as_slice());
    // Golden bytes.
    assert_eq!(hex::encode(entry), V13_GOLDEN);
    // Round trip.
    let decoded = JournalPlain::decode(&bytes).unwrap();
    assert_eq!(decoded, plain);
    let entries = EvmEntries::from_plain(&decoded);
    assert_eq!(entries.corrupt, 0);
    assert_eq!(entries.records(), vec![record]);
}

#[test]
fn container_round_trips_all_three_kinds() {
    let plain = JournalPlain {
        entries: vec![
            Entry {
                kind: EntryKind::Evm,
                body: v13_record().encode().unwrap(),
            },
            Entry {
                kind: EntryKind::Sol,
                body: vec![7; 40],
            },
            Entry {
                kind: EntryKind::Btc,
                body: vec![9; 3],
            },
        ],
    };
    let bytes = plain.encode().unwrap();
    assert_eq!(JournalPlain::decode(&bytes).unwrap(), plain);
    let empty = JournalPlain::default().encode().unwrap();
    assert_eq!(empty.len(), 16);
    assert_eq!(&empty[..8], &PLAIN_MAGIC);
    assert!(JournalPlain::decode(&empty).unwrap().entries.is_empty());
}

fn frame(count: u16, entries: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut out = PLAIN_MAGIC.to_vec();
    out.extend_from_slice(&count.to_be_bytes());
    out.extend_from_slice(&[0; 6]);
    for (kind, body) in entries {
        out.push(*kind);
        out.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes());
        out.extend_from_slice(body);
    }
    out
}

#[test]
fn container_framing_errors_are_sidecar_corrupt() {
    let ok = frame(1, &[(1, vec![1; 4])]);
    assert!(JournalPlain::decode(&ok).is_ok());
    // Kind 0 is never written (5–255 are a later build's chains, kept: see below).
    assert_eq!(
        JournalPlain::decode(&frame(1, &[(0, vec![1])])),
        Err(CORRUPT)
    );
    // body_len 0.
    assert_eq!(
        JournalPlain::decode(&frame(1, &[(1, vec![])])),
        Err(CORRUPT)
    );
    // body_len above 1 MiB (declared, no bytes).
    let mut big = frame(1, &[]);
    big.push(1);
    big.extend_from_slice(&1_048_577_u32.to_be_bytes());
    assert_eq!(JournalPlain::decode(&big), Err(CORRUPT));
    // body_len past the end.
    let mut short = frame(1, &[]);
    short.push(1);
    short.extend_from_slice(&10_u32.to_be_bytes());
    short.extend_from_slice(&[0; 9]);
    assert_eq!(JournalPlain::decode(&short), Err(CORRUPT));
    // Trailing bytes.
    let mut trailing = ok.clone();
    trailing.push(0);
    assert_eq!(JournalPlain::decode(&trailing), Err(CORRUPT));
    // Count mismatch (fewer entries than declared, more entries than declared).
    assert_eq!(
        JournalPlain::decode(&frame(2, &[(1, vec![1])])),
        Err(CORRUPT)
    );
    assert_eq!(
        JournalPlain::decode(&frame(0, &[(1, vec![1])])),
        Err(CORRUPT)
    );
    // entry_count 257.
    let entries: Vec<(u8, Vec<u8>)> = (0..257).map(|_| (2_u8, vec![1_u8])).collect();
    assert_eq!(JournalPlain::decode(&frame(257, &entries)), Err(CORRUPT));
    let entries: Vec<(u8, Vec<u8>)> = (0..256).map(|_| (2_u8, vec![1_u8])).collect();
    assert!(JournalPlain::decode(&frame(256, &entries)).is_ok());
    // Reserved bytes and magic.
    let mut reserved = ok.clone();
    reserved[12] = 1;
    assert_eq!(JournalPlain::decode(&reserved), Err(CORRUPT));
    let mut magic = ok.clone();
    magic[7] = b'4';
    assert_eq!(JournalPlain::decode(&magic), Err(CORRUPT));
    for length in 0..ok.len() {
        assert_eq!(
            JournalPlain::decode(&ok[..length]),
            Err(CORRUPT),
            "{length}"
        );
    }
    // 257 entries are never encoded.
    let over = JournalPlain {
        entries: (0..257)
            .map(|_| Entry {
                kind: EntryKind::Sol,
                body: vec![1],
            })
            .collect(),
    };
    assert_eq!(over.encode(), Err(JournalError::Full));
}

/// A later build's chain (kind 5–255) is not a framing error any more: its entry is kept byte
/// for byte beside this build's chains, which read and clean up only their own entries (before,
/// one new kind made the whole journal — every chain's in-flight records — unreadable here).
#[test]
fn unknown_kinds_are_kept_verbatim() {
    let record = v13_record().encode().unwrap();
    let bytes = frame(3, &[(5, vec![9; 7]), (1, record), (255, vec![0xAB])]);
    let plain = JournalPlain::decode(&bytes).unwrap();
    assert_eq!(plain.entries[0].kind, EntryKind::Unknown(5));
    assert_eq!(plain.entries[2].kind, EntryKind::Unknown(255));
    assert_eq!(plain.encode().unwrap(), bytes, "re-encoded byte for byte");
    let entries = EvmEntries::from_plain(&plain);
    assert_eq!((entries.records().len(), entries.corrupt), (1, 0));
    assert_eq!(EntryKind::read(5), Some(EntryKind::Unknown(5)));
    assert_eq!(EntryKind::read(4), Some(EntryKind::Zec));
    assert_eq!(EntryKind::read(0), None);
    assert_eq!(EntryKind::from_code(5), None);
}

fn tamper(body: &[u8], at: usize, value: u8) -> Vec<u8> {
    let mut out = body.to_vec();
    out[at] = value;
    out
}

#[test]
fn record_read_checks() {
    let body = v13_record().encode().unwrap();
    assert!(EvmRecord::decode(&body).is_ok());
    let mut longer = body.clone();
    longer.push(0);
    assert_eq!(EvmRecord::decode(&longer), Err(RecordError::Length));
    assert_eq!(
        EvmRecord::decode(&body[..body.len() - 1]),
        Err(RecordError::Length)
    );
    assert_eq!(
        EvmRecord::decode(&tamper(&body, 0, 2)),
        Err(RecordError::Header)
    );
    assert_eq!(
        EvmRecord::decode(&tamper(&body, 1, 2)),
        Err(RecordError::Header)
    );
    assert_eq!(
        EvmRecord::decode(&tamper(&body, 38, 7)),
        Err(RecordError::Value)
    );
    assert_eq!(
        EvmRecord::decode(&tamper(&body, 38, 0)),
        Err(RecordError::Value)
    );
    assert_eq!(
        EvmRecord::decode(&tamper(&body, 39, 3)),
        Err(RecordError::Value)
    );
    assert_eq!(
        EvmRecord::decode(&tamper(&body, 40, 3)),
        Err(RecordError::Value)
    );
    assert_eq!(
        EvmRecord::decode(&tamper(&body, 41, 8)),
        Err(RecordError::Flags)
    );
    assert!(EvmRecord::decode(&tamper(&body, 41, 3)).is_ok());
    // bit 2 `manual_resend` (old records without it decode unchanged, see above).
    let manual = EvmRecord::decode(&tamper(&body, 41, 4)).unwrap();
    assert!(manual.has_flag(FLAG_MANUAL_RESEND));
    assert_eq!(manual.encode().unwrap(), tamper(&body, 41, 4));
    assert!(EvmRecord::decode(&tamper(&body, 41, 7)).is_ok());
    // tx_hash.
    assert_eq!(
        EvmRecord::decode(&tamper(&body, 66, body[66] ^ 1)),
        Err(RecordError::Hash)
    );
    // chain id and nonce must match the raw transaction.
    assert_eq!(
        EvmRecord::decode(&tamper(&body, 9, 5)),
        Err(RecordError::Mismatch)
    );
    assert_eq!(
        EvmRecord::decode(&tamper(&body, 37, 0x34)),
        Err(RecordError::Mismatch)
    );
    // Signer.
    assert_eq!(
        EvmRecord::decode(&tamper(&body, 10, 0)),
        Err(RecordError::Signer)
    );
    // Origin text.
    assert_eq!(
        EvmRecord::decode(&tamper(&body, 172, 0xff)),
        Err(RecordError::Text)
    );
    // origin_len 256 is out of range.
    let mut origin = body.clone();
    origin[170] = 1;
    origin[171] = 0;
    assert_eq!(EvmRecord::decode(&origin), Err(RecordError::Length));
    // A raw that is not a strict signed transaction (hash recomputed so that only decoding fails).
    let mut record = v13_record();
    record.raw = vec![0x02, 0xc0];
    record.tx_hash = crate::evm::tx::tx_hash(&record.raw);
    assert_eq!(
        EvmRecord::decode(&record.encode().unwrap()),
        Err(RecordError::Raw)
    );
}

struct Signer {
    ctx: Secp256k1<secp256k1::All>,
    secret: SecretKey,
    account: Address,
}

impl Signer {
    fn new(seed: u8) -> Self {
        let ctx = Secp256k1::new();
        let secret = SecretKey::from_byte_array([seed; 32]).unwrap();
        let account = Address::from_public_key(&secret.public_key(&ctx));
        Self {
            ctx,
            secret,
            account,
        }
    }

    #[expect(clippy::unused_self, reason = "keeps the fixture calls uniform")]
    fn tx(&self, chain_id: u64, nonce: u64, tip: u64, data_len: usize) -> Eip1559Tx {
        Eip1559Tx {
            chain_id,
            nonce,
            max_priority_fee_per_gas: U256::from_u64(tip),
            max_fee_per_gas: U256::from_u64(tip.saturating_mul(10)),
            gas_limit: 21_000,
            to: Address::from_bytes([0x42; 20]),
            value: U256::from_u64(1_000),
            data: vec![0xab; data_len],
            access_list: Vec::new(),
        }
    }

    fn record(&self, tx: &Eip1559Tx, role: Role, created: u64) -> EvmRecord {
        let signed = sign_tx_with(&self.ctx, &self.secret, tx, &self.account).unwrap();
        EvmRecord::new_signed(
            tx.chain_id,
            self.account,
            tx.nonce,
            role,
            created,
            [3; 32],
            "yw-app",
            "[Sepolia 테스트넷] SepoliaETH 보내기",
            signed.raw,
        )
        .unwrap()
    }
}

#[test]
fn state_transition_table() {
    let signer = Signer::new(7);
    let original = signer.record(&signer.tx(11_155_111, 5, 100, 0), Role::Original, T0);
    let speed = signer.record(&signer.tx(11_155_111, 5, 111, 0), Role::SpeedUp, T0 + 10);
    let mut records = vec![original.clone(), speed.clone()];
    let key = original.key();
    // (none) → Signed.
    assert_eq!(records[0].state, TxState::Signed);
    // Signed → Broadcast.
    let changed = apply(
        &mut records,
        &Transition::Broadcast {
            tx_hash: original.tx_hash,
            at_unix_ms: T0 + 1,
        },
    );
    assert_eq!(changed, [0]);
    assert_eq!(records[0].state, TxState::Broadcast);
    assert_eq!(records[0].last_broadcast_unix_ms, T0 + 1);
    // Broadcast again: no change (only Signed moves).
    assert!(
        apply(
            &mut records,
            &Transition::Broadcast {
                tx_hash: original.tx_hash,
                at_unix_ms: T0 + 2,
            }
        )
        .is_empty()
    );
    // Hash mismatch keeps Signed with the flag.
    apply(
        &mut records,
        &Transition::HashMismatch {
            tx_hash: speed.tx_hash,
            at_unix_ms: T0 + 3,
        },
    );
    assert_eq!(records[1].state, TxState::Signed);
    assert!(records[1].has_flag(FLAG_RPC_HASH_MISMATCH));
    // Receipt for the speed-up → Included, the original → Replaced.
    let changed = apply(
        &mut records,
        &Transition::Included {
            tx_hash: speed.tx_hash,
            block_number: 77,
            block_hash: [7; 32],
            success: true,
            at_unix_ms: T0 + 4,
        },
    );
    assert_eq!(changed.len(), 2);
    assert_eq!(records[1].state, TxState::Included);
    assert_eq!(records[1].receipt_status, ReceiptStatus::Success);
    assert_eq!(records[1].included_block_number, 77);
    assert_eq!(records[0].state, TxState::Replaced);
    assert_eq!(in_flight(&records, 11_155_111, &signer.account), Some(5));
    // Finalized (one confirmation, committed with Included by tracking): the nonce is free.
    apply(
        &mut records,
        &Transition::Finalized {
            tx_hash: speed.tx_hash,
            at_unix_ms: T0 + 7,
        },
    );
    assert_eq!(records[1].state, TxState::Finalized);
    assert_eq!(records[1].receipt_status, ReceiptStatus::Success);
    assert_eq!(in_flight(&records, 11_155_111, &signer.account), None);
    // Terminal records do not move.
    for transition in [
        Transition::Broadcast {
            tx_hash: speed.tx_hash,
            at_unix_ms: T0 + 8,
        },
        Transition::Finalized {
            tx_hash: speed.tx_hash,
            at_unix_ms: T0 + 8,
        },
        Transition::Dropped {
            key,
            at_unix_ms: T0 + 8,
        },
        Transition::Included {
            tx_hash: original.tx_hash,
            block_number: 1,
            block_hash: [1; 32],
            success: true,
            at_unix_ms: T0 + 8,
        },
    ] {
        assert!(apply(&mut records, &transition).is_empty());
    }
}

#[test]
fn dropped_and_discarded_groups() {
    let signer = Signer::new(8);
    let a = signer.record(&signer.tx(1, 0, 100, 0), Role::Original, T0);
    let b = signer.record(&signer.tx(1, 0, 111, 0), Role::Cancel, T0 + 1);
    let other = signer.record(&signer.tx(1, 1, 100, 0), Role::Original, T0 + 2);
    let mut records = vec![a.clone(), b, other];
    let changed = apply(
        &mut records,
        &Transition::Dropped {
            key: a.key(),
            at_unix_ms: T0 + 9,
        },
    );
    assert_eq!(changed, [0, 1]);
    assert!(records[..2].iter().all(|r| r.state == TxState::Dropped));
    assert!(!records[0].has_flag(FLAG_USER_DISCARDED));
    assert_eq!(records[2].state, TxState::Signed);
    let third = records[2].key();
    let changed = apply(
        &mut records,
        &Transition::Discarded {
            key: third,
            at_unix_ms: T0 + 10,
        },
    );
    assert_eq!(changed, [2]);
    assert_eq!(records[2].state, TxState::Dropped);
    assert!(records[2].has_flag(FLAG_USER_DISCARDED));
}

#[test]
fn manual_resend_flag_is_set_on_signed_and_cleared_by_broadcast() {
    let signer = Signer::new(10);
    let record = signer.record(&signer.tx(1, 0, 100, 0), Role::Original, T0);
    let mut records = vec![record.clone()];
    let manual = Transition::ManualResend {
        tx_hash: record.tx_hash,
        at_unix_ms: T0 + 1,
    };
    assert_eq!(manual.name(), "ManualResend");
    assert_eq!(apply(&mut records, &manual), [0]);
    assert_eq!(records[0].state, TxState::Signed);
    assert!(records[0].has_flag(FLAG_MANUAL_RESEND));
    assert_eq!(records[0].updated_unix_ms, T0 + 1);
    // Idempotent; the persisted flag survives a round trip.
    assert!(apply(&mut records, &manual).is_empty());
    let decoded = EvmRecord::decode(&records[0].encode().unwrap()).unwrap();
    assert!(decoded.has_flag(FLAG_MANUAL_RESEND));
    // A later broadcast (user `재전송` accepted) clears it.
    apply(
        &mut records,
        &Transition::Broadcast {
            tx_hash: record.tx_hash,
            at_unix_ms: T0 + 2,
        },
    );
    assert_eq!(records[0].state, TxState::Broadcast);
    assert!(!records[0].has_flag(FLAG_MANUAL_RESEND));
    // Only `Signed` takes it.
    assert!(
        apply(
            &mut records,
            &Transition::ManualResend {
                tx_hash: record.tx_hash,
                at_unix_ms: T0 + 3,
            }
        )
        .is_empty()
    );
}

#[test]
fn corrupt_bodies_are_kept_verbatim() {
    let signer = Signer::new(9);
    let good = signer.record(&signer.tx(1, 0, 100, 0), Role::Original, T0);
    let mut bad_body = good.encode().unwrap();
    bad_body[66] ^= 0xff;
    let mut plain = JournalPlain::default();
    plain.entries.push(Entry {
        kind: EntryKind::Evm,
        body: bad_body.clone(),
    });
    plain.entries.push(Entry {
        kind: EntryKind::Sol,
        body: vec![5; 10],
    });
    push_record(&mut plain, &good).unwrap();
    let entries = EvmEntries::from_plain(&plain);
    assert_eq!(entries.corrupt, 1);
    assert_eq!(entries.records.len(), 1);
    assert_eq!(entries.records[0].0, 2);
    let written = apply_to_plain(
        &mut plain,
        &[Transition::Broadcast {
            tx_hash: good.tx_hash,
            at_unix_ms: T0 + 1,
        }],
    );
    assert_eq!(written, 1);
    assert_eq!(plain.entries[0].body, bad_body);
    assert_eq!(plain.entries[1].body, vec![5; 10]);
    let reread = EvmEntries::from_plain(&JournalPlain::decode(&plain.encode().unwrap()).unwrap());
    assert_eq!(reread.records[0].1.state, TxState::Broadcast);
}

#[test]
fn nonce_rule_and_e06_texts() {
    assert_eq!(plan_nonce(None, 4, 4), Ok(4));
    assert_eq!(
        plan_nonce(Some(3), 3, 4),
        Err(NonceBlock::InFlight { nonce: 3 })
    );
    assert_eq!(plan_nonce(None, 4, 5), Err(NonceBlock::ExternalPending));
    let warning = NonceBlock::InFlight { nonce: 3 }.warning();
    assert_eq!(warning.rule, E06);
    assert_eq!(warning.text, "진행 중인 거래가 있습니다 (nonce 3)");
    assert_eq!(
        NonceBlock::ExternalPending.warning().text,
        "이 계정에서 다른 곳으로 보낸 대기 중 거래가 있습니다"
    );
    assert_eq!(
        super::evm::journal_full_warning().text,
        "거래 저널 공간이 부족합니다"
    );
    assert_eq!(
        JournalError::Full.to_string(),
        "거래 저널 공간이 부족합니다"
    );
}

fn finalize(records: &mut [EvmRecord], hash: [u8; 32], success: bool, at: u64) {
    apply(
        records,
        &Transition::Included {
            tx_hash: hash,
            block_number: 1,
            block_hash: [1; 32],
            success,
            at_unix_ms: at,
        },
    );
    apply(
        records,
        &Transition::Finalized {
            tx_hash: hash,
            at_unix_ms: at,
        },
    );
}

#[test]
fn activity_mapping_of_terminal_groups() {
    let signer = Signer::new(10);
    // Speed-up confirmed: one row with the confirmed hash and the original's title.
    let original = signer.record(&signer.tx(1, 0, 100, 0), Role::Original, T0);
    let speed = signer.record(&signer.tx(1, 0, 111, 0), Role::SpeedUp, T0 + 1);
    let mut records = vec![original.clone(), speed.clone()];
    finalize(&mut records, speed.tx_hash, true, T0 + 50);
    let grouped = groups(&records);
    let rows = group_activity(&grouped[0].1).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].tx_id, format!("0x{}", hex::encode(&speed.tx_hash)));
    assert_eq!(rows[0].status, ActivityStatus::Succeeded);
    assert_eq!(rows[0].title, original.label);
    assert_eq!(rows[0].asset, "native");
    assert_eq!(rows[0].amount, "1000");
    assert_eq!(
        rows[0].counterparty,
        Address::from_bytes([0x42; 20]).to_lower_hex()
    );
    assert_eq!(rows[0].time_unix_ms, T0 + 50);
    // Cancel confirmed: original replaced + a separate "거래 취소" row.
    let original = signer.record(&signer.tx(1, 1, 100, 0), Role::Original, T0);
    let mut cancel_tx = signer.tx(1, 1, 111, 0);
    cancel_tx.to = signer.account;
    cancel_tx.value = U256::ZERO;
    cancel_tx.data = Vec::new();
    let cancel = signer.record(&cancel_tx, Role::Cancel, T0 + 1);
    let mut records = vec![original.clone(), cancel.clone()];
    finalize(&mut records, cancel.tx_hash, false, T0 + 60);
    let rows = group_activity(&groups(&records)[0].1).unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].status, ActivityStatus::Replaced);
    assert_eq!(
        rows[0].tx_id,
        format!("0x{}", hex::encode(&original.tx_hash))
    );
    assert_eq!(rows[1].title, "거래 취소");
    assert_eq!(rows[1].status, ActivityStatus::Failed);
    assert_eq!(rows[1].amount, "0");
    // Dropped.
    let mut records = vec![signer.record(&signer.tx(1, 2, 100, 0), Role::Original, T0)];
    let key = records[0].key();
    apply(
        &mut records,
        &Transition::Discarded {
            key,
            at_unix_ms: T0 + 70,
        },
    );
    let rows = group_activity(&groups(&records)[0].1).unwrap();
    assert_eq!(rows[0].status, ActivityStatus::Dropped);
    // A non-terminal group has no rows yet.
    let pending = vec![signer.record(&signer.tx(1, 3, 100, 0), Role::Original, T0)];
    assert!(group_activity(&groups(&pending)[0].1).is_none());
    // ERC-20 transfer summary.
    let mut token_tx = signer.tx(1, 4, 100, 0);
    token_tx.value = U256::ZERO;
    token_tx.data = erc20_transfer_data(&Address::from_bytes([0x11; 20]), &U256::from_u64(5));
    let (asset, amount, counterparty) = transfer_summary(&token_tx);
    assert_eq!(asset, Address::from_bytes([0x42; 20]).to_lower_hex());
    assert_eq!(amount, "5");
    assert_eq!(counterparty, Address::from_bytes([0x11; 20]).to_lower_hex());
    assert_eq!(latest_candidate(&groups(&pending)[0].1).unwrap().nonce, 3);
}

#[test]
fn one_confirmation_is_final_and_frees_the_nonce() {
    // Tracking commits a verified receipt as Included + Finalized in one write (spec/03 §4.5):
    // the record is final at one confirmation, the next nonce is free (D20), and the group's
    // activity row is "succeeded".
    let signer = Signer::new(14);
    let mut plain = JournalPlain::default();
    let sent = signer.record(&signer.tx(1, 0, 100, 0), Role::Original, T0);
    push_record(&mut plain, &sent).unwrap();
    let records = EvmEntries::from_plain(&plain).records();
    assert_eq!(in_flight(&records, 1, &signer.account), Some(0));
    let changed = apply_to_plain(
        &mut plain,
        &[
            Transition::Included {
                tx_hash: sent.tx_hash,
                block_number: 9,
                block_hash: [9; 32],
                success: true,
                at_unix_ms: T0 + 12_000,
            },
            Transition::Finalized {
                tx_hash: sent.tx_hash,
                at_unix_ms: T0 + 12_000,
            },
        ],
    );
    assert_eq!(changed, 1);
    let records = EvmEntries::from_plain(&plain).records();
    assert_eq!(records[0].state, TxState::Finalized);
    assert_eq!(records[0].included_block_number, 9);
    assert_eq!(in_flight(&records, 1, &signer.account), None);
    let members: Vec<&EvmRecord> = records.iter().collect();
    let rows = group_activity(&members).unwrap();
    assert_eq!(rows[0].status, ActivityStatus::Succeeded);
}

#[test]
fn expired_terminal_groups_move_to_activity_after_seven_days() {
    let signer = Signer::new(11);
    let mut plain = JournalPlain::default();
    let done = signer.record(&signer.tx(1, 0, 100, 0), Role::Original, T0);
    let open = signer.record(&signer.tx(1, 1, 100, 0), Role::Original, T0);
    push_record(&mut plain, &done).unwrap();
    push_record(&mut plain, &open).unwrap();
    apply_to_plain(
        &mut plain,
        &[Transition::Discarded {
            key: done.key(),
            at_unix_ms: T0 + 1_000,
        }],
    );
    assert!(take_expired(&mut plain, T0 + 1_000 + super::evm::RETENTION_MS - 1).is_empty());
    let rows = take_expired(&mut plain, T0 + 1_000 + super::evm::RETENTION_MS);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].status, ActivityStatus::Dropped);
    let left = EvmEntries::from_plain(&plain).records();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].tx_hash, open.tx_hash);
}

#[test]
fn room_check_cleans_terminal_groups_oldest_first_then_reports_full() {
    let signer = Signer::new(12);
    let mut plain = JournalPlain::default();
    // 255 opaque SOL entries + one terminal EVM group: no room for a new EVM record until the
    // terminal group goes (count bound).
    for _ in 0..(MAX_ENTRIES - 1) {
        plain.entries.push(Entry {
            kind: EntryKind::Sol,
            body: vec![1],
        });
    }
    let done = signer.record(&signer.tx(1, 0, 100, 0), Role::Original, T0);
    push_record(&mut plain, &done).unwrap();
    apply_to_plain(
        &mut plain,
        &[Transition::Discarded {
            key: done.key(),
            at_unix_ms: T0,
        }],
    );
    assert!(!plain.has_room_for(EntryKind::Evm));
    assert!(room_after_cleanup(&plain));
    let rows = make_room(&mut plain).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(plain.entries.len(), MAX_ENTRIES - 1);
    assert!(plain.has_room_for(EntryKind::Evm));
    // A non-terminal record cannot be removed: Full, nothing changed.
    let open = signer.record(&signer.tx(1, 1, 100, 0), Role::Original, T0);
    push_record(&mut plain, &open).unwrap();
    let before = plain.clone();
    assert!(!room_after_cleanup(&plain));
    assert_eq!(make_room(&mut plain), Err(JournalError::Full));
    assert_eq!(plain, before);
    assert_eq!(push_record(&mut plain, &open), Err(JournalError::Full));
}

#[test]
fn size_bound_uses_the_largest_evm_body() {
    // 127 near-maximal records fill 16 MiB: the 128th does not fit by size (count is far from
    // 256), and removing the oldest terminal group frees room.
    let signer = Signer::new(13);
    let mut plain = JournalPlain::default();
    let mut first: Option<GroupKey> = None;
    let mut nonce = 0;
    while plain.has_room_for(EntryKind::Evm) {
        let record = signer.record(
            &signer.tx(1, nonce, 100, 130_900),
            Role::Original,
            T0 + nonce,
        );
        first.get_or_insert(record.key());
        push_record(&mut plain, &record).unwrap();
        nonce += 1;
    }
    assert!(plain.entries.len() < MAX_ENTRIES);
    assert!(plain.plaintext_len() <= super::MAX_PLAINTEXT);
    assert_eq!(make_room(&mut plain), Err(JournalError::Full));
    apply_to_plain(
        &mut plain,
        &[Transition::Discarded {
            key: first.unwrap(),
            at_unix_ms: T0,
        }],
    );
    let rows = make_room(&mut plain).unwrap();
    assert_eq!(rows.len(), 1);
    assert!(plain.has_room_for(EntryKind::Evm));
}
