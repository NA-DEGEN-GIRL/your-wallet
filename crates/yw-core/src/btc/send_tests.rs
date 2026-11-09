//! Bitcoin send-path tests that need the vault or crate internals (spec/08 §14.2, spec/09 §4.4):
//! `approval_btc_digest`, `amount_record_mismatch_aborts` (BTC-N3), `post_sign_tamper_each_field`,
//! the `sign_plan` refusals (`KeyMismatch`, approvals of other plans) and the core end-to-end
//! flow on testnet4 (verified fake UTXOs → plan → draft → issue/consume → `sign_plan` →
//! `verify_signed` → journal record round trip → state flow → meta updates). Keys come from the
//! `about_vault` helper of `btc::tests`.
#![expect(
    clippy::indexing_slicing,
    reason = "test fixtures index buffers of known length"
)]

use secp256k1::ecdsa::Signature;

use super::account::{BtcAccountKey, ScriptType};
use super::address::parse_address;
use super::amount::Sats;
use super::display::{BtcSendFacts, btc_payload, build_btc_request};
use super::fee::{FeeChoice, FeeRate, FeeSelection, FeeSource, choose_fee_rate, fee_floor};
use super::meta::{BtcMeta, Discovery, ListedUtxo, VerifiedUtxo};
use super::network::BtcNetwork;
use super::policy::{
    BroadcastOutcome, MempoolAccept, PrecheckOutcome, SendRawResult, broadcast_outcome,
    check_mempool_accept,
};
use super::prevtx::verify_prev_output;
use super::select::{SendAmount, SendPlan, SendRequest, plan_send};
use super::sign::{SignError, WitnessSigError, check_recorded_amounts, sign_plan};
use super::tests::about_vault;
use super::tx::{OutPoint, Transaction, TxIn, TxOut, Txid, parse_transaction, serialize, txid};
use super::verify::{PostSignError, verify_signed};
use crate::approval::{
    AccountRef, ApprovalDraft, ApprovalError, ApprovalId, ApprovalKind, ApprovalOrigin,
    ApprovalStore, Approved, ChainRef, FieldKey, Signer, SigningPayload, approval_digest,
};
use crate::bip32::path::{AccountIndex, BtcChain, BtcCoin};
use crate::journal::JournalPlain;
use crate::journal::btc::{
    BtcEntries, BtcRecord, BtcTxState, TrackObservation, apply_observation, check_can_send,
    check_plan_allowed, finished_rows, in_flight_outpoints, make_room, push_record,
    recorded_amounts, set_state,
};
use crate::vault::{EvmKeySource, Vault};

const NET: BtcNetwork = BtcNetwork::Testnet4;
const TIP: u32 = 120_000;
const NOW_UNIX: u64 = 1_790_000_000;
const NOW_MS: u64 = 5_000;
const EXPIRES: u64 = 1_790_000_120_000;
/// BIP173 P2WSH test vector address (testnet).
const P2WSH: &str = "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7";

struct Fixture {
    vault: Vault,
    account: BtcAccountKey,
    meta: BtcMeta,
}

/// A non-witness previous transaction paying `value` to `script` (output 0).
fn fake_prev(script: &[u8], value: u64, salt: u8) -> (Vec<u8>, Txid) {
    let tx = Transaction {
        version: 2,
        inputs: vec![TxIn {
            prevout: OutPoint {
                txid: Txid::from_bytes([salt; 32]),
                vout: 3,
            },
            script_sig: vec![0x51],
            sequence: 0xFFFF_FFFF,
            witness: Vec::new(),
        }],
        outputs: vec![TxOut {
            value: Sats::new(value).unwrap(),
            script_pubkey: script.to_vec(),
        }],
        lock_time: 0,
    };
    (serialize(&tx, false), txid(&tx))
}

/// testnet4 `about` wallet: discovery finds receive 0–1 used, then three verified UTXOs
/// (receive 0: 50,000, receive 1: 30,000, change 0: 80,000 after one change index is used).
/// The account is in HD mode (change on the change chain); [`fixture_fixed`] is the same wallet
/// in fixed-address mode.
fn fixture() -> Fixture {
    fixture_mode(false)
}

/// [`fixture`] with BIP84 account 0 in fixed-address mode (spec/08 §3.5, the default).
fn fixture_fixed() -> Fixture {
    fixture_mode(true)
}

fn fixture_mode(single_address: bool) -> Fixture {
    let vault = about_vault();
    let account = BtcAccountKey::primary(vault.btc_account_xpub(BtcCoin::Test).unwrap())
        .with_single_address(single_address);
    fixture_of(vault, account)
}

/// The [`fixture`] discovery and UTXOs on any account of `vault`.
fn fixture_of(vault: Vault, account: BtcAccountKey) -> Fixture {
    let mut meta = BtcMeta::with_key(NET, account);
    let mut discovery = Discovery::full();
    while let Some((chain, index)) = discovery.next_request() {
        let used =
            (chain == BtcChain::Receive && index < 2) || (chain == BtcChain::Change && index == 0);
        discovery.observe(u64::from(used));
    }
    discovery.apply(&mut meta).unwrap();
    assert_eq!((meta.receive_next(), meta.change_next()), (2, 1));
    let owned = [
        (BtcChain::Receive, 0_u32, 50_000_u64, 0xa1_u8, TIP - 10),
        (BtcChain::Receive, 1, 30_000, 0xa2, TIP - 5),
        (BtcChain::Change, 0, 80_000, 0xa3, TIP - 20),
    ];
    let mut listed = Vec::new();
    let mut newly = Vec::new();
    for (chain, index, value, salt, height) in owned {
        let script = meta.expected_script(chain, index).unwrap();
        let (raw, prev_txid) = fake_prev(&script, value, salt);
        let item = ListedUtxo {
            outpoint: OutPoint {
                txid: prev_txid,
                vout: 0,
            },
            chain,
            index,
            height,
        };
        let prev = verify_prev_output(&raw, &prev_txid, 0, &script).unwrap();
        listed.push(item);
        newly.push(VerifiedUtxo::from_prev(&prev, &item));
    }
    assert_eq!(meta.unverified(&listed).len(), 3);
    let report = meta.apply_refresh(&listed, &newly, &[], &[]);
    assert_eq!((report.inserted, report.auto_frozen), (3, 0));
    Fixture {
        vault,
        account,
        meta,
    }
}

fn two_sat_per_vb() -> FeeChoice {
    choose_fee_rate(
        FeeSelection::Manual(FeeRate::from_sat_per_kvb(2_000)),
        fee_floor(
            Some(FeeRate::from_sat_per_kvb(100)),
            Some(FeeRate::from_sat_per_kvb(100)),
        ),
    )
    .unwrap()
}

fn plan_with(
    fixture: &Fixture,
    amount: SendAmount,
    fee: FeeChoice,
    seed: u8,
    typed: Option<Sats>,
) -> SendPlan {
    let candidates = fixture.meta.spendable(TIP, &[]);
    plan_send(&SendRequest {
        network: NET,
        account: &fixture.account,
        recipient: parse_address(P2WSH, NET).unwrap(),
        amount,
        fee,
        candidates: &candidates,
        tip_height: TIP,
        change_next: fixture.meta.change_next(),
        layout_seed: [seed; 32],
        typed_fee_override: typed,
        conflicts: &[],
    })
    .unwrap()
}

/// 100,000 sats: two inputs (80,000 + 50,000) and change.
fn two_input_plan(fixture: &Fixture) -> SendPlan {
    let plan = plan_with(
        fixture,
        SendAmount::Exact(Sats::new(100_000).unwrap()),
        two_sat_per_vb(),
        7,
        None,
    );
    assert_eq!(plan.inputs().len(), 2);
    assert!(plan.change().is_some());
    plan
}

fn draft_of(fixture: &Fixture, plan: &SendPlan, id: u8) -> ApprovalDraft {
    let facts = fixture.meta.send_facts(plan, TIP, &[]).unwrap();
    build_btc_request(ApprovalId([id; 16]), plan, &fixture.account, &facts).unwrap()
}

/// An `Approved` through the real store (issue → consume).
fn approve(fixture: &Fixture, plan: &SendPlan, id: u8) -> Approved {
    let mut store = ApprovalStore::new();
    let request = store
        .issue(draft_of(fixture, plan, id), NOW_MS, EXPIRES - 120_000)
        .unwrap();
    store
        .consume(request.id, request.digest, NOW_MS + 1)
        .unwrap()
}

/// A test-only `Approved` for exactly `plan` (bypasses the store for plans the policy blocks).
fn approved_for(plan: &SendPlan, account: &BtcAccountKey) -> Approved {
    Approved::for_test(
        ChainRef::Bitcoin {
            network: plan.network().id(),
            genesis: plan.network().genesis(),
        },
        AccountRef::Bitcoin(account.identity()),
        Signer::FromPayload,
        plan.kind(),
        SigningPayload::Btc(btc_payload(plan)),
    )
}

/// spec/08 §14.2 `approval_btc_digest`: every 1-bit change of the payload (and of chain, account
/// and kind) changes the digest; only §10 field keys appear; the store binds kind, origin,
/// signer, chain and payload; `sign_plan` refuses approvals of other plans.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one scenario per digest/store/signing binding"
)]
fn approval_btc_digest() {
    let fixture = fixture();
    let plan = two_input_plan(&fixture);
    let draft = draft_of(&fixture, &plan, 9);
    let base = approval_digest(&draft, EXPIRES).unwrap();
    let payload = btc_payload(&plan);
    assert_eq!(draft.payload, SigningPayload::Btc(payload.clone()));
    for byte in 0..payload.len() {
        for bit in 0..8 {
            let mut flipped = payload.clone();
            flipped[byte] ^= 1 << bit;
            let mut changed = draft.clone();
            changed.payload = SigningPayload::Btc(flipped);
            assert_ne!(
                approval_digest(&changed, EXPIRES).unwrap(),
                base,
                "byte {byte} bit {bit}"
            );
        }
    }
    let mut other = draft.clone();
    other.chain = ChainRef::Bitcoin {
        network: 1,
        genesis: BtcNetwork::Mainnet.genesis(),
    };
    assert_ne!(approval_digest(&other, EXPIRES).unwrap(), base);
    let mut pubkey = fixture.account.identity();
    pubkey[32] ^= 1;
    let mut other = draft.clone();
    other.account = AccountRef::Bitcoin(pubkey);
    assert_ne!(approval_digest(&other, EXPIRES).unwrap(), base);
    let mut other = draft.clone();
    other.kind = ApprovalKind::BtcFeeBump;
    assert_ne!(approval_digest(&other, EXPIRES).unwrap(), base);

    let allowed = [
        0x0001, 0x0002, 0x0003, 0x0601, 0x0602, 0x0603, 0x0604, 0x0605, 0x0606, 0x0607, 0x0608,
        0x0640,
    ];
    let keys: Vec<u16> = draft
        .display
        .fields
        .iter()
        .map(|field| field.key.0)
        .collect();
    assert_eq!(keys, allowed, "send fields in display order");
    for field in &draft.display.fields {
        assert_eq!(
            field.critical,
            !matches!(field.key, FieldKey::BTC_BALANCE | FieldKey::BTC_ADVANCED)
        );
        assert!(!field.volatile);
    }

    // The store's BTC draft rules.
    let mut store = ApprovalStore::new();
    let mut wrong = draft.clone();
    wrong.kind = ApprovalKind::BtcFeeBump;
    assert_eq!(
        store.issue(wrong, NOW_MS, 0),
        Err(ApprovalError::PayloadMismatch)
    );
    let mut wrong = draft.clone();
    wrong.signer = Signer::Evm(EvmKeySource::Derived(AccountIndex::new(0).unwrap()));
    assert_eq!(
        store.issue(wrong, NOW_MS, 0),
        Err(ApprovalError::PayloadMismatch)
    );
    let mut wrong = draft.clone();
    wrong.origin =
        ApprovalOrigin::Site(crate::policy::BrowserOrigin::parse("https://example.com").unwrap());
    assert_eq!(
        store.issue(wrong, NOW_MS, 0),
        Err(ApprovalError::PayloadMismatch)
    );
    let mut wrong = draft.clone();
    wrong.chain = ChainRef::Bitcoin {
        network: 2,
        genesis: BtcNetwork::Mainnet.genesis(),
    };
    assert_eq!(
        store.issue(wrong, NOW_MS, 0),
        Err(ApprovalError::PayloadMismatch)
    );
    let mut wrong = draft.clone();
    wrong.chain = ChainRef::Bitcoin {
        network: 1,
        genesis: BtcNetwork::Mainnet.genesis(),
    };
    assert_eq!(
        store.issue(wrong, NOW_MS, 0),
        Err(ApprovalError::PayloadMismatch)
    );
    let mut wrong = draft.clone();
    let mut truncated = payload.clone();
    truncated.pop();
    wrong.payload = SigningPayload::Btc(truncated);
    assert_eq!(
        store.issue(wrong, NOW_MS, 0),
        Err(ApprovalError::PayloadMismatch)
    );
    let mut wrong = draft.clone();
    wrong.simulation = crate::approval::SimulationBinding::None {
        reason: crate::approval::SimNoneReason::Skipped,
    };
    assert_eq!(
        store.issue(wrong, NOW_MS, 0),
        Err(ApprovalError::SimulationBindingMismatch)
    );

    // sign_plan refuses anything but this plan's approval.
    let other_plan = plan_with(
        &fixture,
        SendAmount::Exact(Sats::new(100_000).unwrap()),
        two_sat_per_vb(),
        8,
        None,
    );
    assert_ne!(btc_payload(&other_plan), btc_payload(&plan));
    let approved = approve(&fixture, &other_plan, 1);
    assert_eq!(
        sign_plan(&fixture.vault, approved, &plan, &fixture.account),
        Err(SignError::ApprovalMismatch)
    );
    let chain = ChainRef::Bitcoin {
        network: 2,
        genesis: NET.genesis(),
    };
    let account = AccountRef::Bitcoin(fixture.account.identity());
    let payload = SigningPayload::Btc(btc_payload(&plan));
    for approved in [
        Approved::for_test(
            chain,
            account,
            Signer::FromPayload,
            ApprovalKind::BtcFeeBump,
            payload.clone(),
        ),
        Approved::for_test(
            ChainRef::Bitcoin {
                network: 1,
                genesis: BtcNetwork::Mainnet.genesis(),
            },
            account,
            Signer::FromPayload,
            ApprovalKind::BtcSend,
            payload.clone(),
        ),
        Approved::for_test(
            chain,
            AccountRef::Bitcoin(pubkey),
            Signer::FromPayload,
            ApprovalKind::BtcSend,
            payload.clone(),
        ),
        Approved::for_test(
            chain,
            account,
            Signer::Evm(EvmKeySource::Derived(AccountIndex::new(0).unwrap())),
            ApprovalKind::BtcSend,
            payload.clone(),
        ),
        Approved::for_test(
            chain,
            account,
            Signer::FromPayload,
            ApprovalKind::EvmPersonalSign,
            SigningPayload::EvmPersonal(btc_payload(&plan)),
        ),
    ] {
        assert_eq!(
            sign_plan(&fixture.vault, approved, &plan, &fixture.account),
            Err(SignError::ApprovalMismatch)
        );
    }
    let signed = sign_plan(
        &fixture.vault,
        approve(&fixture, &plan, 2),
        &plan,
        &fixture.account,
    )
    .unwrap();
    assert_eq!(signed.approval_id, ApprovalId([2; 16]));
    assert!(verify_signed(&signed.raw, &plan, &fixture.account).is_ok());
}

/// spec/08 §3.1/§11.1: a key whose HASH160 is not the cached account's program stops signing.
#[test]
fn key_mismatch_stops_signing() {
    let mut fixture = fixture();
    // A cached node that is not the vault's testnet4 node (here: the mainnet node under the
    // same BIP84 account 0 identity): the lent keys do not match the plan's keys.
    let mainnet = BtcAccountKey::primary(fixture.vault.btc_account_xpub(BtcCoin::Mainnet).unwrap());
    fixture.account = mainnet;
    let plan = two_input_plan(&fixture);
    let approved = approved_for(&plan, &mainnet);
    assert_eq!(
        sign_plan(&fixture.vault, approved, &plan, &mainnet),
        Err(SignError::KeyMismatch { input: 0 })
    );
    // Signing a plan with another account than its own is refused before any key is lent.
    let real = BtcAccountKey::primary(fixture.vault.btc_account_xpub(BtcCoin::Test).unwrap());
    assert_eq!(
        sign_plan(&fixture.vault, approved_for(&plan, &real), &plan, &real),
        Err(SignError::ApprovalMismatch)
    );
}

/// spec/08 §5 / spec/09 BTC-N3: a recorded amount that differs from the plan, or a missing
/// record, stops before signing (a missing record with its own text: a refresh during the
/// approval dropped the input, review fix).
#[test]
fn amount_record_mismatch_aborts() {
    let fixture = fixture();
    let plan = two_input_plan(&fixture);
    let recorded = fixture.meta.recorded_amounts();
    assert_eq!(check_recorded_amounts(&plan, &recorded), Ok(()));
    let first = plan.inputs()[0];
    let mut changed = recorded.clone();
    for entry in &mut changed {
        if entry.0 == first.outpoint {
            entry.1 = Sats::new(entry.1.get() + 1).unwrap();
        }
    }
    assert_eq!(
        check_recorded_amounts(&plan, &changed),
        Err(SignError::AmountRecordMismatch)
    );
    let mut conflicting = recorded.clone();
    conflicting.push((first.outpoint, Sats::new(1).unwrap()));
    assert_eq!(
        check_recorded_amounts(&plan, &conflicting),
        Err(SignError::AmountRecordMismatch)
    );
    let missing: Vec<(OutPoint, Sats)> = recorded
        .iter()
        .copied()
        .filter(|(outpoint, _)| *outpoint != first.outpoint)
        .collect();
    assert_eq!(
        check_recorded_amounts(&plan, &missing),
        Err(SignError::InputNotRecorded)
    );
    assert_ne!(
        SignError::InputNotRecorded.to_string(),
        SignError::AmountRecordMismatch.to_string()
    );
    // A tampered plan amount (the approval would have to show it) is caught the same way.
    let mut tampered = plan.clone();
    tampered.inputs[0].value = Sats::new(first.value.get() + 1).unwrap();
    assert_eq!(
        check_recorded_amounts(&tampered, &recorded),
        Err(SignError::AmountRecordMismatch)
    );
}

const CURVE_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

fn negate_scalar(s: &[u8]) -> [u8; 32] {
    let mut out = [0_u8; 32];
    let mut borrow = 0_i16;
    for i in (0..32).rev() {
        let mut value = i16::from(CURVE_ORDER[i]) - i16::from(s[i]) - borrow;
        borrow = 0;
        if value < 0 {
            value += 256;
            borrow = 1;
        }
        out[i] = u8::try_from(value).unwrap();
    }
    out
}

fn reserialized(raw: &[u8], mutate: impl FnOnce(&mut Transaction)) -> Vec<u8> {
    let mut tx = parse_transaction(raw).unwrap();
    mutate(&mut tx);
    serialize(&tx, true)
}

/// spec/08 §14.2 `post_sign_tamper_each_field`: every §11.2 item changed by one byte (or one
/// field) is rejected.
#[test]
#[expect(clippy::too_many_lines, reason = "one block per spec/08 §11.2 item")]
fn post_sign_tamper_each_field() {
    let fixture = fixture();
    let account = &fixture.account;
    let plan = two_input_plan(&fixture);
    let signed = sign_plan(&fixture.vault, approve(&fixture, &plan, 3), &plan, account).unwrap();
    let raw = signed.raw.clone();
    let verified = verify_signed(&raw, &plan, account).unwrap();
    assert_eq!(verified.fee(), plan.fee());
    assert!(verified.vsize() <= u64::from(plan.planned_vsize()));
    let check = |bytes: &[u8]| verify_signed(bytes, &plan, account);

    // 1. Parse and identical re-serialization.
    assert_eq!(check(&raw[..raw.len() - 1]), Err(PostSignError::Parse));
    let mut trailing = raw.clone();
    trailing.push(0);
    assert_eq!(check(&trailing), Err(PostSignError::Parse));
    // 2. The unsigned transaction.
    for mutate in [
        (|tx: &mut Transaction| tx.version = 1) as fn(&mut Transaction),
        |tx| tx.lock_time += 1,
        |tx| tx.inputs[0].sequence = 0xFFFF_FFFE,
        |tx| tx.inputs[1].prevout.vout ^= 1,
        |tx| tx.outputs[0].value = Sats::new(tx.outputs[0].value.get() - 1).unwrap(),
        |tx| tx.outputs[1].script_pubkey[5] ^= 1,
        |tx| tx.inputs[0].script_sig = vec![0x00],
    ] {
        assert_eq!(
            check(&reserialized(&raw, mutate)),
            Err(PostSignError::UnsignedMismatch)
        );
    }
    // 3. Witness shape and strict signature rules.
    assert_eq!(
        check(&reserialized(&raw, |tx| tx.inputs[1].witness.push(vec![1]))),
        Err(PostSignError::WitnessShape { input: 1 })
    );
    assert_eq!(
        check(&reserialized(&raw, |tx| {
            tx.inputs[0].witness.pop();
        })),
        Err(PostSignError::WitnessShape { input: 0 })
    );
    assert_eq!(
        check(&reserialized(&raw, |tx| {
            let item = &mut tx.inputs[0].witness[0];
            let last = item.len() - 1;
            item[last] = 0x02;
        })),
        Err(PostSignError::Signature {
            input: 0,
            reason: WitnessSigError::SighashType
        })
    );
    assert!(matches!(
        check(&reserialized(&raw, |tx| tx.inputs[0].witness[0][0] ^= 1)),
        Err(PostSignError::Signature { input: 0, .. })
    ));
    assert!(matches!(
        check(&reserialized(&raw, |tx| tx.inputs[1].witness[0][10] ^= 1)),
        Err(PostSignError::Signature { input: 1, .. })
    ));
    let high_s = reserialized(&raw, |tx| {
        let item = &tx.inputs[0].witness[0];
        let signature = Signature::from_der(&item[..item.len() - 1]).unwrap();
        let mut compact = signature.serialize_compact();
        let negated = negate_scalar(&compact[32..]);
        compact[32..].copy_from_slice(&negated);
        let mut der = Signature::from_compact(&compact)
            .unwrap()
            .serialize_der()
            .to_vec();
        der.push(0x01);
        tx.inputs[0].witness[0] = der;
    });
    assert!(matches!(
        check(&high_s),
        Err(PostSignError::Signature {
            input: 0,
            reason: WitnessSigError::HighS | WitnessSigError::DerTooLong
        })
    ));
    // 3/4. The key item.
    assert!(matches!(
        check(&reserialized(&raw, |tx| tx.inputs[0].witness[1][0] = 0x04)),
        Err(PostSignError::KeyMismatch { input: 0 })
    ));
    assert!(matches!(
        check(&reserialized(&raw, |tx| {
            tx.inputs[0].witness[1].pop();
        })),
        Err(PostSignError::Signature {
            input: 0,
            reason: WitnessSigError::PublicKey
        })
    ));
    assert_eq!(
        check(&reserialized(&raw, |tx| {
            let key = tx.inputs[1].witness[1].clone();
            tx.inputs[0].witness[1] = key;
        })),
        Err(PostSignError::KeyMismatch { input: 0 })
    );
    // 5. A valid signature of the other input.
    assert_eq!(
        check(&reserialized(&raw, |tx| {
            let signature = tx.inputs[1].witness[0].clone();
            tx.inputs[0].witness[0] = signature;
        })),
        Err(PostSignError::Signature {
            input: 0,
            reason: WitnessSigError::VerifyFailed
        })
    );
    // 5. The verified amount is committed: a different plan amount fails the signature.
    let mut tampered = plan.clone();
    tampered.inputs[0].value = Sats::new(tampered.inputs[0].value.get() + 1).unwrap();
    assert_eq!(
        verify_signed(&raw, &tampered, account),
        Err(PostSignError::Signature {
            input: 0,
            reason: WitnessSigError::VerifyFailed
        })
    );
    // 6. Change re-derived from the account node.
    let mut tampered = plan.clone();
    let change = tampered.change.as_mut().unwrap();
    change.index += 1;
    assert_eq!(
        verify_signed(&raw, &tampered, account),
        Err(PostSignError::Outputs)
    );
    let mut tampered = plan.clone();
    tampered.change = None;
    assert_eq!(
        verify_signed(&raw, &tampered, account),
        Err(PostSignError::Outputs)
    );
    // 7. Fee.
    let mut tampered = plan.clone();
    tampered.fee = Sats::new(plan.fee().get() + 1).unwrap();
    assert_eq!(
        verify_signed(&raw, &tampered, account),
        Err(PostSignError::FeeMismatch)
    );
    // 8. Planned vsize below the real size.
    let mut tampered = plan.clone();
    tampered.planned_vsize = u32::try_from(verified.vsize()).unwrap() - 1;
    assert_eq!(
        verify_signed(&raw, &tampered, account),
        Err(PostSignError::Vsize)
    );
    // Another account than the plan's: refused before any check.
    let mainnet = BtcAccountKey::primary(fixture.vault.btc_account_xpub(BtcCoin::Mainnet).unwrap());
    assert_eq!(
        verify_signed(&raw, &plan, &mainnet),
        Err(PostSignError::PlanInconsistent)
    );
    // A witness key that is not the account key of the input's path.
    let mut swapped = parse_transaction(&raw).unwrap();
    let other_key = fixture
        .vault
        .btc_public_key(BtcCoin::Test, BtcChain::Receive, 5)
        .unwrap();
    swapped.inputs[0].witness[1] = other_key.to_vec();
    assert_eq!(
        verify_signed(&serialize(&swapped, true), &plan, account),
        Err(PostSignError::KeyMismatch { input: 0 })
    );
}

/// spec/08 §11.2-7: fee caps and dust after signing (plans the policy blocks, signed through a
/// test approval to reach the verifier).
#[test]
fn post_sign_fee_cap_and_dust() {
    let fixture = fixture();
    let account = &fixture.account;
    let over_cap = FeeChoice {
        rate: FeeRate::from_sat_per_kvb(501_000),
        source: FeeSource::Manual,
    };
    let amount = SendAmount::Exact(Sats::new(20_000).unwrap());
    let plan = plan_with(&fixture, amount, over_cap, 4, None);
    assert!(plan.needs_typed_override());
    let signed = sign_plan(&fixture.vault, approved_for(&plan, account), &plan, account).unwrap();
    assert_eq!(
        verify_signed(&signed.raw, &plan, account),
        Err(PostSignError::FeeCap)
    );
    let typed = plan_with(&fixture, amount, over_cap, 4, Some(plan.fee()));
    assert!(typed.fee_override_typed() && !typed.needs_typed_override());
    let signed = sign_plan(
        &fixture.vault,
        approve(&fixture, &typed, 5),
        &typed,
        account,
    )
    .unwrap();
    assert!(verify_signed(&signed.raw, &typed, account).is_ok());

    let mut dusty = two_input_plan(&fixture);
    let recipient = usize::try_from(dusty.recipient_vout).unwrap();
    let change = dusty.change.unwrap();
    let moved = dusty.amount.get() - 100;
    dusty.amount = Sats::new(100).unwrap();
    dusty.tx.outputs[recipient].value = dusty.amount;
    let new_change = Sats::new(change.value.get() + moved).unwrap();
    dusty.tx.outputs[usize::try_from(change.vout).unwrap()].value = new_change;
    dusty.change = Some(super::select::PlanChange {
        value: new_change,
        ..change
    });
    let signed = sign_plan(
        &fixture.vault,
        approved_for(&dusty, account),
        &dusty,
        account,
    )
    .unwrap();
    assert_eq!(
        verify_signed(&signed.raw, &dusty, account),
        Err(PostSignError::Dust)
    );
}

/// spec/08 §11.1 end to end on testnet4 (core part): verified fake UTXOs → plan → draft →
/// issue/consume → in-flight and amount checks → `sign_plan` → `verify_signed` → journal record
/// round trip → `testmempoolaccept` → Broadcasting (`change_next`) → Submitted (sent script) →
/// D20 → Confirmed (own change) → finished activity row.
#[test]
#[expect(clippy::too_many_lines, reason = "the spec/08 §11.1 order end to end")]
fn end_to_end_testnet4_core() {
    let mut fixture = fixture();
    let account = fixture.account;
    let plan = two_input_plan(&fixture);
    assert_eq!(plan.network(), NET);
    assert_eq!(plan.lock_time(), TIP);
    let facts = fixture.meta.send_facts(&plan, TIP, &[]).unwrap();
    assert_eq!(
        facts,
        BtcSendFacts {
            verified_balance: Sats::new(160_000).unwrap(),
            min_confirmations: Some(11),
            first_time_recipient: true,
            own_recipient: None,
        }
    );
    let draft = build_btc_request(ApprovalId([0x42; 16]), &plan, &account, &facts).unwrap();
    assert_eq!(
        draft.display.title,
        "[Bitcoin testnet4] 보내기: 0.00100000 BTC"
    );
    assert_eq!(draft.display.risk, crate::approval::RiskLevel::Caution);
    let mut store = ApprovalStore::new();
    let request = store.issue(draft, NOW_MS, NOW_UNIX * 1_000).unwrap();
    let approved = store
        .consume(request.id, request.digest, NOW_MS + 10)
        .unwrap();
    let digest = approved.digest();

    let mut journal = JournalPlain::default();
    let records = BtcEntries::from_plain(&journal).records();
    assert_eq!(check_plan_allowed(&records, &plan), Ok(()));
    let mut recorded = fixture.meta.recorded_amounts();
    recorded.extend(recorded_amounts(&records, NET));
    assert_eq!(check_recorded_amounts(&plan, &recorded), Ok(()));
    let signed = sign_plan(&fixture.vault, approved, &plan, &account).unwrap();
    assert_eq!(signed.approval_digest, digest);
    let verified = verify_signed(&signed.raw, &plan, &account).unwrap();
    assert_eq!(verified.txid(), plan.txid());
    assert_eq!(verified.raw_hex(), crate::hex::encode(&signed.raw));
    let rate = super::fee::rate_kvb(verified.fee(), verified.vsize()).unwrap();
    assert!((2_000..2_050).contains(&rate), "{rate}");
    let maxfeerate = verified.maxfeerate().unwrap();
    assert_eq!(
        maxfeerate,
        if rate == 2_000 {
            "0.00003000"
        } else {
            "0.00004000"
        }
    );

    assert!(
        make_room(&mut journal, NET, TIP, NOW_UNIX, 1)
            .unwrap()
            .is_empty()
    );
    let record = BtcRecord::new_signed(&plan, &signed, &verified, NOW_UNIX).unwrap();
    push_record(&mut journal, &record).unwrap();
    let bytes = journal.encode().unwrap();
    let mut journal = JournalPlain::decode(&bytes).unwrap();
    let records = BtcEntries::from_plain(&journal).records();
    assert_eq!(records, vec![record.clone()]);
    assert_eq!(
        BtcRecord::decode(&record.encode().unwrap()).unwrap(),
        record
    );
    assert_eq!(record.title(), "[Bitcoin testnet4] 보내기: 0.00100000 BTC");

    // testmempoolaccept → Broadcasting.
    let local = verified.local();
    let answer = MempoolAccept {
        txid: local.txid,
        wtxid: local.wtxid,
        allowed: true,
        vsize: Some(local.vsize),
        fee_base: Some(local.fee),
        reject_reason: None,
    };
    assert_eq!(
        check_mempool_accept(&answer, &local),
        PrecheckOutcome::Accepted
    );
    set_state(
        &mut journal,
        NET,
        &local.txid,
        BtcTxState::Broadcasting,
        NOW_UNIX + 1,
    )
    .unwrap();
    assert!(
        fixture
            .meta
            .on_broadcasting(plan.change().map(|change| change.index))
            .unwrap()
    );
    assert_eq!(fixture.meta.change_next(), 2);
    // sendrawtransaction → Submitted.
    assert_eq!(
        broadcast_outcome(&SendRawResult::Txid(local.txid), &local.txid),
        BroadcastOutcome::Submitted
    );
    set_state(
        &mut journal,
        NET,
        &local.txid,
        BtcTxState::Submitted,
        NOW_UNIX + 2,
    )
    .unwrap();
    assert!(fixture.meta.record_sent_script(&plan.recipient_script()));
    assert!(!fixture.meta.is_first_time(&plan.recipient_script()));
    // D20: in flight.
    let records = BtcEntries::from_plain(&journal).records();
    assert_eq!(
        check_can_send(&records, NET),
        Err(super::select::PlanError::InFlight)
    );
    // Two inputs and the (unconfirmed) change output of the in-flight record.
    let in_flight = in_flight_outpoints(&records, NET);
    assert_eq!(in_flight.len(), 3);
    assert!(in_flight.contains(&records[0].change_outpoint().unwrap()));
    let spendable = fixture.meta.spendable(TIP, &in_flight);
    assert_eq!(spendable.len(), 1);
    // Confirmed at TIP + 1 → own change verified.
    let change = apply_observation(
        &mut journal,
        NET,
        &local.txid,
        TrackObservation::Confirmed { height: TIP + 1 },
        TIP + 1,
        NOW_UNIX + 600,
    )
    .unwrap();
    assert_eq!(change.changed, vec![(local.txid, BtcTxState::Confirmed)]);
    let records = BtcEntries::from_plain(&journal).records();
    let confirmed = &records[0];
    let own = confirmed.own_change_utxo(fixture.meta.account()).unwrap();
    assert_eq!(own.value, plan.change().unwrap().value);
    assert!(fixture.meta.insert_own(own).unwrap());
    // One confirmation is final: D20 is released, the inputs and the change are no longer in
    // flight (the change is spendable), and the record is finished at the same tip. A tip below
    // the confirmation height (a lagging or garbage tip) does not finish it.
    assert_eq!(check_can_send(&records, NET), Ok(()));
    assert!(in_flight_outpoints(&records, NET).is_empty());
    assert!(finished_rows(&journal, NET, TIP, NOW_UNIX + 700, 9).is_empty());
    let rows = finished_rows(&journal, NET, TIP + 1, NOW_UNIX + 700, 9);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].status, "succeeded");
    assert_eq!(rows[0].tx_id, local.txid.to_display_hex());
    assert_eq!(rows[0].amount, "100000");
    assert_eq!(rows[0].counterparty, P2WSH);
    assert_eq!(rows[0].title, "[Bitcoin testnet4] 보내기: 0.00100000 BTC");
    // Meta survives its JSON round trip.
    let json = fixture.meta.to_json();
    assert_eq!(BtcMeta::from_json(&json).unwrap(), fixture.meta);
}

/// spec/08 §3.5/§11.2-6 fixed-address mode (the default of BIP84 account 0): change goes back to
/// the receive address `(Receive, 0)` while inputs on other addresses of the account (receive 1,
/// change 0, found by discovery) are still spent; post-sign verification accepts exactly that
/// change script and refuses any other address of the account (and HD mode refuses `/0/0`).
#[test]
fn fixed_address_change_is_the_receive_address() {
    let fixture = fixture_fixed();
    let account = &fixture.account;
    assert!(account.fixed_address());
    let receive = fixture.meta.expected_script(BtcChain::Receive, 0).unwrap();
    let plan = two_input_plan(&fixture);
    let change = plan.change().unwrap();
    assert_eq!(change.index, 0);
    let vout = usize::try_from(change.vout).unwrap();
    assert_eq!(plan.tx().outputs[vout].script_pubkey, receive);
    // 80,000 on change 0 and 50,000 on receive 0 (both discovered, both spendable).
    assert!(
        plan.inputs()
            .iter()
            .any(|input| (input.chain, input.index) == (BtcChain::Change, 0))
    );
    let signed = sign_plan(&fixture.vault, approve(&fixture, &plan, 3), &plan, account).unwrap();
    assert!(verify_signed(&signed.raw, &plan, account).is_ok());
    // The approval shows the change as returning to the receive path.
    let draft = draft_of(&fixture, &plan, 3);
    let change_text = draft
        .display
        .fields
        .iter()
        .find(|field| field.key == FieldKey::BTC_CHANGE)
        .unwrap();
    assert!(
        change_text.value.contains("m/84'/1'/0'/0/0"),
        "{}",
        change_text.value
    );
    // A plan whose change pays another address of the account (signed for that plan) fails
    // the post-sign output check in fixed-address mode.
    for (chain, index) in [
        (BtcChain::Change, 0),
        (BtcChain::Change, 1),
        (BtcChain::Receive, 1),
    ] {
        let mut tampered = plan.clone();
        tampered.tx.outputs[vout].script_pubkey =
            fixture.meta.expected_script(chain, index).unwrap();
        let signed = sign_plan(
            &fixture.vault,
            approved_for(&tampered, account),
            &tampered,
            account,
        )
        .unwrap();
        assert_eq!(
            verify_signed(&signed.raw, &tampered, account),
            Err(PostSignError::Outputs),
            "{chain:?}/{index}"
        );
    }
    // The same node in HD mode: change on the change chain; a change paying `/0/0` is refused.
    let hd = fixture_mode(false);
    let hd_plan = two_input_plan(&hd);
    let hd_change = hd_plan.change().unwrap();
    let hd_vout = usize::try_from(hd_change.vout).unwrap();
    assert_eq!(
        hd_plan.tx().outputs[hd_vout].script_pubkey,
        hd.meta
            .expected_script(BtcChain::Change, hd_change.index)
            .unwrap()
    );
    let mut tampered = hd_plan.clone();
    tampered.tx.outputs[hd_vout].script_pubkey = receive;
    let signed = sign_plan(
        &hd.vault,
        approved_for(&tampered, &hd.account),
        &tampered,
        &hd.account,
    )
    .unwrap();
    assert_eq!(
        verify_signed(&signed.raw, &tampered, &hd.account),
        Err(PostSignError::Outputs)
    );
}

/// `(type, mainnet address, testnet4 address)`.
type VectorRow = (ScriptType, &'static str, &'static str);

/// Independent vectors (pure-Python secp256k1/BIP32/bech32 over `abandon`×11 `about`, the script
/// cross-checked against the published BIP84/BIP86 first addresses): the BTC addresses of the
/// EVM key `m/44'/60'/0'/0/i` for each address type (spec/08 §3.5 "EVM 계정과 같은 키").
const EVM_SHARED_VECTORS: [(u32, &str, [VectorRow; 4]); 2] = [
    (
        0,
        "0237b0bb7a8288d38ed49a524b5dc98cff3eb5ca824c9f9dc0dfdb3d9cd600f299",
        [
            (
                ScriptType::P2pkh,
                "17D4gErm7cqDznM4EstEfnP6y91MWADXm8",
                "mmj1yHwjveGUmtpfxSrcVhbRq8c4RtLA7N",
            ),
            (
                ScriptType::P2shP2wpkh,
                "34y4LBtWcT2h1o9BH9KGpJz5tXsYXwxMUs",
                "2MvXGPvpYDuY3DamixGw9SFyM6t5iFE1NbY",
            ),
            (
                ScriptType::P2wpkh,
                "bc1qgsvdpdxec8hsu57lhxg5xem7refr233z2ttx7e",
                "tb1qgsvdpdxec8hsu57lhxg5xem7refr233zqds492",
            ),
            (
                ScriptType::P2tr,
                "bc1p08q6wdgnqe0gwpp4ygs0y8lwgxlpv2l4uc0zq5qjnagwtg92fussqdhm72",
                "tb1p08q6wdgnqe0gwpp4ygs0y8lwgxlpv2l4uc0zq5qjnagwtg92fussh9p5y9",
            ),
        ],
    ),
    (
        1,
        "039fd0991d0222b4e1339c1a1a5b5f6d9f6a96672a3247b638ee6156d9ea877a2f",
        [
            (
                ScriptType::P2pkh,
                "1HFtisb5rwGvD3kGuUbV4a4d9mrHDM4BwS",
                "mwmr1vg4fxiAzADtd3ZrtVGx1mSz3jpY82",
            ),
            (
                ScriptType::P2shP2wpkh,
                "37jwSpUyMLBrgH8Q6sCdMDQGTqDUDmsuSB",
                "2MyJ9WZQzxnhCt4kwmzpVyAPXgBRdw3inGz",
            ),
            (
                ScriptType::P2wpkh,
                "bc1qkffs9e9jzdlnmpk025zgklzd0kpcapzaryywkr",
                "tb1qkffs9e9jzdlnmpk025zgklzd0kpcapzafzlads",
            ),
            (
                ScriptType::P2tr,
                "bc1p255jm74yvz5z0hk2jk4mmj3cxy5l02tr7dvweqq55u8y5w036evqsq53hf",
                "tb1p255jm74yvz5z0hk2jk4mmj3cxy5l02tr7dvweqq55u8y5w036evq8gz7dx",
            ),
        ],
    ),
];

#[test]
fn evm_shared_addresses_match_vectors() {
    let vault = about_vault();
    for (evm_index, pubkey, rows) in EVM_SHARED_VECTORS {
        let derived = vault
            .evm_public_key(AccountIndex::new(evm_index).unwrap())
            .unwrap();
        assert_eq!(crate::hex::encode(&derived), pubkey);
        for (script_type, mainnet, testnet4) in rows {
            let key = BtcAccountKey::evm_shared(evm_index, script_type, derived).unwrap();
            assert!(key.is_single() && key.fixed_address() && !key.is_imported());
            for (net, expected) in [
                (BtcNetwork::Mainnet, mainnet),
                (BtcNetwork::Testnet4, testnet4),
            ] {
                assert_eq!(
                    key.address(net, BtcChain::Receive, 0).unwrap().as_str(),
                    expected,
                    "{script_type:?} {net:?}"
                );
            }
            // One address: nothing else derives; the path is the EVM path on both networks.
            assert!(key.address(NET, BtcChain::Receive, 1).is_err());
            assert!(key.address(NET, BtcChain::Change, 0).is_err());
            assert_eq!(
                key.path_text(NET, BtcChain::Receive, 0),
                format!("m/44'/60'/0'/0/{evm_index}")
            );
        }
    }
    // Index 1000 is not an EVM account.
    let any = EVM_SHARED_VECTORS[0].1;
    let point = crate::hex::decode_array::<33>(any).unwrap();
    assert!(BtcAccountKey::evm_shared(1_000, ScriptType::P2wpkh, point).is_err());
    assert!(BtcAccountKey::evm_shared(0, ScriptType::P2wpkh, [5; 33]).is_err());
}

/// One verified output of `value` on `meta`'s `(Receive, 0)` (a fake previous transaction).
fn fund_receive0(meta: &mut BtcMeta, values: &[(u64, u8)]) {
    let script = meta.expected_script(BtcChain::Receive, 0).unwrap();
    let mut listed = Vec::new();
    let mut newly = Vec::new();
    for (value, salt) in values {
        let (raw, prev_txid) = fake_prev(&script, *value, *salt);
        let item = ListedUtxo {
            outpoint: OutPoint {
                txid: prev_txid,
                vout: 0,
            },
            chain: BtcChain::Receive,
            index: 0,
            height: TIP - 3,
        };
        let prev = verify_prev_output(&raw, &prev_txid, 0, &script).unwrap();
        listed.push(item);
        newly.push(VerifiedUtxo::from_prev(&prev, &item));
    }
    let report = meta.apply_refresh(&listed, &newly, &[], &[]);
    assert_eq!(report.inserted as usize, values.len());
}

/// spec/08 §3.5: an account on the EVM key of account 0, every address type, end to end on
/// testnet4 with the real vault: verified outputs on its one address → plan (change back to the
/// same address) → approval → `sign_plan` (the vault lends the EVM key) → `verify_signed` →
/// journal record round trip; a cached key that is not the vault's EVM key is refused.
#[test]
fn evm_shared_send_end_to_end_every_type() {
    for (offset, script_type) in ScriptType::CHOICES.into_iter().enumerate() {
        let vault = about_vault();
        let pubkey = vault.evm_public_key(AccountIndex::ZERO).unwrap();
        let account = BtcAccountKey::evm_shared(0, script_type, pubkey).unwrap();
        let mut meta = BtcMeta::with_key(NET, account);
        assert!(meta.discovery_done() && meta.receive_next() == 1 && meta.change_next() == 0);
        let script = meta.expected_script(BtcChain::Receive, 0).unwrap();
        let salt = 0xb0 + u8::try_from(offset).unwrap() * 4;
        fund_receive0(&mut meta, &[(80_000, salt), (50_000, salt + 1)]);
        let fixture = Fixture {
            vault,
            account,
            meta,
        };
        let plan = two_input_plan(&fixture);
        let change = plan.change().unwrap();
        let vout = usize::try_from(change.vout).unwrap();
        assert_eq!(change.index, 0);
        assert_eq!(
            plan.tx().outputs[vout].script_pubkey,
            script,
            "{script_type:?}"
        );
        let signed =
            sign_plan(&fixture.vault, approve(&fixture, &plan, 6), &plan, &account).unwrap();
        let verified = verify_signed(&signed.raw, &plan, &account).unwrap();
        let record = BtcRecord::new_signed(&plan, &signed, &verified, NOW_UNIX).unwrap();
        assert_eq!(
            record.account,
            super::account::BtcAccountId::EvmShared {
                evm_index: 0,
                script_type
            }
        );
        let decoded = BtcRecord::decode(&record.encode().unwrap()).unwrap();
        assert_eq!(decoded, record);
        // Change to the fixed address never moves a change-chain index.
        assert_eq!(decoded.hd_change_index(&account), None);
        // A cached key that is not the vault's EVM key 0 (here EVM key 1 under index 0): the
        // lent key does not match and nothing is signed.
        let wrong = vault_key(&fixture.vault, 1);
        let other = BtcAccountKey::evm_shared(0, script_type, wrong).unwrap();
        let mut other_meta = BtcMeta::with_key(NET, other);
        fund_receive0(&mut other_meta, &[(90_000, salt + 2)]);
        let other_fixture = Fixture {
            vault: about_vault(),
            account: other,
            meta: other_meta,
        };
        let other_plan = plan_with(
            &other_fixture,
            SendAmount::Exact(Sats::new(20_000).unwrap()),
            two_sat_per_vb(),
            2,
            None,
        );
        assert_eq!(
            sign_plan(
                &other_fixture.vault,
                approved_for(&other_plan, &other),
                &other_plan,
                &other
            ),
            Err(SignError::KeyMismatch { input: 0 })
        );
    }
}

fn vault_key(vault: &Vault, evm_index: u32) -> [u8; 33] {
    vault
        .evm_public_key(AccountIndex::new(evm_index).unwrap())
        .unwrap()
}

// ----- YubiKey single-address accounts (spec/10 §3.3, §6.3) -------------------------------------

/// The `abandon`×11 `about` seed for the card emulator's enrolment.
fn about_seed() -> [u8; 64] {
    *crate::bip39::Mnemonic::parse(super::tests::ABOUT)
        .unwrap()
        .to_seed(&crate::password::Bip39Passphrase::empty())
        .unwrap()
        .expose()
}

/// A card (emulator, `serial`) with SIG = Bitcoin `script_type` address 3 of testnet4 and
/// AUT = EVM key 0 shared as a `script_type` address; its record added to the `about` vault.
fn card_vault(
    serial: u32,
    script_type: ScriptType,
) -> (
    crate::yubikey::mock::MockCard,
    Vault,
    crate::yubikey::record::HwKeyRecord,
) {
    use crate::yubikey::apdu::ApduMode;
    use crate::yubikey::enrol::{EnrolAuth, enrol_card};
    use crate::yubikey::mock::{MockCard, ToyCipher};
    use crate::yubikey::plan::{BtcUse, CardSlot, KeyRole, PgpKey, PlannedSlot};
    let mut card = MockCard::new(serial);
    let plan = [
        PlannedSlot::recommended(
            CardSlot::OpenPgp(PgpKey::Sig),
            KeyRole::Btc {
                network: NET,
                script: script_type,
                index: 3,
            },
        ),
        PlannedSlot::recommended(
            CardSlot::OpenPgp(PgpKey::Aut),
            KeyRole::Evm {
                index: AccountIndex::ZERO,
                btc: Some(BtcUse {
                    network: NET,
                    script: script_type,
                }),
            },
        ),
    ];
    let auth = EnrolAuth {
        admin_pin: b"12345678",
        management_key: &crate::yubikey::piv::DEFAULT_MANAGEMENT_KEY,
        piv_pin: b"",
        cipher: Some(&ToyCipher),
        challenge: [0; 16],
        overwrite: false,
    };
    let record = enrol_card(&mut card, ApduMode::Short, &about_seed(), &plan, &[], &auth)
        .unwrap()
        .record;
    let mut vault = about_vault();
    vault.add_hardware_key(record.clone(), NOW_UNIX).unwrap();
    (card, vault, record)
}

/// The card key of a `YubiKey` account (slot routing through the tag-5 slot map).
fn card_key_of(
    record: &crate::yubikey::record::HwKeyRecord,
    account: &BtcAccountKey,
) -> crate::yubikey::sign::CardKey {
    let BtcAccountKey::Hardware {
        key,
        script_type,
        pubkey,
    } = *account
    else {
        unreachable!("a YubiKey account");
    };
    let role = key.role(NET, script_type).unwrap();
    let holder =
        crate::yubikey::plan::slot_on_card(core::slice::from_ref(record), role, record.serial)
            .unwrap();
    crate::yubikey::sign::CardKey {
        serial: record.serial,
        slot: holder.slot,
        public: crate::yubikey::record::HwPublicKey::Secp256k1(pubkey),
    }
}

/// The sighash input `position` of `tx` signs for a single-key account of `script_type`.
fn input_sighash(
    tx: &Transaction,
    position: usize,
    script_type: ScriptType,
    pubkey: &[u8; 33],
    value: Sats,
) -> [u8; 32] {
    let hash = super::address::hash160(pubkey);
    match script_type {
        ScriptType::P2pkh => super::sighash::legacy_sighash(
            tx,
            position,
            &super::address::script_pubkey(&super::address::ScriptKind::P2pkh(hash)),
            1,
        )
        .unwrap(),
        _ => super::sighash::bip143_sighash_p2wpkh(tx, position, &hash, value).unwrap(),
    }
}

/// spec/10 §3.3, §6.3: `YubiKey` single-address accounts of every card address type (a Bitcoin
/// address key and an EVM key shared as one address) spend two inputs on the card emulator with
/// high-s **and** high-R signatures: the public key comes from the tag-5 slot map (equal to the
/// standard derivation), change goes back to the one address, the vault refuses to sign, the
/// card path signs one input per touch without any write command, the relaxed card check accepts
/// the high-R items the strict software check rejects, the card fee estimate (72 + 1) covers the
/// actual size, and the journal record and meta round trip.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one end-to-end scenario per account kind"
)]
fn yubikey_single_address_send_every_type() {
    use super::account::{BtcAccountId, HwBtcKey};
    use super::sign::{
        CardSignError, check_card_signature, check_p2pkh_signature, check_witness_signature,
        sign_plan_card,
    };
    use crate::yubikey::apdu::ApduMode;
    let ctx = secp256k1::Secp256k1::verification_only();
    let mut salt = 0xc0_u8;
    for (serial, script_type) in [
        (31_u32, ScriptType::P2wpkh),
        (32, ScriptType::P2shP2wpkh),
        (33, ScriptType::P2pkh),
    ] {
        for hw_key in [HwBtcKey::Address(3), HwBtcKey::Evm(0)] {
            let (mut card, vault, record) = card_vault(serial, script_type);
            let account = vault
                .hardware_btc_account(NET, script_type, hw_key)
                .unwrap();
            // The slot map's key is the standard one (address key) or the EVM key.
            let BtcAccountKey::Hardware { pubkey, .. } = account else {
                unreachable!("a YubiKey account");
            };
            let standard = match hw_key {
                HwBtcKey::Address(index) => vault
                    .btc_public_key(
                        NET.account_node(script_type.purpose(), 0).unwrap(),
                        BtcChain::Receive,
                        index,
                    )
                    .unwrap(),
                HwBtcKey::Evm(index) => vault_key(&vault, index),
            };
            assert_eq!(pubkey, standard, "{script_type:?} {hw_key:?}");
            assert!(account.is_single() && account.fixed_address() && account.is_hardware());
            assert!(!account.is_imported() && !account.is_evm_shared());
            assert!(
                account
                    .path_text(NET, BtcChain::Receive, 0)
                    .ends_with("(YubiKey)")
            );
            assert_eq!(account.input_weight(), script_type.card_input_weight());
            // The card estimate is 2 signature bytes above the software one (72 + 1 vs 70 + 1).
            let software = script_type.input_weight(true);
            let extra = if script_type == ScriptType::P2pkh {
                8
            } else {
                2
            };
            assert_eq!(account.input_weight(), software + extra);
            let mut meta = BtcMeta::with_key(NET, account);
            let script = meta.expected_script(BtcChain::Receive, 0).unwrap();
            fund_receive0(&mut meta, &[(80_000, salt), (50_000, salt + 1)]);
            salt += 2;
            let fixture = Fixture {
                vault,
                account,
                meta,
            };
            let plan = two_input_plan(&fixture);
            let change = plan.change().unwrap();
            assert_eq!(
                plan.tx().outputs[usize::try_from(change.vout).unwrap()].script_pubkey,
                script
            );
            // The vault has no key for it.
            assert_eq!(
                sign_plan(&fixture.vault, approve(&fixture, &plan, 9), &plan, &account),
                Err(SignError::Vault(crate::error::VaultError::RecordNotFound))
            );
            // On the card: high-s and high-R signatures, one touch per input, no writes.
            card.high_s = true;
            card.high_r = true;
            card.log.clear();
            let touches = card.touches;
            let key = card_key_of(&record, &account);
            let signed = {
                let mut signer = |sighash: [u8; 32]| {
                    crate::yubikey::sign::sign_btc(
                        &ctx,
                        &mut card,
                        ApduMode::Short,
                        &key,
                        b"123456",
                        sighash,
                    )
                };
                sign_plan_card(approve(&fixture, &plan, 10), &plan, &account, &mut signer).unwrap()
            };
            assert!(!card.saw_write());
            assert_eq!(card.touches - touches, 2);
            let verified = verify_signed(&signed.raw, &plan, &account).unwrap();
            assert!(verified.vsize() <= u64::from(plan.planned_vsize()));
            // Every item is high-R (71-byte DER): the strict software rule refuses it, the
            // relaxed card rule accepts it.
            let parsed = parse_transaction(&signed.raw).unwrap();
            for (position, (input, planned)) in parsed.inputs.iter().zip(plan.inputs()).enumerate()
            {
                let sig_item = if script_type == ScriptType::P2pkh {
                    super::script::split_p2pkh_script_sig(&input.script_sig)
                        .unwrap()
                        .0
                        .to_vec()
                } else {
                    input.witness[0].clone()
                };
                assert!(
                    (71..=72).contains(&sig_item.len()),
                    "{script_type:?} input {position}"
                );
                let sighash = input_sighash(&parsed, position, script_type, &pubkey, planned.value);
                let strict = if script_type == ScriptType::P2pkh {
                    check_p2pkh_signature(&sig_item, &pubkey, &sighash)
                } else {
                    check_witness_signature(&sig_item, &pubkey, &sighash)
                };
                assert!(matches!(
                    strict,
                    Err(WitnessSigError::DerTooLong | WitnessSigError::HighR)
                ));
                check_card_signature(&sig_item, &pubkey, &sighash).unwrap();
            }
            // The journal record and the meta object round trip with the YubiKey identity.
            let record_btc = BtcRecord::new_signed(&plan, &signed, &verified, NOW_UNIX).unwrap();
            assert_eq!(
                record_btc.account,
                BtcAccountId::Hardware {
                    key: hw_key,
                    script_type
                }
            );
            assert_eq!(
                BtcRecord::decode(&record_btc.encode().unwrap()).unwrap(),
                record_btc
            );
            assert_eq!(record_btc.hd_change_index(&account), None);
            let meta_json = fixture.meta.to_json();
            assert_eq!(BtcMeta::from_json(&meta_json).unwrap(), fixture.meta);
            let accounts = super::meta::BtcAccounts {
                selected: Some(account.id()),
                accounts: vec![fixture.meta.clone()],
            };
            assert_eq!(
                super::meta::BtcAccounts::from_json(Some(&accounts.to_json())).unwrap(),
                accounts
            );
            // The payload's account block binds the YubiKey source (4 address key, 5 EVM key).
            let payload = btc_payload(&plan);
            assert_eq!(payload[payload.len() - 18], hw_key.source_code());
            // A software account through the card path: refused.
            if hw_key == HwBtcKey::Evm(0) {
                let software = BtcAccountKey::evm_shared(0, script_type, pubkey).unwrap();
                let mut never = |_: [u8; 32]| -> Result<Vec<u8>, crate::yubikey::CardError> {
                    unreachable!("not asked")
                };
                assert_eq!(
                    sign_plan_card(approved_for(&plan, &software), &plan, &software, &mut never),
                    Err(CardSignError::Sign(SignError::ApprovalMismatch))
                );
            }
        }
    }
}

/// spec/10 §6.3 refusals: a touch not given, another card, a card answer that does not verify
/// and an approval of another plan stop the card path with nothing signed; Taproot cannot be a
/// `YubiKey` account and is refused by the card path if forged.
#[test]
#[expect(clippy::too_many_lines, reason = "one scenario per refusal")]
fn yubikey_card_signing_refusals() {
    use super::account::{AccountKeyError, HwBtcKey};
    use super::sign::{CardSignError, sign_plan_card};
    use crate::yubikey::CardError;
    use crate::yubikey::apdu::ApduMode;
    use crate::yubikey::mock::MockCard;
    let ctx = secp256k1::Secp256k1::verification_only();
    let (mut card, vault, record) = card_vault(41, ScriptType::P2wpkh);
    let account = vault
        .hardware_btc_account(NET, ScriptType::P2wpkh, HwBtcKey::Address(3))
        .unwrap();
    let mut meta = BtcMeta::with_key(NET, account);
    fund_receive0(&mut meta, &[(80_000, 0xd1), (50_000, 0xd2)]);
    let fixture = Fixture {
        vault,
        account,
        meta,
    };
    let plan = two_input_plan(&fixture);
    let key = card_key_of(&record, &account);
    // No touch.
    card.refuse_touch = true;
    let result = {
        let mut signer = |sighash: [u8; 32]| {
            crate::yubikey::sign::sign_btc(
                &ctx,
                &mut card,
                ApduMode::Short,
                &key,
                b"123456",
                sighash,
            )
        };
        sign_plan_card(approve(&fixture, &plan, 11), &plan, &account, &mut signer)
    };
    assert_eq!(result, Err(CardSignError::Card(CardError::SecurityStatus)));
    card.refuse_touch = false;
    // Another card: refused before the PIN.
    let mut other = MockCard::new(42);
    let result = {
        let mut signer = |sighash: [u8; 32]| {
            crate::yubikey::sign::sign_btc(
                &ctx,
                &mut other,
                ApduMode::Short,
                &key,
                b"123456",
                sighash,
            )
        };
        sign_plan_card(approve(&fixture, &plan, 12), &plan, &account, &mut signer)
    };
    assert_eq!(result, Err(CardSignError::Card(CardError::WrongCard)));
    assert!(!other.log.iter().any(|header| header[1] == 0x20));
    // A wrong PIN.
    let result = {
        let mut signer = |sighash: [u8; 32]| {
            crate::yubikey::sign::sign_btc(
                &ctx,
                &mut card,
                ApduMode::Short,
                &key,
                b"654321",
                sighash,
            )
        };
        sign_plan_card(approve(&fixture, &plan, 13), &plan, &account, &mut signer)
    };
    assert_eq!(
        result,
        Err(CardSignError::Card(CardError::WrongPin { retries: 2 }))
    );
    // A card answer that is not a signature of this sighash (another digest) fails the relaxed
    // check; a high-s answer fails it as well.
    let result = {
        let mut signer = |sighash: [u8; 32]| {
            let mut other_digest = sighash;
            other_digest[0] ^= 1;
            crate::yubikey::sign::sign_btc(
                &ctx,
                &mut card,
                ApduMode::Short,
                &key,
                b"123456",
                other_digest,
            )
        };
        sign_plan_card(approve(&fixture, &plan, 14), &plan, &account, &mut signer)
    };
    assert_eq!(
        result,
        Err(CardSignError::Sign(SignError::Witness(
            WitnessSigError::VerifyFailed
        )))
    );
    let result = {
        let mut signer = |sighash: [u8; 32]| {
            let der = crate::yubikey::sign::sign_btc(
                &ctx,
                &mut card,
                ApduMode::Short,
                &key,
                b"123456",
                sighash,
            )?;
            let signature = Signature::from_der(&der).unwrap();
            let compact = signature.serialize_compact();
            let negated = secp256k1::SecretKey::from_byte_array(
                <[u8; 32]>::try_from(&compact[32..]).unwrap(),
            )
            .unwrap()
            .negate();
            let mut high = compact;
            high[32..].copy_from_slice(&negated.secret_bytes());
            Ok(Signature::from_compact(&high)
                .unwrap()
                .serialize_der()
                .to_vec())
        };
        sign_plan_card(approve(&fixture, &plan, 15), &plan, &account, &mut signer)
    };
    assert_eq!(
        result,
        Err(CardSignError::Sign(SignError::Witness(
            WitnessSigError::HighS
        )))
    );
    // An approval of another plan.
    let other_plan = plan_with(
        &fixture,
        SendAmount::Exact(Sats::new(20_000).unwrap()),
        two_sat_per_vb(),
        3,
        None,
    );
    let mut never = |_: [u8; 32]| -> Result<Vec<u8>, CardError> { unreachable!("not asked") };
    assert_eq!(
        sign_plan_card(
            approve(&fixture, &other_plan, 16),
            &plan,
            &account,
            &mut never
        ),
        Err(CardSignError::Sign(SignError::ApprovalMismatch))
    );
    // Taproot: not a YubiKey account, not in the slot map, and refused by the card path.
    let BtcAccountKey::Hardware { pubkey, .. } = account else {
        unreachable!("a YubiKey account");
    };
    assert_eq!(
        BtcAccountKey::hardware(HwBtcKey::Address(3), ScriptType::P2tr, pubkey),
        Err(AccountKeyError::HardwareTaproot)
    );
    assert_eq!(
        BtcAccountKey::hardware(HwBtcKey::Address(1_000), ScriptType::P2wpkh, pubkey),
        Err(AccountKeyError::Account)
    );
    assert_eq!(
        fixture
            .vault
            .hardware_btc_account(NET, ScriptType::P2tr, HwBtcKey::Address(3)),
        Err(crate::error::VaultError::RecordNotFound)
    );
    assert_eq!(
        fixture
            .vault
            .hardware_btc_account(NET, ScriptType::P2wpkh, HwBtcKey::Address(4)),
        Err(crate::error::VaultError::RecordNotFound)
    );
    let forged = BtcAccountKey::Hardware {
        key: HwBtcKey::Address(3),
        script_type: ScriptType::P2tr,
        pubkey,
    };
    let mut forged_meta = BtcMeta::with_key(NET, forged);
    fund_receive0(&mut forged_meta, &[(90_000, 0xd3)]);
    let forged_fixture = Fixture {
        vault: about_vault(),
        account: forged,
        meta: forged_meta,
    };
    let forged_plan = plan_with(
        &forged_fixture,
        SendAmount::Exact(Sats::new(20_000).unwrap()),
        two_sat_per_vb(),
        4,
        None,
    );
    assert_eq!(
        sign_plan_card(
            approved_for(&forged_plan, &forged),
            &forged_plan,
            &forged,
            &mut never
        ),
        Err(CardSignError::Card(CardError::NotSupported))
    );
}

/// spec/02 §8.6: BIP84 account 0 of an added mnemonic (`abandon`×11 `about` primary, the Hardhat
/// mnemonic added) in both address modes: its first address is the independent vector, the
/// payload carries the marker-2 account block with the record id, the vault signs with that
/// mnemonic's keys (the primary mnemonic's node on the same path does not match), and the journal
/// record is version 3.
#[test]
fn added_mnemonic_send_end_to_end() {
    use crate::vault::tests::{HARDHAT, HARDHAT_BIP84_TEST, unlocked_with_added};
    for single_address in [false, true] {
        let (vault, second) = unlocked_with_added(super::tests::ABOUT, HARDHAT);
        let xpub = vault
            .btc_account_xpub_of(Some(second), BtcCoin::Test)
            .unwrap();
        let account = BtcAccountKey::hd(ScriptType::P2wpkh, 0, xpub)
            .unwrap()
            .with_mnemonic(Some(second))
            .with_single_address(single_address);
        assert_eq!(
            account
                .address(NET, BtcChain::Receive, 0)
                .unwrap()
                .to_string(),
            HARDHAT_BIP84_TEST
        );
        let fixture = fixture_of(vault, account);
        let plan = two_input_plan(&fixture);
        let payload = btc_payload(&plan);
        let block = &payload[payload.len() - 35..];
        assert_eq!(block[..3], [2, 1, ScriptType::P2wpkh.code()]);
        assert_eq!(block[3..7], 0_u32.to_be_bytes());
        assert!(block[7..19].iter().all(|byte| *byte == 0));
        assert_eq!(&block[19..], second.as_bytes());
        assert!(super::display::payload_header(&payload).is_some());
        let signed = sign_plan(
            &fixture.vault,
            approve(&fixture, &plan, 3),
            &plan,
            &fixture.account,
        )
        .unwrap();
        let verified = verify_signed(&signed.raw, &plan, &fixture.account).unwrap();
        assert_eq!(verified.txid(), plan.txid());
        // The same node presented as the primary mnemonic's account is refused (the plan's
        // account, mnemonic included, is bound; nothing signed).
        let primary_view = fixture.account.with_mnemonic(None);
        let mut store = ApprovalStore::new();
        let draft = build_btc_request(
            ApprovalId([4; 16]),
            &plan,
            &fixture.account,
            &fixture.meta.send_facts(&plan, TIP, &[]).unwrap(),
        )
        .unwrap();
        let request = store.issue(draft, NOW_MS, EXPIRES - 120_000).unwrap();
        let approved = store
            .consume(request.id, request.digest, NOW_MS + 1)
            .unwrap();
        assert!(sign_plan(&fixture.vault, approved, &plan, &primary_view).is_err());
        // Journal: version 3, round trip.
        let record = BtcRecord::new_signed(&plan, &signed, &verified, NOW_UNIX).unwrap();
        let body = record.encode().unwrap();
        assert_eq!(body[0], 3);
        assert_eq!(BtcRecord::decode(&body).unwrap(), record);
        let mut journal = JournalPlain::default();
        push_record(&mut journal, &record).unwrap();
        let journal = JournalPlain::decode(&journal.encode().unwrap()).unwrap();
        assert_eq!(BtcEntries::from_plain(&journal).records(), vec![record]);
    }
}
