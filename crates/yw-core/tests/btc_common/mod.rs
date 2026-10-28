//! Shared fixtures of the BTC send-path integration tests (public API only). The account node is
//! the public testnet4 node of the `abandon`×11 `about` test wallet (spec/08 §14.1); signed
//! transactions here carry placeholder signatures with the real public keys, which is what the
//! journal decoder and `bump_source` check (they never verify signatures).
#![allow(
    dead_code,
    clippy::unwrap_used,
    reason = "each test binary uses a subset of these fixtures, which panic when broken"
)]

use yw_core::bip32::path::BtcChain;
use yw_core::bip32::{AccountXpub, derive_public_child};
use yw_core::btc::address::ScriptKind;
use yw_core::btc::amount::Sats;
use yw_core::btc::fee::{FeeChoice, FeeRate, FeeSource};
use yw_core::btc::network::BtcNetwork;
use yw_core::btc::select::{SendAmount, SendPlan, SendRequest, Utxo, plan_send};
use yw_core::btc::tx::{OutPoint, Txid, parse_transaction, serialize, txid, vsize, wtxid};
use yw_core::hex;
use yw_core::journal::btc::{BtcRecord, BtcTxState, RecordChange};

/// Wallet network of the fixtures.
pub const NET: BtcNetwork = BtcNetwork::Testnet4;
/// Core tip of the fixtures.
pub const TIP: u32 = 200_000;
/// A fixed layout seed.
pub const SEED: [u8; 32] = [0x5a; 32];

/// testnet4 `m/84'/1'/0'` of `abandon`×11 `about` (public data).
pub fn account() -> AccountXpub {
    AccountXpub {
        pubkey: hex::decode_array::<33>(
            "03b88e0fbe3f646337ed93bc0c0f3b843fcf7d2589e5ec884754e6402027a890b4",
        )
        .unwrap(),
        chain_code: hex::decode_array::<32>(
            "3c8c2037ee4c1621da0d348db51163709a622d0d2838dde6d8419c51f6301c62",
        )
        .unwrap(),
    }
}

/// `m/84'/1'/0'/{chain}/{index}` public key.
pub fn pubkey(chain: BtcChain, index: u32) -> [u8; 33] {
    let chain_node = derive_public_child(&account(), chain.index()).unwrap();
    derive_public_child(&chain_node, index).unwrap().pubkey
}

/// A candidate with outpoint `tag…tag:vout`.
pub fn utxo(value: u64, height: u32, tag: u8, vout: u32) -> Utxo {
    Utxo {
        outpoint: OutPoint {
            txid: Txid::from_bytes([tag; 32]),
            vout,
        },
        value: Sats::new(value).unwrap(),
        chain: BtcChain::Receive,
        index: u32::from(tag) % 7,
        height,
        is_coinbase: false,
    }
}

/// A manual rate of `sat_per_vb`.
pub fn rate(sat_per_vb: u64) -> FeeChoice {
    FeeChoice {
        rate: FeeRate::from_sat_per_kvb(sat_per_vb * 1_000),
        source: FeeSource::Manual,
    }
}

/// A plain P2WPKH recipient (not ours).
pub const RECIPIENT: ScriptKind = ScriptKind::P2wpkh([0x33; 20]);

/// One recipient of each kind (P2TR with a valid x-only key).
pub fn kinds() -> [ScriptKind; 5] {
    [
        ScriptKind::P2pkh([0x11; 20]),
        ScriptKind::P2sh([0x22; 20]),
        ScriptKind::P2wpkh([0x33; 20]),
        ScriptKind::P2wsh([0x44; 32]),
        ScriptKind::P2tr(
            hex::decode_array::<32>(
                "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            )
            .unwrap(),
        ),
    ]
}

/// A send plan.
pub fn plan(
    candidates: &[Utxo],
    recipient: ScriptKind,
    amount: SendAmount,
    fee: FeeChoice,
    seed: [u8; 32],
) -> Result<SendPlan, yw_core::btc::select::PlanError> {
    let account = account();
    plan_send(&SendRequest {
        network: NET,
        account: &account,
        recipient,
        amount,
        fee,
        candidates,
        tip_height: TIP,
        change_next: 3,
        layout_seed: seed,
        typed_fee_override: None,
        conflicts: &[],
    })
}

/// The plan's transaction with placeholder 71-byte signatures and the real public keys.
pub fn signed_raw(plan: &SendPlan) -> Vec<u8> {
    let mut tx = plan.tx().clone();
    for (input, planned) in tx.inputs.iter_mut().zip(plan.inputs()) {
        let mut signature = vec![0x30; 70];
        signature.push(0x01);
        input.witness = vec![signature, pubkey(planned.chain, planned.index).to_vec()];
    }
    serialize(&tx, true)
}

/// A journal record of `plan` in `state`, created at `created` (Unix seconds).
pub fn record(plan: &SendPlan, state: BtcTxState, created: u64) -> BtcRecord {
    let raw = signed_raw(plan);
    let parsed = parse_transaction(&raw).unwrap();
    let mut entry_id = [0_u8; 16];
    entry_id[..8].copy_from_slice(&created.to_be_bytes());
    entry_id[15] = 1;
    BtcRecord {
        network: plan.network(),
        state,
        send_max: plan.send_max(),
        fee_override_typed: plan.fee_override_typed(),
        entry_id,
        created_at_unix: created,
        updated_at_unix: created,
        txid: txid(&parsed),
        wtxid: wtxid(&parsed),
        approval_digest: [0x99; 32],
        fee: plan.fee(),
        vsize: u32::try_from(vsize(&parsed)).unwrap(),
        lock_time: plan.lock_time(),
        not_found_count: 0,
        last_send_comm_failure: false,
        replaces: plan.replaces(),
        replaced_by: None,
        confirmed_height: (state == BtcTxState::Confirmed).then_some(TIP),
        change: plan.change().map(|change| RecordChange {
            index: change.index,
            vout: change.vout,
        }),
        recipient_vout: plan.recipient_vout(),
        inputs: plan.inputs().to_vec(),
        raw,
    }
}

/// A simple 1-input send with change, distinguished by `tag`.
pub fn simple_plan(tag: u8, amount: u64) -> SendPlan {
    plan(
        &[utxo(100_000, TIP - 10, tag, 0)],
        RECIPIENT,
        SendAmount::Exact(Sats::new(amount).unwrap()),
        rate(1),
        SEED,
    )
    .unwrap()
}
