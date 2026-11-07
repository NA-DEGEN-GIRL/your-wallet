//! The approval payload, signing (vault key or `YubiKey`) and the post-sign verification of a
//! Zcash transparent send (spec/12 §8–§10).
//!
//! Software keys sign like Bitcoin P2PKH inputs (`btc::sign::sign_sighash`: RFC 6979 low-R,
//! low-S, verified at once, `DER ‖ 0x01`), but over the ZIP 244 `SIGHASH_ALL` digest. A card
//! signature passes the relaxed card rules (strict DER ≤ 72, low-S, high-R allowed). Before any
//! signature the lent key's public key must be the account's cached key, and after signing
//! [`verify_signed`] re-parses the bytes and re-checks every rule; nothing unverified leaves.
#![deny(clippy::indexing_slicing)]

use core::fmt;

use secp256k1::{All, PublicKey, Secp256k1, SecretKey};

use super::account::{ZecAccount, ZecKeySource};
use super::fee::tx_conventional_fee;
use super::plan::ZecPlan;
use super::sighash::{SIGHASH_ALL, sighash_all};
use super::tx::{ZecTx, parse_tx, serialize_tx, txid};
use super::{ZEC_FEE_ABS_CAP, ZEC_SEQUENCE};
use crate::approval::{AccountRef, ApprovalId, Approved, ChainRef, Signer, SigningPayload};
use crate::bip32::path::AccountIndex;
use crate::btc::script::{p2pkh_script_sig, split_p2pkh_script_sig};
use crate::btc::sign::{
    WitnessSigError, check_card_signature_with, check_p2pkh_signature_with, sign_sighash,
};
use crate::codec::transcript::Transcript;
use crate::entropy::{OsRandom, secp_context};
use crate::error::VaultError;
use crate::vault::{EvmKeySource, KeyRef, Vault};
use crate::yubikey::CardError;

/// The digest bytes of a plan (`SigningPayload::Zec`): transcript `"your-wallet/v3/zec-send"`
/// v1 of the network, key source, public key, recipient (form, destination, text), amount,
/// fee, change, consensus fields, input values and the unsigned transaction bytes.
#[must_use]
pub fn zec_payload(plan: &ZecPlan) -> Vec<u8> {
    let mut transcript = Transcript::default();
    let _ = transcript.push_bytes(b"your-wallet/v3/zec-send");
    transcript.push_u16(1);
    transcript.push_u8(plan.account.network.id());
    let (a, b) = plan.account.source.params();
    transcript.push_u8(plan.account.source.code());
    transcript.push_u32(a);
    transcript.push_u32(b);
    let _ = transcript.push_bytes(&plan.account.pubkey);
    transcript.push_u8(plan.recipient.form.code());
    let _ = transcript.push_bytes(&plan.recipient.dest.script_pubkey());
    let _ = transcript.push_str(&plan.recipient.text);
    transcript.push_u64(plan.amount);
    transcript.push_u64(plan.fee);
    transcript.push_u64(plan.change);
    transcript.push_bool(plan.send_max);
    transcript.push_u32(plan.consensus.branch_id);
    transcript.push_u32(plan.consensus.expiry_height);
    transcript.push_u32(u32::try_from(plan.inputs.len()).unwrap_or(u32::MAX));
    for input in &plan.inputs {
        transcript.push_u64(input.value);
    }
    let _ = transcript.push_bytes(&serialize_tx(&plan.tx));
    transcript.into_bytes()
}

/// The network byte of a [`zec_payload`] (the approval store binds it to the chain).
#[must_use]
pub fn payload_network(payload: &[u8]) -> Option<u8> {
    // Transcript layout: length-prefixed domain bytes, u16 version, then the network byte.
    let mut transcript = Transcript::default();
    let _ = transcript.push_bytes(b"your-wallet/v3/zec-send");
    transcript.push_u16(1);
    let prefix = transcript.into_bytes();
    if payload.get(..prefix.len()) != Some(prefix.as_slice()) {
        return None;
    }
    payload.get(prefix.len()).copied()
}

/// Signing / verification failure: nothing signed is returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZecSignError {
    /// The approval is not for this plan.
    ApprovalMismatch,
    /// The plan does not match its own transaction.
    PlanInconsistent,
    /// The lent (or card) key is not the account key.
    KeyMismatch,
    /// A fresh signature failed its own strict check.
    Signature(WitnessSigError),
    /// The vault refused (locked, backup pending, no mnemonic, ...).
    Vault(VaultError),
    /// The card failed.
    Card(CardError),
    /// The signed bytes failed the post-sign verification (spec/12 §10.2).
    PostSign(PostSignError),
}

impl fmt::Display for ZecSignError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Vault(error) => error.fmt(formatter),
            Self::Card(error) => error.fmt(formatter),
            Self::ApprovalMismatch => formatter.write_str("승인 내용과 서명할 거래가 다릅니다."),
            Self::KeyMismatch => {
                formatter.write_str("서명 키가 이 Zcash 계정의 키와 다릅니다. 서명을 멈췄습니다.")
            }
            Self::PlanInconsistent | Self::Signature(_) | Self::PostSign(_) => {
                formatter.write_str("Zcash 거래 서명 검증에 실패해 폐기했습니다.")
            }
        }
    }
}

impl std::error::Error for ZecSignError {}

/// Which post-sign rule failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PostSignError {
    /// Not a strict transparent v5 transaction.
    Parse,
    /// Header, consensus fields, inputs (outpoints, sequence), or outputs differ from the plan.
    Shape,
    /// A scriptSig is not `<sig> <pubkey>` with our key.
    ScriptSig,
    /// A signature failed its rules or does not verify.
    Signature,
    /// Fee differs from the plan, is below the ZIP 317 fee of the signed size, or above the cap.
    Fee,
}

/// A verified signed transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZecSignedTx {
    /// Raw bytes.
    pub raw: Vec<u8>,
    /// ZIP 244 txid (internal order).
    pub txid: [u8; 32],
    /// Consumed approval id.
    pub approval_id: ApprovalId,
    /// Consumed approval digest.
    pub approval_digest: [u8; 32],
}

fn approval_matches(approved: &Approved, plan: &ZecPlan) -> bool {
    let network = plan.account.network;
    approved.kind() == crate::approval::ApprovalKind::ZecSend
        && approved.signer() == Signer::FromPayload
        && approved.chain()
            == (ChainRef::Zcash {
                network: network.id(),
                genesis: network.genesis(),
            })
        && approved.account() == AccountRef::Zcash(plan.account.pubkey)
        && matches!(approved.payload(), SigningPayload::Zec(bytes) if *bytes == zec_payload(plan))
}

/// The plan's transaction is the transaction its fields describe.
fn check_plan(plan: &ZecPlan) -> Result<(), ZecSignError> {
    let tx = &plan.tx;
    let ok = tx.branch_id == plan.consensus.branch_id
        && tx.expiry_height == plan.consensus.expiry_height
        && tx.lock_time == 0
        && tx.inputs.len() == plan.inputs.len()
        && tx.inputs.iter().zip(&plan.inputs).all(|(input, utxo)| {
            input.prevout == utxo.outpoint
                && input.script_sig.is_empty()
                && input.sequence == ZEC_SEQUENCE
        })
        && expected_outputs_ok(plan, tx)
        && plan
            .input_total()
            .checked_sub(plan.amount)
            .and_then(|rest| rest.checked_sub(plan.change))
            == Some(plan.fee)
        && plan.fee <= ZEC_FEE_ABS_CAP;
    if ok {
        Ok(())
    } else {
        Err(ZecSignError::PlanInconsistent)
    }
}

fn expected_outputs_ok(plan: &ZecPlan, tx: &ZecTx) -> bool {
    let recipient = plan.recipient.dest.script_pubkey();
    match tx.outputs.as_slice() {
        [to] => plan.change == 0 && to.value == plan.amount && to.script_pubkey == recipient,
        [to, change] => {
            plan.change > 0
                && to.value == plan.amount
                && to.script_pubkey == recipient
                && change.value == plan.change
                && change.script_pubkey == plan.account.script_pubkey()
        }
        _ => false,
    }
}

/// Lends the account's secret key to `f` (vault-derived or the EVM key).
fn with_account_key<T>(
    vault: &Vault,
    account: &ZecAccount,
    f: impl FnOnce(&Secp256k1<All>, &SecretKey) -> Result<T, ZecSignError>,
) -> Result<T, ZecSignError> {
    let key = match account.source {
        ZecKeySource::Derived { account: a, index } => KeyRef::Zec {
            test: account.network == super::ZecNetwork::Testnet,
            account: a,
            index,
        },
        ZecKeySource::EvmShared { evm_index } => KeyRef::Evm(EvmKeySource::Derived(
            AccountIndex::new(evm_index).map_err(|_| ZecSignError::KeyMismatch)?,
        )),
        ZecKeySource::Hardware { .. } => {
            return Err(ZecSignError::Vault(VaultError::RecordNotFound));
        }
        ZecKeySource::Imported => KeyRef::ZecImported {
            network: account.network,
            pubkey: account.pubkey,
        },
    };
    vault
        .with_secp_key(key, |ctx, secret| Ok(f(ctx, secret)))
        .map_err(ZecSignError::Vault)?
}

/// Signs an approved plan with the vault (spec/12 §10.1), then verifies the result.
///
/// # Errors
///
/// [`ZecSignError`]; nothing signed is returned on error.
#[expect(
    clippy::needless_pass_by_value,
    reason = "the one-time approval token is consumed by signing (spec/03 §11.5)"
)]
pub fn sign_plan(
    vault: &Vault,
    approved: Approved,
    plan: &ZecPlan,
) -> Result<ZecSignedTx, ZecSignError> {
    if plan.account.is_hardware() || !approval_matches(&approved, plan) {
        return Err(ZecSignError::ApprovalMismatch);
    }
    check_plan(plan)?;
    let prevouts = plan.prevouts();
    let mut sighashes = Vec::with_capacity(plan.inputs.len());
    for index in 0..plan.inputs.len() {
        sighashes
            .push(sighash_all(&plan.tx, index, &prevouts).ok_or(ZecSignError::PlanInconsistent)?);
    }
    let items = with_account_key(vault, &plan.account, |ctx, secret| {
        let public = PublicKey::from_secret_key(ctx, secret);
        if public.serialize() != plan.account.pubkey {
            return Err(ZecSignError::KeyMismatch);
        }
        sighashes
            .iter()
            .map(|sighash| sign_sighash(ctx, secret, sighash).map_err(ZecSignError::Signature))
            .collect::<Result<Vec<_>, _>>()
    })?;
    finish(&approved, plan, &items, false)
}

/// The card signs one 32-byte digest and returns its DER signature (low-S, checked against the
/// recorded key by `yubikey::sign::sign_btc_checked`).
pub type ZecCardSigner<'a> = &'a mut dyn FnMut([u8; 32]) -> Result<Vec<u8>, CardError>;

/// Signs an approved plan of a `YubiKey` account on the card (spec/10 §6.4), then verifies it.
///
/// # Errors
///
/// [`ZecSignError`]; nothing signed is returned on error.
#[expect(
    clippy::needless_pass_by_value,
    reason = "the one-time approval token is consumed by signing (spec/03 §11.5)"
)]
pub fn sign_plan_card(
    approved: Approved,
    plan: &ZecPlan,
    card: ZecCardSigner<'_>,
) -> Result<ZecSignedTx, ZecSignError> {
    if !plan.account.is_hardware() || !approval_matches(&approved, plan) {
        return Err(ZecSignError::ApprovalMismatch);
    }
    check_plan(plan)?;
    let prevouts = plan.prevouts();
    let ctx = Secp256k1::verification_only();
    let mut items = Vec::with_capacity(plan.inputs.len());
    for index in 0..plan.inputs.len() {
        let sighash =
            sighash_all(&plan.tx, index, &prevouts).ok_or(ZecSignError::PlanInconsistent)?;
        let der = card(sighash).map_err(ZecSignError::Card)?;
        let mut item = der;
        item.push(SIGHASH_ALL);
        check_card_signature_with(&ctx, &item, &plan.account.pubkey, &sighash)
            .map_err(ZecSignError::Signature)?;
        items.push(item);
    }
    finish(&approved, plan, &items, true)
}

fn finish(
    approved: &Approved,
    plan: &ZecPlan,
    items: &[Vec<u8>],
    card: bool,
) -> Result<ZecSignedTx, ZecSignError> {
    let mut signed = plan.tx.clone();
    for (input, item) in signed.inputs.iter_mut().zip(items) {
        input.script_sig =
            p2pkh_script_sig(item, &plan.account.pubkey).ok_or(ZecSignError::PlanInconsistent)?;
    }
    let raw = serialize_tx(&signed);
    let txid = verify_signed(&raw, plan, card).map_err(ZecSignError::PostSign)?;
    Ok(ZecSignedTx {
        raw,
        txid,
        approval_id: approved.id(),
        approval_digest: approved.digest(),
    })
}

/// The post-sign verification (spec/12 §10.2): strict parse, the same transaction as the plan
/// except the scriptSigs, every scriptSig `<DER‖01> <our key>` with a valid signature over its
/// ZIP 244 digest (software: low-R/low-S ≤ 70 DER bytes; card: low-S ≤ 72), and the fee equal to
/// the plan, at least the ZIP 317 fee of the signed sizes and at most the cap. Returns the txid.
///
/// # Errors
///
/// [`PostSignError`].
pub fn verify_signed(raw: &[u8], plan: &ZecPlan, card: bool) -> Result<[u8; 32], PostSignError> {
    let tx = parse_tx(raw).map_err(|_| PostSignError::Parse)?;
    let mut unsigned = tx.clone();
    for input in &mut unsigned.inputs {
        input.script_sig.clear();
    }
    if unsigned != plan.tx {
        return Err(PostSignError::Shape);
    }
    let prevouts = plan.prevouts();
    let ctx = secp_context(&mut OsRandom).map_err(|_| PostSignError::Signature)?;
    for (index, input) in tx.inputs.iter().enumerate() {
        let (sig, key) =
            split_p2pkh_script_sig(&input.script_sig).ok_or(PostSignError::ScriptSig)?;
        if key != plan.account.pubkey {
            return Err(PostSignError::ScriptSig);
        }
        let sighash = sighash_all(&tx, index, &prevouts).ok_or(PostSignError::Shape)?;
        let checked = if card {
            check_card_signature_with(&ctx, sig, key, &sighash)
        } else {
            check_p2pkh_signature_with(&ctx, sig, key, &sighash)
        };
        checked.map_err(|_| PostSignError::Signature)?;
    }
    let outputs = tx
        .outputs
        .iter()
        .map(|output| output.value)
        .fold(0_u64, u64::saturating_add);
    let fee = plan.input_total().checked_sub(outputs);
    if fee != Some(plan.fee) || plan.fee < tx_conventional_fee(&tx) || plan.fee > ZEC_FEE_ABS_CAP {
        return Err(PostSignError::Fee);
    }
    Ok(txid(&tx))
}
