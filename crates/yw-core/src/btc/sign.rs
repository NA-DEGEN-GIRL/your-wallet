//! ECDSA for P2WPKH witnesses (spec/08 §6.7, §11.2-3).
//!
//! [`sign_sighash`] runs inside `Vault::with_secp_key` (the context and key it lends): RFC 6979
//! `sign_ecdsa_low_r`, immediate `verify_ecdsa`, then the same strict check the post-sign
//! verification applies, returning the witness item `DER ‖ 0x01`. [`check_witness_signature`]
//! is that strict check: strict DER (`Signature::from_der`) whose `serialize_der` round trip is
//! identical, at most 70 DER bytes with `r < 2^255` (low-R), low-S (`normalize_s` changes
//! nothing), suffix `SIGHASH_ALL`, a 33-byte `02`/`03` public key, and a valid signature over the
//! sighash. [`sign_plan`] (spec/08 §11.1) signs an approved plan with these, one input at a
//! time inside `Vault::with_secp_key`, after checking that the one-time `Approved` token is for
//! exactly this plan (kind, chain, account and the `btc_payload` bytes).
#![deny(clippy::indexing_slicing)]

use core::fmt;

use secp256k1::ecdsa::Signature;
use secp256k1::{All, Message, PublicKey, Secp256k1, SecretKey, Verification};

use super::SIGHASH_ALL;
use super::address::{hash160, p2wpkh_program};
use super::amount::Sats;
use super::display::btc_payload;
use super::policy::texts;
use super::select::SendPlan;
use super::sighash::bip143_sighash_p2wpkh;
use super::tx::{OutPoint, serialize};
use crate::approval::{AccountRef, ApprovalId, Approved, ChainRef, Signer, SigningPayload};
use crate::bip32::AccountXpub;
use crate::entropy::{OsRandom, secp_context};
use crate::error::VaultError;
use crate::vault::{KeyRef, Vault};

/// Longest DER signature we produce or accept (low-R, low-S).
pub const MAX_DER_LEN: usize = 70;
/// Longest witness signature item (`DER ‖ sighash type`).
pub const MAX_WITNESS_SIG_LEN: usize = MAX_DER_LEN + 1;
/// Compressed public key length.
pub const PUBKEY_LEN: usize = 33;

/// Why a witness signature or key item was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WitnessSigError {
    /// The signature item is empty or does not end with `SIGHASH_ALL` (0x01).
    SighashType,
    /// The DER part is longer than 70 bytes.
    DerTooLong,
    /// Not strict DER.
    DerInvalid,
    /// `serialize_der` does not give the same bytes back.
    DerNotCanonical,
    /// `r ≥ 2^255` (not low-R).
    HighR,
    /// `s > n/2` (not low-S).
    HighS,
    /// The key item is not a 33-byte `02`/`03` point on the curve.
    PublicKey,
    /// The signature does not verify for the sighash and key.
    VerifyFailed,
    /// The OS CSPRNG failed while creating the verification context.
    RandomnessUnavailable,
}

impl fmt::Display for WitnessSigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SighashType => "witness signature does not end with SIGHASH_ALL",
            Self::DerTooLong => "DER signature is longer than 70 bytes",
            Self::DerInvalid => "signature is not strict DER",
            Self::DerNotCanonical => "DER signature does not round-trip",
            Self::HighR => "signature is not low-R",
            Self::HighS => "signature is not low-S",
            Self::PublicKey => "witness public key is not a compressed point",
            Self::VerifyFailed => "signature does not verify",
            Self::RandomnessUnavailable => "randomness unavailable",
        })
    }
}

impl std::error::Error for WitnessSigError {}

/// [`check_witness_signature`] with a caller's context.
pub(crate) fn check_witness_signature_with<C: Verification>(
    ctx: &Secp256k1<C>,
    sig_item: &[u8],
    pubkey_item: &[u8],
    sighash: &[u8; 32],
) -> Result<(), WitnessSigError> {
    let (sighash_type, der) = sig_item.split_last().ok_or(WitnessSigError::SighashType)?;
    if *sighash_type != SIGHASH_ALL {
        return Err(WitnessSigError::SighashType);
    }
    if der.len() > MAX_DER_LEN {
        return Err(WitnessSigError::DerTooLong);
    }
    let signature = Signature::from_der(der).map_err(|_| WitnessSigError::DerInvalid)?;
    if signature.serialize_der().as_ref() != der {
        return Err(WitnessSigError::DerNotCanonical);
    }
    if signature
        .serialize_compact()
        .first()
        .is_none_or(|byte| byte & 0x80 != 0)
    {
        return Err(WitnessSigError::HighR);
    }
    let mut normalized = signature;
    normalized.normalize_s();
    if normalized != signature {
        return Err(WitnessSigError::HighS);
    }
    let key = <[u8; PUBKEY_LEN]>::try_from(pubkey_item).map_err(|_| WitnessSigError::PublicKey)?;
    if !matches!(key.first(), Some(0x02 | 0x03)) {
        return Err(WitnessSigError::PublicKey);
    }
    let public =
        PublicKey::from_byte_array_compressed(key).map_err(|_| WitnessSigError::PublicKey)?;
    ctx.verify_ecdsa(Message::from_digest(*sighash), &signature, &public)
        .map_err(|_| WitnessSigError::VerifyFailed)
}

/// Strict check of a P2WPKH witness `[sig_item, pubkey_item]` against `sighash`
/// (spec/08 §11.2-3 and -5).
///
/// # Errors
///
/// The first failing rule's [`WitnessSigError`].
pub fn check_witness_signature(
    sig_item: &[u8],
    pubkey_item: &[u8],
    sighash: &[u8; 32],
) -> Result<(), WitnessSigError> {
    let ctx = secp_context(&mut OsRandom).map_err(|_| WitnessSigError::RandomnessUnavailable)?;
    check_witness_signature_with(&ctx, sig_item, pubkey_item, sighash)
}

/// Signs `sighash` with `secret` (low-R RFC 6979), verifies at once and returns the witness
/// signature item `DER ‖ 0x01` (≤ 71 bytes). Called only inside `Vault::with_secp_key`.
pub(crate) fn sign_sighash(
    ctx: &Secp256k1<All>,
    secret: &SecretKey,
    sighash: &[u8; 32],
) -> Result<Vec<u8>, WitnessSigError> {
    let message = Message::from_digest(*sighash);
    let signature = ctx.sign_ecdsa_low_r(message, secret);
    let public = PublicKey::from_secret_key(ctx, secret);
    ctx.verify_ecdsa(message, &signature, &public)
        .map_err(|_| WitnessSigError::VerifyFailed)?;
    let der = signature.serialize_der();
    let mut item = Vec::with_capacity(MAX_WITNESS_SIG_LEN);
    item.extend_from_slice(der.as_ref());
    item.push(SIGHASH_ALL);
    check_witness_signature_with(ctx, &item, &public.serialize(), sighash)?;
    Ok(item)
}

/// Signing failure: nothing signed is returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignError {
    /// The approval is not for this plan (kind, chain, account, signer or payload bytes).
    ApprovalMismatch,
    /// The plan's inputs do not match its transaction.
    PlanInconsistent,
    /// The derived key of input `input` does not hash to the cached account's program
    /// (spec/08 §3.1 `KeyMismatch`).
    KeyMismatch {
        /// Input index.
        input: usize,
    },
    /// A plan amount differs from a recorded verified amount, or is not recorded
    /// (spec/08 §5 `AmountRecordMismatch`).
    AmountRecordMismatch,
    /// Program derivation from the account node failed.
    Derivation,
    /// The fresh signature failed its own strict check.
    Witness(WitnessSigError),
    /// The vault refused (locked, backup pending, derivation).
    Vault(VaultError),
}

impl fmt::Display for SignError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Vault(error) => error.fmt(formatter),
            Self::ApprovalMismatch => formatter.write_str(texts::APPROVAL_MISMATCH),
            Self::KeyMismatch { .. } => formatter.write_str(texts::KEY_MISMATCH),
            Self::AmountRecordMismatch => formatter.write_str(texts::AMOUNT_RECORD_MISMATCH),
            Self::PlanInconsistent | Self::Derivation | Self::Witness(_) => {
                formatter.write_str(texts::SIGN_INTERNAL)
            }
        }
    }
}

impl std::error::Error for SignError {}

/// A freshly signed transaction. It must pass `verify::verify_signed` before it is journaled
/// or sent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedTx {
    /// Signed bytes with witnesses.
    pub raw: Vec<u8>,
    /// The consumed approval's id (the journal `entry_id`).
    pub approval_id: ApprovalId,
    /// The consumed approval's digest (the journal `approval_digest`).
    pub approval_digest: [u8; 32],
}

/// The amount-record check before signing (spec/08 §5 "검증 금액 기록", BTC-N3): every plan input
/// must have at least one recorded value and every recorded value for its outpoint must equal
/// the plan's value. `recorded` is `BtcMeta::recorded_amounts` plus the input lists of the
/// journal records (`journal::btc::recorded_amounts`). The app calls this right before
/// [`sign_plan`].
///
/// # Errors
///
/// [`SignError::AmountRecordMismatch`] (a hard stop: bug or tampering).
pub fn check_recorded_amounts(
    plan: &SendPlan,
    recorded: &[(OutPoint, Sats)],
) -> Result<(), SignError> {
    for input in plan.inputs() {
        let mut seen = false;
        for (outpoint, value) in recorded {
            if *outpoint == input.outpoint {
                if *value != input.value {
                    return Err(SignError::AmountRecordMismatch);
                }
                seen = true;
            }
        }
        if !seen {
            return Err(SignError::AmountRecordMismatch);
        }
    }
    Ok(())
}

fn approval_matches(approved: &Approved, plan: &SendPlan, acct: &AccountXpub) -> bool {
    let network = plan.network();
    approved.kind() == plan.kind()
        && approved.signer() == Signer::FromPayload
        && approved.chain()
            == (ChainRef::Bitcoin {
                network: network.id(),
                genesis: network.genesis(),
            })
        && approved.account() == AccountRef::Bitcoin(acct.pubkey)
        && matches!(approved.payload(), SigningPayload::Btc(bytes) if *bytes == btc_payload(plan))
}

/// Signs an approved plan (spec/08 §11.1): refuses unless `approved` is this plan's kind, chain,
/// account and byte-identical `btc_payload`; then, per input inside
/// `vault.with_secp_key(KeyRef::Btc { coin, chain, index })`, checks that `HASH160(pubkey)` is the
/// program derived from the cached account node (else `KeyMismatch`), computes the BIP143
/// sighash with the verified amount, signs (low-R, verified at once) and builds the witness
/// `[DER ‖ 0x01, pubkey]`. The private key never leaves the closure.
///
/// # Errors
///
/// [`SignError`]; nothing signed is returned on error.
#[expect(
    clippy::needless_pass_by_value,
    reason = "the one-time approval token is consumed by signing (spec/03 §11.5)"
)]
pub fn sign_plan(
    vault: &Vault,
    approved: Approved,
    plan: &SendPlan,
    acct: &AccountXpub,
) -> Result<SignedTx, SignError> {
    if !approval_matches(&approved, plan, acct) {
        return Err(SignError::ApprovalMismatch);
    }
    let unsigned = plan.tx();
    let inputs = plan.inputs();
    if inputs.len() != unsigned.inputs.len()
        || inputs
            .iter()
            .zip(&unsigned.inputs)
            .any(|(planned, input)| planned.outpoint != input.prevout || !input.witness.is_empty())
    {
        return Err(SignError::PlanInconsistent);
    }
    let coin = plan.network().coin_type();
    let mut signed = unsigned.clone();
    for (position, (planned, input)) in inputs.iter().zip(signed.inputs.iter_mut()).enumerate() {
        let program = p2wpkh_program(acct, planned.chain, planned.index)
            .map_err(|_| SignError::Derivation)?;
        let sighash = bip143_sighash_p2wpkh(unsigned, position, &program, planned.value)
            .ok_or(SignError::PlanInconsistent)?;
        let key = KeyRef::Btc {
            coin,
            chain: planned.chain,
            index: planned.index,
        };
        let witness = vault
            .with_secp_key(key, |ctx, secret| {
                let public = PublicKey::from_secret_key(ctx, secret).serialize();
                if hash160(&public) != program {
                    return Ok(Err(SignError::KeyMismatch { input: position }));
                }
                Ok(sign_sighash(ctx, secret, &sighash)
                    .map(|signature| vec![signature, public.to_vec()])
                    .map_err(SignError::Witness))
            })
            .map_err(SignError::Vault)??;
        input.witness = witness;
    }
    Ok(SignedTx {
        raw: serialize(&signed, true),
        approval_id: approved.id(),
        approval_digest: approved.digest(),
    })
}
