//! Signing approved dApp transactions (spec/07 §20.5, §20.10-3): the signer parses the
//! **approved** bytes again (never the site's copy), checks the kind, chain, account, key source
//! and every site signature, fills only its own slot and verifies the result. The blockhash is
//! never changed. A software key signs every message of the request in one key lending; a
//! `YubiKey` signs each message on the card (one touch per transaction).
//!
//! A send (`SignAndSend`, spec/07 §20.8) additionally runs after the pre-sign RPC check
//! (§20.10-2): the 20 s deadline from that answer, the pre-sign blockhash and the re-resolved
//! lookup tables against the approved ones, and every other required signature present.
#![deny(clippy::indexing_slicing)]

use core::fmt;

use sha2::{Digest, Sha256};

use super::alt::ResolvedKeys;
use super::parse::{SolWireTx, parse_wire_tx};
use super::{SolTxItem, SolTxMode, SolTxPayload, SolTxPayloadError};
use crate::approval::{AccountRef, ApprovalKind, Approved, ChainRef, SigningPayload};
use crate::error::VaultError;
use crate::sol::keys::verify_strict;
use crate::sol::msgsign::{SolMessageError, sign_with_seed};
use crate::sol::sign::{SOL_SIGN_DEADLINE_SECS, SolCardSigner};
use crate::sol::template::SOL_MAX_TX_BYTES;
use crate::vault::Vault;

/// Why an approved dApp transaction was not signed. Nothing is returned on error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SolTxSignError {
    /// More than `SOL_SIGN_DEADLINE_SECS` passed since the pre-sign answer (send only).
    DeadlineExceeded,
    /// Not a dApp transaction approval of this mode, chain or account, or a payload that fails
    /// its own checks.
    KindMismatch,
    /// The approved bytes no longer parse with identity, or the pre-sign blockhash differs.
    EncodingMismatch,
    /// The key does not give the approved public key.
    KeyMismatch,
    /// A site signature does not verify.
    ForeignSignature,
    /// A send whose other required signatures are not all present.
    MissingSignature,
    /// The lookup tables resolve to other addresses than the approved ones (send only).
    TablesChanged,
    /// A recovery-scan source (`needs_move_rule`).
    PolicyMismatch,
    /// The signature or the assembled transaction failed the post-sign checks.
    PostSignVerification,
    /// Vault refusal (locked, record missing, backup gate).
    Vault(VaultError),
}

impl SolTxSignError {
    /// The fixed text in `lang` (`Display` is the Korean one).
    #[must_use]
    pub fn text_in(self, lang: crate::lang::Lang) -> String {
        use super::text as t;
        let text = match self {
            Self::DeadlineExceeded => t::SIGN_DEADLINE,
            Self::TablesChanged => t::SIGN_TABLES_CHANGED,
            Self::ForeignSignature | Self::MissingSignature => t::SIGN_FOREIGN,
            Self::Vault(error) => return error.text_in(lang),
            Self::KindMismatch
            | Self::EncodingMismatch
            | Self::KeyMismatch
            | Self::PolicyMismatch => t::SIGN_INTERNAL,
            Self::PostSignVerification => t::SIGN_POST,
        };
        text.get(lang).to_owned()
    }
}

impl fmt::Display for SolTxSignError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text_in(crate::lang::Lang::Ko))
    }
}

impl std::error::Error for SolTxSignError {}

/// The message signer's errors in this signer's terms (`KindMismatch`/`Refused` cannot happen
/// for a seed signature; they map to `KindMismatch`).
pub(super) const fn from_message_error(error: SolMessageError) -> SolTxSignError {
    match error {
        SolMessageError::KeyMismatch => SolTxSignError::KeyMismatch,
        SolMessageError::Signing => SolTxSignError::PostSignVerification,
        SolMessageError::KindMismatch | SolMessageError::Refused => SolTxSignError::KindMismatch,
    }
}

/// Failure of a card (`YubiKey`) dApp transaction signature (spec/10 §6.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SolTxCardError {
    /// The approval or a post-sign check failed (as for vault signing; `KindMismatch` also for a
    /// source other than `SolKeySource::Hardware`).
    Sign(SolTxSignError),
    /// The card operation failed.
    Card(crate::yubikey::CardError),
}

impl SolTxCardError {
    /// The text in `lang` (`Display` is the Korean one).
    #[must_use]
    pub fn text_in(self, lang: crate::lang::Lang) -> String {
        match self {
            Self::Sign(error) => error.text_in(lang),
            Self::Card(error) => error.text_in(lang),
        }
    }
}

impl fmt::Display for SolTxCardError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sign(error) => error.fmt(formatter),
            Self::Card(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for SolTxCardError {}

impl From<SolTxSignError> for SolTxCardError {
    fn from(error: SolTxSignError) -> Self {
        Self::Sign(error)
    }
}

impl From<crate::yubikey::CardError> for SolTxCardError {
    fn from(error: crate::yubikey::CardError) -> Self {
        Self::Card(error)
    }
}

/// The approval checks before any key use: kind, payload, the cluster's pinned genesis, the
/// account, no recovery-scan source (`PolicyMismatch`), the payload rules (a send missing
/// another required signature is `MissingSignature`) and the mode.
pub(crate) fn approved_tx(
    approved: &Approved,
    mode: SolTxMode,
) -> Result<&SolTxPayload, SolTxSignError> {
    let SigningPayload::SolTx(payload) = approved.payload() else {
        return Err(SolTxSignError::KindMismatch);
    };
    let chain_ok = matches!(
        approved.chain(),
        ChainRef::Solana { cluster, genesis } if genesis == cluster.genesis()
    );
    if approved.kind() != ApprovalKind::SolTransaction
        || approved.account() != AccountRef::Sol(payload.public)
        || !chain_ok
        || payload.mode != mode
    {
        return Err(SolTxSignError::KindMismatch);
    }
    if payload.source.needs_move_rule() {
        return Err(SolTxSignError::PolicyMismatch);
    }
    payload.validate().map_err(|error| match error {
        SolTxPayloadError::MissingSignature => SolTxSignError::MissingSignature,
        _ => SolTxSignError::KindMismatch,
    })?;
    Ok(payload)
}

/// Every approved transaction parsed again, with the slot and site-signature checks: each must
/// parse, carry our key at the approved slot, and every non-zero site signature must verify
/// (a send also needs every other slot signed).
fn checked_wires(payload: &SolTxPayload, send: bool) -> Result<Vec<SolWireTx>, SolTxSignError> {
    payload
        .items
        .iter()
        .map(|item| {
            let wire = parse_wire_tx(&item.wire).map_err(|_| SolTxSignError::EncodingMismatch)?;
            if wire.message.signer_slot(&payload.public) != Ok(item.signer_slot) {
                return Err(SolTxSignError::KindMismatch);
            }
            if !wire.foreign_signatures_ok(item.signer_slot, false) {
                return Err(SolTxSignError::ForeignSignature);
            }
            if send && !wire.foreign_signatures_ok(item.signer_slot, true) {
                return Err(SolTxSignError::MissingSignature);
            }
            Ok(wire)
        })
        .collect()
}

/// Our signature in our slot, nothing else changed: the result parses again with the same
/// message bytes, fits 1,232 bytes and our slot verifies strictly.
fn finish(
    wire: &SolWireTx,
    slot: u8,
    public: &[u8; 32],
    signature: &[u8; 64],
) -> Result<Vec<u8>, SolTxSignError> {
    if !verify_strict(public, &wire.message_bytes, signature) {
        return Err(SolTxSignError::PostSignVerification);
    }
    let tx = wire
        .with_signature(slot, signature)
        .map_err(|_| SolTxSignError::PostSignVerification)?;
    let again = parse_wire_tx(&tx).map_err(|_| SolTxSignError::PostSignVerification)?;
    if tx.len() > SOL_MAX_TX_BYTES
        || again.message_bytes != wire.message_bytes
        || again.slot(usize::from(slot)) != Some(signature)
    {
        return Err(SolTxSignError::PostSignVerification);
    }
    Ok(tx)
}

/// Signs every transaction of an approved sign-only request with the vault key (one key lending
/// for all of them) and returns the signed transactions in request order (spec/07 §20.8). No
/// deadline: like a message signature, the approval is one-shot.
///
/// # Errors
///
/// [`SolTxSignError`]; nothing is returned on error.
#[expect(
    clippy::needless_pass_by_value,
    reason = "the one-time approval token is consumed by signing (spec/03 §11.5)"
)]
pub fn sign_txs(vault: &Vault, approved: Approved) -> Result<Vec<Vec<u8>>, SolTxSignError> {
    let payload = approved_tx(&approved, SolTxMode::SignOnly)?;
    let wires = checked_wires(payload, false)?;
    let sign = |secret: &[u8; 32]| {
        Ok(wires
            .iter()
            .map(|wire| sign_with_seed(secret, &payload.public, &wire.message_bytes))
            .collect::<Result<Vec<[u8; 64]>, SolMessageError>>())
    };
    let signed = if payload.source.is_imported() {
        vault.with_imported_ed25519_seed(&payload.public, sign)
    } else {
        vault.with_ed25519_seed(payload.source, sign)
    };
    let signatures = signed
        .map_err(SolTxSignError::Vault)?
        .map_err(from_message_error)?;
    wires
        .iter()
        .zip(&payload.items)
        .zip(&signatures)
        .map(|((wire, item), signature)| finish(wire, item.signer_slot, &payload.public, signature))
        .collect()
}

/// [`sign_txs`] on a card (spec/10 §6.4): the same checks before the card is asked, then the card
/// signs each approved message (one touch each) and every signature is verified strictly.
///
/// # Errors
///
/// [`SolTxCardError::Sign`] (`KindMismatch` also for a source other than
/// `SolKeySource::Hardware`), [`SolTxCardError::Card`]; nothing is returned on error.
#[expect(
    clippy::needless_pass_by_value,
    reason = "the one-time approval token is consumed by signing (spec/03 §11.5)"
)]
pub fn sign_txs_card(
    approved: Approved,
    card: SolCardSigner<'_>,
) -> Result<Vec<Vec<u8>>, SolTxCardError> {
    let payload = approved_tx(&approved, SolTxMode::SignOnly)?;
    if !payload.source.is_hardware() {
        return Err(SolTxSignError::KindMismatch.into());
    }
    let wires = checked_wires(payload, false)?;
    let mut out = Vec::with_capacity(wires.len());
    for (wire, item) in wires.iter().zip(&payload.items) {
        let signature = card(&wire.message_bytes)?;
        out.push(finish(wire, item.signer_slot, &payload.public, &signature)?);
    }
    Ok(out)
}

/// What the pre-sign RPC check of a send observed (spec/07 §20.10-2): the transaction's own
/// blockhash (`isBlockhashValid(processed)` answered `true` for it) and the addresses its lookup
/// tables resolve to now (`None` for a message without lookups).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreSignCheck {
    /// The blockhash the pre-sign check found valid.
    pub blockhash: [u8; 32],
    /// The lookups re-resolved at pre-sign (`None`: the message has none).
    pub loaded: Option<ResolvedKeys>,
}

/// A signed dApp send, ready for the journal (version 3, spec/07 §14.1) and the broadcast loop.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedSolDappTx {
    /// The fully signed wire transaction (only our slot changed).
    pub tx: Vec<u8>,
    /// Signature 0 (the fee payer's): the transaction id, `SolRecord::signature()`.
    pub tx_id: [u8; 64],
    /// Our signature (in our slot; equal to `tx_id` when the wallet pays the fee).
    pub own_signature: [u8; 64],
    /// `SHA-256(message)`.
    pub message_sha256: [u8; 32],
}

/// The send checks before any key use (spec/07 §20.10-3): the deadline from the pre-sign answer,
/// the approval, the one approved transaction parsed again with every other slot signed and
/// valid, the pre-sign blockhash and the re-resolved tables.
fn approved_send<'a>(
    approved: &'a Approved,
    consumed_at_ms: u64,
    now_ms: u64,
    check: &PreSignCheck,
) -> Result<(&'a SolTxPayload, &'a SolTxItem, SolWireTx), SolTxSignError> {
    let deadline = consumed_at_ms.saturating_add(SOL_SIGN_DEADLINE_SECS.saturating_mul(1_000));
    if now_ms > deadline {
        return Err(SolTxSignError::DeadlineExceeded);
    }
    let payload = approved_tx(approved, SolTxMode::SignAndSend)?;
    let [item] = payload.items.as_slice() else {
        return Err(SolTxSignError::KindMismatch);
    };
    let wire = checked_wires(payload, true)?
        .pop()
        .ok_or(SolTxSignError::KindMismatch)?;
    if wire.message.durable_nonce().is_some() {
        return Err(SolTxSignError::KindMismatch);
    }
    if wire.message.blockhash != check.blockhash {
        return Err(SolTxSignError::EncodingMismatch);
    }
    let same_tables = match (&check.loaded, &item.loaded) {
        (Some(fresh), Some(approved_keys)) => fresh == approved_keys,
        (None, Some(approved_keys)) => {
            wire.message.lookups.is_empty() && *approved_keys == ResolvedKeys::default()
        }
        (_, None) => false,
    };
    if !same_tables {
        return Err(SolTxSignError::TablesChanged);
    }
    Ok((payload, item, wire))
}

/// [`finish`] for a send: every slot of the result is signed and verifies, and signature 0 is
/// the transaction id.
fn finish_send(
    wire: &SolWireTx,
    slot: u8,
    public: &[u8; 32],
    signature: &[u8; 64],
) -> Result<SignedSolDappTx, SolTxSignError> {
    let tx = finish(wire, slot, public, signature)?;
    let signed = parse_wire_tx(&tx).map_err(|_| SolTxSignError::PostSignVerification)?;
    let all_valid = signed
        .signatures
        .iter()
        .zip(&signed.message.static_keys)
        .all(|(slot, key)| verify_strict(key.as_bytes(), &signed.message_bytes, slot));
    let tx_id = *signed.slot(0).ok_or(SolTxSignError::PostSignVerification)?;
    if !all_valid {
        return Err(SolTxSignError::PostSignVerification);
    }
    Ok(SignedSolDappTx {
        tx,
        tx_id,
        own_signature: *signature,
        message_sha256: Sha256::digest(&signed.message_bytes).into(),
    })
}

/// Signs the one transaction of an approved send with the vault key (spec/07 §20.8): the
/// deadline runs from `consumed_at_ms`, which the app sets at the pre-sign answer, and the
/// pre-sign `check` must match what was approved. The blockhash is never changed.
///
/// # Errors
///
/// [`SolTxSignError`]; nothing is returned on error.
pub fn sign_send(
    vault: &Vault,
    approved: &Approved,
    consumed_at_ms: u64,
    now_ms: u64,
    check: &PreSignCheck,
) -> Result<SignedSolDappTx, SolTxSignError> {
    let (payload, item, wire) = approved_send(approved, consumed_at_ms, now_ms, check)?;
    let sign = |secret: &[u8; 32]| Ok(sign_with_seed(secret, &payload.public, &wire.message_bytes));
    let signed = if payload.source.is_imported() {
        vault.with_imported_ed25519_seed(&payload.public, sign)
    } else {
        vault.with_ed25519_seed(payload.source, sign)
    };
    let signature = signed
        .map_err(SolTxSignError::Vault)?
        .map_err(from_message_error)?;
    finish_send(&wire, item.signer_slot, &payload.public, &signature)
}

/// [`sign_send`] on a card (spec/10 §6.4): the same checks before the card is asked (one touch),
/// then the same post-sign verification.
///
/// # Errors
///
/// [`SolTxCardError::Sign`] (`KindMismatch` also for a source other than
/// `SolKeySource::Hardware`), [`SolTxCardError::Card`]; nothing is returned on error.
pub fn sign_send_card(
    approved: &Approved,
    consumed_at_ms: u64,
    now_ms: u64,
    check: &PreSignCheck,
    card: SolCardSigner<'_>,
) -> Result<SignedSolDappTx, SolTxCardError> {
    let (payload, item, wire) = approved_send(approved, consumed_at_ms, now_ms, check)?;
    if !payload.source.is_hardware() {
        return Err(SolTxSignError::KindMismatch.into());
    }
    let signature = card(&wire.message_bytes)?;
    Ok(finish_send(
        &wire,
        item.signer_slot,
        &payload.public,
        &signature,
    )?)
}
