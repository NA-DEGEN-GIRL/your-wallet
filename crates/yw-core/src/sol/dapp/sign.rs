//! Signing approved dApp transactions (spec/07 §20.5, §20.10-3): the signer parses the
//! **approved** bytes again (never the site's copy), checks the kind, chain, account, key source
//! and every site signature, fills only its own slot and verifies the result. The blockhash is
//! never changed. A software key signs every message of the request in one key lending; a
//! `YubiKey` signs each message on the card (one touch per transaction).
#![deny(clippy::indexing_slicing)]

use core::fmt;

use super::parse::{SolWireTx, parse_wire_tx};
use super::{SolTxMode, SolTxPayload};
use crate::approval::{AccountRef, ApprovalKind, Approved, ChainRef, SigningPayload};
use crate::error::VaultError;
use crate::sol::keys::verify_strict;
use crate::sol::msgsign::{SolMessageError, sign_with_seed};
use crate::sol::sign::SolCardSigner;
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

impl fmt::Display for SolTxSignError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeadlineExceeded => {
                formatter.write_str("승인 후 서명까지 시간이 너무 오래 걸려 서명하지 않았습니다")
            }
            Self::TablesChanged => {
                formatter.write_str("조회 테이블 주소가 승인한 값과 달라 서명하지 않았습니다")
            }
            Self::ForeignSignature | Self::MissingSignature => {
                formatter.write_str("사이트가 넣은 서명이 맞지 않아 서명하지 않았습니다")
            }
            Self::Vault(error) => error.fmt(formatter),
            Self::KindMismatch
            | Self::EncodingMismatch
            | Self::KeyMismatch
            | Self::PolicyMismatch => {
                formatter.write_str("내부 검증에 실패해 서명하지 않았습니다.")
            }
            Self::PostSignVerification => formatter.write_str("서명하지 못했습니다(내부 오류)"),
        }
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
/// account, no recovery-scan source (`PolicyMismatch`), the payload rules and the mode.
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
    payload
        .validate()
        .map_err(|_| SolTxSignError::KindMismatch)?;
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
