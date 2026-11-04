//! EVM signing and mandatory post-sign verification (spec/03 §4.2–§4.3).
//!
//! Signing ports `archive/spec-v2.4:crates/secret-core/src/signing.rs:14-120,250-279`
//! (`recovery_id ≤ 1`) with `wallet_protocol::AuthorizedOperation` replaced by
//! [`Approved`]; verification ports `archive/spec-v2.4:crates/key-agent/src/lib.rs:325-353,607-797`
//! (re-encode, strict decode, field comparison, sender recovery) as a required step before any
//! journal write. Keys are used only inside `Vault::with_secp_key` and erased afterwards (D10).

use core::fmt;

use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::{All, Message, Secp256k1, SecretKey, Verification};
use sha3::{Digest, Keccak256};

use super::address::Address;
use super::tx::{Eip1559Tx, MAX_SIGNED_TX_BYTES, decode_signed, tx_hash};
use crate::approval::{AccountRef, ApprovalKind, Approved, ChainRef, Signer, SigningPayload};
use crate::error::VaultError;
use crate::vault::{KeyRef, Vault};

/// Signing failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignError {
    /// Kind, payload, signer or chain of the approval do not match the signing function, or the
    /// transaction breaks the spec/03 §3.1 invariants.
    KindMismatch,
    /// The vault refused (locked, backup pending, key missing).
    Vault(VaultError),
    /// The recovery id is not 0 or 1.
    RecoveryId,
    /// Post-sign verification failed: nothing may be stored or sent ("서명 검증 실패(내부 오류)").
    PostSignVerification,
}

impl fmt::Display for SignError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Vault(error) => error.fmt(formatter),
            Self::KindMismatch | Self::RecoveryId => {
                formatter.write_str("내부 오류가 발생했습니다. 로그를 확인하세요.")
            }
            Self::PostSignVerification => formatter.write_str("서명 검증 실패(내부 오류)"),
        }
    }
}

impl std::error::Error for SignError {}

impl From<VaultError> for SignError {
    fn from(error: VaultError) -> Self {
        Self::Vault(error)
    }
}

/// A verified signed transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedTx {
    /// `0x02 ‖ rlp(12 fields)`.
    pub raw: Vec<u8>,
    /// `keccak256(raw)`.
    pub tx_hash: [u8; 32],
    /// The signed transaction fields.
    pub tx: Eip1559Tx,
}

fn keccak(bytes: &[u8]) -> [u8; 32] {
    Keccak256::digest(bytes).into()
}

/// EIP-191 version 0x45 prefix of a `personal_sign` preimage.
const PERSONAL_PREFIX: &[u8] = b"\x19Ethereum Signed Message:\n";
/// EIP-712 prefix of a typed-data preimage.
const TYPED_PREFIX: [u8; 2] = [0x19, 0x01];

/// Whether `preimage` is exactly `0x19 ‖ "Ethereum Signed Message:\n" ‖ decimal(len) ‖ message`
/// for some message of at most [`super::eip191::MAX_PERSONAL_MESSAGE`] bytes (the form built by
/// [`super::eip191::personal_preimage`]): the decimal length has no leading zero and equals the
/// number of bytes after it. Anything else — a raw 32-byte digest, a transaction or a typed-data
/// preimage presented as a message — is refused before it can be signed.
#[must_use]
pub fn is_personal_preimage(preimage: &[u8]) -> bool {
    let Some(rest) = preimage.strip_prefix(PERSONAL_PREFIX) else {
        return false;
    };
    let max_digits = super::eip191::MAX_PERSONAL_MESSAGE.to_string().len();
    (1..=max_digits).any(|digits| {
        let Some((length, message)) = rest.split_at_checked(digits) else {
            return false;
        };
        message.len() <= super::eip191::MAX_PERSONAL_MESSAGE
            && message.len().to_string().as_bytes() == length
    })
}

/// Whether `preimage` is an EIP-712 preimage `0x19 ‖ 0x01 ‖ domainSeparator ‖ hashStruct`.
#[must_use]
pub fn is_typed_data_preimage(preimage: &[u8; 66]) -> bool {
    preimage.starts_with(&TYPED_PREFIX)
}

/// RFC 6979 recoverable signature of a 32-byte digest: `(y_parity, r ‖ s)` (low-s).
pub(crate) fn sign_digest(
    ctx: &Secp256k1<All>,
    secret: &SecretKey,
    digest: [u8; 32],
) -> Result<(u8, [u8; 64]), SignError> {
    let signature = ctx.sign_ecdsa_recoverable(Message::from_digest(digest), secret);
    let (recovery, compact) = signature.serialize_compact();
    match i32::from(recovery) {
        0 => Ok((0, compact)),
        1 => Ok((1, compact)),
        _ => Err(SignError::RecoveryId),
    }
}

fn recover_with<C: Verification>(
    ctx: &Secp256k1<C>,
    digest: [u8; 32],
    y_parity: u8,
    compact: &[u8; 64],
) -> Option<Address> {
    let recovery = RecoveryId::try_from(i32::from(y_parity)).ok()?;
    if y_parity > 1 {
        return None;
    }
    let signature = RecoverableSignature::from_compact(compact, recovery).ok()?;
    let public = ctx
        .recover_ecdsa(Message::from_digest(digest), &signature)
        .ok()?;
    Some(Address::from_public_key(&public))
}

/// Recovers the signer address of `digest` from `y_parity` and `r ‖ s`.
#[must_use]
pub fn recover_address(digest: [u8; 32], y_parity: u8, compact: &[u8; 64]) -> Option<Address> {
    recover_with(&Secp256k1::verification_only(), digest, y_parity, compact)
}

/// Recovers the signer of a 65-byte `r ‖ s ‖ v` message signature (`v` ∈ {27, 28}).
#[must_use]
pub fn recover_message_signer(digest: [u8; 32], signature: &[u8; 65]) -> Option<Address> {
    let (compact, v) = signature.split_first_chunk::<64>()?;
    let y_parity = v.first()?.checked_sub(27)?;
    recover_address(digest, y_parity, compact)
}

fn scalars(compact: &[u8; 64]) -> ([u8; 32], [u8; 32]) {
    let mut r = [0_u8; 32];
    let mut s = [0_u8; 32];
    let (left, right) = compact.split_at(32);
    r.copy_from_slice(left);
    s.copy_from_slice(right);
    (r, s)
}

/// Post-sign verification of a signed transaction (spec/03 §4.3 steps 1–6).
pub(crate) fn verify_signed_tx<C: Verification>(
    ctx: &Secp256k1<C>,
    approved_tx: &Eip1559Tx,
    signed_hash: [u8; 32],
    raw: &[u8],
    account: &Address,
) -> Result<[u8; 32], SignError> {
    let failure = SignError::PostSignVerification;
    if keccak(&approved_tx.signing_preimage()) != signed_hash {
        return Err(failure);
    }
    if raw.len() > MAX_SIGNED_TX_BYTES {
        return Err(failure);
    }
    let decoded = decode_signed(raw).map_err(|_| failure)?;
    if decoded.tx != *approved_tx {
        return Err(failure);
    }
    let mut compact = [0_u8; 64];
    let (r, s) = compact.split_at_mut(32);
    r.copy_from_slice(&decoded.r);
    s.copy_from_slice(&decoded.s);
    if recover_with(ctx, signed_hash, decoded.y_parity, &compact) != Some(*account) {
        return Err(failure);
    }
    Ok(tx_hash(raw))
}

/// Signs and verifies a transaction with a lent key.
pub(crate) fn sign_tx_with(
    ctx: &Secp256k1<All>,
    secret: &SecretKey,
    tx: &Eip1559Tx,
    account: &Address,
) -> Result<SignedTx, SignError> {
    let hash = keccak(&tx.signing_preimage());
    let (y_parity, compact) = sign_digest(ctx, secret, hash)?;
    let (r, s) = scalars(&compact);
    let raw = tx.encode_signed(y_parity, &r, &s);
    let tx_hash = verify_signed_tx(ctx, tx, hash, &raw, account)?;
    Ok(SignedTx {
        raw,
        tx_hash,
        tx: tx.clone(),
    })
}

/// Signs a message digest and checks the recovered signer (`r ‖ s ‖ v`, `v = 27 + recid`).
pub(crate) fn sign_message_with(
    ctx: &Secp256k1<All>,
    secret: &SecretKey,
    digest: [u8; 32],
    account: &Address,
) -> Result<[u8; 65], SignError> {
    let (y_parity, compact) = sign_digest(ctx, secret, digest)?;
    if recover_with(ctx, digest, y_parity, &compact) != Some(*account) {
        return Err(SignError::PostSignVerification);
    }
    let mut out = [0_u8; 65];
    let (body, v) = out.split_at_mut(64);
    body.copy_from_slice(&compact);
    if let Some(slot) = v.first_mut() {
        *slot = y_parity.checked_add(27).ok_or(SignError::RecoveryId)?;
    }
    Ok(out)
}

fn evm_parts(approved: &Approved) -> Result<(Address, crate::vault::EvmKeySource), SignError> {
    match (approved.account(), approved.signer()) {
        (AccountRef::Evm(account), Signer::Evm(source)) => Ok((account, source)),
        _ => Err(SignError::KindMismatch),
    }
}

fn with_key<T>(
    vault: &Vault,
    approved: &Approved,
    f: impl FnOnce(&Secp256k1<All>, &SecretKey, &Address) -> Result<T, SignError>,
) -> Result<T, SignError> {
    let (account, source) = evm_parts(approved)?;
    vault
        .with_secp_key(KeyRef::Evm(source), |ctx, secret| {
            Ok(f(ctx, secret, &account))
        })
        .map_err(SignError::Vault)?
}

/// Signs an approved EVM transaction (kinds 0x10–0x12), verifying it before returning.
///
/// # Errors
///
/// [`SignError::KindMismatch`], [`SignError::Vault`], [`SignError::PostSignVerification`].
#[expect(
    clippy::needless_pass_by_value,
    reason = "the one-time approval token is consumed by signing (spec/03 §11.5)"
)]
pub fn sign_transaction(vault: &Vault, approved: Approved) -> Result<SignedTx, SignError> {
    let SigningPayload::EvmTx(tx) = approved.payload() else {
        return Err(SignError::KindMismatch);
    };
    let ChainRef::Evm { chain_id, .. } = approved.chain() else {
        return Err(SignError::KindMismatch);
    };
    if !approved.kind().is_evm_transaction() || tx.chain_id != chain_id || tx.validate().is_err() {
        return Err(SignError::KindMismatch);
    }
    with_key(vault, &approved, |ctx, secret, account| {
        sign_tx_with(ctx, secret, tx, account)
    })
}

/// Signs an approved `personal_sign` (kind 0x13): the payload is the EIP-191 preimage.
///
/// # Errors
///
/// [`SignError::KindMismatch`] (also for a payload that is not an exact EIP-191 preimage,
/// [`is_personal_preimage`]), [`SignError::Vault`], [`SignError::PostSignVerification`].
#[expect(
    clippy::needless_pass_by_value,
    reason = "the one-time approval token is consumed by signing (spec/03 §11.5)"
)]
pub fn sign_personal(vault: &Vault, approved: Approved) -> Result<[u8; 65], SignError> {
    let SigningPayload::EvmPersonal(preimage) = approved.payload() else {
        return Err(SignError::KindMismatch);
    };
    if approved.kind() != ApprovalKind::EvmPersonalSign || !is_personal_preimage(preimage) {
        return Err(SignError::KindMismatch);
    }
    let digest = keccak(preimage);
    with_key(vault, &approved, |ctx, secret, account| {
        sign_message_with(ctx, secret, digest, account)
    })
}

/// Signs an approved typed-data request (kind 0x14): the payload is the 66-byte preimage.
///
/// # Errors
///
/// [`SignError::KindMismatch`] (also without the `0x19 0x01` prefix,
/// [`is_typed_data_preimage`]), [`SignError::Vault`], [`SignError::PostSignVerification`].
#[expect(
    clippy::needless_pass_by_value,
    reason = "the one-time approval token is consumed by signing (spec/03 §11.5)"
)]
pub fn sign_typed_data(vault: &Vault, approved: Approved) -> Result<[u8; 65], SignError> {
    let SigningPayload::EvmTypedData(preimage) = approved.payload() else {
        return Err(SignError::KindMismatch);
    };
    if approved.kind() != ApprovalKind::EvmTypedData || !is_typed_data_preimage(preimage) {
        return Err(SignError::KindMismatch);
    }
    let digest = keccak(preimage);
    with_key(vault, &approved, |ctx, secret, account| {
        sign_message_with(ctx, secret, digest, account)
    })
}

/// Failure of a card (`YubiKey`) signature (spec/10 §6.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CardSignError {
    /// The approval or the post-sign verification failed (as for vault signing).
    Sign(SignError),
    /// The card operation failed.
    Card(crate::yubikey::CardError),
}

impl fmt::Display for CardSignError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sign(error) => error.fmt(formatter),
            Self::Card(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for CardSignError {}

impl From<SignError> for CardSignError {
    fn from(error: SignError) -> Self {
        Self::Sign(error)
    }
}

impl From<crate::yubikey::CardError> for CardSignError {
    fn from(error: crate::yubikey::CardError) -> Self {
        Self::Card(error)
    }
}

/// The card signs a 32-byte digest and returns `(y_parity, r ‖ s)` (low-s, recovered against the
/// recorded key: `yubikey::sign::sign_evm`).
pub type CardDigestSigner<'a> =
    &'a mut dyn FnMut([u8; 32]) -> Result<(u8, [u8; 64]), crate::yubikey::CardError>;

fn card_account(approved: &Approved) -> Result<Address, SignError> {
    match (approved.account(), approved.signer()) {
        (AccountRef::Evm(account), Signer::Hardware(crate::yubikey::plan::KeyRole::Evm { .. })) => {
            Ok(account)
        }
        _ => Err(SignError::KindMismatch),
    }
}

/// Signs an approved EVM transaction on a card (spec/10 §6.2): same checks as
/// [`sign_transaction`], the card signs the signing hash, then the full post-sign verification
/// (re-encode, strict decode, field comparison, sender = approved account).
///
/// # Errors
///
/// [`CardSignError::Sign`] (`KindMismatch`, `PostSignVerification`), [`CardSignError::Card`].
#[expect(
    clippy::needless_pass_by_value,
    reason = "the one-time approval token is consumed by signing (spec/03 §11.5)"
)]
pub fn sign_transaction_card(
    approved: Approved,
    card: CardDigestSigner<'_>,
) -> Result<SignedTx, CardSignError> {
    let SigningPayload::EvmTx(tx) = approved.payload() else {
        return Err(SignError::KindMismatch.into());
    };
    let ChainRef::Evm { chain_id, .. } = approved.chain() else {
        return Err(SignError::KindMismatch.into());
    };
    if !approved.kind().is_evm_transaction() || tx.chain_id != chain_id || tx.validate().is_err() {
        return Err(SignError::KindMismatch.into());
    }
    let account = card_account(&approved)?;
    let hash = keccak(&tx.signing_preimage());
    let (y_parity, compact) = card(hash)?;
    let (r, s) = scalars(&compact);
    let raw = tx.encode_signed(y_parity, &r, &s);
    let tx_hash = verify_signed_tx(&Secp256k1::verification_only(), tx, hash, &raw, &account)?;
    Ok(SignedTx {
        raw,
        tx_hash,
        tx: tx.clone(),
    })
}

fn card_message(
    approved: &Approved,
    digest: [u8; 32],
    card: CardDigestSigner<'_>,
) -> Result<[u8; 65], CardSignError> {
    let account = card_account(approved)?;
    let (y_parity, compact) = card(digest)?;
    if recover_address(digest, y_parity, &compact) != Some(account) {
        return Err(SignError::PostSignVerification.into());
    }
    let mut out = [0_u8; 65];
    let (body, v) = out.split_at_mut(64);
    body.copy_from_slice(&compact);
    if let Some(slot) = v.first_mut() {
        *slot = y_parity.checked_add(27).ok_or(SignError::RecoveryId)?;
    }
    Ok(out)
}

/// [`sign_personal`] on a card.
///
/// # Errors
///
/// As [`sign_transaction_card`].
#[expect(
    clippy::needless_pass_by_value,
    reason = "the one-time approval token is consumed by signing (spec/03 §11.5)"
)]
pub fn sign_personal_card(
    approved: Approved,
    card: CardDigestSigner<'_>,
) -> Result<[u8; 65], CardSignError> {
    let SigningPayload::EvmPersonal(preimage) = approved.payload() else {
        return Err(SignError::KindMismatch.into());
    };
    if approved.kind() != ApprovalKind::EvmPersonalSign || !is_personal_preimage(preimage) {
        return Err(SignError::KindMismatch.into());
    }
    card_message(&approved, keccak(preimage), card)
}

/// [`sign_typed_data`] on a card.
///
/// # Errors
///
/// As [`sign_transaction_card`].
#[expect(
    clippy::needless_pass_by_value,
    reason = "the one-time approval token is consumed by signing (spec/03 §11.5)"
)]
pub fn sign_typed_data_card(
    approved: Approved,
    card: CardDigestSigner<'_>,
) -> Result<[u8; 65], CardSignError> {
    let SigningPayload::EvmTypedData(preimage) = approved.payload() else {
        return Err(SignError::KindMismatch.into());
    };
    if approved.kind() != ApprovalKind::EvmTypedData || !is_typed_data_preimage(preimage) {
        return Err(SignError::KindMismatch.into());
    }
    card_message(&approved, keccak(preimage), card)
}

#[cfg(test)]
mod tests;
