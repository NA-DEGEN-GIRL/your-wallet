//! Signing of an approved plan for every account type (spec/08 §6.7, §11.1–§11.2).
//!
//! ECDSA ([`sign_sighash`]) runs inside the key lending closure (the context and key it lends):
//! RFC 6979 `sign_ecdsa_low_r`, immediate `verify_ecdsa`, then the same strict check the
//! post-sign verification applies, returning the signature item `DER ‖ 0x01`.
//! [`check_witness_signature`] is that strict check for a witness: strict DER
//! (`Signature::from_der`) whose `serialize_der` round trip is identical, at most 70 DER bytes
//! with `r < 2^255` (low-R), low-S (`normalize_s` changes nothing), suffix `SIGHASH_ALL`, a
//! 33-byte `02`/`03` public key, and a valid signature over the sighash.
//! [`check_p2pkh_signature`] is the same with a 33- or 65-byte key (legacy scriptSig). Taproot
//! inputs are signed with `taproot::sign_key_path` (BIP340 with OS auxiliary randomness, verified
//! at once against the output key).
//!
//! [`sign_plan`] (spec/08 §11.1) checks that the one-time `Approved` token is for exactly this
//! plan (kind, chain, account and the `btc_payload` bytes), then signs one input at a time
//! through the crate-internal `BtcKeys`: derived keys (and the EVM key `m/44'/60'/0'/0/i` of an
//! account on an EVM account's key) come from `Vault::with_secp_key`, imported
//! single keys from `BtcImportedKeys::btc_imported_secret` (vault tag 4, wrapped in the
//! crate-internal `ImportedBtcSecret` that is erased on drop). Both are lent to the signing
//! closure only; nothing outside yw-core can reach a lent secret. Before signing, the public key
//! computed from the lent secret must be the account's key of that input (else `KeyMismatch`);
//! the private key never leaves the closure.
//!
//! | type | sighash | scriptSig | witness |
//! |---|---|---|---|
//! | P2PKH | legacy, `SIGHASH_ALL` | `<DER‖01> <K>` | — |
//! | P2SH-P2WPKH | BIP143, `SIGHASH_ALL` | `16 00 14 <HASH160(K)>` (in the plan) | `[DER‖01, K]` |
//! | P2WPKH | BIP143, `SIGHASH_ALL` | — | `[DER‖01, K]` |
//! | P2TR | BIP341 key path, `SIGHASH_DEFAULT` | — | `[schnorr64]` |
//!
//! A `YubiKey` account (`BtcAccountKey::Hardware`) has no key in the vault: [`sign_plan`]
//! refuses it (`Vault(RecordNotFound)`) and [`sign_plan_card`] signs each input on the card
//! (spec/10 §6.3) with the relaxed card rules [`check_card_signature`] (high-R allowed, DER ≤ 72).
#![deny(clippy::indexing_slicing)]

use core::fmt;

use secp256k1::ecdsa::Signature;
use secp256k1::{All, Message, PublicKey, Secp256k1, SecretKey, Verification};

use super::SIGHASH_ALL;
use super::account::{BtcAccountKey, BtcKeySource, BtcPubKey, ScriptType};
use super::address::{ScriptKind, hash160, script_pubkey};
use super::amount::Sats;
use super::display::btc_payload;
use super::network::BtcNetwork;
use super::policy::texts;
use super::script::p2pkh_script_sig;
use super::select::SendPlan;
use super::sighash::{bip143_sighash_p2wpkh, legacy_sighash};
use super::taproot::{Prevout, TaprootSigError, sighash_default, sign_key_path};
use super::tx::{OutPoint, serialize};
use super::verify::{PostSignError, verify_signed};
use crate::approval::{AccountRef, ApprovalId, Approved, ChainRef, Signer, SigningPayload};
use crate::bip32::path::AccountIndex;
use crate::entropy::{OsRandom, fill_random, secp_context};
use crate::error::VaultError;
use crate::vault::{EvmKeySource, KeyRef, Vault};
use crate::yubikey::CardError;

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
    /// The key item is not a 33-byte `02`/`03` point on the curve (or, for P2PKH, a 65-byte
    /// `04` point).
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

/// The strict rules on a signature item `DER ‖ 0x01` for `public`, then verification.
fn check_signature_item_with<C: Verification>(
    ctx: &Secp256k1<C>,
    sig_item: &[u8],
    public: &PublicKey,
    sighash: &[u8; 32],
) -> Result<(), WitnessSigError> {
    let signature = check_signature_shape(sig_item)?;
    ctx.verify_ecdsa(Message::from_digest(*sighash), &signature, public)
        .map_err(|_| WitnessSigError::VerifyFailed)
}

/// [`check_witness_signature`] with a caller's context: the signature rules first, then the key
/// rules, then verification.
pub(crate) fn check_witness_signature_with<C: Verification>(
    ctx: &Secp256k1<C>,
    sig_item: &[u8],
    pubkey_item: &[u8],
    sighash: &[u8; 32],
) -> Result<(), WitnessSigError> {
    let signature = check_signature_shape(sig_item)?;
    let key = <[u8; PUBKEY_LEN]>::try_from(pubkey_item).map_err(|_| WitnessSigError::PublicKey)?;
    if !matches!(key.first(), Some(0x02 | 0x03)) {
        return Err(WitnessSigError::PublicKey);
    }
    let public =
        PublicKey::from_byte_array_compressed(key).map_err(|_| WitnessSigError::PublicKey)?;
    ctx.verify_ecdsa(Message::from_digest(*sighash), &signature, &public)
        .map_err(|_| WitnessSigError::VerifyFailed)
}

/// The signature-only rules (type byte, DER shape, low-R, low-S), without verification.
fn check_signature_shape(sig_item: &[u8]) -> Result<Signature, WitnessSigError> {
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
    Ok(signature)
}

/// Strict check of a P2WPKH / P2SH-P2WPKH witness `[sig_item, pubkey_item]` against `sighash`
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

/// [`check_p2pkh_signature`] with a caller's context.
pub(crate) fn check_p2pkh_signature_with<C: Verification>(
    ctx: &Secp256k1<C>,
    sig_item: &[u8],
    pubkey_item: &[u8],
    sighash: &[u8; 32],
) -> Result<(), WitnessSigError> {
    let signature = check_signature_shape(sig_item)?;
    let key = BtcPubKey::parse(pubkey_item).map_err(|_| WitnessSigError::PublicKey)?;
    let public = PublicKey::from_slice(key.as_bytes()).map_err(|_| WitnessSigError::PublicKey)?;
    ctx.verify_ecdsa(Message::from_digest(*sighash), &signature, &public)
        .map_err(|_| WitnessSigError::VerifyFailed)
}

/// Strict check of a P2PKH scriptSig's `<sig_item> <pubkey_item>` against the legacy `sighash`:
/// the witness rules with a 33-byte `02`/`03` or 65-byte `04` key.
///
/// # Errors
///
/// The first failing rule's [`WitnessSigError`].
pub fn check_p2pkh_signature(
    sig_item: &[u8],
    pubkey_item: &[u8],
    sighash: &[u8; 32],
) -> Result<(), WitnessSigError> {
    let ctx = secp_context(&mut OsRandom).map_err(|_| WitnessSigError::RandomnessUnavailable)?;
    check_p2pkh_signature_with(&ctx, sig_item, pubkey_item, sighash)
}

/// Signs `sighash` with `secret` (low-R RFC 6979), verifies at once and returns the signature
/// item `DER ‖ 0x01` (≤ 71 bytes). Called only inside the key lending closure.
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
    check_signature_item_with(ctx, &item, &public, sighash)?;
    Ok(item)
}

/// Signing failure: nothing signed is returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignError {
    /// The approval is not for this plan (kind, chain, account, signer or payload bytes).
    ApprovalMismatch,
    /// The plan's inputs do not match its transaction.
    PlanInconsistent,
    /// The key of input `input` does not give the account's key or output for that input
    /// (spec/08 §3.1 `KeyMismatch`; also an imported key whose network, type or compression
    /// differs from the account).
    KeyMismatch {
        /// Input index.
        input: usize,
    },
    /// A plan amount differs from a recorded verified amount (spec/08 §5
    /// `AmountRecordMismatch`: a bug or tampering signal).
    AmountRecordMismatch,
    /// A plan input has no record at all (spec/08 §5): typically a refresh during the approval
    /// dropped it from `verified` (spent, or no longer listed). Same hard stop, own text.
    InputNotRecorded,
    /// Key derivation from the account node failed.
    Derivation,
    /// The fresh ECDSA signature failed its own strict check.
    Witness(WitnessSigError),
    /// The fresh Schnorr signature failed its own check.
    Taproot(TaprootSigError),
    /// The OS CSPRNG failed (BIP340 auxiliary randomness).
    Randomness,
    /// The vault refused (locked, backup pending, derivation, an imported key's record is gone:
    /// `RecordNotFound`).
    Vault(VaultError),
}

impl fmt::Display for SignError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Vault(error) => error.fmt(formatter),
            Self::ApprovalMismatch => formatter.write_str(texts::APPROVAL_MISMATCH),
            Self::KeyMismatch { .. } => formatter.write_str(texts::KEY_MISMATCH),
            Self::AmountRecordMismatch => formatter.write_str(texts::AMOUNT_RECORD_MISMATCH),
            Self::InputNotRecorded => formatter.write_str(texts::INPUT_NOT_RECORDED),
            Self::PlanInconsistent
            | Self::Derivation
            | Self::Witness(_)
            | Self::Taproot(_)
            | Self::Randomness => formatter.write_str(texts::SIGN_INTERNAL),
        }
    }
}

impl std::error::Error for SignError {}

/// The secret of an imported single key as the vault lends it to [`sign_plan`]
/// (crate-internal, not `Clone`, `Debug` redacted, erased on drop).
pub(crate) struct ImportedBtcSecret {
    secret: SecretKey,
    compressed: bool,
    network: BtcNetwork,
    script_type: ScriptType,
}

impl ImportedBtcSecret {
    /// Wraps a decrypted imported key record (vault tag 4): the secret, its compression flag,
    /// network and address type.
    #[must_use]
    pub(crate) const fn new(
        secret: SecretKey,
        compressed: bool,
        network: BtcNetwork,
        script_type: ScriptType,
    ) -> Self {
        Self {
            secret,
            compressed,
            network,
            script_type,
        }
    }
}

impl Drop for ImportedBtcSecret {
    fn drop(&mut self) {
        self.secret.non_secure_erase();
    }
}

impl fmt::Debug for ImportedBtcSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ImportedBtcSecret([REDACTED])")
    }
}

/// Access to imported single BTC keys (vault tag 4, spec/02 §8.4): crate-internal, used only by
/// `BtcKeys for Vault` inside [`sign_plan`].
pub(crate) trait BtcImportedKeys {
    /// The secret of imported key `id` with its record's network, address type and compression.
    ///
    /// # Errors
    ///
    /// [`SignError::Vault`]: locked or backup pending (`InvalidState` / `BackupNotConfirmed`),
    /// no tag-4 record `id` (`RecordNotFound`).
    fn btc_imported_secret(&self, id: &[u8; 16]) -> Result<ImportedBtcSecret, SignError>;
}

impl BtcImportedKeys for Vault {
    fn btc_imported_secret(&self, id: &[u8; 16]) -> Result<ImportedBtcSecret, SignError> {
        self.imported_btc_secret(id).map_err(SignError::Vault)
    }
}

/// Lends BTC signing keys to [`sign_plan`] (crate-internal: a lent secret never reaches code
/// outside yw-core).
pub(crate) trait BtcKeys {
    /// Lends the secret key of `source` on `network` to `f` and erases it afterwards. An imported
    /// key must belong to `network` and `script_type` with the given compression (else
    /// `KeyMismatch { input }`).
    ///
    /// # Errors
    ///
    /// [`SignError`] from the vault, the checks or `f`.
    fn with_btc_key<T>(
        &self,
        network: BtcNetwork,
        source: BtcKeySource,
        input: usize,
        f: impl FnOnce(&Secp256k1<All>, &SecretKey) -> Result<T, SignError>,
    ) -> Result<T, SignError>;

    /// 32 bytes of BIP340 auxiliary randomness (OS CSPRNG).
    ///
    /// # Errors
    ///
    /// [`SignError::Randomness`].
    fn aux_rand(&self) -> Result<[u8; 32], SignError> {
        let mut aux = [0_u8; 32];
        fill_random(&mut aux).map_err(|_| SignError::Randomness)?;
        Ok(aux)
    }
}

/// [`BtcKeys::with_btc_key`] for an imported secret: network, type and compression must match
/// the account.
fn lend_imported<T>(
    secret: &ImportedBtcSecret,
    network: BtcNetwork,
    (script_type, compressed): (ScriptType, bool),
    input: usize,
    f: impl FnOnce(&Secp256k1<All>, &SecretKey) -> Result<T, SignError>,
) -> Result<T, SignError> {
    if secret.network != network
        || secret.script_type != script_type
        || secret.compressed != compressed
    {
        return Err(SignError::KeyMismatch { input });
    }
    let ctx = secp_context(&mut OsRandom).map_err(|_| SignError::Randomness)?;
    f(&ctx, &secret.secret)
}

impl BtcKeys for Vault {
    fn with_btc_key<T>(
        &self,
        network: BtcNetwork,
        source: BtcKeySource,
        input: usize,
        f: impl FnOnce(&Secp256k1<All>, &SecretKey) -> Result<T, SignError>,
    ) -> Result<T, SignError> {
        match source {
            BtcKeySource::Derived { chain, index, .. } => {
                let coin = source.coin(network).ok_or(SignError::Derivation)?;
                self.with_secp_key(KeyRef::Btc { coin, chain, index }, |ctx, secret| {
                    Ok(f(ctx, secret))
                })
                .map_err(SignError::Vault)?
            }
            BtcKeySource::Imported {
                id,
                script_type,
                compressed,
            } => {
                let secret = self.btc_imported_secret(&id)?;
                lend_imported(&secret, network, (script_type, compressed), input, f)
            }
            BtcKeySource::EvmShared { evm_index, .. } => {
                // `m/44'/60'/0'/0/i` on every BTC network; the caller checks the public key.
                let index = AccountIndex::new(evm_index).map_err(|_| SignError::Derivation)?;
                self.with_secp_key(KeyRef::Evm(EvmKeySource::Derived(index)), |ctx, secret| {
                    Ok(f(ctx, secret))
                })
                .map_err(SignError::Vault)?
            }
            // A YubiKey account has no key on the PC (spec/10 §1): `sign_plan_card` signs it.
            BtcKeySource::Hardware { .. } => Err(SignError::Vault(VaultError::RecordNotFound)),
        }
    }
}

/// A secret-key provider for tests and tools: derived keys from a BIP39 seed, imported keys from
/// a list, fixed auxiliary randomness.
#[cfg(test)]
pub(crate) struct SeedKeys {
    pub(crate) seed: [u8; 64],
    pub(crate) imported: Vec<([u8; 16], ImportedBtcSecret)>,
    pub(crate) aux: [u8; 32],
}

#[cfg(test)]
impl SeedKeys {
    pub(crate) fn add_imported(
        &mut self,
        id: [u8; 16],
        secret: SecretKey,
        compressed: bool,
        network: BtcNetwork,
        script_type: ScriptType,
    ) {
        self.imported.push((
            id,
            ImportedBtcSecret::new(secret, compressed, network, script_type),
        ));
    }
}

#[cfg(test)]
impl BtcKeys for SeedKeys {
    fn with_btc_key<T>(
        &self,
        network: BtcNetwork,
        source: BtcKeySource,
        input: usize,
        f: impl FnOnce(&Secp256k1<All>, &SecretKey) -> Result<T, SignError>,
    ) -> Result<T, SignError> {
        match source {
            BtcKeySource::Derived { chain, index, .. } => {
                let coin = source.coin(network).ok_or(SignError::Derivation)?;
                let path = crate::bip32::path::btc_path(coin, chain, index)
                    .map_err(|_| SignError::Derivation)?;
                let ctx = secp_context(&mut OsRandom).map_err(|_| SignError::Randomness)?;
                let mut secret = crate::bip32::secret_key_from_seed(&ctx, &self.seed, &path)
                    .map_err(|_| SignError::Derivation)?;
                let result = f(&ctx, &secret);
                secret.non_secure_erase();
                result
            }
            BtcKeySource::Imported {
                id,
                script_type,
                compressed,
            } => {
                let (_, secret) = self
                    .imported
                    .iter()
                    .find(|(known, _)| *known == id)
                    .ok_or(SignError::Vault(VaultError::RecordNotFound))?;
                lend_imported(secret, network, (script_type, compressed), input, f)
            }
            BtcKeySource::EvmShared { evm_index, .. } => {
                let index = AccountIndex::new(evm_index).map_err(|_| SignError::Derivation)?;
                let path = crate::bip32::path::evm_path(index);
                let ctx = secp_context(&mut OsRandom).map_err(|_| SignError::Randomness)?;
                let mut secret = crate::bip32::secret_key_from_seed(&ctx, &self.seed, &path)
                    .map_err(|_| SignError::Derivation)?;
                let result = f(&ctx, &secret);
                secret.non_secure_erase();
                result
            }
            BtcKeySource::Hardware { .. } => Err(SignError::Vault(VaultError::RecordNotFound)),
        }
    }

    fn aux_rand(&self) -> Result<[u8; 32], SignError> {
        Ok(self.aux)
    }
}

/// A freshly signed transaction. It must pass `verify::verify_signed` before it is journaled
/// or sent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedTx {
    /// Signed bytes (with witnesses for segwit and Taproot accounts).
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
            return Err(SignError::InputNotRecorded);
        }
    }
    Ok(())
}

fn approval_matches(approved: &Approved, plan: &SendPlan, account: &BtcAccountKey) -> bool {
    let network = plan.network();
    plan.account() == account
        && approved.kind() == plan.kind()
        && approved.signer() == Signer::FromPayload
        && approved.chain()
            == (ChainRef::Bitcoin {
                network: network.id(),
                genesis: network.genesis(),
            })
        && approved.account() == AccountRef::Bitcoin(account.identity())
        && matches!(approved.payload(), SigningPayload::Btc(bytes) if *bytes == btc_payload(plan))
}

/// The plan's inputs are its transaction's inputs (same outpoints, no witness, the unsigned
/// scriptSig of each input's path).
fn check_plan_consistent(plan: &SendPlan, account: &BtcAccountKey) -> Result<(), SignError> {
    let unsigned = plan.tx();
    let inputs = plan.inputs();
    let deriver = account.deriver().map_err(|_| SignError::Derivation)?;
    if inputs.len() != unsigned.inputs.len()
        || inputs.iter().zip(&unsigned.inputs).any(|(planned, input)| {
            planned.outpoint != input.prevout
                || !input.witness.is_empty()
                || deriver
                    .unsigned_script_sig(planned.chain, planned.index)
                    .map_or(true, |script| script != input.script_sig)
        })
    {
        return Err(SignError::PlanInconsistent);
    }
    Ok(())
}

/// The public key and our output of every plan input (derived from the account's public data).
pub(crate) fn expected_inputs(
    plan: &SendPlan,
    account: &BtcAccountKey,
) -> Result<Vec<(BtcPubKey, ScriptKind)>, SignError> {
    let deriver = account.deriver().map_err(|_| SignError::Derivation)?;
    plan.inputs()
        .iter()
        .map(|input| {
            let key = deriver
                .pubkey(input.chain, input.index)
                .map_err(|_| SignError::Derivation)?;
            let kind = deriver
                .kind(input.chain, input.index)
                .map_err(|_| SignError::Derivation)?;
            Ok((key, kind))
        })
        .collect()
}

/// The BIP341 prevouts of a plan: every input's verified value and our scriptPubKey.
pub(crate) fn plan_prevouts(plan: &SendPlan, expected: &[(BtcPubKey, ScriptKind)]) -> Vec<Prevout> {
    plan.inputs()
        .iter()
        .zip(expected)
        .map(|(input, (_, kind))| Prevout {
            value: input.value,
            script_pubkey: script_pubkey(kind),
        })
        .collect()
}

/// The ECDSA public key the lent secret must give for `expected` (same point and compression).
fn check_lent_key(
    ctx: &Secp256k1<All>,
    secret: &SecretKey,
    expected: &BtcPubKey,
    input: usize,
) -> Result<(), SignError> {
    let public = PublicKey::from_secret_key(ctx, secret);
    if BtcPubKey::of_point(&public, expected.is_compressed()) == *expected {
        Ok(())
    } else {
        Err(SignError::KeyMismatch { input })
    }
}

/// Signs an approved plan (spec/08 §11.1): refuses unless `approved` is this plan's kind, chain,
/// account and byte-identical `btc_payload` and the plan is `account`'s; then, per input, lends
/// the input's key ([`BtcAccountKey::key_source`]) from `vault` — a derived key through
/// `with_secp_key`, an imported single key (vault tag 4) through `BtcImportedKeys`, whose record
/// must have the account's network, address type and compression — checks that it gives the
/// account's key of that input (else `KeyMismatch`), computes the sighash of the account type
/// with the verified amount(s), signs (verified at once) and fills the scriptSig / witness. The
/// private key never leaves the closure.
///
/// # Errors
///
/// [`SignError`]; nothing signed is returned on error.
pub fn sign_plan(
    vault: &Vault,
    approved: Approved,
    plan: &SendPlan,
    account: &BtcAccountKey,
) -> Result<SignedTx, SignError> {
    sign_plan_with(vault, approved, plan, account)
}

/// [`sign_plan`] with any key lender (unit tests use a seed and a list of imported secrets).
#[expect(
    clippy::needless_pass_by_value,
    reason = "the one-time approval token is consumed by signing (spec/03 §11.5)"
)]
pub(crate) fn sign_plan_with<K: BtcKeys>(
    keys: &K,
    approved: Approved,
    plan: &SendPlan,
    account: &BtcAccountKey,
) -> Result<SignedTx, SignError> {
    if !approval_matches(&approved, plan, account) {
        return Err(SignError::ApprovalMismatch);
    }
    let unsigned = plan.tx();
    let inputs = plan.inputs();
    check_plan_consistent(plan, account)?;
    let expected = expected_inputs(plan, account)?;
    let network = plan.network();
    let script_type = account.script_type();
    let prevouts = plan_prevouts(plan, &expected);
    let mut signed = unsigned.clone();
    for (position, ((planned, input), (pubkey, kind))) in inputs
        .iter()
        .zip(signed.inputs.iter_mut())
        .zip(&expected)
        .enumerate()
    {
        let source = account.key_source(planned.chain, planned.index);
        match script_type {
            ScriptType::P2wpkh | ScriptType::P2shP2wpkh => {
                let BtcPubKey::Compressed(key) = pubkey else {
                    return Err(SignError::Derivation);
                };
                let sighash =
                    bip143_sighash_p2wpkh(unsigned, position, &hash160(key), planned.value)
                        .ok_or(SignError::PlanInconsistent)?;
                let signature = keys.with_btc_key(network, source, position, |ctx, secret| {
                    check_lent_key(ctx, secret, pubkey, position)?;
                    sign_sighash(ctx, secret, &sighash).map_err(SignError::Witness)
                })?;
                input.witness = vec![signature, key.to_vec()];
            }
            ScriptType::P2pkh => {
                let sighash = legacy_sighash(
                    unsigned,
                    position,
                    &script_pubkey(kind),
                    u32::from(SIGHASH_ALL),
                )
                .ok_or(SignError::PlanInconsistent)?;
                let signature = keys.with_btc_key(network, source, position, |ctx, secret| {
                    check_lent_key(ctx, secret, pubkey, position)?;
                    sign_sighash(ctx, secret, &sighash).map_err(SignError::Witness)
                })?;
                input.script_sig = p2pkh_script_sig(&signature, pubkey.as_bytes())
                    .ok_or(SignError::PlanInconsistent)?;
            }
            ScriptType::P2tr => {
                let ScriptKind::P2tr(output) = kind else {
                    return Err(SignError::Derivation);
                };
                let sighash = sighash_default(unsigned, position, &prevouts)
                    .ok_or(SignError::PlanInconsistent)?;
                let aux = keys.aux_rand()?;
                let signature = keys.with_btc_key(network, source, position, |ctx, secret| {
                    check_lent_key(ctx, secret, pubkey, position)?;
                    let (signature, tweaked) = sign_key_path(ctx, secret, None, &sighash, &aux)
                        .map_err(SignError::Taproot)?;
                    if tweaked != *output {
                        return Err(SignError::KeyMismatch { input: position });
                    }
                    Ok(signature)
                })?;
                input.witness = vec![signature.to_vec()];
            }
        }
    }
    Ok(SignedTx {
        raw: serialize(&signed, true),
        approval_id: approved.id(),
        approval_digest: approved.digest(),
    })
}

// ----- YubiKey card signing (spec/10 §6.3) ------------------------------------------------------

/// Longest DER of a card signature: the card picks its own nonce, so high-R stays (spec/10 §6.3,
/// [`crate::yubikey::sig::MAX_CARD_DER_LEN`]).
pub const MAX_CARD_DER_LEN: usize = crate::yubikey::sig::MAX_CARD_DER_LEN;
/// Longest card signature item (`DER ‖ sighash type`): the `72 + 1` of the card input weight
/// ([`ScriptType::card_input_weight`]).
pub const MAX_CARD_SIG_ITEM_LEN: usize = MAX_CARD_DER_LEN + 1;

/// The card signature rules on `DER ‖ 0x01` (spec/10 §6.3): the type byte, at most
/// [`MAX_CARD_DER_LEN`] DER bytes, strict DER with an identical round trip, low-S. High-R is
/// allowed (unlike [`check_signature_shape`], which stays unchanged for software inputs).
fn check_card_signature_shape(sig_item: &[u8]) -> Result<Signature, WitnessSigError> {
    let (sighash_type, der) = sig_item.split_last().ok_or(WitnessSigError::SighashType)?;
    if *sighash_type != SIGHASH_ALL {
        return Err(WitnessSigError::SighashType);
    }
    if der.len() > MAX_CARD_DER_LEN {
        return Err(WitnessSigError::DerTooLong);
    }
    let signature = Signature::from_der(der).map_err(|_| WitnessSigError::DerInvalid)?;
    if signature.serialize_der().as_ref() != der {
        return Err(WitnessSigError::DerNotCanonical);
    }
    let mut normalized = signature;
    normalized.normalize_s();
    if normalized != signature {
        return Err(WitnessSigError::HighS);
    }
    Ok(signature)
}

/// [`check_card_signature`] with a caller's context.
pub(crate) fn check_card_signature_with<C: Verification>(
    ctx: &Secp256k1<C>,
    sig_item: &[u8],
    pubkey_item: &[u8],
    sighash: &[u8; 32],
) -> Result<(), WitnessSigError> {
    let signature = check_card_signature_shape(sig_item)?;
    let key = <[u8; PUBKEY_LEN]>::try_from(pubkey_item).map_err(|_| WitnessSigError::PublicKey)?;
    if !matches!(key.first(), Some(0x02 | 0x03)) {
        return Err(WitnessSigError::PublicKey);
    }
    let public =
        PublicKey::from_byte_array_compressed(key).map_err(|_| WitnessSigError::PublicKey)?;
    ctx.verify_ecdsa(Message::from_digest(*sighash), &signature, &public)
        .map_err(|_| WitnessSigError::VerifyFailed)
}

/// The relaxed check of a `YubiKey` input's signature item (witness or P2PKH scriptSig) against
/// `sighash` and the compressed card key (spec/10 §6.3): `SIGHASH_ALL`, strict DER of at most
/// 72 bytes, low-S and a valid signature; high-R is allowed. Software inputs keep
/// [`check_witness_signature`] / [`check_p2pkh_signature`] (low-R, ≤ 70 bytes).
///
/// # Errors
///
/// The first failing rule's [`WitnessSigError`].
pub fn check_card_signature(
    sig_item: &[u8],
    pubkey_item: &[u8],
    sighash: &[u8; 32],
) -> Result<(), WitnessSigError> {
    check_card_signature_with(
        &Secp256k1::verification_only(),
        sig_item,
        pubkey_item,
        sighash,
    )
}

/// The card signs one 32-byte sighash and returns the DER signature without the sighash type
/// (`yubikey::sign::sign_btc`: low-s, verified against the recorded key).
pub type CardSighashSigner<'a> = &'a mut dyn FnMut([u8; 32]) -> Result<Vec<u8>, CardError>;

/// Failure of a card (`YubiKey`) Bitcoin signature: nothing signed is returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CardSignError {
    /// The approval, the plan or a card signature failed a check (as for vault signing).
    Sign(SignError),
    /// The card operation failed (`NotSupported` for a Taproot input: no BIP340 on the card).
    Card(CardError),
    /// The post-sign verification of the whole transaction failed (spec/08 §11.2).
    PostSign(PostSignError),
}

impl fmt::Display for CardSignError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sign(error) => error.fmt(formatter),
            Self::Card(error) => error.fmt(formatter),
            Self::PostSign(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for CardSignError {}

impl From<SignError> for CardSignError {
    fn from(error: SignError) -> Self {
        Self::Sign(error)
    }
}

impl From<CardError> for CardSignError {
    fn from(error: CardError) -> Self {
        Self::Card(error)
    }
}

/// One card signature item `DER ‖ 0x01` for `sighash`, checked with the relaxed card rules
/// against the account's key.
fn card_item(
    ctx: &Secp256k1<secp256k1::VerifyOnly>,
    card: &mut dyn FnMut([u8; 32]) -> Result<Vec<u8>, CardError>,
    sighash: [u8; 32],
    key: &[u8; PUBKEY_LEN],
) -> Result<Vec<u8>, CardSignError> {
    let der = card(sighash)?;
    let mut item = Vec::with_capacity(MAX_CARD_SIG_ITEM_LEN);
    item.extend_from_slice(&der);
    item.push(SIGHASH_ALL);
    check_card_signature_with(ctx, &item, key, &sighash).map_err(SignError::Witness)?;
    Ok(item)
}

/// Signs an approved plan of a `YubiKey` account on the card (spec/10 §6.3): the same approval
/// and plan checks as [`sign_plan`], then one card signature per input — the legacy sighash for
/// P2PKH, BIP143 for P2SH-P2WPKH and P2WPKH (Taproot is refused: `Card(NotSupported)`) — each
/// checked with the relaxed card rules ([`check_card_signature`]), the same scriptSig / witness
/// as the vault path, and finally the full post-sign verification of the transaction
/// ([`super::verify::verify_signed`]: unsigned transaction, keys, signatures, outputs, change,
/// fee, caps, dust and sizes). The app runs [`check_recorded_amounts`] first, as for
/// [`sign_plan`]. A software account is refused (`Sign(ApprovalMismatch)`).
///
/// # Errors
///
/// [`CardSignError`]; nothing signed is returned on error.
#[expect(
    clippy::needless_pass_by_value,
    reason = "the one-time approval token is consumed by signing (spec/03 §11.5)"
)]
pub fn sign_plan_card(
    approved: Approved,
    plan: &SendPlan,
    account: &BtcAccountKey,
    card: CardSighashSigner<'_>,
) -> Result<SignedTx, CardSignError> {
    if !account.is_hardware() || !approval_matches(&approved, plan, account) {
        return Err(SignError::ApprovalMismatch.into());
    }
    let script_type = account.script_type();
    if script_type == ScriptType::P2tr {
        return Err(CardError::NotSupported.into());
    }
    check_plan_consistent(plan, account)?;
    let expected = expected_inputs(plan, account)?;
    let unsigned = plan.tx();
    let ctx = Secp256k1::verification_only();
    let mut signed = unsigned.clone();
    for (position, ((planned, input), (pubkey, kind))) in plan
        .inputs()
        .iter()
        .zip(signed.inputs.iter_mut())
        .zip(&expected)
        .enumerate()
    {
        let BtcPubKey::Compressed(key) = pubkey else {
            return Err(SignError::Derivation.into());
        };
        match script_type {
            ScriptType::P2wpkh | ScriptType::P2shP2wpkh => {
                let sighash =
                    bip143_sighash_p2wpkh(unsigned, position, &hash160(key), planned.value)
                        .ok_or(SignError::PlanInconsistent)?;
                let item = card_item(&ctx, card, sighash, key)?;
                input.witness = vec![item, key.to_vec()];
            }
            ScriptType::P2pkh => {
                let sighash = legacy_sighash(
                    unsigned,
                    position,
                    &script_pubkey(kind),
                    u32::from(SIGHASH_ALL),
                )
                .ok_or(SignError::PlanInconsistent)?;
                let item = card_item(&ctx, card, sighash, key)?;
                input.script_sig =
                    p2pkh_script_sig(&item, key).ok_or(SignError::PlanInconsistent)?;
            }
            ScriptType::P2tr => return Err(CardError::NotSupported.into()),
        }
    }
    let raw = serialize(&signed, true);
    verify_signed(&raw, plan, account).map_err(CardSignError::PostSign)?;
    Ok(SignedTx {
        raw,
        approval_id: approved.id(),
        approval_digest: approved.digest(),
    })
}
