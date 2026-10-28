//! Signing an approved SOL transfer (spec/07 §13.1 step 6): deadline, approval/intent checks,
//! the intent-creation rules once more (template compute-unit limit, maximum fee and cap, the
//! non-standard-path "move to an own standard account" rule), message encoding with the
//! parse + re-encoding identity, the key inside
//! `Vault::with_ed25519_seed`, public-key check, signature, `verify_strict`, transaction assembly
//! and re-parse. Post-sign re-verification ports the pattern of
//! `archive/spec-v2.4:crates/key-agent/src/lib.rs:328-345`.

use core::fmt;

use ed25519_dalek::Signer as _;
use sha2::{Digest, Sha256};

use super::fee::{MAX_FEE_RANGE, max_fee, template_cu_limit};
use super::intent::{SolTransferIntent, flags};
use super::keys::{signing_key, verify_strict};
use super::message::{
    SolParseError, assemble_transaction, encode_message, parse_message, parse_transaction,
};
use crate::approval::{AccountRef, ApprovalKind, Approved, ChainRef, SigningPayload};
use crate::bip32::path::{AccountIndex, MAX_ACCOUNT_INDEX};
use crate::error::VaultError;
use crate::slip10::SolKeySource;
use crate::vault::Vault;

/// Time from `ApprovalStore::consume` to the start of signing (separate from the 120 s window).
pub const SOL_SIGN_DEADLINE_SECS: u64 = 20;
/// `lastValidBlockHeight` may be at most this far above the finalized block height.
pub const SOL_MAX_LVBH_AHEAD: u64 = 300;
/// `lastValidBlockHeight` must be at least this far above the finalized block height asked right
/// after it. A finalized blockhash is valid for 150 blocks (`lvbh` = its block height + 150) and
/// `getBlockHeight` cannot see an older bank than `getLatestBlockhash`, so `lvbh ≤ h + 150`; a
/// lower value than `h + 100` (50 blocks ≈ 10 s of drift between the two calls) is implausible
/// and would let the expiry proof (`height > lvbh`, spec/07 §14.3) start too early.
pub const SOL_MIN_LVBH_AHEAD: u64 = 100;

/// A signed, verified transfer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedSolTransfer {
    /// `01 ‖ signature ‖ message` (267 bytes for `T_SOL`).
    pub tx: Vec<u8>,
    /// Ed25519 signature (the transaction id is its base58).
    pub signature: [u8; 64],
    /// `SHA-256(message)`.
    pub message_sha256: [u8; 32],
}

/// Signing failure: nothing was signed or nothing may be stored or sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SolSignError {
    /// More than 20 s since `consume`.
    DeadlineExceeded,
    /// The approval is not a SOL transfer of this intent (kind, payload, account or cluster).
    KindMismatch,
    /// The message does not parse as the template.
    Parse(SolParseError),
    /// The re-encoded message, core or blockhash differ from what was approved.
    EncodingMismatch,
    /// The derived public key is not `intent.core.from`.
    KeyMismatch,
    /// `verify_strict` or the re-parse of the signed transaction failed.
    PostSignVerification,
    /// The vault refused (locked, backup pending, derivation).
    Vault(VaultError),
    /// The intent breaks a rule that intent creation enforces (checked again before any key
    /// use): a compute-unit limit other than the template's, a maximum fee that is not the
    /// formula's value or exceeds the fee cap, or a non-standard-path transfer that is not a
    /// "send max" to one of the wallet's own standard accounts (spec/07 §3.3, §10).
    PolicyMismatch,
    /// A `Pending` transfer of the same (cluster, account) is in the journal (spec/07 §1).
    PendingExists,
}

impl fmt::Display for SolSignError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Vault(error) => error.fmt(formatter),
            Self::DeadlineExceeded => {
                formatter.write_str("승인 후 서명 기한(20초)이 지났습니다. 다시 검토하세요.")
            }
            Self::KindMismatch
            | Self::Parse(_)
            | Self::EncodingMismatch
            | Self::KeyMismatch
            | Self::PolicyMismatch => {
                formatter.write_str("내부 검증에 실패해 서명하지 않았습니다.")
            }
            Self::PostSignVerification => formatter.write_str("서명 검증 실패(내부 오류)"),
            Self::PendingExists => {
                formatter.write_str("이 계정의 이전 전송을 확인 중이라 서명하지 않았습니다.")
            }
        }
    }
}

/// The fee rules of an intent (spec/07 §10): the template's compute-unit limit, the maximum fee
/// of the formula, at most the user's cap, and a cap inside the settings range.
#[must_use]
pub fn fee_policy_ok(intent: &SolTransferIntent) -> bool {
    let core = &intent.core;
    core.cu_limit == template_cu_limit(core.asset)
        && max_fee(core.cu_limit, core.cu_price_micro) == Ok(intent.max_fee_lamports)
        && intent.max_fee_lamports <= intent.fee_cap_lamports
        && intent.fee_cap_lamports <= MAX_FEE_RANGE.1
}

/// The non-standard-path rule (spec/07 §3.3): a key outside `m/44'/501'/i'/0'` may only move its
/// funds with "send max" to one of this wallet's own standard accounts. The recipient is compared
/// with the standard public keys of the unlocked seed (indices 0..=999, batches of 128, stopping
/// at the first match); a standard source passes unchanged.
///
/// # Errors
///
/// The vault's refusal (locked, derivation).
pub fn non_standard_rule_ok(vault: &Vault, intent: &SolTransferIntent) -> Result<bool, VaultError> {
    if !intent.source.needs_move_rule() {
        return Ok(true);
    }
    if !intent.has(flags::SEND_MAX) {
        return Ok(false);
    }
    let to = intent.core.to.to_bytes();
    let mut next = 0_u32;
    while next <= MAX_ACCOUNT_INDEX {
        let end = next
            .saturating_add(STANDARD_BATCH)
            .min(MAX_ACCOUNT_INDEX.saturating_add(1));
        let sources: Vec<SolKeySource> = (next..end)
            .filter_map(|index| AccountIndex::new(index).ok().map(SolKeySource::Standard))
            .collect();
        if vault.sol_public_keys(&sources)?.contains(&to) {
            return Ok(true);
        }
        next = end;
    }
    Ok(false)
}

/// Standard public keys derived per [`Vault::sol_public_keys`] call (its batch bound).
const STANDARD_BATCH: u32 = 128;

impl std::error::Error for SolSignError {}

/// Verifies a fresh signature and assembles the transaction; `from` is the expected signer.
pub(crate) fn finish_signed(
    from: &[u8; 32],
    message: &[u8],
    signature: [u8; 64],
    cluster: crate::sol::SolCluster,
) -> Result<SignedSolTransfer, SolSignError> {
    if !verify_strict(from, message, &signature) {
        return Err(SolSignError::PostSignVerification);
    }
    let tx = assemble_transaction(&signature, message);
    let (core, blockhash, parsed_signature) =
        parse_transaction(&tx, cluster).map_err(|_| SolSignError::PostSignVerification)?;
    if parsed_signature != signature
        || core.from.as_bytes() != from
        || encode_message(&core, &blockhash) != message
    {
        return Err(SolSignError::PostSignVerification);
    }
    Ok(SignedSolTransfer {
        tx,
        signature,
        message_sha256: Sha256::digest(message).into(),
    })
}

/// Signs an approved SOL transfer with the finalized `blockhash` fetched after approval.
/// `consumed_at_ms`/`now_ms` are monotonic milliseconds.
///
/// # Errors
///
/// [`SolSignError`]; on any error nothing has been signed or is returned.
#[expect(
    clippy::needless_pass_by_value,
    reason = "the one-time approval token is consumed by signing (spec/03 §11.5)"
)]
pub fn sign_transfer(
    vault: &Vault,
    approved: Approved,
    consumed_at_ms: u64,
    blockhash: [u8; 32],
    now_ms: u64,
) -> Result<SignedSolTransfer, SolSignError> {
    let deadline = consumed_at_ms.saturating_add(SOL_SIGN_DEADLINE_SECS.saturating_mul(1_000));
    if now_ms > deadline {
        return Err(SolSignError::DeadlineExceeded);
    }
    let SigningPayload::SolTransfer(intent) = approved.payload() else {
        return Err(SolSignError::KindMismatch);
    };
    let intent = *intent;
    let chain_ok = matches!(
        approved.chain(),
        ChainRef::Solana { cluster, genesis } if cluster == intent.cluster && genesis == intent.cluster.genesis()
    );
    if approved.kind() != ApprovalKind::SolTransfer
        || approved.account() != AccountRef::Sol(intent.core.from.to_bytes())
        || !chain_ok
    {
        return Err(SolSignError::KindMismatch);
    }
    // Defence in depth: the rules intent creation enforces, again, before any key use.
    if !fee_policy_ok(&intent)
        || !non_standard_rule_ok(vault, &intent).map_err(SolSignError::Vault)?
    {
        return Err(SolSignError::PolicyMismatch);
    }
    let message = encode_message(&intent.core, &blockhash);
    let (core, parsed_blockhash) =
        parse_message(&message, intent.cluster).map_err(SolSignError::Parse)?;
    if core != intent.core
        || parsed_blockhash != blockhash
        || encode_message(&core, &parsed_blockhash) != message
    {
        return Err(SolSignError::EncodingMismatch);
    }
    let from = intent.core.from.to_bytes();
    let sign = |secret: &[u8; 32]| {
        let key = signing_key(secret);
        if key.verifying_key().to_bytes() != from {
            return Ok(Err(SolSignError::KeyMismatch));
        }
        Ok(Ok(key.sign(&message).to_bytes()))
    };
    // An imported key is looked up by its public key (`from`); a derived one by its path.
    let signed = if intent.source.is_imported() {
        vault.with_imported_ed25519_seed(&from, sign)
    } else {
        vault.with_ed25519_seed(intent.source, sign)
    };
    let signature = signed.map_err(SolSignError::Vault)??;
    finish_signed(&from, &message, signature, intent.cluster)
}
