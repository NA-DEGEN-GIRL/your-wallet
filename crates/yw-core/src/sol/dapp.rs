//! Solana transactions built by a dApp (spec/07 §20, D38): the strict legacy/v0 parser with
//! re-encoding identity, address lookup tables, the instruction decoders, the simulation diff,
//! the approval payload and request, and the signer. The wallet never builds or changes these
//! messages: it fills its own signature slot of the exact bytes the user approved. Everything
//! here is pure; RPC observations (tables, account data, simulation) are arguments.
//!
//! Every message this module accepts is also caught by the message-signing guard
//! (`msgsign::looks_like_transaction`, M01): transaction bytes are never signed as a message.
#![deny(clippy::indexing_slicing)]

pub mod alt;
pub mod decode;
pub mod diff;
pub mod display;
pub mod parse;
pub mod sign;
pub mod text;

use core::fmt;

use sha2::{Digest, Sha256};

pub use alt::{AltError, KeyRole, LookupTable, ResolvedKeys};
pub use decode::DecodedIx;
pub use diff::{AccountSnapshot, AuthorityKind, Change};
pub use display::{SolTxFacts, SolTxItemFacts, SolTxRequest, build_sol_tx_request};
pub use parse::{
    LookupRef, MessageHeader, SOL_TX_MAX_BATCH, SOL_TX_MAX_IX, SOL_TX_MAX_KEYS, SolTxError,
    SolTxMessage, SolTxVersion, SolWireTx, encode_message_any, parse_message_any, parse_wire_tx,
};
pub use sign::{
    PreSignCheck, SignedSolDappTx, SolTxCardError, SolTxSignError, sign_send, sign_send_card,
    sign_txs, sign_txs_card,
};

use crate::codec::transcript::Transcript;
use crate::slip10::SolKeySource;

/// Sign only (`sol_signTransaction`, `sol_signAllTransactions`) or sign and send
/// (`sol_signAndSendTransaction`); the digest byte (spec/07 §20.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SolTxMode {
    /// The signed bytes go back to the site; the wallet neither sends nor tracks them.
    SignOnly = 1,
    /// The wallet journals, sends and tracks the one transaction.
    SignAndSend = 2,
}

impl SolTxMode {
    /// The digest byte.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }
}

/// A `preflightCommitment` (aliases are folded by the provider, spec/05 §2.13).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SolCommitment {
    /// `processed`.
    Processed = 1,
    /// `confirmed` (the RPC default the wallet uses).
    Confirmed = 2,
    /// `finalized`.
    Finalized = 3,
}

impl SolCommitment {
    /// The digest byte.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// The JSON-RPC value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Processed => "processed",
            Self::Confirmed => "confirmed",
            Self::Finalized => "finalized",
        }
    }

    /// Parses the JSON-RPC value (exact, lowercase).
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "processed" => Some(Self::Processed),
            "confirmed" => Some(Self::Confirmed),
            "finalized" => Some(Self::Finalized),
            _ => None,
        }
    }
}

/// The send options a dApp may set (spec/07 §20.8): `skipPreflight` on every send of the record,
/// `preflightCommitment` on every preflighted send, `minContextSlot` on the first send only.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SolSendOptions {
    /// `skipPreflight`.
    pub skip_preflight: bool,
    /// `preflightCommitment` (`None`: the wallet's `confirmed`).
    pub preflight_commitment: Option<SolCommitment>,
    /// `minContextSlot` of the first send.
    pub min_context_slot: Option<u64>,
}

/// One transaction of a dApp request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolTxItem {
    /// The exact wire bytes the site sent (its signatures included, ours zero or stale).
    pub wire: Vec<u8>,
    /// Our signer slot (`SolTxMessage::signer_slot` of the payload key).
    pub signer_slot: u8,
    /// The addresses the lookups resolved to (`Some(empty)` for a message without lookups;
    /// `None` only when the lookups could not be resolved, which blocks the request with X01).
    pub loaded: Option<ResolvedKeys>,
}

/// What a dApp transaction approval signs: every transaction with the key of `source`, whose
/// public key is `public` (the approval account), in `mode` with `options`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolTxPayload {
    /// Key source.
    pub source: SolKeySource,
    /// Ed25519 public key.
    pub public: [u8; 32],
    /// Sign only or sign and send.
    pub mode: SolTxMode,
    /// Send options (all default for sign-only).
    pub options: SolSendOptions,
    /// The transactions, in request order.
    pub items: Vec<SolTxItem>,
}

/// Why a payload is not signable (`check_draft` refuses it; the signer maps it to
/// `KindMismatch`, a recovery-scan source to `PolicyMismatch`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SolTxPayloadError {
    /// No transaction, more than 32, or a send of more than one.
    Count,
    /// A transaction does not parse (spec/07 §20.2).
    Parse(SolTxError),
    /// The signer slot is not the payload key's slot.
    Slot,
    /// `loaded` without lookups, or counts other than the lookups'.
    Loaded,
    /// A send whose other required signatures are not all present.
    MissingSignature,
    /// A send of a durable-nonce transaction.
    DurableNonce,
    /// A recovery-scan source (`needs_move_rule`).
    Source,
}

impl SolTxPayloadError {
    /// The fixed text in `lang` (`Display` is the Korean one).
    #[must_use]
    pub fn text_in(self, lang: crate::lang::Lang) -> String {
        use text as t;
        let text = match self {
            Self::Count => t::PAYLOAD_COUNT,
            Self::Parse(error) => return error.text_in(lang),
            Self::Slot => t::PAYLOAD_SLOT,
            Self::Loaded => t::PAYLOAD_LOADED,
            Self::MissingSignature => t::PAYLOAD_MISSING_SIGNATURE,
            Self::DurableNonce => t::PAYLOAD_DURABLE_NONCE,
            Self::Source => t::PAYLOAD_SOURCE,
        };
        text.get(lang).to_owned()
    }
}

impl fmt::Display for SolTxPayloadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text_in(crate::lang::Lang::Ko))
    }
}

impl std::error::Error for SolTxPayloadError {}

/// The intent hash domain of a dApp send (journal v3, spec/07 §20.9).
const INTENT_DOMAIN: &[u8] = b"your-wallet/v3/sol-tx-intent";

impl SolTxPayload {
    /// Digest bytes: transcript `"your-wallet/v3/sol-tx"` v1 of the source (with an added
    /// mnemonic's record id, as `SolMessagePayload`), key, mode, options and every transaction
    /// with its slot and resolved lookups (spec/07 §20.6).
    #[must_use]
    pub fn digest_bytes(&self) -> Vec<u8> {
        let mut transcript = Transcript::default();
        let _ = transcript.push_bytes(b"your-wallet/v3/sol-tx");
        transcript.push_u16(1);
        let (a, b) = self.source.params();
        transcript.push_u8(self.source.tag());
        transcript.push_u32(a);
        transcript.push_u32(b);
        if let Some(id) = self.source.mnemonic() {
            let _ = transcript.push_bytes(id.as_bytes());
        }
        let _ = transcript.push_bytes(&self.public);
        transcript.push_u8(self.mode.code());
        transcript.push_bool(self.options.skip_preflight);
        transcript.push_u8(
            self.options
                .preflight_commitment
                .map_or(0, SolCommitment::code),
        );
        transcript.push_bool(self.options.min_context_slot.is_some());
        transcript.push_u64(self.options.min_context_slot.unwrap_or(0));
        transcript.push_u16(u16::try_from(self.items.len()).unwrap_or(u16::MAX));
        for item in &self.items {
            let _ = transcript.push_bytes(&item.wire);
            transcript.push_u8(item.signer_slot);
            transcript.push_bool(item.loaded.is_some());
            let empty = ResolvedKeys::default();
            let loaded = item.loaded.as_ref().unwrap_or(&empty);
            for keys in [&loaded.writable, &loaded.readonly] {
                transcript.push_u16(u16::try_from(keys.len()).unwrap_or(u16::MAX));
                for key in keys {
                    let _ = transcript.push_bytes(key.as_bytes());
                }
            }
        }
        transcript.into_bytes()
    }

    /// `SHA-256("your-wallet/v3/sol-tx-intent" ‖ approval id ‖ digest bytes)`: the journal
    /// intent of a send, bound to its one approval (spec/07 §20.9).
    #[must_use]
    pub fn intent_hash(&self, approval_id: &[u8; 16]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(INTENT_DOMAIN);
        hasher.update(approval_id);
        hasher.update(self.digest_bytes());
        hasher.finalize().into()
    }

    /// The payload rules (spec/07 §20.6): 1–32 transactions (one for a send), each parsing with
    /// our slot, lookups resolved with matching counts or left unresolved, a send fully signed
    /// by the others and without a durable nonce, and no recovery-scan source. Foreign signature
    /// validity is the builder's X01 and the signer's check, not this one.
    ///
    /// # Errors
    ///
    /// [`SolTxPayloadError`].
    pub fn validate(&self) -> Result<(), SolTxPayloadError> {
        if self.source.needs_move_rule() {
            return Err(SolTxPayloadError::Source);
        }
        let send = self.mode == SolTxMode::SignAndSend;
        if self.items.is_empty()
            || self.items.len() > SOL_TX_MAX_BATCH
            || (send && self.items.len() != 1)
        {
            return Err(SolTxPayloadError::Count);
        }
        for item in &self.items {
            let wire = parse_wire_tx(&item.wire).map_err(SolTxPayloadError::Parse)?;
            let message = &wire.message;
            if message.signer_slot(&self.public) != Ok(item.signer_slot) {
                return Err(SolTxPayloadError::Slot);
            }
            let loaded_ok = match &item.loaded {
                None => !message.lookups.is_empty(),
                Some(keys) => message.loaded_counts() == (keys.writable.len(), keys.readonly.len()),
            };
            if !loaded_ok {
                return Err(SolTxPayloadError::Loaded);
            }
            if send {
                let all_signed = wire.signatures.iter().enumerate().all(|(index, slot)| {
                    index == usize::from(item.signer_slot) || slot.iter().any(|b| *b != 0)
                });
                if !all_signed {
                    return Err(SolTxPayloadError::MissingSignature);
                }
                if message.durable_nonce().is_some() {
                    return Err(SolTxPayloadError::DurableNonce);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_approval;
#[cfg(test)]
mod tests_send;
