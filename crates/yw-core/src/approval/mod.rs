//! Approval request model, display encoding, digest and one-shot consumption (spec/03 §11, the
//! canonical definition for every chain; D27, D31).
//!
//! Ported from `archive/spec-v2.4:crates/wallet-protocol/src/approval.rs:16-22,163-189,466-541`
//! (transcript digest, constant-time one-shot consume) without registry/ruleset/RPC-observation/
//! protocol-validity bindings, and with the simulation state always bound (D15). Display rules
//! come from `archive/spec-v2.4:crates/approval-wire/src/lib.rs:231-777,1212-1300`. SOL and BTC
//! variants are added at M7/M8.

mod display;
mod store;
mod text;

pub use display::{
    ApprovalDisplay, DISPLAY_DOMAIN, DISPLAY_MAGIC, DisplayError, DisplayField, FieldKey,
    MAX_DISPLAY_FIELDS, MAX_DISPLAY_VALUE_BYTES, MAX_DISPLAY_WARNINGS, MAX_TITLE_BYTES,
};
pub use store::{
    APPROVAL_DOMAIN, APPROVAL_TTL_MS, ApprovalError, ApprovalState, ApprovalStore, Approved,
    approval_digest,
};
pub use text::{
    Escaped, RiskLevel, RuleId, Warning, escape_edges, escape_untrusted, is_forbidden_display_char,
    is_valid_display_text,
};

pub use crate::evm::display::{build_evm_tx_request, build_personal_request, build_typed_request};

use core::fmt;

use crate::error::KeyError;
use crate::evm::address::Address;
use crate::evm::amount::U256;
use crate::evm::tx::Eip1559Tx;
use crate::policy::BrowserOrigin;
use crate::vault::EvmKeySource;

/// Random approval identifier.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ApprovalId(pub [u8; 16]);

impl fmt::Debug for ApprovalId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ApprovalId({})", crate::hex::encode(&self.0))
    }
}

impl ApprovalId {
    /// A fresh non-zero identifier from the OS CSPRNG.
    ///
    /// # Errors
    ///
    /// [`KeyError::RandomnessUnavailable`].
    pub fn random() -> Result<Self, KeyError> {
        crate::entropy::random_nonzero_id().map(Self)
    }
}

/// Request origin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApprovalOrigin {
    /// This app (wallet send, speed-up, cancel).
    App,
    /// A dApp origin.
    Site(BrowserOrigin),
}

impl ApprovalOrigin {
    /// `"yw-app"` or [`BrowserOrigin::as_str`] (digest `origin_serialized`).
    #[must_use]
    pub fn serialized(&self) -> &str {
        match self {
            Self::App => "yw-app",
            Self::Site(origin) => origin.as_str(),
        }
    }
}

/// Chain reference bound into the digest (`chain_tag` 1 = EVM).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainRef {
    /// EVM chain with its verified genesis hash.
    Evm {
        /// Chain id.
        chain_id: u64,
        /// Verified genesis (§1.4).
        genesis: [u8; 32],
    },
}

/// Signing account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountRef {
    /// EVM address.
    Evm(Address),
}

/// Approval kind (digest byte).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
#[expect(
    clippy::enum_variant_names,
    reason = "names fixed by spec/03 §11.1; SOL/BTC kinds arrive at M7/M8"
)]
pub enum ApprovalKind {
    /// EVM transaction.
    EvmTransaction = 0x10,
    /// EVM speed-up replacement.
    EvmSpeedUp = 0x11,
    /// EVM cancel replacement.
    EvmCancel = 0x12,
    /// `personal_sign`.
    EvmPersonalSign = 0x13,
    /// `eth_signTypedData_v4`.
    EvmTypedData = 0x14,
}

impl ApprovalKind {
    /// The digest byte.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Whether this is one of the three EVM transaction kinds.
    #[must_use]
    pub const fn is_evm_transaction(self) -> bool {
        matches!(
            self,
            Self::EvmTransaction | Self::EvmSpeedUp | Self::EvmCancel
        )
    }
}

/// What will be signed (digest bytes per spec/03 §11.4).
#[derive(Clone, Debug, PartialEq, Eq)]
#[expect(
    clippy::enum_variant_names,
    reason = "names fixed by spec/03 §11.1; SOL/BTC payloads arrive at M7/M8"
)]
pub enum SigningPayload {
    /// A type-2 transaction (`0x02 ‖ rlp(9 fields)`).
    EvmTx(Eip1559Tx),
    /// The full EIP-191 preimage.
    EvmPersonal(Vec<u8>),
    /// `0x19 0x01 ‖ domainSeparator ‖ hashStruct`.
    EvmTypedData([u8; 66]),
}

impl SigningPayload {
    /// The signing-payload bytes of the digest (spec/03 §11.4 table).
    #[must_use]
    pub fn digest_bytes(&self) -> Vec<u8> {
        match self {
            Self::EvmTx(tx) => tx.signing_preimage(),
            Self::EvmPersonal(preimage) => preimage.clone(),
            Self::EvmTypedData(preimage) => preimage.to_vec(),
        }
    }
}

/// Key used to sign. Not part of the digest (§4.3-5 recovery check binds the account).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signer {
    /// An EVM key from the vault.
    Evm(EvmKeySource),
}

/// Simulation block binding (spec/03 §6.5, §11.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SimBinding {
    /// Block number.
    pub number: u64,
    /// Parent hash.
    pub parent_hash: [u8; 32],
    /// Timestamp.
    pub timestamp: u64,
    /// Base fee.
    pub base_fee: U256,
    /// `sim_digest`.
    pub sim_digest: [u8; 32],
}

/// Simulation verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SimVerdict {
    /// Success, fully interpreted.
    Ok = 0,
    /// `status 0x0` (E02).
    Reverted = 1,
    /// Interpreted with gaps (E03, E04, E07, E08, E09).
    Incomplete = 2,
}

/// Why there is no simulation result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SimNoneReason {
    /// `simulation = unsupported` (E36).
    Unsupported = 1,
    /// Transport error.
    Transport = 2,
    /// Timeout.
    Timeout = 3,
    /// HTTP/JSON-RPC 429.
    RateLimited = 4,
    /// Top-level JSON-RPC error.
    RpcError = 5,
    /// Malformed response.
    Malformed = 6,
    /// Response or log limits exceeded.
    TooLarge = 7,
    /// A blocking condition stopped preparation before step 8.
    Skipped = 8,
}

/// Simulation state bound into the approval digest (`sim_tag`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimulationBinding {
    /// 0: messages (and SOL/BTC).
    NotApplicable,
    /// 1: a simulation block exists.
    Simulated {
        /// Verdict.
        verdict: SimVerdict,
        /// Block binding.
        block: SimBinding,
    },
    /// 2: EVM transaction without a result.
    None {
        /// Reason.
        reason: SimNoneReason,
    },
}

impl SimulationBinding {
    /// The digest tag.
    #[must_use]
    pub const fn tag(&self) -> u8 {
        match self {
            Self::NotApplicable => 0,
            Self::Simulated { .. } => 1,
            Self::None { .. } => 2,
        }
    }
}

/// The display model (spec/03 §11.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalDraft {
    /// Identifier.
    pub id: ApprovalId,
    /// Origin.
    pub origin: ApprovalOrigin,
    /// Chain.
    pub chain: ChainRef,
    /// Signing account.
    pub account: AccountRef,
    /// Key source.
    pub signer: Signer,
    /// Kind.
    pub kind: ApprovalKind,
    /// Signing payload.
    pub payload: SigningPayload,
    /// Display model.
    pub display: ApprovalDisplay,
    /// Simulation binding.
    pub simulation: SimulationBinding,
}

/// An issued approval request (only [`ApprovalStore::issue`] creates one).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalRequest {
    /// Identifier.
    pub id: ApprovalId,
    /// Origin.
    pub origin: ApprovalOrigin,
    /// Chain.
    pub chain: ChainRef,
    /// Signing account.
    pub account: AccountRef,
    /// Key source.
    pub signer: Signer,
    /// Kind.
    pub kind: ApprovalKind,
    /// Signing payload.
    pub payload: SigningPayload,
    /// Display model.
    pub display: ApprovalDisplay,
    /// Simulation binding.
    pub simulation: SimulationBinding,
    /// First Ready display (wall clock, log only).
    pub created_unix_ms: u64,
    /// `created_unix_ms + 120,000` (digest/display/log only).
    pub expires_unix_ms: u64,
    /// Approval digest (spec/03 §11.4).
    pub digest: [u8; 32],
}

/// Code at an address (spec/03 §8.5).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CodeKind {
    /// No code.
    #[default]
    Eoa,
    /// EIP-7702 delegation designator `0xef0100 ‖ target`.
    Delegated7702 {
        /// Delegation target.
        target: Address,
    },
    /// Contract code.
    Contract,
}

impl CodeKind {
    /// Classifies `eth_getCode` output.
    #[must_use]
    pub fn from_code(code: &[u8]) -> Self {
        if code.is_empty() {
            return Self::Eoa;
        }
        if let Some(target) = code.strip_prefix(&[0xef, 0x01, 0x00])
            && let Ok(target) = <[u8; 20]>::try_from(target)
        {
            return Self::Delegated7702 {
                target: Address::from_bytes(target),
            };
        }
        Self::Contract
    }
}

/// Token metadata looked up by yw-app (spec/03 §2.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenMeta {
    /// Symbol (`None` → `?`, E26).
    pub symbol: Option<String>,
    /// Decimals (`None` → raw units, E25).
    pub decimals: Option<u8>,
    /// Registry token (trusted symbol).
    pub registered: bool,
}

/// Chain facts gathered during preparation (spec/03 §3.7 steps 4 and 9).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChainFacts {
    /// `eth_getCode(account)` (E17).
    pub account_code: CodeKind,
    /// Classified addresses (spenders, operators, recipients, verifying contracts).
    pub code: Vec<(Address, CodeKind)>,
    /// Token metadata.
    pub tokens: Vec<(Address, TokenMeta)>,
    /// `balanceOf(account)` per token.
    pub balances: Vec<(Address, U256)>,
    /// Address-book names (already user-entered text; escaped at display).
    pub address_book: Vec<(Address, String)>,
}

impl ChainFacts {
    /// Code kind of `address`.
    #[must_use]
    pub fn code_of(&self, address: &Address) -> Option<CodeKind> {
        self.code
            .iter()
            .find_map(|(known, kind)| (known == address).then_some(*kind))
    }

    /// Token metadata of `address`.
    #[must_use]
    pub fn token(&self, address: &Address) -> Option<&TokenMeta> {
        self.tokens
            .iter()
            .find_map(|(known, meta)| (known == address).then_some(meta))
    }

    /// Balance of `token`.
    #[must_use]
    pub fn balance(&self, token: &Address) -> Option<U256> {
        self.balances
            .iter()
            .find_map(|(known, balance)| (known == token).then_some(*balance))
    }

    /// Address-book name of `address`.
    #[must_use]
    pub fn book_name(&self, address: &Address) -> Option<&str> {
        self.address_book
            .iter()
            .find_map(|(known, name)| (known == address).then_some(name.as_str()))
    }
}

#[cfg(test)]
mod tests {
    use super::CodeKind;
    use crate::evm::address::Address;

    #[test]
    fn code_classification() {
        assert_eq!(CodeKind::from_code(&[]), CodeKind::Eoa);
        let mut delegated = vec![0xef, 0x01, 0x00];
        delegated.extend_from_slice(&[0x42; 20]);
        assert_eq!(
            CodeKind::from_code(&delegated),
            CodeKind::Delegated7702 {
                target: Address::from_bytes([0x42; 20])
            }
        );
        delegated.push(0);
        assert_eq!(CodeKind::from_code(&delegated), CodeKind::Contract);
        assert_eq!(CodeKind::from_code(&[0x60, 0x80]), CodeKind::Contract);
    }
}
