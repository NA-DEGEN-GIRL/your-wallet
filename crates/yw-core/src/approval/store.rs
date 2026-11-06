//! Approval digest and one-shot consumption (spec/03 §11.4–§11.5).
//!
//! The constant-time, terminal-on-mismatch `consume` follows
//! `archive/spec-v2.4:crates/wallet-protocol/src/approval.rs:466-541`; the platform window types
//! are replaced by the caller's monotonic `now_ms` (yw-win `time::monotonic_ms`).

use core::fmt;

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::display::DisplayError;
use super::text::RiskLevel;
use super::{
    AccountRef, ApprovalDisplay, ApprovalDraft, ApprovalId, ApprovalKind, ApprovalOrigin,
    ApprovalRequest, ChainRef, Signer, SigningPayload, SimulationBinding,
};
use crate::codec::transcript::{CodecError, Transcript};

/// Approval lifetime after the first Ready display (D23).
pub const APPROVAL_TTL_MS: u64 = 120_000;
/// Approval digest transcript domain.
pub const APPROVAL_DOMAIN: &str = "your-wallet/v3/approval";
const MAX_ENTRIES: usize = 256;

/// Approval store errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalError {
    /// The id is already in the store.
    DuplicateId,
    /// EVM transaction kinds need `Simulated`/`None`, others `NotApplicable`.
    SimulationBindingMismatch,
    /// The payload variant does not match the kind.
    PayloadMismatch,
    /// No request with this id.
    UnknownId,
    /// The request is no longer pending.
    NotPending(ApprovalState),
    /// The deadline passed (the request is now `Expired`).
    Expired,
    /// The shown digest differs (the request is now `Invalidated`).
    DigestMismatch,
    /// `replace` with a different id, kind, origin, chain, account or signer.
    ReplaceMismatch,
    /// The request is blocked (`risk == Blocked`): approve is disabled.
    Blocked,
    /// Too many outstanding requests.
    TooMany,
    /// The display model is invalid.
    Display(DisplayError),
    /// Deadline or encoding overflow.
    Overflow,
}

impl fmt::Display for ApprovalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DuplicateId => "duplicate approval id",
            Self::SimulationBindingMismatch => "simulation binding does not match the kind",
            Self::PayloadMismatch => "payload does not match the kind",
            Self::UnknownId => "unknown approval",
            Self::NotPending(_) => "approval is not pending",
            Self::Expired => "approval expired",
            Self::DigestMismatch => "approval digest mismatch",
            Self::ReplaceMismatch => "replacement does not match the request",
            Self::Blocked => "approval is blocked",
            Self::TooMany => "too many approvals",
            Self::Display(_) => "invalid approval display",
            Self::Overflow => "approval arithmetic overflow",
        })
    }
}

impl std::error::Error for ApprovalError {}

impl From<DisplayError> for ApprovalError {
    fn from(error: DisplayError) -> Self {
        Self::Display(error)
    }
}

impl From<CodecError> for ApprovalError {
    fn from(_: CodecError) -> Self {
        Self::Overflow
    }
}

/// Request state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalState {
    /// Waiting for the user.
    Pending,
    /// Consumed once.
    Consumed,
    /// Rejected.
    Rejected,
    /// Deadline passed.
    Expired,
    /// Digest mismatch or wallet lock.
    Invalidated,
}

/// A one-time approval token (only [`ApprovalStore::consume`] creates one; not `Clone`).
#[derive(Debug, PartialEq, Eq)]
pub struct Approved {
    id: ApprovalId,
    digest: [u8; 32],
    chain: ChainRef,
    account: AccountRef,
    signer: Signer,
    kind: ApprovalKind,
    payload: SigningPayload,
}

impl Approved {
    /// Identifier.
    #[must_use]
    pub const fn id(&self) -> ApprovalId {
        self.id
    }

    /// Approval digest.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Chain.
    #[must_use]
    pub const fn chain(&self) -> ChainRef {
        self.chain
    }

    /// Signing account.
    #[must_use]
    pub const fn account(&self) -> AccountRef {
        self.account
    }

    /// Key source.
    #[must_use]
    pub const fn signer(&self) -> Signer {
        self.signer
    }

    /// Kind.
    #[must_use]
    pub const fn kind(&self) -> ApprovalKind {
        self.kind
    }

    /// Payload.
    #[must_use]
    pub const fn payload(&self) -> &SigningPayload {
        &self.payload
    }

    /// Test-only constructor for signing tests that bypass the store.
    #[cfg(test)]
    pub(crate) const fn for_test(
        chain: ChainRef,
        account: AccountRef,
        signer: Signer,
        kind: ApprovalKind,
        payload: SigningPayload,
    ) -> Self {
        Self {
            id: ApprovalId([1; 16]),
            digest: [0; 32],
            chain,
            account,
            signer,
            kind,
            payload,
        }
    }
}

struct Parts<'a> {
    id: &'a ApprovalId,
    kind: ApprovalKind,
    origin: &'a ApprovalOrigin,
    chain: &'a ChainRef,
    account: &'a AccountRef,
    payload: &'a SigningPayload,
    display: &'a ApprovalDisplay,
    simulation: &'a SimulationBinding,
}

fn digest_parts(parts: &Parts<'_>, expires_unix_ms: u64) -> Result<[u8; 32], ApprovalError> {
    let mut transcript = Transcript::start_domain(APPROVAL_DOMAIN, 1)?;
    transcript.push_bytes(&parts.id.0)?;
    transcript.push_u8(parts.kind.code());
    transcript.push_str(parts.origin.serialized())?;
    match parts.chain {
        ChainRef::Evm { chain_id, genesis } => {
            transcript.push_u8(1);
            transcript.push_u64(*chain_id);
            transcript.push_bytes(genesis)?;
        }
        ChainRef::Solana { cluster, genesis } => {
            transcript.push_u8(2);
            transcript.push_u8(cluster.code());
            transcript.push_bytes(genesis)?;
        }
        ChainRef::Bitcoin { network, genesis } => {
            transcript.push_u8(3);
            transcript.push_u8(*network);
            transcript.push_bytes(genesis)?;
        }
        ChainRef::Zcash { network, genesis } => {
            transcript.push_u8(4);
            transcript.push_u8(*network);
            transcript.push_bytes(genesis)?;
        }
    }
    match parts.account {
        AccountRef::Evm(address) => transcript.push_bytes(address.as_bytes())?,
        AccountRef::Sol(public) => transcript.push_bytes(public)?,
        AccountRef::Bitcoin(public) | AccountRef::Zcash(public) => {
            transcript.push_bytes(public)?;
        }
    }
    transcript.push_bytes(&parts.payload.digest_bytes())?;
    transcript.push_bytes(&parts.display.digest()?)?;
    transcript.push_u8(parts.simulation.tag());
    match parts.simulation {
        SimulationBinding::NotApplicable => {}
        SimulationBinding::Simulated { verdict, block } => {
            transcript.push_u8(*verdict as u8);
            transcript.push_u64(block.number);
            transcript.push_bytes(&block.parent_hash)?;
            transcript.push_u64(block.timestamp);
            transcript.push_bytes(block.base_fee.as_be_bytes())?;
            transcript.push_bytes(&block.sim_digest)?;
        }
        SimulationBinding::None { reason } => transcript.push_u8(*reason as u8),
    }
    transcript.push_u64(expires_unix_ms);
    Ok(Sha256::digest(transcript.as_bytes()).into())
}

/// The approval digest of a draft with the given expiry (spec/03 §11.4).
///
/// # Errors
///
/// [`ApprovalError::Display`] for an invalid display, [`ApprovalError::Overflow`] for encoding.
pub fn approval_digest(
    draft: &ApprovalDraft,
    expires_unix_ms: u64,
) -> Result<[u8; 32], ApprovalError> {
    digest_parts(
        &Parts {
            id: &draft.id,
            kind: draft.kind,
            origin: &draft.origin,
            chain: &draft.chain,
            account: &draft.account,
            payload: &draft.payload,
            display: &draft.display,
            simulation: &draft.simulation,
        },
        expires_unix_ms,
    )
}

/// BTC drafts (spec/08 §10): app origin, `Signer::FromPayload`, a Bitcoin chain whose genesis is
/// the network's pinned hash, a Bitcoin account, and a well-formed `btc_payload` whose network
/// byte is the chain's and whose `has_replaces` matches the kind.
fn btc_draft_ok(draft: &ApprovalDraft) -> bool {
    let (
        SigningPayload::Btc(payload),
        ChainRef::Bitcoin { network, genesis },
        AccountRef::Bitcoin(_),
        ApprovalOrigin::App,
        Signer::FromPayload,
    ) = (
        &draft.payload,
        &draft.chain,
        &draft.account,
        &draft.origin,
        &draft.signer,
    )
    else {
        return false;
    };
    let pinned = crate::btc::BtcNetwork::from_id(*network).map(crate::btc::BtcNetwork::genesis);
    let header = crate::btc::display::payload_header(payload);
    pinned == Some(*genesis)
        && header.is_some_and(|header| {
            header.network == *network
                && header.has_replaces == (draft.kind == ApprovalKind::BtcFeeBump)
        })
}

fn check_draft(draft: &ApprovalDraft) -> Result<(), ApprovalError> {
    let binding_ok = if draft.kind.is_evm_transaction() {
        matches!(
            draft.simulation,
            SimulationBinding::Simulated { .. } | SimulationBinding::None { .. }
        )
    } else {
        draft.simulation == SimulationBinding::NotApplicable
    };
    if !binding_ok {
        return Err(ApprovalError::SimulationBindingMismatch);
    }
    let payload_ok = match draft.kind {
        ApprovalKind::EvmTransaction | ApprovalKind::EvmSpeedUp | ApprovalKind::EvmCancel => {
            matches!(draft.payload, SigningPayload::EvmTx(_))
        }
        // The exact EIP-191 / EIP-712 prefixes, so a message approval can never carry a bare
        // digest or another kind's preimage (signing checks them again).
        ApprovalKind::EvmPersonalSign => matches!(
            &draft.payload,
            SigningPayload::EvmPersonal(preimage)
                if crate::evm::sign::is_personal_preimage(preimage)
        ),
        ApprovalKind::EvmTypedData => matches!(
            &draft.payload,
            SigningPayload::EvmTypedData(preimage)
                if crate::evm::sign::is_typed_data_preimage(preimage)
        ),
        ApprovalKind::SolTransfer => {
            matches!(
                (&draft.payload, &draft.chain, &draft.account, &draft.origin),
                (
                    SigningPayload::SolTransfer(intent),
                    ChainRef::Solana { cluster, .. },
                    AccountRef::Sol(from),
                    ApprovalOrigin::App,
                ) if intent.cluster == *cluster && intent.core.from.as_bytes() == from
            )
        }
        ApprovalKind::BtcSend | ApprovalKind::BtcFeeBump => btc_draft_ok(draft),
        // Zcash sends (spec/12 §9): app origin, the key in the payload, the network's pinned
        // genesis and a payload whose network byte is the chain's.
        ApprovalKind::ZecSend => matches!(
            (&draft.payload, &draft.chain, &draft.account, &draft.origin, &draft.signer),
            (
                SigningPayload::Zec(payload),
                ChainRef::Zcash { network, genesis },
                AccountRef::Zcash(_),
                ApprovalOrigin::App,
                Signer::FromPayload,
            ) if crate::zec::ZecNetwork::from_id(*network).map(crate::zec::ZecNetwork::genesis)
                == Some(*genesis)
                && crate::zec::sign::payload_network(payload) == Some(*network)
        ),
        // dApp messages (spec/07 §19, spec/08 §17): a site origin, the key in the payload, the
        // pinned genesis of the chain and the payload's own key as the account.
        ApprovalKind::SolMessage | ApprovalKind::SolSignIn => matches!(
            (&draft.payload, &draft.chain, &draft.account, &draft.origin, &draft.signer),
            (
                SigningPayload::SolMessage(payload),
                ChainRef::Solana { cluster, genesis },
                AccountRef::Sol(public),
                ApprovalOrigin::Site(_),
                Signer::FromPayload,
            ) if payload.public == *public && *genesis == cluster.genesis()
        ),
        ApprovalKind::BtcMessage => matches!(
            (&draft.payload, &draft.chain, &draft.account, &draft.origin, &draft.signer),
            (
                SigningPayload::BtcMessage(payload),
                ChainRef::Bitcoin { network, genesis },
                AccountRef::Bitcoin(public),
                ApprovalOrigin::Site(_),
                Signer::FromPayload,
            ) if payload.network.id() == *network
                && payload.network.genesis() == *genesis
                && payload.pubkey.compressed().is_ok_and(|key| key == *public)
        ),
    };
    if !payload_ok {
        return Err(ApprovalError::PayloadMismatch);
    }
    draft.display.validate()?;
    Ok(())
}

#[derive(Debug)]
struct Entry {
    request: ApprovalRequest,
    state: ApprovalState,
    deadline_ms: u64,
}

/// Issued approvals: id → (request, state, monotonic deadline).
#[derive(Debug, Default)]
pub struct ApprovalStore {
    entries: Vec<Entry>,
}

impl ApprovalStore {
    /// An empty store.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    fn entry_mut(&mut self, id: ApprovalId) -> Result<&mut Entry, ApprovalError> {
        self.entries
            .iter_mut()
            .find(|entry| entry.request.id == id)
            .ok_or(ApprovalError::UnknownId)
    }

    /// The state of `id`.
    #[must_use]
    pub fn state(&self, id: ApprovalId) -> Option<ApprovalState> {
        self.entries
            .iter()
            .find(|entry| entry.request.id == id)
            .map(|entry| entry.state)
    }

    /// Issues a draft when its Ready content is first shown (spec/03 §11.5).
    ///
    /// # Errors
    ///
    /// [`ApprovalError`] for a duplicate id, a kind/binding or kind/payload mismatch, an invalid
    /// display, or overflow.
    pub fn issue(
        &mut self,
        draft: ApprovalDraft,
        now_ms: u64,
        now_unix_ms: u64,
    ) -> Result<ApprovalRequest, ApprovalError> {
        check_draft(&draft)?;
        if self
            .entries
            .iter()
            .any(|entry| entry.request.id == draft.id)
        {
            return Err(ApprovalError::DuplicateId);
        }
        let deadline_ms = now_ms
            .checked_add(APPROVAL_TTL_MS)
            .ok_or(ApprovalError::Overflow)?;
        let expires_unix_ms = now_unix_ms
            .checked_add(APPROVAL_TTL_MS)
            .ok_or(ApprovalError::Overflow)?;
        let digest = approval_digest(&draft, expires_unix_ms)?;
        if self.entries.len() >= MAX_ENTRIES {
            self.entries
                .retain(|entry| entry.state == ApprovalState::Pending);
            if self.entries.len() >= MAX_ENTRIES {
                return Err(ApprovalError::TooMany);
            }
        }
        let request = ApprovalRequest {
            id: draft.id,
            origin: draft.origin,
            chain: draft.chain,
            account: draft.account,
            signer: draft.signer,
            kind: draft.kind,
            payload: draft.payload,
            display: draft.display,
            simulation: draft.simulation,
            created_unix_ms: now_unix_ms,
            expires_unix_ms,
            digest,
        };
        self.entries.push(Entry {
            request: request.clone(),
            state: ApprovalState::Pending,
            deadline_ms,
        });
        Ok(request)
    }

    /// Replaces a pending request after re-simulation (spec/03 §6.6); times are unchanged.
    ///
    /// # Errors
    ///
    /// [`ApprovalError`] when not pending, the shown digest differs, or the replacement does not
    /// keep id, kind, origin, chain, account and signer.
    pub fn replace(
        &mut self,
        id: ApprovalId,
        shown: [u8; 32],
        new: ApprovalDraft,
    ) -> Result<ApprovalRequest, ApprovalError> {
        check_draft(&new)?;
        let entry = self.entry_mut(id)?;
        if entry.state != ApprovalState::Pending {
            return Err(ApprovalError::NotPending(entry.state));
        }
        if !bool::from(entry.request.digest.ct_eq(&shown)) {
            return Err(ApprovalError::DigestMismatch);
        }
        let current = &entry.request;
        if new.id != id
            || new.kind != current.kind
            || new.origin != current.origin
            || new.chain != current.chain
            || new.account != current.account
            || new.signer != current.signer
        {
            return Err(ApprovalError::ReplaceMismatch);
        }
        let digest = approval_digest(&new, current.expires_unix_ms)?;
        let request = ApprovalRequest {
            id,
            origin: new.origin,
            chain: new.chain,
            account: new.account,
            signer: new.signer,
            kind: new.kind,
            payload: new.payload,
            display: new.display,
            simulation: new.simulation,
            created_unix_ms: current.created_unix_ms,
            expires_unix_ms: current.expires_unix_ms,
            digest,
        };
        entry.request = request.clone();
        Ok(request)
    }

    /// Consumes a pending, unexpired request whose shown digest matches (constant time).
    ///
    /// # Errors
    ///
    /// [`ApprovalError::NotPending`], [`ApprovalError::Expired`] (state → `Expired`),
    /// [`ApprovalError::DigestMismatch`] (state → `Invalidated`), [`ApprovalError::Blocked`].
    pub fn consume(
        &mut self,
        id: ApprovalId,
        shown: [u8; 32],
        now_ms: u64,
    ) -> Result<Approved, ApprovalError> {
        let entry = self.entry_mut(id)?;
        if entry.state != ApprovalState::Pending {
            return Err(ApprovalError::NotPending(entry.state));
        }
        if now_ms >= entry.deadline_ms {
            entry.state = ApprovalState::Expired;
            return Err(ApprovalError::Expired);
        }
        if !bool::from(entry.request.digest.ct_eq(&shown)) {
            entry.state = ApprovalState::Invalidated;
            return Err(ApprovalError::DigestMismatch);
        }
        if entry.request.display.risk == RiskLevel::Blocked {
            return Err(ApprovalError::Blocked);
        }
        entry.state = ApprovalState::Consumed;
        let request = &entry.request;
        Ok(Approved {
            id: request.id,
            digest: request.digest,
            chain: request.chain,
            account: request.account,
            signer: request.signer,
            kind: request.kind,
            payload: request.payload.clone(),
        })
    }

    /// Rejects a pending request.
    pub fn reject(&mut self, id: ApprovalId) {
        if let Ok(entry) = self.entry_mut(id)
            && entry.state == ApprovalState::Pending
        {
            entry.state = ApprovalState::Rejected;
        }
    }

    /// Expires every pending request whose deadline passed; returns their ids.
    pub fn expire_due(&mut self, now_ms: u64) -> Vec<ApprovalId> {
        let mut expired = Vec::new();
        for entry in &mut self.entries {
            if entry.state == ApprovalState::Pending && now_ms >= entry.deadline_ms {
                entry.state = ApprovalState::Expired;
                expired.push(entry.request.id);
            }
        }
        expired
    }

    /// Invalidates every pending request (wallet lock).
    pub fn invalidate_all(&mut self) {
        for entry in &mut self.entries {
            if entry.state == ApprovalState::Pending {
                entry.state = ApprovalState::Invalidated;
            }
        }
    }
}
