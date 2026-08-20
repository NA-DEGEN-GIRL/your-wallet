use std::collections::BTreeSet;

use wallet_model::{
    AdapterKind, Address20, BlockAnchor, ChainIdentity, Hash32, NonceLeaseId, U256,
};

use crate::{ErrorField, ProtocolError, ProtocolErrorKind, approval::NonceLeaseBinding};

const DURABLE_MAGIC: &[u8; 4] = b"YWNS";
const DURABLE_VERSION: u16 = 2;
const MAX_CANDIDATES_PER_NONCE: usize = 32;
const LEDGER_MAGIC: &[u8; 4] = b"YWNL";
const LEDGER_VERSION: u16 = 2;
const MAX_LEDGER_SLOTS: usize = 4_096;

/// Stable candidate identifier, normally a digest of the unsigned signing payload.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CandidateId(pub Hash32);

/// Durable transaction-candidate lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateLifecycle {
    /// Nonce is reserved and signing has definitely not begun.
    Reserved,
    /// One non-clone approval lease was issued for this exact candidate.
    ///
    /// The nonce remains quarantined if the approval path crashes or loses the
    /// capability; a second lease is never issued automatically.
    ApprovalPending,
    /// Signing intent was durably recorded; a signature may exist.
    PotentiallySigned,
    /// Signed transaction was journaled but no broadcast began.
    SignedUnbroadcast,
    /// A broadcast call may be in flight.
    Broadcasting,
    /// Broadcast result is unknown, including timeout and crash ambiguity.
    BroadcastUnknown,
    /// At least one endpoint accepted or already knew the transaction.
    Submitted,
}

/// Canonical-chain inclusion observation, independent of finality.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InclusionState {
    /// No canonical inclusion has been observed.
    NotObserved,
    /// Currently included in the named canonical block.
    Included(BlockAnchor),
    /// Monitoring no longer sees this candidate; nonce remains quarantined.
    DroppedCandidate,
    /// A previously observed inclusion was removed by a reorganization.
    Reorged {
        /// Canonical block that previously included this candidate.
        previous: BlockAnchor,
    },
}

/// Finality observation, deliberately separate from inclusion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FinalityState {
    /// Candidate has not reached adapter-defined canonical finality.
    Unfinalized,
    /// Candidate reached canonical finality at this exact anchor.
    Finalized(BlockAnchor),
}

/// Durable candidate for one account/chain nonce.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NonceCandidate {
    account: Address20,
    chain: ChainIdentity,
    nonce: U256,
    lease_id: NonceLeaseId,
    candidate_id: CandidateId,
    replacement_of: Option<CandidateId>,
    lifecycle: CandidateLifecycle,
    signed_transaction_hash: Option<Hash32>,
    inclusion: InclusionState,
    finality: FinalityState,
}

impl NonceCandidate {
    /// Creates a new pre-sign reservation.
    #[must_use]
    pub const fn reserve(
        account: Address20,
        chain: ChainIdentity,
        nonce: U256,
        lease_id: NonceLeaseId,
        candidate_id: CandidateId,
    ) -> Self {
        Self {
            account,
            chain,
            nonce,
            lease_id,
            candidate_id,
            replacement_of: None,
            lifecycle: CandidateLifecycle::Reserved,
            signed_transaction_hash: None,
            inclusion: InclusionState::NotObserved,
            finality: FinalityState::Unfinalized,
        }
    }

    /// Creates a replacement reservation tied to an earlier candidate.
    #[must_use]
    pub const fn reserve_replacement(
        account: Address20,
        chain: ChainIdentity,
        nonce: U256,
        lease_id: NonceLeaseId,
        candidate_id: CandidateId,
        replaces: CandidateId,
    ) -> Self {
        let mut candidate = Self::reserve(account, chain, nonce, lease_id, candidate_id);
        candidate.replacement_of = Some(replaces);
        candidate
    }

    /// Returns the account.
    #[must_use]
    pub const fn account(&self) -> Address20 {
        self.account
    }

    /// Returns the chain fingerprint.
    #[must_use]
    pub const fn chain(&self) -> ChainIdentity {
        self.chain
    }

    /// Returns the account nonce.
    #[must_use]
    pub const fn nonce(&self) -> U256 {
        self.nonce
    }

    /// Returns the durable reservation identifier.
    #[must_use]
    pub const fn lease_id(&self) -> NonceLeaseId {
        self.lease_id
    }

    /// Returns the candidate identifier.
    #[must_use]
    pub const fn candidate_id(&self) -> CandidateId {
        self.candidate_id
    }

    /// Returns the candidate this one replaces.
    #[must_use]
    pub const fn replacement_of(&self) -> Option<CandidateId> {
        self.replacement_of
    }

    /// Returns the broadcast lifecycle.
    #[must_use]
    pub const fn lifecycle(&self) -> CandidateLifecycle {
        self.lifecycle
    }

    /// Returns the signed transaction hash, if signing may have completed and was journaled.
    #[must_use]
    pub const fn signed_transaction_hash(&self) -> Option<Hash32> {
        self.signed_transaction_hash
    }

    /// Returns current inclusion observation.
    #[must_use]
    pub const fn inclusion(&self) -> InclusionState {
        self.inclusion
    }

    /// Returns current finality observation.
    #[must_use]
    pub const fn finality(&self) -> FinalityState {
        self.finality
    }

    /// Durably crosses the point after which automatic nonce reuse is forbidden.
    pub fn mark_signing_intent(&mut self) -> Result<(), ProtocolError> {
        self.require_lifecycle(CandidateLifecycle::ApprovalPending)?;
        self.lifecycle = CandidateLifecycle::PotentiallySigned;
        Ok(())
    }

    fn mark_approval_pending(&mut self) -> Result<(), ProtocolError> {
        self.require_lifecycle(CandidateLifecycle::Reserved)?;
        self.lifecycle = CandidateLifecycle::ApprovalPending;
        Ok(())
    }

    /// Records the signed transaction after the encrypted journal is durable.
    pub fn record_signed(&mut self, transaction_hash: Hash32) -> Result<(), ProtocolError> {
        self.require_lifecycle(CandidateLifecycle::PotentiallySigned)?;
        self.signed_transaction_hash = Some(transaction_hash);
        self.lifecycle = CandidateLifecycle::SignedUnbroadcast;
        Ok(())
    }

    /// Marks the durable state immediately before attempting network broadcast.
    pub fn begin_broadcast(&mut self) -> Result<(), ProtocolError> {
        if !matches!(
            self.lifecycle,
            CandidateLifecycle::SignedUnbroadcast | CandidateLifecycle::BroadcastUnknown
        ) {
            return Err(invalid_transition());
        }
        self.lifecycle = CandidateLifecycle::Broadcasting;
        Ok(())
    }

    /// Records an ambiguous timeout, disconnect, process crash recovery, or RPC response.
    pub fn mark_broadcast_unknown(&mut self) -> Result<(), ProtocolError> {
        self.require_lifecycle(CandidateLifecycle::Broadcasting)?;
        self.lifecycle = CandidateLifecycle::BroadcastUnknown;
        Ok(())
    }

    /// Records RPC acceptance or an already-known response.
    pub fn mark_submitted(&mut self) -> Result<(), ProtocolError> {
        if !matches!(
            self.lifecycle,
            CandidateLifecycle::Broadcasting | CandidateLifecycle::BroadcastUnknown
        ) {
            return Err(invalid_transition());
        }
        self.lifecycle = CandidateLifecycle::Submitted;
        Ok(())
    }

    /// Records current canonical inclusion without claiming finality.
    pub fn observe_inclusion(&mut self, block: BlockAnchor) -> Result<(), ProtocolError> {
        if !self.may_have_signed_transaction() {
            return Err(invalid_transition());
        }
        if let FinalityState::Finalized(finalized) = self.finality
            && finalized != block
        {
            return Err(ProtocolError::new(ProtocolErrorKind::ConflictingFinality));
        }
        self.inclusion = InclusionState::Included(block);
        Ok(())
    }

    /// Records removal of an unfinalized canonical inclusion.
    pub fn observe_reorg(&mut self) -> Result<(), ProtocolError> {
        if self.finality != FinalityState::Unfinalized {
            return Err(ProtocolError::new(ProtocolErrorKind::ConflictingFinality));
        }
        let InclusionState::Included(previous) = self.inclusion else {
            return Err(invalid_transition());
        };
        self.inclusion = InclusionState::Reorged { previous };
        Ok(())
    }

    /// Records a dropped candidate while permanently keeping the nonce quarantined.
    pub fn mark_dropped(&mut self) -> Result<(), ProtocolError> {
        if !self.may_have_signed_transaction()
            || self.finality != FinalityState::Unfinalized
            || matches!(self.inclusion, InclusionState::Included(_))
        {
            return Err(invalid_transition());
        }
        self.inclusion = InclusionState::DroppedCandidate;
        Ok(())
    }

    /// Marks an included candidate finalized at the same canonical block anchor.
    pub fn mark_finalized(&mut self, block: BlockAnchor) -> Result<(), ProtocolError> {
        if self.inclusion != InclusionState::Included(block) {
            return Err(ProtocolError::new(ProtocolErrorKind::ConflictingFinality));
        }
        match self.finality {
            FinalityState::Unfinalized => {
                self.finality = FinalityState::Finalized(block);
                Ok(())
            }
            FinalityState::Finalized(existing) if existing == block => Ok(()),
            FinalityState::Finalized(_) => {
                Err(ProtocolError::new(ProtocolErrorKind::ConflictingFinality))
            }
        }
    }

    /// Releases only a reservation for which signing definitely never began.
    ///
    /// On failure the unchanged candidate is returned, preventing accidental loss
    /// of the durable quarantine record.
    pub fn release_reserved(self) -> Result<ReleasedNonce, Box<Self>> {
        if self.lifecycle != CandidateLifecycle::Reserved
            || self.inclusion != InclusionState::NotObserved
            || self.finality != FinalityState::Unfinalized
        {
            return Err(Box::new(self));
        }
        Ok(ReleasedNonce {
            account: self.account,
            chain: self.chain,
            nonce: self.nonce,
            lease_id: self.lease_id,
        })
    }

    const fn may_have_signed_transaction(&self) -> bool {
        matches!(
            self.lifecycle,
            CandidateLifecycle::SignedUnbroadcast
                | CandidateLifecycle::Broadcasting
                | CandidateLifecycle::BroadcastUnknown
                | CandidateLifecycle::Submitted
        ) && self.signed_transaction_hash.is_some()
    }

    fn require_lifecycle(&self, expected: CandidateLifecycle) -> Result<(), ProtocolError> {
        if self.lifecycle != expected {
            return Err(invalid_transition());
        }
        Ok(())
    }

    fn validate_internal(&self) -> Result<(), ProtocolError> {
        let has_signed_hash = self.signed_transaction_hash.is_some();
        match self.lifecycle {
            CandidateLifecycle::Reserved
            | CandidateLifecycle::ApprovalPending
            | CandidateLifecycle::PotentiallySigned
                if has_signed_hash =>
            {
                return Err(corrupt_record());
            }
            CandidateLifecycle::SignedUnbroadcast
            | CandidateLifecycle::Broadcasting
            | CandidateLifecycle::BroadcastUnknown
            | CandidateLifecycle::Submitted
                if !has_signed_hash =>
            {
                return Err(corrupt_record());
            }
            _ => {}
        }
        match self.finality {
            FinalityState::Finalized(block)
                if self.inclusion != InclusionState::Included(block) =>
            {
                Err(corrupt_record())
            }
            _ => Ok(()),
        }
    }
}

/// Proof that a nonce was released before signing began.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReleasedNonce {
    /// Account.
    pub account: Address20,
    /// Chain identity.
    pub chain: ChainIdentity,
    /// Released nonce.
    pub nonce: U256,
    /// Released lease.
    pub lease_id: NonceLeaseId,
}

/// Opaque proof that the durable nonce ledger owns this exact reservation.
///
/// The fields are private and the type has no public constructor. Preparing a
/// transaction authorization consumes this proof, preventing callers from
/// inventing a lease identifier or changing its nonce.
#[derive(Debug)]
pub struct NonceLease {
    binding: NonceLeaseBinding,
}

impl NonceLease {
    pub(crate) const fn into_binding(self) -> NonceLeaseBinding {
        self.binding
    }
}

/// All known competing candidates for one account/chain nonce.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NonceSlot {
    account: Address20,
    chain: ChainIdentity,
    nonce: U256,
    lease_id: NonceLeaseId,
    candidates: Vec<NonceCandidate>,
    finalized_candidate: Option<CandidateId>,
}

impl NonceSlot {
    /// Starts a durable slot from its first reservation.
    #[must_use]
    pub fn new(initial: NonceCandidate) -> Self {
        Self {
            account: initial.account,
            chain: initial.chain,
            nonce: initial.nonce,
            lease_id: initial.lease_id,
            candidates: vec![initial],
            finalized_candidate: None,
        }
    }

    /// Returns all competing candidates in creation order.
    #[must_use]
    pub fn candidates(&self) -> &[NonceCandidate] {
        &self.candidates
    }

    /// Returns the candidate that consumed the nonce at canonical finality.
    #[must_use]
    pub const fn finalized_candidate(&self) -> Option<CandidateId> {
        self.finalized_candidate
    }

    /// Returns a candidate for monitoring or transition.
    #[must_use]
    pub fn candidate(&self, candidate_id: CandidateId) -> Option<&NonceCandidate> {
        self.candidates
            .iter()
            .find(|candidate| candidate.candidate_id == candidate_id)
    }

    /// Returns a mutable candidate for a validated transition.
    pub fn candidate_mut(&mut self, candidate_id: CandidateId) -> Option<&mut NonceCandidate> {
        self.candidates
            .iter_mut()
            .find(|candidate| candidate.candidate_id == candidate_id)
    }

    /// Adds a pre-sign replacement for an existing candidate.
    pub fn add_replacement(&mut self, replacement: NonceCandidate) -> Result<(), ProtocolError> {
        if self.finalized_candidate.is_some()
            || replacement.account != self.account
            || replacement.chain != self.chain
            || replacement.nonce != self.nonce
            || replacement.lease_id != self.lease_id
            || replacement.lifecycle != CandidateLifecycle::Reserved
            || self.candidate(replacement.candidate_id).is_some()
        {
            return Err(invalid_transition());
        }
        let Some(replaced) = replacement.replacement_of else {
            return Err(invalid_transition());
        };
        if self.candidate(replaced).is_none() || replaced == replacement.candidate_id {
            return Err(invalid_transition());
        }
        if self.candidates.len() >= MAX_CANDIDATES_PER_NONCE {
            return Err(ProtocolError::at(
                ProtocolErrorKind::BoundsExceeded,
                ErrorField::NonceState,
            ));
        }
        self.candidates.push(replacement);
        Ok(())
    }

    /// Returns true when the account nonce remains quarantined by any candidate.
    #[must_use]
    pub fn nonce_consumed_unknown(&self) -> bool {
        self.finalized_candidate.is_none()
            && !self.candidates.is_empty()
            && !matches!(
                self.candidates.as_slice(),
                [candidate]
                    if candidate.lifecycle == CandidateLifecycle::Reserved
                        && candidate.inclusion == InclusionState::NotObserved
                        && candidate.finality == FinalityState::Unfinalized
            )
    }

    /// Marks one included candidate finalized and makes all competitors superseded.
    pub fn finalize_candidate(
        &mut self,
        candidate_id: CandidateId,
        block: BlockAnchor,
    ) -> Result<(), ProtocolError> {
        if let Some(existing) = self.finalized_candidate
            && existing != candidate_id
        {
            return Err(ProtocolError::new(ProtocolErrorKind::ConflictingFinality));
        }
        let candidate = self
            .candidate_mut(candidate_id)
            .ok_or_else(invalid_transition)?;
        candidate.mark_finalized(block)?;
        self.finalized_candidate = Some(candidate_id);
        Ok(())
    }

    /// Returns true only after a competing candidate reached canonical finality.
    #[must_use]
    pub fn is_superseded(&self, candidate_id: CandidateId) -> bool {
        self.finalized_candidate
            .is_some_and(|finalized| finalized != candidate_id)
    }

    /// Automatic reuse is never permitted while a durable slot exists.
    #[must_use]
    #[allow(clippy::unused_self)]
    pub const fn automatic_reuse_permitted(&self) -> bool {
        false
    }

    /// Releases a single untouched reservation, consuming the durable slot.
    pub fn release_single_reserved(mut self) -> Result<ReleasedNonce, Box<Self>> {
        if self.finalized_candidate.is_some()
            || self.candidates.len() != 1
            || self.candidates[0].lifecycle != CandidateLifecycle::Reserved
        {
            return Err(Box::new(self));
        }
        let Some(candidate) = self.candidates.pop() else {
            return Err(Box::new(self));
        };
        match candidate.release_reserved() {
            Ok(released) => Ok(released),
            Err(candidate) => {
                self.candidates.push(*candidate);
                Err(Box::new(self))
            }
        }
    }

    /// Encodes a versioned fixed-width durable record.
    pub fn encode_durable(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate_internal()?;
        let count = u16::try_from(self.candidates.len()).map_err(|_| {
            ProtocolError::at(ProtocolErrorKind::BoundsExceeded, ErrorField::NonceState)
        })?;
        let mut output = Vec::with_capacity(512);
        output.extend_from_slice(DURABLE_MAGIC);
        output.extend_from_slice(&DURABLE_VERSION.to_be_bytes());
        output.extend_from_slice(self.account.as_bytes());
        encode_chain(&mut output, self.chain);
        output.extend_from_slice(self.nonce.as_be_bytes());
        output.extend_from_slice(self.lease_id.as_bytes());
        encode_optional_hash(
            &mut output,
            self.finalized_candidate.map(|candidate| candidate.0),
        );
        output.extend_from_slice(&count.to_be_bytes());
        for candidate in &self.candidates {
            encode_candidate(&mut output, candidate);
        }
        Ok(output)
    }

    /// Decodes and fully validates a durable record before returning it.
    pub fn decode_durable(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let mut cursor = Cursor::new(bytes);
        if cursor.take::<4>()? != *DURABLE_MAGIC {
            return Err(corrupt_record());
        }
        if cursor.read_u16()? != DURABLE_VERSION {
            return Err(corrupt_record());
        }
        let account = Address20::new(cursor.take::<20>()?);
        let chain = decode_chain(&mut cursor)?;
        let nonce = U256::from_be_bytes(cursor.take::<32>()?);
        let lease_id = NonceLeaseId::new(cursor.take::<16>()?);
        let finalized_candidate = decode_optional_hash(&mut cursor)?.map(CandidateId);
        let count = usize::from(cursor.read_u16()?);
        if count == 0 || count > MAX_CANDIDATES_PER_NONCE {
            return Err(corrupt_record());
        }
        let mut candidates = Vec::with_capacity(count);
        for _ in 0..count {
            candidates.push(decode_candidate(
                &mut cursor,
                account,
                chain,
                nonce,
                lease_id,
            )?);
        }
        if !cursor.is_finished() {
            return Err(corrupt_record());
        }
        let slot = Self {
            account,
            chain,
            nonce,
            lease_id,
            candidates,
            finalized_candidate,
        };
        slot.validate_internal()?;
        Ok(slot)
    }

    fn validate_internal(&self) -> Result<(), ProtocolError> {
        if self.candidates.is_empty() || self.candidates.len() > MAX_CANDIDATES_PER_NONCE {
            return Err(corrupt_record());
        }
        let mut prior_ids = BTreeSet::new();
        let mut observed_finalized = None;
        for candidate in &self.candidates {
            candidate.validate_internal()?;
            if candidate.account != self.account
                || candidate.chain != self.chain
                || candidate.nonce != self.nonce
                || candidate.lease_id != self.lease_id
                || !prior_ids.insert(candidate.candidate_id)
            {
                return Err(corrupt_record());
            }
            if let Some(replaced) = candidate.replacement_of
                && (!prior_ids.contains(&replaced) || replaced == candidate.candidate_id)
            {
                return Err(corrupt_record());
            }
            if matches!(candidate.finality, FinalityState::Finalized(_))
                && observed_finalized.replace(candidate.candidate_id).is_some()
            {
                return Err(corrupt_record());
            }
        }
        if observed_finalized != self.finalized_candidate {
            return Err(corrupt_record());
        }
        Ok(())
    }
}

/// Durable collection of quarantined account/chain nonce slots.
///
/// Identity matching intentionally uses chain ID plus genesis hash rather than
/// registry revision, so a registry update cannot make an occupied nonce appear
/// free.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NonceLedger {
    slots: Vec<NonceSlot>,
}

impl NonceLedger {
    /// Creates an empty ledger.
    #[must_use]
    pub const fn new() -> Self {
        Self { slots: Vec::new() }
    }

    /// Returns durable slots in insertion order.
    #[must_use]
    pub fn slots(&self) -> &[NonceSlot] {
        &self.slots
    }

    /// Reserves a previously unused nonce domain.
    pub fn reserve(&mut self, candidate: NonceCandidate) -> Result<(), ProtocolError> {
        if self.slots.len() >= MAX_LEDGER_SLOTS
            || self
                .slot(candidate.account, candidate.chain, candidate.nonce)
                .is_some()
        {
            return Err(invalid_transition());
        }
        self.slots.push(NonceSlot::new(candidate));
        Ok(())
    }

    /// Proves that an exact reservation is present and signing has not begun.
    ///
    /// # Errors
    ///
    /// Returns an invalid-transition error unless the lease identifies the
    /// sole pre-sign candidate for this nonce domain.
    pub fn issue_lease(
        &mut self,
        account: Address20,
        chain: ChainIdentity,
        nonce: U256,
        lease_id: NonceLeaseId,
    ) -> Result<NonceLease, ProtocolError> {
        let slot = self
            .slot_mut(account, chain, nonce)
            .ok_or_else(invalid_transition)?;
        let [candidate] = slot.candidates.as_mut_slice() else {
            return Err(invalid_transition());
        };
        if candidate.lease_id() != lease_id
            || candidate.lifecycle() != CandidateLifecycle::Reserved
            || candidate.inclusion() != InclusionState::NotObserved
            || candidate.finality() != FinalityState::Unfinalized
        {
            return Err(invalid_transition());
        }
        candidate.mark_approval_pending()?;
        Ok(NonceLease {
            binding: NonceLeaseBinding { lease_id, nonce },
        })
    }

    /// Finds a slot by account, chain ID, genesis fingerprint, and nonce.
    #[must_use]
    pub fn slot(
        &self,
        account: Address20,
        chain: ChainIdentity,
        nonce: U256,
    ) -> Option<&NonceSlot> {
        self.slots
            .iter()
            .find(|slot| slot_matches(slot, account, chain, nonce))
    }

    /// Mutably finds a slot by account, chain ID, genesis fingerprint, and nonce.
    pub fn slot_mut(
        &mut self,
        account: Address20,
        chain: ChainIdentity,
        nonce: U256,
    ) -> Option<&mut NonceSlot> {
        self.slots
            .iter_mut()
            .find(|slot| slot_matches(slot, account, chain, nonce))
    }

    /// Releases and removes only a single untouched reservation.
    pub fn release_reserved(
        &mut self,
        account: Address20,
        chain: ChainIdentity,
        nonce: U256,
    ) -> Result<ReleasedNonce, ProtocolError> {
        let Some(index) = self
            .slots
            .iter()
            .position(|slot| slot_matches(slot, account, chain, nonce))
        else {
            return Err(invalid_transition());
        };
        let slot = self.slots.remove(index);
        match slot.release_single_reserved() {
            Ok(released) => Ok(released),
            Err(slot) => {
                self.slots.insert(index, *slot);
                Err(ProtocolError::at(
                    ProtocolErrorKind::UnsafeNonceRelease,
                    ErrorField::NonceState,
                ))
            }
        }
    }

    /// Encodes every slot as a bounded, versioned durable ledger.
    pub fn encode_durable(&self) -> Result<Vec<u8>, ProtocolError> {
        if self.slots.len() > MAX_LEDGER_SLOTS {
            return Err(corrupt_record());
        }
        let slot_count = u32::try_from(self.slots.len()).map_err(|_| corrupt_record())?;
        let mut output = Vec::new();
        output.extend_from_slice(LEDGER_MAGIC);
        output.extend_from_slice(&LEDGER_VERSION.to_be_bytes());
        output.extend_from_slice(&slot_count.to_be_bytes());
        for slot in &self.slots {
            let encoded = slot.encode_durable()?;
            let length = u32::try_from(encoded.len()).map_err(|_| corrupt_record())?;
            output.extend_from_slice(&length.to_be_bytes());
            output.extend_from_slice(&encoded);
        }
        Ok(output)
    }

    /// Decodes a ledger and rejects duplicate nonce domains or malformed slots.
    pub fn decode_durable(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let mut cursor = Cursor::new(bytes);
        if cursor.take::<4>()? != *LEDGER_MAGIC || cursor.read_u16()? != LEDGER_VERSION {
            return Err(corrupt_record());
        }
        let slot_count = usize::try_from(cursor.read_u32()?).map_err(|_| corrupt_record())?;
        if slot_count > MAX_LEDGER_SLOTS {
            return Err(corrupt_record());
        }
        let mut ledger = Self::new();
        for _ in 0..slot_count {
            let length = usize::try_from(cursor.read_u32()?).map_err(|_| corrupt_record())?;
            let record = cursor.take_slice(length)?;
            let slot = NonceSlot::decode_durable(record)?;
            if ledger.slot(slot.account, slot.chain, slot.nonce).is_some() {
                return Err(corrupt_record());
            }
            ledger.slots.push(slot);
        }
        if !cursor.is_finished() {
            return Err(corrupt_record());
        }
        Ok(ledger)
    }
}

fn slot_matches(slot: &NonceSlot, account: Address20, chain: ChainIdentity, nonce: U256) -> bool {
    slot.account == account
        && slot.chain.chain_id() == chain.chain_id()
        && slot.chain.genesis_hash() == chain.genesis_hash()
        && slot.nonce == nonce
}

const fn invalid_transition() -> ProtocolError {
    ProtocolError::at(
        ProtocolErrorKind::InvalidNonceTransition,
        ErrorField::NonceState,
    )
}

const fn corrupt_record() -> ProtocolError {
    ProtocolError::at(
        ProtocolErrorKind::CorruptDurableRecord,
        ErrorField::DurableRecord,
    )
}

fn encode_chain(output: &mut Vec<u8>, chain: ChainIdentity) {
    output.extend_from_slice(chain.chain_id().as_be_bytes());
    output.extend_from_slice(chain.genesis_hash().as_bytes());
    output.push(adapter_tag(chain.adapter()));
    output.extend_from_slice(chain.registry_revision().as_bytes());
}

fn decode_chain(cursor: &mut Cursor<'_>) -> Result<ChainIdentity, ProtocolError> {
    let chain_id = U256::from_be_bytes(cursor.take::<32>()?);
    let genesis_hash = Hash32::new(cursor.take::<32>()?);
    let adapter = decode_adapter(cursor.read_u8()?)?;
    let registry_revision = Hash32::new(cursor.take::<32>()?);
    Ok(ChainIdentity::new(
        chain_id,
        genesis_hash,
        adapter,
        registry_revision,
    ))
}

const fn adapter_tag(adapter: AdapterKind) -> u8 {
    match adapter {
        AdapterKind::EthereumPos => 1,
        AdapterKind::BscParlia => 2,
        AdapterKind::PolygonPos => 3,
        AdapterKind::AvalancheC => 4,
        AdapterKind::OpStack => 5,
        AdapterKind::ArbitrumNitro => 6,
        AdapterKind::GenericEvm155 => 7,
    }
}

const fn decode_adapter(tag: u8) -> Result<AdapterKind, ProtocolError> {
    match tag {
        1 => Ok(AdapterKind::EthereumPos),
        2 => Ok(AdapterKind::BscParlia),
        3 => Ok(AdapterKind::PolygonPos),
        4 => Ok(AdapterKind::AvalancheC),
        5 => Ok(AdapterKind::OpStack),
        6 => Ok(AdapterKind::ArbitrumNitro),
        7 => Ok(AdapterKind::GenericEvm155),
        _ => Err(corrupt_record()),
    }
}

fn encode_candidate(output: &mut Vec<u8>, candidate: &NonceCandidate) {
    output.extend_from_slice(candidate.candidate_id.0.as_bytes());
    encode_optional_hash(
        output,
        candidate.replacement_of.map(|replacement| replacement.0),
    );
    output.push(lifecycle_tag(candidate.lifecycle));
    encode_optional_hash(output, candidate.signed_transaction_hash);
    encode_inclusion(output, candidate.inclusion);
    encode_finality(output, candidate.finality);
}

fn decode_candidate(
    cursor: &mut Cursor<'_>,
    account: Address20,
    chain: ChainIdentity,
    nonce: U256,
    lease_id: NonceLeaseId,
) -> Result<NonceCandidate, ProtocolError> {
    let candidate_id = CandidateId(Hash32::new(cursor.take::<32>()?));
    let replacement_of = decode_optional_hash(cursor)?.map(CandidateId);
    let lifecycle = decode_lifecycle(cursor.read_u8()?)?;
    let signed_transaction_hash = decode_optional_hash(cursor)?;
    let inclusion = decode_inclusion(cursor)?;
    let finality = decode_finality(cursor)?;
    Ok(NonceCandidate {
        account,
        chain,
        nonce,
        lease_id,
        candidate_id,
        replacement_of,
        lifecycle,
        signed_transaction_hash,
        inclusion,
        finality,
    })
}

const fn lifecycle_tag(lifecycle: CandidateLifecycle) -> u8 {
    match lifecycle {
        CandidateLifecycle::Reserved => 0,
        CandidateLifecycle::ApprovalPending => 1,
        CandidateLifecycle::PotentiallySigned => 2,
        CandidateLifecycle::SignedUnbroadcast => 3,
        CandidateLifecycle::Broadcasting => 4,
        CandidateLifecycle::BroadcastUnknown => 5,
        CandidateLifecycle::Submitted => 6,
    }
}

const fn decode_lifecycle(tag: u8) -> Result<CandidateLifecycle, ProtocolError> {
    match tag {
        0 => Ok(CandidateLifecycle::Reserved),
        1 => Ok(CandidateLifecycle::ApprovalPending),
        2 => Ok(CandidateLifecycle::PotentiallySigned),
        3 => Ok(CandidateLifecycle::SignedUnbroadcast),
        4 => Ok(CandidateLifecycle::Broadcasting),
        5 => Ok(CandidateLifecycle::BroadcastUnknown),
        6 => Ok(CandidateLifecycle::Submitted),
        _ => Err(corrupt_record()),
    }
}

fn encode_optional_hash(output: &mut Vec<u8>, value: Option<Hash32>) {
    match value {
        Some(hash) => {
            output.push(1);
            output.extend_from_slice(hash.as_bytes());
        }
        None => output.push(0),
    }
}

fn decode_optional_hash(cursor: &mut Cursor<'_>) -> Result<Option<Hash32>, ProtocolError> {
    match cursor.read_u8()? {
        0 => Ok(None),
        1 => Ok(Some(Hash32::new(cursor.take::<32>()?))),
        _ => Err(corrupt_record()),
    }
}

fn encode_block(output: &mut Vec<u8>, block: BlockAnchor) {
    output.extend_from_slice(block.number.as_be_bytes());
    output.extend_from_slice(block.hash.as_bytes());
}

fn decode_block(cursor: &mut Cursor<'_>) -> Result<BlockAnchor, ProtocolError> {
    Ok(BlockAnchor {
        number: U256::from_be_bytes(cursor.take::<32>()?),
        hash: Hash32::new(cursor.take::<32>()?),
    })
}

fn encode_inclusion(output: &mut Vec<u8>, inclusion: InclusionState) {
    match inclusion {
        InclusionState::NotObserved => output.push(0),
        InclusionState::Included(block) => {
            output.push(1);
            encode_block(output, block);
        }
        InclusionState::DroppedCandidate => output.push(2),
        InclusionState::Reorged { previous } => {
            output.push(3);
            encode_block(output, previous);
        }
    }
}

fn decode_inclusion(cursor: &mut Cursor<'_>) -> Result<InclusionState, ProtocolError> {
    match cursor.read_u8()? {
        0 => Ok(InclusionState::NotObserved),
        1 => Ok(InclusionState::Included(decode_block(cursor)?)),
        2 => Ok(InclusionState::DroppedCandidate),
        3 => Ok(InclusionState::Reorged {
            previous: decode_block(cursor)?,
        }),
        _ => Err(corrupt_record()),
    }
}

fn encode_finality(output: &mut Vec<u8>, finality: FinalityState) {
    match finality {
        FinalityState::Unfinalized => output.push(0),
        FinalityState::Finalized(block) => {
            output.push(1);
            encode_block(output, block);
        }
    }
}

fn decode_finality(cursor: &mut Cursor<'_>) -> Result<FinalityState, ProtocolError> {
    match cursor.read_u8()? {
        0 => Ok(FinalityState::Unfinalized),
        1 => Ok(FinalityState::Finalized(decode_block(cursor)?)),
        _ => Err(corrupt_record()),
    }
}

#[derive(Debug)]
struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], ProtocolError> {
        let end = self.offset.checked_add(N).ok_or_else(corrupt_record)?;
        let Some(slice) = self.bytes.get(self.offset..end) else {
            return Err(corrupt_record());
        };
        let mut output = [0_u8; N];
        output.copy_from_slice(slice);
        self.offset = end;
        Ok(output)
    }

    fn read_u8(&mut self) -> Result<u8, ProtocolError> {
        Ok(self.take::<1>()?[0])
    }

    fn read_u16(&mut self) -> Result<u16, ProtocolError> {
        Ok(u16::from_be_bytes(self.take::<2>()?))
    }

    fn read_u32(&mut self) -> Result<u32, ProtocolError> {
        Ok(u32::from_be_bytes(self.take::<4>()?))
    }

    fn take_slice(&mut self, length: usize) -> Result<&'a [u8], ProtocolError> {
        let end = self.offset.checked_add(length).ok_or_else(corrupt_record)?;
        let Some(slice) = self.bytes.get(self.offset..end) else {
            return Err(corrupt_record());
        };
        self.offset = end;
        Ok(slice)
    }

    fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use wallet_model::{
        AdapterKind, Address20, BlockAnchor, ChainIdentity, Hash32, NonceLeaseId, U256,
    };

    use super::{
        CandidateId, CandidateLifecycle, FinalityState, InclusionState, NonceCandidate,
        NonceLedger, NonceSlot,
    };
    use crate::{ProtocolError, ProtocolErrorKind};

    fn chain() -> ChainIdentity {
        ChainIdentity::new(
            U256::from(1),
            Hash32::new([1; 32]),
            AdapterKind::EthereumPos,
            Hash32::new([2; 32]),
        )
    }

    fn candidate(id: u8) -> NonceCandidate {
        NonceCandidate::reserve(
            Address20::new([3; 20]),
            chain(),
            U256::from(4),
            NonceLeaseId::new([5; 16]),
            CandidateId(Hash32::new([id; 32])),
        )
    }

    fn block(number: u64, id: u8) -> BlockAnchor {
        BlockAnchor {
            number: U256::from(number),
            hash: Hash32::new([id; 32]),
        }
    }

    fn begin_signing(candidate: &mut NonceCandidate) -> Result<(), ProtocolError> {
        candidate.mark_approval_pending()?;
        candidate.mark_signing_intent()
    }

    #[test]
    fn happy_path_preserves_separate_inclusion_and_finality() -> Result<(), ProtocolError> {
        let mut candidate = candidate(6);
        begin_signing(&mut candidate)?;
        candidate.record_signed(Hash32::new([7; 32]))?;
        candidate.begin_broadcast()?;
        candidate.mark_submitted()?;
        candidate.observe_inclusion(block(10, 8))?;
        assert_eq!(candidate.lifecycle(), CandidateLifecycle::Submitted);
        assert_eq!(
            candidate.inclusion(),
            InclusionState::Included(block(10, 8))
        );
        assert_eq!(candidate.finality(), FinalityState::Unfinalized);
        candidate.mark_finalized(block(10, 8))?;
        assert_eq!(candidate.finality(), FinalityState::Finalized(block(10, 8)));
        Ok(())
    }

    #[test]
    fn only_reserved_candidate_can_be_released() -> Result<(), ProtocolError> {
        assert!(candidate(1).release_reserved().is_ok());
        let mut possibly_signed = candidate(2);
        begin_signing(&mut possibly_signed)?;
        assert!(possibly_signed.release_reserved().is_err());
        Ok(())
    }

    #[test]
    fn timeout_drop_and_reorg_never_allow_automatic_reuse() -> Result<(), ProtocolError> {
        let mut dropped_candidate = candidate(1);
        begin_signing(&mut dropped_candidate)?;
        dropped_candidate.record_signed(Hash32::new([7; 32]))?;
        dropped_candidate.begin_broadcast()?;
        dropped_candidate.mark_broadcast_unknown()?;
        dropped_candidate.mark_dropped()?;
        let slot = NonceSlot::new(dropped_candidate);
        assert!(!slot.automatic_reuse_permitted());
        assert!(slot.nonce_consumed_unknown());

        let mut reorged = candidate(2);
        begin_signing(&mut reorged)?;
        reorged.record_signed(Hash32::new([8; 32]))?;
        reorged.begin_broadcast()?;
        reorged.mark_submitted()?;
        reorged.observe_inclusion(block(11, 9))?;
        reorged.observe_reorg()?;
        let slot = NonceSlot::new(reorged);
        assert!(!slot.automatic_reuse_permitted());
        assert!(slot.nonce_consumed_unknown());
        Ok(())
    }

    #[test]
    fn untouched_reservation_is_not_reported_as_consumed_unknown() {
        let slot = NonceSlot::new(candidate(1));
        assert!(!slot.nonce_consumed_unknown());
    }

    #[test]
    fn lease_proof_requires_the_exact_untouched_reservation() -> Result<(), ProtocolError> {
        let mut ledger = NonceLedger::new();
        ledger.reserve(candidate(1))?;
        let lease = ledger.issue_lease(
            Address20::new([3; 20]),
            chain(),
            U256::from(4),
            NonceLeaseId::new([5; 16]),
        )?;
        let binding = lease.into_binding();
        assert_eq!(binding.lease_id(), NonceLeaseId::new([5; 16]));
        assert_eq!(binding.nonce(), U256::from(4));

        let slot = ledger
            .slot_mut(Address20::new([3; 20]), chain(), U256::from(4))
            .ok_or_else(|| ProtocolError::new(ProtocolErrorKind::InvalidNonceTransition))?;
        slot.candidate_mut(CandidateId(Hash32::new([1; 32])))
            .ok_or_else(|| ProtocolError::new(ProtocolErrorKind::InvalidNonceTransition))?
            .mark_signing_intent()?;
        assert!(
            ledger
                .issue_lease(
                    Address20::new([3; 20]),
                    chain(),
                    U256::from(4),
                    NonceLeaseId::new([5; 16]),
                )
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn replacement_supersedes_only_at_finality() -> Result<(), ProtocolError> {
        let first = candidate(1);
        let first_id = first.candidate_id();
        let mut slot = NonceSlot::new(first);
        let replacement_id = CandidateId(Hash32::new([2; 32]));
        let replacement = NonceCandidate::reserve_replacement(
            Address20::new([3; 20]),
            chain(),
            U256::from(4),
            NonceLeaseId::new([5; 16]),
            replacement_id,
            first_id,
        );
        slot.add_replacement(replacement)?;
        {
            let candidate = slot
                .candidate_mut(replacement_id)
                .ok_or_else(|| ProtocolError::new(ProtocolErrorKind::InvalidNonceTransition))?;
            begin_signing(candidate)?;
            candidate.record_signed(Hash32::new([9; 32]))?;
            candidate.begin_broadcast()?;
            candidate.mark_submitted()?;
            candidate.observe_inclusion(block(20, 10))?;
        }
        assert!(!slot.is_superseded(first_id));
        slot.finalize_candidate(replacement_id, block(20, 10))?;
        assert!(slot.is_superseded(first_id));
        assert!(!slot.is_superseded(replacement_id));
        Ok(())
    }

    #[test]
    fn durable_round_trip_preserves_quarantine_state() -> Result<(), ProtocolError> {
        let mut candidate = candidate(1);
        begin_signing(&mut candidate)?;
        candidate.record_signed(Hash32::new([9; 32]))?;
        candidate.begin_broadcast()?;
        candidate.mark_broadcast_unknown()?;
        let slot = NonceSlot::new(candidate);
        let encoded = slot.encode_durable()?;
        let decoded = NonceSlot::decode_durable(&encoded)?;
        assert_eq!(decoded, slot);
        assert!(!decoded.automatic_reuse_permitted());
        Ok(())
    }

    #[test]
    fn durable_decoder_rejects_every_single_byte_truncation() -> Result<(), ProtocolError> {
        let encoded = NonceSlot::new(candidate(1)).encode_durable()?;
        for length in 0..encoded.len() {
            assert!(NonceSlot::decode_durable(&encoded[..length]).is_err());
        }
        Ok(())
    }

    #[test]
    fn invalid_transitions_fail_closed() -> Result<(), ProtocolError> {
        let mut candidate = candidate(1);
        assert_eq!(
            candidate.begin_broadcast(),
            Err(ProtocolError::at(
                ProtocolErrorKind::InvalidNonceTransition,
                crate::ErrorField::NonceState,
            ))
        );
        assert!(candidate.mark_signing_intent().is_err());
        candidate.mark_approval_pending()?;
        candidate.mark_signing_intent()?;
        assert!(candidate.mark_submitted().is_err());
        Ok(())
    }

    #[test]
    fn ledger_does_not_free_a_signed_or_dropped_nonce() -> Result<(), ProtocolError> {
        let mut ledger = NonceLedger::new();
        ledger.reserve(candidate(1))?;
        {
            let slot = ledger
                .slot_mut(Address20::new([3; 20]), chain(), U256::from(4))
                .ok_or_else(|| ProtocolError::new(ProtocolErrorKind::InvalidNonceTransition))?;
            let candidate = slot
                .candidate_mut(CandidateId(Hash32::new([1; 32])))
                .ok_or_else(|| ProtocolError::new(ProtocolErrorKind::InvalidNonceTransition))?;
            begin_signing(candidate)?;
        }
        assert_eq!(
            ledger.release_reserved(Address20::new([3; 20]), chain(), U256::from(4)),
            Err(ProtocolError::at(
                ProtocolErrorKind::UnsafeNonceRelease,
                crate::ErrorField::NonceState,
            ))
        );
        assert_eq!(ledger.slots().len(), 1);
        Ok(())
    }

    #[test]
    fn ledger_round_trip_and_registry_revision_alias_protection() -> Result<(), ProtocolError> {
        let mut ledger = NonceLedger::new();
        ledger.reserve(candidate(1))?;
        let updated_registry_chain = ChainIdentity::new(
            U256::from(1),
            Hash32::new([1; 32]),
            AdapterKind::EthereumPos,
            Hash32::new([99; 32]),
        );
        assert!(
            ledger
                .slot(
                    Address20::new([3; 20]),
                    updated_registry_chain,
                    U256::from(4),
                )
                .is_some()
        );
        assert!(
            ledger
                .reserve(NonceCandidate::reserve(
                    Address20::new([3; 20]),
                    updated_registry_chain,
                    U256::from(4),
                    NonceLeaseId::new([6; 16]),
                    CandidateId(Hash32::new([2; 32])),
                ))
                .is_err()
        );
        let encoded = ledger.encode_durable()?;
        assert_eq!(NonceLedger::decode_durable(&encoded)?, ledger);
        Ok(())
    }
}
