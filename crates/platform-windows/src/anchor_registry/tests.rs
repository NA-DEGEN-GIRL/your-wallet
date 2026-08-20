use std::sync::{Arc, Mutex};

use super::*;

const INSTALLATION_ID: [u8; 32] = [0x11; 32];
const COUNTER_IDENTITY: [u8; 32] = [0x31; 32];
const KEY_EPOCH: u64 = 7;
const PROVISIONING_PROOF: [u8; 32] = [0x51; 32];

#[derive(Clone, Debug, Eq, PartialEq)]
enum Event {
    ReadCounterIdentity,
    ReadCounter,
    IncrementCounter,
    IncrementCounterForProvisioning,
    ReadSlot(RegistrySlot, usize),
    WriteSlot(RegistrySlot),
    ReadManifest(usize),
    WriteManifest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FaultTiming {
    Before,
    After,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FaultPlan {
    event_index: usize,
    timing: FaultTiming,
}

#[derive(Debug)]
struct FakeState {
    counter: u64,
    counter_identity: [u8; 32],
    slots: [Option<Vec<u8>>; 2],
    manifest: Option<Vec<u8>>,
    events: Vec<Event>,
    fault: Option<FaultPlan>,
    ambiguous_increment: bool,
    provisioning_consumed: bool,
    fail_manifest_writes: usize,
}

type RegistryFixture = (RegistryAnchorSet, Arc<Mutex<FakeState>>, RegistryIdentity);

impl FakeState {
    const fn empty(counter: u64) -> Self {
        Self {
            counter,
            counter_identity: COUNTER_IDENTITY,
            slots: [None, None],
            manifest: None,
            events: Vec::new(),
            fault: None,
            ambiguous_increment: false,
            provisioning_consumed: false,
            fail_manifest_writes: 0,
        }
    }

    fn record(&mut self, event: Event) -> Option<FaultTiming> {
        let event_index = self.events.len();
        self.events.push(event);
        if self
            .fault
            .is_some_and(|fault| fault.event_index == event_index)
        {
            self.fault.take().map(|fault| fault.timing)
        } else {
            None
        }
    }

    fn clear_events(&mut self) {
        self.events.clear();
        self.fault = None;
    }
}

#[derive(Clone)]
struct FakeCounter(Arc<Mutex<FakeState>>);

impl fmt::Debug for FakeCounter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FakeCounter([REDACTED])")
    }
}

impl sealed::CounterBackendSealed for FakeCounter {}

impl CounterBackend for FakeCounter {
    fn identity(&mut self) -> Result<[u8; 32], CounterBackendError> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| CounterBackendError::Unavailable)?;
        if state.record(Event::ReadCounterIdentity).is_some() {
            return Err(CounterBackendError::Unavailable);
        }
        Ok(state.counter_identity)
    }

    fn read(&mut self) -> Result<u64, CounterBackendError> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| CounterBackendError::Unavailable)?;
        if state.record(Event::ReadCounter).is_some() {
            return Err(CounterBackendError::Unavailable);
        }
        Ok(state.counter)
    }

    fn increment_once(&mut self) -> Result<(), CounterBackendError> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| CounterBackendError::Unavailable)?;
        let fault = state.record(Event::IncrementCounter);
        if fault == Some(FaultTiming::Before) {
            return Err(CounterBackendError::Unavailable);
        }
        state.counter = state
            .counter
            .checked_add(1)
            .ok_or(CounterBackendError::Unavailable)?;
        if state.ambiguous_increment || fault == Some(FaultTiming::After) {
            Err(CounterBackendError::Ambiguous)
        } else {
            Ok(())
        }
    }

    fn increment_once_for_provisioning(
        &mut self,
        evidence: &ProvisioningEvidence,
    ) -> Result<(), CounterBackendError> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| CounterBackendError::Unavailable)?;
        let fault = state.record(Event::IncrementCounterForProvisioning);
        if fault == Some(FaultTiming::Before) {
            return Err(CounterBackendError::Unavailable);
        }
        if state.provisioning_consumed
            || evidence.installation_id != INSTALLATION_ID
            || evidence.key_epoch != KEY_EPOCH
            || evidence.counter_identity != state.counter_identity
            || evidence.baseline_counter != state.counter
            || *evidence.one_time_proof != PROVISIONING_PROOF
        {
            return Err(CounterBackendError::Unavailable);
        }
        state.counter = state
            .counter
            .checked_add(1)
            .ok_or(CounterBackendError::Unavailable)?;
        state.provisioning_consumed = true;
        if fault == Some(FaultTiming::After) {
            Err(CounterBackendError::Ambiguous)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone)]
struct FakeRegistry(Arc<Mutex<FakeState>>);

impl fmt::Debug for FakeRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FakeRegistry([REDACTED])")
    }
}

impl sealed::RegistryBackendSealed for FakeRegistry {}

impl RegistryBackend for FakeRegistry {
    fn read_slot(
        &mut self,
        slot: RegistrySlot,
        max_bytes: usize,
    ) -> Result<Option<Vec<u8>>, RegistryBackendError> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| RegistryBackendError::Unavailable)?;
        if state.record(Event::ReadSlot(slot, max_bytes)).is_some() {
            return Err(RegistryBackendError::Unavailable);
        }
        let bytes = &state.slots[usize::from(slot.byte())];
        if bytes.as_ref().is_some_and(|bytes| bytes.len() > max_bytes) {
            return Err(RegistryBackendError::BoundsExceeded);
        }
        Ok(bytes.clone())
    }

    fn write_slot_durable(
        &mut self,
        slot: RegistrySlot,
        bytes: &[u8],
    ) -> Result<(), RegistryBackendError> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| RegistryBackendError::Unavailable)?;
        let fault = state.record(Event::WriteSlot(slot));
        if fault == Some(FaultTiming::Before) {
            return Err(RegistryBackendError::Unavailable);
        }
        state.slots[usize::from(slot.byte())] = Some(bytes.to_vec());
        if fault == Some(FaultTiming::After) {
            Err(RegistryBackendError::Unavailable)
        } else {
            Ok(())
        }
    }

    fn read_manifest(&mut self, max_bytes: usize) -> Result<Option<Vec<u8>>, RegistryBackendError> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| RegistryBackendError::Unavailable)?;
        if state.record(Event::ReadManifest(max_bytes)).is_some() {
            return Err(RegistryBackendError::Unavailable);
        }
        if state
            .manifest
            .as_ref()
            .is_some_and(|bytes| bytes.len() > max_bytes)
        {
            return Err(RegistryBackendError::BoundsExceeded);
        }
        Ok(state.manifest.clone())
    }

    fn write_manifest_durable(&mut self, bytes: &[u8]) -> Result<(), RegistryBackendError> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| RegistryBackendError::Unavailable)?;
        let fault = state.record(Event::WriteManifest);
        if state.fail_manifest_writes > 0 {
            state.fail_manifest_writes -= 1;
            return Err(RegistryBackendError::Unavailable);
        }
        if fault == Some(FaultTiming::Before) {
            return Err(RegistryBackendError::Unavailable);
        }
        state.manifest = Some(bytes.to_vec());
        if fault == Some(FaultTiming::After) {
            Err(RegistryBackendError::Unavailable)
        } else {
            Ok(())
        }
    }
}

fn identity() -> Result<RegistryIdentity, RegistryError> {
    RegistryIdentity::new(
        INSTALLATION_ID,
        KEY_EPOCH,
        COUNTER_IDENTITY,
        RegistryStoreIds::new([[0x21; 32], [0x22; 32], [0x23; 32], [0x24; 32]])?,
    )
}

fn key() -> Result<RegistryAuthenticationKey, RegistryError> {
    RegistryAuthenticationKey::new([0x41; 32])
}

fn anchor(generation: u64, marker: u8) -> Result<AnchorValue, AnchorError> {
    AnchorValue::from_authenticated_parts(generation, [marker; 32], [marker.wrapping_add(1); 32])
}

fn evidence(baseline_counter: u64) -> ProvisioningEvidence {
    ProvisioningEvidence {
        installation_id: INSTALLATION_ID,
        key_epoch: KEY_EPOCH,
        counter_identity: COUNTER_IDENTITY,
        baseline_counter,
        one_time_proof: Zeroizing::new(PROVISIONING_PROOF),
    }
}

fn fake_backends(
    state: &Arc<Mutex<FakeState>>,
) -> (Box<dyn RegistryBackend>, Box<dyn CounterBackend>) {
    (
        Box::new(FakeRegistry(Arc::clone(state))),
        Box::new(FakeCounter(Arc::clone(state))),
    )
}

fn provisioned(counter: u64) -> Result<RegistryFixture, RegistryError> {
    let state = Arc::new(Mutex::new(FakeState::empty(counter)));
    let identity = identity()?;
    let (registry, physical_counter) = fake_backends(&state);
    let provisioning_evidence = evidence(counter);
    let set = RegistryAnchorSet::provision(
        registry,
        physical_counter,
        identity,
        key()?,
        &provisioning_evidence,
    )?;
    state
        .lock()
        .map_err(|_| RegistryError::BackendUnavailable)?
        .clear_events();
    Ok((set, state, identity))
}

fn opened(
    state: &Arc<Mutex<FakeState>>,
    identity: RegistryIdentity,
) -> Result<RegistryAnchorSet, RegistryError> {
    let (registry, counter) = fake_backends(state);
    RegistryAnchorSet::open(registry, counter, identity, key()?)
}

fn at_sequence_two(baseline_counter: u64) -> Result<RegistryFixture, Box<dyn std::error::Error>> {
    let (set, state, identity) = provisioned(baseline_counter)?;
    let store_id = identity.store_ids.get(RegistryStore::Vault);
    set.bind(RegistryStore::Vault, store_id)?
        .compare_and_advance(store_id, None, anchor(1, 0x61)?)?;
    state
        .lock()
        .map_err(|_| RegistryError::BackendUnavailable)?
        .clear_events();
    Ok((set, state, identity))
}

fn decoded(
    slot: RegistrySlot,
    state: &RegistryState,
    identity: RegistryIdentity,
    authentication_key: &RegistryAuthenticationKey,
) -> Result<DecodedSlot, RegistryError> {
    let bytes = encode_slot(slot, state, authentication_key)?;
    decode_slot(&bytes, slot, identity, authentication_key)
}

#[test]
fn provisioning_is_bound_ordered_and_consumes_the_proof_once()
-> Result<(), Box<dyn std::error::Error>> {
    let baseline_counter = 8;
    let state = Arc::new(Mutex::new(FakeState::empty(baseline_counter)));
    let identity = identity()?;
    let provisioning_evidence = evidence(baseline_counter);
    let (registry, counter) = fake_backends(&state);
    let set =
        RegistryAnchorSet::provision(registry, counter, identity, key()?, &provisioning_evidence)?;

    {
        let state = state
            .lock()
            .map_err(|_| RegistryError::BackendUnavailable)?;
        assert_eq!(state.counter, baseline_counter + 1);
        assert!(state.provisioning_consumed);
        assert_eq!(
            state.events,
            [
                Event::ReadSlot(RegistrySlot::A, SLOT_BYTES),
                Event::ReadSlot(RegistrySlot::B, SLOT_BYTES),
                Event::ReadManifest(MANIFEST_BYTES),
                Event::ReadCounterIdentity,
                Event::ReadCounter,
                Event::WriteSlot(RegistrySlot::A),
                Event::IncrementCounterForProvisioning,
                Event::ReadCounter,
                Event::WriteManifest,
            ]
        );
    }

    let store_id = identity.store_ids.get(RegistryStore::Vault);
    assert_eq!(
        set.bind(RegistryStore::Vault, store_id)?.load(store_id)?,
        None
    );
    Ok(())
}

#[test]
fn provisioning_proof_is_reusable_only_when_the_counter_did_not_advance()
-> Result<(), Box<dyn std::error::Error>> {
    let baseline_counter = 17;
    let state = Arc::new(Mutex::new(FakeState::empty(baseline_counter)));
    state
        .lock()
        .map_err(|_| RegistryError::BackendUnavailable)?
        .fault = Some(FaultPlan {
        event_index: 6,
        timing: FaultTiming::Before,
    });
    let identity = identity()?;
    let provisioning_evidence = evidence(baseline_counter);
    let (registry, counter) = fake_backends(&state);
    let first =
        RegistryAnchorSet::provision(registry, counter, identity, key()?, &provisioning_evidence);
    assert!(matches!(first, Err(RegistryError::CounterUnavailable)));
    {
        let mut state = state
            .lock()
            .map_err(|_| RegistryError::BackendUnavailable)?;
        assert_eq!(state.counter, baseline_counter);
        assert!(!state.provisioning_consumed);
        assert!(state.slots[0].is_some());
        assert!(state.manifest.is_none());
        state.clear_events();
    }

    let (registry, counter) = fake_backends(&state);
    RegistryAnchorSet::provision(registry, counter, identity, key()?, &provisioning_evidence)?;
    let state = state
        .lock()
        .map_err(|_| RegistryError::BackendUnavailable)?;
    assert_eq!(state.counter, baseline_counter + 1);
    assert!(state.provisioning_consumed);
    Ok(())
}

#[test]
fn ambiguous_provisioning_increment_is_resolved_without_retry()
-> Result<(), Box<dyn std::error::Error>> {
    let baseline_counter = 23;
    let state = Arc::new(Mutex::new(FakeState::empty(baseline_counter)));
    state
        .lock()
        .map_err(|_| RegistryError::BackendUnavailable)?
        .fault = Some(FaultPlan {
        event_index: 6,
        timing: FaultTiming::After,
    });
    let identity = identity()?;
    let provisioning_evidence = evidence(baseline_counter);
    let (registry, counter) = fake_backends(&state);
    RegistryAnchorSet::provision(registry, counter, identity, key()?, &provisioning_evidence)?;
    let state = state
        .lock()
        .map_err(|_| RegistryError::BackendUnavailable)?;
    assert_eq!(state.counter, baseline_counter + 1);
    assert!(state.provisioning_consumed);
    assert_eq!(
        state
            .events
            .iter()
            .filter(|event| **event == Event::IncrementCounterForProvisioning)
            .count(),
        1
    );
    Ok(())
}

#[test]
fn evidence_is_bound_to_installation_epoch_counter_identity_and_baseline()
-> Result<(), RegistryError> {
    let identity = identity()?;
    evidence(31).validate(identity, COUNTER_IDENTITY, 31)?;

    let mismatches = [
        ProvisioningEvidence {
            installation_id: [0x12; 32],
            ..evidence(31)
        },
        ProvisioningEvidence {
            key_epoch: KEY_EPOCH + 1,
            ..evidence(31)
        },
        ProvisioningEvidence {
            counter_identity: [0x32; 32],
            ..evidence(31)
        },
        ProvisioningEvidence {
            baseline_counter: 32,
            ..evidence(31)
        },
        ProvisioningEvidence {
            one_time_proof: Zeroizing::new([0; 32]),
            ..evidence(31)
        },
    ];
    for mismatch in &mismatches {
        assert_eq!(
            mismatch.validate(identity, COUNTER_IDENTITY, 31),
            Err(RegistryError::InvalidIdentity)
        );
    }
    Ok(())
}

#[test]
fn deleting_registry_bytes_cannot_reset_consumed_provisioning()
-> Result<(), Box<dyn std::error::Error>> {
    let baseline_counter = 40;
    let (set, state, identity) = provisioned(baseline_counter)?;
    drop(set);
    {
        let mut state = state
            .lock()
            .map_err(|_| RegistryError::BackendUnavailable)?;
        state.slots = [None, None];
        state.manifest = None;
        state.clear_events();
    }
    assert!(matches!(
        opened(&state, identity),
        Err(RegistryError::MissingRegistry)
    ));

    let replayed_evidence = evidence(baseline_counter);
    let (registry, counter) = fake_backends(&state);
    assert!(matches!(
        RegistryAnchorSet::provision(registry, counter, identity, key()?, &replayed_evidence,),
        Err(RegistryError::InvalidIdentity)
    ));

    let privileged_fresh_evidence = evidence(baseline_counter + 1);
    let (registry, counter) = fake_backends(&state);
    assert!(matches!(
        RegistryAnchorSet::provision(
            registry,
            counter,
            identity,
            key()?,
            &privileged_fresh_evidence,
        ),
        Err(RegistryError::CounterUnavailable)
    ));
    let state = state
        .lock()
        .map_err(|_| RegistryError::BackendUnavailable)?;
    assert_eq!(state.counter, baseline_counter + 1);
    assert!(state.provisioning_consumed);
    assert_eq!(
        state
            .events
            .iter()
            .filter(|event| **event == Event::IncrementCounterForProvisioning)
            .count(),
        1
    );
    Ok(())
}

#[test]
fn opening_existing_registry_needs_no_provisioning_evidence_and_bounds_reads()
-> Result<(), Box<dyn std::error::Error>> {
    let (set, state, identity) = provisioned(52)?;
    drop(set);
    let reopened = opened(&state, identity)?;
    {
        let state = state
            .lock()
            .map_err(|_| RegistryError::BackendUnavailable)?;
        assert_eq!(
            state.events,
            [
                Event::ReadCounterIdentity,
                Event::ReadCounter,
                Event::ReadSlot(RegistrySlot::A, SLOT_BYTES),
                Event::ReadSlot(RegistrySlot::B, SLOT_BYTES),
                Event::ReadManifest(MANIFEST_BYTES),
            ]
        );
        assert!(
            !state
                .events
                .contains(&Event::IncrementCounterForProvisioning)
        );
    }
    let store_id = identity.store_ids.get(RegistryStore::Vault);
    assert_eq!(
        reopened
            .bind(RegistryStore::Vault, store_id)?
            .load(store_id)?,
        None
    );
    Ok(())
}

#[test]
fn oversized_slot_and_manifest_are_stable_integrity_failures_across_reopen()
-> Result<(), Box<dyn std::error::Error>> {
    let (set, slot_state, identity) = provisioned(60)?;
    drop(set);
    slot_state
        .lock()
        .map_err(|_| RegistryError::BackendUnavailable)?
        .slots[0] = Some(vec![0_u8; SLOT_BYTES + 1]);
    for _ in 0..2 {
        assert!(matches!(
            opened(&slot_state, identity),
            Err(RegistryError::IntegrityFailure)
        ));
    }

    let (set, manifest_state, identity) = provisioned(70)?;
    drop(set);
    manifest_state
        .lock()
        .map_err(|_| RegistryError::BackendUnavailable)?
        .manifest = Some(vec![0_u8; MANIFEST_BYTES + 1]);
    for _ in 0..2 {
        assert!(matches!(
            opened(&manifest_state, identity),
            Err(RegistryError::IntegrityFailure)
        ));
    }
    Ok(())
}

#[test]
fn successor_changes_exactly_one_bound_entry_by_one_generation()
-> Result<(), Box<dyn std::error::Error>> {
    let identity = identity()?;
    let authentication_key = key()?;
    let old_state = RegistryState::genesis(identity, 90);
    let old = decoded(RegistrySlot::A, &old_state, identity, &authentication_key)?;
    let mut successor_state = old_state;
    successor_state.physical_counter = 91;
    successor_state.global_sequence = 2;
    successor_state.previous_registry_digest = old.digest;
    successor_state.entries[RegistryStore::Vault.index()] = RegistryEntry {
        store: RegistryStore::Vault,
        store_id: identity.store_ids.get(RegistryStore::Vault),
        present: true,
        generation: 1,
        record_digest: [0x71; 32],
        manifest_digest: [0x72; 32],
    };
    let successor = decoded(
        RegistrySlot::B,
        &successor_state,
        identity,
        &authentication_key,
    )?;
    validate_successor(&old, &successor)?;

    let mut no_entry_change = successor_state;
    no_entry_change.entries = old_state.entries;
    assert_eq!(
        validate_successor(
            &old,
            &decoded(
                RegistrySlot::B,
                &no_entry_change,
                identity,
                &authentication_key,
            )?,
        ),
        Err(RegistryError::RollbackDetected)
    );

    let mut two_entry_changes = successor_state;
    two_entry_changes.entries[RegistryStore::NonceLedger.index()] = RegistryEntry {
        store: RegistryStore::NonceLedger,
        store_id: identity.store_ids.get(RegistryStore::NonceLedger),
        present: true,
        generation: 1,
        record_digest: [0x73; 32],
        manifest_digest: [0x74; 32],
    };
    assert_eq!(
        validate_successor(
            &old,
            &decoded(
                RegistrySlot::B,
                &two_entry_changes,
                identity,
                &authentication_key,
            )?,
        ),
        Err(RegistryError::RollbackDetected)
    );

    let mut generation_gap = successor;
    generation_gap.state.entries[RegistryStore::Vault.index()].generation = 2;
    assert_eq!(
        validate_successor(&old, &generation_gap),
        Err(RegistryError::RollbackDetected)
    );

    let mut rebound_store = successor;
    rebound_store.state.entries[RegistryStore::Vault.index()].store_id = [0x7f; 32];
    assert_eq!(
        validate_successor(&old, &rebound_store),
        Err(RegistryError::RollbackDetected)
    );

    let mut changed_identity = successor;
    changed_identity.state.counter_identity = [0x7e; 32];
    assert_eq!(
        validate_successor(&old, &changed_identity),
        Err(RegistryError::RollbackDetected)
    );

    let mut sequence_gap = successor;
    sequence_gap.state.global_sequence = 3;
    assert_eq!(
        validate_successor(&old, &sequence_gap),
        Err(RegistryError::GapDetected)
    );
    Ok(())
}

#[test]
fn sequence_two_current_plus_prepared_future_recovers_and_retries()
-> Result<(), Box<dyn std::error::Error>> {
    let (set, state, identity) = at_sequence_two(100)?;
    state
        .lock()
        .map_err(|_| RegistryError::BackendUnavailable)?
        .fault = Some(FaultPlan {
        event_index: 5,
        timing: FaultTiming::After,
    });
    let store_id = identity.store_ids.get(RegistryStore::NonceLedger);
    let bound = set.bind(RegistryStore::NonceLedger, store_id)?;
    assert_eq!(
        bound.compare_and_advance(store_id, None, anchor(1, 0x75)?),
        Err(AnchorError::Unavailable)
    );

    {
        let state = state
            .lock()
            .map_err(|_| RegistryError::BackendUnavailable)?;
        let slot_a = state.slots[0]
            .as_deref()
            .ok_or(RegistryError::MissingRegistry)?;
        let slot_b = state.slots[1]
            .as_deref()
            .ok_or(RegistryError::MissingRegistry)?;
        assert_eq!(
            decode_slot(slot_a, RegistrySlot::A, identity, &key()?)?
                .state
                .global_sequence,
            3
        );
        assert_eq!(
            decode_slot(slot_b, RegistrySlot::B, identity, &key()?)?
                .state
                .global_sequence,
            2
        );
    }

    let reopened = opened(&state, identity)?;
    let rebound = reopened.bind(RegistryStore::NonceLedger, store_id)?;
    assert_eq!(rebound.load(store_id)?, None);
    rebound.compare_and_advance(store_id, None, anchor(1, 0x75)?)?;
    assert_eq!(rebound.load(store_id)?, Some(anchor(1, 0x75)?));
    Ok(())
}

#[test]
fn every_commit_boundary_after_sequence_one_recovers_deterministically()
-> Result<(), Box<dyn std::error::Error>> {
    let boundaries = [
        Event::ReadCounterIdentity,
        Event::ReadCounter,
        Event::ReadSlot(RegistrySlot::A, SLOT_BYTES),
        Event::ReadSlot(RegistrySlot::B, SLOT_BYTES),
        Event::ReadManifest(MANIFEST_BYTES),
        Event::WriteSlot(RegistrySlot::A),
        Event::IncrementCounter,
        Event::ReadCounter,
        Event::WriteManifest,
    ];

    for (event_index, expected_event) in boundaries.into_iter().enumerate() {
        let event_offset = u64::try_from(event_index)?;
        let (set, state, identity) = at_sequence_two(200 + event_offset * 10)?;
        state
            .lock()
            .map_err(|_| RegistryError::BackendUnavailable)?
            .fault = Some(FaultPlan {
            event_index,
            timing: FaultTiming::After,
        });
        let store_id = identity.store_ids.get(RegistryStore::NonceLedger);
        let bound = set.bind(RegistryStore::NonceLedger, store_id)?;
        let result = bound.compare_and_advance(store_id, None, anchor(1, 0x76)?);
        if event_index == 6 {
            assert_eq!(result, Ok(()));
        } else {
            assert_eq!(result, Err(AnchorError::Unavailable));
        }
        {
            let state = state
                .lock()
                .map_err(|_| RegistryError::BackendUnavailable)?;
            assert_eq!(state.events.get(event_index), Some(&expected_event));
        }

        let reopened = opened(&state, identity)?;
        let loaded = reopened
            .bind(RegistryStore::NonceLedger, store_id)?
            .load(store_id)?;
        if event_index >= 6 {
            assert_eq!(loaded, Some(anchor(1, 0x76)?));
        } else {
            assert_eq!(loaded, None);
        }
    }
    Ok(())
}

#[test]
fn mutating_boundary_failures_before_effect_also_recover_after_sequence_one()
-> Result<(), Box<dyn std::error::Error>> {
    for (event_index, committed) in [(5, false), (6, false), (8, true)] {
        let event_offset = u64::try_from(event_index)?;
        let (set, state, identity) = at_sequence_two(400 + event_offset * 10)?;
        state
            .lock()
            .map_err(|_| RegistryError::BackendUnavailable)?
            .fault = Some(FaultPlan {
            event_index,
            timing: FaultTiming::Before,
        });
        let store_id = identity.store_ids.get(RegistryStore::NonceLedger);
        let bound = set.bind(RegistryStore::NonceLedger, store_id)?;
        assert_eq!(
            bound.compare_and_advance(store_id, None, anchor(1, 0x77)?),
            Err(AnchorError::Unavailable)
        );

        let reopened = opened(&state, identity)?;
        let loaded = reopened
            .bind(RegistryStore::NonceLedger, store_id)?
            .load(store_id)?;
        assert_eq!(
            loaded,
            if committed {
                Some(anchor(1, 0x77)?)
            } else {
                None
            }
        );
    }
    Ok(())
}

#[test]
fn counter_identity_substitution_and_manifest_equivocation_fail_locked()
-> Result<(), Box<dyn std::error::Error>> {
    let (set, state, identity) = provisioned(300)?;
    let store_id = identity.store_ids.get(RegistryStore::Vault);
    state
        .lock()
        .map_err(|_| RegistryError::BackendUnavailable)?
        .counter_identity = [0x7d; 32];
    assert_eq!(
        set.bind(RegistryStore::Vault, store_id)?.load(store_id),
        Err(AnchorError::Rollback)
    );

    state
        .lock()
        .map_err(|_| RegistryError::BackendUnavailable)?
        .counter_identity = COUNTER_IDENTITY;
    {
        let mut coordinator = set
            .coordinator
            .lock()
            .map_err(|_| RegistryError::BackendUnavailable)?;
        let current = coordinator.load_current()?;
        let mut equivocated = manifest_for(current.slot, &current.state, current.digest);
        equivocated.active_slot = current.slot.other();
        let bytes = encode_manifest(equivocated, &coordinator.key)?;
        coordinator
            .backend
            .write_manifest_durable(&bytes)
            .map_err(map_backend)?;
        assert_eq!(
            coordinator.load_current(),
            Err(RegistryError::SameCounterEquivocation)
        );
    }
    Ok(())
}

#[test]
fn commit_prepares_then_increments_exactly_once_then_finalizes()
-> Result<(), Box<dyn std::error::Error>> {
    let (set, state, identity) = provisioned(40)?;
    let store_id = identity.store_ids.get(RegistryStore::Vault);
    let bound = set.bind(RegistryStore::Vault, store_id)?;
    bound.compare_and_advance(store_id, None, anchor(1, 0x51)?)?;

    let state = state
        .lock()
        .map_err(|_| RegistryError::BackendUnavailable)?;
    assert_eq!(
        state
            .events
            .iter()
            .filter(|event| **event == Event::IncrementCounter)
            .count(),
        1
    );
    let write_slot = state
        .events
        .iter()
        .position(|event| *event == Event::WriteSlot(RegistrySlot::B))
        .ok_or(RegistryError::BackendUnavailable)?;
    let increment = state
        .events
        .iter()
        .position(|event| *event == Event::IncrementCounter)
        .ok_or(RegistryError::BackendUnavailable)?;
    let finalize = state
        .events
        .iter()
        .rposition(|event| *event == Event::WriteManifest)
        .ok_or(RegistryError::BackendUnavailable)?;
    assert!(write_slot < increment && increment < finalize);
    Ok(())
}

#[test]
fn ambiguous_increment_rereads_without_retry_and_finalizes()
-> Result<(), Box<dyn std::error::Error>> {
    let (set, state, identity) = provisioned(9)?;
    state
        .lock()
        .map_err(|_| RegistryError::BackendUnavailable)?
        .ambiguous_increment = true;
    let store_id = identity.store_ids.get(RegistryStore::NonceLedger);
    let bound = set.bind(RegistryStore::NonceLedger, store_id)?;
    bound.compare_and_advance(store_id, None, anchor(1, 0x52)?)?;
    {
        let state = state
            .lock()
            .map_err(|_| RegistryError::BackendUnavailable)?;
        assert_eq!(state.counter, 11);
        assert_eq!(
            state
                .events
                .iter()
                .filter(|event| **event == Event::IncrementCounter)
                .count(),
            1
        );
    }
    assert_eq!(bound.load(store_id)?, Some(anchor(1, 0x52)?));
    Ok(())
}

#[test]
fn prepared_future_slot_is_ignored_while_counter_is_old() -> Result<(), Box<dyn std::error::Error>>
{
    let (set, state, identity) = provisioned(3)?;
    let store_id = identity.store_ids.get(RegistryStore::Vault);
    {
        let mut coordinator = set
            .coordinator
            .lock()
            .map_err(|_| RegistryError::BackendUnavailable)?;
        let current = coordinator.load_current()?;
        let mut future = current.state;
        future.physical_counter += 1;
        future.global_sequence += 1;
        future.previous_registry_digest = current.digest;
        future.entries[0] = RegistryEntry {
            store: RegistryStore::Vault,
            store_id,
            present: true,
            generation: 1,
            record_digest: [0x61; 32],
            manifest_digest: [0x62; 32],
        };
        let bytes = encode_slot(RegistrySlot::B, &future, &coordinator.key)?;
        coordinator
            .backend
            .write_slot_durable(RegistrySlot::B, &bytes)
            .map_err(map_backend)?;
    }
    let bound = set.bind(RegistryStore::Vault, store_id)?;
    assert_eq!(bound.load(store_id)?, None);
    assert_eq!(
        state
            .lock()
            .map_err(|_| RegistryError::BackendUnavailable)?
            .counter,
        4
    );
    Ok(())
}

#[test]
fn advanced_counter_with_old_manifest_recovers_matching_slot()
-> Result<(), Box<dyn std::error::Error>> {
    let (set, state, identity) = provisioned(12)?;
    let store_id = identity
        .store_ids
        .get(RegistryStore::SignedCandidateJournal);
    state
        .lock()
        .map_err(|_| RegistryError::BackendUnavailable)?
        .fail_manifest_writes = 1;
    let bound = set.bind(RegistryStore::SignedCandidateJournal, store_id)?;
    assert_eq!(
        bound.compare_and_advance(store_id, None, anchor(1, 0x63)?),
        Err(AnchorError::Unavailable)
    );
    assert_eq!(bound.load(store_id)?, Some(anchor(1, 0x63)?));

    let state = state
        .lock()
        .map_err(|_| RegistryError::BackendUnavailable)?;
    let manifest_bytes = state
        .manifest
        .as_deref()
        .ok_or(RegistryError::MissingRegistry)?;
    let manifest = decode_manifest(manifest_bytes, identity, &key()?)?;
    assert_eq!(manifest.physical_counter, 14);
    assert_eq!(manifest.active_slot, RegistrySlot::B);
    Ok(())
}

#[test]
fn same_counter_equivocation_fails_locked() -> Result<(), Box<dyn std::error::Error>> {
    let (set, _state, _) = provisioned(18)?;
    let mut coordinator = set
        .coordinator
        .lock()
        .map_err(|_| RegistryError::BackendUnavailable)?;
    let current = coordinator.load_current()?;
    let bytes = encode_slot(RegistrySlot::B, &current.state, &coordinator.key)?;
    coordinator
        .backend
        .write_slot_durable(RegistrySlot::B, &bytes)
        .map_err(map_backend)?;
    assert_eq!(
        coordinator.load_current(),
        Err(RegistryError::SameCounterEquivocation)
    );
    Ok(())
}

#[test]
fn counter_gap_and_missing_registry_fail_locked() -> Result<(), Box<dyn std::error::Error>> {
    let (set, state, identity) = provisioned(25)?;
    state
        .lock()
        .map_err(|_| RegistryError::BackendUnavailable)?
        .counter = 28;
    assert_eq!(
        set.coordinator
            .lock()
            .map_err(|_| RegistryError::BackendUnavailable)?
            .load_current(),
        Err(RegistryError::GapDetected)
    );

    let empty_state = Arc::new(Mutex::new(FakeState::empty(1)));
    let mut missing = RegistryCoordinator {
        backend: Box::new(FakeRegistry(Arc::clone(&empty_state))),
        counter: Box::new(FakeCounter(empty_state)),
        identity,
        key: key()?,
    };
    assert_eq!(missing.load_current(), Err(RegistryError::MissingRegistry));
    Ok(())
}

#[test]
fn generation_rollback_and_bound_id_substitution_fail_locked()
-> Result<(), Box<dyn std::error::Error>> {
    let (set, _, identity) = provisioned(30)?;
    let store_id = identity.store_ids.get(RegistryStore::LocalSettings);
    let other_id = identity.store_ids.get(RegistryStore::Vault);
    let bound = set.bind(RegistryStore::LocalSettings, store_id)?;
    bound.compare_and_advance(store_id, None, anchor(1, 0x70)?)?;
    assert_eq!(
        bound.compare_and_advance(store_id, Some(anchor(1, 0x70)?), anchor(1, 0x71)?),
        Err(AnchorError::Rollback)
    );
    assert_eq!(bound.load(other_id), Err(AnchorError::Rollback));
    assert_eq!(
        bound.compare_and_advance(other_id, None, anchor(2, 0x72)?),
        Err(AnchorError::Rollback)
    );
    Ok(())
}

#[test]
fn physical_counter_rollback_fails_locked() -> Result<(), Box<dyn std::error::Error>> {
    let (set, state, identity) = provisioned(30)?;
    let store_id = identity.store_ids.get(RegistryStore::Vault);
    let bound = set.bind(RegistryStore::Vault, store_id)?;
    bound.compare_and_advance(store_id, None, anchor(1, 0x75)?)?;
    state
        .lock()
        .map_err(|_| RegistryError::BackendUnavailable)?
        .counter = 31;
    assert_eq!(bound.load(store_id), Err(AnchorError::Rollback));
    Ok(())
}

#[test]
fn counter_overflow_fails_before_increment() -> Result<(), Box<dyn std::error::Error>> {
    let (set, state, identity) = provisioned(u64::MAX - 1)?;
    let store_id = identity.store_ids.get(RegistryStore::Vault);
    let bound = set.bind(RegistryStore::Vault, store_id)?;
    assert_eq!(
        bound.compare_and_advance(store_id, None, anchor(1, 0x73)?),
        Err(AnchorError::Rollback)
    );
    assert_eq!(
        state
            .lock()
            .map_err(|_| RegistryError::BackendUnavailable)?
            .events
            .iter()
            .filter(|event| **event == Event::IncrementCounter)
            .count(),
        0
    );
    Ok(())
}

#[test]
fn provisioning_counter_overflow_fails_before_any_durable_write()
-> Result<(), Box<dyn std::error::Error>> {
    let state = Arc::new(Mutex::new(FakeState::empty(u64::MAX)));
    let identity = identity()?;
    let provisioning_evidence = evidence(u64::MAX);
    let (registry, counter) = fake_backends(&state);
    assert!(matches!(
        RegistryAnchorSet::provision(registry, counter, identity, key()?, &provisioning_evidence,),
        Err(RegistryError::Overflow)
    ));
    let state = state
        .lock()
        .map_err(|_| RegistryError::BackendUnavailable)?;
    assert_eq!(state.counter, u64::MAX);
    assert_eq!(state.slots, [None, None]);
    assert!(state.manifest.is_none());
    assert!(
        !state
            .events
            .contains(&Event::IncrementCounterForProvisioning)
    );
    Ok(())
}

#[test]
fn sequence_overflow_fails_before_increment() -> Result<(), Box<dyn std::error::Error>> {
    let (set, state, identity) = provisioned(2)?;
    {
        let mut coordinator = set
            .coordinator
            .lock()
            .map_err(|_| RegistryError::BackendUnavailable)?;
        let genesis = coordinator.load_current()?;
        let mut old = genesis.state;
        old.physical_counter = 2;
        old.global_sequence = u64::MAX - 1;
        old.previous_registry_digest = [0x81; 32];
        let old_bytes = encode_slot(RegistrySlot::B, &old, &coordinator.key)?;
        let old_digest = sha256(&old_bytes);
        let mut current = genesis.state;
        current.physical_counter = 3;
        current.global_sequence = u64::MAX;
        current.previous_registry_digest = old_digest;
        current.entries[RegistryStore::Vault.index()] = RegistryEntry {
            store: RegistryStore::Vault,
            store_id: identity.store_ids.get(RegistryStore::Vault),
            present: true,
            generation: 1,
            record_digest: [0x82; 32],
            manifest_digest: [0x83; 32],
        };
        let current_bytes = encode_slot(RegistrySlot::A, &current, &coordinator.key)?;
        let current_digest = sha256(&current_bytes);
        coordinator
            .backend
            .write_slot_durable(RegistrySlot::B, &old_bytes)
            .map_err(map_backend)?;
        coordinator
            .backend
            .write_slot_durable(RegistrySlot::A, &current_bytes)
            .map_err(map_backend)?;
        let manifest_bytes = encode_manifest(
            manifest_for(RegistrySlot::A, &current, current_digest),
            &coordinator.key,
        )?;
        coordinator
            .backend
            .write_manifest_durable(&manifest_bytes)
            .map_err(map_backend)?;
    }
    state
        .lock()
        .map_err(|_| RegistryError::BackendUnavailable)?
        .clear_events();
    let store_id = identity.store_ids.get(RegistryStore::NonceLedger);
    let bound = set.bind(RegistryStore::NonceLedger, store_id)?;
    assert_eq!(
        bound.compare_and_advance(store_id, None, anchor(1, 0x74)?),
        Err(AnchorError::Rollback)
    );
    assert_eq!(
        state
            .lock()
            .map_err(|_| RegistryError::BackendUnavailable)?
            .events
            .iter()
            .filter(|event| **event == Event::IncrementCounter)
            .count(),
        0
    );
    Ok(())
}

#[test]
fn store_generation_overflow_fails_before_prepare_or_increment()
-> Result<(), Box<dyn std::error::Error>> {
    let (set, state, identity) = provisioned(2)?;
    {
        let mut coordinator = set
            .coordinator
            .lock()
            .map_err(|_| RegistryError::BackendUnavailable)?;
        let genesis = coordinator.load_current()?;
        let store_id = identity.store_ids.get(RegistryStore::Vault);
        let mut old = genesis.state;
        old.physical_counter = 2;
        old.global_sequence = 100;
        old.previous_registry_digest = [0x84; 32];
        old.entries[RegistryStore::Vault.index()] = RegistryEntry {
            store: RegistryStore::Vault,
            store_id,
            present: true,
            generation: u64::MAX - 1,
            record_digest: [0x85; 32],
            manifest_digest: [0x86; 32],
        };
        let old_bytes = encode_slot(RegistrySlot::B, &old, &coordinator.key)?;
        let old_digest = sha256(&old_bytes);
        let mut current = old;
        current.physical_counter = 3;
        current.global_sequence = 101;
        current.previous_registry_digest = old_digest;
        current.entries[RegistryStore::Vault.index()] = RegistryEntry {
            store: RegistryStore::Vault,
            store_id,
            present: true,
            generation: u64::MAX,
            record_digest: [0x87; 32],
            manifest_digest: [0x88; 32],
        };
        let current_bytes = encode_slot(RegistrySlot::A, &current, &coordinator.key)?;
        let current_digest = sha256(&current_bytes);
        coordinator
            .backend
            .write_slot_durable(RegistrySlot::B, &old_bytes)
            .map_err(map_backend)?;
        coordinator
            .backend
            .write_slot_durable(RegistrySlot::A, &current_bytes)
            .map_err(map_backend)?;
        let manifest_bytes = encode_manifest(
            manifest_for(RegistrySlot::A, &current, current_digest),
            &coordinator.key,
        )?;
        coordinator
            .backend
            .write_manifest_durable(&manifest_bytes)
            .map_err(map_backend)?;
    }
    state
        .lock()
        .map_err(|_| RegistryError::BackendUnavailable)?
        .clear_events();
    let store_id = identity.store_ids.get(RegistryStore::Vault);
    let bound = set.bind(RegistryStore::Vault, store_id)?;
    assert_eq!(
        bound.compare_and_advance(
            store_id,
            Some(anchor(u64::MAX, 0x87)?),
            anchor(u64::MAX, 0x89)?,
        ),
        Err(AnchorError::Rollback)
    );
    let state = state
        .lock()
        .map_err(|_| RegistryError::BackendUnavailable)?;
    assert!(
        !state
            .events
            .iter()
            .any(|event| matches!(event, Event::WriteSlot(_) | Event::IncrementCounter))
    );
    Ok(())
}

#[test]
fn codec_is_exact_deterministic_bounded_and_tamper_evident()
-> Result<(), Box<dyn std::error::Error>> {
    let identity = identity()?;
    let authentication_key = key()?;
    let state = RegistryState::genesis(identity, 44);
    let first = encode_slot(RegistrySlot::A, &state, &authentication_key)?;
    let second = encode_slot(RegistrySlot::A, &state, &authentication_key)?;
    assert_eq!(first.len(), SLOT_BYTES);
    assert_eq!(first, second);
    assert_eq!(
        decode_slot(&first, RegistrySlot::A, identity, &authentication_key)?.state,
        state
    );

    let mut tampered = first;
    tampered[80] ^= 1;
    assert_eq!(
        decode_slot(&tampered, RegistrySlot::A, identity, &authentication_key),
        Err(RegistryError::IntegrityFailure)
    );
    assert_eq!(
        decode_slot(
            &second[..SLOT_BYTES - 1],
            RegistrySlot::A,
            identity,
            &authentication_key,
        ),
        Err(RegistryError::IntegrityFailure)
    );
    Ok(())
}

#[test]
fn anchor_constructor_rejects_zero_generation_or_digest() {
    assert_eq!(
        AnchorValue::from_authenticated_parts(0, [1; 32], [2; 32]),
        Err(AnchorError::Rollback)
    );
    assert_eq!(
        AnchorValue::from_authenticated_parts(1, [0; 32], [2; 32]),
        Err(AnchorError::Rollback)
    );
    assert_eq!(
        AnchorValue::from_authenticated_parts(1, [1; 32], [0; 32]),
        Err(AnchorError::Rollback)
    );
}

#[test]
fn debug_output_redacts_ids_keys_and_digests() -> Result<(), RegistryError> {
    let identity = identity()?;
    let state = RegistryState::genesis(identity, 4);
    let output = format!("{:?} {:?}", key()?, state);
    assert!(output.contains("[REDACTED]"));
    assert!(output.contains("[SHA-256]"));
    assert!(!output.contains("11111111"));
    assert!(!output.contains("41414141"));
    Ok(())
}
