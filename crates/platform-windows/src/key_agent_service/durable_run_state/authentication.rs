//! Installation-bound authentication for the exact durable run-state pair.
//!
//! Production deliberately has no way to mint this provider yet. The sealed
//! backend is uninhabited outside tests so callers cannot substitute raw key
//! bytes or obtain a general-purpose MAC oracle while the protected-key
//! adapter remains pending.

#[cfg(not(test))]
use std::convert::Infallible;
use std::fmt;
use std::num::NonZeroU64;

#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(test)]
use hmac::{Hmac, Mac};
use sha2::{Digest as _, Sha256};
#[cfg(test)]
use zeroize::Zeroizing;

use super::{
    CHECKPOINT_CURRENT_OFFSET, CHECKPOINT_GENERATION_OFFSET, CHECKPOINT_INSTALLATION_OFFSET,
    CHECKPOINT_PREDECESSOR_OFFSET, CHECKPOINT_RESERVED_OFFSET, CHECKPOINT_VERSION_OFFSET,
    COMMITMENT_BYTES, CanonicalSnapshot, Commitment, DurableSnapshot, FixedObservation,
    HIGH_WATER_BODY_BYTES, HIGH_WATER_BYTES, INSTALLATION_IDENTITY_BYTES, InstallationIdentity,
    MAC_BYTES, MARKER_CURRENT_OFFSET, MARKER_GENERATION_OFFSET, MARKER_INSTALLATION_OFFSET,
    MARKER_PREDECESSOR_OFFSET, MARKER_RESERVED_OFFSET, MARKER_STATE_OFFSET, MARKER_VERSION_OFFSET,
    RUN_MARKER_BODY_BYTES, RUN_MARKER_BYTES, RecoveryRequired, RunMarkerState, SnapshotObservation,
    VerifiedHighWaterCheckpoint, VerifiedRunMarker,
};

#[cfg(test)]
type HmacSha256 = Hmac<Sha256>;

const RUN_MARKER_MAGIC_V1: &[u8; 8] = b"YWRUNV01";
const HIGH_WATER_MAGIC_V1: &[u8; 8] = b"YWHIWV01";
const RUN_STATE_SCHEMA_V1: u16 = 1;
const RUN_MARKER_RESERVED_V1: u8 = 0;
const HIGH_WATER_RESERVED_V1: u16 = 0;
const RUN_MARKER_COMMITMENT_DOMAIN_V1: &[u8] =
    b"your-wallet/windows-key-agent/run-marker/commitment/v1\0";
#[cfg(test)]
const RUN_MARKER_MAC_DOMAIN_V1: &[u8] = b"your-wallet/windows-key-agent/run-marker/mac/v1\0";
#[cfg(test)]
const HIGH_WATER_MAC_DOMAIN_V1: &[u8] = b"your-wallet/windows-key-agent/run-high-water/mac/v1\0";

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct RunStateProviderIdentity(NonZeroU64);

impl fmt::Debug for RunStateProviderIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RunStateProviderIdentity([REDACTED])")
    }
}

enum SealedAuthenticationBackend {
    #[cfg(test)]
    Fixture(Zeroizing<[u8; MAC_BYTES]>),
    #[cfg(not(test))]
    Unavailable(Infallible),
}

/// Installation-bound, fixed-purpose run-state authentication authority.
///
/// The private backend has no production constructor. It never exposes key
/// material, a raw backend, or a caller-selected authentication domain.
pub(in crate::key_agent_service) struct RunStateAuthenticationProvider {
    installation: InstallationIdentity,
    identity: RunStateProviderIdentity,
    backend: SealedAuthenticationBackend,
}

/// Move-only installation-bound authentication authority for one runtime
/// writer lifecycle.
pub(in crate::key_agent_service) struct RuntimeRunStateAuthority<'provider> {
    provider: &'provider RunStateAuthenticationProvider,
    identity: RunStateProviderIdentity,
}

#[cfg(test)]
static NEXT_PROVIDER_IDENTITY: AtomicU64 = AtomicU64::new(1);

#[cfg(test)]
fn allocate_provider_identity() -> Result<RunStateProviderIdentity, RecoveryRequired> {
    let value = NEXT_PROVIDER_IDENTITY
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .map_err(|_| RecoveryRequired::BackendBindingExhausted)?;
    NonZeroU64::new(value)
        .map(RunStateProviderIdentity)
        .ok_or(RecoveryRequired::BackendBindingExhausted)
}

impl RunStateAuthenticationProvider {
    /// Mints one installation-bound provider for the bounded test fixture.
    ///
    /// # Errors
    ///
    /// Returns recovery-required evidence for the all-zero key sentinel or an
    /// exhausted bounded provider identity allocator.
    #[cfg(test)]
    pub(in crate::key_agent_service) fn from_fixture_bytes(
        installation: InstallationIdentity,
        bytes: [u8; MAC_BYTES],
    ) -> Result<Self, RecoveryRequired> {
        if bytes == [0; MAC_BYTES] {
            return Err(RecoveryRequired::InvalidFixtureAuthenticationKey);
        }
        Ok(Self {
            installation,
            identity: allocate_provider_identity()?,
            backend: SealedAuthenticationBackend::Fixture(Zeroizing::new(bytes)),
        })
    }

    /// Returns the exact installation identity sealed into this provider.
    pub(super) const fn installation(&self) -> InstallationIdentity {
        self.installation
    }

    /// Mints a move-only authority bound to this exact provider identity.
    pub(in crate::key_agent_service) const fn runtime_authority(
        &mut self,
    ) -> RuntimeRunStateAuthority<'_> {
        RuntimeRunStateAuthority {
            provider: self,
            identity: self.identity,
        }
    }

    pub(super) const fn identity(&self) -> RunStateProviderIdentity {
        self.identity
    }

    #[cfg_attr(not(test), allow(unused_variables))]
    fn sign_marker_body(&self, body: &[u8]) -> Result<[u8; MAC_BYTES], RecoveryRequired> {
        match &self.backend {
            #[cfg(test)]
            SealedAuthenticationBackend::Fixture(key) => {
                let mut mac = HmacSha256::new_from_slice(key.as_ref())
                    .map_err(|_| RecoveryRequired::InvalidFixtureAuthenticationKey)?;
                mac.update(RUN_MARKER_MAC_DOMAIN_V1);
                mac.update(body);
                Ok(mac.finalize().into_bytes().into())
            }
            #[cfg(not(test))]
            SealedAuthenticationBackend::Unavailable(never) => match *never {},
        }
    }

    #[cfg_attr(not(test), allow(unused_variables))]
    fn verify_marker_body(&self, body: &[u8], tag: &[u8]) -> Result<(), RecoveryRequired> {
        match &self.backend {
            #[cfg(test)]
            SealedAuthenticationBackend::Fixture(key) => {
                let mut mac = HmacSha256::new_from_slice(key.as_ref())
                    .map_err(|_| RecoveryRequired::InvalidFixtureAuthenticationKey)?;
                mac.update(RUN_MARKER_MAC_DOMAIN_V1);
                mac.update(body);
                mac.verify_slice(tag)
                    .map_err(|_| RecoveryRequired::AuthenticationFailed)
            }
            #[cfg(not(test))]
            SealedAuthenticationBackend::Unavailable(never) => match *never {},
        }
    }

    #[cfg_attr(not(test), allow(unused_variables))]
    fn sign_checkpoint_body(&self, body: &[u8]) -> Result<[u8; MAC_BYTES], RecoveryRequired> {
        match &self.backend {
            #[cfg(test)]
            SealedAuthenticationBackend::Fixture(key) => {
                let mut mac = HmacSha256::new_from_slice(key.as_ref())
                    .map_err(|_| RecoveryRequired::InvalidFixtureAuthenticationKey)?;
                mac.update(HIGH_WATER_MAC_DOMAIN_V1);
                mac.update(body);
                Ok(mac.finalize().into_bytes().into())
            }
            #[cfg(not(test))]
            SealedAuthenticationBackend::Unavailable(never) => match *never {},
        }
    }

    #[cfg_attr(not(test), allow(unused_variables))]
    fn verify_checkpoint_body(&self, body: &[u8], tag: &[u8]) -> Result<(), RecoveryRequired> {
        match &self.backend {
            #[cfg(test)]
            SealedAuthenticationBackend::Fixture(key) => {
                let mut mac = HmacSha256::new_from_slice(key.as_ref())
                    .map_err(|_| RecoveryRequired::InvalidFixtureAuthenticationKey)?;
                mac.update(HIGH_WATER_MAC_DOMAIN_V1);
                mac.update(body);
                mac.verify_slice(tag)
                    .map_err(|_| RecoveryRequired::AuthenticationFailed)
            }
            #[cfg(not(test))]
            SealedAuthenticationBackend::Unavailable(never) => match *never {},
        }
    }
}

impl fmt::Debug for RunStateAuthenticationProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RunStateAuthenticationProvider([REDACTED])")
    }
}

impl RuntimeRunStateAuthority<'_> {
    pub(super) const fn installation(&self) -> InstallationIdentity {
        self.provider.installation
    }

    pub(super) fn build_snapshot(
        &self,
        state: RunMarkerState,
        generation: NonZeroU64,
        predecessor: Commitment,
    ) -> Result<DurableSnapshot, RecoveryRequired> {
        if self.identity != self.provider.identity {
            return Err(RecoveryRequired::AuthenticationFailed);
        }
        build_snapshot(state, generation, predecessor, self.provider)
    }

    pub(super) fn verify_observation(
        &self,
        observed: &SnapshotObservation,
    ) -> Result<DurableSnapshot, RecoveryRequired> {
        if self.identity != self.provider.identity {
            return Err(RecoveryRequired::AuthenticationFailed);
        }
        verify_observation(observed, self.provider)
    }
}

impl fmt::Debug for RuntimeRunStateAuthority<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RuntimeRunStateAuthority([REDACTED])")
    }
}

fn marker_commitment(
    state: RunMarkerState,
    generation: NonZeroU64,
    installation: InstallationIdentity,
    predecessor: Commitment,
) -> Commitment {
    let mut digest = Sha256::new();
    digest.update(RUN_MARKER_COMMITMENT_DOMAIN_V1);
    digest.update(RUN_STATE_SCHEMA_V1.to_be_bytes());
    digest.update([state.tag()]);
    digest.update([RUN_MARKER_RESERVED_V1]);
    digest.update(generation.get().to_be_bytes());
    digest.update(installation.as_bytes());
    digest.update(predecessor.as_bytes());
    Commitment(digest.finalize().into())
}

/// Builds the exact marker/checkpoint pair through one sealed provider.
pub(super) fn build_snapshot(
    state: RunMarkerState,
    generation: NonZeroU64,
    predecessor: Commitment,
    provider: &RunStateAuthenticationProvider,
) -> Result<DurableSnapshot, RecoveryRequired> {
    if generation.get() == 1 && predecessor != Commitment::ZERO {
        return Err(RecoveryRequired::MalformedRunMarker);
    }
    if generation.get() > 1 && predecessor == Commitment::ZERO {
        return Err(RecoveryRequired::MalformedRunMarker);
    }

    let installation = provider.installation();
    let current = marker_commitment(state, generation, installation, predecessor);
    let mut marker = [0_u8; RUN_MARKER_BYTES];
    marker[..RUN_MARKER_MAGIC_V1.len()].copy_from_slice(RUN_MARKER_MAGIC_V1);
    marker[MARKER_VERSION_OFFSET..MARKER_STATE_OFFSET]
        .copy_from_slice(&RUN_STATE_SCHEMA_V1.to_be_bytes());
    marker[MARKER_STATE_OFFSET] = state.tag();
    marker[MARKER_RESERVED_OFFSET] = RUN_MARKER_RESERVED_V1;
    marker[MARKER_GENERATION_OFFSET..MARKER_INSTALLATION_OFFSET]
        .copy_from_slice(&generation.get().to_be_bytes());
    marker[MARKER_INSTALLATION_OFFSET..MARKER_PREDECESSOR_OFFSET]
        .copy_from_slice(installation.as_bytes());
    marker[MARKER_PREDECESSOR_OFFSET..MARKER_CURRENT_OFFSET]
        .copy_from_slice(predecessor.as_bytes());
    marker[MARKER_CURRENT_OFFSET..RUN_MARKER_BODY_BYTES].copy_from_slice(current.as_bytes());
    let marker_tag = provider.sign_marker_body(&marker[..RUN_MARKER_BODY_BYTES])?;
    marker[RUN_MARKER_BODY_BYTES..].copy_from_slice(&marker_tag);

    let mut checkpoint = [0_u8; HIGH_WATER_BYTES];
    checkpoint[..HIGH_WATER_MAGIC_V1.len()].copy_from_slice(HIGH_WATER_MAGIC_V1);
    checkpoint[CHECKPOINT_VERSION_OFFSET..CHECKPOINT_RESERVED_OFFSET]
        .copy_from_slice(&RUN_STATE_SCHEMA_V1.to_be_bytes());
    checkpoint[CHECKPOINT_RESERVED_OFFSET..CHECKPOINT_GENERATION_OFFSET]
        .copy_from_slice(&HIGH_WATER_RESERVED_V1.to_be_bytes());
    checkpoint[CHECKPOINT_GENERATION_OFFSET..CHECKPOINT_INSTALLATION_OFFSET]
        .copy_from_slice(&generation.get().to_be_bytes());
    checkpoint[CHECKPOINT_INSTALLATION_OFFSET..CHECKPOINT_PREDECESSOR_OFFSET]
        .copy_from_slice(installation.as_bytes());
    checkpoint[CHECKPOINT_PREDECESSOR_OFFSET..CHECKPOINT_CURRENT_OFFSET]
        .copy_from_slice(predecessor.as_bytes());
    checkpoint[CHECKPOINT_CURRENT_OFFSET..HIGH_WATER_BODY_BYTES]
        .copy_from_slice(current.as_bytes());
    let checkpoint_tag = provider.sign_checkpoint_body(&checkpoint[..HIGH_WATER_BODY_BYTES])?;
    checkpoint[HIGH_WATER_BODY_BYTES..].copy_from_slice(&checkpoint_tag);

    Ok(DurableSnapshot {
        bytes: CanonicalSnapshot { marker, checkpoint },
        marker: VerifiedRunMarker {
            state,
            generation,
            installation,
            predecessor,
            current,
        },
    })
}

/// Authenticates one exact marker/checkpoint pair through one sealed provider.
pub(super) fn verify_observation(
    observed: &SnapshotObservation,
    provider: &RunStateAuthenticationProvider,
) -> Result<DurableSnapshot, RecoveryRequired> {
    let marker_bytes = match observed.marker {
        FixedObservation::Missing => return Err(RecoveryRequired::MissingRunMarker),
        FixedObservation::Malformed => return Err(RecoveryRequired::MalformedRunMarker),
        FixedObservation::Exact(bytes) => bytes,
    };
    let checkpoint_bytes = match observed.checkpoint {
        FixedObservation::Missing => return Err(RecoveryRequired::MissingHighWaterCheckpoint),
        FixedObservation::Malformed => {
            return Err(RecoveryRequired::MalformedHighWaterCheckpoint);
        }
        FixedObservation::Exact(bytes) => bytes,
    };

    let expected_installation = provider.installation();
    let marker = verify_marker(&marker_bytes, expected_installation, provider)?;
    let checkpoint = verify_checkpoint(&checkpoint_bytes, expected_installation, provider)?;
    if marker.generation < checkpoint.generation {
        return Err(RecoveryRequired::RollbackDetected);
    }
    if marker.generation > checkpoint.generation {
        return Err(RecoveryRequired::HighWaterDrift);
    }
    if marker.installation != checkpoint.installation {
        return Err(RecoveryRequired::InstallationIdentityMismatch);
    }
    if !marker.predecessor.constant_time_eq(&checkpoint.predecessor)
        || !marker.current.constant_time_eq(&checkpoint.current)
    {
        return Err(RecoveryRequired::EquivocationDetected);
    }

    Ok(DurableSnapshot {
        bytes: CanonicalSnapshot {
            marker: marker_bytes,
            checkpoint: checkpoint_bytes,
        },
        marker,
    })
}

fn verify_marker(
    bytes: &[u8; RUN_MARKER_BYTES],
    expected_installation: InstallationIdentity,
    provider: &RunStateAuthenticationProvider,
) -> Result<VerifiedRunMarker, RecoveryRequired> {
    provider.verify_marker_body(
        &bytes[..RUN_MARKER_BODY_BYTES],
        &bytes[RUN_MARKER_BODY_BYTES..],
    )?;
    if &bytes[..RUN_MARKER_MAGIC_V1.len()] != RUN_MARKER_MAGIC_V1
        || read_u16(bytes, MARKER_VERSION_OFFSET) != RUN_STATE_SCHEMA_V1
        || bytes[MARKER_RESERVED_OFFSET] != RUN_MARKER_RESERVED_V1
    {
        return Err(RecoveryRequired::MalformedRunMarker);
    }
    let state = RunMarkerState::from_tag(bytes[MARKER_STATE_OFFSET])?;
    let generation = NonZeroU64::new(read_u64(bytes, MARKER_GENERATION_OFFSET))
        .ok_or(RecoveryRequired::MalformedRunMarker)?;
    let installation = InstallationIdentity(read_array::<INSTALLATION_IDENTITY_BYTES, _>(
        bytes,
        MARKER_INSTALLATION_OFFSET,
    ));
    if installation != expected_installation {
        return Err(RecoveryRequired::InstallationIdentityMismatch);
    }
    let predecessor = Commitment(read_array::<COMMITMENT_BYTES, _>(
        bytes,
        MARKER_PREDECESSOR_OFFSET,
    ));
    if (generation.get() == 1 && predecessor != Commitment::ZERO)
        || (generation.get() > 1 && predecessor == Commitment::ZERO)
    {
        return Err(RecoveryRequired::MalformedRunMarker);
    }
    let current = Commitment(read_array::<COMMITMENT_BYTES, _>(
        bytes,
        MARKER_CURRENT_OFFSET,
    ));
    let expected_current = marker_commitment(state, generation, installation, predecessor);
    if !current.constant_time_eq(&expected_current) {
        return Err(RecoveryRequired::EquivocationDetected);
    }
    Ok(VerifiedRunMarker {
        state,
        generation,
        installation,
        predecessor,
        current,
    })
}

fn verify_checkpoint(
    bytes: &[u8; HIGH_WATER_BYTES],
    expected_installation: InstallationIdentity,
    provider: &RunStateAuthenticationProvider,
) -> Result<VerifiedHighWaterCheckpoint, RecoveryRequired> {
    provider.verify_checkpoint_body(
        &bytes[..HIGH_WATER_BODY_BYTES],
        &bytes[HIGH_WATER_BODY_BYTES..],
    )?;
    if &bytes[..HIGH_WATER_MAGIC_V1.len()] != HIGH_WATER_MAGIC_V1
        || read_u16(bytes, CHECKPOINT_VERSION_OFFSET) != RUN_STATE_SCHEMA_V1
        || read_u16(bytes, CHECKPOINT_RESERVED_OFFSET) != HIGH_WATER_RESERVED_V1
    {
        return Err(RecoveryRequired::MalformedHighWaterCheckpoint);
    }
    let generation = NonZeroU64::new(read_u64(bytes, CHECKPOINT_GENERATION_OFFSET))
        .ok_or(RecoveryRequired::MalformedHighWaterCheckpoint)?;
    let installation = InstallationIdentity(read_array::<INSTALLATION_IDENTITY_BYTES, _>(
        bytes,
        CHECKPOINT_INSTALLATION_OFFSET,
    ));
    if installation != expected_installation {
        return Err(RecoveryRequired::InstallationIdentityMismatch);
    }
    let predecessor = Commitment(read_array::<COMMITMENT_BYTES, _>(
        bytes,
        CHECKPOINT_PREDECESSOR_OFFSET,
    ));
    if (generation.get() == 1 && predecessor != Commitment::ZERO)
        || (generation.get() > 1 && predecessor == Commitment::ZERO)
    {
        return Err(RecoveryRequired::MalformedHighWaterCheckpoint);
    }
    let current = Commitment(read_array::<COMMITMENT_BYTES, _>(
        bytes,
        CHECKPOINT_CURRENT_OFFSET,
    ));
    Ok(VerifiedHighWaterCheckpoint {
        generation,
        installation,
        predecessor,
        current,
    })
}

fn read_u16<const BYTES: usize>(bytes: &[u8; BYTES], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u64<const BYTES: usize>(bytes: &[u8; BYTES], offset: usize) -> u64 {
    u64::from_be_bytes(read_array::<8, _>(bytes, offset))
}

fn read_array<const OUTPUT: usize, const INPUT: usize>(
    bytes: &[u8; INPUT],
    offset: usize,
) -> [u8; OUTPUT] {
    let mut output = [0_u8; OUTPUT];
    output.copy_from_slice(&bytes[offset..offset + OUTPUT]);
    output
}

#[cfg(test)]
pub(super) fn resign_marker_for_test(
    marker: &mut [u8; RUN_MARKER_BYTES],
    provider: &RunStateAuthenticationProvider,
) -> Result<(), RecoveryRequired> {
    let tag = provider.sign_marker_body(&marker[..RUN_MARKER_BODY_BYTES])?;
    marker[RUN_MARKER_BODY_BYTES..].copy_from_slice(&tag);
    Ok(())
}

#[cfg(test)]
pub(super) fn resign_checkpoint_for_test(
    checkpoint: &mut [u8; HIGH_WATER_BYTES],
    provider: &RunStateAuthenticationProvider,
) -> Result<(), RecoveryRequired> {
    let tag = provider.sign_checkpoint_body(&checkpoint[..HIGH_WATER_BODY_BYTES])?;
    checkpoint[HIGH_WATER_BODY_BYTES..].copy_from_slice(&tag);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    trait AmbiguousIfClone<Marker> {
        fn marker() {}
    }
    impl<T> AmbiguousIfClone<()> for T {}
    impl<T: Clone> AmbiguousIfClone<u8> for T {}

    trait AmbiguousIfCopy<Marker> {
        fn marker() {}
    }
    impl<T> AmbiguousIfCopy<()> for T {}
    impl<T: Copy> AmbiguousIfCopy<u8> for T {}

    #[test]
    fn sealed_provider_enforces_identity_purpose_and_redaction() -> Result<(), RecoveryRequired> {
        let installation = InstallationIdentity::from_fixed_bytes([0x41; COMMITMENT_BYTES])?;
        assert!(matches!(
            RunStateAuthenticationProvider::from_fixture_bytes(installation, [0; MAC_BYTES]),
            Err(RecoveryRequired::InvalidFixtureAuthenticationKey)
        ));

        let provider =
            RunStateAuthenticationProvider::from_fixture_bytes(installation, [0x52; MAC_BYTES])?;
        let wrong_provider =
            RunStateAuthenticationProvider::from_fixture_bytes(installation, [0x63; MAC_BYTES])?;
        assert_eq!(
            format!("{provider:?}"),
            "RunStateAuthenticationProvider([REDACTED])"
        );
        let _ = <RunStateAuthenticationProvider as AmbiguousIfClone<_>>::marker;
        let _ = <RunStateAuthenticationProvider as AmbiguousIfCopy<_>>::marker;
        assert!(std::mem::needs_drop::<RunStateAuthenticationProvider>());

        let snapshot = build_snapshot(
            RunMarkerState::Clean,
            NonZeroU64::new(1).ok_or(RecoveryRequired::MalformedRunMarker)?,
            Commitment::ZERO,
            &provider,
        )?;
        assert!(matches!(
            verify_observation(&snapshot.bytes.observation(), &wrong_provider),
            Err(RecoveryRequired::AuthenticationFailed)
        ));

        let same_body = [0x74; RUN_MARKER_BODY_BYTES];
        let marker_purpose_tag = provider.sign_marker_body(&same_body)?;
        let checkpoint_purpose_tag = provider.sign_checkpoint_body(&same_body)?;
        assert_ne!(marker_purpose_tag, checkpoint_purpose_tag);
        provider.verify_marker_body(&same_body, &marker_purpose_tag)?;
        provider.verify_checkpoint_body(&same_body, &checkpoint_purpose_tag)?;
        assert_eq!(
            provider.verify_marker_body(&same_body, &checkpoint_purpose_tag),
            Err(RecoveryRequired::AuthenticationFailed)
        );
        assert_eq!(
            provider.verify_checkpoint_body(&same_body, &marker_purpose_tag),
            Err(RecoveryRequired::AuthenticationFailed)
        );

        let marker_tag =
            <[u8; MAC_BYTES]>::try_from(&snapshot.bytes.marker[RUN_MARKER_BODY_BYTES..])
                .map_err(|_| RecoveryRequired::MalformedRunMarker)?;
        let checkpoint_tag =
            <[u8; MAC_BYTES]>::try_from(&snapshot.bytes.checkpoint[HIGH_WATER_BODY_BYTES..])
                .map_err(|_| RecoveryRequired::MalformedHighWaterCheckpoint)?;

        let mut marker_tag_swapped = snapshot.bytes;
        marker_tag_swapped.marker[RUN_MARKER_BODY_BYTES..].copy_from_slice(&checkpoint_tag);
        assert!(matches!(
            verify_observation(&marker_tag_swapped.observation(), &provider),
            Err(RecoveryRequired::AuthenticationFailed)
        ));

        let mut checkpoint_tag_swapped = snapshot.bytes;
        checkpoint_tag_swapped.checkpoint[HIGH_WATER_BODY_BYTES..].copy_from_slice(&marker_tag);
        assert!(matches!(
            verify_observation(&checkpoint_tag_swapped.observation(), &provider),
            Err(RecoveryRequired::AuthenticationFailed)
        ));

        std::mem::drop(wrong_provider);
        Ok(())
    }

    #[test]
    fn runtime_authority_retains_one_unique_redacted_provider_identity()
    -> Result<(), RecoveryRequired> {
        let installation = InstallationIdentity::from_fixed_bytes([0x75; COMMITMENT_BYTES])?;
        let mut first =
            RunStateAuthenticationProvider::from_fixture_bytes(installation, [0x76; MAC_BYTES])?;
        let second =
            RunStateAuthenticationProvider::from_fixture_bytes(installation, [0x76; MAC_BYTES])?;
        assert_ne!(first.identity, second.identity);
        assert!(format!("{:?}", first.identity).contains("[REDACTED]"));

        let first_identity = first.identity;
        let authority = first.runtime_authority();
        assert_eq!(authority.identity, first_identity);
        assert_eq!(authority.installation(), installation);
        assert_eq!(
            format!("{authority:?}"),
            "RuntimeRunStateAuthority([REDACTED])"
        );
        let _ = <RuntimeRunStateAuthority<'_> as AmbiguousIfClone<_>>::marker;
        let _ = <RuntimeRunStateAuthority<'_> as AmbiguousIfCopy<_>>::marker;

        let snapshot =
            authority.build_snapshot(RunMarkerState::Clean, NonZeroU64::MIN, Commitment::ZERO)?;
        assert!(authority.verify_observation(&snapshot.bytes.observation())? == snapshot);
        Ok(())
    }
}
