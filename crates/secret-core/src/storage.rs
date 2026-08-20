use thiserror::Error;

use crate::VaultBlob;

/// Errors exposed by an atomic vault storage boundary.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum StorageError {
    /// No committed vault exists.
    #[error("vault does not exist")]
    NotFound,
    /// The expected generation no longer matches durable storage.
    #[error("vault generation conflict")]
    GenerationConflict,
    /// Storage could not provide its durability/atomicity contract.
    #[error("durable atomic storage operation failed")]
    DurabilityFailure,
    /// Stored bytes exceed the vault format bound.
    #[error("stored vault exceeds supported bounds")]
    BoundsExceeded,
}

/// Release-critical storage boundary for encrypted vault bytes.
///
/// A production Windows implementation must create files with a restrictive
/// DACL, flush file data, atomically replace the previous generation, flush the
/// containing directory or equivalent metadata, and recover deterministically
/// after interruption at every step. Safe `std::fs` cannot prove that complete
/// Windows contract, so this crate intentionally supplies no filesystem
/// implementation. The platform key agent must implement and crash-test this
/// trait; an implementation that only calls `rename` is not release-ready.
pub trait AtomicVaultStorage {
    /// Loads the latest committed encrypted bytes.
    ///
    /// # Errors
    ///
    /// Returns a storage error if no committed value exists or durable reading
    /// fails.
    fn load(&self) -> Result<Vec<u8>, StorageError>;

    /// Commits a new generation if `expected_generation` is still current.
    ///
    /// # Errors
    ///
    /// Returns a generation conflict or durability failure without reporting a
    /// successful commit unless the complete trait contract is satisfied.
    fn commit(
        &mut self,
        expected_generation: Option<u64>,
        blob: &VaultBlob,
    ) -> Result<(), StorageError>;
}
