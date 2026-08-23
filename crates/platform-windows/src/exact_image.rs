//! Exact simultaneously-held executable identity for dormant helpers.
//!
//! The release-preparation seam derives opaque `FILE_ID_INFO` only from an
//! already verified and held helper handle. The debug-only mapped-image seam
//! additionally compares that identity with the first
//! `CREATE_PROCESS_DEBUG_EVENT` image handle. Neither path authenticates by
//! reopening a path or trusting a PID.

use core::fmt;
#[cfg(all(feature = "broker-channel-contract-test-hook", debug_assertions))]
use std::path::Path;

use thiserror::Error;
use windows::Win32::Foundation::HANDLE;
use zeroize::Zeroize;

#[cfg(all(feature = "broker-channel-contract-test-hook", debug_assertions))]
use crate::helper::HelperError;
use crate::helper::VerifiedHelper;

/// Stable failures from the exact held-helper image boundary.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum ExactImageError {
    /// The held artifact was not derived for the expected helper role.
    #[error("held artifact has the wrong helper role")]
    WrongRole,
    /// The exact helper artifact could not be held.
    #[error("helper artifact could not be held")]
    ArtifactUnavailable,
    /// `FILE_ID_INFO` did not provide an unambiguous identity.
    #[error("helper artifact identity is unavailable")]
    IdentityUnavailable,
    /// The mapped executable was not the simultaneously held helper file.
    #[error("mapped helper image did not match the held artifact")]
    MappedImageMismatch,
}

#[cfg(all(feature = "broker-channel-contract-test-hook", debug_assertions))]
impl From<HelperError> for ExactImageError {
    fn from(_error: HelperError) -> Self {
        Self::ArtifactUnavailable
    }
}

/// Opaque exact file-object identity for one simultaneously held helper.
#[derive(Eq, PartialEq)]
pub(super) struct ExactFileIdentity {
    volume_serial_number: u64,
    file_id: [u8; 16],
}

impl ExactFileIdentity {
    fn new(volume_serial_number: u64, file_id: [u8; 16]) -> Result<Self, ExactImageError> {
        if volume_serial_number == 0 || file_id == [0; 16] || file_id == [u8::MAX; 16] {
            return Err(ExactImageError::IdentityUnavailable);
        }
        Ok(Self {
            volume_serial_number,
            file_id,
        })
    }

    /// Encodes the volume followed by all 128 opaque file-ID bits.
    ///
    /// The volume is big-endian; the Windows-provided file-ID byte sequence is
    /// retained exactly. Callers receive no field-level access to the identity.
    pub(super) fn encode_be(&self) -> [u8; 24] {
        let mut encoded = [0_u8; 24];
        encoded[..8].copy_from_slice(&self.volume_serial_number.to_be_bytes());
        encoded[8..].copy_from_slice(&self.file_id);
        encoded
    }
}

impl fmt::Debug for ExactFileIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExactFileIdentity([FILE_ID_INFO])")
    }
}

impl Zeroize for ExactFileIdentity {
    fn zeroize(&mut self) {
        self.volume_serial_number.zeroize();
        self.file_id.zeroize();
    }
}

impl Drop for ExactFileIdentity {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Derives the exact identity only from the file object already retained by a
/// verified helper. This performs no reopen, canonicalization, or path lookup.
pub(super) fn held_helper_file_identity(
    artifact: &VerifiedHelper,
) -> Result<ExactFileIdentity, ExactImageError> {
    sys::exact_file_identity(artifact.raw_handle())
}

/// Proves that a pre-user-mode mapped image is one already-held file object.
///
/// The expected identity is opaque and the comparison performs no path lookup,
/// PID reopen, canonicalization, or second expected-file open.
pub(super) fn authenticate_mapped_image(
    identity: &ExactFileIdentity,
    mapped_image: HANDLE,
) -> Result<(), ExactImageError> {
    sys::exact_file_identity(mapped_image)?
        .eq(identity)
        .then_some(())
        .ok_or(ExactImageError::MappedImageMismatch)
}

/// Pinned debug Broker artifact and its exact Windows file-object identity.
#[cfg(all(feature = "broker-channel-contract-test-hook", debug_assertions))]
pub(crate) struct PinnedBrokerImage {
    artifact: VerifiedHelper,
    identity: ExactFileIdentity,
}

#[cfg(all(feature = "broker-channel-contract-test-hook", debug_assertions))]
impl PinnedBrokerImage {
    /// Opens and pins the exact debug Broker executable.
    pub(crate) fn hold(path: &Path) -> Result<Self, ExactImageError> {
        let artifact = VerifiedHelper::hold_dormant_broker(path)?;
        if !artifact.is_broker() {
            return Err(ExactImageError::WrongRole);
        }
        let identity = held_helper_file_identity(&artifact)?;
        Ok(Self { artifact, identity })
    }

    pub(crate) fn path(&self) -> &Path {
        self.artifact.path()
    }

    /// Proves that the pre-user-mode mapped image is the pinned artifact.
    pub(crate) fn authenticate_mapped_image(
        &self,
        mapped_image: HANDLE,
    ) -> Result<(), ExactImageError> {
        authenticate_mapped_image(&self.identity, mapped_image)
    }
}

#[cfg(all(feature = "broker-channel-contract-test-hook", debug_assertions))]
impl fmt::Debug for PinnedBrokerImage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PinnedBrokerImage([HELD EXACT BROKER ARTIFACT])")
    }
}

mod sys {
    #![allow(unsafe_code)]

    use core::ffi::c_void;
    use core::mem::size_of_val;
    use core::ptr;

    use windows::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
    use windows::Win32::Storage::FileSystem::{
        FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx,
    };

    use super::{ExactFileIdentity, ExactImageError};

    pub(super) fn exact_file_identity(
        handle: HANDLE,
    ) -> Result<ExactFileIdentity, ExactImageError> {
        if handle.is_invalid() || handle == INVALID_HANDLE_VALUE {
            return Err(ExactImageError::IdentityUnavailable);
        }
        let mut information = FILE_ID_INFO::default();
        // SAFETY: `handle` is borrowed from a simultaneously live file object,
        // and the output is exact writable `FILE_ID_INFO` storage.
        unsafe {
            GetFileInformationByHandleEx(
                handle,
                FileIdInfo,
                ptr::from_mut(&mut information).cast::<c_void>(),
                u32::try_from(size_of_val(&information))
                    .map_err(|_| ExactImageError::IdentityUnavailable)?,
            )
        }
        .map_err(|_| ExactImageError::IdentityUnavailable)?;
        ExactFileIdentity::new(
            information.VolumeSerialNumber,
            information.FileId.Identifier,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{ExactFileIdentity, ExactImageError};

    #[test]
    fn exact_file_identity_rejects_zero_volume_and_sentinel_file_ids() {
        let valid_file_id = [0x5a; 16];
        assert_eq!(
            ExactFileIdentity::new(0, valid_file_id),
            Err(ExactImageError::IdentityUnavailable)
        );
        assert_eq!(
            ExactFileIdentity::new(7, [0; 16]),
            Err(ExactImageError::IdentityUnavailable)
        );
        assert_eq!(
            ExactFileIdentity::new(7, [u8::MAX; 16]),
            Err(ExactImageError::IdentityUnavailable)
        );

        let mut non_sentinel_near_zero = [0; 16];
        non_sentinel_near_zero[0] = 1;
        assert!(ExactFileIdentity::new(7, non_sentinel_near_zero).is_ok());

        let mut non_sentinel_near_all_ones = [u8::MAX; 16];
        non_sentinel_near_all_ones[15] ^= 1;
        assert!(ExactFileIdentity::new(7, non_sentinel_near_all_ones).is_ok());
    }

    #[test]
    fn exact_file_identity_equality_binds_volume_and_all_128_file_id_bits()
    -> Result<(), ExactImageError> {
        let file_id = [0x5a; 16];
        let expected = ExactFileIdentity::new(7, file_id)?;
        assert_eq!(expected, ExactFileIdentity::new(7, file_id)?);
        assert_ne!(expected, ExactFileIdentity::new(8, file_id)?);

        for index in [0_usize, 8, 15] {
            let mut mismatched_file_id = file_id;
            mismatched_file_id[index] ^= 1;
            assert_ne!(expected, ExactFileIdentity::new(7, mismatched_file_id)?);
        }
        Ok(())
    }

    #[test]
    fn exact_file_identity_encoding_binds_volume_and_file_id_low_mid_high_bytes()
    -> Result<(), ExactImageError> {
        let volume_serial_number = 0x0102_0304_0506_0708_u64;
        let file_id = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f,
        ];
        let encoded = ExactFileIdentity::new(volume_serial_number, file_id)?.encode_be();
        assert_eq!(
            encoded,
            [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
            ]
        );

        let volume_mutated = ExactFileIdentity::new(volume_serial_number ^ 1, file_id)?.encode_be();
        let mut expected_volume_mutation = encoded;
        expected_volume_mutation[7] ^= 1;
        assert_eq!(volume_mutated, expected_volume_mutation);

        for index in [0_usize, 8, 15] {
            let mut mutated_file_id = file_id;
            mutated_file_id[index] ^= 1;
            let mutation =
                ExactFileIdentity::new(volume_serial_number, mutated_file_id)?.encode_be();
            let mut expected_mutation = encoded;
            expected_mutation[8 + index] ^= 1;
            assert_eq!(mutation, expected_mutation);
        }
        Ok(())
    }
}
