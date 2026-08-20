//! Exact simultaneously-held executable image comparison for dormant helpers.
//!
//! This debug-only primitive compares the Broker artifact held without
//! write/delete sharing to the executable-image file handle supplied by the
//! first `CREATE_PROCESS_DEBUG_EVENT`. It never authenticates by path or PID.

use core::fmt;
use std::path::Path;

use thiserror::Error;
use windows::Win32::Foundation::HANDLE;

use crate::helper::{HelperError, VerifiedHelper};

/// Stable failures from the exact Broker image boundary.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum ExactImageError {
    /// The debug artifact was not derived as the exact Broker role.
    #[error("held artifact is not the Broker")]
    WrongRole,
    /// The debug Broker artifact could not be held exactly.
    #[error("Broker artifact could not be held")]
    ArtifactUnavailable,
    /// `FILE_ID_INFO` did not provide an unambiguous identity.
    #[error("Broker artifact identity is unavailable")]
    IdentityUnavailable,
    /// The mapped executable was not the simultaneously held Broker file.
    #[error("mapped Broker image did not match the held artifact")]
    MappedImageMismatch,
}

impl From<HelperError> for ExactImageError {
    fn from(_error: HelperError) -> Self {
        Self::ArtifactUnavailable
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct ExactFileIdentity {
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
}

impl fmt::Debug for ExactFileIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExactFileIdentity([FILE_ID_INFO])")
    }
}

/// Pinned debug Broker artifact and its exact Windows file-object identity.
pub(crate) struct PinnedBrokerImage {
    artifact: VerifiedHelper,
    identity: ExactFileIdentity,
}

impl PinnedBrokerImage {
    /// Opens and pins the exact debug Broker executable.
    pub(crate) fn hold(path: &Path) -> Result<Self, ExactImageError> {
        let artifact = VerifiedHelper::hold_dormant_broker(path)?;
        if !artifact.is_broker() {
            return Err(ExactImageError::WrongRole);
        }
        let identity = sys::exact_file_identity(artifact.raw_handle())?;
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
        (sys::exact_file_identity(mapped_image)? == self.identity)
            .then_some(())
            .ok_or(ExactImageError::MappedImageMismatch)
    }
}

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
}
