//! Fail-closed verification of one-shot executable helpers.
//!
//! Verification holds the executable open without write/delete sharing after
//! checking its path. That prevents a path swap between hashing and launch by
//! ordinary Win32 file operations. The configured install root itself remains a
//! trust anchor and must be provisioned by the signed installer.

use core::fmt;
use std::fs::File;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use thiserror::Error;

const MANIFEST_DOMAIN: &[u8] = b"your-wallet/helper-manifest/v1\0";

/// Helper role derived only from the release-bound manifest file name.
///
/// This type deliberately stays private: callers may choose a manifest for
/// verification, but they cannot inject a role into a [`VerifiedHelper`]. The
/// restricted launcher separately requires that manifest's digest to appear in
/// the compiled release allowlist.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HelperRole {
    KeyAgent,
    ApprovalFrontend,
    SecretInputFrontend,
    Other,
}

impl HelperRole {
    fn from_release_file_name(file_name: &str) -> Self {
        if file_name.eq_ignore_ascii_case("key-agent.exe") {
            Self::KeyAgent
        } else if file_name.eq_ignore_ascii_case("approval-ui.exe") {
            Self::ApprovalFrontend
        } else if file_name.eq_ignore_ascii_case("secret-input-ui.exe") {
            Self::SecretInputFrontend
        } else {
            Self::Other
        }
    }
}

/// A four-component Win32 executable file version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HelperVersion {
    /// Major version.
    pub major: u16,
    /// Minor version.
    pub minor: u16,
    /// Patch version.
    pub patch: u16,
    /// Build version.
    pub build: u16,
}

/// Release metadata compiled into the process that launches a helper.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HelperManifest {
    file_name: String,
    version: HelperVersion,
    executable_sha256: [u8; 32],
    signer_certificate_sha256: [u8; 32],
}

impl HelperManifest {
    /// Constructs a canonical manifest entry.
    ///
    /// # Errors
    ///
    /// Returns [`HelperError::InvalidManifest`] when the file name is outside the
    /// canonical grammar or either identity digest is all zero.
    pub fn new(
        file_name: &str,
        version: HelperVersion,
        executable_sha256: [u8; 32],
        signer_certificate_sha256: [u8; 32],
    ) -> Result<Self, HelperError> {
        if file_name.is_empty()
            || file_name.len() > 128
            || !file_name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            || !file_name.to_ascii_lowercase().ends_with(".exe")
        {
            return Err(HelperError::InvalidManifest);
        }
        if executable_sha256 == [0; 32] || signer_certificate_sha256 == [0; 32] {
            return Err(HelperError::InvalidManifest);
        }
        Ok(Self {
            file_name: file_name.to_owned(),
            version,
            executable_sha256,
            signer_certificate_sha256,
        })
    }

    /// Computes the domain-separated canonical manifest hash.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_DOMAIN);
        let name_len = u16::try_from(self.file_name.len()).unwrap_or(u16::MAX);
        hasher.update(name_len.to_be_bytes());
        hasher.update(self.file_name.as_bytes());
        hasher.update(self.version.major.to_be_bytes());
        hasher.update(self.version.minor.to_be_bytes());
        hasher.update(self.version.patch.to_be_bytes());
        hasher.update(self.version.build.to_be_bytes());
        hasher.update(self.executable_sha256);
        hasher.update(self.signer_certificate_sha256);
        hasher.finalize().into()
    }
}

/// Fail-closed helper validation errors. Paths and OS messages are deliberately
/// excluded so this type is safe to surface across the non-secret UI boundary.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum HelperError {
    /// A configured path was not absolute.
    #[error("helper verifier requires absolute paths")]
    NonAbsolutePath,
    /// The executable was outside the configured secure install root.
    #[error("helper executable is outside the configured install root")]
    OutsideInstallRoot,
    /// A path component was a reparse point.
    #[error("helper path contains a reparse point")]
    ReparsePoint,
    /// The current process can modify a parent directory.
    #[error("helper parent directory is writable by the current process")]
    WritableParent,
    /// The release manifest is malformed or its expected hash does not match.
    #[error("helper release manifest is invalid")]
    InvalidManifest,
    /// The executable name did not match the release manifest.
    #[error("helper executable name does not match the release manifest")]
    WrongFileName,
    /// The held file is not a regular executable file.
    #[error("helper path is not a regular file")]
    NotRegularFile,
    /// The held executable bytes did not match the release manifest.
    #[error("helper executable hash does not match the release manifest")]
    HashMismatch,
    /// The executable file version did not match the release manifest.
    #[error("helper executable version does not match the release manifest")]
    VersionMismatch,
    /// Authenticode or the exact leaf signing certificate did not verify.
    #[error("helper executable Authenticode identity is not trusted")]
    UntrustedSignature,
    /// A required operating-system operation failed.
    #[error("Windows helper verification operation failed")]
    OperatingSystem,
    /// This verifier is only available on Windows.
    #[error("Windows helper verification is unavailable on this platform")]
    UnsupportedPlatform,
}

/// Stable identity of the exact file held open by a successful verification.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct FileIdentity {
    /// Volume serial number reported by Windows.
    pub volume_serial_number: u32,
    /// File identifier on that volume.
    pub file_index: u64,
    /// File size observed through the held handle.
    pub file_size: u64,
}

impl fmt::Debug for FileIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileIdentity")
            .field("volume_serial_number", &"[REDACTED]")
            .field("file_index", &"[REDACTED]")
            .field("file_size", &"[REDACTED]")
            .finish()
    }
}

/// A helper executable whose path, bytes, version, and signer were verified.
///
/// This value owns a non-write/non-delete-shared file handle. Keep it alive
/// through process creation to prevent replacement after verification.
pub struct VerifiedHelper {
    path: PathBuf,
    file: File,
    identity: FileIdentity,
    manifest_digest: [u8; 32],
    role: HelperRole,
}

impl VerifiedHelper {
    /// Returns the verified file identity for audit binding.
    #[must_use]
    pub const fn identity(&self) -> FileIdentity {
        self.identity
    }

    /// Returns the canonical release-manifest digest.
    #[must_use]
    pub const fn manifest_digest(&self) -> [u8; 32] {
        self.manifest_digest
    }

    /// Returns whether the verified release manifest names the exact Key Agent
    /// role. Only the dormant supervisor activation boundary may use this
    /// narrower role proof.
    pub(crate) const fn is_key_agent(&self) -> bool {
        matches!(self.role, HelperRole::KeyAgent)
    }

    /// Returns whether the verified manifest names the one exact approval
    /// frontend role. The public restricted-launch entry point uses this role
    /// proof to derive its dedicated LPAC profile.
    pub(crate) const fn is_approval_frontend(&self) -> bool {
        matches!(self.role, HelperRole::ApprovalFrontend)
    }

    /// Returns whether the verified release manifest names the one exact
    /// secret-input frontend role. The private secret/recovery launch entry point
    /// uses this role proof to derive its dedicated LPAC profile.
    pub(crate) const fn is_secret_input_frontend(&self) -> bool {
        matches!(self.role, HelperRole::SecretInputFrontend)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    #[cfg(windows)]
    pub(crate) fn raw_handle(&self) -> windows::Win32::Foundation::HANDLE {
        use std::os::windows::io::AsRawHandle;

        windows::Win32::Foundation::HANDLE(self.file.as_raw_handle())
    }

    #[cfg(all(test, windows))]
    pub(crate) fn for_approval_channel_test(approval_frontend: bool) -> Result<Self, HelperError> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .open("NUL")
            .map_err(|_| HelperError::OperatingSystem)?;
        Ok(Self {
            path: PathBuf::from("NUL"),
            file,
            identity: FileIdentity {
                volume_serial_number: 1,
                file_index: 2,
                file_size: 3,
            },
            manifest_digest: [4; 32],
            role: if approval_frontend {
                HelperRole::ApprovalFrontend
            } else {
                HelperRole::Other
            },
        })
    }

    #[cfg(all(test, windows))]
    pub(crate) fn for_secret_input_channel_test() -> Result<Self, HelperError> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .open("NUL")
            .map_err(|_| HelperError::OperatingSystem)?;
        Ok(Self {
            path: PathBuf::from("NUL"),
            file,
            identity: FileIdentity {
                volume_serial_number: 11,
                file_index: 12,
                file_size: 13,
            },
            manifest_digest: [14; 32],
            role: HelperRole::SecretInputFrontend,
        })
    }

    #[cfg(all(test, windows))]
    pub(crate) fn for_key_agent_activation_test() -> Result<Self, HelperError> {
        use std::os::windows::fs::OpenOptionsExt;

        use windows::Win32::Storage::FileSystem::{FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ};

        let path = std::env::current_exe().map_err(|_| HelperError::OperatingSystem)?;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ.0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
            .open(&path)
            .map_err(|_| HelperError::OperatingSystem)?;
        Ok(Self {
            path,
            file,
            identity: FileIdentity {
                volume_serial_number: 21,
                file_index: 22,
                file_size: 23,
            },
            manifest_digest: [24; 32],
            role: HelperRole::KeyAgent,
        })
    }
}

impl fmt::Debug for VerifiedHelper {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedHelper")
            .field("path", &"[VERIFIED HELPER PATH]")
            .field("identity", &self.identity)
            .field("manifest_digest", &"[SHA-256]")
            .field("role", &"[VERIFIED HELPER ROLE]")
            .finish_non_exhaustive()
    }
}

/// Verifies helper executables against an immutable release manifest entry.
pub struct HelperVerifier {
    install_root: PathBuf,
    manifest: HelperManifest,
    expected_manifest_digest: [u8; 32],
}

impl fmt::Debug for HelperVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HelperVerifier")
            .field("install_root", &"[REDACTED LOCAL PATH]")
            .field("manifest", &"[REDACTED RELEASE MANIFEST]")
            .field("expected_manifest_digest", &"[REDACTED]")
            .finish()
    }
}

impl HelperVerifier {
    /// Constructs a verifier. Validation remains fail-closed until `verify`.
    #[must_use]
    pub fn new(
        install_root: PathBuf,
        manifest: HelperManifest,
        expected_manifest_digest: [u8; 32],
    ) -> Self {
        Self {
            install_root,
            manifest,
            expected_manifest_digest,
        }
    }

    /// Verifies and pins the exact helper file to be launched.
    ///
    /// # Errors
    ///
    /// Returns a [`HelperError`] whenever any path, ACL, byte identity, version,
    /// Authenticode, or signer-certificate check cannot be proven.
    pub fn verify(&self, candidate: &Path) -> Result<VerifiedHelper, HelperError> {
        if !self.install_root.is_absolute() || !candidate.is_absolute() {
            return Err(HelperError::NonAbsolutePath);
        }
        if self.manifest.digest() != self.expected_manifest_digest {
            return Err(HelperError::InvalidManifest);
        }
        let actual_name = candidate
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(HelperError::WrongFileName)?;
        if !actual_name.eq_ignore_ascii_case(&self.manifest.file_name) {
            return Err(HelperError::WrongFileName);
        }

        #[cfg(windows)]
        {
            sys::verify(self, candidate)
        }

        #[cfg(not(windows))]
        {
            Err(HelperError::UnsupportedPlatform)
        }
    }
}

#[cfg(test)]
mod debug_tests {
    use std::path::PathBuf;

    use super::{FileIdentity, HelperManifest, HelperRole, HelperVerifier, HelperVersion};

    #[test]
    fn helper_roles_are_derived_only_from_exact_release_file_names() {
        assert_eq!(
            HelperRole::from_release_file_name("key-agent.exe"),
            HelperRole::KeyAgent
        );
        assert_eq!(
            HelperRole::from_release_file_name("approval-ui.exe"),
            HelperRole::ApprovalFrontend
        );
        assert_eq!(
            HelperRole::from_release_file_name("secret-input-ui.exe"),
            HelperRole::SecretInputFrontend
        );
        assert_eq!(
            HelperRole::from_release_file_name("secret-input-ui.exe.backup"),
            HelperRole::Other
        );
    }

    #[test]
    fn helper_identity_and_verifier_debug_are_redacted() -> Result<(), Box<dyn std::error::Error>> {
        let identity = FileIdentity {
            volume_serial_number: 4_000_000_001,
            file_index: 8_000_000_002,
            file_size: 9_000_000_003,
        };
        let identity_debug = format!("{identity:?}");
        assert!(identity_debug.contains("FileIdentity"));
        assert!(identity_debug.contains("[REDACTED]"));
        assert!(!identity_debug.contains("4000000001"));
        assert!(!identity_debug.contains("8000000002"));
        assert!(!identity_debug.contains("9000000003"));

        let manifest = HelperManifest::new(
            "private-helper-marker.exe",
            HelperVersion {
                major: 1,
                minor: 2,
                patch: 3,
                build: 4,
            },
            [0xa1; 32],
            [0xb2; 32],
        )?;
        let digest = manifest.digest();
        let verifier = HelperVerifier::new(
            PathBuf::from(r"C:\private-local-path-marker"),
            manifest,
            digest,
        );
        let verifier_debug = format!("{verifier:?}");
        assert!(verifier_debug.contains("HelperVerifier"));
        assert!(verifier_debug.contains("[REDACTED"));
        assert!(!verifier_debug.contains("private-local-path-marker"));
        assert!(!verifier_debug.contains("private-helper-marker.exe"));
        assert!(!verifier_debug.contains("161, 161"));
        assert!(!verifier_debug.contains("178, 178"));
        Ok(())
    }
}

#[cfg(windows)]
mod sys {
    #![allow(unsafe_code)]

    use core::ffi::c_void;
    use core::mem::size_of;
    use core::ptr;
    use std::fs::{self, OpenOptions};
    use std::io::{Read, Seek, SeekFrom};
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use std::os::windows::io::AsRawHandle;
    use std::path::{Component, Path, PathBuf};

    use sha2::{Digest, Sha256};
    use windows::Win32::Foundation::{
        CloseHandle, ERROR_ACCESS_DENIED, ERROR_SUCCESS, HANDLE, HWND,
    };
    use windows::Win32::Security::WinTrust::{
        WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
        WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_LIFETIME_SIGNING_FLAG,
        WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, WTD_REVOKE_WHOLECHAIN, WTD_STATEACTION_CLOSE,
        WTD_STATEACTION_VERIFY, WTD_UI_NONE, WTHelperGetProvSignerFromChain,
        WTHelperProvDataFromStateData, WinVerifyTrust,
    };
    use windows::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CreateFileW, DELETE, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_DELETE_CHILD, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_SEQUENTIAL_SCAN, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, GetFileInformationByHandle, GetFileVersionInfoSizeW,
        GetFileVersionInfoW, OPEN_EXISTING, VS_FIXEDFILEINFO, VerQueryValueW, WRITE_DAC,
        WRITE_OWNER,
    };
    use windows::core::PCWSTR;

    use super::{FileIdentity, HelperError, HelperRole, HelperVerifier, VerifiedHelper};

    pub(super) fn verify(
        verifier: &HelperVerifier,
        candidate: &Path,
    ) -> Result<VerifiedHelper, HelperError> {
        let relative = candidate
            .strip_prefix(&verifier.install_root)
            .map_err(|_| HelperError::OutsideInstallRoot)?;
        validate_relative_path(relative)?;
        reject_reparse_traversal(&verifier.install_root, relative)?;

        let canonical_root =
            fs::canonicalize(&verifier.install_root).map_err(|_| HelperError::OperatingSystem)?;
        let canonical_candidate =
            fs::canonicalize(candidate).map_err(|_| HelperError::OperatingSystem)?;
        if !canonical_candidate.starts_with(&canonical_root) {
            return Err(HelperError::OutsideInstallRoot);
        }

        reject_writable_parents(&verifier.install_root, relative)?;
        let mut file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ.0)
            .custom_flags((FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN).0)
            .open(candidate)
            .map_err(|_| HelperError::OperatingSystem)?;
        if !file
            .metadata()
            .map_err(|_| HelperError::OperatingSystem)?
            .is_file()
        {
            return Err(HelperError::NotRegularFile);
        }

        let identity = file_identity(&file)?;
        let executable_digest = hash_file(&mut file)?;
        if executable_digest != verifier.manifest.executable_sha256 {
            return Err(HelperError::HashMismatch);
        }
        let actual_version = file_version(candidate)?;
        if actual_version != verifier.manifest.version {
            return Err(HelperError::VersionMismatch);
        }
        verify_authenticode(
            &file,
            candidate,
            verifier.manifest.signer_certificate_sha256,
        )?;

        Ok(VerifiedHelper {
            path: canonical_candidate,
            file,
            identity,
            manifest_digest: verifier.expected_manifest_digest,
            role: HelperRole::from_release_file_name(&verifier.manifest.file_name),
        })
    }

    fn validate_relative_path(relative: &Path) -> Result<(), HelperError> {
        if relative.as_os_str().is_empty()
            || relative.components().any(|component| {
                matches!(
                    component,
                    Component::Prefix(_) | Component::RootDir | Component::ParentDir
                )
            })
        {
            return Err(HelperError::OutsideInstallRoot);
        }
        Ok(())
    }

    fn reject_reparse_traversal(root: &Path, relative: &Path) -> Result<(), HelperError> {
        for ancestor in root.ancestors().collect::<Vec<_>>().into_iter().rev() {
            reject_reparse_point(ancestor)?;
        }
        let mut cursor = PathBuf::from(root);
        for component in relative.components() {
            cursor.push(component.as_os_str());
            reject_reparse_point(&cursor)?;
        }
        Ok(())
    }

    fn reject_reparse_point(path: &Path) -> Result<(), HelperError> {
        let metadata = fs::symlink_metadata(path).map_err(|_| HelperError::OperatingSystem)?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
            return Err(HelperError::ReparsePoint);
        }
        Ok(())
    }

    fn reject_writable_parents(root: &Path, relative: &Path) -> Result<(), HelperError> {
        for ancestor in root.ancestors().collect::<Vec<_>>().into_iter().rev() {
            reject_writable_directory(ancestor)?;
        }
        let mut cursor = PathBuf::from(root);
        let parent = relative.parent().ok_or(HelperError::OutsideInstallRoot)?;
        for component in parent.components() {
            cursor.push(component.as_os_str());
            reject_writable_directory(&cursor)?;
        }
        Ok(())
    }

    fn reject_writable_directory(path: &Path) -> Result<(), HelperError> {
        let wide = wide_path(path);
        let dangerous_rights = [
            FILE_ADD_FILE.0,
            FILE_ADD_SUBDIRECTORY.0,
            FILE_DELETE_CHILD.0,
            DELETE.0,
            WRITE_DAC.0,
            WRITE_OWNER.0,
        ];
        for right in dangerous_rights {
            // SAFETY: `wide` is NUL terminated. The call asks for access without
            // creating or modifying anything and the returned handle is closed.
            let result = unsafe {
                CreateFileW(
                    PCWSTR(wide.as_ptr()),
                    right,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    None,
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                    None,
                )
            };
            match result {
                Ok(handle) => {
                    // SAFETY: CreateFileW returned this owned handle.
                    unsafe {
                        let _ = CloseHandle(handle);
                    }
                    return Err(HelperError::WritableParent);
                }
                Err(error) if error.code() == ERROR_ACCESS_DENIED.to_hresult() => {}
                Err(_) => return Err(HelperError::OperatingSystem),
            }
        }
        Ok(())
    }

    fn file_identity(file: &std::fs::File) -> Result<FileIdentity, HelperError> {
        let mut information = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: the handle belongs to `file` and output points to initialized
        // storage of the exact Win32 structure type.
        unsafe {
            GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &raw mut information)
                .map_err(|_| HelperError::OperatingSystem)?;
        }
        Ok(FileIdentity {
            volume_serial_number: information.dwVolumeSerialNumber,
            file_index: (u64::from(information.nFileIndexHigh) << 32)
                | u64::from(information.nFileIndexLow),
            file_size: (u64::from(information.nFileSizeHigh) << 32)
                | u64::from(information.nFileSizeLow),
        })
    }

    fn hash_file(file: &mut std::fs::File) -> Result<[u8; 32], HelperError> {
        file.seek(SeekFrom::Start(0))
            .map_err(|_| HelperError::OperatingSystem)?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
        loop {
            let count = file
                .read(&mut buffer)
                .map_err(|_| HelperError::OperatingSystem)?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
        file.seek(SeekFrom::Start(0))
            .map_err(|_| HelperError::OperatingSystem)?;
        Ok(hasher.finalize().into())
    }

    fn file_version(path: &Path) -> Result<super::HelperVersion, HelperError> {
        let wide = wide_path(path);
        // SAFETY: `wide` is a NUL-terminated path valid for the call.
        let length = unsafe { GetFileVersionInfoSizeW(PCWSTR(wide.as_ptr()), None) };
        if length == 0 {
            return Err(HelperError::VersionMismatch);
        }
        let mut data =
            vec![0_u8; usize::try_from(length).map_err(|_| HelperError::OperatingSystem)?];
        // SAFETY: buffer is writable for exactly `length` bytes.
        unsafe {
            GetFileVersionInfoW(
                PCWSTR(wide.as_ptr()),
                None,
                length,
                data.as_mut_ptr().cast::<c_void>(),
            )
            .map_err(|_| HelperError::OperatingSystem)?;
        }
        let root = [u16::from(b'\\'), 0];
        let mut fixed_ptr = ptr::null_mut::<c_void>();
        let mut fixed_len = 0_u32;
        // SAFETY: version-data buffer remains alive; output is an interior pointer
        // valid until `data` is dropped.
        let found = unsafe {
            VerQueryValueW(
                data.as_ptr().cast::<c_void>(),
                PCWSTR(root.as_ptr()),
                &raw mut fixed_ptr,
                &raw mut fixed_len,
            )
        };
        if !found.as_bool()
            || fixed_ptr.is_null()
            || usize::try_from(fixed_len).map_err(|_| HelperError::OperatingSystem)?
                < size_of::<VS_FIXEDFILEINFO>()
        {
            return Err(HelperError::VersionMismatch);
        }
        // SAFETY: VerQueryValueW returned at least a VS_FIXEDFILEINFO. read_unaligned
        // avoids imposing alignment assumptions on the version-data buffer.
        let fixed = unsafe { ptr::read_unaligned(fixed_ptr.cast::<VS_FIXEDFILEINFO>()) };
        Ok(super::HelperVersion {
            major: u16::try_from(fixed.dwFileVersionMS >> 16).unwrap_or(u16::MAX),
            minor: u16::try_from(fixed.dwFileVersionMS & 0xffff).unwrap_or(u16::MAX),
            patch: u16::try_from(fixed.dwFileVersionLS >> 16).unwrap_or(u16::MAX),
            build: u16::try_from(fixed.dwFileVersionLS & 0xffff).unwrap_or(u16::MAX),
        })
    }

    fn verify_authenticode(
        file: &std::fs::File,
        path: &Path,
        expected_signer_sha256: [u8; 32],
    ) -> Result<(), HelperError> {
        let wide = wide_path(path);
        let mut file_info = WINTRUST_FILE_INFO {
            cbStruct: u32::try_from(size_of::<WINTRUST_FILE_INFO>()).unwrap_or(u32::MAX),
            pcwszFilePath: PCWSTR(wide.as_ptr()),
            hFile: HANDLE(file.as_raw_handle()),
            pgKnownSubject: ptr::null_mut(),
        };
        let mut data = WINTRUST_DATA {
            cbStruct: u32::try_from(size_of::<WINTRUST_DATA>()).unwrap_or(u32::MAX),
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
            dwUnionChoice: WTD_CHOICE_FILE,
            Anonymous: WINTRUST_DATA_0 {
                pFile: ptr::from_mut(&mut file_info),
            },
            dwStateAction: WTD_STATEACTION_VERIFY,
            dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL
                | WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT
                | WTD_LIFETIME_SIGNING_FLAG,
            ..WINTRUST_DATA::default()
        };
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        // SAFETY: all pointers in WINTRUST_DATA remain live through VERIFY and
        // CLOSE; UI is disabled and URL retrieval is cache-only.
        let status = unsafe {
            WinVerifyTrust(
                HWND::default(),
                &raw mut action,
                ptr::from_mut(&mut data).cast::<c_void>(),
            )
        };
        let signer_result = if status == i32::try_from(ERROR_SUCCESS.0).unwrap_or(0) {
            signer_certificate_hash(data.hWVTStateData)
                .and_then(|actual| (actual == expected_signer_sha256).then_some(()))
                .ok_or(HelperError::UntrustedSignature)
        } else {
            Err(HelperError::UntrustedSignature)
        };

        data.dwStateAction = WTD_STATEACTION_CLOSE;
        // SAFETY: closes the state created by the preceding VERIFY call. The same
        // backing structures and action GUID are still live.
        let close_status = unsafe {
            WinVerifyTrust(
                HWND::default(),
                &raw mut action,
                ptr::from_mut(&mut data).cast::<c_void>(),
            )
        };
        if close_status != i32::try_from(ERROR_SUCCESS.0).unwrap_or(0) {
            return Err(HelperError::UntrustedSignature);
        }
        signer_result
    }

    fn signer_certificate_hash(state: HANDLE) -> Option<[u8; 32]> {
        // SAFETY: `state` is live WinVerifyTrust provider state until CLOSE.
        let provider = unsafe { WTHelperProvDataFromStateData(state) };
        if provider.is_null() {
            return None;
        }
        // SAFETY: provider was returned by WinVerifyTrust and index zero requests
        // its primary signer.
        let signer = unsafe { WTHelperGetProvSignerFromChain(provider, 0, false, 0) };
        if signer.is_null() {
            return None;
        }
        // SAFETY: signer is non-null and remains owned by WinVerifyTrust state.
        let signer_ref = unsafe { &*signer };
        if signer_ref.csCertChain == 0 || signer_ref.pasCertChain.is_null() {
            return None;
        }
        // SAFETY: a non-zero chain count guarantees element zero is valid.
        let certificate = unsafe { &*signer_ref.pasCertChain };
        if certificate.pCert.is_null() {
            return None;
        }
        // SAFETY: pCert belongs to the live provider state and was checked non-null.
        let context = unsafe { &*certificate.pCert };
        let encoded_len = usize::try_from(context.cbCertEncoded).ok()?;
        if context.pbCertEncoded.is_null() || encoded_len == 0 || encoded_len > 1024 * 1024 {
            return None;
        }
        // SAFETY: CERT_CONTEXT exposes exactly cbCertEncoded bytes until the
        // provider state is closed below.
        let encoded = unsafe { core::slice::from_raw_parts(context.pbCertEncoded, encoded_len) };
        Some(Sha256::digest(encoded).into())
    }

    fn wide_path(path: &Path) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;

        path.as_os_str()
            .encode_wide()
            .chain(core::iter::once(0))
            .collect()
    }
}

#[cfg(all(test, windows))]
mod tests {
    use std::fmt::Write as _;
    use std::fs;
    use std::path::{Path, PathBuf};

    use super::{HelperError, HelperManifest, HelperVerifier, HelperVersion};

    fn manifest() -> Result<HelperManifest, HelperError> {
        HelperManifest::new(
            "approval-ui.exe",
            HelperVersion {
                major: 1,
                minor: 0,
                patch: 0,
                build: 0,
            },
            [1; 32],
            [2; 32],
        )
    }

    fn unique_temp_dir(label: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let mut random = [0_u8; 12];
        getrandom::fill(&mut random)
            .map_err(|_| std::io::Error::other("random generation failed"))?;
        let mut suffix = String::with_capacity(random.len() * 2);
        for byte in random {
            write!(&mut suffix, "{byte:02x}")?;
        }
        let path = std::env::temp_dir().join(format!("your-wallet-{label}-{suffix}"));
        fs::create_dir(&path)?;
        Ok(path)
    }

    fn verifier(root: &Path) -> Result<HelperVerifier, HelperError> {
        let entry = manifest()?;
        let digest = entry.digest();
        Ok(HelperVerifier::new(root.to_path_buf(), entry, digest))
    }

    #[test]
    fn manifest_hash_binds_version_and_signer() -> Result<(), Box<dyn std::error::Error>> {
        let first = manifest()?;
        let second = HelperManifest::new(
            "approval-ui.exe",
            HelperVersion {
                major: 1,
                minor: 0,
                patch: 0,
                build: 1,
            },
            [1; 32],
            [2; 32],
        )?;
        assert_ne!(first.digest(), second.digest());
        Ok(())
    }

    #[test]
    fn relative_paths_are_rejected_before_io() -> Result<(), Box<dyn std::error::Error>> {
        let verifier = verifier(Path::new("relative-root"))?;
        assert!(matches!(
            verifier.verify(Path::new("relative-root/approval-ui.exe")),
            Err(HelperError::NonAbsolutePath)
        ));
        Ok(())
    }

    #[test]
    fn path_outside_install_root_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_temp_dir("root")?;
        let outside = unique_temp_dir("outside")?.join("approval-ui.exe");
        fs::write(&outside, b"not-an-executable")?;
        let result = verifier(&root)?.verify(&outside);
        assert!(matches!(result, Err(HelperError::OutsideInstallRoot)));
        fs::remove_file(&outside)?;
        if let Some(parent) = outside.parent() {
            fs::remove_dir(parent)?;
        }
        fs::remove_dir(root)?;
        Ok(())
    }

    #[test]
    fn writable_install_root_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_temp_dir("writable")?;
        let candidate = root.join("approval-ui.exe");
        fs::write(&candidate, b"not-an-executable")?;
        let result = verifier(&root)?.verify(&candidate);
        assert!(matches!(result, Err(HelperError::WritableParent)));
        fs::remove_file(candidate)?;
        fs::remove_dir(root)?;
        Ok(())
    }

    #[test]
    fn reparse_component_is_rejected_when_supported() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::windows::fs::symlink_file;

        let root = unique_temp_dir("reparse-root")?;
        let target_dir = unique_temp_dir("reparse-target")?;
        let target = target_dir.join("target.exe");
        fs::write(&target, b"not-an-executable")?;
        let link = root.join("approval-ui.exe");
        match symlink_file(&target, &link) {
            Ok(()) => {
                let result = verifier(&root)?.verify(&link);
                assert!(matches!(result, Err(HelperError::ReparsePoint)));
                fs::remove_file(&link)?;
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::PermissionDenied
                    || error.raw_os_error() == Some(1314) => {}
            Err(error) => return Err(error.into()),
        }
        fs::remove_file(target)?;
        fs::remove_dir(target_dir)?;
        fs::remove_dir(root)?;
        Ok(())
    }
}
