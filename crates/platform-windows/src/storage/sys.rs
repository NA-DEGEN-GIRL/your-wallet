#![allow(unsafe_code)]

use core::ffi::c_void;
use core::mem::size_of;
use core::ptr;
use std::fs;
use std::io::{Read, Write};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle, RawHandle};
use std::path::{Component, Path, PathBuf, Prefix};

#[cfg(test)]
use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_PRIVILEGE_NOT_HELD};
use windows::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS, GENERIC_READ,
    GENERIC_WRITE, HANDLE, HLOCAL, LocalFree,
};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_REVISION, ACL_SIZE_INFORMATION, AclSizeInformation,
    DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation, GetLengthSid,
    GetSecurityDescriptorControl, GetSecurityDescriptorSacl, GetTokenInformation, IsValidAcl,
    IsValidSecurityDescriptor, IsValidSid, LABEL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SE_DACL_AUTO_INHERIT_REQ, SE_DACL_AUTO_INHERITED,
    SE_DACL_DEFAULTED, SE_DACL_PRESENT, SE_DACL_PROTECTED, SE_OWNER_DEFAULTED,
    SE_SACL_AUTO_INHERITED, SE_SACL_PRESENT, SE_SELF_RELATIVE, SECURITY_ATTRIBUTES,
    SYSTEM_MANDATORY_LABEL_ACE, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
#[cfg(test)]
use windows::Win32::Security::{
    GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, SE_SACL_AUTO_INHERIT_REQ,
    SE_SACL_DEFAULTED, SECURITY_DESCRIPTOR_RELATIVE, SID_AND_ATTRIBUTES, TOKEN_GROUPS, TokenGroups,
};
use windows::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CREATE_NEW, CreateDirectoryW, CreateFileW, DELETE, FILE_ALL_ACCESS,
    FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_DISPOSITION_INFO,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_WRITE_THROUGH,
    FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_ID_INFO, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES,
    FILE_REMOTE_PROTOCOL_INFO, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_DATA,
    FileDispositionInfo, FileIdInfo, FileRemoteProtocolInfo, FlushFileBuffers, GetDriveTypeW,
    GetFileInformationByHandle, GetFileInformationByHandleEx, GetFinalPathNameByHandleW,
    GetVolumeInformationByHandleW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    OPEN_ALWAYS, OPEN_EXISTING, READ_CONTROL, SetFileInformationByHandle, VOLUME_NAME_GUID,
};
#[cfg(test)]
use windows::Win32::Storage::FileSystem::{
    FILE_EXECUTE, FILE_SHARE_DELETE, WRITE_DAC, WRITE_OWNER,
};
#[cfg(test)]
use windows::Win32::System::SystemServices::ACCESS_SYSTEM_SECURITY;
#[cfg(test)]
use windows::Win32::System::SystemServices::SE_GROUP_LOGON_ID;
use windows::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, FILE_PERSISTENT_ACLS, SYSTEM_MANDATORY_LABEL_ACE_TYPE,
    SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::System::WindowsProgramming::DRIVE_FIXED;
#[cfg(test)]
use windows::Win32::System::WindowsProgramming::{
    DRIVE_CDROM, DRIVE_NO_ROOT_DIR, DRIVE_RAMDISK, DRIVE_REMOTE, DRIVE_REMOVABLE, DRIVE_UNKNOWN,
};
use windows::core::{BOOL, PCWSTR, PWSTR};

use crate::key_agent_storage::{FixedKeyAgentGenerationStoreRole, KeyAgentGenerationStoreBinding};

use super::{
    DurableBackend, FaultControl, FaultPoint, FileRole, RecordClass, StoreConfig, StoreError,
    hit_fault_with_security_revalidation, sha256,
};

const MIN_BINARY_SID_BYTES: usize = 8;
const MAX_BINARY_SID_BYTES: usize = 68;
const MAX_FINAL_PATH_UTF16: usize = 32_768;
const FILESYSTEM_NAME_UTF16: usize = 32;
const KEY_AGENT_FILE_ACCESS: u32 = FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0 | DELETE.0;
const LOW_MANDATORY_LABEL_SID: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 16, 0, 16, 0, 0];
// `INHERITED_ACE` is a byte flag in an ACE header. Keep the literal const-safe;
// the unit contract below pins it to the Windows binding constant.
const INHERITED_FILE_LABEL_ACE_FLAGS: u8 = 0x10;

#[derive(Clone, Copy, Eq, PartialEq)]
struct FileIdentity {
    volume_serial: u64,
    file_id: [u8; 16],
}

impl core::fmt::Debug for FileIdentity {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("FileIdentity([FILE_ID_INFO])")
    }
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "sealed Key-Agent backend is staged behind dormant release activation"
    )
)]
enum HeldRoot {
    Stable(std::fs::File),
    KeyAgent(KeyAgentGenerationStoreBinding),
}

impl HeldRoot {
    fn handle(&self) -> &std::fs::File {
        match self {
            Self::Stable(handle) => handle,
            Self::KeyAgent(binding) => binding.root_handle(),
        }
    }
}

pub(super) struct WindowsBackend {
    root: PathBuf,
    held_root: HeldRoot,
    root_identity: FileIdentity,
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "fixed lock path is retained for the dormant kernel exercise"
        )
    )]
    lock_path: PathBuf,
    lock_handle: std::fs::File,
    slot_paths: [PathBuf; 2],
    manifest_path: PathBuf,
    temp_paths: [PathBuf; 3],
    security_descriptor: SecurityDescriptor,
}

impl WindowsBackend {
    pub(super) fn open(config: &StoreConfig) -> Result<Self, StoreError> {
        validate_absolute_local_path(&config.root)?;
        reject_existing_reparse_ancestors(&config.root)?;
        let security_descriptor = SecurityDescriptor::current_user_only()?;
        create_root_if_missing(&config.root, &security_descriptor)?;
        reject_existing_reparse_ancestors(&config.root)?;

        let opened_root = open_directory(&config.root)?;
        verify_not_reparse(&opened_root)?;
        verify_stable_user_security(&opened_root, &security_descriptor.stable_user_sid)?;
        verify_supported_local_volume(&opened_root)?;
        let root_identity = file_identity(&opened_root)?;
        let canonical_root = fs::canonicalize(&config.root).map_err(|_| StoreError::UnsafePath)?;
        validate_absolute_local_path(&canonical_root)?;
        reject_existing_reparse_ancestors(&canonical_root)?;
        let root_handle = open_directory(&canonical_root)?;
        verify_not_reparse(&root_handle)?;
        verify_stable_user_security(&root_handle, &security_descriptor.stable_user_sid)?;
        verify_supported_local_volume(&root_handle)?;
        if file_identity(&root_handle)? != root_identity {
            return Err(StoreError::UnsafePath);
        }
        drop(opened_root);

        let lock_path = canonical_root.join(format!("{}.lock", config.namespace));
        let lock_handle = create_or_open_lock(&lock_path, &security_descriptor)?;

        let slot_paths = [
            canonical_root.join(format!("{}.slot0", config.namespace)),
            canonical_root.join(format!("{}.slot1", config.namespace)),
        ];
        let manifest_path = canonical_root.join(format!("{}.manifest", config.namespace));
        let temp_paths = [
            canonical_root.join(format!("{}.slot0.new", config.namespace)),
            canonical_root.join(format!("{}.slot1.new", config.namespace)),
            canonical_root.join(format!("{}.manifest.new", config.namespace)),
        ];

        let backend = Self {
            root: canonical_root,
            held_root: HeldRoot::Stable(root_handle),
            root_identity,
            lock_path,
            lock_handle,
            slot_paths,
            manifest_path,
            temp_paths,
            security_descriptor,
        };
        for temp in &backend.temp_paths {
            remove_stale_temp(temp, &backend.security_descriptor)?;
        }
        flush_directory(backend.held_root.handle())?;
        Ok(backend)
    }

    // The release integration consumes this only after its activation typestate
    // is wired; the kernel fixture exercises the same sealed constructor now.
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "sealed Key-Agent backend is staged behind dormant release activation"
        )
    )]
    pub(super) fn open_key_agent(
        binding: KeyAgentGenerationStoreBinding,
    ) -> Result<(Self, StoreConfig), StoreError> {
        binding.revalidate().map_err(|_| StoreError::UnsafePath)?;
        let root = binding.root_path().to_path_buf();
        let root_identity = file_identity(binding.root_handle())?;
        verify_not_reparse(binding.root_handle())?;

        let (namespace, class, max_ciphertext_bytes) = fixed_key_agent_store_spec(binding.role());
        let config = StoreConfig::new(root.clone(), namespace, class, max_ciphertext_bytes)?;
        let security_descriptor = SecurityDescriptor::for_key_agent_files(
            binding.stable_user_sid(),
            binding.profile_sid(),
        )?;

        let lock_path = root.join(format!("{}.lock", config.namespace));
        revalidate_key_agent_root_path(&binding, &root, root_identity)?;
        let lock_result = create_or_open_lock(&lock_path, &security_descriptor);
        revalidate_key_agent_root_path(&binding, &root, root_identity)?;
        let lock_handle = lock_result?;
        let slot_paths = [
            root.join(format!("{}.slot0", config.namespace)),
            root.join(format!("{}.slot1", config.namespace)),
        ];
        let manifest_path = root.join(format!("{}.manifest", config.namespace));
        let temp_paths = [
            root.join(format!("{}.slot0.new", config.namespace)),
            root.join(format!("{}.slot1.new", config.namespace)),
            root.join(format!("{}.manifest.new", config.namespace)),
        ];

        let backend = Self {
            root,
            held_root: HeldRoot::KeyAgent(binding),
            root_identity,
            lock_path,
            lock_handle,
            slot_paths,
            manifest_path,
            temp_paths,
            security_descriptor,
        };
        for temp in &backend.temp_paths {
            backend.remove_key_agent_stale_temp(temp)?;
        }
        flush_directory(backend.held_root.handle())?;
        backend.revalidate_held_root()?;
        Ok((backend, config))
    }

    fn path_for(&self, role: FileRole) -> &Path {
        match role {
            FileRole::Slot(slot) => &self.slot_paths[usize::from(slot)],
            FileRole::Manifest => &self.manifest_path,
        }
    }

    fn temp_path_for(&self, role: FileRole) -> &Path {
        match role {
            FileRole::Slot(slot) => &self.temp_paths[usize::from(slot)],
            FileRole::Manifest => &self.temp_paths[2],
        }
    }

    fn fault_points(role: FileRole) -> [FaultPoint; 5] {
        match role {
            FileRole::Slot(_) => [
                FaultPoint::SlotTempCreated,
                FaultPoint::SlotTempWritten,
                FaultPoint::SlotTempFlushed,
                FaultPoint::SlotReplaced,
                FaultPoint::SlotDirectoryFlushed,
            ],
            FileRole::Manifest => [
                FaultPoint::ManifestTempCreated,
                FaultPoint::ManifestTempWritten,
                FaultPoint::ManifestTempFlushed,
                FaultPoint::ManifestReplaced,
                FaultPoint::ManifestDirectoryFlushed,
            ],
        }
    }

    fn revalidate_held_root(&self) -> Result<(), StoreError> {
        if let HeldRoot::KeyAgent(binding) = &self.held_root {
            // Reject a hostile thread token before any handle or path query.
            binding.revalidate().map_err(|_| StoreError::UnsafePath)?;
        }
        let held = self.held_root.handle();
        verify_not_reparse(held)?;
        if file_identity(held)? != self.root_identity {
            return Err(StoreError::UnsafePath);
        }
        match &self.held_root {
            HeldRoot::Stable(_) => {
                verify_stable_user_security(held, &self.security_descriptor.stable_user_sid)?;
                verify_supported_local_volume(held)?;
            }
            HeldRoot::KeyAgent(binding) => {
                // The startup-bound parent peer already proved fixed local NTFS.
                // The zero-capability LPAC child must not repeat unavailable
                // volume-management queries; it instead retains and revalidates
                // the exact full-identity root binding.
                binding.revalidate().map_err(|_| StoreError::UnsafePath)?;
            }
        }
        let reopened = open_directory(&self.root)?;
        verify_not_reparse(&reopened)?;
        if file_identity(&reopened)? != self.root_identity {
            return Err(StoreError::UnsafePath);
        }
        if let HeldRoot::KeyAgent(binding) = &self.held_root {
            // End every Key-Agent path preparation with the binding's second
            // thread-impersonation rejection immediately before the caller's
            // fixed child-path operation.
            binding.revalidate().map_err(|_| StoreError::UnsafePath)?;
        }
        Ok(())
    }

    fn prepare_key_agent_path_operation(&self) -> Result<(), StoreError> {
        if matches!(&self.held_root, HeldRoot::KeyAgent(_)) {
            self.revalidate_held_root()?;
        }
        Ok(())
    }

    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "sealed Key-Agent backend is staged behind dormant release activation"
        )
    )]
    fn remove_key_agent_stale_temp(&self, path: &Path) -> Result<(), StoreError> {
        self.prepare_key_agent_path_operation()?;
        let opened = open_stale_temp(path);
        self.prepare_key_agent_path_operation()?;
        let Some(file) = opened? else {
            return Ok(());
        };
        verify_persistent_file(&file, &self.security_descriptor)?;
        self.prepare_key_agent_path_operation()?;
        let deletion = mark_file_for_deletion(&file);
        drop(file);
        self.prepare_key_agent_path_operation()?;
        deletion
    }

    #[cfg(test)]
    #[allow(
        clippy::too_many_lines,
        reason = "linear seven-file kernel proof keeps access checks and cleanup ordering auditable"
    )]
    pub(super) fn verify_and_cleanup_key_agent_role_for_test(self) -> Result<(), StoreError> {
        let Self {
            root,
            held_root,
            root_identity,
            lock_path,
            lock_handle,
            slot_paths,
            manifest_path,
            temp_paths,
            security_descriptor,
        } = self;
        let HeldRoot::KeyAgent(binding) = held_root else {
            return Err(StoreError::UnsafePath);
        };
        drop(lock_handle);

        let mut all_paths = Vec::with_capacity(7);
        all_paths.push(lock_path);
        all_paths.extend(slot_paths);
        all_paths.push(manifest_path);
        all_paths.extend(temp_paths.iter().cloned());
        let mut cleanup = KeyAgentTestCleanup {
            binding: &binding,
            root: &root,
            root_identity,
            descriptor: &security_descriptor,
            paths: &all_paths,
            armed: true,
        };

        // Successful commits must leave no `.new` files. Create each exact temp
        // role once so the kernel checks below cover all seven physical names.
        for (index, path) in temp_paths.iter().enumerate() {
            revalidate_key_agent_root_path(&binding, &root, root_identity)?;
            let absent = open_existing_file(path);
            revalidate_key_agent_root_path(&binding, &root, root_identity)?;
            match absent {
                Err(error) if is_not_found(&error) => {}
                Ok(_) | Err(_) => return Err(StoreError::DurabilityFailure),
            }

            revalidate_key_agent_root_path(&binding, &root, root_identity)?;
            let created = create_new_write_through(path, &security_descriptor);
            revalidate_key_agent_root_path(&binding, &root, root_identity)?;
            let mut file = created?;
            file.write_all(&[u8::try_from(index).unwrap_or(u8::MAX).saturating_add(1)])
                .map_err(|_| StoreError::DurabilityFailure)?;
            flush_file(&file)?;
            verify_persistent_file(&file, &security_descriptor)?;
            if file_identity(&file)?.volume_serial != root_identity.volume_serial {
                return Err(StoreError::UnsafePath);
            }
        }

        let mut identities = Vec::with_capacity(all_paths.len());
        for path in &all_paths {
            revalidate_key_agent_root_path(&binding, &root, root_identity)?;
            let opened = open_existing_file(path);
            revalidate_key_agent_root_path(&binding, &root, root_identity)?;
            let file = opened.map_err(|_| StoreError::DurabilityFailure)?;
            verify_persistent_file(&file, &security_descriptor)?;
            let identity = file_identity(&file)?;
            if identity.volume_serial != root_identity.volume_serial {
                return Err(StoreError::UnsafePath);
            }
            drop(file);

            for forbidden_access in [
                WRITE_DAC.0,
                WRITE_OWNER.0,
                FILE_EXECUTE.0,
                ACCESS_SYSTEM_SECURITY,
            ] {
                revalidate_key_agent_root_path(&binding, &root, root_identity)?;
                let denied = request_exact_file_access(path, forbidden_access);
                revalidate_key_agent_root_path(&binding, &root, root_identity)?;
                require_forbidden_access_denial(denied, forbidden_access)?;
            }

            revalidate_key_agent_root_path(&binding, &root, root_identity)?;
            let reopened = open_existing_file(path);
            revalidate_key_agent_root_path(&binding, &root, root_identity)?;
            let reopened = reopened.map_err(|_| StoreError::DurabilityFailure)?;
            verify_persistent_file(&reopened, &security_descriptor)?;
            if file_identity(&reopened)? != identity {
                return Err(StoreError::UnsafePath);
            }
            identities.push(identity);
        }

        for (path, expected_identity) in all_paths.iter().zip(identities) {
            revalidate_key_agent_root_path(&binding, &root, root_identity)?;
            let opened = open_stale_temp(path);
            revalidate_key_agent_root_path(&binding, &root, root_identity)?;
            let file = opened?.ok_or(StoreError::DurabilityFailure)?;
            verify_persistent_file(&file, &security_descriptor)?;
            if file_identity(&file)? != expected_identity {
                return Err(StoreError::UnsafePath);
            }
            revalidate_key_agent_root_path(&binding, &root, root_identity)?;
            let deleted = mark_file_for_deletion(&file);
            drop(file);
            revalidate_key_agent_root_path(&binding, &root, root_identity)?;
            deleted?;

            let reopened = open_existing_file(path);
            revalidate_key_agent_root_path(&binding, &root, root_identity)?;
            match reopened {
                Err(error) if is_not_found(&error) => {}
                Ok(_) | Err(_) => return Err(StoreError::DurabilityFailure),
            }
        }
        flush_directory(binding.root_handle())?;
        revalidate_key_agent_root_path(&binding, &root, root_identity)?;
        cleanup.armed = false;
        Ok(())
    }
}

#[cfg(test)]
struct KeyAgentTestCleanup<'a> {
    binding: &'a KeyAgentGenerationStoreBinding,
    root: &'a Path,
    root_identity: FileIdentity,
    descriptor: &'a SecurityDescriptor,
    paths: &'a [PathBuf],
    armed: bool,
}

#[cfg(test)]
impl Drop for KeyAgentTestCleanup<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        for path in self.paths {
            if revalidate_key_agent_root_path(self.binding, self.root, self.root_identity).is_err()
            {
                continue;
            }
            let opened = open_stale_temp(path);
            if revalidate_key_agent_root_path(self.binding, self.root, self.root_identity).is_err()
            {
                continue;
            }
            let Ok(Some(file)) = opened else {
                continue;
            };
            if verify_persistent_file(&file, self.descriptor).is_err() {
                continue;
            }
            let Ok(identity) = file_identity(&file) else {
                continue;
            };
            if identity.volume_serial != self.root_identity.volume_serial {
                continue;
            }
            if revalidate_key_agent_root_path(self.binding, self.root, self.root_identity).is_err()
            {
                continue;
            }
            let deletion = mark_file_for_deletion(&file);
            let post_mark_revalidation =
                revalidate_key_agent_root_path(self.binding, self.root, self.root_identity);
            drop(file);
            let post_close_revalidation =
                revalidate_key_agent_root_path(self.binding, self.root, self.root_identity);
            let _ = (deletion, post_mark_revalidation, post_close_revalidation);
        }
        if revalidate_key_agent_root_path(self.binding, self.root, self.root_identity).is_ok() {
            let flushed = flush_directory(self.binding.root_handle());
            let post_flush_revalidation =
                revalidate_key_agent_root_path(self.binding, self.root, self.root_identity);
            let _ = (flushed, post_flush_revalidation);
        }
    }
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "sealed Key-Agent backend is staged behind dormant release activation"
    )
)]
fn revalidate_key_agent_root_path(
    binding: &KeyAgentGenerationStoreBinding,
    root: &Path,
    expected_identity: FileIdentity,
) -> Result<(), StoreError> {
    binding.revalidate().map_err(|_| StoreError::UnsafePath)?;
    let reopened = open_directory(root)?;
    verify_not_reparse(&reopened)?;
    if file_identity(&reopened)? != expected_identity {
        return Err(StoreError::UnsafePath);
    }
    // End adjacent to the caller's fixed child-path operation with the sealed
    // binding's thread-impersonation and held-root identity checks.
    binding.revalidate().map_err(|_| StoreError::UnsafePath)
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "fixed Key-Agent roles are staged behind dormant release activation"
    )
)]
fn fixed_key_agent_store_spec(
    role: FixedKeyAgentGenerationStoreRole,
) -> (&'static str, RecordClass, usize) {
    // These names and bounds are durable format contracts, not caller input.
    // Vault is its 112-byte header plus secret-core's 4 MiB ciphertext bound;
    // settings is its 210-byte plaintext bound plus the 16-byte AEAD tag.
    match role {
        FixedKeyAgentGenerationStoreRole::Vault => ("vault", RecordClass::Vault, 4_194_416),
        FixedKeyAgentGenerationStoreRole::NonceLedger => {
            ("nonce-ledger", RecordClass::NonceLedger, 16_777_216)
        }
        FixedKeyAgentGenerationStoreRole::SignedCandidateJournal => (
            "signed-candidate-journal",
            RecordClass::SignedCandidateJournal,
            16_777_216,
        ),
        FixedKeyAgentGenerationStoreRole::LocalSettings => {
            ("local-settings", RecordClass::LocalSettings, 226)
        }
    }
}

impl core::fmt::Debug for WindowsBackend {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("WindowsBackend")
            .field("root", &"[HELD SECURE DIRECTORY]")
            .field("root_identity", &self.root_identity)
            .field("lock_handle", &"[HELD EXCLUSIVE FILE]")
            .finish_non_exhaustive()
    }
}

impl DurableBackend for WindowsBackend {
    fn revalidate_security_context(&self) -> Result<(), StoreError> {
        // Stable-user stores deliberately retain their existing behavior;
        // sealed Key-Agent stores reject impersonation and rebind the exact
        // held root identity around every untrusted callback.
        self.prepare_key_agent_path_operation()
    }

    fn read(&self, role: FileRole, max_bytes: usize) -> Result<Option<Vec<u8>>, StoreError> {
        self.revalidate_held_root()?;
        let path = self.path_for(role);
        self.prepare_key_agent_path_operation()?;
        let opened = open_existing_file(path);
        self.prepare_key_agent_path_operation()?;
        let file = match opened {
            Ok(file) => file,
            Err(error) if is_not_found(&error) => return Ok(None),
            Err(_) => return Err(StoreError::DurabilityFailure),
        };
        verify_persistent_file(&file, &self.security_descriptor)?;
        let length = usize::try_from(
            file.metadata()
                .map_err(|_| StoreError::DurabilityFailure)?
                .len(),
        )
        .map_err(|_| StoreError::BoundsExceeded)?;
        if length > max_bytes {
            return Err(StoreError::BoundsExceeded);
        }
        let mut bytes = Vec::with_capacity(length);
        file.take(
            u64::try_from(max_bytes)
                .map_err(|_| StoreError::BoundsExceeded)?
                .saturating_add(1),
        )
        .read_to_end(&mut bytes)
        .map_err(|_| StoreError::DurabilityFailure)?;
        if bytes.len() > max_bytes {
            return Err(StoreError::BoundsExceeded);
        }
        Ok(Some(bytes))
    }

    fn atomic_write(
        &mut self,
        role: FileRole,
        bytes: &[u8],
        fault: &mut dyn FaultControl,
    ) -> Result<(), StoreError> {
        self.revalidate_held_root()?;
        verify_persistent_file(&self.lock_handle, &self.security_descriptor)?;
        let target = self.path_for(role);
        let temp = self.temp_path_for(role);
        let points = Self::fault_points(role);

        self.prepare_key_agent_path_operation()?;
        let initial_target = open_existing_file(target);
        self.prepare_key_agent_path_operation()?;
        let initial_target_identity = inspect_optional_target(
            initial_target,
            &self.security_descriptor,
            self.root_identity.volume_serial,
        )?;

        self.prepare_key_agent_path_operation()?;
        let created = create_new_write_through(temp, &self.security_descriptor);
        self.prepare_key_agent_path_operation()?;
        let mut file = created?;
        let temp_identity = file_identity(&file)?;
        if temp_identity.volume_serial != self.root_identity.volume_serial {
            return Err(StoreError::UnsafePath);
        }
        hit_fault_with_security_revalidation(self, fault, points[0])?;
        file.write_all(bytes)
            .map_err(|_| StoreError::DurabilityFailure)?;
        hit_fault_with_security_revalidation(self, fault, points[1])?;
        flush_file(&file)?;
        verify_persistent_file(&file, &self.security_descriptor)?;
        if file_identity(&file)? != temp_identity {
            return Err(StoreError::UnsafePath);
        }
        hit_fault_with_security_revalidation(self, fault, points[2])?;
        drop(file);

        // Refuse to use replacement as an ACL, owner, reparse, or hard-link
        // repair mechanism. The verified handle must close before MoveFileExW,
        // leaving only the unavoidable path-name race of that Win32 primitive;
        // the installed full-identity readback below still fails closed.
        self.prepare_key_agent_path_operation()?;
        let existing_target = open_existing_file(target);
        self.prepare_key_agent_path_operation()?;
        let existing_target_identity = inspect_optional_target(
            existing_target,
            &self.security_descriptor,
            self.root_identity.volume_serial,
        )?;
        if existing_target_identity != initial_target_identity {
            return Err(StoreError::UnsafePath);
        }

        self.prepare_key_agent_path_operation()?;
        let replaced = atomic_replace(temp, target);
        self.prepare_key_agent_path_operation()?;
        replaced?;
        hit_fault_with_security_revalidation(self, fault, points[3])?;
        self.prepare_key_agent_path_operation()?;
        let installed = open_existing_file(target);
        self.prepare_key_agent_path_operation()?;
        let installed = installed.map_err(|_| StoreError::DurabilityFailure)?;
        verify_installed_readback(
            &installed,
            temp_identity,
            self.root_identity.volume_serial,
            bytes,
            sha256(bytes),
            &self.security_descriptor,
        )?;
        self.prepare_key_agent_path_operation()?;
        let rebound = open_existing_file(target);
        self.prepare_key_agent_path_operation()?;
        let rebound = rebound.map_err(|_| StoreError::DurabilityFailure)?;
        verify_persistent_file(&rebound, &self.security_descriptor)?;
        if file_identity(&rebound)? != temp_identity {
            return Err(StoreError::UnsafePath);
        }
        flush_directory(self.held_root.handle())?;
        self.revalidate_held_root()?;
        hit_fault_with_security_revalidation(self, fault, points[4])?;
        Ok(())
    }
}

struct SecurityDescriptor {
    descriptor: PSECURITY_DESCRIPTOR,
    stable_user_sid: StableUserSid,
    profile_sid: Option<StableUserSid>,
}

impl SecurityDescriptor {
    fn current_user_only() -> Result<Self, StoreError> {
        let stable_user_sid = current_stable_user_sid()?;
        Self::for_stable_user(stable_user_sid)
    }

    fn for_stable_user(stable_user_sid: StableUserSid) -> Result<Self, StoreError> {
        let sid_text = sid_to_string(stable_user_sid.as_psid())?;
        let sddl = format!(
            "O:{sid_text}D:P(A;;0x{:08x};;;{sid_text})",
            FILE_ALL_ACCESS.0
        );
        Self::from_sddl(stable_user_sid, &sddl)
    }

    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "sealed Key-Agent backend is staged behind dormant release activation"
        )
    )]
    fn for_key_agent_files(stable_user: PSID, profile: PSID) -> Result<Self, StoreError> {
        let stable_user_sid = StableUserSid(copy_sid(stable_user)?);
        let profile_sid = StableUserSid(copy_sid(profile)?);
        // SAFETY: both owned SID copies are valid and live for this comparison.
        if unsafe { EqualSid(stable_user_sid.as_psid(), profile_sid.as_psid()) }.is_ok() {
            return Err(StoreError::WrongStoragePrincipal);
        }
        let user_text = sid_to_string(stable_user_sid.as_psid())?;
        let profile_text = sid_to_string(profile_sid.as_psid())?;
        let sddl = format!(
            "O:{user_text}D:P(A;;0x{:08x};;;{user_text})(A;;0x{KEY_AGENT_FILE_ACCESS:08x};;;{profile_text})",
            FILE_ALL_ACCESS.0,
        );
        Self::from_sddl_with_profile(stable_user_sid, profile_sid, &sddl)
    }

    fn from_sddl(stable_user_sid: StableUserSid, sddl: &str) -> Result<Self, StoreError> {
        Self::from_sddl_policy(stable_user_sid, None, sddl)
    }

    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "sealed Key-Agent backend is staged behind dormant release activation"
        )
    )]
    fn from_sddl_with_profile(
        stable_user_sid: StableUserSid,
        profile_sid: StableUserSid,
        sddl: &str,
    ) -> Result<Self, StoreError> {
        Self::from_sddl_policy(stable_user_sid, Some(profile_sid), sddl)
    }

    fn from_sddl_policy(
        stable_user_sid: StableUserSid,
        profile_sid: Option<StableUserSid>,
        sddl: &str,
    ) -> Result<Self, StoreError> {
        let wide = wide_nul(sddl);
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: `wide` is NUL terminated and the output allocation is owned by
        // this value until released with LocalFree.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide.as_ptr()),
                SDDL_REVISION_1,
                &raw mut descriptor,
                None,
            )
            .map_err(|_| StoreError::DurabilityFailure)?;
            if !IsValidSecurityDescriptor(descriptor).as_bool() {
                let _ = LocalFree(Some(HLOCAL(descriptor.0)));
                return Err(StoreError::DurabilityFailure);
            }
        }
        Ok(Self {
            descriptor,
            stable_user_sid,
            profile_sid,
        })
    }

    fn verify_file_security(&self, file: &std::fs::File) -> Result<(), StoreError> {
        match &self.profile_sid {
            Some(profile_sid) => {
                verify_key_agent_file_security(file, &self.stable_user_sid, profile_sid)
            }
            None => verify_stable_user_security(file, &self.stable_user_sid),
        }
    }

    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(u32::MAX),
            lpSecurityDescriptor: self.descriptor.0,
            bInheritHandle: BOOL(0),
        }
    }

    #[cfg(test)]
    fn inspect_for_test(&self, expected_sid: &StableUserSid) -> Result<(), StoreError> {
        let (owner, dacl) = self.parts_for_test()?;
        inspect_security_descriptor(self.descriptor, owner, dacl, expected_sid)
    }

    #[cfg(test)]
    fn inspect_key_agent_creation_for_test(&self) -> Result<(), StoreError> {
        let profile_sid = self
            .profile_sid
            .as_ref()
            .ok_or(StoreError::WrongStoragePrincipal)?;
        let (owner, dacl) = self.parts_for_test()?;
        let control = inspect_descriptor_control(self.descriptor)?;
        let required = security_control_flag(SE_SELF_RELATIVE)
            | security_control_flag(SE_DACL_PRESENT)
            | security_control_flag(SE_DACL_PROTECTED);
        if control != required {
            return Err(StoreError::InsecurePermissions);
        }
        inspect_owner(owner, &self.stable_user_sid)?;
        inspect_exact_key_agent_dacl(dacl, &self.stable_user_sid, profile_sid)
    }

    #[cfg(test)]
    fn inspect_key_agent_file_for_test(&self) -> Result<(), StoreError> {
        let profile_sid = self
            .profile_sid
            .as_ref()
            .ok_or(StoreError::WrongStoragePrincipal)?;
        let (owner, dacl) = self.parts_for_test()?;
        let mut sacl_present = BOOL(0);
        let mut sacl_defaulted = BOOL(0);
        let mut sacl = ptr::null_mut::<ACL>();
        // SAFETY: the self-relative descriptor remains live and all outputs are
        // initialized writable storage.
        unsafe {
            GetSecurityDescriptorSacl(
                self.descriptor,
                &raw mut sacl_present,
                &raw mut sacl,
                &raw mut sacl_defaulted,
            )
            .map_err(|_| StoreError::InsecurePermissions)?;
        }
        if !sacl_present.as_bool() || sacl_defaulted.as_bool() || sacl.is_null() {
            return Err(StoreError::InsecurePermissions);
        }
        inspect_key_agent_file_security_descriptor(
            self.descriptor,
            owner,
            dacl,
            sacl,
            &self.stable_user_sid,
            profile_sid,
        )
    }

    #[cfg(test)]
    fn parts_for_test(&self) -> Result<(PSID, *mut ACL), StoreError> {
        let mut owner = PSID::default();
        let mut owner_defaulted = BOOL(0);
        let mut dacl_present = BOOL(0);
        let mut dacl = ptr::null_mut::<ACL>();
        let mut dacl_defaulted = BOOL(0);
        // SAFETY: the allocated self-relative descriptor remains live and all
        // output pointers refer to initialized stack storage.
        unsafe {
            GetSecurityDescriptorOwner(self.descriptor, &raw mut owner, &raw mut owner_defaulted)
                .map_err(|_| StoreError::InsecurePermissions)?;
            GetSecurityDescriptorDacl(
                self.descriptor,
                &raw mut dacl_present,
                &raw mut dacl,
                &raw mut dacl_defaulted,
            )
            .map_err(|_| StoreError::InsecurePermissions)?;
        }
        if !dacl_present.as_bool()
            || dacl.is_null()
            || owner.0.is_null()
            || owner_defaulted.as_bool()
            || dacl_defaulted.as_bool()
        {
            return Err(StoreError::InsecurePermissions);
        }
        Ok((owner, dacl))
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: the descriptor was allocated by LocalAlloc through the SDDL
        // conversion API and is released exactly once.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(self.descriptor.0)));
        }
    }
}

impl core::fmt::Debug for SecurityDescriptor {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.profile_sid.is_some() {
            formatter.write_str("SecurityDescriptor([KEY AGENT DUAL-PRINCIPAL FILE POLICY])")
        } else {
            formatter.write_str("SecurityDescriptor([STABLE TOKEN USER SID ONLY])")
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
struct StableUserSid(Vec<u8>);

impl StableUserSid {
    fn as_psid(&self) -> PSID {
        PSID(self.0.as_ptr().cast_mut().cast::<c_void>())
    }

    #[cfg(test)]
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for StableUserSid {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

impl core::fmt::Debug for StableUserSid {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("StableUserSid([REDACTED])")
    }
}

fn validate_absolute_local_path(path: &Path) -> Result<(), StoreError> {
    use std::os::windows::ffi::OsStrExt as _;

    if !path.is_absolute() {
        return Err(StoreError::UnsafePath);
    }
    if path.as_os_str().encode_wide().any(|unit| unit == 0) {
        return Err(StoreError::UnsafePath);
    }
    let mut components = path.components();
    let Some(Component::Prefix(prefix)) = components.next() else {
        return Err(StoreError::UnsafePath);
    };
    if !matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
        || !matches!(components.next(), Some(Component::RootDir))
        || components.any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(StoreError::UnsafePath);
    }
    Ok(())
}

fn verify_supported_local_volume(directory: &std::fs::File) -> Result<(), StoreError> {
    let drive_root = drive_root_for_held_handle(directory)?;
    // SAFETY: `drive_root` is a NUL-terminated volume-GUID root derived from
    // the final path of the live directory handle.
    let drive_type = unsafe { GetDriveTypeW(PCWSTR(drive_root.as_ptr())) };

    let mut remote_protocol = FILE_REMOTE_PROTOCOL_INFO::default();
    // A successful FileRemoteProtocolInfo query proves a redirector-backed
    // handle. Local handles normally reject this information class. Combined
    // with the fixed-drive and volume checks below, failure cannot turn an
    // unsupported remote store into an accepted one.
    // SAFETY: the live directory handle and exact output structure are valid
    // for the complete call.
    let remote_protocol_query_succeeded = unsafe {
        GetFileInformationByHandleEx(
            HANDLE(directory.as_raw_handle()),
            FileRemoteProtocolInfo,
            ptr::from_mut(&mut remote_protocol).cast::<c_void>(),
            u32::try_from(size_of::<FILE_REMOTE_PROTOCOL_INFO>()).unwrap_or(u32::MAX),
        )
    }
    .is_ok();

    let mut filesystem_flags = 0_u32;
    let mut filesystem_name = [0_u16; FILESYSTEM_NAME_UTF16];
    // SAFETY: outputs are fixed initialized storage and the held directory
    // handle remains live. This volume API is unsupported over SMB and failure
    // is therefore treated as an unsafe/unprovable storage location.
    unsafe {
        GetVolumeInformationByHandleW(
            HANDLE(directory.as_raw_handle()),
            None,
            None,
            None,
            Some(&raw mut filesystem_flags),
            Some(&mut filesystem_name),
        )
    }
    .map_err(|_| StoreError::UnsafePath)?;
    validate_volume_characteristics(
        drive_type,
        remote_protocol_query_succeeded,
        filesystem_flags,
        &filesystem_name,
    )
}

fn validate_volume_characteristics(
    drive_type: u32,
    remote_protocol_query_succeeded: bool,
    filesystem_flags: u32,
    filesystem_name: &[u16],
) -> Result<(), StoreError> {
    if drive_type != DRIVE_FIXED
        || remote_protocol_query_succeeded
        || filesystem_flags & FILE_PERSISTENT_ACLS == 0
        || !is_allowed_filesystem_name(filesystem_name)
    {
        return Err(StoreError::UnsafePath);
    }
    Ok(())
}

fn drive_root_for_held_handle(directory: &std::fs::File) -> Result<Vec<u16>, StoreError> {
    let mut final_path = vec![0_u16; MAX_FINAL_PATH_UTF16];
    // SAFETY: the handle remains live and the initialized output slice is
    // writable for its complete declared length.
    let length = unsafe {
        GetFinalPathNameByHandleW(
            HANDLE(directory.as_raw_handle()),
            &mut final_path,
            VOLUME_NAME_GUID,
        )
    };
    let length = usize::try_from(length).map_err(|_| StoreError::UnsafePath)?;
    if length == 0 || length >= final_path.len() {
        return Err(StoreError::UnsafePath);
    }
    volume_guid_root_from_final_path(&final_path[..length])
}

fn volume_guid_root_from_final_path(path: &[u16]) -> Result<Vec<u16>, StoreError> {
    let prefix = "\\\\?\\Volume{".encode_utf16().collect::<Vec<_>>();
    if path.len() <= prefix.len()
        || !path[..prefix.len()]
            .iter()
            .zip(&prefix)
            .all(|(actual, expected)| {
                u8::try_from(*actual)
                    .ok()
                    .zip(u8::try_from(*expected).ok())
                    .is_some_and(|(actual, expected)| actual.eq_ignore_ascii_case(&expected))
            })
    {
        return Err(StoreError::UnsafePath);
    }
    let closing_brace = path[prefix.len()..]
        .iter()
        .position(|unit| *unit == u16::from(b'}'))
        .and_then(|offset| prefix.len().checked_add(offset))
        .ok_or(StoreError::UnsafePath)?;
    if !is_canonical_volume_guid(&path[prefix.len()..closing_brace]) {
        return Err(StoreError::UnsafePath);
    }
    let root_end = closing_brace.checked_add(2).ok_or(StoreError::UnsafePath)?;
    if path.get(closing_brace + 1) != Some(&u16::from(b'\\')) {
        return Err(StoreError::UnsafePath);
    }
    let mut root = path.get(..root_end).ok_or(StoreError::UnsafePath)?.to_vec();
    root.push(0);
    Ok(root)
}

fn is_canonical_volume_guid(value: &[u16]) -> bool {
    value.len() == 36
        && value.iter().enumerate().all(|(index, unit)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                *unit == u16::from(b'-')
            } else {
                u8::try_from(*unit).is_ok_and(|byte| byte.is_ascii_hexdigit())
            }
        })
}

fn is_allowed_filesystem_name(buffer: &[u16]) -> bool {
    let Some(end) = buffer.iter().position(|unit| *unit == 0) else {
        return false;
    };
    if buffer[end..].iter().any(|unit| *unit != 0) {
        return false;
    }
    let name = &buffer[..end];
    // All identity checks now retain full FILE_ID_INFO. NTFS nevertheless
    // remains the sealed allowlist because its ACL inheritance, hard-link, and
    // directory-durability behavior is the policy proved by this backend.
    ascii_utf16_eq_ignore_case(name, b"NTFS")
}

fn ascii_utf16_eq_ignore_case(value: &[u16], expected: &[u8]) -> bool {
    value.len() == expected.len()
        && value.iter().zip(expected).all(|(unit, expected)| {
            u8::try_from(*unit).is_ok_and(|unit| unit.eq_ignore_ascii_case(expected))
        })
}

fn reject_existing_reparse_ancestors(path: &Path) -> Result<(), StoreError> {
    for ancestor in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 => {
                return Err(StoreError::UnsafePath);
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(StoreError::UnsafePath),
        }
    }
    Ok(())
}

fn create_root_if_missing(root: &Path, descriptor: &SecurityDescriptor) -> Result<(), StoreError> {
    if root.exists() {
        return Ok(());
    }
    let parent = root.parent().ok_or(StoreError::UnsafePath)?;
    if !parent.is_dir() {
        return Err(StoreError::UnsafePath);
    }
    let path = wide_path(root);
    let attributes = descriptor.attributes();
    // SAFETY: the absolute path is NUL terminated and the security descriptor
    // remains live for the complete call.
    let result =
        unsafe { CreateDirectoryW(PCWSTR(path.as_ptr()), Some(ptr::from_ref(&attributes))) };
    if let Err(error) = result
        && error.code() != ERROR_ALREADY_EXISTS.to_hresult()
    {
        return Err(StoreError::DurabilityFailure);
    }
    Ok(())
}

fn open_directory(path: &Path) -> Result<std::fs::File, StoreError> {
    let wide = wide_path(path);
    // SAFETY: NUL-terminated path; requested handle has query/list access and no
    // delete sharing so ordinary replacement is held off while the store lives.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_READ_ATTRIBUTES.0 | FILE_LIST_DIRECTORY.0 | READ_CONTROL.0 | GENERIC_WRITE.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map_err(|_| StoreError::UnsafePath)?;
    // SAFETY: CreateFileW returned one owned Win32 handle which is transferred
    // to `File` exactly once.
    Ok(unsafe { std::fs::File::from_raw_handle(handle.0 as RawHandle) })
}

fn open_existing_file(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ.0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)
}

fn inspect_optional_target(
    opened: std::io::Result<std::fs::File>,
    descriptor: &SecurityDescriptor,
    expected_volume_serial: u64,
) -> Result<Option<FileIdentity>, StoreError> {
    match opened {
        Ok(file) => {
            verify_persistent_file(&file, descriptor)?;
            let identity = file_identity(&file)?;
            if identity.volume_serial != expected_volume_serial {
                return Err(StoreError::UnsafePath);
            }
            Ok(Some(identity))
        }
        Err(error) if is_not_found(&error) => Ok(None),
        Err(_) => Err(StoreError::DurabilityFailure),
    }
}

#[cfg(test)]
fn request_exact_file_access(path: &Path, desired_access: u32) -> windows::core::Result<HANDLE> {
    let wide = wide_path(path);
    // SAFETY: the fixed file path is NUL terminated and OPEN_REPARSE_POINT
    // prevents an access probe from following an unexpected reparse object.
    unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            desired_access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
}

#[cfg(test)]
fn require_forbidden_access_denial(
    result: windows::core::Result<HANDLE>,
    desired_access: u32,
) -> Result<(), StoreError> {
    // ACCESS_SYSTEM_SECURITY is privilege-gated before the DACL result is
    // surfaced by CreateFileW. The zero-capability LPAC therefore proves its
    // fail-closed result as ERROR_PRIVILEGE_NOT_HELD; DACL-governed file rights
    // must reach the distinct ERROR_ACCESS_DENIED result.
    match result {
        Err(error)
            if desired_access == ACCESS_SYSTEM_SECURITY
                && error.code() == ERROR_PRIVILEGE_NOT_HELD.to_hresult() =>
        {
            Ok(())
        }
        Err(error)
            if desired_access != ACCESS_SYSTEM_SECURITY
                && error.code() == ERROR_ACCESS_DENIED.to_hresult() =>
        {
            Ok(())
        }
        Err(_) => Err(StoreError::DurabilityFailure),
        Ok(handle) => {
            // SAFETY: a successful probe returned one owned handle, transferred
            // exactly once so the negative test cannot leak it.
            drop(unsafe { std::fs::File::from_raw_handle(handle.0 as RawHandle) });
            Err(StoreError::InsecurePermissions)
        }
    }
}

fn create_or_open_lock(
    path: &Path,
    descriptor: &SecurityDescriptor,
) -> Result<std::fs::File, StoreError> {
    let wide = wide_path(path);
    let attributes = descriptor.attributes();
    // SAFETY: validated same-directory path and live security attributes. A zero
    // share mode makes this an exclusive writer lease released on process crash.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_READ_ATTRIBUTES.0 | READ_CONTROL.0 | GENERIC_READ.0 | GENERIC_WRITE.0,
            windows::Win32::Storage::FileSystem::FILE_SHARE_MODE(0),
            Some(ptr::from_ref(&attributes)),
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map_err(|_| StoreError::DurabilityFailure)?;
    // SAFETY: transfer exactly one successful owned handle to File.
    let file = unsafe { std::fs::File::from_raw_handle(handle.0 as RawHandle) };
    verify_persistent_file(&file, descriptor)?;
    Ok(file)
}

fn remove_stale_temp(path: &Path, descriptor: &SecurityDescriptor) -> Result<(), StoreError> {
    let Some(file) = open_stale_temp(path)? else {
        return Ok(());
    };
    verify_persistent_file(&file, descriptor)?;
    mark_file_for_deletion(&file)
}

fn open_stale_temp(path: &Path) -> Result<Option<std::fs::File>, StoreError> {
    let wide = wide_path(path);
    // SAFETY: exact fixed temp path is NUL terminated. OPEN_REPARSE_POINT prevents
    // following an attacker-created reparse object while obtaining delete access.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            DELETE.0 | FILE_READ_ATTRIBUTES.0 | READ_CONTROL.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    };
    let handle = match handle {
        Ok(handle) => handle,
        Err(error)
            if error.code() == ERROR_FILE_NOT_FOUND.to_hresult()
                || error.code() == ERROR_PATH_NOT_FOUND.to_hresult() =>
        {
            return Ok(None);
        }
        Err(_) => return Err(StoreError::DurabilityFailure),
    };
    // SAFETY: transfer exactly one successful owned handle to File.
    let file = unsafe { std::fs::File::from_raw_handle(handle.0 as RawHandle) };
    Ok(Some(file))
}

fn mark_file_for_deletion(file: &std::fs::File) -> Result<(), StoreError> {
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: the live handle has DELETE access and the input buffer has the
    // exact FILE_DISPOSITION_INFO representation and length.
    unsafe {
        SetFileInformationByHandle(
            HANDLE(file.as_raw_handle()),
            FileDispositionInfo,
            ptr::from_ref(&disposition).cast::<c_void>(),
            u32::try_from(size_of::<FILE_DISPOSITION_INFO>()).unwrap_or(u32::MAX),
        )
    }
    .map_err(|_| StoreError::DurabilityFailure)?;
    Ok(())
}

fn create_new_write_through(
    path: &Path,
    descriptor: &SecurityDescriptor,
) -> Result<std::fs::File, StoreError> {
    let wide = wide_path(path);
    let attributes = descriptor.attributes();
    // SAFETY: the NUL-terminated path and security attributes remain valid for
    // the call. CREATE_NEW prevents following or overwriting an attacker entry.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_WRITE_DATA.0 | FILE_READ_ATTRIBUTES.0 | READ_CONTROL.0,
            FILE_SHARE_READ,
            Some(ptr::from_ref(&attributes)),
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map_err(|_| StoreError::DurabilityFailure)?;
    // SAFETY: transfer exactly one successful owned handle to File.
    let file = unsafe { std::fs::File::from_raw_handle(handle.0 as RawHandle) };
    verify_persistent_file(&file, descriptor)?;
    Ok(file)
}

fn atomic_replace(temp: &Path, target: &Path) -> Result<(), StoreError> {
    let temp_wide = wide_path(temp);
    let target_wide = wide_path(target);
    // Both paths are validated children of the same held local directory.
    // MOVEFILE_REPLACE_EXISTING handles both the first commit and replacement;
    // MOVEFILE_WRITE_THROUGH is the documented durability flag. ReplaceFileW's
    // similarly named REPLACEFILE_WRITE_THROUGH flag is explicitly unsupported.
    // SAFETY: both validated same-directory paths remain live for the call.
    unsafe {
        MoveFileExW(
            PCWSTR(temp_wide.as_ptr()),
            PCWSTR(target_wide.as_ptr()),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    }
    .map_err(|_| StoreError::DurabilityFailure)
}

fn flush_file(file: &std::fs::File) -> Result<(), StoreError> {
    // SAFETY: the handle belongs to the live file and has write access.
    unsafe { FlushFileBuffers(HANDLE(file.as_raw_handle())) }
        .map_err(|_| StoreError::DurabilityFailure)
}

fn flush_directory(directory: &std::fs::File) -> Result<(), StoreError> {
    // Windows documents FlushFileBuffers primarily for file/volume handles. NTFS
    // accepts a directory handle opened with backup semantics; if a filesystem
    // rejects this proof, the store fails closed rather than claiming durability.
    // SAFETY: the handle belongs to the held directory.
    unsafe { FlushFileBuffers(HANDLE(directory.as_raw_handle())) }
        .map_err(|_| StoreError::DurabilityFailure)
}

fn verify_not_reparse(file: &std::fs::File) -> Result<(), StoreError> {
    let attributes = file
        .metadata()
        .map_err(|_| StoreError::UnsafePath)?
        .file_attributes();
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        return Err(StoreError::UnsafePath);
    }
    Ok(())
}

fn verify_persistent_file(
    file: &std::fs::File,
    descriptor: &SecurityDescriptor,
) -> Result<(), StoreError> {
    verify_not_reparse(file)?;
    let information = file_information(file)?;
    if information.nNumberOfLinks != 1 {
        return Err(StoreError::UnsafePath);
    }
    descriptor.verify_file_security(file)
}

fn verify_installed_readback(
    file: &std::fs::File,
    expected_identity: FileIdentity,
    expected_volume_serial: u64,
    expected_bytes: &[u8],
    expected_digest: [u8; 32],
    descriptor: &SecurityDescriptor,
) -> Result<(), StoreError> {
    verify_persistent_file(file, descriptor)?;
    let actual_identity = file_identity(file)?;
    if actual_identity != expected_identity
        || actual_identity.volume_serial != expected_volume_serial
    {
        return Err(StoreError::UnsafePath);
    }
    let length = usize::try_from(
        file.metadata()
            .map_err(|_| StoreError::DurabilityFailure)?
            .len(),
    )
    .map_err(|_| StoreError::BoundsExceeded)?;
    if length != expected_bytes.len() {
        return Err(StoreError::DurabilityFailure);
    }
    let read_bound = expected_bytes
        .len()
        .checked_add(1)
        .ok_or(StoreError::BoundsExceeded)?;
    let mut actual = Vec::with_capacity(expected_bytes.len());
    file.take(u64::try_from(read_bound).map_err(|_| StoreError::BoundsExceeded)?)
        .read_to_end(&mut actual)
        .map_err(|_| StoreError::DurabilityFailure)?;
    if actual.len() != expected_bytes.len()
        || sha256(&actual) != expected_digest
        || actual.as_slice() != expected_bytes
    {
        return Err(StoreError::DurabilityFailure);
    }
    Ok(())
}

fn file_identity(file: &std::fs::File) -> Result<FileIdentity, StoreError> {
    let mut information = FILE_ID_INFO::default();
    // SAFETY: the held handle remains live and the output buffer has the exact
    // FILE_ID_INFO layout requested by FileIdInfo.
    unsafe {
        GetFileInformationByHandleEx(
            HANDLE(file.as_raw_handle()),
            FileIdInfo,
            (&raw mut information).cast::<c_void>(),
            u32::try_from(size_of::<FILE_ID_INFO>()).unwrap_or(u32::MAX),
        )
        .map_err(|_| StoreError::UnsafePath)?;
    }
    let file_id = information.FileId.Identifier;
    if information.VolumeSerialNumber == 0 || file_id == [0_u8; 16] || file_id == [u8::MAX; 16] {
        return Err(StoreError::UnsafePath);
    }
    Ok(FileIdentity {
        volume_serial: information.VolumeSerialNumber,
        file_id,
    })
}

fn file_information(file: &std::fs::File) -> Result<BY_HANDLE_FILE_INFORMATION, StoreError> {
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the file handle remains live; output has the exact API type.
    unsafe {
        GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &raw mut information)
            .map_err(|_| StoreError::UnsafePath)?;
    }
    Ok(information)
}

fn verify_stable_user_security(
    file: &std::fs::File,
    expected_sid: &StableUserSid,
) -> Result<(), StoreError> {
    let mut owner = PSID::default();
    let mut dacl = ptr::null_mut::<ACL>();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: output pointers are valid; GetSecurityInfo allocates descriptor
    // memory that is released below.
    let status = unsafe {
        GetSecurityInfo(
            HANDLE(file.as_raw_handle()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&raw mut owner),
            None,
            Some(&raw mut dacl),
            None,
            Some(&raw mut descriptor),
        )
    };
    if status != ERROR_SUCCESS || descriptor.0.is_null() || owner.0.is_null() || dacl.is_null() {
        return Err(StoreError::InsecurePermissions);
    }
    let result = inspect_security_descriptor(descriptor, owner, dacl, expected_sid);
    // SAFETY: GetSecurityInfo allocated this descriptor with LocalAlloc.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(descriptor.0)));
    }
    result
}

fn verify_key_agent_file_security(
    file: &std::fs::File,
    stable_user_sid: &StableUserSid,
    profile_sid: &StableUserSid,
) -> Result<(), StoreError> {
    let mut owner = PSID::default();
    let mut dacl = ptr::null_mut::<ACL>();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // LABEL_SECURITY_INFORMATION retrieves the mandatory label using the
    // handle's READ_CONTROL access. The returned descriptor owns all pointers.
    // SAFETY: all outputs are initialized writable storage and the file handle
    // remains live through the complete query and inspection.
    let status = unsafe {
        GetSecurityInfo(
            HANDLE(file.as_raw_handle()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
            Some(&raw mut owner),
            None,
            Some(&raw mut dacl),
            None,
            Some(&raw mut descriptor),
        )
    };
    if status != ERROR_SUCCESS || descriptor.0.is_null() || owner.0.is_null() || dacl.is_null() {
        if !descriptor.0.is_null() {
            // SAFETY: a non-null GetSecurityInfo descriptor uses LocalAlloc.
            unsafe {
                let _ = LocalFree(Some(HLOCAL(descriptor.0)));
            }
        }
        return Err(StoreError::InsecurePermissions);
    }

    let mut sacl_present = BOOL(0);
    let mut sacl_defaulted = BOOL(0);
    let mut sacl = ptr::null_mut::<ACL>();
    // SAFETY: the successful query returned one live self-relative descriptor;
    // these outputs only expose its mandatory-label SACL.
    let sacl_result = unsafe {
        GetSecurityDescriptorSacl(
            descriptor,
            &raw mut sacl_present,
            &raw mut sacl,
            &raw mut sacl_defaulted,
        )
    };
    if sacl_result.is_err() || !sacl_present.as_bool() || sacl_defaulted.as_bool() || sacl.is_null()
    {
        // SAFETY: GetSecurityInfo allocated this descriptor with LocalAlloc.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(descriptor.0)));
        }
        return Err(StoreError::InsecurePermissions);
    }

    let result = inspect_key_agent_file_security_descriptor(
        descriptor,
        owner,
        dacl,
        sacl,
        stable_user_sid,
        profile_sid,
    );
    // SAFETY: GetSecurityInfo allocated this descriptor with LocalAlloc.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(descriptor.0)));
    }
    result
}

fn inspect_key_agent_file_security_descriptor(
    descriptor: PSECURITY_DESCRIPTOR,
    owner: PSID,
    dacl: *mut ACL,
    sacl: *mut ACL,
    stable_user_sid: &StableUserSid,
    profile_sid: &StableUserSid,
) -> Result<(), StoreError> {
    if descriptor.0.is_null() || dacl.is_null() || sacl.is_null() {
        return Err(StoreError::InsecurePermissions);
    }
    let control = inspect_descriptor_control(descriptor)?;
    let required = security_control_flag(SE_SELF_RELATIVE)
        | security_control_flag(SE_DACL_PRESENT)
        | security_control_flag(SE_DACL_PROTECTED)
        | security_control_flag(SE_SACL_PRESENT);
    let allowed = required | security_control_flag(SE_SACL_AUTO_INHERITED);
    if control & required != required || control & !allowed != 0 {
        return Err(StoreError::InsecurePermissions);
    }
    inspect_owner(owner, stable_user_sid)?;
    inspect_exact_key_agent_dacl(dacl, stable_user_sid, profile_sid)?;
    inspect_exact_inherited_low_label(sacl)
}

fn inspect_descriptor_control(descriptor: PSECURITY_DESCRIPTOR) -> Result<u16, StoreError> {
    // SAFETY: the descriptor is caller-owned and remains live for inspection.
    if descriptor.0.is_null() || !unsafe { IsValidSecurityDescriptor(descriptor) }.as_bool() {
        return Err(StoreError::InsecurePermissions);
    }
    let mut control = 0_u16;
    let mut revision = 0_u32;
    // SAFETY: outputs are exact initialized scalar storage.
    unsafe {
        GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision)
            .map_err(|_| StoreError::InsecurePermissions)?;
    }
    Ok(control)
}

fn security_control_flag(flag: windows::Win32::Security::SECURITY_DESCRIPTOR_CONTROL) -> u16 {
    u16::from_ne_bytes(flag.0.to_ne_bytes())
}

fn inspect_owner(owner: PSID, expected_sid: &StableUserSid) -> Result<(), StoreError> {
    // SAFETY: a non-null owner pointer inside the live descriptor can be
    // validated before any size-dependent access.
    if owner.0.is_null() || !unsafe { IsValidSid(owner) }.as_bool() {
        return Err(StoreError::InsecurePermissions);
    }
    // SAFETY: both SIDs are valid and live for this comparison.
    unsafe { EqualSid(owner, expected_sid.as_psid()) }
        .map_err(|_| StoreError::WrongStoragePrincipal)
}

fn inspect_security_descriptor(
    descriptor: PSECURITY_DESCRIPTOR,
    owner: PSID,
    dacl: *mut ACL,
    expected_sid: &StableUserSid,
) -> Result<(), StoreError> {
    let control = inspect_descriptor_control(descriptor)?;
    let protected = security_control_flag(SE_DACL_PROTECTED);
    let present = security_control_flag(SE_DACL_PRESENT);
    let self_relative = security_control_flag(SE_SELF_RELATIVE);
    let dacl_defaulted = security_control_flag(SE_DACL_DEFAULTED);
    let owner_defaulted = security_control_flag(SE_OWNER_DEFAULTED);
    if control & protected == 0 {
        return Err(StoreError::UnprotectedDacl);
    }
    if control & (present | self_relative) != (present | self_relative) {
        return Err(StoreError::InsecurePermissions);
    }
    let forbidden_control = dacl_defaulted
        | owner_defaulted
        | security_control_flag(SE_DACL_AUTO_INHERITED)
        | security_control_flag(SE_DACL_AUTO_INHERIT_REQ);
    if control & forbidden_control != 0 {
        return Err(StoreError::InsecurePermissions);
    }

    inspect_owner(owner, expected_sid)?;
    inspect_exact_dacl(dacl, expected_sid)
}

fn inspect_exact_dacl(dacl: *mut ACL, expected_sid: &StableUserSid) -> Result<(), StoreError> {
    let (acl_size, information) = inspect_acl_header(dacl, 1)?;
    let ace = ace_at(dacl, 0)?;
    let allow_bytes = inspect_allow_ace(ace, expected_sid, FILE_ALL_ACCESS.0)?;
    let exact_bytes = size_of::<ACL>()
        .checked_add(allow_bytes)
        .ok_or(StoreError::UnexpectedAccessControlEntry)?;
    require_exact_acl_size(acl_size, &information, exact_bytes)
}

fn inspect_exact_key_agent_dacl(
    dacl: *mut ACL,
    stable_user_sid: &StableUserSid,
    profile_sid: &StableUserSid,
) -> Result<(), StoreError> {
    let (acl_size, information) = inspect_acl_header(dacl, 2)?;
    let user_ace = ace_at(dacl, 0)?;
    let profile_ace = ace_at(dacl, 1)?;
    let user_size = inspect_allow_ace(user_ace, stable_user_sid, FILE_ALL_ACCESS.0)?;
    let profile_size = inspect_allow_ace(profile_ace, profile_sid, KEY_AGENT_FILE_ACCESS)?;
    let exact_bytes = size_of::<ACL>()
        .checked_add(user_size)
        .and_then(|bytes| bytes.checked_add(profile_size))
        .ok_or(StoreError::UnexpectedAccessControlEntry)?;
    require_exact_acl_size(acl_size, &information, exact_bytes)
}

fn inspect_exact_inherited_low_label(sacl: *mut ACL) -> Result<(), StoreError> {
    let (acl_size, information) = inspect_acl_header(sacl, 1)?;
    let ace = ace_at(sacl, 0)?;
    // SAFETY: IsValidAcl and GetAce prove that the common ACE header is present.
    let header = unsafe { &*ace.cast::<ACE_HEADER>() };
    let label_type = u8::try_from(SYSTEM_MANDATORY_LABEL_ACE_TYPE).unwrap_or(u8::MAX);
    let sid_offset = core::mem::offset_of!(SYSTEM_MANDATORY_LABEL_ACE, SidStart);
    if header.AceType != label_type
        || header.AceFlags != INHERITED_FILE_LABEL_ACE_FLAGS
        || usize::from(header.AceSize) < sid_offset.saturating_add(MIN_BINARY_SID_BYTES)
    {
        return Err(StoreError::UnexpectedAccessControlEntry);
    }
    // SAFETY: the accepted type and size prove the mandatory-label fixed fields.
    let label = unsafe { &*ace.cast::<SYSTEM_MANDATORY_LABEL_ACE>() };
    if label.Mask != SYSTEM_MANDATORY_LABEL_NO_WRITE_UP {
        return Err(StoreError::UnexpectedAccessControlEntry);
    }
    let sid_bytes = ptr::addr_of!(label.SidStart).cast::<u8>();
    let available = usize::from(header.AceSize).saturating_sub(sid_offset);
    let sid_length = validate_sid_in_ace(sid_bytes, available)?;
    if sid_length != LOW_MANDATORY_LABEL_SID.len() {
        return Err(StoreError::WrongStoragePrincipal);
    }
    // SAFETY: validation proved that this complete range belongs to the ACE.
    let actual_sid = unsafe { core::slice::from_raw_parts(sid_bytes, sid_length) };
    if actual_sid != LOW_MANDATORY_LABEL_SID {
        return Err(StoreError::WrongStoragePrincipal);
    }
    let exact_bytes = size_of::<ACL>()
        .checked_add(usize::from(header.AceSize))
        .ok_or(StoreError::UnexpectedAccessControlEntry)?;
    require_exact_acl_size(acl_size, &information, exact_bytes)
}

fn inspect_acl_header(
    acl: *mut ACL,
    expected_ace_count: u32,
) -> Result<(u16, ACL_SIZE_INFORMATION), StoreError> {
    // IsValidSecurityDescriptor deliberately does not validate individual
    // ACL/ACE contents. Prove the complete ACL before retrieving any ACE.
    // SAFETY: a non-null ACL pointer lies inside the caller-owned descriptor.
    if acl.is_null() || !unsafe { IsValidAcl(acl) }.as_bool() {
        return Err(StoreError::InsecurePermissions);
    }
    // SAFETY: IsValidAcl accepted the complete fixed header.
    let acl_ref = unsafe { &*acl };
    if u32::from(acl_ref.AclRevision) != ACL_REVISION.0 || acl_ref.Sbz1 != 0 || acl_ref.Sbz2 != 0 {
        return Err(StoreError::UnexpectedAccessControlEntry);
    }
    let mut information = ACL_SIZE_INFORMATION::default();
    // SAFETY: the validated ACL remains live and output has the exact API type.
    unsafe {
        GetAclInformation(
            acl,
            (&raw mut information).cast::<c_void>(),
            u32::try_from(size_of::<ACL_SIZE_INFORMATION>()).unwrap_or(u32::MAX),
            AclSizeInformation,
        )
        .map_err(|_| StoreError::InsecurePermissions)?;
    }
    if information.AceCount != expected_ace_count {
        return Err(StoreError::UnexpectedAccessControlEntry);
    }
    Ok((acl_ref.AclSize, information))
}

fn ace_at(acl: *mut ACL, index: u32) -> Result<*mut c_void, StoreError> {
    let mut ace = ptr::null_mut::<c_void>();
    // SAFETY: inspect_acl_header checked the exact count before fixed indices.
    unsafe {
        GetAce(acl, index, &raw mut ace).map_err(|_| StoreError::InsecurePermissions)?;
    }
    if ace.is_null() {
        return Err(StoreError::UnexpectedAccessControlEntry);
    }
    Ok(ace)
}

fn inspect_allow_ace_with_mask(
    ace: *mut c_void,
    expected_sid: &StableUserSid,
    expected_mask: u32,
) -> Result<usize, StoreError> {
    // SAFETY: IsValidAcl and GetAce proved that the common fixed header is
    // contained in the ACL. Do not cast to a specific ACE layout until its type
    // and complete minimum size have been accepted.
    let header = unsafe { &*ace.cast::<ACE_HEADER>() };
    let (ace_type, ace_flags, ace_size) = (header.AceType, header.AceFlags, header.AceSize);
    let allowed_type = u8::try_from(ACCESS_ALLOWED_ACE_TYPE).unwrap_or(u8::MAX);
    let sid_offset = core::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
    if ace_type != allowed_type
        || ace_flags != 0
        || usize::from(ace_size) < sid_offset.saturating_add(MIN_BINARY_SID_BYTES)
    {
        return Err(StoreError::UnexpectedAccessControlEntry);
    }
    // SAFETY: the accepted type and minimum size now prove that the standard
    // access-allowed ACE fixed fields are present.
    let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
    if allowed.Mask != expected_mask {
        return Err(StoreError::UnexpectedAccessControlEntry);
    }
    // SAFETY: SidStart is the documented first byte of the variable SID within
    // ACCESS_ALLOWED_ACE; the ACE-size lower bound was verified above.
    let actual_sid_bytes = ptr::addr_of!(allowed.SidStart).cast::<u8>();
    let actual_sid = PSID(actual_sid_bytes.cast_mut().cast::<c_void>());
    let sid_bytes_available = usize::from(ace_size).saturating_sub(sid_offset);
    validate_sid_in_ace(actual_sid_bytes, sid_bytes_available)?;
    // SAFETY: both SIDs are valid and live for the comparison.
    unsafe { EqualSid(actual_sid, expected_sid.as_psid()) }
        .map_err(|_| StoreError::WrongStoragePrincipal)?;
    Ok(usize::from(ace_size))
}

fn inspect_allow_ace(
    ace: *mut c_void,
    expected_sid: &StableUserSid,
    expected_mask: u32,
) -> Result<usize, StoreError> {
    inspect_allow_ace_with_mask(ace, expected_sid, expected_mask)
}

fn validate_sid_in_ace(sid_bytes: *const u8, available: usize) -> Result<usize, StoreError> {
    if sid_bytes.is_null() || available < MIN_BINARY_SID_BYTES {
        return Err(StoreError::UnexpectedAccessControlEntry);
    }
    // SAFETY: available contains the complete fixed SID header and count byte.
    let sub_authority_count = usize::from(unsafe { *sid_bytes.add(1) });
    let declared = sub_authority_count
        .checked_mul(size_of::<u32>())
        .and_then(|bytes| bytes.checked_add(MIN_BINARY_SID_BYTES))
        .ok_or(StoreError::UnexpectedAccessControlEntry)?;
    if declared != available || declared > MAX_BINARY_SID_BYTES {
        return Err(StoreError::UnexpectedAccessControlEntry);
    }
    let sid = PSID(sid_bytes.cast_mut().cast::<c_void>());
    // SAFETY: the self-declared SID length fits exactly inside the ACE.
    if !unsafe { IsValidSid(sid) }.as_bool() {
        return Err(StoreError::UnexpectedAccessControlEntry);
    }
    // SAFETY: IsValidSid accepted the SID wholly contained by the ACE.
    let reported = usize::try_from(unsafe { GetLengthSid(sid) })
        .map_err(|_| StoreError::UnexpectedAccessControlEntry)?;
    if reported != declared {
        return Err(StoreError::UnexpectedAccessControlEntry);
    }
    Ok(declared)
}

fn require_exact_acl_size(
    acl_size: u16,
    information: &ACL_SIZE_INFORMATION,
    exact_bytes: usize,
) -> Result<(), StoreError> {
    if usize::try_from(information.AclBytesInUse)
        .map_err(|_| StoreError::UnexpectedAccessControlEntry)?
        != exact_bytes
        || information.AclBytesFree != 0
        || usize::from(acl_size) != exact_bytes
    {
        return Err(StoreError::UnexpectedAccessControlEntry);
    }
    Ok(())
}

fn current_stable_user_sid() -> Result<StableUserSid, StoreError> {
    let mut token = HANDLE::default();
    // SAFETY: query-only token handle output is valid.
    unsafe {
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token)
            .map_err(|_| StoreError::DurabilityFailure)?;
    }
    let token = OwnedHandle(token);
    let mut needed = 0_u32;
    // SAFETY: the first call intentionally queries the required TokenUser size.
    let _ = unsafe { GetTokenInformation(token.0, TokenUser, None, 0, &raw mut needed) };
    if needed < u32::try_from(size_of::<TOKEN_USER>()).unwrap_or(u32::MAX) {
        return Err(StoreError::DurabilityFailure);
    }
    let word_size = size_of::<usize>();
    let word_count = usize::try_from(needed)
        .map_err(|_| StoreError::DurabilityFailure)?
        .checked_add(word_size - 1)
        .and_then(|rounded| rounded.checked_div(word_size))
        .ok_or(StoreError::DurabilityFailure)?;
    let mut buffer = vec![0_usize; word_count];
    // SAFETY: the aligned output buffer is writable for exactly `needed` bytes.
    unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            Some(buffer.as_mut_ptr().cast::<c_void>()),
            needed,
            &raw mut needed,
        )
        .map_err(|_| StoreError::DurabilityFailure)?;
    }
    let token_user = buffer.as_ptr().cast::<TOKEN_USER>();
    // SAFETY: Windows initialized the complete TOKEN_USER record in the buffer.
    let sid = unsafe { (*token_user).User.Sid };
    copy_sid(sid).map(StableUserSid)
}

#[cfg(test)]
fn current_logon_sid() -> Result<Vec<u8>, StoreError> {
    let mut token = HANDLE::default();
    // SAFETY: query-only token handle output is valid.
    unsafe {
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token)
            .map_err(|_| StoreError::DurabilityFailure)?;
    }
    let token = OwnedHandle(token);
    let mut needed = 0_u32;
    // SAFETY: first call intentionally queries required size.
    let _ = unsafe { GetTokenInformation(token.0, TokenGroups, None, 0, &raw mut needed) };
    if needed < u32::try_from(size_of::<TOKEN_GROUPS>()).unwrap_or(u32::MAX) {
        return Err(StoreError::DurabilityFailure);
    }
    let word_size = size_of::<usize>();
    let word_count = usize::try_from(needed)
        .map_err(|_| StoreError::DurabilityFailure)?
        .checked_add(word_size - 1)
        .and_then(|rounded| rounded.checked_div(word_size))
        .ok_or(StoreError::DurabilityFailure)?;
    let mut buffer = vec![0_usize; word_count];
    // SAFETY: aligned output buffer is writable for `needed` bytes.
    unsafe {
        GetTokenInformation(
            token.0,
            TokenGroups,
            Some(buffer.as_mut_ptr().cast::<c_void>()),
            needed,
            &raw mut needed,
        )
        .map_err(|_| StoreError::DurabilityFailure)?;
    }
    let groups_ptr = buffer.as_ptr().cast::<TOKEN_GROUPS>();
    // SAFETY: Windows initialized the TOKEN_GROUPS header.
    let count = usize::try_from(unsafe { (*groups_ptr).GroupCount })
        .map_err(|_| StoreError::DurabilityFailure)?;
    let required = count
        .checked_mul(size_of::<SID_AND_ATTRIBUTES>())
        .and_then(|bytes| bytes.checked_add(core::mem::offset_of!(TOKEN_GROUPS, Groups)))
        .ok_or(StoreError::DurabilityFailure)?;
    if required > usize::try_from(needed).map_err(|_| StoreError::DurabilityFailure)? {
        return Err(StoreError::DurabilityFailure);
    }
    // SAFETY: count was bounded by the initialized output size.
    let groups = unsafe {
        core::slice::from_raw_parts(
            ptr::addr_of!((*groups_ptr).Groups).cast::<SID_AND_ATTRIBUTES>(),
            count,
        )
    };
    let logon_flag = u32::from_ne_bytes(SE_GROUP_LOGON_ID.to_ne_bytes());
    let sid = groups
        .iter()
        .find(|group| group.Attributes & logon_flag == logon_flag)
        .ok_or(StoreError::DurabilityFailure)?
        .Sid;
    copy_sid(sid)
}

fn copy_sid(sid: PSID) -> Result<Vec<u8>, StoreError> {
    // SAFETY: callers supply a non-owning SID pointer from a live token buffer.
    // Validation occurs before reading its declared length.
    if sid.0.is_null() || !unsafe { IsValidSid(sid) }.as_bool() {
        return Err(StoreError::DurabilityFailure);
    }
    // SAFETY: SID pointer remains owned by its token-info buffer for this call.
    let length =
        usize::try_from(unsafe { GetLengthSid(sid) }).map_err(|_| StoreError::DurabilityFailure)?;
    if length == 0 || length > 256 {
        return Err(StoreError::DurabilityFailure);
    }
    let mut copy = vec![0_u8; length];
    // SAFETY: Windows reported `length` bytes for this SID and destination owns
    // exactly that writable allocation.
    unsafe {
        ptr::copy_nonoverlapping(sid.0.cast::<u8>(), copy.as_mut_ptr(), length);
    }
    Ok(copy)
}

fn sid_to_string(sid: PSID) -> Result<String, StoreError> {
    let mut text = PWSTR::null();
    // SAFETY: the SID copy is valid; output is released with LocalFree.
    unsafe {
        ConvertSidToStringSidW(sid, &raw mut text).map_err(|_| StoreError::DurabilityFailure)?;
    }
    // SAFETY: success guarantees a NUL-terminated allocation.
    let result = unsafe { text.to_string() }.map_err(|_| StoreError::DurabilityFailure);
    // SAFETY: conversion allocated with LocalAlloc.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(text.0.cast::<c_void>())));
    }
    result
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: handle is owned exactly once by this wrapper.
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

fn is_not_found(error: &std::io::Error) -> bool {
    matches!(
        error.raw_os_error().map(|code| u32::from_ne_bytes(code.to_ne_bytes())),
        Some(code) if code == ERROR_FILE_NOT_FOUND.0 || code == ERROR_PATH_NOT_FOUND.0
    )
}

fn wide_path(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;

    path.as_os_str()
        .encode_wide()
        .chain(core::iter::once(0))
        .collect()
}

fn wide_nul(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(core::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exact_allow_ace(sid: &str) -> String {
        format!("(A;;0x{:08x};;;{sid})", FILE_ALL_ACCESS.0)
    }

    fn key_agent_test_principals() -> Result<(StableUserSid, StableUserSid), StoreError> {
        let stable_user = current_stable_user_sid()?;
        let profile = StableUserSid(current_logon_sid()?);
        if stable_user == profile {
            return Err(StoreError::WrongStoragePrincipal);
        }
        Ok((stable_user, profile))
    }

    fn key_agent_file_sddl(
        user: &str,
        profile: &str,
        profile_mask: u32,
        dacl_protection: &str,
        label_ace: &str,
    ) -> String {
        format!(
            "O:{user}D:{dacl_protection}(A;;0x{:08x};;;{user})(A;;0x{profile_mask:08x};;;{profile}){label_ace}",
            FILE_ALL_ACCESS.0,
        )
    }

    fn descriptor_with_key_agent_policy(
        stable_user: StableUserSid,
        profile: StableUserSid,
        sddl: &str,
    ) -> Result<SecurityDescriptor, StoreError> {
        SecurityDescriptor::from_sddl_with_profile(stable_user, profile, sddl)
    }

    #[test]
    fn key_agent_file_access_and_fixed_store_contracts_are_exact() {
        assert_eq!(FILE_ALL_ACCESS.0, 0x001f_01ff);
        assert_eq!(KEY_AGENT_FILE_ACCESS, 0x0013_019f);
        assert_eq!(
            KEY_AGENT_FILE_ACCESS,
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0 | DELETE.0
        );
        for forbidden in [
            WRITE_DAC.0,
            WRITE_OWNER.0,
            FILE_EXECUTE.0,
            ACCESS_SYSTEM_SECURITY,
        ] {
            assert_eq!(KEY_AGENT_FILE_ACCESS & forbidden, 0);
        }
        assert_eq!(
            u32::from(INHERITED_FILE_LABEL_ACE_FLAGS),
            windows::Win32::Security::INHERITED_ACE.0,
        );

        assert_eq!(
            fixed_key_agent_store_spec(FixedKeyAgentGenerationStoreRole::Vault),
            ("vault", RecordClass::Vault, 4_194_416),
        );
        assert_eq!(
            fixed_key_agent_store_spec(FixedKeyAgentGenerationStoreRole::NonceLedger),
            ("nonce-ledger", RecordClass::NonceLedger, 16_777_216),
        );
        assert_eq!(
            fixed_key_agent_store_spec(FixedKeyAgentGenerationStoreRole::SignedCandidateJournal),
            (
                "signed-candidate-journal",
                RecordClass::SignedCandidateJournal,
                16_777_216,
            ),
        );
        assert_eq!(
            fixed_key_agent_store_spec(FixedKeyAgentGenerationStoreRole::LocalSettings),
            ("local-settings", RecordClass::LocalSettings, 226),
        );
        assert_eq!(
            4_194_416,
            super::super::VAULT_HEADER_BYTES + 4 * 1024 * 1024,
        );
        assert_eq!(226, 210 + super::super::XCHACHA_TAG_BYTES);
    }

    #[test]
    fn key_agent_creation_and_inherited_file_descriptors_are_exact() -> Result<(), StoreError> {
        let (stable_user, profile) = key_agent_test_principals()?;
        assert_eq!(
            SecurityDescriptor::for_key_agent_files(stable_user.as_psid(), stable_user.as_psid(),)
                .err(),
            Some(StoreError::WrongStoragePrincipal),
        );
        let creation =
            SecurityDescriptor::for_key_agent_files(stable_user.as_psid(), profile.as_psid())?;
        creation.inspect_key_agent_creation_for_test()?;
        assert_eq!(
            creation.inspect_for_test(&stable_user),
            Err(StoreError::UnexpectedAccessControlEntry),
        );

        let user_text = sid_to_string(stable_user.as_psid())?;
        let profile_text = sid_to_string(profile.as_psid())?;
        let sddl = key_agent_file_sddl(
            &user_text,
            &profile_text,
            KEY_AGENT_FILE_ACCESS,
            "P",
            "S:(ML;ID;NW;;;LW)",
        );
        let file = descriptor_with_key_agent_policy(stable_user.clone(), profile, &sddl)?;
        file.inspect_key_agent_file_for_test()?;
        assert_eq!(
            file.inspect_for_test(&stable_user),
            Err(StoreError::UnexpectedAccessControlEntry),
        );
        Ok(())
    }

    #[test]
    fn key_agent_file_descriptor_rejects_dacl_policy_drift() -> Result<(), StoreError> {
        let (stable_user, profile) = key_agent_test_principals()?;
        let user_text = sid_to_string(stable_user.as_psid())?;
        let profile_text = sid_to_string(profile.as_psid())?;
        let exact_label = "S:(ML;ID;NW;;;LW)";
        let cases = [
            key_agent_file_sddl(
                &user_text,
                &profile_text,
                KEY_AGENT_FILE_ACCESS ^ FILE_READ_ATTRIBUTES.0,
                "P",
                exact_label,
            ),
            key_agent_file_sddl(
                &user_text,
                &profile_text,
                KEY_AGENT_FILE_ACCESS | WRITE_DAC.0,
                "P",
                exact_label,
            ),
            key_agent_file_sddl(
                &user_text,
                &profile_text,
                KEY_AGENT_FILE_ACCESS,
                "",
                exact_label,
            ),
            format!(
                "O:{user_text}D:P(A;;0x{KEY_AGENT_FILE_ACCESS:08x};;;{profile_text})(A;;0x{:08x};;;{user_text}){exact_label}",
                FILE_ALL_ACCESS.0,
            ),
            format!(
                "O:{user_text}D:P(A;;0x{:08x};;;{user_text})(A;ID;0x{KEY_AGENT_FILE_ACCESS:08x};;;{profile_text}){exact_label}",
                FILE_ALL_ACCESS.0,
            ),
            format!(
                "O:{user_text}D:P(A;;0x{:08x};;;{user_text})(A;;0x{KEY_AGENT_FILE_ACCESS:08x};;;{profile_text})(A;;FR;;;WD){exact_label}",
                FILE_ALL_ACCESS.0,
            ),
            format!(
                "O:SYD:P(A;;0x{:08x};;;{user_text})(A;;0x{KEY_AGENT_FILE_ACCESS:08x};;;{profile_text}){exact_label}",
                FILE_ALL_ACCESS.0,
            ),
            format!(
                "O:{user_text}D:P(A;;0x{:08x};;;{user_text})(A;;0x{KEY_AGENT_FILE_ACCESS:08x};;;WD){exact_label}",
                FILE_ALL_ACCESS.0,
            ),
            format!(
                "O:{user_text}D:P(A;;0x{:08x};;;{user_text})(D;;0x{KEY_AGENT_FILE_ACCESS:08x};;;{profile_text}){exact_label}",
                FILE_ALL_ACCESS.0,
            ),
        ];
        for sddl in cases {
            let descriptor =
                descriptor_with_key_agent_policy(stable_user.clone(), profile.clone(), &sddl)?;
            assert!(descriptor.inspect_key_agent_file_for_test().is_err());
        }
        Ok(())
    }

    #[test]
    fn key_agent_file_descriptor_rejects_label_policy_drift() -> Result<(), StoreError> {
        let (stable_user, profile) = key_agent_test_principals()?;
        let user_text = sid_to_string(stable_user.as_psid())?;
        let profile_text = sid_to_string(profile.as_psid())?;
        for label in [
            "",
            "S:(ML;;NW;;;LW)",
            "S:(ML;OICIID;NW;;;LW)",
            "S:(ML;ID;NW;;;ME)",
            "S:(ML;ID;NR;;;LW)",
            "S:(ML;ID;NW;;;LW)(ML;ID;NW;;;LW)",
        ] {
            let sddl =
                key_agent_file_sddl(&user_text, &profile_text, KEY_AGENT_FILE_ACCESS, "P", label);
            let descriptor =
                descriptor_with_key_agent_policy(stable_user.clone(), profile.clone(), &sddl)?;
            assert!(descriptor.inspect_key_agent_file_for_test().is_err());
        }
        for forbidden_control in [SE_SACL_DEFAULTED, SE_SACL_AUTO_INHERIT_REQ] {
            let sddl = key_agent_file_sddl(
                &user_text,
                &profile_text,
                KEY_AGENT_FILE_ACCESS,
                "P",
                "S:(ML;ID;NW;;;LW)",
            );
            let descriptor =
                descriptor_with_key_agent_policy(stable_user.clone(), profile.clone(), &sddl)?;
            let relative = descriptor
                .descriptor
                .0
                .cast::<SECURITY_DESCRIPTOR_RELATIVE>();
            // SAFETY: the SDDL conversion returned a live self-relative test
            // descriptor; this changes only its initialized control word.
            unsafe {
                (*relative).Control.0 |= u16::from_ne_bytes(forbidden_control.0.to_ne_bytes());
            }
            assert_eq!(
                descriptor.inspect_key_agent_file_for_test(),
                Err(StoreError::InsecurePermissions),
            );
        }
        Ok(())
    }

    #[test]
    fn key_agent_verifier_rejects_stable_single_principal_policy() -> Result<(), StoreError> {
        let (stable_user, profile) = key_agent_test_principals()?;
        let user_text = sid_to_string(stable_user.as_psid())?;
        let sddl = format!(
            "O:{user_text}D:P(A;;0x{:08x};;;{user_text})S:(ML;ID;NW;;;LW)",
            FILE_ALL_ACCESS.0,
        );
        let stable = descriptor_with_key_agent_policy(stable_user, profile, &sddl)?;
        assert_eq!(
            stable.inspect_key_agent_file_for_test(),
            Err(StoreError::UnexpectedAccessControlEntry),
        );
        Ok(())
    }

    #[test]
    fn persistent_descriptor_uses_stable_token_user_not_logon_sid() -> Result<(), StoreError> {
        let stable_user = current_stable_user_sid()?;
        let logon_sid = StableUserSid(current_logon_sid()?);
        assert_ne!(stable_user.as_bytes(), logon_sid.as_bytes());

        let descriptor = SecurityDescriptor::for_stable_user(stable_user.clone())?;
        descriptor.inspect_for_test(&stable_user)?;
        assert_eq!(
            descriptor.inspect_for_test(&logon_sid),
            Err(StoreError::WrongStoragePrincipal)
        );
        Ok(())
    }

    #[test]
    fn persistent_descriptor_survives_simulated_logon_sid_change() -> Result<(), StoreError> {
        let stable_user = current_stable_user_sid()?;
        let first_logon = current_logon_sid()?;
        let mut second_logon = first_logon.clone();
        let final_byte = second_logon
            .last_mut()
            .ok_or(StoreError::DurabilityFailure)?;
        *final_byte ^= 1;
        assert_ne!(first_logon, second_logon);
        assert_ne!(stable_user.as_bytes(), first_logon);
        assert_ne!(stable_user.as_bytes(), second_logon);

        let descriptor = SecurityDescriptor::for_stable_user(stable_user.clone())?;
        for simulated_logon in [&first_logon, &second_logon] {
            assert_ne!(stable_user.as_bytes(), simulated_logon.as_slice());
            descriptor.inspect_for_test(&stable_user)?;
        }
        Ok(())
    }

    #[test]
    fn generated_descriptor_has_exact_owner_and_single_full_control_ace() -> Result<(), StoreError>
    {
        let stable_user = current_stable_user_sid()?;
        let descriptor = SecurityDescriptor::for_stable_user(stable_user.clone())?;
        descriptor.inspect_for_test(&stable_user)
    }

    #[test]
    fn descriptor_rejects_other_owner_or_access_principal() -> Result<(), StoreError> {
        let stable_user = current_stable_user_sid()?;
        let stable_text = sid_to_string(stable_user.as_psid())?;
        let expected_ace = exact_allow_ace(&stable_text);

        let wrong_owner =
            SecurityDescriptor::from_sddl(stable_user.clone(), &format!("O:SYD:P{expected_ace}"))?;
        assert_eq!(
            wrong_owner.inspect_for_test(&stable_user),
            Err(StoreError::WrongStoragePrincipal)
        );

        let wrong_access = SecurityDescriptor::from_sddl(
            stable_user.clone(),
            &format!("O:{stable_text}D:P{}", exact_allow_ace("WD")),
        )?;
        assert_eq!(
            wrong_access.inspect_for_test(&stable_user),
            Err(StoreError::WrongStoragePrincipal)
        );
        Ok(())
    }

    #[test]
    fn descriptor_rejects_any_extra_writable_or_noncanonical_ace() -> Result<(), StoreError> {
        let stable_user = current_stable_user_sid()?;
        let stable_text = sid_to_string(stable_user.as_psid())?;
        let expected_ace = exact_allow_ace(&stable_text);

        let writable_everyone = SecurityDescriptor::from_sddl(
            stable_user.clone(),
            &format!("O:{stable_text}D:P{expected_ace}(A;;GW;;;WD)"),
        )?;
        assert_eq!(
            writable_everyone.inspect_for_test(&stable_user),
            Err(StoreError::UnexpectedAccessControlEntry)
        );

        let deny_ace = SecurityDescriptor::from_sddl(
            stable_user.clone(),
            &format!(
                "O:{stable_text}D:P(D;;0x{:08x};;;{stable_text})",
                FILE_ALL_ACCESS.0
            ),
        )?;
        assert_eq!(
            deny_ace.inspect_for_test(&stable_user),
            Err(StoreError::UnexpectedAccessControlEntry)
        );

        let inherited_ace = SecurityDescriptor::from_sddl(
            stable_user.clone(),
            &format!(
                "O:{stable_text}D:P(A;ID;0x{:08x};;;{stable_text})",
                FILE_ALL_ACCESS.0
            ),
        )?;
        assert_eq!(
            inherited_ace.inspect_for_test(&stable_user),
            Err(StoreError::UnexpectedAccessControlEntry)
        );

        let inheritable_ace = SecurityDescriptor::from_sddl(
            stable_user.clone(),
            &format!(
                "O:{stable_text}D:P(A;CI;0x{:08x};;;{stable_text})",
                FILE_ALL_ACCESS.0
            ),
        )?;
        assert_eq!(
            inheritable_ace.inspect_for_test(&stable_user),
            Err(StoreError::UnexpectedAccessControlEntry)
        );

        let partial_rights = SecurityDescriptor::from_sddl(
            stable_user.clone(),
            &format!("O:{stable_text}D:P(A;;GR;;;{stable_text})"),
        )?;
        assert_eq!(
            partial_rights.inspect_for_test(&stable_user),
            Err(StoreError::UnexpectedAccessControlEntry)
        );

        let empty_dacl =
            SecurityDescriptor::from_sddl(stable_user.clone(), &format!("O:{stable_text}D:P"))?;
        assert_eq!(
            empty_dacl.inspect_for_test(&stable_user),
            Err(StoreError::UnexpectedAccessControlEntry)
        );

        let unprotected = SecurityDescriptor::from_sddl(
            stable_user.clone(),
            &format!("O:{stable_text}D:{expected_ace}"),
        )?;
        assert_eq!(
            unprotected.inspect_for_test(&stable_user),
            Err(StoreError::UnprotectedDacl)
        );
        Ok(())
    }

    #[test]
    fn descriptor_rejects_defaulted_control_bits_and_noncanonical_acl_layouts()
    -> Result<(), StoreError> {
        let stable_user = current_stable_user_sid()?;
        let forbidden_control_flags = [
            u16::from_ne_bytes(SE_DACL_DEFAULTED.0.to_ne_bytes()),
            u16::from_ne_bytes(SE_OWNER_DEFAULTED.0.to_ne_bytes()),
            u16::from_ne_bytes(SE_DACL_AUTO_INHERITED.0.to_ne_bytes()),
            u16::from_ne_bytes(SE_DACL_AUTO_INHERIT_REQ.0.to_ne_bytes()),
        ];
        for flag in forbidden_control_flags {
            let descriptor = SecurityDescriptor::for_stable_user(stable_user.clone())?;
            let (owner, dacl) = descriptor.parts_for_test()?;
            let relative = descriptor
                .descriptor
                .0
                .cast::<SECURITY_DESCRIPTOR_RELATIVE>();
            // SAFETY: SDDL conversion returned a live self-relative descriptor;
            // the test changes only its initialized control word.
            unsafe {
                (*relative).Control.0 |= flag;
            }
            assert_eq!(
                inspect_security_descriptor(descriptor.descriptor, owner, dacl, &stable_user),
                Err(StoreError::InsecurePermissions)
            );
        }

        let noncanonical_revision = SecurityDescriptor::for_stable_user(stable_user.clone())?;
        let (owner, dacl) = noncanonical_revision.parts_for_test()?;
        // SAFETY: `dacl` points into the live descriptor and its ACL header was
        // returned by the descriptor query above.
        unsafe {
            (*dacl).AclRevision = u8::try_from(ACL_REVISION.0.saturating_add(2)).unwrap_or(u8::MAX);
        }
        assert_eq!(
            inspect_security_descriptor(
                noncanonical_revision.descriptor,
                owner,
                dacl,
                &stable_user,
            ),
            Err(StoreError::UnexpectedAccessControlEntry)
        );

        let malformed_acl = SecurityDescriptor::for_stable_user(stable_user.clone())?;
        let (owner, dacl) = malformed_acl.parts_for_test()?;
        // SAFETY: `dacl` points into the live descriptor. Setting an impossible
        // revision makes `IsValidAcl` reject it before any ACE cast is reached.
        unsafe {
            (*dacl).AclRevision = 0;
        }
        assert_eq!(
            inspect_security_descriptor(malformed_acl.descriptor, owner, dacl, &stable_user),
            Err(StoreError::InsecurePermissions)
        );

        let malformed_sid_shape = SecurityDescriptor::for_stable_user(stable_user.clone())?;
        let (owner, dacl) = malformed_sid_shape.parts_for_test()?;
        let mut ace = ptr::null_mut::<c_void>();
        // SAFETY: the generated ACL is valid and contains exactly one ACE.
        unsafe {
            GetAce(dacl, 0, &raw mut ace).map_err(|_| StoreError::InsecurePermissions)?;
        }
        if ace.is_null() {
            return Err(StoreError::InsecurePermissions);
        }
        // SAFETY: the generated descriptor contains the standard access-allowed
        // ACE validated by earlier tests. The count byte is inside its SID.
        unsafe {
            let allowed = &mut *ace.cast::<ACCESS_ALLOWED_ACE>();
            let sid = ptr::addr_of_mut!(allowed.SidStart).cast::<u8>();
            *sid.add(1) = 0;
        }
        assert_eq!(
            inspect_security_descriptor(malformed_sid_shape.descriptor, owner, dacl, &stable_user,),
            Err(StoreError::UnexpectedAccessControlEntry)
        );
        Ok(())
    }

    #[test]
    fn descriptor_rejects_object_and_callback_ace_layouts() -> Result<(), StoreError> {
        let stable_user = current_stable_user_sid()?;
        let stable_text = sid_to_string(stable_user.as_psid())?;
        let object_ace = SecurityDescriptor::from_sddl(
            stable_user.clone(),
            &format!(
                "O:{stable_text}D:P(OA;;0x{:08x};00112233-4455-6677-8899-aabbccddeeff;;{stable_text})",
                FILE_ALL_ACCESS.0
            ),
        )?;
        assert_eq!(
            object_ace.inspect_for_test(&stable_user),
            Err(StoreError::UnexpectedAccessControlEntry)
        );

        let callback = SecurityDescriptor::from_sddl(
            stable_user.clone(),
            &format!(
                "O:{stable_text}D:P(XA;;0x{:08x};;;{stable_text};(@User.Title == \"wallet-test\"))",
                FILE_ALL_ACCESS.0
            ),
        )?;
        assert_eq!(
            callback.inspect_for_test(&stable_user),
            Err(StoreError::UnexpectedAccessControlEntry)
        );
        Ok(())
    }

    #[test]
    fn filesystem_allowlist_is_exact_ntfs_only_and_case_insensitive() {
        fn encoded(name: &str) -> Vec<u16> {
            name.encode_utf16().chain(core::iter::once(0)).collect()
        }

        for allowed in ["NTFS", "ntfs"] {
            assert!(is_allowed_filesystem_name(&encoded(allowed)));
        }
        for denied in [
            "ReFS", "refs", "FAT32", "exFAT", "CsvFS", "NTFS ", "ReFS2", "",
        ] {
            assert!(!is_allowed_filesystem_name(&encoded(denied)));
        }
        assert!(!is_allowed_filesystem_name(&[
            u16::from(b'N'),
            u16::from(b'T'),
            u16::from(b'F'),
            u16::from(b'S'),
        ]));
        assert!(!is_allowed_filesystem_name(&[
            u16::from(b'N'),
            u16::from(b'T'),
            u16::from(b'F'),
            u16::from(b'S'),
            0,
            u16::from(b'X'),
        ]));
    }

    #[test]
    fn volume_policy_rejects_every_nonfixed_remote_or_nonpersistent_shape() {
        fn encoded(name: &str) -> Vec<u16> {
            name.encode_utf16().chain(core::iter::once(0)).collect()
        }

        assert_eq!(
            validate_volume_characteristics(
                DRIVE_FIXED,
                false,
                FILE_PERSISTENT_ACLS,
                &encoded("NTFS"),
            ),
            Ok(())
        );
        for denied_drive in [
            DRIVE_UNKNOWN,
            DRIVE_NO_ROOT_DIR,
            DRIVE_REMOVABLE,
            DRIVE_REMOTE,
            DRIVE_CDROM,
            DRIVE_RAMDISK,
        ] {
            assert_eq!(
                validate_volume_characteristics(
                    denied_drive,
                    false,
                    FILE_PERSISTENT_ACLS,
                    &encoded("NTFS"),
                ),
                Err(StoreError::UnsafePath)
            );
        }
        assert_eq!(
            validate_volume_characteristics(
                DRIVE_FIXED,
                true,
                FILE_PERSISTENT_ACLS,
                &encoded("NTFS"),
            ),
            Err(StoreError::UnsafePath)
        );
        assert_eq!(
            validate_volume_characteristics(DRIVE_FIXED, false, 0, &encoded("NTFS")),
            Err(StoreError::UnsafePath)
        );
        for unsupported in ["ReFS", "FAT32", "exFAT", "CsvFS", "UDF", "unknown"] {
            assert_eq!(
                validate_volume_characteristics(
                    DRIVE_FIXED,
                    false,
                    FILE_PERSISTENT_ACLS,
                    &encoded(unsupported),
                ),
                Err(StoreError::UnsafePath)
            );
        }
    }

    #[test]
    fn local_path_policy_rejects_unc_device_relative_and_parent_traversal() {
        for allowed in [r"C:\wallet\vault", r"\\?\C:\wallet\vault"] {
            assert_eq!(validate_absolute_local_path(Path::new(allowed)), Ok(()));
        }
        for denied in [
            r"wallet\vault",
            r"\wallet\vault",
            r"C:wallet\vault",
            "C:\\wallet\0vault",
            r"C:\wallet\..\vault",
            r"\\server\share\wallet",
            r"\\?\UNC\server\share\wallet",
            r"\\.\C:\wallet",
        ] {
            assert_eq!(
                validate_absolute_local_path(Path::new(denied)),
                Err(StoreError::UnsafePath)
            );
        }
    }

    #[test]
    fn held_handle_volume_guid_parser_rejects_dos_unc_and_malformed_paths() {
        for malformed_guid in [
            r"\\?\Volume{00000000-0000-0000-0000-00000000000g}\wallet",
            r"\\?\Volume{000000000-000-0000-0000-000000000000}\wallet",
        ] {
            assert_eq!(
                volume_guid_root_from_final_path(
                    &malformed_guid.encode_utf16().collect::<Vec<_>>(),
                ),
                Err(StoreError::UnsafePath)
            );
        }

        let canonical = "\\\\?\\Volume{00112233-4455-6677-8899-aabbccddeeff}\\wallet\\vault"
            .encode_utf16()
            .collect::<Vec<_>>();
        assert_eq!(
            volume_guid_root_from_final_path(&canonical),
            Ok("\\\\?\\Volume{00112233-4455-6677-8899-aabbccddeeff}\\\0"
                .encode_utf16()
                .collect())
        );

        for denied in [
            r"\\?\D:\wallet\vault",
            r"\\server\share\wallet\vault",
            r"\\?\Volume{00112233-4455-6677-8899-aabbccddeeff}vault",
            r"\\?\Volume{00112233-4455-6677-8899-aabbccddeeff",
        ] {
            assert_eq!(
                volume_guid_root_from_final_path(&denied.encode_utf16().collect::<Vec<_>>()),
                Err(StoreError::UnsafePath)
            );
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "linear race-injection test keeps mutation boundaries auditable"
    )]
    fn atomic_write_never_repairs_or_replaces_injected_targets()
    -> Result<(), Box<dyn std::error::Error>> {
        use core::fmt::Write as _;

        const NAMESPACE: &str = "target-preflight";

        struct ExactCleanup {
            root: PathBuf,
            namespace: &'static str,
        }

        impl Drop for ExactCleanup {
            fn drop(&mut self) {
                let temporary_parent = std::env::temp_dir();
                let safe_name = self
                    .root
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("your-wallet-target-preflight-test-"));
                if !self.root.starts_with(&temporary_parent) || !safe_name {
                    return;
                }
                for suffix in [
                    "lock",
                    "slot0",
                    "slot1",
                    "manifest",
                    "slot0.new",
                    "slot1.new",
                    "manifest.new",
                ] {
                    let _ = std::fs::remove_file(
                        self.root.join(format!("{}.{suffix}", self.namespace)),
                    );
                }
                let _ = std::fs::remove_dir(&self.root);
            }
        }

        struct InjectWrongPolicyTarget {
            target: PathBuf,
            bytes: &'static [u8],
            fired: bool,
        }

        impl FaultControl for InjectWrongPolicyTarget {
            fn hit(&mut self, point: FaultPoint) -> Result<(), StoreError> {
                if point == FaultPoint::ManifestTempFlushed && !self.fired {
                    self.fired = true;
                    std::fs::write(&self.target, self.bytes)
                        .map_err(|_| StoreError::DurabilityFailure)?;
                }
                Ok(())
            }
        }

        struct SubstituteValidTarget {
            source: PathBuf,
            target: PathBuf,
            fired: bool,
        }

        impl FaultControl for SubstituteValidTarget {
            fn hit(&mut self, point: FaultPoint) -> Result<(), StoreError> {
                if point == FaultPoint::SlotTempFlushed && !self.fired {
                    self.fired = true;
                    atomic_replace(&self.source, &self.target)?;
                }
                Ok(())
            }
        }

        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(|_| StoreError::DurabilityFailure)?;
        let mut suffix = String::with_capacity(random.len() * 2);
        for byte in random {
            write!(&mut suffix, "{byte:02x}").map_err(|_| StoreError::DurabilityFailure)?;
        }
        let root = std::env::temp_dir().join(format!("your-wallet-target-preflight-test-{suffix}"));
        let _cleanup = ExactCleanup {
            root: root.clone(),
            namespace: NAMESPACE,
        };
        let config = StoreConfig::new(root.clone(), NAMESPACE, RecordClass::NonceLedger, 4096)?;
        let mut backend = WindowsBackend::open(&config)?;

        let wrong_target = root.join(format!("{NAMESPACE}.manifest"));
        let wrong_bytes = b"attacker target remains unchanged";
        let mut wrong_policy = InjectWrongPolicyTarget {
            target: wrong_target.clone(),
            bytes: wrong_bytes,
            fired: false,
        };
        assert!(matches!(
            backend.atomic_write(FileRole::Manifest, b"candidate manifest", &mut wrong_policy),
            Err(StoreError::InsecurePermissions
                | StoreError::UnprotectedDacl
                | StoreError::UnexpectedAccessControlEntry
                | StoreError::WrongStoragePrincipal)
        ));
        assert!(wrong_policy.fired);
        assert_eq!(std::fs::read(&wrong_target)?, wrong_bytes);

        let slot_zero = root.join(format!("{NAMESPACE}.slot0"));
        let slot_one = root.join(format!("{NAMESPACE}.slot1"));
        let mut no_fault = super::super::NoFault;
        backend.atomic_write(FileRole::Slot(0), b"original target", &mut no_fault)?;
        backend.atomic_write(FileRole::Slot(1), b"valid substitution", &mut no_fault)?;
        let mut substitution = SubstituteValidTarget {
            source: slot_one,
            target: slot_zero.clone(),
            fired: false,
        };
        assert_eq!(
            backend.atomic_write(FileRole::Slot(0), b"must not install", &mut substitution),
            Err(StoreError::UnsafePath),
        );
        assert!(substitution.fired);
        assert_eq!(std::fs::read(slot_zero)?, b"valid substitution");
        Ok(())
    }

    #[test]
    fn held_file_readback_binds_bytes_digest_identity_and_acl()
    -> Result<(), Box<dyn std::error::Error>> {
        use core::fmt::Write as _;

        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(|_| StoreError::DurabilityFailure)?;
        let mut suffix = String::with_capacity(random.len() * 2);
        for byte in random {
            write!(&mut suffix, "{byte:02x}").map_err(|_| StoreError::DurabilityFailure)?;
        }
        let root = std::env::temp_dir().join(format!("your-wallet-readback-test-{suffix}"));
        let descriptor = SecurityDescriptor::current_user_only()?;
        create_root_if_missing(&root, &descriptor)?;
        let root_handle = open_directory(&root)?;
        verify_not_reparse(&root_handle)?;
        verify_stable_user_security(&root_handle, &descriptor.stable_user_sid)?;
        verify_supported_local_volume(&root_handle)?;
        let root_identity = file_identity(&root_handle)?;

        let path = root.join("candidate.new");
        let expected = b"authenticated readback bytes";
        let mut writer = create_new_write_through(&path, &descriptor)?;
        let expected_identity = file_identity(&writer)?;
        writer.write_all(expected)?;
        flush_file(&writer)?;
        drop(writer);

        let installed = open_existing_file(&path)?;
        verify_installed_readback(
            &installed,
            expected_identity,
            root_identity.volume_serial,
            expected,
            sha256(expected),
            &descriptor,
        )?;
        drop(installed);

        let wrong_bytes = b"authenticated readback byte!";
        let installed = open_existing_file(&path)?;
        assert_eq!(
            verify_installed_readback(
                &installed,
                expected_identity,
                root_identity.volume_serial,
                wrong_bytes,
                sha256(wrong_bytes),
                &descriptor,
            ),
            Err(StoreError::DurabilityFailure)
        );
        drop(installed);

        let installed = open_existing_file(&path)?;
        let mut wrong_digest = sha256(expected);
        wrong_digest[0] ^= 1;
        assert_eq!(
            verify_installed_readback(
                &installed,
                expected_identity,
                root_identity.volume_serial,
                expected,
                wrong_digest,
                &descriptor,
            ),
            Err(StoreError::DurabilityFailure)
        );
        drop(installed);

        let installed = open_existing_file(&path)?;
        let mut wrong_identity = expected_identity;
        wrong_identity.file_id[15] ^= 1;
        assert_eq!(
            verify_installed_readback(
                &installed,
                wrong_identity,
                root_identity.volume_serial,
                expected,
                sha256(expected),
                &descriptor,
            ),
            Err(StoreError::UnsafePath)
        );
        drop(installed);
        drop(root_handle);

        let temporary_parent = std::env::temp_dir();
        let safe_name = root
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("your-wallet-readback-test-"));
        if !root.starts_with(&temporary_parent) || !safe_name {
            return Err(StoreError::UnsafePath.into());
        }
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
