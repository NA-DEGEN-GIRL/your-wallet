//! Exact ambient process context shared by restricted Windows child launches.
//!
//! The capability owns one validated System32 current-directory string and one
//! double-NUL Unicode environment containing only `SystemRoot` and `WINDIR`.
//! Callers receive borrowed UTF-16 slices only; they cannot substitute an
//! ambient environment or an unvalidated working directory through this API.

#![allow(unsafe_code)]

use core::marker::PhantomData;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::MetadataExt;
use std::path::{Component, Path, PathBuf, Prefix};
use std::rc::Rc;

use windows::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_NO_TOKEN, HANDLE, INVALID_HANDLE_VALUE,
};
use windows::Win32::Globalization::{CSTR_EQUAL, CompareStringOrdinal};
use windows::Win32::Security::TOKEN_QUERY;
use windows::Win32::Storage::FileSystem::{
    CreateFileW, DELETE, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_DELETE_CHILD, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, WRITE_DAC, WRITE_OWNER,
};
use windows::Win32::System::SystemInformation::{GetSystemDirectoryW, GetSystemWindowsDirectoryW};
use windows::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};
use windows::core::PCWSTR;

const MAX_SYSTEM_PATH_UNITS: usize = 32_768;
const MAX_ENVIRONMENT_UNITS: usize = 32_767;
const PATH_REPLACEMENT_RIGHTS: [u32; 4] =
    [FILE_DELETE_CHILD.0, DELETE.0, WRITE_DAC.0, WRITE_OWNER.0];
const PROTECTED_DIRECTORY_CONTENT_RIGHTS: [u32; 2] = [FILE_ADD_FILE.0, FILE_ADD_SUBDIRECTORY.0];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RestrictedProcessContextError {
    OperatingSystem,
    ThreadImpersonation,
    UnsafeWorkingDirectory,
}

/// Prepared, immutable process context retained through one child creation.
#[must_use = "the owned UTF-16 process context must outlive child creation"]
pub(crate) struct RestrictedProcessContext {
    environment: Box<[u16]>,
    current_directory: Box<[u16]>,
    _same_thread: PhantomData<Rc<()>>,
}

struct SystemProcessPaths {
    windows_root: PathBuf,
    current_directory: PathBuf,
}

impl RestrictedProcessContext {
    pub(crate) fn prepare() -> Result<Self, RestrictedProcessContextError> {
        let paths = prepare_system_process_paths()?;
        reject_replaceable_ancestors(&paths.windows_root)?;
        reject_replaceable_ancestors(&paths.current_directory)?;
        reject_content_writable_directory(&paths.windows_root)?;
        reject_content_writable_directory(&paths.current_directory)?;
        reject_thread_impersonation()?;
        Self::from_system_paths(&paths)
    }

    #[cfg(test)]
    pub(crate) fn prepare_for_kernel_test() -> Result<Self, RestrictedProcessContextError> {
        // Kernel activation tests can run under an elevated developer token,
        // which is expected to have administrative write rights to System32.
        // They retain the exact OS paths, path-shape, reparse, containment, and
        // impersonation checks while dedicated policy tests cover writable
        // directory rejection. The production build contains neither this
        // constructor nor a runtime switch that can skip its rights checks.
        let paths = prepare_system_process_paths()?;
        Self::from_system_paths(&paths)
    }

    fn from_system_paths(
        paths: &SystemProcessPaths,
    ) -> Result<Self, RestrictedProcessContextError> {
        Ok(Self {
            environment: minimal_environment_block(&paths.windows_root)?.into_boxed_slice(),
            current_directory: wide_nul_path(&paths.current_directory).into_boxed_slice(),
            _same_thread: PhantomData,
        })
    }

    pub(crate) fn environment(&self) -> &[u16] {
        &self.environment
    }

    pub(crate) fn current_directory(&self) -> &[u16] {
        &self.current_directory
    }

    pub(crate) fn recheck_thread(&self) -> Result<(), RestrictedProcessContextError> {
        if !self.environment.ends_with(&[0, 0]) || self.current_directory.last() != Some(&0) {
            return Err(RestrictedProcessContextError::OperatingSystem);
        }
        reject_thread_impersonation()
    }
}

fn prepare_system_process_paths() -> Result<SystemProcessPaths, RestrictedProcessContextError> {
    reject_thread_impersonation()?;
    let windows_root = query_system_path(GetSystemWindowsDirectoryW)?;
    let current_directory = query_system_path(GetSystemDirectoryW)?;
    validate_existing_reparse_free_directory(&windows_root)?;
    validate_existing_reparse_free_directory(&current_directory)?;
    validate_system_directory_layout(&windows_root, &current_directory)?;
    reject_thread_impersonation()?;
    Ok(SystemProcessPaths {
        windows_root,
        current_directory,
    })
}

fn query_system_path(
    getter: unsafe fn(Option<&mut [u16]>) -> u32,
) -> Result<PathBuf, RestrictedProcessContextError> {
    let mut buffer = vec![0_u16; MAX_SYSTEM_PATH_UNITS];
    // SAFETY: the writable buffer is valid for the complete call. Both
    // accepted getters have identical contracts and return a UTF-16 length.
    let length = unsafe { getter(Some(&mut buffer)) };
    let length =
        usize::try_from(length).map_err(|_| RestrictedProcessContextError::OperatingSystem)?;
    if length == 0 || length >= buffer.len() || buffer[..length].contains(&0) {
        return Err(RestrictedProcessContextError::OperatingSystem);
    }
    Ok(PathBuf::from(OsString::from_wide(&buffer[..length])))
}

#[cfg(test)]
fn validate_secure_working_directory(path: &Path) -> Result<(), RestrictedProcessContextError> {
    validate_existing_reparse_free_directory(path)?;
    reject_replaceable_ancestors(path)?;
    reject_content_writable_directory(path)
}

fn validate_existing_reparse_free_directory(
    path: &Path,
) -> Result<(), RestrictedProcessContextError> {
    if !plain_absolute_dos_path(path)
        || !fs::metadata(path)
            .map_err(|_| RestrictedProcessContextError::UnsafeWorkingDirectory)?
            .is_dir()
    {
        return Err(RestrictedProcessContextError::UnsafeWorkingDirectory);
    }
    for ancestor in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
        reject_reparse_directory(ancestor)?;
    }
    Ok(())
}

fn reject_replaceable_ancestors(path: &Path) -> Result<(), RestrictedProcessContextError> {
    for ancestor in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
        reject_dangerous_directory_rights(ancestor, &PATH_REPLACEMENT_RIGHTS)?;
    }
    Ok(())
}

fn reject_content_writable_directory(path: &Path) -> Result<(), RestrictedProcessContextError> {
    reject_dangerous_directory_rights(path, &PROTECTED_DIRECTORY_CONTENT_RIGHTS)
}

fn plain_absolute_dos_path(path: &Path) -> bool {
    let encoded: Vec<u16> = path.as_os_str().encode_wide().collect();
    if encoded.contains(&u16::from(b'/'))
        || encoded
            .split(|unit| *unit == u16::from(b'\\'))
            .any(|part| part == [u16::from(b'.')] || part == [u16::from(b'.'), u16::from(b'.')])
    {
        return false;
    }
    let mut components = path.components();
    if !matches!(
        components.next(),
        Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::Disk(_))
    ) || !matches!(components.next(), Some(Component::RootDir))
    {
        return false;
    }
    components.all(|component| matches!(component, Component::Normal(_)))
}

fn validate_system_directory_layout(
    windows_root: &Path,
    system_directory: &Path,
) -> Result<(), RestrictedProcessContextError> {
    let parent = system_directory
        .parent()
        .ok_or(RestrictedProcessContextError::UnsafeWorkingDirectory)?;
    let leaf = system_directory
        .file_name()
        .ok_or(RestrictedProcessContextError::UnsafeWorkingDirectory)?;
    if !ordinal_eq(parent.as_os_str(), windows_root.as_os_str())
        || !ordinal_eq(leaf, OsStr::new("System32"))
    {
        return Err(RestrictedProcessContextError::UnsafeWorkingDirectory);
    }
    Ok(())
}

fn ordinal_eq(first: &OsStr, second: &OsStr) -> bool {
    let first: Vec<u16> = first.encode_wide().collect();
    let second: Vec<u16> = second.encode_wide().collect();
    // SAFETY: both slices are initialized UTF-16 and the API receives their
    // explicit lengths, so no terminator or locale-dependent comparison occurs.
    (unsafe { CompareStringOrdinal(&first, &second, true) }) == CSTR_EQUAL
}

fn reject_thread_impersonation() -> Result<(), RestrictedProcessContextError> {
    let mut token = HANDLE::default();
    // SAFETY: the current pseudo-thread handle is valid for this scalar query;
    // OpenAsSelf makes the query itself independent of an impersonation level.
    let result = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &raw mut token) };
    match result {
        Ok(()) if token.is_invalid() || token == INVALID_HANDLE_VALUE => {
            Err(RestrictedProcessContextError::OperatingSystem)
        }
        Ok(()) => {
            // SAFETY: successful OpenThreadToken returned one fresh owned handle.
            unsafe {
                let _ = CloseHandle(token);
            }
            Err(RestrictedProcessContextError::ThreadImpersonation)
        }
        Err(error) if error.code() == ERROR_NO_TOKEN.to_hresult() => Ok(()),
        Err(_) => Err(RestrictedProcessContextError::OperatingSystem),
    }
}

fn reject_reparse_directory(path: &Path) -> Result<(), RestrictedProcessContextError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| RestrictedProcessContextError::UnsafeWorkingDirectory)?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        return Err(RestrictedProcessContextError::UnsafeWorkingDirectory);
    }
    Ok(())
}

fn reject_dangerous_directory_rights(
    path: &Path,
    dangerous_rights: &[u32],
) -> Result<(), RestrictedProcessContextError> {
    let wide = wide_nul_path(path);
    for right in dangerous_rights.iter().copied() {
        // SAFETY: `wide` is NUL terminated. This opens an existing directory
        // only to ask Windows whether the process primary token can obtain one
        // dangerous right. Preparation rejects thread impersonation first.
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
                return Err(RestrictedProcessContextError::UnsafeWorkingDirectory);
            }
            Err(error) if error.code() == ERROR_ACCESS_DENIED.to_hresult() => {}
            Err(_) => return Err(RestrictedProcessContextError::OperatingSystem),
        }
    }
    Ok(())
}

fn minimal_environment_block(
    windows_root: &Path,
) -> Result<Vec<u16>, RestrictedProcessContextError> {
    if !plain_absolute_dos_path(windows_root) {
        return Err(RestrictedProcessContextError::UnsafeWorkingDirectory);
    }
    let value: Vec<u16> = windows_root.as_os_str().encode_wide().collect();
    if value.is_empty() || value.contains(&0) {
        return Err(RestrictedProcessContextError::OperatingSystem);
    }
    let capacity = value
        .len()
        .checked_mul(2)
        .and_then(|length| length.checked_add(24))
        .ok_or(RestrictedProcessContextError::OperatingSystem)?;
    let mut block = Vec::with_capacity(capacity);
    for name in ["SystemRoot=", "WINDIR="] {
        block.extend(name.encode_utf16());
        block.extend_from_slice(&value);
        block.push(0);
    }
    block.push(0);
    if block.len() > MAX_ENVIRONMENT_UNITS {
        return Err(RestrictedProcessContextError::OperatingSystem);
    }
    Ok(block)
}

fn wide_nul_path(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(core::iter::once(0))
        .collect()
}

#[cfg(test)]
pub(crate) fn environment_for_test(root: &Path) -> Result<Vec<u16>, RestrictedProcessContextError> {
    minimal_environment_block(root)
}

#[cfg(test)]
pub(crate) fn validate_working_directory_for_test(
    path: &Path,
) -> Result<(), RestrictedProcessContextError> {
    validate_secure_working_directory(path)
}

#[cfg(test)]
pub(crate) fn validate_system_directory_layout_for_test(
    windows_root: &Path,
    system_directory: &Path,
) -> Result<(), RestrictedProcessContextError> {
    if !plain_absolute_dos_path(windows_root) || !plain_absolute_dos_path(system_directory) {
        return Err(RestrictedProcessContextError::UnsafeWorkingDirectory);
    }
    validate_system_directory_layout(windows_root, system_directory)
}

#[cfg(test)]
pub(crate) fn reject_thread_impersonation_for_test() -> Result<(), RestrictedProcessContextError> {
    reject_thread_impersonation()
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::path::{Path, PathBuf};

    use windows::Win32::Security::{ImpersonateSelf, RevertToSelf, SecurityImpersonation};
    use windows::Win32::Storage::FileSystem::{
        DELETE, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_DELETE_CHILD, WRITE_DAC, WRITE_OWNER,
    };

    use super::{
        MAX_ENVIRONMENT_UNITS, PATH_REPLACEMENT_RIGHTS, PROTECTED_DIRECTORY_CONTENT_RIGHTS,
        RestrictedProcessContext, RestrictedProcessContextError, minimal_environment_block,
        reject_thread_impersonation_for_test, validate_system_directory_layout_for_test,
    };

    struct RevertImpersonation;

    trait AmbiguousIfSend<A> {
        fn marker() {}
    }
    impl<T: ?Sized> AmbiguousIfSend<()> for T {}
    impl<T: ?Sized + Send> AmbiguousIfSend<u8> for T {}

    trait AmbiguousIfSync<A> {
        fn marker() {}
    }
    impl<T: ?Sized> AmbiguousIfSync<()> for T {}
    impl<T: ?Sized + Sync> AmbiguousIfSync<u8> for T {}

    trait AmbiguousIfClone<A> {
        fn marker() {}
    }
    impl<T: ?Sized> AmbiguousIfClone<()> for T {}
    impl<T: Clone> AmbiguousIfClone<u8> for T {}

    trait AmbiguousIfCopy<A> {
        fn marker() {}
    }
    impl<T: ?Sized> AmbiguousIfCopy<()> for T {}
    impl<T: Copy> AmbiguousIfCopy<u8> for T {}

    impl Drop for RevertImpersonation {
        fn drop(&mut self) {
            // SAFETY: this guard is created only after ImpersonateSelf succeeds
            // on the same test thread and reverts that one thread exactly once.
            unsafe {
                let _ = RevertToSelf();
            }
        }
    }

    #[test]
    fn process_context_is_thread_bound_non_clone_and_non_copy() {
        let _ = <RestrictedProcessContext as AmbiguousIfSend<_>>::marker;
        let _ = <RestrictedProcessContext as AmbiguousIfSync<_>>::marker;
        let _ = <RestrictedProcessContext as AmbiguousIfClone<_>>::marker;
        let _ = <RestrictedProcessContext as AmbiguousIfCopy<_>>::marker;
    }

    #[test]
    fn ancestor_replacement_and_protected_content_right_sets_are_distinct() {
        assert_eq!(
            PATH_REPLACEMENT_RIGHTS,
            [FILE_DELETE_CHILD.0, DELETE.0, WRITE_DAC.0, WRITE_OWNER.0]
        );
        assert_eq!(
            PROTECTED_DIRECTORY_CONTENT_RIGHTS,
            [FILE_ADD_FILE.0, FILE_ADD_SUBDIRECTORY.0]
        );
        assert!(
            PATH_REPLACEMENT_RIGHTS
                .iter()
                .all(|right| !PROTECTED_DIRECTORY_CONTENT_RIGHTS.contains(right))
        );
    }

    #[test]
    fn environment_block_rejects_interior_nul_and_excess_length() {
        let interior_nul = PathBuf::from(OsString::from_wide(&[
            u16::from(b'C'),
            u16::from(b':'),
            u16::from(b'\\'),
            u16::from(b'W'),
            0,
            u16::from(b'X'),
        ]));
        assert_eq!(
            minimal_environment_block(&interior_nul),
            Err(RestrictedProcessContextError::OperatingSystem)
        );

        // Two names, two values, three terminators: 21 fixed UTF-16 units.
        let maximum_root_units = (MAX_ENVIRONMENT_UNITS - 21) / 2;
        let mut maximum_root = r"C:\".encode_utf16().collect::<Vec<_>>();
        maximum_root.resize(maximum_root_units, u16::from(b'a'));
        let maximum_root = PathBuf::from(OsString::from_wide(&maximum_root));
        assert_eq!(
            minimal_environment_block(&maximum_root).map(|block| block.len()),
            Ok(MAX_ENVIRONMENT_UNITS)
        );

        let mut oversized_root: Vec<u16> = maximum_root.as_os_str().encode_wide().collect();
        oversized_root.push(u16::from(b'a'));
        let oversized_root = PathBuf::from(OsString::from_wide(&oversized_root));
        assert_eq!(
            minimal_environment_block(&oversized_root),
            Err(RestrictedProcessContextError::OperatingSystem)
        );
    }

    #[test]
    fn exact_system_directory_layout_is_case_insensitive_and_rejects_ambiguous_paths() {
        assert_eq!(
            validate_system_directory_layout_for_test(
                Path::new(r"C:\Windows"),
                Path::new(r"c:\WINDOWS\system32"),
            ),
            Ok(())
        );
        for (root, system) in [
            (r"C:\Windows", r"C:\Windows\SysWOW64"),
            (r"C:\Windows", r"D:\Windows\System32"),
            (r"C:\Windows", r"C:\Other\System32"),
            (r"C:\Windows", r"\\server\share\Windows\System32"),
            (r"C:\Windows", r"\\?\C:\Windows\System32"),
            (r"C:\Windows", r"C:\Windows\.\System32"),
            (r"C:\Windows", r"C:\Windows\Other\..\System32"),
        ] {
            assert_eq!(
                validate_system_directory_layout_for_test(Path::new(root), Path::new(system)),
                Err(RestrictedProcessContextError::UnsafeWorkingDirectory)
            );
        }
    }

    #[test]
    fn kernel_test_context_uses_exact_os_paths_and_two_name_environment()
    -> Result<(), RestrictedProcessContextError> {
        let context = RestrictedProcessContext::prepare_for_kernel_test()?;
        let environment = context.environment();
        let system_root_prefix = "SystemRoot=".encode_utf16().collect::<Vec<_>>();
        let windir_prefix = "WINDIR=".encode_utf16().collect::<Vec<_>>();
        assert!(environment.ends_with(&[0, 0]));
        assert_eq!(environment.iter().filter(|unit| **unit == 0).count(), 3);
        assert!(environment.starts_with(&system_root_prefix));
        assert!(
            environment
                .windows(windir_prefix.len())
                .any(|window| window == windir_prefix)
        );
        assert_eq!(context.current_directory().last(), Some(&0));
        assert_eq!(
            context
                .current_directory()
                .iter()
                .filter(|unit| **unit == 0)
                .count(),
            1
        );
        context.recheck_thread()
    }

    #[test]
    fn impersonating_thread_cannot_prepare_or_recheck_context() -> windows::core::Result<()> {
        let Ok(context) = RestrictedProcessContext::prepare_for_kernel_test() else {
            return Err(windows::core::Error::from_win32());
        };
        // SAFETY: the guard below always reverts this exact test thread.
        unsafe { ImpersonateSelf(SecurityImpersonation)? };
        let guard = RevertImpersonation;
        assert_eq!(
            reject_thread_impersonation_for_test(),
            Err(RestrictedProcessContextError::ThreadImpersonation)
        );
        assert_eq!(
            context.recheck_thread(),
            Err(RestrictedProcessContextError::ThreadImpersonation)
        );
        assert!(matches!(
            RestrictedProcessContext::prepare_for_kernel_test(),
            Err(RestrictedProcessContextError::ThreadImpersonation)
        ));
        drop(guard);
        assert_eq!(reject_thread_impersonation_for_test(), Ok(()));
        assert_eq!(context.recheck_thread(), Ok(()));
        Ok(())
    }
}
