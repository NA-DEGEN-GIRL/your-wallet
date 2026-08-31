//! Kernel-backed tests for the dormant held service run-state root.

#![allow(unsafe_code)]

use core::mem::size_of;
use core::ptr;
use std::fs;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::fs::symlink_file;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_SHARING_VIOLATION, ERROR_SUCCESS,
    GENERIC_WRITE, GetLastError, HANDLE, HLOCAL, LocalFree, SetLastError, WAIT_OBJECT_0,
};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1, SE_FILE_OBJECT,
    SetSecurityInfo,
};
use windows::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, ImpersonateSelf,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, RevertToSelf, SECURITY_ATTRIBUTES,
    SecurityImpersonation,
};
use windows::Win32::Storage::FileSystem::{
    CREATE_ALWAYS, CREATE_NEW, CreateDirectoryW, CreateFileW, DELETE, FILE_ADD_FILE,
    FILE_ADD_SUBDIRECTORY, FILE_ALL_ACCESS, FILE_ATTRIBUTE_NORMAL, FILE_DELETE_CHILD,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_WRITE_DATA, OPEN_EXISTING, READ_CONTROL, WRITE_DAC, WRITE_OWNER,
    WriteFile,
};
use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::System::Ioctl::{FSCTL_SET_REPARSE_POINT, FSCTL_SET_SPARSE};
use windows::Win32::System::SystemServices::IO_REPARSE_TAG_MOUNT_POINT;
use windows::Win32::System::Threading::{
    CreateEventW, EVENT_MODIFY_STATE, OpenEventW, SetEvent, WaitForSingleObject,
};
use windows::core::{BOOL, PCWSTR};

use super::sys::{self, TestObjectIdentity};
use super::{
    ExactFixedRunStatePair, ExpectedInstalledRunStateObjects, FIXED_RUN_STATE_RECORD_BYTES,
    FixedPairCommitOutcome, FixedPairCommitted, FixedRunStateRecordObservation,
    HeldServiceRunStateRoot, HeldServiceRunStateWriter, ObservedFixedRunStatePair,
    RuntimeRunLockStartFailure, ServiceRunStateError, open_test_service_run_state_root,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
type TestResultWith<T> = Result<T, Box<dyn std::error::Error>>;

const TEST_ROOT_PREFIX: &str = "YourWallet.Phase2E.Test.";
const CHILD_TEST_NAME: &str =
    "key_agent_service::run_state_root::tests::cross_process_child_fixture";
const CHILD_MODE_ENV: &str = "YOUR_WALLET_PHASE2E_CHILD_MODE";
const CHILD_BASE_ENV: &str = "YOUR_WALLET_PHASE2E_CHILD_BASE";
const CHILD_EVENT_ENV: &str = "YOUR_WALLET_PHASE2E_CHILD_EVENT";
const CHILD_MODE_HOLD: &str = "hold";
const CHILD_MODE_SENTINEL: &str = "sentinel";
const CHILD_READY_TIMEOUT_MS: u32 = 30_000;
const CHILD_EXIT_TIMEOUT: Duration = Duration::from_secs(30);
const LOCK_REACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(10);

struct TestSecurityDescriptor(PSECURITY_DESCRIPTOR);

impl TestSecurityDescriptor {
    fn from_sddl(sddl: &str) -> Result<Self, ServiceRunStateError> {
        let wide = wide_string(sddl).map_err(|_| ServiceRunStateError::Security)?;
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: the input is NUL-terminated and the successful output is one
        // LocalAlloc allocation owned by this wrapper.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide.as_ptr()),
                SDDL_REVISION_1,
                &raw mut descriptor,
                None,
            )
        }
        .map_err(|_| ServiceRunStateError::Security)?;
        if descriptor.0.is_null() {
            return Err(ServiceRunStateError::Security);
        }
        Ok(Self(descriptor))
    }

    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(u32::MAX),
            lpSecurityDescriptor: self.0.0,
            bInheritHandle: BOOL(0),
        }
    }

    fn dacl(&self) -> Result<*mut ACL, ServiceRunStateError> {
        let mut present = BOOL(0);
        let mut defaulted = BOOL(0);
        let mut dacl = ptr::null_mut::<ACL>();
        // SAFETY: all outputs are exact and this descriptor remains live.
        unsafe {
            GetSecurityDescriptorDacl(self.0, &raw mut present, &raw mut dacl, &raw mut defaulted)
        }
        .map_err(|_| ServiceRunStateError::Security)?;
        if !present.as_bool() || defaulted.as_bool() || dacl.is_null() {
            return Err(ServiceRunStateError::Security);
        }
        Ok(dacl)
    }
}

impl Drop for TestSecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: this is the one LocalAlloc block returned by SDDL conversion.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(self.0.0)));
        }
    }
}

struct CleanupHandle(Option<HANDLE>);

impl CleanupHandle {
    fn raw(&self) -> Result<HANDLE, std::io::Error> {
        self.0
            .ok_or_else(|| std::io::Error::other("cleanup handle is absent"))
    }

    fn relax(&self) -> TestResult {
        let handle = self.raw()?;
        let relaxed = sys::current_service_sid_string_for_test()
            .map(|service| format!("D:P(A;;FA;;;{service})"))
            .and_then(|sddl| TestSecurityDescriptor::from_sddl(&sddl))?;
        let dacl = relaxed.dacl()?;
        // SAFETY: this test-only retained handle requested WRITE_DAC at
        // creation; the descriptor remains live for the complete update.
        let status = unsafe {
            SetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(dacl),
                None,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(std::io::Error::other(format!(
                "fixture root cleanup DACL update failed with status {}",
                status.0
            ))
            .into());
        }
        Ok(())
    }

    fn close_checked(&mut self) -> windows::core::Result<()> {
        let Some(handle) = self.0.take() else {
            return Ok(());
        };
        // SAFETY: this consumes the one non-inheritable cleanup handle.
        unsafe { CloseHandle(handle) }
    }

    fn relax_and_close_checked(&mut self) -> TestResult {
        let relax_result = self.relax();
        let close_result = self.close_checked();
        relax_result?;
        close_result?;
        Ok(())
    }

    fn relax_and_close(&mut self) {
        let _ = self.relax_and_close_checked();
    }
}

struct SetupHandle(Option<HANDLE>);

impl SetupHandle {
    fn raw(&self) -> Result<HANDLE, std::io::Error> {
        self.0
            .ok_or_else(|| std::io::Error::other("setup handle is absent"))
    }

    fn close_checked(&mut self) -> windows::core::Result<()> {
        let Some(handle) = self.0.take() else {
            return Ok(());
        };
        // SAFETY: this consumes the one test setup handle exactly once.
        unsafe { CloseHandle(handle) }
    }
}

impl Drop for SetupHandle {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            // SAFETY: fallback cleanup cannot issue a checked test assertion.
            unsafe {
                let _ = CloseHandle(handle);
            }
        }
    }
}

struct NamedTestEvent {
    name: String,
    handle: SetupHandle,
}

impl NamedTestEvent {
    fn create() -> Result<Self, Box<dyn std::error::Error>> {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random)
            .map_err(|_| std::io::Error::other("test event randomness unavailable"))?;
        let name = format!(
            "Local\\YourWallet.Phase2E.{:032x}",
            u128::from_le_bytes(random)
        );
        let wide = wide_string(&name)?;
        // SAFETY: resetting last-error before CreateEventW permits an exact
        // ERROR_ALREADY_EXISTS adoption check on the random local name.
        unsafe { SetLastError(ERROR_SUCCESS) };
        // SAFETY: the name is NUL-terminated; default security is sufficient
        // for the same-user child, and the returned handle is non-inheritable.
        let handle = unsafe { CreateEventW(None, true, false, PCWSTR(wide.as_ptr())) }?;
        // SAFETY: CreateEventW just completed on this same test thread.
        if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            // SAFETY: an adopted event is rejected and its one handle consumed.
            unsafe { CloseHandle(handle) }?;
            return Err(std::io::Error::other("test event name was already present").into());
        }
        Ok(Self {
            name,
            handle: SetupHandle(Some(handle)),
        })
    }

    fn wait_ready(&self) -> TestResult {
        // SAFETY: the event remains live for the bounded synchronized wait.
        let wait = unsafe { WaitForSingleObject(self.handle.raw()?, CHILD_READY_TIMEOUT_MS) };
        if wait != WAIT_OBJECT_0 {
            return Err(std::io::Error::other(format!(
                "child readiness event wait failed with status {}",
                wait.0
            ))
            .into());
        }
        Ok(())
    }

    fn close_checked(mut self) -> TestResult {
        self.handle.close_checked()?;
        Ok(())
    }
}

struct ChildProcessGuard(Option<Child>);

impl ChildProcessGuard {
    fn spawn(mode: &'static str, base: &Path, event_name: &str) -> TestResultWith<Self> {
        let executable = std::env::current_exe()?;
        let child = Command::new(executable)
            .arg(CHILD_TEST_NAME)
            .arg("--exact")
            .arg("--ignored")
            .arg("--test-threads=1")
            .env_clear()
            .env(CHILD_MODE_ENV, mode)
            .env(CHILD_BASE_ENV, base.as_os_str())
            .env(CHILD_EVENT_ENV, event_name)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| {
                std::io::Error::new(error.kind(), "Phase 2E child process launch failed")
            })?;
        Ok(Self(Some(child)))
    }

    fn force_exit_and_wait(mut self) -> TestResult {
        let child = self
            .0
            .as_mut()
            .ok_or_else(|| std::io::Error::other("child process is absent"))?;
        child.kill().map_err(|error| {
            std::io::Error::new(error.kind(), "Phase 2E child forced exit failed")
        })?;
        let deadline = Instant::now() + CHILD_EXIT_TIMEOUT;
        loop {
            match child.try_wait().map_err(|error| {
                std::io::Error::new(error.kind(), "Phase 2E child exit query failed")
            })? {
                Some(_status) => {
                    let _closed = self.0.take();
                    return Ok(());
                }
                None if Instant::now() >= deadline => {
                    return Err(std::io::Error::other(
                        "Phase 2E child did not exit before the fixed deadline",
                    )
                    .into());
                }
                None => std::thread::sleep(PROCESS_POLL_INTERVAL),
            }
        }
    }
}

impl Drop for ChildProcessGuard {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for CleanupHandle {
    fn drop(&mut self) {
        self.relax_and_close();
    }
}

struct FixtureTreeGuard {
    cleanup_root: PathBuf,
    root_cleanup: Option<CleanupHandle>,
    active: bool,
}

impl FixtureTreeGuard {
    fn create(cleanup_root: PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        fs::create_dir(&cleanup_root)?;
        Ok(Self {
            cleanup_root,
            root_cleanup: None,
            active: true,
        })
    }

    fn path(&self) -> &Path {
        &self.cleanup_root
    }

    fn install_root_cleanup(&mut self, cleanup: CleanupHandle) -> TestResult {
        if self.root_cleanup.is_some() {
            return Err(std::io::Error::other("duplicate fixture cleanup authority").into());
        }
        self.root_cleanup = Some(cleanup);
        Ok(())
    }

    fn root_cleanup(&self) -> Result<&CleanupHandle, std::io::Error> {
        self.root_cleanup
            .as_ref()
            .ok_or_else(|| std::io::Error::other("root cleanup authority is absent"))
    }

    fn relax_and_close_root_checked(&mut self) -> TestResult {
        let mut cleanup = self
            .root_cleanup
            .take()
            .ok_or_else(|| std::io::Error::other("root cleanup authority is absent"))?;
        let result = cleanup.relax_and_close_checked();
        if result.is_err() {
            self.root_cleanup = Some(cleanup);
        }
        result
    }

    fn cleanup_checked(&mut self) -> TestResult {
        if !self.active {
            return Ok(());
        }
        let authority_result = self
            .root_cleanup
            .as_mut()
            .map_or(Ok(()), CleanupHandle::relax_and_close_checked);
        let removal_result = remove_fixture_tree(&self.cleanup_root);
        if removal_result.is_ok() {
            self.active = false;
        }
        authority_result?;
        removal_result?;
        Ok(())
    }
}

impl Drop for FixtureTreeGuard {
    fn drop(&mut self) {
        if self.active {
            let _ = self.cleanup_checked();
        }
    }
}

struct InstalledFixture {
    tree: FixtureTreeGuard,
    cleanup_root: PathBuf,
    base: PathBuf,
    root_identity: TestObjectIdentity,
    lock_identity: TestObjectIdentity,
    state_identity: TestObjectIdentity,
}

impl InstalledFixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let cleanup_root = unique_test_root()?;
        let mut tree = FixtureTreeGuard::create(cleanup_root.clone())?;
        let base = cleanup_root.join("유니코드-base");
        fs::create_dir(&base)?;
        create_intermediate_directories(&base)?;
        let (mut setup, root_cleanup) = create_root_for_test_install(&base)?;
        tree.install_root_cleanup(root_cleanup)?;
        create_lock_for_test_install(&base)?;
        create_state_for_test_install(&base)?;
        seal_handle_dacl(
            setup.raw()?,
            &sys::exact_sddl_for_test(sys::ROOT_ACCESS_FOR_TEST)?,
            "root",
        )?;
        // SAFETY: setup owns the only handle with FILE_ADD_FILE; it is closed
        // before identities are recorded or the production adapter is called.
        setup.close_checked()?;
        if sys::verify_object_security_for_test(&root_path(&base), true, sys::ROOT_ACCESS_FOR_TEST)
            .is_err()
        {
            let diagnostic = sys::diagnose_object_security_for_test(&root_path(&base), true)?;
            return Err(std::io::Error::other(format!(
                "sealed root security mismatch: {diagnostic:?}"
            ))
            .into());
        }
        if sys::verify_object_security_for_test(&lock_path(&base), false, sys::LOCK_ACCESS_FOR_TEST)
            .is_err()
        {
            let diagnostic = sys::diagnose_object_security_for_test(&lock_path(&base), false)?;
            return Err(std::io::Error::other(format!(
                "from-birth lock security mismatch: {diagnostic:?}"
            ))
            .into());
        }
        if sys::verify_object_security_for_test(
            &state_path(&base),
            true,
            sys::STATE_ACCESS_FOR_TEST,
        )
        .is_err()
        {
            let diagnostic = sys::diagnose_object_security_for_test(&state_path(&base), true)?;
            return Err(std::io::Error::other(format!(
                "from-birth state security mismatch: {diagnostic:?}"
            ))
            .into());
        }
        let root_identity = sys::record_object_identity_for_test(&root_path(&base), true)?;
        let lock_identity = sys::record_object_identity_for_test(&lock_path(&base), false)?;
        let state_identity = sys::record_object_identity_for_test(&state_path(&base), true)?;
        Ok(Self {
            tree,
            cleanup_root,
            base,
            root_identity,
            lock_identity,
            state_identity,
        })
    }

    fn expected(&self) -> Result<ExpectedInstalledRunStateObjects, ServiceRunStateError> {
        sys::expected_objects_for_test(self.root_identity, self.lock_identity, self.state_identity)
            .map(ExpectedInstalledRunStateObjects)
    }

    fn identities(&self) -> (TestObjectIdentity, TestObjectIdentity, TestObjectIdentity) {
        (self.root_identity, self.lock_identity, self.state_identity)
    }

    fn root_cleanup(&self) -> Result<&CleanupHandle, std::io::Error> {
        self.tree.root_cleanup()
    }

    fn relax_root(&self) -> TestResult {
        self.root_cleanup()?.relax()
    }

    fn reseal_root(&self) -> TestResult {
        seal_handle_dacl(
            self.root_cleanup()?.raw()?,
            &sys::exact_sddl_for_test(sys::ROOT_ACCESS_FOR_TEST)?,
            "root",
        )
    }

    fn expected_with_lock(
        &self,
        lock_identity: TestObjectIdentity,
    ) -> Result<ExpectedInstalledRunStateObjects, ServiceRunStateError> {
        sys::expected_objects_for_test(self.root_identity, lock_identity, self.state_identity)
            .map(ExpectedInstalledRunStateObjects)
    }

    fn expected_with_state(
        &self,
        state_identity: TestObjectIdentity,
    ) -> Result<ExpectedInstalledRunStateObjects, ServiceRunStateError> {
        sys::expected_objects_for_test(self.root_identity, self.lock_identity, state_identity)
            .map(ExpectedInstalledRunStateObjects)
    }

    fn with_missing_recorded_lock() -> Result<Self, Box<dyn std::error::Error>> {
        let cleanup_root = unique_test_root()?;
        let mut tree = FixtureTreeGuard::create(cleanup_root.clone())?;
        let base = cleanup_root.join("missing-lock-base");
        fs::create_dir(&base)?;
        create_intermediate_directories(&base)?;
        let (mut setup, root_cleanup) = create_root_for_test_install(&base)?;
        tree.install_root_cleanup(root_cleanup)?;
        create_lock_for_test_install(&base)?;
        create_state_for_test_install(&base)?;
        let lock_identity = sys::record_object_identity_for_test(&lock_path(&base), false)?;
        fs::remove_file(lock_path(&base))?;
        seal_handle_dacl(
            setup.raw()?,
            &sys::exact_sddl_for_test(sys::ROOT_ACCESS_FOR_TEST)?,
            "root",
        )?;
        setup.close_checked()?;
        sys::verify_object_security_for_test(&root_path(&base), true, sys::ROOT_ACCESS_FOR_TEST)?;
        let root_identity = sys::record_object_identity_for_test(&root_path(&base), true)?;
        let state_identity = sys::record_object_identity_for_test(&state_path(&base), true)?;
        Ok(Self {
            tree,
            cleanup_root,
            base,
            root_identity,
            lock_identity,
            state_identity,
        })
    }

    fn cleanup_checked(mut self) -> TestResult {
        self.tree.cleanup_checked()
    }
}

fn unique_test_root() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random)
        .map_err(|_| std::io::Error::other("test randomness unavailable"))?;
    let suffix = u128::from_le_bytes(random);
    Ok(std::env::temp_dir().join(format!("{TEST_ROOT_PREFIX}{suffix:032x}")))
}

fn remove_fixture_tree(cleanup_root: &Path) -> std::io::Result<()> {
    let temp = std::env::temp_dir();
    let safe_leaf = cleanup_root
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with(TEST_ROOT_PREFIX));
    if cleanup_root.parent() != Some(temp.as_path()) || !safe_leaf {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "refused to remove a non-Phase-2E fixture tree",
        ));
    }
    if cleanup_root.try_exists()? {
        fs::remove_dir_all(cleanup_root)?;
    }
    Ok(())
}

fn create_intermediate_directories(base: &Path) -> std::io::Result<()> {
    fs::create_dir(base.join("YourWallet"))?;
    fs::create_dir(base.join("YourWallet").join("KeyAgent"))
}

fn bootstrap_sddl(service_mask: u32) -> Result<String, ServiceRunStateError> {
    let service = sys::current_service_sid_string_for_test()?;
    Ok(format!(
        "O:{service}D:P(A;;0x{service_mask:08x};;;{service})(A;;FA;;;SY)"
    ))
}

fn create_root_for_test_install(
    base: &Path,
) -> Result<(SetupHandle, CleanupHandle), Box<dyn std::error::Error>> {
    let setup_access = sys::ROOT_ACCESS_FOR_TEST
        | FILE_ADD_FILE.0
        | FILE_ADD_SUBDIRECTORY.0
        | FILE_DELETE_CHILD.0
        | WRITE_DAC.0;
    let sddl = bootstrap_sddl(setup_access)?;
    create_directory_with_sddl(&root_path(base), &sddl)?;
    let setup = open_test_handle(&root_path(base), setup_access, true)?;
    let setup = SetupHandle(Some(setup));
    // READ_CONTROL makes the retained authority's exact setup grant explicit;
    // neither access participates in file-data sharing, so this handle remains
    // compatible with the runtime run.lock share-zero exclusion.
    let cleanup = open_test_handle(&root_path(base), READ_CONTROL.0 | WRITE_DAC.0, true)?;
    Ok((setup, CleanupHandle(Some(cleanup))))
}

fn create_lock_for_test_install(base: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let sddl = sys::exact_sddl_for_test(sys::LOCK_ACCESS_FOR_TEST)?;
    create_empty_file_with_sddl(&lock_path(base), &sddl)
}

fn create_state_for_test_install(base: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let sddl = sys::exact_sddl_for_test(sys::STATE_ACCESS_FOR_TEST)?;
    create_directory_with_sddl(&state_path(base), &sddl)
}

fn create_directory_with_sddl(path: &Path, sddl: &str) -> Result<(), Box<dyn std::error::Error>> {
    let descriptor = TestSecurityDescriptor::from_sddl(sddl)?;
    let attributes = descriptor.attributes();
    let wide = wide_path(path)?;
    // SAFETY: path and descriptor remain live and the handle-inherit flag is 0.
    unsafe { CreateDirectoryW(PCWSTR(wide.as_ptr()), Some(ptr::from_ref(&attributes))) }?;
    Ok(())
}

fn create_empty_file_with_sddl(path: &Path, sddl: &str) -> Result<(), Box<dyn std::error::Error>> {
    create_empty_file_with_sddl_and_access(path, sddl, sys::LOCK_ACCESS_FOR_TEST)
}

fn create_empty_file_with_sddl_and_access(
    path: &Path,
    sddl: &str,
    desired_access: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let descriptor = TestSecurityDescriptor::from_sddl(sddl)?;
    let attributes = descriptor.attributes();
    let wide = wide_path(path)?;
    // SAFETY: path and descriptor remain live; CREATE_NEW is test-only and the
    // desired rights exactly match the from-birth service ACE.
    let created = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            desired_access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            Some(ptr::from_ref(&attributes)),
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }?;
    // SAFETY: this creator handle owns only eventual runtime read/control
    // rights and is closed before identity recording or adapter use.
    unsafe { CloseHandle(created) }?;
    Ok(())
}

fn create_record_file_with_sddl(
    path: &Path,
    sddl: &str,
    bytes: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let descriptor = TestSecurityDescriptor::from_sddl(sddl)?;
    let attributes = descriptor.attributes();
    let wide = wide_path(path)?;
    // SAFETY: the exact test path and from-birth descriptor remain live and
    // the creator receives only the file policy's intended access.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            sys::PAIR_FILE_ACCESS_FOR_TEST,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            Some(ptr::from_ref(&attributes)),
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }?;
    let mut setup = SetupHandle(Some(handle));
    if !bytes.is_empty() {
        let mut written = 0_u32;
        // SAFETY: the creator owns FILE_WRITE_DATA and the input remains live.
        unsafe { WriteFile(setup.raw()?, Some(bytes), Some(&raw mut written), None) }?;
        if usize::try_from(written).ok() != Some(bytes.len()) {
            return Err(std::io::Error::other("record fixture write was incomplete").into());
        }
    }
    setup.close_checked()?;
    Ok(())
}

fn create_pair_ads(path: &Path) -> TestResult {
    let mut stream_name = path.as_os_str().to_os_string();
    stream_name.push(":phase2fb_ads:$DATA");
    let stream_path = PathBuf::from(stream_name);
    let wide = wide_path(&stream_path)?;
    // SAFETY: the fixed test-only ADS path is NUL-terminated and the base
    // file's exact DACL grants FILE_WRITE_DATA to the service identity.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_WRITE_DATA.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }?;
    let mut stream = SetupHandle(Some(handle));
    let mut written = 0_u32;
    // SAFETY: the one-byte source remains live and the stream handle is held.
    let write = unsafe { WriteFile(stream.raw()?, Some(&[0x5c]), Some(&raw mut written), None) };
    let close = stream.close_checked();
    write?;
    close?;
    if written == 1 {
        Ok(())
    } else {
        Err(std::io::Error::other("ADS fixture write was incomplete").into())
    }
}

fn mark_pair_file_sparse(path: &Path) -> TestResult {
    let mut handle = SetupHandle(Some(open_test_handle(
        path,
        sys::PAIR_FILE_ACCESS_FOR_TEST,
        false,
    )?));
    let mut returned = 0_u32;
    // SAFETY: the exact pair fixture file remains held for this no-input
    // FSCTL_SET_SPARSE operation and the scalar output is writable.
    let sparse = unsafe {
        DeviceIoControl(
            handle.raw()?,
            FSCTL_SET_SPARSE,
            None,
            0,
            None,
            0,
            Some(&raw mut returned),
            None,
        )
    };
    let close = handle.close_checked();
    sparse?;
    close?;
    Ok(())
}

struct FilePermissionsRestore {
    path: PathBuf,
    original: Option<fs::Permissions>,
}

impl FilePermissionsRestore {
    fn make_readonly(path: &Path) -> TestResultWith<Self> {
        let original = fs::metadata(path)?.permissions();
        let mut readonly = original.clone();
        readonly.set_readonly(true);
        fs::set_permissions(path, readonly)?;
        Ok(Self {
            path: path.to_path_buf(),
            original: Some(original),
        })
    }

    fn restore_checked(mut self) -> TestResult {
        let original = self
            .original
            .take()
            .ok_or_else(|| std::io::Error::other("file permissions already restored"))?;
        fs::set_permissions(&self.path, original)?;
        Ok(())
    }
}

impl Drop for FilePermissionsRestore {
    fn drop(&mut self) {
        if let Some(original) = self.original.take() {
            let _ = fs::set_permissions(&self.path, original);
        }
    }
}

fn open_test_handle(
    path: &Path,
    desired_access: u32,
    directory: bool,
) -> Result<HANDLE, Box<dyn std::error::Error>> {
    let wide = wide_path(path)?;
    let flags = if directory {
        FILE_FLAG_BACKUP_SEMANTICS
    } else {
        FILE_ATTRIBUTE_NORMAL
    };
    // SAFETY: this test-only open targets one exact existing fixture object and
    // omits inheritable security attributes.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            desired_access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            flags,
            None,
        )
    }?;
    Ok(handle)
}

fn create_junction(link: &Path, target: &Path) -> TestResult {
    fs::create_dir(link)?;
    let canonical = fs::canonicalize(target)?;
    let canonical = canonical.as_os_str().encode_wide().collect::<Vec<_>>();
    let extended_prefix = [
        u16::from(b'\\'),
        u16::from(b'\\'),
        u16::from(b'?'),
        u16::from(b'\\'),
    ];
    let print_name = canonical
        .strip_prefix(&extended_prefix)
        .ok_or_else(|| std::io::Error::other("junction target is not an extended local path"))?;
    if print_name.is_empty() || print_name.contains(&0) {
        return Err(std::io::Error::other("junction target is not representable").into());
    }

    let mut substitute_name = vec![
        u16::from(b'\\'),
        u16::from(b'?'),
        u16::from(b'?'),
        u16::from(b'\\'),
    ];
    substitute_name.extend_from_slice(print_name);
    let substitute_bytes = substitute_name
        .len()
        .checked_mul(size_of::<u16>())
        .and_then(|value| u16::try_from(value).ok())
        .ok_or_else(|| std::io::Error::other("junction substitute name is too long"))?;

    let mut path_buffer = substitute_name;
    path_buffer.push(0);
    let print_offset = path_buffer
        .len()
        .checked_mul(size_of::<u16>())
        .and_then(|value| u16::try_from(value).ok())
        .ok_or_else(|| std::io::Error::other("junction print offset is too large"))?;
    let print_bytes = print_name
        .len()
        .checked_mul(size_of::<u16>())
        .and_then(|value| u16::try_from(value).ok())
        .ok_or_else(|| std::io::Error::other("junction print name is too long"))?;
    path_buffer.extend_from_slice(print_name);
    path_buffer.push(0);
    let path_bytes = path_buffer
        .len()
        .checked_mul(size_of::<u16>())
        .ok_or_else(|| std::io::Error::other("junction path buffer overflow"))?;
    let reparse_data_length = 8_usize
        .checked_add(path_bytes)
        .and_then(|value| u16::try_from(value).ok())
        .ok_or_else(|| std::io::Error::other("junction reparse data is too large"))?;
    let total_length = 8_usize
        .checked_add(usize::from(reparse_data_length))
        .ok_or_else(|| std::io::Error::other("junction reparse buffer overflow"))?;
    let mut buffer = vec![0_u8; total_length];
    buffer[0..4].copy_from_slice(&IO_REPARSE_TAG_MOUNT_POINT.to_le_bytes());
    buffer[4..6].copy_from_slice(&reparse_data_length.to_le_bytes());
    buffer[8..10].copy_from_slice(&0_u16.to_le_bytes());
    buffer[10..12].copy_from_slice(&substitute_bytes.to_le_bytes());
    buffer[12..14].copy_from_slice(&print_offset.to_le_bytes());
    buffer[14..16].copy_from_slice(&print_bytes.to_le_bytes());
    for (index, unit) in path_buffer.iter().copied().enumerate() {
        let offset = 16_usize
            .checked_add(index.saturating_mul(size_of::<u16>()))
            .ok_or_else(|| std::io::Error::other("junction buffer offset overflow"))?;
        buffer[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
    }

    let wide = wide_path(link)?;
    // SAFETY: this opens the exact empty test directory itself, not its target,
    // with non-inheritable setup authority used only to install the junction.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            GENERIC_WRITE.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }?;
    let mut setup = SetupHandle(Some(handle));
    let mut returned = 0_u32;
    let input_size = u32::try_from(buffer.len())
        .map_err(|_| std::io::Error::other("junction input is too large"))?;
    // SAFETY: the setup handle names the empty directory itself; `buffer` is a
    // complete mount-point REPARSE_DATA_BUFFER and all outputs are exact.
    unsafe {
        DeviceIoControl(
            setup.raw()?,
            FSCTL_SET_REPARSE_POINT,
            Some(buffer.as_ptr().cast()),
            input_size,
            None,
            0,
            Some(&raw mut returned),
            None,
        )
    }?;
    setup.close_checked()?;
    Ok(())
}

fn seal_handle_dacl(handle: HANDLE, exact_sddl: &str, stage: &str) -> TestResult {
    let descriptor = TestSecurityDescriptor::from_sddl(exact_sddl)?;
    let dacl = descriptor.dacl()?;
    // SAFETY: the setup handle owns WRITE_DAC and the exact descriptor remains
    // live. This test-only seal occurs before identity recording or adapter use.
    let status = unsafe {
        SetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(dacl),
            None,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(std::io::Error::other(format!(
            "test {stage} DACL seal failed with status {}",
            status.0
        ))
        .into());
    }
    Ok(())
}

fn create_nonzero_exact_lock(path: &Path) -> TestResult {
    let bootstrap_mask = sys::LOCK_ACCESS_FOR_TEST | FILE_WRITE_DATA.0 | WRITE_DAC.0;
    let sddl = bootstrap_sddl(bootstrap_mask)?;
    let descriptor = TestSecurityDescriptor::from_sddl(&sddl)?;
    let attributes = descriptor.attributes();
    let wide = wide_path(path)?;
    // SAFETY: test-only CREATE_NEW uses one from-birth bootstrap descriptor;
    // the setup handle is non-inheritable and closed before adapter use.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            bootstrap_mask,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            Some(ptr::from_ref(&attributes)),
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }?;
    let mut setup = SetupHandle(Some(handle));
    let mut written = 0_u32;
    // SAFETY: the setup handle owns FILE_WRITE_DATA and the byte slice lives.
    unsafe { WriteFile(setup.raw()?, Some(&[0x5a]), Some(&raw mut written), None) }?;
    if written != 1 {
        return Err(std::io::Error::other("nonzero fixture write was incomplete").into());
    }
    seal_handle_dacl(
        setup.raw()?,
        &sys::exact_sddl_for_test(sys::LOCK_ACCESS_FOR_TEST)?,
        "nonzero lock",
    )?;
    setup.close_checked()?;
    Ok(())
}

fn create_multilink_exact_lock(path: &Path, second_link: &Path) -> TestResult {
    let sddl = bootstrap_sddl(FILE_ALL_ACCESS.0)?;
    let descriptor = TestSecurityDescriptor::from_sddl(&sddl)?;
    let attributes = descriptor.attributes();
    let wide = wide_path(path)?;
    // SAFETY: this deliberately malformed installer fixture is created with
    // test-only setup authority, non-inheritable, and sealed before adapter use.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_ALL_ACCESS.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            Some(ptr::from_ref(&attributes)),
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }?;
    let mut setup = SetupHandle(Some(handle));
    fs::hard_link(path, second_link)
        .map_err(|error| std::io::Error::new(error.kind(), "multilink fixture creation failed"))?;
    seal_handle_dacl(
        setup.raw()?,
        &sys::exact_sddl_for_test(sys::LOCK_ACCESS_FOR_TEST)?,
        "multilink lock",
    )?;
    setup.close_checked()?;
    Ok(())
}

fn fresh_access_fails_with(
    path: &Path,
    desired_access: u32,
    directory: bool,
    object_role: &'static str,
    access_role: &'static str,
    expected_status: windows::core::HRESULT,
) -> TestResult {
    let wide = wide_path(path)?;
    let flags = if directory {
        FILE_FLAG_BACKUP_SEMANTICS
    } else {
        FILE_ATTRIBUTE_NORMAL
    };
    // SAFETY: this is a fresh non-inheritable existing-object access probe.
    match unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            desired_access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            flags,
            None,
        )
    } {
        Ok(handle) => {
            // SAFETY: an unexpected successful probe still owns one handle.
            unsafe { CloseHandle(handle) }?;
            Err(std::io::Error::other(format!(
                "forbidden fresh {object_role} {access_role} access was granted"
            ))
            .into())
        }
        Err(error) => {
            if error.code() != expected_status {
                return Err(std::io::Error::other(format!(
                    "fresh {object_role} {access_role} access failed with unexpected status {}",
                    error.code().0
                ))
                .into());
            }
            Ok(())
        }
    }
}

fn filesystem_mutation_is_denied(result: std::io::Result<()>, stage: &'static str) -> TestResult {
    match result {
        Ok(()) => Err(std::io::Error::other(format!(
            "held-object {stage} mutation unexpectedly succeeded"
        ))
        .into()),
        Err(error) => {
            let access_denied = i32::try_from(ERROR_ACCESS_DENIED.0).ok();
            let sharing_violation = i32::try_from(ERROR_SHARING_VIOLATION.0).ok();
            if error.raw_os_error() == access_denied || error.raw_os_error() == sharing_violation {
                Ok(())
            } else {
                Err(std::io::Error::other(format!(
                    "held-object {stage} mutation failed with unexpected status"
                ))
                .into())
            }
        }
    }
}

struct RevertImpersonation;

impl RevertImpersonation {
    fn install() -> windows::core::Result<Self> {
        // SAFETY: the returned guard reverts this same test thread on every exit.
        unsafe { ImpersonateSelf(SecurityImpersonation) }?;
        Ok(Self)
    }
}

impl Drop for RevertImpersonation {
    fn drop(&mut self) {
        // SAFETY: this guard owns the current thread's test impersonation state.
        unsafe {
            let _ = RevertToSelf();
        }
    }
}

fn root_path(base: &Path) -> PathBuf {
    base.join("YourWallet").join("KeyAgent").join("v1")
}

fn lock_path(base: &Path) -> PathBuf {
    root_path(base).join("run.lock")
}

fn state_path(base: &Path) -> PathBuf {
    root_path(base).join("state")
}

fn pair_paths(base: &Path) -> [PathBuf; 4] {
    let state = state_path(base);
    sys::pair_leaf_names_for_test().map(|leaf| state.join(leaf))
}

fn wide_path(path: &Path) -> Result<Vec<u16>, std::io::Error> {
    let mut wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if wide.is_empty() || wide.contains(&0) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "test path is not representable",
        ));
    }
    wide.push(0);
    Ok(wide)
}

fn wide_string(value: &str) -> Result<Vec<u16>, std::io::Error> {
    if value.encode_utf16().any(|unit| unit == 0) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "test string is not representable",
        ));
    }
    let mut wide = value.encode_utf16().collect::<Vec<_>>();
    wide.push(0);
    Ok(wide)
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum FixtureConstructionFault {
    Base,
    CleanupAuthority,
    Seal,
}

fn construct_fixture_then_fail(
    cleanup_root: PathBuf,
    fault: FixtureConstructionFault,
) -> TestResult {
    let mut tree = FixtureTreeGuard::create(cleanup_root)?;
    let base = tree.path().join("constructor-fault-base");
    fs::create_dir(&base)?;
    create_intermediate_directories(&base)?;
    if fault == FixtureConstructionFault::Base {
        return Err(std::io::Error::other("injected fixture failure after base").into());
    }

    let (mut setup, root_cleanup) = create_root_for_test_install(&base)?;
    tree.install_root_cleanup(root_cleanup)?;
    if fault == FixtureConstructionFault::CleanupAuthority {
        return Err(
            std::io::Error::other("injected fixture failure after cleanup authority").into(),
        );
    }

    create_lock_for_test_install(&base)?;
    create_state_for_test_install(&base)?;
    seal_handle_dacl(
        setup.raw()?,
        &sys::exact_sddl_for_test(sys::ROOT_ACCESS_FOR_TEST)?,
        "constructor fault root",
    )?;
    setup.close_checked()?;
    debug_assert!(fault == FixtureConstructionFault::Seal);
    Err(std::io::Error::other("injected fixture failure after seal").into())
}

fn signal_child_ready(event_name: &str) -> TestResult {
    let wide = wide_string(event_name)?;
    // SAFETY: the event name is NUL-terminated and the child requests only the
    // signaling right without handle inheritance.
    let event = unsafe { OpenEventW(EVENT_MODIFY_STATE, false, PCWSTR(wide.as_ptr())) }?;
    let mut event = SetupHandle(Some(event));
    // SAFETY: the opened event owns EVENT_MODIFY_STATE.
    unsafe { SetEvent(event.raw()?) }?;
    event.close_checked()?;
    Ok(())
}

fn spawn_synchronized_child(
    fixture: &InstalledFixture,
    event: &NamedTestEvent,
    mode: &'static str,
) -> TestResultWith<ChildProcessGuard> {
    ChildProcessGuard::spawn(mode, &fixture.base, &event.name)
}

fn acquire_for_test(
    root: HeldServiceRunStateRoot,
) -> Result<HeldServiceRunStateWriter, ServiceRunStateError> {
    match root.acquire_run_lock() {
        Ok(writer) => Ok(writer),
        Err(RuntimeRunLockStartFailure::BeforeLock(cause)) => Err(cause),
        Err(RuntimeRunLockStartFailure::WithLock(failure)) => {
            let cause = failure.cause();
            failure.retire().map(|_retired| ()).and(Err(cause))
        }
    }
}

fn expect_before_lock_contention(root: HeldServiceRunStateRoot) -> TestResult {
    match root.acquire_run_lock() {
        Err(RuntimeRunLockStartFailure::BeforeLock(ServiceRunStateError::Contended)) => Ok(()),
        Err(RuntimeRunLockStartFailure::BeforeLock(cause)) => Err(cause.into()),
        Err(RuntimeRunLockStartFailure::WithLock(failure)) => {
            let cause = failure.cause();
            let _retired = failure.retire()?;
            Err(cause.into())
        }
        Ok(writer) => {
            release_for_test(writer)?;
            Err(std::io::Error::other("contended run.lock was acquired").into())
        }
    }
}

fn expect_root_reparse_rejected(
    base: &Path,
    expected: ExpectedInstalledRunStateObjects,
) -> TestResult {
    match open_test_service_run_state_root(base, expected) {
        Err(ServiceRunStateError::Reparse) => Ok(()),
        Err(cause) => Err(cause.into()),
        Ok(root) => {
            if let Ok(writer) = acquire_for_test(root) {
                release_for_test(writer)?;
            }
            Err(std::io::Error::other("reparse-backed root path was accepted").into())
        }
    }
}

fn expect_lock_reparse_rejected(root: HeldServiceRunStateRoot) -> TestResult {
    match root.acquire_run_lock() {
        Err(RuntimeRunLockStartFailure::BeforeLock(ServiceRunStateError::Reparse)) => Ok(()),
        Err(RuntimeRunLockStartFailure::BeforeLock(cause)) => Err(cause.into()),
        Err(RuntimeRunLockStartFailure::WithLock(failure)) => {
            let cause = failure.cause();
            let _retired = failure.retire()?;
            if cause == ServiceRunStateError::Reparse {
                Ok(())
            } else {
                Err(cause.into())
            }
        }
        Ok(writer) => {
            release_for_test(writer)?;
            Err(std::io::Error::other("reparse-backed run.lock was accepted").into())
        }
    }
}

fn release_for_test(writer: HeldServiceRunStateWriter) -> Result<(), ServiceRunStateError> {
    match writer.release() {
        Ok(_released) => Ok(()),
        Err(failure) => {
            let cause = failure.cause();
            failure.retire().map(|_retired| ()).and(Err(cause))
        }
    }
}

#[allow(clippy::large_types_passed_by_value)] // Mirrors the consuming production facade.
fn commit_pair_for_test(
    observed: ObservedFixedRunStatePair,
    candidate: ExactFixedRunStatePair,
) -> TestResultWith<FixedPairCommitted> {
    match observed.compare_and_replace(candidate) {
        FixedPairCommitOutcome::Committed(committed) => Ok(committed),
        FixedPairCommitOutcome::KnownNotCommitted(failure) => {
            let cause = failure.cause();
            let _retired = failure.retire()?;
            Err(cause.into())
        }
        FixedPairCommitOutcome::Ambiguous(failure) => {
            let cause = failure.cause();
            let _retired = failure.retire()?;
            Err(cause.into())
        }
    }
}

fn reacquire_after_confirmed_exit_before_deadline(
    fixture: &InstalledFixture,
) -> Result<HeldServiceRunStateWriter, ServiceRunStateError> {
    let deadline = Instant::now() + LOCK_REACQUIRE_TIMEOUT;
    loop {
        let root = open_test_service_run_state_root(&fixture.base, fixture.expected()?)?;
        match root.acquire_run_lock() {
            Ok(writer) => return Ok(writer),
            Err(RuntimeRunLockStartFailure::BeforeLock(ServiceRunStateError::Contended)) => {}
            Err(RuntimeRunLockStartFailure::BeforeLock(cause)) => return Err(cause),
            Err(RuntimeRunLockStartFailure::WithLock(failure)) => {
                let cause = failure.cause();
                let _retired = failure.retire()?;
                if cause != ServiceRunStateError::Contended {
                    return Err(cause);
                }
            }
        }
        if Instant::now() >= deadline {
            return Err(ServiceRunStateError::Contended);
        }
        std::thread::sleep(PROCESS_POLL_INTERVAL);
    }
}

#[test]
fn exact_policy_sddl_is_accepted_by_the_production_parser() -> TestResult {
    for mask in [
        sys::ROOT_ACCESS_FOR_TEST,
        sys::LOCK_ACCESS_FOR_TEST,
        sys::STATE_ACCESS_FOR_TEST,
    ] {
        let sddl = sys::exact_sddl_for_test(mask)?;
        assert_eq!(sys::verify_sddl_for_test(&sddl, mask), Ok(()));
    }
    Ok(())
}

#[test]
fn fixed_leaves_accept_only_single_components_and_reject_ads() {
    for leaf in ["YourWallet", "KeyAgent", "v1", "run.lock", "state"] {
        assert_eq!(sys::validate_leaf_for_test(leaf), Ok(()));
    }
    for leaf in ["", ".", "..", "run.lock:stream", "a/b", "a\\b", "a\0b"] {
        assert_eq!(
            sys::validate_leaf_for_test(leaf),
            Err(ServiceRunStateError::Location)
        );
    }
    assert_eq!(
        sys::validate_test_location_for_test(Path::new(r"C:\base:stream\child")),
        Err(ServiceRunStateError::Location)
    );
}

#[test]
fn fixture_drop_removes_its_exact_temp_tree() -> TestResult {
    let cleanup_root = {
        let fixture = InstalledFixture::new()?;
        fixture.cleanup_root.clone()
    };
    assert!(
        !cleanup_root.exists(),
        "fixture Drop left its exact Phase 2E temp tree behind"
    );
    Ok(())
}

#[test]
fn fixture_checked_cleanup_surfaces_teardown_and_removes_tree() -> TestResult {
    let fixture = InstalledFixture::new()?;
    let cleanup_root = fixture.cleanup_root.clone();
    fixture.cleanup_checked()?;
    assert!(
        !cleanup_root.exists(),
        "checked fixture cleanup left its exact Phase 2E temp tree behind"
    );
    Ok(())
}

#[test]
fn fixture_constructor_failures_remove_their_exact_temp_trees() -> TestResult {
    for fault in [
        FixtureConstructionFault::Base,
        FixtureConstructionFault::CleanupAuthority,
        FixtureConstructionFault::Seal,
    ] {
        let cleanup_root = unique_test_root()?;
        assert!(construct_fixture_then_fail(cleanup_root.clone(), fault).is_err());
        assert!(
            !cleanup_root.exists(),
            "fixture constructor failure left its exact temp tree behind"
        );
    }
    Ok(())
}

#[test]
fn exact_positive_acquire_revalidate_release_and_reacquire_preserves_ids() -> TestResult {
    let fixture = InstalledFixture::new()?;
    let before = fixture.identities();
    let root = open_test_service_run_state_root(&fixture.base, fixture.expected()?)?;
    root.revalidate()?;
    let writer = acquire_for_test(root)?;
    writer.revalidate()?;
    release_for_test(writer)?;

    let after = (
        sys::record_object_identity_for_test(&root_path(&fixture.base), true)?,
        sys::record_object_identity_for_test(&lock_path(&fixture.base), false)?,
        sys::record_object_identity_for_test(&state_path(&fixture.base), true)?,
    );
    assert_eq!(before, after);

    let root = open_test_service_run_state_root(&fixture.base, fixture.expected()?)?;
    let writer = acquire_for_test(root)?;
    release_for_test(writer)?;
    assert_eq!(
        sys::record_object_identity_for_test(&lock_path(&fixture.base), false)?,
        before.1
    );
    Ok(())
}

#[test]
fn fixed_pair_absent_commit_flushes_renames_and_independently_rereads() -> TestResult {
    let fixture = InstalledFixture::new()?;
    let paths = pair_paths(&fixture.base);
    assert!(paths.iter().all(|path| !path.exists()));

    let root = open_test_service_run_state_root(&fixture.base, fixture.expected()?)?;
    let writer = acquire_for_test(root)?;
    let observed = writer.observe_fixed_pair().map_err(|failure| {
        let cause = failure.cause();
        let _ = failure.retire();
        std::io::Error::other(format!("observe absent pair failed: {cause:?}"))
    })?;
    assert_eq!(
        observed.observation().marker(),
        FixedRunStateRecordObservation::Missing
    );
    assert_eq!(
        observed.observation().checkpoint(),
        FixedRunStateRecordObservation::Missing
    );

    let candidate = ExactFixedRunStatePair::new(
        [0x31; FIXED_RUN_STATE_RECORD_BYTES],
        [0x42; FIXED_RUN_STATE_RECORD_BYTES],
    );
    let committed = commit_pair_for_test(observed, candidate)
        .map_err(|error| std::io::Error::other(format!("commit absent pair failed: {error:?}")))?;
    assert_eq!(committed.candidate(), candidate);
    let reread = match committed.reread() {
        Ok(reread) => reread,
        Err(failure) => {
            let cause = failure.cause();
            let _retired = failure.retire()?;
            return Err(cause.into());
        }
    };
    assert_eq!(
        reread.observation().marker(),
        FixedRunStateRecordObservation::Exact(*candidate.marker())
    );
    assert_eq!(
        reread.observation().checkpoint(),
        FixedRunStateRecordObservation::Exact(*candidate.checkpoint())
    );
    release_for_test(reread.into_writer())?;

    assert_eq!(fs::read(&paths[0])?, candidate.marker());
    assert!(!paths[1].exists());
    assert_eq!(fs::read(&paths[2])?, candidate.checkpoint());
    assert!(!paths[3].exists());
    fixture.cleanup_checked()
}

#[test]
fn fixed_pair_existing_commit_replaces_both_full_identities() -> TestResult {
    let fixture = InstalledFixture::new()?;
    let paths = pair_paths(&fixture.base);
    let root = open_test_service_run_state_root(&fixture.base, fixture.expected()?)?;
    let writer = acquire_for_test(root)?;
    let first_observed = writer.observe_fixed_pair().map_err(|failure| {
        let cause = failure.cause();
        let _ = failure.retire();
        cause
    })?;
    let first = ExactFixedRunStatePair::new(
        [0x53; FIXED_RUN_STATE_RECORD_BYTES],
        [0x64; FIXED_RUN_STATE_RECORD_BYTES],
    );
    let first_reread = match commit_pair_for_test(first_observed, first)?.reread() {
        Ok(reread) => reread,
        Err(failure) => {
            let cause = failure.cause();
            let _retired = failure.retire()?;
            return Err(cause.into());
        }
    };
    let writer = first_reread.into_writer();
    let old_marker = sys::record_object_identity_for_test(&paths[0], false)?;
    let old_checkpoint = sys::record_object_identity_for_test(&paths[2], false)?;

    let second_observed = writer.observe_fixed_pair().map_err(|failure| {
        let cause = failure.cause();
        let _ = failure.retire();
        cause
    })?;
    assert_eq!(
        second_observed.observation().marker(),
        FixedRunStateRecordObservation::Exact(*first.marker())
    );
    assert_eq!(
        second_observed.observation().checkpoint(),
        FixedRunStateRecordObservation::Exact(*first.checkpoint())
    );
    let second = ExactFixedRunStatePair::new(
        [0x75; FIXED_RUN_STATE_RECORD_BYTES],
        [0x86; FIXED_RUN_STATE_RECORD_BYTES],
    );
    let second_reread = match commit_pair_for_test(second_observed, second)?.reread() {
        Ok(reread) => reread,
        Err(failure) => {
            let cause = failure.cause();
            let _retired = failure.retire()?;
            return Err(cause.into());
        }
    };
    assert_eq!(
        second_reread.observation().marker(),
        FixedRunStateRecordObservation::Exact(*second.marker())
    );
    assert_eq!(
        second_reread.observation().checkpoint(),
        FixedRunStateRecordObservation::Exact(*second.checkpoint())
    );
    release_for_test(second_reread.into_writer())?;

    let new_marker = sys::record_object_identity_for_test(&paths[0], false)?;
    let new_checkpoint = sys::record_object_identity_for_test(&paths[2], false)?;
    assert_ne!(new_marker, old_marker);
    assert_ne!(new_checkpoint, old_checkpoint);
    assert_eq!(fs::read(&paths[0])?, second.marker());
    assert_eq!(fs::read(&paths[2])?, second.checkpoint());
    assert!(!paths[1].exists() && !paths[3].exists());
    fixture.cleanup_checked()
}

#[test]
fn fixed_pair_leaf_set_and_from_birth_file_security_are_exact() -> TestResult {
    let leaves = sys::pair_leaf_names_for_test();
    assert_eq!(FIXED_RUN_STATE_RECORD_BYTES, 148);
    for (index, leaf) in leaves.iter().enumerate() {
        sys::validate_leaf_for_test(leaf)?;
        assert!(!leaf.contains(['/', '\\', ':']));
        let (base, extension) = leaf
            .split_once('.')
            .ok_or_else(|| std::io::Error::other("fixed pair leaf lacks one extension"))?;
        assert!(base.len() <= 8 && extension.len() <= 3);
        for other in leaves.iter().skip(index + 1) {
            assert_ne!(leaf, other);
        }
    }

    let fixture = InstalledFixture::new()?;
    let paths = pair_paths(&fixture.base);
    let root = open_test_service_run_state_root(&fixture.base, fixture.expected()?)?;
    let writer = acquire_for_test(root)?;
    let observed = writer.observe_fixed_pair().map_err(|failure| {
        let cause = failure.cause();
        let _ = failure.retire();
        cause
    })?;
    let candidate = ExactFixedRunStatePair::new(
        [0x97; FIXED_RUN_STATE_RECORD_BYTES],
        [0xa8; FIXED_RUN_STATE_RECORD_BYTES],
    );
    let reread = match commit_pair_for_test(observed, candidate)?.reread() {
        Ok(reread) => reread,
        Err(failure) => {
            let cause = failure.cause();
            let _retired = failure.retire()?;
            return Err(cause.into());
        }
    };
    release_for_test(reread.into_writer())?;

    for path in [&paths[0], &paths[2]] {
        sys::verify_pair_file_security_for_test(path)?;
        let mut exact = SetupHandle(Some(open_test_handle(
            path,
            sys::PAIR_FILE_ACCESS_FOR_TEST,
            false,
        )?));
        exact.close_checked()?;
        let mut delete = SetupHandle(Some(open_test_handle(path, DELETE.0, false)?));
        delete.close_checked()?;
        fresh_access_fails_with(
            path,
            WRITE_DAC.0,
            false,
            "fixed pair file",
            "WRITE_DAC",
            ERROR_ACCESS_DENIED.to_hresult(),
        )?;
        fresh_access_fails_with(
            path,
            WRITE_OWNER.0,
            false,
            "fixed pair file",
            "WRITE_OWNER",
            ERROR_ACCESS_DENIED.to_hresult(),
        )?;
    }
    assert_ne!(
        sys::PAIR_OWNER_RIGHTS_DENY_FOR_TEST,
        sys::OWNER_RIGHTS_DENY_FOR_TEST
    );
    assert_eq!(sys::PAIR_CREATE_DESIRED_ACCESS_FOR_TEST, 0xc011_0000);
    assert_eq!(sys::PAIR_FILE_ACCESS_FOR_TEST, 0x0013_019f);
    assert_eq!(sys::PAIR_FINAL_OPEN_DESIRED_ACCESS_FOR_TEST, 0x8010_0000);
    assert_eq!(sys::PAIR_FINAL_GRANTED_ACCESS_FOR_TEST, 0x0012_0089);
    assert_eq!(sys::PAIR_TEMP_CLEANUP_DESIRED_ACCESS_FOR_TEST, 0x8011_0000);
    assert_eq!(sys::PAIR_TEMP_CLEANUP_GRANTED_ACCESS_FOR_TEST, 0x0013_0089);
    let expected_sddl = sys::exact_pair_file_sddl_for_test()?;
    assert!(expected_sddl.contains("D;;0x000c0000;;;OW"));
    fixture.cleanup_checked()
}

#[test]
fn fixed_pair_one_sided_malformed_and_hostile_temp_are_terminal_known_failures() -> TestResult {
    let candidate = ExactFixedRunStatePair::new(
        [0xb1; FIXED_RUN_STATE_RECORD_BYTES],
        [0xb2; FIXED_RUN_STATE_RECORD_BYTES],
    );

    let one_sided = InstalledFixture::new()?;
    let paths = pair_paths(&one_sided.base);
    create_record_file_with_sddl(
        &paths[0],
        &sys::exact_pair_file_sddl_for_test()?,
        &[0xc1; FIXED_RUN_STATE_RECORD_BYTES],
    )?;
    let writer = acquire_for_test(open_test_service_run_state_root(
        &one_sided.base,
        one_sided.expected()?,
    )?)?;
    let observed = writer.observe_fixed_pair().map_err(|failure| {
        let cause = failure.cause();
        let _ = failure.retire();
        cause
    })?;
    assert!(matches!(
        observed.observation().marker(),
        FixedRunStateRecordObservation::Exact(_)
    ));
    assert_eq!(
        observed.observation().checkpoint(),
        FixedRunStateRecordObservation::Missing
    );
    match observed.compare_and_replace(candidate) {
        FixedPairCommitOutcome::KnownNotCommitted(failure) => {
            assert_eq!(failure.cause(), ServiceRunStateError::Compare);
            let _retired = failure.retire()?;
        }
        other => {
            return Err(
                std::io::Error::other(format!("unexpected one-sided outcome: {other:?}")).into(),
            );
        }
    }
    assert!(!paths[1].exists() && !paths[2].exists() && !paths[3].exists());
    one_sided.cleanup_checked()?;

    let malformed = InstalledFixture::new()?;
    let paths = pair_paths(&malformed.base);
    let sddl = sys::exact_pair_file_sddl_for_test()?;
    create_record_file_with_sddl(&paths[0], &sddl, &[0xd1; FIXED_RUN_STATE_RECORD_BYTES - 1])?;
    create_record_file_with_sddl(&paths[2], &sddl, &[0xd2; FIXED_RUN_STATE_RECORD_BYTES])?;
    let writer = acquire_for_test(open_test_service_run_state_root(
        &malformed.base,
        malformed.expected()?,
    )?)?;
    let observed = writer.observe_fixed_pair().map_err(|failure| {
        let cause = failure.cause();
        let _ = failure.retire();
        cause
    })?;
    assert_eq!(
        observed.observation().marker(),
        FixedRunStateRecordObservation::Malformed
    );
    match observed.compare_and_replace(candidate) {
        FixedPairCommitOutcome::KnownNotCommitted(failure) => {
            assert_eq!(failure.cause(), ServiceRunStateError::Compare);
            let _retired = failure.retire()?;
        }
        other => {
            return Err(
                std::io::Error::other(format!("unexpected malformed outcome: {other:?}")).into(),
            );
        }
    }
    assert!(!paths[1].exists() && !paths[3].exists());
    malformed.cleanup_checked()?;

    let hostile = InstalledFixture::new()?;
    let paths = pair_paths(&hostile.base);
    create_record_file_with_sddl(
        &paths[1],
        &bootstrap_sddl(sys::PAIR_FILE_ACCESS_FOR_TEST)?,
        &[0xe1; FIXED_RUN_STATE_RECORD_BYTES],
    )?;
    let writer = acquire_for_test(open_test_service_run_state_root(
        &hostile.base,
        hostile.expected()?,
    )?)?;
    let failure = match writer.observe_fixed_pair() {
        Err(failure) => failure,
        Ok(observed) => {
            observed.retire()?;
            return Err(std::io::Error::other("hostile temp was adopted or deleted").into());
        }
    };
    assert_eq!(failure.cause(), ServiceRunStateError::Security);
    assert!(matches!(
        failure.retire(),
        Err(ServiceRunStateError::Release)
    ));
    assert!(paths[1].exists(), "hostile temp was silently deleted");
    hostile.cleanup_checked()
}

#[test]
fn fixed_pair_rejects_ads_and_forbidden_file_attributes() -> TestResult {
    fn install_pair(fixture: &InstalledFixture) -> TestResult {
        let paths = pair_paths(&fixture.base);
        let sddl = sys::exact_pair_file_sddl_for_test()?;
        create_record_file_with_sddl(&paths[0], &sddl, &[0xc4; FIXED_RUN_STATE_RECORD_BYTES])?;
        create_record_file_with_sddl(&paths[2], &sddl, &[0xd5; FIXED_RUN_STATE_RECORD_BYTES])
    }

    fn require_shape_failure(fixture: &InstalledFixture) -> TestResult {
        let writer = acquire_for_test(open_test_service_run_state_root(
            &fixture.base,
            fixture.expected()?,
        )?)?;
        let failure = match writer.observe_fixed_pair() {
            Err(failure) => failure,
            Ok(observed) => {
                observed.retire()?;
                return Err(std::io::Error::other("hostile pair shape was accepted").into());
            }
        };
        assert_eq!(failure.cause(), ServiceRunStateError::Shape);
        let _retired = failure.retire()?;
        Ok(())
    }

    let ads = InstalledFixture::new()?;
    install_pair(&ads)?;
    let paths = pair_paths(&ads.base);
    create_pair_ads(&paths[0])?;
    require_shape_failure(&ads)?;
    ads.cleanup_checked()?;

    let readonly = InstalledFixture::new()?;
    install_pair(&readonly)?;
    let paths = pair_paths(&readonly.base);
    let restore = FilePermissionsRestore::make_readonly(&paths[0])?;
    require_shape_failure(&readonly)?;
    restore.restore_checked()?;
    readonly.cleanup_checked()?;

    let sparse = InstalledFixture::new()?;
    install_pair(&sparse)?;
    let paths = pair_paths(&sparse.base);
    mark_pair_file_sparse(&paths[0])?;
    require_shape_failure(&sparse)?;
    sparse.cleanup_checked()
}

#[test]
fn fixed_pair_startup_cleans_safe_partial_temps_but_preserves_oversized() -> TestResult {
    let partial = InstalledFixture::new()?;
    let paths = pair_paths(&partial.base);
    let sddl = sys::exact_pair_file_sddl_for_test()?;
    create_record_file_with_sddl(&paths[1], &sddl, &[])?;
    create_record_file_with_sddl(&paths[3], &sddl, &[0x47; FIXED_RUN_STATE_RECORD_BYTES - 1])?;
    let writer = acquire_for_test(open_test_service_run_state_root(
        &partial.base,
        partial.expected()?,
    )?)?;
    let observed = writer.observe_fixed_pair().map_err(|failure| {
        let cause = failure.cause();
        let _ = failure.retire();
        cause
    })?;
    assert_eq!(
        observed.observation(),
        super::FixedRunStatePairObservation::new(
            FixedRunStateRecordObservation::Missing,
            FixedRunStateRecordObservation::Missing,
        )
    );
    assert!(!paths[1].exists() && !paths[3].exists());
    let _retired = observed.retire()?;
    partial.cleanup_checked()?;

    let oversized = InstalledFixture::new()?;
    let paths = pair_paths(&oversized.base);
    create_record_file_with_sddl(
        &paths[1],
        &sys::exact_pair_file_sddl_for_test()?,
        &[0x58; FIXED_RUN_STATE_RECORD_BYTES + 1],
    )?;
    let writer = acquire_for_test(open_test_service_run_state_root(
        &oversized.base,
        oversized.expected()?,
    )?)?;
    let failure = match writer.observe_fixed_pair() {
        Err(failure) => failure,
        Ok(observed) => {
            observed.retire()?;
            return Err(std::io::Error::other("oversized stale temp was deleted").into());
        }
    };
    assert_eq!(failure.cause(), ServiceRunStateError::Shape);
    assert!(matches!(
        failure.retire(),
        Err(ServiceRunStateError::Release)
    ));
    assert!(paths[1].exists());
    oversized.cleanup_checked()
}

#[test]
fn fixed_pair_full_id_second_cas_rejects_same_bytes_replacement_without_mutation() -> TestResult {
    let fixture = InstalledFixture::new()?;
    let paths = pair_paths(&fixture.base);
    let root = open_test_service_run_state_root(&fixture.base, fixture.expected()?)?;
    let writer = acquire_for_test(root)?;
    let observed = writer.observe_fixed_pair().map_err(|failure| {
        let cause = failure.cause();
        let _ = failure.retire();
        cause
    })?;
    let prior = ExactFixedRunStatePair::new(
        [0x19; FIXED_RUN_STATE_RECORD_BYTES],
        [0x2a; FIXED_RUN_STATE_RECORD_BYTES],
    );
    let reread = match commit_pair_for_test(observed, prior)?.reread() {
        Ok(reread) => reread,
        Err(failure) => {
            let cause = failure.cause();
            let _retired = failure.retire()?;
            return Err(cause.into());
        }
    };
    let writer = reread.into_writer();
    let original_marker = sys::record_object_identity_for_test(&paths[0], false)?;
    let observed = writer.observe_fixed_pair().map_err(|failure| {
        let cause = failure.cause();
        let _ = failure.retire();
        cause
    })?;

    let replacement_path = paths[0].clone();
    let replacement_sddl = sys::exact_pair_file_sddl_for_test()?;
    let prior_marker = *prior.marker();
    sys::inject_pair_before_second_cas_for_test(move || {
        assert!(
            fs::remove_file(&replacement_path).is_ok(),
            "replace marker after staging"
        );
        assert!(
            create_record_file_with_sddl(&replacement_path, &replacement_sddl, &prior_marker)
                .is_ok(),
            "create same-byte marker replacement after staging"
        );
    });

    let candidate = ExactFixedRunStatePair::new(
        [0x3b; FIXED_RUN_STATE_RECORD_BYTES],
        [0x4c; FIXED_RUN_STATE_RECORD_BYTES],
    );
    match observed.compare_and_replace(candidate) {
        FixedPairCommitOutcome::KnownNotCommitted(failure) => {
            assert_eq!(failure.cause(), ServiceRunStateError::Compare);
            let _retired = failure.retire()?;
        }
        other => {
            return Err(
                std::io::Error::other(format!("unexpected second-CAS outcome: {other:?}")).into(),
            );
        }
    }
    let substituted_marker = sys::record_object_identity_for_test(&paths[0], false)?;
    assert_ne!(substituted_marker, original_marker);
    assert_eq!(
        sys::record_object_identity_for_test(&paths[0], false)?,
        substituted_marker
    );
    assert_eq!(fs::read(&paths[0])?, prior.marker());
    assert_eq!(fs::read(&paths[2])?, prior.checkpoint());
    assert!(!paths[1].exists() && !paths[3].exists());
    fixture.cleanup_checked()
}

#[test]
#[allow(clippy::too_many_lines)] // One test fixes the exact before/after rename boundary matrix.
fn fixed_pair_first_rename_boundary_reload_and_close_poison_are_exact() -> TestResult {
    let candidate = ExactFixedRunStatePair::new(
        [0x5d; FIXED_RUN_STATE_RECORD_BYTES],
        [0x6e; FIXED_RUN_STATE_RECORD_BYTES],
    );

    let before = InstalledFixture::new()?;
    let paths = pair_paths(&before.base);
    let writer = acquire_for_test(open_test_service_run_state_root(
        &before.base,
        before.expected()?,
    )?)?;
    let observed = writer.observe_fixed_pair().map_err(|failure| {
        let cause = failure.cause();
        let _ = failure.retire();
        cause
    })?;
    sys::reset_pair_rename_count_for_test();
    sys::inject_pair_impersonation_fault_for_test(sys::TestPairImpersonationFault::BeforeMarker);
    match observed.compare_and_replace(candidate) {
        FixedPairCommitOutcome::KnownNotCommitted(failure) => {
            assert_eq!(failure.cause(), ServiceRunStateError::Impersonation);
            assert_eq!(sys::pair_rename_count_for_test(), 0);
            let _retired = failure.retire()?;
        }
        other => {
            return Err(
                std::io::Error::other(format!("unexpected pre-rename outcome: {other:?}")).into(),
            );
        }
    }
    assert!(paths.iter().all(|path| !path.exists()));
    before.cleanup_checked()?;

    let marker_partial = InstalledFixture::new()?;
    let paths = pair_paths(&marker_partial.base);
    let writer = acquire_for_test(open_test_service_run_state_root(
        &marker_partial.base,
        marker_partial.expected()?,
    )?)?;
    let observed = writer.observe_fixed_pair().map_err(|failure| {
        let cause = failure.cause();
        let _ = failure.retire();
        cause
    })?;
    sys::reset_pair_rename_count_for_test();
    sys::inject_pair_impersonation_fault_for_test(sys::TestPairImpersonationFault::AfterMarker);
    let ambiguous = match observed.compare_and_replace(candidate) {
        FixedPairCommitOutcome::Ambiguous(failure) => failure,
        other => {
            return Err(std::io::Error::other(format!(
                "unexpected marker ambiguity outcome: {other:?}"
            ))
            .into());
        }
    };
    assert_eq!(ambiguous.cause(), ServiceRunStateError::Impersonation);
    assert_eq!(sys::pair_rename_count_for_test(), 1);
    let reloaded = ambiguous.reload().map_err(|failure| {
        let cause = failure.cause();
        let _ = failure.retire();
        cause
    })?;
    assert_eq!(
        reloaded.observation().marker(),
        FixedRunStateRecordObservation::Exact(*candidate.marker())
    );
    assert_eq!(
        reloaded.observation().checkpoint(),
        FixedRunStateRecordObservation::Missing
    );
    let _retired = reloaded.retire()?;
    assert!(paths[0].exists() && !paths[1].exists() && !paths[2].exists() && !paths[3].exists());
    marker_partial.cleanup_checked()?;

    let before_checkpoint = InstalledFixture::new()?;
    let paths = pair_paths(&before_checkpoint.base);
    let writer = acquire_for_test(open_test_service_run_state_root(
        &before_checkpoint.base,
        before_checkpoint.expected()?,
    )?)?;
    let observed = writer.observe_fixed_pair().map_err(|failure| {
        let cause = failure.cause();
        let _ = failure.retire();
        cause
    })?;
    sys::reset_pair_rename_count_for_test();
    sys::inject_pair_impersonation_fault_for_test(
        sys::TestPairImpersonationFault::BeforeCheckpoint,
    );
    let ambiguous = match observed.compare_and_replace(candidate) {
        FixedPairCommitOutcome::Ambiguous(failure) => failure,
        other => {
            return Err(std::io::Error::other(format!(
                "unexpected pre-checkpoint-rename outcome: {other:?}"
            ))
            .into());
        }
    };
    assert_eq!(ambiguous.cause(), ServiceRunStateError::Impersonation);
    assert_eq!(sys::pair_rename_count_for_test(), 1);
    let reloaded = ambiguous.reload().map_err(|failure| {
        let cause = failure.cause();
        let _ = failure.retire();
        cause
    })?;
    assert_eq!(
        reloaded.observation().marker(),
        FixedRunStateRecordObservation::Exact(*candidate.marker())
    );
    assert_eq!(
        reloaded.observation().checkpoint(),
        FixedRunStateRecordObservation::Missing
    );
    let _retired = reloaded.retire()?;
    assert!(paths[0].exists() && !paths[1].exists() && !paths[2].exists() && !paths[3].exists());
    before_checkpoint.cleanup_checked()?;

    let full = InstalledFixture::new()?;
    let paths = pair_paths(&full.base);
    let writer = acquire_for_test(open_test_service_run_state_root(
        &full.base,
        full.expected()?,
    )?)?;
    let observed = writer.observe_fixed_pair().map_err(|failure| {
        let cause = failure.cause();
        let _ = failure.retire();
        cause
    })?;
    sys::reset_pair_rename_count_for_test();
    sys::inject_pair_impersonation_fault_for_test(sys::TestPairImpersonationFault::AfterCheckpoint);
    let ambiguous = match observed.compare_and_replace(candidate) {
        FixedPairCommitOutcome::Ambiguous(failure) => failure,
        other => {
            return Err(std::io::Error::other(format!(
                "unexpected checkpoint ambiguity outcome: {other:?}"
            ))
            .into());
        }
    };
    assert_eq!(ambiguous.cause(), ServiceRunStateError::Impersonation);
    assert_eq!(sys::pair_rename_count_for_test(), 2);
    let reloaded = ambiguous.reload().map_err(|failure| {
        let cause = failure.cause();
        let _ = failure.retire();
        cause
    })?;
    assert_eq!(
        reloaded.observation().marker(),
        FixedRunStateRecordObservation::Exact(*candidate.marker())
    );
    assert_eq!(
        reloaded.observation().checkpoint(),
        FixedRunStateRecordObservation::Exact(*candidate.checkpoint())
    );
    let _retired = reloaded.retire()?;
    assert!(paths[0].exists() && paths[2].exists() && !paths[1].exists() && !paths[3].exists());
    full.cleanup_checked()?;

    let close_poison = InstalledFixture::new()?;
    let writer = acquire_for_test(open_test_service_run_state_root(
        &close_poison.base,
        close_poison.expected()?,
    )?)?;
    let observed = writer.observe_fixed_pair().map_err(|failure| {
        let cause = failure.cause();
        let _ = failure.retire();
        cause
    })?;
    sys::inject_close_fault_for_test(sys::TestCloseFault::PairMarkerTemp);
    let ambiguous = match observed.compare_and_replace(candidate) {
        FixedPairCommitOutcome::Ambiguous(failure) => failure,
        other => {
            return Err(
                std::io::Error::other(format!("unexpected pair-close outcome: {other:?}")).into(),
            );
        }
    };
    assert_eq!(ambiguous.cause(), ServiceRunStateError::Release);
    assert!(matches!(
        ambiguous.retire(),
        Err(ServiceRunStateError::Release)
    ));
    close_poison.cleanup_checked()
}

#[test]
fn fixed_pair_inspection_has_individual_impersonation_bookends_and_close_poison() -> TestResult {
    fn install_exact_pair(fixture: &InstalledFixture) -> TestResult {
        let paths = pair_paths(&fixture.base);
        let sddl = sys::exact_pair_file_sddl_for_test()?;
        create_record_file_with_sddl(&paths[0], &sddl, &[0x7f; FIXED_RUN_STATE_RECORD_BYTES])?;
        create_record_file_with_sddl(&paths[2], &sddl, &[0x8f; FIXED_RUN_STATE_RECORD_BYTES])
    }

    let before = InstalledFixture::new()?;
    install_exact_pair(&before)?;
    let writer = acquire_for_test(open_test_service_run_state_root(
        &before.base,
        before.expected()?,
    )?)?;
    sys::reset_pair_inspect_count_for_test();
    sys::inject_pair_impersonation_fault_for_test(sys::TestPairImpersonationFault::BeforeInspect);
    let failure = match writer.observe_fixed_pair() {
        Err(failure) => failure,
        Ok(observed) => {
            observed.retire()?;
            return Err(std::io::Error::other("pre-inspect impersonation was accepted").into());
        }
    };
    assert_eq!(failure.cause(), ServiceRunStateError::Impersonation);
    assert_eq!(sys::pair_inspect_count_for_test(), 0);
    let _retired = failure.retire()?;
    before.cleanup_checked()?;

    let after = InstalledFixture::new()?;
    install_exact_pair(&after)?;
    let writer = acquire_for_test(open_test_service_run_state_root(
        &after.base,
        after.expected()?,
    )?)?;
    sys::reset_pair_inspect_count_for_test();
    sys::inject_pair_impersonation_fault_for_test(sys::TestPairImpersonationFault::AfterInspect);
    let failure = match writer.observe_fixed_pair() {
        Err(failure) => failure,
        Ok(observed) => {
            observed.retire()?;
            return Err(std::io::Error::other("post-inspect impersonation was accepted").into());
        }
    };
    assert_eq!(failure.cause(), ServiceRunStateError::Impersonation);
    assert_eq!(sys::pair_inspect_count_for_test(), 1);
    let _retired = failure.retire()?;
    after.cleanup_checked()?;

    let close_poison = InstalledFixture::new()?;
    install_exact_pair(&close_poison)?;
    let writer = acquire_for_test(open_test_service_run_state_root(
        &close_poison.base,
        close_poison.expected()?,
    )?)?;
    sys::reset_pair_inspect_count_for_test();
    sys::inject_pair_impersonation_fault_for_test(sys::TestPairImpersonationFault::AfterInspect);
    sys::inject_close_fault_for_test(sys::TestCloseFault::PairMarkerFinal);
    let failure = match writer.observe_fixed_pair() {
        Err(failure) => failure,
        Ok(observed) => {
            let _ = observed.retire();
            return Err(std::io::Error::other("ambiguous inspect-probe close was accepted").into());
        }
    };
    assert_eq!(failure.cause(), ServiceRunStateError::Release);
    assert_eq!(sys::pair_inspect_count_for_test(), 1);
    assert!(matches!(
        failure.retire(),
        Err(ServiceRunStateError::Release)
    ));
    close_poison.cleanup_checked()
}

#[test]
fn fixed_pair_ambiguous_cleanup_is_bound_to_staged_full_ids() -> TestResult {
    let fixture = InstalledFixture::new()?;
    let paths = pair_paths(&fixture.base);
    let writer = acquire_for_test(open_test_service_run_state_root(
        &fixture.base,
        fixture.expected()?,
    )?)?;
    let observed = writer.observe_fixed_pair().map_err(|failure| {
        let cause = failure.cause();
        let _ = failure.retire();
        cause
    })?;
    let candidate = ExactFixedRunStatePair::new(
        [0x91; FIXED_RUN_STATE_RECORD_BYTES],
        [0xa2; FIXED_RUN_STATE_RECORD_BYTES],
    );
    sys::inject_pair_impersonation_fault_for_test(sys::TestPairImpersonationFault::AfterMarker);
    let ambiguous = match observed.compare_and_replace(candidate) {
        FixedPairCommitOutcome::Ambiguous(failure) => failure,
        other => {
            return Err(std::io::Error::other(format!(
                "unexpected staged-ID setup outcome: {other:?}"
            ))
            .into());
        }
    };
    assert!(!paths[3].exists());
    create_record_file_with_sddl(
        &paths[3],
        &sys::exact_pair_file_sddl_for_test()?,
        &[0xb3; FIXED_RUN_STATE_RECORD_BYTES],
    )?;
    let replacement = sys::record_object_identity_for_test(&paths[3], false)?;

    let reload_failure = match ambiguous.reload() {
        Err(failure) => failure,
        Ok(reloaded) => {
            reloaded.retire()?;
            return Err(
                std::io::Error::other("unrelated replacement temp was adopted or deleted").into(),
            );
        }
    };
    assert_eq!(reload_failure.cause(), ServiceRunStateError::Identity);
    assert!(matches!(
        reload_failure.retire(),
        Err(ServiceRunStateError::Identity | ServiceRunStateError::Release)
    ));
    assert_eq!(
        sys::record_object_identity_for_test(&paths[3], false)?,
        replacement
    );
    fixture.cleanup_checked()
}

#[test]
fn fixed_pair_reread_revalidates_writer_and_probe_close_poison_blocks_receipts() -> TestResult {
    let fixture = InstalledFixture::new()?;
    let writer = acquire_for_test(open_test_service_run_state_root(
        &fixture.base,
        fixture.expected()?,
    )?)?;
    let observed = writer.observe_fixed_pair().map_err(|failure| {
        let cause = failure.cause();
        let _ = failure.retire();
        cause
    })?;
    let candidate = ExactFixedRunStatePair::new(
        [0xe6; FIXED_RUN_STATE_RECORD_BYTES],
        [0xf7; FIXED_RUN_STATE_RECORD_BYTES],
    );
    let committed = commit_pair_for_test(observed, candidate)?;
    sys::inject_close_fault_for_test(sys::TestCloseFault::RevalidationState);
    let ambiguous = match committed.reread() {
        Err(failure) => failure,
        Ok(reread) => {
            reread.retire()?;
            return Err(std::io::Error::other("reread skipped writer revalidation").into());
        }
    };
    assert_eq!(ambiguous.cause(), ServiceRunStateError::Release);
    assert!(matches!(
        ambiguous.retire(),
        Err(ServiceRunStateError::Release)
    ));
    fixture.cleanup_checked()
}

#[test]
fn missing_objects_are_never_created_or_repaired() -> TestResult {
    let authority = InstalledFixture::new()?;
    let missing_root = unique_test_root()?;
    let mut missing_tree = FixtureTreeGuard::create(missing_root.clone())?;
    let base = missing_root.join("base");
    fs::create_dir(&base)?;
    create_intermediate_directories(&base)?;
    let result = open_test_service_run_state_root(&base, authority.expected()?);
    assert!(matches!(result, Err(ServiceRunStateError::Missing)));
    assert!(!root_path(&base).exists());
    missing_tree.cleanup_checked()?;

    let fixture = InstalledFixture::with_missing_recorded_lock()?;
    let root = open_test_service_run_state_root(&fixture.base, fixture.expected()?)?;
    let failure = root.acquire_run_lock();
    assert!(matches!(
        failure,
        Err(RuntimeRunLockStartFailure::BeforeLock(
            ServiceRunStateError::Missing
        ))
    ));
    assert!(!lock_path(&fixture.base).exists());
    Ok(())
}

#[test]
fn missing_state_failure_holds_lock_until_checked_retire() -> TestResult {
    let fixture = InstalledFixture::new()?;
    fixture.relax_root()?;
    fs::remove_dir(state_path(&fixture.base))?;
    fixture.reseal_root()?;

    let root = open_test_service_run_state_root(&fixture.base, fixture.expected()?)?;
    let failure = match root.acquire_run_lock() {
        Err(RuntimeRunLockStartFailure::WithLock(failure)) => failure,
        Err(RuntimeRunLockStartFailure::BeforeLock(cause)) => return Err(cause.into()),
        Ok(writer) => {
            writer.retire()?;
            return Err(std::io::Error::other("missing state was accepted").into());
        }
    };
    assert_eq!(failure.cause(), ServiceRunStateError::Missing);
    let competing = open_test_service_run_state_root(&fixture.base, fixture.expected()?)?;
    expect_before_lock_contention(competing)?;
    let _retired = failure.retire()?;
    assert!(!state_path(&fixture.base).exists());
    Ok(())
}

#[test]
fn second_same_process_writer_is_contended_until_checked_release() -> TestResult {
    let fixture = InstalledFixture::new()?;
    let first_root = open_test_service_run_state_root(&fixture.base, fixture.expected()?)?;
    let first = acquire_for_test(first_root)?;
    let second_root = open_test_service_run_state_root(&fixture.base, fixture.expected()?)?;
    let second = second_root.acquire_run_lock();
    assert!(matches!(
        second,
        Err(RuntimeRunLockStartFailure::BeforeLock(
            ServiceRunStateError::Contended
        ))
    ));
    release_for_test(first)?;

    let third_root = open_test_service_run_state_root(&fixture.base, fixture.expected()?)?;
    let third = acquire_for_test(third_root)?;
    release_for_test(third)?;
    Ok(())
}

#[test]
fn held_writer_exclusivity_directionally_rejects_share_all_nt_open() -> TestResult {
    let fixture = InstalledFixture::new()?;
    let root = open_test_service_run_state_root(&fixture.base, fixture.expected()?)?;
    let writer = acquire_for_test(root)?;

    writer.inner.directional_exclusivity_probe_for_test()?;
    writer.revalidate()?;
    release_for_test(writer)?;
    Ok(())
}

#[test]
fn byte_range_lock_conflicts_between_two_share_readable_same_id_handles() -> TestResult {
    let fixture = InstalledFixture::new()?;
    let root = open_test_service_run_state_root(&fixture.base, fixture.expected()?)?;

    root.inner.byte_range_collision_probe_for_test()?;
    root.revalidate()?;
    let writer = acquire_for_test(root)?;
    release_for_test(writer)?;
    Ok(())
}

#[test]
fn cross_process_crash_releases_lock_and_preserves_exact_identities() -> TestResult {
    let fixture = InstalledFixture::new()?;
    let before = fixture.identities();
    let event = NamedTestEvent::create()?;
    let child = spawn_synchronized_child(&fixture, &event, CHILD_MODE_HOLD)?;
    event.wait_ready()?;

    let root = open_test_service_run_state_root(&fixture.base, fixture.expected()?)?;
    expect_before_lock_contention(root)?;
    child.force_exit_and_wait()?;

    let after = (
        sys::record_object_identity_for_test(&root_path(&fixture.base), true)?,
        sys::record_object_identity_for_test(&lock_path(&fixture.base), false)?,
        sys::record_object_identity_for_test(&state_path(&fixture.base), true)?,
    );
    assert_eq!(after, before);
    release_for_test(reacquire_after_confirmed_exit_before_deadline(&fixture)?)?;
    event.close_checked()?;
    Ok(())
}

#[test]
fn held_handles_are_not_inherited_by_a_synchronized_child() -> TestResult {
    let fixture = InstalledFixture::new()?;
    let root = open_test_service_run_state_root(&fixture.base, fixture.expected()?)?;
    let writer = acquire_for_test(root)?;
    let event = NamedTestEvent::create()?;
    let child = spawn_synchronized_child(&fixture, &event, CHILD_MODE_SENTINEL)?;
    event.wait_ready()?;

    release_for_test(writer)?;
    let root = open_test_service_run_state_root(&fixture.base, fixture.expected()?)?;
    release_for_test(acquire_for_test(root)?)?;

    child.force_exit_and_wait()?;
    event.close_checked()?;
    Ok(())
}

#[test]
#[ignore = "invoked only by synchronized Phase 2E parent-process tests"]
fn cross_process_child_fixture() -> TestResult {
    let Some(mode) = std::env::var_os(CHILD_MODE_ENV) else {
        return Ok(());
    };
    let mode = mode
        .to_str()
        .ok_or_else(|| std::io::Error::other("child mode is not Unicode"))?;
    let base = std::env::var_os(CHILD_BASE_ENV)
        .map(PathBuf::from)
        .ok_or_else(|| std::io::Error::other("child base is absent"))?;
    let event_name = std::env::var(CHILD_EVENT_ENV)
        .map_err(|_| std::io::Error::other("child event name is absent"))?;

    let _writer = match mode {
        CHILD_MODE_HOLD => {
            let root_identity = sys::record_object_identity_for_test(&root_path(&base), true)?;
            let lock_identity = sys::record_object_identity_for_test(&lock_path(&base), false)?;
            let state_identity = sys::record_object_identity_for_test(&state_path(&base), true)?;
            let expected = ExpectedInstalledRunStateObjects(sys::expected_objects_for_test(
                root_identity,
                lock_identity,
                state_identity,
            )?);
            let root = open_test_service_run_state_root(&base, expected)?;
            Some(acquire_for_test(root)?)
        }
        CHILD_MODE_SENTINEL => None,
        _ => return Err(std::io::Error::other("child mode is invalid").into()),
    };
    signal_child_ready(&event_name)?;
    loop {
        std::thread::park();
    }
}

#[test]
fn wrong_and_cross_root_identities_are_never_adopted() -> TestResult {
    let first = InstalledFixture::new()?;
    let second = InstalledFixture::new()?;

    let wrong_root = ExpectedInstalledRunStateObjects(sys::expected_objects_for_test(
        second.root_identity,
        first.lock_identity,
        first.state_identity,
    )?);
    assert!(matches!(
        open_test_service_run_state_root(&first.base, wrong_root),
        Err(ServiceRunStateError::Identity)
    ));

    let crossed = ExpectedInstalledRunStateObjects(sys::expected_objects_for_test(
        first.root_identity,
        second.lock_identity,
        first.state_identity,
    )?);
    let root = open_test_service_run_state_root(&first.base, crossed)?;
    match root.acquire_run_lock() {
        Err(RuntimeRunLockStartFailure::WithLock(failure)) => {
            assert_eq!(failure.cause(), ServiceRunStateError::Identity);
            let _retired = failure.retire()?;
        }
        Err(RuntimeRunLockStartFailure::BeforeLock(cause)) => return Err(cause.into()),
        Ok(writer) => {
            release_for_test(writer)?;
            return Err(
                std::io::Error::other("cross-root lock identity did not fail WithLock").into(),
            );
        }
    }
    Ok(())
}

#[test]
fn stale_and_cross_root_state_identities_are_never_adopted() -> TestResult {
    let first = InstalledFixture::new()?;
    let second = InstalledFixture::new()?;
    let crossed = ExpectedInstalledRunStateObjects(sys::expected_objects_for_test(
        first.root_identity,
        first.lock_identity,
        second.state_identity,
    )?);
    let root = open_test_service_run_state_root(&first.base, crossed)?;
    match root.acquire_run_lock() {
        Err(RuntimeRunLockStartFailure::WithLock(failure)) => {
            assert_eq!(failure.cause(), ServiceRunStateError::Identity);
            let _retired = failure.retire()?;
        }
        Err(RuntimeRunLockStartFailure::BeforeLock(cause)) => return Err(cause.into()),
        Ok(writer) => {
            writer.retire()?;
            return Err(std::io::Error::other("cross-root state identity was adopted").into());
        }
    }

    let stale = InstalledFixture::new()?;
    stale.relax_root()?;
    fs::remove_dir(state_path(&stale.base))?;
    create_state_for_test_install(&stale.base)?;
    stale.reseal_root()?;
    let replacement = sys::record_object_identity_for_test(&state_path(&stale.base), true)?;
    assert_ne!(replacement, stale.state_identity);
    let root = open_test_service_run_state_root(&stale.base, stale.expected()?)?;
    match root.acquire_run_lock() {
        Err(RuntimeRunLockStartFailure::WithLock(failure)) => {
            assert_eq!(failure.cause(), ServiceRunStateError::Identity);
            let _retired = failure.retire()?;
        }
        Err(RuntimeRunLockStartFailure::BeforeLock(cause)) => return Err(cause.into()),
        Ok(writer) => {
            writer.retire()?;
            return Err(std::io::Error::other("stale state identity was adopted").into());
        }
    }
    let root =
        open_test_service_run_state_root(&stale.base, stale.expected_with_state(replacement)?)?;
    release_for_test(acquire_for_test(root)?)?;
    Ok(())
}

#[test]
fn stale_recorded_lock_identity_fails_with_lock_and_can_be_retired() -> TestResult {
    let fixture = InstalledFixture::new()?;
    fixture.relax_root()?;
    fs::remove_file(lock_path(&fixture.base))?;
    create_lock_for_test_install(&fixture.base)?;
    fixture.reseal_root()?;
    let replacement = sys::record_object_identity_for_test(&lock_path(&fixture.base), false)?;
    assert_ne!(replacement, fixture.lock_identity);

    let root = open_test_service_run_state_root(&fixture.base, fixture.expected()?)?;
    match root.acquire_run_lock() {
        Err(RuntimeRunLockStartFailure::WithLock(failure)) => {
            assert_eq!(failure.cause(), ServiceRunStateError::Identity);
            let _retired = failure.retire()?;
        }
        Err(RuntimeRunLockStartFailure::BeforeLock(cause)) => {
            return Err(cause.into());
        }
        Ok(writer) => {
            release_for_test(writer)?;
            return Err(std::io::Error::other("stale lock identity was adopted").into());
        }
    }

    let root =
        open_test_service_run_state_root(&fixture.base, fixture.expected_with_lock(replacement)?)?;
    let writer = acquire_for_test(root)?;
    release_for_test(writer)?;
    Ok(())
}

#[test]
fn wrong_root_and_lock_types_fail_without_repair() -> TestResult {
    let mut root_fixture = InstalledFixture::new()?;
    root_fixture.tree.relax_and_close_root_checked()?;
    fs::remove_file(lock_path(&root_fixture.base))?;
    fs::remove_dir(state_path(&root_fixture.base))?;
    fs::remove_dir(root_path(&root_fixture.base))?;
    fs::write(root_path(&root_fixture.base), [])?;
    assert!(matches!(
        open_test_service_run_state_root(&root_fixture.base, root_fixture.expected()?),
        Err(ServiceRunStateError::Shape)
    ));
    assert!(root_path(&root_fixture.base).is_file());

    let lock_fixture = InstalledFixture::new()?;
    lock_fixture.relax_root()?;
    fs::remove_file(lock_path(&lock_fixture.base))?;
    fs::create_dir(lock_path(&lock_fixture.base))?;
    lock_fixture.reseal_root()?;
    let root = open_test_service_run_state_root(&lock_fixture.base, lock_fixture.expected()?)?;
    assert!(matches!(
        root.acquire_run_lock(),
        Err(RuntimeRunLockStartFailure::BeforeLock(
            ServiceRunStateError::Shape
        ))
    ));
    assert!(lock_path(&lock_fixture.base).is_dir());
    root_fixture.cleanup_checked()?;
    lock_fixture.cleanup_checked()?;
    Ok(())
}

#[test]
fn wrong_state_type_reparse_and_security_are_rejected_with_lock() -> TestResult {
    let wrong_type = InstalledFixture::new()?;
    wrong_type.relax_root()?;
    fs::remove_dir(state_path(&wrong_type.base))?;
    create_empty_file_with_sddl_and_access(
        &state_path(&wrong_type.base),
        &sys::exact_sddl_for_test(sys::STATE_ACCESS_FOR_TEST)?,
        sys::STATE_ACCESS_FOR_TEST,
    )?;
    wrong_type.reseal_root()?;
    let identity = sys::record_object_identity_for_test(&state_path(&wrong_type.base), false)?;
    let root = open_test_service_run_state_root(
        &wrong_type.base,
        wrong_type.expected_with_state(identity)?,
    )?;
    match root.acquire_run_lock() {
        Err(RuntimeRunLockStartFailure::WithLock(failure)) => {
            assert_eq!(failure.cause(), ServiceRunStateError::Shape);
            let _retired = failure.retire()?;
        }
        Err(RuntimeRunLockStartFailure::BeforeLock(cause)) => return Err(cause.into()),
        Ok(writer) => {
            writer.retire()?;
            return Err(std::io::Error::other("file-backed state was accepted").into());
        }
    }

    let reparse = InstalledFixture::new()?;
    reparse.relax_root()?;
    fs::remove_dir(state_path(&reparse.base))?;
    let target = reparse.base.join("state-target");
    fs::create_dir(&target)?;
    create_junction(&state_path(&reparse.base), &target)?;
    reparse.reseal_root()?;
    let identity = sys::record_object_identity_for_test(&state_path(&reparse.base), true)?;
    let root =
        open_test_service_run_state_root(&reparse.base, reparse.expected_with_state(identity)?)?;
    match root.acquire_run_lock() {
        Err(RuntimeRunLockStartFailure::WithLock(failure)) => {
            assert_eq!(failure.cause(), ServiceRunStateError::Reparse);
            let _retired = failure.retire()?;
        }
        Err(RuntimeRunLockStartFailure::BeforeLock(cause)) => return Err(cause.into()),
        Ok(writer) => {
            writer.retire()?;
            return Err(std::io::Error::other("reparse-backed state was accepted").into());
        }
    }

    let wrong_security = InstalledFixture::new()?;
    wrong_security.relax_root()?;
    fs::remove_dir(state_path(&wrong_security.base))?;
    let overbroad = sys::STATE_ACCESS_FOR_TEST | FILE_ADD_SUBDIRECTORY.0;
    create_directory_with_sddl(
        &state_path(&wrong_security.base),
        &sys::exact_sddl_for_test(overbroad)?,
    )?;
    wrong_security.reseal_root()?;
    let identity = sys::record_object_identity_for_test(&state_path(&wrong_security.base), true)?;
    let root = open_test_service_run_state_root(
        &wrong_security.base,
        wrong_security.expected_with_state(identity)?,
    )?;
    match root.acquire_run_lock() {
        Err(RuntimeRunLockStartFailure::WithLock(failure)) => {
            assert_eq!(failure.cause(), ServiceRunStateError::Security);
            let _retired = failure.retire()?;
        }
        Err(RuntimeRunLockStartFailure::BeforeLock(cause)) => return Err(cause.into()),
        Ok(writer) => {
            writer.retire()?;
            return Err(std::io::Error::other("overbroad state DACL was accepted").into());
        }
    }
    Ok(())
}

#[test]
fn junction_reparse_at_test_base_and_product_components_is_rejected() -> TestResult {
    let authority = InstalledFixture::new()?;

    let mut base_tree = FixtureTreeGuard::create(unique_test_root()?)?;
    let real_base = base_tree.path().join("real-base");
    fs::create_dir(&real_base)?;
    let alias = base_tree.path().join("base-alias");
    create_junction(&alias, &real_base)?;
    expect_root_reparse_rejected(&alias, authority.expected()?)?;
    base_tree.cleanup_checked()?;

    let mut your_wallet_tree = FixtureTreeGuard::create(unique_test_root()?)?;
    let base = your_wallet_tree.path().join("base");
    fs::create_dir(&base)?;
    let target = your_wallet_tree.path().join("YourWallet-target");
    fs::create_dir(&target)?;
    create_junction(&base.join("YourWallet"), &target)?;
    expect_root_reparse_rejected(&base, authority.expected()?)?;
    your_wallet_tree.cleanup_checked()?;

    let mut key_agent_tree = FixtureTreeGuard::create(unique_test_root()?)?;
    let base = key_agent_tree.path().join("base");
    fs::create_dir(&base)?;
    fs::create_dir(base.join("YourWallet"))?;
    let target = key_agent_tree.path().join("KeyAgent-target");
    fs::create_dir(&target)?;
    create_junction(&base.join("YourWallet").join("KeyAgent"), &target)?;
    expect_root_reparse_rejected(&base, authority.expected()?)?;
    key_agent_tree.cleanup_checked()?;

    let mut version_tree = FixtureTreeGuard::create(unique_test_root()?)?;
    let base = version_tree.path().join("base");
    fs::create_dir(&base)?;
    create_intermediate_directories(&base)?;
    let target = version_tree.path().join("v1-target");
    fs::create_dir(&target)?;
    create_junction(&root_path(&base), &target)?;
    expect_root_reparse_rejected(&base, authority.expected()?)?;
    version_tree.cleanup_checked()?;
    authority.cleanup_checked()?;

    Ok(())
}

#[test]
#[ignore = "requires Developer Mode or SeCreateSymbolicLinkPrivilege for a file reparse point"]
fn symlink_reparse_at_run_lock_is_rejected_when_capability_is_available() -> TestResult {
    let lock = InstalledFixture::new()?;
    lock.relax_root()?;
    let original = lock_path(&lock.base);
    let target = original.with_file_name("run.lock-target");
    fs::rename(&original, &target)?;
    symlink_file(&target, &original)?;
    lock.reseal_root()?;
    let root = open_test_service_run_state_root(&lock.base, lock.expected()?)?;
    expect_lock_reparse_rejected(root)?;
    lock.cleanup_checked()?;
    Ok(())
}

#[test]
fn lock_hardlink_and_nonzero_length_fail_with_lock() -> TestResult {
    let hardlink = InstalledFixture::new()?;
    hardlink.relax_root()?;
    fs::remove_file(lock_path(&hardlink.base))?;
    create_multilink_exact_lock(
        &lock_path(&hardlink.base),
        &root_path(&hardlink.base).join("second-link"),
    )?;
    hardlink.reseal_root()?;
    let replacement = sys::record_object_identity_for_test(&lock_path(&hardlink.base), false)?;
    let root = open_test_service_run_state_root(
        &hardlink.base,
        hardlink.expected_with_lock(replacement)?,
    )?;
    match root.acquire_run_lock() {
        Err(RuntimeRunLockStartFailure::WithLock(failure)) => {
            assert_eq!(failure.cause(), ServiceRunStateError::Shape);
            let _retired = failure.retire()?;
        }
        Err(RuntimeRunLockStartFailure::BeforeLock(cause)) => return Err(cause.into()),
        Ok(writer) => {
            release_for_test(writer)?;
            return Err(std::io::Error::other("multi-link lock was accepted").into());
        }
    }

    let nonzero = InstalledFixture::new()?;
    nonzero.relax_root()?;
    fs::remove_file(lock_path(&nonzero.base))?;
    create_nonzero_exact_lock(&lock_path(&nonzero.base))?;
    nonzero.reseal_root()?;
    let replacement = sys::record_object_identity_for_test(&lock_path(&nonzero.base), false)?;
    let root =
        open_test_service_run_state_root(&nonzero.base, nonzero.expected_with_lock(replacement)?)?;
    match root.acquire_run_lock() {
        Err(RuntimeRunLockStartFailure::WithLock(failure)) => {
            assert_eq!(failure.cause(), ServiceRunStateError::Shape);
            let _retired = failure.retire()?;
        }
        Err(RuntimeRunLockStartFailure::BeforeLock(cause)) => return Err(cause.into()),
        Ok(writer) => {
            release_for_test(writer)?;
            return Err(std::io::Error::other("nonzero lock was accepted").into());
        }
    }
    Ok(())
}

#[test]
fn exact_owner_rights_service_system_dacl_mutations_are_rejected() -> TestResult {
    let service = sys::current_service_sid_string_for_test()?;
    let root_mask = sys::ROOT_ACCESS_FOR_TEST;
    let deny = sys::OWNER_RIGHTS_DENY_FOR_TEST;
    let system = FILE_ALL_ACCESS.0;
    let exact = sys::exact_sddl_for_test(root_mask)?;
    let auto_inherited = exact.replacen("D:P", "D:PAI", 1);
    assert_eq!(
        sys::verify_sddl_for_test(&auto_inherited, root_mask),
        Ok(())
    );

    let mutations = [
        exact.replacen(&format!("O:{service}"), "O:SY", 1),
        exact.replacen("D:P", "D:", 1),
        exact.replacen("D:P", "D:PAR", 1),
        exact.replacen(
            &format!("(D;;0x{deny:08x};;;OW)"),
            "(D;;0x00040000;;;OW)",
            1,
        ),
        format!(
            "O:{service}D:P(A;;0x{root_mask:08x};;;{service})(D;;0x{deny:08x};;;OW)(A;;0x{system:08x};;;SY)"
        ),
        format!(
            "O:{service}D:P(D;;0x{deny:08x};;;OW)(A;;0x{root_mask:08x};;;AU)(A;;0x{system:08x};;;SY)"
        ),
        format!(
            "O:{service}D:P(D;;0x{deny:08x};;;OW)(A;;0x{root_mask:08x};;;{service})(A;;0x{system:08x};;;BU)"
        ),
        format!(
            "O:{service}D:P(D;;0x{deny:08x};;;OW)(A;;0x00000001;;;{service})(A;;0x{system:08x};;;SY)"
        ),
        format!(
            "O:{service}D:P(D;;0x{deny:08x};;;OW)(A;;0x{root_mask:08x};;;{service})(A;;0x00000001;;;SY)"
        ),
        format!(
            "O:{service}D:P(D;;0x{deny:08x};;;OW)(A;;0x{root_mask:08x};;;{service})(A;;0x{system:08x};;;SY)(A;;FR;;;WD)"
        ),
    ];
    for mutation in mutations {
        assert_eq!(
            sys::verify_sddl_for_test(&mutation, root_mask),
            Err(ServiceRunStateError::Security)
        );
    }
    Ok(())
}

#[test]
fn service_owner_mutation_is_denied_and_held_root_blocks_delete() -> TestResult {
    let fixture = InstalledFixture::new()?;
    for (access_role, access) in [
        ("WRITE_DAC", WRITE_DAC.0),
        ("WRITE_OWNER", WRITE_OWNER.0),
        ("FILE_DELETE_CHILD", FILE_DELETE_CHILD.0),
    ] {
        fresh_access_fails_with(
            &root_path(&fixture.base),
            access,
            true,
            "root",
            access_role,
            ERROR_ACCESS_DENIED.to_hresult(),
        )?;
    }
    for (access_role, access) in [
        ("WRITE_DAC", WRITE_DAC.0),
        ("WRITE_OWNER", WRITE_OWNER.0),
        ("DELETE", DELETE.0),
        ("FILE_DELETE_CHILD", FILE_DELETE_CHILD.0),
        ("FILE_ADD_SUBDIRECTORY", FILE_ADD_SUBDIRECTORY.0),
        ("GENERIC_WRITE", GENERIC_WRITE.0),
    ] {
        fresh_access_fails_with(
            &state_path(&fixture.base),
            access,
            true,
            "state",
            access_role,
            ERROR_ACCESS_DENIED.to_hresult(),
        )?;
    }
    for (access_role, access) in [
        ("WRITE_DAC", WRITE_DAC.0),
        ("WRITE_OWNER", WRITE_OWNER.0),
        ("DELETE", DELETE.0),
    ] {
        fresh_access_fails_with(
            &lock_path(&fixture.base),
            access,
            false,
            "lock",
            access_role,
            ERROR_ACCESS_DENIED.to_hresult(),
        )?;
    }

    let root = open_test_service_run_state_root(&fixture.base, fixture.expected()?)?;
    fresh_access_fails_with(
        &root_path(&fixture.base),
        DELETE.0,
        true,
        "root",
        "DELETE-while-held",
        ERROR_SHARING_VIOLATION.to_hresult(),
    )?;
    release_for_test(acquire_for_test(root)?)?;
    Ok(())
}

#[test]
fn exact_state_authority_allows_file_create_but_denies_directory_mutation() -> TestResult {
    assert_eq!(sys::STATE_ACCESS_FOR_TEST, 0x0012_00a3);
    let fixture = InstalledFixture::new()?;
    let root = open_test_service_run_state_root(&fixture.base, fixture.expected()?)?;
    let writer = acquire_for_test(root)?;

    let marker = state_path(&fixture.base).join("file-create-probe");
    fs::write(&marker, [])?;
    assert!(marker.is_file());
    fs::remove_file(&marker)?;

    let mut allowed = SetupHandle(Some(open_test_handle(
        &state_path(&fixture.base),
        FILE_ADD_FILE.0,
        true,
    )?));
    allowed.close_checked()?;
    filesystem_mutation_is_denied(
        fs::create_dir(state_path(&fixture.base).join("directory-create-probe")),
        "state-subdirectory-create",
    )?;
    writer.revalidate()?;
    release_for_test(writer)?;
    Ok(())
}

#[test]
fn state_no_delete_share_is_nonvacuous_when_delete_acl_allows_access() -> TestResult {
    let fixture = InstalledFixture::new()?;
    fixture.relax_root()?;
    fs::remove_dir(state_path(&fixture.base))?;
    let service = sys::current_service_sid_string_for_test()?;
    let delete_permitted_deny = sys::OWNER_RIGHTS_DENY_FOR_TEST & !DELETE.0;
    let delete_permitted_allow = sys::STATE_ACCESS_FOR_TEST | DELETE.0;
    let custom_state_sddl = format!(
        "O:{service}D:P(D;;0x{delete_permitted_deny:08x};;;OW)(A;;0x{delete_permitted_allow:08x};;;{service})(A;;0x{:08x};;;SY)",
        FILE_ALL_ACCESS.0,
    );
    create_directory_with_sddl(&state_path(&fixture.base), &custom_state_sddl)?;
    fixture.reseal_root()?;
    let state_identity = sys::record_object_identity_for_test(&state_path(&fixture.base), true)?;

    let root = open_test_service_run_state_root(
        &fixture.base,
        fixture.expected_with_state(state_identity)?,
    )?;
    let failure = match root.acquire_run_lock() {
        Err(RuntimeRunLockStartFailure::WithLock(failure)) => failure,
        Err(RuntimeRunLockStartFailure::BeforeLock(cause)) => return Err(cause.into()),
        Ok(writer) => {
            writer.retire()?;
            return Err(std::io::Error::other("custom state DACL was accepted").into());
        }
    };
    assert_eq!(failure.cause(), ServiceRunStateError::Security);
    assert!(failure.inner.has_state_for_test());
    fresh_access_fails_with(
        &state_path(&fixture.base),
        DELETE.0,
        true,
        "state",
        "DELETE-while-held-with-delete-permitted-DACL",
        ERROR_SHARING_VIOLATION.to_hresult(),
    )?;
    let _retired = failure.retire()?;

    let mut delete_probe = SetupHandle(Some(open_test_handle(
        &state_path(&fixture.base),
        DELETE.0,
        true,
    )?));
    delete_probe.close_checked()?;
    Ok(())
}

#[test]
fn held_root_lock_and_state_block_rename_and_delete() -> TestResult {
    let fixture = InstalledFixture::new()?;
    let before = fixture.identities();
    let root = open_test_service_run_state_root(&fixture.base, fixture.expected()?)?;
    let writer = acquire_for_test(root)?;

    filesystem_mutation_is_denied(
        fs::rename(
            root_path(&fixture.base),
            fixture.base.join("held-root-renamed"),
        ),
        "root-rename",
    )?;
    filesystem_mutation_is_denied(
        fs::rename(
            lock_path(&fixture.base),
            root_path(&fixture.base).join("held-lock-renamed"),
        ),
        "lock-rename",
    )?;
    filesystem_mutation_is_denied(fs::remove_file(lock_path(&fixture.base)), "lock-delete")?;
    filesystem_mutation_is_denied(
        fs::rename(
            state_path(&fixture.base),
            root_path(&fixture.base).join("held-state-renamed"),
        ),
        "state-rename",
    )?;
    filesystem_mutation_is_denied(fs::remove_dir(state_path(&fixture.base)), "state-delete")?;
    assert!(root_path(&fixture.base).is_dir());
    assert!(lock_path(&fixture.base).is_file());
    assert!(state_path(&fixture.base).is_dir());
    writer.revalidate()?;
    release_for_test(writer)?;
    assert_eq!(
        (
            sys::record_object_identity_for_test(&root_path(&fixture.base), true)?,
            sys::record_object_identity_for_test(&lock_path(&fixture.base), false)?,
            sys::record_object_identity_for_test(&state_path(&fixture.base), true)?,
        ),
        before
    );
    Ok(())
}

#[test]
fn held_handle_flags_are_zero_and_release_order_is_exact() -> TestResult {
    let fixture = InstalledFixture::new()?;
    let root = open_test_service_run_state_root(&fixture.base, fixture.expected()?)?;
    assert!(root.inner.handle_flags_are_zero_for_test());
    let writer = acquire_for_test(root)?;
    assert!(writer.inner.handle_flags_are_zero_for_test());
    let _ = sys::take_release_trace_for_test();
    release_for_test(writer)?;
    assert_eq!(
        sys::take_release_trace_for_test(),
        vec![
            sys::TestReleaseStep::WriterRevalidated,
            sys::TestReleaseStep::StateClosed,
            sys::TestReleaseStep::RangeUnlocked,
            sys::TestReleaseStep::LockClosed,
            sys::TestReleaseStep::RootRevalidatedAfterLock,
            sys::TestReleaseStep::RootClosed,
        ]
    );
    Ok(())
}

#[test]
fn successful_writer_terminal_retire_has_exact_order_and_close_fault_no_receipt() -> TestResult {
    let fixture = InstalledFixture::new()?;
    let root = open_test_service_run_state_root(&fixture.base, fixture.expected()?)?;
    let writer = acquire_for_test(root)?;
    let _ = sys::take_release_trace_for_test();
    let _retired = writer.retire()?;
    assert_eq!(
        sys::take_release_trace_for_test(),
        vec![
            sys::TestReleaseStep::StateClosed,
            sys::TestReleaseStep::RangeUnlocked,
            sys::TestReleaseStep::LockClosed,
            sys::TestReleaseStep::RootClosed,
        ]
    );

    let root = open_test_service_run_state_root(&fixture.base, fixture.expected()?)?;
    let writer = acquire_for_test(root)?;
    let _ = sys::take_release_trace_for_test();
    sys::inject_close_fault_for_test(sys::TestCloseFault::State);
    assert!(matches!(
        writer.retire(),
        Err(ServiceRunStateError::Release)
    ));
    assert_eq!(
        sys::take_release_trace_for_test(),
        vec![
            sys::TestReleaseStep::RangeUnlocked,
            sys::TestReleaseStep::LockClosed,
            sys::TestReleaseStep::RootClosed,
        ]
    );

    let root = open_test_service_run_state_root(&fixture.base, fixture.expected()?)?;
    release_for_test(acquire_for_test(root)?)?;
    Ok(())
}

#[test]
fn impersonation_is_rejected_before_any_filesystem_open() -> TestResult {
    let fixture = InstalledFixture::new()?;
    let expected = fixture.expected()?;
    sys::reset_open_count_for_test();
    let guard = RevertImpersonation::install()?;
    let result = open_test_service_run_state_root(&fixture.base, expected);
    assert!(matches!(result, Err(ServiceRunStateError::Impersonation)));
    assert_eq!(sys::open_count_for_test(), 0);
    drop(guard);
    Ok(())
}

#[test]
fn state_open_impersonation_bookends_preserve_exact_failure_authority() -> TestResult {
    for (fault, expected_opens, expected_state) in [
        (
            sys::TestStateOpenImpersonationFault::BeforeNativeOpen,
            0,
            false,
        ),
        (
            sys::TestStateOpenImpersonationFault::AfterNativeOpen,
            1,
            true,
        ),
    ] {
        let fixture = InstalledFixture::new()?;
        let root = open_test_service_run_state_root(&fixture.base, fixture.expected()?)?;
        sys::reset_state_native_open_count_for_test();
        sys::inject_state_open_impersonation_fault_for_test(fault);
        let failure = match root.acquire_run_lock() {
            Err(RuntimeRunLockStartFailure::WithLock(failure)) => failure,
            Err(RuntimeRunLockStartFailure::BeforeLock(cause)) => return Err(cause.into()),
            Ok(writer) => {
                writer.retire()?;
                return Err(
                    std::io::Error::other("state-open impersonation fault was accepted").into(),
                );
            }
        };
        assert_eq!(failure.cause(), ServiceRunStateError::Impersonation);
        assert_eq!(sys::state_native_open_count_for_test(), expected_opens);
        assert_eq!(failure.inner.has_state_for_test(), expected_state);
        let competing = open_test_service_run_state_root(&fixture.base, fixture.expected()?)?;
        expect_before_lock_contention(competing)?;
        if expected_state {
            sys::inject_close_fault_for_test(sys::TestCloseFault::State);
            assert!(matches!(
                failure.retire(),
                Err(ServiceRunStateError::Release)
            ));
        } else {
            let _retired = failure.retire()?;
        }
        let root = open_test_service_run_state_root(&fixture.base, fixture.expected()?)?;
        release_for_test(acquire_for_test(root)?)?;
    }
    Ok(())
}

#[test]
fn unlock_failure_never_mints_normal_receipt_and_checked_retire_releases_range() -> TestResult {
    let fixture = InstalledFixture::new()?;
    let root = open_test_service_run_state_root(&fixture.base, fixture.expected()?)?;
    let writer = acquire_for_test(root)?;
    let _ = sys::take_release_trace_for_test();
    sys::inject_unlock_fault_for_test();

    let failure = match writer.release() {
        Err(failure) => failure,
        Ok(_released) => {
            return Err(std::io::Error::other(
                "failed range unlock minted a normal release receipt",
            )
            .into());
        }
    };
    assert_eq!(failure.cause(), ServiceRunStateError::Release);
    assert!(!failure.inner.has_state_for_test());
    let _retired = failure.retire()?;
    assert_eq!(
        sys::take_release_trace_for_test(),
        vec![
            sys::TestReleaseStep::WriterRevalidated,
            sys::TestReleaseStep::StateClosed,
            sys::TestReleaseStep::RangeUnlocked,
            sys::TestReleaseStep::LockClosed,
            sys::TestReleaseStep::RootClosed,
        ]
    );

    let root = open_test_service_run_state_root(&fixture.base, fixture.expected()?)?;
    release_for_test(acquire_for_test(root)?)?;
    Ok(())
}

#[test]
fn retire_unlock_failure_closes_handles_but_never_mints_retired_receipt() -> TestResult {
    let fixture = InstalledFixture::new()?;
    let root = open_test_service_run_state_root(&fixture.base, fixture.expected()?)?;
    let writer = acquire_for_test(root)?;
    let _ = sys::take_release_trace_for_test();
    sys::inject_unlock_fault_for_test();

    let failure = match writer.release() {
        Err(failure) => failure,
        Ok(_released) => {
            return Err(std::io::Error::other(
                "failed range unlock minted a normal release receipt",
            )
            .into());
        }
    };
    sys::inject_unlock_fault_for_test();
    assert!(matches!(
        failure.retire(),
        Err(ServiceRunStateError::Release)
    ));
    assert_eq!(
        sys::take_release_trace_for_test(),
        vec![
            sys::TestReleaseStep::WriterRevalidated,
            sys::TestReleaseStep::StateClosed,
            sys::TestReleaseStep::LockClosed,
            sys::TestReleaseStep::RootClosed,
        ]
    );

    let root = open_test_service_run_state_root(&fixture.base, fixture.expected()?)?;
    release_for_test(acquire_for_test(root)?)?;
    Ok(())
}

#[test]
fn ambiguous_checked_close_never_mints_a_release_or_retire_receipt() -> TestResult {
    for fault in [
        sys::TestCloseFault::State,
        sys::TestCloseFault::Lock,
        sys::TestCloseFault::Root,
    ] {
        let fixture = InstalledFixture::new()?;
        let root = open_test_service_run_state_root(&fixture.base, fixture.expected()?)?;
        let writer = acquire_for_test(root)?;
        sys::inject_close_fault_for_test(fault);
        let failure = match writer.release() {
            Err(failure) => failure,
            Ok(_released) => {
                return Err(
                    std::io::Error::other("ambiguous close minted a normal receipt").into(),
                );
            }
        };
        assert_eq!(failure.cause(), ServiceRunStateError::Release);
        assert!(matches!(
            failure.retire(),
            Err(ServiceRunStateError::Release)
        ));
    }
    Ok(())
}

#[test]
fn revalidation_probe_close_ambiguity_never_mints_any_receipt() -> TestResult {
    for fault in [
        sys::TestCloseFault::RevalidationRoot,
        sys::TestCloseFault::RevalidationState,
    ] {
        let fixture = InstalledFixture::new()?;
        let root = open_test_service_run_state_root(&fixture.base, fixture.expected()?)?;
        let writer = acquire_for_test(root)?;
        sys::inject_close_fault_for_test(fault);
        let failure = match writer.release() {
            Err(failure) => failure,
            Ok(_released) => {
                return Err(std::io::Error::other(
                    "ambiguous revalidation-probe close minted a normal receipt",
                )
                .into());
            }
        };
        assert_eq!(failure.cause(), ServiceRunStateError::Release);
        assert!(matches!(
            failure.retire(),
            Err(ServiceRunStateError::Release)
        ));
    }
    Ok(())
}

#[test]
fn debug_errors_and_authority_are_redacted_and_phase2d_disconnected() -> TestResult {
    let fixture = InstalledFixture::new()?;
    let expected = fixture.expected()?;
    let expected_debug = format!("{expected:?}");
    assert!(expected_debug.contains("REDACTED"));
    assert!(!expected_debug.contains(&fixture.base.to_string_lossy().into_owned()));
    let root = open_test_service_run_state_root(&fixture.base, expected)?;
    let root_debug = format!("{root:?}");
    assert!(root_debug.contains("REDACTED"));
    assert!(!root_debug.contains(&fixture.base.to_string_lossy().into_owned()));
    release_for_test(acquire_for_test(root)?)?;

    for error in [
        ServiceRunStateError::Location,
        ServiceRunStateError::Identity,
        ServiceRunStateError::Security,
    ] {
        let rendered = error.to_string();
        assert!(!rendered.contains('\\'));
        assert!(!rendered.contains(':'));
    }

    let contract = include_str!("../run_state_root.rs");
    assert!(!contract.contains("BootEvidence"));
    assert!(!contract.contains("RuntimeWriterAcquired"));
    assert!(!contract.contains("impl Clone for ServiceRunLockReleased"));
    assert!(!contract.contains("impl Copy for ServiceRunLockReleased"));
    assert!(!contract.contains("impl Clone for FailedRunLockRetired"));
    assert!(!contract.contains("impl Copy for FailedRunLockRetired"));
    Ok(())
}
