//! Exact non-inheriting startup state for one service-owned LPAC probe.
//!
//! The owner deliberately exposes only the `STARTUPINFOW` prefix consumed by
//! process creation. Every pointer in that prefix and its five-slot attribute
//! list remains backed by this move-only, thread-bound value.

#![deny(unsafe_code)]

use core::cell::Cell;
use core::fmt;
use core::marker::PhantomData;
use core::mem::size_of;
use std::rc::Rc;

use thiserror::Error;
use windows::Win32::System::Threading::{
    LPPROC_THREAD_ATTRIBUTE_LIST, STARTUPINFOEXW, STARTUPINFOW,
};
use windows::Win32::System::WindowsProgramming::PROCESS_CREATION_CHILD_PROCESS_RESTRICTED;
use windows::core::PWSTR;

use super::job::{ServiceProbeJob, ServiceProbeJobAttribute};
use super::target_profile::{PreparedTargetLpacAttributes, PreparedTargetUserLpac};
use crate::restricted_process_context::RestrictedProcessContext;

const ATTRIBUTE_COUNT: u32 = 5;
const DESKTOP_NAME: &str = r"winsta0\default";

const MITIGATION_DEP_ENABLE: u64 = 1;
const MITIGATION_SEHOP_ENABLE: u64 = 1 << 2;
const MITIGATION_FORCE_RELOCATE_IMAGES_ALWAYS_ON: u64 = 1 << 8;
const MITIGATION_HEAP_TERMINATE_ALWAYS_ON: u64 = 1 << 12;
const MITIGATION_BOTTOM_UP_ASLR_ALWAYS_ON: u64 = 1 << 16;
const MITIGATION_HIGH_ENTROPY_ASLR_ALWAYS_ON: u64 = 1 << 20;
const MITIGATION_STRICT_HANDLE_CHECKS_ALWAYS_ON: u64 = 1 << 24;
const MITIGATION_EXTENSION_POINT_DISABLE_ALWAYS_ON: u64 = 1 << 32;
const MITIGATION_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON: u64 = 1 << 36;
const MITIGATION_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON: u64 = 1 << 44;
const MITIGATION_IMAGE_LOAD_NO_REMOTE_ALWAYS_ON: u64 = 1 << 52;
const MITIGATION_IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON: u64 = 1 << 56;
const MITIGATION_IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON: u64 = 1 << 60;

// This is intentionally identical to launch.rs's HELPER_MITIGATION_POLICY.
const SERVICE_PROBE_MITIGATION_POLICY: u64 = MITIGATION_DEP_ENABLE
    | MITIGATION_SEHOP_ENABLE
    | MITIGATION_FORCE_RELOCATE_IMAGES_ALWAYS_ON
    | MITIGATION_HEAP_TERMINATE_ALWAYS_ON
    | MITIGATION_BOTTOM_UP_ASLR_ALWAYS_ON
    | MITIGATION_HIGH_ENTROPY_ASLR_ALWAYS_ON
    | MITIGATION_STRICT_HANDLE_CHECKS_ALWAYS_ON
    | MITIGATION_EXTENSION_POINT_DISABLE_ALWAYS_ON
    | MITIGATION_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON
    | MITIGATION_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON
    | MITIGATION_IMAGE_LOAD_NO_REMOTE_ALWAYS_ON
    | MITIGATION_IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON
    | MITIGATION_IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON;

/// Data-free failure classes for exact service-probe startup preparation.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(super) enum ServiceProbeStartupError {
    /// The retained Job no longer satisfies the one-process launch contract.
    #[error("service probe Job is unavailable")]
    Job,
    /// The retained target-user LPAC inputs no longer satisfy their contract.
    #[error("target-user LPAC launch inputs are unavailable")]
    TargetLpac,
    /// Windows could not initialize an exact five-slot attribute list.
    #[error("service probe attribute list is unavailable")]
    AttributeList,
    /// One of the five exact creation attributes could not be installed.
    #[error("service probe creation attributes are unavailable")]
    AttributeInstallation,
    /// The stable startup backing no longer has the required exact shape.
    #[error("service probe startup state is invalid")]
    Verification,
}

trait AttributeListDeleter {
    fn delete(&mut self, pointer: LPPROC_THREAD_ATTRIBUTE_LIST);
}

struct WindowsAttributeListDeleter;

impl AttributeListDeleter for WindowsAttributeListDeleter {
    fn delete(&mut self, pointer: LPPROC_THREAD_ATTRIBUTE_LIST) {
        sys::delete_attribute_list(pointer);
    }
}

/// An initialized list whose destructor is the sole delete authority.
///
/// `words` retains aligned storage, and the deleter is invoked exactly once
/// before that storage is released.
struct InitializedAttributeList<D: AttributeListDeleter> {
    pointer: LPPROC_THREAD_ATTRIBUTE_LIST,
    words: Vec<usize>,
    deleter: D,
}

impl InitializedAttributeList<WindowsAttributeListDeleter> {
    fn initialize() -> Result<Self, ServiceProbeStartupError> {
        let bytes = sys::required_attribute_list_bytes(ATTRIBUTE_COUNT)?;
        let word_size = size_of::<usize>();
        let word_count = bytes
            .checked_add(word_size - 1)
            .and_then(|rounded| rounded.checked_div(word_size))
            .filter(|count| *count != 0)
            .ok_or(ServiceProbeStartupError::AttributeList)?;
        let mut words = vec![0_usize; word_count];
        let pointer = LPPROC_THREAD_ATTRIBUTE_LIST(words.as_mut_ptr().cast());
        sys::initialize_attribute_list(pointer, ATTRIBUTE_COUNT, bytes)?;
        Ok(Self {
            pointer,
            words,
            deleter: WindowsAttributeListDeleter,
        })
    }
}

impl<D: AttributeListDeleter> InitializedAttributeList<D> {
    fn pointer(&self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        debug_assert!(!self.words.is_empty());
        self.pointer
    }
}

impl<D: AttributeListDeleter> Drop for InitializedAttributeList<D> {
    fn drop(&mut self) {
        self.deleter.delete(self.pointer);
    }
}

trait AttributeInstaller {
    fn install_job(&mut self) -> Result<(), ServiceProbeStartupError>;
    fn install_mitigation(&mut self) -> Result<(), ServiceProbeStartupError>;
    fn install_security_capabilities(&mut self) -> Result<(), ServiceProbeStartupError>;
    fn install_all_application_packages_policy(&mut self) -> Result<(), ServiceProbeStartupError>;
    fn install_child_process_policy(&mut self) -> Result<(), ServiceProbeStartupError>;
}

fn install_exact_attributes(
    installer: &mut impl AttributeInstaller,
) -> Result<(), ServiceProbeStartupError> {
    installer.install_job()?;
    installer.install_mitigation()?;
    installer.install_security_capabilities()?;
    installer.install_all_application_packages_policy()?;
    installer.install_child_process_policy()
}

fn install_and_retain<L>(
    list: L,
    installer: &mut impl AttributeInstaller,
) -> Result<L, ServiceProbeStartupError> {
    install_exact_attributes(installer)?;
    Ok(list)
}

struct WindowsAttributeInstaller<'values, 'job, 'lpac> {
    pointer: LPPROC_THREAD_ATTRIBUTE_LIST,
    job: &'values ServiceProbeJobAttribute<'job>,
    lpac: &'values PreparedTargetLpacAttributes<'lpac>,
    mitigation: &'values u64,
    child_process_policy: &'values u32,
}

impl AttributeInstaller for WindowsAttributeInstaller<'_, '_, '_> {
    fn install_job(&mut self) -> Result<(), ServiceProbeStartupError> {
        sys::install_job(self.pointer, self.job)
    }

    fn install_mitigation(&mut self) -> Result<(), ServiceProbeStartupError> {
        sys::install_mitigation(self.pointer, self.mitigation)
    }

    fn install_security_capabilities(&mut self) -> Result<(), ServiceProbeStartupError> {
        sys::install_security_capabilities(self.pointer, self.lpac)
    }

    fn install_all_application_packages_policy(&mut self) -> Result<(), ServiceProbeStartupError> {
        sys::install_all_application_packages_policy(self.pointer, self.lpac)
    }

    fn install_child_process_policy(&mut self) -> Result<(), ServiceProbeStartupError> {
        sys::install_child_process_policy(self.pointer, self.child_process_policy)
    }
}

/// Stable, non-inheriting extended startup state for one service-owned probe.
///
/// Field order is intentional: the initialized attribute list is destroyed
/// before any borrowed attribute wrapper or heap-backed value can be released.
/// The `Rc` marker keeps all preparation, revalidation, and use on one thread.
#[must_use = "startup state must remain live through child creation"]
pub(super) struct ServiceProbeStartup<'job, 'lpac, 'client> {
    attribute_list: InitializedAttributeList<WindowsAttributeListDeleter>,
    startup: Box<STARTUPINFOEXW>,
    job_attribute: ServiceProbeJobAttribute<'job>,
    lpac_attributes: PreparedTargetLpacAttributes<'lpac>,
    mitigation: Box<u64>,
    child_process_policy: Box<u32>,
    desktop: Box<[u16]>,
    job: &'job ServiceProbeJob,
    lpac: &'lpac PreparedTargetUserLpac<'client>,
    _thread_bound: PhantomData<Rc<Cell<()>>>,
}

/// Non-copying lifetime proof for the complete extended startup allocation.
///
/// The pointer names the `STARTUPINFOW` prefix of a live `STARTUPINFOEXW` and
/// must never be retained beyond this view. Keeping the raw pointer behind a
/// thread-bound move-only value prevents safe callers from copying the prefix
/// away from its adjacent attribute-list field and backing allocations.
#[must_use = "the startup view must remain live through the process-creation call"]
pub(super) struct ServiceProbeStartupView<'startup> {
    pointer: *const STARTUPINFOW,
    _owner: PhantomData<&'startup STARTUPINFOEXW>,
    _thread_bound: PhantomData<Rc<Cell<()>>>,
}

impl ServiceProbeStartupView<'_> {
    /// Returns the prefix pointer for the single audited native creation call.
    ///
    /// The view and its `ServiceProbeStartup` owner must remain live until that
    /// call returns. Dereferencing or retaining this pointer is confined to the
    /// unsafe Windows adapter.
    pub(super) const fn as_raw(&self) -> *const STARTUPINFOW {
        self.pointer
    }
}

impl fmt::Debug for ServiceProbeStartupView<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ServiceProbeStartupView([REDACTED])")
    }
}

impl<'job, 'lpac, 'client> ServiceProbeStartup<'job, 'lpac, 'client> {
    /// Creates the exact five-slot startup owner without an inherited-handle
    /// list, standard handles, or `STARTF_USESTDHANDLES`.
    pub(super) fn prepare(
        job: &'job ServiceProbeJob,
        lpac: &'lpac PreparedTargetUserLpac<'client>,
    ) -> Result<Self, ServiceProbeStartupError> {
        let job_attribute = job
            .creation_attribute()
            .map_err(|_| ServiceProbeStartupError::Job)?;
        let lpac_attributes = lpac.creation_attributes();
        let mitigation = Box::new(SERVICE_PROBE_MITIGATION_POLICY);
        let child_process_policy = Box::new(PROCESS_CREATION_CHILD_PROCESS_RESTRICTED);
        let mut desktop = DESKTOP_NAME
            .encode_utf16()
            .chain(core::iter::once(0))
            .collect::<Vec<_>>()
            .into_boxed_slice();

        let attribute_list = InitializedAttributeList::initialize()?;
        let mut installer = WindowsAttributeInstaller {
            pointer: attribute_list.pointer(),
            job: &job_attribute,
            lpac: &lpac_attributes,
            mitigation: mitigation.as_ref(),
            child_process_policy: child_process_policy.as_ref(),
        };
        let attribute_list = install_and_retain(attribute_list, &mut installer)?;
        let startup = build_startup(attribute_list.pointer(), &mut desktop)?;

        let prepared = Self {
            attribute_list,
            startup,
            job_attribute,
            lpac_attributes,
            mitigation,
            child_process_policy,
            desktop,
            job,
            lpac,
            _thread_bound: PhantomData,
        };
        prepared.verify_static_layout()?;
        Ok(prepared)
    }

    /// Borrows the complete extended allocation for one process-creation call.
    pub(super) fn process_creation_view(&self) -> ServiceProbeStartupView<'_> {
        ServiceProbeStartupView {
            pointer: core::ptr::from_ref(&self.startup.StartupInfo),
            _owner: PhantomData,
            _thread_bound: PhantomData,
        }
    }

    /// Revalidates the retained Job, target-user LPAC identity, process
    /// context, and every stable startup pointer immediately before creation.
    pub(super) fn revalidate(
        &self,
        context: &RestrictedProcessContext,
    ) -> Result<(), ServiceProbeStartupError> {
        self.job
            .recheck_non_nested()
            .map_err(|_| ServiceProbeStartupError::Job)?;
        self.lpac
            .revalidate(context)
            .map_err(|_| ServiceProbeStartupError::TargetLpac)?;
        self.verify_static_layout()
    }

    fn verify_static_layout(&self) -> Result<(), ServiceProbeStartupError> {
        if *self.mitigation != SERVICE_PROBE_MITIGATION_POLICY
            || *self.child_process_policy != PROCESS_CREATION_CHILD_PROCESS_RESTRICTED
            || !startup_layout_is_exact(
                self.startup.as_ref(),
                self.attribute_list.pointer(),
                &self.desktop,
            )
        {
            return Err(ServiceProbeStartupError::Verification);
        }
        // Keep the lifetime-bearing wrappers semantically live and make any
        // future attempt to remove their ownership visible to verification.
        let _ = (&self.job_attribute, &self.lpac_attributes);
        Ok(())
    }
}

impl fmt::Debug for ServiceProbeStartup<'_, '_, '_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ServiceProbeStartup([REDACTED])")
    }
}

fn build_startup(
    attribute_list: LPPROC_THREAD_ATTRIBUTE_LIST,
    desktop: &mut [u16],
) -> Result<Box<STARTUPINFOEXW>, ServiceProbeStartupError> {
    let mut startup = Box::new(STARTUPINFOEXW::default());
    startup.StartupInfo.cb = u32::try_from(size_of::<STARTUPINFOEXW>())
        .map_err(|_| ServiceProbeStartupError::Verification)?;
    startup.StartupInfo.lpDesktop = PWSTR(desktop.as_mut_ptr());
    startup.lpAttributeList = attribute_list;
    Ok(startup)
}

fn startup_layout_is_exact(
    startup: &STARTUPINFOEXW,
    attribute_list: LPPROC_THREAD_ATTRIBUTE_LIST,
    desktop: &[u16],
) -> bool {
    let info = &startup.StartupInfo;
    let expected_size = u32::try_from(size_of::<STARTUPINFOEXW>());
    let expected_desktop: Vec<u16> = DESKTOP_NAME
        .encode_utf16()
        .chain(core::iter::once(0))
        .collect();
    expected_size.ok() == Some(info.cb)
        && desktop == expected_desktop
        && info.lpDesktop.0 == desktop.as_ptr().cast_mut()
        && startup.lpAttributeList.0 == attribute_list.0
        && info.lpReserved.0.is_null()
        && info.lpTitle.0.is_null()
        && info.dwX == 0
        && info.dwY == 0
        && info.dwXSize == 0
        && info.dwYSize == 0
        && info.dwXCountChars == 0
        && info.dwYCountChars == 0
        && info.dwFillAttribute == 0
        && info.dwFlags.0 == 0
        && info.wShowWindow == 0
        && info.cbReserved2 == 0
        && info.lpReserved2.is_null()
        && info.hStdInput.0.is_null()
        && info.hStdOutput.0.is_null()
        && info.hStdError.0.is_null()
}

mod sys {
    #![allow(unsafe_code)]

    use core::ffi::c_void;
    use core::mem::size_of;
    use core::ptr;

    use windows::Win32::System::Threading::{
        DeleteProcThreadAttributeList, InitializeProcThreadAttributeList,
        LPPROC_THREAD_ATTRIBUTE_LIST, PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY,
        PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, UpdateProcThreadAttribute,
    };

    use super::{
        ATTRIBUTE_COUNT, PreparedTargetLpacAttributes, ServiceProbeJobAttribute,
        ServiceProbeStartupError,
    };

    pub(super) fn required_attribute_list_bytes(
        attribute_count: u32,
    ) -> Result<usize, ServiceProbeStartupError> {
        if attribute_count != ATTRIBUTE_COUNT {
            return Err(ServiceProbeStartupError::AttributeList);
        }
        let mut bytes = 0_usize;
        // SAFETY: this is the documented sizing call with a null list and one
        // writable size value. Its expected insufficient-buffer error is not a
        // failure; a zero returned size is rejected below.
        let _ = unsafe {
            InitializeProcThreadAttributeList(None, attribute_count, None, &raw mut bytes)
        };
        if bytes == 0 {
            return Err(ServiceProbeStartupError::AttributeList);
        }
        Ok(bytes)
    }

    pub(super) fn initialize_attribute_list(
        pointer: LPPROC_THREAD_ATTRIBUTE_LIST,
        attribute_count: u32,
        mut bytes: usize,
    ) -> Result<(), ServiceProbeStartupError> {
        if pointer.0.is_null() || attribute_count != ATTRIBUTE_COUNT || bytes == 0 {
            return Err(ServiceProbeStartupError::AttributeList);
        }
        // SAFETY: the caller supplies aligned writable backing of at least the
        // size returned by the immediately preceding sizing call.
        unsafe {
            InitializeProcThreadAttributeList(Some(pointer), attribute_count, None, &raw mut bytes)
        }
        .map_err(|_| ServiceProbeStartupError::AttributeList)
    }

    pub(super) fn delete_attribute_list(pointer: LPPROC_THREAD_ATTRIBUTE_LIST) {
        debug_assert!(!pointer.0.is_null());
        // SAFETY: the sole owning guard calls this once for a successfully
        // initialized list while its backing allocation is still live.
        unsafe { DeleteProcThreadAttributeList(pointer) };
    }

    pub(super) fn install_job(
        pointer: LPPROC_THREAD_ATTRIBUTE_LIST,
        job: &ServiceProbeJobAttribute<'_>,
    ) -> Result<(), ServiceProbeStartupError> {
        // SAFETY: the exact five-slot list has its first slot free, and the
        // caller retains the lifetime-bound boxed Job handle through deletion.
        unsafe { job.install_into(pointer) }
            .map_err(|_| ServiceProbeStartupError::AttributeInstallation)
    }

    pub(super) fn install_mitigation(
        pointer: LPPROC_THREAD_ATTRIBUTE_LIST,
        mitigation: &u64,
    ) -> Result<(), ServiceProbeStartupError> {
        update_scalar(
            pointer,
            PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
            ptr::from_ref(mitigation).cast::<c_void>(),
            size_of::<u64>(),
        )
    }

    pub(super) fn install_security_capabilities(
        pointer: LPPROC_THREAD_ATTRIBUTE_LIST,
        lpac: &PreparedTargetLpacAttributes<'_>,
    ) -> Result<(), ServiceProbeStartupError> {
        // SAFETY: the first two slots are occupied, the third is free, and the
        // retained target LPAC owns every pointer until list deletion.
        unsafe { lpac.install_security_capabilities_into(pointer) }
            .map_err(|_| ServiceProbeStartupError::AttributeInstallation)
    }

    pub(super) fn install_all_application_packages_policy(
        pointer: LPPROC_THREAD_ATTRIBUTE_LIST,
        lpac: &PreparedTargetLpacAttributes<'_>,
    ) -> Result<(), ServiceProbeStartupError> {
        // SAFETY: the fourth slot is free and the boxed DWORD remains stable in
        // the retained target LPAC owner until list deletion.
        unsafe { lpac.install_all_application_packages_opt_out_into(pointer) }
            .map_err(|_| ServiceProbeStartupError::AttributeInstallation)
    }

    pub(super) fn install_child_process_policy(
        pointer: LPPROC_THREAD_ATTRIBUTE_LIST,
        policy: &u32,
    ) -> Result<(), ServiceProbeStartupError> {
        update_scalar(
            pointer,
            PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY,
            ptr::from_ref(policy).cast::<c_void>(),
            size_of::<u32>(),
        )
    }

    fn update_scalar(
        pointer: LPPROC_THREAD_ATTRIBUTE_LIST,
        attribute: u32,
        value: *const c_void,
        bytes: usize,
    ) -> Result<(), ServiceProbeStartupError> {
        if pointer.0.is_null() || value.is_null() || bytes == 0 {
            return Err(ServiceProbeStartupError::AttributeInstallation);
        }
        // SAFETY: the initialized list has the next exact slot free, and each
        // scalar pointer refers to heap storage retained through list deletion.
        unsafe {
            UpdateProcThreadAttribute(
                pointer,
                0,
                usize::try_from(attribute)
                    .map_err(|_| ServiceProbeStartupError::AttributeInstallation)?,
                Some(value),
                bytes,
                None,
                None,
            )
        }
        .map_err(|_| ServiceProbeStartupError::AttributeInstallation)
    }
}

#[cfg(test)]
mod tests {
    use core::cell::Cell;
    use core::ffi::c_void;
    use std::rc::Rc;

    use windows::Win32::System::Threading::LPPROC_THREAD_ATTRIBUTE_LIST;
    use windows::Win32::System::WindowsProgramming::PROCESS_CREATION_CHILD_PROCESS_RESTRICTED;

    use super::{
        ATTRIBUTE_COUNT, AttributeInstaller, AttributeListDeleter, DESKTOP_NAME,
        InitializedAttributeList, SERVICE_PROBE_MITIGATION_POLICY, ServiceProbeStartup,
        ServiceProbeStartupError, ServiceProbeStartupView, build_startup, install_and_retain,
        install_exact_attributes, startup_layout_is_exact,
    };

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum InstallEvent {
        Job,
        Mitigation,
        SecurityCapabilities,
        AllApplicationPackagesPolicy,
        ChildProcessPolicy,
    }

    struct FakeInstaller {
        events: Vec<InstallEvent>,
        fail_at: Option<usize>,
    }

    impl FakeInstaller {
        fn record(&mut self, event: InstallEvent) -> Result<(), ServiceProbeStartupError> {
            let index = self.events.len();
            self.events.push(event);
            if self.fail_at == Some(index) {
                return Err(ServiceProbeStartupError::AttributeInstallation);
            }
            Ok(())
        }
    }

    impl AttributeInstaller for FakeInstaller {
        fn install_job(&mut self) -> Result<(), ServiceProbeStartupError> {
            self.record(InstallEvent::Job)
        }

        fn install_mitigation(&mut self) -> Result<(), ServiceProbeStartupError> {
            self.record(InstallEvent::Mitigation)
        }

        fn install_security_capabilities(&mut self) -> Result<(), ServiceProbeStartupError> {
            self.record(InstallEvent::SecurityCapabilities)
        }

        fn install_all_application_packages_policy(
            &mut self,
        ) -> Result<(), ServiceProbeStartupError> {
            self.record(InstallEvent::AllApplicationPackagesPolicy)
        }

        fn install_child_process_policy(&mut self) -> Result<(), ServiceProbeStartupError> {
            self.record(InstallEvent::ChildProcessPolicy)
        }
    }

    struct CountingDeleter(Rc<Cell<u32>>);

    impl AttributeListDeleter for CountingDeleter {
        fn delete(&mut self, _pointer: LPPROC_THREAD_ATTRIBUTE_LIST) {
            self.0.set(self.0.get() + 1);
        }
    }

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

    #[test]
    fn exact_five_attributes_are_installed_in_order_without_a_handle_list() {
        let mut installer = FakeInstaller {
            events: Vec::new(),
            fail_at: None,
        };
        assert_eq!(install_exact_attributes(&mut installer), Ok(()));
        assert_eq!(ATTRIBUTE_COUNT, 5);
        assert_eq!(
            installer.events,
            [
                InstallEvent::Job,
                InstallEvent::Mitigation,
                InstallEvent::SecurityCapabilities,
                InstallEvent::AllApplicationPackagesPolicy,
                InstallEvent::ChildProcessPolicy,
            ]
        );
    }

    #[test]
    fn every_partial_install_failure_deletes_the_initialized_list_once() {
        for fail_at in 0..5 {
            let deletes = Rc::new(Cell::new(0));
            let list = InitializedAttributeList {
                pointer: LPPROC_THREAD_ATTRIBUTE_LIST(core::ptr::dangling_mut::<c_void>()),
                words: vec![0_usize],
                deleter: CountingDeleter(Rc::clone(&deletes)),
            };
            let mut installer = FakeInstaller {
                events: Vec::new(),
                fail_at: Some(fail_at),
            };
            let result = install_and_retain(list, &mut installer);
            assert!(matches!(
                result,
                Err(ServiceProbeStartupError::AttributeInstallation)
            ));
            assert_eq!(deletes.get(), 1);
        }
    }

    #[test]
    fn startup_prefix_has_exact_desktop_size_and_null_stdio() -> Result<(), ServiceProbeStartupError>
    {
        let pointer = LPPROC_THREAD_ATTRIBUTE_LIST(core::ptr::dangling_mut::<c_void>());
        let mut desktop = DESKTOP_NAME
            .encode_utf16()
            .chain(core::iter::once(0))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let startup = build_startup(pointer, &mut desktop)?;
        assert!(startup_layout_is_exact(&startup, pointer, &desktop));
        Ok(())
    }

    #[test]
    fn mitigation_and_child_policies_match_the_existing_launch_contract() {
        assert_eq!(SERVICE_PROBE_MITIGATION_POLICY, 0x1110_1011_0111_1105);
        assert_eq!(PROCESS_CREATION_CHILD_PROCESS_RESTRICTED, 1);
    }

    #[test]
    fn owner_is_move_only_and_thread_bound() {
        type Owner = ServiceProbeStartup<'static, 'static, 'static>;
        type View = ServiceProbeStartupView<'static>;

        let _ = <Owner as AmbiguousIfSend<_>>::marker;
        let _ = <Owner as AmbiguousIfSync<_>>::marker;
        let _ = <Owner as AmbiguousIfClone<_>>::marker;
        let _ = <Owner as AmbiguousIfCopy<_>>::marker;
        let _ = <View as AmbiguousIfSend<_>>::marker;
        let _ = <View as AmbiguousIfSync<_>>::marker;
        let _ = <View as AmbiguousIfClone<_>>::marker;
        let _ = <View as AmbiguousIfCopy<_>>::marker;
    }

    #[test]
    fn errors_and_owner_debug_are_data_free() {
        assert_eq!(
            format!("{:?}", ServiceProbeStartupError::AttributeInstallation),
            "AttributeInstallation"
        );
    }
}
