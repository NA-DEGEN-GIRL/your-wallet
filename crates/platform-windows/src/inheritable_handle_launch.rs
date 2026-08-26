//! Process-wide coordination for Windows launches that temporarily own
//! inheritable handles.
//!
//! `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` constrains what one child receives, but
//! it does not stop a different concurrent `bInheritHandles=TRUE` launch in the
//! same parent from observing the temporary handles. Every production launch
//! in this crate therefore acquires this one non-reentrant flight before the
//! first inheritable handle is created, closes every such handle immediately
//! after `CreateProcessW` returns, and only then releases the flight.

#![allow(unsafe_code)]

use core::ffi::c_void;
use core::fmt;
use core::marker::PhantomData;
use std::cell::Cell;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::thread::ThreadId;
use std::time::{Duration, Instant};

use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::System::Threading::{
    CreateProcessW, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTUPINFOW,
};
use windows::core::{PCWSTR, PWSTR};

static PROCESS_WIDE_INHERITABLE_LAUNCH: InheritableHandleLaunchCoordinator =
    InheritableHandleLaunchCoordinator::new();

thread_local! {
    static OWNED_COORDINATORS: Cell<[usize; 4]> = const { Cell::new([0; 4]) };
}

const WAIT_POLL_INTERVAL: Duration = Duration::from_millis(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InheritableHandleLaunchError {
    Deadline,
    Reentrant,
    Poisoned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InheritableHandleCreateError {
    Deadline,
    WrongThread,
    Poisoned,
    OperatingSystem,
}

/// Borrowed process/thread creation security attributes supplied as one unit.
///
/// Construction requires both values so callers cannot accidentally provide
/// only one side of the `CreateProcessW` security contract.
#[derive(Clone, Copy)]
pub(crate) struct ProcessThreadCreationSecurity<'attributes> {
    process: &'attributes SECURITY_ATTRIBUTES,
    thread: &'attributes SECURITY_ATTRIBUTES,
}

impl<'attributes> ProcessThreadCreationSecurity<'attributes> {
    pub(crate) const fn new(
        process: &'attributes SECURITY_ATTRIBUTES,
        thread: &'attributes SECURITY_ATTRIBUTES,
    ) -> Self {
        Self { process, thread }
    }

    /// Borrows the mandatory process/thread pair without exposing either value
    /// independently through the public launch API.
    pub(crate) const fn as_pair(
        self,
    ) -> (
        &'attributes SECURITY_ATTRIBUTES,
        &'attributes SECURITY_ATTRIBUTES,
    ) {
        (self.process, self.thread)
    }
}

struct InheritableHandleLaunchCoordinator {
    occupied: AtomicBool,
    poisoned: AtomicBool,
    generation: AtomicU64,
    active_generation: AtomicU64,
    waiters: AtomicUsize,
}

struct WaiterRegistration<'coordinator> {
    coordinator: &'coordinator InheritableHandleLaunchCoordinator,
    registered: bool,
}

impl<'coordinator> WaiterRegistration<'coordinator> {
    fn new(coordinator: &'coordinator InheritableHandleLaunchCoordinator) -> Self {
        Self {
            coordinator,
            registered: false,
        }
    }

    fn register(&mut self) -> Result<(), InheritableHandleLaunchError> {
        if self.registered {
            return Ok(());
        }
        if self
            .coordinator
            .waiters
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |waiters| {
                waiters.checked_add(1)
            })
            .is_err()
        {
            self.coordinator.poisoned.store(true, Ordering::SeqCst);
            return Err(InheritableHandleLaunchError::Poisoned);
        }
        self.registered = true;
        Ok(())
    }
}

impl Drop for WaiterRegistration<'_> {
    fn drop(&mut self) {
        if self.registered
            && self
                .coordinator
                .waiters
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |waiters| {
                    waiters.checked_sub(1)
                })
                .is_err()
        {
            self.coordinator.poisoned.store(true, Ordering::SeqCst);
        }
    }
}

impl InheritableHandleLaunchCoordinator {
    const fn new() -> Self {
        Self {
            occupied: AtomicBool::new(false),
            poisoned: AtomicBool::new(false),
            generation: AtomicU64::new(0),
            active_generation: AtomicU64::new(0),
            waiters: AtomicUsize::new(0),
        }
    }

    fn key(&self) -> usize {
        core::ptr::from_ref(self) as usize
    }

    fn current_thread_owns(&self) -> Result<bool, InheritableHandleLaunchError> {
        OWNED_COORDINATORS
            .try_with(|owners| owners.get().contains(&self.key()))
            .map_err(|_| InheritableHandleLaunchError::Poisoned)
    }

    fn record_current_thread_owner(&self) -> Result<(), InheritableHandleLaunchError> {
        OWNED_COORDINATORS
            .try_with(|owners| {
                let mut slots = owners.get();
                if slots.contains(&self.key()) {
                    return Err(InheritableHandleLaunchError::Reentrant);
                }
                let Some(slot) = slots.iter_mut().find(|slot| **slot == 0) else {
                    return Err(InheritableHandleLaunchError::Poisoned);
                };
                *slot = self.key();
                owners.set(slots);
                Ok(())
            })
            .map_err(|_| InheritableHandleLaunchError::Poisoned)?
    }

    fn clear_current_thread_owner(&self) -> bool {
        OWNED_COORDINATORS
            .try_with(|owners| {
                let mut slots = owners.get();
                let Some(slot) = slots.iter_mut().find(|slot| **slot == self.key()) else {
                    return false;
                };
                *slot = 0;
                owners.set(slots);
                true
            })
            .unwrap_or(false)
    }

    fn acquire(
        &self,
        deadline: Instant,
    ) -> Result<InheritableHandleLaunchFlight<'_>, InheritableHandleLaunchError> {
        let owner = std::thread::current().id();
        if self.current_thread_owns()? {
            return Err(InheritableHandleLaunchError::Reentrant);
        }
        let mut waiter = WaiterRegistration::new(self);
        loop {
            if self.poisoned.load(Ordering::SeqCst) {
                return Err(InheritableHandleLaunchError::Poisoned);
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(InheritableHandleLaunchError::Deadline);
            }
            if self
                .occupied
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                if self.poisoned.load(Ordering::SeqCst) {
                    self.occupied.store(false, Ordering::SeqCst);
                    return Err(InheritableHandleLaunchError::Poisoned);
                }
                if Instant::now() >= deadline {
                    self.occupied.store(false, Ordering::SeqCst);
                    return Err(InheritableHandleLaunchError::Deadline);
                }
                let generation = if let Ok(previous) =
                    self.generation
                        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |generation| {
                            generation.checked_add(1)
                        }) {
                    previous + 1
                } else {
                    self.poisoned.store(true, Ordering::SeqCst);
                    self.occupied.store(false, Ordering::SeqCst);
                    return Err(InheritableHandleLaunchError::Poisoned);
                };
                self.active_generation.store(generation, Ordering::SeqCst);
                if let Err(error) = self.record_current_thread_owner() {
                    self.active_generation.store(0, Ordering::SeqCst);
                    self.poisoned.store(true, Ordering::SeqCst);
                    self.occupied.store(false, Ordering::SeqCst);
                    return Err(error);
                }
                drop(waiter);
                return Ok(InheritableHandleLaunchFlight {
                    coordinator: self,
                    owner,
                    generation,
                    deadline,
                    _not_send_or_sync: PhantomData,
                });
            }
            if self.current_thread_owns()? {
                return Err(InheritableHandleLaunchError::Reentrant);
            }
            waiter.register()?;
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return Err(InheritableHandleLaunchError::Deadline);
            };
            if remaining.is_zero() {
                return Err(InheritableHandleLaunchError::Deadline);
            }
            std::thread::park_timeout(remaining.min(WAIT_POLL_INTERVAL));
        }
    }

    fn release(&self, owner: ThreadId, generation: u64, panicking: bool) {
        let wrong_thread = std::thread::current().id() != owner;
        let missing_thread_owner = !self.clear_current_thread_owner();
        let wrong_generation = self
            .active_generation
            .compare_exchange(generation, 0, Ordering::SeqCst, Ordering::SeqCst)
            .is_err();
        if wrong_thread || missing_thread_owner || wrong_generation || panicking {
            self.poisoned.store(true, Ordering::SeqCst);
        }
        self.occupied.store(false, Ordering::SeqCst);
    }

    #[cfg(test)]
    fn waiter_count(&self) -> usize {
        self.waiters.load(Ordering::SeqCst)
    }
}

/// One process-wide, thread-bound inheritable-handle launch flight.
///
/// The constructor is private to this module. The `Rc` marker makes the value
/// `!Send + !Sync`; inheritable-handle owners borrow it so the exact creating
/// thread must close them before the flight can be released. Reentrant attempts
/// fail immediately, concurrent attempts wait only to their trusted deadline,
/// and unwinding through a live flight permanently poisons this coordinator.
#[must_use = "the process-wide launch flight must cover every inheritable handle"]
pub(crate) struct InheritableHandleLaunchFlight<'coordinator> {
    coordinator: &'coordinator InheritableHandleLaunchCoordinator,
    owner: ThreadId,
    generation: u64,
    deadline: Instant,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

impl InheritableHandleLaunchFlight<'_> {
    fn validate_create_admission(&self) -> Result<(), InheritableHandleCreateError> {
        let current_thread_owns = self.coordinator.current_thread_owns().unwrap_or(false);
        if std::thread::current().id() != self.owner || !current_thread_owns {
            self.coordinator.poisoned.store(true, Ordering::SeqCst);
            return Err(InheritableHandleCreateError::WrongThread);
        }
        if self.coordinator.poisoned.load(Ordering::SeqCst) {
            return Err(InheritableHandleCreateError::Poisoned);
        }
        if !self.coordinator.occupied.load(Ordering::SeqCst)
            || self.coordinator.active_generation.load(Ordering::SeqCst) != self.generation
        {
            self.coordinator.poisoned.store(true, Ordering::SeqCst);
            return Err(InheritableHandleCreateError::Poisoned);
        }
        if Instant::now() >= self.deadline {
            return Err(InheritableHandleCreateError::Deadline);
        }
        Ok(())
    }

    /// Calls the crate's sole Rust `CreateProcessW` boundary with inheritance
    /// enabled. Callers must supply a live `STARTUPINFOEXW` whose explicit
    /// handle list contains only handles created under this same flight.
    ///
    /// # Safety
    ///
    /// All pointers must remain valid for the complete call, the startup value
    /// must actually be the `StartupInfo` prefix of a live `STARTUPINFOEXW`, and
    /// every handle listed by its attributes must be valid and inheritable.
    #[allow(clippy::too_many_arguments)]
    pub(crate) unsafe fn create_process_with_explicit_handle_list(
        &self,
        application_name: PCWSTR,
        command_line: Option<PWSTR>,
        process_thread_security: Option<ProcessThreadCreationSecurity<'_>>,
        creation_flags: PROCESS_CREATION_FLAGS,
        environment: Option<*const c_void>,
        current_directory: PCWSTR,
        startup_info: *const STARTUPINFOW,
        process_information: *mut PROCESS_INFORMATION,
    ) -> Result<(), InheritableHandleCreateError> {
        self.validate_create_admission()?;
        let (process_attributes, thread_attributes) =
            process_thread_security.map_or((None, None), |security| {
                let (process, thread) = security.as_pair();
                (
                    Some(core::ptr::from_ref(process)),
                    Some(core::ptr::from_ref(thread)),
                )
            });
        // SAFETY: the caller upholds the documented pointer, attribute-list,
        // security-attribute, and handle-lifetime contract. Security attributes
        // are either both absent or both borrowed for this call, while TRUE
        // inheritance is constrained by the explicit handle list.
        unsafe {
            CreateProcessW(
                application_name,
                command_line,
                process_attributes,
                thread_attributes,
                true,
                creation_flags,
                environment,
                current_directory,
                startup_info,
                process_information,
            )
        }
        .map_err(|_| InheritableHandleCreateError::OperatingSystem)
    }
}

impl fmt::Debug for InheritableHandleLaunchFlight<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InheritableHandleLaunchFlight([PROCESS-WIDE])")
    }
}

impl Drop for InheritableHandleLaunchFlight<'_> {
    fn drop(&mut self) {
        self.coordinator
            .release(self.owner, self.generation, std::thread::panicking());
    }
}

/// Acquires the sole process-wide inheritable-handle launch flight.
pub(crate) fn acquire_inheritable_handle_launch(
    deadline: Instant,
) -> Result<InheritableHandleLaunchFlight<'static>, InheritableHandleLaunchError> {
    PROCESS_WIDE_INHERITABLE_LAUNCH.acquire(deadline)
}

#[cfg(test)]
mod tests {
    use windows::Win32::Security::SECURITY_ATTRIBUTES;

    use super::{
        InheritableHandleLaunchCoordinator, InheritableHandleLaunchError,
        ProcessThreadCreationSecurity,
    };
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier, mpsc};
    use std::time::{Duration, Instant};

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    #[test]
    fn process_thread_creation_security_retains_both_borrowed_values() {
        let process = SECURITY_ATTRIBUTES::default();
        let thread = SECURITY_ATTRIBUTES::default();
        let security = ProcessThreadCreationSecurity::new(&process, &thread);
        let (retained_process, retained_thread) = security.as_pair();

        assert!(core::ptr::eq(retained_process, &raw const process));
        assert!(core::ptr::eq(retained_thread, &raw const thread));
    }

    fn wait_until_waiter_is_parked(coordinator: &InheritableHandleLaunchCoordinator) {
        let observation_deadline = deadline();
        while coordinator.waiter_count() == 0 {
            assert!(
                Instant::now() < observation_deadline,
                "waiter did not enter the coordinator"
            );
            std::thread::yield_now();
        }
    }

    #[test]
    fn local_coordinator_serializes_until_the_exact_flight_drops()
    -> Result<(), InheritableHandleLaunchError> {
        let coordinator = Arc::new(InheritableHandleLaunchCoordinator::new());
        let first = coordinator.acquire(deadline())?;
        let second_coordinator = Arc::clone(&coordinator);
        let (started_sender, started_receiver) = mpsc::sync_channel(1);
        let (acquired_sender, acquired_receiver) = mpsc::sync_channel(1);

        let waiter = std::thread::spawn(move || -> Result<(), InheritableHandleLaunchError> {
            started_sender
                .send(())
                .map_err(|_| InheritableHandleLaunchError::Poisoned)?;
            let _second = second_coordinator.acquire(deadline())?;
            acquired_sender
                .send(())
                .map_err(|_| InheritableHandleLaunchError::Poisoned)
        });

        assert!(
            started_receiver
                .recv_timeout(Duration::from_secs(5))
                .is_ok()
        );
        wait_until_waiter_is_parked(&coordinator);
        assert!(matches!(
            acquired_receiver.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        drop(first);
        assert!(
            acquired_receiver
                .recv_timeout(Duration::from_secs(5))
                .is_ok()
        );
        match waiter.join() {
            Ok(result) => result?,
            Err(payload) => std::panic::resume_unwind(payload),
        }
        Ok(())
    }

    #[test]
    fn local_coordinator_never_overlaps_many_contenders() {
        const THREADS: usize = 8;
        const FLIGHTS_PER_THREAD: usize = 64;

        let coordinator = Arc::new(InheritableHandleLaunchCoordinator::new());
        let barrier = Arc::new(Barrier::new(THREADS));
        let active = Arc::new(AtomicUsize::new(0));
        let overlapped = Arc::new(AtomicBool::new(false));
        let workers = (0..THREADS)
            .map(|_| {
                let coordinator = Arc::clone(&coordinator);
                let barrier = Arc::clone(&barrier);
                let active = Arc::clone(&active);
                let overlapped = Arc::clone(&overlapped);
                std::thread::spawn(move || -> Result<(), InheritableHandleLaunchError> {
                    barrier.wait();
                    for _ in 0..FLIGHTS_PER_THREAD {
                        let flight = coordinator.acquire(deadline())?;
                        if active.fetch_add(1, Ordering::SeqCst) != 0 {
                            overlapped.store(true, Ordering::SeqCst);
                        }
                        std::thread::yield_now();
                        assert_eq!(active.fetch_sub(1, Ordering::SeqCst), 1);
                        drop(flight);
                    }
                    Ok(())
                })
            })
            .collect::<Vec<_>>();
        for worker in workers {
            match worker.join() {
                Ok(result) => assert!(result.is_ok()),
                Err(payload) => std::panic::resume_unwind(payload),
            }
        }
        assert!(!overlapped.load(Ordering::SeqCst));
        assert_eq!(coordinator.waiter_count(), 0);
    }

    #[test]
    fn local_coordinator_rejects_same_thread_reentrancy() -> Result<(), InheritableHandleLaunchError>
    {
        let coordinator = InheritableHandleLaunchCoordinator::new();
        let _first = coordinator.acquire(deadline())?;
        assert!(matches!(
            coordinator.acquire(deadline()),
            Err(InheritableHandleLaunchError::Reentrant)
        ));
        Ok(())
    }

    #[test]
    fn distinct_local_coordinators_have_independent_thread_ownership()
    -> Result<(), InheritableHandleLaunchError> {
        let first_coordinator = InheritableHandleLaunchCoordinator::new();
        let second_coordinator = InheritableHandleLaunchCoordinator::new();
        let first = first_coordinator.acquire(deadline())?;
        let second = second_coordinator.acquire(deadline())?;
        assert!(first.validate_create_admission().is_ok());
        assert!(second.validate_create_admission().is_ok());
        drop(second);
        drop(first);
        Ok(())
    }

    #[test]
    fn local_coordinator_rejects_an_expired_deadline_while_idle()
    -> Result<(), InheritableHandleLaunchError> {
        let coordinator = InheritableHandleLaunchCoordinator::new();
        let expired = Instant::now();
        assert!(matches!(
            coordinator.acquire(expired),
            Err(InheritableHandleLaunchError::Deadline)
        ));
        drop(coordinator.acquire(deadline())?);
        Ok(())
    }

    #[test]
    fn flight_rechecks_its_absolute_deadline_at_create_admission()
    -> Result<(), InheritableHandleLaunchError> {
        let coordinator = InheritableHandleLaunchCoordinator::new();
        let create_deadline = Instant::now() + Duration::from_millis(5);
        let flight = coordinator.acquire(create_deadline)?;
        while Instant::now() < create_deadline {
            std::thread::yield_now();
        }
        assert_eq!(
            flight.validate_create_admission(),
            Err(super::InheritableHandleCreateError::Deadline)
        );
        Ok(())
    }

    #[test]
    fn local_coordinator_bounds_concurrent_wait_by_deadline()
    -> Result<(), InheritableHandleLaunchError> {
        let coordinator = Arc::new(InheritableHandleLaunchCoordinator::new());
        let first = coordinator.acquire(deadline())?;
        let second_coordinator = Arc::clone(&coordinator);
        let waiter = std::thread::spawn(move || {
            let short_deadline = Instant::now() + Duration::from_millis(25);
            second_coordinator.acquire(short_deadline).err()
        });
        let error = match waiter.join() {
            Ok(error) => error,
            Err(payload) => std::panic::resume_unwind(payload),
        };
        assert_eq!(error, Some(InheritableHandleLaunchError::Deadline));
        drop(first);
        Ok(())
    }

    #[test]
    fn local_coordinator_permanently_poisoned_by_in_flight_unwind() {
        let coordinator = Arc::new(InheritableHandleLaunchCoordinator::new());
        let panicking_coordinator = Arc::clone(&coordinator);
        let result = std::thread::spawn(move || {
            let Ok(_flight) = panicking_coordinator.acquire(deadline()) else {
                return;
            };
            std::panic::resume_unwind(Box::new("intentional coordinator poison test"));
        })
        .join();
        assert!(result.is_err());
        assert!(matches!(
            coordinator.acquire(deadline()),
            Err(InheritableHandleLaunchError::Poisoned)
        ));
    }
}
