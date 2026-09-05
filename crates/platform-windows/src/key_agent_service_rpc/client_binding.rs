//! Thread-bound, fixed-endpoint owner for the non-signing desktop RPC probe.
//!
//! The parent module enables this leaf only for the explicit Windows x64 MSVC
//! debug feature. It does not authenticate an installed service image or expose
//! a general binding, endpoint, credentials, or raw-handle interface.
//! Synchronous local RPC has no supported call-timeout option. These deadline
//! checks reject late results; the standalone binary's process watchdog bounds
//! a call that never returns. This library leaf cannot promise that liveness.

#![allow(unsafe_code)]

use core::{ffi::c_void, fmt, marker::PhantomData};
use std::rc::Rc;
use std::time::Instant;

use key_agent_service_rpc_sys::{BindingHandle, RpcFrame};
use windows::Win32::System::Rpc::{
    RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, RPC_STATUS, RpcBindingFree, RpcBindingFromStringBindingW,
    RpcBindingSetAuthInfoW, RpcStringBindingComposeW, RpcStringFreeW,
};
use windows::core::{PCWSTR, PWSTR};

const LOCAL_RPC_PROTOCOL_SEQUENCE_WIDE: [u16; 8] = [110, 99, 97, 108, 114, 112, 99, 0];
const RPC_AUTHN_LEVEL_PACKET_PRIVACY: u32 = 6;
const MAX_REMAINING_MILLISECONDS: u32 = 25_000;

/// Data-free failure confined to the native desktop-probe adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ClientBindingError {
    Unavailable,
    Deadline,
}

/// One non-transferable owner of the fixed, implicitly authenticated binding.
pub(super) struct FixedDesktopRpcBinding {
    raw: *mut c_void,
    _thread_bound: PhantomData<Rc<()>>,
}

impl FixedDesktopRpcBinding {
    pub(super) fn connect() -> Result<Self, ClientBindingError> {
        let mut string = PWSTR::null();
        // SAFETY: all inputs are fixed NUL-terminated strings or null optional
        // fields. The runtime receives one live output slot for its own string.
        let status = unsafe {
            RpcStringBindingComposeW(
                PCWSTR::null(),
                PCWSTR(LOCAL_RPC_PROTOCOL_SEQUENCE_WIDE.as_ptr()),
                PCWSTR::null(),
                PCWSTR(key_agent_service_rpc_sys::LOCAL_RPC_ENDPOINT_WIDE.as_ptr()),
                PCWSTR::null(),
                Some(&raw mut string),
            )
        };
        let string = OwnedRpcString(string);
        rpc_success(status)?;
        if string.0.is_null() {
            return Err(ClientBindingError::Unavailable);
        }

        let mut raw = core::ptr::null_mut();
        // SAFETY: the runtime-owned string remains live throughout conversion;
        // the independent binding result is immediately placed in its owner.
        let status =
            unsafe { RpcBindingFromStringBindingW(PCWSTR(string.0.0.cast_const()), &raw mut raw) };
        let binding = Self {
            raw,
            _thread_bound: PhantomData,
        };
        rpc_success(status)?;
        if binding.raw.is_null() {
            return Err(ClientBindingError::Unavailable);
        }

        // SAFETY: this live owner fixes WINNT packet privacy and AUTHZ_NONE,
        // with implicit current-process credentials and no selected principal.
        // This authenticates transport, not the exact installed service image.
        rpc_success(unsafe {
            RpcBindingSetAuthInfoW(
                binding.raw.cast_const(),
                PCWSTR::null(),
                RPC_AUTHN_LEVEL_PACKET_PRIVACY,
                RPC_C_AUTHN_WINNT,
                None,
                RPC_C_AUTHZ_NONE,
            )
        })?;
        Ok(binding)
    }

    pub(super) fn exchange(
        &mut self,
        request: &RpcFrame,
        deadline: Instant,
    ) -> Result<RpcFrame, ClientBindingError> {
        if !request.is_canonical() {
            return Err(ClientBindingError::Unavailable);
        }
        remaining_milliseconds(deadline, Instant::now())?;
        // SAFETY: the unique owner remains live throughout the synchronous
        // generated call. No borrowed raw binding can escape this method.
        let borrowed =
            unsafe { BindingHandle::from_raw(self.raw) }.ok_or(ClientBindingError::Unavailable)?;
        let result = key_agent_service_rpc_sys::exchange(&borrowed, request);
        // Even an RPC transport error is followed by a fresh deadline check;
        // no late result becomes success. A blocked local RPC call is bounded
        // only by the standalone executable's independent process watchdog.
        remaining_milliseconds(deadline, Instant::now())?;
        result.map_err(|_| ClientBindingError::Unavailable)
    }
}

impl fmt::Debug for FixedDesktopRpcBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FixedDesktopRpcBinding([REDACTED])")
    }
}

impl Drop for FixedDesktopRpcBinding {
    fn drop(&mut self) {
        if self.raw.is_null() {
            return;
        }
        // SAFETY: this is the exact owner returned by Rpcrt4. Every generated
        // call has synchronously returned before the owner can be dropped.
        let status = unsafe { RpcBindingFree(&raw mut self.raw) };
        if status.0 != 0 || !self.raw.is_null() {
            std::process::abort();
        }
    }
}

struct OwnedRpcString(PWSTR);

impl Drop for OwnedRpcString {
    fn drop(&mut self) {
        if self.0.is_null() {
            return;
        }
        // SAFETY: this is the exact string allocation returned by Rpcrt4.
        let status = unsafe { RpcStringFreeW(&raw mut self.0) };
        if status.0 != 0 || !self.0.is_null() {
            std::process::abort();
        }
    }
}

fn rpc_success(status: RPC_STATUS) -> Result<(), ClientBindingError> {
    if status.0 == 0 {
        Ok(())
    } else {
        Err(ClientBindingError::Unavailable)
    }
}

fn remaining_milliseconds(deadline: Instant, now: Instant) -> Result<u32, ClientBindingError> {
    let remaining = deadline
        .checked_duration_since(now)
        .ok_or(ClientBindingError::Deadline)?;
    // Floor fractional milliseconds conservatively: less than one whole
    // millisecond is unavailable. This is result validation, not an RPC timer.
    let milliseconds =
        u32::try_from(remaining.as_millis()).map_err(|_| ClientBindingError::Deadline)?;
    if milliseconds == 0 || milliseconds > MAX_REMAINING_MILLISECONDS {
        return Err(ClientBindingError::Deadline);
    }
    Ok(milliseconds)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    trait AmbiguousIfSend<Marker> {
        fn marker() {}
    }
    impl<Type: ?Sized> AmbiguousIfSend<()> for Type {}
    impl<Type: ?Sized + Send> AmbiguousIfSend<u8> for Type {}
    trait AmbiguousIfSync<Marker> {
        fn marker() {}
    }
    impl<Type: ?Sized> AmbiguousIfSync<()> for Type {}
    impl<Type: ?Sized + Sync> AmbiguousIfSync<u8> for Type {}
    trait AmbiguousIfClone<Marker> {
        fn marker() {}
    }
    impl<Type: ?Sized> AmbiguousIfClone<()> for Type {}
    impl<Type: Clone> AmbiguousIfClone<u8> for Type {}
    trait AmbiguousIfCopy<Marker> {
        fn marker() {}
    }
    impl<Type: ?Sized> AmbiguousIfCopy<()> for Type {}
    impl<Type: Copy> AmbiguousIfCopy<u8> for Type {}

    #[test]
    fn binding_ownership_is_thread_bound_and_move_only() {
        let _ = <FixedDesktopRpcBinding as AmbiguousIfSend<_>>::marker;
        let _ = <FixedDesktopRpcBinding as AmbiguousIfSync<_>>::marker;
        let _ = <FixedDesktopRpcBinding as AmbiguousIfClone<_>>::marker;
        let _ = <FixedDesktopRpcBinding as AmbiguousIfCopy<_>>::marker;
    }

    #[test]
    fn binding_and_authentication_choices_are_fixed() {
        assert_eq!(
            LOCAL_RPC_PROTOCOL_SEQUENCE_WIDE,
            [110, 99, 97, 108, 114, 112, 99, 0],
        );
        assert_eq!(RPC_AUTHN_LEVEL_PACKET_PRIVACY, 6);
        assert_eq!(RPC_C_AUTHN_WINNT, 10);
        assert_eq!(RPC_C_AUTHZ_NONE, 0);
        assert_eq!(MAX_REMAINING_MILLISECONDS, 25_000);
        assert_eq!(
            key_agent_service_rpc_sys::LOCAL_RPC_ENDPOINT,
            "YourWallet.KeyAgentService.v1",
        );
    }

    #[test]
    fn remaining_deadline_is_nonzero_bounded_and_never_rounds_up() -> Result<(), ClientBindingError>
    {
        let now = Instant::now();
        let past = now
            .checked_sub(Duration::from_millis(1))
            .ok_or(ClientBindingError::Deadline)?;
        assert_eq!(
            remaining_milliseconds(now + Duration::from_secs(25), now),
            Ok(25_000),
        );
        assert_eq!(
            remaining_milliseconds(now + Duration::from_micros(1_999), now),
            Ok(1),
        );
        for deadline in [
            past,
            now,
            now + Duration::from_micros(999),
            now + Duration::from_millis(25_001),
            now + Duration::from_secs(u64::from(u32::MAX)),
        ] {
            assert_eq!(
                remaining_milliseconds(deadline, now),
                Err(ClientBindingError::Deadline),
            );
        }
        Ok(())
    }

    #[test]
    fn native_status_mapping_discards_operating_system_details() {
        assert_eq!(rpc_success(RPC_STATUS(0)), Ok(()));
        for status in [1, 5, 87, 1_722, 1_723, 1_726, i32::MAX] {
            assert_eq!(
                rpc_success(RPC_STATUS(status)),
                Err(ClientBindingError::Unavailable),
            );
        }
    }
}
