//! Public fixed-frame, endpoint, and native-link contract checks.

#[cfg(not(windows))]
use core::{ffi::c_void, ptr::NonNull};

#[cfg(not(windows))]
use key_agent_service_rpc_sys::{BindingHandle, RpcStatus, exchange};
use key_agent_service_rpc_sys::{
    FrameError, INTERFACE_UUID, INTERFACE_VERSION_MAJOR, INTERFACE_VERSION_MINOR,
    LOCAL_RPC_ENDPOINT, LOCAL_RPC_ENDPOINT_WIDE, RPC_FRAME_CAPACITY, RPC_FRAME_SIZE, RpcFrame,
};

#[test]
fn public_frame_contract_is_fixed_and_bounded() {
    assert_eq!(RPC_FRAME_CAPACITY, 72);
    assert_eq!(RPC_FRAME_SIZE, 76);
    assert_eq!(core::mem::size_of::<RpcFrame>(), 76);
    assert_eq!(INTERFACE_VERSION_MAJOR, 1);
    assert_eq!(INTERFACE_VERSION_MINOR, 0);
    assert_eq!(
        INTERFACE_UUID,
        [
            0x4c, 0xb7, 0xf9, 0x5a, 0x26, 0x97, 0x4f, 0x96, 0xbd, 0x29, 0x56, 0xe4, 0xb9, 0x78,
            0x74, 0x8a,
        ]
    );
    assert_eq!(LOCAL_RPC_ENDPOINT_WIDE.last(), Some(&0));
    assert_eq!(LOCAL_RPC_ENDPOINT, "YourWallet.KeyAgentService.v1");
    let decoded_endpoint =
        String::from_utf16(&LOCAL_RPC_ENDPOINT_WIDE[..LOCAL_RPC_ENDPOINT_WIDE.len() - 1]);
    assert!(decoded_endpoint.is_ok());
    if let Ok(decoded_endpoint) = decoded_endpoint {
        assert_eq!(decoded_endpoint, LOCAL_RPC_ENDPOINT);
    }

    let maximum = RpcFrame::from_payload(&[0xa5; RPC_FRAME_CAPACITY]);
    assert!(maximum.is_ok());
    if let Ok(maximum) = maximum {
        assert_eq!(maximum.len(), RPC_FRAME_CAPACITY);
    }
    assert_eq!(
        RpcFrame::from_payload(&[0; RPC_FRAME_CAPACITY + 1]),
        Err(FrameError::PayloadTooLarge)
    );
}

#[cfg(not(windows))]
#[test]
fn non_windows_exchange_is_unavailable_without_mutation() {
    let raw = NonNull::<u8>::dangling().as_ptr().cast::<c_void>();
    // SAFETY: the inert non-Windows implementation never dereferences raw.
    let binding = unsafe { BindingHandle::from_raw(raw) };
    let request = RpcFrame::from_payload(b"fixed request");
    assert!(binding.is_some());
    assert!(request.is_ok());
    if let (Some(binding), Ok(request)) = (binding, request) {
        let before = request;
        assert_eq!(exchange(&binding, &request), Err(RpcStatus::UNAVAILABLE));
        assert_eq!(request, before);
    }
}

#[cfg(windows)]
#[test]
fn checked_in_client_and_server_ifspecs_link() {
    assert!(key_agent_service_rpc_sys::client_interface_spec().is_some());
    assert!(key_agent_service_rpc_sys::server_interface_spec().is_some());
}
