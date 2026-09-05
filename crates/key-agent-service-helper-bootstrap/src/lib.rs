//! Dormant child-side bootstrap primitives for Windows Key Agent service helpers.
//!
//! Gate byte specifications and correlation codecs are platform-neutral.
//! Capturing and adopting injected channel candidates is available only to an
//! explicit Windows x64 debug feasibility build; default and release builds
//! expose no handle authority.

mod gate_spec;

mod wire;

pub use self::gate_spec::{
    ADOPTION_COMPLETE_GATE_BREAKPOINT_OFFSET, ADOPTION_COMPLETE_GATE_BYTES,
    ADOPTION_COMPLETE_R10_MARKER, ADOPTION_COMPLETE_R11_MARKER, CAPTURE_GATE_BREAKPOINT_OFFSET,
    CAPTURE_GATE_BYTES, REQUEST_INPUT_MARKER, RESPONSE_OUTPUT_MARKER, adoption_complete_gate_bytes,
    capture_gate_bytes,
};

pub use self::wire::{
    AdoptionWireError, HELPER_ADOPTION_ACK_BYTES, HELPER_BOOTSTRAP_HELLO_BYTES,
    HELPER_RPC_CONFIRMATION_BYTES, HelperAdoptionAck, HelperBootstrapHello, HelperBootstrapRole,
    HelperRpcConfirmation, MAX_SERVICE_APPROVAL_REQUEST_BYTES,
    SERVICE_APPROVAL_REQUEST_PREFIX_BYTES, decode_adoption_ack, decode_bootstrap_hello,
    decode_rpc_confirmation, decode_service_approval_request_prefix, encode_adoption_ack,
    encode_bootstrap_hello, encode_rpc_confirmation, encode_service_approval_request_prefix,
};

#[cfg(all(
    windows,
    target_arch = "x86_64",
    feature = "child-capture-feasibility-test-hook",
    debug_assertions
))]
mod child;

#[cfg(all(
    windows,
    target_arch = "x86_64",
    feature = "child-capture-feasibility-test-hook",
    debug_assertions
))]
pub use self::child::{
    AdoptedInjectedChannels, BootstrappedInjectedChannels, capture_and_adopt_injected_channels,
    complete_injected_channel_bootstrap,
};

#[cfg(all(
    windows,
    target_arch = "x86_64",
    target_env = "msvc",
    feature = "helper-ready-rpc-feasibility-test-hook",
    debug_assertions
))]
pub use self::child::complete_helper_ready_rpc_probe;

#[cfg(all(
    windows,
    target_arch = "x86_64",
    target_env = "msvc",
    feature = "approval-exchange-feasibility-test-hook",
    debug_assertions
))]
pub use self::child::{ServiceApprovalRequest, receive_service_approval_request};
