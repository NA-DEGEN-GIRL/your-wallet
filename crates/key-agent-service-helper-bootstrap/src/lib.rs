//! Dormant child-side bootstrap primitives for Windows Key Agent service helpers.
//!
//! The correlation codec is platform-neutral. Capturing and adopting injected
//! channel candidates is available only to an explicit Windows x64 debug
//! feasibility build; default and release builds expose no handle authority.

mod wire;

pub use self::wire::{
    AdoptionWireError, HELPER_ADOPTION_ACK_BYTES, HelperAdoptionAck, HelperBootstrapRole,
    decode_adoption_ack, encode_adoption_ack,
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
    AdoptedInjectedChannels, REQUEST_INPUT_MARKER, RESPONSE_OUTPUT_MARKER,
    capture_and_adopt_injected_channels,
};
