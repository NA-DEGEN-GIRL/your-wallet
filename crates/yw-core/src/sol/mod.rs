//! Solana send-only core (spec/07, M7 v1 = SOL): strict base58 addresses, compact-u16, the legacy
//! message with its single fixed template `T_SOL`, the strict parser with re-encoding identity,
//! fees, rent rules, recipient checks, the transfer intent and its approval request, signing with
//! post-sign verification, and the pure broadcast/expiry decisions. Journal records are
//! `journal::sol`. Nothing here touches the network, clocks or files: RPC observations and times
//! are arguments (spec/01 §2.2).
//!
//! Allowlisted SPL transfers (`T_SPL`, v1.1) are not part of this milestone: the parser rejects
//! their header as `UnknownTemplate`; the PDA/ATA derivation they need is already here.

// `doc`/`doctest`: rustdoc does not receive the config rustflags; the guard is for the real
// rustc build of the crate (doctests link that build).
#[cfg(not(any(curve25519_dalek_backend = "serial", doc, doctest)))]
compile_error!(
    "Solana phase requires --cfg curve25519_dalek_backend=\"serial\" (.cargo/config.toml); RUSTFLAGS/CARGO_ENCODED_RUSTFLAGS override it"
);

pub mod address;
pub mod broadcast;
pub mod display;
pub mod fee;
pub mod intent;
pub mod keys;
pub mod message;
pub mod pda;
pub mod recipient;
pub mod rent;
pub mod shortvec;
pub mod sign;
pub mod template;

pub use address::{SolAddress, SolCluster};
pub use intent::SolTransferIntent;
pub use sign::{SignedSolTransfer, SolSignError, sign_transfer};
pub use template::{SolAsset, SolTransferCore};

#[cfg(test)]
mod tests;
