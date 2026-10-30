//! Solana send-only core (spec/07, M7): strict base58 addresses, compact-u16, the legacy message
//! with its two fixed templates — `T_SOL` (v1) and `T_SPL` (v1.1: allowlisted USDC/USDT on the
//! classic Token program, ATA `CreateIdempotent` + `TransferChecked`) — the strict parser with
//! re-encoding identity, PDA/ATA derivation, SPL account data, fees, rent rules, recipient
//! checks, the transfer intent and its approval request, signing with post-sign verification, and
//! the pure broadcast/expiry decisions. Journal records are `journal::sol`. Nothing here touches
//! the network, clocks or files: RPC observations and times are arguments (spec/01 §2.2).

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
pub mod msgsign;
pub mod pda;
pub mod recipient;
pub mod rent;
pub mod shortvec;
pub mod sign;
pub mod template;
pub mod token;

pub use address::{SolAddress, SolCluster};
pub use intent::SolTransferIntent;
pub use sign::{SignedSolTransfer, SolSignError, sign_transfer};
pub use template::{SolAsset, SolTransferCore, SplAllowEntry};

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_spl;
