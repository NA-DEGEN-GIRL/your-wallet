//! Secret-bearing wallet primitives.
//!
//! This crate is intended to be linked only into the isolated key-agent process.
//! Secret types deliberately omit `Debug`, `Display`, and serialization traits.

#![forbid(unsafe_code)]

mod bip32;
mod error;
mod mnemonic;
mod password;
mod signing;
mod storage;
mod vault;

pub use bip32::{AccountIndex, DerivationPath, DerivedAccount, EthereumAddress, RawPrivateKey};
pub use error::{SecretError, VaultOpenError};
pub use mnemonic::{MnemonicEntropy, MnemonicWordCount, SecretPhrase, SessionPassphrase};
pub use password::VaultPassword;
pub use signing::{CanonicalSignature, SignedCanonicalOperation};
pub use storage::{AtomicVaultStorage, StorageError};
pub use vault::{
    BackupState, Bip39Record, DerivedAccountRecord, RawKeyRecord, SecretRecord, VaultBlob,
    VaultHeader, VaultPayload,
};
