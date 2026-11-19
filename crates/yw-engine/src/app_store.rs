//! The app's data-folder store (spec/15 §11.2, §11.4 S4 P1; owner decision O-8): the operations
//! the application logic performs on its own files outside the key worker — writing
//! `settings.json`, reading and writing the sealed `apikeys` file, the `vault.ywv` facts shown on
//! the lock screen and settings → 보안, whether a `.prev` copy exists, and the files a wallet reset
//! would move (spec/04 §2.5, §2.20, §6.2, §6.3).
//!
//! The trait is narrow and 1:1 with the calls the Windows app made inline before: its Windows
//! implementation is yw-app `app_store::WinAppStore` over the unchanged `yw_win::file` and
//! `yw_win::dpapi` calls (`apikeys.dpapi`, DPAPI entropy `APIKEYS_ENTROPY`). The sealed file's
//! name and seal change together per platform (Android: `apikeys.ks` + the Keystore wrap,
//! spec/15 §5.1–§5.2), so the seal is part of the store, not a separate trait. Results are
//! synchronous as before (callers branch on the `bool` of a write).
//!
//! No result carries a path or an OS error text (D28); [`SealedRead`]'s `Debug` prints the
//! variant and a length only, never the bytes.
//!
//! 2026-11-20 (spec/15 §11.4 S4 P1): created. Before, the Windows app called the file and DPAPI
//! functions directly in `app.rs`, `app_reset.rs` and `app_sidecar.rs`; `load_settings` (start)
//! stays a shell call.

use core::fmt;

use yw_core::secret::Zeroizing;
use yw_core::vault::FileKind;

use crate::apikeys::{ApiKeys, KeyName, is_registered};
use crate::logging::{self, Field};
use crate::settings::Settings;

/// What reading the sealed `apikeys` file gave (spec/04 §6.3).
pub enum SealedRead {
    /// No file: no keys, not an error.
    NotFound,
    /// The file could not be read or unsealed (too large, a reparse point, an I/O error, a
    /// failed unseal): no keys, E-APP-001-style "unreadable".
    Unreadable,
    /// The unsealed plaintext (wiped on drop).
    Plain(Zeroizing<Vec<u8>>),
}

impl fmt::Debug for SealedRead {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => formatter.write_str("NotFound"),
            Self::Unreadable => formatter.write_str("Unreadable"),
            Self::Plain(plain) => write!(formatter, "Plain(len={})", plain.len()),
        }
    }
}

/// The app's data-folder store (module doc). One per app, bound to its data folder.
pub trait AppStore: Send {
    /// Writes `settings.json` atomically (spec/04 §6.2, §9); `false` when the write failed.
    fn write_settings(&self, json: &[u8]) -> bool;
    /// Reads and unseals the `apikeys` file.
    fn read_sealed_keys(&self) -> SealedRead;
    /// Seals `plain` and writes the `apikeys` file atomically; `false` when either failed.
    fn write_sealed_keys(&self, plain: &[u8]) -> bool;
    /// The `vault.ywv` generation and last write time (Unix ms) from the file itself (review
    /// L17); `None` when absent, unreadable or not a vault.
    fn vault_file_info(&self) -> Option<(u64, u64)>;
    /// Whether the `.prev` copy of `kind` exists (a metadata check only, spec/04 §2.5 S07/S09).
    fn prev_exists(&self, kind: FileKind) -> bool;
    /// The data-folder files a wallet reset would move (spec/04 §2.20 S22), empty when the
    /// folder cannot be listed. `include_settings`: also `settings.json`.
    fn reset_candidates(&self, include_settings: bool) -> Vec<String>;
}

/// Reads the sealed `apikeys` file through `store` (spec/04 §6.3): `(keys, unreadable)`.
///
/// `rpc:` entries of networks not registered in `settings` are kept dormant and logged by name
/// (`apikeys.orphan`, spec/04 §6.6). An LLM key stored by an older version has no `llm:host`; it
/// stays unbound here (never attached to a request) until the first check after an unlock binds
/// it to the host in the vault-encrypted settings snapshot (review M1).
///
/// 2026-11-20 (S4 P1): moved from yw-app `app::load_apikeys`, which now reads through
/// `WinAppStore` and calls this; the mapping is unchanged (no file → no keys, not unreadable; a
/// read, unseal or format failure → no keys, unreadable).
#[must_use]
pub fn load_sealed_keys(store: &dyn AppStore, settings: &Settings) -> (ApiKeys, bool) {
    let plain = match store.read_sealed_keys() {
        SealedRead::Plain(plain) => plain,
        SealedRead::NotFound => return (ApiKeys::default(), false),
        SealedRead::Unreadable => return (ApiKeys::default(), true),
    };
    match ApiKeys::decode(plain.as_slice(), &|network| {
        is_registered(settings, network)
    }) {
        Ok(decoded) => {
            for orphan in decoded.orphans {
                if let KeyName::Rpc(network) = orphan {
                    logging::info("app", "apikeys.orphan", &[("net", Field::Net(network))]);
                }
            }
            (decoded.keys, false)
        }
        Err(_) => (ApiKeys::default(), true),
    }
}
