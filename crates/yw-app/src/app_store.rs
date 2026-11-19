//! The Windows app data store (spec/04 §6.2, §6.3; spec/15 §11.2, §11.4 S4 P1): yw-engine
//! `app_store::AppStore` over the data folder, with the same `yw_win::file` and `yw_win::dpapi`
//! calls the app made inline before (`atomic_write`, `read_limited_no_reparse`, `dpapi::protect`
//! / `unprotect` with [`APIKEYS_ENTROPY`]), the same file names and limits, and the same
//! `store::prev_exists` / `store::reset::candidates` checks. Nothing here logs; no result
//! carries a path, and `Debug` prints no path.
//!
//! 2026-11-20 (S4 P1): created. Before, `app.rs` (settings, `apikeys.dpapi`, `vault_file_info`),
//! `app_reset.rs` and `app_sidecar.rs` made these calls themselves.

use core::fmt;
use std::path::{Path, PathBuf};

use yw_core::secret::Zeroizing;
use yw_core::vault::FileKind;
use yw_engine::app_store::{AppStore, SealedRead};
use yw_win::file::{FileError, atomic_write, read_limited_no_reparse};

use crate::app::Paths;

/// DPAPI optional entropy of `apikeys.dpapi` (spec/04 §6.3). (2026-11-17, spec/15 §11.4 S2 E2:
/// moved to `app` next to the DPAPI calls from `apikeys`, which moved to yw-engine; 2026-11-20
/// S4 P1: moved here with the DPAPI calls from `app`. The value is unchanged.)
pub const APIKEYS_ENTROPY: &[u8] = b"your-wallet/v3/apikeys";

/// Largest `apikeys.dpapi` read (unchanged from `app::load_apikeys`).
const APIKEYS_MAX_BYTES: u64 = 1_048_576;

/// Largest `vault.ywv` header read for [`vault_file_info`] (unchanged).
const VAULT_PEEK_BYTES: u64 = 65_536;

/// The Windows [`AppStore`]: the files of one data folder.
pub struct WinAppStore {
    data: PathBuf,
    settings: PathBuf,
    apikeys: PathBuf,
}

impl WinAppStore {
    /// The store of `paths.data` (`settings.json`, `apikeys.dpapi`, `vault.ywv` and its `.prev`).
    #[must_use]
    pub fn new(paths: &Paths) -> Self {
        Self {
            data: paths.data.clone(),
            settings: paths.settings(),
            apikeys: paths.apikeys(),
        }
    }
}

impl fmt::Debug for WinAppStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WinAppStore")
    }
}

impl AppStore for WinAppStore {
    fn write_settings(&self, json: &[u8]) -> bool {
        atomic_write(&self.settings, json).is_ok()
    }

    fn read_sealed_keys(&self) -> SealedRead {
        let blob = match read_limited_no_reparse(&self.apikeys, APIKEYS_MAX_BYTES) {
            Ok(blob) => blob,
            Err(FileError::NotFound) => return SealedRead::NotFound,
            Err(_) => return SealedRead::Unreadable,
        };
        match yw_win::dpapi::unprotect(&blob, APIKEYS_ENTROPY) {
            // The DPAPI buffer wipes itself on drop; the copy is wiped by `Zeroizing`.
            Ok(plain) => SealedRead::Plain(Zeroizing::new(plain.as_slice().to_vec())),
            Err(_) => SealedRead::Unreadable,
        }
    }

    fn write_sealed_keys(&self, plain: &[u8]) -> bool {
        yw_win::dpapi::protect(plain, APIKEYS_ENTROPY)
            .ok()
            .is_some_and(|blob| atomic_write(&self.apikeys, &blob).is_ok())
    }

    fn vault_file_info(&self) -> Option<(u64, u64)> {
        vault_file_info(&self.data)
    }

    fn prev_exists(&self, kind: FileKind) -> bool {
        crate::store::prev_exists(&self.data, kind)
    }

    fn reset_candidates(&self, include_settings: bool) -> Vec<String> {
        crate::store::reset::candidates(&self.data, include_settings).unwrap_or_default()
    }
}

/// The `vault.ywv` generation and last write time (Unix ms) from the file itself (review L17);
/// `None` when absent, unreadable or not a vault. (2026-11-20 S4 P1: moved from `app`.)
#[must_use]
pub fn vault_file_info(data: &Path) -> Option<(u64, u64)> {
    let path = data.join(crate::store::file_name(FileKind::Vault));
    let bytes = read_limited_no_reparse(&path, VAULT_PEEK_BYTES).ok()?;
    let generation = yw_core::vault::peek_generation(FileKind::Vault, &bytes)?;
    let written = std::fs::symlink_metadata(&path)
        .and_then(|metadata| metadata.modified())
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        });
    Some((generation, written))
}
