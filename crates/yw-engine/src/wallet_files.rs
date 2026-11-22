//! The names of the wallet files and the reset report (spec/02 §6, spec/04 §2.20): pure, no file
//! access.
//!
//! (2026-11-17, spec/15 §11.4 S2: moved unchanged out of `store` and `store::reset`, which
//! re-export them and keep the Windows file operations, so the key worker and the events name
//! only these.)
//!
//! (2026-11-22, spec/15 §11.4 S4d E0a: [`stamp`], the reset folder's time stamp, moved here from
//! `store::reset` unchanged, so the wallet's reset names no yw-app module for it.)

use std::path::{Path, PathBuf};

use yw_core::error::StorageError;
use yw_core::vault::FileKind;

/// The note written into the new folder of a reset.
pub const README_NAME: &str = "README-reset.txt";
/// Folder name prefix of a reset.
pub const FOLDER_PREFIX: &str = "reset-";

/// File name of a kind.
#[must_use]
pub const fn file_name(kind: FileKind) -> &'static str {
    match kind {
        FileKind::Vault => "vault.ywv",
        FileKind::Meta => "meta.ywm",
        FileKind::Journal => "journal.ywj",
    }
}

/// `dir\<name><suffix>` of a kind (`""`, `.prev`, `.tmp` …).
#[must_use]
pub fn with_suffix(dir: &Path, kind: FileKind, suffix: &str) -> PathBuf {
    dir.join(format!("{}{suffix}", file_name(kind)))
}

/// Whether `name` is a set-aside copy of `kind` (`<name>.corrupt-<digits>` or
/// `<name>.prev.corrupt-<digits>`, spec/02 §6.3), so a name from the folder listing never
/// reaches another file.
#[must_use]
pub fn is_set_aside(kind: FileKind, name: &str) -> bool {
    let Some(rest) = name.strip_prefix(file_name(kind)) else {
        return false;
    };
    let digits = rest
        .strip_prefix(".corrupt-")
        .or_else(|| rest.strip_prefix(".prev.corrupt-"));
    digits.is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
}

/// `20261105T091530Z` from Unix milliseconds (UTC): the reset folder's name stamp. 2026-11-22
/// (spec/15 §11.4 S4d E0a): was yw-app `store::reset::stamp` (the wallet's reset names it).
#[must_use]
pub fn stamp(unix_ms: u64) -> String {
    // `YYYY-MM-DDTHH:MM:SS.mmmZ` → `YYYYMMDDTHHMMSSZ`.
    let full = crate::logging::format_utc(unix_ms);
    let mut out: String = full
        .split('.')
        .next()
        .unwrap_or_default()
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect();
    out.push('Z');
    out
}

/// What a reset moved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResetReport {
    /// The new folder (`None`: nothing was there to move).
    pub folder: Option<PathBuf>,
    /// File names moved, in order.
    pub moved: Vec<String>,
    /// `settings.json` or `apikeys.dpapi` was among them.
    pub settings_moved: bool,
}

/// Why a reset stopped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResetError {
    /// The data folder could not be listed or the new folder could not be created.
    Folder(StorageError),
    /// A move failed; the files in `moved` are already in `folder`.
    Move {
        /// The new folder.
        folder: PathBuf,
        /// Moved before the failure.
        moved: Vec<String>,
        /// The file that did not move.
        failed: String,
        /// The error.
        error: StorageError,
    },
}

#[cfg(test)]
mod tests {
    use yw_core::vault::FileKind;

    use super::{file_name, is_set_aside, with_suffix};

    #[test]
    fn names_and_set_aside_copies() {
        assert_eq!(file_name(FileKind::Vault), "vault.ywv");
        assert_eq!(file_name(FileKind::Meta), "meta.ywm");
        assert_eq!(file_name(FileKind::Journal), "journal.ywj");
        assert_eq!(
            with_suffix(std::path::Path::new("d"), FileKind::Meta, ".prev"),
            std::path::Path::new("d").join("meta.ywm.prev")
        );
        assert!(is_set_aside(FileKind::Meta, "meta.ywm.corrupt-17"));
        assert!(is_set_aside(FileKind::Meta, "meta.ywm.prev.corrupt-17"));
        for name in [
            "meta.ywm",
            "meta.ywm.prev",
            "meta.ywm.corrupt-",
            "meta.ywm.corrupt-1x",
            "journal.ywj.corrupt-17",
        ] {
            assert!(!is_set_aside(FileKind::Meta, name), "{name}");
        }
    }
}
