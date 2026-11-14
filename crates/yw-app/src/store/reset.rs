//! `지갑 초기화` file moves (spec/04 §2.20): the wallet files of the data folder are moved — never
//! deleted or overwritten — into a new subfolder `reset-<UTC stamp>` of the same folder, so the
//! app starts over at S01 while everything stays restorable by hand (docs/recovery-guide.ko.md).
//!
//! - Moved: `vault.ywv`, `meta.ywm`, `journal.ywj` and every file that starts with one of those
//!   names and a dot (`.prev`, `.tmp`, `.prev.tmp`, `.corrupt-<t>`). `vault.ywv` goes first, so
//!   a failure part-way leaves no openable wallet behind but its sidecars (T-LEFTOVER then shows
//!   them on S01 and the user can run the reset again).
//! - Kept unless asked: `settings.json` and `apikeys.dpapi` (and their `.tmp`). The logs folder,
//!   earlier `reset-*` folders and anything else stay where they are.
//! - The new folder is created inside the data folder and inherits its protected DACL (spec/04
//!   §1.4-3, `ensure_private_dir`); a moved file keeps its own ACL. A reparse point named like
//!   the new folder, or a data folder that is one, is refused.
//! - `README-reset.txt` in the new folder lists the moved files and how to put them back.
//!
//! Leftover detection (`FileStorage::any_present`) only looks at the data folder itself, so files
//! in a `reset-*` subfolder never block S01.

use std::path::{Path, PathBuf};

use yw_core::error::StorageError;
use yw_core::lang::Lang;
use yw_win::file::{
    FileError, flush_dir, reject_reparse_point, rename_no_replace, write_new_synced,
};

/// Names whose family is moved (the vault and its sidecars).
const WALLET_BASES: [&str; 3] = ["vault.ywv", "meta.ywm", "journal.ywj"];
/// Names moved only with `include_settings`.
const SETTINGS_BASES: [&str; 2] = ["settings.json", "apikeys.dpapi"];
/// The note written into the new folder.
pub const README_NAME: &str = "README-reset.txt";
/// Folder name prefix.
pub const FOLDER_PREFIX: &str = "reset-";

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

fn storage(error: FileError) -> StorageError {
    match error {
        FileError::NotFound => StorageError::NotFound,
        FileError::TooLarge => StorageError::TooLarge,
        FileError::ReparsePoint => StorageError::Io(0x0000_1126),
        FileError::Os(error) => StorageError::Io(error.code),
        FileError::Io(_) => StorageError::Io(0xFFFF_FFFF),
    }
}

fn io(error: &std::io::Error) -> StorageError {
    StorageError::Io(
        error
            .raw_os_error()
            .and_then(|code| u32::try_from(code).ok())
            .unwrap_or(0xFFFF_FFFF),
    )
}

fn in_family(name: &str, base: &str) -> bool {
    name == base
        || name
            .strip_prefix(base)
            .is_some_and(|rest| rest.starts_with('.'))
}

/// Whether `name` (a file directly in the data folder) is moved by a reset.
#[must_use]
pub fn is_moved(name: &str, include_settings: bool) -> bool {
    WALLET_BASES.iter().any(|base| in_family(name, base))
        || (include_settings && SETTINGS_BASES.iter().any(|base| in_family(name, base)))
}

/// `20261105T091530Z` from Unix milliseconds (UTC).
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

/// The files a reset would move now, `vault.ywv` first, then by name (S22 lists them).
///
/// # Errors
///
/// The folder could not be listed.
pub fn candidates(dir: &Path, include_settings: bool) -> Result<Vec<String>, StorageError> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(|error| io(&error))? {
        let entry = entry.map_err(|error| io(&error))?;
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        // Files only (a link named `vault.ywv` is moved as the link itself, never followed);
        // folders such as `logs` and earlier `reset-*` stay.
        if kind.is_dir() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if is_moved(&name, include_settings) {
            names.push(name);
        }
    }
    names.sort_by(|a, b| (a != WALLET_BASES[0], a).cmp(&(b != WALLET_BASES[0], b)));
    Ok(names)
}

/// Creates `reset-<stamp>` (or `reset-<stamp>-2` … `-9` when taken) inside `dir`.
fn create_folder(dir: &Path, stamp: &str) -> Result<PathBuf, StorageError> {
    for attempt in 1_u8..=9 {
        let name = if attempt == 1 {
            format!("{FOLDER_PREFIX}{stamp}")
        } else {
            format!("{FOLDER_PREFIX}{stamp}-{attempt}")
        };
        let folder = dir.join(name);
        match std::fs::create_dir(&folder) {
            Ok(()) => {
                // Created by us just now: a plain folder that inherits the data folder's DACL.
                reject_reparse_point(&folder).map_err(storage)?;
                return Ok(folder);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(io(&error)),
        }
    }
    Err(StorageError::Io(183))
}

/// The fixed texts of `README-reset.txt` (spec/14).
pub mod text {
    yw_core::texts! {
        /// `README-reset.txt` before the list of moved files (CRLF line ends, a plain text file).
        README_HEAD = "Your Wallet — 지갑 초기화로 옮긴 파일\r\n\r\n\
         이 폴더의 파일은 '지갑 초기화' 때 데이터 폴더에서 옮겨 온 것입니다. 지우지 않았습니다.\r\n\
         되돌리려면: 앱을 완전히 종료하고, 데이터 폴더(이 폴더의 상위 폴더)에 새로 생긴 vault.ywv·meta.ywm·journal.ywj가 있으면\r\n\
         먼저 다른 폴더로 옮긴 뒤, 아래 파일을 이 폴더에서 데이터 폴더로 옮기세요. 예전 비밀번호로 열립니다.\r\n\
         자세한 방법: docs/recovery-guide.ko.md '지갑 초기화 되돌리기'.\r\n\r\n옮긴 파일:\r\n"
            / "Your Wallet — files moved by a wallet reset\r\n\r\n\
         The files in this folder were moved here from the data folder by 'Reset wallet'. Nothing was deleted.\r\n\
         To undo: quit the app completely; if the data folder (the parent of this folder) has a new vault.ywv, meta.ywm or journal.ywj,\r\n\
         first move those to another folder, then move the files below from this folder back to the data folder. They open with the old password.\r\n\
         Details: docs/recovery-guide.ko.md (undoing a wallet reset).\r\n\r\nMoved files:\r\n";
    }
}

fn readme(lang: Lang, moved: &[String]) -> String {
    let mut text = String::from(text::README_HEAD.get(lang));
    for name in moved {
        text.push_str("  ");
        text.push_str(name);
        text.push_str("\r\n");
    }
    text
}

/// Moves the wallet files of `dir` into a new `reset-<stamp>` folder (see the module docs).
///
/// # Errors
///
/// [`ResetError::Folder`] before anything moved; [`ResetError::Move`] when a move failed part-way.
pub fn move_wallet_files(
    dir: &Path,
    stamp: &str,
    include_settings: bool,
    lang: Lang,
) -> Result<ResetReport, ResetError> {
    reject_reparse_point(dir).map_err(|error| ResetError::Folder(storage(error)))?;
    let names = candidates(dir, include_settings).map_err(ResetError::Folder)?;
    if names.is_empty() {
        return Ok(ResetReport {
            folder: None,
            moved: Vec::new(),
            settings_moved: false,
        });
    }
    let folder = create_folder(dir, stamp).map_err(ResetError::Folder)?;
    let mut moved = Vec::new();
    for name in names {
        if let Err(error) = rename_no_replace(&dir.join(&name), &folder.join(&name)) {
            let _ = flush_dir(dir);
            return Err(ResetError::Move {
                folder,
                moved,
                failed: name,
                error: storage(error),
            });
        }
        moved.push(name);
    }
    let _ = flush_dir(dir);
    // The note is a convenience: a failure to write it does not undo the moves.
    let _ = write_new_synced(&folder.join(README_NAME), readme(lang, &moved).as_bytes());
    let _ = flush_dir(&folder);
    let settings_moved = moved
        .iter()
        .any(|name| SETTINGS_BASES.iter().any(|base| in_family(name, base)));
    Ok(ResetReport {
        folder: Some(folder),
        moved,
        settings_moved,
    })
}

#[cfg(test)]
mod tests {
    use super::{README_NAME, is_moved, move_wallet_files, stamp};
    use crate::store::FileStorage;
    use yw_core::vault::FileKind;

    fn temp(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "yw-reset-{tag}-{}-{}",
            std::process::id(),
            yw_win::time::monotonic_ms()
        ));
        std::fs::create_dir_all(dir.join("logs")).unwrap();
        dir
    }

    #[test]
    fn names_and_stamp() {
        for name in [
            "vault.ywv",
            "vault.ywv.prev",
            "vault.ywv.corrupt-1793000000",
            "meta.ywm.prev.tmp",
            "journal.ywj",
        ] {
            assert!(is_moved(name, false), "{name}");
        }
        for name in [
            "vault.ywvx",
            "settings.json",
            "apikeys.dpapi",
            "yw-app.log",
            "reset-x",
        ] {
            assert!(!is_moved(name, false), "{name}");
        }
        assert!(is_moved("settings.json", true) && is_moved("apikeys.dpapi", true));
        // 2026-11-05T09:15:30.123Z
        assert_eq!(stamp(1_793_870_130_123), "20261105T091530Z");
    }

    #[test]
    fn moves_wallet_files_keeps_settings_and_clears_leftover() {
        let dir = temp("move");
        for name in [
            "vault.ywv",
            "vault.ywv.prev",
            "vault.ywv.corrupt-17",
            "meta.ywm",
            "meta.ywm.prev",
            "journal.ywj",
            "settings.json",
            "apikeys.dpapi",
            "other.txt",
        ] {
            std::fs::write(dir.join(name), name.as_bytes()).unwrap();
        }
        let report =
            move_wallet_files(&dir, "20261105T091530Z", false, yw_core::lang::Lang::Ko).unwrap();
        let folder = report.folder.clone().unwrap();
        assert_eq!(folder, dir.join("reset-20261105T091530Z"));
        assert_eq!(report.moved.first().map(String::as_str), Some("vault.ywv"));
        assert_eq!(report.moved.len(), 6);
        assert!(!report.settings_moved);
        for name in &report.moved {
            assert!(!dir.join(name).exists(), "{name} left behind");
            assert_eq!(std::fs::read(folder.join(name)).unwrap(), name.as_bytes());
        }
        for kept in ["settings.json", "apikeys.dpapi", "other.txt", "logs"] {
            assert!(dir.join(kept).exists(), "{kept} kept");
        }
        assert!(folder.join(README_NAME).is_file());
        // T-LEFTOVER looks at the data folder only.
        let storage = FileStorage::open(&dir).unwrap();
        assert!(!storage.any_present(FileKind::Meta) && !storage.any_present(FileKind::Journal));
        assert!(!storage.any_present(FileKind::Vault));

        // Same second again (a name clash), now with the settings: `-2`.
        std::fs::write(dir.join("vault.ywv"), b"second").unwrap();
        let again =
            move_wallet_files(&dir, "20261105T091530Z", true, yw_core::lang::Lang::Ko).unwrap();
        assert_eq!(
            again.folder.as_deref(),
            Some(dir.join("reset-20261105T091530Z-2").as_path())
        );
        assert!(again.settings_moved);
        assert!(!dir.join("settings.json").exists() && !dir.join("apikeys.dpapi").exists());
        assert!(dir.join("other.txt").exists() && dir.join("logs").is_dir());
        // The first folder is untouched.
        assert_eq!(
            std::fs::read(folder.join("vault.ywv")).unwrap(),
            b"vault.ywv"
        );
        // Nothing left: no new folder.
        let empty =
            move_wallet_files(&dir, "20261105T091531Z", true, yw_core::lang::Lang::Ko).unwrap();
        assert_eq!(empty.folder, None);
        assert!(!dir.join("reset-20261105T091531Z").exists());
        let _ = std::fs::remove_dir_all(dir);
    }
}
