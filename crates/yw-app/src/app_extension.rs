//! S23 `Chrome 확장 설치` (spec/04 §2.21): how to load the unpacked extension, where its folder
//! is, and whether an extension has connected.
//!
//! The folder is the installed copy `<folder of yw-app.exe>\extension` (`scripts/install.ps1`).
//! Debug builds fall back to the repository's `extension\` only when that one does not exist. A
//! candidate counts only as a plain folder (no reparse point) named `extension` holding a plain
//! `manifest.json`; `폴더 열기` passes that resolved path, never text from elsewhere, to
//! `explorer.exe` (§2.14). Chrome refuses `chrome://` links opened by other programs, so the page
//! address is copied for the user to paste. 2026-11-20 (S4 P3): the press emits
//! `Effect::OpenFolder(Folder::Extension)`; the shell (`App::open_folder`) resolves the folder
//! here and opens it, or answers `Cmd::FolderMissing`.
//!
//! 2026-11-24 (spec/15 §11.4 S5-5, S5 plan critic C7): the status `ExtensionStatus`, its texts and
//! the page address `CHROME_EXTENSIONS_URL` moved to `yw_engine::screen::extension` with the screen
//! builders (S23 is drawn there); this file keeps the folder, its checks and the presses.
//! 2026-11-24 (spec/15 §11.4 S5-9): of the presses, only `경로 복사`'s folder path
//! ([`App::on_ext_copy_path`]); the others are the wallet's (`Wallet::on_ext`).

use std::path::{Path, PathBuf};

use crate::app::App;

// 2026-11-24 (spec/15 §11.4 S5-9): the S23 state `ExtensionUi` (its way back, `back`) is the
// wallet's `ext_back`, with S23's presses; before, the shell's.

/// Whether `path` is a plain folder named `extension` with a plain `manifest.json` inside.
#[must_use]
pub fn is_extension_folder(path: &Path) -> bool {
    if path.file_name().and_then(|name| name.to_str()) != Some("extension") {
        return false;
    }
    let plain_dir = std::fs::symlink_metadata(path)
        .is_ok_and(|meta| meta.is_dir() && yw_win::file::reject_reparse_point(path).is_ok());
    let manifest = path.join("manifest.json");
    plain_dir
        && std::fs::symlink_metadata(&manifest).is_ok_and(|meta| {
            meta.is_file() && yw_win::file::reject_reparse_point(&manifest).is_ok()
        })
}

/// The candidates in order: next to the executable, then (debug builds) the repository's.
#[must_use]
pub fn extension_candidates(exe: Option<&Path>, dev_repo: Option<&Path>) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(dir) = exe.and_then(Path::parent) {
        out.push(dir.join("extension"));
    }
    if let Some(repo) = dev_repo {
        out.push(repo.join("extension"));
    }
    out
}

/// The first valid candidate.
#[must_use]
pub fn resolve_extension_dir(candidates: &[PathBuf]) -> Option<PathBuf> {
    candidates
        .iter()
        .find(|path| is_extension_folder(path))
        .cloned()
}

/// The repository root of a debug build (`crates/yw-app/../..`); `None` in release builds.
fn dev_repo() -> Option<PathBuf> {
    if !cfg!(debug_assertions) {
        return None;
    }
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
}

#[cfg(test)]
thread_local! {
    /// The screenshot tour's stand-in folder: a generic path, never the build tree's
    /// (2026-11-14: shot 45 showed the checkout's folder).
    pub static TOUR_EXTENSION_DIR: core::cell::RefCell<Option<PathBuf>> =
        const { core::cell::RefCell::new(None) };
}

/// The extension folder of this installation (see the module docs).
#[must_use]
pub fn extension_dir() -> Option<PathBuf> {
    #[cfg(test)]
    if let Some(dir) = TOUR_EXTENSION_DIR.with(|dir| dir.borrow().clone()) {
        return Some(dir);
    }
    let exe = std::env::current_exe().ok();
    resolve_extension_dir(&extension_candidates(exe.as_deref(), dev_repo().as_deref()))
}

/// The installed location shown when no folder was found.
#[must_use]
pub fn expected_dir() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    exe.parent().map(|dir| dir.join("extension"))
}

// 2026-11-24 (spec/15 §11.4 S5-3): `App::extension_status` (render code that reads only wallet
// state) moved to `ui/screens_reset.rs`, and the screens ask the folders through `App::facts()`
// (`screen_facts::WinFacts` calls `extension_dir`/`expected_dir` here).
impl App {
    /// S23 `확장 폴더 경로 복사`: the folder this installation found ([`extension_dir`]) goes to
    /// the wallet's typed in-process entry `Wallet::copy_extension_path` (a path never rides in a
    /// `Cmd`), which copies it as a setup step (its band when the copy's result arrives); a
    /// folder not found copies nothing, as before. Run by `App::on_command` right after the press
    /// reached the wallet, which does nothing for it.
    ///
    /// 2026-11-24 (spec/15 §11.4 S5-9): the shell's only S23 step. From 2026-11-22 (S4c W15,
    /// critique B-5) until then every S23 press was the shell's (`App::on_ext`, run right after
    /// the press): `열기`/`← 돌아가기` (the way back was shell state, and a yw-app `Screen` was no
    /// `Cmd` data before S4d E0a) called the wallet's `set_screen`/`return_to`, `폴더 열기` its
    /// `emit(Effect::OpenFolder(..))` and the two copies its `copy_with_band`; those presses are
    /// the wallet's now (`Wallet::on_ext`), with the same steps in the same order.
    pub(crate) fn on_ext_copy_path(&mut self) {
        if let Some(dir) = extension_dir() {
            self.wallet.copy_extension_path(&dir.display().to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{extension_candidates, is_extension_folder, resolve_extension_dir};

    #[test]
    fn installed_folder_first_then_the_repository() {
        let root = std::env::temp_dir().join(format!(
            "yw-ext-path-{}-{}",
            std::process::id(),
            yw_win::time::monotonic_ms()
        ));
        let install = root.join("Programs").join("YourWallet");
        let repo = root.join("repo");
        std::fs::create_dir_all(install.join("extension")).unwrap();
        std::fs::create_dir_all(repo.join("extension")).unwrap();
        std::fs::write(repo.join("extension").join("manifest.json"), b"{}").unwrap();
        let exe = install.join("yw-app.exe");
        let candidates = extension_candidates(Some(&exe), Some(&repo));
        assert_eq!(candidates[0], install.join("extension"));
        // The installed folder has no manifest yet: the repository's is used.
        assert_eq!(
            resolve_extension_dir(&candidates),
            Some(repo.join("extension"))
        );
        std::fs::write(install.join("extension").join("manifest.json"), b"{}").unwrap();
        assert_eq!(
            resolve_extension_dir(&candidates),
            Some(install.join("extension"))
        );
        // Release builds have no repository fallback.
        assert_eq!(extension_candidates(Some(&exe), None).len(), 1);
        // Not a folder named `extension`, or a manifest that is a folder: refused.
        std::fs::create_dir_all(root.join("other")).unwrap();
        std::fs::write(root.join("other").join("manifest.json"), b"{}").unwrap();
        assert!(!is_extension_folder(&root.join("other")));
        std::fs::create_dir_all(root.join("x").join("extension").join("manifest.json")).unwrap();
        assert!(!is_extension_folder(&root.join("x").join("extension")));
        std::fs::write(root.join("file"), b"").unwrap();
        assert!(!is_extension_folder(&root.join("file").join("extension")));
        assert_eq!(resolve_extension_dir(&[]), None);
        let _ = std::fs::remove_dir_all(root);
    }
}
