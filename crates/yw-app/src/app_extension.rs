//! S23 `Chrome 확장 설치` (spec/04 §2.21): how to load the unpacked extension, where its folder
//! is, and whether an extension has connected.
//!
//! The folder is the installed copy `<folder of yw-app.exe>\extension` (`scripts/install.ps1`).
//! Debug builds fall back to the repository's `extension\` only when that one does not exist. A
//! candidate counts only as a plain folder (no reparse point) named `extension` holding a plain
//! `manifest.json`; `폴더 열기` passes that resolved path, never text from elsewhere, to
//! `explorer.exe` (§2.14). Chrome refuses `chrome://` links opened by other programs, so the page
//! address is copied for the user to paste.

use std::path::{Path, PathBuf};

use crate::app::{App, AppMode, Screen};
use crate::logging;

/// The Chrome page that loads unpacked extensions.
pub const CHROME_EXTENSIONS_URL: &str = "chrome://extensions";

/// S23 state.
#[derive(Debug, Default)]
pub struct ExtensionUi {
    /// Where `← 돌아가기` returns to.
    pub back: Option<Screen>,
}

/// Whether an extension has talked to this app.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExtensionStatus {
    /// A pipe connection is open now.
    Connected,
    /// Sites are connected (an extension has connected before).
    ConnectedBefore,
    /// Unlocked, no site and no connection.
    Never,
    /// Locked: the connection record (the sites) is not readable.
    Unknown,
}

impl ExtensionStatus {
    /// The status line.
    #[must_use]
    pub const fn text(self) -> &'static str {
        match self {
            Self::Connected => "확장이 지금 이 앱에 연결되어 있습니다.",
            Self::ConnectedBefore => "확장이 연결된 적 있음 (연결된 사이트가 있습니다).",
            Self::Never => {
                "아직 연결되지 않음 — 확장을 설치한 뒤 dApp 사이트에서 '지갑 연결'을 누르면 연결됩니다."
            }
            Self::Unknown => {
                "지금은 연결되어 있지 않습니다. 연결 기록(연결된 사이트)은 잠금을 해제하면 보입니다."
            }
        }
    }
}

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

/// The extension folder of this installation (see the module docs).
#[must_use]
pub fn extension_dir() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok();
    resolve_extension_dir(&extension_candidates(exe.as_deref(), dev_repo().as_deref()))
}

/// The installed location shown when no folder was found.
#[must_use]
pub fn expected_dir() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    exe.parent().map(|dir| dir.join("extension"))
}

impl App {
    /// The S23 status.
    #[must_use]
    pub fn extension_status(&self) -> ExtensionStatus {
        if self
            .browser
            .as_ref()
            .is_some_and(|browser| browser.connections > 0)
        {
            return ExtensionStatus::Connected;
        }
        if !matches!(self.mode, AppMode::Unlocked { .. }) || self.meta.is_none() {
            return ExtensionStatus::Unknown;
        }
        let (sol, btc) = self.chain_grants();
        if self.browser_grants().is_empty() && sol.is_empty() && btc.is_empty() {
            ExtensionStatus::Never
        } else {
            ExtensionStatus::ConnectedBefore
        }
    }

    /// `Chrome 확장 설치` links (S08, S13, settings).
    pub(crate) fn open_extension_help(&mut self) {
        if self.screen != Screen::Extension {
            self.ext.back = Some(self.screen.clone());
        }
        self.set_screen(Screen::Extension);
    }

    fn close_extension_help(&mut self) {
        let back = self.ext.back.take();
        let fallback = match self.mode {
            AppMode::Unlocked { .. } => Screen::Main,
            AppMode::BackupPending => Screen::BackupPending,
            AppMode::NoVault => Screen::FirstRun,
            _ => Screen::Locked,
        };
        self.set_screen(back.unwrap_or(fallback));
    }

    /// Commands of S23; `false` when `id` is not one of them.
    pub(crate) fn on_extension_command(&mut self, id: u16) -> bool {
        use crate::ui::screens_reset::ids;
        match id {
            ids::EXT_OPEN => self.open_extension_help(),
            ids::EXT_BACK => self.close_extension_help(),
            ids::EXT_OPEN_FOLDER => {
                if let Some(dir) = extension_dir() {
                    Self::open_folder(&dir);
                } else {
                    logging::info("app", "extension.folder_missing", &[]);
                    self.info = Some(crate::ui::screens_reset::T_EXT_MISSING.to_owned());
                    self.refresh();
                }
            }
            ids::EXT_COPY_PATH => {
                if let Some(dir) = extension_dir() {
                    self.copy_text(&dir.display().to_string());
                }
            }
            ids::EXT_COPY_URL => {
                self.copy_text(CHROME_EXTENSIONS_URL);
                if self.info.as_deref() == Some("복사했습니다.") {
                    self.info = Some(
                        "chrome://extensions 주소를 복사했습니다. Chrome 주소창에 붙여넣으세요."
                            .to_owned(),
                    );
                    self.refresh();
                }
            }
            _ => return false,
        }
        true
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
