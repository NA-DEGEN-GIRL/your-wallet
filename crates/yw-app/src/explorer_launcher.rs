//! Opening a link or a folder with `%SystemRoot%\explorer.exe` (spec/04 §2.14): the shell's
//! [`Launcher`], which only the effect executor (`app_effects`) calls. 2026-11-22 (S4d E0c):
//! moved unchanged from `app_explorer` (a file that moves to the engine at S4d E1, which must not
//! name `std::env`, `std::process` or `Path`).

use std::path::{Path, PathBuf};

/// How a link or a folder is opened. Only the effect executor (`app_effects`: `Effect::OpenUrl`,
/// `Effect::OpenFolder`) calls it (2026-11-20, S4 P3: before, `App::open_explorer` launched and
/// `App::open_folder` started `explorer.exe` for a folder itself, also in unit-test builds); the
/// census counts its record (`launch N`). 2026-11-21 (S4 W1, plan §3.3): it is shell state, the
/// field `App::launcher`; before, `ExplorerUi.launcher` (the S15 card's wallet state).
/// 2026-11-22 (S4d E0c): this shell module is its home and the only file that names the program
/// (`explorer_exe`); before, `app_explorer`, a file that moves to the engine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Launcher {
    /// `%SystemRoot%\explorer.exe <url or folder>` (the default browser or File Explorer;
    /// spec/04 §2.14).
    System,
    /// Tests: what would have been opened, in order: a URL, or a folder's path (no process
    /// starts).
    Record(Vec<String>),
}

impl Default for Launcher {
    fn default() -> Self {
        if cfg!(test) {
            Self::Record(Vec::new())
        } else {
            Self::System
        }
    }
}

impl Launcher {
    /// Opens `url` (already built by `explorer::build_url`); `false` when the process did not
    /// start.
    pub(crate) fn launch(&mut self, url: &str) -> bool {
        match self {
            Self::System => explorer_exe(url),
            Self::Record(urls) => {
                urls.push(url.to_owned());
                true
            }
        }
    }

    /// Opens the folder `path` in File Explorer (2026-11-20, S4 P3: was `App::open_folder`,
    /// which always started the process); `false` when the process did not start.
    pub(crate) fn open_folder(&mut self, path: &Path) -> bool {
        match self {
            Self::System => explorer_exe(path),
            Self::Record(opened) => {
                opened.push(path.to_string_lossy().into_owned());
                true
            }
        }
    }
}

/// `%SystemRoot%\explorer.exe <arg>` (`C:\Windows` when `SystemRoot` is not set; spec/04 §2.14);
/// whether the process started.
fn explorer_exe(arg: impl AsRef<std::ffi::OsStr>) -> bool {
    let root =
        std::env::var_os("SystemRoot").map_or_else(|| PathBuf::from("C:\\Windows"), PathBuf::from);
    std::process::Command::new(root.join("explorer.exe"))
        .arg(arg)
        .spawn()
        .is_ok()
}
