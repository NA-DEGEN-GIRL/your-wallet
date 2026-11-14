//! Which build is running (2026-11-10): the commit that `install.ps1` wrote to the installation
//! record `yw-install.json` next to the executable (spec/01 §9), shown in 설정 → 브라우저·정보 →
//! 정보 ("버전 0.3.0 · 커밋 75c3136a1b2c") and in the `app.start` log line. Only `commit` is read,
//! and only a lowercase hex value of 7–40 digits is used; the other fields and the file hashes are
//! not read. No record (a development build, or an older installation without `commit`) is
//! "설치 기록 없음 — 개발 빌드".

use yw_json::{Limits, Value};

/// The startup failure texts of `main.rs` (spec/04 §1.4, spec/14). They live in the library
/// because `main.rs` is the binary crate and every catalogue must be reachable from the tests.
/// The texts before `settings.json` is read (single instance, data folder) are shown in Korean,
/// the default language: no language is known yet, and the settings file is not read before the
/// data folder is checked.
pub mod start_text {
    yw_core::texts! {
        /// The window of a running instance belongs to another program.
        NOT_OURS = "실행 중인 Your Wallet 창을 확인하지 못했습니다. 같은 이름의 창이 이 실행 파일이 아닌 다른 프로그램(또는 다른 위치의 Your Wallet)에 속해 있어 전환하지 않았습니다. 작업 표시줄에서 Your Wallet을 직접 여세요."
            / "The running Your Wallet window could not be confirmed. A window with the same name belongs to another program (or to Your Wallet in another location), so it was not switched to. Open Your Wallet from the taskbar yourself.";
        /// The single-instance lock failed.
        INSTANCE_FAILED = "Your Wallet을 시작하지 못했습니다. (단일 인스턴스)"
            / "Your Wallet could not start. (single instance)";
        /// The data folder is owned or opened by another account.
        DATA_UNTRUSTED = "데이터 폴더(%LOCALAPPDATA%\\YourWallet)를 열지 않았습니다. 이 폴더나 안의 파일이 다른 계정의 소유이거나, 이 사용자가 고칠 수 없는 방식으로 다른 계정에 열려 있습니다. 지갑 파일을 보호하기 위해 시작을 멈춥니다."
            / "The data folder (%LOCALAPPDATA%\\YourWallet) was not opened. The folder or a file in it is owned by another account, or is open to another account in a way this user cannot fix. Starting stops to protect the wallet files.";
        /// The data folder could not be made.
        DATA_UNAVAILABLE = "데이터 폴더를 만들지 못했습니다. LOCALAPPDATA 경로와 권한을 확인하세요."
            / "The data folder could not be created. Check the LOCALAPPDATA path and permissions.";
        /// The data folder is a link or a file: {0} the folder.
        DATA_NOT_PLAIN(1) = "다음 데이터 폴더가 링크(정션·심볼릭 링크)이거나 폴더가 아닌 파일입니다: {0}\n\n지갑 파일을 보호하기 위해 링크된 데이터 폴더는 쓰지 않습니다. 다른 드라이브로 옮기고 링크를 만들었다면 링크만 지우고(대상 폴더의 지갑 파일은 지우지 마세요) 옮긴 폴더를 원래 자리로 되돌린 뒤 다시 시작하세요."
            / "This data folder is a link (junction or symbolic link) or a file, not a folder: {0}\n\nA linked data folder is not used, to protect the wallet files. If you moved it to another drive and made a link, delete only the link (not the wallet files in the target folder), move the folder back to its original place and start again.";
        /// Window class registration failed.
        CLASS_FAILED = "창 클래스를 등록하지 못했습니다." / "The window class could not be registered.";
        /// The main window could not be created.
        MAIN_WINDOW_FAILED = "주 창을 만들지 못했습니다." / "The main window could not be created.";
        /// A worker thread could not start.
        THREADS_FAILED = "작업 스레드를 시작하지 못했습니다." / "The worker threads could not start.";
    }
}

/// The installation record's file name (next to `yw-app.exe`).
pub const INSTALL_RECORD: &str = "yw-install.json";
/// Read limit of [`INSTALL_RECORD`] (it lists every installed file and its hash).
pub const INSTALL_RECORD_MAX_BYTES: u64 = 65_536;
/// How many commit digits the 정보 card shows.
pub const COMMIT_SHOWN: usize = 12;
const LIMITS: Limits = Limits {
    max_bytes: 65_536,
    max_depth: 4,
    max_nodes: 8_192,
    max_items: 4_096,
};

/// Whether `text` is a commit id this app shows: 7–40 lowercase hex digits.
#[must_use]
pub fn is_commit(text: &str) -> bool {
    (7..=40).contains(&text.len())
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// The `commit` of an installation record (strict JSON, an object), when it is a commit id
/// ([`is_commit`]); `None` otherwise.
#[must_use]
pub fn install_commit(bytes: &[u8]) -> Option<String> {
    let Ok(Value::Object(record)) = yw_json::parse(bytes, &LIMITS) else {
        return None;
    };
    record
        .get("commit")?
        .as_str()
        .filter(|commit| is_commit(commit))
        .map(str::to_owned)
}

/// Reads the installation record next to the running executable (`read_limited`, ≤ 64 KiB).
#[must_use]
pub fn read_install_commit() -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    let bytes = yw_win::file::read_limited(
        &exe.parent()?.join(INSTALL_RECORD),
        INSTALL_RECORD_MAX_BYTES,
    )
    .ok()?;
    install_commit(&bytes)
}

/// The fixed texts of the version line (spec/14).
pub mod text {
    yw_core::texts! {
        /// The 정보 card's version line: {0} version, {1} commit.
        VERSION_COMMIT(2) = "{0} · 커밋 {1}" / "{0} · commit {1}";
        /// The version line without an installation record: {0} version.
        VERSION_DEV(1) = "{0} · 설치 기록 없음 — 개발 빌드" / "{0} · no installation record — development build";
    }
}

/// The 정보 card's version line: "0.3.0 · 커밋 75c3136a1b2c", or the development-build note.
#[must_use]
pub fn version_text(lang: yw_core::lang::Lang, commit: Option<&str>) -> String {
    let version = env!("CARGO_PKG_VERSION");
    match commit {
        Some(commit) => text::VERSION_COMMIT.fill(
            lang,
            [version, commit.get(..COMMIT_SHOWN).unwrap_or(commit)],
        ),
        None => text::VERSION_DEV.fill(lang, [version]),
    }
}

#[cfg(test)]
mod tests {
    use super::{install_commit, version_text};
    use yw_core::lang::{Lang, has_hangul};

    #[test]
    fn version_text_in_both_languages() {
        let version = env!("CARGO_PKG_VERSION");
        assert_eq!(
            version_text(Lang::Ko, Some("75c3136a1b2cd3e4")),
            format!("{version} · 커밋 75c3136a1b2c")
        );
        assert_eq!(
            version_text(Lang::Ko, None),
            format!("{version} · 설치 기록 없음 — 개발 빌드")
        );
        assert_eq!(
            version_text(Lang::En, Some("75c3136a1b2cd3e4")),
            format!("{version} · commit 75c3136a1b2c")
        );
        assert!(!has_hangul(&version_text(Lang::En, None)));
    }

    /// 2-13: only a 7–40 digit lowercase hex `commit` of a strict JSON object is used.
    #[test]
    fn a_malformed_commit_is_dropped() {
        let record = |commit: &str| {
            format!(
                "{{\"product\":\"YourWallet\",\"version\":\"0.3.0\",\"commit\":{commit},\"state\":\"installed\",\"files\":[\"yw-app.exe\"]}}\n"
            )
        };
        let full = "75c3136a1b2cd3e4f5a6b7c8d9e0f1a2b3c4d5e6";
        assert_eq!(
            install_commit(record(&format!("\"{full}\"")).as_bytes()).as_deref(),
            Some(full)
        );
        assert_eq!(
            install_commit(record("\"75c3136\"").as_bytes()).as_deref(),
            Some("75c3136")
        );
        for bad in [
            "\"75C3136A\"",
            "\"75c313\"",
            "\"75c3136 \"",
            "\"zz3136a1\"",
            "\"75c3136a1b2cd3e4f5a6b7c8d9e0f1a2b3c4d5e6f\"",
            "null",
            "75",
        ] {
            assert_eq!(install_commit(record(bad).as_bytes()), None, "{bad}");
        }
        assert_eq!(
            install_commit(b"{\"commit\":\"75c3136\",\"commit\":\"75c3137\"}"),
            None
        );
        assert_eq!(install_commit(b"[\"75c3136\"]"), None);
        assert_eq!(install_commit(b"not json"), None);
    }
}
