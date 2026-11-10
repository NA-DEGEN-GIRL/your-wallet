//! Which build is running (2026-11-10): the commit that `install.ps1` wrote to the installation
//! record `yw-install.json` next to the executable (spec/01 §9), shown in 설정 → 브라우저·정보 →
//! 정보 ("버전 0.3.0 · 커밋 75c3136a1b2c") and in the `app.start` log line. Only `commit` is read,
//! and only a lowercase hex value of 7–40 digits is used; the other fields and the file hashes are
//! not read. No record (a development build, or an older installation without `commit`) is
//! "설치 기록 없음 — 개발 빌드".

use yw_json::{Limits, Value};

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

/// The 정보 card's version line: "0.3.0 · 커밋 75c3136a1b2c", or the development-build note.
#[must_use]
pub fn version_text(commit: Option<&str>) -> String {
    let version = env!("CARGO_PKG_VERSION");
    match commit {
        Some(commit) => format!(
            "{version} · 커밋 {}",
            commit.get(..COMMIT_SHOWN).unwrap_or(commit)
        ),
        None => format!("{version} · 설치 기록 없음 — 개발 빌드"),
    }
}

#[cfg(test)]
mod tests {
    use super::install_commit;

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
