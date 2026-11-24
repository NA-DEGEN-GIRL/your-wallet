//! The inputs `call` knows before the wire format of A2-6 exists (spec/15 §3.2; 2026-11-24 A2-3,
//! 2026-11-25 A2-4b).
//!
//! Java (`dev.yw.app.Wire`) sends one of two fixed byte strings or the start input; anything else
//! is unknown and answered with nothing (null). The fixed ones are matched byte for byte, never
//! parsed:
//!
//! - [`STATUS`]: the answer is [`STATUS_LINE`], the library version and ABI as printable ASCII (no
//!   words, so nothing to translate, spec/15 §3.3, spec/14), which the main Activity draws as the
//!   device smoke of the skeleton;
//! - [`JAVA_UNCAUGHT`]: the fixed event of Java's uncaught-exception handler (spec/15 §3.3): the
//!   process ends like a panic (every slot wiped, then `_exit`). The one log line of that end comes
//!   with A2-5.
//!
//! 2026-11-25 A2-4b: the start input `{"t":"start","dir":"<path>"}` ([`start_dir`]), sent once by
//! `App.onCreate` with `Context.getNoBackupFilesDir()`: the shell's data folder is `<path>/v3`
//! (spec/15 §5.1), where the log file starts and the storage opens. It is parsed by yw-json
//! (strict, an object of exactly those two members) and the path must be absolute, printable
//! ASCII, without `..` components, at most [`START_MAX`] bytes in all; anything else is unknown.
//!
//! A2-6 replaces all three with the yw-json input format (`Input`, spec/15 §3.2, §18 8).
//! Platform-neutral (no `unsafe`), so the gate's Windows build tests it; the JVM runner pins the
//! same bytes on the Java side (`JvmTests.interimInputs`).
#![forbid(unsafe_code)]

use std::path::PathBuf;

/// The status request (`{"t":"status"}`).
pub const STATUS: &[u8] = br#"{"t":"status"}"#;

/// The uncaught-exception event (`{"t":"java_uncaught"}`).
pub const JAVA_UNCAUGHT: &[u8] = br#"{"t":"java_uncaught"}"#;

/// The longest fixed input: a longer input is a start input or unknown.
pub const MAX_INPUT: usize = 32;

/// The longest start input `call` reads (longer ones are unknown without being read).
pub const START_MAX: usize = 1_024;

/// The ABI name of the build target, as the APK's `lib/<abi>/` folder names it.
const ABI: &str = if cfg!(target_arch = "aarch64") {
    "arm64-v8a"
} else if cfg!(target_arch = "x86_64") {
    "x86_64"
} else {
    "other"
};

/// The status line: `yw <crate version> <ABI>` (`concat!` cannot take a `const`, so the cases of
/// [`ABI`] are spelled out; the unit test checks they agree).
pub const STATUS_LINE: &str = if cfg!(target_arch = "aarch64") {
    concat!("yw ", env!("CARGO_PKG_VERSION"), " arm64-v8a")
} else if cfg!(target_arch = "x86_64") {
    concat!("yw ", env!("CARGO_PKG_VERSION"), " x86_64")
} else {
    concat!("yw ", env!("CARGO_PKG_VERSION"), " other")
};

/// What an input of `call` is, before A2-6.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Interim {
    /// [`STATUS`].
    Status,
    /// [`JAVA_UNCAUGHT`].
    JavaUncaught,
    /// Anything else: a start input ([`start_dir`]) or unknown.
    Unknown,
}

/// Classifies the bytes of one input (exact match only).
#[must_use]
pub fn classify(input: &[u8]) -> Interim {
    if input == STATUS {
        Interim::Status
    } else if input == JAVA_UNCAUGHT {
        Interim::JavaUncaught
    } else {
        Interim::Unknown
    }
}

/// The folder of a start input (module doc), `None` for any other input.
#[must_use]
pub fn start_dir(input: &[u8]) -> Option<PathBuf> {
    if input.len() > START_MAX {
        return None;
    }
    let limits = yw_json::Limits {
        max_bytes: START_MAX,
        max_depth: 1,
        max_nodes: 8,
        max_items: 4,
    };
    let value = yw_json::parse(input, &limits).ok()?;
    let object = value.as_object()?;
    if object.len() != 2 || object.get("t")?.as_str()? != "start" {
        return None;
    }
    let dir = object.get("dir")?.as_str()?;
    let plain = dir
        .bytes()
        .all(|unit| (0x21..=0x7e).contains(&unit) && unit != b'\\' && unit != b'"');
    if !plain || !dir.starts_with('/') || dir.split('/').any(|part| part == ".." || part == ".") {
        return None;
    }
    Some(PathBuf::from(dir))
}

// The status line is printable ASCII that Java accepts (`Wire.STATUS_MAX` = 64), and both inputs fit
// `MAX_INPUT`, at compile time.
const _: () = {
    let line = STATUS_LINE.as_bytes();
    assert!(!line.is_empty() && line.len() <= 64);
    let mut at = 0;
    while at < line.len() {
        assert!(line[at] >= 0x20 && line[at] <= 0x7e);
        at += 1;
    }
    assert!(STATUS.len() <= MAX_INPUT && JAVA_UNCAUGHT.len() <= MAX_INPUT);
    assert!(!ABI.is_empty());
};

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{
        ABI, Interim, JAVA_UNCAUGHT, MAX_INPUT, START_MAX, STATUS, STATUS_LINE, classify, start_dir,
    };

    /// The same bytes as `dev.yw.app.Wire` (pinned on the Java side by `JvmTests.interimInputs`).
    #[test]
    fn the_inputs_are_the_java_bytes() {
        assert_eq!(STATUS, b"{\"t\":\"status\"}");
        assert_eq!(JAVA_UNCAUGHT, b"{\"t\":\"java_uncaught\"}");
        assert!(STATUS.len() <= MAX_INPUT && JAVA_UNCAUGHT.len() <= MAX_INPUT);
    }

    #[test]
    fn only_exact_bytes_match() {
        assert_eq!(classify(STATUS), Interim::Status);
        assert_eq!(classify(JAVA_UNCAUGHT), Interim::JavaUncaught);
        for other in [
            &b""[..],
            b"{\"t\":\"status\"} ",
            b"{\"t\": \"status\"}",
            b"{\"t\":\"STATUS\"}",
            b"{\"t\":\"java_uncaught\"}\0",
            b"{\"t\":\"java\"}",
        ] {
            assert_eq!(classify(other), Interim::Unknown, "{other:?}");
        }
    }

    /// The bytes `Wire.start` builds for the test device's folder (`JvmTests.startInput`).
    #[test]
    fn the_start_input() {
        assert_eq!(
            start_dir(b"{\"t\":\"start\",\"dir\":\"/data/user/0/dev.yw.app/no_backup\"}"),
            Some(Path::new("/data/user/0/dev.yw.app/no_backup").to_path_buf())
        );
        assert_eq!(
            classify(b"{\"t\":\"start\",\"dir\":\"/d\"}"),
            Interim::Unknown
        );
        for bad in [
            &b"{\"t\":\"start\",\"dir\":\"relative/x\"}"[..],
            b"{\"t\":\"start\",\"dir\":\"/a/../b\"}",
            b"{\"t\":\"start\",\"dir\":\"/a/./b\"}",
            b"{\"t\":\"start\",\"dir\":\"/a b\"}",
            b"{\"t\":\"start\",\"dir\":\"/a\\\\b\"}",
            b"{\"t\":\"start\",\"dir\":\"/a\\u0000b\"}",
            b"{\"t\":\"start\",\"dir\":\"/\xc3\xa9\"}",
            b"{\"t\":\"start\",\"dir\":\"\"}",
            b"{\"t\":\"start\",\"dir\":7}",
            b"{\"t\":\"start\"}",
            b"{\"t\":\"start\",\"dir\":\"/a\",\"x\":1}",
            b"{\"t\":\"start\",\"dir\":\"/a\",\"dir\":\"/b\"}",
            b"{\"t\":\"stop\",\"dir\":\"/a\"}",
            b"[\"start\",\"/a\"]",
            STATUS,
        ] {
            assert_eq!(start_dir(bad), None, "{}", String::from_utf8_lossy(bad));
        }
        let mut long = b"{\"t\":\"start\",\"dir\":\"/".to_vec();
        long.resize(START_MAX, b'a');
        long.extend_from_slice(b"\"}");
        assert_eq!(start_dir(&long), None, "over START_MAX");
    }

    #[test]
    fn the_status_line_is_version_and_abi() {
        assert_eq!(
            STATUS_LINE,
            format!("yw {} {ABI}", env!("CARGO_PKG_VERSION"))
        );
        assert!(
            STATUS_LINE
                .bytes()
                .all(|unit| (0x20..=0x7e).contains(&unit))
        );
        assert!(STATUS_LINE.len() <= 64);
    }
}
