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
//!   with A2-5. (2026-11-25 A2-5: it came: `app.java_uncaught`, written after the wipe.)
//!
//! 2026-11-25 A2-4b: the start input `{"t":"start","dir":"<path>"}` ([`start_dir`]), sent once by
//! `App.onCreate` with `Context.getNoBackupFilesDir()`: the shell's data folder is `<path>/v3`
//! (spec/15 §5.1), where the log file starts and the storage opens. It is parsed by yw-json
//! (strict, an object of exactly those two members) and the path must be absolute, printable
//! ASCII, without `..` components, at most [`START_MAX`] bytes in all; anything else is unknown.
//!
//! 2026-11-25 A2-5: the facts input
//! `{"t":"facts","sdk":<n>,"patch":"<YYYY-MM-DD or empty>","adb":<bool>,"adbw":<bool>}`
//! ([`facts`], spec/15 §1.1, §8.2), sent by `App.onCreate` after the start input and by the main
//! Activity's `onStart` (`Settings.Global` `adb_enabled`/`adb_wifi_enabled` change while the app
//! runs), parsed strictly like the start input (exactly those five members, `sdk` an integer up
//! to [`SDK_MAX`], `patch` a string of at most [`PATCH_MAX`] bytes that is read as unknown unless it is a
//! valid `YYYY-MM-DD`, at most [`START_MAX`] bytes). Its answer
//! is the main screen's warning bands ([`bands_answer`]: their texts in UTF-8, one per line, at
//! most [`BANDS_MAX`] bytes). (2026-11-25 A2-5 review: an input that begins like one
//! ([`is_facts`]) but is refused is answered with the worst case's bands, not with nothing.)
//!
//! A2-6 replaces all four with the yw-json input format (`Input`, spec/15 §3.2, §18 8).
//! Platform-neutral (no `unsafe`), so the gate's Windows build tests it; the JVM runner pins the
//! same bytes on the Java side (`JvmTests.interimInputs`).
#![forbid(unsafe_code)]

use std::path::PathBuf;

use yw_core::lang::Lang;
use yw_engine::protection::{Band, DeviceFacts, PatchDate};

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

/// The largest `sdk` a facts input may carry (a sanity bound, far above any API level).
pub const SDK_MAX: u64 = 1_000;

/// The longest `patch` string of a facts input (a longer one makes the input unknown).
pub const PATCH_MAX: usize = 16;

/// The longest answer of the facts input (Java's `Wire.BANDS_MAX`).
pub const BANDS_MAX: usize = 1_024;

/// How every facts input `Wire.facts` builds begins.
pub const FACTS_HEAD: &[u8] = br#"{"t":"facts","#;

/// The input says it is a facts input (it begins with [`FACTS_HEAD`]), whether or not
/// [`facts`] takes it: `call` answers one it refuses with the worst case's bands, never with
/// nothing (2026-11-25 A2-5 review: before, a refused facts input was answered with null and the
/// main screen drew no band at all, not even the test-build band).
#[must_use]
pub fn is_facts(input: &[u8]) -> bool {
    input.starts_with(FACTS_HEAD)
}

/// The device facts of a facts input (module doc), `None` for any other input.
#[must_use]
pub fn facts(input: &[u8]) -> Option<DeviceFacts> {
    if input.len() > START_MAX {
        return None;
    }
    let limits = yw_json::Limits {
        max_bytes: START_MAX,
        max_depth: 1,
        max_nodes: 12,
        max_items: 8,
    };
    let value = yw_json::parse(input, &limits).ok()?;
    let object = value.as_object()?;
    if object.len() != 5 || object.get("t")?.as_str()? != "facts" {
        return None;
    }
    facts_of(object)
}

/// The four facts members `sdk`, `patch`, `adb` and `adbw` of `object`, by the rules of
/// [`facts`] (2026-11-25 A2-7: also the secret window's ready input, `crate::secret_wire`, which
/// carries the facts read for that open, spec/15 §8.2). The caller checks the other members.
#[must_use]
pub fn facts_of(object: &yw_json::Object) -> Option<DeviceFacts> {
    let sdk = object.get("sdk")?.as_number()?.as_u64()?;
    if sdk > SDK_MAX {
        return None;
    }
    // Any patch string that is not a valid date (Java sends "" for one) reads as unknown, so as
    // old: the input is still taken, and the weak-protection band shows.
    let patch_text = object.get("patch")?.as_str()?;
    if patch_text.len() > PATCH_MAX {
        return None;
    }
    let patch = PatchDate::parse(patch_text);
    Some(DeviceFacts {
        sdk: u32::try_from(sdk).ok()?,
        patch,
        adb: object.get("adb")?.as_bool()?,
        adb_wifi: object.get("adbw")?.as_bool()?,
    })
}

/// The answer of the facts input: the bands' texts in `lang`, one per line (no line end after the
/// last), never more than [`BANDS_MAX`] bytes (a band that would pass it is left out with the
/// ones after it; the three texts are far shorter).
#[must_use]
pub fn bands_answer(bands: &[Band], lang: Lang) -> Vec<u8> {
    let mut out = Vec::new();
    for band in bands {
        let text = band.text(lang).as_bytes();
        let extra = usize::from(!out.is_empty());
        if out.len().saturating_add(extra).saturating_add(text.len()) > BANDS_MAX {
            break;
        }
        if extra == 1 {
            out.push(b'\n');
        }
        out.extend_from_slice(text);
    }
    out
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

    use yw_core::lang::Lang;
    use yw_engine::protection::{Band, DeviceFacts, PatchDate};

    use super::{
        ABI, BANDS_MAX, Interim, JAVA_UNCAUGHT, MAX_INPUT, START_MAX, STATUS, STATUS_LINE,
        bands_answer, classify, facts, is_facts, start_dir,
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

    /// The bytes `Wire.facts` builds for the test device (`JvmTests.factsInput`).
    #[test]
    fn the_facts_input() {
        assert_eq!(
            facts(b"{\"t\":\"facts\",\"sdk\":29,\"patch\":\"2021-01-01\",\"adb\":true,\"adbw\":false}"),
            Some(DeviceFacts {
                sdk: 29,
                patch: PatchDate::parse("2021-01-01"),
                adb: true,
                adb_wifi: false,
            })
        );
        assert_eq!(
            facts(b"{\"t\":\"facts\",\"sdk\":36,\"patch\":\"\",\"adb\":false,\"adbw\":true}"),
            Some(DeviceFacts {
                sdk: 36,
                patch: None,
                adb: false,
                adb_wifi: true,
            })
        );
        // A patch that is not a valid date is unknown, not a refused input.
        for patch in ["2021-1-01", "x", "2021-13-45", "0000000000000000"] {
            let input = format!(
                "{{\"t\":\"facts\",\"sdk\":29,\"patch\":\"{patch}\",\"adb\":false,\"adbw\":false}}"
            );
            assert_eq!(
                facts(input.as_bytes()).map(|facts| facts.patch),
                Some(None),
                "{patch}"
            );
        }
        for bad in [
            &b"{\"t\":\"facts\",\"sdk\":29,\"patch\":\"2021-01-01-01-01-0\",\"adb\":true,\"adbw\":false}"[..],
            b"{\"t\":\"facts\",\"sdk\":29,\"patch\":7,\"adb\":true,\"adbw\":false}",
            b"{\"t\":\"facts\",\"sdk\":-1,\"patch\":\"\",\"adb\":true,\"adbw\":false}",
            b"{\"t\":\"facts\",\"sdk\":29.5,\"patch\":\"\",\"adb\":true,\"adbw\":false}",
            b"{\"t\":\"facts\",\"sdk\":1001,\"patch\":\"\",\"adb\":true,\"adbw\":false}",
            b"{\"t\":\"facts\",\"sdk\":\"29\",\"patch\":\"\",\"adb\":true,\"adbw\":false}",
            b"{\"t\":\"facts\",\"sdk\":29,\"patch\":\"\",\"adb\":1,\"adbw\":false}",
            b"{\"t\":\"facts\",\"sdk\":29,\"patch\":\"\",\"adb\":true}",
            b"{\"t\":\"facts\",\"sdk\":29,\"patch\":\"\",\"adb\":true,\"adbw\":false,\"x\":1}",
            b"{\"t\":\"facts\",\"sdk\":29,\"patch\":\"\",\"adb\":true,\"adb\":false}",
            b"{\"t\":\"fact\",\"sdk\":29,\"patch\":\"\",\"adb\":true,\"adbw\":false}",
            b"{\"t\":\"start\",\"dir\":\"/a\"}",
            STATUS,
            JAVA_UNCAUGHT,
        ] {
            assert_eq!(facts(bad), None, "{}", String::from_utf8_lossy(bad));
            // A refused one that begins like a facts input is still one (the worst case's
            // answer, 2026-11-25 A2-5 review); the others are not.
            assert_eq!(
                is_facts(bad),
                bad.starts_with(b"{\"t\":\"facts\","),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
        for refused in [
            &b"{\"t\":\"facts\",\"sdk\":1001,\"patch\":\"\",\"adb\":true,\"adbw\":false}"[..],
            b"{\"t\":\"facts\",",
            b"{\"t\":\"facts\",\"sdk\":29,\"patch\":\"\",\"adb\":true,\"adbw\":false,\"x\":1}",
        ] {
            assert!(is_facts(refused) && facts(refused).is_none());
        }
        for other in [
            &b""[..],
            b"{\"t\":\"facts\"}",
            b"{\"t\":\"fact\",\"sdk\":29}",
            b" {\"t\":\"facts\",",
            STATUS,
            JAVA_UNCAUGHT,
        ] {
            assert!(!is_facts(other), "{}", String::from_utf8_lossy(other));
        }
        assert!(is_facts(
            b"{\"t\":\"facts\",\"sdk\":29,\"patch\":\"\",\"adb\":true,\"adbw\":false}"
        ));
        assert_eq!(
            classify(b"{\"t\":\"facts\",\"sdk\":29,\"patch\":\"\",\"adb\":true,\"adbw\":false}"),
            Interim::Unknown
        );
    }

    #[test]
    fn the_bands_answer_is_lines_of_text() {
        assert_eq!(bands_answer(&[], Lang::Ko), b"");
        let answer = bands_answer(&[Band::TestBuild, Band::WeakDevice], Lang::Ko);
        let text = String::from_utf8(answer).unwrap();
        assert_eq!(
            text.split('\n').collect::<Vec<_>>(),
            [
                Band::TestBuild.text(Lang::Ko),
                Band::WeakDevice.text(Lang::Ko)
            ]
        );
        let all = bands_answer(
            &[Band::TestBuild, Band::WeakDevice, Band::Debugging],
            Lang::En,
        );
        assert!(all.len() <= BANDS_MAX);
        assert_eq!(all.split(|unit| *unit == b'\n').count(), 3);
        assert!(all.iter().all(|unit| *unit >= 0x20 || *unit == b'\n'));
        let many = [Band::Debugging; 40];
        let capped = bands_answer(&many, Lang::Ko);
        assert!(capped.len() <= BANDS_MAX && !capped.is_empty());
        assert!(!capped.ends_with(b"\n"));
    }
}
