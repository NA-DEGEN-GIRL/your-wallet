//! The two inputs `call` knows before the wire format of A2-6 exists (spec/15 §3.2; 2026-11-24 A2-3).
//!
//! Java (`dev.yw.app.Wire`) sends one of two fixed byte strings; anything else is unknown and answered
//! with nothing (null). They are matched byte for byte, never parsed:
//!
//! - [`STATUS`]: the answer is [`STATUS_LINE`], the library version and ABI as printable ASCII (no
//!   words, so nothing to translate, spec/15 §3.3, spec/14), which the main Activity draws as the
//!   device smoke of the skeleton;
//! - [`JAVA_UNCAUGHT`]: the fixed event of Java's uncaught-exception handler (spec/15 §3.3): the
//!   process ends like a panic (every slot wiped, then `_exit`). The one log line of that end comes
//!   with the log sink (A2-4b, A2-5).
//!
//! A2-6 replaces both with the yw-json input format (`Input`, spec/15 §3.2, §18 8). Platform-neutral
//! (no `unsafe`), so the gate's Windows build tests it; the JVM runner pins the same bytes on the Java
//! side (`JvmTests.interimInputs`).
#![forbid(unsafe_code)]

/// The status request (`{"t":"status"}`).
pub const STATUS: &[u8] = br#"{"t":"status"}"#;

/// The uncaught-exception event (`{"t":"java_uncaught"}`).
pub const JAVA_UNCAUGHT: &[u8] = br#"{"t":"java_uncaught"}"#;

/// The longest input `call` reads before A2-6: longer ones are unknown without being read.
pub const MAX_INPUT: usize = 32;

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
    /// Anything else: answered with nothing.
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
    use super::{ABI, Interim, JAVA_UNCAUGHT, MAX_INPUT, STATUS, STATUS_LINE, classify};

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
