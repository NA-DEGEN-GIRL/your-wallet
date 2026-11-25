//! The secret windows' half of the Android wire (spec/15 §3.2, §9.1; 2026-11-25 A2-7): the
//! inputs Java's secret window sends through `call` and the frames the shell hands it through
//! `next`. Every `t` of this half starts with `s_`, which no input of yw-engine's `wire` does, so
//! the screen host tries this decoder first. None carries a secret: a typed unit goes through
//! `secretKey` and a shown text through `secretFill`, never here.
//!
//! Inputs (strict yw-json, exactly these members, at most [`SECRET_INPUT_MAX`] bytes):
//!
//! - `{"t":"s_ready","serial":S,"win":W,"secure":B,"sdk":N,"patch":"…","adb":B,"adbw":B}`: the
//!   window Java opened for secret session `S` (Activity instance `W`, counted up from 1 in the
//!   process and never reused) is attached, and `secure` is what it read back of its own
//!   `FLAG_SECURE` (spec/15 §9.1: the second phase of the open, §18 42 N23). The facts are those
//!   it read for this open (spec/15 §8.2: the debugging band), by the facts input's rules
//!   (`crate::interim::facts_of`); facts that do not parse leave the worst case (the window still
//!   opens).
//! - `{"t":"s_btn","win":W,"b":"<word>","i":N,"e":"down"|"up"|"out"}`: a button, a field's
//!   `보기` (`reveal`, `i` its field) or a field box (`field`, `i` its index) of window `W`
//!   (`crate::secret_keys::control`).
//! - `{"t":"s_focus","win":W,"on":B}`: window `W` got or lost the focus.
//! - `{"t":"s_back","win":W}`: the Back key in window `W`.
//! - `{"t":"s_gone","serial":S,"win":W}`: window `W` of session `S` is destroyed (Java wiped what
//!   it drew).
//!
//! Frames: `{"t":"s_open","serial":S}` (open a secret window for session `S`),
//! `{"t":"s_close","serial":S}` (close every window of that session, wiped) and the window's
//! model `s_model` (`crate::secret_host`). 2026-11-25 A2-7 review: also
//! `{"t":"s_close_win","serial":S,"win":W}` (close that one window: a ready the host did not take,
//! late or a repeated or older instance; before, such a ready got `s_close` of its whole session,
//! which also closed the window the host kept open) and
//! `{"t":"s_keep","wins":[{"serial":S,"win":W},…]}` (the host's resync, `UiHost::resync`: Java
//! closes every secret window not named; `W` 0 keeps every window of an asked session whose
//! instance is not known yet), so that a `s_close` the full UI queue dropped still closes its
//! window. Platform-neutral: the gate's Windows build tests it; Java's `SecretWire` builds the
//! same bytes (`JvmTests.secretInputs`, `JvmTests.secretWindows`).
#![forbid(unsafe_code)]

use yw_engine::protection::DeviceFacts;
use yw_json::{Number, Object, Value};

use crate::secret_keys::{Control, Edge, WIN_MAX, control};

/// The longest secret-window input read.
pub const SECRET_INPUT_MAX: usize = 1_024;

/// How every input of this half begins.
const HEAD: &[u8] = b"{\"t\":\"s_";

/// One input of a secret window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretInput {
    /// The window of session `serial` is attached and read back its `FLAG_SECURE`.
    Ready {
        /// The secret session the window was opened for.
        serial: u64,
        /// The window (Activity instance).
        win: u32,
        /// `FLAG_SECURE` was set and read back.
        secure: bool,
        /// The device facts read for this open (`None`: the worst case).
        facts: Option<DeviceFacts>,
    },
    /// A button, a `보기` or a field box.
    Button {
        /// The window.
        win: u32,
        /// What was touched.
        control: Control,
        /// What the touch did.
        edge: Edge,
    },
    /// The window got (`true`) or lost the focus.
    Focus {
        /// The window.
        win: u32,
        /// Got the focus.
        on: bool,
    },
    /// The Back key.
    Back {
        /// The window.
        win: u32,
    },
    /// The window is destroyed.
    Gone {
        /// The session it was opened for.
        serial: u64,
        /// The window.
        win: u32,
    },
}

/// Whether `bytes` say they are a secret-window input (they begin with `{"t":"s_`), whether or
/// not [`decode`] takes them.
#[must_use]
pub fn is_secret_input(bytes: &[u8]) -> bool {
    bytes.starts_with(HEAD)
}

/// Whether the input is the user's own (a button, a field box, the Back key) and so restarts the
/// idle clock (2026-11-25 A2-8, spec/04 §5.1): a window's ready, focus change or end is not.
#[must_use]
pub const fn is_user_input(input: &SecretInput) -> bool {
    matches!(input, SecretInput::Button { .. } | SecretInput::Back { .. })
}

fn win_of(object: &Object) -> Option<u32> {
    let win = u32::try_from(object.get("win")?.as_number()?.as_u64()?).ok()?;
    (1..=WIN_MAX).contains(&win).then_some(win)
}

/// One secret-window input (module doc); `None` for anything else, a member too many or too few,
/// or a value out of range.
#[must_use]
pub fn decode(bytes: &[u8]) -> Option<SecretInput> {
    if bytes.len() > SECRET_INPUT_MAX || !is_secret_input(bytes) {
        return None;
    }
    let limits = yw_json::Limits {
        max_bytes: SECRET_INPUT_MAX,
        max_depth: 1,
        max_nodes: 24,
        max_items: 12,
    };
    let value = yw_json::parse(bytes, &limits).ok()?;
    let object = value.as_object()?;
    let members = object.len();
    match object.get("t")?.as_str()? {
        "s_ready" if members == 8 => Some(SecretInput::Ready {
            serial: object.get("serial")?.as_number()?.as_u64()?,
            win: win_of(object)?,
            secure: object.get("secure")?.as_bool()?,
            facts: crate::interim::facts_of(object),
        }),
        "s_btn" if members == 5 => {
            let index = usize::try_from(object.get("i")?.as_number()?.as_u64()?).ok()?;
            Some(SecretInput::Button {
                win: win_of(object)?,
                control: control(object.get("b")?.as_str()?, index)?,
                edge: Edge::from_word(object.get("e")?.as_str()?)?,
            })
        }
        "s_focus" if members == 3 => Some(SecretInput::Focus {
            win: win_of(object)?,
            on: object.get("on")?.as_bool()?,
        }),
        "s_back" if members == 2 => Some(SecretInput::Back {
            win: win_of(object)?,
        }),
        "s_gone" if members == 3 => Some(SecretInput::Gone {
            serial: object.get("serial")?.as_number()?.as_u64()?,
            win: win_of(object)?,
        }),
        _ => None,
    }
}

/// `{"t":"s_open","serial":S}`.
#[must_use]
pub fn open_frame(serial: u64) -> Vec<u8> {
    serial_frame("s_open", serial)
}

/// `{"t":"s_close","serial":S}`.
#[must_use]
pub fn close_frame(serial: u64) -> Vec<u8> {
    serial_frame("s_close", serial)
}

/// `{"t":"s_close_win","serial":S,"win":W}` (2026-11-25 A2-7 review, module doc).
#[must_use]
pub fn close_win_frame(serial: u64, win: u32) -> Vec<u8> {
    let object = Object::from_pairs(vec![
        ("t".to_owned(), Value::String("s_close_win".to_owned())),
        ("serial".to_owned(), Value::Number(Number::from_u64(serial))),
        (
            "win".to_owned(),
            Value::Number(Number::from_u64(u64::from(win))),
        ),
    ])
    .map_or(Value::Null, Value::Object);
    yw_json::to_vec(&object)
}

/// `{"t":"s_keep","wins":[{"serial":S,"win":W},…]}`: the only secret windows that may exist, `W`
/// 0 for every window of `S` (2026-11-25 A2-7 review, module doc).
#[must_use]
pub fn keep_frame(wins: &[(u64, u32)]) -> Vec<u8> {
    let wins = wins
        .iter()
        .map(|&(serial, win)| {
            Object::from_pairs(vec![
                ("serial".to_owned(), Value::Number(Number::from_u64(serial))),
                (
                    "win".to_owned(),
                    Value::Number(Number::from_u64(u64::from(win))),
                ),
            ])
            .map_or(Value::Null, Value::Object)
        })
        .collect();
    let object = Object::from_pairs(vec![
        ("t".to_owned(), Value::String("s_keep".to_owned())),
        ("wins".to_owned(), Value::Array(wins)),
    ])
    .map_or(Value::Null, Value::Object);
    yw_json::to_vec(&object)
}

fn serial_frame(kind: &str, serial: u64) -> Vec<u8> {
    let object = Object::from_pairs(vec![
        ("t".to_owned(), Value::String(kind.to_owned())),
        ("serial".to_owned(), Value::Number(Number::from_u64(serial))),
    ])
    .map_or(Value::Null, Value::Object);
    yw_json::to_vec(&object)
}

#[cfg(test)]
mod tests {
    use yw_engine::protection::{DeviceFacts, PatchDate};
    use yw_engine::secret::input::SecretButton;

    use super::{
        SecretInput, close_frame, close_win_frame, decode, is_secret_input, keep_frame, open_frame,
    };
    use crate::secret_keys::{Control, Edge};

    /// The bytes Java's `SecretWire` builds (pinned by `JvmTests.secretInputs`).
    #[test]
    fn the_java_inputs() {
        assert_eq!(
            decode(br#"{"t":"s_ready","serial":4,"win":2,"secure":true,"sdk":29,"patch":"2021-01-01","adb":true,"adbw":false}"#),
            Some(SecretInput::Ready {
                serial: 4,
                win: 2,
                secure: true,
                facts: Some(DeviceFacts {
                    sdk: 29,
                    patch: PatchDate::parse("2021-01-01"),
                    adb: true,
                    adb_wifi: false,
                }),
            })
        );
        assert_eq!(
            decode(br#"{"t":"s_btn","win":2,"b":"reveal","i":1,"e":"down"}"#),
            Some(SecretInput::Button {
                win: 2,
                control: Control::Button(SecretButton::Reveal(1)),
                edge: Edge::Down,
            })
        );
        assert_eq!(
            decode(br#"{"t":"s_btn","win":2,"b":"field","i":0,"e":"down"}"#),
            Some(SecretInput::Button {
                win: 2,
                control: Control::Field(0),
                edge: Edge::Down,
            })
        );
        assert_eq!(
            decode(br#"{"t":"s_focus","win":2,"on":false}"#),
            Some(SecretInput::Focus { win: 2, on: false })
        );
        assert_eq!(
            decode(br#"{"t":"s_back","win":2}"#),
            Some(SecretInput::Back { win: 2 })
        );
        assert_eq!(
            decode(br#"{"t":"s_gone","serial":4,"win":2}"#),
            Some(SecretInput::Gone { serial: 4, win: 2 })
        );
        // Facts that do not parse leave the worst case; the ready is still taken.
        assert_eq!(
            decode(br#"{"t":"s_ready","serial":4,"win":2,"secure":false,"sdk":"x","patch":"","adb":true,"adbw":false}"#),
            Some(SecretInput::Ready {
                serial: 4,
                win: 2,
                secure: false,
                facts: None,
            })
        );
    }

    #[test]
    fn everything_else_is_refused() {
        for bad in [
            &br#"{"t":"s_ready","serial":4,"win":2,"secure":true}"#[..],
            br#"{"t":"s_ready","serial":4,"win":0,"secure":true,"sdk":29,"patch":"","adb":true,"adbw":false}"#,
            br#"{"t":"s_ready","serial":-4,"win":2,"secure":true,"sdk":29,"patch":"","adb":true,"adbw":false}"#,
            br#"{"t":"s_ready","serial":4,"win":2,"secure":1,"sdk":29,"patch":"","adb":true,"adbw":false}"#,
            br#"{"t":"s_ready","serial":4,"win":8388608,"secure":true,"sdk":29,"patch":"","adb":true,"adbw":false}"#,
            br#"{"t":"s_btn","win":2,"b":"copy","i":0,"e":"down"}"#,
            br#"{"t":"s_btn","win":2,"b":"primary","i":0,"e":"move"}"#,
            br#"{"t":"s_btn","win":2,"b":"primary","e":"down"}"#,
            br#"{"t":"s_btn","win":2,"b":"primary","i":0,"e":"down","x":1}"#,
            br#"{"t":"s_focus","win":2}"#,
            br#"{"t":"s_back","win":2,"win":3}"#,
            br#"{"t":"s_gone","win":2}"#,
            br#"{"t":"s_other","win":2}"#,
            br#"{"t":"press","rev":1,"slot":0}"#,
            br#" {"t":"s_back","win":2}"#,
            b"",
        ] {
            assert_eq!(decode(bad), None, "{}", String::from_utf8_lossy(bad));
        }
        assert!(is_secret_input(br#"{"t":"s_other"}"#));
        assert!(!is_secret_input(br#"{"t":"press"}"#));
        let mut long = br#"{"t":"s_back","win":2,"x":""#.to_vec();
        long.resize(super::SECRET_INPUT_MAX, b'a');
        long.extend_from_slice(b"\"}");
        assert_eq!(decode(&long), None);
    }

    #[test]
    fn the_frames() {
        assert_eq!(open_frame(7), br#"{"t":"s_open","serial":7}"#);
        assert_eq!(close_frame(7), br#"{"t":"s_close","serial":7}"#);
        // 2026-11-25 A2-7 review; the bytes `JvmTests.secretWindows` reads.
        assert_eq!(
            close_win_frame(7, 2),
            br#"{"t":"s_close_win","serial":7,"win":2}"#
        );
        assert_eq!(
            keep_frame(&[(8, 5), (10, 0)]),
            br#"{"t":"s_keep","wins":[{"serial":8,"win":5},{"serial":10,"win":0}]}"#
        );
        assert_eq!(keep_frame(&[]), br#"{"t":"s_keep","wins":[]}"#);
    }
}
