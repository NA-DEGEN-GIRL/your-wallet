//! The Android secret windows on the gate's Windows build (2026-11-25 A2-7): the two-phase open,
//! the window model and its handles, the keys, the fills, the completions and the ends, through
//! the screen host as Java drives it. Test vectors only (the public BIP39 test phrase, synthetic
//! passwords).

use std::sync::Arc;

use yw_core::lang::Lang;
use yw_core::secret::SecretString;
use yw_core::vault::FileKind;
use yw_engine::apikeys::ApiKeys;
use yw_engine::app_store::{AppStore, SealedRead};
use yw_engine::cmd::{CorePress, Press};
use yw_engine::screen::model::Act;
use yw_engine::secret::{DisplaySecret, SecretKind};
use yw_engine::services::Services;
use yw_engine::settings::Settings;
use yw_engine::testkit::WalletTestExt;
use yw_engine::wallet::{AppMode, Purpose, Screen, Wallet};
use yw_engine::wire::InputOutcome;

use super::{FillItem, handle, parse_handle};
use crate::secret_keys::{TARGET_PICK, field_token};
use crate::ui_host::UiHost;

struct NoFiles;

impl AppStore for NoFiles {
    fn write_settings(&self, _json: &[u8]) -> bool {
        true
    }

    fn read_sealed_keys(&self) -> SealedRead {
        SealedRead::NotFound
    }

    fn write_sealed_keys(&self, _plain: &[u8]) -> bool {
        true
    }

    fn vault_file_info(&self) -> Option<(u64, u64)> {
        None
    }

    fn prev_exists(&self, _kind: FileKind) -> bool {
        false
    }

    fn reset_candidates(&self, _include_settings: bool) -> Vec<String> {
        Vec::new()
    }
}

fn host() -> UiHost {
    let clock = Arc::new(crate::clock::AndroidClock::new());
    let mut wallet = Wallet::new(
        Box::new(NoFiles),
        Services {
            llm: Arc::new(|_endpoint| None),
            walletconnect: None,
            ua_platform: "android",
        },
        false,
        Settings::default(),
        ApiKeys::default(),
        clock,
        0,
    );
    wallet.mode = AppMode::NoVault;
    wallet.screen = Screen::FirstRun;
    let mut host = UiHost::new(wallet);
    let _ = host.start();
    host
}

fn texts(frames: &[Vec<u8>]) -> Vec<String> {
    frames
        .iter()
        .map(|frame| String::from_utf8(frame.clone()).unwrap())
        .collect()
}

fn send(host: &mut UiHost, input: &str) -> Vec<String> {
    let (outcome, frames) = host.on_wire_input(input.as_bytes()).unwrap();
    assert_eq!(outcome, InputOutcome::Done, "{input}");
    texts(&frames)
}

fn press(host: &mut UiHost, press: Press) -> Vec<String> {
    let rev = host.wallet().drawn().map_or(0, yw_engine::wire::Drawn::rev);
    let slot = host
        .wallet()
        .drawn()
        .and_then(|drawn| drawn.slots_of(Act::Press(press)).next())
        .unwrap();
    send(
        host,
        &format!(r#"{{"t":"press","rev":{rev},"slot":{slot}}}"#),
    )
}

fn ready(serial: u64, win: u32, secure: bool) -> String {
    format!(
        r#"{{"t":"s_ready","serial":{serial},"win":{win},"secure":{secure},"sdk":29,"patch":"2021-01-01","adb":true,"adbw":false}}"#
    )
}

fn typed(host: &mut UiHost, win: u32, field: u8, text: &str) -> Vec<String> {
    let mut frames = Vec::new();
    for unit in text.encode_utf16() {
        frames.extend(texts(
            &host.on_secret_key(field_token(win, field), i32::from(unit)),
        ));
    }
    frames
}

fn fill(host: &UiHost, win: u32, item: FillItem) -> Option<String> {
    let handle = i64::try_from(handle(win, item)).unwrap();
    host.secret_fill(handle)
        .map(|units| String::from_utf16(&units).unwrap())
}

/// The serial of the window the last `s_open` frame asks for.
fn opened(frames: &[String]) -> u64 {
    let frame = frames
        .iter()
        .rev()
        .find(|frame| frame.starts_with(r#"{"t":"s_open","#))
        .expect("an s_open frame");
    frame
        .trim_start_matches(r#"{"t":"s_open","serial":"#)
        .trim_end_matches('}')
        .parse()
        .unwrap()
}

/// The create flow's W01: asked (no answer yet), made only by a secure ready of its serial, then
/// typed on the app keyboard. Nothing typed is in a frame; the fill gives dots unless `보기` is
/// held; a valid pair submits and the window closes.
#[test]
fn an_input_window_opens_in_two_phases() {
    let mut host = host();
    let _ = press(&mut host, Press::Core(CorePress::FirstCreate));
    let frames = press(&mut host, Press::Core(CorePress::CreateNext));
    let serial = opened(&frames);
    assert!(host.wallet().secret_unshown(serial), "no answer yet");
    assert_eq!(host.secret().asked_serial(), Some(serial));
    assert!(frames.iter().all(|frame| !frame.contains("E-SEC-001")));
    // The ready answer makes the window: its model, the session shown.
    let frames = send(&mut host, &ready(serial, 1, true));
    assert!(!host.wallet().secret_unshown(serial));
    assert_eq!(host.secret().open_window(), Some((serial, 1)));
    let model = frames
        .iter()
        .find(|frame| frame.starts_with(r#"{"t":"s_model","#))
        .unwrap();
    assert!(model.contains(r#""kind":"W01""#), "{model}");
    assert!(model.contains(r#""keys":"text""#), "{model}");
    // The debugging band of the secret surface, from the facts of this open.
    assert!(
        model.contains(yw_engine::protection::Band::Debugging.text(Lang::Ko)),
        "{model}"
    );
    // Typed on the app keyboard: never in a frame.
    let password = "correct horse 1x";
    let mut frames = typed(&mut host, 1, 0, password);
    frames.extend(typed(&mut host, 1, 1, password));
    assert!(
        frames.iter().all(|frame| !frame.contains("horse")),
        "{frames:?}"
    );
    assert!(
        frames
            .last()
            .is_some_and(|frame| frame.contains(r#""right":"16/128""#)),
        "{frames:?}"
    );
    // The second field became active with its first key.
    assert!(frames.last().unwrap().contains(r#""active":true,"reveal""#));
    let dots = fill(&host, 1, FillItem::Field(0)).unwrap();
    assert_eq!(dots.chars().count(), 16);
    assert!(!dots.contains('h'));
    // `보기` held: the plain text fills; released: dots again.
    let _ = send(
        &mut host,
        r#"{"t":"s_btn","win":1,"b":"reveal","i":0,"e":"down"}"#,
    );
    assert_eq!(
        fill(&host, 1, FillItem::Field(0)).as_deref(),
        Some(password)
    );
    let _ = send(
        &mut host,
        r#"{"t":"s_btn","win":1,"b":"reveal","i":0,"e":"out"}"#,
    );
    assert_ne!(
        fill(&host, 1, FillItem::Field(0)).as_deref(),
        Some(password)
    );
    // Another window's handle, a key of another window and an item it has not fill nothing.
    assert_eq!(fill(&host, 2, FillItem::Field(0)), None);
    assert_eq!(fill(&host, 1, FillItem::Shown), None);
    assert_eq!(fill(&host, 1, FillItem::Candidate(0)), None);
    assert!(typed(&mut host, 2, 0, "zz").is_empty());
    // A password window is not a plaintext one: losing the focus masks nothing.
    let _ = send(&mut host, r#"{"t":"s_focus","win":1,"on":false}"#);
    assert!(fill(&host, 1, FillItem::Field(0)).is_some());
    let _ = send(&mut host, r#"{"t":"s_focus","win":1,"on":true}"#);
    // The primary button submits: the session ends, the window closes, the wallet goes on.
    let _ = send(
        &mut host,
        r#"{"t":"s_btn","win":1,"b":"primary","i":0,"e":"down"}"#,
    );
    let frames = send(
        &mut host,
        r#"{"t":"s_btn","win":1,"b":"primary","i":0,"e":"up"}"#,
    );
    assert!(
        frames.contains(&format!(r#"{{"t":"s_close","serial":{serial}}}"#)),
        "{frames:?}"
    );
    assert!(!host.wallet().secret_open());
    assert_eq!(host.secret().open_window(), None);
    assert_eq!(fill(&host, 1, FillItem::Field(0)), None);
    assert!(frames.iter().all(|frame| !frame.contains("horse")));
}

/// A ready that did not read `FLAG_SECURE` back is refused (E-SEC-001, the window closed); a
/// ready for a serial not asked (late) only closes that window; an old window id is refused; an
/// open that never gets ready fails after the wait (E-APP-009).
#[test]
fn only_a_secure_ready_of_the_asked_serial_opens() {
    let mut host = host();
    let _ = press(&mut host, Press::Core(CorePress::FirstCreate));
    let serial = opened(&press(&mut host, Press::Core(CorePress::CreateNext)));
    // Late or unknown serial: only its window closes; the asked one still waits.
    let frames = send(&mut host, &ready(serial + 9, 3, true));
    assert_eq!(
        frames,
        [format!(r#"{{"t":"s_close","serial":{}}}"#, serial + 9)]
    );
    assert_eq!(host.secret().asked_serial(), Some(serial));
    // An older window id than one seen: refused, closed.
    let frames = send(&mut host, &ready(serial, 2, true));
    assert_eq!(frames, [format!(r#"{{"t":"s_close","serial":{serial}}}"#)]);
    assert_eq!(host.secret().asked_serial(), Some(serial));
    // Not secure: refused, the session ends with the band.
    let frames = send(&mut host, &ready(serial, 4, false));
    assert!(frames.contains(&format!(r#"{{"t":"s_close","serial":{serial}}}"#)));
    assert!(
        frames.iter().any(|frame| frame.contains("E-SEC-001")),
        "{frames:?}"
    );
    assert!(!host.wallet().secret_open());
    assert_eq!(host.secret().open_window(), None);
    // The next open (the intro is still shown) waits; with no ready the tick fails it after the
    // wait.
    let serial = opened(&press(&mut host, Press::Core(CorePress::CreateNext)));
    host.wallet_mut().clock = Arc::new(Later(super::OPEN_WAIT_MS + 60_000));
    let frames = send(&mut host, r#"{"t":"tick"}"#);
    assert!(frames.contains(&format!(r#"{{"t":"s_close","serial":{serial}}}"#)));
    assert!(
        frames.iter().any(|frame| frame.contains("E-APP-009")),
        "{frames:?}"
    );
    assert!(!host.wallet().secret_open());
}

/// A clock that reads `0` + a fixed offset (the open's wait).
struct Later(u64);

impl yw_platform::clock::Clock for Later {
    fn now_ms(&self) -> u64 {
        self.0
    }

    fn now_unix_ms(&self) -> u64 {
        1_795_564_800_000
    }

    fn sleep_ms(&self, _ms: u64) {}
}

/// The public test phrase (spec/02 §11.4), built at run time (`privacy-scan`).
fn phrase() -> String {
    let mut phrase = "abandon ".repeat(11);
    phrase.push_str("about");
    phrase
}

fn display(host: &mut UiHost) -> u64 {
    host.wallet_mut().open_display(
        SecretKind::ShowMnemonic { create: true },
        Purpose::ShowForBackup,
        DisplaySecret {
            text: SecretString::from_zeroizing(yw_core::secret::Zeroizing::new(phrase())),
            address: Some("0x9858EfFD232B4033E47d90003D41EC34EcaEda94".to_owned()),
            passphrase_note: false,
            copy_allowed: true,
        },
    );
    host.drain();
    opened(&texts(&host.take_frames()))
}

/// W08 (N23): the secret moves only into a window whose ready read `FLAG_SECURE` back, and only
/// `secretFill` with that window's handle gets it; the model has its handle, the address and the
/// countdown, never a word; no copy button (spec/15 §9.3). An unsecure ready wipes it.
#[test]
fn a_display_window_gets_the_secret_only_when_verified() {
    let mut host = host();
    let serial = display(&mut host);
    assert_eq!(fill(&host, 5, FillItem::Shown), None, "not open yet");
    let frames = send(&mut host, &ready(serial, 5, true));
    let model = frames
        .iter()
        .find(|frame| frame.starts_with(r#"{"t":"s_model","#))
        .unwrap();
    assert!(model.contains(r#""kind":"W08""#) && model.contains(r#""keys":"none""#));
    assert!(model.contains("0x9858EfFD232B4033E47d90003D41EC34EcaEda94"));
    assert!(
        !model.contains("abandon") && !model.contains("about "),
        "{model}"
    );
    assert!(!model.contains(r#""b":"copy""#), "{model}");
    assert!(model.contains(r#""hold":true"#), "{model}");
    assert_eq!(fill(&host, 5, FillItem::Shown), Some(phrase()));
    assert_eq!(fill(&host, 4, FillItem::Shown), None);
    // The hold of `다 적었습니다`: two seconds of ticks complete it; the window closes.
    let _ = send(
        &mut host,
        r#"{"t":"s_btn","win":5,"b":"primary","i":0,"e":"down"}"#,
    );
    host.wallet_mut().clock = Arc::new(Later(60_000));
    let frames = send(&mut host, r#"{"t":"tick"}"#);
    assert!(
        frames.contains(&format!(r#"{{"t":"s_close","serial":{serial}}}"#)),
        "{frames:?}"
    );
    assert_eq!(fill(&host, 5, FillItem::Shown), None);
    // Not secure: the window is refused and the session's secret wiped; nothing ever fills.
    let mut host = self::host();
    let serial = display(&mut host);
    let frames = send(&mut host, &ready(serial, 6, false));
    assert!(frames.contains(&format!(r#"{{"t":"s_close","serial":{serial}}}"#)));
    assert!(!host.wallet().secret_open());
    assert_eq!(fill(&host, 6, FillItem::Shown), None);
    // A Java window destroyed before its ready: refused the same way.
    let mut host = self::host();
    let serial = display(&mut host);
    let _ = send(
        &mut host,
        &format!(r#"{{"t":"s_gone","serial":{serial},"win":7}}"#),
    );
    assert!(!host.wallet().secret_open());
}

/// W05 (N22): the completions of the word being typed fill only through their handles, the model
/// always carries every completion handle and never a word, and a pick by index types the rest of
/// the word and a space.
#[test]
fn completions_fill_by_handle_and_are_picked_by_index() {
    let mut host = host();
    host.wallet_mut()
        .open_input(SecretKind::Mnemonic, Purpose::ImportMnemonic, false);
    host.drain();
    let serial = opened(&texts(&host.take_frames()));
    let _ = send(&mut host, &ready(serial, 1, true));
    let frames = typed(&mut host, 1, 0, "ab");
    let model = frames.last().unwrap();
    assert!(model.contains(r#""keys":"words""#), "{model}");
    assert_eq!(
        model.matches(r#"{"h":"#).count(),
        4,
        "every completion handle"
    );
    for word in ["abandon", "ability", "\"able\"", "about", "\"ab\""] {
        assert!(!model.contains(word), "{word}: {model}");
    }
    assert_eq!(
        fill(&host, 1, FillItem::Candidate(0)).as_deref(),
        Some("abandon")
    );
    assert_eq!(
        fill(&host, 1, FillItem::Candidate(3)).as_deref(),
        Some("about")
    );
    let frames = texts(&host.on_secret_key(field_token(1, TARGET_PICK), 3));
    assert!(frames.iter().all(|frame| !frame.contains("about")));
    assert_eq!(
        fill(&host, 1, FillItem::Field(0)).as_deref(),
        Some("about ")
    );
    // After the space: no completion fills, the handles are still all there.
    assert_eq!(fill(&host, 1, FillItem::Candidate(0)), None);
    // A plaintext window: losing the focus masks it, nothing fills; back, it fills again.
    let frames = send(&mut host, r#"{"t":"s_focus","win":1,"on":false}"#);
    assert!(
        frames
            .last()
            .is_some_and(|frame| !frame.contains(r#""masked":null"#)),
        "{frames:?}"
    );
    assert_eq!(fill(&host, 1, FillItem::Field(0)), None);
    let _ = send(&mut host, r#"{"t":"s_focus","win":1,"on":true}"#);
    assert_eq!(
        fill(&host, 1, FillItem::Field(0)).as_deref(),
        Some("about ")
    );
    // Back is Esc: the window cancels and closes.
    let frames = send(&mut host, r#"{"t":"s_back","win":1}"#);
    assert!(frames.contains(&format!(r#"{{"t":"s_close","serial":{serial}}}"#)));
    assert!(!host.wallet().secret_open());
}

/// The open window destroyed by the platform: its form is wiped and the wallet told it was
/// cancelled; the handles fill nothing.
#[test]
fn a_gone_window_cancels() {
    let mut host = host();
    let _ = press(&mut host, Press::Core(CorePress::FirstCreate));
    let serial = opened(&press(&mut host, Press::Core(CorePress::CreateNext)));
    let _ = send(&mut host, &ready(serial, 3, true));
    let _ = typed(&mut host, 3, 0, "abc");
    let _ = send(
        &mut host,
        &format!(r#"{{"t":"s_gone","serial":{serial},"win":3}}"#),
    );
    assert!(!host.wallet().secret_open());
    assert_eq!(fill(&host, 3, FillItem::Field(0)), None);
    assert_eq!(host.wallet().screen, Screen::FirstRun);
}

/// Handles name a window and an item; every other value fills nothing.
#[test]
fn the_handle_table() {
    for (win, item) in [
        (1, FillItem::Field(0)),
        (9, FillItem::Field(3)),
        (crate::secret_keys::WIN_MAX, FillItem::Shown),
        (2, FillItem::Candidate(3)),
    ] {
        let value = i64::try_from(handle(win, item)).unwrap();
        assert_eq!(parse_handle(value), Some((win, item)));
    }
    assert_eq!(handle(1, FillItem::Field(2)), 0x1_0002);
    assert_eq!(handle(1, FillItem::Shown), 0x1_0100);
    assert_eq!(handle(1, FillItem::Candidate(1)), 0x1_0201);
    for bad in [
        0_i64,
        0x0_0001,
        -1,
        0x1_0040,
        0x1_0101,
        0x1_0204,
        0x1_0300,
        i64::from(crate::secret_keys::WIN_MAX + 1) << 16,
    ] {
        assert_eq!(parse_handle(bad), None, "{bad:#x}");
    }
}
