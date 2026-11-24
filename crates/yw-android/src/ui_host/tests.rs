//! The Android shell's screen host on the gate's Windows build (2026-11-25 A2-6): a wallet with no
//! workers and no files, the frames it hands Java, and the answers it gives itself.

use std::sync::Arc;

use yw_core::vault::FileKind;
use yw_engine::apikeys::ApiKeys;
use yw_engine::app_store::{AppStore, SealedRead};
use yw_engine::cmd::{CorePress, Press};
use yw_engine::effect::{Effect, TimerId};
use yw_engine::screen::model::Act;
use yw_engine::secret::{SecretEffect, SecretKind};
use yw_engine::services::Services;
use yw_engine::settings::Settings;
use yw_engine::wallet::{AppMode, Screen, Wallet};
use yw_engine::wire::InputOutcome;

use super::UiHost;

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
    UiHost::new(wallet)
}

fn texts(frames: &[Vec<u8>]) -> Vec<String> {
    frames
        .iter()
        .map(|frame| String::from_utf8(frame.clone()).unwrap())
        .collect()
}

fn slot_of(host: &UiHost, press: Press) -> u32 {
    host.wallet()
        .drawn()
        .and_then(|drawn| drawn.slots_of(Act::Press(press)).next())
        .unwrap()
}

/// The start draws the screen; a press of a drawn control draws the next screen with the next
/// revision; a stale press and bytes that are no input change nothing.
#[test]
fn a_press_draws_the_next_model() {
    let mut host = host();
    let start = texts(&host.start());
    assert_eq!(start.len(), 1);
    assert!(
        start[0].starts_with(r#"{"t":"model","rev":1,"#),
        "{}",
        start[0]
    );
    let create = slot_of(&host, Press::Core(CorePress::FirstCreate));
    let stale = format!(r#"{{"t":"press","rev":0,"slot":{create}}}"#);
    let (outcome, frames) = host.on_wire_input(stale.as_bytes()).unwrap();
    assert_eq!(outcome, InputOutcome::Stale);
    assert!(frames.is_empty());
    assert!(host.on_wire_input(b"{\"t\":\"press\"}").is_err());
    let input = format!(r#"{{"t":"press","rev":1,"slot":{create}}}"#);
    let (outcome, frames) = host.on_wire_input(input.as_bytes()).unwrap();
    assert_eq!(outcome, InputOutcome::Done);
    let frames = texts(&frames);
    assert!(
        frames
            .iter()
            .any(|frame| frame.starts_with(r#"{"t":"model","rev":2,"#)),
        "{frames:?}"
    );
    assert!(
        frames.iter().any(|frame| frame == r#"{"t":"top"}"#),
        "{frames:?}"
    );
    assert_eq!(host.wallet().screen, Screen::CreateIntro);
}

/// A secret window is refused until the secure window exists (A2-7): the wallet ends the session
/// and draws its error band; nothing secret leaves in a frame.
#[test]
fn a_secret_window_is_refused_for_now() {
    let mut host = host();
    let _ = host.start();
    let wallet = host.wallet_mut();
    wallet.emit(Effect::Secret(SecretEffect::OpenInput {
        serial: 99,
        kind: SecretKind::Unlock,
        step: None,
        topmost: false,
        lang: yw_core::lang::Lang::Ko,
    }));
    let frames = {
        host.drain();
        texts(&host.take_frames())
    };
    // The serial is no open session: the answer is ignored; the screen is drawn again as it was.
    assert_eq!(frames.len(), 1);
    assert!(
        frames[0].starts_with(r#"{"t":"model","rev":2,"#),
        "{frames:?}"
    );
    assert!(!frames[0].contains("E-SEC-001"));
    assert_eq!(host.wallet().screen, Screen::FirstRun);
    // The create flow's first step asks for the new password (W01): refused, the session ends
    // and the band says so.
    let start = slot_of(&host, Press::Core(CorePress::FirstCreate));
    let _ = host
        .on_wire_input(format!(r#"{{"t":"press","rev":2,"slot":{start}}}"#).as_bytes())
        .unwrap();
    let rev = host.wallet().drawn().map_or(0, yw_engine::wire::Drawn::rev);
    let next = slot_of(&host, Press::Core(CorePress::CreateNext));
    let (outcome, frames) = host
        .on_wire_input(format!(r#"{{"t":"press","rev":{rev},"slot":{next}}}"#).as_bytes())
        .unwrap();
    assert_eq!(outcome, InputOutcome::Done);
    // The refusal's band shows: the host draws after the answer (which queues no redraw).
    let frames = texts(&frames);
    assert!(
        frames
            .last()
            .is_some_and(|frame| frame.contains("E-SEC-001")),
        "{frames:?}"
    );
}

/// A copy frame carries an id; its answer reaches the wallet with the mark the shell kept, and an
/// unknown id is dropped. A timer is Java's to run.
#[test]
fn copies_and_timers_are_frames() {
    let mut host = host();
    let _ = host.start();
    host.wallet_mut().emit(Effect::CopyText {
        text: "0x52908400098527886E0F7030069857D2E4169EE7".to_owned(),
        mark: yw_engine::cmd::CopyMark {
            anchor: Press::Core(CorePress::FirstCreate),
            address: true,
            band: None,
        },
    });
    host.wallet_mut().emit(Effect::StartTimer {
        timer: TimerId::SendCheck,
        ms: 700,
    });
    let frames = {
        host.drain();
        texts(&host.take_frames())
    };
    assert_eq!(
        frames,
        [
            r#"{"t":"copy","id":1,"text":"0x52908400098527886E0F7030069857D2E4169EE7"}"#,
            r#"{"t":"timer","id":"send_check","ms":700}"#,
        ]
    );
    let (outcome, _) = host
        .on_wire_input(br#"{"t":"copied","id":7,"ok":true}"#)
        .unwrap();
    assert_eq!(outcome, InputOutcome::Done);
    let (outcome, frames) = host
        .on_wire_input(br#"{"t":"copied","id":1,"ok":true}"#)
        .unwrap();
    assert_eq!(outcome, InputOutcome::Done);
    // The mark shows at the pressed control at once (the host draws after the answer).
    let frames = texts(&frames);
    let copied = yw_engine::screen::model::T_COPIED.ko;
    assert!(
        frames.iter().any(|frame| frame.contains(copied)),
        "{frames:?}"
    );
}
