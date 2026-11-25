//! The Android shell's screen host on the gate's Windows build (2026-11-25 A2-6): a wallet with no
//! workers and no files, the frames it hands Java, and the answers it gives itself.

use std::sync::Arc;

use yw_core::vault::FileKind;
use yw_engine::apikeys::ApiKeys;
use yw_engine::app_store::{AppStore, SealedRead};
use yw_engine::cmd::{CorePress, Press};
use yw_engine::effect::{Effect, TimerId};
use yw_engine::form::EditField;
use yw_engine::screen::model::Act;
use yw_engine::secret::{SecretEffect, SecretKind};
use yw_engine::services::Services;
use yw_engine::settings::Settings;
use yw_engine::wallet::{AppMode, Screen, Wallet};
use yw_engine::wire::InputOutcome;

use super::{UiHost, ui_kind};
use crate::io_request::UiKind;

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

/// A secret window of no open session is refused at once; the open session's window is asked of
/// Java (2026-11-25 A2-7: before, every secret window was refused with E-SEC-001 until the secure
/// window existed; the two-phase open is `secret_host::tests`).
#[test]
fn a_secret_window_is_asked_of_java() {
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
    // The create flow's first step asks for the new password (W01): Java is asked for the secure
    // window (`s_open`), nothing is answered yet, no band.
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
    let frames = texts(&frames);
    assert!(
        frames
            .iter()
            .any(|frame| frame.starts_with(r#"{"t":"s_open","serial":"#)),
        "{frames:?}"
    );
    assert!(frames.iter().all(|frame| !frame.contains("E-SEC-001")));
    assert!(host.wallet().secret_open());
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

fn book_host() -> UiHost {
    let mut host = host();
    let wallet = host.wallet_mut();
    wallet.mode = AppMode::Unlocked {
        alt_passphrase: false,
    };
    wallet.screen = Screen::AddressBook;
    wallet.book.form.open = true;
    host
}

fn field_slot(host: &UiHost, field: EditField) -> u32 {
    host.wallet()
        .drawn()
        .and_then(|drawn| drawn.slots_of(Act::Field(field)).next())
        .unwrap()
}

fn send(host: &mut UiHost, input: &str) -> Vec<String> {
    let (outcome, frames) = host.on_wire_input(input.as_bytes()).unwrap();
    assert_eq!(outcome, InputOutcome::Done, "{input}");
    texts(&frames)
}

/// 2026-11-25 A2-6 review: after Java answers a render, the engine's text of every drawn plain
/// edit that differs from its model text comes back as a field write, and the field that had the
/// focus as a reveal; a field write carries the edits of its slot the engine took since the
/// answer. Java keeps no text of its own.
#[test]
fn a_render_answer_hands_back_the_edit_texts() {
    let mut host = book_host();
    let _ = host.start();
    assert!(
        send(
            &mut host,
            r#"{"t":"rendered","rev":1,"focus":null,"of":null}"#
        )
        .is_empty()
    );
    let label = field_slot(&host, EditField::BookLabel);
    let _ = send(
        &mut host,
        &format!(r#"{{"t":"edit","rev":1,"slot":{label},"text":"typed"}}"#),
    );
    // A field write of a drawn edit says how many edits of its slot were taken.
    host.wallet_mut().emit(Effect::SetField {
        field: EditField::BookLabel,
        text: "written".to_owned(),
    });
    host.drain();
    assert_eq!(
        texts(&host.take_frames()),
        [format!(
            r#"{{"t":"field","rev":1,"slot":{label},"text":"written","seen":1}}"#
        )]
    );
    // The draft moves away from what the edit shows; the same controls are drawn again.
    "draft".clone_into(&mut host.wallet_mut().book.form.label);
    host.wallet_mut().refresh();
    host.drain();
    let frames = texts(&host.take_frames());
    assert!(
        frames[0].starts_with(r#"{"t":"model","rev":2,"#),
        "{frames:?}"
    );
    let frames = send(
        &mut host,
        &format!(r#"{{"t":"rendered","rev":2,"focus":{label},"of":1}}"#),
    );
    let label = field_slot(&host, EditField::BookLabel);
    assert_eq!(
        frames,
        [
            format!(r#"{{"t":"field","rev":2,"slot":{label},"text":"written","seen":0}}"#),
            format!(r#"{{"t":"reveal","rev":2,"slot":{label}}}"#),
        ]
    );
    assert_eq!(
        host.wallet().form.text(EditField::BookLabel),
        Some("written")
    );
    let kinds: Vec<UiKind> = frames
        .iter()
        .map(|frame| ui_kind(frame.as_bytes()))
        .collect();
    assert_eq!(kinds, [UiKind::OfModel, UiKind::OfModel]);
}

/// Every frame kind this host makes is read from its `t` member (the UI queue drops only what a
/// later model replaces).
#[test]
fn every_frame_has_its_queue_kind() {
    for (frame, kind) in [
        (r#"{"t":"model","rev":1,"items":[]}"#, UiKind::Model),
        (
            r#"{"t":"field","rev":1,"slot":0,"text":"","seen":0}"#,
            UiKind::OfModel,
        ),
        (r#"{"t":"reveal","rev":1,"slot":0}"#, UiKind::OfModel),
        (r#"{"t":"top"}"#, UiKind::Other),
        (r#"{"t":"timer","id":"send_check","ms":1}"#, UiKind::Other),
        (r#"{"t":"stop_timer","id":"send_check"}"#, UiKind::Other),
        (r#"{"t":"copy","id":1,"text":"0x"}"#, UiKind::Other),
    ] {
        assert_eq!(ui_kind(frame.as_bytes()), kind, "{frame}");
    }
}

/// A field write of the `WalletConnect` pairing link never becomes a frame (it carries the
/// pairing `symKey`; 2026-11-25 A2-6 review).
#[test]
fn the_pairing_link_is_never_written() {
    let mut host = host();
    let _ = host.start();
    host.wallet_mut().emit(Effect::SetField {
        field: EditField::WcUri,
        text: "wc:00@2?symKey=11".to_owned(),
    });
    host.drain();
    assert!(
        texts(&host.take_frames())
            .iter()
            .all(|frame| !frame.contains("symKey"))
    );
}

/// After the UI queue dropped every waiting frame: the copies Java has not answered fail (a late
/// answer is dropped), a fresh model is drawn and the timers still running are sent again; a
/// fired or stopped timer is not.
#[test]
fn a_resync_sends_the_state_again() {
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
    host.drain();
    let _ = host.take_frames();
    let frames = texts(&host.resync());
    assert!(frames[0].starts_with(r#"{"t":"model","#), "{frames:?}");
    assert_eq!(
        frames.last().map(String::as_str),
        Some(r#"{"t":"timer","id":"send_check","ms":700}"#)
    );
    let copied = yw_engine::screen::model::T_COPIED.ko;
    assert!(
        frames.iter().all(|frame| !frame.contains(copied)),
        "{frames:?}"
    );
    // The copy's late answer is dropped: no mark.
    let (_, frames) = host
        .on_wire_input(br#"{"t":"copied","id":1,"ok":true}"#)
        .unwrap();
    assert!(texts(&frames).iter().all(|frame| !frame.contains(copied)));
    // The timer fired: a later resync does not start it again.
    let _ = host
        .on_wire_input(br#"{"t":"timer","id":"send_check"}"#)
        .unwrap();
    let frames = texts(&host.resync());
    assert!(
        frames.iter().all(|frame| !frame.contains(r#""t":"timer""#)),
        "{frames:?}"
    );
}
