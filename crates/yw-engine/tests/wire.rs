//! The Android wire (2026-11-25 A2-6, spec/15 §3.2, §11.3, §18 8): every screen-model item kind
//! survives the trip through its yw-json encoding, the bytes Java's JVM tests pin, and inputs
//! resolved against the model the wallet drew last — stale revisions and queued redraws dropped,
//! a changed item never pressed, each control taking only its own input. The wallet alone: no
//! yw-app, no window, no file, no network.
#![expect(clippy::panic, reason = "a test fails by panicking")]

mod wire_support;

use wire_support::{Facts, first_run_wallet, take_all};
use yw_core::lang::Lang;
use yw_engine::badge::{Badge, Mark};
use yw_engine::cmd::{BookPress, CorePress, EvmPress, Press, SolPress};
use yw_engine::effect::Effect;
use yw_engine::form::{CredField, EditField};
use yw_engine::screen::Tone;
use yw_engine::screen::model::{
    Act, Ctl, CtlKind, Face, GLYPH_CHECK, GLYPH_COPY, GLYPH_DOWN, GLYPH_LINK, GLYPH_OPEN,
    GLYPH_SAVE, GLYPH_UP, Item, Style, T_COPIED, T_COPIED_ADDRESS,
};
use yw_engine::wallet::{AppMode, Screen, Wallet};
use yw_engine::wire::{Drawn, EditSync, Input, InputOutcome, Life, decode_input};
use yw_json::{Limits, Value};

// --- The model's round trip -------------------------------------------------------------------

const GLYPHS: [&str; 7] = [
    GLYPH_COPY,
    GLYPH_OPEN,
    GLYPH_LINK,
    GLYPH_SAVE,
    GLYPH_DOWN,
    GLYPH_UP,
    GLYPH_CHECK,
];

fn glyph(text: &str) -> &'static str {
    GLYPHS
        .into_iter()
        .find(|known| *known == text)
        .unwrap_or_else(|| panic!("glyph {text}"))
}

fn note(text: &str) -> &'static str {
    [T_COPIED, T_COPIED_ADDRESS]
        .into_iter()
        .flat_map(|note| [note.ko, note.en])
        .find(|known| *known == text)
        .unwrap_or_else(|| panic!("note {text}"))
}

fn tone(word: &str) -> Tone {
    [
        Tone::Danger,
        Tone::Warn,
        Tone::Info,
        Tone::Testnet,
        Tone::BtcMainnet,
        Tone::BtcTestnet4,
        Tone::HighRisk,
        Tone::Blocked,
        Tone::Success,
    ]
    .into_iter()
    .find(|tone| yw_engine::wire::model::tone_word(*tone) == word)
    .unwrap_or_else(|| panic!("tone {word}"))
}

fn style(word: &str) -> Style {
    [
        Style::Primary,
        Style::Secondary,
        Style::Danger,
        Style::Link,
        Style::TabOn,
        Style::TabOff,
        Style::Entry,
        Style::EntryOn,
    ]
    .into_iter()
    .find(|style| yw_engine::wire::model::style_word(*style) == word)
    .unwrap_or_else(|| panic!("style {word}"))
}

fn str_of<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .as_object()
        .and_then(|object| object.get(key))
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key}"))
}

fn member<'a>(value: &'a Value, key: &str) -> &'a Value {
    value
        .as_object()
        .and_then(|object| object.get(key))
        .unwrap_or_else(|| panic!("{key}"))
}

fn num(value: &Value, key: &str) -> u64 {
    member(value, key)
        .as_number()
        .and_then(yw_json::Number::as_u64)
        .unwrap_or_else(|| panic!("{key}"))
}

fn flag(value: &Value, key: &str) -> Option<bool> {
    member(value, key).as_bool()
}

fn decode_badge(value: &Value) -> Badge {
    let mark = match str_of(value, "mark") {
        "diamond" => Mark::Diamond,
        "hexagon" => Mark::Hexagon,
        "ring" => Mark::Ring,
        "hollow_diamond" => Mark::HollowDiamond,
        "bars" => Mark::Bars,
        "bitcoin" => Mark::Bitcoin,
        "letter" => Mark::Letter(str_of(value, "ch").chars().next().unwrap_or(' ')),
        other => panic!("mark {other}"),
    };
    Badge {
        mark,
        color: u32::try_from(num(value, "color")).unwrap_or(0),
        ink: u32::try_from(num(value, "ink")).unwrap_or(0),
        testnet: flag(value, "testnet") == Some(true),
    }
}

fn decode_lines(value: &Value) -> Vec<Vec<(String, bool)>> {
    value
        .as_array()
        .unwrap_or_default()
        .iter()
        .map(|line| {
            line.as_array()
                .unwrap_or_default()
                .iter()
                .map(|span| {
                    let pair = span.as_array().unwrap_or_default();
                    (
                        pair.first()
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned(),
                        pair.get(1).and_then(Value::as_bool) == Some(true),
                    )
                })
                .collect()
        })
        .collect()
}

fn decode_face(value: &Value) -> Option<Face> {
    if value.is_null() {
        return None;
    }
    Some(match str_of(value, "f") {
        "glyph" => Face::Glyph(glyph(str_of(value, "glyph"))),
        "value" => Face::Value(decode_lines(member(value, "lines"))),
        "entry" => Face::Entry(member(value, "glyph").as_str().map(glyph)),
        "copied" => Face::Copied(
            decode_lines(member(value, "lines")),
            note(str_of(value, "note")),
        ),
        other => panic!("face {other}"),
    })
}

fn decode_ctl(value: &Value, drawn: &Drawn) -> Ctl {
    let slot = u32::try_from(num(value, "s")).unwrap_or(u32::MAX);
    let act = drawn
        .slot(slot)
        .unwrap_or_else(|| panic!("slot {slot}"))
        .act;
    let kind = match str_of(value, "c") {
        "button" => CtlKind::Button(style(str_of(value, "style"))),
        "check" => CtlKind::Check,
        "radio" => CtlKind::Radio {
            first: flag(value, "first") == Some(true),
        },
        "edit" => CtlKind::Edit {
            password: flag(value, "password") == Some(true),
            readonly: flag(value, "readonly") == Some(true),
        },
        // A credential edit's kind is the drawn one (the wire names it `cred` only).
        "cred" => drawn.slot(slot).map_or(CtlKind::Check, |info| info.kind),
        other => panic!("control {other}"),
    };
    Ctl {
        act,
        kind,
        text: str_of(value, "text").to_owned(),
        width: 0,
        enabled: flag(value, "on") == Some(true),
        checked: flag(value, "checked"),
        limit: member(value, "limit")
            .as_number()
            .and_then(yw_json::Number::as_u64)
            .and_then(|limit| u32::try_from(limit).ok()),
        badge: (!member(value, "badge").is_null()).then(|| decode_badge(member(value, "badge"))),
        compact: flag(value, "compact") == Some(true),
        face: decode_face(member(value, "face")),
        tip: member(value, "tip").as_str().map(str::to_owned),
        fit: Vec::new(),
    }
}

fn decode_ctls(value: &Value, drawn: &Drawn) -> Vec<Ctl> {
    member(value, "ctls")
        .as_array()
        .unwrap_or_default()
        .iter()
        .map(|ctl| decode_ctl(ctl, drawn))
        .collect()
}

fn decode_item(value: &Value, drawn: &Drawn) -> Item {
    let text = |key| str_of(value, key).to_owned();
    match str_of(value, "k") {
        "title" => Item::Title(text("text")),
        "text" => Item::Text(text("text")),
        "muted" => Item::Muted(text("text")),
        "help" => Item::Help(text("text")),
        "subtitle" => Item::Subtitle(text("text")),
        "display" => Item::Display(text("text")),
        "display_muted" => Item::DisplayMuted(text("text")),
        "mono" => Item::Mono(text("text")),
        "copy" => Item::CopyLine {
            value: decode_ctl(member(value, "value"), drawn),
            actions: member(value, "actions")
                .as_array()
                .unwrap_or_default()
                .iter()
                .map(|ctl| decode_ctl(ctl, drawn))
                .collect(),
        },
        "list" => Item::ListRow {
            title: text("title"),
            note: text("note"),
            value: text("value"),
            dim: flag(value, "dim") == Some(true),
        },
        "pill" => Item::Pill(text("text"), tone(str_of(value, "tone"))),
        "menu" => Item::Menu(decode_ctls(value, drawn)),
        "field" => Item::Field(text("label"), text("value")),
        "banner" => Item::Banner(text("text"), tone(str_of(value, "tone"))),
        "gap" => Item::Gap(i32::try_from(num(value, "dip")).unwrap_or(-1)),
        "row" => Item::Row(decode_ctls(value, drawn)),
        "lrow" => Item::LabeledRow(text("label"), decode_ctls(value, drawn)),
        "rule" => Item::Rule,
        "qr" => Item::Qr(format!("{}:{}", num(value, "size"), str_of(value, "bits"))),
        "card" => Item::CardStart(member(value, "title").as_str().map(str::to_owned)),
        "end" => Item::CardEnd,
        "steps" => Item::Steps(
            member(value, "labels")
                .as_array()
                .unwrap_or_default()
                .iter()
                .map(|label| label.as_str().unwrap_or_default().to_owned())
                .collect(),
            usize::try_from(num(value, "current")).unwrap_or(usize::MAX),
        ),
        "bar" => Item::Toolbar(text("title"), decode_ctls(value, drawn)),
        "badged" => Item::Badged(
            decode_badge(member(value, "badge")),
            Box::new(decode_item(member(value, "item"), drawn)),
        ),
        "hold" => Item::Hold {
            label: text("label"),
            progress: u16::try_from(num(value, "progress")).unwrap_or(0),
            enabled: flag(value, "on") == Some(true),
        },
        other => panic!("item {other}"),
    }
}

/// The QR modules of `payload` as the wire carries them, worked out here on their own.
fn qr_wire(payload: &str) -> String {
    let Some(matrix) = yw_engine::screen::qr::encode(payload) else {
        return "0:".to_owned();
    };
    let size = matrix.size();
    let mut bits = Vec::new();
    for y in 0..size {
        for x in 0..size {
            bits.push(matrix.module(x, y));
        }
    }
    let mut hex = String::new();
    for chunk in bits.chunks(8) {
        let byte = chunk
            .iter()
            .enumerate()
            .fold(0_u8, |byte, (at, bit)| byte | (u8::from(*bit) << (7 - at)));
        for nibble in [byte >> 4, byte & 0x0f] {
            hex.push(char::from_digit(u32::from(nibble), 16).unwrap_or('0'));
        }
    }
    format!("{size}:{hex}")
}

/// What the wire keeps of `item`: the Windows-only layout facts dropped, a QR as its modules.
fn as_sent(item: &Item) -> Item {
    let ctl = |ctl: &Ctl| Ctl {
        width: 0,
        fit: Vec::new(),
        ..ctl.clone()
    };
    let ctls = |ctls: &[Ctl]| ctls.iter().map(ctl).collect::<Vec<_>>();
    match item {
        Item::CopyLine { value, actions } => Item::CopyLine {
            value: ctl(value),
            actions: ctls(actions),
        },
        Item::Menu(items) => Item::Menu(ctls(items)),
        Item::Row(items) => Item::Row(ctls(items)),
        Item::LabeledRow(label, items) => Item::LabeledRow(label.clone(), ctls(items)),
        Item::Toolbar(title, items) => Item::Toolbar(title.clone(), ctls(items)),
        Item::Badged(badge, inner) => Item::Badged(*badge, Box::new(as_sent(inner))),
        Item::Qr(payload) => Item::Qr(qr_wire(payload)),
        other => other.clone(),
    }
}

/// One model with every item kind, every control kind and style, every face, badge mark and
/// tone.
#[expect(clippy::too_many_lines, reason = "one fixture of every kind")]
fn every_kind() -> Vec<Item> {
    let spans = vec![("0xAb".to_owned(), true), ("cd".to_owned(), false)];
    let mut items = vec![
        Item::Title("Title".to_owned()),
        Item::Text("Text \"quoted\"\n2".to_owned()),
        Item::Muted("Muted".to_owned()),
        Item::Help("Help".to_owned()),
        Item::Subtitle("Subtitle".to_owned()),
        Item::Display("1.5 ETH".to_owned()),
        Item::DisplayMuted("1.4 ETH".to_owned()),
        Item::Mono("0x52908400098527886E0F7030069857D2E4169EE7".to_owned()),
        Item::CopyLine {
            value: Ctl::value(EvmPress::CopyAddress, "주소 복사", spans.clone()).width(300),
            actions: vec![
                Ctl::icon(EvmPress::BookOpen, GLYPH_COPY, "복사"),
                Ctl::icon(SolPress::Refresh, GLYPH_LINK, "link"),
            ],
        },
        Item::CopyLine {
            value: {
                let mut copied = Ctl::value(SolPress::CopyAddress, "copy", spans.clone());
                copied.face = Some(Face::Copied(vec![spans], T_COPIED_ADDRESS.ko));
                copied
            },
            actions: Vec::new(),
        },
        Item::ListRow {
            title: "USDC".to_owned(),
            note: "USD Coin".to_owned(),
            value: "12.5".to_owned(),
            dim: true,
        },
        Item::Menu(vec![
            Ctl::entry(CorePress::Lock, "one", true),
            Ctl::entry(CorePress::Exit, "two", false),
        ]),
        Item::Field("Label".to_owned(), "Value".to_owned()),
        Item::Gap(12),
        Item::Row(vec![
            Ctl::primary(CorePress::FirstCreate, "Primary").badge(Badge::evm(1, "Ethereum")),
            Ctl::button(CorePress::FirstImport, "Secondary")
                .tip("tip")
                .fit(["longer label"]),
            Ctl::danger(CorePress::IntroCancel, "Danger").enabled(false),
            Ctl::link(CorePress::OpenSettings, "Link"),
            Ctl::tab(CorePress::Lock, "Tab on", true),
            Ctl::tab(CorePress::Exit, "Tab off", false),
            Ctl::picker(CorePress::CreateNext, "Picker", true),
            Ctl::picker(CorePress::OpenLogFolder, "Picker", false),
        ]),
        Item::Row(vec![
            Ctl::check(CorePress::CopyToggle(None), "Check", true),
            Ctl::check(BookPress::Verified(None), "Check off", false),
            Ctl::radio(CorePress::Lock, "Radio 1", true, true),
            Ctl::radio(CorePress::Exit, "Radio 2", false, false),
        ]),
        Item::LabeledRow(
            "Name".to_owned(),
            vec![
                Ctl::edit(EditField::CoreRename, "typed", 200, false, 32),
                Ctl::edit(EditField::BookLabel, "ro", 200, false, 64).readonly(),
                Ctl::edit(EditField::LlmModel, "", 200, true, 128),
                Ctl::edit(CredField::LlmKey, "never sent", 200, true, 256),
            ],
        ),
        Item::Rule,
        Item::Qr("0x52908400098527886E0F7030069857D2E4169EE7".to_owned()),
        Item::CardStart(Some("Card".to_owned())),
        Item::CardStart(None),
        Item::CardEnd,
        Item::Steps(
            vec!["one".to_owned(), "two".to_owned(), "three".to_owned()],
            2,
        ),
        Item::Toolbar(
            "Your Wallet".to_owned(),
            vec![Ctl::button(CorePress::Lock, "잠금").tip("잠금 (Ctrl+L)")],
        ),
        Item::Badged(
            Badge::evm(7, "Robinhood"),
            Box::new(Item::Field("Network".to_owned(), "Robinhood".to_owned())),
        ),
        Item::Hold {
            label: "Hold".to_owned(),
            progress: 400,
            enabled: true,
        },
    ];
    for tone in [
        Tone::Danger,
        Tone::Warn,
        Tone::Info,
        Tone::Testnet,
        Tone::BtcMainnet,
        Tone::BtcTestnet4,
        Tone::HighRisk,
        Tone::Blocked,
        Tone::Success,
    ] {
        items.push(Item::Banner("Banner".to_owned(), tone));
        items.push(Item::Pill("Pill".to_owned(), tone));
    }
    for mark in [
        Mark::Diamond,
        Mark::Hexagon,
        Mark::Ring,
        Mark::HollowDiamond,
        Mark::Bars,
        Mark::Bitcoin,
        Mark::Letter('R'),
    ] {
        items.push(Item::Badged(
            Badge {
                mark,
                color: 0x0062_7EEA,
                ink: 0x00FF_FFFF,
                testnet: mark == Mark::Ring,
            },
            Box::new(Item::Text("badged".to_owned())),
        ));
    }
    items
}

/// Every item kind comes back from its encoding as it was (the Windows-only layout facts aside),
/// each control resolved through its slot to the press or field it was drawn with.
#[test]
fn every_item_kind_round_trips() {
    let items = every_kind();
    let drawn = Drawn::new(11, items.clone());
    for lang in [Lang::Ko, Lang::En] {
        let bytes = drawn.encode(lang);
        let value = yw_json::parse(&bytes, &Limits::RESPONSE).unwrap_or_else(|_| panic!("json"));
        assert_eq!(str_of(&value, "t"), "model");
        assert_eq!(num(&value, "rev"), 11);
        let decoded: Vec<Item> = member(&value, "items")
            .as_array()
            .unwrap_or_default()
            .iter()
            .map(|item| decode_item(item, &drawn))
            .collect();
        let expected: Vec<Item> = items.iter().map(as_sent).collect();
        assert_eq!(decoded.len(), expected.len());
        for (index, (got, want)) in decoded.iter().zip(&expected).enumerate() {
            assert_eq!(got, want, "item {index}");
        }
        // The banner tags are the tone words of `lang`, null for the Bitcoin network bands.
        let banners: Vec<&Value> = member(&value, "items")
            .as_array()
            .unwrap_or_default()
            .iter()
            .filter(|item| str_of(item, "k") == "banner")
            .collect();
        for banner in banners {
            let tag = member(banner, "tag").as_str();
            assert_eq!(tag, tone(str_of(banner, "tone")).label(lang));
        }
        let text = String::from_utf8(bytes).unwrap_or_default();
        assert!(!text.contains("never sent"), "a credential's text");
    }
}

/// The exact bytes of a small model: Java's JVM test `JvmTests.modelFrame` reads the same string
/// (`Ui` parses it and finds the same slots).
#[test]
fn a_small_model_has_pinned_bytes() {
    let items = vec![
        Item::Title("Hi".to_owned()),
        Item::Banner("état \"x\"".to_owned(), Tone::Warn),
        Item::Row(vec![
            Ctl::primary(CorePress::FirstCreate, "Go"),
            Ctl::check(CorePress::CopyToggle(None), "C", true).enabled(false),
        ]),
        Item::LabeledRow(
            "N".to_owned(),
            vec![Ctl::edit(EditField::CoreRename, "a", 200, false, 32)],
        ),
    ];
    let bytes = Drawn::new(7, items).encode(Lang::En);
    assert_eq!(String::from_utf8(bytes).unwrap_or_default(), MODEL_FRAME,);
}

/// The pinned model of [`a_small_model_has_pinned_bytes`] (also in `JvmTests.java`).
const MODEL_FRAME: &str = concat!(
    r#"{"t":"model","rev":7,"items":[{"k":"title","text":"Hi"},"#,
    r#"{"k":"banner","text":"état \"x\"","tone":"warn","tag":"Caution"},"#,
    r#"{"k":"row","ctls":[{"s":0,"c":"button","style":"primary","text":"Go","on":true,"#,
    r#""checked":null,"first":null,"password":null,"readonly":null,"limit":null,"badge":null,"#,
    r#""compact":false,"face":null,"tip":null},{"s":1,"c":"check","style":null,"text":"C","#,
    r#""on":false,"checked":true,"first":null,"password":null,"readonly":null,"limit":null,"#,
    r#""badge":null,"compact":false,"face":null,"tip":null}]},{"k":"lrow","label":"N","#,
    r#""ctls":[{"s":2,"c":"edit","style":null,"text":"a","on":true,"checked":null,"#,
    r#""first":null,"password":false,"readonly":false,"limit":32,"badge":null,"#,
    r#""compact":false,"face":null,"tip":null}]}]}"#,
);

// --- Inputs against the drawn model ---------------------------------------------------------

fn slot_of(wallet: &Wallet, act: Act) -> u32 {
    wallet
        .drawn()
        .and_then(|drawn| drawn.slots_of(act).next())
        .unwrap_or_else(|| panic!("{act:?} not drawn"))
}

fn press(rev: u64, slot: u32) -> Input {
    Input::Press { rev, slot }
}

fn edit(rev: u64, slot: u32, text: &str) -> Input {
    Input::Edit {
        rev,
        slot,
        text: yw_core::secret::Zeroizing::new(text.to_owned()),
    }
}

/// A press reaches the control drawn at its slot, and only for the model drawn last.
#[test]
fn a_press_reaches_the_drawn_control() {
    let mut wallet = first_run_wallet();
    let _ = wallet.draw(&Facts);
    let rev = wallet.drawn().map_or(0, Drawn::rev);
    assert_eq!(rev, 1);
    let create = slot_of(&wallet, Act::Press(Press::Core(CorePress::FirstCreate)));
    // An older model's press, and one past the controls: dropped.
    assert_eq!(
        wallet.on_input(press(0, create), &Facts),
        InputOutcome::Stale
    );
    assert_eq!(
        wallet.on_input(press(2, create), &Facts),
        InputOutcome::Stale
    );
    assert_eq!(
        wallet.on_input(press(rev, 9_999), &Facts),
        InputOutcome::Refused
    );
    assert_eq!(wallet.screen, Screen::FirstRun);
    assert_eq!(
        wallet.on_input(press(rev, create), &Facts),
        InputOutcome::Done
    );
    assert_eq!(wallet.screen, Screen::CreateIntro);
    // The screen changed and a redraw is queued: the old model takes nothing more.
    let cancel = slot_of(&wallet, Act::Press(Press::Core(CorePress::FirstImport)));
    assert_eq!(
        wallet.on_input(press(rev, cancel), &Facts),
        InputOutcome::Stale
    );
    assert!(take_all(&mut wallet).contains(&Effect::Render));
    let _ = wallet.draw(&Facts);
    assert_eq!(wallet.drawn().map(Drawn::rev), Some(2));
    assert_eq!(
        wallet.on_input(press(1, cancel), &Facts),
        InputOutcome::Stale
    );
}

/// A queued redraw (an `Effect::Render` the shell has not taken) makes the drawn model old.
#[test]
fn a_queued_redraw_drops_inputs() {
    let mut wallet = first_run_wallet();
    let _ = wallet.draw(&Facts);
    let create = slot_of(&wallet, Act::Press(Press::Core(CorePress::FirstCreate)));
    wallet.refresh();
    assert_eq!(
        wallet.on_input(press(1, create), &Facts),
        InputOutcome::Stale
    );
    let _ = take_all(&mut wallet);
    assert_eq!(
        wallet.on_input(press(1, create), &Facts),
        InputOutcome::Done
    );
}

/// A pressed control whose item is built differently now is not pressed: the row the person saw
/// is not the row the press would reach (the drawn row's content is its key, spec/15 §18 40 (3)).
#[test]
fn a_changed_item_is_not_pressed() {
    let mut wallet = first_run_wallet();
    let _ = wallet.draw(&Facts);
    let create = slot_of(&wallet, Act::Press(Press::Core(CorePress::FirstCreate)));
    // The language changed under the drawn model (as a settings write would).
    wallet.settings.language = Lang::En;
    assert_eq!(
        wallet.on_input(press(1, create), &Facts),
        InputOutcome::Changed
    );
    assert_eq!(wallet.screen, Screen::FirstRun);
    assert!(take_all(&mut wallet).contains(&Effect::Render));
    let _ = wallet.draw(&Facts);
    let create = slot_of(&wallet, Act::Press(Press::Core(CorePress::FirstCreate)));
    assert_eq!(
        wallet.on_input(press(2, create), &Facts),
        InputOutcome::Done
    );
    assert_eq!(wallet.screen, Screen::CreateIntro);
}

/// A disabled control is never pressed (the leftover band turns the first-run buttons off).
#[test]
fn a_disabled_control_is_refused() {
    let mut wallet = first_run_wallet();
    wallet.leftover = true;
    let _ = wallet.draw(&Facts);
    let create = slot_of(&wallet, Act::Press(Press::Core(CorePress::FirstCreate)));
    assert_eq!(
        wallet.on_input(press(1, create), &Facts),
        InputOutcome::Refused
    );
    assert_eq!(wallet.screen, Screen::FirstRun);
}

/// An edit reaches its field; a press slot, a read-only edit and a stale model take no text;
/// a render's answer names the focused field.
#[test]
fn edits_and_renders_resolve_their_fields() {
    let mut wallet = first_run_wallet();
    wallet.mode = AppMode::Unlocked {
        alt_passphrase: false,
    };
    wallet.screen = Screen::AddressBook;
    wallet.book.form.open = true;
    let _ = wallet.draw(&Facts);
    let label = slot_of(&wallet, Act::Field(EditField::BookLabel));
    assert_eq!(
        wallet.on_input(
            Input::Rendered {
                rev: 1,
                focus: None
            },
            &Facts
        ),
        InputOutcome::Done
    );
    assert_eq!(
        wallet.on_input(edit(1, label, "typed"), &Facts),
        InputOutcome::Done
    );
    assert_eq!(wallet.form.text(EditField::BookLabel), Some("typed"));
    assert_eq!(
        wallet.on_input(edit(0, label, "old"), &Facts),
        InputOutcome::Stale
    );
    let pressable = wallet
        .drawn()
        .and_then(|drawn| {
            (0..200).find(|slot| {
                drawn
                    .slot(*slot)
                    .is_some_and(|info| matches!(info.act, Act::Press(_)))
            })
        })
        .unwrap_or_else(|| panic!("no press drawn"));
    assert_eq!(
        wallet.on_input(edit(1, pressable, "x"), &Facts),
        InputOutcome::Refused
    );
    assert_eq!(
        wallet.on_input(press(1, label), &Facts),
        InputOutcome::Refused
    );
    assert_eq!(wallet.form.text(EditField::BookLabel), Some("typed"));
    let _ = take_all(&mut wallet);
    let _ = wallet.draw(&Facts);
    assert_eq!(
        wallet.on_input(
            Input::Rendered {
                rev: 2,
                focus: Some((1, label))
            },
            &Facts
        ),
        InputOutcome::Done
    );
    assert_eq!(
        wallet.on_input(
            Input::Rendered {
                rev: 1,
                focus: Some((1, label))
            },
            &Facts
        ),
        InputOutcome::Stale
    );
}

/// A check box's press over the wire carries the drawn state turned over (2026-11-25 A2-6
/// review: before, no test failed when the press carried the drawn state itself), and the next
/// model draws what the engine holds.
#[test]
fn a_check_box_press_turns_the_drawn_state_over() {
    let mut wallet = book_form_wallet();
    let _ = wallet.draw(&Facts);
    let verified = Act::Press(Press::Book(BookPress::Verified(None)));
    let checked = |wallet: &Wallet| {
        let slot = slot_of(wallet, verified);
        wallet
            .drawn()
            .and_then(|drawn| drawn.slot(slot))
            .and_then(|info| info.checked)
    };
    assert_eq!(checked(&wallet), Some(false));
    assert!(!wallet.book.form.verified);
    let slot = slot_of(&wallet, verified);
    assert_eq!(wallet.on_input(press(1, slot), &Facts), InputOutcome::Done);
    assert!(wallet.book.form.verified, "drawn off, pressed: on");
    let _ = take_all(&mut wallet);
    let _ = wallet.draw(&Facts);
    assert_eq!(checked(&wallet), Some(true));
    let slot = slot_of(&wallet, verified);
    assert_eq!(wallet.on_input(press(2, slot), &Facts), InputOutcome::Done);
    assert!(!wallet.book.form.verified, "drawn on, pressed: off");
}

fn book_form_wallet() -> Wallet {
    let mut wallet = first_run_wallet();
    wallet.mode = AppMode::Unlocked {
        alt_passphrase: false,
    };
    wallet.screen = Screen::AddressBook;
    wallet.book.form.open = true;
    wallet
}

fn rendered(wallet: &mut Wallet, rev: u64, focus: Option<(u64, u32)>) {
    assert_eq!(
        wallet.on_input(Input::Rendered { rev, focus }, &Facts),
        InputOutcome::Done
    );
}

fn sync_fields(sync: &EditSync) -> Vec<(u32, String)> {
    sync.fields
        .iter()
        .map(|(slot, text)| (*slot, text.as_str().to_owned()))
        .collect()
}

/// What a plain edit shows on the wire is the engine's (2026-11-25 A2-6 review): after a render's
/// answer the engine hands back every drawn edit whose form text differs from its model text and
/// the focused field's slot, once; the edits it took per slot since the answer are counted for
/// the shell's field writes.
#[test]
fn the_engine_decides_what_the_edits_show() {
    let mut wallet = book_form_wallet();
    let _ = wallet.draw(&Facts);
    // Nothing answered yet: nothing to hand back.
    assert!(wallet.take_edit_sync().is_none());
    rendered(&mut wallet, 1, None);
    let sync = wallet.take_edit_sync().unwrap_or_else(|| panic!("no sync"));
    assert_eq!((sync.rev, sync.focus), (1, None));
    assert!(sync.fields.is_empty(), "{sync:?}");
    assert!(wallet.take_edit_sync().is_none(), "handed back once");
    let label = slot_of(&wallet, Act::Field(EditField::BookLabel));
    let address = slot_of(&wallet, Act::Field(EditField::BookAddress));
    assert_eq!(
        wallet.on_input(edit(1, label, "typed"), &Facts),
        InputOutcome::Done
    );
    assert_eq!(
        wallet.on_input(edit(1, label, "typed2"), &Facts),
        InputOutcome::Done
    );
    assert_eq!(
        wallet.on_input(edit(1, address, "0xab"), &Facts),
        InputOutcome::Done
    );
    assert_eq!(
        (wallet.edits_seen(label), wallet.edits_seen(address)),
        (2, 1)
    );
    // The drafts move away from what the edits show (as a handler's write could), the same
    // controls are drawn again: the Windows rule keeps every edit's text (the keys are the
    // same), while the model gives other texts. The shell draws the model's texts; the engine
    // hands its own back, with the focused field.
    "draft label".clone_into(&mut wallet.book.form.label);
    "0xdraft".clone_into(&mut wallet.book.form.address);
    let _ = wallet.draw(&Facts);
    assert_eq!(wallet.edits_seen(label), 0, "a new model counts afresh");
    rendered(&mut wallet, 2, Some((1, label)));
    let sync = wallet.take_edit_sync().unwrap_or_else(|| panic!("no sync"));
    assert_eq!(sync.rev, 2);
    let mut fields = sync_fields(&sync);
    fields.sort();
    let mut expected = vec![(label, "typed2".to_owned()), (address, "0xab".to_owned())];
    expected.sort();
    assert_eq!(fields, expected);
    assert_eq!(
        sync.focus,
        Some(slot_of(&wallet, Act::Field(EditField::BookLabel)))
    );
    assert_eq!(wallet.form.text(EditField::BookLabel), Some("typed2"));
    assert!(!format!("{sync:?}").contains("typed"), "{sync:?}");
    // A model drawn after the answer, or an answer of another model: nothing handed back.
    rendered(&mut wallet, 2, None);
    let _ = wallet.draw(&Facts);
    assert!(wallet.take_edit_sync().is_none());
    assert_eq!(
        wallet.on_input(
            Input::Rendered {
                rev: 2,
                focus: None
            },
            &Facts
        ),
        InputOutcome::Stale
    );
    assert!(wallet.take_edit_sync().is_none());
    // The same model answered again (the Activity drew it once more): handed back again, and
    // the count starts over.
    rendered(&mut wallet, 3, None);
    assert_eq!(
        wallet.on_input(edit(3, label, "again"), &Facts),
        InputOutcome::Done
    );
    assert_eq!(wallet.edits_seen(label), 1);
    rendered(&mut wallet, 3, None);
    assert_eq!(wallet.edits_seen(label), 0);
    let sync = wallet.take_edit_sync().unwrap_or_else(|| panic!("no sync"));
    assert!(
        sync_fields(&sync).contains(&(label, "again".to_owned())),
        "{sync:?}"
    );
}

/// The lifetime events keep the wallet's main-window mirror and come back to the shell; the
/// main timer and a one-shot timer reach the logic; a copy answer is the shell's.
#[test]
fn life_ticks_and_timers() {
    let mut wallet = first_run_wallet();
    assert_eq!(
        wallet.on_input(Input::Life(Life::Back), &Facts),
        InputOutcome::Life(Life::Back)
    );
    assert!(wallet.main_hidden());
    assert_eq!(
        wallet.on_input(Input::Life(Life::Front), &Facts),
        InputOutcome::Life(Life::Front)
    );
    assert!(!wallet.main_hidden());
    assert_eq!(
        wallet.on_input(Input::Life(Life::ScreenOff), &Facts),
        InputOutcome::Life(Life::ScreenOff)
    );
    assert_eq!(wallet.on_input(Input::Tick, &Facts), InputOutcome::NotMine);
    assert_eq!(
        wallet.on_input(Input::Timer(yw_engine::effect::TimerId::SendCheck), &Facts),
        InputOutcome::Done
    );
    assert_eq!(
        wallet.on_input(Input::Copied { id: 1, ok: true }, &Facts),
        InputOutcome::NotMine
    );
}

/// A decoded press goes the same way as a built one.
#[test]
fn decoded_inputs_resolve_the_same() {
    let mut wallet = first_run_wallet();
    let _ = wallet.draw(&Facts);
    let create = slot_of(&wallet, Act::Press(Press::Core(CorePress::FirstCreate)));
    let bytes = format!(r#"{{"t":"press","rev":1,"slot":{create}}}"#);
    let Ok(input) = decode_input(bytes.as_bytes()) else {
        panic!("decode");
    };
    assert_eq!(wallet.on_input(input, &Facts), InputOutcome::Done);
    assert_eq!(wallet.screen, Screen::CreateIntro);
}
