//! The wire's own tests (2026-11-25 A2-6): the input decoder's shapes, the model's control order
//! and the source check that no approval input is decoded here.
#![expect(clippy::panic, reason = "a test fails by panicking")]

use super::*;
use crate::cmd::{CorePress, EvmPress, Press, SolPress};
use crate::form::{CredField, EditField};
use crate::screen::model::Ctl;

fn decoded(text: &str) -> Result<Input, WireError> {
    decode_input(text.as_bytes())
}

#[test]
fn every_input_decodes_strictly() {
    assert!(matches!(
        decoded(r#"{"t":"press","rev":3,"slot":7}"#),
        Ok(Input::Press { rev: 3, slot: 7 })
    ));
    match decoded(r#"{"t":"edit","rev":2,"slot":1,"text":"a\"b"}"#) {
        Ok(Input::Edit {
            rev: 2,
            slot: 1,
            text,
        }) => assert_eq!(text.as_str(), "a\"b"),
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        decoded(r#"{"t":"rendered","rev":9,"focus":null,"of":null}"#),
        Ok(Input::Rendered {
            rev: 9,
            focus: None
        })
    ));
    assert!(matches!(
        decoded(r#"{"t":"rendered","rev":9,"focus":4,"of":8}"#),
        Ok(Input::Rendered {
            rev: 9,
            focus: Some((8, 4))
        })
    ));
    for life in Life::ALL {
        let text = format!(r#"{{"t":"life","e":"{}"}}"#, life.word());
        assert!(matches!(decoded(&text), Ok(Input::Life(got)) if got == life));
    }
    assert!(matches!(decoded(r#"{"t":"tick"}"#), Ok(Input::Tick)));
    assert!(matches!(
        decoded(r#"{"t":"timer","id":"send_check"}"#),
        Ok(Input::Timer(TimerId::SendCheck))
    ));
    assert!(matches!(
        decoded(r#"{"t":"copied","id":5,"ok":true}"#),
        Ok(Input::Copied { id: 5, ok: true })
    ));
}

#[test]
fn other_inputs_are_refused() {
    for bad in [
        "",
        "null",
        "[]",
        r#"{"t":"press","rev":3}"#,
        r#"{"t":"press","rev":3,"slot":7,"x":1}"#,
        r#"{"t":"press","rev":-1,"slot":7}"#,
        r#"{"t":"press","rev":1.5,"slot":7}"#,
        r#"{"t":"press","rev":"3","slot":7}"#,
        r#"{"t":"press","rev":3,"slot":65536}"#,
        r#"{"t":"press","rev":3,"slot":7,"slot":8}"#,
        r#"{"t":"edit","rev":2,"slot":1,"text":7}"#,
        r#"{"t":"rendered","rev":9}"#,
        r#"{"t":"rendered","rev":9,"focus":null}"#,
        r#"{"t":"rendered","rev":9,"focus":4,"of":null}"#,
        r#"{"t":"rendered","rev":9,"focus":null,"of":3}"#,
        r#"{"t":"rendered","rev":9,"focus":"x","of":1}"#,
        r#"{"t":"life","e":"sideways"}"#,
        r#"{"t":"tick","x":0}"#,
        r#"{"t":"timer","id":"other"}"#,
        r#"{"t":"copied","id":5}"#,
        r#"{"t":"approval","shown":1}"#,
        r#"{"t":"status"}"#,
        r#"{"t":"press","rev":3,"slot":{"a":1}}"#,
    ] {
        assert!(decoded(bad).is_err(), "{bad}");
    }
    let long = format!(
        r#"{{"t":"edit","rev":1,"slot":1,"text":"{}"}}"#,
        "a".repeat(INPUT_MAX)
    );
    assert_eq!(decoded(&long).err(), Some(WireError::TooLarge));
}

/// An edit's text never shows in `Debug`.
#[test]
fn input_debug_prints_no_text() {
    let Ok(input) = decoded(r#"{"t":"edit","rev":2,"slot":1,"text":"wc:secret-ish"}"#) else {
        panic!("edit");
    };
    let shown = format!("{input:?}");
    assert_eq!(shown, "Edit { rev: 2, slot: 1, len: 13 }");
}

/// Slots count controls in document order, a copy line's value first; the model on the wire
/// names the slot and never the press, the field or a credential's text.
#[test]
fn slots_follow_the_document_order() {
    let items = vec![
        Item::Title("t".to_owned()),
        Item::CopyLine {
            value: Ctl::value(EvmPress::CopyAddress, "copy", vec![("0x".to_owned(), true)]),
            actions: vec![Ctl::button(EvmPress::BookOpen, "book")],
        },
        Item::Row(vec![
            Ctl::edit(EditField::CoreRename, "name", 100, false, 32),
            Ctl::edit(CredField::LlmKey, "never", 100, true, 256),
            Ctl::check(CorePress::CopyToggle(None), "copy", true),
        ]),
        Item::Badged(
            crate::badge::Badge::evm(1, "Ethereum"),
            Box::new(Item::Row(vec![Ctl::button(SolPress::Refresh, "r")])),
        ),
    ];
    let drawn = Drawn::new(4, items.clone());
    let acts: Vec<Act> = (0..6)
        .filter_map(|slot| drawn.slot(slot).map(|info| info.act))
        .collect();
    assert_eq!(
        acts,
        [
            Act::Press(Press::Evm(EvmPress::CopyAddress)),
            Act::Press(Press::Evm(EvmPress::BookOpen)),
            Act::Field(EditField::CoreRename),
            Act::Cred(CredField::LlmKey),
            Act::Press(Press::Core(CorePress::CopyToggle(None))),
            Act::Press(Press::Sol(SolPress::Refresh)),
        ]
    );
    assert!(drawn.slot(6).is_none());
    assert_eq!(
        drawn
            .slots_of(Act::Press(Press::Core(CorePress::CopyToggle(Some(true)))))
            .collect::<Vec<_>>(),
        [4]
    );
    let wire = String::from_utf8(drawn.encode(yw_core::lang::Lang::Ko)).unwrap_or_default();
    assert!(
        wire.starts_with(r#"{"t":"model","rev":4,"items":["#),
        "{wire}"
    );
    for slot in 0..6 {
        assert!(
            wire.contains(&format!(r#"{{"s":{slot},"c":"#)),
            "{slot}: {wire}"
        );
    }
    assert!(!wire.contains("never"), "{wire}");
    assert!(
        !wire.contains("CopyAddress") && !wire.contains("CoreRename"),
        "{wire}"
    );
    assert!(wire.contains(r#""c":"cred""#), "{wire}");
}

/// What a slot's control takes (module doc).
#[test]
fn a_control_takes_only_its_own_input() {
    let items = vec![Item::Row(vec![
        Ctl::button(CorePress::Lock, "lock"),
        Ctl::button(CorePress::Exit, "exit").enabled(false),
        Ctl::edit(EditField::CoreRename, "name", 100, false, 32),
        Ctl::edit(EditField::CoreRename, "name", 100, false, 32).readonly(),
        Ctl::edit(CredField::LlmKey, "", 100, true, 256),
    ])];
    let drawn = Drawn::new(1, items);
    let take = |slot| {
        drawn
            .slot(slot)
            .map(|info| (takes_press(info), takes_edit(info)))
    };
    assert_eq!(take(0), Some((true, false)));
    assert_eq!(take(1), Some((false, false)));
    assert_eq!(take(2), Some((false, true)));
    assert_eq!(take(3), Some((false, false)));
    assert_eq!(take(4), Some((false, false)));
}

/// The pressed state of a check box is the drawn state turned over; `with_check(None)` is
/// `without_check`.
#[test]
fn with_check_mirrors_without_check() {
    for press in [
        Press::Core(CorePress::CopyToggle(Some(true))),
        Press::Evm(EvmPress::SendAck(None)),
        Press::Core(CorePress::Lock),
    ] {
        assert_eq!(press.with_check(None), press.without_check());
        assert!(press.with_check(Some(true)).same_control(press));
    }
    assert_eq!(
        Press::Core(CorePress::CopyToggle(None)).with_check(Some(false)),
        Press::Core(CorePress::CopyToggle(Some(false)))
    );
}

/// No approval input is decoded on the wire (spec/15 §18 8): the wire's code names no approval
/// input type, and neither does the Android shell's (yw-android has the same check).
#[test]
fn the_wire_has_no_approval_decoder() {
    for (file, text) in [
        ("wire/mod.rs", include_str!("mod.rs")),
        ("wire/model.rs", include_str!("model.rs")),
        ("wallet/app_wire.rs", include_str!("../wallet/app_wire.rs")),
    ] {
        let code: String = text
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        for name in ["Approval", "approval"] {
            assert!(!code.contains(name), "{file} names {name}");
        }
    }
}
