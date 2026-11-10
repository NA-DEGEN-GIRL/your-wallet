//! SW-1 (ported `archive/spec-v2.4:crates/secret-input-ui/src/recovery_native.rs:1610-1738`
//! tests with v3 semantics) and the app half of SW-4 (spec/04 §4.10).

use yw_win::ui::is_blocked_secret_msg;

use super::{
    BACKUP_ACK_HOLD_MS, CaptureDecision, DisplaySecret, FormAction, HoldGate,
    SECRET_WINDOW_TIMEOUT_MS, SecretForm, SecretKind, capture_decision,
};
use crate::errors::ErrorCode;
use crate::ui::secure_field::{Charset, PushResult, SecretField};
use yw_core::keyimport::ImportChain;
use yw_core::secret::{SecretString, Zeroizing};

fn type_text(form: &mut SecretForm, text: &str, now: u64) {
    for unit in text.encode_utf16() {
        form.on_char(unit, now);
    }
}

#[test]
fn sw1_acknowledgement_requires_one_continuous_two_second_hold() {
    let mut gate = HoldGate::default();
    gate.begin(100);
    assert!(!gate.complete(100 + BACKUP_ACK_HOLD_MS - 1));
    gate.cancel();
    gate.begin(1_000);
    gate.begin(2_999);
    assert!(!gate.complete(2_999));
    assert!(gate.complete(3_000));
    assert_eq!(gate.remaining_ms(2_500), 500);
}

#[test]
fn sw1_backup_buffers_are_bounded_and_need_no_window_text() {
    let mut word = SecretField::new(Charset::BackupWord, 8).unwrap();
    assert_eq!(word.push_unit(u16::from(b'a')), PushResult::Accepted);
    assert_eq!(word.push_unit(u16::from(b'B')), PushResult::Accepted);
    assert_eq!(word.as_bytes(), b"ab");
    assert!(matches!(
        word.push_unit(u16::from(b'1')),
        PushResult::Rejected(_)
    ));
    assert!(word.backspace());
    for _ in 0..7 {
        word.push_unit(u16::from(b'z'));
    }
    assert_eq!(word.push_unit(u16::from(b'z')), PushResult::Full);
    assert_eq!(word.limit(), 8);
}

#[test]
fn sw1_backup_form_collects_only_owned_buffers() {
    let mut form = SecretForm::new(
        SecretKind::Backup {
            positions: [3, 7, 12, 24],
        },
        0,
        true,
    );
    // List words: W10 does not send a word that is not in the BIP39 list (2026-11-10).
    for (index, word) in ["apple", "breeze", "cement", "dune"]
        .into_iter()
        .enumerate()
    {
        if index > 0 {
            form.on_key(0x09, false, false, false, 10);
        }
        type_text(&mut form, word, 10);
    }
    let FormAction::Submit(submission) = form.on_char(0x0D, 20) else {
        unreachable!("expected submit");
    };
    let values: Vec<&[u8]> = submission
        .values
        .iter()
        .map(|value| value.as_slice())
        .collect();
    assert_eq!(values, [b"apple".as_slice(), b"breeze", b"cement", b"dune"]);
    // Paste is refused in W10 (paper backup check).
    assert!(matches!(
        form.on_key(u16::from(b'V'), true, false, false, 30),
        FormAction::None
    ));
}

#[test]
fn sw1_secret_messages_are_blocked_headlessly() {
    for message in [
        0x000D_u32, 0x000E, 0x003D, 0x0317, 0x0318, 0x0301, 0x0300, 0x0302, 0x007B, 0x0233,
    ] {
        assert!(is_blocked_secret_msg(message, false), "{message:#x}");
    }
    assert!(is_blocked_secret_msg(0x000C, true));
    assert!(!is_blocked_secret_msg(0x000C, false));
}

#[test]
fn sw1_timeout_wipes_and_focus_loss_masks() {
    let mut form = SecretForm::new(EVM_KEY, 0, true);
    type_text(&mut form, "0xabc", 1_000);
    assert!(matches!(
        form.on_tick(1_000 + SECRET_WINDOW_TIMEOUT_MS - 1),
        FormAction::None
    ));
    assert!(matches!(
        form.on_tick(1_000 + SECRET_WINDOW_TIMEOUT_MS),
        FormAction::TimedOut
    ));

    let mut plain = SecretForm::new(SecretKind::Mnemonic, 0, true);
    plain.on_deactivate();
    assert!(plain.masked());
    plain.on_activate();
    assert!(!plain.masked());

    let mut masked = SecretForm::new(SecretKind::SetPassword, 0, true);
    masked.on_deactivate();
    assert!(!masked.masked());

    let display = SecretForm::display(
        SecretKind::ShowKey,
        5_000,
        DisplaySecret {
            text: SecretString::from_zeroizing(Zeroizing::new("ab".repeat(32))),
            address: None,
            passphrase_note: false,
            copy_allowed: false,
        },
    );
    let mut display = display;
    // Display windows time out from when they were shown, regardless of input.
    display.on_char(u16::from(b'a'), 5_000 + SECRET_WINDOW_TIMEOUT_MS - 10);
    assert!(matches!(
        display.on_tick(5_000 + SECRET_WINDOW_TIMEOUT_MS),
        FormAction::TimedOut
    ));
    assert!(display.copy_units().is_none());
}

#[test]
fn password_rules_and_confirmation() {
    let mut form = SecretForm::new(SecretKind::SetPassword, 0, true);
    type_text(&mut form, "short", 0);
    form.on_key(0x09, false, false, false, 0);
    type_text(&mut form, "short", 0);
    assert!(matches!(form.on_char(0x0D, 0), FormAction::Redraw));
    let mut form = SecretForm::new(SecretKind::SetPassword, 0, true);
    type_text(&mut form, "m3-test-password!", 0);
    form.on_key(0x09, false, false, false, 0);
    type_text(&mut form, "m3-test-password?", 0);
    assert!(matches!(form.on_char(0x0D, 0), FormAction::Redraw));
    let mut form = SecretForm::new(SecretKind::SetPassword, 0, true);
    type_text(&mut form, "m3-test-password!", 0);
    form.on_key(0x09, false, false, false, 0);
    type_text(&mut form, "m3-test-password!", 0);
    assert!(matches!(form.on_char(0x0D, 0), FormAction::Submit(_)));
}

#[test]
fn ime_and_non_ascii_show_e_inp_008_without_changing_the_buffer() {
    let mut form = SecretForm::new(SecretKind::Unlock, 0, true);
    type_text(&mut form, "ab", 0);
    assert!(matches!(form.on_char(0xAC00, 0), FormAction::Redraw));
    assert!(matches!(
        form.on_key(0xE5, false, false, false, 0),
        FormAction::Redraw
    ));
    assert!(
        matches!(form.on_char(0x0D, 0), FormAction::Submit(ref s) if s.values[0].as_slice() == b"ab")
    );
}

#[test]
fn wrong_password_disables_input_for_one_second() {
    let mut form = SecretForm::new(SecretKind::Unlock, 0, true);
    form.fail_password(1_000);
    assert!(matches!(
        form.on_char(u16::from(b'a'), 1_999),
        FormAction::None
    ));
    assert!(!form.can_submit(1_999));
    form.on_tick(2_000);
    assert!(matches!(
        form.on_char(u16::from(b'a'), 2_000),
        FormAction::Redraw
    ));
}

#[test]
fn mnemonic_next_requires_valid_count_and_known_words() {
    let mut form = SecretForm::new(SecretKind::Mnemonic, 0, true);
    let about = format!("{}about", "abandon ".repeat(11));
    type_text(&mut form, &about, 0);
    assert!(form.can_submit(0));
    let FormAction::Submit(submission) = form.on_char(0x0D, 0) else {
        unreachable!("expected submit");
    };
    assert_eq!(submission.values[0].as_slice(), about.as_bytes());
    assert!(!submission.checkbox);
    let mut form = SecretForm::new(SecretKind::Mnemonic, 0, true);
    type_text(&mut form, &format!("{}abandonn", "abandon ".repeat(11)), 0);
    assert!(!form.can_submit(0));
    assert!(matches!(form.on_char(0x0D, 0), FormAction::Redraw));
    let mut paste = SecretForm::new(SecretKind::Mnemonic, 0, true);
    let units: Vec<u16> = "Abandon\r\n abandon\tabout".encode_utf16().collect();
    assert_eq!(paste.apply_paste(&units), Ok(false));
    assert_eq!(
        paste.apply_paste(&"abandon 1".encode_utf16().collect::<Vec<_>>()),
        Err(ErrorCode::Inp018)
    );
    // A passphrase is pasted exactly; an edge space is reported for the notice (§4.7-3).
    let mut passphrase = SecretForm::new(SecretKind::Passphrase { confirm: false }, 0, true);
    let units: Vec<u16> = " TREZOR \r\n".encode_utf16().collect();
    assert_eq!(passphrase.apply_paste(&units), Ok(true));
    let units: Vec<u16> = "TREZOR".encode_utf16().collect();
    assert_eq!(passphrase.apply_paste(&units), Ok(false));
}

#[test]
fn sw4_capture_decisions() {
    assert_eq!(
        capture_decision(SecretKind::ShowMnemonic { create: true }, Err(())),
        CaptureDecision::Refuse(ErrorCode::Sec001)
    );
    assert_eq!(
        capture_decision(SecretKind::ShowKey, Ok(false)),
        CaptureDecision::Refuse(ErrorCode::Sec001)
    );
    assert_eq!(
        capture_decision(SecretKind::ShowKey, Ok(true)),
        CaptureDecision::Show { warning: false }
    );
    for kind in [
        SecretKind::SetPassword,
        SecretKind::Mnemonic,
        SecretKind::Backup {
            positions: [1, 2, 3, 4],
        },
    ] {
        assert_eq!(
            capture_decision(kind, Ok(false)),
            CaptureDecision::Show { warning: true }
        );
        assert_eq!(
            capture_decision(kind, Ok(true)),
            CaptureDecision::Show { warning: false }
        );
        let unprotected = SecretForm::new(kind, 0, false);
        assert!(!unprotected.reveal_enabled(0));
        assert!(!unprotected.capture_excluded());
    }
    let protected = SecretForm::new(SecretKind::SetPassword, 0, true);
    assert!(protected.reveal_enabled(0));
}

#[test]
fn w07_warns_that_imported_keys_are_not_in_the_recovery_words() {
    let lines = super::intro(EVM_KEY, 0, false);
    assert!(
        lines
            .iter()
            .any(|line| line == super::T_IMPORTED_KEY_BACKUP)
    );
    assert!(super::T_IMPORTED_KEY_BACKUP.contains("복구 단어(24단어)로 복구되지 않습니다"));
    assert_eq!(EVM_KEY.size(), (640, 560));
    // Without recovery words (key-only wallet, "개인키로 시작하기") the warning says the original
    // key is the only backup, for every chain.
    for chain in [ImportChain::Evm, ImportChain::Sol, ImportChain::Btc] {
        let lines = super::intro(
            SecretKind::PrivateKey {
                chain,
                no_words: true,
            },
            0,
            false,
        );
        assert!(lines.iter().any(|line| line == super::T_KEY_ONLY_BACKUP));
        assert!(
            !lines
                .iter()
                .any(|line| line == super::T_IMPORTED_KEY_BACKUP)
        );
    }
    // The redacting display buffer still renders its content for copy.
    let form = SecretForm::display(
        SecretKind::ShowKey,
        0,
        DisplaySecret {
            text: SecretString::from_zeroizing(Zeroizing::new("cd".repeat(32))),
            address: None,
            passphrase_note: false,
            copy_allowed: true,
        },
    );
    assert_eq!(form.copy_units().map(|units| units.len()), Some(64));
}

const EVM_KEY: SecretKind = SecretKind::PrivateKey {
    chain: ImportChain::Evm,
    no_words: false,
};

#[test]
fn w07_solana_and_bitcoin_fields_take_their_formats() {
    // Solana: base58 or a JSON array; spaces collapse, other characters are refused.
    let mut sol = SecretForm::new(
        SecretKind::PrivateKey {
            chain: ImportChain::Sol,
            no_words: false,
        },
        0,
        true,
    );
    type_text(&mut sol, "[1, 2,3]", 1);
    let mut field = SecretField::new(Charset::KeyText, 32).unwrap();
    for unit in "[1,  2]".encode_utf16() {
        let _ = field.push_unit(unit);
    }
    assert_eq!(field.as_bytes(), b"[1, 2]");
    assert_eq!(
        field.push_unit(u16::from(b'"')),
        PushResult::Rejected(crate::ui::secure_field::RejectReason::NotAllowed)
    );
    // Bitcoin WIF: the base58 alphabet only (no 0, O, I, l).
    let mut wif = SecretField::new(Charset::Base58, 52).unwrap();
    for (unit, accepted) in [
        ('K', true),
        ('0', false),
        ('O', false),
        ('I', false),
        ('l', false),
        ('z', true),
    ] {
        let result = wif.push_unit(u16::from(u8::try_from(unit).unwrap()));
        assert_eq!(result == PushResult::Accepted, accepted, "{unit}");
    }
    // A short WIF is refused before anything is sent (E-INP-023).
    let mut btc = SecretForm::new(
        SecretKind::PrivateKey {
            chain: ImportChain::Btc,
            no_words: true,
        },
        0,
        true,
    );
    type_text(&mut btc, "KwDiBf89", 1);
    assert!(matches!(btc.on_char(0x0D, 2), FormAction::Redraw));
    // Pasted JSON with line breaks collapses to single spaces.
    let units: Vec<u16> = "[1,
  2,
 3]"
    .encode_utf16()
    .collect();
    let pasted = crate::ui::secure_field::normalize_paste(&units, Charset::KeyText, 64).unwrap();
    assert_eq!(pasted.as_slice(), b"[1, 2, 3]");
}

/// W11 (spec/10 §9.1): one masked field with the applet's bounds (PIV 6–8 here), ASCII only,
/// no copy (Ctrl+C does nothing), capture exclusion preferred like the other input windows, the
/// submitted PIN moved out as an owned `Zeroizing` buffer and the field wiped; the title and the
/// "N회 터치" line follow the kind.
#[test]
fn w11_card_pin_bounds_mask_and_owned_buffer() {
    let kind = SecretKind::CardPin {
        min: 6,
        max: 8,
        touches: 3,
    };
    assert_eq!(kind.id(), "W11");
    assert_eq!(kind.title(), "YubiKey PIN");
    assert!(!kind.is_display() && !kind.plaintext());
    assert_eq!(
        capture_decision(kind, Ok(false)),
        CaptureDecision::Show { warning: true }
    );
    let intro = super::intro(kind, 0, false);
    assert!(intro[0].contains("YubiKey를 연결하고 PIN 입력 후 터치하세요"));
    assert!(intro[1].contains("YubiKey 터치 3회가 필요합니다"));
    assert_eq!(
        super::intro(
            SecretKind::CardPin {
                min: 6,
                max: 127,
                touches: 1
            },
            0,
            false
        )
        .len(),
        1
    );
    let mut form = SecretForm::new(kind, 0, true);
    form.set_details(vec!["이 키를 가진 YubiKey: #7700011".to_owned()]);
    type_text(&mut form, "12345", 0);
    assert!(
        matches!(form.on_char(0x0D, 0), FormAction::Redraw),
        "too short"
    );
    type_text(&mut form, "6789", 0);
    // The field holds at most 8 characters.
    let FormAction::Submit(submission) = form.on_char(0x0D, 0) else {
        unreachable!("expected submit");
    };
    let [pin] = submission.values.as_slice() else {
        unreachable!("one value");
    };
    let owned: &Zeroizing<Vec<u8>> = pin;
    assert_eq!(owned.as_slice(), b"12345678");
    assert!(matches!(
        form.on_key(u16::from(b'C'), true, false, false, 0),
        FormAction::None
    ));
    // Non-ASCII is refused like in every secret window.
    assert!(matches!(form.on_char(0xAC00, 0), FormAction::Redraw));
    assert!(!form.can_submit(0), "the field was wiped by the submission");
}

/// W12 (spec/10 §7.3, §9.3): the admin PIN 8–127, the management key exactly 48 hex digits, a
/// PIN change with current / new / new again (the two new fields equal, different from the
/// current one, the target's bounds); "PIN 하나로 통일" (current empty or 8, new exactly 8
/// twice); the PIV PIN 6–8.
#[test]
fn w12_card_secrets() {
    use super::CardSecretKind;
    use crate::yubikey::PinTarget;
    let submit = |kind: SecretKind, fields: &[&str]| {
        let mut form = SecretForm::new(kind, 0, true);
        for (index, text) in fields.iter().enumerate() {
            if index > 0 {
                form.on_key(0x09, false, false, false, 0);
            }
            type_text(&mut form, text, 0);
        }
        form.on_char(0x0D, 0)
    };
    let admin = SecretKind::CardSecret(CardSecretKind::AdminPin);
    assert_eq!(admin.id(), "W12");
    assert!(!admin.is_display() && admin.paste_allowed());
    assert!(matches!(submit(admin, &["1234567"]), FormAction::Redraw));
    assert!(matches!(
        submit(admin, &["12345678"]),
        FormAction::Submit(_)
    ));
    let key = SecretKind::CardSecret(CardSecretKind::ManagementKey);
    assert!(matches!(
        submit(key, &[&"0a".repeat(23)]),
        FormAction::Redraw
    ));
    let FormAction::Submit(submission) = submit(key, &[&"0A".repeat(24)]) else {
        unreachable!("48 hex digits");
    };
    assert_eq!(submission.values[0].as_slice(), "0a".repeat(24).as_bytes());
    let change = SecretKind::CardSecret(CardSecretKind::ChangePin(PinTarget::PivPin));
    assert!(matches!(
        submit(change, &["123456", "654321", "654320"]),
        FormAction::Redraw
    ));
    assert!(matches!(
        submit(change, &["123456", "123456", "123456"]),
        FormAction::Redraw
    ));
    // A PIV PIN field holds at most 8 characters (the 9th is not taken).
    let FormAction::Submit(long) = submit(change, &["123456", "876543219", "876543219"]) else {
        unreachable!("8 characters kept");
    };
    assert_eq!(long.values[1].as_slice(), b"87654321");
    // A factory value is never a new secret (spec/10 §9.3): 12345678 is the factory PUK and
    // admin PIN.
    assert!(matches!(
        submit(change, &["654321", "12345678", "12345678"]),
        FormAction::Redraw
    ));
    let FormAction::Submit(submission) = submit(change, &["123456", "654321", "654321"]) else {
        unreachable!("valid change");
    };
    assert_eq!(submission.values.len(), 3);
    let pw3 = SecretKind::CardSecret(CardSecretKind::ChangePin(PinTarget::OpenPgpAdmin));
    assert!(matches!(
        submit(pw3, &["12345678", "1234567", "1234567"]),
        FormAction::Redraw
    ));
    // "PIN 하나로 통일": current empty (factory) or 8, the new value exactly 8, twice.
    let pins = SecretKind::CardSecret(CardSecretKind::SetPins);
    assert!(!pins.is_display() && pins.paste_allowed());
    assert!(matches!(
        submit(pins, &["", "1234567", "1234567"]),
        FormAction::Redraw
    ));
    assert!(matches!(
        submit(pins, &["123456", "24681357", "24681357"]),
        FormAction::Redraw
    ));
    assert!(matches!(
        submit(pins, &["", "24681357", "24681358"]),
        FormAction::Redraw
    ));
    assert!(matches!(
        submit(pins, &["", "12345678", "12345678"]),
        FormAction::Redraw
    ));
    let FormAction::Submit(submission) = submit(pins, &["", "24681357", "24681357"]) else {
        unreachable!("factory current, new twice");
    };
    assert!(submission.values[0].is_empty());
    assert_eq!(submission.values[1].as_slice(), b"24681357");
    let piv_pin = SecretKind::CardSecret(CardSecretKind::PivPin);
    assert!(matches!(submit(piv_pin, &["12345"]), FormAction::Redraw));
    assert!(matches!(
        submit(piv_pin, &["123456"]),
        FormAction::Submit(_)
    ));
}

/// 2026-11-10 (batch 1): W10 checks each word against the public BIP39 list as it is typed — a
/// word that is not in the list keeps `확인` off and is never sent (a typo is not "the paper is
/// wrong"); fixing it turns `확인` on. A word being typed is not marked until it can no longer
/// become one.
#[test]
fn w10_word_not_in_the_list_keeps_confirm_off() {
    use super::WordMark;
    let mut form = SecretForm::new(
        SecretKind::Backup {
            positions: [3, 9, 16, 22],
        },
        0,
        true,
    );
    for (index, word) in ["abandon", "ability", "aban", "abandonx"]
        .into_iter()
        .enumerate()
    {
        if index > 0 {
            form.on_key(0x09, false, false, false, 10);
        }
        type_text(&mut form, word, 10);
        if index == 2 {
            assert_eq!(form.word_mark(2), WordMark::None, "still typing");
        }
    }
    assert_eq!(form.word_mark(0), WordMark::Listed);
    assert_eq!(form.word_mark(2), WordMark::Unlisted, "left unfinished");
    assert_eq!(form.word_mark(3), WordMark::Unlisted, "no word starts so");
    assert!(!form.can_submit(20));
    assert!(matches!(form.on_char(0x0D, 20), FormAction::Redraw));
    form.on_char(0x08, 30);
    form.on_key(0x09, false, false, false, 30);
    form.on_key(0x09, false, false, false, 30);
    form.on_key(0x09, false, false, false, 30);
    type_text(&mut form, "don", 30);
    assert_eq!(form.word_mark(2), WordMark::Listed);
    assert!(form.can_submit(40));
    // Enter moves to the last field, then sends.
    assert!(matches!(form.on_char(0x0D, 40), FormAction::Redraw));
    assert!(matches!(form.on_char(0x0D, 50), FormAction::Submit(_)));
}
