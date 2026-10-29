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
    assert!(word.backspace());
    for _ in 0..7 {
        word.push_unit(u16::from(b'z'));
    }
    assert_eq!(word.push_unit(u16::from(b'z')), PushResult::Full);
    assert_eq!(word.limit(), 8);
    let mut suffix = SecretField::new(Charset::HexSuffix, 6).unwrap();
    assert!(matches!(
        suffix.push_unit(u16::from(b'x')),
        PushResult::Rejected(_)
    ));
    for byte in b"aBc123" {
        assert_eq!(suffix.push_unit(u16::from(*byte)), PushResult::Accepted);
    }
    assert_eq!(suffix.as_bytes(), b"aBc123");
    assert_eq!(suffix.push_unit(u16::from(b'4')), PushResult::Full);
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
    for word in ["apple", "breeze", "cedar", "dune"] {
        type_text(&mut form, word, 10);
        form.on_key(0x09, false, false, false, 10);
    }
    type_text(&mut form, "ABCDEF", 10);
    let FormAction::Submit(submission) = form.on_char(0x0D, 20) else {
        unreachable!("expected submit");
    };
    let values: Vec<&[u8]> = submission
        .values
        .iter()
        .map(|value| value.as_slice())
        .collect();
    assert_eq!(
        values,
        [b"apple".as_slice(), b"breeze", b"cedar", b"dune", b"ABCDEF"]
    );
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
    let lines = super::intro(EVM_KEY, 0);
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
