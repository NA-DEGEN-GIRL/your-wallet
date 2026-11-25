//! SW-1 (ported `archive/spec-v2.4:crates/secret-input-ui/src/recovery_native.rs:1610-1738`
//! tests with v3 semantics) and the form's half of SW-4 (spec/04 §4.10).
//!
//! 2026-11-24 (spec/15 §11.4 S5-7): the form takes neutral keys (`SecretKey`); these tests send
//! them with the same assertions (before, `on_char(unit)` and `on_key(vk, ctrl, shift, alt)`:
//! Tab was `0x09`, paste `Ctrl+'V'`, copy `Ctrl+'C'`, the IME key `0xE5`). [`differential`]
//! compares the new entries with a test-only copy of the old ones.
//!
//! 2026-11-24 (spec/15 §11.4 S5-8): moved here from yw-app `ui::secret::tests` with the form,
//! the same assertions (an input form is built with `PlatformFlags::WINDOWS`, [`input`]); the
//! Windows parts stayed there (the blocked messages, the capture decision, the window size, the
//! W01/W04 status colours). New: the platform flags only narrow paste and copy
//! ([`platform_flags_only_narrow_paste_and_copy`]) and the paint view reads what the form holds
//! ([`the_view_reads_what_the_form_holds`]).

use crate::secret::input::SecretKey;

mod differential;

use super::{FormAction, SECRET_WINDOW_TIMEOUT_MS, SecretForm, SecretKind};
use crate::errors::ErrorCode;
use crate::screen::facts::PlatformFlags;
use crate::secret::{BACKUP_ACK_HOLD_MS, DisplaySecret, HoldGate};
use crate::secure_field::{Charset, PushResult, SecretField};
use yw_core::keyimport::ImportChain;
use yw_core::lang::Lang;
use yw_core::secret::{SecretString, Zeroizing};

/// An input window on Windows (every platform flag set but `seen_all`).
fn input(kind: SecretKind, lang: Lang, now_ms: u64, capture_excluded: bool) -> SecretForm {
    SecretForm::new(kind, lang, now_ms, capture_excluded, PlatformFlags::WINDOWS)
}

fn type_text(form: &mut SecretForm, text: &str, now: u64) {
    for unit in text.encode_utf16() {
        form.on_key(SecretKey::Char(unit), now);
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
    let mut form = input(
        SecretKind::Backup {
            positions: [3, 7, 12, 24],
        },
        Lang::Ko,
        0,
        true,
    );
    // List words: W10 does not send a word that is not in the BIP39 list (2026-11-10).
    for (index, word) in ["apple", "breeze", "cement", "dune"]
        .into_iter()
        .enumerate()
    {
        if index > 0 {
            form.on_key(SecretKey::Tab { back: false }, 10);
        }
        type_text(&mut form, word, 10);
    }
    let FormAction::Submit(submission) = form.on_key(SecretKey::Char(0x0D), 20) else {
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
        form.on_key(SecretKey::Paste, 30),
        FormAction::None
    ));
}

#[test]
fn sw1_timeout_wipes_and_focus_loss_masks() {
    let mut form = input(EVM_KEY, Lang::Ko, 0, true);
    type_text(&mut form, "0xabc", 1_000);
    assert!(matches!(
        form.on_tick(1_000 + SECRET_WINDOW_TIMEOUT_MS - 1),
        FormAction::None
    ));
    assert!(matches!(
        form.on_tick(1_000 + SECRET_WINDOW_TIMEOUT_MS),
        FormAction::TimedOut
    ));

    let mut plain = input(SecretKind::Mnemonic, Lang::Ko, 0, true);
    plain.on_deactivate();
    assert!(plain.masked());
    plain.on_activate();
    assert!(!plain.masked());

    let mut masked = input(SecretKind::SetPassword, Lang::Ko, 0, true);
    masked.on_deactivate();
    assert!(!masked.masked());

    let display = SecretForm::display(
        SecretKind::ShowKey,
        Lang::Ko,
        5_000,
        DisplaySecret {
            text: SecretString::from_zeroizing(Zeroizing::new("ab".repeat(32))),
            address: None,
            passphrase_note: false,
            copy_allowed: false,
        },
        PlatformFlags::WINDOWS,
    );
    let mut display = display;
    // Display windows time out from when they were shown, regardless of input.
    display.on_key(
        SecretKey::Char(u16::from(b'a')),
        5_000 + SECRET_WINDOW_TIMEOUT_MS - 10,
    );
    assert!(matches!(
        display.on_tick(5_000 + SECRET_WINDOW_TIMEOUT_MS),
        FormAction::TimedOut
    ));
    assert!(display.copy_units().is_none());
}

#[test]
fn password_rules_and_confirmation() {
    let mut form = input(SecretKind::SetPassword, Lang::Ko, 0, true);
    type_text(&mut form, "short", 0);
    form.on_key(SecretKey::Tab { back: false }, 0);
    type_text(&mut form, "short", 0);
    assert!(matches!(
        form.on_key(SecretKey::Char(0x0D), 0),
        FormAction::Redraw
    ));
    let mut form = input(SecretKind::SetPassword, Lang::Ko, 0, true);
    type_text(&mut form, "m3-test-password!", 0);
    form.on_key(SecretKey::Tab { back: false }, 0);
    type_text(&mut form, "m3-test-password?", 0);
    assert!(matches!(
        form.on_key(SecretKey::Char(0x0D), 0),
        FormAction::Redraw
    ));
    let mut form = input(SecretKind::SetPassword, Lang::Ko, 0, true);
    type_text(&mut form, "m3-test-password!", 0);
    form.on_key(SecretKey::Tab { back: false }, 0);
    type_text(&mut form, "m3-test-password!", 0);
    assert!(matches!(
        form.on_key(SecretKey::Char(0x0D), 0),
        FormAction::Submit(_)
    ));
}

/// W01/W04's two conditions: each `None` (grey) while its field is empty (the status line's
/// texts are the yw-app paint's, `ui::secret::tests::password_status_names_the_problem`).
#[test]
fn password_checks_follow_the_fields() {
    let mut form = input(SecretKind::SetPassword, Lang::Ko, 0, true);
    type_text(&mut form, "short", 0);
    assert_eq!(form.password_checks(), Some((Some(false), None)));
    form.on_key(SecretKey::Tab { back: false }, 0);
    type_text(&mut form, "shorT", 0);
    assert_eq!(form.password_checks(), Some((Some(false), Some(false))));
}

#[test]
fn ime_and_non_ascii_show_e_inp_008_without_changing_the_buffer() {
    let mut form = input(SecretKind::Unlock, Lang::Ko, 0, true);
    type_text(&mut form, "ab", 0);
    assert!(matches!(
        form.on_key(SecretKey::Char(0xAC00), 0),
        FormAction::Redraw
    ));
    assert!(matches!(
        form.on_key(SecretKey::Composition, 0),
        FormAction::Redraw
    ));
    assert!(
        matches!(form.on_key(SecretKey::Char(0x0D), 0), FormAction::Submit(ref s) if s.values[0].as_slice() == b"ab")
    );
}

#[test]
fn wrong_password_disables_input_for_one_second() {
    let mut form = input(SecretKind::Unlock, Lang::Ko, 0, true);
    form.fail_password(1_000);
    assert!(matches!(
        form.on_key(SecretKey::Char(u16::from(b'a')), 1_999),
        FormAction::None
    ));
    assert!(!form.can_submit(1_999));
    form.on_tick(2_000);
    assert!(matches!(
        form.on_key(SecretKey::Char(u16::from(b'a')), 2_000),
        FormAction::Redraw
    ));
}

#[test]
fn mnemonic_next_requires_valid_count_and_known_words() {
    let mut form = input(SecretKind::Mnemonic, Lang::Ko, 0, true);
    let about = format!("{}about", "abandon ".repeat(11));
    type_text(&mut form, &about, 0);
    assert!(form.can_submit(0));
    let FormAction::Submit(submission) = form.on_key(SecretKey::Char(0x0D), 0) else {
        unreachable!("expected submit");
    };
    assert_eq!(submission.values[0].as_slice(), about.as_bytes());
    assert!(!submission.checkbox);
    let mut form = input(SecretKind::Mnemonic, Lang::Ko, 0, true);
    type_text(&mut form, &format!("{}abandonn", "abandon ".repeat(11)), 0);
    assert!(!form.can_submit(0));
    assert!(matches!(
        form.on_key(SecretKey::Char(0x0D), 0),
        FormAction::Redraw
    ));
    let mut paste = input(SecretKind::Mnemonic, Lang::Ko, 0, true);
    let units: Vec<u16> = "Abandon\r\n abandon\tabout".encode_utf16().collect();
    assert_eq!(paste.apply_paste(&units), Ok(false));
    assert_eq!(
        paste.apply_paste(&"abandon 1".encode_utf16().collect::<Vec<_>>()),
        Err(ErrorCode::Inp018)
    );
    // A passphrase is pasted exactly; an edge space is reported for the notice (§4.7-3).
    let mut passphrase = input(SecretKind::Passphrase { confirm: false }, Lang::Ko, 0, true);
    let units: Vec<u16> = " TREZOR \r\n".encode_utf16().collect();
    assert_eq!(passphrase.apply_paste(&units), Ok(true));
    let units: Vec<u16> = "TREZOR".encode_utf16().collect();
    assert_eq!(passphrase.apply_paste(&units), Ok(false));
}

/// SW-4's form half: `보기` is off without capture exclusion (the capture decision is the yw-app
/// shell's, `ui::secret::tests::sw4_capture_decisions`).
#[test]
fn sw4_reveal_needs_capture_exclusion() {
    for kind in [
        SecretKind::SetPassword,
        SecretKind::Mnemonic,
        SecretKind::Backup {
            positions: [1, 2, 3, 4],
        },
    ] {
        let unprotected = input(kind, Lang::Ko, 0, false);
        assert!(!unprotected.reveal_enabled(0));
        assert!(!unprotected.capture_excluded());
    }
    let protected = input(SecretKind::SetPassword, Lang::Ko, 0, true);
    assert!(protected.reveal_enabled(0));
}

#[test]
fn w07_warns_that_imported_keys_are_not_in_the_recovery_words() {
    let lines = super::intro(EVM_KEY, Lang::Ko, (0, false), None);
    assert!(
        lines
            .iter()
            .any(|line| line == super::text::IMPORTED_KEY_BACKUP.get(Lang::Ko))
    );
    assert!(
        super::text::IMPORTED_KEY_BACKUP
            .get(Lang::Ko)
            .contains("복구 단어(24단어)로 복구되지 않습니다")
    );
    // Without recovery words (key-only wallet, "개인키로 시작하기") the warning says the original
    // key is the only backup, for every chain.
    for chain in [ImportChain::Evm, ImportChain::Sol, ImportChain::Btc] {
        let lines = super::intro(
            SecretKind::PrivateKey {
                chain,
                no_words: true,
            },
            Lang::Ko,
            (0, false),
            None,
        );
        assert!(
            lines
                .iter()
                .any(|line| line == super::text::KEY_ONLY_BACKUP.get(Lang::Ko))
        );
        assert!(
            !lines
                .iter()
                .any(|line| line == super::text::IMPORTED_KEY_BACKUP.get(Lang::Ko))
        );
    }
    // The redacting display buffer still renders its content for copy.
    let form = SecretForm::display(
        SecretKind::ShowKey,
        Lang::Ko,
        0,
        DisplaySecret {
            text: SecretString::from_zeroizing(Zeroizing::new("cd".repeat(32))),
            address: None,
            passphrase_note: false,
            copy_allowed: true,
        },
        PlatformFlags::WINDOWS,
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
    let mut sol = input(
        SecretKind::PrivateKey {
            chain: ImportChain::Sol,
            no_words: false,
        },
        Lang::Ko,
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
        PushResult::Rejected(crate::secure_field::RejectReason::NotAllowed)
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
    let mut btc = input(
        SecretKind::PrivateKey {
            chain: ImportChain::Btc,
            no_words: true,
        },
        Lang::Ko,
        0,
        true,
    );
    type_text(&mut btc, "KwDiBf89", 1);
    assert!(matches!(
        btc.on_key(SecretKey::Char(0x0D), 2),
        FormAction::Redraw
    ));
    // Pasted JSON with line breaks collapses to single spaces.
    let units: Vec<u16> = "[1,
  2,
 3]"
    .encode_utf16()
    .collect();
    let pasted = crate::secure_field::normalize_paste(&units, Charset::KeyText, 64).unwrap();
    assert_eq!(pasted.as_slice(), b"[1, 2, 3]");
}

/// W11 (spec/10 §9.1): one masked field with the applet's bounds (PIV 6–8 here), ASCII only,
/// no copy (Ctrl+C does nothing), capture exclusion preferred like the other input windows, the
/// submitted PIN moved out as an owned `Zeroizing` buffer and the field wiped; the title and the
/// "N회 터치" line follow the kind (per input for Bitcoin and Zcash, per transaction for a Solana
/// dApp request).
#[test]
fn w11_card_pin_bounds_mask_and_owned_buffer() {
    let kind = SecretKind::CardPin {
        min: 6,
        max: 8,
        touches: 3,
        per_tx: false,
        serial: 7_700_011,
    };
    assert_eq!(kind.id(), "W11");
    assert_eq!(kind.title(Lang::Ko), "YubiKey PIN");
    assert!(!kind.is_display() && !kind.plaintext());
    let intro = super::intro(kind, Lang::Ko, (0, false), None);
    assert!(intro[0].starts_with(
        "1. YubiKey #7700011 연결 → 2. PIN 입력 후 확인 → 3. 깜박이면 15초 안에 터치"
    ));
    // A named card (2026-11-15): the name with its serial.
    let named = super::intro(kind, Lang::Ko, (0, false), Some("메인 (#7700011)"));
    assert!(named[0].starts_with("1. YubiKey 메인 (#7700011) 연결 → 2. PIN 입력 후 확인"));
    assert!(intro[1].contains("YubiKey 터치 3회가 필요합니다 (입력마다 한 번,"));
    let per_tx = super::intro(
        SecretKind::CardPin {
            min: 6,
            max: 8,
            touches: 3,
            per_tx: true,
            serial: 7_700_011,
        },
        Lang::Ko,
        (0, false),
        None,
    );
    assert!(
        per_tx[1].contains("YubiKey 터치 3회가 필요합니다 (거래마다 한 번,")
            && per_tx[1].contains("15초 안의 거래는 터치 없이")
            && !per_tx[1].contains("입력"),
        "{}",
        per_tx[1]
    );
    assert_eq!(
        super::intro(
            SecretKind::CardPin {
                min: 6,
                max: 127,
                touches: 1,
                per_tx: false,
                serial: 0,
            },
            Lang::Ko,
            (0, false),
            None,
        )
        .len(),
        1
    );
    let mut form = input(kind, Lang::Ko, 0, true);
    form.set_details(vec!["이 키를 가진 YubiKey: #7700011".to_owned()]);
    type_text(&mut form, "12345", 0);
    assert!(
        matches!(form.on_key(SecretKey::Char(0x0D), 0), FormAction::Redraw),
        "too short"
    );
    type_text(&mut form, "6789", 0);
    // The field holds at most 8 characters.
    let FormAction::Submit(submission) = form.on_key(SecretKey::Char(0x0D), 0) else {
        unreachable!("expected submit");
    };
    let [pin] = submission.values.as_slice() else {
        unreachable!("one value");
    };
    let owned: &Zeroizing<Vec<u8>> = pin;
    assert_eq!(owned.as_slice(), b"12345678");
    assert!(matches!(form.on_key(SecretKey::Copy, 0), FormAction::None));
    // Non-ASCII is refused like in every secret window.
    assert!(matches!(
        form.on_key(SecretKey::Char(0xAC00), 0),
        FormAction::Redraw
    ));
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
        let mut form = input(kind, Lang::Ko, 0, true);
        for (index, text) in fields.iter().enumerate() {
            if index > 0 {
                form.on_key(SecretKey::Tab { back: false }, 0);
            }
            type_text(&mut form, text, 0);
        }
        form.on_key(SecretKey::Char(0x0D), 0)
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
    let mut form = input(
        SecretKind::Backup {
            positions: [3, 9, 16, 22],
        },
        Lang::Ko,
        0,
        true,
    );
    for (index, word) in ["abandon", "ability", "aban", "abandonx"]
        .into_iter()
        .enumerate()
    {
        if index > 0 {
            form.on_key(SecretKey::Tab { back: false }, 10);
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
    assert!(matches!(
        form.on_key(SecretKey::Char(0x0D), 20),
        FormAction::Redraw
    ));
    form.on_key(SecretKey::Char(0x08), 30);
    form.on_key(SecretKey::Tab { back: false }, 30);
    form.on_key(SecretKey::Tab { back: false }, 30);
    form.on_key(SecretKey::Tab { back: false }, 30);
    type_text(&mut form, "don", 30);
    assert_eq!(form.word_mark(2), WordMark::Listed);
    assert!(form.can_submit(40));
    // Enter moves to the last field, then sends.
    assert!(matches!(
        form.on_key(SecretKey::Char(0x0D), 40),
        FormAction::Redraw
    ));
    assert!(matches!(
        form.on_key(SecretKey::Char(0x0D), 50),
        FormAction::Submit(_)
    ));
}

/// spec/14: every secret-window text exists in both languages with the same placeholders (each
/// index `0..args` used by at least one side), and the English side has no Hangul.
#[test]
fn secret_text_catalogue_is_complete() {
    use yw_core::lang::{has_hangul, placeholders};
    for entry in super::text::ALL {
        let ko = placeholders(entry.ko);
        let en = placeholders(entry.en);
        assert!(
            ko.iter().chain(&en).all(|index| *index < entry.args),
            "{}: placeholder out of range",
            entry.name
        );
        for index in 0..entry.args {
            assert!(
                ko.contains(&index) || en.contains(&index),
                "{}: {{{index}}} unused",
                entry.name
            );
        }
        assert!(!has_hangul(entry.en), "{}: {}", entry.name, entry.en);
        assert!(
            !entry.en.is_empty() && !entry.ko.is_empty(),
            "{}",
            entry.name
        );
    }
}

/// The Korean PIN-target texts of the W12 windows stay those of `PinTarget` (byte-identical).
#[test]
fn pin_target_texts_match_the_korean_originals() {
    use crate::yubikey::PinTarget;
    for target in [
        PinTarget::OpenPgpUser,
        PinTarget::OpenPgpAdmin,
        PinTarget::PivPin,
        PinTarget::PivPuk,
    ] {
        for lang in Lang::ALL {
            assert_eq!(super::target_name(target, lang), target.name(lang));
            // 2026-11-20 (S4 P7a1): the title helper moved to `crate::secret` with the kind;
            // compared through the W12 kind (the engine test compares the helper itself).
            assert_eq!(
                super::CardSecretKind::ChangePin(target).title(lang),
                target.change_title(lang)
            );
            assert_eq!(super::target_rule(target, lang), target.rule(lang));
        }
    }
}

/// With `Lang::En` no secret window draws Hangul in its title, field labels, intro and rule lines,
/// checkbox, status line or buttons (ASCII inputs).
#[test]
#[expect(clippy::too_many_lines, reason = "one table of every window kind")]
fn every_secret_window_is_english_with_lang_en() {
    use super::CardSecretKind;
    use crate::yubikey::PinTarget;
    use yw_core::lang::has_hangul;
    let mut kinds = vec![
        SecretKind::SetPassword,
        SecretKind::Unlock,
        SecretKind::ConfirmPassword,
        SecretKind::ChangePassword,
        SecretKind::Mnemonic,
        SecretKind::Passphrase { confirm: true },
        SecretKind::Passphrase { confirm: false },
        SecretKind::ShowMnemonic { create: true },
        SecretKind::ShowMnemonic { create: false },
        SecretKind::ShowKey,
        SecretKind::Backup {
            positions: [3, 7, 12, 24],
        },
        SecretKind::CardSecret(CardSecretKind::AdminPin),
        SecretKind::CardSecret(CardSecretKind::ManagementKey),
        SecretKind::CardSecret(CardSecretKind::PivPin),
        SecretKind::CardSecret(CardSecretKind::SetPins),
        SecretKind::CardSecret(CardSecretKind::UserPin { piv: false }),
        SecretKind::CardSecret(CardSecretKind::UserPin { piv: true }),
    ];
    for chain in [
        ImportChain::Evm,
        ImportChain::Sol,
        ImportChain::Btc,
        ImportChain::Zec,
    ] {
        for no_words in [false, true] {
            kinds.push(SecretKind::PrivateKey { chain, no_words });
        }
    }
    for target in [
        PinTarget::OpenPgpUser,
        PinTarget::OpenPgpAdmin,
        PinTarget::PivPin,
        PinTarget::PivPuk,
    ] {
        kinds.push(SecretKind::CardSecret(CardSecretKind::ChangePin(target)));
    }
    for (touches, per_tx, serial) in [(1, false, 0), (3, false, 7_700_011), (2, true, 7)] {
        kinds.push(SecretKind::CardPin {
            min: 6,
            max: 8,
            touches,
            per_tx,
            serial,
        });
    }
    for kind in kinds {
        let id = kind.id();
        let form = if kind.is_display() {
            SecretForm::display(
                kind,
                Lang::En,
                0,
                DisplaySecret {
                    text: SecretString::from_zeroizing(Zeroizing::new("ab".repeat(32))),
                    address: None,
                    passphrase_note: true,
                    copy_allowed: true,
                },
                PlatformFlags::WINDOWS,
            )
        } else {
            input(kind, Lang::En, 0, false)
        };
        let mut texts: Vec<String> = vec![kind.title(Lang::En).to_owned()];
        texts.extend(form.slots.iter().map(|slot| slot.label.clone()));
        for address in [false, true] {
            texts.extend(super::intro(kind, Lang::En, (24, address), None));
        }
        if let Some((label, _)) = form.checkbox {
            texts.push(label.to_owned());
        }
        texts.extend(form.note.clone());
        let (right, left) = form.button_labels(0);
        texts.extend(right.into_iter().chain(left).map(|(_, label)| label));
        for text in &texts {
            assert!(!text.is_empty() && !has_hangul(text), "{id}: {text}");
        }
    }
    // The W08 hold button and W12's own validation errors (the W01/W04 status line is the yw-app
    // paint's, `ui::secret::tests::password_status_names_the_problem`).
    let mut hold = SecretForm::display(
        SecretKind::ShowMnemonic { create: true },
        Lang::En,
        0,
        DisplaySecret {
            text: SecretString::from_zeroizing(Zeroizing::new("abandon".to_owned())),
            address: None,
            passphrase_note: false,
            copy_allowed: false,
        },
        PlatformFlags::WINDOWS,
    );
    hold.hold.begin(0);
    let (right, _) = hold.button_labels(500);
    assert!(right.iter().all(|(_, label)| !has_hangul(label)));
    assert!(super::card_pin_steps(Lang::En, Some("#7")).starts_with("1. Connect YubiKey #7 → "));
    assert!(
        super::card_pin_steps(Lang::En, Some("Main (#7)"))
            .starts_with("1. Connect YubiKey Main (#7) → ")
    );
    assert!(super::card_pin_steps(Lang::En, None).starts_with("1. Connect YubiKey → "));
    for (kind, fields) in [
        (
            SecretKind::CardSecret(CardSecretKind::AdminPin),
            &["1234567"][..],
        ),
        (
            SecretKind::CardSecret(CardSecretKind::ManagementKey),
            &["0a"][..],
        ),
        (
            SecretKind::CardSecret(CardSecretKind::PivPin),
            &["12345"][..],
        ),
        (
            SecretKind::CardSecret(CardSecretKind::UserPin { piv: false }),
            &["12345"][..],
        ),
        (
            SecretKind::CardSecret(CardSecretKind::SetPins),
            &["123", "24681357", "24681357"][..],
        ),
        (
            SecretKind::CardSecret(CardSecretKind::SetPins),
            &["", "24681357", "24681358"][..],
        ),
        (
            SecretKind::CardSecret(CardSecretKind::SetPins),
            &["", "12345678", "12345678"][..],
        ),
        (
            SecretKind::CardSecret(CardSecretKind::ChangePin(PinTarget::OpenPgpAdmin)),
            &["12345678", "87654321", "87654320"][..],
        ),
        (
            SecretKind::CardSecret(CardSecretKind::ChangePin(PinTarget::OpenPgpAdmin)),
            &["12345678", "1234", "1234"][..],
        ),
        (
            SecretKind::CardSecret(CardSecretKind::ChangePin(PinTarget::PivPin)),
            &["123456", "123456", "123456"][..],
        ),
        (
            SecretKind::CardPin {
                min: 6,
                max: 8,
                touches: 1,
                per_tx: false,
                serial: 0,
            },
            &["12345"][..],
        ),
    ] {
        let mut form = input(kind, Lang::En, 0, true);
        for (index, text) in fields.iter().enumerate() {
            if index > 0 {
                form.on_key(SecretKey::Tab { back: false }, 0);
            }
            type_text(&mut form, text, 0);
        }
        assert!(matches!(
            form.on_key(SecretKey::Char(0x0D), 0),
            FormAction::Redraw
        ));
        let error = form.error.clone().unwrap_or_default();
        assert!(
            !error.is_empty() && !has_hangul(&error),
            "{}: {error}",
            kind.id()
        );
    }
}

/// 2026-11-24 (S5-8; spec/15 §9.3–§9.4, S5 plan critic C10): a platform flag only narrows. With
/// [`PlatformFlags::WINDOWS`] paste and copy are what they were; on a platform without word
/// paste the recovery-word and private-key windows (W05, W07) take no paste (the password,
/// passphrase and PIN windows still do, W10 never), and without secret copy a display window has
/// no `복사` button, copies nothing and asks for no copy on Ctrl+C. Copying also needs the user's
/// `allowSecretCopy` on every platform.
#[test]
fn platform_flags_only_narrow_paste_and_copy() {
    let narrow = PlatformFlags {
        secret_copy: false,
        secret_word_paste: false,
        ..PlatformFlags::WINDOWS
    };
    let words: Vec<u16> = "abandon".encode_utf16().collect();
    for (kind, windows, narrowed) in [
        (SecretKind::Mnemonic, true, false),
        (EVM_KEY, true, false),
        (SecretKind::SetPassword, true, true),
        (SecretKind::Passphrase { confirm: false }, true, true),
        (
            SecretKind::CardPin {
                min: 6,
                max: 8,
                touches: 1,
                per_tx: false,
                serial: 0,
            },
            true,
            true,
        ),
        (
            SecretKind::Backup {
                positions: [1, 2, 3, 4],
            },
            false,
            false,
        ),
    ] {
        for (flags, offered) in [(PlatformFlags::WINDOWS, windows), (narrow, narrowed)] {
            let mut form = SecretForm::new(kind, Lang::Ko, 0, true, flags);
            assert_eq!(
                matches!(form.on_key(SecretKey::Paste, 0), FormAction::Paste),
                offered,
                "{} {flags:?}",
                kind.id()
            );
            if !offered {
                assert_eq!(form.apply_paste(&words), Err(ErrorCode::Inp018));
                assert_eq!(form.test_held_units(), 0, "{}", kind.id());
            }
        }
    }
    for (flags, copy_allowed, offered) in [
        (PlatformFlags::WINDOWS, true, true),
        (PlatformFlags::WINDOWS, false, false),
        (narrow, true, false),
        (narrow, false, false),
    ] {
        let mut form = SecretForm::display(
            SecretKind::ShowKey,
            Lang::Ko,
            0,
            DisplaySecret {
                text: SecretString::from_zeroizing(Zeroizing::new("ab".repeat(32))),
                address: None,
                passphrase_note: false,
                copy_allowed,
            },
            flags,
        );
        assert_eq!(
            form.copy_units().is_some(),
            offered,
            "{flags:?} {copy_allowed}"
        );
        let (_, left) = form.button_labels(0);
        assert_eq!(
            left.iter()
                .any(|(button, _)| *button == crate::secret::input::SecretButton::Copy),
            offered
        );
        assert_eq!(
            form.button_enabled(crate::secret::input::SecretButton::Copy, 0),
            offered
        );
        // Ctrl+C: Windows asks the shell even with the setting off (it shows T-COPY-OFF and
        // copies nothing, spec/04 §4.8); a platform without secret copy never asks.
        assert_eq!(
            matches!(form.on_key(SecretKey::Copy, 0), FormAction::Copy),
            flags.secret_copy
        );
    }
}

/// 2026-11-24 (S5-8): the paint's read-only view shows what the form holds — its texts, flags and
/// counts, a field's drawing copy (masked or not), W08's displayed secret, address, note and
/// countdown — and nothing changes the form.
#[test]
fn the_view_reads_what_the_form_holds() {
    let mut form = input(SecretKind::SetPassword, Lang::En, 0, false);
    type_text(&mut form, "short", 0);
    form.set_details(vec!["detail".to_owned()]);
    form.set_error(Some("error".to_owned()));
    form.set_info(Some("info".to_owned()));
    form.set_busy(true);
    let view = form.paint_view();
    assert_eq!(view.lang(), Lang::En);
    assert_eq!(view.kind(), SecretKind::SetPassword);
    assert!(!view.capture_excluded() && view.step().is_none());
    assert_eq!(
        view.intro(),
        super::intro(SecretKind::SetPassword, Lang::En, (24, false), None)
    );
    assert_eq!(view.details(), ["detail"]);
    assert_eq!(
        (view.error(), view.transient(), view.info()),
        (Some("error"), None, Some("info"))
    );
    assert!(view.busy() && !view.masked() && !view.input_enabled(0));
    assert_eq!(view.password_checks(), Some((Some(false), None)));
    assert_eq!(view.checkbox(), None);
    assert_eq!(view.countdown_line(0), None);
    assert_eq!(view.shown_text(), None);
    let fields: Vec<(String, usize, usize, bool)> = view
        .fields()
        .map(|field| {
            (
                field.label().to_owned(),
                field.len(),
                field.limit(),
                field.masked(),
            )
        })
        .collect();
    assert_eq!(
        fields,
        [
            (
                super::text::LABEL_PASSWORD.get(Lang::En).to_owned(),
                5,
                128,
                true
            ),
            (
                super::text::LABEL_PASSWORD_AGAIN.get(Lang::En).to_owned(),
                0,
                128,
                true
            ),
        ]
    );
    let first = view.first_field().unwrap();
    // Redacted: the window id only, never a unit.
    assert_eq!(format!("{view:?}"), "SecretView(W01, [REDACTED])");
    assert_eq!(format!("{first:?}"), "FieldView([REDACTED])");
    let plain: Vec<u16> = "short".encode_utf16().collect();
    assert_eq!(first.render_utf16(false).as_slice(), plain.as_slice());
    assert_ne!(first.render_utf16(true).as_slice(), plain.as_slice());
    assert_eq!(view.active(), 0);
    assert_eq!(form.test_held_units(), 5, "the view changed nothing");

    let mut shown = SecretForm::display(
        SecretKind::ShowMnemonic { create: true },
        Lang::Ko,
        1_000,
        DisplaySecret {
            text: SecretString::from_zeroizing(Zeroizing::new("abandon about".to_owned())),
            address: Some("address".to_owned()),
            passphrase_note: true,
            copy_allowed: false,
        },
        PlatformFlags::WINDOWS,
    );
    shown.set_timeout_note(Some(crate::secret::TimeoutNote::Mnemonics));
    let view = shown.paint_view();
    assert_eq!(view.shown_text(), Some("abandon about"));
    assert_eq!(view.shown_address(), Some("address"));
    assert!(view.shown_passphrase_note());
    assert_eq!(
        view.intro(),
        super::intro(
            SecretKind::ShowMnemonic { create: true },
            Lang::Ko,
            (2, true),
            None
        )
    );
    // 238.5 s left: 3:59, then the note.
    assert_eq!(
        view.countdown_line(1_000 + 61_500),
        Some(format!(
            "{} {}",
            super::text::COUNTDOWN.fill(Lang::Ko, ["3", "59"]),
            crate::secret::TimeoutNote::Mnemonics.text(Lang::Ko)
        ))
    );
    assert!(view.fields().next().is_none() && view.first_field().is_none());
}

/// 2026-11-25 (spec/15 §9.2, §18 42 N22, A2-7): W05's completions are the list words that start
/// with the word being typed (none after a space, none while masked, none in another window), and
/// `SecretKey::Pick(n)` types the rest of completion `n` and a space as keys would; an index with
/// no completion changes nothing. The view's `Debug` never shows them.
#[test]
fn word_completions_are_picked_by_index() {
    let mut form = input(SecretKind::Mnemonic, Lang::Ko, 0, true);
    assert!(form.paint_view().word_candidates().is_empty());
    type_text(&mut form, "ab", 1);
    assert_eq!(
        form.paint_view().word_candidates(),
        ["abandon", "ability", "able", "about"]
    );
    assert!(!format!("{:?}", form.paint_view()).contains("abandon"));
    assert!(matches!(
        form.on_key(SecretKey::Pick(4), 2),
        FormAction::None
    ));
    assert!(matches!(
        form.on_key(SecretKey::Pick(0), 3),
        FormAction::Redraw
    ));
    let typed = |form: &SecretForm| {
        form.paint_view()
            .first_field()
            .map(|field| String::from_utf16(&field.render_utf16(false)).unwrap())
            .unwrap()
    };
    assert_eq!(typed(&form), "abandon ");
    assert!(
        form.paint_view().word_candidates().is_empty(),
        "after a space"
    );
    type_text(&mut form, "abo", 4);
    assert_eq!(form.paint_view().word_candidates(), ["about", "above"]);
    form.on_key(SecretKey::Pick(1), 5);
    assert_eq!(typed(&form), "abandon above ");
    // A full word picks itself and adds the space.
    type_text(&mut form, "zoo", 6);
    form.on_key(SecretKey::Pick(0), 7);
    assert_eq!(typed(&form), "abandon above zoo ");
    // Masked content (focus lost) shows no completion and takes no pick.
    type_text(&mut form, "ab", 8);
    form.on_deactivate();
    assert!(form.paint_view().word_candidates().is_empty());
    assert!(matches!(
        form.on_key(SecretKey::Pick(0), 9),
        FormAction::None
    ));
    // Other windows have none.
    let mut backup = input(
        SecretKind::Backup {
            positions: [1, 2, 3, 4],
        },
        Lang::Ko,
        0,
        true,
    );
    type_text(&mut backup, "ab", 1);
    assert!(backup.paint_view().word_candidates().is_empty());
    assert!(matches!(
        backup.on_key(SecretKey::Pick(0), 2),
        FormAction::None
    ));
}
