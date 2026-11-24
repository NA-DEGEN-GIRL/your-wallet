//! The Windows half of SW-1 and SW-4 (spec/04 §4.10): the blocked secret-window messages, the
//! capture decision, the window size and the W01/W04 status line's texts.
//!
//! 2026-11-24 (spec/15 §11.4 S5-8): the form's state tests (SW-1's buffers, hold, time-out and
//! masking, the password, mnemonic, key, W10–W12 rules, the catalogue and English checks) and
//! the S5-7 differential test moved with the form to `yw_engine::secret::form::tests`; what is
//! left here tests the shell's own code, with the same assertions as before.

use yw_win::ui::is_blocked_secret_msg;

use super::{CaptureDecision, SecretKind, capture_decision};
use yw_core::keyimport::ImportChain;
use yw_core::lang::Lang;
use yw_engine::errors::ErrorCode;
use yw_engine::screen::facts::PlatformFlags;
use yw_engine::secret::form::SecretForm;

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

/// W01/W04's status line names what is wrong: a ✗ never stands before the rule itself, and an
/// empty field is a grey hint; with `Lang::En` it has no Hangul.
#[test]
fn password_status_names_the_problem() {
    let texts = |rule, same| super::password_status(Lang::Ko, rule, same).map(|(text, _)| text);
    assert_eq!(
        texts(None, None),
        ["· 12–128자", "· 확인 칸에 한 번 더 입력"]
    );
    assert_eq!(
        texts(Some(false), Some(false)),
        ["✗ 12자 이상 필요", "✗ 두 칸이 다름"]
    );
    assert_eq!(
        texts(Some(true), Some(true)),
        ["✓ 12–128자", "✓ 두 칸이 같음"]
    );
    for rule in [None, Some(false), Some(true)] {
        for (text, _) in super::password_status(Lang::En, rule, rule) {
            assert!(!yw_core::lang::has_hangul(text), "{text}");
        }
    }
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
        // W11 (spec/10 §9.1): capture exclusion preferred like the other input windows.
        SecretKind::CardPin {
            min: 6,
            max: 8,
            touches: 3,
            per_tx: false,
            serial: 7_700_011,
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
        // The shell's form of a warned window: `보기` off (the form's own test is
        // `yw_engine::secret::form::tests::sw4_reveal_needs_capture_exclusion`).
        let unprotected = SecretForm::new(kind, Lang::Ko, 0, false, PlatformFlags::WINDOWS);
        assert!(!unprotected.reveal_enabled(0));
        assert!(!unprotected.capture_excluded());
    }
}

/// W07 carries the T-IMPORTED-KEY backup warning in a taller window.
#[test]
fn w07_window_holds_its_backup_warning() {
    let evm_key = SecretKind::PrivateKey {
        chain: ImportChain::Evm,
        no_words: false,
    };
    assert_eq!(super::window_size(evm_key), (640, 560));
    assert_eq!(
        super::window_size(SecretKind::ShowMnemonic { create: true }),
        (820, 680)
    );
}
