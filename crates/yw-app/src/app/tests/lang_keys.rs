//! English screens of the key, recovery-phrase, side-file and `rpc.json` flows (spec/14,
//! 2026-11-14): built with `Lang::En`, no fixed text has Hangul — only data (labels the wallet
//! made in Korean before) may — and Korean stays the catalogue's Korean.

use yw_core::lang::{Lang, has_hangul};
use yw_core::vault::{FileKind, MnemonicInfo, RecordId};

use super::{Screen, app_at, controls, has_text, temp_dir, texts, unlocked_app};
use crate::events::{SidecarMoves, SidecarRefusal};
use crate::ui::main_window::Item;

/// Every fixed text of `items`: item texts, labelled-row labels and control texts, minus the
/// given data strings.
fn fixed_texts(items: &[Item], data: &[String]) -> Vec<String> {
    let mut all = texts(items);
    all.extend(items.iter().filter_map(|item| match item {
        Item::LabeledRow(label, _) | Item::Field(label, _) => Some(label.clone()),
        Item::CardStart(Some(title)) => Some(title.clone()),
        _ => None,
    }));
    all.extend(controls(items).into_iter().map(|ctl| ctl.text));
    all.into_iter()
        .map(|text| {
            data.iter()
                .fold(text, |text, value| text.replace(value.as_str(), ""))
        })
        .collect()
}

fn assert_english(items: &[Item], data: &[String]) {
    for text in fixed_texts(items, data) {
        assert!(!has_hangul(&text), "Hangul in English UI: {text}");
    }
}

#[test]
fn english_key_start_screens() {
    let dir = temp_dir("lang-keystart");
    let mut app = app_at(&dir);
    app.settings.language = Lang::En;
    for chain in [
        yw_core::keyimport::ImportChain::Evm,
        yw_core::keyimport::ImportChain::Btc,
    ] {
        app.keys.start.chain = chain;
        let mut items = Vec::new();
        app.key_start_intro(&mut items);
        assert_english(&items, &[]);
        assert!(has_text(
            &items,
            crate::ui::screens_keys::text::KEY_START_BACKUP.en
        ));
    }
    app.settings.language = Lang::Ko;
    let mut items = Vec::new();
    app.key_start_intro(&mut items);
    assert!(has_text(
        &items,
        crate::ui::screens_keys::text::KEY_START_BACKUP.ko
    ));
    assert_eq!(
        crate::ui::screens_keys::no_accounts_text(Lang::En, yw_core::keyimport::ImportChain::Sol),
        "This wallet has no Solana account."
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn english_recovery_phrase_section() {
    let (mut app, dir) = unlocked_app("lang-mn", false);
    app.settings.language = Lang::En;
    let added = RecordId::from_bytes([4; 16]);
    let info = |id: RecordId, primary: bool, backup_confirmed: bool| MnemonicInfo {
        id,
        created_unix: 0,
        words: 24,
        passphrase_used: true,
        backup_confirmed,
        primary,
    };
    app.mn.infos = vec![
        info(RecordId::from_bytes([1; 16]), true, true),
        info(added, false, false),
    ];
    app.mn.confirm_remove = Some(added);
    // Labels are data (default labels are Korean in a wallet made in Korean).
    let mut labels: Vec<String> = app
        .mn
        .infos
        .iter()
        .map(|info| app.mnemonic_label(info.id))
        .collect();
    if let Some(meta) = app.meta.as_ref() {
        labels.extend(
            meta.evm_accounts
                .iter()
                .map(|account| account.label.clone()),
        );
    }
    let mut items = Vec::new();
    app.mn_settings_section(&mut items);
    assert_english(&items, &labels);
    assert!(has_text(&items, crate::app_mnemonics::text::INTRO.en));
    assert!(has_text(
        &items,
        crate::app_mnemonics::text::REMOVE_UNCONFIRMED.en
    ));
    app.mn.add_pick = true;
    let mut items = Vec::new();
    app.mn_pick_row(&mut items);
    assert_english(&items, &labels);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn english_side_file_overlays_and_notices() {
    let (mut app, dir) = unlocked_app("lang-sidecar", false);
    app.settings.language = Lang::En;
    for newer in [false, true] {
        app.sidecar.meta_newer = newer;
        app.sidecar.journal_newer = newer;
        app.sidecar.advanced = true;
        app.sidecar.refusal = Some(crate::app_sidecar::refusal_text(
            Lang::En,
            FileKind::Meta,
            SidecarRefusal::PrevUnreadable,
        ));
        let mut items = Vec::new();
        app.meta_overlay(&mut items);
        app.journal_overlay(&mut items);
        assert_english(&items, &[]);
    }
    app.sidecar.journal_closed = true;
    app.screen = Screen::Main;
    let mut items = Vec::new();
    app.journal_closed_items(&mut items);
    app.journal_send_items(crate::app_sidecar::SendChain::Sol, &mut items);
    assert_english(&items, &[]);
    assert!(has_text(
        &items,
        crate::app_sidecar::text::JOURNAL_CLOSED.en
    ));
    let moves = SidecarMoves {
        quarantined: Some("meta.ywm.corrupt-1".to_owned()),
        prev: Some("meta.ywm.prev.corrupt-1".to_owned()),
    };
    for (kind, use_prev) in [
        (FileKind::Meta, true),
        (FileKind::Meta, false),
        (FileKind::Journal, false),
    ] {
        let text = crate::app_sidecar::resolved_text(Lang::En, kind, use_prev, &moves);
        assert!(!has_hangul(&text), "{text}");
        assert!(text.contains("meta.ywm.prev.corrupt-1"), "{text}");
    }
    // Korean is the catalogue's Korean, particles included.
    assert!(
        crate::app_sidecar::resolved_text(Lang::Ko, FileKind::Journal, false, &moves)
            .contains("읽을 수 없던 파일은 meta.ywm.corrupt-1, 이전 사본은 meta.ywm.prev.corrupt-1(으)로 옮겨 두었습니다")
    );
    let refusal = crate::app_sidecar::refusal_text(
        Lang::En,
        FileKind::Journal,
        SidecarRefusal::Failed(crate::errors::ErrorCode::Vlt003),
    );
    assert!(
        !has_hangul(&refusal) && refusal.ends_with("(E-VLT-003)"),
        "{refusal}"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn english_rpc_import_texts() {
    use crate::app_rpc_import::ImportError;
    for error in [ImportError::Unreadable, ImportError::Format] {
        assert!(!has_hangul(error.text(Lang::En)));
        assert!(has_hangul(error.text(Lang::Ko)));
    }
}
