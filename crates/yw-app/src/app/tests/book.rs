//! The tests of `app_book.rs` that build an `App` (2026-11-21, S4 W0, spec/09 §2.1),
//! moved unchanged from its inline `mod tests` (which keeps the tests that build no `App`).
//! A `#[cfg(test)] #[path]` child of `crate::app_book`, not of `app::tests`: it keeps the
//! access of the inline module, so no production item of that file is widened.

use super::tests::EVM;
use super::*;
use crate::app::App;

/// A new entry is compared with everything the send forms know, not only the book: a poison
/// of a past recipient is flagged on save with the sent-history wording (it used to save
/// silently and then pass for known), a book entry by its label.
#[test]
fn book_saves_compare_with_the_whole_known_set() {
    use crate::apikeys::ApiKeys;
    use crate::app::{AppMode, Paths};
    use crate::meta::{ActivityEntry, Meta};
    use crate::settings::Settings;

    let dir = std::env::temp_dir().join(format!("yw-app-book-known-{}", std::process::id()));
    let mut app = App::new(
        Paths {
            data: dir.clone(),
            logs: dir.join("logs"),
        },
        true,
        Settings::default(),
        ApiKeys::default(),
    );
    app.mode = AppMode::Unlocked {
        alt_passphrase: false,
    };
    let mut meta = Meta::default();
    meta.upsert_activity(
        "eip155:1",
        &ActivityEntry {
            account: "0xfe3b557e8fb62b89f4916b721be55ceb828dbd73".to_owned(),
            tx_id: format!("0x{}", "ab".repeat(32)),
            title: "보내기".to_owned(),
            asset: "native".to_owned(),
            amount: "1".to_owned(),
            counterparty: EVM.to_owned(),
            status: "succeeded".to_owned(),
            time_unix_ms: 1,
        },
    );
    app.meta = Some(meta);
    let poisoned = format!("0x5290{}4169ee7", "0".repeat(29));
    let note = app.book_look_alike(BookChain::Evm, &poisoned);
    assert!(
        note.as_deref()
            .is_some_and(|note| note.starts_with("보낸 내역에 있는 주소(0x5290")),
        "{note:?}"
    );
    assert!(app.book_look_alike(BookChain::Evm, EVM).is_none());
    let other = "0x1111111111111111111111111111111111111111";
    assert!(app.book_look_alike(BookChain::Evm, other).is_none());
    if let Some(meta) = app.meta.as_mut() {
        meta.add_contact(&Contact {
            chain: BookChain::Evm,
            address: EVM.to_owned(),
            label: "친구".to_owned(),
            verified: false,
            added_at_unix_ms: 1,
        })
        .unwrap();
    }
    let note = app.book_look_alike(BookChain::Evm, &poisoned);
    assert!(
        note.as_deref()
            .is_some_and(|note| note.starts_with("주소록의 '친구'과 앞·끝 글자가")),
        "{note:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// S14's row `편집` opens the form at the top of the screen (2026-11-21, S4 W4): the handler
/// queues `Effect::ScrollTop` before its `refresh`'s `Render` and writes no shell state; the
/// offset is 0 once the entry drains. Before W4 `on_book_row` set the shell's offset itself.
/// The W4 review (same day) also pins that the arm leaves the remembered offsets and any
/// wheel glide alone, as the old write did.
#[test]
fn a_book_row_edit_opens_the_form_at_the_top_through_an_effect() {
    use crate::apikeys::ApiKeys;
    use crate::app::{AppMode, Paths};
    use crate::meta::Meta;
    use crate::settings::Settings;

    let dir = std::env::temp_dir().join(format!("yw-app-book-top-{}", std::process::id()));
    let mut app = App::new(
        Paths {
            data: dir.clone(),
            logs: dir.join("logs"),
        },
        true,
        Settings::default(),
        ApiKeys::default(),
    );
    app.mode = AppMode::Unlocked {
        alt_passphrase: false,
    };
    let mut meta = Meta::default();
    meta.add_contact(&Contact {
        chain: BookChain::Evm,
        address: EVM.to_owned(),
        label: "친구".to_owned(),
        verified: false,
        added_at_unix_ms: 1,
    })
    .unwrap();
    app.meta = Some(meta);
    app.scroll = 120;
    // 2026-11-21 (S4 W4 review): the executor arm sets the offset only. The remembered offsets
    // stay (this entry pins it); the wheel glide's state is private to `app_scroll`, so the arm's
    // body is pinned from the source below (no `stop_scroll`, no `scroll_memory` call).
    let place = yw_engine::screen::ScrollPlace::AddressBook;
    app.scroll_memory.set(place, 200);
    app.scroll_memory.under_overlay = Some(40);
    app.on_book(BookPress::Row(Row(0), BookRowAction::Edit));
    assert_eq!(app.book.form.editing.as_deref(), Some(EVM));
    assert_eq!(app.scroll, 120, "the handler writes no shell state");
    assert_eq!(app.outbox.front(), Some(&Effect::ScrollTop));
    assert_eq!(app.outbox.back(), Some(&Effect::Render));
    app.drain();
    assert_eq!(app.scroll, 0);
    assert_eq!(app.scroll_memory.get(place), Some(200));
    assert_eq!(app.scroll_memory.under_overlay, Some(40));
    let effects = include_str!("../../app_effects.rs")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert_eq!(
        effects
            .matches("Effect::ScrollTop => { self.scroll = 0; None }")
            .count(),
        1,
        "the ScrollTop arm sets the offset and nothing else"
    );
    assert_eq!(effects.matches("Effect::ScrollTop").count(), 1);
    // A row the screen does not show queues nothing.
    app.scroll = 120;
    app.on_book(BookPress::Row(Row(5), BookRowAction::Edit));
    assert!(app.outbox.is_empty());
    assert_eq!(app.scroll, 120);
    let _ = std::fs::remove_dir_all(&dir);
}
