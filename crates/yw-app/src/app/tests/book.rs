//! The tests of `app_book.rs` that build an `App` (2026-11-21, S4 W0, spec/09 §2.1),
//! moved unchanged from its inline `mod tests` (which keeps the tests that build no `App`).
//! A `#[cfg(test)] #[path]` child of `crate::app_book`, not of `app::tests`: it keeps the
//! access of the inline module, so no production item of that file is widened.

use super::tests::EVM;
use super::*;

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
