//! The engine's form state (2026-11-24, spec/15 §11.3, §11.4 S5-6; S5 plan O-3, O-4): what the
//! plain edits show is the wallet's own — from `Cmd::Edit`, the field writes it emitted (resolved
//! as a shell takes them from the outbox) and the screen models a shell answered it drew
//! (`Cmd::Rendered`) — with no read-back from a window; the lock's screen change clears it. The
//! wallet alone, with made-up shell facts: no yw-app, no window, no file, no network.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use yw_core::lang::Lang;
use yw_core::vault::FileKind;
use yw_engine::apikeys::ApiKeys;
use yw_engine::app_store::{AppStore, SealedRead};
use yw_engine::cmd::Cmd;
use yw_engine::effect::Effect;
use yw_engine::form::EditField;
use yw_engine::screen::facts::{PipeStatus, PlatformFlags, ScreenFacts};
use yw_engine::services::Services;
use yw_engine::settings::Settings;
use yw_engine::wallet::lock::LockReason;
use yw_engine::wallet::{AppMode, Screen, Wallet};

/// A manual test clock (monotonic ms; the wall clock a fixed base after it).
struct TestClock(AtomicU64);

impl yw_platform::clock::Clock for TestClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }

    fn now_unix_ms(&self) -> u64 {
        1_800_000_000_000 + self.now_ms()
    }

    fn sleep_ms(&self, _ms: u64) {}
}

/// No files: nothing is read or kept.
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

/// Made-up shell facts (no file is probed).
struct Facts;

impl ScreenFacts for Facts {
    fn local_wall_ms(&self, unix_ms: u64) -> Option<u64> {
        Some(unix_ms)
    }

    fn data_dir(&self) -> String {
        "data".to_owned()
    }

    fn rpc_json_present(&self) -> bool {
        false
    }

    fn extension_dir(&self) -> Option<String> {
        None
    }

    fn expected_extension_dir(&self) -> Option<String> {
        None
    }

    fn pipe(&self) -> PipeStatus {
        PipeStatus {
            server: false,
            error: None,
        }
    }

    fn version_text(&self, _lang: Lang) -> String {
        "test".to_owned()
    }

    fn flags(&self) -> PlatformFlags {
        PlatformFlags::WINDOWS
    }
}

/// An unlocked wallet with no workers, on S14 with its form open and a drafted address.
fn wallet() -> Wallet {
    let clock = Arc::new(TestClock(AtomicU64::new(1_000_000)));
    let mut wallet = Wallet::new(
        Box::new(NoFiles),
        Services {
            llm: Arc::new(|_endpoint| None),
            walletconnect: None,
            ua_platform: "test",
        },
        true,
        Settings::default(),
        ApiKeys::default(),
        clock,
        1_000_000,
    );
    wallet.mode = AppMode::Unlocked {
        alt_passphrase: false,
    };
    wallet.screen = Screen::AddressBook;
    wallet.book.form.open = true;
    "draft".clone_into(&mut wallet.book.form.address);
    wallet
}

/// The shell drew the current screen: it built the model, then answered `Render` with the
/// plain edit that had the focus.
fn draw(wallet: &mut Wallet, focus: Option<EditField>) {
    let _ = wallet.screen(&Facts);
    wallet.on_cmd(Cmd::Rendered { focus });
}

/// Every effect queued, taken as a shell takes them (each field write resolved), unapplied.
fn take_all(wallet: &mut Wallet) {
    while wallet.next_effect().is_some() {}
}

/// A drawn model's edits are the form state; the user's change, then a field write and a clear
/// resolved as the shell takes them; the same screen drawn again keeps what was typed.
#[test]
fn the_form_state_follows_what_the_wallet_drew_and_wrote() {
    let mut wallet = wallet();
    assert_eq!(wallet.form.text(EditField::BookAddress), None);
    // Answered with nothing built: no change.
    wallet.on_cmd(Cmd::Rendered { focus: None });
    assert_eq!(wallet.form.text(EditField::BookAddress), None);
    draw(&mut wallet, None);
    assert_eq!(wallet.form.text(EditField::BookAddress), Some("draft"));
    assert_eq!(wallet.form.text(EditField::BookLabel), Some(""));
    wallet.on_cmd(Cmd::Edit {
        field: EditField::BookLabel,
        text: yw_core::secret::Zeroizing::new("typed".to_owned()),
    });
    take_all(&mut wallet);
    assert_eq!(wallet.form.text(EditField::BookLabel), Some("typed"));
    // The same controls drawn again: the typed text stays (the model still says "").
    draw(&mut wallet, None);
    assert_eq!(wallet.form.text(EditField::BookLabel), Some("typed"));
    // A write is the form state at once (O-10) and what the drawn edit shows once taken.
    wallet.emit(Effect::SetField {
        field: EditField::BookAddress,
        text: "written".to_owned(),
    });
    assert_eq!(wallet.form.text(EditField::BookAddress), Some("written"));
    take_all(&mut wallet);
    assert_eq!(wallet.form.text(EditField::BookAddress), Some("written"));
    // A clear: empty at once, and the drawn edit is empty once taken.
    wallet.emit(Effect::ClearField {
        field: EditField::BookLabel,
    });
    assert_eq!(wallet.form.text(EditField::BookLabel), Some(""));
    take_all(&mut wallet);
    assert_eq!(wallet.form.text(EditField::BookLabel), Some(""));
    // A write to an edit that is not drawn: there while queued, gone once taken.
    wallet.emit(Effect::SetField {
        field: EditField::LlmModel,
        text: "model".to_owned(),
    });
    assert_eq!(wallet.form.text(EditField::LlmModel), Some("model"));
    take_all(&mut wallet);
    assert_eq!(wallet.form.text(EditField::LlmModel), None);
}

/// O-4: the lock that leaves the screen for S07 clears the form state at once; its render then
/// draws no plain edit.
#[test]
fn the_lock_clears_the_form_state() {
    let mut wallet = wallet();
    draw(&mut wallet, None);
    assert_eq!(wallet.form.text(EditField::BookAddress), Some("draft"));
    let vault_present = wallet.lock_steps(LockReason::Manual);
    wallet.lock_after_wait(vault_present);
    assert_eq!(wallet.screen, Screen::Locked);
    for field in EditField::ALL {
        assert_eq!(wallet.form.text(field), None, "{field:?}");
    }
    take_all(&mut wallet);
    draw(&mut wallet, None);
    for field in EditField::ALL {
        assert_eq!(wallet.form.text(field), None, "{field:?}");
    }
}

/// O-4, the other branch (2026-11-24, S5-6 review): with no vault (`NoVault`), the lock leaves the
/// screen for S01 and clears the form state at once too; a mode with no vault that is not
/// `NoVault` keeps its screen, and so its form state.
#[test]
fn the_lock_with_no_vault_clears_the_form_state() {
    let mut wallet = wallet();
    draw(&mut wallet, None);
    assert_eq!(wallet.form.text(EditField::BookAddress), Some("draft"));
    wallet.mode = AppMode::NoVault;
    let vault_present = wallet.lock_steps(LockReason::Manual);
    assert!(!vault_present);
    wallet.lock_after_wait(vault_present);
    assert_eq!(wallet.screen, Screen::FirstRun);
    for field in EditField::ALL {
        assert_eq!(wallet.form.text(field), None, "{field:?}");
    }
    take_all(&mut wallet);
    draw(&mut wallet, None);
    for field in EditField::ALL {
        assert_eq!(wallet.form.text(field), None, "{field:?}");
    }
    // `Starting` has no vault either but is not `NoVault`: the screen and its edits stay.
    let mut wallet = wallet_on_book();
    wallet.mode = AppMode::Starting;
    let vault_present = wallet.lock_steps(LockReason::Manual);
    wallet.lock_after_wait(vault_present);
    assert_eq!(wallet.screen, Screen::AddressBook);
    assert_eq!(wallet.form.text(EditField::BookAddress), Some("draft"));
}

/// [`wallet`] with its address-book screen drawn.
fn wallet_on_book() -> Wallet {
    let mut wallet = wallet();
    draw(&mut wallet, None);
    wallet
}
