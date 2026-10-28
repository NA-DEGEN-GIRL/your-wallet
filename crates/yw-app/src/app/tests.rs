//! Headless app-state tests: the real `App` and `KeyWorker` on a temp folder, no windows (secret
//! windows cannot open without a main window, so form submissions go straight to `on_submit`).
//! Key jobs run on this thread one at a time through `workers::key::step`, and their results
//! reach `App::on_key_result` as the UI thread would receive them.

use std::cell::RefCell;
use std::path::PathBuf;

use yw_core::evm::address::{Address, parse_address};
use yw_core::evm::amount::U256;
use yw_core::secret::Zeroizing;

use super::{App, AppMode, Confirm, PasswordAction, Paths, Purpose, Screen};
use crate::apikeys::ApiKeys;
use crate::app_evm::{AppApproval, BalanceState, QueuedItem};
use crate::events::{BalanceSnapshot, KeyOutcome, KeyResult};
use crate::flow::evm::prepare::SendIntent;
use crate::lock::{IdleTracker, LockReason};
use crate::meta::{EvmAccountPref, Meta, RawAccount, Tab};
use crate::settings::Settings;
use crate::ui::approval::{QueueOutcome, QueueSource};
use crate::ui::main_window::{Ctl, Item, Tone};
use crate::ui::screens::{
    RECEIVE_IDS, T_ACCOUNTS_BACKUP, T_ALT_PASS, T_ALT_PASS_RECEIVE, T_DISCARD, T_MAINNET, ids,
};
use crate::ui::secret::Submission;
use crate::workers::key::{KeyWorker, step};

const WALLET_PW: &[u8] = b"app-state-test password";
const WRONG: &[u8] = b"not the wallet password";
const ABOUT: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "yw-app-state-{tag}-{}-{}",
        std::process::id(),
        yw_win::time::monotonic_ms()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn app_at(dir: &std::path::Path) -> App {
    App::new(
        Paths {
            data: dir.to_path_buf(),
            logs: dir.join("logs"),
        },
        true,
        Settings::default(),
        ApiKeys::default(),
    )
}

/// The app, its key worker, and what W08 would have shown after `CreateWallet`.
struct Harness {
    app: App,
    worker: KeyWorker,
    dir: PathBuf,
    phrase: Option<String>,
    address: Option<Address>,
}

impl Harness {
    fn new(tag: &str) -> Self {
        let dir = temp_dir(tag);
        let app = app_at(&dir);
        let worker = KeyWorker::new(&dir);
        app.key(crate::events::KeyJob::Load);
        let mut harness = Self {
            app,
            worker,
            dir,
            phrase: None,
            address: None,
        };
        harness.pump();
        harness
    }

    /// Runs one queued job; its results are returned, not delivered.
    fn run_one(&mut self) -> Vec<KeyResult> {
        let Some(entry) = self.app.key_queue.pop() else {
            return Vec::new();
        };
        let results = RefCell::new(Vec::new());
        let signal = std::sync::Arc::clone(&self.app.lock_signal);
        step(
            &mut self.worker,
            &self.app.key_queue,
            entry,
            &|result| results.borrow_mut().push(result),
            &signal,
        );
        results.into_inner()
    }

    fn deliver(&mut self, results: Vec<KeyResult>) {
        for result in results {
            if let KeyOutcome::Created(Ok((phrase, address))) = &result.outcome {
                self.phrase = Some(phrase.expose().to_owned());
                self.address = Some(*address);
            }
            self.app.on_key_result(result);
        }
    }

    /// Runs every queued job (and the ones they queue) and delivers the results.
    fn pump(&mut self) {
        let mut guard = 0;
        while !self.app.key_queue.is_empty() {
            let results = self.run_one();
            self.deliver(results);
            guard += 1;
            assert!(guard < 200, "key jobs keep queueing each other");
        }
    }

    fn submit(&mut self, purpose: Purpose, values: &[&[u8]]) {
        let values = values
            .iter()
            .map(|value| Zeroizing::new(value.to_vec()))
            .collect();
        self.app.on_submit(
            purpose,
            Submission {
                values,
                checkbox: false,
            },
        );
    }

    fn vault_file(&self) -> PathBuf {
        self.dir.join("vault.ywv")
    }

    /// Create → W08 (refused headless; the phrase is captured) → challenge → W10 → `Unlocked`.
    fn create_and_confirm(&mut self) {
        self.submit(Purpose::CreatePassword, &[WALLET_PW]);
        self.pump();
        assert_eq!(self.app.mode, AppMode::BackupPending);
        let phrase = self.phrase.clone().unwrap();
        let address = self.address.unwrap().to_lower_hex();
        self.app.key(crate::events::KeyJob::BackupChallenge);
        self.pump();
        let challenge = self.app.challenge.unwrap();
        let words: Vec<&str> = phrase.split(' ').collect();
        let mut values: Vec<&[u8]> = challenge
            .positions
            .iter()
            .map(|position| words[usize::from(*position) - 1].as_bytes())
            .collect();
        values.push(&address.as_bytes()[address.len() - 6..]);
        self.submit(Purpose::Backup, &values);
        self.pump();
        assert_eq!(
            self.app.mode,
            AppMode::Unlocked {
                alt_passphrase: false
            }
        );
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn texts(items: &[Item]) -> Vec<String> {
    items
        .iter()
        .filter_map(|item| match item {
            Item::Title(text)
            | Item::Text(text)
            | Item::Muted(text)
            | Item::Help(text)
            | Item::Subtitle(text)
            | Item::Display(text)
            | Item::Banner(text, _) => Some(text.clone()),
            _ => None,
        })
        .collect()
}

fn controls(items: &[Item]) -> Vec<Ctl> {
    items
        .iter()
        .flat_map(|item| match item {
            Item::Row(ctls) | Item::LabeledRow(_, ctls) | Item::Toolbar(_, ctls) => ctls.clone(),
            _ => Vec::new(),
        })
        .collect()
}

fn has_text(items: &[Item], needle: &str) -> bool {
    texts(items).iter().any(|text| text.contains(needle))
}

/// Item 1 of the review: create → backup → damage the payload → unlock → S09 stays reachable
/// through a reload, and `.prev` recovery restores the wallet.
#[test]
fn payload_damage_keeps_prev_recovery_reachable() {
    let mut h = Harness::new("payload");
    assert_eq!(h.app.mode, AppMode::NoVault);
    assert_eq!(h.app.screen, Screen::FirstRun);
    h.create_and_confirm();
    // Backup confirmation wrote generation 2, so `.prev` (generation 1) exists.
    assert!(h.dir.join("vault.ywv.prev").is_file());
    h.app.lock(LockReason::Manual);
    h.pump();
    assert_eq!(h.app.mode, AppMode::Locked);
    assert_eq!(h.app.screen, Screen::Locked);

    // One flipped payload byte: the header (and so `Vault::load`) stays valid.
    let mut bytes = std::fs::read(h.vault_file()).unwrap();
    bytes[200] ^= 1;
    std::fs::write(h.vault_file(), &bytes).unwrap();

    h.submit(Purpose::Unlock, &[WALLET_PW]);
    assert_eq!(h.app.mode, AppMode::Unlocking);
    h.pump();
    assert_eq!(
        h.app.mode,
        AppMode::Corrupt {
            prev_available: true
        }
    );
    assert_eq!(h.app.screen, Screen::Recovery);
    assert!(h.app.payload_damaged);
    assert!(
        h.app
            .banners
            .iter()
            .any(|banner| banner.code == Some(crate::errors::ErrorCode::Vlt008)),
        "E-VLT-008 shown"
    );
    let items = h.app.items();
    assert!(
        controls(&items).iter().any(|ctl| ctl.id == ids::RECOVER),
        "S09 offers .prev recovery"
    );

    // A lock while on S09 reloads the vault (now `Locked`): S09 stays.
    h.app.lock(LockReason::SessionLock);
    h.pump();
    assert_eq!(h.app.screen, Screen::Recovery);
    assert!(matches!(h.app.mode, AppMode::Corrupt { .. }));

    // A wrong password: the window would stay open; the mode returns to S09.
    h.app.on_command(ids::RECOVER);
    h.submit(Purpose::ConfirmPassword(PasswordAction::Recover), &[WRONG]);
    assert_eq!(h.app.mode, AppMode::Unlocking);
    h.pump();
    assert!(matches!(h.app.mode, AppMode::Corrupt { .. }));
    assert_eq!(h.app.screen, Screen::Recovery);
    assert_eq!(std::fs::read(h.vault_file()).unwrap(), bytes);

    // The right password restores `.prev` (generation 1: backup not yet confirmed there).
    h.submit(
        Purpose::ConfirmPassword(PasswordAction::Recover),
        &[WALLET_PW],
    );
    h.pump();
    assert_eq!(h.app.mode, AppMode::BackupPending);
    assert_eq!(h.app.screen, Screen::BackupPending);
    assert!(!h.app.payload_damaged);
    assert!(
        h.app
            .info
            .as_deref()
            .is_some_and(|info| info.contains("이전 사본(.prev)으로 복구했습니다"))
    );
    let quarantined = std::fs::read_dir(&h.dir)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("vault.ywv.corrupt-")
        })
        .count();
    assert_eq!(quarantined, 1, "the damaged file is kept aside");

    // The restored file unlocks normally after a restart-like reload.
    h.app.lock(LockReason::Manual);
    h.pump();
    assert_eq!(h.app.screen, Screen::Locked);
    h.submit(Purpose::Unlock, &[WALLET_PW]);
    h.pump();
    assert_eq!(h.app.mode, AppMode::BackupPending);
}

/// A damaged key section looks like a wrong password: after a failed unlock S07 offers
/// recovery, which restores `.prev` with the same password.
#[test]
fn damaged_key_section_offers_recovery_from_the_lock_screen() {
    let mut h = Harness::new("keysection");
    h.create_and_confirm();
    h.app.lock(LockReason::Manual);
    h.pump();
    let items = h.app.items();
    assert!(
        !controls(&items).iter().any(|ctl| ctl.id == ids::RECOVER),
        "no recovery offer before a failed unlock"
    );
    let mut bytes = std::fs::read(h.vault_file()).unwrap();
    bytes[100] ^= 1; // wrapped DEK
    std::fs::write(h.vault_file(), &bytes).unwrap();
    h.submit(Purpose::Unlock, &[WALLET_PW]);
    h.pump();
    assert_eq!(h.app.mode, AppMode::Locked);
    assert!(h.app.unlock_failed);
    let items = h.app.items();
    assert!(controls(&items).iter().any(|ctl| ctl.id == ids::RECOVER));

    // Cancelling the password window returns to S07 without a reload.
    h.app.on_command(ids::RECOVER);
    h.app
        .on_cancel(Purpose::ConfirmPassword(PasswordAction::Recover));
    assert_eq!(h.app.mode, AppMode::Locked);
    assert_eq!(h.app.screen, Screen::Locked);
    assert!(h.app.key_queue.is_empty());

    h.app.on_command(ids::RECOVER);
    h.submit(
        Purpose::ConfirmPassword(PasswordAction::Recover),
        &[WALLET_PW],
    );
    h.pump();
    assert_eq!(h.app.mode, AppMode::BackupPending);
    assert!(!h.app.unlock_failed);
}

/// Item 2: a lock while `CreateWallet` / `CommitImport` runs drops their results, and the
/// `Load` that survives the lock moves the UI to S07 (the vault exists).
#[test]
fn lock_during_create_or_import_reports_the_new_vault() {
    let mut h = Harness::new("lockcreate");
    h.submit(Purpose::CreatePassword, &[WALLET_PW]);
    assert!(matches!(h.app.screen, Screen::Processing(_)));
    let running = h.run_one(); // Argon2 "in progress"
    h.app.lock(LockReason::SessionLock);
    assert_eq!(h.app.screen, Screen::FirstRun);
    h.deliver(running); // the old epoch's `Created` is dropped
    assert_eq!(h.app.mode, AppMode::NoVault);
    assert!(h.phrase.is_some(), "the worker did create the vault");
    h.pump();
    assert_eq!(h.app.mode, AppMode::Locked);
    assert_eq!(h.app.screen, Screen::Locked);
    h.submit(Purpose::Unlock, &[WALLET_PW]);
    h.pump();
    assert_eq!(h.app.mode, AppMode::BackupPending);

    let mut h = Harness::new("lockimport");
    h.submit(Purpose::ImportPassword, &[WALLET_PW]);
    h.submit(Purpose::ImportMnemonic, &[ABOUT.as_bytes()]);
    h.pump();
    assert!(matches!(h.app.screen, Screen::ImportAddress(_)));
    h.app.on_command(ids::IMPORT_CORRECT);
    let running = h.run_one();
    assert!(
        running
            .iter()
            .any(|result| matches!(result.outcome, KeyOutcome::Imported(Ok(())))),
        "the import committed"
    );
    h.app.lock(LockReason::Suspend);
    h.deliver(running);
    assert_ne!(h.app.screen, Screen::Done);
    h.pump();
    assert_eq!(h.app.mode, AppMode::Locked);
    assert_eq!(h.app.screen, Screen::Locked);
    h.submit(Purpose::Unlock, &[WALLET_PW]);
    h.pump();
    assert_eq!(
        h.app.mode,
        AppMode::Unlocked {
            alt_passphrase: false
        }
    );
}

fn unlocked_app(tag: &str, alt_passphrase: bool) -> (App, PathBuf) {
    let dir = temp_dir(tag);
    let mut app = app_at(&dir);
    app.mode = AppMode::Unlocked { alt_passphrase };
    let mut meta = Meta::default();
    if let Some(first) = meta.evm_accounts.first_mut() {
        first.address = "0x9858effd232b4033e47d90003d41ec34ecaeda94".to_owned();
    }
    meta.sol_accounts.push(crate::meta::Account {
        index: 0,
        label: "Solana 1".to_owned(),
        address: yw_core::sol::SolAddress::from_bytes([7; 32]).to_base58(),
        hidden: false,
    });
    app.meta = Some(meta);
    app.screen = Screen::Main;
    (app, dir)
}

/// Item 3: a mistyped-passphrase session blocks every `받기` and shows T-ALT-PASS everywhere.
#[test]
fn unverified_passphrase_blocks_receive_and_shows_the_banner_everywhere() {
    let (mut app, dir) = unlocked_app("altpass", true);
    assert!(app.passphrase_unverified());
    for tab in [Tab::Evm, Tab::Sol] {
        if let Some(meta) = app.meta.as_mut() {
            meta.prefs.tab = tab;
        }
        let items = app.items();
        assert!(
            items.iter().any(
                |item| matches!(item, Item::Banner(text, Tone::HighRisk) if text == T_ALT_PASS)
            ),
            "{tab:?}"
        );
        let receive: Vec<Ctl> = controls(&items)
            .into_iter()
            .filter(|ctl| RECEIVE_IDS.contains(&ctl.id))
            .collect();
        assert!(!receive.is_empty(), "{tab:?}");
        assert!(receive.iter().all(|ctl| !ctl.enabled), "{tab:?}");
    }
    for screen in [
        Screen::Settings(super::SettingsSection::Security),
        Screen::Sites,
        Screen::AddressBook,
    ] {
        app.screen = screen.clone();
        assert!(has_text(&app.items(), T_ALT_PASS), "{screen:?}");
    }
    app.screen = Screen::Main;
    for id in RECEIVE_IDS {
        app.on_command(id);
        assert_eq!(app.screen, Screen::Main, "{id}");
        assert_eq!(app.info.as_deref(), Some(T_ALT_PASS_RECEIVE));
    }
    assert!(app.key_queue.is_empty(), "no BTC address was derived");
    for screen in [Screen::Receive, Screen::SolReceive, Screen::BtcReceive] {
        app.set_screen(screen);
        assert_eq!(app.screen, Screen::Main);
    }

    // A verified session is unaffected.
    let (mut app, other) = unlocked_app("verified", false);
    assert!(!app.passphrase_unverified());
    let items = app.items();
    assert!(!has_text(&items, T_ALT_PASS));
    assert!(
        controls(&items)
            .iter()
            .filter(|ctl| RECEIVE_IDS.contains(&ctl.id))
            .all(|ctl| ctl.enabled)
    );
    app.on_command(crate::ui::screens_evm::ids::RECEIVE_OPEN);
    assert_eq!(app.screen, Screen::Receive);
    let _ = std::fs::remove_dir_all(dir);
    let _ = std::fs::remove_dir_all(other);
}

/// Item 6 (LK-1): the idle clock pauses while an approval is shown and restarts on close.
#[test]
fn idle_lock_pauses_while_an_approval_is_shown() {
    let (mut app, dir) = unlocked_app("idle", false);
    app.settings.auto_lock_minutes = 1;
    app.idle = IdleTracker::new(0);
    let item = QueuedItem::App(Box::new(AppApproval {
        chain_id: 11_155_111,
        account: parse_address("0x9858EfFD232B4033E47d90003D41EC34EcaEda94").unwrap(),
        signer: yw_core::vault::EvmKeySource::Derived(yw_core::bip32::path::AccountIndex::ZERO),
        intent: SendIntent {
            to: parse_address("0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb").unwrap(),
            value: U256::from_u64(1),
            data: Vec::new(),
            access_list: Vec::new(),
            dapp_gas: None,
            dapp_nonce: None,
        },
        replace: None,
    }));
    app.evm.queue.enqueue(QueueSource::App, item).unwrap();
    let mut finished = Vec::new();
    assert!(app.evm.queue.show_next(1_000, &mut finished).is_some());
    // Five idle minutes with the approval open: no lock.
    app.idle_tick(300_000);
    assert!(matches!(app.mode, AppMode::Unlocked { .. }));
    assert!(app.key_queue.is_empty());
    // Closed at 300 s: the count restarts from there.
    let _ = app.evm.queue.finish_shown(QueueOutcome::Rejected);
    app.idle_tick(300_000);
    app.idle_tick(359_000);
    assert!(matches!(app.mode, AppMode::Unlocked { .. }));
    app.idle_tick(360_000);
    assert_eq!(app.mode, AppMode::Locked);
    let _ = std::fs::remove_dir_all(dir);
}

/// Items 4, 5, 7, 8: imported-key backup texts, removal balance check, discard warning,
/// mainnet badges and the import S08 text.
#[test]
fn backup_discard_mainnet_and_done_texts() {
    let (mut app, dir) = unlocked_app("texts", false);
    // S10 `내 계정`: imported keys are not covered by the recovery words.
    app.settings.evm_chain_id = 11_155_111;
    let items = app.items();
    assert!(has_text(&items, T_ACCOUNTS_BACKUP));
    assert!(!has_text(&items, "모든 계정은 같은 복구 단어로 복구됩니다"));
    assert!(!has_text(&items, T_MAINNET), "Sepolia is a testnet");
    // Mainnet badges: Ethereum, HyperEVM, Solana mainnet; none on Solana devnet.
    for chain in [1, 999] {
        app.settings.evm_chain_id = chain;
        assert!(has_text(&app.items(), T_MAINNET), "chain {chain}");
    }
    if let Some(meta) = app.meta.as_mut() {
        meta.prefs.tab = Tab::Sol;
    }
    app.settings.solana.cluster = crate::network::SolCluster::Mainnet;
    assert!(has_text(&app.items(), T_MAINNET));
    app.settings.solana.cluster = crate::network::SolCluster::Devnet;
    assert!(!has_text(&app.items(), T_MAINNET));
    if let Some(meta) = app.meta.as_mut() {
        meta.prefs.tab = Tab::Evm;
    }

    // EVM `폐기`: paying twice.
    app.set_screen(Screen::Confirm(Confirm::Discard));
    let items = app.items();
    assert!(has_text(&items, T_DISCARD));
    assert!(T_DISCARD.contains("두 번 지불"));

    // Imported key removal: export first, and the balance check.
    let raw = "0x6fac4d18c912343bf86fa7049364dd4e424ab9c0";
    let record = [9_u8; 16];
    if let Some(meta) = app.meta.as_mut() {
        meta.evm_raw_accounts.push(RawAccount {
            record_id: record,
            label: "가져온 계정 1".to_owned(),
            address: raw.to_owned(),
        });
        meta.prefs.evm_account = EvmAccountPref::Record(record);
    }
    app.settings.evm_chain_id = 11_155_111;
    app.screen = Screen::Main;
    app.on_command(ids::REMOVE_KEY);
    assert_eq!(app.screen, Screen::Confirm(Confirm::RemoveKey));
    let items = app.items();
    assert!(has_text(&items, "개인키 보기"));
    assert!(has_text(&items, "복구 단어로 복구되지 않"));
    assert!(
        items
            .iter()
            .any(|item| matches!(item, Item::Banner(text, Tone::Warn) if text.contains("잔액을 확인하지 못했습니다"))),
        "unknown balance warns"
    );
    let address = parse_address(raw).unwrap();
    app.evm.balances.insert(
        11_155_111,
        BalanceState {
            snapshot: Some(BalanceSnapshot {
                block: 7,
                native: vec![(address, U256::from_u64(5_000_000_000_000_000))],
                tokens: Vec::new(),
            }),
            ..BalanceState::default()
        },
    );
    let items = app.items();
    assert!(
        items
            .iter()
            .any(|item| matches!(item, Item::Banner(text, Tone::HighRisk) if text.contains("잔액이 있습니다"))),
        "a balance is a high-risk warning"
    );
    app.on_command(ids::CONFIRM_NO);

    // S08 after an import never claims a backup check.
    app.done_imported = true;
    app.set_screen(Screen::Done);
    let items = app.items();
    assert!(!has_text(&items, "백업을 확인했습니다"));
    assert!(has_text(&items, "지갑을 가져왔습니다"));
    app.done_imported = false;
    assert!(has_text(&app.items(), "백업을 확인했습니다"));
    let _ = std::fs::remove_dir_all(dir);
}
