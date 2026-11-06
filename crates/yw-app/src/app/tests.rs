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
    let quarantined: Vec<String> = std::fs::read_dir(&h.dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("vault.ywv.corrupt-"))
        .collect();
    assert_eq!(quarantined.len(), 1, "the damaged file is kept aside");
    // The note names the exact file, so the user can restore it by hand.
    assert!(
        h.app
            .info
            .as_deref()
            .is_some_and(|info| info.contains(quarantined[0].as_str())),
        "{:?}",
        h.app.info
    );

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

/// D2 follow-up: a `settings.json` of a newer app version is read-only — `save_settings`
/// applies the change in memory and never rewrites the file (spec/04 §6.6).
#[test]
fn read_only_settings_are_never_written() {
    let dir = temp_dir("readonly");
    let original = br#"{"version":2,"autoLockMinutes":7,"futureKey":true}"#;
    std::fs::write(dir.join("settings.json"), original).unwrap();
    let loaded = crate::settings::load(Some(original));
    assert_eq!(loaded.settings.read_only(), Some(2));
    let mut app = App::new(
        Paths {
            data: dir.clone(),
            logs: dir.join("logs"),
        },
        true,
        loaded.settings,
        ApiKeys::default(),
    );
    let mut changed = app.settings.clone();
    changed.auto_lock_minutes = 9;
    app.save_settings(changed, "autoLockMinutes");
    assert_eq!(app.settings.auto_lock_minutes, 9, "applied for this run");
    assert_eq!(std::fs::read(dir.join("settings.json")).unwrap(), original);
    assert!(app.banners.is_empty(), "no E-APP-002");

    // A current-version file is written as before.
    let current = dir.join("current");
    std::fs::create_dir_all(&current).unwrap();
    let mut app = app_at(&current);
    let mut changed = app.settings.clone();
    changed.auto_lock_minutes = 9;
    app.save_settings(changed, "autoLockMinutes");
    let written = std::fs::read(current.join("settings.json")).unwrap();
    let reread = crate::settings::load(Some(&written));
    assert_eq!(reread.settings.auto_lock_minutes, 9);
    assert_eq!(reread.settings.read_only(), None);
    let _ = std::fs::remove_dir_all(dir);
}

/// D2 follow-up: S15 `QuickNode` 저장 accepts the whole dashboard URL in either field and names
/// the wrong field in E-KEY-002 (`QuickNodeField::label`).
#[test]
fn quicknode_fields_accept_a_pasted_endpoint_url() {
    use crate::apikeys::QuickNodeField;
    const TOKEN: &str = "abcdef0123456789abcdef0123456789";
    let url = format!("https://My-Node.base-sepolia.quiknode.pro/{TOKEN}/");
    assert_eq!(super::quicknode_input("", ""), Ok(None));
    assert_eq!(super::quicknode_input("  ", " "), Ok(None));
    for (name, token) in [
        (url.as_str(), ""),
        ("", url.as_str()),
        (url.as_str(), url.as_str()),
        ("my-node", TOKEN),
        (url.as_str(), TOKEN),
    ] {
        let (parsed_name, parsed_token) = super::quicknode_input(name, token)
            .unwrap()
            .expect("both fields filled");
        assert_eq!(parsed_name, "my-node");
        assert_eq!(parsed_token.as_str(), TOKEN);
    }
    let name_error = super::quicknode_input("my node", TOKEN).unwrap_err();
    assert!(
        name_error.ends_with(&format!(" ({}) (E-KEY-002)", QuickNodeField::Name.label())),
        "{name_error}"
    );
    let token_error = super::quicknode_input("my-node", "short").unwrap_err();
    assert!(
        token_error.ends_with(&format!(" ({}) (E-KEY-002)", QuickNodeField::Token.label())),
        "{token_error}"
    );
    // A URL in one field and a different token in the other is the token field's error.
    let mismatch = super::quicknode_input(&url, "zzzzzzzzzzzzzzzzzzzz").unwrap_err();
    assert!(
        mismatch.contains(QuickNodeField::Token.label()),
        "{mismatch}"
    );
}

/// D2 follow-up: dormant `apikeys.dpapi` entries are listed in S15 and removed only through the
/// `보관 항목 삭제` confirmation (`ApiKeys::prune_dormant`, spec/04 §6.6).
#[test]
fn prune_dormant_entries_after_confirmation() {
    use crate::ui::screens::ids as core_ids;
    let dir = temp_dir("prune");
    let mut plain = crate::apikeys::APIKEYS_MAGIC.to_vec();
    plain.push(1);
    let name = b"rpc:eip155:8453";
    let value = b"https://base.example.test/v1";
    plain.push(u8::try_from(name.len()).unwrap());
    plain.extend_from_slice(name);
    plain.extend_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
    plain.extend_from_slice(value);
    let decoded = ApiKeys::decode(&plain, &|_| false).unwrap();
    assert_eq!(decoded.keys.dormant_names(), ["rpc:eip155:8453"]);
    let mut app = App::new(
        Paths {
            data: dir.clone(),
            logs: dir.join("logs"),
        },
        true,
        Settings::default(),
        decoded.keys,
    );
    app.mode = AppMode::Unlocked {
        alt_passphrase: false,
    };
    app.meta = Some(Meta::default());
    app.screen = Screen::Settings(super::SettingsSection::Network);
    let items = app.items();
    assert!(has_text(&items, "보관하고 있습니다"));
    assert!(
        controls(&items)
            .iter()
            .any(|ctl| ctl.id == core_ids::PRUNE_DORMANT)
    );
    // Cancel keeps them.
    app.on_command(core_ids::PRUNE_DORMANT);
    assert_eq!(app.screen, Screen::Confirm(Confirm::PruneDormant));
    assert!(has_text(&app.items(), "rpc:eip155:8453"));
    app.on_command(core_ids::CONFIRM_NO);
    assert_eq!(app.apikeys.dormant_names().len(), 1);
    // Confirm removes and saves them.
    app.on_command(core_ids::PRUNE_DORMANT);
    app.on_command(core_ids::CONFIRM_YES);
    assert_eq!(
        app.screen,
        Screen::Settings(super::SettingsSection::Network)
    );
    assert!(app.apikeys.dormant_names().is_empty());
    assert!(dir.join("apikeys.dpapi").is_file());
    let (reloaded, unreadable) = super::load_apikeys(&app.paths, &app.settings);
    assert!(!unreadable);
    assert!(reloaded.dormant_names().is_empty());
    let items = app.items();
    assert!(
        !controls(&items)
            .iter()
            .any(|ctl| ctl.id == core_ids::PRUNE_DORMANT)
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// D2 follow-up: the S12 EVM receive QR can encode the bare address (exchange apps) instead of
/// EIP-681, with the network note; the shared-address note is always shown.
#[test]
fn evm_receive_qr_toggles_to_the_plain_address() {
    use crate::ui::qr::{EvmQrKind, RECEIVE_SHARED_ADDRESS_NOTE};
    use crate::ui::screens_evm::ids as evm_ids;
    let (mut app, dir) = unlocked_app("receive-qr", false);
    let address = parse_address("0x9858effd232b4033e47d90003d41ec34ecaeda94").unwrap();
    app.set_screen(Screen::Receive);
    let qr = |items: &[Item]| {
        items.iter().find_map(|item| match item {
            Item::Qr(payload) => Some(payload.clone()),
            _ => None,
        })
    };
    let items = app.items();
    assert_eq!(app.evm.receive_qr, EvmQrKind::Eip681);
    assert_eq!(
        qr(&items),
        Some(format!("ethereum:{}@11155111", address.to_checksum()))
    );
    assert!(has_text(&items, RECEIVE_SHARED_ADDRESS_NOTE));
    assert!(!has_text(&items, "네트워크 정보가 없습니다"));
    app.on_command(evm_ids::QR_PLAIN);
    let items = app.items();
    assert_eq!(app.evm.receive_qr, EvmQrKind::PlainAddress);
    assert_eq!(qr(&items), Some(address.to_checksum()));
    assert!(has_text(&items, "네트워크 정보가 없습니다"));
    assert!(has_text(&items, RECEIVE_SHARED_ADDRESS_NOTE));
    let radios: Vec<Ctl> = controls(&items)
        .into_iter()
        .filter(|ctl| ctl.id == evm_ids::QR_EIP681 || ctl.id == evm_ids::QR_PLAIN)
        .collect();
    assert_eq!(radios.len(), 2);
    app.on_command(evm_ids::QR_EIP681);
    assert!(qr(&app.items()).is_some_and(|payload| payload.starts_with("ethereum:")));
    let _ = std::fs::remove_dir_all(dir);
}

// ---------------------------------------------------------------- imported keys (spec/04 §2.18)

/// spec/07 §17.1 abandon `m/44'/501'/0'/0'` seed: a public test vector, imported as a keypair.
const SOL_SEED_HEX: &str = "37df573b3ac4ad5b522e064e25b63ea16bcbe79d449e81a0268d1047948bb445";
const SOL_ADDRESS: &str = "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk";
/// BIP84 test vector WIF (abandon mnemonic, `m/84'/0'/0'/0/0`) and its address.
const BIP84_WIF: &str = "KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d";
const BIP84_ADDRESS: &str = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";

fn sol_keypair_text() -> String {
    let mut pair = yw_core::hex::decode(SOL_SEED_HEX).unwrap();
    pair.extend_from_slice(&yw_core::codec::base58::base58_decode_32(SOL_ADDRESS).unwrap());
    yw_core::codec::base58::encode(&pair)
}

fn control_ids(items: &[Item]) -> Vec<u16> {
    controls(items).iter().map(|ctl| ctl.id).collect()
}

/// "개인키로 시작하기" with a Solana key: a key-only wallet (no recovery words) whose tabs hide
/// derivation, takes a Bitcoin key, survives lock/unlock straight to S10, and keeps its last key.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one key-only wallet from S01 to removal"
)]
fn key_start_creates_a_key_only_wallet() {
    use crate::ui::screens_keys::{self as keys_ui, ids as key_ids};
    use yw_core::bip32::path::BtcChain;
    use yw_core::btc::ScriptType;
    use yw_core::keyimport::{ImportChain, ImportSpec};

    let mut h = Harness::new("keystart");
    assert_eq!(h.app.screen, Screen::FirstRun);
    assert!(control_ids(&h.app.items()).contains(&key_ids::FIRST_KEY));
    h.app.on_command(key_ids::FIRST_KEY);
    assert_eq!(h.app.screen, Screen::KeyStartIntro);
    assert!(has_text(&h.app.items(), keys_ui::T_KEY_START_BACKUP));
    h.app.on_command(key_ids::START_CHAIN_SOL);
    assert_eq!(h.app.keys.start.chain, ImportChain::Sol);
    // W01, then W07 with an address instead of a key: back to S18 with W07 (headless: refused).
    h.submit(Purpose::KeyStartPassword, &[WALLET_PW]);
    h.submit(Purpose::KeyStartKey, &[SOL_ADDRESS.as_bytes()]);
    h.pump();
    assert_eq!(h.app.screen, Screen::KeyStartIntro);
    assert!(
        h.app.keys.start.password_held,
        "the worker keeps the password"
    );
    // The keypair: S19 shows its address and the backup warning.
    h.submit(Purpose::KeyStartKey, &[sol_keypair_text().as_bytes()]);
    h.pump();
    let Screen::KeyStartAddress(view) = h.app.screen.clone() else {
        unreachable!("S19 expected, got {:?}", h.app.screen);
    };
    assert_eq!(view.address, SOL_ADDRESS);
    assert!(has_text(&h.app.items(), keys_ui::T_KEY_START_BACKUP));
    h.app.on_command(key_ids::START_CORRECT);
    h.pump();
    assert_eq!(
        h.app.mode,
        AppMode::Unlocked {
            alt_passphrase: false
        }
    );
    assert_eq!(h.app.screen, Screen::Done);
    assert!(has_text(&h.app.items(), keys_ui::T_KEY_START_OK));
    h.app.on_command(ids::DONE_CONTINUE);
    assert_eq!(h.app.screen, Screen::Main);
    assert!(h.app.key_only());
    let meta = h.app.meta.clone().unwrap();
    assert!(meta.evm_accounts.is_empty() && meta.sol_accounts.is_empty());
    assert_eq!(meta.sol_raw_accounts.len(), 1);
    assert_eq!(meta.prefs.tab, Tab::Sol);
    // Solana tab: the imported account with its badge, no derivation controls; it signs as an
    // imported key.
    let items = h.app.items();
    assert!(
        items
            .iter()
            .any(|item| matches!(item, Item::Mono(text) if text.replace(' ', "") == SOL_ADDRESS))
    );
    assert!(
        controls(&items)
            .iter()
            .any(|ctl| ctl.text.contains("[가져온 키]"))
    );
    let ids_now = control_ids(&items);
    assert!(!ids_now.contains(&crate::ui::screens_sol::ids::ADD_ACCOUNT));
    assert!(!ids_now.contains(&crate::ui::screens_sol::ids::SCAN_OPEN));
    assert!(ids_now.contains(&key_ids::SOL_IMPORT));
    let (source, from, _) = h.app.sol_form_sender().unwrap();
    assert_eq!(source, yw_core::slip10::SolKeySource::Imported);
    assert_eq!(from.to_base58(), SOL_ADDRESS);
    // EVM and Bitcoin tabs: "이 지갑에는 … 계정이 없습니다" with `개인키 가져오기`.
    h.app.sol_select_tab(Tab::Evm);
    let items = h.app.items();
    assert!(has_text(
        &items,
        &keys_ui::no_accounts_text(ImportChain::Evm)
    ));
    assert!(control_ids(&items).contains(&ids::IMPORT_KEY));
    assert!(!control_ids(&items).contains(&ids::ADD_ACCOUNT));
    h.app.btc_select_tab();
    let items = h.app.items();
    assert!(has_text(
        &items,
        &keys_ui::no_accounts_text(ImportChain::Btc)
    ));
    // Settings: no recovery-word reveal.
    h.app
        .set_screen(Screen::Settings(super::SettingsSection::Security));
    assert!(!control_ids(&h.app.items()).contains(&ids::REVEAL_MNEMONIC));
    // A Bitcoin WIF as P2WPKH: a single-key account of the Bitcoin list (`AddImported`).
    h.app.set_screen(Screen::Main);
    h.submit(
        Purpose::ImportChainKey(ImportSpec::Btc(ScriptType::P2wpkh)),
        &[BIP84_WIF.as_bytes()],
    );
    h.pump();
    let meta = h.app.meta.clone().unwrap();
    assert_eq!(meta.btc_accounts.accounts.len(), 1);
    let account = &meta.btc_accounts.accounts[0];
    assert!(account.is_single() && account.discovery_done());
    assert_eq!(
        account.address(BtcChain::Receive, 0).unwrap().as_str(),
        BIP84_ADDRESS
    );
    assert_eq!(meta.btc_accounts.selected, Some(account.id()));
    // Bitcoin on (mainnet, the key's network): the account list shows it with the badge, the
    // selected imported account's `개인키 보기`·`삭제`, no `계정 추가`, and no placeholder.
    h.app.settings.bitcoin.enabled = true;
    let items = h.app.items();
    assert!(
        controls(&items)
            .iter()
            .any(|ctl| ctl.text.starts_with("[가져온 키] bc1qcr") && ctl.checked == Some(true))
    );
    let ids_now = control_ids(&items);
    assert!(ids_now.contains(&key_ids::BTC_REVEAL) && ids_now.contains(&key_ids::BTC_REMOVE));
    assert!(ids_now.contains(&key_ids::BTC_IMPORT));
    assert!(!ids_now.contains(&crate::ui::screens_btc::ids::ACCOUNT_ADD));
    assert!(!has_text(&items, "통합 후"));
    // Lock and unlock: straight to S10, meta and the key-only flag come back.
    h.app.lock(LockReason::Manual);
    h.pump();
    assert_eq!(h.app.mode, AppMode::Locked);
    h.submit(Purpose::Unlock, &[WALLET_PW]);
    h.pump();
    assert_eq!(
        h.app.mode,
        AppMode::Unlocked {
            alt_passphrase: false
        }
    );
    assert!(h.app.key_only());
    let meta = h.app.meta.clone().unwrap();
    assert_eq!(
        (
            meta.sol_raw_accounts.len(),
            meta.btc_accounts.accounts.len()
        ),
        (1, 1)
    );
    // Remove the Solana key (export-first overlay, then W03).
    h.app.sol_select_tab(Tab::Sol);
    h.app.on_command(key_ids::SOL_REMOVE);
    assert_eq!(h.app.screen, Screen::Confirm(Confirm::RemoveImported));
    assert!(has_text(&h.app.items(), keys_ui::T_REMOVE_IMPORTED));
    let record = yw_core::vault::RecordId::from_bytes(meta.sol_raw_accounts[0].record_id);
    h.app.on_command(ids::CONFIRM_YES);
    h.submit(
        Purpose::ConfirmPassword(PasswordAction::RemoveImported(record)),
        &[WALLET_PW],
    );
    h.pump();
    assert!(h.app.meta.as_ref().unwrap().sol_raw_accounts.is_empty());
    // The Bitcoin key is the last one: it cannot be removed.
    assert!(!h.app.can_remove_imported());
    h.app.btc_select_tab();
    let items = h.app.items();
    let remove = key_ids::BTC_REMOVE;
    assert!(
        controls(&items)
            .iter()
            .any(|ctl| ctl.id == remove && !ctl.enabled)
    );
    h.app.on_command(remove);
    assert_ne!(h.app.screen, Screen::Confirm(Confirm::RemoveImported));
}

/// Imports into a mnemonic wallet: every chain tab offers `개인키 가져오기`; imported Solana
/// accounts list after the derived ones with the badge and sign as `Imported`.
#[test]
fn imports_into_a_mnemonic_wallet() {
    use crate::ui::screens_keys::ids as key_ids;
    use yw_core::keyimport::ImportSpec;

    let mut h = Harness::new("keyimport");
    h.submit(Purpose::ImportPassword, &[WALLET_PW]);
    h.submit(Purpose::ImportMnemonic, &[ABOUT.as_bytes()]);
    h.pump();
    h.app.on_command(ids::IMPORT_CORRECT);
    h.pump();
    h.app.on_command(ids::DONE_CONTINUE);
    assert!(!h.app.key_only());
    // EVM tab: 계정 추가 and 개인키 가져오기 side by side.
    let items = h.app.items();
    assert!(control_ids(&items).contains(&ids::ADD_ACCOUNT));
    assert!(control_ids(&items).contains(&ids::IMPORT_KEY));
    // Solana tab: account 0 is derived on entry; the imported key is added after it.
    h.app.sol_select_tab(Tab::Sol);
    h.pump();
    assert_eq!(h.app.meta.as_ref().unwrap().sol_accounts.len(), 1);
    // The same key as account 0 (abandon m/44'/501'/0'/0') is still a separate imported record.
    h.submit(
        Purpose::ImportChainKey(ImportSpec::Sol),
        &[sol_keypair_text().as_bytes()],
    );
    h.pump();
    let meta = h.app.meta.clone().unwrap();
    assert_eq!(meta.sol_raw_accounts.len(), 1);
    let rows = h.app.sol_account_rows();
    assert_eq!(rows.len(), 2);
    assert!(rows[1].0.is_imported());
    // Select the imported row: the form signs with `SolKeySource::Imported`.
    h.app
        .on_command(crate::ui::screens_sol::ids::ACCOUNT_BASE + 1);
    let (source, _, _) = h.app.sol_form_sender().unwrap();
    assert_eq!(source, yw_core::slip10::SolKeySource::Imported);
    let items = h.app.items();
    assert!(control_ids(&items).contains(&key_ids::SOL_REVEAL));
    assert!(control_ids(&items).contains(&key_ids::SOL_REMOVE));
    // Duplicate import: the vault refuses (E-VLT-011), meta unchanged.
    h.submit(
        Purpose::ImportChainKey(ImportSpec::Sol),
        &[sol_keypair_text().as_bytes()],
    );
    h.pump();
    assert_eq!(h.app.meta.as_ref().unwrap().sol_raw_accounts.len(), 1);
    // Reveal: the key worker returns the base58 keypair (W09 cannot open headless).
    let record = yw_core::vault::RecordId::from_bytes(
        h.app.meta.as_ref().unwrap().sol_raw_accounts[0].record_id,
    );
    h.app.key(crate::events::KeyJob::Reveal {
        password: Zeroizing::new(WALLET_PW.to_vec()),
        what: crate::events::RevealWhat::ImportedKey(record),
    });
    let results = h.run_one();
    assert!(results.iter().any(|result| matches!(
        &result.outcome,
        KeyOutcome::Revealed(Ok((_, text, None))) if text.expose() == sol_keypair_text()
    )));
}

/// "개인키로 시작하기" with a Bitcoin key (spec/04 §2.18, spec/08 §3.5): Bitcoin is turned on
/// with the key's network, the Bitcoin tab lists the imported account with its badge (no BIP84
/// account 0, no `계정 추가`), lock/unlock keeps it, the EVM tab says it has no account and a dApp
/// connect is refused at once with 4100 `NoEvmAccount`.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one key-only Bitcoin wallet from S01 to a dApp"
)]
fn key_start_with_a_bitcoin_key() {
    use crate::browser::envelope::{Correlation, Id16, Id32};
    use crate::browser::{DappEvent, Reply, SiteKind, SiteRequest};
    use crate::network::BtcNet;
    use crate::ui::screens_btc::ids as btc_ids;
    use crate::ui::screens_keys::{self as keys_ui, ids as key_ids};
    use yw_core::btc::{BtcNetwork, ScriptType};
    use yw_core::keyimport::ImportChain;
    use yw_core::policy::ProviderError;
    /// BIP49 test vector key (abandon `m/49'/1'/0'/0/0`), compressed testnet WIF (public).
    const BIP49_TEST_WIF: &str = "cULrpoZGXiuC19Uhvykx7NugygA3k86b3hmdCeyvHYQZSxojGyXJ";

    let mut h = Harness::new("keystart-btc");
    h.app.on_command(key_ids::FIRST_KEY);
    h.app.on_command(key_ids::START_CHAIN_BTC);
    h.app.on_command(key_ids::script_id(ScriptType::P2tr));
    assert_eq!(h.app.keys.start.script, ScriptType::P2tr);
    let items = h.app.items();
    assert!(
        controls(&items)
            .iter()
            .any(|ctl| ctl.text == "탭루트 (bc1p…, P2TR)" && ctl.checked == Some(true))
    );
    h.submit(Purpose::KeyStartPassword, &[WALLET_PW]);
    h.submit(Purpose::KeyStartKey, &[BIP49_TEST_WIF.as_bytes()]);
    h.pump();
    let Screen::KeyStartAddress(view) = h.app.screen.clone() else {
        unreachable!("S19 expected, got {:?}", h.app.screen);
    };
    assert_eq!(view.btc, Some((ScriptType::P2tr, BtcNetwork::Testnet4)));
    assert!(view.address.starts_with("tb1p"));
    assert!(h.app.items().iter().any(|item| matches!(
        item,
        Item::Field(label, value) if label == "주소 형식" && value == "탭루트 (tb1p…, P2TR)"
    )));
    h.app.on_command(key_ids::START_CORRECT);
    h.pump();
    assert_eq!(h.app.screen, Screen::Done);
    // Bitcoin on, on the key's network.
    assert!(h.app.settings.bitcoin.enabled);
    assert_eq!(h.app.settings.bitcoin.network, BtcNet::Testnet4);
    h.app.on_command(ids::DONE_CONTINUE);
    assert_eq!(h.app.screen, Screen::Main);
    assert!(h.app.key_only());
    let meta = h.app.meta.clone().unwrap();
    assert_eq!(meta.prefs.tab, Tab::Btc);
    assert!(meta.btc.is_none());
    assert_eq!(meta.btc_accounts.accounts.len(), 1);
    let address = meta.btc_accounts.accounts[0]
        .address(yw_core::bip32::path::BtcChain::Receive, 0)
        .unwrap();
    assert_eq!(address.as_str(), view.address);
    // The Bitcoin tab (no RPC URL here: the E-KEY-005 banner) lists the imported account.
    let items = h.app.items();
    assert!(
        controls(&items)
            .iter()
            .any(|ctl| ctl.text.starts_with("[가져온 키] tb1p") && ctl.checked == Some(true))
    );
    let ids_now = control_ids(&items);
    assert!(!ids_now.contains(&btc_ids::ACCOUNT_ADD));
    assert!(ids_now.contains(&key_ids::BTC_REVEAL) && ids_now.contains(&key_ids::BTC_REMOVE));
    assert!(ids_now.contains(&key_ids::BTC_IMPORT));
    assert!(!has_text(&items, "통합 후"));
    // Lock and unlock: straight to S10 with the same account.
    h.app.lock(LockReason::Manual);
    h.pump();
    assert_eq!(h.app.mode, AppMode::Locked);
    h.submit(Purpose::Unlock, &[WALLET_PW]);
    h.pump();
    assert_eq!(
        h.app.mode,
        AppMode::Unlocked {
            alt_passphrase: false
        }
    );
    assert!(h.app.key_only());
    let meta = h.app.meta.clone().unwrap();
    assert_eq!(meta.btc_accounts.accounts.len(), 1);
    assert!(meta.btc.is_none());
    // The EVM tab: no account, `개인키 가져오기` offered.
    h.app.sol_select_tab(Tab::Evm);
    let items = h.app.items();
    assert!(has_text(
        &items,
        &keys_ui::no_accounts_text(ImportChain::Evm)
    ));
    assert!(control_ids(&items).contains(&ids::IMPORT_KEY));
    // A dApp connect: 4100 `NoEvmAccount` at once, never queued.
    let site = SiteRequest {
        reply: Reply {
            conn: 1,
            correlation: Correlation {
                session_id: Id32([1; 32]),
                sequence: 1,
                activation_nonce: Id32([2; 32]),
                request_id: Id16([3; 16]),
            },
        },
        origin: yw_core::policy::BrowserOrigin::parse("https://app.example").unwrap(),
        chain_id: yw_core::evm::chain::SEPOLIA,
        deadline_ms: u64::MAX,
        method: yw_core::policy::Method::RequestAccounts,
        kind: SiteKind::RequestAccounts,
        compat_mode: None,
    };
    let refusal = h.app.unlocked_refusal(&site);
    assert_eq!(refusal, Some(ProviderError::NoEvmAccount));
    assert_eq!(refusal.map(|error| error.code()), Some(4100));
    h.app.on_dapp_event(DappEvent::Request(Box::new(site)));
    assert!(h.app.evm.queue.is_empty());
}

/// Regression (adversarial PoC): imported-account labels were `len + 1`, so after a removal two
/// different keys shared one label. They are now numbered after the highest existing number, and
/// the removal overlay names the account by label AND address.
#[test]
fn imported_labels_never_collide_after_removal() {
    let mut h = Harness::new("advlabel");
    h.submit(Purpose::ImportPassword, &[WALLET_PW]);
    h.submit(Purpose::ImportMnemonic, &[ABOUT.as_bytes()]);
    h.pump();
    h.app.on_command(ids::IMPORT_CORRECT);
    h.pump();
    h.app.on_command(ids::DONE_CONTINUE);
    h.pump();
    let key = |n: u8| format!("{}{:02x}", "0".repeat(62), n);
    for n in [1_u8, 2] {
        h.submit(Purpose::ImportKey, &[key(n).as_bytes()]);
        h.pump();
    }
    let first = h.app.meta.as_ref().unwrap().evm_raw_accounts[0].record_id;
    h.app.key(crate::events::KeyJob::RemoveRawKey {
        password: Zeroizing::new(WALLET_PW.to_vec()),
        id: yw_core::vault::RecordId::from_bytes(first),
    });
    h.pump();
    h.submit(Purpose::ImportKey, &[key(3).as_bytes()]);
    h.pump();
    let raws: Vec<RawAccount> = h.app.meta.as_ref().unwrap().evm_raw_accounts.clone();
    assert_eq!(raws.len(), 2);
    assert_eq!(raws[0].label, "가져온 계정 2");
    assert_eq!(raws[1].label, "가져온 계정 3");
    assert_ne!(
        raws[0].label, raws[1].label,
        "two different keys, two labels"
    );

    // The removal overlay shows the account's address next to its label.
    h.app.pending_remove = Some(yw_core::vault::RecordId::from_bytes(raws[1].record_id));
    h.app.set_screen(Screen::Confirm(Confirm::RemoveKey));
    let items = h.app.items();
    assert!(items.iter().any(|item| matches!(
        item,
        Item::Mono(text) if text.replace(' ', "").eq_ignore_ascii_case(&raws[1].address)
    )));
}

#[test]
fn next_imported_label_is_one_above_the_highest_default_number() {
    use crate::meta::{EVM_IMPORTED_PREFIX, SOL_IMPORTED_PREFIX, next_imported_label};
    assert_eq!(
        next_imported_label(EVM_IMPORTED_PREFIX, []),
        "가져온 계정 1"
    );
    assert_eq!(
        next_imported_label(
            EVM_IMPORTED_PREFIX,
            ["가져온 계정 2", "내 지갑", "가져온 계정 7"]
        ),
        "가져온 계정 8"
    );
    assert_eq!(
        next_imported_label(SOL_IMPORTED_PREFIX, ["가져온 계정 4", "가져온 Solana 1"]),
        "가져온 Solana 2"
    );
}

/// A create whose vault was saved but whose later step (the address lookup) failed: the state
/// is reloaded from disk (S07: the vault exists), never S01 "first run" over an existing vault.
#[test]
fn failed_create_after_the_vault_was_saved_reloads_instead_of_first_run() {
    let mut h = Harness::new("createfail");
    h.submit(Purpose::CreatePassword, &[WALLET_PW]);
    let results: Vec<KeyResult> = h
        .run_one()
        .into_iter()
        .map(|result| KeyResult {
            epoch: result.epoch,
            outcome: match result.outcome {
                KeyOutcome::Created(Ok(_)) => KeyOutcome::Created(Err(
                    yw_core::error::VaultError::Key(yw_core::error::KeyError::Internal),
                )),
                other => other,
            },
        })
        .collect();
    assert!(h.vault_file().exists(), "the vault was written");
    h.deliver(results);
    h.pump();
    assert_ne!(h.app.screen, Screen::FirstRun);
    assert_eq!(h.app.mode, AppMode::Locked);
    assert_eq!(h.app.screen, Screen::Locked);
}

/// A first-run import left idle (password and words held, the address preview open, no vault
/// yet) is discarded after the auto-lock time: nothing is left to commit.
#[test]
fn idle_first_run_import_is_discarded() {
    let mut h = Harness::new("firstrunidle");
    h.submit(Purpose::ImportPassword, &[WALLET_PW]);
    h.submit(Purpose::ImportMnemonic, &[ABOUT.as_bytes()]);
    h.pump();
    assert!(matches!(h.app.screen, Screen::ImportAddress(_)));
    assert_eq!(h.app.mode, AppMode::NoVault);
    let start = super::now_ms();
    h.app.idle = IdleTracker::new(start);
    let minutes = u64::from(h.app.settings.auto_lock_minutes);
    h.app.idle_tick(start + minutes * 60_000 - 1);
    assert!(matches!(h.app.screen, Screen::ImportAddress(_)), "not yet");
    h.app.idle_tick(start + minutes * 60_000);
    h.pump();
    assert_eq!(h.app.screen, Screen::FirstRun);
    assert!(h.app.import.password.is_none() && h.app.import.phrase.is_none());
    // The key worker no longer holds the import: `맞습니다` now commits nothing.
    h.app.key(crate::events::KeyJob::CommitImport);
    h.pump();
    assert!(!h.vault_file().exists());
    assert_eq!(h.app.mode, AppMode::NoVault);
}

const LLM_A: &str = "https://api.example.org/v1/chat/completions";
const LLM_B: &str = "https://other.example.net/v1/chat/completions";

/// An app whose saved AI settings use `endpoint` (no window, no worker).
fn llm_app(tag: &str, endpoint: &str) -> (App, PathBuf) {
    let dir = temp_dir(tag);
    let settings = Settings {
        llm_explain: crate::settings::LlmSettings {
            endpoint: endpoint.to_owned(),
            model: "m".to_owned(),
            ..crate::settings::LlmSettings::default()
        },
        ..Settings::default()
    };
    let app = App::new(
        Paths {
            data: dir.clone(),
            logs: dir.join("logs"),
        },
        true,
        settings,
        ApiKeys::default(),
    );
    (app, dir)
}

/// `저장` of the S15 form with a new endpoint draft.
fn llm_save_endpoint(app: &mut App, endpoint: &str) {
    app.llm_ui.endpoint_text = endpoint.to_owned();
    app.llm_ui.model_text = "m".to_owned();
    app.llm_save();
    assert_eq!(app.settings.llm_explain.endpoint, endpoint);
}

/// spec/06 §2.1: the key is bound to the saved endpoint's host when it is entered; after the
/// endpoint moves to another host it is not sent, the connection test and `켜기` ask for it
/// again, and entering it again binds it to the new host.
#[test]
fn llm_key_is_bound_to_the_saved_endpoint_host() {
    let (mut app, dir) = llm_app("llm-bind", LLM_A);
    app.llm_store_key("test-key-01");
    assert_eq!(app.apikeys.llm_host(), Some("api.example.org"));
    assert!(!app.llm_key_withheld());
    let (reloaded, _) = super::load_apikeys(&app.paths, &app.settings);
    assert_eq!(reloaded.llm_host(), Some("api.example.org"));
    let config = crate::explain::LlmConfig::from_settings(
        &app.settings.llm_explain,
        crate::app_llm::stored_llm_key(&app.apikeys),
    )
    .unwrap();
    assert!(config.api_key().is_some() && !config.key_withheld());

    // Another host: the key is never attached.
    llm_save_endpoint(&mut app, LLM_B);
    assert!(app.llm_key_withheld());
    let config = crate::explain::LlmConfig::from_settings(
        &app.settings.llm_explain,
        crate::app_llm::stored_llm_key(&app.apikeys),
    )
    .unwrap();
    assert!(config.api_key().is_none() && config.key_withheld());
    // A port change is a host change too.
    let mut keys = ApiKeys::default();
    keys.set_llm("k", Some("api.example.org"));
    let on_port = crate::settings::LlmSettings {
        endpoint: "https://api.example.org:8443/v1/chat/completions".to_owned(),
        model: "m".to_owned(),
        ..crate::settings::LlmSettings::default()
    };
    let config =
        crate::explain::LlmConfig::from_settings(&on_port, crate::app_llm::stored_llm_key(&keys))
            .unwrap();
    assert!(config.key_withheld());

    // The connection test fails without sending anything.
    app.llm_test();
    let (text, ok) = app.llm_ui.test_result.clone().unwrap();
    assert!(!ok);
    assert!(text.contains("API 키를 다시 입력하세요"), "{text}");
    assert!(!app.llm_ui.test_running);
    // `켜기` after the notice is refused with the same message.
    app.llm_ui.notice_checked = true;
    app.llm_confirm_on();
    assert!(!app.settings.llm_explain.enabled);
    let (text, ok) = app.llm_ui.message.clone().unwrap();
    assert!(!ok);
    assert!(text.contains("API 키를 다시 입력하세요"), "{text}");
    app.mode = AppMode::Unlocked {
        alt_passphrase: false,
    };
    app.meta = Some(Meta::default());
    assert_eq!(app.screen, Screen::Settings(super::SettingsSection::Ai));
    assert!(has_text(
        &app.items(),
        "다른 엔드포인트 주소용이라 보내지 않음"
    ));

    // Entering the key again binds it to the current host; then `켜기` works.
    app.llm_store_key("test-key-02");
    assert_eq!(app.apikeys.llm_host(), Some("other.example.net"));
    assert!(!app.llm_key_withheld());
    app.llm_ui.notice_checked = true;
    app.llm_confirm_on();
    assert!(app.settings.llm_explain.enabled);
    let _ = std::fs::remove_dir_all(dir);
}

/// The meta of an unlocked wallet whose settings snapshot was taken of `settings`.
fn meta_with_snapshot(settings: &Settings) -> Meta {
    Meta {
        security: Box::new(crate::meta::MetaSecurity {
            snapshot: Some(crate::settings::SecuritySnapshot::of(settings)),
            vault_generation_seen: 0,
        }),
        ..Meta::default()
    }
}

/// spec/06 §2.1 compatibility: an older version's key (no `llm:host`) is not bound when
/// `apikeys.dpapi` is loaded (`settings.json` is plain text, review M1); the check after unlock
/// binds it to the host in the vault-encrypted snapshot, and that binding is written before the
/// endpoint changes.
#[test]
fn legacy_llm_key_is_bound_to_the_endpoint_saved_at_load() {
    let mut plain = crate::apikeys::APIKEYS_MAGIC.to_vec();
    plain.push(1);
    let (name, value) = (b"llm".as_slice(), b"legacy-key-01".as_slice());
    plain.push(u8::try_from(name.len()).unwrap());
    plain.extend_from_slice(name);
    plain.extend_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
    plain.extend_from_slice(value);
    let blob = yw_win::dpapi::protect(&plain, crate::apikeys::APIKEYS_ENTROPY).unwrap();

    let (mut app, dir) = llm_app("llm-legacy", LLM_A);
    std::fs::write(app.paths.apikeys(), &blob).unwrap();
    let (keys, unreadable) = super::load_apikeys(&app.paths, &app.settings);
    assert!(!unreadable);
    assert_eq!(keys.llm_key(), Some("legacy-key-01"));
    assert_eq!(keys.llm_host(), None);
    app.apikeys = keys;
    assert!(app.llm_key_withheld());
    app.meta = Some(meta_with_snapshot(&app.settings));
    app.verify_settings();
    assert_eq!(app.apikeys.llm_host(), Some("api.example.org"));
    assert!(!app.llm_key_withheld());
    // The endpoint changes: the old binding is on disk first, so a restart with the new
    // endpoint does not re-bind the key to it.
    llm_save_endpoint(&mut app, LLM_B);
    assert!(app.llm_key_withheld());
    let (reloaded, _) = super::load_apikeys(&app.paths, &app.settings);
    assert_eq!(reloaded.llm_host(), Some("api.example.org"));

    // No endpoint saved at load: the key stays unbound (never sent) until the first one is.
    let (mut fresh, fresh_dir) = llm_app("llm-legacy-none", "");
    std::fs::write(fresh.paths.apikeys(), &blob).unwrap();
    let (keys, _) = super::load_apikeys(&fresh.paths, &fresh.settings);
    assert_eq!(keys.llm_host(), None);
    fresh.apikeys = keys;
    llm_save_endpoint(&mut fresh, LLM_A);
    assert_eq!(fresh.apikeys.llm_host(), Some("api.example.org"));
    assert!(!fresh.llm_key_withheld());
    let (reloaded, _) = super::load_apikeys(&fresh.paths, &fresh.settings);
    assert_eq!(reloaded.llm_host(), Some("api.example.org"));
    let _ = std::fs::remove_dir_all(dir);
    let _ = std::fs::remove_dir_all(fresh_dir);
}

/// Review M1: `settings.json` edited to point the AI at another host (with `enabled` and the
/// notice version forged). Before unlock no worker runs; after the check the AI is off in memory
/// and in the file, the legacy key is bound to the consented host only (never sent to the new
/// one), a banner says so, and only a new consent in the UI switches it back on.
#[test]
fn llm_endpoint_swapped_in_the_file_needs_a_new_consent() {
    let mut plain = crate::apikeys::APIKEYS_MAGIC.to_vec();
    plain.push(1);
    let (name, value) = (b"llm".as_slice(), b"legacy-key-01".as_slice());
    plain.push(u8::try_from(name.len()).unwrap());
    plain.extend_from_slice(name);
    plain.extend_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
    plain.extend_from_slice(value);
    let blob = yw_win::dpapi::protect(&plain, crate::apikeys::APIKEYS_ENTROPY).unwrap();

    let (mut app, dir) = llm_app("llm-swap", LLM_B);
    let consented = Settings {
        llm_explain: crate::settings::LlmSettings {
            enabled: true,
            endpoint: LLM_A.to_owned(),
            model: "m".to_owned(),
            privacy_notice_version: 1,
            ..crate::settings::LlmSettings::default()
        },
        ..Settings::default()
    };
    app.settings.llm_explain.enabled = true;
    app.settings.llm_explain.privacy_notice_version = 1;
    std::fs::write(app.paths.apikeys(), &blob).unwrap();
    let (keys, _) = super::load_apikeys(&app.paths, &app.settings);
    assert_eq!(keys.llm_host(), None);
    app.apikeys = keys;
    app.events = Some(std::sync::Arc::new(crate::events::EventQueue::new(
        Box::new(|| {}),
    )));
    app.llm_reconfigure();
    assert!(!app.llm_running(), "no worker before the snapshot check");

    app.meta = Some(meta_with_snapshot(&consented));
    app.verify_settings();
    assert!(!app.settings.llm_explain.enabled);
    assert!(!app.llm_running());
    let on_disk = crate::settings::load(Some(&std::fs::read(app.paths.settings()).unwrap()));
    assert!(!on_disk.settings.llm_explain.enabled);
    assert_eq!(app.apikeys.llm_host(), Some("api.example.org"));
    assert!(
        app.llm_key_withheld(),
        "the key is never attached for the new host"
    );
    assert!(
        app.banners
            .iter()
            .any(|banner| banner.text == crate::settings::LLM_FORCED_OFF_TEXT)
    );
    // The snapshot keeps the old consent; a new key and consent for the new host in the UI
    // switch it on and move the consent.
    let snapshot = app
        .meta
        .as_ref()
        .unwrap()
        .security
        .snapshot
        .clone()
        .unwrap();
    assert_eq!(snapshot.llm.host, "api.example.org");
    app.llm_store_key("test-key-02");
    app.llm_ui.notice_checked = true;
    app.llm_confirm_on();
    assert!(app.settings.llm_explain.enabled);
    assert!(app.llm_running());
    let snapshot = app
        .meta
        .as_ref()
        .unwrap()
        .security
        .snapshot
        .clone()
        .unwrap();
    assert!(snapshot.llm_consented_to("other.example.net"));
    app.llm_shutdown();
    let _ = std::fs::remove_dir_all(dir);
}

/// Review L15: fee caps and auto-lock changed in the file use the snapshot values; the banner's
/// `파일 값 사용` takes the file values (and the snapshot follows), `되돌리기` rewrites the file;
/// a deleted `HyperEVM` pin is restored in memory and on disk.
#[test]
fn settings_changed_outside_the_app_banner_accept_and_restore() {
    use crate::ui::screens::ids;
    let pin = [0x99; 32];
    let written = Settings {
        evm_genesis_pins: vec![(yw_core::evm::chain::HYPEREVM_MAINNET, pin)],
        ..Settings::default()
    };
    for accept in [true, false] {
        let (mut app, dir) = llm_app(
            if accept {
                "snap-accept"
            } else {
                "snap-restore"
            },
            "",
        );
        std::fs::create_dir_all(&app.paths.data).unwrap();
        let mut file = written.clone();
        file.evm_genesis_pins.clear();
        file.auto_lock_minutes = 60;
        file.fee_caps[0].1.max_fee_per_gas_gwei = "10000".to_owned();
        app.settings = crate::settings::load(Some(&file.to_json())).settings;
        app.meta = Some(meta_with_snapshot(&written));
        app.mode = AppMode::Unlocked {
            alt_passphrase: false,
        };
        app.verify_settings();
        assert_eq!(app.settings.evm_genesis_pins, written.evm_genesis_pins);
        assert_eq!(app.settings.auto_lock_minutes, 10);
        assert_eq!(app.settings.fee_caps, written.fee_caps);
        let settings_path = app.paths.settings();
        let on_disk =
            || crate::settings::load(Some(&std::fs::read(&settings_path).unwrap())).settings;
        // The pin is restored on disk at once; the other values wait for the user.
        assert_eq!(on_disk().evm_genesis_pins, written.evm_genesis_pins);
        assert_eq!(on_disk().auto_lock_minutes, 60);
        assert!(app.guard.pending.is_some());
        app.set_screen(Screen::Main);
        assert!(has_text(
            &app.items(),
            crate::settings::SETTINGS_TAMPERED_TEXT
        ));
        if accept {
            app.on_command(ids::SETTINGS_ACCEPT_FILE);
            assert_eq!(app.settings.auto_lock_minutes, 60);
            let snapshot = app
                .meta
                .as_ref()
                .unwrap()
                .security
                .snapshot
                .clone()
                .unwrap();
            assert_eq!(snapshot.auto_lock_minutes, 60);
            assert_eq!(snapshot.fee_caps, {
                let mut caps = on_disk().fee_caps;
                caps.sort_by_key(|(id, _)| *id);
                caps
            });
        } else {
            app.on_command(ids::SETTINGS_RESTORE);
            assert_eq!(app.settings.auto_lock_minutes, 10);
            assert_eq!(on_disk().auto_lock_minutes, 10);
            assert_eq!(on_disk().fee_caps, written.fee_caps);
        }
        assert!(app.guard.pending.is_none());
        assert!(!has_text(
            &app.items(),
            crate::settings::SETTINGS_TAMPERED_TEXT
        ));
        // A second check (next unlock) finds nothing.
        app.verify_settings();
        assert!(app.guard.pending.is_none());
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// Review M1/L15: the first check without a snapshot (an upgrade) creates it from the settings
/// in use; settings saved while locked are taken over at the next check, not flagged.
#[test]
fn snapshot_created_once_and_early_saves_taken_over() {
    let (mut app, dir) = llm_app("snap-create", "");
    std::fs::create_dir_all(&app.paths.data).unwrap();
    app.meta = Some(Meta::default());
    app.verify_settings();
    let created = app
        .meta
        .as_ref()
        .unwrap()
        .security
        .snapshot
        .clone()
        .unwrap();
    assert_eq!(
        created,
        crate::settings::SecuritySnapshot::of(&app.settings)
    );
    // Locked: the meta is gone; a change made now is remembered by key.
    app.meta = None;
    let mut changed = app.settings.clone();
    changed.auto_lock_minutes = 30;
    app.save_settings(changed, "autoLockMinutes");
    assert_eq!(app.guard.saved_early, vec!["autoLockMinutes"]);
    app.meta = Some(Meta {
        security: Box::new(crate::meta::MetaSecurity {
            snapshot: Some(created),
            vault_generation_seen: 0,
        }),
        ..Meta::default()
    });
    app.verify_settings();
    assert!(app.guard.pending.is_none());
    assert_eq!(app.settings.auto_lock_minutes, 30);
    assert_eq!(
        app.meta
            .as_ref()
            .unwrap()
            .security
            .snapshot
            .as_ref()
            .unwrap()
            .auto_lock_minutes,
        30
    );
    assert!(app.guard.saved_early.is_empty());
    let _ = std::fs::remove_dir_all(dir);
}

/// Review L17: the meta remembers the newest `vault.ywv` generation; a smaller one at the next
/// check shows the rollback banner. The generation is shown on the lock screen.
#[test]
fn vault_generation_going_backwards_is_flagged() {
    let mut h = Harness::new("rollback");
    h.create_and_confirm();
    let now = super::vault_file_info(&h.app.paths.data).unwrap().0;
    assert!(now >= 2);
    h.app.verify_settings();
    assert_eq!(
        h.app.meta.as_ref().unwrap().security.vault_generation_seen,
        now
    );
    assert!(h.app.guard.rollback.is_none());
    // The meta remembers a newer generation than the file: the file was rolled back.
    h.app.meta.as_mut().unwrap().security.vault_generation_seen = now + 3;
    h.app.verify_settings();
    assert_eq!(h.app.guard.rollback, Some((now + 3, now)));
    h.app.set_screen(Screen::Main);
    assert!(has_text(
        &h.app.items(),
        &crate::ui::screens::rollback_text(now + 3, now)
    ));
    h.app.guard.vault_file = super::vault_file_info(&h.app.paths.data);
    h.app.set_screen(Screen::Locked);
    assert!(has_text(&h.app.items(), &format!("저장 횟수(세대) {now}")));
}

/// Two child controls with the same command id on one screen: the owner-drawn button lookup
/// (`yw_win::ui::controls::draw_item`) finds only the first, so the second is never drawn (the
/// send form's `다른 계정으로 바꾸기` link was invisible next to `← 메인으로`). Every screen of an
/// unlocked wallet, on every chain tab, has unique ids.
#[test]
fn every_screen_has_unique_control_ids() {
    use super::SettingsSection;
    let (mut app, dir) = unlocked_app("unique-ids", false);
    app.settings.bitcoin.enabled = true;
    let screens = [
        Screen::Main,
        Screen::Send,
        Screen::SendResult,
        Screen::Receive,
        Screen::AddressBook,
        Screen::TokenAdd,
        Screen::ChainEdit,
        Screen::Sites,
        Screen::SolSend,
        Screen::SolSendResult,
        Screen::SolReceive,
        Screen::SolScan,
        Screen::BtcSend,
        Screen::BtcSendResult,
        Screen::BtcBump,
        Screen::BtcReceive,
        Screen::Settings(SettingsSection::Security),
        Screen::Settings(SettingsSection::Network),
        Screen::Settings(SettingsSection::Chains),
        Screen::Settings(SettingsSection::Solana),
        Screen::Settings(SettingsSection::Bitcoin),
        Screen::Settings(SettingsSection::Ai),
        Screen::Settings(SettingsSection::Other),
        Screen::Settings(SettingsSection::YubiKey),
        Screen::Done,
        Screen::Reset,
        Screen::Extension,
        Screen::HyperCore,
    ];
    let check = |app: &mut App, screens: &[Screen], pass: &str| {
        for tab in [Tab::Evm, Tab::Sol, Tab::Btc] {
            if let Some(meta) = app.meta.as_mut() {
                meta.prefs.tab = tab;
            }
            for screen in screens {
                app.screen = screen.clone();
                let ids = control_ids(&app.items());
                let mut seen = std::collections::HashSet::new();
                for id in ids {
                    assert!(seen.insert(id), "{pass} {tab:?} {screen:?}: id {id} twice");
                }
            }
        }
    };
    check(&mut app, &screens, "plain");
    // Token rows (2026-11-03): user tokens, hidden registry/user/Solana rows with both hidden
    // lists and the send form's hidden radios expanded, the zero toggle on, the delete overlay.
    {
        let meta = app.meta.as_mut().unwrap();
        for (n, label) in [(1_u8, "SCAM"), (2, "GOOD")] {
            let address = format!("0x{}", format!("{n:02x}").repeat(20));
            meta.add_token(
                "eip155:11155111",
                &crate::meta::TokenEntry {
                    address: address.clone(),
                    label: label.to_owned(),
                    decimals: 18,
                },
            )
            .unwrap();
            if n == 1 {
                assert!(
                    meta.token_view
                        .set_hidden("eip155:11155111", &address, true)
                );
            }
        }
        meta.token_view.hide_zero = true;
    }
    let first = app.chain_tokens(11_155_111)[0].0;
    app.meta.as_mut().unwrap().token_view.set_hidden(
        "eip155:11155111",
        &first.to_lower_hex(),
        true,
    );
    if let Some(entry) = yw_core::sol::template::spl_entries(app.sol_cluster()).next() {
        let network = app.sol_token_network();
        app.meta
            .as_mut()
            .unwrap()
            .token_view
            .set_hidden(&network, &entry.mint.to_base58(), true);
    }
    app.evm.show_hidden_tokens = true;
    app.sol.show_hidden_tokens = true;
    app.evm.send_show_hidden = true;
    app.evm.token_delete = Some((
        11_155_111,
        parse_address("0x0202020202020202020202020202020202020202").unwrap(),
    ));
    let mut with_tokens = screens.to_vec();
    with_tokens.push(Screen::Confirm(Confirm::TokenDelete));
    check(&mut app, &with_tokens, "tokens");
    let _ = std::fs::remove_dir_all(dir);
}

/// Ctrl+1/2/3 press the chain tabs on S10 only (not on other screens, not over a secret window).
#[test]
fn tab_shortcuts_switch_chain_tabs_on_the_main_screen() {
    let (mut app, dir) = unlocked_app("tab-shortcut", false);
    let tab = |app: &App| app.meta.as_ref().map(|meta| meta.prefs.tab);
    app.tab_shortcut(2);
    assert_eq!(tab(&app), Some(Tab::Sol));
    app.tab_shortcut(1);
    assert_eq!(tab(&app), Some(Tab::Evm));
    app.tab_shortcut(9);
    assert_eq!(tab(&app), Some(Tab::Evm));
    app.screen = Screen::Sites;
    app.tab_shortcut(2);
    assert_eq!(tab(&app), Some(Tab::Evm));
    let _ = std::fs::remove_dir_all(dir);
}

// ---------------------------------------------------------------- token rows (spec/04 §2.6)

const SCAM: &str = "0x1111111111111111111111111111111111111111";
const GOOD: &str = "0x2222222222222222222222222222222222222222";

/// An unlocked wallet on Sepolia with two user tokens (`SCAM`, `GOOD`) after the registry ones.
fn token_app(tag: &str) -> (App, PathBuf) {
    let (mut app, dir) = unlocked_app(tag, false);
    let meta = app.meta.as_mut().unwrap();
    for (address, label) in [(SCAM, "SCAM"), (GOOD, "GOOD")] {
        meta.add_token(
            "eip155:11155111",
            &crate::meta::TokenEntry {
                address: address.to_owned(),
                label: label.to_owned(),
                decimals: 18,
            },
        )
        .unwrap();
    }
    (app, dir)
}

fn fields(items: &[Item]) -> Vec<String> {
    items
        .iter()
        .filter_map(|item| match item {
            Item::Field(label, _) => Some(label.clone()),
            _ => None,
        })
        .collect()
}

fn ctl(items: &[Item], id: u16) -> Option<Ctl> {
    controls(items).into_iter().find(|ctl| ctl.id == id)
}

/// `숨기기` moves a row under `숨긴 토큰 n개 보기` (dimmed, `다시 보이기`) and persists in meta
/// `token_view`; `잔액 0인 토큰 숨기기` hides only known zero balances; registry tokens have no
/// `삭제`; hiding never removes a token from `chain_tokens` (balances, approvals, recognition).
#[test]
#[expect(clippy::too_many_lines, reason = "one walk through the card states")]
fn evm_token_rows_hide_unhide_and_zero_balance() {
    use crate::token_view::RowPlace;
    use crate::ui::screens_evm::ids::{
        TOKEN_HIDDEN_TOGGLE, TOKEN_HIDE_ZERO, TokenAction, token_row_id,
    };
    let (mut app, dir) = token_app("token-hide");
    let chain = 11_155_111;
    let tokens = app.chain_tokens(chain);
    let registry = tokens.iter().filter(|(.., registered)| *registered).count();
    assert!(registry >= 2, "Sepolia registry WETH/USDC");
    assert_eq!(tokens.len(), registry + 2);
    let scam = registry;
    let items = app.items();
    assert!(fields(&items).contains(&"SCAM (사용자 추가)".to_owned()));
    for (index, (.., registered)) in tokens.iter().enumerate() {
        let hide = ctl(
            &items,
            token_row_id(TokenAction::ToggleHidden(index)).unwrap(),
        )
        .unwrap();
        assert_eq!(hide.text, "숨기기");
        // Registry tokens can only be hidden; user tokens also have `삭제`.
        let delete = ctl(&items, token_row_id(TokenAction::Delete(index)).unwrap());
        assert_eq!(delete.is_some(), !registered, "row {index}");
    }
    assert!(
        ctl(&items, TOKEN_HIDDEN_TOGGLE).is_none(),
        "nothing hidden yet"
    );
    assert_eq!(ctl(&items, TOKEN_HIDE_ZERO).unwrap().checked, Some(false));

    // Hide the scam token.
    app.on_command(token_row_id(TokenAction::ToggleHidden(scam)).unwrap());
    let meta = app.meta.as_ref().unwrap();
    assert!(meta.token_view.is_hidden("eip155:11155111", SCAM));
    let items = app.items();
    assert!(!fields(&items).contains(&"SCAM (사용자 추가)".to_owned()));
    assert_eq!(
        ctl(&items, TOKEN_HIDDEN_TOGGLE).unwrap().text,
        "숨긴 토큰 1개 보기 ▸"
    );
    assert!(
        ctl(
            &items,
            token_row_id(TokenAction::ToggleHidden(scam)).unwrap()
        )
        .is_none()
    );
    // Still known everywhere safety matters.
    assert_eq!(app.chain_tokens(chain), tokens);
    assert_eq!(app.evm_token_rows(chain)[scam].place, RowPlace::Hidden);
    // Expand: dimmed row with `다시 보이기` and `삭제`.
    app.on_command(TOKEN_HIDDEN_TOGGLE);
    let items = app.items();
    assert!(has_text(
        &items,
        "SCAM (사용자 추가) · 잔액 알 수 없음 · 숨김"
    ));
    assert!(has_text(
        &items,
        crate::ui::screens_evm::T_TOKEN_HIDDEN_NOTE
    ));
    let again = ctl(
        &items,
        token_row_id(TokenAction::ToggleHidden(scam)).unwrap(),
    )
    .unwrap();
    assert_eq!(again.text, "다시 보이기");
    assert!(ctl(&items, token_row_id(TokenAction::Delete(scam)).unwrap()).is_some());
    assert_eq!(
        ctl(&items, TOKEN_HIDDEN_TOGGLE).unwrap().text,
        "숨긴 토큰 1개 접기 ▾"
    );

    // Zero balances: registry[0] = 0, registry[1] = 5, GOOD unread.
    let address = |index: usize| tokens[index].0;
    app.evm.balances.insert(
        chain,
        BalanceState {
            snapshot: Some(BalanceSnapshot {
                block: 7,
                native: Vec::new(),
                tokens: vec![
                    (address(0), Some(U256::ZERO)),
                    (address(1), Some(U256::from_u64(5))),
                    (address(scam), Some(U256::ZERO)),
                ],
            }),
            ..BalanceState::default()
        },
    );
    let zero_label = tokens[0].1.clone();
    assert!(fields(&app.items()).contains(&zero_label));
    app.on_command(TOKEN_HIDE_ZERO);
    assert!(app.meta.as_ref().unwrap().token_view.hide_zero);
    let items = app.items();
    assert!(!fields(&items).contains(&zero_label));
    assert!(fields(&items).contains(&tokens[1].1));
    assert!(
        fields(&items).contains(&"GOOD (사용자 추가)".to_owned()),
        "an unread balance never hides a row"
    );
    assert!(has_text(&items, "잔액이 0인 토큰 1개를 감췄습니다"));
    assert_eq!(ctl(&items, TOKEN_HIDE_ZERO).unwrap().checked, Some(true));
    // An explicit hide wins over the zero rule (still listed under the hidden tokens).
    assert_eq!(app.evm_token_rows(chain)[scam].place, RowPlace::Hidden);

    // Unhide: back in the list, the hidden section collapses.
    app.on_command(token_row_id(TokenAction::ToggleHidden(scam)).unwrap());
    assert!(app.meta.as_ref().unwrap().token_view.hidden.is_empty());
    assert!(!app.evm.show_hidden_tokens);
    let items = app.items();
    assert!(ctl(&items, TOKEN_HIDDEN_TOGGLE).is_none());
    // SCAM's balance is 0 and the zero toggle is on.
    assert_eq!(app.evm_token_rows(chain)[scam].place, RowPlace::ZeroHidden);
    app.on_command(TOKEN_HIDE_ZERO);
    assert!(app.meta.as_ref().unwrap().token_view.is_default());
    assert!(fields(&app.items()).contains(&"SCAM (사용자 추가)".to_owned()));
    let _ = std::fs::remove_dir_all(dir);
}

/// The send form's asset radios leave hidden tokens out until `숨긴 토큰 n개 보기`; a selected
/// hidden token is always shown; zero-balance tokens stay; radio ids never renumber.
#[test]
fn send_picker_tucks_hidden_tokens_away() {
    use crate::app_evm::SendAsset;
    use crate::ui::screens_evm::ids::{SEND_ASSET_BASE, SEND_HIDDEN_TOGGLE};
    let (mut app, dir) = token_app("token-send");
    let chain = 11_155_111;
    let tokens = app.chain_tokens(chain);
    let scam = tokens.len() - 2;
    let scam_radio = SEND_ASSET_BASE + u16::try_from(scam + 1).unwrap();
    let good_radio = scam_radio + 1;
    {
        let meta = app.meta.as_mut().unwrap();
        assert!(meta.token_view.set_hidden("eip155:11155111", SCAM, true));
        meta.token_view.hide_zero = true;
    }
    app.evm.balances.insert(
        chain,
        BalanceState {
            snapshot: Some(BalanceSnapshot {
                block: 7,
                native: Vec::new(),
                tokens: vec![(tokens[scam + 1].0, Some(U256::ZERO))],
            }),
            ..BalanceState::default()
        },
    );
    app.set_screen(Screen::Send);
    let items = app.items();
    assert!(ctl(&items, scam_radio).is_none());
    assert!(
        ctl(&items, good_radio).is_some(),
        "zero balance is not hidden here"
    );
    assert!(ctl(&items, SEND_ASSET_BASE).is_some());
    let toggle = ctl(&items, SEND_HIDDEN_TOGGLE).unwrap();
    assert_eq!(toggle.text, "숨긴 토큰 1개 보기 ▸");
    app.on_command(SEND_HIDDEN_TOGGLE);
    let items = app.items();
    let radio = ctl(&items, scam_radio).unwrap();
    assert_eq!(radio.text, "SCAM (사용자 추가)");
    assert!(items.iter().any(|item| matches!(
        item,
        Item::LabeledRow(label, ctls) if label == "숨긴 토큰" && ctls.iter().any(|c| c.id == scam_radio)
    )));
    assert_eq!(
        ctl(&items, SEND_HIDDEN_TOGGLE).unwrap().text,
        "숨긴 토큰 접기 ▾"
    );
    // Collapsed again, but the selected hidden token stays visible (toggle disabled).
    app.on_command(SEND_HIDDEN_TOGGLE);
    app.evm.send.asset = SendAsset::Token(tokens[scam].0);
    let items = app.items();
    assert_eq!(ctl(&items, scam_radio).unwrap().checked, Some(true));
    assert!(!ctl(&items, SEND_HIDDEN_TOGGLE).unwrap().enabled);
    // The radio id maps to the same token whatever is hidden.
    assert_eq!(app.send_asset_meta(), (18, "SCAM".to_owned()));
    let _ = std::fs::remove_dir_all(dir);
}

/// `삭제` of a user token: a confirmation with the label and the full contract, then meta
/// `tokens` without it (and without its hidden mark). Registry rows offer no `삭제`.
#[test]
fn user_token_delete_confirms_with_label_and_address() {
    use crate::ui::screens_evm::ids::{TokenAction, token_row_id};
    let (mut app, dir) = token_app("token-delete");
    let chain = 11_155_111;
    let tokens = app.chain_tokens(chain);
    let scam = tokens.len() - 2;
    app.on_command(token_row_id(TokenAction::Delete(0)).unwrap());
    assert_eq!(app.screen, Screen::Main, "registry token: no delete");
    app.on_command(token_row_id(TokenAction::ToggleHidden(scam)).unwrap());
    app.on_command(token_row_id(TokenAction::Delete(scam)).unwrap());
    assert_eq!(app.screen, Screen::Confirm(Confirm::TokenDelete));
    let items = app.items();
    assert!(has_text(&items, crate::ui::screens::T_TOKEN_DELETE));
    assert!(items.iter().any(
        |item| matches!(item, Item::Field(label, value) if label == "토큰" && value == "SCAM")
    ));
    let full = yw_core::evm::display::format_address(&tokens[scam].0);
    assert!(
        items
            .iter()
            .any(|item| matches!(item, Item::Mono(text) if *text == full))
    );
    // `취소` keeps it.
    app.on_command(ids::CONFIRM_NO);
    assert_eq!(app.evm.token_delete, None);
    assert_eq!(app.chain_tokens(chain).len(), tokens.len());
    app.on_command(token_row_id(TokenAction::Delete(scam)).unwrap());
    app.on_command(ids::CONFIRM_YES);
    assert_eq!(app.screen, Screen::Main);
    let meta = app.meta.as_ref().unwrap();
    let left: Vec<String> = meta
        .tokens_of("eip155:11155111")
        .into_iter()
        .map(|entry| entry.label)
        .collect();
    assert_eq!(left, ["GOOD"]);
    assert!(meta.token_view.is_default(), "the hidden mark went with it");
    let _ = std::fs::remove_dir_all(dir);
}

/// Activity rows of a hidden token stay (history), tagged `[숨긴 토큰]`.
#[test]
fn activity_of_hidden_tokens_stays_tagged() {
    let (mut app, dir) = token_app("token-activity");
    let meta = app.meta.as_mut().unwrap();
    meta.upsert_activity(
        "eip155:11155111",
        &crate::meta::ActivityEntry {
            account: "0x9858effd232b4033e47d90003d41ec34ecaeda94".to_owned(),
            tx_id: format!("0x{}", "ab".repeat(32)),
            title: "토큰 보내기".to_owned(),
            asset: SCAM.to_owned(),
            amount: "1000000000000000000".to_owned(),
            counterparty: GOOD.to_owned(),
            status: "succeeded".to_owned(),
            time_unix_ms: 1,
        },
    );
    let head = |app: &App| app.activity_rows()[0].head.clone();
    assert!(head(&app).contains("1 SCAM") && !head(&app).contains("숨긴 토큰"));
    assert!(
        app.meta
            .as_mut()
            .unwrap()
            .token_view
            .set_hidden("eip155:11155111", SCAM, true)
    );
    assert_eq!(app.activity_rows().len(), 1);
    assert!(
        head(&app).contains("1 SCAM · [숨긴 토큰]"),
        "{}",
        head(&app)
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// Solana: the allowlist rows of the token card hide and show the same way (per cluster); the
/// send form still offers every allowlisted token.
#[test]
fn sol_token_card_hides_allowlist_rows_per_cluster() {
    use crate::ui::screens_sol::ids::{SEND_ASSET_BASE, TOKEN_HIDDEN_TOGGLE, TOKEN_HIDE_BASE};
    let (mut app, dir) = unlocked_app("token-sol", false);
    app.meta.as_mut().unwrap().prefs.tab = Tab::Sol;
    let entry = yw_core::sol::template::spl_entries(app.sol_cluster())
        .next()
        .unwrap();
    let items = app.items();
    assert!(fields(&items).contains(&entry.symbol.to_owned()));
    assert_eq!(ctl(&items, TOKEN_HIDE_BASE).unwrap().text, "숨기기");
    app.on_command(TOKEN_HIDE_BASE);
    let network = app.sol_token_network();
    assert!(
        app.meta
            .as_ref()
            .unwrap()
            .token_view
            .is_hidden(&network, &entry.mint.to_base58())
    );
    let items = app.items();
    assert!(!fields(&items).contains(&entry.symbol.to_owned()));
    assert_eq!(
        ctl(&items, TOKEN_HIDDEN_TOGGLE).unwrap().text,
        "숨긴 토큰 1개 보기 ▸"
    );
    app.on_command(TOKEN_HIDDEN_TOGGLE);
    let items = app.items();
    assert!(has_text(
        &items,
        &format!("{} · 잔액 알 수 없음 · 숨김", entry.symbol)
    ));
    assert_eq!(ctl(&items, TOKEN_HIDE_BASE).unwrap().text, "다시 보이기");
    // Another cluster is not affected.
    assert!(!network.ends_with("devnet"));
    assert!(
        !app.meta
            .as_ref()
            .unwrap()
            .token_view
            .is_hidden("solana:devnet", &entry.mint.to_base58())
    );
    // The send form keeps every allowlisted token.
    app.set_screen(Screen::SolSend);
    assert!(ctl(&app.items(), SEND_ASSET_BASE + 1).is_some());
    app.set_screen(Screen::Main);
    app.on_command(TOKEN_HIDE_BASE);
    assert!(app.meta.as_ref().unwrap().token_view.is_default());
    assert!(!app.sol.show_hidden_tokens);
    assert!(fields(&app.items()).contains(&entry.symbol.to_owned()));
    let _ = std::fs::remove_dir_all(dir);
}

/// spec/08 §3.5: `개인키 보기` of a Bitcoin account on an EVM account's key goes through the same
/// T-REVEAL-WARN overlay and W03 as an imported key, and the key worker returns the compressed WIF
/// of `m/44'/60'/0'/0/0` for the account's network (W09 cannot open headless).
#[test]
fn evm_shared_bitcoin_key_reveal() {
    use yw_core::btc::BtcNetwork;
    /// Testnet WIF of the EVM key `m/44'/60'/0'/0/0` of `abandon … about` (public test key).
    const EVM0_TEST_WIF: &str = "cNUcMV1Uwy9xWKgNzrjKaJ5A7bPTk4Gs8KPujpMqzwkfUuBoD4Kv";

    let mut h = Harness::new("evm-shared-reveal");
    h.submit(Purpose::ImportPassword, &[WALLET_PW]);
    h.submit(Purpose::ImportMnemonic, &[ABOUT.as_bytes()]);
    h.pump();
    h.app.on_command(ids::IMPORT_CORRECT);
    h.pump();
    h.app.on_command(ids::DONE_CONTINUE);
    h.app.btc_evm_shared_reveal(0, BtcNetwork::Testnet4);
    assert_eq!(h.app.screen, Screen::Confirm(Confirm::RevealImported));
    assert_eq!(h.app.keys.btc_evm_target, Some((0, BtcNetwork::Testnet4)));
    // W03's submission (the window itself cannot open headless) queues the reveal job.
    h.submit(
        Purpose::ConfirmPassword(PasswordAction::RevealBtcEvmShared {
            evm_index: 0,
            network: BtcNetwork::Testnet4,
        }),
        &[WALLET_PW],
    );
    let results = h.run_one();
    assert!(results.iter().any(|result| matches!(
        &result.outcome,
        KeyOutcome::Revealed(Ok((_, text, None))) if text.expose() == EVM0_TEST_WIF
    )));
}

/// spec/10 §9.2, §13 at the App level (no windows): a wallet with enrolled emulator `YubiKey`s
/// lists the `YubiKey` accounts in the EVM, Solana and Bitcoin tabs (badge, slot-map addresses,
/// dApp connect lists, no "개인키 보기"); an approved EVM transfer of a `YubiKey` account opens
/// the card step (W11 `CardPin`, `Purpose::CardSign`) instead of `SignEvm`; a wrong PIN returns
/// the unused approval and asks again; the right PIN dispatches `SignEvmCard` and journals the
/// transaction; cancelling drops the approval; a software account still goes to `SignEvm`.
#[test]
#[expect(clippy::too_many_lines, reason = "one card-step scenario")]
fn yubikey_accounts_and_the_card_step() {
    use yw_core::approval::{ApprovalId, ApprovalKind, ApprovalOrigin, ApprovalStore};
    use yw_core::bip32::path::AccountIndex;
    use yw_core::evm::decode::{DecodedTx, decode_call};
    use yw_core::evm::simulate::SimResult;
    use yw_core::evm::tx::Eip1559Tx;
    use yw_core::journal::evm::Role;
    use yw_core::vault::EvmKeySource;

    use crate::app_browser::SignWaiter;
    use crate::app_sol::SolAccountId;
    use crate::events::{KeyJob, SignInfo};

    let (worker, cards, dir, _) = crate::workers::key::tests::yubikey_wallet("app");
    let mut h = Harness {
        app: app_at(&dir),
        worker,
        dir,
        phrase: None,
        address: None,
    };
    h.app.key(KeyJob::Load);
    h.pump();
    h.submit(Purpose::Unlock, &[b"yubikey wallet password"]);
    h.pump();
    assert!(matches!(h.app.mode, AppMode::Unlocked { .. }));

    // EVM: the derived account 0, then the two YubiKey accounts (badge, path, EIP-55 address).
    let rows = h.app.account_rows();
    let hardware: Vec<(EvmAccountPref, String, String)> = rows
        .iter()
        .filter(|(pref, ..)| matches!(pref, EvmAccountPref::Hardware(_)))
        .map(|(pref, _, address, path)| (*pref, address.clone(), path.clone()))
        .collect();
    assert_eq!(
        hardware,
        [
            (
                EvmAccountPref::Hardware(0),
                "0x9858EfFD232B4033E47d90003D41EC34EcaEda94".to_owned(),
                "m/44'/60'/0'/0/0 (YubiKey)".to_owned()
            ),
            (
                EvmAccountPref::Hardware(1),
                "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0".to_owned(),
                "m/44'/60'/0'/0/1 (YubiKey)".to_owned()
            )
        ]
    );
    let card_row = rows
        .iter()
        .position(|(pref, ..)| *pref == EvmAccountPref::Hardware(1))
        .unwrap();
    h.app
        .on_command(ids::ACCOUNT_BASE + u16::try_from(card_row).unwrap());
    h.pump();
    assert_eq!(h.app.selected_pref(), Some(EvmAccountPref::Hardware(1)));
    let (account, source, _) = h.app.selected_account().unwrap();
    assert_eq!(
        source,
        EvmKeySource::Hardware(AccountIndex::new(1).unwrap())
    );
    assert!(h.app.hardware_selected());
    h.app.set_screen(Screen::Main);
    assert!(
        controls(&h.app.items())
            .iter()
            .any(|ctl| ctl.text.contains("[YubiKey]"))
    );
    // dApp connect lists offer it.
    assert!(
        h.app
            .own_accounts()
            .iter()
            .any(|(address, _)| *address == account)
    );
    // Solana: the PIV account, selectable.
    let sol = h.app.sol_account_rows();
    let (sol_row, (_, _, sol_address)) = sol
        .iter()
        .enumerate()
        .find(|(_, (id, ..))| *id == SolAccountId::Hardware(0))
        .unwrap();
    assert_eq!(
        sol_address.to_base58(),
        "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk"
    );
    h.app.sol_select_account(sol_row);
    assert_eq!(
        h.app.sol_selected().map(|(id, ..)| id),
        Some(SolAccountId::Hardware(0))
    );
    assert!(
        h.app
            .sol_dapp_rows()
            .iter()
            .any(|row| row.source == yw_core::slip10::SolKeySource::Hardware(AccountIndex::ZERO))
    );
    // Bitcoin (mainnet): the BIP84 address key as a single-address account with the badge.
    h.app.settings.bitcoin.enabled = true;
    h.app.settings.bitcoin.network = crate::network::BtcNet::Mainnet;
    assert!(
        h.app
            .btc_dapp_rows()
            .iter()
            .any(|row| row.entry.address == "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu")
    );
    if let Some(meta) = h.app.meta.as_mut() {
        meta.prefs.tab = Tab::Btc;
    }
    assert!(
        controls(&h.app.items())
            .iter()
            .any(|ctl| ctl.text.contains("[YubiKey]"))
    );
    if let Some(meta) = h.app.meta.as_mut() {
        meta.prefs.tab = Tab::Evm;
    }

    // An approved Sepolia transfer of YubiKey EVM account 1.
    let chain = yw_core::evm::chain::sepolia();
    let tx = Eip1559Tx {
        chain_id: 11_155_111,
        nonce: 0,
        max_priority_fee_per_gas: U256::from_u64(1_000_000_000),
        max_fee_per_gas: U256::from_u64(2_000_000_000),
        gas_limit: 21_000,
        to: parse_address("0x9858EfFD232B4033E47d90003D41EC34EcaEda94").unwrap(),
        value: U256::from_u64(1_000),
        data: Vec::new(),
        access_list: Vec::new(),
    };
    let mut store = ApprovalStore::new();
    let mut approve = |source: EvmKeySource, from: Address| {
        let decoded = DecodedTx {
            call: decode_call(&chain, &tx.to, &tx.data),
            tx: tx.clone(),
        };
        let draft = yw_core::approval::build_evm_tx_request(
            ApprovalId::random().unwrap(),
            ApprovalOrigin::App,
            source,
            from,
            ApprovalKind::EvmTransaction,
            &chain,
            &decoded,
            &SimResult::skipped(),
            &yw_core::approval::ChainFacts::default(),
            Vec::new(),
            1_790_000_000_000,
        )
        .unwrap();
        let request = store.issue(draft, 0, 1_790_000_000_000).unwrap();
        store.consume(request.id, request.digest, 1).unwrap()
    };
    let info = SignInfo {
        origin: "yw-app".to_owned(),
        label: "YubiKey 보내기".to_owned(),
        role: Role::Original,
        now_unix_ms: 1_790_000_000_000,
    };
    // Runs the next queued job after checking its name.
    let run_named = |h: &mut Harness, name: &str| {
        let entry = h.app.key_queue.pop().unwrap();
        assert_eq!(entry.1.name(), name);
        let results = std::cell::RefCell::new(Vec::new());
        let signal = std::sync::Arc::clone(&h.app.lock_signal);
        step(
            &mut h.worker,
            &h.app.key_queue,
            entry,
            &|result| results.borrow_mut().push(result),
            &signal,
        );
        h.deliver(results.into_inner());
    };
    let records = |h: &Harness| {
        h.app
            .evm
            .journal
            .as_ref()
            .map_or(0, |journal| journal.records.len())
    };
    h.pump();
    let before = records(&h);

    let ticket = h.app.push_sign_waiter(SignWaiter::App);
    h.app
        .dispatch_evm_sign(ticket, approve(source, account), info.clone());
    // No signing job yet: the card step waits for the PIN (W11 bounds: OpenPGP PW1 6–127).
    assert!(h.app.key_queue.is_empty());
    let id = h.app.card_waiting_id().unwrap();
    let step = h.app.card.step.as_ref().unwrap();
    assert_eq!(crate::yubikey::pin_bounds(step.role), (6, 127));
    assert_eq!(step.touches, 1);
    assert_eq!(
        crate::yubikey::holders(&h.app.card.records, step.role),
        [7_700_011]
    );

    // Wrong PIN: the worker checks it before the approval is used; the step asks again.
    h.submit(Purpose::CardSign(id), &[b"000000"]);
    assert!(!h.app.card_waiting(id));
    run_named(&mut h, "SignEvmCard");
    assert!(h.app.card_waiting(id), "the PIN window opens again");
    assert!(
        h.app
            .card
            .step
            .as_ref()
            .and_then(|step| step.error.clone())
            .is_some_and(|error| error.contains("PIN이 틀렸습니다"))
    );
    assert_eq!(records(&h), before);
    // The right PIN signs on the card and journals the transaction.
    h.submit(Purpose::CardSign(id), &[b"123456"]);
    run_named(&mut h, "SignEvmCard");
    h.pump();
    assert!(h.app.card.step.is_none());
    assert_eq!(records(&h), before + 1);

    // Cancelling the PIN window signs nothing.
    let ticket = h.app.push_sign_waiter(SignWaiter::App);
    h.app
        .dispatch_evm_sign(ticket, approve(source, account), info.clone());
    let id = h.app.card_waiting_id().unwrap();
    h.app.on_cancel(Purpose::CardSign(id));
    assert!(h.app.card.step.is_none());
    assert!(h.app.key_queue.is_empty());
    assert_eq!(records(&h), before + 1);

    // A software account is unchanged: `SignEvm` right away, no card step.
    let derived = EvmKeySource::Derived(AccountIndex::ZERO);
    let address = parse_address("0x9858EfFD232B4033E47d90003D41EC34EcaEda94").unwrap();
    let ticket = h.app.push_sign_waiter(SignWaiter::App);
    h.app
        .dispatch_evm_sign(ticket, approve(derived, address), info);
    assert!(h.app.card.step.is_none());
    run_named(&mut h, "SignEvm");
    h.pump();

    // The wizard's entry point: a third card (SIG = EVM 2) enrolled through the App — the
    // accounts are reconciled from the slot map and the defaults to change are reported.
    {
        use yw_core::yubikey::plan::{CardSlot, KeyRole, PgpKey, PlannedSlot};
        *cards.lock().unwrap() = vec![yw_core::yubikey::mock::MockCard::new(7_700_013)];
        h.app.enrol_yubikey(crate::app_card::EnrolRequest {
            phrase: Zeroizing::new(format!("{} about", ["abandon"; 11].join(" ")).into_bytes()),
            passphrase: None,
            slots: vec![PlannedSlot::recommended(
                CardSlot::OpenPgp(PgpKey::Sig),
                KeyRole::Evm {
                    index: AccountIndex::new(2).unwrap(),
                    btc: None,
                },
            )],
            admin_pin: Zeroizing::new(b"12345678".to_vec()),
            management_key: Zeroizing::new(Vec::new()),
        });
        h.pump();
    }
    assert!(matches!(
        &h.app.card.enrol,
        Some(crate::app_card::EnrolState::Done {
            serial: 7_700_013,
            slots: 1,
            defaults,
        }) if !defaults.is_empty()
    ));
    assert_eq!(h.app.card.records.len(), 3);
    let meta = h.app.meta.as_ref().unwrap();
    assert!(
        meta.hw_accounts
            .evm
            .iter()
            .any(|account| account.index == 2)
    );
    assert_eq!(meta.hw_accounts.defaults, [7_700_013]);
    assert!(
        h.app
            .account_rows()
            .iter()
            .any(|(pref, ..)| *pref == EvmAccountPref::Hardware(2))
    );
    let _ = std::fs::remove_dir_all(&h.dir);
}

// ------------------------------------------------- YubiKey wizard (spec/10 §7, §9.3, §13)

type Cards = std::sync::Arc<std::sync::Mutex<Vec<yw_core::yubikey::mock::MockCard>>>;

/// The non-secret values the key worker hands to W08/W10 (those windows cannot open
/// headless): captured from the results before they are delivered.
#[derive(Default)]
struct YkSeen {
    words: Option<String>,
    positions: Option<[u8; 4]>,
}

/// A harness whose key worker talks to emulated cards only.
fn card_harness(tag: &str, serial: u32) -> (Harness, Cards) {
    let dir = temp_dir(tag);
    let cards: Cards = std::sync::Arc::new(std::sync::Mutex::new(vec![
        yw_core::yubikey::mock::MockCard::new(serial),
    ]));
    let worker = KeyWorker::new(&dir).with_card_source(Box::new(crate::yubikey::MockSource {
        cards: std::sync::Arc::clone(&cards),
    }));
    let app = app_at(&dir);
    app.key(crate::events::KeyJob::Load);
    let mut h = Harness {
        app,
        worker,
        dir,
        phrase: None,
        address: None,
    };
    h.pump();
    (h, cards)
}

/// [`Harness::pump`] that also records what the `YubiKey` windows would show.
fn yk_pump(h: &mut Harness, seen: &mut YkSeen) {
    use crate::workers::key::yubikey::YkOutcome;
    let mut guard = 0;
    while !h.app.key_queue.is_empty() {
        let results = h.run_one();
        for result in &results {
            match &result.outcome {
                KeyOutcome::YubiKey(YkOutcome::Words(Ok((words, _)))) => {
                    seen.words = Some(words.expose().to_owned());
                }
                KeyOutcome::YubiKey(YkOutcome::Challenge(Ok(positions))) => {
                    seen.positions = Some(*positions);
                }
                _ => {}
            }
        }
        h.deliver(results);
        guard += 1;
        assert!(guard < 200, "key jobs keep queueing each other");
    }
}

/// Every text, field value and monospace line of a screen.
fn all_text(items: &[Item]) -> Vec<String> {
    items
        .iter()
        .filter_map(|item| match item {
            Item::Title(text)
            | Item::Text(text)
            | Item::Muted(text)
            | Item::Help(text)
            | Item::Subtitle(text)
            | Item::Display(text)
            | Item::Mono(text)
            | Item::Banner(text, _)
            | Item::Field(_, text) => Some(text.clone()),
            _ => None,
        })
        .collect()
}

fn unique_ids(items: &[Item]) {
    let mut seen = std::collections::HashSet::new();
    for id in control_ids(items) {
        assert!(seen.insert(id), "id {id} twice");
    }
}

fn wizard_step(h: &Harness) -> Option<crate::app_yubikey::WizardStep> {
    h.app.card.wizard.as_ref().map(|wizard| wizard.step)
}

/// An unlocked wallet of `abandon … about` (imported) on Bitcoin mainnet.
fn about_wallet(h: &mut Harness) {
    h.submit(Purpose::ImportPassword, &[WALLET_PW]);
    h.submit(Purpose::ImportMnemonic, &[ABOUT.as_bytes()]);
    h.pump();
    h.app.on_command(ids::IMPORT_CORRECT);
    h.pump();
    h.app.on_command(ids::DONE_CONTINUE);
    h.pump();
    h.app.settings.bitcoin.enabled = true;
    h.app.settings.bitcoin.network = crate::network::BtcNet::Mainnet;
    assert!(matches!(h.app.mode, AppMode::Unlocked { .. }));
}

/// "슬롯 구성 바꾸기" and "YubiKey 비우기" (spec/10 §15).
mod yubikey_manage;

/// spec/10 §7.1-2, §7.2, §13 at the App level: Settings → `YubiKey` → the wizard with SIG = EVM 2,
/// AUT = Bitcoin P2WPKH 0 and 2 Solana accounts from index 1 → the recovery words (this vault's:
/// the same-mnemonic warning must be acknowledged) → the confirmation with every path and its
/// address (the vault's own derivation of the same paths) → the admin PIN → the emulator card →
/// the accounts in all three tabs, "다시 확인", the PIV PIN change on the card.
#[test]
#[expect(clippy::too_many_lines, reason = "one wizard walk-through")]
fn yubikey_wizard_enrols_an_existing_wallet() {
    use crate::app_sol::SolAccountId;
    use crate::app_yubikey::{WizardStep, YkPurpose};
    use crate::ui::screens_yubikey::ids as yk;
    use crate::yubikey::PinTarget;

    let (mut h, cards) = card_harness("yk-wizard", 8_800_001);
    let mut seen = YkSeen::default();
    about_wallet(&mut h);
    h.app.on_command(yk::SECTION_YUBIKEY);
    h.pump();
    assert_eq!(
        h.app.screen,
        Screen::Settings(super::SettingsSection::YubiKey)
    );
    let items = h.app.items();
    unique_ids(&items);
    assert!(has_text(
        &items,
        crate::ui::screens_yubikey::T_YK_MNEMONIC_WALLET
    ));
    h.app.on_command(yk::ENROL_START);
    assert_eq!(h.app.screen, Screen::YubiKey);
    assert_eq!(wizard_step(&h), Some(WizardStep::Plan));
    unique_ids(&h.app.items());
    // (a) SIG = EVM 2, AUT = Bitcoin P2WPKH 0 (the default), 2 Solana accounts from index 1.
    h.app.yk_set_text(yk::SIG_INDEX_EDIT, "2".to_owned());
    h.app.yk_set_text(yk::SOL_COUNT_EDIT, "2".to_owned());
    h.app.yk_set_text(yk::SOL_START_EDIT, "1".to_owned());
    // An out-of-range index is refused on the plan screen.
    h.app.yk_set_text(yk::AUT_INDEX_EDIT, "1000".to_owned());
    h.app.on_command(yk::PLAN_NEXT);
    assert_eq!(wizard_step(&h), Some(WizardStep::Plan));
    assert!(h.app.card.wizard.as_ref().unwrap().error.is_some());
    h.app.yk_set_text(yk::AUT_INDEX_EDIT, "0".to_owned());
    h.app.on_command(yk::PLAN_NEXT);
    assert_eq!(wizard_step(&h), Some(WizardStep::Confirm));
    // (b) W05 (headless: the submission) → the key worker derives the preview, no card.
    h.submit(Purpose::YubiKey(YkPurpose::Mnemonic), &[ABOUT.as_bytes()]);
    yk_pump(&mut h, &mut seen);
    assert!(!cards.lock().unwrap()[0].saw_write());
    assert!(cards.lock().unwrap()[0].log.is_empty(), "no card contact");
    let wizard = h.app.card.wizard.as_ref().unwrap();
    let preview = wizard.preview.as_ref().unwrap();
    assert!(preview.same_as_vault);
    assert_eq!(preview.plan, Ok(()));
    let items = h.app.items();
    unique_ids(&items);
    let shown = all_text(&items);
    assert!(
        shown
            .iter()
            .any(|text| text == crate::app_yubikey::T_YK_SAME)
    );
    let evm2 = yw_core::bip32::preview_evm_address(
        ABOUT,
        None,
        yw_core::bip32::path::AccountIndex::new(2).unwrap(),
    )
    .unwrap()
    .to_checksum();
    let sol = match h
        .worker
        .handle(crate::events::KeyJob::SolKeys {
            purpose: crate::events::SolKeysPurpose::Scan,
            sources: [1, 2]
                .map(|index| {
                    yw_core::slip10::SolKeySource::Standard(
                        yw_core::bip32::path::AccountIndex::new(index).unwrap(),
                    )
                })
                .to_vec(),
        })
        .pop()
    {
        Some(KeyOutcome::SolKeys(_, Ok(keys))) => keys
            .into_iter()
            .map(|(_, address)| address.to_base58())
            .collect::<Vec<_>>(),
        _ => unreachable!("vault Solana keys"),
    };
    for expected in [
        "m/44'/60'/0'/0/2",
        evm2.as_str(),
        "m/84'/0'/0'/0/0",
        "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
        "m/44'/501'/1'/0'",
        sol[0].as_str(),
        "m/44'/501'/2'/0'",
        sol[1].as_str(),
    ] {
        assert!(
            shown.iter().any(|text| text == expected),
            "{expected} not shown"
        );
    }
    // The same-mnemonic warning blocks `다음` until it is acknowledged.
    let next = |h: &Harness| ctl(&h.app.items(), yk::CONFIRM_NEXT).unwrap().enabled;
    assert!(!next(&h));
    h.app.on_command(yk::CONFIRM_NEXT);
    assert_eq!(wizard_step(&h), Some(WizardStep::Confirm));
    h.app.on_command(yk::SAME_ACK);
    assert!(next(&h));
    h.app.on_command(yk::CONFIRM_NEXT);
    assert_eq!(wizard_step(&h), Some(WizardStep::Credentials));
    unique_ids(&h.app.items());
    // (d) `가져오기` → W12 admin PIN → the card job (factory management key for PIV).
    h.app.on_command(yk::IMPORT);
    h.submit(Purpose::YubiKey(YkPurpose::AdminPin), &[b"12345678"]);
    assert_eq!(wizard_step(&h), Some(WizardStep::Running));
    yk_pump(&mut h, &mut seen);
    assert_eq!(wizard_step(&h), Some(WizardStep::Result));
    let wizard = h.app.card.wizard.as_ref().unwrap();
    let record = wizard.enrolled.as_ref().unwrap().record.clone();
    assert_eq!(record.serial, 8_800_001);
    assert_eq!(record.slots.len(), 4);
    assert!(wizard.defaults.openpgp_admin && wizard.defaults.piv_pin);
    assert_eq!(h.app.card.records, core::slice::from_ref(&record));
    let items = h.app.items();
    unique_ids(&items);
    assert!(all_text(&items).contains(&evm2));
    // The accounts of the three tabs.
    assert!(h.app.account_rows().iter().any(|(pref, _, address, path)| {
        *pref == EvmAccountPref::Hardware(2)
            && *address == evm2
            && path == "m/44'/60'/0'/0/2 (YubiKey)"
    }));
    let sol_rows: Vec<(SolAccountId, String)> = h
        .app
        .sol_account_rows()
        .into_iter()
        .map(|(id, _, address)| (id, address.to_base58()))
        .collect();
    assert!(sol_rows.contains(&(SolAccountId::Hardware(1), sol[0].clone())));
    assert!(sol_rows.contains(&(SolAccountId::Hardware(2), sol[1].clone())));
    assert!(
        h.app
            .btc_dapp_rows()
            .iter()
            .any(|row| row.entry.address == "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu")
    );
    // "다시 확인": the public keys are read again (read-only).
    cards.lock().unwrap()[0].log.clear();
    h.app.on_command(yk::RECHECK);
    yk_pump(&mut h, &mut seen);
    assert!(!cards.lock().unwrap()[0].saw_write());
    let check = h.app.card.wizard.as_ref().unwrap().check.clone().unwrap();
    assert_eq!(check.len(), 4);
    assert!(check.iter().all(|line| line.ends_with('✓')), "{check:?}");
    // §9.3: the PIV PIN and PUK changed on the card; a wrong current value is refused.
    h.app.on_command(yk::CHANGE_PIV_PIN);
    h.submit(
        Purpose::YubiKey(YkPurpose::ChangePin(PinTarget::PivPin)),
        &[b"999999", b"654321", b"654321"],
    );
    yk_pump(&mut h, &mut seen);
    assert_eq!(cards.lock().unwrap()[0].piv_pin, b"123456");
    h.submit(
        Purpose::YubiKey(YkPurpose::ChangePin(PinTarget::PivPin)),
        &[b"123456", b"654321", b"654321"],
    );
    h.submit(
        Purpose::YubiKey(YkPurpose::ChangePin(PinTarget::PivPuk)),
        &[b"12345678", b"87654321", b"87654321"],
    );
    yk_pump(&mut h, &mut seen);
    assert_eq!(cards.lock().unwrap()[0].piv_pin, b"654321");
    assert_eq!(cards.lock().unwrap()[0].piv_puk, b"87654321");
    assert!(!h.app.card.wizard.as_ref().unwrap().defaults.piv_pin);
    // `완료`: the key worker forgets the words.
    h.app.on_command(yk::FINISH);
    yk_pump(&mut h, &mut seen);
    assert!(h.app.card.wizard.is_none());
    assert_eq!(
        h.app.screen,
        Screen::Settings(super::SettingsSection::YubiKey)
    );
    let outcome = h
        .worker
        .handle(crate::events::KeyJob::YubiKey(
            crate::workers::key::yubikey::YkJob::Preview {
                mnemonic: None,
                slots: Vec::new(),
            },
        ))
        .pop();
    assert!(matches!(
        outcome,
        Some(KeyOutcome::YubiKey(
            crate::workers::key::yubikey::YkOutcome::Preview(Err(_))
        ))
    ));
    let items = h.app.items();
    unique_ids(&items);
    assert!(has_text(
        &items,
        &format!("{} (m/44'/60'/0'/0/2) — #8800001 SIG", "EVM 계정 2")
    ));
    let _ = std::fs::remove_dir_all(&h.dir);
}

/// spec/10 §3.4, §3.5, §7.1-3: on a second card the same path is refused unless it is a backup
/// copy; the "백업 복사본" of the first card's plan enrols the second emulator card; the list
/// shows both holders; removing the first card's record asks the password and keeps the
/// accounts (the copy still holds them); a card with a custom management key needs it typed;
/// "PIV 관리 키 자동 보호" stores a new key PIN-protected, "8자리 하나로 통일" sets the four PINs,
/// and the next enrolment of that card asks only the PIV PIN.
#[test]
#[expect(clippy::too_many_lines, reason = "one multi-card scenario")]
fn yubikey_backup_copy_removal_and_management_key() {
    use crate::app_yubikey::{WizardStep, YkPurpose};
    use crate::ui::screens_yubikey::ids as yk;
    use yw_core::yubikey::mock::MockCard;

    let (mut h, cards) = card_harness("yk-backup", 8_800_011);
    let mut seen = YkSeen::default();
    about_wallet(&mut h);
    h.app.on_command(yk::SECTION_YUBIKEY);
    h.pump();
    h.app.on_command(yk::ENROL_START);
    // Card A: SIG = EVM 0, AUT = none, no PIV.
    h.app.on_command(crate::ui::screens_yubikey::ids::pgp_id(
        yw_core::yubikey::plan::PgpKey::Aut,
        crate::ui::screens_yubikey::ids::PgpAction::Kind(crate::app_yubikey::PgpKind::None),
    ));
    h.app.yk_set_text(yk::SOL_COUNT_EDIT, "0".to_owned());
    h.app.on_command(yk::PLAN_NEXT);
    h.submit(Purpose::YubiKey(YkPurpose::Mnemonic), &[ABOUT.as_bytes()]);
    yk_pump(&mut h, &mut seen);
    h.app.on_command(yk::SAME_ACK);
    h.app.on_command(yk::CONFIRM_NEXT);
    h.app.on_command(yk::IMPORT);
    h.submit(Purpose::YubiKey(YkPurpose::AdminPin), &[b"12345678"]);
    yk_pump(&mut h, &mut seen);
    assert_eq!(h.app.card.records.len(), 1);
    // `다른 YubiKey 등록(백업)`: back to the plan with the copy of card A; first without it.
    h.app.on_command(yk::ANOTHER);
    assert_eq!(wizard_step(&h), Some(WizardStep::Plan));
    assert_eq!(
        h.app.card.wizard.as_ref().unwrap().backup_of,
        Some(8_800_011)
    );
    h.app.on_command(yk::BACKUP_TOGGLE);
    assert_eq!(h.app.card.wizard.as_ref().unwrap().backup_of, None);
    h.app.yk_set_text(yk::SIG_INDEX_EDIT, "0".to_owned());
    h.app.on_command(yk::PLAN_NEXT);
    yk_pump(&mut h, &mut seen);
    let preview = h.app.card.wizard.as_ref().unwrap().preview.clone().unwrap();
    assert_eq!(
        preview.plan,
        Err(yw_core::yubikey::plan::PlanError::PathOnOtherCard(
            yw_core::yubikey::plan::CardSlot::OpenPgp(yw_core::yubikey::plan::PgpKey::Sig)
        ))
    );
    h.app.on_command(yk::SAME_ACK);
    assert!(!ctl(&h.app.items(), yk::CONFIRM_NEXT).unwrap().enabled);
    assert!(has_text(&h.app.items(), "백업 복사본"));
    // The backup copy (the words are still held: no W05).
    h.app.on_command(yk::CONFIRM_BACK);
    h.app.on_command(yk::BACKUP_TOGGLE);
    h.app.on_command(yk::PLAN_NEXT);
    yk_pump(&mut h, &mut seen);
    assert_eq!(
        h.app
            .card
            .wizard
            .as_ref()
            .unwrap()
            .preview
            .as_ref()
            .unwrap()
            .plan,
        Ok(())
    );
    *cards.lock().unwrap() = vec![MockCard::new(8_800_012)];
    h.app.on_command(yk::SAME_ACK);
    h.app.on_command(yk::CONFIRM_NEXT);
    h.app.on_command(yk::IMPORT);
    h.submit(Purpose::YubiKey(YkPurpose::AdminPin), &[b"12345678"]);
    yk_pump(&mut h, &mut seen);
    assert_eq!(h.app.card.records.len(), 2);
    let role = h.app.card.records[1].slots[0].role;
    assert_eq!(
        crate::yubikey::holders(&h.app.card.records, role),
        [8_800_011, 8_800_012]
    );
    // A second copy of the same card is refused at the card (already enrolled).
    h.app.on_command(yk::ANOTHER);
    h.app.on_command(yk::PLAN_NEXT);
    yk_pump(&mut h, &mut seen);
    h.app.on_command(yk::SAME_ACK);
    h.app.on_command(yk::CONFIRM_NEXT);
    h.app.on_command(yk::IMPORT);
    cards.lock().unwrap()[0].log.clear();
    h.submit(Purpose::YubiKey(YkPurpose::AdminPin), &[b"12345678"]);
    yk_pump(&mut h, &mut seen);
    let failure = h.app.card.wizard.as_ref().unwrap().failure.clone().unwrap();
    assert!(failure.contains("이미 등록되어"), "{failure}");
    assert!(
        !cards.lock().unwrap()[0].saw_write(),
        "refused before any write"
    );
    assert_eq!(h.app.card.records.len(), 2);
    h.app.on_command(yk::WIZARD_CANCEL);
    yk_pump(&mut h, &mut seen);
    let items = h.app.items();
    assert!(has_text(&items, "#8800011 SIG, #8800012 SIG(백업)"));
    // Remove card A's record: overlay, W03 (a wrong password first), the copy keeps the account.
    h.app.on_command(yk::REMOVE_BASE);
    assert_eq!(h.app.screen, Screen::Confirm(Confirm::RemoveYubiKey));
    assert!(has_text(&h.app.items(), "다른 YubiKey에도 있어"));
    let id = h.app.card.record_ids[0];
    h.app.on_command(ids::CONFIRM_YES);
    h.submit(
        Purpose::ConfirmPassword(PasswordAction::RemoveHardwareKey(id)),
        &[WRONG],
    );
    yk_pump(&mut h, &mut seen);
    assert_eq!(h.app.card.records.len(), 2);
    h.submit(
        Purpose::ConfirmPassword(PasswordAction::RemoveHardwareKey(id)),
        &[WALLET_PW],
    );
    yk_pump(&mut h, &mut seen);
    assert_eq!(h.app.card.records.len(), 1);
    assert_eq!(h.app.card.records[0].serial, 8_800_012);
    assert!(
        h.app
            .account_rows()
            .iter()
            .any(|(pref, ..)| *pref == EvmAccountPref::Hardware(0))
    );
    // Card A again (record removed), now with PIV: change its management key first.
    {
        let mut inserted = cards.lock().unwrap();
        let mut card_a = MockCard::new(8_800_011);
        card_a.mgmt_key = vec![0x42; 24];
        *inserted = vec![card_a];
    }
    h.app.on_command(yk::ENROL_START);
    h.app.on_command(crate::ui::screens_yubikey::ids::pgp_id(
        yw_core::yubikey::plan::PgpKey::Sig,
        crate::ui::screens_yubikey::ids::PgpAction::Kind(crate::app_yubikey::PgpKind::None),
    ));
    h.app.on_command(crate::ui::screens_yubikey::ids::pgp_id(
        yw_core::yubikey::plan::PgpKey::Aut,
        crate::ui::screens_yubikey::ids::PgpAction::Kind(crate::app_yubikey::PgpKind::None),
    ));
    h.app.on_command(yk::PLAN_NEXT);
    h.submit(Purpose::YubiKey(YkPurpose::Mnemonic), &[ABOUT.as_bytes()]);
    yk_pump(&mut h, &mut seen);
    h.app.on_command(yk::SAME_ACK);
    h.app.on_command(yk::CONFIRM_NEXT);
    // The factory key no longer works on this card: nothing is written, the failure is shown.
    h.app.on_command(yk::IMPORT);
    yk_pump(&mut h, &mut seen);
    assert!(h.app.card.wizard.as_ref().unwrap().failure.is_some());
    assert_eq!(h.app.card.records.len(), 1);
    h.app.on_command(yk::RETRY);
    h.app.on_command(yk::MGMT_CUSTOM);
    h.app.on_command(yk::IMPORT);
    h.submit(
        Purpose::YubiKey(YkPurpose::ManagementKey),
        &["42".repeat(24).as_bytes()],
    );
    yk_pump(&mut h, &mut seen);
    assert_eq!(h.app.card.records.len(), 2);
    // §9.3 on the result screen ("하나씩 따로"): "PIV 관리 키 자동 보호" — a random key made on
    // this PC and stored PIN-protected on the card; the user never sees or types it. A custom
    // key the wallet does not know is refused first.
    let items = h.app.items();
    assert!(
        ctl(&items, yk::SET_PINS).is_some(),
        "unified mode by default"
    );
    assert!(ctl(&items, yk::CHANGE_MGMT).is_none());
    h.app.on_command(yk::PINS_SEPARATE);
    assert!(ctl(&h.app.items(), yk::CHANGE_MGMT).is_some());
    h.app.on_command(yk::CHANGE_MGMT);
    h.submit(Purpose::YubiKey(YkPurpose::ProtectManagement), &[b"123456"]);
    yk_pump(&mut h, &mut seen);
    assert_eq!(cards.lock().unwrap()[0].mgmt_key, [0x42; 24]);
    {
        let mut inserted = cards.lock().unwrap();
        inserted[0].mgmt_key = yw_core::yubikey::piv::DEFAULT_MANAGEMENT_KEY.to_vec();
    }
    h.app.card.wizard.as_mut().unwrap().defaults.piv_management = true;
    h.submit(Purpose::YubiKey(YkPurpose::ProtectManagement), &[b"123456"]);
    yk_pump(&mut h, &mut seen);
    {
        use yw_core::yubikey::piv::{OBJECT_PRINTED, parse_protected_key};
        let card = &cards.lock().unwrap()[0];
        assert_ne!(card.mgmt_key, yw_core::yubikey::piv::DEFAULT_MANAGEMENT_KEY);
        let stored = parse_protected_key(card.piv_object(OBJECT_PRINTED).unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(stored.as_slice(), card.mgmt_key.as_slice());
    }
    assert!(!h.app.card.wizard.as_ref().unwrap().defaults.piv_management);
    // "8자리 하나로 통일" from the factory values: PIV PIN, PUK, (key already protected:
    // skipped), OpenPGP admin and user — one value everywhere.
    h.app.on_command(yk::PINS_UNIFIED);
    h.app.on_command(yk::SET_PINS);
    h.submit(
        Purpose::YubiKey(YkPurpose::SetPins),
        &[b"", b"80808080", b"80808080"],
    );
    yk_pump(&mut h, &mut seen);
    {
        let card = &cards.lock().unwrap()[0];
        for value in [&card.piv_pin, &card.piv_puk, &card.pw3, &card.pw1] {
            assert_eq!(value.as_slice(), b"80808080");
        }
    }
    let wizard = h.app.card.wizard.as_ref().unwrap();
    assert!(!wizard.defaults.piv_pin && !wizard.defaults.openpgp_admin);
    assert!(
        wizard
            .notes
            .iter()
            .any(|note| note
                .starts_with("바꾼 것: PIV PIN, PIV PUK, OpenPGP 관리자 PIN, OpenPGP PIN.")),
        "{:?}",
        wizard.notes
    );
    // The next enrolment of this card asks only the PIV PIN for the management key.
    h.app.on_command(yk::RETRY);
    yk_pump(&mut h, &mut seen);
    assert!(h.app.card.wizard.as_ref().unwrap().management_protected());
    assert!(
        all_text(&h.app.items())
            .iter()
            .any(|text| text == "관리 키: PIN으로 보호됨 — PIV PIN만 입력")
    );
    let _ = std::fs::remove_dir_all(&h.dir);
}

/// spec/10 §7.1-1: the YubiKey-only wallet from the first-run screen — 24 new words (W08), the
/// in-memory four-word check (a wrong answer asks again), the wizard with the defaults, the card,
/// then `create_with_hardware`: no recovery words in the vault, one `YubiKey` record, the accounts
/// from the slot map; after a restart and unlock they are the same. A lock before the end wipes
/// the words in the key worker.
#[test]
#[expect(clippy::too_many_lines, reason = "one wallet-creation scenario")]
fn yubikey_only_wallet_from_the_first_run_screen() {
    use crate::app_yubikey::{WizardStep, YkPurpose};
    use crate::ui::screens_yubikey::ids as yk;
    use crate::workers::key::yubikey::{YkJob, YkOutcome};

    let (mut h, cards) = card_harness("yk-wallet", 8_800_021);
    let mut seen = YkSeen::default();
    assert_eq!(h.app.screen, Screen::FirstRun);
    let items = h.app.items();
    assert!(has_text(&items, crate::app_yubikey::T_YK_WALLET));
    // A lock in the middle wipes everything: the words are gone from the key worker.
    h.app.on_command(yk::NEW_WALLET);
    assert_eq!(h.app.screen, Screen::YubiKeyWalletIntro);
    unique_ids(&h.app.items());
    h.app.on_command(yk::NEW_WALLET_START);
    h.submit(Purpose::YubiKey(YkPurpose::NewPassword), &[WALLET_PW]);
    yk_pump(&mut h, &mut seen);
    assert!(seen.words.is_some());
    h.app.lock(LockReason::Manual);
    yk_pump(&mut h, &mut seen);
    assert!(matches!(
        h.worker
            .handle(crate::events::KeyJob::YubiKey(YkJob::Challenge))
            .pop(),
        Some(KeyOutcome::YubiKey(YkOutcome::Challenge(Err(_))))
    ));
    assert_eq!(h.app.screen, Screen::FirstRun);
    // Again, to the end.
    h.app.on_command(yk::NEW_WALLET);
    h.app.on_command(yk::NEW_WALLET_START);
    h.submit(Purpose::YubiKey(YkPurpose::NewPassword), &[WALLET_PW]);
    yk_pump(&mut h, &mut seen);
    let words: Vec<String> = seen
        .words
        .clone()
        .unwrap()
        .split(' ')
        .map(str::to_owned)
        .collect();
    assert_eq!(words.len(), 24);
    // W08's 2 s hold → the challenge (W10); a wrong answer → new positions.
    h.app.yk_hold_complete(YkPurpose::ShowWords);
    yk_pump(&mut h, &mut seen);
    let answer = |positions: [u8; 4]| -> Vec<Vec<u8>> {
        positions
            .iter()
            .map(|position| words[usize::from(*position) - 1].as_bytes().to_vec())
            .collect()
    };
    let positions = seen.positions.take().unwrap();
    let mut wrong = answer(positions);
    wrong[0] = if wrong[0] == b"zoo" {
        b"zone".to_vec()
    } else {
        b"zoo".to_vec()
    };
    let refs: Vec<&[u8]> = wrong.iter().map(Vec::as_slice).collect();
    h.submit(Purpose::YubiKey(YkPurpose::Backup), &refs);
    yk_pump(&mut h, &mut seen);
    assert!(h.app.card.wizard.is_none());
    let right = answer(seen.positions.take().unwrap());
    let refs: Vec<&[u8]> = right.iter().map(Vec::as_slice).collect();
    h.submit(Purpose::YubiKey(YkPurpose::Backup), &refs);
    yk_pump(&mut h, &mut seen);
    assert_eq!(h.app.screen, Screen::YubiKey);
    assert_eq!(wizard_step(&h), Some(WizardStep::Plan));
    assert_eq!(h.app.mode, AppMode::NoVault);
    // The defaults: SIG = EVM 0, AUT = Bitcoin P2WPKH 0, Solana 0; no W05 (the words are held).
    h.app.on_command(yk::PLAN_NEXT);
    yk_pump(&mut h, &mut seen);
    let preview = h.app.card.wizard.as_ref().unwrap().preview.clone().unwrap();
    assert!(!preview.same_as_vault);
    let paths: Vec<&str> = preview
        .lines
        .iter()
        .map(|line| line.path.as_str())
        .collect();
    assert_eq!(
        paths,
        ["m/44'/60'/0'/0/0", "m/84'/0'/0'/0/0", "m/44'/501'/0'/0'"]
    );
    h.app.on_command(yk::CONFIRM_NEXT);
    h.app.on_command(yk::IMPORT);
    h.submit(Purpose::YubiKey(YkPurpose::AdminPin), &[b"12345678"]);
    yk_pump(&mut h, &mut seen);
    assert!(matches!(h.app.mode, AppMode::Unlocked { .. }));
    let wizard = h.app.card.wizard.as_ref().unwrap();
    assert!(wizard.created && wizard.failure.is_none());
    assert!(!h.app.keys.has_mnemonic);
    assert_eq!(h.app.card.records.len(), 1);
    assert!(h.app.settings.bitcoin.enabled);
    let accounts = |h: &Harness| {
        let evm: Vec<String> = h
            .app
            .account_rows()
            .into_iter()
            .map(|(_, _, address, _)| address)
            .collect();
        let sol: Vec<String> = h
            .app
            .sol_account_rows()
            .into_iter()
            .map(|(_, _, address)| address.to_base58())
            .collect();
        let btc: Vec<String> = h
            .app
            .btc_dapp_rows()
            .into_iter()
            .map(|row| row.entry.address)
            .collect();
        (evm, sol, btc)
    };
    let before = accounts(&h);
    assert_eq!(before.0.len(), 1);
    assert_eq!(before.1.len(), 1);
    assert!(before.2.iter().any(|address| address.starts_with("bc1q")));
    let items = h.app.items();
    unique_ids(&items);
    assert!(has_text(&items, "YubiKey 지갑을 만들었습니다"));
    h.app.on_command(yk::FINISH);
    yk_pump(&mut h, &mut seen);
    assert_eq!(h.app.screen, Screen::Main);
    // The vault has no recovery words: the worker's meta load says so.
    assert!(matches!(
        h.worker.handle(crate::events::KeyJob::LoadMeta).pop(),
        Some(KeyOutcome::Meta(Ok(loaded))) if !loaded.has_mnemonic
    ));
    // Restart: a new app and worker on the same folder, unlock, the same accounts.
    h.app.lock(LockReason::Manual);
    yk_pump(&mut h, &mut seen);
    let dir = h.dir.clone();
    let worker = KeyWorker::new(&dir).with_card_source(Box::new(crate::yubikey::MockSource {
        cards: std::sync::Arc::clone(&cards),
    }));
    let mut again = Harness {
        app: app_at(&dir),
        worker,
        dir: dir.clone(),
        phrase: None,
        address: None,
    };
    again.app.settings.bitcoin.enabled = true;
    again.app.key(crate::events::KeyJob::Load);
    again.pump();
    again.submit(Purpose::Unlock, &[WALLET_PW]);
    again.pump();
    assert!(matches!(again.app.mode, AppMode::Unlocked { .. }));
    assert_eq!(accounts(&again), before);
    assert_eq!(again.app.card.records.len(), 1);
}

/// spec/10 §10 with spec/03 §11.3: the approval window's `YubiKey로 서명` badge (holders, touches)
/// is app chrome computed from the request's signer — the digested display of a `YubiKey`
/// request is the core's own and names no card; a Solana `YubiKey` recipient is `내 계정(YubiKey)`.
#[test]
fn yubikey_badge_is_chrome_and_the_solana_note() {
    use yw_core::approval::{ApprovalId, ApprovalKind, ApprovalOrigin};
    use yw_core::bip32::path::AccountIndex;
    use yw_core::vault::EvmKeySource;
    use yw_core::yubikey::plan::KeyRole;

    let (mut worker, _cards, dir, _) = crate::workers::key::tests::yubikey_wallet("badge");
    let Some(KeyOutcome::HardwareKeys(Ok(keys))) =
        worker.handle(crate::events::KeyJob::HardwareKeys).pop()
    else {
        unreachable!("records");
    };
    let records: Vec<_> = keys.into_iter().map(|key| key.record).collect();
    let role = KeyRole::Evm {
        index: AccountIndex::ZERO,
        btc: None,
    };
    assert_eq!(
        crate::app_card::card_badge(&records, role, 1),
        "YubiKey로 서명 · #7700011 · 터치 1회"
    );
    assert_eq!(
        crate::app_card::card_badge(&[], role, 3),
        "YubiKey로 서명 · 터치 3회"
    );
    let chain = yw_core::evm::chain::sepolia();
    let tx = yw_core::evm::tx::Eip1559Tx {
        chain_id: 11_155_111,
        nonce: 0,
        max_priority_fee_per_gas: U256::from_u64(1),
        max_fee_per_gas: U256::from_u64(2),
        gas_limit: 21_000,
        to: parse_address("0x9858EfFD232B4033E47d90003D41EC34EcaEda94").unwrap(),
        value: U256::from_u64(1),
        data: Vec::new(),
        access_list: Vec::new(),
    };
    let draft = yw_core::approval::build_evm_tx_request(
        ApprovalId::random().unwrap(),
        ApprovalOrigin::App,
        EvmKeySource::Hardware(AccountIndex::ZERO),
        parse_address("0x9858EfFD232B4033E47d90003D41EC34EcaEda94").unwrap(),
        ApprovalKind::EvmTransaction,
        &chain,
        &yw_core::evm::decode::DecodedTx {
            call: yw_core::evm::decode::decode_call(&chain, &tx.to, &tx.data),
            tx: tx.clone(),
        },
        &yw_core::evm::simulate::SimResult::skipped(),
        &yw_core::approval::ChainFacts::default(),
        Vec::new(),
        1_790_000_000_000,
    )
    .unwrap();
    assert_eq!(
        crate::yubikey::role_of(&draft.signer, &draft.payload),
        Some(role)
    );
    assert!(
        !draft
            .display
            .fields
            .iter()
            .any(|field| field.value.contains("YubiKey"))
            && !draft.display.title.contains("YubiKey")
    );
    // The send form's recipient note of a YubiKey Solana account.
    let (mut app, other) = unlocked_app("yk-sol-note", false);
    if let Some(meta) = app.meta.as_mut() {
        meta.hw_accounts.sol.push(crate::meta::Account {
            index: 0,
            label: "YubiKey Solana 1".to_owned(),
            address: "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk".to_owned(),
            hidden: false,
        });
        meta.prefs.tab = Tab::Sol;
    }
    app.sol.send.to_text = "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk".to_owned();
    app.sol_validate_send();
    app.screen = Screen::SolSend;
    assert!(has_text(&app.items(), "내 계정(YubiKey): YubiKey Solana 1"));
    drop(worker);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(other);
}

/// The meta an older build (2026-10-31) wrote with a new wallet: no settings snapshot, no
/// `hardware`, no token view.
fn old_build_meta(address: &str) -> String {
    format!(
        r#"{{"schema":"yw-meta/3","evm_accounts":[{{"index":0,"label":"계정 1","address":"{address}","hidden":false}}],"evm_raw_accounts":[],"sol_accounts":[],"sol_raw_accounts":[],"btc":null,"address_book":[],"connected_sites":[],"tokens":{{}},"activity":{{}},"prefs":{{"evm_account":{{"index":0}},"sol_account":0,"tab":"evm"}}}}"#
    )
}

/// 2026-11-05 field report: wallet created, `다 적었습니다` held (`backup.written_ack`), app
/// closed before the word quiz; the new build starts → S07 → unlock → `BackupPending`. S04 must
/// show at once, and its `받기` (S12) must show account 0 instead of waiting forever for a meta
/// that `BackupPending` never requested; `← 메인으로` returns to S04 (never a `Processing`
/// screen that only an `Unlocked` meta answer would leave). A wait that does not end shows
/// T-WAIT-STALLED after `WAIT_TIMEOUT_MS`.
#[test]
#[expect(clippy::too_many_lines, reason = "one field report, step by step")]
fn backup_pending_after_restart_shows_s04_and_receive() {
    use crate::app_reset::WAIT_TIMEOUT_MS;
    use crate::ui::screens_reset::T_WAIT_STALLED;

    let dir = temp_dir("bp-restart");
    {
        // The first run: create, `다 적었습니다` (the challenge is asked for), quit before the quiz.
        let mut first = Harness {
            app: app_at(&dir),
            worker: KeyWorker::new(&dir),
            dir: temp_dir("bp-restart-unused"),
            phrase: None,
            address: None,
        };
        first.app.key(crate::events::KeyJob::Load);
        first.pump();
        first.submit(Purpose::CreatePassword, &[WALLET_PW]);
        first.pump();
        assert_eq!(first.app.mode, AppMode::BackupPending);
        let address = first.address.unwrap();
        first.app.key(crate::events::KeyJob::BackupChallenge);
        first.pump();
        // The older build's meta.
        first
            .worker
            .test_write_meta_bytes(old_build_meta(&address.to_lower_hex()).as_bytes())
            .unwrap();
    }

    // The new build starts on the same folder.
    let mut again = Harness {
        app: app_at(&dir),
        worker: KeyWorker::new(&dir),
        dir,
        phrase: None,
        address: None,
    };
    again.app.key(crate::events::KeyJob::Load);
    again.pump();
    assert_eq!(again.app.screen, Screen::Locked);
    again.submit(Purpose::Unlock, &[WALLET_PW]);
    again.pump();
    assert_eq!(again.app.mode, AppMode::BackupPending);
    assert_eq!(again.app.screen, Screen::BackupPending);
    assert!(again.app.meta.is_some(), "BackupPending loads the meta");
    assert!(again.app.guard.verified, "the settings snapshot check ran");
    let items = again.app.items();
    assert!(has_text(&items, "백업 확인이 필요합니다"));
    let shown = control_ids(&items);
    for id in [
        ids::BACKUP_CHECK,
        crate::ui::screens_evm::ids::RECEIVE_OPEN,
        ids::LOCK,
        crate::ui::screens_reset::ids::RESET_OPEN,
    ] {
        assert!(shown.contains(&id), "S04 control {id}");
    }
    // S04 `받기` → S12 with account 0, no loading line.
    again
        .app
        .on_command(crate::ui::screens_evm::ids::RECEIVE_OPEN);
    again.pump();
    assert_eq!(again.app.screen, Screen::Receive);
    let items = again.app.items();
    assert!(
        !has_text(&items, "계정을 불러오는 중"),
        "{:?}",
        texts(&items)
    );
    assert!(
        items.iter().any(|item| matches!(item, Item::Qr(_))),
        "S12 shows account 0: {:?}",
        texts(&items)
    );
    // `← 메인으로` from S12: S04 again (not S10, not a Processing screen).
    again.app.on_command(ids::BACK_MAIN);
    again.pump();
    assert_eq!(again.app.screen, Screen::BackupPending);

    // The meta answer never comes (simulated): the wait times out to T-WAIT-STALLED with the
    // next steps instead of hanging; the self-heal requests a meta when none was requested.
    again.app.meta = None;
    again.app.wait = crate::app_reset::WaitWatch::default();
    again.app.set_screen(Screen::Receive);
    let now = yw_win::time::monotonic_ms();
    again.app.wait_tick(now);
    assert!(
        again.app.wait.meta_since.is_some(),
        "a missing meta is requested"
    );
    assert!(has_text(&again.app.items(), "계정을 불러오는 중"));
    // The worker is "stuck": nothing answers (`pop` blocks on an empty queue).
    while !again.app.key_queue.is_empty() {
        let _ = again.app.key_queue.pop();
    }
    let since = again.app.wait.meta_since.unwrap();
    again.app.wait_tick(since + WAIT_TIMEOUT_MS);
    assert!(again.app.wait.stalled);
    let items = again.app.items();
    assert!(has_text(&items, T_WAIT_STALLED));
    let shown = control_ids(&items);
    assert!(shown.contains(&crate::ui::screens_reset::ids::WAIT_RETRY));
    assert!(shown.contains(&ids::LOCK));
    // `다시 불러오기` → the meta arrives → the stall line goes.
    again
        .app
        .on_command(crate::ui::screens_reset::ids::WAIT_RETRY);
    again.pump();
    assert!(again.app.meta.is_some());
    again.app.wait_tick(since + WAIT_TIMEOUT_MS + 1);
    assert!(!again.app.wait.stalled);
    // A Processing screen that never ends also times out.
    again.app.set_screen(Screen::Processing("불러오는 중…"));
    let since = again.app.wait.since.unwrap();
    again.app.wait_tick(since + WAIT_TIMEOUT_MS);
    assert!(has_text(&again.app.items(), T_WAIT_STALLED));
}

/// S22 `지갑 초기화` from the lock screen without the password: the files move into
/// `reset-<UTC>`, settings and API keys stay, the app is back at S01 with no T-LEFTOVER.
#[test]
fn wallet_reset_from_the_lock_screen_returns_to_first_run() {
    use crate::ui::screens_reset::ids as reset_ids;

    let mut h = Harness::new("reset");
    h.create_and_confirm();
    std::fs::write(h.dir.join("settings.json"), b"{}").unwrap();
    h.app.lock(LockReason::Manual);
    h.pump();
    assert_eq!(h.app.screen, Screen::Locked);
    assert!(control_ids(&h.app.items()).contains(&reset_ids::RESET_OPEN));
    h.app.on_command(reset_ids::RESET_OPEN);
    assert_eq!(h.app.screen, Screen::Reset);
    let items = h.app.items();
    assert!(has_text(&items, "비밀번호를 잊었어도"));
    assert!(
        items
            .iter()
            .any(|item| matches!(item, Item::Field(_, value) if value.contains("vault.ywv")))
    );
    // The hold area stays disabled until the phrase is typed; `취소` goes back to S07.
    assert!(
        items
            .iter()
            .any(|item| matches!(item, Item::Hold { enabled: false, .. }))
    );
    h.app.reset_execute();
    assert_eq!(h.app.screen, Screen::Reset, "no phrase, no reset");
    h.app.on_command(reset_ids::RESET_CANCEL);
    assert_eq!(h.app.screen, Screen::Locked);
    h.app.on_command(reset_ids::RESET_OPEN);
    h.app.reset_phrase_changed(" 초기화 ");
    assert!(
        h.app
            .items()
            .iter()
            .any(|item| matches!(item, Item::Hold { enabled: true, .. }))
    );
    // The 2 s hold, then the reset (the hold area's rectangle is not laid out headless).
    h.app.reset.holding = Some(reset_ids::RESET_HOLD);
    let start = yw_win::time::monotonic_ms();
    h.app.reset.gate.begin(start);
    h.app.reset_hold_tick(start + 1_000);
    assert_eq!(h.app.screen, Screen::Reset, "half a hold does nothing");
    h.app.reset_hold_tick(start + 2_000);
    assert!(matches!(h.app.screen, Screen::Processing(_)));
    h.pump();
    assert_eq!(h.app.mode, AppMode::NoVault);
    assert_eq!(h.app.screen, Screen::FirstRun);
    assert!(!h.app.leftover, "files in reset-* never block S01");
    assert!(h.app.info.as_deref().unwrap_or_default().contains("reset-"));
    let folders: Vec<PathBuf> = std::fs::read_dir(&h.dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("reset-"))
        })
        .collect();
    assert_eq!(folders.len(), 1);
    assert!(folders[0].join("vault.ywv").is_file() && folders[0].join("meta.ywm").is_file());
    assert!(!h.vault_file().exists());
    assert!(
        h.dir.join("settings.json").is_file(),
        "settings stay by default"
    );
    // S01 creation works again.
    assert!(control_ids(&h.app.items()).contains(&ids::FIRST_CREATE));
}
