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
            .any(|ctl| ctl.text == "P2TR (탭루트, bc1p…)" && ctl.checked == Some(true))
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
        Item::Field(label, value) if label == "주소 형식" && value == "P2TR (탭루트, tb1p…)"
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
