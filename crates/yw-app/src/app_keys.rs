//! Imported private keys in the app (spec/04 §2.18, D9): "개인키로 시작하기" (S01 third card →
//! S18 → W01 → W07 → S19 → S08), `개인키 가져오기` on the Solana and Bitcoin tabs (the EVM tab keeps
//! its `ImportPrivateKey` job), reveal and removal of imported Solana/Bitcoin keys, and the
//! key-only wallet flag (a vault without recovery words hides derivation features).

use yw_core::error::{KeyError, VaultError};
use yw_core::keyimport::{BtcScriptType, ImportChain, ImportPreview, ImportSpec};
use yw_core::secret::Zeroizing;
use yw_core::vault::RecordId;

use crate::app::{App, AppMode, Confirm, PasswordAction, Purpose, Screen};
use crate::errors::{key_code, vault_code};
use crate::events::{ImportedAccount, KeyJob};
use crate::logging::{self, Field};
use crate::meta::{BtcRawAccount, MAX_RAW_ACCOUNTS, RawAccount, SolRawAccount, Tab};
use crate::ui::secret::SecretKind;

/// "개인키로 시작하기" state (before any vault exists).
pub struct KeyStartFlow {
    /// Chosen chain.
    pub chain: ImportChain,
    /// Chosen Bitcoin script type.
    pub script: BtcScriptType,
    /// The password from W01 until the first preview moves it to the key worker.
    password: Option<Zeroizing<Vec<u8>>>,
    /// The key worker holds the password (a preview was sent; `다릅니다` keeps it).
    pub password_held: bool,
}

impl Default for KeyStartFlow {
    fn default() -> Self {
        Self {
            chain: ImportChain::Evm,
            script: BtcScriptType::P2wpkh,
            password: None,
            password_held: false,
        }
    }
}

impl core::fmt::Debug for KeyStartFlow {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("KeyStartFlow")
            .field("chain", &self.chain)
            .field("script", &self.script)
            .finish_non_exhaustive()
    }
}

impl KeyStartFlow {
    /// What is being imported.
    #[must_use]
    pub const fn spec(&self) -> ImportSpec {
        match self.chain {
            ImportChain::Evm => ImportSpec::Evm,
            ImportChain::Sol => ImportSpec::Sol,
            ImportChain::Btc => ImportSpec::Btc(self.script),
        }
    }
}

/// The address shown on S19 for confirmation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyStartView {
    /// Chain.
    pub chain: ImportChain,
    /// Full address (EVM EIP-55, Solana base58, Bitcoin as encoded).
    pub address: String,
    /// Bitcoin: script type and network name.
    pub btc: Option<(BtcScriptType, &'static str)>,
}

impl KeyStartView {
    /// The view of a preview.
    #[must_use]
    pub fn of(preview: &ImportPreview) -> Self {
        match preview {
            ImportPreview::Evm(address) => Self {
                chain: ImportChain::Evm,
                address: address.to_checksum(),
                btc: None,
            },
            ImportPreview::Sol(address) => Self {
                chain: ImportChain::Sol,
                address: address.to_base58(),
                btc: None,
            },
            ImportPreview::Btc(info) => Self {
                chain: ImportChain::Btc,
                address: info.address.clone(),
                btc: Some((info.script, info.network.display_name())),
            },
        }
    }
}

/// Imported-key UI state.
#[derive(Debug)]
pub struct KeysUi {
    /// "개인키로 시작하기".
    pub start: KeyStartFlow,
    /// `false` for a key-only wallet (from `MetaLoaded`; `true` until meta is read).
    pub has_mnemonic: bool,
    /// Script type for `개인키 가져오기` on the Bitcoin tab.
    pub btc_script: BtcScriptType,
    /// The imported Solana/Bitcoin key being revealed or removed.
    pub target: Option<RecordId>,
    /// S08 follows "개인키로 시작하기".
    pub done_start: bool,
}

impl Default for KeysUi {
    fn default() -> Self {
        Self {
            start: KeyStartFlow::default(),
            has_mnemonic: true,
            btc_script: BtcScriptType::P2wpkh,
            target: None,
            done_start: false,
        }
    }
}

/// Steps of "개인키로 시작하기" (S18 → W01 → W07 → S19).
pub const KEY_START_STEPS: [&str; 3] = ["비밀번호 정하기", "개인키 입력", "주소 확인"];

impl App {
    /// The wallet has no recovery words (spec/02 §4.6).
    #[must_use]
    pub const fn key_only(&self) -> bool {
        !self.keys.has_mnemonic
    }

    /// Imported keys of every chain (meta lists).
    #[must_use]
    pub fn imported_count(&self) -> usize {
        self.meta.as_ref().map_or(0, |meta| {
            meta.evm_raw_accounts
                .len()
                .saturating_add(meta.sol_raw_accounts.len())
                .saturating_add(meta.btc_raw_accounts.len())
        })
    }

    /// An imported key may be removed: a mnemonic wallet always, a key-only wallet while it
    /// keeps at least one other key (`LastKey`).
    #[must_use]
    pub fn can_remove_imported(&self) -> bool {
        self.keys.has_mnemonic || self.imported_count() > 1
    }

    /// Imported keys of `chain` (meta list length).
    #[must_use]
    pub fn imported_of(&self, chain: ImportChain) -> usize {
        self.meta.as_ref().map_or(0, |meta| match chain {
            ImportChain::Evm => meta.evm_raw_accounts.len(),
            ImportChain::Sol => meta.sol_raw_accounts.len(),
            ImportChain::Btc => meta.btc_raw_accounts.len(),
        })
    }

    /// `개인키 가져오기` is available (unlocked, below the per-chain cap of 15).
    #[must_use]
    pub fn can_import(&self, chain: ImportChain) -> bool {
        matches!(self.mode, AppMode::Unlocked { .. })
            && !self.passphrase_unverified()
            && self.imported_of(chain) < MAX_RAW_ACCOUNTS
    }

    /// Opens W07 for `개인키 가져오기` on a chain tab.
    pub fn open_key_import(&mut self, chain: ImportChain) {
        if !self.can_import(chain) {
            return;
        }
        let kind = SecretKind::PrivateKey {
            chain,
            no_words: self.key_only(),
        };
        let purpose = match chain {
            ImportChain::Evm => Purpose::ImportKey,
            ImportChain::Sol => Purpose::ImportChainKey(ImportSpec::Sol),
            ImportChain::Btc => Purpose::ImportChainKey(ImportSpec::Btc(self.keys.btc_script)),
        };
        self.open_input(kind, purpose, false);
    }

    // ----- "개인키로 시작하기" ----------------------------------------------------------------

    /// S01 third card.
    pub fn key_start_open(&mut self) {
        self.key_start_cancel();
        self.set_screen(Screen::KeyStartIntro);
    }

    /// Leaves the flow: the worker drops any held key and password.
    pub fn key_start_cancel(&mut self) {
        if self.keys.start.password_held {
            self.key(KeyJob::DiscardKeyStart {
                keep_password: false,
            });
        }
        self.keys.start = KeyStartFlow::default();
    }

    /// S18 `시작하기`: W01 first, or straight to W07 when the worker still holds the password
    /// (after `다릅니다`).
    pub fn key_start_next(&mut self) {
        let kind = SecretKind::PrivateKey {
            chain: self.keys.start.chain,
            no_words: true,
        };
        if self.keys.start.password_held {
            self.open_input(kind, Purpose::KeyStartKey, false);
        } else {
            self.open_input(SecretKind::SetPassword, Purpose::KeyStartPassword, false);
        }
    }

    /// W01 of the flow submitted.
    pub fn key_start_password(&mut self, password: Zeroizing<Vec<u8>>) {
        self.keys.start.password = Some(password);
        self.open_input(
            SecretKind::PrivateKey {
                chain: self.keys.start.chain,
                no_words: true,
            },
            Purpose::KeyStartKey,
            false,
        );
    }

    /// W07 of the flow submitted: preview without a vault.
    pub fn key_start_key(&mut self, key: Zeroizing<Vec<u8>>) {
        self.close_secret();
        let password = if self.keys.start.password_held {
            None
        } else {
            self.keys.start.password_held = true;
            self.keys.start.password.take()
        };
        self.set_screen(Screen::Processing("확인 중…"));
        self.key(KeyJob::PreviewKeyStart {
            password,
            spec: self.keys.start.spec(),
            key,
        });
    }

    /// The preview arrived: S19, or W07 again with the parser's error.
    pub fn on_key_start_preview(&mut self, result: Result<ImportPreview, KeyError>) {
        match result {
            Ok(preview) => {
                self.set_screen(Screen::KeyStartAddress(KeyStartView::of(&preview)));
            }
            Err(error) => {
                let message = key_code(error).text();
                self.set_screen(Screen::KeyStartIntro);
                self.open_input(
                    SecretKind::PrivateKey {
                        chain: self.keys.start.chain,
                        no_words: true,
                    },
                    Purpose::KeyStartKey,
                    false,
                );
                self.with_form(|form| form.set_error(Some(message)));
            }
        }
    }

    /// S19 `맞습니다`.
    pub fn key_start_commit(&mut self) {
        self.set_screen(Screen::Processing(
            "지갑을 만드는 중입니다. 몇 초 걸립니다.",
        ));
        self.key(KeyJob::CommitKeyStart);
    }

    /// S19 `다릅니다`: back to S18 with the password kept (another key or script type).
    pub fn key_start_wrong(&mut self) {
        self.key(KeyJob::DiscardKeyStart {
            keep_password: true,
        });
        self.set_screen(Screen::KeyStartIntro);
    }

    // ----- chain-tab imports ------------------------------------------------------------------

    /// A Solana or Bitcoin key was imported (or refused).
    pub fn on_key_imported(&mut self, result: Result<ImportedAccount, VaultError>) {
        let account = match result {
            Ok(account) => account,
            Err(error) => {
                let code = vault_code(error);
                self.with_form(|form| {
                    form.set_busy(false);
                    form.set_error(Some(code.text()));
                });
                return;
            }
        };
        self.close_secret();
        if let Some(meta) = self.meta.as_mut() {
            match &account {
                ImportedAccount::Evm(id, address) => {
                    let number = meta.evm_raw_accounts.len().saturating_add(1);
                    meta.evm_raw_accounts.push(RawAccount {
                        record_id: *id.as_bytes(),
                        label: format!("가져온 계정 {number}"),
                        address: address.to_lower_hex(),
                    });
                }
                ImportedAccount::Sol(id, address) => {
                    let number = meta.sol_raw_accounts.len().saturating_add(1);
                    meta.sol_raw_accounts.push(SolRawAccount {
                        record_id: *id.as_bytes(),
                        label: format!("가져온 Solana {number}"),
                        address: address.to_base58(),
                    });
                    // The new account becomes the selected one when the tab had none.
                    if meta.sol_accounts.is_empty() && meta.sol_raw_selected.is_none() {
                        meta.sol_raw_selected = Some(*id.as_bytes());
                    }
                    meta.prefs.tab = Tab::Sol;
                }
                ImportedAccount::Btc(id, info) => {
                    let number = meta.btc_raw_accounts.len().saturating_add(1);
                    meta.btc_raw_accounts.push(BtcRawAccount {
                        record_id: *id.as_bytes(),
                        label: format!("가져온 Bitcoin {number}"),
                        address: info.address.clone(),
                        network: info.network,
                        script: info.script,
                    });
                    meta.prefs.tab = Tab::Btc;
                }
            }
        }
        let chain = match account {
            ImportedAccount::Evm(..) => "evm",
            ImportedAccount::Sol(..) => "sol",
            ImportedAccount::Btc(..) => "btc",
        };
        logging::info("app", "key.imported", &[("chain", Field::Word(chain))]);
        self.save_meta();
        self.sol.next_balance_ms = 0;
        self.refresh();
    }

    /// `개인키 보기` of an imported Solana/Bitcoin account: T-REVEAL-WARN first.
    pub fn imported_reveal(&mut self, id: [u8; 16]) {
        if matches!(self.mode, AppMode::Unlocked { .. }) {
            self.keys.target = Some(RecordId::from_bytes(id));
            self.set_screen(Screen::Confirm(Confirm::RevealImported));
        }
    }

    /// `삭제` of an imported Solana/Bitcoin account: the export-first confirmation.
    pub fn imported_remove(&mut self, id: [u8; 16]) {
        if matches!(self.mode, AppMode::Unlocked { .. }) && self.can_remove_imported() {
            self.keys.target = Some(RecordId::from_bytes(id));
            self.set_screen(Screen::Confirm(Confirm::RemoveImported));
        }
    }

    /// Overlay `계속` of [`Confirm::RevealImported`] / [`Confirm::RemoveImported`]: W03.
    pub fn imported_confirmed(&mut self, kind: Confirm) {
        let previous = self.previous_screen.clone();
        self.set_screen(previous);
        let Some(id) = self.keys.target.take() else {
            return;
        };
        let action = if kind == Confirm::RevealImported {
            PasswordAction::RevealImported(id)
        } else {
            PasswordAction::RemoveImported(id)
        };
        self.open_input(
            SecretKind::ConfirmPassword,
            Purpose::ConfirmPassword(action),
            false,
        );
    }

    /// The label and address of an imported Solana/Bitcoin record (overlay text).
    #[must_use]
    pub fn imported_target_text(&self) -> Option<(String, String)> {
        let id = *self.keys.target?.as_bytes();
        let meta = self.meta.as_ref()?;
        meta.sol_raw_accounts
            .iter()
            .find(|raw| raw.record_id == id)
            .map(|raw| (raw.label.clone(), raw.address.clone()))
            .or_else(|| {
                meta.btc_raw_accounts
                    .iter()
                    .find(|raw| raw.record_id == id)
                    .map(|raw| (raw.label.clone(), raw.address.clone()))
            })
    }

    /// An imported key was removed from the vault: drop it from meta.
    pub fn on_imported_key_removed(&mut self, id: RecordId, chain: ImportChain) {
        self.close_secret();
        let id = *id.as_bytes();
        if let Some(meta) = self.meta.as_mut() {
            meta.evm_raw_accounts.retain(|raw| raw.record_id != id);
            meta.sol_raw_accounts.retain(|raw| raw.record_id != id);
            meta.btc_raw_accounts.retain(|raw| raw.record_id != id);
            if meta.sol_raw_selected == Some(id) {
                meta.sol_raw_selected = None;
            }
        }
        if chain == ImportChain::Sol {
            self.sol.rename = None;
        }
        let word = match chain {
            ImportChain::Evm => "evm",
            ImportChain::Sol => "sol",
            ImportChain::Btc => "btc",
        };
        logging::info("app", "key.removed", &[("chain", Field::Word(word))]);
        self.save_meta();
        self.refresh();
    }

    /// Main-window commands of this module; `false` when `id` is not one of them.
    pub fn on_keys_command(&mut self, id: u16) -> bool {
        use crate::ui::screens_keys::ids;
        if let Some(script) = ids::script_of(id) {
            if self.screen == Screen::KeyStartIntro {
                self.keys.start.script = script;
            } else {
                self.keys.btc_script = script;
            }
            self.refresh();
            return true;
        }
        if let Some((row, action)) = ids::btc_row(id) {
            let target = self
                .meta
                .as_ref()
                .and_then(|meta| meta.btc_raw_accounts.get(row))
                .map(|raw| (raw.record_id, raw.address.clone()));
            if let Some((record, address)) = target {
                match action {
                    ids::BtcRowAction::Reveal => self.imported_reveal(record),
                    ids::BtcRowAction::Remove => self.imported_remove(record),
                    ids::BtcRowAction::Copy => self.copy_plain_address(&address),
                }
            }
            return true;
        }
        match id {
            ids::FIRST_KEY => self.key_start_open(),
            ids::START_CHAIN_EVM | ids::START_CHAIN_SOL | ids::START_CHAIN_BTC => {
                self.keys.start.chain = match id {
                    ids::START_CHAIN_SOL => ImportChain::Sol,
                    ids::START_CHAIN_BTC => ImportChain::Btc,
                    _ => ImportChain::Evm,
                };
                self.refresh();
            }
            ids::START_NEXT => self.key_start_next(),
            ids::START_CORRECT => self.key_start_commit(),
            ids::START_WRONG => self.key_start_wrong(),
            ids::SOL_IMPORT => self.open_key_import(ImportChain::Sol),
            ids::BTC_IMPORT => self.open_key_import(ImportChain::Btc),
            ids::SOL_REVEAL | ids::SOL_REMOVE => {
                let selected = self.meta.as_ref().and_then(|meta| meta.sol_raw_selected);
                if let Some(record) = selected {
                    if id == ids::SOL_REVEAL {
                        self.imported_reveal(record);
                    } else {
                        self.imported_remove(record);
                    }
                }
            }
            _ => return false,
        }
        true
    }

    /// `주소 복사` of a Bitcoin imported account (an ordinary copy, spec/04 §2.8).
    fn copy_plain_address(&mut self, address: &str) {
        self.copy_text(address);
    }
}
