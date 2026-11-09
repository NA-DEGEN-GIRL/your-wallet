//! Imported private keys in the app (spec/04 §2.18, D9): "개인키로 시작하기" (S01 third card →
//! S18 → W01 → W07 → S19 → S08), `개인키 가져오기` on the Solana and Bitcoin tabs (the EVM tab keeps
//! its `ImportPrivateKey` job), reveal and removal of imported Solana/Bitcoin keys, and the
//! key-only wallet flag (a vault without recovery words hides derivation features). An imported
//! Bitcoin key becomes a single-key account of the Bitcoin account list (`BtcMetaOp::AddImported`
//! after the vault stored it, spec/08 §3.5); its `삭제` also removes that account.

use yw_core::btc::{BtcNetwork, ScriptType};
use yw_core::error::{KeyError, VaultError};
use yw_core::evm::address::Address;
use yw_core::keyimport::{ImportChain, ImportPreview, ImportSpec};
use yw_core::secret::Zeroizing;
use yw_core::vault::RecordId;

use crate::app::{App, AppMode, Confirm, PasswordAction, Purpose, Screen};
use crate::errors::{key_code, vault_code};
use crate::events::{ImportedAccount, KeyJob};
use crate::logging::{self, Field};
use crate::meta::{EvmAccountPref, MAX_RAW_ACCOUNTS, RawAccount, SolRawAccount, Tab};
use crate::ui::secret::SecretKind;
use crate::workers::journal::btc::BtcMetaOp;

/// "개인키로 시작하기" state (before any vault exists).
pub struct KeyStartFlow {
    /// Chosen chain.
    pub chain: ImportChain,
    /// Chosen Bitcoin address type.
    pub script: ScriptType,
    /// The network of the previewed Bitcoin key (its WIF version): Bitcoin is turned on with it
    /// once the wallet exists.
    pub btc_network: Option<BtcNetwork>,
    /// The password from W01 until the first preview moves it to the key worker.
    password: Option<Zeroizing<Vec<u8>>>,
    /// The key worker holds the password (a preview was sent; `다릅니다` keeps it).
    pub password_held: bool,
}

impl KeyStartFlow {
    /// Whether a password is held here or in the key worker (with a pending key).
    #[must_use]
    pub const fn holds_secret(&self) -> bool {
        self.password.is_some() || self.password_held
    }
}

impl Default for KeyStartFlow {
    fn default() -> Self {
        Self {
            chain: ImportChain::Evm,
            script: ScriptType::P2wpkh,
            btc_network: None,
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
            // "개인키로 시작하기" offers no Zcash key (the Zcash tab imports them).
            ImportChain::Zec => ImportSpec::Zec(yw_core::zec::ZecNetwork::Mainnet),
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
    /// Bitcoin: address type and network.
    pub btc: Option<(ScriptType, BtcNetwork)>,
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
                btc: Some((info.script, info.network)),
            },
            ImportPreview::Zec(info) => Self {
                chain: ImportChain::Zec,
                address: info.address.clone(),
                btc: None,
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
    /// Address type for `개인키 가져오기` on the Bitcoin tab.
    pub btc_script: ScriptType,
    /// The Bitcoin tab's address-type chooser of `개인키 가져오기` is open (run time only).
    pub btc_import_open: bool,
    /// The imported Solana/Bitcoin key being revealed or removed.
    pub target: Option<RecordId>,
    /// The Bitcoin account on an EVM account's key being revealed (EVM index, network).
    pub btc_evm_target: Option<(u32, yw_core::btc::BtcNetwork)>,
    /// S08 follows "개인키로 시작하기".
    pub done_start: bool,
    /// Imported Zcash keys (vault tag 6, from `MetaLoaded`): the Zcash tab's "[가져온 키]" list.
    pub zec_keys: Vec<(RecordId, yw_core::keyimport::ZecKeyInfo)>,
}

impl Default for KeysUi {
    fn default() -> Self {
        Self {
            start: KeyStartFlow::default(),
            has_mnemonic: true,
            btc_script: ScriptType::P2wpkh,
            btc_import_open: false,
            target: None,
            btc_evm_target: None,
            done_start: false,
            zec_keys: Vec::new(),
        }
    }
}

/// Steps of "개인키로 시작하기" (S18 → W01 → W07 → S19).
pub const KEY_START_STEPS: [&str; 3] = ["비밀번호 정하기", "개인키 입력", "주소 확인"];

/// Imported Bitcoin keys: the single-key accounts of both networks (one per vault tag-4 record).
fn btc_imported_count(meta: &crate::meta::Meta) -> usize {
    meta.btc_accounts
        .accounts
        .iter()
        .filter(|account| account.is_imported())
        .count()
}

/// The imported Bitcoin account of vault record `id` (any network).
fn btc_imported_account(meta: &crate::meta::Meta, id: [u8; 16]) -> Option<&yw_core::btc::BtcMeta> {
    meta.btc_accounts
        .accounts
        .iter()
        .find(|account| account.id() == yw_core::btc::BtcAccountId::Imported { id })
}

impl App {
    /// The wallet has no recovery words (spec/02 §4.6).
    #[must_use]
    pub const fn key_only(&self) -> bool {
        !self.keys.has_mnemonic
    }

    /// Imported keys of every chain (meta lists; Bitcoin: the single-key accounts of both
    /// networks in `btc_accounts`, one per vault tag-4 record).
    #[must_use]
    pub fn imported_count(&self) -> usize {
        self.meta.as_ref().map_or(0, |meta| {
            meta.evm_raw_accounts
                .len()
                .saturating_add(meta.sol_raw_accounts.len())
                .saturating_add(btc_imported_count(meta))
                .saturating_add(self.keys.zec_keys.len())
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
            ImportChain::Btc => btc_imported_count(meta),
            ImportChain::Zec => self.keys.zec_keys.len(),
        })
    }

    /// `개인키 가져오기` is available (unlocked, below the per-chain cap of 15).
    #[must_use]
    pub fn can_import(&self, chain: ImportChain) -> bool {
        // A Bitcoin key also needs room in the Bitcoin account list (64 accounts, both networks),
        // and no open BTC approval (its account becomes the selected one, like `계정 추가`).
        let btc_room = chain != ImportChain::Btc
            || (!self.btc.slot
                && self.meta.as_ref().is_none_or(|meta| {
                    meta.btc_accounts.accounts.len() < yw_core::btc::meta::MAX_BTC_ACCOUNTS
                }));
        matches!(self.mode, AppMode::Unlocked { .. })
            && !self.passphrase_unverified()
            && self.imported_of(chain) < MAX_RAW_ACCOUNTS
            && btc_room
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
            ImportChain::Zec => Purpose::ImportChainKey(ImportSpec::Zec(self.zec_network())),
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
                let view = KeyStartView::of(&preview);
                self.keys.start.btc_network = view.btc.map(|(_, network)| network);
                self.set_screen(Screen::KeyStartAddress(view));
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
                    let label = crate::meta::next_imported_label(
                        crate::meta::EVM_IMPORTED_PREFIX,
                        meta.evm_raw_accounts.iter().map(|raw| raw.label.as_str()),
                    );
                    meta.evm_raw_accounts.push(RawAccount {
                        record_id: *id.as_bytes(),
                        label,
                        address: address.to_lower_hex(),
                    });
                }
                ImportedAccount::Sol(id, address) => {
                    let label = crate::meta::next_imported_label(
                        crate::meta::SOL_IMPORTED_PREFIX,
                        meta.sol_raw_accounts.iter().map(|raw| raw.label.as_str()),
                    );
                    meta.sol_raw_accounts.push(SolRawAccount {
                        record_id: *id.as_bytes(),
                        label,
                        address: address.to_base58(),
                    });
                    // The new account becomes the selected one when the tab had none.
                    if meta.sol_accounts.is_empty() && meta.sol_raw_selected.is_none() {
                        meta.sol_raw_selected = Some(*id.as_bytes());
                    }
                    meta.prefs.tab = Tab::Sol;
                }
                ImportedAccount::Btc(..) => meta.prefs.tab = Tab::Btc,
                ImportedAccount::Zec(..) => meta.prefs.tab = Tab::Zec,
            }
        }
        if let ImportedAccount::Zec(id, info) = &account {
            // The Zcash tab lists it ("[가져온 키]") and uses it for the account of its network
            // unless a transaction of the current account is still in flight.
            self.keys.zec_keys.push((*id, info.clone()));
            self.zec_imported(info);
        }
        if let ImportedAccount::Btc(id, info) = &account {
            // The key worker adds the single-key account (stored and selected) to meta
            // `btc_accounts`; the account list shows it with balance, receive and send.
            match info.account_key(*id.as_bytes()) {
                Ok(key) => self.key(KeyJob::BtcMeta {
                    op: BtcMetaOp::AddImported {
                        network: info.network,
                        key,
                    },
                }),
                Err(_) => logging::warn("app", "btc.imported_account_invalid", &[]),
            }
            let settings_net = crate::btc::core_network(self.settings.bitcoin.network);
            if info.network != settings_net {
                self.info = Some(format!(
                    "가져온 키는 {} 키입니다. 지금 Bitcoin 네트워크가 {}라 계정 목록에 보이지 않습니다. 설정 → Bitcoin에서 네트워크를 바꾸면 보입니다.",
                    info.network.display_name(),
                    settings_net.display_name()
                ));
            }
        }
        let chain = match account {
            ImportedAccount::Evm(..) => "evm",
            ImportedAccount::Sol(..) => "sol",
            ImportedAccount::Btc(..) => "btc",
            ImportedAccount::Zec(..) => "zec",
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
            self.keys.btc_evm_target = None;
            self.set_screen(Screen::Confirm(Confirm::RevealImported));
        }
    }

    /// `개인키 보기` of a Bitcoin account on an EVM account's key (spec/08 §3.5): the same
    /// T-REVEAL-WARN and password, then its WIF.
    pub fn btc_evm_shared_reveal(&mut self, evm_index: u32, network: yw_core::btc::BtcNetwork) {
        if matches!(self.mode, AppMode::Unlocked { .. }) {
            self.keys.target = None;
            self.keys.btc_evm_target = Some((evm_index, network));
            self.set_screen(Screen::Confirm(Confirm::RevealImported));
        }
    }

    /// `삭제` of an imported Solana/Bitcoin account: the export-first confirmation. An imported
    /// Bitcoin key is kept while a BTC approval is open or its account has an in-flight
    /// transaction (tracking and fee bumps need the account), with the reason shown.
    pub fn imported_remove(&mut self, id: [u8; 16]) {
        if !matches!(self.mode, AppMode::Unlocked { .. }) || !self.can_remove_imported() {
            return;
        }
        if let Some(reason) = self.zec_remove_block(id) {
            self.zec.error = Some(reason.to_owned());
            self.refresh();
            return;
        }
        let is_btc = self
            .meta
            .as_ref()
            .is_some_and(|meta| btc_imported_account(meta, id).is_some());
        if is_btc && let Some(reason) = self.btc_ctx().remove_block(id, self.btc.slot) {
            self.btc.account_message = Some(reason.to_owned());
            self.refresh();
            return;
        }
        self.keys.target = Some(RecordId::from_bytes(id));
        self.set_screen(Screen::Confirm(Confirm::RemoveImported));
    }

    /// The worker refused `삭제` of an imported Bitcoin or Zcash key (an in-flight transaction
    /// appeared meanwhile, or a Zcash key's records cannot be checked): the password form shows
    /// why, nothing was removed.
    pub fn on_imported_key_busy(&mut self, id: RecordId) {
        let zec = self.keys.zec_keys.iter().any(|(record, _)| *record == id);
        let text = if zec {
            self.zec_remove_block(*id.as_bytes())
                .unwrap_or(crate::app_zec::ZEC_REMOVE_BUSY)
        } else {
            crate::app_btc::REMOVE_BUSY_IN_FLIGHT
        };
        self.with_form(|form| {
            form.set_busy(false);
            form.set_error(Some(text.to_owned()));
        });
    }

    /// Overlay `계속` of [`Confirm::RevealImported`] / [`Confirm::RemoveImported`]: W03.
    pub fn imported_confirmed(&mut self, kind: Confirm) {
        let previous = self.previous_screen.clone();
        self.set_screen(previous);
        if kind == Confirm::RevealImported
            && let Some((evm_index, network)) = self.keys.btc_evm_target.take()
        {
            self.open_input(
                SecretKind::ConfirmPassword,
                Purpose::ConfirmPassword(PasswordAction::RevealBtcEvmShared { evm_index, network }),
                false,
            );
            return;
        }
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

    /// The label and address of an imported EVM/Solana/Bitcoin record (overlay text; a Bitcoin
    /// key: its account name and address). Labels can repeat (a rename), so the address is
    /// always shown with it.
    #[must_use]
    pub fn imported_target_text(&self) -> Option<(String, String)> {
        let meta = self.meta.as_ref()?;
        if self.keys.btc_evm_target.is_some() {
            // The selected account of the Bitcoin list (the one `개인키 보기` was pressed for).
            let ctx = self.btc_ctx();
            let account = ctx
                .btc_meta()
                .filter(|account| account.account().is_evm_shared())?;
            let address = account
                .address(yw_core::bip32::path::BtcChain::Receive, 0)
                .ok()?;
            return Some((
                crate::app_btc::account_label(account.account()),
                address.as_str().to_owned(),
            ));
        }
        let id = *self.keys.target?.as_bytes();
        meta.evm_raw_accounts
            .iter()
            .find(|raw| raw.record_id == id)
            .map(|raw| (raw.label.clone(), raw.address.clone()))
            .or_else(|| {
                meta.sol_raw_accounts
                    .iter()
                    .find(|raw| raw.record_id == id)
                    .map(|raw| (raw.label.clone(), raw.address.clone()))
            })
            .or_else(|| {
                let account = btc_imported_account(meta, id)?;
                let address = account
                    .address(yw_core::bip32::path::BtcChain::Receive, 0)
                    .ok()?;
                Some((
                    crate::app_btc::account_label(account.account()),
                    address.as_str().to_owned(),
                ))
            })
            .or_else(|| {
                let (_, info) = self
                    .keys
                    .zec_keys
                    .iter()
                    .find(|(record, _)| *record.as_bytes() == id)?;
                Some((
                    format!("Zcash 가져온 키 ({})", info.network.display_name()),
                    info.address.clone(),
                ))
            })
    }

    /// The EVM tab's imported key `id` was removed from the vault (`remove_evm_raw_key`): its
    /// address leaves the dApp grants unless another visible account still has it — a derived,
    /// added-phrase or `YubiKey` account whose private key was imported (spec/02 §8.4) stays,
    /// and so do its site connections — then the key leaves meta.
    pub(crate) fn on_evm_raw_key_removed(&mut self, id: RecordId) {
        self.close_secret();
        let record = *id.as_bytes();
        let removed: Vec<Address> = self
            .meta
            .as_ref()
            .and_then(|meta| {
                meta.evm_raw_accounts
                    .iter()
                    .find(|raw| raw.record_id == record)
            })
            .and_then(|raw| yw_core::evm::address::parse_address(&raw.address).ok())
            .into_iter()
            .collect();
        self.evm_key_removed_from_sites(&removed, |pref| pref == EvmAccountPref::Record(record));
        if let Some(meta) = self.meta.as_mut() {
            meta.evm_raw_accounts.retain(|raw| raw.record_id != record);
            if meta.prefs.evm_account == EvmAccountPref::Record(record) {
                meta.prefs.evm_account = EvmAccountPref::Index(0);
            }
        }
        logging::info("app", "rawkey.removed", &[]);
        self.save_meta();
        self.refresh();
    }

    /// An imported key was removed from the vault: drop it from meta (an imported Bitcoin key's
    /// account is dropped by the key worker, which owns meta `btc_accounts`).
    pub fn on_imported_key_removed(&mut self, id: RecordId, chain: ImportChain) {
        self.close_secret();
        let id = *id.as_bytes();
        let sol_removed = self.meta.as_ref().and_then(|meta| {
            let raw = meta
                .sol_raw_accounts
                .iter()
                .find(|raw| raw.record_id == id)?;
            yw_core::sol::SolAddress::parse(&raw.address).ok()
        });
        if let Some(meta) = self.meta.as_mut() {
            meta.evm_raw_accounts.retain(|raw| raw.record_id != id);
            meta.sol_raw_accounts.retain(|raw| raw.record_id != id);
            if meta.sol_raw_selected == Some(id) {
                meta.sol_raw_selected = None;
            }
        }
        if chain == ImportChain::Sol {
            self.sol.rename = None;
        }
        if chain == ImportChain::Zec {
            self.zec_imported_removed(id);
        }
        let word = match chain {
            ImportChain::Evm => "evm",
            ImportChain::Sol => "sol",
            ImportChain::Btc => "btc",
            ImportChain::Zec => "zec",
        };
        logging::info("app", "key.removed", &[("chain", Field::Word(word))]);
        self.save_meta();
        // Its Solana connections go with it (an imported Bitcoin key's: `btc_meta_replaced`).
        if let Some(address) = sol_removed {
            self.sol_account_removed_from_sites(&address.to_bytes());
        }
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
            ids::BTC_IMPORT => {
                self.keys.btc_import_open = true;
                self.refresh();
            }
            ids::BTC_IMPORT_CANCEL => {
                self.keys.btc_import_open = false;
                self.refresh();
            }
            ids::BTC_IMPORT_NEXT => {
                self.keys.btc_import_open = false;
                self.open_key_import(ImportChain::Btc);
            }
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
            ids::BTC_REVEAL | ids::BTC_REMOVE => {
                // The selected account of the Bitcoin list, when it is an imported key (or, for
                // `개인키 보기` only, an account on an EVM account's key).
                let evm_shared = self.btc_ctx().selected_evm_shared();
                if let Some(record) = self.btc_ctx().selected_imported() {
                    if id == ids::BTC_REVEAL {
                        self.imported_reveal(record);
                    } else {
                        self.imported_remove(record);
                    }
                } else if let Some((evm_index, network)) = evm_shared
                    && id == ids::BTC_REVEAL
                {
                    self.btc_evm_shared_reveal(evm_index, network);
                }
            }
            _ => return false,
        }
        true
    }
}
