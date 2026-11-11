//! Block explorer links on the UI thread (2026-11-11, spec/04 §2.6, §2.11 "블록 탐색기",
//! §2.14): the templates in use per network ([`App::explorer_templates`]), the URL helpers other
//! screens call ([`App::explorer_tx_url`], [`App::open_explorer_tx`],
//! [`App::explorer_address_url`], [`App::open_explorer_address`]), the commands of the
//! `탐색기에서 열기` / `탐색기 링크 복사` / `탐색기에서 주소 보기` buttons and the S15 card's
//! edit form.
//!
//! A URL is built only from a validated template and a value of the network's character set
//! (`crate::explorer::build_url`) and opened with `%SystemRoot%\explorer.exe <url>` like a
//! folder (§2.14) — no shell API, no `cmd.exe`. The log names only the network.

use std::path::PathBuf;

use crate::app::App;
use crate::explorer::{
    self, ExplorerNet, ExplorerOverride, LinkKind, Templates, validate_template,
};
use crate::logging::{self, Field};
use crate::network::{NetworkId, SolCluster};
use crate::ui::screens_explorer::ids;

/// The information band when a network has no template of that kind.
pub const T_EXPLORER_NONE: &str = "이 네트워크에는 탐색기 주소가 없습니다. 설정 → 네트워크(RPC) → 블록 탐색기에서 넣을 수 있습니다.";
/// The band when `explorer.exe` could not be started.
pub const T_EXPLORER_FAILED: &str =
    "브라우저를 열지 못했습니다. '탐색기 링크 복사'로 주소를 복사해 브라우저에 붙여넣으세요.";

const TEXT_MAX: usize = 512;

/// How a link is opened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Launcher {
    /// `%SystemRoot%\explorer.exe <url>` (the default browser; spec/04 §2.14).
    System,
    /// Tests: the URLs that would have been opened, in order (no browser starts).
    Record(Vec<String>),
}

impl Default for Launcher {
    fn default() -> Self {
        if cfg!(test) {
            Self::Record(Vec::new())
        } else {
            Self::System
        }
    }
}

impl Launcher {
    /// Opens `url` (already built by `explorer::build_url`); `false` when the process did not
    /// start.
    fn launch(&mut self, url: &str) -> bool {
        match self {
            Self::System => {
                let root = std::env::var_os("SystemRoot")
                    .map_or_else(|| PathBuf::from("C:\\Windows"), PathBuf::from);
                std::process::Command::new(root.join("explorer.exe"))
                    .arg(url)
                    .spawn()
                    .is_ok()
            }
            Self::Record(urls) => {
                urls.push(url.to_owned());
                true
            }
        }
    }
}

/// The S15 card's state and the launcher.
#[derive(Debug, Default)]
pub struct ExplorerUi {
    /// The row whose `변경` form is open.
    pub editing: Option<ExplorerNet>,
    /// Its transaction template field.
    pub tx_text: String,
    /// Its address template field.
    pub address_text: String,
    /// What `저장` refused (under the form).
    pub message: Option<String>,
    /// How links are opened (tests record them).
    pub launcher: Launcher,
}

fn offset(id: u16, base: u16, span: u16) -> Option<u16> {
    id.checked_sub(base).filter(|offset| *offset < span)
}

/// The app's Solana cluster of a core cluster (the send result keeps the core one).
#[must_use]
pub const fn app_cluster(cluster: yw_core::sol::SolCluster) -> SolCluster {
    match cluster {
        yw_core::sol::SolCluster::Mainnet => SolCluster::Mainnet,
        yw_core::sol::SolCluster::Devnet => SolCluster::Devnet,
    }
}

impl App {
    /// A user chain's own `explorer` base (its default; spec/04 §2.17).
    fn user_chain_explorer(&self, net: ExplorerNet) -> Option<&str> {
        let ExplorerNet::Evm(chain_id) = net else {
            return None;
        };
        self.settings
            .evm_chains
            .iter()
            .find(|chain| chain.chain_id == chain_id)
            .and_then(|chain| chain.explorer.as_deref())
    }

    /// The default templates of a network (built-in, or a user chain's `explorer`).
    #[must_use]
    pub fn explorer_default_templates(&self, network: impl Into<ExplorerNet>) -> Templates {
        let net = network.into();
        explorer::defaults(net, self.user_chain_explorer(net))
    }

    /// The user's override of a network, if any.
    #[must_use]
    pub fn explorer_override(&self, network: impl Into<ExplorerNet>) -> Option<&ExplorerOverride> {
        let net = network.into();
        self.settings
            .explorers
            .iter()
            .find(|entry| entry.net == net)
    }

    /// The templates in use: the override of each kind, else the default.
    #[must_use]
    pub fn explorer_templates(&self, network: impl Into<ExplorerNet>) -> Templates {
        let net = network.into();
        explorer::effective(
            &self.explorer_default_templates(net),
            self.explorer_override(net),
        )
    }

    /// The `kind` URL of `value` on `network` (`None`: no template, or a value outside the
    /// network's character set).
    #[must_use]
    pub fn explorer_url(
        &self,
        network: impl Into<ExplorerNet>,
        kind: LinkKind,
        value: &str,
    ) -> Option<String> {
        let net = network.into();
        let templates = self.explorer_templates(net);
        explorer::build_url(templates.get(kind)?, net, kind, value)
    }

    /// The transaction page of `hash` (EVM/`HyperCore` `0x…`, Solana base58 signature,
    /// Bitcoin/Zcash display txid). `network` is a `NetworkId` or an `ExplorerNet`.
    #[must_use]
    pub fn explorer_tx_url(&self, network: impl Into<ExplorerNet>, hash: &str) -> Option<String> {
        self.explorer_url(network, LinkKind::Tx, hash)
    }

    /// The address page of `address`.
    #[must_use]
    pub fn explorer_address_url(
        &self,
        network: impl Into<ExplorerNet>,
        address: &str,
    ) -> Option<String> {
        self.explorer_url(network, LinkKind::Address, address)
    }

    /// `탐색기에서 열기` of a transaction.
    pub fn open_explorer_tx(&mut self, network: impl Into<ExplorerNet>, hash: &str) {
        self.open_explorer(network.into(), LinkKind::Tx, hash);
    }

    /// `탐색기에서 주소 보기`.
    pub fn open_explorer_address(&mut self, network: impl Into<ExplorerNet>, address: &str) {
        self.open_explorer(network.into(), LinkKind::Address, address);
    }

    /// `탐색기 링크 복사` of a transaction (the same URL `탐색기에서 열기` opens).
    pub fn copy_explorer_tx(&mut self, network: impl Into<ExplorerNet>, hash: &str) {
        if let Some(url) = self.explorer_tx_url(network, hash) {
            self.copy_text(&url);
        } else {
            self.info = Some(T_EXPLORER_NONE.to_owned());
            self.refresh();
        }
    }

    fn open_explorer(&mut self, net: ExplorerNet, kind: LinkKind, value: &str) {
        let Some(url) = self.explorer_url(net, kind, value) else {
            self.info = Some(T_EXPLORER_NONE.to_owned());
            self.refresh();
            return;
        };
        let ok = self.explorer_ui.launcher.launch(&url);
        let net_field = match (net.network_id(), net) {
            (Some(id), _) => Field::Net(id),
            (None, ExplorerNet::HyperCore(network)) => {
                Field::Word(ExplorerNet::hypercore_word(network))
            }
            (None, _) => Field::Word("?"),
        };
        // The network only: never the URL, the hash or the address.
        logging::info(
            "app",
            "explorer.open",
            &[
                ("net", net_field),
                ("ok", Field::Word(if ok { "yes" } else { "no" })),
            ],
        );
        self.info = Some(if ok {
            explorer::url_host(&url).map_or_else(
                || "브라우저에서 탐색기를 열었습니다.".to_owned(),
                |host| {
                    format!(
                        "브라우저에서 {host} 페이지를 열었습니다. 주소창의 사이트 이름이 맞는지 확인하세요."
                    )
                },
            )
        } else {
            T_EXPLORER_FAILED.to_owned()
        });
        self.refresh();
    }

    /// The networks of the S15 card, in order: every registered EVM chain, Solana, Bitcoin and
    /// Zcash (the RPC list's order), then `HyperCore`.
    #[must_use]
    pub fn explorer_networks(&self) -> Vec<ExplorerNet> {
        let mut networks: Vec<ExplorerNet> = self
            .url_networks()
            .into_iter()
            .map(ExplorerNet::from)
            .collect();
        networks.push(ExplorerNet::HyperCore(
            yw_core::hypercore::HcNetwork::Mainnet,
        ));
        networks.push(ExplorerNet::HyperCore(
            yw_core::hypercore::HcNetwork::Testnet,
        ));
        networks.truncate(usize::from(ids::ROW_SPAN / ids::ROW_STRIDE));
        networks
    }

    /// The display name of a card row.
    #[must_use]
    pub fn explorer_net_name(&self, net: ExplorerNet) -> String {
        match (net.network_id(), net) {
            (Some(id), _) => self.network_name(id),
            (None, ExplorerNet::HyperCore(network)) => format!("Hyperliquid {}", network.label()),
            (None, _) => net.to_string(),
        }
    }

    /// `EN_CHANGE` of the card's fields; `false` when `id` is not one of them.
    pub fn on_explorer_edit_change(&mut self, id: u16) -> bool {
        let text = || self.controls.text(id, TEXT_MAX).unwrap_or_default();
        match id {
            ids::EDIT_TX => self.explorer_ui.tx_text = text(),
            ids::EDIT_ADDRESS => self.explorer_ui.address_text = text(),
            _ => return false,
        }
        true
    }

    fn explorer_start_edit(&mut self, net: ExplorerNet) {
        let used = self.explorer_templates(net);
        self.explorer_ui.editing = Some(net);
        self.explorer_ui.tx_text = used.tx.unwrap_or_default();
        self.explorer_ui.address_text = used.address.unwrap_or_default();
        self.explorer_ui.message = None;
        self.refresh();
    }

    fn explorer_cancel_edit(&mut self) {
        self.explorer_ui.editing = None;
        self.explorer_ui.message = None;
        self.refresh();
    }

    /// Stores `entry` (or removes the network's override when `None`).
    fn explorer_store(&mut self, net: ExplorerNet, entry: Option<ExplorerOverride>) {
        let mut settings = self.settings.clone();
        match (
            settings.explorers.iter().position(|old| old.net == net),
            entry,
        ) {
            (Some(position), Some(entry)) => {
                if let Some(slot) = settings.explorers.get_mut(position) {
                    *slot = entry;
                }
            }
            (Some(position), None) => {
                settings.explorers.remove(position);
            }
            (None, Some(entry)) => settings.explorers.push(entry),
            (None, None) => return,
        }
        self.save_settings(settings, "explorers");
    }

    /// `저장` of the open form: each field empty = the default of its kind; a value equal to the
    /// default is not stored as an override.
    pub fn explorer_save_edit(&mut self) {
        let Some(net) = self.explorer_ui.editing else {
            return;
        };
        // The fields as they are now (EN_CHANGE keeps the texts across re-layouts).
        for (id, kind) in [
            (ids::EDIT_TX, LinkKind::Tx),
            (ids::EDIT_ADDRESS, LinkKind::Address),
        ] {
            if let Some(text) = self.controls.text(id, TEXT_MAX) {
                match kind {
                    LinkKind::Tx => self.explorer_ui.tx_text = text,
                    LinkKind::Address => self.explorer_ui.address_text = text,
                }
            }
        }
        let defaults = self.explorer_default_templates(net);
        let mut templates = Templates::default();
        for (kind, text) in [
            (LinkKind::Tx, self.explorer_ui.tx_text.clone()),
            (LinkKind::Address, self.explorer_ui.address_text.clone()),
        ] {
            if text.trim().is_empty() {
                continue;
            }
            let checked = match validate_template(&text, kind) {
                Ok(checked) => checked,
                Err(error) => {
                    self.explorer_ui.message = Some(format!("{}: {}", kind.label(), error.text()));
                    self.refresh();
                    return;
                }
            };
            if defaults.get(kind) == Some(checked.as_str()) {
                continue;
            }
            match kind {
                LinkKind::Tx => templates.tx = Some(checked),
                LinkKind::Address => templates.address = Some(checked),
            }
        }
        let entry =
            (templates != Templates::default()).then_some(ExplorerOverride { net, templates });
        self.explorer_ui.editing = None;
        self.explorer_ui.message = None;
        if entry.is_none() && self.explorer_override(net).is_none() {
            self.refresh();
            return;
        }
        self.explorer_store(net, entry);
        self.info = Some(format!(
            "{}의 블록 탐색기 주소를 저장했습니다.",
            self.explorer_net_name(net)
        ));
        self.refresh();
    }

    /// `기본값으로` of a row.
    fn explorer_reset(&mut self, net: ExplorerNet) {
        if self.explorer_override(net).is_none() {
            return;
        }
        if self.explorer_ui.editing == Some(net) {
            self.explorer_ui.editing = None;
            self.explorer_ui.message = None;
        }
        self.explorer_store(net, None);
        self.info = Some(format!(
            "{}의 블록 탐색기 주소를 기본값으로 되돌렸습니다.",
            self.explorer_net_name(net)
        ));
        self.refresh();
    }

    /// The account cards' `탐색기에서 주소 보기`: the address the card shows.
    fn explorer_card(&mut self, id: u16) {
        match id {
            ids::CARD_EVM => {
                if let Some((address, ..)) = self.selected_account() {
                    let network = NetworkId::Eip155(self.settings.evm_chain_id);
                    self.open_explorer_address(network, &address.to_checksum());
                }
            }
            ids::CARD_SOL => {
                if let Some((_, _, address)) = self.sol_selected() {
                    let network = NetworkId::Solana(self.settings.solana.cluster);
                    self.open_explorer_address(network, &address.to_base58());
                }
            }
            ids::CARD_BTC => {
                if let Some(address) = self.btc_card_address() {
                    let network = NetworkId::Bitcoin(self.settings.bitcoin.network);
                    self.open_explorer_address(network, &address);
                }
            }
            ids::CARD_ZEC => {
                if let Some(account) = self.zec_account()
                    && matches!(
                        self.zec_hw_state(),
                        crate::app_zec::ZecHwState::NotHardware
                            | crate::app_zec::ZecHwState::Present
                    )
                {
                    let network = NetworkId::Zcash(self.zec_network());
                    self.open_explorer_address(network, &account.address());
                }
            }
            ids::CARD_HC => {
                if let Some((address, ..)) = self.selected_account() {
                    let network = ExplorerNet::HyperCore(self.hc_network());
                    self.open_explorer_address(network, &address.to_checksum());
                }
            }
            _ => {}
        }
    }

    /// The transaction of a send result screen: `(network, hash)`.
    fn explorer_result(&self, id: u16) -> Option<(ExplorerNet, String)> {
        match id {
            ids::RESULT_EVM_OPEN | ids::RESULT_EVM_COPY => self.evm.sent.map(|sent| {
                (
                    ExplorerNet::Evm(sent.chain_id),
                    crate::app_evm::hash_text(&sent.tx_hash),
                )
            }),
            ids::RESULT_SOL_OPEN | ids::RESULT_SOL_COPY => self.sol.sent.map(|(cluster, sig)| {
                (
                    ExplorerNet::Solana(app_cluster(cluster)),
                    yw_core::codec::base58::base58_encode(&sig),
                )
            }),
            ids::RESULT_BTC_OPEN | ids::RESULT_BTC_COPY => self.btc.result.map(|txid| {
                (
                    ExplorerNet::Bitcoin(self.settings.bitcoin.network),
                    txid.to_display_hex(),
                )
            }),
            ids::RESULT_ZEC_OPEN | ids::RESULT_ZEC_COPY => self.zec.sent.map(|txid| {
                (
                    ExplorerNet::Zcash(self.zec_network()),
                    yw_core::zec::tx::txid_display(&txid),
                )
            }),
            _ => None,
        }
    }

    /// The transaction of activity row `row` of the Solana, Bitcoin or Zcash list (`base` names
    /// the list), as drawn.
    fn explorer_activity(&self, base: u16, row: usize) -> Option<(ExplorerNet, String)> {
        match base {
            ids::SOL_ACTIVITY_BASE => self.sol_activity_tx_ids().get(row).map(|tx_id| {
                (
                    ExplorerNet::Solana(self.settings.solana.cluster),
                    tx_id.clone(),
                )
            }),
            ids::BTC_ACTIVITY_BASE => {
                let ctx = self.btc_ctx();
                self.btc.activity_rows(&ctx).get(row).map(|view| {
                    (
                        ExplorerNet::Bitcoin(self.settings.bitcoin.network),
                        view.txid.clone(),
                    )
                })
            }
            ids::ZEC_ACTIVITY_BASE => self
                .zec_records()
                .iter()
                .rev()
                .nth(row)
                .map(|record| (ExplorerNet::Zcash(self.zec_network()), record.txid_hex())),
            _ => None,
        }
    }

    /// The explorer commands; `false` when `id` is not one of them.
    pub fn on_explorer_command(&mut self, id: u16) -> bool {
        match id {
            ids::SAVE => self.explorer_save_edit(),
            ids::CANCEL => self.explorer_cancel_edit(),
            ids::CARD_EVM | ids::CARD_SOL | ids::CARD_BTC | ids::CARD_ZEC | ids::CARD_HC => {
                self.explorer_card(id);
            }
            ids::RESULT_EVM_OPEN
            | ids::RESULT_SOL_OPEN
            | ids::RESULT_BTC_OPEN
            | ids::RESULT_ZEC_OPEN => {
                if let Some((net, hash)) = self.explorer_result(id) {
                    self.open_explorer_tx(net, &hash);
                }
            }
            ids::RESULT_EVM_COPY
            | ids::RESULT_SOL_COPY
            | ids::RESULT_BTC_COPY
            | ids::RESULT_ZEC_COPY => {
                if let Some((net, hash)) = self.explorer_result(id) {
                    self.copy_explorer_tx(net, &hash);
                }
            }
            other => return self.on_explorer_indexed(other),
        }
        true
    }

    fn on_explorer_indexed(&mut self, id: u16) -> bool {
        if let Some(position) = offset(id, ids::ROW_BASE, ids::ROW_SPAN) {
            let row = usize::from(position / ids::ROW_STRIDE);
            if let Some(net) = self.explorer_networks().get(row).copied() {
                if position % ids::ROW_STRIDE == 0 {
                    self.explorer_start_edit(net);
                } else {
                    self.explorer_reset(net);
                }
            }
            return true;
        }
        for (base, span) in [
            (ids::SOL_ACTIVITY_BASE, ids::SOL_ACTIVITY_SPAN),
            (ids::BTC_ACTIVITY_BASE, ids::BTC_ACTIVITY_SPAN),
            (ids::ZEC_ACTIVITY_BASE, ids::ZEC_ACTIVITY_SPAN),
        ] {
            if let Some(position) = offset(id, base, span) {
                let row = usize::from(position / ids::ACTIVITY_STRIDE);
                if let Some((net, hash)) = self.explorer_activity(base, row) {
                    if position % ids::ACTIVITY_STRIDE == 0 {
                        self.open_explorer_tx(net, &hash);
                    } else {
                        self.copy_explorer_tx(net, &hash);
                    }
                }
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use crate::apikeys::ApiKeys;
    use crate::app::{App, AppMode, Paths, Screen};
    use crate::app_explorer::Launcher;
    use crate::explorer::{EXPLORERS_KEY, ExplorerNet, ExplorerOverride, LinkKind, Templates};
    use crate::network::{NetworkId, SolCluster};
    use crate::settings::{EvmChainDef, Settings};
    use crate::ui::screens_explorer::ids;

    const HASH: &str = "0x7a329aaf9f457ef8516d5a51631fe5a75e3c12d7d71b6a73a38ce42ad352de2d";

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("yw-app-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn app(dir: &Path, settings: Settings) -> App {
        let mut app = App::new(
            Paths {
                data: dir.to_path_buf(),
                logs: dir.join("logs"),
            },
            true,
            settings,
            ApiKeys::default(),
        );
        app.mode = AppMode::Unlocked {
            alt_passphrase: false,
        };
        app.screen = Screen::Main;
        app
    }

    fn user_chain(explorer: Option<&str>) -> EvmChainDef {
        EvmChainDef {
            chain_id: 10,
            name: "Test L2".to_owned(),
            symbol: "ETH".to_owned(),
            decimals: 18,
            quicknode_subdomain: None,
            alchemy_label: None,
            explorer: explorer.map(str::to_owned),
            simulation: yw_core::evm::chain::SimulationSupport::Auto,
            genesis_hash: [7; 32],
        }
    }

    #[test]
    fn helpers_follow_user_chains_and_overrides_and_open_without_a_browser() {
        let dir = temp_dir("explorer-helpers");
        let mut settings = Settings::default();
        settings
            .evm_chains
            .push(user_chain(Some("https://scan.example")));
        let mut app = app(&dir, settings);
        assert!(matches!(app.explorer_ui.launcher, Launcher::Record(_)));
        assert_eq!(
            app.explorer_tx_url(NetworkId::Eip155(10), HASH).as_deref(),
            Some(format!("https://scan.example/tx/{HASH}").as_str())
        );
        assert_eq!(app.explorer_tx_url(NetworkId::Eip155(77), HASH), None);
        assert_eq!(app.explorer_tx_url(NetworkId::Eip155(1), "0x12/../x"), None);
        app.open_explorer_tx(NetworkId::Eip155(10), HASH);
        app.open_explorer_tx(NetworkId::Eip155(77), HASH);
        assert_eq!(
            app.info.as_deref(),
            Some(crate::app_explorer::T_EXPLORER_NONE)
        );
        app.open_explorer_address(
            ExplorerNet::HyperCore(yw_core::hypercore::HcNetwork::Testnet),
            "0xF9900bb6FF2D2C67858c3468d21c5f103C4Ff646",
        );
        assert_eq!(
            app.explorer_ui.launcher,
            Launcher::Record(vec![
                format!("https://scan.example/tx/{HASH}"),
                "https://app.hyperliquid-testnet.xyz/explorer/address/0xF9900bb6FF2D2C67858c3468d21c5f103C4Ff646"
                    .to_owned(),
            ])
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_card_stores_overrides_only_and_resets_them() {
        let dir = temp_dir("explorer-card");
        let mut app = app(&dir, Settings::default());
        let networks = app.explorer_networks();
        assert_eq!(networks.len(), 7 + 2 + 2 + 2 + 2);
        let devnet = ExplorerNet::Solana(SolCluster::Devnet);
        let row = u16::try_from(networks.iter().position(|net| *net == devnet).unwrap()).unwrap();
        let change = ids::ROW_BASE + row * ids::ROW_STRIDE;
        assert!(app.on_explorer_command(change));
        assert_eq!(app.explorer_ui.editing, Some(devnet));
        assert_eq!(
            app.explorer_ui.tx_text,
            "https://solscan.io/tx/{hash}?cluster=devnet"
        );
        // Unchanged defaults: nothing is stored.
        assert!(app.on_explorer_command(ids::SAVE));
        assert!(app.settings.explorers.is_empty());
        // A refused template keeps the form open with the reason.
        assert!(app.on_explorer_command(change));
        app.controls
            .type_text(ids::EDIT_TX, "http://explorer.example/tx/{hash}");
        assert!(app.on_explorer_command(ids::SAVE));
        assert_eq!(app.explorer_ui.editing, Some(devnet));
        assert!(
            app.explorer_ui
                .message
                .as_deref()
                .unwrap()
                .contains("https://")
        );
        assert!(app.settings.explorers.is_empty());
        // A valid one is stored as the transaction override only.
        app.controls.type_text(
            ids::EDIT_TX,
            "https://explorer.solana.com/tx/{hash}?cluster=devnet",
        );
        assert!(app.on_explorer_command(ids::SAVE));
        assert_eq!(app.explorer_ui.editing, None);
        assert_eq!(
            app.settings.explorers,
            [ExplorerOverride {
                net: devnet,
                templates: Templates {
                    tx: Some("https://explorer.solana.com/tx/{hash}?cluster=devnet".to_owned()),
                    address: None,
                },
            }]
        );
        let written = std::fs::read(dir.join("settings.json")).unwrap();
        let text = String::from_utf8(written.clone()).unwrap();
        assert!(text.contains(&format!("\"{EXPLORERS_KEY}\":{{\"solana:devnet\":")));
        assert_eq!(
            crate::settings::load(Some(&written)).settings.explorers,
            app.settings.explorers
        );
        assert_eq!(
            app.explorer_templates(devnet).get(LinkKind::Address),
            Some("https://solscan.io/account/{address}?cluster=devnet")
        );
        // 기본값으로 removes it; the key is no longer written.
        assert!(app.on_explorer_command(change + 1));
        assert!(app.settings.explorers.is_empty());
        let written = std::fs::read(dir.join("settings.json")).unwrap();
        assert!(!String::from_utf8(written).unwrap().contains(EXPLORERS_KEY));
        // Activity, result and card ids that name nothing do nothing.
        assert!(app.on_explorer_command(ids::BTC_ACTIVITY_BASE));
        assert!(app.on_explorer_command(ids::RESULT_ZEC_OPEN));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
