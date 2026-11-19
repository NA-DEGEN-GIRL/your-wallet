//! Block explorer links on the UI thread (2026-11-11, spec/04 §2.6, §2.11 "블록 탐색기",
//! §2.14): the templates in use per network ([`App::explorer_templates`]), the URL helpers other
//! screens call ([`App::explorer_tx_url`], [`App::open_explorer_tx`],
//! [`App::explorer_address_url`], [`App::open_explorer_address`]), the commands of the
//! `탐색기에서 열기` / `탐색기 링크 복사` / `탐색기에서 주소 보기` buttons and the S15 card's
//! edit form.
//!
//! A URL is built only from a validated template and a value of the network's character set
//! (`crate::explorer::build_url`) and opened with `%SystemRoot%\explorer.exe <url>` like a
//! folder (§2.14) — no shell API, no `cmd.exe`. The log names only the network. 2026-11-20
//! (S4 P3): the handlers emit `Effect::OpenUrl`; the effect executor starts the [`Launcher`] and
//! answers `Cmd::Opened` ([`App::on_opened`]).

use std::path::{Path, PathBuf};

use crate::app::App;
use crate::explorer::{
    self, ExplorerNet, ExplorerOverride, LinkKind, Templates, validate_template,
};
use crate::logging::{self, Field};
use crate::network::{NetworkId, SolCluster};
use crate::ui::screens_explorer::ids;
use yw_engine::cmd::{ExplorerLinkAction, ExplorerPress, ExplorerRowAction, LinkTarget, Row};
use yw_engine::effect::Effect;
use yw_engine::form::EditField;

/// Explorer link texts (spec/04 §2.11, §2.14; English spec/14 §5).
pub mod text {
    yw_core::texts! {
        /// The information band when a network has no template of that kind.
        EXPLORER_NONE = "이 네트워크에는 탐색기 주소가 없습니다. 설정 → 네트워크(RPC) → 블록 탐색기에서 넣을 수 있습니다."
            / "This network has no explorer address. You can add one in Settings → Networks (RPC) → Block explorer.";
        /// The band when `explorer.exe` could not be started.
        EXPLORER_FAILED = "브라우저를 열지 못했습니다. '탐색기 링크 복사'로 주소를 복사해 브라우저에 붙여넣으세요."
            / "Could not open the browser. Copy the address with 'Copy explorer link' and paste it into your browser.";
        OPENED = "브라우저에서 탐색기를 열었습니다." / "Opened the explorer in your browser.";
        OPENED_HOST(1) = "브라우저에서 {0} 페이지를 열었습니다. 주소창의 사이트 이름이 맞는지 확인하세요."
            / "Opened a {0} page in your browser. Check that the site name in the address bar is right.";
        SAVED(1) = "{0}의 블록 탐색기 주소를 저장했습니다." / "Saved the block explorer address of {0}.";
        RESET(1) = "{0}의 블록 탐색기 주소를 기본값으로 되돌렸습니다."
            / "Reset the block explorer address of {0} to the default.";
    }
}

/// How a link or a folder is opened. Only the effect executor (`app_effects`: `Effect::OpenUrl`,
/// `Effect::OpenFolder`) calls it (2026-11-20, S4 P3: before, `App::open_explorer` launched and
/// `App::open_folder` started `explorer.exe` for a folder itself, also in unit-test builds). The
/// field stays in `ExplorerUi` until the shell gets its own state (S4 W1); the census counts its
/// record (`launch N`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Launcher {
    /// `%SystemRoot%\explorer.exe <url or folder>` (the default browser or File Explorer;
    /// spec/04 §2.14).
    System,
    /// Tests: what would have been opened, in order: a URL, or a folder's path (no process
    /// starts).
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
    pub(crate) fn launch(&mut self, url: &str) -> bool {
        match self {
            Self::System => explorer_exe(url),
            Self::Record(urls) => {
                urls.push(url.to_owned());
                true
            }
        }
    }

    /// Opens the folder `path` in File Explorer (2026-11-20, S4 P3: was `App::open_folder`,
    /// which always started the process); `false` when the process did not start.
    pub(crate) fn open_folder(&mut self, path: &Path) -> bool {
        match self {
            Self::System => explorer_exe(path),
            Self::Record(opened) => {
                opened.push(path.to_string_lossy().into_owned());
                true
            }
        }
    }
}

/// `%SystemRoot%\explorer.exe <arg>` (`C:\Windows` when `SystemRoot` is not set; spec/04 §2.14);
/// whether the process started.
fn explorer_exe(arg: impl AsRef<std::ffi::OsStr>) -> bool {
    let root =
        std::env::var_os("SystemRoot").map_or_else(|| PathBuf::from("C:\\Windows"), PathBuf::from);
    std::process::Command::new(root.join("explorer.exe"))
        .arg(arg)
        .spawn()
        .is_ok()
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
            self.info = Some(text::EXPLORER_NONE.get(self.settings.language).to_owned());
            self.refresh();
        }
    }

    /// 2026-11-20 (S4 P3): the launch is `Effect::OpenUrl`, applied by the shell; its result
    /// comes back as `Cmd::Opened` ([`App::on_opened`]: the log and the band). Before, this
    /// called the launcher and went on with its `bool`. The host the band names is taken from
    /// the URL here and travels in the [`LinkTarget`].
    fn open_explorer(&mut self, net: ExplorerNet, kind: LinkKind, value: &str) {
        let Some(url) = self.explorer_url(net, kind, value) else {
            self.info = Some(text::EXPLORER_NONE.get(self.settings.language).to_owned());
            self.refresh();
            return;
        };
        let host = explorer::url_host(&url);
        self.emit(Effect::OpenUrl {
            url,
            which: LinkTarget::Explorer { net, host },
        });
    }

    /// `Cmd::Opened` (S4 P3): the `explorer.open` log line (the network only: never the URL,
    /// the host, the hash or the address), then the band (the host when the browser was started)
    /// and the repaint, as `open_explorer` did after its launch before.
    pub(crate) fn on_opened(&mut self, ok: bool, which: LinkTarget) {
        let LinkTarget::Explorer { net, host } = which;
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
        let lang = self.settings.language;
        self.info = Some(if ok {
            host.map_or_else(
                || text::OPENED.get(lang).to_owned(),
                |host| text::OPENED_HOST.fill(lang, [&host]),
            )
        } else {
            text::EXPLORER_FAILED.get(lang).to_owned()
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
            (None, ExplorerNet::HyperCore(network)) => format!(
                "Hyperliquid {}",
                yw_core::hypercore::text::network_label(self.settings.language, network)
            ),
            (None, _) => net.to_string(),
        }
    }

    /// `EN_CHANGE` of the card's fields: `text` is the field's text now (2026-11-18, S3 C3:
    /// from `Cmd::Edit`; before, a read of the edit by id); `false` when `field` is not one of
    /// them.
    pub(crate) fn on_explorer_edit(&mut self, field: EditField, text: &str) -> bool {
        match field {
            EditField::ExplorerTx => text.clone_into(&mut self.explorer_ui.tx_text),
            EditField::ExplorerAddress => text.clone_into(&mut self.explorer_ui.address_text),
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
        // The fields as they are now (EN_CHANGE keeps the texts across re-layouts; 2026-11-18,
        // S3 C3: from the form state, which equals the edits).
        for (field, kind) in [
            (EditField::ExplorerTx, LinkKind::Tx),
            (EditField::ExplorerAddress, LinkKind::Address),
        ] {
            if let Some(text) = self.form_text(field) {
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
                    let lang = self.settings.language;
                    self.explorer_ui.message =
                        Some(format!("{}: {}", kind.label_in(lang), error.text_in(lang)));
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
        self.info = Some(text::SAVED.fill(self.settings.language, [&self.explorer_net_name(net)]));
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
        self.info = Some(text::RESET.fill(self.settings.language, [&self.explorer_net_name(net)]));
        self.refresh();
    }

    /// The account cards' `탐색기에서 주소 보기`: the address the card shows.
    fn explorer_card(&mut self, press: ExplorerPress) {
        match press {
            ExplorerPress::CardEvm => {
                if let Some((address, ..)) = self.selected_account() {
                    let network = NetworkId::Eip155(self.settings.evm_chain_id);
                    self.open_explorer_address(network, &address.to_checksum());
                }
            }
            ExplorerPress::CardSol => {
                if let Some((_, _, address)) = self.sol_selected() {
                    let network = NetworkId::Solana(self.settings.solana.cluster);
                    self.open_explorer_address(network, &address.to_base58());
                }
            }
            ExplorerPress::CardBtc => {
                if let Some(address) = self.btc_card_address() {
                    let network = NetworkId::Bitcoin(self.settings.bitcoin.network);
                    self.open_explorer_address(network, &address);
                }
            }
            ExplorerPress::CardZec => {
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
            ExplorerPress::CardHc => {
                if let Some((address, ..)) = self.selected_account() {
                    let network = ExplorerNet::HyperCore(self.hc_network());
                    self.open_explorer_address(network, &address.to_checksum());
                }
            }
            _ => {}
        }
    }

    /// The transaction of a send result screen: `(network, hash)`.
    fn explorer_result(&self, press: ExplorerPress) -> Option<(ExplorerNet, String)> {
        match press {
            ExplorerPress::ResultEvmOpen | ExplorerPress::ResultEvmCopy => {
                self.evm.sent.map(|sent| {
                    (
                        ExplorerNet::Evm(sent.chain_id),
                        crate::app_evm::hash_text(&sent.tx_hash),
                    )
                })
            }
            ExplorerPress::ResultSolOpen | ExplorerPress::ResultSolCopy => {
                self.sol.sent.map(|(cluster, sig)| {
                    (
                        ExplorerNet::Solana(app_cluster(cluster)),
                        yw_core::codec::base58::base58_encode(&sig),
                    )
                })
            }
            ExplorerPress::ResultBtcOpen | ExplorerPress::ResultBtcCopy => {
                self.btc.result.map(|txid| {
                    (
                        ExplorerNet::Bitcoin(self.settings.bitcoin.network),
                        txid.to_display_hex(),
                    )
                })
            }
            ExplorerPress::ResultZecOpen | ExplorerPress::ResultZecCopy => {
                self.zec.sent.map(|txid| {
                    (
                        ExplorerNet::Zcash(self.zec_network()),
                        yw_core::zec::tx::txid_display(&txid),
                    )
                })
            }
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

    /// The explorer presses (2026-11-18, S3 C3: an `ExplorerPress`; before, the control id).
    pub(crate) fn on_explorer(&mut self, press: ExplorerPress) {
        match press {
            ExplorerPress::Save => self.explorer_save_edit(),
            ExplorerPress::Cancel => self.explorer_cancel_edit(),
            ExplorerPress::CardEvm
            | ExplorerPress::CardSol
            | ExplorerPress::CardBtc
            | ExplorerPress::CardZec
            | ExplorerPress::CardHc => {
                self.explorer_card(press);
            }
            ExplorerPress::ResultEvmOpen
            | ExplorerPress::ResultSolOpen
            | ExplorerPress::ResultBtcOpen
            | ExplorerPress::ResultZecOpen => {
                if let Some((net, hash)) = self.explorer_result(press) {
                    self.open_explorer_tx(net, &hash);
                }
            }
            ExplorerPress::ResultEvmCopy
            | ExplorerPress::ResultSolCopy
            | ExplorerPress::ResultBtcCopy
            | ExplorerPress::ResultZecCopy => {
                if let Some((net, hash)) = self.explorer_result(press) {
                    self.copy_explorer_tx(net, &hash);
                }
            }
            ExplorerPress::Row(Row(row), action) => {
                if let Some(net) = self.explorer_networks().get(usize::from(row)).copied() {
                    match action {
                        ExplorerRowAction::Edit => self.explorer_start_edit(net),
                        ExplorerRowAction::Reset => self.explorer_reset(net),
                    }
                }
            }
            ExplorerPress::SolActivity(row, action) => {
                self.explorer_activity_link(ids::SOL_ACTIVITY_BASE, row, action);
            }
            ExplorerPress::BtcActivity(row, action) => {
                self.explorer_activity_link(ids::BTC_ACTIVITY_BASE, row, action);
            }
            ExplorerPress::ZecActivity(row, action) => {
                self.explorer_activity_link(ids::ZEC_ACTIVITY_BASE, row, action);
            }
        }
    }

    /// ↗ or 🔗 of activity row `row` of the list starting at `base`.
    fn explorer_activity_link(&mut self, base: u16, Row(row): Row, action: ExplorerLinkAction) {
        if let Some((net, hash)) = self.explorer_activity(base, usize::from(row)) {
            match action {
                ExplorerLinkAction::Open => self.open_explorer_tx(net, &hash),
                ExplorerLinkAction::Copy => self.copy_explorer_tx(net, &hash),
            }
        }
    }

    /// Test adapter (S3 C3, plan §3.2): presses explorer control `id` directly, as the tests
    /// did before; `false` when `id` is not one.
    #[cfg(test)]
    pub(crate) fn on_explorer_command(&mut self, id: u16) -> bool {
        self.press_family(
            id,
            |press| match press {
                yw_engine::cmd::Press::Explorer(press) => Some(press),
                _ => None,
            },
            |app, press| {
                app.on_explorer(press);
                true
            },
        )
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

    /// The code of a Rust source without comments and without whitespace outside literals, so a
    /// call that rustfmt wraps over several lines reads as one chain (2026-11-20, S4 P3 review:
    /// the first scan cut each line at `//` and so missed wrapped calls, calls through a local
    /// binding and calls after a `"https://…"` literal). Strings, raw strings and char literals
    /// are kept as written (a `//` inside one is not a comment); a lifetime is not a literal.
    fn code_only(text: &str) -> String {
        let chars: Vec<char> = text.chars().collect();
        let at = |i: usize| chars.get(i).copied().unwrap_or('\0');
        let ident = |c: char| c.is_alphanumeric() || c == '_';
        let mut out = String::new();
        let mut i = 0;
        while i < chars.len() {
            let c = chars[i];
            if c == '/' && at(i + 1) == '/' {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            } else if c == '/' && at(i + 1) == '*' {
                let mut depth = 0_usize;
                while i < chars.len() {
                    if chars[i] == '/' && at(i + 1) == '*' {
                        depth += 1;
                        i += 2;
                    } else if chars[i] == '*' && at(i + 1) == '/' {
                        depth -= 1;
                        i += 2;
                        if depth == 0 {
                            break;
                        }
                    } else {
                        i += 1;
                    }
                }
            } else if c == 'r'
                && (i == 0
                    || !ident(chars[i - 1])
                    || (chars[i - 1] == 'b' && (i < 2 || !ident(chars[i - 2]))))
                && {
                    let mut j = i + 1;
                    while at(j) == '#' {
                        j += 1;
                    }
                    at(j) == '"'
                }
            {
                // A raw string: `r"…"`, `r#"…"#` (also after `b`).
                let begin = i;
                i += 1;
                let mut hashes = 0;
                while at(i) == '#' {
                    hashes += 1;
                    i += 1;
                }
                i += 1;
                while i < chars.len()
                    && !(chars[i] == '"' && (1..=hashes).all(|k| at(i + k) == '#'))
                {
                    i += 1;
                }
                i += 1 + hashes;
                out.extend(&chars[begin..i.min(chars.len())]);
            } else if c == '"' {
                let begin = i;
                i += 1;
                while i < chars.len() && chars[i] != '"' {
                    i += if chars[i] == '\\' { 2 } else { 1 };
                }
                i += 1;
                out.extend(&chars[begin..i.min(chars.len())]);
            } else if c == '\'' && (at(i + 1) == '\\' || at(i + 2) == '\'') {
                // A char literal (`'x'`, `'\n'`, `'\u{..}'`); a lifetime has no closing quote.
                let begin = i;
                i += if at(i + 1) == '\\' { 3 } else { 2 };
                while i < chars.len() && chars[i] != '\'' {
                    i += 1;
                }
                i += 1;
                out.extend(&chars[begin..i.min(chars.len())]);
            } else {
                if !c.is_whitespace() {
                    out.push(c);
                }
                i += 1;
            }
        }
        out
    }

    /// 2026-11-20 (S4 P3): only the effect executor (`app_effects.rs`: `Effect::OpenUrl`,
    /// `Effect::OpenFolder`) starts the launcher, and only the launcher (this file) names
    /// `explorer.exe`: no handler opens a link or a folder itself. A read-only scan of yw-app's
    /// `src` (code without comments and whitespace, [`code_only`]): every `.launch(` /
    /// `.open_folder(` call and every `::launch` / `::open_folder` path counts, whatever the
    /// receiver (2026-11-20 review: was only `launcher.launch(` / `launcher.open_folder(` within
    /// one line). `app_effects.rs` has three: `launcher.open_folder`, `launcher.launch` and the
    /// executor's own `self.open_folder` (`App::open_folder`, the shell half). It asserts that the
    /// scan sees the shapes the first scan missed and that it found its targets.
    #[test]
    fn only_the_effect_executor_starts_the_launcher() {
        fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().is_some_and(|ext| ext == "rs") {
                    out.push(path);
                }
            }
        }
        // Split so that this test's own text does not match.
        let calls = [
            [".", "launch("].concat(),
            [".", "open_folder("].concat(),
            [":", ":launch"].concat(),
            [":", ":open_folder"].concat(),
        ];
        let count = |code: &str| -> usize {
            calls
                .iter()
                .map(|pattern| code.matches(pattern.as_str()).count())
                .sum()
        };
        // The shapes the line scan missed: a wrapped chain, a local binding, a call after a URL
        // literal on the same line (and a commented-out call that must not count), a path.
        let wrapped = ["self.explorer_ui\n    .launcher\n    .", "launch(&url);"].concat();
        let bound = [
            "let l = &mut self.explorer_ui.launcher; l.",
            "open_folder(&p);",
        ]
        .concat();
        let after_url = [
            "let u = \"https://x\"; launcher.",
            "launch(u); // l.",
            "launch(u);",
        ]
        .concat();
        let path = ["let f = Launcher:", ":launch;"].concat();
        for sample in [&wrapped, &bound, &after_url, &path] {
            assert_eq!(count(&code_only(sample)), 1, "{sample}");
        }
        assert_eq!(
            code_only("/* a /* b */ c */ x // y\n'a' &'b T br#\"//\"# '\\''"),
            "x'a'&'bTbr#\"//\"#'\\''"
        );

        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        walk(&root, &mut files);
        let program = ["explorer", ".exe"].concat();
        let (mut launch_sites, mut program_sites) = (Vec::new(), Vec::new());
        for file in &files {
            let code = code_only(&std::fs::read_to_string(file).unwrap());
            let name = file
                .strip_prefix(&root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            let calls = count(&code);
            if calls > 0 {
                launch_sites.push((name.clone(), calls));
            }
            let programs = code.matches(program.as_str()).count();
            if programs > 0 {
                program_sites.push((name, programs));
            }
        }
        assert!(files.len() > 50, "{} files", files.len());
        assert_eq!(launch_sites, [("app_effects.rs".to_owned(), 3)]);
        assert_eq!(program_sites, [("app_explorer.rs".to_owned(), 1)]);
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
            Some(crate::app_explorer::text::EXPLORER_NONE.ko)
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

    /// spec/14 (2026-11-14): group B's fixed texts in English carry no Hangul — the S15
    /// explorer card and form, S17, the send-form notes, the site and extension lines — and
    /// every catalogue keeps its placeholders.
    #[test]
    #[expect(clippy::too_many_lines, reason = "one check per group B text source")]
    fn english_explorer_chain_and_site_texts() {
        use yw_core::lang::{Entry, Lang, has_hangul, placeholders};

        use crate::ui::main_window::Item;

        fn strings(items: &[Item], out: &mut Vec<String>) {
            for item in items {
                match item {
                    Item::Help(text) | Item::Banner(text, _) | Item::Title(text) => {
                        out.push(text.clone());
                    }
                    Item::CardStart(Some(text)) => out.push(text.clone()),
                    Item::LabeledRow(label, ctls) => {
                        out.push(label.clone());
                        out.extend(ctls.iter().map(|ctl| ctl.text.clone()));
                    }
                    Item::Row(ctls) => out.extend(ctls.iter().map(|ctl| ctl.text.clone())),
                    Item::Badged(_, inner) => strings(core::slice::from_ref(&**inner), out),
                    _ => {}
                }
            }
        }

        let dir = temp_dir("explorer-english");
        let mut settings = Settings {
            language: Lang::En,
            ..Settings::default()
        };
        settings
            .evm_chains
            .push(user_chain(Some("https://scan.example")));
        let mut app = app(&dir, settings);
        let mut items = Vec::new();
        app.explorer_settings_card(&mut items);
        app.open_chain_form(None);
        app.chain_edit_screen(&mut items);
        let mut texts = Vec::new();
        strings(&items, &mut texts);
        assert!(texts.len() > 20, "{texts:?}");
        for text in &texts {
            assert!(!has_hangul(text), "{text}");
        }
        let notes = [
            crate::flow::evm::form::AddressNote::SameAsSender,
            crate::flow::evm::form::AddressNote::Book {
                name: "Alice".to_owned(),
                verified: true,
            },
            crate::flow::evm::form::AddressNote::LookAlike {
                name: "Alice".to_owned(),
                history: false,
                prefix: 3,
                suffix: 4,
            },
            crate::flow::evm::form::AddressNote::NotInBook,
            crate::flow::evm::form::AddressNote::Contract,
        ];
        let mut lines: Vec<String> = notes.iter().map(|note| note.text_in(Lang::En)).collect();
        lines.push(crate::app_book::look_alike_note(
            Lang::En,
            &crate::app_book::Resembles::Sent("0x5290".to_owned()),
        ));
        lines.push(crate::app_browser::status_text(Lang::En, None));
        lines.push(crate::explorer::TemplateError::Placeholder(LinkKind::Tx).text_in(Lang::En));
        lines.push(app.unlock_pending_text().unwrap_or_default());
        lines.push(
            crate::app_extension::ExtensionStatus::Never
                .text_in(Lang::En)
                .to_owned(),
        );
        for line in &lines {
            assert!(!has_hangul(line), "{line}");
        }
        assert_eq!(
            notes[2].text_in(yw_core::lang::Lang::Ko),
            "'Alice'과 앞 3자·끝 4자가 같지만 다른 주소입니다. 주소 오염 공격일 수 있습니다."
        );
        let catalogues: [&[Entry]; 13] = [
            crate::app_book::text::ALL,
            crate::app_browser::text::ALL,
            crate::app_chain_sites::text::ALL,
            crate::app_evm::text::ALL,
            crate::app_explorer::text::ALL,
            crate::app_extension::text::ALL,
            crate::app_tokens::text::ALL,
            crate::explorer::text::ALL,
            crate::flow::evm::form::text::ALL,
            crate::flow::evm::user_chain::text::ALL,
            crate::received::evm::text::ALL,
            crate::ui::screens_book::text::ALL,
            crate::ui::screens_evm::text::ALL,
        ];
        let more: [&[Entry]; 2] = [
            crate::ui::screens_explorer::text::ALL,
            crate::ui::screens_sites::text::ALL,
        ];
        for entry in catalogues.into_iter().chain(more).flatten() {
            for template in [entry.ko, entry.en] {
                let mut used = placeholders(template);
                used.sort_unstable();
                used.dedup();
                assert_eq!(used, (0..entry.args).collect::<Vec<_>>(), "{}", entry.name);
            }
            assert!(!has_hangul(entry.en), "{}", entry.name);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
