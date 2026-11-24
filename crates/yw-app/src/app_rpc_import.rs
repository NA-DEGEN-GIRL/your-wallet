//! Settings → 네트워크(RPC) `rpc.json에서 가져오기`: reads the development endpoint file of
//! spec/01 §4.6 (`%USERPROFILE%\.yw-dev\rpc.json`; debug builds also honour `YW_RPC_JSON`) so a
//! developer does not type the same URLs again.
//!
//! - The file: one UTF-8 JSON object ≤ 64 KiB, strict parsing (duplicate keys refused), a
//!   reparse point is not followed. Keys are `NetworkId`s of the URL list; other keys are skipped.
//! - Every value passes the manual-entry check (`HttpsUrl::parse`: `https://` only, no userinfo
//!   or fragment) and must be a provider endpoint the templates know: a `QuickNode` URL
//!   (`parse_quicknode_url`) or an Alchemy `https://<label>.g.alchemy.com/v2/<key>`, no port.
//! - The confirmation lists network name, provider and `…/****` only. Saving goes through the
//!   same `apikeys.dpapi` path as `교체` (DPAPI, current user); when every URL is one `QuickNode`
//!   endpoint name + token, those become the template credential and the provider switches to
//!   `QuickNode 멀티체인` through `save_settings` (which also updates the meta snapshot). A URL
//!   the template would not produce stays as that network's own entry.
//! - URLs, hosts and tokens are never logged or shown (D13): logs carry `NetworkId`s and counts.
//! - The file itself holds every token in plaintext, readable by any process of this user
//!   (Low integrity included, unless `dev-rpc-setup.ps1` labelled its folder). The card says so,
//!   right after an import it moves to the top and recommends deleting the file, and
//!   `rpc.json 지우기…` deletes it after a confirmation (a link is not followed or deleted).
//!
//! 2026-11-24 (spec/15 §11.4 S5-5, S5 plan critic C7): the card's texts (`text`) moved to
//! `yw_engine::screen::build::rpc_import::text` with the builder that draws the card.

use std::path::{Path, PathBuf};

use yw_core::secret::Zeroizing;
use yw_win::file::read_limited_no_reparse;

use crate::app::App;
use yw_engine::cmd::{Cmd, RpcImportPress};
use yw_engine::network::NetworkId;
use yw_engine::settings::Settings;
use yw_engine::wallet::app_rpc_plan::{DeleteError, ImportError, ImportPlan, plan_from_bytes};

/// Largest `rpc.json` (spec/01 §4.6).
pub const RPC_JSON_MAX: u64 = 65_536;

/// Deletes the endpoint file at `path`; a missing file counts as deleted. A link is refused:
/// deleting it would leave its target, with the tokens, in place.
///
/// # Errors
///
/// [`DeleteError`].
pub fn delete_file(path: &Path) -> Result<(), DeleteError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => {
            std::fs::remove_file(path).map_err(|_| DeleteError::Failed)
        }
        Ok(_) => Err(DeleteError::NotPlainFile),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(DeleteError::Failed),
    }
}

/// The `rpc.json` import card's presses (its ids are core ids, `ui::screens::ids`).
pub mod ids {
    use crate::ui::screens::ids::{
        RPC_IMPORT, RPC_IMPORT_CANCEL, RPC_IMPORT_FILL, RPC_IMPORT_OVERWRITE, RPC_JSON_DELETE,
        RPC_JSON_DELETE_CANCEL, RPC_JSON_DELETE_CONFIRM,
    };
    use yw_engine::cmd::RpcImportPress;

    /// The press control `id` stands for (2026-11-18, S3 C5: `ui::cmd_table`); `None` when `id`
    /// is not one of the card's.
    #[must_use]
    pub const fn press_of(id: u16) -> Option<RpcImportPress> {
        Some(match id {
            RPC_IMPORT => RpcImportPress::Import,
            RPC_IMPORT_OVERWRITE => RpcImportPress::Overwrite,
            RPC_IMPORT_FILL => RpcImportPress::Fill,
            RPC_IMPORT_CANCEL => RpcImportPress::Cancel,
            RPC_JSON_DELETE => RpcImportPress::Delete,
            RPC_JSON_DELETE_CONFIRM => RpcImportPress::DeleteConfirm,
            RPC_JSON_DELETE_CANCEL => RpcImportPress::DeleteCancel,
            _ => return None,
        })
    }

    /// The control id of `press` (the inverse of [`press_of`]).
    #[must_use]
    pub const fn id_of(press: RpcImportPress) -> u16 {
        match press {
            RpcImportPress::Import => RPC_IMPORT,
            RpcImportPress::Overwrite => RPC_IMPORT_OVERWRITE,
            RpcImportPress::Fill => RPC_IMPORT_FILL,
            RpcImportPress::Cancel => RPC_IMPORT_CANCEL,
            RpcImportPress::Delete => RPC_JSON_DELETE,
            RpcImportPress::DeleteConfirm => RPC_JSON_DELETE_CONFIRM,
            RpcImportPress::DeleteCancel => RPC_JSON_DELETE_CANCEL,
        }
    }
}

#[cfg(test)]
thread_local! {
    /// Tests: the endpoint file in the test's own temp folder, consulted first (2026-11-18, S3
    /// command census: a press of `rpc.json에서 가져오기` or `rpc.json 지우기` must never reach
    /// the owner's real file — AGENTS rules 2 and 4). Thread-local, so no `set_var`.
    pub static TEST_RPC_JSON: core::cell::RefCell<Option<PathBuf>> =
        const { core::cell::RefCell::new(None) };
}

/// The endpoint file: `YW_RPC_JSON` (debug builds only), else `%USERPROFILE%\.yw-dev\rpc.json`.
#[must_use]
pub fn rpc_json_path() -> Option<PathBuf> {
    #[cfg(test)]
    if let Some(path) = TEST_RPC_JSON.with(|path| path.borrow().clone()) {
        return Some(path);
    }
    if cfg!(debug_assertions)
        && let Some(path) = std::env::var_os("YW_RPC_JSON").filter(|path| !path.is_empty())
    {
        return Some(PathBuf::from(path));
    }
    let home = PathBuf::from(std::env::var_os("USERPROFILE")?);
    home.is_absolute()
        .then(|| home.join(".yw-dev").join("rpc.json"))
}

/// Reads `path` and builds the plan.
///
/// # Errors
///
/// [`ImportError`].
pub fn read_plan(
    path: &Path,
    networks: &[NetworkId],
    settings: &Settings,
) -> Result<ImportPlan, ImportError> {
    let bytes = Zeroizing::new(
        read_limited_no_reparse(path, RPC_JSON_MAX).map_err(|_| ImportError::Unreadable)?,
    );
    plan_from_bytes(&bytes, networks, settings)
}

impl App {
    /// `rpc.json에서 가져오기` presses (2026-11-18, S3 C5: an `RpcImportPress`; before, the
    /// control id). The file is found by [`rpc_json_path`] in the shell (2026-11-20, S4 P1:
    /// owner decision O-13 keeps `rpc.json` Windows-only with no platform trait; it was
    /// "S4: a platform trait").
    ///
    /// 2026-11-22 (S4c W13, critique B-5): this is the shell's press handler. It finds, reads
    /// and deletes the file (`begin_rpc_import`, `delete_rpc_json`) and hands everything else to
    /// the wallet's typed in-process entries: the parsed plan or the read error to
    /// `on_rpc_json_read`, the delete's result to `on_rpc_json_deleted`, the
    /// confirmation to [`Self::finish_rpc_import`], the cancel and the delete question to
    /// `rpc_import_cancel` and `rpc_json_delete_asked`. Before, the arms wrote
    /// the import state themselves and one fn read the file and wrote the wallet. Same steps,
    /// same order (the two moves are under `begin_rpc_import` and `delete_rpc_json`).
    /// 2026-11-22 (S4c W15, critique B-5): run by `App::on_command` right after the press
    /// reached the wallet (before, by the wallet's family router inside it), and the wallet's
    /// entries are named on the wallet (non-test builds have no `DerefMut`). Only the press's
    /// own drain (nothing to apply) runs before it, and `on_command` drains its effects and
    /// their answers right after it, before a closed drop-down's repaint, as inside the press
    /// (2026-11-22, W15 review).
    ///
    /// 2026-11-24 (spec/15 §11.4 S5-9): only the two presses that need the file — the read
    /// (`rpc.json에서 가져오기`) and the delete (`지우기`); `App::on_command` runs this for them
    /// alone. The confirmation, its `취소` and the delete question need no file and are the
    /// wallet's, handled in the press (`Wallet::on_rpc_import_press`; before, the arms here
    /// called the wallet's `finish_rpc_import`, `rpc_import_cancel` and
    /// `rpc_json_delete_asked` by name). The delete's result goes as `Cmd::RpcJsonDeleted`.
    pub(crate) fn on_rpc_import(&mut self, press: RpcImportPress) {
        match press {
            RpcImportPress::Import => {
                if let Some(path) = rpc_json_path() {
                    self.begin_rpc_import(&path);
                }
            }
            RpcImportPress::DeleteConfirm => {
                if let Some(path) = rpc_json_path() {
                    self.delete_rpc_json(&path);
                }
            }
            // The wallet's (`Wallet::on_rpc_import_press`, in the press).
            RpcImportPress::Overwrite
            | RpcImportPress::Fill
            | RpcImportPress::Cancel
            | RpcImportPress::Delete
            | RpcImportPress::DeleteCancel => {}
        }
    }
}

impl App {
    /// Test adapter (S3 C5, plan §3.2): presses an import-card control `id` directly, as the
    /// module tests did before; `false` when `id` is not one. 2026-11-24 (spec/15 §11.4 S5-9):
    /// the presses that need no file are the wallet's, so they go as the press itself
    /// (`Cmd::Press`, which also makes it the last press); the read and the delete go to the
    /// shell's half as before.
    #[cfg(test)]
    pub(crate) fn on_rpc_import_command(&mut self, id: u16) -> bool {
        self.press_family(
            id,
            |press| match press {
                yw_engine::cmd::Press::RpcImport(press) => Some(press),
                _ => None,
            },
            |app, press| {
                match press {
                    RpcImportPress::Import | RpcImportPress::DeleteConfirm => {
                        app.on_rpc_import(press);
                    }
                    _ => app.dispatch(Cmd::Press {
                        press: yw_engine::cmd::Press::RpcImport(press),
                        input: yw_engine::form::PressInput::default(),
                    }),
                }
                true
            },
        )
    }

    /// `rpc.json 지우기` confirmed: deletes the file (never a link) and says what happened.
    /// 2026-11-22 (S4c W13, critique B-5): the shell's half, the delete; the wallet's half,
    /// `on_rpc_json_deleted`, takes its result. Before, this fn did both and cleared the
    /// confirmation before the delete (now right after it: nothing reads it in between).
    /// 2026-11-24 (spec/15 §11.4 S5-9): the result goes as `Cmd::RpcJsonDeleted` (plain data;
    /// not drained here: the press's entry `App::on_command` drains right after, as before);
    /// before, the typed call `on_rpc_json_deleted`.
    pub(crate) fn delete_rpc_json(&mut self, path: &Path) {
        let deleted = delete_file(path);
        self.wallet.on_cmd(Cmd::RpcJsonDeleted(deleted));
    }
}

impl App {
    /// Reads `path` and shows the confirmation list (or a fixed error text).
    /// 2026-11-22 (S4c W13, critique B-5): the shell's half, the read; the plan (or the read
    /// error) enters the wallet through `on_rpc_json_read`. Before, this fn did both and
    /// reset the import state before the read (now right after it: the read takes the networks
    /// and settings only, never that state).
    pub(crate) fn begin_rpc_import(&mut self, path: &Path) {
        let read = read_plan(path, &self.wallet.url_networks(), &self.wallet.settings);
        self.wallet.on_rpc_json_read(read);
    }
}

// 2026-11-24 (spec/15 §11.4 S5-3): the card's render builder `rpc_import_section` moved to
// `ui/screens.rs`; it asks whether the file is there through `App::facts()`
// (`screen_facts::WinFacts::rpc_json_present`, which calls [`rpc_json_path`] and `is_file` as
// the builder did here). Its texts stay in [`text`] until the builders move (S5-5).

#[cfg(test)]
mod tests {
    use crate::app::{App, Paths};
    use yw_engine::apikeys::{ApiKeys, KeyName};
    use yw_engine::network::{BtcNet, NetworkId, SolCluster};
    use yw_engine::settings::{RpcTemplate, Settings};
    use yw_engine::wallet::app_rpc_plan::{
        ImportError, Provider, apply_plan, check_url, plan_from_bytes,
    };

    // Fake endpoint values only (never a real endpoint).
    const NAME: &str = "fake-node";
    const TOKEN: &str = "faketoken0123456789abcdef";

    fn qn(subdomain: Option<&str>, path: &str) -> String {
        let host = subdomain.map_or_else(|| NAME.to_owned(), |sub| format!("{NAME}.{sub}"));
        format!("https://{host}.quiknode.pro/{TOKEN}/{path}")
    }

    fn fake_file() -> String {
        format!(
            r#"{{"eip155:1":"{}","eip155:11155111":"{}","eip155:999":"{}","solana:mainnet":"{}","solana:devnet":"{}","bitcoin:mainnet":"{}","bitcoin:testnet4":"{}","eip155:424242":"https://x.example/"}}"#,
            qn(None, ""),
            qn(Some("ethereum-sepolia"), ""),
            qn(Some("hype-mainnet"), "nanoreth"),
            qn(Some("solana-mainnet"), ""),
            qn(Some("solana-devnet"), ""),
            qn(Some("btc"), ""),
            qn(Some("btc-testnet4"), ""),
        )
    }

    fn networks() -> Vec<NetworkId> {
        let mut networks: Vec<NetworkId> = Settings::default()
            .registered_evm()
            .into_iter()
            .map(NetworkId::Eip155)
            .collect();
        networks.extend([
            NetworkId::Solana(SolCluster::Mainnet),
            NetworkId::Solana(SolCluster::Devnet),
            NetworkId::Bitcoin(BtcNet::Mainnet),
            NetworkId::Bitcoin(BtcNet::Testnet4),
        ]);
        networks
    }

    #[test]
    fn check_url_takes_provider_endpoints_only() {
        assert_eq!(
            check_url(&qn(None, "")).map(|(_, p)| p),
            Some(Provider::QuickNode)
        );
        // Built at run time so the privacy scan never sees a provider-shaped URL in the source.
        let alchemy = "https://eth-mainnet.g.alchemy.com";
        let quicknode = format!("{NAME}.quiknode.pro");
        assert_eq!(
            check_url(&format!("{alchemy}/v2/{TOKEN}")).map(|(_, p)| p),
            Some(Provider::Alchemy)
        );
        for bad in [
            format!("http://{quicknode}/{TOKEN}/"),
            format!("https://user:pw@{quicknode}/{TOKEN}/"),
            format!("https://{NAME}.quiknode.pro:8443/{TOKEN}/"),
            "https://rpc.example.test/v1".to_owned(),
            format!("{alchemy}/v3/{TOKEN}"),
            format!("https://{quicknode}/short/"),
        ] {
            assert!(check_url(&bad).is_none(), "accepted a bad value");
        }
    }

    #[test]
    fn plan_detects_one_quicknode_endpoint_and_applies() {
        let settings = Settings::default();
        let plan = plan_from_bytes(fake_file().as_bytes(), &networks(), &settings).unwrap();
        assert_eq!(plan.entries.len(), 7);
        assert_eq!(plan.ignored, 1);
        assert!(plan.rejected.is_empty());
        let (name, token) = plan.quicknode.as_ref().expect("one endpoint");
        assert_eq!((name.as_str(), token.as_str()), (NAME, TOKEN));
        // HyperEVM's `/nanoreth` path is what the template produces: no override needed.
        assert!(plan.entries.iter().all(|entry| entry.fits_template));

        let mut keys = ApiKeys::default();
        let other = check_url(&qn(None, "other")).unwrap().0;
        keys.set_rpc(NetworkId::Eip155(1), &other);
        keys.set_quicknode("kept-node", "keptkeptkeptkept0000");
        let applied = apply_plan(&mut keys, &plan, false);
        assert_eq!(applied.kept, [NetworkId::Eip155(1)]);
        assert_eq!(applied.written.len(), 6);
        assert!(!applied.template);
        assert!(keys.rpc_url(NetworkId::Eip155(1)) == Some(other));
        let applied = apply_plan(&mut keys, &plan, true);
        assert_eq!(applied.written.len(), 7);
        assert!(applied.template);
        assert!(
            keys.rpc_url(NetworkId::Eip155(1))
                .is_some_and(|url| url.expose() == plan.entries[0].url.as_str())
        );
        // 2026-11-22 (S4c W13 review): an entry keeps the normalized text, which parses back
        // to itself, so `apply_plan` writes every entry it does not keep.
        for entry in &plan.entries {
            let url = yw_platform::http::HttpsUrl::parse(&entry.url).unwrap();
            assert_eq!(url.expose(), entry.url.as_str());
        }

        // Duplicate keys and non-objects are format errors; a bad value is a rejected network.
        let duplicate = br#"{"eip155:1":"a","eip155:1":"b"}"#;
        assert_eq!(
            plan_from_bytes(duplicate, &networks(), &settings).unwrap_err(),
            ImportError::Format
        );
        assert_eq!(
            plan_from_bytes(b"[]", &networks(), &settings).unwrap_err(),
            ImportError::Format
        );
        let mixed = format!(
            r#"{{"eip155:1":"{}","solana:devnet":"https://rpc.example.test/"}}"#,
            qn(None, "")
        );
        let plan = plan_from_bytes(mixed.as_bytes(), &networks(), &settings).unwrap();
        assert_eq!(plan.rejected, [NetworkId::Solana(SolCluster::Devnet)]);
        assert_eq!(plan.entries.len(), 1);
    }

    /// 2026-11-22 (S4c W13, critique B-5): the plan, and the import state that holds it, print
    /// counts only: no network, URL, endpoint name or token (before, the plan's `Debug` listed
    /// the networks by id).
    #[test]
    fn the_plan_prints_counts_only() {
        let plan =
            plan_from_bytes(fake_file().as_bytes(), &networks(), &Settings::default()).unwrap();
        let text = format!("{plan:?}");
        assert_eq!(
            text,
            "ImportPlan { entries: 7, rejected: 0, ignored: 1, quicknode: true }"
        );
        // 2026-11-22 (S4c W13 review): an entry's URL is a wiped string now, and its `Debug`
        // still redacts it (`Zeroizing`'s own would print it).
        let entry_text = format!("{:?}", plan.entries[0]);
        assert!(entry_text.contains("https://[redacted]"), "{entry_text}");
        for secret in [NAME, TOKEN, "quiknode"] {
            assert!(!entry_text.contains(secret), "{entry_text}");
        }
        let state = yw_engine::wallet::app_rpc_plan::RpcImportUi {
            plan: Some(plan),
            ..yw_engine::wallet::app_rpc_plan::RpcImportUi::default()
        };
        let state_text = format!("{state:?}");
        for text in [text, state_text] {
            for secret in [
                NAME, TOKEN, "quiknode", "https", "eip155", "solana", "bitcoin",
            ] {
                assert!(!text.contains(secret), "{text}");
            }
        }
    }

    /// The app path: fake `rpc.json` in a temp dir → confirmation → `apikeys.dpapi` written and
    /// the template switched to `QuickNode 멀티체인` through `save_settings`.
    #[test]
    fn import_saves_like_manual_entry() {
        use crate::ui::screens::ids;
        let dir = std::env::temp_dir().join(format!(
            "yw-rpc-import-{}-{}",
            std::process::id(),
            yw_win::time::monotonic_ms()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("rpc.json");
        std::fs::write(&file, fake_file()).unwrap();
        let mut app = App::new(
            Paths {
                data: dir.clone(),
                logs: dir.join("logs"),
            },
            true,
            Settings::default(),
            ApiKeys::default(),
        );
        app.begin_rpc_import(&file);
        assert!(app.rpc_import.plan.is_some());
        assert!(app.on_rpc_import_command(ids::RPC_IMPORT_OVERWRITE));
        assert!(app.rpc_import.plan.is_none());
        assert!(app.apikeys.has(KeyName::TplQuickNode));
        assert_eq!(app.settings.rpc_template, RpcTemplate::QuickNode);
        // The file lists 7 networks; the template fills every other one (2026-11-11).
        let targets = app.generation_plan().0;
        assert!(targets.len() > 7);
        assert_eq!(app.apikeys.endpoints().len(), targets.len());
        assert!(dir.join("apikeys.dpapi").is_file());
        let info = app.info.clone().unwrap_or_default();
        assert!(info.contains("재설치해도 유지됩니다"), "{info}");
        assert!(info.contains("파일에 없던"), "{info}");
        assert!(!info.contains(TOKEN) && !info.contains(NAME));
        let (reloaded, failed) = crate::app::load_apikeys(&app.paths, &app.settings);
        assert!(!failed);
        assert_eq!(reloaded.endpoints().len(), targets.len());

        // The plaintext source is still there: the card recommends deleting it, which is asked
        // first and then removes the file only.
        assert!(app.rpc_import.imported && app.rpc_import.on_top());
        assert!(app.on_rpc_import_command(ids::RPC_JSON_DELETE));
        assert!(app.rpc_import.confirm_delete);
        app.delete_rpc_json(&file);
        assert!(!file.exists());
        assert!(!app.rpc_import.confirm_delete && !app.rpc_import.on_top());
        assert_eq!(app.apikeys.endpoints().len(), targets.len());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A stored `QuickNode` credential gives every network without an address the template's
    /// address (start, after an update added chains); a stored address is never replaced.
    #[test]
    fn template_fills_networks_without_an_address() {
        let dir = std::env::temp_dir().join(format!(
            "yw-rpc-fill-{}-{}",
            std::process::id(),
            yw_win::time::monotonic_ms()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let mut keys = ApiKeys::default();
        keys.set_quicknode(NAME, TOKEN);
        let own = check_url(&qn(None, "own")).unwrap().0;
        keys.set_rpc(NetworkId::Eip155(1), &own);
        let mut app = App::new(
            Paths {
                data: dir.clone(),
                logs: dir.join("logs"),
            },
            true,
            Settings::default(),
            keys,
        );
        let filled = app.fill_template_gaps();
        let targets = app.generation_plan().0;
        assert_eq!(filled.len(), targets.len() - 1);
        assert!(!filled.contains(&NetworkId::Eip155(1)));
        assert!(filled.contains(&NetworkId::Eip155(42_161)));
        assert!(app.apikeys.rpc_url(NetworkId::Eip155(1)) == Some(own));
        assert!(dir.join("apikeys.dpapi").is_file());
        assert!(app.fill_template_gaps().is_empty());

        // `직접 입력` makes nothing.
        let mut manual = App::new(
            Paths {
                data: dir.clone(),
                logs: dir.join("logs"),
            },
            true,
            Settings {
                rpc_template: RpcTemplate::Manual,
                ..Settings::default()
            },
            ApiKeys::default(),
        );
        assert!(manual.fill_template_gaps().is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }
}
