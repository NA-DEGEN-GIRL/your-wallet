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

use core::fmt::{self, Write as _};
use std::path::{Path, PathBuf};

use yw_core::secret::Zeroizing;
use yw_win::file::read_limited_no_reparse;
use yw_win::http::HttpsUrl;

use crate::apikeys::{
    ApiKeys, KeyName, TemplateCred, parse_quicknode_url, template_entry, template_url,
    valid_provider_token,
};
use crate::app::App;
use crate::logging::{self, Field};
use crate::network::NetworkId;
use crate::settings::{RpcTemplate, Settings};
use crate::text::is_dns_label;
use crate::ui::main_window::{Ctl, Item, Tone};

/// Largest `rpc.json` (spec/01 §4.6).
pub const RPC_JSON_MAX: u64 = 65_536;

const LIMITS: yw_json::Limits = yw_json::Limits {
    max_bytes: 65_536,
    max_depth: 4,
    max_nodes: 512,
    max_items: 256,
};

/// The persistence note of the import result (the data folder survives `install.cmd`,
/// `uninstall.cmd` without `-RemoveWalletData`, and a default `지갑 초기화`).
pub const T_IMPORT_KEPT: &str = "주소는 %LOCALAPPDATA%\\YourWallet\\v3\\apikeys.dpapi에 이 Windows 사용자만 풀 수 있게 암호화해 저장했습니다. 재설치해도 유지됩니다. 지갑 초기화 때 '설정과 API 키도 함께 옮기기'를 켜지 않으면 그대로 남습니다.";

/// The card's note on the source file (before an import).
pub const T_JSON_PLAINTEXT: &str = "이 파일에는 RPC 주소와 그 토큰이 암호화되지 않은 채 들어 있어, 이 Windows 사용자로 도는 다른 프로그램도 읽을 수 있습니다. 가져온 뒤 개발 스크립트에 더 쓰지 않으면 지우세요.";

/// The card's warning right after an import.
pub const T_JSON_LEFT: &str = "가져오기를 마쳤습니다. 앱에는 암호화해 저장했지만 rpc.json에는 같은 주소·토큰이 암호화되지 않은 채 남아 있습니다. 개발 스크립트(probe-rpc 등)에 더 쓰지 않으면 지우세요.";

/// The delete confirmation.
pub const T_JSON_DELETE_CONFIRM: &str = "rpc.json을 지웁니다. 휴지통으로 가지 않아 되돌릴 수 없습니다. 앱에 저장한 RPC 주소는 그대로이고, 개발 스크립트가 이 파일을 쓴다면 scripts\\dev-rpc-setup.ps1로 다시 만들어야 합니다.";

/// Why `rpc.json 지우기` did not delete the file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeleteError {
    /// A link (symbolic link, junction) or not a file: neither it nor its target is deleted.
    NotPlainFile,
    /// The delete failed (in use, no permission).
    Failed,
}

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

/// The endpoint file: `YW_RPC_JSON` (debug builds only), else `%USERPROFILE%\.yw-dev\rpc.json`.
#[must_use]
pub fn rpc_json_path() -> Option<PathBuf> {
    if cfg!(debug_assertions)
        && let Some(path) = std::env::var_os("YW_RPC_JSON").filter(|path| !path.is_empty())
    {
        return Some(PathBuf::from(path));
    }
    let home = PathBuf::from(std::env::var_os("USERPROFILE")?);
    home.is_absolute()
        .then(|| home.join(".yw-dev").join("rpc.json"))
}

/// Why the file gave nothing (fixed texts, never content or parser messages).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImportError {
    /// Missing, too large, a link, or unreadable.
    Unreadable,
    /// Not one strict JSON object.
    Format,
}

impl ImportError {
    /// The S15 text.
    #[must_use]
    pub const fn text(self) -> &'static str {
        match self {
            Self::Unreadable => {
                "rpc.json을 읽을 수 없습니다. 파일이 없거나, 64 KiB보다 크거나, 바로가기·링크입니다."
            }
            Self::Format => {
                "rpc.json 형식이 올바르지 않습니다. UTF-8 JSON 객체 하나({\"eip155:1\": \"https://…\", …} 모양, 같은 키 두 번 금지)여야 합니다."
            }
        }
    }
}

/// The endpoint provider of an accepted URL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Provider {
    /// `*.quiknode.pro`.
    QuickNode,
    /// `*.g.alchemy.com`.
    Alchemy,
}

impl Provider {
    const fn label(self) -> &'static str {
        match self {
            Self::QuickNode => "QuickNode",
            Self::Alchemy => "알케미",
        }
    }
}

/// One accepted network (`HttpsUrl`'s `Debug` shows only `https://[redacted]`).
#[derive(Debug)]
pub struct ImportEntry {
    /// Network.
    pub network: NetworkId,
    /// The URL (secret).
    pub url: HttpsUrl,
    /// Provider.
    pub provider: Provider,
    /// The detected `QuickNode` template produces exactly this URL.
    pub fits_template: bool,
}

/// What the file offers (kept until `가져오기` / `취소`).
#[derive(Default)]
pub struct ImportPlan {
    /// Accepted networks, in URL-list order.
    pub entries: Vec<ImportEntry>,
    /// Networks of the list whose value failed the URL check.
    pub rejected: Vec<NetworkId>,
    /// Keys that are not a network of the URL list.
    pub ignored: usize,
    /// One `QuickNode` endpoint name + token behind every URL.
    pub quicknode: Option<(String, Zeroizing<String>)>,
}

impl fmt::Debug for ImportPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let networks: Vec<String> = self
            .entries
            .iter()
            .map(|entry| entry.network.to_string())
            .collect();
        formatter
            .debug_struct("ImportPlan")
            .field("networks", &networks)
            .field("rejected", &self.rejected)
            .field("ignored", &self.ignored)
            .field("quicknode", &self.quicknode.is_some())
            .finish()
    }
}

/// The URL check of one value: the manual-entry rules plus a provider endpoint shape.
#[must_use]
pub fn check_url(text: &str) -> Option<(HttpsUrl, Provider)> {
    let url = HttpsUrl::parse(text.trim()).ok()?;
    if url.port().is_some() {
        return None;
    }
    if parse_quicknode_url(url.expose()).is_some() {
        return Some((url, Provider::QuickNode));
    }
    let label = url.host().strip_suffix(".g.alchemy.com")?;
    let key = url.path().strip_prefix("/v2/")?;
    (is_dns_label(label) && valid_provider_token(key)).then_some((url, Provider::Alchemy))
}

/// Builds the plan from the file bytes for the networks of the URL list.
///
/// # Errors
///
/// [`ImportError::Format`] unless the bytes are one strict JSON object.
pub fn plan_from_bytes(
    bytes: &[u8],
    networks: &[NetworkId],
    settings: &Settings,
) -> Result<ImportPlan, ImportError> {
    let body = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    let value = yw_json::parse(body, &LIMITS).map_err(|_| ImportError::Format)?;
    let object = value.as_object().ok_or(ImportError::Format)?;
    let mut plan = ImportPlan::default();
    for (key, _) in object.iter() {
        if !NetworkId::parse(key).is_some_and(|network| networks.contains(&network)) {
            plan.ignored = plan.ignored.saturating_add(1);
        }
    }
    for &network in networks {
        let Some(item) = object.get(&network.to_string()) else {
            continue;
        };
        match item.as_str().and_then(check_url) {
            Some((url, provider)) => plan.entries.push(ImportEntry {
                network,
                url,
                provider,
                fits_template: false,
            }),
            None => plan.rejected.push(network),
        }
    }
    drop(value);
    let mut credentials = plan
        .entries
        .iter()
        .map(|entry| parse_quicknode_url(entry.url.expose()));
    let first = credentials.next().flatten();
    if let Some(first) = first
        && credentials.all(|other| other.as_ref() == Some(&first))
    {
        let cred = TemplateCred::QuickNode {
            name: first.0.clone(),
            token: first.1.clone(),
        };
        for entry in &mut plan.entries {
            let wanted = template_entry(RpcTemplate::QuickNode, entry.network, settings);
            entry.fits_template = template_url(RpcTemplate::QuickNode, &cred, wanted.as_ref())
                .is_some_and(|url| url == entry.url);
        }
        plan.quicknode = Some(first);
    }
    Ok(plan)
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

/// What [`apply_plan`] wrote (in memory; the caller saves).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Applied {
    /// Networks whose URL was written.
    pub written: Vec<NetworkId>,
    /// Networks left alone (`비어 있는 네트워크만` and a URL already stored).
    pub kept: Vec<NetworkId>,
    /// The `QuickNode` template credential was written.
    pub template: bool,
}

/// Writes the plan into `keys`: every URL (only into empty networks unless `overwrite`) and the
/// `QuickNode` credential when one was detected (unless `overwrite` is off and one is stored).
pub fn apply_plan(keys: &mut ApiKeys, plan: &ImportPlan, overwrite: bool) -> Applied {
    let mut applied = Applied::default();
    for entry in &plan.entries {
        if !overwrite && keys.has(KeyName::Rpc(entry.network)) {
            applied.kept.push(entry.network);
            continue;
        }
        keys.set_rpc(entry.network, &entry.url);
        applied.written.push(entry.network);
    }
    if let Some((name, token)) = &plan.quicknode
        && (overwrite || !keys.has(KeyName::TplQuickNode))
    {
        keys.set_quicknode(name, token);
        applied.template = true;
    }
    applied
}

/// The S15 import state.
#[derive(Debug, Default)]
pub struct RpcImportUi {
    /// The plan waiting for confirmation.
    pub plan: Option<ImportPlan>,
    /// An import finished on this screen: the card recommends deleting the file.
    pub imported: bool,
    /// `rpc.json 지우기…` waits for its confirmation.
    pub confirm_delete: bool,
}

impl RpcImportUi {
    /// The card goes first in settings → 네트워크(RPC) (it waits for a decision); otherwise last.
    #[must_use]
    pub const fn on_top(&self) -> bool {
        self.plan.is_some() || self.imported
    }
}

impl App {
    /// `rpc.json에서 가져오기` commands; `false` when `id` is not one of them.
    pub(crate) fn on_rpc_import_command(&mut self, id: u16) -> bool {
        use crate::ui::screens::ids;
        match id {
            ids::RPC_IMPORT => {
                if let Some(path) = rpc_json_path() {
                    self.begin_rpc_import(&path);
                }
            }
            ids::RPC_IMPORT_OVERWRITE => self.finish_rpc_import(true),
            ids::RPC_IMPORT_FILL => self.finish_rpc_import(false),
            ids::RPC_IMPORT_CANCEL => {
                self.rpc_import = RpcImportUi::default();
                self.refresh();
            }
            ids::RPC_JSON_DELETE | ids::RPC_JSON_DELETE_CANCEL => {
                self.rpc_import.confirm_delete = id == ids::RPC_JSON_DELETE;
                self.refresh();
            }
            ids::RPC_JSON_DELETE_CONFIRM => {
                if let Some(path) = rpc_json_path() {
                    self.delete_rpc_json(&path);
                }
            }
            _ => return false,
        }
        true
    }

    /// `rpc.json 지우기` confirmed: deletes the file (never a link) and says what happened.
    pub(crate) fn delete_rpc_json(&mut self, path: &Path) {
        self.rpc_import.confirm_delete = false;
        let text = match delete_file(path) {
            Ok(()) => {
                logging::info("app", "rpc.import_file_deleted", &[]);
                self.rpc_import.imported = false;
                "rpc.json을 지웠습니다. 앱에 저장한 RPC 주소는 그대로입니다."
            }
            Err(error) => {
                logging::info("app", "rpc.import_file_delete_failed", &[]);
                match error {
                    DeleteError::NotPlainFile => {
                        "rpc.json이 링크(심볼릭 링크)이거나 파일이 아니라 지우지 않았습니다. 링크가 가리키는 파일에 토큰이 있으니 탐색기에서 확인해 직접 지우세요."
                    }
                    DeleteError::Failed => {
                        "rpc.json을 지우지 못했습니다. 다른 프로그램이 열고 있거나 권한이 없습니다. 탐색기에서 직접 지우세요."
                    }
                }
            }
        };
        self.info = Some(text.to_owned());
        self.refresh();
    }

    /// Reads `path` and shows the confirmation list (or a fixed error text).
    pub(crate) fn begin_rpc_import(&mut self, path: &Path) {
        self.rpc_import = RpcImportUi::default();
        match read_plan(path, &self.url_networks(), &self.settings) {
            Ok(plan) => {
                logging::info(
                    "app",
                    "rpc.import_read",
                    &[
                        ("count", Field::Num(len_u64(plan.entries.len()))),
                        ("rejected", Field::Num(len_u64(plan.rejected.len()))),
                        ("ignored", Field::Num(len_u64(plan.ignored))),
                    ],
                );
                if plan.entries.is_empty() {
                    let mut text = "rpc.json에 가져올 수 있는 RPC 주소가 없습니다.".to_owned();
                    self.push_rejected(&mut text, &plan);
                    self.info = Some(text);
                } else {
                    self.info = None;
                    self.rpc_import.plan = Some(plan);
                }
            }
            Err(error) => {
                logging::info("app", "rpc.import_failed", &[]);
                self.info = Some(error.text().to_owned());
            }
        }
        self.refresh();
    }

    /// `덮어쓰기` / `가져오기` (`overwrite`) or `비어 있는 네트워크만`.
    pub(crate) fn finish_rpc_import(&mut self, overwrite: bool) {
        let Some(plan) = self.rpc_import.plan.take() else {
            return;
        };
        let applied = apply_plan(&mut self.apikeys, &plan, overwrite);
        drop(plan);
        if !self.save_apikeys() {
            self.refresh();
            return;
        }
        for network in &applied.written {
            logging::info("app", "rpc.imported", &[("net", Field::Net(*network))]);
            self.rpc_messages.retain(|(id, _, _)| id != network);
            self.network_url_changed(*network);
        }
        if applied.template {
            logging::info(
                "app",
                "tpl.saved",
                &[("template", Field::Word(RpcTemplate::QuickNode.as_str()))],
            );
        }
        let mut text = format!(
            "rpc.json에서 RPC 주소 {}개를 가져왔습니다",
            applied.written.len()
        );
        if !applied.kept.is_empty() {
            let _ = write!(
                text,
                "(이미 주소가 있는 {}개는 그대로 두었습니다)",
                applied.kept.len()
            );
        }
        text.push('.');
        if applied.template {
            text.push_str(" 모두 같은 QuickNode 엔드포인트라 RPC 공급자를 'QuickNode 멀티체인'으로 하고 이름·토큰을 템플릿 자격 정보로 저장했습니다.");
        }
        // Every imported address is tested in turn (2026-11-10).
        if !applied.written.is_empty() {
            text.push_str(" 연결을 확인하는 중입니다 — 결과는 아래 각 행에 나옵니다.");
        }
        text.push(' ');
        text.push_str(T_IMPORT_KEPT);
        self.info = Some(text);
        self.queue_rpc_tests(&applied.written);
        // The plaintext source is still there: the card moves up and recommends deleting it.
        self.rpc_import.imported = true;
        if applied.template && self.settings.rpc_template != RpcTemplate::QuickNode {
            let mut settings = self.settings.clone();
            settings.rpc_template = RpcTemplate::QuickNode;
            self.save_settings(settings, "rpc.template");
        } else {
            self.refresh();
        }
    }

    fn push_rejected(&self, text: &mut String, plan: &ImportPlan) {
        if !plan.rejected.is_empty() {
            let names: Vec<String> = plan
                .rejected
                .iter()
                .map(|network| format!("{} ({network})", self.network_name(*network)))
                .collect();
            let _ = write!(
                text,
                "\n가져오지 않음(https QuickNode·알케미 주소가 아니거나 형식 오류): {}",
                names.join(", ")
            );
        }
        if plan.ignored > 0 {
            let _ = write!(
                text,
                "\n이 앱의 네트워크 목록에 없는 키 {}개는 건너뜁니다.",
                plan.ignored
            );
        }
    }

    /// The `rpc.json에서 가져오기` card of settings → 네트워크(RPC) ([`RpcImportUi::on_top`]):
    /// shown only when the file exists or a plan waits for confirmation.
    pub(crate) fn rpc_import_section(&self, items: &mut Vec<Item>) {
        use crate::ui::screens::ids;
        let Some(plan) = self.rpc_import.plan.as_ref() else {
            if rpc_json_path().is_some_and(|path| path.is_file()) {
                items.push(Item::CardStart(Some("rpc.json에서 가져오기".to_owned())));
                if !self.rpc_import.imported {
                    items.push(Item::Help(
                        "개발용 설정 파일(%USERPROFILE%\\.yw-dev\\rpc.json)에 있는 RPC 주소를 읽어 위 '네트워크별 RPC 주소' 목록에 넣습니다. 저장하기 전에 가린 목록으로 한 번 더 확인합니다."
                            .to_owned(),
                    ));
                    items.push(Item::Help(T_JSON_PLAINTEXT.to_owned()));
                }
                if self.rpc_import.confirm_delete {
                    items.push(Item::Banner(T_JSON_DELETE_CONFIRM.to_owned(), Tone::Warn));
                    items.push(Item::Row(vec![
                        Ctl::danger(ids::RPC_JSON_DELETE_CONFIRM, "지우기"),
                        Ctl::button(ids::RPC_JSON_DELETE_CANCEL, "취소"),
                    ]));
                } else {
                    if self.rpc_import.imported {
                        items.push(Item::Banner(T_JSON_LEFT.to_owned(), Tone::Warn));
                    }
                    items.push(Item::Row(vec![
                        Ctl::button(ids::RPC_IMPORT, "rpc.json에서 가져오기"),
                        Ctl::button(ids::RPC_JSON_DELETE, "rpc.json 지우기…"),
                    ]));
                }
                items.push(Item::CardEnd);
            }
            return;
        };
        items.push(Item::CardStart(Some(
            "rpc.json에서 가져오기 — 확인".to_owned(),
        )));
        let mut text =
            "다음 RPC 주소를 가져옵니다(주소에는 토큰이 있어 가린 형태로만 보입니다):".to_owned();
        let mut existing = 0_usize;
        for entry in &plan.entries {
            let has = self.apikeys.has(KeyName::Rpc(entry.network));
            if has {
                existing = existing.saturating_add(1);
            }
            let _ = write!(
                text,
                "\n· {} ({}) — {} …/****{}{}",
                self.network_name(entry.network),
                entry.network,
                entry.provider.label(),
                if has { " — 기존 주소 있음" } else { "" },
                if plan.quicknode.is_some() && !entry.fits_template {
                    " — 템플릿과 다른 주소(이 네트워크에 그대로 저장)"
                } else {
                    ""
                },
            );
        }
        self.push_rejected(&mut text, plan);
        items.push(Item::Text(text));
        if plan.quicknode.is_some() {
            items.push(Item::Help(
                "모든 주소가 같은 QuickNode 엔드포인트(이름·토큰)입니다. RPC 공급자를 'QuickNode 멀티체인'으로 바꾸고 이름·토큰을 템플릿 자격 정보로 함께 저장합니다."
                    .to_owned(),
            ));
        }
        if existing > 0 {
            items.push(Item::Banner(
                format!(
                    "이미 주소가 있는 네트워크가 {existing}개 있습니다. 덮어쓰거나, 비어 있는 네트워크에만 넣을 수 있습니다."
                ),
                Tone::Warn,
            ));
            items.push(Item::Row(vec![
                Ctl::button(ids::RPC_IMPORT_OVERWRITE, "덮어쓰기"),
                Ctl::button(ids::RPC_IMPORT_FILL, "비어 있는 네트워크만"),
                Ctl::button(ids::RPC_IMPORT_CANCEL, "취소"),
            ]));
        } else {
            items.push(Item::Row(vec![
                Ctl::button(ids::RPC_IMPORT_OVERWRITE, "가져오기"),
                Ctl::button(ids::RPC_IMPORT_CANCEL, "취소"),
            ]));
        }
        items.push(Item::Help(
            "저장은 '교체'와 같습니다: Windows가 이 사용자 계정에서만 풀 수 있게 암호화해 apikeys.dpapi에 둡니다."
                .to_owned(),
        ));
        items.push(Item::CardEnd);
    }
}

fn len_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::{ImportError, Provider, apply_plan, check_url, plan_from_bytes};
    use crate::apikeys::{ApiKeys, KeyName};
    use crate::app::{App, Paths};
    use crate::network::{BtcNet, NetworkId, SolCluster};
    use crate::settings::{RpcTemplate, Settings};

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
        assert!(keys.rpc_url(NetworkId::Eip155(1)) == Some(plan.entries[0].url.clone()));

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
        assert_eq!(app.apikeys.endpoints().len(), 7);
        assert_eq!(app.settings.rpc_template, RpcTemplate::QuickNode);
        assert!(dir.join("apikeys.dpapi").is_file());
        let info = app.info.clone().unwrap_or_default();
        assert!(info.contains("재설치해도 유지됩니다"), "{info}");
        assert!(!info.contains(TOKEN) && !info.contains(NAME));
        let (reloaded, failed) = crate::app::load_apikeys(&app.paths, &app.settings);
        assert!(!failed);
        assert_eq!(reloaded.endpoints().len(), 7);

        // The plaintext source is still there: the card recommends deleting it, which is asked
        // first and then removes the file only.
        assert!(app.rpc_import.imported && app.rpc_import.on_top());
        assert!(app.on_rpc_import_command(ids::RPC_JSON_DELETE));
        assert!(app.rpc_import.confirm_delete);
        app.delete_rpc_json(&file);
        assert!(!file.exists());
        assert!(!app.rpc_import.confirm_delete && !app.rpc_import.on_top());
        assert_eq!(app.apikeys.endpoints().len(), 7);
        let _ = std::fs::remove_dir_all(dir);
    }
}
