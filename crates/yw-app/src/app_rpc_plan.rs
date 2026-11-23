//! The wallet half of Settings → 네트워크(RPC) `rpc.json에서 가져오기` (spec/01 §4.6, spec/04
//! §2.11): the import plan the shell parses from the development endpoint file, its checks, and
//! the wallet's typed in-process entries that take the plan, the read error and the delete's
//! result (critique B-5). The file itself (its path, the read and the delete) and the card stay
//! in the shell's `app_rpc_import` (owner decision O-13: Windows only, no platform trait).
//!
//! - Every value passes the manual-entry check (`HttpsUrl::parse`: `https://` only, no userinfo
//!   or fragment) and must be a provider endpoint the templates know: a `QuickNode` URL
//!   (`parse_quicknode_url`) or an Alchemy `https://<label>.g.alchemy.com/v2/<key>`, no port.
//! - URLs, hosts and tokens are never logged or shown (D13): logs carry `NetworkId`s and counts.
//!   The plan never enters a `Cmd`, an `Effect`, a log or a golden line (plan §7); its `Debug`
//!   prints counts only and its URLs, endpoint name and token are wiped on drop.
//!
//! 2026-11-23 (spec/15 §11.4 S4d E0b): split out of `app_rpc_import` unchanged (bodies, docs), so
//! the wallet's part is in a file that moves to yw-engine at E1.

use core::fmt;

use yw_core::lang::Lang;
use yw_core::secret::Zeroizing;
use yw_platform::http::HttpsUrl;

use crate::apikeys::ApiKeys;
use crate::apikeys::KeyName;
use crate::apikeys::TemplateCred;
use crate::apikeys::parse_quicknode_url;
use crate::apikeys::template_entry;
use crate::apikeys::template_url;
use crate::apikeys::valid_provider_token;
use crate::app::Wallet;
use crate::logging;
use crate::logging::Field;
use crate::network::NetworkId;
use crate::settings::RpcTemplate;
use crate::settings::Settings;
use crate::text::is_dns_label;

const LIMITS: yw_json::Limits = yw_json::Limits {
    max_bytes: 65_536,
    max_depth: 4,
    max_nodes: 512,
    max_items: 256,
};

/// Why `rpc.json 지우기` did not delete the file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeleteError {
    /// A link (symbolic link, junction) or not a file: neither it nor its target is deleted.
    NotPlainFile,
    /// The delete failed (in use, no permission).
    Failed,
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
    /// The S15 text in `lang`.
    #[must_use]
    pub const fn text(self, lang: Lang) -> &'static str {
        match self {
            Self::Unreadable => text::UNREADABLE,
            Self::Format => text::FORMAT,
        }
        .get(lang)
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
    pub(crate) const fn label(self, lang: Lang) -> &'static str {
        match self {
            Self::QuickNode => "QuickNode",
            Self::Alchemy => text::ALCHEMY.get(lang),
        }
    }
}

/// One accepted network.
pub struct ImportEntry {
    /// Network.
    pub network: NetworkId,
    /// The URL (secret): the normalized text of the `HttpsUrl` the check parsed
    /// (`HttpsUrl::expose`, which parses back to the same `HttpsUrl`), wiped on drop
    /// (2026-11-22, S4c W13 review, critique B-5: before, an `HttpsUrl`, whose strings are not
    /// wiped). The `HttpsUrl`s made from it for a moment (the check, the template comparison,
    /// [`apply_plan`]) are not wiped: yw-platform has no wipe, and every RPC URL the app uses is
    /// such an `HttpsUrl` (`ApiKeys::rpc_url`).
    pub url: Zeroizing<String>,
    /// Provider.
    pub provider: Provider,
    /// The detected `QuickNode` template produces exactly this URL.
    pub fits_template: bool,
}

/// The URL is redacted, as `HttpsUrl`'s `Debug` was (`Zeroizing`'s own `Debug` would print it).
impl fmt::Debug for ImportEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ImportEntry")
            .field("network", &self.network)
            .field("url", &format_args!("https://[redacted]"))
            .field("provider", &self.provider)
            .field("fits_template", &self.fits_template)
            .finish()
    }
}

/// What the file offers (kept until `가져오기` / `취소`): the plan critique B-5 calls
/// `RpcImportPlan`. The shell parses it from the file and it enters the wallet only through the
/// typed in-process entry `Wallet::on_rpc_json_read` (2026-11-22, S4c W13), never in a `Cmd`,
/// an `Effect`, a log line or a golden (plan §7).
#[derive(Default)]
pub struct ImportPlan {
    /// Accepted networks, in URL-list order.
    pub entries: Vec<ImportEntry>,
    /// Networks of the list whose value failed the URL check.
    pub rejected: Vec<NetworkId>,
    /// Keys that are not a network of the URL list.
    pub ignored: usize,
    /// One `QuickNode` endpoint name + token behind every URL, both wiped on drop (2026-11-22,
    /// S4c W13, critique B-5: before, the name was a plain `String`). Since the W13 review
    /// (2026-11-22) the entries' URLs, which hold the same name and token, are wiped too
    /// ([`ImportEntry::url`]); the W13 note here said they stayed `HttpsUrl`s "the type
    /// `ApiKeys` stores them in", which was wrong: `ApiKeys` keeps wiped strings.
    pub quicknode: Option<(Zeroizing<String>, Zeroizing<String>)>,
}

/// Counts only (2026-11-22, S4c W13, critique B-5): before, it also listed the accepted
/// networks and the rejected ones by id.
impl fmt::Debug for ImportPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ImportPlan")
            .field("entries", &self.entries.len())
            .field("rejected", &self.rejected.len())
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
                url: Zeroizing::new(url.expose().to_owned()),
                provider,
                fits_template: false,
            }),
            None => plan.rejected.push(network),
        }
    }
    drop(value);
    // Every endpoint name is wiped as soon as it is parsed (2026-11-22, S4c W13 review; before,
    // the names `parse_quicknode_url` returns were dropped as plain `String`s).
    let mut credentials = plan.entries.iter().map(|entry| {
        parse_quicknode_url(&entry.url).map(|(name, token)| (Zeroizing::new(name), token))
    });
    let first = credentials.next().flatten();
    if let Some(first) = first
        && credentials.all(|other| other.as_ref() == Some(&first))
    {
        let cred = TemplateCred::QuickNode {
            name: (*first.0).clone(),
            token: first.1.clone(),
        };
        for entry in &mut plan.entries {
            let wanted = template_entry(RpcTemplate::QuickNode, entry.network, settings);
            // The same comparison as `HttpsUrl`'s before: both texts are normalized, and an
            // `HttpsUrl` is a function of its normalized text.
            entry.fits_template = template_url(RpcTemplate::QuickNode, &cred, wanted.as_ref())
                .is_some_and(|url| url.expose() == entry.url.as_str());
        }
        // yw-engine's `TemplateCred` keeps the name as a plain `String`: wiped here.
        if let TemplateCred::QuickNode { name, .. } = cred {
            drop(Zeroizing::new(name));
        }
        plan.quicknode = Some(first);
    }
    Ok(plan)
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
        // The entry holds `HttpsUrl::expose` text, which parses back to the same `HttpsUrl`
        // (2026-11-22, S4c W13 review), so this never skips one.
        let Ok(url) = HttpsUrl::parse(&entry.url) else {
            continue;
        };
        keys.set_rpc(entry.network, &url);
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

impl Wallet {
    /// `취소` of the confirmation list: the plan is dropped (its credentials wiped).
    pub(crate) fn rpc_import_cancel(&mut self) {
        self.rpc_import = RpcImportUi::default();
        self.refresh();
    }

    /// `rpc.json 지우기…` (`ask`) or its `취소`: whether the delete waits for its confirmation.
    pub(crate) fn rpc_json_delete_asked(&mut self, ask: bool) {
        self.rpc_import.confirm_delete = ask;
        self.refresh();
    }
}

impl Wallet {
    /// The wallet's half of `rpc.json 지우기` (2026-11-22, S4c W13, critique B-5): the shell
    /// deleted the file, `deleted` is the result; the band says what happened.
    pub(crate) fn on_rpc_json_deleted(&mut self, deleted: Result<(), DeleteError>) {
        self.rpc_import.confirm_delete = false;
        let message = match deleted {
            Ok(()) => {
                logging::info("app", "rpc.import_file_deleted", &[]);
                self.rpc_import.imported = false;
                text::DELETED
            }
            Err(error) => {
                logging::info("app", "rpc.import_file_delete_failed", &[]);
                match error {
                    DeleteError::NotPlainFile => text::DELETE_LINK,
                    DeleteError::Failed => text::DELETE_FAILED,
                }
            }
        };
        self.info = Some(message.get(self.settings.language).to_owned());
        self.refresh();
    }
}

impl Wallet {
    /// The typed in-process entry of critique B-5 (2026-11-22, S4c W13): the plan the shell
    /// parsed from `rpc.json` (or why it gave none) enters the wallet here and waits in the
    /// import state for `가져오기`/`덮어쓰기`/`비어 있는 네트워크만` ([`Self::finish_rpc_import`],
    /// which applies it, saves, fills the template's gaps and queues the tests in that order)
    /// or `취소`. Never a `Cmd` or an `Effect`; the log line carries counts only.
    pub(crate) fn on_rpc_json_read(&mut self, read: Result<ImportPlan, ImportError>) {
        self.rpc_import = RpcImportUi::default();
        match read {
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
                    let mut message = text::NOTHING_TO_IMPORT
                        .get(self.settings.language)
                        .to_owned();
                    self.push_rejected(&mut message, &plan);
                    self.info = Some(message);
                } else {
                    self.info = None;
                    self.rpc_import.plan = Some(plan);
                }
            }
            Err(error) => {
                logging::info("app", "rpc.import_failed", &[]);
                self.info = Some(error.text(self.settings.language).to_owned());
            }
        }
        self.refresh();
    }

    /// `덮어쓰기` / `가져오기` (`overwrite`) or `비어 있는 네트워크만`. 2026-11-22 (S4c W13,
    /// critique B-5): wallet code, the confirmation of the plan that entered through
    /// `on_rpc_json_read` and waits in the wallet's import state (B-5 keeps the plan there, so
    /// it enters once, at the read, not again with `overwrite`): `apply_plan`, `save_apikeys`,
    /// `save_settings`, `fill_template_gaps`, `queue_rpc_tests` in today's order, unchanged.
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
        let lang = self.settings.language;
        let mut message = text::IMPORTED.fill(lang, [&applied.written.len().to_string()]);
        if !applied.kept.is_empty() {
            message.push_str(&text::IMPORTED_KEPT.fill(lang, [&applied.kept.len().to_string()]));
        }
        message.push('.');
        if applied.template {
            message.push_str(text::IMPORTED_TEMPLATE.get(lang));
        }
        if applied.template && self.settings.rpc_template != RpcTemplate::QuickNode {
            let mut settings = self.settings.clone();
            settings.rpc_template = RpcTemplate::QuickNode;
            self.save_settings(settings, "rpc.template");
        }
        // The networks the file did not list get the template's address (2026-11-11): one
        // QuickNode URL is enough for every chain.
        let filled = self.fill_template_gaps();
        if !filled.is_empty() {
            message.push_str(&text::FILLED.fill(lang, [&filled.len().to_string()]));
        }
        // Every imported or made address is tested in turn (2026-11-10).
        if !applied.written.is_empty() || !filled.is_empty() {
            message.push_str(text::TESTING.get(lang));
        }
        message.push(' ');
        message.push_str(text::IMPORT_KEPT.get(lang));
        self.info = Some(message);
        self.queue_rpc_tests(&applied.written);
        self.queue_rpc_tests(&filled);
        // The plaintext source is still there: the card moves up and recommends deleting it.
        self.rpc_import.imported = true;
        self.refresh();
    }

    pub(crate) fn push_rejected(&self, message: &mut String, plan: &ImportPlan) {
        let lang = self.settings.language;
        if !plan.rejected.is_empty() {
            let names: Vec<String> = plan
                .rejected
                .iter()
                .map(|network| format!("{} ({network})", self.network_name(*network)))
                .collect();
            message.push_str(&text::REJECTED.fill(lang, [&names.join(", ")]));
        }
        if plan.ignored > 0 {
            message.push_str(&text::IGNORED.fill(lang, [&plan.ignored.to_string()]));
        }
    }
}

fn len_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

/// The wallet's `rpc.json` import texts (spec/04 §2.11). 2026-11-23 (S4d E0b): the entries the
/// wallet part uses moved here from `app_rpc_import::text` (wording unchanged); the card's other
/// texts stay there.
pub mod text {
    yw_core::texts! {
        /// 2026-11-23 (S4d E0b): was `app_rpc_import::text`.
        ALCHEMY = "알케미" / "Alchemy";
        /// 2026-11-23 (S4d E0b): was `app_rpc_import::text`.
        DELETED = "rpc.json을 지웠습니다. 앱에 저장한 RPC 주소는 그대로입니다."
            / "rpc.json was deleted. The RPC addresses saved in the app stay.";
        /// 2026-11-23 (S4d E0b): was `app_rpc_import::text`.
        DELETE_FAILED = "rpc.json을 지우지 못했습니다. 다른 프로그램이 열고 있거나 권한이 없습니다. 탐색기에서 직접 지우세요."
            / "rpc.json could not be deleted. Another program has it open or there is no permission. Delete it yourself in Explorer.";
        /// 2026-11-23 (S4d E0b): was `app_rpc_import::text`.
        DELETE_LINK = "rpc.json이 링크(심볼릭 링크)이거나 파일이 아니라 지우지 않았습니다. 링크가 가리키는 파일에 토큰이 있으니 탐색기에서 확인해 직접 지우세요."
            / "rpc.json is a link (symbolic link) or not a file, so it was not deleted. The file the link points to holds the tokens; check it in Explorer and delete it yourself.";
        /// 2026-11-23 (S4d E0b): was `app_rpc_import::text`.
        FILLED(1) = " 파일에 없던 {0}개 네트워크는 저장된 RPC 공급자 템플릿으로 주소를 만들었습니다."
            / " For {0} networks not in the file, addresses were made from the saved RPC provider template.";
        /// 2026-11-23 (S4d E0b): was `app_rpc_import::text`.
        FORMAT = "rpc.json 형식이 올바르지 않습니다. UTF-8 JSON 객체 하나({\"eip155:1\": \"https://…\", …} 모양, 같은 키 두 번 금지)여야 합니다."
            / "rpc.json is not in the right format. It must be one UTF-8 JSON object (shaped like {\"eip155:1\": \"https://…\", …}, no key twice).";
        /// 2026-11-23 (S4d E0b): was `app_rpc_import::text`.
        IGNORED(1) = "\n이 앱의 네트워크 목록에 없는 키 {0}개는 건너뜁니다."
            / "\n{0} keys that are not in this app's network list are skipped.";
        /// 2026-11-23 (S4d E0b): was `app_rpc_import::text`.
        IMPORTED(1) = "rpc.json에서 RPC 주소 {0}개를 가져왔습니다"
            / "Imported {0} RPC addresses from rpc.json";
        /// 2026-11-23 (S4d E0b): was `app_rpc_import::text`.
        IMPORTED_KEPT(1) = "(이미 주소가 있는 {0}개는 그대로 두었습니다)"
            / " ({0} that already had an address were left as is)";
        /// 2026-11-23 (S4d E0b): was `app_rpc_import::text`.
        IMPORTED_TEMPLATE = " 모두 같은 QuickNode 엔드포인트라 RPC 공급자를 'QuickNode 멀티체인'으로 하고 이름·토큰을 템플릿 자격 정보로 저장했습니다."
            / " They all use the same QuickNode endpoint, so the RPC provider was set to 'QuickNode multichain' and the name and token were saved as the template credentials.";
        /// The persistence note of the import result (the data folder survives `install.cmd`,
        /// `uninstall.cmd` without `-RemoveWalletData`, and a default `지갑 초기화`).
        /// 2026-11-23 (S4d E0b): was `app_rpc_import::text`.
        IMPORT_KEPT = "주소는 %LOCALAPPDATA%\\YourWallet\\v3\\apikeys.dpapi에 이 Windows 사용자만 풀 수 있게 암호화해 저장했습니다. 재설치해도 유지됩니다. 지갑 초기화 때 '설정과 API 키도 함께 옮기기'를 켜지 않으면 그대로 남습니다."
            / "The addresses are saved in %LOCALAPPDATA%\\YourWallet\\v3\\apikeys.dpapi, encrypted so that only this Windows user can open them. They stay after a reinstall. A wallet reset leaves them in place unless 'Also move settings and API keys' is on.";
        /// 2026-11-23 (S4d E0b): was `app_rpc_import::text`.
        NOTHING_TO_IMPORT = "rpc.json에 가져올 수 있는 RPC 주소가 없습니다."
            / "rpc.json has no RPC addresses that can be imported.";
        /// 2026-11-23 (S4d E0b): was `app_rpc_import::text`.
        REJECTED(1) = "\n가져오지 않음(https QuickNode·알케미 주소가 아니거나 형식 오류): {0}"
            / "\nNot imported (not an https QuickNode or Alchemy address, or a format error): {0}";
        /// 2026-11-23 (S4d E0b): was `app_rpc_import::text`.
        TESTING = " 연결을 확인하는 중입니다 — 결과는 아래 각 행에 나옵니다."
            / " Checking the connections — the results appear in each row below.";
        /// 2026-11-23 (S4d E0b): was `app_rpc_import::text`.
        UNREADABLE = "rpc.json을 읽을 수 없습니다. 파일이 없거나, 64 KiB보다 크거나, 바로가기·링크입니다."
            / "rpc.json cannot be read. The file is missing, larger than 64 KiB, or a shortcut or link.";
    }
}
