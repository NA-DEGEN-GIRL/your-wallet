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

use yw_core::lang::{Lang, Text};
use yw_core::secret::Zeroizing;
use yw_platform::http::HttpsUrl;
use yw_win::file::read_limited_no_reparse;

use crate::apikeys::{
    ApiKeys, KeyName, TemplateCred, parse_quicknode_url, template_entry, template_url,
    valid_provider_token,
};
use crate::app::{App, Wallet};
use crate::logging::{self, Field};
use crate::network::NetworkId;
use crate::settings::{RpcTemplate, Settings};
use crate::text::is_dns_label;
use crate::ui::main_window::{Ctl, Item, Tone};
use yw_engine::cmd::RpcImportPress;

/// Largest `rpc.json` (spec/01 §4.6).
pub const RPC_JSON_MAX: u64 = 65_536;

const LIMITS: yw_json::Limits = yw_json::Limits {
    max_bytes: 65_536,
    max_depth: 4,
    max_nodes: 512,
    max_items: 256,
};

/// The S15 `rpc.json에서 가져오기` texts (spec/04 §2.11).
pub mod text {
    yw_core::texts! {
        /// The persistence note of the import result (the data folder survives `install.cmd`,
        /// `uninstall.cmd` without `-RemoveWalletData`, and a default `지갑 초기화`).
        IMPORT_KEPT = "주소는 %LOCALAPPDATA%\\YourWallet\\v3\\apikeys.dpapi에 이 Windows 사용자만 풀 수 있게 암호화해 저장했습니다. 재설치해도 유지됩니다. 지갑 초기화 때 '설정과 API 키도 함께 옮기기'를 켜지 않으면 그대로 남습니다."
            / "The addresses are saved in %LOCALAPPDATA%\\YourWallet\\v3\\apikeys.dpapi, encrypted so that only this Windows user can open them. They stay after a reinstall. A wallet reset leaves them in place unless 'Also move settings and API keys' is on.";
        /// The card's note on the source file (before an import).
        JSON_PLAINTEXT = "이 파일에는 RPC 주소와 그 토큰이 암호화되지 않은 채 들어 있어, 이 Windows 사용자로 도는 다른 프로그램도 읽을 수 있습니다. 가져온 뒤 개발 스크립트에 더 쓰지 않으면 지우세요."
            / "This file holds RPC addresses and their tokens unencrypted, so other programs running as this Windows user can read it. After importing, delete it unless development scripts still need it.";
        /// The card's warning right after an import.
        JSON_LEFT = "가져오기를 마쳤습니다. 앱에는 암호화해 저장했지만 rpc.json에는 같은 주소·토큰이 암호화되지 않은 채 남아 있습니다. 개발 스크립트(probe-rpc 등)에 더 쓰지 않으면 지우세요."
            / "Import finished. The app saved them encrypted, but rpc.json still holds the same addresses and tokens unencrypted. Delete it unless development scripts (probe-rpc and others) still need it.";
        /// The delete confirmation.
        JSON_DELETE_CONFIRM = "rpc.json을 지웁니다. 휴지통으로 가지 않아 되돌릴 수 없습니다. 앱에 저장한 RPC 주소는 그대로이고, 개발 스크립트가 이 파일을 쓴다면 scripts\\dev-rpc-setup.ps1로 다시 만들어야 합니다."
            / "rpc.json will be deleted. It does not go to the Recycle Bin, so this cannot be undone. The RPC addresses saved in the app stay; if development scripts use this file, recreate it with scripts\\dev-rpc-setup.ps1.";
        UNREADABLE = "rpc.json을 읽을 수 없습니다. 파일이 없거나, 64 KiB보다 크거나, 바로가기·링크입니다."
            / "rpc.json cannot be read. The file is missing, larger than 64 KiB, or a shortcut or link.";
        FORMAT = "rpc.json 형식이 올바르지 않습니다. UTF-8 JSON 객체 하나({\"eip155:1\": \"https://…\", …} 모양, 같은 키 두 번 금지)여야 합니다."
            / "rpc.json is not in the right format. It must be one UTF-8 JSON object (shaped like {\"eip155:1\": \"https://…\", …}, no key twice).";
        ALCHEMY = "알케미" / "Alchemy";
        DELETED = "rpc.json을 지웠습니다. 앱에 저장한 RPC 주소는 그대로입니다."
            / "rpc.json was deleted. The RPC addresses saved in the app stay.";
        DELETE_LINK = "rpc.json이 링크(심볼릭 링크)이거나 파일이 아니라 지우지 않았습니다. 링크가 가리키는 파일에 토큰이 있으니 탐색기에서 확인해 직접 지우세요."
            / "rpc.json is a link (symbolic link) or not a file, so it was not deleted. The file the link points to holds the tokens; check it in Explorer and delete it yourself.";
        DELETE_FAILED = "rpc.json을 지우지 못했습니다. 다른 프로그램이 열고 있거나 권한이 없습니다. 탐색기에서 직접 지우세요."
            / "rpc.json could not be deleted. Another program has it open or there is no permission. Delete it yourself in Explorer.";
        NOTHING_TO_IMPORT = "rpc.json에 가져올 수 있는 RPC 주소가 없습니다."
            / "rpc.json has no RPC addresses that can be imported.";
        IMPORTED(1) = "rpc.json에서 RPC 주소 {0}개를 가져왔습니다"
            / "Imported {0} RPC addresses from rpc.json";
        IMPORTED_KEPT(1) = "(이미 주소가 있는 {0}개는 그대로 두었습니다)"
            / " ({0} that already had an address were left as is)";
        IMPORTED_TEMPLATE = " 모두 같은 QuickNode 엔드포인트라 RPC 공급자를 'QuickNode 멀티체인'으로 하고 이름·토큰을 템플릿 자격 정보로 저장했습니다."
            / " They all use the same QuickNode endpoint, so the RPC provider was set to 'QuickNode multichain' and the name and token were saved as the template credentials.";
        FILLED(1) = " 파일에 없던 {0}개 네트워크는 저장된 RPC 공급자 템플릿으로 주소를 만들었습니다."
            / " For {0} networks not in the file, addresses were made from the saved RPC provider template.";
        TESTING = " 연결을 확인하는 중입니다 — 결과는 아래 각 행에 나옵니다."
            / " Checking the connections — the results appear in each row below.";
        REJECTED(1) = "\n가져오지 않음(https QuickNode·알케미 주소가 아니거나 형식 오류): {0}"
            / "\nNot imported (not an https QuickNode or Alchemy address, or a format error): {0}";
        IGNORED(1) = "\n이 앱의 네트워크 목록에 없는 키 {0}개는 건너뜁니다."
            / "\n{0} keys that are not in this app's network list are skipped.";
        CARD_TITLE = "rpc.json에서 가져오기" / "Import from rpc.json";
        CARD_HELP = "개발용 설정 파일(%USERPROFILE%\\.yw-dev\\rpc.json)에 있는 RPC 주소를 읽어 위 '네트워크별 RPC 주소' 목록에 넣습니다. 저장하기 전에 가린 목록으로 한 번 더 확인합니다."
            / "Reads the RPC addresses in the development settings file (%USERPROFILE%\\.yw-dev\\rpc.json) into the 'RPC address per network' list above. A masked list is shown for one more check before saving.";
        DELETE = "지우기" / "Delete";
        CANCEL = "취소" / "Cancel";
        IMPORT_BUTTON = "rpc.json에서 가져오기" / "Import from rpc.json";
        DELETE_FILE = "rpc.json 지우기…" / "Delete rpc.json…";
        CONFIRM_TITLE = "rpc.json에서 가져오기 — 확인" / "Import from rpc.json — confirm";
        CONFIRM_LEAD = "다음 RPC 주소를 가져옵니다(주소에는 토큰이 있어 가린 형태로만 보입니다):"
            / "These RPC addresses will be imported (they contain tokens, so they are shown masked only):";
        HAS_ADDRESS = " — 기존 주소 있음" / " — has an address already";
        OFF_TEMPLATE = " — 템플릿과 다른 주소(이 네트워크에 그대로 저장)"
            / " — differs from the template (saved as is for this network)";
        SAME_ENDPOINT = "모든 주소가 같은 QuickNode 엔드포인트(이름·토큰)입니다. RPC 공급자를 'QuickNode 멀티체인'으로 바꾸고 이름·토큰을 템플릿 자격 정보로 함께 저장합니다."
            / "All addresses use the same QuickNode endpoint (name and token). The RPC provider is changed to 'QuickNode multichain' and the name and token are saved as the template credentials too.";
        EXISTING(1) = "이미 주소가 있는 네트워크가 {0}개 있습니다. 덮어쓰거나, 비어 있는 네트워크에만 넣을 수 있습니다."
            / "{0} networks already have an address. You can overwrite them or fill only the empty networks.";
        OVERWRITE = "덮어쓰기" / "Overwrite";
        FILL_EMPTY = "비어 있는 네트워크만" / "Empty networks only";
        IMPORT = "가져오기" / "Import";
        SAVE_NOTE = "저장은 '교체'와 같습니다: Windows가 이 사용자 계정에서만 풀 수 있게 암호화해 apikeys.dpapi에 둡니다."
            / "Saving works like 'Replace': Windows encrypts it so only this user account can open it, in apikeys.dpapi.";
    }
}

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
    const fn label(self, lang: Lang) -> &'static str {
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
    pub(crate) fn on_rpc_import(&mut self, press: RpcImportPress) {
        match press {
            RpcImportPress::Import => {
                if let Some(path) = rpc_json_path() {
                    self.begin_rpc_import(&path);
                }
            }
            RpcImportPress::Overwrite => self.finish_rpc_import(true),
            RpcImportPress::Fill => self.finish_rpc_import(false),
            RpcImportPress::Cancel => self.rpc_import_cancel(),
            RpcImportPress::Delete | RpcImportPress::DeleteCancel => {
                self.rpc_json_delete_asked(press == RpcImportPress::Delete);
            }
            RpcImportPress::DeleteConfirm => {
                if let Some(path) = rpc_json_path() {
                    self.delete_rpc_json(&path);
                }
            }
        }
    }
}

impl Wallet {
    /// `취소` of the confirmation list: the plan is dropped (its credentials wiped).
    fn rpc_import_cancel(&mut self) {
        self.rpc_import = RpcImportUi::default();
        self.refresh();
    }

    /// `rpc.json 지우기…` (`ask`) or its `취소`: whether the delete waits for its confirmation.
    fn rpc_json_delete_asked(&mut self, ask: bool) {
        self.rpc_import.confirm_delete = ask;
        self.refresh();
    }
}

impl App {
    /// Test adapter (S3 C5, plan §3.2): presses an import-card control `id` directly, as the
    /// module tests did before; `false` when `id` is not one.
    #[cfg(test)]
    pub(crate) fn on_rpc_import_command(&mut self, id: u16) -> bool {
        self.press_family(
            id,
            |press| match press {
                yw_engine::cmd::Press::RpcImport(press) => Some(press),
                _ => None,
            },
            |app, press| {
                app.on_rpc_import(press);
                true
            },
        )
    }

    /// `rpc.json 지우기` confirmed: deletes the file (never a link) and says what happened.
    /// 2026-11-22 (S4c W13, critique B-5): the shell's half, the delete; the wallet's half,
    /// `on_rpc_json_deleted`, takes its result. Before, this fn did both and cleared the
    /// confirmation before the delete (now right after it: nothing reads it in between).
    pub(crate) fn delete_rpc_json(&mut self, path: &Path) {
        let deleted = delete_file(path);
        self.on_rpc_json_deleted(deleted);
    }
}

impl Wallet {
    /// The wallet's half of `rpc.json 지우기` (2026-11-22, S4c W13, critique B-5): the shell
    /// deleted the file, `deleted` is the result; the band says what happened.
    fn on_rpc_json_deleted(&mut self, deleted: Result<(), DeleteError>) {
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

impl App {
    /// Reads `path` and shows the confirmation list (or a fixed error text).
    /// 2026-11-22 (S4c W13, critique B-5): the shell's half, the read; the plan (or the read
    /// error) enters the wallet through `on_rpc_json_read`. Before, this fn did both and
    /// reset the import state before the read (now right after it: the read takes the networks
    /// and settings only, never that state).
    pub(crate) fn begin_rpc_import(&mut self, path: &Path) {
        let read = read_plan(path, &self.url_networks(), &self.settings);
        self.on_rpc_json_read(read);
    }
}

impl Wallet {
    /// The typed in-process entry of critique B-5 (2026-11-22, S4c W13): the plan the shell
    /// parsed from `rpc.json` (or why it gave none) enters the wallet here and waits in the
    /// import state for `가져오기`/`덮어쓰기`/`비어 있는 네트워크만` ([`Self::finish_rpc_import`],
    /// which applies it, saves, fills the template's gaps and queues the tests in that order)
    /// or `취소`. Never a `Cmd` or an `Effect`; the log line carries counts only.
    fn on_rpc_json_read(&mut self, read: Result<ImportPlan, ImportError>) {
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

    fn push_rejected(&self, message: &mut String, plan: &ImportPlan) {
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

impl App {
    /// The `rpc.json에서 가져오기` card of settings → 네트워크(RPC) ([`RpcImportUi::on_top`]):
    /// shown only when the file exists or a plan waits for confirmation.
    pub(crate) fn rpc_import_section(&self, items: &mut Vec<Item>) {
        use crate::ui::screens::ids;
        let lang = self.settings.language;
        let t = |entry: Text| entry.get(lang).to_owned();
        let Some(plan) = self.rpc_import.plan.as_ref() else {
            if rpc_json_path().is_some_and(|path| path.is_file()) {
                items.push(Item::CardStart(Some(t(text::CARD_TITLE))));
                if !self.rpc_import.imported {
                    items.push(Item::Help(t(text::CARD_HELP)));
                    items.push(Item::Help(t(text::JSON_PLAINTEXT)));
                }
                if self.rpc_import.confirm_delete {
                    items.push(Item::Banner(t(text::JSON_DELETE_CONFIRM), Tone::Warn));
                    items.push(Item::Row(vec![
                        Ctl::danger(ids::RPC_JSON_DELETE_CONFIRM, text::DELETE.get(lang)),
                        Ctl::button(ids::RPC_JSON_DELETE_CANCEL, text::CANCEL.get(lang)),
                    ]));
                } else {
                    if self.rpc_import.imported {
                        items.push(Item::Banner(t(text::JSON_LEFT), Tone::Warn));
                    }
                    items.push(Item::Row(vec![
                        Ctl::button(ids::RPC_IMPORT, text::IMPORT_BUTTON.get(lang)),
                        Ctl::button(ids::RPC_JSON_DELETE, text::DELETE_FILE.get(lang)),
                    ]));
                }
                items.push(Item::CardEnd);
            }
            return;
        };
        items.push(Item::CardStart(Some(t(text::CONFIRM_TITLE))));
        let mut list = t(text::CONFIRM_LEAD);
        let mut existing = 0_usize;
        for entry in &plan.entries {
            let has = self.apikeys.has(KeyName::Rpc(entry.network));
            if has {
                existing = existing.saturating_add(1);
            }
            let _ = write!(
                list,
                "\n· {} ({}) — {} …/****{}{}",
                self.network_name(entry.network),
                entry.network,
                entry.provider.label(lang),
                if has { text::HAS_ADDRESS.get(lang) } else { "" },
                if plan.quicknode.is_some() && !entry.fits_template {
                    text::OFF_TEMPLATE.get(lang)
                } else {
                    ""
                },
            );
        }
        self.push_rejected(&mut list, plan);
        items.push(Item::Text(list));
        if plan.quicknode.is_some() {
            items.push(Item::Help(t(text::SAME_ENDPOINT)));
        }
        if existing > 0 {
            items.push(Item::Banner(
                text::EXISTING.fill(lang, [&existing.to_string()]),
                Tone::Warn,
            ));
            items.push(Item::Row(vec![
                Ctl::button(ids::RPC_IMPORT_OVERWRITE, text::OVERWRITE.get(lang)),
                Ctl::button(ids::RPC_IMPORT_FILL, text::FILL_EMPTY.get(lang)),
                Ctl::button(ids::RPC_IMPORT_CANCEL, text::CANCEL.get(lang)),
            ]));
        } else {
            items.push(Item::Row(vec![
                Ctl::button(ids::RPC_IMPORT_OVERWRITE, text::IMPORT.get(lang)),
                Ctl::button(ids::RPC_IMPORT_CANCEL, text::CANCEL.get(lang)),
            ]));
        }
        items.push(Item::Help(t(text::SAVE_NOTE)));
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
        let state = super::RpcImportUi {
            plan: Some(plan),
            ..super::RpcImportUi::default()
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
