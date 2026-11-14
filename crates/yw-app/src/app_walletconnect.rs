//! `WalletConnect` on the UI thread (spec/13 §6–§8): the worker's lifetime, the session list and
//! its persistence in meta, the pairing inputs (pasted URI, clipboard screenshot, image file),
//! and the hooks that show a session's self-claimed origin in the connect and approval windows
//! (`WalletConnect: {url} (사이트가 주장한 주소 — 확인되지 않음)`) with the Verify warnings.

use std::sync::Arc;

use yw_core::approval::{
    ApprovalDisplay, ApprovalDraft, ApprovalOrigin, DisplayField, FieldKey, MAX_DISPLAY_WARNINGS,
};
use yw_core::policy::{BrowserOrigin, ProviderError};

use crate::app::App;
use crate::browser::{SiteRequest, VaultView};
use crate::logging::{self, Field};
use crate::walletconnect::engine::ProposalView;
use crate::walletconnect::store::WcStore;
use crate::walletconnect::worker::{
    ProposalEnd, RelayStatus, SessionView, WcCommand, WcEvent, WcHandle,
};
use crate::walletconnect::{Metadata, VerifyStatus, is_session_origin};

/// The panel texts of the UI side (spec/13 §6; English spec/14).
pub mod text {
    yw_core::texts! {
        PROPOSAL_ARRIVED = "연결 요청이 도착했습니다 — 연결 창을 확인하세요."
            / "A connection request arrived — check the connection window.";
        REFUSED_WHILE_LOCKED(1) = "지갑이 잠겨 있는 동안 WalletConnect 요청 {0}개를 거절했습니다(잠금 해제 창은 열지 않습니다). 필요하면 dApp에서 다시 요청하세요."
            / "Refused {0} WalletConnect requests while the wallet was locked (no unlock window is opened). Request again from the dApp if needed.";
        END_CONNECTED = "연결을 승인했습니다. 아래 WalletConnect 세션 카드에서 확인하세요."
            / "Connection approved. See the WalletConnect session card below.";
        END_TOO_LATE = "연결 요청이 그 사이 만료되어 연결하지 않았습니다. dApp에서 다시 연결하세요."
            / "The connection request expired in the meantime, so nothing was connected. Connect again from the dApp.";
        END_LOCKED = "지갑이 잠겨 있어 연결 요청을 거절했습니다(잠금 해제 창은 열지 않습니다). 잠금을 해제한 뒤 dApp에서 다시 연결하세요."
            / "The connection request was refused because the wallet is locked (no unlock window is opened). Unlock, then connect again from the dApp.";
        END_REJECTED = "연결 요청을 거절했습니다." / "Connection request rejected.";
        END_EXPIRED = "연결 창의 시간이 지나 연결하지 않았습니다. dApp에서 다시 연결하세요."
            / "The connection window timed out, so nothing was connected. Connect again from the dApp.";
        END_NO_EVM = "지갑에 EVM 계정이 없어 연결할 수 없습니다. EVM 개인키를 가져온 뒤 dApp에서 다시 연결하세요."
            / "The wallet has no EVM account, so it cannot connect. Import an EVM private key, then connect again from the dApp.";
        END_PASSPHRASE = "확인되지 않은 passphrase로 연 지갑이라 연결할 수 없습니다. 잠근 뒤 올바른 passphrase로 다시 여세요."
            / "The wallet was opened with an unverified passphrase, so it cannot connect. Lock it and open it again with the correct passphrase.";
        END_TOO_MANY_SITES = "연결된 사이트가 이미 256개라 연결하지 않았습니다. 연결된 사이트에서 하나를 해제한 뒤 dApp에서 다시 연결하세요."
            / "256 sites are already connected, so nothing was connected. Disconnect one in Connected sites, then connect again from the dApp.";
        END_FAILED(1) = "연결 요청을 처리하지 못했습니다 (코드 {0}). dApp에서 다시 연결하세요."
            / "The connection request could not be handled (code {0}). Connect again from the dApp.";
        PAIR_NO_PROJECT = "먼저 Reown Project ID를 저장하세요. dashboard.reown.com에서 무료 프로젝트를 만들면 ID를 받을 수 있습니다."
            / "Save a Reown Project ID first. You get one by creating a free project at dashboard.reown.com.";
        PAIR_LOCKED = "지갑 잠금을 해제한 뒤 연결하세요." / "Unlock the wallet, then connect.";
        QR_NOT_WC = "QR을 읽었지만 WalletConnect 연결 주소(wc:)가 아닙니다."
            / "The QR code was read, but it is not a WalletConnect link (wc:).";
        QR_NOT_FOUND = "이미지에서 QR 코드를 찾지 못했습니다. QR 전체가 보이게 캡처했는지 확인하세요."
            / "No QR code was found in the image. Check that the capture shows the whole QR code.";
        CLIPBOARD_FORMAT = "클립보드 이미지 형식을 읽을 수 없습니다."
            / "The clipboard image format cannot be read.";
        CLIPBOARD_NO_IMAGE = "클립보드에 이미지가 없습니다. Win+Shift+S로 QR 부분을 캡처한 뒤 다시 누르세요."
            / "There is no image on the clipboard. Capture the QR code with Win+Shift+S, then press again.";
        CLIPBOARD_OPEN = "클립보드를 열 수 없습니다. 잠시 후 다시 시도하세요."
            / "Cannot open the clipboard. Try again in a moment.";
        FILE_EMPTY = "이미지 파일 경로를 입력하세요." / "Enter the image file path.";
        FILE_KIND = "PNG·JPEG·BMP·GIF 이미지 파일만 읽을 수 있습니다 (64 MB 이하)."
            / "Only PNG, JPEG, BMP and GIF image files can be read (64 MB or less).";
        FILE_OPEN = "이미지 파일을 열 수 없습니다 (PNG·JPEG·BMP·GIF)."
            / "Cannot open the image file (PNG, JPEG, BMP, GIF).";
        PROJECT_FORMAT = "Project ID는 32자리 16진수입니다(dashboard.reown.com 프로젝트의 Project ID)."
            / "The Project ID is 32 hex digits (the Project ID of your dashboard.reown.com project).";
        PROJECT_CLEARED = "Project ID를 지웠습니다. WalletConnect가 꺼집니다."
            / "Project ID removed. WalletConnect turns off.";
        PROJECT_SAVED = "Project ID를 저장했습니다." / "Project ID saved.";
        CLIPBOARD_LINK = "클립보드의 연결 주소(wc:)로 연결합니다."
            / "Connecting with the link (wc:) on the clipboard.";
    }
}

/// The starts of a `WalletConnect` pairing link: `wc:`, or the whole link percent-encoded
/// (`wc%3A…`, which the URI parser also takes); ASCII case ignored.
const PAIRING_LINK_STARTS: [&str; 2] = ["wc:", "wc%3a"];

/// Whether `text` starts like a pairing link (leading whitespace ignored).
#[must_use]
pub fn looks_like_pairing_link(text: &str) -> bool {
    let text = text.trim_start();
    PAIRING_LINK_STARTS.iter().any(|prefix| {
        text.get(..prefix.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
    })
}

/// [`looks_like_pairing_link`] on UTF-16 clipboard units (leading whitespace already skipped),
/// without copying any of them out of the wiped buffer.
#[must_use]
pub fn units_look_like_pairing_link(units: &[u16]) -> bool {
    PAIRING_LINK_STARTS.iter().any(|prefix| {
        units.len() >= prefix.len()
            && units.iter().zip(prefix.bytes()).all(|(unit, byte)| {
                u8::try_from(*unit).is_ok_and(|unit| unit.to_ascii_lowercase() == byte)
            })
    })
}

/// Largest clipboard bitmap read (bytes; a 4K screenshot is ≈ 33 MB).
pub const MAX_CLIPBOARD_IMAGE: usize = 80 * 1_048_576;

/// The UI-side state.
#[derive(Debug, Default)]
pub struct WcUi {
    /// The worker (started at the first unlock with a project id).
    pub handle: Option<WcHandle>,
    /// Relay state.
    pub status: RelayStatus,
    /// Sessions (worker snapshot).
    pub sessions: Vec<SessionView>,
    /// Proposals waiting for their connect window.
    pub proposals: Vec<ProposalView>,
    /// The last panel message.
    pub notice: Option<String>,
    /// The URI edit text.
    pub uri_text: String,
    /// The image path edit text.
    pub file_text: String,
    /// The project id edit text (`None`: the saved value).
    pub project_text: Option<String>,
    /// `Project ID 바꾸기 ▸` is open (a saved id is otherwise one read-only line).
    pub project_open: bool,
    /// `다른 방법 (이미지 파일) ▸` is open.
    pub file_open: bool,
    /// The topic behind each `연결 해제` row button as last drawn.
    pub rows: std::cell::RefCell<Vec<[u8; 32]>>,
}

impl App {
    /// The peer and Verify state of a session or pending proposal origin.
    pub(crate) fn wc_peer_of(&self, origin: &BrowserOrigin) -> Option<(Metadata, VerifyStatus)> {
        if !is_session_origin(origin) {
            return None;
        }
        let topic = crate::walletconnect::topic_of_origin(origin)?;
        self.wc
            .sessions
            .iter()
            .find(|s| s.topic == topic)
            .map(|s| (s.peer.clone(), s.verify))
            .or_else(|| {
                self.wc
                    .proposals
                    .iter()
                    .find(|p| p.session_topic == topic)
                    .map(|p| (p.peer.clone(), p.verify))
            })
    }

    /// The approval origin of a site request: for a `WalletConnect` session its claimed origin
    /// (so SIWE domain checks compare against what the dApp claims and the window says so), the
    /// site origin otherwise.
    pub(crate) fn site_approval_origin(&self, site: &SiteRequest) -> ApprovalOrigin {
        let claimed = self
            .wc_peer_of(&site.origin)
            .and_then(|(peer, _)| crate::walletconnect::claimed_origin(&peer.url));
        ApprovalOrigin::Site(claimed.unwrap_or_else(|| site.origin.clone()))
    }

    /// What an app notice calls the dApp of `origin`: a `WalletConnect` session's synthetic
    /// `….walletconnect.invalid` origin means nothing to the user (and looks like phishing), so
    /// its claimed origin label, or `WalletConnect dApp` once the session is gone (spec/13 §7);
    /// any other origin as it is.
    pub(crate) fn origin_display(&self, origin: &BrowserOrigin) -> String {
        if !is_session_origin(origin) {
            return origin.as_str().to_owned();
        }
        self.wc_peer_of(origin).map_or_else(
            || "WalletConnect dApp".to_owned(),
            |(peer, _)| crate::walletconnect::origin_label(self.approval_lang(), &peer),
        )
    }

    /// The origin text of a site request for logs-free display and the AI explanation input.
    pub(crate) fn site_origin_text(&self, site: &SiteRequest) -> String {
        self.wc_peer_of(&site.origin).map_or_else(
            || site.origin.as_str().to_owned(),
            |(peer, _)| crate::walletconnect::origin_label(self.approval_lang(), &peer),
        )
    }

    /// A draft about to be shown: a `WalletConnect` request gets the `WalletConnect: …` origin
    /// text and its Verify warning (C01–C04; mismatch and scam are high risk). The warning always
    /// gets a slot: at [`MAX_DISPLAY_WARNINGS`] the least severe one gives way. Returns `false`
    /// when the draft could not be decorated — the caller must not show it (fail closed: the
    /// bare claimed origin is never shown as if it were the site).
    #[must_use]
    pub(crate) fn wc_decorate_draft(
        &self,
        origin: Option<&BrowserOrigin>,
        draft: &mut ApprovalDraft,
    ) -> bool {
        let Some(origin) = origin else {
            return true;
        };
        if !is_session_origin(origin) {
            return true;
        }
        let Some((peer, verify)) = self.wc_peer_of(origin) else {
            // A session origin without its session (ended meanwhile): nothing to label it with.
            return false;
        };
        decorate(draft, &peer, verify)
    }

    /// What the connect window of a `WalletConnect` proposal shows instead of the synthetic
    /// origin: the origin label, the chains to approve and the Verify warning.
    pub(crate) fn wc_connect_patch(&self, origin: &BrowserOrigin) -> Option<ConnectPatch> {
        let topic = crate::walletconnect::topic_of_origin(origin)?;
        let proposal = self
            .wc
            .proposals
            .iter()
            .find(|p| p.session_topic == topic)?;
        let chains: Vec<String> = proposal
            .chains
            .iter()
            .map(|id| {
                self.settings
                    .evm_chain_name_in(self.settings.language, *id)
                    .map_or_else(
                        || format!("eip155:{id}"),
                        |name| format!("{name} (eip155:{id})"),
                    )
            })
            .collect();
        Some(ConnectPatch {
            proposal: proposal.clone(),
            chains: chains.join(", "),
        })
    }
}

/// Largest QR image file read (bytes).
pub const MAX_IMAGE_FILE: u64 = 64 * 1_048_576;

/// Whether `head` starts like a PNG, JPEG, BMP or GIF file.
#[must_use]
pub fn image_magic_ok(head: &[u8]) -> bool {
    head.starts_with(b"\x89PNG\r\n\x1a\n")
        || head.starts_with(&[0xFF, 0xD8, 0xFF])
        || head.starts_with(b"BM")
        || head.starts_with(b"GIF87a")
        || head.starts_with(b"GIF89a")
}

/// A regular file of at most [`MAX_IMAGE_FILE`] bytes with an accepted signature.
fn image_file_acceptable(path: &std::path::Path) -> bool {
    use std::io::Read as _;
    let Ok(file) = std::fs::File::open(path) else {
        return false;
    };
    let size_ok = file
        .metadata()
        .is_ok_and(|meta| meta.is_file() && meta.len() <= MAX_IMAGE_FILE);
    let mut head = [0_u8; 8];
    size_ok && file.take(8).read_exact(&mut head).is_ok() && image_magic_ok(&head)
}

/// [`App::wc_decorate_draft`] for a known peer.
#[must_use]
pub fn decorate(draft: &mut ApprovalDraft, peer: &Metadata, verify: VerifyStatus) -> bool {
    let lang = draft.display.lang;
    let label = crate::walletconnect::origin_label(lang, peer);
    let Ok(origin_field) = DisplayField::new(FieldKey::ORIGIN, "", label) else {
        return false;
    };
    let mut fields = draft.display.fields.clone();
    match fields.iter_mut().find(|f| f.key == FieldKey::ORIGIN) {
        Some(slot) => *slot = origin_field,
        None => return false,
    }
    let mut warnings = draft.display.warnings.clone();
    if warnings.len() >= MAX_DISPLAY_WARNINGS {
        yw_core::evm::risk::sort_warnings(&mut warnings);
        warnings.truncate(MAX_DISPLAY_WARNINGS - 1);
    }
    warnings.push(crate::walletconnect::verify_warning(lang, verify));
    match ApprovalDisplay::new(
        draft.display.lang,
        draft.display.title.clone(),
        fields,
        warnings,
    ) {
        Ok(display) => {
            draft.display = display;
            true
        }
        Err(_) => false,
    }
}

/// See [`App::wc_connect_patch`].
#[derive(Clone, Debug)]
pub struct ConnectPatch {
    proposal: ProposalView,
    chains: String,
}

impl ConnectPatch {
    /// Rewrites a connect view.
    pub fn apply(&self, view: &mut crate::ui::approval_view::ApprovalView) {
        use crate::ui::approval_view::{Block, Tone};
        use crate::walletconnect::text as wc_text;
        let lang = view.lang;
        let proposal = &self.proposal;
        // The origin line and title carry wallet-normalized text only; the self-claimed name
        // gets its own labelled field, and the Verify state only the badge and warning below.
        let label = crate::walletconnect::origin_label(lang, &proposal.peer);
        view.header = vec![(
            crate::ui::approval_text::CONNECT_ORIGIN
                .get(lang)
                .to_owned(),
            label.clone(),
        )];
        if let Some(Block::Title(title)) = view.blocks.first_mut() {
            title.clone_from(&label);
        }
        let (text, tone) = match proposal.verify {
            // What the Verify server reported, not a proof (a dApp outside a browser can obtain
            // it, spec/13 §7): a mild caution, never the plain "confirmed" tone.
            VerifyStatus::Valid => (wc_text::CONNECT_VALID, Tone::Warn),
            VerifyStatus::Unknown => (wc_text::CONNECT_UNKNOWN, Tone::Warn),
            VerifyStatus::Invalid => (wc_text::CONNECT_INVALID, Tone::Danger),
            VerifyStatus::Scam => (wc_text::CONNECT_SCAM, Tone::Danger),
        };
        let text = text.get(lang).to_owned();
        let at = view.blocks.len().min(1);
        view.blocks.insert(at, Block::Warning { text, tone });
        view.blocks.insert(
            at + 1,
            Block::Field {
                label: wc_text::SITE_NAME.get(lang).to_owned(),
                value: proposal.peer.display_name(lang),
                mono: false,
            },
        );
        for block in &mut view.blocks {
            if let Block::Field { label, value, .. } = block
                && label == crate::ui::approval_text::CONNECT_NETWORK.get(lang)
            {
                wc_text::NETWORKS.get(lang).clone_into(label);
                value.clone_from(&self.chains);
            }
        }
        if !proposal.unsupported_methods.is_empty() {
            view.blocks.push(Block::Muted(
                wc_text::UNSUPPORTED.fill(lang, [&proposal.unsupported_methods.join(", ")]),
            ));
        }
        if proposal.dropped_names > 0 {
            // Only a count: the names themselves are dApp text the wallet does not know.
            view.blocks.push(Block::Muted(
                wc_text::DROPPED.fill(lang, [&proposal.dropped_names.to_string()]),
            ));
        }
        view.badges
            .push(format!("Verify {}", proposal.verify.label(lang)));
    }
}

impl App {
    // ----- worker lifetime -------------------------------------------------------------

    fn wc_start(&mut self) {
        if self.wc.handle.is_some() {
            return;
        }
        let (Some(browser), Some(events)) = (self.browser.as_ref(), self.events.as_ref()) else {
            return;
        };
        let http = yw_win::http::Client::new(yw_win::http::Timeouts {
            resolve_ms: 5_000,
            connect_ms: 5_000,
            send_ms: 5_000,
            receive_ms: 5_000,
        })
        .ok()
        .map(|client| Box::new(client) as Box<dyn crate::walletconnect::verify::VerifyHttp + Send>);
        self.wc.handle = crate::walletconnect::worker::start(
            Arc::clone(&browser.core),
            Arc::clone(events) as Arc<dyn crate::walletconnect::worker::WcSink>,
            Box::new(crate::walletconnect::worker::WsConnector),
            http,
        );
        if self.wc.handle.is_none() {
            logging::warn("walletconnect", "worker.start_failed", &[]);
        }
    }

    fn wc_send(&self, command: WcCommand) {
        if let Some(handle) = self.wc.handle.as_ref() {
            let _ = handle.send(command);
        }
    }

    /// The dispatcher's grants were just written (any change): the worker brings every session
    /// in line with its grant (spec/13 §5.3) — sent after the change on this thread, so the
    /// worker reads the new grants, and after a connect window's answer, so a just-approved
    /// session already has its grant.
    pub(crate) fn wc_grants_changed(&self) {
        self.wc_send(WcCommand::SyncGrants);
    }

    /// The meta state, with a relay client key created (and saved) when a project id is set.
    fn wc_store(&mut self) -> Option<WcStore> {
        let meta = self.meta.as_mut()?;
        let mut store = WcStore::from_value(meta.chain_sites.walletconnect.as_ref());
        if store.client_seed.is_none() && !self.settings.walletconnect_project.is_empty() {
            let mut seed = yw_core::secret::Zeroizing::new([0_u8; 32]);
            yw_core::entropy::fill_random(seed.as_mut()).ok()?;
            store.client_seed = Some(seed);
            meta.chain_sites.walletconnect = Some(store.to_value());
            self.save_meta();
        }
        Some(store)
    }

    /// After every unlock with meta: start the worker (project id set), configure it and hand it
    /// the stored sessions (the worker keeps its live state on later unlocks).
    pub(crate) fn wc_after_unlock(&mut self) {
        if self.vault_view() != VaultView::Unlocked
            || (self.settings.walletconnect_project.is_empty() && self.wc.handle.is_none())
        {
            return;
        }
        self.wc_start();
        let Some(store) = self.wc_store() else {
            return;
        };
        let project = Some(self.settings.walletconnect_project.clone()).filter(|p| !p.is_empty());
        self.wc_send(WcCommand::Configure(project));
        self.wc_send(WcCommand::Load(Box::new(store)));
    }

    /// Shutdown: stop the worker (it closes the relay connection).
    pub(crate) fn wc_shutdown(&mut self) {
        if let Some(mut handle) = self.wc.handle.take() {
            let _ = handle.send(WcCommand::Shutdown);
            if let Some(thread) = handle.thread.take() {
                let deadline = yw_win::time::monotonic_ms().saturating_add(1_000);
                while !thread.is_finished() && yw_win::time::monotonic_ms() < deadline {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                if thread.is_finished() {
                    let _ = thread.join();
                }
            }
        }
    }

    /// A worker event.
    pub(crate) fn on_wc_event(&mut self, event: WcEvent) {
        match event {
            WcEvent::Status(status) => self.wc.status = status,
            WcEvent::Notice(notice) => {
                self.wc.notice = Some(notice.text(self.settings.language));
            }
            WcEvent::Proposal(view) => {
                self.wc
                    .proposals
                    .retain(|p| p.session_topic != view.session_topic);
                if self.wc.proposals.len() >= crate::walletconnect::engine::MAX_PROPOSALS {
                    self.wc.proposals.remove(0);
                }
                self.wc.proposals.push(*view);
                self.wc.notice = Some(
                    text::PROPOSAL_ARRIVED
                        .get(self.settings.language)
                        .to_owned(),
                );
            }
            WcEvent::ProposalDone(topic, end) => {
                self.wc.proposals.retain(|p| p.session_topic != topic);
                // "연결 요청이 도착했습니다" never outlives its window (or a refusal that opened
                // none): the panel says how it ended.
                self.wc.notice = Some(self.wc_proposal_end_text(&end));
            }
            WcEvent::RefusedWhileLocked(count) => {
                let text =
                    text::REFUSED_WHILE_LOCKED.fill(self.settings.language, [&count.to_string()]);
                if !self.banners.iter().any(|banner| banner.text == text) {
                    self.notice(text, crate::ui::main_window::Tone::Info);
                }
            }
            WcEvent::Sessions(views, store) => {
                if !self.wc_store_is_current(&store) {
                    // A snapshot of another wallet's worker state (sent before a reset): never
                    // shown, never copied into this wallet's meta.
                    logging::info("walletconnect", "sessions.stale", &[]);
                    return;
                }
                self.wc.sessions = views;
                self.wc_persist(&store);
                self.wc_prune_grants();
            }
            WcEvent::Ended(origin) => {
                self.wc.sessions.retain(|s| s.origin != origin);
                self.disconnect_site(&origin);
                logging::info("walletconnect", "session.ended", &[]);
            }
        }
        self.refresh();
    }

    /// The panel line after a proposal's connect request ended (wallet text only).
    fn wc_proposal_end_text(&self, end: &ProposalEnd) -> String {
        let lang = self.settings.language;
        let fixed = match end {
            ProposalEnd::Connected => text::END_CONNECTED,
            ProposalEnd::TooLate => text::END_TOO_LATE,
            ProposalEnd::Locked => text::END_LOCKED,
            ProposalEnd::Refused(ProviderError::UserRejected) => text::END_REJECTED,
            ProposalEnd::Refused(ProviderError::Expired | ProviderError::TimedOut) => {
                text::END_EXPIRED
            }
            ProposalEnd::Refused(ProviderError::NoEvmAccount) => text::END_NO_EVM,
            ProposalEnd::Refused(ProviderError::PassphraseUnverified) => text::END_PASSPHRASE,
            ProposalEnd::Refused(ProviderError::Unauthorized)
                if self.browser_grants().len() >= yw_core::policy::MAX_GRANTS =>
            {
                text::END_TOO_MANY_SITES
            }
            ProposalEnd::Refused(error) => {
                return text::END_FAILED.fill(lang, [&error.code().to_string()]);
            }
        };
        fixed.get(lang).to_owned()
    }

    /// Whether a worker snapshot belongs to the loaded wallet: its relay key is the one in this
    /// meta (created at unlock before the worker's `Load`). Without meta nothing is current.
    fn wc_store_is_current(&self, store: &WcStore) -> bool {
        self.meta.as_ref().is_some_and(|meta| {
            WcStore::from_value(meta.chain_sites.walletconnect.as_ref()).client_seed
                == store.client_seed
        })
    }

    fn wc_persist(&mut self, store: &WcStore) {
        if self.vault_view() != VaultView::Unlocked {
            return;
        }
        let value = store.to_value();
        if let Some(meta) = self.meta.as_mut()
            && meta.chain_sites.walletconnect.as_ref() != Some(&value)
        {
            meta.chain_sites.walletconnect = Some(value);
            self.save_meta();
        }
    }

    /// Grants of `WalletConnect` origins without a live session or pending proposal go (a session
    /// deleted or expired while locked).
    fn wc_prune_grants(&mut self) {
        if self.vault_view() != VaultView::Unlocked {
            return;
        }
        let stale: Vec<BrowserOrigin> = self
            .browser_grants()
            .into_iter()
            .map(|grant| grant.origin)
            .filter(|origin| {
                crate::walletconnect::topic_of_origin(origin).is_some_and(|topic| {
                    !self.wc.sessions.iter().any(|s| s.topic == topic)
                        && !self.wc.proposals.iter().any(|p| p.session_topic == topic)
                })
            })
            .collect();
        for origin in stale {
            self.disconnect_site(&origin);
        }
    }

    // ----- panel actions ---------------------------------------------------------------

    /// Pairs with a pasted or decoded URI.
    pub(crate) fn wc_pair(&mut self, text: &str) {
        if self.settings.walletconnect_project.is_empty() {
            self.wc_notice(text::PAIR_NO_PROJECT);
            return;
        }
        if self.vault_view() != VaultView::Unlocked {
            self.wc_notice(text::PAIR_LOCKED);
            return;
        }
        if let Err(error) = yw_core::walletconnect::parse_pairing_uri(text) {
            self.wc.notice = Some(error.message(self.settings.language).to_owned());
            return;
        }
        self.wc_after_unlock();
        self.wc_send(WcCommand::Pair(text.trim().to_owned()));
        self.wc.uri_text.clear();
        logging::info("walletconnect", "pair", &[]);
    }

    fn wc_notice(&mut self, text: yw_core::lang::Text) {
        self.wc.notice = Some(text.get(self.settings.language).to_owned());
    }

    /// Decodes a QR from BGRA pixels and pairs with it.
    fn wc_pair_pixels(&mut self, width: usize, height: usize, pixels: &[u8], source: &'static str) {
        match crate::walletconnect::qr_decode::decode_bgra_text(width, height, pixels) {
            Some(text) if looks_like_pairing_link(&text) => {
                logging::info(
                    "walletconnect",
                    "qr.decoded",
                    &[("source", Field::Word(source))],
                );
                self.wc_pair(&text);
            }
            Some(_) => self.wc_notice(text::QR_NOT_WC),
            None => self.wc_notice(text::QR_NOT_FOUND),
        }
    }

    /// `클립보드 이미지에서 QR 읽기` (Win+Shift+S places a bitmap on the clipboard).
    pub(crate) fn wc_clipboard_qr(&mut self) {
        let Some(main) = self.main.as_ref() else {
            return;
        };
        match yw_win::clipboard::read_dib(main, MAX_CLIPBOARD_IMAGE) {
            Ok(Some(dib)) => match crate::walletconnect::qr_decode::dib_to_bgra(&dib) {
                Some((width, height, pixels)) => {
                    self.wc_pair_pixels(width, height, &pixels, "clipboard");
                }
                None => self.wc_notice(text::CLIPBOARD_FORMAT),
            },
            Ok(None) => self.wc_notice(text::CLIPBOARD_NO_IMAGE),
            Err(_) => self.wc_notice(text::CLIPBOARD_OPEN),
        }
    }

    /// `이미지 파일에서 QR 읽기` (PNG, JPEG, BMP, GIF; the path field accepts a quoted path from
    /// Explorer's `경로로 복사`).
    pub(crate) fn wc_file_qr(&mut self) {
        let path = self.wc.file_text.trim().trim_matches('"').to_owned();
        if path.is_empty() {
            self.wc_notice(text::FILE_EMPTY);
            return;
        }
        // Only the four formats are handed to GDI+ (no EMF/WMF/TIFF/ICO codecs on untrusted
        // files), and only files of a screenshot's size.
        if !image_file_acceptable(std::path::Path::new(&path)) {
            self.wc_notice(text::FILE_KIND);
            return;
        }
        match yw_win::image::decode_file(std::path::Path::new(&path)) {
            Ok(image) => self.wc_pair_pixels(image.width, image.height, &image.pixels, "file"),
            Err(_) => self.wc_notice(text::FILE_OPEN),
        }
    }

    /// Saves the project id (32 hex; empty clears it).
    pub(crate) fn wc_save_project(&mut self) {
        let text = self
            .wc
            .project_text
            .clone()
            .unwrap_or_else(|| self.settings.walletconnect_project.clone())
            .trim()
            .to_ascii_lowercase();
        if !text.is_empty() && !crate::walletconnect::worker::valid_project_id(&text) {
            self.wc_notice(text::PROJECT_FORMAT);
            return;
        }
        let mut settings = self.settings.clone();
        settings.walletconnect_project.clone_from(&text);
        self.save_settings(settings, "walletconnect");
        self.wc.project_text = None;
        self.wc.project_open = false;
        self.wc_notice(if text.is_empty() {
            text::PROJECT_CLEARED
        } else {
            text::PROJECT_SAVED
        });
        if self.wc.handle.is_some() || !text.is_empty() {
            self.wc_after_unlock();
            if text.is_empty() {
                self.wc_send(WcCommand::Configure(None));
            }
        }
    }

    /// Disconnects one session (its grant and waiting requests go; the worker sends
    /// `wc_sessionDelete` when it sees the grant gone).
    pub(crate) fn wc_disconnect(&mut self, topic: [u8; 32]) {
        if let Some(origin) = crate::walletconnect::session_origin(&topic) {
            self.disconnect_site(&origin);
        }
        self.wc_send(WcCommand::Disconnect(topic));
    }

    /// `클립보드에서 연결` (2026-11-08): a copied `wc:` link (also a wholly percent-encoded
    /// `wc%3A…` one) pairs at once; otherwise a copied image goes to the QR reader. The clipboard
    /// is read only on this press, never written, and its text is not logged (only the source
    /// word, as `qr.decoded`). Only a pairing link leaves the wiped buffer as a `String`: other
    /// clipboard text (it may be a copied secret) is never copied out of it.
    pub(crate) fn wc_clipboard_connect(&mut self) {
        let Some(main) = self.main.as_ref() else {
            return;
        };
        let text = yw_win::clipboard::read_text(main, 2_048)
            .ok()
            .and_then(|(units, _)| {
                let units = units.as_slice();
                let start = units.iter().position(|unit| {
                    !char::from_u32(u32::from(*unit)).is_some_and(char::is_whitespace)
                })?;
                units_look_like_pairing_link(units.get(start..)?)
                    .then(|| String::from_utf16_lossy(units))
            });
        if let Some(text) = text {
            logging::info(
                "walletconnect",
                "clipboard.link",
                &[("source", Field::Word("text"))],
            );
            self.wc_notice(text::CLIPBOARD_LINK);
            self.wc_pair(text.trim());
            return;
        }
        self.wc_clipboard_qr();
    }

    /// `모든 WalletConnect 세션 끊기`.
    pub(crate) fn wc_disconnect_all(&mut self) {
        let topics: Vec<[u8; 32]> = self.wc.sessions.iter().map(|s| s.topic).collect();
        for topic in topics {
            self.wc_disconnect(topic);
        }
    }
}
