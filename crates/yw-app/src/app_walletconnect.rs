//! `WalletConnect` on the UI thread (spec/13 §6–§8): the worker's lifetime, the session list and
//! its persistence in meta, the pairing inputs (pasted URI, clipboard screenshot, image file),
//! and the hooks that show a session's self-claimed origin in the connect and approval windows
//! (`WalletConnect: {url} (사이트가 주장한 주소 — 확인되지 않음)`) with the Verify warnings.

use std::sync::Arc;

use yw_core::approval::{
    ApprovalDisplay, ApprovalDraft, ApprovalOrigin, DisplayField, FieldKey, MAX_DISPLAY_WARNINGS,
};
use yw_core::policy::BrowserOrigin;

use crate::app::App;
use crate::browser::{SiteRequest, VaultView};
use crate::logging::{self, Field};
use crate::walletconnect::engine::ProposalView;
use crate::walletconnect::store::WcStore;
use crate::walletconnect::worker::{RelayStatus, SessionView, WcCommand, WcEvent, WcHandle};
use crate::walletconnect::{Metadata, VerifyStatus, is_session_origin};

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

    /// The origin text of a site request for logs-free display and the AI explanation input.
    pub(crate) fn site_origin_text(&self, site: &SiteRequest) -> String {
        self.wc_peer_of(&site.origin).map_or_else(
            || site.origin.as_str().to_owned(),
            |(peer, _)| crate::walletconnect::origin_label(&peer),
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
                self.settings.evm_chain_name(*id).map_or_else(
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
    let label = crate::walletconnect::origin_label(peer);
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
    warnings.push(crate::walletconnect::verify_warning(verify));
    match ApprovalDisplay::new(draft.display.title.clone(), fields, warnings) {
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
        let proposal = &self.proposal;
        // The origin line and title carry wallet-normalized text only; the self-claimed name
        // gets its own labelled field, and the Verify state only the badge and warning below.
        let label = crate::walletconnect::origin_label(&proposal.peer);
        view.header = vec![("요청 출처".to_owned(), label.clone())];
        if let Some(Block::Title(title)) = view.blocks.first_mut() {
            title.clone_from(&label);
        }
        let (text, tone) = match proposal.verify {
            VerifyStatus::Valid => (
                "WalletConnect 연결입니다. Verify가 사이트 주소를 확인했습니다.".to_owned(),
                Tone::Plain,
            ),
            VerifyStatus::Unknown => (
                "WalletConnect 연결입니다. 사이트 이름과 주소는 사이트가 스스로 주장한 값이며 확인되지 않았습니다. 지금 연결하려던 사이트가 맞는지 확인하세요.".to_owned(),
                Tone::Warn,
            ),
            VerifyStatus::Invalid => (
                "위험: WalletConnect Verify 결과, 사이트가 주장한 주소와 실제 주소가 다릅니다. 피싱일 수 있습니다. 연결하지 마세요.".to_owned(),
                Tone::Danger,
            ),
            VerifyStatus::Scam => (
                "위험: WalletConnect Verify가 이 사이트를 알려진 사기 사이트로 표시했습니다. 연결하지 마세요.".to_owned(),
                Tone::Danger,
            ),
        };
        let at = view.blocks.len().min(1);
        view.blocks.insert(at, Block::Warning { text, tone });
        view.blocks.insert(
            at + 1,
            Block::Field {
                label: "사이트 이름 (사이트가 주장)".to_owned(),
                value: proposal.peer.display_name(),
                mono: false,
            },
        );
        for block in &mut view.blocks {
            if let Block::Field { label, value, .. } = block
                && label == "현재 네트워크"
            {
                "연결할 네트워크 (WalletConnect)".clone_into(label);
                value.clone_from(&self.chains);
            }
        }
        if !proposal.unsupported_methods.is_empty() {
            view.blocks.push(Block::Muted(format!(
                "이 지갑이 지원하지 않는 요청은 거부됩니다: {}",
                proposal.unsupported_methods.join(", ")
            )));
        }
        view.badges
            .push(format!("Verify {}", proposal.verify.label()));
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
            WcEvent::Notice(text) => self.wc.notice = Some(text),
            WcEvent::Proposal(view) => {
                self.wc
                    .proposals
                    .retain(|p| p.session_topic != view.session_topic);
                if self.wc.proposals.len() >= crate::walletconnect::engine::MAX_PROPOSALS {
                    self.wc.proposals.remove(0);
                }
                self.wc.proposals.push(*view);
                self.wc.notice =
                    Some("연결 요청이 도착했습니다 — 연결 창을 확인하세요.".to_owned());
            }
            WcEvent::ProposalDone(topic) => {
                self.wc.proposals.retain(|p| p.session_topic != topic);
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
            self.wc.notice = Some(
                "먼저 Reown Project ID를 저장하세요. dashboard.reown.com에서 무료 프로젝트를 만들면 ID를 받을 수 있습니다."
                    .to_owned(),
            );
            return;
        }
        if self.vault_view() != VaultView::Unlocked {
            self.wc.notice = Some("지갑 잠금을 해제한 뒤 연결하세요.".to_owned());
            return;
        }
        if let Err(error) = yw_core::walletconnect::parse_pairing_uri(text) {
            self.wc.notice = Some(error.message().to_owned());
            return;
        }
        self.wc_after_unlock();
        self.wc_send(WcCommand::Pair(text.trim().to_owned()));
        self.wc.uri_text.clear();
        logging::info("walletconnect", "pair", &[]);
    }

    /// Decodes a QR from BGRA pixels and pairs with it.
    fn wc_pair_pixels(&mut self, width: usize, height: usize, pixels: &[u8], source: &'static str) {
        match crate::walletconnect::qr_decode::decode_bgra_text(width, height, pixels) {
            Some(text)
                if text
                    .trim_start()
                    .get(..3)
                    .is_some_and(|p| p.eq_ignore_ascii_case("wc:")) =>
            {
                logging::info(
                    "walletconnect",
                    "qr.decoded",
                    &[("source", Field::Word(source))],
                );
                self.wc_pair(&text);
            }
            Some(_) => {
                self.wc.notice =
                    Some("QR을 읽었지만 WalletConnect 연결 주소(wc:)가 아닙니다.".to_owned());
            }
            None => {
                self.wc.notice = Some(
                    "이미지에서 QR 코드를 찾지 못했습니다. QR 전체가 보이게 캡처했는지 확인하세요."
                        .to_owned(),
                );
            }
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
                None => {
                    self.wc.notice = Some("클립보드 이미지 형식을 읽을 수 없습니다.".to_owned());
                }
            },
            Ok(None) => {
                self.wc.notice = Some(
                    "클립보드에 이미지가 없습니다. Win+Shift+S로 QR 부분을 캡처한 뒤 다시 누르세요."
                        .to_owned(),
                );
            }
            Err(_) => {
                self.wc.notice =
                    Some("클립보드를 열 수 없습니다. 잠시 후 다시 시도하세요.".to_owned());
            }
        }
    }

    /// `이미지 파일에서 QR 읽기` (PNG, JPEG, BMP, GIF; the path field accepts a quoted path from
    /// Explorer's `경로로 복사`).
    pub(crate) fn wc_file_qr(&mut self) {
        let path = self.wc.file_text.trim().trim_matches('"').to_owned();
        if path.is_empty() {
            self.wc.notice = Some("이미지 파일 경로를 입력하세요.".to_owned());
            return;
        }
        // Only the four formats are handed to GDI+ (no EMF/WMF/TIFF/ICO codecs on untrusted
        // files), and only files of a screenshot's size.
        if !image_file_acceptable(std::path::Path::new(&path)) {
            self.wc.notice =
                Some("PNG·JPEG·BMP·GIF 이미지 파일만 읽을 수 있습니다 (64 MB 이하).".to_owned());
            return;
        }
        match yw_win::image::decode_file(std::path::Path::new(&path)) {
            Ok(image) => self.wc_pair_pixels(image.width, image.height, &image.pixels, "file"),
            Err(_) => {
                self.wc.notice =
                    Some("이미지 파일을 열 수 없습니다 (PNG·JPEG·BMP·GIF).".to_owned());
            }
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
            self.wc.notice = Some(
                "Project ID는 32자리 16진수입니다 (Reown Cloud 대시보드의 Project ID).".to_owned(),
            );
            return;
        }
        let mut settings = self.settings.clone();
        settings.walletconnect_project.clone_from(&text);
        self.save_settings(settings, "walletconnect");
        self.wc.project_text = None;
        self.wc.project_open = false;
        self.wc.notice = Some(if text.is_empty() {
            "Project ID를 지웠습니다. WalletConnect가 꺼집니다.".to_owned()
        } else {
            "Project ID를 저장했습니다.".to_owned()
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

    /// `모든 WalletConnect 세션 끊기`.
    pub(crate) fn wc_disconnect_all(&mut self) {
        let topics: Vec<[u8; 32]> = self.wc.sessions.iter().map(|s| s.topic).collect();
        for topic in topics {
            self.wc_disconnect(topic);
        }
    }
}
