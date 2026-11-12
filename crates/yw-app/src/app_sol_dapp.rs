//! Solana dApp transactions on the UI thread (spec/07 §20, spec/05 §3.6): the refusals of a
//! granted request before its window (no endpoint, too many pending sends), the RPC preview and
//! the approval draft built from it, and the hand-off of an approved sign-only request to the
//! key worker (the chain-message route: `SignChainMessage(Card)`, answered by
//! `browser_chain_message_signed` after the grant re-check). The wallet never builds or changes
//! these transactions; the core signs the exact approved bytes in our slot.

use yw_core::approval::{ApprovalDraft, Approved, SigningPayload};
use yw_core::journal::sol::{
    SOL_DAPP_MAX_PENDING, SOL_DAPP_MAX_PENDING_TOTAL, pending_dapp_count, pending_dapp_total,
};
use yw_core::policy::ProviderError;
use yw_core::sol::dapp::{SolTxMode, SolTxRequest, build_sol_tx_request};
use yw_core::sol::{SolAddress, SolCluster};

use crate::app::App;
use crate::app_browser::SignWaiter;
use crate::app_chain_sites::ChainAnswer;
use crate::app_evm::QueuedItem;
use crate::browser::{SiteKind, SiteRequest};
use crate::errors::ErrorCode;
use crate::events::KeyJob;
use crate::logging::{self, Field};
use crate::sol::flow::{DappPreview, DappPreviewJob};
use crate::workers::rpc::RpcJob;

impl App {
    /// Why a granted dApp transaction request of `public` on `cluster` ends before its window
    /// (spec/05 §3.6): `cluster` is no longer the wallet's (-32602, Q16: switched while it
    /// waited), no endpoint for the cluster (4901; the preview needs RPC), or for a send the
    /// (cluster, signer) or whole-journal cap of pending dApp sends (-32002). `None`: open the
    /// window.
    ///
    /// Step 6 of the rollout: a send is refused with 4200 until the send path exists.
    pub(crate) fn sol_dapp_refusal(
        &self,
        public: &[u8; 32],
        cluster: SolCluster,
        mode: SolTxMode,
    ) -> Option<ProviderError> {
        if cluster != self.sol_cluster() {
            return Some(ProviderError::InvalidParams);
        }
        if self.sol_endpoint(cluster).is_err() {
            return Some(ProviderError::ChainUnavailable);
        }
        if mode == SolTxMode::SignAndSend {
            let records = self.sol_records();
            let signer = SolAddress::from_bytes(*public);
            if pending_dapp_count(&records, cluster, &signer) >= SOL_DAPP_MAX_PENDING
                || pending_dapp_total(&records) >= SOL_DAPP_MAX_PENDING_TOTAL
            {
                return Some(ProviderError::TransactionPending);
            }
            return Some(ProviderError::UnsupportedMethod);
        }
        None
    }

    /// The preview on the RPC worker (called by `prepare_site`, spec/07 §20.7).
    pub(crate) fn prepare_sol_dapp(&mut self, job: u64, site: &SiteRequest) {
        let SiteKind::SolTx {
            public,
            cluster,
            txs,
            ..
        } = &site.kind
        else {
            self.show_failure(ErrorCode::App009, false, ErrorCode::App009.text());
            return;
        };
        // The request's cluster, never the one shown now: the preview facts, the draft and the
        // signature all belong to the cluster the dApp asked for.
        let endpoint = match self.sol_endpoint(*cluster) {
            Ok(endpoint) => endpoint,
            Err(code) => {
                self.show_failure(code, false, code.text());
                return;
            }
        };
        let sent = self.rpc(RpcJob::SolDappPreview(Box::new(DappPreviewJob {
            job,
            endpoint,
            wallet: SolAddress::from_bytes(*public),
            txs: txs.clone(),
        })));
        if !sent {
            self.show_failure(ErrorCode::Rpc001, true, ErrorCode::Rpc001.text());
        }
    }

    /// The preview of the shown request finished: its draft ([`Self::sol_dapp_draft`]) or the
    /// failure goes to the window.
    pub(crate) fn on_sol_dapp_previewed(
        &mut self,
        job: u64,
        result: Result<DappPreview, ErrorCode>,
    ) {
        let site = match self.evm.window.as_ref() {
            Some(window) if window.job() == job => match window.item() {
                QueuedItem::Site(site) => site.clone(),
                _ => return,
            },
            _ => return,
        };
        match self.sol_dapp_draft(&site, result) {
            Ok(draft) => self.show_ready_draft(draft, None),
            Err((code, retryable)) => self.show_failure(code, retryable, code.text()),
        }
    }

    /// The approval draft of the dApp transaction request `site` from its preview: the core
    /// builder with the address book, own accounts and the fee cap, on the request's cluster.
    /// Otherwise the window's failure `(code, retryable)`, never a draft without the preview (no
    /// X01): the wallet switched to another cluster since the request came (Q16) or a genesis
    /// mismatch is E-RPC-006, not retried; a transport error keeps its own code.
    pub(crate) fn sol_dapp_draft(
        &self,
        site: &SiteRequest,
        result: Result<DappPreview, ErrorCode>,
    ) -> Result<ApprovalDraft, (ErrorCode, bool)> {
        let SiteKind::SolTx {
            public,
            cluster,
            txs,
            mode,
            options,
            ..
        } = &site.kind
        else {
            return Err((ErrorCode::App009, false));
        };
        if *cluster != self.sol_cluster() {
            logging::warn("app", "sol.dapp_cluster_changed", &[]);
            return Err((ErrorCode::Rpc006, false));
        }
        let preview = result.map_err(|code| {
            logging::warn(
                "app",
                "sol.dapp_preview_failed",
                &[("code", Field::Code(code))],
            );
            (code, crate::sol::flow::retryable(code))
        })?;
        let row = self
            .sol_dapp_rows()
            .into_iter()
            .find(|row| row.public == *public)
            .ok_or((ErrorCode::App009, false))?;
        let id = Self::new_approval_id().map_err(|_| (ErrorCode::Vlt005, false))?;
        let request = SolTxRequest {
            id,
            origin: site.origin.clone(),
            cluster: *cluster,
            source: row.source,
            public: *public,
            label: row.label,
            mode: *mode,
            options: *options,
            txs: txs.clone(),
        };
        let facts = preview.into_facts(self.sol_known(), self.settings.solana.max_fee_lamports);
        build_sol_tx_request(&request, &facts).map_err(|_| (ErrorCode::App009, false))
    }

    /// An approved dApp transaction request (spec/07 §20.8): the waiter that answers it, then a
    /// sign-only request goes the chain-message route — a `YubiKey` account through its PIN
    /// (one touch per transaction), otherwise `SignChainMessage`. Nothing is sent or journaled.
    pub(crate) fn sol_dapp_consumed(&mut self, approved: Approved, site: &SiteRequest) {
        let (SiteKind::SolTx { public, batch, .. }, SigningPayload::SolTx(payload)) =
            (&site.kind, approved.payload())
        else {
            self.respond(&site.reply, Err(ProviderError::Internal));
            return;
        };
        if payload.mode == SolTxMode::SignAndSend {
            // Refused at preflight until the send path exists (step 6); never signed here.
            self.respond(&site.reply, Err(ProviderError::UnsupportedMethod));
            return;
        }
        let answer = ChainAnswer::SolTx {
            public: *public,
            origin: site.origin.clone(),
            batch: *batch,
            send: false,
        };
        let ticket = self.push_sign_waiter(SignWaiter::Chain(site.reply, Box::new(answer)));
        if let Err(approved) = self.card_begin(
            approved,
            crate::app_card::CardJobKind::ChainMessage,
            Some(ticket),
        ) {
            self.key(KeyJob::SignChainMessage { ticket, approved });
        }
    }
}
