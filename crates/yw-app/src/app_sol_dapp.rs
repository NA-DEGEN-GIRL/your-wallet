//! Solana dApp transactions on the UI thread (spec/07 §20, spec/05 §3.6): the refusals of a
//! granted request before its window (no endpoint, too many pending sends), the RPC preview and
//! the approval draft built from it, and the hand-off of an approved sign-only request to the
//! key worker (the chain-message route: `SignChainMessage(Card)`, answered by
//! `browser_chain_message_signed` after the grant re-check). The wallet never builds or changes
//! these transactions; the core signs the exact approved bytes in our slot.

use yw_core::approval::{Approved, SigningPayload};
use yw_core::journal::sol::{
    SOL_DAPP_MAX_PENDING, SOL_DAPP_MAX_PENDING_TOTAL, pending_dapp_count, pending_dapp_total,
};
use yw_core::policy::ProviderError;
use yw_core::sol::SolAddress;
use yw_core::sol::dapp::{SolTxMode, SolTxRequest, build_sol_tx_request};

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
    /// Why a granted dApp transaction request of `public` ends before its window (spec/05 §3.6):
    /// no endpoint for the cluster (4901; the preview needs RPC), or for a send the (cluster,
    /// signer) or whole-journal cap of pending dApp sends (-32002). `None`: open the window.
    ///
    /// Step 6 of the rollout: a send is refused with 4200 until the send path exists.
    pub(crate) fn sol_dapp_refusal(
        &self,
        public: &[u8; 32],
        mode: SolTxMode,
    ) -> Option<ProviderError> {
        let cluster = self.sol_cluster();
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
        let SiteKind::SolTx { public, txs, .. } = &site.kind else {
            self.show_failure(ErrorCode::App009, false, ErrorCode::App009.text());
            return;
        };
        let endpoint = match self.sol_endpoint(self.sol_cluster()) {
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

    /// The preview of the shown request finished: the draft from the core builder with the
    /// address book, own accounts and the fee cap, or the failure (a genesis mismatch is
    /// E-RPC-006, not retried).
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
        let preview = match result {
            Ok(preview) => preview,
            Err(code) => {
                logging::warn(
                    "app",
                    "sol.dapp_preview_failed",
                    &[("code", Field::Code(code))],
                );
                self.show_failure(code, crate::sol::flow::retryable(code), code.text());
                return;
            }
        };
        let SiteKind::SolTx {
            public,
            txs,
            mode,
            options,
            ..
        } = &site.kind
        else {
            return;
        };
        let Some(row) = self
            .sol_dapp_rows()
            .into_iter()
            .find(|row| row.public == *public)
        else {
            self.show_failure(ErrorCode::App009, false, ErrorCode::App009.text());
            return;
        };
        let Ok(id) = Self::new_approval_id() else {
            self.show_failure(ErrorCode::Vlt005, false, ErrorCode::Vlt005.text());
            return;
        };
        let request = SolTxRequest {
            id,
            origin: site.origin.clone(),
            cluster: self.sol_cluster(),
            source: row.source,
            public: *public,
            label: row.label,
            mode: *mode,
            options: *options,
            txs: txs.clone(),
        };
        let facts = preview.into_facts(self.sol_known(), self.settings.solana.max_fee_lamports);
        match build_sol_tx_request(&request, &facts) {
            Ok(draft) => self.show_ready_draft(draft, None),
            Err(_) => self.show_failure(ErrorCode::App009, false, ErrorCode::App009.text()),
        }
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
