//! The test holder of the dApp chain sites (2026-11-23, spec/15 §11.4 S4d E1, preflight §0 item
//! 9 and O-9): the wallet code of `app_chain_sites` moved to `yw_engine::wallet::app_chain_sites`;
//! its inline test module, with the 32 pinned helpers (`frozen-helpers.txt`, rule `mutable`) and
//! its child `app/tests/chain_sites.rs` (the A-4 frozen tests), stays here unchanged, so the
//! pinned file and its `tests::` prefix stay where `s4_frozen.rs`'s `HELPER_SET` looks
//! (no re-point needed). `cfg(test)` only.
//!
//! The imports below are the wallet module's (the tests reach them through `use super::*`),
//! written with the paths yw-app reaches them by.

#![cfg(test)]

pub(crate) use yw_engine::wallet::app_chain_sites::*;

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use std::sync::Arc;
    use yw_engine::testkit::WalletTestExt;

    // `BtcRow`: the moved tests of `app_tests` name it as `super::BtcRow` (2026-11-21, S4 W0).
    use super::{BtcRow, ChainAnswer, ConnectChoice, chain_answer_value, default_protocol};
    use crate::apikeys::ApiKeys;
    use crate::app::{App, Paths};
    use crate::app_browser::{BrowserUi, GrantWrite};
    use crate::browser::envelope::{Correlation, Id16, Id32};
    use crate::browser::{Reply, SiteKind, SiteRequest};
    use crate::events::{ChainSignature, EventQueue};
    use crate::settings::Settings;
    use crate::ui::approval::QueueOutcome;
    use yw_core::approval::{ApprovalKind, RiskLevel};
    use yw_core::btc::msgsign::{BtcMessageProtocol, BtcMessageSignature};
    use yw_core::btc::{BtcPubKey, ScriptType};
    use yw_core::policy::{BrowserOrigin, BtcGrantAddress, BtcPurpose, Family, ProviderError};
    use yw_engine::wallet::app_approval::ConnectState;

    const SOL_KEY: &str = "FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z";

    fn app(with_sol: bool) -> App {
        let dir = std::env::temp_dir().join(format!("yw-app-chain-{}", std::process::id()));
        let mut app = App::new(
            Paths {
                data: dir.clone(),
                logs: dir.join("logs"),
            },
            true,
            Settings::default(),
            ApiKeys::default(),
        );
        let events = Arc::new(EventQueue::new(Box::new(|| {})));
        let core = crate::browser::BrowserCore::new(
            "abcdefghijklmnopabcdefghijklmnop",
            events as Arc<dyn crate::browser::DappSink>,
            Arc::clone(&app.clock),
        );
        app.browser = Some(BrowserUi {
            core,
            reads: Arc::new(crate::browser::read::ReadContext::new(None)),
            connections: 0,
            waiters: HashMap::new(),
            broadcasts: HashMap::new(),
            sol_broadcasts: HashMap::new(),
            dapp_unlock: false,
            unlocked: false,
            locking: false,
            grant_write: GrantWrite::default(),
            site_rows: crate::app_browser::SiteRows::default(),
        });
        let mut meta = crate::meta::Meta::default();
        if with_sol {
            meta.sol_accounts.push(crate::meta::Account {
                index: 0,
                label: "SOL 1".to_owned(),
                address: SOL_KEY.to_owned(),
                hidden: false,
            });
        }
        app.meta = Some(meta);
        app
    }

    fn site(kind: SiteKind) -> SiteRequest {
        SiteRequest {
            reply: Reply {
                conn: 1,
                correlation: Correlation {
                    session_id: Id32([1; 32]),
                    sequence: 1,
                    activation_nonce: Id32([2; 32]),
                    request_id: Id16([3; 16]),
                },
            },
            origin: BrowserOrigin::parse("https://app.example").unwrap(),
            chain_id: yw_core::evm::chain::SEPOLIA,
            deadline_ms: u64::MAX,
            method: yw_core::policy::Method::SolConnect,
            kind,
            compat_mode: None,
        }
    }

    fn public() -> [u8; 32] {
        yw_core::codec::base58::base58_decode_32(SOL_KEY).unwrap()
    }

    #[test]
    fn btc_connect_window_is_one_radio_per_purpose() {
        let entry = |purpose, script_type, address: &str| {
            ConnectChoice::Btc(BtcGrantAddress {
                purpose,
                address: address.to_owned(),
                pubkey: BtcPubKey::Compressed([2; 33]),
                script_type,
            })
        };
        let mut state = ConnectState {
            accounts: vec![
                (
                    entry(BtcPurpose::Payment, ScriptType::P2wpkh, "a"),
                    String::new(),
                    "a".to_owned(),
                    0,
                ),
                (
                    entry(BtcPurpose::Payment, ScriptType::P2shP2wpkh, "b"),
                    String::new(),
                    "b".to_owned(),
                    0,
                ),
                (
                    entry(BtcPurpose::Ordinals, ScriptType::P2tr, "c"),
                    String::new(),
                    "c".to_owned(),
                    1,
                ),
            ],
            selected: vec![true, false, false],
            chain_name: String::new(),
            chain_id: 0,
            family: Family::Bitcoin,
            groups: 2,
        };
        assert_eq!(state.gate_count(), 0, "ordinals group empty");
        state.toggle(2);
        assert_eq!(state.gate_count(), 2);
        state.toggle(1);
        assert_eq!(state.selected, vec![false, true, true]);
        assert_eq!(state.gate_count(), 2);
    }

    fn sol_grant(origin: &str, public: [u8; 32]) -> yw_core::policy::SolGrant {
        yw_core::policy::SolGrant {
            origin: BrowserOrigin::parse(origin).unwrap(),
            public,
            granted_at_unix_ms: 1,
        }
    }

    fn core(app: &App) -> Arc<crate::browser::BrowserCore> {
        Arc::clone(&app.browser.as_ref().unwrap().core)
    }

    /// The dispatcher view of an unlocked wallet with the app's current accounts.
    fn unlocked_view(app: &App) -> crate::browser::WalletView {
        crate::browser::WalletView {
            vault: crate::browser::VaultView::Unlocked,
            sol_accounts: app.sol_dapp_rows().iter().map(|row| row.public).collect(),
            btc_enabled: true,
            btc_network: app.btc_network_now(),
            btc_accounts: app
                .btc_dapp_rows()
                .into_iter()
                .map(|row| row.entry.address)
                .collect(),
            ..crate::browser::WalletView::default()
        }
    }

    /// Lock, then unlock with the grants meta holds now (what the next session sees).
    fn relock(app: &App) -> bool {
        let core = core(app);
        core.lock_wallet();
        core.set_wallet(unlocked_view(app));
        let meta = app.meta.as_ref().unwrap();
        core.unlock_chains(
            crate::browser::grants::sol_sites_from_values(&meta.chain_sites.sol),
            crate::browser::grants::btc_sites_from_values(&meta.chain_sites.btc),
        )
    }

    /// What `show_next_approval` does up to the window: the next shown site item that passed its
    /// preflight (items finished by the preflight are answered and skipped).
    fn next_window(app: &mut App) -> Option<SiteRequest> {
        use crate::app_evm::QueuedItem;
        loop {
            let mut finished = Vec::new();
            let shown = app.evm.queue.show_next(0, &mut finished);
            for (item, outcome) in finished {
                app.approval_finished(&item.payload, outcome);
            }
            shown?;
            let QueuedItem::Site(site) = app.evm.queue.shown()?.payload.clone() else {
                return None;
            };
            match app.site_preflight(&site) {
                Some(outcome) => {
                    if let Some((done, outcome)) = app.evm.queue.finish_shown(outcome) {
                        app.approval_finished(&done.payload, outcome);
                    }
                }
                None => return Some(*site),
            }
        }
    }

    #[test]
    fn answers_and_defaults() {
        assert_eq!(
            default_protocol(ScriptType::P2tr),
            BtcMessageProtocol::Bip322
        );
        assert_eq!(
            default_protocol(ScriptType::P2wpkh),
            BtcMessageProtocol::Ecdsa
        );
        let sol = ChainAnswer::Sol {
            public: [1; 32],
            origin: BrowserOrigin::parse("https://app.example").unwrap(),
            message: b"hi".to_vec(),
            sign_in: true,
        };
        let value = chain_answer_value(&sol, &ChainSignature::Sol([2; 64])).unwrap();
        let text = String::from_utf8(yw_json::to_vec(&value)).unwrap();
        assert!(text.contains(r#""signedMessage":"6869""#), "{text}");
        let btc = ChainAnswer::Btc {
            address: "bc1q".to_owned(),
            origin: BrowserOrigin::parse("https://app.example").unwrap(),
            protocol: BtcMessageProtocol::Bip322,
        };
        let signed = ChainSignature::Btc(BtcMessageSignature {
            signature: "AA==".to_owned(),
            message_hash: [0; 32],
        });
        let text = String::from_utf8(yw_json::to_vec(&chain_answer_value(&btc, &signed).unwrap()))
            .unwrap();
        assert!(text.contains(r#""protocol":"bip322""#), "{text}");
        assert_eq!(
            chain_answer_value(&btc, &ChainSignature::Sol([0; 64])),
            None
        );
        // Solana dApp transactions (spec/05 §3.6): one hex string, or the list in order; a send
        // is never answered with bytes, a count mismatch is no answer.
        let tx = |batch: bool, send: bool| ChainAnswer::SolTx {
            public: [1; 32],
            origin: BrowserOrigin::parse("https://app.example").unwrap(),
            batch,
            send,
        };
        let text = |value: Option<yw_json::Value>| {
            value.map(|value| String::from_utf8(yw_json::to_vec(&value)).unwrap())
        };
        let key = yw_core::codec::base58::base58_encode(&[1; 32]);
        assert_eq!(
            text(chain_answer_value(
                &tx(false, false),
                &ChainSignature::SolTxs(vec![vec![0xab, 1]])
            )),
            Some(format!(
                r#"{{"publicKey":"{key}","signedTransaction":"ab01"}}"#
            ))
        );
        assert_eq!(
            text(chain_answer_value(
                &tx(true, false),
                &ChainSignature::SolTxs(vec![vec![1], vec![2]])
            )),
            Some(format!(
                r#"{{"publicKey":"{key}","signedTransactions":["01","02"]}}"#
            ))
        );
        for (answer, signed) in [
            (tx(false, false), vec![vec![1], vec![2]]),
            (tx(true, false), Vec::new()),
            (tx(false, true), vec![vec![1]]),
        ] {
            assert_eq!(
                chain_answer_value(&answer, &ChainSignature::SolTxs(signed)),
                None
            );
        }
        assert_eq!(
            chain_answer_value(&tx(false, false), &ChainSignature::Sol([0; 64])),
            None
        );
    }

    /// A legacy transaction the fixture key signs and pays for (one unknown-program
    /// instruction with data `[tag]`).
    fn sol_tx(tag: u8) -> Vec<u8> {
        let mut out = vec![1_u8];
        out.extend_from_slice(&[0; 64]);
        out.extend_from_slice(&[1, 0, 1, 2]);
        out.extend_from_slice(&public());
        out.extend_from_slice(&[5; 32]);
        out.extend_from_slice(&[7; 32]);
        out.extend_from_slice(&[1, 1, 1, 0, 1, tag]);
        out
    }

    const DEVNET: yw_core::sol::SolCluster = yw_core::sol::SolCluster::Devnet;

    /// A request of [`sol_tx`] bound to devnet.
    fn sol_tx_kind(mode: yw_core::sol::dapp::SolTxMode) -> SiteKind {
        SiteKind::SolTx {
            public: public(),
            cluster: DEVNET,
            txs: vec![sol_tx(1)],
            mode,
            batch: false,
            options: yw_core::sol::dapp::SolSendOptions::default(),
        }
    }

    /// A `Pending` dApp send record of `public` on devnet (only the fields the caps read).
    fn dapp_pending(public: [u8; 32]) -> yw_core::journal::sol::SolRecord {
        yw_core::journal::sol::SolRecord {
            state: yw_core::journal::sol::SolTxState::Pending,
            cluster: yw_core::sol::SolCluster::Devnet,
            source: yw_core::slip10::SolKeySource::Standard(
                yw_core::bip32::path::AccountIndex::ZERO,
            ),
            intent_id: [0; 16],
            intent_hash: [0; 32],
            signed_at_ms: 1,
            last_valid_block_height: 1,
            terminal_slot: 0,
            terminal_err: 0,
            tx: sol_tx(1),
            dapp: Some(yw_core::journal::sol::SolDappMeta {
                public,
                signer_slot: 0,
                flags: 1,
                origin: "https://app.example".to_owned(),
            }),
        }
    }

    /// One preview entry per transaction (no tables, no simulation result).
    fn preview(n: usize) -> crate::sol::flow::DappPreview {
        let item = yw_core::sol::dapp::SolTxItemFacts {
            tables: Ok((0, Vec::new())),
            pre: Vec::new(),
            post: None,
            sim: yw_core::sol::display::SimSummary::NoResult,
            sim_replaced_blockhash: false,
            rpc_fee: Some(5_000),
            blockhash_valid: Some(true),
        };
        crate::sol::flow::DappPreview {
            items: vec![item; n],
            mints: Vec::new(),
            unread_mints: Vec::new(),
        }
    }

    /// A devnet wallet with a devnet endpoint (no request is ever sent: the RPC worker is a
    /// channel in these tests).
    fn devnet(app: &mut App) {
        app.settings.solana.cluster = crate::network::SolCluster::Devnet;
        let url = yw_platform::http::HttpsUrl::parse("https://sol.example.test/").unwrap();
        app.apikeys.set_rpc(
            crate::network::NetworkId::Solana(crate::network::SolCluster::Devnet),
            &url,
        );
    }

    /// The window's part for `site`: its draft issued and consumed.
    fn approve_site(app: &App, site: &SiteRequest) -> yw_core::approval::Approved {
        let draft = app.sol_dapp_draft(site, Ok(preview(1))).unwrap();
        let mut store = yw_core::approval::ApprovalStore::new();
        let request = store.issue(draft, 1, 1_800_000_000_000).unwrap();
        store.consume(request.id, request.digest, 2).unwrap()
    }

    /// [`queued_sol_tx`] as `sol_signAndSendTransaction`.
    fn queued_send(app: &App, events: &EventQueue, conn: u64, n: u8) -> SiteRequest {
        let mut send = queued_sol_tx(app, events, conn, n);
        if let SiteKind::SolTx { mode, .. } = &mut send.kind {
            *mode = yw_core::sol::dapp::SolTxMode::SignAndSend;
        }
        send
    }

    /// The send waiter `sol_dapp_consumed` leaves for `site`.
    fn send_waiter(app: &mut App, site: &SiteRequest) -> crate::events::SignTicket {
        app.push_sign_waiter(crate::app_browser::SignWaiter::Chain(
            site.reply,
            Box::new(ChainAnswer::SolTx {
                public: public(),
                origin: site.origin.clone(),
                batch: false,
                send: true,
            }),
        ))
    }

    /// A journaled send of [`public`] with transaction id `tx_id`.
    fn summary(
        tx_id: [u8; 64],
        reused: bool,
        min_context_slot: Option<u64>,
    ) -> crate::events::SolDappSignedSummary {
        crate::events::SolDappSignedSummary {
            cluster: DEVNET,
            public: public(),
            tx_id,
            own_signature: tx_id,
            tx: sol_tx(1),
            signed_at_ms: 1,
            last_valid_block_height: 1,
            min_context_slot,
            reused,
        }
    }

    /// The first broadcast round of `tx_id` with `state` and `outcome`.
    fn first_round(
        tx_id: [u8; 64],
        state: yw_core::sol::broadcast::LoopState,
        outcome: Result<yw_core::sol::broadcast::Outcome, crate::errors::ErrorCode>,
    ) -> crate::events::RpcEvent {
        crate::events::RpcEvent::SolTracked(Box::new(crate::sol::flow::TrackResult {
            signature: tx_id,
            state,
            outcome,
            genesis_ok: Some(true),
            sends: 1,
            generation: 0,
        }))
    }

    /// The `{publicKey, signature}` text of a send answer.
    fn send_answer_text(tx_id: [u8; 64]) -> String {
        format!(
            r#"{{"publicKey":"{SOL_KEY}","signature":"{}"}}"#,
            yw_core::hex::encode(&tx_id)
        )
    }

    fn texts(
        found: Vec<Result<yw_json::Value, ProviderError>>,
    ) -> Vec<Result<String, ProviderError>> {
        found
            .into_iter()
            .map(|body| body.map(|value| String::from_utf8(yw_json::to_vec(&value)).unwrap()))
            .collect()
    }

    /// A recorded connection on a fresh dispatcher of `app`, unlocked with the app's accounts
    /// and the Solana grant of `https://app.example`: the queue its requests go to, the frames
    /// it answers with, and the connection.
    fn recorded(
        app: &mut App,
    ) -> (
        Arc<EventQueue>,
        std::sync::mpsc::Receiver<crate::browser::Outbound>,
        crate::browser::ConnId,
    ) {
        let events = Arc::new(EventQueue::new(Box::new(|| {})));
        let core = crate::browser::BrowserCore::new(
            "abcdefghijklmnopabcdefghijklmnop",
            Arc::clone(&events) as Arc<dyn crate::browser::DappSink>,
            Arc::clone(&app.clock),
        );
        core.set_wallet(unlocked_view(app));
        core.upsert_sol_grant(sol_grant("https://app.example", public()));
        let (sender, receiver) = std::sync::mpsc::channel();
        let conn = core.open_connection(Box::new(sender));
        if let Some(browser) = app.browser.as_mut() {
            browser.core = core;
        }
        let _ = events.drain();
        (events, receiver, conn)
    }

    /// Sends `sol_signTransaction` of [`sol_tx`] on `conn` and returns the queued request.
    fn queued_sol_tx(app: &App, events: &EventQueue, conn: u64, n: u8) -> SiteRequest {
        let deadline = app.clock.now_unix_ms() + 600_000;
        let frame = format!(
            concat!(
                r#"{{"namespace":"your-wallet","version":1,"role":"extension","kind":"request","#,
                r#""sessionId":"{session}","sequence":{n},"deadlineUnixMs":{deadline},"#,
                r#""profileInstallId":"{profile}","activationNonce":"{activation}","#,
                r#""requestId":"{request}","method":"sol_signTransaction","#,
                r#""params":[{{"publicKey":"{key}","transaction":"{tx}"}}],"route":"signing","#,
                r#""context":{{"browserFamily":"chrome","extensionId":"abcdefghijklmnopabcdefghijklmnop","#,
                r#""tabId":17,"frameId":0,"documentId":"document-17","topOrigin":"https://app.example","#,
                r#""frameOrigin":"https://app.example","documentLifecycle":"active","#,
                r#""channelNonce":"{channel}"}}}}"#
            ),
            n = n,
            deadline = deadline,
            session = "bb".repeat(32),
            profile = "aa".repeat(32),
            activation = format!("{}0c", "00".repeat(31)),
            channel = format!("{}0d", "00".repeat(31)),
            request = format!("{n:02x}").repeat(16),
            key = SOL_KEY,
            tx = yw_core::hex::encode(&sol_tx(n)),
        );
        core(app).handle_frame(conn, frame.as_bytes());
        events
            .drain()
            .into_iter()
            .find_map(|event| match event {
                crate::events::UiEvent::Dapp(crate::browser::DappEvent::Request(request)) => {
                    Some(*request)
                }
                _ => None,
            })
            .expect("queued")
    }

    /// The answers recorded since the last call.
    fn answers(
        frames: &std::sync::mpsc::Receiver<crate::browser::Outbound>,
    ) -> Vec<Result<yw_json::Value, ProviderError>> {
        frames
            .try_iter()
            .filter_map(|frame| match frame {
                crate::browser::Outbound::Response { body, .. } => Some(body),
                crate::browser::Outbound::Event { .. } => None,
            })
            .collect()
    }

    /// The EVM account the grant tests sign with.
    fn evm_account() -> yw_core::evm::address::Address {
        yw_core::evm::address::Address::from_bytes([0x6f; 20])
    }

    /// The EVM grant of `https://app.example` naming [`evm_account`].
    fn evm_grant() -> yw_core::policy::ConnectedSite {
        yw_core::policy::ConnectedSite::new(
            BrowserOrigin::parse("https://app.example").unwrap(),
            vec![evm_account()],
            yw_core::evm::chain::SEPOLIA,
            1,
        )
        .unwrap()
    }

    /// [`evm_account`] signing for `https://app.example`.
    fn evm_signer() -> crate::app_browser::SiteSigner {
        crate::app_browser::SiteSigner {
            origin: BrowserOrigin::parse("https://app.example").unwrap(),
            account: evm_account(),
        }
    }

    /// The names of the key jobs queued since the last call (`pop` blocks on an empty queue).
    fn job_names(app: &App) -> Vec<&'static str> {
        std::iter::from_fn(|| {
            (!app.key_queue.is_empty())
                .then(|| app.key_queue.pop())
                .flatten()
        })
        .map(|(_, job)| job.name())
        .collect()
    }

    /// A consumed `personal_sign` approval of the `YubiKey` EVM account 1 for
    /// `https://app.example`.
    fn approved_card_message() -> yw_core::approval::Approved {
        use yw_core::approval::{ApprovalId, ApprovalKind, ApprovalOrigin, ApprovalStore};
        let draft = yw_core::approval::build_personal_request(
            yw_core::lang::Lang::Ko,
            ApprovalId::random().unwrap(),
            ApprovalOrigin::Site(BrowserOrigin::parse("https://app.example").unwrap()),
            yw_core::vault::EvmKeySource::Hardware(
                yw_core::bip32::path::AccountIndex::new(1).unwrap(),
            ),
            evm_account(),
            ApprovalKind::EvmPersonalSign,
            &yw_core::evm::chain::sepolia(),
            &yw_core::evm::eip191::decode_personal_message(b"hi".to_vec()),
            1_790_000_000_000,
        )
        .unwrap();
        let mut store = ApprovalStore::new();
        let request = store.issue(draft, 0, 1_790_000_000_000).unwrap();
        store.consume(request.id, request.digest, 1).unwrap()
    }

    /// A consumed transaction approval of the `YubiKey` EVM account 1 for `https://app.example`
    /// (Sepolia, 1000 wei to a public test address; no simulation).
    fn approved_card_tx() -> yw_core::approval::Approved {
        use yw_core::approval::{ApprovalId, ApprovalKind, ApprovalOrigin, ApprovalStore};
        use yw_core::evm::amount::U256;
        use yw_core::evm::decode::{DecodedTx, decode_call};
        let chain = yw_core::evm::chain::sepolia();
        let tx = yw_core::evm::tx::Eip1559Tx {
            chain_id: yw_core::evm::chain::SEPOLIA,
            nonce: 0,
            max_priority_fee_per_gas: U256::from_u64(1_000_000_000),
            max_fee_per_gas: U256::from_u64(2_000_000_000),
            gas_limit: 21_000,
            to: yw_core::evm::address::Address::from_bytes([0x70; 20]),
            value: U256::from_u64(1_000),
            data: Vec::new(),
            access_list: Vec::new(),
        };
        let decoded = DecodedTx {
            call: decode_call(&chain, &tx.to, &tx.data),
            tx,
        };
        let draft = yw_core::approval::build_evm_tx_request(
            yw_core::lang::Lang::Ko,
            ApprovalId::random().unwrap(),
            ApprovalOrigin::Site(BrowserOrigin::parse("https://app.example").unwrap()),
            yw_core::vault::EvmKeySource::Hardware(
                yw_core::bip32::path::AccountIndex::new(1).unwrap(),
            ),
            evm_account(),
            ApprovalKind::EvmTransaction,
            &chain,
            &decoded,
            &yw_core::evm::simulate::SimResult::skipped(),
            &yw_core::approval::ChainFacts::default(),
            Vec::new(),
            1_790_000_000_000,
        )
        .unwrap();
        let mut store = ApprovalStore::new();
        let request = store.issue(draft, 0, 1_790_000_000_000).unwrap();
        store.consume(request.id, request.digest, 1).unwrap()
    }

    /// The record fields of [`approved_card_tx`].
    fn card_tx_info() -> crate::events::SignInfo {
        crate::events::SignInfo {
            origin: "https://app.example".to_owned(),
            label: "dApp 거래".to_owned(),
            role: yw_core::journal::evm::Role::Original,
            now_unix_ms: 1_790_000_000_000,
        }
    }

    /// The tests that build an `App` (2026-11-21, S4 W0, spec/09 §2.1), in
    /// `app/tests/chain_sites.rs`: a child of this module, so that they reach its helpers.
    /// The path is relative to `app_chain_sites/tests/` (an inline module of a
    /// non-`mod.rs` file).
    #[path = "../../app/tests/chain_sites.rs"]
    mod app_tests;
}
