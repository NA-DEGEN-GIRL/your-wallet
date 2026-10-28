//! The RPC worker thread `yw-rpc` (spec/04 §1.2): FIFO jobs over the shared HTTPS client —
//! endpoint tests, chain checks, balances, the send-form quote, EVM preparation and
//! re-simulation, broadcast, receipt tracking and user-chain checks. It never touches the DEK.
//! URLs travel inside jobs and are never logged (D13): logs carry `net=<NetworkId>` only.

use std::sync::mpsc::Receiver;

use yw_core::approval::TokenMeta;
use yw_core::evm::abi::balance_of_data;
use yw_core::evm::address::Address;
use yw_win::http::HttpsUrl;

use crate::errors::ErrorCode;
use crate::events::{BalanceSnapshot, EventQueue, RpcEvent, UiEvent};
use crate::flow::evm::form::quote;
use crate::flow::evm::prepare::{
    ChainEvent, PrepareJob, ResimJob, SendIntent, prepare, resimulate,
};
use crate::flow::evm::track::{TrackInput, broadcast, track_group};
use crate::flow::evm::user_chain::probe_chain;
use crate::flow::evm::{
    ChainCache, ChainCheck, ChainJob, Clock, Limits, SharedTransport, SystemClock,
};
use crate::logging::{self, Field};
use crate::network::NetworkId;
use crate::rpc::evm as rpc;
use crate::rpc::{RpcClient, TestOutcome, Transport, classify, test_endpoint};
use crate::sol::flow::{PreviewJob, SolEndpoint, TrackJob};
use crate::workers::journal::fault_point;

/// An RPC job.
pub enum RpcJob {
    /// Endpoint test with an explicit URL (typed or stored).
    Test {
        /// Network.
        network: NetworkId,
        /// Display name for the message.
        name: String,
        /// URL (secret).
        url: HttpsUrl,
    },
    /// Forget a chain's verification (URL or definition changed, spec/04 §1.9).
    ResetChain {
        /// Chain.
        chain_id: u64,
    },
    /// Native balances of `accounts` and token balances of `token_owner`.
    Balances {
        /// Job.
        job: u64,
        /// Chain.
        chain: ChainJob,
        /// Accounts.
        accounts: Vec<Address>,
        /// Tokens.
        tokens: Vec<Address>,
        /// Token owner (selected account).
        token_owner: Address,
    },
    /// Send-form quote.
    Quote {
        /// Job.
        job: u64,
        /// Chain.
        chain: ChainJob,
        /// Sender.
        from: Address,
        /// Intent.
        intent: SendIntent,
    },
    /// `eth_getCode` of a recipient (W-ADDR-4).
    Code {
        /// Job.
        job: u64,
        /// Chain.
        chain: ChainJob,
        /// Address.
        address: Address,
    },
    /// Token metadata (S16).
    TokenMeta {
        /// Job.
        job: u64,
        /// Chain.
        chain: ChainJob,
        /// Token.
        token: Address,
    },
    /// Approval preparation.
    Prepare(Box<PrepareJob>),
    /// Re-simulation at click.
    Resimulate(Box<ResimJob>),
    /// Broadcast a journaled transaction.
    Broadcast {
        /// Chain.
        chain: ChainJob,
        /// Signed bytes.
        raw: Vec<u8>,
        /// Hash.
        tx_hash: [u8; 32],
    },
    /// One tracking round.
    Track {
        /// Chain.
        chain: ChainJob,
        /// Input.
        input: TrackInput,
    },
    /// User chain RPC check.
    Probe {
        /// Job.
        job: u64,
        /// URL to check (secret).
        url: HttpsUrl,
        /// Expected chain id.
        chain_id: u64,
        /// Pinned genesis to compare (edit), `None` when adding or re-pinning.
        pinned: Option<[u8; 32]>,
        /// Check `baseFeePerGas` (adding).
        check_base_fee: bool,
    },
    /// Typed-data facts for a dApp signature (spec/03 §8.5).
    TypedFacts {
        /// UI job id.
        job: u64,
        /// Chain.
        chain: ChainJob,
        /// Signing account.
        account: Address,
        /// The validated typed data.
        typed: Box<yw_core::evm::eip712::DecodedTypedData>,
        /// Address-book names.
        address_book: Vec<(Address, String)>,
    },
    /// Solana balances of `accounts` (genesis checked first).
    SolBalances {
        /// Job.
        job: u64,
        /// Endpoint.
        endpoint: SolEndpoint,
        /// Accounts.
        accounts: Vec<yw_core::sol::SolAddress>,
    },
    /// Solana step-2 preview.
    SolPreview(Box<PreviewJob>),
    /// Solana step-5 lookup (after approval, before signing).
    SolPreSign {
        /// Job.
        job: u64,
        /// Endpoint.
        endpoint: SolEndpoint,
    },
    /// One Solana broadcast round.
    SolTrack(Box<TrackJob>),
    /// Solana recovery scan.
    SolScan {
        /// Job.
        job: u64,
        /// Endpoint.
        endpoint: SolEndpoint,
        /// Sources and their addresses.
        keys: Vec<(yw_core::slip10::SolKeySource, yw_core::sol::SolAddress)>,
    },
    /// A Bitcoin job (spec/08).
    Btc(Box<crate::btc::work::BtcRpcJob>),
    /// Stop.
    Shutdown,
}

impl core::fmt::Debug for RpcJob {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.name())
    }
}

impl RpcJob {
    /// Fixed name for logs.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Test { .. } => "Test",
            Self::ResetChain { .. } => "ResetChain",
            Self::Balances { .. } => "Balances",
            Self::Quote { .. } => "Quote",
            Self::Code { .. } => "Code",
            Self::TokenMeta { .. } => "TokenMeta",
            Self::Prepare(_) => "Prepare",
            Self::Resimulate(_) => "Resimulate",
            Self::Broadcast { .. } => "Broadcast",
            Self::Track { .. } => "Track",
            Self::Probe { .. } => "Probe",
            Self::TypedFacts { .. } => "TypedFacts",
            Self::SolBalances { .. } => "SolBalances",
            Self::SolPreview(_) => "SolPreview",
            Self::SolPreSign { .. } => "SolPreSign",
            Self::SolTrack(_) => "SolTrack",
            Self::SolScan { .. } => "SolScan",
            Self::Btc(job) => job.name(),
            Self::Shutdown => "Shutdown",
        }
    }
}

/// Runs one test and builds its event; logs `rpc.test net=<NetworkId> result=<code|ok>`.
#[must_use]
pub fn run_test(
    transport: &dyn Transport,
    network: NetworkId,
    name: &str,
    url: &HttpsUrl,
) -> RpcEvent {
    let client = RpcClient::new(transport);
    let outcome = test_endpoint(&client, network, url);
    logging::info(
        "rpc",
        "rpc.test",
        &[
            ("net", Field::Net(network)),
            ("result", Field::Word(outcome.log_word())),
        ],
    );
    RpcEvent::Test {
        network,
        message: outcome.message(name),
        ok: matches!(outcome, TestOutcome::Ok(_)),
    }
}

/// The transport when the HTTPS client could not be created: every call fails like a connection
/// error, so each job still answers (E-RPC-001) through its normal path.
struct Unavailable;

impl Transport for Unavailable {
    fn post_json(
        &self,
        _url: &HttpsUrl,
        _body: &[u8],
        _max_response: usize,
    ) -> Result<crate::rpc::HttpReply, yw_win::http::HttpError> {
        Err(yw_win::http::HttpError::Os(yw_win::WinError {
            api: "WinHttpOpen",
            code: 0,
        }))
    }
}

/// The worker's state: transport, chain verification cache, clock, limits and the Bitcoin
/// sessions.
pub struct RpcWorker {
    transport: SharedTransport,
    cache: ChainCache,
    clock: Box<dyn Clock>,
    limits: Limits,
    btc: crate::btc::work::BtcWorker,
}

impl core::fmt::Debug for RpcWorker {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("RpcWorker")
    }
}

fn push(events: &EventQueue, event: RpcEvent) {
    if events.push(UiEvent::Rpc(event)).is_err() {
        logging::warn("rpc", "E-APP-005", &[]);
    }
}

fn log_check(chain_id: u64, check: &ChainCheck) {
    match check {
        ChainCheck::Verified { pinned_now, .. } => logging::info(
            "rpc",
            "chain.verified",
            &[
                ("net", Field::Net(NetworkId::Eip155(chain_id))),
                (
                    "pinned",
                    Field::Word(if *pinned_now { "now" } else { "no" }),
                ),
            ],
        ),
        other => logging::warn(
            "rpc",
            "chain.check",
            &[
                ("net", Field::Net(NetworkId::Eip155(chain_id))),
                (
                    "code",
                    Field::Code(other.code().unwrap_or(ErrorCode::App009)),
                ),
            ],
        ),
    }
}

impl RpcWorker {
    /// A worker; `transport = None` (client creation failed) answers every job with E-RPC-001.
    #[must_use]
    pub fn new(transport: Option<SharedTransport>, clock: Box<dyn Clock>, limits: Limits) -> Self {
        Self {
            transport: transport.unwrap_or_else(|| std::sync::Arc::new(Unavailable)),
            cache: ChainCache::default(),
            clock,
            limits,
            btc: crate::btc::work::BtcWorker::new(),
        }
    }

    /// The production worker.
    #[must_use]
    pub fn production(transport: Option<SharedTransport>) -> Self {
        Self::new(transport, Box::new(SystemClock), Limits::PRODUCTION)
    }

    /// Checks a chain (cached) and reports the result.
    fn ensure(
        &mut self,
        transport: &SharedTransport,
        chain: &ChainJob,
        events: &EventQueue,
    ) -> ChainCheck {
        let client = RpcClient::new(&**transport);
        let check = self.cache.ensure(
            &client,
            &chain.url,
            &chain.info,
            &*self.clock,
            self.limits.retry_delay_ms,
        );
        log_check(chain.info.chain_id, &check);
        push(
            events,
            RpcEvent::Chain {
                chain_id: chain.info.chain_id,
                check,
            },
        );
        check
    }

    fn balances(
        &mut self,
        transport: &SharedTransport,
        chain: &ChainJob,
        accounts: &[Address],
        tokens: &[Address],
        owner: &Address,
        events: &EventQueue,
    ) -> Result<BalanceSnapshot, ErrorCode> {
        match self.ensure(transport, chain, events) {
            ChainCheck::Verified { .. } => {}
            other => return Err(other.code().unwrap_or(ErrorCode::App009)),
        }
        let client = RpcClient::new(&**transport);
        let block = rpc::block_number(&client, &chain.url).map_err(classify)?;
        let tag = crate::rpc::canonical_quantity(block);
        let mut native = Vec::with_capacity(accounts.len());
        for account in accounts {
            let balance = rpc::balance(&client, &chain.url, account, &tag).map_err(classify)?;
            native.push((*account, balance));
        }
        let mut token_balances = Vec::with_capacity(tokens.len());
        for token in tokens {
            let value = rpc::eth_call(&client, &chain.url, token, &balance_of_data(owner), &tag)
                .ok()
                .and_then(|output| yw_core::evm::abi::decode_uint256_result(&output));
            token_balances.push((*token, value));
        }
        Ok(BalanceSnapshot {
            block,
            native,
            tokens: token_balances,
        })
    }

    fn token_meta(
        &mut self,
        transport: &SharedTransport,
        chain: &ChainJob,
        token: &Address,
        events: &EventQueue,
    ) -> Result<TokenMeta, ErrorCode> {
        match self.ensure(transport, chain, events) {
            ChainCheck::Verified { .. } => {}
            other => return Err(other.code().unwrap_or(ErrorCode::App009)),
        }
        let client = RpcClient::new(&**transport);
        let decimals = rpc::eth_call(
            &client,
            &chain.url,
            token,
            &yw_core::evm::abi::SEL_DECIMALS,
            "latest",
        )
        .map_err(classify)?;
        let symbol = rpc::eth_call(
            &client,
            &chain.url,
            token,
            &yw_core::evm::abi::SEL_SYMBOL,
            "latest",
        )
        .ok()
        .and_then(|output| yw_core::evm::abi::decode_symbol(&output));
        Ok(TokenMeta {
            symbol,
            decimals: yw_core::evm::abi::decode_decimals(&decimals),
            registered: false,
        })
    }

    /// Handles one job (pushes its events).
    #[expect(clippy::too_many_lines, reason = "one arm per job kind")]
    pub fn handle(&mut self, job: RpcJob, events: &EventQueue) {
        let transport = std::sync::Arc::clone(&self.transport);
        match job {
            RpcJob::Shutdown => {}
            RpcJob::Btc(btc_job) => {
                self.btc
                    .handle(&*transport, &*self.clock, *btc_job, &mut |event| {
                        push(events, RpcEvent::Btc(Box::new(event)));
                    });
            }
            RpcJob::Test { network, name, url } => {
                push(events, run_test(&*transport, network, &name, &url));
            }
            RpcJob::ResetChain { chain_id } => self.cache.reset(chain_id),
            RpcJob::TypedFacts {
                job,
                chain,
                account,
                typed,
                address_book,
            } => {
                let (facts, check) = crate::flow::evm::prepare::typed_facts(
                    &transport,
                    &mut self.cache,
                    &chain,
                    &account,
                    &typed,
                    address_book,
                    &*self.clock,
                    self.limits.retry_delay_ms,
                );
                log_check(chain.info.chain_id, &check);
                push(
                    events,
                    RpcEvent::Chain {
                        chain_id: chain.info.chain_id,
                        check,
                    },
                );
                push(
                    events,
                    RpcEvent::TypedFacts {
                        job,
                        facts: Box::new(facts),
                        check,
                    },
                );
            }
            RpcJob::Balances {
                job,
                chain,
                accounts,
                tokens,
                token_owner,
            } => {
                let result =
                    self.balances(&transport, &chain, &accounts, &tokens, &token_owner, events);
                push(
                    events,
                    RpcEvent::Balances {
                        job,
                        chain_id: chain.info.chain_id,
                        result,
                    },
                );
            }
            RpcJob::Quote {
                job,
                chain,
                from,
                intent,
            } => {
                let result = quote(
                    &transport,
                    &mut self.cache,
                    &chain,
                    &from,
                    &intent,
                    &*self.clock,
                    self.limits.retry_delay_ms,
                );
                push(events, RpcEvent::Quote { job, result });
            }
            RpcJob::Code {
                job,
                chain,
                address,
            } => {
                let result = match self.ensure(&transport, &chain, events) {
                    ChainCheck::Verified { .. } => {
                        let client = RpcClient::new(&*transport);
                        rpc::code(&client, &chain.url, &address)
                            .map(|code| !code.is_empty())
                            .map_err(classify)
                    }
                    other => Err(other.code().unwrap_or(ErrorCode::App009)),
                };
                push(
                    events,
                    RpcEvent::Code {
                        job,
                        address,
                        result,
                    },
                );
            }
            RpcJob::TokenMeta { job, chain, token } => {
                let result = self.token_meta(&transport, &chain, &token, events);
                push(events, RpcEvent::TokenMeta { job, token, result });
            }
            RpcJob::Prepare(prepare_job) => {
                let job_id = prepare_job.job;
                let result = prepare(
                    &transport,
                    &mut self.cache,
                    &prepare_job,
                    &*self.clock,
                    &|since_ms| {
                        push(
                            events,
                            RpcEvent::Simulating {
                                job: job_id,
                                since_ms,
                            },
                        );
                    },
                );
                for ChainEvent::Checked { chain_id, check } in &result.chain_events {
                    log_check(*chain_id, check);
                    push(
                        events,
                        RpcEvent::Chain {
                            chain_id: *chain_id,
                            check: *check,
                        },
                    );
                }
                if let crate::flow::evm::prepare::PrepareOutcome::Ready(prepared) = &result.outcome
                {
                    logging::info(
                        "rpc",
                        "evm.prepared",
                        &[
                            (
                                "net",
                                Field::Net(NetworkId::Eip155(prepare_job.chain.info.chain_id)),
                            ),
                            ("gas_limit", Field::Num(prepared.context.tx.gas_limit)),
                            ("sim_gas", Field::Num(prepared.sim_gas_used.unwrap_or(0))),
                        ],
                    );
                }
                push(events, RpcEvent::Prepared(Box::new(result)));
            }
            RpcJob::Resimulate(resim_job) => {
                let result = resimulate(&transport, &mut self.cache, &resim_job, &*self.clock);
                logging::info(
                    "rpc",
                    "evm.resimulated",
                    &[(
                        "net",
                        Field::Net(NetworkId::Eip155(resim_job.chain.info.chain_id)),
                    )],
                );
                push(events, RpcEvent::Resimulated(Box::new(result)));
            }
            RpcJob::Broadcast {
                chain,
                raw,
                tx_hash,
            } => {
                let outcome = broadcast(
                    &transport,
                    &chain.url,
                    chain.info.chain_id,
                    &raw,
                    &tx_hash,
                    &*self.clock,
                    self.limits.broadcast_retry_ms,
                );
                fault_point("evm.after_send_raw");
                logging::info(
                    "rpc",
                    "evm.broadcast",
                    &[
                        ("net", Field::Net(NetworkId::Eip155(chain.info.chain_id))),
                        ("tx", Field::Hash(&tx_hash)),
                        ("result", Field::Word(outcome.name())),
                    ],
                );
                push(
                    events,
                    RpcEvent::Broadcast {
                        chain_id: chain.info.chain_id,
                        tx_hash,
                        outcome,
                        at_unix_ms: self.clock.now_unix_ms(),
                    },
                );
            }
            RpcJob::Track { chain, input } => {
                let Some(key) = input
                    .group
                    .first()
                    .map(yw_core::journal::evm::EvmRecord::key)
                else {
                    return;
                };
                let result = match self.ensure(&transport, &chain, events) {
                    ChainCheck::Verified { .. } => track_group(&transport, &chain.url, &input),
                    other => crate::flow::evm::track::TrackResult {
                        drop_seen_unix_ms: input.drop_seen_unix_ms,
                        error: Some(other.code().unwrap_or(ErrorCode::App009)),
                        ..crate::flow::evm::track::TrackResult::default()
                    },
                };
                if let Some(code) = result.error {
                    logging::warn(
                        "rpc",
                        "evm.track",
                        &[
                            ("net", Field::Net(NetworkId::Eip155(key.chain_id))),
                            ("code", Field::Code(code)),
                        ],
                    );
                }
                push(events, RpcEvent::Tracked { key, result });
            }
            RpcJob::SolBalances {
                job,
                endpoint,
                accounts,
            } => {
                let result = crate::sol::flow::balances(&*transport, &endpoint, &accounts);
                if let Err(code) = result {
                    logging::warn(
                        "rpc",
                        "sol.balances",
                        &[
                            ("net", Field::Net(sol_net(&endpoint))),
                            ("code", Field::Code(code)),
                        ],
                    );
                }
                push(
                    events,
                    RpcEvent::SolBalances {
                        job,
                        cluster: endpoint.cluster,
                        result,
                    },
                );
            }
            RpcJob::SolPreview(preview_job) => {
                let result = crate::sol::flow::preview(&*transport, &preview_job);
                logging::info(
                    "rpc",
                    "sol.previewed",
                    &[("net", Field::Net(sol_net(&preview_job.endpoint)))],
                );
                push(events, RpcEvent::SolPreviewed(Box::new(result)));
            }
            RpcJob::SolPreSign { job, endpoint } => {
                let result = crate::sol::flow::pre_sign(&*transport, &endpoint);
                logging::info(
                    "rpc",
                    "sol.presign",
                    &[
                        ("net", Field::Net(sol_net(&endpoint))),
                        (
                            "result",
                            Field::Word(if result.is_ok() { "ok" } else { "err" }),
                        ),
                    ],
                );
                push(events, RpcEvent::SolPreSigned { job, result });
            }
            RpcJob::SolTrack(track_job) => {
                let result = crate::sol::flow::track_round(&*transport, &track_job, &*self.clock);
                if result.sends > 0 {
                    fault_point("sol.after_send");
                }
                push(events, RpcEvent::SolTracked(Box::new(result)));
            }
            RpcJob::SolScan {
                job,
                endpoint,
                keys,
            } => {
                let result = crate::sol::scan::scan(&*transport, &endpoint, &keys);
                logging::info(
                    "rpc",
                    "sol.scan",
                    &[
                        ("net", Field::Net(sol_net(&endpoint))),
                        (
                            "rows",
                            Field::Num(
                                result.as_ref().map_or(0, |rows| {
                                    u64::try_from(rows.len()).unwrap_or(u64::MAX)
                                }),
                            ),
                        ),
                    ],
                );
                push(events, RpcEvent::SolScanned { job, result });
            }
            RpcJob::Probe {
                job,
                url,
                chain_id,
                pinned,
                check_base_fee,
            } => {
                let result = probe_chain(&transport, &url, chain_id, pinned, check_base_fee);
                logging::info(
                    "rpc",
                    "chain.probe",
                    &[
                        ("net", Field::Net(NetworkId::Eip155(chain_id))),
                        (
                            "result",
                            Field::Word(match &result {
                                Ok(_) => "ok",
                                Err(error) => error.code().code(),
                            }),
                        ),
                    ],
                );
                push(events, RpcEvent::Probe { job, result });
            }
        }
    }
}

fn sol_net(endpoint: &SolEndpoint) -> NetworkId {
    crate::workers::journal::sol_network(endpoint.cluster)
}

/// The worker loop.
pub fn run(mut worker: RpcWorker, jobs: &Receiver<RpcJob>, events: &EventQueue) {
    while let Ok(job) = jobs.recv() {
        if matches!(job, RpcJob::Shutdown) {
            break;
        }
        worker.handle(job, events);
    }
}
