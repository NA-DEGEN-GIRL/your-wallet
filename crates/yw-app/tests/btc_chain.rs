//! `check_chain()` (spec/08 §2; spec/09 §4.4 BTC-N8): steps 1–4 and their caching
//! (first call, change → `reset`, 600 s; steps 1–2 before `testmempoolaccept` /
//! `sendrawtransaction`), the step-2 conditions, `chain_check_genesis` (testnet3 / signet /
//! mainnet genesis → blocked, then zero requests), `chain_check_indexer_genesis` (indexer genesis
//! mismatch → E-BTC-003, no address ever sent; tip lag → W-BTC-IDX-LAG only) and
//! `network_mismatch_blocks` (settings ≠ `BtcMeta` → zero BTC calls).

mod btc_support;

use std::sync::atomic::AtomicBool;

use btc_support::{
    MAINNET_GENESIS, MEDIAN_TIME, NOW_UNIX_SECS, Reply, Rig, SIGNET_GENESIS, TESTNET3_GENESIS,
    TESTNET4_GENESIS, TIP, TestResult, Verb, account, chain_info, chain_input, healthy,
};
use yw_app::btc::broadcast::{send_raw_transaction, test_mempool_accept};
use yw_app::btc::chain::{
    ChainInput, CoreCheckFailure, check_core, ensure_chain, judge_blockchain_info,
    lag_warning_text, tip_ahead_check,
};
use yw_app::btc::flow::{DiscoveryJob, RefreshJob, TrackJob, discover, observe_tx, refresh};
use yw_app::btc::rpc::BlockchainInfo;
use yw_app::btc::{BtcBlock, BtcClient, BtcError, ChainSession, IndexerError, Trigger};
use yw_app::errors::ErrorCode;
use yw_app::settings::BtcIndexer;
use yw_core::btc::{BtcNetwork, Discovery, Txid};

fn new_session() -> ChainSession {
    ChainSession::new(BtcNetwork::Testnet4, BtcNetwork::Testnet4)
}

fn with_core_genesis(genesis: &'static str) -> impl Fn(&btc_support::Call) -> Reply {
    move |call| {
        if call.method == "getblockhash" {
            Reply::Result(format!("\"{genesis}\""))
        } else {
            healthy(call)
        }
    }
}

fn with_indexer_genesis(genesis: &'static str) -> impl Fn(&btc_support::Call) -> Reply {
    move |call| match (call.verb, call.path(), call.method.as_str()) {
        (Verb::Get, "/block-height/0", _) => Reply::text(genesis),
        (Verb::Rpc, _, "bb_getBlockHash") => {
            Reply::Result(format!("{{\"blockHash\":\"{genesis}\"}}"))
        }
        _ => healthy(call),
    }
}

/// Every BTC pipeline once; all must fail with `expected` and send nothing.
fn every_pipeline_blocked(rig: &Rig, session: &mut ChainSession, expected: BtcBlock) {
    let before = rig.fake.count();
    let client = BtcClient::new(rig.env(), &rig.endpoint);
    let input = chain_input();
    let blocked = Err(BtcError::Blocked(expected));
    assert_eq!(ensure_chain(&client, session, input, true), blocked);
    assert_eq!(check_core(&client, session, input), blocked);
    let discovery = DiscoveryJob {
        account: account(),
        discovery: Discovery::full(),
        chain: input,
    };
    assert_eq!(
        discover(
            &client,
            session,
            &discovery,
            &AtomicBool::new(false),
            &mut |_| {}
        )
        .err(),
        Some(BtcError::Blocked(expected))
    );
    let job = RefreshJob {
        account: account(),
        receive_count: 3,
        change_count: 1,
        known: Vec::new(),
        inflight_change: Vec::new(),
        chain: input,
        trigger: Trigger::User,
    };
    assert_eq!(
        refresh(&client, session, &job).err(),
        Some(BtcError::Blocked(expected))
    );
    let track = TrackJob {
        txid: Txid::from_bytes([7; 32]),
        mempool_entry: true,
        indexer_only: false,
        replacements: Vec::new(),
        trigger: Trigger::User,
        chain: input,
    };
    assert_eq!(
        observe_tx(&client, session, &track).err(),
        Some(BtcError::Blocked(expected))
    );
    assert_eq!(
        test_mempool_accept(&client, session, &[1, 2], "0.00002000", input).err(),
        Some(BtcError::Blocked(expected))
    );
    assert_eq!(
        send_raw_transaction(
            &client,
            session,
            &[1, 2],
            "0.00002000",
            &Txid::from_bytes([7; 32]),
            input
        )
        .err(),
        Some(BtcError::Blocked(expected))
    );
    assert_eq!(rig.fake.count(), before, "no BTC request while blocked");
}

#[test]
fn chain_check_passes_and_caches() -> TestResult {
    let rig = Rig::new(BtcIndexer::Esplora, healthy);
    let client = BtcClient::new(rig.env(), &rig.endpoint);
    let mut session = new_session();
    assert!(!session.indexer_verified());
    let input = ChainInput {
        max_tip_seen: TIP - 6,
        now_unix_secs: NOW_UNIX_SECS,
    };
    let status = ensure_chain(&client, &mut session, input, false)?;
    assert_eq!(status.tip_height, TIP);
    assert_eq!(status.max_tip_seen, TIP);
    assert_eq!(status.lag_warning, None);
    assert!(session.indexer_verified());
    assert_eq!(rig.fake.methods(), ["getblockhash", "getblockchaininfo"]);
    assert_eq!(
        rig.fake.get_paths(),
        ["/block-height/0", "/blocks/tip/height"]
    );
    // Cached within 600 s: nothing, or only step 2 when the caller needs a current tip.
    ensure_chain(&client, &mut session, input, false)?;
    assert_eq!(rig.fake.count(), 4);
    ensure_chain(&client, &mut session, input, true)?;
    assert_eq!(
        rig.fake.methods(),
        ["getblockhash", "getblockchaininfo", "getblockchaininfo"]
    );
    // 600 s later: steps 1–4 again.
    rig.clock.advance(600_000);
    ensure_chain(&client, &mut session, input, false)?;
    assert_eq!(rig.fake.count(), 9);
    // A change (endpoint, indexer, Esplora base) resets the session.
    session.reset();
    assert!(!session.indexer_verified());
    ensure_chain(&client, &mut session, input, false)?;
    assert_eq!(rig.fake.count(), 13);
    // check_core always runs steps 1–2.
    check_core(&client, &mut session, input)?;
    assert_eq!(rig.fake.count(), 15);
    rig.log.assert_no_url();
    Ok(())
}

#[test]
fn chain_check_genesis() {
    for genesis in [TESTNET3_GENESIS, SIGNET_GENESIS, MAINNET_GENESIS] {
        let rig = Rig::new(BtcIndexer::Esplora, with_core_genesis(genesis));
        let client = BtcClient::new(rig.env(), &rig.endpoint);
        let mut session = new_session();
        let blocked = BtcBlock::Core(CoreCheckFailure::Genesis);
        assert_eq!(
            ensure_chain(&client, &mut session, chain_input(), false),
            Err(BtcError::Blocked(blocked))
        );
        assert_eq!(rig.fake.methods(), ["getblockhash"]);
        assert_eq!(session.blocked(), Some(blocked));
        assert_eq!(blocked.code(), Some(ErrorCode::Rpc006));
        assert_eq!(
            blocked.text(),
            "RPC가 다른 네트워크를 가리킵니다. 작업을 중단했습니다. (E-RPC-006)"
        );
        every_pipeline_blocked(&rig, &mut session, blocked);
        assert!(rig.fake.get_paths().is_empty(), "no address sent");
    }
    // A malformed genesis is a failed call, not a mismatch.
    let rig = Rig::new(BtcIndexer::Esplora, with_core_genesis("00"));
    let client = BtcClient::new(rig.env(), &rig.endpoint);
    let mut session = new_session();
    assert!(matches!(
        ensure_chain(&client, &mut session, chain_input(), false),
        Err(BtcError::Core(_))
    ));
    assert_eq!(session.blocked(), None);
}

#[test]
fn chain_check_step2_conditions() {
    let net = BtcNetwork::Testnet4;
    let info = |chain: Option<BtcNetwork>, blocks: u32, headers: u32, ibd: bool, median: u64| {
        BlockchainInfo {
            chain,
            blocks,
            headers,
            initial_block_download: ibd,
            median_time: median,
        }
    };
    let now = NOW_UNIX_SECS;
    let judge = |info: &BlockchainInfo, max: u32| judge_blockchain_info(info, net, max, now);
    let good = info(Some(net), 1_000, 1_002, false, now - 86_400);
    assert_eq!(judge(&good, 1_006), Ok(1_000));
    assert_eq!(
        judge(&info(Some(net), 1_000, 1_000, false, now + 7_200), 0),
        Ok(1_000)
    );
    for (bad, max, failure) in [
        (
            info(None, 1_000, 1_000, false, now),
            0,
            CoreCheckFailure::Chain,
        ),
        (
            info(Some(BtcNetwork::Mainnet), 1_000, 1_000, false, now),
            0,
            CoreCheckFailure::Chain,
        ),
        (
            info(Some(net), 1_000, 1_000, true, now),
            0,
            CoreCheckFailure::InitialBlockDownload,
        ),
        (
            info(Some(net), 1_000, 1_003, false, now),
            0,
            CoreCheckFailure::HeadersAhead,
        ),
        (
            info(Some(net), 1_000, 1_000, false, now - 86_401),
            0,
            CoreCheckFailure::MedianTime,
        ),
        (
            info(Some(net), 1_000, 1_000, false, now + 7_201),
            0,
            CoreCheckFailure::MedianTime,
        ),
        (
            info(Some(net), 1_000, 1_000, false, now),
            1_007,
            CoreCheckFailure::TipRegressed,
        ),
    ] {
        assert_eq!(judge(&bad, max), Err(failure), "{bad:?} {max}");
    }

    // Through the pipeline: `chain: "test"` (testnet3 name) blocks the session.
    for (body, failure) in [
        (
            chain_info("test", TIP, TIP, false, MEDIAN_TIME),
            CoreCheckFailure::Chain,
        ),
        (
            chain_info("testnet4", TIP, TIP, true, MEDIAN_TIME),
            CoreCheckFailure::InitialBlockDownload,
        ),
        (
            chain_info("testnet4", TIP, TIP + 3, false, MEDIAN_TIME),
            CoreCheckFailure::HeadersAhead,
        ),
    ] {
        let rig = Rig::new(BtcIndexer::Esplora, move |call| {
            if call.method == "getblockchaininfo" {
                Reply::Result(body.clone())
            } else {
                healthy(call)
            }
        });
        let client = BtcClient::new(rig.env(), &rig.endpoint);
        let mut session = new_session();
        assert_eq!(
            ensure_chain(&client, &mut session, chain_input(), false),
            Err(BtcError::Blocked(BtcBlock::Core(failure)))
        );
        every_pipeline_blocked(&rig, &mut session, BtcBlock::Core(failure));
    }
    // Tip regression against the persisted `max_tip_seen`.
    let rig = Rig::new(BtcIndexer::Esplora, healthy);
    let client = BtcClient::new(rig.env(), &rig.endpoint);
    let mut session = new_session();
    let regressed = ChainInput {
        max_tip_seen: TIP + 7,
        now_unix_secs: NOW_UNIX_SECS,
    };
    assert_eq!(
        ensure_chain(&client, &mut session, regressed, false),
        Err(BtcError::Blocked(BtcBlock::Core(
            CoreCheckFailure::TipRegressed
        )))
    );
}

#[test]
fn chain_check_indexer_genesis() -> TestResult {
    for indexer in [BtcIndexer::Esplora, BtcIndexer::BbRpc] {
        for genesis in [TESTNET3_GENESIS, SIGNET_GENESIS, MAINNET_GENESIS] {
            let rig = Rig::new(indexer, with_indexer_genesis(genesis));
            let client = BtcClient::new(rig.env(), &rig.endpoint);
            let mut session = new_session();
            assert_eq!(
                ensure_chain(&client, &mut session, chain_input(), false),
                Err(BtcError::Blocked(BtcBlock::Indexer))
            );
            assert_eq!(BtcBlock::Indexer.code(), Some(ErrorCode::Btc003));
            every_pipeline_blocked(&rig, &mut session, BtcBlock::Indexer);
            for call in rig.fake.calls() {
                assert!(!call.url.contains("/address/") && !call.params.contains("tb1"));
            }
        }
    }
    // Step 3 failing (404, 500, malformed) is not a mismatch: no block, no address request.
    for reply in [Reply::status(404), Reply::status(500), Reply::text("x")] {
        let rig = Rig::new(BtcIndexer::Esplora, move |call| {
            if call.path() == "/block-height/0" {
                reply.clone()
            } else {
                healthy(call)
            }
        });
        let client = BtcClient::new(rig.env(), &rig.endpoint);
        let mut session = new_session();
        let error = ensure_chain(&client, &mut session, chain_input(), false)
            .err()
            .ok_or("step 3 failure")?;
        assert!(matches!(
            error,
            BtcError::Indexer(IndexerError::Malformed | IndexerError::Unreachable(None))
        ));
        assert_eq!(session.blocked(), None);
        assert!(!session.indexer_verified());
        let job = RefreshJob {
            account: account(),
            receive_count: 2,
            change_count: 0,
            known: Vec::new(),
            inflight_change: Vec::new(),
            chain: chain_input(),
            trigger: Trigger::User,
        };
        assert!(refresh(&client, &mut session, &job).is_err());
        assert!(
            rig.fake
                .get_paths()
                .iter()
                .all(|path| !path.starts_with("/address/"))
        );
    }
    // Step 4: tip lag 4 → W-BTC-IDX-LAG only; 3 → nothing; failure → logged only.
    for (tip, lag) in [(TIP + 4, Some(4)), (TIP - 4, Some(4)), (TIP + 3, None)] {
        let rig = Rig::new(BtcIndexer::Esplora, move |call| {
            if call.path() == "/blocks/tip/height" {
                Reply::text(&tip.to_string())
            } else {
                healthy(call)
            }
        });
        let client = BtcClient::new(rig.env(), &rig.endpoint);
        let mut session = new_session();
        let status = ensure_chain(&client, &mut session, chain_input(), false)?;
        assert_eq!(status.lag_warning, lag);
        assert_eq!(session.blocked(), None);
        assert!(session.indexer_verified());
    }
    assert_eq!(
        lag_warning_text(4),
        "인덱서와 노드의 블록 높이가 4 차이 납니다. 잔액·확인 수가 늦게 반영될 수 있습니다"
    );
    let rig = Rig::new(BtcIndexer::Esplora, |call| {
        if call.path() == "/blocks/tip/height" {
            Reply::status(500)
        } else {
            healthy(call)
        }
    });
    let client = BtcClient::new(rig.env(), &rig.endpoint);
    let mut session = new_session();
    let status = ensure_chain(&client, &mut session, chain_input(), false)?;
    assert_eq!(status.lag_warning, None);
    assert!(session.indexer_verified());
    // bb-* indexers have no step 4.
    let rig = Rig::new(BtcIndexer::BbRpc, healthy);
    let client = BtcClient::new(rig.env(), &rig.endpoint);
    let mut session = new_session();
    ensure_chain(&client, &mut session, chain_input(), false)?;
    assert_eq!(
        rig.fake.methods(),
        ["getblockhash", "getblockchaininfo", "bb_getBlockHash"]
    );
    assert!(rig.fake.get_paths().is_empty());
    let _ = TESTNET4_GENESIS;
    Ok(())
}

#[test]
fn network_mismatch_blocks() {
    let rig = Rig::new(BtcIndexer::Esplora, healthy);
    let mut session = ChainSession::new(BtcNetwork::Testnet4, BtcNetwork::Mainnet);
    assert_eq!(session.blocked(), Some(BtcBlock::NetworkMismatch));
    assert_eq!(
        BtcBlock::NetworkMismatch.text(),
        "BTC 네트워크 설정이 지갑 데이터와 다릅니다"
    );
    every_pipeline_blocked(&rig, &mut session, BtcBlock::NetworkMismatch);
    // `reset` does not lift it.
    session.reset();
    every_pipeline_blocked(&rig, &mut session, BtcBlock::NetworkMismatch);
    // An endpoint of another network than the session is refused the same way.
    let mut mainnet = ChainSession::new(BtcNetwork::Mainnet, BtcNetwork::Mainnet);
    every_pipeline_blocked(&rig, &mut mainnet, BtcBlock::NetworkMismatch);
    assert_eq!(rig.fake.count(), 0);
}

#[test]
fn chain_check_before_broadcast() -> TestResult {
    let rig = Rig::new(BtcIndexer::Esplora, |call| match call.method.as_str() {
        "testmempoolaccept" => {
            Reply::Envelope(btc_support::core::TESTNET4_TESTMEMPOOLACCEPT_MISSING_INPUTS.to_vec())
        }
        "sendrawtransaction" => Reply::RpcError(-26),
        _ => healthy(call),
    });
    let client = BtcClient::new(rig.env(), &rig.endpoint);
    let mut session = new_session();
    let input = chain_input();
    let accept = test_mempool_accept(&client, &mut session, &[1], "0.00002000", input)?;
    assert!(!accept.allowed);
    // The reject reason is logged as its known token only.
    assert!(
        rig.log
            .lines()
            .iter()
            .any(|line| line.contains("allowed=false reject=missing-inputs"))
    );
    let _ = send_raw_transaction(
        &client,
        &mut session,
        &[1],
        "0.00002000",
        &Txid::from_bytes([1; 32]),
        input,
    )?;
    assert_eq!(
        rig.fake.methods(),
        [
            "getblockhash",
            "getblockchaininfo",
            "testmempoolaccept",
            "getblockhash",
            "getblockchaininfo",
            "sendrawtransaction",
        ]
    );
    // A genesis mismatch right before sending: nothing is sent.
    let rig = Rig::new(BtcIndexer::Esplora, with_core_genesis(SIGNET_GENESIS));
    let client = BtcClient::new(rig.env(), &rig.endpoint);
    let mut session = new_session();
    assert!(
        send_raw_transaction(
            &client,
            &mut session,
            &[1],
            "0.00002000",
            &Txid::from_bytes([1; 32]),
            input
        )
        .is_err()
    );
    assert_eq!(rig.fake.methods(), ["getblockhash"]);
    Ok(())
}

/// Review M2: a Core tip at or above 500,000,000 (a lock-time timestamp) blocks the session; a
/// Core tip far above the Esplora tip raises `max_tip_seen` only to the indexer tip + 3, and
/// planning is refused while it is more than 6 blocks ahead.
#[test]
fn implausible_and_runaway_core_tip() -> TestResult {
    let net = BtcNetwork::Testnet4;
    let at = |blocks: u32| BlockchainInfo {
        chain: Some(net),
        blocks,
        headers: blocks,
        initial_block_download: false,
        median_time: NOW_UNIX_SECS,
    };
    assert_eq!(
        judge_blockchain_info(&at(499_999_999), net, 0, NOW_UNIX_SECS),
        Ok(499_999_999)
    );
    assert_eq!(
        judge_blockchain_info(&at(500_000_000), net, 0, NOW_UNIX_SECS),
        Err(CoreCheckFailure::TipImplausible)
    );
    // Through the pipeline: blocked.
    let rig = Rig::new(BtcIndexer::Esplora, move |call| {
        if call.method == "getblockchaininfo" {
            Reply::Result(chain_info(
                "testnet4",
                600_000_000,
                600_000_000,
                false,
                MEDIAN_TIME,
            ))
        } else {
            healthy(call)
        }
    });
    let client = BtcClient::new(rig.env(), &rig.endpoint);
    let mut session = new_session();
    assert_eq!(
        ensure_chain(&client, &mut session, chain_input(), false),
        Err(BtcError::Blocked(BtcBlock::Core(
            CoreCheckFailure::TipImplausible
        )))
    );
    // Core 100 blocks above the Esplora tip (157,717): `max_tip_seen` stops at indexer + 3.
    let ahead = TIP + 100;
    let rig = Rig::new(BtcIndexer::Esplora, move |call| {
        if call.method == "getblockchaininfo" {
            Reply::Result(chain_info("testnet4", ahead, ahead, false, MEDIAN_TIME))
        } else {
            healthy(call)
        }
    });
    let client = BtcClient::new(rig.env(), &rig.endpoint);
    let mut session = new_session();
    let status = ensure_chain(&client, &mut session, chain_input(), false)?;
    assert_eq!(status.tip_height, ahead);
    assert_eq!(status.max_tip_seen, TIP + 3);
    assert_eq!(session.indexer_tip(), Some(TIP));
    let status = ensure_chain(&client, &mut session, chain_input(), true)?;
    assert_eq!(status.max_tip_seen, TIP + 3, "cached path capped too");
    assert_eq!(
        tip_ahead_check(&client, &mut session, ahead)?,
        Err((ahead, TIP))
    );
    assert_eq!(tip_ahead_check(&client, &mut session, TIP + 6)?, Ok(()));
    // `bb-*` has no indexer tip: nothing to compare.
    let rig = Rig::new(BtcIndexer::BbRpc, healthy);
    let client = BtcClient::new(rig.env(), &rig.endpoint);
    let mut session = new_session();
    assert_eq!(tip_ahead_check(&client, &mut session, ahead)?, Ok(()));
    assert_eq!(rig.fake.count(), 0);
    Ok(())
}
