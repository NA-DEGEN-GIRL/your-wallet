//! Networks, constants and amounts (spec/08 §2, §4.3 `conf`, §7.3, §8.1, §15; spec/09 §3.11):
//! the network table and genesis pins (testnet3/signet genesis must differ), the constant table,
//! the decimal BTC grammar (no floats), user BTC/sats input and the display strings.

use yw_core::bip32::path::BtcCoin;
use yw_core::btc::amount::{
    AmountError, Sats, format_btc, format_btc_and_sats, format_sats_grouped, parse_btc_decimal,
    parse_user_btc, parse_user_sats,
};
use yw_core::btc::network::{
    BtcNetwork, MAINNET_GENESIS_HEX, SIGNET_GENESIS_HEX, TESTNET3_GENESIS_HEX, TESTNET4_GENESIS_HEX,
};
use yw_core::btc::{self, MAX_MONEY, conf};
use yw_core::hex;

#[test]
fn network_table() {
    use BtcNetwork::{Mainnet, Testnet4};
    assert_eq!(BtcNetwork::ALL, [Mainnet, Testnet4]);
    assert_eq!((Mainnet.id(), Testnet4.id()), (1, 2));
    for net in BtcNetwork::ALL {
        assert_eq!(BtcNetwork::from_id(net.id()), Some(net));
        assert_eq!(
            BtcNetwork::parse_settings_name(net.settings_name()),
            Some(net)
        );
        assert_eq!(hex::encode(&net.genesis()), net.genesis_hex());
        assert_eq!(net.other().other(), net);
    }
    assert_eq!(BtcNetwork::from_id(0), None);
    assert_eq!(BtcNetwork::from_id(3), None);
    assert_eq!(BtcNetwork::parse_settings_name("Mainnet"), None);
    assert_eq!(BtcNetwork::parse_settings_name("testnet"), None);
    assert_eq!(Mainnet.coin_type(), BtcCoin::Mainnet);
    assert_eq!(Testnet4.coin_type(), BtcCoin::Test);
    assert_eq!(
        Mainnet.genesis_hex(),
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    );
    assert_eq!(
        Testnet4.genesis_hex(),
        "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043"
    );
    assert_eq!(MAINNET_GENESIS_HEX, Mainnet.genesis_hex());
    assert_eq!(TESTNET4_GENESIS_HEX, Testnet4.genesis_hex());
    assert_eq!(Mainnet.genesis()[..3], [0, 0, 0]);
    // testnet3 and signet share tb/0x6f/0xc4 with testnet4; only the genesis differs.
    for other in [TESTNET3_GENESIS_HEX, SIGNET_GENESIS_HEX] {
        assert_eq!(other.len(), 64);
        assert!(BtcNetwork::ALL.iter().all(|net| net.genesis_hex() != other));
    }
    assert_eq!(
        TESTNET3_GENESIS_HEX,
        "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"
    );
    assert_eq!(
        SIGNET_GENESIS_HEX,
        "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6"
    );
    assert_eq!(
        (Mainnet.core_chain(), Testnet4.core_chain()),
        ("main", "testnet4")
    );
    assert_eq!((Mainnet.hrp(), Testnet4.hrp()), ("bc", "tb"));
    assert_eq!(
        (Mainnet.p2pkh_version(), Mainnet.p2sh_version()),
        (0x00, 0x05)
    );
    assert_eq!(
        (Testnet4.p2pkh_version(), Testnet4.p2sh_version()),
        (0x6f, 0xc4)
    );
    assert_eq!(
        (Mainnet.network_id(), Testnet4.network_id()),
        ("bitcoin:mainnet", "bitcoin:testnet4")
    );
    assert_eq!(
        (Mainnet.settings_name(), Testnet4.settings_name()),
        ("mainnet", "testnet4")
    );
    assert_eq!(
        (Mainnet.display_name(), Testnet4.display_name()),
        ("Bitcoin 메인넷", "Bitcoin testnet4")
    );
    assert_eq!(
        (Mainnet.banner(), Testnet4.banner()),
        ("BITCOIN MAINNET", "BITCOIN TESTNET4 — 가치 없음")
    );
    assert_eq!(
        (Mainnet.esplora_default(), Testnet4.esplora_default()),
        (
            "https://mempool.space/api",
            "https://mempool.space/testnet4/api"
        )
    );
}

/// spec/08 §15.
#[test]
fn constants() {
    assert_eq!(MAX_MONEY, 2_100_000_000_000_000);
    assert_eq!((btc::BTC_GAP_LIMIT, btc::BTC_GAP_HARD_LIMIT), (20, 100));
    assert_eq!(
        (btc::BTC_TX_VERSION, btc::BTC_SEQUENCE, btc::SIGHASH_ALL),
        (2, 0xFFFF_FFFD, 0x01)
    );
    assert_eq!(
        (
            btc::BTC_MAX_INPUTS,
            btc::BTC_MIN_CONF,
            btc::BTC_COINBASE_MATURITY
        ),
        (100, 1, 100)
    );
    assert_eq!(
        (btc::BTC_CHANGE_DUST, btc::BTC_AUTO_FREEZE_BELOW),
        (294, 1_000)
    );
    assert_eq!(btc::BTC_FEE_FLOOR_DEFAULT, 1_000);
    assert_eq!(
        (btc::BTC_FEE_RATE_CAP, btc::BTC_FEE_RATE_UNOVERRIDABLE),
        (500_000, 10_000_000)
    );
    assert_eq!(
        (btc::BTC_FEE_ABS_CAP, btc::BTC_FEE_RATIO_CONFIRM),
        (500_000, 50)
    );
    assert_eq!(btc::BTC_CONF_TARGETS, [2, 6, 24]);
    assert_eq!(btc::BTC_MAX_PREV_TX_BYTES, 400_000);
    assert_eq!(
        (btc::BTC_MAX_JOURNAL_RAW, btc::BTC_JOURNAL_FINAL_KEEP),
        (32_768, 64)
    );
    assert_eq!(
        (
            btc::BTC_REQ_MIN_INTERVAL_MS,
            btc::BTC_POLL_SECS,
            btc::BTC_CHAIN_RECHECK_SECS
        ),
        (200, 60, 600)
    );
    assert_eq!(btc::BTC_429_BACKOFF_MS, [2_000, 4_000, 8_000]);
    assert_eq!(btc::BTC_429_COOLDOWN_SECS, 300);
    assert_eq!(
        (
            btc::BTC_ESPLORA_DEFAULT_MAINNET,
            btc::BTC_ESPLORA_DEFAULT_TESTNET4
        ),
        (
            "https://mempool.space/api",
            "https://mempool.space/testnet4/api"
        )
    );
    assert_eq!(
        (btc::BTC_INDEXER_MAX_UTXOS, btc::BTC_INDEXER_TIP_LAG_WARN),
        (1_000, 3)
    );
    assert_eq!(btc::BTC_NOT_FOUND_LIMIT, 10);
}

/// spec/08 §4.3: `tip_height >= height ? tip_height - height + 1 : 0`.
#[test]
fn confirmations() {
    assert_eq!(conf(100, 100), 1);
    assert_eq!(conf(100, 105), 6);
    assert_eq!(conf(101, 100), 0);
    assert_eq!(conf(0, 0), 1);
    assert_eq!(conf(u32::MAX, 0), 0);
    assert_eq!(conf(0, u32::MAX), u32::MAX);
}

#[test]
fn sats_type() {
    assert_eq!(Sats::new(MAX_MONEY), Some(Sats::MAX));
    assert_eq!(Sats::new(MAX_MONEY + 1), None);
    assert_eq!(
        Sats::try_from(MAX_MONEY + 1),
        Err(AmountError::AboveMaxMoney)
    );
    let one = Sats::new(1).unwrap();
    assert_eq!(Sats::MAX.checked_add(one), None);
    assert_eq!(Sats::ZERO.checked_sub(one), None);
    assert_eq!(one.checked_sub(one), Some(Sats::ZERO));
    assert_eq!(Sats::checked_sum([one, one, one]).map(Sats::get), Some(3));
    assert_eq!(Sats::checked_sum([Sats::MAX, one]), None);
    assert_eq!(u64::from(one), 1);
}

/// spec/08 §8.1 grammar `^(0|[1-9][0-9]{0,7})(\.[0-9]{1,8})?$`, decimal-point shift only
/// (spec/08 §14.2 `fee_units_btc_per_kvb`: `0.00001000` → 1,000 sat/kvB).
#[test]
fn btc_decimal_grammar() {
    let accepted = [
        ("0.00001000", 1_000),
        ("0.00012000", 12_000),
        ("0", 0),
        ("0.0", 0),
        ("1", 100_000_000),
        ("1.5", 150_000_000),
        ("0.00000001", 1),
        ("21000000", MAX_MONEY),
        ("20999999.99999999", MAX_MONEY - 1),
        ("12345678.12345678", 1_234_567_812_345_678),
    ];
    for (text, sats) in accepted {
        assert_eq!(parse_btc_decimal(text).map(Sats::get), Ok(sats), "{text}");
        assert_eq!(parse_user_btc(text).map(Sats::get), Ok(sats), "{text}");
    }
    for text in [
        "",
        "1e-05",
        "1E3",
        "-0.1",
        "+1",
        "0.000000001",
        "00",
        "01",
        "01.5",
        ".5",
        "5.",
        "1.2.3",
        " 1",
        "1 ",
        "1,000",
        "１",
        "123456789",
        "0x10",
        "NaN",
        "1_000",
        "0.1e1",
    ] {
        assert_eq!(
            parse_btc_decimal(text),
            Err(AmountError::InvalidFormat),
            "{text:?}"
        );
    }
    assert_eq!(
        parse_btc_decimal("21000000.00000001"),
        Err(AmountError::AboveMaxMoney)
    );
    assert_eq!(
        parse_btc_decimal("99999999.99999999"),
        Err(AmountError::AboveMaxMoney)
    );
}

/// spec/08 §7.3 sats input `^[1-9][0-9]{0,15}$`.
#[test]
fn user_sats_grammar() {
    assert_eq!(parse_user_sats("1").map(Sats::get), Ok(1));
    assert_eq!(parse_user_sats("120000").map(Sats::get), Ok(120_000));
    assert_eq!(
        parse_user_sats("2100000000000000").map(Sats::get),
        Ok(MAX_MONEY)
    );
    assert_eq!(
        parse_user_sats("2100000000000001"),
        Err(AmountError::AboveMaxMoney)
    );
    assert_eq!(
        parse_user_sats("9999999999999999"),
        Err(AmountError::AboveMaxMoney)
    );
    for text in [
        "",
        "0",
        "01",
        "-1",
        "+1",
        "1.0",
        "1e3",
        "1,000",
        "12345678901234567",
        " 1",
        "1 ",
    ] {
        assert_eq!(
            parse_user_sats(text),
            Err(AmountError::InvalidFormat),
            "{text:?}"
        );
    }
}

#[test]
fn formatting() {
    let sats = |value: u64| Sats::new(value).unwrap();
    assert_eq!(format_btc(sats(120_000)), "0.00120000");
    assert_eq!(format_btc(Sats::ZERO), "0.00000000");
    assert_eq!(format_btc(sats(1)), "0.00000001");
    assert_eq!(format_btc(sats(100_000_000)), "1.00000000");
    assert_eq!(format_btc(Sats::MAX), "21000000.00000000");
    assert_eq!(format_sats_grouped(0), "0");
    assert_eq!(format_sats_grouped(999), "999");
    assert_eq!(format_sats_grouped(1_000), "1,000");
    assert_eq!(format_sats_grouped(120_000), "120,000");
    assert_eq!(format_sats_grouped(1_234_567), "1,234,567");
    assert_eq!(format_sats_grouped(MAX_MONEY), "2,100,000,000,000,000");
    assert_eq!(
        format_btc_and_sats(sats(120_000)),
        "0.00120000 BTC (120,000 sats)"
    );
    for value in [0, 1, 99, 120_000, 123_456_789, MAX_MONEY] {
        assert_eq!(
            parse_btc_decimal(&format_btc(sats(value))).map(Sats::get),
            Ok(value)
        );
    }
}
