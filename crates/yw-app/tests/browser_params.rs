//! spec/05 §10.2 R-V1 (`browser::params`, ported from `archive/spec-v2.4:crates/broker/src/
//! params.rs:673-829` with the reversed and added cases) and spec/09 §4.2 X-1, X-2 (format part;
//! X-3 and the origin-chain rules are dispatcher tests in `browser_dispatch.rs`).

mod common;

use common::browser::json;
use yw_app::browser::params::{LogsBound, LogsRange, Validated, check_logs_range, validate};
use yw_core::policy::{Method, ProviderError};

const A: &str = "0x1111111111111111111111111111111111111111";
const B: &str = "0x2222222222222222222222222222222222222222";
const EIP55: &str = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
const BAD_SUM: &str = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD";
const H: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn ok(method: Method, params: &str) -> TestResult<Validated> {
    validate(method, &json(params)).map_err(|error| format!("{params}: {error:?}").into())
}

fn bad(method: Method, params: &str) {
    assert_eq!(
        validate(method, &json(params)),
        Err(ProviderError::InvalidParams),
        "{params}"
    );
}

fn forwarded(method: Method, params: &str) -> TestResult<String> {
    match ok(method, params)? {
        Validated::Read(read) => Ok(String::from_utf8(yw_json::to_vec(&read.params))?),
        other => Err(format!("not a read: {other:?}").into()),
    }
}

fn logs_range(params: &str) -> TestResult<Option<LogsRange>> {
    match ok(Method::GetLogs, params)? {
        Validated::Read(read) => Ok(read.logs),
        other => Err(format!("not a read: {other:?}").into()),
    }
}

#[test]
fn r_v1_exact_arrays_and_objects() -> TestResult {
    bad(Method::Accounts, r#"["surprise"]"#);
    bad(Method::Accounts, "{}");
    assert_eq!(ok(Method::Accounts, "[]")?, Validated::Empty);
    assert_eq!(ok(Method::ClientVersion, "[]")?, Validated::Empty);
    bad(
        Method::SwitchEthereumChain,
        r#"[{"chainId":"0x1","ignored":true}]"#,
    );
    bad(Method::SwitchEthereumChain, r#"[{"chainId":1}]"#);
    bad(Method::SwitchEthereumChain, r#"[{"chainId":"0x"}]"#);
    bad(
        Method::SwitchEthereumChain,
        r#"[{"chainId":"0x10000000000000000"}]"#,
    );
    assert_eq!(
        ok(Method::SwitchEthereumChain, r#"[{"chainId":"0x02105"}]"#)?,
        Validated::Switch(8453)
    );
    assert_eq!(
        ok(Method::SwitchEthereumChain, r#"[{"chainId":"0x0"}]"#)?,
        Validated::Switch(0)
    );
    assert_eq!(
        ok(Method::RequestPermissions, r#"[{"eth_accounts":{}}]"#)?,
        Validated::Permissions
    );
    bad(
        Method::RevokePermissions,
        r#"[{"eth_accounts":{"requiredMethods":[]}}]"#,
    );
    bad(Method::RevokePermissions, r#"[{"eth_accounts":{},"x":{}}]"#);
    Ok(())
}

#[test]
fn r_v1_addresses_quantities_hashes_normalize() -> TestResult {
    // EIP-55 accepted (archive 707-726 reversed), wrong checksum rejected, upper case accepted.
    assert_eq!(
        forwarded(Method::GetBalance, &format!(r#"["{EIP55}","latest"]"#))?,
        r#"["0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed","latest"]"#
    );
    bad(Method::GetBalance, &format!(r#"["{BAD_SUM}","latest"]"#));
    assert_eq!(
        forwarded(
            Method::GetBalance,
            r#"["0x5AAEB6053F3E94C9B9A09F33669435E7EF1BEAED"]"#
        )?,
        r#"["0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed","latest"]"#
    );
    bad(
        Method::GetBalance,
        r#"["0X1111111111111111111111111111111111111111"]"#,
    );
    bad(Method::GetBalance, r#"["0x1111"]"#);
    bad(Method::GetBalance, "[1]");
    // Upper-case and leading-zero quantities are normalized (the archive rejected them).
    assert_eq!(
        forwarded(Method::GetBalance, &format!(r#"["{A}","0x00A"]"#))?,
        format!(r#"["{A}","0xa"]"#)
    );
    assert_eq!(
        forwarded(Method::GetBalance, &format!(r#"["{A}","0x0"]"#))?,
        format!(r#"["{A}","0x0"]"#)
    );
    bad(Method::GetBalance, &format!(r#"["{A}","0x"]"#));
    bad(Method::GetBalance, &format!(r#"["{A}",10]"#));
    bad(
        Method::GetBalance,
        &format!(r#"["{A}","0x10000000000000000"]"#),
    );
    bad(Method::GetBalance, &format!(r#"["{A}","newest"]"#));
    assert_eq!(
        forwarded(
            Method::GetStorageAt,
            &format!(
                r#"["{A}","0x0000000000000000000000000000000000000000000000000000000000000002"]"#
            )
        )?,
        format!(r#"["{A}","0x2","latest"]"#)
    );
    bad(
        Method::GetStorageAt,
        &format!(r#"["{A}","0x{}"]"#, "0".repeat(65)),
    );
    // Hashes: any case → lowercase.
    assert_eq!(
        forwarded(
            Method::GetTransactionByHash,
            &format!(r#"["{}"]"#, H.to_uppercase().replacen("0X", "0x", 1))
        )?,
        format!(r#"["{H}"]"#)
    );
    bad(Method::GetTransactionReceipt, r#"["0x11"]"#);
    bad(Method::GetBlockByHash, &format!(r#"["{H}"]"#));
    assert_eq!(
        forwarded(Method::GetBlockByHash, &format!(r#"["{H}",true]"#))?,
        format!(r#"["{H}",true]"#)
    );
    assert_eq!(
        forwarded(Method::GetBlockByNumber, r#"["0x01",false]"#)?,
        r#"["0x1",false]"#
    );
    bad(Method::GetBlockByNumber, r#"[{"blockNumber":"0x1"},false]"#);
    Ok(())
}

#[test]
fn r_v1_eip1898_block_references() -> TestResult {
    assert_eq!(
        forwarded(
            Method::GetCode,
            &format!(r#"["{A}",{{"blockNumber":"0x0A"}}]"#)
        )?,
        format!(r#"["{A}",{{"blockNumber":"0xa"}}]"#)
    );
    assert_eq!(
        forwarded(
            Method::GetTransactionCount,
            &format!(r#"["{A}",{{"blockHash":"{H}","requireCanonical":true}}]"#)
        )?,
        format!(r#"["{A}",{{"blockHash":"{H}","requireCanonical":true}}]"#)
    );
    bad(
        Method::GetCode,
        &format!(r#"["{A}",{{"blockHash":"{H}","blockNumber":"0x1"}}]"#),
    );
    bad(
        Method::GetCode,
        &format!(r#"["{A}",{{"requireCanonical":true}}]"#),
    );
    bad(
        Method::GetCode,
        &format!(r#"["{A}",{{"blockHash":"{H}","requireCanonical":"yes"}}]"#),
    );
    Ok(())
}

#[test]
fn r_v1_calls_without_to_and_data_input() -> TestResult {
    // `to` omitted / null is allowed for reads (deployment estimate).
    assert_eq!(
        forwarded(
            Method::EstimateGas,
            &format!(r#"[{{"from":"{A}","data":"0x6000"}}]"#)
        )?,
        format!(r#"[{{"from":"{A}","input":"0x6000"}},"latest"]"#)
    );
    assert_eq!(
        forwarded(Method::Call, r#"[{"to":null,"input":"0xAB"}]"#)?,
        r#"[{"to":null,"input":"0xab"},"latest"]"#
    );
    // data = input (same bytes, any case) merged into `input`; different bytes rejected.
    assert_eq!(
        forwarded(
            Method::Call,
            &format!(r#"[{{"to":"{B}","data":"0xAbCd","input":"0xabcd"}}]"#)
        )?,
        format!(r#"[{{"to":"{B}","input":"0xabcd"}},"latest"]"#)
    );
    bad(
        Method::Call,
        &format!(r#"[{{"to":"{B}","data":"0xabcd","input":"0xabce"}}]"#),
    );
    bad(Method::Call, &format!(r#"[{{"to":"{B}","data":"0xabc"}}]"#));
    // Third argument (state override) rejected; unknown keys rejected.
    bad(Method::Call, &format!(r#"[{{"to":"{B}"}},"latest",{{}}]"#));
    bad(Method::Call, &format!(r#"[{{"to":"{B}","blobs":[]}}]"#));
    let oversized = format!("0x{}", "aa".repeat(131_073));
    bad(
        Method::Call,
        &format!(r#"[{{"to":"{B}","data":"{oversized}"}}]"#),
    );
    let largest = format!("0x{}", "aa".repeat(131_072));
    assert!(matches!(
        validate(
            Method::Call,
            &json(&format!(r#"[{{"to":"{B}","data":"{largest}"}}]"#))
        ),
        Ok(Validated::Read(_))
    ));
    Ok(())
}

#[test]
fn r_v1_x1_x2_send_transaction_rules() -> TestResult {
    let tx = |extra: &str| format!(r#"[{{"from":"{A}","to":"{B}"{extra}}}]"#);
    let Validated::Send(params) = ok(
        Method::SendTransaction,
        &tx(r#","value":"0x0DE0B6B3A7640000","gas":"0x5208","maxFeePerGas":"0x1","type":"0x2""#),
    )?
    else {
        return Err("not a send".into());
    };
    assert_eq!(params.value.to_quantity(), "0xde0b6b3a7640000");
    assert_eq!(params.gas, Some(21_000));
    assert!(params.fee_fields);
    let Validated::Send(plain) = ok(Method::SendTransaction, &tx(""))? else {
        return Err("not a send".into());
    };
    assert!(!plain.fee_fields);
    assert!(plain.data.is_empty());
    // X-1: forbidden keys.
    for key in [
        "authorizationList",
        "blobVersionedHashes",
        "blobs",
        "maxFeePerBlobGas",
        "commitments",
        "proofs",
        "foo",
    ] {
        bad(Method::SendTransaction, &tx(&format!(r#","{key}":[]"#)));
    }
    // X-2: type 1/3/4, missing or null `to`, gas over 2^24, data ≠ input, data too long.
    for kind in ["0x1", "0x3", "0x4"] {
        bad(
            Method::SendTransaction,
            &tx(&format!(r#","type":"{kind}""#)),
        );
    }
    assert!(matches!(
        ok(Method::SendTransaction, &tx(r#","type":"0x0""#))?,
        Validated::Send(_)
    ));
    bad(Method::SendTransaction, &format!(r#"[{{"from":"{A}"}}]"#));
    bad(
        Method::SendTransaction,
        &format!(r#"[{{"from":"{A}","to":null}}]"#),
    );
    bad(Method::SendTransaction, &format!(r#"[{{"to":"{B}"}}]"#));
    bad(Method::SendTransaction, &tx(r#","gas":"0x1000001""#));
    assert!(matches!(
        ok(Method::SendTransaction, &tx(r#","gas":"0x1000000""#))?,
        Validated::Send(_)
    ));
    bad(
        Method::SendTransaction,
        &tx(r#","data":"0x00","input":"0x01""#),
    );
    let oversized = format!("0x{}", "aa".repeat(131_073));
    bad(
        Method::SendTransaction,
        &tx(&format!(r#","data":"{oversized}""#)),
    );
    // Duplicate access-list addresses are rejected for transactions (spec/03 §3.2).
    let entry = format!(r#"{{"address":"{A}","storageKeys":["{H}"]}}"#);
    bad(
        Method::SendTransaction,
        &tx(&format!(r#","accessList":[{entry},{entry}]"#)),
    );
    assert!(matches!(
        ok(
            Method::SendTransaction,
            &tx(&format!(r#","accessList":[{entry}]"#))
        )?,
        Validated::Send(_)
    ));
    bad(
        Method::SendTransaction,
        &tx(&format!(r#","accessList":[{{"address":"{A}"}}]"#)),
    );
    // chainId format only here; the origin-chain comparison is the dispatcher's.
    let Validated::Send(with_chain) = ok(Method::SendTransaction, &tx(r#","chainId":"0x1""#))?
    else {
        return Err("not a send".into());
    };
    assert_eq!(with_chain.chain_id, Some(1));
    Ok(())
}

#[test]
fn r_v1_personal_sign_utf8_or_hex() -> TestResult {
    assert_eq!(
        ok(Method::PersonalSign, &format!(r#"["0x48656c6c6f","{A}"]"#))?,
        Validated::PersonalSign {
            message: b"Hello".to_vec(),
            account: yw_core::evm::address::parse_address(A).unwrap()
        }
    );
    assert_eq!(
        ok(
            Method::PersonalSign,
            &format!(r#"["Hello, Your Wallet","{A}"]"#)
        )?,
        Validated::PersonalSign {
            message: b"Hello, Your Wallet".to_vec(),
            account: yw_core::evm::address::parse_address(A).unwrap()
        }
    );
    // An odd-length "hex" is text.
    assert!(matches!(
        ok(Method::PersonalSign, &format!(r#"["0xabc","{A}"]"#))?,
        Validated::PersonalSign { message, .. } if message == b"0xabc"
    ));
    // Swapped order rejected.
    bad(Method::PersonalSign, &format!(r#"["{A}","0x48656c6c6f"]"#));
    bad(Method::PersonalSign, &format!(r#"["0x00","{A}","extra"]"#));
    let largest = format!("0x{}", "00".repeat(65_536));
    assert!(matches!(
        ok(Method::PersonalSign, &format!(r#"["{largest}","{A}"]"#))?,
        Validated::PersonalSign { .. }
    ));
    let oversized = format!("0x{}", "00".repeat(65_537));
    bad(Method::PersonalSign, &format!(r#"["{oversized}","{A}"]"#));
    Ok(())
}

#[test]
fn r_v1_typed_data_object_or_string() -> TestResult {
    let typed = r#"{"types":{"EIP712Domain":[]},"primaryType":"Mail","domain":{},"message":{}}"#;
    let quoted =
        String::from_utf8(yw_json::to_vec(&yw_json::Value::String(typed.to_owned()))).unwrap();
    let as_string = format!(r#"["{A}",{quoted}]"#);
    let Validated::TypedData { source, value, .. } = ok(Method::SignTypedDataV4, &as_string)?
    else {
        return Err("not typed data".into());
    };
    assert_eq!(source, typed.as_bytes());
    let Validated::TypedData {
        source: object_source,
        value: object_value,
        ..
    } = ok(Method::SignTypedDataV4, &format!(r#"["{A}",{typed}]"#))?
    else {
        return Err("not typed data".into());
    };
    assert_eq!(object_source, typed.as_bytes());
    assert_eq!(object_value, value);
    bad(
        Method::SignTypedDataV4,
        &format!(
            r#"["{A}",{{"types":{{}},"primaryType":"Mail","domain":{{}},"message":{{}},"extra":1}}]"#
        ),
    );
    bad(Method::SignTypedDataV4, &format!(r#"["{A}","not json"]"#));
    bad(Method::SignTypedDataV4, &format!(r#"["{A}","[]"]"#));
    bad(
        Method::SignTypedDataV4,
        &format!(
            r#"["{A}",{{"types":{{}},"primaryType":"Mail","domain":{{}},"message":{{}},"types":{{}}}}]"#
        ),
    );
    bad(Method::SignTypedDataV4, &format!(r#"[{typed},"{A}"]"#));
    Ok(())
}

#[test]
fn r_v1_fee_history() -> TestResult {
    assert_eq!(
        forwarded(Method::FeeHistory, r#"[10,"latest",[25,50.5,75]]"#)?,
        r#"["0xa","latest",[25,50.5,75]]"#
    );
    assert_eq!(
        forwarded(Method::FeeHistory, r#"["0x0A","0x10"]"#)?,
        r#"["0xa","0x10"]"#
    );
    bad(Method::FeeHistory, r#"[0,"latest"]"#);
    bad(Method::FeeHistory, r#"[1025,"latest"]"#);
    bad(Method::FeeHistory, r#"[10,{"blockNumber":"0x1"}]"#);
    bad(Method::FeeHistory, r#"[10,"latest",[50,50]]"#);
    bad(Method::FeeHistory, r#"[10,"latest",[60,50]]"#);
    bad(Method::FeeHistory, r#"[10,"latest",[101]]"#);
    bad(Method::FeeHistory, r#"[10,"latest",[-1]]"#);
    let many: Vec<String> = (0..101)
        .map(|i| format!("{}", f64::from(i) * 0.5))
        .collect();
    bad(
        Method::FeeHistory,
        &format!(r#"[10,"latest",[{}]]"#, many.join(",")),
    );
    Ok(())
}

#[test]
fn r_v1_get_logs_ranges() -> TestResult {
    const BIG_B: u64 = 20_000;
    let numbers =
        |from: u64, to: u64| format!(r#"[{{"fromBlock":"0x{from:x}","toBlock":"0x{to:x}"}}]"#);
    // Both numbers: checked now.
    assert_eq!(logs_range(&numbers(100, 10_100))?, None);
    bad(Method::GetLogs, &numbers(100, 10_101));
    bad(Method::GetLogs, &numbers(200, 100));
    // Both tags (or omitted): pass, no block-number lookup.
    assert_eq!(
        logs_range(r#"[{"fromBlock":"latest","toBlock":"safe"}]"#)?,
        None
    );
    assert_eq!(logs_range("[{}]")?, None);
    // One side tagged: checked against B by the worker.
    let one = |from: u64, tag: &str| -> TestResult<LogsRange> {
        logs_range(&format!(
            r#"[{{"fromBlock":"0x{from:x}","toBlock":"{tag}"}}]"#
        ))?
        .ok_or_else(|| "one-sided".into())
    };
    assert_eq!(
        one(BIG_B - 10_000, "latest")?,
        LogsRange {
            from: LogsBound::Number(BIG_B - 10_000),
            to: LogsBound::Tag
        }
    );
    assert_eq!(
        check_logs_range(&one(BIG_B - 10_000, "latest")?, BIG_B),
        Ok(())
    );
    assert_eq!(
        check_logs_range(&one(BIG_B - 10_001, "latest")?, BIG_B),
        Err(ProviderError::InvalidParams)
    );
    assert_eq!(
        check_logs_range(&one(0, "safe")?, BIG_B),
        Err(ProviderError::InvalidParams)
    );
    assert_eq!(check_logs_range(&one(BIG_B + 1, "latest")?, BIG_B), Ok(()));
    let only_from = logs_range(r#"[{"fromBlock":"0x4e1f"}]"#)?.expect("one-sided");
    assert_eq!(check_logs_range(&only_from, BIG_B), Ok(()));
    // earliest / pending rejected on either side; blockHash excludes the range keys.
    for tag in ["earliest", "pending"] {
        bad(Method::GetLogs, &format!(r#"[{{"fromBlock":"{tag}"}}]"#));
        bad(Method::GetLogs, &format!(r#"[{{"toBlock":"{tag}"}}]"#));
    }
    bad(
        Method::GetLogs,
        &format!(r#"[{{"blockHash":"{H}","fromBlock":"0x1"}}]"#),
    );
    assert_eq!(logs_range(&format!(r#"[{{"blockHash":"{H}"}}]"#))?, None);
    // Tags are forwarded as tags.
    assert_eq!(
        forwarded(
            Method::GetLogs,
            r#"[{"fromBlock":"0x01","toBlock":"finalized"}]"#
        )?,
        r#"[{"fromBlock":"0x1","toBlock":"finalized"}]"#
    );
    // Address and topic fan-out bounds.
    let addresses: Vec<String> = (0..33).map(|_| format!(r#""{A}""#)).collect();
    bad(
        Method::GetLogs,
        &format!(r#"[{{"address":[{}]}}]"#, addresses.join(",")),
    );
    bad(Method::GetLogs, r#"[{"address":[]}]"#);
    let topics: Vec<String> = (0..33).map(|_| format!(r#""{H}""#)).collect();
    bad(
        Method::GetLogs,
        &format!(r#"[{{"topics":[[{}]]}}]"#, topics.join(",")),
    );
    bad(
        Method::GetLogs,
        &format!(r#"[{{"topics":[null,null,null,null,"{H}"]}}]"#),
    );
    assert_eq!(
        forwarded(
            Method::GetLogs,
            &format!(r#"[{{"address":"{EIP55}","topics":[null,["{H}"]]}}]"#)
        )?,
        format!(
            r#"[{{"address":"0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed","topics":[null,["{H}"]]}}]"#
        )
    );
    Ok(())
}
