//! Send-form and settings-form rules without windows: recipient checks with address-book notes
//! and look-alikes (spec/04 §2.15), amounts, funds and `최대`, the fee quote through a fake
//! transport, the S17 input rules (ST-3) with template URLs, the user-chain delete rule
//! (UI-M4-15) and the activity bounds of `meta.json` (spec/02 §5.3).

mod common;

use common::FakeClock;
use common::evm::{NEW, S2_UNIX_MS, TestResult, USER, address, fake, send_intent, world};
use yw_app::apikeys::ApiKeys;
use yw_app::errors::ErrorCode;
use yw_app::flow::evm::form::{
    AddressNote, KnownAddress, add_history, check_funds, check_recipient, look_alike, max_native,
    parse_amount, quote, tx_recipients,
};
use yw_app::flow::evm::user_chain::{
    ChainForm, FormError, ProbeError, RpcSpec, check_delete, probe_chain, validate_chain_form,
};
use yw_app::flow::evm::{ChainCache, ChainJob};
use yw_app::meta::{ActivityEntry, Meta};
use yw_app::settings::{EvmChainDef, RpcTemplate, Settings};
use yw_core::evm::abi::{
    AbiValue, SEL_APPROVE, SEL_TRANSFER_FROM, encode_call, erc20_transfer_data,
};
use yw_core::evm::amount::U256;
use yw_core::evm::chain::{SEPOLIA_GENESIS, SimulationSupport, sepolia};
use yw_core::evm::tx::Eip1559Tx;
use yw_core::journal::evm::{EvmRecord, Role, TxState};

const BOOK: &str = "0x52908400098527886E0F7030069857D2E4169EE7";
/// Same first and last four hex digits as `BOOK`.
const LOOK_ALIKE: &str = "0x5290000000000000000000000000000000009ee7";

fn known() -> TestResult<Vec<KnownAddress>> {
    Ok(vec![
        KnownAddress {
            address: address(BOOK)?,
            name: "거래소".to_owned(),
            verified: true,
            mine: false,
            history: false,
        },
        KnownAddress {
            address: address(USER)?,
            name: "계정 1".to_owned(),
            verified: false,
            mine: true,
            history: false,
        },
    ])
}

/// A known address for the look-alike splits.
const BASE: &str = "0xabcdef0123456789abcdef0123456789abcdef01";

/// `BASE` with exactly the first `prefix` and last `suffix` hex digits kept and every other
/// digit changed.
fn poisoned(prefix: usize, suffix: usize) -> TestResult<yw_core::evm::address::Address> {
    let digits: String = BASE
        .trim_start_matches("0x")
        .chars()
        .enumerate()
        .map(|(index, digit)| {
            if index < prefix || index >= 40 - suffix {
                digit
            } else {
                let value = digit.to_digit(16).unwrap_or(0);
                char::from_digit((value + 8) % 16, 16).unwrap_or('0')
            }
        })
        .collect();
    address(&format!("0x{digits}"))
}

#[test]
fn look_alike_splits_total_six_or_more() -> TestResult {
    let base = address(BASE)?;
    for (prefix, suffix) in [
        (3, 3),
        (2, 4),
        (4, 2),
        (6, 0),
        (0, 6),
        (1, 5),
        (5, 1),
        (4, 4),
    ] {
        assert_eq!(
            look_alike(&base, &poisoned(prefix, suffix)?),
            Some((prefix, suffix)),
            "{prefix}+{suffix}"
        );
    }
    // Five matching end digits in any split are not enough.
    for (prefix, suffix) in [(3, 2), (2, 3), (5, 0), (0, 5), (1, 4), (4, 1), (0, 0)] {
        assert_eq!(
            look_alike(&base, &poisoned(prefix, suffix)?),
            None,
            "{prefix}+{suffix}"
        );
    }
    // Equal addresses are never look-alikes (checksum casing is ignored).
    assert_eq!(look_alike(&base, &base), None);
    assert_eq!(
        look_alike(
            &address(BOOK)?,
            &address("0x52908400098527886e0f7030069857d2e4169ee7")?
        ),
        None
    );
    // Through the form: a 3+3 poison of a book entry needs the checkbox and names the split.
    let book = vec![KnownAddress {
        address: base,
        name: "거래소".to_owned(),
        verified: false,
        mine: false,
        history: false,
    }];
    let sender = address(USER)?;
    let typed = poisoned(3, 3)?.to_lower_hex();
    let (_, notes) = check_recipient(&typed, &sender, None, &book).map_err(ErrorCode::code)?;
    assert_eq!(
        notes,
        vec![AddressNote::LookAlike {
            name: "거래소".to_owned(),
            history: false,
            prefix: 3,
            suffix: 3,
        }]
    );
    assert!(notes[0].needs_ack());
    assert!(
        notes[0].text().contains("앞 3자·끝 3자"),
        "{}",
        notes[0].text()
    );
    let typed = poisoned(0, 6)?.to_lower_hex();
    let (_, notes) = check_recipient(&typed, &sender, None, &book).map_err(ErrorCode::code)?;
    assert!(
        notes[0].text().starts_with("'거래소'과 끝 6자가"),
        "{}",
        notes[0].text()
    );
    let typed = poisoned(2, 3)?.to_lower_hex();
    let (_, notes) = check_recipient(&typed, &sender, None, &book).map_err(ErrorCode::code)?;
    assert_eq!(notes, vec![AddressNote::NotInBook]);
    Ok(())
}

#[test]
fn past_recipients_become_history_entries() -> TestResult {
    let token = address("0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238")?;
    let recipient = address(NEW)?;
    let tx = |to, data| Eip1559Tx {
        chain_id: 11_155_111,
        nonce: 0,
        max_priority_fee_per_gas: U256::from_u64(1),
        max_fee_per_gas: U256::from_u64(2),
        gas_limit: 21_000,
        to,
        value: U256::ZERO,
        data,
        access_list: Vec::new(),
    };
    // Native: `to`. ERC-20 `transfer` / `transferFrom`: the token and the decoded recipient.
    assert_eq!(tx_recipients(&tx(recipient, Vec::new())), vec![recipient]);
    let amount = U256::from_u64(5);
    let transfer = tx(token, erc20_transfer_data(&recipient, &amount));
    assert_eq!(tx_recipients(&transfer), vec![token, recipient]);
    let transfer_from = tx(
        token,
        encode_call(
            SEL_TRANSFER_FROM,
            &[
                AbiValue::Address(address(USER)?),
                AbiValue::Address(recipient),
                AbiValue::Uint(amount),
            ],
        ),
    );
    assert_eq!(tx_recipients(&transfer_from), vec![token, recipient]);
    // Other calldata (an approval's spender is not a recipient): only `to`.
    let approve = tx(
        token,
        encode_call(
            SEL_APPROVE,
            &[AbiValue::Address(recipient), AbiValue::Uint(amount)],
        ),
    );
    assert_eq!(tx_recipients(&approve), vec![token]);

    // History entries are deduplicated against the book, own accounts and each other.
    let mut known = known()?;
    add_history(
        &mut known,
        [
            address(BOOK)?,
            recipient,
            recipient,
            yw_core::evm::address::Address::from_bytes([0; 20]),
        ]
        .into_iter()
        .chain(tx_recipients(&transfer)),
    );
    let history: Vec<_> = known.iter().filter(|entry| entry.history).collect();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].address, recipient);
    assert_eq!(history[0].name, recipient.to_lower_hex());
    assert_eq!(history[1].address, token);
    assert!(!history[0].mine && !history[0].verified);

    // A history entry is compared for look-alikes only: an exact match is still not in the
    // book, and a poison of it is flagged with the history wording.
    let sender = address(USER)?;
    let (_, notes) = check_recipient(NEW, &sender, None, &known).map_err(ErrorCode::code)?;
    assert_eq!(notes, vec![AddressNote::NotInBook]);
    let mut digits: Vec<char> = NEW
        .trim_start_matches("0x")
        .to_ascii_lowercase()
        .chars()
        .collect();
    for digit in digits.iter_mut().skip(2).take(34) {
        *digit = if *digit == '0' { '1' } else { '0' };
    }
    let poison = format!("0x{}", digits.into_iter().collect::<String>());
    let (_, notes) = check_recipient(&poison, &sender, None, &known).map_err(ErrorCode::code)?;
    assert_eq!(
        notes,
        vec![AddressNote::LookAlike {
            name: recipient.to_lower_hex(),
            history: true,
            prefix: 2,
            suffix: 4,
        }]
    );
    assert!(notes[0].needs_ack());
    assert!(notes[0].text().contains("보낸 내역"), "{}", notes[0].text());
    Ok(())
}

/// spec/04 §2.15 rows 6–7: a poison saved to the book (an unverified entry) is still flagged
/// against the past recipient it imitates — the book note does not end the check — until the
/// user verifies that entry.
#[test]
fn a_saved_poison_is_still_flagged() -> TestResult {
    let real = address(BASE)?;
    let poison = poisoned(3, 3)?;
    let mut known = vec![KnownAddress {
        address: poison,
        name: "친구".to_owned(),
        verified: false,
        mine: false,
        history: false,
    }];
    add_history(&mut known, [real]);
    let sender = address(USER)?;
    let book = |verified| AddressNote::Book {
        name: "친구".to_owned(),
        verified,
    };
    let typed = poison.to_lower_hex();
    let (_, notes) = check_recipient(&typed, &sender, None, &known).map_err(ErrorCode::code)?;
    assert_eq!(
        notes,
        vec![
            book(false),
            AddressNote::LookAlike {
                name: real.to_lower_hex(),
                history: true,
                prefix: 3,
                suffix: 3,
            }
        ]
    );
    known[0].verified = true;
    let (_, notes) = check_recipient(&typed, &sender, None, &known).map_err(ErrorCode::code)?;
    assert_eq!(notes, vec![book(true)]);
    Ok(())
}

#[test]
fn recipient_rules_and_notes() -> TestResult {
    let sender = address(USER)?;
    let known = known()?;
    let check = |text: &str| check_recipient(text, &sender, None, &known);
    assert_eq!(check("0x1234").err(), Some(ErrorCode::Inp009));
    assert_eq!(
        check("0x52908400098527886E0F7030069857D2E4169Ee7").err(),
        Some(ErrorCode::Inp010)
    );
    assert_eq!(
        check(&format!("0x{}", "0".repeat(40))).err(),
        Some(ErrorCode::Inp014)
    );
    let token = address(BOOK)?;
    assert_eq!(
        check_recipient(BOOK, &sender, Some(&token), &known).err(),
        Some(ErrorCode::Inp015)
    );
    // Book entry (with surrounding whitespace pasted in).
    let (parsed, notes) = check(&format!("  {BOOK}\r\n")).map_err(ErrorCode::code)?;
    assert_eq!(parsed, address(BOOK)?);
    assert_eq!(
        notes,
        vec![AddressNote::Book {
            name: "거래소".to_owned(),
            verified: true
        }]
    );
    assert_eq!(notes[0].text(), "주소록: 거래소 ✓ 확인됨");
    // Own account = sender: both notes.
    let (_, notes) = check(USER).map_err(ErrorCode::code)?;
    assert_eq!(
        notes,
        vec![
            AddressNote::SameAsSender,
            AddressNote::Mine {
                label: "계정 1".to_owned()
            }
        ]
    );
    // W-ADDR-3 look-alike needs the checkbox; W-ADDR-2 otherwise.
    let (_, notes) = check(LOOK_ALIKE).map_err(ErrorCode::code)?;
    assert_eq!(
        notes,
        vec![AddressNote::LookAlike {
            name: "거래소".to_owned(),
            history: false,
            prefix: 4,
            suffix: 4,
        }]
    );
    assert!(notes[0].needs_ack() && notes[0].is_warning());
    assert!(notes[0].text().contains("주소 오염 공격"));
    let (_, notes) =
        check("0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb").map_err(ErrorCode::code)?;
    assert_eq!(notes, vec![AddressNote::NotInBook]);
    assert!(!notes[0].needs_ack());
    Ok(())
}

#[test]
fn amounts_funds_and_max() {
    assert_eq!(
        parse_amount("0.001", 18),
        Ok(U256::from_u64(1_000_000_000_000_000))
    );
    assert_eq!(parse_amount("1.5", 6), Ok(U256::from_u64(1_500_000)));
    for bad in ["0", "0.0", "", "abc", "1.0000001", "-1", "1e3"] {
        assert_eq!(parse_amount(bad, 6), Err(ErrorCode::Inp011), "{bad}");
    }
    let balance = U256::from_u64(1_000);
    let fee = U256::from_u64(300);
    assert!(check_funds(true, &U256::from_u64(700), &fee, &balance, None).is_ok());
    assert_eq!(
        check_funds(true, &U256::from_u64(701), &fee, &balance, None),
        Err(ErrorCode::Inp012)
    );
    // Token: amount against the token balance, fee against the native balance.
    let tokens = U256::from_u64(50);
    assert!(check_funds(false, &U256::from_u64(50), &fee, &balance, Some(&tokens)).is_ok());
    assert!(check_funds(false, &U256::from_u64(51), &fee, &balance, Some(&tokens)).is_err());
    assert!(
        check_funds(
            false,
            &U256::from_u64(1),
            &U256::from_u64(1_001),
            &balance,
            Some(&tokens)
        )
        .is_err()
    );
    assert!(check_funds(false, &U256::from_u64(1), &fee, &balance, None).is_err());
    // 최대: balance − max total (gas × maxFee + L1 part), nothing left → E-INP-012.
    assert_eq!(
        max_native(&U256::from_u64(1_000_000), &U256::from_u64(210_000)),
        Ok(U256::from_u64(790_000))
    );
    assert_eq!(
        max_native(&U256::from_u64(210_000), &U256::from_u64(210_000)),
        Err(ErrorCode::Inp012)
    );
}

#[test]
fn fee_quote_uses_the_gas_plan_and_caps() -> TestResult {
    let rpc = fake(world(11_155_111, SEPOLIA_GENESIS, Vec::new()));
    let clock = FakeClock::at(S2_UNIX_MS);
    let chain = sepolia();
    let mut job = ChainJob {
        caps: chain.default_caps,
        info: chain.clone(),
        url: common::url(),
    };
    let intent = send_intent()?;
    let mut cache = ChainCache::default();
    let quoted = quote(
        yw_core::lang::Lang::Ko,
        &rpc.shared(),
        &mut cache,
        &job,
        &address(USER)?,
        &intent,
        &clock,
        0,
    )
    .map_err(ErrorCode::code)?;
    assert_eq!(quoted.gas_limit, 245_520);
    assert_eq!(quoted.max_fee_per_gas, U256::from_u64(2_100_000_000));
    assert_eq!(quoted.max_total, U256::from_u64(515_592_000_000_000));
    assert_eq!(quoted.cap_violation, None);
    assert!(!quoted.estimate_failed);
    let line = quoted.line(&chain);
    assert!(line.starts_with("예상 최대 수수료: "), "{line}");
    assert!(line.contains("2.1 gwei"), "{line}");
    assert_eq!(rpc.count("eth_simulateV1"), 0, "the quote never simulates");
    // A lowered cap → E-TX-001 text that blocks `검토`.
    job.caps.max_total_fee = U256::from_u64(1);
    let quoted = quote(
        yw_core::lang::Lang::Ko,
        &rpc.shared(),
        &mut cache,
        &job,
        &address(USER)?,
        &intent,
        &clock,
        0,
    )
    .map_err(ErrorCode::code)?;
    assert!(
        quoted
            .cap_violation
            .is_some_and(|text| text.contains("E-TX-001") || text.contains("수수료"))
    );
    Ok(())
}

fn form<'a>(chain_id: &'a str, name: &'a str, rpc: &'a str) -> ChainForm<'a> {
    ChainForm {
        chain_id,
        name,
        symbol: "ETH",
        decimals: "18",
        rpc,
        explorer: "",
        simulation: SimulationSupport::Unsupported,
    }
}

fn code_of(
    result: Result<yw_app::flow::evm::user_chain::ValidChainForm, FormError>,
) -> Option<ErrorCode> {
    result.err().map(|error| error.code)
}

#[test]
#[expect(clippy::too_many_lines, reason = "one block per ST-3 input rule")]
fn st3_chain_form_rules() -> TestResult {
    let mut settings = Settings {
        rpc_template: RpcTemplate::Manual,
        ..Settings::default()
    };
    let none = ApiKeys::default();
    let url = "https://rpc.example.test/base";
    for bad in ["0", "01", "9223372036854775772", "-1", "", "0x14a34"] {
        let error = validate_chain_form(&form(bad, "Base Sepolia", url), &settings, &none, None)
            .err()
            .ok_or("accepted")?;
        assert_eq!(
            (error.code, error.item),
            (ErrorCode::Chn004, Some("chainId")),
            "{bad}"
        );
        assert!(error.message().contains("chainId"));
    }
    assert_eq!(
        code_of(validate_chain_form(
            &form("11155111", "X", url),
            &settings,
            &none,
            None
        )),
        Some(ErrorCode::Chn003)
    );
    assert_eq!(
        code_of(validate_chain_form(
            &form("999", "X", url),
            &settings,
            &none,
            None
        )),
        Some(ErrorCode::Chn003)
    );
    let ok = validate_chain_form(&form("84532", "Base Sepolia", url), &settings, &none, None)
        .map_err(|error| error.message())?;
    assert_eq!(ok.chain_id, 84_532);
    assert!(matches!(ok.rpc, RpcSpec::Url(_)));
    // Manual template + a bare label → E-KEY-003; `http://` → E-KEY-003; empty → E-KEY-003.
    for rpc in ["base-sepolia", "http://x", ""] {
        assert_eq!(
            code_of(validate_chain_form(
                &form("84532", "Base Sepolia", rpc),
                &settings,
                &none,
                None
            )),
            Some(ErrorCode::Key003),
            "{rpc}"
        );
    }
    // QuickNode template.
    settings.rpc_template = RpcTemplate::QuickNode;
    assert_eq!(
        code_of(validate_chain_form(
            &form("84532", "Base Sepolia", "Base-Sepolia"),
            &settings,
            &none,
            None
        )),
        Some(ErrorCode::Key004)
    );
    let mut keys = ApiKeys::default();
    keys.set_quicknode("dawn-test-node", "test-token-1");
    let valid = validate_chain_form(
        &form("84532", "Base Sepolia", "Base-Sepolia"),
        &settings,
        &keys,
        None,
    )
    .map_err(|error| error.message())?;
    let RpcSpec::Template {
        template,
        entry,
        url,
    } = valid.rpc
    else {
        return Err("template expected".into());
    };
    assert_eq!(
        (template, entry.as_str()),
        (RpcTemplate::QuickNode, "base-sepolia")
    );
    assert_eq!(
        url.expose(),
        "https://dawn-test-node.base-sepolia.quiknode.pro/test-token-1/"
    );
    let dotted = validate_chain_form(
        &form("84532", "Base Sepolia", "base.sepolia"),
        &settings,
        &keys,
        None,
    )
    .err()
    .ok_or("accepted")?;
    assert_eq!(dotted.code, ErrorCode::Chn004);
    assert!(dotted.message().contains("QuickNode 서브도메인"));
    // Alchemy template.
    settings.rpc_template = RpcTemplate::Alchemy;
    keys.set_alchemy("test-key-1");
    let valid = validate_chain_form(
        &form("84532", "Base Sepolia", "Base-Sepolia.g.alchemy.com"),
        &settings,
        &keys,
        None,
    )
    .map_err(|error| error.message())?;
    let RpcSpec::Template { entry, url, .. } = valid.rpc else {
        return Err("template expected".into());
    };
    assert_eq!(entry, "base-sepolia");
    assert_eq!(
        url.expose(),
        "https://base-sepolia.g.alchemy.com/v2/test-key-1"
    );
    Ok(())
}

#[test]
#[expect(clippy::too_many_lines, reason = "one block per ST-3 input rule")]
fn st3_names_symbols_decimals_explorer_and_limits() -> TestResult {
    let mut settings = Settings {
        rpc_template: RpcTemplate::Manual,
        ..Settings::default()
    };
    let none = ApiKeys::default();
    let url = "https://rpc.example.test/base";
    let base = form("84532", "Base Sepolia", url);
    // Name clash with a built-in chain differs only by case → E-CHN-005.
    let builtin = yw_core::evm::chain::sepolia().name.to_uppercase();
    assert_eq!(
        code_of(validate_chain_form(
            &ChainForm {
                name: &builtin,
                ..base
            },
            &settings,
            &none,
            None
        )),
        Some(ErrorCode::Chn005)
    );
    assert_eq!(
        code_of(validate_chain_form(
            &ChainForm {
                name: " padded",
                ..base
            },
            &settings,
            &none,
            None
        )),
        Some(ErrorCode::Inp017)
    );
    for (patch, item) in [
        (
            ChainForm {
                symbol: "e th",
                ..base
            },
            "네이티브 심볼",
        ),
        (
            ChainForm {
                decimals: "37",
                ..base
            },
            "소수 자릿수",
        ),
        (
            ChainForm {
                decimals: "+8",
                ..base
            },
            "소수 자릿수",
        ),
        (
            ChainForm {
                explorer: "http://scan.example",
                ..base
            },
            "탐색기 URL",
        ),
        (
            ChainForm {
                explorer: "https://scan.example/?q=1",
                ..base
            },
            "탐색기 URL",
        ),
    ] {
        let error = validate_chain_form(&patch, &settings, &none, None)
            .err()
            .ok_or("accepted")?;
        assert_eq!((error.code, error.item), (ErrorCode::Chn004, Some(item)));
    }
    let valid = validate_chain_form(
        &ChainForm {
            explorer: "https://sepolia.basescan.org/",
            decimals: "6",
            ..base
        },
        &settings,
        &none,
        None,
    )
    .map_err(|error| error.message())?;
    assert_eq!(
        valid.explorer.as_deref(),
        Some("https://sepolia.basescan.org")
    );
    assert_eq!(valid.decimals, 6);
    // Editing keeps the chain id and the RPC when the field is empty.
    settings.evm_chains.push(EvmChainDef {
        chain_id: 84_532,
        name: "Base Sepolia".to_owned(),
        symbol: "ETH".to_owned(),
        decimals: 18,
        quicknode_subdomain: None,
        alchemy_label: None,
        explorer: None,
        simulation: SimulationSupport::Unsupported,
        genesis_hash: [0x31; 32],
    });
    let edited = validate_chain_form(
        &ChainForm {
            chain_id: "",
            rpc: "",
            ..base
        },
        &settings,
        &none,
        Some(84_532),
    )
    .map_err(|error| error.message())?;
    assert!(matches!(edited.rpc, RpcSpec::Keep));
    assert_eq!(
        code_of(validate_chain_form(&base, &settings, &none, None)),
        Some(ErrorCode::Chn003),
        "now registered"
    );
    // 32 user chains → E-CHN-006.
    let template = settings.evm_chains[0].clone();
    settings.evm_chains = (0..32_u64)
        .map(|index| EvmChainDef {
            chain_id: 100_000 + index,
            name: format!("Chain {index}"),
            ..template.clone()
        })
        .collect();
    assert_eq!(
        code_of(validate_chain_form(
            &form("84533", "Other", url),
            &settings,
            &none,
            None
        )),
        Some(ErrorCode::Chn006)
    );
    Ok(())
}

#[test]
fn st3_mock_rpc_checks() -> TestResult {
    let genesis = [0x31; 32];
    // chainId answer 0x2105 ≠ entered 8452 → E-CHN-001 showing 8453.
    let rpc = fake(world(8_453, genesis, Vec::new()));
    let error = probe_chain(&rpc.shared(), &common::url(), 8_452, None, true)
        .err()
        .ok_or("accepted")?;
    assert_eq!(error, ProbeError::ChainId { rpc: Some(8_453) });
    assert_eq!(error.code(), ErrorCode::Chn001);
    assert!(error.message().contains("8453"));
    // Pinned hash differs while editing → E-CHN-008, nothing returned to save.
    let rpc = fake(world(8_453, genesis, Vec::new()));
    let error = probe_chain(
        &rpc.shared(),
        &common::url(),
        8_453,
        Some([0x32; 32]),
        false,
    )
    .err()
    .ok_or("accepted")?;
    assert_eq!(error.code(), ErrorCode::Chn008);
    assert_eq!(rpc.count("eth_feeHistory"), 0);
    Ok(())
}

fn record(chain_id: u64, state: TxState) -> TestResult<EvmRecord> {
    // The EVM-V13 Besu transaction (chain 4, nonce 819); only the chain id is moved.
    let mut record = EvmRecord::new_signed(
        4,
        address("0xFE3B557E8Fb62b89F4916B721be55cEb828dBd73")?,
        819,
        Role::Original,
        S2_UNIX_MS,
        [0; 32],
        "yw-app",
        "t",
        yw_core::hex::decode(
            "02f86e048203338301284d8301d97c828ae094000000000000000000000000000000000000aaaa8402933bc980c080a00f924cb68412c8f1cfd74d9b581c71eeaf94fff6abdde3e5b02ca6b2931dcf47a07dd1c50027c3e31f8b565e25ce68a5072110f61fce5eee81b195dd51273c2f83",
        )?,
    )?;
    record.chain_id = chain_id;
    record.state = state;
    Ok(record)
}

#[test]
fn user_chain_delete_rule() -> TestResult {
    assert_eq!(
        check_delete(84_532, 84_532, &[], false),
        Err(ErrorCode::Chn009)
    );
    let open = [record(84_532, TxState::Broadcast)?];
    assert_eq!(
        check_delete(84_532, 11_155_111, &open, false),
        Err(ErrorCode::Chn007)
    );
    assert_eq!(
        check_delete(84_532, 11_155_111, &[], true),
        Err(ErrorCode::Chn007)
    );
    let done = [
        record(84_532, TxState::Finalized)?,
        record(4, TxState::Signed)?,
    ];
    assert_eq!(check_delete(84_532, 11_155_111, &done, false), Ok(()));
    Ok(())
}

fn entry(index: u64) -> ActivityEntry {
    ActivityEntry {
        account: format!("0x{}", "11".repeat(20)),
        tx_id: format!("0x{index:064x}"),
        title: "[Sepolia 테스트넷] 0.001 SepoliaETH 보내기".to_owned(),
        asset: "native".to_owned(),
        amount: "1000000000000000".to_owned(),
        counterparty: format!("0x{}", "22".repeat(20)),
        status: "succeeded".to_owned(),
        time_unix_ms: 1_000 + index,
    }
}

#[test]
fn activity_upsert_replaces_orders_and_bounds() {
    let mut meta = Meta::default();
    meta.upsert_activity("eip155:11155111", &entry(1));
    meta.upsert_activity("eip155:11155111", &entry(2));
    let mut replaced = entry(1);
    replaced.status = "failed".to_owned();
    replaced.time_unix_ms = 5_000;
    meta.upsert_activity("eip155:11155111", &replaced);
    let rows = meta.activity_of("eip155:11155111");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0], replaced, "newest first, same tx_id replaced");
    // 500 per network: the oldest goes.
    for index in 3..=501 {
        meta.upsert_activity("eip155:11155111", &entry(index));
    }
    let rows = meta.activity_of("eip155:11155111");
    assert_eq!(rows.len(), 500);
    assert!(!rows.iter().any(|row| row.tx_id == entry(2).tx_id));
    // The bytes round-trip.
    let parsed = yw_app::meta::parse(&meta.to_json()).map(|parsed| parsed.meta);
    assert_eq!(parsed.ok(), Some(meta));
}
