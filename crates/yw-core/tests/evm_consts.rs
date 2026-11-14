//! Constant tables (spec/09 §3.6–§3.7, §3.11; spec/03 EVM-V04, EVM-V16 built-in constants):
//! each signature string is hashed here and compared with the code constant.

use yw_core::codec::keccak256;
use yw_core::evm::abi::*;
use yw_core::evm::address::{AddressError, parse_address};
use yw_core::evm::chain::{
    ChainSource, ContractRole, GenesisRule, MAINNET_GENESIS, OPENSEA_CONDUIT_KEY, SEPOLIA_GENESIS,
    SimulationSupport, TokenRole, arbitrum_one, base_mainnet, bsc_mainnet, builtin_chain,
    builtin_chains, ethereum_mainnet, hyperevm_mainnet, is_builtin_mainnet, robinhood_mainnet,
    sepolia,
};
use yw_core::evm::eip712::*;
use yw_core::evm::fee::L1DataFee;
use yw_core::evm::simulate::{EIP7708_SYSTEM, ERC7528_NATIVE};
use yw_core::hex;

fn selector(signature: &str) -> [u8; 4] {
    let digest = keccak256(signature.as_bytes());
    [digest[0], digest[1], digest[2], digest[3]]
}

#[test]
#[expect(clippy::too_many_lines, reason = "table-driven test")]
fn selectors_match_keccak() {
    let table: [([u8; 4], &str); 40] = [
        (SEL_TRANSFER, "transfer(address,uint256)"),
        (SEL_APPROVE, "approve(address,uint256)"),
        (SEL_TRANSFER_FROM, "transferFrom(address,address,uint256)"),
        (SEL_INCREASE_ALLOWANCE, "increaseAllowance(address,uint256)"),
        (SEL_DECREASE_ALLOWANCE, "decreaseAllowance(address,uint256)"),
        (SEL_SET_APPROVAL_FOR_ALL, "setApprovalForAll(address,bool)"),
        (
            SEL_SAFE_TRANSFER_FROM_721,
            "safeTransferFrom(address,address,uint256)",
        ),
        (
            SEL_SAFE_TRANSFER_FROM_721_DATA,
            "safeTransferFrom(address,address,uint256,bytes)",
        ),
        (
            SEL_SAFE_TRANSFER_FROM_1155,
            "safeTransferFrom(address,address,uint256,uint256,bytes)",
        ),
        (
            SEL_SAFE_BATCH_TRANSFER_FROM_1155,
            "safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)",
        ),
        (SEL_WETH_DEPOSIT, "deposit()"),
        (SEL_WETH_WITHDRAW, "withdraw(uint256)"),
        (
            SEL_PERMIT2_APPROVE,
            "approve(address,address,uint160,uint48)",
        ),
        (SEL_PERMIT2_LOCKDOWN, "lockdown((address,address)[])"),
        (
            SEL_PERMIT2_INVALIDATE_NONCES,
            "invalidateNonces(address,address,uint48)",
        ),
        (
            SEL_PERMIT2_INVALIDATE_UNORDERED_NONCES,
            "invalidateUnorderedNonces(uint256,uint256)",
        ),
        (
            SEL_PERMIT2_PERMIT_SINGLE,
            "permit(address,((address,uint160,uint48,uint48),address,uint256),bytes)",
        ),
        (
            SEL_PERMIT2_PERMIT_BATCH,
            "permit(address,((address,uint160,uint48,uint48)[],address,uint256),bytes)",
        ),
        (
            SEL_PERMIT2_TRANSFER_FROM,
            "transferFrom(address,address,uint160,address)",
        ),
        (
            SEL_PERMIT2_TRANSFER_FROM_BATCH,
            "transferFrom((address,address,uint160,address)[])",
        ),
        (
            SEL_PERMIT2_PERMIT_TRANSFER_FROM,
            "permitTransferFrom(((address,uint256),uint256,uint256),(address,uint256),address,bytes)",
        ),
        (
            SEL_PERMIT2_PERMIT_BATCH_TRANSFER_FROM,
            "permitTransferFrom(((address,uint256)[],uint256,uint256),(address,uint256)[],address,bytes)",
        ),
        (
            SEL_PERMIT2_PERMIT_WITNESS_TRANSFER_FROM,
            "permitWitnessTransferFrom(((address,uint256),uint256,uint256),(address,uint256),address,bytes32,string,bytes)",
        ),
        (SEL_PERMIT2_ALLOWANCE, "allowance(address,address,address)"),
        (SEL_MULTICALL, "multicall(bytes[])"),
        (SEL_MULTICALL_DEADLINE, "multicall(uint256,bytes[])"),
        (SEL_MULTICALL_BLOCKHASH, "multicall(bytes32,bytes[])"),
        (
            SEL_ERC2612_PERMIT,
            "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
        ),
        (
            SEL_DAI_PERMIT,
            "permit(address,address,uint256,uint256,bool,uint8,bytes32,bytes32)",
        ),
        (
            SEL_UNIVERSAL_ROUTER_EXECUTE_DEADLINE,
            "execute(bytes,bytes[],uint256)",
        ),
        (SEL_UNIVERSAL_ROUTER_EXECUTE, "execute(bytes,bytes[])"),
        (
            SEL_SEAPORT_FULFILL_BASIC_ORDER,
            "fulfillBasicOrder((address,uint256,uint256,address,address,address,uint256,uint256,uint8,uint256,uint256,bytes32,uint256,bytes32,bytes32,uint256,(uint256,address)[],bytes))",
        ),
        (
            SEL_SEAPORT_CANCEL,
            "cancel((address,address,(uint8,address,uint256,uint256,uint256)[],(uint8,address,uint256,uint256,uint256,address)[],uint8,uint256,uint256,bytes32,uint256,bytes32,uint256)[])",
        ),
        (SEL_SEAPORT_INCREMENT_COUNTER, "incrementCounter()"),
        (SEL_DECIMALS, "decimals()"),
        (SEL_SYMBOL, "symbol()"),
        (SEL_NAME, "name()"),
        (SEL_BALANCE_OF, "balanceOf(address)"),
        (SEL_ALLOWANCE, "allowance(address,address)"),
        (SEL_ERROR_STRING, "Error(string)"),
    ];
    for (constant, signature) in table {
        assert_eq!(constant, selector(signature), "{signature}");
    }
    assert_eq!(SEL_PANIC_UINT256, selector("Panic(uint256)"));
    // fulfillBasicOrder_efficient_6GL6yc: table constant only (spec/09 §3.6).
    assert_eq!(SEL_SEAPORT_FULFILL_BASIC_ORDER_EFFICIENT, [0, 0, 0, 0]);
}

#[test]
fn topics_match_keccak() {
    for (constant, signature) in [
        (TOPIC_TRANSFER, "Transfer(address,address,uint256)"),
        (TOPIC_APPROVAL, "Approval(address,address,uint256)"),
        (
            TOPIC_APPROVAL_FOR_ALL,
            "ApprovalForAll(address,address,bool)",
        ),
        (
            TOPIC_TRANSFER_SINGLE,
            "TransferSingle(address,address,address,uint256,uint256)",
        ),
        (
            TOPIC_TRANSFER_BATCH,
            "TransferBatch(address,address,address,uint256[],uint256[])",
        ),
        (TOPIC_WETH_DEPOSIT, "Deposit(address,uint256)"),
        (TOPIC_WETH_WITHDRAWAL, "Withdrawal(address,uint256)"),
        (
            TOPIC_PERMIT2_APPROVAL,
            "Approval(address,address,address,uint160,uint48)",
        ),
        (
            TOPIC_PERMIT2_PERMIT,
            "Permit(address,address,address,uint160,uint48,uint48)",
        ),
        (TOPIC_PERMIT2_LOCKDOWN, "Lockdown(address,address,address)"),
        (
            TOPIC_PERMIT2_NONCE_INVALIDATION,
            "NonceInvalidation(address,address,address,uint48,uint48)",
        ),
        (
            TOPIC_PERMIT2_UNORDERED_NONCE_INVALIDATION,
            "UnorderedNonceInvalidation(address,uint256,uint256)",
        ),
    ] {
        assert_eq!(constant, keccak256(signature.as_bytes()), "{signature}");
    }
}

const PD: &str = "PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)";
const TP: &str = "TokenPermissions(address token,uint256 amount)";

#[test]
fn type_hashes_match_keccak() {
    let seaport = "OrderComponents(address offerer,address zone,OfferItem[] offer,ConsiderationItem[] consideration,uint8 orderType,uint256 startTime,uint256 endTime,bytes32 zoneHash,uint256 salt,bytes32 conduitKey,uint256 counter)ConsiderationItem(uint8 itemType,address token,uint256 identifierOrCriteria,uint256 startAmount,uint256 endAmount,address recipient)OfferItem(uint8 itemType,address token,uint256 identifierOrCriteria,uint256 startAmount,uint256 endAmount)";
    for (constant, encoded) in [
        (
            TYPEHASH_DOMAIN_4,
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                .to_owned(),
        ),
        (
            TYPEHASH_DOMAIN_PERMIT2,
            "EIP712Domain(string name,uint256 chainId,address verifyingContract)".to_owned(),
        ),
        (
            TYPEHASH_EIP2612_PERMIT,
            "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
                .to_owned(),
        ),
        (
            TYPEHASH_DAI_PERMIT,
            "Permit(address holder,address spender,uint256 nonce,uint256 expiry,bool allowed)"
                .to_owned(),
        ),
        (TYPEHASH_PERMIT_DETAILS, PD.to_owned()),
        (
            TYPEHASH_PERMIT_SINGLE,
            format!("PermitSingle(PermitDetails details,address spender,uint256 sigDeadline){PD}"),
        ),
        (
            TYPEHASH_PERMIT_BATCH,
            format!("PermitBatch(PermitDetails[] details,address spender,uint256 sigDeadline){PD}"),
        ),
        (TYPEHASH_TOKEN_PERMISSIONS, TP.to_owned()),
        (
            TYPEHASH_PERMIT_TRANSFER_FROM,
            format!(
                "PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline){TP}"
            ),
        ),
        (
            TYPEHASH_PERMIT_BATCH_TRANSFER_FROM,
            format!(
                "PermitBatchTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline){TP}"
            ),
        ),
        (TYPEHASH_SEAPORT_ORDER, seaport.to_owned()),
    ] {
        assert_eq!(constant, keccak256(encoded.as_bytes()), "{encoded}");
    }
}

fn word_u64(value: u64) -> [u8; 32] {
    let mut out = [0_u8; 32];
    out[24..].copy_from_slice(&value.to_be_bytes());
    out
}

fn separator(
    type_hash: [u8; 32],
    name: &str,
    version: Option<&str>,
    chain_id: u64,
    contract: &str,
) -> Result<[u8; 32], AddressError> {
    let mut encoded = type_hash.to_vec();
    encoded.extend_from_slice(&keccak256(name.as_bytes()));
    if let Some(version) = version {
        encoded.extend_from_slice(&keccak256(version.as_bytes()));
    }
    encoded.extend_from_slice(&word_u64(chain_id));
    encoded.extend_from_slice(&[0; 12]);
    encoded.extend_from_slice(parse_address(contract)?.as_bytes());
    Ok(keccak256(&encoded))
}

#[test]
fn domain_separators() {
    let permit2 = "0x000000000022D473030F116dDEE9F6B43aC78BA3";
    for (computed, expected) in [
        (
            separator(TYPEHASH_DOMAIN_PERMIT2, "Permit2", None, 1, permit2).unwrap(),
            "866a5aba21966af95d6c7ab78eb2b2fc913915c28be3b9aa07cc04ff903e3f28",
        ),
        (
            separator(
                TYPEHASH_DOMAIN_PERMIT2,
                "Permit2",
                None,
                11_155_111,
                permit2,
            )
            .unwrap(),
            "94c1dec87927751697bfc9ebf6fc4ca506bed30308b518f0e9d6c5f74bbafdb8",
        ),
        (
            separator(
                TYPEHASH_DOMAIN_4,
                "Seaport",
                Some("1.6"),
                1,
                "0x0000000000000068F116a894984e2DB1123eB395",
            )
            .unwrap(),
            "fce34bc6e1752c1117e5063116d25cad2fa2bdcf15ff2d2e275eece7dc31ba64",
        ),
        (
            separator(
                TYPEHASH_DOMAIN_4,
                "Dai Stablecoin",
                Some("1"),
                1,
                "0x6B175474E89094C44Da98b954EedeAC495271d0F",
            )
            .unwrap(),
            "dbb8cf42e1ecb028be3f3dbc922e1d878b963f411dc388ced501601c60f7c6f7",
        ),
        (
            separator(
                TYPEHASH_DOMAIN_4,
                "Ether Mail",
                Some("1"),
                1,
                "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
            )
            .unwrap(),
            "f2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f",
        ),
    ] {
        assert_eq!(hex::encode(&computed), expected);
    }
}

#[test]
fn native_emitters_and_labels() {
    assert_eq!(
        ERC7528_NATIVE,
        parse_address(&format!("0x{}", "e".repeat(40))).unwrap()
    );
    assert_eq!(
        EIP7708_SYSTEM,
        parse_address("0xfffffffffffffffffffffffffffffffffffffffe").unwrap()
    );
    assert_eq!(
        hex::encode(&OPENSEA_CONDUIT_KEY),
        "0000007b02230091a7ed01230072f7006a004d60a8d4e71d599b8104250f0000"
    );
}

#[test]
fn builtin_chain_constants_spec_09_3_11() {
    let chains = builtin_chains();
    let ids: Vec<u64> = chains.iter().map(|chain| chain.chain_id).collect();
    assert_eq!(ids, [1, 11_155_111, 999, 42_161, 8_453, 56, 4_663]);
    let mainnet = ethereum_mainnet();
    assert_eq!(
        hex::encode(&MAINNET_GENESIS),
        "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
    );
    assert_eq!(mainnet.genesis, GenesisRule::Fixed(MAINNET_GENESIS));
    assert_eq!(mainnet.amsterdam_time, None);
    assert_eq!(mainnet.small_block_gas_limit, None);
    assert_eq!(mainnet.native_symbol, "ETH");
    let templates = mainnet.templates.unwrap();
    assert_eq!(templates.quicknode_subdomain, None);
    assert_eq!(templates.quicknode_path, None);
    assert_eq!(templates.alchemy_label, Some("eth-mainnet"));

    let sepolia = sepolia();
    assert_eq!(
        hex::encode(&SEPOLIA_GENESIS),
        "25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9"
    );
    assert_eq!(sepolia.genesis, GenesisRule::Fixed(SEPOLIA_GENESIS));
    assert_eq!(sepolia.amsterdam_time, Some(1_791_294_816));
    assert_eq!(sepolia.native_symbol, "SepoliaETH");
    let templates = sepolia.templates.unwrap();
    assert_eq!(templates.quicknode_subdomain, Some("ethereum-sepolia"));
    assert_eq!(templates.alchemy_label, Some("eth-sepolia"));

    let hyper = hyperevm_mainnet();
    assert_eq!(hyper.genesis, GenesisRule::PinOnFirstUse(None));
    assert_eq!(hyper.small_block_gas_limit, Some(3_000_000));
    assert_eq!(hyper.simulation, SimulationSupport::Auto);
    assert_eq!(hyper.native_symbol, "HYPE");
    let templates = hyper.templates.unwrap();
    assert_eq!(templates.quicknode_subdomain, Some("hype-mainnet"));
    assert_eq!(templates.quicknode_path, Some("nanoreth"));
    assert_eq!(templates.alchemy_label, Some("hyperliquid-mainnet"));

    for chain in &chains {
        assert_eq!(chain.source, ChainSource::BuiltIn);
        assert_eq!(chain.simulation, SimulationSupport::Auto);
        assert_eq!(chain.native_decimals, 18);
    }
    for chain in [&mainnet, &sepolia, &hyper] {
        assert_eq!(chain.tip_floor_wei, 10_000_000);
        assert_eq!(chain.l1_data_fee, L1DataFee::None);
    }
    // Default caps (spec/03 §1.1).
    let gwei = |value: u64| yw_core::evm::amount::U256::from_u64(value * 1_000_000_000);
    assert_eq!(mainnet.default_caps.max_fee_per_gas, gwei(200));
    assert_eq!(mainnet.default_caps.max_priority_fee_per_gas, gwei(5));
    assert_eq!(
        mainnet.default_caps.max_total_fee,
        yw_core::evm::amount::U256::from_u64(50_000_000_000_000_000)
    );
    assert_eq!(sepolia.default_caps.max_fee_per_gas, gwei(1_000));
    assert_eq!(sepolia.default_caps.max_priority_fee_per_gas, gwei(100));
    assert_eq!(
        sepolia.default_caps.max_total_fee,
        yw_core::evm::amount::U256::from_u64(1_000_000_000_000_000_000)
    );
    assert_eq!(hyper.default_caps.max_fee_per_gas, gwei(100));
    assert_eq!(hyper.default_caps.max_priority_fee_per_gas, gwei(10));
}

#[test]
#[expect(clippy::too_many_lines, reason = "table-driven test")]
fn registry_rows_spec_03_1_2() {
    // The spec table strings must be valid EIP-55 and equal to the code constants.
    let mainnet = ethereum_mainnet();
    let sepolia = sepolia();
    let hyper = hyperevm_mainnet();
    for (chain, address, symbol, decimals, role) in [
        (
            &mainnet,
            "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
            "WETH",
            18,
            TokenRole::Weth,
        ),
        (
            &mainnet,
            "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            "USDC",
            6,
            TokenRole::Plain,
        ),
        (
            &mainnet,
            "0xdAC17F958D2ee523a2206206994597C13D831ec7",
            "USDT",
            6,
            TokenRole::Plain,
        ),
        (
            &mainnet,
            "0x6B175474E89094C44Da98b954EedeAC495271d0F",
            "DAI",
            18,
            TokenRole::Dai,
        ),
        (
            &sepolia,
            "0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14",
            "WETH",
            18,
            TokenRole::Weth,
        ),
        (
            &sepolia,
            "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238",
            "USDC",
            6,
            TokenRole::Plain,
        ),
        (
            &hyper,
            "0x5555555555555555555555555555555555555555",
            "WHYPE",
            18,
            TokenRole::Weth,
        ),
    ] {
        let token = chain.token(&parse_address(address).unwrap()).unwrap();
        assert_eq!(
            (token.symbol, token.decimals, token.role),
            (symbol, decimals, role)
        );
    }
    for (chain, address, role) in [
        (
            &mainnet,
            "0x000000000022D473030F116dDEE9F6B43aC78BA3",
            ContractRole::Permit2,
        ),
        (
            &sepolia,
            "0x000000000022D473030F116dDEE9F6B43aC78BA3",
            ContractRole::Permit2,
        ),
        (
            &hyper,
            "0x000000000022D473030F116dDEE9F6B43aC78BA3",
            ContractRole::Permit2,
        ),
        (
            &mainnet,
            "0x0000000000000068F116a894984e2DB1123eB395",
            ContractRole::Seaport16,
        ),
        (
            &sepolia,
            "0x0000000000000068F116a894984e2DB1123eB395",
            ContractRole::Seaport16,
        ),
        (
            &mainnet,
            "0x00000000000000ADc04C56Bf30aC9d3c0aAF14dC",
            ContractRole::Seaport15,
        ),
        (
            &sepolia,
            "0x00000000000000ADc04C56Bf30aC9d3c0aAF14dC",
            ContractRole::Seaport15,
        ),
        (
            &mainnet,
            "0x00000000006c3852cbEf3e08E8dF289169EdE581",
            ContractRole::LabelOnly,
        ),
        (
            &mainnet,
            "0x00000000F9490004C11Cef243f5400493c00Ad63",
            ContractRole::LabelOnly,
        ),
        (
            &mainnet,
            "0x1E0049783F008A0085193E00003D00cd54003c71",
            ContractRole::LabelOnly,
        ),
        (
            &mainnet,
            "0x66a9893cC07D91D95644AEDD05D03f95e1dBA8Af",
            ContractRole::LabelOnly,
        ),
        (
            &mainnet,
            "0x4C82D1fBFe28C977cBB58D8C7FF8FCF9F70a2cCA",
            ContractRole::LabelOnly,
        ),
        (
            &mainnet,
            "0x23617e59A5925b2A4Bf75d73ff6711cD0b29De85",
            ContractRole::LabelOnly,
        ),
        (
            &sepolia,
            "0x3A9D48AB9751398BbFa63ad67599Bb04e4BdF98b",
            ContractRole::LabelOnly,
        ),
        (
            &sepolia,
            "0x7DfD4F31be6814D2906BDE155c3e1B146EAc1468",
            ContractRole::LabelOnly,
        ),
        (
            &sepolia,
            "0x7E4f6c5e954Da5c61B3423D81E2277431Ac043f3",
            ContractRole::LabelOnly,
        ),
    ] {
        let contract = chain.contract(&parse_address(address).unwrap()).unwrap();
        assert_eq!(contract.role, role, "{address}");
    }
    assert_eq!(mainnet.tokens.len(), 4);
    assert_eq!(mainnet.contracts.len(), 9);
    assert_eq!(sepolia.tokens.len(), 2);
    assert_eq!(sepolia.contracts.len(), 6);
    assert_eq!(hyper.tokens.len(), 1);
    assert_eq!(hyper.contracts.len(), 1);
}

#[test]
fn user_chain_validation_boundaries() {
    use yw_core::evm::chain::{
        ChainConfigError, MAX_CHAIN_ID, UserChainInput, user_chain_info, validate_user_chain,
    };
    // OP Mainnet (10) stays a user chain; Base (8453) became built-in on 2026-11-06.
    let base = UserChainInput {
        chain_id: 10,
        name: "Test L2".to_owned(),
        native_symbol: "ETH".to_owned(),
        native_decimals: 18,
        explorer: None,
        simulation: SimulationSupport::Auto,
    };
    assert_eq!(validate_user_chain(&base, &[]), Ok(()));
    for builtin in [42_161, 8_453, 56, 4_663] {
        let mut taken = base.clone();
        taken.chain_id = builtin;
        assert_eq!(
            validate_user_chain(&taken, &[]),
            Err(ChainConfigError::ChainIdRegistered)
        );
    }
    let with = |change: &dyn Fn(&mut UserChainInput)| {
        let mut input = base.clone();
        change(&mut input);
        validate_user_chain(&input, &[42])
    };
    assert_eq!(
        with(&|i| i.chain_id = 0),
        Err(ChainConfigError::ChainIdOutOfRange)
    );
    assert_eq!(with(&|i| i.chain_id = MAX_CHAIN_ID), Ok(()));
    assert_eq!(
        with(&|i| i.chain_id = MAX_CHAIN_ID + 1),
        Err(ChainConfigError::ChainIdOutOfRange)
    );
    for registered in [1, 11_155_111, 999, 42] {
        assert_eq!(
            with(&|i| i.chain_id = registered),
            Err(ChainConfigError::ChainIdRegistered)
        );
    }
    assert_eq!(with(&|i| i.name = "a".repeat(32)), Ok(()));
    assert_eq!(
        with(&|i| i.name = "a".repeat(33)),
        Err(ChainConfigError::NameInvalid)
    );
    assert_eq!(with(&|i| i.name = "가".repeat(32)), Ok(()));
    assert_eq!(
        with(&|i| i.name = String::new()),
        Err(ChainConfigError::NameInvalid)
    );
    assert_eq!(
        with(&|i| i.name = " L2".to_owned()),
        Err(ChainConfigError::NameInvalid)
    );
    assert_eq!(
        with(&|i| i.name = "L\n2".to_owned()),
        Err(ChainConfigError::NameInvalid)
    );
    assert_eq!(
        with(&|i| i.name = "sepolia 테스트넷".to_owned()),
        Err(ChainConfigError::NameReserved)
    );
    assert_eq!(with(&|i| i.native_symbol = "A".repeat(16)), Ok(()));
    assert_eq!(
        with(&|i| i.native_symbol = "A".repeat(17)),
        Err(ChainConfigError::SymbolInvalid)
    );
    assert_eq!(
        with(&|i| i.native_symbol = "E H".to_owned()),
        Err(ChainConfigError::SymbolInvalid)
    );
    assert_eq!(with(&|i| i.native_decimals = 36), Ok(()));
    assert_eq!(
        with(&|i| i.native_decimals = 37),
        Err(ChainConfigError::DecimalsInvalid)
    );
    let info = user_chain_info(&base, [9; 32]);
    assert_eq!(info.source, ChainSource::User);
    assert_eq!(info.templates, None);
    assert!(info.tokens.is_empty() && info.contracts.is_empty());
    assert_eq!(info.genesis, GenesisRule::PinOnFirstUse(Some([9; 32])));
    assert_eq!(
        info.default_caps.max_total_fee,
        yw_core::evm::amount::U256::from_u64(50_000_000_000_000_000)
    );
}

/// The L2/L1 built-ins added 2026-11-06 (spec/03 §1.1 table, sources in §1.1a): chain ids,
/// fixed genesis hashes, URL templates, explorers, fee model, caps and registry rows.
#[test]
#[expect(clippy::too_many_lines, reason = "table-driven test")]
fn added_builtin_chains_spec_03_1_1() {
    struct Row {
        chain: yw_core::evm::chain::ChainInfo,
        id: u64,
        genesis: &'static str,
        quicknode: &'static str,
        alchemy: &'static str,
        name: &'static str,
        symbol: &'static str,
        explorer: &'static str,
        l1: L1DataFee,
        floor: u64,
    }
    let gwei = |value: u64| yw_core::evm::amount::U256::from_u64(value * 1_000_000_000);
    let percent2 = yw_core::evm::amount::U256::from_u64(20_000_000_000_000_000);
    let rows = [
        Row {
            chain: arbitrum_one(),
            id: 42_161,
            genesis: "7ee576b35482195fc49205cec9af72ce14f003b9ae69f6ba0faef4514be8b442",
            quicknode: "arbitrum-mainnet",
            alchemy: "arb-mainnet",
            name: "Arbitrum One",
            symbol: "ETH",
            explorer: "https://arbiscan.io",
            l1: L1DataFee::None,
            floor: 10_000_000,
        },
        Row {
            chain: base_mainnet(),
            id: 8_453,
            genesis: "f712aa9241cc24369b143cf6dce85f0902a9731e70d66818a3a5845b296c73dd",
            quicknode: "base-mainnet",
            alchemy: "base-mainnet",
            name: "Base",
            symbol: "ETH",
            explorer: "https://basescan.org",
            l1: L1DataFee::OpStack,
            floor: 1_000_000,
        },
        Row {
            chain: bsc_mainnet(),
            id: 56,
            genesis: "0d21840abff46b96c84b2ac9e10e4f5cdaeb5693cb665db62a2f3b02d2d57b5b",
            quicknode: "bsc",
            alchemy: "bnb-mainnet",
            name: "BNB Smart Chain",
            symbol: "BNB",
            explorer: "https://bscscan.com",
            l1: L1DataFee::None,
            floor: 50_000_000,
        },
        Row {
            chain: robinhood_mainnet(),
            id: 4_663,
            genesis: "aad15f3d702aaea00caf3e9bb56395efe9127bc3b31b24921abf1eee3409305c",
            quicknode: "robinhood-mainnet",
            alchemy: "robinhood-mainnet",
            name: "Robinhood Chain",
            symbol: "ETH",
            explorer: "https://robinhoodchain.blockscout.com",
            l1: L1DataFee::None,
            floor: 10_000_000,
        },
    ];
    for row in rows {
        let chain = row.chain;
        assert_eq!(chain.chain_id, row.id);
        assert!(is_builtin_mainnet(row.id));
        assert_eq!(builtin_chain(row.id).map(|c| c.chain_id), Some(row.id));
        assert_eq!(
            chain.genesis_hash().map(|hash| hex::encode(&hash)),
            Some(row.genesis.to_owned())
        );
        assert!(matches!(chain.genesis, GenesisRule::Fixed(_)));
        let templates = chain.templates.unwrap();
        assert_eq!(templates.quicknode_subdomain, Some(row.quicknode));
        assert_eq!(templates.quicknode_path, None);
        assert_eq!(templates.alchemy_label, Some(row.alchemy));
        assert_eq!(chain.name, row.name);
        assert_eq!(chain.native_symbol, row.symbol);
        assert_eq!(chain.native_decimals, 18);
        assert_eq!(chain.explorer.as_deref(), Some(row.explorer));
        assert_eq!(chain.simulation, SimulationSupport::Auto);
        assert_eq!(chain.l1_data_fee, row.l1);
        assert_eq!(chain.tip_floor_wei, row.floor);
        assert_eq!(chain.amsterdam_time, None);
        assert_eq!(chain.small_block_gas_limit, None);
        assert_eq!(chain.default_caps.max_fee_per_gas, gwei(10));
        assert_eq!(chain.default_caps.max_total_fee, percent2);
        assert!(chain.contracts.is_empty());
    }
    assert_eq!(
        bsc_mainnet().default_caps.max_priority_fee_per_gas,
        gwei(10)
    );
    assert_eq!(
        base_mainnet().default_caps.max_priority_fee_per_gas,
        gwei(1)
    );
    assert!(!is_builtin_mainnet(11_155_111));

    // Registry rows (spec/03 §1.2): EIP-55 strings exactly as the issuer docs print them.
    for (chain, address, symbol, decimals, role, label) in [
        (
            arbitrum_one(),
            "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1",
            "WETH",
            18,
            TokenRole::Weth,
            "WETH",
        ),
        (
            arbitrum_one(),
            "0xaf88d065e77c8cC2239327C5EDb3A432268e5831",
            "USDC",
            6,
            TokenRole::Plain,
            "USDC",
        ),
        (
            arbitrum_one(),
            "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9",
            "USDT0",
            6,
            TokenRole::Plain,
            "USDT0 (Tether OFT)",
        ),
        (
            base_mainnet(),
            "0x4200000000000000000000000000000000000006",
            "WETH",
            18,
            TokenRole::Weth,
            "WETH",
        ),
        (
            base_mainnet(),
            "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
            "USDC",
            6,
            TokenRole::Plain,
            "USDC",
        ),
        (
            bsc_mainnet(),
            "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c",
            "WBNB",
            18,
            TokenRole::Weth,
            "WBNB",
        ),
        (
            bsc_mainnet(),
            "0x55d398326f99059fF775485246999027B3197955",
            "USDT",
            18,
            TokenRole::Plain,
            "USDT (Binance-Peg)",
        ),
        (
            bsc_mainnet(),
            "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d",
            "USDC",
            18,
            TokenRole::Plain,
            "USDC (Binance-Peg)",
        ),
        (
            robinhood_mainnet(),
            "0x0Bd7D308f8E1639FAb988df18A8011f41EAcAD73",
            "WETH",
            18,
            TokenRole::Weth,
            "WETH",
        ),
        (
            robinhood_mainnet(),
            "0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168",
            "USDG",
            6,
            TokenRole::Plain,
            "USDG (Global Dollar, Paxos)",
        ),
    ] {
        let parsed = parse_address(address).unwrap();
        let token = chain.token(&parsed).unwrap();
        assert_eq!(
            (token.symbol, token.decimals, token.role),
            (symbol, decimals, role)
        );
        assert_eq!(
            chain.label_in(&parsed, yw_core::lang::Lang::Ko),
            Some(label)
        );
    }
    assert_eq!(arbitrum_one().tokens.len(), 3);
    assert_eq!(base_mainnet().tokens.len(), 2);
    assert_eq!(bsc_mainnet().tokens.len(), 3);
    assert_eq!(robinhood_mainnet().tokens.len(), 2);
}

/// spec/14 (2026-11-14): the EVM error and connect texts exist in English without Hangul, keep
/// their placeholders and pass the display-text rule; Korean `Display` is unchanged.
#[test]
fn english_evm_error_texts() {
    use yw_core::approval::{MAX_DISPLAY_VALUE_BYTES, is_valid_display_text};
    use yw_core::evm::amount::AmountError;
    use yw_core::evm::chain::ChainConfigError;
    use yw_core::evm::sign::SignError;
    use yw_core::journal::evm::RecordError;
    use yw_core::lang::{Entry, Lang, has_hangul, placeholders};
    use yw_core::policy::BtcPurpose;

    let catalogues: [&[Entry]; 6] = [
        yw_core::evm::address::text::ALL,
        yw_core::evm::amount::text::ALL,
        yw_core::evm::chain::config_text::ALL,
        yw_core::evm::sign::text::ALL,
        yw_core::journal::evm::text::ALL,
        yw_core::policy::chain_grant_text::ALL,
    ];
    for entry in catalogues.into_iter().flatten() {
        for template in [entry.ko, entry.en] {
            let mut used = placeholders(template);
            used.sort_unstable();
            used.dedup();
            assert_eq!(used, (0..entry.args).collect::<Vec<_>>(), "{}", entry.name);
            assert!(
                is_valid_display_text(template, MAX_DISPLAY_VALUE_BYTES, true),
                "{}",
                entry.name
            );
        }
        assert!(!has_hangul(entry.en), "{}", entry.name);
    }
    let english = [
        AddressError::InvalidFormat.text_in(Lang::En).to_owned(),
        AddressError::BadChecksum.text_in(Lang::En).to_owned(),
        AmountError::Format.text_in(Lang::En).to_owned(),
        AmountError::TooManyDecimals.text_in(Lang::En).to_owned(),
        AmountError::Overflow.text_in(Lang::En).to_owned(),
        ChainConfigError::ChainIdOutOfRange
            .text_in(Lang::En)
            .to_owned(),
        ChainConfigError::NameReserved.text_in(Lang::En).to_owned(),
        SignError::KindMismatch.text_in(Lang::En),
        SignError::PostSignVerification.text_in(Lang::En),
        RecordError::Hash.text_in(Lang::En).to_owned(),
        BtcPurpose::Payment.label_in(Lang::En).to_owned(),
        BtcPurpose::Ordinals.label_in(Lang::En).to_owned(),
        BtcPurpose::Any.label_in(Lang::En).to_owned(),
    ];
    for text in &english {
        assert!(!has_hangul(text) && !text.is_empty(), "{text}");
    }
    assert_eq!(
        AddressError::BadChecksum.to_string(),
        AddressError::BadChecksum.text_in(Lang::Ko)
    );
    assert_eq!(
        ChainConfigError::DecimalsInvalid.to_string(),
        "소수 자릿수는 0–36이어야 합니다."
    );
    assert_eq!(
        SignError::RecoveryId.to_string(),
        "내부 오류가 발생했습니다. 로그를 확인하세요."
    );
    assert_eq!(RecordError::Signer.to_string(), "저널 손상");
}
