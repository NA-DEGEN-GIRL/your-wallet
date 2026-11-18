//! V14 approval goldens (spec/09 §3.13, spec/03 EVM-V14): one golden per `SimulationBinding` tag
//! and display language (spec/14 §3), each pinned as display bytes (`YWDSP004…`), display digest
//! and approval digest. 2026-11-14: the layout gained the language byte; the Korean bytes are
//! the earlier `YWDSP003` goldens (kept as `*_V3`) with the new magic and that byte, which
//! `korean_bytes_are_v3_with_the_language_byte` proves.
//!
//! Recording procedure (same as vault G1): `print_v14_goldens` (`--ignored --exact`) prints the
//! values; they were pinned in the commit where the independent checks below — which re-read the
//! display bytes with the spec/03 §11.3 layout and rebuild the §6.5/§11.3/§11.4 transcripts
//! without the approval module — passed. A change means the display or digest format changed.

use yw_core::approval::{
    ApprovalDraft, ApprovalId, ApprovalKind, ApprovalOrigin, ApprovalRequest, ApprovalStore,
    ChainFacts, build_evm_tx_request, build_personal_request,
};
use yw_core::bip32::path::AccountIndex;
use yw_core::codec::sha256;
use yw_core::evm::address::{Address, parse_address};
use yw_core::evm::amount::U256;
use yw_core::evm::chain::{SEPOLIA_GENESIS, sepolia};
use yw_core::evm::decode::{DecodedTx, decode_call};
use yw_core::evm::eip191::decode_personal_message;
use yw_core::evm::simulate::{SimOutcome, interpret};
use yw_core::evm::tx::Eip1559Tx;
use yw_core::hex;
use yw_core::lang::{Lang, has_hangul};
use yw_core::policy::BrowserOrigin;
use yw_core::vault::EvmKeySource;
use yw_engine::rpc::evm::parse_simulate_response;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const ID: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
const CREATED_UNIX_MS: u64 = 1_791_381_216_000;
const EXPIRES_UNIX_MS: u64 = 1_791_381_336_000;
const ACC1: &str = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";

const TAG1_DISPLAY_V3: &str = "5957445350303033000100000000003c5b5365706f6c696120ed858cec8aa4ed8ab8eb84b75d205365706f6c696145544820ebb3b4eb82b4eab8b03a20302e3031205365706f6c6961455448000e000101000000000000000f596f75722057616c6c657420ec95b100020100000000000000275365706f6c696120ed858cec8aa4ed8ab8eb84b72028636861696e49642031313135353131312900030100000000000000333078393835382045664644203233324220343033332045343764203930303020334434312045433334204563614520646139340101010000000000000033307846323738206346353920463832652044636638203731643620333046322038456343203830353620663235432031636462010201000000000000000f302e3031205365706f6c696145544801030100000000000000145365706f6c696145544820ebb3b4eb82b4eab8b0011001000000000000000f302e3031205365706f6c69614554480120010000000000000015302e3030303439313034205365706f6c69614554480121020000000000000015302e3030303232353036205365706f6c6961455448012200000000000000001d6d61784665652032206777656920c2b72074697020302e31206777656901230000000000000000073234352c353230012400000000000000000130013002000000000000002cebb894eba19d2031302c3039322c35343420c2b720323032362d31302d30372031333a35333a3336205554430141000000000000000013ec9786ec9d8c202830ebb094ec9db4ed8ab8290001451c000000002aeca3bcec868ceba19dec979020ec9786eb8a9420ebb09beb8a9420eca3bcec868cec9e85eb8b88eb8ba4";
const TAG1_DISPLAY_DIGEST: &str =
    "af90d1784b1499ea3370eec95fda4638b40f4a01ca4b4f33771d7ac7131e1e31";
const TAG1_APPROVAL_DIGEST: &str =
    "a7c571ce56297212670c3274d94cccb5a182a04167035297bd9462d012163819";
const TAG2_DISPLAY_V3: &str = "5957445350303033000102010000003c5b5365706f6c696120ed858cec8aa4ed8ab8eb84b75d205365706f6c696145544820ebb3b4eb82b4eab8b03a20302e3031205365706f6c6961455448000d000101000000000000000f596f75722057616c6c657420ec95b100020100000000000000275365706f6c696120ed858cec8aa4ed8ab8eb84b72028636861696e49642031313135353131312900030100000000000000333078393835382045664644203233324220343033332045343764203930303020334434312045433334204563614520646139340101010000000000000033307846323738206346353920463832652044636638203731643620333046322038456343203830353620663235432031636462010201000000000000000f302e3031205365706f6c696145544801030100000000000000145365706f6c696145544820ebb3b4eb82b4eab8b00120010000000000000015302e3030303439313034205365706f6c6961455448012102000000000000000eec958c20ec889820ec9786ec9d8c012200000000000000001d6d61784665652032206777656920c2b72074697020302e31206777656901230000000000000000073234352c353230012400000000000000000130013002000000000000005dec8b9cebaeaceba088ec9db4ec859820ec9786ec9d8c3a20ec9e94ec95a1ec9db420ebb3b4eb82bc20eab888ec95a1eab3bc20ecb59ceb8c8020ec8898ec8898eba38cec9d9820ed95a9ebb3b4eb8ba420eca081ec8ab5eb8b88eb8ba40141000000000000000013ec9786ec9d8c202830ebb094ec9db4ed8ab829000245010200000093ec8b9cebaeaceba088ec9db4ec859820eab2b0eab3bc20ec9786ec9d8c20e2809420ec8ba4eca09c20ed9aa8eab3bceba5bc20ed9995ec9db8ed95a020ec889820ec9786ec8ab5eb8b88eb8ba40aec9e94ec95a1ec9db420ebb3b4eb82bc20eab888ec95a1eab3bc20ecb59ceb8c8020ec8898ec8898eba38cec9d9820ed95a9ebb3b4eb8ba420eca081ec8ab5eb8b88eb8ba4451c000000002aeca3bcec868ceba19dec979020ec9786eb8a9420ebb09beb8a9420eca3bcec868cec9e85eb8b88eb8ba4";
const TAG2_DISPLAY_DIGEST: &str =
    "d889e0bd76c8c947df73c4a23727134e817c7cc98372e3efda093b4e33aedb60";
const TAG2_APPROVAL_DIGEST: &str =
    "b038e224c300ac115fca2bcc2fdc2ade3fb212c5b2e9fc48d5d9a3f30b916249";
const TAG0_DISPLAY_V3: &str = "595744535030303300010000000000275b5365706f6c696120ed858cec8aa4ed8ab8eb84b75d20eba994ec8b9ceca78020ec849cebaa850005000101000000000000001368747470733a2f2f6170702e6578616d706c6500020100000000000000275365706f6c696120ed858cec8aa4ed8ab8eb84b72028636861696e49642031313135353131312900030100000000000000333078393835382045664644203233324220343033332045343764203930303020334434312045433334204563614520646139340401010000000000000009536f6d652064617461040300000000000000000a39ebb094ec9db4ed8ab8000150030000000017eba994ec8b9ceca78020ec849cebaa8520ec9a94ecb2ad";
const TAG0_DISPLAY_DIGEST: &str =
    "614f55bf24272cc10a0c86226184e1e68213f4ac9d680536ae8f10fe379516d1";
const TAG0_APPROVAL_DIGEST: &str =
    "2696db3c0a11d3b4f2e4e3eb1293b72c7d8a8ddfa2b1b8d575977f012a043880";

const TAG1_DISPLAY: &str = "595744535030303400010100000000003c5b5365706f6c696120ed858cec8aa4ed8ab8eb84b75d205365706f6c696145544820ebb3b4eb82b4eab8b03a20302e3031205365706f6c6961455448000e000101000000000000000f596f75722057616c6c657420ec95b100020100000000000000275365706f6c696120ed858cec8aa4ed8ab8eb84b72028636861696e49642031313135353131312900030100000000000000333078393835382045664644203233324220343033332045343764203930303020334434312045433334204563614520646139340101010000000000000033307846323738206346353920463832652044636638203731643620333046322038456343203830353620663235432031636462010201000000000000000f302e3031205365706f6c696145544801030100000000000000145365706f6c696145544820ebb3b4eb82b4eab8b0011001000000000000000f302e3031205365706f6c69614554480120010000000000000015302e3030303439313034205365706f6c69614554480121020000000000000015302e3030303232353036205365706f6c6961455448012200000000000000001d6d61784665652032206777656920c2b72074697020302e31206777656901230000000000000000073234352c353230012400000000000000000130013002000000000000002cebb894eba19d2031302c3039322c35343420c2b720323032362d31302d30372031333a35333a3336205554430141000000000000000013ec9786ec9d8c202830ebb094ec9db4ed8ab8290001451c000000002aeca3bcec868ceba19dec979020ec9786eb8a9420ebb09beb8a9420eca3bcec868cec9e85eb8b88eb8ba4";
const TAG2_DISPLAY: &str = "595744535030303400010102010000003c5b5365706f6c696120ed858cec8aa4ed8ab8eb84b75d205365706f6c696145544820ebb3b4eb82b4eab8b03a20302e3031205365706f6c6961455448000d000101000000000000000f596f75722057616c6c657420ec95b100020100000000000000275365706f6c696120ed858cec8aa4ed8ab8eb84b72028636861696e49642031313135353131312900030100000000000000333078393835382045664644203233324220343033332045343764203930303020334434312045433334204563614520646139340101010000000000000033307846323738206346353920463832652044636638203731643620333046322038456343203830353620663235432031636462010201000000000000000f302e3031205365706f6c696145544801030100000000000000145365706f6c696145544820ebb3b4eb82b4eab8b00120010000000000000015302e3030303439313034205365706f6c6961455448012102000000000000000eec958c20ec889820ec9786ec9d8c012200000000000000001d6d61784665652032206777656920c2b72074697020302e31206777656901230000000000000000073234352c353230012400000000000000000130013002000000000000005dec8b9cebaeaceba088ec9db4ec859820ec9786ec9d8c3a20ec9e94ec95a1ec9db420ebb3b4eb82bc20eab888ec95a1eab3bc20ecb59ceb8c8020ec8898ec8898eba38cec9d9820ed95a9ebb3b4eb8ba420eca081ec8ab5eb8b88eb8ba40141000000000000000013ec9786ec9d8c202830ebb094ec9db4ed8ab829000245010200000093ec8b9cebaeaceba088ec9db4ec859820eab2b0eab3bc20ec9786ec9d8c20e2809420ec8ba4eca09c20ed9aa8eab3bceba5bc20ed9995ec9db8ed95a020ec889820ec9786ec8ab5eb8b88eb8ba40aec9e94ec95a1ec9db420ebb3b4eb82bc20eab888ec95a1eab3bc20ecb59ceb8c8020ec8898ec8898eba38cec9d9820ed95a9ebb3b4eb8ba420eca081ec8ab5eb8b88eb8ba4451c000000002aeca3bcec868ceba19dec979020ec9786eb8a9420ebb09beb8a9420eca3bcec868cec9e85eb8b88eb8ba4";
const TAG0_DISPLAY: &str = "59574453503030340001010000000000275b5365706f6c696120ed858cec8aa4ed8ab8eb84b75d20eba994ec8b9ceca78020ec849cebaa850005000101000000000000001368747470733a2f2f6170702e6578616d706c6500020100000000000000275365706f6c696120ed858cec8aa4ed8ab8eb84b72028636861696e49642031313135353131312900030100000000000000333078393835382045664644203233324220343033332045343764203930303020334434312045433334204563614520646139340401010000000000000009536f6d652064617461040300000000000000000a39ebb094ec9db4ed8ab8000150030000000017eba994ec8b9ceca78020ec849cebaa8520ec9a94ecb2ad";
const EN_TAG1_DISPLAY: &str = "59574453503030340001020000000000325b5365706f6c696120546573746e65745d2053656e64205365706f6c69614554483a20302e3031205365706f6c6961455448000e000101000000000000000f596f75722057616c6c65742061707000020100000000000000225365706f6c696120546573746e65742028636861696e49642031313135353131312900030100000000000000333078393835382045664644203233324220343033332045343764203930303020334434312045433334204563614520646139340101010000000000000033307846323738206346353920463832652044636638203731643620333046322038456343203830353620663235432031636462010201000000000000000f302e3031205365706f6c6961455448010301000000000000000f53656e64205365706f6c6961455448011001000000000000000f302e3031205365706f6c69614554480120010000000000000015302e3030303439313034205365706f6c69614554480121020000000000000015302e3030303232353036205365706f6c6961455448012200000000000000001d6d61784665652032206777656920c2b72074697020302e31206777656901230000000000000000073234352c353230012400000000000000000130013002000000000000002b426c6f636b2031302c3039322c35343420c2b720323032362d31302d30372031333a35333a333620555443014100000000000000000e6e6f6e65202830206279746573290001451c000000002954686520726563697069656e74206973206e6f7420696e20796f7572206164647265737320626f6f6b";
const EN_TAG1_DISPLAY_DIGEST: &str =
    "a22280d5c4b029edd70b78785a56e66d6c83b91b957c684be97e6a616a86b08f";
const EN_TAG1_APPROVAL_DIGEST: &str =
    "fdfd17fd0f53c81e8ce6bff06bab5cb8dffc80956c04a1aae57db5fc7e6c8bbc";
const EN_TAG2_DISPLAY: &str = "59574453503030340001020201000000325b5365706f6c696120546573746e65745d2053656e64205365706f6c69614554483a20302e3031205365706f6c6961455448000d000101000000000000000f596f75722057616c6c65742061707000020100000000000000225365706f6c696120546573746e65742028636861696e49642031313135353131312900030100000000000000333078393835382045664644203233324220343033332045343764203930303020334434312045433334204563614520646139340101010000000000000033307846323738206346353920463832652044636638203731643620333046322038456343203830353620663235432031636462010201000000000000000f302e3031205365706f6c6961455448010301000000000000000f53656e64205365706f6c69614554480120010000000000000015302e3030303439313034205365706f6c69614554480121020000000000000007756e6b6e6f776e012200000000000000001d6d61784665652032206777656920c2b72074697020302e31206777656901230000000000000000073234352c35323001240000000000000000013001300200000000000000434e6f2073696d756c6174696f6e3a205468652062616c616e6365206973206c657373207468616e2074686520616d6f756e7420706c757320746865206d617820666565014100000000000000000e6e6f6e652028302062797465732900024501020000006f4e6f2073696d756c6174696f6e20726573756c7420e2809420746865207265616c206566666563742063616e6e6f7420626520636865636b65640a5468652062616c616e6365206973206c657373207468616e2074686520616d6f756e7420706c757320746865206d617820666565451c000000002954686520726563697069656e74206973206e6f7420696e20796f7572206164647265737320626f6f6b";
const EN_TAG2_DISPLAY_DIGEST: &str =
    "c4536796cb963c7843d6dd3c0e4994cb431bebc5f38dee78d653f5f6ca6cdee4";
const EN_TAG2_APPROVAL_DIGEST: &str =
    "17b6437d17c1bc183c1bb10c8e3bf64b36a872da5959eec34f3b70b2ed972d91";
const EN_TAG0_DISPLAY: &str = "59574453503030340001020000000000235b5365706f6c696120546573746e65745d204d657373616765207369676e61747572650005000101000000000000001368747470733a2f2f6170702e6578616d706c6500020100000000000000225365706f6c696120546573746e65742028636861696e49642031313135353131312900030100000000000000333078393835382045664644203233324220343033332045343764203930303020334434312045433334204563614520646139340401010000000000000009536f6d6520646174610403000000000000000007392062797465730001500300000000194d657373616765207369676e61747572652072657175657374";
const EN_TAG0_DISPLAY_DIGEST: &str =
    "61fc050a23008cd74231bb907329f2255349b20c86d0b61fcd1fb015c592f1e3";
const EN_TAG0_APPROVAL_DIGEST: &str =
    "ee7333e056920e9b586d58f0d43c7fdd73c649b2cea9213e2c6d965d4aa00e5d";

fn s2_tx() -> TestResult<Eip1559Tx> {
    Ok(Eip1559Tx {
        chain_id: 11_155_111,
        nonce: 0,
        max_priority_fee_per_gas: U256::from_u64(0x05f5_e100),
        max_fee_per_gas: U256::from_u64(0x7735_9400),
        gas_limit: 0x3bf10,
        to: parse_address("0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb")?,
        value: U256::from_u64(0x0023_86f2_6fc1_0000),
        data: Vec::new(),
        access_list: Vec::new(),
    })
}

fn tx_draft(lang: Lang, outcome: &SimOutcome) -> TestResult<ApprovalDraft> {
    let chain = sepolia();
    let tx = s2_tx()?;
    let user = parse_address(ACC1)?;
    let sim = interpret(lang, &chain, &tx, &user, outcome, CREATED_UNIX_MS);
    let decoded = DecodedTx {
        call: decode_call(&chain, &tx.to, &tx.data),
        tx,
    };
    Ok(build_evm_tx_request(
        lang,
        ApprovalId(ID),
        ApprovalOrigin::App,
        EvmKeySource::Derived(AccountIndex::ZERO),
        user,
        ApprovalKind::EvmTransaction,
        &chain,
        &decoded,
        &sim,
        &ChainFacts::default(),
        Vec::new(),
        CREATED_UNIX_MS,
    )?)
}

fn tag1(lang: Lang) -> TestResult<ApprovalDraft> {
    tx_draft(
        lang,
        &parse_simulate_response(
            include_bytes!("fixtures/eth_simulateV1/S2.response.json"),
            1,
        ),
    )
}

fn tag2(lang: Lang) -> TestResult<ApprovalDraft> {
    tx_draft(
        lang,
        &parse_simulate_response(
            include_bytes!("fixtures/eth_simulateV1/S4.response.json"),
            1,
        ),
    )
}

fn tag0(lang: Lang) -> TestResult<ApprovalDraft> {
    let origin = BrowserOrigin::parse("https://app.example").ok_or("origin")?;
    Ok(build_personal_request(
        lang,
        ApprovalId(ID),
        ApprovalOrigin::Site(origin),
        EvmKeySource::Derived(AccountIndex::ZERO),
        parse_address(ACC1)?,
        ApprovalKind::EvmPersonalSign,
        &sepolia(),
        &decode_personal_message(b"Some data".to_vec()),
        CREATED_UNIX_MS,
    )?)
}

fn issue(draft: ApprovalDraft) -> TestResult<ApprovalRequest> {
    let mut store = ApprovalStore::new();
    Ok(store.issue(draft, 5_000, CREATED_UNIX_MS)?)
}

// ------------------------------------------------------------ independent re-reading

struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> TestResult<&'a [u8]> {
        if self.bytes.len() < count {
            return Err("truncated".into());
        }
        let (head, rest) = self.bytes.split_at(count);
        self.bytes = rest;
        Ok(head)
    }

    fn u8(&mut self) -> TestResult<u8> {
        Ok(*self.take(1)?.first().ok_or("u8")?)
    }

    fn u16(&mut self) -> TestResult<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into()?))
    }

    fn u32(&mut self) -> TestResult<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into()?))
    }

    fn text(&mut self) -> TestResult<String> {
        let length = usize::try_from(self.u32()?)?;
        Ok(String::from_utf8(self.take(length)?.to_vec())?)
    }
}

/// Re-reads display bytes with the spec/03 §11.3 layout and compares with the model.
fn check_display_bytes(request: &ApprovalRequest, bytes: &[u8]) -> TestResult {
    let display = &request.display;
    let mut reader = Reader { bytes };
    assert_eq!(reader.take(8)?, b"YWDSP004");
    assert_eq!(reader.u16()?, 1);
    assert_eq!(reader.u8()?, display.lang as u8);
    assert_eq!(reader.u8()?, display.risk as u8);
    assert_eq!(reader.u8()?, u8::from(display.ack_required));
    assert_eq!(reader.text()?, display.title);
    let fields = usize::from(reader.u16()?);
    assert_eq!(fields, display.fields.len());
    for field in &display.fields {
        assert_eq!(reader.u16()?, field.key.0);
        assert_eq!(
            reader.u8()?,
            u8::from(field.critical) | (u8::from(field.volatile) << 1)
        );
        assert_eq!(reader.text()?, field.sub_label);
        assert_eq!(reader.text()?, field.value);
    }
    let warnings = usize::from(reader.u16()?);
    assert_eq!(warnings, display.warnings.len());
    for warning in &display.warnings {
        assert_eq!(reader.u16()?, warning.rule.0);
        assert_eq!(reader.u8()?, warning.level as u8);
        assert_eq!(reader.text()?, warning.text);
    }
    assert!(reader.bytes.is_empty());
    Ok(())
}

fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> TestResult {
    out.extend_from_slice(&u32::try_from(bytes.len())?.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn start(domain: &str) -> TestResult<Vec<u8>> {
    start_version(domain, 1)
}

fn start_version(domain: &str, version: u16) -> TestResult<Vec<u8>> {
    let mut out = Vec::new();
    push_bytes(&mut out, domain.as_bytes())?;
    out.extend_from_slice(&version.to_be_bytes());
    Ok(out)
}

fn independent_display_digest(bytes: &[u8]) -> TestResult<[u8; 32]> {
    let mut transcript = start("your-wallet/v3/display")?;
    push_bytes(&mut transcript, bytes)?;
    Ok(sha256(&transcript))
}

/// §6.5 simulation digest (transcript version 2) of the S2 fixture for the S2 transaction, from
/// the raw JSON values.
fn independent_s2_sim_digest() -> TestResult<[u8; 32]> {
    let mut t = start_version("your-wallet/v3/evm-simulation", 2)?;
    push_bytes(&mut t, &s2_tx()?.signing_hash())?;
    t.extend_from_slice(&0x9a_0000_u64.to_be_bytes());
    push_bytes(&mut t, &[0xb0; 32])?;
    t.extend_from_slice(&0x6ac6_4ee0_u64.to_be_bytes());
    push_bytes(&mut t, &U256::from_u64(1_000_000_000).to_be_bytes())?;
    t.push(1);
    t.extend_from_slice(&0x31f38_u64.to_be_bytes());
    t.push(1);
    t.extend_from_slice(&0x31f38_u64.to_be_bytes());
    push_bytes(&mut t, &[])?;
    t.extend_from_slice(&1_u32.to_be_bytes());
    push_bytes(
        &mut t,
        &[0xff; 19].iter().copied().chain([0xfe]).collect::<Vec<_>>(),
    )?;
    t.push(3);
    push_bytes(
        &mut t,
        &hex::decode("ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")?,
    )?;
    push_bytes(
        &mut t,
        &hex::decode("0000000000000000000000009858effd232b4033e47d90003d41ec34ecaeda94")?,
    )?;
    push_bytes(
        &mut t,
        &hex::decode("000000000000000000000000f278cf59f82edcf871d630f28ecc8056f25c1cdb")?,
    )?;
    push_bytes(
        &mut t,
        &hex::decode("000000000000000000000000000000000000000000000000002386f26fc10000")?,
    )?;
    Ok(sha256(&t))
}

enum Tag {
    NotApplicable,
    Simulated([u8; 32]),
    NoneRpcError,
}

fn independent_approval_digest(
    request: &ApprovalRequest,
    origin: &str,
    payload: &[u8],
    display_digest: [u8; 32],
    tag: &Tag,
) -> TestResult<[u8; 32]> {
    let account: Address = parse_address(ACC1)?;
    let mut t = start("your-wallet/v3/approval")?;
    push_bytes(&mut t, &ID)?;
    t.push(request.kind as u8);
    push_bytes(&mut t, origin.as_bytes())?;
    t.push(1);
    t.extend_from_slice(&11_155_111_u64.to_be_bytes());
    push_bytes(&mut t, &SEPOLIA_GENESIS)?;
    push_bytes(&mut t, account.as_bytes())?;
    push_bytes(&mut t, payload)?;
    push_bytes(&mut t, &display_digest)?;
    match tag {
        Tag::NotApplicable => t.push(0),
        Tag::Simulated(sim_digest) => {
            t.push(1);
            t.push(0); // verdict Ok
            t.extend_from_slice(&0x9a_0000_u64.to_be_bytes());
            push_bytes(&mut t, &[0xb0; 32])?;
            t.extend_from_slice(&0x6ac6_4ee0_u64.to_be_bytes());
            push_bytes(&mut t, &U256::from_u64(1_000_000_000).to_be_bytes())?;
            push_bytes(&mut t, sim_digest)?;
        }
        Tag::NoneRpcError => {
            t.push(2);
            t.push(5);
        }
    }
    t.extend_from_slice(&EXPIRES_UNIX_MS.to_be_bytes());
    Ok(sha256(&t))
}

fn check(
    draft: ApprovalDraft,
    origin: &str,
    payload: &[u8],
    tag: &Tag,
    golden: (&str, &str, &str),
) -> TestResult {
    let request = issue(draft)?;
    assert_eq!(request.created_unix_ms, CREATED_UNIX_MS);
    assert_eq!(request.expires_unix_ms, EXPIRES_UNIX_MS);
    let bytes = request.display.bytes()?;
    check_display_bytes(&request, &bytes)?;
    let display_digest = independent_display_digest(&bytes)?;
    assert_eq!(display_digest, request.display.digest()?);
    let approval = independent_approval_digest(&request, origin, payload, display_digest, tag)?;
    assert_eq!(approval, request.digest);
    assert_eq!(hex::encode(&bytes), golden.0);
    assert_eq!(hex::encode(&display_digest), golden.1);
    assert_eq!(hex::encode(&approval), golden.2);
    Ok(())
}

#[test]
fn v14_tag1_simulated() -> TestResult {
    let draft = tag1(Lang::Ko)?;
    let payload = s2_tx()?.signing_preimage();
    check(
        draft,
        "yw-app",
        &payload,
        &Tag::Simulated(independent_s2_sim_digest()?),
        (TAG1_DISPLAY, TAG1_DISPLAY_DIGEST, TAG1_APPROVAL_DIGEST),
    )
}

#[test]
fn v14_tag2_none_rpc_error() -> TestResult {
    let draft = tag2(Lang::Ko)?;
    assert!(
        draft
            .display
            .fields
            .iter()
            .all(|field| !(0x0110..=0x0113).contains(&field.key.0))
    );
    let payload = s2_tx()?.signing_preimage();
    check(
        draft,
        "yw-app",
        &payload,
        &Tag::NoneRpcError,
        (TAG2_DISPLAY, TAG2_DISPLAY_DIGEST, TAG2_APPROVAL_DIGEST),
    )
}

#[test]
fn v14_tag0_not_applicable() -> TestResult {
    let draft = tag0(Lang::Ko)?;
    let payload = b"\x19Ethereum Signed Message:\n9Some data";
    check(
        draft,
        "https://app.example",
        payload,
        &Tag::NotApplicable,
        (TAG0_DISPLAY, TAG0_DISPLAY_DIGEST, TAG0_APPROVAL_DIGEST),
    )
}

/// The Korean bytes are exactly the `YWDSP003` bytes pinned before 2026-11-14 with the magic
/// `YWDSP004` and the language byte 1 after the version: the language change altered no Korean
/// text.
#[test]
fn korean_bytes_are_v3_with_the_language_byte() {
    for (v3, v4) in [
        (TAG1_DISPLAY_V3, TAG1_DISPLAY),
        (TAG2_DISPLAY_V3, TAG2_DISPLAY),
        (TAG0_DISPLAY_V3, TAG0_DISPLAY),
    ] {
        let rest = v3.strip_prefix("59574453503030330001").unwrap_or_default();
        assert_eq!(format!("5957445350303034000101{rest}"), v4);
    }
}

/// Draft, origin, signing payload, simulation tag and the three golden values.
type Case<'a> = (
    ApprovalDraft,
    &'a str,
    &'a [u8],
    Tag,
    (&'a str, &'a str, &'a str),
);

/// The English goldens: same request, English display — no Hangul in any text, and display and
/// approval digests differ from the Korean ones (spec/14 §3).
#[test]
fn v14_english() -> TestResult {
    let payload = s2_tx()?.signing_preimage();
    let personal = b"Ethereum Signed Message:
9Some data";
    let cases: [Case<'_>; 3] = [
        (
            tag1(Lang::En)?,
            "yw-app",
            &payload,
            Tag::Simulated(independent_s2_sim_digest()?),
            (
                EN_TAG1_DISPLAY,
                EN_TAG1_DISPLAY_DIGEST,
                EN_TAG1_APPROVAL_DIGEST,
            ),
        ),
        (
            tag2(Lang::En)?,
            "yw-app",
            &payload,
            Tag::NoneRpcError,
            (
                EN_TAG2_DISPLAY,
                EN_TAG2_DISPLAY_DIGEST,
                EN_TAG2_APPROVAL_DIGEST,
            ),
        ),
        (
            tag0(Lang::En)?,
            "https://app.example",
            personal,
            Tag::NotApplicable,
            (
                EN_TAG0_DISPLAY,
                EN_TAG0_DISPLAY_DIGEST,
                EN_TAG0_APPROVAL_DIGEST,
            ),
        ),
    ];
    for (draft, origin, payload, tag, golden) in cases {
        let display = &draft.display;
        assert_eq!(display.lang, Lang::En);
        assert!(!has_hangul(&display.title));
        assert!(
            display
                .fields
                .iter()
                .all(|field| !has_hangul(&field.sub_label) && !has_hangul(&field.value))
        );
        assert!(
            display
                .warnings
                .iter()
                .all(|warning| !has_hangul(&warning.text))
        );
        check(draft, origin, payload, &tag, golden)?;
    }
    for (english, korean) in [
        (EN_TAG1_DISPLAY_DIGEST, TAG1_DISPLAY_DIGEST),
        (EN_TAG1_APPROVAL_DIGEST, TAG1_APPROVAL_DIGEST),
        (EN_TAG0_APPROVAL_DIGEST, TAG0_APPROVAL_DIGEST),
    ] {
        assert_ne!(english, korean);
    }
    Ok(())
}

#[test]
#[ignore = "prints the V14 golden values for recording"]
#[expect(clippy::print_stdout, reason = "golden recording")]
fn print_v14_goldens() -> TestResult {
    for (name, draft) in [
        ("TAG1", tag1(Lang::Ko)?),
        ("TAG2", tag2(Lang::Ko)?),
        ("TAG0", tag0(Lang::Ko)?),
        ("EN_TAG1", tag1(Lang::En)?),
        ("EN_TAG2", tag2(Lang::En)?),
        ("EN_TAG0", tag0(Lang::En)?),
    ] {
        let request = issue(draft)?;
        let bytes = request.display.bytes()?;
        println!("const {name}_DISPLAY: &str = \"{}\";", hex::encode(&bytes));
        println!(
            "const {name}_DISPLAY_DIGEST: &str = \"{}\";",
            hex::encode(&request.display.digest()?)
        );
        println!(
            "const {name}_APPROVAL_DIGEST: &str = \"{}\";",
            hex::encode(&request.digest)
        );
    }
    // 2026-11-18 (S4 A2): the rows of `KIND_GOLDENS`.
    for lang in [Lang::Ko, Lang::En] {
        for case in kind_cases(lang)? {
            let request = issue(case.draft)?;
            println!(
                "    (\"{}\", \"{}\", \"{}\", \"{}\"),",
                golden_name(lang, case.name),
                hex::encode(&request.display.bytes()?),
                hex::encode(&request.display.digest()?),
                hex::encode(&request.digest)
            );
        }
    }
    Ok(())
}

// ------------------------------------------------------------ every approval kind (S4 A2)
//
// 2026-11-18 (spec/15 §11.4 S4 A2, spec/09 §3.13): before S4 moves the approval flow into the
// engine, every `ApprovalKind` gets display-byte, display-digest and approval-digest goldens in
// Korean and English, plus the WalletConnect-decorated dApp send (spec/13 §7). Each is a
// synthetic request built with the yw-core builders from public test vectors only (ACC-1/2/3,
// the `abandon`×11 `about` Solana keys 0 and 1 and testnet4 BIP84 node, the EIP-712 Ether Mail
// example, the secp256k1 keys 1 and 2, the BIP173 P2WPKH vector) and patterned bytes for txids,
// outpoints and blockhashes. The approval digest is rebuilt with the spec/03 §11.4 field order
// in the test (kind byte, chain tag and network codes written out); the payload bytes of the
// transcript-shaped payloads (SOL intent and messages, dApp SOL transactions, BTC messages,
// HyperCore actions) are the payload's own (their layouts are pinned by their modules' tests),
// the EVM ones are rebuilt here. Recorded from the code at `0909127` with `print_v14_goldens`.

use yw_core::approval::{ApprovalDisplay, SigningPayload, build_typed_request};
use yw_core::bip32::AccountXpub;
use yw_core::bip32::derive_public_child;
use yw_core::bip32::path::BtcChain;
use yw_core::btc::account::{BtcAccountKey, BtcKeySource, BtcPubKey, ScriptType};
use yw_core::btc::address::ScriptKind;
use yw_core::btc::amount::Sats;
use yw_core::btc::display::{BtcSendFacts, build_btc_request};
use yw_core::btc::fee::{FeeChoice, FeeRate, FeeSource};
use yw_core::btc::msgsign::{BtcMessageProtocol, BtcMessageRequest, build_btc_message_request};
use yw_core::btc::network::BtcNetwork;
use yw_core::btc::select::{
    BumpRequest, BumpSource, SendAmount, SendRequest, Utxo, plan_fee_bump, plan_send,
};
use yw_core::btc::tx::{OutPoint, Txid};
use yw_core::evm::display::add_replacement;
use yw_core::evm::eip712::validate_typed_data_v4;
use yw_core::hypercore::display::{HcApprovalInput, HcRecipient, build_hypercore_request};
use yw_core::hypercore::{HcAction, HcNetwork, HcPayload};
use yw_core::slip10::SolKeySource;
use yw_core::sol::address::{SolAddress, SolCluster};
use yw_core::sol::dapp::display::{SolTxFacts, SolTxItemFacts, SolTxRequest};
use yw_core::sol::dapp::{SolSendOptions, SolTxMode, build_sol_tx_request};
use yw_core::sol::display::{
    SimSummary, SolPreviewFacts, build_sol_transfer_request, intent_flags,
};
use yw_core::sol::fee::{SOL_TRANSFER_CU_LIMIT, max_fee};
use yw_core::sol::intent::SolTransferIntent;
use yw_core::sol::msgsign::{SolMessageRequest, build_sol_message_request};
use yw_core::sol::recipient::{AccountClass, check_recipient};
use yw_core::sol::template::{SolAsset, SolTransferCore};
use yw_core::zec::upgrade::{ConsensusObservation, tx_consensus};
use yw_core::zec::{
    ZecAccount, ZecAmount, ZecKeySource, ZecNetwork, ZecOutPoint, ZecSendRequest, ZecUtxo,
    parse_recipient,
};
use yw_engine::flow::evm::prepare::stable_equal;
use yw_engine::walletconnect::{Metadata, VerifyStatus, decorate, session_origin};

/// ACC-2 (`abandon`×11 `about`, `m/44'/60'/0'/0/1`).
const ACC2: &str = "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0";
/// Solana `abandon`×11 `about` `m/44'/501'/0'/0'` and `/1'/0'` (spec/07 §17.1).
const SOL_ABOUT_0: &str = "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk";
const SOL_ABOUT_1: &str = "Hh8QwFUA6MtVu1qAoq12ucvFHNwCcVTV7hpWjeY1Hztb";
/// The S2 block time (2026-10-07 13:53:36 UTC) is `CREATED_UNIX_MS`; the SIWE check time of
/// spec/09 §4.2 is 2026-10-26T00:00:00Z.
const SIWE_NOW_UNIX_MS: u64 = 1_792_972_800_000;
/// The spec/09 §4.2 SIWE base form.
const SIWE_BASE: &str = "app.example wants you to sign in with your Ethereum account:\n0x9858EfFD232B4033E47d90003D41EC34EcaEda94\n\nSign in to Example.\n\nURI: https://app.example/login\nVersion: 1\nChain ID: 11155111\nNonce: 32891756\nIssued At: 2026-10-25T23:59:00Z";
/// The EIP-712 Ether Mail example with the Sepolia chain id.
const ETHER_MAIL_SEPOLIA: &str = r#"{"types":{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Person":[{"name":"name","type":"string"},{"name":"wallet","type":"address"}],"Mail":[{"name":"from","type":"Person"},{"name":"to","type":"Person"},{"name":"contents","type":"string"}]},"primaryType":"Mail","domain":{"name":"Ether Mail","version":"1","chainId":11155111,"verifyingContract":"0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"},"message":{"from":{"name":"Cow","wallet":"0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},"to":{"name":"Bob","wallet":"0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},"contents":"Hello, Bob!"}}"#;
/// testnet4 `m/84'/1'/0'` of `abandon`×11 `about` (spec/08 §14.1, public data).
const BTC_ABOUT_XPUB: &str = "03b88e0fbe3f646337ed93bc0c0f3b843fcf7d2589e5ec884754e6402027a890b4";
const BTC_ABOUT_CHAIN_CODE: &str =
    "3c8c2037ee4c1621da0d348db51163709a622d0d2838dde6d8419c51f6301c62";
/// BIP173 P2WPKH vector program (`tb1qw508d6…`): HASH160 of the secp256k1 generator.
const BIP173_PROGRAM: &str = "751e76e8199196d454941c45d1b3a323f1433bd6";
/// secp256k1 public key of the private key 2 (compressed).
const KEY2_PUBKEY: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
/// testnet P2PKH of the private key 1 (spec/12 §2.3 `cMahea7z…` vector).
const ZEC_KEY1_TESTNET: &str = "tmLPctKo9j49rtCSKpwEBpLBeykiTGomGQs";

/// One recorded kind: the draft and what the independent digest binds.
struct KindCase {
    name: &'static str,
    kind: u8,
    draft: ApprovalDraft,
    origin: String,
    chain: Vec<u8>,
    account: Vec<u8>,
    payload: Vec<u8>,
    tag: Tag,
}

fn evm_chain_bytes() -> TestResult<Vec<u8>> {
    let mut out = vec![1];
    out.extend_from_slice(&11_155_111_u64.to_be_bytes());
    push_bytes(&mut out, &SEPOLIA_GENESIS)?;
    Ok(out)
}

/// `tag ‖ network/cluster code ‖ genesis` (SOL 2, BTC 3, ZEC 5; every test network is code 2).
fn coded_chain_bytes(tag: u8, genesis: &[u8; 32]) -> TestResult<Vec<u8>> {
    let mut out = vec![tag, 2];
    push_bytes(&mut out, genesis)?;
    Ok(out)
}

fn site_origin() -> TestResult<BrowserOrigin> {
    Ok(BrowserOrigin::parse("https://app.example").ok_or("origin")?)
}

fn user() -> TestResult<Address> {
    Ok(parse_address(ACC1)?)
}

fn s2_response() -> SimOutcome {
    parse_simulate_response(
        include_bytes!("fixtures/eth_simulateV1/S2.response.json"),
        1,
    )
}

fn s4_response() -> SimOutcome {
    parse_simulate_response(
        include_bytes!("fixtures/eth_simulateV1/S4.response.json"),
        1,
    )
}

/// An EVM transaction draft of any kind and origin on Sepolia from ACC-1.
fn evm_tx_draft(
    lang: Lang,
    origin: ApprovalOrigin,
    kind: ApprovalKind,
    tx: Eip1559Tx,
    outcome: &SimOutcome,
) -> TestResult<ApprovalDraft> {
    let chain = sepolia();
    let sim = interpret(lang, &chain, &tx, &user()?, outcome, CREATED_UNIX_MS);
    let decoded = DecodedTx {
        call: decode_call(&chain, &tx.to, &tx.data),
        tx,
    };
    Ok(build_evm_tx_request(
        lang,
        ApprovalId(ID),
        origin,
        EvmKeySource::Derived(AccountIndex::ZERO),
        user()?,
        kind,
        &chain,
        &decoded,
        &sim,
        &ChainFacts::default(),
        Vec::new(),
        CREATED_UNIX_MS,
    )?)
}

fn evm_case(
    name: &'static str,
    kind: u8,
    draft: ApprovalDraft,
    origin: &str,
    payload: Vec<u8>,
    tag: Tag,
) -> TestResult<KindCase> {
    Ok(KindCase {
        name,
        kind,
        draft,
        origin: origin.to_owned(),
        chain: evm_chain_bytes()?,
        account: user()?.as_bytes().to_vec(),
        payload,
        tag,
    })
}

/// Speed-up of the S2 transaction (same fees, as `add_replacement` shows them) replacing a
/// patterned hash; simulated with the S2 response.
fn speed_up_case(lang: Lang) -> TestResult<KindCase> {
    let tx = s2_tx()?;
    let draft = evm_tx_draft(
        lang,
        ApprovalOrigin::App,
        ApprovalKind::EvmSpeedUp,
        tx.clone(),
        &s2_response(),
    )?;
    let draft = add_replacement(
        draft,
        &sepolia(),
        &[0xab; 32],
        Some(U256::from_u64(400_000_000_000_000)),
    )?;
    evm_case(
        "SPEED_UP",
        0x11,
        draft,
        "yw-app",
        tx.signing_preimage(),
        Tag::Simulated(independent_s2_sim_digest()?),
    )
}

/// Cancel of the S2 transaction (zero-value self-transfer, same nonce); no simulation result
/// (the S4 response).
fn cancel_case(lang: Lang) -> TestResult<KindCase> {
    let tx = Eip1559Tx {
        gas_limit: 21_000,
        to: user()?,
        value: U256::ZERO,
        ..s2_tx()?
    };
    let draft = evm_tx_draft(
        lang,
        ApprovalOrigin::App,
        ApprovalKind::EvmCancel,
        tx.clone(),
        &s4_response(),
    )?;
    let draft = add_replacement(draft, &sepolia(), &[0xab; 32], None)?;
    evm_case(
        "CANCEL",
        0x12,
        draft,
        "yw-app",
        tx.signing_preimage(),
        Tag::NoneRpcError,
    )
}

/// The Ether Mail example on Sepolia from a site.
fn typed_case(lang: Lang) -> TestResult<KindCase> {
    let value = yw_json::parse(ETHER_MAIL_SEPOLIA.as_bytes(), &yw_json::Limits::REQUEST)?;
    let typed = validate_typed_data_v4(ETHER_MAIL_SEPOLIA.as_bytes(), &value, 11_155_111)?;
    let mut preimage = vec![0x19, 0x01];
    preimage.extend_from_slice(&typed.domain_separator());
    preimage.extend_from_slice(&typed.message_hash());
    let draft = build_typed_request(
        lang,
        ApprovalId(ID),
        ApprovalOrigin::Site(site_origin()?),
        EvmKeySource::Derived(AccountIndex::ZERO),
        user()?,
        ApprovalKind::EvmTypedData,
        &sepolia(),
        &typed,
        &ChainFacts::default(),
        CREATED_UNIX_MS,
    )?;
    evm_case(
        "TYPED",
        0x14,
        draft,
        "https://app.example",
        preimage,
        Tag::NotApplicable,
    )
}

/// The spec/09 §4.2 SIWE base form as `personal_sign` (checked at its own check time).
fn siwe_case(lang: Lang) -> TestResult<KindCase> {
    let mut preimage = format!("\x19Ethereum Signed Message:\n{}", SIWE_BASE.len()).into_bytes();
    preimage.extend_from_slice(SIWE_BASE.as_bytes());
    let draft = build_personal_request(
        lang,
        ApprovalId(ID),
        ApprovalOrigin::Site(site_origin()?),
        EvmKeySource::Derived(AccountIndex::ZERO),
        user()?,
        ApprovalKind::EvmPersonalSign,
        &sepolia(),
        &decode_personal_message(SIWE_BASE.as_bytes().to_vec()),
        SIWE_NOW_UNIX_MS,
    )?;
    evm_case(
        "SIWE",
        0x13,
        draft,
        "https://app.example",
        preimage,
        Tag::NotApplicable,
    )
}

/// The S2 transaction requested over `WalletConnect` (session origin of a patterned topic), with
/// the peer label and the C01 (unverified) warning.
fn walletconnect_drafts(lang: Lang) -> TestResult<(ApprovalDraft, ApprovalDraft, String)> {
    let origin = session_origin(&[0x5c; 32]).ok_or("session origin")?;
    let serialized = origin.as_str().to_owned();
    let undecorated = evm_tx_draft(
        lang,
        ApprovalOrigin::Site(origin),
        ApprovalKind::EvmTransaction,
        s2_tx()?,
        &s2_response(),
    )?;
    let mut decorated = undecorated.clone();
    let peer = Metadata {
        name: "Example dApp".to_owned(),
        description: String::new(),
        url: "https://app.example".to_owned(),
        icons: Vec::new(),
    };
    if !decorate(&mut decorated, &peer, VerifyStatus::Unknown) {
        return Err("decorate".into());
    }
    Ok((decorated, undecorated, serialized))
}

fn walletconnect_case(lang: Lang) -> TestResult<KindCase> {
    let (decorated, _, origin) = walletconnect_drafts(lang)?;
    evm_case(
        "WC_SEND",
        0x10,
        decorated,
        &origin,
        s2_tx()?.signing_preimage(),
        Tag::Simulated(independent_s2_sim_digest()?),
    )
}

/// 1,000,000 lamports from Solana `about` 0 to `about` 1 on devnet at the template limit.
fn sol_transfer_case(lang: Lang) -> TestResult<KindCase> {
    let from = SolAddress::parse(SOL_ABOUT_0).map_err(|_| "from")?;
    let source = SolKeySource::Standard(AccountIndex::ZERO);
    let core = SolTransferCore {
        from,
        to: SolAddress::parse(SOL_ABOUT_1).map_err(|_| "to")?,
        asset: SolAsset::Sol,
        amount: 1_000_000,
        cu_limit: SOL_TRANSFER_CU_LIMIT,
        cu_price_micro: 1_000,
    };
    let recipient = check_recipient(SOL_ABOUT_1, &from, &[]).map_err(|_| "recipient")?;
    let simulation = SimSummary::Ok { units: 450 };
    let flags = intent_flags(
        false,
        &recipient,
        AccountClass::SystemWallet,
        simulation,
        core.cu_limit,
        source,
    );
    let max_fee_lamports = max_fee(core.cu_limit, core.cu_price_micro).map_err(|_| "fee")?;
    let intent = SolTransferIntent {
        id: ID,
        cluster: SolCluster::Devnet,
        source,
        core,
        max_fee_lamports,
        fee_cap_lamports: 100_000,
        flags,
        created_at_ms: CREATED_UNIX_MS,
    };
    let facts = SolPreviewFacts {
        account_label: "Solana 1".to_owned(),
        recipient,
        recipient_account: AccountClass::SystemWallet,
        balance: 10_000_000,
        rent0: 890_880,
        rpc_fee: Some(max_fee_lamports),
        simulation,
        spl: None,
        blocks: Vec::new(),
    };
    let draft = build_sol_transfer_request(lang, &intent, &SolCluster::Devnet.genesis(), &facts)?;
    Ok(KindCase {
        name: "SOL_TRANSFER",
        kind: 0x20,
        payload: intent.transcript(),
        draft,
        origin: "yw-app".to_owned(),
        chain: coded_chain_bytes(2, &SolCluster::Devnet.genesis())?,
        account: from.as_bytes().to_vec(),
        tag: Tag::NotApplicable,
    })
}

fn sol_message_request(message: &[u8], sign_in: bool) -> TestResult<SolMessageRequest> {
    Ok(SolMessageRequest {
        id: ApprovalId(ID),
        origin: site_origin()?,
        cluster: SolCluster::Devnet,
        source: SolKeySource::Standard(AccountIndex::ZERO),
        public: SolAddress::parse(SOL_ABOUT_0)
            .map_err(|_| "key")?
            .to_bytes(),
        label: "Solana 1".to_owned(),
        message: message.to_vec(),
        sign_in,
    })
}

fn sol_message_case(
    name: &'static str,
    kind: u8,
    lang: Lang,
    sign_in: bool,
) -> TestResult<KindCase> {
    let message = if sign_in {
        format!(
            "app.example wants you to sign in with your Solana account:\n{SOL_ABOUT_0}\n\nSign in to Example.\n\nURI: https://app.example/login\nVersion: 1\nChain ID: devnet\nNonce: 32891756\nIssued At: 2026-10-07T13:53:00Z"
        )
    } else {
        "Prove you own this account for app.example".to_owned()
    };
    let draft = build_sol_message_request(
        lang,
        &sol_message_request(message.as_bytes(), sign_in)?,
        CREATED_UNIX_MS,
    )?;
    let SigningPayload::SolMessage(payload) = &draft.payload else {
        return Err("payload".into());
    };
    Ok(KindCase {
        name,
        kind,
        payload: payload.digest_bytes(),
        origin: "https://app.example".to_owned(),
        chain: coded_chain_bytes(2, &SolCluster::Devnet.genesis())?,
        account: SolAddress::parse(SOL_ABOUT_0)
            .map_err(|_| "key")?
            .to_bytes()
            .to_vec(),
        draft,
        tag: Tag::NotApplicable,
    })
}

/// A dApp transfer of 1,000 lamports from Solana `about` 0 (fee payer, its slot zero) to
/// `about` 1, signed and sent by the wallet; patterned blockhash.
fn sol_transaction_case(lang: Lang) -> TestResult<KindCase> {
    let wallet = SolAddress::parse(SOL_ABOUT_0).map_err(|_| "wallet")?;
    let to = SolAddress::parse(SOL_ABOUT_1).map_err(|_| "to")?;
    let mut message = vec![1, 0, 1, 3];
    message.extend_from_slice(wallet.as_bytes());
    message.extend_from_slice(to.as_bytes());
    message.extend_from_slice(&[0; 32]);
    message.extend_from_slice(&[7; 32]);
    message.extend_from_slice(&[1, 2, 2, 0, 1, 12, 2, 0, 0, 0]);
    message.extend_from_slice(&1_000_u64.to_le_bytes());
    let mut wire = vec![1];
    wire.extend_from_slice(&[0; 64]);
    wire.extend_from_slice(&message);
    let request = SolTxRequest {
        id: ApprovalId(ID),
        origin: site_origin()?,
        cluster: SolCluster::Devnet,
        source: SolKeySource::Standard(AccountIndex::ZERO),
        public: wallet.to_bytes(),
        label: "Solana 1".to_owned(),
        mode: SolTxMode::SignAndSend,
        options: SolSendOptions::default(),
        txs: vec![wire],
    };
    let facts = SolTxFacts {
        items: vec![SolTxItemFacts {
            tables: Ok((0, Vec::new())),
            pre: Vec::new(),
            post: None,
            sim: SimSummary::Ok { units: 150 },
            sim_replaced_blockhash: false,
            rpc_fee: Some(5_000),
            blockhash_valid: Some(true),
        }],
        mints: Vec::new(),
        unread_mints: Vec::new(),
        known: Vec::new(),
        fee_cap: 100_000,
    };
    let draft = build_sol_tx_request(lang, &request, &facts)?;
    Ok(KindCase {
        name: "SOL_TX",
        kind: 0x23,
        payload: draft.payload.digest_bytes(),
        draft,
        origin: "https://app.example".to_owned(),
        chain: coded_chain_bytes(2, &SolCluster::Devnet.genesis())?,
        account: wallet.as_bytes().to_vec(),
        tag: Tag::NotApplicable,
    })
}

fn btc_xpub() -> TestResult<AccountXpub> {
    Ok(AccountXpub {
        pubkey: hex::decode_array::<33>(BTC_ABOUT_XPUB)?,
        chain_code: hex::decode_array::<32>(BTC_ABOUT_CHAIN_CODE)?,
    })
}

/// The testnet4 BIP84 account 0 of `abandon`×11 `about` (change on the change chain).
fn btc_account() -> TestResult<BtcAccountKey> {
    Ok(BtcAccountKey::primary(btc_xpub()?).with_single_address(false))
}

fn btc_rate(sat_per_vb: u64) -> FeeChoice {
    FeeChoice {
        rate: FeeRate::from_sat_per_kvb(sat_per_vb * 1_000),
        source: FeeSource::Manual,
    }
}

fn btc_facts() -> TestResult<BtcSendFacts> {
    Ok(BtcSendFacts {
        verified_balance: Sats::new(100_000).ok_or("sats")?,
        min_confirmations: Some(10),
        first_time_recipient: true,
        own_recipient: None,
    })
}

/// 40,000 sats to the BIP173 P2WPKH vector from one 100,000-sat input at 1 sat/vB.
fn btc_send_plan(account: &BtcAccountKey) -> TestResult<yw_core::btc::select::SendPlan> {
    let candidates = [Utxo {
        outpoint: OutPoint {
            txid: Txid::from_bytes([0x11; 32]),
            vout: 0,
        },
        value: Sats::new(100_000).ok_or("sats")?,
        chain: BtcChain::Receive,
        index: 0,
        height: 199_990,
        is_coinbase: false,
    }];
    Ok(plan_send(&SendRequest {
        network: BtcNetwork::Testnet4,
        account,
        recipient: ScriptKind::P2wpkh(hex::decode_array::<20>(BIP173_PROGRAM)?),
        amount: SendAmount::Exact(Sats::new(40_000).ok_or("sats")?),
        fee: btc_rate(1),
        candidates: &candidates,
        tip_height: 200_000,
        change_next: 3,
        layout_seed: [0x5a; 32],
        typed_fee_override: None,
        conflicts: &[],
    })?)
}

fn btc_case(name: &'static str, kind: u8, lang: Lang, bump: bool) -> TestResult<KindCase> {
    let account = btc_account()?;
    let send = btc_send_plan(&account)?;
    let plan = if bump {
        let source = BumpSource {
            network: BtcNetwork::Testnet4,
            txid: Txid::from_bytes([0x5b; 32]),
            inputs: send.inputs().to_vec(),
            recipient: send.recipient(),
            amount: send.amount(),
            change_index: send.change().map(|change| change.index),
            fee: send.fee(),
            vsize: u64::from(send.planned_vsize()),
            send_max: false,
        };
        plan_fee_bump(&BumpRequest {
            source: &source,
            account: &account,
            fee: btc_rate(3),
            incremental: None,
            candidates: &[],
            tip_height: 200_003,
            change_next: 7,
            layout_seed: [0x77; 32],
            typed_fee_override: None,
        })?
    } else {
        send
    };
    let draft = build_btc_request(lang, ApprovalId(ID), &plan, &account, &btc_facts()?)?;
    let SigningPayload::Btc(payload) = &draft.payload else {
        return Err("payload".into());
    };
    Ok(KindCase {
        name,
        kind,
        payload: payload.clone(),
        origin: "yw-app".to_owned(),
        chain: coded_chain_bytes(3, &BtcNetwork::Testnet4.genesis())?,
        account: hex::decode(BTC_ABOUT_XPUB)?,
        draft,
        tag: Tag::NotApplicable,
    })
}

/// A BIP322 message from the testnet4 `about` receive address 0.
fn btc_message_case(lang: Lang) -> TestResult<KindCase> {
    let chain_node = derive_public_child(&btc_xpub()?, BtcChain::Receive.index())?;
    let pubkey = derive_public_child(&chain_node, 0)?.pubkey;
    let draft = build_btc_message_request(
        lang,
        &BtcMessageRequest {
            id: ApprovalId(ID),
            origin: site_origin()?,
            network: BtcNetwork::Testnet4,
            source: BtcKeySource::Derived {
                mnemonic: None,
                script_type: ScriptType::P2wpkh,
                account: 0,
                chain: BtcChain::Receive,
                index: 0,
            },
            pubkey: BtcPubKey::parse(&pubkey)?,
            script_type: ScriptType::P2wpkh,
            label: "Bitcoin 1".to_owned(),
            path: "m/84'/1'/0'/0/0".to_owned(),
            protocol: BtcMessageProtocol::Bip322,
            message: b"Prove you own this address for app.example".to_vec(),
        },
    )?;
    Ok(KindCase {
        name: "BTC_MESSAGE",
        kind: 0x32,
        payload: draft.payload.digest_bytes(),
        draft,
        origin: "https://app.example".to_owned(),
        chain: coded_chain_bytes(3, &BtcNetwork::Testnet4.genesis())?,
        account: pubkey.to_vec(),
        tag: Tag::NotApplicable,
    })
}

/// 40,000 zatoshi from the testnet key 2 (imported) to the testnet P2PKH of key 1.
fn zec_case(lang: Lang) -> TestResult<KindCase> {
    let pubkey = hex::decode_array::<33>(KEY2_PUBKEY)?;
    let account = ZecAccount {
        network: ZecNetwork::Testnet,
        source: ZecKeySource::Imported,
        pubkey,
    };
    let consensus = tx_consensus(
        ZecNetwork::Testnet,
        &ConsensusObservation {
            tip: 4_470_000,
            next_branch: 0x7719_0AD9,
            upgrades: Vec::new(),
        },
    )?;
    let plan = yw_core::zec::plan_send(
        &account,
        &ZecSendRequest {
            recipient: parse_recipient(ZEC_KEY1_TESTNET, ZecNetwork::Testnet)?,
            amount: ZecAmount::Exact(40_000),
            utxos: vec![ZecUtxo {
                outpoint: ZecOutPoint {
                    txid: [0x21; 32],
                    index: 0,
                },
                value: 100_000,
                height: Some(4_469_000),
                coinbase: false,
            }],
            reserved: Vec::new(),
            consensus,
        },
    )?;
    let draft = yw_core::zec::display::build_zec_request(lang, ApprovalId(ID), &plan)?;
    let SigningPayload::Zec(payload) = &draft.payload else {
        return Err("payload".into());
    };
    Ok(KindCase {
        name: "ZEC_SEND",
        kind: 0x50,
        payload: payload.clone(),
        origin: "yw-app".to_owned(),
        chain: coded_chain_bytes(5, &ZecNetwork::Testnet.genesis())?,
        account: pubkey.to_vec(),
        draft,
        tag: Tag::NotApplicable,
    })
}

/// `usdSend` of 1 USDC on the `HyperCore` testnet from ACC-1 to ACC-2 (not in the book).
fn hypercore_case(lang: Lang) -> TestResult<KindCase> {
    let action = HcAction::new(
        HcNetwork::Testnet,
        CREATED_UNIX_MS,
        HcPayload::UsdSend {
            destination: parse_address(ACC2)?,
            amount: "1".to_owned(),
        },
    );
    let draft = build_hypercore_request(
        lang,
        ApprovalId(ID),
        &HcApprovalInput {
            action: &action,
            account: user()?,
            signer: EvmKeySource::Derived(AccountIndex::ZERO),
            token: None,
            recipient: HcRecipient {
                notes: Vec::new(),
                look_alike: false,
                not_in_book: true,
            },
        },
    )?;
    let mut chain = vec![4, 2];
    chain.extend_from_slice(&action.signature_chain_id.to_be_bytes());
    Ok(KindCase {
        name: "HYPERCORE",
        kind: 0x40,
        payload: draft.payload.digest_bytes(),
        draft,
        origin: "yw-app".to_owned(),
        chain,
        account: user()?.as_bytes().to_vec(),
        tag: Tag::NotApplicable,
    })
}

/// Every case of one language, in a fixed order.
fn kind_cases(lang: Lang) -> TestResult<Vec<KindCase>> {
    Ok(vec![
        speed_up_case(lang)?,
        cancel_case(lang)?,
        typed_case(lang)?,
        siwe_case(lang)?,
        walletconnect_case(lang)?,
        sol_transfer_case(lang)?,
        sol_message_case("SOL_MESSAGE", 0x21, lang, false)?,
        sol_message_case("SOL_SIGN_IN", 0x22, lang, true)?,
        sol_transaction_case(lang)?,
        btc_case("BTC_SEND", 0x30, lang, false)?,
        btc_case("BTC_FEE_BUMP", 0x31, lang, true)?,
        btc_message_case(lang)?,
        zec_case(lang)?,
        hypercore_case(lang)?,
    ])
}

fn golden_name(lang: Lang, name: &str) -> String {
    match lang {
        Lang::Ko => name.to_owned(),
        Lang::En => format!("EN_{name}"),
    }
}

/// The approval digest of spec/03 §11.4 rebuilt from a case.
fn independent_kind_digest(case: &KindCase, display_digest: [u8; 32]) -> TestResult<[u8; 32]> {
    let mut t = start("your-wallet/v3/approval")?;
    push_bytes(&mut t, &ID)?;
    t.push(case.kind);
    push_bytes(&mut t, case.origin.as_bytes())?;
    t.extend_from_slice(&case.chain);
    push_bytes(&mut t, &case.account)?;
    push_bytes(&mut t, &case.payload)?;
    push_bytes(&mut t, &display_digest)?;
    match &case.tag {
        Tag::NotApplicable => t.push(0),
        Tag::Simulated(sim_digest) => {
            t.push(1);
            t.push(0);
            t.extend_from_slice(&0x9a_0000_u64.to_be_bytes());
            push_bytes(&mut t, &[0xb0; 32])?;
            t.extend_from_slice(&0x6ac6_4ee0_u64.to_be_bytes());
            push_bytes(&mut t, &U256::from_u64(1_000_000_000).to_be_bytes())?;
            push_bytes(&mut t, sim_digest)?;
        }
        Tag::NoneRpcError => {
            t.push(2);
            t.push(5);
        }
    }
    t.extend_from_slice(&EXPIRES_UNIX_MS.to_be_bytes());
    Ok(sha256(&t))
}

fn has_no_hangul(display: &ApprovalDisplay) -> bool {
    !has_hangul(&display.title)
        && display
            .fields
            .iter()
            .all(|field| !has_hangul(&field.sub_label) && !has_hangul(&field.value))
        && display
            .warnings
            .iter()
            .all(|warning| !has_hangul(&warning.text))
}

/// The golden row of `name`: display bytes, display digest, approval digest.
type KindGolden = (&'static str, &'static str, &'static str, &'static str);

/// Every approval kind ko and en (spec/09 §3.13): display bytes, display digest, approval digest.
const KIND_GOLDENS: &[KindGolden] = &[
    (
        "SPEED_UP",
        "595744535030303400010100000000003c5b5365706f6c696120ed858cec8aa4ed8ab8eb84b75d205365706f6c696145544820ebb3b4eb82b4eab8b03a20302e3031205365706f6c6961455448000f000101000000000000000f596f75722057616c6c657420ec95b100020100000000000000275365706f6c696120ed858cec8aa4ed8ab8eb84b72028636861696e49642031313135353131312900030100000000000000333078393835382045664644203233324220343033332045343764203930303020334434312045433334204563614520646139340101010000000000000033307846323738206346353920463832652044636638203731643620333046322038456343203830353620663235432031636462010201000000000000000f302e3031205365706f6c696145544801030100000000000000145365706f6c696145544820ebb3b4eb82b4eab8b0011001000000000000000f302e3031205365706f6c69614554480120010000000000000015302e3030303439313034205365706f6c69614554480121020000000000000015302e3030303232353036205365706f6c6961455448012200000000000000001d6d61784665652032206777656920c2b72074697020302e31206777656901230000000000000000073234352c353230012400000000000000000130012501000000000000006c3078616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261620aeab8b0eca1b420ecb59ceb8c8020ec8898ec8898eba38c20302e30303034205365706f6c6961455448013002000000000000002cebb894eba19d2031302c3039322c35343420c2b720323032362d31302d30372031333a35333a3336205554430141000000000000000013ec9786ec9d8c202830ebb094ec9db4ed8ab8290001451c000000002aeca3bcec868ceba19dec979020ec9786eb8a9420ebb09beb8a9420eca3bcec868cec9e85eb8b88eb8ba4",
        "5f5b033b1830a48c8a7335f68b425ee0a9a395cfdb21c85c5a93f2be1a7f5f63",
        "4e4cd2516eea6e59ce24d28840b033a5a1abd7e9095ec380a758cf4e05b7dd9e",
    ),
    (
        "CANCEL",
        "595744535030303400010102010000002e5b5365706f6c696120ed858cec8aa4ed8ab8eb84b75d20eab1b0eb9e9820ecb7a8ec868c20286e6f6e6365203029000e000101000000000000000f596f75722057616c6c657420ec95b100020100000000000000275365706f6c696120ed858cec8aa4ed8ab8eb84b72028636861696e49642031313135353131312900030100000000000000333078393835382045664644203233324220343033332045343764203930303020334434312045433334204563614520646139340101010000000000000033307839383538204566464420323332422034303333204534376420393030302033443431204543333420456361452064613934010201000000000000000c30205365706f6c696145544801030100000000000000145365706f6c696145544820ebb3b4eb82b4eab8b00120010000000000000013302e303030303432205365706f6c6961455448012102000000000000000eec958c20ec889820ec9786ec9d8c012200000000000000001d6d61784665652032206777656920c2b72074697020302e312067776569012300000000000000000632312c30303001240000000000000000013001250100000000000000683078616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261620aeab8b0eca1b420ecb59ceb8c8020ec8898ec8898eba38c20eab384ec82b020ebb688eab080013002000000000000005dec8b9cebaeaceba088ec9db4ec859820ec9786ec9d8c3a20ec9e94ec95a1ec9db420ebb3b4eb82bc20eab888ec95a1eab3bc20ecb59ceb8c8020ec8898ec8898eba38cec9d9820ed95a9ebb3b4eb8ba420eca081ec8ab5eb8b88eb8ba40141000000000000000013ec9786ec9d8c202830ebb094ec9db4ed8ab829000145010200000093ec8b9cebaeaceba088ec9db4ec859820eab2b0eab3bc20ec9786ec9d8c20e2809420ec8ba4eca09c20ed9aa8eab3bceba5bc20ed9995ec9db8ed95a020ec889820ec9786ec8ab5eb8b88eb8ba40aec9e94ec95a1ec9db420ebb3b4eb82bc20eab888ec95a1eab3bc20ecb59ceb8c8020ec8898ec8898eba38cec9d9820ed95a9ebb3b4eb8ba420eca081ec8ab5eb8b88eb8ba4",
        "07ef28e8a5830f3671fcd732ae67c9ea75c6901eb98a7ea5d0fccc0a6eadb007",
        "d5a57378c9a03cf3e0531ff2d48c4ec51b72078cafb8eab49bea479b6f6e941d",
    ),
    (
        "TYPED",
        "595744535030303400010102010000002e5b5365706f6c696120ed858cec8aa4ed8ab8eb84b75d20ed8380ec9e8520eb8db0ec9db4ed84b020ec849cebaa85000a000101000000000000001368747470733a2f2f6170702e6578616d706c6500020100000000000000275365706f6c696120ed858cec8aa4ed8ab8eb84b72028636861696e496420313131353531313129000301000000000000003330783938353820456646442032333242203430333320453437642039303030203344343120454333342045636145206461393403010100000000000000746e616d653a204574686572204d61696c0a76657273696f6e3a20310a636861696e49643a2031313135353131310a766572696679696e67436f6e74726163743a20307843634343206363636320434343432063434343204343436320436343632063436343204343634320636363632063636343030201000000000000001bec958c20ec889820ec9786eb8a9420ed9895ec8b9d3a204d61696c0304010000000966726f6d2e6e616d6500000003436f770304010000000b66726f6d2e77616c6c65740000003330784344326120336439462039333845203133434420393437452063303541206243374620453733342044663844204438323603040100000007746f2e6e616d6500000003426f6203040100000009746f2e77616c6c65740000003330786242624220424242622062424242206262624220626242622062626242204262426220626262422062426262204242624203040100000008636f6e74656e74730000000b48656c6c6f2c20426f622100015404020000002fec958c20ec889820ec9786eb8a9420ed9895ec8b9dec9d9820ec849cebaa8520ec9a94ecb2adec9e85eb8b88eb8ba4",
        "88963c7a0b10f73436b4b8bb30c2a3ea8a3a52710460cb1d2b12b1e5f3d97d5b",
        "04a19d4d1ce4efd7bfafeb4e57711cca49cba368efcf0ec72fdbf17a59319a23",
    ),
    (
        "SIWE",
        "595744535030303400010100000000002e5b5365706f6c696120ed858cec8aa4ed8ab8eb84b75d20eba19ceab7b8ec9db820ec9a94ecb2ad20285349574529000c000101000000000000001368747470733a2f2f6170702e6578616d706c6500020100000000000000275365706f6c696120ed858cec8aa4ed8ab8eb84b72028636861696e496420313131353531313129000301000000000000003330783938353820456646442032333242203430333320453437642039303030203344343120454333342045636145206461393404010100000000000001326170702e6578616d706c652077616e747320796f7520746f207369676e20696e207769746820796f757220457468657265756d206163636f756e743a5b552b303030415d0a3078393835384566464432333242343033334534376439303030334434314543333445636145646139345b552b303030415d0a5b552b303030415d0a5369676e20696e20746f204578616d706c652e5b552b303030415d0a5b552b303030415d0a5552493a2068747470733a2f2f6170702e6578616d706c652f6c6f67696e5b552b303030415d0a56657273696f6e3a20315b552b303030415d0a436861696e2049443a2031313135353131315b552b303030415d0a4e6f6e63653a2033323839313735365b552b303030415d0a4973737565642041743a20323032362d31302d32355432333a35393a30305a040300000000000000000c323334ebb094ec9db4ed8ab804040100000009eb8f84eba994ec9db80000000b6170702e6578616d706c6504040100000006eca3bcec868c0000003330783938353820456646442032333242203430333320453437642039303030203344343120454333342045636145206461393404040100000006ec84a4ebaa85000000135369676e20696e20746f204578616d706c652e040401000000035552490000001968747470733a2f2f6170702e6578616d706c652f6c6f67696e04040100000009ecb2b4ec9db8204944000000083131313535313131040401000000054e6f6e63650000000833323839313735360404010000000debb09ceab88920ec8b9ceab0810000003b323032362d31302d32355432333a35393a30305a0a323032362d31302d32352032333a35393a3030205554432028ec95bd2031ebb68420eca08429000153090000000017eba19ceab7b8ec9db820ec9a94ecb2ad20285349574529",
        "e52c5d2fba89906fc2aab1545ea6b98f84f2e395edb4a59f11e267cf4add36b2",
        "f9e85f5e6360293d5cb6eb153dae862a472db6ef27ee6e8a2524a4fd5a35166a",
    ),
    (
        "WC_SEND",
        "595744535030303400010101000000003c5b5365706f6c696120ed858cec8aa4ed8ab8eb84b75d205365706f6c696145544820ebb3b4eb82b4eab8b03a20302e3031205365706f6c6961455448000e000101000000000000004257616c6c6574436f6e6e6563743a2068747470733a2f2f6170702e6578616d706c652028ec82acec9db4ed8ab8eab08020eca3bcec9ea5ed959c20eca3bcec868c2900020100000000000000275365706f6c696120ed858cec8aa4ed8ab8eb84b72028636861696e49642031313135353131312900030100000000000000333078393835382045664644203233324220343033332045343764203930303020334434312045433334204563614520646139340101010000000000000033307846323738206346353920463832652044636638203731643620333046322038456343203830353620663235432031636462010201000000000000000f302e3031205365706f6c696145544801030100000000000000145365706f6c696145544820ebb3b4eb82b4eab8b0011001000000000000000f302e3031205365706f6c69614554480120010000000000000015302e3030303439313034205365706f6c69614554480121020000000000000015302e3030303232353036205365706f6c6961455448012200000000000000001d6d61784665652032206777656920c2b72074697020302e31206777656901230000000000000000073234352c353230012400000000000000000130013002000000000000002cebb894eba19d2031302c3039322c35343420c2b720323032362d31302d30372031333a35333a3336205554430141000000000000000013ec9786ec9d8c202830ebb094ec9db4ed8ab82900024301010000007d57616c6c6574436f6e6e65637420ec9a94ecb2adec9e85eb8b88eb8ba420e2809420ec82acec9db4ed8ab820eca3bcec868ceb8a9420ec82acec9db4ed8ab8eab08020ec8aa4ec8aa4eba19c20eca3bcec9ea5ed959c20eab092ec9db4eba9b020ed9995ec9db8eb9098eca78020ec958aec9598ec8ab5eb8b88eb8ba4451c000000007deca3bcec868ceba19dec979020ec9786eb8a9420ebb09beb8a9420eca3bcec868cec9e85eb8b88eb8ba40aec82acec9db4ed8ab8eab08020eca095ed959c20eca3bcec868cec9e85eb8b88eb8ba420e2809420ebb09beb8a9420eca3bcec868ceab08020eba79eeb8a94eca78020ed9995ec9db8ed9598ec84b8ec9a94",
        "d60585789a314eed5d97f1691a128dfdbb766672fbf915f0609834d21e1c77a5",
        "ecb36524f29af1ecf172e1b7c175bfa19f9fad257606d035c2681bf59f4bd03c",
    ),
    (
        "SOL_TRANSFER",
        "59574453503030340001010100000000375b536f6c616e61206465766e65742028ed858cec8aa4ed8ab8295d20534f4c20eca084ec86a13a20302e30303130303030303020534f4c000b000101000000000000000f596f75722057616c6c657420ec95b10002010000000000000059536f6c616e61206465766e65742028ed858cec8aa4ed8ab8290a67656e6573697320ed9995ec9db8eb90a83a20457457545241425a61597136694d6665594b6f75527531363656553278716131776361576f78506b725a42470003010000000000000050536f6c616e6120310a6d2f3434272f353031272f30272f30270a4841676b2031344a70204d514c6720743672562067763763204251464a205746746f203544717820693437322075543344204b70716b050101000000000000003648683851207746554120364d74562075317141206f713132207563764620484e774320635654562037687057206a65593120487a74620502010000000000000022302e30303130303030303020534f4c0a312c3030302c303030206c616d706f72747305040100000000000000f7eab8b0ebb3b820ec8898ec8898eba38c20352c303030206c616d706f72747320c39720ec849cebaa8520310aec9ab0ec84a020ec8898ec8898eba38c2031206c616d706f7274732028435520ed959ceb8f842036303020c39720eab080eab2a920312c303030206d6963726f2d6c616d706f7274732f43552c20ec98aceba6bc290aecb59ceb8c8020ed95a9eab38420302e30303030303530303120534f4c2028352c303031206c616d706f727473290aec82acec9aa9ec9e9020ec8381ed959c203130302c303030206c616d706f7274730a52504320676574466565466f724d6573736167653a20352c303031206c616d706f7274730505010000000000000022302e30303130303530303120534f4c0a312c3030352c303031206c616d706f7274730506000000000000000030302e30313030303030303020534f4c20e2869220302e30303839393439393920534f4c202852504320eab8b0eca48029050700000000000000000eec84b1eab3b528435520343530290508000000000000000081ec8ab9ec9db820ecb0bdec9d8020ed919cec8b9c20ed9b8420313230ecb488ec979020eba78ceba38c28eb82a8ec9d8020ec8b9ceab084ec9d8020ec8381ed839c20eca484292e20ec8ab9ec9db820eca689ec8b9c20ec849cebaa85ed9598eba9b020eab1b0eb9e98eb8a9420ec95bd203330ecb48820eb92a420eba78ceba38c0509000000000b696e74656e745f68617368000000406633363531373262323239353937383964383338626366643435373762373738653039346132323030636337303931396334636336316561626232363332313400014c060100000075ecb298ec9d8c20ebb3b4eb82b4eb8a9420eca3bcec868cec9e85eb8b88eb8ba42e20eca3bcec868c20eca084ecb2b4eba5bc20ed9995ec9db8ed9598eab3a02c20ed81b020eab888ec95a1ec9d8020ec868cec95a120ec8b9ced979820ec86a1eab88820eb92a420ebb3b4eb82b4ec84b8ec9a942e",
        "71761eab394ed85f6e491cf0c1a8308e9ad391c31985ebf726691f7364fb2e75",
        "9f681fe50e5f36a234afc1660bd3e3c322c9e709ab8d52a64a09962133e7631d",
    ),
    (
        "SOL_MESSAGE",
        "595744535030303400010100000000003c5b536f6c616e61206465766e65742028ed858cec8aa4ed8ab8295d20eba994ec8b9ceca78020ec849cebaa852028ec868cec9ca020eca69debaa85290005000101000000000000001368747470733a2f2f6170702e6578616d706c650002010000000000000019536f6c616e61206465766e65742028ed858cec8aa4ed8ab8290003010000000000000046536f6c616e6120310a6d2f3434272f353031272f30272f30270a4841676b31344a704d514c6774367256677637634251464a5746746f3544717869343732755433444b70716b040101000000000000002a50726f766520796f75206f776e2074686973206163636f756e7420666f72206170702e6578616d706c65040300000000000000000b3432ebb094ec9db4ed8ab800014d04000000005aec868cec9ca020eca69debaa85ec9aa920eba994ec8b9ceca78020ec849cebaa85ec9e85eb8b88eb8ba420e2809420eab1b0eb9e98c2b7ec86a1eab888ec9790eb8a9420ec93b0ec9db4eca78020ec958aec8ab5eb8b88eb8ba4",
        "0f53cabe6b19a4ed53c1f85b7945937bdd35cdee3800a3fccedca5199388e36d",
        "001b66b01a8e318ac9af2339ca0f227375d8f989390bb7396aed756c9f456b6f",
    ),
    (
        "SOL_SIGN_IN",
        "59574453503030340001010000000000335b536f6c616e61206465766e65742028ed858cec8aa4ed8ab8295d20eba19ceab7b8ec9db820ec9a94ecb2ad20285349575329000d000101000000000000001368747470733a2f2f6170702e6578616d706c650002010000000000000019536f6c616e61206465766e65742028ed858cec8aa4ed8ab8290003010000000000000046536f6c616e6120310a6d2f3434272f353031272f30272f30270a4841676b31344a704d514c6774367256677637634251464a5746746f3544717869343732755433444b70716b04010100000000000001306170702e6578616d706c652077616e747320796f7520746f207369676e20696e207769746820796f757220536f6c616e61206163636f756e743a5b552b303030415d0a4841676b31344a704d514c6774367256677637634251464a5746746f3544717869343732755433444b70716b5b552b303030415d0a5b552b303030415d0a5369676e20696e20746f204578616d706c652e5b552b303030415d0a5b552b303030415d0a5552493a2068747470733a2f2f6170702e6578616d706c652f6c6f67696e5b552b303030415d0a56657273696f6e3a20315b552b303030415d0a436861696e2049443a206465766e65745b552b303030415d0a4e6f6e63653a2033323839313735365b552b303030415d0a4973737565642041743a20323032362d31302d30375431333a35333a30305a040300000000000000000c323332ebb094ec9db4ed8ab804050100000009eb8f84eba994ec9db80000000b6170702e6578616d706c6504050100000006eca3bcec868c0000002c4841676b31344a704d514c6774367256677637634251464a5746746f3544717869343732755433444b70716b04050100000006ec84a4ebaa85000000135369676e20696e20746f204578616d706c652e040501000000035552490000001968747470733a2f2f6170702e6578616d706c652f6c6f67696e04050100000006ebb284eca084000000013104050100000008436861696e204944000000066465766e6574040501000000054e6f6e63650000000833323839313735360405010000000debb09ceab88920ec8b9ceab08100000014323032362d31302d30375431333a35333a30305a00024d04000000005aec868cec9ca020eca69debaa85ec9aa920eba994ec8b9ceca78020ec849cebaa85ec9e85eb8b88eb8ba420e2809420eab1b0eb9e98c2b7ec86a1eab888ec9790eb8a9420ec93b0ec9db4eca78020ec958aec8ab5eb8b88eb8ba457080000000017eba19ceab7b8ec9db820ec9a94ecb2ad20285349575329",
        "927d3a8a3d4de230878ed6d38c3d1e72466f345e8310c3890ca041ccb3ff60e8",
        "d5cbe18eaf8d751f7459e8bbd2522897d9b78f98ef4a0029b2a182d83fbd100a",
    ),
    (
        "SOL_TX",
        "595744535030303400010100000000003e5b536f6c616e61206465766e65742028ed858cec8aa4ed8ab8295d20ec82acec9db4ed8ab820eab1b0eb9e9820ec849cebaa8520ed9b8420eca084ec86a1000f000101000000000000001368747470733a2f2f6170702e6578616d706c650002010000000000000059536f6c616e61206465766e65742028ed858cec8aa4ed8ab8290a67656e6573697320ed9995ec9db8eb90a83a20457457545241425a61597136694d6665594b6f75527531363656553278716131776361576f78506b725a42470003010000000000000050536f6c616e6120310a6d2f3434272f353031272f30272f30270a4841676b2031344a70204d514c6720743672562067763763204251464a205746746f203544717820693437322075543344204b70716b051001000000000000004fec849cebaa8520ed9b8420eca084ec86a120e2809420eca780eab091ec9db420ec849cebaa85ed9598eab3a020ebb094eba19c20eca084ec86a1ed95a9eb8b88eb8ba40aeab1b0eb9e982031eab1b40519010000000000000082707265666c6967687420eab280ec82ac3a20ed95a82028636f6d6d69746d656e7420636f6e6669726d6564290a6d696e436f6e74657874536c6f743a20ec9786ec9d8c0aec9eaceca084ec86a13a20eba78ceba38ceb90a020eb958ceab98ceca78020eca780eab091ec9db420eca781eca09120286d6178526574726965732030290515010000000000000045ec8b9cebaeaceba088ec9db4ec859820eab2b0eab3bceab08020ec9786ec96b420ebb380ed9994eba5bc20ed9995ec9db8ed95a020ec889820ec9786ec8ab5eb8b88eb8ba4051601000000000000009a352c303030206c616d706f727473202852504320676574466565466f724d657373616765290aeab384ec82b0eab09220352c303030206c616d706f7274732028eab1b0eb9e9820ebb094ec9db4ed8ab8eba19c20eab384ec82b0290aec8898ec8898eba38c20eca780ebb6883a20eb82b420eca780eab0910aec82acec9aa9ec9e9020ec8381ed959c203130302c303030206c616d706f72747305120100000000000000f9312e2053797374656d3a20534f4c20ebb3b4eb82b4eab8b020285472616e73666572290aebb3b4eb82b4eb8a9420eab384eca0950a4841676b2031344a70204d514c6720743672562067763763204251464a205746746f203544717820693437322075543344204b70716b0a5bec849cebaa855d205bec93b0eab8b05d205beb82b420eca780eab0915d0aebb09beb8a9420eab384eca0950a48683851207746554120364d74562075317141206f713132207563764620484e774320635654562037687057206a65593120487a74620a5bec93b0eab8b05d0a302e30303030303130303020534f4c2028312c303030206c616d706f7274732905130100000000000000954841676b2031344a70204d514c6720743672562067763763204251464a205746746f203544717820693437322075543344204b70716b0a5bec849cebaa855d205bec93b0eab8b05d205beb82b420eca780eab0915d0a48683851207746554120364d74562075317141206f713132207563764620484e774320635654562037687057206a65593120487a74620a5bec93b0eab8b05d051101000000000000008fec849cebaa85ec9e90203120c2b720ec8898ec8898eba38c20eca780ebb6880a4841676b2031344a70204d514c6720743672562067763763204251464a205746746f203544717820693437322075543344204b70716b0a5bec849cebaa855d205bec93b0eab8b05d205beb82b420eca780eab0915d0aeca780eab091ec9db420ec849cebaa85ed95a9eb8b88eb8ba40514010000000000000027eca1b0ed9a8c20ed858cec9db4ebb89420ec9786ec9d8c20286c656761637920eab1b0eb9e9829051700000000000000000fec84b1eab3b5202843552031353029051800000000000000009debb894eba19ded95b4ec8b9c20ec9ca0ed9aa820ed9995ec9db8eb90a820285250432c2070726f636573736564290aebb894eba19ded95b4ec8b9ceb8a9420ec95bd20313530ebb894eba19d20eb92a420eba78ceba38ceb90a9eb8b88eb8ba420e2809420eb8aa6eab28c20ec8ab9ec9db8ed9598eba9b420eab1b0eb9e98eab08020ec8ba4ed8ca8ed95a020ec889820ec9e88ec8ab5eb8b88eb8ba4051a0000000000000000403538653231613963303334643965613664653965316264633331353263323934356333303032363562333538353438313833383565373133356231306166663205400000000000000001323078303130303031303366303336323736323436613735623964653333343965643432623135653233326636353138666332306635666364346631643634653831660a396264323538663766383032396163663563626362646435616334366563313437663362373861336466366535303232656630343131646232626162363530640a333239613463643430303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030300a303030303030303030373037303730373037303730373037303730373037303730373037303730373037303730373037303730373037303730373037303730370a30373037303730373031303230323030303130633032303030303030653830333030303030303030303030300000",
        "eaf2769a08f28757be731bbc9487f8d4f25ab56e9f3be53e0f4f1c75795d2763",
        "a79c69989ec1ebbcea97b12ffc96a442cc77f0681178bf54270af0e3529d6412",
    ),
    (
        "BTC_SEND",
        "595744535030303400010101000000002c5b426974636f696e20746573746e6574345d20ebb3b4eb82b4eab8b03a20302e303030343030303020425443000c000101000000000000000f596f75722057616c6c657420ec95b10002010000000000000022424954434f494e20544553544e45543420e2809420eab080ecb99820ec9786ec9d8c0003010000000000000035426974636f696e20eb84a4ec9db4ed8bb0ebb88c20ec84b8eab7b8ec9c9720eab384eca095203020286d2f3834272f31272f302729060101000000000000002a7462317177353038643671656a7874646734793572337a6172766172793063357877376b78706a7a73780602010000000000000006503257504b48060301000000000000001c302e303030343030303020425443202834302c303030207361747329060401000000000000003d302e30303035393835392042544320e2809420ec9db420eca780eab091ec9cbceba19c20eb8f8cec9584ec98b4206d2f3834272f31272f30272f312f33060501000000000000008931eab09c2c20ed95a9eab38420302e30303130303030302042544320283130302c3030302073617473290aebaaa8eb93a020ec9e85eba0a520eab888ec95a1ec9d8020ec9db4eca08420eab1b0eb9e9820ed95b4ec8b9ceba19c20eab280eca69deb90a80aecb59cec868c20ed9995ec9db820ec88982031302028ec849cebb28420eab8b0eca48029060601000000000000009a302e30303030303134312042544320283134312073617473290a31207361742f76422028eab384ed9a8d207673697a652031343120764220eab8b0eca4802c20ec849cebaa8520ed9b8420ec8ba4eca09c20eab092ec9d8020eab099eab1b0eb829820eb8692ec9d8c290aebb3b4eb82b4eb8a9420eab888ec95a1ec9d9820302e3335250aecb69cecb2983a20eca781eca09120ec9e85eba0a5060701000000000000001c302e303030343031343120425443202834302c3134312073617473290608000000000000000042302e303030353938353920425443202835392c3835392073617473292028eab280eca69d20ec9e94ec95a120302e30303130303030302042544320eab8b0eca4802906400000000000000000e176657273696f6e20320a6e4c6f636b54696d652032303030303020283d20ebb894eba19d20eb8692ec9db420323030303030290a52424620eab080eb8aa5202873657175656e63652030784646464646464644290aec9e85eba0a520ed9895ec8b9d20503257504b480a7673697a652031343120764220c2b720776569676874203536312057552028ec849cebaa8520eca08420ecb694eca095290a747869642066383238396461386635303261383436316234633735666536393339376430373236303733613639383639396636653830643436356263336230653662616134000142050100000075ecb298ec9d8c20ebb3b4eb82b4eb8a9420eca3bcec868cec9e85eb8b88eb8ba42e20eca3bcec868c20eca084ecb2b4eba5bc20ed9995ec9db8ed9598eab3a02c20ed81b020eab888ec95a1ec9d8020ec868cec95a120ec8b9ced979820ec86a1eab88820eb92a420ebb3b4eb82b4ec84b8ec9a942e",
        "4c281dd6a686a716fede8db53a11080cf95523e385d041ac5b93cbcf84ef2e76",
        "4b23b8d5c6618210a054925cbffd8eadd25d35a1012b9f708f5b2596dd806c13",
    ),
    (
        "BTC_FEE_BUMP",
        "59574453503030340001010100000000265b426974636f696e20746573746e6574345d20ec8898ec8898eba38c20ec98aceba6aceab8b0000d000101000000000000000f596f75722057616c6c657420ec95b10002010000000000000022424954434f494e20544553544e45543420e2809420eab080ecb99820ec9786ec9d8c0003010000000000000035426974636f696e20eb84a4ec9db4ed8bb0ebb88c20ec84b8eab7b8ec9c9720eab384eca095203020286d2f3834272f31272f302729060101000000000000002a7462317177353038643671656a7874646734793572337a6172766172793063357877376b78706a7a73780602010000000000000006503257504b48060301000000000000001c302e303030343030303020425443202834302c303030207361747329060401000000000000003d302e30303035393537372042544320e2809420ec9db420eca780eab091ec9cbceba19c20eb8f8cec9584ec98b4206d2f3834272f31272f30272f312f33060501000000000000008931eab09c2c20ed95a9eab38420302e30303130303030302042544320283130302c3030302073617473290aebaaa8eb93a020ec9e85eba0a520eab888ec95a1ec9d8020ec9db4eca08420eab1b0eb9e9820ed95b4ec8b9ceba19c20eab280eca69deb90a80aecb59cec868c20ed9995ec9db820ec88982031302028ec849cebb28420eab8b0eca48029060601000000000000009a302e30303030303432332042544320283432332073617473290a33207361742f76422028eab384ed9a8d207673697a652031343120764220eab8b0eca4802c20ec849cebaa8520ed9b8420ec8ba4eca09c20eab092ec9d8020eab099eab1b0eb829820eb8692ec9d8c290aebb3b4eb82b4eb8a9420eab888ec95a1ec9d9820312e3036250aecb69cecb2983a20eca781eca09120ec9e85eba0a5060701000000000000001c302e303030343034323320425443202834302c3432332073617473290608000000000000000043302e30303135393537372042544320283135392c3537372073617473292028eab280eca69d20ec9e94ec95a120302e30303130303030302042544320eab8b0eca480290609010000000000000088eab590ecb2b420eb8c80ec838120356235623562356235623562356235623562356235623562356235623562356235623562356235623562356235623562356235623562356235623562356235620aec8898ec8898eba38c2031343120e2869220343233207361747320282b323832290aec8898ec8ba0ec9e9020ebb380eab2bd20ec9786ec9d8c06400000000000000000e176657273696f6e20320a6e4c6f636b54696d652032303030303320283d20ebb894eba19d20eb8692ec9db420323030303033290a52424620eab080eb8aa5202873657175656e63652030784646464646464644290aec9e85eba0a520ed9895ec8b9d20503257504b480a7673697a652031343120764220c2b720776569676874203536312057552028ec849cebaa8520eca08420ecb694eca095290a747869642064663838376661353163323931366638343163313636303135306666616331316461343533636663663262383135623730303263646235313836363134323162000142050100000075ecb298ec9d8c20ebb3b4eb82b4eb8a9420eca3bcec868cec9e85eb8b88eb8ba42e20eca3bcec868c20eca084ecb2b4eba5bc20ed9995ec9db8ed9598eab3a02c20ed81b020eab888ec95a1ec9d8020ec868cec95a120ec8b9ced979820ec86a1eab88820eb92a420ebb3b4eb82b4ec84b8ec9a942e",
        "ffc85e367e558bd16f0b85d3b3ae2ff802cd8a22fc69019071d35a578a03be85",
        "b1a600b7595b73b10349e8a5620b4e8fc5cf33a69ab814884dd112f853221e21",
    ),
    (
        "BTC_MESSAGE",
        "59574453503030340001010000000000335b426974636f696e20746573746e6574345d20eba994ec8b9ceca78020ec849cebaa852028ec868cec9ca020eca69debaa85290006000101000000000000001368747470733a2f2f6170702e6578616d706c650002010000000000000010426974636f696e20746573746e6574340003010000000000000044426974636f696e20310a6d2f3834272f31272f30272f302f300a7462317136727a32386d63666178746d6436763738396c3972726c727573647072723970716370766b6c040601000000000000000f424950333232202873696d706c6529040101000000000000002a50726f766520796f75206f776e2074686973206164647265737320666f72206170702e6578616d706c65040300000000000000000b3432ebb094ec9db4ed8ab800014d04000000005aec868cec9ca020eca69debaa85ec9aa920eba994ec8b9ceca78020ec849cebaa85ec9e85eb8b88eb8ba420e2809420eab1b0eb9e98c2b7ec86a1eab888ec9790eb8a9420ec93b0ec9db4eca78020ec958aec8ab5eb8b88eb8ba4",
        "ba2b67f8bbb91692f2568dfb1ac1fb0c18d4b5ad0489193a5269a72e9b30b56a",
        "96f2d7e2655fa5c875aa7df56c94de7c1c2fc95f5c91ce49a0d956e6a42c8c81",
    ),
    (
        "ZEC_SEND",
        "59574453503030340001010000000000295b5a6361736820746573746e65745d20ebb3b4eb82b4eab8b03a20302e3030303430303030205a4543000c000101000000000000000f596f75722057616c6c657420ec95b1000201000000000000001f5a4341534820544553544e455420e2809420eab080ecb99820ec9786ec9d8c00030100000000000000625a6361736820eab080eca0b8ec98a820ed82a420c2b720eab080eca0b8ec98a820eab09cec9db8ed82a42028ebb3b5eab5ac20eb8ba8ec96b420ebb096290a746d414b693242766665535670674b4e75556a68634762766f6f647575636e317447780801010000000000000023746d4c5063744b6f396a3439727443534b70774542704c4265796b6954476f6d475173080201000000000000001aec9dbcebb098287472616e73706172656e742920eca3bcec868c080301000000000000001c302e3030303430303030205a4543202834302c303030207a617473290804010000000000000051302e3030303530303030205a454320e2809420eab099ec9d8020eca3bcec868ceba19c20eb8f8cec9584ec98b420746d414b693242766665535670674b4e75556a68634762766f6f647575636e31744778080501000000000000005c302e3030303130303030205a4543202831302c303030207a617473290a5a49502033313720eab8b0ebb3b820ec8898ec8898eba38c2031302c303030207a6174732028ec9e85eba0a52031eab09c2c20ecb69ceba0a52032eab09c29080601000000000000001c302e3030303530303030205a4543202835302c303030207a61747329080701000000000000009cebb894eba19d20343437303132312028eb8ba4ec9d8c20ebb894eba19d2034343730303031ebb680ed84b020313231ebb894eba19d2c20ec95bd203530ebb68420ec9588ec979020ed8faced95a8eb9098eca78020ec958aec9cbceba9b420ebacb4ed9aa8290aeb84a4ed8ab8ec9b8ced81ac20ec9785eab7b8eba088ec9db4eb939c204e553720286272616e636820696420373731393061643929080800000000000000009431eab09c2c20ed95a9eab38420302e3030313030303030205a454320283130302c303030207a617473290aec9e85eba0a520eab888ec95a1eab3bc20ec8aa4ed81aceba6bded8ab8eb8a9420ec849cebaa85285a49502032343429ec979020ed8faced95a8eb9098ec96b42c20ed8b80eba6aceba9b420eab1b0eb9e98eab08020ebacb4ed9aa8eab08020eb90a9eb8b88eb8ba40840000000000000000081763520eab1b0eb9e9820285a495020323235292c20ec9dbcebb098287472616e73706172656e742920ec9e85eba0a5c2b7ecb69ceba0a5eba78c0a6e4c6f636b54696d65203020c2b72073657175656e636520307846464646464646460a534947484153485f414c4c20285a495020323434290aeca780eca09520eab888ec95a100015a050000000069ec9dbcebb098287472616e73706172656e742920eca084ec86a1ec9d8020ebb3b4eb82b4eb8a9420eca3bcec868cc2b7ebb09beb8a9420eca3bcec868cc2b7eab888ec95a1ec9db420ebb894eba19decb2b4ec9db8ec979020eab3b5eab09ceb90a9eb8b88eb8ba42e",
        "1514162185187c631d713cd52ad6728fc63f6d0435e277d1485652759b6991a8",
        "24caa8f656ae16976d51b87f7b855fbef77728cbe96392f615ed33d430ef206f",
    ),
    (
        "HYPERCORE",
        "59574453503030340001010100000000455b4879706572436f726520ed858cec8aa4ed8ab8eb84b75d204879706572436f726520eca084ec86a13a205553444320ebb3b4eb82b4eab8b020284879706572436f7265290009000101000000000000000f596f75722057616c6c657420ec95b1000201000000000000005948797065726c6971756964204879706572436f726520ed858cec8aa4ed8ab8eb84b72028636861696e496420343231363134eba19c20ec849cebaa8520c2b72068797065726c6971756964436861696e20546573746e657429000301000000000000002a30783938353845664644323332423430333345343764393030303344343145433334456361456461393407010100000000000000295553444320ebb3b4eb82b4eab8b020284879706572436f7265290a28747970652075736453656e6429070201000000000000002a3078364661633444313863393132333433424638366661373034393336344464344534323441623943300703010000000000000006312055534443070401000000000000002aec9786ec9d8c20284879706572436f726520ec82acec9aa9ec9e9020ec849cebaa8520ec9e91ec9785290705000000000000000026313739313338313231363030302028756e6978206d732c20ec849cebaa8520ec8b9ceab0812907060000000000000002ad7b227479706573223a7b22454950373132446f6d61696e223a5b7b226e616d65223a226e616d65222c2274797065223a22737472696e67227d2c7b226e616d65223a2276657273696f6e222c2274797065223a22737472696e67227d2c7b226e616d65223a22636861696e4964222c2274797065223a2275696e74323536227d2c7b226e616d65223a22766572696679696e67436f6e7472616374222c2274797065223a2261646472657373227d5d2c2248797065726c69717569645472616e73616374696f6e3a55736453656e64223a5b7b226e616d65223a2268797065726c6971756964436861696e222c2274797065223a22737472696e67227d2c7b226e616d65223a2264657374696e6174696f6e222c2274797065223a22737472696e67227d2c7b226e616d65223a22616d6f756e74222c2274797065223a22737472696e67227d2c7b226e616d65223a2274696d65222c2274797065223a2275696e743634227d5d7d2c227072696d61727954797065223a2248797065726c69717569645472616e73616374696f6e3a55736453656e64222c22646f6d61696e223a7b226e616d65223a2248797065726c69717569645369676e5472616e73616374696f6e222c2276657273696f6e223a2231222c22636861696e4964223a3432313631342c22766572696679696e67436f6e7472616374223a22307830303030303030303030303030303030303030303030303030303030303030303030303030303030227d2c226d657373616765223a7b2268797065726c6971756964436861696e223a22546573746e6574222c2264657374696e6174696f6e223a22307836666163346431386339313233343362663836666137303439333634646434653432346162396330222c22616d6f756e74223a2231222c2274696d65223a313739313338313231363030307d7d00024802010000004febb09beb8a9420eca3bcec868ceab08020eca3bcec868ceba19dec979020ec9786ec8ab5eb8b88eb8ba420e2809420eca3bcec868c20eca084ecb2b4eba5bc20ed9995ec9db8ed9598ec84b8ec9a94480100000000794879706572436f726520ec82acec9aa9ec9e9020ec849cebaa8520ec9e91ec9785ec9e85eb8b88eb8ba420e2809420ec849cebaa85ed9598eba9b42048797065726c6971756964eab08020ebb094eba19c20ecb298eba6aced9598eba9b020eb9098eb8f8ceba6b420ec889820ec9786ec8ab5eb8b88eb8ba4",
        "63d62dc0c577ccd9a2f4d38cedc3fe225e80fd9341d58be50ec6b1885ed82c06",
        "753ccca7e0ac177d57526d59fde0e4a112ac6de2fad359b6f5e99fd1fed95217",
    ),
    (
        "EN_SPEED_UP",
        "59574453503030340001020000000000325b5365706f6c696120546573746e65745d2053656e64205365706f6c69614554483a20302e3031205365706f6c6961455448000f000101000000000000000f596f75722057616c6c65742061707000020100000000000000225365706f6c696120546573746e65742028636861696e49642031313135353131312900030100000000000000333078393835382045664644203233324220343033332045343764203930303020334434312045433334204563614520646139340101010000000000000033307846323738206346353920463832652044636638203731643620333046322038456343203830353620663235432031636462010201000000000000000f302e3031205365706f6c6961455448010301000000000000000f53656e64205365706f6c6961455448011001000000000000000f302e3031205365706f6c69614554480120010000000000000015302e3030303439313034205365706f6c69614554480121020000000000000015302e3030303232353036205365706f6c6961455448012200000000000000001d6d61784665652032206777656920c2b72074697020302e31206777656901230000000000000000073234352c35323001240000000000000000013001250100000000000000653078616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261620a50726576696f7573206d61782066656520302e30303034205365706f6c6961455448013002000000000000002b426c6f636b2031302c3039322c35343420c2b720323032362d31302d30372031333a35333a333620555443014100000000000000000e6e6f6e65202830206279746573290001451c000000002954686520726563697069656e74206973206e6f7420696e20796f7572206164647265737320626f6f6b",
        "6f7976351ad15c922b0d7611a7006b1139d5b4f8c167f745d266f66d32d11cb7",
        "0468c8d1f57e72ee0658ccb5ea3bd25131715868f00dabf0f084015eeacd022c",
    ),
    (
        "EN_CANCEL",
        "595744535030303400010202010000002e5b5365706f6c696120546573746e65745d2043616e63656c207472616e73616374696f6e20286e6f6e6365203029000e000101000000000000000f596f75722057616c6c65742061707000020100000000000000225365706f6c696120546573746e65742028636861696e49642031313135353131312900030100000000000000333078393835382045664644203233324220343033332045343764203930303020334434312045433334204563614520646139340101010000000000000033307839383538204566464420323332422034303333204534376420393030302033443431204543333420456361452064613934010201000000000000000c30205365706f6c6961455448010301000000000000000f53656e64205365706f6c69614554480120010000000000000013302e303030303432205365706f6c69614554480121020000000000000007756e6b6e6f776e012200000000000000001d6d61784665652032206777656920c2b72074697020302e312067776569012300000000000000000632312c30303001240000000000000000013001250100000000000000663078616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261620a50726576696f7573206d6178206665652063616e6e6f7420626520636f6d707574656401300200000000000000434e6f2073696d756c6174696f6e3a205468652062616c616e6365206973206c657373207468616e2074686520616d6f756e7420706c757320746865206d617820666565014100000000000000000e6e6f6e652028302062797465732900014501020000006f4e6f2073696d756c6174696f6e20726573756c7420e2809420746865207265616c206566666563742063616e6e6f7420626520636865636b65640a5468652062616c616e6365206973206c657373207468616e2074686520616d6f756e7420706c757320746865206d617820666565",
        "ad21cec63669cde8ceb7e3cf91f1d1d472327a5a8ada7df1ae217fab321151de",
        "9272a45867b85dd93fc331ea0f3648e2e88b4db13a001560256e36c3e93da6d8",
    ),
    (
        "EN_TYPED",
        "59574453503030340001020201000000265b5365706f6c696120546573746e65745d2054797065642064617461207369676e6174757265000a000101000000000000001368747470733a2f2f6170702e6578616d706c6500020100000000000000225365706f6c696120546573746e65742028636861696e496420313131353531313129000301000000000000003330783938353820456646442032333242203430333320453437642039303030203344343120454333342045636145206461393403010100000000000000746e616d653a204574686572204d61696c0a76657273696f6e3a20310a636861696e49643a2031313135353131310a766572696679696e67436f6e74726163743a203078436343432063636363204343434320634343432043434363204363436320634363432043436343206363636320636363430302010000000000000014556e6b6e6f776e20666f726d61743a204d61696c0304010000000966726f6d2e6e616d6500000003436f770304010000000b66726f6d2e77616c6c65740000003330784344326120336439462039333845203133434420393437452063303541206243374620453733342044663844204438323603040100000007746f2e6e616d6500000003426f6203040100000009746f2e77616c6c65740000003330786242624220424242622062424242206262624220626242622062626242204262426220626262422062426262204242624203040100000008636f6e74656e74730000000b48656c6c6f2c20426f62210001540402000000265369676e6174757265207265717565737420696e20616e20756e6b6e6f776e20666f726d6174",
        "66a485ba7d90e497655ee03f599ecb7d209b13c7f36115a9bf77e8871fea8f95",
        "4cd10c94b9fb39520f48ee7b10c321d16283754dad3c23233587efa6ca54fe5a",
    ),
    (
        "EN_SIWE",
        "59574453503030340001020000000000285b5365706f6c696120546573746e65745d205369676e2d696e207265717565737420285349574529000c000101000000000000001368747470733a2f2f6170702e6578616d706c6500020100000000000000225365706f6c696120546573746e65742028636861696e496420313131353531313129000301000000000000003330783938353820456646442032333242203430333320453437642039303030203344343120454333342045636145206461393404010100000000000001326170702e6578616d706c652077616e747320796f7520746f207369676e20696e207769746820796f757220457468657265756d206163636f756e743a5b552b303030415d0a3078393835384566464432333242343033334534376439303030334434314543333445636145646139345b552b303030415d0a5b552b303030415d0a5369676e20696e20746f204578616d706c652e5b552b303030415d0a5b552b303030415d0a5552493a2068747470733a2f2f6170702e6578616d706c652f6c6f67696e5b552b303030415d0a56657273696f6e3a20315b552b303030415d0a436861696e2049443a2031313135353131315b552b303030415d0a4e6f6e63653a2033323839313735365b552b303030415d0a4973737565642041743a20323032362d31302d32355432333a35393a30305a040300000000000000000932333420627974657304040100000006446f6d61696e0000000b6170702e6578616d706c650404010000000741646472657373000000333078393835382045664644203233324220343033332045343764203930303020334434312045433334204563614520646139340404010000000953746174656d656e74000000135369676e20696e20746f204578616d706c652e040401000000035552490000001968747470733a2f2f6170702e6578616d706c652f6c6f67696e04040100000008436861696e204944000000083131313535313131040401000000054e6f6e63650000000833323839313735360404010000000949737375656420617400000042323032362d31302d32355432333a35393a30305a0a323032362d31302d32352032333a35393a303020555443202861626f75742031206d696e757465732061676f290001530900000000165369676e2d696e207265717565737420285349574529",
        "e106762e6643175ffecb63954c776989c55adf5c3e5c5c45f0bd919ec5094704",
        "2aae5e05037c03ad0cc1c89838f1dccaacfa13d9cffd6eca07830f3a46f33605",
    ),
    (
        "EN_WC_SEND",
        "59574453503030340001020100000000325b5365706f6c696120546573746e65745d2053656e64205365706f6c69614554483a20302e3031205365706f6c6961455448000e000101000000000000004057616c6c6574436f6e6e6563743a2068747470733a2f2f6170702e6578616d706c6520286164647265737320636c61696d65642062792074686520736974652900020100000000000000225365706f6c696120546573746e65742028636861696e49642031313135353131312900030100000000000000333078393835382045664644203233324220343033332045343764203930303020334434312045433334204563614520646139340101010000000000000033307846323738206346353920463832652044636638203731643620333046322038456343203830353620663235432031636462010201000000000000000f302e3031205365706f6c6961455448010301000000000000000f53656e64205365706f6c6961455448011001000000000000000f302e3031205365706f6c69614554480120010000000000000015302e3030303439313034205365706f6c69614554480121020000000000000015302e3030303232353036205365706f6c6961455448012200000000000000001d6d61784665652032206777656920c2b72074697020302e31206777656901230000000000000000073234352c353230012400000000000000000130013002000000000000002b426c6f636b2031302c3039322c35343420c2b720323032362d31302d30372031333a35333a333620555443014100000000000000000e6e6f6e652028302062797465732900024301010000005657616c6c6574436f6e6e656374207265717565737420e280942074686520736974652061646472657373206973207768617420746865207369746520636c61696d7320616e64206973206e6f74207665726966696564451c000000006b54686520726563697069656e74206973206e6f7420696e20796f7572206164647265737320626f6f6b0a54686520736974652063686f73652074686973206164647265737320e2809420636865636b20746861742074686520726563697069656e74206973207269676874",
        "d31063e85034346842e027e9f39c0b4924b70e77f440a12d4dac6ecede59502a",
        "de6fbad0407fe548d7d5dbcce33a2ae27ec6d7880c479355e81bde96fcc4fed5",
    ),
    (
        "EN_SOL_TRANSFER",
        "59574453503030340001020100000000345b536f6c616e61206465766e6574202874657374295d20534f4c207472616e736665723a20302e30303130303030303020534f4c000b000101000000000000000f596f75722057616c6c6574206170700002010000000000000053536f6c616e61206465766e6574202874657374290a67656e657369732076657269666965643a20457457545241425a61597136694d6665594b6f75527531363656553278716131776361576f78506b725a42470003010000000000000050536f6c616e6120310a6d2f3434272f353031272f30272f30270a4841676b2031344a70204d514c6720743672562067763763204251464a205746746f203544717820693437322075543344204b70716b050101000000000000003648683851207746554120364d74562075317141206f713132207563764620484e774320635654562037687057206a65593120487a74620502010000000000000022302e30303130303030303020534f4c0a312c3030302c303030206c616d706f72747305040100000000000000e4426173652066656520352c303030206c616d706f72747320c3972031207369676e61747572650a5072696f72697479206665652031206c616d706f72747320284355206c696d69742036303020c39720707269636520312c303030206d6963726f2d6c616d706f7274732f43552c20726f756e646564207570290a4d617820746f74616c20302e30303030303530303120534f4c2028352c303031206c616d706f727473290a596f757220636170203130302c303030206c616d706f7274730a52504320676574466565466f724d6573736167653a20352c303031206c616d706f7274730505010000000000000022302e30303130303530303120534f4c0a312c3030352c303031206c616d706f727473050600000000000000002d302e30313030303030303020534f4c20e2869220302e30303839393439393920534f4c2028706572205250432905070000000000000000105375636365737320284355203435302905080000000000000000a054686520617070726f76616c2077696e646f7720657870697265732031323020732061667465722069742069732073686f776e202874696d65206c65667420696e207468652073746174757320626172292e204974207369676e7320617320736f6f6e20617320796f7520617070726f76652c20616e6420746865207472616e73616374696f6e20657870697265732061667465722061626f757420333020730509000000000b696e74656e745f68617368000000406633363531373262323239353937383964383338626366643435373762373738653039346132323030636337303931396334636336316561626232363332313400014c06010000006546697273742073656e6420746f207468697320616464726573732e20436865636b207468652077686f6c6520616464726573732c20616e642073656e64206120736d616c6c207465737420616d6f756e74206265666f72652061206c61726765206f6e652e",
        "c9d3329dbc0441489c0455b5bcfebb8be34858e512e538a039f08eb894561d9c",
        "2077b9825a34c898bcee996241d73f13e41eb454f4dd5bf60387b4462aa1aca9",
    ),
    (
        "EN_SOL_MESSAGE",
        "59574453503030340001020000000000385b536f6c616e61206465766e6574202874657374295d205369676e206d657373616765202870726f6f66206f66206f776e657273686970290005000101000000000000001368747470733a2f2f6170702e6578616d706c650002010000000000000014536f6c616e61206465766e6574202874657374290003010000000000000046536f6c616e6120310a6d2f3434272f353031272f30272f30270a4841676b31344a704d514c6774367256677637634251464a5746746f3544717869343732755433444b70716b040101000000000000002a50726f766520796f75206f776e2074686973206163636f756e7420666f72206170702e6578616d706c650403000000000000000008343220627974657300014d0400000000534d657373616765207369676e617475726520666f722070726f6f66206f66206f776e65727368697020e28094206e6f74207573656420666f72207472616e73616374696f6e73206f72207472616e7366657273",
        "d9b16d750834703444632b45d5531816d9529b8b43130ae31b278faeea32343a",
        "6c91fd2554e46d93b280036e248b3206e04e826fd1e488bc5d757d11c5d74ca1",
    ),
    (
        "EN_SOL_SIGN_IN",
        "595744535030303400010200000000002d5b536f6c616e61206465766e6574202874657374295d205369676e2d696e207265717565737420285349575329000d000101000000000000001368747470733a2f2f6170702e6578616d706c650002010000000000000014536f6c616e61206465766e6574202874657374290003010000000000000046536f6c616e6120310a6d2f3434272f353031272f30272f30270a4841676b31344a704d514c6774367256677637634251464a5746746f3544717869343732755433444b70716b04010100000000000001306170702e6578616d706c652077616e747320796f7520746f207369676e20696e207769746820796f757220536f6c616e61206163636f756e743a5b552b303030415d0a4841676b31344a704d514c6774367256677637634251464a5746746f3544717869343732755433444b70716b5b552b303030415d0a5b552b303030415d0a5369676e20696e20746f204578616d706c652e5b552b303030415d0a5b552b303030415d0a5552493a2068747470733a2f2f6170702e6578616d706c652f6c6f67696e5b552b303030415d0a56657273696f6e3a20315b552b303030415d0a436861696e2049443a206465766e65745b552b303030415d0a4e6f6e63653a2033323839313735365b552b303030415d0a4973737565642041743a20323032362d31302d30375431333a35333a30305a040300000000000000000932333220627974657304050100000006446f6d61696e0000000b6170702e6578616d706c6504050100000007416464726573730000002c4841676b31344a704d514c6774367256677637634251464a5746746f3544717869343732755433444b70716b0405010000000953746174656d656e74000000135369676e20696e20746f204578616d706c652e040501000000035552490000001968747470733a2f2f6170702e6578616d706c652f6c6f67696e0405010000000756657273696f6e000000013104050100000008436861696e204944000000066465766e6574040501000000054e6f6e63650000000833323839313735360405010000000949737375656420617400000014323032362d31302d30375431333a35333a30305a00024d0400000000534d657373616765207369676e617475726520666f722070726f6f66206f66206f776e65727368697020e28094206e6f74207573656420666f72207472616e73616374696f6e73206f72207472616e7366657273570800000000165369676e2d696e207265717565737420285349575329",
        "f110487fe1a3f895314cf19e17b92a7a80f6e58cd845d1a38a4dd02285ef77fc",
        "8a94a5a2e5f673e831fed222b8fe3e654469ff28a74f0b1582bb726043d93b71",
    ),
    (
        "EN_SOL_TX",
        "59574453503030340001020000000000355b536f6c616e61206465766e6574202874657374295d205369676e20616e642073656e642073697465207472616e73616374696f6e000f000101000000000000001368747470733a2f2f6170702e6578616d706c650002010000000000000053536f6c616e61206465766e6574202874657374290a67656e657369732076657269666965643a20457457545241425a61597136694d6665594b6f75527531363656553278716131776361576f78506b725a42470003010000000000000050536f6c616e6120310a6d2f3434272f353031272f30272f30270a4841676b2031344a70204d514c6720743672562067763763204251464a205746746f203544717820693437322075543344204b70716b05100100000000000000475369676e20616e642073656e6420e28094207468652077616c6c6574207369676e7320616e642073656e647320726967687420617761790a5472616e73616374696f6e733a2031051901000000000000007b507265666c6967687420636865636b3a206f6e2028636f6d6d69746d656e7420636f6e6669726d6564290a6d696e436f6e74657874536c6f743a206e6f6e650a526573656e64696e673a206279207468652077616c6c657420697473656c6620756e74696c2065787069727920286d61785265747269657320302905150100000000000000364e6f2073696d756c6174696f6e20726573756c742c20736f20746865206368616e6765732063616e6e6f7420626520636865636b65640516010000000000000089352c303030206c616d706f727473202852504320676574466565466f724d657373616765290a436f6d707574656420352c303030206c616d706f727473202866726f6d20746865207472616e73616374696f6e206279746573290a4665652070617965723a206d792077616c6c65740a596f757220636170203130302c303030206c616d706f72747305120100000000000000fa312e2053797374656d3a2053656e6420534f4c20285472616e73666572290a53656e64696e67206163636f756e740a4841676b2031344a70204d514c6720743672562067763763204251464a205746746f203544717820693437322075543344204b70716b0a5b7369676e65725d205b7772697461626c655d205b6d792077616c6c65745d0a526563656976696e67206163636f756e740a48683851207746554120364d74562075317141206f713132207563764620484e774320635654562037687057206a65593120487a74620a5b7772697461626c655d0a302e30303030303130303020534f4c2028312c303030206c616d706f7274732905130100000000000000984841676b2031344a70204d514c6720743672562067763763204251464a205746746f203544717820693437322075543344204b70716b0a5b7369676e65725d205b7772697461626c655d205b6d792077616c6c65745d0a48683851207746554120364d74562075317141206f713132207563764620484e774320635654562037687057206a65593120487a74620a5b7772697461626c655d051101000000000000007d5369676e6572203120c2b7206665652070617965720a4841676b2031344a70204d514c6720743672562067763763204251464a205746746f203544717820693437322075543344204b70716b0a5b7369676e65725d205b7772697461626c655d205b6d792077616c6c65745d0a5468652077616c6c6574207369676e7305140100000000000000254e6f206c6f6f6b7570207461626c657320286c6567616379207472616e73616374696f6e29051700000000000000001053756363657373202843552031353029051800000000000000008a426c6f636b686173682076657269666965642061732076616c696420285250432c2070726f636573736564290a54686520626c6f636b6861736820657870697265732061667465722061626f75742031353020626c6f636b7320e2809420617070726f76696e67206c6174652063616e206d616b6520746865207472616e73616374696f6e206661696c051a0000000000000000403538653231613963303334643965613664653965316264633331353263323934356333303032363562333538353438313833383565373133356231306166663205400000000000000001323078303130303031303366303336323736323436613735623964653333343965643432623135653233326636353138666332306635666364346631643634653831660a396264323538663766383032396163663563626362646435616334366563313437663362373861336466366535303232656630343131646232626162363530640a333239613463643430303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030300a303030303030303030373037303730373037303730373037303730373037303730373037303730373037303730373037303730373037303730373037303730370a30373037303730373031303230323030303130633032303030303030653830333030303030303030303030300000",
        "fdb32e9dd248ed39943d959b9b7c647f7bff57d9933b6a7966878df5d8f2147c",
        "f0ca92f918c5e70e427928392a1db59df23da891cabc4d6a7f2aa645c4ee659e",
    ),
    (
        "EN_BTC_SEND",
        "59574453503030340001020100000000275b426974636f696e20746573746e6574345d2053656e643a20302e303030343030303020425443000c000101000000000000000f596f75722057616c6c657420617070000201000000000000001d424954434f494e20544553544e45543420e28094204e4f2056414c5545000301000000000000002d426974636f696e204e617469766520536567576974206163636f756e74203020286d2f3834272f31272f302729060101000000000000002a7462317177353038643671656a7874646734793572337a6172766172793063357877376b78706a7a73780602010000000000000006503257504b48060301000000000000001c302e303030343030303020425443202834302c3030302073617473290604010000000000000039302e30303035393835392042544320e280942072657475726e7320746f20746869732077616c6c6574206d2f3834272f31272f30272f312f33060501000000000000008a312c20746f74616c20302e30303130303030302042544320283130302c3030302073617473290a457665727920696e70757420616d6f756e74207665726966696564206279206974732070726576696f7573207472616e73616374696f6e20686173680a4d696e696d756d20636f6e6669726d6174696f6e73203130202873657276657220646174612906060100000000000000a8302e30303030303134312042544320283134312073617473290a31207361742f7642202861742074686520706c616e6e6564207673697a65203134312076423b207468652061637475616c2076616c7565206166746572207369676e696e67206973207468652073616d65206f7220686967686572290a302e333525206f662074686520616d6f756e742073656e740a536f757263653a20456e7465726564206d616e75616c6c79060701000000000000001c302e303030343031343120425443202834302c313431207361747329060800000000000000004b302e303030353938353920425443202835392c38353920736174732920286261736564206f6e207468652076657269666965642062616c616e636520302e3030313030303030204254432906400000000000000000e576657273696f6e20320a6e4c6f636b54696d652032303030303020283d20626c6f636b2068656967687420323030303030290a52424620656e61626c6564202873657175656e63652030784646464646464644290a496e707574207479706520503257504b480a7673697a652031343120764220c2b720776569676874203536312057552028657374696d61746564206265666f7265207369676e696e67290a74786964206638323839646138663530326138343631623463373566653639333937643037323630373361363938363939663665383064343635626333623065366261613400014205010000006546697273742073656e6420746f207468697320616464726573732e20436865636b207468652077686f6c6520616464726573732c20616e642073656e64206120736d616c6c207465737420616d6f756e74206265666f72652061206c61726765206f6e652e",
        "27c6cab6d912cbc0d968e4cb3243d476e5f33e76f5746478877f3c12a4d2553c",
        "3ea935884f22538dc803ca1dfd7e019ab7a42e517393816ca6791c55607c91a4",
    ),
    (
        "EN_BTC_FEE_BUMP",
        "595744535030303400010201000000001b5b426974636f696e20746573746e6574345d2042756d7020666565000d000101000000000000000f596f75722057616c6c657420617070000201000000000000001d424954434f494e20544553544e45543420e28094204e4f2056414c5545000301000000000000002d426974636f696e204e617469766520536567576974206163636f756e74203020286d2f3834272f31272f302729060101000000000000002a7462317177353038643671656a7874646734793572337a6172766172793063357877376b78706a7a73780602010000000000000006503257504b48060301000000000000001c302e303030343030303020425443202834302c3030302073617473290604010000000000000039302e30303035393537372042544320e280942072657475726e7320746f20746869732077616c6c6574206d2f3834272f31272f30272f312f33060501000000000000008a312c20746f74616c20302e30303130303030302042544320283130302c3030302073617473290a457665727920696e70757420616d6f756e74207665726966696564206279206974732070726576696f7573207472616e73616374696f6e20686173680a4d696e696d756d20636f6e6669726d6174696f6e73203130202873657276657220646174612906060100000000000000a8302e30303030303432332042544320283432332073617473290a33207361742f7642202861742074686520706c616e6e6564207673697a65203134312076423b207468652061637475616c2076616c7565206166746572207369676e696e67206973207468652073616d65206f7220686967686572290a312e303625206f662074686520616d6f756e742073656e740a536f757263653a20456e7465726564206d616e75616c6c79060701000000000000001c302e303030343034323320425443202834302c343233207361747329060800000000000000004c302e30303135393537372042544320283135392c35373720736174732920286261736564206f6e207468652076657269666965642062616c616e636520302e3030313030303030204254432906090100000000000000795265706c6163657320356235623562356235623562356235623562356235623562356235623562356235623562356235623562356235623562356235623562356235623562356235620a4665652031343120e2869220343233207361747320282b323832290a526563697069656e7420756e6368616e67656406400000000000000000e576657273696f6e20320a6e4c6f636b54696d652032303030303320283d20626c6f636b2068656967687420323030303033290a52424620656e61626c6564202873657175656e63652030784646464646464644290a496e707574207479706520503257504b480a7673697a652031343120764220c2b720776569676874203536312057552028657374696d61746564206265666f7265207369676e696e67290a74786964206466383837666135316332393136663834316331363630313530666661633131646134353363666366326238313562373030326364623531383636313432316200014205010000006546697273742073656e6420746f207468697320616464726573732e20436865636b207468652077686f6c6520616464726573732c20616e642073656e64206120736d616c6c207465737420616d6f756e74206265666f72652061206c61726765206f6e652e",
        "7b0cb9e0de0c463a4800f3ac06d561e305cd37c1badc5834e8f6b21617a6a731",
        "57ad6f06e3c786ac9ced3d8cea69f36ccce043dcabed56068989b4a4eca6268f",
    ),
    (
        "EN_BTC_MESSAGE",
        "59574453503030340001020000000000345b426974636f696e20746573746e6574345d205369676e206d657373616765202870726f6f66206f66206f776e657273686970290006000101000000000000001368747470733a2f2f6170702e6578616d706c650002010000000000000010426974636f696e20746573746e6574340003010000000000000044426974636f696e20310a6d2f3834272f31272f30272f302f300a7462317136727a32386d63666178746d6436763738396c3972726c727573647072723970716370766b6c040601000000000000000f424950333232202873696d706c6529040101000000000000002a50726f766520796f75206f776e2074686973206164647265737320666f72206170702e6578616d706c650403000000000000000008343220627974657300014d0400000000534d657373616765207369676e617475726520666f722070726f6f66206f66206f776e65727368697020e28094206e6f74207573656420666f72207472616e73616374696f6e73206f72207472616e7366657273",
        "7c4e24eac6d233bafddfdacf78f880b9e0c35d468b98f7870bfb52c0d07bbcb6",
        "f85d8d17a71a0b2b7dffaf7dd2b1e53595bd7c659e7640b3c24577e46e922257",
    ),
    (
        "EN_ZEC_SEND",
        "59574453503030340001020000000000245b5a6361736820746573746e65745d2053656e643a20302e3030303430303030205a4543000c000101000000000000000f596f75722057616c6c657420617070000201000000000000001a5a4341534820544553544e455420e28094204e4f2056414c5545000301000000000000006b5a6361736820496d706f72746564206b657920c2b720496d706f727465642070726976617465206b657920286f75747369646520746865207265636f7665727920776f726473290a746d414b693242766665535670674b4e75556a68634762766f6f647575636e317447780801010000000000000023746d4c5063744b6f396a3439727443534b70774542704c4265796b6954476f6d47517308020100000000000000135472616e73706172656e742061646472657373080301000000000000001c302e3030303430303030205a4543202834302c303030207a617473290804010000000000000052302e3030303530303030205a454320e280942072657475726e7320746f207468652073616d65206164647265737320746d414b693242766665535670674b4e75556a68634762766f6f647575636e317447780805010000000000000057302e3030303130303030205a4543202831302c303030207a617473290a5a49502033313720636f6e76656e74696f6e616c206665652031302c303030207a61747320283120696e707574732c2032206f75747075747329080601000000000000001c302e3030303530303030205a4543202835302c303030207a61747329080701000000000000008c426c6f636b20343437303132312028696e76616c696420756e6c65737320696e636c756465642077697468696e2031323120626c6f636b732066726f6d20746865206e65787420626c6f636b20343437303030312c2061626f7574203530206d696e290a4e6574776f726b2075706772616465204e553720286272616e6368206964203737313930616439290808000000000000000093312c20746f74616c20302e3030313030303030205a454320283130302c303030207a617473290a496e70757420616d6f756e747320616e642073637269707473206172652070617274206f6620746865207369676e617475726520285a495020323434293b2069662074686579206172652077726f6e672c20746865207472616e73616374696f6e20697320696e76616c696408400000000000000000847635207472616e73616374696f6e20285a495020323235292c207472616e73706172656e7420696e70757473c2b76f757470757473206f6e6c790a6e4c6f636b54696d65203020c2b72073657175656e636520307846464646464646460a534947484153485f414c4c20285a495020323434290a53706563696669656420616d6f756e7400015a05000000006141207472616e73706172656e742073656e64206d616b6573207468652073656e64696e672061646472657373c2b7726563697069656e742061646472657373c2b7616d6f756e74207075626c6963206f6e2074686520626c6f636b636861696e2e",
        "25798a1dc8aedf4457be02839e81dbf934efddd395da1a72df48f22082e4312a",
        "89423e65ecae0de61c417a5a59fdc48e7a123d87f9d6e31b1b9b012f7b2d37cb",
    ),
    (
        "EN_HYPERCORE",
        "595744535030303400010201000000003d5b4879706572436f726520746573746e65745d204879706572436f7265207472616e736665723a2053656e64205553444320284879706572436f7265290009000101000000000000000f596f75722057616c6c657420617070000201000000000000005648797065726c6971756964204879706572436f726520746573746e657420287369676e6564207769746820636861696e49642034323136313420c2b72068797065726c6971756964436861696e20546573746e657429000301000000000000002a307839383538456646443233324234303333453437643930303033443431454333344563614564613934070101000000000000002453656e64205553444320284879706572436f7265290a28747970652075736453656e6429070201000000000000002a307836466163344431386339313233343342463836666137303439333634446434453432344162394330070301000000000000000631205553444307040100000000000000234e6f6e6520284879706572436f726520757365722d7369676e656420616374696f6e290705000000000000000025313739313338313231363030302028756e6978206d732c207369676e696e672074696d652907060000000000000002ad7b227479706573223a7b22454950373132446f6d61696e223a5b7b226e616d65223a226e616d65222c2274797065223a22737472696e67227d2c7b226e616d65223a2276657273696f6e222c2274797065223a22737472696e67227d2c7b226e616d65223a22636861696e4964222c2274797065223a2275696e74323536227d2c7b226e616d65223a22766572696679696e67436f6e7472616374222c2274797065223a2261646472657373227d5d2c2248797065726c69717569645472616e73616374696f6e3a55736453656e64223a5b7b226e616d65223a2268797065726c6971756964436861696e222c2274797065223a22737472696e67227d2c7b226e616d65223a2264657374696e6174696f6e222c2274797065223a22737472696e67227d2c7b226e616d65223a22616d6f756e74222c2274797065223a22737472696e67227d2c7b226e616d65223a2274696d65222c2274797065223a2275696e743634227d5d7d2c227072696d61727954797065223a2248797065726c69717569645472616e73616374696f6e3a55736453656e64222c22646f6d61696e223a7b226e616d65223a2248797065726c69717569645369676e5472616e73616374696f6e222c2276657273696f6e223a2231222c22636861696e4964223a3432313631342c22766572696679696e67436f6e7472616374223a22307830303030303030303030303030303030303030303030303030303030303030303030303030303030227d2c226d657373616765223a7b2268797065726c6971756964436861696e223a22546573746e6574222c2264657374696e6174696f6e223a22307836666163346431386339313233343362663836666137303439333634646434653432346162396330222c22616d6f756e74223a2231222c2274696d65223a313739313338313231363030307d7d00024802010000004554686520726563697069656e74206973206e6f7420696e20796f7572206164647265737320626f6f6b20e2809420636865636b207468652077686f6c6520616464726573734801000000006a4879706572436f726520757365722d7369676e656420616374696f6e20e28094206f6e6365207369676e65642c2048797065726c69717569642070726f63657373657320697420696d6d6564696174656c7920616e642069742063616e6e6f7420626520756e646f6e65",
        "4ae22c8aa92e52243e486c305913ea715349d771d45c2f463b1e7264f404520c",
        "ad9bf76ed3c4169d1162406b7f4cfda5f787bda5d2f2227dd2199ef0bd6e8d0d",
    ),
];

#[test]
fn v14_every_approval_kind() -> TestResult {
    let mut used = Vec::new();
    for lang in [Lang::Ko, Lang::En] {
        for case in kind_cases(lang)? {
            let name = golden_name(lang, case.name);
            assert_eq!(case.draft.display.lang, lang, "{name}");
            assert_eq!(case.draft.kind as u8, case.kind, "{name}");
            if lang == Lang::En {
                assert!(has_no_hangul(&case.draft.display), "{name}");
            }
            let request = issue(case.draft.clone())?;
            assert_eq!(request.created_unix_ms, CREATED_UNIX_MS);
            assert_eq!(request.expires_unix_ms, EXPIRES_UNIX_MS);
            let bytes = request.display.bytes()?;
            check_display_bytes(&request, &bytes)?;
            let display_digest = independent_display_digest(&bytes)?;
            assert_eq!(display_digest, request.display.digest()?, "{name}");
            let approval = independent_kind_digest(&case, display_digest)?;
            assert_eq!(approval, request.digest, "{name}");
            assert_eq!(request.payload.digest_bytes(), case.payload, "{name}");
            let golden = KIND_GOLDENS
                .iter()
                .find(|row| row.0 == name)
                .ok_or_else(|| format!("no golden {name}"))?;
            assert_eq!(hex::encode(&bytes), golden.1, "{name}");
            assert_eq!(hex::encode(&display_digest), golden.2, "{name}");
            assert_eq!(hex::encode(&approval), golden.3, "{name}");
            used.push(name);
        }
    }
    assert_eq!(used.len(), KIND_GOLDENS.len(), "every row is used once");
    Ok(())
}

/// The golden that pins each `ApprovalKind` (exhaustive: a new kind does not compile without one).
const fn kind_golden(kind: ApprovalKind) -> &'static str {
    match kind {
        ApprovalKind::EvmTransaction => "TAG1",
        ApprovalKind::EvmSpeedUp => "SPEED_UP",
        ApprovalKind::EvmCancel => "CANCEL",
        ApprovalKind::EvmPersonalSign => "TAG0",
        ApprovalKind::EvmTypedData => "TYPED",
        ApprovalKind::SolTransfer => "SOL_TRANSFER",
        ApprovalKind::SolMessage => "SOL_MESSAGE",
        ApprovalKind::SolSignIn => "SOL_SIGN_IN",
        ApprovalKind::SolTransaction => "SOL_TX",
        ApprovalKind::BtcSend => "BTC_SEND",
        ApprovalKind::BtcFeeBump => "BTC_FEE_BUMP",
        ApprovalKind::BtcMessage => "BTC_MESSAGE",
        ApprovalKind::ZecSend => "ZEC_SEND",
        ApprovalKind::HyperCoreAction => "HYPERCORE",
    }
}

/// No approval kind is left without a golden in either language.
#[test]
fn every_approval_kind_has_a_golden() -> TestResult {
    let kinds = [
        ApprovalKind::EvmTransaction,
        ApprovalKind::EvmSpeedUp,
        ApprovalKind::EvmCancel,
        ApprovalKind::EvmPersonalSign,
        ApprovalKind::EvmTypedData,
        ApprovalKind::SolTransfer,
        ApprovalKind::SolMessage,
        ApprovalKind::SolSignIn,
        ApprovalKind::SolTransaction,
        ApprovalKind::BtcSend,
        ApprovalKind::BtcFeeBump,
        ApprovalKind::BtcMessage,
        ApprovalKind::ZecSend,
        ApprovalKind::HyperCoreAction,
    ];
    for kind in kinds {
        let name = kind_golden(kind);
        if matches!(name, "TAG1" | "TAG0") {
            continue; // the earlier V14 goldens above
        }
        for lang in [Lang::Ko, Lang::En] {
            let full = golden_name(lang, name);
            assert!(KIND_GOLDENS.iter().any(|row| row.0 == full), "{full}");
            assert!(
                kind_cases(lang)?
                    .iter()
                    .any(|case| case.name == name && case.draft.kind == kind),
                "{full}"
            );
        }
    }
    Ok(())
}

/// spec/13 §7: a `WalletConnect` request is shown with the peer's label and its Verify warning.
/// The issued decorated request is not `stable_equal` to the undecorated draft the worker
/// re-simulates, and is again once that draft is decorated the same way — what
/// `App::on_resimulated` relies on (`app_approval.rs` 2026-11-18).
#[test]
fn v14_walletconnect_decorated_send() -> TestResult {
    for lang in [Lang::Ko, Lang::En] {
        let (decorated, undecorated, _) = walletconnect_drafts(lang)?;
        let issued = issue(decorated)?;
        assert!(!stable_equal(&issued, &undecorated));
        let mut again = undecorated.clone();
        let peer = Metadata {
            name: "Example dApp".to_owned(),
            description: String::new(),
            url: "https://app.example".to_owned(),
            icons: Vec::new(),
        };
        assert!(decorate(&mut again, &peer, VerifyStatus::Unknown));
        assert!(stable_equal(&issued, &again));
        // A different Verify result is a different display.
        let mut other = undecorated;
        assert!(decorate(&mut other, &peer, VerifyStatus::Invalid));
        assert!(!stable_equal(&issued, &other));
    }
    Ok(())
}
