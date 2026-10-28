//! V14 approval goldens (spec/09 §3.13, spec/03 EVM-V14): one golden per `SimulationBinding` tag,
//! each pinned as display bytes (`YWDSP003…`), display digest and approval digest.
//!
//! Recording procedure (same as vault G1): `print_v14_goldens` (`--ignored --exact`) prints the
//! values; they were pinned in the commit where the independent checks below — which re-read the
//! display bytes with the spec/03 §11.3 layout and rebuild the §6.5/§11.3/§11.4 transcripts
//! without the approval module — passed. A change means the display or digest format changed.

use yw_app::rpc::evm::parse_simulate_response;
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
use yw_core::policy::BrowserOrigin;
use yw_core::vault::EvmKeySource;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const ID: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
const CREATED_UNIX_MS: u64 = 1_791_381_216_000;
const EXPIRES_UNIX_MS: u64 = 1_791_381_336_000;
const ACC1: &str = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";

const TAG1_DISPLAY: &str = "5957445350303033000100000000003c5b5365706f6c696120ed858cec8aa4ed8ab8eb84b75d205365706f6c696145544820ebb3b4eb82b4eab8b03a20302e3031205365706f6c6961455448000e0001010000000000000018596f75722057616c6c657420ec95b1202879772d6170702900020100000000000000275365706f6c696120ed858cec8aa4ed8ab8eb84b72028636861696e49642031313135353131312900030100000000000000333078393835382045664644203233324220343033332045343764203930303020334434312045433334204563614520646139340101010000000000000033307846323738206346353920463832652044636638203731643620333046322038456343203830353620663235432031636462010201000000000000000f302e3031205365706f6c696145544801030100000000000000145365706f6c696145544820ebb3b4eb82b4eab8b0011001000000000000000f302e3031205365706f6c69614554480120010000000000000015302e3030303439313034205365706f6c69614554480121020000000000000015302e3030303232353036205365706f6c6961455448012200000000000000001d6d61784665652032206777656920c2b72074697020302e31206777656901230000000000000000073234352c353230012400000000000000000130013002000000000000002cebb894eba19d2031302c3039322c35343420c2b720323032362d31302d30372031333a35333a3336205554430141000000000000000013ec9786ec9d8c202830ebb094ec9db4ed8ab8290001451c000000002aeca3bcec868ceba19dec979020ec9786eb8a9420ebb09beb8a9420eca3bcec868cec9e85eb8b88eb8ba4";
const TAG1_DISPLAY_DIGEST: &str =
    "7ecc0136cfe75717c79306aa1ca49660e8e471622e73352483c4ab0eeb03688a";
const TAG1_APPROVAL_DIGEST: &str =
    "9d2dbcb843c83da6d377d0e5722cae7cf336e97bb2bd30ebbcb2c0517ea0bb48";
const TAG2_DISPLAY: &str = "5957445350303033000102010000003c5b5365706f6c696120ed858cec8aa4ed8ab8eb84b75d205365706f6c696145544820ebb3b4eb82b4eab8b03a20302e3031205365706f6c6961455448000d0001010000000000000018596f75722057616c6c657420ec95b1202879772d6170702900020100000000000000275365706f6c696120ed858cec8aa4ed8ab8eb84b72028636861696e49642031313135353131312900030100000000000000333078393835382045664644203233324220343033332045343764203930303020334434312045433334204563614520646139340101010000000000000033307846323738206346353920463832652044636638203731643620333046322038456343203830353620663235432031636462010201000000000000000f302e3031205365706f6c696145544801030100000000000000145365706f6c696145544820ebb3b4eb82b4eab8b00120010000000000000015302e3030303439313034205365706f6c6961455448012102000000000000000eec958c20ec889820ec9786ec9d8c012200000000000000001d6d61784665652032206777656920c2b72074697020302e31206777656901230000000000000000073234352c353230012400000000000000000130013002000000000000005dec8b9cebaeaceba088ec9db4ec859820ec9786ec9d8c3a20ec9e94ec95a1ec9db420ebb3b4eb82bc20eab888ec95a1eab3bc20ecb59ceb8c8020ec8898ec8898eba38cec9d9820ed95a9ebb3b4eb8ba420eca081ec8ab5eb8b88eb8ba40141000000000000000013ec9786ec9d8c202830ebb094ec9db4ed8ab829000245010200000093ec8b9cebaeaceba088ec9db4ec859820eab2b0eab3bc20ec9786ec9d8c20e2809420ec8ba4eca09c20ed9aa8eab3bceba5bc20ed9995ec9db8ed95a020ec889820ec9786ec8ab5eb8b88eb8ba40aec9e94ec95a1ec9db420ebb3b4eb82bc20eab888ec95a1eab3bc20ecb59ceb8c8020ec8898ec8898eba38cec9d9820ed95a9ebb3b4eb8ba420eca081ec8ab5eb8b88eb8ba4451c000000002aeca3bcec868ceba19dec979020ec9786eb8a9420ebb09beb8a9420eca3bcec868cec9e85eb8b88eb8ba4";
const TAG2_DISPLAY_DIGEST: &str =
    "a86e9f1a4d3efcb39ce5668767c204db8923a326cf73e29b01a2b11f22054ad3";
const TAG2_APPROVAL_DIGEST: &str =
    "2505c36a29cb23195504a10e676cffaae5b3123dc6c0b959a26e53f8d42ea701";
const TAG0_DISPLAY: &str = "595744535030303300010000000000275b5365706f6c696120ed858cec8aa4ed8ab8eb84b75d20eba994ec8b9ceca78020ec849cebaa850005000101000000000000001368747470733a2f2f6170702e6578616d706c6500020100000000000000275365706f6c696120ed858cec8aa4ed8ab8eb84b72028636861696e49642031313135353131312900030100000000000000333078393835382045664644203233324220343033332045343764203930303020334434312045433334204563614520646139340401010000000000000009536f6d652064617461040300000000000000000a39ebb094ec9db4ed8ab8000150030000000017eba994ec8b9ceca78020ec849cebaa8520ec9a94ecb2ad";
const TAG0_DISPLAY_DIGEST: &str =
    "8fb98192b47cc0c506c61f6cbbb0fe6bbc24e35679b773534f2da0ac7b88b2e2";
const TAG0_APPROVAL_DIGEST: &str =
    "f62260be7e207ff9ffee73de40abb00676c39af016a23b24828cda76ac15f5c3";

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

fn tx_draft(outcome: &SimOutcome) -> TestResult<ApprovalDraft> {
    let chain = sepolia();
    let tx = s2_tx()?;
    let user = parse_address(ACC1)?;
    let sim = interpret(&chain, &tx, &user, outcome, CREATED_UNIX_MS);
    let decoded = DecodedTx {
        call: decode_call(&chain, &tx.to, &tx.data),
        tx,
    };
    Ok(build_evm_tx_request(
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

fn tag1() -> TestResult<ApprovalDraft> {
    tx_draft(&parse_simulate_response(
        include_bytes!("fixtures/eth_simulateV1/S2.response.json"),
        1,
    ))
}

fn tag2() -> TestResult<ApprovalDraft> {
    tx_draft(&parse_simulate_response(
        include_bytes!("fixtures/eth_simulateV1/S4.response.json"),
        1,
    ))
}

fn tag0() -> TestResult<ApprovalDraft> {
    let origin = BrowserOrigin::parse("https://app.example").ok_or("origin")?;
    Ok(build_personal_request(
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
    assert_eq!(reader.take(8)?, b"YWDSP003");
    assert_eq!(reader.u16()?, 1);
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
    let draft = tag1()?;
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
    let draft = tag2()?;
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
    let draft = tag0()?;
    let payload = b"\x19Ethereum Signed Message:\n9Some data";
    check(
        draft,
        "https://app.example",
        payload,
        &Tag::NotApplicable,
        (TAG0_DISPLAY, TAG0_DISPLAY_DIGEST, TAG0_APPROVAL_DIGEST),
    )
}

#[test]
#[ignore = "prints the V14 golden values for recording"]
#[expect(clippy::print_stdout, reason = "golden recording")]
fn print_v14_goldens() -> TestResult {
    for (name, draft) in [("TAG1", tag1()?), ("TAG2", tag2()?), ("TAG0", tag0()?)] {
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
    Ok(())
}
