//! Rule table (spec/03 §10.2–§10.4): identifiers, levels and fixed base texts.

use crate::approval::{RiskLevel, RuleId, Warning};

macro_rules! rules {
    ($($name:ident = $family:literal $number:literal, $level:ident, $text:literal;)*) => {
        $(
            #[doc = concat!("Rule `", stringify!($name), "`.")]
            pub const $name: RuleId = RuleId::new($family, $number);
        )*

        /// The rule's level, `None` for an unknown rule.
        #[must_use]
        pub fn level_of(rule: RuleId) -> Option<RiskLevel> {
            $(if rule == $name { return Some(RiskLevel::$level); })*
            None
        }

        /// The rule's fixed base text, `None` for an unknown rule.
        #[must_use]
        pub fn base_text(rule: RuleId) -> Option<&'static str> {
            $(if rule == $name { return Some($text); })*
            None
        }
    };
}

rules! {
    E01 = b'E' 1, High, "시뮬레이션 결과 없음 — 실제 효과를 확인할 수 없습니다";
    E02 = b'E' 2, High, "시뮬레이션에서 거래가 실패했습니다 — 수수료만 잃을 수 있습니다";
    E03 = b'E' 3, High, "시뮬레이션 결과가 불완전합니다";
    E04 = b'E' 4, High, "시뮬레이션 결과가 불완전합니다";
    E05 = b'E' 5, Blocked, "수수료가 상한을 넘습니다";
    E06 = b'E' 6, Blocked, "진행 중인 거래가 있습니다";
    E07 = b'E' 7, High, "시뮬레이션 결과가 불완전합니다";
    E08 = b'E' 8, High, "시뮬레이션 결과가 불완전합니다";
    E09 = b'E' 9, High, "시뮬레이션 결과가 불완전합니다";
    E10 = b'E' 10, Blocked, "가스 추정값이 거래 가스 상한(16,777,216)을 넘습니다";
    E11 = b'E' 11, Blocked, "서명할 거래가 너무 큽니다(131,072바이트 초과)";
    E12 = b'E' 12, High, "해석되지 않은 컨트랙트 호출";
    E13 = b'E' 13, High, "해석한 호출 내용이 시뮬레이션 결과로 확인되지 않습니다";
    E14 = b'E' 14, High, "무제한 승인";
    E15 = b'E' 15, High, "컬렉션 전체 권한 부여";
    E16 = b'E' 16, High, "승인 대상이 일반 계정(EOA) 또는 위임된 계정입니다";
    E17 = b'E' 17, High, "서명 계정에 코드가 있습니다(EIP-7702 위임 포함)";
    E18 = b'E' 18, High, "0 주소 또는 토큰 컨트랙트 자신에게 보내는 이동입니다";
    E19 = b'E' 19, High, "등록되지 않은 토큰이 알려진 심볼을 사용합니다";
    E20 = b'E' 20, Caution, "토큰 사용 승인";
    E21 = b'E' 21, Caution, "승인 대상이 등록되지 않은 컨트랙트입니다";
    E22 = b'E' 22, Caution, "Permit2 승인 만료가 30일을 넘거나 만료가 없습니다";
    E23 = b'E' 23, Caution, "보내는 자산만 있고 받는 자산이 없습니다";
    E24 = b'E' 24, Caution, "자기 자신에게 보내는 호출에 데이터가 있습니다";
    E25 = b'E' 25, Caution, "토큰 소수 자릿수를 확인할 수 없어 원시 단위로 표시합니다";
    E26 = b'E' 26, Caution, "토큰 심볼을 읽을 수 없습니다";
    E27 = b'E' 27, Caution, "조회 한도를 넘어 일부 정보를 원시 값으로 표시합니다";
    E28 = b'E' 28, Info, "주소록에 없는 받는 주소입니다";
    E29 = b'E' 29, Info, "받는 주소가 컨트랙트입니다";
    E30 = b'E' 30, Info, "승인 해제";
    E31 = b'E' 31, Info, "dApp이 보낸 수수료 값은 무시하고 지갑이 계산한 수수료를 씁니다";
    E32 = b'E' 32, Info, "기타 이벤트";
    E33 = b'E' 33, Info, "등록되지 않은 토큰 (미확인)";
    E34 = b'E' 34, Blocked, "RPC 체인 불일치";
    E35 = b'E' 35, Blocked, "거래를 준비할 수 없음";
    E36 = b'E' 36, High, "시뮬레이션 미지원 체인 — 실제 효과를 확인할 수 없습니다";
    E37 = b'E' 37, High, "가스 추정 실패 — 거래가 실패할 수 있습니다";
    E38 = b'E' 38, Caution, "HyperEVM 작은 블록 한도를 넘는 거래입니다 — 계정에 큰 블록 사용이 켜져 있지 않으면 포함되지 않을 수 있습니다";
    E39 = b'E' 39, High, "승인 대상의 계정 종류를 확인할 수 없습니다(조회 실패)";
    E40 = b'E' 40, High, "내 자산을 보내고 받는 것은 등록되지 않은 토큰·NFT입니다 — 가짜 자산일 수 있습니다";
    E41 = b'E' 41, Caution, "L1 데이터 수수료를 확인하지 못했습니다 — 최대 수수료에 L1 수수료가 빠져 있습니다";
    E42 = b'E' 42, High, "보내려는 금액보다 많은 자산이 빠져나갑니다 — 자산을 빼가는 거래일 수 있습니다";
    T01 = b'T' 1, Blocked, "typed data의 chainId가 현재 체인과 다릅니다";
    T02 = b'T' 2, Blocked, "typed data 형식이 올바르지 않습니다";
    T03 = b'T' 3, High, "도메인에 chainId가 없습니다 — 다른 체인에서도 쓰일 수 있습니다";
    T04 = b'T' 4, High, "알 수 없는 형식의 서명 요청입니다";
    T05 = b'T' 5, High, "토큰 사용 허가(permit) 서명입니다 — 서명만으로 토큰을 가져갈 수 있습니다";
    T06 = b'T' 6, High, "Permit2 즉시 이체 서명(조건 포함)입니다 — 조건 내용은 해석하지 않았습니다";
    T07 = b'T' 7, High, "소유자가 서명 계정과 다릅니다";
    T08 = b'T' 8, High, "이 주문에서 내가 받는 것이 없습니다";
    T09 = b'T' 9, High, "spender가 일반 계정(EOA) 또는 위임된 계정입니다";
    T10 = b'T' 10, Caution, "verifyingContract가 없거나 0 주소입니다";
    T11 = b'T' 11, Caution, "verifyingContract가 일반 계정(EOA)입니다";
    T12 = b'T' 12, Caution, "기한이 이미 지났거나 30일을 넘거나 만료가 없습니다";
    T13 = b'T' 13, Caution, "서명 유효 기간이 깁니다";
    T14 = b'T' 14, Caution, "컬렉션의 아무 토큰이나 대상이 되는 주문이거나 CONTRACT 주문입니다";
    T15 = b'T' 15, Info, "DAI 사용 허가 해제";
    T16 = b'T' 16, Blocked, "표시 한도를 넘는 typed data입니다";
    T17 = b'T' 17, Caution, "숨은 문자 또는 방향 제어 문자가 있습니다";
    T18 = b'T' 18, High, "spender의 계정 종류를 확인할 수 없습니다(조회 실패)";
    T19 = b'T' 19, High, "내 자산을 내놓는 마켓 주문입니다 — 서명만으로 주문이 체결될 수 있습니다";
    T20 = b'T' 20, High, "등록되지 않은 토큰이 알려진 심볼을 사용합니다";
    P01 = b'P' 1, High, "UTF-8 텍스트가 아닌 메시지입니다 — hex로 표시합니다";
    P02 = b'P' 2, Caution, "숨은 문자 또는 방향 제어 문자가 있습니다";
    P03 = b'P' 3, Info, "메시지 서명 요청";
    P04 = b'P' 4, High, "텍스트로 보기 어려운 메시지입니다 — hex로 표시합니다";
    S01 = b'S' 1, Blocked, "SIWE 도메인이 요청 사이트와 다릅니다";
    S02 = b'S' 2, Blocked, "SIWE scheme이 요청 사이트와 다르거나 사용자 정보가 있습니다";
    S03 = b'S' 3, Blocked, "SIWE 주소가 서명 계정과 다르거나 체크섬이 틀립니다";
    S04 = b'S' 4, Blocked, "SIWE 메시지가 만료되었습니다";
    S05 = b'S' 5, Caution, "SIWE 도메인의 포트가 요청 사이트와 다릅니다";
    S06 = b'S' 6, Caution, "SIWE Chain ID가 현재 체인과 다릅니다";
    S07 = b'S' 7, Caution, "SIWE 메시지가 아직 유효하지 않습니다(Not Before)";
    S08 = b'S' 8, High, "SIWE 형식처럼 보이지만 형식이 올바르지 않습니다";
    S09 = b'S' 9, Info, "로그인 요청 (SIWE)";
    M01 = b'M' 1, Blocked, "Solana 거래로 해석되는 바이트입니다 — 메시지 서명으로 거래에 서명할 수 없습니다";
    M02 = b'M' 2, Blocked, "Solana 오프체인 메시지 머리글이 있지만 형식이 올바르지 않습니다";
    M03 = b'M' 3, Blocked, "Bitcoin 거래 또는 PSBT로 해석되는 바이트입니다 — 메시지 서명으로 거래에 서명할 수 없습니다";
    M04 = b'M' 4, Info, "소유 증명용 메시지 서명입니다 — 거래·송금에는 쓰이지 않습니다";
    M05 = b'M' 5, Info, "Solana 오프체인 메시지(v0)입니다";
    W01 = b'W' 1, Blocked, "SIWS 도메인이 요청 사이트와 다릅니다";
    W02 = b'W' 2, Blocked, "SIWS 주소가 서명 계정과 다릅니다";
    W03 = b'W' 3, Blocked, "SIWS Chain ID가 현재 Solana 클러스터와 다릅니다";
    W04 = b'W' 4, Blocked, "SIWS 메시지가 만료되었습니다";
    W05 = b'W' 5, Caution, "SIWS 메시지가 아직 유효하지 않습니다(Not Before)";
    W06 = b'W' 6, High, "SIWS 발급 시각이 현재 시각과 10분 넘게 다릅니다";
    W07 = b'W' 7, Blocked, "SIWS 형식이 올바르지 않습니다";
    W08 = b'W' 8, Info, "로그인 요청 (SIWS)";
    H01 = b'H' 1, Info, "HyperCore 사용자 서명 작업입니다 — 서명하면 Hyperliquid가 바로 처리하며 되돌릴 수 없습니다";
    H02 = b'H' 2, Caution, "받는 주소가 주소록에 없습니다 — 주소 전체를 확인하세요";
    H03 = b'H' 3, High, "알고 있는 주소와 앞뒤가 같지만 다른 주소입니다 — 주소 오염 공격일 수 있습니다";
    H04 = b'H' 4, Info, "HyperEVM으로 이동합니다 — HyperEVM의 같은 주소로 들어갑니다";
    H05 = b'H' 5, Info, "Arbitrum 출금에는 고정 수수료 1 USDC가 듭니다(약 5분 걸림)";
    H06 = b'H' 6, High, "Hyperliquid 거래 권한 위임(API 지갑 승인)입니다 — 승인한 주소가 내 계정으로 주문·취소를 할 수 있습니다";
    H07 = b'H' 7, High, "Hyperliquid 주문·거래 서명(L1 action)입니다 — 지갑은 서명 내용(해시)을 해석할 수 없고, 이 지갑은 거래 기능을 지원하지 않습니다";
    H08 = b'H' 8, High, "Hyperliquid 빌더 수수료 승인입니다 — 승인한 주소가 내 주문에 수수료를 붙일 수 있습니다";
    H09 = b'H' 9, Caution, "hyperliquidChain이 Testnet입니다 — 테스트넷 작업입니다";
    H10 = b'H' 10, High, "사이트가 요청한 HyperCore 전송의 받는 주소가 내 계정도, 주소록에 있는 주소도 아닙니다 — 되돌릴 수 없으니 주소 전체를 확인하세요";
    H11 = b'H' 11, High, "사이트가 요청한 Arbitrum 출금(withdraw3)의 받는 주소가 서명 계정이 아닙니다 — 다른 사람에게 출금될 수 있습니다";
    H12 = b'H' 12, High, "토큰 이름과 tokenId가 spotMeta와 맞지 않거나 spotMeta를 확인할 수 없습니다 — 다른 토큰일 수 있습니다";
    H13 = b'H' 13, High, "HyperEVM 시스템 주소로 보내지만 이 토큰의 시스템 주소가 아니거나 HyperEVM에 연결되지 않은 토큰입니다 — 자산을 잃을 수 있습니다";
    C01 = b'C' 1, Caution, "WalletConnect 요청입니다 — 사이트 주소는 사이트가 스스로 주장한 값이며 확인되지 않았습니다";
    C02 = b'C' 2, High, "WalletConnect Verify 결과 사이트가 주장한 주소와 실제 주소가 다릅니다 — 피싱일 수 있습니다";
    C03 = b'C' 3, High, "WalletConnect Verify가 이 사이트를 알려진 사기 사이트로 표시했습니다";
    C04 = b'C' 4, Info, "WalletConnect 요청 — Verify로 사이트 주소가 확인되었습니다";
}

/// Simulation-status rules shown first within their level (spec/03 §10.1, D15).
#[must_use]
pub fn is_simulation_status(rule: RuleId) -> bool {
    [E01, E02, E03, E04, E07, E08, E09, E36, E37].contains(&rule)
}

/// A warning with the rule's base text and an optional cause line (`base ‖ LF ‖ cause`).
#[must_use]
pub fn warning(rule: RuleId, cause: Option<&str>) -> Warning {
    let level = level_of(rule).unwrap_or(RiskLevel::High);
    let mut text = base_text(rule).unwrap_or("").to_owned();
    if let Some(cause) = cause {
        text.push('\n');
        text.push_str(cause);
    }
    Warning { rule, level, text }
}

/// A warning whose whole text replaces the base text (E32 "기타 이벤트 N개", E38 with the limit).
#[must_use]
pub fn warning_text(rule: RuleId, text: String) -> Warning {
    Warning {
        rule,
        level: level_of(rule).unwrap_or(RiskLevel::High),
        text,
    }
}

/// Orders warnings: level descending, simulation-status rules first within a level, then by
/// rule id; exact duplicates are removed (spec/03 §10.1).
pub fn sort_warnings(warnings: &mut Vec<Warning>) {
    warnings.sort_by(|a, b| {
        b.level
            .cmp(&a.level)
            .then_with(|| is_simulation_status(b.rule).cmp(&is_simulation_status(a.rule)))
            .then_with(|| a.rule.cmp(&b.rule))
            .then_with(|| a.text.cmp(&b.text))
    });
    warnings.dedup();
}

/// Request level = maximum warning level (Info without warnings); `ack_required = (risk == High)`.
#[must_use]
pub fn request_risk(warnings: &[Warning]) -> (RiskLevel, bool) {
    let risk = warnings
        .iter()
        .map(|warning| warning.level)
        .max()
        .unwrap_or(RiskLevel::Info);
    (risk, risk == RiskLevel::High)
}
