# YubiKey 계정 (선택 기능)

상위 문서: [spec.md](../spec.md)

- 상태: **명세 2026-11-04 · 코어 구현(yw-core `yubikey`, vault tag 5, yw-win PC/SC·CNG) · 앱 연결(계정·PIN 창·카드 서명)·등록 마법사·YubiKey 지갑 2026-11-05 · Zcash 슬롯·슬롯 구성 바꾸기·YubiKey 비우기 2026-11-06(§3.1, §15) · 복구 단어 없이 연결(경로 모름 슬롯) 2026-11-07(§7.6), 남은 작업은 §13** — 실제 YubiKey 확인은 [docs/acceptance/yubikey-20261104.md](../docs/acceptance/yubikey-20261104.md)(사용자가 수행).
- 범위: 니모닉에서 고른 키를 한 번 파생해 하나 이상의 YubiKey 5(펌웨어 5.7 이상 권장, OpenPGP만 쓰면 5.2.3 이상)에 **가져오기(import)** 하고, 그 뒤로는 PC가 그 계정의 비밀을 전혀 갖지 않은 채(공개키·주소·일련번호·슬롯 표만) YubiKey에서 PIN + 터치로 서명한다. 니모닉 자체가 종이 백업이다. 같은 키를 여러 YubiKey에 넣어 서로의 백업으로 쓸 수 있다.
- 기존 소프트웨어 vault 경로([02](02-core-keys-vault.md)·[03](03-evm.md)·[07](07-solana.md)·[08](08-bitcoin.md))는 바뀌지 않는다. 이 문서는 **추가**만 한다: vault payload의 새 tag 5(§8), 새 모듈 `yw_core::yubikey`·`yw_win::pcsc`·`yw_win::cng`(§4), 승인 후 서명 단계의 카드 분기(§10).
- 규범 용어는 spec.md와 같다(MUST/반드시, SHOULD/권고, MAY/선택). 바이트 값의 출처는 §14.

## 1. 위협 모델 변화 (spec.md §2에 대한 차이)

| 항목 | 소프트웨어 계정 | YubiKey 계정 |
|---|---|---|
| 서명 순간 PC 메모리의 개인키 | 서명마다 복호화·파생 후 소거(D10) | **없음.** 개인키는 카드 밖으로 나오지 않는다(가져온 키도 내보낼 수 없음, §14 [Y-EXP]) |
| 디스크(vault) 도난 + 비밀번호 추측 | 니모닉·개인키 노출 | 공개키·슬롯 표만 노출(자산 이동 불가, 주소 연결성만) |
| 같은 사용자 권한의 악성코드(§2.2 비목표) | 즉시 전부 탈취 | 키 탈취는 불가. PIN은 키 입력을 가로채 알 수 있으므로 **터치가 마지막 방어선**이다: 터치 정책 "항상"이면 악성코드가 몰래 서명하려 해도 사용자가 카드를 만져야 한다. 단, 사용자가 승인한 서명의 **내용을 바꿔 터치를 받아내는 공격**(표시는 PC가 하므로)은 막지 못한다 — 아래 "표시 무결성" |
| 표시 무결성 | PC 승인 창 | **변화 없음: 여전히 PC 승인 창이 유일한 표시다.** YubiKey는 화면이 없어 무엇에 서명하는지 보여주지 않는다. 장악된 PC는 다른 digest를 카드에 보낼 수 있다. YubiKey는 "키가 PC 밖에 있음"을 주지 "PC를 믿지 않아도 됨"을 주지 않는다 |
| 니모닉 | vault에 암호화 저장 | **PC에 저장하지 않는다**(등록 중 한 번 입력·파생 후 소거, §7). 종이 백업만 있다. 기존 지갑의 니모닉과 같은 니모닉으로 등록하면 PC에 그 니모닉이 이미 있으므로 보안 이득이 없다 — 마법사가 경고한다(§7.1) |
| 카드 분실 | — | 다른 백업 YubiKey 또는 니모닉으로 재등록(§7.5). 분실 카드는 PIN 3회 오류로 잠기므로(PIN 추측 3회) 즉시 자산 위험은 아니지만 **새 니모닉으로 옮기는 것은 사용자 판단**이다 |

권고(체크리스트, 코드 게이트 아님):

- 터치 정책 기본값은 **항상**(OpenPGP UIF `01`, PIV `02`; 나중에 바꿀 수 있음)이다(사용자 결정 2026-11-05). **고정**(UIF `02`/`04`)은 명시적 선택지다: 관리자 PIN을 아는 악성코드도 터치를 끌 수 없게 하지만, 바꾸려면 OpenPGP 애플릿 초기화 + 재등록이 필요하다. Bitcoin 다중 입력 거래가 잦으면 BTC 슬롯만 **15초 유지**(UIF `03`/`04`, PIV `03`)를 고를 수 있다 — 대신 그 15초 동안은 터치 없이 추가 서명이 가능하다.
- 기본 PIN·관리자 PIN·PIV 관리 키는 등록 직후 바꾼다(§9.3).
- 여러 YubiKey에 같은 키를 넣어 두면 하나를 잃어도 서명할 수 있다. 니모닉 종이 백업은 별도 장소에 둔다.

## 2. 지원 범위와 펌웨어

| 기능 | 애플릿 | 알고리즘 | 펌웨어 | 근거 |
|---|---|---|---|---|
| secp256k1 서명 키 가져오기·서명 | OpenPGP 3.4 (SIG `B6`, AUT `A4`) | ECDSA secp256k1 (OID 1.3.132.0.10) | 5.2.3+ | [Y-523], [Y-PGP], [KIT-PGP] |
| Ed25519 키 가져오기·서명 | PIV (`9A`·`9C`·`9D`·`9E`·`82`–`95`) | Ed25519 (alg `E0`) | 문서상 **5.7.4+**(Yubico 매뉴얼 "as of 5.7.4"; yubikit은 5.7.0으로 판정). 사용자 결정(2026-11-05): 5.7.4 이상이면 그대로, 5.7.0–5.7.3이면 마법사가 경고한 뒤 시도하고 카드가 거부하면(`6A80`·미지원) `Ed25519ImportRefused`로 "이 펌웨어는 Ed25519 가져오기를 거부했습니다 — 5.7.4 이상 필요"를 보인다. 5.7.0 미만은 PIV 슬롯을 고를 수 없다. 실제 펌웨어는 사용자가 Y-03에서 기록 | [Y-57], [KIT-PIV] |
| PIV 메타데이터(GET METADATA) | PIV | — | 5.3+ | [KIT-PIV] |
| PIV 일련번호(GET SERIAL) | PIV | — | 5.0.3+ | [KIT-PIV] |
| 터치 15초 유지(OpenPGP UIF `03`/`04`) | OpenPGP | — | 5.2.1+ | [KIT-PGP] |
| PIV 관리 키 기본값 AES-192 | PIV | `0A` | 5.7+ (이전 3DES `03`) | [Y-PIVM] |

- **PIV에는 secp256k1이 없다**(P-256·P-384·RSA·Ed25519·X25519뿐, [KIT-PIV] `KEY_TYPE`). 그래서 EVM·Bitcoin 키는 OpenPGP에만 넣을 수 있고, OpenPGP의 서명 가능한 슬롯은 SIG·AUT 두 개뿐이다(DEC `B8`은 복호 전용) → **YubiKey 하나에 secp256k1 키 최대 2개.** 더 많은 EVM/BTC 키는 YubiKey를 더 쓰거나(§3.4) 인덱스를 나눠 등록한다.
- **BIP340 Schnorr가 없다**(어느 애플릿에도 없음) → 탭루트(P2TR) 키는 YubiKey에 둘 수 없다.
- OpenPGP KDF-DO(`F9`)가 켜진 카드(PIN을 해시해서 VERIFY하는 설정)는 v1에서 지원하지 않는다(`KdfEnabled`, §11).
- YubiKey 4 이하, NEO, Security Key 시리즈는 대상이 아니다.

## 3. 슬롯 계획

### 3.1 역할과 경로

| 역할 (`plan::KeyRole`) | 곡선 | 파생 경로 | 들어가는 슬롯 |
|---|---|---|---|
| EVM 계정 i (`Evm { index: i, btc: None }`) | secp256k1 | `m/44'/60'/0'/0/i` (D29와 같음) | OpenPGP SIG 또는 AUT |
| EVM 공유 키 (`Evm { index: i, btc: Some(형식, 네트워크) }`) | secp256k1 | `m/44'/60'/0'/0/i` — 같은 공개키를 Bitcoin 단일 주소로도 쓴다 | OpenPGP SIG 또는 AUT |
| Bitcoin 단일 주소 (`Btc { network, script, index: i }`) | secp256k1 | `m/{44\|49\|84}'/{0\|1}'/0'/0/i` — P2PKH 44, P2SH-P2WPKH 49, P2WPKH 84(기본), 메인넷 coin 0·testnet4 1 | OpenPGP SIG 또는 AUT |
| Solana 계정 i (`Sol { index: i }`) | Ed25519 | `m/44'/501'/i'/0'` (D25와 같음) | PIV `82`–`95`(보관 슬롯 20개), 원하면 `9A`·`9C`·`9D`·`9E` |
| Zcash 일반(transparent) 주소 i (`Zec { network, index: i }`, 2026-11-06) | secp256k1 | `m/44'/133'/0'/0/i`(메인넷, `t1…`) / `m/44'/1'/0'/0/i`(테스트넷, `tm…`) — 계정 0의 받기 주소 인덱스, Bitcoin 단일 주소와 같은 규칙(§3.3) | OpenPGP SIG 또는 AUT |

- Zcash 역할(2026-11-06): 등록 마법사의 OpenPGP 슬롯 "넣을 키"에 `Zcash 주소`가 있다(Bitcoin 단일 주소처럼 OpenPGP secp256k1 슬롯만). 고르는 것은 주소 인덱스(0–999, 기본 0)와 네트워크(`메인넷 (t1…)` / `테스트넷 (tm…)`, 처음 값은 설정의 Bitcoin 네트워크를 따른다: testnet4면 테스트넷). 가져오기 전 확인 화면에 전체 경로와 `plan::zec_address`로 만든 `t1…`/`tm…` 주소가 나온다. record 코드는 role 4(§8). Zcash 계정의 목록·서명·보내기는 Zcash 앱([12])의 범위이고, 이 문서는 슬롯 계획·등록·record만 다룬다.
- 주의: 테스트넷 Zcash 경로 `m/44'/1'/0'/0/i`는 **Bitcoin testnet4 P2PKH 주소 i의 경로와 같다**(coin type 1'을 함께 쓴다) — 같은 키다. 그래서 한 YubiKey에 둘을 함께 넣으면 `DuplicatePath`, 다른 YubiKey에 있으면 백업 복사본 규칙(§3.4)이 적용된다. 메인넷(133')은 겹치지 않는다.

- **인덱스는 슬롯마다 사용자가 고른다**(고정값 없음). 마법사는 첫 YubiKey의 기본값으로 SIG = EVM 0, AUT = Bitcoin P2WPKH 0을 채워 두고(공유 키 방식이면 SIG = EVM 0, AUT = EVM 1), 다음 YubiKey에는 아직 쓰지 않은 다음 인덱스(예: 2·3, 4·5 …)를 제안한다. 인덱스 범위: EVM·Solana 0–999(`AccountIndex`), Bitcoin 0–999(`MAX_BTC_INDEX`) — 단 900–999는 복구 단어 없이 연결한 키(경로 모름)의 계정 번호 대역이라 복구 단어로 등록하는 마법사는 0–899만 받는다(2026-11-07, §7.6).
- 니모닉은 오프라인에 안전하게 보관되어 있고 언제든 다시 파생·재등록할 수 있다고 가정한다. 따라서 YubiKey N개(또는 백업 쌍 N개)로 같은 니모닉에서 secp256k1 키 N×2개를 쓸 수 있다.
- 마법사는 가져오기 **전에** 모든 슬롯의 전체 경로 문자열과 그 키의 주소(EVM 체크섬 주소, Bitcoin 주소, Solana base58; 공유 키는 둘 다)를 보여준다(`enrol::preview`, 카드 통신 없음).

### 3.2 공유 키 방식의 공개키 연결

EVM 공유 키는 EVM 주소와 Bitcoin 주소가 **같은 secp256k1 공개키**에서 나온다. Bitcoin에서 그 주소로 한 번이라도 보내면(입력 서명 시 공개키 공개) 누구나 그 공개키에서 EVM 주소를 계산할 수 있어 **두 체인의 신원이 연결된다.** 또 표준 Bitcoin 지갑은 BIP84 스캔으로 이 주소를 찾지 못한다(경로가 `m/44'/60'/…`). 복구는 이 지갑으로 같은 니모닉·같은 인덱스를 다시 등록하거나, 그 EVM 개인키를 WIF로 다른 지갑에 가져와야 한다. 마법사는 공유 키를 고르면 이 두 문장을 확인 체크박스와 함께 보인다. 권장은 §3.1의 분리 방식(SIG = EVM, AUT = BTC 표준 경로)이다.

### 3.3 Bitcoin 인덱스 선택: 주소 인덱스

Bitcoin 슬롯의 인덱스는 **계정 0의 받기 체인 주소 인덱스**(`…/0'/0/i`)다. 계정 번호(`…/i'/0/0`)가 아니다. 이유: 표준 지갑(Sparrow·Electrum 등)으로 같은 니모닉·같은 형식의 계정 0을 복구하면 gap limit 20 안의 주소가 그대로 보인다(i < 20 권장, 그 이상이면 마법사가 "복구 시 gap limit을 늘려야 합니다" 안내). 단점: 같은 니모닉으로 소프트웨어 지갑의 BTC 계정 0을 함께 쓰면 그 지갑도 이 주소를 자기 주소로 본다(키가 같으므로 당연하다 — 그 경우 YubiKey의 의미가 없다, §1). 잔돈은 같은 주소로 돌아온다(단일 주소 계정, [08] §3.5와 같은 규칙).

### 3.4 여러 YubiKey

- 한 YubiKey(일련번호) = vault tag 5 record 하나 = 슬롯 표 하나(일련번호 → 슬롯 → 경로 → 공개키, §8).
- 예: YubiKey #1 = EVM 0·1, #2 = EVM 2·3, #3 = EVM 4·5, #4 = #1의 백업 복사본(EVM 0·1, 슬롯은 달라도 됨).
- **같은 경로는 한 YubiKey 안에서 두 번 넣을 수 없다**(`DuplicatePath`). EVM 계정 i와 같은 i의 EVM 공유 키도 같은 키다.
- **다른 YubiKey와 같은 경로는 사용자가 그 슬롯을 "백업 복사본"으로 명시했을 때만** 허용한다(`PathOnOtherCard`). 반대로 "백업 복사본"인데 다른 YubiKey에 그 경로가 없으면 `NotACopy`.
- 모든 YubiKey는 **같은 니모닉(+ passphrase)** 이어야 한다: BIP32 마스터 지문(`HASH160(master pubkey)[0..4]`)을 record에 두고 다르면 `DifferentMnemonic`으로 거부한다. 같은 경로는 언제나 같은 공개키여야 한다(vault 디코드·추가 시 검사, §8).
- 마법사의 "YubiKey 목록" 화면은 계정별로 그 키를 가진 YubiKey(일련번호·슬롯)를 모두 보인다(`plan::accounts`): 예) "EVM 계정 0 — #12345678 SIG, #23456789 AUT(백업)".
- 최대 8개 YubiKey(`MAX_CARDS`), YubiKey당 슬롯 24개(`MAX_SLOTS_PER_CARD`: OpenPGP 2 + PIV 22, 또는 PIV 24).

### 3.5 계획 검사 규칙 (`plan::validate_plan`, `plan::validate_against`)

1. 슬롯 1–24개. 2. 같은 슬롯 두 번 금지. 3. OpenPGP 슬롯은 secp256k1 역할만, PIV 슬롯은 Ed25519 역할만(`WrongApplet`). 4. 탭루트·범위 밖 인덱스 금지(`UnsupportedRole`). PIV 슬롯은 `9A 9C 9D 9E 82–95`만(`9B` 관리 키·`F9` 증명 금지). 5. 터치 "고정" 변형은 OpenPGP만, PIV는 PIN 정책 필수(`Policy`). 같은 YubiKey 안 같은 경로 금지(`DuplicatePath`). 6. 이미 등록한 일련번호 금지(`CardAlreadyEnrolled` — 다시 등록하려면 먼저 그 record를 지운다). 7. 8개 초과 금지. 8. 지문 불일치 금지. 9. 다른 YubiKey와 같은 경로는 백업 복사본 표시가 있어야 하고, 표시가 있으면 실제로 있어야 한다.

검사는 **카드에 아무것도 쓰기 전에** 한다(일련번호는 읽기 전용 명령으로 먼저 읽음, §7.3).

## 4. 모듈 배치

| 위치 | 내용 | OS |
|---|---|---|
| `yw_core::yubikey::{apdu, tlv}` | ISO 7816-4 APDU(짧은·확장, 체이닝, `61xx` GET RESPONSE, `6Cxx`), BER-TLV | 없음 |
| `yw_core::yubikey::{openpgp, piv}` | 명령 빌더·응답 파서(순수)와 `CardTransport` 위의 흐름 | 없음 |
| `yw_core::yubikey::{plan, record, enrol, sign, sig}` | 슬롯 계획·경로·검사, tag 5 코덱, 등록, 카드 서명, 서명 후처리 | 없음 |
| `yw_core::yubikey::mock` | 두 애플릿의 APDU 수준 에뮬레이터(실제 secp256k1·Ed25519 서명). 시험 전용이지만 의존성 검사가 dev-dependency·feature 전환을 막으므로 항상 컴파일된다. 시험 밖에서는 아무도 만들지 않는다(yw-app의 `MockSource`는 `cfg(test)`) | 없음 |
| `yw_core::vault` | tag 5 record, `hardware_keys`·`add_hardware_key`·`remove_hardware_key`·`create_with_hardware` | 없음 |
| `yw_win::pcsc` | `SCardEstablishContext`(사용자 범위)/`ListReadersW`/`ConnectW`(T=1, 공유)/`BeginTransaction`/`Transmit`/`EndTransaction`·`Disconnect`(`SCARD_LEAVE_CARD`, 재설정 없음) 래퍼. USB·NFC 리더 모두 같은 경로. yw-win은 yw-core에 의존하지 않으므로(D4) `CardTransport` 구현은 yw-app의 얇은 어댑터가 한다 | 있음 |
| `yw_win::cng` | PIV 관리 키용 AES-ECB·3DES-ECB 한 블록(`BCRYPT_AES_ECB_ALG_HANDLE`·`BCRYPT_3DES_ECB_ALG_HANDLE` 의사 핸들, `BCryptEncrypt`/`BCryptDecrypt`). `MgmtCipher` 구현은 yw-app 어댑터 | 있음 |
| `yw-app` (§13) | 등록 마법사, "YubiKey" 계정 종류, 승인 후 카드 서명 단계 | — |

- yw-core에는 AES·3DES 구현이 없다(D6 "직접 구현 금지" 취지): PIV 관리 키 상호 인증의 블록 암호는 `piv::MgmtCipher` trait으로 받고 yw-win이 Windows CNG로 구현한다. 새 크레이트는 없다(windows-sys feature `Win32_Security_Credentials`만 추가).
- 게이트(`check.ps1`)의 어떤 테스트도 실제 리더·카드에 접근하지 않는다. yw-win의 PC/SC 테스트는 리더가 필요 없는 부분(오류 코드 매핑, 다중 문자열 파싱)만 자동이고, 실제 리더 진단은 `#[ignore]` + 읽기 전용(§12.2).

## 5. APDU 흐름

### 5.1 공통

- 전송: `CardTransport::transmit(frame) → data ‖ SW1 SW2`. 기본은 **짧은 APDU + 명령 체이닝**(CLA `10`, 255바이트씩)과 `61xx` GET RESPONSE(`00 C0 00 00 xx`) — USB·NFC 모두 동작한다. 확장 APDU(최대 3,000바이트 데이터)도 지원한다(ykman은 USB에서만 확장을 쓴다 [KIT-SC]).
- 상태어 매핑(`CardError::from_status`): `9000` 성공, `63Cx` PIN 오류(남은 x회), `6983` 잠김, `6982` 보안 조건(PIN·관리 키·**터치 시간 초과**), `6985` 사용 조건, `6A80` 데이터 오류, `6A82` 애플릿 없음, `6A88` 빈 슬롯, `6A81`/`6A86`/`6D00`/`6E00` 미지원.
- 응답 최대 16 KiB, GET RESPONSE 80회 상한(고장 난 카드 방어).
- 한 작업 동안 `SCardBeginTransaction`으로 카드를 잡는다(다른 프로그램이 애플릿을 바꾸지 못하게). 작업이 끝나면 `SCARD_LEAVE_CARD`로 놓는다(재설정 없음).

### 5.2 OpenPGP (secp256k1: SIG·AUT)

| 단계 | APDU | 비고 |
|---|---|---|
| SELECT | `00 A4 04 00 06 D2 76 00 01 24 01 00` | [OPC] p12 |
| 펌웨어 | `00 F1 00 00 00` → 3바이트 | Yubico 전용 [KIT-PGP] |
| 응용 데이터 | `00 CA 00 6E 00` → `6E { 4F AID(16), 73 { C0, C1 C2 C3, C4, … } }` | AID `[10..14]` = 일련번호(BCD) |
| KDF | `00 CA 00 F9 00` → `81 01 00`이면 꺼짐, 그 밖이면 `KdfEnabled`로 중단 | [OPC] p19 |
| PW3 (관리자) | `00 20 00 83 Lc PIN` | 기본 `12345678`, 8–127자 |
| 알고리즘 속성 | `00 DA 00 C1`(SIG)/`C3`(AUT) `06 13 2B 81 04 00 0A` | `13` = ECDSA, OID secp256k1, 가져오기 형식 표준(FF 없음). 속성을 바꾸면 그 슬롯의 기존 키가 지워진다 |
| 가져오기 | `00 DB 3F FF Lc 4D { B6 00 \| A4 00, 7F48 { 92 20 }, 5F48 <32바이트 스칼라> }` | 확장 헤더 목록, 공개키(`99`)는 넣지 않음 [OPC] p38–39 |
| 터치(UIF) | `00 DA 00 D6`(SIG)/`D8`(AUT) `02 <uif> 20` | `00` 끔, `01` 켬, `02` 고정, `03` 15초, `04` 15초 고정; 고정은 이후 변경 불가 [KIT-PGP] |
| 공개키 읽기 | `00 47 81 00 02 B6 00`(또는 `A4 00`) `00` → `7F49 { 86 41 04‖X‖Y }` | P1 `81` = 기존 키 읽기(생성 아님) |
| PW1 (서명) | SIG: `00 20 00 81 Lc PIN`, AUT: `00 20 00 82 Lc PIN` | 기본 `123456`, 6–127자. `81`은 PSO:CDS 한 번에만 유효(C4 첫 바이트 `00`) |
| 서명 (SIG) | `00 2A 9E 9A 20 <digest 32> 00` → `r ‖ s`(64) | PSO: COMPUTE DIGITAL SIGNATURE [OPC] p63 |
| 서명 (AUT) | `00 88 00 00 20 <digest 32> 00` → `r ‖ s`(64) | INTERNAL AUTHENTICATE [OPC] p71 |
| PIN 변경 | `00 24 00 81`(PW1)/`83`(PW3) `Lc old‖new` | §9.3 |

- **틀린 PIN의 응답(2026-11-07)**: YubiKey의 OpenPGP 애플릿은 틀린 PW1·PW3에 `63Cx`가 아니라 **`6982`**(보안 상태 불충족)를 돌려준다(잠긴 뒤는 `6983`). 그래서 `OpenPgp::verify`·`change_pin`은 `6982`(또는 `63Cx`)를 받으면 `6E`를 다시 읽어 `C4`의 남은 횟수(PW1 = 바이트 4, PW3 = 바이트 6)로 `WrongPin { retries }`를 만들고 `OpenPgp::app`도 갱신한다(읽지 못하면 원래 오류). `retries: 0`은 잠김과 같이 최종이다(`CardError::pin_retryable`, W11 재요청 없음). 에뮬레이터도 `6982`/`6983`으로 답한다. PIV는 표준대로 `63Cx`이므로 그대로다.
- 입력은 항상 32바이트 digest(EVM keccak256, Bitcoin sighash). 카드는 짧은 입력을 앞쪽 0으로 채운다고 명세에 있으나([OPC] p64) 우리는 항상 정확히 32바이트를 보낸다.
- 서명 흐름의 순서: SELECT → 일련번호 확인(`WrongCard`) → **공개키 읽기로 슬롯의 키가 기록과 같은지 확인**(`KeyMismatch`, 덮어쓴 슬롯을 PIN 전에 거부) → VERIFY PW1 → 서명 → §6 후처리. 서명 흐름은 쓰기 명령(`DA`·`DB`·`FE`·`FF`·`24`, `47 80`)을 **절대 보내지 않는다**(에뮬레이터 로그로 시험, §12.1).

### 5.3 PIV (Ed25519)

| 단계 | APDU | 비고 |
|---|---|---|
| SELECT | `00 A4 04 00 05 A0 00 00 03 08 00` | |
| 펌웨어 / 일련번호 | `00 FD 00 00 00` / `00 F8 00 00 00` → 3 / 4바이트(BE) | 5.7 미만이면 `FirmwareTooOld` |
| 관리 키 메타데이터 | `00 F7 00 9B 00` → `01 <type>`, `05 <기본값 여부>` | type: `03` 3DES, `08` AES-128, `0A` AES-192, `0C` AES-256. ykman처럼 **메타데이터로** 판정한다(펌웨어로 추측하지 않음) [KIT-PIV] |
| PIN 메타데이터 | `00 F7 00 80 00` → `05 <기본값 여부>`, `06 <전체, 남은 횟수>` | 기본 PIN이면 §9.3 안내 |
| 관리 키 상호 인증 1 | `00 87 <type> 9B 04 7C 02 80 00 00` → `7C { 80 <witness> }` | witness 8(3DES)/16(AES) |
| 관리 키 상호 인증 2 | `00 87 <type> 9B Lc 7C { 80 D(witness), 81 <challenge> } 00` → `7C { 82 E(challenge) }` | 우리가 `E(challenge)`를 계산해 **상수 시간 비교**, 다르면 `ManagementKeyMismatch`. 키가 틀리면 카드가 `6982` [KIT-PIV] `authenticate` |
| 가져오기 | `00 FE E0 <slot> Lc 07 20 <seed 32> AA 01 <pin> AB 01 <touch>` | Ed25519는 tag `07`(원시 32바이트 seed, 바이트 순서 그대로), PIN 정책 `02` 한 번/`03` 항상, 터치 `01` 없음/`02` 항상/`03` 15초 [KIT-PIV] |
| 확인 | `00 F7 00 <slot> 00` → `01 E0`, `02 <pin touch>`, `03 02`(가져옴), `04 { 86 <공개키 32> }` | 알고리즘·출처·정책·공개키가 모두 기대값이어야 함 |
| PIN | `00 20 00 80 08 <PIN, FF로 8바이트 채움>` | 기본 `123456`, 6–8자 |
| 서명 | `00 87 E0 <slot> Lc 7C { 82 00, 81 <메시지 전체> } 00` → `7C { 82 <서명 64> }` | Ed25519는 해시하지 않은 **메시지 원문**(Solana 메시지 ≤ 1,232바이트 → 체이닝) |
| PIN·PUK 변경 | `00 24 00 80`/`81` `10 old(8,FF) ‖ new(8,FF)` | §9.3 |
| 관리 키 변경 | `00 FF FF FF Lc <type> 9B <len> <key>` | 인증된 상태에서만. 터치 요구 변형(`P2 FE`)은 쓰지 않음 |

- PIV 서명 흐름: SELECT → 일련번호 확인 → GET METADATA로 슬롯 공개키가 기록과 같은지 → VERIFY PIN → GENERAL AUTHENTICATE → §6.4 검증.
- PIN 정책 기본값은 **항상**(`03`): 한 번의 VERIFY가 한 번의 서명에만 쓰인다. "한 번"(`02`)도 고를 수 있으나 이 지갑은 어차피 작업마다 SELECT·VERIFY를 다시 하므로 차이는 "같은 PIV 세션 안 다른 프로그램"뿐이다.

#### 5.3.3 PIN으로 보호된 관리 키 (2026-11-06)

`ykman piv access change-management-key --generate --protect`가 만드는 상태다. 사용자는 관리 키를 본 적이 없고, 카드가 PIN을 확인한 뒤에만 읽게 해 주는 데이터 객체에 들어 있다. 바이트 배치는 yubikey-manager `ykman/piv.py`의 `PivmanData`·`PivmanProtectedData`·`get_pivman_data`·`get_pivman_protected_data`·`pivman_set_mgm_key`와 `yubikit/piv.py`의 `get_object`·`put_object`(`INS_GET_DATA = 0xCB`, `INS_PUT_DATA = 0xDB`, `TAG_OBJ_ID = 0x5C`, `TAG_OBJ_DATA = 0x53`, `OBJECT_ID.PRINTED = 0x5FC109`)를 따른다 [KIT-PIVMAN] [KIT-PIV].

| 단계 | APDU | 비고 |
|---|---|---|
| GET DATA | `00 CB 3F FF 05 5C 03 <id 3바이트> 00` → `53 { 내용 }` | `6A82`면 객체 없음(ykman도 빈 객체로 본다) |
| PUT DATA | `00 DB 3F FF Lc 5C 03 <id> 53 <len> <내용>` | 관리 키 인증 필요. 빈 내용은 객체를 지운다 |
| ADMIN DATA `5FFF00` | 내용 `80 { 81 <flags 1>, 82 <salt>, 83 <PIN 시각 4> }` | 인증 없이 읽힌다. flags `01` PUK 막음, **`02` 관리 키가 PRINTED에 저장됨**(`mgm_key_protected`). `82` salt는 옛 "PIN에서 파생한 3DES 키"(`--pin-derived`) — 이 지갑은 지원하지 않는다(`NotSupported`) |
| PRINTED `5FC109` | 내용 `88 { 89 <관리 키> }` | **VERIFY PIN 뒤에만** 읽힌다(그 전에는 `6982`) |

- 판정(`Piv::management_state`): GET METADATA `9B`(알고리즘·기본값 여부) + ADMIN DATA(보호 여부). 저장된 키의 알고리즘은 메타데이터 `9B`가 알려 준다(PRINTED에는 없다). 키 길이가 그 알고리즘과 다르면 `Malformed`.
- 인증(`Piv::authenticate_management`): 보호되어 있으면 PIV PIN이 있어야 한다(없으면 `ManagementKeyProtected`, 기본 키를 시도하지 않음) → VERIFY PIN → PRINTED에서 키를 꺼내 `Zeroizing`에 → 상호 인증 → 키를 지움. 보호되어 있지 않으면 사용자가 입력한(또는 공장 기본) 키를 쓴다.
- 이 지갑의 `--generate --protect`(`Piv::protect_management_key`, §9.3): VERIFY PIN → 현재 키로 인증(보호돼 있으면 PRINTED의 키, 아니면 공장 기본 키; 둘 다 아니면 `ManagementKeyUnknown` — 지갑이 모르는 키) → 이 PC의 OS 난수(`entropy::fill_random`)로 AES-192 키 생성 → **PRINTED를 먼저** `88 { 89 새 키 }`로 쓰고 → SET MANAGEMENT KEY(AES-192) → ADMIN DATA flags에 `02`를 켜고 salt를 지워 바뀌었으면 쓴다. SET이 실패하면 PRINTED를 이전 내용으로 되돌린다(최선 노력) — 그래서 SET 실패가 옛 키를 잃게 하지 않는다(ykman은 SET → ADMIN → PRINTED 순서). 새 키는 화면에 나오지 않고 작업이 끝나면 지워진다.
- **중간에 멈춘 경우의 복구(2026-11-07)**: 세 쓰기(PRINTED → SET → ADMIN DATA)는 원자적이지 않다.
  - SET이 오류를 돌려주면(응답만 잃고 카드는 바꿨을 수 있음) 먼저 새 키로 인증해 보고, 되면 그대로 ADMIN DATA까지 끝낸다. 안 되면 아직 메모리에 있는 이전 키로 다시 인증해 PRINTED를 되돌린다(최선 노력).
  - SET 뒤 ADMIN DATA 전에 멈추면(카드 뽑힘 등) 카드는 "기본값도 보호도 아닌" 관리 키 + PRINTED에 그 키 상태가 된다. 그 상태에서 PIN이 주어지면 `protect_management_key`와 `authenticate_management`는 VERIFY PIN 뒤 PRINTED의 키로 인증해 본다 — `PIV 관리 키 자동 보호`(또는 "8자리 하나로 통일")를 PIV PIN으로 다시 실행하면 flag를 켜 복구된다. PRINTED의 키로도 안 되면 `ManagementKeyUnknown`(문구가 이 복구를 안내한다).
  - 보호 표시가 있는데 PRINTED의 키로 인증이 안 되면(PRINTED를 쓴 뒤 SET 전에 멈추고 되돌리기도 실패) 메모리에 있는 이전 키(입력한 키), 메타데이터가 기본이라면 공장 키를 한 번 더 시도한다. 그 밖에는 이전 키를 알 길이 없으므로 PIV 애플릿 초기화(§15.3) 뒤 다시 등록한다.

## 6. 서명 후처리 (`yubikey::sig`)

### 6.1 ECDSA 공통

1. `r ‖ s` 64바이트를 엄격히 파싱한다(각각 1..n, 영 금지).
2. **low-s 정규화**: `s > n/2`면 `s ← n − s`(EIP-2, BIP62/146). 카드는 무작위 nonce로 서명하므로 high-s가 절반쯤 나온다.
3. **기록된 공개키로 검증**한다(카드 응답을 믿지 않는다). 실패는 `BadSignature`("서명 검증 실패(YubiKey 응답 오류)").

### 6.2 EVM

- 복구 id(y_parity)는 카드가 주지 않는다: 정규화된 `(r, s)`로 0과 1을 차례로 복구해 **기록된 공개키와 같은 쪽**을 고른다(`sig::evm_recoverable`). 둘 다 아니면 `BadSignature`.
- 그 뒤는 소프트웨어 경로와 같은 **서명 후 검증**([03] §4.3: 재인코딩, 엄격 디코드, 필드 비교, 보낸 주소 복구 = 승인된 계정)을 그대로 거친다. 실패하면 저장·전송하지 않는다.

### 6.3 Bitcoin

- 서명 항목 = `DER(r, s) ‖ 01`(SIGHASH_ALL). 정규화로 low-s는 보장되지만 **low-R은 보장할 수 없다**(카드 nonce를 고를 수 없고, 다시 서명하면 터치가 또 필요하다). 따라서 카드 서명에는 [08]의 "DER ≤ 70바이트(low-R)" 검사 대신 **DER ≤ 72바이트, low-s, 엄격 DER(왕복 동일), 서명 검증**을 적용한다(`sig::btc_der`, 서명 후 `btc::sign::check_card_signature`). 표준성(BIP66·BIP146)은 low-R을 요구하지 않는다. 이 완화는 **YubiKey 계정의 입력에만** 적용되고 소프트웨어 입력의 검사(`check_witness_signature`·`check_p2pkh_signature`, low-R ≤ 70)는 그대로다.
- 수수료 계산의 서명 항목 크기는 YubiKey 입력에서 **72 + 1바이트**(카드 DER 상한 + sighash)로 잡는다(소프트웨어 입력은 지금처럼 70 + 1 = 71바이트). 입력 무게(`ScriptType::card_input_weight`): P2WPKH 273(소프트웨어 271), P2SH-P2WPKH 365(363), P2PKH 596(588). witness 입력은 서명 항목 2바이트(0.5 vB), P2PKH는 scriptSig 2바이트(2 vB) 차이다. low-s 뒤 실제 DER은 최대 71바이트라 이 추정은 실제 크기를 넘지 않는다(서명 후 검증의 "실제 vsize ≤ 계획 vsize").
- 표현(코어): YubiKey Bitcoin 계정은 단일 주소 계정 `BtcAccountKey::Hardware { key, script_type, pubkey }`다. `key: HwBtcKey`는 슬롯 역할이다 — `Address(i)` = `KeyRole::Btc`(`m/{44|49|84}'/{coin}'/0'/0/i`), `Evm(i)` = EVM 공유 키(`m/44'/60'/0'/0/i`). 공개키는 **tag 5 슬롯 표에서만** 온다(`Vault::hardware_btc_account`, 시드에서 파생하지 않음 — 같은 경로의 표준 파생과 같은지는 시험이 확인). 주소·scriptPubKey·받기·잔돈 규칙은 [08] §3.5의 단일 주소 계정과 같다(`(Receive, 0)` 하나, 잔돈도 같은 주소, gap 탐색 없음). P2TR은 만들 수 없다(`AccountKeyError::HardwareTaproot`). 입력 키 출처는 `BtcKeySource::Hardware`이고 vault 서명 경로(`sign_plan`)는 `Vault(RecordNotFound)`로 거부한다. 승인 payload·저널 계정 블록의 source는 4(주소 키)·5(EVM 키), 활동 태그 `yubikey/p2wpkh/i`·`yubikey/evm/p2wpkh/i`, meta `btc_accounts`의 `key.yubikey`(`kind` `btc`/`evm`, `index`, `pubkey`)·`selected.yubikey`.
- 서명(코어): `btc::sign::sign_plan_card(approved, plan, account, card)` — `sign_plan`과 같은 승인·계획 검사 → 입력마다 sighash(P2PKH 레거시, P2SH-P2WPKH·P2WPKH BIP143; P2TR은 `Card(NotSupported)`)를 카드 클로저(`yubikey::sign::sign_btc`, DER 반환)로 서명 → 완화 검사 → 소프트웨어 경로와 같은 scriptSig·witness → 거래 전체의 서명 후 검증(`verify::verify_signed`: 비서명 거래 동일, 키, 서명, 출력·잔돈, 수수료·상한, dust, 크기, [08] §11.2). 오류는 `CardSignError::{Sign, Card, PostSign}`. 앱은 그 전에 `check_recorded_amounts`를 부른다(vault 경로와 같음).
- 입력마다 카드 서명 한 번: 터치 "항상"이면 입력 수만큼 터치, "15초 유지"면 첫 터치 뒤 15초 안의 입력은 터치 없이 서명된다. 승인 창은 "YubiKey 터치 N회가 필요합니다"를 보인다(§10).
- 탭루트 입력은 YubiKey 계정에 존재하지 않는다(§2).

### 6.4 Ed25519 (Solana)

- 카드 서명 64바이트를 기록된 공개키로 `verify_strict` 한다(정규 S, 소수 위수 키 거부). 그 뒤는 [07] §13의 서명 후 검증(메시지 바이트 = 승인한 템플릿)을 그대로 거친다.
- 표현(코어): 키 출처 `SolKeySource::Hardware(i)`(**tag 7**, 매개변수 `(i, 0)`, 경로 `m/44'/501'/i'/0'`, 경로 문구 "… (YubiKey PIV)"). 표준 경로이므로 비표준 경로 규칙([07] §3.3)은 적용되지 않는다. vault는 이 출처에 시드를 빌려 주지 않고(`with_ed25519_seed` → `RecordNotFound`), 공개키는 `Vault::sol_public_keys`가 tag 5 슬롯 표에서 답한다(니모닉 없는 YubiKey 지갑에서도).
- 서명(코어): `sol::sign::sign_transfer_card(approved, consumed_at_ms, blockhash, now_ms, card)` — `sign_transfer`와 같은 기한·승인·수수료 규칙·메시지(파싱 + 재인코딩 동일) 검사 → 카드가 메시지 바이트 그대로 서명 → 같은 서명 후 검증(`verify_strict`, 조립, 재파싱). `sol::msgsign::sign_message_card(approved, card)` — `sign_message`와 같은 승인 검사와 거래 모양·잘못된 오프체인 메시지 거부(M01·M02)를 **카드에 묻기 전에** 하고, 카드 서명을 `verify_strict` 한다. 카드 클로저 형식은 `sol::sign::SolCardSigner`(`yubikey::sign::sign_sol`), 오류는 `SolCardSignError`·`SolMessageCardError`(`Sign`·`Card`).

### 6.5 Zcash 서명 (2026-11-06)

- YubiKey Zcash 계정(`KeyRole::Zec`, §3.1)의 일반(transparent) 보내기는 **입력마다 카드 서명 한 번**이다: 입력의 ZIP 244 `SIGHASH_ALL` digest(32바이트)를 그 슬롯(SIG는 PSO:CDS, AUT는 INTERNAL AUTHENTICATE, §5.2)으로 서명한다(`zec::sign::sign_plan_card`, 카드 클로저는 Bitcoin과 같은 `yubikey::sign::sign_btc_checked` 경로).
- 서명 항목 규칙은 Bitcoin §6.3과 같다: low-S로 정규화, 기록된 공개키로 검증, 엄격 DER ≤ 72바이트(low-R은 보장하지 않음), 끝에 `SIGHASH_ALL`(`01`) 바이트. 그 뒤 거래 전체의 서명 후 검증([12] §10.2)을 그대로 거친다.
- PIN은 보내기 한 건에 한 번(모든 입력에 같은 PIN 버퍼, §9.1), 터치는 입력마다(터치 정책 "15초 유지"면 첫 터치 뒤 15초 안의 입력은 터치 없이). 자세한 내용은 [12] §8.2.

## 7. 등록 (`yubikey::enrol`)

### 7.1 진입점

1. **새 YubiKey 지갑**(지갑 생성 화면의 "YubiKey에 키 보관"): 24단어를 새로 만들고 보여준 뒤 백업 확인(메모리 안에서, [02] §8.3과 같은 4단어 확인)까지 마치고 §7.3 등록을 한다. 첫 YubiKey 등록이 끝나면 `Vault::create_with_hardware`로 **니모닉 없는 vault**(tag 5만)를 만든다. 니모닉은 저장되지 않는다.
2. **복구 단어로 YubiKey 계정 추가**(설정 → YubiKey, 또는 키 전용·YubiKey 지갑에서): 니모닉(+ 선택 passphrase)을 비밀 입력 창에 **한 번** 입력한다. 그 니모닉이 이 vault의 니모닉과 같으면(같은 지문) **경고하고 허용한다**(사용자 결정 2026-11-05): "이 복구 단어는 이 PC의 vault에도 저장되어 있습니다. 복구 단어가 이 PC에 남아 있는 동안 YubiKey는 보안 이득이 없습니다(같은 키를 PC에서도 만들 수 있음). 키를 PC 밖에 두려면 'YubiKey 지갑'(복구 단어를 저장하지 않는 지갑)을 새로 만드세요." 확인하면 계속한다.
3. **백업 YubiKey 추가**: 2와 같되 슬롯마다 "백업 복사본"을 고를 수 있다.

어느 경우든 니모닉·시드·파생 키는 `Zeroizing` 버퍼에만 있고 마법사가 닫히거나 잠금(자동 잠금 포함)되면 즉시 지운다. 등록 중 자동 잠금은 등록을 취소한다(카드에 일부 쓴 상태일 수 있음 → §7.4).

구현(2026-11-05, 화면은 [04] §2.19):

- 진입점 1은 S01 카드 "YubiKey에 키 보관" → S20 → W01 → W08 → W10 → S21이다. 24단어는 키 작업자가 만들어(`bip39::Mnemonic::generate`) 비밀번호와 함께 보관하고, W08에 한 번 보인다. W10의 4단어 확인은 vault 없이 보관한 니모닉으로 한다(`Mnemonic::backup_positions`·`backup_words_match`: `Vault::backup_challenge`·`confirm_backup`과 같은 추첨·같은 상수 시간 비교 — vault도 이 함수를 쓴다). 첫 YubiKey가 등록되면 `create_with_hardware`와 슬롯 표의 기본 meta(파생 계정 없음, 첫 계정 선택)를 쓰고 `Unlocked`가 된다. 같은 단어로 백업 YubiKey를 이어서 등록할 수 있도록 단어는 마법사의 `완료`(또는 `취소`·유휴 폐기·잠금)까지 키 작업자 메모리에만 있다.
- 진입점 2·3은 설정 → YubiKey `YubiKey 등록`(키 전용·YubiKey 지갑의 빈 체인 카드에도)이다. 단어는 W05(+ W06)에서 한 번 받아 바로 키 작업자로 옮기고(`YkJob::Preview`), 그 뒤 미리보기·등록·백업 YubiKey 반복은 보관한 시드로 한다. 같은 니모닉 판정은 입력한 시드의 EVM 계정 0 주소 = vault에 있는 **모든** 복구 단어(첫 단어와 추가한 단어, 각자의 passphrase로)의 계정 0 주소 중 하나(`enrol::seed_identity`, `KeyWorker::vault_holds_evm0`; passphrase가 다르면 다른 시드이므로 경고하지 않음)이고, 경고(T-YK-SAME)를 체크해야 계속한다. 반대 방향도 막는다(2026-11-08): "복구 단어 추가 가져오기"([02] §8.6)는 미리보기에서 새 시드의 마스터 지문을 경로를 아는 등록 YubiKey record의 지문과 비교하고(`MnOutcome::Preview`의 카드 목록), 같으면 그 카드 번호와 T-YK-SAME(위험 띠)을 보이고 확인 체크 전에는 `가져오기`(비밀번호·저장)를 막는다.
- "백업 복사본"은 이미 등록한 카드 하나의 슬롯 계획(슬롯·경로·정책)을 그대로 복사하고 모든 슬롯에 `backup_copy`를 켠다. 직접 고른 계획에서 같은 경로는 `PathOnOtherCard`로 확인 화면에서 막힌다.

- **떠나면 지움(2026-11-07)**: 마법사(새 YubiKey 지갑의 S20 포함)나 `슬롯 구성 바꾸기`를 버튼이 아닌 길로 떠나도 — 다른 화면, 다른 설정 탭, 메인 화면(`App::set_screen`이 `yk_leaving`을 부른다) — 흐름을 닫고 키 작업자가 보관한 64바이트 시드를 지운다(`YkJob::Discard`). 카드 작업이 도는 중이면 끝날 때까지 두고, 확인 오버레이는 떠나는 것으로 보지 않는다.

### 7.2 확인 화면 (카드 통신 전)

슬롯마다: 슬롯 이름(예 "OpenPGP 서명(SIG)", "PIV 82 (보관 1)"), 역할 제목, **전체 경로**, 주소(공유 키는 EVM·Bitcoin 둘 다), 터치·PIN 정책. 다른 YubiKey와의 관계(새 키 / 백업 복사본: 어느 YubiKey의 어느 슬롯과 같은지). §3.5 검사 결과를 여기서 보인다.

구현: 미리보기는 `enrol::preview_seed`(카드 통신 없음), 검사는 일련번호가 필요 없는 규칙 1–5·7–9(`plan::validate_before_card`; 규칙 6 `CardAlreadyEnrolled`는 카드에서 `enrol_card`가 판정)이며 오류면 `다음`·`가져오기`가 꺼진다. 관계는 같은 경로를 가진 등록 카드의 일련번호. PIV 슬롯이 있으면 펌웨어 안내(5.7.4 / 5.7.0–5.7.3 / 5.7.0 미만)를 언제나 보인다.

**어느 카드인지(2026-11-07)**: 확인 화면과 자격 정보 화면에 들어갈 때 키 작업자가 꽂힌 카드를 **읽기만** 해서 식별한다(`YkJob::Identify` → `yubikey::single_card`: 카드마다 SELECT·버전·`6E`/일련번호와 PIN 남은 횟수, PIN·쓰기 없음). 둘 이상이면 `MultipleCards` "YubiKey가 둘 이상 연결되어 있습니다. YubiKey를 하나만 연결하세요."를 보이고 `다시 읽기`를 둔다. 하나면 "YubiKey #일련번호 (펌웨어 x.y.z) — 이 YubiKey에만 씁니다."를 보이고, 자격 정보 화면의 `가져오기`·`가져오기 없이 등록`은 그 일련번호가 있어야 켜진다. 관리 키 상태 읽기(`ProbeManagement { serial }`)·등록(`YkJob::Enrol { serial }` → `enrol_card_serial`)·가져오기 없이 등록(`adopt_card_serial`)은 그 일련번호의 카드에만 간다(`on_serial`: 다른 카드면 `WrongCard`, 아무것도 쓰지 않음). 서명은 전처럼 기록의 일련번호로 카드를 고른다. 옛 진입점 `KeyJob::EnrolYubiKey`도 `single_card`로 하나인지 확인한 뒤 그 일련번호로 등록한다.

### 7.3 카드 절차 (`enrol_card`)

1. **읽기만**: OpenPGP(계획에 있으면) SELECT·버전·`6E`·KDF → 일련번호; PIV(계획에 있으면) SELECT·버전·일련번호. 두 일련번호가 다르면 `SerialMismatch`(YubiKey를 하나만 꽂으라고 안내).
2. §3.5 규칙 6–9 검사(`validate_against`). 실패면 **아무것도 쓰지 않고** 끝.
3. OpenPGP: VERIFY PW3 → 슬롯마다 속성 `C1`/`C3` → 가져오기 → UIF → 공개키 읽기 = 파생 공개키(`KeyMismatch`).
4. PIV(OpenPGP 뒤에: 다른 애플릿을 SELECT하면 PW3 확인이 풀린다 [OPC] p52): 관리 키 메타데이터 → ADMIN DATA(PIN으로 보호된 키면 VERIFY PIN → PRINTED, §5.3.3) → 상호 인증 → 슬롯마다 가져오기 → 메타데이터 확인.

구현(2026-11-06): 마법사 자격 정보 단계(d)에 들어갈 때 PIV 슬롯이 있으면 키 작업자가 꽂힌 카드의 관리 키 상태를 읽는다(`YkJob::ProbeManagement`: SELECT·버전·일련번호·GET METADATA `9B`·GET DATA ADMIN DATA, 읽기만). 보호되어 있으면 관리 키 선택 대신 "관리 키: PIN으로 보호됨 — PIV PIN만 입력"을 보이고 `가져오기`는 (OpenPGP 관리자 PIN 뒤에) W12 PIV PIN(6–8)을 묻는다(`EnrolAuth::piv_pin`). 보호되어 있지 않으면 지금처럼 "기본 관리 키 사용 / 관리 키 직접 입력"이며, 읽은 기본값 여부로 처음 선택을 맞춘다. 읽지 못했으면(카드 없음) 그 선택을 그대로 보이고, 보호된 카드면 등록이 `ManagementKeyProtected`로 아무것도 쓰기 전에 멈춘다 — `다시 시도`가 상태를 다시 읽는다. 선택지 이름과 설명([04] §2.19): "복구 단어에서 키를 넣기 (처음 등록)" / "이미 넣은 키 연결하기 (가져오기 없이 등록)".
5. record 완성(일련번호, 펌웨어, 지문, 계획 순서의 슬롯·공개키). 기존 record들과의 일관성(같은 경로 = 같은 공개키) 확인.
6. vault에 `add_hardware_key`(또는 첫 YubiKey 지갑이면 `create_with_hardware`). 그 뒤 "다시 확인"(`sign::check_key`, 읽기 전용)으로 슬롯마다 공개키를 한 번 더 읽어 보인다.

### 7.4 실패와 재시도

- 3–4단계 중 실패하면 앞 슬롯은 카드에 이미 써졌을 수 있지만 vault에는 아무 record도 없다. 같은 계획으로 다시 하면 덮어쓴다(속성 재설정이 기존 키를 지운다). 화면: "일부 슬롯에 키가 이미 들어갔을 수 있습니다. 다시 시도하면 덮어씁니다."
- 터치 정책이 이미 **고정**(UIF `02`/`04`)인 슬롯을 다시 등록할 때: 원하는 정책과 같으면 UIF를 쓰지 않고 진행하고, 다르면 키를 쓰기 전에 `Conditions`로 거부한다("이 슬롯의 터치 정책은 고정되어 있습니다 — 바꾸려면 OpenPGP 초기화가 필요합니다"). 그래서 "항상(고정)"으로 등록한 YubiKey도 같은 정책으로는 언제든 다시 등록할 수 있다.
- 카드를 다른 지갑 용도(GPG 등)로 쓰던 경우 그 슬롯의 키는 **지워진다**. 마법사는 가져오기 전에 "이 YubiKey의 OpenPGP SIG/AUT 키와 PIV 82…의 키가 바뀝니다"를 보이고, 읽을 수 있으면 현재 키가 있는지(공개키 읽기·메타데이터 `6A88` 여부)를 함께 보인다.

### 7.5 복구

- YubiKey를 잃으면: 다른 백업 YubiKey로 계속 서명하거나, 니모닉으로 새 YubiKey에 같은 경로를 다시 등록한다(§7.1-2, "백업 복사본"). 잃은 YubiKey의 record는 설정에서 지운다(비밀번호 재입력).
- PC·vault를 잃으면: 새 PC에서 "YubiKey 지갑 복구" = §7.1-2와 같은 경로로 니모닉 입력 → 경로 선택 → 카드 쓰기 **없이**(이미 키가 있는 카드) 공개키만 읽어 record를 만드는 "가져오기 없이 등록"(카드의 공개키 = 파생 공개키일 때만). v1에서는 다시 가져오기(덮어쓰기)로 대신해도 결과가 같다.
- 구현(2026-11-05): `enrol::adopt_card` — 일련번호 읽기 → `validate_against` → 슬롯마다 OpenPGP `00 47 81 00`·UIF 읽기 / PIV GET METADATA(알고리즘 `E0`, 공개키, PIN·터치 정책)만 보내고, 공개키가 파생 공개키와 다르거나 비어 있으면 `KeyMismatch`/`NotFound`. record의 터치·PIN 정책은 카드의 실제 값이다. 마법사 자격 정보 화면의 `이미 넣은 키 연결하기 (가져오기 없이 등록)`(관리자 PIN·관리 키를 묻지 않음; PIV 상태 판정에 GET DATA ADMIN DATA도 읽는다). 결과 화면은 `가져오기`와 같이 "기본값 변경 / PIN 설정"으로 끝난다(§9.3). 복구 단어 없는 새 PC에서 처음부터 하는 복구는 §7.6 "YubiKey 연결하기 (복구 단어 없이)"(2026-11-07)다: 복구 단어 없이 카드의 공개키만으로 YubiKey 지갑을 만든다.
- 기록 삭제: 설정 → YubiKey `삭제` → 그 카드에만 있는 계정을 보이는 확인 오버레이 → W03 → `remove_hardware_key` → meta 다시 읽기(그 카드에만 있던 계정은 목록에서 빠지고, 백업 카드가 가진 계정은 남는다).
- 니모닉만 있으면 이 지갑 없이도 다른 표준 지갑으로 복구된다(공유 키 방식의 Bitcoin 주소는 §3.2 예외).

### 7.6 YubiKey 연결하기 (복구 단어 없이) (2026-11-07)

사용자 결정: "어차피 PIN으로만 풀면 주소는 나올 테니" — 이미 키가 든 카드는 복구 단어 없이 연결한다. 서명은 지금처럼 카드가 PIN + 터치로 하므로, PC가 알아야 할 것은 공개키·슬롯·정책뿐이다. 경로는 알 수 없다(카드는 경로를 저장하지 않는다).

- **진입점**: S01 카드 "YubiKey에 키 보관"의 `YubiKey 연결하기 (복구 단어 없이)`(W01 비밀번호 → 키 작업자가 vault가 생길 때까지 보관 `YkJob::HoldConnectPassword`, 마법사 종료·떠남·잠금에 지움 → 아래 흐름 → `create_with_hardware`로 tag 5만 있는 YubiKey 지갑), 설정 → YubiKey와 키 전용·YubiKey 지갑의 빈 체인 카드의 `YubiKey 연결하기 (복구 단어 없이)`(`add_hardware_key`). 화면은 S21 마법사 안의 연결 모드(단계 "YubiKey 읽기·키 고르기" → "주소 확인" → "결과", [04] §2.19).
- **1. 읽기(PIN 없음, 쓰기 없음)** `yubikey::connect::scan_card`(앱 `YkJob::Scan` → `scan_single`: 카드가 둘 이상이면 `MultipleCards`): OpenPGP SELECT·버전·`6E`(속성 `C1`/`C3`, PW1 남은 횟수)·KDF → SIG·AUT마다 `00 47 81 00`(`6A88`이면 빈 슬롯) + UIF. 속성이 secp256k1 ECDSA(`13 2B8104000A`, 끝에 가져오기 형식 `00`/`FF` 허용)인 키만 쓴다; RSA·OpenPGP Ed25519·다른 곡선은 "쓸 수 없음"으로 보인다. PIV SELECT·버전·일련번호·PIN 메타데이터(남은 횟수·기본값)·관리 키 상태 → `9A 9C 9D 9E 82–95`마다 GET METADATA(`6A88` 빈 슬롯); 알고리즘 `E0` Ed25519이고 정책이 이 지갑이 쓰는 값(PIN 한 번·항상, 터치 없음·항상·15초)인 키만 쓴다. 두 애플릿의 일련번호가 다르면 `SerialMismatch`. 한 애플릿을 못 읽으면(없음·펌웨어·KDF) 그 이유를 보이고 다른 쪽으로 계속한다. 이미 등록된 일련번호면 "먼저 그 기록을 지우세요".
- **2. 무엇인지 고르기**: 찾은 키마다 라디오 — secp256k1: `EVM 계정` / `Bitcoin 네이티브 세그윗(P2WPKH)` / `호환 세그윗(P2SH-P2WPKH)` / `레거시(P2PKH)`(탭루트 없음, 설정의 Bitcoin 네트워크) / `Zcash 일반 주소`(Zcash가 켜져 있으면 그 네트워크, 아니면 Bitcoin 네트워크에 맞춘 것) / `연결하지 않음`; Ed25519: `Solana 계정` / `연결하지 않음`. 기본값 SIG = EVM, AUT = Bitcoin P2WPKH, PIV = Solana. 고른 용도의 주소를 바로 보인다(형식마다 주소가 다르다는 안내).
- **3. 주소 확인** `connect_record`(카드 통신 없음): 모든 주소를 전체로, 경로 칸은 "경로를 알 수 없음", 띠 T-YK-UNKNOWN-PATH "경로를 알 수 없음 — 이 키는 카드에서 가져왔습니다. 같은 주소가 맞는지 이전에 쓰던 지갑과 비교하세요." 같은 키를 이미 등록된 카드가 같은 용도로 가지고 있으면 그 계정에 이 카드를 더한다(관계 줄; 역할·경로 상태를 그대로 물려받음 = 백업 보유자). PIV PIN이 공장값이면 "PIN 설정 전에는 서명하지 않음" 경고.
- **선택: PIN으로 소유 확인** — W12 `CardSecretKind::UserPin`(OpenPGP PIN 6–127, secp256k1 키가 없으면 PIV PIN 6–8) → `YkJob::ConnectVerify` → `connect::verify_pin`: VERIFY 한 번(OpenPGP `00 20 00 82`, PIV `00 20 00 80`), 서명·쓰기·터치 없음. 공장 PIN `123456`은 보내지 않는다(`PinFormat`, 창에 안내). 틀리면 남은 횟수를 보이고 다시, 잠기면 창을 닫고 결과를 보인다. 확인하지 않아도 저장할 수 있다(설명: "확인하지 않아도 연결할 수 있고, 서명할 때는 언제나 PIN과 터치가 필요합니다").
- **4. 저장** `YkJob::Connect { serial, choices, expected }` → `connect::connect_card`: 그 일련번호 카드를 다시 읽어(읽기만) 같은 선택으로 만든 record가 확인한 record와 정확히 같아야 한다(다르면 `KeyMismatch`, 다른 카드면 `WrongCard`, 아무것도 저장 안 함). 결과 화면은 등록과 같다("다시 확인", "PIN 설정", 결과 띠에 T-YK-UNKNOWN-PATH). 새 지갑이어도 PIN 설정 단계를 강제하지 않는다(이미 쓰던 카드; 공장 PIN은 §9.2대로 서명에서 거부). 기본값이 보였으면(PIV PIN·관리 키 메타데이터) `hw_accounts.defaults`에 더한다.
- **record**(§8): 경로를 모르는 슬롯은 flags `01`, 역할 인덱스는 종류(EVM·Bitcoin·Zcash·Solana)마다 900부터 빈 번호(`plan::UNKNOWN_PATH_FIRST`, `KeyRole::index`/`with_index`); 경로를 알게 된 것이 아니라 계정 번호일 뿐이다. 그래서 모든 경로 문구(`KeyRole::path_text`, `SolKeySource::path_text`, Bitcoin YubiKey 계정의 `path_text`, `ZecKeySource::path_text`, EVM 계정 줄)는 900–999 대역에서 "경로를 알 수 없음"을 쓰고, 이름은 "YubiKey 카드 키 n"·"EVM 계정 (카드 키 n)"이다. 복구 단어로 등록하는 계획은 이 대역을 쓸 수 없다(`validate_before_card` → `UnsupportedRole`, 마법사 인덱스 0–899).
- **서명**은 바뀌지 않는다: 계정 → 역할 → `slot_on_card` → 일련번호·슬롯·기록 공개키 확인 → PIN → 터치 → §6 후처리. 공장 기본 PIN 거부(§9.2), 남은 횟수 표시(§9.1), 여러 카드 거부(§7.2)도 그대로다.
- **경로 맞추기(미구현)**: 나중에 니모닉을 넣으면 표준 경로(EVM 0–19, BIP44/49/84 0–19, SOL 0–19, ZEC 0–19)를 훑어 경로를 찾아 줄 수 있으나, 대역 인덱스가 계정 식별자(meta·저널·승인)이므로 경로를 찾으면 계정이 바뀐다(이름·숨김·선택 이전 필요). 이번에는 넣지 않았다(§13).
- 시험(에뮬레이터만): `yubikey::tests::connect_without_words_and_sign_every_chain`(다른 단어로 넣은 키를 읽기만 → 경로 모름 record, 주소 = 원래 경로의 주소, flags 바이트 위치, 왕복, 위조 거부, 다시 읽기 일치·다른 카드, PIN 확인(공장 PIN 안 보냄, 남은 횟수), 백업 카드의 같은 키 = 같은 계정, 대역의 니모닉 등록 거부, EVM·Bitcoin·Zcash·Solana 서명과 쓰기 없음), `vault::tests::unknown_path_card_vault_accounts_and_zcash_collision`, 앱 `yubikey_connect_without_words_from_the_first_run_screen`(S01 → W01 → 읽기 → 고르기 → 주소 → 저장 → YubiKey 지갑, 계정 줄 "경로를 알 수 없음", 앱 어댑터 서명).

## 8. vault 기록: tag 5 `HwKey` (공개 데이터만)

[02] §4.6의 형식 확장 규칙(새 tag만 더함)을 따른다.

```
HwKey (tag 5, 25 + 12 + 48n 바이트)
1   tag = 5
16  record_id (0 아님)
8   created_unix u64
4   serial u32 (OpenPGP AID와 PIV GET SERIAL이 같아야 함)
3   firmware major, minor, patch
4   master_fingerprint = HASH160(BIP32 master 공개키)[0..4]
1   slot_count n (1..=24)
n × 48:
  1 applet (1 OpenPGP, 2 PIV)          1 slot (OpenPGP 1 SIG / 3 AUT; PIV 슬롯 id)
  1 curve (1 secp256k1, 2 Ed25519)     1 role (1 EVM, 2 BTC, 3 SOL, 4 ZEC)
  1 btc_network (0, 1, 2; ZEC: 1 메인넷, 2 테스트넷)  1 btc_script (0, 1 P2PKH, 2 P2SH-P2WPKH, 3 P2WPKH; ZEC: 0)
  4 index u32                          1 touch (1 없음, 2 항상, 3 15초, 4 항상 고정, 5 15초 고정)
  1 pin (0 해당 없음, 2 한 번, 3 항상)
  33 공개키 (secp256k1 압축; Ed25519는 00 ‖ 32바이트)
  1 flags (0; 01 = 경로 모름, §7.6 — 2026-11-07, 그 전에는 예약)   2 예약 0
```

- 경로 모름(flags `01`) 슬롯: 역할 인덱스가 900–999여야 한다. 모든 슬롯이 경로 모름인 record의 마스터 지문은 `00000000`이어야 하고, 지문 규칙("같은 니모닉")은 경로를 아는 슬롯이 있는 record끼리만 본다. 같은 역할(경로 식별) = 같은 공개키 규칙은 그대로다. 경로를 아는 슬롯만 있는 record는 바이트가 이전과 같다. 이전 버전은 flags ≠ 0을 예약 바이트 위반으로 보고 payload 전체를 `UnsupportedPayload`(업데이트 안내, `.prev` 제안 없음)로 거부한다 — 손상으로 다루지 않는다.

- 순서: tag 1 → 2 → 3 → 4 → **5**(0–8개). tag 5만 있는 payload = **YubiKey 지갑**(니모닉 없음; [02] §8.5 키 전용 vault와 같이 `has_mnemonic() = false`, 파생 호출은 `NoMnemonic`). 가져온 키와 함께 있을 수 있다.
- 디코드 거부(`UnsupportedPayload`): 알 수 없는 코드, 예약 바이트 ≠ 0, 슬롯 수 0·25 이상, §3.5 규칙 1–5 위반, 곡선과 공개키 형식 불일치, 곡선 위에 없는 공개키, 같은 일련번호 두 record, record 간 지문 불일치, 같은 경로·다른 공개키, 9번째 record.
- 상한: `MAX_RECORDS` 46 → **54**, `PAYLOAD_CT_MAX` 4,096 → **16,384**(최대 평문 3,170 + 8 × 1,189 = 12,682바이트). 호환: 이 버전 이전의 앱은 tag 5를 만나면 `UnsupportedPayload`(업데이트 안내, `.prev` 제안 없음)로 멈춘다. payload 암호문이 4,096바이트를 넘는 vault는 이전 앱이 구조 단계에서 `Malformed`로 본다 — [04] §6.6과 같이 **되돌린 앱에서 `.prev` 복구를 하지 말고 새 버전을 다시 설치한다.** YubiKey를 등록하지 않은 vault는 바이트가 전혀 바뀌지 않는다.
- 비밀이 없으므로 `add_hardware_key`는 비밀번호를 다시 묻지 않는다(`PayloadRewrite`). 지우기(`remove_hardware_key`)는 비밀번호를 다시 묻는다(실수로 계정을 잃지 않게). 니모닉 없는 vault의 마지막 record는 지울 수 없다(`LastKey`).
- meta(`yw-meta/3`)에는 선택 최상위 키 `hw_accounts`(라벨·숨김·선택; 주소는 표시 캐시)만 더한다 — 진실 원천은 vault의 tag 5다(잠금 해제 때 다시 계산). 형식(구현 2026-11-05, [02] §5.3의 "새 최상위 키" 규칙: 없으면 빈 값, 기본값이 아닐 때만 씀, 안쪽은 엄격 검사, 이전 버전은 모르는 키로 보존): `{"evm": [Account], "sol": [Account], "sol_selected": i | null, "defaults": [serial]}` — `Account`는 `evm_accounts`와 같은 `{index, label, address, hidden}`(index 오름차순·중복 없음, 주소 비어 있으면 안 됨, 체인당 192개 이하), `sol_selected`는 `sol`에 있는 index, `defaults`는 등록 때 기본 PIN·관리 키가 보였던 카드의 일련번호(오름차순, 8개 이하, "기본 PIN 사용 중" 안내 §9.3). EVM 선택은 `prefs.evm_account`의 `{"hardware": i}`(이전 버전은 prefs를 기본값으로 되돌림 — 허용). Bitcoin YubiKey 계정은 `btc_accounts`의 `key.yubikey`(§6.3)다.

## 9. PIN 처리

### 9.1 입력

- 사용자 결정(2026-11-05): PIN 입력은 기존 비밀 입력 창에 **새 종류(PIN)** 를 더해 받는다 — 캡처 제외, 복사 금지, 사용 후 즉시 지움.
- PIN·관리자 PIN·PUK·관리 키는 **우리의 비밀 입력 창**(D11: 캡처 제외, 직접 그린 입력, 복사 금지)에서만 받는다. Windows의 스마트카드 PIN 대화상자(minidriver)는 쓰지 않는다(PC/SC로 직접 VERIFY).
- 입력 버퍼는 `Zeroizing`이고, **한 작업(서명 1건, 등록 1회)이 끝나면 지운다.** 작업 사이에 PIN을 캐시하지 않는다. Bitcoin 다중 입력 거래는 "한 작업"이므로 입력마다 같은 PIN 버퍼로 VERIFY한다(카드가 PSO:CDS 한 번마다 PW1을 요구).
- 길이 검사: OpenPGP PW1 6–127, PW3 8–127, PIV PIN·PUK 6–8(ASCII, `FF` 금지). 남은 횟수가 1이면 "한 번 더 틀리면 PIN이 잠깁니다"를 입력 전에 보인다(OpenPGP `C4`, PIV 메타데이터 `06`).
- 구현(2026-11-05): 서명 PIN 창은 **W11 `SecretKind::CardPin { min, max, touches }`**(`ui::secret`): 기존 비밀 입력 창과 같이 캡처 제외 우선·직접 그린 입력·복사 금지·ASCII, 가린 칸 하나, 길이는 키가 있는 애플릿의 범위(OpenPGP 6–127, PIV 6–8)를 넘겨받는다. 제목 "YubiKey PIN", 안내 "YubiKey를 연결하고 PIN 입력 후 터치하세요", 그 아래 서명할 키(역할·경로)·이 키를 가진 YubiKey 일련번호·직전 시도의 오류(남은 횟수, 1회면 잠김 경고), 터치가 여러 번이면 "YubiKey 터치 N회가 필요합니다". 남은 횟수는 창이 열릴 때 카드를 읽어 입력 전에 보인다(아래 2026-11-07). 제출된 PIN은 `Zeroizing` 버퍼 그대로 카드 작업(`KeyJob::*Card`의 `pin`)으로 옮겨지고 작업과 함께 지워진다(SOL 전송은 blockhash를 받는 동안 `PinBuffer`로 보관, 잠금·취소 때 지움). 작업 사이 캐시는 없다. 등록 마법사의 관리자 PIN·PIV 관리 키와 PIN·PUK 바꾸기는 **W12** `SecretKind::CardSecret`(같은 규칙: 캡처 제외 우선·가림·복사 금지·ASCII; 관리 키는 16진수 정확히 48자리; PIV PIN 6–8; "PIN 하나로 통일"은 현재 값(비우면 공장 기본값, 아니면 8자)·새 8자·새 8자 확인)다. 제출된 값은 `Zeroizing` 버퍼 그대로 키 작업자 작업(`YkJob::Enrol`·`ChangePin`·`ProtectManagementKey`·`SetPins`)으로 옮겨지고 작업과 함께 지워진다(관리자 PIN은 W12 → 관리 키·PIV PIN W12 사이에만 마법사가 보관). 새 관리 키를 보여 주는 창(옛 W13)은 없앴다(2026-11-06): 관리 키는 사용자가 보거나 입력하지 않는다(§9.3).
- **남은 횟수를 입력 전에(2026-11-07)**: W11이 열릴 때 `YkJob::Counters(CounterTarget::Key(role))`, W12(관리자 PIN·PIV PIN·PIN 바꾸기·통일·슬롯 구성 바꾸기·비우기)가 열릴 때 `Counters(CounterTarget::Card(serial))`로 카드를 읽기만 해서(OpenPGP `6E`/`C4`의 PW1·PW3, PIV GET METADATA `80`의 PIN) 창 설명에 "OpenPGP PIN: 남은 시도 N회"를 보인다. 1회면 "남은 시도 1회 — 한 번 더 틀리면 잠깁니다.", 0회면 "잠김". 등록 마법사는 자격 정보 화면에서 식별할 때 읽은 값을 바로 보인다. 틀린 PIN의 문구도 남은 횟수를 담는다(1회면 같은 경고).
- **관리자 PIN 마지막 시도(2026-11-07)**: PW3가 1회 남은 카드에는 사용자 확인 없이 관리자 PIN을 보내지 않는다. 어댑터(`yubikey::admin_guard`, 읽기만)가 등록·슬롯 구성 바꾸기·비우기(우리 슬롯)·관리자 PIN 바꾸기·통일 전에 `C4`를 보고 `AdminLastTry`("…1회 남았습니다. 한 번 더 틀리면 잠깁니다… 정확한 관리자 PIN이 확실하면 다시 입력해 제출하세요")로 멈춘다(아무것도 보내지 않음, 통일은 PIV 단계 전에 멈춤). 이 오류를 본 뒤 **같은 카드에 다시 제출하면** 작업이 `admin_last_try: true`를 실어 마지막 시도를 보낸다(`CardUi::admin_last_try`, 한 번만 쓰임). PIV PIN은 PUK로 풀 수 있으므로 경고만 한다.

### 9.2 서명 중 표시

승인 → **"YubiKey를 연결하고 PIN 입력 후 터치하세요"** 단계(PIN 입력 칸, 연결된 YubiKey의 일련번호, 이 계정의 키를 가진 YubiKey 목록) → PIN 확인 뒤 "YubiKey가 깜박이면 터치하세요"(터치 대기 최대 15초는 카드가 정한다; 시간이 지나면 `6982` → "터치 시간이 지났습니다. 다시 시도하세요") → 카드 서명 → 기존 서명 후 검증 → 기존 저장·전송.

구현(2026-11-05, `app_card`):

- 승인(consume) 뒤 서명자가 YubiKey 키인 승인(`EvmKeySource::Hardware`, `SolKeySource::Hardware`, `BtcAccountKey::Hardware` 계획, YubiKey 출처의 Solana·Bitcoin dApp 메시지)은 소프트웨어 작업(`SignEvm`·`SignMessage`·`SignChainMessage`·`SignSol`·`SignBtc`) 대신 **카드 단계**(`CardStep`, `Purpose::CardSign(id)`)에 보관되고 W11이 열린다. 소프트웨어 계정의 경로는 그대로다(같은 작업, 같은 순서).
- PIN 제출 → `SignEvmCard`·`SignMessageCard`·`SignChainMessageCard`·`SignBtcCard`(입력마다 같은 PIN으로 카드 서명 1회) 또는 SOL은 blockhash 조회 뒤 `SignSolCard`(SOL 서명 기한 20초는 PIN 제출 시각부터 잰다). 결과는 기존 `SignedEvm`·`SignedMessage`·`SignedChainMessage`·`SignedSol`·`SignedBtc` 처리로 간다(실패 문구는 `CardJobError` 문구).
- 키 작업자는 승인을 쓰기 **전에** 카드에서 PIN을 확인한다(`yubikey::sign::check_pin`: 일련번호·기록 공개키 확인 뒤 VERIFY 한 번, 쓰기·서명 명령·터치 없음). 틀린 PIN·다른 카드·카드 없음이면 쓰지 않은 승인을 돌려주고(`KeyOutcome::CardUnused`) 실패 결과를 보낸다. 앱은 카드 단계가 상한(승인 뒤 120초) 안이고 PIN이 잠기지 않았으면 그 실패를 보이지 않고 W11을 오류와 함께 다시 연다. 그 밖에는 승인을 버리고 실패를 보인다.
- W11 취소·닫기·창이 열리지 못함(캡처 제외 거부 등)·120초 초과는 승인을 버린다(아무것도 서명하지 않음). dApp에는 4001(사용자 거부), 120초 초과는 -32603. 잠금은 보관 중인 승인과 PIN을 지우고 dApp에 4001을 보낸다.
- **공장 기본 PIN으로는 서명하지 않는다(2026-11-07)**: 키를 가진 카드 중 하나라도 `hw_accounts.defaults`에 있으면(등록 때 기본값을 보았고 아직 바꾸지 않음) 카드 단계를 열지 않고 승인을 버린다. 입력한 PIN이 공장 값 `123456`(OpenPGP PW1·PIV PIN)이면 카드에 보내지 않고 같은 처리를 한다. 둘 다 dApp에는 실패, 배너 "이 YubiKey는 아직 공장 기본 PIN을 쓰고 있어 서명하지 않았습니다…", 메인 창 머리에 "PIN 설정" 버튼(`ids::PIN_NEEDED_OPEN` → 설정 → YubiKey의 그 카드 "PIN 설정")이 남는다(PIN 설정을 마치면 사라짐).

### 9.3 기본값 변경 안내

등록 중 기본값을 발견하면(`DefaultsSeen`: 성공한 관리자 PIN이 `12345678`, PIV PIN 메타데이터 기본, 관리 키 메타데이터 기본; 보호 여부 `piv_management_protected`) 등록 직후 바꾸도록 안내한다. 사용자 결정(2026-11-06): **PIV 관리 키는 자동으로 처리한다** — 이 PC의 OS 난수로 AES-192 키를 만들어 SET MANAGEMENT KEY하고 PIN으로 보호해 카드에 저장한 뒤(PRINTED + ADMIN DATA, `ykman … --generate --protect`와 같음, §5.3.3) 지운다. 사용자는 관리 키를 보지도 입력하지도 않는다. 사용자가 정하는 것은 숫자 PIN뿐이다. 기본값이 남은 카드는 서명하지 않는다(2026-11-07, §9.2; 정보는 meta `hw_accounts.defaults`에).

구현(2026-11-06): 카드 "기본값 변경 / PIN 설정 — YubiKey #n"(`App::yk_pin_items`)은 등록 결과 화면(`가져오기`와 `가져오기 없이 등록` 둘 다 — 나중에 다시 연결할 때 PIN을 정하려는 경우)과 설정 → YubiKey 목록의 카드별 `PIN 설정 / 기본값 변경 (PIN 안내)`에서 연다. 내용:

- 남은 기본값 경고(결과 화면에서 본 것), **PIN 안내**: OpenPGP PIN — EVM·Bitcoin 서명할 때마다(기본 123456, 6자 이상); OpenPGP 관리자 PIN — 키를 넣을 때·OpenPGP PIN이 잠겼을 때(기본 12345678, 8자 이상); PIV PIN — Solana 서명할 때(기본 123456, 6–8자); PIV PUK — PIV PIN이 잠겼을 때 풀기(기본 12345678, 6–8자); PIV 관리 키 — 앱이 자동으로 만들어 PIN으로 잠가 보관(입력할 필요 없음). 각각 3번 틀리면 따로 잠기고, 하나가 잠겨도 다른 애플릿은 그대로이며, FIDO2·패스키 로그인과는 관계없다. "편하게 쓰려면: 8자리 하나로 통일하세요 (네 개 모두 같은 값). 기본값 그대로 두면 YubiKey를 가진 사람이 서명할 수 있습니다."
- 방식 라디오, 기본 **"8자리 하나로 통일 (권장)"**: `PIN 설정하기 (8자리 하나)` → W12 `CardSecretKind::SetPins`(현재 값: 비우면 공장 기본값, 전에 통일했다면 그 8자; 새 PIN 정확히 8자 두 번 — PIV 6–8, OpenPGP PIN 6+, 관리자 PIN 8+를 모두 만족하는 길이) → `YkJob::SetPins` → `yubikey::set_pins`. 안전한 순서로 하나씩: **PIV PIN → PIV PUK → PIV 관리 키(새 PIN으로 VERIFY 뒤 `protect_management_key`; 이미 보호돼 있으면 건너뜀) → OpenPGP 관리자 PIN → OpenPGP PIN**. 처음 실패에서 멈추고 `PinReport { done, skipped, failed }`로 바뀐 것·건너뛴 것(카드에 없는 애플릿)·실패한 것을 그대로 보인다("바꾼 것: …. 실패: … — 그 뒤 항목은 바꾸지 않았습니다."). 첫 단계부터 실패하면 아무것도 바뀌지 않았으므로 창이 오류와 함께 남는다. 같은 값을 쓰는 대가(잠기기 전 시도 횟수가 늘고 서명 PIN이 관리자 권한도 준다; 개인용으로는 괜찮다)를 짧게 안내한다.
- **"하나씩 따로"**: `OpenPGP PIN`·`OpenPGP 관리자 PIN`·`PIV PIN`·`PIV PUK`는 W12(현재·새·새 확인) → `YkJob::ChangePin` → CHANGE REFERENCE DATA(OpenPGP `24 81`/`83`, PIV `24 80`/`81`); `PIV 관리 키 자동 보호`는 W12 PIV PIN → `YkJob::ProtectManagementKey`. 관리 키가 기본값도 보호도 아니면 `ManagementKeyUnknown`("`ykman piv access change-management-key --generate --protect`로 바꾼 뒤 다시").
- 바꾼 기본값이 모두 없어지면(또는 통일이 실패 없이 끝나면) 그 일련번호를 `hw_accounts.defaults`에서 지운다. 새 PIN은 저장하지 않는다. YubiKey 목록에서 "하나씩 따로"로 바꾼 경우는 이번 세션에 그 카드 애플릿의 PIN·관리자 PIN(OpenPGP)과 PIN·PUK·관리 키 보호(PIV)를 모두 바꿨을 때 지운다(`CardUi::list_pins_done`).
- **건너뛸 수 없음(2026-11-07)**: 기본값은 서명을 막는다(§9.2). 새 YubiKey 지갑(`wizard.created`)의 결과 화면은 "PIN 설정"을 마칠 때까지(`YkWizard::pins_done`: 통일 성공, 또는 애플릿별로 모두 바꿈) `완료`·`다른 YubiKey 등록(백업)`이 꺼지고 T-YK-PINS-FIRST를 보인다.

## 10. 기존 기능과의 상호작용

| 기능 | YubiKey 계정에서 |
|---|---|
| 승인 창·digest([03] §11) | 변화 없음. 서명자 종류(`Signer`)는 digest에 들어가지 않고 계정 주소가 묶는다. YubiKey EVM 계정은 키 출처 `EvmKeySource::Hardware(i)`(vault는 이 출처에 키를 빌려 주지 않고 `RecordNotFound`, 주소는 tag 5의 공개키에서 계산)로 표시하고, 승인 창에 "YubiKey로 서명" 배지와 이 키를 가진 YubiKey 목록을 더한다. 구현(2026-11-05): 배지 "YubiKey로 서명 · #일련번호… · 터치 N회"(Bitcoin은 입력 수)는 헤더의 앱 배지 줄(사용자 체인·테스트넷 배지와 같은 곳)에 그리며 요청의 `ApprovalDisplay`·display 바이트·digest에는 들어가지 않는다([03] §11.3) |
| EVM 보내기·dApp(`eth_sendTransaction`·`personal_sign`·`eth_signTypedData_v4`) | 같은 준비·시뮬레이션·위험 규칙. 서명 단계만 카드(§9.2). 서명 결과는 §6.2 후 기존 서명 후 검증 |
| 승인 만료(D23, 120초) | 승인 클릭까지가 기존 규칙이다. 승인 뒤 카드 단계는 별도 상한 120초(PIN 입력·터치 포함), 넘으면 취소 |
| Bitcoin 보내기 | 단일 주소 계정(§3.3). 입력마다 카드 서명, 수수료 서명 크기 72+1(§6.3). dApp 메시지 서명도 카드로 한다: BIP137(카드 DER → compact, 복구 id는 기록된 공개키를 복구하는 값, 헤더는 주소 형식), BIP322 simple(P2WPKH: `to_sign`의 BIP143 sighash를 카드로 서명한 witness)·full(P2SH-P2WPKH) — `btc::msgsign::sign_message_card`(vault 경로와 같은 승인 검사, 기존 검증기로 시험) |
| 계정 목록 | EVM·Solana·Bitcoin 탭에 "[YubiKey]" 배지로 나온다(선택·이름 바꾸기·숨기기는 탭이 지원하는 만큼; Bitcoin 탭은 이름·숨김 없음). 받기 주소·QR은 기록된 공개키의 주소. "개인키 보기"는 없다(설정의 버튼도 YubiKey 계정이 선택되면 꺼짐). dApp 연결 목록(EVM `eth_requestAccounts`, Solana·Bitcoin 연결)에도 들어간다. 숨긴 YubiKey 계정은 그 키를 가진 카드를 다시 등록하면 다시 보인다 |
| Solana 보내기·메시지 서명(SIWS 포함) | PIV Ed25519로 메시지 원문 서명(§5.3), 기존 템플릿·서명 후 검증 그대로 |
| 키 전용 지갑·가져온 키 | 같은 vault에 공존. YubiKey 지갑에는 "계정 추가(파생)"·"복구 단어 보기"가 없다(`has_mnemonic = false`) |
| 잠금·자동 잠금(D12) | 잠긴 동안 카드 작업 없음. 잠금은 진행 중인 카드 작업의 PIN 버퍼를 지우고 PC/SC 연결을 끊는다(이미 카드로 보낸 한 APDU는 끝까지 간다) |
| 저널([02] §5.4) | 변화 없음(서명 결과만 저장) |
| 백업 확인 | 새 YubiKey 지갑은 등록 전에 메모리 안에서 한다(§7.1) |
| 복구 단어 보기 | YubiKey 지갑에는 없다(저장하지 않으므로) |

## 11. 제한과 범위 밖

- 탭루트(P2TR) — BIP340 없음. YubiKey 하나에 secp256k1 키 3개 이상 — OpenPGP 슬롯 2개(DEC는 복호 전용).
- OpenPGP KDF-DO 켜진 카드, OpenPGP 4.x 이전 카드 형식, YubiKey 4 이하.
- YubiKey에서 키 **생성**(on-card generation): 니모닉 백업이 불가능하므로 하지 않는다.
- PIV P-256 등 다른 곡선, PIV 인증서 쓰기, 증명(attestation) — 가져온 키는 증명 대상이 아니다.
- 터치 없는 정책(`Never`)은 마법사가 제안하지 않는다(읽기는 허용).
- FIDO/U2F·OTP·OATH 애플릿은 건드리지 않는다.
- 카드 쪽 표시(화면) — 없다. 표시 무결성은 PC에 남는다(§1).

## 12. 테스트

### 12.1 자동 (게이트, 실제 카드 없음)

- `yubikey::mock::MockCard`: OpenPGP(SELECT, F1, 6E, F9, VERIFY 81/82/83, C1–C3(RSA 2048·4096·secp256k1), D6–D8, 3FFF 가져오기, 47 81, PSO:CDS, INTERNAL AUTHENTICATE, CHANGE REFERENCE, TERMINATE E6·ACTIVATE 44)와 PIV(SELECT, FD, F8, F7, VERIFY, 87 관리 키·서명, FE, FF, 24, GET/PUT DATA `CB`/`DB` — ADMIN DATA·PRINTED, PRINTED 읽기는 VERIFY PIN 뒤에만, 쓰기는 관리 키 인증 뒤에만; `protect_management` = ykman `--generate --protect` 상태; RESET RETRY COUNTER 2C·PUK 횟수, DELETE KEY F6, RESET FB), 체이닝·`61xx`, PIN 횟수·잠김, PW1 일회성, PIN 정책 "항상", 터치 거부, high-s, 손상 서명. 관리 키 블록 암호는 테스트용 `ToyCipher`(AES가 아님 — 실제 AES·3DES는 yw-win CNG에서 FIPS-197·SP 800-67 벡터로 시험).
- 벡터: `abandon`×11 `about`로 SIG = EVM 0 → `0x9858EfFD232B4033E47d90003D41EC34EcaEda94`, AUT = BIP84 0 → `bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu`, PIV 82 = Solana 0 → `HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk`, 지문 `73c5da0a`.
- 서명: high-s 카드에서도 EVM 복구 주소 = 등록 주소, BIP143 P2WPKH sighash 서명 검증(low-s), Solana 1,000바이트 메시지(체이닝) `verify_strict`, 서명 흐름에 쓰기 명령 없음.
- 오류: 틀린 PIN(남은 횟수), 3회 → 잠김, 터치 없음, 손상 서명, 다른 일련번호(PIN 전 거부), 덮어쓴 슬롯, KDF, 구 펌웨어, 틀린 관리자 PIN·관리 키(쓰기 0), 애플릿 없음.
- 계획: 슬롯별 인덱스 선택·경로 문자열, 한 카드 안 같은 경로 거부(공유 키 변형 포함), 다른 카드와 같은 경로는 백업 표시가 있을 때만, 다른 니모닉 거부, 같은 카드 재등록 거부, 카드 3개가 EVM 0–5를 나눠 갖고 4번째가 #1의 백업인 슬롯 표와 라우팅(`slot_on_card`).
- record 코덱: 왕복, 코드·예약 바이트·패딩 변조 거부, record 간 일관성. vault: YubiKey 지갑 생성·잠금 해제 후 동일·추가·중복 일련번호·모순 record·삭제(비밀번호·`LastKey`)·최대 크기(24단어 + 가져온 키 45개 + 카드 8 × 24슬롯)가 상한 안·9번째 거부, tag 6이 `UnsupportedPayload`.
- yw-win: CNG AES-128/192/256·3DES 한 블록 KAT, PC/SC 다중 문자열 파서·오류 매핑(리더 불필요).

### 12.2 수동 (사용자 YubiKey)

[docs/acceptance/yubikey-20261104.md](../docs/acceptance/yubikey-20261104.md). 실제 카드 진단(`yw_win::pcsc` 읽기 전용 테스트, `#[ignore]`)은 `SCardListReaders`, SELECT, GET VERSION/SERIAL, GET DATA `6E`·`F9`, GET METADATA만 보낸다.

## 13. 구현 상태와 남은 작업 (2026-11-05)

완료:

- yw-core: §4의 `yubikey` 모듈 전부(APDU·TLV, OpenPGP·PIV 흐름, 슬롯 계획·검사, tag 5 코덱, 등록, 카드 서명, 후처리, 에뮬레이터), vault tag 5(`hardware_keys`·`add_hardware_key`·`remove_hardware_key`·`create_with_hardware`), `EvmKeySource::Hardware`(vault 서명 경로는 거부, 주소는 슬롯 표에서), EVM 카드 서명 진입점 `evm::sign::{sign_transaction_card, sign_personal_card, sign_typed_data_card}`(승인 검사 → 카드 → 기존 서명 후 검증).
- yw-core Solana(§6.4): `SolKeySource::Hardware`(tag 7; vault 서명 거부, 공개키는 슬롯 표에서), `sol::sign::sign_transfer_card`, `sol::msgsign::sign_message_card`. 시험: 에뮬레이터 카드 서명 = 템플릿 메시지의 RFC 8032 서명, 서명 후 검증, 쓰기 명령 없음, 기한·출처·수수료 규칙·파싱 거부, 거래 모양·오프체인 메시지 거부, 터치 없음·다른 카드·틀린 PIN, vault 경로 거부.
- yw-core Bitcoin(§6.3): 단일 주소 계정 `BtcAccountKey::Hardware`(`HwBtcKey::{Address, Evm}`, `Vault::hardware_btc_account`), 입력별 카드 서명 `btc::sign::sign_plan_card`(P2PKH·P2SH-P2WPKH·P2WPKH, P2TR 거부), 카드 입력의 완화 검사(`check_card_signature`, `verify_signed`에서도), 수수료 서명 크기 72 + 1, 승인 payload·저널·meta의 YubiKey 계정 식별(source 4·5). 시험: 세 형식 × (주소 키, EVM 공유 키) 두 입력 송금을 high-s·high-R 에뮬레이터로 서명(엄격 검사는 거부, 카드 검사는 통과), 잔돈 = 같은 주소, 입력당 터치 1회, 쓰기 명령 없음, 서명 후 검증·vsize, 저널·meta 왕복, vault 경로 거부, 터치 없음·다른 카드·틀린 PIN·다른 digest·high-s 응답·다른 계획 승인·탭루트 거부.
- yw-win: `pcsc`(PC/SC 래퍼, 읽기 전용 수동 진단 `pcsc_readonly_probe`), `cng`(AES·3DES 한 블록, KAT).
- yw-app(백엔드): `yubikey` 어댑터(`PcscTransport`, `CngCipher`, `CardSource`/`PcscSource`, `sign_evm_digest`, `enrol_first_card`), 키 작업자 작업 `EnrolYubiKey`·`HardwareKeys`·`SignEvmCard`·`SignMessageCard`(PIN은 작업이 소유하고 작업과 함께 지워짐), `SignFailure::Card`·`MessageSignFailure::Card`. 작업자 수준의 EVM 종단 시험(지갑 가져오기 → 에뮬레이터 YubiKey 등록 → 승인된 Sepolia 전송을 카드로 서명 → 서명 후 검증 → `Signed` 저널 기록, `personal_sign`, 틀린 PIN·다른 카드·카드 없음, vault 경로 거부).
- yw-core(2026-11-05): `yubikey::sign::check_pin`(서명 전 PIN 확인, 쓰기·서명·터치 없음), `sign_btc_checked`, `btc::msgsign::sign_message_card`(BIP137·BIP322 simple/full, §10).
- yw-app 연결(2026-11-05):
  - meta `hw_accounts`(§8)와 `EvmAccountPref::Hardware`(`{"hardware": i}`). 잠금 해제·등록 뒤 meta를 읽을 때 tag 5 슬롯 표로 맞춘다(`reconcile_hardware`, 가져온 키의 `reconcile_imported`와 같은 방식: 새 키는 기본 이름 "YubiKey 계정 n"·"YubiKey Solana n"으로 추가, 없어진 키는 삭제, 주소 캐시 재계산, 사라진 선택은 되돌림; Bitcoin은 `KeyRole::Btc` 슬롯과 공유 키의 Bitcoin 용도마다 `btc_accounts`의 단일 주소 계정 `key.yubikey`를 만들고 키가 없어진 계정을 지움).
  - 세 탭의 계정 목록·배지·받기·dApp 연결 목록(§10 표), W11 PIN 창과 카드 단계(§9.1, §9.2), 키 작업자 작업 `SignSolCard`·`SignBtcCard`·`SignChainMessageCard`(+ `SolSignFailure::Card`·`BtcSignFailure::Card`, 저널 처리는 `sign_sol_with`·`sign_btc_with`로 소프트웨어 경로와 같음), `KeyOutcome::CardUnused`.
  - 등록 진입점(마법사가 부름): `App::enrol_yubikey(EnrolRequest)` → `KeyJob::EnrolYubiKey`; 결과 `App::on_yubikey_enrolled`가 `CardUi::enrol`(`EnrolState::{Running, Done { serial, slots, defaults }, Failed}`)을 채우고, 기본값이 보였으면 일련번호를 `hw_accounts.defaults`에 더하고, `HardwareKeys`·`LoadMeta`로 계정을 다시 맞추고, 그 카드의 키로 숨겨 둔 계정을 다시 보인다.
  - 시험: meta 왕복·엄격 검사·이전 파일·이전 버전 보존, 등록 뒤 세 체인 계정(`abandon` 벡터 주소), 에뮬레이터로 `SignSolCard`·`SignBtcCard` 종단(저널 기록, 서명 검증, high-s·high-R 카드, 입력당 카드 서명 1회, 틀린 PIN은 승인 반환·저널 없음), App 수준(승인된 EVM 전송 → W11 카드 단계 → 틀린 PIN 재요청 → `SignEvmCard` 저널, 취소, 소프트웨어 계정은 `SignEvm`, `enrol_yubikey` 진입점), W11 입력 규칙.

- 등록 마법사·YubiKey 지갑(2026-11-05, [04] §2.19):
  - yw-core: `bip39::Mnemonic::{generate, backup_positions, backup_words_match}`(vault 백업 확인과 같은 함수), `plan::{validate_before_card, address_texts}`, `enrol::{preview_seed, seed_identity, adopt_card}`, 에뮬레이터 PIV PUK 변경, `sol::recipient::KnownKind::OwnHardware`("내 계정(YubiKey)").
  - yw-app: S21 마법사(키·슬롯 → W05/W06 → 확인 → 자격 정보 W12 → 결과, `다시 확인`, 기본값 바꾸기 W12(2026-11-06부터 §9.3 "PIN 설정"), `다른 YubiKey 등록(백업)`), S01 카드 → S20 → W01 → W08 → W10 → 마법사 → `create_with_hardware`(니모닉 없음), "가져오기 없이 등록"(§7.5), 설정 → YubiKey(카드·슬롯·계정별 보유 카드·`삭제` + W03), 키 작업자 `KeyJob::YubiKey(YkJob)`(단어·시드·새 관리 키를 보관하고 `Discard`·잠금에 지움), 어댑터 `change_card_pin`·`change_management_key`·`check_record`·`adopt_first_card`, 승인 창 배지(앱 배지 줄, digest 밖), Solana 받는 사람 "내 계정(YubiKey)", 투어 장면 35–43.
  - 시험(에뮬레이터만): 기존 지갑 마법사 종단(SIG = EVM 2, AUT = BIP84 0, Solana 1·2 → 확인 화면의 경로 `m/44'/60'/0'/0/2`·`m/84'/0'/0'/0/0`·`m/44'/501'/1'/0'`·`m/44'/501'/2'/0'`과 vault 파생과 같은 주소, 같은 니모닉 경고, 세 탭의 계정, 다시 확인, PIV PIN·PUK 변경), 다른 카드의 같은 경로 거부·백업 복사본 등록·같은 카드 재등록 거부(쓰기 없음)·기록 삭제(틀린 비밀번호, 백업이 계정 유지)·바뀐 관리 키(기본 키 실패 → 새 키 성공)·W13 확인 뒤에만 설정, YubiKey 지갑 생성(틀린 단어 → 새 위치, `has_mnemonic = false`, 기록 1개, 재시작·잠금 해제 뒤 같은 계정, 중간 잠금이 단어를 지움), 키 작업자 작업(미리보기 카드 통신 없음, 틀린 관리자 PIN은 기록 없음, PW1 변경, 관리 키 보관·설정, 삭제, 가져오기 없이 등록 쓰기 없음, `Discard`·잠금), W12/W13 입력 규칙, 배지가 digest된 표시에 없음, 화면별 명령 ID 중복 없음.

남은 작업:

1. ~~복구 단어만 있는 새 PC에서 "YubiKey 지갑 복구"~~ → 2026-11-07 §7.6 "YubiKey 연결하기 (복구 단어 없이)"로 대신했다(복구 단어도 필요 없음). 남은 것: 연결한 카드의 경로를 나중에 니모닉으로 맞추기(§7.6 "경로 맞추기").
2. 확인 화면에서 카드의 실제 펌웨어·현재 키 유무를 읽어 보이는 것(§7.4 "읽을 수 있으면 현재 키가 있는지"; 지금은 결과 화면에서 기록의 펌웨어만, 확인 화면은 일반 안내).
3. 관리 키가 기본값도 PIN 보호도 아닌 카드(직접 정한 키)의 자동 보호 — 지금은 `ManagementKeyUnknown`과 ykman 안내. PIN에서 파생한 옛 관리 키(ADMIN DATA salt)는 지원하지 않는다(`NotSupported`).
4. 실제 YubiKey 수동 판정(docs/acceptance/yubikey-20261104.md Y-01–Y-31, 사용자 수행). §15는 docs/acceptance/yubikey-manage-20261106.md YM-01–YM-13.

- PIN으로 보호된 관리 키·PIN 설정(2026-11-06, §5.3.3, §9.3):
  - yw-core: `piv::{get_data, put_data, AdminData, parse_protected_key, encode_protected_key, ManagementState, ManagementCredential, MgmtKey::random}`, `Piv::{get_object, put_object, admin_data, management_state, protected_management_key, authenticate_management, protect_management_key}`, `EnrolAuth::piv_pin`, `DefaultsSeen::piv_management_protected`, `CardError::{ManagementKeyProtected, ManagementKeyUnknown}`, 에뮬레이터 GET/PUT DATA·`protect_management`.
  - yw-app: 자격 정보 단계의 `YkJob::ProbeManagement`와 W12 PIV PIN(보호된 키), 등록 선택지 이름·설명, 결과 화면과 YubiKey 목록의 "기본값 변경 / PIN 설정"(PIN 안내, "8자리 하나로 통일" 기본 → `YkJob::SetPins`/`yubikey::set_pins`, "하나씩 따로" + `PIV 관리 키 자동 보호` → `YkJob::ProtectManagementKey`). 옛 `NewManagementKey`·`SetManagementKey`·W13 `ShowCardKey`·`change_management_key`는 지웠다.
  - 시험(에뮬레이터만): ADMIN DATA·PRINTED 바이트(ykman 배치), 보호된 카드 등록(PIN 없으면 `ManagementKeyProtected`, 틀린 PIN 남은 횟수, 맞는 PIN), 공장 키 → 자동 보호(PRINTED = 카드 키, flags `02`), 보호된 키 재생성, 모르는 키 거부; 키 작업자 `SetPins`(순서, PW1이 기본이 아니면 마지막 단계에서 멈추고 앞 네 개는 바뀜), `ProbeManagement`; 앱 수준 자동 보호·통일(네 값 모두 같음, 관리 키는 이미 보호돼 건너뜀)·다음 등록에서 "PIN으로 보호됨"; W12 입력 규칙.

- Zcash 슬롯·카드 바꾸기(2026-11-06, §3.1, §15):
  - yw-core: `plan::KeyRole::Zec`·`zec_address`(record role 4), `manage::{reslot_plan, validate_reslot, reslot_card, ClearMethod, ClearPlan, ClearReport, ClearAuth, clear_card}`, `OpenPgp::{delete_key, reset}`·`openpgp::{put_attributes, terminate, activate, RSA2048_ATTRIBUTES, RSA4096_ATTRIBUTES, INVALID_PIN}`, `Piv::{delete_key, reset}`·`piv::{delete_key, verify_invalid_pin, reset_retry_invalid, reset, DOCUMENTED_FIRMWARE_DELETE_KEY}`, `Vault::{check_replace_hardware_key, replace_hardware_key}`, 에뮬레이터 `E6`·`44`·`2C`·`F6`·`FB`·RSA 4096 속성(`WRITE_INS`에 `44`·`F6`·`FB` 추가).
  - yw-app: 마법사 OpenPGP "넣을 키" `Zcash 주소`(네트워크 라디오), YubiKey 목록의 `슬롯 구성 바꾸기`·`YubiKey 비우기`(`app_yubikey::manage`, `ui::screens_yubikey::manage`), 키 작업자 `YkJob::Manage(ManageJob::{ReslotPreview, Reslot, Clear})`, 어댑터 `yubikey::{reslot_card, clear_card}`, W05/W06/W12 목적 `YkPurpose::{ReslotMnemonic, ReslotPassphrase, ReslotAdminPin, ClearAdminPin, ClearPivPin}`, 명령 id 13,310–13,387.
  - 시험(에뮬레이터만): §15.1·§15.4의 두 App 수준 시험.

## 14. 출처

- [Y-523] Yubico, YubiKey 5.2.3 Enhancements to OpenPGP 3.4 — secp256k1 등 곡선 목록: https://developers.yubico.com/PGP/YubiKey_5.2.3_Enhancements_to_OpenPGP_3.4.html
- [Y-PGP] YubiKey 5 기술 매뉴얼, OpenPGP: https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps-openpgp.html
- [Y-57] YubiKey 5.7 펌웨어 노트(Ed25519·X25519 PIV, "As of 5.7.4" 가져오기 문구): https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-firmware-5.7.html
- [Y-PIVM] YubiKey 5 기술 매뉴얼, PIV(기본 PIN·PUK·관리 키, 5.7 AES-192): https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps-piv.html
- [Y-IMP] Yubico .NET SDK, PIV IMPORT ASYMMETRIC KEY(관리 키 인증 필요, 없으면 `6982`): https://docs.yubico.com/yesdk/users-manual/application-piv/apdu/import-asym.html
- [Y-SIGN] Yubico .NET SDK, PIV GENERAL AUTHENTICATE 서명: https://docs.yubico.com/yesdk/users-manual/application-piv/apdu/auth-sign.html
- [Y-EXP] Yubico .NET SDK, PIV 개인키("a YubiKey will never return a private key"): https://docs.yubico.com/yesdk/users-manual/application-piv/private-keys.html
- [KIT-PIV] yubikey-manager `yubikit/piv.py`(KEY_TYPE, `authenticate`, `put_key` tag 06/07/08, AA/AB, GET METADATA 태그, 버전 조건): https://github.com/Yubico/yubikey-manager/blob/main/yubikit/piv.py
- [KIT-PIVMAN] yubikey-manager `ykman/piv.py`(`OBJECT_ID_PIVMAN_DATA = 0x5FFF00`, `OBJECT_ID_PIVMAN_PROTECTED_DATA = OBJECT_ID.PRINTED`; `PivmanData`: `Tlv(0x80)` 안 `0x81` flags(`0x01` puk_blocked, `0x02` mgm_key_protected)·`0x82` salt·`0x83` PIN 시각 `>I`; `PivmanProtectedData`: `Tlv(0x88)` 안 `0x89` key; `get_pivman_protected_data`는 "requires PIN verification"; `pivman_set_mgm_key`의 순서; 2026-11-06 확인): https://github.com/Yubico/yubikey-manager/blob/main/ykman/piv.py — `get_object`/`put_object`(`INS_GET_DATA 0xCB`·`INS_PUT_DATA 0xDB`, P1P2 `3F FF`, `5C` id + `53` 내용)는 [KIT-PIV].
- [KIT-PGP] yubikey-manager `yubikit/openpgp.py`(GET VERSION `F1`, UIF 값·버전, EcAttributes, 가져오기 템플릿, KDF): https://github.com/Yubico/yubikey-manager/blob/main/yubikit/openpgp.py
- [KIT-SC] yubikey-manager `yubikit/core/smartcard/__init__.py`(확장 APDU는 USB만, 최대 3,062바이트, 체이닝·GET RESPONSE): https://github.com/Yubico/yubikey-manager/blob/main/yubikit/core/smartcard/__init__.py
- [OPC] Functional Specification of the OpenPGP application on ISO Smart Card Operating Systems, v3.4(.1): https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf — AID p12·p15, DO C4 p23, UIF p24, 속성 p35, 가져오기 p38–39, VERIFY p52, PSO:CDS p63–64, INTERNAL AUTHENTICATE p71–72, 공개키 읽기 p74–75, KDF-DO p19.
- 메모: Ed25519 EdDSA 속성(`16 2B 06 01 04 01 DA 47 0F 01`)은 명세 3.4.1이 아니라 yubikit에서 온다(이 지갑은 OpenPGP Ed25519를 쓰지 않는다). OpenPGP X25519 가져오기는 바이트를 뒤집지만 이 지갑은 X25519를 쓰지 않는다.
- [KIT-PGP-RESET] yubikey-manager `yubikit/openpgp.py`(2026-11-06 확인): `INS.TERMINATE = 0xE6`, `INS.ACTIVATE = 0x44`, `_INVALID_PIN = b"\0" * 8`; `reset()` = PW1(`81`)·PW3(`83`)마다 `get_pin_status`의 남은 횟수만큼 `VERIFY(0, pw, _INVALID_PIN)`(오류 무시) → `TERMINATE(00 E6 00 00)` → `ACTIVATE(00 44 00 00)`; `delete_key(key_ref)` = 펌웨어 4 이상에서 "Delete key by changing the key attributes twice" — `put_data(속성 DO, RSA 4096)` 뒤 `set_algorithm_attributes(RSA 2048)`(1–3.x는 무작위 RSA 키로 덮어쓰기).
- [KIT-PIV-DELETE] yubikey-manager `yubikit/piv.py`(2026-11-06 확인): `INS_MOVE_KEY = 0xF6`, `INS_RESET = 0xFB`, `INS_RESET_RETRY = 0x2C`; `delete_key(slot)` = `require_version(5, 7, 0)` 뒤 `send_apdu(0, INS_MOVE_KEY, 0xFF, slot)`(`move_key(from, to)` = `send_apdu(0, INS_MOVE_KEY, to, from)`); `reset()` = `verify_pin("")`(FF 8바이트)을 남은 횟수가 0이 될 때까지, `_change_reference(INS_RESET_RETRY, PIN_P2, "", "")`를 PUK가 막힐 때까지, 그다음 `send_apdu(0, INS_RESET, 0, 0)`. 인증서 객체 id: `9A 5FC105`, `9C 5FC10A`, `9D 5FC10B`, `9E 5FC101`, `82`–`95` `5FC10D`–`5FC120`.
- [Y-PIV-RESET] Yubico .NET SDK, PIV Reset APDU: `00 FB 00 00`(데이터·Le 없음), PIN과 PUK가 막혀 있을 때만 `9000`, 아니면 `6985`; 모든 키·인증서를 지우고 PIN·PUK·관리 키를 기본값으로: https://docs.yubico.com/yesdk/users-manual/application-piv/apdu/reset-piv.html
- [Y-57-DELETE] YubiKey 5.7 펌웨어 노트: "As of YubiKey Firmware 5.7.4, any key can be deleted from any slot, including F9", 키 이동도 5.7.4부터(F9 제외). 관리 키 요구 여부는 이 문서에 없다(§15.5).

## 15. 카드 바꾸기: 슬롯 구성 바꾸기 · YubiKey 비우기 (2026-11-06)

설정 → YubiKey 목록의 카드마다 `슬롯 구성 바꾸기`와 `YubiKey 비우기` 버튼이 있다. 누르면 목록 대신 그 작업 화면이 같은 탭에 열린다(`App::card.manage`, `app_yubikey::manage`, `ui::screens_yubikey::manage`; 키 작업자 `YkJob::Manage(ManageJob)`, 코어 `yubikey::manage`). 둘 다 **자금을 옮기지 않는다**: 카드에서 빠진 키도 니모닉에서 언제든 다시 파생되고, 같은 역할(같은 표준 경로)을 다시 넣으면 같은 주소가 돌아온다. FIDO2·패스키, OTP, OATH는 어떤 경우에도 건드리지 않는다.

**복구 단어 없이 연결한 키(경로 모름, §7.6)는 예외다**(2026-11-08): 그 키는 어디에서도 다시 만들 수 없다. 덮어쓰거나 비울 슬롯 중 `path_known = false`이고 **다른 등록 카드가 같은 키를 갖지 않은 것**(`manage::lost_slots`)이 있으면 "복구 단어로 언제든 복구" 문구(T-YK-RESLOT-REMOVED, T-YK-CLEAR-FUNDS)는 경로를 아는 슬롯이 하나라도 있을 때만 보이고, 대신 T-YK-KEY-LOST(위험 띠: "이 키는 복구 단어가 없습니다 — 지우면 영구히 사라지고 이 주소의 자산을 다시 쓸 수 없습니다. 잔액이 있으면 먼저 다른 주소로 옮기세요.")와 그 키의 주소, 별도 확인 체크(`RESLOT_LOSS_ACK`/`CLEAR_LOSS_ACK`)와 입력란에 정확히 `영구 삭제`(`LOSS_WORD`)가 있어야 `YubiKey에 넣기`/`비우기`가 진행한다(체크 전에는 꺼짐, 단어는 누를 때 검사). 계정 줄은 "복구 단어 없음·다른 YubiKey에도 없음 — 바꾸면/비우면 이 키는 영구히 사라집니다"이고 경로 칸은 "경로를 알 수 없음"이다.

### 15.1 슬롯 구성 바꾸기 (`manage::reslot_card`)

OpenPGP secp256k1 두 슬롯(SIG `B6`, AUT `A4`)을 한 번에 다른 체인 조합으로 바꾼다. PIV(Solana) 슬롯은 그대로 둔다.

1. **지금 구성**: 이 카드 record의 슬롯마다 경로·주소·정책을 보인다.
2. **새 구성**: 조합 `EVM + Bitcoin` / `EVM + Zcash`(처음 선택) / `Bitcoin + Zcash` / `EVM + EVM` / `직접 고르기`. 조합은 SIG·AUT 순서로 채우고, 인덱스 처음 값은 이 카드에서 **경로를 아는** EVM 슬롯의 인덱스(없으면 0; `EVM + EVM`은 i, i+1, 최대 899), Bitcoin·Zcash는 0이다. 직접 고르기는 슬롯마다 체인(EVM 계정 / Bitcoin 주소 / Zcash 주소)·인덱스(0–899: 900–999는 경로 모름 키의 계정 번호 대역이라 경로가 아니다, `MAX_RESLOT_INDEX`)·Bitcoin 주소 형식(P2WPKH·P2SH-P2WPKH·P2PKH, 탭루트 없음)을 고른다. Zcash 네트워크는 하나(메인넷/테스트넷). **표준 경로만** 쓴다(EVM `m/44'/60'/0'/0/i`, Bitcoin `m/{44|49|84}'/{0|1}'/0'/0/i`, Zcash `m/44'/{133|1}'/0'/0/i`). EVM 공유 키(§3.2)는 `고급` 확인란을 켠 때만 체인 목록에 나오고, 고르면 §3.2 문장과 확인 체크가 필요하다. 터치 정책은 각 슬롯의 지금 값을 그대로 쓴다(고정 정책도 같은 값이므로 다시 쓸 수 있다, §7.4). 두 슬롯을 모두 채워야 한다.
3. **복구 단어**: W05(+ W06)에서 한 번 받는다. 화면 문구(T-YK-RESLOT-WORDS): 키를 만드는 데만 쓰고 저장하지 않으며, 이 작업(백업 YubiKey 적용 포함)을 마치거나 취소하거나 잠기면 바로 지운다. 단어는 마법사와 같은 키 작업자 버퍼(`PendingEnrol`)에 시드로만 있고 `완료`·`취소`(`YkJob::Discard`)·잠금에 지워진다. 마법사가 열려 있었다면 그 단어는 먼저 지운다.
4. **확인**(카드 통신 없음, `ManageJob::ReslotPreview`): 새 슬롯마다 전체 경로·주소(`enrol::preview_seed`)와 관계(그대로 / 새로 넣음 / 다른 YubiKey가 가진 같은 키 = 백업 복사본). 검사(`manage::validate_reslot`): 새 계획이 OpenPGP 슬롯만, 역할 인덱스가 900–999 대역이 아님(`UnsupportedRole`, 2026-11-08), 카드 전체 계획(새 OpenPGP + 기존 PIV)이 §3.5 규칙 1–5, 마스터 지문 = record의 지문(`DifferentMnemonic`); 그리고 새 record가 다른 카드와 일관(같은 경로 = 같은 공개키, `Vault::check_replace_hardware_key`). 다른 카드에 이미 있는 경로는 막지 않는다(그 카드의 백업 복사본이 된다 — 백업 카드에 같은 변경을 적용하는 흐름이 바로 이것이다). **이 카드에서 빠지는 계정**을 따로 보인다(`dropped_roles`: 같은 슬롯이 역할과 **공개키**를 모두 그대로 가질 때만 남는 것으로 본다 — 파생 키가 경로 모름 키를 덮어쓰면 빠지는 계정이다): 계정마다 그 키를 아직 가진 다른 YubiKey(있으면 "그 YubiKey로는 계속 서명", 없으면 "이 지갑에서 서명할 수 없음")와 T-YK-RESLOT-REMOVED("빠지는 체인은 이 YubiKey로 서명할 수 없습니다. 자금은 체인에 그대로 있고, 같은 구성으로 다시 바꾸면 같은 주소가 돌아옵니다"), 확인 체크가 있어야 `YubiKey에 넣기`가 켜진다. T-YK-RESLOT-BACKUP: 백업 YubiKey에도 같은 변경을 하라.
5. **카드**: W12 OpenPGP 관리자 PIN → `ManageJob::Reslot` → 아래 APDU → record 교체(`Vault::replace_hardware_key`) → `HardwareKeys`·`LoadMeta`(meta `hw_accounts`·Bitcoin `btc_accounts`가 §13의 `reconcile_hardware`로 맞춰진다: 새 키 계정은 생기고 빠진 키 계정은 그 키를 가진 카드가 없으면 사라진다. 숨긴 계정은 그 키가 다시 들어오면 보인다).
6. **결과**: 카드에서 다시 읽은 공개키와 주소, 그리고 "백업 YubiKey에도 같은 구성 적용" — 아직 바꾸지 않은 다른 등록 카드마다 버튼(같은 키를 가졌던 카드는 "백업: 같은 키 n개"). 누르면 그 카드로 4단계부터(단어를 다시 묻지 않음, 그 카드의 터치 정책). `완료 (복구 단어 지우기)`로 끝낸다.

APDU(카드 하나, 이 순서):

| 단계 | APDU | 비고 |
|---|---|---|
| 일련번호 | `00 A4 04 00 06 D2 76 00 01 24 01` · `00 F1 00 00` · `00 CA 00 6E` · `00 CA 00 F9` | 읽기만. 일련번호 ≠ record → `WrongCard`, 아무것도 쓰지 않음 |
| 관리자 PIN | `00 20 00 83 Lc PW3` | |
| 바뀌지 않는 슬롯 | `00 47 81 00 02 B6 00`(또는 `A4 00`) | 같은 경로·같은 정책이고 카드 공개키 = record면 쓰지 않는다 |
| 바뀌는 슬롯 | `00 DA 00 C1`/`C3 13 2B 81 04 00 0A` → `00 DB 3F FF 4D{…}` → (정책이 다르면) `00 DA 00 D6`/`D8` → `00 47 81 00` | §5.2와 같은 가져오기. 다시 읽은 공개키 = 니모닉에서 파생한 공개키(`KeyMismatch`) |

- 실패: 가져오기 도중 실패하면 앞 슬롯은 이미 바뀌었을 수 있고 vault의 record는 **바꾸지 않는다**(화면: "일부 슬롯에 새 키가 이미 들어갔을 수 있습니다… 다시 시도하면 덮어씁니다"). `다시 시도`는 같은 계획으로 관리자 PIN부터 다시 한다. 다른 카드가 꽂혀 있으면 아무것도 쓰기 전에 `WrongCard`.
- 시험: `yubikey::tests::connect_without_words_and_sign_every_chain`(900–999 대역 → `UnsupportedRole`), `app::tests::yubikey_manage::yubikey_reslot_switches_chains_and_applies_it_to_the_backup`(에뮬레이터; 마법사의 Zcash 슬롯 등록·확인 화면의 `m/44'/133'/0'/0/0`·`t1…`, EVM+Zcash → EVM+Bitcoin, 빠지는 Zcash 계정과 다른 보유 카드, 확인 체크 전 꺼짐, 미리보기 카드 통신 없음, 다른 카드 거부·쓰기 없음, 다시 읽기·`check_record`, PIV 그대로, Bitcoin 계정 생김, 백업 카드 적용(단어 재입력 없음), `완료` 뒤 단어 없음).

### 15.2 YubiKey 비우기 — OpenPGP (SIG/AUT: EVM·Bitcoin·Zcash 키)

무엇을 비울지(OpenPGP 지갑 키 / PIV Solana 슬롯 / 둘 다, record에 있는 애플릿만 보인다)와 방법을 고른다. 확인은 입력란에 정확히 `비우기`를 쓰고 `비우기`를 누르는 것이다(틀리면 오류 띠, 작업 없음). 그 전에 쓸 수 없게 되는 계정을 보인다: 비울 슬롯마다 역할·경로·주소와 그 키를 가진 다른 YubiKey(있으면 "그 YubiKey로는 계속 서명", 없으면 "계정 목록에서 빠집니다 — 같은 복구 단어로 다시 넣으면 돌아옵니다"), T-YK-CLEAR-FUNDS("자금은 체인에 그대로 있고 복구 단어로 언제든 복구").

OpenPGP 카드 3.4에는 **키를 지우는 명령이 없다**(덮어쓰기·생성은 삭제가 아니다). 두 방법:

| 방법 | APDU | 결과 |
|---|---|---|
| `이 지갑의 슬롯만 지우기`(관리자 PIN) | `00 20 00 83 Lc PW3` → 슬롯마다 `00 DA 00 C1`/`C3 06 01 10 00 00 20 00`(RSA 4096) → `00 DA 00 C1`/`C3 06 01 08 00 00 20 00`(RSA 2048) → `00 47 81 00 02 B6 00`/`A4 00` | yubikit `delete_key`와 같다: 속성을 바꾸면 카드가 그 슬롯의 키를 지운다. 다시 읽기에 공개키(`86`/`81` 값)가 있으면 `KeyMismatch`. PIN·DEC 슬롯·다른 슬롯은 그대로. **UIF(터치 정책)는 바꾸지 않는다** — "고정" 정책은 남는다(지우려면 초기화). 지문·생성 시각 DO(`C7`–`CF`)는 이 지갑이 쓰지 않으므로 건드리지 않는다 |
| `애플릿 초기화`(PIN 없음) | PW1: `00 20 00 81 08 00×8`을 `6983`(또는 `63C0`)까지, PW3: `00 20 00 83 08 00×8`을 같은 식으로(각각 최대 16회) → `00 E6 00 00`(TERMINATE DF) → `00 44 00 00`(ACTIVATE FILE) → 다시 SELECT 해 record의 공개키가 남지 않았는지 확인 | Yubico 절차(yubikit `reset`). 세 슬롯의 모든 키(GPG 등 다른 용도 포함), 터치 정책(고정 포함), PIN이 공장값(PW1 `123456`, PW3 `12345678`)으로. **PIN도 초기화된다**는 문구를 화면에 보인다(T-YK-CLEAR-PGP-RESET). PIN 없이 누구나 할 수 있는 동작이다 |

### 15.3 YubiKey 비우기 — PIV (Solana 슬롯)

| 방법 | APDU | 결과 |
|---|---|---|
| `이 지갑의 슬롯만 지우기`(PIV PIN) | GET METADATA `9B` + ADMIN DATA(관리 키 상태) → 기본값도 PIN 보호도 아니면 `ManagementKeyUnknown`(초기화를 쓰라고 안내) → `00 20 00 80 08 PIN` → 관리 키 상호 인증(보호돼 있으면 PRINTED, 아니면 공장 키, §5.3.3) → 슬롯마다 `00 F6 FF <slot>`(DELETE KEY = MOVE KEY to `FF`) → `00 F7 00 <slot>`이 `6A88` | yubikit `delete_key`. 이미 빈 슬롯(`6A88`)은 지운 것으로 본다. 이 지갑은 PIV 인증서를 쓰지 않으므로(§11) **지울 인증서가 없다** — 다른 프로그램이 그 슬롯에 넣은 인증서 객체(`5FC10D`… 등)는 건드리지 않는다. 펌웨어가 DELETE를 모르면(`6D00` 등) `NotSupported` → 초기화를 쓰라는 안내 |
| `애플릿 초기화`(PIN 없음) | `00 20 00 80 08 FF×8`을 PIN이 막힐 때까지 → `00 2C 00 80 10 FF×16`(RESET RETRY COUNTER, 틀린 PUK)을 PUK가 막힐 때까지(각각 최대 16회) → `00 FB 00 00` → 다시 SELECT 해 record의 슬롯이 `6A88`인지 확인 | Yubico 절차(yubikit `reset`, .NET SDK: 둘 다 막혀야 `9000`, 아니면 `6985`). 모든 PIV 키·인증서·데이터 객체(ADMIN DATA·PRINTED 포함)를 지우고 **PIN `123456`·PUK `12345678`·관리 키 공장값**으로 되돌린다(T-YK-CLEAR-PIV-RESET) |

- 순서: OpenPGP 먼저, 그다음 PIV(PIV SELECT가 PW3 확인을 끝내므로). OpenPGP가 실패하면 PIV는 하지 않는다. 결과는 애플릿마다 따로 보인다(`ClearReport`).
- 펌웨어: record의 펌웨어가 5.7.4 미만이면 "Yubico는 PIV 키 삭제를 5.7.4부터 문서화했습니다. 카드가 거부하면 초기화를 쓰세요"를 보인다(5.7.0 미만 카드에는 PIV 슬롯이 없다, §2).

### 15.4 슬롯 표와 계정

- 키 작업자는 카드에 쓰기 **전에** 결과 record로 vault를 검사한다(`Vault::check_replace_hardware_key`): 니모닉 없는 지갑의 마지막 YubiKey를 모두 비우면 지갑에 키가 남지 않으므로 `LastKey`로 거부한다(화면도 미리 `비우기`를 끄고 이유를 보인다). 카드 작업 뒤 실제로 성공한 애플릿의 슬롯만 record에서 뺀다(`ClearPlan::remaining`); **슬롯이 하나도 남지 않은 record는 지운다**. `Vault::replace_hardware_key(id, Some(record) | None)`은 비밀이 없으므로 비밀번호를 묻지 않는다(`PayloadRewrite`, §8의 `add_hardware_key`와 같다 — 카드 쪽은 이미 그 카드의 PIN 또는 일부러 PIN을 잠그는 초기화로 바뀌었다). 같은 일련번호, 유효한 record, 다른 카드와의 일관성을 요구한다.
- 카드가 바뀌었는데 vault 갱신이 실패하면 결과 화면이 그대로 알린다("YubiKey는 바뀌었지만 지갑의 슬롯 표를 고치지 못했습니다"). 이때 그 계정의 서명은 카드의 `KeyMismatch`로 PIN 전에 거부된다(§5.2).
- 초기화한 애플릿이 있고 record가 남으면 그 일련번호를 `hw_accounts.defaults`에 더한다(공장 PIN 경고, §9.3; 그 카드는 PIN 설정 전까지 서명하지 않는다). record가 지워지면 뺀다.
- Zcash(2026-11-07): 비우기 확인의 "쓸 수 없게 되는 계정"과 슬롯 구성 바꾸기의 "빠지는 계정"에는 지갑의 Zcash 계정 중 그 카드의 그 슬롯만 키를 가진 것(`App::zec_accounts_using_card(serial, slots)`, [12])을 위험 띠로 더한다(주소와 "…뒤에는 Zcash 탭에서 이 주소로 보낼 수 없습니다").
- 시험: `app::tests::yubikey_connect_without_words_from_the_first_run_screen`의 끝(경로 모름 카드의 PIV 비우기: T-YK-KEY-LOST, T-YK-CLEAR-FUNDS 없음, 확인 체크 전 `비우기` 꺼짐, `영구 삭제` 없이 거부, 카드 쓰기 없음), `app::tests::yubikey_manage::yubikey_clear_our_slots_and_applet_resets`(에뮬레이터; 두 애플릿 "우리 슬롯만": 입력 단어 검사, 관리자 PIN·PIV PIN, SIG/AUT 키 없음·속성 RSA 2048, `F6` 전송, 초기화 명령 없음, PIN 그대로, 슬롯 0개 → record 삭제·계정 사라짐; 다시 등록 후 PIN을 바꾼 카드에서 PIV 초기화(`FB`, PIN·PUK·관리 키 공장값, OpenPGP 그대로, record에 OpenPGP 슬롯만 남음, `defaults`에 추가) → OpenPGP 초기화(`E6`·`44`, PW1·PW3 공장값, 키 없음, record 삭제)). 에뮬레이터는 `E6`/`44`(TERMINATE 상태에서는 ACTIVATE만), RSA 4096 속성, `2C`·PUK 횟수, `F6`(5.7 미만 `6D00`), `FB`(PIN·PUK가 막히지 않으면 `6985`)를 구현한다.

### 15.5 확인한 것과 가정한 것

- 확인(문서·코드, 2026-11-06): OpenPGP 초기화 절차와 바이트(`E6`·`44`, `_INVALID_PIN` = `00×8`) — [KIT-PGP-RESET]; OpenPGP 키 삭제 = 속성 두 번 변경(RSA 4096 → RSA 2048) — [KIT-PGP-RESET] `delete_key`; PIV DELETE = `00 F6 FF <slot>`(yubikit 5.7.0 요구, Yubico 매뉴얼 "as of 5.7.4") — [KIT-PIV-DELETE], [Y-57-DELETE]; PIV 초기화 = PIN·PUK 차단 뒤 `00 FB 00 00`, 아니면 `6985` — [Y-PIV-RESET], [KIT-PIV-DELETE].
- 가정(문서로 확인하지 못함, 실제 카드에서 확인 — 체크리스트 YM-07·YM-08·YM-10): (1) PIV DELETE KEY에 **관리 키 인증**이 필요한지 — 확인한 문서에는 없다. IMPORT와 같다고 보고 상호 인증 뒤에 보낸다(필요 없더라도 해가 없다). (2) RSA 2048 속성으로 바꾼 빈 OpenPGP 슬롯의 `00 47 81 00` 답이 `6A88` 또는 빈 템플릿이다(공개키 값이 있으면 지워지지 않은 것으로 보고 `KeyMismatch`). (3) 차단용 VERIFY의 답이 `63Cx`/`6983`이다(그 밖의 상태어도 다시 시도하고, 16회 안에 막히지 않으면 `Conditions`로 멈춘다 — TERMINATE·RESET은 보내지 않는다). (4) 5.7.0–5.7.3에서 DELETE KEY가 동작하는지는 모른다(거부되면 초기화 안내).
- 하지 않는 것: OpenPGP DEC 슬롯·지문 DO·카드 소유자 정보, PIV 인증서·다른 데이터 객체(초기화 제외), FIDO2·OTP·OATH, YubiKey 전체 장치 초기화.

## 16. 수동 확인 (사용자 YubiKey, 테스트넷)

[docs/acceptance/yubikey-manage-20261106.md](../docs/acceptance/yubikey-manage-20261106.md) — Zcash 슬롯 등록, 슬롯 구성 바꾸기(백업 카드 포함), YubiKey 비우기(우리 슬롯만 / 애플릿 초기화)를 테스트넷 소액으로 확인한다. 처음에는 **다른 용도로 쓰지 않는 YubiKey**로 한다(초기화는 그 애플릿의 다른 키를 지운다).
