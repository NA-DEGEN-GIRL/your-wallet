# YubiKey Zcash 슬롯 · 슬롯 구성 바꾸기 · YubiKey 비우기 판정 기록 — 2026-11-06 (자동 통과, 실제 카드 항목은 사용자 수행)

- 범위: [spec/10](../../spec/10-yubikey.md) §3.1(Zcash 역할), §8(record role 4), §15(슬롯 구성 바꾸기·YubiKey 비우기), §16.
- 의존성: **추가 없음**(`Cargo.lock` 변경 없음).
- 이름(2026-11-10): 카드의 버튼은 `YubiKey의 키 지우기…`(2026-11-08 U19, 이전 이름 `YubiKey 비우기`)이고 그 흐름의 제목은 "YubiKey의 키 지우기 — YubiKey #n"이다. 흐름 안의 실행 버튼과 입력할 단어는 그대로 `비우기`. YM-09는 11-10 동작(애플릿 초기화만으로는 "기본 PIN" 표시 없음, spec/10 §15.4)에 맞춰 고쳤다.
- 안전 규칙: 자동 시험은 에뮬레이터(`yubikey::mock::MockCard`)만 쓴다. 실제 카드에는 사용자가 아래 순서로만 쓴다. 처음에는 **다른 용도(GPG·PIV 인증서·SSH)로 쓰지 않는 YubiKey**와 **테스트넷 소액**으로 한다. 초기화(YM-09·YM-10)는 그 애플릿의 다른 키를 모두 지운다.

## 자동 항목 (게이트 `scripts/check.ps1 -Offline`)

| 항목 | 판정 | 근거 |
|---|---|---|
| 마법사 Zcash 슬롯(메인넷 0): 확인 화면 `m/44'/133'/0'/0/0`·`t1…`, record role 4 | 통과 | `app::tests::yubikey_manage::yubikey_reslot_switches_chains_and_applies_it_to_the_backup` |
| 슬롯 구성 바꾸기 EVM+Zcash → EVM+Bitcoin: 미리보기 카드 통신 없음, 빠지는 계정·다른 보유 카드, 확인 체크, 다른 카드 거부(쓰기 없음), 다시 읽기, PIV 그대로, 계정 갱신, 백업 카드 적용(단어 재입력 없음), `완료` 뒤 단어 없음 | 통과 | 같은 시험 |
| 비우기: 입력 단어, 우리 슬롯만(OpenPGP 속성 두 번·PIV `F6`, 초기화 명령 없음, PIN 그대로), 슬롯 0개 → record 삭제, PIV 초기화(`FB`, 공장값, OpenPGP 그대로, `defaults`), OpenPGP 초기화(`E6`·`44`, 공장 PIN) | 통과 | `app::tests::yubikey_manage::yubikey_clear_our_slots_and_applet_resets` |
| 기존 YubiKey 시험 전부, 화면별 명령 id 유일, id 범위 겹침 없음 | 통과 | `cargo test --workspace`, `ui::command_ids::tests::*`, `app::tests::every_screen_has_unique_control_ids` |

## 수동 항목 (사용자 YubiKey 5, 테스트넷)

준비: 설정에서 Bitcoin testnet4, EVM Sepolia, Zcash 테스트넷(Zcash 앱이 있으면). 복구 단어는 테스트용 새 단어. `ykman`(yubikey-manager)으로 각 단계 전후의 `ykman openpgp info`·`ykman piv info`를 기록한다. 각 항목 뒤에 펌웨어 버전과 결과(화면 문구·상태)를 적는다.

| # | 항목 | 판정 |
|---|---|---|
| YM-01 | 마법사: AUT = `Zcash 주소`, 네트워크 `테스트넷 (tm…)`, 인덱스 0 → 확인 화면 `m/44'/1'/0'/0/0`과 `tm…` 주소가 같은 복구 단어를 넣은 다른 Zcash 지갑의 transparent 주소 0과 같다. 가져오기 → 결과 화면의 다시 읽은 주소가 같고 `다시 확인` ✓ | 대기 |
| YM-02 | 메인넷 Zcash(`m/44'/133'/0'/0/0`, `t1…`)를 확인 화면까지만 열어 주소가 다른 지갑과 같은지 본다(가져오지 않아도 됨). 테스트넷 Zcash와 Bitcoin testnet4 P2PKH 0을 한 카드에 함께 고르면 `DuplicatePath`(같은 경로 `m/44'/1'/0'/0/0`) | 대기 |
| YM-03 | 카드 #1(EVM 0 + Bitcoin P2WPKH 0) → `슬롯 구성 바꾸기` → `EVM + Zcash`: 지금 구성, 복구 단어 한 번(문구: 저장하지 않고 끝나면 지움), 새 경로·주소, "이 YubiKey에서 빠지는 계정"에 Bitcoin(다른 카드에 없으면 "서명할 수 없음"), 확인 체크 전 `YubiKey에 넣기` 꺼짐, 관리자 PIN → 결과의 다시 읽은 주소. `ykman openpgp info`: SIG 그대로, AUT 새 키 | 대기 |
| YM-04 | 바꾼 뒤: Sepolia 소액 보내기(SIG, PIN + 터치) 성공. Zcash 테스트넷 보내기(Zcash 앱이 있으면) 성공. Bitcoin 탭에서 그 계정이 사라졌거나(다른 카드에 없을 때) 백업 카드로만 서명된다 | 대기 |
| YM-05 | 결과 화면 `#…에 같은 구성 적용`(백업 카드 #2): 단어를 다시 묻지 않음, 카드를 #2로 바꿔 끼우고 관리자 PIN → 성공. 목록 "계정별 YubiKey"에 `#1 AUT, #2 AUT(백업)`. `완료` 뒤 다시 열면 단어를 묻는다 | 대기 |
| YM-06 | 되돌리기: `EVM + Bitcoin`으로 다시 바꾸면 Bitcoin 주소가 YM-03 전과 같고 잔액이 그대로 보이며 testnet4 소액 보내기 성공(자금은 체인에 그대로) | 대기 |
| YM-07 | `YubiKey의 키 지우기…` → OpenPGP 지갑 키, `이 지갑의 슬롯만 지우기`, `비우기` 입력, 관리자 PIN: 결과 "슬롯을 지웠습니다". `ykman openpgp info`: SIG/AUT 키 없음(속성 RSA 2048), PIN 남은 횟수 그대로, 터치 정책 그대로(고정이면 고정 유지). spec/10 §15.5 가정 (2): 빈 슬롯의 공개키 읽기 답(상태어) 기록 | 대기 |
| YM-08 | `YubiKey의 키 지우기…` → PIV Solana 슬롯, `이 지갑의 슬롯만 지우기`, PIV PIN: `ykman piv info`에서 슬롯 82가 비었고 다른 슬롯·인증서 그대로. 관리 키가 기본값인 카드와 PIN 보호(`--protect`) 카드 둘 다. spec/10 §15.5 가정 (1)(4): 펌웨어 5.7.4 미만이면 결과 기록 | 대기 |
| YM-09 | `YubiKey의 키 지우기…` → OpenPGP `애플릿 초기화 (PIN도 공장 기본값)`(PIN 묻지 않음, "PIN도 공장 기본값" 경고): `ykman openpgp info` PIN 3/3·관리자 PIN 3/3·키 없음·터치 Off. 초기화**만으로는** 앱의 YubiKey 목록에 "기본 PIN·관리 키를 쓰고 있을 수 있습니다" 안내가 생기지 **않는다**(그 애플릿에 지갑 키가 남지 않으므로, spec/10 §15.4 — PIV에 PIN을 바꿔 둔 Solana 키가 있으면 그 서명도 그대로 된다). 이어서 같은 카드의 `슬롯 구성 바꾸기`로 OpenPGP에 키를 다시 넣으며 공장 관리자 PIN `12345678`을 쓰면 그 카드에 그 안내가 생기고 PIN 설정 전에는 서명하지 않으며, `PIN 설정 / 기본값 변경` → `하나씩 따로`는 OpenPGP PIN·관리자 PIN만 묻는다(PIV는 그대로) | 대기 |
| YM-10 | `YubiKey의 키 지우기…` → PIV `애플릿 초기화 (PIN도 공장 기본값)`: `ykman piv info` PIN·PUK 기본값(3/3), 관리 키 기본값, 키·인증서 없음. spec/10 §15.5 가정 (3): 차단 중 상태어(`63Cx`/`6983`) 기록 | 대기 |
| YM-11 | YubiKey 지갑(복구 단어 없음)에서 유일한 카드의 모든 슬롯을 고르면 `비우기`가 꺼지고 "마지막 키" 이유가 보인다 | 대기 |
| YM-12 | `슬롯 구성 바꾸기` 확인 뒤 다른 YubiKey를 꽂고 진행: "이 YubiKey에는 이 계정의 키가 없습니다" 류 오류, 그 카드의 `ykman openpgp info` 변화 없음. 원래 카드로 `다시 시도` 성공 | 대기 |
| YM-13 | YM-09·YM-10 뒤 FIDO2·패스키 로그인, `ykman oath accounts list`, OTP 슬롯이 그대로다 | 대기 |
| YM-14 | (2026-11-10, spec/10 §15.1) `YubiKey 연결하기 (복구 단어 없이)`로 연결한 카드 → `슬롯 구성 바꾸기`: 고르기 단계에 "복구 단어 없이 연결한 YubiKey입니다…" 안내, 테스트용 새 단어 → 확인 화면에 `DifferentMnemonic` 없이 새 경로·주소, 빠지는 계정은 "복구 단어 없음… 영구히 사라집니다"와 T-YK-KEY-LOST·`영구 삭제` 입력이 있어야 넣기. 넣은 뒤 목록의 경로가 `m/44'/…`로 보이고 PIV 슬롯은 "경로를 알 수 없음" 그대로, 같은 단어로 `YubiKey 등록`(다른 카드)이 된다. 이 PC의 복구 단어를 넣으면 T-YK-SAME과 확인 체크 전에는 `YubiKey에 넣기`가 꺼진다 | 대기 |
