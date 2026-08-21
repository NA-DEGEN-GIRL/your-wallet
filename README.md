# Your Wallet

정식 지갑의 백업 원칙과 복구 연습은
[한국어 지갑 백업·복구 안내](docs/recovery-guide.ko.md)에 따로 정리했습니다.

Windows에서 더블클릭으로 실행하는 **Ethereum Sepolia 테스트넷 전용 지갑**입니다.

앱을 실행하려면 [`RUN-SEPOLIA-WALLET.cmd`](RUN-SEPOLIA-WALLET.cmd)를
더블클릭하세요. [`TEST-WALLET.cmd`](TEST-WALLET.cmd)는 앱이 아니라 개발자용
자동검사 파일입니다.

## 받기 QR 계약 (Sepolia 실행판 한정)

받기 QR은 사용자가 직접 열 때만 보이며, 현재 선택한 계정에서 백엔드가 검증한
EIP-55 주소만 사용합니다. 기본값은 금액 없는 정확한
`ethereum:<address>@11155111`입니다. 사용자가 금액 지정을 명시적으로 켜고 0보다
큰 Sepolia ETH 십진수를 입력했을 때만, 소수점 아래 최대 18자리와 uint256 범위를
검사한 뒤 정확한
`ethereum:<address>@11155111?value=<canonical-decimal-wei>`를 만듭니다. 빈 값,
잘못된 형식, 0, 초과 정밀도, 범위 초과 값에서는 QR과 결제 URI 및 그 복사 버튼을
표시하지 않습니다. 별도의 일반 주소 복사는 그대로 사용할 수 있으며, `pay-` 형식과
그 밖의 query parameter는 지원하지 않습니다. QR 보기, 금액 지정, 결제 URI 복사,
일반 주소 복사는 모두 각각 사용자가 명시적으로 조작해야 합니다.

주소, 선택 계정 번호, Sepolia chain ID와 요청 금액은 공개 금융 메타데이터입니다.
금액 포함 URI는 강제 청구서나 입금 영수증이 아니며 보내는 쪽이 금액을 바꾸거나
무시할 수 있으므로, 실제 입금은 선택 주소와 온체인 결과로 별도 확인하세요. 결제 URI를
복사하면 운영체제 클립보드가 지갑 잠금이나 종료 뒤에도 남을 수 있습니다.

금액 입력은 UI 세션 안의 `Zeroizing` 버퍼에만 두고, 금액 지정 여부도 세션 상태로만
둡니다. 받기 패널 숨김, 금액 지정 해제, 계정 전환 요청·성공, 살아 있는 앱의
잠금·세션 정리는 소유한 금액을 지우고 그 프레임 끝에 egui 텍스트 편집 기록도
폐기합니다. 앱
종료(`Drop`)는 소유한 입력을 다시 지우며, 보통의 프로세스·컨텍스트 종료가 egui
메모리를 없애지만 별도 포렌식 삭제를 보장하지는 않습니다. 백엔드, RPC, 저장소,
스키마를 건드리거나 새 의존성을 추가하지 않고, 금액 때문에 네트워크를 호출하지
않습니다. QR은 매 화면 프레임에서만 만들며 정확히
`qrcodegen =1.8.0`, 4모듈 여백, 저배율에서도 모듈당 최소 6 physical pixel을
사용합니다. 전체 QR이 현재 보이는 영역 안에 들어오지 않으면 그리지 않고 안내를
표시하므로, 잘리거나 일부만 보이는 QR은 만들지 않습니다. QR texture, cache, 파일,
네트워크 경로도 없습니다.

> [!WARNING]
> 실제 ETH, 메인넷 자산, 구매한 토큰을 절대 넣지 마세요. 이 앱에서는 가치가
> 없는 Sepolia 테스트 ETH만 사용해야 합니다.

## 처음부터 보내기까지

1. Windows 탐색기에서 `RUN-SEPOLIA-WALLET.cmd`를 더블클릭합니다.
2. 처음 실행할 때는 릴리스 빌드가 끝날 때까지 기다립니다. 컴퓨터에 따라 몇
   분 걸릴 수 있으며, 다음 실행부터는 보통 더 빠릅니다.
3. 앱이 열리면 **12바이트 이상의 비밀번호**를 입력합니다. 영문·숫자만
   사용한다면 12글자 이상으로 입력하세요.
4. `새로 만들기`에서 영어 복구 문구를 12단어 또는 24단어로 고른 뒤
   `복구 문구 생성 (아직 저장 안 함)`을 누릅니다.
5. 생성된 12/24단어와 첫 주소를 번호가 붙은 목록에서 직접 기록합니다. 전체
   120초 안에 화면의 단어 확인 전환 버튼을 2초 연속 누른 뒤, 무작위 네
   위치의 단어와 첫 주소 전체를 다시 입력합니다. 마지막
   `백업 확인 후 v2 지갑 저장 — 2초 누르기`도 2초 연속 눌러야 합니다.
   불일치 한 번은 절차를 소모하며 파일을 쓰지 않습니다. 만료, 취소, 포커스
   상실, 비활성 잠금 또는 명시적 잠금은 backend commit checkpoint에서 관찰되면
   파일을 쓰지 않습니다. 마지막 pre-write checkpoint 이후의 race는 아래 경계를
   따릅니다.
6. 복구 문구 지갑이라면 `사용할 계정`에서 계정 0 또는 계정 1을 고릅니다. 선택은
   열린 세션에만 적용되며 잠그거나 다시 실행하면 계정 0으로 돌아갑니다.
7. 화면에 나온 내 주소 옆의 `주소 복사`를 누릅니다.
8. [ethereum.org의 Sepolia faucet 안내](https://ethereum.org/developers/docs/networks/)에서
   복사한 주소로 무료 테스트 ETH를 받습니다. Faucet마다 로그인이나 사용량
   제한이 있을 수 있습니다.
9. 가져온 지갑, 기존 지갑 열기, v1 → v2 이전, 계정 전환이 성공하면 선택 계정의
   개요를 한 번 자동 조회합니다. 새로 생성한 지갑은 offline 생성 경계를 유지해
   `조회 전`으로 남으므로 필요할 때 `새로고침`을 누릅니다.
10. `Sepolia ETH` 또는 저장 후 다시 검증된 ERC-20을 전송 자산으로 고르고, 받는
   Sepolia 주소와 보낼 금액을 입력합니다. ERC-20은 먼저 아래의 `검증 후 추가`와
   `저장된 토큰 다시 검증`을 거쳐야 선택할 수 있습니다. 가스 수수료를 `추천`,
   `빠르게`, `직접 입력` 중에서 고른 뒤 `전송 내용 준비`를 누릅니다. 처음에는
   `추천`을 사용하면 됩니다.
11. 앱이 확정해서 보여 주는 항목을 전부 확인합니다.

   - 보내는 계정 번호와 전체 주소
   - 받는 주소
   - 보낼 ETH 또는 정규화된 토큰 수량
   - ERC-20이면 전체 토큰 컨트랙트 주소, 심볼, decimals
   - nonce
   - 수수료 방식과 가스 한도: ETH는 `21,000`, ERC-20은 RPC 추정값과 20% 올림값
   - 견적 시점의 기본 수수료
   - 최대 우선 수수료 / gas
   - 최대 수수료 / gas
   - 현재 기준 예상 네트워크 수수료와 예상 총액
   - 최대 네트워크 수수료
   - 최대 총지출
   - 준비 완료 시점에 남은 견적 유효 시간

12. 하나라도 틀리면 `취소하고 수정`을 누릅니다. 모두 맞으면
    `확인하고 전송 — 2초 동안 누르기`를 2초 동안 계속 누릅니다. 미리보기가
    나오기 전에는 이 최종 전송 버튼을 사용할 수 없습니다.

앱을 다시 실행할 때는 같은 비밀번호를 입력하고 `기존 테스트 지갑 열기`를
누르면 됩니다.

## 꼭 알아둘 제한사항

이 실행판은 기능을 연습하고 Sepolia에서 전체 흐름을 확인하기 위한 별도
데모입니다.

- Ethereum 메인넷과 실제 ETH를 지원하지 않습니다.
- 새 영어 복구 문구 생성과 영어 복구 문구/개인 키 가져오기를 지원하지만,
  비밀값은 짧게 한 번만 표시하며 클립보드 복사 기능은 제공하지 않습니다.
- Chrome 확장 프로그램이나 dApp과 연결되지 않습니다.
- 검증해 저장한 커스텀 ERC-20의 표준 `transfer(address,uint256)`만 전송할 수
  있습니다. 임의 컨트랙트 호출, 임의 calldata, 메시지 서명은 지원하지 않습니다.
- 네트워크를 바꾸거나 RPC 주소를 직접 입력할 수 없습니다.

이 배포·보안 증거는 Windows 실행판만 대상으로 합니다. 비-Windows 빌드 경로는
개발·테스트 호환용이며, `pending-v1.bin`의 exact-object 고정·삭제 보장을 입증하는
릴리스 경로로 지원하지 않습니다.

새 지갑은 운영체제 난수로 만든 영어 복구 문구와 정확한 계정 메타데이터를 v2
암호화 파일에 저장합니다. 복구 문구 지갑은 검증된 계정 0과 1 사이에서 전환할 수
있고, 선택한 계정이 주소·ETH/토큰 잔액·개인 키 내보내기·ETH/ERC-20 전송의
보내는 계정이 됩니다. 선택 번호는 파일에 저장하지 않으며 잠금·재열기·재실행마다
계정 0으로 돌아갑니다. 가져온 개인 키 지갑과 v1 지갑은 계정 0 하나만 가집니다.
준비한 전송, 보류 거래, 비밀값 표시, 생성 백업 확인 또는 worker 작업이 있으면
계정 전환을 명시적으로 차단합니다.

### 선택 계정 개요 조회 경계

개요 조회는 authoritative 지갑 열기·가져오기·이전·계정 전환이 성공한 **뒤**에
별도 worker 작업으로 정확히 한 번만 실행합니다. RPC 장애가 지갑 열기나 계정
전환을 되돌리지는 않으며, 확인하지 못한 ETH는 `조회 전`, 확인하지 못한 토큰은
category-only 오류로 표시합니다. 체인 identity 확인 subcall은 한 작업 안에서 최대
3번만 시도하지만, 개요 작업 자체를 자동으로 다시 등록하거나 timer/polling을
실행하거나 다른 계정을 미리 조회하지는 않습니다. 새 복구 문구로 만든 지갑은
자동 조회하지 않으므로 offline 생성 자체가 네트워크 성공에 의존하지 않습니다.

한 번의 자동 개요 조회는 선택 계정의 Sepolia ETH와 인증된 저장 순서상 앞의
ERC-20 최대 3개만 확인합니다. 4번째 이후 계약도 숨기거나 삭제하지 않고 지연된
전체 주소 행으로 남기며, `저장된 토큰 다시 검증`을 누르면 기존의 전체 32개 수동
경로를 실행합니다. token-store를 안전하게 관찰하지 못한 경우에도 빈 목록을
“저장 토큰 없음”으로 단정하지 않고, 같은 계정의 이전 행을 유지하면서 경고합니다.

이 동작은 선택 계정 전체 주소, 조회 시각, 자동 대상이 된 최대 3개의 토큰 계약
주소를 앱에 고정된 단일 Sepolia RPC에 노출합니다. endpoint가 서로 일관된 거짓
응답을 만들거나 데이터를 숨길 수 있다는 기존 신뢰 한계도 그대로입니다. 따라서
표시된 전체 주소와 contract identity를 직접 확인해야 합니다.

```text
%LOCALAPPDATA%\YourWallet\SepoliaDemo\vault-v2.bin
%LOCALAPPDATA%\YourWallet\SepoliaDemo\tokens-v1.bin
%LOCALAPPDATA%\YourWallet\SepoliaDemo\activity-v1.bin
```

`vault-v1.bin`은 이전 실행판에서 만든 개인 키 지갑을 열고 이전하기 위해서만
지원합니다. `v1 → v2 이전`은 기존 비밀번호로 다시 인증하고 새 v2 비밀번호를
두 번 확인한 뒤 같은 개인 키와 주소를 보존합니다. v1에는 애초에 복구 문구가
없었으므로 이전 뒤에도 복구 문구 내보내기는 불가능합니다.

새 지갑 생성/가져오기/이전은 기존 v1 또는 v2 파일을 덮어쓰지 않습니다. 전송
결과가 불확실한 보류 거래가 있으면 먼저 같은 거래의 상태를 해결해야 하며,
그동안 지갑 생성·가져오기·이전을 차단합니다.

지갑을 연 뒤 `지갑 비밀값 내보내기`에서 현재 비밀번호를 다시 입력하고 버튼을
2초 동안 계속 누르면, 복구 문구 지갑의 복구 문구 또는 현재 선택한 계정의 개인 키를 약
20초 동안 한 번만 표시합니다. 표시값은 `Clone`/일반 디버그 출력이 없는
zeroizing 소유값이며 시간이 끝나거나 닫으면 지웁니다. 화면 캡처·악성 프로그램
등의 위험은 막아 주지 못하므로 테스트 키만 사용하세요.

### 생성 지갑 백업 확인 경계

생성 백업은 Display → Challenge → Confirm의 한 번뿐인 절차입니다. backend가
Display 시작 시 정한 120초 deadline을 두 단계가 공유합니다. Display는 사용자가
전환하기 전까지 번호가 붙은 12/24단어와 첫 파생 주소를 보여 주고, Challenge를
요청하기 전에 reveal을 drop/zeroize합니다. Challenge DTO에는 CSPRNG로 고른 서로
다른 네 위치와 deadline만 있으며, 기대 단어·주소·mnemonic은 포함하지 않습니다.

사용자는 네 단어와 첫 주소 전체를 다시 입력하고 마지막 2초 연속 누르기로 저장을
승인합니다. 응답은 한 번만 소비되며 불일치는 검증 단계에서 끝나므로 파일을 쓰지
않습니다. backend는 검증 전, 검증 직후/봉인 직전, 봉인 후/열기 전, 열기와 metadata
검증 후, 실제 write 직전에 같은 SessionPermit과 inclusive deadline을 다시 확인합니다.
만료, 취소, 포커스 상실, 비활성 잠금, 명시적 잠금 또는 stale session epoch가 이 다섯
checkpoint 중 하나에서 관찰되면 pending secret을 폐기하고 파일을 쓰지 않습니다.
마지막 pre-write check를 통과한 뒤 `write_new_file`이 실행되는 사이에 revoke/expiry가
발생하는 race에서는 durable vault 파일이 남을 수 있습니다. 이 경우 UI는 stale
response를 버리고 backend를 잠그며, 사용자는 저장된 vault를 다시 인증해 열어야
합니다. 기존 재인증 mnemonic/private-key export의 20초 reveal 정책은 변경하지
않습니다.

이 demo는 ceremony 중 Cut/Copy/Paste 이벤트를 차단하고 Paste payload를 지운 뒤
버리며, 모든 비밀·전송 입력에 고정 egui ID를 사용해 focus를 반납하고 TextEdit
undo state를 제거합니다. 따라서 이후 Ctrl+Z로 이전 입력이 UI에 되살아나는 경로는
막습니다. 다만 framework가 관리하는 galley와 이미 drop된 undo String을 포함해
egui의 일반 String, renderer, allocator, IME, 접근성 계층 또는 OS 메모리의 물리적
완전 삭제는 보장하지 못합니다. production 연결은
`crates/secret-input-ui` 같은 전용 helper에서 캡처/메모리/clipboard 경계를 검증하기
전까지 STOP-SHIP입니다.

## 전송 화면이 두 단계인 이유

`전송 내용 준비`는 아직 서명하거나 전송하지 않습니다. Sepolia에서 nonce,
잔액, 수수료를 확인한 뒤 정확한 전송 내용을 고정해 보여 주기만 합니다. ERC-20은
UI가 들고 있던 심볼·decimals·잔액을 신뢰하지 않고, 새로 연 인증 토큰 목록에서
전체 컨트랙트 주소를 다시 찾은 뒤 직접 bytecode 해시·decimals·symbol을 처음과
끝에서 확인합니다. 토큰 잔액과 최대 네트워크 수수료를 낼 보류 상태 ETH 잔액도
각각 확인합니다.

그다음 화면에서 모든 항목을 확인하고 2초 동안 버튼을 눌러야만, 준비해 둔
동일한 내용을 서명하고 전송합니다. 미리보기의 문자열이나 처음 입력한 값을
나중에 바꿔도 백엔드에 고정된 거래 내용이 몰래 바뀌지 않습니다.

수수료 견적의 최대 수명은 60초입니다. 화면에는 네트워크 조회까지 모두 끝난
준비 완료 시점에 실제로 남은 시간을 소수점 이하를 버려 보수적으로 표시합니다.
2초 확인 버튼을 끝까지 누를 시간을 보장하기 위해 남은 시간이 온전한 3초보다
짧으면 미리보기를 만들지 않고 다시 준비하라고 안내합니다.
확인할 때 Sepolia 네트워크, 고정한 nonce, 현재 기본 수수료, 보류 거래를 반영한
잔액과 가스 추정값을 다시 확인합니다. ETH는 가스가 정확히 `21,000`이어야 하고,
ERC-20은 같은 nonce·EIP-1559 수수료·고정 gas·value 0·빈 access list와 정확한
68-byte `transfer` calldata로 `eth_call`을 다시 실행합니다. 저장 토큰 파일의 exact
바이트와 generation, 직접 bytecode 해시·decimals·symbol도 다시 bookend합니다.
하나라도 달라졌거나 확인 도중 견적이 만료되면 수수료나 nonce를 몰래 바꾸어
서명하지 않고, 미리보기를 없앤 뒤 다시 준비하라고 안내합니다.

이 bookend는 여러 RPC 사이에서 직접 bytecode·metadata·일반적인 파일 변경이 섞인
미리보기를 만드는 위험을 줄일 뿐 원자적 온체인 스냅샷은 아닙니다. bytecode가 같은
EIP-1967류 프록시의 implementation/storage 변경을 알 수 없고, 마지막 사전 실행 뒤
채굴 전 상태가 바뀌는 것도 막지 못합니다. 미리보기의 토큰 수량은 calldata에 넣는
정확한 인자이지 전송 수수료형·리베이스·악성 토큰의 실제 수령량이나 owner 잔액
변화를 보장하는 값이 아닙니다. `eth_call`의 empty/canonical true 결과 역시 미래의
state diff를 보장하지 않습니다.

전송 결과를 확인하지 못한 채 네트워크가 끊기면 새 거래를 만들지 마세요.
화면 아래의 `전송 중 네트워크가 끊겼나요?`를 열고
`보류 거래의 서명 계정 확인`을 먼저 사용합니다. 앱은 정규 Sepolia type-2
서명에서 보내는 주소를 복구해 현재 지갑의 계정 0/1 중 정확히 하나와 결합합니다.
재시작 뒤 화면 선택이 계정 0으로 돌아갔더라도 보류 거래 서명자가 계정 1이면
계정 1과 전체 주소·해시를 눈에 띄게 표시합니다. 별도의
`같은 서명 거래 다시 제출 — 2초 동안 누르기`를 완료해야 디스크에 보관된 같은
서명 거래의 exact bytes만 다시 제출합니다.

## 가스 수수료를 고르는 방법

- `추천`: Sepolia 노드가 제안한 최대 우선 수수료를 사용합니다.
- `빠르게`: 추천 우선 수수료를 데모 안전 한도 안에서 높입니다. 블록 포함이 더
  빨라질 수는 있지만 보장하지 않습니다.
- `직접 입력`: 최대 우선 수수료와 최대 수수료를 Gwei 단위로 직접 입력합니다.
  각 입력은 최대 32자이며, 부호나 지수 표기 없이 소수점 아래 최대 9자리까지
  입력할 수 있습니다. 앞쪽의 `0`은 허용되며 미리보기에서는 정규화해 보여 줍니다.

직접 입력을 포함한 모든 방식에 최대 우선 수수료 `10 Gwei`, 최대 수수료
`100 Gwei`의 데모 안전 한도가 적용됩니다. 최대 수수료는 견적 시점의 기본
수수료와 최대 우선 수수료를 합한 값 이상이어야 합니다.

`현재 기준 예상` 금액은 견적 시점의 기본 수수료로 계산한 값이고, `최대` 금액은
트랜잭션에 실제로 서명되는 지출 상한입니다. 포함될 블록에 따라 실제 수수료는
예상값과 달라질 수 있지만 최대값을 넘지 않으며, 사용하지 않은 최대 금액은
청구되지 않습니다.

일반 ETH 전송은 데이터가 없어야 하며 준비할 때와 확인할 때 Sepolia 노드의 가스
추정값이 정확히 `21,000`인지 확인합니다. 저장·재검증된 ERC-20 전송은 RPC 추정
가스가 `21,000..=416,666`이고 `u64`에 정확히 들어올 때만 20%를 올림해
`25,200..=500,000`으로 고정합니다. 확인 때 추정값이 달라지면 서명하지 않습니다.
사용자가 가스 한도를 직접 바꾸거나 임의 calldata를 넣는 기능은 없습니다.

이미 서명되어 보류 중인 거래에는 새 수수료 방식을 적용할 수 없습니다.
`이전 거래 그대로 다시 전송`은 저장된 서명 거래의 같은 바이트만 재전송하며,
새 nonce·수수료·서명을 만들지 않습니다.

## 거래 활동과 보류 거래 복구

새 v2 전송은 최대 64개의 고정 크기 인증 활동 파일에 거래 hash, 보내는 계정,
nonce, 수수료, 자산 식별자와 상태를 저장합니다. 상태는 `Submitted`, `Pending`,
성공 또는 revert와 아직 최종이 아닌 깊이를 가진 `Included`, `Reorged`, 세 번의
미관찰과 최소 64 head 진행 뒤의 `DroppedCandidate`, 그리고 latest nonce가 앞선
`ReplacementSuspected`입니다. 이 이름들은 nonce 재사용 허가가 아닙니다. 보관된
어떤 상태의 행도 같은 계정·보내는 주소·nonce에 다른 거래를 만들지 못하게 합니다.

활동은 주기적·백그라운드로 자동 조회하지 않습니다. 사용자는 각 행의
`이 행만 Sepolia에서 새로고침`을 누르거나, 선택한 계정의 시작 시점
`Submitted`/`Pending`/`Reorged`/`DroppedCandidate`/`ReplacementSuspected` 행을
submission 순서로 최대 64개 고정해 명시적인 순차 조회를 시작할 수 있습니다.
`Included` 행과 작업 도중 새로 생긴 행은 이 목록에 들어가지 않습니다. 순차
작업도 기존 단일 행 경로를 한 번에 하나만 사용하며, 성공한 내구 결과 뒤 다음
요청까지 최소 2초를 기다립니다. 첫 오류·불일치·잠금·계정 전환에서 성공 응답으로
설치한 `k/전체`까지만 표시하고 그 뒤 대기 행은 요청하지 않으며, 자동 재시작·재시도·
polling은 없습니다. 단일 행 저장 뒤 인증 readback이 실패한 오류라면 그 오류 행의
디스크 상태는 UI가 확정할 수 없으므로 지갑을 다시 열거나 그 행을 직접 조회해야
합니다.

각 조회는 앱에 고정된 RPC를 head 조회로 bookend하고 거래·receipt·canonical
block을 typed 응답으로 대조합니다. 순차 조회를 시작하면 선택한 보내는 주소와
최대 64개 거래 hash, 요청 간격이 그 RPC에 노출됩니다. 전체 거래 hash, 보내는
주소, 받는 주소 또는 토큰 컨트랙트 주소와 포함 block hash를 표시합니다. 저장된
ERC-20 symbol은 과거 컨트랙트가 제공한 신뢰되지 않은 표시 이름입니다. 포함
깊이는 finality 선언이 아니며 앱은 nonce를 자동으로 다시 사용하지 않습니다.

선택 계정의 각 활동 행에 있는 `거래 hash 복사`는 사용자가 직접 눌렀을 때만 그
행의 검증된 전체 hash를 운영체제 클립보드에 넣습니다. 앱은 explorer URL을 만들거나
열지 않으며 외부 조회 서비스를 대신 선택하지 않습니다. 클립보드 내용은 지갑을
잠그거나 닫은 뒤에도 운영체제에 남을 수 있으므로, 신뢰하는 도구에 붙여넣은 뒤
필요하면 사용자가 직접 덮어써야 합니다.

서명 전에는 활동 capacity와 nonce 슬롯을 예약하고, exact `pending-v1.bin`을 잡은
상태로 전송합니다. 노드가 받은 뒤 결과가 불확실해도 pending을 보존합니다. 성공
hash가 확인되면 `Submitted` 행을 원자적으로 저장·폴더 flush·인증 readback한 뒤에만
같은 열린 pending 객체를 삭제합니다. 재시작 때 이미 같은 거래가 노드나 활동
파일에서 정확히 확인되면 다시 broadcast하지 않고 활동 저장과 pending 정리만
idempotent하게 끝냅니다. v1 지갑에 기존 native pending이 있으면 서명자와 exact
bytes를 account 0에 귀속한 lease를 유지한 채 v2로 이전하고 pending 자체는 그대로
보존합니다. foreign signer, ERC-20, 변조 또는 교체는 이전 전에 거부합니다.

`activity-v1.bin`의 generation은 외부 롤백 방지 앵커가 아닙니다. 현재 남아 있는
행만 nonce 충돌을 막습니다. 과거의 유효한 파일 복원이나 삭제로 기록이 숨으면,
그 부재는 nonce가 안전하다는 증거가 아니며 RPC nonce 회귀와 결합해 로컬 충돌
감지를 무력화할 수 있습니다. 운영 환경에는 별도의 외부 단조 앵커가 필요합니다.
또한 RPC의 최신 head가 활동에 저장된 high-water보다 낮으면 행과 generation을
바꾸지 않고 head가 따라잡을 때까지 새로고침을 보류합니다. 이는 깊이 언더플로와
잘못된 reorg 판정을 막지만 깊은 롤백 뒤 업데이트를 지연시킬 수 있습니다.
단일 고정 TLS RPC는 head·header·receipt를 서로 맞춰 조작하거나 데이터를 숨길 수
있습니다. canonical transaction 재구성은 관찰된 signed envelope의 로컬
self-consistency만 증명하며 실제 전파·포함 여부에 대한 RPC의 정직성은 증명하지
않습니다.

충돌 복구용 고정 임시 파일 `activity-v1.tmp`와 `tokens-v1.tmp`가 이전 프로세스의
중단으로 남으면, 다음 mutation lease가 Windows의 같은 열린 객체를 regular·
non-reparse로 확인한 경우에만 삭제하고 부모 폴더를 flush합니다. 디렉터리, reparse,
다른 프로세스가 잡은 객체는 덮어쓰지 않고 실패합니다. v1 이전은
`vault-v2.migrating`에 먼저 쓰고 인증한 같은 handle을 최종 이름으로 설치하므로,
설치 전 crash는 v1과 pending을 보존하고 다음 이전에서 임시 파일을 정리합니다.
설치 후에는 완전한 v2를 우선 사용하며 v1 정리 실패를 별도 복구 상태로 취급합니다.
반면 최종 `activity-v1.bin` 또는 `tokens-v1.bin`에 다른/과거 vault의 regular 파일,
nonregular 객체, reparse가 있으면 자동 덮어쓰지 않습니다. 새 vault 활성화나 열기를
실패시키므로 사용자가 원인을 확인한 뒤 의도적으로 수리하거나 제거해야 합니다.

메모리 포렌식 한계도 남아 있습니다. master key와 최종 파생 출력은 `Zeroizing`으로
소유하지만, `hkdf`/`hmac` 0.12 내부의 HMAC/PRK context는 `Zeroize` 또는
`ZeroizeOnDrop`을 구현하지 않습니다. 따라서 password-equivalent 파생 context의
stack 잔여를 완전히 지웠다고 보장하지 않습니다. 이 데모의 잠금은 소유한 secret
buffer를 지우는 수준이며 process-memory forensic erase가 아닙니다. 운영 제품은
격리된 Key Agent와 zeroizing KDF 구현 없이는 출시하면 안 됩니다(STOP-SHIP).

## 커스텀 ERC-20 토큰 추가

v2 지갑을 연 뒤 `커스텀 ERC-20 토큰`에서 Sepolia 토큰 컨트랙트의 전체 `0x`
주소를 입력하고 `검증 후 추가`를 누릅니다. v1 지갑은 먼저 `v1 → v2 이전`을
완료해야 합니다. 토큰 목록은 최대 32개입니다.

앱은 고정 Sepolia RPC에서 다음 항목을 확인한 뒤에만 토큰을 암호화 목록에
저장합니다.

- 해당 주소에 비어 있지 않은 컨트랙트 코드가 있는지
- 코드의 SHA-256 해시
- 표준 ABI로 정확히 디코딩되는 `decimals`, 선택적 안전 ASCII `symbol`
- 현재 선택한 계정의 `balanceOf` 잔액

화면에는 심볼만 표시하지 않고 전체 컨트랙트 주소를 항상 함께 표시합니다.
심볼은 컨트랙트가 제공한 신뢰되지 않은 표시 이름입니다. 지갑을 다시 열거나
`저장된 토큰 다시 검증`을 누르면 코드 해시와 메타데이터를 다시 읽습니다. 저장
뒤 코드나 메타데이터가 달라졌거나 응답이 잘못되면 기존 심볼·decimals·잔액을
숨기고 전체 주소와 실패 범주만 보여 줍니다.

`tokens-v1.bin`은 v2 지갑의 별도 파생 키와 vault ID에 묶인 고정 크기 인증 암호화
파일입니다. 임시 파일을 완전히 기록하고 flush한 뒤 원자적으로 교체하고, 설치된
바이트를 다시 열어 검증합니다. 다만 이 데모의 token generation은 하드웨어
롤백 방지 앵커가 아니라 파일 일관성 값입니다. 같은 사용자가 과거의 유효한
`tokens-v1.bin`을 준비 전에 되돌리면 최신 항목이 사라지거나 과거에 제거한 토큰이
다시 저장·선택·전송 가능한 목록으로 나타날 수 있습니다. 이때도 전체 주소를
표시하고 live code/metadata/balance/preflight를 다시 확인하지만, 이미 설치된 과거
인증 blob이라는 사실 자체는 탐지하지 못합니다. 준비가 끝난 뒤의 일반적인 exact
바이트/generation 변경은 미리보기 baseline과 달라 확인을 거부하지만, 동일한 blob
복원은 새 롤백 사건으로 구별할 수 없습니다. 이 제한 때문에 메인넷 자산 관리용으로
사용하면 안 됩니다.

전송 자산 선택에는 현재 조회가 `Verified`인 저장 토큰만 나타납니다. backend는
선택된 전체 주소를 fresh authenticated sidecar에서 다시 resolve하고, 정확한 token
amount와 ETH 수수료 잔액, 동적 가스, exact typed preflight를 통과한 뒤에만 미리보기를
만듭니다. signer는 contract를 `to`, ETH value를 0으로 하고 내부에서 만든 정확한
68-byte `transfer(address,uint256)` calldata만 넣는 EIP-1559 type-2 거래를 만듭니다.
토큰/ETH 자산 전환, 토큰 목록 변경, 잠금, ERC-20 준비·확인 실패 또는 전송 성공 때
금액과 egui undo 상태를 지워 다른 decimals나 ETH 단위로 이전 숫자가 되살아나지 않게
합니다.

## 로컬 저장 시 적용한 보강

지갑 파일과 전송 대기 파일은 완전히 기록하고 디스크에 flush한 뒤에만 성공한
것으로 처리합니다. Windows에서는 파일이 들어 있는 정확한 폴더 핸들도 잡아
두고, 파일 생성이나 삭제 뒤 `FlushFileBuffers`로 폴더 변경 기록까지 저장되었는지
확인합니다. 폴더가 안전하지 않거나 flush가 실패하면 성공했다고 넘어가지 않고
작업을 중단합니다.

이 보강은 갑작스러운 종료 때 불완전한 저장을 성공으로 오인하지 않기 위한
것입니다. 백업이나 복구 문구를 대신하지 않으며, 이 데모를 메인넷용 지갑으로
만들어 주는 기능도 아닙니다.

## 실행 스크립트가 하는 일

`RUN-SEPOLIA-WALLET.cmd`는 Windows 코드 페이지와 무관한 ASCII 실행 파일이며,
UTF-8 한글 안내를 담당하는 PowerShell 실행기로 안전하게 넘긴 뒤 다음 두 단계만
수행합니다.

1. 잠금 파일에 기록된 정확한 의존성으로 Sepolia 앱을 릴리스 빌드합니다.
2. 빌드에 성공한 실행 파일을 엽니다.

Rust/Cargo가 설치되어 있지 않으면 스크립트가 설치 필요 메시지를 보여 줍니다.
자동으로 프로그램이나 지갑 키를 설치하지는 않습니다.

한글이 깨지거나 창이 바로 닫히는 문제가 있으면 저장소 폴더의 파일을 수정하지
말고 아래 명령으로 같은 실행기를 직접 열어 오류를 확인하세요.

```powershell
powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -File scripts/run-sepolia-wallet.ps1
```

PowerShell에서 직접 빌드하고 실행하려면 다음 명령을 사용하세요.

```powershell
cargo build --release --locked --manifest-path demo/sepolia-wallet/Cargo.toml
.\demo\sepolia-wallet\target\release\sepolia-wallet-demo.exe
```

## 창 없이 확인하기 (권장)

제가 자동으로 확인할 때는 아래 헤드리스 모드를 사용합니다. 이 모드는 GUI 창을
열지 않고 마우스나 키보드를 움직이지 않습니다.

```powershell
# 가장 빠른 확인: 가짜 백엔드로 지갑 관리, 비밀값 hold, 세 수수료 방식과 ETH/ERC-20 전송 흐름 검사
cargo run --quiet --locked --manifest-path demo/sepolia-wallet/Cargo.toml -- --headless smoke

# 실제 네트워크 확인: 고정 Sepolia chain ID와 genesis 검사
cargo run --quiet --locked --manifest-path demo/sepolia-wallet/Cargo.toml -- --headless rpc

# 위 두 검사를 차례로 실행
cargo run --quiet --locked --manifest-path demo/sepolia-wallet/Cargo.toml -- --headless all
```

## Sepolia demo 잠금 정책

Sepolia GUI demo는 명시적인 `지갑 잠그기`, 5분간 입력이 없을 때의 자동 잠금,
창이 focus를 잃을 때의 즉시 잠금을 지원한다. 잠금이 시작되면 비밀번호, mnemonic,
private key, export 재인증 값, transfer/custom-token 입력, 준비된 transaction 및
화면의 pending/reveal 상태를 즉시 지우고 모든 token/transfer/export 동작을 막는다.
worker의 `Lock` 응답을 받기 전에는 vault를 다시 열 수 없다.

각 worker 요청과 응답에는 session epoch가 붙는다. 잠금으로 epoch가 바뀌면 아직
실행되지 않은 이전 요청은 실행하지 않고, 이미 실행 중이던 이전 요청의 결과도 UI에
반영하지 않는다. backend 잠금은 반복 호출해도 안전하며 unlocked key material과
미확정 wallet generation, 준비된 transaction을 제거한다. 다만 이미 서명된 pending
record인 `pending-v1.bin`의 transaction은 잠금 후에도 보존한다. 그래야 재시작
후 broadcast 상태를 조회하거나 안전하게 재시도할 수 있다.

이미 backend에서 실행을 시작한 vault/export/custom-token store 같은 동기 작업은
강제로 중단하거나 되돌릴 수 없으므로 잠금과 동시에 진행 중이던 파일 쓰기가 끝날
수 있다. confirm과 retry에는 더 좁은 revocation guard를 적용한다. confirm은 각
blocking 사전검증 RPC
반환 직후와 서명 직전, 서명 후 pending record 쓰기 전, pending record를 쓴 후 RPC
send 직전, send 반환 후 record 삭제 전에 epoch를 다시 확인한다. `SepoliaRpc`의
유일한 send API도 내부 chain ID/genesis 재검증을 모두 마친 뒤 실제
`eth_sendRawTransaction` transport 호출 바로 전에 같은 concrete SessionPermit을 다시
확인한다. retry도 pending record를 읽은 뒤, chain 검증 뒤와 guarded RPC 내부
재검증 뒤 send 직전, send 반환 후 삭제 전에 확인한다. 따라서 guarded transport
check 전에 감지된 잠금은 새 broadcast를 만들지 않는다.
post-write/pre-send 또는 post-send/pre-delete check가 잠금을 관찰하면 이미 기록된
`pending-v1.bin`을 보존한다.

RPC 내부의 마지막 guarded pre-transport check가 이 demo의 외부 side-effect commit
point다. 그 check를 통과한 직후부터 실제 transport send가 시작되는 사이 또는
send가 실행 중일 때 잠금이
경합하면 transaction 전파 자체는 취소할 수 없다. 다만 send 반환 직후의
post-send check가 epoch 변경을 관찰하면 성공 hash가 일치해도 `pending-v1.bin`을
삭제하지 않고 stale UI 응답을 폐기한다. pending inspection부터 send 이후 정리까지
Windows zero-share exact-file handle을 유지하고 같은 handle만 delete-pending으로
전환하므로 close 뒤 path 삭제 간격이나 교체 파일 삭제가 없다. pending record가
남아 있다면 재인증 후 서명 계정과 동일한 signed bytes를 다시 확인하고 exact
retry할 수 있다.
또한 현재 demo는 eframe의 focus 상태를 사용하며 Windows session-lock 알림을 직접
구독하지 않는다. OS session-lock 감지, 취소 가능한 signer/RPC 작업, GUI framework
내부 text cache까지 포함한 물리적 memory zeroization은 production hardening 범위다.

`smoke` 검사는 생성/가져오기/열기/계정 전환/이전/내보내기 명령 경계, 저장 토큰의
선택·준비·2초 확인·새로고침·삭제, 보류 거래 서명 계정 확인·별도 2초 retry,
durable 활동 행 생성과 정확히 한 행만 새로고침하는 경계,
복구 백업·내보내기 2초 hold도 확인하지만 지갑
파일을 만들거나 읽지 않고, 네트워크에도 연결하지 않습니다.
주소·비밀번호·키·경로도 출력하지 않습니다. 결과는 짧은 JSON 한 줄이며 성공하면
종료 코드 `0`, 실패하면 `0`이 아닌 코드가 나옵니다. `rpc`와 `all`만 실제 Sepolia
네트워크에 연결합니다. 기존 `--check-rpc`도 `--headless rpc`와 같은 방식으로
창 없이 동작합니다.

## 자동검사

`TEST-WALLET.cmd`를 더블클릭하면 프로덕션 기반 코드와 릴리스 정책 검사를
실행합니다. 이 파일은 지갑 앱을 열지 않습니다.

- `PASS`: 현재 자동검사를 모두 통과함
- `FAIL`: 위쪽에 표시된 실패 내용을 확인해야 함

PowerShell에서 직접 검사하려면 다음 명령을 사용하세요.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check.ps1 check
cargo test --manifest-path demo/sepolia-wallet/Cargo.toml --locked
```

## 확인된 테스트 결과

2026년 8월 21일 기준:

- Sepolia 실행판 테스트 264개 통과
- 실제 Sepolia chain ID와 고정 genesis 연결 확인 통과
- Sepolia 실행판 포맷·엄격한 Clippy·릴리스 빌드 통과
- 프로덕션 Rust 테스트 548개 실행 통과
- 부모 커널 테스트 전용 headless 자식 fixture 6개는 직접 실행하지 않도록 의도적으로 제외
- 위 Rust 테스트와 별도로 보안용 컴파일 실패 테스트 23개 통과
- Chrome 확장 프로그램 테스트 33개 통과
- 릴리스 정책·검증기 테스트 34개 통과
- 개인정보 스캔과 보안 아키텍처 불변조건 검사 통과

## 왜 메인넷은 여전히 잠겨 있나요?

Sepolia 앱은 프로덕션 지갑과 분리된 연습용 실행판입니다. 프로덕션 경로의
보안 잠금은 그대로 유지됩니다.

- Broker, Key Agent, 승인 UI, 비밀 입력 UI는 종료 코드 `78`로 닫혀 있습니다.
- Native Host는 하나의 제한된 연결을 유지하며 각 유효 요청에
  `4900 Wallet unavailable`을 반환하고, 입력 종료나 첫 프로토콜 오류 뒤 종료 코드
  `78`로 닫힙니다. 현재 실행 경로의 릴리스 증명은 항상 비활성이라 Broker나 후속
  실행기는 호출되지 않습니다.
- Windows Native Host↔Broker 조합은 별도의 debug-assertion 전용 기능에서만
  headless로 시험합니다. 이 경로는 동시에 잡아 둔 정확한 `broker.exe` 파일과 첫
  `CREATE_PROCESS_DEBUG_EVENT`의 이미지 파일을 `FILE_ID_INFO`로 사용자 코드 실행 전에
  비교하고, 최소 2개 환경 변수·부모 프로세스 capability와 단일 read/write NUL 표준
  입출력만 담은 정확한 상속 핸들 목록·1프로세스 kill-on-close Job·비공개 프로세스 결합
  파이프를 함께 유지합니다. 파이프 프레임은 4바이트 big-endian
  길이와 최대 8,192바이트 JSON payload 하나이며, 닫힌 typed 상태기계는
  `eth_chainId`·지원 불가·취소만 표현합니다. 계정, 외부 RPC, 서명 기능은 없습니다.
  기본 빌드와 모든 기능을 켠 릴리스 빌드는 위의 `4900`/종료 코드 `78` 동작을 그대로
  유지합니다.
- 이 debug 증거는 Chrome이 시작한 Native Host 자신의 정확한 이미지나 Authenticode
  릴리스 정책을 증명하지 않습니다. 서명되고 변경 불가능한 설치 위치, Native
  Messaging 등록, 고정된 확장 프로그램 ID와 설치 시점 allowlist가 결합되기 전에는
  릴리스 Broker 시작 경로로 사용할 수 없습니다.
- 일반 빌드에는 Broker 전송 증거와 Broker manifest를 3개 서명 helper allowlist와
  분리해 검사하는 비공개 사전검증 capability도 있습니다. 역할, 완전한 릴리스 증거,
  정확한 manifest, 절대 경로를 순서대로 확인하지만 실행·프로세스·파이프 API가 없고
  어떤 supervisor도 아직 소비하지 않습니다. 실제 릴리스 정책은 계속 `None`이므로
  이 구조만으로 Broker가 시작되지는 않습니다.
- Key Agent 실행 준비 경계는 정확한 실행 파일, 비공개 파이프 3개와 2프로세스
  Windows Job을 한 번의 생성에 묶지만, 프로세스는 검증 후에도 정지된 채이며
  시작하거나 재개하는 API가 없습니다.
- Key Agent 전용 LPAC·저장소 ACL, 최소 환경/작업 폴더, Broker 시작 nonce 교환과
  보호 설정 lease 연결이 아직 없습니다.
- 실제 릴리스 정책과 서명된 설치 증거가 없으면 helper를 실행할 수 없습니다.
- 독립 보안 검토와 Windows 격리 E2E 증거가 없으면 메인넷 서명이 불가능합니다.

따라서 Sepolia 앱이 실행된다는 사실은 실제 자금을 보관할 수 있는 완성된
메인넷 지갑이라는 뜻이 아닙니다.

## 폴더 안내

- `demo/sepolia-wallet`: 실행 가능한 Sepolia 테스트넷 앱
- `crates/secret-core`: 프로덕션 암호화 저장소와 키 파생 핵심부
- `crates/wallet-model`, `crates/wallet-protocol`: 거래·승인·nonce 상태기계
- `crates/key-agent`, `crates/platform-windows`: 격리 서명과 Windows 보안 경계
- `crates/broker`, `crates/native-host`, `extension`: 브라우저 비신뢰 경계
- `crates/approval-ui`, `crates/secret-input-ui`: 승인·비밀 입력 화면
- `docs`: 상세 설계, 프로토콜, 보안 결정과 출시 차단 조건

프로덕션 상태는 [아키텍처 문서](docs/architecture.md)와
[보안 결정 문서](docs/security-decisions.md)에서 자세히 볼 수 있습니다.
