# Your Wallet

정식 지갑의 백업 원칙과 복구 연습은
[한국어 지갑 백업·복구 안내](docs/recovery-guide.ko.md)에 따로 정리했습니다.

Windows에서 더블클릭으로 실행하는 **Ethereum Sepolia 테스트넷 전용 지갑**입니다.

앱을 실행하려면 [`RUN-SEPOLIA-WALLET.cmd`](RUN-SEPOLIA-WALLET.cmd)를
더블클릭하세요. [`TEST-WALLET.cmd`](TEST-WALLET.cmd)는 앱이 아니라 개발자용
자동검사 파일입니다.

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
5. 잠시 표시되는 복구 문구를 종이나 오프라인 매체에 정확히 적습니다. 확인이
   끝나면 `백업 확인 후 v2 저장 — 2초 동안 누르기`를 2초 동안 계속 누릅니다.
   이 확인 전에는 지갑 파일을 쓰지 않습니다.
6. 화면에 나온 내 주소 옆의 `주소 복사`를 누릅니다.
7. [ethereum.org의 Sepolia faucet 안내](https://ethereum.org/developers/docs/networks/)에서
   복사한 주소로 무료 테스트 ETH를 받습니다. Faucet마다 로그인이나 사용량
   제한이 있을 수 있습니다.
8. 앱으로 돌아와 `새로고침`을 눌러 Sepolia ETH 잔액을 확인합니다.
9. 받는 Sepolia 주소와 보낼 금액을 입력하고 가스 수수료를 `추천`, `빠르게`,
   `직접 입력` 중에서 고른 뒤 `전송 내용 준비`를 누릅니다. 처음에는 `추천`을
   사용하면 됩니다.
10. 앱이 확정해서 보여 주는 항목을 전부 확인합니다.

   - 받는 주소
   - 보낼 금액
   - nonce
   - 수수료 방식과 고정 가스 한도 `21,000`
   - 견적 시점의 기본 수수료
   - 최대 우선 수수료 / gas
   - 최대 수수료 / gas
   - 현재 기준 예상 네트워크 수수료와 예상 총액
   - 최대 네트워크 수수료
   - 최대 총지출
   - 준비 완료 시점에 남은 견적 유효 시간

11. 하나라도 틀리면 `취소하고 수정`을 누릅니다. 모두 맞으면
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
- 검증한 커스텀 ERC-20 토큰을 목록에 추가하고 잔액을 볼 수 있지만, 토큰 전송,
  임의 컨트랙트 호출, 메시지 서명은 지원하지 않습니다.
- 네트워크를 바꾸거나 RPC 주소를 직접 입력할 수 없습니다.

새 지갑은 운영체제 난수로 만든 영어 복구 문구와 정확한 계정 메타데이터를 v2
암호화 파일에 저장합니다. 복구 문구 지갑은 계정 0과 1을 검증하지만, 현재
송금·개인 키 내보내기는 계정 0만 사용합니다. 가져온 개인 키 지갑은 계정 0
하나만 가집니다.

```text
%LOCALAPPDATA%\YourWallet\SepoliaDemo\vault-v2.bin
%LOCALAPPDATA%\YourWallet\SepoliaDemo\tokens-v1.bin
```

`vault-v1.bin`은 이전 실행판에서 만든 개인 키 지갑을 열고 이전하기 위해서만
지원합니다. `v1 → v2 이전`은 기존 비밀번호로 다시 인증하고 새 v2 비밀번호를
두 번 확인한 뒤 같은 개인 키와 주소를 보존합니다. v1에는 애초에 복구 문구가
없었으므로 이전 뒤에도 복구 문구 내보내기는 불가능합니다.

새 지갑 생성/가져오기/이전은 기존 v1 또는 v2 파일을 덮어쓰지 않습니다. 전송
결과가 불확실한 보류 거래가 있으면 먼저 같은 거래의 상태를 해결해야 하며,
그동안 지갑 생성·가져오기·이전을 차단합니다.

지갑을 연 뒤 `지갑 비밀값 내보내기`에서 현재 비밀번호를 다시 입력하고 버튼을
2초 동안 계속 누르면, 복구 문구 지갑의 복구 문구 또는 계정 0 개인 키를 약
20초 동안 한 번만 표시합니다. 표시값은 `Clone`/일반 디버그 출력이 없는
zeroizing 소유값이며 시간이 끝나거나 닫으면 지웁니다. 화면 캡처·악성 프로그램
등의 위험은 막아 주지 못하므로 테스트 키만 사용하세요.

## 전송 화면이 두 단계인 이유

`전송 내용 준비`는 아직 서명하거나 전송하지 않습니다. Sepolia에서 nonce,
잔액, 수수료를 확인한 뒤 정확한 전송 내용을 고정해 보여 주기만 합니다.

그다음 화면에서 모든 항목을 확인하고 2초 동안 버튼을 눌러야만, 준비해 둔
동일한 내용을 서명하고 전송합니다. 미리보기의 문자열이나 처음 입력한 값을
나중에 바꿔도 백엔드에 고정된 거래 내용이 몰래 바뀌지 않습니다.

수수료 견적의 최대 수명은 60초입니다. 화면에는 네트워크 조회까지 모두 끝난
준비 완료 시점에 실제로 남은 시간을 소수점 이하를 버려 보수적으로 표시합니다.
2초 확인 버튼을 끝까지 누를 시간을 보장하기 위해 남은 시간이 온전한 3초보다
짧으면 미리보기를 만들지 않고 다시 준비하라고 안내합니다.
확인할 때 Sepolia 네트워크, 고정한
nonce, 현재 기본 수수료, 보류 거래를 반영한 잔액, 일반 ETH 전송의 가스 사용량
`21,000`을 다시 확인합니다. 하나라도 달라졌거나 확인 도중 견적이 만료되면
수수료나 nonce를 몰래 바꾸어 서명하지 않고, 미리보기를 없앤 뒤 다시 준비하라고
안내합니다.

전송 결과를 확인하지 못한 채 네트워크가 끊기면 새 거래를 만들지 마세요.
화면 아래의 `전송 중 네트워크가 끊겼나요?`를 열고
`이전 거래 그대로 다시 전송`을 사용하면, 디스크에 보관된 같은 서명 거래만
다시 제출합니다.

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

이 데모는 데이터가 없는 일반 ETH 전송만 지원합니다. 준비할 때와 확인할 때
Sepolia 노드의 가스 추정값이 정확히 `21,000`인지 확인하며, 컨트랙트 실행처럼
더 많은 가스가 필요한 전송은 서명하지 않습니다. 가스 한도는 직접 바꿀 수
없습니다.

이미 서명되어 보류 중인 거래에는 새 수수료 방식을 적용할 수 없습니다.
`이전 거래 그대로 다시 전송`은 저장된 서명 거래의 같은 바이트만 재전송하며,
새 nonce·수수료·서명을 만들지 않습니다.

## 커스텀 ERC-20 토큰 추가

v2 지갑을 연 뒤 `커스텀 ERC-20 토큰`에서 Sepolia 토큰 컨트랙트의 전체 `0x`
주소를 입력하고 `검증 후 추가`를 누릅니다. v1 지갑은 먼저 `v1 → v2 이전`을
완료해야 합니다. 토큰 목록은 최대 32개입니다.

앱은 고정 Sepolia RPC에서 다음 항목을 확인한 뒤에만 토큰을 암호화 목록에
저장합니다.

- 해당 주소에 비어 있지 않은 컨트랙트 코드가 있는지
- 코드의 SHA-256 해시
- 표준 ABI로 정확히 디코딩되는 `decimals`, 선택적 안전 ASCII `symbol`
- 현재 계정 0의 `balanceOf` 잔액

화면에는 심볼만 표시하지 않고 전체 컨트랙트 주소를 항상 함께 표시합니다.
심볼은 컨트랙트가 제공한 신뢰되지 않은 표시 이름입니다. 지갑을 다시 열거나
`저장된 토큰 다시 검증`을 누르면 코드 해시와 메타데이터를 다시 읽습니다. 저장
뒤 코드나 메타데이터가 달라졌거나 응답이 잘못되면 기존 심볼·decimals·잔액을
숨기고 전체 주소와 실패 범주만 보여 줍니다.

`tokens-v1.bin`은 v2 지갑의 별도 파생 키와 vault ID에 묶인 고정 크기 인증 암호화
파일입니다. 임시 파일을 완전히 기록하고 flush한 뒤 원자적으로 교체하고, 설치된
바이트를 다시 열어 검증합니다. 다만 이 데모의 token generation은 하드웨어
롤백 방지 앵커가 아니라 파일 일관성 값입니다. 같은 사용자가 과거의 유효한
`tokens-v1.bin`을 되돌리면 이전 목록이 다시 보이거나 최신 항목이 사라진 사실을
완전히 탐지하지 못합니다. 표시되는 토큰은 매번 온체인 정보를 재검증하지만,
이 제한 때문에 메인넷 자산 관리용으로 사용하면 안 됩니다.

현재 커스텀 토큰은 추가·조회·새로고침·삭제만 지원합니다. 토큰 전송 버튼은
제공하지 않으며, 일반 ETH 전송의 고정 가스 `21,000` 경로와 섞지 않습니다.

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
# 가장 빠른 확인: 가짜 백엔드로 지갑 관리, 비밀값 hold, 세 수수료 방식과 전송 흐름 검사
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
send 직전, send 반환 후 record 삭제 전에 epoch를 다시 확인한다. retry도 pending
record를 읽은 뒤, chain 검증 뒤 send 직전, send 반환 후 삭제 전에 확인한다. 따라서
마지막 pre-send check 전에 감지된 잠금은 새 broadcast를 만들지 않는다.
post-write/pre-send 또는 post-send/pre-delete check가 잠금을 관찰하면 이미 기록된
`pending-v1.bin`을 보존한다.

마지막 pre-send check가 이 demo의 외부 side-effect commit point다. 그 check를 통과한
직후부터 실제 transport send가 시작되는 사이 또는 send가 실행 중일 때 잠금이
경합하면 transaction 전파 자체는 취소할 수 없다. 다만 send 반환 직후의
post-send check가 epoch 변경을 관찰하면 성공 hash가 일치해도 `pending-v1.bin`을
삭제하지 않고 stale UI 응답을 폐기한다. 이 check가 통과한 직후와 실제 파일 삭제
사이에 잠금이 경합하면 삭제가 먼저 끝날 수 있다. pending record가 남아 있다면
재인증 후 동일한 signed bytes의 상태를 복구하거나 exact retry할 수 있다.
또한 현재 demo는 eframe의 focus 상태를 사용하며 Windows session-lock 알림을 직접
구독하지 않는다. OS session-lock 감지, 취소 가능한 signer/RPC 작업, GUI framework
내부 text cache까지 포함한 물리적 memory zeroization은 production hardening 범위다.

`smoke` 검사는 생성/가져오기/열기/이전/내보내기 명령 경계와 복구 백업·내보내기
2초 hold도 확인하지만 지갑 파일을 만들거나 읽지 않고, 네트워크에도 연결하지 않습니다.
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

2026년 8월 20일 기준:

- Sepolia 실행판 테스트 129개 통과
- 실제 Sepolia chain ID와 고정 genesis 연결 확인 통과
- Sepolia 실행판 포맷·엄격한 Clippy·릴리스 빌드 통과
- 프로덕션 Rust 테스트 511개 실행 통과
- 부모 커널 테스트 전용 headless 자식 fixture 3개는 직접 실행하지 않도록 의도적으로 제외
- 위 Rust 테스트와 별도로 보안용 컴파일 실패 테스트 23개 통과
- Chrome 확장 프로그램 테스트 24개 통과
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
