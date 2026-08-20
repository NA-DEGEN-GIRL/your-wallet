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
4. `새 테스트 지갑 만들기`를 누릅니다.
5. 화면에 나온 내 주소 옆의 `주소 복사`를 누릅니다.
6. [ethereum.org의 Sepolia faucet 안내](https://ethereum.org/developers/docs/networks/)에서
   복사한 주소로 무료 테스트 ETH를 받습니다. Faucet마다 로그인이나 사용량
   제한이 있을 수 있습니다.
7. 앱으로 돌아와 `새로고침`을 눌러 Sepolia ETH 잔액을 확인합니다.
8. 받는 Sepolia 주소와 보낼 금액을 입력하고 `전송 내용 준비`를 누릅니다.
9. 앱이 확정해서 보여 주는 다음 7개 항목을 전부 확인합니다.

   - 받는 주소
   - 보낼 금액
   - nonce
   - 최대 우선 수수료 / gas
   - 최대 수수료 / gas
   - 최대 네트워크 수수료
   - 최대 총지출

10. 하나라도 틀리면 `취소하고 수정`을 누릅니다. 모두 맞으면
    `확인하고 전송 — 2초 동안 누르기`를 2초 동안 계속 누릅니다. 미리보기가
    나오기 전에는 이 최종 전송 버튼을 사용할 수 없습니다.

앱을 다시 실행할 때는 같은 비밀번호를 입력하고 `기존 테스트 지갑 열기`를
누르면 됩니다.

## 꼭 알아둘 제한사항

이 실행판은 기능을 연습하고 Sepolia에서 전체 흐름을 확인하기 위한 별도
데모입니다.

- Ethereum 메인넷과 실제 ETH를 지원하지 않습니다.
- 복구 문구와 키 가져오기·내보내기를 지원하지 않습니다.
- Chrome 확장 프로그램이나 dApp과 연결되지 않습니다.
- 토큰 전송, 컨트랙트 호출, 메시지 서명을 지원하지 않습니다.
- 네트워크를 바꾸거나 RPC 주소를 직접 입력할 수 없습니다.

새 지갑은 운영체제 난수로 만든 키 하나를 로컬 암호화 파일에만 저장합니다.
복구 문구가 따로 없으므로 **지갑 파일이나 비밀번호 중 하나라도 잃으면 복구할
수 없습니다.** 연습용 일회성 계정으로 취급하세요.

```text
%LOCALAPPDATA%\YourWallet\SepoliaDemo\vault-v1.bin
```

## 전송 화면이 두 단계인 이유

`전송 내용 준비`는 아직 서명하거나 전송하지 않습니다. Sepolia에서 nonce,
잔액, 수수료를 확인한 뒤 정확한 전송 내용을 고정해 보여 주기만 합니다.

그다음 화면에서 7개 항목을 확인하고 2초 동안 버튼을 눌러야만, 준비해 둔
동일한 내용을 서명하고 전송합니다. 미리보기의 문자열이나 처음 입력한 값을
나중에 바꿔도 백엔드에 고정된 거래 내용이 몰래 바뀌지 않습니다.

전송 결과를 확인하지 못한 채 네트워크가 끊기면 새 거래를 만들지 마세요.
화면 아래의 `전송 중 네트워크가 끊겼나요?`를 열고
`이전 거래 그대로 다시 전송`을 사용하면, 디스크에 보관된 같은 서명 거래만
다시 제출합니다.

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

`RUN-SEPOLIA-WALLET.cmd`는 다음 두 단계만 수행합니다.

1. 잠금 파일에 기록된 정확한 의존성으로 Sepolia 앱을 릴리스 빌드합니다.
2. 빌드에 성공한 실행 파일을 엽니다.

Rust/Cargo가 설치되어 있지 않으면 스크립트가 설치 필요 메시지를 보여 줍니다.
자동으로 프로그램이나 지갑 키를 설치하지는 않습니다.

PowerShell에서 직접 빌드하고 실행하려면 다음 명령을 사용하세요.

```powershell
cargo build --release --locked --manifest-path demo/sepolia-wallet/Cargo.toml
.\demo\sepolia-wallet\target\release\sepolia-wallet-demo.exe
```

## 창 없이 확인하기 (권장)

제가 자동으로 확인할 때는 아래 헤드리스 모드를 사용합니다. 이 모드는 GUI 창을
열지 않고 마우스나 키보드를 움직이지 않습니다.

```powershell
# 가장 빠른 확인: 가짜 백엔드로 준비 → 미리보기 → 확정/취소/재시도 흐름 검사
cargo run --quiet --locked --manifest-path demo/sepolia-wallet/Cargo.toml -- --headless smoke

# 실제 네트워크 확인: 고정 Sepolia chain ID와 genesis 검사
cargo run --quiet --locked --manifest-path demo/sepolia-wallet/Cargo.toml -- --headless rpc

# 위 두 검사를 차례로 실행
cargo run --quiet --locked --manifest-path demo/sepolia-wallet/Cargo.toml -- --headless all
```

`smoke` 검사는 지갑 파일을 만들거나 읽지 않고, 네트워크에도 연결하지 않습니다.
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

- Sepolia 실행판 테스트 42개 통과
- 실제 Sepolia chain ID와 고정 genesis 연결 확인 통과
- Sepolia 실행판 포맷·엄격한 Clippy·릴리스 빌드 통과
- 프로덕션 Rust 테스트 498개 실행 통과
- 부모 커널 테스트 전용 자식 sentinel fixture 1개는 직접 실행하지 않도록 의도적으로 제외
- 위 Rust 테스트에 포함된 보안용 컴파일 실패 테스트 21개 통과
- Chrome 확장 프로그램 테스트 23개 통과
- 릴리스 정책·검증기 테스트 34개 통과
- 개인정보 스캔과 보안 아키텍처 불변조건 검사 통과

## 왜 메인넷은 여전히 잠겨 있나요?

Sepolia 앱은 프로덕션 지갑과 분리된 연습용 실행판입니다. 프로덕션 경로의
보안 잠금은 그대로 유지됩니다.

- Broker, Key Agent, 승인 UI, 비밀 입력 UI는 종료 코드 `78`로 닫혀 있습니다.
- Native Host는 `4900 Wallet unavailable`을 반환하고 종료합니다.
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
