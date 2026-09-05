# Your Wallet

## Current development checkpoint (2026-09-05)

Phase 3D now connects the debug service's Approval probe to the real native UI
with a service-authored **non-signing** request. Approval continues after
`HelperReady` through one bounded request and bound response plus EOF; the
historical ready-only Approval description below is superseded. Secret Input
remains ready-only. Fresh admitted-helper liveness and terminal cleanup precede
success, under the original five-second deadline. This is not installed-service
or signed-artifact evidence. Release remains **STOP-SHIP**, and both compiled
policies remain `None`. See [current status and completion gates](docs/development-status.md).

## Windows Phase 1 checkpoint (2026-08-30)

**Release status remains STOP-SHIP.** The debug-only Windows feasibility path
now creates a real suspended, inert target and reports it with the exact
96-byte `TARGET_FROZEN` frame. Its containment Job reads back exactly
`KILL_ON_JOB_CLOSE | ACTIVE_PROCESS`, `ActiveProcessLimit = 2`, and no
breakaway. Current-host probes cover the exact debugger/target topology
`2 -> 1 -> 0`, denial of a third member at the Job quota, and forced outer-
parent death before `READY_FROZEN`, at `READY_FROZEN`, and after target handoff.
The parent retains only narrow target process/thread handles; the measured host
adds native `THREAD_RESUME` (`0x1000`) to the requested thread mask, so this
normalization remains a supported-kernel matrix obligation.

Desktop RPC admission now rejects `SeDebugPrivilege` whenever it is assigned,
including assigned-but-disabled, and the authenticated desktop token must receive
exact `ERROR_ACCESS_DENIED` when opening the still-suspended child with only
`PROCESS_DUP_HANDLE`. Under the LPAC probe feature, the live RPC manager and its
independent If3 callback now classify desktop and service-created-LPAC callers
through the role-aware router. The service-owned expected-peer registry has
exactly eight slots, never reuses a retired slot during one server lifetime,
registers while the helper is suspended, publishes running state across the sole
resume, keeps callback observation non-consuming, consumes manager authority
exactly once, and uses a five-second terminal-cleanup quiescence bound.

The immutable version-1 `YWKASV01` service wire remains unchanged. A separate,
non-default `debug-feasibility-v2` module defines the debug-only `YWKASV02`
generation with six exact 20/52/72/72/68/68-byte request/response frames for
open-epoch, desktop command, and helper-ready exchanges. Its closed desktop
commands are status, Approval RPC probe, and Secret Input RPC probe; completed
results bind only to the matching probe, while `Unavailable` is the fail-closed
result for every command. No frame carries caller role, PID, or image authority.
Epoch slots permanently bind V1 or V2, and a wrong-version use consumes the
epoch before returning denial.

The feature-gated V2 desktop dispatcher now reaches the live `ServerContext`.
Open-epoch and status responses remain immediate, while Approval/Secret Input
probes become move-only launch actions. The exact consumed
`DesktopCommandRequest` is the sole source of helper role, epoch, request ID, and
matching success result; a caller cannot supply those values independently. The
RPC manager thread retains the one-shot response capability and sends only the
authenticated desktop authority plus an exact request copy to one coordinator
worker. One occupied flag spans the worker and its one-slot transport, so a
second launch returns correlated `Unavailable` instead of queuing behind active
work; the manager-side result wait is bounded at 20 seconds.

The debug coordinator derives an exact fixed sibling Approval or Secret Input
image, holds and hashes that file without write/delete sharing, creates the
service-owned LPAC on a fresh debugger thread, completes both authenticated
bootstrap gates, registers before resume, and waits while retaining the request
writer. This artifact pin is not Authenticode, version, manifest, or immutable-
installation proof. The sibling names `approval-ui.exe` and
`secret-input-ui.exe` are exact, including case after canonicalization; a
differently spelled or cased name fails closed as an availability failure.
Separate feature-gated entrypoints fix their roles. The status-only server keeps
its existing single AU/SY-`GA`, Medium/`NW` descriptor for both endpoint and
If3. The LPAC probe derives the exact Approval and Secret Input package SIDs from
their fixed profile monikers with OS APIs, then retains a separate Low/`NW`
endpoint descriptor granting connect `0x1` and an If3 descriptor granting `GA`
to AU, SY, and those two package SIDs. This closes the prior descriptor-level
transport-reachability defect in the debug composition; it is not installed-SCM
fixed-LPAC E2E evidence. Each helper uses the fixed
local endpoint with implicit WINNT credentials, packet privacy, and no RPC authz
mode; it sends the exact `HelperReady`, accepts only the correlated ACK, frees
the RPC binding, writes the distinct 72-byte `YWKHRC01` confirmation, closes the
response pipe, and blocks on the request pipe until service termination. The
confirmation remains correlation evidence only, not the adoption ACK or helper-
role authority.

Malformed helper candidates retire exact or identity-indeterminate peers rather
than preserving related authority. Cleanup, registry-internal, debugger-
invariant, or role-correlation failures latch fatal coordinator health and close
new RPC admission. Shutdown first completes RPC rundown, then stops and joins the
coordinator, then calls the helper registry's five-second quiescence stop. Only
the LPAC probe build derives a 30-second SCM hard fail-fast watchdog from the
terminal-resource bounds plus margin; that watchdog does not prove every Windows
call is interruptible and is not a clean per-operation deadline.

This is a no-secret, debug-only composition path, not proof that the Phase 1
exit gate has passed. No actual installed restricted SCM service has yet
completed the service-created LPAC
round trip across sessions under elevation, and the exact helpers have not been
proved signed, immutable, or release-manifest-bound. Parent-pinned production
image identity, system-wide sole Job-handle ownership, signed-helper `ncalrpc`
E2E, and the supported-kernel matrix remain open. Phase 1 is not passed, release
status remains **STOP-SHIP**, and both compiled policies stay `None`.

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
위의 repo-local 경계를 signed artifact와 실제 supervisor에 결합한 격리 Key Agent
증거와 완전한 zeroizing KDF 구현 없이는 출시하면 안 됩니다(STOP-SHIP).

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
- 프로덕션 Rust 테스트 549개 실행 통과
- 부모 커널 테스트 전용 headless 자식 fixture 6개는 직접 실행하지 않도록 의도적으로 제외
- 위 Rust 테스트와 별도로 보안용 컴파일 실패 테스트 23개 통과
- Chrome 확장 프로그램 테스트 33개 통과
- 릴리스 정책·검증기 테스트 66개 통과
- 봉인된 Windows 검증 도구셋·최소 환경·정확한 자식 출력·경로 교체 공격 회귀 통과
- 개인정보 스캔과 보안 아키텍처 불변조건 검사 통과

## 왜 메인넷은 여전히 잠겨 있나요?

Sepolia 앱은 프로덕션 지갑과 분리된 연습용 실행판입니다. 프로덕션 경로의
보안 잠금은 그대로 유지됩니다.

- Broker와 기본 빌드의 승인 UI·비밀 입력 UI는 종료 코드 `78`로 닫혀 있습니다.
  Key Agent도 직접 실행하거나 startup 모양이 틀리면 `78`로 닫힙니다. 정확한 private
  inherited startup만 request exact EOF 뒤 ambient stdin/stdout을 분리하고 raw stdin을
  닫은 뒤 root work로 진행합니다. response write/flush/close를 시도한 뒤에는 오류를
  `main`으로 돌려보내지 않고 `Sleep(INFINITE)`에 들어갑니다. 부모가 deadline 안에서
  exact response와 EOF를 모두 관찰해야만 storage 증명이 완성됩니다. runtime이나 signing
  protocol은 제공하지 않습니다.
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
  정확한 manifest, 절대 경로를 순서대로 확인한 뒤에만 `PreflightBrokerArtifact`가
  pinned Broker와 성공한 `ReleaseAttestation`의 opaque whole-release
  `AttestedArtifactDigest`를 함께 보관합니다. 이 값은 전체 `ReleasePolicy`
  `ArtifactDigest`에 대한 증거이며 Broker/helper manifest digest나 Windows file-object
  identity가 아닙니다. 그 모듈의 비공개 자식 supervisor만 이를 소비해
  `PreparedReleaseBrokerSupervisor`를 만들 수 있습니다. 이 non-clone 상태는 같은
  opaque whole-release 증거, 이미 잡아 둔 바로 그 파일 핸들, `FILE_ID_INFO`의 volume
  serial 및 128비트 file ID를 서로 별개로 보관합니다. production-compiled exact-image 활성화 core는
  prepared 값을 통째로 한 번 소비하고, 첫
  `CREATE_PROCESS_DEBUG_EVENT`의 mapped image가 같은
  파일 객체인지 user mode 전에 확인한 뒤 process·one-member Job·비공개 채널과 함께
  수명 끝까지 보유합니다. release 함수에는 경로, raw handle, PID, command line 또는
  generic launch 입력이 없고, 신원 검증을 위한 경로 재열기도 없습니다.
  이 증거 보존만으로 Broker와 Key Agent의 same-release aggregate, 인증된 process
  topology, single-instance 또는 runtime/signing authority가 생기지는 않으며, 이
  release-bound Broker preflight·preparation·activation에는 여전히 production caller가
  없습니다.
  `COMPILED_RELEASE_POLICY`는 계속 `None`이므로 이 core는 운영 진입점에서 도달할 수
  없으며 signed install, native-host provenance 또는 릴리스 활성화 완료의 증거도 아닙니다.
- Broker, Key Agent, 제한 helper launcher의 세 Rust production 상속형 생성 경로는
  이제 하나의 비공개 deadline-bound process-wide coordinator를 사용합니다. 각 경로의
  임시 inheritable-handle owner는 coordinator flight의 수명을 빌리며, `CreateProcessW`
  반환 뒤 `STARTUPINFOEX` attribute list와 임시 핸들을 정리한 다음에만 flight를
  해제합니다. deadline은 flight 획득과 명시적인 생성 직전 검사만 제한하며, 동기식
  `CreateProcessW`나 fresh worker의 최종 join을 중단시키지는 못합니다. 이 보장은 한
  프로세스에 적재된 같은 `platform-windows` crate instance와
  그 비공개 API를 따르는 Rust 호출에 한정됩니다. 임의의 foreign FFI,
  `std::process::Command`, 별도 프로세스나 별도 적재 사본의 생성까지 가로채지는 않습니다.
- 제한 helper와 휴면 Key Agent 생성은 이제 같은 비공개 process-context 기반 정책을
  사용합니다. OS가 보고한 system-shared Windows root에서 정확한 `SystemRoot`와
  `WINDIR` 항목을 만들고, 그 root 바로 아래의 검증된 `System32`를 명시적 current
  directory로 전달합니다. 그 두 이름은 immutable base block일 뿐입니다. 제한
  helper와 Key Agent는 각자의 고정 profile을 준비한 뒤
  `GetAppContainerFolderPath`가 돌려준 `...\Packages\<profile>\AC` 모양을 검증하고,
  그 상위 user-local-data base를 OS 유래 `LOCALAPPDATA`로 앞에 추가해 Windows가
  AppContainer 내부에서 rebase하도록 합니다. 최종 전달 allowlist는 모두 정확히
  `LOCALAPPDATA`, `SystemRoot`, `WINDIR` 세 이름입니다. 어느 경로도 부모의 ambient environment나 current
  directory를 상속하지 않습니다. 제한 helper는 이 preflight를 parent-proof, 영구
  profile, Job 작업 전에 끝내며, Key Agent도 inheritable-handle flight 획득 전에
  끝냅니다. 두 경로 모두 `CreateProcessW` 직전에 thread impersonation 부재를 다시
  확인합니다. 이 검증은 DOS 경로 문자열·root/System32 배치·directory/reparse 상태,
  모든 조상의 경로 교체 권한과 Windows root/System32 자체의 내용 생성 권한 거부에
  한정되며, directory handle을 유지하는 원자적 object-identity 증명이나 error
  mode/priority를 포함한 모든 Win32 process state 차단, DLL/dependency identity
  증거는 아닙니다.
- Key Agent 자식은 생성 시 inheritable stdio 핸들을 받지만, 실행 파일의 첫 Windows
  application 동작이 정확히 세 핸들을 모두 변경 전에 검사합니다. stdin/stdout은 서로
  다른 `PIPE`, stderr는 제3의 `CHAR` 객체여야 하고, 세 핸들은 서로 같은 커널 객체가
  아니며 flags가 각각 정확히 `HANDLE_FLAG_INHERIT`여야 합니다. 그 뒤 세 inherit bit를
  모두 제거하고 flags가 정확히 0인지 다시 확인합니다. 일부 제거가 실패해도 나머지
  핸들의 제거를 계속 시도하며 상속을 복원하지 않고, 오류에서는 다른 동작 전에 종료
  코드 78로 닫힙니다. 별도 child/grandchild 커널 테스트는 봉인 전의 세 exact stdio
  객체가 grandchild에 하나도 나타나지 않음을 `CompareObjectHandles`로 확인합니다.
- Windows 경계에는 비공개 Approval release-admission 준비 상태도 추가되어 있습니다.
  역할, 완전한 release attestation, helper manifest allowlist, 절대 경로를 순서대로
  통과한 `PreflightApprovalArtifact`만 이미 pinned된 같은 파일 핸들에서
  `FILE_ID_INFO`를 얻어 `PreparedReleaseApprovalSupervisor`로 이동할 수 있습니다. 두
  상태는 non-clone이며 artifact, whole-release identity, exact file identity를 별도로
  보유하지만 process, Job, pipe, channel, thread, launch state 또는 두 번째 파일 핸들을
  만들지 않고 path/PID/raw-handle accessor도 제공하지 않습니다. 기존
  `launch_approval_frontend`, `PendingApproval`, `LaunchedHelper`,
  `RestrictedLauncher::spawn`은 외부 crate에서 더 이상 호출하거나 보유할 수 없습니다.
  legacy launcher는 wrong role을 먼저 구분한 뒤 complete logical-parent aggregate가 없으면
  `LogicalParentUnavailable`로 nonce/pipe/process/request 작업 전에 fail closed하며 더 이상
  `RestrictedLauncher::spawn`을 호출하지 않습니다. 범용 `spawn` 자체도 Approval role을
  `ApprovalRequiresParentBoundActivation`으로 생성 전에 거부하고, 내부 legacy launch leaf는
  Secret Input role만 허용해 parentless Approval resume를 이중으로 닫습니다.
  이어지는 비공개 전이는 이 준비 상태와 분해하지 않은 전체
  `BoundStorageProvenKeyAgent`를 함께 소비합니다. 같은 실행 중인 storage-proven Key Agent
  process object에서 PID로 다시 열지 않고, 상속 불가이며 접근권이 정확히
  `PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE`인 fresh duplicate 하나만 만들어
  `ParentBoundReleaseApprovalSupervisor` 안에 보유합니다. 이 opaque 상태는 constituent,
  PID, path 또는 raw handle accessor와 launch operation을 제공하지 않으며, 새로 보유하는
  OS 자원도 그 narrow handle 하나뿐입니다. Approval session 발급 시 플랫폼은 caller가
  절대 deadline을 넣을 수 없는 단 하나의 opaque monotonic window를 만들고, 같은 발급
  identity를 공유하는 non-Clone authorization/transport half로 이를 분할합니다.
  `wallet-protocol`은 두 half를 비공개로 함께 보유하고, invalidation은 사용하지 않은
  transport half를 폐기합니다. Key Agent가 protected phrase와 authorization TCB의 exact
  digest, one-shot nonce, canonical display로 canonical request를 만든 뒤에만 matching
  authorization half가 transport half를 한 번 소비해 opaque `BoundApprovalTransport`로
  묶습니다. production binder에는 새 비공개 consumer가 정확히 하나 있습니다. 이
  consumer는 parent-bound aggregate와 그 carrier를 함께 소비하고, original expiry가 이미
  끝났으면 pipe 또는 process를 만들기 전에 거절합니다. 이어 고정 revision-v1 Approval
  profile과 exact two-object private stdio를 사용해 Approval process를 single-process Job
  안에 만들지만 primary thread를 resume하지 않습니다. 기존 channel-supervisor
  process/image proof는
  그대로 두고, narrow Key Agent handle은 별도의 다섯 번째 non-inheritable
  logical-parent capability로 suspended child에 복사합니다. 결과
  `BoundDormantApproval`은 process/thread/Job, 아직 사용하지 않은 parent endpoints, 전체
  parent-bound aggregate와 bound transport carrier를 함께 보유하고 자체
  resume/request/response/signing 또는
  path/PID/raw-handle operation을 제공하지 않습니다. Drop은 pipe와 Key Agent tree를
  놓기 전에 bounded terminate/reap을 시도하며, 실패하면 retained kill-on-close Job을
  먼저 닫는 fallback을 사용합니다. 이 최외곽 dormant transition의
  production caller는 0개입니다. 이어지는 sealed consuming bootstrap transition만
  original expiry와 그 시점부터의 fresh 5초 grace 중 이른 값을 bootstrap deadline으로
  정합니다. bootstrap-v2 parent hello를 suspended child의 stdin에 먼저 기록하고,
  primary thread의 정확한 suspend count 하나를 한 번만 해제한 뒤 exact child hello를 읽고
  transcript 및 child/Job/전체 parent-bound aggregate를 재검증합니다. 성공한
  `AuthenticatedApprovalBootstrap`은 실행 중인 Approval, 두 parent endpoint, 두 hello,
  전체 Key Agent aggregate와 bound transport carrier를 함께 보유하며, 단 하나의 별도
  sealed function만 이를 소비할 수 있습니다. 그 full-exchange transition은 raw request나
  caller-supplied deadline을 받지 않습니다. carrier가 보존한 exact canonical request와
  original monotonic deadline을 내부에서 사용하고, 그 같은 deadline을 response arming,
  110-byte finish+canonical request의 consuming write와 request EOF, 고정 75-byte
  response+EOF 검증, exact held child의 자연 종료 wait에 모두 사용합니다.
  성공은 child/Job과 Key Agent를 finish 전과 response read 전에 재검증하고,
  response+EOF 뒤 그 exact process가 스스로 종료하여 exit code 0을 반환하고,
  그 자연 종료 후 Key Agent aggregate를 마지막으로 재검증하며, deadline이 아직
  유효할 때만 승인됩니다. 그 뒤에만 crate-private opaque
  `VerifiedParentBoundApprovalExchange`를 만들며, 이 값은 exited child, aggregate, hello,
  sealed response evidence와 original lifetime/request carrier를 함께 보존하지만 response
  accessor나
  `VerifiedApprovalResponse`/signing conversion을 전혀 제공하지 않습니다. 성공 경로는
  살아 있는 child를 강제 종료해 증거를 만들지 않습니다. malformed/truncated/trailing
  response 또는 EOF 오류, timeout, nonzero exit, wait 오류는 실패이며, 이때만
  별도 bounded terminate/reap을 시도하고 cleanup 실패를 원래 오류보다 우선합니다. Drop도 retained
  kill-on-close Job을 닫는 fail-closed fallback 전에 bounded cleanup을 시도합니다.
  bootstrap과 full-exchange transition 모두 production caller가 0개이고 signing composition은
  없습니다. 이 handle은 Approval이
  인증하는 logical parent proof source일 뿐이고
  `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`를 설정하거나 Windows process parentage를
  확립하는 capability가 아닙니다. bootstrap v2는 ordinary supervisor와 별도 Key Agent의
  child-local PID/handle을 함께 transcript에 묶되 pipe peer authority는 계속 supervisor로
  유지합니다. repo-local `cfg(test)` 통합은 actual
  zero-capability Approval LPAC에 그 exact handle을 non-inheritable로 복사하고,
  Key Agent logical-parent process proof에 대한 `OpenProcessToken(..., TOKEN_QUERY)`,
  session/image/PID/liveness/zero flags를 확인한
  뒤 12개 stronger/standard token right를 거부합니다. local `DuplicateHandle` denial
  matrix는 `PROCESS_DUP_HANDLE`, `PROCESS_TERMINATE`, `PROCESS_CREATE_THREAD`,
  `PROCESS_VM_OPERATION`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`,
  `PROCESS_CREATE_PROCESS`, `PROCESS_QUERY_INFORMATION`, `PROCESS_SET_QUOTA`,
  `PROCESS_SET_INFORMATION`, `PROCESS_SET_LIMITED_INFORMATION`(`0x2000`),
  `PROCESS_SUSPEND_RESUME`, `WRITE_DAC`, `WRITE_OWNER`, `READ_CONTROL`, `DELETE`를
  각각 요청합니다. PID-reopen denial matrix는 `PROCESS_DUP_HANDLE`,
  `PROCESS_QUERY_INFORMATION`, `PROCESS_QUERY_LIMITED_INFORMATION`,
  `PROCESS_SET_LIMITED_INFORMATION`(`0x2000`), `SYNCHRONIZE`, query-limited/synchronize의
  exact combined mask, `WRITE_DAC`을 요청합니다. 또한 `SeDebugPrivilege` LUID가
  없음을 증명합니다. production Key Agent activation의 첫 token-hardening
  phase는 `CREATE_PROCESS_DEBUG_EVENT`에서 then-current token을 정확히
  `TOKEN_QUERY | WRITE_DAC | READ_CONTROL` 권한의 `Hwrite`로 열고, 별도
  temporary current-token `Hadjust`를 exact `TOKEN_QUERY | TOKEN_ADJUST_DEFAULT`로
  엽니다. 어떤 mutation보다 먼저
  `CompareObjectHandles(Hwrite, Hadjust)`가 exact same token object임을 증명해야
  합니다. 이 phase에서는 protected three-ACE token-object DACL만 설치한 뒤 같은
  `Hwrite`에서
  `GetKernelObjectSecurity(DACL_SECURITY_INFORMATION)`를 bounded two-pass로 즉시
  read back합니다. 1차 조회는 `ERROR_INSUFFICIENT_BUFFER`와 1..=64 KiB의
  필요 크기를 내야 하고, 2차 결과와 descriptor 길이는 그 크기와 정확히
  같아야 합니다. readback은 valid self-relative이며 DACL은 present/protected,
  non-defaulted, non-auto-inherited여야 합니다. `ACL_REVISION`과 zero reserved
  fields, exact offset/length/end shape 안에 zero-flag explicit `ACCESS_ALLOWED_ACE` 세 개만
  stable `TokenUser` SID + `TOKEN_ALL_ACCESS`, fixed Key Agent SID +
  `TOKEN_QUERY | TOKEN_DUPLICATE`, fixed Approval SID + `TOKEN_QUERY` 순서로 존재해야
  하며, mask·binary SID·ACE/ACL/descriptor byte shape의 extra/slack/trailing byte를 모두
  거부합니다. fresh `Hfinal`은 여전히 exact
  `TOKEN_QUERY | TOKEN_DUPLICATE | READ_CONTROL`만 가지고 `Hwrite`·`Hadjust`와
  same object임을 통과해야 합니다. `Hwrite`는 checked-close하지만
  `Hadjust`는 아직 final proof가 아닌 opaque `PendingKeyAgentLpac` 안에만 남습니다.
  이 값은
  `PreparedKeyAgentLpac::prepare_suspended_process_for_gate(...)`만 만들 수 있습니다.

  `TokenDefaultDacl`의 pre-resume kernel matrix는 이제 현재 same-user LPAC 경계를
  확정합니다. green
  `pre_resume_token_default_dacl_matrix_proves_loader_and_same_user_boundary`의 여덟
  case 중 no-mutation control과 original DACL exact deep-copy control은 user mode exit
  0이고, `OWNER RIGHTS` mask `0x000e0000` deny를 앞에 둔 나머지 여섯 case는
  `SYSTEM`/exact-package/child-user `GENERIC_ALL`의 tested 조합과 무관하게 모두 exact
  `0xC0000142`(`STATUS_DLL_INIT_FAILED`)입니다. green
  `pre_resume_owner_rights_deny_mask_axis_proves_each_standard_right_breaks_loader`는
  child-user, `SYSTEM`, exact package에 모두 `GENERIC_ALL`을 허용해도 standalone
  `READ_CONTROL`, `WRITE_DAC`, `WRITE_OWNER` 각각의 `OWNER RIGHTS` deny가 같은 exact
  loader failure를 만든다고 분해합니다. 원본 default DACL의 sanitized exact shape은
  child user `GENERIC_ALL`, `SYSTEM` `GENERIC_ALL`, logon-session
  `GENERIC_READ | GENERIC_EXECUTE`, exact package `GENERIC_ALL` allow입니다. 별도 green
  `lpac_package_sid_is_absent_from_groups_and_not_token_owner_eligible`는 exact package
  SID가 `TokenGroups`에 없고 `TokenOwner`로 설정하면 `ERROR_INVALID_OWNER`임을
  증명합니다.

  따라서 현재 same-user LPAC principal은 `WRITE_DAC`을 거부하면서 loader-compatible한
  from-birth policy를 제공할 수 없습니다. 이는 모든 Windows 설계의 불가능성이 아니라
  현재 아키텍처를 배제하는 host/kernel inference입니다. post-loader final DACL
  feasibility와 아래 gate machinery는 from-birth gap을 소급해 닫지 못합니다. 다음 설계
  후보는 Key Agent를 별도 OS principal/service boundary로 옮기고 그 principal·IPC·service
  lifecycle을 새로 증명하는 것입니다. 현재 구현의 final default DACL은 여전히
  CRT/TLS/runtime 초기화 뒤 `serve`의 reviewed semantic gate에서만 설치되며, gate 전에
  loader·DLL·TLS·CRT가 생성한 default-security object는 이 proof 밖입니다.
  별도의 생성 보안 단계는 launcher current token의 `TokenOwner`와
  `TokenPrimaryGroup`을 각각 bounded exact token query로 읽고, 서로 다른 두
  `LocalAlloc` self-relative descriptor와 non-inheritable `SECURITY_ATTRIBUTES`를
  만듭니다. 두 descriptor의 protected DACL은 allow ACE 없이 zero-flag
  `OWNER RIGHTS`(`S-1-3-4`) deny ACE 하나만 가지며, exact mask `0x000e0000`은
  `READ_CONTROL | WRITE_DAC | WRITE_OWNER`입니다. process와 primary-thread
  attributes는 분리할 수 없는 pair로만 `CreateProcessW`의
  `lpProcessAttributes`/`lpThreadAttributes`에 전달됩니다. 반환된 creator-owned
  process/thread exact handle에 대해 PID/TID와 `GetHandleInformation` exact-zero
  flags를 확인하고, bounded exact `GetKernelObjectSecurity` readback으로 captured
  owner/group, expected self-relative/DACL-present/protected control state, 요청한
  owner/group/DACL projection의 zero SACL offset, one-ACE ACL과 descriptor의
  no-slack/no-trailing shape를 첫 `ResumeThread` 전에 모두 다시 확인합니다. SACL
  자체는 요청하지 않으므로 실제 SACL 부재의 증거는 아닙니다. 불일치는 child를
  fail-closed cleanup하며 descriptor owner는 resume 전에 drop됩니다. creator
  handle은 PID/TID reopen으로 대체하지 않지만 `Held`까지 보유하지도 않습니다.

  child-side gate eligibility도 marker보다 앞에 고정됩니다.
  `serve_inherited_key_agent_storage_startup()`은 stdio를 보거나 INT3를 실행하기 전에
  `verify_current_key_agent_lpac_before_gate()`로 current process token을 fresh
  `TOKEN_QUERY | TOKEN_DUPLICATE` handle로 열고 fixed Key Agent SID, exact
  zero-capability LPAC policy를 검증한 뒤 그 handle을 checked-close합니다. 이 read-only
  검사가 성공해야만 아래 debugger gate로 들어갑니다. green `default_disabled`는 ordinary
  non-LPAC `key-agent.exe`가 INT3 없이 기존 silent exit 78을 유지함을 증명하며, LPAC
  policy mismatch도 stdio와 INT3 전에 fail closed합니다. 이는 gate eligibility와 ordering
  증거이지 actual production gate 성공 증거가 아닙니다.

  gate preflight는 이미 held/authenticated된 exact Key Agent file을 bounded AMD64
  PE32+ parser로 읽습니다. 전체 file에 exact one
  `49 BA <marker-le> CC` sequence만 허용하고, 11 bytes 전체가 하나의 executable
  section initialized raw non-padding range 안에 있을 때만 RVA를 만듭니다.
  `CREATE_PROCESS_DEBUG_EVENT` hFile이 같은 held file object임을 인증하고 그 event를
  continue하기 전에 checked-close한 뒤
  runtime gate INT3 주소는 preferred image base나 `lpStartAddress`가 아닌,
  authenticated `lpBaseOfImage + sequence_rva + 10`으로만 계산합니다.

  원래 `CREATE_SUSPENDED` count는 first debug event 생성을 위해 1→0으로 이미
  소비되었고, authenticated CREATE_PROCESS event 자체의 process-wide stop만 이 phase를
  고정합니다. pending token proof와 create-event hFile close가 끝난 뒤 그 event를
  continue해야만 loader가 실행됩니다. 현재 compiled candidate loop는 monotonic
  deadline, CREATE_PROCESS 뒤 event 최대 160개, 그중 `LOAD_DLL_DEBUG_EVENT` 최대
  128개를 두고 모든 event를 expected PID/primary TID로 제한하며
  `CREATE_THREAD`/`EXIT_THREAD`·`UNLOAD_DLL`·비-landmark exception을 거부합니다. 이 strict candidate는
  fail closed하지만 production-compatible contract는 아닙니다. test와 production은
  이제 loader event에 동일한 strict policy를 사용하며 진단용 worker 허용 경로는
  없습니다. green `real_key_agent_loader_activity_fails_closed_before_detach`는 실제
  GUI-subsystem `key-agent.exe`의 non-primary loader `CREATE_THREAD`를 detach 전에
  거부하고 joined Job cleanup을 확인합니다. GUI subsystem은 console host를
  구조적으로 제거하며 이 회귀 테스트의 root Job active-process count는 1을
  유지합니다. 이는 거부·정리 증거이지 product-compatible gate 성공 증거가
  아닙니다. 이전 CUI diagnostic fixture의 exact System32 `conhost.exe`와 root count
  2, multiple loader workers, worker-TID DLL load, first-chance C++ `0xe06d7363`, DLL
  unload 관측은 historical threat-model input일 뿐 현재 accepted event contract나
  gate proof가 아닙니다.

  replacement loop는 monotonic deadline/count 안에서 각 loader worker의 생성
  provenance, exact thread object/ID, 허용 event와 lifetime, semantic gate 전 전원 exit,
  post-exit fresh reopen denial을
  인증하고 모든 non-null hFile을 continue 전에 checked-close해야 합니다. 이 policy와
  bound는 아직 **STOP-SHIP**입니다. 재설계 뒤 automatic system breakpoint를 허용할
  때도 exact System32 `ntdll.dll` held `FILE_ID_INFO`가 pin한 allocation base,
  first chance, remote `0xCC`, `RIP == ExceptionAddress + 1`,
  `MEM_COMMIT | MEM_IMAGE`·executable·non-guard page를 요구하며 `DbgBreakPoint` export
  RVA나 fixed exception `NumberParameters` shape은 가정하지 않습니다.
  이 replacement loader policy가 성공하더라도 위 from-birth `WRITE_DAC` gap을 해소하지
  않으므로 현재 same-user architecture의 production admission 조건으로는 충분하지
  않습니다.

  revised loader policy가 gate까지 증명된 경우 cooperative gate event는 exact
  PID/primary TID의 first-chance `EXCEPTION_BREAKPOINT`, exact
  authenticated INT3 address, `RIP == address + 1`, `R10 == marker`, remote exact 11 bytes,
  그리고 authenticated main base와 같은 `AllocationBase`의
  `MEM_COMMIT | MEM_IMAGE`·executable·non-guard region을 모두 요구합니다. continue
  전에 explicit 16-byte-aligned AMD64 `CONTEXT` wrapper를 사용해 `R10`을 zeroing하고
  context readback으로 확인합니다. readback에서 달라질 수 있는 것은 reserved
  always-one EFLAGS bit 1의 API representation뿐이고, 모든 mutable flag bit와
  나머지 reviewed context field는 exact해야 합니다. debug-event stop
  안에서 primary `SuspendThread`가 prior count exact 0을 반환해 explicit count 1을
  만들어야 합니다.

  별도 green
  `minimal_primary_gate_proof_detaches_with_one_verified_suspend_count`는 deterministic,
  import-free, relocatable GUI PE fixture로 exact PID/primary-TID gate,
  `PendingKeyAgentLpac`→`VerifiedKeyAgentLpac`, verified suspend count 하나, detach와
  root Job count 1을 증명합니다. 이는 gate machinery proof이지 실제 Key Agent의
  loader compatibility, signed artifact, product E2E 증거가 아닙니다.

  supervisor test layering도 이 경계를 보존합니다. 같은 minimal PE를 쓰는 green
  `integrated_kernel_binding_owns_one_member_and_no_inheritable_parent_handles`와
  `dormant_aggregate_unwind_synchronously_aborts_the_exact_process`는 dormant ownership,
  non-inheritance, drop/unwind cleanup만 증명합니다. Rust-startup fixture를 storage와
  Approval까지 잇는 supervisor integration test 일곱 개는 loader worker가
  exact-primary gate보다 먼저 생성되므로 모두 명시적 `#[ignore = "STOP-SHIP: ..."]`이고
  성공 증거가 아닙니다. 반대로 green
  `rust_startup_fixture_loader_activity_fails_closed_before_supervisor_binding`은 그 loader
  activity가 `KeyAgentSupervisorError::Activation`을 반환하고 준비한 storage root를
  정리함을 증명합니다. actual production gate나 storage-startup 성공은 주장하지
  않습니다.

  그 상태에서 `PendingKeyAgentLpac::finalize_after_gate(...)`가 pending proof를
  소비해 current-token association,
  `Hfinal`·`Hadjust` exact object/identity, LPAC, token-object DACL을 다시 검증합니다.
  `Hadjust`는 그때만 `SetTokenInformation(TokenDefaultDacl)`로 exact 28-byte
  deny-only ACL을 설치합니다. 이 ACL은 `ACL_REVISION`, zero reserved fields,
  no allow ACE, exact one zero-flag `ACCESS_DENIED_ACE`, binary
  `OWNER RIGHTS`(`S-1-3-4`), exact `0x000e0000`
  (`READ_CONTROL | WRITE_DAC | WRITE_OWNER`), no slack/trailing bytes를 요구합니다.
  같은 `Hadjust`의 immediate bounded `GetTokenInformation(TokenDefaultDacl)`는 complete
  fixed prefix/returned range와 non-null aligned `PACL`의 header·entire 28-byte ACL range를
  checked arithmetic으로 먼저 증명한 뒤에만 slice를 만듭니다. OS API wrapper의
  initialized padding/trailing bytes는 허용하지만 28-byte ACL 내부 slack은 허용하지
  않습니다. mutation 후 exact
  statistics로 final baseline을 새로 잡고 provisional `TokenId` continuity를 확인한
  다음 `Hadjust`를 checked-close합니다. 조정 권한이 사라진 상태에서 `Hfinal`의 full
  policy·두 DACL·identity·baseline-equal statistics를 bookend하고 fresh current token
  same-object check까지 통과해야만 final proof가 됩니다. 나중 sole post-gate
  `ResumeThread`가 explicit count 1을 풀면 child는
  gate 다음의 첫 semantic step에서
  `verify_current_key_agent_default_dacl_after_gate()`로 current token을 fresh
  `TOKEN_QUERY` handle로 열고
  exact default DACL을 독립적으로 read back해야 다음 `serve` step으로 갈 수
  있습니다. final revalidation은 post-detach probe, narrow-process attenuation,
  post-gate execution을 풀어 주는 sole `ResumeThread` 직전, resident authority edge마다
  baseline-equal statistics로 `Hfinal`의 full LPAC policy·token-object DACL·
  `TokenDefaultDacl`을 bookend하고 fresh current token과 exact object/identity를 요구합니다.
  이는 point-in-time evidence이지 token association/contents의 atomic freeze가 아닙니다.

  첫 `CREATE_PROCESS_DEBUG_EVENT`의 process/thread alias는 서로 및 creator handle과
  distinct여야 하고, expected PID/TID와 creator handle에 대한 exact-object 일치를
  증명해야 합니다. debugging 중에는 system-managed observation으로만 다룹니다.
  CREATE_PROCESS event에서 독립적으로 안전한 raw alias가 드러나는 즉시 hFile,
  mapped-image, ID/object, LPAC 및 이후 fallible 검사보다 먼저 같은 run의
  witness-branded shared cleanup registry에 등록합니다. malformed partial event도
  안전한 alias는 보존하며 no-kill은 complete authenticated set을 다시 요구합니다.
  matching debugger OS thread를 join하고
  `CheckRemoteDebuggerPresent(FALSE)`를 확인한 뒤 normal finalization은 두 alias의
  distinct/object/ID/exact-zero flags를 다시 인증하고 thread alias, process alias
  순서로 checked `CloseHandle`하여 정확히 한 번 수거합니다. worker `Err`, panic,
  abandoned joined proof도 post-join registry cleanup을 실행합니다. adoption 실패는
  set을 복원하고 partial close는 남은 slot을 보존하며 last-owner `Drop`은 bounded
  retry합니다. 매 cleanup pass는 한 alias의 검증/close 실패와 무관하게 두 alias를
  각각 시도하고, post-join process cleanup 실패도 alias close를 막지 않습니다. 이
  thread-exit detach 경로에는 supervisor가 의존할 이후 exit event가
  없고 현재 host kernel에서는 두 alias가 live로 남습니다. 지원 Windows
  kernel/version별 동등한 증거는 **STOP-SHIP**입니다.

  detach 뒤 creator thread의 1→2→1 probe와 creator process의 token/root-Job
  revalidation을 마치면, inheritance false와 options 0인 `DuplicateHandle` 세 개를
  만듭니다. resident process access는 exact `0x00101001`
  (`PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE`)입니다.
  ephemeral post-detach probe는 exact `THREAD_SUSPEND_RESUME`(`0x2`)를 요청하지만
  modern Windows가 `THREAD_RESUME`을 자동 추가하므로 host의 effective
  `GrantedAccess`는 exact `0x1002`, attributes는 zero입니다. 별도의 retained startup
  handle은 `THREAD_RESUME`(`0x1000`)만 요청합니다. 모든 duplicate는 source와 same
  object이고 flags가 exact zero여야 합니다.

  narrow process 자체로 PID/liveness/current-token/root-Job을 검증합니다. ephemeral
  `0x1002` handle 자체로 다시 1→2→1을 검증한 뒤 `Held` 전에 checked-close합니다.
  checked-close 실패 시 RAII owner를 보존해 ordinary `Drop`이 즉시 재시도합니다.
  kernel test는 retained thread가 exact `0x1000`/zero attributes임과 그 handle의
  `SuspendThread`가 `ERROR_ACCESS_DENIED`로 거부됨을 증명합니다. 그 뒤에만 creator
  thread/process handle을 순서대로 checked-close하여 `Held`를 만들 수 있습니다.
  Microsoft Learn의 현재 [`ResumeThread` 문서](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread)는 여전히
  `THREAD_SUSPEND_RESUME`을 요구하지만 current SDK는 `THREAD_RESUME`을 공개하고
  host/integration kernel test는 resume-only 동작을 증명합니다. 이 문서/SDK 불일치,
  automatic-right addition, 지원 Windows version별 차이는 **STOP-SHIP** kernel-proof
  대상입니다.

  `Held`는 `Send`이지만 `!Sync`, `!Clone`, `!Copy`이며 exact `0x1000` resume-only
  thread만 보유합니다. 유일한 post-gate application-releasing `ResumeThread`가 prior count 1을
  반환하면 그 handle을 즉시 checked-close하며 실패 시 같은 RAII 재시도 소유권을
  유지합니다. `Running`은 같은 transfer trait과
  narrow process만 구조적으로 보유하고 thread handle은 없습니다. 명시적 실패는
  bounded terminate/wait/exact-exit-code cleanup을 수행하고 cleanup error가 우선합니다.
  `Drop`도 cleanup을 시도하지만 실패를 보고할 수는 없습니다.

  kernel test는 initial process/primary-thread pseudo-handle operation을 유지합니다. 별도
  green
  `post_loader_worker_feasibility_default_dacl_hardens_later_null_security_thread`는
  post-loader cooperative feasibility child의 READY 후 parent exact default-DACL
  install/readback/adjust-close, child의 independent current-token/default-DACL readback,
  real `CreateThread(NULL, ...)`, 그 thread의 pseudo `GetThreadTimes`·
  `OpenThreadToken(ERROR_NO_TOKEN)`, exact owner/group·one-ACE DACL, parent/child
  single-right `OpenThread` denial matrix, privilege bookend, checked cleanup, natural exit 0을
  증명합니다. default-created descriptor는 kernel-generated이므로 parser는
  `SE_SELF_RELATIVE | SE_DACL_PRESENT`만 요구하고 `SE_DACL_PROTECTED`·
  `SE_DACL_DEFAULTED`를 explicit protected creation descriptor와 같다고 가정하지 않습니다.
  이 ignored libtest probe는 non-primary TID에서 실행되므로 kernel feasibility이지
  위 실제 Key Agent의 loader-compatible exact-primary production gate를 대체하는
  증거가 아닙니다.
  last-check/`ResumeThread` gap 및 swap-away/back race는 **STOP-SHIP**이며, DACL 변경이
  `ModifiedId`를 갱신한다고 가정하지 않습니다. 생성 DACL 자체는 preexisting same-user
  high-right handle을 배제하거나 이미 반환·복제된 high-right handle을 회수하지
  못합니다. activation이 명시적으로 닫는 것은 자신이 인증한 creator pair뿐이며 다른
  alias는 proof 밖입니다. post-loader feasibility에서는 final default DACL 설치 이후
  default-security Win32 later thread가 tested host에서 이 정책을 상속합니다. 그러나
  actual Key Agent gate가 성공하지 않았고 from-birth `WRITE_DAC` denial도 양립하지
  않으므로 이 사실을 현재 architecture의 production coverage로 승격하지 않습니다.
  caller-supplied
  descriptor, raw native/remote thread creation, returned/preexisting/duplicated high-right handle은
  다루지 않습니다. `TokenDefaultDacl`은 thread-only 정책이 아니라 token-global
  default-object 정책입니다. gate 전 loader·DLL·TLS·CRT가 기존 default DACL로
  생성한 non-thread object/handle은 소급해 바뀌지 않으며 inventory도 아닙니다.
  hostile same-user process와 supervisor/owner를 완전히 분리하지도 않고,
  enabled debug/take-ownership privilege를 견디는 경계도 아닙니다. 따라서 distinct OS
  principal/service boundary와 same-user owner 분리는 다음 설계의 **STOP-SHIP**
  전제입니다. 모든
  continuity/revalidation failure는 다음
  typestate 또는 authority 사용 전에 fail closed합니다.
  `cfg(test)` integration은 token-object/creation DACL과 post-loader default-DACL kernel
  feasibility를 실행하고 Approval query-only 결과를 증명하지만,
  same-user isolation이나 release evidence는 아닙니다. Key Agent fixture는 CSPRNG
  directory와 copied executable 각각에서 exact current-user owner를 요구하고 read back하며,
  protected two-ACE DACL과 Medium/`NW` mandatory label을 명시 적용·재검증한 상태로
  `NO_LOW_LABEL`을 포함한 full mitigation을 유지합니다. 별도 Approval copied-image
  fixture만 mandatory label을 직접 read back하지 않고 profile-scoped copy를 위해
  `cfg(test)`에서 `NO_LOW_LABEL` 한 비트만 제거하며 production mitigation은 그대로입니다.
  이는 signed/mapped release proof가 아닙니다. signed DLL/TLS provenance, pre-gate
  non-thread object inventory, loader-worker provenance/lifetime/exit/reopen-denial
  policy, distinct OS principal/service design과 그 IPC/lifecycle proof,
  real GUI Key Agent loader-compatible exact-primary gate E2E,
  exact AMD64/context/system-breakpoint의 supported-architecture/Windows matrix와
  same-user owner 분리,
  caller-supplied/raw-native/remote thread 우회, preexisting/returned/duplicated high-right handle 및
  enabled privilege 위협, bootstrap/provenance, endpoint topology 및
  production cleanup/orchestration/signing은 여전히 release blocker이고, production
  binder caller는 0개이며 두 compiled policy는 `None`입니다.
- runtime-enabled Approval launcher의 `HANDLE_LIST`에는 stdin과 숫자상 같은
  stdout/stderr 응답 pipe인 정확히 두 stdio `PIPE` 객체만 들어갑니다. 자식은 이
  synchronous server ends를 상속하고 부모는 대응하는 overlapped client ends를
  보유합니다. supervisor process/image와 Key Agent logical-parent process proof handle은
  Approval 자식이 suspended인 동안 inherit 불가 상태로 원격 주입됩니다. 자식은 binary mode보다 앞선 첫
  Windows/CRT application 동작에서 두 stdio 객체의 `HANDLE_FLAG_INHERIT`인 exact
  inherit-only preflags를 확인하고 rollback 없는 순차 clear와 exact-zero readback으로
  먼저 봉인합니다. 그 뒤 Approval LPAC과 Job을 검증하고, 봉인된 stdin, shared
  output pipe, supervisor process proof, supervisor image proof, Key Agent logical-parent
  process proof가 모두 flags 0인 다섯 pairwise-distinct exact object인지 확인합니다. 세
  injected proof 모두 fresh child-local duplicate만 authority가 되어 response write까지
  유지되며, launcher가 아는 원래 source slot은 adopt하지 않고 bounded process-exit
  cleanup에만 남깁니다. 자식은 retained live exact supervisor process handle에서 부모
  PID와 process-token `TokenSessionId`를 도출하고, parent hello의 supervisor PID, 두 pipe server가
  보고한 client PID/session, 자식 token session이 모두 그 identity와 일치해야
  합니다. 별도 retained Key Agent process는 hello의 logical-parent PID, 동일 session,
  live/queryable image, 고정 `YourWallet.KeyAgent.LPAC.v1` SID, AppContainer/LPAC 상태와 zero
  capabilities 및 least-authority denial matrix를 독립적으로 만족해야 하며 pipe PID로
  사용하지 않습니다. 두 binding은 UI 표시와 response write 동안 보유되고 재검증됩니다. 따라서
  retained process handles가 live인 동안 PID-reuse substitution을 막고 supervisor가 pipe
  observation을 exact live ordinary channel-supervisor process object와 대조합니다. 다만 pipe handle은
  transferable/duplicable이므로 exclusive endpoint ownership, endpoint
  topology/exclusivity, per-write attribution은 증명하지 못합니다. image
  proof는 case-preserving exact normalized path-string equality를 사용합니다. 즉 live
  process image path와 별도 held file final path에서 선택적인 `\\?\` prefix와
  separator만 정규화하고, ambiguous casing은 fail closed입니다. 이어 held path의
  `\\key-agent.exe` suffix와 held-handle-derived path로 다시 조회한 version metadata를
  검사하고, held handle+path를 사용한 Authenticode signer 검증과 cloned held handle의
  SHA-256를 수행합니다. 따라서 live process가 그 exact file
  object에서 mapped되었다는 증명은 아닙니다. dormant binder가 보유하는 정확한
  `PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE` Key Agent handle은 별도 logical proof
  source입니다. 위 repo-local kernel probe는 실제 zero-capability Approval LPAC에서
  exact `TOKEN_QUERY` 사용과 위에 열거한 local `DuplicateHandle`/PID-reopen 요청의
  거부를 증명하지만, 현재
  channel-supervisor binding이나 signed/mapped image를 증명하지 않습니다. 따라서 두
  compiled policy는 계속 `None`이고 handle-first production 경로는 release-unproven입니다.

  wire가 정의하는 전체 Parent-auth 순서는 고정 74-byte bootstrap-v2 parent hello, 고정 106-byte child hello,
  110-byte parent-finish header와 exact request 및 request EOF, 고정 75-byte response와
  response EOF입니다. fresh nonzero parent nonce와 독립적인 fresh nonzero child nonce가
  domain-separated SHA-256 bootstrap transcript에 묶이고, parent-finish header는 두
  nonce, canonical request hash, exact request length를 함께 묶습니다. 자식은 그 길이의
  request 뒤 exact EOF가 있어야만 수락합니다. 부모가 response와 EOF 뒤 로컬에서
  계산하는 transcript는 held child PID/file identity, manifest digest, profile revision,
  request digest/one-shot Approval nonce/canonical hash, exact response bytes, child에게
  전송되지 않는 fresh parent-local transcript salt, 두 bootstrap nonce를 해시합니다. 이
  salt는 challenge-response 증거가 아닙니다. Job은 별도로 재검증되는
  live gate이지 hashed identity가 아닙니다. 고정 75-byte response는 magic, version,
  decision, request digest, one-shot Approval request nonce 순서이며, request에서
  echo하는 값은 digest와 nonce뿐입니다. bootstrap nonce는 echo하지 않습니다.
  따라서 replay 방어는 private one-shot endpoint와 fresh one-shot Approval request
  nonce에도 의존합니다. raw executable direct launch는 이 교환을 만들 수 없어 진단 없이
  종료되고, legacy Rust API는 resource allocation 전에 `LogicalParentUnavailable`을
  반환합니다. sealed parent는 hello bootstrap과 그 값을 소비하는 full exchange를
  별도 typestate로 구현합니다. bootstrap은 bound carrier의 original expiry와 fresh 5초
  grace 중 이른 값을 사용하고, full exchange는 raw request/deadline 인수 없이 carrier의
  exact request 및 original monotonic deadline을 사용합니다. 그 같은 deadline 안에서
  finish+request EOF, response+EOF, exact child의 자연 exit code 0, 자연 종료 후의 final
  Key Agent revalidation까지 완료한 뒤 accessor 없고 carrier를 보존하는
  `VerifiedParentBoundApprovalExchange`만 만듭니다. 이 transition의 production caller는
  0개이고 public `VerifiedApprovalResponse`나 signing으로의 conversion은 없습니다.
  post-exit Key Agent 검사는 그 시점의 증거이므로, 미래에 conversion을 추가한다면
  retained exact Key Agent를 authorization 사용 직전에 다시 검사해야 합니다.

  수명 경계는 하나의 platform-issued monotonic window에서 함께 나온 non-Clone
  authorization/transport half로 이어집니다. Key Agent가 exact phrase/request를 한 번
  묶은 opaque carrier는 dormant 상태 전에 소비되고, bootstrap과 full exchange 및 terminal
  evidence까지 original deadline과 같은 issuance identity를 유지합니다. wire의 relative
  expiry에서 full-exchange deadline을 다시 샘플하는 경로는 없습니다.

  별도 inheritable positive sentinel을 둔 repo-local child/grandchild 커널 테스트는
  sentinel은 broad-inheritance grandchild에 도달하지만 원래의 두 exact stdio
  객체는 도달하지 않음만 `CompareObjectHandles`로 확인합니다. 주입된 세 proof까지
  포함한 five-object grandchild 증거는 아닙니다. stdio 순차 clear는 원자적이지 않고
  이후 inherit-bit 재설정이나 explicit duplication을 막지 않으며, 이 two-object
  음성은 stray handle 전체의 exhaustive enumeration, exact signed artifact,
  intended supervisor topology, immutable install, DLL/dependency identity 또는 release
  activation 증거가 아닙니다. case-sensitive directory와 alternate path form을 포괄하는
  signed release-path positive evidence, live mapped exact file object, complete
  DLL/dependency graph, immutable installation, supervisor-held activation capability,
  exact endpoint topology/exclusivity는 모두 **STOP-SHIP**입니다. 현재
  sealed full launch-to-`VerifiedParentBoundApprovalExchange` transition의 production
  orchestration caller는 0개이고, 이 opaque 증거를 public verified response나 signing으로
  전환하는 composition 및 positive signed handshake E2E도 없습니다.
  `COMPILED_PARENT_POLICY`와 `COMPILED_RELEASE_POLICY`는 모두 `None`이고 default
  `approval-ui`는 계속 exit 78이므로 release activation은 fail closed입니다.
- runtime-enabled Secret Input/recovery 자식도 첫 Windows/CRT application 동작에서
  stdin과 stdout=stderr인 두 unique `PIPE` 객체가 서로 다르고 flags가 정확히
  `HANDLE_FLAG_INHERIT`인지 먼저 검증한 뒤, 두 inherit bit를 모두 제거하고 exact-zero
  readback을 요구합니다. 부모의 `HANDLE_LIST`에는 이 두 stdio 객체만 들어가며, parent
  process와 image-file proof handle은 자식이 아직 suspended인 동안 `DuplicateHandle`로
  직접 주입되고 inherit flag는 처음부터 false입니다. 자식은 고정 parent hello를 읽은
  직후 stdio 둘과 proof 둘이 네 개의 pairwise-distinct exact object이고 flags가 모두
  0인지 검증합니다. positive sentinel을 포함한 repo-local child/grandchild 커널 테스트는
  이 네 exact object가 broad-inheritance grandchild에 나타나지 않음을
  `CompareObjectHandles`로 확인합니다. 두 stdio의 순차 `SetHandleInformation`은 원자적
  bulk clear가 아니며, 이후 코드의 inherit-bit 재설정이나 explicit duplication을 막지
  않습니다. 이 exact-object negative는 stray handle이 전혀 없었다는 exhaustive
  enumeration, exact signed artifact/intended topology, immutable install 또는 release
  activation 증거가 아닙니다. `COMPILED_PARENT_POLICY`는 계속 `None`입니다.
- 별도 fresh 경계는 고정 AppContainer profile `YourWallet.KeyAgent.LPAC.v1`과 그 `AC`
  아래 고정 leaf `YourWallet.KeyAgent.Storage.v1`을 만들 수 있지만, activation에 넣을 수
  없는 `Pending` capability만 반환하며 pending/candidate의 직접 conversion은 없습니다.
  production에 컴파일되는 `PreparedKeyAgentProvisioning` mint는 정확히 하나로, private
  sealed existing-install adoption transition의 `HeldExistingKeyAgentInstallObjects::into_prepared`
  입니다. 이 transition은 initial snapshot과 계약상 post-observation reread snapshot,
  fixed-profile binding과 no-delete-share held root를 받아 matcher 전후로 binding/root를
  재검증하고 `Prepared`를 `VerifiedExistingKeyAgentInstall` 안에 봉인합니다. 이어 구현된
  dormant release-binding은 held Key Agent를 preflight하고 journal `release_identity`를
  `ReleaseAttestation`이 승인한 전체 `ReleasePolicy` `ArtifactDigest`와 constant-time으로
  비교한 뒤에만 `ArtifactBoundExistingKeyAgentInstall`을 만듭니다. 이 값은 helper manifest
  digest나 Windows file identity와 다릅니다. helper manifest는 역할·버전·실행 파일 hash·
  signer를, held handle과 `FILE_ID_INFO`는 실제 child file object를 별도로 묶습니다. 봉인된
  supervisor split만 artifact-bound 값을 소비할 수 있고 install continuity는 dormant 및
  storage-proven 상태까지 유지됩니다. 하지만 adoption transition, release-binding, dormant
  supervisor binder의 production caller는 모두 0개입니다. 이와 별개인 storage-only
  `open_existing_fixed_key_agent_storage_root`도 dormant하게 컴파일되지만 production caller는
  0개입니다. 이 함수는 authoritative observer가 제공해야 할 validated `AC` folder와 live
  fixed-profile SID만 받고 leaf를 `YourWallet.KeyAgent.Storage.v1`로 고정합니다. 생성·수리·
  삭제 없이 `OPEN_EXISTING | FILE_FLAG_OPEN_REPARSE_POINT`와 no-delete-share로 연 initial
  handle에서 local NTFS, exact owner/protected DACL/inherited Low-`NW` label 및 전체
  `FILE_ID_INFO`를 검증하고, canonicalize한 path를 다시 같은 방식으로 열어 security와
  identity가 initial handle과 같은지 확인한 뒤 reopened handle과 private canonical path를
  보존합니다. 이후 `revalidate`도 held handle과 canonical-path reopen을 함께 대조합니다.
  이는 `CreateDirectoryW`를 사용하는 fresh pending 경계나 자식이 OS-rerouted
  `LOCALAPPDATA`와 자기 token으로 독립적으로 여는 child opener와 다른 경계입니다. 반환값은
  root-only `HeldKeyAgentStorageRoot`일 뿐 profile registration, held aggregate,
  `Prepared`/`Verified`, journal/checkpoint authority, adoption, recovery/activation,
  signing/RPC/GUI, supervisor ownership 또는 Broker+Key Agent same-release aggregate
  authority가 아닙니다. production에는 여전히
  authoritative profile-registration observer와 `HeldExistingKeyAgentInstallObjects`
  constructor가 없어 이 opener나 adoption transition에 도달하지 못합니다.
- 같은 dormant activation은 정확한 실행 파일, 비공개 파이프 3개, 2프로세스 Windows
  Job과 위 provisioning 증명을 묶습니다. 네 개의 `STARTUPINFOEX` attribute는 handle
  allowlist, Job, null capability pointer와 count 0인 `SECURITY_CAPABILITIES`,
  `ALL_APPLICATION_PACKAGES` opt-out입니다. 원래 `CREATE_SUSPENDED` count는 Windows가
  첫 pre-user-mode debug 생성 이벤트를 만들도록 먼저 1→0으로 소비합니다. 그 event가
  process 전체를 멈춘 동안 mapped image의 정확한 파일 신원을 먼저 확인하고, later gate의
  explicit suspend count를 아직 추가하지 않은 채 token을 gate-pending proof로 검증합니다.
  token은 AppContainer이고 profile SID가 정확히 같으며 capability count가 0이어야 합니다.
  이어 primary token을 `SecurityIdentification` impersonation token으로
  복제하고 그 `TokenUser` SID에 `CheckTokenMembershipEx`를 두 번 적용합니다.
  `CTMF_INCLUDE_APPCONTAINER`로는 거부되고 `CTMF_INCLUDE_LPAC`까지 더했을 때만 허용되는
  정확한 `(false, true)` 결과가 필수입니다. `TokenIsLessPrivilegedAppContainer`를
  지원하는 경우 exact DWORD 값 1도 필수이며, 그 query만 `ERROR_INVALID_PARAMETER`를
  반환하는 Windows에서도 위의 차등 access-membership 증명은 그대로 필수입니다. 다른
  query 오류와 `(false, true)` 이외의 결과는 모두 거부합니다. opt-out만 생략한 정지
  상태 일반 AppContainer가 `(true, true)`를 내는 kernel 음성 대조군도 있으며 두
  대조 프로세스 모두 user mode로 재개하지 않습니다. 부모 프로세스의 Key Agent·Approval·
  Secret Input profile API 호출은 하나의 process-wide 비재진입 coordinator를 공유합니다.
  이 central API는 gate 획득 전과 mutex 대기를 마친 직후 thread impersonation을 거부하고, 보호된
  `CreateAppContainerProfile`, `DeriveAppContainerSidFromAppContainerName`,
  `GetAppContainerFolderPath` 호출마다 직전과 직후에 다시 검사합니다. 성공 반환의 raw
  SID 또는 `CoTaskMem` path는 직후 검사 전에 private RAII owner가 포획하므로, 그 검사나
  이후 검증이 실패해도 해제됩니다. 바인딩이 성공 할당을 포획하기 위해 success/Err를
  나누는 최소 분기 외의 구체 OS 오류 코드 분기, 포인터/SID validity, path 해석·검증,
  SID 비교와 애플리케이션 사용은 직후 검사가 성공한 뒤에만 수행합니다. 이 bookend는
  fail-closed 관찰이지만 두 검사 사이에 impersonation token이 설정됐다가 제거되는 순간
  경합을 원자적으로 배제하는 증명은 아닙니다. `CreateAppContainerProfile` 성공 뒤
  직후 검사가 실패해도 자동 `DeleteAppContainerProfile`이나 rollback은 하지 않습니다.
  따라서 신규 Key Agent fresh provisioning은 profile을 이미 만들었을 수 있으며 recovery가
  필요합니다. 이 계약은 profile-registration authority나 production reachability를 늘리지
  않고 production `DeleteAppContainerProfile` 경로도 만들지 않습니다. 같은 스레드
  재진입이나 poisoned gate도 fail-closed입니다. 이 검증이 성공하면 CREATE_PROCESS
  event를 test/production 공통 strict ntdll loader loop로 넘깁니다. 실제
  GUI-subsystem Key Agent 회귀 테스트는 non-primary loader thread를 detach 전에
  fail closed하고 Job을 정리하며, console host 없이 root Job count 1을 유지합니다.
  별도 최소 import-free GUI PE fixture만 exact-primary gate와 pending-to-final token
  transition, suspend count 하나, detach를 증명합니다. pre-resume DACL matrix는
  same-user LPAC principal이 loader-compatible from-birth `WRITE_DAC` denial을 제공할 수
  없음을 추가로 증명하므로, replacement loader policy만으로는 현재 architecture를
  구제하지 못합니다. 아래 gate 흐름은 구현된 conditional mechanism으로만 남습니다.
  그러한 gate가 모든 thread를 멈춘 경우에만 primary explicit suspend
  count를 exact 0→1로 만들고 default DACL을 finalize/readback한 뒤, 그 count를 보존한 채
  gate event를 계속합니다. CREATE_PROCESS event에서 독립적으로 안전한 process/thread
  alias와 ID는 hFile 및 다른 fallible 인증보다 먼저 exact-run shared join-cleanup
  registry에 등록합니다. malformed partial event도 안전한 alias를 보존합니다. 이후
  replacement loader/gate의 모든 검사를 마친 경우에만 complete registration을 다시 요구하고 fresh debugger OS
  thread의 마지막 fallible 연산으로 `DebugSetProcessKillOnExit(FALSE)`를 수행합니다.
  명시적 suspend count 하나를 유지한 opaque final owner만 join 경계를 건너고, 전용 OS
  thread 종료와 join 뒤 같은 run의 final·join proof·root Job witness가 모두 일치해야
  합니다. normal finalization은 registry의 alias를 채택해 인증·checked-close합니다.
  worker `Err`/panic 또는 abandoned joined proof도 post-join closure를 수행하고, partial
  failure는 남은 slot을 bounded retry합니다. 각 pass는 두 alias를 독립적으로 시도하며
  process cleanup 실패도 post-join alias closure를 막지 않습니다. 이어 retained creator process handle의
  `CheckRemoteDebuggerPresent == false`, retained creator primary-thread handle의 정확한
  `SuspendThread`/`ResumeThread` 1→2→1 probe, token·Job·provisioning·lease 재검증을 통과한
  뒤에만 least-authority attenuation으로 진행합니다. PID/TID reopen은 없습니다.
  별도 Secret Input child 프로세스는 이 parent-side mutex를 공유하지 않습니다. 그
  프로세스의 유일한 deterministic `DeriveAppContainerSidFromAppContainerName` 호출은
  child-local thread-impersonation 검사를 직전과 직후에 수행하고, 성공한 raw SID를
  직후 검사 전에 private RAII owner로 포획합니다. 최소 success/error 분기 외의 native
  오류 해석, SID validity 검사와 `EqualSid` 비교는 직후 검사가 성공한 뒤에만 수행하며,
  실패 경로에서는 owner가 SID를 해제합니다. 이 bookend 역시 fail-closed 관찰일 뿐 두
  검사 사이에 impersonation token이 설정됐다가 제거되는 순간 경합을 원자적으로
  배제하는 증명은 아닙니다. 이 child 경계에는 `CreateAppContainerProfile`,
  `GetAppContainerFolderPath`, `DeleteAppContainerProfile` 호출이 없고,
  profile-registration authority나 새 production reachability를 추가하지 않습니다.
  `COMPILED_PARENT_POLICY`는 계속 `None`입니다.
- 그 dormant 상태의 유일한 consuming 전이는 private one-shot storage-startup
  증명입니다. 부모는 자식이 정지된 동안 fresh nonce, 정확한 PID와 process creation
  `FILETIME`, supervisor-held root의 volume serial과 128비트 file ID, 그리고 고정
  production leaf(또는 `cfg(test)`의 정확한 CSPRNG test leaf)를 담은 고정
  `YWKSREQ1` frame을 먼저 쓰고 parent request writer를 consume해 닫습니다. 그 뒤에만
  검증된 suspend count 하나를 해제합니다.
  raw thread handle이나 caller-selectable path를 받는 generic resume API는 없습니다.
- 자식은 stdio sealing 직후 정확한 188-byte 요청과 EOF를 모두 확인하기 전에는 decode나
  root open을 하지 않습니다. suffix, EOF 부재, read 실패는 response 전에 닫히며, 성공한
  EOF 뒤에는 ambient stdin/stdout entry를 모두 detach하고 raw stdin을 실제로 닫습니다.
  raw stdout은 더 이상 `STD_OUTPUT_HANDLE`로 찾을 수 없고 response-only capability 안에만
  남습니다. 이 preflight가 끝난 뒤에만 OS가 해당 AppContainer에 대해 돌려준
  `LOCALAPPDATA`의 정확한
  `Packages/<fixed-profile>/AC` 모양을 다시 확인하고, 그 아래 고정/test leaf를 직접
  엽니다. 현재 process token에서 얻은 `TokenUser`와 AppContainer SID를 기준으로
  directory object, owner, protected two-ACE DACL, inherited Low/`NW` label과 전체
  `FILE_ID_INFO`를 검사하고 handle을 유지합니다. 요청과 실제 nonce·PID·creation
  time·root identity가 모두 같을 때만 정확한 88-byte `YWKSRES1` response를 만듭니다.
  첫 response write 시도가 commit point입니다. 자식은 write 결과와 이어지는
  `FlushFileBuffers`·`CloseHandle` 결과를 모두 무시하고, output 시작 뒤에는 `main`으로
  오류를 반환하지 않습니다. 이어 startup 전용 lexical scope를 벗어나면서
  `request_frame`·`request`·`response`·`response_frame`의 `Zeroizing` owner를 모두
  drop한 뒤, 그 scope에서 유일하게 빠져나온 sealed stderr 경계와 고정 store binding만
  들고 non-alertable `Sleep(INFINITE)` loop에 들어갑니다.
- 부모는 원래 startup deadline 안에서 정확한 88-byte response와 EOF를 모두 받아야
  decode나 성공 전이를 할 수 있습니다. 이 exact response-plus-EOF 관찰이 child response
  endpoint close의 authoritative protocol proof입니다. 그 뒤 nonce, PID, creation time과
  전체 root identity를 독립적으로 비교합니다.
  이어 held root의 volume/security/identity, exact resident process의 생존과 root Job
  membership과 Job context·limits·topology를 monotonic startup lease 소비 전과 후에
  다시 검사하므로, 자식이 종료돼 생긴 EOF만으로는 성공 join을 통과할 수 없습니다.
  성공 증명은 domain, held artifact identity, exact
  request와 exact response를 SHA-256 transcript commitment로 묶고 running process, root
  Job과 no-delete-share root handle을 보유하지만 startup endpoint는 하나도 보유하지
  않습니다. 자식은 sealed stderr와 독립적으로 연 root에서 만든 고정 generation-store
  binding을 유지한 채 Job이 종료할 때까지 `Sleep(INFINITE)`에서 inert하게 남습니다.
  write/flush/close 실패로 frame이나 EOF가 빠지면 부모는 성공 aggregate를 만들지 않고
  실패 또는 timeout으로 Job을 정리합니다. startup stream은 runtime channel로 재사용되지
  않으며 generic runtime request나 signing API도 없습니다.
- Rust-startup storage/supervisor integration positive 일곱 개는 현재 모두 명시적
  **STOP-SHIP** ignore입니다. 의도적으로 실행할 때 쓰는 fixture code만 persistent test
  profile의 CSPRNG leaf, 고정 libtest terse preamble, test process 옆의 선택적 exact
  System32 `conhost.exe` accommodation을 유지합니다. production parser는 response magic을
  byte zero에서 요구하고 Job member 하나만 허용합니다. 이 dormant fixture contract와
  green failure-cleanup negative는 production fresh fixed-profile/root, actual gate,
  storage-proven aggregate, exact signed artifact E2E 성공 증거가 아닙니다.
- 좁은 crate-private Key Agent generation-store adapter와 그 `cfg(test)` 통합 증명은 이제
  구현되어 있습니다. child-held root를 소비하는 봉인된 전이가 caller가 만들 수 없는
  binding 네 개(`Vault`, `NonceLedger`, `SignedCandidateJournal`, `LocalSettings`)를 고정
  namespace/class/bound와 함께 한 번만 만들고, private backend open은 raw path·principal·
  class selector나 frontend reference를 받지 않습니다. 공개 `WindowsGenerationStore`는
  변경 없이 stable-`TokenUser`-only입니다. Key Agent 파일은 stable `TokenUser` owner,
  user `FILE_ALL_ACCESS`(`0x001f01ff`)와 fixed profile
  `FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE`(`0x0013019f`)의 정확한 explicit allow
  ACE 두 개, 그리고 `ID`만 남은 inherited Low/`NW` mandatory-label ACE를 요구합니다.
  모든 fixed child-path 연산 주위에서 thread impersonation과 held/reopened root의 전체
  `FILE_ID_INFO`를 재검증하며, replace 전의 기존 target identity baseline과 설치 후
  byte/hash/identity/security readback도 확인합니다. 또한 신뢰하지 않는 fault callback은
  anchor 전·후 callback을 포함해 같은 security-context 재검증으로 앞뒤를 감쌉니다. 통합
  zero-capability LPAC fixture는 네
  role을 각각 generation 1/2까지 commit/load/reopen하고 role별 일곱 물리 파일에서
  `WRITE_DAC`/`WRITE_OWNER`/`FILE_EXECUTE`는 `ACCESS_DENIED`,
  `ACCESS_SYSTEM_SECURITY`는 `PRIVILEGE_NOT_HELD`인지 확인합니다. held root는
  `DELETE` actual-open의 `SHARING_VIOLATION`과 별도 `AccessCheck` denial,
  `FILE_DELETE_CHILD`/`WRITE_DAC`/`WRITE_OWNER`의 `ACCESS_DENIED`,
  `ACCESS_SYSTEM_SECURITY`의 `PRIVILEGE_NOT_HELD`를 각각 구분해 증명합니다.
- 설치 provenance에는 이제 고정 phase별 payload를 쓰는 정규 prefix-journal codec이 있습니다.
  각 레코드는 installer-owned HMAC-SHA256으로 먼저 인증되고, `Prepared=1`부터
  `Committed=4`까지 정확한 순서·세대·predecessor commitment를 따라야 하며, 독립된
  rollback-resistant 체크포인트의 high-water와 현재 commitment에도 정확히 일치해야
  합니다. 아직 존재하지 않는 root identity를 초기 phase에 요구하지 않고,
  `RootCreated`와 `Committed`만 동일한 완전한 root 증거를 가집니다. canonical journal
  validator에는 production installer key/checkpoint constructor, journal reader/writer
  backend와 caller가 없습니다. 인증된 two-snapshot matcher의 production-code consumer는
  위 private dormant adoption transition 하나뿐입니다. journal `release_identity`는 전체
  `ReleasePolicy` `ArtifactDigest`이고 helper manifest digest나 `FILE_ID_INFO`가 아닙니다.
  이 전체 release 비교와 exact child preflight를 결합하는 dormant binding은 구현됐지만
  production caller가 없습니다. committed whole-release identity가 달라지면 현재 계약상
  in-place upgrade가 아니라 `RecoveryRequired`입니다. checkpoint/observation/reread 순서를
  직렬화하는 exclusive installer lease가 없으므로 production upgrade orchestration도
  열리지 않습니다. 그 결과는 runtime/signing IPC, installer key,
  rollback anchor, storage/AEAD key 또는 protected-settings/lease authority가 아닙니다.
- 따라서 통합 증명은 여전히 persistent test profile과 CSPRNG leaf, test-only memory
  anchor와 합성 key/payload를 사용하는 `cfg(test)` 증명이지 production fresh
  profile/root E2E나 release wiring이 아닙니다. production에는 authoritative
  profile-registration observer와 held-aggregate constructor가 없고, fixed existing-root
  opener와 dormant adoption/binding의 production caller도 0개입니다. 또한
  post-observation reread 순서를 강제하는 exclusive installer lease, production installer
  key/checkpoint 및 journal I/O backend, recovery 및 release-activation wiring이 없습니다.
  구현된 canonical reopen 대조는 path
  rebinding을 fail-closed로 탐지할 뿐 same-user actor나 ancestor 교체를 원자적으로 막지
  않습니다.
  same-user 접근 및 non-atomic ancestor race, production rollback anchor와 storage/AEAD key
  provisioning, live protected-settings lease, 인증된 Broker/supervisor topology와
  single-instance, signed immutable artifact 및 DLL/dependency E2E도 모두 남아 있습니다.
  구현된 request exact EOF와 부모가 authoritative하게 판정하는
  response-plus-EOF/deadline은 repo-local startup framing 증명일 뿐 runtime channel,
  signing authority, signed-artifact 증거나 release activation을 제공하지 않습니다.
  generic runtime/signing IPC도 없고 `COMPILED_RELEASE_POLICY`는 계속 `None`이며 남은
  항목들은 **STOP-SHIP**입니다.
- 실제 릴리스 정책과 서명된 설치 증거가 없으면 helper를 실행할 수 없습니다.
- 실제 signed-artifact E2E와 DLL/dependency 로딩·신원 증거도 아직 없습니다.
- 독립 보안 검토와 Windows 격리 E2E 증거가 없으면 메인넷 서명이 불가능합니다.
- 최종 오프라인 검증도 후보 번들과 분리된 7파일 도구셋, 독립적으로 기록한 집계 해시,
  쓰기 방지 상태와 `[1-9][0-9]{0,31}` 형식의 rollback-resistant offline checkpoint에서
  계산한 예상 릴리스 sequence를 요구합니다.
  sequence `1`은 이전 manifest와 그 독립 hash pin을 금지하고, 더 큰 sequence는 둘을
  정확한 쌍으로 요구합니다. PowerShell wrapper와 Node는 후보 파일·트리를 읽기 전에
  이 모양을 거부하며, Node는 release key와 확장 ID를 고정한 직후 후보 sequence가
  독립 checkpoint와 정확히 같은지 확인합니다. 따라서 유효하게 서명된 과거 sequence-1
  번들도 후속 릴리스 checkpoint에 재사용할 수 없습니다. 검증용 Node는
  첫 디버그 생성 이벤트의 실제 이미지
  파일 ID가 고정된 파일과 같을 때만 실행되고, 세 검증 모듈은
  고정된 volume 경로에서 읽은 허용 목록 메모리 그래프로만 연결됩니다. 이 경계 자체도
  실제 출시 증거를 대신하지는 않습니다. 이 C# runner는 inheritable pipe 생성부터
  `CreateProcessW`, attribute list와 임시 child-end 핸들 정리까지 자체 정적 lock으로
  직렬화합니다. 이 lock은 같은 runner type의 협력 호출만 맞춰 주며 Rust coordinator나
  임의의 외부 process-creation 호출과 공유되는 전역 OS 잠금은 아닙니다. lock 획득은
  deadline으로 제한되지만 동기식 `CreateProcessW`와 fail-closed worker join은 그렇지
  않습니다.

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
