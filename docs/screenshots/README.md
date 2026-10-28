# 화면 투어 (2026-10-28, M6 AI 설명 화면 추가)

완성된 지갑의 주요 화면과 창입니다. `scripts/screenshot-tour.ps1`이 만듭니다(spec/04 §11, 개발 전용). 바뀐 점과 이유는 [UX 검토](../ux-review-20261028.md)에 있습니다.

- 모든 값은 시험용입니다. 버리는 임시 데이터 폴더만 쓰고 실제 지갑 폴더(`%LOCALAPPDATA%\YourWallet`)는 건드리지 않았습니다.
- 새 지갑 만들기 화면의 단어는 누구나 아는 BIP39 **공개 시험 벡터**(엔트로피 0, 24단어)이고, 메인 화면은 공개 시험 니모닉(`abandon` × 11 + `about`) 지갑입니다. 이 단어들로 만든 지갑에 실제 자산을 두면 안 됩니다.
- 잔액·토큰 잔액·연결된 사이트·UTXO·RPC 주소는 지어낸 값이며 네트워크에 연결하지 않았습니다. 승인 창은 저장소의 고정 시뮬레이션 응답(EVM)과 투어 안의 고정 Solana 응답(토큰)으로 준비했습니다.
- AI 설명 화면(22·23)은 투어가 직접 띄운 이 PC의 가짜 AI 서버(`http://127.0.0.1:<임의 포트>/v1/chat/completions`, 고정 답 1개)에 연결했습니다. 외부 AI 공급자·API 키는 쓰지 않았고, 설명 문장은 지어낸 것입니다.
- 화면 크기는 100%(96 DPI) 기준입니다. 비밀 창(03–05, 09)은 실제로는 화면 캡처에서 제외되며, 투어 프로세스가 직접 만든 창에 한해 캡처 직전에 제외를 풀었습니다.

| 파일 | 설명 |
|---|---|
| [01-welcome.png](01-welcome.png) | 첫 화면 — 지갑이 무엇인지 세 문장으로 설명하고, 새로 만들지 가져올지 고릅니다. |
| [02-create-start.png](02-create-start.png) | 새 지갑 만들기 안내 — 1·2·3 단계 표시와 시작 전에 준비할 것. |
| [03-create-password.png](03-create-password.png) | 1/3단계 비밀번호 정하기 — 입력은 가려지고 글자 수가 보입니다. |
| [04-create-recovery-words.png](04-create-recovery-words.png) | 2/3단계 복구 단어 적기 — 24단어와 첫 주소, 2초 길게 눌러 다음으로. |
| [05-create-backup-check.png](05-create-backup-check.png) | 3/3단계 백업 확인 — 적은 종이를 보고 단어 4개와 주소 끝 6자를 입력합니다. |
| [06-create-done.png](06-create-done.png) | 완료 — 마지막 단계로 블록체인 연결(RPC)이 왜 필요한지 안내합니다. |
| [07-import-start.png](07-import-start.png) | 기존 지갑 가져오기 안내 — 단계 표시와 준비할 것. |
| [08-locked.png](08-locked.png) | 잠금 화면 — 언제 자동으로 잠기는지 함께 보입니다. |
| [09-unlock-password.png](09-unlock-password.png) | 잠금 해제 창 — 비밀번호 입력. |
| [10-main-evm.png](10-main-evm.png) | 메인(EVM, Sepolia) — 큰 잔액과 보내기·받기, 네트워크 칩, 내 계정. |
| [11-send.png](11-send.png) | 보내기 — 보내는 계정 / 받는 사람(주소록 확인됨) / 금액, 예상 최대 수수료. |
| [12-approval-simulated.png](12-approval-simulated.png) | 승인 창(시뮬레이션 성공) — 맨 위 한 문장 요약과 받는 주소 전체, 자산 변화, 핵심 정보. `승인`은 창이 앞에 나온 뒤 1초가 지나야 켜지므로 여기서는 회색입니다. |
| [13-approval-no-simulation.png](13-approval-no-simulation.png) | 승인 창(시뮬레이션 결과 없음) — 고위험 띠, 확인 체크박스 1개, 2초 길게 누르기. |
| [14-receive.png](14-receive.png) | 받기 — QR, 4자씩 끊은 전체 주소, 주소 복사. |
| [15-main-solana.png](15-main-solana.png) | 메인(Solana devnet) — 같은 배치, 주소 가운데 묶음 굵게. 큰 SOL 잔액 아래 허용 목록 토큰(USDC) 한 줄 요약(자세한 행은 아래 "토큰" 카드). |
| [16-main-bitcoin.png](16-main-bitcoin.png) | 메인(Bitcoin testnet4) — 네트워크 배너, 사용 가능 잔액, 검증된 UTXO. |
| [17-settings-rpc.png](17-settings-rpc.png) | 설정 → 네트워크(RPC) — RPC가 무엇인지, 입력 칸마다 어디서 찾는 값인지 설명. |
| [18-sites.png](18-sites.png) | 연결된 사이트 — 사이트마다 볼 수 있는 계정과 연결 해제. |
| [19-extension-popup.png](19-extension-popup.png) | 크롬 확장 팝업 — 앱 연결 상태와 dApp에 보이는 지갑(호환 모드) 선택. 실제 Chrome 대신 미리보기 페이지로 찍었습니다. |
| [20-send-solana-usdc.png](20-send-solana-usdc.png) | Solana 보내기(v1.1) — `자산` 라디오에서 USDC를 고른 모습. 받는 사람은 지갑 주소(토큰 계정 주소가 아님)라는 안내와 보유 잔액·mint. |
| [21-approval-solana-usdc.png](21-approval-solana-usdc.png) | Solana 토큰 승인 창(devnet USDC) — 요약 문장과 받는 지갑 주소, 금액·mint·토큰 프로그램·보내는·받는 토큰 계정(ATA) 전체, 받는 토큰 계정이 없어 만드는 비용(rent)을 보내는 쪽이 낸다는 안내. 고정 응답으로 준비했고 서명하지 않았습니다. |
| [22-approval-ai-explain.png](22-approval-ai-explain.png) | 승인 창 + AI 설명(M6, 선택 기능) — dApp(`https://app.example.org`)의 0.01 SepoliaETH 보내기. 코어 표시(요약·자산 변화·경고·핵심 정보)는 그대로이고, 버튼 바로 위 별도 보라색 패널 "AI 설명 (참고용, 틀릴 수 있음)"에 검증을 통과한 설명·지갑이 다시 만든 동작 줄(`보냄 · SepoliaETH 0.01 · 보낸 주소 → 받는 주소`)·AI가 판단하지 못한 것·`호스트 · 모델 · 경과 초`가 보입니다. 패널 높이는 창을 열 때 미리 확보하므로 설명이 와도 버튼 위치가 바뀌지 않고, `승인`은 AI 결과와 무관합니다(창이 앞에 나온 뒤 1초가 지나야 켜지므로 여기서는 회색). |
| [23-settings-ai.png](23-settings-ai.png) | 설정 → AI 설명 — 기본 꺼짐, 켤 때 전송 내용 고지·동의, OpenAI 호환 엔드포인트(https 또는 이 PC의 로컬 http만)·모델·응답 형식·max_tokens, `연결 테스트`(지어낸 표본 요청 `0x…dEaD`로 형식만 확인) 성공 결과. 아래(화면 밖)에 API 키 카드(저장된 값은 다시 보이지 않음)가 있습니다. |
