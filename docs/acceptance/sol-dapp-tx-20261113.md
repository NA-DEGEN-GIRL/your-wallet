# Solana dApp 거래 서명·전송(M7.2) 판정 기록 — 2026-11-13

- 범위: spec.md D20(예외)·D25·D27·D38, spec/07 §20(신규)·§14.1(버전 3)·§15.2·§15.3(코드 9), spec/05 §2.9·§2.13·§3.6·§5·§10(S9·P13·P14·C6·B5), spec/04 §3.9, spec/10 §5, spec/09 M7-10–M7-15.
- 사용자 결정(정본, 2026-11-12): Solana dApp은 연결·메시지 서명에 더해 **사이트가 만든 거래**(legacy·v0+ALT, 모든 프로그램)에 서명하고(`sol_signTransaction`·`sol_signAllTransactions` ≤ 32건), 지갑이 직접 보낼 수도 있다(`sol_signAndSendTransaction`). 해석하지 않은 프로그램은 차단하지 않고 고위험(X02). Bitcoin은 소유 증명만 그대로.
- 기준 트리: 브랜치 `sol-dapp-tx`, `0b5bef1` 위의 step 1–8 커밋(`feat(sol-dapp): step 1` … `step 8`)과 각 검토 수정 커밋.
- 환경: Windows 11 Pro 10.0.26200, Rust 1.95.0 MSVC, `--offline --locked`, Cargo.toml·Cargo.lock 변경 없음(새 크레이트 없음), npm 의존성 0, 확장 권한 불변(`nativeMessaging`, `storage`), 새 확장 파일 없음(`provider-main.js`·`popup-core.js`·`shared.js` 안에서). test-dapp에 `sol.js`를 더했다(설치 대상 아님, spec/09 §5.7).
- **devnet·mainnet E2E와 YubiKey 실물 시험은 아직 하지 않았다.** 이 기록을 만든 자동 단계는 실제 RPC 호출·브로드캐스트·실제 YubiKey APDU를 쓰지 않는 규칙으로 돌았다. 아래 "수동 체크리스트"를 사람이 채운다(M7-12–M7-15).

## 설계 요약

| 주제 | 결정 |
|---|---|
| 와이어 | `sol_signTransaction` `[{publicKey, transaction: hex, chain?}]` → `{publicKey, signedTransaction}`; `sol_signAllTransactions` `transactions: [hex] (1..=32)` → `signedTransactions`; `sol_signAndSendTransaction` `options?: {skipPreflight, preflightCommitment, minContextSlot}` → `{publicKey, signature: hex(서명 0번)}`. 새 ProviderError 없음 |
| 승인 | `ApprovalKind::SolTransaction = 0x23`, 시뮬레이션 결합 `NotApplicable`(표시 digest로 결합), X01–X19, FieldKey `0x0510–0x051A`·`0x0540`. 코어가 승인된 바이트를 다시 파싱하고 우리 슬롯 하나만 서명(블록해시 불변) |
| 서명만 | 메시지 서명 경로(`SignChainMessage(Card)`), 전 RPC·저널·활동 없음(X11). 카드는 거래마다 터치 1회 |
| 전송 | 서명 전 확인(`isBlockhashValid(processed)` → `getLatestBlockhash(processed, minContextSlot)` → 높이 범위, 테이블 재해석) → `SignSolDapp(Card)` 저널 우선(버전 3) → 기존 브로드캐스트 루프 → 첫 라운드 뒤 응답. (클러스터, 계정)당 Pending 16건·전체 32건, 넘으면 -32002 |
| 응답 직전 | origin의 grant가 아직 그 키를 가리켜야 함(아니면 4100, 바이트 버림). 잠금: 서명 전 대기 4001, 전송 대기는 저널된 서명으로 응답 |
| provider | Wallet Standard `solana:signTransaction`·`solana:signAndSendTransaction`(`["legacy", 0]`), Phantom shim 거래 4종과 `request()`(폐기된 base58 `message` 형식 포함). 앱 응답은 길이·서명 배치·서명 밖 바이트가 같고 바뀐 바이트가 슬롯 하나 안일 때만 받는다(-32603) |

## 자동 항목

### yw-core

| 항목 | 근거 | 메모 |
|---|---|---|
| 파서·ALT·디코더 | `sol::dapp::tests` (`legacy_vectors_parse_with_identity`, `v0_with_two_tables_parses_in_load_order`, `every_bit_flip_is_rejected_or_identical`, `signer_slots_and_foreign_signatures`, `durable_nonce_detection`, `lookup_table_layout`, `lookup_resolution_rules`, `ata_instructions`, `compute_budget_memo_precompiles_and_unknown` 등) | 재인코딩 동일성, 0x81+ 거부, 적재 순서, Agave `last_extended_slot` 규칙, 형식 불일치 → `Unknown` |
| 규칙·초안·서명만 | `sol::dapp::tests_approval` (`rule_table_levels`, `unknown_programs_are_high_and_approvable`, `site_signatures_and_foreign_fee_payer`, `lookup_tables_resolve_or_block_one_transaction`, `every_payload_field_changes_the_digest`, `display_keys_bounds_whole_addresses_and_escaping`, `card_signs_each_transaction_once`, `kinds_never_cross_and_the_message_error_map`, `every_accepted_draft_is_m01_blocked_as_a_message` 등) | X01만 소비 불가, 배치당 규칙 하나, 325 필드 이하, M01 불변식 |
| 전송·저널 v3·코드 9 | `sol::dapp::tests_send` (`send_signs_only_our_slot_with_the_approved_blockhash`, `send_compares_the_tables_and_refuses_other_payloads`, `version_3_layout_and_round_trip`, `version_3_rejections`, `version_3_origin_and_nonce_rejections`, `room_uses_the_version_3_maximum`, `template_shaped_dapp_send_is_not_a_wallet_send`, `program_instruction_errors_are_deterministic` 등) | 256 B origin 왕복, v1/v2 바이트 불변 |
| fuzz-lite | `tests/sol_fuzz_lite.rs` `fuzz_lite_sol_dapp_tx`, 버전 3 씨앗; `tests/msgsign_fuzz_lite.rs` 불변식 | Ok ⇒ 재인코딩 == 입력 ⇒ `looks_like_transaction` |
| 정책 | `tests/policy.rs` | 허용 40, `rejected` 35, 오류 표 24행 그대로 |

### yw-app

| 항목 | 근거 | 메모 |
|---|---|---|
| RPC·흐름 | `tests/sol_flow.rs` (`dapp_preview_calls_in_order_with_the_spec_config`, `dapp_preview_table_failures_stay_with_their_transaction`, `dapp_preview_retries_a_stale_blockhash_simulation_with_replacement`, `dapp_preview_reference_calls_stop_at_the_budget`, `pre_sign_dapp_checks_the_blockhash_at_processed_and_the_tables_again`, `dapp_record_rounds_resend_the_same_bytes_with_its_options`, `dapp_rpc_requests_are_exact`) | 템플릿 `simulate`·`send_transaction`·`latest_blockhash` JSON 바이트 불변 |
| 끝에서 끝 | `tests/sol_dapp_flow.rs` | 부분 서명 유지·우리 슬롯만, signAll 순서, 전송 → 서명 전 확인 → 저널 → 첫 라운드 → 응답 |
| 저널 작업자 | `tests/sol_journal_worker.rs` (`dapp_pending_write_reported_failed_but_on_disk_is_tracked`, `dapp_send_is_capped_journal_wide`, `dapp_send_into_a_full_journal_is_too_many_pending`) | 저널 우선, 상한 → -32002 |
| 디스패처·파라미터 | `tests/browser_chain_dispatch.rs` `solana_transactions_need_the_grant_and_reach_the_queue`, `browser::chain_params::tests`, `tests/fuzz_lite_chain_params.rs` | 4100·-32602·체인 불일치·nonce 전송·빈 외부 슬롯 |
| 앱 응답·잠금·카드 | `app_chain_sites`·`app_browser`·`app_sol_dapp`·`workers::key` 단위 시험 | grant 재확인 4100, `browser_sign_cancelled` 4001(E10), 잠금 시 서명 응답, emulator 카드 3건 = 터치 3회 |
| 화면 투어 | `ui::tour::screenshot_tour`(ignore) | 58(v0+ALT 전송, 고위험)·59(서명만 3건) 창이 가짜 devnet `SolDappTourRpc`로 열림 — `docs/screenshots/58-*.png`·`59-*.png` |
| 실시간 탐침(ignore) | `tests/sol_live_probe.rs` `probe_dapp` | `isBlockhashValid(processed)`, `getLatestBlockhash(processed, minContextSlot)`, 수수료 지불자 시뮬레이션 사후 상태, 살아 있는 조회 테이블의 v0 미리보기·서명 전 확인. **이 기록에서는 돌리지 않았다** |

### 확장 (`node --test extension/tests/*.test.mjs`)

| 항목 | 근거 | 메모 |
|---|---|---|
| S1·S9 | `shared.test.mjs` | 세 `sol_*`는 `signing`·계열 `sol`, 허용 40·`rejected` 35 |
| P13 | `provider-main.test.mjs` | feature 7개(`solana:signAndSendTransaction` 신규), 두 거래 feature `["legacy", 0]`; 입력 1개 정확한 와이어 JSON(`options`·`chain: undefined` 무시), 3개 → `sol_signAllTransactions` 한 번; 다른 계정 4100·잘못된/섞인 `chain`·33개·1,233 B·서명 수 0 → 로컬 -32602(전송 0); 메시지 바이트·길이·두 슬롯·서명 수를 바꾼 응답 -32603; 전송 옵션 정규화(`singleGossip → confirmed`, `maxRetries`·`mode`·`foo` 버림), `minContextSlot: -1` -32602; 두 건은 순서대로, 두 번째 실패 → `data.signatures`; M01 짝(거래 모양 바이트의 `signMessage`는 `sol_signMessage`만) |
| P14 | 같음 | 가짜 `Tx`·`VTx` 페이지 클래스: 페이지 클래스로 복원, legacy serialize 옵션 기록, signAll 요청 하나, signAndSend base58 `{signature, publicKey}`, signAndSendAll 순서대로, serialize 실패 -32602·전송 0, 팩토리 없음 -32603, 미연결 4100; `request({method:"signTransaction", params:{transaction}})`; base58 `message`(legacy·v0·앞 0바이트)는 0 슬롯으로 감싸 `{publicKey, signature}`, `messages` 배열, 전송 형식, 잘못된 메시지 -32602, 그 밖 메서드 4200 `Unsupported method.` |
| C6 | `content.test.mjs` | `sol_signTransaction`이 `phantom` 모드면 `compatMode: "phantom"`, `off`면 키 없이 전달 |
| B5 | `extension.test.mjs` | `sol_signAndSendTransaction`의 마감 600 s(signing 경로) |
| 팝업 | `popup.test.mjs` | 공통 안내 "Bitcoin은 연결과 메시지 서명만 됩니다. Solana는 거래 서명·전송도 됩니다." |

### 게이트

`cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --offline --locked -- -D warnings`, `cargo test -p yw-core`·`-p yw-app --offline --locked`, `node --test extension/tests/*.test.mjs` 통과(step 8 커밋 시점).

## 수동 체크리스트 (아직 하지 않음)

준비: 설치 빌드, 확장 다시 로드, yw-app Solana devnet + RPC 주소, `allowLocalhostDapps` 켬, devnet SOL 조금, `node extension/test-dapp/serve.mjs` → `http://localhost:5173/`의 "Solana dApp 거래" 구역(블록해시는 `solana block` 등에서 매번 새로).

- [ ] M7-12 devnet: test-dapp S01 연결 → S02(legacy)·S03(v0) 서명만, 우리 슬롯만 바뀌고 서명 유효(PASS 줄)
- [ ] M7-12 S04 서명 ×3: 창 하나에 "거래 1/3–3/3", 승인 한 번
- [ ] M7-12 S05 사이트가 수수료 지불·먼저 서명(X13) → 사이트 서명 유지; S06 잘못된 사이트 서명 → X01 차단, 4001
- [ ] M7-12 S07 durable nonce 서명만(X08), 같은 거래 전송 → -32602
- [ ] M7-12 S08 signAndSend(v0 이체 + 메모) 착지, 앱 활동에 "사이트 거래 · <origin>" 행; S09 skipPreflight(전송 방식 줄)
- [ ] M7-12 wallet-adapter 데모(legacy·v0)와 v0+ALT 스왑(skipPreflight 포함) 한 번씩
- [ ] M7-12 전송 직후 잠금 → 페이지에 서명 응답, 잠금 해제 뒤 추적 재개
- [ ] M7-12 S10 거래 바이트의 `signMessage` → M01 차단(4001)
- [ ] M7-13 YubiKey: S04(3건) = 터치 3회, S08 = PIN 뒤 서명 전 확인·터치 1회
- [ ] M7-14 Phantom 모드: P01 `signTransaction`(바이트), P02 `signAndSendTransaction` → `{signature, publicKey}` base58, P03 `request({params:{message}})` → `{publicKey, signature}`(메시지 위 서명 검증 PASS)
- [ ] M7-15 mainnet: Jupiter 소액 스왑 1회(v0+ALT, X02 확인 후 승인)
- [ ] 실시간 탐침 `cargo test -p yw-app --test sol_live_probe -- --ignored --test-threads=1 --nocapture`의 dApp 줄(`isBlockhashValid(processed)`, `getLatestBlockhash(processed,min)`, `simulateTransaction{accounts}`, `dapp v0+ALT table`, `app dapp preview v0+ALT`, `app dapp pre-sign check`)

결과(서명·시각·이상)는 이 파일 아래에 덧붙인다.
