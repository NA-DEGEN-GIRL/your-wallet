# 개인키 가져오기·개인키로 시작하기 판정 기록 — 2026-10-29

- 범위: spec.md D9·D25·D29 개정, spec/02 §4.6(tag 3 `SolKey`·tag 4 `BtcKey`, `Bip39` 선택), §5.3(선택 최상위 키 `sol_raw_accounts`·`sol_raw_selected`; 가져온 Bitcoin 키는 통합 뒤 `btc_accounts`의 계정), §8.4(가져온 개인키), §8.5(키 전용 vault), §9·§10, spec/04 §2.2·§2.6·§2.12·§2.16·§2.18·§4.1–§4.2·§6.6·§7, spec/05 §4.2·§5(`NoEvmAccount`), spec/07 §1·§3.2·§3.4·§13.2·§14.1.
- 사용자 요청: 통합 니모닉 관리는 그대로 두고, 개별 개인키도 가져와 쓸 수 있게 한다 — (1) 니모닉 없이 개인키만으로 지갑 시작, (2) Solana 개인키 가져오기, (3) Bitcoin WIF 가져오기(주소 형식 포함).
- 기준 트리: `efdbacb feat: app and extension icon` 위의 이 브랜치 커밋들.
- 의존성: **추가 없음**(`Cargo.lock` 변경 없음, `scripts/check-core-deps.mjs` 허용 목록 그대로). taproot 출력 키는 기존 `secp256k1`(`XOnlyPublicKey::add_tweak`), 태그 해시는 `sha2`, WIF는 기존 `codec::base58`. `unsafe` 추가 없음.
- 경계: Bitcoin 주소 형식 작업(병렬)의 파일 `crates/yw-core/src/btc/*`, `crates/yw-app/src/flow/btc*`, BTC 서명 작업자는 고치지 않았다. 주소 문자열은 `btc::address::encode_address`·`hash160`을 호출만 한다.
- **통합(2026-10-29, `feat: wire imported Bitcoin keys into address-type accounts`)**: 두 브랜치를 합친 뒤 가져온 Bitcoin 키를 주소 형식 계정에 연결했다 — 아래 "통합" 절. Bitcoin 가져온 키의 수동 항목(옛 KI-18·KI-19)은 [btc-types-20261029.md](btc-types-20261029.md) §E로 옮겨 한곳에 모았다.

## 구현 요약

| 부분 | 내용 |
|---|---|
| vault payload (`vault::format`) | `Bip39` 0–1개 → `EvmRawKey`(tag 2) → `SolKey`(tag 3, 89 B: 시드 + 공개키, 디코드 때 공개키 재계산) → `BtcKey`(tag 4, 60 B: secret, compressed, network 1/2, script 1–4) 순서. 체인별 15개, `MAX_RECORDS` 46, `PAYLOAD_CT_MAX` 4,096(최대 평문 3,170 B). tag 1·2 바이트 그대로(골든 G1–G5 불변) |
| 파서 (`keyimport`, `codec::wif`) | EVM hex, Solana base58 64바이트 keypair·`solana-keygen` JSON(64개), Bitcoin WIF(0x80/0xef, 압축·비압축). 앞뒤 공백 무시, ASCII만, `Zeroizing`, 오류에 입력 없음. 주소: P2PKH·P2SH-P2WPKH·P2WPKH·P2TR(BIP86) — 통합 뒤 형식은 `btc::ScriptType`, 출력·주소는 `btc::account::kind_for_key`·`btc::taproot`(구현 하나; `keyimport/btc.rs` 삭제) |
| Vault API | `create_with_key`, `import_key`, `remove_imported_key`(`LastKey`), `reveal_imported_key`, `imported_keys`, `has_mnemonic`, `with_imported_ed25519_seed`, (통합 뒤) crate 내부 `imported_btc_secret` — `KeyRef::BtcImported`·`vault::BtcKeySource`는 없앴다. 키 전용 vault는 잠금 해제 → 곧바로 `Unlocked`, 파생·복구 단어·passphrase는 `NoMnemonic` |
| Solana 서명 | `SolKeySource::Imported`(태그 6, 매개변수 0·0): 공개키(`from`)로 record를 찾아 서명, 비표준 경로 규칙·`L07` 없음, 저널 태그 6 |
| 키 작업자 | `PreviewKeyStart`·`DiscardKeyStart`·`CommitKeyStart`, `ImportKey`, `RemoveImportedKey`, `Reveal(ImportedKey)`, meta 재조정(`reconcile_imported`; 통합 뒤 Bitcoin은 `btc_accounts` 계정과 맞춤), `RemoveImportedKey`의 Bitcoin 계정 삭제·`ImportedKeyBusy` (`btc_imported_signer`는 통합 때 없앴다) |
| 화면 | S01 셋째 카드 "개인키만 있습니다"/`개인키로 시작하기` → S18(체인·주소 형식) → W01 → W07 → S19(주소 확인) → S08. 체인 탭마다 `개인키 가져오기`, "[가져온 키]" 배지, Solana 가져온 계정의 `개인키 보기`·`삭제`, Bitcoin 가져온 키는 통합 뒤 Bitcoin 계정 목록의 "[가져온 키]" 행(잔액·받기·보내기, 선택 시 `개인키 보기`·`삭제`). 키 전용 지갑: 계정 추가·다른 경로 스캔·복구 단어 보기·파생 BTC 숨김, 계정 없는 체인 "이 지갑에는 {체인} 계정이 없습니다" |
| 오류 | E-INP-020–024, E-VLT-012(`NoMnemonic`)·013(`LastKey`), E-VLT-010 문구 "체인마다", dApp 4100 `NoEvmAccount` |

## 자동 항목

| 항목 | 판정 | 근거 |
|---|---|---|
| WIF 벡터(위키 예제, secret 1의 네 형식) 왕복·거부 표 | 통과 | `keyimport::tests::wif_wiki_vectors_round_trip`, `wif_rejections` |
| BIP84·BIP49·BIP173·BIP86 주소(공유 btc 코드), 비압축 키 형식 제한, 형식 코드 1–4 | 통과 | `btc_imported_addresses_match_bip_vectors`, `bip86_taproot_output_key_and_address`, `script_type_codes_and_names` |
| Solana keypair(base58·JSON 3종) 같은 키, 내보내기 왕복, spec/07 §17.1 주소 | 통과 | `solana_keypair_formats_parse_to_the_same_key` |
| Solana 거부 표(주소·불일치·길이·JSON 형식) | 통과 | `solana_rejections` |
| EVM 공백 무시·주소 미리보기 | 통과 | `evm_import_trims_and_previews_the_known_address` |
| 이전 배치 payload 호환(디코드·재인코드 동일), 골든 G1–G5 불변 | 통과 | `vault::tests::old_layout_payload_decodes_and_re_encodes_identically`, `g1_g2_golden_bytes_and_field_offsets`, `g3_independent_decryption` |
| tag 3·4 코덱·거부 표, 키 전용 payload | 통과 | `tagged_records_codec_and_rejections` |
| 최대 payload 봉인·개봉, 16번째 키 거부 | 통과 | `largest_payload_fits_and_seals` |
| 키 전용 vault 생명 주기(`NoMnemonic` 표, 서명 시드, 내보내기, `LastKey`) | 통과 | `key_only_vault_lifecycle` |
| 체인별 상한·중복 규칙·가져온 Bitcoin 키를 서명자에게 빌려 줌(network·형식 불일치 `KeyMismatch`, 없는 id `RecordNotFound`)·WIF 내보내기·삭제 | 통과 | `imported_keys_caps_duplicates_signing_and_removal`, `backup_pending_refuses_key_import` |
| 가져온 Solana 키 서명 = 파생 키 서명, `L07` 없음, 저널 태그 6 | 통과 | `sol::tests::imported_key_signs_the_golden_transfer_without_the_move_rule`, `imported_source_needs_the_matching_imported_key`, `slip10::tests::key_source_tags_and_parts_round_trip` |
| meta 선택 키 왕복·이전 파일·검증 | 통과 | `meta::tests::imported_lists_and_key_only_meta_round_trip`, `imported_lists_are_validated` |
| W07 체인별 문자 집합·붙여넣기 정규화 | 통과 | `ui::secret::tests::w07_solana_and_bitcoin_fields_take_their_formats`, `w07_warns_that_imported_keys_are_not_in_the_recovery_words` |
| 개인키로 시작하기(앱 상태, 창 없이): S01 → S18 → 주소 오입력 → S19 → S08, 탭별 숨김·빈 체인 카드, BTC 가져오기(계정 목록 "[가져온 키]" 행, `개인키 보기`·`삭제`, `계정 추가` 없음), 잠금·해제, 삭제·마지막 키 | 통과 | `app::tests::key_start_creates_a_key_only_wallet` |
| Bitcoin 키로 시작(앱 상태): S18 형식 라디오 → S19 "P2TR (탭루트, tb1p…)" → Bitcoin 켜짐(그 키의 네트워크) → 계정 목록, 잠금·해제, EVM 탭 계정 없음, dApp 연결 4100 `NoEvmAccount`(대기열 없음) | 통과 | `app::tests::key_start_with_a_bitcoin_key` |
| 니모닉 지갑에 Solana 키 가져오기·선택·서명 출처·중복·내보내기 | 통과 | `app::tests::imports_into_a_mnemonic_wallet` |
| 키 작업자(실제 파일, 256 MiB KDF): 키 전용 지갑 전 과정(계정 없는 태그 4 레코드 → meta 읽기에서 계정 추가, Bitcoin 키 삭제 → `BtcMetaDone::Removed`) | 통과 | `tests/keys_import.rs::key_only_vault_through_the_key_worker` |
| 가져온 Solana 키 보내기 준비(가짜 RPC)·승인·서명·`Pending` 기록 | 통과 | `tests/keys_import.rs::imported_sol_key_prepares_and_signs_a_devnet_transfer` |
| dApp 4100 `NoEvmAccount` 코드·문구 | 통과 | `yw-core/tests/policy.rs` 오류 표 |
| `scripts/check.ps1 -Offline` | 통과 | 아래 게이트 줄 |

## 수동 항목 (미실시)

### 개인키로 시작하기

- [ ] KI-1 S01에 카드 세 개가 보이고, T-LEFTOVER(데이터 폴더에 이전 파일)일 때 세 버튼이 모두 꺼진다.
- [ ] KI-2 S18에서 체인 라디오를 바꾸면 형식 도움말이 바뀌고, Bitcoin을 고르면 주소 형식 라디오 4개(기본 P2WPKH)와 T-KEYSTART-SCRIPT가 보인다.
- [ ] KI-3 EVM 키(테스트용으로 새로 만든 키)로 시작: W01 → W07(T-KEY-ONLY) → S19 주소가 MetaMask에서 본 주소와 같다 → `맞습니다` → S08에 T-KEYSTART-OK·T-KEYSTART-BACKUP, 백업 확인 단계 없음.
- [ ] KI-4 Solana: Phantom에서 내보낸 base58 keypair(테스트 계정)를 붙여넣으면 S19 주소가 Phantom 주소와 같다. 같은 키의 `solana-keygen` JSON 파일 내용(줄바꿈 포함)을 붙여넣어도 같다.
- [ ] KI-5 Solana W07에 주소(32바이트)를 넣으면 E-INP-021, 마지막 글자를 바꾼 keypair는 E-INP-022 또는 E-INP-020이 W07에 보이고 비밀번호를 다시 묻지 않는다.
- [ ] KI-6 Bitcoin: Electrum(testnet4)에서 내보낸 WIF(`c…`)를 P2WPKH로 → S19 주소가 Electrum 주소와 같고 네트워크 "Bitcoin testnet4". `다릅니다` → S18에서 P2TR로 바꾼 뒤 `시작하기`는 W01 없이 W07을 연다.
- [ ] KI-7 비압축 WIF(`5…`/`9…`)를 P2WPKH로 넣으면 E-INP-024, P2PKH면 통과.
- [ ] KI-8 키 전용 지갑: EVM·Bitcoin 탭(키가 없는 체인)은 "이 지갑에는 {체인} 계정이 없습니다"와 `개인키 가져오기`만, Solana 탭에는 `계정 추가`·`다른 경로 스캔`이 없고, 설정 → 보안에 `복구 단어 보기`가 없다.
- [ ] KI-9 키 전용 지갑을 잠그고(Ctrl+L, Windows 잠금, 자동 잠금 1분) 다시 열면 passphrase·백업 화면 없이 S10으로 간다.

### 기존(니모닉) 지갑에 가져오기

- [ ] KI-10 각 체인 탭의 `개인키 가져오기` → W07 안내에 T-IMPORTED-KEY("복구 단어(24단어)로 복구되지 않습니다"). 가져온 계정 행에 "[가져온 키]" 배지와 도움말.
- [ ] KI-11 같은 Solana 키를 두 번 가져오면 E-VLT-011, 체인마다 16번째는 E-VLT-010.
- [ ] KI-12 W07은 화면 캡처(캡처 도구·OBS)에 나타나지 않고, 붙여넣은 뒤 T-PASTE-CLEARED, 비ASCII·IME 입력은 E-INP-008(W07 공통 보호).

### Solana 가져온 계정 사용 (devnet)

- [ ] KI-13 가져온 Solana 계정을 선택하면 선택 계정 카드 경로 줄이 "가져온 개인키 (복구 단어로 복구되지 않음)", 잔액이 RPC 값과 같다.
- [ ] KI-14 devnet SOL 0.001 보내기: 승인 창 계정 필드 경로 줄 "가져온 개인키 (복구 단어 밖)", `L07` 없음 → 승인 → 전송 → `Landed` → 활동 `succeeded`. 앱 강제 종료 후 다시 열면 진행 중 기록이 이어진다.
- [ ] KI-15 허용 목록 devnet USDC를 가져온 계정에서 보내기(받는 ATA 생성 포함).
- [ ] KI-16 `개인키 보기` → T-REVEAL-WARN → W03 → W09에 base58 keypair(두 줄)가 보이고, 복사 허용 토글이 켜져 있을 때만 `복사`(30초 뒤 삭제, Win+V 기록 없음). 그 값을 Phantom에 가져오면 같은 주소.
- [ ] KI-17 `삭제` → T-REMOVE-IMPORTED(라벨·주소) → W03 → 목록에서 사라진다. 잘못된 비밀번호는 E-VLT-001 후 1초 비활성.

### Bitcoin 가져온 키

- KI-18·KI-19는 통합 때 [btc-types-20261029.md](btc-types-20261029.md) §E(E1–E7)로 합쳤다: 계정 목록의 "[가져온 키]" 행, 잔액·받기·보내기(형식별·비압축 P2PKH), `개인키 보기`(WIF), `삭제`(승인·진행 중 거래면 거절, 키 전용 지갑의 마지막 키는 꺼짐), 키 전용 지갑의 Bitcoin 탭. 체크는 그 문서에서 한다.

### 브라우저

- [ ] KI-20 Solana 키로만 시작한 지갑에 dApp(Sepolia)이 연결을 요청하면 연결 창 없이 4100과 "this wallet has no EVM account" 문구. EVM 키를 가져온 뒤에는 연결 창에 그 계정이 보이고 `personal_sign`·`eth_sendTransaction`·typed data(Permit2)·승인(approve)이 가져온 키로 서명된다.

### 호환

- [ ] KI-21 이전 버전 앱의 `v3` 폴더(니모닉 + EVM 개인키)를 이 버전으로 열면 그대로 열리고 계정·라벨이 같다(폴더를 먼저 통째로 복사해 둔다).
- [ ] KI-22 이 버전으로 Solana·Bitcoin 키를 가져온 폴더를 이전 버전으로 열면 E-VLT-008(또는 E-VLT-002)이 보이고 파일은 바뀌지 않는다 — `.prev` 복구를 하지 말고 새 버전을 다시 설치한다(spec/04 §6.6).

## 통합 (Bitcoin 주소 형식 작업과 함께, 2026-10-29)

- 서명 경로 하나: `btc::sign::sign_plan(&Vault, ..)`이 가져온 키 계정의 입력마다 crate 내부 `BtcImportedKeys::btc_imported_secret` → `Vault::imported_btc_secret`(태그 4 레코드, `Unlocked`만)으로 비밀키를 받아 서명 클로저에만 빌려 준다(`ImportedBtcSecret`: 복제 없음, `Debug` 가림, drop 때 지움). 레코드의 network·형식·압축이 계정과 다르면 `KeyMismatch`. 키를 빌려 주는 `BtcKeys`도 crate 내부다. 이 문서가 쓴 `KeyRef::BtcImported`·`vault::BtcKeySource`·`KeyWorker::btc_imported_signer`는 없앴다(중복 경로).
- meta: `btc_raw_accounts` 목록을 없애고 가져온 Bitcoin 키는 `btc_accounts`의 `BtcAccountKey::Single` 계정이다. 가져오기는 vault 저장 뒤 `BtcMetaOp::AddImported`, 개인키로 시작하기는 첫 meta에 같은 계정(+ 설정 Bitcoin 켬, 그 키의 네트워크). meta 읽기는 계정 없는 태그 4 레코드에 계정을 더하고 레코드 없는 계정을 지운다.
- 키 전용 지갑의 Bitcoin 탭: 기본 계정·발견·계정 추가 없음, 최고 블록 높이는 그 네트워크의 첫 계정이 보관(`BtcAccounts::tip_holder`).
- 주소 계산 중복 제거: `keyimport::btc` 삭제, 형식은 `btc::ScriptType`(같은 코드 1–4).
- 화면: "가져온 Bitcoin 개인키" 카드·T-BTC-IMPORTED-PENDING("통합 후 지원")을 없애고 계정 목록 행으로 옮겼다(T-BTC-IMPORTED).
- 자동 시험: `btc::types_tests::vault_signs_every_hd_and_imported_type`, `accounts_without_primary`, `tests/btc_app_flow.rs`의 `imported_keys_in_a_mnemonic_wallet_end_to_end`·`imported_keys_in_a_key_only_wallet_end_to_end`·`key_only_bitcoin_wallet_locks_and_keeps_its_account`·`imported_key_removal`, `app::tests::key_start_with_a_bitcoin_key`.

## 게이트

- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check.ps1 -Offline` → 종료 코드 0(`check: OK`): fmt, deps(yw-core 40·yw-json 0·yw-win 2·yw-app 43·yw-host 2, 변경 없음), clippy `-D warnings`, cargo 테스트 894 통과·27 무시·0 실패(이 작업이 더한 테스트 23개: yw-core 16, yw-app 7), fuzz-lite, build, ext-test 84, script-test 44, privacy scan, `EXTENSION_STATIC_AUDIT_PASS`, icons.
- 통합 뒤(`feat: wire imported Bitcoin keys into address-type accounts`): `scripts/check.ps1 -Offline` → 종료 코드 0(`check: OK`): deps 변경 없음(yw-core 40·yw-json 0·yw-win 2·yw-app 43·yw-host 2), cargo 테스트 921 통과·27 무시·0 실패, fuzz-lite, build, ext-test 84, script-test 44 통과(1 건너뜀)·0 실패, privacy scan, `EXTENSION_STATIC_AUDIT_PASS`, icons.
