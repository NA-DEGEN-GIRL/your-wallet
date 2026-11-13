# Guide for AI assistants: answering users' questions about Your Wallet

Audience: an AI assistant answering a person's questions about Your Wallet after (or before) they install it. Answer in
the person's language (often Korean), in plain words, one step at a time. The app UI is Korean only; Korean strings
below are quoted exactly as the app shows them, with an English gloss.

How to use this file:

- Each answer ends with **Source:** the document section it comes from. Point the person there when they want detail,
  and prefer the source over this file if they disagree. The specs (`spec.md`, `spec/*.md`) are Korean and normative.
- Do not invent features, menu paths or error texts. If a question is not covered here or in the sources, say you
  are not sure and point to the README or a GitHub issue.
- Install and build questions: [llm-install-guide.md](llm-install-guide.md). "Is it safe / can I trust the code":
  [llm-verify-guide.md](llm-verify-guide.md).

Rules that always apply:

1. **Never ask for, accept or repeat** a recovery phrase (12–24 words), BIP39 passphrase, private key, vault password,
   YubiKey PIN / Admin PIN / PUK, RPC URL, or any API key or token (Alchemy key, QuickNode token, LLM provider API key
   for the AI explanation). If the person pastes one, tell them it is now exposed and what to do (Q5.5; for an RPC URL,
   API key or token: regenerate it in the provider dashboard).
2. Never read the wallet data folder `%LOCALAPPDATA%\YourWallet\`; the person opens logs themselves and shares only
   error-code lines.
3. You do not approve, sign or send anything, and you do not give investment advice. You can explain what a screen or
   warning means.
4. Be honest: there has been **no third-party security audit**, manual verification is still in progress, and the
   README advises keeping only amounts the person can afford to lose.

---

## 1. What it is and what it supports

**Q1.1 What is Your Wallet?**
A personal multichain wallet for one Windows 11 x64 PC with Google Chrome. A desktop app (`yw-app.exe`) keeps the keys
in an encrypted vault, shows every request in its own window and signs. The Chrome extension holds no secrets and only
forwards website (dApp) requests to the app. Source only: the person builds it on their PC. Licence Apache-2.0 OR MIT,
no warranty.
Source: [README.md](../README.md) "English", [AGENTS.md](../AGENTS.md) intro.

**Q1.2 Which chains?**
- EVM: Ethereum, Arbitrum One, Base, BNB Smart Chain, Robinhood Chain, HyperEVM, Sepolia testnet, plus EVM chains the
  user adds. Native coins and ERC-20 tokens.
- Solana: SOL and allow-listed USDC/USDT on mainnet and devnet; dApp transaction signing.
- Bitcoin: native segwit (`bc1q`, default), taproot (`bc1p`), nested segwit (`3…`), legacy (`1…`) on mainnet and testnet4.
- Zcash: transparent addresses only.
- Hyperliquid HyperCore: balances, transfers, spot↔perp, withdraw to Arbitrum. No trading.
Source: README "Features → Chains".

**Q1.3 What is not included?**
Other operating systems or mobile, Edge/Brave (Chrome only), swaps or trading inside the app, Bitcoin transaction
signing for dApps (PSBT; dApps get Bitcoin message signing only), multisig, Zcash shielded addresses, Token-2022 or NFT
sends from the app. The user brings their own RPC.
Source: README "Features → Not included"; the Chrome-only point is from README "Install" (requirements: Windows 11 x64
and Chrome) and spec.md D22.

**Q1.4 How do websites (dApps) find it?**
EVM: EIP-6963 name "Your Wallet (EVM)". Solana: Wallet Standard "Your Wallet (Solana)". Bitcoin: only after picking
the UniSat or Xverse compatibility mode in the extension popup. Look-alike modes for MetaMask, Rabby and Phantom also
exist (best-effort; turn off the real extension of the same kind). WalletConnect v2 (EVM only) works without the
extension but needs the user's own Reown Project ID from `dashboard.reown.com`.
Source: [dapp-integration.md](dapp-integration.md) §2, README "Signing and dApps".

---

## 2. Receiving and sending

**Q2.1 How do I receive?**
Open the chain's tab (EVM, Solana, Bitcoin, Zcash), pick the network and account, press `받기` (Receive), and give the
sender the address shown. The app always shows **whole addresses** and emphasises the 4 characters after the prefix
and the last 4; tell the person to also check the middle when they copy it elsewhere. For a new wallet, receive only
after the backup check is done.
Source: README "Address-poisoning and phishing defences", [recovery-guide.ko.md](recovery-guide.ko.md) "정식 지갑을 만들 때".

**Q2.2 How do I send?**
`보내기` (Send) → enter the address (or pick an address-book chip) and the amount (`최대` = max) → `검토` (Review) →
the approval window shows the decoded transaction, fee and (for EVM) the simulated balance changes → `승인` (Approve)
or `거부` (Reject). If the address only shares the start and end with a known address, the app warns about a
look-alike and requires ticking `주소 전체를 직접 확인했습니다` (I checked the whole address myself) before `검토`.
Source: spec/04 §2 (send screens), README "Address-poisoning and phishing defences".

**Q2.3 My EVM balance is zero / wrong network?**
The EVM tab starts on the **Sepolia testnet**. Switch the network (or press "Ethereum 메인넷으로 보기", view Ethereum
mainnet). There is no automatic account discovery after importing; extra accounts are added by hand.
Source: spec/04 S08 card, [install.ko.md](install.ko.md) §4.

**Q2.4 "이 계정의 이전 거래가 아직 확정되지 않았습니다." (E-TX-002)**
One unconfirmed send per account at a time. Wait for it to confirm (see 활동 / activity). For EVM, the activity entry
offers "수수료 올리기" (speed up) and "취소" (cancel).
Source: spec/04 §7 E-TX-002.

**Q2.5 "전송 결과를 확인할 수 없습니다. 다시 보내지 마세요…" (E-TX-004)**
The send may already have gone out. **Do not send again.** Check the activity entry or a block explorer first.
Source: spec/04 §7 E-TX-004.

**Q2.6 Why didn't my received coins show in activity?**
Activity lists what this wallet sent. Received history is **off by default**; turn on the `받은 내역도 보기` (also show
received) checkbox on the activity card. Zero-value and dust deposits stay hidden.
Source: README "Address-poisoning and phishing defences", spec/04 §2 (received history).

---

## 3. RPC (blockchain connection)

**Q3.1 What is an RPC and why do I need one?**
The wallet has no server of its own. To read balances, estimate fees, simulate and send, it talks to an RPC provider
the user chooses. Free QuickNode or Alchemy plans are enough. One QuickNode endpoint URL can serve every supported chain.
Source: README "Privacy" and "Not included", [install.ko.md](install.ko.md) §4, step 3.

**Q3.2 How do I set it up?**
On the "처음 설정" (first setup) card after creating or importing a wallet, paste the full QuickNode HTTP Provider URL
into "QuickNode 주소" and press **연결하기** (connect). Or later: 설정 → 네트워크(RPC) (Settings → Network (RPC)) →
choose `QuickNode 멀티체인` (QuickNode multichain) / `알케미` (Alchemy) / `직접 입력` (manual) →
`저장하고 RPC 주소 만들기` (save and generate RPC URLs).
The app then tests each network and shows ✓/✗ and "n개 중 m개 작동" (m of n working).
**In QuickNode, each chain must be enabled on the endpoint**; otherwise that network fails with E-RPC-003 or E-RPC-007.
Source: [install.ko.md](install.ko.md) §4, step 3, spec/04 §2.11.

**Q3.3 Is the RPC URL secret?**
Yes. The whole URL (name and token) is a credential. It is stored encrypted with Windows DPAPI in `apikeys.dpapi`
(only this Windows user on this PC can decrypt it) and never shown again. Never paste it into chats, screenshots,
messengers or GitHub issues. Moving to a new PC means entering it again.
Source: [install.ko.md](install.ko.md) §4, step 3, and §8.

**Q3.4 Can the RPC lie to me?**
The configured RPC is trusted for balances, confirmations and simulation, and one confirmation counts as final. A lying
RPC can mislead what is displayed but cannot change the bytes being signed. If the RPC lacks `eth_simulateV1`, every
EVM transaction is marked High risk.
Source: README "Security model → Trusted RPC".

**Q3.5 Bitcoin balances don't load.**
Bitcoin lookups use a separate keyless Esplora server (`https://mempool.space/api` by default). If E-BTC-001 or
E-BTC-002 keeps appearing: 설정 → Bitcoin → **Esplora URL** → `https://blockstream.info/api` (testnet4:
`https://blockstream.info/testnet4/api`) → `저장` → `테스트`.
Source: [install.ko.md](install.ko.md) §4, step 3.

---

## 4. YubiKey

**Q4.1 What does the YubiKey do?**
A YubiKey 5 can act as the hardware signer: OpenPGP secp256k1 for EVM, Bitcoin and Zcash (firmware 5.2.3+, no taproot)
and PIV Ed25519 for Solana (firmware 5.7.4+; 5.7.0–5.7.3 is tried after a warning). Every signature needs the PIN
(never cached) and, by default, a touch. Keys from the same phrase can go on up to 8 cards as backups of each other.
Source: README "Keys → YubiKey 5", [spec/10-yubikey.md](../spec/10-yubikey.md) §2.

**Q4.2 Which option should I choose?**
- `YubiKey에 보관하는 새 지갑` (new wallet kept on a YubiKey): the recovery phrase is written on paper and **not kept
  on the PC**; only public keys stay on the PC. This is the option that keeps keys off the PC.
- Enrolling a YubiKey for a phrase that is **also in the PC vault adds no protection** (the PC can derive the same
  keys); the wizard warns about this.
- `YubiKey 연결하기 (복구 단어 없이)` (connect without words): uses keys already on the card.
Source: README "Security model → YubiKey and the same recovery phrase", spec/10 §7.

**Q4.3 PINs?**
Factory defaults are public (OpenPGP PIN `123456`, Admin PIN `12345678`; PIV PIN `123456`, PIV PUK `12345678`).
**Until the factory PINs are changed, the wallet will not sign with that card**: the approval is dropped with the
banner "이 YubiKey는 아직 공장 기본 PIN을 쓰고 있어 서명하지 않았습니다…" (this YubiKey still uses a factory PIN, so it
did not sign) and the dApp gets a failure. Change them with the card's `PIN 설정` (PIN setup) button in 설정 → YubiKey
(the main window also shows a `PIN 설정` button while defaults remain); `123456` and `12345678` are not accepted as new
PINs. The wallet asks for PINs in its own window after you approve; never type a PIN into a chat. By default, three
wrong tries lock each PIN separately.
Source: spec/10 §5 (default values), §9.2–§9.3, [screenshots/README.md](screenshots/README.md) (YubiKey scenes).

**Q4.4 Limits**
The card has no screen, so the PC's approval window is the only place to see what is signed; a compromised PC could
get a touch for something else. Keys are computed on the PC from the phrase at enrolment, not generated on the card.
With the "15 s cached" touch policy, further signatures within 15 s need no touch.
Source: README "Security model → YubiKey".

---

## 5. Backups and recovery

**Q5.1 What is the backup?**
**The recovery phrase (24 words, plus the BIP39 passphrase if one was used) on paper or metal**, kept away from the PC.
No photos, screenshots, cloud, messengers, email or password managers. The vault password only opens the file on this
PC; it cannot recover a wallet.
Source: [recovery-guide.ko.md](recovery-guide.ko.md) "정식 지갑을 만들 때", [install.ko.md](install.ko.md) §8.

**Q5.2 What does the phrase NOT recover?**
- Accounts added with private-key import (shown as "[가져온 키]", imported key) — back up each key separately.
- A wallet started with `개인키로 시작하기` has no phrase at all; its keys are the backup.
- Each additional recovery phrase (up to 8) needs its own backup.
- Names, address book, connected sites, activity and RPC settings are not in the phrase (optional folder backup, Q5.3).
Source: recovery-guide.ko.md "복구 단어로 되살아나는 것과 아닌 것", "복구 단어가 여러 개인 지갑".

**Q5.3 Can I back up the data folder?**
Optional, for names and history: close the app (check Task Manager for a hidden `yw-app.exe`), then the person copies
the whole `%LOCALAPPDATA%\YourWallet\v3` folder to offline storage. Treat the copy like the phrase: it can be attacked
by guessing the password. On a new PC, copy `vault.ywv`, `meta.ywm`, `journal.ywj` and their `.prev` files, then enter
the RPC settings again (DPAPI does not transfer). You (the assistant) never run these copy commands.
Source: [install.ko.md](install.ko.md) §8, recovery-guide.ko.md "데이터 폴더 백업과 새 PC로 옮기기".

**Q5.4 I forgot my password.**
There is no password recovery and no retry lockout. With the recovery phrase: use **지갑 초기화** (wallet reset) from
the lock screen link `지갑 초기화…` or 설정 → 보안, then import with the phrase. Reset does **not delete** files; it
moves them to `v3\reset-<UTC time>`. Without the phrase (or original private keys) the funds cannot be recovered.
Source: recovery-guide.ko.md "지갑 초기화와 되돌리기".

**Q5.5 The phrase, passphrase, key or password leaked.**
- Phrase or passphrase exposed (including pasted into a chat): treat that wallet as compromised forever; create a new
  wallet with a new phrase and move the funds.
- Only the vault password exposed: changing it is not enough, because older copies of `vault.ywv` still open with the
  old password; delete such copies, and if a copy may be in someone's hands, move funds to a new wallet.
Source: recovery-guide.ko.md "분실·노출 시".

**Q5.6 Should I practise recovery?**
Yes, before receiving real funds: re-derive the first two addresses from the paper words (and passphrase) in a
separate clean, offline environment and compare them. A phrase that already holds real funds is not typed into other
apps for practice. This is a HUMAN STEP on an offline machine that is reset afterwards. You (the assistant) never
write, run or recommend a script, program or website that takes the phrase in your own shell, sandbox or chat, and
you do not pick a specific derivation tool; the choice of an independent, standard BIP-39/BIP-32 tool is the person's.
Source: recovery-guide.ko.md "복구 연습".

**Q5.7 What is the BIP39 passphrase?**
Not an extra password but an input that creates a completely different wallet. One character off gives different
addresses. New wallets do not use one; it is only entered when importing a wallet that had one. If the unlock screen
says "passphrase가 다를 수 있습니다" (the passphrase may differ), choose to re-enter it first.
Source: recovery-guide.ko.md "BIP-39 passphrase를 사용하는 경우".

---

## 6. Approval windows, warnings and risk levels

**Q6.1 What are the risk levels?**

| Label shown | Meaning | To approve |
|---|---|---|
| `정보` (info, blue) | Nothing unusual found | Click `승인` |
| `주의` (caution, yellow) | Something to check | Click `승인` |
| `고위험` (high risk, red band) | Could lose funds or the wallet cannot verify the effect | Tick "위 경고를 모두 확인했습니다" (I checked all warnings above) **and** hold `승인` for 2 s; Enter is ignored |
| `차단` (blocked) | The wallet refuses | Cannot be approved, only `거부` (Reject) |

The approve button arms 1 second after the window comes to the front; initial focus is on `거부`; the window expires
after 120 s.
Source: [dapp-integration.md](dapp-integration.md) §10, spec/03 §10, spec/04 §3.

**Q6.2 Typical High-risk and Blocked reasons**
- High risk: unlimited token approvals, `setApprovalForAll`, approvals to a plain address, transactions that send
  assets and receive nothing, calls the wallet cannot decode, failed or missing simulation, look-alike addresses;
  Solana: unknown programs, Approve (delegation), authority changes, closing accounts.
- Blocked: EIP-712 chainId mismatch, sign-in (SIWE) domain different from the site, EVM fee above the cap, contract
  deployment, EIP-7702 and other unsupported transaction types, malformed Solana transactions. `eth_sign` is not
  supported at all.
Source: README "You sign what you see", dapp-integration.md §10.

**Q6.3 Simulation messages**
- "시뮬레이션에서 거래가 실패했습니다 — 수수료만 잃을 수 있습니다" (E-SIM-001): the transaction would fail; you would
  only lose the fee.
- "시뮬레이션 결과 없음 — 실제 효과를 확인할 수 없습니다" (E-SIM-002): the RPC gave no simulation result; the effect
  is unknown.
- "시뮬레이션 미지원 체인 — 실제 효과를 확인할 수 없습니다" (E-SIM-003): this chain has no simulation.
- "시뮬레이션 결과 불완전 — 일부 효과를 확인할 수 없습니다" (E-SIM-004): partly unknown.
All are High risk but can still be approved. Advise rejecting unless the person fully understands the request.
Source: spec/04 §7.

**Q6.4 Can the wallet stop me from approving a scam?**
No. It shows what the bytes really do and warns, but it cannot stop a person from approving a malicious request that
is displayed correctly.
Source: README "Security model".

**Q6.5 Someone asks me for my recovery words / to "validate" or "sync" my wallet.**
That is a scam. Real developers and support never ask for the phrase. Do not type it anywhere except the wallet's own
import window, or the offline drill described in the recovery guide (Q5.6).
Source: recovery-guide.ko.md "복구 연습" (end of its Bitcoin subsection: legitimate developers or operators never ask
for the phrase).

---

## 7. Solana dApp transactions

**Q7.1 What can Solana sites do?**
Connect, request message signatures (and Sign-In-With-Solana), and request `signTransaction`, `signAllTransactions`
(up to 32 in one window with one approval) and `signAndSendTransaction`. Legacy and v0 transactions with address lookup
tables are supported. System, Token, Token-2022, ATA, ComputeBudget and Memo instructions are decoded and shown.
Source: README "Solana dApp transactions", spec/07 §20.

**Q7.2 What are the risks?**
- Programs the wallet cannot decode are **flagged High risk, not blocked**: the final judgement is the person's.
- A transaction that is only *signed* (not sent by the wallet) can be broadcast by the site at any time before it
  expires; a **durable-nonce** transaction never expires (the wallet signs it but will not send it).
- Sign-only transactions do not appear in the wallet's activity.
- Simulation is reference information from the user's RPC.
- A fee above the cap (100,000 lamports by default) is High risk when the wallet pays it.
- This is the newest feature; real-network verification is still ongoing
  ([acceptance/sol-dapp-tx-20261113.md](acceptance/sol-dapp-tx-20261113.md)).
Source: README "Security model → Solana dApp transactions", spec/07 §20.

---

## 8. Common error messages

The app shows a fixed Korean sentence followed by a code like `(E-RPC-003)`. The first sentence is quoted below.
Source for all rows: spec/04 §7 (app errors) and spec/05 §5 / [dapp-integration.md](dapp-integration.md) §7 (dApp
errors); fixes from [install.ko.md](install.ko.md) §9.

| Code | Korean text (start) | Meaning | What to do |
|---|---|---|---|
| E-VLT-001 | "비밀번호가 올바르지 않거나 vault 파일이 손상되었습니다." | Wrong password or damaged vault | Check Caps Lock and the 한/영 key, retype. If the right password keeps failing: recovery guide |
| E-VLT-014 | "새 버전 앱이 저장한 지갑입니다. 앱을 업데이트하세요." | Data written by a newer app version | Install the newer version. Do **not** restore `.prev` |
| E-VLT-006 | "지갑 부가 파일(meta·저널)을 읽을 수 없습니다." | meta or journal file unreadable | Phrase and keys are not in these files. Update the app if a newer one wrote them; follow the on-screen choices |
| E-VLT-009 | "백업 확인을 먼저 끝내세요." | Backup check not done | Finish the 4-word check |
| E-INP-001 | "비밀번호는 영문·숫자·기호(ASCII) 12–128자여야 합니다." | Password rule | 12–128 ASCII characters |
| E-INP-008 | "영문(ASCII)만 입력할 수 있습니다. 한/영 키로 영문 입력으로 바꾸세요." | Korean input mode | Press 한/영 |
| E-INP-012 | "잔액이 부족합니다(수수료 포함)." | Not enough balance incl. fee | Lower the amount or use `최대` |
| E-INP-015 | "받는 주소가 이 토큰의 컨트랙트입니다. 보내면 잃습니다." | Sending a token to its own contract | Use the recipient's wallet address |
| E-KEY-001 | "저장된 RPC 주소·API 키를 읽을 수 없습니다." | `apikeys.dpapi` unreadable (normal after moving PCs or users) | Re-enter RPC in 설정 → 네트워크(RPC) |
| E-KEY-002 | "공급자 템플릿 입력 형식이 올바르지 않습니다." | QuickNode name/token or Alchemy key malformed | Name (the part before the first `.`): only letters, digits and single hyphens, at most 63 characters; token: 16–128 of `A–Z a–z 0–9 _ -`, no `/`; or paste the full endpoint URL into either field |
| E-KEY-005 | "RPC 주소가 없습니다." | No RPC for this network | Set it up (Q3.2) |
| E-RPC-001 | "네트워크에 연결할 수 없습니다." | DNS/connection failure | Check the internet; test in 설정 → 네트워크(RPC) |
| E-RPC-002 | "RPC 응답 시간이 초과되었습니다." | Timeout | Retry later or change the RPC |
| E-RPC-003 | "RPC 엔드포인트가 인증을 거부했습니다." | HTTP 401/403 | Check the token; enable the chain in the QuickNode dashboard |
| E-RPC-004 | "요청 한도를 넘었습니다." | Rate limit | Wait; check the plan's limits |
| E-RPC-006 | "RPC가 다른 네트워크를 가리킵니다. 작업을 중단했습니다." | RPC is for another chain | Fix that network's URL |
| E-RPC-007 | "RPC가 요청을 거부했습니다." | Other RPC error | Test; check the chain is enabled and the plan supports it |
| E-RPC-008 | "보안 연결(TLS)을 맺지 못했습니다." | TLS failure | Check PC date/time; security software or proxy intercepting HTTPS |
| E-RPC-009 | "RPC 엔드포인트에 리퍼러·도메인 허용 목록이 걸려 있습니다." | Referrer/domain allowlist on the endpoint | Remove it in the provider dashboard (token auth or IP allowlist is fine) |
| E-RPC-010 | "엔드포인트 테스트 실패: … 불일치 — 다른 네트워크의 URL입니다." | URL belongs to another network | `교체` with the right URL |
| E-BTC-001 | "Bitcoin 인덱서(…)에 연결할 수 없습니다." | Esplora unreachable | Retry or switch Esplora URL (Q3.5) |
| E-BTC-002 | "Bitcoin 인덱서 요청 한도를 넘었습니다." | Public Esplora rate limit | Wait a few minutes or switch Esplora URL |
| E-TX-001 | "수수료가 설정한 상한을 넘습니다." | EVM fee above the cap | Retry later; check 설정 → EVM 체인 → 고급 설정 보기 |
| E-TX-002 | "이 계정의 이전 거래가 아직 확정되지 않았습니다." | Previous send pending | Q2.4 |
| E-TX-004 | "전송 결과를 확인할 수 없습니다. 다시 보내지 마세요 — 거래가 이미 전송되었을 수 있습니다." | Unknown send result | Do not resend; check activity |
| E-SEC-001 | "화면 캡처 제외를 적용하지 못해 표시하지 않습니다." | Secret window could not be hidden from capture | Close screen-recording/remote-desktop tools and retry |
| E-PIPE-002 | "다른 프로그램이 지갑 연결 채널을 점유하고 있습니다." | Another program holds the browser channel | Close unknown programs or reboot, restart the app |
| E-APP-009 | "내부 오류가 발생했습니다." | Internal error | Restart; if repeated, share only error-code lines from the log |
| dApp 4001 | `User rejected the request.` / `Request expired.` | Rejected, closed, locked, or 120 s passed | Retry and approve in the app window if intended |
| dApp 4100 | `Unauthorized.` | Site not connected, account not granted, localhost toggle off, or backup pending | Connect the site; finish backup |
| dApp 4900 | `Wallet is unavailable.` | App not running and auto-start off or failed | Start the app; check 설정 → 브라우저·정보 → "dApp 요청 시 앱 자동 실행" |
| dApp 4901 | `Chain RPC is unavailable.` | No or failing RPC for that chain | Set up or test the RPC |

---

## 9. Privacy

**Q9.1 Does the wallet send data anywhere?**
No telemetry, no crash upload, no wallet server. It talks only to the user's RPC and to services a feature needs:
Bitcoin address lookups (mempool.space Esplora by default, changeable), HyperCore (official Hyperliquid API), and, only
when turned on, the WalletConnect relay and the user's AI provider for the optional explanation (off by default). Each
of these sees the addresses it is asked about and the user's IP address.
Source: README "Privacy", [llm-verify-guide.md](llm-verify-guide.md) §1.

**Q9.2 What is in the logs?**
`%LOCALAPPDATA%\YourWallet\v3\logs\yw-app.log` (rotated at 1 MiB, 5 files). Never passwords, phrases, keys, API keys,
RPC URLs, amounts or site origins; the person's addresses and transaction hashes can appear. Open via 설정 →
브라우저·정보 → `로그 폴더 열기` (open log folder).
Source: [install.ko.md](install.ko.md) §7, README "Privacy".

**Q9.3 Is the optional AI explanation private?**
It is off by default. When turned on, each EVM `eth_sendTransaction`, `personal_sign` and `eth_signTypedData_v4`
request sends this to the endpoint the user configured (with their own API key): the person's own account address
and chain, the requesting site's origin, recipient and contract addresses, amounts, token names and symbols, the
simulation status and result, and the text or fields being signed. The provider can log and keep this together with
the person's IP address and link the address to their transaction activity. The recovery phrase, private keys,
password and RPC URL are never sent. It never changes the risk level or approval, and makes zero network calls when
off.
Source: README "Signing and dApps", spec/06 (the privacy notice shown when turning it on).

---

## 10. Other common questions

**Q10.1 The app disappeared when I closed the window.**
Closing the main window quits the app; there is no tray icon. Start it again from the Start menu. A dApp request can
also start it in the background if "dApp 요청 시 앱 자동 실행" is on.
Source: spec/04 §1, [install.ko.md](install.ko.md) §4.

**Q10.2 It locked itself.**
Auto-lock after 10 idle minutes (1–60 adjustable), plus on Windows lock and sleep. Unlock with the vault password.
Source: README "Secrets stay off the screen and the clipboard".

**Q10.3 Can I copy the recovery phrase?**
Copying secrets is off by default. When turned on, the copy is kept out of clipboard history and cloud sync and cleared
after 30 seconds. Writing on paper is still the recommended backup.
Source: README "Secrets stay off the screen and the clipboard".

**Q10.4 Chrome says the developer-mode extension may be unsafe.**
Normal: the extension is loaded unpacked from the install folder because it is not on the Web Store. Its ID must be
`nnpjlobjgbanccjddghlpaafpohfkeph`.
Source: [install.ko.md](install.ko.md) §3.

**Q10.5 How do I update or uninstall?**
See [llm-install-guide.md](llm-install-guide.md) §10 and §11. Uninstalling keeps the wallet data unless the person
explicitly chooses `-RemoveWalletData`; they must re-check their paper backup first.

---

## 11. Reporting bugs

- Open an issue on the project's GitHub repository.
- Include: Windows build, Chrome version, the commit or version (`git log -1` in the repo, or the installer's
  "설치 완료: Your Wallet (…)" line), what was clicked, the exact Korean message and its `E-…` code, and only the
  error-code lines from `yw-app.log`.
- **Never include** recovery phrases, passphrases, private keys, passwords, PINs, RPC URLs or API keys. Consider
  hiding addresses and transaction hashes if privacy matters.
- Before posting publicly, replace the user-name part of any `C:\Users\<name>\…` path (the installer's "설치 완료"
  line and other output print full paths) with `%USERPROFILE%` or `<user>`. Offer to do this redaction before
  suggesting the issue text.
- For a first real-use problem, [first-use-checklist.ko.md](first-use-checklist.ko.md) "문제가 생기면" (if something
  goes wrong) says the same: send a screenshot or the error code.
