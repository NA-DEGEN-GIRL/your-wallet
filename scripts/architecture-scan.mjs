import { readFile, readdir } from "node:fs/promises";
import { join, relative, resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");

async function text(path) {
  return readFile(resolve(root, path), "utf8");
}

function withoutBottomTestModule(source) {
  const marker = source.search(
    /\r?\n#\[cfg\([^\]\r\n]*\btest\b[^\]\r\n]*\)\]\r?\nmod tests \{/u,
  );
  return marker === -1 ? source : source.slice(0, marker);
}

function rustItemBlock(source, headerPattern) {
  const header = headerPattern.exec(source);
  if (header === null) {
    return "";
  }

  const openingBrace = source.indexOf("{", header.index);
  if (openingBrace === -1) {
    return "";
  }

  let depth = 0;
  for (let index = openingBrace; index < source.length; index += 1) {
    if (source[index] === "{") {
      depth += 1;
    } else if (source[index] === "}") {
      depth -= 1;
      if (depth === 0) {
        return source.slice(header.index, index + 1);
      }
    }
  }
  return "";
}

function rustFunctionBlock(source, functionName) {
  const escapedName = functionName.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  return rustItemBlock(
    source,
    new RegExp(
      `(?:^|\\n)\\s*(?:pub(?:\\([^\\r\\n)]*\\))?\\s+)?(?:const\\s+)?fn\\s+${escapedName}\\b[^{}]*\\{`,
      "u",
    ),
  );
}

async function rustProductionSources(relativeDirectory) {
  const files = [];
  async function walk(directory) {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const absolute = join(directory, entry.name);
      if (entry.isDirectory()) {
        await walk(absolute);
      } else if (entry.isFile() && entry.name.endsWith(".rs")) {
        files.push(absolute);
      }
    }
  }

  await walk(resolve(root, relativeDirectory));
  files.sort((left, right) => left.localeCompare(right, "en"));
  return Promise.all(
    files.map(async (absolute) => ({
      path: relative(root, absolute).replaceAll("\\", "/"),
      source: withoutBottomTestModule(await readFile(absolute, "utf8")),
    })),
  );
}

function requireInvariant(condition, message) {
  if (!condition) {
    throw new Error(`architecture invariant failed: ${message}`);
  }
}

function hasDependency(manifest, crateName) {
  const escaped = crateName.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  return new RegExp(`^\\s*${escaped}\\s*=`, "mu").test(manifest);
}

function requireCustomRedactedDebug(source, typeName) {
  const customImplementation = [
    `impl fmt::Debug for ${typeName}`,
    `impl core::fmt::Debug for ${typeName}`,
  ].some((marker) => source.includes(marker));
  requireInvariant(
    customImplementation && source.includes("[REDACTED]"),
    `${typeName} must retain an explicit redacted Debug implementation`,
  );
}

function requireStableDisplay(source, typeName, stableMessage) {
  requireInvariant(
    source.includes(`impl fmt::Display for ${typeName}`) && source.includes(stableMessage),
    `${typeName} Display must remain category-only and stable`,
  );
}

const secretBearingCrates = ["secret-core", "key-agent"];
for (const crateName of secretBearingCrates) {
  const manifest = await text(`crates/${crateName}/Cargo.toml`);
  requireInvariant(
    /^publish\s*=\s*false$/mu.test(manifest),
    `${crateName} must remain a non-publishable in-repository TCB crate`,
  );
}
const publicBoundaryManifests = [
  "crates/broker/Cargo.toml",
  "crates/native-host/Cargo.toml",
  "crates/approval-ui/Cargo.toml",
  "crates/dashboard/Cargo.toml",
];

for (const manifestPath of publicBoundaryManifests) {
  const manifest = await text(manifestPath);
  for (const crateName of secretBearingCrates) {
    requireInvariant(
      !hasDependency(manifest, crateName),
      `${manifestPath} must not depend on ${crateName}`,
    );
  }
}

const rootManifest = await text("Cargo.toml");
const rootReadme = await text("README.md");
const sepoliaArchitectureDoc = await text("docs/architecture.md");
const sepoliaDemoManifest = await text("demo/sepolia-wallet/Cargo.toml");
const sepoliaDemoLock = await text("demo/sepolia-wallet/Cargo.lock");
const sepoliaDemoMain = await text("demo/sepolia-wallet/src/main.rs");
const sepoliaDemoBackend = await text("demo/sepolia-wallet/src/backend.rs");
const sepoliaDemoRpc = await text("demo/sepolia-wallet/src/rpc.rs");
const sepoliaDemoReceiveQr = await text("demo/sepolia-wallet/src/receive_qr.rs");
const sepoliaDemoUi = await text("demo/sepolia-wallet/src/ui.rs");
const sepoliaDemoHeadless = await text("demo/sepolia-wallet/src/headless.rs");
const sepoliaDemoVaultV2 = await text("demo/sepolia-wallet/src/vault_v2.rs");
const sepoliaDemoTokenStore = await text("demo/sepolia-wallet/src/token_store.rs");
const sepoliaDemoActivityStore = await text(
  "demo/sepolia-wallet/src/activity_store.rs",
);
const qrcodegenLockBlock =
  /\[\[package\]\]\r?\nname = "qrcodegen"\r?\n[\s\S]*?(?=\r?\n\[\[package\]\]|\s*$)/u.exec(
    sepoliaDemoLock,
  )?.[0] ?? "";
requireInvariant(
  !rootManifest.includes("demo/sepolia-wallet"),
  "Sepolia demo must remain outside the production workspace",
);
requireInvariant(
  /^publish\s*=\s*false$/mu.test(sepoliaDemoManifest) && /^\[workspace\]$/mu.test(sepoliaDemoManifest),
  "Sepolia demo must remain non-publishable and independently locked",
);
for (const productionSecretCrate of [
  "secret-core",
  "key-agent",
  "platform-windows",
  "secret-input-ui",
]) {
  requireInvariant(
    !hasDependency(sepoliaDemoManifest, productionSecretCrate),
    `Sepolia demo must not weaken ${productionSecretCrate} boundaries`,
  );
}
requireInvariant(
  sepoliaDemoRpc.includes("pub const SEPOLIA_CHAIN_ID: u64 = 11_155_111") &&
    sepoliaDemoRpc.includes("https://ethereum-sepolia-rpc.publicnode.com") &&
    sepoliaDemoRpc.includes("SEPOLIA_GENESIS_HASH") &&
    sepoliaDemoRpc.includes(".max_redirects(0)") &&
    sepoliaDemoRpc.includes(".proxy(None)"),
  "Sepolia demo RPC identity, endpoint, redirect, and proxy policy changed",
);
requireInvariant(
  sepoliaDemoBackend.includes("PENDING_MAGIC") &&
    sepoliaDemoBackend.includes("write_new_pending") &&
    sepoliaDemoBackend.includes("retry_pending_inner") &&
    sepoliaDemoBackend.includes("rlp_integer(&[y_parity])"),
  "Sepolia demo lost durable ambiguous-broadcast or canonical-signature guards",
);
requireInvariant(
  sepoliaDemoUi.includes("pub struct SensitiveText(Zeroizing<String>);") &&
    /pub struct SecretReveal\s*\{[\s\S]*?text:\s*Zeroizing<String>[\s\S]*?\}/u.test(
      sepoliaDemoUi,
    ) &&
    /pub struct GeneratedBackupReveal\s*\{[\s\S]*?phrase:\s*Zeroizing<String>[\s\S]*?first_address:\s*Zeroizing<String>[\s\S]*?\}/u.test(
      sepoliaDemoUi,
    ) &&
    /pub struct GeneratedBackupConfirmation\s*\{[\s\S]*?words:\s*\[SensitiveText;[\s\S]*?first_address:\s*SensitiveText[\s\S]*?\}/u.test(
      sepoliaDemoUi,
    ) &&
    !/#\[derive\([^\]]*(?:Clone|Copy|Debug|Serialize)[^\]]*\)\]\s*pub struct (?:SensitiveText|SecretReveal|GeneratedBackupReveal|GeneratedBackupConfirmation)/u.test(
      sepoliaDemoUi,
    ) &&
    !/impl\s+(?:Clone|Copy|Debug|Serialize)\s+for\s+(?:SensitiveText|SecretReveal|GeneratedBackupReveal|GeneratedBackupConfirmation)/u.test(
      sepoliaDemoUi,
    ),
  "Sepolia secret input/reveal/confirmation wrappers must stay zeroizing and move-only",
);
requireInvariant(
  sepoliaDemoUi.includes(
    "const SECRET_REVEAL_DURATION: Duration = Duration::from_secs(20)",
  ) &&
    sepoliaDemoUi.includes(".selectable(false)") &&
    !/copy_text\s*\([^)]*(?:secret|reveal|mnemonic|private_key)/isu.test(sepoliaDemoUi),
  "Sepolia secret reveal must stay short-lived, non-selectable, and clipboard-free",
);

const generatedChallengeBody =
  /pub struct GeneratedBackupChallenge\s*\{(?<body>[\s\S]*?)\n\}/u.exec(sepoliaDemoUi)
    ?.groups?.body ?? "";
const generatedConfirmationBody =
  /fn confirm_generated\([\s\S]*?(?=\n    fn ensure_generated_confirmation_live)/u.exec(
    sepoliaDemoBackend,
  )?.[0] ?? "";
requireInvariant(
  sepoliaDemoBackend.includes(
    "const GENERATED_BACKUP_TTL: Duration = Duration::from_secs(120)",
    ) &&
    sepoliaDemoBackend.includes("enum PendingGeneratedStage") &&
    sepoliaDemoBackend.includes("Display") &&
    /Challenge\s*\{\s*positions:\s*\[u8;/u.test(sepoliaDemoBackend) &&
    sepoliaDemoBackend.includes("random_backup_challenge_positions") &&
    sepoliaDemoBackend.includes("const MAX_RANDOM_SAMPLES: usize = 256") &&
    generatedChallengeBody.includes("positions:") &&
    generatedChallengeBody.includes("expires_at:") &&
    !/(?:phrase|mnemonic|expected|first_address|SensitiveText|Zeroizing|Serialize|Debug)/u.test(
      generatedChallengeBody,
    ) &&
    sepoliaDemoUi.includes("BeginGeneratedBackupChallenge") &&
    sepoliaDemoUi.includes("confirmation: GeneratedBackupConfirmation") &&
    sepoliaDemoUi.includes("permit: &SessionPermit<'_>") &&
    (generatedConfirmationBody.match(/ensure_generated_confirmation_live\(/gu) ?? [])
      .length === 5 &&
    generatedConfirmationBody.indexOf("verify_generated_backup") <
      generatedConfirmationBody.indexOf("seal_vault_v2") &&
    generatedConfirmationBody.indexOf("seal_vault_v2") <
      generatedConfirmationBody.indexOf("open_vault_v2") &&
    generatedConfirmationBody.indexOf("open_vault_v2") <
      generatedConfirmationBody.indexOf("write_new_file") &&
    sepoliaDemoUi.includes("events.retain_mut(retain_generated_backup_event)") &&
    /Event::Paste\(text\)[\s\S]*?text\.zeroize\(\)[\s\S]*?false/u.test(
      sepoliaDemoUi,
    ) &&
    sepoliaDemoUi.includes("fn secret_text_edit_ids() -> [egui::Id; 15]") &&
    sepoliaDemoUi.includes("state.clear_undoer()") &&
    sepoliaDemoUi.includes(
      "data.remove::<egui::widgets::text_edit::TextEditState>(id)",
    ) &&
    !/#\[derive\([^\]]*(?:Clone|Debug|Serialize)[^\]]*\)\]\s*(?:enum WorkerCommand|enum WorkerEvent|struct WorkerResponse)/u.test(
      sepoliaDemoUi,
    ),
  "Sepolia generated-backup challenge lost deadline, move-only DTO, permit, clipboard, undo, or no-write-before-verification guards",
);
requireInvariant(
  sepoliaDemoBackend.includes("V2(OpenedVaultV2)") &&
    sepoliaDemoBackend.includes("selected_account_index: u8") &&
    sepoliaDemoBackend.includes("pending_generation: Option<PendingGeneratedWallet>") &&
    sepoliaDemoBackend.includes("self.ensure_management_mutation_allowed()?") &&
    sepoliaDemoBackend.includes("path_may_exist(&self.pending_path)"),
  "Sepolia v2 unlock/bounded-account/pending-quarantine management boundary changed",
);

// Sepolia authenticated saved ERC-20 transfer invariants (demo-only).
const sepoliaDemoBackendProduction = withoutBottomTestModule(sepoliaDemoBackend);
const sepoliaDemoRpcProduction = withoutBottomTestModule(sepoliaDemoRpc);
const sepoliaDemoReceiveQrProduction = withoutBottomTestModule(sepoliaDemoReceiveQr);
const sepoliaDemoUiProduction = withoutBottomTestModule(sepoliaDemoUi);
const sepoliaDemoHeadlessProduction = withoutBottomTestModule(sepoliaDemoHeadless);
const sepoliaDemoUiHeadlessStart = sepoliaDemoUiProduction.indexOf(
  "pub(crate) fn run_headless_smoke",
);
const sepoliaDemoUiRuntime =
  sepoliaDemoUiHeadlessStart === -1
    ? sepoliaDemoUiProduction
    : sepoliaDemoUiProduction.slice(0, sepoliaDemoUiHeadlessStart);

// Sepolia bounded account switching is authenticated, session-only, and
// bound independently at every prepare/confirm/export/pending boundary.
const selectAccountBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "select_account_inner",
);
const walletSnapshotBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "snapshot",
);
const openWalletBlock = rustFunctionBlock(sepoliaDemoBackendProduction, "open");
const lockWalletBlock = rustFunctionBlock(sepoliaDemoBackendProduction, "lock");
const prepareNativeAccountBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "prepare_transfer_inner",
);
const confirmAccountBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "confirm_prepared_with_permit",
);
const exportSelectedAccountBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "export_account_private_key_inner",
);
const tokenAccountContextBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "token_context",
);
const tokenAccountContextForAccountBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "token_context_for_account",
);
const preparePendingAccountBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "prepare_pending_retry",
);
const retryPendingAccountBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "retry_pending_with_permit",
);
const recoverPendingSenderBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "recover_signed_type_two_sender",
);
const pendingLeaseBlock = rustItemBlock(
  sepoliaDemoBackendProduction,
  /(?:^|\n)struct PendingFileLease\s*\{/u,
);
const pendingWriteBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "write_new_pending",
);
const accountSelectedUiBlock = rustItemBlock(
  sepoliaDemoUiProduction,
  /WorkerEvent::AccountSelected\(result\)\s*=>\s*match result\s*\{/u,
);
const walletAppBlock = rustItemBlock(
  sepoliaDemoUiProduction,
  /(?:^|\n)pub struct WalletApp\s*\{/u,
);
const walletAppImplBlock = rustItemBlock(
  sepoliaDemoUiProduction,
  /(?:^|\n)impl WalletApp\s*\{/u,
);
const selectAccountUiBlock = rustFunctionBlock(
  walletAppImplBlock,
  "select_account",
);
const scrubFrontendSessionBlock = rustFunctionBlock(
  walletAppImplBlock,
  "scrub_frontend_session",
);
const accountPanelBlock = rustFunctionBlock(walletAppImplBlock, "account_panel");
const receiveRevealBlock = rustItemBlock(
  accountPanelBlock,
  /(?:^|\n)\s*if self\.receive_qr_visible\s*\{\s*ui\.add_space\(6\.0\);/u,
);
const qrLayoutImplBlock = rustItemBlock(
  sepoliaDemoReceiveQrProduction,
  /(?:^|\n)impl QrLayout\s*\{/u,
);
const qrLayoutConstructorBlock = rustFunctionBlock(qrLayoutImplBlock, "new");
const receiveQrImplBlock = rustItemBlock(
  sepoliaDemoReceiveQrProduction,
  /(?:^|\n)impl ReceiveQr\s*\{/u,
);
const receiveQrConstructorBlock = rustFunctionBlock(receiveQrImplBlock, "new");
const receiveQrPaintBlock = rustFunctionBlock(receiveQrImplBlock, "paint");
const exactEip55Block = rustFunctionBlock(
  sepoliaDemoReceiveQrProduction,
  "is_exact_eip55_address",
);
const accountPrivateKeyRevealBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "account_private_key_reveal",
);
const secretRevealItem = rustItemBlock(
  sepoliaDemoUiProduction,
  /(?:^|\n)pub struct SecretReveal\s*\{/u,
);
const mnemonicExportUiBlock = rustItemBlock(
  sepoliaDemoUiProduction,
  /WorkerEvent::MnemonicExported\(result\)\s*=>\s*match result\s*\{/u,
);
const privateKeyExportUiBlock = rustItemBlock(
  sepoliaDemoUiProduction,
  /WorkerEvent::AccountPrivateKeyExported\(result\)\s*=>\s*match result\s*\{/u,
);
requireInvariant(
  sepoliaDemoBackendProduction.includes("selected_account_index: u8") &&
    sepoliaDemoBackendProduction.includes("fn account_snapshots(&self)") &&
    sepoliaDemoBackendProduction.includes("wallet.account_count() != 2") &&
    sepoliaDemoBackendProduction.includes("wallet.account(2).is_some()") &&
    selectAccountBlock.includes("wallet.account_address(index)?") &&
    selectAccountBlock.includes("self.pending_broadcast_exists()") &&
    selectAccountBlock.includes("self.prepared.is_some()") &&
    selectAccountBlock.includes("self.pending_generation.is_some()") &&
    selectAccountBlock.includes("self.selected_account_index = index") &&
    selectAccountBlock.includes("self.last_balance = None") &&
    !/(?:write_new_file|seal_vault|token_store|fs::write)/u.test(selectAccountBlock) &&
    lockWalletBlock.includes("self.selected_account_index = 0") &&
    openWalletBlock.includes("self.selected_account_index = 0") &&
    walletSnapshotBlock.includes("selected_account_index: self.selected_account_index") &&
    walletSnapshotBlock.includes("pending_broadcast:") &&
    !sepoliaDemoVaultV2.includes("selected_account_index") &&
    !sepoliaDemoTokenStore.includes("selected_account_index") &&
    !pendingWriteBlock.includes("account_index"),
  "Sepolia account 0/1 selection must remain bounded, session-only, reset-on-lock/open, and absent from vault/token/pending formats",
);
requireInvariant(
  sepoliaDemoUiProduction.includes("pub struct WalletAccountSnapshot") &&
    sepoliaDemoUiProduction.includes("pub selected_account_index: u8") &&
    sepoliaDemoUiProduction.includes("pub sender_account_index: u8") &&
    sepoliaDemoBackendProduction.includes("account_index: u8") &&
    prepareNativeAccountBlock.includes("let (account_index, sender) = self.selected_account()?") &&
    confirmAccountBlock.includes("self.selected_account_index != prepared.account_index") &&
    confirmAccountBlock.includes("wallet.account_address(prepared.account_index)?") &&
    confirmAccountBlock.includes("account_private_key(u32::from(prepared.account_index))") &&
    exportSelectedAccountBlock.includes("let (selected_index, selected_address)") &&
    exportSelectedAccountBlock.includes("let expected_index = u32::from(selected_index)") &&
    exportSelectedAccountBlock.includes("requested_index() != expected_index") &&
    exportSelectedAccountBlock.includes("export_account_private_key(u32::from(selected_index))") &&
    exportSelectedAccountBlock.includes(
      "account_private_key_reveal(export, selected_index, selected_address)",
    ) &&
    tokenAccountContextBlock.includes(
      "self.token_context_for_account(self.selected_account_index)",
    ) &&
    tokenAccountContextForAccountBlock.includes("account(usize::from(account_index))") &&
    tokenAccountContextForAccountBlock.includes("requested_index() != expected_index") &&
    tokenAccountContextForAccountBlock.includes("actual_index() != expected_index") &&
    tokenAccountContextForAccountBlock.includes("account_index,") &&
    tokenAccountContextForAccountBlock.includes("owner: *owner.address().as_bytes()") &&
    accountSelectedUiBlock.includes("self.reauth_password.zeroize()") &&
    accountSelectedUiBlock.includes("self.secret_text_state_purge_pending = true") &&
    accountSelectedUiBlock.includes("zeroize_custom_token_snapshots") &&
    accountSelectedUiBlock.includes("zeroize_optional_string(&mut self.last_transaction_hash)"),
  "Sepolia selected account identity must stay visible and independently rebound for balance, token, signer, export, and UI scrub paths",
);
requireInvariant(
  secretRevealItem.includes("account_index: Option<u8>") &&
    secretRevealItem.includes("account_address: Option<Zeroizing<String>>") &&
    accountPrivateKeyRevealBlock.includes("account_index > 1") &&
    accountPrivateKeyRevealBlock.includes("checksum_address(account_address)") &&
    mnemonicExportUiBlock.includes(
      "completed_action == Some(PendingAction::ExportMnemonic)",
    ) &&
    mnemonicExportUiBlock.includes("reveal.kind() == SecretRevealKind::Mnemonic") &&
    privateKeyExportUiBlock.includes(
      "completed_action == Some(PendingAction::ExportAccountPrivateKey)",
    ) &&
    privateKeyExportUiBlock.includes(
      "reveal.kind() == SecretRevealKind::AccountPrivateKey",
    ) &&
    privateKeyExportUiBlock.includes("index == selected.index") &&
    privateKeyExportUiBlock.includes("address == selected.address.as_str()") &&
    sepoliaDemoUiProduction.includes(
      'format!("계정 {index} 개인 키 · 전체 주소 {address}")',
    ) &&
    sepoliaDemoUiProduction.includes(
      'format!("계정 {selected_account_index} 잔액: {balance}")',
    ) &&
    !sepoliaDemoUiProduction.includes('"계정 0 개인 키"') &&
    !sepoliaDemoUiProduction.includes('"계정 0 잔액:'),
  "Sepolia secret export purpose/account binding and selected-account balance labels must remain exact and non-hardcoded",
);
requireInvariant(
  receiveQrConstructorBlock.includes("if !is_exact_eip55_address(address)") &&
    receiveQrConstructorBlock.includes(
      'format!("ethereum:{address}@{SEPOLIA_CHAIN_ID}")',
    ) &&
    receiveQrConstructorBlock.includes(
      "QrCode::encode_text(payment_uri.as_str(), QrCodeEcc::Medium)",
    ) &&
    !/(?:push_str|insert_str|ethereum:pay-|\bamount\b|\bvalue\b)/u.test(
      receiveQrConstructorBlock,
    ) &&
    exactEip55Block.includes('address.strip_prefix("0x")') &&
    exactEip55Block.includes("hex.len() != ADDRESS_HEX_BYTES") &&
    exactEip55Block.includes("byte.is_ascii_hexdigit()") &&
    exactEip55Block.includes("hex.bytes().all(|byte| byte == b'0')") &&
    exactEip55Block.includes("hex.to_ascii_lowercase()") &&
    exactEip55Block.includes("Keccak256::digest(lowercase.as_bytes())") &&
    exactEip55Block.includes("byte.is_ascii_uppercase() == (nibble >= 8)") &&
    sepoliaDemoRpc.includes("pub const SEPOLIA_CHAIN_ID: u64 = 11_155_111"),
  "Sepolia Receive QR must remain strict selected-account EIP-55 with exact amount-free ethereum:<address>@11155111 payload",
);
requireInvariant(
  accountPanelBlock.includes("snapshot.selected_account().cloned()") &&
    accountPanelBlock.includes("copy_text(selected_account.address.clone())") &&
    /if ui\.button\([^{}]*\)\.clicked\(\)\s*\{\s*ui\.ctx\(\)\.copy_text\(selected_account\.address\.clone\(\)\);/u.test(
      accountPanelBlock,
    ) &&
    /\.add_enabled\(\s*self\.pending\.is_none\(\),\s*egui::Button::new\(receive_button_text\),\s*\)\s*\.clicked\(\)/u.test(
      accountPanelBlock,
    ) &&
    /if ui[\s\S]{0,320}?\.clicked\(\)\s*\{\s*self\.receive_qr_visible = !self\.receive_qr_visible;\s*\}/u.test(
      accountPanelBlock,
    ) &&
    receiveRevealBlock.includes(
      "ReceiveQr::new(selected_account.address.as_str())",
    ) &&
    receiveRevealBlock.includes("selected_account.index") &&
    receiveRevealBlock.includes("crate::rpc::SEPOLIA_CHAIN_ID") &&
    receiveRevealBlock.indexOf("palette.warning") <
      receiveRevealBlock.indexOf("ReceiveQr::new") &&
    /if ui\.button\([^{}]*\)\.clicked\(\)\s*\{\s*ui\.ctx\(\)\.copy_text\(qr\.payment_uri\(\)\.to_owned\(\)\);/u.test(
      receiveRevealBlock,
    ) &&
    (sepoliaDemoUiProduction.match(/ReceiveQr::new\(/gu) ?? []).length === 1 &&
    selectAccountUiBlock.indexOf("self.receive_qr_visible = false") <
      selectAccountUiBlock.indexOf("self.send_command(") &&
    accountSelectedUiBlock.includes("self.receive_qr_visible = false") &&
    scrubFrontendSessionBlock.includes("self.receive_qr_visible = false"),
  "Sepolia Receive QR reveal/copy must stay explicit, selected-account-bound, public-metadata-warned, and hidden across selection and lock",
);
requireInvariant(
  sepoliaDemoReceiveQrProduction.includes("const QUIET_ZONE_MODULES: u32 = 4") &&
    sepoliaDemoReceiveQrProduction.includes("const MIN_MODULE_PIXELS: u32 = 6") &&
    qrLayoutConstructorBlock.includes(
      "let maximum_module_pixels = available_for_modules / total_modules",
    ) &&
    qrLayoutConstructorBlock.includes(
      "if maximum_module_pixels < MIN_MODULE_PIXELS",
    ) &&
    qrLayoutConstructorBlock.includes(
      "let preferred_module_pixels = (preferred_module_pixels as u32).max(MIN_MODULE_PIXELS)",
    ) &&
    qrLayoutConstructorBlock.includes(
      "let module_pixels = preferred_module_pixels.min(maximum_module_pixels)",
    ) &&
    qrLayoutConstructorBlock.indexOf(".max(MIN_MODULE_PIXELS)") <
      qrLayoutConstructorBlock.indexOf(".min(maximum_module_pixels)") &&
    qrLayoutConstructorBlock.includes("checked_add(QUIET_ZONE_MODULES * 2)") &&
    receiveQrPaintBlock.includes(
      "ui.available_rect_before_wrap().intersect(clip_rect)",
    ) &&
    receiveQrPaintBlock.includes(
      "visible_rect.width().min(visible_rect.height())",
    ) &&
    receiveQrPaintBlock.includes(
      "QrLayout::new(self.code.size(), pixels_per_point, available_side)?",
    ) &&
    receiveQrPaintBlock.includes(
      "if !clip_rect.contains(canvas.min) || !clip_rect.contains(canvas.max)",
    ) &&
    receiveQrPaintBlock.indexOf("clip_rect.contains(canvas.min)") <
      receiveQrPaintBlock.indexOf("rect_filled(canvas") &&
    receiveQrPaintBlock.includes("x + QUIET_ZONE_MODULES") &&
    receiveQrPaintBlock.includes("y + QUIET_ZONE_MODULES") &&
    receiveQrPaintBlock.includes("x + QUIET_ZONE_MODULES + 1") &&
    receiveQrPaintBlock.includes("y + QUIET_ZONE_MODULES + 1"),
  "Sepolia Receive QR must retain quiet-zone 4, >=6 integer physical modules, and whole-canvas width/height clip fail-closure",
);
requireInvariant(
  sepoliaDemoManifest.includes('qrcodegen = "=1.8.0"') &&
    qrcodegenLockBlock.includes('version = "1.8.0"') &&
    !qrcodegenLockBlock.includes("dependencies =") &&
    /^mod receive_qr;$/mu.test(sepoliaDemoMain) &&
    !/^pub(?:\(crate\))?\s+mod receive_qr;$/mu.test(sepoliaDemoMain) &&
    !/\bpub\s+use\b[^\r\n]*\breceive_qr\b/u.test(
      `${sepoliaDemoMain}\n${sepoliaDemoUiProduction}`,
    ) &&
    walletAppBlock.includes("receive_qr_visible: bool") &&
    !/(?:payment_uri|QrCode|ReceiveQr)/u.test(walletAppBlock) &&
    (sepoliaDemoReceiveQrProduction.match(/crate::rpc::/gu) ?? []).length === 1 &&
    !/(?:\bstatic\b|thread_local!|OnceLock|LazyLock|Mutex|RwLock|RefCell)/u.test(
      sepoliaDemoReceiveQrProduction,
    ) &&
    !/(?:TextureHandle|load_texture|include_bytes!|std::fs|OpenOptions|File::|std::net|TcpStream|UdpSocket|ureq::|reqwest|web_sys|tokio::)/u.test(
      sepoliaDemoReceiveQrProduction,
    ),
  "Sepolia Receive QR must stay qrcodegen 1.8.0, frame-local, and free of texture/cache/file/network APIs",
);
requireInvariant(
  rootReadme.includes("## 받기 QR 계약 (Sepolia 실행판 한정)") &&
    rootReadme.includes("`ethereum:<address>@11155111`") &&
    rootReadme.includes("`qrcodegen =1.8.0`") &&
    rootReadme.includes("전체 QR이 현재 보이는 영역 안에 들어오지 않으면 그리지 않고") &&
    rootReadme.includes("계정 전환 요청·성공과 잠금·세션 정리는 QR을 다시 숨깁니다") &&
    sepoliaArchitectureDoc.includes("### Sepolia demo receive QR boundary") &&
    /the address,\s+selected account index,\s+and Sepolia chain\s+ID are public identifying metadata/u.test(
      sepoliaArchitectureDoc,
    ) &&
    sepoliaArchitectureDoc.includes(
      "the entire canvas remains inside that clip before painting",
    ) &&
    /No QR texture,\s+cache, file, or network path exists/u.test(
      sepoliaArchitectureDoc,
    ),
  "Sepolia Receive QR documentation must retain exact payload, public-metadata warning, dependency, geometry, and fail-closed scope",
);

// Sepolia selected-account overview hydration remains a one-shot, bounded,
// non-authoritative follow-up. It may observe authenticated token rows but may
// not mutate their namespace, and its response can update only the exact local
// account/session snapshot that initiated the request.
const selectedOverviewBlock = rustItemBlock(
  sepoliaDemoUiProduction,
  /(?:^|\n)pub struct SelectedAccountOverview\s*\{/u,
);
const selectedOverviewImplBlock = rustItemBlock(
  sepoliaDemoUiProduction,
  /(?:^|\n)impl SelectedAccountOverview\s*\{/u,
);
const selectedOverviewValidationBlock = rustFunctionBlock(
  selectedOverviewImplBlock,
  "is_well_formed",
);
const runtimeBalanceValidationBlock = rustFunctionBlock(
  sepoliaDemoUiProduction,
  "valid_runtime_balance_shape",
);
const customTokenStateValidationBlock = rustFunctionBlock(
  sepoliaDemoUiProduction,
  "custom_token_state_is_well_formed",
);
const verifySepoliaBlock = rustFunctionBlock(
  sepoliaDemoRpcProduction,
  "verify_sepolia",
);
const tokenObservationLeaseBlock = rustItemBlock(
  sepoliaDemoBackendProduction,
  /(?:^|\n)struct TokenObservationLease\s*<[^>]+>\s*\{/u,
);
const tokenObservationLeaseImplBlock = rustItemBlock(
  sepoliaDemoBackendProduction,
  /(?:^|\n)impl\s*<[^>]+>\s*TokenObservationLease\s*<[^>]+>\s*\{/u,
);
const tokenObservationAcquireBlock = rustFunctionBlock(
  tokenObservationLeaseImplBlock,
  "acquire",
);
const productionTokenObservationLockBlock =
  /#\[cfg\(not\(test\)\)\]\s*let process_guard = match TOKEN_STORE_PROCESS_LOCK\.try_lock\(\)\s*\{[\s\S]*?\n\s*\};\s*#\[cfg\(test\)\]/u.exec(
    tokenObservationAcquireBlock,
  )?.[0] ?? "";
const openTokenObservationFileBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "open_token_observation_file",
);
const refreshSelectedOverviewOuterBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "refresh_selected_overview",
);
const refreshSelectedOverviewBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "refresh_selected_overview_inner",
);
const refreshOverviewUiBlock = rustFunctionBlock(walletAppImplBlock, "refresh");
const refreshedOverviewUiBlock = rustItemBlock(
  sepoliaDemoUiProduction,
  /WorkerEvent::Refreshed\(result\)\s*=>\s*match result\s*\{/u,
);
const importedOverviewUiBlock = rustItemBlock(
  sepoliaDemoUiProduction,
  /WorkerEvent::MnemonicImported\(result\)\s*\|\s*WorkerEvent::PrivateKeyImported\(result\)\s*=>\s*\{/u,
);
const openedOverviewUiBlock = rustItemBlock(
  sepoliaDemoUiProduction,
  /WorkerEvent::Opened\(result\)\s*=>\s*match result\s*\{/u,
);
const migratedOverviewUiBlock = rustItemBlock(
  sepoliaDemoUiProduction,
  /WorkerEvent::LegacyMigrated\(result\)\s*=>\s*match result\s*\{/u,
);
const generatedConfirmedUiBlock = rustItemBlock(
  sepoliaDemoUiProduction,
  /WorkerEvent::GeneratedConfirmed\(result\)\s*=>\s*match result\s*\{/u,
);
const executeWorkerCommandBlock = rustFunctionBlock(
  sepoliaDemoUiProduction,
  "execute_worker_command",
);
const customTokenPanelBlock = rustFunctionBlock(
  walletAppImplBlock,
  "custom_token_panel",
);
requireInvariant(
  sepoliaDemoUiProduction.includes(
    "pub(crate) const AUTO_OVERVIEW_TOKEN_LIMIT: usize = 3",
  ) &&
    sepoliaDemoUiProduction.includes(
      "const MAX_RUNTIME_BALANCE_BYTES: usize = 79",
    ) &&
    sepoliaDemoUiProduction.includes(
      'pub(crate) const ACCOUNT_BALANCE_UNKNOWN: &str = "조회 전"',
    ) &&
    selectedOverviewBlock.includes("snapshot: WalletSnapshot") &&
    selectedOverviewBlock.includes("token_owner_account_index: u8") &&
    selectedOverviewBlock.includes("token_owner_address: String") &&
    selectedOverviewBlock.includes("custom_tokens: Vec<CustomTokenSnapshot>") &&
    selectedOverviewBlock.includes("token_rows_loaded: bool") &&
    selectedOverviewBlock.includes("balance_refreshed: bool") &&
    selectedOverviewBlock.includes("deferred_token_count: u8") &&
    !/#\[derive\([^\]]*(?:Clone|Copy|Debug|Serialize)[^\]]*\)\]\s*pub struct SelectedAccountOverview/u.test(
      sepoliaDemoUiProduction,
    ) &&
    !/(?:^|\n)\s*(?:unsafe\s+)?impl(?:\s*<[^>{}\r\n]*>)?\s+[^{}\r\n]+\s+for\s+[^{};\r\n]*\bSelectedAccountOverview\b/mu.test(
      sepoliaDemoUiProduction,
    ) &&
    !/\bpub(?:\([^)]*\))?\s+(?:snapshot|token_owner_account_index|token_owner_address|custom_tokens|token_rows_loaded|balance_refreshed|status|deferred_token_count)\s*:/u.test(
      selectedOverviewBlock,
    ) &&
    selectedOverviewValidationBlock.includes("self.snapshot.is_well_formed()") &&
    selectedOverviewValidationBlock.includes(
      "account.index == self.token_owner_account_index",
    ) &&
    selectedOverviewValidationBlock.includes(
      "account.address == self.token_owner_address",
    ) &&
    selectedOverviewValidationBlock.includes("self.custom_tokens.len() <= 32") &&
    selectedOverviewValidationBlock.includes(
      ".saturating_sub(AUTO_OVERVIEW_TOKEN_LIMIT)",
    ) &&
    selectedOverviewValidationBlock.includes(
      "index >= AUTO_OVERVIEW_TOKEN_LIMIT",
    ) &&
    selectedOverviewValidationBlock.includes(
      "self.snapshot.balance_eth == ACCOUNT_BALANCE_UNKNOWN",
    ) &&
    selectedOverviewValidationBlock.includes("WalletKind::LegacyV1RawPrivateKey") &&
    runtimeBalanceValidationBlock.includes(
      "amount.len() > MAX_RUNTIME_BALANCE_BYTES",
    ) &&
    customTokenStateValidationBlock.includes("*decimals <= 36") &&
    customTokenStateValidationBlock.includes("symbol.len() <= 16") &&
    customTokenStateValidationBlock.includes(
      "OVERVIEW_TOKEN_UNAVAILABLE_ERRORS.contains(&reason_ko.as_str())",
    ),
  "Sepolia selected-overview DTO must remain move-only, exact-owner-bound, bounded, canonical, and category-only",
);
requireInvariant(
  tokenObservationLeaseBlock.includes("_process_guard: MutexGuard") &&
    tokenObservationLeaseBlock.includes("_lock_file: Option<File>") &&
    tokenObservationLeaseBlock.includes("_store_file: Option<File>") &&
    productionTokenObservationLockBlock.includes(
      "TOKEN_STORE_PROCESS_LOCK.try_lock()",
    ) &&
    productionTokenObservationLockBlock.includes("TryLockError::WouldBlock") &&
    productionTokenObservationLockBlock.includes("return Ok(None)") &&
    productionTokenObservationLockBlock.includes("TryLockError::Poisoned") &&
    productionTokenObservationLockBlock.includes(
      "return Err(BackendError::TokenStoreStorage)",
    ) &&
    !productionTokenObservationLockBlock.includes(
      "TOKEN_STORE_PROCESS_LOCK.lock()",
    ) &&
    tokenObservationAcquireBlock.includes("fs::symlink_metadata(&lock_path)") &&
    tokenObservationAcquireBlock.includes("fs::symlink_metadata(token_store_path)") &&
    tokenObservationAcquireBlock.includes("FILE_ATTRIBUTE_REPARSE_POINT") &&
    tokenObservationAcquireBlock.includes("MAX_TOKEN_STORE_BYTES") &&
    tokenObservationAcquireBlock.includes("TokenObservationOpenError::Contended") &&
    tokenObservationAcquireBlock.includes("TokenObservationOpenError::NotFound") &&
    tokenObservationAcquireBlock.includes("TokenObservationOpenError::Storage") &&
    !/(?:create_new|\.write(?:_all)?\s*\(|remove_file|delete|reconcile_orphan|\.flush\s*\(|sync_all|temporary_path)/u.test(
      tokenObservationAcquireBlock,
    ) &&
    openTokenObservationFileBlock.includes(".read(true)") &&
    openTokenObservationFileBlock.includes(".share_mode(FILE_SHARE_READ.0)") &&
    openTokenObservationFileBlock.includes("FILE_FLAG_OPEN_REPARSE_POINT") &&
    openTokenObservationFileBlock.includes("ERROR_SHARING_VIOLATION") &&
    !/(?:\.write\(true\)|FILE_SHARE_WRITE|FILE_SHARE_DELETE)/u.test(
      openTokenObservationFileBlock,
    ),
  "Sepolia token observation must stay non-mutating, contention-distinct, exact-object, regular, and reparse-safe",
);
const initialOverviewVerifyIndex = refreshSelectedOverviewBlock.indexOf(
  "let chain_verified = self.rpc.verify_sepolia().is_ok()",
);
const overviewBalanceIndex = refreshSelectedOverviewBlock.indexOf(
  "let balance = self.rpc.balance(address).ok()",
);
const overviewInspectIndex = refreshSelectedOverviewBlock.indexOf(
  "self.inspect_token_with_permit(",
);
const finalOverviewPermitIndex = refreshSelectedOverviewBlock.indexOf(
  "ensure_session_current(permit)?;\n            let final_chain_verified",
);
const finalOverviewVerifyIndex = refreshSelectedOverviewBlock.indexOf(
  "let final_chain_verified = self.rpc.verify_sepolia().is_ok()",
);
const finalOverviewLoadIndex = refreshSelectedOverviewBlock.lastIndexOf(
  "self.load_token_store(context)?",
);
const overviewCacheInstallIndex = refreshSelectedOverviewBlock.indexOf(
  "self.last_balance = observed_balance.map",
);
requireInvariant(
  refreshSelectedOverviewOuterBlock.includes(
    "let result = self.refresh_selected_overview_inner(permit)",
  ) &&
    refreshSelectedOverviewOuterBlock.includes("if result.is_err()") &&
    refreshSelectedOverviewOuterBlock.includes("self.lock()") &&
    refreshSelectedOverviewBlock.includes("self.last_balance = None") &&
    refreshSelectedOverviewBlock.includes("let local_snapshot = self.snapshot()?") &&
    refreshSelectedOverviewBlock.includes(
      "TokenObservationLease::acquire(&self.token_store_path)",
    ) &&
    refreshSelectedOverviewBlock.includes("position >= AUTO_OVERVIEW_TOKEN_LIMIT") &&
    refreshSelectedOverviewBlock.includes("AUTO_OVERVIEW_DEFERRED_ERROR") &&
    initialOverviewVerifyIndex !== -1 &&
    overviewBalanceIndex > initialOverviewVerifyIndex &&
    overviewInspectIndex > overviewBalanceIndex &&
    finalOverviewPermitIndex > overviewInspectIndex &&
    finalOverviewVerifyIndex > finalOverviewPermitIndex &&
    finalOverviewLoadIndex > finalOverviewVerifyIndex &&
    overviewCacheInstallIndex > finalOverviewLoadIndex &&
    (refreshSelectedOverviewBlock.match(/self\.rpc\.verify_sepolia\(\)/gu) ?? [])
      .length === 2 &&
    refreshSelectedOverviewBlock.includes("observed_balance = None") &&
    refreshSelectedOverviewBlock.includes(
      "final_loaded.baseline.bytes != loaded.baseline.bytes",
    ) &&
    refreshSelectedOverviewBlock.includes(
      "final_loaded.store.entries() != loaded.store.entries()",
    ) &&
    refreshSelectedOverviewBlock.includes(
      "snapshot.pending_broadcast != local_snapshot.pending_broadcast",
    ) &&
    refreshSelectedOverviewBlock.includes(
      "snapshot.activity != local_snapshot.activity",
    ),
  "Sepolia selected-overview hydration must retain permit, chain, token-baseline, local-identity bookends before cache installation",
);
requireInvariant(
  refreshOverviewUiBlock.includes("if self.pending.is_some()") &&
    refreshOverviewUiBlock.includes("mark_snapshot_balance_stale") &&
    refreshOverviewUiBlock.includes(
      "self.send_command(WorkerCommand::Refresh, PendingAction::Refresh)",
    ) &&
    importedOverviewUiBlock.includes("self.refresh()") &&
    openedOverviewUiBlock.includes("self.refresh()") &&
    accountSelectedUiBlock.includes("self.refresh()") &&
    migratedOverviewUiBlock.includes("self.refresh()") &&
    !generatedConfirmedUiBlock.includes("self.refresh()") &&
    (sepoliaDemoUiProduction.match(/self\.refresh\(\);/gu) ?? []).length === 5 &&
    executeWorkerCommandBlock.includes(
      "WorkerCommand::Refresh => WorkerEvent::Refreshed(backend.refresh(permit))",
    ) &&
    refreshedOverviewUiBlock.includes(
      "completed_action == Some(PendingAction::Refresh)",
    ) &&
    refreshedOverviewUiBlock.includes("self.session_phase == SessionPhase::Unlocked") &&
    refreshedOverviewUiBlock.includes(
      "current.wallet_kind == overview.snapshot.wallet_kind",
    ) &&
    refreshedOverviewUiBlock.includes("current.accounts == overview.snapshot.accounts") &&
    refreshedOverviewUiBlock.includes(
      "current.pending_broadcast == overview.snapshot.pending_broadcast",
    ) &&
    refreshedOverviewUiBlock.includes("current.activity == overview.snapshot.activity") &&
    refreshedOverviewUiBlock.includes(
      "selected.index == overview.token_owner_account_index",
    ) &&
    refreshedOverviewUiBlock.includes(
      "selected.address == overview.token_owner_address",
    ) &&
    refreshedOverviewUiBlock.includes("!overview.is_well_formed()") &&
    refreshedOverviewUiBlock.includes("invalidate_frontend_after_backend_error") &&
    !refreshedOverviewUiBlock.includes("self.refresh()") &&
    !refreshedOverviewUiBlock.includes("WorkerCommand::Refresh") &&
    (walletAppImplBlock.match(/\bWorkerCommand::Refresh\b/gu) ?? []).length === 1 &&
    (executeWorkerCommandBlock.match(/\bWorkerCommand::Refresh\b/gu) ?? [])
      .length === 1 &&
    (sepoliaDemoUiRuntime.match(/\bWorkerCommand::Refresh\b/gu) ?? []).length ===
      2 &&
    (walletAppImplBlock.match(
      /self\.send_command\(\s*WorkerCommand::Refresh\s*,\s*PendingAction::Refresh\s*,?\s*\)/gu,
    ) ?? []).length === 1 &&
    (sepoliaDemoUiRuntime.match(/\.\s*refresh\s*\(\s*\)/gu) ?? []).length ===
      5 &&
    !/(?:(?:\bSelf|\bWalletApp)|<(?:Self|WalletApp)>)::refresh\b/u.test(
      sepoliaDemoUiRuntime,
    ) &&
    customTokenPanelBlock.includes("token_rows_warning") &&
    customTokenPanelBlock.includes(
      "목록이 비어 있어도 저장 토큰이 없다는 뜻이 아닙니다",
    ) &&
    customTokenPanelBlock.includes(
      '"현재 안전하게 표시할 수 있는 저장 토큰 행이 없습니다."',
    ),
  "Sepolia selected-overview UI must remain exactly-once, non-looping, exact-response-bound, and honest about unobserved token rows",
);
requireInvariant(
  rootReadme.includes("### 선택 계정 개요 조회 경계") &&
    rootReadme.includes("ERC-20 최대 3개만 확인합니다") &&
    rootReadme.includes("체인 identity 확인 subcall은 한 작업 안에서 최대") &&
    rootReadme.includes("개요 작업 자체를 자동으로 다시 등록하거나 timer/polling") &&
    rootReadme.includes("빈 목록을") &&
    rootReadme.includes("단일 Sepolia RPC에 노출합니다") &&
    sepoliaArchitectureDoc.includes(
      "### Sepolia demo selected-overview hydration boundary",
    ) &&
    sepoliaArchitectureDoc.includes("With `N <= 3`") &&
    sepoliaDemoRpcProduction.includes("const VERIFY_ATTEMPTS: usize = 3") &&
    verifySepoliaBlock.includes("for attempt in 0..VERIFY_ATTEMPTS") &&
    verifySepoliaBlock.includes("attempt + 1 < VERIFY_ATTEMPTS") &&
    verifySepoliaBlock.includes("is_retryable_verification_error(error)") &&
    verifySepoliaBlock.includes("std::thread::sleep(VERIFY_RETRY_DELAY)") &&
    sepoliaArchitectureDoc.includes("exactly `5 + 11N` RPC") &&
    sepoliaArchitectureDoc.includes("`13 + 19N`") &&
    sepoliaArchitectureDoc.includes("at most 70 calls when `N = 3`") &&
    sepoliaArchitectureDoc.includes(
      "identity subcall retains its bounded three-attempt retry",
    ) &&
    sepoliaArchitectureDoc.includes(
      "automatic re-enqueue of the overview request",
    ) &&
    /A\s+chain or balance RPC failure returns a category-only Partial result with\s+ETH/u.test(
      sepoliaArchitectureDoc,
    ) &&
    /An individual token RPC failure marks only that token\s+Unavailable/u.test(
      sepoliaArchitectureDoc,
    ) &&
    /The observation\s+lease never creates/u.test(sepoliaArchitectureDoc) &&
    sepoliaArchitectureDoc.includes(
      "Final Sepolia verification discards every earlier network value",
    ) &&
    sepoliaArchitectureDoc.includes("single fixed TLS RPC"),
  "Sepolia selected-overview docs must retain bounded cost, non-mutating observation, and fixed-RPC privacy/trust disclosure",
);
for (const requiredOverviewTest of [
  "selected_overview_treats_witnessed_missing_store_as_authenticated_empty",
  "selected_overview_accepts_pre_lock_store_without_creating_a_sentinel",
  "selected_overview_queries_exact_first_three_and_defers_every_tail_row",
  "selected_overview_network_failures_are_partial_and_never_restore_a_local_zero",
  "selected_overview_final_chain_failure_discards_every_observed_value",
  "selected_overview_revocation_stops_before_final_or_next_rpc_and_clears_cache",
  "selected_overview_contention_is_non_mutating_partial_but_local_faults_are_fatal",
  "selected_overview_authenticated_activity_drift_is_fatal_and_never_installs_balance",
  "overview_dto_rejects_noncanonical_balances_tokens_status_and_legacy_rows",
  "overview_reducer_installs_only_exact_bound_data_and_locks_on_forgery",
  "overview_partial_preserves_same_owner_rows_warns_persistently_and_stays_unlocked",
  "overview_partial_with_loaded_rows_is_nonfatal_and_uses_exact_unknown_marker",
  "unlock_switch_triggers_are_exactly_once_generated_is_offline_and_manual_uses_overview",
  "stale_epoch_overview_is_dropped_and_backend_err_scrubs_and_locks",
]) {
  requireInvariant(
    sepoliaDemoBackend.includes(requiredOverviewTest) ||
      sepoliaDemoUi.includes(requiredOverviewTest),
    `Sepolia selected-overview regression evidence missing: ${requiredOverviewTest}`,
  );
}
requireInvariant(
  preparePendingAccountBlock.includes("self.attribute_pending_sender") &&
    preparePendingAccountBlock.includes("lease.read_record()") &&
    retryPendingAccountBlock.includes("self.verify_frozen_pending(&mut prepared, permit)") &&
    retryPendingAccountBlock.includes("prepared.raw_transaction.as_slice()") &&
    retryPendingAccountBlock.includes("prepared.lease.delete_exact") &&
    pendingLeaseBlock.includes("file: File") &&
    sepoliaDemoBackendProduction.includes("FILE_SHARE_MODE(0)") &&
    sepoliaDemoBackendProduction.includes("SetFileInformationByHandle") &&
    sepoliaDemoBackendProduction.includes("#[cfg(not(windows))]") &&
    sepoliaDemoBackendProduction.includes("not production evidence") &&
    rootReadme.includes("비-Windows 빌드 경로는") &&
    rootReadme.includes("릴리스 경로로 지원하지 않습니다") &&
    recoverPendingSenderBlock.includes("fields = [empty; 12]") &&
    recoverPendingSenderBlock.includes("rpc::SEPOLIA_CHAIN_ID") &&
    recoverPendingSenderBlock.includes("HALF_CURVE_ORDER") &&
    recoverPendingSenderBlock.includes("recover_ecdsa") &&
    sepoliaDemoUiProduction.includes("같은 서명 거래 다시 제출 — 2초 동안 누르기"),
  "Sepolia pending retry must recover a canonical bounded sender, freeze exact bytes under an exact-object lease, disclose it, and require a separate hold",
);

const preparedTransferBlock = rustItemBlock(
  sepoliaDemoBackendProduction,
  /(?:^|\n)enum PreparedTransfer\s*\{/u,
);
const prepareSavedErc20Block = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "prepare_saved_erc20_transfer_inner",
);
const confirmSavedErc20Block = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "confirm_saved_erc20_transfer",
);
const signSavedErc20Block = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "sign_erc20_type_two",
);
const retryPendingBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "retry_pending_with_permit",
);
requireInvariant(
  preparedTransferBlock.includes("Native(PreparedNativeTransfer)") &&
    preparedTransferBlock.includes("SavedErc20(PreparedErc20Transfer)") &&
    prepareSavedErc20Block.includes("permit: &SessionPermit<'_>") &&
    prepareSavedErc20Block.includes("load_token_store(&context)") &&
    prepareSavedErc20Block.includes("verify_token_store_baseline(") &&
    (prepareSavedErc20Block.match(/inspect_token_with_permit\(/gu) ?? []).length === 2 &&
    prepareSavedErc20Block.indexOf("estimate_erc20_transfer_gas(") <
      prepareSavedErc20Block.indexOf("erc20_transfer_preflight(") &&
    confirmSavedErc20Block.includes("permit: &SessionPermit<'_>") &&
    (confirmSavedErc20Block.match(/verify_token_store_baseline\(/gu) ?? []).length === 2 &&
    (confirmSavedErc20Block.match(/inspect_token_with_permit\(/gu) ?? []).length === 2 &&
    confirmSavedErc20Block.indexOf("estimate_erc20_transfer_gas(") <
      confirmSavedErc20Block.indexOf("erc20_transfer_preflight(") &&
    signSavedErc20Block.includes("erc20::transfer_call_data") &&
    signSavedErc20Block.includes("rlp_bytes(&contract)") &&
    signSavedErc20Block.includes("rlp_word(Word::ZERO)") &&
    signSavedErc20Block.includes("rlp_list(&[])") &&
    !/\bcalldata\s*:/u.test(signSavedErc20Block),
  "saved ERC-20 must stay distinct, authenticated, bookended, estimate-before-exact-preflight, and internally calldata-bound",
);
requireInvariant(
  retryPendingBlock.includes("self.verify_frozen_pending(&mut prepared, permit)") &&
    retryPendingBlock.includes("prepared.raw_transaction.as_slice()") &&
    retryPendingBlock.includes("prepared.lease.delete_exact") &&
    retryPendingBlock.includes("guarded_broadcast(") &&
    !/(?:pending_nonce|fee_quote|latest_base_fee|estimate_erc20|sign_erc20|account_private_key)/u.test(
      retryPendingBlock,
    ) &&
    sepoliaDemoUiProduction.includes("let CustomTokenState::Verified") &&
    sepoliaDemoUiProduction.includes("clear_transfer_amount_after_asset_change(") &&
    sepoliaDemoUiProduction.includes("zeroize_custom_token_snapshots(&mut self.custom_tokens)") &&
    sepoliaDemoUiProduction.includes("확인하고 전송 — 2초 동안 누르기"),
  "saved ERC-20 UI/retry path lost verified-only selection, shared hold, stale scrub, or exact-byte no-resign recovery",
);

// Sepolia durable transaction-activity invariants (demo-only). The activity
// sidecar is v2-derived, bounded, and committed before an exact pending object
// may be deleted. Refresh remains explicit and per-row.
const activityLeaseBlock = rustItemBlock(
  sepoliaDemoBackendProduction,
  /(?:^|\n)struct ActivityMutationLease<'a>\s*\{/u,
);
const activityLeaseImplBlock = rustItemBlock(
  sepoliaDemoBackendProduction,
  /(?:^|\n)impl<'a> ActivityMutationLease<'a>\s*\{/u,
);
const tokenLeaseImplBlock = rustItemBlock(
  sepoliaDemoBackendProduction,
  /(?:^|\n)impl<'a> TokenMutationLease<'a>\s*\{/u,
);
const newV2SidecarLeaseBlock = rustItemBlock(
  sepoliaDemoBackendProduction,
  /(?:^|\n)struct NewV2SidecarNamespaceLease<'a>\s*\{/u,
);
const newV2SidecarLeaseImplBlock = rustItemBlock(
  sepoliaDemoBackendProduction,
  /(?:^|\n)impl<'a> NewV2SidecarNamespaceLease<'a>\s*\{/u,
);
const durableNamespaceParentBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "open_or_create_durable_namespace_parent",
);
const activityContextBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "activity_context",
);
const loadActivityStoreBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "load_activity_store",
);
const persistActivityStoreBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "persist_activity_store",
);
const commitSubmittedActivityBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "commit_submitted_activity",
);
const readActivityStoreBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "read_activity_store_file",
);
const writeActivityStoreBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "write_atomic_activity_store",
);
const migrateLegacyActivityBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "migrate_legacy",
);
const refreshActivityBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "refresh_activity_inner",
);
const observeActivityBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "observe_activity",
);
const observedPendingBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "pending_transaction_is_observed",
);
const canonicalObservedTransactionBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "canonical_observed_type_two_bytes",
);
const liveRpcImplBlock = rustItemBlock(
  sepoliaDemoBackendProduction,
  /(?:^|\n)impl RpcAccess for LiveRpc\s*\{/u,
);
const legacyMigrationLeaseImplBlock = rustItemBlock(
  sepoliaDemoBackendProduction,
  /(?:^|\n)impl LegacyVaultMigrationLease\s*\{/u,
);
const createdV2MigrationLeaseImplBlock = rustItemBlock(
  sepoliaDemoBackendProduction,
  /(?:^|\n)impl CreatedV2VaultMigrationLease\s*\{/u,
);
const createdV2MigrationLeaseDropBlock = rustItemBlock(
  sepoliaDemoBackendProduction,
  /(?:^|\n)impl Drop for CreatedV2VaultMigrationLease\s*\{/u,
);
const accountSelectedEventBlock = rustItemBlock(
  sepoliaDemoUiProduction,
  /WorkerEvent::AccountSelected\(result\)\s*=>\s*match result\s*\{/u,
);
const refreshedEventBlock = rustItemBlock(
  sepoliaDemoUiProduction,
  /WorkerEvent::Refreshed\(result\)\s*=>\s*match result\s*\{/u,
);
const activityPanelBlock = rustFunctionBlock(
  sepoliaDemoUiProduction,
  "activity_panel",
);
const pendingActionBlock = rustItemBlock(
  sepoliaDemoUiProduction,
  /(?:^|\n)enum PendingAction\s*\{/u,
);
const workerCommandBlock = rustItemBlock(
  sepoliaDemoUiProduction,
  /(?:^|\n)enum WorkerCommand\s*\{/u,
);
const walletBackendTraitBlock = rustItemBlock(
  sepoliaDemoUiProduction,
  /(?:^|\n)pub trait WalletBackend\s*:\s*Send\s*\+\s*'static\s*\{/u,
);
const activityRefreshOriginBlock = rustItemBlock(
  sepoliaDemoUiProduction,
  /(?:^|\n)enum ActivityRefreshOrigin\s*\{/u,
);
const activityRefreshTargetBlock = rustItemBlock(
  sepoliaDemoUiProduction,
  /(?:^|\n)struct ActivityRefreshTarget\s*\{/u,
);
const activityRefreshTargetDropBlock = rustItemBlock(
  sepoliaDemoUiProduction,
  /(?:^|\n)impl Drop for ActivityRefreshTarget\s*\{/u,
);
const activityRefreshBatchBlock = rustItemBlock(
  sepoliaDemoUiProduction,
  /(?:^|\n)struct ActivityRefreshBatch\s*\{/u,
);
const activityRefreshBatchImplBlock = rustItemBlock(
  sepoliaDemoUiProduction,
  /(?:^|\n)impl ActivityRefreshBatch\s*\{/u,
);
const activityRefreshBatchDropBlock = rustItemBlock(
  sepoliaDemoUiProduction,
  /(?:^|\n)impl Drop for ActivityRefreshBatch\s*\{/u,
);
const clearActivityRefreshStateBlock = rustFunctionBlock(
  walletAppImplBlock,
  "clear_activity_refresh_state",
);
const activityBatchWaitMatchesBlock = rustFunctionBlock(
  walletAppImplBlock,
  "activity_refresh_batch_wait_matches_current",
);
const startActivityBatchBlock = rustFunctionBlock(
  walletAppImplBlock,
  "start_activity_refresh_batch_at",
);
const driveActivityBatchBlock = rustFunctionBlock(
  walletAppImplBlock,
  "drive_activity_refresh_batch",
);
const stopActivityBatchErrorBlock = rustFunctionBlock(
  walletAppImplBlock,
  "stop_activity_refresh_batch_with_error",
);
const stopActivityBatchUserBlock = rustFunctionBlock(
  walletAppImplBlock,
  "stop_activity_refresh_batch_by_user",
);
const selectAccountActivityBatchBlock = rustFunctionBlock(
  walletAppImplBlock,
  "select_account",
);
const applyWorkerEventAtBlock = rustFunctionBlock(
  walletAppImplBlock,
  "apply_worker_event_at",
);
const activityRefreshedUiStart = applyWorkerEventAtBlock.lastIndexOf(
  "WorkerEvent::ActivityRefreshed {",
);
const activityRefreshedUiEnd = applyWorkerEventAtBlock.indexOf(
  "WorkerEvent::CustomTokenAdded",
  activityRefreshedUiStart,
);
const activityRefreshedUiBlock =
  activityRefreshedUiStart >= 0 && activityRefreshedUiEnd > activityRefreshedUiStart
    ? applyWorkerEventAtBlock.slice(activityRefreshedUiStart, activityRefreshedUiEnd)
    : "";
const walletEframeAppBlock = rustItemBlock(
  sepoliaDemoUiProduction,
  /(?:^|\n)impl eframe::App for WalletApp\s*\{/u,
);
const headlessSmokeBlock = rustFunctionBlock(
  sepoliaDemoUiProduction,
  "run_headless_smoke",
);
const activityBatchCandidateBlock = rustFunctionBlock(
  sepoliaDemoUiProduction,
  "activity_is_batch_candidate",
);
requireInvariant(
  sepoliaDemoActivityStore.includes("pub(crate) const ACTIVITY_CAPACITY: usize = 64") &&
    sepoliaDemoActivityStore.includes("pub(crate) const ACTIVITY_FILE_BYTES") &&
    sepoliaDemoActivityStore.includes("pub(crate) enum ActivityStatus") &&
    sepoliaDemoActivityStore.includes("DroppedCandidate") &&
    sepoliaDemoActivityStore.includes("ReplacementSuspected") &&
    sepoliaDemoActivityStore.includes("pub(crate) fn ensure_nonce_available(") &&
    sepoliaDemoActivityStore.includes("pub(crate) fn can_upsert(") &&
    sepoliaDemoActivityStore.includes("pub(crate) fn upsert_submitted(") &&
    sepoliaDemoActivityStore.includes("pub(crate) fn transition(") &&
    sepoliaDemoActivityStore.includes("ActivityStoreError::NonceConflict"),
  "Sepolia activity codec lost its fixed capacity, closed states, transition API, or nonce-slot conflict invariant",
);
requireInvariant(
  activityContextBlock.includes("UnlockedWallet::V2(opened)") &&
    activityContextBlock.includes("ActivityRequiresV2") &&
    activityContextBlock.includes("opened.derive_activity_store_key()") &&
    !/(?:private_key|mnemonic|LegacyV1)/u.test(activityContextBlock) &&
    loadActivityStoreBlock.includes("ActivityStore::open(") &&
    loadActivityStoreBlock.includes("wallet.account_address(entry.identity().account_index())?") &&
    loadActivityStoreBlock.includes("*entry.identity().sender()") &&
    loadActivityStoreBlock.includes("ActivityIdentityMismatch"),
  "Sepolia activity context must remain v2-key-derived and every authenticated row must bind sender to account 0/1",
);
requireInvariant(
  activityLeaseBlock.includes("_process_guard: MutexGuard") &&
    activityLeaseBlock.includes("activity_store_path: PathBuf") &&
    activityLeaseBlock.includes("_lock_file: File") &&
    activityLeaseBlock.includes("_parent_directory: DurableParentDirectory") &&
    activityLeaseImplBlock.includes("ACTIVITY_STORE_PROCESS_LOCK") &&
    activityLeaseImplBlock.includes("ActivityMutationBlocked") &&
    activityLeaseImplBlock.includes(".share_mode(0)") &&
    activityLeaseImplBlock.includes("FILE_FLAG_OPEN_REPARSE_POINT") &&
    activityLeaseImplBlock.includes("!metadata.file_type().is_file()") &&
    activityLeaseImplBlock.includes("FILE_ATTRIBUTE_REPARSE_POINT") &&
    activityLeaseImplBlock.includes("activity_store_temporary_path(activity_store_path)") &&
    activityLeaseImplBlock.includes("reconcile_orphan_activity_temporary") &&
    activityLeaseImplBlock.includes("parent_directory") &&
    activityLeaseImplBlock.includes(".flush()"),
  "Sepolia activity mutations must retain the process lock, persistent Windows no-share sibling, and exact parent directory",
);
requireInvariant(
  tokenLeaseImplBlock.includes("TOKEN_STORE_PROCESS_LOCK") &&
    tokenLeaseImplBlock.includes(".share_mode(0)") &&
    tokenLeaseImplBlock.includes("FILE_FLAG_OPEN_REPARSE_POINT") &&
    tokenLeaseImplBlock.includes("token_store_temporary_path(token_store_path)") &&
    tokenLeaseImplBlock.includes("reconcile_orphan_token_temporary") &&
    newV2SidecarLeaseBlock.indexOf("_token_lease: TokenMutationLease") <
      newV2SidecarLeaseBlock.indexOf("_activity_lease: ActivityMutationLease") &&
    newV2SidecarLeaseImplBlock.indexOf("TokenMutationLease::acquire") <
      newV2SidecarLeaseImplBlock.indexOf("ActivityMutationLease::acquire") &&
    newV2SidecarLeaseImplBlock.includes("lease.verify_absent()?") &&
    newV2SidecarLeaseImplBlock.includes("read_token_store_file") &&
    newV2SidecarLeaseImplBlock.includes("read_activity_store_file") &&
    durableNamespaceParentBlock.includes("for component in [application_root, parent]") &&
    durableNamespaceParentBlock.includes("DurableParentDirectory::open(trusted_base)") &&
    durableNamespaceParentBlock.includes("DurableParentDirectory::open(component)") &&
    durableNamespaceParentBlock.includes("created.flush()?") &&
    durableNamespaceParentBlock.includes("current_directory.flush()?"),
  "Sepolia new-v2 namespace must reconcile both fixed temps, acquire token before activity, and durably pin every fixed parent level",
);
requireInvariant(
  readActivityStoreBlock.includes("fs::symlink_metadata(path)") &&
    readActivityStoreBlock.includes("ACTIVITY_FILE_BYTES") &&
    readActivityStoreBlock.includes("!metadata.file_type().is_file()") &&
    readActivityStoreBlock.includes("FILE_ATTRIBUTE_REPARSE_POINT") &&
    writeActivityStoreBlock.includes("fs::symlink_metadata(path)") &&
    writeActivityStoreBlock.includes(
      "activity_lease: &ActivityMutationLease<'_>",
    ) &&
    writeActivityStoreBlock.includes("activity_lease.activity_store_path != path") &&
    writeActivityStoreBlock.includes(".create_new(true)") &&
    writeActivityStoreBlock.includes("file.sync_all()") &&
    writeActivityStoreBlock.includes("verify_exact_activity_store_readback(&temporary, bytes)") &&
    writeActivityStoreBlock.includes("atomic_replace_activity_store(&temporary, path)") &&
    writeActivityStoreBlock.includes("parent_directory") &&
    writeActivityStoreBlock.includes(".flush()") &&
    persistActivityStoreBlock.includes("current.as_deref() != baseline.bytes.as_deref()") &&
    persistActivityStoreBlock.includes(
      "activity_lease: &ActivityMutationLease<'_>",
    ) &&
    /write_atomic_activity_store\(\s*activity_lease,\s*&self\.activity_store_path/u.test(
      persistActivityStoreBlock,
    ) &&
    commitSubmittedActivityBlock.includes(
      "activity_lease: &ActivityMutationLease<'_>",
    ) &&
    commitSubmittedActivityBlock.includes("self.persist_activity_store(") &&
    commitSubmittedActivityBlock.includes("activity_lease,") &&
    persistActivityStoreBlock.includes("reopened.generation() != baseline.generation") &&
    persistActivityStoreBlock.indexOf("store.seal(&context.key)") <
      persistActivityStoreBlock.indexOf("write_atomic_activity_store(") &&
    persistActivityStoreBlock.indexOf("write_atomic_activity_store(") <
      persistActivityStoreBlock.indexOf("verify_exact_activity_store_readback(") &&
    persistActivityStoreBlock.indexOf("verify_exact_activity_store_readback(") <
      persistActivityStoreBlock.lastIndexOf("ActivityStore::open(") &&
    persistActivityStoreBlock.includes("entry.identity() != expected_identity"),
  "Sepolia activity persistence lost nonregular/reparse rejection, same-dir exclusive replace, CAS, flush, or authenticated exact readback",
);
const nativeActivityLeaseIndex = confirmAccountBlock.indexOf(
  "ActivityMutationLease::acquire",
);
const nativeActivityLoadIndex = confirmAccountBlock.indexOf("load_activity_store(");
const nativeCapacityIndex = confirmAccountBlock.indexOf(
  "entries().len() >= ACTIVITY_CAPACITY",
);
const nativeNonceIndex = confirmAccountBlock.indexOf("ensure_nonce_available(");
const nativeSignIndex = confirmAccountBlock.indexOf("self.sign_attempts += 1");
const nativePendingIndex = confirmAccountBlock.indexOf("write_new_pending(");
const nativeSendIndex = confirmAccountBlock.indexOf("guarded_broadcast(");
const nativeCommitIndex = confirmAccountBlock.indexOf("commit_submitted_activity(");
const nativeDeleteIndex = confirmAccountBlock.indexOf("pending_lease.delete_exact(");
const erc20ActivityLeaseIndex = confirmSavedErc20Block.indexOf(
  "ActivityMutationLease::acquire",
);
const erc20ActivityLoadIndex = confirmSavedErc20Block.indexOf("load_activity_store(");
const erc20CapacityIndex = confirmSavedErc20Block.indexOf(
  "entries().len() >= ACTIVITY_CAPACITY",
);
const erc20NonceIndex = confirmSavedErc20Block.indexOf("ensure_nonce_available(");
const erc20SignIndex = confirmSavedErc20Block.indexOf("self.sign_attempts += 1");
const erc20PendingIndex = confirmSavedErc20Block.indexOf("write_new_pending(");
const erc20SendIndex = confirmSavedErc20Block.indexOf("guarded_broadcast(");
const erc20CommitIndex = confirmSavedErc20Block.indexOf("commit_submitted_activity(");
const erc20DeleteIndex = confirmSavedErc20Block.indexOf("pending_lease.delete_exact(");
requireInvariant(
  [
    nativeActivityLeaseIndex,
    nativeActivityLoadIndex,
    nativeCapacityIndex,
    nativeNonceIndex,
    nativeSignIndex,
    nativePendingIndex,
    nativeSendIndex,
    nativeCommitIndex,
    nativeDeleteIndex,
  ].every((index) => index >= 0) &&
    nativeActivityLeaseIndex < nativeActivityLoadIndex &&
    nativeActivityLoadIndex < nativeCapacityIndex &&
    nativeCapacityIndex < nativeNonceIndex &&
    nativeNonceIndex < nativeSignIndex &&
    nativeSignIndex < nativePendingIndex &&
    nativePendingIndex < nativeSendIndex &&
    nativeSendIndex < nativeCommitIndex &&
    nativeCommitIndex < nativeDeleteIndex &&
    [
      erc20ActivityLeaseIndex,
      erc20ActivityLoadIndex,
      erc20CapacityIndex,
      erc20NonceIndex,
      erc20SignIndex,
      erc20PendingIndex,
      erc20SendIndex,
      erc20CommitIndex,
      erc20DeleteIndex,
    ].every((index) => index >= 0) &&
    erc20ActivityLeaseIndex < erc20ActivityLoadIndex &&
    erc20ActivityLoadIndex < erc20CapacityIndex &&
    erc20CapacityIndex < erc20NonceIndex &&
    erc20NonceIndex < erc20SignIndex &&
    erc20SignIndex < erc20PendingIndex &&
    erc20PendingIndex < erc20SendIndex &&
    erc20SendIndex < erc20CommitIndex &&
    erc20CommitIndex < erc20DeleteIndex,
  "Sepolia native/ERC-20 send must reserve capacity and nonce before signing, then durably commit activity before exact pending deletion",
);
requireInvariant(
  retryPendingBlock.indexOf("ActivityMutationLease::acquire") <
      retryPendingBlock.indexOf("load_activity_store(") &&
    retryPendingBlock.indexOf("load_activity_store(") <
      retryPendingBlock.indexOf("can_upsert(&identity)") &&
    retryPendingBlock.indexOf("can_upsert(&identity)") <
      retryPendingBlock.indexOf("pending_transaction_is_observed(") &&
    retryPendingBlock.indexOf("pending_transaction_is_observed(") <
      retryPendingBlock.indexOf("guarded_broadcast(") &&
    /find\(identity\.transaction_hash\(\)\)[\s\S]*?delete_exact[\s\S]*?broadcast_performed:\s*false/u.test(
      retryPendingBlock,
    ) &&
    /pending_transaction_is_observed[\s\S]*?commit_submitted_activity[\s\S]*?delete_exact[\s\S]*?broadcast_performed:\s*false/u.test(
      retryPendingBlock,
    ) &&
    /guarded_broadcast[\s\S]*?commit_submitted_activity[\s\S]*?verify_frozen_pending[\s\S]*?delete_exact/u.test(
      retryPendingBlock,
    ) &&
    observedPendingBlock.indexOf("activity_head()") <
      observedPendingBlock.indexOf("activity_transaction(") &&
    observedPendingBlock.indexOf("activity_transaction(") <
      observedPendingBlock.lastIndexOf("activity_head()") &&
    observedPendingBlock.includes("activity_transaction_matches_identity") &&
    observedPendingBlock.includes("None => Ok(false)"),
  "Sepolia retry must reserve the exact identity, observe before its sole resend, and commit activity before cleanup",
);
requireInvariant(
  sepoliaDemoRpcProduction.includes("pub y_parity: u8") &&
    sepoliaDemoRpcProduction.includes("pub r: Quantity256") &&
    sepoliaDemoRpcProduction.includes("pub s: Quantity256") &&
    (sepoliaDemoBackendProduction.match(/\.transaction_by_hash\(/gu) ?? []).length === 1 &&
    liveRpcImplBlock.includes(".transaction_by_hash(") &&
    liveRpcImplBlock.includes("y_parity: transaction.y_parity") &&
    liveRpcImplBlock.includes("r: Word::from_be_bytes") &&
    liveRpcImplBlock.includes("s: Word::from_be_bytes") &&
    liveRpcImplBlock.includes("canonical_observed_type_two_bytes(&transaction)") &&
    canonicalObservedTransactionBlock.includes("transaction.y_parity > 1") &&
    canonicalObservedTransactionBlock.includes("transaction.r.is_zero()") &&
    canonicalObservedTransactionBlock.includes("transaction.s.is_zero()") &&
    canonicalObservedTransactionBlock.includes("rpc::SEPOLIA_CHAIN_ID") &&
    canonicalObservedTransactionBlock.includes("rlp_list(&[])") &&
    canonicalObservedTransactionBlock.includes("MAX_PENDING_RAW_BYTES") &&
    canonicalObservedTransactionBlock.includes("keccak32(raw.as_slice()) != transaction.hash") &&
    canonicalObservedTransactionBlock.includes("recover_signed_type_two_sender(raw.as_slice())") &&
    observedPendingBlock.includes("expected_raw: &[u8]") &&
    observedPendingBlock.includes("canonical_observed_type_two_bytes(&transaction)?") &&
    observedPendingBlock.includes("canonical.as_slice() != expected_raw"),
  "Sepolia raw transaction observations must have one reviewed RPC consumer and locally prove canonical hash, low-S sender recovery, and pending byte identity",
);
requireInvariant(
  migrateLegacyActivityBlock.includes("NewV2SidecarNamespaceLease::acquire(") &&
    migrateLegacyActivityBlock.includes("PendingFileLease::open(&self.pending_path)") &&
    migrateLegacyActivityBlock.includes("recover_signed_type_two_sender(") &&
    migrateLegacyActivityBlock.includes("recovered != legacy_address") &&
    migrateLegacyActivityBlock.includes("DecodedPendingTransfer::Native") &&
    (migrateLegacyActivityBlock.match(/verify_pending_lease\(/gu) ?? []).length >= 3 &&
    migrateLegacyActivityBlock.includes("else if self.pending_broadcast_exists()") &&
    migrateLegacyActivityBlock.includes("LegacyVaultMigrationLease::open(&self.vault_path)") &&
    migrateLegacyActivityBlock.includes("CreatedV2VaultMigrationLease::create(") &&
    migrateLegacyActivityBlock.indexOf("CreatedV2VaultMigrationLease::create(") <
      migrateLegacyActivityBlock.indexOf("sidecar_namespace_lease.verify_absent()?") &&
    migrateLegacyActivityBlock.indexOf("sidecar_namespace_lease.verify_absent()?") <
      migrateLegacyActivityBlock.indexOf("persisted_v2_lease.install_exact(") &&
    migrateLegacyActivityBlock.indexOf("persisted_v2_lease.install_exact(") <
      migrateLegacyActivityBlock.lastIndexOf("verify_pending_lease(") &&
    migrateLegacyActivityBlock.lastIndexOf("verify_pending_lease(") <
      migrateLegacyActivityBlock.indexOf("persisted_v2_lease.mark_committed()?") &&
    migrateLegacyActivityBlock.indexOf("persisted_v2_lease.mark_committed()?") <
      migrateLegacyActivityBlock.indexOf("legacy_lease.delete_exact(&self.vault_path)") &&
    migrateLegacyActivityBlock.indexOf("legacy_lease.delete_exact(&self.vault_path)") <
      migrateLegacyActivityBlock.indexOf("self.unlocked = Some(UnlockedWallet::V2(opened))") &&
    migrateLegacyActivityBlock.indexOf("self.snapshot_or_lock()") <
      migrateLegacyActivityBlock.indexOf("drop(persisted_v2_lease)") &&
    migrateLegacyActivityBlock.indexOf("drop(persisted_v2_lease)") <
      migrateLegacyActivityBlock.indexOf("drop(legacy_lease)") &&
    legacyMigrationLeaseImplBlock.includes("FILE_SHARE_MODE(0)") &&
    legacyMigrationLeaseImplBlock.includes("FILE_FLAG_OPEN_REPARSE_POINT") &&
    legacyMigrationLeaseImplBlock.includes("SetFileInformationByHandle(") &&
    legacyMigrationLeaseImplBlock.includes("FileDispositionInfo") &&
    createdV2MigrationLeaseImplBlock.includes("vault_v2_migration_temporary_path(path)") &&
    createdV2MigrationLeaseImplBlock.includes("reconcile_orphan_v2_migration_temporary") &&
    createdV2MigrationLeaseImplBlock.includes(".create_new(true)") &&
    createdV2MigrationLeaseImplBlock.includes(".share_mode(0)") &&
    createdV2MigrationLeaseImplBlock.includes("FileRenameInfo") &&
    createdV2MigrationLeaseImplBlock.includes("ReplaceIfExists = false") &&
    createdV2MigrationLeaseImplBlock.includes("self.parent_directory.flush()?") &&
    createdV2MigrationLeaseImplBlock.includes("self.committed = true") &&
    createdV2MigrationLeaseDropBlock.includes("let _ = self.abort()") &&
    migrateLegacyActivityBlock.includes(
      "self.prepared_pending_retry = prepared_pending_retry",
    ) &&
    !/(?:guarded_broadcast|send_raw_transaction|write_new_file|remove_legacy_vault)/u.test(
      migrateLegacyActivityBlock,
    ),
  "Sepolia legacy migration must pin exact v1/pending/v2 objects, install the authenticated migrating handle before commit, and delete only the held v1 handle",
);
requireInvariant(
  refreshActivityBlock.includes("ActivityMutationLease::acquire") &&
    refreshActivityBlock.includes("entry.identity().account_index() != self.selected_account_index") &&
    refreshActivityBlock.includes("account_address(self.selected_account_index)?") &&
    refreshActivityBlock.includes("self.observe_activity(entry, permit)?") &&
    refreshActivityBlock.includes(".transition(&hash, next_status, next_observations)") &&
    observeActivityBlock.indexOf("activity_head()") <
      observeActivityBlock.indexOf("activity_transaction(") &&
    observeActivityBlock.indexOf("activity_transaction(") <
      observeActivityBlock.indexOf("activity_receipt(") &&
    observeActivityBlock.indexOf("activity_receipt(") <
      observeActivityBlock.indexOf("latest_nonce(") &&
    observeActivityBlock.indexOf("latest_nonce(") <
      observeActivityBlock.lastIndexOf("activity_head()") &&
    observeActivityBlock.includes("head_before != head_after") &&
    observeActivityBlock.includes("activity_transaction_matches_identity") &&
    observeActivityBlock.includes("activity_receipt_matches_identity") &&
    observeActivityBlock.includes("transaction.transaction_index != Some(receipt.transaction_index)") &&
    observeActivityBlock.includes("former_reorg_proven") &&
    observeActivityBlock.includes("record_present(head_before.number)") &&
    observeActivityBlock.includes("record_missing(head_before.number)") &&
    observeActivityBlock.includes("observations.dropped_candidate_ready()") &&
    observeActivityBlock.includes("ActivityStatus::ReplacementSuspected") &&
    observeActivityBlock.includes("entry.status()"),
  "Sepolia activity refresh must stay manual-row scoped, stable-head bookended, immutable/tx-index exact, and fail closed on ambiguous reorg evidence",
);
requireInvariant(
  sepoliaDemoUiProduction.includes(
    "const ACTIVITY_BATCH_DELAY: Duration = Duration::from_secs(2)",
  ) &&
    sepoliaDemoUiProduction.includes("const MAX_ACTIVITY_BATCH_ROWS: usize = 64") &&
    pendingActionBlock.includes("RefreshActivityBatchWait") &&
    activityRefreshOriginBlock.includes("ManualRow") &&
    activityRefreshOriginBlock.includes("origin_epoch: u64") &&
    activityRefreshOriginBlock.includes("selected_account_index: u8") &&
    activityRefreshOriginBlock.includes("submission_sequence: u64") &&
    /^\s*enum ActivityRefreshOrigin\s*\{\s*ManualRow,\s*Batch\s*\{\s*origin_epoch:\s*u64,\s*selected_account_index:\s*u8,\s*submission_sequence:\s*u64,?\s*\},?\s*\}$/u.test(
      activityRefreshOriginBlock,
    ) &&
    activityRefreshTargetBlock.includes("transaction_hash: Zeroizing<String>") &&
    activityRefreshTargetBlock.includes("origin: ActivityRefreshOrigin") &&
    /^\s*struct ActivityRefreshTarget\s*\{\s*transaction_hash:\s*Zeroizing<String>,\s*origin:\s*ActivityRefreshOrigin,?\s*\}$/u.test(
      activityRefreshTargetBlock,
    ) &&
    !/#\[derive\([^\]]*(?:Clone|Copy|Debug|Serialize)[^\]]*\)\]\s*struct ActivityRefreshTarget/u.test(
      sepoliaDemoUiProduction,
    ) &&
    activityRefreshTargetDropBlock.includes("self.transaction_hash.zeroize()") &&
    activityRefreshTargetDropBlock.includes("*origin_epoch = 0") &&
    activityRefreshTargetDropBlock.includes("*selected_account_index = 0") &&
    activityRefreshTargetDropBlock.includes("*submission_sequence = 0") &&
    activityRefreshBatchBlock.includes("origin_epoch: u64") &&
    activityRefreshBatchBlock.includes("selected_account_index: u8") &&
    activityRefreshBatchBlock.includes("remaining_sequences: VecDeque<u64>") &&
    activityRefreshBatchBlock.includes("in_flight_sequence: Option<u64>") &&
    activityRefreshBatchBlock.includes("completed: usize") &&
    activityRefreshBatchBlock.includes("total: usize") &&
    activityRefreshBatchBlock.includes("next_dispatch_at: Option<Instant>") &&
    /^\s*struct ActivityRefreshBatch\s*\{\s*origin_epoch:\s*u64,\s*selected_account_index:\s*u8,\s*remaining_sequences:\s*VecDeque<u64>,\s*in_flight_sequence:\s*Option<u64>,\s*completed:\s*usize,\s*total:\s*usize,\s*next_dispatch_at:\s*Option<Instant>,?\s*\}$/u.test(
      activityRefreshBatchBlock,
    ) &&
    !/#\[derive\([^\]]*(?:Clone|Copy|Debug|Serialize)[^\]]*\)\]\s*struct ActivityRefreshBatch/u.test(
      sepoliaDemoUiProduction,
    ) &&
    !/(?:^|\n)\s*(?:unsafe\s+)?impl(?:\s*<[^>{}\r\n]*>)?\s+(?:Clone|Copy|Debug|fmt::Debug|(?:std|core)::fmt::Debug|Serialize|serde::Serialize)\s+for\s+(?:ActivityRefreshTarget|ActivityRefreshBatch)\b/mu.test(
      sepoliaDemoUiProduction,
    ) &&
    activityRefreshBatchImplBlock.includes("self.total != 0") &&
    activityRefreshBatchImplBlock.includes("self.total <= MAX_ACTIVITY_BATCH_ROWS") &&
    activityRefreshBatchImplBlock.includes("self.completed < self.total") &&
    activityRefreshBatchImplBlock.includes("self.completed + self.remaining_sequences.len() == self.total") &&
    activityRefreshBatchImplBlock.includes(".all(|sequence| sequence != 0)") &&
    activityRefreshBatchImplBlock.includes(".all(|(left, right)| left < right)") &&
    activityRefreshBatchImplBlock.includes(
      "match (self.in_flight_sequence, self.next_dispatch_at)",
    ) &&
    activityRefreshBatchImplBlock.includes("(Some(in_flight), None)") &&
    activityRefreshBatchImplBlock.includes("self.remaining_sequences.front().copied() == Some(in_flight)") &&
    activityRefreshBatchImplBlock.includes("(None, Some(_)) => true") &&
    activityRefreshBatchImplBlock.includes("(Some(_), Some(_)) | (None, None) => false") &&
    activityRefreshBatchImplBlock.includes("self.origin_epoch == origin_epoch") &&
    activityRefreshBatchImplBlock.includes(
      "self.selected_account_index == selected_account_index",
    ) &&
    activityRefreshBatchImplBlock.includes(
      "self.in_flight_sequence == Some(submission_sequence)",
    ) &&
    activityRefreshBatchImplBlock.includes(
      "self.remaining_sequences.front().copied() == Some(submission_sequence)",
    ) &&
    activityRefreshBatchImplBlock.includes("fn scrub(&mut self)") &&
    activityRefreshBatchImplBlock.includes("self.remaining_sequences.clear()") &&
    activityRefreshBatchDropBlock.includes("self.scrub()") &&
    walletAppBlock.includes("activity_refresh_target: Option<ActivityRefreshTarget>") &&
    walletAppBlock.includes("activity_refresh_batch: Option<ActivityRefreshBatch>"),
  "Sepolia activity batch state must remain bounded, move-only, sequence-only, and explicitly scrubbed",
);
requireInvariant(
  activityBatchCandidateBlock.includes("ActivityStatusSnapshot::Submitted") &&
    activityBatchCandidateBlock.includes("ActivityStatusSnapshot::Pending") &&
    activityBatchCandidateBlock.includes("ActivityStatusSnapshot::Reorged(_)") &&
    activityBatchCandidateBlock.includes("ActivityStatusSnapshot::DroppedCandidate") &&
    activityBatchCandidateBlock.includes("ActivityStatusSnapshot::ReplacementSuspected") &&
    (activityBatchCandidateBlock.match(/ActivityStatusSnapshot::/gu) ?? []).length === 5 &&
    !activityBatchCandidateBlock.includes("ActivityStatusSnapshot::Included") &&
    /^\s*const fn activity_is_batch_candidate\(status:\s*&ActivityStatusSnapshot\)\s*->\s*bool\s*\{\s*matches!\(\s*status,\s*ActivityStatusSnapshot::Submitted\s*\|\s*ActivityStatusSnapshot::Pending\s*\|\s*ActivityStatusSnapshot::Reorged\(_\)\s*\|\s*ActivityStatusSnapshot::DroppedCandidate\s*\|\s*ActivityStatusSnapshot::ReplacementSuspected\s*\)\s*\}\s*$/u.test(
      activityBatchCandidateBlock,
    ) &&
    startActivityBatchBlock.includes("self.require_unlocked_action()") &&
    startActivityBatchBlock.includes("self.pending.is_some()") &&
    startActivityBatchBlock.includes("self.prepared.is_some()") &&
    startActivityBatchBlock.includes("self.secret_reveal.is_some()") &&
    startActivityBatchBlock.includes("self.generated_backup.is_some()") &&
    startActivityBatchBlock.includes("snapshot.pending_broadcast.is_some()") &&
    startActivityBatchBlock.includes("snapshot.is_well_formed()") &&
    startActivityBatchBlock.includes("snapshot.selected_account_index") &&
    startActivityBatchBlock.includes("activity_is_batch_candidate(&row.status)") &&
    startActivityBatchBlock.includes(".map(|row| row.submission_sequence)") &&
    startActivityBatchBlock.includes("sequences.sort_unstable()") &&
    startActivityBatchBlock.includes("sequences.truncate(MAX_ACTIVITY_BATCH_ROWS)") &&
    startActivityBatchBlock.includes("next_dispatch_at: Some(now)") &&
    startActivityBatchBlock.includes("PendingAction::RefreshActivityBatchWait") &&
    startActivityBatchBlock.includes("self.drive_activity_refresh_batch(now)") &&
    (sepoliaDemoUiRuntime.match(/self\.start_activity_refresh_batch_at\s*\(/gu) ?? [])
      .length === 1 &&
    (sepoliaDemoUiRuntime.match(/\bstart_activity_refresh_batch_at\b/gu) ?? [])
      .length === 2 &&
    (sepoliaDemoUiRuntime.match(/ActivityRefreshBatch\s*\{\s*origin_epoch:/gu) ?? [])
      .length === 2 &&
    (sepoliaDemoUiRuntime.match(/activity_refresh_batch\s*=\s*Some\s*\(/gu) ?? [])
      .length === 1 &&
    /start_batch\s*=\s*ui[\s\S]*?\.clicked\(\);[\s\S]*?if start_batch\s*\{\s*self\.start_activity_refresh_batch_at\(Instant::now\(\)\)/u.test(
      activityPanelBlock,
    ) &&
    driveActivityBatchBlock.includes("self.pending != Some(PendingAction::RefreshActivityBatchWait)") &&
    driveActivityBatchBlock.includes("if batch.in_flight_sequence.is_some()") &&
    driveActivityBatchBlock.includes("if now < deadline") &&
    driveActivityBatchBlock.includes("batch.remaining_sequences.front().copied()") &&
    driveActivityBatchBlock.includes("origin_epoch == self.session_epoch") &&
    driveActivityBatchBlock.includes("self.session_phase == SessionPhase::Unlocked") &&
    driveActivityBatchBlock.includes("snapshot.selected_account_index != selected_account_index") &&
    driveActivityBatchBlock.includes("row.sender_address == selected.address") &&
    driveActivityBatchBlock.includes("activity_is_batch_candidate(&row.status)") &&
    driveActivityBatchBlock.includes("transaction_hash: Zeroizing::new(transaction_hash.clone())") &&
    driveActivityBatchBlock.includes("WorkerCommand::RefreshActivity { transaction_hash }") &&
    driveActivityBatchBlock.includes("PendingAction::RefreshActivity") &&
    driveActivityBatchBlock.indexOf("batch.in_flight_sequence = Some(submission_sequence)") >= 0 &&
    driveActivityBatchBlock.indexOf("batch.in_flight_sequence = Some(submission_sequence)") <
      driveActivityBatchBlock.indexOf("self.activity_refresh_target = Some(ActivityRefreshTarget") &&
    driveActivityBatchBlock.indexOf("self.activity_refresh_target = Some(ActivityRefreshTarget") <
      driveActivityBatchBlock.indexOf("self.send_command(") &&
    !/(?:thread::sleep|std::thread::sleep|last_activity_at)/u.test(
      `${startActivityBatchBlock}\n${driveActivityBatchBlock}`,
    ) &&
    (sepoliaDemoUiRuntime.match(/WorkerCommand::RefreshActivity\s*\{/gu) ?? []).length === 3 &&
    /RefreshActivity\s*\{\s*transaction_hash:\s*String,?\s*\}/u.test(
      workerCommandBlock,
    ) &&
    (workerCommandBlock.match(/\b[A-Za-z_]\w*Activity\w*\b/gu) ?? []).length === 1 &&
    walletBackendTraitBlock.includes(
      "fn refresh_activity(",
    ) &&
    (walletBackendTraitBlock.match(/\bfn\s+\w*activity\w*\s*\(/gu) ?? []).length === 1 &&
    !/(?:refresh_activity_batch|activity_batch)/u.test(
      `${sepoliaDemoBackendProduction}\n${sepoliaDemoRpcProduction}\n${sepoliaDemoActivityStore}`,
    ) &&
    (sepoliaDemoUiRuntime.match(/self\.drive_activity_refresh_batch\s*\(/gu) ?? [])
      .length === 2,
  "Sepolia activity batch must be explicit-click only, freeze the five unresolved states, and reuse exactly one existing row request at a time",
);
const activityUpdateFirstLock = walletEframeAppBlock.indexOf(
  "self.observe_automatic_lock(context, now)",
);
const activityUpdateEvents = walletEframeAppBlock.indexOf("self.process_events_at(now)");
const activityUpdateSecondLock = walletEframeAppBlock.lastIndexOf(
  "self.observe_automatic_lock(context, now)",
);
const activityUpdateDrive = walletEframeAppBlock.indexOf(
  "self.drive_activity_refresh_batch(now)",
);
requireInvariant(
  [
    activityUpdateFirstLock,
    activityUpdateEvents,
    activityUpdateSecondLock,
    activityUpdateDrive,
  ].every((index) => index >= 0) &&
    activityUpdateFirstLock < activityUpdateEvents &&
    activityUpdateEvents < activityUpdateSecondLock &&
    activityUpdateSecondLock < activityUpdateDrive &&
    walletEframeAppBlock.includes("context.request_repaint_after(") &&
    walletEframeAppBlock.includes("deadline.saturating_duration_since(now)") &&
    activityRefreshedUiBlock.includes("completed_action == Some(PendingAction::RefreshActivity)") &&
    activityRefreshedUiBlock.includes("batch.matches_in_flight(") &&
    activityRefreshedUiBlock.includes("batch.origin_epoch == self.session_epoch") &&
    activityRefreshedUiBlock.includes("snapshot.selected_account_index != selected_account_index") &&
    activityRefreshedUiBlock.includes("prior.sender_address == selected.address") &&
    activityRefreshedUiBlock.includes("same_activity_identity(prior, &refreshed)") &&
    activityRefreshedUiBlock.includes("now.checked_add(ACTIVITY_BATCH_DELAY)") &&
    activityRefreshedUiBlock.includes("PendingAction::RefreshActivityBatchWait") &&
    activityRefreshedUiBlock.includes("let category = safe_error(error)") &&
    activityRefreshedUiBlock.includes("self.stop_activity_refresh_batch_with_error(category.as_str())") &&
    (activityRefreshedUiBlock.match(/batch\.matches_in_flight\s*\(/gu) ?? []).length === 2 &&
    /Err\(error\),[\s\S]*?ActivityRefreshOrigin::Batch[\s\S]*?request_matches[\s\S]*?batch\.matches_in_flight\([\s\S]*?origin_epoch[\s\S]*?selected_account_index[\s\S]*?submission_sequence[\s\S]*?batch\.origin_epoch\s*==\s*self\.session_epoch[\s\S]*?let category = safe_error\(error\)/u.test(
      activityRefreshedUiBlock,
    ) &&
    clearActivityRefreshStateBlock.includes("self.activity_refresh_target = None") &&
    clearActivityRefreshStateBlock.includes("self.activity_refresh_batch = None") &&
    clearActivityRefreshStateBlock.includes("PendingAction::RefreshActivityBatchWait") &&
    stopActivityBatchErrorBlock.includes("zeroize_optional_string(&mut self.notice)") &&
    stopActivityBatchErrorBlock.includes("현재 행의 내구 상태") &&
    stopActivityBatchErrorBlock.includes("이후 대기 행은 요청하지 않았습니다") &&
    stopActivityBatchUserBlock.includes("self.pending != Some(PendingAction::RefreshActivityBatchWait)") &&
    activityBatchWaitMatchesBlock.includes(
      "self.pending == Some(PendingAction::RefreshActivityBatchWait)",
    ) &&
    activityBatchWaitMatchesBlock.includes("self.session_phase == SessionPhase::Unlocked") &&
    activityBatchWaitMatchesBlock.includes("batch.is_well_formed()") &&
    activityBatchWaitMatchesBlock.includes("batch.origin_epoch == self.session_epoch") &&
    activityBatchWaitMatchesBlock.includes("batch.in_flight_sequence.is_none()") &&
    activityBatchWaitMatchesBlock.includes("snapshot.is_well_formed()") &&
    activityBatchWaitMatchesBlock.includes(
      "snapshot.selected_account_index == batch.selected_account_index",
    ) &&
    /let selection_allowed\s*=\s*\(self\.pending\.is_none\(\)\s*\|\|\s*self\.activity_refresh_batch_wait_matches_current\(\)\)\s*&&/u.test(
      accountPanelBlock,
    ) &&
    accountPanelBlock.includes("ui.add_enabled_ui(selection_allowed") &&
    accountPanelBlock.includes("if requested_index != snapshot.selected_account_index") &&
    accountPanelBlock.includes("self.select_account(requested_index)") &&
    [
      selectAccountActivityBatchBlock.indexOf(
        "self.activity_refresh_batch_wait_matches_current()",
      ),
      selectAccountActivityBatchBlock.indexOf("self.stop_activity_refresh_batch_by_user()"),
      selectAccountActivityBatchBlock.indexOf("if self.pending.is_some()"),
      selectAccountActivityBatchBlock.indexOf("WorkerCommand::SelectAccount"),
    ].every((index) => index >= 0) &&
    selectAccountActivityBatchBlock.indexOf("self.activity_refresh_batch_wait_matches_current()") <
      selectAccountActivityBatchBlock.indexOf("self.stop_activity_refresh_batch_by_user()") &&
    selectAccountActivityBatchBlock.indexOf("self.stop_activity_refresh_batch_by_user()") <
      selectAccountActivityBatchBlock.indexOf("if self.pending.is_some()") &&
    selectAccountActivityBatchBlock.indexOf("if self.pending.is_some()") <
      selectAccountActivityBatchBlock.indexOf("WorkerCommand::SelectAccount") &&
    !/(?:thread::sleep|std::thread::sleep|last_activity_at)/u.test(
      `${activityRefreshedUiBlock}\n${stopActivityBatchErrorBlock}\n${stopActivityBatchUserBlock}\n${clearActivityRefreshStateBlock}`,
    ),
  "Sepolia activity batch must bind every response, schedule from response time, let lock/account change preempt dispatch, and scrub on every stop",
);
requireInvariant(
  activityPanelBlock.includes("이 행만 Sepolia에서 새로고침") &&
    activityPanelBlock.includes("고정된 Sepolia RPC") &&
    activityPanelBlock.includes("자동 새로고침, 자동 재시작, nonce 자동 재사용은 하지 않습니다") &&
    activityPanelBlock.includes("Submitted/Pending/Reorged/DroppedCandidate/ReplacementSuspected") &&
    activityPanelBlock.includes("최대 64개 고정") &&
    activityPanelBlock.includes("Included 행은 포함하지 않으며") &&
    activityPanelBlock.includes("선택한 발신 주소와 최대 64개 거래 해시, 요청 간격") &&
    activityPanelBlock.includes("한 번에 한 행만 요청") &&
    activityPanelBlock.includes("최소 2초") &&
    activityPanelBlock.includes("현재 조회 행의 내구 상태는 응답 전까지 알 수 없으며") &&
    activityPanelBlock.includes("다음 행 조회 전 순차 작업 중지") &&
    activityPanelBlock.includes("외부 단조 앵커") &&
    activityPanelBlock.includes("저장된 high-water보다 낮으면") &&
    activityPanelBlock.includes("전체 거래 해시") &&
    activityPanelBlock.includes("신뢰하지 않는 과거 컨트랙트 라벨") &&
    (sepoliaDemoUiProduction.match(/self\.refresh_activity_row\(/gu) ?? []).length === 1 &&
    sepoliaDemoUiProduction.includes("WorkerCommand::RefreshActivity { transaction_hash }") &&
    sepoliaDemoUiProduction.includes("same_activity_identity(prior, &refreshed)") &&
    sepoliaDemoUiProduction.includes("zeroize_activity_snapshot") &&
    sepoliaDemoUi.includes(
      "fn activity_batch_dispatch_deadline_is_inclusive_exactly_once_and_sleep_free()",
    ) &&
    sepoliaDemoUi.includes(
      "fn activity_batch_freezes_sorted_unresolved_start_sequences_and_excludes_included()",
    ) &&
    sepoliaDemoUi.includes(
      "fn activity_batch_accepts_exactly_the_bounded_sixty_four_start_rows()",
    ) &&
    sepoliaDemoUi.includes(
      "fn activity_batch_due_time_row_drift_stops_and_clears_scheduled_notice()",
    ) &&
    sepoliaDemoUi.includes(
      "fn activity_refresh_origin_and_first_error_progress_are_exact()",
    ) &&
    sepoliaDemoUi.includes(
      "fn activity_batch_forged_error_origin_stops_without_attribution_or_mutation()",
    ) &&
    sepoliaDemoUi.includes(
      "fn activity_batch_immutable_identity_mismatch_stops_without_row_mutation()",
    ) &&
    sepoliaDemoUi.includes(
      "fn activity_batch_account_selector_is_enabled_only_between_requests_and_scrubs_before_select()",
    ) &&
    sepoliaDemoUi.includes(
      "fn activity_batch_focus_and_inactivity_preempt_due_dispatch()",
    ) &&
    sepoliaDemoUi.includes(
      "fn activity_batch_panel_discloses_scope_privacy_and_manual_only_controls()",
    ) &&
    headlessSmokeBlock.includes("let batch_started_at = Instant::now()") &&
    headlessSmokeBlock.includes("app.start_activity_refresh_batch_at(batch_started_at)") &&
    headlessSmokeBlock.includes("batch.total == 2") &&
    headlessSmokeBlock.includes("batch.in_flight_sequence == Some(1)") &&
    headlessSmokeBlock.includes("batch.remaining_sequences.iter().copied().eq([1, 2])") &&
    headlessSmokeBlock.includes("first_completed_at + ACTIVITY_BATCH_DELAY") &&
    headlessSmokeBlock.includes("next_deadline - Duration::from_nanos(1)") &&
    headlessSmokeBlock.includes("command_receiver.try_recv().is_ok()") &&
    headlessSmokeBlock.includes("app.drive_activity_refresh_batch(next_deadline)") &&
    headlessSmokeBlock.includes("batch.in_flight_sequence == Some(2)") &&
    headlessSmokeBlock.includes("submission_sequence: 2") &&
    headlessSmokeBlock.includes("app.activity_refresh_batch.is_some()") &&
    headlessSmokeBlock.includes("app.activity_refresh_target.is_some()") &&
    headlessSmokeBlock.includes("notice.contains(\"2/2 응답 확인·화면 반영 완료\")") &&
    headlessSmokeBlock.includes("transitions_checked: 101") &&
    headlessSmokeBlock.includes("backend_routes_checked: backend.calls.len()") &&
    sepoliaDemoUi.includes("assert_eq!(evidence.transitions_checked, 101)") &&
    sepoliaDemoUi.includes("assert_eq!(evidence.backend_routes_checked, 37)") &&
    sepoliaDemoHeadless.includes("assert_eq!(report.transitions_checked, 101)") &&
    sepoliaDemoHeadless.includes("assert_eq!(report.backend_routes_checked, 37)") &&
    sepoliaDemoHeadlessProduction.includes("ui::run_headless_smoke()") &&
    rootReadme.includes("activity-v1.bin") &&
    /현재 남아 있는\s*행만 nonce 충돌을 막습니다/u.test(rootReadme) &&
    rootReadme.includes("head가 따라잡을 때까지 새로고침을 보류합니다") &&
    rootReadme.includes("시작 시점") &&
    rootReadme.includes("submission 순서로 최대 64개 고정") &&
    rootReadme.includes("단일 행 저장 뒤 인증 readback이 실패한 오류") &&
    /at\s+most 64 start-of-run/u.test(sepoliaArchitectureDoc) &&
    sepoliaArchitectureDoc.includes("one at a time") &&
    sepoliaArchitectureDoc.includes("at least two seconds") &&
    sepoliaArchitectureDoc.includes("A failing row may already have reached durable storage"),
  "Sepolia activity UI/docs lost exact identifiers, bounded explicit sequencing, privacy disclosure, scrubbing, rollback honesty, or high-water delay disclosure",
);
requireInvariant(
  sepoliaDemoUiProduction.includes("BackendStateInvalidated") &&
    sepoliaDemoUiProduction.includes("fn invalidate_frontend_after_backend_error(") &&
    sepoliaDemoUiProduction.includes(
      "self.request_lock(LockReason::BackendStateInvalidated)",
    ) &&
    accountSelectedEventBlock.includes("invalidate_frontend_after_backend_error") &&
    refreshedEventBlock.includes("invalidate_frontend_after_backend_error") &&
    sepoliaDemoUi.includes(
      "fn account_select_or_refresh_backend_invalidation_scrubs_and_locks_frontend()",
    ) &&
    rootReadme.includes("activity-v1.tmp") &&
    rootReadme.includes("tokens-v1.tmp") &&
    rootReadme.includes("vault-v2.migrating") &&
    rootReadme.includes("HMAC/PRK context") &&
    rootReadme.includes("ZeroizeOnDrop") &&
    rootReadme.includes("격리된 Key Agent") &&
    rootReadme.includes("canonical transaction 재구성") &&
    rootReadme.includes("실제 전파·포함 여부") &&
    sepoliaArchitectureDoc.includes("token-then-activity namespaces") &&
    sepoliaArchitectureDoc.includes("exact same-directory `vault-v2.migrating` handle") &&
    sepoliaArchitectureDoc.includes("HMAC/PRK context implements neither") &&
    sepoliaArchitectureDoc.includes("single fixed TLS RPC remains a trust boundary") &&
    sepoliaArchitectureDoc.includes("local envelope self-consistency") &&
    sepoliaArchitectureDoc.includes("isolated Key Agent and a zeroizing KDF implementation"),
  "Sepolia backend-invalidated UI lock/scrub and durable-temp/memory-forensics residuals must remain explicit",
);
for (const requiredActivityTest of [
  "legacy_migration_preserves_exact_native_pending_for_v2_restart_retry",
  "legacy_migration_rejects_foreign_signer_and_valid_erc20_before_v2_write",
  "accepted_broadcast_then_activity_commit_failure_retries_by_observation_without_resend",
  "committed_activity_with_leftover_pending_cleans_exact_file_without_network",
  "retry_nonce_collision_preserves_exact_pending_before_node_lookup_or_resend",
  "occupied_activity_nonce_slot_rejects_before_sign_pending_or_send",
  "occupied_activity_nonce_slot_rejects_saved_erc20_before_sign_pending_or_send",
  "full_activity_store_rejects_native_and_saved_erc20_before_signing",
  "authenticated_activity_sender_must_bind_to_vault_account_index",
  "manual_activity_refresh_reduces_missing_inclusion_reorg_and_reappearance_safely",
  "observed_type_two_requires_canonical_hash_signature_and_recovered_sender",
  "account_one_erc20_restart_observes_exact_pending_without_rebroadcast",
  "activity_orphan_temp_is_reconciled_before_sign_and_nonregular_temp_fails_closed",
  "token_orphan_temp_is_reconciled_before_new_v2_or_token_mutation",
  "fresh_v2_parent_is_created_durably_and_invalid_parent_fails_before_vault_write",
  "migration_temp_crash_recovery_pins_install_and_preserves_pending_until_commit",
  "windows_migration_leases_pin_v1_temp_and_installed_v2_exact_objects",
  "windows_activity_lock_and_temp_are_exclusive_reparse_safe_and_recoverable",
  "stale_or_nonregular_sidecars_block_legacy_migration_before_vault_mutation",
  "confirm_revocation_checkpoints_bound_signing_pending_and_broadcast",
  "saved_erc20_confirm_permit_checkpoints_bound_sign_write_send_and_delete",
]) {
  requireInvariant(
    sepoliaDemoBackend.includes(`fn ${requiredActivityTest}()`),
    `Sepolia activity regression evidence missing: ${requiredActivityTest}`,
  );
}

const exactErc20PreflightBlock = rustFunctionBlock(
  sepoliaDemoRpcProduction,
  "erc20_transfer_preflight",
);
const guardedRpcSendBlock = rustFunctionBlock(
  sepoliaDemoRpcProduction,
  "send_raw_transaction",
);
const guardedPermitIndex = guardedRpcSendBlock.indexOf("if !permit.is_current()");
requireInvariant(
  exactErc20PreflightBlock.includes("value: \"0x0\"") &&
    exactErc20PreflightBlock.includes("input: encode_prefixed_hex(&calldata)") &&
    exactErc20PreflightBlock.includes("transaction_type: \"0x2\"") &&
    exactErc20PreflightBlock.includes("nonce: encode_quantity(nonce)") &&
    exactErc20PreflightBlock.includes("gas: encode_quantity(gas_limit)") &&
    exactErc20PreflightBlock.includes("access_list: &[]") &&
    !/\bdata\s*:/u.test(exactErc20PreflightBlock) &&
    !/gas_price/u.test(exactErc20PreflightBlock) &&
    guardedRpcSendBlock.includes("permit: &SessionPermit<'_>") &&
    guardedRpcSendBlock.indexOf("self.verify_sepolia()?") !== -1 &&
    guardedPermitIndex > guardedRpcSendBlock.indexOf("self.verify_sepolia()?") &&
    guardedRpcSendBlock.indexOf("RpcMethod::SendRawTransaction") > guardedPermitIndex &&
    (sepoliaDemoRpcProduction.match(/pub fn send_raw_transaction\s*\(/gu) ?? []).length === 1 &&
    !/pub fn (?:unguarded_|raw_)?broadcast/u.test(sepoliaDemoRpcProduction),
  "typed ERC-20 preflight or the sole post-reverify concrete-permit broadcast guard changed",
);

const noNetworkManifests = [
  "crates/approval-wire/Cargo.toml",
  "crates/secret-core/Cargo.toml",
  "crates/key-agent/Cargo.toml",
  "crates/approval-ui/Cargo.toml",
  "crates/secret-input-ui/Cargo.toml",
];
const networkCrates = ["reqwest", "hyper", "ureq", "curl", "tonic", "tungstenite"];
for (const manifestPath of noNetworkManifests) {
  const manifest = await text(manifestPath);
  for (const crateName of networkCrates) {
    requireInvariant(
      !hasDependency(manifest, crateName),
      `${manifestPath} must remain network-free (${crateName})`,
    );
  }
}

const extensionManifest = JSON.parse(await text("extension/manifest.json"));
requireInvariant(extensionManifest.manifest_version === 3, "extension must remain MV3");
requireInvariant(
  extensionManifest.incognito === "not_allowed",
  "incognito must be explicitly disabled",
);
requireInvariant(
  JSON.stringify([...(extensionManifest.permissions ?? [])].sort()) ===
    JSON.stringify(["nativeMessaging", "storage"]),
  "extension permission set changed",
);
requireInvariant(
  !Object.hasOwn(extensionManifest, "host_permissions"),
  "extension must not gain broad host_permissions",
);
for (const script of extensionManifest.content_scripts ?? []) {
  requireInvariant(script.all_frames === false, "content scripts must remain top-frame only");
  requireInvariant(
    JSON.stringify(script.matches) === JSON.stringify(["https://*/*"]),
    "content-script origin scope changed",
  );
}

for (const sourcePath of [
  "extension/src/background-core.js",
  "extension/src/background.js",
  "extension/src/content-core.js",
  "extension/src/content.js",
  "extension/src/provider-main.js",
  "extension/src/shared.js",
]) {
  const source = await text(sourcePath);
  for (const forbidden of [
    /\beval\s*\(/u,
    /\bnew\s+Function\s*\(/u,
    /WebAssembly\s*\.\s*(?:compile|instantiate)/u,
    /document\s*\.\s*write\s*\(/u,
  ]) {
    requireInvariant(!forbidden.test(source), `${sourcePath} contains remote-code primitive`);
  }
}

const eip712Exports = await text("crates/eip712/src/lib.rs");
for (const forbiddenExport of [
  "SchemaExceptionVerifier",
  "SchemaExceptionRequest",
  "ValidationContext",
  "DenySchemaExceptions",
]) {
  requireInvariant(
    !eip712Exports.includes(forbiddenExport),
    `EIP-712 policy injection escaped: ${forbiddenExport}`,
  );
}

const approval = await text("crates/wallet-protocol/src/approval.rs");
requireInvariant(
  /pub\(crate\)\s+lease_id\s*:/u.test(approval) && /pub\(crate\)\s+nonce\s*:/u.test(approval),
  "nonce lease fields must not be caller-constructible",
);
const approvalWireManifest = await text("crates/approval-wire/Cargo.toml");
const approvalWire = await text("crates/approval-wire/src/lib.rs");
requireInvariant(
  !/pub\s+label\s*:/u.test(approvalWire),
  "approval wire must not accept caller-provided labels",
);
requireInvariant(
  !/#\[derive\([^\]]*Debug[^\]]*\)\]\s*pub\s+struct\s+ApprovalRequest/su.test(approvalWire) &&
    /impl\s+core::fmt::Debug\s+for\s+ApprovalRequest[\s\S]*?anti_phishing_phrase[\s\S]*?\[REDACTED\]/u.test(
      approvalWire,
    ),
  "approval request Debug output must redact phrase, challenge, and display payload",
);
for (const manifestPath of [
  "crates/approval-ui/Cargo.toml",
  "crates/wallet-protocol/Cargo.toml",
  "crates/key-agent/Cargo.toml",
]) {
  requireInvariant(
    hasDependency(await text(manifestPath), "approval-wire"),
    `${manifestPath} must use the shared approval-wire codec`,
  );
}
requireInvariant(
  !hasDependency(approvalWireManifest, "wallet-model") &&
    !hasDependency(approvalWireManifest, "wallet-protocol"),
  "approval-wire must remain an independent leaf protocol crate",
);
const protocolExports = await text("crates/wallet-protocol/src/lib.rs");
requireInvariant(
  !/pub\s+use\s+approval::[\s\S]*?NonceLeaseBinding/u.test(protocolExports),
  "raw nonce lease binding must not be publicly exported",
);
const authorization = await text("crates/wallet-protocol/src/authorization.rs");
requireInvariant(
  /const\s+COMPILED_RELEASE_CHANNEL\s*:\s*ReleaseChannel\s*=\s*ReleaseChannel::PrivateCanary/u.test(
    authorization,
  ),
  "release channel must be compiled into the authorization TCB",
);
requireInvariant(
  /pub\s+fn\s+prepare_authorization\s*\(\s*(?:mut\s+)?request\s*:\s*AuthorizationRequest\s*,?\s*\)/su.test(
    authorization,
  ),
  "public authorization must not accept nonce, TTL, or release-channel policy",
);

const signer = await text("crates/secret-core/src/signing.rs");
const bip32 = await text("crates/secret-core/src/bip32.rs");
const signerProduction = withoutBottomTestModule(signer);
const bip32Production = withoutBottomTestModule(bip32);
const secretCoreProductionFiles = await rustProductionSources("crates/secret-core/src");
const secretCoreProduction = secretCoreProductionFiles
  .map((file) => `// ${file.path}\n${file.source}`)
  .join("\n");
requireInvariant(
  signer.includes("AuthorizedOperation"),
  "secret signer must require an authorization capability",
);
requireInvariant(!/pub\s+fn\s+sign_(?:hash|prehash|digest)/u.test(signer), "raw signer API exposed");

const ephemeralImpl = rustItemBlock(
  bip32Production,
  /(?:^|\n)\s*impl\s+EphemeralSecpSecret\s*\{/u,
);
const ephemeralConstructor = rustFunctionBlock(ephemeralImpl, "new");
const ephemeralAccessor = rustFunctionBlock(ephemeralImpl, "as_secret");
const rawPrivateKeyImpl = rustItemBlock(
  bip32Production,
  /(?:^|\n)\s*impl\s+RawPrivateKey\s*\{/u,
);
const rawKeyImport = rustFunctionBlock(rawPrivateKeyImpl, "import");
const ethereumAddress = rustFunctionBlock(rawPrivateKeyImpl, "ethereum_address");
const recoverableSigner = rustFunctionBlock(rawPrivateKeyImpl, "sign_recoverable_prehash");
const extendedPrivateKeyImpl = rustItemBlock(
  bip32Production,
  /(?:^|\n)\s*impl\s+ExtendedPrivateKey\s*\{/u,
);
const extendedFromSeed = rustFunctionBlock(extendedPrivateKeyImpl, "from_seed");
const deriveChild = rustFunctionBlock(extendedPrivateKeyImpl, "derive_child");
const authorizedSigner = rustFunctionBlock(signerProduction, "sign_authorized_operation");

function hasOneScopedEphemeralUse(functionBlock, consumerName) {
  const bindings = [
    ...functionBlock.matchAll(
      /\blet\s+(?<binding>[A-Za-z_]\w*)\s*=\s*EphemeralSecpSecret\s*::\s*new\s*\(\s*self\s*\)\s*\?\s*;/gu,
    ),
  ];
  if (bindings.length !== 1) {
    return false;
  }
  const binding = bindings[0].groups.binding.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  const accessorUses = functionBlock.match(
    new RegExp(`\\b${binding}\\s*\\.\\s*as_secret\\s*\\(\\s*\\)`, "gu"),
  );
  return (
    accessorUses?.length === 1 &&
    new RegExp(
      `\\b${consumerName}\\s*\\([\\s\\S]*?\\b${binding}\\s*\\.\\s*as_secret\\s*\\(\\s*\\)`,
      "u",
    ).test(functionBlock)
  );
}

const directSecretKeyConstructors = [
  ...bip32Production.matchAll(/\bSecretKey\s*::\s*(?<constructor>(?:from_[A-Za-z_]\w*|new))\s*\(/gu),
];
const ephemeralDeclaration = /(?<attributes>(?:\s*#\s*\[[^\]]*\]\s*)*)struct\s+EphemeralSecpSecret\s*\(\s*SecretKey\s*\)\s*;/u.exec(
  bip32Production,
);
const visibleSecretKeySignature =
  /(?:^|\n)\s*pub(?:\s*\([^)]*\))?\s+(?:(?:const|async|unsafe)\s+)*fn\s+[A-Za-z_]\w*\b[^{}]*\b(?:SecretKey|EphemeralSecpSecret)\b[^{}]*\{/u;
requireInvariant(
  ephemeralDeclaration !== null &&
    !/(?:^|\n)\s*pub(?:\s*\([^\r\n)]*\))?\s+struct\s+EphemeralSecpSecret\b/u.test(
      bip32Production,
    ) &&
    !/\b(?:Clone|Copy)\b/u.test(ephemeralDeclaration.groups.attributes) &&
    !/\bimpl\s+(?:Clone|Copy)\s+for\s+EphemeralSecpSecret\b/u.test(bip32Production) &&
    (bip32Production.match(/\bEphemeralSecpSecret\s*\(/gu) ?? []).length === 1 &&
    !/\bSelf\s*\(/u.test(ephemeralImpl),
  "the ephemeral secp256k1 wrapper must remain private and non-cloneable",
);
requireInvariant(
  /(?:^|\n)\s*fn\s+new\b[^;{]*->\s*Result\s*<\s*Self\s*,\s*SecretError\s*>\s*\{/u.test(
      ephemeralConstructor,
    ) &&
    /(?:^|\n)\s*(?:const\s+)?fn\s+as_secret\b[^;{]*->\s*&\s*SecretKey\s*\{/u.test(
      ephemeralAccessor,
    ) &&
    !/\bpub(?:\s*\([^\r\n)]*\))?\s+(?:const\s+)?fn\s+(?:new|as_secret)\b/u.test(
      ephemeralImpl,
    ) &&
    bip32Production.includes("impl Drop for EphemeralSecpSecret") &&
    /\bself\s*\.\s*0\s*\.\s*non_secure_erase\s*\(\s*\)\s*;/u.test(bip32Production),
  "the ephemeral secp256k1 constructor, accessor, and erasing Drop must remain private",
);
requireInvariant(
  (bip32Production.match(/\bEphemeralSecpSecret\s*::\s*new\s*\(/gu) ?? []).length === 2,
  "the ephemeral secp256k1 wrapper must be constructed at exactly two reviewed sites",
);
requireInvariant(
  hasOneScopedEphemeralUse(ethereumAddress, "PublicKey\\s*::\\s*from_secret_key"),
  "address derivation must use one scoped ephemeral secp256k1 key",
);
requireInvariant(
  hasOneScopedEphemeralUse(recoverableSigner, "sign_ecdsa_recoverable"),
  "raw signing must use one scoped ephemeral secp256k1 key",
);
requireInvariant(
  (secretCoreProduction.match(/\.\s*sign_recoverable_prehash\s*\(/gu) ?? []).length === 1 &&
    /\bself\s*\.\s*sign_recoverable_prehash\s*\(\s*signing_prehash\s*\)\s*\?/u.test(
      authorizedSigner,
    ),
  "the raw signing primitive must be called only from authorized signing",
);
requireInvariant(
  directSecretKeyConstructors.length === 5 &&
    directSecretKeyConstructors.every(
      (match) => match.groups.constructor === "from_byte_array",
    ) &&
    (ephemeralConstructor.match(/\bSecretKey\s*::\s*from_byte_array\s*\(/gu) ?? []).length === 1 &&
    (rawKeyImport.match(/\bSecretKey\s*::\s*from_byte_array\s*\(/gu) ?? []).length === 1 &&
    (extendedFromSeed.match(/\bSecretKey\s*::\s*from_byte_array\s*\(/gu) ?? []).length === 1 &&
    (deriveChild.match(/\bSecretKey\s*::\s*from_byte_array\s*\(/gu) ?? []).length === 2,
  "direct secp256k1 key reconstruction must remain at the five reviewed sites",
);
requireInvariant(
  !visibleSecretKeySignature.test(bip32Production) &&
    !/(?:^|\n)\s*(?:pub(?:\s*\([^\r\n)]*\))?\s+)?type\s+[A-Za-z_]\w*[^=;]*=\s*[^;]*\bSecretKey\b/u.test(
      bip32Production,
    ) &&
    !/\bManuallyDrop\b/u.test(secretCoreProduction) &&
    !/\bforget\b/u.test(secretCoreProduction) &&
    !bip32Production.includes("as_secp_secret") &&
    !bip32Production.includes("with_secp_secret"),
  "secp256k1 key material must not escape or bypass scoped erasure",
);

const keyAgent = await text("crates/key-agent/src/lib.rs");
const keyMaterial = await text("crates/key-agent/src/key_material.rs");
const keyAgentProductionFiles = await rustProductionSources("crates/key-agent/src");
const keyMaterialProduction = keyAgentProductionFiles.find(
  (file) => file.path === "crates/key-agent/src/key_material.rs",
)?.source;
requireInvariant(keyMaterialProduction !== undefined, "key material production source is missing");
const keyAgentProduction = keyAgentProductionFiles
  .map((file) => `// ${file.path}\n${file.source}`)
  .join("\n");
const keyAgentOutsideKeyMaterialProduction = keyAgentProductionFiles
  .filter((file) => file.path !== "crates/key-agent/src/key_material.rs")
  .map((file) => file.source)
  .join("\n");
const keyAgentSettings = await text("crates/key-agent/src/settings.rs");
const keyAgentSettingsProduction = keyAgentSettings.split(
  "\n#[cfg(test)]\nmod tests {",
)[0];
const vaultSession = await text("crates/key-agent/src/vault_session.rs");
requireInvariant(
  keyAgent.includes("pub(crate) mod vault_session;") &&
    !keyAgent.includes("pub mod vault_session;") &&
    keyAgent.includes("pub(crate) mod offline_service;"),
  "low-level vault lifecycle must remain behind the crate-private offline service",
);
requireInvariant(
  keyAgent.includes("pub(crate) mod key_material;") &&
    !keyAgent.includes("pub mod key_material;") &&
    keyMaterial.includes("pub(crate) struct VerifiedKeyBundleAnchor") &&
    keyMaterial.includes("mod sealed {") &&
    !keyMaterial.includes("pub(crate) mod sealed {") &&
    keyMaterial.includes("_verification_seal: AnchorVerificationSeal") &&
    keyMaterial.includes("enum VerifiedAnchorPredecessor") &&
    keyMaterial.includes("previous: KeyBundleAnchorCommitment") &&
    keyMaterial.includes("anchor_generation: u64") &&
    keyMaterial.includes("const ANCHOR_DOMAIN") &&
    keyMaterial.includes("envelope_anchor_digest(&encoded)?") &&
    keyMaterial.includes("verified.follows(&current.commitment)") &&
    keyMaterial.includes(
      "verified.anchor_generation > current.anchor_generation",
    ) &&
    keyMaterial.includes("pub(crate) enum KeyBundleAnchorState") &&
    keyMaterial.includes("BootstrapPending") &&
    keyMaterial.includes("RotationPending") &&
    keyMaterial.includes("pub(crate) fn open_anchored") &&
    !/pub\(crate\)\s+fn\s+open\s*[<(]/u.test(keyMaterialProduction) &&
    /impl PcpWrappingKeyIdentity \{[\s\S]*?\n\s+fn new\(/u.test(keyMaterialProduction) &&
    /impl PcpSigningKeyIdentity \{[\s\S]*?\n\s+fn new\(/u.test(keyMaterialProduction) &&
    !/impl Pcp(?:Wrapping|Signing)KeyIdentity \{[\s\S]*?\n\s+pub(?:\(crate\))?\s+fn new\(/u.test(
      keyMaterialProduction,
    ) &&
    keyMaterial.includes("RsaSpkiDerSha256V1") &&
    keyMaterial.includes("P256SpkiDerSha256V1") &&
    keyMaterial.includes("BCRYPT_RSAPUBLIC_BLOB") &&
    keyMaterial.includes("BCRYPT_ECCPUBLIC_BLOB") &&
    keyMaterial.includes("RSA3072_OAEP_SHA256_MGF1_SHA256_EMPTY_LABEL_ALGORITHM_ID") &&
    keyMaterial.includes("ECDSA_P256_SHA256_P1363_ALGORITHM_ID") &&
    keyMaterial.includes("MICROSOFT_PCP_TPM_NONEXPORTABLE_V1_PROVENANCE_ID") &&
    keyMaterial.includes("canonical_p256_p1363_signature") &&
    keyMaterial.includes("AnchorRegistryHmacKey") &&
    keyMaterial.includes("StorageMacRootKey") &&
    keyMaterial.includes("JournalAeadKey") &&
    keyMaterial.includes("LocalSettingsAeadKey") &&
    keyMaterial.includes("NonceLedgerAeadKey") &&
    keyMaterial.includes("TpmNvAuthValue") &&
    keyMaterial.includes("fill_rotated_material_slot") &&
    !/pub\(crate\)\s+(?:const\s+)?fn\s+(?:key|role_key|material)\s*\(/u.test(
      keyMaterialProduction,
    ) &&
    !/impl\s+(?:[A-Za-z_][A-Za-z0-9_]*::)*Pcp(?:OaepKeyWrapper|DigestSigner|OaepKeyUnwrapper|DigestVerifier)(?:Sealed)?\s+for/u.test(
      keyAgentProduction,
    ),
  "device key material must remain anchored, role-typed, canonical-SPKI-bound, and adapter-free",
);
for (const forbiddenPcpMarker of [
  "PcpOaepKeyWrapper",
  "PcpDigestSigner",
  "PcpOaepKeyUnwrapper",
  "PcpDigestVerifier",
  "PcpWrappingKeyIdentity",
  "PcpSigningKeyIdentity",
]) {
  requireInvariant(
    !keyAgentOutsideKeyMaterialProduction.includes(forbiddenPcpMarker),
    `PCP adapter marker ${forbiddenPcpMarker} must remain inside the reviewed key-material module`,
  );
}
const vaultCore = await text("crates/secret-core/src/vault.rs");
requireInvariant(
  keyAgent.includes("pub(crate) mod settings;") &&
    !keyAgent.includes("pub use settings::LocalAntiPhishingPhrase;") &&
    /pub\(crate\)\s+struct\s+LocalAntiPhishingPhrase\s*\(Zeroizing<String>\)\s*;/u.test(
      keyAgentSettings,
    ) &&
    !/#\[derive\([^\]]*Clone[^\]]*\)\]\s*pub(?:\(crate\))?\s+struct\s+LocalAntiPhishingPhrase/u.test(
      keyAgentSettings,
    ) &&
    !/impl\s+Clone\s+for\s+LocalAntiPhishingPhrase/u.test(keyAgentSettings) &&
    keyAgentSettings.includes(
      "trait SettingsStore: fmt::Debug + sealed::SettingsStoreSealed",
    ) &&
    keyAgentSettings.includes("struct ProtectedLocalSettings") &&
    keyAgentSettings.includes("highest_authenticated_generation") &&
    keyAgentSettings.includes("SettingsError::CommitAmbiguous") &&
    keyAgentSettings.includes("AuthenticatedSettingsSnapshot") &&
    keyAgentSettings.includes("AuthenticatedSettingsPayload::Empty") &&
    keyAgentSettings.includes("SettingsStoreIdentity") &&
    keyAgentSettings.includes("SettingsOwnerEvidence") &&
    keyAgentSettings.includes("SettingsAnchorEvidence") &&
    keyAgentSettings.includes("previous_record_digest") &&
    keyAgentSettings.includes("high_water_generation") &&
    keyAgentSettings.includes("EquivocationDetected") &&
    keyAgentSettings.includes("TrustedSettingsPresenter") &&
    keyAgentSettings.includes("PendingEnrollment") &&
    keyAgentSettings.includes("PendingRotation") &&
    !keyAgentSettingsProduction.includes("impl SettingsStore for") &&
    !keyAgentSettingsProduction.includes("impl TrustedSettingsPresenter for"),
  "anti-phishing phrase must remain an opaque Key-Agent-local setting",
);
requireInvariant(
  /pub\(crate\)\s+fn\s+prepare_approval_prompt<[\s\S]*?ProtectedLocalSettings/su.test(
    keyAgent,
  ) && !/pub\s+fn\s+prepare_approval_prompt/u.test(keyAgent),
  "approval prompt preparation must remain internal and use protected settings",
);
requireInvariant(
  /pub\(crate\)\s+struct\s+PreparedApprovalPrompt\s*\{[\s\S]*?prepared:\s*PreparedAuthorization[\s\S]*?request_hash:\s*\[u8;\s*32\][\s\S]*?settings_lease:\s*settings::LiveSettingsLease[\s\S]*?settings_binding:\s*\[u8;\s*32\]/su.test(
    keyAgent,
  ) &&
    /pub\(crate\)\s+fn\s+approve_and_sign[\s\S]*?revalidate_and_consume_approval\([\s\S]*?prepared\.authorize\(request_hash,/su.test(
      keyAgent,
    ) &&
    /pub\(super\)\s+struct\s+LiveSettingsLease\s*\{[\s\S]*?generation:\s*u64[\s\S]*?revision:\s*u64[\s\S]*?record_digest:\s*\[u8;\s*32\][\s\S]*?lease_nonce:\s*\[u8;\s*32\]/su.test(
      keyAgentSettings,
    ) &&
    !/#\[derive\([^\]]*Clone[^\]]*\)\]\s*pub\(super\)\s+struct\s+LiveSettingsLease/u.test(
      keyAgentSettings,
    ) &&
    keyAgentSettings.includes("revalidate_current_or_lock") &&
    keyAgentSettings.includes("self.active_lease.take()"),
  "signing must consume one freshly revalidated settings-bound prompt",
);
requireInvariant(
  !authorization.includes("anti_phishing_phrase"),
  "authorization protocol must not accept an injected anti-phishing phrase",
);
for (const lifecycleInvariant of [
  "VaultSessionStatus::Locked",
  "VaultSessionStatus::BackupPending",
  "VaultSessionStatus::Unlocked",
  "pub(crate) fn display_recovery",
  "pub(crate) fn confirm_backup_checked",
  "pub fn copyable_address",
  "pub(crate) fn with_signing_key_checked",
]) {
  requireInvariant(
    vaultSession.includes(lifecycleInvariant),
    `production recovery lifecycle invariant missing: ${lifecycleInvariant}`,
  );
}
requireInvariant(
  /pub\s+fn\s+copyable_address[\s\S]*?SessionState::Unlocked/su.test(vaultSession) &&
    /pub\(crate\)\s+fn\s+with_signing_key_checked[\s\S]*?SessionState::Unlocked/su.test(
      vaultSession,
    ),
  "address and signing-key access must remain gated on confirmed backup",
);
requireInvariant(
  vaultCore.includes("pub const fn new_unconfirmed") &&
    !/pub(?:\([^)]*\))?\s+(?:const\s+)?fn\s+set_backup_state\b/u.test(vaultCore) &&
    !/pub(?:\([^)]*\))?\s+(?:const\s+)?fn\s+new_with_state\b/u.test(vaultCore) &&
    vaultCore.includes("pub fn verify_and_confirm_bip39_backup") &&
    vaultCore.includes("const BACKUP_CHALLENGE_WORDS: usize = 4") &&
    vaultCore.includes("let [persisted_zero, persisted_one]") &&
    vaultCore.includes("ct_eq(answer.as_bytes())") &&
    vaultCore.includes("confirmed_first_address != persisted_zero.address") &&
    vaultCore.includes("record.passphrase_required") &&
    vaultCore.includes("!matches!(word_count, 12 | 24)") &&
    vaultCore.includes("BackupState::Unconfirmed") &&
    vaultCore.includes("BackupState::Confirmed"),
  "vault backup confirmation must remain a four-word, two-account verified one-way core transition",
);
for (const privateRecoveryType of [
  "RecoveryWordPosition",
  "RecoveryConfirmation",
  "RecoveryDisplayView",
  "RecoveryChallenge",
]) {
  requireInvariant(
    new RegExp(`pub\\(crate\\)\\s+struct\\s+${privateRecoveryType}\\b`, "u").test(
      vaultSession,
    ) &&
      !new RegExp(`pub\\s+struct\\s+${privateRecoveryType}\\b`, "u").test(vaultSession),
    `recovery capability must remain Key-Agent-internal: ${privateRecoveryType}`,
  );
}
for (const privateRecoveryMethod of ["present_recovery", "confirm_backup"]) {
  requireInvariant(
    new RegExp(`pub\\(crate\\)\\s+fn\\s+${privateRecoveryMethod}\\b`, "u").test(
      vaultSession,
    ) &&
      !new RegExp(`pub\\s+fn\\s+${privateRecoveryMethod}\\b`, "u").test(vaultSession),
    `recovery operation must remain Key-Agent-internal: ${privateRecoveryMethod}`,
  );
}
requireInvariant(
  vaultSession.includes("challenge_nonce: Option<Zeroizing<[u8; 32]>>") &&
    vaultSession.includes("pending.display_consumed") &&
    vaultSession.includes("matches_pending") &&
    vaultSession.includes("ct_eq(expected_nonce.as_ref())"),
  "recovery challenge must remain bound to one displayed live session nonce",
);
const recoveryDisplayBody =
  /pub\(crate\)\s+struct\s+RecoveryDisplayView<'a>\s*\{(?<body>[\s\S]*?)\n\}/u.exec(
    vaultSession,
  )?.groups?.body ?? "";
const recoveryChallengeBody =
  /pub\(crate\)\s+struct\s+RecoveryChallenge\s*\{(?<body>[\s\S]*?)\n\}/u.exec(
    vaultSession,
  )?.groups?.body ?? "";
requireInvariant(
  recoveryDisplayBody.includes("phrase:") &&
    recoveryDisplayBody.includes("first_address:") &&
    !recoveryDisplayBody.includes("position") &&
    recoveryChallengeBody.includes("positions:") &&
    recoveryChallengeBody.includes("binding:") &&
    !recoveryChallengeBody.includes("address") &&
    vaultSession.includes("presenter: impl FnOnce(RecoveryDisplayView<'_>)") &&
    !vaultSession.includes("presenter: impl FnOnce(RecoveryDisplayView<'_>) ->"),
  "recovery display and later confirmation challenge must remain stage-separated",
);
for (const capability of [
  "RecoveryConfirmation",
  "RecoveryDisplayView",
  "RecoveryChallenge",
]) {
  requireCustomRedactedDebug(vaultSession, capability);
}

const secretInput = await text("crates/secret-input-ui/src/lib.rs");
const recoveryProtocol = await text("crates/secret-input-ui/src/recovery.rs");
const secretBootstrap = await text("crates/secret-input-ui/src/bootstrap.rs");
const secretBootstrapWindows = await text("crates/secret-input-ui/src/bootstrap/windows.rs");
const recoveryNative = await text("crates/secret-input-ui/src/recovery_native.rs");
const secretInputMain = await text("crates/secret-input-ui/src/main.rs");
const architectureDocument = await text("docs/architecture.md");
requireInvariant(
  /pub\s+struct\s+SecretPrompt\s*\{[\s\S]*?\n\}/u.test(secretInput) &&
    !/pub\s+(?:kind|minimum_bytes|maximum_bytes|anti_phishing_phrase)\s*:/u.test(
      secretInput,
    ) &&
    secretInput.includes("pub const fn canonical_byte_bounds") &&
    secretInput.includes("!= prompt.kind.canonical_byte_bounds()"),
  "secret prompt fields and kind-specific byte policy must remain canonical",
);
requireInvariant(
  !/#\[derive\([^\]]*Debug[^\]]*\)\]\s*pub\s+enum\s+SecretOutcome/su.test(secretInput),
  "secret input result must not derive a payload-revealing Debug implementation",
);

const secretChannel = await text("crates/platform-windows/src/secret_channel.rs");
const recoveryChannel = await text(
  "crates/platform-windows/src/recovery_channel.rs",
);
const ceremonyIdImpl =
  /impl\s+RecoveryCeremonyId\s*\{(?<body>[\s\S]*?)\n\}/u.exec(recoveryProtocol)
    ?.groups?.body ?? "";
const ceremonyPublicMethods = [
  ...ceremonyIdImpl.matchAll(/\bpub\s+(?:const\s+)?fn\s+(?<name>[A-Za-z_]\w*)/gu),
].map((match) => match.groups.name);
const displayLinkBody =
  /struct\s+DisplayLink\s*\{(?<body>[\s\S]*?)\n\}/u.exec(recoveryChannel)?.groups
    ?.body ?? "";
requireInvariant(
  secretChannel.includes("fn arm_from_held_helper(") &&
    !secretChannel.includes("pub fn arm_from_held_helper(") &&
    !secretChannel.includes("pub(crate) fn arm_from_held_helper(") &&
    secretChannel.includes("pub struct VerifiedSecretInput") &&
    !/#\[derive\([^\]]*Clone[^\]]*\)\]\s*pub\s+struct\s+VerifiedSecretInput/u.test(
      secretChannel,
    ) &&
    secretChannel.includes("Accepted(Zeroizing<Vec<u8>>)") &&
    secretChannel.includes("decode_authenticated_outcome(") &&
    secretChannel.includes("&self.child_challenge"),
  "secret-input arming must remain private, one-shot, prompt-bound, and zeroizing",
);
requireInvariant(
  recoveryChannel.includes("pub(crate) fn launch_recovery_display_frontend(") &&
    recoveryChannel.includes("pub(crate) fn launch_recovery_confirm_frontend(") &&
    recoveryChannel.includes("acknowledgement: RecoveryDisplayAcknowledgement") &&
    recoveryChannel.includes("ceremony_id: RecoveryCeremonyId") &&
    displayLinkBody.includes("ceremony_id: RecoveryCeremonyId") &&
    displayLinkBody.includes("expires_at: Instant") &&
    recoveryChannel.includes("request.matches_ceremony(&display_link.ceremony_id)") &&
    recoveryChannel.includes(
      "clamped_deadline_capped(requested_duration, display_link.expires_at)",
    ) &&
    recoveryChannel.includes("requested_expiry.min(original_display_expiry)") &&
    /terminate_and_wait\(expires_at\)[\s\S]*?terminated\?;[\s\S]*?RecoveryDisplayAcknowledgement/u.test(
      recoveryChannel,
    ) &&
    recoveryChannel.includes(".terminate_and_wait(expires_at)") &&
    recoveryChannel.includes("Duration::from_mins(2)") &&
    recoveryChannel.includes("encode_recovery_parent_hello(") &&
    recoveryChannel.includes("decode_recovery_child_hello(") &&
    recoveryChannel.includes("encode_recovery_parent_finish(") &&
    recoveryChannel.includes("decode_authenticated_recovery_outcome(") &&
    recoveryChannel.includes("Confirmed(Box<VerifiedRecoveryConfirmation>)") &&
    recoveryChannel.includes("[Zeroizing<String>; 4]") &&
    !/#\[derive\([^\]]*Clone[^\]]*\)\]\s*pub\(crate\)\s+struct\s+(?:RecoveryDisplayAcknowledgement|VerifiedRecoveryConfirmation)/u.test(
      recoveryChannel,
    ),
  "parent recovery channel must remain ceremony-bound, original-deadline-capped, stage-separated, ack-gated, nonce-bound, terminated, and zeroizing",
);
requireInvariant(
  /#\[allow\(dead_code\)\]\s*mod\s+recovery_channel;/u.test(
    await text("crates/platform-windows/src/lib.rs"),
  ) &&
    !/pub\s+(?:mod|use)[^;\n]*recovery_channel/u.test(
      await text("crates/platform-windows/src/lib.rs"),
    ),
  "recovery launch facade must remain crate-private until settings-lease provenance exists",
);
requireInvariant(
  /impl\s+fmt::Debug\s+for\s+SecretOutcome[\s\S]*?Accepted\(_\)[\s\S]*?\[REDACTED\]/u.test(secretInput),
  "accepted secret input Debug output must be explicitly redacted",
);
requireInvariant(
  !/#\[derive\([^\]]*Debug[^\]]*\)\]\s*pub\s+struct\s+SecretPrompt/su.test(secretInput) &&
    /impl\s+fmt::Debug\s+for\s+SecretPrompt[\s\S]*?anti_phishing_phrase[\s\S]*?\[REDACTED\]/u.test(
      secretInput,
    ),
  "secret prompt Debug output must redact the local anti-phishing phrase",
);
requireInvariant(
  /pub\s+fn\s+write_outcome[\s\S]*?secret\.len\(\)\s*>\s*MAX_SECRET_BYTES/su.test(
    secretInput,
  ),
  "secret helper response writer must enforce the global 1024-byte bound",
);
requireInvariant(
  /pub\s+fn\s+encode_prompt[\s\S]*?validate_prompt\(prompt\)/su.test(secretInput) &&
    /pub\s+fn\s+decode_outcome[\s\S]*?Zeroizing<Vec<u8>>[\s\S]*?MAX_RESPONSE_BYTES[\s\S]*?copy_within[\s\S]*?zeroize\(\)/su.test(
      secretInput,
    ) &&
    /pub\s+fn\s+read_outcome[\s\S]*?Vec::with_capacity\(MAX_RESPONSE_BYTES \+ 2\)[\s\S]*?take\(maximum \+ 1\)[\s\S]*?read_to_end/su.test(
      secretInput,
    ),
  "secret parent codec must validate prompts and consume one capped, zeroizing response through EOF",
);
requireInvariant(
  recoveryProtocol.includes(
    "pub struct RecoveryCeremonyId([u8; RECOVERY_CEREMONY_ID_BYTES]);",
  ) &&
    ceremonyPublicMethods.join(",") === "generate,matches" &&
    ceremonyIdImpl.includes("getrandom::fill(&mut bytes)") &&
    ceremonyIdImpl.includes("self.0.ct_eq(&other.0)") &&
    ceremonyIdImpl.includes("fn from_bytes(") &&
    !ceremonyIdImpl.includes("pub fn from_bytes(") &&
    !ceremonyIdImpl.includes("pub(crate) fn from_bytes(") &&
    !/impl\s+(?:Clone|Copy)\s+for\s+RecoveryCeremonyId/u.test(
      recoveryProtocol,
    ) &&
    !/#\[derive\([^\]]*(?:Clone|Copy)[^\]]*\)\]\s*pub\s+struct\s+RecoveryCeremonyId/u.test(
      recoveryProtocol,
    ) &&
    (recoveryProtocol.match(
      /output\.extend_from_slice\(&request\.ceremony_id\.0\);/gu,
    )?.length ?? 0) === 2 &&
    /struct\s+RecoveryDisplayRequest\s*\{[^}]*ceremony_id:\s*RecoveryCeremonyId/u.test(
      recoveryProtocol,
    ) &&
    /struct\s+RecoveryConfirmRequest\s*\{[^}]*ceremony_id:\s*RecoveryCeremonyId/u.test(
      recoveryProtocol,
    ) &&
    recoveryProtocol.includes(
      "ceremony_id_bits_are_canonical_request_data_and_zero_is_rejected",
    ),
  "recovery ceremony IDs must remain OS-random, nonzero, opaque, non-cloneable, constant-time compared, and encoded in both stages",
);
requireInvariant(
  secretInput.includes("pub mod recovery;") &&
    recoveryProtocol.includes("enum RecoveryRequest") &&
    recoveryProtocol.includes("Display(RecoveryDisplayRequest)") &&
    recoveryProtocol.includes("Confirm(RecoveryConfirmRequest)") &&
    /struct\s+RecoveryDisplayRequest\s*\{[^}]*first_address:[^}]*mnemonic:[^}]*\}/u.test(
      recoveryProtocol,
    ) &&
    !/struct\s+RecoveryDisplayRequest\s*\{[^}]*positions:/u.test(recoveryProtocol) &&
    /struct\s+RecoveryConfirmRequest\s*\{[^}]*positions:\s*\[u8;\s*CHALLENGE_WORDS\][^}]*\}/u.test(
      recoveryProtocol,
    ) &&
    !/struct\s+RecoveryConfirmRequest\s*\{[^}]*(?:mnemonic|expected_words|first_address):/u.test(
      recoveryProtocol,
    ) &&
    recoveryProtocol.includes("PASSPHRASE_NOT_REQUIRED") &&
    recoveryProtocol.includes("if position <= previous") &&
    recoveryProtocol.includes("decode_outcome(") &&
    recoveryProtocol.includes("Zeroizing<Vec<u8>>"),
  "recovery display and answer collection must remain separate, bounded, and secret-zeroizing",
);
requireInvariant(
  secretBootstrap.includes("enum AuthenticatedRequestSession") &&
    secretBootstrap.includes("Secret(AuthenticatedSession)") &&
    secretBootstrap.includes("Recovery(AuthenticatedRecoverySession)") &&
    secretBootstrap.includes("RECOVERY_DISPLAY_PARENT_HELLO_MAGIC") &&
    secretBootstrap.includes("RECOVERY_CONFIRM_PARENT_HELLO_MAGIC") &&
    secretBootstrap.includes("RECOVERY_DISPLAY_CHILD_TRANSCRIPT_DOMAIN") &&
    secretBootstrap.includes("RECOVERY_CONFIRM_CHILD_TRANSCRIPT_DOMAIN") &&
    secretBootstrap.includes("RECOVERY_DISPLAY_PARENT_FINISH_MAGIC") &&
    secretBootstrap.includes("RECOVERY_CONFIRM_PARENT_FINISH_MAGIC") &&
    secretBootstrap.includes("RECOVERY_DISPLAY_OUTCOME_MAGIC") &&
    secretBootstrap.includes("RECOVERY_CONFIRM_OUTCOME_MAGIC") &&
    secretBootstrap.includes("pub fn authenticate_inherited_request") &&
    /verify_parent_handles[\s\S]*?decode_recovery_parent_finish/u.test(secretBootstrapWindows),
  "recovery stages must use distinct authenticated domains and verify the exact parent before request decode",
);
requireInvariant(
  secretBootstrapWindows.includes(
    "const COMPILED_PARENT_POLICY: Option<ParentTrustPolicy> = None;",
  ) &&
    architectureDocument.includes(
      "### Secret Input parent activation invariant (STOP-SHIP)",
    ) &&
    architectureDocument.includes(
      "opens the exact Key Agent artifact without write or delete",
    ) &&
    architectureDocument.includes(
      "exact launched PID and process",
    ) &&
    architectureDocument.includes(
      "both inherited request/response pipe peers",
    ) &&
    architectureDocument.includes(
      "Path equality from `QueryFullProcessImageNameW`",
    ),
  "compiled Secret Input parent policy must remain disabled until a supervisor-held immutable artifact, exact launched process, and channel capability are one reviewed proof",
);
requireInvariant(
  /fn\s+create_base_window[\s\S]*?SetWindowDisplayAffinity\(window, WDA_EXCLUDEFROMCAPTURE\)[\s\S]*?GetWindowDisplayAffinity[\s\S]*?Ok\(\(surface,/u.test(
    recoveryNative,
  ) &&
    /fn\s+create_display[\s\S]*?create_base_window[\s\S]*?attach_secret_state[\s\S]*?arm_and_show/u.test(
      recoveryNative,
    ) &&
    /fn\s+create_confirm[\s\S]*?create_base_window[\s\S]*?attach_secret_state[\s\S]*?arm_and_show/u.test(
      recoveryNative,
    ) &&
    !recoveryNative.includes('w!("EDIT")') &&
    !recoveryNative.includes("GetWindowText") &&
    !recoveryNative.includes("ALLOW_SECRET_CONTROL_ACCESS") &&
    recoveryNative.includes("GetWindowDisplayAffinity") &&
    recoveryNative.includes("ACKNOWLEDGEMENT_HOLD_MS: u64 = 2_000") &&
    recoveryNative.includes("WM_KILLFOCUS") &&
    recoveryNative.includes("WM_ACTIVATEAPP") &&
    recoveryNative.includes("SESSION_TIMEOUT_MS") &&
    recoveryNative.includes("WM_COPY") &&
    recoveryNative.includes("WM_PASTE") &&
    recoveryNative.includes("WM_CONTEXTMENU") &&
    recoveryNative.includes("WM_DROPFILES") &&
    recoveryNative.includes("WM_GETOBJECT") &&
    recoveryNative.includes("WM_PRINTCLIENT") &&
    recoveryNative.includes("SecureAsciiBuffer") &&
    recoveryNative.includes("Zeroizing<Vec<u8>>") &&
    recoveryNative.includes("DrawTextW") &&
    recoveryNative.includes("is_blocked_secret_message") &&
    recoveryNative.includes("headless_confirmation_state_collects_only_owned_zeroizing_buffers"),
  "native recovery UI must install capture resistance before attaching custom-drawn zeroizing state, require a hold, and expose no OS-owned secret text control",
);
requireInvariant(
  secretInputMain.includes("AuthenticatedRequestSession::Secret(session)") &&
    secretInputMain.includes("AuthenticatedRequestSession::Recovery(session)") &&
    secretInputMain.includes("present_authenticated_recovery") &&
    secretInputMain.includes("write_authenticated_recovery_outcome"),
  "secret-input runtime must dispatch only authenticated typed capabilities",
);
for (const recoverySecret of [
  "RecoveryDisplayRequest",
  "RecoveryConfirmationInput",
  "RecoveryOutcome",
]) {
  requireInvariant(
    !new RegExp(
      `#\\[derive\\([^\\]]*(?:Clone|Debug)[^\\]]*\\)\\]\\s*pub\\s+(?:struct|enum)\\s+${recoverySecret}`,
      "u",
    ).test(recoveryProtocol),
    `recovery secret type must not derive Clone/Debug: ${recoverySecret}`,
  );
}

const durableSigner = await text("crates/key-agent/src/durable.rs");
for (const invariant of [
  "CandidateLifecycle::ApprovalPending",
  "record_signing_intent",
  "record_signed_transaction",
  "CandidateLifecycle::Broadcasting",
  "CandidateLifecycle::BroadcastUnknown",
  "CandidateLifecycle::Submitted",
  "pub struct BroadcastLease",
  "pub fn begin_broadcast",
  "pub fn submit",
  "ReloadRequired",
  "XChaCha20Poly1305",
]) {
  requireInvariant(durableSigner.includes(invariant), `durable signer invariant missing: ${invariant}`);
}
const signedArtifactBlock =
  keyAgent.match(/pub\s+struct\s+SignedTransactionArtifact\s*\{[\s\S]*?\n\}/u)?.[0] ?? "";
requireInvariant(
  !keyAgent.includes("pub trait SignedCandidateJournal") &&
    signedArtifactBlock.length > 0 &&
    !signedArtifactBlock.includes("signed_bytes"),
  "signed transaction bytes must remain private to the durable broadcast lease",
);

const brokerTransport = await text("crates/broker/src/transport.rs");
for (const ownedField of [
  "context: BrowserContext",
  "params: Value",
  "method: ProviderMethod",
  "target: BrokerTarget",
  "request_id: [u8; 16]",
  "request_sequence: u64",
]) {
  requireInvariant(
    brokerTransport.includes(ownedField),
    `authorized broker dispatch must retain ${ownedField}`,
  );
}
requireInvariant(
  brokerTransport.includes('impl fmt::Debug for AuthorizedDispatch') &&
    brokerTransport.includes('[VALIDATED BROWSER CONTEXT]') &&
    brokerTransport.includes('[BOUNDED JSON REDACTED]'),
  "authorized broker dispatch Debug output must redact context and parameters",
);

const windowsStorage = await text("crates/platform-windows/src/storage/sys.rs");
const windowsStorageFacade = await text("crates/platform-windows/src/storage.rs");
const anchorRegistry = await text("crates/platform-windows/src/anchor_registry.rs");
const keyAgentDurable = await text("crates/key-agent/src/durable.rs");
requireInvariant(
  !/(?:use\s+[^;]*\bREPLACEFILE_WRITE_THROUGH\b|[|,]\s*REPLACEFILE_WRITE_THROUGH\b)/su.test(
    windowsStorage,
  ),
  "unsupported ReplaceFileW write-through flag must not be used",
);
requireInvariant(
  windowsStorageFacade.includes("pub(crate) trait RollbackAnchor") &&
    !/(?:^|\n)pub\s+trait\s+RollbackAnchor\b/u.test(windowsStorageFacade) &&
    windowsStorageFacade.includes(
      "pub use crate::anchor_registry::BoundRollbackAnchor;",
    ) &&
    /pub\s+struct\s+WindowsGenerationStore\s*\{/u.test(windowsStorageFacade) &&
    !/pub\s+struct\s+WindowsGenerationStore\s*</u.test(windowsStorageFacade) &&
    windowsStorageFacade.includes(
      "StoreCore<sys::WindowsBackend, BoundRollbackAnchor>",
    ) &&
    windowsStorageFacade.includes("anchor: BoundRollbackAnchor") &&
    anchorRegistry.includes("pub struct BoundRollbackAnchor") &&
    !/#\[derive\([^\]]*Clone[^\]]*\)\]\s*pub\s+struct\s+BoundRollbackAnchor/u.test(
      anchorRegistry,
    ) &&
    !/impl\s+BoundRollbackAnchor\s*\{[\s\S]*?pub\s+fn\s+(?:new|from_|for_)/u.test(
      anchorRegistry,
    ) &&
    /pub\s+struct\s+WindowsJournalStore\s*\{/u.test(keyAgentDurable) &&
    /pub\s+struct\s+WindowsVaultStorage\s*\{/u.test(keyAgentDurable) &&
    !/pub\s+struct\s+Windows(?:JournalStore|VaultStorage|GenerationStore)\s*</u.test(
      `${keyAgentDurable}\n${windowsStorageFacade}`,
    ) &&
    !/impl\s*<[^>]*>\s+Windows(?:JournalStore|VaultStorage|GenerationStore)\s*</u.test(
      `${keyAgentDurable}\n${windowsStorageFacade}`,
    ),
  "production Windows storage must accept only the opaque bound rollback anchor",
);
requireInvariant(
  windowsStorage.includes('ascii_utf16_eq_ignore_case(name, b"NTFS")') &&
    !windowsStorage.includes('ascii_utf16_eq_ignore_case(name, b"ReFS")'),
  "persistent Windows storage must remain NTFS-only until 128-bit ReFS file IDs are used",
);

const attestation = await text("crates/platform-windows/src/attestation.rs");
requireInvariant(
  /COMPILED_RELEASE_POLICY[^=]*=\s*None\s*;/su.test(attestation),
  "development tree must remain release-attestation fail-closed",
);
requireInvariant(
  attestation.includes("const REQUIRED_HELPER_MANIFESTS: usize = 3") &&
    attestation.includes("helper_manifest_digests") &&
    attestation.includes("valid_helper_manifest_allowlist"),
  "release evidence must bind the exact three signing-TCB helper manifests",
);
requireInvariant(
  attestation.includes("broker_transport_suite_digest") &&
    attestation.includes("broker_manifest_digest") &&
    attestation.includes("with_broker_transport") &&
    attestation.includes("valid_broker_manifest") &&
    attestation.includes("!helpers.contains(&broker)") &&
    /COMPILED_RELEASE_POLICY[^=]*=\s*None\s*;/su.test(attestation),
  "Broker transport evidence and manifest must remain separate from the three helper manifests and release-disabled",
);
const brokerArtifactSource = await text(
  "crates/platform-windows/src/broker_artifact.rs",
);
const brokerArtifactProduction = withoutBottomTestModule(brokerArtifactSource);
const restrictedLauncher = await text("crates/platform-windows/src/launch.rs");
const restrictedLauncherProduction = withoutBottomTestModule(restrictedLauncher);
requireInvariant(
  restrictedLauncher.includes("allows_helper_manifest") &&
    restrictedLauncher.includes("HelperManifestNotAllowed"),
  "restricted launcher must enforce the release-bound helper allowlist",
);

const keyAgentActivation = withoutBottomTestModule(
  await text("crates/platform-windows/src/key_agent_activation.rs"),
);
const keyAgentRootJobSource = await text(
  "crates/platform-windows/src/key_agent_root_job.rs",
);
const keyAgentPipeSource = await text("crates/platform-windows/src/pipe.rs");
const keyAgentPipeProduction = withoutBottomTestModule(keyAgentPipeSource);
const keyAgentSupervisor = withoutBottomTestModule(
  await text("crates/platform-windows/src/key_agent_supervisor.rs"),
);
const platformWindowsProductionFiles = await rustProductionSources(
  "crates/platform-windows/src",
);
const platformWindowsLib = await text("crates/platform-windows/src/lib.rs");
const activationHelper = withoutBottomTestModule(
  await text("crates/platform-windows/src/helper.rs"),
);
const activationArchitecture = await text("docs/architecture.md");
const activationReadme = await text("crates/platform-windows/README.md");
const securityDecisions = await text("docs/security-decisions.md");
const brokerPreflight = rustFunctionBlock(
  brokerArtifactProduction,
  "preflight_broker_artifact",
);
const brokerPreflightOrder = [
  "if !artifact.is_broker()",
  "if !attestation.signing_enabled()",
  "if !attestation.allows_broker_manifest(artifact.manifest_digest())",
  "if !artifact.path().is_absolute()",
  "Ok(PreflightBrokerArtifact { artifact })",
].map((marker) => brokerPreflight.indexOf(marker));
requireInvariant(
  platformWindowsLib.includes("mod broker_artifact;") &&
    !/pub(?:\([^)]*\))?\s+mod\s+broker_artifact\b/u.test(platformWindowsLib) &&
    !/pub(?:\([^)]*\))?\s+use\s+[^;]*broker_artifact/u.test(platformWindowsLib) &&
    /pub\(crate\)\s+struct\s+PreflightBrokerArtifact\s*\{\s*artifact:\s*VerifiedHelper,?\s*\}/u.test(
      brokerArtifactProduction,
    ) &&
    !/#\[derive\([^\]]*\bClone\b[^\]]*\)\]\s*(?:#\[[^\]\r\n]+\]\s*)*pub\(crate\)\s+struct\s+PreflightBrokerArtifact\b/u.test(
      brokerArtifactProduction,
    ) &&
    !/impl\s+Clone\s+for\s+PreflightBrokerArtifact\b/u.test(
      brokerArtifactProduction,
    ) &&
    brokerPreflightOrder.every((position) => position !== -1) &&
    brokerPreflightOrder.every(
      (position, index, positions) => index === 0 || positions[index - 1] < position,
    ) &&
    activationHelper.includes("pub(crate) const fn is_broker(&self) -> bool") &&
    !/pub\(crate\)\s+(?:const\s+)?fn\s+(?:artifact|into_artifact|path|raw_handle|launch|spawn)\b/u.test(
      brokerArtifactProduction,
    ) &&
    !/\b(?:CreateProcess\w*|ShellExecute\w*|WinExec|Command::new|std::thread::spawn)\s*\(/u.test(
      brokerArtifactProduction,
    ),
  "private Broker preflight must own one opaque artifact and preserve role/evidence/manifest/path ordering without activation APIs",
);
requireInvariant(
  activationArchitecture.includes("private, dormant Broker") &&
    activationArchitecture.includes("exactly three signing-TCB helper manifests") &&
    /no supervisor\s+consumes it yet/u.test(activationArchitecture) &&
    activationReadme.includes("private dormant Broker artifact preflight") &&
    activationReadme.includes("no supervisor consumes") &&
    securityDecisions.includes("private dormant Broker preflight") &&
    securityDecisions.includes("not production Broker activation"),
  "Broker artifact admission must remain documented as dormant and release-blocking",
);
const productionProcessCreationSites = platformWindowsProductionFiles.flatMap(
  (file) =>
    [
      ...file.source.matchAll(
        /\b(CreateProcess(?:AsUser|WithToken|WithLogon)?[WA]?|ShellExecute(?:Ex)?[WA]?|WinExec)\s*\(|\b((?:std::process::)?Command::new)\s*\(/gu,
      ),
    ].map((match) => ({
      path: file.path,
      api: match[1] ?? match[2],
    })),
);
requireInvariant(
  JSON.stringify(productionProcessCreationSites) ===
    JSON.stringify([
      {
        path: "crates/platform-windows/src/broker_supervisor.rs",
        api: "CreateProcessW",
      },
      {
        path: "crates/platform-windows/src/key_agent_activation.rs",
        api: "CreateProcessW",
      },
      {
        path: "crates/platform-windows/src/launch.rs",
        api: "CreateProcessW",
      },
    ]),
  "production Windows process creation must remain confined to the reviewed debug Broker supervisor, dormant Key Agent activation, and restricted launcher call sites",
);
requireInvariant(
  platformWindowsLib.includes("#[cfg(windows)]\nmod key_agent_activation;") &&
    !/pub(?:\([^)]*\))?\s+mod\s+key_agent_activation\b/u.test(platformWindowsLib) &&
    !/pub(?:\([^)]*\))?\s+use\s+[^;]*key_agent_activation/u.test(platformWindowsLib) &&
    platformWindowsLib.includes(
      "use platform_windows::key_agent_activation::HeldKeyAgentActivation;",
    ) &&
    platformWindowsLib.includes(
      "use platform_windows::key_agent_activation::activate_key_agent;",
    ) &&
    platformWindowsLib.includes("#[cfg(windows)]\nmod key_agent_supervisor;") &&
    !/pub(?:\([^)]*\))?\s+mod\s+key_agent_supervisor\b/u.test(platformWindowsLib) &&
    !/pub(?:\([^)]*\))?\s+use\s+[^;]*key_agent_supervisor/u.test(platformWindowsLib) &&
    platformWindowsLib.includes(
      "use platform_windows::key_agent_supervisor::BoundDormantKeyAgent;",
    ) &&
    platformWindowsLib.includes(
      "use platform_windows::key_agent_supervisor::bind_dormant_key_agent;",
    ),
  "Key Agent activation and bound supervisor capabilities must remain externally private",
);
const keyAgentRequestWriterImpl = rustItemBlock(
  keyAgentPipeProduction,
  /impl\s+KeyAgentRequestWriter\s*\{/u,
);
const keyAgentResponseReaderImpl = rustItemBlock(
  keyAgentPipeProduction,
  /impl\s+KeyAgentResponseReader\s*\{/u,
);
const keyAgentRequestWriterMethods = [...keyAgentRequestWriterImpl.matchAll(
  /pub\(crate\)\s+(?:const\s+)?fn\s+(\w+)/gu,
)].map((match) => match[1]);
const keyAgentResponseReaderMethods = [...keyAgentResponseReaderImpl.matchAll(
  /pub\(crate\)\s+(?:const\s+)?fn\s+(\w+)/gu,
)].map((match) => match[1]);
requireInvariant(
  keyAgentPipeProduction.includes("unsafe impl Send for KeyAgentRequestWriter {}") &&
    keyAgentPipeProduction.includes("unsafe impl Send for KeyAgentResponseReader {}") &&
    keyAgentPipeProduction.includes(
      "Windows permits the owned HANDLE to be used and",
    ) &&
    !/unsafe\s+impl\s+Sync\s+for\s+KeyAgent(?:RequestWriter|ResponseReader)\b/u.test(
      keyAgentPipeProduction,
    ) &&
    !/unsafe\s+impl\s+Send\s+for\s+(?:OwnedWinHandle|PrivateKeyAgentPipes|PreparedKeyAgentInheritance)\b/u.test(
      keyAgentPipeProduction,
    ) &&
    !/#\[derive\([^\]]*(?:Clone|Copy)[^\]]*\)\]\s*pub\(crate\)\s+struct\s+KeyAgent(?:RequestWriter|ResponseReader)\b/u.test(
      keyAgentPipeProduction,
    ) &&
    !/impl\s+(?:Clone|Copy)\s+for\s+KeyAgent(?:RequestWriter|ResponseReader)\b/u.test(
      keyAgentPipeProduction,
    ) &&
    JSON.stringify(keyAgentRequestWriterMethods) === JSON.stringify(["write_bounded"]) &&
    JSON.stringify(keyAgentResponseReaderMethods) ===
      JSON.stringify(["read_bounded_to_end"]) &&
    keyAgentPipeSource.includes(
      "fn key_agent_parent_endpoints_transfer_once_to_a_fresh_thread()",
    ),
  "only the unique consuming Key Agent parent endpoints may cross one worker boundary",
);
const boundDormantBlock =
  /pub\(crate\)\s+struct\s+BoundDormantKeyAgent\s*\{(?<body>[\s\S]*?)\n\}/u.exec(
    keyAgentSupervisor,
  )?.groups?.body ?? "";
const bindDormantFunction = rustFunctionBlock(
  keyAgentSupervisor,
  "bind_dormant_key_agent",
);
const issueSupervisorLease = rustFunctionBlock(keyAgentSupervisor, "issue");
const consumeSupervisorLease = rustFunctionBlock(
  keyAgentSupervisor,
  "verify_and_consume",
);
const ensureSupervisorLeaseLive = rustFunctionBlock(
  keyAgentSupervisor,
  "ensure_live",
);
const boundDormantOrder = [
  "preflight_key_agent_activation(attestation, artifact)?",
  "SupervisorActivationLease::issue(MAX_STARTUP_LIFETIME)?",
  "run_on_fresh_key_agent_debug_thread(move |fresh_thread|",
  "let root_job = KeyAgentRootJob::create()?",
  "let pipes = PrivateKeyAgentPipes::create()?",
  "let inheritance = pipes.prepare_child_inheritance()?",
  "let root_job_attribute = root_job.creation_attribute()?",
  "activate_preflighted_key_agent_on_fresh_worker(",
  "drop(root_job_attribute)",
  "drop(inheritance)",
  "root_job.recheck_supervisor_context()?",
  "root_job.verify_effective_limits()?",
  "root_job.active_process_count()? != 1",
  "let (request_writer, response_reader) = pipes.into_parent()",
  "Ok(BoundDormantKeyAgent {",
].map((marker) => bindDormantFunction.indexOf(marker));
requireInvariant(
  boundDormantBlock.includes("activation: HeldKeyAgentActivation") &&
    boundDormantBlock.includes("root_job: KeyAgentRootJob") &&
    boundDormantBlock.includes("request_writer: KeyAgentRequestWriter") &&
    boundDormantBlock.includes("response_reader: KeyAgentResponseReader") &&
    boundDormantBlock.includes("startup_lease: SupervisorActivationLease") &&
    boundDormantBlock.includes("not_sync: PhantomData<Cell<()>>") &&
    !/\bpub(?:\([^)]*\))?\s+\w+\s*:/u.test(boundDormantBlock) &&
    !/#\[derive\([^\]]*(?:Clone|Copy)[^\]]*\)\]\s*pub\(crate\)\s+struct\s+BoundDormantKeyAgent/u.test(
      keyAgentSupervisor,
    ) &&
    !/impl\s+(?:Clone|Copy|Sync)\s+for\s+BoundDormantKeyAgent\b/u.test(
      keyAgentSupervisor,
    ) &&
    keyAgentSupervisor.includes("impl fmt::Debug for BoundDormantKeyAgent") &&
    !/impl\s+BoundDormantKeyAgent\s*\{[\s\S]*?fn\s+(?:resume|start|raw|handle|pipe_name|duplicate)\b/u.test(
      keyAgentSupervisor,
    ) &&
    boundDormantOrder.every((position) => position !== -1) &&
    boundDormantOrder
      .slice(1)
      .every((position, index) => position > boundDormantOrder[index]) &&
    !/fn\s+bind_dormant_key_agent\s*\([^)]*\b(?:Instant|Duration)\b/su.test(
      bindDormantFunction,
    ) &&
    bindDormantFunction.match(/startup_lease\.ensure_live\(\)\?/gu)?.length === 2 &&
    bindDormantFunction.indexOf("startup_lease.ensure_live()?") <
      bindDormantFunction.indexOf("let root_job = KeyAgentRootJob::create()?") &&
    bindDormantFunction.lastIndexOf("startup_lease.ensure_live()?") >
      bindDormantFunction.indexOf(
        "let (request_writer, response_reader) = pipes.into_parent()",
      ) &&
    issueSupervisorLease.includes("Instant::now()") &&
    issueSupervisorLease.includes("requested_lifetime.min(MAX_STARTUP_LIFETIME)") &&
    /fn\s+verify_and_consume\s*\(\s*self,/su.test(consumeSupervisorLease) &&
    consumeSupervisorLease.includes("self.ensure_live()?") &&
    ensureSupervisorLeaseLive.includes("Instant::now()") &&
    !/fn\s+ensure_live\s*\([^)]*\bInstant\b/su.test(ensureSupervisorLeaseLive),
  "the bound dormant Key Agent must atomically own one internally timed, non-clone, no-resume supervisor attempt",
);
const heldActivationBlock =
  /pub\(crate\)\s+struct\s+HeldKeyAgentActivation\s*\{(?<body>[\s\S]*?)\n\}/u.exec(
    keyAgentActivation,
  )?.groups?.body ?? "";
const heldActivationImpl = rustItemBlock(
  keyAgentActivation,
  /impl\s+HeldKeyAgentActivation\s*\{/u,
);
const heldActivationMethods = [...heldActivationImpl.matchAll(
  /pub\(crate\)\s+(?:const\s+)?fn\s+(\w+)/gu,
)].map((match) => match[1]);
requireInvariant(
  heldActivationBlock.includes("process: sys::DetachedSuspendedDebuggee") &&
    !/\bpub(?:\([^)]*\))?\s+\w+\s*:/u.test(heldActivationBlock) &&
    JSON.stringify(heldActivationMethods) ===
      JSON.stringify([
        "process_id",
        "creation_time",
        "artifact_identity",
        "is_detached_and_suspended",
        "duplicate_process_observation",
        "is_member_of_root_job_for_test",
      ]) &&
    /#\[cfg\(test\)\]\s*pub\(crate\)\s+fn\s+duplicate_process_observation/u.test(
      heldActivationImpl,
    ) &&
    /#\[cfg\(test\)\]\s*pub\(crate\)\s+fn\s+is_member_of_root_job_for_test/u.test(
      heldActivationImpl,
    ) &&
    /impl\s+Drop\s+for\s+HeldKeyAgentActivation[\s\S]*?self\.process\.abort\(\)/u.test(
      keyAgentActivation,
    ) &&
    !/#\[derive\([^\]]*(?:Clone|Copy)[^\]]*\)\]\s*pub\(crate\)\s+struct\s+HeldKeyAgentActivation/u.test(
      keyAgentActivation,
    ),
  "held Key Agent activation must remain opaque, non-clone, detached-only, and drop-aborting",
);
const preflightActivation = rustFunctionBlock(
  keyAgentActivation,
  "preflight_key_agent_activation",
);
const preflightArtifactBlock =
  /pub\(crate\)\s+struct\s+PreflightKeyAgentArtifact\s*\{(?<body>[\s\S]*?)\n\}/u.exec(
    keyAgentActivation,
  )?.groups?.body ?? "";
const activationGatePositions = [
  "if !artifact.is_key_agent()",
  "if !attestation.signing_enabled()",
  "if !attestation.allows_helper_manifest(artifact.manifest_digest())",
  "if !artifact.path().is_absolute()",
  "Ok(PreflightKeyAgentArtifact { artifact })",
].map((marker) => preflightActivation.indexOf(marker));
requireInvariant(
  activationGatePositions.every((position) => position !== -1) &&
    activationGatePositions
      .slice(1)
      .every((position, index) => position > activationGatePositions[index]) &&
    preflightArtifactBlock.includes("artifact: VerifiedHelper") &&
    !/\bpub(?:\([^)]*\))?\s+artifact\s*:/u.test(preflightArtifactBlock) &&
    !/#\[derive\([^\]]*(?:Clone|Copy)[^\]]*\)\]\s*pub\(crate\)\s+struct\s+PreflightKeyAgentArtifact/u.test(
      keyAgentActivation,
    ) &&
    !/pub\(crate\)\s+(?:const\s+)?fn\s+(?:artifact|into_artifact|raw_handle)\b/u.test(
      keyAgentActivation,
    ) &&
    bindDormantFunction.indexOf(
      "preflight_key_agent_activation(attestation, artifact)?",
    ) < bindDormantFunction.indexOf("run_on_fresh_key_agent_debug_thread("),
  "Key Agent role, release, manifest, and path gates must precede worker creation",
);
requireInvariant(
  /#\[cfg\(test\)\]\s*supervisor_context_bypass_for_kernel_test:\s*bool/u.test(
    keyAgentRootJobSource,
  ) &&
    /#\[cfg\(test\)\][\s\S]{0,180}pub\(crate\)\s+fn\s+create_for_kernel_test/u.test(
      keyAgentRootJobSource,
    ) &&
    /pub\(crate\)\s+fn\s+create\(\)[\s\S]*?sys::verify_supervisor_context\(\)\?/u.test(
      keyAgentRootJobSource,
    ) &&
    /#\[cfg\(test\)\]\s*if\s+self\.supervisor_context_bypass_for_kernel_test/u.test(
      keyAgentRootJobSource,
    ),
  "only the cfg(test) root-Job constructor may bypass the outer test-runner Job; production must live-check",
);
const derivedLpacRole = rustFunctionBlock(
  restrictedLauncherProduction,
  "from_helper",
);
const approvalRoleGate = rustFunctionBlock(
  restrictedLauncherProduction,
  "require_approval_frontend",
);
const secretInputRoleGate = rustFunctionBlock(
  restrictedLauncherProduction,
  "require_secret_input_frontend",
);
const publicGenericSpawn = rustFunctionBlock(restrictedLauncherProduction, "spawn");
const privateSecretSpawn = rustFunctionBlock(
  restrictedLauncherProduction,
  "spawn_secret_input",
);
const lowLevelLpacLaunch = rustFunctionBlock(
  restrictedLauncherProduction,
  "launch",
);
const lpacAttributeConstruction = rustFunctionBlock(
  restrictedLauncherProduction,
  "for_lpac",
);
const lpacProfileOpen = rustFunctionBlock(
  restrictedLauncherProduction,
  "open_or_create",
);
const lpacProfileMetadata = rustFunctionBlock(
  restrictedLauncherProduction,
  "profile_metadata",
);
const approvalGatePositions = [
  "VerifiedLpacRole::from_helper(helper)?",
  "role != VerifiedLpacRole::ApprovalFrontend",
  "self.require_allowed_helper(helper.manifest_digest())?",
].map((marker) => approvalRoleGate.indexOf(marker));
const secretInputGatePositions = [
  "VerifiedLpacRole::from_helper(helper)?",
  "role != VerifiedLpacRole::SecretInputFrontend",
  "self.require_allowed_helper(helper.manifest_digest())?",
].map((marker) => secretInputRoleGate.indexOf(marker));
requireInvariant(
  /(?:^|\n)enum\s+VerifiedLpacRole\s*\{/u.test(restrictedLauncherProduction) &&
    !/(?:^|\n)pub(?:\([^)]*\))?\s+enum\s+VerifiedLpacRole\s*\{/u.test(
      restrictedLauncherProduction,
    ) &&
    derivedLpacRole.includes("if helper.is_approval_frontend()") &&
    derivedLpacRole.includes("if helper.is_secret_input_frontend()") &&
    derivedLpacRole.includes("if helper.is_key_agent()") &&
    derivedLpacRole.includes(
      "Err(LaunchError::HelperRoleNotAllowed)",
    ) &&
    derivedLpacRole.includes(
      "Err(LaunchError::KeyAgentRequiresSupervisorActivation)",
    ) &&
    approvalGatePositions.every((position) => position !== -1) &&
    approvalGatePositions
      .slice(1)
      .every((position, index) => position > approvalGatePositions[index]) &&
    secretInputGatePositions.every((position) => position !== -1) &&
    secretInputGatePositions
      .slice(1)
      .every((position, index) => position > secretInputGatePositions[index]) &&
    restrictedLauncherProduction.match(/sys::launch\(helper,/gu)?.length === 2 &&
    publicGenericSpawn.indexOf("self.require_approval_frontend(helper)?") <
      publicGenericSpawn.indexOf("sys::launch(helper, handles, self.profile, role)") &&
    privateSecretSpawn.indexOf("self.require_secret_input_frontend(helper)?") <
      privateSecretSpawn.indexOf("sys::launch(helper, handles, self.profile, role)") &&
    lowLevelLpacLaunch.includes("role: VerifiedLpacRole") &&
    lowLevelLpacLaunch.includes("if role.inherits_parent_proof()") &&
    lowLevelLpacLaunch.includes(
      "AttributeList::for_lpac(inherited_raw.into_boxed_slice(), profile, role)",
    ) &&
    lpacAttributeConstruction.includes(
      "OwnedAppContainerSid::open_or_create(profile, role)?",
    ) &&
    lpacProfileOpen.includes("profile_metadata(profile, role)?") &&
    lpacProfileMetadata.includes(
      "(1, VerifiedLpacRole::ApprovalFrontend)",
    ) &&
    lpacProfileMetadata.includes(
      "(1, VerifiedLpacRole::SecretInputFrontend)",
    ) &&
    restrictedLauncherProduction.includes(
      '"YourWallet.ApprovalFrontend.LPAC.v1"',
    ) &&
    restrictedLauncherProduction.includes(
      '"YourWallet.SecretInputFrontend.LPAC.v1"',
    ) &&
    secretBootstrapWindows.includes(
      'const PROFILE_V1_NAME: &str = "YourWallet.SecretInputFrontend.LPAC.v1";',
    ) &&
    !restrictedLauncherProduction.includes(
      '"YourWallet.SecurityHelper.LPAC.v1"',
    ) &&
    !secretBootstrapWindows.includes('"YourWallet.SecurityHelper.LPAC.v1"'),
  "restricted launch must derive distinct stable LPAC identities from the exact manifest role, reject cross-role/Key Agent/Other helpers before release and Win32, and bind Secret Input bootstrap to its own SID",
);
const freshDebugRunner = rustFunctionBlock(
  keyAgentActivation,
  "run_on_fresh_key_agent_debug_thread",
);
const freshWorkerActivation = rustFunctionBlock(
  keyAgentActivation,
  "activate_preflighted_key_agent_on_fresh_worker_with_identity",
);
const freshWorkerEntry = rustFunctionBlock(
  keyAgentActivation,
  "activate_preflighted_key_agent_on_fresh_worker",
);
const debugWorkerPositions = [
  "verify_empty_root_job(root_job)?",
  "sys::SuspendedDebuggee::create(",
  ".authenticate_first_event(",
  "process.detach_still_suspended()",
  "verify_bound_root_process(root_job, process.process_handle())",
  "let process = process.into_detached()?;",
  "Ok(HeldKeyAgentActivation {",
].map((marker) => freshWorkerActivation.indexOf(marker));
requireInvariant(
  freshDebugRunner.includes("std::thread::Builder::new()") &&
    freshDebugRunner.includes(".spawn(move ||") &&
    freshDebugRunner.includes(".join()") &&
    freshDebugRunner.match(/KeyAgentActivationError::ActivationWorker/gu)?.length === 2 &&
    /pub\(crate\)\s+struct\s+FreshKeyAgentDebugThread\s*\{\s*_not_send_or_sync:\s*PhantomData<Rc<\(\)>>/su.test(
      keyAgentActivation,
    ) &&
    !/#\[derive\([^\]]*(?:Clone|Copy)[^\]]*\)\]\s*pub\(crate\)\s+struct\s+FreshKeyAgentDebugThread/u.test(
      keyAgentActivation,
    ) &&
    freshDebugRunner.includes("FnOnce(FreshKeyAgentDebugThread)") &&
    freshWorkerEntry.includes("fresh_thread: FreshKeyAgentDebugThread") &&
    freshWorkerEntry.includes("let PreflightKeyAgentArtifact { artifact } = preflighted;") &&
    freshWorkerEntry.indexOf("let artifact_identity = sys::exact_file_identity") <
      freshWorkerEntry.indexOf(
        "activate_preflighted_key_agent_on_fresh_worker_with_identity(",
      ) &&
    freshWorkerActivation.includes("_fresh_thread: FreshKeyAgentDebugThread") &&
    debugWorkerPositions.every((position) => position !== -1) &&
    debugWorkerPositions
      .slice(1)
      .every((position, index) => position > debugWorkerPositions[index]) &&
    bindDormantFunction.match(/run_on_fresh_key_agent_debug_thread\(/gu)?.length === 1,
  "one unforgeable consumed fresh-worker proof must own the complete Key Agent debug-event lifecycle",
);
const keyAgentCreationAttributeBlock =
  /struct\s+KeyAgentCreationAttributes<'resources,\s*'pipes,\s*'job>\s*\{(?<body>[\s\S]*?)\n\s*\}/u.exec(
    keyAgentActivation,
  )?.groups?.body ?? "";
const keyAgentCreationAttributeImpl = rustItemBlock(
  keyAgentActivation,
  /impl<'resources,\s*'pipes,\s*'job>\s+KeyAgentCreationAttributes<'resources,\s*'pipes,\s*'job>\s*\{/u,
);
const keyAgentCreateProcess = rustFunctionBlock(
  keyAgentActivation,
  "create_suspended_debuggee_process",
);
const keyAgentCreationFlags = rustFunctionBlock(
  keyAgentActivation,
  "key_agent_creation_flags",
);
const verifyBoundRootProcess = rustFunctionBlock(
  keyAgentActivation,
  "verify_bound_root_process",
);
requireInvariant(
  keyAgentCreationAttributeBlock.includes("inherited_handles: Box<[HANDLE; 3]>") &&
    keyAgentCreationAttributeBlock.includes(
      "_inheritance: &'resources PreparedKeyAgentInheritance<'pipes>",
    ) &&
    keyAgentCreationAttributeBlock.includes(
      "root_job_attribute: &'resources KeyAgentRootJobAttribute<'job>",
    ) &&
    keyAgentCreationAttributeImpl.match(
      /InitializeProcThreadAttributeList\([^\n]*,\s*2,\s*None,/gu,
    )?.length === 2 &&
    keyAgentCreationAttributeImpl.includes(
      "usize::try_from(PROC_THREAD_ATTRIBUTE_HANDLE_LIST)",
    ) &&
    keyAgentCreationAttributeImpl.includes(".install_into(attributes.pointer)") &&
    keyAgentActivation.includes(
      "impl Drop for KeyAgentCreationAttributes<'_, '_, '_>",
    ) &&
    keyAgentActivation.includes("DeleteProcThreadAttributeList(self.pointer)") &&
    keyAgentCreateProcess.includes("let mut startup = STARTUPINFOEXW::default();") &&
    keyAgentCreateProcess.includes("startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;") &&
    keyAgentCreateProcess.includes("startup.StartupInfo.hStdInput = attributes.stdin();") &&
    keyAgentCreateProcess.includes("startup.StartupInfo.hStdOutput = attributes.stdout();") &&
    keyAgentCreateProcess.includes("startup.StartupInfo.hStdError = attributes.stderr();") &&
    keyAgentCreateProcess.includes("startup.lpAttributeList = attributes.pointer();") &&
    keyAgentCreateProcess.indexOf(".recheck_supervisor_context()") !== -1 &&
    keyAgentCreateProcess.indexOf(".recheck_supervisor_context()") <
      keyAgentCreateProcess.indexOf("CreateProcessW(") &&
    /CreateProcessW\([\s\S]*?true,\s*key_agent_creation_flags\(\),/u.test(
      keyAgentCreateProcess,
    ) &&
    keyAgentCreationFlags.includes("CREATE_SUSPENDED") &&
    keyAgentCreationFlags.includes("DEBUG_PROCESS") &&
    keyAgentCreationFlags.includes("DEBUG_ONLY_THIS_PROCESS") &&
    keyAgentCreationFlags.includes("CREATE_NO_WINDOW") &&
    keyAgentCreationFlags.includes("EXTENDED_STARTUPINFO_PRESENT") &&
    verifyBoundRootProcess.includes(".recheck_supervisor_context()") &&
    verifyBoundRootProcess.includes(".contains_process(process)") &&
    verifyBoundRootProcess.includes("active_processes == 1") &&
    !keyAgentActivation.includes("PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES") &&
    !keyAgentActivation.includes("SECURITY_CAPABILITIES"),
  "dormant Key Agent creation must atomically bind exactly three stdio handles and one root Job without claiming LPAC",
);
const detachedImplStart = keyAgentActivation.indexOf("impl DetachedSuspendedDebuggee {");
const detachedImplEnd = keyAgentActivation.indexOf(
  "impl fmt::Debug for DetachedSuspendedDebuggee",
);
const detachedImpl = keyAgentActivation.slice(detachedImplStart, detachedImplEnd);
const detachedMethods = [...detachedImpl.matchAll(
  /pub\(super\)\s+(?:const\s+)?fn\s+(\w+)/gu,
)].map((match) => match[1]);
requireInvariant(
  keyAgentActivation.includes(
    "pub(super) struct DetachedSuspendedDebuggee(SuspendedDebuggee);",
  ) &&
    keyAgentActivation.includes("unsafe impl Send for DetachedSuspendedDebuggee {}") &&
    !/unsafe\s+impl\s+(?:Send|Sync)\s+for\s+SuspendedDebuggee\b/u.test(
      keyAgentActivation,
    ) &&
    !/unsafe\s+impl\s+Sync\s+for\s+DetachedSuspendedDebuggee\b/u.test(
      keyAgentActivation,
    ) &&
    !/#\[derive\([^\]]*(?:Clone|Copy)[^\]]*\)\]\s*(?:pub\(super\)\s+)?struct\s+DetachedSuspendedDebuggee/u.test(
      keyAgentActivation,
    ) &&
    keyAgentActivation.includes(
      "if !self.is_detached_and_suspended() || self.pending_event.is_some()",
    ) &&
    JSON.stringify(detachedMethods) ===
      JSON.stringify([
        "process_id",
        "is_detached_and_suspended",
        "abort",
        "duplicate_process_observation",
        "is_member_of_root_job_for_test",
      ]) &&
    /#\[cfg\(test\)\]\s*pub\(super\)\s+fn\s+duplicate_process_observation/u.test(
      detachedImpl,
    ) &&
    /#\[cfg\(test\)\]\s*pub\(super\)\s+fn\s+is_member_of_root_job_for_test/u.test(
      detachedImpl,
    ) &&
    !/impl\s+(?:core::ops::)?(?:Deref|DerefMut|AsRawHandle)\s+for\s+DetachedSuspendedDebuggee/u.test(
      keyAgentActivation,
    ) &&
    !/fn\s+(?:into_inner|as_raw_handle|resume|continue|detach)\b/u.test(detachedImpl),
  "only the proven detached suspended type-state may cross the fresh worker boundary",
);
requireInvariant(
  keyAgentActivation.includes("volume_serial_number == 0") &&
    keyAgentActivation.includes("file_id == [0; 16]") &&
    keyAgentActivation.includes("file_id == [u8::MAX; 16]") &&
    /fn\s+exact_file_identity[\s\S]*?ExactFileObjectIdentity::from_file_id_info\(\s*information\.VolumeSerialNumber,\s*information\.FileId\.Identifier/u.test(
      keyAgentActivation,
    ),
  "exact image identity must reject non-unique FILE_ID_INFO sentinels",
);
requireInvariant(
  /(?:^|\n)enum\s+HelperRole\s*\{/u.test(activationHelper) &&
    !/(?:^|\n)pub(?:\([^)]*\))?\s+enum\s+HelperRole\s*\{/u.test(activationHelper) &&
    activationHelper.includes("matches!(self.role, HelperRole::KeyAgent)") &&
    activationHelper.includes(
      "role: HelperRole::from_release_file_name(&verifier.manifest.file_name)",
    ),
  "verified Key Agent role must remain private and manifest-derived",
);
requireInvariant(
  activationArchitecture.includes("### Key Agent activation invariant (STOP-SHIP)") &&
    activationArchitecture.includes("fresh dedicated OS thread") &&
    activationArchitecture.includes("all-zero or all-`FF`") &&
    activationArchitecture.includes(
      "Zero-capability Key Agent LPAC/profile provisioning, storage authorization, and",
    ) &&
    activationArchitecture.includes("Do not add `registryRead`") &&
    /fresh dedicated\s+debugger OS thread/u.test(activationReadme) &&
    activationReadme.includes("all-zero and all-`FF`") &&
    activationReadme.includes("no resume API") &&
    activationReadme.includes(
      "Keep zero-capability Key Agent LPAC activation and profile provisioning",
    ) &&
    activationReadme.includes("Do not add") &&
    activationReadme.includes("`registryRead`") &&
    activationArchitecture.includes("**STOP-SHIP (English):**") &&
    activationArchitecture.includes("**릴리스 차단 조건 (한국어):**") &&
    activationArchitecture.includes("process-wide single-flight") &&
    activationArchitecture.includes("다른 상속형 자식 프로세스") &&
    activationArchitecture.includes("sealed coordinator") &&
    activationArchitecture.includes("dedicated launcher process") &&
    activationReadme.includes("**STOP-SHIP (English):**") &&
    activationReadme.includes("**릴리스 차단 조건 (한국어):**") &&
    activationReadme.includes("process-wide single-flight") &&
    activationReadme.includes("다른 상속형 자식 프로세스") &&
    activationReadme.includes("sealed coordinator") &&
    activationReadme.includes("dedicated launcher process"),
  "Key Agent activation limitations, LPAC/storage blockers, and type-state proof must remain documented",
);

for (const mainPath of [
  "crates/broker/src/main.rs",
  "crates/key-agent/src/main.rs",
  "crates/approval-ui/src/main.rs",
  "crates/secret-input-ui/src/main.rs",
]) {
  const mainSource = await text(mainPath);
  const literalExit = mainSource.includes("std::process::exit(78);");
  const namedExit =
    mainSource.includes("const PRIVATE_LAUNCH_UNAVAILABLE: i32 = 78;") &&
    mainSource.includes("std::process::exit(PRIVATE_LAUNCH_UNAVAILABLE);");
  requireInvariant(literalExit || namedExit, `${mainPath} must remain fail-closed with exit 78`);
}

for (const helper of [
  {
    cratePath: "crates/approval-ui",
    readCall: "approval_ui::read_request",
    presentCall: "approval_ui::present",
    writeCall: "approval_ui::write_response",
  },
  {
    cratePath: "crates/secret-input-ui",
    readCall: "secret_input_ui::bootstrap::authenticate_inherited_request",
    presentCall: "secret_input_ui::present_authenticated",
    writeCall: "secret_input_ui::bootstrap::write_authenticated_outcome",
  },
]) {
  const manifest = await text(`${helper.cratePath}/Cargo.toml`);
  const mainSource = await text(`${helper.cratePath}/src/main.rs`);
  requireInvariant(
    manifest.includes("default = []") && manifest.includes("runtime-entrypoint = []"),
    `${helper.cratePath} runtime entrypoint must remain opt-in`,
  );
  requireInvariant(
    mainSource.includes('#[cfg(not(feature = "runtime-entrypoint"))]') &&
      mainSource.includes('#[cfg(feature = "runtime-entrypoint")]') &&
      mainSource.includes(helper.readCall) &&
      mainSource.includes(helper.presentCall) &&
      mainSource.includes(helper.writeCall) &&
      mainSource.includes("fn set_binary_stdio()") &&
      mainSource.includes(
        '#[cfg(all(feature = "runtime-contract-test-hook", debug_assertions))]',
      ) &&
      !/(?:e?println!|dbg!)/u.test(mainSource),
    `${helper.cratePath} runtime contract must be bounded, native-presented, binary-safe, silent, and release-safe`,
  );
}

const nativeMain = await text("crates/native-host/src/main.rs");
requireInvariant(
  nativeMain.includes("const PRIVATE_BROKER_UNAVAILABLE: i32 = 78;") &&
    nativeMain.includes("native_host::run_release_disabled_stream") &&
    nativeMain.includes("std::process::exit(PRIVATE_BROKER_UNAVAILABLE);"),
  "native host main must retain its release-disabled persistent path and exit 78",
);
const nativeWireForActivation = await text("crates/native-host/src/wire.rs");
requireInvariant(
  nativeWireForActivation.includes("const UNAVAILABLE_CODE: i64 = 4_900;") &&
    nativeWireForActivation.includes("code: UNAVAILABLE_CODE") &&
    nativeWireForActivation.includes("pub fn run_release_disabled_stream") &&
    /pub fn run_release_disabled_stream[\s\S]*?NativeHostDispatcher::new\(\s*ReleaseDisabledBrokerEndpoint,\s*ReleaseAttestation::default\(\)\s*\)/u.test(
      nativeWireForActivation,
    ) &&
    /impl BrokerEndpoint for ReleaseDisabledBrokerEndpoint[\s\S]*?Err\(BrokerEndpointError::Unavailable\)/u.test(
      nativeWireForActivation,
    ) &&
    nativeWireForActivation.includes("pub fn run_unattested_once"),
  "native host release-disabled paths must retain false attestation and stable provider code 4900",
);

// Debug subprocess contract: this is deliberately disjoint from the Sepolia
// wallet-management/token invariants above and from the release attestation
// composition. It may prove protocol shape only; it must never become a release
// Broker bootstrap or carry an unavailable request body.
const brokerManifestForContract = await text("crates/broker/Cargo.toml");
const nativeManifestForContract = await text("crates/native-host/Cargo.toml");
const brokerMainForContract = await text("crates/broker/src/main.rs");
const brokerLibraryForContract = await text("crates/broker/src/lib.rs");
const brokerTransportForContract = await text("crates/broker/src/transport.rs");
const brokerIpcContract = await text("crates/broker/src/ipc.rs");
const nativeLibraryForContract = await text("crates/native-host/src/lib.rs");
const nativeContractBridge = await text("crates/native-host/src/contract_bridge.rs");
const extensionBackgroundContract = await text("extension/src/background-core.js");
const nativeProcessContractTest = await text("extension/tests/native-host-process.test.mjs");
const platformManifestForWindowsBroker = await text(
  "crates/platform-windows/Cargo.toml",
);
const brokerChannelProduction = withoutBottomTestModule(
  await text("crates/platform-windows/src/broker_channel.rs"),
);
const brokerSupervisor = await text(
  "crates/platform-windows/src/broker_supervisor.rs",
);
const brokerSupervisorProduction = withoutBottomTestModule(brokerSupervisor);
const exactBrokerImage = await text(
  "crates/platform-windows/src/exact_image.rs",
);
const exactBrokerImageProduction = withoutBottomTestModule(exactBrokerImage);
const nativeWindowsBrokerBridge = await text(
  "crates/native-host/src/windows_broker_bridge.rs",
);
const brokerProtocolContract = await text("docs/protocol-contract.md");
const nativeHostContractReadme = await text("extension/native-host/README.md");
const brokerContractProductionFiles = await rustProductionSources(
  "crates/broker/src",
);
const nativeContractProductionFiles = await rustProductionSources(
  "crates/native-host/src",
);
requireInvariant(
  brokerManifestForContract.includes(
    'ipc-contract-test-hook = ["dep:getrandom"]',
  ) &&
    brokerManifestForContract.includes(
      "getrandom = { workspace = true, optional = true }",
    ) &&
    nativeManifestForContract.includes(
      'broker-ipc-contract-test-hook = ["broker/ipc-contract-test-hook", "dep:getrandom"]',
    ) &&
    nativeManifestForContract.includes(
      "getrandom = { workspace = true, optional = true }",
    ),
  "debug Broker subprocess randomness must remain optional and feature-scoped",
);

// Dormant Windows composition: every exported module and entrypoint must
// require Windows AND its explicit feature AND debug assertions. This keeps
// the APIs absent from default builds and from all-feature release builds.
const brokerSupervisorExports =
  /#\[cfg\(all\(\s*windows,\s*feature = "broker-channel-contract-test-hook",\s*debug_assertions\s*\)\)\]\s*pub use broker_supervisor::\{(?<body>[^}]*)\};/u.exec(
    platformWindowsLib,
  )?.groups?.body ?? "";
const nativeWindowsBridgeExports =
  /#\[cfg\(all\(\s*windows,\s*feature = "windows-broker-channel-contract-test-hook",\s*debug_assertions\s*\)\)\]\s*pub use windows_broker_bridge::(?<body>[^;]+);/u.exec(
    nativeLibraryForContract,
  )?.groups?.body ?? "";
requireInvariant(
  /^default\s*=\s*\[\]$/mu.test(platformManifestForWindowsBroker) &&
    /^broker-channel-contract-test-hook\s*=\s*\[\]$/mu.test(
      platformManifestForWindowsBroker,
    ) &&
    /^windows-broker-channel-contract-test-hook\s*=\s*\[\s*"ipc-contract-test-hook",\s*"dep:platform-windows",\s*"platform-windows\/broker-channel-contract-test-hook",?\s*\]$/mu.test(
      brokerManifestForContract,
    ) &&
    /^windows-broker-channel-contract-test-hook\s*=\s*\[\s*"broker-ipc-contract-test-hook",\s*"broker\/windows-broker-channel-contract-test-hook",\s*"platform-windows\/broker-channel-contract-test-hook",?\s*\]$/mu.test(
      nativeManifestForContract,
    ),
  "Windows Broker composition features must remain opt-in and transitively bind the same platform debug feature",
);
requireInvariant(
  /#\[cfg\(all\(\s*windows,\s*feature = "broker-channel-contract-test-hook",\s*debug_assertions\s*\)\)\]\s*mod broker_supervisor;/u.test(
    platformWindowsLib,
  ) &&
    /#\[cfg\(all\(\s*windows,\s*feature = "broker-channel-contract-test-hook",\s*debug_assertions\s*\)\)\]\s*mod exact_image;/u.test(
      platformWindowsLib,
    ) &&
    brokerSupervisorExports.includes("DormantBrokerPayloadChannel") &&
    brokerSupervisorExports.includes("connect_inherited_native_host_channel") &&
    brokerSupervisorExports.includes("launch_dormant_broker_channel") &&
    (platformWindowsLib.match(/\bbroker_supervisor\b/gu) ?? []).length === 2 &&
    (platformWindowsLib.match(/\bexact_image\b/gu) ?? []).length === 1 &&
    /#\[cfg\(all\(\s*windows,\s*feature = "windows-broker-channel-contract-test-hook",\s*debug_assertions\s*\)\)\]\s*mod windows_broker_bridge;/u.test(
      nativeLibraryForContract,
    ) &&
    nativeWindowsBridgeExports.includes(
      "run_windows_broker_contract_test_stream",
    ) &&
    (nativeLibraryForContract.match(/\bwindows_broker_bridge\b/gu) ?? [])
      .length === 2,
  "Windows Broker supervisor, exact-image proof, and Native Host bridge APIs must be absent outside the Windows debug feature gate",
);
const brokerDisabledMain = rustItemBlock(
  brokerMainForContract,
  /(?:^|\n)#\[cfg\(not\(any\([\s\S]*?feature = "ipc-contract-test-hook"[\s\S]*?feature = "windows-broker-channel-contract-test-hook"[\s\S]*?debug_assertions[\s\S]*?\)\)\)\]\s*fn main\s*\(\s*\)/u,
);
const brokerLegacyMain = rustItemBlock(
  brokerMainForContract,
  /(?:^|\n)#\[cfg\(all\(\s*feature = "ipc-contract-test-hook",\s*debug_assertions,\s*not\(all\(windows, feature = "windows-broker-channel-contract-test-hook"\)\)\s*\)\)\]\s*fn main\s*\(\s*\)/u,
);
const brokerWindowsMain = rustItemBlock(
  brokerMainForContract,
  /(?:^|\n)#\[cfg\(all\(\s*windows,\s*feature = "windows-broker-channel-contract-test-hook",\s*debug_assertions\s*\)\)\]\s*fn main\s*\(\s*\)/u,
);
const brokerLegacyServerEntry = rustItemBlock(
  brokerMainForContract,
  /(?:^|\n)#\[cfg\(all\(\s*feature = "ipc-contract-test-hook",\s*debug_assertions,\s*not\(all\(windows, feature = "windows-broker-channel-contract-test-hook"\)\)\s*\)\)\]\s*fn run_contract_server\s*\(\s*\)/u,
);
const brokerWindowsServerEntry = rustItemBlock(
  brokerMainForContract,
  /(?:^|\n)#\[cfg\(all\(\s*windows,\s*feature = "windows-broker-channel-contract-test-hook",\s*debug_assertions\s*\)\)\]\s*fn run_windows_contract_server\s*\(\s*\)/u,
);
const nativeDisabledMain = rustItemBlock(
  nativeMain,
  /(?:^|\n)#\[cfg\(not\(all\(feature = "broker-ipc-contract-test-hook", debug_assertions\)\)\)\]\s*fn main\s*\(\s*\)/u,
);
const nativeLegacyMain = rustItemBlock(
  nativeMain,
  /(?:^|\n)#\[cfg\(all\(\s*feature = "broker-ipc-contract-test-hook",\s*debug_assertions,\s*not\(all\(windows, feature = "windows-broker-channel-contract-test-hook"\)\)\s*\)\)\]\s*fn main\s*\(\s*\)/u,
);
const nativeWindowsMain = rustItemBlock(
  nativeMain,
  /(?:^|\n)#\[cfg\(all\(\s*windows,\s*feature = "windows-broker-channel-contract-test-hook",\s*debug_assertions\s*\)\)\]\s*fn main\s*\(\s*\)/u,
);
const nativeLegacyProcessEntry = rustItemBlock(
  nativeMain,
  /(?:^|\n)#\[cfg\(all\(\s*feature = "broker-ipc-contract-test-hook",\s*debug_assertions,\s*not\(all\(windows, feature = "windows-broker-channel-contract-test-hook"\)\)\s*\)\)\]\s*fn run_contract_process\s*\(\s*\)/u,
);
const nativeWindowsProcessEntry = rustItemBlock(
  nativeMain,
  /(?:^|\n)#\[cfg\(all\(\s*windows,\s*feature = "windows-broker-channel-contract-test-hook",\s*debug_assertions\s*\)\)\]\s*fn run_windows_contract_process\s*\(\s*\)/u,
);
const brokerNativeMainBlocks = [
  brokerDisabledMain,
  brokerLegacyMain,
  brokerWindowsMain,
  brokerLegacyServerEntry,
  brokerWindowsServerEntry,
  nativeDisabledMain,
  nativeLegacyMain,
  nativeWindowsMain,
  nativeLegacyProcessEntry,
  nativeWindowsProcessEntry,
];
requireInvariant(
  brokerNativeMainBlocks.every(
    (block) => block.length > 0 && !/(?:e?println!|dbg!)/u.test(block),
  ) &&
    brokerDisabledMain.includes("std::process::exit(78);") &&
    !/\brun_(?:contract|windows_contract)_server\s*\(/u.test(
      brokerDisabledMain,
    ) &&
    brokerLegacyMain.includes("run_contract_server()") &&
    !brokerLegacyMain.includes("run_windows_contract_server()") &&
    brokerWindowsMain.includes("run_windows_contract_server()") &&
    !brokerWindowsMain.includes("run_contract_server()") &&
    nativeDisabledMain.includes("native_host::run_release_disabled_stream") &&
    nativeDisabledMain.includes(
      "std::process::exit(PRIVATE_BROKER_UNAVAILABLE);",
    ) &&
    !/\brun_(?:contract|windows_contract)_process\s*\(/u.test(
      nativeDisabledMain,
    ) &&
    nativeLegacyMain.includes("run_contract_process()") &&
    !nativeLegacyMain.includes("run_windows_contract_process()") &&
    nativeWindowsMain.includes("run_windows_contract_process()") &&
    !nativeWindowsMain.includes("run_contract_process()"),
  "legacy stdio, Windows Broker, and default/release mains must remain mutually exclusive, feature-and-debug gated, silent, and fail-closed",
);
requireInvariant(
  nativeProcessContractTest.includes(
    'test("release all-feature binaries keep both subprocess hooks disabled"',
  ) &&
    nativeProcessContractTest.includes(
      '"build", "--release", "--offline", "--locked"',
    ) &&
    nativeProcessContractTest.includes(
      '"-p", "native-host", "-p", "broker", "--all-features"',
    ) &&
    nativeProcessContractTest.includes(
      "assert.deepEqual(await runClosedProcess(executables.broker), { code: 78, signal: null })",
    ) &&
    nativeProcessContractTest.includes("response.error.code, 4900") &&
    nativeProcessContractTest.includes(
      "assert.deepEqual(await nativeProcess.closed, { code: 78, signal: null })",
    ) &&
    nativeProcessContractTest.includes(
      'test("Windows native host reaches the exact hidden Broker channel without stdio composition"',
    ) &&
    nativeProcessContractTest.includes(
      "native-host/windows-broker-channel-contract-test-hook,broker/windows-broker-channel-contract-test-hook",
    ),
  "real subprocess evidence must retain the Windows debug composition and default/release all-feature negative behavior",
);

// The Windows pipe owns its one BE frame. Broker IPC owns only the closed JSON
// payload state machine; its legacy stdio wrapper is the sole separate framing
// adapter and delegates immediately to the same payload APIs.
const brokerChannelWriteFrame = rustFunctionBlock(
  brokerChannelProduction,
  "write_frame_after_prefix",
);
const brokerChannelReadFrame = rustFunctionBlock(
  brokerChannelProduction,
  "read_frame_or_eof",
);
const brokerPayloadTrait = rustItemBlock(
  brokerIpcContract,
  /(?:^|\n)pub trait BrokerIpcPayloads\s*\{/u,
);
const brokerSplitFramingAdapter = rustItemBlock(
  brokerIpcContract,
  /(?:^|\n)impl<Reader, Writer> BrokerIpcPayloads for SplitFramedPayloads<'_, Reader, Writer>\s*/u,
);
const brokerStdioServer = rustFunctionBlock(
  brokerIpcContract,
  "run_secretless_server",
);
const brokerPayloadServer = rustFunctionBlock(
  brokerIpcContract,
  "run_secretless_server_payloads",
);
const brokerReadFramedPayload = rustFunctionBlock(
  brokerIpcContract,
  "read_framed_payload",
);
const brokerWriteFramedPayload = rustFunctionBlock(
  brokerIpcContract,
  "write_framed_payload",
);
const brokerWindowsServer = rustFunctionBlock(
  brokerMainForContract,
  "run_windows_contract_server",
);
const nativeWindowsProcess = rustFunctionBlock(
  nativeMain,
  "run_windows_contract_process",
);
const supervisorWritePayload = rustFunctionBlock(
  brokerSupervisorProduction,
  "write_payload",
);
const supervisorReadPayload = rustFunctionBlock(
  brokerSupervisorProduction,
  "read_payload",
);
requireInvariant(
  brokerChannelProduction.includes(
    "const MAX_BROKER_FRAME_BYTES: usize = 8_192;",
  ) &&
    brokerChannelWriteFrame.includes("length.to_be_bytes()") &&
    brokerChannelReadFrame.includes("u32::from_be_bytes(prefix)") &&
    !/(?:to|from)_le_bytes/u.test(brokerChannelProduction) &&
    brokerIpcContract.includes(
      "pub const MAX_BROKER_IPC_FRAME_BYTES: usize = 8_192;",
    ) &&
    brokerReadFramedPayload.includes("u32::from_be_bytes(length_bytes)") &&
    brokerWriteFramedPayload.includes("length.to_be_bytes()") &&
    !/(?:to|from)_le_bytes/u.test(brokerIpcContract),
  "Windows and stdio Broker framing must remain four-byte big-endian with the exact 8192-byte payload bound",
);
requireInvariant(
  brokerPayloadTrait.includes(
    "fn read_payload(&mut self) -> Result<Option<Vec<u8>>, BrokerIpcError>;",
  ) &&
    brokerPayloadTrait.includes(
      "fn write_payload(&mut self, payload: &[u8]) -> Result<(), BrokerIpcError>;",
    ) &&
    brokerSplitFramingAdapter.includes("read_framed_payload(self.reader)") &&
    brokerSplitFramingAdapter.includes(
      "write_framed_payload(self.writer, payload)",
    ) &&
    brokerStdioServer.includes("SplitFramedPayloads { reader, writer }") &&
    brokerStdioServer.includes("run_secretless_server_payloads(") &&
    brokerPayloadServer.includes("read_required_payload_value(payloads)") &&
    brokerPayloadServer.includes("write_payload_value(") &&
    brokerPayloadServer.includes("payloads,") &&
    !/(?:read|write)_framed_payload|to_be_bytes|from_be_bytes/u.test(
      brokerPayloadServer,
    ) &&
    supervisorWritePayload.includes("channel.write_frame(payload, deadline)") &&
    supervisorReadPayload.includes("channel.read_frame_or_eof(deadline)") &&
    brokerWindowsServer.includes("run_secretless_server_payloads(") &&
    !/\brun_secretless_server\s*\(/u.test(brokerWindowsServer) &&
    nativeWindowsBrokerBridge.includes(
      "run_broker_contract_test_payloads(native_reader, native_writer, &mut payloads, random_nonce)",
    ) &&
    !/(?:read|write)_framed_payload|to_be_bytes|from_be_bytes/u.test(
      [
        brokerSupervisorProduction,
        nativeWindowsBrokerBridge,
        nativeContractBridge,
      ].join("\n"),
    ) &&
    !nativeWindowsProcess.includes("Command::new"),
  "Windows composition must have one channel framing owner and reuse Broker IPC only as a payload-state machine",
);

const dormantBrokerFacadeReferences = [
  ...platformWindowsProductionFiles,
  ...brokerContractProductionFiles,
  ...nativeContractProductionFiles,
]
  .filter((file) => file.source.includes("DormantBrokerPayloadChannel"))
  .map((file) => file.path)
  .sort((left, right) => left.localeCompare(right, "en"));
const brokerWindowsPayloadAdapter = rustItemBlock(
  brokerMainForContract,
  /(?:^|\n)\s*impl BrokerIpcPayloads for WindowsPayloads\s*\{/u,
);
const nativeWindowsPayloadAdapter = rustItemBlock(
  nativeWindowsBrokerBridge,
  /(?:^|\n)impl BrokerIpcPayloads for WindowsBrokerPayloads\s*\{/u,
);
requireInvariant(
  JSON.stringify(dormantBrokerFacadeReferences) ===
    JSON.stringify([
      "crates/broker/src/main.rs",
      "crates/native-host/src/windows_broker_bridge.rs",
      "crates/platform-windows/src/broker_supervisor.rs",
      "crates/platform-windows/src/lib.rs",
    ]) &&
    (brokerWindowsPayloadAdapter.match(/\.read_payload\(/gu) ?? []).length === 1 &&
    (brokerWindowsPayloadAdapter.match(/\.write_payload\(/gu) ?? []).length === 1 &&
    (nativeWindowsPayloadAdapter.match(/\.read_payload\(/gu) ?? []).length === 1 &&
    (nativeWindowsPayloadAdapter.match(/\.write_payload\(/gu) ?? []).length === 1 &&
    brokerSupervisorProduction.includes(
      "cross-crate `BrokerIpcPayloads` adapters must supply framing-free JSON",
    ),
  "debug raw Broker payload facade must remain release-absent and confined to the two typed payload adapters",
);

// The debug creator may run only at its one reviewed callsite and must prove
// the simultaneously held Broker image before releasing user mode. No PID
// reopen is accepted in either the channel peer binding or supervisor.
const launchBrokerPath = rustFunctionBlock(
  brokerSupervisorProduction,
  "launch_broker_path",
);
const launchBrokerApplicationWithAfterCreate = rustFunctionBlock(
  brokerSupervisorProduction,
  "launch_broker_application_with_after_create",
);
const launchBrokerApplicationWrapper = rustFunctionBlock(
  brokerSupervisorProduction,
  "launch_broker_application",
);
const panicAfterBrokerCreate = rustFunctionBlock(
  brokerSupervisorProduction,
  "panic_after_create_for_test",
);
const authenticateBrokerImage = rustFunctionBlock(
  brokerSupervisorProduction,
  "authenticate_first_event",
);
const brokerCreationFlags = rustFunctionBlock(
  brokerSupervisorProduction,
  "creation_flags",
);
const brokerCreationFlagNames = [
  ...brokerCreationFlags.matchAll(
    /\b(?:CREATE_[A-Z_]+|DEBUG_[A-Z_]+|EXTENDED_STARTUPINFO_PRESENT)\b/gu,
  ),
].map((match) => match[0]);
const brokerCreationAttributesDefinition = rustItemBlock(
  brokerSupervisorProduction,
  /(?:^|\n)\s*struct CreationAttributes<'resources>\s*\{/u,
);
const brokerCreationAttributesImplementation = rustItemBlock(
  brokerSupervisorProduction,
  /(?:^|\n)\s*impl<'resources> CreationAttributes<'resources>\s*\{/u,
);
const brokerInheritedNullStdio = rustItemBlock(
  brokerSupervisorProduction,
  /(?:^|\n)\s*impl InheritedNullStdio\s*\{/u,
);
const brokerChildKernelContract = rustFunctionBlock(
  brokerSupervisorProduction,
  "assert_child_kernel_contract",
);
const brokerInheritableSentinel = rustItemBlock(
  brokerSupervisorProduction,
  /(?:^|\n)\s*impl InheritableSentinel\s*\{/u,
);
const brokerDebugWaitClassifier = rustFunctionBlock(
  brokerSupervisorProduction,
  "classify_debug_wait_failure",
);
const brokerJobImplementation = rustItemBlock(
  brokerSupervisorProduction,
  /(?:^|\n)\s*impl BrokerJob\s*\{/u,
);
const brokerProcessObservationImplementation = rustItemBlock(
  brokerSupervisorProduction,
  /(?:^|\n)\s*impl ProcessObservation\s*\{/u,
);
const duplicateBrokerProcessObservation = rustItemBlock(
  brokerSupervisorProduction,
  /(?:^|\n)    fn duplicate_process_observation\s*\(/u,
);
const exactFileIdentityDefinition = rustItemBlock(
  exactBrokerImageProduction,
  /(?:^|\n)struct ExactFileIdentity\s*\{/u,
);
const exactFileIdentityNew = rustFunctionBlock(
  exactBrokerImageProduction,
  "new",
);
const exactMappedImageAuthentication = rustFunctionBlock(
  exactBrokerImageProduction,
  "authenticate_mapped_image",
);
requireInvariant(
  launchBrokerPath.includes("PinnedBrokerImage::hold(broker_path)") &&
    exactBrokerImageProduction.includes(
      "VerifiedHelper::hold_dormant_broker(path)",
    ) &&
    exactBrokerImageProduction.includes("FILE_ID_INFO") &&
    exactBrokerImageProduction.includes("GetFileInformationByHandleEx(") &&
    /#\[derive\(Clone, Copy, Eq, PartialEq\)\]\s*struct ExactFileIdentity/u.test(
      exactBrokerImageProduction,
    ) &&
    exactFileIdentityDefinition.includes("volume_serial_number: u64") &&
    exactFileIdentityDefinition.includes("file_id: [u8; 16]") &&
    exactFileIdentityNew.includes("volume_serial_number == 0") &&
    exactFileIdentityNew.includes("file_id == [0; 16]") &&
    exactFileIdentityNew.includes("file_id == [u8::MAX; 16]") &&
    exactMappedImageAuthentication.includes(
      "sys::exact_file_identity(mapped_image)? == self.identity",
    ) &&
    exactBrokerImage.includes(
      "exact_file_identity_rejects_zero_volume_and_sentinel_file_ids",
    ) &&
    exactBrokerImage.includes(
      "exact_file_identity_equality_binds_volume_and_all_128_file_id_bits",
    ) &&
    exactBrokerImage.includes("for index in [0_usize, 8, 15]") &&
    authenticateBrokerImage.includes("CREATE_PROCESS_DEBUG_EVENT") &&
    authenticateBrokerImage.includes(
      "image.authenticate_mapped_image(event_file.raw())",
    ) &&
    JSON.stringify(brokerCreationFlagNames) ===
      JSON.stringify([
        "CREATE_SUSPENDED",
        "DEBUG_PROCESS",
        "DEBUG_ONLY_THIS_PROCESS",
        "CREATE_NO_WINDOW",
        "CREATE_UNICODE_ENVIRONMENT",
        "EXTENDED_STARTUPINFO_PRESENT",
      ]) &&
    brokerCreationAttributesDefinition.includes(
      "inherited_handles: Box<[HANDLE; 2]>",
    ) &&
    brokerCreationAttributesDefinition.includes("job_handle: Box<[HANDLE; 1]>") &&
    brokerCreationAttributesImplementation.includes(
      "InitializeProcThreadAttributeList(None, 2",
    ) &&
    brokerCreationAttributesImplementation.includes(
      "InitializeProcThreadAttributeList(Some(pointer), 2",
    ) &&
    (brokerCreationAttributesImplementation.match(
      /InitializeProcThreadAttributeList\(/gu,
    ) ?? []).length === 2 &&
    brokerCreationAttributesImplementation.includes(
      "Box::new([parent.raw(), stdio.raw()])",
    ) &&
    brokerCreationAttributesImplementation.includes("Box::new([job.raw()])") &&
    brokerCreationAttributesImplementation.includes(
      "PROC_THREAD_ATTRIBUTE_HANDLE_LIST",
    ) &&
    brokerCreationAttributesImplementation.includes(
      "PROC_THREAD_ATTRIBUTE_JOB_LIST",
    ) &&
    brokerInheritedNullStdio.includes("PCWSTR(NULL_DEVICE.as_ptr())") &&
    brokerInheritedNullStdio.includes("GENERIC_READ.0 | GENERIC_WRITE.0") &&
    brokerInheritedNullStdio.includes("FILE_SHARE_READ | FILE_SHARE_WRITE") &&
    brokerInheritedNullStdio.includes("HANDLE_FLAG_INHERIT") &&
    brokerInheritedNullStdio.includes("file_type != FILE_TYPE_CHAR") &&
    launchBrokerApplicationWrapper.includes(
      "launch_broker_application_with_after_create(",
    ) &&
    launchBrokerApplicationWrapper.includes("|_debuggee| {}") &&
    /#\[cfg\(test\)\]\s*pub\(super\) fn panic_after_create_for_test/u.test(
      brokerSupervisorProduction,
    ) &&
    panicAfterBrokerCreate.includes(
      "launch_broker_application_with_after_create(",
    ) &&
    panicAfterBrokerCreate.includes("std::panic::resume_unwind") &&
    launchBrokerApplicationWithAfterCreate.includes("CreateProcessW(") &&
    launchBrokerApplicationWithAfterCreate.includes(
      "startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES",
    ) &&
    launchBrokerApplicationWithAfterCreate.includes(
      "startup.StartupInfo.hStdInput = inherited_stdio.raw()",
    ) &&
    launchBrokerApplicationWithAfterCreate.includes(
      "startup.StartupInfo.hStdOutput = inherited_stdio.raw()",
    ) &&
    launchBrokerApplicationWithAfterCreate.includes(
      "startup.StartupInfo.hStdError = inherited_stdio.raw()",
    ) &&
    (launchBrokerApplicationWithAfterCreate.match(/\bSTARTF_[A-Z_]+\b/gu) ?? [])
      .length === 1 &&
    /CreateProcessW\([\s\S]*?true,\s*creation_flags\(\),/u.test(
      launchBrokerApplicationWithAfterCreate,
    ) &&
    launchBrokerApplicationWithAfterCreate.includes(
      "debuggee.authenticate_first_event",
    ) &&
    launchBrokerApplicationWithAfterCreate.includes(
      "debuggee.detach_while_suspended",
    ) &&
    launchBrokerApplicationWithAfterCreate.includes("job.verify_exact_member") &&
    launchBrokerApplicationWithAfterCreate.includes("debuggee.start_user_mode") &&
    launchBrokerApplicationWithAfterCreate.indexOf("Debuggee::new(information)") <
      launchBrokerApplicationWithAfterCreate.indexOf("after_create(&debuggee)") &&
    launchBrokerApplicationWithAfterCreate.indexOf("after_create(&debuggee)") <
      launchBrokerApplicationWithAfterCreate.indexOf(
        "debuggee.release_creation_suspend",
      ) &&
    launchBrokerApplicationWithAfterCreate.indexOf(
      "debuggee.authenticate_first_event",
    ) <
      launchBrokerApplicationWithAfterCreate.indexOf(
        "debuggee.detach_while_suspended",
      ) &&
    launchBrokerApplicationWithAfterCreate.indexOf(
      "debuggee.detach_while_suspended",
    ) < launchBrokerApplicationWithAfterCreate.indexOf("job.verify_exact_member") &&
    launchBrokerApplicationWithAfterCreate.indexOf("job.verify_exact_member") <
      launchBrokerApplicationWithAfterCreate.indexOf("debuggee.start_user_mode") &&
    brokerChildKernelContract.includes("SetEvent(unrelated)") &&
    brokerChildKernelContract.includes(
      "[STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE]",
    ) &&
    brokerChildKernelContract.includes("expected != handle") &&
    brokerChildKernelContract.includes("file_type != FILE_TYPE_CHAR") &&
    brokerInheritableSentinel.includes("WaitForSingleObject(self.0.raw(), 0)") &&
    brokerInheritableSentinel.includes("== WAIT_TIMEOUT") &&
    (brokerSupervisor.match(/unrelated_sentinel\.assert_not_signaled\(\)\?/gu) ?? [])
      .length === 2 &&
    !/QueryInformationJobObject\(\s*None/u.test(brokerSupervisorProduction) &&
    !/false\s*&&/u.test(brokerSupervisor) &&
    authenticateBrokerImage.includes("GetLastError()") &&
    authenticateBrokerImage.includes("ERROR_SEM_TIMEOUT") &&
    authenticateBrokerImage.includes("classify_debug_wait_failure") &&
    brokerDebugWaitClassifier.includes("timed_out && Instant::now() >= deadline") &&
    brokerDebugWaitClassifier.includes("DormantBrokerError::Deadline") &&
    brokerDebugWaitClassifier.includes("DormantBrokerError::ProcessProof") &&
    brokerSupervisorProduction.includes("JOB_OBJECT_LIMIT_ACTIVE_PROCESS") &&
    brokerSupervisorProduction.includes("JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE") &&
    brokerJobImplementation.includes("ActiveProcessLimit = 1") &&
    brokerJobImplementation.includes("IsProcessInJob(") &&
    brokerJobImplementation.includes("accounting.ActiveProcesses != 1") &&
    brokerJobImplementation.includes("QueryInformationJobObject(") &&
    brokerJobImplementation.includes("Some(self.raw())") &&
    brokerSupervisorProduction.includes(
      "unsafe impl Send for ProcessObservation {}",
    ) &&
    !brokerSupervisorProduction.includes(
      "unsafe impl Sync for ProcessObservation",
    ) &&
    duplicateBrokerProcessObservation.includes("PROCESS_SYNCHRONIZE.0") &&
    duplicateBrokerProcessObservation.includes("false,") &&
    !/\bfn\s+raw\b/u.test(brokerProcessObservationImplementation) &&
    brokerSupervisor.includes(
      "panic_after_create_terminates_and_reaps_the_exact_child",
    ) &&
    brokerSupervisor.includes(
      "debug_wait_timeout_maps_to_deadline_only_at_absolute_expiry",
    ) &&
    !/\bOpenProcess\s*\(/u.test(
      [brokerChannelProduction, brokerSupervisorProduction].join("\n"),
    ),
  "debug Broker creation must retain full FILE_ID_INFO identity, exact NUL/parent and Job attributes, pre-user-mode ordering, kernel probes, deadlines, cleanup, and no PID reopen",
);
const brokerChannelModuleDocs = brokerChannelProduction.slice(
  0,
  brokerChannelProduction.indexOf("use core::fmt;"),
);
requireInvariant(
  brokerChannelModuleDocs.includes("persistent, secretless, process-bound multi-frame") &&
    brokerChannelModuleDocs.includes("broker_supervisor") &&
    brokerChannelModuleDocs.includes("payload-only `broker::ipc` adapters") &&
    !/(?:one-shot|unimplemented|future exact launcher|constructor intentionally does not exist)/iu.test(
      brokerChannelModuleDocs,
    ) &&
    !platformWindowsLib.includes(
      "This one-shot, secretless native-host/Broker transport proof",
    ) &&
    !platformWindowsLib.includes(
      "composition with `broker::ipc` are still release-blocking",
    ),
  "platform Broker module docs must describe the current persistent debug composition rather than stale future/one-shot blockers",
);
for (const [document, label] of [
  [architectureDocument, "architecture"],
  [brokerProtocolContract, "protocol contract"],
  [nativeHostContractReadme, "native-host README"],
]) {
  requireInvariant(
    /HANDLE_LIST[^\n]*\[restricted\s+parent\s+process,\s*shared\s+read\/write\s+NUL\]/u.test(
      document,
    ) &&
      document.includes("STARTF_USESTDHANDLES") &&
      /(?:stdin, stdout, and stderr[\s\S]{0,100}same NUL|same NUL[\s\S]{0,100}stdin, stdout, and stderr)/u.test(
        document,
      ) &&
      /JOB_LIST[^\n]*\[job\]/u.test(document),
    `${label} must retain the exact parent/NUL HANDLE_LIST, shared NUL standard streams, and one-Job JOB_LIST contract`,
  );
}

requireInvariant(
  brokerLibraryForContract.includes(
    '#[cfg(any(test, all(feature = "ipc-contract-test-hook", debug_assertions)))]',
  ) &&
    brokerMainForContract.includes("std::process::exit(78);") &&
    nativeMain.includes("native_host::run_release_disabled_stream") &&
    nativeMain.includes("std::process::exit(PRIVATE_BROKER_UNAVAILABLE);"),
  "default and release Broker/native-host entrypoints must retain exit-78 gating",
);
requireInvariant(
  /#\[cfg\(any\(test,\s*all\(feature = "ipc-contract-test-hook", debug_assertions\)\)\)\]\s*#\[derive\([^\]]+\)\]\s*pub\(crate\) enum SecretlessLocalOutcome/u.test(
    brokerTransportForContract,
  ) &&
    /#\[cfg\(any\(test,\s*all\(feature = "ipc-contract-test-hook", debug_assertions\)\)\)\]\s*pub\(crate\) fn execute_secretless_local/u.test(
      brokerTransportForContract,
    ) &&
    !brokerLibraryForContract.includes("SecretlessLocalOutcome"),
  "Broker local chain-ID success must remain crate-private and absent outside tests or the debug feature gate",
);
requireInvariant(
  nativeMain.includes("std::env::current_exe()") &&
    nativeMain.includes("executable.set_file_name(") &&
    nativeMain.includes("std::fs::symlink_metadata(&executable)") &&
    nativeMain.includes("metadata.file_type().is_file()") &&
    nativeMain.includes("struct BrokerChildGuard") &&
    nativeMain.includes("impl Drop for BrokerChildGuard") &&
    nativeMain.includes("self.0.kill()") &&
    nativeMain.includes("self.0.wait()") &&
    nativeMain.includes(".env_clear()") &&
    !nativeMain.includes("YOUR_WALLET_BROKER_CONTRACT_EXE") &&
    !nativeProcessContractTest.includes("YOUR_WALLET_BROKER_CONTRACT_EXE"),
  "debug native host must select only its regular-file Broker sibling and reap it on every exit or unwind",
);
requireInvariant(
  brokerIpcContract.includes("BrokerIpcError::Io") &&
    nativeLibraryForContract.includes("FrameError::Io") &&
    !/Io\s*\(\s*#\[source\]|Io\s*\(\s*(?:std::)?io::Error/u.test(
      `${brokerIpcContract}\n${nativeLibraryForContract}`,
    ) &&
    brokerIpcContract.includes("std::error::Error::source(&error).is_none()") &&
    nativeLibraryForContract.includes("std::error::Error::source(&error).is_none()"),
  "native and Broker transport errors must retain only a stable I/O category with no raw source chain",
);
const unavailableWireBlock =
  /struct\s+UnavailableRequestWire\s*\{(?<body>[\s\S]*?)\n\}/u.exec(
    brokerIpcContract,
  )?.groups?.body ?? "";
const unavailableMethodBlock =
  /enum\s+UnavailableMethodWire\s*\{(?<body>[\s\S]*?)\n\}/u.exec(
    brokerIpcContract,
  )?.groups?.body ?? "";
requireInvariant(
  brokerIpcContract.includes("MAX_BROKER_IPC_FRAME_BYTES: usize = 8_192") &&
    brokerIpcContract.includes("MAX_BROKER_IPC_COMMANDS: u64 = 4_096") &&
    brokerIpcContract.includes(
      "summary.commands >= MAX_BROKER_IPC_COMMANDS",
    ) &&
    brokerIpcContract.includes(
      "server_accepts_exact_command_lifetime_and_rejects_the_next_frame_before_dispatch",
    ) &&
    brokerIpcContract.includes("BrokerIpcClient::connect") &&
    brokerIpcContract.includes("pub fn run_secretless_server") &&
    brokerIpcContract.includes("ClientBodyWire::Unavailable") &&
    brokerIpcContract.includes("complete_unavailable(transport)") &&
    unavailableWireBlock.includes("session_id: FixedHex<32>") &&
    unavailableWireBlock.includes("request_sequence: u64") &&
    unavailableWireBlock.includes("activation_nonce: FixedHex<32>") &&
    unavailableWireBlock.includes("request_id: FixedHex<16>") &&
    unavailableWireBlock.includes("method: UnavailableMethodWire") &&
    !/(?:params|message|account|address|origin|method_name|serde_json::Value)/u.test(
      unavailableWireBlock,
    ) &&
    unavailableMethodBlock.includes("PersonalSign") &&
    unavailableMethodBlock.includes("SendTransaction") &&
    !/\bChainId\b/u.test(unavailableMethodBlock),
  "debug unavailable IPC must retain exact frame/session bounds, enum-only correlation, and no chainId replacement",
);
requireInvariant(
  nativeContractBridge.includes('request.method_name() == "eth_chainId"') &&
    nativeContractBridge.includes("broker.complete_unavailable(") &&
    nativeContractBridge.includes("TransportCancellationOutcome::AlreadyCompleted") &&
    nativeContractBridge.includes("return Err(ProtocolError::SessionSequence.into())") &&
    !/(?:KeyAgent|DownstreamExecutor|eth_sendRawTransaction|http::|https::)/u.test(
      nativeContractBridge,
    ),
  "debug native contract must remain chainId-only, completion-bound, and network/signing-free",
);
requireInvariant(
  extensionBackgroundContract.includes(
    "const MAX_NATIVE_CONNECTION_ATTEMPTS = 4_096",
  ) &&
    extensionBackgroundContract.includes(
      "this.sessionId = this.issuePortNonce()",
    ) &&
    extensionBackgroundContract.includes(
      "value.sequence !== this.lastNativeSequence + 1",
    ) &&
    extensionBackgroundContract.includes("this.outboundSequence = 0") &&
    extensionBackgroundContract.includes(
      "sequence = this.nextOutboundSequenceCandidate()",
    ) &&
    extensionBackgroundContract.includes("this.outboundSequence = sequence") &&
    extensionBackgroundContract.includes("normalizeCancelReason(reason)") &&
    extensionBackgroundContract.includes("Number.isSafeInteger(value.code)") &&
    extensionBackgroundContract.includes("value.message.length > 0"),
  "extension reconnect must rotate sessions, reset request sequence, reject response gaps, avoid local sequence holes, normalize cancel reasons, enforce exact RPC errors, and remain bounded",
);
requireInvariant(
  nativeProcessContractTest.includes('"--offline", "--locked"') &&
    nativeProcessContractTest.includes('"--release"') &&
    nativeProcessContractTest.includes('"--all-features"') &&
    nativeProcessContractTest.includes("windowsHide: true") &&
    nativeProcessContractTest.includes("cancelled.disconnect(\"navigation\")") &&
    nativeProcessContractTest.includes("router.reconnectNative()") &&
    nativeProcessContractTest.includes("{ code: 78, signal: null }") &&
    !/(?:puppeteer|playwright|selenium|launchPersistentContext)/iu.test(
      nativeProcessContractTest,
    ),
  "real bridge evidence must stay offline, headless, cancel/reconnect aware, and release-exit-78 checked",
);

const approvalChannel = await text("crates/platform-windows/src/approval_channel.rs");
requireInvariant(
  /pub\s+struct\s+VerifiedApprovalResponse\s*\{\s*decision\s*:/su.test(approvalChannel) &&
    !/impl\s+VerifiedApprovalResponse\s*\{[\s\S]*?pub\s+fn\s+(?:new|from_|for_)/u.test(
      approvalChannel,
    ),
  "verified approval response must remain opaque and externally unconstructible",
);
requireInvariant(
  /pub\s+fn\s+receive\s*\(\s*self\s*\)[\s\S]*?self\.channel\.receive\(self\.helper\)/su.test(
    approvalChannel,
  ) &&
    approvalChannel.includes("RESPONSE_BYTES") &&
    approvalChannel.includes("DeadlineElapsed") &&
    approvalChannel.includes("BindingMismatch"),
  "approval result must consume the held helper and enforce exact wire binding/deadline",
);

const offlineWire = await text("crates/key-agent/src/offline_wire.rs");
const offlineController = await text("crates/key-agent/src/offline_controller.rs");
const offlineService = await text("crates/key-agent/src/offline_service.rs");
const offlineVaultSession = await text("crates/key-agent/src/vault_session.rs");
const offlineControllerProduction = keyAgentProductionFiles.find(
  (file) => file.path === "crates/key-agent/src/offline_controller.rs",
)?.source;
requireInvariant(
  offlineControllerProduction !== undefined,
  "offline controller production source is missing",
);
const checkedDeadlineBody =
  /pub\(crate\)\s+struct\s+CheckedOfflineDeadline<'a>\s*\{(?<body>[\s\S]*?)\n\}/u.exec(
    offlineControllerProduction,
  )?.groups?.body ?? "";
const offlineCommandBody =
  offlineWire.match(/enum\s+OfflineCommand\s*\{([\s\S]*?)\n\}/u)?.[1] ?? "";
for (const command of [
  "Status",
  "Create12",
  "Create24",
  "BeginBackupDisplay",
  "SubmitBackupConfirmation",
  "Open",
  "Lock",
  "GetConfirmedAddress",
]) {
  requireInvariant(
    offlineCommandBody.includes(command),
    `offline lifecycle wire must retain closed command ${command}`,
  );
}
requireInvariant(
  !/(?:Sign|Export|Import|Network|Mnemonic|Password|PrivateKey)/u.test(offlineCommandBody) &&
    offlineWire.includes('const REQUEST_MAGIC: &[u8; 8] = b"YWOFREQ1"') &&
    offlineWire.includes('const RESPONSE_MAGIC: &[u8; 8] = b"YWOFRES1"') &&
    offlineWire.includes("MAX_OFFLINE_REQUEST_BYTES: usize = 64") &&
    offlineWire.includes("MAX_OFFLINE_RESPONSE_BYTES: usize = 64") &&
    offlineWire.includes("request_id: u64") &&
    offlineWire.includes("sequence: u64") &&
    offlineWire.includes("deadline_unix_ms: u64") &&
    /reader\s*\.take\(limit \+ 1\)/u.test(offlineWire) &&
    offlineWire.includes("OfflineWireError::Reserved"),
  "offline lifecycle wire must remain bounded, exact, reserved-zero, and secret/sign/network free",
);
requireInvariant(
  offlineController.includes("trait OfflineFrontendCapabilities") &&
    offlineController.includes("mod sealed") &&
    !offlineController.includes("pub(crate) mod sealed") &&
    offlineController.includes("UnavailableOfflineFrontends") &&
    offlineController.includes("Err(FrontendDispatchError::Unavailable)") &&
    offlineController.includes("struct OfflineFrontendDeadline") &&
    offlineController.includes("expires_at_unix_ms: u64") &&
    offlineController.includes("expires_at_monotonic: Instant") &&
    offlineController.includes("fn monotonic_now") &&
    offlineController.includes("fn checked_deadline<'a, C: OfflineClock>(") &&
    !offlineController.includes("pub(crate) fn checked_deadline") &&
    checkedDeadlineBody.includes("expires_at_monotonic: Instant") &&
    checkedDeadlineBody.includes("clock: &'a mut dyn OfflineClock") &&
    !checkedDeadlineBody.includes("pub ") &&
    !/#\[derive\([^\]]*(?:Clone|Copy)[^\]]*\)\]\s*pub\(crate\)\s+struct\s+CheckedOfflineDeadline/u.test(
      offlineControllerProduction,
    ) &&
    !/impl\s+(?:Clone|Copy)\s+for\s+CheckedOfflineDeadline/u.test(
      offlineControllerProduction,
    ) &&
    keyAgentProductionFiles
      .filter((file) => file.path !== "crates/key-agent/src/offline_controller.rs")
      .every((file) => !file.source.includes("CheckedOfflineDeadline {")) &&
    /#\[cfg\(test\)\]\s*pub\(crate\)\s+fn\s+with_live_test_deadline/u.test(
      offlineControllerProduction,
    ) &&
    /#\[cfg\(test\)\]\s*pub\(crate\)\s+const\s+fn\s+with_parts/u.test(
      offlineControllerProduction,
    ) &&
    !offlineController.includes("_service: &mut OfflineWalletService") &&
    offlineController.includes("MAX_REQUESTS_PER_CHANNEL: usize = 64") &&
    offlineController.includes("OfflineResponseCode::Duplicate") &&
    offlineController.includes("OfflineResponseCode::Replay") &&
    offlineController.includes("OfflineResponseCode::OutOfSequence") &&
    offlineController.includes("self.service.lock()"),
  "offline controller must remain sealed, replay-bounded, and the sole minter of non-clone checked deadlines",
);
requireInvariant(
  offlineService.includes("pending_confirmation: Option<PendingRecoveryConfirmation>") &&
    /fn\s+create_from_input\s*\([^)]*checked_deadline:\s*CheckedOfflineDeadline/u.test(
      offlineService,
    ) &&
    /fn\s+unlock_from_input\s*\([^)]*checked_deadline:\s*CheckedOfflineDeadline/u.test(
      offlineService,
    ) &&
    offlineService.includes("fn display_recovery") &&
    /fn\s+begin_display\s*\([^)]*checked_deadline:\s*CheckedOfflineDeadline/u.test(
      offlineService,
    ) &&
    offlineService.includes("fn confirmation_prompt") &&
    /fn\s+submit_confirmation\s*\([^)]*checked_deadline:\s*CheckedOfflineDeadline/u.test(
      offlineService,
    ) &&
    /fn\s+with_signing_key_checked\s*<R>\s*\([^)]*checked_deadline:\s*CheckedOfflineDeadline/u.test(
      offlineService,
    ) &&
    offlineService.includes("self.pending_confirmation = None") &&
    offlineVaultSession.includes("struct DisplayedRecovery") &&
    offlineVaultSession.includes("session_nonce: Zeroizing<[u8; 32]>") &&
    offlineVaultSession.includes("fn create_checked(") &&
    offlineVaultSession.includes("fn open_checked(") &&
    offlineVaultSession.includes("fn commit_displayed_recovery_checked(") &&
    offlineVaultSession.includes("fn confirm_backup_checked(") &&
    offlineVaultSession.includes("fn with_signing_key_checked<R>(") &&
    /VaultBlob::seal_new[\s\S]*?recheck_deadline\(&mut checked_deadline\)\?;[\s\S]*?self\.storage\.commit\(None/u.test(
      offlineVaultSession,
    ) &&
    /inspect_payload[\s\S]*?recheck_deadline\(&mut checked_deadline\)\?;[\s\S]*?self\.state = next_state/u.test(
      offlineVaultSession,
    ) &&
    /matches_uncommitted_display[\s\S]*?recheck_deadline\(&mut checked_deadline\)\?;[\s\S]*?pending\.display_consumed = true/u.test(
      offlineVaultSession,
    ) &&
    /VaultBlob::reseal[\s\S]*?recheck_deadline\(&mut checked_deadline\)\?;[\s\S]*?\.commit\(Some\(pending\.header\.generation\(\)\), &blob\)/u.test(
      offlineVaultSession,
    ) &&
    offlineController.includes(
      "expiry_after_post_frontend_check_but_before_create_commit_leaves_storage_empty",
    ) &&
    offlineController.includes(
      "expiry_after_open_kdf_but_before_state_activation_leaves_session_locked",
    ) &&
    offlineController.includes(
      "final_display_recheck_prevents_pending_challenge_activation",
    ) &&
    offlineController.includes(
      "expiry_after_confirmation_reseal_but_before_commit_preserves_unconfirmed_generation",
    ),
  "offline recovery must remain split, live-session-bound, capability-gated, and rechecked at each last safe mutation point",
);

// These are the high-level containers most likely to be logged at trust
// boundaries. Runtime regression tests exercise representative payloads; this
// lightweight guard prevents a future return to derived Debug without trying
// to parse or enumerate every nested Rust field here.
const walletContext = await text("crates/wallet-model/src/context.rs");
const walletOperation = await text("crates/wallet-model/src/operation.rs");
const brokerState = await text("crates/broker/src/lib.rs");
const helperBoundary = await text("crates/platform-windows/src/helper.rs");
const nativeWire = await text("crates/native-host/src/wire.rs");
const nativeHost = await text("crates/native-host/src/lib.rs");
const approvalUi = await text("crates/approval-ui/src/lib.rs");
const storageFacade = await text("crates/platform-windows/src/storage.rs");
for (const [source, typeName] of [
  [walletContext, "BrowserContext"],
  [walletOperation, "CanonicalOperation"],
  [approvalWire, "ApprovalDisplay"],
  [approvalWire, "ApprovalResponse"],
  [authorization, "AuthorizationRequest"],
  [approval, "ApprovalBinding"],
  [brokerState, "PermissionStore"],
  [brokerTransport, "TransportBroker"],
  [helperBoundary, "FileIdentity"],
  [helperBoundary, "HelperVerifier"],
  [restrictedLauncher, "HeldProcessIdentity"],
  [nativeHost, "FrameError"],
  [nativeWire, "DispatchOutcome"],
  [nativeWire, "ProtocolError"],
  [approvalUi, "ApprovalError"],
  [secretInput, "SecretInputError"],
  [signer, "SignedCanonicalOperation"],
  [storageFacade, "StoreConfig"],
  [approvalChannel, "VerifiedApprovalResponse"],
]) {
  requireCustomRedactedDebug(source, typeName);
}
requireInvariant(
  nativeHost.includes('#[error("native-messaging I/O failed")]'),
  "FrameError Display must not reproduce its retained I/O source",
);
requireStableDisplay(approvalUi, "ApprovalError", "approval channel I/O failed");
requireStableDisplay(secretInput, "SecretInputError", "secret-input channel I/O failed");

const releaseVerifier = await text("scripts/release/verify-release-offline.ps1");
for (const pinnedInput of [
  "ExpectedReleaseKeyIdSha256",
  "ExpectedReviewerKeyIdSha256",
  "ExpectedSignerCertificateSha256",
]) {
  requireInvariant(
    releaseVerifier.includes(`[Parameter(Mandatory = $true)][ValidatePattern("^[0-9a-f]{64}$")][string]$${pinnedInput}`),
    `offline release verification must require independently pinned ${pinnedInput}`,
  );
}
requireInvariant(
  (releaseVerifier.match(/Invoke-ReleaseCommand\s+-Executable\s+"node"\s+-CommandArguments\s+\$verifyArguments/gu) ?? [])
    .length === 2,
  "offline release verification must rehash and reverify after Authenticode inspection",
);

process.stdout.write("architecture scan passed\n");
