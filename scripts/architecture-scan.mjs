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
const sepoliaDemoManifest = await text("demo/sepolia-wallet/Cargo.toml");
const sepoliaDemoBackend = await text("demo/sepolia-wallet/src/backend.rs");
const sepoliaDemoRpc = await text("demo/sepolia-wallet/src/rpc.rs");
const sepoliaDemoUi = await text("demo/sepolia-wallet/src/ui.rs");
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
    sepoliaDemoBackend.includes(".account_private_key(0)") &&
    sepoliaDemoBackend.includes("pending_generation: Option<PendingGeneratedWallet>") &&
    sepoliaDemoBackend.includes("self.ensure_management_mutation_allowed()?") &&
    sepoliaDemoBackend.includes("path_may_exist(&self.pending_path)"),
  "Sepolia v2 unlock/account-0/pending-quarantine management boundary changed",
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
        path: "crates/platform-windows/src/key_agent_activation.rs",
        api: "CreateProcessW",
      },
      {
        path: "crates/platform-windows/src/launch.rs",
        api: "CreateProcessW",
      },
    ]),
  "production Windows process creation must remain confined to the reviewed dormant activation and restricted launcher call sites",
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
for (const [source, feature] of [
  [brokerMainForContract, "ipc-contract-test-hook"],
  [nativeMain, "broker-ipc-contract-test-hook"],
]) {
  requireInvariant(
    source.includes(
      `#[cfg(all(feature = "${feature}", debug_assertions))]`,
    ) &&
      source.includes(
        `#[cfg(not(all(feature = "${feature}", debug_assertions)))]`,
      ) &&
      !/(?:e?println!|dbg!)/u.test(source),
    `${feature} must remain debug-assertion gated, release-disabled, and silent`,
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
