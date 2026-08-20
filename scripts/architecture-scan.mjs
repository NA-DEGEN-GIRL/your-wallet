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
requireInvariant(
  !rootManifest.includes("demo/sepolia-wallet"),
  "Sepolia demo must remain outside the production workspace",
);
requireInvariant(
  /^publish\s*=\s*false$/mu.test(sepoliaDemoManifest) && /^\[workspace\]$/mu.test(sepoliaDemoManifest),
  "Sepolia demo must remain non-publishable and independently locked",
);
for (const productionSecretCrate of ["secret-core", "key-agent", "platform-windows"]) {
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
const platformWindowsLib = await text("crates/platform-windows/src/lib.rs");
const activationHelper = withoutBottomTestModule(
  await text("crates/platform-windows/src/helper.rs"),
);
const activationArchitecture = await text("docs/architecture.md");
const activationReadme = await text("crates/platform-windows/README.md");
requireInvariant(
  platformWindowsLib.includes("#[cfg(windows)]\nmod key_agent_activation;") &&
    !/pub(?:\([^)]*\))?\s+mod\s+key_agent_activation\b/u.test(platformWindowsLib) &&
    !/pub(?:\([^)]*\))?\s+use\s+[^;]*key_agent_activation/u.test(platformWindowsLib) &&
    platformWindowsLib.includes(
      "use platform_windows::key_agent_activation::HeldKeyAgentActivation;",
    ) &&
    platformWindowsLib.includes(
      "use platform_windows::key_agent_activation::activate_key_agent;",
    ),
  "Key Agent activation module and capability must remain externally private",
);
const heldActivationBlock =
  /pub\(crate\)\s+struct\s+HeldKeyAgentActivation\s*\{(?<body>[\s\S]*?)\n\}/u.exec(
    keyAgentActivation,
  )?.groups?.body ?? "";
const heldActivationImplStart = keyAgentActivation.indexOf("impl HeldKeyAgentActivation {");
const heldActivationImplEnd = keyAgentActivation.indexOf(
  "impl fmt::Debug for HeldKeyAgentActivation",
);
const heldActivationImpl = keyAgentActivation.slice(
  heldActivationImplStart,
  heldActivationImplEnd,
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
      ]) &&
    /impl\s+Drop\s+for\s+HeldKeyAgentActivation[\s\S]*?self\.process\.abort\(\)/u.test(
      keyAgentActivation,
    ) &&
    !/#\[derive\([^\]]*(?:Clone|Copy)[^\]]*\)\]\s*pub\(crate\)\s+struct\s+HeldKeyAgentActivation/u.test(
      keyAgentActivation,
    ),
  "held Key Agent activation must remain opaque, non-clone, detached-only, and drop-aborting",
);
const activationGatePositions = [
  "if !artifact.is_key_agent()",
  "if !attestation.signing_enabled()",
  "if !attestation.allows_helper_manifest(artifact.manifest_digest())",
  "if !artifact.path().is_absolute()",
  "run_on_fresh_debug_thread(move || activate_key_agent_on_debug_thread(artifact))",
].map((marker) => keyAgentActivation.indexOf(marker));
requireInvariant(
  activationGatePositions.every((position) => position !== -1) &&
    activationGatePositions
      .slice(1)
      .every((position, index) => position > activationGatePositions[index]),
  "Key Agent role, release, manifest, and path gates must precede worker creation",
);
const genericKeyAgentGatePositions = [
  "if helper.is_key_agent()",
  "return Err(LaunchError::KeyAgentRequiresSupervisorActivation);",
  "self.require_allowed_helper(helper.manifest_digest())",
].map((marker) => restrictedLauncherProduction.indexOf(marker));
const publicGenericSpawn = rustFunctionBlock(restrictedLauncherProduction, "spawn");
const privateSecretSpawn = rustFunctionBlock(
  restrictedLauncherProduction,
  "spawn_secret_input",
);
requireInvariant(
  restrictedLauncherProduction.includes(
    "KeyAgentRequiresSupervisorActivation",
  ) &&
    genericKeyAgentGatePositions.every((position) => position !== -1) &&
    genericKeyAgentGatePositions
      .slice(1)
      .every((position, index) => position > genericKeyAgentGatePositions[index]) &&
    restrictedLauncherProduction.match(
      /self\.require_allowed_one_shot_helper\(helper\)\?;/gu,
    )?.length === 2 &&
    restrictedLauncherProduction.match(/sys::launch\(helper,/gu)?.length === 2 &&
    publicGenericSpawn.indexOf("self.require_allowed_one_shot_helper(helper)?;") <
      publicGenericSpawn.indexOf("sys::launch(helper, handles, self.profile, false)") &&
    privateSecretSpawn.indexOf("self.require_allowed_one_shot_helper(helper)?;") <
      privateSecretSpawn.indexOf("sys::launch(helper, handles, self.profile, true)"),
  "generic restricted launch paths must reject the Key Agent before allowlist evaluation and Win32 launch",
);
const debugWorkerPositions = [
  "let artifact_identity = sys::exact_file_identity(artifact.raw_handle())?;",
  "let mut process = sys::SuspendedDebuggee::create(&artifact)?;",
  ".authenticate_first_event(",
  "process.detach_still_suspended()",
  "let process = process.into_detached()?;",
  "Ok(HeldKeyAgentActivation {",
].map((marker) => keyAgentActivation.indexOf(marker));
requireInvariant(
  keyAgentActivation.includes("std::thread::Builder::new()") &&
    keyAgentActivation.includes(".spawn(worker)") &&
    keyAgentActivation.includes(".join()") &&
    keyAgentActivation.match(/KeyAgentActivationError::ActivationWorker/gu)?.length === 2 &&
    debugWorkerPositions.every((position) => position !== -1) &&
    debugWorkerPositions
      .slice(1)
      .every((position, index) => position > debugWorkerPositions[index]) &&
    keyAgentActivation.match(/run_on_fresh_debug_thread\(/gu)?.length === 1,
  "one fresh OS worker must own the complete Key Agent debug-event lifecycle",
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
      ]) &&
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
    /fresh dedicated\s+debugger OS thread/u.test(activationReadme) &&
    activationReadme.includes("all-zero and all-`FF`") &&
    activationReadme.includes("no resume API"),
  "Key Agent activation limitations and type-state proof must remain documented",
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
    nativeMain.includes("native_host::run_unattested_once") &&
    nativeMain.includes("std::process::exit(PRIVATE_BROKER_UNAVAILABLE);"),
  "native host main must retain its unattested response path and exit 78",
);
const nativeWireForActivation = await text("crates/native-host/src/wire.rs");
requireInvariant(
  nativeWireForActivation.includes("const UNAVAILABLE_CODE: i64 = 4_900;") &&
    nativeWireForActivation.includes("code: UNAVAILABLE_CODE") &&
    nativeWireForActivation.includes("pub fn run_unattested_once"),
  "native host unattested path must retain stable provider code 4900",
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
