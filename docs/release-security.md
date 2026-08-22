# Private Mainnet Canary release security

## Current status

This repository contains a fail-closed release-evidence scaffold. It does **not** contain a release signing key, reviewer key, Authenticode certificate, production installer, stable Chrome extension ID, published update, or completed release evidence bundle. Running the normal repository gate or the release-policy tests cannot install, sign, publish, or mark a build eligible.

The only command allowed to print an eligibility result is `verify-release-offline.ps1` from an independently pinned, write-protected verifier toolset. It succeeds only after its mapped Node image and module graph, the signed manifest, every hashed bundle file, independently signed review attestation, exact Windows negative-test set, independently pinned Authenticode and stable extension identities, installer evidence, checkpointed lineage, and key-lifecycle drills verify together. This release evidence does not waive any application-level STOP-SHIP item.

## Commands and trust separation

The CI-safe check is read-only apart from test-owned temporary directories:

```powershell
$systemPowerShell = [System.IO.Path]::Combine([System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::System), "WindowsPowerShell", "v1.0", "powershell.exe")
$nodeExecutable = $ExecutionContext.InvokeCommand.GetCommand("node", [System.Management.Automation.CommandTypes]::Application).Path
& $systemPowerShell -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File scripts/release/check.ps1 all -NodeExecutable $nodeExecutable
```

It parses every release script, audits the extension source, runs deterministic policy tests, and verifies deterministic PowerShell packaging helpers. The caller must select the absolute Node application path explicitly; the sealed gate rejects relative input, never resolves `node` through its own `PATH`, requires every child to exit zero with empty stderr, and applies exact stdout sentinels to both PowerShell behavior tests. It never invokes a release build or asks for credentials.

The manual `release-evidence-policy` workflow requires exact cargo-audit/OSV Scanner versions, scanner-binary hashes, and immutable RustSec/OSV database identifiers and hashes. It validates only their shape and the repository policy tests, prints `POLICY_INPUTS_VALIDATED_NOT_RELEASE_ELIGIBLE`, and deliberately does not download a scanner, build, sign, upload, install, or publish anything.

Unsigned preparation is an explicit, separate ceremony:

```powershell
$systemPowerShell = [System.IO.Path]::Combine([System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::System), "WindowsPowerShell\v1.0\powershell.exe")
& $systemPowerShell -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File scripts/release/prepare-unsigned.ps1 `
  -OutputDirectory .\release-preparation
```

Preparation refuses a dirty or uncommitted worktree and ambient Cargo target/flags. It uses `cargo vendor --frozen`, creates two clean directories from the same `git archive`, adds the same audited vendor tree to each, and runs the workspace binary build with `--frozen --offline --locked`. `CARGO_INCREMENTAL=0`, the commit timestamp, the pinned Rust toolchain, the Windows MSVC target, and `/Brepro` are explicit. It compares every unsigned payload byte and stops if the inventories differ.

The command also creates deterministic, uncompressed extension ZIPs with sorted entries and fixed ZIP timestamps; an SPDX 2.3 SBOM; dependency, build-script, proc-macro, feature, and license inventories; source/toolchain/lockfile/vendor hashes; and a static extension audit. Its output contains `INELIGIBLE.txt`. Missing cached crates cause an offline failure; dependency acquisition is a separate audited provisioning action.

Private keys are deliberately out of scope. No repository command generates, imports, stores, or uses a private signing key. Canonical files must be signed by an offline hardware-backed process outside the repository. Only public-key identification and signature verification are implemented here.

## Extension audit policy

`audit-extension.mjs` packages and checks only `manifest.json` and the statically reachable files in `extension/src`.

The audit requires:

- Manifest V3, no incognito operation, and the exact reviewed `nativeMessaging` and `storage` permissions;
- the reviewed HTTPS-only, top-frame, document-start MAIN/ISOLATED script declarations;
- a local module graph with no unreferenced executable source;
- no remote URL in executable source, dynamic import, `eval`, `Function`, WebAssembly, HTML injection sink, runtime script injection, direct network API, or string-based timer execution;
- bounded regular UTF-8 files with no symbolic-link traversal.

The audit is intentionally strict. A manifest capability or new packaged source file requires a policy/code-review change, not an automatic allowance.

## Final bundle layout

Platform signing and installer creation happen outside `prepare-unsigned.ps1`. Assemble a new directory with exactly these payload names and the evidence paths below. Do not convert `release-preparation` in place; retain its unsigned payload and reproducibility report as immutable input evidence.

```text
release-bundle/
  payload/
    approval-ui.exe
    broker.exe
    dashboard.exe
    extension-package.zip
    key-agent.exe
    native-host.exe
    secret-input-ui.exe
    your-wallet-canary.msi
  evidence/
    Cargo.lock
    cargo-vv.txt
    dependencies.json
    extension-audit.json
    installer-acl-negative.json
    key-revocation-drill.json
    key-rotation-drill.json
    licenses.json
    native-host-manifest.json
    native-host-registration.json
    osv-advisory.json
    osv-raw.json
    reproducibility.json
    review-attestation.json
    review-attestation.sig
    review-public-key.pem
    rustsec-advisory.json
    rustsec-raw.json
    rust-toolchain.toml
    rustc-vv.txt
    sbom.spdx.json
    source.zip
    vendor-inventory.json
    authenticode.json
    windows-negative/<one JSON file for every required test ID>
```

The extension package in the final bundle must be the exact deterministic unsigned ZIP from the reproducibility run. All EXEs and the MSI must be Authenticode-signed by the independently pinned leaf certificate. The installer must install executables, the native-host manifest, and registration data into non-user-writable locations without reparse-point traversal or a writable DLL search path.

The production Chrome extension ID is an external release input. It must match the store/self-hosted production identity and the native-host manifest's sole `allowed_origins` entry. Final verification requires the same exact 32-character lowercase `a` through `p` ID again as an independently sourced `ExpectedExtensionId`; it is not derived from the candidate bundle, installer evidence, native-host manifest, or previous manifest. A mismatch is rejected before bundle/evidence reads without echoing either ID. Every successor manifest must retain the previous release's exact extension ID. The final verifier also strictly parses the exact hashed native-host manifest, requires host name `com.your_wallet.native`, type `stdio`, one matching Chrome-extension origin, and an absolute Windows path whose basename is `native-host.exe`. A development/unpacked extension ID is not acceptable evidence.

## Hashing and Authenticode evidence

After platform signing and installer creation, compute the final payload commitment:

```powershell
node scripts/release/hash-payload.mjs `
  --payload-root .\release-bundle\payload `
  --output .\payload-hashes.json
```

The command prints the artifact-set SHA-256. Supply that value and the independently pinned Authenticode leaf-certificate SHA-256 to the Windows verifier:

```powershell
$systemPowerShell = [System.IO.Path]::Combine([System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::System), "WindowsPowerShell\v1.0\powershell.exe")
& $systemPowerShell -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File scripts/release/verify-authenticode.ps1 `
  -PayloadDirectory .\release-bundle\payload `
  -ArtifactSetSha256 <64-lower-hex> `
  -ExpectedSignerCertificateSha256 <64-lower-hex> `
  -OutputPath .\release-bundle\evidence\authenticode.json
```

The script invokes Windows Authenticode verification for every EXE and the MSI, rejects an invalid/missing signature, rejects any leaf certificate other than the independently pinned certificate, and binds the report to the final artifact set. Entries are emitted once each in canonical payload-path order. The final Node verifier independently requires that every manifest artifact and every report entry name that same pinned certificate hash. It never signs a file.

## Mandatory external evidence

All JSON evidence uses printable ASCII, string-encoded integers, strict unique keys, and the exact schema consumed by `release-manifest.mjs`. Evidence files are hashed into the release manifest. The final verifier reparses their contents and checks their bindings; a file with a correct name but unrelated content is rejected. The independently signed review additionally commits to the byte length, exact path, and SHA-256 of every evidence file and every Windows-negative log except the review attestation and its detached signature. Those two exclusions are the only way to avoid a signature cycle; `review-public-key.pem` remains inside the reviewed set.

### Exact Windows negative tests

Every test file uses schema `your-wallet-windows-negative-test-v1` and has exactly these fields:

```json
{
  "artifactSetSha256": "<final artifact-set SHA-256>",
  "id": "<required ID>",
  "osBuild": "10.0.00000.0000",
  "profile": "private-mainnet-canary",
  "result": "pass",
  "schema": "your-wallet-windows-negative-test-v1",
  "sourceCommit": "<Git commit>"
}
```

The exact, lexically ordered IDs are:

1. `helper-binary-hash-mismatch`
2. `helper-binary-reparse-point-rejected`
3. `helper-binary-signing-leaf-mismatch`
4. `helper-child-identity-mismatch`
5. `helper-handle-inheritance-allowlist`
6. `helper-job-kill-on-close`
7. `helper-no-network-sandbox`
8. `named-pipe-current-sid-dacl-denies-other-user`
9. `named-pipe-first-instance-squatting`
10. `named-pipe-rejects-remote-client`
11. `native-host-registry-wrong-extension-id`
12. `vault-crash-after-replace`
13. `vault-crash-before-replace`
14. `vault-file-acl-denies-other-user`
15. `vault-reparse-point-rejected`
16. `vault-rollback-detected`
17. `virtual-lock-failure`

A generic unit-test log, skipped test, simulation, or report from a different Windows build/commit/artifact set is not accepted.

### RustSec and OSV advisory evidence

Dependency inventory is not a vulnerability scan. Release eligibility requires both an offline RustSec scan and an offline OSV scan against explicit immutable database snapshots. Neither scanner is installed or downloaded by repository automation.

The release operator must independently obtain and review pinned scanner binaries, record each binary's SHA-256, provision immutable advisory snapshots, then execute the scanners outside the check-only gate. `rustsec-raw.json` and `osv-raw.json` retain the native scanner outputs. Their companion canonical attestations are hashed into the release manifest and must report zero vulnerabilities and zero accepted warnings/findings.

`rustsec-advisory.json` uses schema `your-wallet-rustsec-advisory-evidence-v1`. It binds the candidate commit and Cargo.lock hash to scanner `cargo-audit`, an exact semantic version, scanner-binary SHA-256, RustSec database commit/tree SHA-256, raw-report SHA-256, `vulnerabilitiesFound: "0"`, `acceptedWarnings: "0"`, and `result: "pass"`.

`osv-advisory.json` uses schema `your-wallet-osv-advisory-evidence-v1`. It binds the same candidate and lockfile to scanner `osv-scanner`, an exact semantic version, scanner-binary SHA-256, UTC database snapshot ID, database snapshot SHA-256, raw-report SHA-256, `vulnerabilitiesFound: "0"`, `acceptedFindings: "0"`, and `result: "pass"`.

The exact tool versions, binary hashes, and database identifiers/hashes are release inputs, not floating `latest` references. Updating any one requires regenerating the reports and manifest. Because those pinned tools and snapshots are absent in this repository, advisory clearance is currently STOP-SHIP.

### Independent security review

The independent reviewer uses a signing key distinct from the release-manifest key. The public key is `review-public-key.pem`; `review-attestation.sig` is canonical base64 for the raw 64-byte Ed25519 signature over the exact bytes of `review-attestation.json`.

Both Windows wrappers must run from a separately staged verifier toolset, not from the working repository and not from inside the candidate bundle. The approved runtime tree has exactly four directories and these seven files, with the spelling and casing shown and no other entry:

```text
node.exe
extension/native-host/validate-manifest.mjs
scripts/release/common.ps1
scripts/release/release-manifest.mjs
scripts/release/review-evidence-set.mjs
scripts/release/review-evidence-set.ps1
scripts/release/verify-release-offline.ps1
```

An operator can prepare those bytes without making an eligibility claim:

```powershell
$systemPowerShell = [System.IO.Path]::Combine([System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::System), "WindowsPowerShell\v1.0\powershell.exe")
& $systemPowerShell -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File scripts/release/prepare-verifier-toolset.ps1 `
  -NodeExecutable <independently-reviewed-node.exe> `
  -OutputDirectory .\verifier-toolset-staging `
  -OperatorConfirmedPreparationOnly
```

The preparation command prints `VERIFIER_TOOLSET_SHA256=<64-lower-hex>` followed by `VERIFIER_TOOLSET_PREPARED_NOT_RELEASE_ELIGIBLE`. Treat that digest as provisional until the exact transferred tree has been independently reviewed and recomputed on its write-protected destination. Record only that independently confirmed aggregate through a separately controlled checkpoint. The destination medium or access control must deny the verifier token both file and subdirectory creation in every directory. The script's read-only attributes are only staging hygiene; they do not prove effective write protection. Never take the expected aggregate from the candidate bundle or from a command copied out of it. A failed preparation deliberately leaves its partial directory in place and refuses to reuse it; do not treat it as a success marker, and review then discard it before rerunning with a new absent output path.

The repository architecture gate recursively inventories every `.ps1`, `.psm1`,
and `.psd1` source outside its explicit generated and control-directory
exclusions. Each entry must use an unambiguous accepted encoding and match both
the exact approved path inventory and its reviewed raw-byte SHA-256 pin in
`scripts/architecture-scan.mjs`; any PowerShell source edit or addition must
update that table explicitly. This is a repository change-review checkpoint,
not an independent trust anchor for the scanner or a way for already executing
release code to authenticate itself.

The same architecture gate discovers the five top-level release-policy
`.test.mjs` suites as one exact regular-file inventory and derives both semantic
analysis and raw-byte SHA-256 from each file's single read. The release check
also requires those exact ordered filenames and hashes before it starts Node;
retaining a suite name or test count while hollowing a callback therefore fails
the reviewed gate. This is deterministic regression protection, not a security
boundary against a same-user process that can rewrite developer-check inputs
concurrently.

Every release entry that consumes `common.ps1` sets `$PSModuleAutoLoadingPreference` to `None` as its first executable statement and performs the PowerShell bootstrap preflight before it opens any caller-controlled release, toolset, or candidate path. The preflight accepts only the exact system 64-bit Desktop Windows PowerShell 5.1 image and the exact engine argument vector `-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File <current-entry>`; abbreviations, extra engine options, a different `-File` target, 32-bit hosts, PowerShell Core, and non-system images fail closed. `common.ps1` then requires exactly zero loaded modules, zero pre-existing protected `YourWallet.*` types, zero long-form aliases, and zero function, alias, script, or application shadows for its critical commands. It never searches `PSModulePath`: it imports only the absolute manifests `Microsoft.PowerShell.Management\Microsoft.PowerShell.Management.psd1`, `Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1`, and `Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1` beneath `$PSHOME\Modules`. It deliberately does not import the script-based `Microsoft.PowerShell.Archive` module. Authenticode inspection and `Add-Type` compilation invoke their already verified `CmdletInfo` objects directly rather than resolving a command name. ZIP handling retains exact framework `Type` and enum identities from the strong-named GAC assemblies after validating their system location, and source extraction rejects traversal, automatic `~`-form DOS 8.3 aliases, device-name aliases, duplicate Windows paths, reparse output, and symbolic-link entries. Generic build-tool names are resolved specifically as `Application` commands and invoked by the resulting absolute path, so same-name functions or aliases cannot intercept them. Any bootstrap mismatch is rejected before release data is opened, so module/type/command cleanliness is a code-enforced invariant rather than an operator-supplied host assumption.

At ceremony time the wrapper derives the toolset root from its own location. It requires the exact case-sensitive printable-ASCII tree, one default data stream and one hard link per runtime file, read-only attributes, failed create-new file and subdirectory probes in every directory, the independently checkpointed aggregate, and complete retained volume/file identities. The toolset and candidate trees must be disjoint. The expected aggregate is a consistency and version pin for the already trusted wrapper/toolset; it cannot make an untrusted `common.ps1`, wrapper, exact system PowerShell image, or Windows OS authenticate itself. Invoke the write-protected entry through the system path variable and exact engine flags shown here; the entry independently validates that bootstrap before accepting the runtime tree.

The attestation schema is `your-wallet-independent-security-review-v2` and includes the release profile/version, source commit, final artifact-set hash, exact `reviewedEvidenceSetSha256`, reviewer public-key ID, `independenceAttestation: "pass"`, and zero open Critical/High findings. `reviewedEvidenceSetSha256` is the SHA-256 of the canonical, exact-path-ordered array of `{bytes,path,sha256}` records for every mandatory evidence file other than `review-attestation.json` and `review-attestation.sig`, plus all 17 Windows-negative logs. A v1 attestation fails closed. Its `scope` array must have this exact order:

1. `browser-origin-document-lifetime`
2. `canonical-encoding`
3. `chain-rpc-ssrf`
4. `dependency-advisory-license`
5. `display-sign-binding`
6. `eip712-and-high-risk-signing`
7. `entropy-key-lifecycle`
8. `nonce-broadcast`
9. `recovery`
10. `release-update`
11. `secret-input-memory`
12. `vault-derivation-signing`

Before creating either `review-attestation.json` or `review-attestation.sig`, stage every other mandatory evidence file, all 17 Windows-negative logs, and `review-public-key.pem` on the reviewer's separately controlled, read-only tree. Do not copy a digest out of the candidate manifest. The read-only subject command walks that exact evidence subtree itself, rejects missing, extra, case-aliased, reparse, non-regular, or hard-linked files, pins each opened file while hashing it, and prints one canonical JSON subject. It neither reads a candidate manifest nor claims release eligibility:

```powershell
$systemPowerShell = [System.IO.Path]::Combine([System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::System), "WindowsPowerShell\v1.0\powershell.exe")
& $systemPowerShell -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File <write-protected-verifier-toolset>\scripts\release\review-evidence-set.ps1 `
  -BundleRoot .\release-bundle `
  -ExpectedVerifierToolsetSha256 <independently-checkpointed-64-lower-hex> `
  -OperatorConfirmedNetworkIsolation
```

The Windows wrapper requires the entire staging tree to be effectively read-only and non-reparse. It parses the raw command line into an exact, case-sensitive, duplicate-free named-argument dictionary inside its protected failure boundary, then opens the requested root, derives a local volume-GUID path from that handle, locks every canonical ancestor from the volume root down with no delete sharing, and requires the bootstrap root and canonical root to match by non-sentinel volume serial plus the complete 128-bit `FILE_ID_INFO`. The original path alias is then discarded. It retains those directory handles and every read-only file handle with no write/delete sharing across the calculation.

The sealed Node runner does not use a PowerShell function, alias, or `PATH` lookup. One fresh, one-shot verifier thread owns process creation, every debug event, mapped-image authentication, continuation, detach, and fail-closed debugger-thread exit. It creates the pinned `node.exe` hidden with an exact three-variable environment, closed stdin, byte-bounded stdout/stderr, no addon or global module search, and a hard timeout. The first pre-user-mode `CREATE_PROCESS_DEBUG_EVENT` image handle must match the retained Node handle by the full volume serial and 128-bit file ID before the guarded primary thread is released. The three JavaScript modules are then read only through their retained volume-GUID paths and evaluated as one in-memory `vm.SourceTextModule` graph in a distinct, string/wasm-code-generation-disabled context with only the pinned source's required `Buffer` and `TextDecoder` globals plus a minimal `node:process` facade. The two repository-relative edges shown by the source graph and the five required `node:` built-ins are the entire static/dynamic module-resolution allowlist. Thus neither a DOS-device remap nor an ambient `NODE_OPTIONS`, preload, function, or fake `node.exe` can redirect the executable or module bytes. The VM context prevents accidental ambient CommonJS/global lookup; it is not a hostile-JavaScript sandbox, so the independently reviewed source bytes and toolset aggregate remain part of the trust boundary.

The review entry runs exactly once with only the pinned bundle volume path. The Node core enumerates each volume-path parent to require the requested on-disk spelling exactly before it walks the evidence tree. The wrapper requires exit zero, zero stderr bytes, and exactly one canonical subject followed by one LF; CRLF, a BOM, trailing bytes, or diagnostics fail closed. It repeats the tree checks and releases the handles only after the subject is fixed. A junction, mount alias, drive alias, UNC path, unsupported filesystem identity, ancestor retarget, or case-only `evidence` alias therefore fails closed or cannot redirect the subject calculation. The release gate exercises this behaviorally with a staged exact toolset: it rejects a volume-GUID tree whose root entry is spelled `Evidence`; a successful wrapper ceremony is paused at its pinned child, a live rename probe proves the canonical root is still locked, its ancestor junction is retargeted from tree A to different valid tree B, and the exact emitted bytes must still be A plus one LF. Running the Node core alone does not establish the Windows share-mode, mapped-image, module-graph, volume-identity, or offline-ceremony guarantees. Unknown, missing, duplicate, or wrong-case parameters and all later wrapper failures emit only one fixed category line and never echo the supplied or resolved path.

The reviewer copies the command's exact `reviewedEvidenceSetSha256` into the v2 draft, verifies the final artifact-set/source/version inputs independently, and only then canonicalizes and signs. The reviewer can calculate a public-key ID and canonicalize the unsigned attestation without exposing a private key:

```powershell
node scripts/release/release-manifest.mjs key-id --public-key .\review-public-key.pem
node scripts/release/release-manifest.mjs canonicalize-json `
  --input .\review-attestation.draft.json `
  --output .\review-attestation.json
```

The signature is produced externally. After adding only the resulting canonical attestation and detached signature, assembly independently recomputes the same evidence-set commitment from its freshly hashed file records and refuses a mismatch. Final verification recomputes it again after byte-for-byte bundle verification and before accepting the reviewer signature. Replacing a native-host/installer record, advisory report or policy-bound record, reviewer public key, or Windows-negative log therefore requires a new independent review signature; merely re-signing the release manifest is insufficient. Self-review, a reviewer key equal to the release key, omitted scope, stale evidence-set commitment, or any open Critical/High finding is an unconditional refusal.

### Installer and native-host registration

`installer-acl-negative.json` uses schema `your-wallet-installer-acl-evidence-v1`, result `pass`, and binds `extensionId`, `installerSha256`, and `nativeHostManifestSha256`. Its `tests` array is exactly:

```json
["install-directory-not-user-writable","native-host-manifest-not-user-writable","path-reparse-rejected"]
```

`native-host-registration.json` uses schema `your-wallet-native-host-registration-evidence-v1`, result `pass`, and binds `extensionId`, `nativeHostName`, and `nativeHostManifestSha256`. Its `tests` array is exactly:

```json
["allowed-origin-exact","registry-user-scope","wrong-extension-id-rejected"]
```

### Release-key rotation and revocation drills

`key-rotation-drill.json` and `key-revocation-drill.json` use schemas `your-wallet-key-rotation-drill-v1` and `your-wallet-key-revocation-drill-v1`. Each contains exactly `performedAtUtc`, `releaseKeyIdSha256`, `result`, `schema`, `sourceCommit`, and `version`. The result must be `pass`; the timestamp is whole-second UTC; and the commit, version, and Ed25519 public-key ID must match the candidate.

These are evidence of a performed recovery exercise, not a key generator. The exercise must demonstrate an offline recovery copy, loss/compromise handling, a blocked old key, operator communications, and restoration of an independently trusted public-key checkpoint. Never put a private key or recovery material in an evidence file.

## Manifest assembly, external signing, and verification

Calculate release and reviewer key IDs from public keys only. Run the independent evidence-set subject/signing sequence above before adding the two excluded review files. After the complete evidence tree is present, assemble a canonical unsigned manifest:

```powershell
node scripts/release/assemble-manifest.mjs `
  --bundle-root .\release-bundle `
  --output .\release-manifest.json `
  --source-commit <40-or-64-lower-hex> `
  --version 0.1.0 `
  --sequence 1 `
  --extension-id <32-lowercase-a-through-p> `
  --native-host-name com.your_wallet.native `
  --cargo-audit-version <exact-semver> `
  --cargo-audit-binary-sha256 <64-lower-hex> `
  --rustsec-db-commit <40-or-64-lower-hex> `
  --rustsec-db-tree-sha256 <64-lower-hex> `
  --osv-scanner-version <exact-semver> `
  --osv-scanner-binary-sha256 <64-lower-hex> `
  --osv-db-snapshot-id <whole-second-UTC> `
  --osv-db-snapshot-sha256 <64-lower-hex> `
  --release-public-key .\release-public-key.pem
```

For every release after sequence 1, add `--previous .\accepted-previous-manifest.json`. Assembly binds the previous manifest's canonical SHA-256, sequence, and version. The verifier rejects omitted lineage, hash substitution, non-consecutive sequence, equal version, rollback, or any extension-ID change. Verify the previous release signature against the locally accepted checkpoint before using it; a filename alone is not a trust anchor. Record its canonical SHA-256 and production extension ID separately because final verification requires both independently pinned values.

The assembly command writes `UNSIGNED_CANONICAL_MANIFEST_WRITTEN_NOT_RELEASE_ELIGIBLE`. Sign the exact manifest bytes outside this repository with the offline hardware-backed Ed25519 release key. Store only the raw 64-byte signature encoded as canonical base64 in `release-manifest.sig`. Do not add a newline before signing and do not commit a private key.

On a separately controlled Windows verification system with networking physically or administratively disabled, run:

```powershell
$systemPowerShell = [System.IO.Path]::Combine([System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::System), "WindowsPowerShell\v1.0\powershell.exe")
& $systemPowerShell -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File <write-protected-verifier-toolset>\scripts\release\verify-release-offline.ps1 `
  -Manifest .\release-manifest.json `
  -Signature .\release-manifest.sig `
  -ReleasePublicKey .\release-public-key.pem `
  -BundleRoot .\release-bundle `
  -ExpectedReleaseKeyIdSha256 <independently pinned 64-lower-hex> `
  -ExpectedExtensionId <independently pinned 32-lowercase-a-through-p> `
  -ExpectedReleaseSequence <independently pinned canonical decimal> `
  -ExpectedReviewerKeyIdSha256 <independently pinned 64-lower-hex> `
  -ExpectedSignerCertificateSha256 <independently pinned 64-lower-hex> `
  -ExpectedVerifierToolsetSha256 <independently checkpointed 64-lower-hex> `
  -OperatorConfirmedNetworkIsolation
```

`ExpectedReleaseSequence` is a mandatory external assertion in exact canonical decimal form `[1-9][0-9]{0,31}`. Sequence `1` is authorized only for a deliberately empty initial-release ledger and forbids both `-PreviousManifest` and `-ExpectedPreviousManifestSha256`. For every successor, derive the expected value as the canonical increment of the last accepted sequence in the write-protected, rollback-resistant offline checkpoint; every value greater than `1` requires the previous manifest and its checkpointed SHA-256 as an exact pair. The wrapper and Node entry point enforce this shape before opening or reading any candidate manifest, previous manifest, signature, key, bundle, or evidence tree. After the candidate manifest is parsed, Node compares its exact sequence with the external assertion immediately after the independent release-key and extension-ID pins and before any bundle or evidence read. Thus an older, correctly signed sequence-1 bundle cannot be replayed when the offline checkpoint expects a successor.

For non-initial releases, add both `-PreviousManifest .\accepted-previous-manifest.json` and `-ExpectedPreviousManifestSha256 <independently pinned 64-lower-hex>`. Supplying only one is refused. The expected release sequence and previous-manifest hash must come only from the write-protected, rollback-resistant offline checkpoint and its canonical successor calculation, never from the candidate bundle, a copied command, or a merely separate but rollbackable source. The two expected key IDs, certificate hash, stable extension ID, and verifier-toolset aggregate must come from that checkpoint or another independently controlled trusted source. The switch records an operator assertion; software cannot prove physical network isolation. The command pins the extension ID and release sequence immediately after the release-key identity and before bundle/evidence reads, hashes all payload/evidence files, validates every attestation and independent-review signature, verifies lineage and the release signature, reruns Windows Authenticode validation, then repeats the complete bundle and signature verification through the same held executable/module identities and immutable argument list. Both passes must return exit zero, no stderr, and exactly `CRYPTOGRAPHIC_BUNDLE_VERIFICATION_PASS_REQUIRES_WINDOWS_WRAPPER` plus one LF. Only then can it print `PRIVATE_MAINNET_CANARY_RELEASE_ELIGIBLE_AFTER_OFFLINE_VERIFICATION`.

Record the accepted sequence, version, canonical manifest hash, stable extension ID, release public-key ID, reviewer public-key ID, and Authenticode certificate hash in a write-protected offline checkpoint. Local state alone does not resist disk/snapshot rollback; restoring an older machine image must require reconciliation with that independent checkpoint.

Final verification refuses a bundle root, descendant, manifest, signature, public key, previous manifest, or verifier runtime entry that is not marked read-only, and rejects reparse points, hard-linked runtime/bundle files, missing entries, and unlisted files/directories. Mark the complete staging tree and external inputs read-only before invoking the command. A read-only attribute alone is deliberately insufficient: the wrapper attempts separate uniquely named create-new file and empty-subdirectory probes in every bundle and toolset directory and refuses eligibility unless both operations are denied to the verifier token (or the medium reports write protection), including the checks around Authenticode inspection. As with the review subject wrapper, it first converts the exact raw arguments into a case-sensitive duplicate-free dictionary inside the protected boundary; every root and external input is then bootstrap-opened, converted to a handle-derived local volume-GUID path, pinned through its full canonical ancestor chain, and matched by non-sentinel volume serial plus all 128 file-ID bits before the original aliases are discarded. It holds every directory, input file, runtime file, and the authenticated mapped Node image across both cryptographic passes, Authenticode inspection, and eligibility output. This binds the path-based checks to the same objects and bytes even if an untrusted ancestor alias or DOS-device mapping is retargeted during the ceremony; access-controlled read-only media remains mandatory because owner/DACL changes by a same-user privileged process and mutation after verification exits are outside the script's proof. Parameter-binding, preflight, child-output, and process-identity failures collapse to one fixed wrapper error line without path disclosure.

## Guarantees and non-guarantees

This scaffold guarantees, when its final verifier succeeds, byte-level binding among the independently pinned exact verifier toolset, authenticated mapped Node image and in-memory module graph, exact canonical signed manifest, mandatory external release sequence, fixed role-to-path artifact set, fixed evidence paths, source/vendor/toolchain/lockfile records, the independently pinned stable extension identity, final native-host/installer identity, exact Windows tests, independently pinned signing identities, and independently signed review. The review signature binds the payload artifact-set commitment and the separate non-circular commitment over all reviewable evidence records, so a release-key holder cannot silently substitute those evidence bytes while reusing an older review signature. It rejects duplicate JSON keys, non-canonical integer representation, unknown manifest members, path traversal/reparse points/hard links in the bundle or verifier runtime, Windows case-folded path reuse, unlisted tree entries, artifact substitution, missing evidence, an extension-ID change across successor lineage, an old signed sequence replay against a newer checkpoint, uncheckpointed lineage, and semantic-version rollback.

It does not prove that a reviewer is organizationally independent, that an operator truly disconnected networking, that a hardware key was protected correctly, that GitHub's runner image is honest, that the compiler is free from compromise, or that an evidence-generating test was competently designed. For the ambient PowerShell bootstrap boundary, however, module, protected-type, and command-shadow cleanliness is verified by code and is not delegated to an operator cleanliness assumption. The residual external bootstrap trust is limited to the Windows OS and exact system Windows PowerShell 5.1 image, the independently reviewed write-protected verifier toolset that is already executing, and the absence of live same-integrity process injection into the bootstrap PowerShell or resumed Node process. Release preparation additionally assumes no concurrent same-user mutation of its fresh temporary extraction tree; that staging step cannot make a hostile peer process trustworthy. The toolset's runtime self-hash does not bootstrap trust in the code already performing that check, and the VM context is a resolution boundary for reviewed source rather than a hostile-code sandbox. Authenticode bytes are expected to differ from reproducible unsigned bytes; reproducibility is checked before platform signing and final hashes bind the signed form. Consumers must require process exit zero and the exact success bytes; grepping a marker while ignoring the exit status is never an eligibility check.

## Remaining release STOP-SHIP conditions

At repository scaffold time, all of the following remain unresolved:

- no successful frozen, offline, exact-system-host two-directory release run has been recorded;
- no production installer or verified install/uninstall/upgrade ACL behavior exists;
- no stable production extension ID and store/update ceremony is recorded;
- no Authenticode certificate or independently pinned leaf-certificate hash is configured;
- no offline hardware-backed release key, reviewer key, signatures, rotation drill, or revocation drill exists;
- none of the 17 exact Windows negative-test evidence files has been produced for a final artifact set;
- no independently signed review with zero Critical/High findings exists;
- no production independently reviewed write-protected verifier-toolset aggregate, exact-system-host bootstrap transcript, or trusted offline checkpoint has been recorded;
- no accepted release-sequence/previous-manifest checkpoint or rollback-resistant external ledger exists;
- dependency cache provisioning, advisory review, compiler/SDK provenance, and diverse-build review remain external work;
- pinned cargo-audit/OSV Scanner binaries, immutable RustSec/OSV snapshots, and zero-finding raw reports are absent;
- the canonical, exact-envelope-anchored device key-bundle model is present, including predecessor-linked pending rotation, canonical SPKI identities, role-typed secret access, module-private identity constructors/sealing markers, and a whole-production-source PCP adapter absence check, but no production Microsoft Platform Crypto Provider provisioning, TPM NV rollback/auth adapter, hardware key rotation/recovery ceremony, or signed-artifact lifecycle evidence exists;
- application-level STOP-SHIP items documented elsewhere remain in force.

Until every applicable item is resolved and the final offline verifier succeeds, the candidate is not a Private Mainnet Canary release.
