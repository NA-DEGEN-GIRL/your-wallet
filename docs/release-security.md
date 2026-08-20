# Private Mainnet Canary release security

## Current status

This repository contains a fail-closed release-evidence scaffold. It does **not** contain a release signing key, reviewer key, Authenticode certificate, production installer, stable Chrome extension ID, published update, or completed release evidence bundle. Running the normal repository gate or the release-policy tests cannot install, sign, publish, or mark a build eligible.

The only command allowed to print an eligibility result is `verify-release-offline.ps1`. It succeeds only after the signed manifest, every hashed bundle file, independently signed review attestation, exact Windows negative-test set, independently pinned Authenticode identity, installer evidence, extension identity, checkpointed lineage, and key-lifecycle drills verify together. This release evidence does not waive any application-level STOP-SHIP item.

## Commands and trust separation

The CI-safe check is read-only apart from test-owned temporary directories:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/release/check.ps1 all
```

It parses every release script, audits the extension source, runs deterministic policy tests, and verifies deterministic PowerShell packaging helpers. It never invokes a release build or asks for credentials.

The manual `release-evidence-policy` workflow requires exact cargo-audit/OSV Scanner versions, scanner-binary hashes, and immutable RustSec/OSV database identifiers and hashes. It validates only their shape and the repository policy tests, prints `POLICY_INPUTS_VALIDATED_NOT_RELEASE_ELIGIBLE`, and deliberately does not download a scanner, build, sign, upload, install, or publish anything.

Unsigned preparation is an explicit, separate ceremony:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/release/prepare-unsigned.ps1 `
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

The production Chrome extension ID is an external release input. It must match the store/self-hosted production identity and the native-host manifest's sole `allowed_origins` entry. The final verifier strictly parses that exact hashed manifest, requires host name `com.your_wallet.native`, type `stdio`, one matching Chrome-extension origin, and an absolute Windows path whose basename is `native-host.exe`. A development/unpacked extension ID is not acceptable evidence.

## Hashing and Authenticode evidence

After platform signing and installer creation, compute the final payload commitment:

```powershell
node scripts/release/hash-payload.mjs `
  --payload-root .\release-bundle\payload `
  --output .\payload-hashes.json
```

The command prints the artifact-set SHA-256. Supply that value and the independently pinned Authenticode leaf-certificate SHA-256 to the Windows verifier:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/release/verify-authenticode.ps1 `
  -PayloadDirectory .\release-bundle\payload `
  -ArtifactSetSha256 <64-lower-hex> `
  -ExpectedSignerCertificateSha256 <64-lower-hex> `
  -OutputPath .\release-bundle\evidence\authenticode.json
```

The script invokes Windows Authenticode verification for every EXE and the MSI, rejects an invalid/missing signature, rejects any leaf certificate other than the independently pinned certificate, and binds the report to the final artifact set. Entries are emitted once each in canonical payload-path order. The final Node verifier independently requires that every manifest artifact and every report entry name that same pinned certificate hash. It never signs a file.

## Mandatory external evidence

All JSON evidence uses printable ASCII, string-encoded integers, strict unique keys, and the exact schema consumed by `release-manifest.mjs`. Evidence files are hashed into the release manifest. The final verifier reparses their contents and checks their bindings; a file with a correct name but unrelated content is rejected.

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

The attestation schema is `your-wallet-independent-security-review-v1` and includes the release profile/version, source commit, final artifact-set hash, reviewer public-key ID, `independenceAttestation: "pass"`, and zero open Critical/High findings. Its `scope` array must have this exact order:

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

The reviewer can calculate a public-key ID and canonicalize the unsigned attestation without exposing a private key:

```powershell
node scripts/release/release-manifest.mjs key-id --public-key .\review-public-key.pem
node scripts/release/release-manifest.mjs canonicalize-json `
  --input .\review-attestation.draft.json `
  --output .\review-attestation.json
```

The signature is produced externally. Self-review, a reviewer key equal to the release key, omitted scope, or any open Critical/High finding is an unconditional refusal.

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

Calculate release and reviewer key IDs from public keys only. After all evidence is present, assemble a canonical unsigned manifest:

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

For every release after sequence 1, add `--previous .\accepted-previous-manifest.json`. Assembly binds the previous manifest's canonical SHA-256, sequence, and version. The verifier rejects omitted lineage, hash substitution, non-consecutive sequence, equal version, or rollback. Verify the previous release signature against the locally accepted checkpoint before using it; a filename alone is not a trust anchor. Record its canonical SHA-256 separately because final verification requires that independently pinned value.

The assembly command writes `UNSIGNED_CANONICAL_MANIFEST_WRITTEN_NOT_RELEASE_ELIGIBLE`. Sign the exact manifest bytes outside this repository with the offline hardware-backed Ed25519 release key. Store only the raw 64-byte signature encoded as canonical base64 in `release-manifest.sig`. Do not add a newline before signing and do not commit a private key.

On a separately controlled Windows verification system with networking physically or administratively disabled, run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/release/verify-release-offline.ps1 `
  -Manifest .\release-manifest.json `
  -Signature .\release-manifest.sig `
  -ReleasePublicKey .\release-public-key.pem `
  -BundleRoot .\release-bundle `
  -ExpectedReleaseKeyIdSha256 <independently pinned 64-lower-hex> `
  -ExpectedReviewerKeyIdSha256 <independently pinned 64-lower-hex> `
  -ExpectedSignerCertificateSha256 <independently pinned 64-lower-hex> `
  -OperatorConfirmedNetworkIsolation
```

For non-initial releases, add both `-PreviousManifest .\accepted-previous-manifest.json` and `-ExpectedPreviousManifestSha256 <independently pinned 64-lower-hex>`. Supplying only one is refused. The two expected key IDs, certificate hash, and previous-manifest hash must come from the independently trusted offline checkpoint, not from the candidate bundle or a copied command. The switch records an operator assertion; software cannot prove physical network isolation. The command hashes all payload/evidence files, validates every attestation and independent-review signature, verifies lineage and the release signature, reruns Windows Authenticode validation, then repeats the complete bundle and signature verification. Only then can it print `PRIVATE_MAINNET_CANARY_RELEASE_ELIGIBLE_AFTER_OFFLINE_VERIFICATION`.

Record the accepted sequence, version, canonical manifest hash, release public-key ID, reviewer public-key ID, and Authenticode certificate hash in a write-protected offline checkpoint. Local state alone does not resist disk/snapshot rollback; restoring an older machine image must require reconciliation with that independent checkpoint.

Final verification refuses a bundle root, descendant, manifest, signature, public key, or previous manifest that is not marked read-only, and rejects reparse points, hard-linked bundle files, missing entries, and unlisted files/directories. Mark the complete staging tree and external inputs read-only before invoking the command. A read-only attribute alone is deliberately insufficient: the wrapper attempts a uniquely named create-new probe in every bundle directory and refuses eligibility unless the verifier token is denied (or the medium reports write protection), both before and after Authenticode inspection. It also holds every directory and input file without write/delete sharing across both Node passes, Authenticode inspection, and eligibility output. This binds the path-based checks to the same bytes during the ceremony; access-controlled read-only media remains mandatory because owner/DACL changes by a same-user privileged process and mutation after verification exits are outside the script's proof.

## Guarantees and non-guarantees

This scaffold guarantees, when its final verifier succeeds, byte-level binding among the exact canonical signed manifest, fixed role-to-path artifact set, fixed evidence paths, source/vendor/toolchain/lockfile records, final extension/native-host/installer identity, exact Windows tests, independently pinned signing identities, and independently signed review. It rejects duplicate JSON keys, non-canonical integer representation, unknown manifest members, path traversal/reparse points/hard links in the bundle, Windows case-folded path reuse, unlisted tree entries, artifact substitution, missing evidence, uncheckpointed successor lineage, and semantic-version rollback.

It does not prove that a reviewer is organizationally independent, that an operator truly disconnected networking, that a hardware key was protected correctly, that GitHub's runner image is honest, that the compiler is free from compromise, or that an evidence-generating test was competently designed. Those are external ceremony and review obligations. Authenticode bytes are expected to differ from reproducible unsigned bytes; reproducibility is checked before platform signing and final hashes bind the signed form.

## Remaining release STOP-SHIP conditions

At repository scaffold time, all of the following remain unresolved:

- no successful clean, frozen, offline two-directory release run has been recorded;
- no production installer or verified install/uninstall/upgrade ACL behavior exists;
- no stable production extension ID and store/update ceremony is recorded;
- no Authenticode certificate or independently pinned leaf-certificate hash is configured;
- no offline hardware-backed release key, reviewer key, signatures, rotation drill, or revocation drill exists;
- none of the 17 exact Windows negative-test evidence files has been produced for a final artifact set;
- no independently signed review with zero Critical/High findings exists;
- no accepted previous-manifest checkpoint or rollback-resistant external ledger exists;
- dependency cache provisioning, advisory review, compiler/SDK provenance, and diverse-build review remain external work;
- pinned cargo-audit/OSV Scanner binaries, immutable RustSec/OSV snapshots, and zero-finding raw reports are absent;
- the canonical, exact-envelope-anchored device key-bundle model is present, including predecessor-linked pending rotation, canonical SPKI identities, role-typed secret access, module-private identity constructors/sealing markers, and a whole-production-source PCP adapter absence check, but no production Microsoft Platform Crypto Provider provisioning, TPM NV rollback/auth adapter, hardware key rotation/recovery ceremony, or signed-artifact lifecycle evidence exists;
- application-level STOP-SHIP items documented elsewhere remain in force.

Until every applicable item is resolved and the final offline verifier succeeds, the candidate is not a Private Mainnet Canary release.
