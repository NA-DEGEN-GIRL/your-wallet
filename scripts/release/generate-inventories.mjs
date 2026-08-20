import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { canonicalEncode, sha256Hex } from "./release-manifest.mjs";

const CRATES_IO_SOURCE = "registry+https://github.com/rust-lang/crates.io-index";
const COMMIT_RE = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u;
const SHA256_RE = /^[0-9a-f]{64}$/u;
const ALLOWED_LICENSE_IDENTIFIERS = new Set([
  "0BSD", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "BSL-1.0", "CC0-1.0", "ISC", "MIT",
  "OFL-1.1", "Ubuntu-font-1.0", "Unicode-3.0", "Unlicense", "Zlib",
]);

export class InventoryError extends Error {
  constructor(message) {
    super(message);
    this.name = "InventoryError";
  }
}

function fail(message) {
  throw new InventoryError(message);
}

function ascii(value, label, maximum = 512) {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum || /[^\u0020-\u007e]/u.test(value)) fail(`${label} must be bounded printable ASCII`);
  return value;
}

function componentRef(pkg) {
  return `SPDXRef-Package-${pkg.name.replace(/[^A-Za-z0-9.-]/gu, "-")}-${pkg.version}-${sha256Hex(Buffer.from(pkg.id, "utf8")).slice(0, 12)}`;
}

function stablePackageKey(pkg) {
  return `${pkg.name}\u0000${pkg.version}\u0000${pkg.source ?? "workspace"}`;
}

function sourceKind(source) {
  if (source === null) return "workspace";
  if (source === CRATES_IO_SOURCE) return "crates.io";
  fail("release inventory refuses non-crates.io dependency sources until they receive a dedicated provenance policy");
}

function assertReviewedLicense(expression, packageName) {
  if (expression === "NOASSERTION") return;
  const identifiers = expression.match(/[A-Za-z0-9][A-Za-z0-9.+-]*/gu) ?? [];
  for (const identifier of identifiers) {
    if (!["AND", "OR", "WITH"].includes(identifier) && !ALLOWED_LICENSE_IDENTIFIERS.has(identifier)) {
      fail(`package ${packageName} uses an unreviewed license identifier: ${identifier}`);
    }
  }
}

export function buildInventories(metadata, options) {
  if (!metadata || !Array.isArray(metadata.packages) || !metadata.resolve || !Array.isArray(metadata.resolve.nodes) || !Array.isArray(metadata.workspace_members)) {
    fail("cargo metadata input is incomplete");
  }
  ascii(options.sourceCommit, "source commit", 64);
  if (!COMMIT_RE.test(options.sourceCommit)) fail("source commit format is invalid");
  ascii(options.cargoLockSha256, "Cargo.lock hash", 64);
  if (!SHA256_RE.test(options.cargoLockSha256)) fail("Cargo.lock hash format is invalid");
  ascii(options.target, "target", 64);
  if (!/^[A-Za-z0-9_-]+(?:-[A-Za-z0-9_-]+)+$/u.test(options.target)) fail("target format is invalid");
  if (!Number.isSafeInteger(options.sourceDateEpoch) || options.sourceDateEpoch < 0) fail("source date epoch must be a non-negative safe integer");

  const workspace = new Set(metadata.workspace_members);
  const nodeById = new Map(metadata.resolve.nodes.map((node) => [node.id, node]));
  const packagesById = new Map(metadata.packages.map((pkg) => [pkg.id, pkg]));
  const packages = [...metadata.packages].sort((left, right) => stablePackageKey(left).localeCompare(stablePackageKey(right), "en"));

  const dependencies = packages.map((pkg) => {
    const kind = sourceKind(pkg.source ?? null);
    const license = pkg.license ?? "NOASSERTION";
    if (kind !== "workspace" && license === "NOASSERTION") fail(`dependency ${pkg.name} ${pkg.version} has no declared license`);
    assertReviewedLicense(license, pkg.name);
    const targets = Array.isArray(pkg.targets) ? pkg.targets : [];
    const node = nodeById.get(pkg.id);
    const dependencyIds = Array.isArray(node?.dependencies)
      ? node.dependencies.map((id) => {
        const dependency = packagesById.get(id);
        if (!dependency) fail(`cargo metadata dependency is unresolved for ${pkg.name}`);
        return `${dependency.name}@${dependency.version}`;
      }).sort()
      : [];
    return {
      dependencyIds,
      features: Array.isArray(node?.features) ? [...node.features].sort() : [],
      hasBuildScript: targets.some((target) => Array.isArray(target.kind) && target.kind.includes("custom-build")) ? "yes" : "no",
      license: ascii(license, `license for ${pkg.name}`, 256),
      links: pkg.links === null || pkg.links === undefined ? null : ascii(pkg.links, `links for ${pkg.name}`, 128),
      name: ascii(pkg.name, "package name", 128),
      procMacro: targets.some((target) => Array.isArray(target.kind) && target.kind.includes("proc-macro")) ? "yes" : "no",
      source: kind,
      version: ascii(pkg.version, `version for ${pkg.name}`, 64),
      workspace: workspace.has(pkg.id) ? "yes" : "no",
    };
  });

  const common = {
    cargoLockSha256: options.cargoLockSha256,
    sourceCommit: options.sourceCommit,
    target: options.target,
  };
  const dependencyInventory = {
    ...common,
    packages: dependencies,
    schema: "your-wallet-cargo-dependency-inventory-v1",
  };
  const licenseInventory = {
    ...common,
    packages: dependencies.map(({ license, name, source, version }) => ({ license, name, source, version })),
    schema: "your-wallet-license-inventory-v1",
  };

  const spdxPackages = packages.map((pkg) => {
    const kind = sourceKind(pkg.source ?? null);
    const license = pkg.license ?? "NOASSERTION";
    return {
      SPDXID: componentRef(pkg),
      copyrightText: "NOASSERTION",
      downloadLocation: "NOASSERTION",
      filesAnalyzed: false,
      licenseConcluded: license,
      licenseDeclared: license,
      name: pkg.name,
      supplier: kind === "workspace" ? "Organization: your-wallet project" : "NOASSERTION",
      versionInfo: pkg.version,
    };
  });
  const spdxIdByCargoId = new Map(packages.map((pkg) => [pkg.id, componentRef(pkg)]));
  const relationships = [];
  for (const node of metadata.resolve.nodes) {
    const sourceId = spdxIdByCargoId.get(node.id);
    if (!sourceId) continue;
    for (const dependencyId of node.dependencies ?? []) {
      const targetId = spdxIdByCargoId.get(dependencyId);
      if (targetId) relationships.push({ relatedSpdxElement: targetId, relationshipType: "DEPENDS_ON", spdxElementId: sourceId });
    }
  }
  relationships.sort((left, right) => `${left.spdxElementId}\u0000${left.relatedSpdxElement}`.localeCompare(`${right.spdxElementId}\u0000${right.relatedSpdxElement}`, "en"));
  const described = packages.filter((pkg) => workspace.has(pkg.id)).map(componentRef).sort();
  const created = new Date(options.sourceDateEpoch * 1000).toISOString().replace(".000Z", "Z");
  const sbom = {
    SPDXID: "SPDXRef-DOCUMENT",
    creationInfo: { created, creators: ["Tool: your-wallet/scripts/release/generate-inventories.mjs"] },
    dataLicense: "CC0-1.0",
    documentDescribes: described,
    documentNamespace: `https://spdx.org/spdxdocs/your-wallet-${options.sourceCommit}-${options.cargoLockSha256}`,
    name: `your-wallet-${options.sourceCommit}`,
    packages: spdxPackages,
    relationships,
    spdxVersion: "SPDX-2.3",
  };
  return { dependencyInventory, licenseInventory, sbom };
}

function parseArguments(argv) {
  const args = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    if (!argv[index]?.startsWith("--") || argv[index + 1] === undefined) fail("arguments must be --name value pairs");
    if (args.has(argv[index])) fail(`duplicate argument: ${argv[index]}`);
    args.set(argv[index], argv[index + 1]);
  }
  return args;
}

async function runCli() {
  const args = parseArguments(process.argv.slice(2));
  const required = ["--metadata", "--source-commit", "--cargo-lock-sha256", "--source-date-epoch", "--target", "--dependency-output", "--license-output", "--sbom-output"];
  if (args.size !== required.length || required.some((name) => !args.has(name))) fail(`required arguments: ${required.join(", ")}`);
  const metadata = JSON.parse(await readFile(args.get("--metadata"), "utf8"));
  const sourceDateEpoch = Number(args.get("--source-date-epoch"));
  const outputs = buildInventories(metadata, {
    cargoLockSha256: args.get("--cargo-lock-sha256"),
    sourceCommit: args.get("--source-commit"),
    sourceDateEpoch,
    target: args.get("--target"),
  });
  await Promise.all([
    writeFile(args.get("--dependency-output"), `${canonicalEncode(outputs.dependencyInventory)}\n`, { encoding: "utf8", flag: "wx" }),
    writeFile(args.get("--license-output"), `${canonicalEncode(outputs.licenseInventory)}\n`, { encoding: "utf8", flag: "wx" }),
    writeFile(args.get("--sbom-output"), `${canonicalEncode(outputs.sbom)}\n`, { encoding: "utf8", flag: "wx" }),
  ]);
  process.stdout.write("DEPENDENCY_LICENSE_SBOM_EVIDENCE_WRITTEN\n");
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runCli().catch((error) => {
    const message = error instanceof InventoryError ? error.message : "unexpected inventory generation failure";
    process.stderr.write(`INVENTORY_GENERATION_FAILED: ${message}\n`);
    process.exitCode = 1;
  });
}
