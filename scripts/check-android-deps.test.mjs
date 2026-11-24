import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { checkApk, checkManifest, checkRuntime, readExpected, resolvedRuntime, zipEntries } from "./check-android-deps.mjs";

const root = join(fileURLToPath(new URL(".", import.meta.url)), "..");

const header = [
  "",
  "------------------------------------------------------------",
  "Project ':app'",
  "------------------------------------------------------------",
  "",
];

function report(...lines) {
  return [...header, "releaseRuntimeClasspath - Resolved configuration for runtime for variant: release", ...lines, "",
    "A web-based, searchable dependency report is available by adding the --scan option."].join("\n");
}

test("an empty closure matches an empty list (A2, spec/15 §4.2)", () => {
  assert.deepEqual(checkRuntime(report("No dependencies"), "# comment only\n\n"), []);
  assert.deepEqual(readExpected(readFileSync(join(root, "android/runtime-deps.txt"), "utf8")), []);
});

test("the resolved closure must equal the list line by line", () => {
  const tree = report(
    "+--- androidx.webkit:webkit:1.18.0",
    "|    +--- androidx.annotation:annotation:1.8.1",
    "|    |    \\--- androidx.annotation:annotation-jvm:1.8.1",
    "|    |         \\--- org.jetbrains.kotlin:kotlin-stdlib:1.7.10 -> 1.9.0",
    "|    \\--- androidx.core:core:1.1.0 (*)",
    "\\--- androidx.collection:collection:1.0.0 (c)",
  );
  assert.deepEqual(resolvedRuntime(tree).coordinates, [
    "androidx.annotation:annotation-jvm:1.8.1",
    "androidx.annotation:annotation:1.8.1",
    "androidx.core:core:1.1.0",
    "androidx.webkit:webkit:1.18.0",
    "org.jetbrains.kotlin:kotlin-stdlib:1.9.0",
  ]);
  const list = "androidx.annotation:annotation-jvm:1.8.1\nandroidx.annotation:annotation:1.8.1\nandroidx.core:core:1.1.0\n"
    + "androidx.webkit:webkit:1.18.0\norg.jetbrains.kotlin:kotlin-stdlib:1.9.0\n";
  assert.deepEqual(checkRuntime(tree, list), []);
  // A new artifact, a changed version, a missing one: each is a failure.
  assert.deepEqual(checkRuntime(tree, list.replace("1.9.0", "1.7.10")), [
    "not in runtime-deps.txt: org.jetbrains.kotlin:kotlin-stdlib:1.9.0",
    "in runtime-deps.txt but not resolved: org.jetbrains.kotlin:kotlin-stdlib:1.7.10",
  ]);
  assert.deepEqual(checkRuntime(report("No dependencies"), "a:b:1\n"), ["in runtime-deps.txt but not resolved: a:b:1"]);
  assert.deepEqual(checkRuntime(tree, `${list}androidx.core:core:1.1.0\n`), ["runtime-deps.txt lists a coordinate twice"]);
});

test("a report without the section, an unresolved or unreadable entry fails", () => {
  assert.deepEqual(checkRuntime(header.join("\n"), ""), ["no releaseRuntimeClasspath section in the report"]);
  assert.deepEqual(checkRuntime(report("+--- a:b:1 FAILED"), ""), ["not resolved: a:b:1 FAILED"]);
  assert.deepEqual(checkRuntime(report("\\--- a:b:1 (n)"), ""), ["not resolved: a:b:1 (n)"]);
  assert.deepEqual(checkRuntime(report("\\--- project :lib"), ""), ["unreadable coordinate: project :lib"]);
  assert.deepEqual(checkRuntime(report("something else"), ""), ["unexpected report line: something else"]);
});

/** A zip of stored entries; each entry's data starts at `align` bytes when given (padding in the extra field). */
function zip(entries) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const { name, data = Buffer.alloc(4), method = 0, align = 0 } of entries) {
    const nameBytes = Buffer.from(name, "utf8");
    let extra = 0;
    if (align > 0) {
      extra = (align - ((offset + 30 + nameBytes.length) % align)) % align;
    }
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x0403_4b50, 0);
    local.writeUInt16LE(method, 8);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBytes.length, 26);
    local.writeUInt16LE(extra, 28);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x0201_4b50, 0);
    central.writeUInt16LE(method, 10);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(nameBytes.length, 28);
    central.writeUInt32LE(offset, 42);
    locals.push(local, nameBytes, Buffer.alloc(extra), data);
    centrals.push(central, nameBytes);
    offset += 30 + nameBytes.length + extra + data.length;
  }
  const directory = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x0605_4b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, directory, end]);
}

test("the APK holds libyw.so stored and 16 KB aligned for exactly the built ABIs", () => {
  const good = zip([
    { name: "AndroidManifest.xml" },
    { name: "lib/arm64-v8a/libyw.so", align: 16_384 },
    { name: "classes.dex" },
    { name: "lib/x86_64/libyw.so", align: 16_384 },
  ]);
  assert.deepEqual(zipEntries(good).map(({ name }) => name), [
    "AndroidManifest.xml", "lib/arm64-v8a/libyw.so", "classes.dex", "lib/x86_64/libyw.so",
  ]);
  assert.deepEqual(checkApk(good, ["arm64-v8a", "x86_64"]), []);
  assert.deepEqual(checkApk(good, ["arm64-v8a"]), ["unexpected native library: lib/x86_64/libyw.so"]);
  const misaligned = zip([{ name: "x" }, { name: "lib/arm64-v8a/libyw.so", align: 4 }]);
  assert.match(checkApk(misaligned, ["arm64-v8a"]).join("\n"), /is not 16 KB aligned/u);
  const compressed = zip([{ name: "lib/arm64-v8a/libyw.so", method: 8, align: 16_384 }]);
  assert.deepEqual(checkApk(compressed, ["arm64-v8a"]), ["lib/arm64-v8a/libyw.so is compressed (method 8)"]);
  assert.deepEqual(checkApk(zip([{ name: "a" }]), ["arm64-v8a"]), ["missing lib/arm64-v8a/libyw.so"]);
  const extra = zip([{ name: "lib/arm64-v8a/libyw.so", align: 16_384 }, { name: "lib/arm64-v8a/libother.so", align: 16_384 }]);
  assert.deepEqual(checkApk(extra, ["arm64-v8a"]), ["unexpected native library: lib/arm64-v8a/libother.so"]);
});

test("the APK carries no repository revision and no Kotlin runtime (spec/15 §4.2, §4.3)", () => {
  const base = { name: "lib/arm64-v8a/libyw.so", align: 16_384 };
  assert.deepEqual(checkApk(zip([base, { name: "META-INF/version-control-info.textproto" }]), ["arm64-v8a"]),
    ["META-INF/version-control-info.textproto present"]);
  assert.deepEqual(checkApk(zip([base, { name: "kotlin/kotlin.kotlin_builtins" }]), ["arm64-v8a"]),
    ["Kotlin runtime entry: kotlin/kotlin.kotlin_builtins"]);
  assert.deepEqual(checkApk(zip([base, { name: "META-INF/x.kotlin_module" }]), ["arm64-v8a"]),
    ["Kotlin runtime entry: META-INF/x.kotlin_module"]);
  assert.throws(() => zipEntries(Buffer.from("not a zip")), /not a zip file/u);
});

const NS = "http://schemas.android.com/apk/res/android";
function manifest({ application = [], components = null, extra = [], debuggable = null } = {}) {
  const lines = [
    `N: android=${NS} (line=2)`,
    "  E: manifest (line=2)",
    `    A: ${NS}:versionCode(0x0101021b)=1`,
    "    A: package=\"dev.yw.app\" (Raw: \"dev.yw.app\")",
    ...extra,
    "      E: uses-sdk (line=12)",
    `        A: ${NS}:minSdkVersion(0x0101020c)=29`,
    `        A: ${NS}:targetSdkVersion(0x01010270)=36`,
    "      E: application (line=16)",
    `        A: ${NS}:name(0x01010003)="dev.yw.app.App" (Raw: "dev.yw.app.App")`,
    ...(debuggable === null ? [] : [`        A: ${NS}:debuggable(0x0101000f)=${debuggable}`]),
    `        A: ${NS}:allowBackup(0x01010280)=false`,
    `        A: ${NS}:extractNativeLibs(0x010104ea)=false`,
    `        A: ${NS}:fullBackupContent(0x010104eb)=false`,
    `        A: ${NS}:usesCleartextTraffic(0x010104ec)=false`,
    `        A: ${NS}:allowAudioPlaybackCapture(0x01010605)=false`,
    `        A: ${NS}:hasFragileUserData(0x0101059a)=false`,
    `        A: ${NS}:dataExtractionRules(0x0101063e)=@0x7f050000`,
    ...application,
    "          E: meta-data (line=30)",
    `            A: ${NS}:name(0x01010003)="android.webkit.WebView.MetricsOptOut" (Raw: "android.webkit.WebView.MetricsOptOut")`,
    `            A: ${NS}:value(0x01010024)=true`,
    ...(components ?? [
      "          E: activity (line=34)",
      `            A: ${NS}:name(0x01010003)="dev.yw.app.MainActivity" (Raw: "dev.yw.app.MainActivity")`,
      `            A: ${NS}:exported(0x01010010)=true`,
      "              E: intent-filter (line=37)",
      "                  E: action (line=38)",
      `                    A: ${NS}:name(0x01010003)="android.intent.action.MAIN" (Raw: "android.intent.action.MAIN")`,
      "                  E: category (line=40)",
      `                    A: ${NS}:name(0x01010003)="android.intent.category.LAUNCHER" (Raw: "android.intent.category.LAUNCHER")`,
    ]),
  ];
  return lines.join("\n");
}

test("the A2 manifest passes: no permission, no backup, only the launcher exported", () => {
  assert.deepEqual(checkManifest(manifest(), "release"), []);
  assert.deepEqual(checkManifest(manifest({ debuggable: "true" }), "debug"), []);
  assert.deepEqual(checkManifest(manifest({ debuggable: "true" }), "release"), ["release build is debuggable"]);
});

test("any permission request fails (no INTERNET in A2, spec/15 §18 42 N16)", () => {
  const internet = [
    "      E: uses-permission (line=5)",
    `        A: ${NS}:name(0x01010003)="android.permission.INTERNET" (Raw: "android.permission.INTERNET")`,
  ];
  assert.deepEqual(checkManifest(manifest({ extra: internet }), "release"), ["uses-permission android.permission.INTERNET"]);
});

test("backups, cleartext and the application class are checked (spec/15 §5.1)", () => {
  const text = manifest().replace("allowBackup(0x01010280)=false", "allowBackup(0x01010280)=true")
    .replace(/.*dataExtractionRules.*\n/u, "");
  assert.deepEqual(checkManifest(text, "release"), ["application allowBackup is not false", "application has no dataExtractionRules"]);
});

test("a second exported component, or one without exported=\"false\", fails", () => {
  const service = (exported) => [
    "          E: service (line=50)",
    `            A: ${NS}:name(0x01010003)="dev.yw.app.Relay" (Raw: "dev.yw.app.Relay")`,
    ...(exported === null ? [] : [`            A: ${NS}:exported(0x01010010)=${exported}`]),
  ];
  const launcher = manifest().split("\n").slice(-8);
  const base = manifest({ components: [] }).split("\n");
  const build = (extraComponents) => [...base, ...launcher, ...extraComponents].join("\n");
  assert.deepEqual(checkManifest(build(service("false")), "release"), []);
  assert.deepEqual(checkManifest(build(service("true")), "release"), [
    "exported component other than the launcher: service dev.yw.app.Relay",
    "2 exported components, expected only the launcher",
  ]);
  assert.deepEqual(checkManifest(build(service(null)), "release"), ["service dev.yw.app.Relay does not set exported=\"false\""]);
  assert.deepEqual(checkManifest(manifest({ components: [] }), "release"), ["0 exported components, expected only the launcher"]);
});
