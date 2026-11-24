#!/usr/bin/env node
// scripts/check-android-deps.mjs — Android 빌드 결과 검사([15] §4.2, §5.1, §12, §13; 2026-11-24 A2-3).
// scripts/build-android.ps1이 부른다(게이트 android 단계, 종료 33).
//   node scripts/check-android-deps.mjs runtime <gradle dependencies 출력> <android/runtime-deps.txt>
//     Gradle이 해석한 releaseRuntimeClasspath(R8 축소 전 그래프)가 목록과 한 줄씩 같아야 한다. 목록 밖 아티팩트, 버전 차이,
//     빠진 항목, 해석 못 한 항목은 실패다(§4.2: 목록을 바꾸는 것은 의존성 추가와 같다).
//   node scripts/check-android-deps.mjs apk <정렬한 APK> <abi[,abi]>
//     lib/<abi>/libyw.so가 정확히 그 ABI들에 하나씩, 압축 없이(stored) 데이터 오프셋이 16 384의 배수(§13 5); 다른 .so 없음;
//     META-INF/version-control-info.textproto(빌드 PC 저장소의 판, §4.3) 없음; Kotlin 런타임의 흔적(kotlin/, *.kotlin_module) 없음.
//   node scripts/check-android-deps.mjs manifest <aapt2 dump xmltree 출력> <release|debug>
//     권한 요청이 하나도 없다(A2에는 INTERNET도 없다, §12, §18 42 N16); 백업·기기 이전 끔(§5.1); 모든 구성 요소는
//     exported="false"이고 런처 Activity 하나만 true(§13); release는 debuggable이 아니다.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

/** The coordinates `group:name:version` of the expected-list file (comments and blank lines skipped). */
export function readExpected(text) {
  return text
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter((line) => line !== "" && !line.startsWith("#"));
}

/**
 * The resolved coordinates of the `releaseRuntimeClasspath` section of a `gradle dependencies` report, or problems.
 * A requested version replaced by conflict resolution (`a:b:1 -> 2`) counts as the resolved one; constraints `(c)`
 * are not artifacts; `(n)` (not resolved) and `FAILED` are problems.
 */
export function resolvedRuntime(report) {
  const lines = report.split(/\r?\n/u);
  const start = lines.findIndex((line) => /^releaseRuntimeClasspath\b/u.test(line));
  if (start === -1) return { coordinates: [], problems: ["no releaseRuntimeClasspath section in the report"] };
  const coordinates = new Set();
  const problems = [];
  for (const line of lines.slice(start + 1)) {
    if (line.trim() === "") break;
    if (line.trim() === "No dependencies") continue;
    const match = /^[|\s]*[+\\]--- (.+)$/u.exec(line);
    if (match === null) {
      problems.push(`unexpected report line: ${line.trim()}`);
      continue;
    }
    let entry = match[1].trim();
    if (/\(c\)$/u.test(entry)) continue;
    if (/\((n|FAILED)\)$|\bFAILED$/u.test(entry)) {
      problems.push(`not resolved: ${entry}`);
      continue;
    }
    entry = entry.replace(/ \(\*\)$/u, "");
    const parts = /^([^:\s]+):([^:\s]+)(?::([^\s]+))?(?: -> ([^\s]+))?$/u.exec(entry);
    if (parts === null) {
      problems.push(`unreadable coordinate: ${entry}`);
      continue;
    }
    const version = parts[4] ?? parts[3];
    if (version === undefined) {
      problems.push(`no version: ${entry}`);
      continue;
    }
    coordinates.add(`${parts[1]}:${parts[2]}:${version}`);
  }
  return { coordinates: [...coordinates].sort(), problems };
}

export function checkRuntime(report, expectedText) {
  const { coordinates, problems } = resolvedRuntime(report);
  const expected = readExpected(expectedText);
  const resolved = new Set(coordinates);
  const listed = new Set(expected);
  for (const coordinate of coordinates) {
    if (!listed.has(coordinate)) problems.push(`not in runtime-deps.txt: ${coordinate}`);
  }
  for (const coordinate of expected) {
    if (!resolved.has(coordinate)) problems.push(`in runtime-deps.txt but not resolved: ${coordinate}`);
  }
  if (new Set(expected).size !== expected.length) problems.push("runtime-deps.txt lists a coordinate twice");
  return problems;
}

/** The central-directory entries of a zip: { name, method, dataOffset }. */
export function zipEntries(bytes) {
  const buffer = Buffer.from(bytes);
  let end = -1;
  for (let at = buffer.length - 22; at >= Math.max(0, buffer.length - 65_557); at -= 1) {
    if (buffer.readUInt32LE(at) === 0x0605_4b50) {
      end = at;
      break;
    }
  }
  if (end === -1) throw new Error("not a zip file (no end of central directory)");
  const count = buffer.readUInt16LE(end + 10);
  let at = buffer.readUInt32LE(end + 16);
  const entries = [];
  for (let index = 0; index < count; index += 1) {
    if (buffer.readUInt32LE(at) !== 0x0201_4b50) throw new Error("broken central directory");
    const method = buffer.readUInt16LE(at + 10);
    const nameLength = buffer.readUInt16LE(at + 28);
    const extraLength = buffer.readUInt16LE(at + 30);
    const commentLength = buffer.readUInt16LE(at + 32);
    const local = buffer.readUInt32LE(at + 42);
    const name = buffer.toString("utf8", at + 46, at + 46 + nameLength);
    if (buffer.readUInt32LE(local) !== 0x0403_4b50) throw new Error(`broken local header: ${name}`);
    const dataOffset = local + 30 + buffer.readUInt16LE(local + 26) + buffer.readUInt16LE(local + 28);
    entries.push({ name, method, dataOffset });
    at += 46 + nameLength + extraLength + commentLength;
  }
  return entries;
}

export function checkApk(bytes, abis) {
  const problems = [];
  const entries = zipEntries(bytes);
  const expected = new Set(abis.map((abi) => `lib/${abi}/libyw.so`));
  const libraries = entries.filter(({ name }) => name.endsWith(".so"));
  for (const { name, method, dataOffset } of libraries) {
    if (!expected.has(name)) problems.push(`unexpected native library: ${name}`);
    if (method !== 0) problems.push(`${name} is compressed (method ${method})`);
    if (dataOffset % 16_384 !== 0) problems.push(`${name} data offset ${dataOffset} is not 16 KB aligned`);
  }
  for (const name of expected) {
    if (!libraries.some((entry) => entry.name === name)) problems.push(`missing ${name}`);
  }
  for (const { name } of entries) {
    if (name === "META-INF/version-control-info.textproto") problems.push(`${name} present`);
    if (name.startsWith("kotlin/") || name.endsWith(".kotlin_module") || name.endsWith(".kotlin_builtins")) {
      problems.push(`Kotlin runtime entry: ${name}`);
    }
  }
  return problems;
}

/** The element tree of an `aapt2 dump xmltree` text: { name, attributes: Map, children, line }. */
export function manifestTree(text) {
  const root = { name: "#root", attributes: new Map(), children: [], indent: -1 };
  const stack = [root];
  for (const raw of text.split(/\r?\n/u)) {
    const match = /^(\s*)([NEA]): (.*)$/u.exec(raw);
    if (match === null) continue;
    const indent = match[1].length;
    if (match[2] === "N") continue;
    if (match[2] === "E") {
      const element = { name: match[3].replace(/ \(line=\d+\)$/u, ""), attributes: new Map(), children: [], indent };
      while (stack.length > 1 && stack.at(-1).indent >= indent) stack.pop();
      stack.at(-1).children.push(element);
      stack.push(element);
    } else {
      const attribute = /^(?:[^:]*:[^:]*:)?(?:http:\/\/schemas\.android\.com\/apk\/res\/android:)?([\w-]+)(?:\(0x[0-9a-f]+\))?=(.*)$/u.exec(match[3]);
      if (attribute === null) continue;
      let value = attribute[2].replace(/ \(Raw: .*\)$/u, "");
      if (value.startsWith("\"") && value.endsWith("\"")) value = value.slice(1, -1);
      while (stack.length > 1 && stack.at(-1).indent >= indent) stack.pop();
      stack.at(-1).attributes.set(attribute[1], value);
    }
  }
  return root;
}

function walk(element, visit) {
  visit(element);
  for (const child of element.children) walk(child, visit);
}

const COMPONENTS = new Set(["activity", "activity-alias", "service", "receiver", "provider"]);
const PERMISSION_ELEMENTS = new Set(["uses-permission", "uses-permission-sdk-23", "permission", "permission-group", "permission-tree"]);

function isLauncher(element) {
  let main = false;
  let launcher = false;
  for (const filter of element.children.filter((child) => child.name === "intent-filter")) {
    for (const child of filter.children) {
      if (child.name === "action" && child.attributes.get("name") === "android.intent.action.MAIN") main = true;
      if (child.name === "category" && child.attributes.get("name") === "android.intent.category.LAUNCHER") launcher = true;
    }
  }
  return main && launcher;
}

export function checkManifest(text, variant) {
  const problems = [];
  const root = manifestTree(text);
  const manifest = root.children.find((child) => child.name === "manifest");
  if (manifest === undefined) return ["no manifest element"];
  if (manifest.attributes.get("package") !== "dev.yw.app") problems.push("package is not dev.yw.app");
  const sdk = manifest.children.find((child) => child.name === "uses-sdk");
  if (sdk?.attributes.get("minSdkVersion") !== "29") problems.push("minSdkVersion is not 29");
  if (sdk?.attributes.get("targetSdkVersion") !== "36") problems.push("targetSdkVersion is not 36");
  const application = manifest.children.find((child) => child.name === "application");
  if (application === undefined) return [...problems, "no application element"];
  const expected = {
    name: "dev.yw.app.App",
    allowBackup: "false",
    fullBackupContent: "false",
    hasFragileUserData: "false",
    usesCleartextTraffic: "false",
    allowAudioPlaybackCapture: "false",
    extractNativeLibs: "false",
  };
  for (const [key, value] of Object.entries(expected)) {
    if (application.attributes.get(key) !== value) problems.push(`application ${key} is not ${value}`);
  }
  if (!application.attributes.has("dataExtractionRules")) problems.push("application has no dataExtractionRules");
  if (application.attributes.has("testOnly")) problems.push("application is testOnly");
  const debuggable = application.attributes.get("debuggable");
  if (variant === "release" && debuggable !== undefined && debuggable !== "false") problems.push("release build is debuggable");
  let exported = 0;
  walk(manifest, (element) => {
    if (PERMISSION_ELEMENTS.has(element.name)) {
      problems.push(`${element.name} ${element.attributes.get("name") ?? ""}`.trim());
    }
    if (!COMPONENTS.has(element.name)) return;
    const name = element.attributes.get("name") ?? "?";
    const value = element.attributes.get("exported");
    if (value === "true") {
      exported += 1;
      if (element.name !== "activity" || name !== "dev.yw.app.MainActivity" || !isLauncher(element)) {
        problems.push(`exported component other than the launcher: ${element.name} ${name}`);
      }
    } else if (value !== "false") {
      problems.push(`${element.name} ${name} does not set exported="false"`);
    }
  });
  if (exported !== 1) problems.push(`${exported} exported components, expected only the launcher`);
  const optOut = application.children.find(
    (child) => child.name === "meta-data" && child.attributes.get("name") === "android.webkit.WebView.MetricsOptOut",
  );
  if (optOut?.attributes.get("value") !== "true") problems.push("WebView MetricsOptOut is not true");
  return problems;
}

function main(argv) {
  const [mode, ...rest] = argv;
  let problems;
  if (mode === "runtime" && rest.length === 2) {
    problems = checkRuntime(readFileSync(rest[0], "utf8"), readFileSync(rest[1], "utf8"));
  } else if (mode === "apk" && rest.length === 2) {
    problems = checkApk(readFileSync(rest[0]), rest[1].split(",").filter((abi) => abi !== ""));
  } else if (mode === "manifest" && rest.length === 2 && ["release", "debug"].includes(rest[1])) {
    problems = checkManifest(readFileSync(rest[0], "utf8"), rest[1]);
  } else {
    process.stderr.write("usage: check-android-deps.mjs runtime <report> <list> | apk <apk> <abis> | manifest <tree> <release|debug>\n");
    return 2;
  }
  if (problems.length > 0) {
    process.stderr.write(`check-android-deps ${mode}: FAIL\n${problems.map((problem) => `- ${problem}`).join("\n")}\n`);
    return 1;
  }
  process.stdout.write(`check-android-deps ${mode}: OK\n`);
  return 0;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  process.exitCode = main(process.argv.slice(2));
}
