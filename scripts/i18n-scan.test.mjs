import assert from "node:assert/strict";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { androidXmlViolations, cataloguePaths, check, stringLiterals, violations } from "./i18n-scan.mjs";

const root = join(fileURLToPath(new URL(".", import.meta.url)), "..");

test("Hangul literals outside the catalogues are found; comments, catalogues and tests are not", () => {
  const source = [
    "// 주석은 보지 않는다",
    "/* 블록 \"주석\" */",
    "const A: &str = \"보이는 문구\";",
    "crate::texts! {",
    "    B = \"카탈로그\" / \"catalogue\";",
    "}",
    "const C: Text = Tpl { ko: \"한국어 쪽\", en: \"English side\" };",
    "let d = r#\"원시 \"문자열\"\"#;",
    "let e = 'x';",
    "#[cfg(test)]",
    "mod tests {",
    "    const F: &str = \"시험\";",
    "}",
  ].join("\n");
  const found = violations(source, true).map(({ value }) => value);
  assert.deepEqual(found, ["보이는 문구", "원시 \"문자열\""]);
});

test("every #[cfg(test)] item is skipped, wherever it is and however it is declared", () => {
  const source = [
    "#[cfg(test)]",
    "pub(crate) mod tests;",
    "const A: &str = \"선언 뒤의 문구\";",
    "    #[cfg(test)]",
    "    const B: &str = \"시험 전용 {;\";",
    "#[cfg(test)]",
    "pub(crate) mod helpers {",
    "    fn f() { let _ = \"시험 }\"; }",
    "}",
    "const C: &str = \"끝의 문구\";",
  ].join("\n");
  const found = violations(source, true).map(({ value }) => value);
  assert.deepEqual(found, ["선언 뒤의 문구", "끝의 문구"]);
});

test("JavaScript strings of every quote kind are literals", () => {
  const values = stringLiterals("const a = \"하나\"; const b = '둘'; const c = `셋`; // 넷", false)
    .map(({ value }) => value);
  assert.deepEqual(values, ["하나", "둘", "셋"]);
});

test("the yw-engine module tree is scanned under its own crate name (spec/15 §11.4 S2)", () => {
  const paths = cataloguePaths(root, "yw_engine", "crates/yw-engine/src/lib.rs");
  for (const path of ["yw_engine::errors::text", "yw_engine::approval::labels", "yw_engine::approval::text"]) {
    assert.ok(paths.includes(path), path);
  }
  assert.ok(!cataloguePaths(root, "yw_app", "crates/yw-app/src/lib.rs").includes("yw_app::errors::text"));
});

test("Java has no catalogue: every Hangul literal is a violation (spec/15 §3.3 N24)", () => {
  const java = [
    "// 주석은 보지 않는다",
    "final class A {",
    "    static final String B = \"보이는 문구\";",
    "    static final char C = '나';",
    "    static final String D = \"plain\";",
    "}",
  ].join("\n");
  assert.deepEqual(violations(java, false).map(({ value }) => value), ["보이는 문구", "나"]);
});

test("Android XML: Hangul only in values-ko/strings.xml, a manifest label only a string resource (spec/15 §3.3 N24)", () => {
  const manifest = (label) => `<manifest>\n    <application\n        android:label="${label}">\n    </application>\n</manifest>\n`;
  const at = "android/app/src/main/AndroidManifest.xml";
  assert.deepEqual(androidXmlViolations(at, manifest("@string/app_name")), []);
  assert.deepEqual(androidXmlViolations(at, manifest("지갑")), [
    { count: 2, first: "android:label=\"지갑\">" },
    { count: 1, first: "android:label=\"지갑\" is not a string resource" },
  ]);
  assert.deepEqual(androidXmlViolations(at, manifest("Your Wallet")),
    [{ count: 1, first: "android:label=\"Your Wallet\" is not a string resource" }]);
  assert.deepEqual(androidXmlViolations(at, "<manifest>\n<!-- 주석 -->\n</manifest>\n"), [{ count: 2, first: "<!-- 주석 -->" }]);
  const strings = "<resources>\n    <string name=\"app_name\">내 지갑</string>\n</resources>\n";
  assert.deepEqual(androidXmlViolations("android/app/src/main/res/values-ko/strings.xml", strings), []);
  assert.deepEqual(androidXmlViolations("android/app/src/main/res/values/strings.xml", strings),
    [{ count: 3, first: "<string name=\"app_name\">내 지갑</string>" }]);
  assert.deepEqual(androidXmlViolations("android/app/src/debug/res/values-ko/strings.xml", strings),
    [{ count: 3, first: "<string name=\"app_name\">내 지갑</string>" }]);
});

test("the repository has no Hangul literal outside catalogues except the allowlisted files", () => {
  assert.deepEqual(check(root), []);
});
