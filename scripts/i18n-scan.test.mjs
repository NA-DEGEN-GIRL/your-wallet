import assert from "node:assert/strict";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { check, stringLiterals, violations } from "./i18n-scan.mjs";

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

test("the repository has no Hangul literal outside catalogues except the allowlisted files", () => {
  assert.deepEqual(check(root), []);
});
