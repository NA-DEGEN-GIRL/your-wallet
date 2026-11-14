#!/usr/bin/env node
// spec/14 §4 (2026-11-14): 부분 번역 방지 검사. 비시험 코드(crates/yw-core/src, crates/yw-app/src,
// extension/src)의 한글 문자열 리터럴은 문구 카탈로그(`texts!`·`rules!` 블록, `ko:` 필드) 안에만
// 있어야 한다. 아직 옮기지 않은 파일은 scripts/i18n-allowlist.txt에 적고(3단계에서 비운다),
// 목록에 있는데 더는 한글 리터럴이 없는 파일도 실패로 본다(목록이 줄어들기만 하게).
// 주석, #[cfg(test)] 모듈(파일 끝), tests 파일은 보지 않는다.

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

const HANGUL = /[ᄀ-ᇿ㄰-㆏ꥠ-꥿가-힯ힰ-퟿]/u;
const ROOTS = ["crates/yw-core/src", "crates/yw-app/src", "extension/src"];
const CATALOGUE_MACROS = ["texts!", "rules!"];
// The language card shows the first two in both languages (spec/14 §1); the last two are font
// measurement probes, never shown.
const ALLOWED_LITERALS = new Set(["언어 · Language", "한국어", "가Ay", "가"]);

function isTestFile(path) {
  const name = path.split(/[\\/]/u).pop();
  return name === "tests.rs" || /^tests_.*\.rs$/u.test(name) || /_tests\.rs$/u.test(name)
    || path.split(/[\\/]/u).includes("tests");
}

function walk(directory, out) {
  for (const name of readdirSync(directory)) {
    const path = join(directory, name);
    if (statSync(path).isDirectory()) {
      walk(path, out);
    } else if (/\.(rs|js|mjs)$/u.test(name)) {
      out.push(path);
    }
  }
}

// The source up to the first top-level `#[cfg(test)]` test module (this repository keeps unit
// tests at the end of a file).
function withoutTestModule(text) {
  const match = /^#\[cfg\(test\)\]\s*\n(?:#\[[^\n]*\]\s*\n)*mod\s/mu.exec(text);
  return match === null ? text : text.slice(0, match.index);
}

// String literals of Rust or JavaScript source with their offsets; comments are skipped.
export function stringLiterals(text, rust) {
  const literals = [];
  let index = 0;
  while (index < text.length) {
    const character = text[index];
    const next = text[index + 1];
    if (character === "/" && next === "/") {
      const end = text.indexOf("\n", index);
      index = end === -1 ? text.length : end;
    } else if (character === "/" && next === "*") {
      const end = text.indexOf("*/", index + 2);
      index = end === -1 ? text.length : end + 2;
    } else if (rust && character === "r" && (next === "\"" || next === "#") && !/[\w]/u.test(text[index - 1] ?? "")) {
      let hashes = 0;
      let cursor = index + 1;
      while (text[cursor] === "#") {
        hashes += 1;
        cursor += 1;
      }
      if (text[cursor] !== "\"") {
        index += 1;
        continue;
      }
      const close = "\"" + "#".repeat(hashes);
      const end = text.indexOf(close, cursor + 1);
      const stop = end === -1 ? text.length : end;
      literals.push({ start: index, value: text.slice(cursor + 1, stop) });
      index = stop + close.length;
    } else if (character === "\"" || (!rust && (character === "'" || character === "`"))) {
      let cursor = index + 1;
      let value = "";
      while (cursor < text.length && text[cursor] !== character) {
        if (text[cursor] === "\\") {
          value += text.slice(cursor, cursor + 2);
          cursor += 2;
        } else {
          value += text[cursor];
          cursor += 1;
        }
      }
      literals.push({ start: index, value });
      index = cursor + 1;
    } else if (rust && character === "'") {
      // A char literal ('x', '\n', '\u{..}') or a lifetime.
      const match = /^'(?:\\u\{[0-9a-fA-F]+\}|\\.|[^\\'])'/u.exec(text.slice(index, index + 12));
      index += match === null ? 1 : match[0].length;
    } else {
      index += 1;
    }
  }
  return literals;
}

// [start, end) offsets of every `texts! { … }` / `rules! { … }` block.
function catalogueSpans(text) {
  const spans = [];
  for (const macro of CATALOGUE_MACROS) {
    let from = 0;
    for (;;) {
      const at = text.indexOf(`${macro} {`, from);
      if (at === -1) {
        break;
      }
      let depth = 0;
      let cursor = text.indexOf("{", at);
      for (; cursor < text.length; cursor += 1) {
        if (text[cursor] === "{") {
          depth += 1;
        } else if (text[cursor] === "}") {
          depth -= 1;
          if (depth === 0) {
            break;
          }
        }
      }
      spans.push([at, cursor]);
      from = cursor;
    }
  }
  return spans;
}

// Hangul literals outside catalogues (`ko:` struct fields count as catalogue entries).
export function violations(text, rust) {
  const source = rust ? withoutTestModule(text) : text;
  const spans = catalogueSpans(source);
  return stringLiterals(source, rust).filter(({ start, value }) => {
    if (!HANGUL.test(value) || ALLOWED_LITERALS.has(value)) {
      return false;
    }
    if (spans.some(([begin, end]) => start > begin && start < end)) {
      return false;
    }
    const before = source.slice(Math.max(0, start - 16), start);
    return !/\bko:\s*$/u.test(before);
  });
}

export function scan(repositoryRoot) {
  const files = [];
  for (const root of ROOTS) {
    walk(join(repositoryRoot, root), files);
  }
  const offending = [];
  for (const path of files) {
    const rel = relative(repositoryRoot, path).split(sep).join("/");
    if (isTestFile(rel) || rel.endsWith(".test.mjs")) {
      continue;
    }
    const found = violations(readFileSync(path, "utf8"), rel.endsWith(".rs"));
    if (found.length > 0) {
      offending.push({ path: rel, count: found.length, first: found[0].value });
    }
  }
  return offending;
}

export function readAllowlist(repositoryRoot) {
  return readFileSync(join(repositoryRoot, "scripts/i18n-allowlist.txt"), "utf8")
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter((line) => line !== "" && !line.startsWith("#"));
}

export function check(repositoryRoot) {
  const allow = new Set(readAllowlist(repositoryRoot));
  const offending = scan(repositoryRoot);
  const problems = [];
  for (const { path, count, first } of offending) {
    if (!allow.has(path)) {
      problems.push(`${path}: 카탈로그 밖 한글 리터럴 ${count}개 (예: "${first.slice(0, 40)}")`);
    }
  }
  const found = new Set(offending.map(({ path }) => path));
  for (const path of allow) {
    if (!found.has(path)) {
      problems.push(`${path}: 한글 리터럴이 없습니다 — scripts/i18n-allowlist.txt에서 지우세요`);
    }
  }
  return problems;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const root = join(fileURLToPath(new URL(".", import.meta.url)), "..");
  if (process.argv.includes("--list")) {
    for (const { path, count } of scan(root)) {
      process.stdout.write(`${path}\t${count}\n`);
    }
  } else {
    const problems = check(root);
    if (problems.length > 0) {
      process.stderr.write(`${problems.join("\n")}\n`);
      process.exitCode = 1;
    } else {
      process.stdout.write("i18n-scan: OK\n");
    }
  }
}
