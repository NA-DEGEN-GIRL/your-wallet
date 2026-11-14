#!/usr/bin/env node
// spec/14 §4 (2026-11-14): 부분 번역 방지 검사. 비시험 코드(crates/yw-core/src, crates/yw-app/src,
// extension/src)의 한글 문자열 리터럴은 문구 카탈로그(`texts!`·`rules!` 블록, `ko:` 필드) 안에만
// 있어야 한다. 아직 옮기지 않은 파일은 scripts/i18n-allowlist.txt에 적고(3단계에서 비운다),
// 목록에 있는데 더는 한글 리터럴이 없는 파일도 실패로 본다(목록이 줄어들기만 하게).
// 주석, #[cfg(test)] 항목(모듈·선언·단일 항목), tests 파일은 보지 않는다.

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

// String literals ({ start, end, value }) and comment spans ([start, end)) of Rust or JavaScript
// source.
function lex(text, rust) {
  const literals = [];
  const comments = [];
  let index = 0;
  while (index < text.length) {
    const character = text[index];
    const next = text[index + 1];
    if (character === "/" && next === "/") {
      const end = text.indexOf("\n", index);
      const stop = end === -1 ? text.length : end;
      comments.push([index, stop]);
      index = stop;
    } else if (character === "/" && next === "*") {
      const end = text.indexOf("*/", index + 2);
      const stop = end === -1 ? text.length : end + 2;
      comments.push([index, stop]);
      index = stop;
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
      index = Math.min(text.length, stop + close.length);
      literals.push({ start: cursor - hashes - 1, end: index, value: text.slice(cursor + 1, stop) });
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
      const start = index;
      index = Math.min(text.length, cursor + 1);
      literals.push({ start, end: index, value });
    } else if (rust && character === "'") {
      // A char literal ('x', '\n', '\u{..}') or a lifetime.
      const match = /^'(?:\\u\{[0-9a-fA-F]+\}|\\.|[^\\'])'/u.exec(text.slice(index, index + 12));
      index += match === null ? 1 : match[0].length;
    } else {
      index += 1;
    }
  }
  return { literals, comments };
}

// String literals of Rust or JavaScript source with their offsets; comments are skipped.
export function stringLiterals(text, rust) {
  return lex(text, rust).literals;
}

function blank(text) {
  return text.replace(/[^\n]/gu, " ");
}

// Rust source with its literals and comments blanked (same offsets and lines).
function maskRust(text) {
  const { literals, comments } = lex(text, true);
  const spans = [...literals.map(({ start, end }) => [start, end]), ...comments].sort((x, y) => x[0] - y[0]);
  let masked = "";
  let at = 0;
  for (const [begin, end] of spans) {
    if (begin >= at) {
      masked += text.slice(at, begin) + blank(text.slice(begin, end));
      at = end;
    }
  }
  return masked + text.slice(at);
}

// The source with every `#[cfg(test)]` item blanked out: a test module block, a `mod tests;`
// declaration or a single test-only item, at any indentation and visibility. Braces and
// semicolons inside literals and comments do not count. (2026-11-14: before, everything after
// the first top-level `#[cfg(test)] mod` was skipped, which hid the rest of a file whose test
// module is declared near the top, and missed `pub(crate) mod tests`.)
function withoutTestItems(text) {
  const masked = maskRust(text);
  const attribute = /^[ \t]*#\[cfg\(test\)\]/gmu;
  let out = "";
  let kept = 0;
  for (let match = attribute.exec(masked); match !== null; match = attribute.exec(masked)) {
    let depth = 0;
    let cursor = match.index + match[0].length;
    for (; cursor < masked.length; cursor += 1) {
      const character = masked[cursor];
      if (character === "{" || character === "[" || character === "(") {
        depth += 1;
      } else if (character === "]" || character === ")") {
        depth -= 1;
      } else if (character === "}") {
        depth -= 1;
        if (depth === 0) {
          break;
        }
      } else if (character === ";" && depth === 0) {
        break;
      }
    }
    out += text.slice(kept, match.index) + blank(text.slice(match.index, cursor + 1));
    kept = Math.min(text.length, cursor + 1);
    attribute.lastIndex = kept;
  }
  return out + text.slice(kept);
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
  const source = rust ? withoutTestItems(text) : text;
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

// spec/14 §4 (2026-11-14): every `texts!` block outside test code is listed, by its module path,
// in its crate's catalogue registry, so `tests/lang_spec.rs` compares it with the spec tables.
const REGISTRIES = [
  { crate: "yw_core", lib: "crates/yw-core/src/lib.rs", registry: "crates/yw-core/src/lang.rs" },
  { crate: "yw_app", lib: "crates/yw-app/src/lib.rs", registry: "crates/yw-app/src/catalogues.rs" },
];

// The source files of a crate's module tree from its lib.rs: [{ file, path: ["yw_app", …] }],
// following `mod name;` and `#[path = "…"] mod name;`; modules declared `#[cfg(test)]` and their
// children are left out.
function moduleFiles(repositoryRoot, crate, lib) {
  const out = [];
  const visit = (file, path) => {
    out.push({ file, path });
    const masked = withoutTestItems(readFileSync(join(repositoryRoot, file), "utf8"));
    const source = readFileSync(join(repositoryRoot, file), "utf8");
    const directory = file.split("/").slice(0, -1).join("/");
    const stem = file.split("/").pop().replace(/\.rs$/u, "");
    const own = ["lib", "main", "mod"].includes(stem) ? directory : `${directory}/${stem}`;
    const declaration = /^[ \t]*(?:pub(?:\([\w:]+\))?\s+)?mod\s+(\w+)\s*;/gmu;
    for (let match = declaration.exec(masked); match !== null; match = declaration.exec(masked)) {
      const before = source.slice(0, match.index).split("\n").slice(-4).join("\n");
      const attribute = /#\[path\s*=\s*"([^"]+)"\]\s*$/u.exec(before);
      const name = match[1];
      const candidates = attribute === null
        ? [`${own}/${name}.rs`, `${own}/${name}/mod.rs`]
        : [`${directory}/${attribute[1]}`];
      const found = candidates.find((candidate) => {
        try {
          return statSync(join(repositoryRoot, candidate)).isFile();
        } catch {
          return false;
        }
      });
      if (found !== undefined) {
        visit(found, [...path, name]);
      }
    }
  };
  visit(lib, [crate]);
  return out;
}

// [start, end) offsets and names of the inline `mod name { … }` blocks of masked source.
function inlineModules(masked) {
  const modules = [];
  const opening = /(?:pub(?:\([\w:]+\))?\s+)?mod\s+(\w+)\s*\{/gu;
  for (let match = opening.exec(masked); match !== null; match = opening.exec(masked)) {
    let depth = 0;
    let cursor = match.index + match[0].length - 1;
    for (; cursor < masked.length; cursor += 1) {
      if (masked[cursor] === "{") {
        depth += 1;
      } else if (masked[cursor] === "}") {
        depth -= 1;
        if (depth === 0) {
          break;
        }
      }
    }
    modules.push({ start: match.index, end: cursor, name: match[1] });
  }
  return modules;
}

// The module paths of every non-test `texts!` block of a crate.
export function cataloguePaths(repositoryRoot, crate, lib) {
  const paths = [];
  for (const { file, path } of moduleFiles(repositoryRoot, crate, lib)) {
    const masked = withoutTestItems(readFileSync(join(repositoryRoot, file), "utf8"));
    const modules = inlineModules(masked);
    const invocation = /\btexts!\s*\{/gu;
    for (let match = invocation.exec(masked); match !== null; match = invocation.exec(masked)) {
      const inner = modules
        .filter(({ start, end }) => start < match.index && match.index < end)
        .sort((a, b) => a.start - b.start)
        .map(({ name }) => name);
      paths.push([...path, ...inner].join("::"));
    }
  }
  return paths;
}

export function registryProblems(repositoryRoot) {
  const problems = [];
  for (const { crate, lib, registry } of REGISTRIES) {
    const listed = new Set(
      [...readFileSync(join(repositoryRoot, registry), "utf8").matchAll(/"((?:yw_core|yw_app)::[\w:]+)",/gu)]
        .map((match) => match[1]),
    );
    const found = new Set(cataloguePaths(repositoryRoot, crate, lib));
    for (const path of found) {
      if (!listed.has(path)) {
        problems.push(`${path}: texts! 카탈로그가 ${registry}에 없습니다`);
      }
    }
    for (const path of listed) {
      if (!found.has(path)) {
        problems.push(`${path}: ${registry}에 있지만 그런 texts! 카탈로그가 없습니다`);
      }
    }
  }
  return problems;
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
  problems.push(...registryProblems(repositoryRoot));
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
