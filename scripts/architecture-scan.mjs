import { lstat, open, readFile, readdir } from "node:fs/promises";
import { createHash } from "node:crypto";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { TextDecoder } from "node:util";

const root = resolve(import.meta.dirname, "..");

async function text(path) {
  return trustedRegularFileText(path);
}

function sameFileSystemObjectSnapshot(left, right) {
  return (
    (process.platform === "win32" || left.dev === right.dev) &&
    left.ino === right.ino &&
    left.mode === right.mode &&
    left.nlink === right.nlink &&
    left.size === right.size &&
    left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs
  );
}

function sameRegularFileSnapshot(left, right) {
  return (
    left.isFile() &&
    right.isFile() &&
    sameFileSystemObjectSnapshot(left, right)
  );
}

function sameDirectorySnapshot(left, right) {
  return (
    left.isDirectory() &&
    right.isDirectory() &&
    sameFileSystemObjectSnapshot(left, right)
  );
}

async function trustedRegularFileText(path) {
  const absolute = resolve(root, path);
  const pathBefore = await lstat(absolute, { bigint: true });
  if (
    pathBefore.isSymbolicLink() ||
    !pathBefore.isFile() ||
    pathBefore.nlink !== 1n
  ) {
    throw new Error(`trusted input must be a regular single-link file: ${path}`);
  }

  const handle = await open(absolute, "r");
  try {
    const openedBefore = await handle.stat({ bigint: true });
    if (!sameRegularFileSnapshot(pathBefore, openedBefore)) {
      throw new Error(`trusted input identity changed before read: ${path}`);
    }
    const source = await handle.readFile({ encoding: "utf8" });
    const openedAfter = await handle.stat({ bigint: true });
    const pathAfter = await lstat(absolute, { bigint: true });
    if (
      pathAfter.isSymbolicLink() ||
      !sameRegularFileSnapshot(openedBefore, openedAfter) ||
      !sameRegularFileSnapshot(openedAfter, pathAfter)
    ) {
      throw new Error(`trusted input changed during held-handle read: ${path}`);
    }
    return source;
  } finally {
    await handle.close();
  }
}

async function trustedDirectoryEntryInventory(path) {
  const absolute = resolve(root, path);
  const directoryBefore = await lstat(absolute, { bigint: true });
  if (directoryBefore.isSymbolicLink() || !directoryBefore.isDirectory()) {
    throw new Error(`trusted inventory root must be a non-link directory: ${path}`);
  }
  const entries = await readdir(absolute, { withFileTypes: true });
  const inventory = [];
  for (const entry of entries) {
    const entryPath = join(absolute, entry.name);
    const snapshot = await lstat(entryPath, { bigint: true });
    inventory.push({
      name: entry.name,
      kind: snapshot.isSymbolicLink()
        ? "symbolic-link"
        : snapshot.isFile()
          ? "file"
          : snapshot.isDirectory()
            ? "directory"
            : "other",
    });
  }
  const directoryAfter = await lstat(absolute, { bigint: true });
  if (!sameDirectorySnapshot(directoryBefore, directoryAfter)) {
    throw new Error(`trusted inventory directory changed during scan: ${path}`);
  }
  return inventory.sort((left, right) => left.name.localeCompare(right.name, "en"));
}

async function repositoryCargoOverridePaths() {
  const paths = [];
  const ignoredDirectoryNames = new Set([
    ".agents",
    ".codex",
    ".git",
    ".handoff",
    "node_modules",
    "target",
  ]);
  async function walk(directory) {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const absolute = join(directory, entry.name);
      if (entry.name.toLowerCase() === ".cargo") {
        paths.push(relative(root, absolute).replaceAll("\\", "/"));
        continue;
      }
      if (
        entry.isDirectory() &&
        !ignoredDirectoryNames.has(entry.name.toLowerCase())
      ) {
        await walk(absolute);
      }
    }
  }
  await walk(root);
  return paths.sort((left, right) => left.localeCompare(right, "en"));
}

function cargoLockPackageRecords(source) {
  return [
    ...source.matchAll(
      /(?:^|\r?\n)\[\[package\]\]\r?\n(?<body>[\s\S]*?)(?=\r?\n\[\[package\]\]|\s*$)/gu,
    ),
  ].map((match) => {
    const field = (name) =>
      new RegExp(`^${name}\\s*=\\s*"(?<value>[^"]+)"\\s*$`, "mu").exec(
        match.groups.body,
      )?.groups.value ?? null;
    const dependencies =
      /^dependencies\s*=\s*\[(?<body>[\s\S]*?)^\]\s*$/mu.exec(
        match.groups.body,
      )?.groups.body ?? "";
    return {
      name: field("name"),
      version: field("version"),
      source: field("source"),
      checksum: field("checksum"),
      dependencies: [
        ...dependencies.matchAll(/^\s*"(?<name>[^"]+)",?\s*$/gmu),
      ].map((dependency) => dependency.groups.name),
    };
  });
}

function maskRustRange(characters, source, start, end) {
  for (let index = start; index < end; index += 1) {
    if (source[index] !== "\r" && source[index] !== "\n") {
      characters[index] = " ";
    }
  }
}

function rustLexicalCode(source) {
  const characters = source.split("");
  for (let index = 0; index < source.length; ) {
    if (source.startsWith("//", index)) {
      const end = source.indexOf("\n", index + 2);
      const exclusiveEnd = end === -1 ? source.length : end;
      maskRustRange(characters, source, index, exclusiveEnd);
      index = exclusiveEnd;
      continue;
    }
    if (source.startsWith("/*", index)) {
      let depth = 1;
      let cursor = index + 2;
      while (cursor < source.length && depth !== 0) {
        if (source.startsWith("/*", cursor)) {
          depth += 1;
          cursor += 2;
        } else if (source.startsWith("*/", cursor)) {
          depth -= 1;
          cursor += 2;
        } else {
          cursor += 1;
        }
      }
      if (depth !== 0) {
        throw new Error("architecture scan found an unterminated Rust block comment");
      }
      maskRustRange(characters, source, index, cursor);
      index = cursor;
      continue;
    }
    if (source[index] === "r") {
      let delimiter = index + 1;
      while (source[delimiter] === "#") {
        delimiter += 1;
      }
      if (source[delimiter] === '"') {
        const hashes = source.slice(index + 1, delimiter);
        const closing = `"${hashes}`;
        const close = source.indexOf(closing, delimiter + 1);
        if (close === -1) {
          throw new Error("architecture scan found an unterminated Rust raw string");
        }
        const exclusiveEnd = close + closing.length;
        maskRustRange(characters, source, index, exclusiveEnd);
        index = exclusiveEnd;
        continue;
      }
    }
    if (source[index] === '"') {
      let cursor = index + 1;
      let escaped = false;
      while (cursor < source.length) {
        if (!escaped && source[cursor] === '"') {
          cursor += 1;
          break;
        }
        if (!escaped && source[cursor] === "\\") {
          escaped = true;
        } else {
          escaped = false;
        }
        cursor += 1;
      }
      if (cursor > source.length || source[cursor - 1] !== '"') {
        throw new Error("architecture scan found an unterminated Rust string");
      }
      maskRustRange(characters, source, index, cursor);
      index = cursor;
      continue;
    }
    if (source[index] === "'") {
      const character = /^'(?:[^'\\\r\n]|\\(?:x[\dA-Fa-f]{2}|u\{[\dA-Fa-f_]+\}|.))'/u.exec(
        source.slice(index),
      );
      if (character !== null) {
        const exclusiveEnd = index + character[0].length;
        maskRustRange(characters, source, index, exclusiveEnd);
        index = exclusiveEnd;
        continue;
      }
    }
    index += 1;
  }
  return characters.join("");
}

function matchingRustDelimiter(sourceCode, opening, open, close) {
  let depth = 0;
  for (let index = opening; index < sourceCode.length; index += 1) {
    if (sourceCode[index] === open) {
      depth += 1;
    } else if (sourceCode[index] === close) {
      depth -= 1;
      if (depth === 0) {
        return index;
      }
    }
  }
  return -1;
}

function rustBraceDepthBefore(sourceCode, end) {
  let depth = 0;
  for (let index = 0; index < end; index += 1) {
    if (sourceCode[index] === "{") {
      depth += 1;
    } else if (sourceCode[index] === "}") {
      depth -= 1;
    }
  }
  return depth;
}

function rustCfgMetaCallArguments(expression, name) {
  const code = rustLexicalCode(expression).trim();
  const prefix = new RegExp(`^${name}\\s*\\(`, "u").exec(code);
  if (prefix === null) {
    return null;
  }
  const opening = code.indexOf("(", prefix.index);
  const closing = matchingRustDelimiter(code, opening, "(", ")");
  if (closing === -1 || code.slice(closing + 1).trim() !== "") {
    return null;
  }
  const argumentsSource = code.slice(opening + 1, closing);
  const argumentsList = [];
  let depth = 0;
  let start = 0;
  for (let index = 0; index <= argumentsSource.length; index += 1) {
    const character = argumentsSource[index];
    if (character === "(") {
      depth += 1;
    } else if (character === ")") {
      depth -= 1;
      if (depth < 0) {
        return null;
      }
    } else if ((character === "," || index === argumentsSource.length) && depth === 0) {
      const argument = argumentsSource.slice(start, index).trim();
      if (argument !== "") {
        argumentsList.push(argument);
      }
      start = index + 1;
    }
  }
  return depth === 0 ? argumentsList : null;
}

function rustCfgExpressionRequiresTest(expression) {
  const code = rustLexicalCode(expression).trim();
  if (code === "test") {
    return true;
  }
  const allArguments = rustCfgMetaCallArguments(code, "all");
  if (allArguments !== null) {
    return allArguments.some((argument) =>
      rustCfgExpressionRequiresTest(argument),
    );
  }
  const anyArguments = rustCfgMetaCallArguments(code, "any");
  if (anyArguments !== null) {
    return (
      anyArguments.length > 0 &&
      anyArguments.every((argument) =>
        rustCfgExpressionRequiresTest(argument),
      )
    );
  }
  return false;
}

function withoutBottomTestModule(source) {
  const sourceCode = rustLexicalCode(source);
  const candidates = [
    ...sourceCode.matchAll(
      /(?:^|\n)[\t ]*#\s*\[\s*cfg\s*\((?<expression>[^\]\r\n]*)\)\s*\][\t ]*(?:\r?\n[\t ]*)?mod\s+tests\s*\{/gu,
    ),
  ].filter(
    (match) =>
      rustBraceDepthBefore(sourceCode, match.index) === 0 &&
      rustCfgExpressionRequiresTest(match.groups.expression),
  );
  if (candidates.length === 0) {
    return source;
  }
  if (candidates.length !== 1) {
    throw new Error("architecture scan requires exactly one bottom Rust test module");
  }
  const marker = candidates[0];
  const openingBrace = sourceCode.indexOf("{", marker.index);
  const closingBrace = matchingRustDelimiter(sourceCode, openingBrace, "{", "}");
  if (closingBrace === -1) {
    throw new Error("architecture scan found an unterminated bottom Rust test module");
  }
  if (sourceCode.slice(closingBrace + 1).trim() !== "") {
    throw new Error(
      "architecture scan requires the bottom Rust test module to be the final lexical item",
    );
  }
  return source.slice(0, marker.index);
}

function endOfRustItemAfterAttribute(sourceCode, attributeEnd) {
  let cursor = attributeEnd;
  while (/\s/u.test(sourceCode[cursor] ?? "")) {
    cursor += 1;
  }
  for (;;) {
    const attachedAttribute = /^#\s*\[/u.exec(sourceCode.slice(cursor));
    if (attachedAttribute === null) {
      break;
    }
    const openingBracket =
      cursor + attachedAttribute[0].lastIndexOf("[");
    const closingBracket = matchingRustDelimiter(
      sourceCode,
      openingBracket,
      "[",
      "]",
    );
    if (closingBracket === -1) {
      return -1;
    }
    cursor = closingBracket + 1;
    while (/\s/u.test(sourceCode[cursor] ?? "")) {
      cursor += 1;
    }
  }

  const itemSource = sourceCode.slice(cursor);
  const visibility = String.raw`(?:pub(?:\s*\([^)]*\))?\s+)?`;
  const bracedOrSemicolonItem = new RegExp(
    `^${visibility}(?:(?:(?:const|async|unsafe)\\s+)*(?:extern(?:\\s+"[^"\\r\\n]*")?\\s+)?fn\\b|(?:unsafe\\s+)?(?:impl|trait)\\b|(?:struct|enum|union|mod)\\b|(?:unsafe\\s+)?extern(?:\\s+"[^"\\r\\n]*")?\\s*\\{)`,
    "u",
  ).test(itemSource);
  const semicolonItem = new RegExp(
    `^${visibility}(?:use\\b|type\\s+(?:r#)?[\\p{XID_Start}_][\\p{XID_Continue}_]*\\b|const\\s+(?:(?:r#)?[\\p{XID_Start}_][\\p{XID_Continue}_]*|_)\\s*:|static\\s+(?:mut\\s+)?(?:r#)?[\\p{XID_Start}_][\\p{XID_Continue}_]*\\s*:|extern\\s+crate\\b)`,
    "u",
  ).test(itemSource);
  if (!bracedOrSemicolonItem && !semicolonItem) {
    return null;
  }

  let parentheses = 0;
  let brackets = 0;
  let braces = 0;
  for (let index = cursor; index < sourceCode.length; index += 1) {
    switch (sourceCode[index]) {
      case "(":
        parentheses += 1;
        break;
      case ")":
        parentheses -= 1;
        break;
      case "[":
        brackets += 1;
        break;
      case "]":
        brackets -= 1;
        break;
      case "{":
        if (
          bracedOrSemicolonItem &&
          parentheses === 0 &&
          brackets === 0 &&
          braces === 0
        ) {
          const closingBrace = matchingRustDelimiter(sourceCode, index, "{", "}");
          return closingBrace === -1 ? -1 : closingBrace + 1;
        }
        braces += 1;
        break;
      case "}":
        braces -= 1;
        if (braces < 0) {
          return -1;
        }
        break;
      case ";":
        if (parentheses === 0 && brackets === 0 && braces === 0) {
          return index + 1;
        }
        break;
      default:
        break;
    }
  }
  return -1;
}

function withoutCfgTestItems(source) {
  const sourceCode = rustLexicalCode(source);
  const characters = source.split("");
  for (const attribute of sourceCode.matchAll(
    /#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]/gu,
  )) {
    const end = endOfRustItemAfterAttribute(
      sourceCode,
      attribute.index + attribute[0].length,
    );
    if (end === null) {
      continue;
    }
    if (end === -1) {
      throw new Error("architecture scan could not bound a cfg(test) Rust item");
    }
    maskRustRange(characters, source, attribute.index, end);
  }
  return characters.join("");
}

function normalizeRustFragment(fragment) {
  return fragment.replace(/\s+/gu, " ").trim();
}

function rustCallSites(source, callee) {
  const sourceCode = rustLexicalCode(source);
  const escapedCallee = callee.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  const calls = [];
  for (const match of sourceCode.matchAll(
    new RegExp(`\\b${escapedCallee}\\s*\\(`, "gu"),
  )) {
    const opening = sourceCode.indexOf("(", match.index);
    const closing = matchingRustDelimiter(sourceCode, opening, "(", ")");
    if (closing === -1) {
      throw new Error(`architecture scan could not bound ${callee} call`);
    }
    const argumentsList = [];
    let argumentStart = opening + 1;
    let parentheses = 0;
    let brackets = 0;
    let braces = 0;
    for (let index = argumentStart; index < closing; index += 1) {
      switch (sourceCode[index]) {
        case "(":
          parentheses += 1;
          break;
        case ")":
          parentheses -= 1;
          break;
        case "[":
          brackets += 1;
          break;
        case "]":
          brackets -= 1;
          break;
        case "{":
          braces += 1;
          break;
        case "}":
          braces -= 1;
          break;
        case ",":
          if (parentheses === 0 && brackets === 0 && braces === 0) {
            argumentsList.push(
              normalizeRustFragment(source.slice(argumentStart, index)),
            );
            argumentStart = index + 1;
          }
          break;
        default:
          break;
      }
    }
    const finalArgument = normalizeRustFragment(
      source.slice(argumentStart, closing),
    );
    if (finalArgument !== "") {
      argumentsList.push(finalArgument);
    }
    calls.push({
      index: match.index,
      arguments: argumentsList,
      source: source.slice(match.index, closing + 1),
    });
  }
  return calls;
}

function rustStructLiteralSites(source, typeName) {
  const sourceCode = rustLexicalCode(source);
  const escapedType = typeName.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  const literals = [];
  for (const match of sourceCode.matchAll(
    new RegExp(`\\b${escapedType}\\s*\\{`, "gu"),
  )) {
    const prefix = sourceCode.slice(Math.max(0, match.index - 32), match.index);
    if (/(?:->|\b(?:struct|enum|union|impl|for))\s*$/u.test(prefix)) {
      continue;
    }
    const opening = sourceCode.indexOf("{", match.index);
    const closing = matchingRustDelimiter(sourceCode, opening, "{", "}");
    if (closing === -1) {
      throw new Error(`architecture scan could not bound ${typeName} literal`);
    }
    literals.push({
      index: match.index,
      source: source.slice(match.index, closing + 1),
    });
  }
  return literals;
}

function rustImplItems(source) {
  const sourceCode = rustLexicalCode(source);
  const items = [];
  for (let index = 0; index < sourceCode.length; index += 1) {
    if (
      !sourceCode.startsWith("impl", index) ||
      /[A-Za-z0-9_]/u.test(sourceCode[index - 1] ?? "") ||
      /[A-Za-z0-9_]/u.test(sourceCode[index + 4] ?? "")
    ) {
      continue;
    }

    const prefix = sourceCode.slice(0, index);
    if (/(?:->|[:=<])\s*$/u.test(prefix)) {
      continue;
    }

    const delimiters = [];
    let opening = -1;
    header: for (let cursor = index + 4; cursor < sourceCode.length; cursor += 1) {
      const character = sourceCode[cursor];
      switch (character) {
        case "(":
          delimiters.push(")");
          break;
        case "[":
          delimiters.push("]");
          break;
        case "<":
          delimiters.push(">");
          break;
        case ")":
        case "]":
        case ">":
          if (delimiters.at(-1) === character) {
            delimiters.pop();
          }
          break;
        case "{":
          if (delimiters.length === 0) {
            opening = cursor;
            break header;
          }
          delimiters.push("}");
          break;
        case "}":
          if (delimiters.at(-1) === "}") {
            delimiters.pop();
          }
          break;
        case ";":
          if (delimiters.length === 0) {
            throw new Error("architecture scan found an unterminated impl item");
          }
          break;
        default:
          break;
      }
    }
    if (opening === -1) {
      throw new Error("architecture scan could not bound an impl header");
    }
    const closing = matchingRustDelimiter(sourceCode, opening, "{", "}");
    if (closing === -1) {
      throw new Error("architecture scan could not bound an impl body");
    }
    items.push({
      index,
      header: normalizeRustFragment(source.slice(index, opening)),
      source: source.slice(index, closing + 1),
    });
  }
  return items;
}

function rustTypeAliasItems(source) {
  const sourceCode = rustLexicalCode(source);
  const items = [];
  for (let index = 0; index < sourceCode.length; index += 1) {
    if (
      !sourceCode.startsWith("type", index) ||
      /[A-Za-z0-9_#]/u.test(sourceCode[index - 1] ?? "") ||
      /[A-Za-z0-9_]/u.test(sourceCode[index + 4] ?? "")
    ) {
      continue;
    }

    const delimiters = [];
    let closing = -1;
    for (let cursor = index + 4; cursor < sourceCode.length; cursor += 1) {
      const character = sourceCode[cursor];
      switch (character) {
        case "(":
          delimiters.push(")");
          break;
        case "[":
          delimiters.push("]");
          break;
        case "<":
          delimiters.push(">");
          break;
        case "{":
          delimiters.push("}");
          break;
        case ")":
        case "]":
        case ">":
        case "}":
          if (delimiters.at(-1) === character) {
            delimiters.pop();
          }
          break;
        case ";":
          if (delimiters.length === 0) {
            closing = cursor;
          }
          break;
        default:
          break;
      }
      if (closing !== -1) {
        break;
      }
    }
    if (closing === -1) {
      throw new Error("architecture scan could not bound a type alias item");
    }
    items.push({
      index,
      source: source.slice(index, closing + 1),
    });
    index = closing;
  }
  return items;
}

function rustUseItems(source) {
  const sourceCode = rustLexicalCode(source);
  const items = [];
  for (let index = 0; index < sourceCode.length; index += 1) {
    if (
      !sourceCode.startsWith("use", index) ||
      /[\p{XID_Continue}_#]/u.test(sourceCode[index - 1] ?? "") ||
      /[\p{XID_Continue}_]/u.test(sourceCode[index + 3] ?? "")
    ) {
      continue;
    }

    const delimiters = [];
    let closing = -1;
    for (let cursor = index + 3; cursor < sourceCode.length; cursor += 1) {
      const character = sourceCode[cursor];
      switch (character) {
        case "(":
          delimiters.push(")");
          break;
        case "[":
          delimiters.push("]");
          break;
        case "{":
          delimiters.push("}");
          break;
        case "<":
          delimiters.push(">");
          break;
        case ")":
        case "]":
        case "}":
        case ">":
          if (delimiters.at(-1) === character) {
            delimiters.pop();
          }
          break;
        case ";":
          if (delimiters.length === 0) {
            closing = cursor;
          }
          break;
        default:
          break;
      }
      if (closing !== -1) {
        break;
      }
    }
    if (closing === -1) {
      throw new Error("architecture scan could not bound a use item");
    }
    items.push({
      index,
      source: source.slice(index, closing + 1),
    });
    index = closing;
  }
  return items;
}

function rustExpansionSensitiveUseItems(source) {
  return rustUseItems(source).filter((item) => {
    const code = rustLexicalCode(item.source);
    return /\bas\s+(?:r#)?(?:Clone|Copy|Debug|Default|Eq|Error|Hash|PartialEq|allow|assert|assert_eq|assert_ne|cfg|cfg_attr|core|debug_assert|debug_assert_eq|derive|error|expect|format|matches|must_use|offset_of|path|ptr|repr|source|std|test|thiserror|thread_local|unreachable|vec|write)\b/u.test(
      code,
    ) || /\b(?:r#)?(?:Clone|Copy|Debug|Default|Eq|Error|Hash|PartialEq|allow|assert|assert_eq|assert_ne|cfg|cfg_attr|core|debug_assert|debug_assert_eq|derive|error|expect|format|matches|must_use|offset_of|path|ptr|repr|source|std|test|thiserror|thread_local|unreachable|vec|write)\s*(?=,|\}|;|\bas\b)/u.test(
      code,
    );
  });
}

function rustFunctionSignatures(source) {
  const sourceCode = rustLexicalCode(source);
  const signatures = [];
  for (let index = 0; index < sourceCode.length; index += 1) {
    if (
      !sourceCode.startsWith("fn", index) ||
      /[A-Za-z0-9_#]/u.test(sourceCode[index - 1] ?? "") ||
      /[A-Za-z0-9_]/u.test(sourceCode[index + 2] ?? "")
    ) {
      continue;
    }

    const delimiters = [];
    let closing = -1;
    for (let cursor = index + 2; cursor < sourceCode.length; cursor += 1) {
      const character = sourceCode[cursor];
      switch (character) {
        case "(":
          delimiters.push(")");
          break;
        case "[":
          delimiters.push("]");
          break;
        case "<":
          delimiters.push(">");
          break;
        case ")":
        case "]":
        case ">":
          if (delimiters.at(-1) === character) {
            delimiters.pop();
          }
          break;
        case "{":
          if (delimiters.length === 0) {
            closing = cursor;
          } else {
            delimiters.push("}");
          }
          break;
        case "}":
          if (delimiters.at(-1) === "}") {
            delimiters.pop();
          }
          break;
        case ";":
          if (delimiters.length === 0) {
            closing = cursor;
          }
          break;
        default:
          break;
      }
      if (closing !== -1) {
        break;
      }
    }
    if (closing === -1) {
      throw new Error("architecture scan could not bound a function signature");
    }
    signatures.push({
      index,
      source: source.slice(index, closing),
    });
  }
  return signatures;
}

function rustVisibleFunctionItems(source) {
  const sourceCode = rustLexicalCode(source);
  const signatures = rustFunctionSignatures(source);
  const implItems = rustImplItems(source);
  return [
    ...sourceCode.matchAll(
      /(?<![\p{XID_Continue}_#])pub(?<scope>\s*\([^)]*\))?\s+(?:(?:const|async|unsafe|extern)\s+)*fn\s+(?<name>(?:r#)?[\p{XID_Start}_][\p{XID_Continue}_]*)/gu,
    ),
  ].map((match) => {
    const relativeFnIndex = match[0].search(/\bfn\b/u);
    const fnIndex = match.index + relativeFnIndex;
    const signature = signatures.find((item) => item.index === fnIndex);
    if (signature === undefined) {
      throw new Error(
        `architecture scan lost visible function ${match.groups.name}`,
      );
    }
    const owner = implItems
      .filter(
        (item) =>
          item.index < match.index &&
          match.index < item.index + item.source.length,
      )
      .at(-1);
    return {
      owner: owner?.header ?? "free",
      visibility: compactRust(source.slice(match.index, fnIndex)),
      name: match.groups.name.replace(/^r#/u, ""),
      signature: compactRust(signature.source),
    };
  });
}

function rustMacroInvocations(source) {
  const sourceCode = rustLexicalCode(source);
  const invocations = [];
  const macroPattern =
    /(?<![\p{XID_Continue}_#])(?<path>(?:r#)?[\p{XID_Start}_][\p{XID_Continue}_]*(?:::(?:r#)?[\p{XID_Start}_][\p{XID_Continue}_]*)*)\s*!\s*(?<opening>[([{])/gu;
  for (const match of sourceCode.matchAll(macroPattern)) {
    if (
      !match.groups.path.includes("::") &&
      /^(?:abstract|as|async|await|become|box|break|const|continue|crate|do|dyn|else|enum|extern|false|final|fn|for|gen|if|impl|in|let|loop|macro|match|mod|move|mut|override|priv|pub|ref|return|self|Self|static|struct|super|trait|true|try|type|typeof|unsafe|unsized|use|virtual|where|while|yield)$/u.test(
        match.groups.path,
      )
    ) {
      continue;
    }
    const opening = sourceCode.indexOf(match.groups.opening, match.index);
    const closingCharacter = { "(": ")", "[": "]", "{": "}" }[
      match.groups.opening
    ];
    const closing = matchingRustDelimiter(
      sourceCode,
      opening,
      match.groups.opening,
      closingCharacter,
    );
    if (closing === -1) {
      throw new Error(
        `architecture scan could not bound ${match.groups.path} macro invocation`,
      );
    }
    invocations.push({
      index: match.index,
      absolute: sourceCode.slice(Math.max(0, match.index - 2), match.index) === "::",
      path: match.groups.path,
      normalizedPath: match.groups.path
        .split("::")
        .map((segment) => segment.replace(/^r#/u, ""))
        .join("::"),
      source: source.slice(match.index, closing + 1),
    });
  }
  return invocations;
}

function rustAttributeItems(source) {
  const sourceCode = rustLexicalCode(source);
  const attributes = [];
  for (const match of sourceCode.matchAll(/#\s*(?<inner>!)?\s*\[/gu)) {
    const opening = sourceCode.indexOf("[", match.index);
    const closing = matchingRustDelimiter(sourceCode, opening, "[", "]");
    if (closing === -1) {
      throw new Error("architecture scan could not bound a Rust attribute");
    }
    attributes.push({
      index: match.index,
      inner: match.groups.inner === "!",
      source: source.slice(match.index, closing + 1),
    });
  }
  return attributes;
}

function rustAttachedOuterAttributes(source, itemIndex) {
  const sourceCode = rustLexicalCode(source);
  const preceding = rustAttributeItems(source).filter(
    (attribute) => !attribute.inner && attribute.index < itemIndex,
  );
  const attached = [];
  let cursor = itemIndex;
  for (let index = preceding.length - 1; index >= 0; index -= 1) {
    const attribute = preceding[index];
    const attributeEnd = attribute.index + attribute.source.length;
    if (attributeEnd > cursor) {
      continue;
    }
    if (sourceCode.slice(attributeEnd, cursor).trim() !== "") {
      break;
    }
    attached.unshift(attribute);
    cursor = attribute.index;
  }
  return attached;
}

function rustModuleDeclarations(source) {
  const sourceCode = rustLexicalCode(source);
  return [
    ...sourceCode.matchAll(
      /(?<![\p{XID_Continue}_#])(?:(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+(?<name>(?:r#)?[\p{XID_Start}_][\p{XID_Continue}_]*)\s*;)/gu,
    ),
  ].map((match) => ({
    index: match.index,
    name: match.groups.name.replace(/^r#/u, ""),
    source: source.slice(match.index, match.index + match[0].length),
  }));
}

function rustExternalModulePaths(filePath, source, productionPaths) {
  const crateSourceRoot = resolve(root, "crates/platform-windows/src");
  const declaringFile = resolve(root, filePath);
  return rustModuleDeclarations(source).flatMap((moduleDeclaration) => {
    const attributes = rustAttachedOuterAttributes(
      source,
      moduleDeclaration.index,
    );
    return attributes
      .filter((attribute) => /^#\s*\[\s*path\b/u.test(attribute.source))
      .map((attribute) => {
        const parsed =
          /^#\s*\[\s*path\s*=\s*"(?<literal>[^"\r\n]+)"\s*\]\s*$/u.exec(
            attribute.source,
          );
        const literal = parsed?.groups.literal ?? "[UNPARSED]";
        const target =
          parsed === null
            ? resolve(root, "[UNPARSED]")
            : resolve(dirname(declaringFile), literal);
        const sourceRelativeTarget = relative(crateSourceRoot, target);
        const workspaceRelativeTarget = relative(root, target).replaceAll(
          "\\",
          "/",
        );
        return {
          declaringFile: filePath,
          module: moduleDeclaration.name,
          literal,
          resolvedTarget: workspaceRelativeTarget,
          insideCrateSource:
            sourceRelativeTarget !== "" &&
            sourceRelativeTarget !== ".." &&
            !sourceRelativeTarget.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`) &&
            !isAbsolute(sourceRelativeTarget),
          inProductionInventory: productionPaths.has(workspaceRelativeTarget),
          attributes: attributes.map((item) => compactRust(item.source)),
        };
      });
  });
}

function rustAuthorityTypeErasureSites(source) {
  return [
    ...rustLexicalCode(source).matchAll(
      /\b(?:transmute|transmute_copy|ManuallyDrop|MaybeUninit|zeroed|uninitialized|forget|into_raw(?:_parts)?|leak)\b|\bunion\s+(?:r#)?[\p{XID_Start}_][\p{XID_Continue}_]*|\b(?:Box|Rc|Arc)::from_raw\b|\b(?:Vec|String)::from_raw_parts(?:_mut)?\b|\b(?:ptr|core::ptr|std::ptr)::(?:read|read_unaligned|write|copy|copy_nonoverlapping)\s*\(|\.\s*cast\s*::\s*<[^<>]+>\s*\(\s*\)|\bas\s+\*\s*(?:const|mut)\b|\.\s*(?:read|read_unaligned)\s*\(\s*\)|\.\s*(?:copy_to|copy_to_nonoverlapping|copy_from|copy_from_nonoverlapping|set_len)\s*\(/gu,
    ),
  ].map((match) => match[0]);
}

function normalizedSourceSha256(source) {
  return createHash("sha256")
    .update(source.replace(/\r\n?/gu, "\n"), "utf8")
    .digest("hex");
}

function rustUnsafeKeywordCount(source) {
  return [...rustLexicalCode(source).matchAll(/\bunsafe\b/gu)].length;
}

function rustUnsafeSourceInventory(files) {
  return files
    .map((file) => ({
      path: file.path,
      unsafeCount: rustUnsafeKeywordCount(file.source),
      sha256: normalizedSourceSha256(file.source),
    }))
    .filter((file) => file.unsafeCount > 0);
}

function isRustSourceFileName(name) {
  return name.replace(/[ .]+$/gu, "").toLowerCase().endsWith(".rs");
}

function isCanonicalRustSourceFileName(name) {
  return /^[a-z0-9_]+\.rs$/u.test(name);
}

function rustItemBlock(source, headerPattern) {
  headerPattern.lastIndex = 0;
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

function rustLexicalItemBlock(source, headerPattern) {
  const sourceCode = rustLexicalCode(source);
  headerPattern.lastIndex = 0;
  const header = headerPattern.exec(sourceCode);
  if (header === null) {
    return "";
  }

  let itemStart = header.index;
  while (/\s/u.test(sourceCode[itemStart] ?? "")) {
    itemStart += 1;
  }
  const openingBrace = sourceCode.indexOf("{", itemStart);
  if (openingBrace === -1) {
    return "";
  }
  const closingBrace = matchingRustDelimiter(sourceCode, openingBrace, "{", "}");
  return closingBrace === -1 ? "" : source.slice(itemStart, closingBrace + 1);
}

function rustTopLevelLexicalItemBlock(source, headerPattern) {
  const sourceCode = rustLexicalCode(source);
  const flags = headerPattern.flags.includes("g")
    ? headerPattern.flags
    : `${headerPattern.flags}g`;
  const matches = [
    ...sourceCode.matchAll(new RegExp(headerPattern.source, flags)),
  ].filter((match) => rustBraceDepthBefore(sourceCode, match.index) === 0);
  if (matches.length !== 1) {
    throw new Error(
      `architecture scan expected exactly one top-level Rust item for ${headerPattern.source}`,
    );
  }

  let itemStart = matches[0].index;
  while (/\s/u.test(sourceCode[itemStart] ?? "")) {
    itemStart += 1;
  }
  const openingBrace = sourceCode.indexOf("{", itemStart);
  if (openingBrace === -1) {
    return "";
  }
  const closingBrace = matchingRustDelimiter(sourceCode, openingBrace, "{", "}");
  return closingBrace === -1 ? "" : source.slice(itemStart, closingBrace + 1);
}

function rustTopLevelFunctionBlock(source, functionName) {
  const escapedName = functionName.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  return rustTopLevelLexicalItemBlock(
    source,
    new RegExp(
      `(?:^|\\n)\\s*(?:pub(?:\\([^\\r\\n)]*\\))?\\s+)?(?:(?:const|async|unsafe)\\s+)*(?:extern(?:\\s+"[^"\\r\\n]*")?\\s+)?fn\\s+${escapedName}\\b[^{}]*\\{`,
      "u",
    ),
  );
}

function rustTopLevelConstItem(source, constantName) {
  const sourceCode = rustLexicalCode(source);
  const escapedName = constantName.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  const matches = [
    ...sourceCode.matchAll(
      new RegExp(`(?:^|\\n)\\s*const\\s+${escapedName}\\b`, "gu"),
    ),
  ].filter((match) => rustBraceDepthBefore(sourceCode, match.index) === 0);
  if (matches.length !== 1) {
    throw new Error(
      `architecture scan expected exactly one top-level Rust const ${constantName}`,
    );
  }

  let itemStart = matches[0].index;
  while (/\s/u.test(sourceCode[itemStart] ?? "")) {
    itemStart += 1;
  }
  let parentheses = 0;
  let brackets = 0;
  let braces = 0;
  for (let index = itemStart; index < sourceCode.length; index += 1) {
    switch (sourceCode[index]) {
      case "(":
        parentheses += 1;
        break;
      case ")":
        parentheses -= 1;
        break;
      case "[":
        brackets += 1;
        break;
      case "]":
        brackets -= 1;
        break;
      case "{":
        braces += 1;
        break;
      case "}":
        braces -= 1;
        break;
      case ";":
        if (parentheses === 0 && brackets === 0 && braces === 0) {
          return source.slice(itemStart, index + 1);
        }
        break;
      default:
        break;
    }
  }
  return "";
}

function rustFunctionBlock(source, functionName) {
  const escapedName = functionName.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  return rustLexicalItemBlock(
    source,
    new RegExp(
      `(?:^|\\n)\\s*(?:pub(?:\\([^\\r\\n)]*\\))?\\s+)?(?:(?:const|async|unsafe)\\s+)*(?:extern(?:\\s+\"[^\"\\r\\n]*\")?\\s+)?fn\\s+${escapedName}\\b[^{}]*\\{`,
      "u",
    ),
  );
}

async function rustProductionSources(
  relativeDirectory,
  { withoutInlineTests = false, withTestCode = false } = {},
) {
  const files = [];
  async function walk(directory) {
    const directoryBefore = await lstat(directory, { bigint: true });
    if (directoryBefore.isSymbolicLink() || !directoryBefore.isDirectory()) {
      const path = relative(root, directory).replaceAll("\\", "/");
      throw new Error(`Rust production inventory contains a non-directory: ${path}`);
    }
    const entries = await readdir(directory, { withFileTypes: true });
    const caseFoldedEntryNames = new Set();
    for (const entry of entries) {
      if (/[ .]$/u.test(entry.name)) {
        const path = relative(root, join(directory, entry.name)).replaceAll(
          "\\",
          "/",
        );
        throw new Error(
          `Rust production entry has a forbidden Win32 trailing-dot/space alias: ${path}`,
        );
      }
      const caseFoldedName = entry.name
        .replace(/[ .]+$/gu, "")
        .toLowerCase();
      if (caseFoldedEntryNames.has(caseFoldedName)) {
        const path = relative(root, directory).replaceAll("\\", "/");
        throw new Error(
          `Rust production directory has case-ambiguous entries: ${path}`,
        );
      }
      caseFoldedEntryNames.add(caseFoldedName);
      const absolute = join(directory, entry.name);
      if (entry.isSymbolicLink()) {
        const path = relative(root, absolute).replaceAll("\\", "/");
        throw new Error(`Rust production inventory contains a symbolic link: ${path}`);
      }
      if (entry.isDirectory()) {
        await walk(absolute);
      } else if (entry.isFile() && isRustSourceFileName(entry.name)) {
        if (!isCanonicalRustSourceFileName(entry.name)) {
          const path = relative(root, absolute).replaceAll("\\", "/");
          throw new Error(
            `Rust production source extension must be canonical lowercase .rs: ${path}`,
          );
        }
        files.push(absolute);
      }
    }
    const directoryAfter = await lstat(directory, { bigint: true });
    if (!sameDirectorySnapshot(directoryBefore, directoryAfter)) {
      const path = relative(root, directory).replaceAll("\\", "/");
      throw new Error(`Rust production directory changed during scan: ${path}`);
    }
  }

  await walk(resolve(root, relativeDirectory));
  files.sort((left, right) => left.localeCompare(right, "en"));
  return Promise.all(
    files.map(async (absolute) => {
      const path = relative(root, absolute).replaceAll("\\", "/");
      const rawSource = await trustedRegularFileText(path);
      const source = withTestCode
        ? rawSource
        : withoutBottomTestModule(rawSource);
      return {
        path,
        source:
          withoutInlineTests && !withTestCode
            ? withoutCfgTestItems(source)
            : source,
      };
    }),
  );
}

async function repositoryPowerShellSources() {
  const files = [];
  const ignoredRootDirectories = new Set([
    ".git",
    ".agents",
    ".codex",
    ".handoff",
    "node_modules",
    "target",
  ]);
  async function walk(directory) {
    const isRoot = resolve(directory) === root;
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const absolute = join(directory, entry.name);
      if (
        isRoot &&
        entry.isDirectory() &&
        ignoredRootDirectories.has(entry.name)
      ) {
        continue;
      }
      if (entry.isSymbolicLink()) {
        const path = relative(root, absolute).replaceAll("\\", "/");
        throw new Error(`repository inventory contains a symbolic link: ${path}`);
      }
      if (entry.isDirectory()) {
        await walk(absolute);
      } else if (entry.isFile()) {
        const extension = entry.name.toLowerCase();
        if (
          extension.endsWith(".ps1") ||
          extension.endsWith(".psm1") ||
          extension.endsWith(".psd1")
        ) {
          files.push(absolute);
        }
      }
    }
  }

  await walk(root);
  files.sort((left, right) => left.localeCompare(right, "en"));
  return Promise.all(
    files.map(async (absolute) => {
      const path = relative(root, absolute).replaceAll("\\", "/");
      const bytes = await readFile(absolute);
      const hasUtf8Bom =
        bytes.length >= 3 &&
        bytes[0] === 0xef &&
        bytes[1] === 0xbb &&
        bytes[2] === 0xbf;
      let source;
      if (hasUtf8Bom) {
        try {
          source = new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(3));
        } catch {
          throw new Error(`PowerShell source is not valid UTF-8 with BOM: ${path}`);
        }
      } else if (bytes.every((byte) => byte <= 0x7f)) {
        source = bytes.toString("ascii");
      } else {
        throw new Error(
          `PowerShell source must be ASCII or valid UTF-8 with BOM: ${path}`,
        );
      }
      if (source.includes("\u0000")) {
        throw new Error(`PowerShell source contains a NUL byte: ${path}`);
      }
      return {
        path,
        sha256: createHash("sha256").update(bytes).digest("hex"),
        source: source.replace(/\r\n?/gu, "\n"),
      };
    }),
  );
}

async function releasePolicyTestSources() {
  const directory = resolve(root, "scripts/release");
  const entries = (await readdir(directory, { withFileTypes: true }))
    .filter((entry) => entry.name.endsWith(".test.mjs"))
    .sort((left, right) => left.name.localeCompare(right.name, "en"));
  return Promise.all(
    entries.map(async (entry) => {
      const path = `scripts/release/${entry.name}`;
      if (entry.isSymbolicLink() || !entry.isFile()) {
        throw new Error(`release-policy test is not a regular file: ${path}`);
      }
      const bytes = await readFile(resolve(root, path));
      if (
        bytes.length >= 3 &&
        bytes[0] === 0xef &&
        bytes[1] === 0xbb &&
        bytes[2] === 0xbf
      ) {
        throw new Error(`release-policy test must not use a UTF-8 BOM: ${path}`);
      }
      let source;
      try {
        source = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
      } catch {
        throw new Error(`release-policy test is not valid UTF-8: ${path}`);
      }
      if (source.includes("\u0000")) {
        throw new Error(`release-policy test contains a NUL byte: ${path}`);
      }
      return {
        path,
        sha256: createHash("sha256").update(bytes).digest("hex"),
        source: source.replace(/\r\n?/gu, "\n"),
      };
    }),
  );
}

function hasExactCaseInsensitivePathInventory(actualPaths, approvedPaths) {
  const actual = actualPaths.map((path) => path.toLowerCase());
  const approved = approvedPaths.map((path) => path.toLowerCase());
  return (
    new Set(actual).size === actual.length &&
    new Set(approved).size === approved.length &&
    JSON.stringify([...actual].sort()) === JSON.stringify([...approved].sort())
  );
}

function hasExactSourcePins(sources, approvedPins) {
  const approvedPaths = Object.keys(approvedPins);
  return (
    hasExactCaseInsensitivePathInventory(
      sources.map(({ path }) => path),
      approvedPaths,
    ) &&
    sources.every(
      ({ path, sha256 }) => approvedPins[path.toLowerCase()] === sha256,
    )
  );
}

function requireInvariant(condition, message) {
  if (!condition) {
    throw new Error(`architecture invariant failed: ${message}`);
  }
}

const rustBottomTestProductionFixture = [
  "fn production() {",
  '    let _ = r###"} /* lexical trivia */"###;',
  "}",
].join("\n");
const rustBottomTestFixture = [
  rustBottomTestProductionFixture,
  "#[cfg(test)]",
  "mod tests {",
  '    const TEXT: &str = r#"}"#;',
  "    /* { nested comment brace } */",
  "}",
  "",
].join("\n");
let rustBottomTestRejectedTrailingProduction = false;
try {
  withoutBottomTestModule(`${rustBottomTestFixture}fn hidden_production() {}\n`);
} catch {
  rustBottomTestRejectedTrailingProduction = true;
}
const rustBottomProductionCapableCfgFixtures = [
  "#[cfg(any(test, windows))]\nmod tests { fn production_on_windows() {} }\n",
  "#[cfg(not(test))]\nmod tests { fn production_outside_tests() {} }\n",
  "#[cfg(any(test, not(test)))]\nmod tests { fn production_tautology() {} }\n",
];
const rustBottomTestRequiredCfgFixtures = [
  "#[cfg(all(test, windows))]\nmod tests { fn windows_test_only() {} }\n",
  "#[cfg(any(test, all(windows, test)))]\nmod tests { fn nested_test_only() {} }\n",
];
requireInvariant(
  withoutBottomTestModule(rustBottomTestFixture) ===
      rustBottomTestProductionFixture &&
    rustBottomTestRejectedTrailingProduction &&
    rustBottomProductionCapableCfgFixtures.every(
      (fixture) => withoutBottomTestModule(fixture) === fixture,
    ) &&
    rustBottomTestRequiredCfgFixtures.every(
      (fixture) => withoutBottomTestModule(fixture) === "",
    ),
  "Rust production slicing must remove only bottom modules whose cfg logically requires test, preserve production-capable compound/negated forms, balance them lexically, and reject any later item",
);
requireInvariant(
  isCanonicalRustSourceFileName("module.rs") &&
    [
      "module.RS",
      "module.Rs",
      "module.rS",
      "Module.rs",
      "module.rs.",
      "module.rs ",
    ].every(
      (name) =>
        isRustSourceFileName(name) && !isCanonicalRustSourceFileName(name),
    ) &&
    !isRustSourceFileName("module.rs.txt"),
  "Rust source discovery must recognize case-insensitive extensions and accept only canonical lowercase .rs names",
);
const rustCfgTestNonItemFixtures = [
  `
enum Transport {
    #[cfg(test)]
    PinnedLibtestTerse,
}
struct ProductionAfterVariant;
`,
  `
struct Evidence {
    #[cfg(test)]
    test_only: bool,
    production: u8,
}
fn production_after_field() {}
`,
  `
fn classify(value: u8) {
    match value {
        #[cfg(test)]
        0 => test_only(),
        _ => production(),
    }
}
fn production_after_arm() {}
`,
  `
fn execute() {
    #[cfg(test)]
    test_only();
    production();
}
fn production_after_statement() {}
`,
  `
fn execute_const_block() {
    #[cfg(test)]
    const { test_only() };
    production();
}
fn production_after_const_block() {}
`,
];
const rustCfgTestFullItemFixture = `
#[cfg(test)]
fn test_only_item() {}
fn production_after_item() {}
`;
const rustCfgTestFullItemRelease = rustLexicalCode(
  withoutCfgTestItems(rustCfgTestFullItemFixture),
);
requireInvariant(
  rustCfgTestNonItemFixtures.every(
    (fixture) => withoutCfgTestItems(fixture) === fixture,
  ) &&
    !rustCfgTestFullItemRelease.includes("test_only_item") &&
    rustCfgTestFullItemRelease.includes("production_after_item"),
  "cfg(test) slicing must remove only complete Rust items and preserve variants, fields, match arms, statements, and all following production code",
);

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

const rootManifest = await trustedRegularFileText("Cargo.toml");
const rootManifestSha256 = normalizedSourceSha256(rootManifest);
const rootReadme = await text("README.md");
const sepoliaArchitectureDoc = await text("docs/architecture.md");
const sepoliaDemoManifest = await text("demo/sepolia-wallet/Cargo.toml");
const sepoliaDemoLock = await text("demo/sepolia-wallet/Cargo.lock");
const sepoliaDemoMain = await text("demo/sepolia-wallet/src/main.rs");
const sepoliaDemoBackend = await text("demo/sepolia-wallet/src/backend.rs");
const sepoliaDemoErc20 = await text("demo/sepolia-wallet/src/erc20.rs");
const sepoliaDemoRpc = await text("demo/sepolia-wallet/src/rpc.rs");
const sepoliaDemoReceiveQr = await text("demo/sepolia-wallet/src/receive_qr.rs");
const sepoliaDemoUi = await text("demo/sepolia-wallet/src/ui.rs");
const sepoliaDemoHeadless = await text("demo/sepolia-wallet/src/headless.rs");
const sepoliaDemoVaultV2 = await text("demo/sepolia-wallet/src/vault_v2.rs");
const sepoliaDemoTokenStore = await text("demo/sepolia-wallet/src/token_store.rs");
const sepoliaDemoActivityStore = await text(
  "demo/sepolia-wallet/src/activity_store.rs",
);
const qrcodegenLockBlock =
  /\[\[package\]\]\r?\nname = "qrcodegen"\r?\n[\s\S]*?(?=\r?\n\[\[package\]\]|\s*$)/u.exec(
    sepoliaDemoLock,
  )?.[0] ?? "";
requireInvariant(
  !rootManifest.includes("demo/sepolia-wallet"),
  "Sepolia demo must remain outside the production workspace",
);
requireInvariant(
  /^publish\s*=\s*false$/mu.test(sepoliaDemoManifest) && /^\[workspace\]$/mu.test(sepoliaDemoManifest),
  "Sepolia demo must remain non-publishable and independently locked",
);
for (const productionSecretCrate of [
  "secret-core",
  "key-agent",
  "platform-windows",
  "secret-input-ui",
]) {
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
requireInvariant(
  sepoliaDemoUi.includes("pub struct SensitiveText(Zeroizing<String>);") &&
    /pub struct SecretReveal\s*\{[\s\S]*?text:\s*Zeroizing<String>[\s\S]*?\}/u.test(
      sepoliaDemoUi,
    ) &&
    /pub struct GeneratedBackupReveal\s*\{[\s\S]*?phrase:\s*Zeroizing<String>[\s\S]*?first_address:\s*Zeroizing<String>[\s\S]*?\}/u.test(
      sepoliaDemoUi,
    ) &&
    /pub struct GeneratedBackupConfirmation\s*\{[\s\S]*?words:\s*\[SensitiveText;[\s\S]*?first_address:\s*SensitiveText[\s\S]*?\}/u.test(
      sepoliaDemoUi,
    ) &&
    !/#\[derive\([^\]]*(?:Clone|Copy|Debug|Serialize)[^\]]*\)\]\s*pub struct (?:SensitiveText|SecretReveal|GeneratedBackupReveal|GeneratedBackupConfirmation)/u.test(
      sepoliaDemoUi,
    ) &&
    !/impl\s+(?:Clone|Copy|Debug|Serialize)\s+for\s+(?:SensitiveText|SecretReveal|GeneratedBackupReveal|GeneratedBackupConfirmation)/u.test(
      sepoliaDemoUi,
    ),
  "Sepolia secret input/reveal/confirmation wrappers must stay zeroizing and move-only",
);
requireInvariant(
  sepoliaDemoUi.includes(
    "const SECRET_REVEAL_DURATION: Duration = Duration::from_secs(20)",
  ) &&
    sepoliaDemoUi.includes(".selectable(false)") &&
    !/copy_text\s*\([^)]*(?:secret|reveal|mnemonic|private_key)/isu.test(sepoliaDemoUi),
  "Sepolia secret reveal must stay short-lived, non-selectable, and clipboard-free",
);

const generatedChallengeBody =
  /pub struct GeneratedBackupChallenge\s*\{(?<body>[\s\S]*?)\n\}/u.exec(sepoliaDemoUi)
    ?.groups?.body ?? "";
const generatedConfirmationBody =
  /fn confirm_generated\([\s\S]*?(?=\n    fn ensure_generated_confirmation_live)/u.exec(
    sepoliaDemoBackend,
  )?.[0] ?? "";
requireInvariant(
  sepoliaDemoBackend.includes(
    "const GENERATED_BACKUP_TTL: Duration = Duration::from_secs(120)",
    ) &&
    sepoliaDemoBackend.includes("enum PendingGeneratedStage") &&
    sepoliaDemoBackend.includes("Display") &&
    /Challenge\s*\{\s*positions:\s*\[u8;/u.test(sepoliaDemoBackend) &&
    sepoliaDemoBackend.includes("random_backup_challenge_positions") &&
    sepoliaDemoBackend.includes("const MAX_RANDOM_SAMPLES: usize = 256") &&
    generatedChallengeBody.includes("positions:") &&
    generatedChallengeBody.includes("expires_at:") &&
    !/(?:phrase|mnemonic|expected|first_address|SensitiveText|Zeroizing|Serialize|Debug)/u.test(
      generatedChallengeBody,
    ) &&
    sepoliaDemoUi.includes("BeginGeneratedBackupChallenge") &&
    sepoliaDemoUi.includes("confirmation: GeneratedBackupConfirmation") &&
    sepoliaDemoUi.includes("permit: &SessionPermit<'_>") &&
    (generatedConfirmationBody.match(/ensure_generated_confirmation_live\(/gu) ?? [])
      .length === 5 &&
    generatedConfirmationBody.indexOf("verify_generated_backup") <
      generatedConfirmationBody.indexOf("seal_vault_v2") &&
    generatedConfirmationBody.indexOf("seal_vault_v2") <
      generatedConfirmationBody.indexOf("open_vault_v2") &&
    generatedConfirmationBody.indexOf("open_vault_v2") <
      generatedConfirmationBody.indexOf("write_new_file") &&
    sepoliaDemoUi.includes("events.retain_mut(retain_generated_backup_event)") &&
    /Event::Paste\(text\)[\s\S]*?text\.zeroize\(\)[\s\S]*?false/u.test(
      sepoliaDemoUi,
    ) &&
    sepoliaDemoUi.includes("fn secret_text_edit_ids() -> [egui::Id; 16]") &&
    sepoliaDemoUi.includes("state.clear_undoer()") &&
    sepoliaDemoUi.includes(
      "data.remove::<egui::widgets::text_edit::TextEditState>(id)",
    ) &&
    !/#\[derive\([^\]]*(?:Clone|Debug|Serialize)[^\]]*\)\]\s*(?:enum WorkerCommand|enum WorkerEvent|struct WorkerResponse)/u.test(
      sepoliaDemoUi,
    ),
  "Sepolia generated-backup challenge lost deadline, move-only DTO, permit, clipboard, undo, or no-write-before-verification guards",
);
requireInvariant(
  sepoliaDemoBackend.includes("V2(OpenedVaultV2)") &&
    sepoliaDemoBackend.includes("selected_account_index: u8") &&
    sepoliaDemoBackend.includes("pending_generation: Option<PendingGeneratedWallet>") &&
    sepoliaDemoBackend.includes("self.ensure_management_mutation_allowed()?") &&
    sepoliaDemoBackend.includes("path_may_exist(&self.pending_path)"),
  "Sepolia v2 unlock/bounded-account/pending-quarantine management boundary changed",
);

// Sepolia authenticated saved ERC-20 transfer invariants (demo-only).
const sepoliaDemoBackendProduction = withoutBottomTestModule(sepoliaDemoBackend);
const sepoliaDemoErc20Production = withoutBottomTestModule(sepoliaDemoErc20);
const sepoliaDemoRpcProduction = withoutBottomTestModule(sepoliaDemoRpc);
const sepoliaDemoReceiveQrProduction = withoutBottomTestModule(sepoliaDemoReceiveQr);
const sepoliaDemoUiProduction = withoutBottomTestModule(sepoliaDemoUi);
const sepoliaDemoHeadlessProduction = withoutBottomTestModule(sepoliaDemoHeadless);
const sepoliaDemoUiHeadlessStart = sepoliaDemoUiProduction.indexOf(
  "pub(crate) fn run_headless_smoke",
);
const sepoliaDemoUiRuntime =
  sepoliaDemoUiHeadlessStart === -1
    ? sepoliaDemoUiProduction
    : sepoliaDemoUiProduction.slice(0, sepoliaDemoUiHeadlessStart);

// Sepolia bounded account switching is authenticated, session-only, and
// bound independently at every prepare/confirm/export/pending boundary.
const selectAccountBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "select_account_inner",
);
const walletSnapshotBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "snapshot",
);
const openWalletBlock = rustFunctionBlock(sepoliaDemoBackendProduction, "open");
const lockWalletBlock = rustFunctionBlock(sepoliaDemoBackendProduction, "lock");
const prepareNativeAccountBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "prepare_transfer_inner",
);
const confirmAccountBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "confirm_prepared_with_permit",
);
const exportSelectedAccountBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "export_account_private_key_inner",
);
const tokenAccountContextBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "token_context",
);
const tokenAccountContextForAccountBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "token_context_for_account",
);
const preparePendingAccountBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "prepare_pending_retry",
);
const retryPendingAccountBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "retry_pending_with_permit",
);
const recoverPendingSenderBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "recover_signed_type_two_sender",
);
const pendingLeaseBlock = rustItemBlock(
  sepoliaDemoBackendProduction,
  /(?:^|\n)struct PendingFileLease\s*\{/u,
);
const pendingWriteBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "write_new_pending",
);
const accountSelectedUiBlock = rustItemBlock(
  sepoliaDemoUiProduction,
  /WorkerEvent::AccountSelected\(result\)\s*=>\s*match result\s*\{/u,
);
const walletAppBlock = rustItemBlock(
  sepoliaDemoUiProduction,
  /(?:^|\n)pub struct WalletApp\s*\{/u,
);
const walletAppImplBlock = rustItemBlock(
  sepoliaDemoUiProduction,
  /(?:^|\n)impl WalletApp\s*\{/u,
);
const selectAccountUiBlock = rustFunctionBlock(
  walletAppImplBlock,
  "select_account",
);
const scrubFrontendSessionBlock = rustFunctionBlock(
  walletAppImplBlock,
  "scrub_frontend_session",
);
const accountPanelBlock = rustFunctionBlock(walletAppImplBlock, "account_panel");
const walletAppNewBlock = rustFunctionBlock(walletAppImplBlock, "new");
const walletAppUnavailableBlock = rustFunctionBlock(
  walletAppImplBlock,
  "unavailable",
);
const runHeadlessSmokeBlock = rustFunctionBlock(
  sepoliaDemoUiProduction,
  "run_headless_smoke",
);
const receiveWorkerCommandBlock = rustItemBlock(
  sepoliaDemoUiProduction,
  /(?:^|\n)enum WorkerCommand\s*\{/u,
);
const receiveWorkerEventBlock = rustItemBlock(
  sepoliaDemoUiProduction,
  /(?:^|\n)enum WorkerEvent\s*\{/u,
);
const receiveRevealBlock = rustItemBlock(
  accountPanelBlock,
  /(?:^|\n)\s*if self\.receive_qr_visible\s*\{\s*ui\.add_space\(6\.0\);/u,
);
const qrLayoutImplBlock = rustItemBlock(
  sepoliaDemoReceiveQrProduction,
  /(?:^|\n)impl QrLayout\s*\{/u,
);
const qrLayoutConstructorBlock = rustFunctionBlock(qrLayoutImplBlock, "new");
const receiveQrImplBlock = rustItemBlock(
  sepoliaDemoReceiveQrProduction,
  /(?:^|\n)impl ReceiveQr\s*\{/u,
);
const receiveQrStructBlock = rustItemBlock(
  sepoliaDemoReceiveQrProduction,
  /(?:^|\n)pub\(crate\) struct ReceiveQr\s*\{/u,
);
const receiveQrConstructorBlock = rustFunctionBlock(receiveQrImplBlock, "new");
const receiveQrAmountConstructorBlock = rustFunctionBlock(
  receiveQrImplBlock,
  "new_with_native_eth_amount",
);
const receiveQrEncodeBlock = rustFunctionBlock(receiveQrImplBlock, "encode");
const receiveQrPaintBlock = rustFunctionBlock(receiveQrImplBlock, "paint");
const receiveCanonicalWeiBlock = rustFunctionBlock(
  sepoliaDemoReceiveQrProduction,
  "canonical_wei",
);
const exactEip55Block = rustFunctionBlock(
  sepoliaDemoReceiveQrProduction,
  "is_exact_eip55_address",
);
const parseTokenAmountBlock = rustFunctionBlock(
  sepoliaDemoErc20Production,
  "parse_token_amount",
);
const formatTokenAmountBlock = rustFunctionBlock(
  sepoliaDemoErc20Production,
  "format_token_amount",
);
const clearReceiveAmountRequestBlock = rustFunctionBlock(
  walletAppImplBlock,
  "clear_receive_amount_request",
);
const clearReceiveRequestStateBlock = rustFunctionBlock(
  walletAppImplBlock,
  "clear_receive_request_state",
);
const hasSensitiveSessionStateBlock = rustFunctionBlock(
  walletAppImplBlock,
  "has_sensitive_session_state",
);
const purgeQueuedSecretTextEditStateBlock = rustFunctionBlock(
  walletAppImplBlock,
  "purge_queued_secret_text_edit_state",
);
const receiveAmountTextEditIdBlock = rustFunctionBlock(
  sepoliaDemoUiProduction,
  "receive_amount_text_edit_id",
);
const secretTextEditIdsBlock = rustFunctionBlock(
  sepoliaDemoUiProduction,
  "secret_text_edit_ids",
);
const purgeSecretTextEditStateBlock = rustFunctionBlock(
  sepoliaDemoUiProduction,
  "purge_secret_text_edit_state",
);
const walletAppDropBlock = rustItemBlock(
  sepoliaDemoUiProduction,
  /(?:^|\n)impl Drop for WalletApp\s*\{/u,
);
const walletAppEframeImplBlock = rustItemBlock(
  sepoliaDemoUiProduction,
  /(?:^|\n)impl eframe::App for WalletApp\s*\{/u,
);
const walletAppUpdateBlock = rustFunctionBlock(walletAppEframeImplBlock, "update");
const receiveQrOkUiBlock = rustItemBlock(
  receiveRevealBlock,
  /(?:^|\n)\s*Ok\(qr\)\s*=>\s*\{/u,
);
const receiveQrInvalidAmountUiBlock = rustItemBlock(
  receiveRevealBlock,
  /(?:^|\n)\s*Err\(crate::receive_qr::ReceiveQrError::InvalidAmount\)\s*=>\s*\{/u,
);
const receiveAmountToggleOffBlock = rustItemBlock(
  receiveRevealBlock,
  /(?:^|\n)\s*if amount_toggle\.changed\(\) && !self\.receive_amount_requested\s*\{/u,
);
const receiveAmountInputUiBlock = rustItemBlock(
  receiveRevealBlock,
  /(?:^|\n)\s*if self\.receive_amount_requested\s*\{/u,
);
const receiveAmountBoundsTestBlock = rustFunctionBlock(
  sepoliaDemoReceiveQr,
  "native_eth_amount_is_canonical_integer_wei_and_uint256_bounded",
);
const receiveAmountGoldenTestBlock = rustFunctionBlock(
  sepoliaDemoReceiveQr,
  "native_eth_amount_uri_and_matrix_are_one_exact_payload",
);
const receiveSelectedAccountTestBlock = rustFunctionBlock(
  sepoliaDemoUi,
  "receive_qr_payload_follows_only_the_selected_account",
);
const receiveAmountPurgeTestBlock = rustFunctionBlock(
  sepoliaDemoUi,
  "receive_amount_hide_toggle_select_request_and_response_purge_actual_egui_undo",
);
const receiveAmountPanelTestBlock = rustFunctionBlock(
  sepoliaDemoUi,
  "receive_amount_panel_suppresses_invalid_and_copies_exact_valid_qr_payload",
);
const clearReceiveAmountRequestNormalized = clearReceiveAmountRequestBlock
  .replace(/\s+/gu, " ")
  .trim();
const clearReceiveRequestStateNormalized = clearReceiveRequestStateBlock
  .replace(/\s+/gu, " ")
  .trim();
const walletAppDropNormalized = walletAppDropBlock.replace(/\s+/gu, " ").trim();
const accountPrivateKeyRevealBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "account_private_key_reveal",
);
const secretRevealItem = rustItemBlock(
  sepoliaDemoUiProduction,
  /(?:^|\n)pub struct SecretReveal\s*\{/u,
);
const mnemonicExportUiBlock = rustItemBlock(
  sepoliaDemoUiProduction,
  /WorkerEvent::MnemonicExported\(result\)\s*=>\s*match result\s*\{/u,
);
const privateKeyExportUiBlock = rustItemBlock(
  sepoliaDemoUiProduction,
  /WorkerEvent::AccountPrivateKeyExported\(result\)\s*=>\s*match result\s*\{/u,
);
requireInvariant(
  sepoliaDemoBackendProduction.includes("selected_account_index: u8") &&
    sepoliaDemoBackendProduction.includes("fn account_snapshots(&self)") &&
    sepoliaDemoBackendProduction.includes("wallet.account_count() != 2") &&
    sepoliaDemoBackendProduction.includes("wallet.account(2).is_some()") &&
    selectAccountBlock.includes("wallet.account_address(index)?") &&
    selectAccountBlock.includes("self.pending_broadcast_exists()") &&
    selectAccountBlock.includes("self.prepared.is_some()") &&
    selectAccountBlock.includes("self.pending_generation.is_some()") &&
    selectAccountBlock.includes("self.selected_account_index = index") &&
    selectAccountBlock.includes("self.last_balance = None") &&
    !/(?:write_new_file|seal_vault|token_store|fs::write)/u.test(selectAccountBlock) &&
    lockWalletBlock.includes("self.selected_account_index = 0") &&
    openWalletBlock.includes("self.selected_account_index = 0") &&
    walletSnapshotBlock.includes("selected_account_index: self.selected_account_index") &&
    walletSnapshotBlock.includes("pending_broadcast:") &&
    !sepoliaDemoVaultV2.includes("selected_account_index") &&
    !sepoliaDemoTokenStore.includes("selected_account_index") &&
    !pendingWriteBlock.includes("account_index"),
  "Sepolia account 0/1 selection must remain bounded, session-only, reset-on-lock/open, and absent from vault/token/pending formats",
);
requireInvariant(
  sepoliaDemoUiProduction.includes("pub struct WalletAccountSnapshot") &&
    sepoliaDemoUiProduction.includes("pub selected_account_index: u8") &&
    sepoliaDemoUiProduction.includes("pub sender_account_index: u8") &&
    sepoliaDemoBackendProduction.includes("account_index: u8") &&
    prepareNativeAccountBlock.includes("let (account_index, sender) = self.selected_account()?") &&
    confirmAccountBlock.includes("self.selected_account_index != prepared.account_index") &&
    confirmAccountBlock.includes("wallet.account_address(prepared.account_index)?") &&
    confirmAccountBlock.includes("account_private_key(u32::from(prepared.account_index))") &&
    exportSelectedAccountBlock.includes("let (selected_index, selected_address)") &&
    exportSelectedAccountBlock.includes("let expected_index = u32::from(selected_index)") &&
    exportSelectedAccountBlock.includes("requested_index() != expected_index") &&
    exportSelectedAccountBlock.includes("export_account_private_key(u32::from(selected_index))") &&
    exportSelectedAccountBlock.includes(
      "account_private_key_reveal(export, selected_index, selected_address)",
    ) &&
    tokenAccountContextBlock.includes(
      "self.token_context_for_account(self.selected_account_index)",
    ) &&
    tokenAccountContextForAccountBlock.includes("account(usize::from(account_index))") &&
    tokenAccountContextForAccountBlock.includes("requested_index() != expected_index") &&
    tokenAccountContextForAccountBlock.includes("actual_index() != expected_index") &&
    tokenAccountContextForAccountBlock.includes("account_index,") &&
    tokenAccountContextForAccountBlock.includes("owner: *owner.address().as_bytes()") &&
    accountSelectedUiBlock.includes("self.reauth_password.zeroize()") &&
    accountSelectedUiBlock.includes("self.secret_text_state_purge_pending = true") &&
    accountSelectedUiBlock.includes("zeroize_custom_token_snapshots") &&
    accountSelectedUiBlock.includes("zeroize_optional_string(&mut self.last_transaction_hash)"),
  "Sepolia selected account identity must stay visible and independently rebound for balance, token, signer, export, and UI scrub paths",
);
requireInvariant(
  secretRevealItem.includes("account_index: Option<u8>") &&
    secretRevealItem.includes("account_address: Option<Zeroizing<String>>") &&
    accountPrivateKeyRevealBlock.includes("account_index > 1") &&
    accountPrivateKeyRevealBlock.includes("checksum_address(account_address)") &&
    mnemonicExportUiBlock.includes(
      "completed_action == Some(PendingAction::ExportMnemonic)",
    ) &&
    mnemonicExportUiBlock.includes("reveal.kind() == SecretRevealKind::Mnemonic") &&
    privateKeyExportUiBlock.includes(
      "completed_action == Some(PendingAction::ExportAccountPrivateKey)",
    ) &&
    privateKeyExportUiBlock.includes(
      "reveal.kind() == SecretRevealKind::AccountPrivateKey",
    ) &&
    privateKeyExportUiBlock.includes("index == selected.index") &&
    privateKeyExportUiBlock.includes("address == selected.address.as_str()") &&
    sepoliaDemoUiProduction.includes(
      'format!("계정 {index} 개인 키 · 전체 주소 {address}")',
    ) &&
    sepoliaDemoUiProduction.includes(
      'format!("계정 {selected_account_index} 잔액: {balance}")',
    ) &&
    !sepoliaDemoUiProduction.includes('"계정 0 개인 키"') &&
    !sepoliaDemoUiProduction.includes('"계정 0 잔액:'),
  "Sepolia secret export purpose/account binding and selected-account balance labels must remain exact and non-hardcoded",
);
requireInvariant(
  receiveQrConstructorBlock.includes("if !is_exact_eip55_address(address)") &&
    receiveQrConstructorBlock.includes(
      'format!("ethereum:{address}@{SEPOLIA_CHAIN_ID}")',
    ) &&
    receiveQrConstructorBlock.includes("Self::encode(payment_uri)") &&
    !/(?:\?|ethereum:pay-|canonical_wei|amount_eth|\bvalue\b|push_str|insert_str|\.push\(|\.extend\(|\+=|replace\()/u.test(
      receiveQrConstructorBlock,
    ) &&
    receiveQrAmountConstructorBlock.includes(
      "if !is_exact_eip55_address(address)",
    ) &&
    receiveQrAmountConstructorBlock.includes(
      "let value_wei = canonical_wei(amount_eth)?",
    ) &&
    receiveQrAmountConstructorBlock.indexOf("is_exact_eip55_address(address)") <
      receiveQrAmountConstructorBlock.indexOf("canonical_wei(amount_eth)") &&
    /format!\(\s*"ethereum:\{address\}@\{SEPOLIA_CHAIN_ID\}\?value=\{\}",\s*value_wei\.as_str\(\)\s*\)/u.test(
      receiveQrAmountConstructorBlock,
    ) &&
    receiveQrAmountConstructorBlock.includes("Self::encode(payment_uri)") &&
    !/(?:ethereum:pay-|[?&](?:amount|gas|gasLimit|gasPrice|chainId)=|push_str|insert_str|\.push\(|\.extend\(|\+=|replace\()/u.test(
      receiveQrAmountConstructorBlock,
    ) &&
    receiveQrEncodeBlock.includes(
      "QrCode::encode_text(payment_uri.as_str(), QrCodeEcc::Medium)",
    ) &&
    receiveQrEncodeBlock.includes("Ok(Self { payment_uri, code })") &&
    exactEip55Block.includes('address.strip_prefix("0x")') &&
    exactEip55Block.includes("hex.len() != ADDRESS_HEX_BYTES") &&
    exactEip55Block.includes("byte.is_ascii_hexdigit()") &&
    exactEip55Block.includes("hex.bytes().all(|byte| byte == b'0')") &&
    exactEip55Block.includes("hex.to_ascii_lowercase()") &&
    exactEip55Block.includes("Keccak256::digest(lowercase.as_bytes())") &&
    exactEip55Block.includes("byte.is_ascii_uppercase() == (nibble >= 8)") &&
    sepoliaDemoRpcProduction.includes("pub const SEPOLIA_CHAIN_ID: u64 = 11_155_111"),
  "Sepolia Receive QR must retain strict EIP-55 and only the exact address-only or native-value Sepolia payload constructors",
);
requireInvariant(
  sepoliaDemoReceiveQrProduction.includes(
    "pub(crate) const MAX_ETH_AMOUNT_INPUT_BYTES: usize = 79",
  ) &&
    sepoliaDemoReceiveQrProduction.includes("const ETH_DECIMALS: u8 = 18") &&
    /enum ReceiveQrError\s*\{[^}]*\bInvalidAmount\b/u.test(
      sepoliaDemoReceiveQrProduction,
    ) &&
    receiveCanonicalWeiBlock.includes(
      "amount_eth.len() > MAX_ETH_AMOUNT_INPUT_BYTES",
    ) &&
    receiveCanonicalWeiBlock.includes(
      "crate::erc20::parse_token_amount(amount_eth, ETH_DECIMALS)",
    ) &&
    receiveCanonicalWeiBlock.includes(
      "crate::erc20::format_token_amount(amount, 0)",
    ) &&
    receiveCanonicalWeiBlock.includes(".map(Zeroizing::new)") &&
    (receiveCanonicalWeiBlock.match(/ReceiveQrError::InvalidAmount/gu) ?? [])
      .length === 3 &&
    parseTokenAmountBlock.includes("input.is_empty()") &&
    parseTokenAmountBlock.includes("input.trim() != input") &&
    parseTokenAmountBlock.includes("matches!(byte, b'+' | b'-' | b'e' | b'E' | b',')") &&
    parseTokenAmountBlock.includes("let mut parts = input.split('.')") &&
    parseTokenAmountBlock.includes("parts.next().is_some()") &&
    parseTokenAmountBlock.includes("integer.is_empty()") &&
    parseTokenAmountBlock.includes("byte.is_ascii_digit()") &&
    parseTokenAmountBlock.includes("fraction.len() > usize::from(decimals)") &&
    parseTokenAmountBlock.includes(
      "fraction.bytes().any(|byte| !byte.is_ascii_digit())",
    ) &&
    parseTokenAmountBlock.includes("input.ends_with('.')") &&
    parseTokenAmountBlock.includes(".checked_mul_small(10)") &&
    parseTokenAmountBlock.includes(".checked_add_small(digit - b'0')") &&
    parseTokenAmountBlock.includes("if output.is_zero()") &&
    formatTokenAmountBlock.includes("if decimals == 0") &&
    formatTokenAmountBlock.includes("return Ok(decimal)"),
  "Sepolia Receive QR native amount must remain positive, <=18-decimal, uint256-bounded, category-only, and canonical integer wei",
);
requireInvariant(
  accountPanelBlock.includes("snapshot.selected_account().cloned()") &&
    accountPanelBlock.includes("copy_text(selected_account.address.clone())") &&
    /if ui\.button\([^{}]*\)\.clicked\(\)\s*\{\s*ui\.ctx\(\)\.copy_text\(selected_account\.address\.clone\(\)\);/u.test(
      accountPanelBlock,
    ) &&
    /\.add_enabled\(\s*self\.pending\.is_none\(\),\s*egui::Button::new\(receive_button_text\),\s*\)\s*\.clicked\(\)/u.test(
      accountPanelBlock,
    ) &&
    /\.clicked\(\)\s*\{\s*if self\.receive_qr_visible\s*\{\s*self\.clear_receive_request_state\(\);\s*\}\s*else\s*\{\s*self\.receive_qr_visible = true;\s*\}\s*\}/u.test(
      accountPanelBlock,
    ) &&
    receiveRevealBlock.includes("ui.toggle_value(") &&
    receiveRevealBlock.includes("&mut self.receive_amount_requested") &&
    receiveAmountToggleOffBlock.includes("self.clear_receive_amount_request()") &&
    receiveAmountInputUiBlock.includes(
      "egui::TextEdit::singleline(&mut *self.receive_amount_eth)",
    ) &&
    receiveAmountInputUiBlock.includes(".id(receive_amount_text_edit_id())") &&
    receiveAmountInputUiBlock.includes(
      ".char_limit(crate::receive_qr::MAX_ETH_AMOUNT_INPUT_BYTES)",
    ) &&
    receiveAmountInputUiBlock.includes("선택 계정 주소, 고정 Sepolia 체인, 요청 금액") &&
    receiveAmountInputUiBlock.includes("운영체제 클립보드") &&
    receiveAmountInputUiBlock.includes("강제 청구서나 입금 확인이 아닙니다") &&
    receiveAmountInputUiBlock.includes("보내는 쪽이 금액을 바꾸거나 무시할 수 있으므로") &&
    /let receive_qr = if self\.receive_amount_requested\s*\{\s*crate::receive_qr::ReceiveQr::new_with_native_eth_amount\(\s*selected_account\.address\.as_str\(\),\s*self\.receive_amount_eth\.as_str\(\),\s*\)\s*\}\s*else\s*\{\s*crate::receive_qr::ReceiveQr::new\(selected_account\.address\.as_str\(\)\)\s*\};/u.test(
      receiveRevealBlock,
    ) &&
    receiveRevealBlock.includes("selected_account.index") &&
    receiveRevealBlock.includes("crate::rpc::SEPOLIA_CHAIN_ID") &&
    receiveRevealBlock.indexOf("palette.warning") <
      receiveRevealBlock.indexOf("let receive_qr =") &&
    receiveQrOkUiBlock.includes("qr.payment_uri()") &&
    receiveQrOkUiBlock.includes("qr.paint(ui)") &&
    receiveQrOkUiBlock.includes("운영체제 클립보드는 지갑 잠금 뒤에도 남을 수 있습니다") &&
    /if ui\.button\([^{}]*\)\.clicked\(\)\s*\{\s*ui\.ctx\(\)\.copy_text\(qr\.payment_uri\(\)\.to_owned\(\)\);/u.test(
      receiveQrOkUiBlock,
    ) &&
    receiveQrInvalidAmountUiBlock.includes(
      "0보다 크고 소수점 18자리 이하인 ETH 십진수만 입력할 수 있습니다",
    ) &&
    !/(?:payment_uri|copy_text|qr\.paint|receive_amount_eth|selected_account\.address)/u.test(
      receiveQrInvalidAmountUiBlock,
    ) &&
    (receiveRevealBlock.match(/copy_text\(qr\.payment_uri\(\)\.to_owned\(\)\)/gu) ?? [])
      .length === 1 &&
    (sepoliaDemoUiProduction.match(/ReceiveQr::new\(/gu) ?? []).length === 2 &&
    (sepoliaDemoUiProduction.match(/ReceiveQr::new_with_native_eth_amount\(/gu) ?? [])
      .length === 2,
  "Sepolia Receive QR amount opt-in must stay explicit, selected-account-bound, publicly disclosed, and invalid-input fail-closed",
);
requireInvariant(
  walletAppBlock.includes("receive_qr_visible: bool") &&
    walletAppBlock.includes("receive_amount_requested: bool") &&
    walletAppBlock.includes("receive_amount_eth: Zeroizing<String>") &&
    !/pub(?:\([^)]*\))?\s+receive_(?:qr_visible|amount_requested|amount_eth)\b/u.test(
      walletAppBlock,
    ) &&
    !/#\[derive\([^\]]*(?:Clone|Copy|Debug|Serialize)[^\]]*\)\]\s*pub struct WalletApp/u.test(
      sepoliaDemoUiProduction,
    ) &&
    !/impl\s+(?:Clone|Copy|Debug|fmt::Debug|(?:std|core)::fmt::Debug|Serialize|serde::Serialize)\s+for\s+WalletApp\b/u.test(
      sepoliaDemoUiProduction,
    ) &&
    !sepoliaDemoUiRuntime.includes("receive_amount_requested = true") &&
    !/(?:receive_amount_eth\.clone\(|receive_amount_eth\.to_owned\(|clone\([^\r\n]*receive_amount_eth)/u.test(
      sepoliaDemoUiRuntime,
    ) &&
    walletAppNewBlock.includes("receive_qr_visible: false") &&
    walletAppNewBlock.includes("receive_amount_requested: false") &&
    walletAppNewBlock.includes(
      "receive_amount_eth: Zeroizing::new(String::new())",
    ) &&
    walletAppUnavailableBlock.includes("receive_qr_visible: false") &&
    walletAppUnavailableBlock.includes("receive_amount_requested: false") &&
    walletAppUnavailableBlock.includes(
      "receive_amount_eth: Zeroizing::new(String::new())",
    ) &&
    runHeadlessSmokeBlock.includes("receive_qr_visible: false") &&
    runHeadlessSmokeBlock.includes("receive_amount_requested: false") &&
    runHeadlessSmokeBlock.includes(
      "receive_amount_eth: Zeroizing::new(String::new())",
    ) &&
    hasSensitiveSessionStateBlock.includes("self.receive_amount_requested") &&
    hasSensitiveSessionStateBlock.includes("!self.receive_amount_eth.is_empty()") &&
    clearReceiveAmountRequestNormalized ===
      "fn clear_receive_amount_request(&mut self) { self.receive_amount_requested = false; self.receive_amount_eth.zeroize(); self.secret_text_state_purge_pending = true; }" &&
    clearReceiveRequestStateNormalized ===
      "fn clear_receive_request_state(&mut self) { self.receive_qr_visible = false; self.clear_receive_amount_request(); }" &&
    selectAccountUiBlock.indexOf("self.clear_receive_request_state()") <
      selectAccountUiBlock.indexOf("self.send_command(") &&
    accountSelectedUiBlock.includes("self.clear_receive_request_state()") &&
    scrubFrontendSessionBlock.includes("self.clear_receive_request_state()") &&
    walletAppDropNormalized ===
      "impl Drop for WalletApp { fn drop(&mut self) { self.active_epoch.store(u64::MAX, Ordering::SeqCst); self.scrub_frontend_session(); } }" &&
    receiveAmountTextEditIdBlock.includes(
      'egui::Id::new("sepolia-demo-receive-amount")',
    ) &&
    secretTextEditIdsBlock.includes("fn secret_text_edit_ids() -> [egui::Id; 16]") &&
    (secretTextEditIdsBlock.match(/receive_amount_text_edit_id\(\)/gu) ?? [])
      .length === 1 &&
    purgeQueuedSecretTextEditStateBlock.includes(
      "std::mem::take(&mut self.secret_text_state_purge_pending)",
    ) &&
    purgeQueuedSecretTextEditStateBlock.includes("purge_secret_text_edit_state(context)") &&
    purgeSecretTextEditStateBlock.includes("state.clear_undoer()") &&
    purgeSecretTextEditStateBlock.includes(
      "data.remove::<egui::widgets::text_edit::TextEditState>(id)",
    ) &&
    (walletAppUpdateBlock.match(/self\.purge_queued_secret_text_edit_state\(context\)/gu) ?? [])
      .length === 2,
  "Sepolia Receive QR amount state must stay private, default-off, zeroizing, exact-ID purged on live frames, and owned-input-scrubbed on Drop",
);
requireInvariant(
  !/(?:receive_amount|ReceiveAmount|new_with_native_eth_amount)/u.test(
    `${sepoliaDemoBackendProduction}\n${sepoliaDemoRpcProduction}\n${sepoliaDemoVaultV2}\n${sepoliaDemoTokenStore}\n${sepoliaDemoActivityStore}\n${sepoliaDemoHeadlessProduction}`,
  ) &&
    !/(?:receive_amount|ReceiveAmount|ReceiveQr|payment_uri)/u.test(
      `${receiveWorkerCommandBlock}\n${receiveWorkerEventBlock}`,
    ) &&
    !/(?:send_command|WorkerCommand|OpenUrl|open_url|hyperlink|Command::new|std::process|std::fs|OpenOptions|File::|std::net|TcpStream|UdpSocket|ureq::|reqwest|web_sys|tokio::|TextureHandle|load_texture)/u.test(
      receiveRevealBlock,
    ),
  "Sepolia Receive QR amount opt-in must add no worker/backend/RPC/store/schema/headless route or file/network/texture side effect",
);
const receiveAmountGoldenTestNormalized = receiveAmountGoldenTestBlock
  .replace(/\s+/gu, " ")
  .trim();
requireInvariant(
  receiveAmountBoundsTestBlock.includes('("0.000000000000000001", "1")') &&
    receiveAmountBoundsTestBlock.includes('("1.2300", "1230000000000000000")') &&
    receiveAmountBoundsTestBlock.includes('("0001", "1000000000000000000")') &&
    receiveAmountBoundsTestBlock.includes("(MAXIMUM_ETH, MAXIMUM_WEI)") &&
    receiveAmountBoundsTestBlock.includes('"0"') &&
    receiveAmountBoundsTestBlock.includes('"0.0"') &&
    receiveAmountBoundsTestBlock.includes('".1"') &&
    receiveAmountBoundsTestBlock.includes('"1."') &&
    receiveAmountBoundsTestBlock.includes('"+1"') &&
    receiveAmountBoundsTestBlock.includes('"-1"') &&
    receiveAmountBoundsTestBlock.includes('"1e2"') &&
    receiveAmountBoundsTestBlock.includes('"1,2"') &&
    receiveAmountBoundsTestBlock.includes('"1.0000000000000000001"') &&
    receiveAmountBoundsTestBlock.includes("OVERFLOW_ETH") &&
    receiveAmountBoundsTestBlock.includes(
      '"1".repeat(super::MAX_ETH_AMOUNT_INPUT_BYTES + 1)',
    ) &&
    receiveAmountGoldenTestBlock.includes(
      '"ethereum:{CHECKSUMMED_ADDRESS}@{}?value=1250000000000000000"',
    ) &&
    receiveAmountGoldenTestBlock.includes("assert_eq!(qr.code.size(), 41)") &&
    receiveAmountGoldenTestNormalized.includes(
      "[ 189, 39, 255, 98, 163, 97, 226, 214, 226, 229, 58, 23, 149, 57, 211, 218, 105, 218, 200, 28, 198, 166, 119, 43, 108, 126, 115, 252, 107, 40, 213, 202, ]",
    ) &&
    receiveAmountGoldenTestNormalized.includes(
      "[ 94, 55, 93, 190, 117, 50, 112, 133, 26, 214, 44, 165, 249, 37, 71, 21, 107, 173, 161, 224, 238, 85, 24, 21, 151, 175, 14, 53, 181, 181, 108, 183, ]",
    ) &&
    receiveSelectedAccountTestBlock.includes("for selected_index in [0, 1]") &&
    receiveSelectedAccountTestBlock.includes(
      "ReceiveQr::new(selected.address.as_str())",
    ) &&
    receiveSelectedAccountTestBlock.includes(
      "ReceiveQr::new_with_native_eth_amount(\n                selected.address.as_str(),",
    ) &&
    receiveSelectedAccountTestBlock.includes(
      '"ethereum:{}@{}?value=1250000000000000000"',
    ) &&
    (receiveSelectedAccountTestBlock.match(/!\w*qr\.payment_uri\(\)\.contains\(other\.address\.as_str\(\)\)/gu) ?? [])
      .length === 2,
  "Sepolia Receive QR amount tests must retain strict syntax/uint256 boundaries, canonical selected-account value, and exact URI/matrix goldens",
);
requireInvariant(
  receiveAmountPurgeTestBlock.includes('"hide receive QR"') &&
    receiveAmountPurgeTestBlock.includes('"turn amount request off"') &&
    receiveAmountPurgeTestBlock.includes('"start account selection"') &&
    receiveAmountPurgeTestBlock.includes('"install selected account"') &&
    receiveAmountPurgeTestBlock.includes("0 => app.clear_receive_request_state()") &&
    receiveAmountPurgeTestBlock.includes("1 => app.clear_receive_amount_request()") &&
    receiveAmountPurgeTestBlock.includes("2 => app.select_account(1)") &&
    receiveAmountPurgeTestBlock.includes(
      "app.apply_worker_event(WorkerEvent::AccountSelected(Ok(switched)))",
    ) &&
    receiveAmountPurgeTestBlock.includes("app.receive_amount_eth.is_empty()") &&
    receiveAmountPurgeTestBlock.includes("app.secret_text_state_purge_pending") &&
    receiveAmountPurgeTestBlock.includes(
      "app.purge_queued_secret_text_edit_state(&context)",
    ) &&
    receiveAmountPurgeTestBlock.includes(
      "TextEditState::load(&context, receive_amount_id)\n                    .is_none()",
    ) &&
    receiveAmountPurgeTestBlock.includes("WorkerCommand::SelectAccount { index: 1 }") &&
    receiveAmountPurgeTestBlock.includes("command: WorkerCommand::Refresh") &&
    receiveAmountPurgeTestBlock.includes("vec![undo_key_event()]") &&
    receiveAmountPurgeTestBlock.includes("recreated.is_empty()") &&
    receiveAmountPanelTestBlock.includes(
      'invalid.receive_amount_eth = zeroize::Zeroizing::new("0".to_owned())',
    ) &&
    receiveAmountPanelTestBlock.includes(
      'assert!(!rendered.contains("EIP-681 결제 URI"))',
    ) &&
    receiveAmountPanelTestBlock.includes(
      'assert!(!rendered.contains("결제 URI 복사"))',
    ) &&
    receiveAmountPanelTestBlock.includes('assert!(!rendered.contains("ethereum:"))') &&
    receiveAmountPanelTestBlock.includes("assert!(copy_button_rect.is_none())") &&
    receiveAmountPanelTestBlock.includes("assert_eq!(qr_rectangles, 0)") &&
    receiveAmountPanelTestBlock.includes(
      "ReceiveQr::new_with_native_eth_amount(\n            selected.address.as_str(),",
    ) &&
    receiveAmountPanelTestBlock.includes(
      "vec![egui::OutputCommand::CopyText(expected_uri.clone())]",
    ) &&
    receiveAmountPanelTestBlock.includes(
      "assert!(!notice.contains(expected_uri.as_str()))",
    ) &&
    receiveAmountPanelTestBlock.includes(
      "assert!(!notice.contains(selected.address.as_str()))",
    ) &&
    (receiveAmountPanelTestBlock.match(/command_receiver\.try_recv\(\)\.is_err\(\)/gu) ?? [])
      .length === 4 &&
    runHeadlessSmokeBlock.includes(
      "let amount_request = crate::receive_qr::ReceiveQr::new_with_native_eth_amount(",
    ) &&
    runHeadlessSmokeBlock.includes(
      '"ethereum:{}@{}?value=1250000000000000000"',
    ) &&
    runHeadlessSmokeBlock.includes("app.receive_amount_requested = true") &&
    runHeadlessSmokeBlock.includes("app.select_account(1)") &&
    runHeadlessSmokeBlock.includes("!app.receive_amount_eth.is_empty()") &&
    runHeadlessSmokeBlock.includes("transitions_checked: 105") &&
    runHeadlessSmokeBlock.includes("backend_routes_checked: backend.calls.len()") &&
    sepoliaDemoUi.includes("assert_eq!(evidence.transitions_checked, 105)") &&
    sepoliaDemoUi.includes("assert_eq!(evidence.backend_routes_checked, 37)") &&
    sepoliaDemoHeadless.includes("assert_eq!(report.transitions_checked, 105)") &&
    sepoliaDemoHeadless.includes("assert_eq!(report.backend_routes_checked, 37)"),
  "Sepolia Receive QR UI/headless evidence must retain invalid suppression, exact click-only copy, four live purge paths, no undo resurrection, and 105/37 accounting",
);
requireInvariant(
  sepoliaDemoReceiveQrProduction.includes("const QUIET_ZONE_MODULES: u32 = 4") &&
    sepoliaDemoReceiveQrProduction.includes("const MIN_MODULE_PIXELS: u32 = 6") &&
    qrLayoutConstructorBlock.includes(
      "let maximum_module_pixels = available_for_modules / total_modules",
    ) &&
    qrLayoutConstructorBlock.includes(
      "if maximum_module_pixels < MIN_MODULE_PIXELS",
    ) &&
    qrLayoutConstructorBlock.includes(
      "let preferred_module_pixels = (preferred_module_pixels as u32).max(MIN_MODULE_PIXELS)",
    ) &&
    qrLayoutConstructorBlock.includes(
      "let module_pixels = preferred_module_pixels.min(maximum_module_pixels)",
    ) &&
    qrLayoutConstructorBlock.indexOf(".max(MIN_MODULE_PIXELS)") <
      qrLayoutConstructorBlock.indexOf(".min(maximum_module_pixels)") &&
    qrLayoutConstructorBlock.includes("checked_add(QUIET_ZONE_MODULES * 2)") &&
    receiveQrPaintBlock.includes(
      "ui.available_rect_before_wrap().intersect(clip_rect)",
    ) &&
    receiveQrPaintBlock.includes(
      "visible_rect.width().min(visible_rect.height())",
    ) &&
    receiveQrPaintBlock.includes(
      "QrLayout::new(self.code.size(), pixels_per_point, available_side)?",
    ) &&
    receiveQrPaintBlock.includes(
      "if !clip_rect.contains(canvas.min) || !clip_rect.contains(canvas.max)",
    ) &&
    receiveQrPaintBlock.indexOf("clip_rect.contains(canvas.min)") <
      receiveQrPaintBlock.indexOf("rect_filled(canvas") &&
    receiveQrPaintBlock.includes("x + QUIET_ZONE_MODULES") &&
    receiveQrPaintBlock.includes("y + QUIET_ZONE_MODULES") &&
    receiveQrPaintBlock.includes("x + QUIET_ZONE_MODULES + 1") &&
    receiveQrPaintBlock.includes("y + QUIET_ZONE_MODULES + 1"),
  "Sepolia Receive QR must retain quiet-zone 4, >=6 integer physical modules, and whole-canvas width/height clip fail-closure",
);
requireInvariant(
  sepoliaDemoManifest.includes('qrcodegen = "=1.8.0"') &&
    qrcodegenLockBlock.includes('version = "1.8.0"') &&
    !qrcodegenLockBlock.includes("dependencies =") &&
    /^mod receive_qr;$/mu.test(sepoliaDemoMain) &&
    !/^pub(?:\(crate\))?\s+mod receive_qr;$/mu.test(sepoliaDemoMain) &&
    !/\bpub\s+use\b[^\r\n]*\breceive_qr\b/u.test(
      `${sepoliaDemoMain}\n${sepoliaDemoUiProduction}`,
    ) &&
    receiveQrStructBlock.includes("payment_uri: Zeroizing<String>") &&
    receiveQrStructBlock.includes("code: QrCode") &&
    !/(?:pub|pub\([^)]*\))\s+(?:payment_uri|code)\b/u.test(
      receiveQrStructBlock,
    ) &&
    !/#\[derive\([^\]]*(?:Clone|Copy|Debug|Serialize)[^\]]*\)\]\s*pub\(crate\) struct ReceiveQr/u.test(
      sepoliaDemoReceiveQrProduction,
    ) &&
    !/impl\s+(?:Clone|Copy|Debug|fmt::Debug|(?:std|core)::fmt::Debug|Serialize|serde::Serialize)\s+for\s+ReceiveQr\b/u.test(
      sepoliaDemoReceiveQrProduction,
    ) &&
    walletAppBlock.includes("receive_qr_visible: bool") &&
    !/(?:payment_uri|QrCode|ReceiveQr)/u.test(walletAppBlock) &&
    (sepoliaDemoReceiveQrProduction.match(/crate::rpc::/gu) ?? []).length === 1 &&
    !/(?:\bstatic\b|thread_local!|OnceLock|LazyLock|Mutex|RwLock|RefCell)/u.test(
      sepoliaDemoReceiveQrProduction,
    ) &&
    !/(?:TextureHandle|load_texture|include_bytes!|std::fs|OpenOptions|File::|std::net|TcpStream|UdpSocket|ureq::|reqwest|web_sys|tokio::)/u.test(
      sepoliaDemoReceiveQrProduction,
    ),
  "Sepolia Receive QR must stay qrcodegen 1.8.0, frame-local, and free of texture/cache/file/network APIs",
);
requireInvariant(
  rootReadme.includes("## 받기 QR 계약 (Sepolia 실행판 한정)") &&
    rootReadme.includes("`ethereum:<address>@11155111`") &&
    rootReadme.includes(
      "`ethereum:<address>@11155111?value=<canonical-decimal-wei>`",
    ) &&
    /0보다\s+큰 Sepolia ETH 십진수를 입력했을 때만, 소수점 아래 최대 18자리와 uint256 범위를\s+검사/u.test(
      rootReadme,
    ) &&
    /빈 값,\s+잘못된 형식, 0, 초과 정밀도, 범위 초과 값에서는 QR과 결제 URI 및 그 복사 버튼을\s+표시하지 않습니다/u.test(
      rootReadme,
    ) &&
    rootReadme.includes("별도의 일반 주소 복사는 그대로 사용할 수 있으며") &&
    rootReadme.includes("강제 청구서나 입금 영수증이 아니며") &&
    rootReadme.includes("운영체제 클립보드가 지갑 잠금이나 종료 뒤에도 남을 수 있습니다") &&
    rootReadme.includes("`Zeroizing` 버퍼") &&
    rootReadme.includes("별도 포렌식 삭제를 보장하지는 않습니다") &&
    /백엔드, RPC, 저장소,\s+스키마를 건드리거나 새 의존성을 추가하지 않고/u.test(
      rootReadme,
    ) &&
    rootReadme.includes("`qrcodegen =1.8.0`") &&
    rootReadme.includes("전체 QR이 현재 보이는 영역 안에 들어오지 않으면 그리지 않고") &&
    sepoliaArchitectureDoc.includes("### Sepolia demo receive QR boundary") &&
    sepoliaArchitectureDoc.includes(
      "`ethereum:<address>@11155111?value=<canonical-decimal-wei>`",
    ) &&
    /positive decimal ETH input with at most 18 fractional\s+digits and within the full uint256 range/u.test(
      sepoliaArchitectureDoc,
    ) &&
    /no URI, matrix, or URI-copy control is then\s+created/u.test(
      sepoliaArchitectureDoc,
    ) &&
    /selected address, account index, fixed Sepolia chain\s+ID, and requested amount are public financial metadata/u.test(
      sepoliaArchitectureDoc,
    ) &&
    /neither an enforced invoice\s+nor proof of payment, and the payer may alter or ignore it/u.test(
      sepoliaArchitectureDoc,
    ) &&
    /OS clipboard, which may retain it after wallet lock or\s+process exit/u.test(
      sepoliaArchitectureDoc,
    ) &&
    /Drop has no `egui::Context` with which to make a separate forensic or\s+retained-context erasure guarantee/u.test(
      sepoliaArchitectureDoc,
    ) &&
    /adds no worker command,\s+backend\/RPC call, storage or schema field, dependency, file access, or network\s+path/u.test(
      sepoliaArchitectureDoc,
    ) &&
    sepoliaArchitectureDoc.includes(
      "the entire canvas remains inside that clip before painting",
    ) &&
    /No QR texture,\s+cache, file, or network path exists/u.test(
      sepoliaArchitectureDoc,
    ),
  "Sepolia Receive QR documentation must retain address-only default, exact optional wei payload, invalid suppression, public/payment/clipboard caveats, lifecycle residual, dependency, and geometry scope",
);

// Sepolia selected-account overview hydration remains a one-shot, bounded,
// non-authoritative follow-up. It may observe authenticated token rows but may
// not mutate their namespace, and its response can update only the exact local
// account/session snapshot that initiated the request.
const selectedOverviewBlock = rustItemBlock(
  sepoliaDemoUiProduction,
  /(?:^|\n)pub struct SelectedAccountOverview\s*\{/u,
);
const selectedOverviewImplBlock = rustItemBlock(
  sepoliaDemoUiProduction,
  /(?:^|\n)impl SelectedAccountOverview\s*\{/u,
);
const selectedOverviewValidationBlock = rustFunctionBlock(
  selectedOverviewImplBlock,
  "is_well_formed",
);
const runtimeBalanceValidationBlock = rustFunctionBlock(
  sepoliaDemoUiProduction,
  "valid_runtime_balance_shape",
);
const customTokenStateValidationBlock = rustFunctionBlock(
  sepoliaDemoUiProduction,
  "custom_token_state_is_well_formed",
);
const verifySepoliaBlock = rustFunctionBlock(
  sepoliaDemoRpcProduction,
  "verify_sepolia",
);
const tokenObservationLeaseBlock = rustItemBlock(
  sepoliaDemoBackendProduction,
  /(?:^|\n)struct TokenObservationLease\s*<[^>]+>\s*\{/u,
);
const tokenObservationLeaseImplBlock = rustItemBlock(
  sepoliaDemoBackendProduction,
  /(?:^|\n)impl\s*<[^>]+>\s*TokenObservationLease\s*<[^>]+>\s*\{/u,
);
const tokenObservationAcquireBlock = rustFunctionBlock(
  tokenObservationLeaseImplBlock,
  "acquire",
);
const productionTokenObservationLockBlock =
  /#\[cfg\(not\(test\)\)\]\s*let process_guard = match TOKEN_STORE_PROCESS_LOCK\.try_lock\(\)\s*\{[\s\S]*?\n\s*\};\s*#\[cfg\(test\)\]/u.exec(
    tokenObservationAcquireBlock,
  )?.[0] ?? "";
const openTokenObservationFileBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "open_token_observation_file",
);
const refreshSelectedOverviewOuterBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "refresh_selected_overview",
);
const refreshSelectedOverviewBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "refresh_selected_overview_inner",
);
const refreshOverviewUiBlock = rustFunctionBlock(walletAppImplBlock, "refresh");
const refreshedOverviewUiBlock = rustItemBlock(
  sepoliaDemoUiProduction,
  /WorkerEvent::Refreshed\(result\)\s*=>\s*match result\s*\{/u,
);
const importedOverviewUiBlock = rustItemBlock(
  sepoliaDemoUiProduction,
  /WorkerEvent::MnemonicImported\(result\)\s*\|\s*WorkerEvent::PrivateKeyImported\(result\)\s*=>\s*\{/u,
);
const openedOverviewUiBlock = rustItemBlock(
  sepoliaDemoUiProduction,
  /WorkerEvent::Opened\(result\)\s*=>\s*match result\s*\{/u,
);
const migratedOverviewUiBlock = rustItemBlock(
  sepoliaDemoUiProduction,
  /WorkerEvent::LegacyMigrated\(result\)\s*=>\s*match result\s*\{/u,
);
const generatedConfirmedUiBlock = rustItemBlock(
  sepoliaDemoUiProduction,
  /WorkerEvent::GeneratedConfirmed\(result\)\s*=>\s*match result\s*\{/u,
);
const executeWorkerCommandBlock = rustFunctionBlock(
  sepoliaDemoUiProduction,
  "execute_worker_command",
);
const customTokenPanelBlock = rustFunctionBlock(
  walletAppImplBlock,
  "custom_token_panel",
);
requireInvariant(
  sepoliaDemoUiProduction.includes(
    "pub(crate) const AUTO_OVERVIEW_TOKEN_LIMIT: usize = 3",
  ) &&
    sepoliaDemoUiProduction.includes(
      "const MAX_RUNTIME_BALANCE_BYTES: usize = 79",
    ) &&
    sepoliaDemoUiProduction.includes(
      'pub(crate) const ACCOUNT_BALANCE_UNKNOWN: &str = "조회 전"',
    ) &&
    selectedOverviewBlock.includes("snapshot: WalletSnapshot") &&
    selectedOverviewBlock.includes("token_owner_account_index: u8") &&
    selectedOverviewBlock.includes("token_owner_address: String") &&
    selectedOverviewBlock.includes("custom_tokens: Vec<CustomTokenSnapshot>") &&
    selectedOverviewBlock.includes("token_rows_loaded: bool") &&
    selectedOverviewBlock.includes("balance_refreshed: bool") &&
    selectedOverviewBlock.includes("deferred_token_count: u8") &&
    !/#\[derive\([^\]]*(?:Clone|Copy|Debug|Serialize)[^\]]*\)\]\s*pub struct SelectedAccountOverview/u.test(
      sepoliaDemoUiProduction,
    ) &&
    !/(?:^|\n)\s*(?:unsafe\s+)?impl(?:\s*<[^>{}\r\n]*>)?\s+[^{}\r\n]+\s+for\s+[^{};\r\n]*\bSelectedAccountOverview\b/mu.test(
      sepoliaDemoUiProduction,
    ) &&
    !/\bpub(?:\([^)]*\))?\s+(?:snapshot|token_owner_account_index|token_owner_address|custom_tokens|token_rows_loaded|balance_refreshed|status|deferred_token_count)\s*:/u.test(
      selectedOverviewBlock,
    ) &&
    selectedOverviewValidationBlock.includes("self.snapshot.is_well_formed()") &&
    selectedOverviewValidationBlock.includes(
      "account.index == self.token_owner_account_index",
    ) &&
    selectedOverviewValidationBlock.includes(
      "account.address == self.token_owner_address",
    ) &&
    selectedOverviewValidationBlock.includes("self.custom_tokens.len() <= 32") &&
    selectedOverviewValidationBlock.includes(
      ".saturating_sub(AUTO_OVERVIEW_TOKEN_LIMIT)",
    ) &&
    selectedOverviewValidationBlock.includes(
      "index >= AUTO_OVERVIEW_TOKEN_LIMIT",
    ) &&
    selectedOverviewValidationBlock.includes(
      "self.snapshot.balance_eth == ACCOUNT_BALANCE_UNKNOWN",
    ) &&
    selectedOverviewValidationBlock.includes("WalletKind::LegacyV1RawPrivateKey") &&
    runtimeBalanceValidationBlock.includes(
      "amount.len() > MAX_RUNTIME_BALANCE_BYTES",
    ) &&
    customTokenStateValidationBlock.includes("*decimals <= 36") &&
    customTokenStateValidationBlock.includes("symbol.len() <= 16") &&
    customTokenStateValidationBlock.includes(
      "OVERVIEW_TOKEN_UNAVAILABLE_ERRORS.contains(&reason_ko.as_str())",
    ),
  "Sepolia selected-overview DTO must remain move-only, exact-owner-bound, bounded, canonical, and category-only",
);
requireInvariant(
  tokenObservationLeaseBlock.includes("_process_guard: MutexGuard") &&
    tokenObservationLeaseBlock.includes("_lock_file: Option<File>") &&
    tokenObservationLeaseBlock.includes("_store_file: Option<File>") &&
    productionTokenObservationLockBlock.includes(
      "TOKEN_STORE_PROCESS_LOCK.try_lock()",
    ) &&
    productionTokenObservationLockBlock.includes("TryLockError::WouldBlock") &&
    productionTokenObservationLockBlock.includes("return Ok(None)") &&
    productionTokenObservationLockBlock.includes("TryLockError::Poisoned") &&
    productionTokenObservationLockBlock.includes(
      "return Err(BackendError::TokenStoreStorage)",
    ) &&
    !productionTokenObservationLockBlock.includes(
      "TOKEN_STORE_PROCESS_LOCK.lock()",
    ) &&
    tokenObservationAcquireBlock.includes("fs::symlink_metadata(&lock_path)") &&
    tokenObservationAcquireBlock.includes("fs::symlink_metadata(token_store_path)") &&
    tokenObservationAcquireBlock.includes("FILE_ATTRIBUTE_REPARSE_POINT") &&
    tokenObservationAcquireBlock.includes("MAX_TOKEN_STORE_BYTES") &&
    tokenObservationAcquireBlock.includes("TokenObservationOpenError::Contended") &&
    tokenObservationAcquireBlock.includes("TokenObservationOpenError::NotFound") &&
    tokenObservationAcquireBlock.includes("TokenObservationOpenError::Storage") &&
    !/(?:create_new|\.write(?:_all)?\s*\(|remove_file|delete|reconcile_orphan|\.flush\s*\(|sync_all|temporary_path)/u.test(
      tokenObservationAcquireBlock,
    ) &&
    openTokenObservationFileBlock.includes(".read(true)") &&
    openTokenObservationFileBlock.includes(".share_mode(FILE_SHARE_READ.0)") &&
    openTokenObservationFileBlock.includes("FILE_FLAG_OPEN_REPARSE_POINT") &&
    openTokenObservationFileBlock.includes("ERROR_SHARING_VIOLATION") &&
    !/(?:\.write\(true\)|FILE_SHARE_WRITE|FILE_SHARE_DELETE)/u.test(
      openTokenObservationFileBlock,
    ),
  "Sepolia token observation must stay non-mutating, contention-distinct, exact-object, regular, and reparse-safe",
);
const initialOverviewVerifyIndex = refreshSelectedOverviewBlock.indexOf(
  "let chain_verified = self.rpc.verify_sepolia().is_ok()",
);
const overviewBalanceIndex = refreshSelectedOverviewBlock.indexOf(
  "let balance = self.rpc.balance(address).ok()",
);
const overviewInspectIndex = refreshSelectedOverviewBlock.indexOf(
  "self.inspect_token_with_permit(",
);
const finalOverviewPermitIndex = refreshSelectedOverviewBlock.indexOf(
  "ensure_session_current(permit)?;\n            let final_chain_verified",
);
const finalOverviewVerifyIndex = refreshSelectedOverviewBlock.indexOf(
  "let final_chain_verified = self.rpc.verify_sepolia().is_ok()",
);
const finalOverviewLoadIndex = refreshSelectedOverviewBlock.lastIndexOf(
  "self.load_token_store(context)?",
);
const overviewCacheInstallIndex = refreshSelectedOverviewBlock.indexOf(
  "self.last_balance = observed_balance.map",
);
requireInvariant(
  refreshSelectedOverviewOuterBlock.includes(
    "let result = self.refresh_selected_overview_inner(permit)",
  ) &&
    refreshSelectedOverviewOuterBlock.includes("if result.is_err()") &&
    refreshSelectedOverviewOuterBlock.includes("self.lock()") &&
    refreshSelectedOverviewBlock.includes("self.last_balance = None") &&
    refreshSelectedOverviewBlock.includes("let local_snapshot = self.snapshot()?") &&
    refreshSelectedOverviewBlock.includes(
      "TokenObservationLease::acquire(&self.token_store_path)",
    ) &&
    refreshSelectedOverviewBlock.includes("position >= AUTO_OVERVIEW_TOKEN_LIMIT") &&
    refreshSelectedOverviewBlock.includes("AUTO_OVERVIEW_DEFERRED_ERROR") &&
    initialOverviewVerifyIndex !== -1 &&
    overviewBalanceIndex > initialOverviewVerifyIndex &&
    overviewInspectIndex > overviewBalanceIndex &&
    finalOverviewPermitIndex > overviewInspectIndex &&
    finalOverviewVerifyIndex > finalOverviewPermitIndex &&
    finalOverviewLoadIndex > finalOverviewVerifyIndex &&
    overviewCacheInstallIndex > finalOverviewLoadIndex &&
    (refreshSelectedOverviewBlock.match(/self\.rpc\.verify_sepolia\(\)/gu) ?? [])
      .length === 2 &&
    refreshSelectedOverviewBlock.includes("observed_balance = None") &&
    refreshSelectedOverviewBlock.includes(
      "final_loaded.baseline.bytes != loaded.baseline.bytes",
    ) &&
    refreshSelectedOverviewBlock.includes(
      "final_loaded.store.entries() != loaded.store.entries()",
    ) &&
    refreshSelectedOverviewBlock.includes(
      "snapshot.pending_broadcast != local_snapshot.pending_broadcast",
    ) &&
    refreshSelectedOverviewBlock.includes(
      "snapshot.activity != local_snapshot.activity",
    ),
  "Sepolia selected-overview hydration must retain permit, chain, token-baseline, local-identity bookends before cache installation",
);
requireInvariant(
  refreshOverviewUiBlock.includes("if self.pending.is_some()") &&
    refreshOverviewUiBlock.includes("mark_snapshot_balance_stale") &&
    refreshOverviewUiBlock.includes(
      "self.send_command(WorkerCommand::Refresh, PendingAction::Refresh)",
    ) &&
    importedOverviewUiBlock.includes("self.refresh()") &&
    openedOverviewUiBlock.includes("self.refresh()") &&
    accountSelectedUiBlock.includes("self.refresh()") &&
    migratedOverviewUiBlock.includes("self.refresh()") &&
    !generatedConfirmedUiBlock.includes("self.refresh()") &&
    (sepoliaDemoUiProduction.match(/self\.refresh\(\);/gu) ?? []).length === 5 &&
    executeWorkerCommandBlock.includes(
      "WorkerCommand::Refresh => WorkerEvent::Refreshed(backend.refresh(permit))",
    ) &&
    refreshedOverviewUiBlock.includes(
      "completed_action == Some(PendingAction::Refresh)",
    ) &&
    refreshedOverviewUiBlock.includes("self.session_phase == SessionPhase::Unlocked") &&
    refreshedOverviewUiBlock.includes(
      "current.wallet_kind == overview.snapshot.wallet_kind",
    ) &&
    refreshedOverviewUiBlock.includes("current.accounts == overview.snapshot.accounts") &&
    refreshedOverviewUiBlock.includes(
      "current.pending_broadcast == overview.snapshot.pending_broadcast",
    ) &&
    refreshedOverviewUiBlock.includes("current.activity == overview.snapshot.activity") &&
    refreshedOverviewUiBlock.includes(
      "selected.index == overview.token_owner_account_index",
    ) &&
    refreshedOverviewUiBlock.includes(
      "selected.address == overview.token_owner_address",
    ) &&
    refreshedOverviewUiBlock.includes("!overview.is_well_formed()") &&
    refreshedOverviewUiBlock.includes("invalidate_frontend_after_backend_error") &&
    !refreshedOverviewUiBlock.includes("self.refresh()") &&
    !refreshedOverviewUiBlock.includes("WorkerCommand::Refresh") &&
    (walletAppImplBlock.match(/\bWorkerCommand::Refresh\b/gu) ?? []).length === 1 &&
    (executeWorkerCommandBlock.match(/\bWorkerCommand::Refresh\b/gu) ?? [])
      .length === 1 &&
    (sepoliaDemoUiRuntime.match(/\bWorkerCommand::Refresh\b/gu) ?? []).length ===
      2 &&
    (walletAppImplBlock.match(
      /self\.send_command\(\s*WorkerCommand::Refresh\s*,\s*PendingAction::Refresh\s*,?\s*\)/gu,
    ) ?? []).length === 1 &&
    (sepoliaDemoUiRuntime.match(/\.\s*refresh\s*\(\s*\)/gu) ?? []).length ===
      5 &&
    !/(?:(?:\bSelf|\bWalletApp)|<(?:Self|WalletApp)>)::refresh\b/u.test(
      sepoliaDemoUiRuntime,
    ) &&
    customTokenPanelBlock.includes("token_rows_warning") &&
    customTokenPanelBlock.includes(
      "목록이 비어 있어도 저장 토큰이 없다는 뜻이 아닙니다",
    ) &&
    customTokenPanelBlock.includes(
      '"현재 안전하게 표시할 수 있는 저장 토큰 행이 없습니다."',
    ),
  "Sepolia selected-overview UI must remain exactly-once, non-looping, exact-response-bound, and honest about unobserved token rows",
);
requireInvariant(
  rootReadme.includes("### 선택 계정 개요 조회 경계") &&
    rootReadme.includes("ERC-20 최대 3개만 확인합니다") &&
    rootReadme.includes("체인 identity 확인 subcall은 한 작업 안에서 최대") &&
    rootReadme.includes("개요 작업 자체를 자동으로 다시 등록하거나 timer/polling") &&
    rootReadme.includes("빈 목록을") &&
    rootReadme.includes("단일 Sepolia RPC에 노출합니다") &&
    sepoliaArchitectureDoc.includes(
      "### Sepolia demo selected-overview hydration boundary",
    ) &&
    sepoliaArchitectureDoc.includes("With `N <= 3`") &&
    sepoliaDemoRpcProduction.includes("const VERIFY_ATTEMPTS: usize = 3") &&
    verifySepoliaBlock.includes("for attempt in 0..VERIFY_ATTEMPTS") &&
    verifySepoliaBlock.includes("attempt + 1 < VERIFY_ATTEMPTS") &&
    verifySepoliaBlock.includes("is_retryable_verification_error(error)") &&
    verifySepoliaBlock.includes("std::thread::sleep(VERIFY_RETRY_DELAY)") &&
    sepoliaArchitectureDoc.includes("exactly `5 + 11N` RPC") &&
    sepoliaArchitectureDoc.includes("`13 + 19N`") &&
    sepoliaArchitectureDoc.includes("at most 70 calls when `N = 3`") &&
    sepoliaArchitectureDoc.includes(
      "identity subcall retains its bounded three-attempt retry",
    ) &&
    sepoliaArchitectureDoc.includes(
      "automatic re-enqueue of the overview request",
    ) &&
    /A\s+chain or balance RPC failure returns a category-only Partial result with\s+ETH/u.test(
      sepoliaArchitectureDoc,
    ) &&
    /An individual token RPC failure marks only that token\s+Unavailable/u.test(
      sepoliaArchitectureDoc,
    ) &&
    /The observation\s+lease never creates/u.test(sepoliaArchitectureDoc) &&
    sepoliaArchitectureDoc.includes(
      "Final Sepolia verification discards every earlier network value",
    ) &&
    sepoliaArchitectureDoc.includes("single fixed TLS RPC"),
  "Sepolia selected-overview docs must retain bounded cost, non-mutating observation, and fixed-RPC privacy/trust disclosure",
);
for (const requiredOverviewTest of [
  "selected_overview_treats_witnessed_missing_store_as_authenticated_empty",
  "selected_overview_accepts_pre_lock_store_without_creating_a_sentinel",
  "selected_overview_queries_exact_first_three_and_defers_every_tail_row",
  "selected_overview_network_failures_are_partial_and_never_restore_a_local_zero",
  "selected_overview_final_chain_failure_discards_every_observed_value",
  "selected_overview_revocation_stops_before_final_or_next_rpc_and_clears_cache",
  "selected_overview_contention_is_non_mutating_partial_but_local_faults_are_fatal",
  "selected_overview_authenticated_activity_drift_is_fatal_and_never_installs_balance",
  "overview_dto_rejects_noncanonical_balances_tokens_status_and_legacy_rows",
  "overview_reducer_installs_only_exact_bound_data_and_locks_on_forgery",
  "overview_partial_preserves_same_owner_rows_warns_persistently_and_stays_unlocked",
  "overview_partial_with_loaded_rows_is_nonfatal_and_uses_exact_unknown_marker",
  "unlock_switch_triggers_are_exactly_once_generated_is_offline_and_manual_uses_overview",
  "stale_epoch_overview_is_dropped_and_backend_err_scrubs_and_locks",
]) {
  requireInvariant(
    sepoliaDemoBackend.includes(requiredOverviewTest) ||
      sepoliaDemoUi.includes(requiredOverviewTest),
    `Sepolia selected-overview regression evidence missing: ${requiredOverviewTest}`,
  );
}
requireInvariant(
  preparePendingAccountBlock.includes("self.attribute_pending_sender") &&
    preparePendingAccountBlock.includes("lease.read_record()") &&
    retryPendingAccountBlock.includes("self.verify_frozen_pending(&mut prepared, permit)") &&
    retryPendingAccountBlock.includes("prepared.raw_transaction.as_slice()") &&
    retryPendingAccountBlock.includes("prepared.lease.delete_exact") &&
    pendingLeaseBlock.includes("file: File") &&
    sepoliaDemoBackendProduction.includes("FILE_SHARE_MODE(0)") &&
    sepoliaDemoBackendProduction.includes("SetFileInformationByHandle") &&
    sepoliaDemoBackendProduction.includes("#[cfg(not(windows))]") &&
    sepoliaDemoBackendProduction.includes("not production evidence") &&
    rootReadme.includes("비-Windows 빌드 경로는") &&
    rootReadme.includes("릴리스 경로로 지원하지 않습니다") &&
    recoverPendingSenderBlock.includes("fields = [empty; 12]") &&
    recoverPendingSenderBlock.includes("rpc::SEPOLIA_CHAIN_ID") &&
    recoverPendingSenderBlock.includes("HALF_CURVE_ORDER") &&
    recoverPendingSenderBlock.includes("recover_ecdsa") &&
    sepoliaDemoUiProduction.includes("같은 서명 거래 다시 제출 — 2초 동안 누르기"),
  "Sepolia pending retry must recover a canonical bounded sender, freeze exact bytes under an exact-object lease, disclose it, and require a separate hold",
);

const preparedTransferBlock = rustItemBlock(
  sepoliaDemoBackendProduction,
  /(?:^|\n)enum PreparedTransfer\s*\{/u,
);
const prepareSavedErc20Block = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "prepare_saved_erc20_transfer_inner",
);
const confirmSavedErc20Block = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "confirm_saved_erc20_transfer",
);
const signSavedErc20Block = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "sign_erc20_type_two",
);
const retryPendingBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "retry_pending_with_permit",
);
requireInvariant(
  preparedTransferBlock.includes("Native(PreparedNativeTransfer)") &&
    preparedTransferBlock.includes("SavedErc20(PreparedErc20Transfer)") &&
    prepareSavedErc20Block.includes("permit: &SessionPermit<'_>") &&
    prepareSavedErc20Block.includes("load_token_store(&context)") &&
    prepareSavedErc20Block.includes("verify_token_store_baseline(") &&
    (prepareSavedErc20Block.match(/inspect_token_with_permit\(/gu) ?? []).length === 2 &&
    prepareSavedErc20Block.indexOf("estimate_erc20_transfer_gas(") <
      prepareSavedErc20Block.indexOf("erc20_transfer_preflight(") &&
    confirmSavedErc20Block.includes("permit: &SessionPermit<'_>") &&
    (confirmSavedErc20Block.match(/verify_token_store_baseline\(/gu) ?? []).length === 2 &&
    (confirmSavedErc20Block.match(/inspect_token_with_permit\(/gu) ?? []).length === 2 &&
    confirmSavedErc20Block.indexOf("estimate_erc20_transfer_gas(") <
      confirmSavedErc20Block.indexOf("erc20_transfer_preflight(") &&
    signSavedErc20Block.includes("erc20::transfer_call_data") &&
    signSavedErc20Block.includes("rlp_bytes(&contract)") &&
    signSavedErc20Block.includes("rlp_word(Word::ZERO)") &&
    signSavedErc20Block.includes("rlp_list(&[])") &&
    !/\bcalldata\s*:/u.test(signSavedErc20Block),
  "saved ERC-20 must stay distinct, authenticated, bookended, estimate-before-exact-preflight, and internally calldata-bound",
);
requireInvariant(
  retryPendingBlock.includes("self.verify_frozen_pending(&mut prepared, permit)") &&
    retryPendingBlock.includes("prepared.raw_transaction.as_slice()") &&
    retryPendingBlock.includes("prepared.lease.delete_exact") &&
    retryPendingBlock.includes("guarded_broadcast(") &&
    !/(?:pending_nonce|fee_quote|latest_base_fee|estimate_erc20|sign_erc20|account_private_key)/u.test(
      retryPendingBlock,
    ) &&
    sepoliaDemoUiProduction.includes("let CustomTokenState::Verified") &&
    sepoliaDemoUiProduction.includes("clear_transfer_amount_after_asset_change(") &&
    sepoliaDemoUiProduction.includes("zeroize_custom_token_snapshots(&mut self.custom_tokens)") &&
    sepoliaDemoUiProduction.includes("확인하고 전송 — 2초 동안 누르기"),
  "saved ERC-20 UI/retry path lost verified-only selection, shared hold, stale scrub, or exact-byte no-resign recovery",
);

// Sepolia durable transaction-activity invariants (demo-only). The activity
// sidecar is v2-derived, bounded, and committed before an exact pending object
// may be deleted. Refresh remains explicit and per-row.
const activityLeaseBlock = rustItemBlock(
  sepoliaDemoBackendProduction,
  /(?:^|\n)struct ActivityMutationLease<'a>\s*\{/u,
);
const activityLeaseImplBlock = rustItemBlock(
  sepoliaDemoBackendProduction,
  /(?:^|\n)impl<'a> ActivityMutationLease<'a>\s*\{/u,
);
const tokenLeaseImplBlock = rustItemBlock(
  sepoliaDemoBackendProduction,
  /(?:^|\n)impl<'a> TokenMutationLease<'a>\s*\{/u,
);
const newV2SidecarLeaseBlock = rustItemBlock(
  sepoliaDemoBackendProduction,
  /(?:^|\n)struct NewV2SidecarNamespaceLease<'a>\s*\{/u,
);
const newV2SidecarLeaseImplBlock = rustItemBlock(
  sepoliaDemoBackendProduction,
  /(?:^|\n)impl<'a> NewV2SidecarNamespaceLease<'a>\s*\{/u,
);
const durableNamespaceParentBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "open_or_create_durable_namespace_parent",
);
const activityContextBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "activity_context",
);
const loadActivityStoreBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "load_activity_store",
);
const persistActivityStoreBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "persist_activity_store",
);
const commitSubmittedActivityBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "commit_submitted_activity",
);
const readActivityStoreBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "read_activity_store_file",
);
const writeActivityStoreBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "write_atomic_activity_store",
);
const migrateLegacyActivityBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "migrate_legacy",
);
const refreshActivityBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "refresh_activity_inner",
);
const observeActivityBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "observe_activity",
);
const observedPendingBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "pending_transaction_is_observed",
);
const canonicalObservedTransactionBlock = rustFunctionBlock(
  sepoliaDemoBackendProduction,
  "canonical_observed_type_two_bytes",
);
const liveRpcImplBlock = rustItemBlock(
  sepoliaDemoBackendProduction,
  /(?:^|\n)impl RpcAccess for LiveRpc\s*\{/u,
);
const legacyMigrationLeaseImplBlock = rustItemBlock(
  sepoliaDemoBackendProduction,
  /(?:^|\n)impl LegacyVaultMigrationLease\s*\{/u,
);
const createdV2MigrationLeaseImplBlock = rustItemBlock(
  sepoliaDemoBackendProduction,
  /(?:^|\n)impl CreatedV2VaultMigrationLease\s*\{/u,
);
const createdV2MigrationLeaseDropBlock = rustItemBlock(
  sepoliaDemoBackendProduction,
  /(?:^|\n)impl Drop for CreatedV2VaultMigrationLease\s*\{/u,
);
const accountSelectedEventBlock = rustItemBlock(
  sepoliaDemoUiProduction,
  /WorkerEvent::AccountSelected\(result\)\s*=>\s*match result\s*\{/u,
);
const refreshedEventBlock = rustItemBlock(
  sepoliaDemoUiProduction,
  /WorkerEvent::Refreshed\(result\)\s*=>\s*match result\s*\{/u,
);
const activityPanelBlock = rustFunctionBlock(
  sepoliaDemoUiProduction,
  "activity_panel",
);
const renderActivityTransactionHashBlock = rustFunctionBlock(
  sepoliaDemoUiProduction,
  "render_activity_transaction_hash",
);
const pendingActionBlock = rustItemBlock(
  sepoliaDemoUiProduction,
  /(?:^|\n)enum PendingAction\s*\{/u,
);
const workerCommandBlock = rustItemBlock(
  sepoliaDemoUiProduction,
  /(?:^|\n)enum WorkerCommand\s*\{/u,
);
const walletBackendTraitBlock = rustItemBlock(
  sepoliaDemoUiProduction,
  /(?:^|\n)pub trait WalletBackend\s*:\s*Send\s*\+\s*'static\s*\{/u,
);
const activityRefreshOriginBlock = rustItemBlock(
  sepoliaDemoUiProduction,
  /(?:^|\n)enum ActivityRefreshOrigin\s*\{/u,
);
const activityRefreshTargetBlock = rustItemBlock(
  sepoliaDemoUiProduction,
  /(?:^|\n)struct ActivityRefreshTarget\s*\{/u,
);
const activityRefreshTargetDropBlock = rustItemBlock(
  sepoliaDemoUiProduction,
  /(?:^|\n)impl Drop for ActivityRefreshTarget\s*\{/u,
);
const activityRefreshBatchBlock = rustItemBlock(
  sepoliaDemoUiProduction,
  /(?:^|\n)struct ActivityRefreshBatch\s*\{/u,
);
const activityRefreshBatchImplBlock = rustItemBlock(
  sepoliaDemoUiProduction,
  /(?:^|\n)impl ActivityRefreshBatch\s*\{/u,
);
const activityRefreshBatchDropBlock = rustItemBlock(
  sepoliaDemoUiProduction,
  /(?:^|\n)impl Drop for ActivityRefreshBatch\s*\{/u,
);
const clearActivityRefreshStateBlock = rustFunctionBlock(
  walletAppImplBlock,
  "clear_activity_refresh_state",
);
const activityBatchWaitMatchesBlock = rustFunctionBlock(
  walletAppImplBlock,
  "activity_refresh_batch_wait_matches_current",
);
const startActivityBatchBlock = rustFunctionBlock(
  walletAppImplBlock,
  "start_activity_refresh_batch_at",
);
const driveActivityBatchBlock = rustFunctionBlock(
  walletAppImplBlock,
  "drive_activity_refresh_batch",
);
const stopActivityBatchErrorBlock = rustFunctionBlock(
  walletAppImplBlock,
  "stop_activity_refresh_batch_with_error",
);
const stopActivityBatchUserBlock = rustFunctionBlock(
  walletAppImplBlock,
  "stop_activity_refresh_batch_by_user",
);
const selectAccountActivityBatchBlock = rustFunctionBlock(
  walletAppImplBlock,
  "select_account",
);
const applyWorkerEventAtBlock = rustFunctionBlock(
  walletAppImplBlock,
  "apply_worker_event_at",
);
const activityRefreshedUiStart = applyWorkerEventAtBlock.lastIndexOf(
  "WorkerEvent::ActivityRefreshed {",
);
const activityRefreshedUiEnd = applyWorkerEventAtBlock.indexOf(
  "WorkerEvent::CustomTokenAdded",
  activityRefreshedUiStart,
);
const activityRefreshedUiBlock =
  activityRefreshedUiStart >= 0 && activityRefreshedUiEnd > activityRefreshedUiStart
    ? applyWorkerEventAtBlock.slice(activityRefreshedUiStart, activityRefreshedUiEnd)
    : "";
const walletEframeAppBlock = rustItemBlock(
  sepoliaDemoUiProduction,
  /(?:^|\n)impl eframe::App for WalletApp\s*\{/u,
);
const headlessSmokeBlock = rustFunctionBlock(
  sepoliaDemoUiProduction,
  "run_headless_smoke",
);
const activityBatchCandidateBlock = rustFunctionBlock(
  sepoliaDemoUiProduction,
  "activity_is_batch_candidate",
);
const activityHashCopyClickTestBlock = rustFunctionBlock(
  sepoliaDemoUi,
  "activity_hash_copy_is_click_gated_and_emits_only_the_exact_hash",
);
const activityHashCopyPanelTestBlock = rustFunctionBlock(
  sepoliaDemoUi,
  "activity_hash_copy_panel_filters_foreign_rows_and_never_dispatches_without_click",
);
requireInvariant(
  sepoliaDemoActivityStore.includes("pub(crate) const ACTIVITY_CAPACITY: usize = 64") &&
    sepoliaDemoActivityStore.includes("pub(crate) const ACTIVITY_FILE_BYTES") &&
    sepoliaDemoActivityStore.includes("pub(crate) enum ActivityStatus") &&
    sepoliaDemoActivityStore.includes("DroppedCandidate") &&
    sepoliaDemoActivityStore.includes("ReplacementSuspected") &&
    sepoliaDemoActivityStore.includes("pub(crate) fn ensure_nonce_available(") &&
    sepoliaDemoActivityStore.includes("pub(crate) fn can_upsert(") &&
    sepoliaDemoActivityStore.includes("pub(crate) fn upsert_submitted(") &&
    sepoliaDemoActivityStore.includes("pub(crate) fn transition(") &&
    sepoliaDemoActivityStore.includes("ActivityStoreError::NonceConflict"),
  "Sepolia activity codec lost its fixed capacity, closed states, transition API, or nonce-slot conflict invariant",
);
requireInvariant(
  activityContextBlock.includes("UnlockedWallet::V2(opened)") &&
    activityContextBlock.includes("ActivityRequiresV2") &&
    activityContextBlock.includes("opened.derive_activity_store_key()") &&
    !/(?:private_key|mnemonic|LegacyV1)/u.test(activityContextBlock) &&
    loadActivityStoreBlock.includes("ActivityStore::open(") &&
    loadActivityStoreBlock.includes("wallet.account_address(entry.identity().account_index())?") &&
    loadActivityStoreBlock.includes("*entry.identity().sender()") &&
    loadActivityStoreBlock.includes("ActivityIdentityMismatch"),
  "Sepolia activity context must remain v2-key-derived and every authenticated row must bind sender to account 0/1",
);
requireInvariant(
  activityLeaseBlock.includes("_process_guard: MutexGuard") &&
    activityLeaseBlock.includes("activity_store_path: PathBuf") &&
    activityLeaseBlock.includes("_lock_file: File") &&
    activityLeaseBlock.includes("_parent_directory: DurableParentDirectory") &&
    activityLeaseImplBlock.includes("ACTIVITY_STORE_PROCESS_LOCK") &&
    activityLeaseImplBlock.includes("ActivityMutationBlocked") &&
    activityLeaseImplBlock.includes(".share_mode(0)") &&
    activityLeaseImplBlock.includes("FILE_FLAG_OPEN_REPARSE_POINT") &&
    activityLeaseImplBlock.includes("!metadata.file_type().is_file()") &&
    activityLeaseImplBlock.includes("FILE_ATTRIBUTE_REPARSE_POINT") &&
    activityLeaseImplBlock.includes("activity_store_temporary_path(activity_store_path)") &&
    activityLeaseImplBlock.includes("reconcile_orphan_activity_temporary") &&
    activityLeaseImplBlock.includes("parent_directory") &&
    activityLeaseImplBlock.includes(".flush()"),
  "Sepolia activity mutations must retain the process lock, persistent Windows no-share sibling, and exact parent directory",
);
requireInvariant(
  tokenLeaseImplBlock.includes("TOKEN_STORE_PROCESS_LOCK") &&
    tokenLeaseImplBlock.includes(".share_mode(0)") &&
    tokenLeaseImplBlock.includes("FILE_FLAG_OPEN_REPARSE_POINT") &&
    tokenLeaseImplBlock.includes("token_store_temporary_path(token_store_path)") &&
    tokenLeaseImplBlock.includes("reconcile_orphan_token_temporary") &&
    newV2SidecarLeaseBlock.indexOf("_token_lease: TokenMutationLease") <
      newV2SidecarLeaseBlock.indexOf("_activity_lease: ActivityMutationLease") &&
    newV2SidecarLeaseImplBlock.indexOf("TokenMutationLease::acquire") <
      newV2SidecarLeaseImplBlock.indexOf("ActivityMutationLease::acquire") &&
    newV2SidecarLeaseImplBlock.includes("lease.verify_absent()?") &&
    newV2SidecarLeaseImplBlock.includes("read_token_store_file") &&
    newV2SidecarLeaseImplBlock.includes("read_activity_store_file") &&
    durableNamespaceParentBlock.includes("for component in [application_root, parent]") &&
    durableNamespaceParentBlock.includes("DurableParentDirectory::open(trusted_base)") &&
    durableNamespaceParentBlock.includes("DurableParentDirectory::open(component)") &&
    durableNamespaceParentBlock.includes("created.flush()?") &&
    durableNamespaceParentBlock.includes("current_directory.flush()?"),
  "Sepolia new-v2 namespace must reconcile both fixed temps, acquire token before activity, and durably pin every fixed parent level",
);
requireInvariant(
  readActivityStoreBlock.includes("fs::symlink_metadata(path)") &&
    readActivityStoreBlock.includes("ACTIVITY_FILE_BYTES") &&
    readActivityStoreBlock.includes("!metadata.file_type().is_file()") &&
    readActivityStoreBlock.includes("FILE_ATTRIBUTE_REPARSE_POINT") &&
    writeActivityStoreBlock.includes("fs::symlink_metadata(path)") &&
    writeActivityStoreBlock.includes(
      "activity_lease: &ActivityMutationLease<'_>",
    ) &&
    writeActivityStoreBlock.includes("activity_lease.activity_store_path != path") &&
    writeActivityStoreBlock.includes(".create_new(true)") &&
    writeActivityStoreBlock.includes("file.sync_all()") &&
    writeActivityStoreBlock.includes("verify_exact_activity_store_readback(&temporary, bytes)") &&
    writeActivityStoreBlock.includes("atomic_replace_activity_store(&temporary, path)") &&
    writeActivityStoreBlock.includes("parent_directory") &&
    writeActivityStoreBlock.includes(".flush()") &&
    persistActivityStoreBlock.includes("current.as_deref() != baseline.bytes.as_deref()") &&
    persistActivityStoreBlock.includes(
      "activity_lease: &ActivityMutationLease<'_>",
    ) &&
    /write_atomic_activity_store\(\s*activity_lease,\s*&self\.activity_store_path/u.test(
      persistActivityStoreBlock,
    ) &&
    commitSubmittedActivityBlock.includes(
      "activity_lease: &ActivityMutationLease<'_>",
    ) &&
    commitSubmittedActivityBlock.includes("self.persist_activity_store(") &&
    commitSubmittedActivityBlock.includes("activity_lease,") &&
    persistActivityStoreBlock.includes("reopened.generation() != baseline.generation") &&
    persistActivityStoreBlock.indexOf("store.seal(&context.key)") <
      persistActivityStoreBlock.indexOf("write_atomic_activity_store(") &&
    persistActivityStoreBlock.indexOf("write_atomic_activity_store(") <
      persistActivityStoreBlock.indexOf("verify_exact_activity_store_readback(") &&
    persistActivityStoreBlock.indexOf("verify_exact_activity_store_readback(") <
      persistActivityStoreBlock.lastIndexOf("ActivityStore::open(") &&
    persistActivityStoreBlock.includes("entry.identity() != expected_identity"),
  "Sepolia activity persistence lost nonregular/reparse rejection, same-dir exclusive replace, CAS, flush, or authenticated exact readback",
);
const nativeActivityLeaseIndex = confirmAccountBlock.indexOf(
  "ActivityMutationLease::acquire",
);
const nativeActivityLoadIndex = confirmAccountBlock.indexOf("load_activity_store(");
const nativeCapacityIndex = confirmAccountBlock.indexOf(
  "entries().len() >= ACTIVITY_CAPACITY",
);
const nativeNonceIndex = confirmAccountBlock.indexOf("ensure_nonce_available(");
const nativeSignIndex = confirmAccountBlock.indexOf("self.sign_attempts += 1");
const nativePendingIndex = confirmAccountBlock.indexOf("write_new_pending(");
const nativeSendIndex = confirmAccountBlock.indexOf("guarded_broadcast(");
const nativeCommitIndex = confirmAccountBlock.indexOf("commit_submitted_activity(");
const nativeDeleteIndex = confirmAccountBlock.indexOf("pending_lease.delete_exact(");
const erc20ActivityLeaseIndex = confirmSavedErc20Block.indexOf(
  "ActivityMutationLease::acquire",
);
const erc20ActivityLoadIndex = confirmSavedErc20Block.indexOf("load_activity_store(");
const erc20CapacityIndex = confirmSavedErc20Block.indexOf(
  "entries().len() >= ACTIVITY_CAPACITY",
);
const erc20NonceIndex = confirmSavedErc20Block.indexOf("ensure_nonce_available(");
const erc20SignIndex = confirmSavedErc20Block.indexOf("self.sign_attempts += 1");
const erc20PendingIndex = confirmSavedErc20Block.indexOf("write_new_pending(");
const erc20SendIndex = confirmSavedErc20Block.indexOf("guarded_broadcast(");
const erc20CommitIndex = confirmSavedErc20Block.indexOf("commit_submitted_activity(");
const erc20DeleteIndex = confirmSavedErc20Block.indexOf("pending_lease.delete_exact(");
requireInvariant(
  [
    nativeActivityLeaseIndex,
    nativeActivityLoadIndex,
    nativeCapacityIndex,
    nativeNonceIndex,
    nativeSignIndex,
    nativePendingIndex,
    nativeSendIndex,
    nativeCommitIndex,
    nativeDeleteIndex,
  ].every((index) => index >= 0) &&
    nativeActivityLeaseIndex < nativeActivityLoadIndex &&
    nativeActivityLoadIndex < nativeCapacityIndex &&
    nativeCapacityIndex < nativeNonceIndex &&
    nativeNonceIndex < nativeSignIndex &&
    nativeSignIndex < nativePendingIndex &&
    nativePendingIndex < nativeSendIndex &&
    nativeSendIndex < nativeCommitIndex &&
    nativeCommitIndex < nativeDeleteIndex &&
    [
      erc20ActivityLeaseIndex,
      erc20ActivityLoadIndex,
      erc20CapacityIndex,
      erc20NonceIndex,
      erc20SignIndex,
      erc20PendingIndex,
      erc20SendIndex,
      erc20CommitIndex,
      erc20DeleteIndex,
    ].every((index) => index >= 0) &&
    erc20ActivityLeaseIndex < erc20ActivityLoadIndex &&
    erc20ActivityLoadIndex < erc20CapacityIndex &&
    erc20CapacityIndex < erc20NonceIndex &&
    erc20NonceIndex < erc20SignIndex &&
    erc20SignIndex < erc20PendingIndex &&
    erc20PendingIndex < erc20SendIndex &&
    erc20SendIndex < erc20CommitIndex &&
    erc20CommitIndex < erc20DeleteIndex,
  "Sepolia native/ERC-20 send must reserve capacity and nonce before signing, then durably commit activity before exact pending deletion",
);
requireInvariant(
  retryPendingBlock.indexOf("ActivityMutationLease::acquire") <
      retryPendingBlock.indexOf("load_activity_store(") &&
    retryPendingBlock.indexOf("load_activity_store(") <
      retryPendingBlock.indexOf("can_upsert(&identity)") &&
    retryPendingBlock.indexOf("can_upsert(&identity)") <
      retryPendingBlock.indexOf("pending_transaction_is_observed(") &&
    retryPendingBlock.indexOf("pending_transaction_is_observed(") <
      retryPendingBlock.indexOf("guarded_broadcast(") &&
    /find\(identity\.transaction_hash\(\)\)[\s\S]*?delete_exact[\s\S]*?broadcast_performed:\s*false/u.test(
      retryPendingBlock,
    ) &&
    /pending_transaction_is_observed[\s\S]*?commit_submitted_activity[\s\S]*?delete_exact[\s\S]*?broadcast_performed:\s*false/u.test(
      retryPendingBlock,
    ) &&
    /guarded_broadcast[\s\S]*?commit_submitted_activity[\s\S]*?verify_frozen_pending[\s\S]*?delete_exact/u.test(
      retryPendingBlock,
    ) &&
    observedPendingBlock.indexOf("activity_head()") <
      observedPendingBlock.indexOf("activity_transaction(") &&
    observedPendingBlock.indexOf("activity_transaction(") <
      observedPendingBlock.lastIndexOf("activity_head()") &&
    observedPendingBlock.includes("activity_transaction_matches_identity") &&
    observedPendingBlock.includes("None => Ok(false)"),
  "Sepolia retry must reserve the exact identity, observe before its sole resend, and commit activity before cleanup",
);
requireInvariant(
  sepoliaDemoRpcProduction.includes("pub y_parity: u8") &&
    sepoliaDemoRpcProduction.includes("pub r: Quantity256") &&
    sepoliaDemoRpcProduction.includes("pub s: Quantity256") &&
    (sepoliaDemoBackendProduction.match(/\.transaction_by_hash\(/gu) ?? []).length === 1 &&
    liveRpcImplBlock.includes(".transaction_by_hash(") &&
    liveRpcImplBlock.includes("y_parity: transaction.y_parity") &&
    liveRpcImplBlock.includes("r: Word::from_be_bytes") &&
    liveRpcImplBlock.includes("s: Word::from_be_bytes") &&
    liveRpcImplBlock.includes("canonical_observed_type_two_bytes(&transaction)") &&
    canonicalObservedTransactionBlock.includes("transaction.y_parity > 1") &&
    canonicalObservedTransactionBlock.includes("transaction.r.is_zero()") &&
    canonicalObservedTransactionBlock.includes("transaction.s.is_zero()") &&
    canonicalObservedTransactionBlock.includes("rpc::SEPOLIA_CHAIN_ID") &&
    canonicalObservedTransactionBlock.includes("rlp_list(&[])") &&
    canonicalObservedTransactionBlock.includes("MAX_PENDING_RAW_BYTES") &&
    canonicalObservedTransactionBlock.includes("keccak32(raw.as_slice()) != transaction.hash") &&
    canonicalObservedTransactionBlock.includes("recover_signed_type_two_sender(raw.as_slice())") &&
    observedPendingBlock.includes("expected_raw: &[u8]") &&
    observedPendingBlock.includes("canonical_observed_type_two_bytes(&transaction)?") &&
    observedPendingBlock.includes("canonical.as_slice() != expected_raw"),
  "Sepolia raw transaction observations must have one reviewed RPC consumer and locally prove canonical hash, low-S sender recovery, and pending byte identity",
);
requireInvariant(
  migrateLegacyActivityBlock.includes("NewV2SidecarNamespaceLease::acquire(") &&
    migrateLegacyActivityBlock.includes("PendingFileLease::open(&self.pending_path)") &&
    migrateLegacyActivityBlock.includes("recover_signed_type_two_sender(") &&
    migrateLegacyActivityBlock.includes("recovered != legacy_address") &&
    migrateLegacyActivityBlock.includes("DecodedPendingTransfer::Native") &&
    (migrateLegacyActivityBlock.match(/verify_pending_lease\(/gu) ?? []).length >= 3 &&
    migrateLegacyActivityBlock.includes("else if self.pending_broadcast_exists()") &&
    migrateLegacyActivityBlock.includes("LegacyVaultMigrationLease::open(&self.vault_path)") &&
    migrateLegacyActivityBlock.includes("CreatedV2VaultMigrationLease::create(") &&
    migrateLegacyActivityBlock.indexOf("CreatedV2VaultMigrationLease::create(") <
      migrateLegacyActivityBlock.indexOf("sidecar_namespace_lease.verify_absent()?") &&
    migrateLegacyActivityBlock.indexOf("sidecar_namespace_lease.verify_absent()?") <
      migrateLegacyActivityBlock.indexOf("persisted_v2_lease.install_exact(") &&
    migrateLegacyActivityBlock.indexOf("persisted_v2_lease.install_exact(") <
      migrateLegacyActivityBlock.lastIndexOf("verify_pending_lease(") &&
    migrateLegacyActivityBlock.lastIndexOf("verify_pending_lease(") <
      migrateLegacyActivityBlock.indexOf("persisted_v2_lease.mark_committed()?") &&
    migrateLegacyActivityBlock.indexOf("persisted_v2_lease.mark_committed()?") <
      migrateLegacyActivityBlock.indexOf("legacy_lease.delete_exact(&self.vault_path)") &&
    migrateLegacyActivityBlock.indexOf("legacy_lease.delete_exact(&self.vault_path)") <
      migrateLegacyActivityBlock.indexOf("self.unlocked = Some(UnlockedWallet::V2(opened))") &&
    migrateLegacyActivityBlock.indexOf("self.snapshot_or_lock()") <
      migrateLegacyActivityBlock.indexOf("drop(persisted_v2_lease)") &&
    migrateLegacyActivityBlock.indexOf("drop(persisted_v2_lease)") <
      migrateLegacyActivityBlock.indexOf("drop(legacy_lease)") &&
    legacyMigrationLeaseImplBlock.includes("FILE_SHARE_MODE(0)") &&
    legacyMigrationLeaseImplBlock.includes("FILE_FLAG_OPEN_REPARSE_POINT") &&
    legacyMigrationLeaseImplBlock.includes("SetFileInformationByHandle(") &&
    legacyMigrationLeaseImplBlock.includes("FileDispositionInfo") &&
    createdV2MigrationLeaseImplBlock.includes("vault_v2_migration_temporary_path(path)") &&
    createdV2MigrationLeaseImplBlock.includes("reconcile_orphan_v2_migration_temporary") &&
    createdV2MigrationLeaseImplBlock.includes(".create_new(true)") &&
    createdV2MigrationLeaseImplBlock.includes(".share_mode(0)") &&
    createdV2MigrationLeaseImplBlock.includes("FileRenameInfo") &&
    createdV2MigrationLeaseImplBlock.includes("ReplaceIfExists = false") &&
    createdV2MigrationLeaseImplBlock.includes("self.parent_directory.flush()?") &&
    createdV2MigrationLeaseImplBlock.includes("self.committed = true") &&
    createdV2MigrationLeaseDropBlock.includes("let _ = self.abort()") &&
    migrateLegacyActivityBlock.includes(
      "self.prepared_pending_retry = prepared_pending_retry",
    ) &&
    !/(?:guarded_broadcast|send_raw_transaction|write_new_file|remove_legacy_vault)/u.test(
      migrateLegacyActivityBlock,
    ),
  "Sepolia legacy migration must pin exact v1/pending/v2 objects, install the authenticated migrating handle before commit, and delete only the held v1 handle",
);
requireInvariant(
  refreshActivityBlock.includes("ActivityMutationLease::acquire") &&
    refreshActivityBlock.includes("entry.identity().account_index() != self.selected_account_index") &&
    refreshActivityBlock.includes("account_address(self.selected_account_index)?") &&
    refreshActivityBlock.includes("self.observe_activity(entry, permit)?") &&
    refreshActivityBlock.includes(".transition(&hash, next_status, next_observations)") &&
    observeActivityBlock.indexOf("activity_head()") <
      observeActivityBlock.indexOf("activity_transaction(") &&
    observeActivityBlock.indexOf("activity_transaction(") <
      observeActivityBlock.indexOf("activity_receipt(") &&
    observeActivityBlock.indexOf("activity_receipt(") <
      observeActivityBlock.indexOf("latest_nonce(") &&
    observeActivityBlock.indexOf("latest_nonce(") <
      observeActivityBlock.lastIndexOf("activity_head()") &&
    observeActivityBlock.includes("head_before != head_after") &&
    observeActivityBlock.includes("activity_transaction_matches_identity") &&
    observeActivityBlock.includes("activity_receipt_matches_identity") &&
    observeActivityBlock.includes("transaction.transaction_index != Some(receipt.transaction_index)") &&
    observeActivityBlock.includes("former_reorg_proven") &&
    observeActivityBlock.includes("record_present(head_before.number)") &&
    observeActivityBlock.includes("record_missing(head_before.number)") &&
    observeActivityBlock.includes("observations.dropped_candidate_ready()") &&
    observeActivityBlock.includes("ActivityStatus::ReplacementSuspected") &&
    observeActivityBlock.includes("entry.status()"),
  "Sepolia activity refresh must stay manual-row scoped, stable-head bookended, immutable/tx-index exact, and fail closed on ambiguous reorg evidence",
);
const activityHashCopyPanelIndexes = [
  activityPanelBlock.indexOf("let selected_account_index = snapshot.selected_account_index"),
  activityPanelBlock.indexOf("let activity = snapshot.activity.clone()"),
  activityPanelBlock.indexOf(
    ".filter(|row| row.sender_account_index == selected_account_index)",
  ),
  activityPanelBlock.indexOf("render_activity_transaction_hash(ui, &row)"),
];
const activityHashCopyChecks = [
  [
    "exact helper",
    renderActivityTransactionHashBlock.replace(/\s+/gu, " ").trim() ===
      'fn render_activity_transaction_hash( ui: &mut egui::Ui, activity: &TransactionActivitySnapshot, ) -> egui::Response { ui.horizontal_wrapped(|ui| { ui.monospace(&activity.transaction_hash); let response = ui.button("거래 hash 복사"); if response.clicked() { ui.ctx().copy_text(activity.transaction_hash.clone()); } response }) .inner }',
  ],
  [
    "helper scope",
    !/(?:WorkerCommand|WorkerEvent|PendingAction|send_command|OpenUrl|open_url|hyperlink|Command::new|CreateProcess|ureq|https?:)/iu.test(
      renderActivityTransactionHashBlock,
    ) &&
      (sepoliaDemoUiRuntime.match(/\brender_activity_transaction_hash\b/gu) ?? [])
        .length === 2,
  ],
  [
    "selected row call",
    activityHashCopyPanelIndexes.every((index) => index >= 0) &&
      activityHashCopyPanelIndexes.every(
        (index, position) => position === 0 || activityHashCopyPanelIndexes[position - 1] < index,
      ) &&
      /if render_activity_transaction_hash\(ui,\s*&row\)\.clicked\(\)\s*\{\s*self\.notice\s*=\s*Some\(ACTIVITY_HASH_COPIED_NOTICE\.to_owned\(\)\);\s*\}/u.test(
        activityPanelBlock,
      ),
  ],
  [
    "notice and no URL",
    sepoliaDemoUiProduction.includes(
      'const ACTIVITY_HASH_COPIED_NOTICE: &str =\n    "거래 hash를 클립보드에 복사했습니다. 운영체제 클립보드는 잠금 뒤에도 남을 수 있습니다."',
    ) &&
      !/(?:OpenUrl|open_url|hyperlink(?:_to)?|etherscan|explorer)/iu.test(
        sepoliaDemoUiRuntime,
      ),
  ],
  [
    "no retained copy state",
    !/(?:explorer|copied_activity_hash|activity_hash_(?:copy|url))\s*:/iu.test(
      walletAppBlock,
    ) &&
      !/(?:copy|copied|clipboard|explorer|url)\w*(?:hash|activity|transaction)\w*\s*:/iu.test(
        walletAppBlock,
      ) &&
      !/(?:hash|activity|transaction)\w*(?:copy|copied|clipboard|explorer|url)\w*\s*:/iu.test(
        walletAppBlock,
      ) &&
      (walletAppBlock.match(/^[ \t]{4}[A-Za-z_]\w*\s*:/gmu) ?? []).length === 43,
  ],
  [
    "click evidence",
    activityHashCopyClickTestBlock.includes("assert!(!clicked)") &&
      activityHashCopyClickTestBlock.includes("assert!(commands.is_empty())") &&
      activityHashCopyClickTestBlock.includes("egui::OutputCommand::CopyText(") &&
      activityHashCopyClickTestBlock.includes("activity.transaction_hash.clone()") &&
      activityHashCopyClickTestBlock.includes(
        "assert!(!ACTIVITY_HASH_COPIED_NOTICE.contains(\"0x\"))",
      ),
  ],
  [
    "panel evidence",
    activityHashCopyPanelTestBlock.includes(
      "!rendered.contains(foreign.transaction_hash.as_str())",
    ) &&
      activityHashCopyPanelTestBlock.includes("app.snapshot == snapshot_before") &&
      activityHashCopyPanelTestBlock.includes("app.pending.is_none()") &&
      activityHashCopyPanelTestBlock.includes("app.activity_refresh_target.is_none()") &&
      activityHashCopyPanelTestBlock.includes("app.activity_refresh_batch.is_none()") &&
      activityHashCopyPanelTestBlock.includes(
        'const PRIOR_TRANSACTION_HASH_SENTINEL: &str = "public-prior-transaction-hash"',
      ) &&
      activityHashCopyPanelTestBlock.includes(
        "app.last_transaction_hash = Some(PRIOR_TRANSACTION_HASH_SENTINEL.to_owned())",
      ) &&
      activityHashCopyPanelTestBlock.includes(
        "app.last_transaction_hash.as_deref(),\n            Some(PRIOR_TRANSACTION_HASH_SENTINEL)",
      ) &&
      activityHashCopyPanelTestBlock.includes("app.last_activity_at == inactivity_before") &&
      activityHashCopyPanelTestBlock.includes("command_receiver.try_recv().is_err()"),
  ],
  [
    "README",
    rootReadme.includes("각 활동 행에 있는 `거래 hash 복사`") &&
      rootReadme.includes("클립보드 내용은 지갑을"),
  ],
  [
    "architecture",
    sepoliaArchitectureDoc.includes("already validated full transaction hash") &&
      /The\s+OS clipboard\s+may outlive the wallet lock/u.test(sepoliaArchitectureDoc) &&
      /Merely rendering the panel, pressing without completing a click, and foreign-\s*account rows do not copy anything/u.test(
        sepoliaArchitectureDoc,
      ) &&
      /Lock\/session transitions never trigger this\s+copy/u.test(
        sepoliaArchitectureDoc,
      ) &&
      /copy affordance itself enqueues no worker work/u.test(sepoliaArchitectureDoc) &&
      /copy affordance deliberately\s+neither constructs nor\s+opens\s+an\s+explorer URL/u.test(
        sepoliaArchitectureDoc,
      ),
  ],
];
const failedActivityHashCopyChecks = activityHashCopyChecks
  .filter(([, passed]) => !passed)
  .map(([name]) => name)
  .join(", ");
requireInvariant(
  failedActivityHashCopyChecks.length === 0,
  `Sepolia activity hash copy must remain exact-row, click-only, category-only, URL-free, and side-effect-free before consent (${failedActivityHashCopyChecks})`,
);
requireInvariant(
  sepoliaDemoUiProduction.includes(
    "const ACTIVITY_BATCH_DELAY: Duration = Duration::from_secs(2)",
  ) &&
    sepoliaDemoUiProduction.includes("const MAX_ACTIVITY_BATCH_ROWS: usize = 64") &&
    pendingActionBlock.includes("RefreshActivityBatchWait") &&
    activityRefreshOriginBlock.includes("ManualRow") &&
    activityRefreshOriginBlock.includes("origin_epoch: u64") &&
    activityRefreshOriginBlock.includes("selected_account_index: u8") &&
    activityRefreshOriginBlock.includes("submission_sequence: u64") &&
    /^\s*enum ActivityRefreshOrigin\s*\{\s*ManualRow,\s*Batch\s*\{\s*origin_epoch:\s*u64,\s*selected_account_index:\s*u8,\s*submission_sequence:\s*u64,?\s*\},?\s*\}$/u.test(
      activityRefreshOriginBlock,
    ) &&
    activityRefreshTargetBlock.includes("transaction_hash: Zeroizing<String>") &&
    activityRefreshTargetBlock.includes("origin: ActivityRefreshOrigin") &&
    /^\s*struct ActivityRefreshTarget\s*\{\s*transaction_hash:\s*Zeroizing<String>,\s*origin:\s*ActivityRefreshOrigin,?\s*\}$/u.test(
      activityRefreshTargetBlock,
    ) &&
    !/#\[derive\([^\]]*(?:Clone|Copy|Debug|Serialize)[^\]]*\)\]\s*struct ActivityRefreshTarget/u.test(
      sepoliaDemoUiProduction,
    ) &&
    activityRefreshTargetDropBlock.includes("self.transaction_hash.zeroize()") &&
    activityRefreshTargetDropBlock.includes("*origin_epoch = 0") &&
    activityRefreshTargetDropBlock.includes("*selected_account_index = 0") &&
    activityRefreshTargetDropBlock.includes("*submission_sequence = 0") &&
    activityRefreshBatchBlock.includes("origin_epoch: u64") &&
    activityRefreshBatchBlock.includes("selected_account_index: u8") &&
    activityRefreshBatchBlock.includes("remaining_sequences: VecDeque<u64>") &&
    activityRefreshBatchBlock.includes("in_flight_sequence: Option<u64>") &&
    activityRefreshBatchBlock.includes("completed: usize") &&
    activityRefreshBatchBlock.includes("total: usize") &&
    activityRefreshBatchBlock.includes("next_dispatch_at: Option<Instant>") &&
    /^\s*struct ActivityRefreshBatch\s*\{\s*origin_epoch:\s*u64,\s*selected_account_index:\s*u8,\s*remaining_sequences:\s*VecDeque<u64>,\s*in_flight_sequence:\s*Option<u64>,\s*completed:\s*usize,\s*total:\s*usize,\s*next_dispatch_at:\s*Option<Instant>,?\s*\}$/u.test(
      activityRefreshBatchBlock,
    ) &&
    !/#\[derive\([^\]]*(?:Clone|Copy|Debug|Serialize)[^\]]*\)\]\s*struct ActivityRefreshBatch/u.test(
      sepoliaDemoUiProduction,
    ) &&
    !/(?:^|\n)\s*(?:unsafe\s+)?impl(?:\s*<[^>{}\r\n]*>)?\s+(?:Clone|Copy|Debug|fmt::Debug|(?:std|core)::fmt::Debug|Serialize|serde::Serialize)\s+for\s+(?:ActivityRefreshTarget|ActivityRefreshBatch)\b/mu.test(
      sepoliaDemoUiProduction,
    ) &&
    activityRefreshBatchImplBlock.includes("self.total != 0") &&
    activityRefreshBatchImplBlock.includes("self.total <= MAX_ACTIVITY_BATCH_ROWS") &&
    activityRefreshBatchImplBlock.includes("self.completed < self.total") &&
    activityRefreshBatchImplBlock.includes("self.completed + self.remaining_sequences.len() == self.total") &&
    activityRefreshBatchImplBlock.includes(".all(|sequence| sequence != 0)") &&
    activityRefreshBatchImplBlock.includes(".all(|(left, right)| left < right)") &&
    activityRefreshBatchImplBlock.includes(
      "match (self.in_flight_sequence, self.next_dispatch_at)",
    ) &&
    activityRefreshBatchImplBlock.includes("(Some(in_flight), None)") &&
    activityRefreshBatchImplBlock.includes("self.remaining_sequences.front().copied() == Some(in_flight)") &&
    activityRefreshBatchImplBlock.includes("(None, Some(_)) => true") &&
    activityRefreshBatchImplBlock.includes("(Some(_), Some(_)) | (None, None) => false") &&
    activityRefreshBatchImplBlock.includes("self.origin_epoch == origin_epoch") &&
    activityRefreshBatchImplBlock.includes(
      "self.selected_account_index == selected_account_index",
    ) &&
    activityRefreshBatchImplBlock.includes(
      "self.in_flight_sequence == Some(submission_sequence)",
    ) &&
    activityRefreshBatchImplBlock.includes(
      "self.remaining_sequences.front().copied() == Some(submission_sequence)",
    ) &&
    activityRefreshBatchImplBlock.includes("fn scrub(&mut self)") &&
    activityRefreshBatchImplBlock.includes("self.remaining_sequences.clear()") &&
    activityRefreshBatchDropBlock.includes("self.scrub()") &&
    walletAppBlock.includes("activity_refresh_target: Option<ActivityRefreshTarget>") &&
    walletAppBlock.includes("activity_refresh_batch: Option<ActivityRefreshBatch>"),
  "Sepolia activity batch state must remain bounded, move-only, sequence-only, and explicitly scrubbed",
);
requireInvariant(
  activityBatchCandidateBlock.includes("ActivityStatusSnapshot::Submitted") &&
    activityBatchCandidateBlock.includes("ActivityStatusSnapshot::Pending") &&
    activityBatchCandidateBlock.includes("ActivityStatusSnapshot::Reorged(_)") &&
    activityBatchCandidateBlock.includes("ActivityStatusSnapshot::DroppedCandidate") &&
    activityBatchCandidateBlock.includes("ActivityStatusSnapshot::ReplacementSuspected") &&
    (activityBatchCandidateBlock.match(/ActivityStatusSnapshot::/gu) ?? []).length === 5 &&
    !activityBatchCandidateBlock.includes("ActivityStatusSnapshot::Included") &&
    /^\s*const fn activity_is_batch_candidate\(status:\s*&ActivityStatusSnapshot\)\s*->\s*bool\s*\{\s*matches!\(\s*status,\s*ActivityStatusSnapshot::Submitted\s*\|\s*ActivityStatusSnapshot::Pending\s*\|\s*ActivityStatusSnapshot::Reorged\(_\)\s*\|\s*ActivityStatusSnapshot::DroppedCandidate\s*\|\s*ActivityStatusSnapshot::ReplacementSuspected\s*\)\s*\}\s*$/u.test(
      activityBatchCandidateBlock,
    ) &&
    startActivityBatchBlock.includes("self.require_unlocked_action()") &&
    startActivityBatchBlock.includes("self.pending.is_some()") &&
    startActivityBatchBlock.includes("self.prepared.is_some()") &&
    startActivityBatchBlock.includes("self.secret_reveal.is_some()") &&
    startActivityBatchBlock.includes("self.generated_backup.is_some()") &&
    startActivityBatchBlock.includes("snapshot.pending_broadcast.is_some()") &&
    startActivityBatchBlock.includes("snapshot.is_well_formed()") &&
    startActivityBatchBlock.includes("snapshot.selected_account_index") &&
    startActivityBatchBlock.includes("activity_is_batch_candidate(&row.status)") &&
    startActivityBatchBlock.includes(".map(|row| row.submission_sequence)") &&
    startActivityBatchBlock.includes("sequences.sort_unstable()") &&
    startActivityBatchBlock.includes("sequences.truncate(MAX_ACTIVITY_BATCH_ROWS)") &&
    startActivityBatchBlock.includes("next_dispatch_at: Some(now)") &&
    startActivityBatchBlock.includes("PendingAction::RefreshActivityBatchWait") &&
    startActivityBatchBlock.includes("self.drive_activity_refresh_batch(now)") &&
    (sepoliaDemoUiRuntime.match(/self\.start_activity_refresh_batch_at\s*\(/gu) ?? [])
      .length === 1 &&
    (sepoliaDemoUiRuntime.match(/\bstart_activity_refresh_batch_at\b/gu) ?? [])
      .length === 2 &&
    (sepoliaDemoUiRuntime.match(/ActivityRefreshBatch\s*\{\s*origin_epoch:/gu) ?? [])
      .length === 2 &&
    (sepoliaDemoUiRuntime.match(/activity_refresh_batch\s*=\s*Some\s*\(/gu) ?? [])
      .length === 1 &&
    /start_batch\s*=\s*ui[\s\S]*?\.clicked\(\);[\s\S]*?if start_batch\s*\{\s*self\.start_activity_refresh_batch_at\(Instant::now\(\)\)/u.test(
      activityPanelBlock,
    ) &&
    driveActivityBatchBlock.includes("self.pending != Some(PendingAction::RefreshActivityBatchWait)") &&
    driveActivityBatchBlock.includes("if batch.in_flight_sequence.is_some()") &&
    driveActivityBatchBlock.includes("if now < deadline") &&
    driveActivityBatchBlock.includes("batch.remaining_sequences.front().copied()") &&
    driveActivityBatchBlock.includes("origin_epoch == self.session_epoch") &&
    driveActivityBatchBlock.includes("self.session_phase == SessionPhase::Unlocked") &&
    driveActivityBatchBlock.includes("snapshot.selected_account_index != selected_account_index") &&
    driveActivityBatchBlock.includes("row.sender_address == selected.address") &&
    driveActivityBatchBlock.includes("activity_is_batch_candidate(&row.status)") &&
    driveActivityBatchBlock.includes("transaction_hash: Zeroizing::new(transaction_hash.clone())") &&
    driveActivityBatchBlock.includes("WorkerCommand::RefreshActivity { transaction_hash }") &&
    driveActivityBatchBlock.includes("PendingAction::RefreshActivity") &&
    driveActivityBatchBlock.indexOf("batch.in_flight_sequence = Some(submission_sequence)") >= 0 &&
    driveActivityBatchBlock.indexOf("batch.in_flight_sequence = Some(submission_sequence)") <
      driveActivityBatchBlock.indexOf("self.activity_refresh_target = Some(ActivityRefreshTarget") &&
    driveActivityBatchBlock.indexOf("self.activity_refresh_target = Some(ActivityRefreshTarget") <
      driveActivityBatchBlock.indexOf("self.send_command(") &&
    !/(?:thread::sleep|std::thread::sleep|last_activity_at)/u.test(
      `${startActivityBatchBlock}\n${driveActivityBatchBlock}`,
    ) &&
    (sepoliaDemoUiRuntime.match(/WorkerCommand::RefreshActivity\s*\{/gu) ?? []).length === 3 &&
    /RefreshActivity\s*\{\s*transaction_hash:\s*String,?\s*\}/u.test(
      workerCommandBlock,
    ) &&
    (workerCommandBlock.match(/\b[A-Za-z_]\w*Activity\w*\b/gu) ?? []).length === 1 &&
    walletBackendTraitBlock.includes(
      "fn refresh_activity(",
    ) &&
    (walletBackendTraitBlock.match(/\bfn\s+\w*activity\w*\s*\(/gu) ?? []).length === 1 &&
    !/(?:refresh_activity_batch|activity_batch)/u.test(
      `${sepoliaDemoBackendProduction}\n${sepoliaDemoRpcProduction}\n${sepoliaDemoActivityStore}`,
    ) &&
    (sepoliaDemoUiRuntime.match(/self\.drive_activity_refresh_batch\s*\(/gu) ?? [])
      .length === 2,
  "Sepolia activity batch must be explicit-click only, freeze the five unresolved states, and reuse exactly one existing row request at a time",
);
const activityUpdateFirstLock = walletEframeAppBlock.indexOf(
  "self.observe_automatic_lock(context, now)",
);
const activityUpdateEvents = walletEframeAppBlock.indexOf("self.process_events_at(now)");
const activityUpdateSecondLock = walletEframeAppBlock.lastIndexOf(
  "self.observe_automatic_lock(context, now)",
);
const activityUpdateDrive = walletEframeAppBlock.indexOf(
  "self.drive_activity_refresh_batch(now)",
);
requireInvariant(
  [
    activityUpdateFirstLock,
    activityUpdateEvents,
    activityUpdateSecondLock,
    activityUpdateDrive,
  ].every((index) => index >= 0) &&
    activityUpdateFirstLock < activityUpdateEvents &&
    activityUpdateEvents < activityUpdateSecondLock &&
    activityUpdateSecondLock < activityUpdateDrive &&
    walletEframeAppBlock.includes("context.request_repaint_after(") &&
    walletEframeAppBlock.includes("deadline.saturating_duration_since(now)") &&
    activityRefreshedUiBlock.includes("completed_action == Some(PendingAction::RefreshActivity)") &&
    activityRefreshedUiBlock.includes("batch.matches_in_flight(") &&
    activityRefreshedUiBlock.includes("batch.origin_epoch == self.session_epoch") &&
    activityRefreshedUiBlock.includes("snapshot.selected_account_index != selected_account_index") &&
    activityRefreshedUiBlock.includes("prior.sender_address == selected.address") &&
    activityRefreshedUiBlock.includes("same_activity_identity(prior, &refreshed)") &&
    activityRefreshedUiBlock.includes("now.checked_add(ACTIVITY_BATCH_DELAY)") &&
    activityRefreshedUiBlock.includes("PendingAction::RefreshActivityBatchWait") &&
    activityRefreshedUiBlock.includes("let category = safe_error(error)") &&
    activityRefreshedUiBlock.includes("self.stop_activity_refresh_batch_with_error(category.as_str())") &&
    (activityRefreshedUiBlock.match(/batch\.matches_in_flight\s*\(/gu) ?? []).length === 2 &&
    /Err\(error\),[\s\S]*?ActivityRefreshOrigin::Batch[\s\S]*?request_matches[\s\S]*?batch\.matches_in_flight\([\s\S]*?origin_epoch[\s\S]*?selected_account_index[\s\S]*?submission_sequence[\s\S]*?batch\.origin_epoch\s*==\s*self\.session_epoch[\s\S]*?let category = safe_error\(error\)/u.test(
      activityRefreshedUiBlock,
    ) &&
    clearActivityRefreshStateBlock.includes("self.activity_refresh_target = None") &&
    clearActivityRefreshStateBlock.includes("self.activity_refresh_batch = None") &&
    clearActivityRefreshStateBlock.includes("PendingAction::RefreshActivityBatchWait") &&
    stopActivityBatchErrorBlock.includes("zeroize_optional_string(&mut self.notice)") &&
    stopActivityBatchErrorBlock.includes("현재 행의 내구 상태") &&
    stopActivityBatchErrorBlock.includes("이후 대기 행은 요청하지 않았습니다") &&
    stopActivityBatchUserBlock.includes("self.pending != Some(PendingAction::RefreshActivityBatchWait)") &&
    activityBatchWaitMatchesBlock.includes(
      "self.pending == Some(PendingAction::RefreshActivityBatchWait)",
    ) &&
    activityBatchWaitMatchesBlock.includes("self.session_phase == SessionPhase::Unlocked") &&
    activityBatchWaitMatchesBlock.includes("batch.is_well_formed()") &&
    activityBatchWaitMatchesBlock.includes("batch.origin_epoch == self.session_epoch") &&
    activityBatchWaitMatchesBlock.includes("batch.in_flight_sequence.is_none()") &&
    activityBatchWaitMatchesBlock.includes("snapshot.is_well_formed()") &&
    activityBatchWaitMatchesBlock.includes(
      "snapshot.selected_account_index == batch.selected_account_index",
    ) &&
    /let selection_allowed\s*=\s*\(self\.pending\.is_none\(\)\s*\|\|\s*self\.activity_refresh_batch_wait_matches_current\(\)\)\s*&&/u.test(
      accountPanelBlock,
    ) &&
    accountPanelBlock.includes("ui.add_enabled_ui(selection_allowed") &&
    accountPanelBlock.includes("if requested_index != snapshot.selected_account_index") &&
    accountPanelBlock.includes("self.select_account(requested_index)") &&
    [
      selectAccountActivityBatchBlock.indexOf(
        "self.activity_refresh_batch_wait_matches_current()",
      ),
      selectAccountActivityBatchBlock.indexOf("self.stop_activity_refresh_batch_by_user()"),
      selectAccountActivityBatchBlock.indexOf("if self.pending.is_some()"),
      selectAccountActivityBatchBlock.indexOf("WorkerCommand::SelectAccount"),
    ].every((index) => index >= 0) &&
    selectAccountActivityBatchBlock.indexOf("self.activity_refresh_batch_wait_matches_current()") <
      selectAccountActivityBatchBlock.indexOf("self.stop_activity_refresh_batch_by_user()") &&
    selectAccountActivityBatchBlock.indexOf("self.stop_activity_refresh_batch_by_user()") <
      selectAccountActivityBatchBlock.indexOf("if self.pending.is_some()") &&
    selectAccountActivityBatchBlock.indexOf("if self.pending.is_some()") <
      selectAccountActivityBatchBlock.indexOf("WorkerCommand::SelectAccount") &&
    !/(?:thread::sleep|std::thread::sleep|last_activity_at)/u.test(
      `${activityRefreshedUiBlock}\n${stopActivityBatchErrorBlock}\n${stopActivityBatchUserBlock}\n${clearActivityRefreshStateBlock}`,
    ),
  "Sepolia activity batch must bind every response, schedule from response time, let lock/account change preempt dispatch, and scrub on every stop",
);
requireInvariant(
  activityPanelBlock.includes("이 행만 Sepolia에서 새로고침") &&
    activityPanelBlock.includes("고정된 Sepolia RPC") &&
    activityPanelBlock.includes("자동 새로고침, 자동 재시작, nonce 자동 재사용은 하지 않습니다") &&
    activityPanelBlock.includes("Submitted/Pending/Reorged/DroppedCandidate/ReplacementSuspected") &&
    activityPanelBlock.includes("최대 64개 고정") &&
    activityPanelBlock.includes("Included 행은 포함하지 않으며") &&
    activityPanelBlock.includes("선택한 발신 주소와 최대 64개 거래 해시, 요청 간격") &&
    activityPanelBlock.includes("한 번에 한 행만 요청") &&
    activityPanelBlock.includes("최소 2초") &&
    activityPanelBlock.includes("현재 조회 행의 내구 상태는 응답 전까지 알 수 없으며") &&
    activityPanelBlock.includes("다음 행 조회 전 순차 작업 중지") &&
    activityPanelBlock.includes("외부 단조 앵커") &&
    activityPanelBlock.includes("저장된 high-water보다 낮으면") &&
    activityPanelBlock.includes("전체 거래 해시") &&
    activityPanelBlock.includes("신뢰하지 않는 과거 컨트랙트 라벨") &&
    (sepoliaDemoUiProduction.match(/self\.refresh_activity_row\(/gu) ?? []).length === 1 &&
    sepoliaDemoUiProduction.includes("WorkerCommand::RefreshActivity { transaction_hash }") &&
    sepoliaDemoUiProduction.includes("same_activity_identity(prior, &refreshed)") &&
    sepoliaDemoUiProduction.includes("zeroize_activity_snapshot") &&
    sepoliaDemoUi.includes(
      "fn activity_batch_dispatch_deadline_is_inclusive_exactly_once_and_sleep_free()",
    ) &&
    sepoliaDemoUi.includes(
      "fn activity_batch_freezes_sorted_unresolved_start_sequences_and_excludes_included()",
    ) &&
    sepoliaDemoUi.includes(
      "fn activity_batch_accepts_exactly_the_bounded_sixty_four_start_rows()",
    ) &&
    sepoliaDemoUi.includes(
      "fn activity_batch_due_time_row_drift_stops_and_clears_scheduled_notice()",
    ) &&
    sepoliaDemoUi.includes(
      "fn activity_refresh_origin_and_first_error_progress_are_exact()",
    ) &&
    sepoliaDemoUi.includes(
      "fn activity_batch_forged_error_origin_stops_without_attribution_or_mutation()",
    ) &&
    sepoliaDemoUi.includes(
      "fn activity_batch_immutable_identity_mismatch_stops_without_row_mutation()",
    ) &&
    sepoliaDemoUi.includes(
      "fn activity_batch_account_selector_is_enabled_only_between_requests_and_scrubs_before_select()",
    ) &&
    sepoliaDemoUi.includes(
      "fn activity_batch_focus_and_inactivity_preempt_due_dispatch()",
    ) &&
    sepoliaDemoUi.includes(
      "fn activity_batch_panel_discloses_scope_privacy_and_manual_only_controls()",
    ) &&
    headlessSmokeBlock.includes("let batch_started_at = Instant::now()") &&
    headlessSmokeBlock.includes("app.start_activity_refresh_batch_at(batch_started_at)") &&
    headlessSmokeBlock.includes("batch.total == 2") &&
    headlessSmokeBlock.includes("batch.in_flight_sequence == Some(1)") &&
    headlessSmokeBlock.includes("batch.remaining_sequences.iter().copied().eq([1, 2])") &&
    headlessSmokeBlock.includes("first_completed_at + ACTIVITY_BATCH_DELAY") &&
    headlessSmokeBlock.includes("next_deadline - Duration::from_nanos(1)") &&
    headlessSmokeBlock.includes("command_receiver.try_recv().is_ok()") &&
    headlessSmokeBlock.includes("app.drive_activity_refresh_batch(next_deadline)") &&
    headlessSmokeBlock.includes("batch.in_flight_sequence == Some(2)") &&
    headlessSmokeBlock.includes("submission_sequence: 2") &&
    headlessSmokeBlock.includes("app.activity_refresh_batch.is_some()") &&
    headlessSmokeBlock.includes("app.activity_refresh_target.is_some()") &&
    headlessSmokeBlock.includes("notice.contains(\"2/2 응답 확인·화면 반영 완료\")") &&
    headlessSmokeBlock.includes("transitions_checked: 105") &&
    headlessSmokeBlock.includes("backend_routes_checked: backend.calls.len()") &&
    sepoliaDemoUi.includes("assert_eq!(evidence.transitions_checked, 105)") &&
    sepoliaDemoUi.includes("assert_eq!(evidence.backend_routes_checked, 37)") &&
    sepoliaDemoHeadless.includes("assert_eq!(report.transitions_checked, 105)") &&
    sepoliaDemoHeadless.includes("assert_eq!(report.backend_routes_checked, 37)") &&
    sepoliaDemoHeadlessProduction.includes("ui::run_headless_smoke()") &&
    rootReadme.includes("activity-v1.bin") &&
    /현재 남아 있는\s*행만 nonce 충돌을 막습니다/u.test(rootReadme) &&
    rootReadme.includes("head가 따라잡을 때까지 새로고침을 보류합니다") &&
    rootReadme.includes("시작 시점") &&
    rootReadme.includes("submission 순서로 최대 64개 고정") &&
    rootReadme.includes("단일 행 저장 뒤 인증 readback이 실패한 오류") &&
    /at\s+most 64 start-of-run/u.test(sepoliaArchitectureDoc) &&
    sepoliaArchitectureDoc.includes("one at a time") &&
    sepoliaArchitectureDoc.includes("at least two seconds") &&
    sepoliaArchitectureDoc.includes("A failing row may already have reached durable storage"),
  "Sepolia activity UI/docs lost exact identifiers, bounded explicit sequencing, privacy disclosure, scrubbing, rollback honesty, or high-water delay disclosure",
);
requireInvariant(
  sepoliaDemoUiProduction.includes("BackendStateInvalidated") &&
    sepoliaDemoUiProduction.includes("fn invalidate_frontend_after_backend_error(") &&
    sepoliaDemoUiProduction.includes(
      "self.request_lock(LockReason::BackendStateInvalidated)",
    ) &&
    accountSelectedEventBlock.includes("invalidate_frontend_after_backend_error") &&
    refreshedEventBlock.includes("invalidate_frontend_after_backend_error") &&
    sepoliaDemoUi.includes(
      "fn account_select_or_refresh_backend_invalidation_scrubs_and_locks_frontend()",
    ) &&
    rootReadme.includes("activity-v1.tmp") &&
    rootReadme.includes("tokens-v1.tmp") &&
    rootReadme.includes("vault-v2.migrating") &&
    rootReadme.includes("HMAC/PRK context") &&
    rootReadme.includes("ZeroizeOnDrop") &&
    /격리(?:된)?\s+Key Agent/u.test(rootReadme) &&
    rootReadme.includes("canonical transaction 재구성") &&
    rootReadme.includes("실제 전파·포함 여부") &&
    sepoliaArchitectureDoc.includes("token-then-activity namespaces") &&
    sepoliaArchitectureDoc.includes("exact same-directory `vault-v2.migrating` handle") &&
    sepoliaArchitectureDoc.includes("HMAC/PRK context implements neither") &&
    sepoliaArchitectureDoc.includes("single fixed TLS RPC remains a trust boundary") &&
    sepoliaArchitectureDoc.includes("local envelope self-consistency") &&
    /isolated Key Agent(?: execution)? and a zeroizing\s+KDF implementation/u.test(
      sepoliaArchitectureDoc,
    ),
  "Sepolia backend-invalidated UI lock/scrub and durable-temp/memory-forensics residuals must remain explicit",
);
for (const requiredActivityTest of [
  "legacy_migration_preserves_exact_native_pending_for_v2_restart_retry",
  "legacy_migration_rejects_foreign_signer_and_valid_erc20_before_v2_write",
  "accepted_broadcast_then_activity_commit_failure_retries_by_observation_without_resend",
  "committed_activity_with_leftover_pending_cleans_exact_file_without_network",
  "retry_nonce_collision_preserves_exact_pending_before_node_lookup_or_resend",
  "occupied_activity_nonce_slot_rejects_before_sign_pending_or_send",
  "occupied_activity_nonce_slot_rejects_saved_erc20_before_sign_pending_or_send",
  "full_activity_store_rejects_native_and_saved_erc20_before_signing",
  "authenticated_activity_sender_must_bind_to_vault_account_index",
  "manual_activity_refresh_reduces_missing_inclusion_reorg_and_reappearance_safely",
  "observed_type_two_requires_canonical_hash_signature_and_recovered_sender",
  "account_one_erc20_restart_observes_exact_pending_without_rebroadcast",
  "activity_orphan_temp_is_reconciled_before_sign_and_nonregular_temp_fails_closed",
  "token_orphan_temp_is_reconciled_before_new_v2_or_token_mutation",
  "fresh_v2_parent_is_created_durably_and_invalid_parent_fails_before_vault_write",
  "migration_temp_crash_recovery_pins_install_and_preserves_pending_until_commit",
  "windows_migration_leases_pin_v1_temp_and_installed_v2_exact_objects",
  "windows_activity_lock_and_temp_are_exclusive_reparse_safe_and_recoverable",
  "stale_or_nonregular_sidecars_block_legacy_migration_before_vault_mutation",
  "confirm_revocation_checkpoints_bound_signing_pending_and_broadcast",
  "saved_erc20_confirm_permit_checkpoints_bound_sign_write_send_and_delete",
]) {
  requireInvariant(
    sepoliaDemoBackend.includes(`fn ${requiredActivityTest}()`),
    `Sepolia activity regression evidence missing: ${requiredActivityTest}`,
  );
}

const exactErc20PreflightBlock = rustFunctionBlock(
  sepoliaDemoRpcProduction,
  "erc20_transfer_preflight",
);
const guardedRpcSendBlock = rustFunctionBlock(
  sepoliaDemoRpcProduction,
  "send_raw_transaction",
);
const guardedPermitIndex = guardedRpcSendBlock.indexOf("if !permit.is_current()");
requireInvariant(
  exactErc20PreflightBlock.includes("value: \"0x0\"") &&
    exactErc20PreflightBlock.includes("input: encode_prefixed_hex(&calldata)") &&
    exactErc20PreflightBlock.includes("transaction_type: \"0x2\"") &&
    exactErc20PreflightBlock.includes("nonce: encode_quantity(nonce)") &&
    exactErc20PreflightBlock.includes("gas: encode_quantity(gas_limit)") &&
    exactErc20PreflightBlock.includes("access_list: &[]") &&
    !/\bdata\s*:/u.test(exactErc20PreflightBlock) &&
    !/gas_price/u.test(exactErc20PreflightBlock) &&
    guardedRpcSendBlock.includes("permit: &SessionPermit<'_>") &&
    guardedRpcSendBlock.indexOf("self.verify_sepolia()?") !== -1 &&
    guardedPermitIndex > guardedRpcSendBlock.indexOf("self.verify_sepolia()?") &&
    guardedRpcSendBlock.indexOf("RpcMethod::SendRawTransaction") > guardedPermitIndex &&
    (sepoliaDemoRpcProduction.match(/pub fn send_raw_transaction\s*\(/gu) ?? []).length === 1 &&
    !/pub fn (?:unguarded_|raw_)?broadcast/u.test(sepoliaDemoRpcProduction),
  "typed ERC-20 preflight or the sole post-reverify concrete-permit broadcast guard changed",
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
const windowsStorageProduction = withoutBottomTestModule(windowsStorage);
const windowsStorageRelease = withoutCfgTestItems(windowsStorageProduction);
const windowsStorageFacadeProduction = withoutBottomTestModule(
  windowsStorageFacade,
);
const windowsStorageFacadeRelease = withoutCfgTestItems(
  windowsStorageFacadeProduction,
);
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
requireInvariant(
  attestation.includes("broker_transport_suite_digest") &&
    attestation.includes("broker_manifest_digest") &&
    attestation.includes("with_broker_transport") &&
    attestation.includes("valid_broker_manifest") &&
    attestation.includes("!helpers.contains(&broker)") &&
    /COMPILED_RELEASE_POLICY[^=]*=\s*None\s*;/su.test(attestation),
  "Broker transport evidence and manifest must remain separate from the three helper manifests and release-disabled",
);
const brokerArtifactSource = await text(
  "crates/platform-windows/src/broker_artifact.rs",
);
const brokerArtifactProduction = withoutBottomTestModule(brokerArtifactSource);
const exactBrokerImage = await text(
  "crates/platform-windows/src/exact_image.rs",
);
const exactBrokerImageProduction = withoutBottomTestModule(exactBrokerImage);
const releaseBrokerSupervisorSource = await text(
  "crates/platform-windows/src/broker_supervisor.rs",
);
const releaseBrokerSupervisorProduction = withoutBottomTestModule(
  releaseBrokerSupervisorSource,
);
const exactImageVisibleFunctionNames = [
  ...exactBrokerImageProduction.matchAll(
    /(?:^|\n)\s*pub(?:\((?:crate|super|in [^)]+)\))?\s+(?:const\s+)?fn\s+(?<name>[A-Za-z_]\w*)/gu,
  ),
].map((match) => match.groups.name);
const restrictedLauncher = await text("crates/platform-windows/src/launch.rs");
const restrictedLauncherProduction = withoutBottomTestModule(restrictedLauncher);
const restrictedLauncherRelease = withoutCfgTestItems(
  restrictedLauncherProduction,
);
requireInvariant(
  restrictedLauncher.includes("allows_helper_manifest") &&
    restrictedLauncher.includes("HelperManifestNotAllowed"),
  "restricted launcher must enforce the release-bound helper allowlist",
);

const keyAgentActivationSource = await text(
  "crates/platform-windows/src/key_agent_activation.rs",
);
const keyAgentActivation = withoutBottomTestModule(keyAgentActivationSource);
const keyAgentActivationRelease = withoutCfgTestItems(keyAgentActivation);
const keyAgentLpacSource = await text(
  "crates/platform-windows/src/key_agent_lpac.rs",
);
const keyAgentLpac = withoutBottomTestModule(keyAgentLpacSource);
const keyAgentLpacRelease = withoutCfgTestItems(keyAgentLpac);
const keyAgentInstallAdoptionSource = await text(
  "crates/platform-windows/src/key_agent_install_adoption.rs",
);
const keyAgentInstallAdoption = withoutBottomTestModule(
  keyAgentInstallAdoptionSource,
);
const keyAgentInstallAdoptionRelease = withoutCfgTestItems(
  keyAgentInstallAdoption,
);
const keyAgentInstallProvenanceSource = await text(
  "crates/platform-windows/src/key_agent_install_provenance.rs",
);
const keyAgentInstallProvenance = withoutBottomTestModule(
  keyAgentInstallProvenanceSource,
);
const keyAgentInstallProvenanceRelease = withoutCfgTestItems(
  keyAgentInstallProvenance,
);
const keyAgentStorageSource = await text(
  "crates/platform-windows/src/key_agent_storage.rs",
);
const keyAgentStorage = withoutBottomTestModule(keyAgentStorageSource);
const keyAgentStorageRelease = withoutCfgTestItems(keyAgentStorage);
const keyAgentStartupSource = await text(
  "crates/platform-windows/src/key_agent_startup.rs",
);
const keyAgentStartup = withoutBottomTestModule(keyAgentStartupSource);
const keyAgentStartupRelease = withoutCfgTestItems(keyAgentStartup);
const appContainerProfileApiSource = await text(
  "crates/platform-windows/src/appcontainer_profile_api.rs",
);
const appContainerProfileApiProduction = withoutBottomTestModule(
  appContainerProfileApiSource,
);
const restrictedProcessContextSource = await text(
  "crates/platform-windows/src/restricted_process_context.rs",
);
const restrictedProcessContext = withoutBottomTestModule(
  restrictedProcessContextSource,
);
const restrictedProcessContextProduction = withoutCfgTestItems(
  restrictedProcessContext,
);
const keyAgentRootJobSource = await text(
  "crates/platform-windows/src/key_agent_root_job.rs",
);
const keyAgentPipeSource = await text("crates/platform-windows/src/pipe.rs");
const keyAgentPipeProduction = withoutBottomTestModule(keyAgentPipeSource);
const keyAgentPipeRelease = withoutCfgTestItems(keyAgentPipeProduction);
const keyAgentSupervisorSource = await text(
  "crates/platform-windows/src/key_agent_supervisor.rs",
);
const keyAgentSupervisor = withoutBottomTestModule(keyAgentSupervisorSource);
const keyAgentSupervisorRelease = withoutCfgTestItems(keyAgentSupervisor);
const keyAgentMainSource = await text("crates/key-agent/src/main.rs");
const keyAgentWindowsMain = rustLexicalItemBlock(
  keyAgentMainSource,
  /#\s*\[\s*cfg\s*\(\s*windows\s*\)\s*\]\s*fn\s+main\s*\(\s*\)\s*\{/u,
);
const keyAgentChildBootstrapSource = await text(
  "crates/platform-windows/src/key_agent_child_bootstrap.rs",
);
const keyAgentChildBootstrapProduction = withoutBottomTestModule(
  keyAgentChildBootstrapSource,
);
const serveInheritedKeyAgentStorageStartup = rustFunctionBlock(
  keyAgentChildBootstrapProduction,
  "serve_inherited_key_agent_storage_startup",
);
const sealInheritedKeyAgentStdio = rustFunctionBlock(
  keyAgentChildBootstrapProduction,
  "seal_inherited_key_agent_stdio",
);
const sealExactKeyAgentStandardHandleSet = rustFunctionBlock(
  keyAgentChildBootstrapProduction,
  "seal_exact_standard_handle_set",
);
const keyAgentBootstrapInvalidHandle = rustFunctionBlock(
  keyAgentChildBootstrapProduction,
  "invalid",
);
const keyAgentBootstrapSameObject = rustFunctionBlock(
  keyAgentChildBootstrapProduction,
  "same_object",
);
const keyAgentBootstrapHandleFlags = rustFunctionBlock(
  keyAgentChildBootstrapProduction,
  "handle_flags",
);
const sealedKeyAgentStdioDefinition = rustLexicalItemBlock(
  keyAgentChildBootstrapProduction,
  /(?:^|\n)\s*struct\s+SealedKeyAgentStdio\s*\{/u,
);
const platformWindowsProductionFiles = await rustProductionSources(
  "crates/platform-windows/src",
  { withoutInlineTests: true },
);
const workspaceRustProductionFiles = (
  await rustProductionSources("crates", { withoutInlineTests: true })
).filter((file) => /^crates\/[^/]+\/src\//u.test(file.path));
const secretInputUiManifest = await text("crates/secret-input-ui/Cargo.toml");
const platformWindowsLocalDependencyManifestInventory = [
  {
    path: "crates/approval-wire/Cargo.toml",
    source: approvalWireManifest,
  },
  {
    path: "crates/secret-input-ui/Cargo.toml",
    source: secretInputUiManifest,
  },
].map(({ path, source }) => ({
  path,
  sha256: normalizedSourceSha256(source),
}));
const platformWindowsLocalDependencyCrateRootInventory = await Promise.all(
  ["crates/approval-wire", "crates/secret-input-ui"].map(async (path) => ({
    path,
    entries: await trustedDirectoryEntryInventory(path),
  })),
);
const platformWindowsLocalDependencySourceInventory = (
  await Promise.all(
    ["crates/approval-wire/src", "crates/secret-input-ui/src"].map((path) =>
      rustProductionSources(path, { withTestCode: true }),
    ),
  )
)
  .flat()
  .map((file) => ({
    path: file.path,
    sha256: normalizedSourceSha256(file.source),
  }));
const approvedPlatformWindowsLocalDependencyManifestInventory = [
  {
    path: "crates/approval-wire/Cargo.toml",
    sha256: "c4425735387a3699cd3fd51eb6ae613a7e42f23a4fa8e282406103b09230f913",
  },
  {
    path: "crates/secret-input-ui/Cargo.toml",
    sha256: "a1fdd15bff500909518a7a9ba357775ad4bf65d40703f4db77e047a905e39572",
  },
];
const approvedPlatformWindowsLocalDependencyCrateRootInventory = [
  {
    path: "crates/approval-wire",
    entries: [
      { name: "Cargo.toml", kind: "file" },
      { name: "src", kind: "directory" },
    ],
  },
  {
    path: "crates/secret-input-ui",
    entries: [
      { name: "Cargo.toml", kind: "file" },
      { name: "src", kind: "directory" },
      { name: "tests", kind: "directory" },
    ],
  },
];
const approvedPlatformWindowsLocalDependencySourceInventory = [
  {
    path: "crates/approval-wire/src/lib.rs",
    sha256: "d4c288cfa442d9e8efc3a008071e057d1607ffc9276265ecddd0c8a07ac28d37",
  },
  {
    path: "crates/secret-input-ui/src/bootstrap.rs",
    sha256: "04c65140711ed0b0725fc7d1444d1c57cff3197cc6766f4494d130e4adcfa81d",
  },
  {
    path: "crates/secret-input-ui/src/bootstrap/windows.rs",
    sha256: "5ef8c130bbade022f8948aaa3917d2eb71c794e457502bbffa67443fba6a034c",
  },
  {
    path: "crates/secret-input-ui/src/lib.rs",
    sha256: "0b597ffcfaea1359c7d8cf853234e0245e87151d549843eb363ac766f3ec5403",
  },
  {
    path: "crates/secret-input-ui/src/main.rs",
    sha256: "e1cece62907c531879318b64a17ada0fedee5416a35357a17e96bbba798c0fc0",
  },
  {
    path: "crates/secret-input-ui/src/recovery_native.rs",
    sha256: "599bf37dbdf31028f8e0f1a335719e3fc3c92fb79f25cb1e2c4788b3b857ffae",
  },
  {
    path: "crates/secret-input-ui/src/recovery.rs",
    sha256: "0de0473d33514c5ccefab8c2de5dc4d154d764cb507a1e4a25e2100748f3a058",
  },
];
const platformWindowsLib = await text("crates/platform-windows/src/lib.rs");
const platformWindowsManifest = await trustedRegularFileText(
  "crates/platform-windows/Cargo.toml",
);
const platformWindowsManifestSha256 = normalizedSourceSha256(
  platformWindowsManifest,
);
const platformWindowsCrateRootInventory =
  await trustedDirectoryEntryInventory("crates/platform-windows");
const workspaceManifest = rootManifest;
const workspaceLock = await trustedRegularFileText("Cargo.lock");
const workspaceLockSha256 = normalizedSourceSha256(workspaceLock);
const repositoryCargoOverrideInventory = await repositoryCargoOverridePaths();
const platformWindowsLibCode = platformWindowsLib.replace(/^\s*\/\/.*$/gmu, "");
const inheritableHandleLaunchSource = await text(
  "crates/platform-windows/src/inheritable_handle_launch.rs",
);
const inheritableHandleLaunch = withoutBottomTestModule(
  inheritableHandleLaunchSource,
);
const attestationProduction = withoutBottomTestModule(attestation);
const attestationRelease = withoutCfgTestItems(attestationProduction);
const attestationReleaseCode = rustLexicalCode(attestationRelease);
const attestedArtifactDigestImpl = rustLexicalItemBlock(
  attestationRelease,
  /impl\s+AttestedArtifactDigest\s*\{/u,
);
const attestedArtifactDigestDebugImpl = rustLexicalItemBlock(
  attestationRelease,
  /impl\s+core::fmt::Debug\s+for\s+AttestedArtifactDigest\s*\{/u,
);
const releaseAttestationBlock = rustTopLevelLexicalItemBlock(
  attestationRelease,
  /pub\s+struct\s+ReleaseAttestation\s*\{/u,
);
const releaseAttestationImpl = rustLexicalItemBlock(
  attestationRelease,
  /impl\s+ReleaseAttestation\s*\{/u,
);
const evaluateReleaseAttestationAgainstPolicy = rustFunctionBlock(
  releaseAttestationImpl,
  "evaluate_against_policy",
);
const attestedArtifactAccessor = rustFunctionBlock(
  releaseAttestationImpl,
  "attested_artifact",
);
const attestedArtifactMatches = rustFunctionBlock(
  attestedArtifactDigestImpl,
  "matches",
);
const attestedArtifactDigestConsumers = platformWindowsProductionFiles
  .filter(
    (file) =>
      file.path !== "crates/platform-windows/src/attestation.rs" &&
      /\bAttestedArtifactDigest\b/u.test(rustLexicalCode(file.source)),
  )
  .map((file) => file.path);
const attestedArtifactAccessorConsumers = platformWindowsProductionFiles
  .filter(
    (file) =>
      file.path !== "crates/platform-windows/src/attestation.rs" &&
      rustCallSites(file.source, "attested_artifact").length > 0,
  )
  .map((file) => file.path);
const activationHelper = withoutBottomTestModule(
  await text("crates/platform-windows/src/helper.rs"),
);
const activationArchitecture = await text("docs/architecture.md");
const activationReadme = await text("crates/platform-windows/README.md");
const securityDecisions = await text("docs/security-decisions.md");
const keyAgentProtocolDocumentation = await text("docs/protocol-contract.md");
requireInvariant(
  /#\[cfg\(test\)\]\s*pub\(crate\) fn for_broker_artifact_test\(\s*path: PathBuf,\s*manifest_digest: \[u8; 32\],\s*broker_role: bool,\s*\) -> Result<Self, HelperError>\s*\{/u.test(
    activationHelper,
  ) &&
    (activationHelper.match(/\bfor_broker_artifact_test\b/gu) ?? []).length === 1 &&
    /#\[cfg\(test\)\]\s*pub\(crate\) const fn with_broker_manifest_for_test\(\s*artifact: ArtifactDigest,\s*digest: \[u8; 32\],\s*\) -> Self\s*\{/u.test(
      attestationProduction,
    ) &&
    (attestationProduction.match(/\bwith_broker_manifest_for_test\b/gu) ?? [])
      .length === 1 &&
    /#\[cfg\(test\)\]\s*pub\(crate\) const fn with_helper_manifests_for_test\(\s*artifact: ArtifactDigest,\s*digests: \[\[u8; 32\]; REQUIRED_HELPER_MANIFESTS\],\s*\) -> Self\s*\{/u.test(
      attestationProduction,
    ) &&
    (attestationProduction.match(/\bwith_helper_manifests_for_test\b/gu) ?? [])
      .length === 1 &&
    /#\[cfg\(test\)\]\s*pub\(crate\) fn for_test\(value: \[u8; 32\]\) -> Self\s*\{\s*assert!\(\s*value != \[0; 32\]/u.test(
      attestationProduction,
    ) &&
    (attestationProduction.match(/\bfor_test\b/gu) ?? []).length === 1,
  "Broker/helper artifact and signing-enabled attestation test constructors must remain test-only with no production duplicate",
);
requireInvariant(
  /#\[derive\(Clone,\s*Copy,\s*Eq,\s*PartialEq\)\]\s*pub\(crate\)\s+struct\s+AttestedArtifactDigest\(ArtifactDigest\)\s*;/u.test(
    attestationReleaseCode,
  ) &&
    (attestationReleaseCode.match(/\bAttestedArtifactDigest\s*\(/gu) ?? [])
      .length === 2 &&
    evaluateReleaseAttestationAgainstPolicy.includes(
      "attested_artifact: signing_enabled.then_some(AttestedArtifactDigest(artifact))",
    ) &&
    rustLexicalCode(releaseAttestationBlock).replace(/\s+/gu, "") ===
      "pubstructReleaseAttestation{attested_artifact:Option<AttestedArtifactDigest>,allowed_helper_manifest_digests:Option<[[u8;32];REQUIRED_HELPER_MANIFESTS]>,allowed_broker_manifest_digest:Option<[u8;32]>,}" &&
    rustLexicalCode(attestedArtifactMatches).replace(/\s+/gu, "") ===
      "pub(crate)fnmatches(self,expected:&[u8;32])->bool{self.0.0.ct_eq(expected).into()}" &&
    rustLexicalCode(attestedArtifactAccessor).replace(/\s+/gu, "") ===
      "pub(crate)constfnattested_artifact(self)->Option<AttestedArtifactDigest>{self.attested_artifact}" &&
    JSON.stringify(
      [
        ...rustLexicalCode(attestedArtifactDigestImpl).matchAll(
          /\bpub(?:\s*\([^)]*\))?\s+(?:const\s+)?fn\s+(?<name>[A-Za-z_]\w*)/gu,
        ),
      ].map((match) => match.groups.name),
    ) === JSON.stringify(["matches"]) &&
    JSON.stringify(
      [
        ...rustLexicalCode(releaseAttestationImpl).matchAll(
          /\bpub(?:\s*\([^)]*\))?\s+(?:const\s+)?fn\s+(?<name>[A-Za-z_]\w*)/gu,
        ),
      ].map((match) => match.groups.name),
    ) ===
      JSON.stringify([
        "evaluate",
        "signing_enabled",
        "attested_artifact",
        "allows_helper_manifest",
        "allows_broker_manifest",
      ]) &&
    JSON.stringify(
      rustImplItems(attestationRelease)
        .filter((item) => /\bAttestedArtifactDigest\b/u.test(item.header))
        .map((item) => item.header),
    ) ===
      JSON.stringify([
        "impl AttestedArtifactDigest",
        "impl core::fmt::Debug for AttestedArtifactDigest",
      ]) &&
    rustLexicalCode(attestedArtifactDigestDebugImpl).replace(/\s+/gu, "") ===
      "implcore::fmt::DebugforAttestedArtifactDigest{fnfmt(&self,formatter:&mutcore::fmt::Formatter<'_>)->core::fmt::Result{formatter.write_str()}}" &&
    attestation.includes("AttestedArtifactDigest([REDACTED])") &&
    JSON.stringify(attestedArtifactDigestConsumers) ===
      JSON.stringify(["crates/platform-windows/src/key_agent_activation.rs"]) &&
    JSON.stringify(attestedArtifactAccessorConsumers) ===
      JSON.stringify(["crates/platform-windows/src/key_agent_activation.rs"]) &&
    platformWindowsProductionFiles
      .filter(
        (file) =>
          file.path !== "crates/platform-windows/src/attestation.rs",
      )
      .every(
        (file) =>
          (rustLexicalCode(file.source).match(
            /\bAttestedArtifactDigest\s*\(/gu,
          ) ?? []).length === 0,
      ) &&
    !/impl\s+(?:Default|Drop|Deref|DerefMut|AsRef|Borrow|From(?:<[^>]+>)?|Into(?:<[^>]+>)?|TryFrom(?:<[^>]+>)?)\s+for\s+AttestedArtifactDigest\b/u.test(
      attestationReleaseCode,
    ) &&
    !/pub\(crate\)\s+(?:const\s+)?fn\s+(?:raw\w*|as_bytes|into_inner|into_parts|artifact_digest|manifest_digest)\b/u.test(
      attestedArtifactDigestImpl,
    ) &&
    !/\b(?:allowed_helper_manifest_digests|allowed_broker_manifest_digest)\s*:\s*Option<AttestedArtifactDigest>/u.test(
      attestationReleaseCode,
    ),
  "whole-release AttestedArtifactDigest authority must be opaque, compiled-policy-minted once, raw-getter-free, and distinct from helper or Broker manifest digests",
);
const brokerPreflight = rustFunctionBlock(
  brokerArtifactProduction,
  "preflight_broker_artifact",
);
const prepareReleaseBrokerSupervisor = rustFunctionBlock(
  brokerArtifactProduction,
  "prepare_release_broker_supervisor",
);
const preparedReleaseBrokerSupervisor = rustItemBlock(
  releaseBrokerSupervisorProduction,
  /(?:^|\n)pub\(crate\)\s+struct\s+PreparedReleaseBrokerSupervisor\s*\{/u,
);
const preflightBrokerArtifactDebug = rustItemBlock(
  brokerArtifactProduction,
  /(?:^|\n)impl fmt::Debug for PreflightBrokerArtifact\s*\{/u,
);
const preparedReleaseBrokerSupervisorDebug = rustItemBlock(
  releaseBrokerSupervisorProduction,
  /(?:^|\n)impl fmt::Debug for PreparedReleaseBrokerSupervisor\s*\{/u,
);
const preparedReleaseBrokerSupervisorDrop = rustItemBlock(
  releaseBrokerSupervisorProduction,
  /(?:^|\n)impl Drop for PreparedReleaseBrokerSupervisor\s*\{/u,
);
const preparedReleaseBrokerSupervisorNew = rustFunctionBlock(
  releaseBrokerSupervisorProduction,
  "new",
);
const brokerActivationImage = rustItemBlock(
  releaseBrokerSupervisorProduction,
  /(?:^|\n)enum BrokerActivationImage\s*\{/u,
);
const brokerActivationImagePath = rustFunctionBlock(
  releaseBrokerSupervisorProduction,
  "path",
);
const brokerActivationImageAuthentication = rustFunctionBlock(
  releaseBrokerSupervisorProduction,
  "authenticate_mapped_image",
);
const launchPreparedReleaseBroker = rustFunctionBlock(
  releaseBrokerSupervisorProduction,
  "launch_prepared_release_broker_channel",
);
const launchBrokerImage = rustFunctionBlock(
  releaseBrokerSupervisorProduction,
  "launch_broker_image",
);
const runningBrokerDefinition = rustItemBlock(
  releaseBrokerSupervisorProduction,
  /(?:^|\n)\s*pub\(super\) struct RunningBroker\s*\{/u,
);
const releaseBrokerProcessCreation = rustFunctionBlock(
  releaseBrokerSupervisorProduction,
  "launch_broker_application_with_after_create",
);
const heldHelperFileIdentity = rustFunctionBlock(
  exactBrokerImageProduction,
  "held_helper_file_identity",
);
const exactMappedImageAuthenticationCore = rustFunctionBlock(
  exactBrokerImageProduction,
  "authenticate_mapped_image",
);
const preparedReleaseBrokerSupervisorTest = rustFunctionBlock(
  releaseBrokerSupervisorSource,
  "prepared_release_supervisor_retains_same_handle_and_full_file_identity",
);
const preparedReleaseBrokerRoundTripTest = rustFunctionBlock(
  releaseBrokerSupervisorSource,
  "prepared_release_supervisor_round_trips_one_be_frame_and_8192_payload",
);
const preparedReleaseBrokerMismatchTest = rustFunctionBlock(
  releaseBrokerSupervisorSource,
  "mismatched_mapped_file_is_rejected_before_user_mode",
);
const preparedReleaseBrokerDropTest = rustFunctionBlock(
  releaseBrokerSupervisorSource,
  "dropping_channel_terminates_and_reaps_a_hung_exact_child",
);
const preparedReleaseBrokerPanicTest = rustFunctionBlock(
  releaseBrokerSupervisorSource,
  "panic_after_create_terminates_and_reaps_the_exact_child",
);
const preparedReleaseBrokerDeadlineTest = rustFunctionBlock(
  releaseBrokerSupervisorSource,
  "expired_release_entry_rejects_before_allocating_activation_resources",
);
const brokerPreflightOrder = [
  "if !artifact.is_broker()",
  "if !attestation.signing_enabled()",
  "if !attestation.allows_broker_manifest(artifact.manifest_digest())",
  "if !artifact.path().is_absolute()",
  "Ok(PreflightBrokerArtifact { artifact })",
].map((marker) => brokerPreflight.indexOf(marker));
const preparedReleaseBrokerSupervisorNormalized = preparedReleaseBrokerSupervisor
  .replace(/\s+/gu, " ")
  .trim();
const preflightBrokerArtifactDebugNormalized = preflightBrokerArtifactDebug
  .replace(/\s+/gu, " ")
  .trim();
const preparedReleaseBrokerSupervisorDebugNormalized =
  preparedReleaseBrokerSupervisorDebug.replace(/\s+/gu, " ").trim();
const preparedReleaseBrokerSupervisorNewNormalized =
  preparedReleaseBrokerSupervisorNew.replace(/\s+/gu, " ").trim();
const prepareReleaseBrokerSupervisorNormalized = prepareReleaseBrokerSupervisor
  .replace(/\s+/gu, " ")
  .trim();
const heldHelperFileIdentityNormalized = heldHelperFileIdentity
  .replace(/\s+/gu, " ")
  .trim();
const brokerAdmissionAndPreparedSurface = [
  brokerPreflight,
  prepareReleaseBrokerSupervisor,
  heldHelperFileIdentity,
].join("\n");
const preflightBrokerTraitImpls = [
  ...brokerArtifactProduction.matchAll(
    /(?:^|\n)\s*(?:unsafe\s+)?impl\s+(?<trait>[^\r\n{]+?)\s+for\s+[^\r\n{]*\bPreflightBrokerArtifact\b[^\r\n{]*\{/gu,
  ),
].map((match) => match.groups.trait.trim());
const preparedBrokerTraitImpls = [
  ...releaseBrokerSupervisorProduction.matchAll(
    /(?:^|\n)\s*(?:unsafe\s+)?impl\s+(?<trait>[^\r\n{]+?)\s+for\s+[^\r\n{]*\bPreparedReleaseBrokerSupervisor\b[^\r\n{]*\{/gu,
  ),
].map((match) => match.groups.trait.trim());
const brokerArtifactVisibleFunctionNames = [
  ...brokerArtifactProduction.matchAll(
    /(?:^|\n)\s*pub(?:\((?:crate|super|in [^)]+)\))?\s+(?:const\s+)?fn\s+(?<name>[A-Za-z_]\w*)/gu,
  ),
].map((match) => match.groups.name);
const preparedBrokerTestOrder = [
  "let held_handle = broker.raw_handle()",
  "let expected_identity = held_helper_file_identity(&broker)?",
  "preflight_broker_artifact(attestation, broker)?",
  "prepare_release_broker_supervisor(admitted)?",
  "assert_eq!(prepared.artifact.raw_handle(), held_handle)",
  "assert_eq!(prepared.identity, expected_identity)",
  'format!("{prepared:?}")',
  "drop(prepared)",
].map((marker) => preparedReleaseBrokerSupervisorTest.indexOf(marker));
requireInvariant(
  platformWindowsLib.includes("mod broker_artifact;") &&
    !/pub(?:\([^)]*\))?\s+mod\s+broker_artifact\b/u.test(platformWindowsLib) &&
    !/pub(?:\([^)]*\))?\s+use\s+[^;]*(?:PreflightBrokerArtifact|preflight_broker_artifact|prepare_release_broker_supervisor)/u.test(
      platformWindowsLib,
    ) &&
    /pub\(crate\)\s+struct\s+PreflightBrokerArtifact\s*\{\s*artifact:\s*VerifiedHelper,?\s*\}/u.test(
      brokerArtifactProduction,
    ) &&
    !/#\[derive\([^\]]*\bClone\b[^\]]*\)\]\s*(?:#\[[^\]\r\n]+\]\s*)*pub\(crate\)\s+struct\s+PreflightBrokerArtifact\b/u.test(
      brokerArtifactProduction,
    ) &&
    !/impl\s+Clone\s+for\s+PreflightBrokerArtifact\b/u.test(
      brokerArtifactProduction,
    ) &&
    JSON.stringify(preflightBrokerTraitImpls) ===
      JSON.stringify(["fmt::Debug"]) &&
    preflightBrokerArtifactDebugNormalized ===
      'impl fmt::Debug for PreflightBrokerArtifact { fn fmt(&self, formatter: &mut fmt::Formatter<\'_>) -> fmt::Result { formatter.write_str("PreflightBrokerArtifact([PINNED VERIFIED BROKER])") } }' &&
    !/(?:^|\n)\s*impl\s+PreflightBrokerArtifact\b[^\{]*\{/u.test(
      brokerArtifactProduction,
    ) &&
    brokerPreflightOrder.every((position) => position !== -1) &&
    brokerPreflightOrder.every(
      (position, index, positions) => index === 0 || positions[index - 1] < position,
    ) &&
    activationHelper.includes("pub(crate) const fn is_broker(&self) -> bool") &&
    !/pub\(crate\)\s+(?:const\s+)?fn\s+(?:artifact|into_artifact|path|raw_handle|launch|spawn)\b/u.test(
      brokerArtifactProduction,
    ) &&
    !/\b(?:CreateProcess\w*|ShellExecute\w*|WinExec|Command::new|std::thread::spawn)\s*\(/u.test(
      brokerArtifactProduction,
    ),
  "private Broker preflight must own one opaque artifact and preserve role/evidence/manifest/path ordering without activation APIs",
);
requireInvariant(
  /#\[must_use = "dropping the prepared Broker supervisor closes its pinned file"\]\s*pub\(crate\) struct PreparedReleaseBrokerSupervisor/u.test(
    releaseBrokerSupervisorProduction,
  ) &&
    preparedReleaseBrokerSupervisorNormalized ===
      "pub(crate) struct PreparedReleaseBrokerSupervisor { artifact: VerifiedHelper, identity: ExactFileIdentity, }" &&
    !/#\[derive\([^\]]*(?:Clone|Copy|Debug|Serialize)[^\]]*\)\]\s*(?:#\[[^\]\r\n]+\]\s*)*pub\(crate\)\s+struct\s+PreparedReleaseBrokerSupervisor/u.test(
      releaseBrokerSupervisorProduction,
    ) &&
    JSON.stringify(preparedBrokerTraitImpls) ===
      JSON.stringify(["fmt::Debug", "Drop"]) &&
    JSON.stringify(brokerArtifactVisibleFunctionNames) ===
      JSON.stringify([
        "preflight_broker_artifact",
        "prepare_release_broker_supervisor",
      ]) &&
    !/pub\(in\s+[^)]+\)/u.test(
      `${brokerArtifactProduction}\n${releaseBrokerSupervisorProduction}`,
    ) &&
    !/(?:^|\n)\s*(?:pub(?:\([^)]*\))?\s+)?type\s+\w+(?:<[^;=]*>)?\s*=\s*[^;]*\b(?:PreflightBrokerArtifact|PreparedReleaseBrokerSupervisor)\b[^;]*;/u.test(
      `${brokerArtifactProduction}\n${releaseBrokerSupervisorProduction}`,
    ) &&
    !/(?:^|\n)\s*(?:pub(?:\([^)]*\))?\s+)?use\s+[^;]*\b(?:PreflightBrokerArtifact|PreparedReleaseBrokerSupervisor)\b\s+as\s+\w+[^;]*;/u.test(
      `${brokerArtifactProduction}\n${releaseBrokerSupervisorProduction}`,
    ) &&
    preparedReleaseBrokerSupervisorDebugNormalized ===
      'impl fmt::Debug for PreparedReleaseBrokerSupervisor { fn fmt(&self, formatter: &mut fmt::Formatter<\'_>) -> fmt::Result { formatter.write_str("PreparedReleaseBrokerSupervisor([HELD BROKER/FILE_ID_INFO])") } }' &&
    preparedReleaseBrokerSupervisorDrop
      .replace(/\s+/gu, " ")
      .trim() ===
      "impl Drop for PreparedReleaseBrokerSupervisor { fn drop(&mut self) { self.identity.zeroize(); } }" &&
    preparedReleaseBrokerSupervisorNewNormalized ===
      "pub(super) fn new(artifact: VerifiedHelper, identity: ExactFileIdentity) -> Self { Self { artifact, identity } }" &&
    (releaseBrokerSupervisorProduction.match(/\bfn new\(artifact: VerifiedHelper, identity: ExactFileIdentity\)/gu) ?? [])
      .length === 1 &&
    brokerArtifactProduction.includes(
      '#[path = "broker_supervisor.rs"]\npub(crate) mod broker_supervisor;',
    ) &&
    !platformWindowsLibCode.includes("mod broker_supervisor;") &&
    /#\[cfg\(windows\)\]\s*pub\(crate\) fn prepare_release_broker_supervisor/u.test(
      brokerArtifactProduction,
    ) &&
    prepareReleaseBrokerSupervisorNormalized ===
      "pub(crate) fn prepare_release_broker_supervisor( artifact: PreflightBrokerArtifact, ) -> Result<PreparedReleaseBrokerSupervisor, BrokerSupervisorPreflightError> { let identity = held_helper_file_identity(&artifact.artifact)?; let PreflightBrokerArtifact { artifact } = artifact; Ok(PreparedReleaseBrokerSupervisor::new(artifact, identity)) }" &&
    heldHelperFileIdentityNormalized ===
      "pub(super) fn held_helper_file_identity( artifact: &VerifiedHelper, ) -> Result<ExactFileIdentity, ExactImageError> { sys::exact_file_identity(artifact.raw_handle()) }" &&
    /enum BrokerSupervisorPreflightError\s*\{[^}]*IdentityUnavailable/u.test(
      brokerArtifactProduction,
    ) &&
    /impl From<ExactImageError> for BrokerSupervisorPreflightError\s*\{[\s\S]*?Self::IdentityUnavailable/u.test(
      brokerArtifactProduction,
    ) &&
    !/(?:std::fs|OpenOptions|File::open|CreateFile\w*|OpenProcess|CreateProcess\w*|ShellExecute\w*|Command::new|std::thread|thread::Builder|\bmpsc\b|\b(?:sync_)?channel\s*\(|CreateNamedPipe\w*|CreatePipe|DormantBrokerPipe|BrokerJob|BrokerChannel|JobObject|\blaunch\w*\s*\(|\bspawn\w*\s*\()/u.test(
      brokerAdmissionAndPreparedSurface,
    ) &&
    !/(?:\.path\s*\(|canonicalize\s*\(|\bopen\s*\(|\bhold\s*\(|raw_handle|\bpid\b)/iu.test(
      prepareReleaseBrokerSupervisor,
    ) &&
    platformWindowsLib.includes(
      "use platform_windows::broker_artifact::broker_supervisor::PreparedReleaseBrokerSupervisor;",
    ) &&
    platformWindowsLib.includes(
      "use platform_windows::broker_artifact::prepare_release_broker_supervisor;",
    ) &&
    !/pub(?:\([^)]*\))?\s+use\s+[^;]*(?:PreparedReleaseBrokerSupervisor|prepare_release_broker_supervisor)/u.test(
      platformWindowsLib,
    ) &&
    !/(?:PreparedReleaseBrokerSupervisor|prepare_release_broker_supervisor)/u.test(
      platformWindowsLibCode,
    ) &&
    platformWindowsProductionFiles
      .filter(
        (file) =>
          file.path !== "crates/platform-windows/src/broker_artifact.rs" &&
          file.path !== "crates/platform-windows/src/broker_supervisor.rs" &&
          file.path !== "crates/platform-windows/src/lib.rs",
      )
      .every(
        (file) =>
          !/(?:PreflightBrokerArtifact|PreparedReleaseBrokerSupervisor|prepare_release_broker_supervisor)/u.test(
            file.source,
          ),
      ) &&
    preparedBrokerTestOrder.every((position) => position !== -1) &&
    preparedBrokerTestOrder.every(
      (position, index, positions) => index === 0 || positions[index - 1] < position,
    ),
  "Broker admission must be the sole prepared-state minting authority and retain one same-handle, non-cloneable, redacted capability",
);
const preparedBrokerActivationOrder = [
  "check_deadline(deadline)?",
  'DormantBrokerPipe::create("ipc-v1")?',
  ".spawn(move || sys::launch_broker(image, &endpoint, command_line, deadline))",
  ".join()",
  "ExpectedBrokerPeer::from_process_handle(running.process_handle())?",
  "server.accept(expected, deadline)",
].map((marker) => launchBrokerImage.indexOf(marker));
requireInvariant(
  /enum BrokerActivationImage\s*\{\s*Prepared\(PreparedReleaseBrokerSupervisor\),\s*#\[cfg\(all\(feature = "broker-channel-contract-test-hook", debug_assertions\)\)\]\s*Debug\(PinnedBrokerImage\),?\s*\}/u.test(
    brokerActivationImage,
  ) &&
    brokerActivationImagePath.includes(
      "Self::Prepared(prepared) => prepared.artifact.path()",
    ) &&
    brokerActivationImageAuthentication.includes(
      "authenticate_mapped_image(&prepared.identity, mapped_image)",
    ) &&
    exactMappedImageAuthenticationCore.includes(
      "sys::exact_file_identity(mapped_image)?",
    ) &&
    exactMappedImageAuthenticationCore.includes(".eq(identity)"),
  "prepared Broker activation image must remain a sealed prepared/debug sum with same-held-file mapped-image authentication",
);
requireInvariant(
  /pub\(crate\) fn launch_prepared_release_broker_channel\(\s*prepared: PreparedReleaseBrokerSupervisor,\s*deadline: Instant,\s*\)/u.test(
    releaseBrokerSupervisorProduction,
  ) &&
    launchPreparedReleaseBroker.includes(
      "BrokerActivationImage::Prepared(prepared)",
    ) &&
    launchPreparedReleaseBroker.includes("None,") &&
    !/(?:PinnedBrokerImage|hold_dormant_broker|OpenOptions|File::open|CreateFile\w*|raw_handle|\bpid\b|command_line:|application_override)/iu.test(
      launchPreparedReleaseBroker,
    ) &&
    (releaseBrokerSupervisorProduction.match(
      /BrokerActivationImage::Prepared\(prepared\)/gu,
    ) ?? []).length === 2 &&
    /#\[cfg\(test\)\]\s*fn launch_prepared_release_broker_channel_for_test\(/u.test(
      releaseBrokerSupervisorProduction,
    ) &&
    (platformWindowsProductionFiles
      .filter((file) =>
        file.source.includes("PreparedReleaseBrokerSupervisor::new("),
      )
      .map((file) => file.path)
      .join(",") === "crates/platform-windows/src/broker_artifact.rs") &&
    JSON.stringify(
      platformWindowsProductionFiles.flatMap((file) =>
        [...file.source.matchAll(/\blaunch_prepared_release_broker_channel\b/gu)].map(
          () => file.path,
        ),
      ),
    ) === JSON.stringify(["crates/platform-windows/src/broker_supervisor.rs"]),
  "prepared Broker release entry must have one admission-minted consumer and no path/raw-handle/PID/command-line launch input",
);
requireInvariant(
  preparedBrokerActivationOrder.every((position) => position !== -1) &&
    preparedBrokerActivationOrder.every(
      (position, index, positions) => index === 0 || positions[index - 1] < position,
    ) &&
    runningBrokerDefinition.includes("_image: BrokerActivationImage") &&
    releaseBrokerProcessCreation.includes("debuggee.authenticate_first_event(&image") &&
    releaseBrokerProcessCreation.includes("_image: image") &&
    releaseBrokerProcessCreation.indexOf("debuggee.authenticate_first_event(&image") <
      releaseBrokerProcessCreation.indexOf("debuggee.start_user_mode()") &&
    !/pub(?:\([^)]*\))?\s+use\s+[^;]*(?:PreparedReleaseBrokerSupervisor|launch_prepared_release_broker_channel)/u.test(
      platformWindowsLib,
    ),
  "prepared Broker ownership must cross the exact-image worker and remain retained until process/Job/channel cleanup without public export",
);
requireInvariant(
  preparedReleaseBrokerRoundTripTest.includes(
    "launch_prepared_release_broker_channel_for_test(",
  ) &&
    preparedReleaseBrokerRoundTripTest.includes("8_192") &&
    preparedReleaseBrokerMismatchTest.includes(
      "BrokerActivationImage::Prepared(prepared)",
    ) &&
    preparedReleaseBrokerMismatchTest.includes("&artifacts.mismatch") &&
    preparedReleaseBrokerDropTest.includes("observation.wait_terminated()") &&
    preparedReleaseBrokerPanicTest.includes("std::thread::spawn") &&
    preparedReleaseBrokerPanicTest.includes("wait_terminated()") &&
    preparedReleaseBrokerDeadlineTest.includes(
      "launch_prepared_release_broker_channel(prepared, Instant::now())",
    ) &&
    preparedReleaseBrokerDeadlineTest.includes("DormantBrokerError::Deadline") &&
    /COMPILED_RELEASE_POLICY[^=]*=\s*None\s*;/su.test(attestation),
  "prepared Broker activation must retain round-trip, mismatch, cleanup, panic, pre-allocation deadline, and release-disabled evidence",
);
requireInvariant(
  activationArchitecture.includes("private, dormant Broker") &&
    activationArchitecture.includes("exactly three signing-TCB helper manifests") &&
    activationArchitecture.includes("`PreparedReleaseBrokerSupervisor`") &&
    activationArchitecture.includes("same already-held file handle") &&
    activationArchitecture.includes("all 128") &&
    activationArchitecture.includes(
      "production-compiled, crate-private Broker activation core",
    ) &&
    activationArchitecture.includes("deadline-bound process-wide coordinator") &&
    activationArchitecture.includes("one loaded crate instance") &&
    activationArchitecture.includes("separate matching static lock") &&
    activationArchitecture.includes("`COMPILED_RELEASE_POLICY` remains `None`") &&
    activationArchitecture.includes("4900/exit-78") &&
    activationReadme.includes("private dormant Broker artifact preflight") &&
    activationReadme.includes("`prepare_release_broker_supervisor`") &&
    activationReadme.includes("same already-held file handle") &&
    activationReadme.includes("non-cloneable and drop-only") &&
    activationReadme.includes("production-compiled, crate-private exact-image") &&
    activationReadme.includes("deadline-bound process-wide flight") &&
    activationReadme.includes("one loaded `platform-windows` crate") &&
    activationReadme.includes("separate matching static lock") &&
    activationReadme.includes("`COMPILED_RELEASE_POLICY = None`") &&
    securityDecisions.includes("private dormant Broker preflight") &&
    securityDecisions.includes("`PreparedReleaseBrokerSupervisor`") &&
    securityDecisions.includes("same already-held") &&
    securityDecisions.includes(
      "production-compiled, crate-private exact-image activation core",
    ) &&
    securityDecisions.includes("deadline-bound") &&
    securityDecisions.includes("one loaded") &&
    securityDecisions.includes("separate matching static lock") &&
    securityDecisions.includes("Current release status: STOP-SHIP") &&
    rootReadme.includes("`PreparedReleaseBrokerSupervisor`") &&
    rootReadme.includes("경로 재열기") &&
    rootReadme.includes("production-compiled exact-image 활성화 core") &&
    rootReadme.includes("deadline-bound process-wide coordinator") &&
    rootReadme.includes("같은 `platform-windows` crate instance") &&
    rootReadme.includes("`COMPILED_RELEASE_POLICY`는 계속 `None`"),
  "Broker preflight and dormant activation must remain documented as same-held-file, private, release-disabled, coordinator-covered within one crate instance, and STOP-SHIP",
);

const keyAgentWindowsMainNormalized = normalizeRustFragment(
  rustLexicalCode(keyAgentWindowsMain),
);
const keyAgentWindowsStorageStartupCalls = rustCallSites(
  keyAgentWindowsMain,
  "serve_inherited_key_agent_storage_startup",
);
const keyAgentWindowsExitCalls = rustCallSites(keyAgentWindowsMain, "exit");
requireInvariant(
  keyAgentWindowsMainNormalized ===
    "#[cfg(windows)] fn main() { let Ok(()) = platform_windows::serve_inherited_key_agent_storage_startup() else { std::process::exit(78); }; std::process::exit(78); }" &&
    keyAgentWindowsStorageStartupCalls.length === 1 &&
    keyAgentWindowsStorageStartupCalls[0]?.arguments.length === 0 &&
    keyAgentWindowsExitCalls.length === 2 &&
    keyAgentWindowsExitCalls.every(
      (call) => JSON.stringify(call.arguments) === JSON.stringify(["78"]),
    ),
  "the Windows Key Agent entrypoint must invoke only the zero-argument storage-startup child service and terminate with exit 78 on both outcomes",
);

const keyAgentBootstrapPublicFunctionNames = [
  ...rustLexicalCode(keyAgentChildBootstrapProduction).matchAll(
    /(?:^|\n)\s*pub(?:\([^\r\n)]*\))?\s+(?:(?:const|async|unsafe)\s+)*(?:extern(?:\s+"[^"\r\n]*")?\s+)?fn\s+(?<name>[A-Za-z_]\w*)/gu,
  ),
].map((match) => match.groups.name);
const keyAgentBootstrapExportMembers = normalizeRustFragment(
  /pub\s+use\s+key_agent_child_bootstrap::\{(?<members>[^}]*)\}/u.exec(
    rustLexicalCode(platformWindowsLib),
  )?.groups?.members ?? "",
);
const keyAgentBootstrapApiAliases = [
  ...rustLexicalCode(keyAgentChildBootstrapProduction).matchAll(
    /\b(?:CompareObjectHandles|GetFileType|GetHandleInformation|GetStdHandle|SetHandleInformation)\s+as\s+(?:_|[A-Za-z_]\w*)|\b(?:let|const|static)\s+(?:mut\s+)?[A-Za-z_]\w*(?:\s*:[^=;]+)?\s*=\s*(?:[A-Za-z_]\w*::)*(?:CompareObjectHandles|GetFileType|GetHandleInformation|GetStdHandle|SetHandleInformation)\b/gu,
  ),
];
const keyAgentBootstrapGetStdHandleCalls = rustCallSites(
  keyAgentChildBootstrapProduction,
  "GetStdHandle",
);
const keyAgentBootstrapCompareObjectCalls = rustCallSites(
  keyAgentChildBootstrapProduction,
  "CompareObjectHandles",
);
const keyAgentBootstrapGetFileTypeCalls = rustCallSites(
  keyAgentChildBootstrapProduction,
  "GetFileType",
);
const keyAgentBootstrapGetHandleInformationCalls = rustCallSites(
  keyAgentChildBootstrapProduction,
  "GetHandleInformation",
);
const keyAgentBootstrapSetHandleInformationCalls = rustCallSites(
  keyAgentChildBootstrapProduction,
  "SetHandleInformation",
);
const sealedKeyAgentStdioTraitImplementations = [
  ...rustLexicalCode(keyAgentChildBootstrapProduction).matchAll(
    /\bimpl(?:\s*<[^>{}]*>)?\s+(?<trait>[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*(?:<[^>{}]*>)?)\s+for\s+SealedKeyAgentStdio\s*\{/gu,
  ),
].map((match) => normalizeRustFragment(match.groups.trait));
requireInvariant(
  platformWindowsLib.includes("#[cfg(windows)]\nmod key_agent_child_bootstrap;") &&
    platformWindowsLib.includes(
      "KeyAgentChildBootstrapError, serve_inherited_key_agent_storage_startup,",
    ) &&
    keyAgentBootstrapExportMembers ===
      "KeyAgentChildBootstrapError, serve_inherited_key_agent_storage_startup," &&
    JSON.stringify(keyAgentBootstrapPublicFunctionNames) ===
      JSON.stringify(["serve_inherited_key_agent_storage_startup"]) &&
    /^pub fn serve_inherited_key_agent_storage_startup\s*\(\s*\)\s*->\s*Result<\s*\(\s*\)\s*,\s*KeyAgentChildBootstrapError\s*>\s*\{/u.test(
      rustLexicalCode(serveInheritedKeyAgentStorageStartup),
    ) &&
    /^fn seal_inherited_key_agent_stdio\s*\(\s*\)\s*->\s*Result<\s*SealedKeyAgentStdio\s*,\s*KeyAgentChildBootstrapError\s*>\s*\{/u.test(
      rustLexicalCode(sealInheritedKeyAgentStdio),
    ) &&
    JSON.stringify(
      keyAgentBootstrapGetStdHandleCalls.map((call) => call.arguments),
    ) ===
      JSON.stringify([
        ["STD_INPUT_HANDLE"],
        ["STD_OUTPUT_HANDLE"],
        ["STD_ERROR_HANDLE"],
      ]) &&
    rustCallSites(sealInheritedKeyAgentStdio, "seal_exact_standard_handle_set")
      .length === 1 &&
    JSON.stringify(
      rustCallSites(
        sealInheritedKeyAgentStdio,
        "seal_exact_standard_handle_set",
      )[0]?.arguments,
    ) === JSON.stringify(["[stdin, stdout, stderr]"]) &&
    keyAgentBootstrapApiAliases.length === 0,
  "the Key Agent child bootstrap must expose only one safe zero-argument storage-startup service while its private seal obtains stdin/stdout/stderr exactly once without API aliases",
);

const keyAgentStartupRequestFrameDefinition = rustLexicalItemBlock(
  keyAgentStartupRelease,
  /(?:^|\n)\s*pub\(crate\)\s+struct\s+KeyAgentStartupRequestFrame\s*\{/u,
);
const keyAgentStartupResponseFrameDefinition = rustLexicalItemBlock(
  keyAgentStartupRelease,
  /(?:^|\n)\s*pub\(crate\)\s+struct\s+KeyAgentStartupResponseFrame\s*\{/u,
);
const keyAgentStartupRequestDefinition = rustLexicalItemBlock(
  keyAgentStartupRelease,
  /(?:^|\n)\s*pub\(crate\)\s+struct\s+KeyAgentStartupRequest\s*\{/u,
);
const keyAgentStartupResponseDefinition = rustLexicalItemBlock(
  keyAgentStartupRelease,
  /(?:^|\n)\s*pub\(crate\)\s+struct\s+KeyAgentStartupResponse\s*\{/u,
);
const keyAgentStartupRequestEncode = rustFunctionBlock(
  keyAgentStartupRelease,
  "encode",
);
const keyAgentStartupRequestDecode = rustFunctionBlock(
  keyAgentStartupRelease,
  "decode",
);
const keyAgentStartupResponseImpl = rustLexicalItemBlock(
  keyAgentStartupRelease,
  /(?:^|\n)\s*impl\s+KeyAgentStartupResponse\s*\{/u,
);
const keyAgentStartupResponseEncode = rustFunctionBlock(
  keyAgentStartupResponseImpl,
  "encode",
);
const keyAgentStartupResponseDecode = rustFunctionBlock(
  keyAgentStartupResponseImpl,
  "decode",
);
const keyAgentStorageStartupProductionSurface = [
  keyAgentWindowsMain,
  keyAgentStartupRelease,
  keyAgentChildBootstrapProduction,
  keyAgentStorage,
  keyAgentSupervisor,
  keyAgentPipeProduction,
  keyAgentActivationRelease,
  windowsStorageRelease,
  windowsStorageFacadeRelease,
].join("\n");
requireInvariant(
  platformWindowsLib.includes("#[cfg(windows)]\nmod key_agent_startup;") &&
    !/pub(?:\([^)]*\))?\s+mod\s+key_agent_startup\b/u.test(
      rustLexicalCode(platformWindowsLib),
    ) &&
    !/pub(?:\([^)]*\))?\s+use\s+[^;]*\bkey_agent_startup\b/u.test(
      rustLexicalCode(platformWindowsLib),
    ) &&
    keyAgentStartupRelease.includes(
      "pub(crate) const KEY_AGENT_STARTUP_REQUEST_BYTES: usize = 188;",
    ) &&
    keyAgentStartupRelease.includes(
      "pub(crate) const KEY_AGENT_STARTUP_RESPONSE_BYTES: usize = 88;",
    ) &&
    keyAgentStartupRelease.includes('const REQUEST_MAGIC: [u8; 8] = *b"YWKSREQ1";') &&
    keyAgentStartupRelease.includes('const RESPONSE_MAGIC: [u8; 8] = *b"YWKSRES1";') &&
    normalizeRustFragment(rustLexicalCode(keyAgentStartupRequestFrameDefinition)) ===
      "pub(crate) struct KeyAgentStartupRequestFrame { bytes: Zeroizing<[u8; KEY_AGENT_STARTUP_REQUEST_BYTES]>, }" &&
    normalizeRustFragment(rustLexicalCode(keyAgentStartupResponseFrameDefinition)) ===
      "pub(crate) struct KeyAgentStartupResponseFrame { bytes: Zeroizing<[u8; KEY_AGENT_STARTUP_RESPONSE_BYTES]>, }" &&
    normalizeRustFragment(rustLexicalCode(keyAgentStartupRequestDefinition)) ===
      "pub(crate) struct KeyAgentStartupRequest { nonce: Zeroizing<[u8; NONCE_BYTES]>, expected_process_id: u32, expected_creation_time: u64, storage_root_identity: KeyAgentStorageRootIdentity, storage_leaf: String, }" &&
    normalizeRustFragment(rustLexicalCode(keyAgentStartupResponseDefinition)) ===
      "pub(crate) struct KeyAgentStartupResponse { echoed_nonce: Zeroizing<[u8; NONCE_BYTES]>, actual_process_id: u32, actual_creation_time: u64, storage_root_identity: KeyAgentStorageRootIdentity, }" &&
    keyAgentStartupRequestEncode.includes("FrameBuilder::<KEY_AGENT_STARTUP_REQUEST_BYTES>::new()") &&
    keyAgentStartupRequestEncode.includes(".push(&188_u32.to_be_bytes())") &&
    keyAgentStartupRequestDecode.includes(
      "frame.len() != KEY_AGENT_STARTUP_REQUEST_BYTES",
    ) &&
    keyAgentStartupRequestDecode.includes(
      "read_u32(frame, REQUEST_LENGTH_OFFSET) != Some(188)",
    ) &&
    keyAgentStartupResponseEncode.includes(
      "FrameBuilder::<KEY_AGENT_STARTUP_RESPONSE_BYTES>::new()",
    ) &&
    keyAgentStartupResponseEncode.includes(".push(&88_u32.to_be_bytes())") &&
    keyAgentStartupResponseDecode.includes(
      "frame.len() != KEY_AGENT_STARTUP_RESPONSE_BYTES",
    ) &&
    keyAgentStartupResponseDecode.includes(
      "read_u32(frame, RESPONSE_LENGTH_OFFSET) != Some(88)",
    ) &&
    !/\b(?:Path|PathBuf|LOCALAPPDATA|LocalAppData|local_app_data|storage_path|path_hash|path_digest|storage_hash)\b/u.test(
      rustLexicalCode(keyAgentStartupRelease),
    ),
  "the private Key Agent startup codec must retain exact zeroizing 188/88-byte process-and-full-storage-identity frames without serializing a LOCALAPPDATA path or hash",
);
requireInvariant(
  !keyAgentStorageStartupProductionSurface.includes("YWKSDIAG") &&
    !/\blast_storage\w*\b/iu.test(
      rustLexicalCode(keyAgentStorageStartupProductionSurface),
    ),
  "the Key Agent storage-startup slice must not regain YWKSDIAG or last_storage diagnostic state",
);

const keyAgentChildStartupOrder = [
  "let sealed_stdio = seal_inherited_key_agent_stdio()?",
  "let mut request_frame = Zeroizing::new([0_u8; KEY_AGENT_STARTUP_REQUEST_BYTES])",
  "read_exact_synchronous(sealed_stdio.stdin, &mut request_frame)?",
  "reject_buffered_key_agent_startup_bytes(stdin)",
  "KeyAgentStartupRequest::decode(request_frame.as_slice())",
  "let actual_process_id = current_process_id()?",
  "let actual_creation_time = current_process_creation_time()?",
  "open_fixed_key_agent_storage_root_for_child()",
  "let actual_storage_identity = child_root.identity()",
  "request.storage_root_identity() != actual_storage_identity",
  ".revalidate()",
  "let generation_store_bindings =",
  ".into_fixed_generation_store_bindings()",
  "KeyAgentStartupResponse::from_validated_request(",
  "let response_frame = response.encode()",
  "write_exact_synchronous(sealed_stdio.stdout, response_frame.as_bytes())?",
  "wait_for_parent_disconnect(&sealed_stdio, &generation_store_bindings)",
].map((marker) => serveInheritedKeyAgentStorageStartup.indexOf(marker));
const readExactKeyAgentStartupRequest = rustFunctionBlock(
  keyAgentChildBootstrapProduction,
  "read_exact_synchronous",
);
const writeExactKeyAgentStartupResponse = rustFunctionBlock(
  keyAgentChildBootstrapProduction,
  "write_exact_synchronous",
);
const waitForKeyAgentParentDisconnect = rustFunctionBlock(
  keyAgentChildBootstrapProduction,
  "wait_for_parent_disconnect",
);
requireInvariant(
  keyAgentChildStartupOrder.every((position) => position !== -1) &&
    keyAgentChildStartupOrder
      .slice(1)
      .every(
        (position, index) => position > keyAgentChildStartupOrder[index],
      ) &&
    /fn\s+read_exact_synchronous\s*\([\s\S]*bytes:\s*&mut\s*\[u8;\s*KEY_AGENT_STARTUP_REQUEST_BYTES\]/u.test(
      readExactKeyAgentStartupRequest,
    ) &&
    /fn\s+write_exact_synchronous\s*\([\s\S]*bytes:\s*&\[u8;\s*KEY_AGENT_STARTUP_RESPONSE_BYTES\]/u.test(
      writeExactKeyAgentStartupResponse,
    ) &&
    waitForKeyAgentParentDisconnect.includes(
      "sealed_stdio: &SealedKeyAgentStdio",
    ) &&
    waitForKeyAgentParentDisconnect.includes(
      "_generation_store_bindings: &FixedKeyAgentGenerationStoreBindings",
    ) &&
    waitForKeyAgentParentDisconnect.includes(
      "reject_nonzero_post_startup_bytes(transferred)?",
    ),
  "the sole child bootstrap service must seal first, exchange exactly one 188/88 frame pair, prove the child-opened full storage identity, consume it into fixed generation-store bindings, and retain both child capabilities until disconnect",
);

const keyAgentBootstrapSameObjectCalls = rustCallSites(
  sealExactKeyAgentStandardHandleSet,
  "same_object",
);
const keyAgentBootstrapFileTypeCalls = rustCallSites(
  sealExactKeyAgentStandardHandleSet,
  "file_type",
);
const keyAgentBootstrapFlagCalls = rustCallSites(
  sealExactKeyAgentStandardHandleSet,
  "handle_flags",
);
const keyAgentBootstrapClearCalls = rustCallSites(
  sealExactKeyAgentStandardHandleSet,
  "SetHandleInformation",
);
const keyAgentBootstrapPreFlagCheck = sealExactKeyAgentStandardHandleSet.indexOf(
  "handle_flags(*handle) != Ok(HANDLE_FLAG_INHERIT.0)",
);
const keyAgentBootstrapClearLoop = sealExactKeyAgentStandardHandleSet.indexOf(
  "for handle in handles",
);
const keyAgentBootstrapPostFlagCheck = sealExactKeyAgentStandardHandleSet.indexOf(
  "handle_flags(*handle) == Ok(0)",
);
const keyAgentBootstrapValidationPositions = [
  sealExactKeyAgentStandardHandleSet.indexOf(
    "handles.iter().copied().any(invalid)",
  ),
  ...keyAgentBootstrapSameObjectCalls.map((call) => call.index),
  ...keyAgentBootstrapFileTypeCalls.map((call) => call.index),
  keyAgentBootstrapPreFlagCheck,
];
requireInvariant(
  sealExactKeyAgentStandardHandleSet.includes(
    "handles.iter().copied().any(invalid)",
  ) &&
    normalizeRustFragment(rustLexicalCode(keyAgentBootstrapInvalidHandle)) ===
      "fn invalid(handle: HANDLE) -> bool { handle.is_invalid() || handle == INVALID_HANDLE_VALUE }" &&
    JSON.stringify(
      keyAgentBootstrapSameObjectCalls.map((call) => call.arguments),
    ) ===
      JSON.stringify([
        ["stdin", "stdout"],
        ["stdin", "stderr"],
        ["stdout", "stderr"],
      ]) &&
    JSON.stringify(keyAgentBootstrapFileTypeCalls.map((call) => call.arguments)) ===
      JSON.stringify([["stdin"], ["stdout"], ["stderr"]]) &&
    sealExactKeyAgentStandardHandleSet.includes(
      "file_type(stdin) != FILE_TYPE_PIPE",
    ) &&
    sealExactKeyAgentStandardHandleSet.includes(
      "file_type(stdout) != FILE_TYPE_PIPE",
    ) &&
    sealExactKeyAgentStandardHandleSet.includes(
      "file_type(stderr) != FILE_TYPE_CHAR",
    ) &&
    keyAgentBootstrapCompareObjectCalls.length === 1 &&
    JSON.stringify(keyAgentBootstrapCompareObjectCalls[0]?.arguments) ===
      JSON.stringify(["first", "second"]) &&
    keyAgentBootstrapSameObject.includes(
      "unsafe { CompareObjectHandles(first, second) }.as_bool()",
    ) &&
    keyAgentBootstrapGetFileTypeCalls.length === 1 &&
    JSON.stringify(keyAgentBootstrapGetFileTypeCalls[0]?.arguments) ===
      JSON.stringify(["handle"]) &&
    keyAgentBootstrapGetHandleInformationCalls.length === 1 &&
    JSON.stringify(keyAgentBootstrapGetHandleInformationCalls[0]?.arguments) ===
      JSON.stringify(["handle", "&raw mut flags"]) &&
    keyAgentBootstrapHandleFlags.includes("let mut flags = u32::MAX") &&
    keyAgentBootstrapHandleFlags.includes("Ok(flags)"),
  "the Key Agent child bootstrap must reject aliases pairwise and require exact PIPE/PIPE/CHAR kernel types using direct reviewed queries",
);
requireInvariant(
  keyAgentBootstrapFlagCalls.length === 2 &&
    keyAgentBootstrapFlagCalls.every(
      (call) => JSON.stringify(call.arguments) === JSON.stringify(["*handle"]),
    ) &&
    keyAgentBootstrapClearCalls.length === 1 &&
    keyAgentBootstrapSetHandleInformationCalls.length === 1 &&
    JSON.stringify(keyAgentBootstrapClearCalls[0]?.arguments) ===
      JSON.stringify(["handle", "HANDLE_FLAG_INHERIT.0", "HANDLE_FLAGS(0)"]) &&
    keyAgentBootstrapValidationPositions.every((position) => position !== -1) &&
    keyAgentBootstrapValidationPositions.every(
      (position) => position < keyAgentBootstrapClearCalls[0].index,
    ) &&
    keyAgentBootstrapClearLoop !== -1 &&
    keyAgentBootstrapClearLoop < keyAgentBootstrapClearCalls[0].index &&
    keyAgentBootstrapPostFlagCheck > keyAgentBootstrapClearCalls[0].index &&
    sealExactKeyAgentStandardHandleSet.includes("let mut clear_failed = false") &&
    sealExactKeyAgentStandardHandleSet.includes("clear_failed = true") &&
    sealExactKeyAgentStandardHandleSet.includes(
      "if clear_failed || !exact_zero_flags",
    ),
  "all three Key Agent stdio handles must have exact INHERIT flags before one loop clear call and exact zero flags afterward, while attempting every clear",
);
requireInvariant(
  normalizeRustFragment(rustLexicalCode(sealedKeyAgentStdioDefinition)) ===
    "struct SealedKeyAgentStdio { stdin: HANDLE, stdout: HANDLE, _not_send_or_sync: PhantomData<Rc<()>>, }" &&
    keyAgentChildBootstrapProduction.includes(
      '#[must_use = "the Key Agent must retain its sealed stdio proof through startup"]',
    ) &&
    !/#\s*\[\s*derive\s*\([^\]]*\b(?:Clone|Copy)\b[^\]]*\)\s*\]\s*(?:#\s*\[[^\]]*\]\s*)*struct\s+SealedKeyAgentStdio/u.test(
      keyAgentChildBootstrapProduction,
    ) &&
    !/\b(?:unsafe\s+)?impl(?:\s*<[^>{}]*>)?\s+(?:Clone|Copy|Send|Sync)\s+for\s+SealedKeyAgentStdio\b/u.test(
      rustLexicalCode(keyAgentChildBootstrapProduction),
    ) &&
    !/\bimpl\s+SealedKeyAgentStdio\s*\{/u.test(
      rustLexicalCode(keyAgentChildBootstrapProduction),
    ) &&
    JSON.stringify(sealedKeyAgentStdioTraitImplementations) ===
      JSON.stringify(["fmt::Debug"]) &&
    !/\bimpl\s+(?:AsHandle|AsRawHandle|IntoRawHandle)\s+for\s+SealedKeyAgentStdio\b/u.test(
      rustLexicalCode(keyAgentChildBootstrapProduction),
    ),
  "the private SealedKeyAgentStdio must retain only the request/response peers and expose no raw, clone, or thread-transfer capability",
);

const keyAgentBootstrapSubprocessTest = rustFunctionBlock(
  keyAgentChildBootstrapSource,
  "inherited_stdio_is_sealed_in_an_isolated_child_before_descendant_creation",
);
const keyAgentBootstrapChildFixture = rustFunctionBlock(
  keyAgentChildBootstrapSource,
  "inherited_stdio_child_fixture",
);
const keyAgentBootstrapChildFixtureCode = rustLexicalCode(
  keyAgentBootstrapChildFixture,
);
const keyAgentBootstrapGrandchildFixture = rustFunctionBlock(
  keyAgentChildBootstrapSource,
  "deinheritance_grandchild_fixture",
);
const keyAgentBootstrapGrandchildImplementation = rustLexicalItemBlock(
  keyAgentChildBootstrapSource,
  /(?:^|\n)\s*impl\s+BroadInheritanceGrandchild\s*\{/u,
);
const keyAgentBootstrapGrandchildSpawn = rustFunctionBlock(
  keyAgentChildBootstrapSource,
  "spawn",
);
const keyAgentBootstrapGrandchildIsAlive = rustFunctionBlock(
  keyAgentBootstrapGrandchildImplementation,
  "is_alive",
);
const keyAgentBootstrapGrandchildIdentity = rustFunctionBlock(
  keyAgentChildBootstrapSource,
  "names_same_object",
);
const keyAgentBootstrapGrandchildTermination = rustFunctionBlock(
  keyAgentChildBootstrapSource,
  "terminate_and_reap",
);
const keyAgentBootstrapCurrentStandardHandles = rustFunctionBlock(
  keyAgentChildBootstrapSource,
  "current_standard_handles",
);
const keyAgentBootstrapGrandchildDefinition = rustLexicalItemBlock(
  keyAgentChildBootstrapSource,
  /(?:^|\n)\s*struct\s+BroadInheritanceGrandchild\s*\{/u,
);
const keyAgentBootstrapGrandchildDrop = rustLexicalItemBlock(
  keyAgentChildBootstrapSource,
  /(?:^|\n)\s*impl\s+Drop\s+for\s+BroadInheritanceGrandchild\s*\{/u,
);
const keyAgentBootstrapGrandchildDuplicate = rustCallSites(
  keyAgentBootstrapGrandchildIdentity,
  "DuplicateHandle",
);
const keyAgentBootstrapGrandchildCreate = rustCallSites(
  keyAgentBootstrapGrandchildSpawn,
  "CreateProcessW",
);
const keyAgentBootstrapSentinelFlagChanges = rustCallSites(
  keyAgentBootstrapChildFixture,
  "SetHandleInformation",
);
const keyAgentBootstrapSentinelCreation = rustCallSites(
  keyAgentBootstrapChildFixture,
  "CreateEventW",
);
const keyAgentBootstrapBroadSpawnCalls = rustCallSites(
  keyAgentBootstrapChildFixture,
  "BroadInheritanceGrandchild::spawn",
);
const keyAgentBootstrapChildIdentityCalls = rustCallSites(
  keyAgentBootstrapChildFixture,
  "names_same_object",
);
const keyAgentBootstrapChildAliveCalls = rustCallSites(
  keyAgentBootstrapChildFixture,
  "is_alive",
);
const keyAgentBootstrapChildTerminationCalls = rustCallSites(
  keyAgentBootstrapChildFixture,
  "terminate_and_reap",
);
const keyAgentBootstrapTestGetStdHandleCalls = rustCallSites(
  keyAgentBootstrapCurrentStandardHandles,
  "GetStdHandle",
);
const keyAgentBootstrapTerminationOrder = [
  "WaitForSingleObject(process, 0)",
  "TerminateProcess(process, 1)",
  "WaitForSingleObject(process, 5_000)",
].map((marker) => keyAgentBootstrapGrandchildTermination.indexOf(marker));
const keyAgentBootstrapSentinelZeroAssertion =
  keyAgentBootstrapChildFixtureCode.indexOf(
    "assert_eq!(handle_flags(sentinel_handle)?, 0)",
  );
const keyAgentBootstrapAliveAssertion = keyAgentBootstrapChildFixtureCode.indexOf(
  "assert!(grandchild.is_alive())",
);
const keyAgentBootstrapExactTermination = keyAgentBootstrapChildFixtureCode.indexOf(
  "grandchild.terminate_and_reap()?;",
);
const keyAgentChildBootstrapCode = rustLexicalCode(
  keyAgentChildBootstrapSource,
);
const keyAgentBootstrapDriverOrder = [
  "acquire_inheritable_handle_launch(deadline())",
  "let mut command = Command::new(executable)",
  ".env(CHILD_FIXTURE_ENV, \"1\")",
  "let child = command.spawn()?",
  "drop(command)",
  "drop(flight)",
].map((marker) => keyAgentBootstrapSubprocessTest.indexOf(marker));
const keyAgentBootstrapChildOrder = [
  keyAgentBootstrapChildFixtureCode.indexOf(
    "let original_handles = current_standard_handles()?",
  ),
  keyAgentBootstrapChildFixtureCode.indexOf(
    "let sealed = seal_inherited_key_agent_stdio()?",
  ),
  keyAgentBootstrapChildFixtureCode.indexOf(
    "assert_eq!(handle_flags(handle)?, 0)",
  ),
  keyAgentBootstrapChildFixtureCode.indexOf(
    "acquire_inheritable_handle_launch(deadline())",
  ),
  keyAgentBootstrapSentinelCreation[0]?.index ?? -1,
  keyAgentBootstrapSentinelFlagChanges[0]?.index ?? -1,
  keyAgentBootstrapBroadSpawnCalls[0]?.index ?? -1,
  keyAgentBootstrapSentinelFlagChanges[1]?.index ?? -1,
  keyAgentBootstrapSentinelZeroAssertion,
  keyAgentBootstrapChildFixtureCode.indexOf("drop(flight)"),
  keyAgentBootstrapAliveAssertion,
  keyAgentBootstrapChildIdentityCalls[0]?.index ?? -1,
  keyAgentBootstrapChildFixtureCode.indexOf("for original in original_handles"),
  keyAgentBootstrapChildIdentityCalls[1]?.index ?? -1,
  keyAgentBootstrapExactTermination,
  keyAgentBootstrapChildFixtureCode.indexOf(
    "std::io::stdout().write_all(ACKNOWLEDGEMENT)?",
  ),
  keyAgentBootstrapChildFixtureCode.indexOf("drop(sealed)"),
];
requireInvariant(
  /#\s*\[\s*test\s*\]\s*fn inherited_stdio_is_sealed_in_an_isolated_child_before_descendant_creation\b/u.test(
    keyAgentChildBootstrapCode,
  ) &&
    /#\s*\[\s*test\s*\]\s*#\s*\[\s*ignore\s*=[^\]]*\]\s*fn inherited_stdio_child_fixture\b/u.test(
      keyAgentChildBootstrapCode,
    ) &&
    /#\s*\[\s*test\s*\]\s*#\s*\[\s*ignore\s*=[^\]]*\]\s*fn deinheritance_grandchild_fixture\b/u.test(
      keyAgentChildBootstrapCode,
    ) &&
    keyAgentChildBootstrapSource.includes(
      '#[ignore = "launched only by the isolated Key Agent stdio driver"]',
    ) &&
    keyAgentChildBootstrapSource.includes(
      '#[ignore = "launched only as the Key Agent stdio grandchild probe"]',
    ) &&
    rustCallSites(keyAgentChildBootstrapSource, "Command::new").length === 1 &&
    rustCallSites(keyAgentChildBootstrapProduction, "CreateProcessW").length === 0 &&
    rustCallSites(keyAgentChildBootstrapSource, "CreateProcessW").length === 1 &&
    rustCallSites(keyAgentChildBootstrapSource, "GetStdHandle").length === 6 &&
    JSON.stringify(
      keyAgentBootstrapTestGetStdHandleCalls.map((call) => call.arguments),
    ) ===
      JSON.stringify([
        ["super::STD_INPUT_HANDLE"],
        ["super::STD_OUTPUT_HANDLE"],
        ["super::STD_ERROR_HANDLE"],
      ]) &&
    keyAgentBootstrapCurrentStandardHandles.includes(
      "Ok([stdin, stdout, stderr])",
    ) &&
    keyAgentBootstrapDriverOrder.every((position) => position !== -1) &&
    keyAgentBootstrapDriverOrder
      .slice(1)
      .every((position, index) => position > keyAgentBootstrapDriverOrder[index]) &&
    keyAgentBootstrapChildOrder.every((position) => position !== -1) &&
    keyAgentBootstrapChildOrder
      .slice(1)
      .every((position, index) => position > keyAgentBootstrapChildOrder[index]) &&
    keyAgentBootstrapSubprocessTest.includes(".stdin(Stdio::piped())") &&
    keyAgentBootstrapSubprocessTest.includes(".stdout(Stdio::piped())") &&
    keyAgentBootstrapSubprocessTest.includes(".stderr(Stdio::null())") &&
    keyAgentBootstrapSubprocessTest.includes("child_input.write_all(CHALLENGE)?") &&
    keyAgentBootstrapSubprocessTest.includes("window == ACKNOWLEDGEMENT") &&
    keyAgentBootstrapGrandchildFixture.includes(
      "std::thread::sleep(Duration::from_secs(15))",
    ) &&
    keyAgentBootstrapGrandchildCreate.length === 1 &&
    JSON.stringify(keyAgentBootstrapGrandchildCreate[0]?.arguments) ===
      JSON.stringify([
        "PCWSTR(application.as_ptr())",
        "Some(PWSTR(command.as_mut_ptr()))",
        "None",
        "None",
        "true",
        "CREATE_NO_WINDOW",
        "None",
        "PCWSTR::null()",
        "&raw const startup",
        "&raw mut information",
      ]) &&
    keyAgentBootstrapGrandchildSpawn.includes("let startup = STARTUPINFOW") &&
    !keyAgentBootstrapGrandchildSpawn.includes("STARTUPINFOEXW") &&
    !keyAgentBootstrapGrandchildSpawn.includes("PROC_THREAD_ATTRIBUTE_HANDLE_LIST") &&
    !keyAgentBootstrapGrandchildSpawn.includes("EXTENDED_STARTUPINFO_PRESENT") &&
    JSON.stringify(
      keyAgentBootstrapSentinelFlagChanges.map((call) => call.arguments),
    ) ===
      JSON.stringify([
        ["sentinel_handle", "HANDLE_FLAG_INHERIT.0", "HANDLE_FLAG_INHERIT"],
        ["sentinel_handle", "HANDLE_FLAG_INHERIT.0", "HANDLE_FLAGS(0)"],
      ]) &&
    keyAgentBootstrapSentinelCreation.length === 1 &&
    JSON.stringify(keyAgentBootstrapSentinelCreation[0]?.arguments) ===
      JSON.stringify(["None", "true", "false", "None"]) &&
    keyAgentBootstrapChildFixtureCode.includes(
      "OwnedHandle::from_raw_handle(sentinel.0)",
    ) &&
    keyAgentBootstrapBroadSpawnCalls.length === 1 &&
    JSON.stringify(keyAgentBootstrapBroadSpawnCalls[0]?.arguments) ===
      JSON.stringify(["&executable"]) &&
    keyAgentBootstrapChildAliveCalls.length === 1 &&
    keyAgentBootstrapChildAliveCalls[0]?.arguments.length === 0 &&
    (rustLexicalCode(keyAgentBootstrapGrandchildImplementation).match(
      /\bfn\s+is_alive\b/gu,
    ) ?? []).length === 1 &&
    normalizeRustFragment(rustLexicalCode(keyAgentBootstrapGrandchildIsAlive)) ===
      "fn is_alive(&self) -> bool { (unsafe { WaitForSingleObject(HANDLE(self.process.as_raw_handle()), 0) }) == WAIT_TIMEOUT }" &&
    keyAgentBootstrapAliveAssertion !== -1 &&
    keyAgentBootstrapSentinelZeroAssertion >
      keyAgentBootstrapSentinelFlagChanges[1].index &&
    keyAgentBootstrapSentinelZeroAssertion <
      keyAgentBootstrapChildFixtureCode.indexOf("drop(flight)") &&
    JSON.stringify(
      keyAgentBootstrapChildIdentityCalls.map((call) => call.arguments),
    ) ===
      JSON.stringify([
        ["sentinel_handle", "sentinel_handle"],
        ["original", "original"],
      ]) &&
    keyAgentBootstrapChildTerminationCalls.length === 1 &&
    keyAgentBootstrapChildTerminationCalls[0]?.arguments.length === 0 &&
    keyAgentBootstrapExactTermination !== -1 &&
    keyAgentBootstrapChildFixtureCode.includes(
      "assert!(grandchild.names_same_object(sentinel_handle, sentinel_handle)?)",
    ) &&
    keyAgentBootstrapChildFixtureCode.includes(
      "assert!(!grandchild.names_same_object(original, original)?)",
    ) &&
    keyAgentBootstrapGrandchildDuplicate.length === 1 &&
    JSON.stringify(keyAgentBootstrapGrandchildDuplicate[0]?.arguments) ===
      JSON.stringify([
        "HANDLE(self.process.as_raw_handle())",
        "candidate",
        "GetCurrentProcess()",
        "&raw mut duplicate",
        "0",
        "false",
        "DUPLICATE_SAME_ACCESS",
      ]) &&
    keyAgentBootstrapGrandchildIdentity.includes(
      "OwnedHandle::from_raw_handle(duplicate.0.cast::<c_void>())",
    ) &&
    keyAgentBootstrapGrandchildIdentity.includes(
      "same_object(HANDLE(duplicate.as_raw_handle()), expected)",
    ) &&
    keyAgentBootstrapGrandchildDefinition.includes("process: OwnedHandle") &&
    keyAgentBootstrapGrandchildDrop.includes(
      "let _ = self.terminate_and_reap()",
    ) &&
    keyAgentBootstrapTerminationOrder.every((position) => position !== -1) &&
    keyAgentBootstrapTerminationOrder
      .slice(1)
      .every(
        (position, index) => position > keyAgentBootstrapTerminationOrder[index],
      ) &&
    keyAgentBootstrapGrandchildTermination.includes(
      "let state = unsafe { WaitForSingleObject(process, 0) }",
    ) &&
    keyAgentBootstrapGrandchildTermination.includes(
      "TerminateProcess(process, 1).map_err(|_| KeyAgentChildBootstrapError)?",
    ) &&
    keyAgentBootstrapGrandchildTermination.includes(
      "WaitForSingleObject(process, 5_000) != WAIT_OBJECT_0",
    ),
  "the Key Agent stdio boundary must retain an actual child-and-grandchild test that proves the original three kernel objects are not inherited",
);

const productionProcessCreationSites = workspaceRustProductionFiles.flatMap(
  (file) =>
    [
      ...file.source.matchAll(
        /\b(CreateProcess(?:AsUser|WithToken|WithLogon)?[WA]?|ShellExecute(?:Ex)?[WA]?|WinExec)\s*\(|\b((?:std::process::)?Command::new)\s*\(/gu,
      ),
    ].map((match) => ({
      path: file.path,
      api: match[1] ?? match[2],
    })),
);
requireInvariant(
  JSON.stringify(productionProcessCreationSites) ===
    JSON.stringify([
      {
        path: "crates/native-host/src/main.rs",
        api: "Command::new",
      },
      {
        path: "crates/platform-windows/src/inheritable_handle_launch.rs",
        api: "CreateProcessW",
      },
    ]),
  "workspace production process creation must remain confined to the sealed Windows coordinator and the exact debug-only Native Host contract hook",
);
requireInvariant(
  productionProcessCreationSites.every(
    (site) => !site.path.startsWith("crates/key-agent/src/"),
  ) &&
    !/\b(?:CreateProcess(?:AsUser|WithToken|WithLogon)?[WA]?|ShellExecute(?:Ex)?[WA]?|WinExec)\s*\(|\b(?:std::process::)?Command::new\s*\(/u.test(
      rustLexicalCode(keyAgentChildBootstrapProduction),
    ),
  "the production Key Agent binary and child bootstrap must not gain descendant process creation",
);
const aliasedProcessCreationApis = workspaceRustProductionFiles.flatMap((file) =>
  [
    ...file.source.matchAll(
      /\b(?:CreateProcess(?:AsUser|WithToken|WithLogon)?[WA]?|ShellExecute(?:Ex)?[WA]?|WinExec|Command|std::process)\s+as\s+\w+/gu,
    ),
  ].map((match) => ({ path: file.path, alias: match[0] })),
);
requireInvariant(
  aliasedProcessCreationApis.length === 0,
  "production process-creation APIs and std::process must not be aliased around the exact callsite inventory",
);
const duplicateHandleInventory = platformWindowsProductionFiles.flatMap((file) =>
  rustCallSites(file.source, "DuplicateHandle").map((call) => ({
    path: file.path,
    sourceProcess: call.arguments[0],
    sourceHandle: call.arguments[1],
    targetProcess: call.arguments[2],
    targetHandle: call.arguments[3],
    desiredAccess: call.arguments[4],
    inheritable: call.arguments[5],
    options: call.arguments[6],
  })),
);
const setHandleInformationInventory = platformWindowsProductionFiles.flatMap(
  (file) =>
    rustCallSites(file.source, "SetHandleInformation").map((call) => ({
      path: file.path,
      handle: call.arguments[0],
      mask: call.arguments[1],
      flags: call.arguments[2],
    })),
);
const securityAttributesInventory = platformWindowsProductionFiles.flatMap(
  (file) =>
    rustStructLiteralSites(file.source, "SECURITY_ATTRIBUTES").map((literal) => ({
      path: file.path,
      inherit:
        /\bbInheritHandle\s*:\s*(?<value>[^,}\r\n]+)/u.exec(
          rustLexicalCode(literal.source),
        )?.groups?.value.trim() ?? "",
    })),
);
const aliasedInheritableHandleApis = platformWindowsProductionFiles.flatMap(
  (file) => {
    const sourceCode = rustLexicalCode(file.source);
    return [
      ...sourceCode.matchAll(
        /\b(?:DuplicateHandle|SetHandleInformation|SECURITY_ATTRIBUTES)\s+as\s+(?:_|[A-Za-z_]\w*)|\btype\s+[A-Za-z_]\w*\s*=\s*(?:[A-Za-z_]\w*::)*SECURITY_ATTRIBUTES\b|\b(?:let|const|static)\s+(?:mut\s+)?[A-Za-z_]\w*(?:\s*:[^=;]+)?\s*=\s*(?:[A-Za-z_]\w*::)*(?:DuplicateHandle|SetHandleInformation)\b/gu,
      ),
    ].map((match) => ({ path: file.path, alias: match[0] }));
  },
);
const alternativeSecurityAttributesInitialization =
  platformWindowsProductionFiles.flatMap((file) => {
    const sourceCode = rustLexicalCode(file.source);
    return [
      ...sourceCode.matchAll(
        /\bSECURITY_ATTRIBUTES\s*::|\b(?:zeroed|uninit)(?:\s*::\s*<[^>]*>)?\s*\([^)]*SECURITY_ATTRIBUTES|\.bInheritHandle\s*=/gu,
      ),
    ].map((match) => ({ path: file.path, initialization: match[0] }));
  });
const expectedDuplicateHandleInventory = [
  {
    path: "crates/platform-windows/src/broker_channel.rs",
    sourceProcess: "GetCurrentProcess()",
    sourceHandle: "source",
    targetProcess: "GetCurrentProcess()",
    targetHandle: "&raw mut duplicate",
    desiredAccess: "desired",
    inheritable: "false",
    options: "DUPLICATE_HANDLE_OPTIONS(0)",
  },
  {
    path: "crates/platform-windows/src/broker_supervisor.rs",
    sourceProcess: "GetCurrentProcess()",
    sourceHandle: "handle",
    targetProcess: "GetCurrentProcess()",
    targetHandle: "&raw mut duplicate",
    desiredAccess: "desired",
    inheritable: "false",
    options: "DUPLICATE_HANDLE_OPTIONS(0)",
  },
  {
    path: "crates/platform-windows/src/broker_supervisor.rs",
    sourceProcess: "GetCurrentProcess()",
    sourceHandle: "GetCurrentProcess()",
    targetProcess: "GetCurrentProcess()",
    targetHandle: "&raw mut duplicate",
    desiredAccess: "desired",
    inheritable: "true",
    options: "DUPLICATE_HANDLE_OPTIONS(0)",
  },
  {
    path: "crates/platform-windows/src/launch.rs",
    sourceProcess: "GetCurrentProcess()",
    sourceHandle: "source",
    targetProcess: "GetCurrentProcess()",
    targetHandle: "&raw mut duplicate",
    desiredAccess: "0",
    inheritable: "true",
    options: "DUPLICATE_SAME_ACCESS",
  },
  {
    path: "crates/platform-windows/src/pipe.rs",
    sourceProcess: "GetCurrentProcess()",
    sourceHandle: "source.raw()",
    targetProcess: "GetCurrentProcess()",
    targetHandle: "&raw mut duplicate",
    desiredAccess: "0",
    inheritable: "true",
    options: "DUPLICATE_SAME_ACCESS",
  },
];
const expectedSetHandleInformationInventory = [
  {
    path: "crates/platform-windows/src/broker_supervisor.rs",
    handle: "handle",
    mask: "HANDLE_FLAG_INHERIT.0",
    flags: "HANDLE_FLAGS(0)",
  },
  {
    path: "crates/platform-windows/src/broker_supervisor.rs",
    handle: "handle.raw()",
    mask: "HANDLE_FLAG_INHERIT.0",
    flags: "HANDLE_FLAG_INHERIT",
  },
  {
    path: "crates/platform-windows/src/key_agent_child_bootstrap.rs",
    handle: "handle",
    mask: "HANDLE_FLAG_INHERIT.0",
    flags: "HANDLE_FLAGS(0)",
  },
];
const expectedSecurityAttributesInventory = [
  {
    path: "crates/platform-windows/src/broker_channel.rs",
    inherit: "BOOL(0)",
  },
  {
    path: "crates/platform-windows/src/key_agent_storage.rs",
    inherit: "BOOL(0)",
  },
  {
    path: "crates/platform-windows/src/pipe.rs",
    inherit: "BOOL(0)",
  },
  {
    path: "crates/platform-windows/src/storage/sys.rs",
    inherit: "BOOL(0)",
  },
];
const coordinatorConsumers = platformWindowsProductionFiles.filter(
  (file) =>
    file.path !==
      "crates/platform-windows/src/inheritable_handle_launch.rs" &&
    file.source.includes("acquire_inheritable_handle_launch("),
).map((file) => file.path);
const coordinatorCreateConsumers = platformWindowsProductionFiles.filter(
  (file) =>
    file.path !==
      "crates/platform-windows/src/inheritable_handle_launch.rs" &&
    file.source.includes(".create_process_with_explicit_handle_list("),
).map((file) => file.path);
const coordinatorAcquireCallSites = platformWindowsProductionFiles.flatMap(
  (file) =>
    file.path === "crates/platform-windows/src/inheritable_handle_launch.rs"
      ? []
      : rustCallSites(file.source, "acquire_inheritable_handle_launch").map(
          () => file.path,
        ),
);
const coordinatorCreateCallSites = platformWindowsProductionFiles.flatMap(
  (file) =>
    file.path === "crates/platform-windows/src/inheritable_handle_launch.rs"
      ? []
      : rustCallSites(
          file.source,
          "create_process_with_explicit_handle_list",
        ).map(() => file.path),
);
const inheritableCoordinatorDefinition = rustLexicalItemBlock(
  inheritableHandleLaunch,
  /(?:^|\n)\s*struct InheritableHandleLaunchCoordinator\s*\{/u,
);
const inheritableCoordinatorImplementation = rustLexicalItemBlock(
  inheritableHandleLaunch,
  /(?:^|\n)\s*impl InheritableHandleLaunchCoordinator\s*\{/u,
);
const coordinatorAcquire = rustFunctionBlock(inheritableHandleLaunch, "acquire");
const coordinatorRelease = rustFunctionBlock(inheritableHandleLaunch, "release");
const coordinatorWaiterRegister = rustFunctionBlock(
  inheritableHandleLaunch,
  "register",
);
const inheritableFlightDefinition = rustLexicalItemBlock(
  inheritableHandleLaunch,
  /(?:^|\n)\s*pub\(crate\) struct InheritableHandleLaunchFlight<'coordinator>\s*\{/u,
);
const inheritableFlightValidation = rustFunctionBlock(
  inheritableHandleLaunch,
  "validate_create_admission",
);
const inheritableCreateProcessLeaf = rustFunctionBlock(
  inheritableHandleLaunch,
  "create_process_with_explicit_handle_list",
);
const coordinatorReleaseOrder = [
  "let wrong_thread = std::thread::current().id() != owner",
  "let missing_thread_owner = !self.clear_current_thread_owner()",
  ".active_generation",
  ".compare_exchange(generation, 0, Ordering::SeqCst, Ordering::SeqCst)",
  "if wrong_thread || missing_thread_owner || wrong_generation || panicking",
  "self.poisoned.store(true, Ordering::SeqCst)",
  "self.occupied.store(false, Ordering::SeqCst)",
].map((marker) => coordinatorRelease.indexOf(marker));
const coordinatorAcquireOrder = [
  "if self.current_thread_owns()?",
  "let mut waiter = WaiterRegistration::new(self)",
  "if self.poisoned.load(Ordering::SeqCst)",
  "if now >= deadline",
  ".compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)",
  "let generation = if let Ok(previous) =",
  ".fetch_update(Ordering::SeqCst, Ordering::SeqCst, |generation|",
  "self.active_generation.store(generation, Ordering::SeqCst)",
  "self.record_current_thread_owner()",
  "return Ok(InheritableHandleLaunchFlight",
  "waiter.register()?",
  "deadline.checked_duration_since(Instant::now())",
  "std::thread::park_timeout(remaining.min(WAIT_POLL_INTERVAL))",
].map((marker) => coordinatorAcquire.indexOf(marker));
const flightAdmissionOrder = [
  "self.coordinator.current_thread_owns().unwrap_or(false)",
  "std::thread::current().id() != self.owner || !current_thread_owns",
  "self.coordinator.poisoned.load(Ordering::SeqCst)",
  "!self.coordinator.occupied.load(Ordering::SeqCst)",
  "self.coordinator.active_generation.load(Ordering::SeqCst) != self.generation",
  "Instant::now() >= self.deadline",
].map((marker) => inheritableFlightValidation.indexOf(marker));
const expectedCoordinatorTests = [
  "local_coordinator_serializes_until_the_exact_flight_drops",
  "local_coordinator_never_overlaps_many_contenders",
  "local_coordinator_rejects_same_thread_reentrancy",
  "distinct_local_coordinators_have_independent_thread_ownership",
  "local_coordinator_rejects_an_expired_deadline_while_idle",
  "flight_rechecks_its_absolute_deadline_at_create_admission",
  "local_coordinator_bounds_concurrent_wait_by_deadline",
  "local_coordinator_permanently_poisoned_by_in_flight_unwind",
];
const coordinatorTests = [
  ...inheritableHandleLaunchSource.matchAll(
    /#\[test\]\s*fn\s+(?<name>[A-Za-z_]\w*)\s*\(/gu,
  ),
].map((match) => match.groups.name);
const restrictedLaunchLeaf = rustFunctionBlock(
  restrictedLauncherProduction,
  "launch",
);
const keyAgentCreateInner = rustFunctionBlock(keyAgentActivation, "create_inner");
const keyAgentCreateProcess = rustFunctionBlock(
  keyAgentActivation,
  "create_suspended_debuggee_process",
);
const keyAgentInstallProvenanceReleaseCode = rustLexicalCode(
  keyAgentInstallProvenanceRelease,
);
const installerJournalAuthenticationKeyBlock = rustTopLevelLexicalItemBlock(
  keyAgentInstallProvenanceRelease,
  /struct\s+InstallerJournalAuthenticationKey\s*\{/u,
);
const authenticatedKeyAgentInstallCheckpointBlock = rustTopLevelLexicalItemBlock(
  keyAgentInstallProvenanceRelease,
  /struct\s+AuthenticatedKeyAgentInstallCheckpoint\s*\{/u,
);
const authenticatedKeyAgentInstallJournalBlock = rustTopLevelLexicalItemBlock(
  keyAgentInstallProvenanceRelease,
  /pub\(crate\)\s+struct\s+AuthenticatedKeyAgentInstallJournal\s*\{/u,
);
const authenticatedKeyAgentInstallSnapshotBlock = rustTopLevelLexicalItemBlock(
  keyAgentInstallProvenanceRelease,
  /pub\(crate\)\s+struct\s+AuthenticatedKeyAgentInstallSnapshot\s*\{/u,
);
const expectedKeyAgentInstallIdentitiesBlock = rustTopLevelLexicalItemBlock(
  keyAgentInstallProvenanceRelease,
  /pub\(crate\)\s+struct\s+ExpectedKeyAgentInstallIdentities\s*\{/u,
);
const observedKeyAgentInstallObjectsBlock = rustTopLevelLexicalItemBlock(
  keyAgentInstallProvenanceRelease,
  /pub\(crate\)\s+struct\s+ObservedKeyAgentInstallObjects\s*\{/u,
);
const uninitializedKeyAgentInstallCandidateBlock = rustTopLevelLexicalItemBlock(
  keyAgentInstallProvenanceRelease,
  /pub\(crate\)\s+struct\s+UninitializedKeyAgentInstallCandidate\s*\{/u,
);
const consistentExistingKeyAgentInstallCandidateBlock = rustTopLevelLexicalItemBlock(
  keyAgentInstallProvenanceRelease,
  /pub\(crate\)\s+struct\s+ConsistentExistingKeyAgentInstallCandidate\s*\{/u,
);
const stableExistingKeyAgentInstallEvidenceBlock = rustTopLevelLexicalItemBlock(
  keyAgentInstallProvenanceRelease,
  /pub\(crate\)\s+struct\s+StableExistingKeyAgentInstallEvidence\s*\{/u,
);
const keyAgentInstallDispositionBlock = rustTopLevelLexicalItemBlock(
  keyAgentInstallProvenanceRelease,
  /pub\(crate\)\s+enum\s+KeyAgentInstallDisposition\s*\{/u,
);
const keyAgentInstallRecordBlock = rustTopLevelLexicalItemBlock(
  keyAgentInstallProvenanceRelease,
  /enum\s+KeyAgentInstallRecord\s*\{/u,
);
const classifyKeyAgentInstall = rustTopLevelFunctionBlock(
  keyAgentInstallProvenanceRelease,
  "classify_key_agent_install",
);
const verifyExistingKeyAgentInstallSnapshots = rustTopLevelFunctionBlock(
  keyAgentInstallProvenanceRelease,
  "verify_existing_key_agent_install_snapshots",
);
const consumeStableExistingKeyAgentInstallEvidence = rustTopLevelFunctionBlock(
  keyAgentInstallProvenanceRelease,
  "consume_stable_existing_key_agent_install_evidence",
);
const sameAuthenticatedKeyAgentInstallSnapshot = rustTopLevelFunctionBlock(
  keyAgentInstallProvenanceRelease,
  "same_authenticated_install_snapshot",
);
const observedInstallObjectsFromCanonical = rustTopLevelFunctionBlock(
  keyAgentInstallProvenanceRelease,
  "observed_install_objects_from_canonical",
);
const canonicalObservedInstallSid = rustTopLevelFunctionBlock(
  keyAgentInstallProvenanceRelease,
  "canonical_observed_sid",
);
const exactCommittedKeyAgentInstallMatch = rustTopLevelFunctionBlock(
  keyAgentInstallProvenanceRelease,
  "exact_committed_match",
);
const keyAgentInstallTransactionGeneration = rustTopLevelFunctionBlock(
  keyAgentInstallProvenanceRelease,
  "transaction_generation",
);
const validKeyAgentInstallRecord = rustTopLevelFunctionBlock(
  keyAgentInstallProvenanceRelease,
  "valid_install_record",
);
const encodeKeyAgentInstallJournalRecordBody = rustTopLevelFunctionBlock(
  keyAgentInstallProvenanceRelease,
  "encode_install_journal_record_body",
);
const decodeKeyAgentInstallJournalRecordBody = rustTopLevelFunctionBlock(
  keyAgentInstallProvenanceRelease,
  "decode_install_journal_record_body",
);
const decodeKeyAgentInstallJournalRoot = rustTopLevelFunctionBlock(
  keyAgentInstallProvenanceRelease,
  "decode_install_journal_root",
);
const verifyKeyAgentInstallJournalRecordMac = rustTopLevelFunctionBlock(
  keyAgentInstallProvenanceRelease,
  "verify_install_journal_record_mac",
);
const decodeAuthenticatedKeyAgentInstallJournalRecord = rustTopLevelFunctionBlock(
  keyAgentInstallProvenanceRelease,
  "decode_authenticated_install_journal_record",
);
const authenticatedKeyAgentInstallJournalRecordDigest = rustTopLevelFunctionBlock(
  keyAgentInstallProvenanceRelease,
  "authenticated_install_journal_record_digest",
);
const keyAgentInstallCheckpointCommitment = rustTopLevelFunctionBlock(
  keyAgentInstallProvenanceRelease,
  "install_checkpoint_commitment",
);
const bindKeyAgentInstallJournalPhasePayload = rustTopLevelFunctionBlock(
  keyAgentInstallProvenanceRelease,
  "bind_install_journal_phase_payload",
);
const validateNonemptyKeyAgentInstallJournalHistory = rustTopLevelFunctionBlock(
  keyAgentInstallProvenanceRelease,
  "validate_nonempty_install_journal_history",
);
const validateAuthenticatedKeyAgentInstallJournal = rustTopLevelFunctionBlock(
  keyAgentInstallProvenanceRelease,
  "validate_authenticated_install_journal",
);
const installJournalRecordMagicConstant = rustTopLevelConstItem(
  keyAgentInstallProvenanceRelease,
  "INSTALL_JOURNAL_RECORD_MAGIC_V1",
);
const installJournalRecordDigestDomainConstant = rustTopLevelConstItem(
  keyAgentInstallProvenanceRelease,
  "INSTALL_JOURNAL_RECORD_DIGEST_DOMAIN_V1",
);
const installJournalRecordMacDomainConstant = rustTopLevelConstItem(
  keyAgentInstallProvenanceRelease,
  "INSTALL_JOURNAL_RECORD_MAC_DOMAIN_V1",
);
const installCheckpointCommitmentDomainConstant = rustTopLevelConstItem(
  keyAgentInstallProvenanceRelease,
  "INSTALL_CHECKPOINT_COMMITMENT_DOMAIN_V1",
);
const keyAgentInstallAdoptionReleaseCode = rustLexicalCode(
  keyAgentInstallAdoptionRelease,
);
const existingInstallAdoptionSealBlock = rustTopLevelLexicalItemBlock(
  keyAgentInstallAdoptionRelease,
  /pub\(crate\)\s+struct\s+ExistingInstallAdoptionSeal\s*\{/u,
);
const verifiedExistingKeyAgentInstallBlock = rustTopLevelLexicalItemBlock(
  keyAgentInstallAdoptionRelease,
  /pub\(crate\)\s+struct\s+VerifiedExistingKeyAgentInstall\s*\{/u,
);
const verifiedKeyAgentInstallContinuityBlock = rustTopLevelLexicalItemBlock(
  keyAgentInstallAdoptionRelease,
  /pub\(crate\)\s+struct\s+VerifiedKeyAgentInstallContinuity\s*\{/u,
);
const artifactBoundExistingKeyAgentInstallBlock =
  rustTopLevelLexicalItemBlock(
    keyAgentInstallAdoptionRelease,
    /pub\(crate\)\s+struct\s+ArtifactBoundExistingKeyAgentInstall\s*\{/u,
  );
const verifiedExistingKeyAgentInstallDebugImpl = rustLexicalItemBlock(
  keyAgentInstallAdoptionRelease,
  /impl\s+fmt::Debug\s+for\s+VerifiedExistingKeyAgentInstall\s*\{/u,
);
const verifiedKeyAgentInstallContinuityDebugImpl = rustLexicalItemBlock(
  keyAgentInstallAdoptionRelease,
  /impl\s+fmt::Debug\s+for\s+VerifiedKeyAgentInstallContinuity\s*\{/u,
);
const artifactBoundExistingKeyAgentInstallDebugImpl = rustLexicalItemBlock(
  keyAgentInstallAdoptionRelease,
  /impl\s+fmt::Debug\s+for\s+ArtifactBoundExistingKeyAgentInstall\s*\{/u,
);
const keyAgentInstallAdoptionErrorBlock = rustTopLevelLexicalItemBlock(
  keyAgentInstallAdoptionRelease,
  /pub\(crate\)\s+enum\s+KeyAgentInstallAdoptionError\s*\{/u,
);
const keyAgentInstallReleaseBindingErrorBlock =
  rustTopLevelLexicalItemBlock(
    keyAgentInstallAdoptionRelease,
    /pub\(crate\)\s+enum\s+KeyAgentInstallReleaseBindingError\s*\{/u,
  );
const adoptExistingKeyAgentInstall = rustTopLevelFunctionBlock(
  keyAgentInstallAdoptionRelease,
  "adopt_existing_key_agent_install",
);
const bindExistingKeyAgentInstallToRelease = rustTopLevelFunctionBlock(
  keyAgentInstallAdoptionRelease,
  "bind_existing_key_agent_install_to_release",
);
const consumeArtifactBoundExistingKeyAgentInstall =
  rustTopLevelFunctionBlock(
    keyAgentInstallAdoptionRelease,
    "consume_artifact_bound_existing_key_agent_install",
  );
const provisionFreshKeyAgentBoundary = rustFunctionBlock(
  keyAgentSupervisor,
  "provision_fresh_key_agent_boundary",
);
const pendingKeyAgentProvisioningBlock = rustLexicalItemBlock(
  keyAgentLpacRelease,
  /pub\(crate\)\s+struct\s+PendingKeyAgentProvisioning\s*\{/u,
);
const heldExistingKeyAgentInstallObjectsBlock = rustLexicalItemBlock(
  keyAgentLpacRelease,
  /pub\(crate\)\s+struct\s+HeldExistingKeyAgentInstallObjects\s*\{/u,
);
const heldExistingKeyAgentInstallObjectsImpl = rustLexicalItemBlock(
  keyAgentLpacRelease,
  /impl\s+HeldExistingKeyAgentInstallObjects\s*\{/u,
);
const heldExistingKeyAgentInstallObjectsMethods = [
  ...rustLexicalCode(heldExistingKeyAgentInstallObjectsImpl).matchAll(
    /pub\(crate\)\s+(?:const\s+)?fn\s+(?<name>[A-Za-z_]\w*)/gu,
  ),
].map((match) => match.groups.name);
const revalidateHeldExistingKeyAgentInstallObjects = rustFunctionBlock(
  heldExistingKeyAgentInstallObjectsImpl,
  "revalidate",
);
const observeHeldExistingKeyAgentInstallObjects = rustFunctionBlock(
  heldExistingKeyAgentInstallObjectsImpl,
  "install_observation",
);
const convertHeldExistingKeyAgentInstallObjects = rustFunctionBlock(
  heldExistingKeyAgentInstallObjectsImpl,
  "into_prepared",
);
const heldKeyAgentInstallObservationBlock = rustLexicalItemBlock(
  keyAgentLpacRelease,
  /pub\(crate\)\s+struct\s+KeyAgentHeldInstallObservation\s*\{/u,
);
const heldKeyAgentInstallObservationImpl = rustLexicalItemBlock(
  keyAgentLpacRelease,
  /impl\s+KeyAgentHeldInstallObservation\s*\{/u,
);
const heldKeyAgentInstallObservationMethods = [
  ...rustLexicalCode(heldKeyAgentInstallObservationImpl).matchAll(
    /pub\(crate\)\s+(?:const\s+)?fn\s+(?<name>[A-Za-z_]\w*)/gu,
  ),
].map((match) => match.groups.name);
const preparedKeyAgentProvisioningBlock = rustLexicalItemBlock(
  keyAgentLpacRelease,
  /pub\(crate\)\s+struct\s+PreparedKeyAgentProvisioning\s*\{/u,
);
const preparedKeyAgentProfileBlock = rustLexicalItemBlock(
  keyAgentLpacRelease,
  /(?:^|\n)\s*struct\s+PreparedKeyAgentProfile\s*\{/u,
);
const pendingKeyAgentProvisioningImpl = rustLexicalItemBlock(
  keyAgentLpacRelease,
  /impl\s+PendingKeyAgentProvisioning\s*\{/u,
);
const preparedKeyAgentProvisioningImpl = rustLexicalItemBlock(
  keyAgentLpacRelease,
  /impl\s+PreparedKeyAgentProvisioning\s*\{/u,
);
const preparedKeyAgentProfileImpl = rustLexicalItemBlock(
  keyAgentLpacRelease,
  /impl\s+PreparedKeyAgentProfile\s*\{/u,
);
const ownedAppContainerSidReleaseImpl = rustLexicalItemBlock(
  keyAgentLpacRelease,
  /impl\s+OwnedAppContainerSid\s*\{/u,
);
const ownedAppContainerSidTestImpl = rustLexicalItemBlock(
  keyAgentLpac,
  /impl\s+OwnedAppContainerSid\s*\{/u,
);
const provisionFreshKeyAgent = rustFunctionBlock(
  pendingKeyAgentProvisioningImpl,
  "provision_fresh",
);
const pendingKeyAgentProvisioningMethods = [
  ...rustLexicalCode(pendingKeyAgentProvisioningImpl).matchAll(
    /\bfn\s+(?<name>[A-Za-z_]\w*)\s*\(/gu,
  ),
].map((match) => match.groups.name);
const preparedKeyAgentProvisioningMethods = [
  ...rustLexicalCode(preparedKeyAgentProvisioningImpl).matchAll(
    /\bfn\s+(?<name>[A-Za-z_]\w*)\s*\(/gu,
  ),
].map((match) => match.groups.name);
const provisionFreshKeyAgentProfile = rustFunctionBlock(
  preparedKeyAgentProfileImpl,
  "provision_fresh",
);
const prepareKeyAgentProfileFromSid = rustFunctionBlock(
  preparedKeyAgentProfileImpl,
  "from_profile_sid",
);
const createFreshKeyAgentProfileSid = rustFunctionBlock(
  ownedAppContainerSidReleaseImpl,
  "create_fresh",
);
const keyAgentLpacPrepare = rustFunctionBlock(keyAgentLpac, "prepare");
const keyAgentLpacEnvironment = rustFunctionBlock(
  keyAgentLpacRelease,
  "environment_with_local_app_data",
);
const keyAgentLpacAttributeInstall = rustFunctionBlock(
  keyAgentLpacRelease,
  "install_into",
);
const keyAgentLpacVerifySuspended = rustFunctionBlock(
  keyAgentLpacRelease,
  "verify_suspended_process",
);
const keyAgentLpacOpenOrCreate = rustFunctionBlock(
  ownedAppContainerSidTestImpl,
  "open_or_create",
);
const keyAgentLpacDeriveUnderGuard = rustFunctionBlock(
  keyAgentLpacRelease,
  "derive_under_guard",
);
const launchProfileOpenOrCreate = rustFunctionBlock(
  restrictedLauncherRelease,
  "open_or_create",
);
const launchProfileDeriveUnderGuard = rustFunctionBlock(
  restrictedLauncherRelease,
  "derive_under_guard",
);
const acquireAppContainerProfileApi = rustFunctionBlock(
  appContainerProfileApiProduction,
  "acquire_appcontainer_profile_api",
);
const rejectAppContainerProfileThreadImpersonation = rustFunctionBlock(
  appContainerProfileApiProduction,
  "reject_thread_impersonation",
);
const appContainerProfileApiGuardDrop = rustLexicalItemBlock(
  appContainerProfileApiProduction,
  /impl\s+Drop\s+for\s+AppContainerProfileApiGuard\s*\{/u,
);
const appContainerProfileReentryTest = rustFunctionBlock(
  appContainerProfileApiSource,
  "same_thread_reentry_fails_closed_without_poisoning_gate",
);
const appContainerProfileImpersonationTest = rustFunctionBlock(
  appContainerProfileApiSource,
  "impersonating_thread_is_rejected_before_profile_gate",
);
const concurrentKeyAgentProfilePreparationTest = rustFunctionBlock(
  keyAgentLpacSource,
  "concurrent_fixed_profile_preparation_is_process_serialized",
);
const requireCreatedKeyAgentSidMatchesDerived = rustFunctionBlock(
  keyAgentLpacRelease,
  "require_created_sid_matches_derived",
);
const verifyKeyAgentLpacToken = rustFunctionBlock(
  keyAgentLpacRelease,
  "verify_process_token",
);
const queryKeyAgentLpacDword = rustFunctionBlock(
  keyAgentLpacRelease,
  "token_dword",
);
const queryOptionalKeyAgentLpacDword = rustFunctionBlock(
  keyAgentLpacRelease,
  "less_privileged_appcontainer_dword",
);
const queryKeyAgentLpacMembershipEvidence = rustFunctionBlock(
  keyAgentLpacRelease,
  "appcontainer_membership_evidence",
);
const checkKeyAgentTokenMembership = rustFunctionBlock(
  keyAgentLpacRelease,
  "check_token_membership",
);
const keyAgentLpacMembershipEvidenceDefinition = rustLexicalItemBlock(
  keyAgentLpacRelease,
  /enum\s+AppContainerMembershipEvidence\s*\{/u,
);
const queryKeyAgentTokenInformation = rustFunctionBlock(
  keyAgentLpacRelease,
  "token_information",
);
const validateKeyAgentLpacToken = rustFunctionBlock(
  keyAgentLpacRelease,
  "validate_token_policy",
);
const keyAgentAppContainerFolder = rustFunctionBlock(
  keyAgentLpacRelease,
  "appcontainer_folder",
);
const validateKeyAgentAppContainerFolder = rustFunctionBlock(
  keyAgentLpacRelease,
  "validated_appcontainer_folder",
);
const exactKeyAgentBaseEnvironment = rustFunctionBlock(
  keyAgentLpacRelease,
  "base_environment_is_exact",
);
const exactKeyAgentEnvironmentTest = rustFunctionBlock(
  keyAgentLpacSource,
  "exact_environment_has_only_three_os_scoped_names",
);
const compactRust = (source) => rustLexicalCode(source).replace(/\s+/gu, "");
const heldKeyAgentStorageRootDefinition = rustLexicalItemBlock(
  keyAgentStorage,
  /pub\(crate\)\s+struct\s+HeldKeyAgentStorageRoot\s*\{/u,
);
const heldKeyAgentStorageRootImpl = rustLexicalItemBlock(
  keyAgentStorage,
  /impl\s+HeldKeyAgentStorageRoot\s*\{/u,
);
const heldKeyAgentStorageRootDrop = rustLexicalItemBlock(
  keyAgentStorage,
  /impl\s+Drop\s+for\s+HeldKeyAgentStorageRoot\s*\{/u,
);
const heldKeyAgentStorageRootDebug = rustLexicalItemBlock(
  keyAgentStorage,
  /impl\s+fmt::Debug\s+for\s+HeldKeyAgentStorageRoot\s*\{/u,
);
const heldKeyAgentStorageRootMethods = [
  ...heldKeyAgentStorageRootImpl.matchAll(
    /pub\(crate\)\s+(?:const\s+)?fn\s+(?<name>[A-Za-z_]\w*)/gu,
  ),
].map((match) => match.groups.name);
const heldKeyAgentStorageInstallObservation = rustFunctionBlock(
  heldKeyAgentStorageRootImpl,
  "install_observation",
);
const heldKeyAgentRootObservationDefinition = rustLexicalItemBlock(
  keyAgentStorageRelease,
  /pub\(crate\)\s+struct\s+KeyAgentHeldRootObservation\s*\{/u,
);
const heldKeyAgentRootObservationImpl = rustLexicalItemBlock(
  keyAgentStorageRelease,
  /impl\s+KeyAgentHeldRootObservation\s*\{/u,
);
const heldKeyAgentRootObservationMethods = [
  ...heldKeyAgentRootObservationImpl.matchAll(
    /pub\(crate\)\s+(?:const\s+)?fn\s+(?<name>[A-Za-z_]\w*)/gu,
  ),
].map((match) => match.groups.name);
const keyAgentStorageIdentityDefinition = rustLexicalItemBlock(
  keyAgentStorage,
  /pub\(crate\)\s+struct\s+KeyAgentStorageRootIdentity\s*\{/u,
);
const keyAgentStorageIdentityImpl = rustLexicalItemBlock(
  keyAgentStorage,
  /impl\s+KeyAgentStorageRootIdentity\s*\{/u,
);
const heldChildKeyAgentStorageRootDefinition = rustLexicalItemBlock(
  keyAgentStorage,
  /pub\(crate\)\s+struct\s+HeldChildKeyAgentStorageRoot\s*\{/u,
);
const heldChildKeyAgentStorageRootImpl = rustLexicalItemBlock(
  keyAgentStorage,
  /impl\s+HeldChildKeyAgentStorageRoot\s*\{/u,
);
const heldChildKeyAgentStorageRootDebug = rustLexicalItemBlock(
  keyAgentStorage,
  /impl\s+fmt::Debug\s+for\s+HeldChildKeyAgentStorageRoot\s*\{/u,
);
const heldChildKeyAgentStorageRootMethods = [
  ...heldChildKeyAgentStorageRootImpl.matchAll(
    /pub\(crate\)\s+(?:const\s+)?fn\s+(?<name>[A-Za-z_]\w*)/gu,
  ),
].map((match) => match.groups.name);
const fixedKeyAgentGenerationStoreRoleDefinition = rustLexicalItemBlock(
  keyAgentStorageRelease,
  /pub\(crate\)\s+enum\s+FixedKeyAgentGenerationStoreRole\s*\{/u,
);
const keyAgentGenerationStoreRootAuthorityDefinition = rustLexicalItemBlock(
  keyAgentStorageRelease,
  /struct\s+KeyAgentGenerationStoreRootAuthority\s*\{/u,
);
const keyAgentGenerationStoreBindingDefinition = rustLexicalItemBlock(
  keyAgentStorageRelease,
  /pub\(crate\)\s+struct\s+KeyAgentGenerationStoreBinding\s*\{/u,
);
const keyAgentGenerationStoreBindingImpl = rustLexicalItemBlock(
  keyAgentStorageRelease,
  /impl\s+KeyAgentGenerationStoreBinding\s*\{/u,
);
const keyAgentGenerationStoreBindingNew = rustFunctionBlock(
  keyAgentGenerationStoreBindingImpl,
  "new",
);
const keyAgentGenerationStoreBindingMethods = [
  ...keyAgentGenerationStoreBindingImpl.matchAll(
    /pub\(crate\)\s+(?:const\s+)?fn\s+(?<name>[A-Za-z_]\w*)/gu,
  ),
].map((match) => match.groups.name);
const fixedKeyAgentGenerationStoreBindingsDefinition = rustLexicalItemBlock(
  keyAgentStorageRelease,
  /pub\(crate\)\s+struct\s+FixedKeyAgentGenerationStoreBindings\s*\{/u,
);
const fixedKeyAgentGenerationStoreBindingsImpl = rustLexicalItemBlock(
  keyAgentStorageRelease,
  /impl\s+FixedKeyAgentGenerationStoreBindings\s*\{/u,
);
const fixedKeyAgentGenerationStoreBindingsMethods = [
  ...fixedKeyAgentGenerationStoreBindingsImpl.matchAll(
    /pub\(crate\)\s+(?:const\s+)?fn\s+(?<name>[A-Za-z_]\w*)/gu,
  ),
].map((match) => match.groups.name);
const mintFixedKeyAgentGenerationStoreBindings = rustFunctionBlock(
  heldChildKeyAgentStorageRootImpl,
  "into_fixed_generation_store_bindings",
);
const fixedKeyAgentGenerationStoreBindingsFromChildRoot = rustFunctionBlock(
  fixedKeyAgentGenerationStoreBindingsImpl,
  "from_child_root",
);
const createFixedKeyAgentStorageRoot = rustFunctionBlock(
  keyAgentStorage,
  "create_fixed_key_agent_storage_root",
);
const createKeyAgentStorageRoot = rustFunctionBlock(
  keyAgentStorage,
  "create_storage_root",
);
const openAndVerifyKeyAgentStorageRoot = rustFunctionBlock(
  keyAgentStorage,
  "open_and_verify_created_root",
);
const openFixedKeyAgentStorageRootForChild = rustFunctionBlock(
  keyAgentStorage,
  "open_fixed_key_agent_storage_root_for_child",
);
const openChildKeyAgentStorageRoot = rustFunctionBlock(
  keyAgentStorage,
  "open_child_storage_root",
);
const openKeyAgentStorageRootHandle = rustFunctionBlock(
  keyAgentStorage,
  "open_storage_root_handle",
);
const verifyChildKeyAgentStorageRoot = rustFunctionBlock(
  keyAgentStorage,
  "verify_child_open_storage_root",
);
const validateChildKeyAgentStorageProfileFolder = rustFunctionBlock(
  keyAgentStorage,
  "validate_child_profile_folder_shape",
);
const validateKeyAgentStorageProfileFolder = rustFunctionBlock(
  keyAgentStorage,
  "validate_profile_folder",
);
const verifyKeyAgentStorageDirectory = rustFunctionBlock(
  keyAgentStorage,
  "verify_directory_object",
);
const queryKeyAgentStorageIdentity = rustFunctionBlock(
  keyAgentStorage,
  "exact_file_identity",
);
const verifyKeyAgentStorageVolume = rustFunctionBlock(
  keyAgentStorage,
  "verify_supported_local_ntfs",
);
const keyAgentStorageRootDescriptor = rustFunctionBlock(
  keyAgentStorage,
  "for_key_agent_root",
);
const verifyKeyAgentStorageHandleSecurity = rustFunctionBlock(
  keyAgentStorage,
  "verify_handle_security",
);
const inspectKeyAgentStorageCreationDescriptor = rustFunctionBlock(
  keyAgentStorage,
  "inspect_creation_security_descriptor",
);
const inspectKeyAgentStorageHandleDescriptor = rustFunctionBlock(
  keyAgentStorage,
  "inspect_handle_security_descriptor",
);
const inspectExactKeyAgentStorageDacl = rustFunctionBlock(
  keyAgentStorage,
  "inspect_exact_dacl",
);
const inspectExactKeyAgentStorageLowLabel = rustFunctionBlock(
  keyAgentStorage,
  "inspect_exact_low_label",
);
const currentStableKeyAgentStorageUserSid = rustFunctionBlock(
  keyAgentStorage,
  "current_stable_user_sid",
);
const currentKeyAgentStorageProcessToken = rustFunctionBlock(
  keyAgentStorage,
  "current_process_token",
);
const revalidateHeldKeyAgentStorageRoot = rustFunctionBlock(
  heldKeyAgentStorageRootImpl,
  "revalidate",
);
const openFixedKeyAgentGenerationStore = rustFunctionBlock(
  windowsStorageRelease,
  "open_key_agent",
);
const fixedKeyAgentGenerationStoreSpec = rustFunctionBlock(
  windowsStorageRelease,
  "fixed_key_agent_store_spec",
);
const revalidateFixedKeyAgentGenerationStoreRootPath = rustFunctionBlock(
  windowsStorageRelease,
  "revalidate_key_agent_root_path",
);
const prepareFixedKeyAgentGenerationStorePathOperation = rustFunctionBlock(
  windowsStorageRelease,
  "prepare_key_agent_path_operation",
);
const removeFixedKeyAgentGenerationStoreStaleTemp = rustFunctionBlock(
  windowsStorageRelease,
  "remove_key_agent_stale_temp",
);
const readFixedKeyAgentGenerationStore = rustFunctionBlock(
  windowsStorageRelease,
  "read",
);
const writeFixedKeyAgentGenerationStore = rustFunctionBlock(
  windowsStorageRelease,
  "atomic_write",
);
const fixedKeyAgentGenerationStoreFileDescriptor = rustFunctionBlock(
  windowsStorageRelease,
  "for_key_agent_files",
);
const verifyFixedKeyAgentGenerationStoreFileSecurity = rustFunctionBlock(
  windowsStorageRelease,
  "verify_key_agent_file_security",
);
const inspectFixedKeyAgentGenerationStoreFileDescriptor = rustFunctionBlock(
  windowsStorageRelease,
  "inspect_key_agent_file_security_descriptor",
);
const inspectFixedKeyAgentGenerationStoreDacl = rustFunctionBlock(
  windowsStorageRelease,
  "inspect_exact_key_agent_dacl",
);
const inspectFixedKeyAgentGenerationStoreLowLabel = rustFunctionBlock(
  windowsStorageRelease,
  "inspect_exact_inherited_low_label",
);
const queryFixedKeyAgentGenerationStoreFileIdentity = rustFunctionBlock(
  windowsStorageRelease,
  "file_identity",
);
const inspectFixedKeyAgentGenerationStoreTarget = rustFunctionBlock(
  windowsStorageRelease,
  "inspect_optional_target",
);
const publicWindowsGenerationStoreImpl = rustLexicalItemBlock(
  windowsStorageFacadeRelease,
  /impl\s+WindowsGenerationStore\s*\{/u,
);
const publicWindowsGenerationStoreOpen = rustFunctionBlock(
  publicWindowsGenerationStoreImpl,
  "open",
);
const publicWindowsGenerationStoreMethods = [
  ...publicWindowsGenerationStoreImpl.matchAll(
    /pub\s+(?:const\s+)?fn\s+(?<name>[A-Za-z_]\w*)/gu,
  ),
].map((match) => match.groups.name);
const exerciseFixedKeyAgentGenerationStores = rustFunctionBlock(
  windowsStorageFacade,
  "exercise_fixed_key_agent_generation_stores_for_test",
);
const verifyFixedKeyAgentGenerationStoreRoleForTest = rustFunctionBlock(
  windowsStorage,
  "verify_and_cleanup_key_agent_role_for_test",
);
const fixedKeyAgentGenerationStoreContractTest = rustFunctionBlock(
  windowsStorage,
  "key_agent_file_access_and_fixed_store_contracts_are_exact",
);
const fixedKeyAgentGenerationStoreDaclNegativeTest = rustFunctionBlock(
  windowsStorage,
  "key_agent_file_descriptor_rejects_dacl_policy_drift",
);
const fixedKeyAgentGenerationStoreLabelNegativeTest = rustFunctionBlock(
  windowsStorage,
  "key_agent_file_descriptor_rejects_label_policy_drift",
);
const fixedKeyAgentGenerationStoreTargetBaselineTest = rustFunctionBlock(
  windowsStorage,
  "atomic_write_never_repairs_or_replaces_injected_targets",
);
const integratedKeyAgentGenerationStoreTest = rustFunctionBlock(
  keyAgentSupervisorSource,
  "integrated_storage_startup_binds_child_process_and_full_root_identity",
);
const keyAgentStorageCreateDirectoryCalls = rustCallSites(
  keyAgentStorage,
  "CreateDirectoryW",
);
const keyAgentStorageFactoryCalls = rustCallSites(
  createFixedKeyAgentStorageRoot,
  "create_storage_root",
);
const keyAgentStorageOpenCalls = rustCallSites(
  openKeyAgentStorageRootHandle,
  "CreateFileW",
);
const keyAgentStorageAllOpenCalls = rustCallSites(
  keyAgentStorage,
  "CreateFileW",
);
const keyAgentStorageSecurityInfoCalls = rustCallSites(
  verifyKeyAgentStorageHandleSecurity,
  "GetSecurityInfo",
);
const keyAgentProvisioningKernelTest = rustFunctionBlock(
  keyAgentLpacSource,
  "provisioning_proof_is_revalidated_redacted_and_exactly_cleaned",
);
const integratedKeyAgentStorageBindingTest = rustFunctionBlock(
  keyAgentSupervisorSource,
  "integrated_kernel_binding_owns_one_member_and_no_inheritable_parent_handles",
);
const restrictedProcessContextDefinition = rustLexicalItemBlock(
  restrictedProcessContextProduction,
  /(?:^|\n)\s*pub\(crate\)\s+struct\s+RestrictedProcessContext\s*\{/u,
);
const systemProcessPathsDefinition = rustLexicalItemBlock(
  restrictedProcessContextProduction,
  /(?:^|\n)\s*struct\s+SystemProcessPaths\s*\{/u,
);
const restrictedProcessContextImplementation = rustLexicalItemBlock(
  restrictedProcessContext,
  /(?:^|\n)\s*impl\s+RestrictedProcessContext\s*\{/u,
);
const restrictedContextPublicMethods = [
  ...rustLexicalCode(restrictedProcessContextImplementation).matchAll(
    /\bpub\(crate\)\s+fn\s+(?<name>[A-Za-z_]\w*)\s*\(/gu,
  ),
].map((match) => match.groups.name);
const restrictedContextPrepare = rustFunctionBlock(
  restrictedProcessContextProduction,
  "prepare",
);
const restrictedContextKernelPrepare = rustFunctionBlock(
  restrictedProcessContext,
  "prepare_for_kernel_test",
);
const restrictedContextFromPaths = rustFunctionBlock(
  restrictedProcessContextProduction,
  "from_system_paths",
);
const prepareSystemProcessPaths = rustFunctionBlock(
  restrictedProcessContextProduction,
  "prepare_system_process_paths",
);
const querySystemPath = rustFunctionBlock(
  restrictedProcessContextProduction,
  "query_system_path",
);
const validateExistingReparseFreeDirectory = rustFunctionBlock(
  restrictedProcessContextProduction,
  "validate_existing_reparse_free_directory",
);
const rejectReplaceableAncestors = rustFunctionBlock(
  restrictedProcessContextProduction,
  "reject_replaceable_ancestors",
);
const rejectContentWritableDirectory = rustFunctionBlock(
  restrictedProcessContextProduction,
  "reject_content_writable_directory",
);
const plainAbsoluteDosPath = rustFunctionBlock(
  restrictedProcessContextProduction,
  "plain_absolute_dos_path",
);
const validateSystemDirectoryLayout = rustFunctionBlock(
  restrictedProcessContextProduction,
  "validate_system_directory_layout",
);
const restrictedContextOrdinalEq = rustFunctionBlock(
  restrictedProcessContextProduction,
  "ordinal_eq",
);
const rejectThreadImpersonation = rustFunctionBlock(
  restrictedProcessContextProduction,
  "reject_thread_impersonation",
);
const rejectReparseDirectory = rustFunctionBlock(
  restrictedProcessContextProduction,
  "reject_reparse_directory",
);
const rejectDangerousDirectoryRights = rustFunctionBlock(
  restrictedProcessContextProduction,
  "reject_dangerous_directory_rights",
);
const minimalRestrictedEnvironment = rustFunctionBlock(
  restrictedProcessContextProduction,
  "minimal_environment_block",
);
const wideNulRestrictedPath = rustFunctionBlock(
  restrictedProcessContextProduction,
  "wide_nul_path",
);
const restrictedContextRecheck = rustFunctionBlock(
  restrictedProcessContextProduction,
  "recheck_thread",
);
const restrictedContextEnvironmentAccessor = rustFunctionBlock(
  restrictedProcessContextProduction,
  "environment",
);
const restrictedContextDirectoryAccessor = rustFunctionBlock(
  restrictedProcessContextProduction,
  "current_directory",
);
const preparedKeyAgentProcessDefinition = rustLexicalItemBlock(
  keyAgentActivationRelease,
  /(?:^|\n)\s*struct\s+PreparedKeyAgentProcess\s*\{/u,
);
const prepareKeyAgentProcess = rustFunctionBlock(
  keyAgentActivation,
  "prepare_key_agent_process",
);
const prepareKeyAgentProcessRelease = rustFunctionBlock(
  keyAgentActivationRelease,
  "prepare_key_agent_process",
);
const restrictedContextConsumers = platformWindowsProductionFiles
  .filter(
    (file) =>
      file.path !==
        "crates/platform-windows/src/restricted_process_context.rs" &&
      file.path !== "crates/platform-windows/src/lib.rs" &&
      /\bRestrictedProcessContext\b|\brestricted_process_context\s*::/u.test(
        rustLexicalCode(file.source),
      ),
  )
  .map((file) => file.path);
const restrictedContextPrepareCallSites = platformWindowsProductionFiles.flatMap(
  (file) =>
    rustCallSites(file.source, "RestrictedProcessContext::prepare").map(
      (call) => ({ path: file.path, arguments: call.arguments }),
    ),
);
const systemDirectoryApiInventory = platformWindowsProductionFiles.flatMap(
  (file) =>
    [
      ...rustLexicalCode(file.source).matchAll(
        /\b(?<api>GetSystemWindowsDirectoryW|GetSystemDirectoryW)\b/gu,
      ),
    ].map((match) => ({ path: file.path, api: match.groups.api })),
);
const forbiddenAmbientDirectoryApis = platformWindowsProductionFiles.flatMap(
  (file) =>
    [
      ...rustLexicalCode(file.source).matchAll(
        /\b(?<api>GetWindowsDirectoryW|GetEnvironmentStrings[AW]?|GetCurrentDirectory[AW]?)\b/gu,
      ),
    ].map((match) => ({ path: file.path, api: match.groups.api })),
);
const prepareSystemPathQueries = rustCallSites(
  prepareSystemProcessPaths,
  "query_system_path",
);
const systemLayoutOrdinalCalls = rustCallSites(
  validateSystemDirectoryLayout,
  "ordinal_eq",
);
const compareStringOrdinalCalls = rustCallSites(
  restrictedContextOrdinalEq,
  "CompareStringOrdinal",
);
const openThreadTokenCalls = rustCallSites(
  rejectThreadImpersonation,
  "OpenThreadToken",
);
const dangerousDirectoryOpenCalls = rustCallSites(
  rejectDangerousDirectoryRights,
  "CreateFileW",
);
const replaceableAncestorPrepareCalls = rustCallSites(
  restrictedContextPrepare,
  "reject_replaceable_ancestors",
);
const protectedContentPrepareCalls = rustCallSites(
  restrictedContextPrepare,
  "reject_content_writable_directory",
);
const replacementRightsLeafCalls = rustCallSites(
  rejectReplaceableAncestors,
  "reject_dangerous_directory_rights",
);
const protectedContentRightsLeafCalls = rustCallSites(
  rejectContentWritableDirectory,
  "reject_dangerous_directory_rights",
);
const environmentNulPushes = rustCallSites(
  minimalRestrictedEnvironment,
  "push",
);
const restrictedLaunchCreateCalls = rustCallSites(
  restrictedLaunchLeaf,
  "create_process_with_explicit_handle_list",
);
const restrictedLaunchCompact = compactRust(restrictedLaunchLeaf);
const restrictedLaunchContextPreparationOrder = [
  "validate_live_handle(handles.input)?;",
  "validate_live_handle(handles.output)?;",
  "validate_live_handle(handles.error)?;",
  "letprocess_context=RestrictedProcessContext::prepare().map_err(map_process_context_error)?;",
  "lethelper_file=helper.identity();",
  "lethelper_manifest_digest=helper.manifest_digest();",
  "letoriginals=unique_raw_handles(handles);",
  ".then(current_parent_proof_sources)",
  "letprofile_sid=OwnedAppContainerSid::open_or_create(profile,role)?;",
  "letjob=restricted_job()?;",
  "letapplication:Vec<u16>=helper",
  ".encode_wide()",
  "letcoordination_deadline=Instant::now()",
  "acquire_inheritable_handle_launch(coordination_deadline)",
].map((marker) => restrictedLaunchCompact.indexOf(marker));
const keyAgentCreateCalls = rustCallSites(
  keyAgentCreateProcess,
  "create_process_with_explicit_handle_list",
);
const restrictedLaunchCreateIndex = restrictedLaunchLeaf.indexOf(
  ".create_process_with_explicit_handle_list(",
);
const restrictedLaunchFinalContextIndex = [
  ...rustLexicalCode(restrictedLaunchLeaf).matchAll(
    /\bprocess_context\s*\.\s*recheck_thread\s*\(\s*\)/gu,
  ),
].at(-1)?.index ?? -1;
const restrictedLaunchFinalContextGap = compactRust(
  restrictedLaunchLeaf.slice(
    restrictedLaunchFinalContextIndex,
    restrictedLaunchCreateIndex,
  ),
);
const keyAgentCreateIndex = keyAgentCreateProcess.indexOf(
  ".create_process_with_explicit_handle_list(",
);
const keyAgentFinalContextIndex = [
  ...rustLexicalCode(keyAgentCreateProcess).matchAll(
    /\bprepared_process\s*\.\s*context\s*\.\s*recheck_thread\s*\(\s*\)/gu,
  ),
].at(-1)?.index ?? -1;
const keyAgentFinalContextGap = compactRust(
  keyAgentCreateProcess.slice(keyAgentFinalContextIndex, keyAgentCreateIndex),
);
const restrictedContextKernelTest = rustFunctionBlock(
  restrictedProcessContextSource,
  "kernel_test_context_uses_exact_os_paths_and_two_name_environment",
);
const restrictedContextImpersonationTest = rustFunctionBlock(
  restrictedProcessContextSource,
  "impersonating_thread_cannot_prepare_or_recheck_context",
);
const restrictedContextImpersonationOrder = [
  "ImpersonateSelf(SecurityImpersonation)?",
  "letguard=RevertImpersonation",
  "context.recheck_thread(),Err(RestrictedProcessContextError::ThreadImpersonation)",
  "RestrictedProcessContext::prepare_for_kernel_test(),Err(RestrictedProcessContextError::ThreadImpersonation)",
  "drop(guard)",
  "reject_thread_impersonation_for_test(),Ok(())",
  "context.recheck_thread(),Ok(())",
].map((marker) => compactRust(restrictedContextImpersonationTest).indexOf(marker));
const restrictedContextRightSetsTest = rustFunctionBlock(
  restrictedProcessContextSource,
  "ancestor_replacement_and_protected_content_right_sets_are_distinct",
);
const restrictedContextTraitTest = rustFunctionBlock(
  restrictedProcessContextSource,
  "process_context_is_thread_bound_non_clone_and_non_copy",
);
const restrictedEnvironmentBoundsTest = rustFunctionBlock(
  restrictedProcessContextSource,
  "environment_block_rejects_interior_nul_and_excess_length",
);
const restrictedEnvironmentAllowlistTest = rustFunctionBlock(
  restrictedLauncher,
  "environment_is_an_exact_allowlist_without_user_secrets",
);
const restrictedWorkingDirectoryTest = rustFunctionBlock(
  restrictedLauncher,
  "relative_and_user_writable_working_directories_are_rejected",
);
const keyAgentActivateForTest = rustFunctionBlock(
  keyAgentActivationSource,
  "activate_for_test",
);
const keyAgentSuccessfulKernelTest = rustFunctionBlock(
  keyAgentActivationSource,
  "successful_kernel_proof_detaches_with_one_verified_suspend_count",
);
const keyAgentProductionActivationForContext = rustFunctionBlock(
  keyAgentActivationRelease,
  "activate_preflighted_key_agent_on_fresh_worker_with_identity",
);
const brokerCoordinatedCreate = rustFunctionBlock(
  releaseBrokerSupervisorProduction,
  "launch_broker_application_with_after_create",
);
const prepareKeyAgentInheritance = rustFunctionBlock(
  keyAgentPipeProduction,
  "prepare_child_inheritance",
);
const preparedKeyAgentInheritanceBlock =
  /pub\(crate\)\s+struct\s+PreparedKeyAgentInheritance<'pipes,\s*'flight>\s*\{(?<body>[\s\S]*?)\n\}/u.exec(
    keyAgentPipeProduction,
  )?.groups?.body ?? "";
const inheritedStdioConstructor = rustFunctionBlock(
  restrictedLauncherProduction,
  "new",
);
const secretInputStdioConstructor = rustFunctionBlock(
  restrictedLauncherProduction,
  "for_secret_input_servers",
);
const validateRestrictedSourceHandle = rustFunctionBlock(
  restrictedLauncherProduction,
  "validate_live_handle",
);
const restrictedInheritableDuplicateLeaf = rustFunctionBlock(
  restrictedLauncherProduction,
  "duplicate_inheritable",
);
const keyAgentInheritableDuplicateLeaf = rustFunctionBlock(
  keyAgentPipeProduction,
  "duplicate_inheritable",
);
const brokerInheritedParentDefinition = rustLexicalItemBlock(
  releaseBrokerSupervisorProduction,
  /(?:^|\n)\s*struct InheritedParentProcess<'flight>\s*\{/u,
);
const brokerInheritedParentLeaf = rustLexicalItemBlock(
  releaseBrokerSupervisorProduction,
  /(?:^|\n)\s*impl<'flight> InheritedParentProcess<'flight>\s*\{/u,
);
const brokerInheritedNullDefinition = rustLexicalItemBlock(
  releaseBrokerSupervisorProduction,
  /(?:^|\n)\s*struct InheritedNullStdio<'flight>\s*\{/u,
);
const brokerInheritedNullLeaf = rustLexicalItemBlock(
  releaseBrokerSupervisorProduction,
  /(?:^|\n)\s*impl<'flight> InheritedNullStdio<'flight>\s*\{/u,
);
const duplicateInheritedParentProcess = rustFunctionBlock(
  releaseBrokerSupervisorProduction,
  "duplicate_inherited_parent_process",
);
const restrictedAttributeValuesDefinition = rustLexicalItemBlock(
  restrictedLauncherProduction,
  /(?:^|\n)\s*struct AttributeValues\s*\{/u,
);
const restrictedAttributeValuesImplementation = rustLexicalItemBlock(
  restrictedLauncherProduction,
  /(?:^|\n)\s*impl AttributeValues\s*\{/u,
);
const restrictedAttributeListDefinition = rustLexicalItemBlock(
  restrictedLauncherProduction,
  /(?:^|\n)\s*struct AttributeList<'handles,\s*'flight,\s*'coordinator[^>]*>\s*\{/u,
);
const restrictedAttributeListImplementation = rustLexicalItemBlock(
  restrictedLauncherProduction,
  /(?:^|\n)\s*impl<'handles,\s*'flight,\s*'coordinator[^>]*> AttributeList<'handles,\s*'flight,\s*'coordinator[^>]*>\s*\{/u,
);
const restrictedCreatedChildGuard = rustLexicalItemBlock(
  restrictedLauncherProduction,
  /(?:^|\n)\s*struct CreatedChildGuard<'process,\s*'job>\s*\{/u,
);
const restrictedCreatedChildGuardImplementation = rustLexicalItemBlock(
  restrictedLauncherProduction,
  /(?:^|\n)\s*impl<'process,\s*'job> CreatedChildGuard<'process,\s*'job>\s*\{/u,
);
const restrictedCreatedChildGuardDrop = rustLexicalItemBlock(
  restrictedLauncherProduction,
  /(?:^|\n)\s*impl Drop for CreatedChildGuard<'_,\s*'_>\s*\{/u,
);
const restrictedCreatedChildCleanup = rustFunctionBlock(
  restrictedLauncherProduction,
  "terminate_and_reap_created_child",
);
const restrictedCreatedChildCleanupOrder = [
  "TerminateJobObject(job, 1)",
  "TerminateProcess(process, 1)",
  "WaitForSingleObject(process, CREATED_CHILD_CLEANUP_TIMEOUT_MILLISECONDS)",
].map((marker) => restrictedCreatedChildCleanup.indexOf(marker));
const restrictedAcquireIndex = restrictedLaunchLeaf.indexOf(
  "acquire_inheritable_handle_launch(coordination_deadline)",
);
const restrictedLateSourceChecks = [
  "validate_live_handle(handles.input)?",
  "validate_live_handle(handles.output)?",
  "validate_live_handle(handles.error)?",
].map((marker) => restrictedLaunchLeaf.indexOf(marker, restrictedAcquireIndex));
const inheritableStdioSourceTest = rustFunctionBlock(
  restrictedLauncher,
  "already_inheritable_stdio_sources_are_rejected_before_launch",
);
const inheritableStdioSourceTestOrder = [
  "acquire_inheritable_handle_launch(deadline)",
  "let (read, write) = anonymous_pipe()?",
  "HANDLE_FLAG_INHERIT",
  "InheritedStdio::new(",
  "let private_result = InheritedStdio::for_secret_input_servers(",
  "HANDLE_FLAGS(0)",
  "drop(flight)",
].map((marker) => inheritableStdioSourceTest.indexOf(marker));
const restrictedLaunchFlightOrder = [
  "acquire_inheritable_handle_launch(coordination_deadline)",
  "InheritableDuplicates::new(&flight)",
  "AttributeList::for_lpac(&duplicates, &job, profile_sid)",
  ".create_process_with_explicit_handle_list(",
  "let process = OwnedWinHandle(process_information.hProcess)",
  "let thread = OwnedWinHandle(process_information.hThread)",
  "CreatedChildGuard::new(&process, &job)",
  "attributes.into_profile_sid()",
  "drop(duplicates)",
  "drop(flight)",
  "GetProcessId(process.raw())",
  "IsProcessInJob(process.raw(), Some(job.raw()), &raw mut in_job)",
  "verify_child_token",
  "ResumeThread",
  "if previous_suspend_count != 1",
  "child_guard.disarm()",
].map((marker) => restrictedLaunchLeaf.indexOf(marker));
const keyAgentFlightOrder = [
  "acquire_inheritable_handle_launch(coordination_deadline)",
  ".prepare_child_inheritance(&flight)",
  "create_suspended_debuggee_process(",
  "drop(inheritance)",
  "drop(flight)",
  "GetProcessId",
  "GetThreadId",
].map((marker) => keyAgentCreateInner.indexOf(marker));
const brokerFlightOrder = [
  "acquire_inheritable_handle_launch(deadline)",
  "InheritedParentProcess::duplicate_current(&flight)",
  "InheritedNullStdio::create(&flight)",
  "CreationAttributes::new",
  "flight.create_process_with_explicit_handle_list(",
  "drop(attributes)",
  "drop(inherited_stdio)",
  "drop(inherited_parent)",
  "drop(flight)",
  "Debuggee::new(information)",
  "after_create(&debuggee)",
  "debuggee.authenticate_first_event",
].map((marker) => brokerCoordinatedCreate.indexOf(marker));
const duplicateInheritedParentProcessOrder = [
  "let handle = HANDLE(raw as *mut c_void)",
  "GetHandleInformation(handle, &raw mut flags)",
  "flags != HANDLE_FLAG_INHERIT.0",
  "SetHandleInformation(handle, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0))",
  "flags = u32::MAX",
  "if flags != 0",
  "let desired = (PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE).0",
  "DuplicateHandle(",
  "if invalid(duplicate)",
  "StdOwnedHandle::from_raw_handle(duplicate.0)",
  "HANDLE(duplicate.as_raw_handle())",
  "if duplicate_flags != 0",
].map((marker) => duplicateInheritedParentProcess.indexOf(marker));
const duplicateInheritedParentOriginalFlagQueries = [
  ...rustLexicalCode(duplicateInheritedParentProcess).matchAll(
    /GetHandleInformation\(handle,\s*&raw mut flags\)/gu,
  ),
].map((match) => match.index);
const restrictedDeadlineChecks = [
  ...restrictedLaunchLeaf.matchAll(
    /if Instant::now\(\) >= coordination_deadline/gu,
  ),
].map((match) => match.index);
const keyAgentFinalDeadlineCheck = keyAgentCreateProcess.indexOf(
  "if Instant::now() >= coordination_deadline",
);
const prepareSystemProcessPathOrder = [
  "reject_thread_impersonation()?",
  "query_system_path(GetSystemWindowsDirectoryW)?",
  "query_system_path(GetSystemDirectoryW)?",
  "validate_existing_reparse_free_directory(&windows_root)?",
  "validate_existing_reparse_free_directory(&current_directory)?",
  "validate_system_directory_layout(&windows_root, &current_directory)?",
  "reject_thread_impersonation()?",
  "Ok(SystemProcessPaths {",
].map((marker, index) =>
  prepareSystemProcessPaths.indexOf(
    marker,
    index === 6
      ? prepareSystemProcessPaths.indexOf(marker) + marker.length
      : undefined,
  ),
);
const plainAbsoluteDosPathOrder = [
  "encoded.contains(&u16::from(b'/'))",
  ".split(|unit| *unit == u16::from(b'\\\\'))",
  "part == [u16::from(b'.')]",
  "part == [u16::from(b'.'), u16::from(b'.')]",
  "Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::Disk(_))",
  "Some(Component::RootDir)",
  "components.all(|component| matches!(component, Component::Normal(_)))",
].map((marker) => plainAbsoluteDosPath.indexOf(marker));
const validateExistingDirectoryOrder = [
  "!plain_absolute_dos_path(path)",
  "fs::metadata(path)",
  ".is_dir()",
  "path.ancestors().collect::<Vec<_>>().into_iter().rev()",
  "reject_reparse_directory(ancestor)?",
].map((marker) => validateExistingReparseFreeDirectory.indexOf(marker));
const restrictedEnvironmentOrder = [
  "if !plain_absolute_dos_path(windows_root)",
  "if value.is_empty() || value.contains(&0)",
  ".checked_mul(2)",
  ".checked_add(24)",
  'for name in ["SystemRoot=", "WINDIR="]',
  "block.extend(name.encode_utf16())",
  "block.extend_from_slice(&value)",
  "block.push(0)",
  "block.push(0)",
  "if block.len() > MAX_ENVIRONMENT_UNITS",
  "Ok(block)",
].map((marker, index) =>
  minimalRestrictedEnvironment.indexOf(
    marker,
    index === 8
      ? minimalRestrictedEnvironment.indexOf(marker) + marker.length
      : undefined,
  ),
);
requireInvariant(
  (
    rustLexicalCode(platformWindowsLib).match(
      /#\s*\[\s*cfg\s*\(\s*windows\s*\)\s*\]\s*mod\s+restricted_process_context\s*;/gu,
    ) ?? []
  ).length === 1 &&
    !/\bpub(?:\([^)]*\))?\s+mod\s+restricted_process_context\b/u.test(
      rustLexicalCode(platformWindowsLib),
    ) &&
    !/\bpub(?:\([^)]*\))?\s+use\s+[^;]*\brestricted_process_context\b/u.test(
      rustLexicalCode(platformWindowsLib),
    ) &&
    normalizeRustFragment(rustLexicalCode(restrictedProcessContextDefinition)) ===
      "pub(crate) struct RestrictedProcessContext { environment: Box<[u16]>, current_directory: Box<[u16]>, _same_thread: PhantomData<Rc<()>>, }" &&
    normalizeRustFragment(rustLexicalCode(systemProcessPathsDefinition)) ===
      "struct SystemProcessPaths { windows_root: PathBuf, current_directory: PathBuf, }" &&
    JSON.stringify(restrictedContextPublicMethods) ===
      JSON.stringify([
        "prepare",
        "prepare_for_kernel_test",
        "environment",
        "current_directory",
        "recheck_thread",
      ]) &&
    normalizeRustFragment(
      rustLexicalCode(restrictedContextEnvironmentAccessor),
    ) ===
      "pub(crate) fn environment(&self) -> &[u16] { &self.environment }" &&
    normalizeRustFragment(rustLexicalCode(restrictedContextDirectoryAccessor)) ===
      "pub(crate) fn current_directory(&self) -> &[u16] { &self.current_directory }" &&
    !/#\s*\[\s*derive\s*\([^\]]*\b(?:Clone|Copy|Default)\b[^\]]*\)\s*\]\s*(?:#\s*\[[^\]]*\]\s*)*pub\(crate\)\s+struct\s+RestrictedProcessContext\b/u.test(
      restrictedProcessContext,
    ) &&
    !/\bimpl\s+(?:Clone|Copy|Default)\s+for\s+RestrictedProcessContext\b/u.test(
      rustLexicalCode(restrictedProcessContextProduction),
    ) &&
    !/\bunsafe\s+impl\s+(?:Send|Sync)\s+for\s+RestrictedProcessContext\b/u.test(
      rustLexicalCode(restrictedProcessContextProduction),
    ) &&
    !/\bimpl(?:\s*<[^>{}]*>)?\s+[^{};\r\n]+\s+for\s+RestrictedProcessContext\b/u.test(
      rustLexicalCode(restrictedProcessContextProduction),
    ) &&
    ["Send", "Sync", "Clone", "Copy"].every((traitName) =>
      restrictedContextTraitTest.includes(
        `<RestrictedProcessContext as AmbiguousIf${traitName}<_>>::marker`,
      ),
    ) &&
    !/\bimpl(?:\s*<[^>{}]*>)?\s+(?:AsRef|AsMut|Borrow|BorrowMut|Deref|DerefMut)\b[\s\S]{0,160}\bfor\s+RestrictedProcessContext\b/u.test(
      rustLexicalCode(restrictedProcessContextProduction),
    ) &&
    !/\bpub\(crate\)\s+fn\s+[A-Za-z_]\w*(?:raw|path|handle)[A-Za-z_]\w*\s*\(/u.test(
      rustLexicalCode(restrictedProcessContextImplementation),
    ) &&
    JSON.stringify([...restrictedContextConsumers].sort()) ===
      JSON.stringify([
        "crates/platform-windows/src/key_agent_activation.rs",
        "crates/platform-windows/src/launch.rs",
      ]) &&
    restrictedContextPrepareCallSites.length === 2 &&
    restrictedContextPrepareCallSites.every(
      (call) => call.arguments.length === 0,
    ) &&
    JSON.stringify(
      restrictedContextPrepareCallSites.map((call) => call.path).sort(),
    ) ===
      JSON.stringify([
        "crates/platform-windows/src/key_agent_activation.rs",
        "crates/platform-windows/src/launch.rs",
      ]) &&
    !platformWindowsProductionFiles.some((file) =>
      /\bRestrictedProcessContext\s+as\s+[A-Za-z_]\w*/u.test(
        rustLexicalCode(file.source),
      ),
    ),
  "the restricted Windows process context must remain private, opaque, thread-affine, zero-input, and consumed only by the two approved launchers",
);
requireInvariant(
  normalizeRustFragment(rustLexicalCode(restrictedContextPrepare)) ===
    "pub(crate) fn prepare() -> Result<Self, RestrictedProcessContextError> { let paths = prepare_system_process_paths()?; reject_replaceable_ancestors(&paths.windows_root)?; reject_replaceable_ancestors(&paths.current_directory)?; reject_content_writable_directory(&paths.windows_root)?; reject_content_writable_directory(&paths.current_directory)?; reject_thread_impersonation()?; Self::from_system_paths(&paths) }" &&
    /#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]\s*pub\(crate\)\s+fn\s+prepare_for_kernel_test\s*\(\s*\)/u.test(
      rustLexicalCode(restrictedProcessContext),
    ) &&
    normalizeRustFragment(rustLexicalCode(restrictedContextKernelPrepare)) ===
      "pub(crate) fn prepare_for_kernel_test() -> Result<Self, RestrictedProcessContextError> { let paths = prepare_system_process_paths()?; Self::from_system_paths(&paths) }" &&
    !/\bprepare_for_kernel_test\b/u.test(
      rustLexicalCode(restrictedProcessContextProduction),
    ) &&
    !/\bprepare_with_directory_policy\b|\breject_(?:writable|dangerous|content|replaceable)[A-Za-z_]*\s*:\s*bool\b|\bif\s+reject_writable\b/u.test(
      rustLexicalCode(restrictedProcessContextProduction),
    ) &&
    normalizeRustFragment(rustLexicalCode(restrictedContextFromPaths)) ===
      "fn from_system_paths( paths: &SystemProcessPaths, ) -> Result<Self, RestrictedProcessContextError> { Ok(Self { environment: minimal_environment_block(&paths.windows_root)?.into_boxed_slice(), current_directory: wide_nul_path(&paths.current_directory).into_boxed_slice(), _same_thread: PhantomData, }) }" &&
    normalizeRustFragment(rustLexicalCode(preparedKeyAgentProcessDefinition)) ===
      "struct PreparedKeyAgentProcess { application: Vec<u16>, context: RestrictedProcessContext, environment: Box<[u16]>, lpac: PreparedKeyAgentLpac, }" &&
    /#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]\s*let\s+context\s*=\s*RestrictedProcessContext::prepare_for_kernel_test\(\s*\)\s*;/u.test(
      rustLexicalCode(prepareKeyAgentProcess),
    ) &&
    /#\s*\[\s*cfg\s*\(\s*not\s*\(\s*test\s*\)\s*\)\s*\]\s*let\s+context\s*=\s*RestrictedProcessContext::prepare\(\s*\)\s*;/u.test(
      rustLexicalCode(prepareKeyAgentProcess),
    ) &&
    (prepareKeyAgentProcessRelease.match(
      /\bRestrictedProcessContext::prepare_for_kernel_test\(\s*\)/gu,
    ) ?? []).length === 1 &&
    (prepareKeyAgentProcessRelease.match(
      /\bRestrictedProcessContext::prepare\(\s*\)/gu,
    ) ?? []).length === 1 &&
    (keyAgentActivationRelease.match(/\bprepare_for_kernel_test\b/gu) ?? [])
      .length === 1 &&
    JSON.stringify(
      platformWindowsProductionFiles
        .map((file) => ({
          path: file.path,
          count: (rustLexicalCode(file.source).match(
            /\bprepare_for_kernel_test\b/gu,
          ) ?? []).length,
        }))
        .filter((file) => file.count > 0),
    ) ===
      JSON.stringify([
        {
          path: "crates/platform-windows/src/key_agent_activation.rs",
          count: 1,
        },
      ]),
  "production context preparation must always enforce the replacement-ancestor and protected-directory content gates while the narrower kernel-test bypass remains structurally cfg(test)-only",
);
requireInvariant(
  systemDirectoryApiInventory.length === 4 &&
    systemDirectoryApiInventory.every(
      (entry) =>
        entry.path ===
        "crates/platform-windows/src/restricted_process_context.rs",
    ) &&
    systemDirectoryApiInventory.filter(
      (entry) => entry.api === "GetSystemWindowsDirectoryW",
    ).length === 2 &&
    systemDirectoryApiInventory.filter(
      (entry) => entry.api === "GetSystemDirectoryW",
    ).length === 2 &&
    !platformWindowsProductionFiles.some((file) =>
      /\b(?:GetSystemWindowsDirectoryW|GetSystemDirectoryW)\s+as\s+[A-Za-z_]\w*/u.test(
        rustLexicalCode(file.source),
      ),
    ) &&
    forbiddenAmbientDirectoryApis.length === 0 &&
    !/\bstd\s*::\s*env\b/u.test(
      rustLexicalCode(restrictedProcessContextProduction),
    ) &&
    !/\bstd\s*::\s*env\b/u.test(
      rustLexicalCode(
        `${restrictedLaunchLeaf}\n${prepareKeyAgentProcessRelease}\n${keyAgentCreateProcess}`,
      ),
    ) &&
    prepareSystemPathQueries.length === 2 &&
    prepareSystemPathQueries[0]?.arguments[0] ===
      "GetSystemWindowsDirectoryW" &&
    prepareSystemPathQueries[1]?.arguments[0] === "GetSystemDirectoryW" &&
    prepareSystemPathQueries.every((call) => call.arguments.length === 1) &&
    prepareSystemProcessPathOrder.every((position) => position !== -1) &&
    prepareSystemProcessPathOrder
      .slice(1)
      .every(
        (position, index) => position > prepareSystemProcessPathOrder[index],
      ) &&
    querySystemPath.includes(
      "let mut buffer = vec![0_u16; MAX_SYSTEM_PATH_UNITS]",
    ) &&
    querySystemPath.includes("let length = unsafe { getter(Some(&mut buffer)) }") &&
    querySystemPath.includes(
      "if length == 0 || length >= buffer.len() || buffer[..length].contains(&0)",
    ) &&
    querySystemPath.includes(
      "PathBuf::from(OsString::from_wide(&buffer[..length]))",
    ),
  "restricted child paths must use only the exact unaliased system Windows/System32 APIs and reject ambient environment/current-directory APIs",
);
requireInvariant(
  plainAbsoluteDosPathOrder.every((position) => position !== -1) &&
    plainAbsoluteDosPathOrder
      .slice(1)
      .every((position, index) => position > plainAbsoluteDosPathOrder[index]),
  "restricted child paths must remain plain local absolute DOS paths without slash or dot-component ambiguity",
);
requireInvariant(
    validateExistingDirectoryOrder.every((position) => position !== -1) &&
    validateExistingDirectoryOrder
      .slice(1)
      .every(
        (position, index) => position > validateExistingDirectoryOrder[index],
      ) &&
    rejectReparseDirectory.includes("fs::symlink_metadata(path)") &&
    rejectReparseDirectory.includes(
      "metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0",
    ),
  "restricted child paths must exist as directories and every ancestor must remain reparse-free",
);
requireInvariant(
    normalizeRustFragment(rustLexicalCode(rejectReplaceableAncestors)) ===
      "fn reject_replaceable_ancestors(path: &Path) -> Result<(), RestrictedProcessContextError> { for ancestor in path.ancestors().collect::<Vec<_>>().into_iter().rev() { reject_dangerous_directory_rights(ancestor, &PATH_REPLACEMENT_RIGHTS)?; } Ok(()) }" &&
    normalizeRustFragment(
      rustLexicalCode(rejectContentWritableDirectory),
    ) ===
      "fn reject_content_writable_directory(path: &Path) -> Result<(), RestrictedProcessContextError> { reject_dangerous_directory_rights(path, &PROTECTED_DIRECTORY_CONTENT_RIGHTS) }",
  "restricted child path replacement and protected-directory content checks must remain separate exact leaves",
);
requireInvariant(
    systemLayoutOrdinalCalls.length === 2 &&
    JSON.stringify(systemLayoutOrdinalCalls[0]?.arguments) ===
      JSON.stringify(["parent.as_os_str()", "windows_root.as_os_str()"]) &&
    JSON.stringify(systemLayoutOrdinalCalls[1]?.arguments) ===
      JSON.stringify(["leaf", 'OsStr::new("System32")']) &&
    compactRust(validateSystemDirectoryLayout).indexOf(
      "system_directory.parent()",
    ) <
      compactRust(validateSystemDirectoryLayout).indexOf(
        "system_directory.file_name()",
      ) &&
    compareStringOrdinalCalls.length === 1 &&
    JSON.stringify(compareStringOrdinalCalls[0]?.arguments) ===
      JSON.stringify(["&first", "&second", "true"]) &&
    restrictedContextOrdinalEq.includes("== CSTR_EQUAL"),
  "restricted child System32 must remain the immediate ordinal-case-insensitive child of the OS-reported Windows directory",
);
requireInvariant(
  /\bconst\s+PATH_REPLACEMENT_RIGHTS\s*:\s*\[u32;\s*4\]\s*=\s*\[\s*FILE_DELETE_CHILD\.0\s*,\s*DELETE\.0\s*,\s*WRITE_DAC\.0\s*,\s*WRITE_OWNER\.0\s*,?\s*\]\s*;/u.test(
    rustLexicalCode(restrictedProcessContextProduction),
  ) &&
    /\bconst\s+PROTECTED_DIRECTORY_CONTENT_RIGHTS\s*:\s*\[u32;\s*2\]\s*=\s*\[\s*FILE_ADD_FILE\.0\s*,\s*FILE_ADD_SUBDIRECTORY\.0\s*,?\s*\]\s*;/u.test(
      rustLexicalCode(restrictedProcessContextProduction),
    ) &&
    replaceableAncestorPrepareCalls.length === 2 &&
    JSON.stringify(
      replaceableAncestorPrepareCalls.map((call) => call.arguments),
    ) ===
      JSON.stringify([
        ["&paths.windows_root"],
        ["&paths.current_directory"],
      ]) &&
    protectedContentPrepareCalls.length === 2 &&
    JSON.stringify(protectedContentPrepareCalls.map((call) => call.arguments)) ===
      JSON.stringify([
        ["&paths.windows_root"],
        ["&paths.current_directory"],
      ]) &&
    replacementRightsLeafCalls.length === 1 &&
    JSON.stringify(replacementRightsLeafCalls[0]?.arguments) ===
      JSON.stringify(["ancestor", "&PATH_REPLACEMENT_RIGHTS"]) &&
    protectedContentRightsLeafCalls.length === 1 &&
    JSON.stringify(protectedContentRightsLeafCalls[0]?.arguments) ===
      JSON.stringify(["path", "&PROTECTED_DIRECTORY_CONTENT_RIGHTS"]) &&
    (rustLexicalCode(restrictedProcessContextProduction).match(
      /\breject_dangerous_directory_rights\b/gu,
    ) ?? []).length === 3 &&
    dangerousDirectoryOpenCalls.length === 1 &&
    JSON.stringify(dangerousDirectoryOpenCalls[0]?.arguments) ===
      JSON.stringify([
        "PCWSTR(wide.as_ptr())",
        "right",
        "FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE",
        "None",
        "OPEN_EXISTING",
        "FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT",
        "None",
      ]) &&
    rejectDangerousDirectoryRights.includes(
      "for right in dangerous_rights.iter().copied()",
    ) &&
    rejectDangerousDirectoryRights.includes("let _ = CloseHandle(handle)") &&
    rejectDangerousDirectoryRights.includes(
      "return Err(RestrictedProcessContextError::UnsafeWorkingDirectory)",
    ) &&
    rejectDangerousDirectoryRights.includes(
      "Err(error) if error.code() == ERROR_ACCESS_DENIED.to_hresult() => {}",
    ) &&
    rejectDangerousDirectoryRights.includes(
      "Err(_) => return Err(RestrictedProcessContextError::OperatingSystem)",
    ) &&
    openThreadTokenCalls.length === 1 &&
    JSON.stringify(openThreadTokenCalls[0]?.arguments) ===
      JSON.stringify([
        "GetCurrentThread()",
        "TOKEN_QUERY",
        "true",
        "&raw mut token",
      ]) &&
    rejectThreadImpersonation.includes(
      "token.is_invalid() || token == INVALID_HANDLE_VALUE",
    ) &&
    rejectThreadImpersonation.includes("let _ = CloseHandle(token)") &&
    rejectThreadImpersonation.includes(
      "Err(RestrictedProcessContextError::ThreadImpersonation)",
    ) &&
    rejectThreadImpersonation.includes(
      "ERROR_NO_TOKEN.to_hresult() => Ok(())",
    ) &&
    restrictedContextRecheck.includes(
      "!self.environment.ends_with(&[0, 0])",
    ) &&
    restrictedContextRecheck.includes(
      "self.current_directory.last() != Some(&0)",
    ) &&
    restrictedContextRecheck.indexOf("reject_thread_impersonation()") >
      restrictedContextRecheck.indexOf("self.current_directory.last()") &&
    restrictedContextRightSetsTest.includes(
      "PATH_REPLACEMENT_RIGHTS,\n            [FILE_DELETE_CHILD.0, DELETE.0, WRITE_DAC.0, WRITE_OWNER.0]",
    ) &&
    restrictedContextRightSetsTest.includes(
      "PROTECTED_DIRECTORY_CONTENT_RIGHTS,\n            [FILE_ADD_FILE.0, FILE_ADD_SUBDIRECTORY.0]",
    ) &&
    restrictedContextRightSetsTest.includes(
      ".all(|right| !PROTECTED_DIRECTORY_CONTENT_RIGHTS.contains(right))",
    ),
  "restricted child context must reject replacement rights on every ancestor, content rights only on Windows/System32, and thread impersonation without a release switch",
);
requireInvariant(
  /\bconst\s+MAX_SYSTEM_PATH_UNITS\s*:\s*usize\s*=\s*32_768\s*;/u.test(
    rustLexicalCode(restrictedProcessContextProduction),
  ) &&
    /\bconst\s+MAX_ENVIRONMENT_UNITS\s*:\s*usize\s*=\s*32_767\s*;/u.test(
      rustLexicalCode(restrictedProcessContextProduction),
    ) &&
    restrictedEnvironmentOrder.every((position) => position !== -1) &&
    restrictedEnvironmentOrder
      .slice(1)
      .every((position, index) => position > restrictedEnvironmentOrder[index]) &&
    (minimalRestrictedEnvironment.match(/"SystemRoot="/gu) ?? []).length === 1 &&
    (minimalRestrictedEnvironment.match(/"WINDIR="/gu) ?? []).length === 1 &&
    environmentNulPushes.length === 2 &&
    environmentNulPushes.every(
      (call) =>
        call.arguments.length === 1 && compactRust(call.arguments[0]) === "0",
    ) &&
    normalizeRustFragment(rustLexicalCode(wideNulRestrictedPath)) ===
      "fn wide_nul_path(path: &Path) -> Vec<u16> { path.as_os_str() .encode_wide() .chain(core::iter::once(0)) .collect() }" &&
    restrictedContextFromPaths.indexOf(
      "minimal_environment_block(&paths.windows_root)",
    ) <
      restrictedContextFromPaths.indexOf(
        "wide_nul_path(&paths.current_directory)",
      ) &&
    restrictedEnvironmentAllowlistTest.includes("block.ends_with(&[0, 0])") &&
    restrictedEnvironmentAllowlistTest.includes(
      '[r"SystemRoot=C:\\Windows", r"WINDIR=C:\\Windows"]',
    ) &&
    [
      '"PATH"',
      '"TEMP"',
      '"TMP"',
      '"USERPROFILE"',
      '"HTTP_PROXY"',
      '"HTTPS_PROXY"',
      '"AUTHORIZATION"',
      '"PASSWORD"',
      '"SECRET"',
      '"TOKEN"',
    ].every((name) => restrictedEnvironmentAllowlistTest.includes(name)) &&
    restrictedEnvironmentBoundsTest.includes(
      "minimal_environment_block(&interior_nul)",
    ) &&
    restrictedEnvironmentBoundsTest.includes(
      "let maximum_root_units = (MAX_ENVIRONMENT_UNITS - 21) / 2",
    ) &&
    restrictedEnvironmentBoundsTest.includes(
      "Ok(MAX_ENVIRONMENT_UNITS)",
    ) &&
    restrictedEnvironmentBoundsTest.includes(
      "minimal_environment_block(&oversized_root)",
    ) &&
    (restrictedEnvironmentBoundsTest.match(
      /Err\(RestrictedProcessContextError::OperatingSystem\)/gu,
    ) ?? []).length === 2,
  "restricted child environment storage must remain the bounded SystemRoot-then-WINDIR double-NUL Unicode allowlist",
);
requireInvariant(
  restrictedLaunchCompact.includes(
    "validate_live_handle(handles.input)?;validate_live_handle(handles.output)?;validate_live_handle(handles.error)?;letprocess_context=RestrictedProcessContext::prepare().map_err(map_process_context_error)?;",
  ) &&
    restrictedLaunchContextPreparationOrder.every(
      (position) => position !== -1,
    ) &&
    restrictedLaunchContextPreparationOrder
      .slice(1)
      .every(
        (position, index) =>
          position > restrictedLaunchContextPreparationOrder[index],
    ) &&
    keyAgentCreateInner.indexOf(
      "let prepared_process = prepare_key_agent_process(artifact, provisioning)?",
    ) !== -1 &&
    keyAgentCreateInner.indexOf(
      "let prepared_process = prepare_key_agent_process(artifact, provisioning)?",
    ) <
      keyAgentCreateInner.indexOf(
        "acquire_inheritable_handle_launch(coordination_deadline)",
      ) &&
    compactRust(keyAgentCreateInner).includes(
      "create_suspended_debuggee_process(&flight,&prepared_process,",
    ) &&
    keyAgentCreateProcess.includes(
      "prepared_process: &PreparedKeyAgentProcess",
    ) &&
    !/\bartifact\s*:\s*&VerifiedHelper\b/u.test(
      rustLexicalCode(keyAgentCreateProcess),
    ),
  "restricted launch must prepare context immediately after initial stdio validation and before parent proof, LPAC profile, Job, application, deadline, or flight work; Key Agent must likewise prepare before its flight",
);
requireInvariant(
  restrictedLaunchCreateCalls.length === 1 &&
    restrictedLaunchCreateCalls[0]?.arguments.length === 7 &&
    compactRust(restrictedLaunchCreateCalls[0]?.arguments[2] ?? "") ===
      "EXTENDED_STARTUPINFO_PRESENT|CREATE_SUSPENDED|CREATE_UNICODE_ENVIRONMENT" &&
    compactRust(restrictedLaunchCreateCalls[0]?.arguments[3] ?? "") ===
      "Some(process_context.environment().as_ptr().cast::<c_void>())" &&
    compactRust(restrictedLaunchCreateCalls[0]?.arguments[4] ?? "") ===
      "PCWSTR(process_context.current_directory().as_ptr())" &&
    keyAgentCreateCalls.length === 1 &&
    keyAgentCreateCalls[0]?.arguments.length === 7 &&
    compactRust(keyAgentCreateCalls[0]?.arguments[0] ?? "") ===
      "PCWSTR(prepared_process.application.as_ptr())" &&
    compactRust(keyAgentCreateCalls[0]?.arguments[2] ?? "") ===
      "key_agent_creation_flags()" &&
    compactRust(keyAgentCreateCalls[0]?.arguments[3] ?? "") ===
      "Some(prepared_process.environment.as_ptr().cast::<c_void>())" &&
    compactRust(keyAgentCreateCalls[0]?.arguments[4] ?? "") ===
      "PCWSTR(prepared_process.context.current_directory().as_ptr())",
  "both restricted launchers must pass the owned explicit Unicode environment and non-null current directory to the sole coordinated process-create call",
);
requireInvariant(
  (restrictedLaunchLeaf.match(/\.recheck_thread\(\)/gu) ?? []).length === 1 &&
    restrictedLaunchFinalContextGap ===
      "process_context.recheck_thread().map_err(map_process_context_error)?;letmutprocess_information=PROCESS_INFORMATION::default();unsafe{flight" &&
    (keyAgentCreateProcess.match(/\.recheck_thread\(\)/gu) ?? []).length === 1 &&
    keyAgentFinalContextGap ===
      "prepared_process.context.recheck_thread().map_err(|_|KeyAgentActivationError::ProcessContextPolicy)?;unsafe{flight",
  "both restricted launchers must make the thread-context recheck the final operation immediately before the coordinated process-create call",
);
requireInvariant(
  restrictedContextKernelTest.includes(
    "RestrictedProcessContext::prepare_for_kernel_test()?",
  ) &&
    restrictedContextKernelTest.includes("environment.ends_with(&[0, 0])") &&
    restrictedContextKernelTest.includes(
      "environment.iter().filter(|unit| **unit == 0).count(), 3",
    ) &&
    restrictedContextKernelTest.includes(
      "context.current_directory().last(), Some(&0)",
    ) &&
    restrictedContextKernelTest.includes("context.recheck_thread()") &&
    restrictedContextImpersonationTest.includes(
      "ImpersonateSelf(SecurityImpersonation)?",
    ) &&
    restrictedContextImpersonationTest.includes(
      "RestrictedProcessContext::prepare_for_kernel_test()",
    ) &&
    (restrictedContextImpersonationTest.match(
      /\bcontext\.recheck_thread\(\)/gu,
    ) ?? []).length === 2 &&
    restrictedContextImpersonationOrder.every((position) => position !== -1) &&
    restrictedContextImpersonationOrder
      .slice(1)
      .every(
        (position, index) =>
          position > restrictedContextImpersonationOrder[index],
      ) &&
    restrictedContextImpersonationTest.includes(
      "Err(RestrictedProcessContextError::ThreadImpersonation)",
    ) &&
    restrictedWorkingDirectoryTest.includes(
      'validate_working_directory_for_test(Path::new("relative"))',
    ) &&
    restrictedWorkingDirectoryTest.includes(
      "validate_working_directory_for_test(&current)",
    ) &&
    keyAgentSuccessfulKernelTest.includes(
      "activate_for_test(attestation, artifact",
    ) &&
    keyAgentActivateForTest.includes(
      "activate_preflighted_key_agent_on_fresh_worker(",
    ) &&
    keyAgentProductionActivationForContext.includes(
      "sys::SuspendedDebuggee::create(",
    ) &&
    keyAgentCreateInner.includes("create_suspended_debuggee_process(") &&
    keyAgentCreateProcess.includes(
      ".create_process_with_explicit_handle_list(",
    ),
  "the cfg(test) context bypass must retain policy coverage and at least one kernel proof must still traverse the actual coordinated Key Agent creation path",
);
requireInvariant(
  platformWindowsLib.includes("#[cfg(windows)]\nmod inheritable_handle_launch;") &&
    !/pub(?:\([^)]*\))?\s+(?:mod|use)\s+[^;]*inheritable_handle_launch/u.test(
      platformWindowsLib,
    ) &&
    (inheritableHandleLaunch.match(
      /static PROCESS_WIDE_INHERITABLE_LAUNCH:/gu,
    ) ?? []).length === 1 &&
    /^struct InheritableHandleLaunchCoordinator\s*\{\s*occupied: AtomicBool,\s*poisoned: AtomicBool,\s*generation: AtomicU64,\s*active_generation: AtomicU64,\s*waiters: AtomicUsize,\s*\}$/u.test(
      inheritableCoordinatorDefinition,
    ) &&
    inheritableCoordinatorImplementation.includes(
      "occupied: AtomicBool::new(false)",
    ) &&
    inheritableCoordinatorImplementation.includes(
      "poisoned: AtomicBool::new(false)",
    ) &&
    inheritableCoordinatorImplementation.includes("generation: AtomicU64::new(0)") &&
    inheritableCoordinatorImplementation.includes(
      "active_generation: AtomicU64::new(0)",
    ) &&
    inheritableCoordinatorImplementation.includes("waiters: AtomicUsize::new(0)") &&
    /thread_local!\s*\{\s*static OWNED_COORDINATORS:\s*Cell<\[usize; 4\]>\s*=\s*const\s*\{\s*Cell::new\(\[0; 4\]\)\s*\};\s*\}/u.test(
      inheritableHandleLaunch,
    ) &&
    !/\b(?:Mutex|Condvar|RefCell)\b/u.test(inheritableHandleLaunch) &&
    inheritableHandleLaunch.includes("InheritableHandleLaunchError::Reentrant") &&
    inheritableHandleLaunch.includes("InheritableHandleLaunchError::Poisoned") &&
    /^pub\(crate\) struct InheritableHandleLaunchFlight<'coordinator>\s*\{\s*coordinator: &'coordinator InheritableHandleLaunchCoordinator,\s*owner: ThreadId,\s*generation: u64,\s*deadline: Instant,\s*_not_send_or_sync: PhantomData<Rc<\(\)>>,\s*\}$/u.test(
      inheritableFlightDefinition,
    ) &&
    coordinatorAcquireOrder.every((position) => position !== -1) &&
    coordinatorAcquireOrder
      .slice(1)
      .every((position, index) => position > coordinatorAcquireOrder[index]) &&
    coordinatorAcquire.includes("waiters.checked_add(1)") === false &&
    coordinatorWaiterRegister.includes("waiters.checked_add(1)") &&
    inheritableHandleLaunch.includes("waiters.checked_sub(1)") &&
    flightAdmissionOrder.every((position) => position !== -1) &&
    flightAdmissionOrder
      .slice(1)
      .every((position, index) => position > flightAdmissionOrder[index]) &&
    /->\s*Result<\(\), InheritableHandleCreateError>\s*\{\s*self\.validate_create_admission\(\)\?;/u.test(
      rustLexicalCode(inheritableCreateProcessLeaf),
    ) &&
    inheritableCreateProcessLeaf.indexOf("self.validate_create_admission()?") <
      inheritableCreateProcessLeaf.indexOf("CreateProcessW(") &&
    coordinatorReleaseOrder.every((position) => position !== -1) &&
    coordinatorReleaseOrder
      .slice(1)
      .every((position, index) => position > coordinatorReleaseOrder[index]) &&
    inheritableHandleLaunch.includes(
      ".release(self.owner, self.generation, std::thread::panicking())",
    ) &&
    inheritableHandleLaunch.includes(
      "CreateProcessW(\n                application_name,",
    ) &&
    inheritableHandleLaunch.includes(
      "None,\n                None,\n                true,",
    ) &&
    JSON.stringify(coordinatorTests) === JSON.stringify(expectedCoordinatorTests) &&
    inheritableHandleLaunchSource.includes("wait_until_waiter_is_parked") &&
    rustFunctionBlock(
      inheritableHandleLaunchSource,
      "local_coordinator_never_overlaps_many_contenders",
    ).includes("const THREADS: usize = 8") &&
    rustFunctionBlock(
      inheritableHandleLaunchSource,
      "local_coordinator_never_overlaps_many_contenders",
    ).includes("const FLIGHTS_PER_THREAD: usize = 64") &&
    !/unsafe\s+impl\s+(?:Send|Sync)|impl\s+(?:Clone|Copy)\s+for\s+InheritableHandleLaunchFlight|#\[derive\([^\]]*\b(?:Clone|Copy)\b[^\]]*\)\]\s*(?:pub\(crate\)\s+)?struct\s+InheritableHandleLaunchFlight/u.test(
      inheritableHandleLaunch,
    ) &&
    JSON.stringify(duplicateHandleInventory) ===
      JSON.stringify(expectedDuplicateHandleInventory) &&
    JSON.stringify(setHandleInformationInventory) ===
      JSON.stringify(expectedSetHandleInformationInventory) &&
    JSON.stringify(securityAttributesInventory) ===
      JSON.stringify(expectedSecurityAttributesInventory) &&
    aliasedInheritableHandleApis.length === 0 &&
    alternativeSecurityAttributesInitialization.length === 0 &&
    rustCallSites(restrictedInheritableDuplicateLeaf, "DuplicateHandle").length ===
      1 &&
    rustCallSites(restrictedInheritableDuplicateLeaf, "DuplicateHandle")[0]
      ?.arguments[5] === "true" &&
    restrictedInheritableDuplicateLeaf.includes(
      "_flight: &InheritableHandleLaunchFlight<'_>",
    ) &&
    rustCallSites(keyAgentInheritableDuplicateLeaf, "DuplicateHandle").length === 1 &&
    rustCallSites(keyAgentInheritableDuplicateLeaf, "DuplicateHandle")[0]
      ?.arguments[5] === "true" &&
    keyAgentInheritableDuplicateLeaf.includes(
      "_flight: &InheritableHandleLaunchFlight<'_>",
    ) &&
    brokerInheritedParentDefinition.includes(
      "flight: &'flight InheritableHandleLaunchFlight<'static>",
    ) &&
    rustCallSites(brokerInheritedParentLeaf, "DuplicateHandle").length === 1 &&
    rustCallSites(brokerInheritedParentLeaf, "DuplicateHandle")[0]?.arguments[5] ===
      "true" &&
    /flight:\s*&'flight InheritableHandleLaunchFlight<'static>/u.test(
      brokerInheritedParentLeaf,
    ) &&
    brokerInheritedParentLeaf.includes("Ok(Self { handle, flight })") &&
    brokerInheritedParentLeaf.includes("let _ = self.flight") &&
    brokerInheritedNullDefinition.includes(
      "flight: &'flight InheritableHandleLaunchFlight<'static>",
    ) &&
    rustCallSites(brokerInheritedNullLeaf, "SetHandleInformation").length === 1 &&
    rustCallSites(brokerInheritedNullLeaf, "SetHandleInformation")[0]?.arguments[2] ===
      "HANDLE_FLAG_INHERIT" &&
    /flight:\s*&'flight InheritableHandleLaunchFlight<'static>/u.test(
      brokerInheritedNullLeaf,
    ) &&
    brokerInheritedNullLeaf.includes("Ok(Self { handle, flight })") &&
    brokerInheritedNullLeaf.includes("let _ = self.flight") &&
    inheritedStdioConstructor.match(/sys::validate_handle\(/gu)?.length === 3 &&
    secretInputStdioConstructor.match(/sys::validate_live_handle\(/gu)?.length === 3 &&
    validateRestrictedSourceHandle.includes(
      "flags & HANDLE_FLAG_INHERIT.0 != 0",
    ) &&
    validateRestrictedSourceHandle.includes("Err(LaunchError::InvalidHandle)") &&
    restrictedLaunchLeaf.match(/validate_live_handle\(handles\.(?:input|output|error)\)\?/gu)
      ?.length === 6 &&
    restrictedLateSourceChecks.every(
      (position) => position > restrictedAcquireIndex,
    ) &&
    restrictedLateSourceChecks.every(
      (position) =>
        position < restrictedLaunchLeaf.indexOf("InheritableDuplicates::new(&flight)"),
    ) &&
    inheritableStdioSourceTestOrder.every((position) => position !== -1) &&
    inheritableStdioSourceTestOrder.every(
      (position, index, positions) => index === 0 || positions[index - 1] < position,
    ) &&
    (inheritableStdioSourceTest.match(/Err\(LaunchError::InvalidHandle\)/gu) ?? [])
      .length === 2 &&
    prepareKeyAgentInheritance.includes(
      "fn prepare_child_inheritance<'pipes, 'flight>",
    ) &&
    prepareKeyAgentInheritance.includes("&'pipes self") &&
    prepareKeyAgentInheritance.includes(
      "flight: &'flight crate::inheritable_handle_launch::InheritableHandleLaunchFlight<'static>",
    ) &&
    prepareKeyAgentInheritance.includes(
      "Result<PreparedKeyAgentInheritance<'pipes, 'flight>, PipeError>",
    ) &&
    preparedKeyAgentInheritanceBlock.includes(
      "owner: PhantomData<&'pipes PrivateKeyAgentPipes>",
    ) &&
    preparedKeyAgentInheritanceBlock.includes(
      "flight: &'flight crate::inheritable_handle_launch::InheritableHandleLaunchFlight<'static>",
    ) &&
    JSON.stringify(coordinatorConsumers) ===
      JSON.stringify([
        "crates/platform-windows/src/broker_supervisor.rs",
        "crates/platform-windows/src/key_agent_activation.rs",
        "crates/platform-windows/src/launch.rs",
      ]) &&
    JSON.stringify(coordinatorCreateConsumers) ===
      JSON.stringify(coordinatorConsumers) &&
    JSON.stringify(coordinatorAcquireCallSites) ===
      JSON.stringify(coordinatorConsumers) &&
    JSON.stringify(coordinatorCreateCallSites) ===
      JSON.stringify(coordinatorConsumers) &&
    restrictedLaunchLeaf.indexOf("if Instant::now() >= coordination_deadline") >
      restrictedLaunchLeaf.indexOf(
        "acquire_inheritable_handle_launch(coordination_deadline)",
      ) &&
    restrictedLaunchLeaf.indexOf("if Instant::now() >= coordination_deadline") <
      restrictedLaunchLeaf.indexOf("InheritableDuplicates::new(&flight)") &&
    restrictedDeadlineChecks.length === 2 &&
    restrictedDeadlineChecks[1] <
      restrictedLaunchLeaf.indexOf(".create_process_with_explicit_handle_list(") &&
    keyAgentCreateInner.indexOf("if Instant::now() >= coordination_deadline") >
      keyAgentCreateInner.indexOf(
        "acquire_inheritable_handle_launch(coordination_deadline)",
      ) &&
    keyAgentCreateInner.indexOf("if Instant::now() >= coordination_deadline") <
      keyAgentCreateInner.indexOf(".prepare_child_inheritance(&flight)") &&
    keyAgentCreateProcess.includes("coordination_deadline: Instant") &&
    keyAgentFinalDeadlineCheck >
      keyAgentCreateProcess.indexOf(".recheck_supervisor_context()") &&
    keyAgentFinalDeadlineCheck <
      keyAgentCreateProcess.indexOf(
        ".create_process_with_explicit_handle_list(",
      ) &&
    brokerCoordinatedCreate.indexOf(
      "check_deadline(deadline)?",
      brokerCoordinatedCreate.indexOf("acquire_inheritable_handle_launch(deadline)"),
    ) <
      brokerCoordinatedCreate.indexOf(
        "InheritedParentProcess::duplicate_current(&flight)",
      ) &&
    [restrictedLaunchFlightOrder, keyAgentFlightOrder, brokerFlightOrder].every(
      (positions) =>
        positions.every((position) => position !== -1) &&
        positions
          .slice(1)
          .every((position, index) => position > positions[index]),
    ),
  "all inheriting Rust launches must use one private deadline-bound, non-reentrant, panic-poisoning process-wide flight from first temporary handle through immediate post-create close",
);
requireInvariant(
  duplicateInheritedParentProcess.includes(
    "pub(super) fn duplicate_inherited_parent_process(",
  ) &&
    duplicateInheritedParentProcess.includes(
      "!text.bytes().all(|byte| byte.is_ascii_digit())",
    ) &&
    duplicateInheritedParentProcess.includes("if raw == 0") &&
    duplicateInheritedParentProcessOrder.every((position) => position !== -1) &&
    duplicateInheritedParentProcessOrder
      .slice(1)
      .every(
        (position, index) => position > duplicateInheritedParentProcessOrder[index],
      ) &&
    duplicateInheritedParentOriginalFlagQueries.length === 2 &&
    duplicateInheritedParentOriginalFlagQueries[0] <
      duplicateInheritedParentProcess.indexOf("SetHandleInformation(") &&
    duplicateInheritedParentOriginalFlagQueries[1] >
      duplicateInheritedParentProcess.indexOf("SetHandleInformation(") &&
    duplicateInheritedParentOriginalFlagQueries[1] <
      duplicateInheritedParentProcess.indexOf(
        "let desired = (PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE).0",
      ) &&
    rustCallSites(duplicateInheritedParentProcess, "DuplicateHandle").length === 1 &&
    rustCallSites(duplicateInheritedParentProcess, "DuplicateHandle")[0]
      ?.arguments[4] === "desired" &&
    rustCallSites(duplicateInheritedParentProcess, "DuplicateHandle")[0]
      ?.arguments[5] === "false" &&
    rustCallSites(duplicateInheritedParentProcess, "DuplicateHandle")[0]
      ?.arguments[6] === "DUPLICATE_HANDLE_OPTIONS(0)" &&
    rustCallSites(duplicateInheritedParentProcess, "from_raw_handle").length === 1 &&
    rustCallSites(duplicateInheritedParentProcess, "from_raw_handle")[0]
      ?.arguments[0] === "duplicate.0" &&
    duplicateInheritedParentProcess.includes("Ok(duplicate)") &&
    !/from_raw_handle\(\s*(?:raw|handle(?:\.0)?)\s*\)/u.test(
      rustLexicalCode(duplicateInheritedParentProcess),
    ),
  "the Broker debug-hook parent capability must de-inherit the ambient raw handle, make one minimal-rights non-inheritable duplicate, validate that fresh duplicate directly, and own only the duplicate",
);
requireInvariant(
  restrictedLauncherProduction.includes("const ATTRIBUTE_COUNT: u32 = 6") &&
    restrictedAttributeValuesDefinition.includes("job: [HANDLE; 1]") &&
    restrictedAttributeValuesImplementation.includes(
      "fn new(handles: Box<[HANDLE]>, job: HANDLE, profile_sid: PSID)",
    ) &&
    restrictedAttributeValuesImplementation.includes("job: [job]") &&
    restrictedAttributeListDefinition.includes(
    "duplicate_owner: &'handles InheritableDuplicates<'flight, 'coordinator>",
  ) &&
    restrictedAttributeListDefinition.includes("job_owner: &'job OwnedWinHandle") &&
    restrictedAttributeListImplementation.includes(
      "duplicate_owner: &'handles InheritableDuplicates<'flight, 'coordinator>",
    ) &&
    restrictedAttributeListImplementation.includes(
      "job_owner: &'job OwnedWinHandle",
    ) &&
    restrictedAttributeListImplementation.includes(
      "let handles = duplicate_owner.raw_handles()",
    ) &&
    restrictedAttributeListImplementation.includes("duplicate_owner,") &&
    restrictedAttributeListImplementation.includes("job_owner,") &&
    /AttributeValues::new\(\s*handles,\s*job_owner\.raw\(\),\s*profile_sid\.raw\(\),?\s*\)/u.test(
      restrictedAttributeListImplementation,
    ) &&
    (restrictedAttributeListImplementation.match(/self\.update\(/gu) ?? []).length ===
      6 &&
    restrictedAttributeListImplementation.indexOf(
      "PROC_THREAD_ATTRIBUTE_HANDLE_LIST",
    ) <
      restrictedAttributeListImplementation.indexOf(
        "PROC_THREAD_ATTRIBUTE_JOB_LIST",
      ) &&
    restrictedAttributeListImplementation.includes(
      "self.values.job.as_ptr().cast::<c_void>()",
    ) &&
    restrictedAttributeListImplementation.includes("size_of_val(&self.values.job)") &&
    restrictedAttributeListImplementation.includes(
      "self.duplicate_owner.handles.len()",
    ) &&
    restrictedAttributeListImplementation.includes(
      "debug_assert_eq!(self.job_owner.raw(), self.values.job[0])",
    ) &&
    restrictedLaunchLeaf.includes(
      "AttributeList::for_lpac(&duplicates, &job, profile_sid)?",
    ) &&
    !restrictedLaunchLeaf.includes(
      "AttributeList::for_lpac(duplicates.raw_handles()",
    ) &&
    !restrictedLaunchLeaf.includes("AssignProcessToJobObject") &&
    restrictedLaunchLeaf.includes(
      "IsProcessInJob(process.raw(), Some(job.raw()), &raw mut in_job)",
    ) &&
    restrictedLaunchLeaf.includes("if !in_job.as_bool()") &&
    restrictedCreatedChildGuard.includes(
      "process: &'process OwnedWinHandle",
    ) &&
    restrictedCreatedChildGuard.includes("job: &'job OwnedWinHandle") &&
    restrictedCreatedChildGuard.includes("armed: bool") &&
    restrictedCreatedChildGuardImplementation.includes(
      "fn new(process: &'process OwnedWinHandle, job: &'job OwnedWinHandle) -> Self",
    ) &&
    restrictedCreatedChildGuardImplementation.includes("process,") &&
    restrictedCreatedChildGuardImplementation.includes("job,") &&
    restrictedCreatedChildGuardImplementation.includes("armed: true") &&
    restrictedCreatedChildGuardImplementation.includes("fn disarm(mut self)") &&
    restrictedCreatedChildGuardImplementation.includes("self.armed = false") &&
    restrictedCreatedChildGuardDrop.includes("if self.armed") &&
    restrictedCreatedChildGuardDrop.includes(
      "terminate_and_reap_created_child(self.process.raw(), self.job.raw())",
    ) &&
    restrictedLauncherProduction.includes(
      "const CREATED_CHILD_CLEANUP_TIMEOUT_MILLISECONDS: u32 = 5_000",
    ) &&
    restrictedCreatedChildCleanupOrder.every((position) => position !== -1) &&
    restrictedCreatedChildCleanupOrder
      .slice(1)
      .every(
        (position, index) => position > restrictedCreatedChildCleanupOrder[index],
      ),
  "restricted AttributeList must retain both duplicate and Job owners, atomically install the exact JOB_LIST, and guard every suspended child until Job/token verification and resume succeed",
);
const keyAgentLpacModuleConsumers = platformWindowsProductionFiles
  .filter(
    (file) =>
      file.path !== "crates/platform-windows/src/key_agent_lpac.rs" &&
      file.path !== "crates/platform-windows/src/lib.rs" &&
      /\bkey_agent_lpac\b/u.test(rustLexicalCode(file.source)),
  )
  .map((file) => file.path);
const keyAgentStorageModuleConsumers = platformWindowsProductionFiles
  .filter(
    (file) =>
      file.path !== "crates/platform-windows/src/key_agent_storage.rs" &&
      file.path !== "crates/platform-windows/src/lib.rs" &&
      /\bkey_agent_storage\b/u.test(rustLexicalCode(file.source)),
  )
  .map((file) => file.path);
const keyAgentStartupModuleConsumers = platformWindowsProductionFiles
  .filter(
    (file) =>
      file.path !== "crates/platform-windows/src/key_agent_startup.rs" &&
      file.path !== "crates/platform-windows/src/lib.rs" &&
      /\bkey_agent_startup\b/u.test(rustLexicalCode(file.source)),
  )
  .map((file) => file.path);
requireInvariant(
  platformWindowsLib.includes("#[cfg(windows)]\nmod key_agent_activation;") &&
    !/pub(?:\([^)]*\))?\s+mod\s+key_agent_activation\b/u.test(platformWindowsLib) &&
    !/pub(?:\([^)]*\))?\s+use\s+[^;]*key_agent_activation/u.test(platformWindowsLib) &&
    platformWindowsLib.includes("#[cfg(windows)]\nmod key_agent_lpac;") &&
    !/pub(?:\([^)]*\))?\s+mod\s+key_agent_lpac\b/u.test(platformWindowsLib) &&
    !/pub(?:\([^)]*\))?\s+use\s+[^;]*key_agent_lpac/u.test(platformWindowsLib) &&
    JSON.stringify(keyAgentLpacModuleConsumers) ===
      JSON.stringify([
        "crates/platform-windows/src/helper.rs",
        "crates/platform-windows/src/key_agent_activation.rs",
        "crates/platform-windows/src/key_agent_install_adoption.rs",
        "crates/platform-windows/src/key_agent_install_provenance.rs",
        "crates/platform-windows/src/key_agent_storage.rs",
        "crates/platform-windows/src/key_agent_supervisor.rs",
      ]) &&
    !platformWindowsProductionFiles.some((file) =>
      /\bpub(?:\([^)]*\))?\s+use\s+[^;]*\bkey_agent_lpac\b/u.test(
        rustLexicalCode(file.source),
      ),
    ) &&
    platformWindowsLib.includes("#[cfg(windows)]\nmod key_agent_storage;") &&
    !/pub(?:\([^)]*\))?\s+mod\s+key_agent_storage\b/u.test(platformWindowsLib) &&
    !/pub(?:\([^)]*\))?\s+use\s+[^;]*\bkey_agent_storage\b/u.test(
      platformWindowsLib,
    ) &&
    JSON.stringify(keyAgentStorageModuleConsumers) ===
      JSON.stringify([
        "crates/platform-windows/src/key_agent_child_bootstrap.rs",
        "crates/platform-windows/src/key_agent_install_provenance.rs",
        "crates/platform-windows/src/key_agent_lpac.rs",
        "crates/platform-windows/src/key_agent_startup.rs",
        "crates/platform-windows/src/storage.rs",
        "crates/platform-windows/src/storage/sys.rs",
      ]) &&
    platformWindowsLib.includes(
      "use platform_windows::key_agent_activation::HeldKeyAgentActivation;",
    ) &&
    platformWindowsLib.includes(
      "use platform_windows::key_agent_activation::activate_key_agent;",
    ) &&
    platformWindowsLib.includes("#[cfg(windows)]\nmod key_agent_supervisor;") &&
    !/pub(?:\([^)]*\))?\s+mod\s+key_agent_supervisor\b/u.test(platformWindowsLib) &&
    !/pub(?:\([^)]*\))?\s+use\s+[^;]*key_agent_supervisor/u.test(platformWindowsLib) &&
    platformWindowsLib.includes(
      "use platform_windows::key_agent_supervisor::BoundDormantKeyAgent;",
    ) &&
    platformWindowsLib.includes(
      "use platform_windows::key_agent_supervisor::bind_dormant_key_agent;",
    ),
  "Key Agent LPAC, storage, activation, and bound supervisor capabilities must remain externally private",
);
requireInvariant(
  platformWindowsLib.includes("#[cfg(windows)]\nmod key_agent_startup;") &&
    !/pub(?:\([^)]*\))?\s+mod\s+key_agent_startup\b/u.test(platformWindowsLib) &&
    !/pub(?:\([^)]*\))?\s+use\s+[^;]*key_agent_startup/u.test(platformWindowsLib) &&
    JSON.stringify(keyAgentStartupModuleConsumers) ===
      JSON.stringify([
        "crates/platform-windows/src/key_agent_child_bootstrap.rs",
        "crates/platform-windows/src/key_agent_supervisor.rs",
        "crates/platform-windows/src/pipe.rs",
      ]),
  "the Key Agent startup codec must remain private to the child bootstrap, supervisor, and exact pipe typestates",
);
const keyAgentInstallProvenanceTypeNames = [
  "AuthenticatedKeyAgentInstallJournal",
  "AuthenticatedKeyAgentInstallSnapshot",
  "ExpectedKeyAgentInstallIdentities",
  "ObservedKeyAgentInstallObjects",
  "UninitializedKeyAgentInstallCandidate",
  "ConsistentExistingKeyAgentInstallCandidate",
  "KeyAgentInstallDisposition",
  "StableExistingKeyAgentInstallEvidence",
];
const keyAgentInstallProvenanceExternalTokenNames = [
  ...keyAgentInstallProvenanceTypeNames,
  "InstallerJournalAuthenticationKey",
  "AuthenticatedKeyAgentInstallCheckpoint",
  "validate_authenticated_install_journal",
  "classify_key_agent_install",
  "verify_existing_key_agent_install_snapshots",
  "consume_stable_existing_key_agent_install_evidence",
];
const keyAgentInstallProvenanceModuleConsumers = platformWindowsProductionFiles
  .filter(
    (file) =>
      file.path !==
        "crates/platform-windows/src/key_agent_install_provenance.rs" &&
      file.path !== "crates/platform-windows/src/lib.rs" &&
      /\bkey_agent_install_provenance\b/u.test(rustLexicalCode(file.source)),
  )
  .map((file) => file.path);
const keyAgentInstallProvenanceRawInclusionConsumers =
  platformWindowsProductionFiles
    .filter(
      (file) =>
        file.path !==
          "crates/platform-windows/src/key_agent_install_provenance.rs" &&
        file.source.includes("key_agent_install_provenance.rs"),
    )
    .map((file) => file.path);
const platformWindowsLibWithoutInstallProvenanceDeclaration =
  platformWindowsLibCode.replace(
    /\bmod\s+key_agent_install_provenance\s*;/u,
    "",
  );
const keyAgentInstallProvenanceConsumers = platformWindowsProductionFiles
  .filter(
    (file) =>
      file.path !==
        "crates/platform-windows/src/key_agent_install_provenance.rs" &&
      file.path !== "crates/platform-windows/src/lib.rs" &&
      keyAgentInstallProvenanceExternalTokenNames.some((name) =>
        new RegExp(`\\b${name}\\b`, "u").test(rustLexicalCode(file.source)),
      ),
  )
  .map((file) => file.path);
const classifyKeyAgentInstallConsumers = platformWindowsProductionFiles
  .filter(
    (file) =>
      file.path !==
        "crates/platform-windows/src/key_agent_install_provenance.rs" &&
      rustCallSites(file.source, "classify_key_agent_install").length > 0,
  )
  .map((file) => file.path);
const validateAuthenticatedKeyAgentInstallJournalConsumers =
  platformWindowsProductionFiles
    .filter(
      (file) =>
        file.path !==
          "crates/platform-windows/src/key_agent_install_provenance.rs" &&
        rustCallSites(
          file.source,
          "validate_authenticated_install_journal",
        ).length > 0,
    )
    .map((file) => file.path);
const verifyExistingKeyAgentInstallSnapshotsConsumers =
  platformWindowsProductionFiles
    .filter(
      (file) =>
        file.path !==
          "crates/platform-windows/src/key_agent_install_provenance.rs" &&
        rustCallSites(
          file.source,
          "verify_existing_key_agent_install_snapshots",
        ).length > 0,
    )
    .map((file) => file.path);
const consumeStableExistingKeyAgentInstallEvidenceConsumers =
  platformWindowsProductionFiles
    .filter(
      (file) =>
        file.path !==
          "crates/platform-windows/src/key_agent_install_provenance.rs" &&
        rustCallSites(
          file.source,
          "consume_stable_existing_key_agent_install_evidence",
        ).length > 0,
    )
    .map((file) => file.path);
const freshKeyAgentBoundaryConsumers = platformWindowsProductionFiles
  .filter(
    (file) =>
      file.path !== "crates/platform-windows/src/key_agent_supervisor.rs" &&
      rustCallSites(file.source, "provision_fresh_key_agent_boundary").length > 0,
  )
  .map((file) => file.path);
const pendingToPreparedConsumers = platformWindowsProductionFiles
  .filter((file) => {
    const code = rustLexicalCode(file.source);
    return (
      /impl\s+(?:From|TryFrom)\s*<\s*PendingKeyAgentProvisioning\s*>\s+for\s+PreparedKeyAgentProvisioning/u.test(
        code,
      ) ||
      /fn\s+\w+\s*\([^)]*PendingKeyAgentProvisioning[^)]*\)\s*->\s*(?:Result\s*<\s*)?PreparedKeyAgentProvisioning/u.test(
        code,
      )
    );
  })
  .map((file) => file.path);
const provenanceVisibleTypes = [
  ...keyAgentInstallProvenanceReleaseCode.matchAll(
    /\bpub(?:\s*\([^\r\n)]*\))?\s+(?:struct|enum|union)\s+(?<name>[A-Za-z_]\w*)/gu,
  ),
].map((match) => match.groups.name);
const provenanceVisibleFunctions = [
  ...keyAgentInstallProvenanceReleaseCode.matchAll(
    /\bpub(?:\s*\([^\r\n)]*\))?\s+(?:(?:const|async|unsafe)\s+)*(?:extern(?:\s+"[^"\r\n]*")?\s+)?fn\s+(?<name>[A-Za-z_]\w*)/gu,
  ),
].map((match) => match.groups.name);
const provenancePublicVisibilitySites = [
  ...keyAgentInstallProvenanceReleaseCode.matchAll(
    /\bpub(?:\s*\([^\r\n)]*\))?/gu,
  ),
];
const provenanceImplItems = rustImplItems(keyAgentInstallProvenanceRelease);
const provenanceImplHeaders = provenanceImplItems.map((item) => item.header);
const expectedProvenanceImplHeaders = [
  "impl fmt::Debug for InstallerJournalAuthenticationKey",
  "impl fmt::Debug for AuthenticatedKeyAgentInstallCheckpoint",
  "impl fmt::Debug for AuthenticatedKeyAgentInstallJournal",
  "impl fmt::Debug for AuthenticatedKeyAgentInstallSnapshot",
  "impl fmt::Debug for ExpectedKeyAgentInstallIdentities",
  "impl fmt::Debug for ObservedKeyAgentInstallObjects",
  "impl fmt::Debug for UninitializedKeyAgentInstallCandidate",
  "impl fmt::Debug for ConsistentExistingKeyAgentInstallCandidate",
  "impl fmt::Debug for KeyAgentInstallDisposition",
  "impl fmt::Debug for StableExistingKeyAgentInstallEvidence",
];
const provenanceReleaseAttributes = [
  ...keyAgentInstallProvenanceReleaseCode.matchAll(/#\s*\[[^\]]*\]/gu),
].map((match) => compactRust(match[0]));
const provenanceUseItems = [
  ...keyAgentInstallProvenanceReleaseCode.matchAll(/\buse\s+[^;]+;/gu),
].map((match) => compactRust(match[0]));
const provenanceCrateModulePaths = [
  ...keyAgentInstallProvenanceReleaseCode.matchAll(
    /\bcrate::(?<module>[A-Za-z_]\w*)/gu,
  ),
].map((match) => match.groups.module);
const provenanceTypeAliases = rustTypeAliasItems(
  keyAgentInstallProvenanceRelease,
).map((item) => compactRust(item.source));
const provenanceMacroInvocations = rustMacroInvocations(
  keyAgentInstallProvenanceRelease,
);
const provenanceTypeDefinitionCounts = keyAgentInstallProvenanceTypeNames.map(
  (name) =>
    (
      keyAgentInstallProvenanceReleaseCode.match(
        new RegExp(`\\b(?:struct|enum|union)\\s+${name}\\b`, "gu"),
      ) ?? []
    ).length,
);
const provenancePinnedConstantDefinitionCounts = [
  "INSTALL_JOURNAL_SCHEMA_V1",
  "INSTALL_POLICY_V1",
  "COMMITTED_JOURNAL_GENERATION_V1",
  "INSTALL_JOURNAL_RECORD_MAGIC_V1",
  "INSTALL_JOURNAL_RECORD_DIGEST_DOMAIN_V1",
  "INSTALL_JOURNAL_RECORD_MAC_DOMAIN_V1",
  "INSTALL_CHECKPOINT_COMMITMENT_DOMAIN_V1",
  "INSTALL_JOURNAL_RECORD_BODY_BYTES",
  "INSTALL_JOURNAL_MAC_BYTES",
  "INSTALL_JOURNAL_RECORD_BYTES",
].map(
  (name) =>
    (
      keyAgentInstallProvenanceReleaseCode.match(
        new RegExp(`\\bconst\\s+${name}\\b`, "gu"),
      ) ?? []
    ).length,
);
const provenancePinnedByteStringOccurrenceCounts = [
  "INSTALL_JOURNAL_RECORD_MAGIC_V1",
  "INSTALL_JOURNAL_RECORD_DIGEST_DOMAIN_V1",
  "INSTALL_JOURNAL_RECORD_MAC_DOMAIN_V1",
  "INSTALL_CHECKPOINT_COMMITMENT_DOMAIN_V1",
].map(
  (name) =>
    (
      keyAgentInstallProvenanceReleaseCode.match(
        new RegExp(`\\b${name}\\b`, "gu"),
      ) ?? []
    ).length,
);
const provenanceVerifierHelperOccurrenceCounts = [
  "encode_install_journal_record_body",
  "decode_install_journal_record_body",
  "verify_install_journal_record_mac",
  "decode_authenticated_install_journal_record",
  "authenticated_install_journal_record_digest",
  "install_checkpoint_commitment",
  "bind_install_journal_phase_payload",
  "validate_nonempty_install_journal_history",
].map(
  (name) =>
    (
      keyAgentInstallProvenanceReleaseCode.match(
        new RegExp(`\\b${name}\\b`, "gu"),
      ) ?? []
    ).length,
);
const provenanceAuthorityConstructionCounts = [
  "AuthenticatedKeyAgentInstallJournal",
  "AuthenticatedKeyAgentInstallSnapshot",
  "ExpectedKeyAgentInstallIdentities",
  "ObservedKeyAgentInstallObjects",
].map(
  (name) =>
    rustStructLiteralSites(keyAgentInstallProvenanceRelease, name).length,
);
const provenancePrivateAuthorityConstructionCounts = [
  "InstallerJournalAuthenticationKey",
  "AuthenticatedKeyAgentInstallCheckpoint",
].map(
  (name) =>
    rustStructLiteralSites(keyAgentInstallProvenanceRelease, name).length,
);
const provenanceCandidateConstructionCounts = [
  "UninitializedKeyAgentInstallCandidate",
  "ConsistentExistingKeyAgentInstallCandidate",
  "StableExistingKeyAgentInstallEvidence",
].map(
  (name) =>
    rustStructLiteralSites(keyAgentInstallProvenanceRelease, name).length,
);
const provenanceAuthorityBlocks = [
  installerJournalAuthenticationKeyBlock,
  authenticatedKeyAgentInstallCheckpointBlock,
  authenticatedKeyAgentInstallJournalBlock,
  authenticatedKeyAgentInstallSnapshotBlock,
  expectedKeyAgentInstallIdentitiesBlock,
  observedKeyAgentInstallObjectsBlock,
  uninitializedKeyAgentInstallCandidateBlock,
  consistentExistingKeyAgentInstallCandidateBlock,
  stableExistingKeyAgentInstallEvidenceBlock,
];
const provenanceForbiddenProductionPatterns = [
  /\bunsafe\b/u,
  /\bextern\b/u,
  /\bstd\b/u,
  /\b(?:super|self)::/u,
  /\bstd::(?:fs|io|path|env|process|net)\b/u,
  /\bwindows(?:::|_sys\b)/u,
  /\bWin32\b/u,
  /\b(?:File|OpenOptions|Command)\b/u,
  /\b(?:serde|bincode|postcard)\b/u,
  /\b(?!(?:if|while|return|let|else|match)\b)(?:[A-Za-z_]\w*::)*[A-Za-z_]\w*\s*!\s*[([{]/u,
  /\buse\b[^;]*\bas\s+[A-Za-z_]\w*/u,
  /\b(?:Create|Open|Delete|Remove|Move|Reg|CryptProtect|NCrypt|BCrypt|Tpm)\w*\s*\(/u,
];
const provenanceForbiddenTraitImpl = new RegExp(
  `impl\\s+(?:Clone|Copy|Default|Drop|Deref|AsRef|From(?:<[^>]+>)?|TryFrom(?:<[^>]+>)?)\\s+for\\s+(?:InstallerJournalAuthenticationKey|AuthenticatedKeyAgentInstallCheckpoint|${keyAgentInstallProvenanceTypeNames.join("|")})\\b`,
  "u",
);
const compactInstallTransactionGeneration = compactRust(
  keyAgentInstallTransactionGeneration,
);
const compactKeyAgentInstallProvenanceRelease = compactRust(
  keyAgentInstallProvenanceRelease,
);
const compactKeyAgentInstallRecord = compactRust(keyAgentInstallRecordBlock);
const compactValidKeyAgentInstallRecord = compactRust(
  validKeyAgentInstallRecord,
);
const compactEncodeKeyAgentInstallJournalRecordBody = compactRust(
  encodeKeyAgentInstallJournalRecordBody,
);
const compactDecodeKeyAgentInstallJournalRecordBody = compactRust(
  decodeKeyAgentInstallJournalRecordBody,
);
const compactVerifyKeyAgentInstallJournalRecordMac = compactRust(
  verifyKeyAgentInstallJournalRecordMac,
);
const compactDecodeAuthenticatedKeyAgentInstallJournalRecord = compactRust(
  decodeAuthenticatedKeyAgentInstallJournalRecord,
);
const compactAuthenticatedKeyAgentInstallJournalRecordDigest = compactRust(
  authenticatedKeyAgentInstallJournalRecordDigest,
);
const compactKeyAgentInstallCheckpointCommitment = compactRust(
  keyAgentInstallCheckpointCommitment,
);
const compactBindKeyAgentInstallJournalPhasePayload = compactRust(
  bindKeyAgentInstallJournalPhasePayload,
);
const compactValidateNonemptyKeyAgentInstallJournalHistory = compactRust(
  validateNonemptyKeyAgentInstallJournalHistory,
);
const compactValidateAuthenticatedKeyAgentInstallJournal = compactRust(
  validateAuthenticatedKeyAgentInstallJournal,
);
const compactVerifyExistingKeyAgentInstallSnapshots = compactRust(
  verifyExistingKeyAgentInstallSnapshots,
);
const compactObservedInstallObjectsFromCanonical = compactRust(
  observedInstallObjectsFromCanonical,
);
const verifyExistingSnapshotSameCalls = rustCallSites(
  verifyExistingKeyAgentInstallSnapshots,
  "same_authenticated_install_snapshot",
);
const verifyExistingSnapshotObservationCalls = rustCallSites(
  verifyExistingKeyAgentInstallSnapshots,
  "observed_install_objects_from_canonical",
);
const verifyExistingSnapshotClassifierCalls = rustCallSites(
  verifyExistingKeyAgentInstallSnapshots,
  "classify_key_agent_install",
);
const validateCheckpointCommitmentCalls = rustCallSites(
  validateAuthenticatedKeyAgentInstallJournal,
  "install_checkpoint_commitment",
);
const validateNonemptyHistoryCalls = rustCallSites(
  validateAuthenticatedKeyAgentInstallJournal,
  "validate_nonempty_install_journal_history",
);
const historyAuthenticatedDecodeCalls = rustCallSites(
  validateNonemptyKeyAgentInstallJournalHistory,
  "decode_authenticated_install_journal_record",
);
const historyPhasePayloadCalls = rustCallSites(
  validateNonemptyKeyAgentInstallJournalHistory,
  "bind_install_journal_phase_payload",
);
const historyRecordDigestCalls = rustCallSites(
  validateNonemptyKeyAgentInstallJournalHistory,
  "authenticated_install_journal_record_digest",
);
const authenticatedDecodeMacCalls = rustCallSites(
  decodeAuthenticatedKeyAgentInstallJournalRecord,
  "verify_install_journal_record_mac",
);
const authenticatedDecodeBodyCalls = rustCallSites(
  decodeAuthenticatedKeyAgentInstallJournalRecord,
  "decode_install_journal_record_body",
);
const expectedKeyAgentInstallProvenanceTests = [
  "full_presence_and_transaction_truth_table_is_fail_closed",
  "deterministic_profile_squatting_without_a_record_requires_recovery",
  "every_record_binding_mismatch_requires_recovery",
  "every_live_observation_or_expected_identity_mismatch_requires_recovery",
  "malformed_or_aliased_canonical_sids_require_recovery",
  "sentinel_expected_identities_and_invalid_journal_generation_require_recovery",
  "authority_is_one_shot_thread_affine_and_debug_redacted",
  "canonical_authenticated_codec_round_trips_all_phase_prefixes",
  "codec_rejects_truncation_trailing_authentication_reserved_and_unused_bytes",
  "exact_history_rejects_gap_order_id_payload_and_predecessor_drift",
  "checkpoint_rejects_rollback_equivocation_digest_and_empty_mismatches",
];
requireInvariant(
  platformWindowsLib.includes(
    "#[cfg(windows)]\n#[allow(dead_code)]\nmod key_agent_install_provenance;",
  ) &&
    !/pub(?:\([^)]*\))?\s+mod\s+key_agent_install_provenance\b/u.test(
      platformWindowsLib,
    ) &&
    !/pub(?:\([^)]*\))?\s+use\s+[^;]*key_agent_install_provenance/u.test(
      platformWindowsLibCode,
    ) &&
    !/\bkey_agent_install_provenance\b/u.test(
      platformWindowsLibWithoutInstallProvenanceDeclaration,
    ) &&
    JSON.stringify(keyAgentInstallProvenanceModuleConsumers) ===
      JSON.stringify([
        "crates/platform-windows/src/key_agent_install_adoption.rs",
      ]) &&
    JSON.stringify(keyAgentInstallProvenanceRawInclusionConsumers) ===
      JSON.stringify([]) &&
    JSON.stringify(keyAgentInstallProvenanceConsumers) ===
      JSON.stringify([
        "crates/platform-windows/src/key_agent_install_adoption.rs",
      ]) &&
    JSON.stringify(classifyKeyAgentInstallConsumers) === JSON.stringify([]) &&
    JSON.stringify(validateAuthenticatedKeyAgentInstallJournalConsumers) ===
      JSON.stringify([]) &&
    JSON.stringify(verifyExistingKeyAgentInstallSnapshotsConsumers) ===
      JSON.stringify([
        "crates/platform-windows/src/key_agent_install_adoption.rs",
      ]) &&
    JSON.stringify(consumeStableExistingKeyAgentInstallEvidenceConsumers) ===
      JSON.stringify([
        "crates/platform-windows/src/key_agent_install_adoption.rs",
      ]) &&
    JSON.stringify(freshKeyAgentBoundaryConsumers) === JSON.stringify([]) &&
    JSON.stringify(pendingToPreparedConsumers) === JSON.stringify([]) &&
    JSON.stringify(provenanceVisibleTypes) ===
      JSON.stringify(keyAgentInstallProvenanceTypeNames) &&
    JSON.stringify(provenanceVisibleFunctions) ===
      JSON.stringify([
        "classify_key_agent_install",
        "consume_stable_existing_key_agent_install_evidence",
        "verify_existing_key_agent_install_snapshots",
      ]) &&
    provenancePublicVisibilitySites.length === 11 &&
    provenanceReleaseAttributes.length === 6 &&
    provenanceReleaseAttributes.includes(
      "#[derive(Clone,Copy,Debug,Eq,PartialEq)]",
    ) &&
    provenanceReleaseAttributes.includes("#[derive(Eq,PartialEq)]") &&
    provenanceReleaseAttributes.filter(
      (attribute) => attribute === "#[allow(clippy::needless_pass_by_value)]",
    ).length === 3 &&
    keyAgentInstallProvenanceRelease.includes(
      '#[must_use = "stable existing-install evidence must remain bound to held objects"]',
    ) &&
    JSON.stringify(provenanceUseItems) ===
      JSON.stringify([
        "usecore::fmt;",
        "usecore::marker::PhantomData;",
        "usehmac::{Hmac,Mac};",
        "usesha2::{Digest,Sha256};",
        "usesubtle::ConstantTimeEq;",
        "usezeroize::Zeroizing;",
        "usecrate::key_agent_lpac::{KEY_AGENT_PROFILE_V1_NAME,KeyAgentHeldInstallObservation};",
        "usecrate::key_agent_storage::KeyAgentStorageRootIdentity;",
      ]) &&
    JSON.stringify(provenanceCrateModulePaths) ===
      JSON.stringify(["key_agent_lpac", "key_agent_storage"]) &&
    JSON.stringify(provenanceTypeDefinitionCounts) ===
      JSON.stringify([1, 1, 1, 1, 1, 1, 1, 1]) &&
    provenancePinnedConstantDefinitionCounts.length === 10 &&
    provenancePinnedConstantDefinitionCounts.every((count) => count === 1) &&
    JSON.stringify(provenancePinnedByteStringOccurrenceCounts) ===
      JSON.stringify([3, 2, 2, 2]) &&
    provenanceVerifierHelperOccurrenceCounts.length === 8 &&
    provenanceVerifierHelperOccurrenceCounts.every((count) => count === 2) &&
    JSON.stringify(provenanceImplHeaders) ===
      JSON.stringify(expectedProvenanceImplHeaders) &&
    JSON.stringify(provenanceAuthorityConstructionCounts) ===
      JSON.stringify([1, 1, 1, 1]) &&
    JSON.stringify(provenancePrivateAuthorityConstructionCounts) ===
      JSON.stringify([1, 1]) &&
    rustStructLiteralSites(
      validateAuthenticatedKeyAgentInstallJournal,
      "AuthenticatedKeyAgentInstallJournal",
    ).length === 1 &&
    rustStructLiteralSites(
      validateAuthenticatedKeyAgentInstallJournal,
      "ExpectedKeyAgentInstallIdentities",
    ).length === 1 &&
    rustStructLiteralSites(
      validateAuthenticatedKeyAgentInstallJournal,
      "AuthenticatedKeyAgentInstallSnapshot",
    ).length === 1 &&
    rustStructLiteralSites(
      validateAuthenticatedKeyAgentInstallJournal,
      "InstallerJournalAuthenticationKey",
    ).length === 1 &&
    rustStructLiteralSites(
      validateAuthenticatedKeyAgentInstallJournal,
      "AuthenticatedKeyAgentInstallCheckpoint",
    ).length === 1 &&
    JSON.stringify(provenanceCandidateConstructionCounts) ===
      JSON.stringify([1, 1, 1]) &&
    rustStructLiteralSites(
      verifyExistingKeyAgentInstallSnapshots,
      "StableExistingKeyAgentInstallEvidence",
    ).length === 1 &&
    rustStructLiteralSites(
      observedInstallObjectsFromCanonical,
      "ObservedKeyAgentInstallObjects",
    ).length === 1 &&
    rustStructLiteralSites(keyAgentInstallProvenanceRelease, "Self").length === 0 &&
    rustCallSites(
      keyAgentInstallProvenanceRelease,
      "classify_key_agent_install",
    ).length === 2 &&
    provenanceAuthorityBlocks.every(
      (block) =>
        block !== "" &&
        !/\bpub(?:\([^)]*\))?\s+\w+\s*:/u.test(rustLexicalCode(block)),
    ) &&
    !provenanceForbiddenProductionPatterns.some((pattern) =>
      pattern.test(keyAgentInstallProvenanceReleaseCode),
    ) &&
    !provenanceForbiddenTraitImpl.test(keyAgentInstallProvenanceReleaseCode) &&
    JSON.stringify(provenanceTypeAliases) ===
      JSON.stringify(["typeInstallerJournalHmacSha256=Hmac<Sha256>;"]) &&
    provenanceMacroInvocations.length === 0 &&
    (keyAgentInstallProvenanceReleaseCode.match(
      /\bKeyAgentStorageRootIdentity::decode_be\s*\(/gu,
    ) ?? []).length === 1 &&
    decodeKeyAgentInstallJournalRoot.includes(
      "KeyAgentStorageRootIdentity::decode_be(root_identity)",
    ) &&
    (keyAgentInstallProvenanceReleaseCode.match(/\.encode_be\s*\(/gu) ?? [])
      .length === 1 &&
    encodeKeyAgentInstallJournalRecordBody.includes(
      "root.root_identity.encode_be()",
    ) &&
    /const\s+INSTALL_JOURNAL_SCHEMA_V1\s*:\s*u16\s*=\s*1\s*;/u.test(
      keyAgentInstallProvenanceReleaseCode,
    ) &&
    /const\s+INSTALL_POLICY_V1\s*:\s*u16\s*=\s*1\s*;/u.test(
      keyAgentInstallProvenanceReleaseCode,
    ) &&
    /const\s+COMMITTED_JOURNAL_GENERATION_V1\s*:\s*u64\s*=\s*4\s*;/u.test(
      keyAgentInstallProvenanceReleaseCode,
    ) &&
    [
      "constINSTALL_JOURNAL_RECORD_MAGIC_V1:[u8;8]=*b;",
      "constRECORD_MAGIC_OFFSET:usize=0;",
      "constRECORD_SCHEMA_OFFSET:usize=8;",
      "constRECORD_POLICY_OFFSET:usize=10;",
      "constRECORD_STATE_OFFSET:usize=12;",
      "constRECORD_HEADER_RESERVED_OFFSET:usize=13;",
      "constRECORD_HEADER_RESERVED_BYTES:usize=3;",
      "constRECORD_GENERATION_OFFSET:usize=16;",
      "constRECORD_TRANSACTION_ID_OFFSET:usize=24;",
      "constRECORD_INSTALLATION_ID_OFFSET:usize=56;",
      "constRECORD_RELEASE_IDENTITY_OFFSET:usize=88;",
      "constRECORD_PREDECESSOR_DIGEST_OFFSET:usize=120;",
      "constRECORD_PROFILE_NAME_LEN_OFFSET:usize=152;",
      "constRECORD_PROFILE_NAME_OFFSET:usize=153;",
      "constRECORD_PROFILE_SID_LEN_OFFSET:usize=217;",
      "constRECORD_PROFILE_SID_OFFSET:usize=218;",
      "constRECORD_STABLE_USER_SID_LEN_OFFSET:usize=286;",
      "constRECORD_STABLE_USER_SID_OFFSET:usize=287;",
      "constRECORD_ROOT_IDENTITY_OFFSET:usize=355;",
      "constRECORD_TAIL_RESERVED_OFFSET:usize=379;",
      "constRECORD_TAIL_RESERVED_BYTES:usize=5;",
      "constINSTALL_JOURNAL_RECORD_BODY_BYTES:usize=384;",
      "constINSTALL_JOURNAL_MAC_BYTES:usize=32;",
      "constINSTALL_JOURNAL_RECORD_BYTES:usize=INSTALL_JOURNAL_RECORD_BODY_BYTES+INSTALL_JOURNAL_MAC_BYTES;",
      "constRECORD_MAC_OFFSET:usize=INSTALL_JOURNAL_RECORD_BODY_BYTES;",
    ].every((source) =>
      compactKeyAgentInstallProvenanceRelease.includes(source),
    ) &&
    /^const\s+INSTALL_JOURNAL_RECORD_MAGIC_V1\s*:\s*\[u8;\s*8\]\s*=\s*\*b"YWKAIJ01"\s*;$/u.test(
      installJournalRecordMagicConstant.trim(),
    ) &&
    /^const\s+INSTALL_JOURNAL_RECORD_DIGEST_DOMAIN_V1\s*:\s*&\[u8\]\s*=\s*b"your-wallet\/key-agent-install\/record-digest\/v1\\0"\s*;$/u.test(
      installJournalRecordDigestDomainConstant.trim(),
    ) &&
    /^const\s+INSTALL_JOURNAL_RECORD_MAC_DOMAIN_V1\s*:\s*&\[u8\]\s*=\s*b"your-wallet\/key-agent-install\/record-mac\/v1\\0"\s*;$/u.test(
      installJournalRecordMacDomainConstant.trim(),
    ) &&
    /^const\s+INSTALL_CHECKPOINT_COMMITMENT_DOMAIN_V1\s*:\s*&\[u8\]\s*=\s*b"your-wallet\/key-agent-install\/checkpoint\/v1\\0"\s*;$/u.test(
      installCheckpointCommitmentDomainConstant.trim(),
    ) &&
    compactEncodeKeyAgentInstallJournalRecordBody.includes(
      "encoded[RECORD_MAGIC_OFFSET..RECORD_SCHEMA_OFFSET].copy_from_slice(&INSTALL_JOURNAL_RECORD_MAGIC_V1);",
    ) &&
    compactDecodeKeyAgentInstallJournalRecordBody.includes(
      "ifencoded[RECORD_MAGIC_OFFSET..RECORD_SCHEMA_OFFSET]!=INSTALL_JOURNAL_RECORD_MAGIC_V1||",
    ) &&
    !/#\[derive\([^\]]*(?:Clone|Copy|Default)[^\]]*\)\]\s*pub\(crate\)\s+(?:struct|enum)\s+(?:AuthenticatedKeyAgentInstallJournal|AuthenticatedKeyAgentInstallSnapshot|ExpectedKeyAgentInstallIdentities|ObservedKeyAgentInstallObjects|UninitializedKeyAgentInstallCandidate|ConsistentExistingKeyAgentInstallCandidate|KeyAgentInstallDisposition|StableExistingKeyAgentInstallEvidence)\b/u.test(
      keyAgentInstallProvenanceReleaseCode,
    ) &&
    !/#\[derive\([^\]]*(?:Clone|Copy|Default)[^\]]*\)\]\s*struct\s+(?:InstallerJournalAuthenticationKey|AuthenticatedKeyAgentInstallCheckpoint)\b/u.test(
      keyAgentInstallProvenanceReleaseCode,
    ) &&
    !/impl\s+(?:InstallerJournalAuthenticationKey|AuthenticatedKeyAgentInstallCheckpoint|AuthenticatedKeyAgentInstallJournal|AuthenticatedKeyAgentInstallSnapshot|ExpectedKeyAgentInstallIdentities|ObservedKeyAgentInstallObjects|UninitializedKeyAgentInstallCandidate|ConsistentExistingKeyAgentInstallCandidate|StableExistingKeyAgentInstallEvidence)\s*\{/u.test(
      keyAgentInstallProvenanceReleaseCode,
    ) &&
    (keyAgentInstallProvenanceReleaseCode.match(
      /_not_send_or_sync:\s*PhantomData<\*mut \(\)>/gu,
    ) ?? []).length === 9 &&
    keyAgentInstallProvenanceReleaseCode.includes("struct JournalEvidenceSeal;") &&
    keyAgentInstallProvenanceReleaseCode.includes("struct ExpectedIdentitySeal;") &&
    keyAgentInstallProvenanceReleaseCode.includes("struct OsObservationSeal;") &&
    keyAgentInstallProvenanceReleaseCode.includes("struct CheckpointEvidenceSeal;") &&
    keyAgentInstallProvenanceReleaseCode.includes(
      "struct InstallerJournalAuthenticationKeySeal;",
    ) &&
    installerJournalAuthenticationKeyBlock.includes(
      "_seal: InstallerJournalAuthenticationKeySeal",
    ) &&
    authenticatedKeyAgentInstallCheckpointBlock.includes(
      "_seal: CheckpointEvidenceSeal",
    ) &&
    authenticatedKeyAgentInstallJournalBlock.includes(
      "_seal: JournalEvidenceSeal",
    ) &&
    authenticatedKeyAgentInstallSnapshotBlock.includes(
      "journal: AuthenticatedKeyAgentInstallJournal",
    ) &&
    authenticatedKeyAgentInstallSnapshotBlock.includes(
      "expected: ExpectedKeyAgentInstallIdentities",
    ) &&
    authenticatedKeyAgentInstallSnapshotBlock.includes(
      "current_record_digest: [u8; INSTALL_JOURNAL_DIGEST_BYTES]",
    ) &&
    expectedKeyAgentInstallIdentitiesBlock.includes(
      "_seal: ExpectedIdentitySeal",
    ) &&
    observedKeyAgentInstallObjectsBlock.includes("_seal: OsObservationSeal") &&
    keyAgentInstallProvenanceReleaseCode.includes(
      "KeyAgentHeldInstallObservation",
    ) &&
    !keyAgentInstallProvenanceReleaseCode.includes(
      "YourWallet.KeyAgent.LPAC.v1",
    ) &&
    /pub\(crate\)\s+fn\s+classify_key_agent_install\s*\(\s*journal:\s*AuthenticatedKeyAgentInstallJournal,\s*expected:\s*ExpectedKeyAgentInstallIdentities,\s*objects:\s*ObservedKeyAgentInstallObjects,?\s*\)\s*->\s*KeyAgentInstallDisposition/u.test(
      classifyKeyAgentInstall,
    ) &&
    /pub\(crate\)\s+fn\s+verify_existing_key_agent_install_snapshots\s*\(\s*initial:\s*AuthenticatedKeyAgentInstallSnapshot,\s*reread:\s*AuthenticatedKeyAgentInstallSnapshot,\s*observation:\s*KeyAgentHeldInstallObservation,?\s*\)\s*->\s*Option<\s*StableExistingKeyAgentInstallEvidence\s*>/u.test(
      verifyExistingKeyAgentInstallSnapshots,
    ) &&
    JSON.stringify(verifyExistingSnapshotSameCalls.map((call) => call.arguments)) ===
      JSON.stringify([["&initial", "&reread"]]) &&
    JSON.stringify(
      verifyExistingSnapshotObservationCalls.map((call) => call.arguments),
    ) === JSON.stringify([["&observation"]]) &&
    JSON.stringify(
      verifyExistingSnapshotClassifierCalls.map((call) => call.arguments),
    ) ===
      JSON.stringify([["initial.journal", "initial.expected", "objects"]]) &&
    compactVerifyExistingKeyAgentInstallSnapshots.includes(
      "journal_generation!=COMMITTED_JOURNAL_GENERATION_V1",
    ) &&
    compactVerifyExistingKeyAgentInstallSnapshots.includes(
      "!valid_digest(&journal_record_digest)",
    ) &&
    compactVerifyExistingKeyAgentInstallSnapshots.includes(
      "letKeyAgentInstallDisposition::ConsistentExisting(candidate)=dispositionelse",
    ) &&
    compactObservedInstallObjectsFromCanonical.includes(
      "profile:Some(ObservedKeyAgentProfile",
    ) &&
    compactObservedInstallObjectsFromCanonical.includes(
      "root:Some(ObservedKeyAgentStorageRoot",
    ) &&
    /pub\(crate\)\s+fn\s+consume_stable_existing_key_agent_install_evidence\s*\(\s*evidence:\s*StableExistingKeyAgentInstallEvidence,?\s*\)/u.test(
      consumeStableExistingKeyAgentInstallEvidence,
    ) &&
    /Uninitialized\s*\(\s*UninitializedKeyAgentInstallCandidate\s*\)/u.test(
      keyAgentInstallDispositionBlock,
    ) &&
    /ConsistentExisting\s*\(\s*ConsistentExistingKeyAgentInstallCandidate\s*\)/u.test(
      keyAgentInstallDispositionBlock,
    ) &&
    /RecoveryRequired\s*,/u.test(keyAgentInstallDispositionBlock) &&
    !/\b(?:Fresh|Adopt|VerifiedExisting)\b/u.test(
      keyAgentInstallProvenanceReleaseCode,
    ) &&
    classifyKeyAgentInstall.includes(
      "expected_installation_id == expected_release_identity",
    ) &&
    classifyKeyAgentInstall.includes(
      "journal.authenticated_generation == record_common(&record).journal_generation",
    ) &&
    exactCommittedKeyAgentInstallMatch.includes(
      "let KeyAgentInstallRecord::Committed",
    ) &&
    exactCommittedKeyAgentInstallMatch.includes(
      "valid_install_record(record)",
    ) &&
    compactValidKeyAgentInstallRecord.includes(
      "common.journal_generation!=transaction_generation(state)",
    ) &&
    /Prepared\s*\{\s*common\s*:\s*KeyAgentInstallCommonRecord\s*,?\s*\}/u.test(
      keyAgentInstallRecordBlock,
    ) &&
    /ProfileCreated\s*\{\s*common\s*:\s*KeyAgentInstallCommonRecord\s*,\s*profile\s*:\s*KeyAgentInstallProfileEvidence\s*,?\s*\}/u.test(
      keyAgentInstallRecordBlock,
    ) &&
    /RootCreated\s*\{\s*common\s*:\s*KeyAgentInstallCommonRecord\s*,\s*profile\s*:\s*KeyAgentInstallProfileEvidence\s*,\s*root\s*:\s*KeyAgentInstallRootEvidence\s*,?\s*\}/u.test(
      keyAgentInstallRecordBlock,
    ) &&
    /Committed\s*\{\s*common\s*:\s*KeyAgentInstallCommonRecord\s*,\s*profile\s*:\s*KeyAgentInstallProfileEvidence\s*,\s*root\s*:\s*KeyAgentInstallRootEvidence\s*,?\s*\}/u.test(
      keyAgentInstallRecordBlock,
    ) &&
    compactInstallTransactionGeneration.includes("Prepared=>1") &&
    compactInstallTransactionGeneration.includes("ProfileCreated=>2") &&
    compactInstallTransactionGeneration.includes("RootCreated=>3") &&
    compactInstallTransactionGeneration.includes(
      "Committed=>COMMITTED_JOURNAL_GENERATION_V1",
    ) &&
    compactEncodeKeyAgentInstallJournalRecordBody.includes(
      "common.schema_version.to_be_bytes()",
    ) &&
    compactEncodeKeyAgentInstallJournalRecordBody.includes(
      "common.policy_version.to_be_bytes()",
    ) &&
    compactEncodeKeyAgentInstallJournalRecordBody.includes(
      "common.journal_generation.to_be_bytes()",
    ) &&
    (keyAgentInstallProvenanceReleaseCode.match(
      /\b(?:u16|u64)::from_be_bytes\s*\(/gu,
    ) ?? []).length === 3 &&
    !/\b(?:from|to)_le_bytes\s*\(/u.test(
      keyAgentInstallProvenanceReleaseCode,
    ) &&
    compactDecodeKeyAgentInstallJournalRecordBody.includes(
      "letcanonical=encode_install_journal_record_body(&record)?;ifcanonical!=*encoded",
    ) &&
    decodeKeyAgentInstallJournalRecordBody.includes(
      "RECORD_HEADER_RESERVED_BYTES",
    ) &&
    decodeKeyAgentInstallJournalRecordBody.includes(
      "RECORD_TAIL_RESERVED_BYTES",
    ) &&
    JSON.stringify(
      validateCheckpointCommitmentCalls.map((call) => call.arguments),
    ) ===
      JSON.stringify([
        [
          "high_water_generation",
          "&current_record_digest",
          "&installation_id",
          "&release_identity",
        ],
      ]) &&
    JSON.stringify(validateNonemptyHistoryCalls.map((call) => call.arguments)) ===
      JSON.stringify([
        [
          "encoded_journal",
          "&key",
          "high_water_generation",
          "&current_record_digest",
          "&installation_id",
          "&release_identity",
        ],
      ]) &&
    JSON.stringify(
      historyAuthenticatedDecodeCalls.map((call) => call.arguments),
    ) === JSON.stringify([["&encoded_record", "authentication_key"]]) &&
    JSON.stringify(historyPhasePayloadCalls.map((call) => call.arguments)) ===
      JSON.stringify([
        [
          "index",
          "&encoded_record[..INSTALL_JOURNAL_RECORD_BODY_BYTES]",
          "&mut profile_payload",
          "&mut root_payload",
        ],
      ]) &&
    JSON.stringify(historyRecordDigestCalls.map((call) => call.arguments)) ===
      JSON.stringify([["&encoded_record"]]) &&
    JSON.stringify(authenticatedDecodeMacCalls.map((call) => call.arguments)) ===
      JSON.stringify([
        ["&body", "&encoded[RECORD_MAC_OFFSET..]", "key"],
      ]) &&
    JSON.stringify(authenticatedDecodeBodyCalls.map((call) => call.arguments)) ===
      JSON.stringify([["&body"]]) &&
    compactValidateAuthenticatedKeyAgentInstallJournal.includes(
      "letexpected_commitment=install_checkpoint_commitment(high_water_generation,&current_record_digest,&installation_id,&release_identity,);",
    ) &&
    compactValidateAuthenticatedKeyAgentInstallJournal.includes(
      "Some(validate_nonempty_install_journal_history(encoded_journal,&key,high_water_generation,&current_record_digest,&installation_id,&release_identity,)?",
    ) &&
    compactValidateNonemptyKeyAgentInstallJournalHistory.includes(
      "letrecord=decode_authenticated_install_journal_record(&encoded_record,authentication_key)?;",
    ) &&
    compactValidateNonemptyKeyAgentInstallJournalHistory.includes(
      "bind_install_journal_phase_payload(index,&encoded_record[..INSTALL_JOURNAL_RECORD_BODY_BYTES],&mutprofile_payload,&mutroot_payload,)?;",
    ) &&
    compactValidateNonemptyKeyAgentInstallJournalHistory.includes(
      "previous_digest=authenticated_install_journal_record_digest(&encoded_record);",
    ) &&
    compactDecodeAuthenticatedKeyAgentInstallJournalRecord.includes(
      "verify_install_journal_record_mac(&body,&encoded[RECORD_MAC_OFFSET..],key)?;decode_install_journal_record_body(&body)",
    ) &&
    compactDecodeAuthenticatedKeyAgentInstallJournalRecord.indexOf(
      "verify_install_journal_record_mac",
    ) >= 0 &&
    compactDecodeAuthenticatedKeyAgentInstallJournalRecord.indexOf(
      "verify_install_journal_record_mac",
    ) <
      compactDecodeAuthenticatedKeyAgentInstallJournalRecord.indexOf(
        "decode_install_journal_record_body",
      ) &&
    compactVerifyKeyAgentInstallJournalRecordMac.includes(
      "InstallerJournalHmacSha256::new_from_slice(key)",
    ) &&
    compactVerifyKeyAgentInstallJournalRecordMac.includes(
      "mac.update(INSTALL_JOURNAL_RECORD_MAC_DOMAIN_V1);mac.update(body);mac.verify_slice(tag)",
    ) &&
    compactAuthenticatedKeyAgentInstallJournalRecordDigest.includes(
      "digest.update(INSTALL_JOURNAL_RECORD_DIGEST_DOMAIN_V1);digest.update(encoded);digest.finalize().into()",
    ) &&
    compactKeyAgentInstallCheckpointCommitment ===
      "fninstall_checkpoint_commitment(high_water_generation:u64,current_record_digest:&[u8;INSTALL_JOURNAL_DIGEST_BYTES],installation_id:&[u8;IDENTITY_BYTES],release_identity:&[u8;IDENTITY_BYTES],)->[u8;INSTALL_JOURNAL_DIGEST_BYTES]{letmutdigest=Sha256::new();digest.update(INSTALL_CHECKPOINT_COMMITMENT_DOMAIN_V1);digest.update(INSTALL_JOURNAL_SCHEMA_V1.to_be_bytes());digest.update(INSTALL_POLICY_V1.to_be_bytes());digest.update(high_water_generation.to_be_bytes());digest.update(current_record_digest);digest.update(installation_id);digest.update(release_identity);digest.finalize().into()}" &&
    (keyAgentInstallProvenanceReleaseCode.match(/\.ct_eq\s*\(/gu) ?? [])
      .length === 3 &&
    compactValidateNonemptyKeyAgentInstallJournalHistory.includes(
      "record_count.checked_mul(INSTALL_JOURNAL_RECORD_BYTES)",
    ) &&
    compactValidateNonemptyKeyAgentInstallJournalHistory.includes(
      "encoded_journal.len()!=expected_bytes",
    ) &&
    compactValidateNonemptyKeyAgentInstallJournalHistory.includes(
      "record_state(&record)!=expected_state",
    ) &&
    compactValidateNonemptyKeyAgentInstallJournalHistory.includes(
      "common.journal_generation!=u64::try_from(index+1)",
    ) &&
    compactValidateNonemptyKeyAgentInstallJournalHistory.includes(
      "common.installation_id!=*installation_id",
    ) &&
    compactValidateNonemptyKeyAgentInstallJournalHistory.includes(
      "common.release_identity!=*release_identity",
    ) &&
    compactValidateNonemptyKeyAgentInstallJournalHistory.includes(
      "common.predecessor_digest.ct_eq(&previous_digest)",
    ) &&
    compactValidateNonemptyKeyAgentInstallJournalHistory.includes(
      "common.transaction_id!=first_transaction_id",
    ) &&
    compactBindKeyAgentInstallJournalPhasePayload.includes("ifindex>=1") &&
    compactBindKeyAgentInstallJournalPhasePayload.includes("ifindex>=2") &&
    compactBindKeyAgentInstallJournalPhasePayload.includes(
      "profile_payload.is_some_and(|first|current!=first)",
    ) &&
    compactBindKeyAgentInstallJournalPhasePayload.includes(
      "root_payload.is_some_and(|first|current!=first)",
    ) &&
    compactValidateAuthenticatedKeyAgentInstallJournal.includes(
      "expected_commitment.ct_eq(&commitment)",
    ) &&
    compactValidateAuthenticatedKeyAgentInstallJournal.includes(
      "ifencoded_journal.is_empty()",
    ) &&
    compactValidateAuthenticatedKeyAgentInstallJournal.includes(
      "high_water_generation!=0||current_record_digest!=[0;INSTALL_JOURNAL_DIGEST_BYTES]",
    ) &&
    compactValidateAuthenticatedKeyAgentInstallJournal.includes(
      "(1..=COMMITTED_JOURNAL_GENERATION_V1).contains(&high_water_generation)",
    ) &&
    !/\b(?:DeviceKeyBundle|LocalSettings|GenerationStore|key_material|settings)\b/u.test(
      keyAgentInstallProvenanceReleaseCode,
    ) &&
    ![
      "ObservedKeyAgentInstallObjects",
      "UninitializedKeyAgentInstallCandidate",
      "ConsistentExistingKeyAgentInstallCandidate",
      "KeyAgentInstallDisposition",
      "PreparedKeyAgentProvisioning",
    ].some((name) => validateAuthenticatedKeyAgentInstallJournal.includes(name)) &&
    keyAgentInstallProvenanceSource.includes(
      'InstallerJournalAuthenticationKey([REDACTED])',
    ) &&
    keyAgentInstallProvenanceSource.includes(
      'AuthenticatedKeyAgentInstallCheckpoint([REDACTED])',
    ) &&
    keyAgentInstallProvenanceSource.includes("compiled fixed profile name") &&
    keyAgentInstallProvenanceSource.includes("fixed storage leaf") &&
    keyAgentInstallProvenanceSource.includes(
      "retains no root handle",
    ) &&
    expectedKeyAgentInstallProvenanceTests.every((name) =>
      keyAgentInstallProvenanceSource.includes(`fn ${name}`),
    ) &&
    /pub\(crate\)\s+fn\s+provision_fresh_key_agent_boundary\s*\(\s*\)\s*->\s*Result<\s*PendingKeyAgentProvisioning,\s*KeyAgentSupervisorError\s*>/u.test(
      provisionFreshKeyAgentBoundary,
    ) &&
    provisionFreshKeyAgentBoundary.includes(
      "PendingKeyAgentProvisioning::provision_fresh()",
    ) &&
    !keyAgentInstallProvenanceReleaseCode.includes(
      "PreparedKeyAgentProvisioning",
    ),
  "Key Agent install provenance must retain its exact canonical HMAC journal/checkpoint verifier, phase history, sealed classifier facts, one exact pure adoption consumer, non-launchable Pending freshness, and no Pending/candidate-to-Prepared conversion",
);
const keyAgentInstallAdoptionTypeNames = [
  "ExistingInstallAdoptionSeal",
  "VerifiedExistingKeyAgentInstall",
  "VerifiedKeyAgentInstallContinuity",
  "ArtifactBoundExistingKeyAgentInstall",
  "KeyAgentInstallAdoptionError",
  "KeyAgentInstallReleaseBindingError",
];
const keyAgentInstallAdoptionExternalTokenNames = [
  ...keyAgentInstallAdoptionTypeNames,
  "adopt_existing_key_agent_install",
  "bind_existing_key_agent_install_to_release",
  "consume_artifact_bound_existing_key_agent_install",
];
const keyAgentInstallAdoptionModuleConsumers = platformWindowsProductionFiles
  .filter(
    (file) =>
      file.path !== "crates/platform-windows/src/key_agent_install_adoption.rs" &&
      file.path !== "crates/platform-windows/src/lib.rs" &&
      /\bkey_agent_install_adoption\b/u.test(rustLexicalCode(file.source)),
  )
  .map((file) => file.path);
const keyAgentInstallAdoptionConsumers = platformWindowsProductionFiles
  .filter(
    (file) =>
      file.path !== "crates/platform-windows/src/key_agent_install_adoption.rs" &&
      file.path !== "crates/platform-windows/src/lib.rs" &&
      keyAgentInstallAdoptionExternalTokenNames.some((name) =>
        new RegExp(`\\b${name}\\b`, "u").test(rustLexicalCode(file.source)),
      ),
  )
  .map((file) => file.path);
const adoptExistingKeyAgentInstallConsumers = platformWindowsProductionFiles
  .filter(
    (file) =>
      file.path !== "crates/platform-windows/src/key_agent_install_adoption.rs" &&
      rustCallSites(file.source, "adopt_existing_key_agent_install").length > 0,
  )
  .map((file) => file.path);
const adoptExistingKeyAgentInstallTokenConsumers = platformWindowsProductionFiles
  .filter(
    (file) =>
      file.path !== "crates/platform-windows/src/key_agent_install_adoption.rs" &&
      /\badopt_existing_key_agent_install\b/u.test(
        rustLexicalCode(file.source),
      ),
  )
  .map((file) => file.path);
const bindExistingKeyAgentInstallToReleaseConsumers =
  platformWindowsProductionFiles
    .filter(
      (file) =>
        file.path !== "crates/platform-windows/src/key_agent_install_adoption.rs" &&
        rustCallSites(file.source, "bind_existing_key_agent_install_to_release")
          .length > 0,
    )
    .map((file) => file.path);
const bindExistingKeyAgentInstallToReleaseTokenConsumers =
  platformWindowsProductionFiles
    .filter(
      (file) =>
        file.path !== "crates/platform-windows/src/key_agent_install_adoption.rs" &&
        /\bbind_existing_key_agent_install_to_release\b/u.test(
          rustLexicalCode(file.source),
        ),
    )
    .map((file) => file.path);
const consumeArtifactBoundExistingKeyAgentInstallConsumers =
  platformWindowsProductionFiles
    .filter(
      (file) =>
        file.path !== "crates/platform-windows/src/key_agent_install_adoption.rs" &&
        rustCallSites(
          file.source,
          "consume_artifact_bound_existing_key_agent_install",
        ).length > 0,
    )
    .map((file) => file.path);
const consumeArtifactBoundExistingKeyAgentInstallTokenConsumers =
  platformWindowsProductionFiles
    .filter(
      (file) =>
        file.path !== "crates/platform-windows/src/key_agent_install_adoption.rs" &&
        /\bconsume_artifact_bound_existing_key_agent_install\b/u.test(
          rustLexicalCode(file.source),
        ),
    )
    .map((file) => file.path);
const convertHeldExistingKeyAgentInstallConsumers =
  platformWindowsProductionFiles
    .filter(
      (file) =>
        file.path !== "crates/platform-windows/src/key_agent_lpac.rs" &&
        rustCallSites(file.source, "into_prepared").length > 0,
    )
    .map((file) => file.path);
const keyAgentInstallAdoptionVisibleTypes = [
  ...keyAgentInstallAdoptionReleaseCode.matchAll(
    /\bpub(?:\s*\([^\r\n)]*\))?\s+(?:struct|enum|union)\s+(?<name>[A-Za-z_]\w*)/gu,
  ),
].map((match) => match.groups.name);
const keyAgentInstallAdoptionVisibleFunctions = [
  ...keyAgentInstallAdoptionReleaseCode.matchAll(
    /\bpub(?:\s*\([^\r\n)]*\))?\s+(?:(?:const|async|unsafe)\s+)*(?:extern(?:\s+"[^"\r\n]*")?\s+)?fn\s+(?<name>[A-Za-z_]\w*)/gu,
  ),
].map((match) => match.groups.name);
const keyAgentInstallAdoptionVisibleFunctionInventory = rustVisibleFunctionItems(
  keyAgentInstallAdoptionRelease,
);
const keyAgentInstallAdoptionPublicVisibilitySites = [
  ...keyAgentInstallAdoptionReleaseCode.matchAll(
    /\bpub(?:\s*\([^\r\n)]*\))?/gu,
  ),
];
const keyAgentInstallAdoptionImplHeaders = rustImplItems(
  keyAgentInstallAdoptionRelease,
).map((item) => item.header);
const keyAgentInstallAdoptionAttributes = [
  ...keyAgentInstallAdoptionReleaseCode.matchAll(/#\s*\[[^\]]*\]/gu),
].map((match) => compactRust(match[0]));
const keyAgentInstallAdoptionUseItems = [
  ...keyAgentInstallAdoptionReleaseCode.matchAll(/\buse\s+[^;]+;/gu),
].map((match) => compactRust(match[0]));
const keyAgentInstallAdoptionCrateModulePaths = [
  ...keyAgentInstallAdoptionReleaseCode.matchAll(
    /\bcrate::(?<module>[A-Za-z_]\w*)/gu,
  ),
].map((match) => match.groups.module);
const keyAgentInstallAdoptionTypeAliases = rustTypeAliasItems(
  keyAgentInstallAdoptionRelease,
).map((item) => compactRust(item.source));
const keyAgentInstallAdoptionMacroInvocations = rustMacroInvocations(
  keyAgentInstallAdoptionRelease,
);
const keyAgentInstallAdoptionTypeDefinitionCounts =
  keyAgentInstallAdoptionTypeNames.map(
    (name) =>
      (
        keyAgentInstallAdoptionReleaseCode.match(
          new RegExp(`\\b(?:struct|enum|union)\\s+${name}\\b`, "gu"),
        ) ?? []
      ).length,
  );
const keyAgentInstallAdoptionConstructionCounts = [
  "ExistingInstallAdoptionSeal",
  "VerifiedExistingKeyAgentInstall",
  "VerifiedKeyAgentInstallContinuity",
  "ArtifactBoundExistingKeyAgentInstall",
].map(
  (name) =>
    rustStructLiteralSites(keyAgentInstallAdoptionRelease, name).length,
);
const heldExistingKeyAgentInstallConstructionSites =
  platformWindowsProductionFiles.flatMap((file) =>
    rustStructLiteralSites(file.source, "HeldExistingKeyAgentInstallObjects").map(
      () => file.path,
    ),
  );
const keyAgentInstallAdoptionSealConsumers = platformWindowsProductionFiles
  .filter(
    (file) =>
      file.path !== "crates/platform-windows/src/key_agent_install_adoption.rs" &&
      file.path !== "crates/platform-windows/src/lib.rs" &&
      /\bExistingInstallAdoptionSeal\b/u.test(rustLexicalCode(file.source)),
  )
  .map((file) => file.path);
const verifiedExistingKeyAgentInstallConsumers = platformWindowsProductionFiles
  .filter(
    (file) =>
      file.path !== "crates/platform-windows/src/key_agent_install_adoption.rs" &&
      file.path !== "crates/platform-windows/src/lib.rs" &&
      /\bVerifiedExistingKeyAgentInstall\b/u.test(
        rustLexicalCode(file.source),
      ),
  )
  .map((file) => file.path);
const verifiedKeyAgentInstallContinuityConsumers =
  platformWindowsProductionFiles
    .filter(
      (file) =>
        file.path !== "crates/platform-windows/src/key_agent_install_adoption.rs" &&
        file.path !== "crates/platform-windows/src/lib.rs" &&
        /\bVerifiedKeyAgentInstallContinuity\b/u.test(
          rustLexicalCode(file.source),
        ),
    )
    .map((file) => file.path);
const artifactBoundExistingKeyAgentInstallConsumers =
  platformWindowsProductionFiles
    .filter(
      (file) =>
        file.path !== "crates/platform-windows/src/key_agent_install_adoption.rs" &&
        file.path !== "crates/platform-windows/src/lib.rs" &&
        /\bArtifactBoundExistingKeyAgentInstall\b/u.test(
          rustLexicalCode(file.source),
        ),
    )
    .map((file) => file.path);
const keyAgentInstallAdoptionErrorConsumers = platformWindowsProductionFiles
  .filter(
    (file) =>
      file.path !== "crates/platform-windows/src/key_agent_install_adoption.rs" &&
      file.path !== "crates/platform-windows/src/lib.rs" &&
      /\bKeyAgentInstallAdoptionError\b/u.test(rustLexicalCode(file.source)),
  )
  .map((file) => file.path);
const keyAgentInstallReleaseBindingErrorConsumers =
  platformWindowsProductionFiles
    .filter(
      (file) =>
        file.path !== "crates/platform-windows/src/key_agent_install_adoption.rs" &&
        file.path !== "crates/platform-windows/src/lib.rs" &&
        /\bKeyAgentInstallReleaseBindingError\b/u.test(
          rustLexicalCode(file.source),
        ),
    )
    .map((file) => file.path);
const keyAgentSupervisorBindingSealConsumers =
  platformWindowsProductionFiles
    .filter(
      (file) =>
        file.path !== "crates/platform-windows/src/key_agent_supervisor.rs" &&
        file.path !== "crates/platform-windows/src/lib.rs" &&
        /\bKeyAgentSupervisorBindingSeal\b/u.test(
          rustLexicalCode(file.source),
        ),
    )
    .map((file) => file.path);
const keyAgentSupervisorBindingSealLiteralSites =
  platformWindowsProductionFiles.flatMap((file) =>
    rustStructLiteralSites(file.source, "KeyAgentSupervisorBindingSeal").map(
      (site) => ({ path: file.path, source: compactRust(site.source) }),
    ),
  );
const keyAgentInstallAdoptionForbiddenProductionPatterns = [
  /\bunsafe\b/u,
  /\b(?:async|await|union|macro_rules)\b/u,
  /\bextern\b/u,
  /\bstd\b/u,
  /\bwindows(?:::|_sys\b)/u,
  /\bWin32\b/u,
  /\b(?:File|OpenOptions|Command)\b/u,
  /\b(?:getrandom|hmac|sha2|subtle|zeroize)::/u,
  /\b(?:InstallerJournalAuthenticationKey|AuthenticatedKeyAgentInstallCheckpoint)\b/u,
  /\b(?:Box|Rc|Arc|Mutex|RwLock|OnceLock|ManuallyDrop|MaybeUninit)\b/u,
  /\b(?:transmute(?:_copy)?|forget|from_raw|into_raw|leak)\b/u,
  /\b(?:DeviceKeyBundle|LocalSettings|GenerationStore|settings|registry)\b/u,
  /\buse\b[^;]*\bas\s+[A-Za-z_]\w*/u,
  /\b(?:Create|Open|Delete|Remove|Move|Reg|CryptProtect|NCrypt|BCrypt|Tpm)\w*\s*\(/u,
];
const keyAgentInstallAdoptionForbiddenTraitImpl = new RegExp(
  `impl\\s+(?:Clone|Copy|Default|Drop|Deref|DerefMut|AsRef|Borrow|From(?:<[^>]+>)?|Into(?:<[^>]+>)?|TryFrom(?:<[^>]+>)?)\\s+for\\s+(?:ExistingInstallAdoptionSeal|VerifiedExistingKeyAgentInstall|VerifiedKeyAgentInstallContinuity|ArtifactBoundExistingKeyAgentInstall|KeyAgentSupervisorBindingSeal)\\b`,
  "u",
);
const compactAdoptExistingKeyAgentInstall = compactRust(
  adoptExistingKeyAgentInstall,
);
const expectedCompactAdoptExistingKeyAgentInstall = [
  "pub(crate)fnadopt_existing_key_agent_install(initial:AuthenticatedKeyAgentInstallSnapshot,held:HeldExistingKeyAgentInstallObjects,reread:AuthenticatedKeyAgentInstallSnapshot,)->Result<VerifiedExistingKeyAgentInstall,KeyAgentInstallAdoptionError>{",
  "held.revalidate().map_err(|_|KeyAgentInstallAdoptionError::RecoveryRequired)?;",
  "letobservation=held.install_observation().map_err(|_|KeyAgentInstallAdoptionError::RecoveryRequired)?;",
  "letstable=verify_existing_key_agent_install_snapshots(initial,reread,observation).ok_or(KeyAgentInstallAdoptionError::RecoveryRequired)?;",
  "let(installation_id,release_identity,journal_generation,journal_record_digest)=consume_stable_existing_key_agent_install_evidence(stable);",
  "held.revalidate().map_err(|_|KeyAgentInstallAdoptionError::RecoveryRequired)?;",
  "letprovisioning=held.into_prepared(ExistingInstallAdoptionSeal{_private:()});",
  "Ok(VerifiedExistingKeyAgentInstall{provisioning,installation_id,release_identity,journal_generation,journal_record_digest,_not_sync:PhantomData,})",
  "}",
].join("");
const expectedCompactVerifiedExistingKeyAgentInstallDebugImpl = [
  "implfmt::DebugforVerifiedExistingKeyAgentInstall{",
  "fnfmt(&self,formatter:&mutfmt::Formatter<'_>)->fmt::Result{",
  "let_=(&self.provisioning,&self.installation_id,&self.release_identity,&self.journal_generation,&self.journal_record_digest,);",
  "formatter.write_str()",
  "}",
  "}",
].join("");
const expectedCompactVerifiedKeyAgentInstallContinuityDebugImpl = [
  "implfmt::DebugforVerifiedKeyAgentInstallContinuity{",
  "fnfmt(&self,formatter:&mutfmt::Formatter<'_>)->fmt::Result{",
  "let_=(&self.installation_id,&self.release_identity,&self.journal_generation,&self.journal_record_digest,);",
  "formatter.write_str()",
  "}",
  "}",
].join("");
const expectedCompactArtifactBoundExistingKeyAgentInstallDebugImpl = [
  "implfmt::DebugforArtifactBoundExistingKeyAgentInstall{",
  "fnfmt(&self,formatter:&mutfmt::Formatter<'_>)->fmt::Result{",
  "let_=(&self.preflighted,&self.provisioning,&self.continuity);",
  "formatter.write_str()",
  "}",
  "}",
].join("");
const compactBindExistingKeyAgentInstallToRelease = compactRust(
  bindExistingKeyAgentInstallToRelease,
);
const expectedCompactBindExistingKeyAgentInstallToRelease = [
  "pub(crate)fnbind_existing_key_agent_install_to_release(attestation:ReleaseAttestation,artifact:VerifiedHelper,verified:VerifiedExistingKeyAgentInstall,)->Result<ArtifactBoundExistingKeyAgentInstall,KeyAgentInstallReleaseBindingError>{",
  "letpreflighted=preflight_key_agent_activation(attestation,artifact).map_err(|_|KeyAgentInstallReleaseBindingError::ReleaseUnavailable)?;",
  "verified.provisioning.revalidate().map_err(|_|KeyAgentInstallReleaseBindingError::RecoveryRequired)?;",
  "if!preflighted.matches_release_identity(&verified.release_identity){returnErr(KeyAgentInstallReleaseBindingError::RecoveryRequired);}",
  "verified.provisioning.revalidate().map_err(|_|KeyAgentInstallReleaseBindingError::RecoveryRequired)?;",
  "letVerifiedExistingKeyAgentInstall{provisioning,installation_id,release_identity,journal_generation,journal_record_digest,_not_sync:_,}=verified;",
  "Ok(ArtifactBoundExistingKeyAgentInstall{preflighted,provisioning,continuity:VerifiedKeyAgentInstallContinuity{installation_id,release_identity,journal_generation,journal_record_digest,_not_sync:PhantomData,},})",
  "}",
].join("");
const compactConsumeArtifactBoundExistingKeyAgentInstall = compactRust(
  consumeArtifactBoundExistingKeyAgentInstall,
);
const expectedCompactConsumeArtifactBoundExistingKeyAgentInstall = [
  "pub(crate)fnconsume_artifact_bound_existing_key_agent_install(bound:ArtifactBoundExistingKeyAgentInstall,_seal:KeyAgentSupervisorBindingSeal,)->(PreflightKeyAgentArtifact,PreparedKeyAgentProvisioning,VerifiedKeyAgentInstallContinuity,){",
  "letArtifactBoundExistingKeyAgentInstall{preflighted,provisioning,continuity,}=bound;",
  "(preflighted,provisioning,continuity)",
  "}",
].join("");
const bindExistingKeyAgentInstallToReleaseOrder = [
  "preflight_key_agent_activation(attestation,artifact)",
  "verified.provisioning.revalidate()",
  "preflighted.matches_release_identity(&verified.release_identity)",
  "verified.provisioning.revalidate()",
  "letVerifiedExistingKeyAgentInstall{",
  "Ok(ArtifactBoundExistingKeyAgentInstall{",
  "continuity:VerifiedKeyAgentInstallContinuity{",
].map((marker, index) =>
  index === 3
    ? compactBindExistingKeyAgentInstallToRelease.lastIndexOf(marker)
    : compactBindExistingKeyAgentInstallToRelease.indexOf(marker),
);
const adoptExistingKeyAgentInstallOrder = [
  compactAdoptExistingKeyAgentInstall.indexOf("held.revalidate()"),
  compactAdoptExistingKeyAgentInstall.indexOf(
    "letobservation=held.install_observation()",
  ),
  compactAdoptExistingKeyAgentInstall.indexOf(
    "verify_existing_key_agent_install_snapshots(initial,reread,observation)",
  ),
  compactAdoptExistingKeyAgentInstall.indexOf(
    "consume_stable_existing_key_agent_install_evidence(stable)",
  ),
  compactAdoptExistingKeyAgentInstall.lastIndexOf("held.revalidate()"),
  compactAdoptExistingKeyAgentInstall.indexOf(
    "held.into_prepared(ExistingInstallAdoptionSeal{_private:()})",
  ),
  compactAdoptExistingKeyAgentInstall.indexOf(
    "Ok(VerifiedExistingKeyAgentInstall{",
  ),
];
const keyAgentInstallAdoptionExpectedTests = [
  "exact_held_objects_and_unchanged_committed_snapshots_mint_adoption",
  "checkpoint_reread_drift_and_uncommitted_history_require_recovery",
  "held_root_identity_mismatch_requires_recovery",
  "held_sid_bindings_must_match_authenticated_snapshots",
  "adoption_authority_is_send_only_noncopy_and_redacted",
  "exact_attested_release_mints_one_artifact_bound_install",
  "release_mismatch_and_helper_manifest_substitution_require_recovery",
  "unavailable_release_fails_before_install_binding",
];
requireInvariant(
  platformWindowsLib.includes(
    "#[cfg(windows)]\n#[allow(dead_code)]\nmod key_agent_install_adoption;",
  ) &&
    !/pub(?:\([^)]*\))?\s+mod\s+key_agent_install_adoption\b/u.test(
      platformWindowsLib,
    ) &&
    !/pub(?:\([^)]*\))?\s+use\s+[^;]*key_agent_install_adoption/u.test(
      platformWindowsLibCode,
    ) &&
    JSON.stringify(keyAgentInstallAdoptionModuleConsumers) ===
      JSON.stringify([
        "crates/platform-windows/src/key_agent_lpac.rs",
        "crates/platform-windows/src/key_agent_supervisor.rs",
      ]) &&
    JSON.stringify(keyAgentInstallAdoptionConsumers) ===
      JSON.stringify([
        "crates/platform-windows/src/key_agent_lpac.rs",
        "crates/platform-windows/src/key_agent_supervisor.rs",
      ]) &&
    JSON.stringify(keyAgentInstallAdoptionSealConsumers) ===
      JSON.stringify(["crates/platform-windows/src/key_agent_lpac.rs"]) &&
    JSON.stringify(verifiedExistingKeyAgentInstallConsumers) ===
      JSON.stringify([]) &&
    JSON.stringify(verifiedKeyAgentInstallContinuityConsumers) ===
      JSON.stringify(["crates/platform-windows/src/key_agent_supervisor.rs"]) &&
    JSON.stringify(artifactBoundExistingKeyAgentInstallConsumers) ===
      JSON.stringify(["crates/platform-windows/src/key_agent_supervisor.rs"]) &&
    JSON.stringify(keyAgentInstallAdoptionErrorConsumers) ===
      JSON.stringify([]) &&
    JSON.stringify(keyAgentInstallReleaseBindingErrorConsumers) ===
      JSON.stringify([]) &&
    JSON.stringify(adoptExistingKeyAgentInstallConsumers) === JSON.stringify([]) &&
    JSON.stringify(adoptExistingKeyAgentInstallTokenConsumers) ===
      JSON.stringify([]) &&
    JSON.stringify(bindExistingKeyAgentInstallToReleaseConsumers) ===
      JSON.stringify([]) &&
    JSON.stringify(bindExistingKeyAgentInstallToReleaseTokenConsumers) ===
      JSON.stringify([]) &&
    JSON.stringify(consumeArtifactBoundExistingKeyAgentInstallConsumers) ===
      JSON.stringify(["crates/platform-windows/src/key_agent_supervisor.rs"]) &&
    JSON.stringify(consumeArtifactBoundExistingKeyAgentInstallTokenConsumers) ===
      JSON.stringify(["crates/platform-windows/src/key_agent_supervisor.rs"]) &&
    JSON.stringify(keyAgentSupervisorBindingSealConsumers) ===
      JSON.stringify(["crates/platform-windows/src/key_agent_install_adoption.rs"]) &&
    JSON.stringify(keyAgentSupervisorBindingSealLiteralSites) ===
      JSON.stringify([
        {
          path: "crates/platform-windows/src/key_agent_supervisor.rs",
          source: "KeyAgentSupervisorBindingSeal{_private:()}",
        },
      ]) &&
    JSON.stringify(convertHeldExistingKeyAgentInstallConsumers) ===
      JSON.stringify([
        "crates/platform-windows/src/key_agent_install_adoption.rs",
      ]) &&
    JSON.stringify(keyAgentInstallAdoptionVisibleTypes) ===
      JSON.stringify(keyAgentInstallAdoptionTypeNames) &&
    JSON.stringify(keyAgentInstallAdoptionVisibleFunctions) ===
      JSON.stringify([
        "adopt_existing_key_agent_install",
        "bind_existing_key_agent_install_to_release",
        "consume_artifact_bound_existing_key_agent_install",
      ]) &&
    JSON.stringify(keyAgentInstallAdoptionVisibleFunctionInventory) ===
      JSON.stringify([
        {
          owner: "free",
          visibility: "pub(crate)",
          name: "adopt_existing_key_agent_install",
          signature:
            "fnadopt_existing_key_agent_install(initial:AuthenticatedKeyAgentInstallSnapshot,held:HeldExistingKeyAgentInstallObjects,reread:AuthenticatedKeyAgentInstallSnapshot,)->Result<VerifiedExistingKeyAgentInstall,KeyAgentInstallAdoptionError>",
        },
        {
          owner: "free",
          visibility: "pub(crate)",
          name: "bind_existing_key_agent_install_to_release",
          signature:
            "fnbind_existing_key_agent_install_to_release(attestation:ReleaseAttestation,artifact:VerifiedHelper,verified:VerifiedExistingKeyAgentInstall,)->Result<ArtifactBoundExistingKeyAgentInstall,KeyAgentInstallReleaseBindingError>",
        },
        {
          owner: "free",
          visibility: "pub(crate)",
          name: "consume_artifact_bound_existing_key_agent_install",
          signature:
            "fnconsume_artifact_bound_existing_key_agent_install(bound:ArtifactBoundExistingKeyAgentInstall,_seal:KeyAgentSupervisorBindingSeal,)->(PreflightKeyAgentArtifact,PreparedKeyAgentProvisioning,VerifiedKeyAgentInstallContinuity,)",
        },
      ]) &&
    keyAgentInstallAdoptionPublicVisibilitySites.length === 9 &&
    JSON.stringify(keyAgentInstallAdoptionImplHeaders) ===
      JSON.stringify([
        "impl fmt::Debug for VerifiedKeyAgentInstallContinuity",
        "impl fmt::Debug for ArtifactBoundExistingKeyAgentInstall",
        "impl fmt::Debug for VerifiedExistingKeyAgentInstall",
        "impl fmt::Display for KeyAgentInstallAdoptionError",
        "impl fmt::Debug for KeyAgentInstallAdoptionError",
        "impl core::error::Error for KeyAgentInstallAdoptionError",
        "impl fmt::Display for KeyAgentInstallReleaseBindingError",
        "impl fmt::Debug for KeyAgentInstallReleaseBindingError",
        "impl core::error::Error for KeyAgentInstallReleaseBindingError",
      ]) &&
    JSON.stringify(keyAgentInstallAdoptionAttributes) ===
      JSON.stringify([
        "#[must_use=]",
        "#[must_use=]",
        "#[must_use=]",
        "#[derive(Clone,Copy,Eq,PartialEq)]",
        "#[derive(Clone,Copy,Eq,PartialEq)]",
        "#[allow(clippy::needless_pass_by_value)]",
      ]) &&
    JSON.stringify(keyAgentInstallAdoptionUseItems) ===
      JSON.stringify([
        "usecore::cell::Cell;",
        "usecore::fmt;",
        "usecore::marker::PhantomData;",
        "usecrate::attestation::ReleaseAttestation;",
        "usecrate::helper::VerifiedHelper;",
        "usecrate::key_agent_activation::{PreflightKeyAgentArtifact,preflight_key_agent_activation};",
        "usecrate::key_agent_install_provenance::{AuthenticatedKeyAgentInstallSnapshot,consume_stable_existing_key_agent_install_evidence,verify_existing_key_agent_install_snapshots,};",
        "usecrate::key_agent_lpac::{HeldExistingKeyAgentInstallObjects,PreparedKeyAgentProvisioning};",
        "usecrate::key_agent_supervisor::KeyAgentSupervisorBindingSeal;",
      ]) &&
    JSON.stringify(keyAgentInstallAdoptionCrateModulePaths) ===
      JSON.stringify([
        "attestation",
        "helper",
        "key_agent_activation",
        "key_agent_install_provenance",
        "key_agent_lpac",
        "key_agent_supervisor",
      ]) &&
    JSON.stringify(keyAgentInstallAdoptionTypeAliases) === JSON.stringify([]) &&
    keyAgentInstallAdoptionMacroInvocations.length === 0 &&
    JSON.stringify(keyAgentInstallAdoptionTypeDefinitionCounts) ===
      JSON.stringify([1, 1, 1, 1, 1, 1]) &&
    JSON.stringify(keyAgentInstallAdoptionConstructionCounts) ===
      JSON.stringify([1, 2, 1, 2]) &&
    JSON.stringify(heldExistingKeyAgentInstallConstructionSites) ===
      JSON.stringify([]) &&
    rustStructLiteralSites(
      adoptExistingKeyAgentInstall,
      "ExistingInstallAdoptionSeal",
    ).length === 1 &&
    rustStructLiteralSites(
      adoptExistingKeyAgentInstall,
      "VerifiedExistingKeyAgentInstall",
    ).length === 1 &&
    rustStructLiteralSites(
      bindExistingKeyAgentInstallToRelease,
      "VerifiedExistingKeyAgentInstall",
    ).length === 1 &&
    rustStructLiteralSites(
      bindExistingKeyAgentInstallToRelease,
      "VerifiedKeyAgentInstallContinuity",
    ).length === 1 &&
    rustStructLiteralSites(
      bindExistingKeyAgentInstallToRelease,
      "ArtifactBoundExistingKeyAgentInstall",
    ).length === 1 &&
    rustStructLiteralSites(
      consumeArtifactBoundExistingKeyAgentInstall,
      "ArtifactBoundExistingKeyAgentInstall",
    ).length === 1 &&
    rustStructLiteralSites(
      adoptExistingKeyAgentInstall,
      "PreparedKeyAgentProvisioning",
    ).length === 0 &&
    rustStructLiteralSites(
      convertHeldExistingKeyAgentInstallObjects,
      "PreparedKeyAgentProvisioning",
    ).length === 1 &&
    rustStructLiteralSites(
      convertHeldExistingKeyAgentInstallObjects,
      "ExistingInstallAdoptionSeal",
    ).length === 0 &&
    compactRust(existingInstallAdoptionSealBlock) ===
      "pub(crate)structExistingInstallAdoptionSeal{_private:(),}" &&
    compactRust(verifiedExistingKeyAgentInstallBlock) ===
      "pub(crate)structVerifiedExistingKeyAgentInstall{provisioning:PreparedKeyAgentProvisioning,installation_id:[u8;32],release_identity:[u8;32],journal_generation:u64,journal_record_digest:[u8;32],_not_sync:PhantomData<Cell<()>>,}" &&
    compactRust(verifiedKeyAgentInstallContinuityBlock) ===
      "pub(crate)structVerifiedKeyAgentInstallContinuity{installation_id:[u8;32],release_identity:[u8;32],journal_generation:u64,journal_record_digest:[u8;32],_not_sync:PhantomData<Cell<()>>,}" &&
    compactRust(artifactBoundExistingKeyAgentInstallBlock) ===
      "pub(crate)structArtifactBoundExistingKeyAgentInstall{preflighted:PreflightKeyAgentArtifact,provisioning:PreparedKeyAgentProvisioning,continuity:VerifiedKeyAgentInstallContinuity,}" &&
    compactRust(keyAgentInstallAdoptionErrorBlock) ===
      "pub(crate)enumKeyAgentInstallAdoptionError{RecoveryRequired,}" &&
    compactRust(keyAgentInstallReleaseBindingErrorBlock) ===
      "pub(crate)enumKeyAgentInstallReleaseBindingError{ReleaseUnavailable,RecoveryRequired,}" &&
    compactAdoptExistingKeyAgentInstall ===
      expectedCompactAdoptExistingKeyAgentInstall &&
    compactBindExistingKeyAgentInstallToRelease ===
      expectedCompactBindExistingKeyAgentInstallToRelease &&
    compactConsumeArtifactBoundExistingKeyAgentInstall ===
      expectedCompactConsumeArtifactBoundExistingKeyAgentInstall &&
    compactRust(verifiedExistingKeyAgentInstallDebugImpl) ===
      expectedCompactVerifiedExistingKeyAgentInstallDebugImpl &&
    compactRust(verifiedKeyAgentInstallContinuityDebugImpl) ===
      expectedCompactVerifiedKeyAgentInstallContinuityDebugImpl &&
    compactRust(artifactBoundExistingKeyAgentInstallDebugImpl) ===
      expectedCompactArtifactBoundExistingKeyAgentInstallDebugImpl &&
    !/\bpub(?:\([^)]*\))?\s+\w+\s*:/u.test(
      keyAgentInstallAdoptionReleaseCode,
    ) &&
    !/impl\s+(?:ExistingInstallAdoptionSeal|VerifiedExistingKeyAgentInstall|VerifiedKeyAgentInstallContinuity|ArtifactBoundExistingKeyAgentInstall)\s*\{/u.test(
      keyAgentInstallAdoptionReleaseCode,
    ) &&
    !keyAgentInstallAdoptionForbiddenProductionPatterns.some((pattern) =>
      pattern.test(keyAgentInstallAdoptionReleaseCode),
    ) &&
    !keyAgentInstallAdoptionForbiddenTraitImpl.test(
      keyAgentInstallAdoptionReleaseCode,
    ) &&
    rustAuthorityTypeErasureSites(keyAgentInstallAdoptionRelease).length === 0 &&
    !/\btrait\b/u.test(keyAgentInstallAdoptionReleaseCode) &&
    !/\b(?:unwrap|expect|panic)\s*!?\s*\(/u.test(
      keyAgentInstallAdoptionReleaseCode,
    ) &&
    (keyAgentInstallAdoptionReleaseCode.match(
      /\bKeyAgentInstallAdoptionError::RecoveryRequired\b/gu,
    ) ?? []).length === 4 &&
    rustCallSites(
      bindExistingKeyAgentInstallToRelease,
      "preflight_key_agent_activation",
    ).length === 1 &&
    JSON.stringify(
      rustCallSites(
        bindExistingKeyAgentInstallToRelease,
        "preflight_key_agent_activation",
      ).map((call) => call.arguments),
    ) === JSON.stringify([["attestation", "artifact"]]) &&
    rustCallSites(bindExistingKeyAgentInstallToRelease, "revalidate").length ===
      2 &&
    JSON.stringify(
      rustCallSites(bindExistingKeyAgentInstallToRelease, "revalidate").map(
        (call) => call.arguments,
      ),
    ) === JSON.stringify([[], []]) &&
    rustCallSites(
      bindExistingKeyAgentInstallToRelease,
      "matches_release_identity",
    ).length === 1 &&
    JSON.stringify(
      rustCallSites(
        bindExistingKeyAgentInstallToRelease,
        "matches_release_identity",
      ).map((call) => call.arguments),
    ) === JSON.stringify([["&verified.release_identity"]]) &&
    bindExistingKeyAgentInstallToReleaseOrder.every(
      (position) => position !== -1,
    ) &&
    bindExistingKeyAgentInstallToReleaseOrder
      .slice(1)
      .every(
        (position, index) =>
          position > bindExistingKeyAgentInstallToReleaseOrder[index],
      ) &&
    !/\b(?:manifest_digest|allows_helper_manifest|ArtifactDigest|AttestedArtifactDigest)\b/u.test(
      rustLexicalCode(bindExistingKeyAgentInstallToRelease),
    ) &&
    rustCallSites(
      keyAgentSupervisorRelease,
      "consume_artifact_bound_existing_key_agent_install",
    ).length === 1 &&
    JSON.stringify(
      rustCallSites(
        keyAgentSupervisorRelease,
        "consume_artifact_bound_existing_key_agent_install",
      ).map((call) => call.arguments),
    ) ===
      JSON.stringify([
        ["bound", "KeyAgentSupervisorBindingSeal { _private: () }"],
      ]) &&
    rustCallSites(adoptExistingKeyAgentInstall, "revalidate").length === 2 &&
    JSON.stringify(
      rustCallSites(adoptExistingKeyAgentInstall, "revalidate").map(
        (call) => call.arguments,
      ),
    ) === JSON.stringify([[], []]) &&
    rustCallSites(adoptExistingKeyAgentInstall, "install_observation").length ===
      1 &&
    JSON.stringify(
      rustCallSites(adoptExistingKeyAgentInstall, "install_observation").map(
        (call) => call.arguments,
      ),
    ) === JSON.stringify([[]]) &&
    rustCallSites(
      adoptExistingKeyAgentInstall,
      "verify_existing_key_agent_install_snapshots",
    ).length === 1 &&
    JSON.stringify(
      rustCallSites(
        adoptExistingKeyAgentInstall,
        "verify_existing_key_agent_install_snapshots",
      ).map((call) => call.arguments),
    ) === JSON.stringify([["initial", "reread", "observation"]]) &&
    rustCallSites(
      adoptExistingKeyAgentInstall,
      "consume_stable_existing_key_agent_install_evidence",
    ).length === 1 &&
    JSON.stringify(
      rustCallSites(
        adoptExistingKeyAgentInstall,
        "consume_stable_existing_key_agent_install_evidence",
      ).map((call) => call.arguments),
    ) === JSON.stringify([["stable"]]) &&
    rustCallSites(adoptExistingKeyAgentInstall, "into_prepared").length === 1 &&
    JSON.stringify(
      rustCallSites(adoptExistingKeyAgentInstall, "into_prepared").map(
        (call) => call.arguments,
      ),
    ) === JSON.stringify([["ExistingInstallAdoptionSeal { _private: () }"]]) &&
    adoptExistingKeyAgentInstallOrder.every((position) => position !== -1) &&
    adoptExistingKeyAgentInstallOrder
      .slice(1)
      .every(
        (position, index) =>
          position > adoptExistingKeyAgentInstallOrder[index],
      ) &&
    keyAgentInstallAdoptionReleaseCode.includes(
      "_not_sync: PhantomData<Cell<()>>",
    ) &&
    (keyAgentInstallAdoptionReleaseCode.match(
      /_not_sync:\s*PhantomData<Cell<\(\)>>/gu,
    ) ?? []).length === 2 &&
    !/\b(?:ArtifactDigest|AttestedArtifactDigest|manifest_digest|allows_helper_manifest)\b/u.test(
      keyAgentInstallAdoptionReleaseCode.replace(
        bindExistingKeyAgentInstallToRelease,
        "",
      ),
    ) &&
    !/pub\(crate\)\s+(?:const\s+)?fn\s+(?:raw\w*|as_bytes|into_inner|into_parts|release_identity|installation_id|journal_generation|journal_record_digest)\b/u.test(
      keyAgentInstallAdoptionReleaseCode,
    ) &&
    keyAgentInstallAdoptionSource.includes(
      'VerifiedExistingKeyAgentInstall([HELD; REDACTED])',
    ) &&
    keyAgentInstallAdoptionSource.includes(
      'VerifiedKeyAgentInstallContinuity([REDACTED])',
    ) &&
    keyAgentInstallAdoptionSource.includes(
      'ArtifactBoundExistingKeyAgentInstall([HELD; REDACTED])',
    ) &&
    keyAgentInstallAdoptionSource.includes(
      "future backend must enforce that temporal ordering",
    ) &&
    keyAgentInstallAdoptionExpectedTests.every((name) =>
      keyAgentInstallAdoptionSource.includes(`fn ${name}`),
    ),
  "existing Key Agent adoption and release binding must remain private, linear, exact-order, whole-release-bound, sealed into one supervisor consumer, and free of raw authority escape",
);
const keyAgentStorageFactoryConsumers = platformWindowsProductionFiles
  .filter(
    (file) =>
      file.path !== "crates/platform-windows/src/key_agent_storage.rs" &&
      rustLexicalCode(file.source).includes(
        "create_fixed_key_agent_storage_root(",
      ),
  )
  .map((file) => file.path);
const keyAgentChildStorageOpenerConsumers = platformWindowsProductionFiles
  .filter(
    (file) =>
      file.path !== "crates/platform-windows/src/key_agent_storage.rs" &&
      rustCallSites(file.source, "open_fixed_key_agent_storage_root_for_child")
        .length > 0,
  )
  .map((file) => file.path);
const compactKeyAgentStorage = compactRust(keyAgentStorage);
const compactCreateKeyAgentStorageRoot = compactRust(createKeyAgentStorageRoot);
const compactOpenKeyAgentStorageRootHandle = compactRust(
  openKeyAgentStorageRootHandle,
);
const compactValidateKeyAgentStorageProfileFolder = compactRust(
  validateKeyAgentStorageProfileFolder,
);
const compactQueryKeyAgentStorageIdentity = compactRust(
  queryKeyAgentStorageIdentity,
);
const compactVerifyKeyAgentStorageVolume = compactRust(
  verifyKeyAgentStorageVolume,
);
const compactVerifyKeyAgentStorageHandleSecurity = compactRust(
  verifyKeyAgentStorageHandleSecurity,
);
const compactInspectKeyAgentStorageCreationDescriptor = compactRust(
  inspectKeyAgentStorageCreationDescriptor,
);
const compactInspectKeyAgentStorageHandleDescriptor = compactRust(
  inspectKeyAgentStorageHandleDescriptor,
);
const compactInspectExactKeyAgentStorageDacl = compactRust(
  inspectExactKeyAgentStorageDacl,
);
const compactInspectExactKeyAgentStorageLowLabel = compactRust(
  inspectExactKeyAgentStorageLowLabel,
);
const compactRevalidateHeldKeyAgentStorageRoot = compactRust(
  revalidateHeldKeyAgentStorageRoot,
);
const keyAgentStorageRevalidationOrder = [
  "verify_directory_object(handle)?",
  "verify_supported_local_ntfs(handle)?",
  "letidentity=exact_file_identity(handle)?",
  "ifidentity!=self.identity",
  "verify_handle_security(handle,&self.stable_user_sid,&self.profile_sid)",
].map((marker) => compactRevalidateHeldKeyAgentStorageRoot.indexOf(marker));
requireInvariant(
  keyAgentStorage.includes(
    'const KEY_AGENT_STORAGE_ROOT_LEAF: &str = "YourWallet.KeyAgent.Storage.v1";',
  ) &&
    compactKeyAgentStorage.includes(
      "constKEY_AGENT_STORAGE_ROOT_ACCESS:u32=READ_CONTROL.0|SYNCHRONIZE.0|FILE_LIST_DIRECTORY.0|FILE_ADD_FILE.0|FILE_ADD_SUBDIRECTORY.0|FILE_WRITE_EA.0|FILE_TRAVERSE.0|FILE_READ_ATTRIBUTES.0|FILE_WRITE_ATTRIBUTES.0;",
    ) &&
    JSON.stringify(keyAgentStorageFactoryConsumers) ===
      JSON.stringify(["crates/platform-windows/src/key_agent_lpac.rs"]) &&
    keyAgentStorageFactoryCalls.length === 1 &&
    JSON.stringify(
      keyAgentStorageFactoryCalls[0].arguments.map((argument) => compactRust(argument)),
    ) ===
      JSON.stringify([
        "validated_ac_folder",
        "fixed_profile_sid",
        "KEY_AGENT_STORAGE_ROOT_LEAF",
        "false",
      ]) &&
    keyAgentStorageCreateDirectoryCalls.length === 1 &&
    keyAgentStorageCreateDirectoryCalls[0].arguments.length === 2 &&
    keyAgentStorageCreateDirectoryCalls[0].arguments[1] ===
      "Some(ptr::from_ref(&attributes))" &&
    compactCreateKeyAgentStorageRoot.includes(
      "ERROR_ALREADY_EXISTS.to_hresult()",
    ) &&
    compactCreateKeyAgentStorageRoot.includes(
      "Err(KeyAgentStorageError::AlreadyExists)",
    ) &&
    compactCreateKeyAgentStorageRoot.includes("fs::remove_dir(&path)") &&
    !keyAgentStorage.includes("remove_dir_all") &&
    !keyAgentStorage.includes("OPEN_ALWAYS") &&
    keyAgentStorageOpenCalls.length === 1 &&
    keyAgentStorageAllOpenCalls.length === 2 &&
    keyAgentStorageOpenCalls[0].arguments.length === 7 &&
    compactRust(keyAgentStorageOpenCalls[0].arguments[1]) ===
      "FILE_READ_ATTRIBUTES.0|FILE_LIST_DIRECTORY.0|READ_CONTROL.0|GENERIC_WRITE.0" &&
    compactRust(keyAgentStorageOpenCalls[0].arguments[2]) ===
      "FILE_SHARE_READ|FILE_SHARE_WRITE" &&
    keyAgentStorageOpenCalls[0].arguments[4] === "OPEN_EXISTING" &&
    compactRust(keyAgentStorageOpenCalls[0].arguments[5]) ===
      "FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT" &&
    !compactOpenKeyAgentStorageRootHandle.includes("FILE_SHARE_DELETE") &&
    !/\b(?:OpenFileById|NtOpenFile|ZwOpenFile|CreateFile2|File::open|OpenOptions|canonicalize)\b/u.test(
      rustLexicalCode(keyAgentStorage),
    ) &&
    compactValidateKeyAgentStorageProfileFolder.includes("!path.is_absolute()") &&
    validateKeyAgentStorageProfileFolder.includes(
      '!name.eq_ignore_ascii_case("AC")',
    ) &&
    compactValidateKeyAgentStorageProfileFolder.includes(
      "path.ancestors().collect::<Vec<_>>()",
    ) &&
    compactValidateKeyAgentStorageProfileFolder.includes(
      "FILE_ATTRIBUTE_REPARSE_POINT.0!=0",
    ) &&
    verifyKeyAgentStorageDirectory.includes("FILE_ATTRIBUTE_DIRECTORY.0") &&
    verifyKeyAgentStorageDirectory.includes("FILE_ATTRIBUTE_REPARSE_POINT.0") &&
    compactQueryKeyAgentStorageIdentity.includes("FileIdInfo") &&
    compactVerifyKeyAgentStorageVolume.includes("GetDriveTypeW(") &&
    compactVerifyKeyAgentStorageVolume.includes("!=DRIVE_FIXED") &&
    compactVerifyKeyAgentStorageVolume.includes("FileRemoteProtocolInfo") &&
    compactVerifyKeyAgentStorageVolume.includes("GetVolumeInformationByHandleW(") &&
    compactVerifyKeyAgentStorageVolume.includes("FILE_PERSISTENT_ACLS==0") &&
    compactVerifyKeyAgentStorageVolume.includes(
      "!is_exact_ntfs_name(&filesystem_name)",
    ) &&
    keyAgentStorageRootDescriptor.includes(
      '"O:{user}D:P(A;;0x{:08x};;;{user})(A;;0x{:08x};;;{profile})"',
    ) &&
    !keyAgentStorageRootDescriptor.includes("S:") &&
    currentStableKeyAgentStorageUserSid.includes(
      "let token = current_process_token()?",
    ) &&
    currentStableKeyAgentStorageUserSid.includes("token_user_sid(token.0)") &&
    currentKeyAgentStorageProcessToken.includes(
      "OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY",
    ) &&
    compactInspectKeyAgentStorageCreationDescriptor.includes(
      "control_flag(SE_DACL_PROTECTED)",
    ) &&
    compactInspectKeyAgentStorageCreationDescriptor.includes(
      "control_flag(SE_SACL_PRESENT)",
    ) &&
    keyAgentStorageSecurityInfoCalls.length === 1 &&
    keyAgentStorageSecurityInfoCalls[0].arguments.length === 8 &&
    compactRust(keyAgentStorageSecurityInfoCalls[0].arguments[2]) ===
      "OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION|LABEL_SECURITY_INFORMATION" &&
    keyAgentStorageSecurityInfoCalls[0].arguments[6] === "None" &&
    compactVerifyKeyAgentStorageHandleSecurity.includes(
      "GetSecurityDescriptorSacl(",
    ) &&
    compactInspectKeyAgentStorageHandleDescriptor.includes(
      "inspect_exact_low_label(sacl)",
    ) &&
    compactInspectExactKeyAgentStorageDacl.includes(
      "inspect_acl_header(dacl,2)?",
    ) &&
    compactInspectExactKeyAgentStorageDacl.includes(
      "FILE_ALL_ACCESS.0",
    ) &&
    compactInspectExactKeyAgentStorageDacl.includes(
      "KEY_AGENT_STORAGE_ROOT_ACCESS",
    ) &&
    compactInspectExactKeyAgentStorageLowLabel.includes(
      "inspect_acl_header(sacl,1)?",
    ) &&
    compactInspectExactKeyAgentStorageLowLabel.includes(
      "INHERITED_LOW_LABEL_ACE_FLAGS",
    ) &&
    compactInspectExactKeyAgentStorageLowLabel.includes(
      "SYSTEM_MANDATORY_LABEL_NO_WRITE_UP",
    ) &&
    compactInspectExactKeyAgentStorageLowLabel.includes(
      "LOW_MANDATORY_LABEL_SID",
    ) &&
    JSON.stringify(heldKeyAgentStorageRootMethods) ===
      JSON.stringify([
        "identity",
        "install_observation",
        "revalidate",
        "path_for_test",
      ]) &&
    normalizeRustFragment(rustLexicalCode(heldKeyAgentRootObservationDefinition)) ===
      "pub(crate) struct KeyAgentHeldRootObservation { root_identity: KeyAgentStorageRootIdentity, stable_user_sid_len: u8, stable_user_sid: [u8; MAX_BINARY_SID_BYTES], profile_sid_len: u8, profile_sid: [u8; MAX_BINARY_SID_BYTES], }" &&
    JSON.stringify(heldKeyAgentRootObservationMethods) ===
      JSON.stringify(["root_identity", "stable_user_sid", "profile_sid"]) &&
    rustStructLiteralSites(
      heldKeyAgentStorageInstallObservation,
      "KeyAgentHeldRootObservation",
    ).length === 1 &&
    heldKeyAgentStorageInstallObservation.includes(
      "self.stable_user_sid.canonical_bytes()?",
    ) &&
    heldKeyAgentStorageInstallObservation.includes(
      "self.profile_sid.canonical_bytes()?",
    ) &&
    keyAgentStorageSource.includes(
      "KeyAgentHeldRootObservation([REDACTED IDENTITIES])",
    ) &&
    heldKeyAgentStorageRootImpl.includes(
      "#[cfg(test)]\n    pub(crate) fn path_for_test",
    ) &&
    heldKeyAgentStorageRootDefinition.includes("handle: Option<std::fs::File>") &&
    heldKeyAgentStorageRootDefinition.includes(
      "identity: KeyAgentStorageRootIdentity",
    ) &&
    heldKeyAgentStorageRootDefinition.includes("#[cfg(test)]\n    path: PathBuf") &&
    heldKeyAgentStorageRootDefinition.includes(
      "#[cfg(test)]\n    cleanup_on_drop: bool",
    ) &&
    !/#\[derive\([^\]]*(?:Clone|Copy)[^\]]*\)\]\s*pub\(crate\)\s+struct\s+HeldKeyAgentStorageRoot/u.test(
      keyAgentStorage,
    ) &&
    !/impl\s+(?:Clone|Copy|Sync)\s+for\s+HeldKeyAgentStorageRoot\b/u.test(
      keyAgentStorage,
    ) &&
    heldKeyAgentStorageRootDebug.includes("[REDACTED LOCAL PATH]") &&
    keyAgentStorageRevalidationOrder.every((position) => position !== -1) &&
    keyAgentStorageRevalidationOrder
      .slice(1)
      .every(
        (position, index) => position > keyAgentStorageRevalidationOrder[index],
      ) &&
    heldKeyAgentStorageRootDrop.includes("drop(self.handle.take())") &&
    heldKeyAgentStorageRootDrop.includes("fs::remove_dir(&self.path)") &&
    !heldKeyAgentStorageRootDrop.includes("remove_dir_all") &&
    keyAgentProvisioningKernelTest.includes("provisioning.revalidate()?") &&
    keyAgentProvisioningKernelTest.includes("assert!(storage_root.is_dir())") &&
    keyAgentProvisioningKernelTest.includes("drop(provisioning)") &&
    keyAgentProvisioningKernelTest.includes("assert!(!storage_root.exists())") &&
    integratedKeyAgentStorageBindingTest.includes("assert!(storage_root.is_dir())") &&
    integratedKeyAgentStorageBindingTest.includes("drop(bound)") &&
    integratedKeyAgentStorageBindingTest.includes("assert!(!storage_root.exists())") &&
    !keyAgentStorage.includes("WindowsGenerationStore") &&
    !keyAgentActivationRelease.includes("HeldKeyAgentStorageRoot"),
  "the Key Agent storage proof must fresh-create one fixed root with the exact dual-principal protected DACL, inherited Low/NW label, local NTFS identity, no-delete-share held handle, opaque revalidation authority, and real cfg(test) kernel cleanup proof",
);
requireInvariant(
  normalizeRustFragment(rustLexicalCode(keyAgentStorageIdentityDefinition)) ===
      "pub(crate) struct KeyAgentStorageRootIdentity { volume_serial_number: u64, file_id: [u8; 16], }" &&
    keyAgentStorageIdentityImpl.includes(
      "pub(crate) fn encode_be(self) -> [u8; 24]",
    ) &&
    keyAgentStorageIdentityImpl.includes(
      "pub(crate) fn decode_be(encoded: [u8; 24])",
    ) &&
    keyAgentStorageIdentityImpl.includes("volume_serial_number == 0") &&
    keyAgentStorageIdentityImpl.includes("file_id == [0; 16]") &&
    keyAgentStorageIdentityImpl.includes("file_id == [u8::MAX; 16]") &&
    normalizeRustFragment(rustLexicalCode(heldChildKeyAgentStorageRootDefinition)) ===
      "pub(crate) struct HeldChildKeyAgentStorageRoot { handle: std::fs::File, identity: KeyAgentStorageRootIdentity, stable_user_sid: OwnedSid, profile_sid: OwnedSid, #[allow(dead_code)] path: PathBuf, }" &&
    JSON.stringify(heldChildKeyAgentStorageRootMethods) ===
      JSON.stringify([
        "identity",
        "revalidate",
        "into_fixed_generation_store_bindings",
      ]) &&
    !/#\[derive\([^\]]*(?:Clone|Copy)[^\]]*\)\]\s*pub\(crate\)\s+struct\s+HeldChildKeyAgentStorageRoot/u.test(
      keyAgentStorage,
    ) &&
    !/impl\s+(?:Clone|Copy|Sync|AsRawHandle)\s+for\s+HeldChildKeyAgentStorageRoot\b/u.test(
      keyAgentStorage,
    ) &&
    heldChildKeyAgentStorageRootDebug.includes(
      "HeldChildKeyAgentStorageRoot([REDACTED HELD DIRECTORY])",
    ) &&
    /pub\(crate\)\s+fn\s+open_fixed_key_agent_storage_root_for_child\s*\(\s*\)\s*->\s*Result<HeldChildKeyAgentStorageRoot,\s*KeyAgentStorageError>\s*\{\s*open_child_storage_root\(KEY_AGENT_STORAGE_ROOT_LEAF\)\s*\}/u.test(
      rustLexicalCode(openFixedKeyAgentStorageRootForChild),
    ) &&
    JSON.stringify(keyAgentChildStorageOpenerConsumers) ===
      JSON.stringify([
        "crates/platform-windows/src/key_agent_child_bootstrap.rs",
      ]) &&
    openChildKeyAgentStorageRoot.includes(
      'std::env::var_os("LOCALAPPDATA")',
    ) &&
    openChildKeyAgentStorageRoot.includes("reject_thread_impersonation()?") &&
    openChildKeyAgentStorageRoot.includes("current_process_token()?") &&
    openChildKeyAgentStorageRoot.includes("token_user_sid(token.0)?") &&
    openChildKeyAgentStorageRoot.includes("token_appcontainer_sid(token.0)?") &&
    openChildKeyAgentStorageRoot.includes(
      "let handle = open_storage_root_handle(&path)?",
    ) &&
    openChildKeyAgentStorageRoot.includes("held.revalidate()?") &&
    validateChildKeyAgentStorageProfileFolder.includes(
      '!local_folder_name.eq_ignore_ascii_case("AC")',
    ) &&
    validateChildKeyAgentStorageProfileFolder.includes(
      "!profile_name.eq_ignore_ascii_case(KEY_AGENT_PROFILE_V1_NAME)",
    ) &&
    validateChildKeyAgentStorageProfileFolder.includes(
      '!packages_name.eq_ignore_ascii_case("Packages")',
    ) &&
    verifyChildKeyAgentStorageRoot.includes("verify_directory_object(handle)?") &&
    verifyChildKeyAgentStorageRoot.includes(
      "verify_handle_security(handle, stable_user_sid, profile_sid)?",
    ) &&
    verifyChildKeyAgentStorageRoot.includes("exact_file_identity(handle)"),
  "the Key Agent storage proof must expose full path-free FILE_ID_INFO and let only the child bootstrap reopen and retain that root through the sole exact no-delete-share probe",
);
const fixedKeyAgentBindingMintConsumers = platformWindowsProductionFiles
  .filter(
    (file) =>
      file.path !== "crates/platform-windows/src/key_agent_storage.rs" &&
      rustCallSites(file.source, "into_fixed_generation_store_bindings")
        .length > 0,
  )
  .map((file) => file.path);
const fixedKeyAgentBackendOpenProductionConsumers =
  platformWindowsProductionFiles
    .filter(
      (file) =>
        file.path !== "crates/platform-windows/src/storage/sys.rs" &&
        file.path !== "crates/platform-windows/src/storage.rs" &&
        rustCallSites(file.source, "WindowsBackend::open_key_agent").length >
          0,
    )
    .map((file) => file.path);
const fixedKeyAgentBackendFacadeProductionCalls = rustCallSites(
  windowsStorageFacadeRelease.replace(
    exerciseFixedKeyAgentGenerationStores,
    "",
  ),
  "sys::WindowsBackend::open_key_agent",
);
const fixedKeyAgentBindingConstructorCalls = rustCallSites(
  keyAgentStorageRelease,
  "KeyAgentGenerationStoreBinding::new",
);
const fixedKeyAgentBindingFromRootCalls = rustCallSites(
  keyAgentStorageRelease,
  "FixedKeyAgentGenerationStoreBindings::from_child_root",
);
const fixedKeyAgentBackendTestOpenCalls = rustCallSites(
  exerciseFixedKeyAgentGenerationStores,
  "sys::WindowsBackend::open_key_agent",
);
const compactMintFixedKeyAgentGenerationStoreBindings = compactRust(
  mintFixedKeyAgentGenerationStoreBindings,
);
const compactFixedKeyAgentGenerationStoreBindingsFromChildRoot = compactRust(
  fixedKeyAgentGenerationStoreBindingsFromChildRoot,
);
const fixedKeyAgentBindingSurface = [
  fixedKeyAgentGenerationStoreRoleDefinition,
  keyAgentGenerationStoreRootAuthorityDefinition,
  keyAgentGenerationStoreBindingDefinition,
  keyAgentGenerationStoreBindingImpl,
  fixedKeyAgentGenerationStoreBindingsDefinition,
  fixedKeyAgentGenerationStoreBindingsImpl,
  openFixedKeyAgentGenerationStore,
  fixedKeyAgentGenerationStoreSpec,
].join("\n");
requireInvariant(
  JSON.stringify(publicWindowsGenerationStoreMethods) ===
    JSON.stringify(["open", "load", "commit"]) &&
    publicWindowsGenerationStoreOpen.includes(
      "let backend = sys::WindowsBackend::open(&config)?",
    ) &&
    !publicWindowsGenerationStoreImpl.includes("open_key_agent") &&
    normalizeRustFragment(
      rustLexicalCode(fixedKeyAgentGenerationStoreRoleDefinition),
    ) ===
      "pub(crate) enum FixedKeyAgentGenerationStoreRole { Vault = 1, NonceLedger = 2, SignedCandidateJournal = 3, LocalSettings = 4, }" &&
    normalizeRustFragment(
      rustLexicalCode(keyAgentGenerationStoreRootAuthorityDefinition),
    ) ===
      "struct KeyAgentGenerationStoreRootAuthority { root: HeldChildKeyAgentStorageRoot, }" &&
    normalizeRustFragment(
      rustLexicalCode(keyAgentGenerationStoreBindingDefinition),
    ) ===
      "pub(crate) struct KeyAgentGenerationStoreBinding { authority: Arc<KeyAgentGenerationStoreRootAuthority>, role: FixedKeyAgentGenerationStoreRole, _not_send_or_sync: PhantomData<Rc<()>>, }" &&
    normalizeRustFragment(
      rustLexicalCode(fixedKeyAgentGenerationStoreBindingsDefinition),
    ) ===
      "pub(crate) struct FixedKeyAgentGenerationStoreBindings { vault: KeyAgentGenerationStoreBinding, nonce_ledger: KeyAgentGenerationStoreBinding, signed_candidate_journal: KeyAgentGenerationStoreBinding, local_settings: KeyAgentGenerationStoreBinding, }" &&
    /^fn\s+new\s*\(/u.test(
      normalizeRustFragment(rustLexicalCode(keyAgentGenerationStoreBindingNew)),
    ) &&
    JSON.stringify(keyAgentGenerationStoreBindingMethods) ===
      JSON.stringify([
        "role",
        "root_path",
        "root_handle",
        "stable_user_sid",
        "profile_sid",
        "identity",
        "revalidate",
      ]) &&
    JSON.stringify(fixedKeyAgentGenerationStoreBindingsMethods) ===
      JSON.stringify(["identity", "revalidate", "into_parts"]) &&
    !/#\[derive\([^\]]*(?:Clone|Copy)[^\]]*\)\]\s*pub\(crate\)\s+struct\s+(?:KeyAgentGenerationStoreBinding|FixedKeyAgentGenerationStoreBindings)/u.test(
      keyAgentStorageRelease,
    ) &&
    !/impl\s+(?:Clone|Copy|Send|Sync|AsRawHandle)\s+for\s+(?:KeyAgentGenerationStoreBinding|FixedKeyAgentGenerationStoreBindings)\b/u.test(
      keyAgentStorageRelease,
    ) &&
    compactMintFixedKeyAgentGenerationStoreBindings.includes(
      "reject_thread_impersonation()?;self.revalidate()?;reject_thread_impersonation()?;",
    ) &&
    fixedKeyAgentBindingFromRootCalls.length === 1 &&
    fixedKeyAgentBindingFromRootCalls[0].arguments.length === 1 &&
    fixedKeyAgentBindingFromRootCalls[0].arguments[0] === "self" &&
    fixedKeyAgentBindingConstructorCalls.length === 4 &&
    compactFixedKeyAgentGenerationStoreBindingsFromChildRoot.includes(
      "FixedKeyAgentGenerationStoreRole::Vault",
    ) &&
    compactFixedKeyAgentGenerationStoreBindingsFromChildRoot.includes(
      "FixedKeyAgentGenerationStoreRole::NonceLedger",
    ) &&
    compactFixedKeyAgentGenerationStoreBindingsFromChildRoot.includes(
      "FixedKeyAgentGenerationStoreRole::SignedCandidateJournal",
    ) &&
    compactFixedKeyAgentGenerationStoreBindingsFromChildRoot.includes(
      "FixedKeyAgentGenerationStoreRole::LocalSettings",
    ) &&
    JSON.stringify(fixedKeyAgentBindingMintConsumers) ===
      JSON.stringify([
        "crates/platform-windows/src/key_agent_child_bootstrap.rs",
      ]) &&
    JSON.stringify(fixedKeyAgentBackendOpenProductionConsumers) ===
      JSON.stringify([]) &&
    fixedKeyAgentBackendFacadeProductionCalls.length === 0 &&
    /pub\(super\)\s+fn\s+open_key_agent\s*\(\s*binding:\s*KeyAgentGenerationStoreBinding\s*,?\s*\)/u.test(
      rustLexicalCode(openFixedKeyAgentGenerationStore),
    ) &&
    openFixedKeyAgentGenerationStore.includes(
      "fixed_key_agent_store_spec(binding.role())",
    ) &&
    openFixedKeyAgentGenerationStore.includes(
      "SecurityDescriptor::for_key_agent_files(",
    ) &&
    /FixedKeyAgentGenerationStoreRole::Vault\s*=>\s*\(\s*"vault",\s*RecordClass::Vault,\s*4_194_416,?\s*\)/su.test(
      fixedKeyAgentGenerationStoreSpec,
    ) &&
    /FixedKeyAgentGenerationStoreRole::NonceLedger\s*=>\s*\{?\s*\(\s*"nonce-ledger",\s*RecordClass::NonceLedger,\s*16_777_216,?\s*\)\s*\}?/su.test(
      fixedKeyAgentGenerationStoreSpec,
    ) &&
    /FixedKeyAgentGenerationStoreRole::SignedCandidateJournal\s*=>\s*\(\s*"signed-candidate-journal",\s*RecordClass::SignedCandidateJournal,\s*16_777_216,?\s*\)/su.test(
      fixedKeyAgentGenerationStoreSpec,
    ) &&
    /FixedKeyAgentGenerationStoreRole::LocalSettings\s*=>\s*\{?\s*\(\s*"local-settings",\s*RecordClass::LocalSettings,\s*226,?\s*\)\s*\}?/su.test(
      fixedKeyAgentGenerationStoreSpec,
    ) &&
    fixedKeyAgentBackendTestOpenCalls.length === 3 &&
    /#\s*\[\s*cfg\s*\(\s*all\s*\(\s*windows\s*,\s*test\s*\)\s*\)\s*\]\s*(?:#\s*\[[^\]]*\]\s*)*pub\(crate\)\s+fn\s+exercise_fixed_key_agent_generation_stores_for_test/u.test(
      rustLexicalCode(windowsStorageFacade),
    ) &&
    !/\b(?:Approval|SecretInput|Frontend)\b/u.test(
      rustLexicalCode(fixedKeyAgentBindingSurface),
    ),
  "the public stable-user store must remain unchanged while only the consuming child-root transition can mint four sealed fixed-role bindings for the dormant private Key Agent backend",
);
const revalidateFixedKeyAgentGenerationStoreHeldRoot = rustFunctionBlock(
  windowsStorageRelease,
  "revalidate_held_root",
);
const fixedKeyAgentGenerationStoreHeldRootBranch =
  /HeldRoot::KeyAgent\(binding\)\s*=>\s*\{[\s\S]*?\n\s*\}/u.exec(
    revalidateFixedKeyAgentGenerationStoreHeldRoot,
  )?.[0] ?? "";
const fixedKeyAgentGenerationStoreBackendDefinition = rustLexicalItemBlock(
  windowsStorageRelease,
  /pub\(super\)\s+struct\s+WindowsBackend\s*\{/u,
);
const verifyFixedKeyAgentGenerationStorePersistentFile = rustFunctionBlock(
  windowsStorageRelease,
  "verify_persistent_file",
);
const requireFixedKeyAgentGenerationStoreForbiddenDenial = rustFunctionBlock(
  windowsStorage,
  "require_forbidden_access_denial",
);
const verifyFixedKeyAgentGenerationStoreRootRights = rustFunctionBlock(
  keyAgentStorage,
  "verify_forbidden_root_rights_for_test",
);
const requireFixedKeyAgentGenerationStoreRootOpenError = rustFunctionBlock(
  keyAgentStorage,
  "require_root_open_error_for_test",
);
const accessCheckFixedKeyAgentGenerationStoreRootRight = rustFunctionBlock(
  keyAgentStorage,
  "access_check_denies_root_right_for_test",
);
const revalidateFixedKeyAgentGenerationStoreSecurityContext = rustFunctionBlock(
  windowsStorageRelease,
  "revalidate_security_context",
);
const hitFixedKeyAgentGenerationStoreFault = rustFunctionBlock(
  windowsStorageFacadeRelease,
  "hit_fault_with_security_revalidation",
);
const commitFixedKeyAgentGenerationStoreWithFault = rustFunctionBlock(
  windowsStorageFacadeRelease,
  "commit_with_fault",
);
const fixedKeyAgentGenerationStoreFaultPoints = rustFunctionBlock(
  windowsStorageRelease,
  "fault_points",
);
const fixedKeyAgentGenerationStoreOpenRevalidations = rustCallSites(
  openFixedKeyAgentGenerationStore,
  "revalidate_key_agent_root_path",
);
const fixedKeyAgentGenerationStoreRootPathRevalidations = rustCallSites(
  revalidateFixedKeyAgentGenerationStoreRootPath,
  "revalidate",
);
const fixedKeyAgentGenerationStoreStaleTempRevalidations = rustCallSites(
  removeFixedKeyAgentGenerationStoreStaleTemp,
  "prepare_key_agent_path_operation",
);
const fixedKeyAgentGenerationStoreReadRevalidations = rustCallSites(
  readFixedKeyAgentGenerationStore,
  "prepare_key_agent_path_operation",
);
const fixedKeyAgentGenerationStoreWriteRevalidations = rustCallSites(
  writeFixedKeyAgentGenerationStore,
  "prepare_key_agent_path_operation",
);
const compactFixedKeyAgentGenerationStoreWrite = compactRust(
  writeFixedKeyAgentGenerationStore,
);
const fixedKeyAgentGenerationStoreTargetOrder = [
  "letinitial_target=open_existing_file(target);",
  "letinitial_target_identity=inspect_optional_target(",
  "letexisting_target=open_existing_file(target);",
  "letexisting_target_identity=inspect_optional_target(",
  "ifexisting_target_identity!=initial_target_identity",
  "letreplaced=atomic_replace(temp,target);",
  "verify_installed_readback(",
  "letrebound=open_existing_file(target);",
  "iffile_identity(&rebound)?!=temp_identity",
].map((marker) => compactFixedKeyAgentGenerationStoreWrite.indexOf(marker));
const fixedKeyAgentGenerationStorePathBookends = [
  "self.prepare_key_agent_path_operation()?;letinitial_target=open_existing_file(target);self.prepare_key_agent_path_operation()?;",
  "self.prepare_key_agent_path_operation()?;letcreated=create_new_write_through(temp,&self.security_descriptor);self.prepare_key_agent_path_operation()?;",
  "self.prepare_key_agent_path_operation()?;letexisting_target=open_existing_file(target);self.prepare_key_agent_path_operation()?;",
  "self.prepare_key_agent_path_operation()?;letreplaced=atomic_replace(temp,target);self.prepare_key_agent_path_operation()?;",
  "self.prepare_key_agent_path_operation()?;letinstalled=open_existing_file(target);self.prepare_key_agent_path_operation()?;",
  "self.prepare_key_agent_path_operation()?;letrebound=open_existing_file(target);self.prepare_key_agent_path_operation()?;",
];
const compactFixedKeyAgentGenerationStoreFault = compactRust(
  hitFixedKeyAgentGenerationStoreFault,
);
const compactFixedKeyAgentGenerationStoreCommitWithFault = compactRust(
  commitFixedKeyAgentGenerationStoreWithFault,
);
const fixedKeyAgentGenerationStoreWriteFaultCalls = rustCallSites(
  writeFixedKeyAgentGenerationStore,
  "hit_fault_with_security_revalidation",
);
const fixedKeyAgentGenerationStoreCommitFaultCalls = rustCallSites(
  commitFixedKeyAgentGenerationStoreWithFault,
  "hit_fault_with_security_revalidation",
);
const fixedKeyAgentGenerationStoreKernelRights = [
  "WRITE_DAC.0",
  "WRITE_OWNER.0",
  "FILE_EXECUTE.0",
  "ACCESS_SYSTEM_SECURITY",
];
const fixedKeyAgentGenerationStoreKernelSurface = compactRust(
  verifyFixedKeyAgentGenerationStoreRoleForTest,
);
const compactFixedKeyAgentGenerationStoreExercise = compactRust(
  exerciseFixedKeyAgentGenerationStores,
);
const compactFixedKeyAgentGenerationStoreRootRights = compactRust(
  verifyFixedKeyAgentGenerationStoreRootRights,
);
requireInvariant(
  windowsStorage.includes(
    "const KEY_AGENT_FILE_ACCESS: u32 = FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0 | DELETE.0;",
  ) &&
    fixedKeyAgentGenerationStoreContractTest.includes(
      "assert_eq!(KEY_AGENT_FILE_ACCESS, 0x0013_019f)",
    ) &&
    fixedKeyAgentGenerationStoreContractTest.includes(
      "assert_eq!(FILE_ALL_ACCESS.0, 0x001f_01ff)",
    ) &&
    fixedKeyAgentGenerationStoreFileDescriptor.includes(
      '"O:{user_text}D:P(A;;0x{:08x};;;{user_text})(A;;0x{KEY_AGENT_FILE_ACCESS:08x};;;{profile_text})"',
    ) &&
    fixedKeyAgentGenerationStoreFileDescriptor.includes("FILE_ALL_ACCESS.0") &&
    verifyFixedKeyAgentGenerationStoreFileSecurity.includes(
      "OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION",
    ) &&
    inspectFixedKeyAgentGenerationStoreFileDescriptor.includes(
      "inspect_exact_key_agent_dacl(dacl, stable_user_sid, profile_sid)?",
    ) &&
    inspectFixedKeyAgentGenerationStoreFileDescriptor.includes(
      "inspect_exact_inherited_low_label(sacl)",
    ) &&
    inspectFixedKeyAgentGenerationStoreDacl.includes(
      "inspect_acl_header(dacl, 2)?",
    ) &&
    inspectFixedKeyAgentGenerationStoreDacl.indexOf(
      "inspect_allow_ace(user_ace, stable_user_sid, FILE_ALL_ACCESS.0)?",
    ) <
      inspectFixedKeyAgentGenerationStoreDacl.indexOf(
        "inspect_allow_ace(profile_ace, profile_sid, KEY_AGENT_FILE_ACCESS)?",
      ) &&
    inspectFixedKeyAgentGenerationStoreDacl.includes(
      "require_exact_acl_size(acl_size, &information, exact_bytes)",
    ) &&
    inspectFixedKeyAgentGenerationStoreLowLabel.includes(
      "inspect_acl_header(sacl, 1)?",
    ) &&
    inspectFixedKeyAgentGenerationStoreLowLabel.includes(
      "header.AceFlags != INHERITED_FILE_LABEL_ACE_FLAGS",
    ) &&
    inspectFixedKeyAgentGenerationStoreLowLabel.includes(
      "SYSTEM_MANDATORY_LABEL_NO_WRITE_UP",
    ) &&
    inspectFixedKeyAgentGenerationStoreLowLabel.includes(
      "LOW_MANDATORY_LABEL_SID",
    ) &&
    queryFixedKeyAgentGenerationStoreFileIdentity.includes(
      "let mut information = FILE_ID_INFO::default()",
    ) &&
    queryFixedKeyAgentGenerationStoreFileIdentity.includes(
      "GetFileInformationByHandleEx(",
    ) &&
    queryFixedKeyAgentGenerationStoreFileIdentity.includes("FileIdInfo") &&
    queryFixedKeyAgentGenerationStoreFileIdentity.includes(
      "information.FileId.Identifier",
    ) &&
    queryFixedKeyAgentGenerationStoreFileIdentity.includes(
      "information.VolumeSerialNumber == 0",
    ) &&
    queryFixedKeyAgentGenerationStoreFileIdentity.includes(
      "file_id == [0_u8; 16]",
    ) &&
    queryFixedKeyAgentGenerationStoreFileIdentity.includes(
      "file_id == [u8::MAX; 16]",
    ) &&
    verifyFixedKeyAgentGenerationStorePersistentFile.includes(
      "verify_not_reparse(file)?",
    ) &&
    verifyFixedKeyAgentGenerationStorePersistentFile.includes(
      "information.nNumberOfLinks != 1",
    ) &&
    inspectFixedKeyAgentGenerationStoreTarget.includes(
      "verify_persistent_file(&file, descriptor)?",
    ) &&
    inspectFixedKeyAgentGenerationStoreTarget.includes(
      "identity.volume_serial != expected_volume_serial",
    ) &&
    fixedKeyAgentGenerationStoreOpenRevalidations.length === 2 &&
    fixedKeyAgentGenerationStoreRootPathRevalidations.length === 2 &&
    fixedKeyAgentGenerationStoreHeldRootBranch.includes(
      "binding.revalidate().map_err(|_| StoreError::UnsafePath)?",
    ) &&
    !fixedKeyAgentGenerationStoreHeldRootBranch.includes(
      "verify_supported_local_volume",
    ) &&
    fixedKeyAgentGenerationStoreBackendDefinition.includes(
      "slot_paths: [PathBuf; 2]",
    ) &&
    fixedKeyAgentGenerationStoreBackendDefinition.includes(
      "temp_paths: [PathBuf; 3]",
    ) &&
    revalidateFixedKeyAgentGenerationStoreRootPath.includes(
      "let reopened = open_directory(root)?",
    ) &&
    revalidateFixedKeyAgentGenerationStoreRootPath.includes(
      "file_identity(&reopened)? != expected_identity",
    ) &&
    prepareFixedKeyAgentGenerationStorePathOperation.includes(
      "self.revalidate_held_root()?",
    ) &&
    fixedKeyAgentGenerationStoreStaleTempRevalidations.length === 4 &&
    fixedKeyAgentGenerationStoreReadRevalidations.length === 2 &&
    fixedKeyAgentGenerationStoreWriteRevalidations.length === 12 &&
    fixedKeyAgentGenerationStorePathBookends.every((bookend) =>
      compactFixedKeyAgentGenerationStoreWrite.includes(bookend),
    ) &&
    revalidateFixedKeyAgentGenerationStoreSecurityContext.includes(
      "self.prepare_key_agent_path_operation()",
    ) &&
    compactFixedKeyAgentGenerationStoreFault.includes(
      "backend.revalidate_security_context()?;letfault_result=fault.hit(point);backend.revalidate_security_context()?;fault_result",
    ) &&
    fixedKeyAgentGenerationStoreWriteFaultCalls.length === 5 &&
    [0, 1, 2, 3, 4].every((index) =>
      compactFixedKeyAgentGenerationStoreWrite.includes(
        `hit_fault_with_security_revalidation(self,fault,points[${index}])?;`,
      ),
    ) &&
    !compactFixedKeyAgentGenerationStoreWrite.includes("fault.hit(") &&
    fixedKeyAgentGenerationStoreCommitFaultCalls.length === 2 &&
    compactFixedKeyAgentGenerationStoreCommitWithFault.includes(
      "hit_fault_with_security_revalidation(&self.backend,fault,FaultPoint::BeforeAnchorAdvance,)?;",
    ) &&
    compactFixedKeyAgentGenerationStoreCommitWithFault.includes(
      "hit_fault_with_security_revalidation(&self.backend,fault,FaultPoint::AfterAnchorAdvance)?;",
    ) &&
    compactFixedKeyAgentGenerationStoreCommitWithFault.indexOf(
      "FaultPoint::BeforeAnchorAdvance",
    ) <
      compactFixedKeyAgentGenerationStoreCommitWithFault.indexOf(
        "self.anchor.compare_and_advance",
      ) &&
    compactFixedKeyAgentGenerationStoreCommitWithFault.indexOf(
      "self.anchor.compare_and_advance",
    ) <
      compactFixedKeyAgentGenerationStoreCommitWithFault.indexOf(
        "FaultPoint::AfterAnchorAdvance",
      ) &&
    !compactFixedKeyAgentGenerationStoreCommitWithFault.includes("fault.hit(") &&
    fixedKeyAgentGenerationStoreFaultPoints.includes(
      "FaultPoint::SlotTempCreated",
    ) &&
    fixedKeyAgentGenerationStoreFaultPoints.includes(
      "FaultPoint::SlotTempWritten",
    ) &&
    fixedKeyAgentGenerationStoreFaultPoints.includes(
      "FaultPoint::SlotTempFlushed",
    ) &&
    fixedKeyAgentGenerationStoreFaultPoints.includes(
      "FaultPoint::SlotReplaced",
    ) &&
    fixedKeyAgentGenerationStoreFaultPoints.includes(
      "FaultPoint::SlotDirectoryFlushed",
    ) &&
    fixedKeyAgentGenerationStoreFaultPoints.includes(
      "FaultPoint::ManifestTempCreated",
    ) &&
    fixedKeyAgentGenerationStoreFaultPoints.includes(
      "FaultPoint::ManifestTempWritten",
    ) &&
    fixedKeyAgentGenerationStoreFaultPoints.includes(
      "FaultPoint::ManifestTempFlushed",
    ) &&
    fixedKeyAgentGenerationStoreFaultPoints.includes(
      "FaultPoint::ManifestReplaced",
    ) &&
    fixedKeyAgentGenerationStoreFaultPoints.includes(
      "FaultPoint::ManifestDirectoryFlushed",
    ) &&
    fixedKeyAgentGenerationStoreTargetOrder.every(
      (position) => position !== -1,
    ) &&
    fixedKeyAgentGenerationStoreTargetOrder
      .slice(1)
      .every(
        (position, index) =>
          position > fixedKeyAgentGenerationStoreTargetOrder[index],
      ) &&
    fixedKeyAgentGenerationStoreTargetBaselineTest.includes(
      "InjectWrongPolicyTarget",
    ) &&
    fixedKeyAgentGenerationStoreTargetBaselineTest.includes(
      "SubstituteValidTarget",
    ) &&
    fixedKeyAgentGenerationStoreDaclNegativeTest.includes(
      "KEY_AGENT_FILE_ACCESS ^ FILE_READ_ATTRIBUTES.0",
    ) &&
    fixedKeyAgentGenerationStoreDaclNegativeTest.includes(
      "KEY_AGENT_FILE_ACCESS | WRITE_DAC.0",
    ) &&
    fixedKeyAgentGenerationStoreDaclNegativeTest.includes(
      "(A;;FR;;;WD)",
    ) &&
    fixedKeyAgentGenerationStoreDaclNegativeTest.includes("(A;ID;") &&
    fixedKeyAgentGenerationStoreDaclNegativeTest.includes("(D;;") &&
    fixedKeyAgentGenerationStoreLabelNegativeTest.includes(
      '"S:(ML;ID;NW;;;LW)"',
    ) &&
    fixedKeyAgentGenerationStoreLabelNegativeTest.includes(
      '"S:(ML;OICIID;NW;;;LW)"',
    ) &&
    fixedKeyAgentGenerationStoreLabelNegativeTest.includes(
      '"S:(ML;ID;NW;;;ME)"',
    ),
  "the private Key Agent generation backend must enforce the exact 0x001f01ff/0x0013019f two-principal file policy, ID-only inherited Low/NW label, full FILE_ID_INFO, per-path root revalidation, and target baseline",
);
requireInvariant(
  fixedKeyAgentGenerationStoreKernelSurface.includes(
    "letmutall_paths=Vec::with_capacity(7);",
  ) &&
    fixedKeyAgentGenerationStoreKernelSurface.includes(
      "all_paths.push(lock_path);",
    ) &&
    fixedKeyAgentGenerationStoreKernelSurface.includes(
      "all_paths.extend(slot_paths);",
    ) &&
    fixedKeyAgentGenerationStoreKernelSurface.includes(
      "all_paths.push(manifest_path);",
    ) &&
    fixedKeyAgentGenerationStoreKernelSurface.includes(
      "all_paths.extend(temp_paths.iter().cloned());",
    ) &&
    fixedKeyAgentGenerationStoreKernelSurface.includes(
      "forpathin&all_paths",
    ) &&
    fixedKeyAgentGenerationStoreKernelSurface.includes(
      "forforbidden_accessin[WRITE_DAC.0,WRITE_OWNER.0,FILE_EXECUTE.0,ACCESS_SYSTEM_SECURITY,]",
    ) &&
    fixedKeyAgentGenerationStoreKernelRights.every((right) =>
      fixedKeyAgentGenerationStoreKernelSurface.includes(right),
    ) &&
    fixedKeyAgentGenerationStoreKernelSurface.includes(
      "require_forbidden_access_denial(denied,forbidden_access)?;",
    ) &&
    requireFixedKeyAgentGenerationStoreForbiddenDenial.includes(
      "desired_access == ACCESS_SYSTEM_SECURITY",
    ) &&
    requireFixedKeyAgentGenerationStoreForbiddenDenial.includes(
      "ERROR_PRIVILEGE_NOT_HELD.to_hresult()",
    ) &&
    requireFixedKeyAgentGenerationStoreForbiddenDenial.includes(
      "desired_access != ACCESS_SYSTEM_SECURITY",
    ) &&
    requireFixedKeyAgentGenerationStoreForbiddenDenial.includes(
      "ERROR_ACCESS_DENIED.to_hresult()",
    ) &&
    exerciseFixedKeyAgentGenerationStores.includes(
      "let anchors: [MemoryAnchor; 4]",
    ) &&
    exerciseFixedKeyAgentGenerationStores.includes(
      "let first_bindings = aggregate.bindings_for_test()",
    ) &&
    exerciseFixedKeyAgentGenerationStores.includes(
      "let second_bindings = aggregate.bindings_for_test()",
    ) &&
    compactFixedKeyAgentGenerationStoreExercise.includes(
      "ifstore.commit(None,&payload)?.generation()!=1||store.load()?.generation()!=1",
    ) &&
    compactFixedKeyAgentGenerationStoreExercise.includes("drop(first_stores);") &&
    compactFixedKeyAgentGenerationStoreExercise.includes(
      "ifstore.load()?.generation()!=1||store.commit(Some(1),&payload)?.generation()!=2||store.load()?.generation()!=2",
    ) &&
    exerciseFixedKeyAgentGenerationStores.includes(
      "store.backend.verify_and_cleanup_key_agent_role_for_test()",
    ) &&
    exerciseFixedKeyAgentGenerationStores.includes("struct ExactCleanup") &&
    exerciseFixedKeyAgentGenerationStores.includes("cleanup.armed = false") &&
    compactFixedKeyAgentGenerationStoreRootRights.includes(
      "(DELETE.0,ERROR_SHARING_VIOLATION.to_hresult())",
    ) &&
    compactFixedKeyAgentGenerationStoreRootRights.includes(
      "(FILE_DELETE_CHILD.0,ERROR_ACCESS_DENIED.to_hresult())",
    ) &&
    compactFixedKeyAgentGenerationStoreRootRights.includes(
      "(WRITE_DAC.0,ERROR_ACCESS_DENIED.to_hresult())",
    ) &&
    compactFixedKeyAgentGenerationStoreRootRights.includes(
      "(WRITE_OWNER.0,ERROR_ACCESS_DENIED.to_hresult())",
    ) &&
    compactFixedKeyAgentGenerationStoreRootRights.includes(
      "(ACCESS_SYSTEM_SECURITY,ERROR_PRIVILEGE_NOT_HELD.to_hresult(),)",
    ) &&
    compactFixedKeyAgentGenerationStoreRootRights.includes(
      "ifaccess==DELETE.0||access==WRITE_DAC.0",
    ) &&
    compactFixedKeyAgentGenerationStoreRootRights.includes(
      "access_check_denies_root_right_for_test(",
    ) &&
    compactFixedKeyAgentGenerationStoreRootRights.includes(
      "require_root_open_error_for_test(self.vault.root_path(),access,expected_error)?;",
    ) &&
    requireFixedKeyAgentGenerationStoreRootOpenError.includes("CreateFileW(") &&
    requireFixedKeyAgentGenerationStoreRootOpenError.includes(
      "error.code() == expected_error",
    ) &&
    accessCheckFixedKeyAgentGenerationStoreRootRight.includes("AccessCheck(") &&
    accessCheckFixedKeyAgentGenerationStoreRootRight.includes(
      "access_status.as_bool()",
    ) &&
    accessCheckFixedKeyAgentGenerationStoreRootRight.includes(
      "granted_access != 0",
    ) &&
    serveInheritedKeyAgentStorageStartup.includes(
      ".verify_forbidden_root_rights_for_test()",
    ) &&
    serveInheritedKeyAgentStorageStartup.includes(
      "crate::storage::exercise_fixed_key_agent_generation_stores_for_test(",
    ) &&
    serveInheritedKeyAgentStorageStartup.includes(
      "&generation_store_bindings",
    ) &&
    integratedKeyAgentGenerationStoreTest.includes(
      "bind_key_agent_storage_startup_for_kernel_test(dormant)?",
    ) &&
    integratedKeyAgentGenerationStoreTest.includes(
      "assert!(bound.provisioning.revalidate().is_ok())",
    ) &&
    integratedKeyAgentGenerationStoreTest.includes("drop(bound)") &&
    integratedKeyAgentGenerationStoreTest.includes(
      "assert!(!storage_root.exists())",
    ),
  "the cfg(test) integrated zero-capability LPAC helper must exercise four fixed stores across close/reopen, the exact per-store seven-file by four-right kernel-denial matrix, and the root open/AccessCheck denial split",
);
const keyAgentRequestWriterImpl = rustItemBlock(
  keyAgentPipeRelease,
  /impl\s+KeyAgentRequestWriter\s*\{/u,
);
const keyAgentResponseReaderImpl = rustItemBlock(
  keyAgentPipeRelease,
  /impl\s+KeyAgentResponseReader\s*\{/u,
);
const keyAgentStartupRequestWriterImpl = rustItemBlock(
  keyAgentPipeRelease,
  /impl\s+KeyAgentStartupRequestWriter\s*\{/u,
);
const keyAgentStartupResponseReaderImpl = rustItemBlock(
  keyAgentPipeRelease,
  /impl\s+KeyAgentStartupResponseReader\s*\{/u,
);
const keyAgentRequestWriterMethods = [...keyAgentRequestWriterImpl.matchAll(
  /pub\(crate\)\s+(?:const\s+)?fn\s+(\w+)/gu,
)].map((match) => match[1]);
const keyAgentResponseReaderMethods = [...keyAgentResponseReaderImpl.matchAll(
  /pub\(crate\)\s+(?:const\s+)?fn\s+(\w+)/gu,
)].map((match) => match[1]);
const keyAgentStartupRequestWriterMethods = [
  ...keyAgentStartupRequestWriterImpl.matchAll(
    /pub\(crate\)\s+(?:const\s+)?fn\s+(\w+)/gu,
  ),
].map((match) => match[1]);
const keyAgentStartupResponseReaderMethods = [
  ...keyAgentStartupResponseReaderImpl.matchAll(
    /pub\(crate\)\s+(?:const\s+)?fn\s+(\w+)/gu,
  ),
].map((match) => match[1]);
const keyAgentStartupRequestSend = rustFunctionBlock(
  keyAgentStartupRequestWriterImpl,
  "send",
);
const keyAgentStartupResponseReceive = rustFunctionBlock(
  keyAgentStartupResponseReaderImpl,
  "receive",
);
const rejectBufferedKeyAgentStartupBytes = rustFunctionBlock(
  keyAgentPipeRelease,
  "reject_buffered_key_agent_startup_bytes",
);
const rejectBufferedPipeBytes = rustFunctionBlock(
  keyAgentPipeRelease,
  "reject_buffered_bytes",
);
const rejectBufferedPipeBytesPeekCalls = rustCallSites(
  rejectBufferedPipeBytes,
  "PeekNamedPipe",
);
const bufferedKeyAgentResponseSuffixTest = rustFunctionBlock(
  keyAgentPipeSource,
  "key_agent_startup_transport_rejects_buffered_response_suffix",
);
const bufferedKeyAgentRequestSuffixTest = rustFunctionBlock(
  keyAgentPipeSource,
  "key_agent_child_boundary_detects_buffered_request_suffix",
);
const keyAgentStartupResponseReceiveOrder = [
  "sys::read_exact_before(self.0.raw(), KEY_AGENT_STARTUP_RESPONSE_BYTES, deadline)?",
  "reject_buffered_key_agent_startup_bytes(self.0.as_handle())?",
  "exact.copy_from_slice(frame.as_slice())",
  "Ok((exact, KeyAgentResponseReader(self.0)))",
].map((marker) => keyAgentStartupResponseReceive.indexOf(marker));
const privateKeyAgentPipesIntoParent = rustFunctionBlock(
  rustLexicalItemBlock(
    keyAgentPipeRelease,
    /impl\s+PrivateKeyAgentPipes\s*\{/u,
  ),
  "into_parent",
);
requireInvariant(
  keyAgentPipeProduction.includes(
    "unsafe impl Send for KeyAgentStartupRequestWriter {}",
  ) &&
    keyAgentPipeProduction.includes(
      "unsafe impl Send for KeyAgentStartupResponseReader {}",
    ) &&
  keyAgentPipeProduction.includes("unsafe impl Send for KeyAgentRequestWriter {}") &&
    keyAgentPipeProduction.includes("unsafe impl Send for KeyAgentResponseReader {}") &&
    keyAgentPipeProduction.includes(
      "Windows permits the owned HANDLE to be used and",
    ) &&
    !/unsafe\s+impl\s+Sync\s+for\s+KeyAgent(?:Startup)?(?:RequestWriter|ResponseReader)\b/u.test(
      keyAgentPipeProduction,
    ) &&
    !/unsafe\s+impl\s+Send\s+for\s+(?:OwnedWinHandle|PrivateKeyAgentPipes|PreparedKeyAgentInheritance)\b/u.test(
      keyAgentPipeProduction,
    ) &&
    !/#\[derive\([^\]]*(?:Clone|Copy)[^\]]*\)\]\s*pub\(crate\)\s+struct\s+KeyAgent(?:Startup)?(?:RequestWriter|ResponseReader)\b/u.test(
      keyAgentPipeProduction,
    ) &&
    !/impl\s+(?:Clone|Copy)\s+for\s+KeyAgent(?:Startup)?(?:RequestWriter|ResponseReader)\b/u.test(
      keyAgentPipeProduction,
    ) &&
    JSON.stringify(keyAgentStartupRequestWriterMethods) ===
      JSON.stringify(["send"]) &&
    JSON.stringify(keyAgentStartupResponseReaderMethods) ===
      JSON.stringify(["receive"]) &&
    keyAgentRequestWriterMethods.length === 0 &&
    keyAgentResponseReaderMethods.length === 0 &&
    /fn\s+send\s*\(\s*self,\s*frame:\s*&\[u8;\s*KEY_AGENT_STARTUP_REQUEST_BYTES\],\s*deadline:\s*Instant,?\s*\)\s*->\s*Result<\s*KeyAgentRequestWriter\s*,\s*PipeError\s*>/u.test(
      rustLexicalCode(keyAgentStartupRequestSend),
    ) &&
    keyAgentStartupRequestSend.includes(
      "sys::write_all_before(self.0.raw(), frame, deadline)?",
    ) &&
    /fn\s+receive\s*\(\s*self,\s*deadline:\s*Instant,?\s*\)/u.test(
      rustLexicalCode(keyAgentStartupResponseReceive),
    ) &&
    keyAgentStartupResponseReceive.includes(
      "sys::read_exact_before(self.0.raw(), KEY_AGENT_STARTUP_RESPONSE_BYTES, deadline)?",
    ) &&
    keyAgentStartupResponseReceiveOrder.every((position) => position !== -1) &&
    keyAgentStartupResponseReceiveOrder
      .slice(1)
      .every(
        (position, index) =>
          position > keyAgentStartupResponseReceiveOrder[index],
      ) &&
    keyAgentStartupResponseReceive.includes(
      "Zeroizing<[u8; KEY_AGENT_STARTUP_RESPONSE_BYTES]>",
    ) &&
    keyAgentStartupResponseReceive.includes("KeyAgentResponseReader") &&
    privateKeyAgentPipesIntoParent.includes(
      "(KeyAgentStartupRequestWriter, KeyAgentStartupResponseReader)",
    ) &&
    !/\b(?:write_bounded|read_bounded_to_end)\b/u.test(
      `${keyAgentStartupRequestWriterImpl}\n${keyAgentStartupResponseReaderImpl}\n${keyAgentRequestWriterImpl}\n${keyAgentResponseReaderImpl}`,
    ) &&
    keyAgentPipeSource.includes(
      "fn key_agent_parent_endpoints_transfer_once_to_a_fresh_thread()",
    ),
  "only the unique consuming 188/88-byte Key Agent startup typestates may perform pipe I/O, while retained parent endpoints expose no operational methods",
);
requireInvariant(
  /pub\(crate\)\s+fn\s+reject_buffered_key_agent_startup_bytes\s*\(\s*handle:\s*BorrowedHandle<'_>,?\s*\)\s*->\s*Result<\(\),\s*PipeError>\s*\{\s*sys::reject_buffered_bytes\(handle\)\s*\}/u.test(
    rustLexicalCode(rejectBufferedKeyAgentStartupBytes),
  ),
  "the Key Agent startup buffered-byte wrapper must remain one exact crate-private forwarding function",
);
requireInvariant(
  rejectBufferedPipeBytesPeekCalls.length === 1 &&
    JSON.stringify(rejectBufferedPipeBytesPeekCalls[0]?.arguments) ===
      JSON.stringify([
        "HANDLE(handle.as_raw_handle())",
        "None",
        "0",
        "None",
        "Some(&raw mut available)",
        "None",
      ]),
  "the Key Agent startup buffered-byte probe must make one exact non-consuming PeekNamedPipe call",
);
requireInvariant(
  rejectBufferedPipeBytes.includes("let mut available = 0_u32") &&
    rejectBufferedPipeBytes.includes("if available == 0") &&
    rejectBufferedPipeBytes.includes("Err(PipeError::TrailingData)"),
  "the Key Agent startup buffered-byte probe must accept only an empty immediate queue and reject a suffix",
);
requireInvariant(
  bufferedKeyAgentResponseSuffixTest.includes(
      "KEY_AGENT_STARTUP_RESPONSE_BYTES",
    ) &&
    bufferedKeyAgentResponseSuffixTest.includes(".checked_add(1)") &&
    bufferedKeyAgentResponseSuffixTest.includes("Err(PipeError::TrailingData)") &&
    bufferedKeyAgentRequestSuffixTest.includes(
      "KEY_AGENT_STARTUP_REQUEST_BYTES",
    ) &&
    bufferedKeyAgentRequestSuffixTest.includes(".checked_add(1)") &&
    bufferedKeyAgentRequestSuffixTest.includes(
      "sys::reject_buffered_bytes(child_request.as_handle())",
    ) &&
    bufferedKeyAgentRequestSuffixTest.includes("Err(PipeError::TrailingData)"),
  "the Key Agent startup boundary must keep exact request/response buffered-suffix negative tests",
);
const boundDormantBlock =
  /pub\(crate\)\s+struct\s+BoundDormantKeyAgent\s*\{(?<body>[\s\S]*?)\n\}/u.exec(
    keyAgentSupervisor,
  )?.groups?.body ?? "";
const bindDormantFunction = rustFunctionBlock(
  keyAgentSupervisor,
  "bind_dormant_key_agent",
);
const keyAgentSupervisorBindingSealBlock = rustTopLevelLexicalItemBlock(
  keyAgentSupervisorRelease,
  /pub\(crate\)\s+struct\s+KeyAgentSupervisorBindingSeal\s*\{/u,
);
const bindDormantKeyAgentConsumers = platformWindowsProductionFiles
  .filter(
    (file) =>
      file.path !== "crates/platform-windows/src/key_agent_supervisor.rs" &&
      file.path !== "crates/platform-windows/src/lib.rs" &&
      rustCallSites(file.source, "bind_dormant_key_agent").length > 0,
  )
  .map((file) => file.path);
const bindDormantKeyAgentTokenConsumers = platformWindowsProductionFiles
  .filter(
    (file) =>
      file.path !== "crates/platform-windows/src/key_agent_supervisor.rs" &&
      file.path !== "crates/platform-windows/src/lib.rs" &&
      /\bbind_dormant_key_agent\b/u.test(rustLexicalCode(file.source)),
  )
  .map((file) => file.path);
const issueSupervisorLease = rustFunctionBlock(keyAgentSupervisor, "issue");
const consumeSupervisorLease = rustFunctionBlock(
  keyAgentSupervisor,
  "verify_and_consume",
);
const ensureSupervisorLeaseLive = rustFunctionBlock(
  keyAgentSupervisor,
  "ensure_live",
);
const boundDormantOrder = [
  "consume_artifact_bound_existing_key_agent_install(",
  "KeyAgentSupervisorBindingSeal { _private: () }",
  "provisioning.revalidate()?",
  "SupervisorActivationLease::issue(MAX_STARTUP_LIFETIME)?",
  "run_on_fresh_key_agent_debug_thread(move |fresh_thread|",
  "startup_lease.ensure_live()?",
  "let root_job = KeyAgentRootJob::create()?",
  "let pipes = PrivateKeyAgentPipes::create()?",
  "let root_job_attribute = root_job.creation_attribute()?",
  "activate_preflighted_key_agent_on_fresh_worker(",
  "&provisioning",
  "&pipes",
  "startup_lease.expires_at()",
  "drop(root_job_attribute)",
  "root_job.recheck_supervisor_context()?",
  "root_job.verify_effective_limits()?",
  "root_job.active_process_count()? != 1",
  "let (request_writer, response_reader) = pipes.into_parent()",
  "Ok(BoundDormantKeyAgent {",
  "startup_lease,\n            install_continuity,\n            not_sync: PhantomData,\n            provisioning,",
].map((marker) => bindDormantFunction.indexOf(marker));
const provisioningRevalidationPositions = [
  ...bindDormantFunction.matchAll(/provisioning\.revalidate\(\)\?/gu),
].map((match) => match.index);
requireInvariant(
  boundDormantBlock.includes("activation: HeldKeyAgentActivation") &&
    boundDormantBlock.includes("root_job: KeyAgentRootJob") &&
    boundDormantBlock.includes(
      "request_writer: KeyAgentStartupRequestWriter",
    ) &&
    boundDormantBlock.includes(
      "response_reader: KeyAgentStartupResponseReader",
    ) &&
    boundDormantBlock.includes("startup_lease: SupervisorActivationLease") &&
    boundDormantBlock.includes(
      "install_continuity: VerifiedKeyAgentInstallContinuity",
    ) &&
    boundDormantBlock.includes("not_sync: PhantomData<Cell<()>>") &&
    boundDormantBlock.includes("provisioning: PreparedKeyAgentProvisioning") &&
    /activation:\s*HeldKeyAgentActivation[\s\S]*root_job:\s*KeyAgentRootJob[\s\S]*request_writer:\s*KeyAgentStartupRequestWriter[\s\S]*response_reader:\s*KeyAgentStartupResponseReader[\s\S]*startup_lease:\s*SupervisorActivationLease[\s\S]*install_continuity:\s*VerifiedKeyAgentInstallContinuity[\s\S]*not_sync:\s*PhantomData<Cell<\(\)>>[\s\S]*provisioning:\s*PreparedKeyAgentProvisioning/u.test(
      boundDormantBlock,
    ) &&
    !/\bpub(?:\([^)]*\))?\s+\w+\s*:/u.test(boundDormantBlock) &&
    !/#\[derive\([^\]]*(?:Clone|Copy)[^\]]*\)\]\s*pub\(crate\)\s+struct\s+BoundDormantKeyAgent/u.test(
      keyAgentSupervisor,
    ) &&
    !/impl\s+(?:Clone|Copy|Sync)\s+for\s+BoundDormantKeyAgent\b/u.test(
      keyAgentSupervisor,
    ) &&
    !/impl\s+BoundDormantKeyAgent\s*\{/u.test(keyAgentSupervisorRelease) &&
    keyAgentSupervisor.includes("impl fmt::Debug for BoundDormantKeyAgent") &&
    keyAgentSupervisor.includes("[VERIFIED PROFILE AND HELD STORAGE ROOT]") &&
    keyAgentSupervisor.includes(
      "[AUTHENTICATED INSTALL/RELEASE CONTINUITY]",
    ) &&
    boundDormantOrder.every((position) => position !== -1) &&
    boundDormantOrder
      .slice(1)
      .every((position, index) => position > boundDormantOrder[index]) &&
    /pub\(crate\)\s+fn\s+bind_dormant_key_agent\s*\(\s*bound:\s*ArtifactBoundExistingKeyAgentInstall,?\s*\)\s*->\s*Result<\s*BoundDormantKeyAgent\s*,\s*KeyAgentSupervisorError\s*>/u.test(
      rustLexicalCode(bindDormantFunction),
    ) &&
    !/\b(?:ReleaseAttestation|VerifiedHelper|PreparedKeyAgentProvisioning|preflight_key_agent_activation)\b/u.test(
      rustLexicalCode(bindDormantFunction),
    ) &&
    !/\b(?:ArtifactDigest|AttestedArtifactDigest|ReleaseAttestation|VerifiedHelper|manifest_digest|allows_helper_manifest|preflight_key_agent_activation)\b/u.test(
      rustLexicalCode(keyAgentSupervisorRelease),
    ) &&
    JSON.stringify(bindDormantKeyAgentConsumers) === JSON.stringify([]) &&
    JSON.stringify(bindDormantKeyAgentTokenConsumers) === JSON.stringify([]) &&
    compactRust(keyAgentSupervisorBindingSealBlock) ===
      "pub(crate)structKeyAgentSupervisorBindingSeal{_private:(),}" &&
    !/impl\s+(?:KeyAgentSupervisorBindingSeal|(?:Clone|Copy|Default|Drop|Deref|DerefMut|AsRef|Borrow|From|Into|TryFrom)[^\r\n{]*for\s+KeyAgentSupervisorBindingSeal)\b/u.test(
      rustLexicalCode(keyAgentSupervisorRelease),
    ) &&
    rustStructLiteralSites(
      bindDormantFunction,
      "KeyAgentSupervisorBindingSeal",
    ).length === 1 &&
    rustStructLiteralSites(bindDormantFunction, "BoundDormantKeyAgent").length ===
      1 &&
    rustCallSites(
      bindDormantFunction,
      "consume_artifact_bound_existing_key_agent_install",
    ).length === 1 &&
    JSON.stringify(
      rustCallSites(
        bindDormantFunction,
        "consume_artifact_bound_existing_key_agent_install",
      ).map((call) => call.arguments),
    ) ===
      JSON.stringify([
        ["bound", "KeyAgentSupervisorBindingSeal { _private: () }"],
      ]) &&
    !/fn\s+bind_dormant_key_agent\s*\([^)]*\b(?:Instant|Duration)\b/su.test(
      bindDormantFunction,
    ) &&
    bindDormantFunction.match(/startup_lease\.ensure_live\(\)\?/gu)?.length === 2 &&
    bindDormantFunction.indexOf("startup_lease.ensure_live()?") <
      bindDormantFunction.indexOf("let root_job = KeyAgentRootJob::create()?") &&
    bindDormantFunction.lastIndexOf("startup_lease.ensure_live()?") >
      bindDormantFunction.indexOf(
        "let (request_writer, response_reader) = pipes.into_parent()",
      ) &&
    provisioningRevalidationPositions.length === 3 &&
    provisioningRevalidationPositions[0] <
      bindDormantFunction.indexOf(
        "SupervisorActivationLease::issue(MAX_STARTUP_LIFETIME)?",
      ) &&
    provisioningRevalidationPositions[1] <
      bindDormantFunction.indexOf("let root_job = KeyAgentRootJob::create()?") &&
    provisioningRevalidationPositions[2] >
      bindDormantFunction.indexOf(
        "let (request_writer, response_reader) = pipes.into_parent()",
      ) &&
    issueSupervisorLease.includes("Instant::now()") &&
    issueSupervisorLease.includes("requested_lifetime.min(MAX_STARTUP_LIFETIME)") &&
    /fn\s+verify_and_consume\s*\(\s*self,/su.test(consumeSupervisorLease) &&
    consumeSupervisorLease.includes("self.ensure_live()?") &&
    ensureSupervisorLeaseLive.includes("Instant::now()") &&
    !/fn\s+ensure_live\s*\([^)]*\bInstant\b/su.test(ensureSupervisorLeaseLive),
  "the bound dormant Key Agent must atomically own one internally timed, non-clone storage-startup attempt with pre-transcript pipe typestates",
);
const boundStorageProvenBlock =
  /pub\(crate\)\s+struct\s+BoundStorageProvenKeyAgent\s*\{(?<body>[\s\S]*?)\n\}/u.exec(
    keyAgentSupervisor,
  )?.groups?.body ?? "";
const bindKeyAgentStorageStartup = rustFunctionBlock(
  keyAgentSupervisor,
  "bind_key_agent_storage_startup",
);
const bindKeyAgentStorageStartupWithRequest = rustFunctionBlock(
  keyAgentSupervisor,
  "bind_key_agent_storage_startup_with_request",
);
const keyAgentStartupTranscriptCommitment = rustFunctionBlock(
  keyAgentSupervisor,
  "startup_transcript_commitment",
);
const receiveKeyAgentStorageStartupResponse = rustFunctionBlock(
  keyAgentSupervisor,
  "receive_storage_startup_response",
);
const validateKeyAgentStorageStartupResponse = rustFunctionBlock(
  keyAgentSupervisor,
  "validate_storage_startup_response",
);
const revalidatePostKeyAgentStartupState = rustFunctionBlock(
  keyAgentSupervisor,
  "revalidate_post_startup_state",
);
const compactBindKeyAgentStorageStartupWithRequest = compactRust(
  bindKeyAgentStorageStartupWithRequest,
);
const firstPostSendProvisioningRevalidation =
  compactBindKeyAgentStorageStartupWithRequest.indexOf(
    "ifletErr(error)=provisioning.revalidate()",
  );
const bindKeyAgentStorageStartupOrder = [
  "bound.startup_lease.ensure_live()?",
  "bound.provisioning.revalidate()?",
  "bound.startup_lease.nonce_for_child()",
  "request.expected_process_id()!=bound.activation.process_id()",
  "request.expected_creation_time()!=bound.activation.creation_time()",
  "request.storage_root_identity()!=bound.provisioning.storage_root_identity()",
  "letrequest_frame=request.encode()?",
  "letdeadline=bound.startup_lease.expires_at()",
  "letartifact_identity=bound.activation.artifact_identity()",
  "letBoundDormantKeyAgent{",
  "request_writer.send(request_frame.as_bytes(),deadline)",
  "ifletErr(error)=startup_lease.ensure_live()",
].map((marker) =>
  compactBindKeyAgentStorageStartupWithRequest.indexOf(compactRust(marker)),
);
bindKeyAgentStorageStartupOrder.push(
  firstPostSendProvisioningRevalidation,
  ...[
    "activation.resume_for_storage_startup()",
    "receive_storage_startup_response(response_reader,deadline,response_transport)",
    "KeyAgentStartupResponse::decode(response_frame.as_slice())",
    "validate_storage_startup_response(request,&response)",
    "revalidate_post_startup_state(&provisioning,&root_job,&activation,response_transport)",
  ].map((marker) =>
    compactBindKeyAgentStorageStartupWithRequest.indexOf(compactRust(marker)),
  ),
  ...[
    "startup_transcript_commitment(",
    "startup_lease.verify_and_consume(response.echoed_nonce(),transcript_commitment)",
    "Ok(BoundStorageProvenKeyAgent{",
  ].map((marker) =>
    compactBindKeyAgentStorageStartupWithRequest.indexOf(compactRust(marker)),
  ),
);
requireInvariant(
  bindKeyAgentStorageStartupOrder.every((position) => position !== -1) &&
    bindKeyAgentStorageStartupOrder
      .slice(1)
      .every(
        (position, index) =>
          position > bindKeyAgentStorageStartupOrder[index],
      ),
  "the one Key Agent storage-startup transition must preserve request, resume, response, revalidation, topology, transcript, and minting order",
);
const validateKeyAgentStorageStartupResponseOrder = [
  "request.nonce().ct_eq(response.echoed_nonce())",
  "response.actual_process_id()!=request.expected_process_id()",
  "response.actual_creation_time()!=request.expected_creation_time()",
  "response.storage_root_identity()!=request.storage_root_identity()",
  "Ok(())",
].map((marker) =>
  compactRust(validateKeyAgentStorageStartupResponse).indexOf(
    compactRust(marker),
  ),
);
const revalidatePostKeyAgentStartupOrder = [
  "provisioning.revalidate()?",
  "root_job.recheck_supervisor_context()?",
  "root_job.verify_effective_limits()?",
  "lettopology_is_valid=matchresponse_transport",
  "StartupResponseTransport::Exact=>root_job.active_process_count().map(|count|count==1)",
  "topology_is_valid.then_some(()).ok_or(KeyAgentSupervisorError::RootJobPolicy)",
].map((marker) =>
  compactRust(revalidatePostKeyAgentStartupState).indexOf(compactRust(marker)),
);
requireInvariant(
  /response_reader:\s*KeyAgentStartupResponseReader/u.test(
    rustLexicalCode(receiveKeyAgentStorageStartupResponse),
  ) &&
    receiveKeyAgentStorageStartupResponse.includes(
      "Zeroizing<[u8; KEY_AGENT_STARTUP_RESPONSE_BYTES]>",
    ) &&
    receiveKeyAgentStorageStartupResponse.includes("KeyAgentResponseReader") &&
    rustCallSites(receiveKeyAgentStorageStartupResponse, "receive").length === 1 &&
    receiveKeyAgentStorageStartupResponse.includes(
      "StartupResponseTransport::Exact => response_reader.receive(deadline)",
    ) &&
    validateKeyAgentStorageStartupResponseOrder.every(
      (position) => position !== -1,
    ) &&
    validateKeyAgentStorageStartupResponseOrder
      .slice(1)
      .every(
        (position, index) =>
          position > validateKeyAgentStorageStartupResponseOrder[index],
      ) &&
    revalidatePostKeyAgentStartupOrder.every((position) => position !== -1) &&
    revalidatePostKeyAgentStartupOrder
      .slice(1)
      .every(
        (position, index) =>
          position > revalidatePostKeyAgentStartupOrder[index],
      ),
  "the storage-startup response helper must consume one exact 88-byte frame before full nonce/process/storage validation and post-resume provisioning/Job/topology revalidation",
);
requireInvariant(
  /fn\s+bind_key_agent_storage_startup\s*\(\s*bound:\s*BoundDormantKeyAgent,?\s*\)\s*->\s*Result<\s*BoundStorageProvenKeyAgent\s*,\s*KeyAgentSupervisorError\s*>/u.test(
    rustLexicalCode(bindKeyAgentStorageStartup),
  ) &&
    bindKeyAgentStorageStartup.includes("KeyAgentStartupRequest::new(") &&
    bindKeyAgentStorageStartup.includes(
      "bound.provisioning.storage_root_identity()",
    ) &&
    bindKeyAgentStorageStartup.includes(
      "StartupResponseTransport::Exact",
    ) &&
    rustCallSites(keyAgentSupervisor, "resume_for_storage_startup").length === 1 &&
    boundStorageProvenBlock.includes(
      "activation: RunningKeyAgentActivation",
    ) &&
    boundStorageProvenBlock.includes("root_job: KeyAgentRootJob") &&
    boundStorageProvenBlock.includes("request_writer: KeyAgentRequestWriter") &&
    boundStorageProvenBlock.includes("response_reader: KeyAgentResponseReader") &&
    boundStorageProvenBlock.includes(
      "handshake: VerifiedSupervisorHandshake",
    ) &&
    boundStorageProvenBlock.includes(
      "install_continuity: VerifiedKeyAgentInstallContinuity",
    ) &&
    boundStorageProvenBlock.includes("not_sync: PhantomData<Cell<()>>") &&
    boundStorageProvenBlock.includes(
      "provisioning: PreparedKeyAgentProvisioning",
    ) &&
    !/\bpub(?:\([^)]*\))?\s+\w+\s*:/u.test(boundStorageProvenBlock) &&
    !/#\[derive\([^\]]*(?:Clone|Copy)[^\]]*\)\]\s*pub\(crate\)\s+struct\s+BoundStorageProvenKeyAgent/u.test(
      keyAgentSupervisor,
    ) &&
    !/impl\s+(?:Clone|Copy|Sync)\s+for\s+BoundStorageProvenKeyAgent\b/u.test(
      keyAgentSupervisor,
    ) &&
    !/impl\s+(?:Default|Drop|Deref|DerefMut|AsRef|Borrow|From(?:<[^>]+>)?|Into(?:<[^>]+>)?|TryFrom(?:<[^>]+>)?)\s+for\s+(?:BoundDormantKeyAgent|BoundStorageProvenKeyAgent)\b/u.test(
      keyAgentSupervisorRelease,
    ) &&
    !/impl\s+BoundStorageProvenKeyAgent\s*\{/u.test(keyAgentSupervisor) &&
    keyAgentSupervisor.includes(
      "impl fmt::Debug for BoundStorageProvenKeyAgent",
    ) &&
    keyAgentSupervisor.includes("[DETACHED RUNNING KEY AGENT]") &&
    keyAgentSupervisor.includes("[VERIFIED STORAGE-STARTUP TRANSCRIPT]") &&
    (compactBindKeyAgentStorageStartupWithRequest.match(
      /install_continuity/gu,
    ) ?? []).length === 2 &&
    !/install_continuity\s*\./u.test(
      rustLexicalCode(bindKeyAgentStorageStartupWithRequest),
    ) &&
    compactBindKeyAgentStorageStartupWithRequest.includes(
      "letBoundDormantKeyAgent{activation,root_job,request_writer,response_reader,startup_lease,install_continuity,not_sync:_,provisioning,}=bound;",
    ) &&
    compactBindKeyAgentStorageStartupWithRequest.includes(
      "Ok(BoundStorageProvenKeyAgent{activation,root_job,request_writer,response_reader,handshake,install_continuity,not_sync:PhantomData,provisioning,})",
    ) &&
    rustStructLiteralSites(
      bindKeyAgentStorageStartupWithRequest,
      "BoundDormantKeyAgent",
    ).length === 1 &&
    rustStructLiteralSites(
      bindKeyAgentStorageStartupWithRequest,
      "BoundStorageProvenKeyAgent",
    ).length === 1 &&
    /fn\s+startup_transcript_commitment\s*\(\s*artifact_identity:\s*\[u8;\s*24\],\s*request_frame:\s*&\[u8;\s*KEY_AGENT_STARTUP_REQUEST_BYTES\],\s*response_frame:\s*&\[u8;\s*KEY_AGENT_STARTUP_RESPONSE_BYTES\],?\s*\)\s*->\s*\[u8;\s*STARTUP_TRANSCRIPT_BYTES\]/u.test(
      rustLexicalCode(keyAgentStartupTranscriptCommitment),
    ) &&
    keyAgentStartupTranscriptCommitment.includes(
      "transcript.update(STARTUP_TRANSCRIPT_DOMAIN)",
    ) &&
    keyAgentStartupTranscriptCommitment.includes(
      "transcript.update(artifact_identity)",
    ) &&
    keyAgentStartupTranscriptCommitment.includes(
      "transcript.update(request_frame)",
    ) &&
    keyAgentStartupTranscriptCommitment.includes(
      "transcript.update(response_frame)",
    ) &&
    !/\b(?:LOCALAPPDATA|storage_path|path_hash|path_digest|storage_hash)\b/u.test(
      rustLexicalCode(
        `${bindKeyAgentStorageStartup}\n${bindKeyAgentStorageStartupWithRequest}\n${keyAgentStartupTranscriptCommitment}`,
      ),
    ),
  "one consuming supervisor transition must bind the exact storage-startup transcript and mint only BoundStorageProvenKeyAgent with retained non-operational endpoints",
);
const heldActivationBlock =
  /pub\(crate\)\s+struct\s+HeldKeyAgentActivation\s*\{(?<body>[\s\S]*?)\n\}/u.exec(
    keyAgentActivation,
  )?.groups?.body ?? "";
const heldActivationImpl = rustItemBlock(
  keyAgentActivation,
  /impl\s+HeldKeyAgentActivation\s*\{/u,
);
const heldActivationMethods = [...heldActivationImpl.matchAll(
  /pub\(crate\)\s+(?:const\s+)?fn\s+(\w+)/gu,
)].map((match) => match[1]);
const resumeHeldKeyAgentForStorageStartup = rustFunctionBlock(
  heldActivationImpl,
  "resume_for_storage_startup",
);
const runningActivationBlock =
  /pub\(crate\)\s+struct\s+RunningKeyAgentActivation\s*\{(?<body>[\s\S]*?)\n\}/u.exec(
    keyAgentActivation,
  )?.groups?.body ?? "";
const runningActivationImpl = rustItemBlock(
  keyAgentActivation,
  /impl\s+RunningKeyAgentActivation\s*\{/u,
);
const runningActivationMethods = [...runningActivationImpl.matchAll(
  /pub\(crate\)\s+(?:const\s+)?fn\s+(\w+)/gu,
)].map((match) => match[1]);
const suspendedDebuggeeStartupImpl = rustLexicalItemBlock(
  keyAgentActivation,
  /impl\s+SuspendedDebuggee\s*\{/u,
);
const resumeSuspendedDebuggeeForStorageStartup = rustFunctionBlock(
  suspendedDebuggeeStartupImpl,
  "resume_for_storage_startup",
);
const compactHeldKeyAgentActivationDefinition = compactRust(
  `pub(crate) struct HeldKeyAgentActivation {${heldActivationBlock}\n}`,
);
const compactRunningKeyAgentActivationDefinition = compactRust(
  `pub(crate) struct RunningKeyAgentActivation {${runningActivationBlock}\n}`,
);
const compactResumeHeldKeyAgentForStorageStartup = compactRust(
  resumeHeldKeyAgentForStorageStartup,
);
requireInvariant(
  compactHeldKeyAgentActivationDefinition ===
      "pub(crate)structHeldKeyAgentActivation{process:sys::DetachedSuspendedDebuggee,artifact:VerifiedHelper,release_identity:AttestedArtifactDigest,artifact_identity:ExactFileObjectIdentity,creation_time:u64,}" &&
    compactRunningKeyAgentActivationDefinition ===
      "pub(crate)structRunningKeyAgentActivation{process:sys::DetachedRunningDebuggee,artifact:VerifiedHelper,release_identity:AttestedArtifactDigest,artifact_identity:ExactFileObjectIdentity,creation_time:u64,}",
  "held and running Key Agent activation states must retain the pinned helper and opaque whole-release identity in exact drop order",
);
requireInvariant(
  compactResumeHeldKeyAgentForStorageStartup ===
    "pub(crate)fnresume_for_storage_startup(self,)->Result<RunningKeyAgentActivation,KeyAgentActivationError>{letSelf{process,artifact,release_identity,artifact_identity,creation_time,}=self;letprocess=process.resume_for_storage_startup()?;Ok(RunningKeyAgentActivation{process,artifact,release_identity,artifact_identity,creation_time,})}",
  "the only held-to-running activation transition must move the opaque whole-release identity without reading or replacing it",
);
requireInvariant(
  heldActivationBlock.includes("process: sys::DetachedSuspendedDebuggee") &&
    !/\bpub(?:\([^)]*\))?\s+\w+\s*:/u.test(heldActivationBlock) &&
    JSON.stringify(heldActivationMethods) ===
      JSON.stringify([
        "process_id",
        "creation_time",
        "artifact_identity",
        "is_detached_and_suspended",
        "resume_for_storage_startup",
        "duplicate_process_observation",
        "is_member_of_root_job_for_test",
      ]) &&
    /#\[cfg\(test\)\]\s*pub\(crate\)\s+fn\s+duplicate_process_observation/u.test(
      heldActivationImpl,
    ) &&
    /#\[cfg\(test\)\]\s*pub\(crate\)\s+fn\s+is_member_of_root_job_for_test/u.test(
      heldActivationImpl,
    ) &&
    /fn\s+resume_for_storage_startup\s*\(\s*self,?\s*\)\s*->\s*Result<\s*RunningKeyAgentActivation\s*,\s*KeyAgentActivationError\s*>/u.test(
      rustLexicalCode(resumeHeldKeyAgentForStorageStartup),
    ) &&
    !/impl\s+Drop\s+for\s+HeldKeyAgentActivation\b/u.test(
      keyAgentActivation,
    ) &&
    !/#\[derive\([^\]]*(?:Clone|Copy)[^\]]*\)\]\s*pub\(crate\)\s+struct\s+HeldKeyAgentActivation/u.test(
      keyAgentActivation,
    ),
  "held Key Agent activation must remain opaque and non-clone with only the consuming fixed storage-startup transition",
);
requireInvariant(
  runningActivationBlock.includes("process: sys::DetachedRunningDebuggee") &&
    runningActivationBlock.includes("artifact: VerifiedHelper") &&
    runningActivationBlock.includes(
      "artifact_identity: ExactFileObjectIdentity",
    ) &&
    runningActivationBlock.includes("creation_time: u64") &&
    !/\bpub(?:\([^)]*\))?\s+\w+\s*:/u.test(runningActivationBlock) &&
    JSON.stringify(runningActivationMethods) ===
      JSON.stringify([
        "process_id",
        "creation_time",
        "artifact_identity",
        "is_detached_and_running",
        "duplicate_process_observation",
        "is_member_of_root_job_for_test",
      ]) &&
    /#\[cfg\(test\)\]\s*pub\(crate\)\s+fn\s+duplicate_process_observation/u.test(
      runningActivationImpl,
    ) &&
    /#\[cfg\(test\)\]\s*pub\(crate\)\s+fn\s+is_member_of_root_job_for_test/u.test(
      runningActivationImpl,
    ) &&
    !/#\[derive\([^\]]*(?:Clone|Copy)[^\]]*\)\]\s*pub\(crate\)\s+struct\s+RunningKeyAgentActivation/u.test(
      keyAgentActivation,
    ) &&
    !/impl\s+(?:Clone|Copy|Sync|AsRawHandle)\s+for\s+RunningKeyAgentActivation\b/u.test(
      keyAgentActivation,
    ) &&
    rustCallSites(resumeSuspendedDebuggeeForStorageStartup, "ResumeThread").length === 1 &&
    resumeSuspendedDebuggeeForStorageStartup.includes(
      "if previous_suspend_count != 1",
    ) &&
    resumeSuspendedDebuggeeForStorageStartup.includes(
      "self.proven_suspend_count = 0",
    ) &&
    resumeSuspendedDebuggeeForStorageStartup.includes(
      ".transition(LaunchTransition::ResumeStorageStartup)?",
    ) &&
    resumeSuspendedDebuggeeForStorageStartup.includes(
      "WaitForSingleObject(self.process.raw(), 0)",
    ) &&
    resumeSuspendedDebuggeeForStorageStartup.includes("!= WAIT_TIMEOUT"),
  "the fixed resume leaf must release exactly one suspend count and mint only the opaque detached-running proof after a live-process check",
);
const preflightActivation = rustFunctionBlock(
  keyAgentActivation,
  "preflight_key_agent_activation",
);
const preflightArtifactBlock =
  /pub\(crate\)\s+struct\s+PreflightKeyAgentArtifact\s*\{(?<body>[\s\S]*?)\n\}/u.exec(
    keyAgentActivation,
  )?.groups?.body ?? "";
const preflightArtifactImpl = rustLexicalItemBlock(
  keyAgentActivationRelease,
  /impl\s+PreflightKeyAgentArtifact\s*\{/u,
);
const matchesPreflightReleaseIdentity = rustFunctionBlock(
  preflightArtifactImpl,
  "matches_release_identity",
);
const compactPreflightActivation = compactRust(preflightActivation);
const activationGatePositions = [
  "if!artifact.is_key_agent()",
  "letrelease_identity=attestation.attested_artifact().ok_or(KeyAgentActivationError::ReleaseNotAttested)?",
  "if!attestation.allows_helper_manifest(artifact.manifest_digest())",
  "if!artifact.path().is_absolute()",
  "Ok(PreflightKeyAgentArtifact{artifact,release_identity,})",
].map((marker) => compactPreflightActivation.indexOf(marker));
const preflightKeyAgentArtifactConsumers = platformWindowsProductionFiles
  .filter(
    (file) =>
      file.path !== "crates/platform-windows/src/key_agent_activation.rs" &&
      /\bPreflightKeyAgentArtifact\b/u.test(rustLexicalCode(file.source)),
  )
  .map((file) => file.path);
const preflightKeyAgentActivationConsumers = platformWindowsProductionFiles
  .filter(
    (file) =>
      file.path !== "crates/platform-windows/src/key_agent_activation.rs" &&
      rustCallSites(file.source, "preflight_key_agent_activation").length > 0,
  )
  .map((file) => file.path);
const matchesPreflightReleaseIdentityConsumers =
  platformWindowsProductionFiles
    .filter(
      (file) =>
        file.path !== "crates/platform-windows/src/key_agent_activation.rs" &&
        rustCallSites(file.source, "matches_release_identity").length > 0,
    )
    .map((file) => file.path);
requireInvariant(
  activationGatePositions.every((position) => position !== -1) &&
    activationGatePositions
      .slice(1)
      .every((position, index) => position > activationGatePositions[index]) &&
    preflightArtifactBlock.includes("artifact: VerifiedHelper") &&
    preflightArtifactBlock.includes(
      "release_identity: AttestedArtifactDigest",
    ) &&
    compactRust(`pub(crate) struct PreflightKeyAgentArtifact {${preflightArtifactBlock}\n}`) ===
      "pub(crate)structPreflightKeyAgentArtifact{artifact:VerifiedHelper,release_identity:AttestedArtifactDigest,}" &&
    !/\bpub(?:\([^)]*\))?\s+(?:artifact|release_identity)\s*:/u.test(
      preflightArtifactBlock,
    ) &&
    !/#\[derive\([^\]]*(?:Clone|Copy)[^\]]*\)\]\s*pub\(crate\)\s+struct\s+PreflightKeyAgentArtifact/u.test(
      keyAgentActivation,
    ) &&
    !/pub\(crate\)\s+(?:const\s+)?fn\s+(?:artifact|into_artifact|raw_handle|release_identity|artifact_digest|manifest_digest|as_bytes|into_inner)\b/u.test(
      keyAgentActivation,
    ) &&
    compactRust(matchesPreflightReleaseIdentity) ===
      "pub(crate)fnmatches_release_identity(&self,expected:&[u8;32])->bool{self.release_identity.matches(expected)}" &&
    JSON.stringify(
      rustVisibleFunctionItems(preflightArtifactImpl).map((item) => item.name),
    ) === JSON.stringify(["matches_release_identity"]) &&
    rustStructLiteralSites(
      preflightActivation,
      "PreflightKeyAgentArtifact",
    ).length === 1 &&
    platformWindowsProductionFiles
      .filter(
        (file) =>
          file.path !== "crates/platform-windows/src/key_agent_activation.rs",
      )
      .every(
        (file) =>
          rustStructLiteralSites(file.source, "PreflightKeyAgentArtifact")
            .length === 0,
      ) &&
    JSON.stringify(preflightKeyAgentArtifactConsumers) ===
      JSON.stringify([
        "crates/platform-windows/src/key_agent_install_adoption.rs",
      ]) &&
    JSON.stringify(preflightKeyAgentActivationConsumers) ===
      JSON.stringify([
        "crates/platform-windows/src/key_agent_install_adoption.rs",
      ]) &&
    JSON.stringify(matchesPreflightReleaseIdentityConsumers) ===
      JSON.stringify([
        "crates/platform-windows/src/key_agent_install_adoption.rs",
      ]) &&
    (keyAgentActivationRelease.match(/\bmanifest_digest\b/gu) ?? []).length ===
      1 &&
    !/\bArtifactDigest\b/u.test(keyAgentActivationRelease) &&
    bindExistingKeyAgentInstallToRelease.indexOf(
      "preflight_key_agent_activation(attestation, artifact)",
    ) <
      bindExistingKeyAgentInstallToRelease.indexOf(
        "matches_release_identity(&verified.release_identity)",
      ),
  "Key Agent role, opaque whole-release evidence, helper manifest, and path gates must precede release binding and worker creation without exposing either digest",
);
requireInvariant(
  /#\[cfg\(test\)\]\s*supervisor_context_bypass_for_kernel_test:\s*bool/u.test(
    keyAgentRootJobSource,
  ) &&
    /#\[cfg\(test\)\][\s\S]{0,180}pub\(crate\)\s+fn\s+create_for_kernel_test/u.test(
      keyAgentRootJobSource,
    ) &&
    /pub\(crate\)\s+fn\s+create\(\)[\s\S]*?sys::verify_supervisor_context\(\)\?/u.test(
      keyAgentRootJobSource,
    ) &&
    /#\[cfg\(test\)\]\s*if\s+self\.supervisor_context_bypass_for_kernel_test/u.test(
      keyAgentRootJobSource,
    ),
  "only the cfg(test) root-Job constructor may bypass the outer test-runner Job; production must live-check",
);
const derivedLpacRole = rustFunctionBlock(
  restrictedLauncherProduction,
  "from_helper",
);
const approvalRoleGate = rustFunctionBlock(
  restrictedLauncherProduction,
  "require_approval_frontend",
);
const secretInputRoleGate = rustFunctionBlock(
  restrictedLauncherProduction,
  "require_secret_input_frontend",
);
const publicGenericSpawn = rustFunctionBlock(restrictedLauncherProduction, "spawn");
const privateSecretSpawn = rustFunctionBlock(
  restrictedLauncherProduction,
  "spawn_secret_input",
);
const lowLevelLpacLaunch = rustFunctionBlock(
  restrictedLauncherProduction,
  "launch",
);
const lpacAttributeConstruction = rustFunctionBlock(
  restrictedLauncherProduction,
  "for_lpac",
);
const lpacProfileOpen = rustFunctionBlock(
  restrictedLauncherProduction,
  "open_or_create",
);
const lpacProfileMetadata = rustFunctionBlock(
  restrictedLauncherProduction,
  "profile_metadata",
);
const approvalGatePositions = [
  "VerifiedLpacRole::from_helper(helper)?",
  "role != VerifiedLpacRole::ApprovalFrontend",
  "self.require_allowed_helper(helper.manifest_digest())?",
].map((marker) => approvalRoleGate.indexOf(marker));
const secretInputGatePositions = [
  "VerifiedLpacRole::from_helper(helper)?",
  "role != VerifiedLpacRole::SecretInputFrontend",
  "self.require_allowed_helper(helper.manifest_digest())?",
].map((marker) => secretInputRoleGate.indexOf(marker));
requireInvariant(
  /(?:^|\n)enum\s+VerifiedLpacRole\s*\{/u.test(restrictedLauncherProduction) &&
    !/(?:^|\n)pub(?:\([^)]*\))?\s+enum\s+VerifiedLpacRole\s*\{/u.test(
      restrictedLauncherProduction,
    ) &&
    derivedLpacRole.includes("if helper.is_approval_frontend()") &&
    derivedLpacRole.includes("if helper.is_secret_input_frontend()") &&
    derivedLpacRole.includes("if helper.is_key_agent()") &&
    derivedLpacRole.includes(
      "Err(LaunchError::HelperRoleNotAllowed)",
    ) &&
    derivedLpacRole.includes(
      "Err(LaunchError::KeyAgentRequiresSupervisorActivation)",
    ) &&
    approvalGatePositions.every((position) => position !== -1) &&
    approvalGatePositions
      .slice(1)
      .every((position, index) => position > approvalGatePositions[index]) &&
    secretInputGatePositions.every((position) => position !== -1) &&
    secretInputGatePositions
      .slice(1)
      .every((position, index) => position > secretInputGatePositions[index]) &&
    restrictedLauncherProduction.match(/sys::launch\(helper,/gu)?.length === 2 &&
    publicGenericSpawn.indexOf("self.require_approval_frontend(helper)?") <
      publicGenericSpawn.indexOf("sys::launch(helper, handles, self.profile, role)") &&
    privateSecretSpawn.indexOf("self.require_secret_input_frontend(helper)?") <
    privateSecretSpawn.indexOf("sys::launch(helper, handles, self.profile, role)") &&
    lowLevelLpacLaunch.includes("role: VerifiedLpacRole") &&
    lowLevelLpacLaunch.includes("let parent_sources = role") &&
    lowLevelLpacLaunch.includes(".inherits_parent_proof()") &&
    lowLevelLpacLaunch.includes(
      "if let Some(sources) = parent_sources.as_ref()",
    ) &&
    lowLevelLpacLaunch.includes(
      "let profile_sid = OwnedAppContainerSid::open_or_create(profile, role)?;",
    ) &&
    lowLevelLpacLaunch.indexOf(
      "let profile_sid = OwnedAppContainerSid::open_or_create(profile, role)?;",
    ) <
      lowLevelLpacLaunch.indexOf("acquire_inheritable_handle_launch(") &&
    lowLevelLpacLaunch.includes(
      "AttributeList::for_lpac(&duplicates, &job, profile_sid)?",
    ) &&
    lpacAttributeConstruction.includes(
      "profile_sid: OwnedAppContainerSid",
    ) &&
    /AttributeValues::new\(\s*handles,\s*job_owner\.raw\(\),\s*profile_sid\.raw\(\),?\s*\)/u.test(
      lpacAttributeConstruction,
    ) &&
    lpacProfileOpen.includes("profile_metadata(profile, role)?") &&
    lpacProfileMetadata.includes(
      "(1, VerifiedLpacRole::ApprovalFrontend)",
    ) &&
    lpacProfileMetadata.includes(
      "(1, VerifiedLpacRole::SecretInputFrontend)",
    ) &&
    restrictedLauncherProduction.includes(
      '"YourWallet.ApprovalFrontend.LPAC.v1"',
    ) &&
    restrictedLauncherProduction.includes(
      '"YourWallet.SecretInputFrontend.LPAC.v1"',
    ) &&
    secretBootstrapWindows.includes(
      'const PROFILE_V1_NAME: &str = "YourWallet.SecretInputFrontend.LPAC.v1";',
    ) &&
    !restrictedLauncherProduction.includes(
      '"YourWallet.SecurityHelper.LPAC.v1"',
    ) &&
    !secretBootstrapWindows.includes('"YourWallet.SecurityHelper.LPAC.v1"'),
  "restricted launch must derive distinct stable LPAC identities from the exact manifest role, reject cross-role/Key Agent/Other helpers before release and Win32, and bind Secret Input bootstrap to its own SID",
);
const freshDebugRunner = rustFunctionBlock(
  keyAgentActivation,
  "run_on_fresh_key_agent_debug_thread",
);
const freshWorkerActivation = rustFunctionBlock(
  keyAgentActivation,
  "activate_preflighted_key_agent_on_fresh_worker_with_identity",
);
const freshWorkerEntry = rustFunctionBlock(
  keyAgentActivation,
  "activate_preflighted_key_agent_on_fresh_worker",
);
const authenticateDetachAndBindActivation = rustFunctionBlock(
  keyAgentActivation,
  "authenticate_detach_and_bind_activation",
);
const compactFreshWorkerEntry = compactRust(freshWorkerEntry);
const compactFreshWorkerActivation = compactRust(freshWorkerActivation);
const compactAuthenticateDetachAndBindActivation = compactRust(
  authenticateDetachAndBindActivation,
);
const debugWorkerCreationPositions = [
  "verify_empty_root_job(root_job)?",
  "sys::SuspendedDebuggee::create(",
  "authenticate_detach_and_bind_activation(",
].map((marker) => freshWorkerActivation.indexOf(marker));
const debugWorkerAuthenticationPositions = [
  ".authenticate_first_event(",
  "process.detach_still_suspended()",
  "verify_bound_root_process(root_job, process.process_handle())",
  "let process = process.into_detached()?;",
  "Ok(HeldKeyAgentActivation {",
].map((marker) => authenticateDetachAndBindActivation.indexOf(marker));
requireInvariant(
  freshDebugRunner.includes("std::thread::Builder::new()") &&
    freshDebugRunner.includes(".spawn(move ||") &&
    freshDebugRunner.includes(".join()") &&
    freshDebugRunner.match(/KeyAgentActivationError::ActivationWorker/gu)?.length === 2 &&
    /pub\(crate\)\s+struct\s+FreshKeyAgentDebugThread\s*\{\s*_not_send_or_sync:\s*PhantomData<Rc<\(\)>>/su.test(
      keyAgentActivation,
    ) &&
    !/#\[derive\([^\]]*(?:Clone|Copy)[^\]]*\)\]\s*pub\(crate\)\s+struct\s+FreshKeyAgentDebugThread/u.test(
      keyAgentActivation,
    ) &&
    freshDebugRunner.includes("FnOnce(FreshKeyAgentDebugThread)") &&
    freshWorkerEntry.includes("fresh_thread: FreshKeyAgentDebugThread") &&
    compactFreshWorkerEntry.includes(
      "letPreflightKeyAgentArtifact{artifact,release_identity,}=preflighted;",
    ) &&
    JSON.stringify(
      rustCallSites(
        freshWorkerEntry,
        "activate_preflighted_key_agent_on_fresh_worker_with_identity",
      ).map((call) => call.arguments),
    ) ===
      JSON.stringify([
        [
          "fresh_thread",
          "artifact",
          "release_identity",
          "artifact_identity",
          "provisioning",
          "pipes",
          "root_job",
          "root_job_attribute",
          "coordination_deadline",
        ],
      ]) &&
    freshWorkerEntry.indexOf("let artifact_identity = sys::exact_file_identity") <
      freshWorkerEntry.indexOf(
        "activate_preflighted_key_agent_on_fresh_worker_with_identity(",
    ) &&
    freshWorkerActivation.includes("_fresh_thread: FreshKeyAgentDebugThread") &&
    /fn\s+activate_preflighted_key_agent_on_fresh_worker_with_identity\s*\(\s*_fresh_thread:\s*FreshKeyAgentDebugThread,\s*artifact:\s*VerifiedHelper,\s*release_identity:\s*AttestedArtifactDigest,/u.test(
      rustLexicalCode(freshWorkerActivation),
    ) &&
    JSON.stringify(
      rustCallSites(
        freshWorkerActivation,
        "authenticate_detach_and_bind_activation",
      ).map((call) => call.arguments),
    ) ===
      JSON.stringify([
        [
          "artifact",
          "release_identity",
          "artifact_identity",
          "root_job",
          "process",
        ],
      ]) &&
    /fn\s+authenticate_detach_and_bind_activation\s*\(\s*artifact:\s*VerifiedHelper,\s*release_identity:\s*AttestedArtifactDigest,\s*artifact_identity:\s*ExactFileObjectIdentity,/u.test(
      rustLexicalCode(authenticateDetachAndBindActivation),
    ) &&
    compactAuthenticateDetachAndBindActivation.includes(
      "Ok(HeldKeyAgentActivation{process,artifact,release_identity,artifact_identity,creation_time:first_event.creation_time,})",
    ) &&
    (compactFreshWorkerEntry.match(/release_identity/gu) ?? []).length === 2 &&
    (compactFreshWorkerActivation.match(/release_identity/gu) ?? []).length ===
      2 &&
    (compactAuthenticateDetachAndBindActivation.match(/release_identity/gu) ??
      []).length === 2 &&
    !/release_identity\s*\./u.test(
      rustLexicalCode(
        `${freshWorkerEntry}\n${freshWorkerActivation}\n${authenticateDetachAndBindActivation}\n${resumeHeldKeyAgentForStorageStartup}`,
      ),
    ) &&
    debugWorkerCreationPositions.every((position) => position !== -1) &&
    debugWorkerCreationPositions
      .slice(1)
      .every(
        (position, index) => position > debugWorkerCreationPositions[index],
      ) &&
    debugWorkerAuthenticationPositions.every((position) => position !== -1) &&
    debugWorkerAuthenticationPositions
      .slice(1)
      .every(
        (position, index) =>
          position > debugWorkerAuthenticationPositions[index],
      ) &&
    bindDormantFunction.match(/run_on_fresh_key_agent_debug_thread\(/gu)?.length === 1,
  "one unforgeable consumed fresh-worker proof must carry the opaque attested release identity through exact image authentication and the complete debug-event lifecycle",
);
const keyAgentCreationAttributeBlock =
  /struct\s+KeyAgentCreationAttributes<'resources,\s*'pipes,\s*'flight,\s*'job>\s*\{(?<body>[\s\S]*?)\n\s*\}/u.exec(
    keyAgentActivation,
  )?.groups?.body ?? "";
const keyAgentCreationAttributeImpl = rustItemBlock(
  keyAgentActivation,
  /impl<'resources,\s*'pipes,\s*'flight,\s*'job>\s*KeyAgentCreationAttributes<'resources,\s*'pipes,\s*'flight,\s*'job>\s*\{/u,
);
const keyAgentCreationFlags = rustFunctionBlock(
  keyAgentActivation,
  "key_agent_creation_flags",
);
const keyAgentCreationFlagsTest = rustFunctionBlock(
  keyAgentActivationSource,
  "process_creation_flags_are_exact_and_do_not_debug_descendants",
);
const verifyBoundRootProcess = rustFunctionBlock(
  keyAgentActivation,
  "verify_bound_root_process",
);
const keyAgentAttributeListInitializations = rustCallSites(
  keyAgentCreationAttributeImpl,
  "InitializeProcThreadAttributeList",
);
const keyAgentLpacAttributeUpdates = rustCallSites(
  keyAgentLpacAttributeInstall,
  "update_attribute",
);
const keyAgentLpacAttributeValues = rustFunctionBlock(
  keyAgentLpacRelease,
  "from_profile",
);
const keyAgentProfileCreation = rustCallSites(
  createFreshKeyAgentProfileSid,
  "CreateAppContainerProfile",
);
const keyAgentProfileDerivations = rustCallSites(
  createFreshKeyAgentProfileSid,
  "Self::derive_under_guard",
);
const launchProfileCreation = rustCallSites(
  launchProfileOpenOrCreate,
  "CreateAppContainerProfile",
);
const launchProfileDerivations = rustCallSites(
  launchProfileOpenOrCreate,
  "Self::derive_under_guard",
);
const appContainerProfileNativeApis = [
  "CreateAppContainerProfile",
  "DeriveAppContainerSidFromAppContainerName",
  "GetAppContainerFolderPath",
];
const appContainerProfileNativeApiInventory =
  platformWindowsProductionFiles.flatMap((file) =>
    appContainerProfileNativeApis.flatMap((api) =>
      rustCallSites(file.source, api).map(() => ({ api, path: file.path })),
    ),
  );
const appContainerProfileCoordinatorConsumers =
  platformWindowsProductionFiles
    .filter(
      (file) =>
        file.path !==
          "crates/platform-windows/src/appcontainer_profile_api.rs" &&
        rustCallSites(file.source, "acquire_appcontainer_profile_api").length > 0,
    )
    .map((file) => file.path)
    .sort();
const compactKeyAgentCreationAttributeImpl = compactRust(
  keyAgentCreationAttributeImpl,
);
const keyAgentCreationAttributeOrder = [
  "attributes.install_handle_list()?",
  "attributes.root_job_attribute.install_into(attributes.pointer)",
  "attributes.lpac.install_into(attributes.pointer)",
].map((marker) => compactKeyAgentCreationAttributeImpl.indexOf(marker));
const compactAppContainerProfileAcquire = compactRust(
  acquireAppContainerProfileApi,
);
const compactRejectAppContainerProfileThreadImpersonation = compactRust(
  rejectAppContainerProfileThreadImpersonation,
);
const compactAppContainerProfileGuardDrop = compactRust(
  appContainerProfileApiGuardDrop,
);
const appContainerProfileAcquireOrder = [
  "reject_thread_impersonation()?",
  "PROFILE_API_HELD_BY_THREAD.try_with(Cell::get)",
  "APP_CONTAINER_PROFILE_API.lock()",
  "PROFILE_API_HELD_BY_THREAD.try_with(|held|held.replace(true))",
  "Ok(AppContainerProfileApiGuard{_mutex:mutex})",
].map((marker) => compactAppContainerProfileAcquire.indexOf(marker));
const compactCreateFreshKeyAgentProfileSid = compactRust(
  createFreshKeyAgentProfileSid,
);
const keyAgentProfileApiOrder = [
  "wide_nul_str(KEY_AGENT_PROFILE_V1_NAME)?",
  "wide_nul_str(KEY_AGENT_PROFILE_DISPLAY_NAME)?",
  "wide_nul_str(KEY_AGENT_PROFILE_DESCRIPTION)?",
  "acquire_appcontainer_profile_api()",
  "CreateAppContainerProfile(",
  "Self::derive_under_guard(&profile_api,&name)?",
  "require_created_sid_matches_derived(&created,&derived)?",
].map((marker) => compactCreateFreshKeyAgentProfileSid.indexOf(marker));
const compactLaunchProfileOpenOrCreate = compactRust(
  launchProfileOpenOrCreate,
);
const launchProfileApiOrder = [
  "profile_metadata(profile,role)?",
  "wide_nul_str(metadata.name)",
  "wide_nul_str(metadata.display_name)",
  "wide_nul_str(metadata.description)",
  "acquire_appcontainer_profile_api()",
  "CreateAppContainerProfile(",
  "Self::derive_under_guard(&profile_api,&name_wide)?",
  "EqualSid(created.raw(),derived.raw())",
].map((marker) => compactLaunchProfileOpenOrCreate.indexOf(marker));
const compactKeyAgentAppContainerFolder = compactRust(
  keyAgentAppContainerFolder,
);
const keyAgentAppContainerFolderOrder = [
  "sid_string(profile_sid.as_psid())?",
  "acquire_appcontainer_profile_api()",
  "GetAppContainerFolderPath(",
  "folder.to_string()",
  "CoTaskMemFree(",
].map((marker) => compactKeyAgentAppContainerFolder.indexOf(marker));
requireInvariant(
  platformWindowsLib.includes(
    "#[cfg(windows)]\nmod appcontainer_profile_api;",
  ) &&
    !/pub(?:\([^)]*\))?\s+mod\s+appcontainer_profile_api\b/u.test(
      platformWindowsLibCode,
    ) &&
    appContainerProfileApiProduction.includes(
      "static APP_CONTAINER_PROFILE_API: Mutex<()> = Mutex::new(());",
    ) &&
    appContainerProfileApiProduction.includes(
      "static PROFILE_API_HELD_BY_THREAD: Cell<bool>",
    ) &&
    appContainerProfileApiProduction.includes("ThreadImpersonation") &&
    appContainerProfileApiProduction.includes("OperatingSystem") &&
    /#\[must_use\s*=\s*"[^"]+"\]\s*pub\(crate\)\s+struct\s+AppContainerProfileApiGuard/u.test(
      appContainerProfileApiProduction,
    ) &&
    appContainerProfileApiProduction.includes(
      "_mutex: MutexGuard<'static, ()>",
    ) &&
    appContainerProfileAcquireOrder.every((position) => position !== -1) &&
    appContainerProfileAcquireOrder
      .slice(1)
      .every(
        (position, index) =>
          position > appContainerProfileAcquireOrder[index],
      ) &&
    compactAppContainerProfileAcquire.includes(
      "Err(AppContainerProfileApiCoordinationError::Reentrant)",
    ) &&
    compactRejectAppContainerProfileThreadImpersonation.includes(
      "OpenThreadToken(GetCurrentThread(),TOKEN_QUERY,true,&rawmuttoken)",
    ) &&
    compactRejectAppContainerProfileThreadImpersonation.includes(
      "ERROR_NO_TOKEN.to_hresult()",
    ) &&
    compactRejectAppContainerProfileThreadImpersonation.includes(
      "CloseHandle(token)",
    ) &&
    compactAppContainerProfileAcquire.includes(
      "map_err(|_|AppContainerProfileApiCoordinationError::Poisoned)",
    ) &&
    compactAppContainerProfileAcquire.includes("letwas_held=") &&
    compactAppContainerProfileAcquire.includes("debug_assert!(!was_held)") &&
    !appContainerProfileApiProduction.includes("into_inner") &&
    compactAppContainerProfileGuardDrop.includes(
      "try_with(|held|held.replace(false))",
    ) &&
    JSON.stringify(appContainerProfileCoordinatorConsumers) ===
      JSON.stringify([
        "crates/platform-windows/src/key_agent_lpac.rs",
        "crates/platform-windows/src/launch.rs",
      ]) &&
    appContainerProfileNativeApiInventory.filter(
      (call) => call.api === "CreateAppContainerProfile",
    ).length === 2 &&
    appContainerProfileNativeApiInventory.filter(
      (call) => call.api === "DeriveAppContainerSidFromAppContainerName",
    ).length === 2 &&
    appContainerProfileNativeApiInventory.filter(
      (call) => call.api === "GetAppContainerFolderPath",
    ).length === 1 &&
    appContainerProfileNativeApiInventory.every(
      (call) =>
        call.path === "crates/platform-windows/src/key_agent_lpac.rs" ||
        call.path === "crates/platform-windows/src/launch.rs",
    ) &&
    keyAgentAppContainerFolderOrder.every((position) => position !== -1) &&
    keyAgentAppContainerFolderOrder
      .slice(1)
      .every(
        (position, index) =>
          position > keyAgentAppContainerFolderOrder[index],
      ) &&
    !platformWindowsProductionFiles.some((file) =>
      /\bDeleteAppContainerProfile\b/u.test(rustLexicalCode(file.source)),
    ) &&
    appContainerProfileReentryTest.includes(
      "Err(AppContainerProfileApiCoordinationError::Reentrant)",
    ) &&
    appContainerProfileImpersonationTest.includes(
      "ImpersonateSelf(SecurityImpersonation)",
    ) &&
    appContainerProfileImpersonationTest.includes(
      "Err(AppContainerProfileApiCoordinationError::ThreadImpersonation)",
    ) &&
    concurrentKeyAgentProfilePreparationTest.includes("const WORKERS: usize = 16") &&
    concurrentKeyAgentProfilePreparationTest.includes(
      "AtomicBool::new(false)",
    ) &&
    concurrentKeyAgentProfilePreparationTest.includes(
      "start.load(Ordering::Acquire)",
    ) &&
    concurrentKeyAgentProfilePreparationTest.includes(
      "start.store(true, Ordering::Release)",
    ) &&
    concurrentKeyAgentProfilePreparationTest.includes(
      "PreparedKeyAgentLpac::prepare()?",
    ) &&
    concurrentKeyAgentProfilePreparationTest.includes(
      ".environment_with_local_app_data(context.environment())?",
    ),
  "all AppContainer profile APIs must share one non-reentrant, poison-fail-closed process coordinator whose release build mutates TLS outside debug assertions",
);
const compactProvisionFreshKeyAgent = compactRust(provisionFreshKeyAgent);
const platformWindowsMacroRulesDefinitions = platformWindowsProductionFiles
  .filter((file) => /\bmacro_rules\s*!/u.test(rustLexicalCode(file.source)))
  .map((file) => file.path);
const platformWindowsMacroItemDefinitions = platformWindowsProductionFiles
  .filter((file) =>
    /\bmacro\s+(?:r#)?[\p{XID_Start}_][\p{XID_Continue}_]*/u.test(
      rustLexicalCode(file.source),
    ),
  )
  .map((file) => file.path);
const platformWindowsMacroNamespaceAttributes =
  platformWindowsProductionFiles.flatMap((file) =>
    rustAttributeItems(file.source)
      .filter((attribute) =>
        /^#!?\[macro_(?:export|use)\b/u.test(compactRust(attribute.source)),
      )
      .map((attribute) => ({
        path: file.path,
        attribute: compactRust(attribute.source),
      })),
  );
const platformWindowsAttributeHeadInventory = [
  ...new Set(
    platformWindowsProductionFiles.flatMap((file) =>
      rustAttributeItems(file.source).map((attribute) => {
        const match =
          /^#!?\[(?<path>[\p{XID_Start}_][\p{XID_Continue}_]*(?:::[\p{XID_Start}_][\p{XID_Continue}_]*)*)/u.exec(
            compactRust(attribute.source),
          );
        return match?.groups.path ?? "[UNPARSED]";
      }),
    ),
  ),
].sort();
const platformWindowsProductionPathSet = new Set(
  platformWindowsProductionFiles.map((file) => file.path),
);
const platformWindowsExternalModulePathInventory =
  platformWindowsProductionFiles.flatMap((file) =>
    rustExternalModulePaths(
      file.path,
      file.source,
      platformWindowsProductionPathSet,
    ),
  );
const platformWindowsFunctionLikeMacroPathInventory = [
  ...new Set(
    platformWindowsProductionFiles.flatMap((file) =>
      rustMacroInvocations(file.source).map(
        (invocation) => invocation.normalizedPath,
      ),
    ),
  ),
].sort();
const platformWindowsDerivePathInventory = [
  ...new Set(
    platformWindowsProductionFiles.flatMap((file) =>
      rustAttributeItems(file.source).flatMap((attribute) => {
        const compact = compactRust(attribute.source);
        if (!/^#\[derive\(/u.test(compact)) {
          return [];
        }
        return [
          ...compact
            .slice("#[derive(".length, -2)
            .matchAll(
              /(?:r#)?[\p{XID_Start}_][\p{XID_Continue}_]*(?:::(?:r#)?[\p{XID_Start}_][\p{XID_Continue}_]*)*/gu,
            ),
        ].map((match) =>
          match[0]
            .split("::")
            .map((segment) => segment.replace(/^r#/u, ""))
            .join("::"),
        );
      }),
    ),
  ),
].sort();
const platformWindowsCfgAttrInventory = [
  ...new Set(
    platformWindowsProductionFiles.flatMap((file) =>
      rustAttributeItems(file.source)
        .map((attribute) => compactRust(attribute.source))
        .filter((attribute) => /^#!?\[cfg_attr\(/u.test(attribute)),
    ),
  ),
].sort();
const platformWindowsExpansionSensitiveUseInventory =
  platformWindowsProductionFiles.flatMap((file) =>
    rustExpansionSensitiveUseItems(file.source)
      .map((item) => ({ path: file.path, source: compactRust(item.source) })),
  );
const platformWindowsGlobUseInventory = platformWindowsProductionFiles.flatMap(
  (file) =>
    rustUseItems(file.source)
      .filter((item) => /(?:^|::|\{)\s*\*\s*[,\};]/u.test(item.source))
      .map((item) => ({ path: file.path, source: compactRust(item.source) })),
);
const platformWindowsForbiddenExpansionNamespaces =
  platformWindowsProductionFiles
    .filter((file) => {
      const code = rustLexicalCode(file.source);
      return /\bextern\s+crate\b/u.test(code) ||
        /\bmod\s+(?:r#)?(?:core|ptr|std|thiserror)\b/u.test(code);
    })
    .map((file) => file.path);
const platformWindowsDependencySectionMatch =
  /\[dependencies\]\s*(?<body>[\s\S]*?)(?=\r?\n\[|$)/u.exec(
    platformWindowsManifest,
  );
if (platformWindowsDependencySectionMatch === null) {
  throw new Error("architecture scan lost platform-windows dependencies");
}
const compactPlatformWindowsDependencies =
  platformWindowsDependencySectionMatch.groups.body
    .replace(/^\s*#.*$/gmu, "")
    .replace(/\s+/gu, "");
const platformWindowsDependencySectionInventory = [
  ...platformWindowsManifest.matchAll(
    /^\[(?<section>[^\]]*dependencies[^\]]*)\]\s*$/gmu,
  ),
].map((match) => match.groups.section);
const approvedThiserrorLockRecords = cargoLockPackageRecords(workspaceLock).filter(
  (record) =>
    (record.name === "thiserror" || record.name === "thiserror-impl") &&
    record.version === "2.0.12",
);
const workspaceManifestWithoutComments = workspaceManifest
  .replace(/^\s*#.*$/gmu, "")
  .replace(/\s+#.*$/gmu, "");
const platformWindowsIncludeMacroInvocations =
  platformWindowsProductionFiles.flatMap((file) =>
    rustMacroInvocations(file.source)
      .filter((invocation) =>
        /^(?:include|include_str|include_bytes)$/u.test(
          invocation.normalizedPath.split("::").at(-1),
        ),
      )
      .map((invocation) => ({ path: file.path, macro: invocation.path })),
  );
const platformWindowsIncludeMacroTokens = platformWindowsProductionFiles
  .filter((file) =>
    /\b(?:r#)?include(?:_str|_bytes)?\b/u.test(rustLexicalCode(file.source)),
  )
  .map((file) => file.path);
const keyAgentProvisioningAuthorityTypeNames = [
  "PendingKeyAgentProvisioning",
  "HeldExistingKeyAgentInstallObjects",
  "PreparedKeyAgentProvisioning",
  "PreparedKeyAgentLpac",
  "VerifiedKeyAgentLpac",
  "ExistingInstallAdoptionSeal",
  "VerifiedExistingKeyAgentInstall",
  "VerifiedKeyAgentInstallContinuity",
  "ArtifactBoundExistingKeyAgentInstall",
  "KeyAgentSupervisorBindingSeal",
];
const keyAgentProvisioningAuthorityTypePattern = new RegExp(
  `\\b(?:${keyAgentProvisioningAuthorityTypeNames.join("|")})\\b`,
  "u",
);
const keyAgentProvisioningAuthorityMacroTokenPattern = new RegExp(
  `\\b(?:${keyAgentProvisioningAuthorityTypeNames.join("|")}|PreparedKeyAgentProfile|AttestedArtifactDigest|PreflightKeyAgentArtifact|HeldKeyAgentActivation|RunningKeyAgentActivation|BoundDormantKeyAgent|BoundStorageProvenKeyAgent|attestation|key_agent_activation|key_agent_lpac|key_agent_install_adoption|key_agent_supervisor)\\b`,
  "u",
);
const keyAgentReleaseBindingAuthorityTypeNames = [
  "AttestedArtifactDigest",
  "PreflightKeyAgentArtifact",
  "HeldKeyAgentActivation",
  "RunningKeyAgentActivation",
  "BoundDormantKeyAgent",
  "BoundStorageProvenKeyAgent",
];
const keyAgentReleaseBindingAuthorityTypePattern = new RegExp(
  `\\b(?:${keyAgentReleaseBindingAuthorityTypeNames.join("|")})\\b`,
  "u",
);
const keyAgentReleaseBindingAuthorityImplHeaders =
  platformWindowsProductionFiles.flatMap((file) =>
    rustImplItems(file.source)
      .filter((item) =>
        keyAgentReleaseBindingAuthorityTypePattern.test(item.header),
      )
      .map((item) => ({ path: file.path, header: item.header })),
  );
const keyAgentReleaseBindingAuthorityAliases =
  platformWindowsProductionFiles.flatMap((file) => [
    ...rustUseItems(file.source)
      .filter((item) =>
        keyAgentReleaseBindingAuthorityTypeNames.some((typeName) =>
          new RegExp(`\\b${typeName}\\s+as\\b`, "u").test(
            rustLexicalCode(item.source),
          ),
        ),
      )
      .map((item) => ({ path: file.path, source: compactRust(item.source) })),
    ...rustTypeAliasItems(file.source)
      .filter((item) =>
        keyAgentReleaseBindingAuthorityTypePattern.test(
          rustLexicalCode(item.source),
        ),
      )
      .map((item) => ({ path: file.path, source: compactRust(item.source) })),
  ]);
const keyAgentProvisioningAuthorityMacroInvocations =
  platformWindowsProductionFiles.flatMap((file) =>
    rustMacroInvocations(file.source)
      .filter((invocation) =>
        keyAgentProvisioningAuthorityMacroTokenPattern.test(
          rustLexicalCode(invocation.source),
        ),
      )
      .map((invocation) => ({ path: file.path, macro: invocation.path })),
  );
const keyAgentLpacMacroInvocationInventory = rustMacroInvocations(
  keyAgentLpacRelease,
).map((invocation) => ({
  absolute: invocation.absolute,
  path: invocation.path,
  source: compactRust(invocation.source),
}));
const keyAgentLpacCopySidMacroInventory = rustMacroInvocations(
  rustFunctionBlock(ownedAppContainerSidReleaseImpl, "copy_from"),
).map((invocation) => ({
  absolute: invocation.absolute,
  path: invocation.path,
  source: compactRust(invocation.source),
}));
const keyAgentLpacTokenInformationMacroInventory = rustMacroInvocations(
  rustFunctionBlock(keyAgentLpacRelease, "token_information"),
).map((invocation) => ({
  absolute: invocation.absolute,
  path: invocation.path,
  source: compactRust(invocation.source),
}));
const keyAgentLpacAttributeInventory = rustAttributeItems(
  keyAgentLpacRelease,
).map((attribute) => compactRust(attribute.source));
const keyAgentLpacReleaseCode = rustLexicalCode(keyAgentLpacRelease);
const keyAgentLpacVisibilityCount = [
  ...keyAgentLpacReleaseCode.matchAll(
    /(?<![\p{XID_Continue}_#])pub(?:\s*\([^)]*\))?/gu,
  ),
].length;
const keyAgentLpacVisibleFunctionInventory = rustVisibleFunctionItems(
  keyAgentLpacRelease,
);
const keyAgentLpacVisibleNonFunctionInventory = [
  ...keyAgentLpacReleaseCode.matchAll(
    /(?<![\p{XID_Continue}_#])pub(?<scope>\s*\([^)]*\))?\s+(?<kind>const|static|struct|enum|trait|type|mod|use)\s+(?<name>(?:r#)?[\p{XID_Start}_][\p{XID_Continue}_]*)/gu,
  ),
]
  .filter((match) => !(match.groups.kind === "const" && match.groups.name === "fn"))
  .map((match) => ({
    visibility: `pub${compactRust(match.groups.scope ?? "")}`,
    kind: match.groups.kind,
    name: match.groups.name.replace(/^r#/u, ""),
  }));
const keyAgentLpacAuthorityAttributeInventory = [
  {
    target: "KeyAgentLpacError",
    index: keyAgentLpacReleaseCode.search(
      /\bpub\(crate\)\s+enum\s+KeyAgentLpacError\b/u,
    ),
  },
  {
    target: "PendingKeyAgentProvisioning",
    index: keyAgentLpacReleaseCode.search(
      /\bpub\(crate\)\s+struct\s+PendingKeyAgentProvisioning\b/u,
    ),
  },
  {
    target: "HeldExistingKeyAgentInstallObjects",
    index: keyAgentLpacReleaseCode.search(
      /\bpub\(crate\)\s+struct\s+HeldExistingKeyAgentInstallObjects\b/u,
    ),
  },
  {
    target: "PreparedKeyAgentProvisioning",
    index: keyAgentLpacReleaseCode.search(
      /\bpub\(crate\)\s+struct\s+PreparedKeyAgentProvisioning\b/u,
    ),
  },
  {
    target: "PreparedKeyAgentProfile",
    index: keyAgentLpacReleaseCode.search(/\bstruct\s+PreparedKeyAgentProfile\b/u),
  },
  {
    target: "AppContainerMembershipEvidence",
    index: keyAgentLpacReleaseCode.search(
      /\benum\s+AppContainerMembershipEvidence\b/u,
    ),
  },
].map(({ target, index }) => ({
  target,
  attributes: rustAttachedOuterAttributes(keyAgentLpacRelease, index).map(
    (attribute) => compactRust(attribute.source),
  ),
}));
const platformWindowsLibCodeForAttributes = rustLexicalCode(platformWindowsLib);
const keyAgentSensitiveModuleAttributeInventory = [
  "attestation",
  "key_agent_activation",
  "key_agent_install_adoption",
  "key_agent_install_provenance",
  "key_agent_lpac",
  "key_agent_supervisor",
].map((moduleName) => {
  const index = platformWindowsLibCodeForAttributes.search(
    new RegExp(`\\bmod\\s+${moduleName}\\s*;`, "u"),
  );
  return {
    module: moduleName,
    attributes: rustAttachedOuterAttributes(platformWindowsLib, index).map(
      (attribute) => compactRust(attribute.source),
    ),
  };
});
const preparedKeyAgentProvisioningTokenInventory =
  platformWindowsProductionFiles
    .map((file) => ({
      path: file.path,
      count: [
        ...rustLexicalCode(file.source).matchAll(
          /\bPreparedKeyAgentProvisioning\b/gu,
        ),
      ].length,
    }))
    .filter((entry) => entry.count > 0);
const pendingKeyAgentProvisioningTokenInventory =
  platformWindowsProductionFiles
    .map((file) => ({
      path: file.path,
      count: [
        ...rustLexicalCode(file.source).matchAll(
          /\bPendingKeyAgentProvisioning\b/gu,
        ),
      ].length,
    }))
    .filter((entry) => entry.count > 0);
const platformWindowsAuthorityTypeErasureInventory =
  platformWindowsProductionFiles
    .map((file) => ({
      path: file.path,
      sites: rustAuthorityTypeErasureSites(file.source).length,
    }))
    .filter((file) => file.sites > 0);
const platformWindowsUnsafeSourceInventory = rustUnsafeSourceInventory(
  platformWindowsProductionFiles,
);
const platformWindowsVisibleGenericFunctionInventory =
  platformWindowsProductionFiles.flatMap((file) =>
    rustVisibleFunctionItems(file.source)
      .filter((item) =>
        /^fn(?:r#)?[\p{XID_Start}_][\p{XID_Continue}_]*</u.test(
          item.signature,
        ),
      )
      .map((item) => ({ path: file.path, ...item })),
  );
const approvedPlatformWindowsAuthorityTypeErasureInventory = [
  { path: "crates/platform-windows/src/anchor_registry.rs", sites: 4 },
  { path: "crates/platform-windows/src/broker_channel.rs", sites: 15 },
  { path: "crates/platform-windows/src/broker_supervisor.rs", sites: 7 },
  { path: "crates/platform-windows/src/exact_image.rs", sites: 1 },
  { path: "crates/platform-windows/src/helper.rs", sites: 6 },
  { path: "crates/platform-windows/src/key_agent_activation.rs", sites: 4 },
  { path: "crates/platform-windows/src/key_agent_lpac.rs", sites: 18 },
  { path: "crates/platform-windows/src/key_agent_root_job.rs", sites: 4 },
  { path: "crates/platform-windows/src/key_agent_storage.rs", sites: 20 },
  { path: "crates/platform-windows/src/launch.rs", sites: 15 },
  { path: "crates/platform-windows/src/pipe.rs", sites: 4 },
  { path: "crates/platform-windows/src/storage/sys.rs", sites: 18 },
];
const approvedPlatformWindowsUnsafeSourceInventory = [
  {
    path: "crates/platform-windows/src/appcontainer_profile_api.rs",
    unsafeCount: 2,
    sha256: "6bb03a36657dcf86d1ca7987fc9b3c65d2ed38b21cdcb7790836c1ffb3438194",
  },
  {
    path: "crates/platform-windows/src/broker_channel.rs",
    unsafeCount: 54,
    sha256: "71b01b9d71c9c6920c06118c3b7a65cd571743246c4e28270ea530c08388cf52",
  },
  {
    path: "crates/platform-windows/src/broker_supervisor.rs",
    unsafeCount: 54,
    sha256: "2282924004398ace5b32135e7bfe95e9435b9d611fdb57a48c26ab672ac7b11a",
  },
  {
    path: "crates/platform-windows/src/exact_image.rs",
    unsafeCount: 1,
    sha256: "e02a90adc25ccad2b1ca03dde9cf1abbd269d0f0ef9eb0d9199ab1477dfea763",
  },
  {
    path: "crates/platform-windows/src/helper.rs",
    unsafeCount: 15,
    sha256: "2beb23ad76a85190e9b972d70e35c6ed0a3d0084994158d9736c0ed92cbdd879",
  },
  {
    path: "crates/platform-windows/src/inheritable_handle_launch.rs",
    unsafeCount: 2,
    sha256: "19db654fa8c1f1ea487f0cc5b48ee55e7d9afa8c3f0d19467d6f1215bde525d9",
  },
  {
    path: "crates/platform-windows/src/key_agent_activation.rs",
    unsafeCount: 39,
    sha256: "bb42b3e715a900372ea314f2c8637fdc7a6cd39eebbf64e3510c49a7eeeeb662",
  },
  {
    path: "crates/platform-windows/src/key_agent_child_bootstrap.rs",
    unsafeCount: 13,
    sha256: "a009b6553c58a1cb378f45c1316cd1249d3ce5623350f25a2a79353b2712de1d",
  },
  {
    path: "crates/platform-windows/src/key_agent_lpac.rs",
    unsafeCount: 38,
    sha256: "a5529179a21a58412b26e245b3edb66d179689c8ea90e45f3efaf043e6128d0a",
  },
  {
    path: "crates/platform-windows/src/key_agent_root_job.rs",
    unsafeCount: 12,
    sha256: "41d690a8080eca9981620560e5ce219e6d9008ab652ce8659adb122f718b201c",
  },
  {
    path: "crates/platform-windows/src/key_agent_storage.rs",
    unsafeCount: 56,
    sha256: "0125c5d4c9b6c65b8afded7240ecae6ebeba43e21f7398b01b18ce97bd8aae23",
  },
  {
    path: "crates/platform-windows/src/launch.rs",
    unsafeCount: 35,
    sha256: "4c8771a90b1a09ff28948f95d8ae3b264ed2e4ca46442656670055a9e07a3e4e",
  },
  {
    path: "crates/platform-windows/src/pipe.rs",
    unsafeCount: 40,
    sha256: "4ac64730478967df6cf904269156a3a71ebb43a23bd7b2cb1944e218d4947fa7",
  },
  {
    path: "crates/platform-windows/src/restricted_process_context.rs",
    unsafeCount: 7,
    sha256: "23253730c814bdb3918b96586fb2b91effa2d9ba6da90f2c4d9b10e9571f26cd",
  },
  {
    path: "crates/platform-windows/src/storage/sys.rs",
    unsafeCount: 57,
    sha256: "9f43024a824f0490da4350ae735208d844515aa028bc11bd72b3a24b91426ad7",
  },
];
const approvedPlatformWindowsVisibleGenericFunctionInventory = [
  {
    path: "crates/platform-windows/src/key_agent_activation.rs",
    owner: "free",
    visibility: "pub(crate)",
    name: "run_on_fresh_key_agent_debug_thread",
    signature:
      "fnrun_on_fresh_key_agent_debug_thread<T,E,F>(worker:F)->Result<T,E>whereT:Send+'static,E:From<KeyAgentActivationError>+Send+'static,F:FnOnce(FreshKeyAgentDebugThread)->Result<T,E>+Send+'static,",
  },
  {
    path: "crates/platform-windows/src/pipe.rs",
    owner: "impl PrivateKeyAgentPipes",
    visibility: "pub(crate)",
    name: "prepare_child_inheritance",
    signature:
      "fnprepare_child_inheritance<'pipes,'flight>(&'pipesself,flight:&'flightcrate::inheritable_handle_launch::InheritableHandleLaunchFlight<'static>,)->Result<PreparedKeyAgentInheritance<'pipes,'flight>,PipeError>",
  },
];
const preparedKeyAgentProvisioningReturningFunctions =
  platformWindowsProductionFiles.flatMap((file) =>
    rustFunctionSignatures(file.source)
      .filter((signature) =>
        /->[\s\S]*\bPreparedKeyAgentProvisioning\b/u.test(
          rustLexicalCode(signature.source),
        ),
      )
      .map((signature) => ({ path: file.path, source: signature.source })),
  );
const preparedKeyAgentProvisioningConstructionSites =
  platformWindowsProductionFiles.flatMap((file) =>
    rustStructLiteralSites(file.source, "PreparedKeyAgentProvisioning").map(
      () => file.path,
    ),
  );
const preparedKeyAgentProvisioningAliases = platformWindowsProductionFiles.flatMap(
  (file) => {
    const code = rustLexicalCode(file.source);
    return [
      ...[
        ...code.matchAll(
          /\bPreparedKeyAgentProvisioning\s+as\s+[A-Za-z_]\w*/gu,
        ),
      ].map(() => file.path),
      ...rustTypeAliasItems(file.source)
        .filter((item) =>
          /\bPreparedKeyAgentProvisioning\b/u.test(
            rustLexicalCode(item.source),
          ),
        )
        .map(() => file.path),
    ];
  },
);
const preparedKeyAgentProvisioningImplItems =
  platformWindowsProductionFiles.flatMap((file) =>
    rustImplItems(file.source)
      .filter((item) => /\bPreparedKeyAgentProvisioning\b/u.test(item.header))
      .map((item) => ({ path: file.path, ...item })),
  );
const preparedKeyAgentProvisioningImplHeaders =
  preparedKeyAgentProvisioningImplItems.map(({ path, header }) => ({
    path,
    header,
  }));
const pendingKeyAgentProvisioningImplItems =
  platformWindowsProductionFiles.flatMap((file) =>
    rustImplItems(file.source)
      .filter((item) => /\bPendingKeyAgentProvisioning\b/u.test(item.header))
      .map((item) => ({ path: file.path, ...item })),
  );
const pendingKeyAgentProvisioningImplHeaders =
  pendingKeyAgentProvisioningImplItems.map(({ path, header }) => ({
    path,
    header,
  }));
const keyAgentProvisioningAuthorityImplItems =
  platformWindowsProductionFiles.flatMap((file) =>
    rustImplItems(file.source)
      .filter((item) =>
        keyAgentProvisioningAuthorityTypePattern.test(item.header),
      )
      .map((item) => ({ path: file.path, ...item })),
  );
const keyAgentProvisioningAuthorityImplHeaders =
  keyAgentProvisioningAuthorityImplItems.map(({ path, header }) => ({
    path,
    header,
  }));
const keyAgentProvisioningAuthorityAliases =
  platformWindowsProductionFiles.flatMap((file) => [
    ...rustUseItems(file.source)
      .filter((item) =>
        keyAgentProvisioningAuthorityTypeNames.some((typeName) =>
          new RegExp(`\\b${typeName}\\s+as\\b`, "u").test(
            rustLexicalCode(item.source),
          ),
        ),
      )
      .map((item) => ({ path: file.path, source: compactRust(item.source) })),
    ...rustTypeAliasItems(file.source)
      .filter((item) =>
        keyAgentProvisioningAuthorityTypePattern.test(
          rustLexicalCode(item.source),
        ),
      )
      .map((item) => ({ path: file.path, source: compactRust(item.source) })),
  ]);
const keyAgentProvisioningImplAttributeInventory =
  keyAgentProvisioningAuthorityImplItems.map((item) => {
  const source = platformWindowsProductionFiles.find(
    (file) => file.path === item.path,
  )?.source;
  if (source === undefined) {
    throw new Error("architecture scan lost a provisioning impl source");
  }
  return {
    header: item.header,
    attributes: rustAttachedOuterAttributes(source, item.index).map(
      (attribute) => compactRust(attribute.source),
    ),
  };
  });
const preparedKeyAgentProvisioningSelfConstructionSites =
  preparedKeyAgentProvisioningImplItems.flatMap((item) =>
    rustStructLiteralSites(item.source, "Self").map(() => item.path),
  );
const keyAgentProvisioningTypeDefinitionCounts = [
  "PendingKeyAgentProvisioning",
  "HeldExistingKeyAgentInstallObjects",
  "KeyAgentHeldInstallObservation",
  "PreparedKeyAgentProvisioning",
  "PreparedKeyAgentProfile",
].map(
  (name) =>
    (
      rustLexicalCode(keyAgentLpacRelease).match(
        new RegExp(`\\bstruct\\s+${name}\\b`, "gu"),
      ) ?? []
    ).length,
);
const preparedKeyAgentProvisioningImplScannerProbe = rustImplItems(`
impl PreparedKeyAgentProvisioning
where
    [(); { 1 }]: Sized,
{
    fn hidden_constructor() -> Self {
        Self {}
    }
}
`);
const preparedKeyAgentProvisioningUnsafeImplScannerProbe = rustImplItems(`
unsafe impl HiddenMint for PreparedKeyAgentProvisioning {}
`);
const preparedKeyAgentProvisioningNestedImplScannerProbe = rustImplItems(`
impl UnrelatedType {
    fn install_hidden_impl() {
        impl HiddenMint for PreparedKeyAgentProvisioning {
            fn mint() -> Self {
                Self {}
            }
        }
    }
}
`);
const preparedKeyAgentProvisioningAliasScannerProbe = rustTypeAliasItems(`
type Alias where [(); 1]: Sized = PreparedKeyAgentProvisioning;
`);
const preparedKeyAgentProvisioningReturnScannerProbe = rustFunctionSignatures(`
fn hidden_transition(pending: PendingKeyAgentProvisioning)
    -> core::result::Result<PreparedKeyAgentProvisioning, ()>
{
    transform(pending)
}
`);
const keyAgentProvisioningMacroScannerProbe = `
macro_rules! make_item {
    ($ty:ident) => {
        fn hidden(profile: PreparedKeyAgentProfile, storage_root: HeldKeyAgentStorageRoot) -> Self {
            $ty { profile, storage_root }
        }
    };
}
make_item!(PreparedKeyAgentProvisioning);
`;
const keyAgentProvisioningMacroScannerProbeInvocations = rustMacroInvocations(
  keyAgentProvisioningMacroScannerProbe,
);
const keyAgentProvisioningAdoptionMacroScannerProbeInvocations =
  rustMacroInvocations(`
mint!(HeldExistingKeyAgentInstallObjects);
mint!(ExistingInstallAdoptionSeal);
mint!(VerifiedExistingKeyAgentInstall);
mint!(VerifiedKeyAgentInstallContinuity);
mint!(ArtifactBoundExistingKeyAgentInstall);
mint!(KeyAgentSupervisorBindingSeal);
mint!(AttestedArtifactDigest);
mint!(PreflightKeyAgentArtifact);
mint!(HeldKeyAgentActivation);
mint!(RunningKeyAgentActivation);
mint!(BoundDormantKeyAgent);
mint!(BoundStorageProvenKeyAgent);
mint!(attestation);
mint!(key_agent_activation);
mint!(key_agent_install_adoption);
mint!(key_agent_supervisor);
`).filter((invocation) =>
    keyAgentProvisioningAuthorityMacroTokenPattern.test(
      rustLexicalCode(invocation.source),
    ),
  );
const keyAgentProvisioningAttributeScannerProbe = rustAttributeItems(`
#[derive(HiddenMint)]
struct PreparedKeyAgentProvisioning;
#[cfg_attr(windows, derive(HiddenMint))]
struct PreparedKeyAgentProfile;
#[hidden_mint]
impl PreparedKeyAgentProvisioning {}
`);
const keyAgentProvisioningIncludeScannerProbe = rustMacroInvocations(`
include!(concat!("hidden_prepared_", "constructor.rs"));
`);
const keyAgentProvisioningMacroItemScannerProbe = `
pub macro hidden_mint($ty:ty) {
    impl HiddenMint for $ty {}
}
`;
const keyAgentProvisioningMacroNamespaceAttributeScannerProbe =
  rustAttributeItems(`
#[macro_export]
macro_rules! hidden_mint { () => {} }
#![macro_use]
extern crate hidden_macros;
`);
const keyAgentProvisioningAttachedModuleScannerProbe = `
#[evil::inject]
#[cfg(windows)]
mod key_agent_lpac;
`;
const keyAgentProvisioningAttachedModuleScannerProbeAttributes =
  rustAttachedOuterAttributes(
    keyAgentProvisioningAttachedModuleScannerProbe,
    rustLexicalCode(keyAgentProvisioningAttachedModuleScannerProbe).search(
      /\bmod\s+key_agent_lpac\s*;/u,
    ),
  );
const keyAgentProvisioningKeywordNotScannerProbe = rustMacroInvocations(`
if !(profile_exists || root_exists) {}
`);
const keyAgentProvisioningUnicodeMacroScannerProbe = rustMacroInvocations(`
use ::std::include as μ;
μ!("hidden_prepared_constructor.inc");
`);
const keyAgentProvisioningRawIdentifierMacroScannerProbe =
  rustMacroInvocations(`
r#include!("hidden_prepared_constructor.inc");
`);
const keyAgentProvisioningTypeErasureScannerProbe = `
#[allow(unsafe_code)]
fn cast<T, U>(value: T) -> U {
    let output = unsafe { core::mem::transmute_copy::<T, U>(&value) };
    core::mem::forget(value);
    output
}
`;
const keyAgentProvisioningRawOwnershipScannerProbe = `
union HiddenCast<T, U> {
    source: core::mem::ManuallyDrop<T>,
    target: core::mem::ManuallyDrop<U>,
}
fn boxed_cast<T, U>(value: T) -> U {
    let raw = Box::into_raw(Box::new(value));
    unsafe { ptr::read(raw.cast::<U>()) }
}
fn vector_cast<T, U>(value: T) -> U {
    let mut slot = Vec::with_capacity(1);
    slot.push(value);
    let output = unsafe { slot.as_mut_ptr().cast::<U>().read() };
    unsafe { slot.set_len(0) };
    output
}
fn pointer_ops<T: Copy>(source: *const T, target: *mut T) -> T {
    unsafe {
        target.copy_from_nonoverlapping(source, 1);
        core::ptr::read_unaligned(source)
    }
}
`;
const keyAgentProvisioningTypeErasureScannerProbeSites =
  rustAuthorityTypeErasureSites(keyAgentProvisioningTypeErasureScannerProbe);
const keyAgentProvisioningRawOwnershipScannerProbeSites =
  rustAuthorityTypeErasureSites(keyAgentProvisioningRawOwnershipScannerProbe);
const keyAgentProvisioningExternalPathScannerProbe = rustExternalModulePaths(
  "crates/platform-windows/src/lib.rs",
  `
#[cfg(windows)]
#[path = "../hidden_authority.rs"]
mod hidden_authority;
`,
  platformWindowsProductionPathSet,
);
const keyAgentProvisioningVisibleSurfaceScannerProbe =
  rustVisibleFunctionItems(`
pub(crate) fn erase<T, U>(value: T) -> U {
    convert(value)
}
`);
const keyAgentProvisioningTraitImplScannerProbe = rustImplItems(`
impl HiddenAuthority for VerifiedKeyAgentLpac {
    fn mint(&self) {}
}
`).map((item) => item.header);
const keyAgentProvisioningUnsafeSourceOriginal =
  platformWindowsUnsafeSourceInventory.find(
    (file) => file.path === "crates/platform-windows/src/helper.rs",
  );
const keyAgentProvisioningUnsafeSourceMutationProbe = rustUnsafeSourceInventory([
  {
    path: "crates/platform-windows/src/helper.rs",
    source: `${
      platformWindowsProductionFiles.find(
        (file) => file.path === "crates/platform-windows/src/helper.rs",
      )?.source ?? ""
    }
pub(crate) fn hidden_raw_move<T, U>(pointer: *const U) -> U {
    unsafe { *pointer }
}
`,
  },
]).at(0);
const keyAgentProvisioningDeriveAliasScannerProbe =
  rustExpansionSensitiveUseItems(`
use approval_wire::Mint as Clone;
use approval_wire::OtherMint as r#Debug;
`);
const keyAgentFreshProvisioningOrder = [
  "PreparedKeyAgentProfile::provision_fresh()?",
  "create_fixed_key_agent_storage_root(",
  "&profile.appcontainer_local_data",
  "profile.profile_sid.as_psid()",
  "Ok(Self{profile,storage_root,})",
].map((marker) => compactProvisionFreshKeyAgent.indexOf(marker));
requireInvariant(
  JSON.stringify(pendingKeyAgentProvisioningTokenInventory) ===
      JSON.stringify([
        {
          path: "crates/platform-windows/src/key_agent_lpac.rs",
          count: 3,
        },
        {
          path: "crates/platform-windows/src/key_agent_supervisor.rs",
          count: 3,
        },
      ]) &&
    JSON.stringify(platformWindowsAuthorityTypeErasureInventory) ===
      JSON.stringify(approvedPlatformWindowsAuthorityTypeErasureInventory) &&
    JSON.stringify(platformWindowsUnsafeSourceInventory) ===
      JSON.stringify(approvedPlatformWindowsUnsafeSourceInventory) &&
    JSON.stringify(platformWindowsVisibleGenericFunctionInventory) ===
      JSON.stringify(approvedPlatformWindowsVisibleGenericFunctionInventory) &&
    /\bpub\(crate\)\s+enum\s+KeyAgentSupervisorError\b/u.test(
      rustLexicalCode(keyAgentSupervisorRelease),
    ) &&
    !/\bunsafe\b/u.test(rustLexicalCode(keyAgentSupervisorRelease)),
  "Pending authority references, crate-visible generic callables, raw ownership sites, and unsafe-bearing production sources must remain exact while supervisor code stays safe-only",
);
requireInvariant(
  JSON.stringify(platformWindowsMacroRulesDefinitions) === JSON.stringify([]) &&
    JSON.stringify(platformWindowsMacroItemDefinitions) === JSON.stringify([]) &&
    JSON.stringify(platformWindowsMacroNamespaceAttributes) ===
      JSON.stringify([]) &&
    JSON.stringify(platformWindowsIncludeMacroInvocations) ===
      JSON.stringify([]) &&
    JSON.stringify(platformWindowsIncludeMacroTokens) === JSON.stringify([]) &&
    JSON.stringify(keyAgentProvisioningAuthorityMacroInvocations) ===
      JSON.stringify([]),
  "production Rust must not hide Key Agent provisioning authority behind declarative, include, or authority-bearing function-like macros",
);
requireInvariant(
  JSON.stringify(keyAgentReleaseBindingAuthorityImplHeaders) ===
      JSON.stringify([
        {
          path: "crates/platform-windows/src/attestation.rs",
          header: "impl AttestedArtifactDigest",
        },
        {
          path: "crates/platform-windows/src/attestation.rs",
          header: "impl core::fmt::Debug for AttestedArtifactDigest",
        },
        {
          path: "crates/platform-windows/src/key_agent_activation.rs",
          header: "impl HeldKeyAgentActivation",
        },
        {
          path: "crates/platform-windows/src/key_agent_activation.rs",
          header: "impl RunningKeyAgentActivation",
        },
        {
          path: "crates/platform-windows/src/key_agent_activation.rs",
          header: "impl fmt::Debug for RunningKeyAgentActivation",
        },
        {
          path: "crates/platform-windows/src/key_agent_activation.rs",
          header: "impl fmt::Debug for HeldKeyAgentActivation",
        },
        {
          path: "crates/platform-windows/src/key_agent_activation.rs",
          header: "impl PreflightKeyAgentArtifact",
        },
        {
          path: "crates/platform-windows/src/key_agent_activation.rs",
          header: "impl fmt::Debug for PreflightKeyAgentArtifact",
        },
        {
          path: "crates/platform-windows/src/key_agent_supervisor.rs",
          header: "impl fmt::Debug for BoundDormantKeyAgent",
        },
        {
          path: "crates/platform-windows/src/key_agent_supervisor.rs",
          header: "impl fmt::Debug for BoundStorageProvenKeyAgent",
        },
      ]) &&
    JSON.stringify(keyAgentReleaseBindingAuthorityAliases) === JSON.stringify([]),
  "opaque release, preflight, activation, and bound supervisor authorities must have no alternate trait conversion or alias surface",
);
requireInvariant(
  JSON.stringify(platformWindowsAttributeHeadInventory) ===
    JSON.stringify([
      "allow",
      "cfg",
      "cfg_attr",
      "derive",
      "error",
      "expect",
      "must_use",
      "path",
      "repr",
      "source",
      "test",
    ]),
  "production Rust attributes must not introduce an unreviewed proc-macro expansion entry point",
);
requireInvariant(
  JSON.stringify(platformWindowsExternalModulePathInventory) ===
    JSON.stringify([
      {
        declaringFile: "crates/platform-windows/src/broker_artifact.rs",
        module: "broker_supervisor",
        literal: "broker_supervisor.rs",
        resolvedTarget:
          "crates/platform-windows/src/broker_supervisor.rs",
        insideCrateSource: true,
        inProductionInventory: true,
        attributes: ["#[cfg(windows)]", "#[path=]"],
      },
    ]),
  "production #[path] modules must remain exact, resolve inside platform-windows/src, and be included in the scanned production inventory",
);
requireInvariant(
  keyAgentLpacVisibilityCount === 22 &&
    JSON.stringify(keyAgentLpacVisibleFunctionInventory) ===
      JSON.stringify([
        {
          owner: "impl PendingKeyAgentProvisioning",
          visibility: "pub(crate)",
          name: "provision_fresh",
          signature:
            "fnprovision_fresh()->Result<Self,KeyAgentLpacError>",
        },
        {
          owner: "impl HeldExistingKeyAgentInstallObjects",
          visibility: "pub(crate)",
          name: "revalidate",
          signature: "fnrevalidate(&self)->Result<(),KeyAgentLpacError>",
        },
        {
          owner: "impl HeldExistingKeyAgentInstallObjects",
          visibility: "pub(crate)",
          name: "install_observation",
          signature:
            "fninstall_observation(&self,)->Result<KeyAgentHeldInstallObservation,KeyAgentLpacError>",
        },
        {
          owner: "impl HeldExistingKeyAgentInstallObjects",
          visibility: "pub(crate)",
          name: "into_prepared",
          signature:
            "fninto_prepared(self,_seal:ExistingInstallAdoptionSeal,)->PreparedKeyAgentProvisioning",
        },
        {
          owner: "impl KeyAgentHeldInstallObservation",
          visibility: "pub(crate)",
          name: "profile_sid",
          signature: "fnprofile_sid(&self)->&[u8]",
        },
        {
          owner: "impl KeyAgentHeldInstallObservation",
          visibility: "pub(crate)",
          name: "stable_user_sid",
          signature: "fnstable_user_sid(&self)->&[u8]",
        },
        {
          owner: "impl KeyAgentHeldInstallObservation",
          visibility: "pub(crate)",
          name: "storage_profile_sid",
          signature: "fnstorage_profile_sid(&self)->&[u8]",
        },
        {
          owner: "impl KeyAgentHeldInstallObservation",
          visibility: "pub(crate)const",
          name: "storage_root_identity",
          signature:
            "fnstorage_root_identity(&self)->KeyAgentStorageRootIdentity",
        },
        {
          owner: "impl PreparedKeyAgentProvisioning",
          visibility: "pub(crate)",
          name: "revalidate",
          signature:
            "fnrevalidate(&self)->Result<(),KeyAgentLpacError>",
        },
        {
          owner: "impl PreparedKeyAgentProvisioning",
          visibility: "pub(crate)",
          name: "prepare_lpac",
          signature:
            "fnprepare_lpac(&self)->Result<PreparedKeyAgentLpac,KeyAgentLpacError>",
        },
        {
          owner: "impl PreparedKeyAgentProvisioning",
          visibility: "pub(crate)",
          name: "storage_root_identity",
          signature:
            "fnstorage_root_identity(&self)->KeyAgentStorageRootIdentity",
        },
        {
          owner: "impl PreparedKeyAgentLpac",
          visibility: "pub(crate)",
          name: "environment_with_local_app_data",
          signature:
            "fnenvironment_with_local_app_data(&self,base_environment:&[u16],)->Result<Box<[u16]>,KeyAgentLpacError>",
        },
        {
          owner: "impl PreparedKeyAgentLpac",
          visibility: "pub(crate)unsafe",
          name: "install_into",
          signature:
            "fninstall_into(&self,attribute_list:LPPROC_THREAD_ATTRIBUTE_LIST,)->Result<(),KeyAgentLpacError>",
        },
        {
          owner: "impl PreparedKeyAgentLpac",
          visibility: "pub(crate)",
          name: "verify_suspended_process",
          signature:
            "fnverify_suspended_process(self,process:BorrowedHandle<'_>,)->Result<VerifiedKeyAgentLpac,KeyAgentLpacError>",
        },
      ]) &&
    JSON.stringify(keyAgentLpacVisibleNonFunctionInventory) ===
      JSON.stringify([
        {
          visibility: "pub(crate)",
          kind: "const",
          name: "KEY_AGENT_PROFILE_V1_NAME",
        },
        {
          visibility: "pub(crate)",
          kind: "enum",
          name: "KeyAgentLpacError",
        },
        {
          visibility: "pub(crate)",
          kind: "struct",
          name: "PendingKeyAgentProvisioning",
        },
        {
          visibility: "pub(crate)",
          kind: "struct",
          name: "HeldExistingKeyAgentInstallObjects",
        },
        {
          visibility: "pub(crate)",
          kind: "struct",
          name: "KeyAgentHeldInstallObservation",
        },
        {
          visibility: "pub(crate)",
          kind: "struct",
          name: "PreparedKeyAgentProvisioning",
        },
        {
          visibility: "pub(crate)",
          kind: "struct",
          name: "PreparedKeyAgentLpac",
        },
        {
          visibility: "pub(crate)",
          kind: "struct",
          name: "VerifiedKeyAgentLpac",
        },
      ]),
  "the complete release LPAC crate-visible callable and item surface must remain exact",
);
requireInvariant(
  JSON.stringify(platformWindowsFunctionLikeMacroPathInventory) ===
      JSON.stringify([
        "assert",
        "assert_eq",
        "assert_ne",
        "core::mem::offset_of",
        "debug_assert",
        "debug_assert_eq",
        "format",
        "matches",
        "offset_of",
        "ptr::addr_of",
        "std::vec",
        "thread_local",
        "unreachable",
        "vec",
        "write",
      ]) &&
    JSON.stringify(platformWindowsDerivePathInventory) ===
      JSON.stringify([
        "Clone",
        "Copy",
        "Debug",
        "Default",
        "Eq",
        "Error",
        "Hash",
        "PartialEq",
      ]) &&
    JSON.stringify(platformWindowsCfgAttrInventory) ===
      JSON.stringify([
        "#![cfg_attr(not(windows),allow(dead_code))]",
        "#[cfg_attr(not(test),allow(dead_code,reason=))]",
        "#[cfg_attr(not(test),allow(unused_variables))]",
      ]) &&
    platformWindowsExpansionSensitiveUseInventory.every((item) =>
      [
        "usecore::mem::{offset_of,size_of,size_of_val};",
        "usecore::ptr;",
        "usethiserror::Error;",
      ].includes(item.source),
    ) &&
    JSON.stringify(platformWindowsGlobUseInventory) ===
      JSON.stringify([
        {
          path: "crates/platform-windows/src/anchor_registry/tests.rs",
          source: "usesuper::*;",
        },
      ]) &&
    JSON.stringify(platformWindowsForbiddenExpansionNamespaces) ===
      JSON.stringify([]),
  "platform-windows production macro, derive, cfg_attr, import, glob, and namespace expansion providers must remain exact",
);
requireInvariant(
  platformWindowsManifestSha256 ===
      "c38ce9223cdb6b5fc12e33e27df69c6f5f8796affa753f31eb4386f6c87680bc" &&
    JSON.stringify(platformWindowsCrateRootInventory) ===
      JSON.stringify([
        { name: "Cargo.toml", kind: "file" },
        { name: "README.md", kind: "file" },
        { name: "src", kind: "directory" },
      ]) &&
    JSON.stringify(platformWindowsLocalDependencyManifestInventory) ===
      JSON.stringify(approvedPlatformWindowsLocalDependencyManifestInventory) &&
    JSON.stringify(platformWindowsLocalDependencyCrateRootInventory) ===
      JSON.stringify(approvedPlatformWindowsLocalDependencyCrateRootInventory) &&
    JSON.stringify(platformWindowsLocalDependencySourceInventory) ===
      JSON.stringify(approvedPlatformWindowsLocalDependencySourceInventory) &&
    [approvalWireManifest, secretInputUiManifest].every((manifest) =>
      /^build\s*=\s*false$/gmu.test(manifest),
    ) &&
    /^build\s*=\s*false$/gmu.test(platformWindowsManifest) &&
    JSON.stringify(platformWindowsDependencySectionInventory) ===
      JSON.stringify(["dependencies"]) &&
    compactPlatformWindowsDependencies ===
      [
        'approval-wire={path="../approval-wire"}',
        "getrandom.workspace=true",
        "hmac.workspace=true",
        "sha2.workspace=true",
        'secret-input-ui={path="../secret-input-ui"}',
        "subtle.workspace=true",
        "thiserror.workspace=true",
        "windows={workspace=true,features=[",
        '"Win32_Globalization",',
        '"Win32_Security_Authorization",',
        '"Win32_Security_Cryptography",',
        '"Win32_Security_Cryptography_Catalog",',
        '"Win32_Security_Cryptography_Sip",',
        '"Win32_Security_Isolation",',
        '"Win32_Security_WinTrust",',
        '"Win32_System_Diagnostics_Debug",',
        '"Win32_System_Com",',
        '"Win32_System_IO",',
        '"Win32_System_ProcessStatus",',
        '"Win32_System_RemoteDesktop",',
        '"Win32_System_SystemInformation",',
        '"Win32_System_SystemServices",',
        '"Win32_System_WindowsProgramming",',
        "]}",
        "zeroize.workspace=true",
      ].join("") &&
    rootManifestSha256 ===
      "f0e60d7e80e30c69bb9b3251a4217d8c52e242a1f1f85c10add4c893c8df4e49" &&
    workspaceLockSha256 ===
      "8ff742854955e290a3d5b5c502221c7fb6829d82931f50f838d849648d9fe483" &&
    (workspaceManifest.match(/^thiserror\s*=\s*"=2\.0\.12"\s*$/gmu) ?? [])
      .length === 1 &&
    !/\b(?:patch|replace)\b/u.test(workspaceManifestWithoutComments) &&
    JSON.stringify(repositoryCargoOverrideInventory) === JSON.stringify([]) &&
    JSON.stringify(approvedThiserrorLockRecords) ===
      JSON.stringify([
        {
          name: "thiserror",
          version: "2.0.12",
          source: "registry+https://github.com/rust-lang/crates.io-index",
          checksum:
            "567b8a2dae586314f7be2a752ec7474332959c6460e02bde30d702a66d488708",
          dependencies: ["thiserror-impl 2.0.12"],
        },
        {
          name: "thiserror-impl",
          version: "2.0.12",
          source: "registry+https://github.com/rust-lang/crates.io-index",
          checksum:
            "7f7cf42b4507d8ea322120659672cf1b9dbb93f8f2d4ecfd6e51350ff5b17a1d",
          dependencies: ["proc-macro2", "quote", "syn 2.0.119"],
        },
      ]) &&
    !/\bproc-macro\s*=/u.test(platformWindowsManifest),
  "platform-windows package/local-dependency source closure, workspace manifest, complete lockfile/provider closure, default entrypoints, disabled build scripts, and dependencies must remain exact",
);
requireInvariant(
  JSON.stringify(keyAgentLpacMacroInvocationInventory) ===
      JSON.stringify([
        {
          absolute: true,
          path: "std::vec",
          source: "std::vec![0_usize;word_count]",
        },
        {
          absolute: true,
          path: "std::vec",
          source: "std::vec![0_usize;word_count]",
        },
      ]) &&
    JSON.stringify(keyAgentLpacCopySidMacroInventory) ===
      JSON.stringify([
        {
          absolute: true,
          path: "std::vec",
          source: "std::vec![0_usize;word_count]",
        },
      ]) &&
    JSON.stringify(keyAgentLpacTokenInformationMacroInventory) ===
      JSON.stringify([
        {
          absolute: true,
          path: "std::vec",
          source: "std::vec![0_usize;word_count]",
        },
      ]),
  "the release Key Agent LPAC function-like macro inventory and enclosing functions must remain exact",
);
requireInvariant(
  JSON.stringify(keyAgentLpacAttributeInventory) ===
    JSON.stringify([
      "#![allow(unsafe_code)]",
      "#[derive(Eq,PartialEq)]",
      "#[must_use=]",
      "#[must_use=]",
      "#[must_use=]",
      "#[must_use=]",
      "#[derive(Clone,Copy,Debug,Eq,PartialEq)]",
    ]),
  "the release Key Agent LPAC attribute inventory must remain exact",
);
requireInvariant(
  JSON.stringify(keyAgentLpacAuthorityAttributeInventory) ===
    JSON.stringify([
      {
        target: "KeyAgentLpacError",
        attributes: ["#[derive(Eq,PartialEq)]"],
      },
      {
        target: "PendingKeyAgentProvisioning",
        attributes: ["#[must_use=]"],
      },
      {
        target: "HeldExistingKeyAgentInstallObjects",
        attributes: ["#[must_use=]"],
      },
      {
        target: "PreparedKeyAgentProvisioning",
        attributes: ["#[must_use=]"],
      },
      {
        target: "PreparedKeyAgentProfile",
        attributes: ["#[must_use=]"],
      },
      {
        target: "AppContainerMembershipEvidence",
        attributes: ["#[derive(Clone,Copy,Debug,Eq,PartialEq)]"],
      },
    ]),
  "the release Key Agent LPAC authority-bearing type attributes must stay attached to their exact targets",
);
requireInvariant(
  JSON.stringify(keyAgentProvisioningImplAttributeInventory) ===
    JSON.stringify([
      {
        header: "impl fmt::Debug for VerifiedKeyAgentInstallContinuity",
        attributes: [],
      },
      {
        header: "impl fmt::Debug for ArtifactBoundExistingKeyAgentInstall",
        attributes: [],
      },
      {
        header: "impl fmt::Debug for VerifiedExistingKeyAgentInstall",
        attributes: [],
      },
      {
        header: "impl PendingKeyAgentProvisioning",
        attributes: [],
      },
      {
        header: "impl fmt::Debug for PendingKeyAgentProvisioning",
        attributes: [],
      },
      {
        header: "impl HeldExistingKeyAgentInstallObjects",
        attributes: [],
      },
      {
        header: "impl fmt::Debug for HeldExistingKeyAgentInstallObjects",
        attributes: [],
      },
      {
        header: "impl PreparedKeyAgentProvisioning",
        attributes: [],
      },
      {
        header: "impl fmt::Debug for PreparedKeyAgentProvisioning",
        attributes: [],
      },
      {
        header: "impl PreparedKeyAgentLpac",
        attributes: [],
      },
      {
        header: "impl fmt::Debug for PreparedKeyAgentLpac",
        attributes: [],
      },
      {
        header: "impl fmt::Debug for VerifiedKeyAgentLpac",
        attributes: [],
      },
    ]),
  "the release Key Agent provisioning impls must have no expansion attributes",
);
requireInvariant(
  JSON.stringify(keyAgentSensitiveModuleAttributeInventory) ===
    JSON.stringify([
      {
        module: "attestation",
        attributes: [],
      },
      {
        module: "key_agent_activation",
        attributes: ["#[cfg(windows)]"],
      },
      {
        module: "key_agent_install_adoption",
        attributes: ["#[cfg(windows)]", "#[allow(dead_code)]"],
      },
      {
        module: "key_agent_install_provenance",
        attributes: ["#[cfg(windows)]", "#[allow(dead_code)]"],
      },
      {
        module: "key_agent_lpac",
        attributes: ["#[cfg(windows)]"],
      },
      {
        module: "key_agent_supervisor",
        attributes: ["#[cfg(windows)]"],
      },
    ]),
  "the sensitive Key Agent module declarations must retain only their exact built-in attributes",
);
requireInvariant(
  JSON.stringify(keyAgentLpacMacroInvocationInventory) ===
      JSON.stringify([
        {
          absolute: true,
          path: "std::vec",
          source: "std::vec![0_usize;word_count]",
        },
        {
          absolute: true,
          path: "std::vec",
          source: "std::vec![0_usize;word_count]",
        },
      ]) &&
    JSON.stringify(keyAgentLpacCopySidMacroInventory) ===
      JSON.stringify([
        {
          absolute: true,
          path: "std::vec",
          source: "std::vec![0_usize;word_count]",
        },
      ]) &&
    JSON.stringify(keyAgentLpacTokenInformationMacroInventory) ===
      JSON.stringify([
        {
          absolute: true,
          path: "std::vec",
          source: "std::vec![0_usize;word_count]",
        },
      ]) &&
    JSON.stringify(keyAgentLpacAttributeInventory) ===
      JSON.stringify([
        "#![allow(unsafe_code)]",
        "#[derive(Eq,PartialEq)]",
        "#[must_use=]",
        "#[must_use=]",
        "#[must_use=]",
        "#[must_use=]",
        "#[derive(Clone,Copy,Debug,Eq,PartialEq)]",
      ]) &&
    JSON.stringify(keyAgentLpacAuthorityAttributeInventory) ===
      JSON.stringify([
        {
          target: "KeyAgentLpacError",
          attributes: ["#[derive(Eq,PartialEq)]"],
        },
        {
          target: "PendingKeyAgentProvisioning",
          attributes: ["#[must_use=]"],
        },
        {
          target: "HeldExistingKeyAgentInstallObjects",
          attributes: ["#[must_use=]"],
        },
        {
          target: "PreparedKeyAgentProvisioning",
          attributes: ["#[must_use=]"],
        },
        {
          target: "PreparedKeyAgentProfile",
          attributes: ["#[must_use=]"],
        },
        {
          target: "AppContainerMembershipEvidence",
          attributes: ["#[derive(Clone,Copy,Debug,Eq,PartialEq)]"],
        },
      ]) &&
    JSON.stringify(keyAgentProvisioningImplAttributeInventory) ===
      JSON.stringify([
        {
          header: "impl fmt::Debug for VerifiedKeyAgentInstallContinuity",
          attributes: [],
        },
        {
          header: "impl fmt::Debug for ArtifactBoundExistingKeyAgentInstall",
          attributes: [],
        },
        {
          header: "impl fmt::Debug for VerifiedExistingKeyAgentInstall",
          attributes: [],
        },
        {
          header: "impl PendingKeyAgentProvisioning",
          attributes: [],
        },
        {
          header: "impl fmt::Debug for PendingKeyAgentProvisioning",
          attributes: [],
        },
        {
          header: "impl HeldExistingKeyAgentInstallObjects",
          attributes: [],
        },
        {
          header: "impl fmt::Debug for HeldExistingKeyAgentInstallObjects",
          attributes: [],
        },
        {
          header: "impl PreparedKeyAgentProvisioning",
          attributes: [],
        },
        {
          header: "impl fmt::Debug for PreparedKeyAgentProvisioning",
          attributes: [],
        },
        {
          header: "impl PreparedKeyAgentLpac",
          attributes: [],
        },
        {
          header: "impl fmt::Debug for PreparedKeyAgentLpac",
          attributes: [],
        },
        {
          header: "impl fmt::Debug for VerifiedKeyAgentLpac",
          attributes: [],
        },
      ]) &&
    JSON.stringify(keyAgentSensitiveModuleAttributeInventory) ===
      JSON.stringify([
        {
          module: "attestation",
          attributes: [],
        },
        {
          module: "key_agent_activation",
          attributes: ["#[cfg(windows)]"],
        },
        {
          module: "key_agent_install_adoption",
          attributes: ["#[cfg(windows)]", "#[allow(dead_code)]"],
        },
        {
          module: "key_agent_install_provenance",
          attributes: ["#[cfg(windows)]", "#[allow(dead_code)]"],
        },
        {
          module: "key_agent_lpac",
          attributes: ["#[cfg(windows)]"],
        },
        {
          module: "key_agent_supervisor",
          attributes: ["#[cfg(windows)]"],
        },
      ]),
  "the release Key Agent LPAC macro and attribute surface must remain exact so expansion cannot mint provisioning authority",
);
requireInvariant(
  /\bmacro_rules\s*!/u.test(
    rustLexicalCode(keyAgentProvisioningMacroScannerProbe),
  ) &&
    keyAgentProvisioningMacroScannerProbeInvocations.length === 1 &&
    keyAgentProvisioningMacroScannerProbeInvocations[0].path === "make_item" &&
    /\bPreparedKeyAgentProvisioning\b/u.test(
      rustLexicalCode(
        keyAgentProvisioningMacroScannerProbeInvocations[0].source,
      ),
    ) &&
    JSON.stringify(
      keyAgentProvisioningAdoptionMacroScannerProbeInvocations.map(
        (invocation) => ({
          path: invocation.path,
          source: compactRust(invocation.source),
        }),
      ),
    ) ===
      JSON.stringify([
        {
          path: "mint",
          source: "mint!(HeldExistingKeyAgentInstallObjects)",
        },
        {
          path: "mint",
          source: "mint!(ExistingInstallAdoptionSeal)",
        },
        {
          path: "mint",
          source: "mint!(VerifiedExistingKeyAgentInstall)",
        },
        {
          path: "mint",
          source: "mint!(VerifiedKeyAgentInstallContinuity)",
        },
        {
          path: "mint",
          source: "mint!(ArtifactBoundExistingKeyAgentInstall)",
        },
        {
          path: "mint",
          source: "mint!(KeyAgentSupervisorBindingSeal)",
        },
        {
          path: "mint",
          source: "mint!(AttestedArtifactDigest)",
        },
        {
          path: "mint",
          source: "mint!(PreflightKeyAgentArtifact)",
        },
        {
          path: "mint",
          source: "mint!(HeldKeyAgentActivation)",
        },
        {
          path: "mint",
          source: "mint!(RunningKeyAgentActivation)",
        },
        {
          path: "mint",
          source: "mint!(BoundDormantKeyAgent)",
        },
        {
          path: "mint",
          source: "mint!(BoundStorageProvenKeyAgent)",
        },
        {
          path: "mint",
          source: "mint!(attestation)",
        },
        {
          path: "mint",
          source: "mint!(key_agent_activation)",
        },
        {
          path: "mint",
          source: "mint!(key_agent_install_adoption)",
        },
        {
          path: "mint",
          source: "mint!(key_agent_supervisor)",
        },
      ]) &&
    keyAgentProvisioningAttributeScannerProbe.length === 3 &&
    keyAgentProvisioningAttributeScannerProbe.every(
      (attribute) => attribute.inner === false,
    ) &&
    JSON.stringify(
      keyAgentProvisioningIncludeScannerProbe.map(
        (invocation) => invocation.path,
      ),
    ) === JSON.stringify(["include", "concat"]) &&
    /\bmacro\s+hidden_mint\b/u.test(
      rustLexicalCode(keyAgentProvisioningMacroItemScannerProbe),
    ) &&
    JSON.stringify(
      keyAgentProvisioningMacroNamespaceAttributeScannerProbe.map(
        (attribute) => compactRust(attribute.source),
      ),
    ) === JSON.stringify(["#[macro_export]", "#![macro_use]"]) &&
    keyAgentProvisioningAttachedModuleScannerProbeAttributes.length === 2 &&
    JSON.stringify(
      keyAgentProvisioningAttachedModuleScannerProbeAttributes.map(
        (attribute) => compactRust(attribute.source),
      ),
    ) === JSON.stringify(["#[evil::inject]", "#[cfg(windows)]"]) &&
    keyAgentProvisioningKeywordNotScannerProbe.length === 0 &&
    keyAgentProvisioningUnicodeMacroScannerProbe.length === 1 &&
    keyAgentProvisioningUnicodeMacroScannerProbe[0].path === "μ" &&
    keyAgentProvisioningUnicodeMacroScannerProbe[0].normalizedPath === "μ" &&
    keyAgentProvisioningRawIdentifierMacroScannerProbe.length === 1 &&
    keyAgentProvisioningRawIdentifierMacroScannerProbe[0].path ===
      "r#include" &&
    keyAgentProvisioningRawIdentifierMacroScannerProbe[0].normalizedPath ===
      "include" &&
    JSON.stringify(keyAgentProvisioningTypeErasureScannerProbeSites) ===
      JSON.stringify(["transmute_copy", "forget"]) &&
    JSON.stringify(keyAgentProvisioningRawOwnershipScannerProbeSites) ===
      JSON.stringify([
        "union HiddenCast",
        "ManuallyDrop",
        "ManuallyDrop",
        "into_raw",
        "ptr::read(",
        ".cast::<U>()",
        ".cast::<U>()",
        ".read()",
        ".set_len(",
        ".copy_from_nonoverlapping(",
        "core::ptr::read_unaligned(",
      ]) &&
    JSON.stringify(keyAgentProvisioningExternalPathScannerProbe) ===
      JSON.stringify([
        {
          declaringFile: "crates/platform-windows/src/lib.rs",
          module: "hidden_authority",
          literal: "../hidden_authority.rs",
          resolvedTarget: "crates/platform-windows/hidden_authority.rs",
          insideCrateSource: false,
          inProductionInventory: false,
          attributes: ["#[cfg(windows)]", "#[path=]"],
        },
      ]) &&
    JSON.stringify(keyAgentProvisioningVisibleSurfaceScannerProbe) ===
      JSON.stringify([
        {
          owner: "free",
          visibility: "pub(crate)",
          name: "erase",
          signature: "fnerase<T,U>(value:T)->U",
        },
      ]) &&
    JSON.stringify(keyAgentProvisioningTraitImplScannerProbe) ===
      JSON.stringify(["impl HiddenAuthority for VerifiedKeyAgentLpac"]) &&
    keyAgentProvisioningUnsafeSourceOriginal !== undefined &&
    keyAgentProvisioningUnsafeSourceMutationProbe !== undefined &&
    keyAgentProvisioningUnsafeSourceMutationProbe.unsafeCount ===
      keyAgentProvisioningUnsafeSourceOriginal.unsafeCount + 1 &&
    keyAgentProvisioningUnsafeSourceMutationProbe.sha256 !==
      keyAgentProvisioningUnsafeSourceOriginal.sha256 &&
    JSON.stringify(
      keyAgentProvisioningDeriveAliasScannerProbe.map((item) =>
        compactRust(item.source),
      ),
    ) ===
      JSON.stringify([
        "useapproval_wire::MintasClone;",
        "useapproval_wire::OtherMintasr#Debug;",
      ]),
  "the architecture scanner must detect macro and attribute expansion probes around Key Agent provisioning authority",
);
requireInvariant(
  /const\s+KEY_AGENT_PROFILE_V1_NAME:\s*&str\s*=\s*"YourWallet\.KeyAgent\.LPAC\.v1"\s*;/u.test(
    keyAgentLpacRelease,
  ) &&
    compactRust(pendingKeyAgentProvisioningBlock) ===
      "pub(crate)structPendingKeyAgentProvisioning{profile:PreparedKeyAgentProfile,storage_root:HeldKeyAgentStorageRoot,}" &&
    compactRust(heldExistingKeyAgentInstallObjectsBlock) ===
      "pub(crate)structHeldExistingKeyAgentInstallObjects{profile:PreparedKeyAgentProfile,storage_root:HeldKeyAgentStorageRoot,}" &&
    compactRust(heldKeyAgentInstallObservationBlock) ===
      "pub(crate)structKeyAgentHeldInstallObservation{profile_sid_len:u8,profile_sid:[u8;MAX_INSTALL_SID_BYTES],root:KeyAgentHeldRootObservation,}" &&
    compactRust(preparedKeyAgentProvisioningBlock) ===
      "pub(crate)structPreparedKeyAgentProvisioning{profile:PreparedKeyAgentProfile,storage_root:HeldKeyAgentStorageRoot,}" &&
    compactRust(preparedKeyAgentProfileBlock) ===
      "structPreparedKeyAgentProfile{profile_sid:OwnedAppContainerSid,appcontainer_local_data:PathBuf,_not_sync:PhantomData<Cell<()>>,}" &&
    JSON.stringify(keyAgentProvisioningTypeDefinitionCounts) ===
      JSON.stringify([1, 1, 1, 1, 1]) &&
    JSON.stringify(preparedKeyAgentProvisioningTokenInventory) ===
      JSON.stringify([
        {
          path: "crates/platform-windows/src/key_agent_activation.rs",
          count: 7,
        },
        {
          path: "crates/platform-windows/src/key_agent_install_adoption.rs",
          count: 4,
        },
        {
          path: "crates/platform-windows/src/key_agent_lpac.rs",
          count: 5,
        },
        {
          path: "crates/platform-windows/src/key_agent_supervisor.rs",
          count: 4,
        },
      ]) &&
    JSON.stringify(
      preparedKeyAgentProvisioningReturningFunctions.map((entry) => ({
        path: entry.path,
        source: compactRust(entry.source),
      })),
    ) ===
      JSON.stringify([
        {
          path: "crates/platform-windows/src/key_agent_install_adoption.rs",
          source:
            "fnconsume_artifact_bound_existing_key_agent_install(bound:ArtifactBoundExistingKeyAgentInstall,_seal:KeyAgentSupervisorBindingSeal,)->(PreflightKeyAgentArtifact,PreparedKeyAgentProvisioning,VerifiedKeyAgentInstallContinuity,)",
        },
        {
          path: "crates/platform-windows/src/key_agent_lpac.rs",
          source:
            "fninto_prepared(self,_seal:ExistingInstallAdoptionSeal,)->PreparedKeyAgentProvisioning",
        },
      ]) &&
    preparedKeyAgentProvisioningImplScannerProbe.length === 1 &&
    rustStructLiteralSites(
      preparedKeyAgentProvisioningImplScannerProbe[0].source,
      "Self",
    ).length === 1 &&
    preparedKeyAgentProvisioningUnsafeImplScannerProbe.filter((item) =>
      /\bPreparedKeyAgentProvisioning\b/u.test(item.header),
    ).length === 1 &&
    preparedKeyAgentProvisioningNestedImplScannerProbe.filter((item) =>
      /\bPreparedKeyAgentProvisioning\b/u.test(item.header),
    ).length === 1 &&
    preparedKeyAgentProvisioningNestedImplScannerProbe
      .filter((item) =>
        /\bPreparedKeyAgentProvisioning\b/u.test(item.header),
      )
      .every(
        (item) => rustStructLiteralSites(item.source, "Self").length === 1,
      ) &&
    preparedKeyAgentProvisioningAliasScannerProbe.length === 1 &&
    /\bPreparedKeyAgentProvisioning\b/u.test(
      preparedKeyAgentProvisioningAliasScannerProbe[0].source,
    ) &&
    preparedKeyAgentProvisioningReturnScannerProbe.length === 1 &&
    /->[\s\S]*\bPreparedKeyAgentProvisioning\b/u.test(
      preparedKeyAgentProvisioningReturnScannerProbe[0].source,
    ) &&
    JSON.stringify(pendingKeyAgentProvisioningMethods) ===
      JSON.stringify(["provision_fresh"]) &&
    JSON.stringify(heldExistingKeyAgentInstallObjectsMethods) ===
      JSON.stringify(["revalidate", "install_observation", "into_prepared"]) &&
    JSON.stringify(heldKeyAgentInstallObservationMethods) ===
      JSON.stringify([
        "profile_sid",
        "stable_user_sid",
        "storage_profile_sid",
        "storage_root_identity",
      ]) &&
    JSON.stringify(preparedKeyAgentProvisioningMethods) ===
      JSON.stringify(["revalidate", "prepare_lpac", "storage_root_identity"]) &&
    JSON.stringify(preparedKeyAgentProvisioningConstructionSites) ===
      JSON.stringify(["crates/platform-windows/src/key_agent_lpac.rs"]) &&
    JSON.stringify(preparedKeyAgentProvisioningAliases) === JSON.stringify([]) &&
    JSON.stringify(preparedKeyAgentProvisioningImplHeaders) ===
      JSON.stringify([
        {
          path: "crates/platform-windows/src/key_agent_lpac.rs",
          header: "impl PreparedKeyAgentProvisioning",
        },
        {
          path: "crates/platform-windows/src/key_agent_lpac.rs",
          header: "impl fmt::Debug for PreparedKeyAgentProvisioning",
        },
      ]) &&
    JSON.stringify(pendingKeyAgentProvisioningImplHeaders) ===
      JSON.stringify([
        {
          path: "crates/platform-windows/src/key_agent_lpac.rs",
          header: "impl PendingKeyAgentProvisioning",
        },
        {
          path: "crates/platform-windows/src/key_agent_lpac.rs",
          header: "impl fmt::Debug for PendingKeyAgentProvisioning",
        },
      ]) &&
    JSON.stringify(keyAgentProvisioningAuthorityImplHeaders) ===
      JSON.stringify([
        {
          path: "crates/platform-windows/src/key_agent_install_adoption.rs",
          header: "impl fmt::Debug for VerifiedKeyAgentInstallContinuity",
        },
        {
          path: "crates/platform-windows/src/key_agent_install_adoption.rs",
          header: "impl fmt::Debug for ArtifactBoundExistingKeyAgentInstall",
        },
        {
          path: "crates/platform-windows/src/key_agent_install_adoption.rs",
          header: "impl fmt::Debug for VerifiedExistingKeyAgentInstall",
        },
        {
          path: "crates/platform-windows/src/key_agent_lpac.rs",
          header: "impl PendingKeyAgentProvisioning",
        },
        {
          path: "crates/platform-windows/src/key_agent_lpac.rs",
          header: "impl fmt::Debug for PendingKeyAgentProvisioning",
        },
        {
          path: "crates/platform-windows/src/key_agent_lpac.rs",
          header: "impl HeldExistingKeyAgentInstallObjects",
        },
        {
          path: "crates/platform-windows/src/key_agent_lpac.rs",
          header: "impl fmt::Debug for HeldExistingKeyAgentInstallObjects",
        },
        {
          path: "crates/platform-windows/src/key_agent_lpac.rs",
          header: "impl PreparedKeyAgentProvisioning",
        },
        {
          path: "crates/platform-windows/src/key_agent_lpac.rs",
          header: "impl fmt::Debug for PreparedKeyAgentProvisioning",
        },
        {
          path: "crates/platform-windows/src/key_agent_lpac.rs",
          header: "impl PreparedKeyAgentLpac",
        },
        {
          path: "crates/platform-windows/src/key_agent_lpac.rs",
          header: "impl fmt::Debug for PreparedKeyAgentLpac",
        },
        {
          path: "crates/platform-windows/src/key_agent_lpac.rs",
          header: "impl fmt::Debug for VerifiedKeyAgentLpac",
        },
      ]) &&
    JSON.stringify(keyAgentProvisioningAuthorityAliases) ===
      JSON.stringify([]) &&
    JSON.stringify(preparedKeyAgentProvisioningSelfConstructionSites) ===
      JSON.stringify([]) &&
    rustStructLiteralSites(
      observeHeldExistingKeyAgentInstallObjects,
      "KeyAgentHeldInstallObservation",
    ).length === 1 &&
    rustStructLiteralSites(
      keyAgentLpacRelease,
      "ExistingInstallAdoptionSeal",
    ).length === 0 &&
    revalidateHeldExistingKeyAgentInstallObjects.includes(
      "self.profile.revalidate()?",
    ) &&
    revalidateHeldExistingKeyAgentInstallObjects.includes(
      "self.storage_root",
    ) &&
    observeHeldExistingKeyAgentInstallObjects.includes(
      "self.profile.profile_sid.canonical_bytes()?",
    ) &&
    observeHeldExistingKeyAgentInstallObjects.includes(
      ".storage_root\n            .install_observation()",
    ) &&
    convertHeldExistingKeyAgentInstallObjects.includes(
      "_seal: ExistingInstallAdoptionSeal",
    ) &&
    preparedKeyAgentProvisioningImpl.includes("self.profile.revalidate()?") &&
    keyAgentFreshProvisioningOrder.every((position) => position !== -1) &&
    keyAgentFreshProvisioningOrder
      .slice(1)
      .every((position, index) => position > keyAgentFreshProvisioningOrder[index]) &&
    provisionFreshKeyAgentProfile.includes("OwnedAppContainerSid::create_fresh()?") &&
    provisionFreshKeyAgentProfile.includes("Self::from_profile_sid(profile_sid)") &&
    keyAgentProfileCreation.length === 1 &&
    keyAgentProfileCreation[0].arguments.length === 4 &&
    keyAgentProfileCreation[0].arguments[3] === "None" &&
    keyAgentProfileApiOrder.every((position) => position !== -1) &&
    keyAgentProfileApiOrder
      .slice(1)
      .every((position, index) => position > keyAgentProfileApiOrder[index]) &&
    keyAgentProfileDerivations.length === 1 &&
    JSON.stringify(keyAgentProfileDerivations[0].arguments) ===
      JSON.stringify(["&profile_api", "&name"]) &&
    keyAgentLpacDeriveUnderGuard.includes(
      "_profile_api: &AppContainerProfileApiGuard",
    ) &&
    rustCallSites(
      keyAgentLpacDeriveUnderGuard,
      "DeriveAppContainerSidFromAppContainerName",
    ).length === 1 &&
    createFreshKeyAgentProfileSid.includes(
      "require_created_sid_matches_derived(&created, &derived)?",
    ) &&
    requireCreatedKeyAgentSidMatchesDerived.includes(
      "EqualSid(created.as_psid(), derived.as_psid())",
    ) &&
    requireCreatedKeyAgentSidMatchesDerived.includes(
      ".map_err(|_| KeyAgentLpacError::Profile)",
    ) &&
    !rustLexicalCode(keyAgentLpacRelease).includes("ERROR_ALREADY_EXISTS") &&
    !rustLexicalCode(keyAgentLpacRelease).includes("fn open_or_create(") &&
    !rustLexicalCode(keyAgentLpacRelease).includes(
      "PreparedKeyAgentLpac::prepare()",
    ) &&
    !/\bfn\s+(?:new|from_\w*|provision\w*|prepare_for_\w*)\s*\(/u.test(
      preparedKeyAgentProvisioningImpl,
    ) &&
    keyAgentLpacOpenOrCreate.includes("ERROR_ALREADY_EXISTS.to_hresult()") &&
    keyAgentLpacPrepare.includes("PreparedKeyAgentProfile::open_or_create()?") &&
    launchProfileApiOrder.every((position) => position !== -1) &&
    launchProfileApiOrder
      .slice(1)
      .every((position, index) => position > launchProfileApiOrder[index]) &&
    launchProfileCreation.length === 1 &&
    launchProfileDerivations.length === 2 &&
    launchProfileDerivations.every(
      (call) =>
        JSON.stringify(call.arguments) ===
        JSON.stringify(["&profile_api", "&name_wide"]),
    ) &&
    launchProfileDeriveUnderGuard.includes(
      "_profile_api: &AppContainerProfileApiGuard",
    ) &&
    !/pub\(crate\)\s+fn\s+(?:raw|sid|profile|name|into_sid|profile_sid)\b/u.test(
      keyAgentLpacRelease.replace(heldKeyAgentInstallObservationImpl, ""),
    ) &&
    !/#\[derive\([^\]]*(?:Clone|Copy)[^\]]*\)\]\s*pub\(crate\)\s+struct\s+(?:PendingKeyAgentProvisioning|HeldExistingKeyAgentInstallObjects|KeyAgentHeldInstallObservation|PreparedKeyAgentProvisioning|PreparedKeyAgentLpac|VerifiedKeyAgentLpac)\b/u.test(
      keyAgentLpacRelease,
    ),
  "release Key Agent provisioning must quarantine fresh fixed objects as Pending, permit only the sealed dormant held-object Prepared transition, validate created-versus-derived SID equality, and expose only exact authority-free observations",
);
requireInvariant(
  keyAgentCreationAttributeBlock.includes("inherited_handles: Box<[HANDLE; 3]>") &&
    keyAgentCreationAttributeBlock.includes(
      "_inheritance: &'resources PreparedKeyAgentInheritance<'pipes, 'flight>",
    ) &&
    keyAgentCreationAttributeBlock.includes(
      "root_job_attribute: &'resources KeyAgentRootJobAttribute<'job>",
    ) &&
    keyAgentCreationAttributeBlock.includes("lpac: &'resources PreparedKeyAgentLpac") &&
    keyAgentAttributeListInitializations.length === 2 &&
    keyAgentAttributeListInitializations.every(
      (call) => call.arguments.length === 4 && call.arguments[1] === "4",
    ) &&
    keyAgentAttributeListInitializations[0].arguments[0] === "None" &&
    keyAgentAttributeListInitializations[1].arguments[0] === "Some(pointer)" &&
    keyAgentCreationAttributeImpl.includes(
      "usize::try_from(PROC_THREAD_ATTRIBUTE_HANDLE_LIST)",
    ) &&
    (keyAgentCreationAttributeImpl.match(/\bUpdateProcThreadAttribute\s*\(/gu) ?? [])
      .length === 1 &&
    keyAgentCreationAttributeOrder.every((position) => position !== -1) &&
    keyAgentCreationAttributeOrder
      .slice(1)
      .every(
        (position, index) => position > keyAgentCreationAttributeOrder[index],
      ) &&
    keyAgentLpacAttributeUpdates.length === 2 &&
    JSON.stringify(
      keyAgentLpacAttributeUpdates.map((call) => call.arguments[1]),
    ) ===
      JSON.stringify([
        "PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES",
        "PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY",
      ]) &&
    keyAgentLpacAttributeUpdates[0].arguments[3] ===
      "size_of::<SECURITY_CAPABILITIES>()" &&
    keyAgentLpacAttributeUpdates[1].arguments[3] === "size_of::<u32>()" &&
    /const\s+CAPABILITY_COUNT:\s*u32\s*=\s*0\s*;/u.test(keyAgentLpacRelease) &&
    keyAgentLpacAttributeValues.includes("AppContainerSid: profile_sid.as_psid()") &&
    keyAgentLpacAttributeValues.includes("Capabilities: ptr::null_mut()") &&
    keyAgentLpacAttributeValues.includes("CapabilityCount: CAPABILITY_COUNT") &&
    keyAgentLpacAttributeValues.includes("Reserved: 0") &&
    keyAgentLpacAttributeValues.includes(
      "all_application_packages_policy: PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT",
    ) &&
    !/\b(?:PROC_THREAD_ATTRIBUTE_)?CHILD_PROCESS_POLICY\b/u.test(
      `${keyAgentActivationRelease}\n${keyAgentLpacRelease}`,
    ) &&
    keyAgentActivation.includes(
      "impl Drop for KeyAgentCreationAttributes<'_, '_, '_, '_>",
    ) &&
    keyAgentActivation.includes("DeleteProcThreadAttributeList(self.pointer)") &&
    keyAgentCreateProcess.includes("let mut startup = STARTUPINFOEXW::default();") &&
    keyAgentCreateProcess.includes("startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;") &&
    keyAgentCreateProcess.includes("startup.StartupInfo.hStdInput = attributes.stdin();") &&
    keyAgentCreateProcess.includes("startup.StartupInfo.hStdOutput = attributes.stdout();") &&
    keyAgentCreateProcess.includes("startup.StartupInfo.hStdError = attributes.stderr();") &&
    keyAgentCreateProcess.includes("startup.lpAttributeList = attributes.pointer();") &&
    keyAgentCreateProcess.indexOf(".recheck_supervisor_context()") !== -1 &&
    keyAgentCreateProcess.indexOf(".recheck_supervisor_context()") <
      keyAgentCreateProcess.indexOf(
        ".create_process_with_explicit_handle_list(",
      ) &&
    keyAgentCreateProcess.includes(
      "flight: &InheritableHandleLaunchFlight<'_>",
    ) &&
    keyAgentCreateProcess.includes("key_agent_creation_flags()") &&
    normalizeRustFragment(rustLexicalCode(keyAgentCreationFlags)) ===
      "fn key_agent_creation_flags() -> windows::Win32::System::Threading::PROCESS_CREATION_FLAGS { CREATE_SUSPENDED | DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT }" &&
    normalizeRustFragment(rustLexicalCode(keyAgentCreationFlagsTest)).includes(
      "let expected = (CREATE_SUSPENDED | DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT) .0; assert_eq!(sys::key_agent_creation_flag_bits_for_test(), expected);",
    ) &&
    verifyBoundRootProcess.includes(".recheck_supervisor_context()") &&
    verifyBoundRootProcess.includes(".contains_process(process)") &&
    verifyBoundRootProcess.includes("active_processes == 1"),
  "dormant Key Agent creation must atomically bind three stdio handles, one root Job, and the exact zero-capability LPAC attributes without descendant policy",
);
const compactPrepareKeyAgentProcess = compactRust(prepareKeyAgentProcessRelease);
const keyAgentProcessPreparationOrder = [
  "RestrictedProcessContext::prepare()",
  "provisioning.revalidate()",
  "provisioning.prepare_lpac()",
  ".environment_with_local_app_data(context.environment())",
  "artifact.path()",
  "Ok(PreparedKeyAgentProcess{",
].map((marker) => compactPrepareKeyAgentProcess.indexOf(marker));
const compactKeyAgentLpacEnvironment = compactRust(keyAgentLpacEnvironment);
requireInvariant(
  keyAgentProcessPreparationOrder.every((position) => position !== -1) &&
    keyAgentProcessPreparationOrder
      .slice(1)
      .every(
        (position, index) => position > keyAgentProcessPreparationOrder[index],
      ) &&
    /struct\s+PreparedKeyAgentProcess\s*\{[\s\S]*?context:\s*RestrictedProcessContext,[\s\S]*?environment:\s*Box<\[u16\]>,[\s\S]*?lpac:\s*PreparedKeyAgentLpac,/u.test(
      keyAgentActivationRelease,
    ) &&
    compactKeyAgentLpacEnvironment.includes(
      "letappcontainer_local_data=&self.appcontainer_local_data;",
    ) &&
    prepareKeyAgentProfileFromSid.includes(
      "validated_appcontainer_folder(&profile_sid)?",
    ) &&
    keyAgentLpacAttributeValues.includes(
      "appcontainer_local_data: profile.appcontainer_local_data.clone()",
    ) &&
    validateKeyAgentAppContainerFolder.includes(
      "appcontainer_folder(profile_sid)?",
    ) &&
    validateKeyAgentAppContainerFolder.includes(
      '!local_folder_name.eq_ignore_ascii_case("AC")',
    ) &&
    keyAgentLpacEnvironment.includes(
      '!local_folder_name.eq_ignore_ascii_case("AC")',
    ) &&
    compactKeyAgentLpacEnvironment.includes(
      "!profile_name.eq_ignore_ascii_case(KEY_AGENT_PROFILE_V1_NAME)",
    ) &&
    keyAgentLpacEnvironment.includes(
      '!packages_name.eq_ignore_ascii_case("Packages")',
    ) &&
    compactKeyAgentLpacEnvironment.includes(
      "!appcontainer_local_data.is_absolute()",
    ) &&
    compactKeyAgentLpacEnvironment.includes("!packages_parent.is_absolute()") &&
    compactKeyAgentLpacEnvironment.includes(
      "!base_environment_is_exact(base_environment)",
    ) &&
    (keyAgentLpacEnvironment.match(/"LOCALAPPDATA="/gu) ?? []).length === 2 &&
    keyAgentLpacEnvironment.includes(
      'environment.extend("LOCALAPPDATA=".encode_utf16());',
    ) &&
    compactKeyAgentLpacEnvironment.includes(
      "environment.extend_from_slice(&local_value);environment.push(0);environment.extend_from_slice(base_environment);",
    ) &&
    keyAgentLpacEnvironment.includes(
      "let local_value: Vec<u16> = packages_parent.as_os_str().encode_wide().collect();",
    ) &&
    compactKeyAgentLpacEnvironment.includes(
      "environment.len()>32_767||!environment.ends_with(&[0,0])",
    ) &&
    keyAgentAppContainerFolder.includes("GetAppContainerFolderPath") &&
    keyAgentAppContainerFolder.includes("CoTaskMemFree") &&
    exactKeyAgentBaseEnvironment.includes("environment.ends_with(&[0, 0])") &&
    exactKeyAgentBaseEnvironment.includes('"SystemRoot=".encode_utf16()') &&
    exactKeyAgentBaseEnvironment.includes('"WINDIR=".encode_utf16()') &&
    exactKeyAgentBaseEnvironment.includes("entries.next().is_none()") &&
    exactKeyAgentEnvironmentTest.includes(
      "appcontainer_folder(&prepared.profile_sid)?",
    ) &&
    exactKeyAgentEnvironmentTest.includes(
      "assert!(entries[0] == exact_local_app_data);",
    ) &&
    !/\b(?:std::env|env)::(?:var|var_os|vars|vars_os)\s*\(/u.test(
      `${keyAgentActivationRelease}\n${keyAgentLpacRelease}`,
    ) &&
    !/\b(?:GetEnvironmentVariable|GetEnvironmentStrings|CreateEnvironmentBlock)\w*\b/u.test(
      `${keyAgentActivationRelease}\n${keyAgentLpacRelease}`,
    ) &&
    keyAgentCreateProcess.includes(
      "Some(prepared_process.environment.as_ptr().cast::<c_void>())",
    ),
  "Key Agent creation must use the OS-derived user local-data base that Windows rebases to the exact AppContainer AC path as LOCALAPPDATA, plus validated SystemRoot/WINDIR with no ambient inheritance",
);
const compactVerifyKeyAgentLpacToken = compactRust(verifyKeyAgentLpacToken);
const keyAgentLpacTokenQueryOrder = [
  "OpenProcessToken(",
  "token_dword(token.0,TokenIsAppContainer)?",
  "less_privileged_appcontainer_dword(token.0)?",
  "token_information(token.0,TokenAppContainerSid)?",
  "EqualSid(container.TokenAppContainer,expected_sid)",
  "token_information(token.0,TokenCapabilities)?",
  "appcontainer_membership_evidence(token.0)?",
  "validate_token_policy(&evidence)",
].map((marker) => compactVerifyKeyAgentLpacToken.indexOf(marker));
const compactOptionalKeyAgentLpacDword = compactRust(
  queryOptionalKeyAgentLpacDword,
);
const compactKeyAgentLpacMembershipEvidence = compactRust(
  queryKeyAgentLpacMembershipEvidence,
);
const keyAgentMembershipChecks = rustCallSites(
  checkKeyAgentTokenMembership,
  "CheckTokenMembershipEx",
);
const keyAgentMembershipEvidenceCalls = rustCallSites(
  queryKeyAgentLpacMembershipEvidence,
  "check_token_membership",
);
const compactKeyAgentTokenValidation = compactRust(validateKeyAgentLpacToken);
requireInvariant(
  /pub\(crate\)\s+fn\s+verify_suspended_process\(\s*self,\s*process:\s*BorrowedHandle<'_>/u.test(
    keyAgentLpacVerifySuspended,
  ) &&
    keyAgentLpacVerifySuspended.includes(
      "verify_process_token(process, self.profile_sid.as_psid())?",
    ) &&
    keyAgentLpacVerifySuspended.includes("Ok(VerifiedKeyAgentLpac { _private: () })") &&
    /pub\(crate\)\s+struct\s+VerifiedKeyAgentLpac\s*\{\s*_private:\s*\(\),\s*\}/su.test(
      keyAgentLpacRelease,
    ) &&
    keyAgentLpacTokenQueryOrder.every((position) => position !== -1) &&
    keyAgentLpacTokenQueryOrder
      .slice(1)
      .every(
        (position, index) => position > keyAgentLpacTokenQueryOrder[index],
    ) &&
    compactVerifyKeyAgentLpacToken.includes(
      "OpenProcessToken(HANDLE(process.as_raw_handle()),TOKEN_QUERY|TOKEN_DUPLICATE,&rawmutraw_token,)",
    ) &&
    queryKeyAgentLpacDword.includes("GetTokenInformation") &&
    queryKeyAgentLpacDword.includes("size_of::<u32>()") &&
    compactOptionalKeyAgentLpacDword.includes(
      "TokenIsLessPrivilegedAppContainer",
    ) &&
    compactOptionalKeyAgentLpacDword.includes(
      "Err(error)iferror.code()==ERROR_INVALID_PARAMETER.to_hresult()=>Ok(None)",
    ) &&
    (compactOptionalKeyAgentLpacDword.match(/=>Ok\(None\)/gu) ?? []).length ===
      1 &&
    compactOptionalKeyAgentLpacDword.includes(
      "Err(_)=>Err(KeyAgentLpacError::Token)",
    ) &&
    compactKeyAgentLpacMembershipEvidence.includes(
      "token_information(token,TokenUser)?",
    ) &&
    compactKeyAgentLpacMembershipEvidence.includes(
      "IsValidSid(user.User.Sid)",
    ) &&
    compactKeyAgentLpacMembershipEvidence.includes(
      "DuplicateToken(token,SecurityIdentification,&rawmutraw_impersonation_token,)",
    ) &&
    compactKeyAgentLpacMembershipEvidence.includes(
      "letimpersonation_token=OwnedToken::new(raw_impersonation_token)?;",
    ) &&
    normalizeRustFragment(
      rustLexicalCode(keyAgentLpacMembershipEvidenceDefinition),
    ) ===
      "enum AppContainerMembershipEvidence { Lpac, RegularAppContainer, Neither, Inverted, }" &&
    keyAgentMembershipEvidenceCalls.length === 2 &&
    (rustLexicalCode(keyAgentLpacRelease).match(
      /\bcheck_token_membership\s*\(/gu,
    ) ?? []).length === 3 &&
    JSON.stringify(
      keyAgentMembershipEvidenceCalls.map((call) => call.arguments),
    ) ===
      JSON.stringify([
        [
          "impersonation_token.0",
          "user.User.Sid",
          "CTMF_INCLUDE_APPCONTAINER",
        ],
        [
          "impersonation_token.0",
          "user.User.Sid",
          "CTMF_INCLUDE_APPCONTAINER | CTMF_INCLUDE_LPAC",
        ],
      ]) &&
    compactKeyAgentLpacMembershipEvidence.includes(
      "Ok(match(passes_appcontainer,passes_lpac){(false,true)=>AppContainerMembershipEvidence::Lpac,(true,true)=>AppContainerMembershipEvidence::RegularAppContainer,(false,false)=>AppContainerMembershipEvidence::Neither,(true,false)=>AppContainerMembershipEvidence::Inverted,})",
    ) &&
    keyAgentMembershipChecks.length === 1 &&
    JSON.stringify(keyAgentMembershipChecks[0].arguments) ===
      JSON.stringify([
        "Some(impersonation_token)",
        "sid",
        "flags",
        "&raw mut is_member",
      ]) &&
    (keyAgentLpacRelease.match(/\bCheckTokenMembershipEx\s*\(/gu) ?? [])
      .length === 1 &&
    !/\bToken(?:Groups|RestrictedSids)\b/u.test(keyAgentLpacRelease) &&
    queryKeyAgentTokenInformation.includes("MAX_TOKEN_INFORMATION_BYTES") &&
    queryKeyAgentTokenInformation.includes("checked_add(word_size - 1)") &&
    queryKeyAgentTokenInformation.includes("returned_bytes > required") &&
    compactKeyAgentTokenValidation.includes("evidence.is_lpac.as_ref()") &&
    compactKeyAgentTokenValidation.includes(
      "Some(is_lpac)=>is_lpac.value==1&&is_lpac.returned_bytes==size_of::<u32>()",
    ) &&
    compactKeyAgentTokenValidation.includes("None=>true") &&
    compactKeyAgentTokenValidation.includes("evidence.is_appcontainer.value!=1") &&
    compactKeyAgentTokenValidation.includes(
      "evidence.is_appcontainer.returned_bytes!=size_of::<u32>()",
    ) &&
    compactKeyAgentTokenValidation.includes(
      "evidence.membership!=AppContainerMembershipEvidence::Lpac",
    ) &&
    compactKeyAgentTokenValidation.includes("!evidence.appcontainer_sid_valid") &&
    compactKeyAgentTokenValidation.includes("!evidence.appcontainer_sid_matches") &&
    compactKeyAgentTokenValidation.includes(
      "evidence.capability_count!=CAPABILITY_COUNT",
    ),
  "the suspended Key Agent token must prove the fixed AppContainer SID, zero capabilities, and the exact AppContainer-versus-LPAC membership differential while allowing only the documented invalid-parameter query fallback",
);
const regularAppContainerAttributeList = rustFunctionBlock(
  keyAgentLpacSource,
  "regular_appcontainer_attribute_list",
);
const regularAppContainerAttributeInitializations = rustCallSites(
  regularAppContainerAttributeList,
  "InitializeProcThreadAttributeList",
);
const createSuspendedRegularAppContainer = rustFunctionBlock(
  keyAgentLpacSource,
  "create_suspended_regular_appcontainer",
);
const regularAppContainerCreateCalls = rustCallSites(
  createSuspendedRegularAppContainer,
  "CreateProcessW",
);
const regularAppContainerNegativeControl = rustFunctionBlock(
  keyAgentLpacSource,
  "regular_appcontainer_negative_control_passes_both_membership_paths",
);
const tokenPolicyNegativeControl = rustFunctionBlock(
  keyAgentLpacSource,
  "token_policy_rejects_each_single_invariant_break",
);
const testSuspendedProcessDrop = rustLexicalItemBlock(
  keyAgentLpacSource,
  /impl\s+Drop\s+for\s+TestSuspendedProcess\s*\{/u,
);
const terminateAndWaitTestSuspendedProcess = rustFunctionBlock(
  keyAgentLpacSource,
  "terminate_and_wait",
);
const compactTestSuspendedProcessDrop = compactRust(testSuspendedProcessDrop);
const regularAppContainerCleanupOrder = [
  "TerminateProcess(self.process,0xE0A0_0002)",
  "WaitForSingleObject(self.process,5_000)",
  "CloseHandle(self.process)",
  "CloseHandle(self.thread)",
].map((marker) => compactTestSuspendedProcessDrop.indexOf(marker));
const compactTerminateAndWaitTestSuspendedProcess = compactRust(
  terminateAndWaitTestSuspendedProcess,
);
const regularAppContainerExplicitCleanupOrder = [
  "TerminateProcess(self.process,0xE0A0_0002)",
  "WaitForSingleObject(self.process,5_000)",
  "CloseHandle(self.thread)",
  "CloseHandle(self.process)",
  "self.thread=HANDLE::default()",
  "self.process=HANDLE::default()",
].map((marker) => compactTerminateAndWaitTestSuspendedProcess.indexOf(marker));
requireInvariant(
  !keyAgentLpacRelease.includes("regular_appcontainer") &&
    regularAppContainerAttributeInitializations.length === 2 &&
    regularAppContainerAttributeInitializations.every(
      (call) => call.arguments.length === 4 && call.arguments[1] === "1",
    ) &&
    regularAppContainerAttributeList.includes(
      "PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES",
    ) &&
    !rustLexicalCode(regularAppContainerAttributeList).includes(
      "PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY",
    ) &&
    (regularAppContainerAttributeList.match(
      /\bUpdateProcThreadAttribute\s*\(/gu,
    ) ?? []).length === 1 &&
    regularAppContainerCreateCalls.length === 1 &&
    regularAppContainerCreateCalls[0].arguments.length === 10 &&
    regularAppContainerCreateCalls[0].arguments[1] === "None" &&
    regularAppContainerCreateCalls[0].arguments[4] === "false" &&
    compactRust(regularAppContainerCreateCalls[0].arguments[5]) ===
      "CREATE_SUSPENDED|CREATE_NO_WINDOW|CREATE_UNICODE_ENVIRONMENT|EXTENDED_STARTUPINFO_PRESENT" &&
    compactRust(regularAppContainerCreateCalls[0].arguments[6]) ===
      "Some(environment.as_ptr().cast::<c_void>())" &&
    compactRust(regularAppContainerCreateCalls[0].arguments[7]) ===
      "PCWSTR(context.current_directory().as_ptr())" &&
    !/\b(?:ResumeThread|ContinueDebugEvent|DebugActiveProcessStop)\b/u.test(
      rustLexicalCode(
        `${createSuspendedRegularAppContainer}\n${regularAppContainerNegativeControl}\n${testSuspendedProcessDrop}`,
      ),
    ) &&
    regularAppContainerNegativeControl.includes(
      "create_suspended_regular_appcontainer(&prepared, &fixture)?",
    ) &&
    regularAppContainerNegativeControl.includes(
      "appcontainer_membership_evidence(token.0)?",
    ) &&
    regularAppContainerNegativeControl.includes(
      "AppContainerMembershipEvidence::RegularAppContainer",
    ) &&
    regularAppContainerNegativeControl.includes("process.terminate_and_wait()?") &&
    regularAppContainerNegativeControl.indexOf("process.terminate_and_wait()?") <
      regularAppContainerNegativeControl.indexOf("Ok(())") &&
    tokenPolicyNegativeControl.includes(
      "membership: AppContainerMembershipEvidence::RegularAppContainer",
    ) &&
    tokenPolicyNegativeControl.includes(
      "membership: AppContainerMembershipEvidence::Neither",
    ) &&
    tokenPolicyNegativeControl.includes(
      "membership: AppContainerMembershipEvidence::Inverted",
    ) &&
    tokenPolicyNegativeControl.includes("validate_token_policy(&evidence)") &&
    tokenPolicyNegativeControl.includes("Err(KeyAgentLpacError::Token)") &&
    regularAppContainerCleanupOrder.every((position) => position !== -1) &&
    regularAppContainerCleanupOrder
      .slice(1)
      .every(
        (position, index) => position > regularAppContainerCleanupOrder[index],
      ) &&
    regularAppContainerExplicitCleanupOrder.every(
      (position) => position !== -1,
    ) &&
    regularAppContainerExplicitCleanupOrder
      .slice(1)
      .every(
        (position, index) =>
          position > regularAppContainerExplicitCleanupOrder[index],
      ) &&
    compactTerminateAndWaitTestSuspendedProcess.includes(
      "WaitForSingleObject(self.process,5_000)}!=WAIT_OBJECT_0",
    ),
  "the cfg(test) regular-AppContainer negative control must omit only AAP opt-out, prove APP=true and APP|LPAC=true, never resume, and terminate/wait/close its suspended child",
);
const suspendedDebuggeeBlock = rustLexicalItemBlock(
  keyAgentActivation,
  /pub\(super\)\s+struct\s+SuspendedDebuggee\s*\{/u,
);
const suspendedDebuggeeImpl = rustLexicalItemBlock(
  keyAgentActivation,
  /impl\s+SuspendedDebuggee\s*\{/u,
);
const authenticateKeyAgentFirstEvent = rustFunctionBlock(
  suspendedDebuggeeImpl,
  "authenticate_first_event",
);
const detachKeyAgentStillSuspended = rustFunctionBlock(
  suspendedDebuggeeImpl,
  "detach_still_suspended",
);
const keyAgentDetachedSuspensionProof = rustFunctionBlock(
  suspendedDebuggeeImpl,
  "is_detached_and_suspended",
);
const compactAuthenticateKeyAgentFirstEvent = compactRust(
  authenticateKeyAgentFirstEvent,
);
const keyAgentLpacAuthenticationOrder = [
  "letmapped_identity=exact_file_identity(event_file.raw())?;",
  "ifmapped_identity!=expected_artifact",
  "drop(event_file);",
  "letcreation_time=process_creation_time(self.process.raw())?;",
  "letprevious_suspend_count=unsafe{SuspendThread(self.primary_thread.raw())};",
  "ifprevious_suspend_count!=0",
  "self.proven_suspend_count=1;",
  "self.prepared_lpac.take()",
  ".verify_suspended_process(self.process_handle())",
  "self.lpac=Some(verified_lpac);",
  "Ok(AuthenticatedFirstEvent{creation_time})",
].map((marker) => compactAuthenticateKeyAgentFirstEvent.indexOf(marker));
requireInvariant(
  suspendedDebuggeeBlock.includes(
    "prepared_lpac: Option<PreparedKeyAgentLpac>",
  ) &&
    suspendedDebuggeeBlock.includes("lpac: Option<VerifiedKeyAgentLpac>") &&
    keyAgentLpacAuthenticationOrder.every((position) => position !== -1) &&
    keyAgentLpacAuthenticationOrder
      .slice(1)
      .every(
        (position, index) => position > keyAgentLpacAuthenticationOrder[index],
      ) &&
    authenticateKeyAgentFirstEvent.includes("self.prepared_lpac.is_none()") &&
    authenticateKeyAgentFirstEvent.includes("self.lpac.is_some()") &&
    !rustLexicalCode(authenticateKeyAgentFirstEvent).includes(
      "ContinueDebugEvent",
    ) &&
    detachKeyAgentStillSuspended.includes("self.proven_suspend_count != 1") &&
    detachKeyAgentStillSuspended.includes("self.prepared_lpac.is_some()") &&
    detachKeyAgentStillSuspended.includes("self.lpac.is_none()") &&
    detachKeyAgentStillSuspended.indexOf("self.lpac.is_none()") <
      detachKeyAgentStillSuspended.indexOf("ContinueDebugEvent") &&
    keyAgentDetachedSuspensionProof.includes(
      "self.phase == LaunchPhase::DetachedSuspended",
    ) &&
    keyAgentDetachedSuspensionProof.includes("self.proven_suspend_count == 1") &&
    keyAgentDetachedSuspensionProof.includes("self.prepared_lpac.is_none()") &&
    keyAgentDetachedSuspensionProof.includes("self.lpac.is_some()"),
  "mapped-image authentication and an explicit suspend count must precede LPAC token proof, debug continuation, detachment, and detached type-state export",
);
const keyAgentLpacFixtureCreate = rustFunctionBlock(keyAgentLpac, "create");
const keyAgentLpacFixtureDrop = rustLexicalItemBlock(
  keyAgentLpac,
  /impl\s+Drop\s+for\s+KeyAgentLpacKernelTestFixture\s*\{/u,
);
const keyAgentLpacFixtureDebug = rustLexicalItemBlock(
  keyAgentLpac,
  /impl\s+fmt::Debug\s+for\s+KeyAgentLpacKernelTestFixture\s*\{/u,
);
const applyExactKeyAgentFixtureDacl = rustFunctionBlock(
  keyAgentLpac,
  "apply_exact_fixture_dacl",
);
const createUniqueKeyAgentFixtureDirectory = rustFunctionBlock(
  keyAgentLpac,
  "create_unique_fixture_directory",
);
const copyCurrentKeyAgentTestImage = rustFunctionBlock(
  keyAgentLpac,
  "copy_current_test_image",
);
const keyAgentActivationTestArtifact = rustFunctionBlock(
  activationHelper,
  "for_key_agent_activation_test",
);
const compactKeyAgentLpacFixtureCreate = compactRust(
  keyAgentLpacFixtureCreate,
);
const keyAgentFixtureCreationOrder = [
  "OwnedAppContainerSid::open_or_create()?",
  "appcontainer_folder(&profile_sid)?",
  "create_unique_fixture_directory(&profile_folder)?",
  "letexecutable=directory.join(",
  "apply_exact_fixture_dacl(&directory,profile_sid.as_psid())",
  "copy_current_test_image(&executable)",
  "apply_exact_fixture_dacl(&executable,profile_sid.as_psid())",
  "Ok(Self{directory,executable,})",
].map((marker) => compactKeyAgentLpacFixtureCreate.indexOf(marker));
requireInvariant(
  /#\[cfg\(test\)\]\s*pub\(crate\)\s+struct\s+KeyAgentLpacKernelTestFixture\s*\{/u.test(
    keyAgentLpac,
  ) &&
    !keyAgentLpacRelease.includes("KeyAgentLpacKernelTestFixture") &&
    !keyAgentLpacRelease.includes("SetFileSecurityW") &&
    !keyAgentLpacRelease.includes("std::env::current_exe") &&
    keyAgentFixtureCreationOrder.every((position) => position !== -1) &&
    keyAgentFixtureCreationOrder
      .slice(1)
      .every(
        (position, index) => position > keyAgentFixtureCreationOrder[index],
      ) &&
    keyAgentLpacFixtureCreate.includes(
      'directory.join("key-agent-kernel-test.exe")',
    ) &&
    compactKeyAgentLpacFixtureCreate.includes("!profile_folder.is_absolute()") &&
    compactKeyAgentLpacFixtureCreate.includes("!profile_folder.is_dir()") &&
    createUniqueKeyAgentFixtureDirectory.includes("getrandom::fill(&mut random)") &&
    createUniqueKeyAgentFixtureDirectory.includes("std::fs::create_dir(&candidate)") &&
    !createUniqueKeyAgentFixtureDirectory.includes("create_dir_all") &&
    copyCurrentKeyAgentTestImage.includes("std::env::current_exe()") &&
    copyCurrentKeyAgentTestImage.includes(".create_new(true)") &&
    copyCurrentKeyAgentTestImage.includes("destination_file.sync_all()") &&
    applyExactKeyAgentFixtureDacl.includes(
      'format!("D:P(A;;FA;;;{user_sid})(A;;GRGX;;;{profile_sid})")',
    ) &&
    applyExactKeyAgentFixtureDacl.includes(
      "DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION",
    ) &&
    applyExactKeyAgentFixtureDacl.includes("SetFileSecurityW") &&
    keyAgentLpacFixtureDrop.includes("remove_file(&self.executable)") &&
    keyAgentLpacFixtureDrop.includes("remove_dir(&self.directory)") &&
    !keyAgentLpacFixtureDrop.includes("remove_dir_all") &&
    keyAgentLpacFixtureDebug.includes(
      'formatter.write_str("KeyAgentLpacKernelTestFixture([REDACTED PATH])")',
    ) &&
    /#\[cfg\(all\(test,\s*windows\)\)\]\s*pub\(crate\)\s+fn\s+for_key_agent_activation_test/u.test(
      activationHelper,
    ) &&
    keyAgentActivationTestArtifact.includes(
      "KeyAgentLpacKernelTestFixture::create()",
    ) &&
    keyAgentActivationTestArtifact.includes("fixture.path().to_path_buf()") &&
    keyAgentActivationTestArtifact.includes(".share_mode(FILE_SHARE_READ.0)") &&
    keyAgentActivationTestArtifact.includes("_key_agent_lpac_fixture: Some(fixture)"),
  "the Key Agent LPAC launchability fixture must remain test-only, profile-folder confined, CSPRNG-unique, exact-ACL protected, pinned, redacted, and non-recursively cleaned up",
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
        "resume_for_storage_startup",
        "duplicate_process_observation",
        "is_member_of_root_job_for_test",
      ]) &&
    /#\[cfg\(test\)\]\s*pub\(super\)\s+fn\s+duplicate_process_observation/u.test(
      detachedImpl,
    ) &&
    /#\[cfg\(test\)\]\s*pub\(super\)\s+fn\s+is_member_of_root_job_for_test/u.test(
      detachedImpl,
    ) &&
    !/impl\s+(?:core::ops::)?(?:Deref|DerefMut|AsRawHandle)\s+for\s+DetachedSuspendedDebuggee/u.test(
      keyAgentActivation,
    ) &&
    /fn\s+resume_for_storage_startup\s*\(\s*mut\s+self,?\s*\)\s*->\s*Result<\s*DetachedRunningDebuggee\s*,\s*KeyAgentActivationError\s*>/u.test(
      rustLexicalCode(detachedImpl),
    ) &&
    !/fn\s+(?:into_inner|as_raw_handle|continue|detach|resume)\b/u.test(
      detachedImpl,
    ),
  "only the proven detached suspended type-state may cross the fresh worker boundary and consume itself into the fixed storage-startup running proof",
);
const detachedRunningImplStart = keyAgentActivation.indexOf(
  "impl DetachedRunningDebuggee {",
);
const detachedRunningImplEnd = keyAgentActivation.indexOf(
  "impl fmt::Debug for DetachedRunningDebuggee",
);
const detachedRunningImpl = keyAgentActivation.slice(
  detachedRunningImplStart,
  detachedRunningImplEnd,
);
const detachedRunningMethods = [...detachedRunningImpl.matchAll(
  /pub\(super\)\s+(?:const\s+)?fn\s+(\w+)/gu,
)].map((match) => match[1]);
requireInvariant(
  keyAgentActivation.includes(
    "pub(super) struct DetachedRunningDebuggee(SuspendedDebuggee);",
  ) &&
    keyAgentActivation.includes("unsafe impl Send for DetachedRunningDebuggee {}") &&
    !/unsafe\s+impl\s+Sync\s+for\s+DetachedRunningDebuggee\b/u.test(
      keyAgentActivation,
    ) &&
    !/#\[derive\([^\]]*(?:Clone|Copy)[^\]]*\)\]\s*(?:pub\(super\)\s+)?struct\s+DetachedRunningDebuggee/u.test(
      keyAgentActivation,
    ) &&
    JSON.stringify(detachedRunningMethods) ===
      JSON.stringify([
        "process_id",
        "is_detached_and_running",
        "duplicate_process_observation",
        "is_member_of_root_job_for_test",
      ]) &&
    !/impl\s+(?:core::ops::)?(?:Deref|DerefMut|AsRawHandle)\s+for\s+DetachedRunningDebuggee/u.test(
      keyAgentActivation,
    ) &&
    !/fn\s+(?:into_inner|as_raw_handle|resume|continue|detach|start|write|read)\b/u.test(
      detachedRunningImpl,
    ) &&
    keyAgentActivation.includes(
      'formatter.write_str("DetachedRunningDebuggee([REDACTED HANDLES AND IDENTITY])")',
    ),
  "the detached-running Key Agent type-state must remain a non-cloneable, non-Sync, observation-only proof with no second transition or operational I/O",
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
const keyAgentBoundaryDocumentation = [
  rootReadme,
  activationArchitecture,
  activationReadme,
  securityDecisions,
  keyAgentProtocolDocumentation,
].join("\n");
requireInvariant(
    activationArchitecture.includes("### Key Agent activation invariant (STOP-SHIP)") &&
    /fresh\s+dedicated OS thread/u.test(activationArchitecture) &&
    /all-zero[\s\S]{0,100}all-`FF`/u.test(activationArchitecture) &&
    activationArchitecture.includes("YourWallet.KeyAgent.LPAC.v1") &&
    /\bfour-slot\s+`STARTUPINFOEXW` attribute list/u.test(
      activationArchitecture,
    ) &&
    activationArchitecture.includes("`SECURITY_CAPABILITIES`") &&
    activationArchitecture.includes("`ALL_APPLICATION_PACKAGES_POLICY`") &&
    activationArchitecture.includes("`GetAppContainerFolderPath`") &&
    activationArchitecture.includes("Do not add `registryRead`") &&
    /fresh dedicated\s+debugger OS thread/u.test(activationReadme) &&
    activationReadme.includes("all-zero and all-`FF`") &&
    /no raw handle or\s+generic resume API/u.test(activationReadme) &&
    activationReadme.includes(
      "its only consuming resume transition is the fixed",
    ) &&
    activationReadme.includes("YourWallet.KeyAgent.LPAC.v1") &&
    activationReadme.includes("SECURITY_CAPABILITIES") &&
    activationReadme.includes("ALL_APPLICATION_PACKAGES") &&
    activationReadme.includes("Do not add") &&
    activationReadme.includes("`registryRead`") &&
    activationArchitecture.includes("**STOP-SHIP (English):**") &&
    activationArchitecture.includes("**릴리스 차단 조건 (한국어):**") &&
    activationArchitecture.includes("deadline-bound process-wide coordinator") &&
    activationArchitecture.includes("one loaded crate instance") &&
    activationArchitecture.includes("separate matching static lock") &&
    activationArchitecture.includes("supervisor is single-instance") &&
    activationArchitecture.includes("receives inheritable stdio handles") &&
    activationReadme.includes("**Implemented Rust coordination boundary:**") &&
    activationReadme.includes("**Scope and remaining STOP-SHIP conditions:**") &&
    activationReadme.includes("**구현 범위와 남은 릴리스 차단 조건:**") &&
    activationReadme.includes("one loaded `platform-windows` crate") &&
    activationReadme.includes("`std::process::Command`") &&
    activationReadme.includes("separate matching static lock") &&
    activationReadme.includes("single-instance/process topology") &&
    activationReadme.includes("clear the inherit bit") &&
    keyAgentBoundaryDocumentation.includes("CheckTokenMembershipEx") &&
    keyAgentBoundaryDocumentation.includes("(false, true)") &&
    keyAgentBoundaryDocumentation.includes("(true, true)") &&
    !/\bToken(?:Groups|RestrictedSids)\b/u.test(keyAgentBoundaryDocumentation) &&
    !/Keep zero-capability Key Agent LPAC activation and profile provisioning\s+\*\*STOP-SHIP\*\* until a distinct Key Agent profile is provisioned/iu.test(
      keyAgentBoundaryDocumentation,
    ) &&
    activationArchitecture.includes("YourWallet.KeyAgent.Storage.v1") &&
    activationArchitecture.includes(
      "The private fresh-provisioning selector has no caller input.",
    ) &&
    /but returns only a\s+non-launchable pending capability/u.test(
      activationArchitecture,
    ) &&
    /Activation accepts a\s+separate prepared capability, and no direct pending\/candidate\s+conversion exists/u.test(
      activationArchitecture,
    ) &&
    activationArchitecture.includes(
      "The sole production-compiled mint is the private sealed existing-install",
    ) &&
    activationArchitecture.includes("VerifiedExistingKeyAgentInstall") &&
    /activation에 넣을 수\s+없는 `Pending` capability만 반환/u.test(rootReadme) &&
    rootReadme.includes("pending/candidate의 직접 conversion") &&
    rootReadme.includes("production에 컴파일되는 `PreparedKeyAgentProvisioning` mint는 정확히 하나") &&
    securityDecisions.includes(
      "returns only a non-launchable pending capability",
    ) &&
    [
      rootReadme,
      activationArchitecture,
      activationReadme,
      securityDecisions,
      keyAgentProtocolDocumentation,
    ].every(
      (document) =>
        document.includes("HMAC-SHA256") &&
        /predecessor\s+commitments?/iu.test(document),
    ) &&
    !/observes\s+no\s+predecessor\s+history/iu.test(
      keyAgentBoundaryDocumentation,
    ) &&
    /`Prepared=1`,\s*`ProfileCreated=2`,\s*`RootCreated=3`,\s*`Committed=4`/u.test(
      activationArchitecture,
    ) &&
    /canonical journal\s+validator에는 production installer key\/checkpoint constructor, journal reader\/writer\s+backend와 caller가 없습니다/iu.test(
      rootReadme,
    ) &&
    /two-snapshot matcher의 production-code consumer는\s+위 private dormant adoption transition 하나뿐/iu.test(
      rootReadme,
    ) &&
    /Production has no installer-key\/checkpoint constructor, journal reader\/writer\s+backend, or caller for the canonical journal validator/iu.test(
      activationReadme,
    ) &&
    activationReadme.includes(
      "two-snapshot matcher has exactly one production-code consumer",
    ) &&
    /private\s+dormant adoption transition/iu.test(activationReadme) &&
    /journal validator has no production\s+installer-key\/checkpoint constructor, reader\/writer backend, or caller/iu.test(
      activationArchitecture,
    ) &&
    /sole production-code consumer is the dormant sealed\s+transition/iu.test(
      activationArchitecture,
    ) &&
    /journal validator performs no I\/O and has no production key\/checkpoint\s+constructor, journal reader\/writer backend, or caller/iu.test(
      keyAgentProtocolDocumentation,
    ) &&
    /sole production-code consumer is the\s+dormant adoption transition/iu.test(
      keyAgentProtocolDocumentation,
    ) &&
    /journal validator has no\s+production key\/checkpoint constructor, journal reader\/writer backend, or caller/iu.test(
      securityDecisions,
    ) &&
    /sole production-code consumer is the dormant sealed transition/iu.test(
      securityDecisions,
    ) &&
    [
      rootReadme,
      activationArchitecture,
      activationReadme,
      securityDecisions,
      keyAgentProtocolDocumentation,
    ].every(
      (document) =>
        document.includes("VerifiedExistingKeyAgentInstall") &&
        document.includes("post-observation") &&
        document.includes("profile-registration") &&
        /existing-root opener/iu.test(document) &&
        /exclusive installer\s+lease/iu.test(document) &&
        /canonical-path/iu.test(document) &&
        document.includes("ArtifactBoundExistingKeyAgentInstall") &&
        /whole-release/iu.test(document) &&
        /production\s+(?:caller|call sites?)/iu.test(document) &&
        /journal(?:\s+reader\/writer|\s+I\/O)?\s+backends?/iu.test(document),
    ) &&
    activationArchitecture.includes(
      "The private storage-startup transition now proves that this exact child opens and",
    ) &&
    activationArchitecture.includes("complete 188-byte") &&
    activationArchitecture.includes("one exact 88-byte") &&
    /offers neither a follow-on read\/write\s+method nor signing authority/u.test(
      activationArchitecture,
    ) &&
    /public\s+`WindowsGenerationStore` (?:is unchanged and\s+)?remains\s+stable-`TokenUser`-only/u.test(
      activationArchitecture,
    ) &&
    /immediate\s+buffered-byte snapshots/u.test(activationArchitecture) &&
    /do not prove the absence\s+of a future delayed suffix or EOF/u.test(
      activationArchitecture,
    ) &&
    keyAgentBoundaryDocumentation.includes("WindowsBackend::open_key_agent") &&
    ["Vault", "NonceLedger", "SignedCandidateJournal", "LocalSettings"].every(
      (role) => keyAgentBoundaryDocumentation.includes(role),
    ) &&
    keyAgentBoundaryDocumentation.includes("4,194,416") &&
    keyAgentBoundaryDocumentation.includes("16,777,216") &&
    keyAgentBoundaryDocumentation.includes("`226` bytes") &&
    keyAgentBoundaryDocumentation.includes("0x001f01ff") &&
    keyAgentBoundaryDocumentation.includes("0x0013019f") &&
    keyAgentBoundaryDocumentation.includes("exactly two explicit allow ACEs") &&
    keyAgentBoundaryDocumentation.includes("INHERITED_ACE") &&
    keyAgentBoundaryDocumentation.includes("FILE_ID_INFO") &&
    keyAgentBoundaryDocumentation.includes("security-context hook") &&
    keyAgentBoundaryDocumentation.includes("untrusted fault callback") &&
    keyAgentBoundaryDocumentation.includes("seven physical") &&
    keyAgentBoundaryDocumentation.includes("SHARING_VIOLATION") &&
    keyAgentBoundaryDocumentation.includes("PRIVILEGE_NOT_HELD") &&
    keyAgentBoundaryDocumentation.includes("AccessCheck") &&
    activationArchitecture.includes(
      "narrow private fixed-role Key Agent generation-store adapter",
    ) &&
    activationArchitecture.includes(
      "no production protected-settings consumer or settings key provisioning",
    ) &&
    /pending\/launch typestate split, and compiled dormant adoption transition do\s+not supply production journal inputs, authoritative profile-registration\s+observation/iu.test(
      activationReadme,
    ) &&
    /same-user processes while ancestor checks remain\s+non-atomic/u.test(
      activationReadme,
    ) &&
    activationReadme.includes(
      "Production rollback-anchor and storage/AEAD-key provisioning",
    ) &&
    activationReadme.includes("live protected-settings/lease authority") &&
    /authenticated Broker\/supervisor\s+topology and single-instance enforcement/u.test(
      activationReadme,
    ) &&
    activationReadme.includes("signed immutable artifacts") &&
    activationReadme.includes("exact DLL/dependency E2E evidence") &&
    activationReadme.includes("future-delayed") &&
    activationReadme.includes("no generic Key Agent runtime or") &&
    activationReadme.includes("signing IPC exists") &&
    /not a production fresh\s+fixed profile\/root E2E/u.test(activationReadme) &&
    !/Generation-file adaptation\/file DACLs[^\n]*STOP-SHIP/iu.test(
      keyAgentBoundaryDocumentation,
    ) &&
    !/pending a\s+file-level adapter and policy/iu.test(
      keyAgentBoundaryDocumentation,
    ) &&
    !/\bno Key Agent adapter\b/iu.test(keyAgentBoundaryDocumentation) &&
    !/(?:generation-file|generation-store)[^\n]{0,100}(?:adapter|DACL)[^\n]{0,100}(?:absent|missing|pending|unimplemented)/iu.test(
      keyAgentBoundaryDocumentation,
    ) &&
    keyAgentBoundaryDocumentation.includes("durable installer provenance/recovery") &&
    keyAgentBoundaryDocumentation.includes("same-user mutation") &&
    /CSPRNG(?:-named)?\s+(?:test|storage)\s+leaf/u.test(
      keyAgentBoundaryDocumentation,
    ) &&
    activationArchitecture.includes(
      "This central profile API rejects thread impersonation",
    ) &&
    /authenticated\s+(?:Native Host\/)?Broker[\s\S]{0,120}(?:startup|process topology|프로세스 topology)/iu.test(
      keyAgentBoundaryDocumentation,
    ) &&
    /(?:startup[^\n]{0,80}(?:nonce|exchange|교환)|nonce[^\n]{0,80}(?:startup|exchange|교환))/iu.test(
      keyAgentBoundaryDocumentation,
    ) &&
    /(?:single-instance\/process topology|single-instance|단일\s*인스턴스)/iu.test(
      keyAgentBoundaryDocumentation,
    ) &&
    /(?:signed immutable installation|signed install|서명[^\n]{0,40}(?:설치|artifact))/iu.test(
      keyAgentBoundaryDocumentation,
    ) &&
    securityDecisions.includes("**Current release status: STOP-SHIP.**") &&
    securityDecisions.includes("`COMPILED_RELEASE_POLICY` remains `None`") &&
    activationArchitecture.includes("`COMPILED_RELEASE_POLICY`") &&
    activationArchitecture.includes("remain separate blockers") &&
    activationReadme.includes("`COMPILED_RELEASE_POLICY` is `None`"),
  "Key Agent fixed-LPAC proof and exact membership semantics must be documented without weakening storage, startup/topology, signed-install, or release-disabled STOP-SHIP claims",
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
    nativeMain.includes("native_host::run_release_disabled_stream") &&
    nativeMain.includes("std::process::exit(PRIVATE_BROKER_UNAVAILABLE);"),
  "native host main must retain its release-disabled persistent path and exit 78",
);
const nativeWireForActivation = await text("crates/native-host/src/wire.rs");
requireInvariant(
  nativeWireForActivation.includes("const UNAVAILABLE_CODE: i64 = 4_900;") &&
    nativeWireForActivation.includes("code: UNAVAILABLE_CODE") &&
    nativeWireForActivation.includes("pub fn run_release_disabled_stream") &&
    /pub fn run_release_disabled_stream[\s\S]*?NativeHostDispatcher::new\(\s*ReleaseDisabledBrokerEndpoint,\s*ReleaseAttestation::default\(\)\s*\)/u.test(
      nativeWireForActivation,
    ) &&
    /impl BrokerEndpoint for ReleaseDisabledBrokerEndpoint[\s\S]*?Err\(BrokerEndpointError::Unavailable\)/u.test(
      nativeWireForActivation,
    ) &&
    nativeWireForActivation.includes("pub fn run_unattested_once"),
  "native host release-disabled paths must retain false attestation and stable provider code 4900",
);

// Debug subprocess contract: this is deliberately disjoint from the Sepolia
// wallet-management/token invariants above and from the release attestation
// composition. It may prove protocol shape only; it must never become a release
// Broker bootstrap or carry an unavailable request body.
const brokerManifestForContract = await text("crates/broker/Cargo.toml");
const nativeManifestForContract = await text("crates/native-host/Cargo.toml");
const brokerMainForContract = await text("crates/broker/src/main.rs");
const brokerLibraryForContract = await text("crates/broker/src/lib.rs");
const brokerTransportForContract = await text("crates/broker/src/transport.rs");
const brokerIpcContract = await text("crates/broker/src/ipc.rs");
const nativeLibraryForContract = await text("crates/native-host/src/lib.rs");
const nativeContractBridge = await text("crates/native-host/src/contract_bridge.rs");
const extensionBackgroundContract = await text("extension/src/background-core.js");
const nativeProcessContractTest = await text("extension/tests/native-host-process.test.mjs");
const platformManifestForWindowsBroker = await text(
  "crates/platform-windows/Cargo.toml",
);
const brokerChannelSource = await text(
  "crates/platform-windows/src/broker_channel.rs",
);
const brokerChannelProduction = withoutBottomTestModule(brokerChannelSource);
const brokerSupervisor = await text(
  "crates/platform-windows/src/broker_supervisor.rs",
);
const brokerSupervisorProduction = withoutBottomTestModule(brokerSupervisor);
const brokerDuplicateRestrictedProcessHandle = rustFunctionBlock(
  brokerChannelProduction,
  "duplicate_restricted_process_handle",
);
const brokerTestInheritedProcessStdio = rustFunctionBlock(
  brokerChannelSource,
  "process_handle_as_inherited_stdio",
);
const brokerTestSpawnChild = rustFunctionBlock(brokerChannelSource, "spawn_child");
const brokerTestSpawnOrder = [
  "acquire_inheritable_handle_launch(",
  "let stdin = match expected_server",
  "current_process_stdio_for_test(&flight)",
  "child_process_stdio_for_test(&flight, child)",
  "let child = command.spawn()?",
  "drop(command)",
  "drop(flight)",
].map((marker) => brokerTestSpawnChild.indexOf(marker));
requireInvariant(
  /fn duplicate_restricted_process_handle\(\s*source: HANDLE,?\s*\)/u.test(
    brokerDuplicateRestrictedProcessHandle,
  ) &&
    !/\binheritable\s*:\s*(?:bool|BOOL)\b/u.test(
      brokerDuplicateRestrictedProcessHandle,
    ) &&
    rustCallSites(brokerDuplicateRestrictedProcessHandle, "DuplicateHandle").length ===
      1 &&
    rustCallSites(brokerDuplicateRestrictedProcessHandle, "DuplicateHandle")[0]
      ?.arguments[5] === "false" &&
    brokerDuplicateRestrictedProcessHandle.includes(
      "let desired = (PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE).0",
    ) &&
    brokerDuplicateRestrictedProcessHandle.includes("if flags != 0") &&
    /#\[cfg\(test\)\]\s*fn process_handle_as_inherited_stdio\(\s*_flight:\s*&crate::inheritable_handle_launch::InheritableHandleLaunchFlight<'_>/u.test(
      brokerChannelSource,
    ) &&
    rustCallSites(brokerTestInheritedProcessStdio, "DuplicateHandle").length === 1 &&
    rustCallSites(brokerTestInheritedProcessStdio, "DuplicateHandle")[0]
      ?.arguments[5] === "true" &&
    brokerTestSpawnOrder.every((position) => position !== -1) &&
    brokerTestSpawnOrder
      .slice(1)
      .every((position, index) => position > brokerTestSpawnOrder[index]),
  "Broker parent-process duplication must be production-sealed to literal false, while its cfg(test) inheritable Stdio helper remains flight-bound through Command::spawn and immediate cleanup",
);
const nativeWindowsBrokerBridge = await text(
  "crates/native-host/src/windows_broker_bridge.rs",
);
const brokerProtocolContract = await text("docs/protocol-contract.md");
const nativeHostContractReadme = await text("extension/native-host/README.md");
const brokerContractProductionFiles = await rustProductionSources(
  "crates/broker/src",
);
const nativeContractProductionFiles = await rustProductionSources(
  "crates/native-host/src",
);
requireInvariant(
  brokerManifestForContract.includes(
    'ipc-contract-test-hook = ["dep:getrandom"]',
  ) &&
    brokerManifestForContract.includes(
      "getrandom = { workspace = true, optional = true }",
    ) &&
    nativeManifestForContract.includes(
      'broker-ipc-contract-test-hook = ["broker/ipc-contract-test-hook", "dep:getrandom"]',
    ) &&
    nativeManifestForContract.includes(
      "getrandom = { workspace = true, optional = true }",
    ),
  "debug Broker subprocess randomness must remain optional and feature-scoped",
);

// Dormant Windows composition: the prepared-value core is private and compiled
// on Windows, while every cross-crate facade still requires Windows AND its
// explicit feature AND debug assertions. Release builds cannot name the facade.
const brokerSupervisorExports =
  /#\[cfg\(all\(\s*windows,\s*feature = "broker-channel-contract-test-hook",\s*debug_assertions\s*\)\)\]\s*pub use broker_artifact::broker_supervisor::\{(?<body>[^}]*)\};/u.exec(
    platformWindowsLib,
  )?.groups?.body ?? "";
const nativeWindowsBridgeExports =
  /#\[cfg\(all\(\s*windows,\s*feature = "windows-broker-channel-contract-test-hook",\s*debug_assertions\s*\)\)\]\s*pub use windows_broker_bridge::(?<body>[^;]+);/u.exec(
    nativeLibraryForContract,
  )?.groups?.body ?? "";
requireInvariant(
  /^default\s*=\s*\[\]$/mu.test(platformManifestForWindowsBroker) &&
    /^broker-channel-contract-test-hook\s*=\s*\[\]$/mu.test(
      platformManifestForWindowsBroker,
    ) &&
    /^windows-broker-channel-contract-test-hook\s*=\s*\[\s*"ipc-contract-test-hook",\s*"dep:platform-windows",\s*"platform-windows\/broker-channel-contract-test-hook",?\s*\]$/mu.test(
      brokerManifestForContract,
    ) &&
    /^windows-broker-channel-contract-test-hook\s*=\s*\[\s*"broker-ipc-contract-test-hook",\s*"broker\/windows-broker-channel-contract-test-hook",\s*"platform-windows\/broker-channel-contract-test-hook",?\s*\]$/mu.test(
      nativeManifestForContract,
    ),
  "Windows Broker composition features must remain opt-in and transitively bind the same platform debug feature",
);
requireInvariant(
  /#\[cfg\(windows\)\]\s*#\[path = "broker_supervisor.rs"\]\s*pub\(crate\) mod broker_supervisor;/u.test(
    brokerArtifactProduction,
  ) &&
    !/(?:^|\n)\s*mod broker_supervisor;/u.test(platformWindowsLibCode) &&
    /#\[cfg\(windows\)\]\s*#\[allow\(dead_code\)\]\s*mod exact_image;/u.test(
      platformWindowsLib,
    ) &&
    !/pub(?:\([^)]*\))?\s+(?:mod|use)\s+[^;]*exact_image/u.test(
      platformWindowsLib,
    ) &&
    /#\[cfg\(all\(\s*feature = "broker-channel-contract-test-hook",\s*debug_assertions\s*\)\)\]\s*pub\(crate\) struct PinnedBrokerImage/u.test(
      exactBrokerImageProduction,
    ) &&
    /#\[cfg\(all\(\s*feature = "broker-channel-contract-test-hook",\s*debug_assertions\s*\)\)\]\s*impl PinnedBrokerImage/u.test(
      exactBrokerImageProduction,
    ) &&
    /#\[cfg\(all\(\s*feature = "broker-channel-contract-test-hook",\s*debug_assertions\s*\)\)\]\s*impl fmt::Debug for PinnedBrokerImage/u.test(
      exactBrokerImageProduction,
    ) &&
    /#\[cfg\(all\(\s*feature = "broker-channel-contract-test-hook",\s*debug_assertions\s*\)\)\]\s*impl From<HelperError> for ExactImageError/u.test(
      exactBrokerImageProduction,
    ) &&
    /#\[cfg\(all\(\s*windows,\s*feature = "broker-channel-contract-test-hook",\s*debug_assertions\s*\)\)\]\s*pub\(crate\) fn hold_dormant_broker\(candidate: &Path\) -> Result<Self, HelperError>\s*\{\s*sys::hold_dormant_broker\(candidate\)\s*\}/u.test(
      activationHelper,
    ) &&
    /#\[cfg\(all\(\s*feature = "broker-channel-contract-test-hook",\s*debug_assertions\s*\)\)\]\s*pub\(super\) fn hold_dormant_broker\(candidate: &Path\) -> Result<VerifiedHelper, HelperError>\s*\{/u.test(
      activationHelper,
    ) &&
    (activationHelper.match(/\bhold_dormant_broker\s*\(/gu) ?? []).length === 3 &&
    (exactBrokerImageProduction.match(/VerifiedHelper::hold_dormant_broker\(/gu) ?? [])
      .length === 1 &&
    (exactBrokerImageProduction.match(/VerifiedHelper::hold_dormant_broker\b/gu) ?? [])
      .length === 1 &&
    platformWindowsProductionFiles
      .filter(
        (file) =>
          file.path !== "crates/platform-windows/src/helper.rs" &&
          file.path !== "crates/platform-windows/src/exact_image.rs",
      )
      .every((file) => !/\bhold_dormant_broker\b/u.test(file.source)) &&
    JSON.stringify(exactImageVisibleFunctionNames) ===
      JSON.stringify([
        "held_helper_file_identity",
        "authenticate_mapped_image",
        "hold",
        "path",
        "authenticate_mapped_image",
        "exact_file_identity",
      ]) &&
    brokerSupervisorExports.includes("DormantBrokerPayloadChannel") &&
    brokerSupervisorExports.includes("connect_inherited_native_host_channel") &&
    brokerSupervisorExports.includes("launch_dormant_broker_channel") &&
    (platformWindowsLib.match(/\bbroker_supervisor\b/gu) ?? []).length === 2 &&
    (platformWindowsLib.match(/\bexact_image\b/gu) ?? []).length === 1 &&
    /#\[cfg\(all\(\s*windows,\s*feature = "windows-broker-channel-contract-test-hook",\s*debug_assertions\s*\)\)\]\s*mod windows_broker_bridge;/u.test(
      nativeLibraryForContract,
    ) &&
    nativeWindowsBridgeExports.includes(
      "run_windows_broker_contract_test_stream",
    ) &&
    (nativeLibraryForContract.match(/\bwindows_broker_bridge\b/gu) ?? [])
      .length === 2,
  "Windows exact-file identity and prepared Broker core must stay private and Windows-only while every path-opening facade and Native Host bridge API remains behind the exact debug feature gate",
);
const brokerDisabledMain = rustItemBlock(
  brokerMainForContract,
  /(?:^|\n)#\[cfg\(not\(any\([\s\S]*?feature = "ipc-contract-test-hook"[\s\S]*?feature = "windows-broker-channel-contract-test-hook"[\s\S]*?debug_assertions[\s\S]*?\)\)\)\]\s*fn main\s*\(\s*\)/u,
);
const brokerLegacyMain = rustItemBlock(
  brokerMainForContract,
  /(?:^|\n)#\[cfg\(all\(\s*feature = "ipc-contract-test-hook",\s*debug_assertions,\s*not\(all\(windows, feature = "windows-broker-channel-contract-test-hook"\)\)\s*\)\)\]\s*fn main\s*\(\s*\)/u,
);
const brokerWindowsMain = rustItemBlock(
  brokerMainForContract,
  /(?:^|\n)#\[cfg\(all\(\s*windows,\s*feature = "windows-broker-channel-contract-test-hook",\s*debug_assertions\s*\)\)\]\s*fn main\s*\(\s*\)/u,
);
const brokerLegacyServerEntry = rustItemBlock(
  brokerMainForContract,
  /(?:^|\n)#\[cfg\(all\(\s*feature = "ipc-contract-test-hook",\s*debug_assertions,\s*not\(all\(windows, feature = "windows-broker-channel-contract-test-hook"\)\)\s*\)\)\]\s*fn run_contract_server\s*\(\s*\)/u,
);
const brokerWindowsServerEntry = rustItemBlock(
  brokerMainForContract,
  /(?:^|\n)#\[cfg\(all\(\s*windows,\s*feature = "windows-broker-channel-contract-test-hook",\s*debug_assertions\s*\)\)\]\s*fn run_windows_contract_server\s*\(\s*\)/u,
);
const nativeDisabledMain = rustItemBlock(
  nativeMain,
  /(?:^|\n)#\[cfg\(not\(all\(feature = "broker-ipc-contract-test-hook", debug_assertions\)\)\)\]\s*fn main\s*\(\s*\)/u,
);
const nativeLegacyMain = rustItemBlock(
  nativeMain,
  /(?:^|\n)#\[cfg\(all\(\s*feature = "broker-ipc-contract-test-hook",\s*debug_assertions,\s*not\(all\(windows, feature = "windows-broker-channel-contract-test-hook"\)\)\s*\)\)\]\s*fn main\s*\(\s*\)/u,
);
const nativeWindowsMain = rustItemBlock(
  nativeMain,
  /(?:^|\n)#\[cfg\(all\(\s*windows,\s*feature = "windows-broker-channel-contract-test-hook",\s*debug_assertions\s*\)\)\]\s*fn main\s*\(\s*\)/u,
);
const nativeLegacyProcessEntry = rustItemBlock(
  nativeMain,
  /(?:^|\n)#\[cfg\(all\(\s*feature = "broker-ipc-contract-test-hook",\s*debug_assertions,\s*not\(all\(windows, feature = "windows-broker-channel-contract-test-hook"\)\)\s*\)\)\]\s*fn run_contract_process\s*\(\s*\)/u,
);
const nativeWindowsProcessEntry = rustItemBlock(
  nativeMain,
  /(?:^|\n)#\[cfg\(all\(\s*windows,\s*feature = "windows-broker-channel-contract-test-hook",\s*debug_assertions\s*\)\)\]\s*fn run_windows_contract_process\s*\(\s*\)/u,
);
const brokerNativeMainBlocks = [
  brokerDisabledMain,
  brokerLegacyMain,
  brokerWindowsMain,
  brokerLegacyServerEntry,
  brokerWindowsServerEntry,
  nativeDisabledMain,
  nativeLegacyMain,
  nativeWindowsMain,
  nativeLegacyProcessEntry,
  nativeWindowsProcessEntry,
];
requireInvariant(
  brokerNativeMainBlocks.every(
    (block) => block.length > 0 && !/(?:e?println!|dbg!)/u.test(block),
  ) &&
    brokerDisabledMain.includes("std::process::exit(78);") &&
    !/\brun_(?:contract|windows_contract)_server\s*\(/u.test(
      brokerDisabledMain,
    ) &&
    brokerLegacyMain.includes("run_contract_server()") &&
    !brokerLegacyMain.includes("run_windows_contract_server()") &&
    brokerWindowsMain.includes("run_windows_contract_server()") &&
    !brokerWindowsMain.includes("run_contract_server()") &&
    nativeDisabledMain.includes("native_host::run_release_disabled_stream") &&
    nativeDisabledMain.includes(
      "std::process::exit(PRIVATE_BROKER_UNAVAILABLE);",
    ) &&
    !/\brun_(?:contract|windows_contract)_process\s*\(/u.test(
      nativeDisabledMain,
    ) &&
    nativeLegacyMain.includes("run_contract_process()") &&
    !nativeLegacyMain.includes("run_windows_contract_process()") &&
    nativeWindowsMain.includes("run_windows_contract_process()") &&
    !nativeWindowsMain.includes("run_contract_process()"),
  "legacy stdio, Windows Broker, and default/release mains must remain mutually exclusive, feature-and-debug gated, silent, and fail-closed",
);
requireInvariant(
  nativeProcessContractTest.includes(
    'test("release all-feature binaries keep both subprocess hooks disabled"',
  ) &&
    nativeProcessContractTest.includes(
      '"build", "--release", "--offline", "--locked"',
    ) &&
    nativeProcessContractTest.includes(
      '"-p", "native-host", "-p", "broker", "--all-features"',
    ) &&
    nativeProcessContractTest.includes(
      "assert.deepEqual(await runClosedProcess(executables.broker), { code: 78, signal: null })",
    ) &&
    nativeProcessContractTest.includes("response.error.code, 4900") &&
    nativeProcessContractTest.includes(
      "assert.deepEqual(await nativeProcess.closed, { code: 78, signal: null })",
    ) &&
    nativeProcessContractTest.includes(
      'test("Windows native host reaches the exact hidden Broker channel without stdio composition"',
    ) &&
    nativeProcessContractTest.includes(
      "native-host/windows-broker-channel-contract-test-hook,broker/windows-broker-channel-contract-test-hook",
    ),
  "real subprocess evidence must retain the Windows debug composition and default/release all-feature negative behavior",
);

// The Windows pipe owns its one BE frame. Broker IPC owns only the closed JSON
// payload state machine; its legacy stdio wrapper is the sole separate framing
// adapter and delegates immediately to the same payload APIs.
const brokerChannelWriteFrame = rustFunctionBlock(
  brokerChannelProduction,
  "write_frame_after_prefix",
);
const brokerChannelReadFrame = rustFunctionBlock(
  brokerChannelProduction,
  "read_frame_or_eof",
);
const brokerPayloadTrait = rustItemBlock(
  brokerIpcContract,
  /(?:^|\n)pub trait BrokerIpcPayloads\s*\{/u,
);
const brokerSplitFramingAdapter = rustItemBlock(
  brokerIpcContract,
  /(?:^|\n)impl<Reader, Writer> BrokerIpcPayloads for SplitFramedPayloads<'_, Reader, Writer>\s*/u,
);
const brokerStdioServer = rustFunctionBlock(
  brokerIpcContract,
  "run_secretless_server",
);
const brokerPayloadServer = rustFunctionBlock(
  brokerIpcContract,
  "run_secretless_server_payloads",
);
const brokerReadFramedPayload = rustFunctionBlock(
  brokerIpcContract,
  "read_framed_payload",
);
const brokerWriteFramedPayload = rustFunctionBlock(
  brokerIpcContract,
  "write_framed_payload",
);
const brokerWindowsServer = rustFunctionBlock(
  brokerMainForContract,
  "run_windows_contract_server",
);
const nativeWindowsProcess = rustFunctionBlock(
  nativeMain,
  "run_windows_contract_process",
);
const supervisorWritePayload = rustFunctionBlock(
  brokerSupervisorProduction,
  "write_payload",
);
const supervisorReadPayload = rustFunctionBlock(
  brokerSupervisorProduction,
  "read_payload",
);
requireInvariant(
  brokerChannelProduction.includes(
    "const MAX_BROKER_FRAME_BYTES: usize = 8_192;",
  ) &&
    brokerChannelWriteFrame.includes("length.to_be_bytes()") &&
    brokerChannelReadFrame.includes("u32::from_be_bytes(prefix)") &&
    !/(?:to|from)_le_bytes/u.test(brokerChannelProduction) &&
    brokerIpcContract.includes(
      "pub const MAX_BROKER_IPC_FRAME_BYTES: usize = 8_192;",
    ) &&
    brokerReadFramedPayload.includes("u32::from_be_bytes(length_bytes)") &&
    brokerWriteFramedPayload.includes("length.to_be_bytes()") &&
    !/(?:to|from)_le_bytes/u.test(brokerIpcContract),
  "Windows and stdio Broker framing must remain four-byte big-endian with the exact 8192-byte payload bound",
);
requireInvariant(
  brokerPayloadTrait.includes(
    "fn read_payload(&mut self) -> Result<Option<Vec<u8>>, BrokerIpcError>;",
  ) &&
    brokerPayloadTrait.includes(
      "fn write_payload(&mut self, payload: &[u8]) -> Result<(), BrokerIpcError>;",
    ) &&
    brokerSplitFramingAdapter.includes("read_framed_payload(self.reader)") &&
    brokerSplitFramingAdapter.includes(
      "write_framed_payload(self.writer, payload)",
    ) &&
    brokerStdioServer.includes("SplitFramedPayloads { reader, writer }") &&
    brokerStdioServer.includes("run_secretless_server_payloads(") &&
    brokerPayloadServer.includes("read_required_payload_value(payloads)") &&
    brokerPayloadServer.includes("write_payload_value(") &&
    brokerPayloadServer.includes("payloads,") &&
    !/(?:read|write)_framed_payload|to_be_bytes|from_be_bytes/u.test(
      brokerPayloadServer,
    ) &&
    supervisorWritePayload.includes("channel.write_frame(payload, deadline)") &&
    supervisorReadPayload.includes("channel.read_frame_or_eof(deadline)") &&
    brokerWindowsServer.includes("run_secretless_server_payloads(") &&
    !/\brun_secretless_server\s*\(/u.test(brokerWindowsServer) &&
    nativeWindowsBrokerBridge.includes(
      "run_broker_contract_test_payloads(native_reader, native_writer, &mut payloads, random_nonce)",
    ) &&
    !/(?:read|write)_framed_payload|to_be_bytes|from_be_bytes/u.test(
      [
        brokerSupervisorProduction,
        nativeWindowsBrokerBridge,
        nativeContractBridge,
      ].join("\n"),
    ) &&
    !nativeWindowsProcess.includes("Command::new"),
  "Windows composition must have one channel framing owner and reuse Broker IPC only as a payload-state machine",
);

const dormantBrokerFacadeReferences = [
  ...platformWindowsProductionFiles,
  ...brokerContractProductionFiles,
  ...nativeContractProductionFiles,
]
  .filter((file) => file.source.includes("DormantBrokerPayloadChannel"))
  .map((file) => file.path)
  .sort((left, right) => left.localeCompare(right, "en"));
const brokerWindowsPayloadAdapter = rustItemBlock(
  brokerMainForContract,
  /(?:^|\n)\s*impl BrokerIpcPayloads for WindowsPayloads\s*\{/u,
);
const nativeWindowsPayloadAdapter = rustItemBlock(
  nativeWindowsBrokerBridge,
  /(?:^|\n)impl BrokerIpcPayloads for WindowsBrokerPayloads\s*\{/u,
);
requireInvariant(
  JSON.stringify(dormantBrokerFacadeReferences) ===
    JSON.stringify([
      "crates/broker/src/main.rs",
      "crates/native-host/src/windows_broker_bridge.rs",
      "crates/platform-windows/src/broker_supervisor.rs",
      "crates/platform-windows/src/lib.rs",
    ]) &&
    (brokerWindowsPayloadAdapter.match(/\.read_payload\(/gu) ?? []).length === 1 &&
    (brokerWindowsPayloadAdapter.match(/\.write_payload\(/gu) ?? []).length === 1 &&
    (nativeWindowsPayloadAdapter.match(/\.read_payload\(/gu) ?? []).length === 1 &&
    (nativeWindowsPayloadAdapter.match(/\.write_payload\(/gu) ?? []).length === 1 &&
    brokerSupervisorProduction.includes(
      "cross-crate `BrokerIpcPayloads` adapters must supply framing-free JSON",
    ),
  "debug raw Broker payload facade must remain release-absent and confined to the two typed payload adapters",
);

// The debug creator may run only at its one reviewed callsite and must prove
// the simultaneously held Broker image before releasing user mode. No PID
// reopen is accepted in either the channel peer binding or supervisor.
const launchBrokerPath = rustFunctionBlock(
  brokerSupervisorProduction,
  "launch_broker_path",
);
const launchBrokerApplicationWithAfterCreate = rustFunctionBlock(
  brokerSupervisorProduction,
  "launch_broker_application_with_after_create",
);
const launchBrokerApplicationWrapper = rustFunctionBlock(
  brokerSupervisorProduction,
  "launch_broker_application",
);
const panicAfterBrokerCreate = rustFunctionBlock(
  brokerSupervisorProduction,
  "panic_after_create_for_test",
);
const authenticateBrokerImage = rustFunctionBlock(
  brokerSupervisorProduction,
  "authenticate_first_event",
);
const dormantBrokerPayloadImplementation = rustItemBlock(
  brokerSupervisorProduction,
  /(?:^|\n)impl DormantBrokerPayloadChannel\s*\{/u,
);
const closeTerminalBrokerPayload = rustFunctionBlock(
  dormantBrokerPayloadImplementation,
  "close_terminal",
);
const writeBrokerPayload = rustFunctionBlock(
  dormantBrokerPayloadImplementation,
  "write_payload",
);
const readBrokerPayload = rustFunctionBlock(
  dormantBrokerPayloadImplementation,
  "read_payload",
);
const dormantBrokerPayloadDrop = rustItemBlock(
  brokerSupervisorProduction,
  /(?:^|\n)impl Drop for DormantBrokerPayloadChannel\s*\{/u,
);
const terminalBrokerPayloadTest = rustFunctionBlock(
  brokerSupervisor,
  "terminal_channel_error_terminates_before_the_wrapper_is_dropped",
);
const brokerCreationFlags = rustFunctionBlock(
  brokerSupervisorProduction,
  "creation_flags",
);
const brokerCreationFlagNames = [
  ...brokerCreationFlags.matchAll(
    /\b(?:CREATE_[A-Z_]+|DEBUG_[A-Z_]+|EXTENDED_STARTUPINFO_PRESENT)\b/gu,
  ),
].map((match) => match[0]);
const brokerCreationAttributesDefinition = rustItemBlock(
  brokerSupervisorProduction,
  /(?:^|\n)\s*struct CreationAttributes<'resources,\s*'flight>\s*\{/u,
);
const brokerCreationAttributesImplementation = rustItemBlock(
  brokerSupervisorProduction,
  /(?:^|\n)\s*impl<'resources,\s*'flight> CreationAttributes<'resources,\s*'flight>\s*\{/u,
);
const brokerInheritedNullStdio = rustItemBlock(
  brokerSupervisorProduction,
  /(?:^|\n)\s*impl<'flight> InheritedNullStdio<'flight>\s*\{/u,
);
const brokerInheritedParentProcess = rustItemBlock(
  brokerSupervisorProduction,
  /(?:^|\n)\s*impl<'flight> InheritedParentProcess<'flight>\s*\{/u,
);
const brokerChildKernelContract = rustFunctionBlock(
  brokerSupervisor,
  "assert_child_kernel_contract",
);
const brokerUnrelatedSentinel = rustItemBlock(
  brokerSupervisor,
  /(?:^|\n)\s*impl UnrelatedSentinel\s*\{/u,
);
const brokerSentinelDriver = rustFunctionBlock(
  brokerSupervisor,
  "inheritable_handle_list_probe_runs_in_a_single_test_subprocess",
);
const brokerSentinelFixture = rustFunctionBlock(
  brokerSupervisor,
  "isolated_inheritable_sentinel_fixture",
);
const brokerSentinelWait = rustFunctionBlock(
  brokerSupervisor,
  "wait_for_isolated_child",
);
const brokerDebugWaitClassifier = rustFunctionBlock(
  brokerSupervisorProduction,
  "classify_debug_wait_failure",
);
const brokerJobImplementation = rustItemBlock(
  brokerSupervisorProduction,
  /(?:^|\n)\s*impl BrokerJob\s*\{/u,
);
const brokerProcessObservationImplementation = rustItemBlock(
  brokerSupervisorProduction,
  /(?:^|\n)\s*impl ProcessObservation\s*\{/u,
);
const duplicateBrokerProcessObservation = rustItemBlock(
  brokerSupervisorProduction,
  /(?:^|\n)    fn duplicate_process_observation\s*\(/u,
);
const exactFileIdentityDefinition = rustItemBlock(
  exactBrokerImageProduction,
  /(?:^|\n)pub\(super\) struct ExactFileIdentity\s*\{/u,
);
const exactFileIdentityNew = rustFunctionBlock(
  exactBrokerImageProduction,
  "new",
);
const exactFileIdentityQuery = rustFunctionBlock(
  exactBrokerImageProduction,
  "exact_file_identity",
);
const exactFileIdentityNewNormalized = exactFileIdentityNew
  .replace(/\s+/gu, " ")
  .trim();
const exactFileIdentityQueryNormalized = exactFileIdentityQuery
  .replace(/^\s*\/\/.*$/gmu, "")
  .replace(/\s+/gu, " ")
  .trim();
const exactFileIdentityDebug = rustItemBlock(
  exactBrokerImageProduction,
  /(?:^|\n)impl fmt::Debug for ExactFileIdentity\s*\{/u,
);
const exactFileIdentityZeroize = rustItemBlock(
  exactBrokerImageProduction,
  /(?:^|\n)impl Zeroize for ExactFileIdentity\s*\{/u,
);
const exactFileIdentityDrop = rustItemBlock(
  exactBrokerImageProduction,
  /(?:^|\n)impl Drop for ExactFileIdentity\s*\{/u,
);
const exactFileIdentityTraitImpls = [
  ...exactBrokerImageProduction.matchAll(
    /(?:^|\n)\s*(?:unsafe\s+)?impl\s+(?<trait>[^\r\n{]+?)\s+for\s+[^\r\n{]*\bExactFileIdentity\b[^\r\n{]*\{/gu,
  ),
].map((match) => match.groups.trait.trim());
const exactFileIdentityDebugNormalized = exactFileIdentityDebug
  .replace(/\s+/gu, " ")
  .trim();
const exactFileIdentityZeroizeNormalized = exactFileIdentityZeroize
  .replace(/\s+/gu, " ")
  .trim();
const exactFileIdentityDropNormalized = exactFileIdentityDrop
  .replace(/\s+/gu, " ")
  .trim();
const exactMappedImageAuthentication = rustFunctionBlock(
  exactBrokerImageProduction,
  "authenticate_mapped_image",
);
const exactFileIdentitySentinelTest = rustFunctionBlock(
  exactBrokerImage,
  "exact_file_identity_rejects_zero_volume_and_sentinel_file_ids",
);
const exactFileIdentityEqualityTest = rustFunctionBlock(
  exactBrokerImage,
  "exact_file_identity_equality_binds_volume_and_all_128_file_id_bits",
);
const brokerDebugEventOwnershipOrder = [
  "let event_file = match event.dwDebugEventCode",
  "if event.dwProcessId != self.process_id",
  "self.pending_event = Some((event.dwProcessId, event.dwThreadId))",
  "if event.dwDebugEventCode != CREATE_PROCESS_DEBUG_EVENT",
  "let create = unsafe { event.u.CreateProcessInfo }",
  "let event_file = event_file.ok_or(DormantBrokerError::ProcessProof)?",
  "let event_process_id = unsafe { GetProcessId(create.hProcess) }",
  "image.authenticate_mapped_image(event_file.raw())",
].map((marker) => authenticateBrokerImage.indexOf(marker));
requireInvariant(
  brokerDebugEventOwnershipOrder.every((position) => position !== -1) &&
    brokerDebugEventOwnershipOrder.every(
      (position, index, positions) => index === 0 || positions[index - 1] < position,
    ) &&
    authenticateBrokerImage.includes(
      "OwnedWinHandle::new(unsafe { event.u.LoadDll }.hFile)",
    ) &&
    closeTerminalBrokerPayload.indexOf("drop(self.channel.take())") <
      closeTerminalBrokerPayload.indexOf("self.supervisor.take()") &&
    closeTerminalBrokerPayload.includes("supervisor.shutdown()?") &&
    writeBrokerPayload.indexOf("self.close_terminal()?") !== -1 &&
    writeBrokerPayload.indexOf(
      "Err(error)",
      writeBrokerPayload.indexOf("self.close_terminal()?") + 1,
    ) > writeBrokerPayload.indexOf("self.close_terminal()?") &&
    (readBrokerPayload.match(/self\.close_terminal\(\)\?/gu) ?? []).length === 2 &&
    dormantBrokerPayloadDrop.includes("let _ = self.close_terminal()") &&
    terminalBrokerPayloadTest.indexOf("let observation =") <
      terminalBrokerPayloadTest.indexOf("channel.read_payload(Instant::now())") &&
    terminalBrokerPayloadTest.indexOf("channel.read_payload(Instant::now())") <
      terminalBrokerPayloadTest.indexOf("observation.wait_terminated()") &&
    terminalBrokerPayloadTest.indexOf("observation.wait_terminated()") <
      terminalBrokerPayloadTest.indexOf("drop(channel)"),
  "Broker debug-event file ownership must precede identity rejection, and every terminal payload result must synchronously shut down the exact process before the wrapper can be retained",
);
requireInvariant(
  launchBrokerPath.includes("PinnedBrokerImage::hold(broker_path)") &&
    exactBrokerImageProduction.includes(
      "VerifiedHelper::hold_dormant_broker(path)",
    ) &&
    exactBrokerImageProduction.includes("FILE_ID_INFO") &&
    exactBrokerImageProduction.includes("GetFileInformationByHandleEx(") &&
    /#\[derive\(Eq, PartialEq\)\]\s*pub\(super\) struct ExactFileIdentity/u.test(
      exactBrokerImageProduction,
    ) &&
    !/#\[derive\([^\]]*(?:Clone|Copy|Debug|Serialize)[^\]]*\)\]\s*pub\(super\) struct ExactFileIdentity/u.test(
      exactBrokerImageProduction,
    ) &&
    !/impl\s+(?:Clone|Copy|Serialize|serde::Serialize)\s+for\s+ExactFileIdentity/u.test(
      exactBrokerImageProduction,
    ) &&
    JSON.stringify(exactFileIdentityTraitImpls) ===
      JSON.stringify(["fmt::Debug", "Zeroize", "Drop"]) &&
    exactFileIdentityDefinition.includes("volume_serial_number: u64") &&
    exactFileIdentityDefinition.includes("file_id: [u8; 16]") &&
    exactFileIdentityDebugNormalized ===
      'impl fmt::Debug for ExactFileIdentity { fn fmt(&self, formatter: &mut fmt::Formatter<\'_>) -> fmt::Result { formatter.write_str("ExactFileIdentity([FILE_ID_INFO])") } }' &&
    exactFileIdentityZeroizeNormalized ===
      "impl Zeroize for ExactFileIdentity { fn zeroize(&mut self) { self.volume_serial_number.zeroize(); self.file_id.zeroize(); } }" &&
    exactFileIdentityDropNormalized ===
      "impl Drop for ExactFileIdentity { fn drop(&mut self) { self.zeroize(); } }" &&
    exactFileIdentityNewNormalized ===
      "fn new(volume_serial_number: u64, file_id: [u8; 16]) -> Result<Self, ExactImageError> { if volume_serial_number == 0 || file_id == [0; 16] || file_id == [u8::MAX; 16] { return Err(ExactImageError::IdentityUnavailable); } Ok(Self { volume_serial_number, file_id, }) }" &&
    exactFileIdentityQueryNormalized ===
      "pub(super) fn exact_file_identity( handle: HANDLE, ) -> Result<ExactFileIdentity, ExactImageError> { if handle.is_invalid() || handle == INVALID_HANDLE_VALUE { return Err(ExactImageError::IdentityUnavailable); } let mut information = FILE_ID_INFO::default(); unsafe { GetFileInformationByHandleEx( handle, FileIdInfo, ptr::from_mut(&mut information).cast::<c_void>(), u32::try_from(size_of_val(&information)) .map_err(|_| ExactImageError::IdentityUnavailable)?, ) } .map_err(|_| ExactImageError::IdentityUnavailable)?; ExactFileIdentity::new( information.VolumeSerialNumber, information.FileId.Identifier, ) }" &&
    exactMappedImageAuthentication.includes("sys::exact_file_identity(mapped_image)?") &&
    exactMappedImageAuthentication.includes(".eq(identity)") &&
    exactFileIdentitySentinelTest.includes("ExactFileIdentity::new(0, valid_file_id)") &&
    exactFileIdentitySentinelTest.includes("ExactFileIdentity::new(7, [0; 16])") &&
    exactFileIdentitySentinelTest.includes("ExactFileIdentity::new(7, [u8::MAX; 16])") &&
    (exactFileIdentitySentinelTest.match(/ExactImageError::IdentityUnavailable/gu) ?? [])
      .length === 3 &&
    exactFileIdentityEqualityTest.includes(
      "assert_eq!(expected, ExactFileIdentity::new(7, file_id)?)",
    ) &&
    exactFileIdentityEqualityTest.includes(
      "assert_ne!(expected, ExactFileIdentity::new(8, file_id)?)",
    ) &&
    exactFileIdentityEqualityTest.includes("for index in [0_usize, 8, 15]") &&
    exactFileIdentityEqualityTest.includes("mismatched_file_id[index] ^= 1") &&
    exactFileIdentityEqualityTest.includes(
      "assert_ne!(expected, ExactFileIdentity::new(7, mismatched_file_id)?)",
    ) &&
    authenticateBrokerImage.includes("CREATE_PROCESS_DEBUG_EVENT") &&
    authenticateBrokerImage.includes(
      "image.authenticate_mapped_image(event_file.raw())",
    ) &&
    JSON.stringify(brokerCreationFlagNames) ===
      JSON.stringify([
        "CREATE_SUSPENDED",
        "DEBUG_PROCESS",
        "DEBUG_ONLY_THIS_PROCESS",
        "CREATE_NO_WINDOW",
        "CREATE_UNICODE_ENVIRONMENT",
        "EXTENDED_STARTUPINFO_PRESENT",
      ]) &&
    brokerCreationAttributesDefinition.includes(
      "inherited_handles: Box<[HANDLE; 2]>",
    ) &&
    brokerCreationAttributesDefinition.includes("job_handle: Box<[HANDLE; 1]>") &&
    brokerCreationAttributesDefinition.includes(
      "_parent: &'resources InheritedParentProcess<'flight>",
    ) &&
    brokerCreationAttributesDefinition.includes(
      "_stdio: &'resources InheritedNullStdio<'flight>",
    ) &&
    brokerCreationAttributesImplementation.includes(
      "InitializeProcThreadAttributeList(None, 2",
    ) &&
    brokerCreationAttributesImplementation.includes(
      "InitializeProcThreadAttributeList(Some(pointer), 2",
    ) &&
    (brokerCreationAttributesImplementation.match(
      /InitializeProcThreadAttributeList\(/gu,
    ) ?? []).length === 2 &&
    brokerCreationAttributesImplementation.includes(
      "Box::new([parent.raw(), stdio.raw()])",
    ) &&
    brokerCreationAttributesImplementation.includes("Box::new([job.raw()])") &&
    brokerCreationAttributesImplementation.includes(
      "PROC_THREAD_ATTRIBUTE_HANDLE_LIST",
    ) &&
    brokerCreationAttributesImplementation.includes(
      "PROC_THREAD_ATTRIBUTE_JOB_LIST",
    ) &&
    brokerInheritedNullStdio.includes("PCWSTR(NULL_DEVICE.as_ptr())") &&
    brokerInheritedNullStdio.includes("GENERIC_READ.0 | GENERIC_WRITE.0") &&
    brokerInheritedNullStdio.includes("FILE_SHARE_READ | FILE_SHARE_WRITE") &&
    brokerInheritedNullStdio.includes(
      "flight: &'flight InheritableHandleLaunchFlight<'static>",
    ) &&
    brokerInheritedNullStdio.includes("HANDLE_FLAG_INHERIT") &&
    brokerInheritedNullStdio.includes("file_type != FILE_TYPE_CHAR") &&
    brokerInheritedParentProcess.includes(
      "flight: &'flight InheritableHandleLaunchFlight<'static>",
    ) &&
    brokerInheritedParentProcess.includes("true,") &&
    launchBrokerApplicationWrapper.includes(
      "launch_broker_application_with_after_create(",
    ) &&
    launchBrokerApplicationWrapper.includes("|_debuggee| {}") &&
    /#\[cfg\(test\)\]\s*pub\(super\) fn panic_after_create_for_test/u.test(
      brokerSupervisorProduction,
    ) &&
    panicAfterBrokerCreate.includes(
      "launch_broker_application_with_after_create(",
    ) &&
    panicAfterBrokerCreate.includes("std::panic::resume_unwind") &&
    launchBrokerApplicationWithAfterCreate.includes(
      "flight.create_process_with_explicit_handle_list(",
    ) &&
    launchBrokerApplicationWithAfterCreate.includes(
      "startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES",
    ) &&
    launchBrokerApplicationWithAfterCreate.includes(
      "startup.StartupInfo.hStdInput = inherited_stdio.raw()",
    ) &&
    launchBrokerApplicationWithAfterCreate.includes(
      "startup.StartupInfo.hStdOutput = inherited_stdio.raw()",
    ) &&
    launchBrokerApplicationWithAfterCreate.includes(
      "startup.StartupInfo.hStdError = inherited_stdio.raw()",
    ) &&
    (launchBrokerApplicationWithAfterCreate.match(/\bSTARTF_[A-Z_]+\b/gu) ?? [])
      .length === 1 &&
    launchBrokerApplicationWithAfterCreate.includes("creation_flags()") &&
    launchBrokerApplicationWithAfterCreate.includes(
      "debuggee.authenticate_first_event",
    ) &&
    launchBrokerApplicationWithAfterCreate.includes(
      "debuggee.detach_while_suspended",
    ) &&
    launchBrokerApplicationWithAfterCreate.includes("job.verify_exact_member") &&
    launchBrokerApplicationWithAfterCreate.includes("debuggee.start_user_mode") &&
    launchBrokerApplicationWithAfterCreate.indexOf("Debuggee::new(information)") <
      launchBrokerApplicationWithAfterCreate.indexOf("after_create(&debuggee)") &&
    launchBrokerApplicationWithAfterCreate.indexOf("after_create(&debuggee)") <
      launchBrokerApplicationWithAfterCreate.indexOf(
        "debuggee.release_creation_suspend",
      ) &&
    launchBrokerApplicationWithAfterCreate.indexOf(
      "debuggee.authenticate_first_event",
    ) <
      launchBrokerApplicationWithAfterCreate.indexOf(
        "debuggee.detach_while_suspended",
      ) &&
    launchBrokerApplicationWithAfterCreate.indexOf(
      "debuggee.detach_while_suspended",
    ) < launchBrokerApplicationWithAfterCreate.indexOf("job.verify_exact_member") &&
    launchBrokerApplicationWithAfterCreate.indexOf("job.verify_exact_member") <
      launchBrokerApplicationWithAfterCreate.indexOf("debuggee.start_user_mode") &&
    brokerChildKernelContract.includes("SetEvent(unrelated)") &&
    brokerChildKernelContract.includes(
      "[STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE]",
    ) &&
    brokerChildKernelContract.includes("expected != handle") &&
    brokerChildKernelContract.includes("file_type != FILE_TYPE_CHAR") &&
    !brokerSupervisorProduction.includes("UnrelatedSentinel") &&
    !brokerSupervisorProduction.includes("SENTINEL_HANDLE_FILE") &&
    !brokerSupervisorProduction.includes("CreateEventW") &&
    !brokerSupervisorProduction.includes("SetEvent(") &&
    brokerUnrelatedSentinel.includes("fn create(inheritable: bool)") &&
    brokerUnrelatedSentinel.includes("CreateEventW(None, true, false, None)") &&
    brokerUnrelatedSentinel.includes("if inheritable") &&
    brokerUnrelatedSentinel.includes("HANDLE_FLAG_INHERIT") &&
    brokerUnrelatedSentinel.includes("WaitForSingleObject(") &&
    brokerUnrelatedSentinel.includes("== WAIT_TIMEOUT") &&
    brokerSentinelDriver.includes("Command::new(executable)") &&
    brokerSentinelDriver.includes(".arg(ISOLATED_SENTINEL_FIXTURE)") &&
    brokerSentinelDriver.includes('.arg("--exact")') &&
    brokerSentinelDriver.includes('.arg("--ignored")') &&
    brokerSentinelDriver.includes('.arg("--test-threads=1")') &&
    brokerSentinelDriver.includes('.env(ISOLATED_SENTINEL_ENV, "1")') &&
    brokerSentinelDriver.indexOf(".spawn()?") <
      brokerSentinelDriver.indexOf("drop(flight)") &&
    brokerSentinelDriver.indexOf("drop(flight)") <
      brokerSentinelDriver.indexOf("wait_for_isolated_child") &&
    /#\[ignore = "launched only by the single-test sentinel isolation driver"\]\s*fn isolated_inheritable_sentinel_fixture/u.test(
      brokerSupervisor,
    ) &&
    brokerSentinelFixture.indexOf("std::env::var_os(ISOLATED_SENTINEL_ENV)") <
      brokerSentinelFixture.indexOf("arm_unrelated_sentinel(true)") &&
    brokerSentinelFixture.indexOf("arm_unrelated_sentinel(true)") <
      brokerSentinelFixture.indexOf(
        "launch_prepared_release_broker_channel_for_test(",
      ) &&
    brokerSentinelFixture.indexOf(
      "launch_prepared_release_broker_channel_for_test(",
    ) < brokerSentinelFixture.indexOf("assert_not_signaled()") &&
    (brokerSupervisor.match(/arm_unrelated_sentinel\(true\)/gu) ?? []).length === 1 &&
    brokerSentinelWait.includes("child.try_wait()") &&
    brokerSentinelWait.includes("Instant::now() < deadline") &&
    brokerSentinelWait.includes("child.kill()") &&
    (brokerSentinelWait.match(/child\.wait\(\)/gu) ?? []).length === 2 &&
    !/QueryInformationJobObject\(\s*None/u.test(brokerSupervisorProduction) &&
    !/false\s*&&/u.test(brokerSupervisor) &&
    authenticateBrokerImage.includes("GetLastError()") &&
    authenticateBrokerImage.includes("ERROR_SEM_TIMEOUT") &&
    authenticateBrokerImage.includes("classify_debug_wait_failure") &&
    brokerDebugWaitClassifier.includes("timed_out && Instant::now() >= deadline") &&
    brokerDebugWaitClassifier.includes("DormantBrokerError::Deadline") &&
    brokerDebugWaitClassifier.includes("DormantBrokerError::ProcessProof") &&
    brokerSupervisorProduction.includes("JOB_OBJECT_LIMIT_ACTIVE_PROCESS") &&
    brokerSupervisorProduction.includes("JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE") &&
    brokerJobImplementation.includes("ActiveProcessLimit = 1") &&
    brokerJobImplementation.includes("IsProcessInJob(") &&
    brokerJobImplementation.includes("accounting.ActiveProcesses != 1") &&
    brokerJobImplementation.includes("QueryInformationJobObject(") &&
    brokerJobImplementation.includes("Some(self.raw())") &&
    brokerSupervisorProduction.includes(
      "unsafe impl Send for ProcessObservation {}",
    ) &&
    !brokerSupervisorProduction.includes(
      "unsafe impl Sync for ProcessObservation",
    ) &&
    duplicateBrokerProcessObservation.includes("PROCESS_SYNCHRONIZE.0") &&
    duplicateBrokerProcessObservation.includes("false,") &&
    !/\bfn\s+raw\b/u.test(brokerProcessObservationImplementation) &&
    brokerSupervisor.includes(
      "panic_after_create_terminates_and_reaps_the_exact_child",
    ) &&
    brokerSupervisor.includes(
      "debug_wait_timeout_maps_to_deadline_only_at_absolute_expiry",
    ) &&
    !/\bOpenProcess\s*\(/u.test(
      [brokerChannelProduction, brokerSupervisorProduction].join("\n"),
    ),
  "dormant Broker creation must retain full FILE_ID_INFO identity, exact NUL/parent and Job attributes, pre-user-mode ordering, kernel probes, deadlines, cleanup, and no PID reopen",
);
const brokerChannelModuleDocs = brokerChannelProduction.slice(
  0,
  brokerChannelProduction.indexOf("use core::fmt;"),
);
requireInvariant(
  brokerChannelModuleDocs.includes("persistent, secretless, process-bound multi-frame") &&
    brokerChannelModuleDocs.includes("broker_supervisor") &&
    brokerChannelModuleDocs.includes("payload-only `broker::ipc` adapters") &&
    !/(?:one-shot|unimplemented|future exact launcher|constructor intentionally does not exist)/iu.test(
      brokerChannelModuleDocs,
    ) &&
    !platformWindowsLib.includes(
      "This one-shot, secretless native-host/Broker transport proof",
    ) &&
    !platformWindowsLib.includes(
      "composition with `broker::ipc` are still release-blocking",
    ),
  "platform Broker module docs must describe the current persistent debug composition rather than stale future/one-shot blockers",
);
for (const [document, label] of [
  [architectureDocument, "architecture"],
  [brokerProtocolContract, "protocol contract"],
  [nativeHostContractReadme, "native-host README"],
]) {
  requireInvariant(
    /HANDLE_LIST[^\n]*\[restricted\s+parent\s+process,\s*shared\s+read\/write\s+NUL\]/u.test(
      document,
    ) &&
      document.includes("STARTF_USESTDHANDLES") &&
      /(?:stdin, stdout, and stderr[\s\S]{0,100}same NUL|same NUL[\s\S]{0,100}stdin, stdout, and stderr)/u.test(
        document,
      ) &&
      /JOB_LIST[^\n]*\[job\]/u.test(document),
    `${label} must retain the exact parent/NUL HANDLE_LIST, shared NUL standard streams, and one-Job JOB_LIST contract`,
  );
}

requireInvariant(
  brokerLibraryForContract.includes(
    '#[cfg(any(test, all(feature = "ipc-contract-test-hook", debug_assertions)))]',
  ) &&
    brokerMainForContract.includes("std::process::exit(78);") &&
    nativeMain.includes("native_host::run_release_disabled_stream") &&
    nativeMain.includes("std::process::exit(PRIVATE_BROKER_UNAVAILABLE);"),
  "default and release Broker/native-host entrypoints must retain exit-78 gating",
);
requireInvariant(
  /#\[cfg\(any\(test,\s*all\(feature = "ipc-contract-test-hook", debug_assertions\)\)\)\]\s*#\[derive\([^\]]+\)\]\s*pub\(crate\) enum SecretlessLocalOutcome/u.test(
    brokerTransportForContract,
  ) &&
    /#\[cfg\(any\(test,\s*all\(feature = "ipc-contract-test-hook", debug_assertions\)\)\)\]\s*pub\(crate\) fn execute_secretless_local/u.test(
      brokerTransportForContract,
    ) &&
    !brokerLibraryForContract.includes("SecretlessLocalOutcome"),
  "Broker local chain-ID success must remain crate-private and absent outside tests or the debug feature gate",
);
requireInvariant(
  nativeMain.includes("std::env::current_exe()") &&
    nativeMain.includes("executable.set_file_name(") &&
    nativeMain.includes("std::fs::symlink_metadata(&executable)") &&
    nativeMain.includes("metadata.file_type().is_file()") &&
    nativeMain.includes("struct BrokerChildGuard") &&
    nativeMain.includes("impl Drop for BrokerChildGuard") &&
    nativeMain.includes("self.0.kill()") &&
    nativeMain.includes("self.0.wait()") &&
    nativeMain.includes(".env_clear()") &&
    !nativeMain.includes("YOUR_WALLET_BROKER_CONTRACT_EXE") &&
    !nativeProcessContractTest.includes("YOUR_WALLET_BROKER_CONTRACT_EXE"),
  "debug native host must select only its regular-file Broker sibling and reap it on every exit or unwind",
);
requireInvariant(
  brokerIpcContract.includes("BrokerIpcError::Io") &&
    nativeLibraryForContract.includes("FrameError::Io") &&
    !/Io\s*\(\s*#\[source\]|Io\s*\(\s*(?:std::)?io::Error/u.test(
      `${brokerIpcContract}\n${nativeLibraryForContract}`,
    ) &&
    brokerIpcContract.includes("std::error::Error::source(&error).is_none()") &&
    nativeLibraryForContract.includes("std::error::Error::source(&error).is_none()"),
  "native and Broker transport errors must retain only a stable I/O category with no raw source chain",
);
const unavailableWireBlock =
  /struct\s+UnavailableRequestWire\s*\{(?<body>[\s\S]*?)\n\}/u.exec(
    brokerIpcContract,
  )?.groups?.body ?? "";
const unavailableMethodBlock =
  /enum\s+UnavailableMethodWire\s*\{(?<body>[\s\S]*?)\n\}/u.exec(
    brokerIpcContract,
  )?.groups?.body ?? "";
requireInvariant(
  brokerIpcContract.includes("MAX_BROKER_IPC_FRAME_BYTES: usize = 8_192") &&
    brokerIpcContract.includes("MAX_BROKER_IPC_COMMANDS: u64 = 4_096") &&
    brokerIpcContract.includes(
      "summary.commands >= MAX_BROKER_IPC_COMMANDS",
    ) &&
    brokerIpcContract.includes(
      "server_accepts_exact_command_lifetime_and_rejects_the_next_frame_before_dispatch",
    ) &&
    brokerIpcContract.includes("BrokerIpcClient::connect") &&
    brokerIpcContract.includes("pub fn run_secretless_server") &&
    brokerIpcContract.includes("ClientBodyWire::Unavailable") &&
    brokerIpcContract.includes("complete_unavailable(transport)") &&
    unavailableWireBlock.includes("session_id: FixedHex<32>") &&
    unavailableWireBlock.includes("request_sequence: u64") &&
    unavailableWireBlock.includes("activation_nonce: FixedHex<32>") &&
    unavailableWireBlock.includes("request_id: FixedHex<16>") &&
    unavailableWireBlock.includes("method: UnavailableMethodWire") &&
    !/(?:params|message|account|address|origin|method_name|serde_json::Value)/u.test(
      unavailableWireBlock,
    ) &&
    unavailableMethodBlock.includes("PersonalSign") &&
    unavailableMethodBlock.includes("SendTransaction") &&
    !/\bChainId\b/u.test(unavailableMethodBlock),
  "debug unavailable IPC must retain exact frame/session bounds, enum-only correlation, and no chainId replacement",
);
requireInvariant(
  nativeContractBridge.includes('request.method_name() == "eth_chainId"') &&
    nativeContractBridge.includes("broker.complete_unavailable(") &&
    nativeContractBridge.includes("TransportCancellationOutcome::AlreadyCompleted") &&
    nativeContractBridge.includes("return Err(ProtocolError::SessionSequence.into())") &&
    !/(?:KeyAgent|DownstreamExecutor|eth_sendRawTransaction|http::|https::)/u.test(
      nativeContractBridge,
    ),
  "debug native contract must remain chainId-only, completion-bound, and network/signing-free",
);
requireInvariant(
  extensionBackgroundContract.includes(
    "const MAX_NATIVE_CONNECTION_ATTEMPTS = 4_096",
  ) &&
    extensionBackgroundContract.includes(
      "this.sessionId = this.issuePortNonce()",
    ) &&
    extensionBackgroundContract.includes(
      "value.sequence !== this.lastNativeSequence + 1",
    ) &&
    extensionBackgroundContract.includes("this.outboundSequence = 0") &&
    extensionBackgroundContract.includes(
      "sequence = this.nextOutboundSequenceCandidate()",
    ) &&
    extensionBackgroundContract.includes("this.outboundSequence = sequence") &&
    extensionBackgroundContract.includes("normalizeCancelReason(reason)") &&
    extensionBackgroundContract.includes("Number.isSafeInteger(value.code)") &&
    extensionBackgroundContract.includes("value.message.length > 0"),
  "extension reconnect must rotate sessions, reset request sequence, reject response gaps, avoid local sequence holes, normalize cancel reasons, enforce exact RPC errors, and remain bounded",
);
requireInvariant(
  nativeProcessContractTest.includes('"--offline", "--locked"') &&
    nativeProcessContractTest.includes('"--release"') &&
    nativeProcessContractTest.includes('"--all-features"') &&
    nativeProcessContractTest.includes("windowsHide: true") &&
    nativeProcessContractTest.includes("cancelled.disconnect(\"navigation\")") &&
    nativeProcessContractTest.includes("router.reconnectNative()") &&
    nativeProcessContractTest.includes("{ code: 78, signal: null }") &&
    !/(?:puppeteer|playwright|selenium|launchPersistentContext)/iu.test(
      nativeProcessContractTest,
    ),
  "real bridge evidence must stay offline, headless, cancel/reconnect aware, and release-exit-78 checked",
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

const repositoryPowerShellScripts = await repositoryPowerShellSources();
const repositoryPowerShellScriptsByPath = new Map(
  repositoryPowerShellScripts.map((script) => [script.path.toLowerCase(), script]),
);
function repositoryPowerShellSource(path) {
  const script = repositoryPowerShellScriptsByPath.get(path.toLowerCase());
  if (script === undefined) {
    throw new Error(`approved PowerShell source is missing: ${path}`);
  }
  return script.source;
}
const releasePolicyTests = await releasePolicyTestSources();
const releasePolicyTestsByPath = new Map(
  releasePolicyTests.map((test) => [test.path.toLowerCase(), test]),
);
function releasePolicyTestSource(path) {
  const test = releasePolicyTestsByPath.get(path.toLowerCase());
  if (test === undefined) {
    throw new Error(`approved release-policy test is missing: ${path}`);
  }
  return test.source;
}

const releaseVerifier = repositoryPowerShellSource(
  "scripts/release/verify-release-offline.ps1",
);
const releaseCommon = repositoryPowerShellSource("scripts/release/common.ps1");
const releaseCommonTests = repositoryPowerShellSource(
  "scripts/release/common.test.ps1",
);
const releaseUnsignedPreparation = repositoryPowerShellSource(
  "scripts/release/prepare-unsigned.ps1",
);
const releaseAuthenticodeVerifier = repositoryPowerShellSource(
  "scripts/release/verify-authenticode.ps1",
);
const releaseVerifierToolsetPreparation = repositoryPowerShellSource(
  "scripts/release/prepare-verifier-toolset.ps1",
);
const releaseVerifierToolsetTests = repositoryPowerShellSource(
  "scripts/release/verifier-toolset.test.ps1",
);
const releaseCheck = repositoryPowerShellSource("scripts/release/check.ps1");
const releaseManifestVerifier = await text("scripts/release/release-manifest.mjs");
const releaseManifestTests = releasePolicyTestSource(
  "scripts/release/release-manifest.test.mjs",
);
const releaseManifestAssembler = await text("scripts/release/assemble-manifest.mjs");
const releaseReviewEvidenceSet = await text("scripts/release/review-evidence-set.mjs");
const releaseReviewEvidenceSetWrapper = repositoryPowerShellSource(
  "scripts/release/review-evidence-set.ps1",
);
const releaseReviewEvidenceSetTests = releasePolicyTestSource(
  "scripts/release/review-evidence-set.test.mjs",
);
const releaseVerifierIntegrationTests = releasePolicyTestSource(
  "scripts/release/release-verifier-integration.test.mjs",
);
const releaseExtensionAuditTests = releasePolicyTestSource(
  "scripts/release/audit-extension.test.mjs",
);
const releaseInventoryTests = releasePolicyTestSource(
  "scripts/release/generate-inventories.test.mjs",
);
const approvedSealedReleasePowerShellEntryPaths = [
  "scripts/release/check.ps1",
  "scripts/release/common.test.ps1",
  "scripts/release/prepare-unsigned.ps1",
  "scripts/release/prepare-verifier-toolset.ps1",
  "scripts/release/review-evidence-set.ps1",
  "scripts/release/verifier-toolset.test.ps1",
  "scripts/release/verify-authenticode.ps1",
  "scripts/release/verify-release-offline.ps1",
];
const approvedOtherPowerShellScriptPaths = [
  "scripts/check.ps1",
  "scripts/launcher-contract.test.ps1",
  "scripts/release/common.ps1",
  "scripts/run-sepolia-wallet.ps1",
];
const approvedRepositoryPowerShellScriptPaths = [
  ...approvedSealedReleasePowerShellEntryPaths,
  ...approvedOtherPowerShellScriptPaths,
];
const approvedPowerShellSourceSha256 = Object.freeze({
  "scripts/check.ps1": "ec9f3f41d47008f2579047b4ef157af933b998c61a8a35ac37c418696810f25f",
  "scripts/launcher-contract.test.ps1": "4b82c49f96d4b90da0cabb17992a8ae7f77c5664796730aab6e6ff65a3649b50",
  "scripts/release/check.ps1": "a9d5d263f07a5bd8459597e3749aa5617708ac0b87536ca6fdd3341adfcde378",
  "scripts/release/common.ps1": "82368bd92780baaffd487c5b674203349a7a4f1ee56b9d71a4ba3e58bd3db5fb",
  "scripts/release/common.test.ps1": "d67800a958a60df98ccbdf8d522344cc3f84d49c44b373d9dfc46faf851442a7",
  "scripts/release/prepare-unsigned.ps1": "5b84c796d4a9899b37666f295793e193b101e0a3564d7492ea26dd00bd0cbb3b",
  "scripts/release/prepare-verifier-toolset.ps1": "0523e4a106675d161a385e50fea097d859a9e0a3c942396ca4c1de0d0224a013",
  "scripts/release/review-evidence-set.ps1": "1d9575c405d0c01d3787270c5d5853a13f814ac0636cb7959ef7dc0d7d8e53fa",
  "scripts/release/verifier-toolset.test.ps1": "aa9f4e1e4a13a47dba1032c528a0f0e2febf09134653b4300cd82c57fe766945",
  "scripts/release/verify-authenticode.ps1": "179923bb1c5cf2acd349fd97e5c7731a63fefe8627969afaf6447d4841f3bbdd",
  "scripts/release/verify-release-offline.ps1": "8f25897182ab4da26cd40b0f8abe4259cf9d72b3d69ac2c7bd007b987fe5bff6",
  "scripts/run-sepolia-wallet.ps1": "6f80276eca155ecd7af5165ac8b973e00dabeab6e8d3c4ea2b50517666d104c2",
});
const approvedReleasePolicyTestSha256 = Object.freeze({
  "scripts/release/audit-extension.test.mjs": "ad38466ba18481611a6e55575231b313c12644464d643580edc9aaede73a6906",
  "scripts/release/generate-inventories.test.mjs": "cf6a80cd902dc3a35fc88a8cb5c65fe84790254bc1e9693a0404a311223f7dbc",
  "scripts/release/release-manifest.test.mjs": "4549e101f37087dcde8ed02ceeef9fb68db88c6593475a3a06b9496c7b11eb6a",
  "scripts/release/release-verifier-integration.test.mjs": "9094bc4d988c3290d6f7b3bf7243367ac90499c470e500205f5c49a40993b80e",
  "scripts/release/review-evidence-set.test.mjs": "b556b49d3c349c6519edddf5817e16972540ed55f613cb208a738c4e3ed6f470",
});
const sealedReleasePowerShellEntries = approvedSealedReleasePowerShellEntryPaths
  .map((path) => repositoryPowerShellScriptsByPath.get(path.toLowerCase()))
  .filter((script) => script !== undefined);
const discoveredReleaseCommonConsumerPaths = repositoryPowerShellScripts
  .filter(
    ({ path, source }) =>
      path.toLowerCase() !== "scripts/release/common.ps1" &&
      powerShellReferencesReleaseCommon(source),
  )
  .map(({ path }) => path);
const releaseCommonPowerShellAnalysis = analyzePowerShellSource(releaseCommon);
const releaseCommonTestsPowerShellAnalysis = analyzePowerShellSource(releaseCommonTests);
const releaseVerifierToolsetTestsPowerShellAnalysis = analyzePowerShellSource(
  releaseVerifierToolsetTests,
);
const releaseCheckPowerShellAnalysis = analyzePowerShellSource(releaseCheck);
const releaseWrapperCeremonyStart = releaseCommonTests.indexOf(
  "$wrapperToolsetRoot =",
);
const releaseWrapperCeremonyEnd = releaseCommonTests.indexOf(
  'Write-Output "POWERSHELL_RELEASE_HELPERS_PASS"',
  releaseWrapperCeremonyStart,
);
const releaseWrapperCeremonyBlock =
  releaseWrapperCeremonyStart >= 0 && releaseWrapperCeremonyEnd > releaseWrapperCeremonyStart
    ? releaseCommonTests.slice(releaseWrapperCeremonyStart, releaseWrapperCeremonyEnd)
    : "";
const missingHostFlagProbeStart = activePowerShellLiteralIndexes(
  releaseVerifierToolsetTestsPowerShellAnalysis,
  '$missingFlagProbePath = Join-Path $probeRoot "missing-host-flag.ps1"',
)[0] ?? -1;
const missingHostFlagProbeEnd = activePowerShellLiteralIndexes(
  releaseVerifierToolsetTestsPowerShellAnalysis,
  '$wrapperPath = Join-Path $PSScriptRoot "verify-release-offline.ps1"',
).find((index) => index > missingHostFlagProbeStart) ?? -1;
const missingHostFlagProbeBlock =
  missingHostFlagProbeStart >= 0 && missingHostFlagProbeEnd > missingHostFlagProbeStart
    ? releaseVerifierToolsetTestsPowerShellAnalysis.commentFreeCode.slice(
        missingHostFlagProbeStart,
        missingHostFlagProbeEnd,
      )
    : "";
const releaseTestSuiteNames = releasePolicyTests.map(({ path }) =>
  path.slice("scripts/release/".length),
);
const releaseSecurity = await text("docs/release-security.md");
const ciWorkflow = await text(".github/workflows/ci.yml");
const releaseEvidencePolicyWorkflow = await text(
  ".github/workflows/release-evidence-policy.yml",
);
const trustedReleaseModuleNamesBlock =
  /foreach \(\$moduleName in @\((?<body>[\s\S]*?)\)\) \{\s*\$manifestPath =/u.exec(
    releaseCommon,
  )?.groups?.body ?? "";
const trustedReleaseModuleNames = [
  ...trustedReleaseModuleNamesBlock.matchAll(/"(?<name>Microsoft\.PowerShell\.[A-Za-z]+)"/gu),
].map((match) => match.groups.name);
const approvedReleaseEntryScriptNamesBlock =
  /foreach \(\$approvedEntryScriptName in @\((?<body>[\s\S]*?)\)\) \{/u.exec(
    releaseCommon,
  )?.groups?.body ?? "";
const approvedReleaseEntryScriptNames = [
  ...approvedReleaseEntryScriptNamesBlock.matchAll(/"(?<name>[A-Za-z0-9.-]+\.ps1)"/gu),
].map((match) => match.groups.name);
const releaseBootstrapPreflightOrder = [
  'foreach ($protectedTypeName in @(',
  'foreach ($visibleAlias in @(',
  "$getModuleCommand =",
  "@(& $getModuleCommand -All -ErrorAction Stop).Count -ne 0",
  'foreach ($coreCommandName in @(',
  'foreach ($moduleCommandName in @(',
  "$trustedModules =",
  'foreach ($moduleName in @(',
].map((marker) => releaseCommon.indexOf(marker));
const offlineReleaseVerificationBlock = rustItemBlock(
  releaseVerifier,
  /(?:^|\n)function Invoke-OfflineReleaseVerification\s*\{/u,
);
const offlineReleaseRequiredValueNamesBlock =
  /-RequiredValueNames\s+@\((?<body>[\s\S]*?)\)\s*`/u.exec(releaseVerifier)?.groups?.body ?? "";
const offlineReleaseRequiredValueNames = [
  ...offlineReleaseRequiredValueNamesBlock.matchAll(/"(?<name>[A-Za-z][A-Za-z0-9]*)"/gu),
].map((match) => match.groups.name);
const validateReleaseManifestBlock = rustItemBlock(
  releaseManifestVerifier,
  /(?:^|\n)export function validateManifest\s*\(/u,
);
const resolveExactReleasePathBlock = rustItemBlock(
  releaseManifestVerifier,
  /(?:^|\n)export async function resolveExactReleasePath\s*\(/u,
);
const assertNoReparseComponentsBlock = rustItemBlock(
  releaseManifestVerifier,
  /(?:^|\n)async function assertNoReparseComponents\s*\(/u,
);
const verifyExpectedExtensionIdBlock = rustItemBlock(
  releaseManifestVerifier,
  /(?:^|\n)export function verifyExpectedExtensionId\s*\(/u,
);
const validateExpectedReleaseSequenceBlock = rustItemBlock(
  releaseManifestVerifier,
  /(?:^|\n)function validateExpectedReleaseSequence\s*\(/u,
);
const verifyExpectedReleaseSequenceBlock = rustItemBlock(
  releaseManifestVerifier,
  /(?:^|\n)export function verifyExpectedReleaseSequence\s*\(/u,
);
const runReleaseManifestCliBlock = rustItemBlock(
  releaseManifestVerifier,
  /(?:^|\n)async function runCli\s*\(/u,
);
const extensionPinUnitTestBlock = rustItemBlock(
  releaseManifestTests,
  /(?:^|\n)test\("release verification requires an independently pinned stable extension id"/u,
);
const extensionLineageUnitTestBlock = rustItemBlock(
  releaseManifestTests,
  /(?:^|\n)test\("successor cannot rotate the stable extension identity"/u,
);
const releaseSequenceSuccessUnitTestBlock = rustItemBlock(
  releaseManifestTests,
  /(?:^|\n)test\("release sequence pin accepts exact initial and successor candidates"/u,
);
const releaseSequenceReplayUnitTestBlock = rustItemBlock(
  releaseManifestTests,
  /(?:^|\n)test\("release sequence pin rejects an old sequence-1 replay without echoing either value"/u,
);
const releaseSequenceFormatUnitTestBlock = rustItemBlock(
  releaseManifestTests,
  /(?:^|\n)test\("release sequence pin rejects malformed and leading-zero values"/u,
);
const releaseSequenceRequiredCliTestBlock = rustItemBlock(
  releaseManifestTests,
  /(?:^|\n)test\("verify CLI requires the external release sequence before reading candidate files"/u,
);
const releaseSequenceArityCliTestBlock = rustItemBlock(
  releaseManifestTests,
  /(?:^|\n)test\("verify CLI rejects extra and malformed sequence arguments before reading candidate files"/u,
);
const releaseSequencePairCliTestBlock = rustItemBlock(
  releaseManifestTests,
  /(?:^|\n)test\("verify CLI derives previous-input shape from the external release sequence before file reads"/u,
);
const extensionPinAttackerIntegrationTestBlock = rustItemBlock(
  releaseVerifierIntegrationTests,
  /(?:^|\n)test\("verify CLI rejects a self-consistent signed attacker-selected extension id without echo"/u,
);
const rebindSyntheticExtensionIdentityBlock = rustItemBlock(
  releaseVerifierIntegrationTests,
  /(?:^|\n)async function rebindSyntheticExtensionIdentity\s*\(/u,
);
const extensionPinSuccessIntegrationTestBlock = rustItemBlock(
  releaseVerifierIntegrationTests,
  /(?:^|\n)test\("verify CLI accepts the exact initial-release arity and cryptographic bindings"/u,
);
const extensionPinArityIntegrationTestBlock = rustItemBlock(
  releaseVerifierIntegrationTests,
  /(?:^|\n)test\("verify CLI rejects missing and extra extension-pin arguments"/u,
);
const extensionPinWrapperIntegrationTestBlock = rustItemBlock(
  releaseVerifierIntegrationTests,
  /(?:^|\n)test\("offline wrapper requires case-sensitive identity pins and a sealed verifier toolset"/u,
);
const computeReviewedEvidenceSetBlock = rustItemBlock(
  releaseManifestVerifier,
  /(?:^|\n)export function computeReviewedEvidenceSetSha256\s*\(/u,
);
const computeManifestReviewedEvidenceSetBlock = rustItemBlock(
  releaseManifestVerifier,
  /(?:^|\n)export function computeManifestReviewedEvidenceSetSha256\s*\(/u,
);
const validateIndependentReviewAttestationBlock = rustItemBlock(
  releaseManifestVerifier,
  /(?:^|\n)export function validateIndependentReviewAttestation\s*\(/u,
);
const verifyEvidenceAttestationsBlock = rustItemBlock(
  releaseManifestVerifier,
  /(?:^|\n)export async function verifyEvidenceAttestations\s*\(/u,
);
const assembleReleaseManifestRunBlock = rustItemBlock(
  releaseManifestAssembler,
  /(?:^|\n)async function run\s*\(/u,
);
const collectReviewedEvidenceSetSubjectBlock = rustItemBlock(
  releaseReviewEvidenceSet,
  /(?:^|\n)export async function collectReviewedEvidenceSetSubject\s*\(/u,
);
const reviewEvidenceSetTreeBlock = rustItemBlock(
  releaseReviewEvidenceSet,
  /(?:^|\n)async function verifyExactEvidenceTree\s*\(/u,
);
const reviewEvidenceSetPinnedFileBlock = rustItemBlock(
  releaseReviewEvidenceSet,
  /(?:^|\n)async function openPinnedFileRecord\s*\(/u,
);
const reviewEvidenceSetPinnedPathBlock = rustItemBlock(
  releaseReviewEvidenceSet,
  /(?:^|\n)async function verifyPinnedFilePath\s*\(/u,
);
const reviewEvidenceSetMetadataIdentityBlock = rustItemBlock(
  releaseReviewEvidenceSet,
  /(?:^|\n)function samePinnedMetadata\s*\(/u,
);
const reviewEvidenceSetSupportedIdentityBlock = rustItemBlock(
  releaseReviewEvidenceSet,
  /(?:^|\n)function hasSupportedPinnedIdentity\s*\(/u,
);
const reviewEvidenceDigestUnitTestBlock = rustItemBlock(
  releaseManifestTests,
  /(?:^|\n)test\("independent review evidence commitment is exact, canonical, and non-circular"/u,
);
const reviewAttestationV2UnitTestBlock = rustItemBlock(
  releaseManifestTests,
  /(?:^|\n)test\("independent review attestation v2 binds the reviewed evidence set"/u,
);
const reviewNativeReplacementTestBlock = rustItemBlock(
  releaseVerifierIntegrationTests,
  /(?:^|\n)test\("old reviewer signature rejects a release-signed native-host evidence replacement"/u,
);
const reviewRefreshedCommitmentOldSignatureTestBlock = rustItemBlock(
  releaseVerifierIntegrationTests,
  /(?:^|\n)test\("a refreshed v2 commitment cannot reuse the old reviewer signature under a fresh release signature"/u,
);
const reviewExternalRolePinsTestBlock = rustItemBlock(
  releaseVerifierIntegrationTests,
  /(?:^|\n)test\("verify CLI keeps release, Authenticode, and reviewer pins in distinct external roles"/u,
);
const reviewWindowsReplacementTestBlock = rustItemBlock(
  releaseVerifierIntegrationTests,
  /(?:^|\n)test\("old reviewer signature rejects a release-signed Windows-negative log replacement"/u,
);
const reviewAdvisoryReplacementTestBlock = rustItemBlock(
  releaseVerifierIntegrationTests,
  /(?:^|\n)test\("old reviewer signature rejects advisory evidence and policy replacement"/u,
);
const reviewV1RejectionTestBlock = rustItemBlock(
  releaseVerifierIntegrationTests,
  /(?:^|\n)test\("independent review attestation v1 fails closed even with a valid old-schema signature"/u,
);
const reviewAssemblyIntegrationTestBlock = rustItemBlock(
  releaseVerifierIntegrationTests,
  /(?:^|\n)test\("manifest assembly independently enforces review evidence-set v2 before output"/u,
);
const reviewSubjectSuccessTestBlock = rustItemBlock(
  releaseReviewEvidenceSetTests,
  /(?:^|\n)test\("review evidence-set subject is exact, deterministic, and read-only"/u,
);
const reviewSubjectFileSetTestBlock = rustItemBlock(
  releaseReviewEvidenceSetTests,
  /(?:^|\n)test\("review evidence-set command rejects missing, extra, and case-aliased files without path disclosure"/u,
);
const reviewSubjectHardlinkTestBlock = rustItemBlock(
  releaseReviewEvidenceSetTests,
  /(?:^|\n)test\("review evidence-set command rejects hard-linked evidence"/u,
);
const reviewSubjectArityTestBlock = rustItemBlock(
  releaseReviewEvidenceSetTests,
  /(?:^|\n)test\("review evidence-set command rejects missing and extra arguments"/u,
);
const reviewSubjectWrapperTestBlock = rustItemBlock(
  releaseReviewEvidenceSetTests,
  /(?:^|\n)test\("Windows review wrapper holds one offline read-only tree around the exact subject command"/u,
);
const reviewSubjectWrapperPrivacyTestBlock = rustItemBlock(
  releaseReviewEvidenceSetTests,
  /(?:^|\n)\s*async \(\) => \{\s*const privateParent = await mkdtemp\(path\.join\(os\.tmpdir\(\), "your-wallet-review-wrapper-private-"\)\)/u,
);

function analyzePowerShellSource(source) {
  const normalized = source
    .replace(/^\uFEFF/u, "")
    .replace(/\r\n?/gu, "\n");
  const commentFree = normalized.split("");
  const executable = normalized.split("");
  const activeCode = new Uint8Array(normalized.length);
  let state = "code";
  let blockCommentDepth = 0;
  let hereStringQuote = "";
  let hasRequiresDirective = false;
  let hasExpandableSubexpression = false;

  const blank = (characters, index) => {
    if (characters[index] !== "\n") characters[index] = " ";
  };
  const blankBoth = (index) => {
    blank(commentFree, index);
    blank(executable, index);
  };
  const lineEndAfter = (index) => {
    const lineEnd = normalized.indexOf("\n", index);
    return lineEnd < 0 ? normalized.length : lineEnd;
  };
  const isHereStringBoundary = (index, token) => {
    if (!normalized.startsWith(token, index)) return false;
    const lineEnd = lineEndAfter(index + token.length);
    return /^[ \t]*$/u.test(
      normalized.slice(index + token.length, lineEnd),
    );
  };

  for (let index = 0; index < normalized.length; index += 1) {
    const character = normalized[index];
    const next = normalized[index + 1];

    if (state === "line-comment") {
      blankBoth(index);
      if (character === "\n") state = "code";
      continue;
    }
    if (state === "block-comment") {
      blankBoth(index);
      if (character === "<" && next === "#") {
        blankBoth(index + 1);
        blockCommentDepth += 1;
        index += 1;
      } else if (character === "#" && next === ">") {
        blankBoth(index + 1);
        blockCommentDepth -= 1;
        index += 1;
        if (blockCommentDepth === 0) state = "code";
      }
      continue;
    }
    if (state === "here-string") {
      const atLineStart = index === 0 || normalized[index - 1] === "\n";
      const terminator = `${hereStringQuote}@`;
      if (atLineStart && normalized.startsWith(terminator, index)) {
        blankBoth(index);
        blankBoth(index + 1);
        index += 1;
        state = "code";
        hereStringQuote = "";
      } else {
        if (hereStringQuote === '"' && character === "$" && next === "(") {
          hasExpandableSubexpression = true;
        }
        blankBoth(index);
      }
      continue;
    }
    if (state === "single-string") {
      blank(executable, index);
      if (character === "'" && next === "'") {
        blank(executable, index + 1);
        index += 1;
      } else if (character === "'") {
        state = "code";
      }
      continue;
    }
    if (state === "double-string") {
      blank(executable, index);
      if (character === "$" && next === "(") {
        hasExpandableSubexpression = true;
      }
      if (character === "`") {
        if (index + 1 < normalized.length) blank(executable, index + 1);
        index += 1;
      } else if (character === '"' && next === '"') {
        blank(executable, index + 1);
        index += 1;
      } else if (character === '"') {
        state = "code";
      }
      continue;
    }

    if (
      character === "@" &&
      (next === "'" || next === '"') &&
      isHereStringBoundary(index, `${character}${next}`)
    ) {
      const lineEnd = lineEndAfter(index + 2);
      hereStringQuote = next;
      for (let offset = index; offset < lineEnd; offset += 1) blankBoth(offset);
      index = lineEnd - 1;
      state = "here-string";
      continue;
    }
    if (character === "<" && next === "#") {
      blankBoth(index);
      blankBoth(index + 1);
      blockCommentDepth = 1;
      state = "block-comment";
      index += 1;
      continue;
    }
    if (character === "#") {
      const directive = normalized.slice(index, index + 9);
      const afterDirective = normalized[index + 9] ?? "";
      if (
        directive.toLowerCase() === "#requires" &&
        !/[A-Za-z0-9_-]/u.test(afterDirective)
      ) {
        hasRequiresDirective = true;
      }
      blankBoth(index);
      state = "line-comment";
      continue;
    }
    if (character === "'") {
      blank(executable, index);
      state = "single-string";
      continue;
    }
    if (character === '"') {
      blank(executable, index);
      state = "double-string";
      continue;
    }
    activeCode[index] = 1;
    if (character === "`" && index + 1 < normalized.length) {
      activeCode[index + 1] = 1;
      index += 1;
    }
  }

  const valid =
    (state === "code" || state === "line-comment") &&
    !hasExpandableSubexpression;
  const executableCode = executable.join("");
  return {
    activeCode,
    commentFreeCode: commentFree.join(""),
    executableCode,
    hasPreExecutionDirective:
      hasRequiresDirective || /^[^\S\r\n]*using\b/imu.test(executableCode),
    valid,
  };
}

function activePowerShellMatches(analysis, pattern) {
  if (!pattern.global) {
    throw new Error("active PowerShell match patterns must be global");
  }
  return [...analysis.commentFreeCode.matchAll(pattern)].filter(
    (match) => analysis.activeCode[match.index] === 1,
  );
}

function activePowerShellLiteralIndexes(analysis, literal) {
  const indexes = [];
  let cursor = 0;
  for (;;) {
    const index = analysis.commentFreeCode.indexOf(literal, cursor);
    if (index < 0) return indexes;
    if (analysis.activeCode[index] === 1) indexes.push(index);
    cursor = index + literal.length;
  }
}

function powerShellReferencesReleaseCommon(source) {
  const analysis = analyzePowerShellSource(source);
  return (
    /common[^.\r\n]{0,80}\.ps1/iu.test(analysis.commentFreeCode) ||
    activePowerShellLiteralIndexes(
      analysis,
      "ReleasePowerShellEntryScriptPath",
    ).length > 0
  );
}

function powerShellBraceDepthAt(analysis, targetIndex) {
  let depth = 0;
  for (let index = 0; index < targetIndex; index += 1) {
    const character = analysis.executableCode[index];
    if (character === "{") depth += 1;
    else if (character === "}") depth -= 1;
    if (depth < 0) return -1;
  }
  return depth;
}

function hasOneActivePowerShellMatchAtBraceDepth(
  analysis,
  pattern,
  expectedDepth,
) {
  const matches = activePowerShellMatches(analysis, pattern);
  return (
    matches.length === 1 &&
    powerShellBraceDepthAt(analysis, matches[0].index) === expectedDepth
  );
}

function hasOneActivePowerShellLiteralAtBraceDepth(
  analysis,
  literal,
  expectedDepth,
) {
  const indexes = activePowerShellLiteralIndexes(analysis, literal);
  return (
    indexes.length === 1 &&
    powerShellBraceDepthAt(analysis, indexes[0]) === expectedDepth
  );
}

function skipPowerShellTrivia(source, initialIndex) {
  let index = initialIndex;
  for (;;) {
    while (/\s/u.test(source[index] ?? "")) index += 1;
    if (source[index] === "#") {
      const lineEnd = source.indexOf("\n", index + 1);
      return lineEnd < 0 ? source.length : skipPowerShellTrivia(source, lineEnd + 1);
    }
    if (source[index] === "<" && source[index + 1] === "#") {
      const commentEnd = source.indexOf("#>", index + 2);
      if (commentEnd < 0) return -1;
      index = commentEnd + 2;
      continue;
    }
    return index;
  }
}

function powerShellBraceEnd(source, openingBrace) {
  let depth = 0;
  let state = "code";
  for (let index = openingBrace; index < source.length; index += 1) {
    const character = source[index];
    const next = source[index + 1];
    if (state === "single") {
      if (character === "'" && next === "'") index += 1;
      else if (character === "'") state = "code";
      continue;
    }
    if (state === "double") {
      if (character === "`") index += 1;
      else if (character === '"') state = "code";
      continue;
    }
    if (state === "line-comment") {
      if (character === "\n") state = "code";
      continue;
    }
    if (state === "block-comment") {
      if (character === "#" && next === ">") {
        state = "code";
        index += 1;
      }
      continue;
    }
    if (character === "@" && (next === "'" || next === '"')) {
      const terminator = `\n${next}@`;
      const hereEnd = source.indexOf(terminator, index + 2);
      if (hereEnd < 0) return -1;
      index = hereEnd + terminator.length - 1;
      continue;
    }
    if (character === "'") {
      state = "single";
      continue;
    }
    if (character === '"') {
      state = "double";
      continue;
    }
    if (character === "#") {
      state = "line-comment";
      continue;
    }
    if (character === "<" && next === "#") {
      state = "block-comment";
      index += 1;
      continue;
    }
    if (character === "`") {
      index += 1;
      continue;
    }
    if (character === "{") depth += 1;
    else if (character === "}") {
      depth -= 1;
      if (depth === 0) return index;
      if (depth < 0) return -1;
    }
  }
  return -1;
}

function powerShellFunctionBlock(source, functionName) {
  const analysis = analyzePowerShellSource(source);
  if (!analysis.valid) return "";
  const escapedName = functionName.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  const header = new RegExp(
    `(?:^|\\n)\\s*function\\s+${escapedName}\\s*\\{`,
    "u",
  ).exec(analysis.executableCode);
  if (header === null) return "";
  const openingBrace = analysis.executableCode.indexOf("{", header.index);
  const closingBrace = powerShellBraceEnd(analysis.executableCode, openingBrace);
  return closingBrace < 0
    ? ""
    : analysis.commentFreeCode.slice(header.index, closingBrace + 1);
}

function powerShellExecutableOutsideNamedFunctions(analysis) {
  if (!analysis.valid) return "";
  const outsideFunctions = analysis.executableCode.split("");
  const functionHeader =
    /(?:^|\n)[ \t]*function[ \t]+(?:global:|script:|local:)?[A-Za-z_][A-Za-z0-9_-]*[ \t]*\{/gu;
  for (const match of analysis.executableCode.matchAll(functionHeader)) {
    const openingBrace = analysis.executableCode.indexOf("{", match.index);
    if (
      openingBrace < 0 ||
      powerShellBraceDepthAt(analysis, openingBrace) !== 0
    ) {
      continue;
    }
    const closingBrace = powerShellBraceEnd(
      analysis.executableCode,
      openingBrace,
    );
    if (closingBrace < 0) return "";
    for (let index = match.index; index <= closingBrace; index += 1) {
      if (outsideFunctions[index] !== "\n") outsideFunctions[index] = " ";
    }
    functionHeader.lastIndex = closingBrace + 1;
  }
  return outsideFunctions.join("");
}

function hasPowerShellEarlyTerminationOutsideNamedFunctions(analysis) {
  const outsideFunctions = powerShellExecutableOutsideNamedFunctions(analysis);
  return /\b(?:return|exit|break|continue)\b/iu.test(outsideFunctions);
}

function bootstrapPrecedesPowerShellExecution(source, prefixEnd) {
  const exactDotSource =
    '. ([System.IO.Path]::Combine($PSScriptRoot, "common.ps1"))';
  if (source[prefixEnd] !== "\n") return false;
  let cursor = skipPowerShellTrivia(source, prefixEnd + 1);
  if (cursor < 0) return false;
  if (source.startsWith(exactDotSource, cursor)) {
    let afterDotSource = cursor + exactDotSource.length;
    while (source[afterDotSource] === " " || source[afterDotSource] === "\t") {
      afterDotSource += 1;
    }
    return source[afterDotSource] === "\n" || afterDotSource === source.length;
  }

  for (;;) {
    const functionHeader = /function\s+(?:global:|script:|local:)?[A-Za-z_][A-Za-z0-9_-]*\s*\{/uy;
    functionHeader.lastIndex = cursor;
    const match = functionHeader.exec(source);
    if (match === null) break;
    const openingBrace = source.indexOf("{", cursor);
    const closingBrace = powerShellBraceEnd(source, openingBrace);
    if (closingBrace < 0) return false;
    cursor = skipPowerShellTrivia(source, closingBrace + 1);
    if (cursor < 0) return false;
  }

  if (!source.startsWith("try", cursor)) return false;
  cursor += "try".length;
  if (/[A-Za-z0-9_-]/u.test(source[cursor] ?? "")) return false;
  cursor = skipPowerShellTrivia(source, cursor);
  if (cursor < 0 || source[cursor] !== "{") return false;
  cursor = skipPowerShellTrivia(source, cursor + 1);
  if (cursor < 0 || !source.startsWith(exactDotSource, cursor)) return false;
  let afterDotSource = cursor + exactDotSource.length;
  while (source[afterDotSource] === " " || source[afterDotSource] === "\t") {
    afterDotSource += 1;
  }
  return source[afterDotSource] === "\n" || source[afterDotSource] === "}";
}

function hasSealedPowerShellExecutablePrefix(source, prefix) {
  const analysis = analyzePowerShellSource(source);
  if (!analysis.valid || analysis.hasPreExecutionDirective) return false;
  const normalized = analysis.commentFreeCode;
  const prefixIndex = normalized.indexOf(prefix);
  if (prefixIndex >= 0 && analysis.activeCode[prefixIndex] !== 1) return false;
  if (prefixIndex === 0) {
    return bootstrapPrecedesPowerShellExecution(normalized, prefix.length);
  }
  if (prefixIndex < 0) return false;

  const preamble = normalized.slice(0, prefixIndex);
  const allowedParameterMetadata = new Set([
    "CmdletBinding",
    "Parameter",
    "ValidatePattern",
    "ValidateSet",
    "string",
    "switch",
    "System.Text.RegularExpressions.RegexOptions",
  ]);
  const parameterMetadataNames = [
    ...preamble.matchAll(/\[(?<name>[A-Za-z][A-Za-z0-9.]*)/gu),
  ].map((match) => match.groups.name);
  if (
    parameterMetadataNames.some((name) => !allowedParameterMetadata.has(name))
  ) {
    return false;
  }
  const cmdletBinding = "[CmdletBinding()]\n";
  if (!preamble.startsWith(cmdletBinding)) return false;

  let cursor = cmdletBinding.length;
  while (/\s/u.test(preamble[cursor] ?? "")) cursor += 1;
  if (!preamble.startsWith("param", cursor)) return false;
  cursor += "param".length;
  while (/\s/u.test(preamble[cursor] ?? "")) cursor += 1;
  if (preamble[cursor] !== "(") return false;

  let depth = 0;
  let squareDepth = 0;
  let state = "code";
  let parameterEnd = -1;
  for (let index = cursor; index < preamble.length; index += 1) {
    const character = preamble[index];
    const next = preamble[index + 1];
    if (state === "single") {
      if (character === "'" && next === "'") {
        index += 1;
      } else if (character === "'") {
        state = "code";
      }
      continue;
    }
    if (state === "double") {
      if (character === "`") {
        index += 1;
      } else if (character === '"') {
        state = "code";
      }
      continue;
    }
    if (state === "line-comment") {
      if (character === "\n") state = "code";
      continue;
    }
    if (state === "block-comment") {
      if (character === "#" && next === ">") {
        state = "code";
        index += 1;
      }
      continue;
    }
    if (character === "'") {
      state = "single";
      continue;
    }
    if (character === '"') {
      state = "double";
      continue;
    }
    if (character === "#") {
      state = "line-comment";
      continue;
    }
    if (character === "<" && next === "#") {
      state = "block-comment";
      index += 1;
      continue;
    }
    if (character === "`") {
      index += 1;
      continue;
    }
    if (
      character === "{" ||
      character === "}" ||
      character === ";" ||
      character === "&" ||
      character === "|" ||
      (character === "$" && next === "(")
    ) {
      return false;
    }
    if (character === "[") {
      squareDepth += 1;
      continue;
    }
    if (character === "]") {
      squareDepth -= 1;
      if (squareDepth < 0) return false;
      continue;
    }
    if (character === "(") {
      depth += 1;
      continue;
    }
    if (character === ")") {
      depth -= 1;
      if (depth < 0) return false;
      if (depth === 0) {
        parameterEnd = index;
        break;
      }
      continue;
    }
    if (character === "=" && depth === 1 && squareDepth === 0) {
      return false;
    }
  }
  const validPreamble =
    parameterEnd >= 0 &&
    squareDepth === 0 &&
    preamble.slice(parameterEnd + 1).trim().length === 0;
  return (
    validPreamble &&
    bootstrapPrecedesPowerShellExecution(normalized, prefixIndex + prefix.length)
  );
}

const releaseCheckInvokeTestsBlock = powerShellFunctionBlock(
  releaseCheck,
  "Invoke-Tests",
);
const releaseCheckInvokeCheckedBlock = powerShellFunctionBlock(
  releaseCheck,
  "Invoke-Checked",
);
const expectedReleaseCheckInvokeCheckedBlock = [
  "function Invoke-Checked {",
  "    param([Parameter(Mandatory = $true)][string]$Executable, [Parameter(Mandatory = $true)][string[]]$CommandArguments)",
  "    $result = Invoke-ReleaseCommand `",
  "        -Executable $Executable `",
  "        -CommandArguments $CommandArguments `",
  "        -WorkingDirectory $RepoRoot",
  "    if (-not [System.String]::IsNullOrEmpty($result.Stderr)) {",
  '        throw "Release check command emitted stderr"',
  "    }",
  "    if (-not [System.String]::IsNullOrEmpty($result.Stdout)) {",
  "        Write-Output $result.Stdout",
  "    }",
  "}",
].join("\n");
const exactSealedReleaseCheckWorkflowInvocation = [
  "        run: |",
  '          $systemPowerShell = [System.IO.Path]::Combine([System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::System), "WindowsPowerShell", "v1.0", "powershell.exe")',
  '          $nodeExecutable = $ExecutionContext.InvokeCommand.GetCommand("node", [System.Management.Automation.CommandTypes]::Application).Path',
  "          & $systemPowerShell -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File scripts/release/check.ps1 all -NodeExecutable $nodeExecutable",
].join("\n");
const releaseCheckInvokeTestsAnalysis = analyzePowerShellSource(
  releaseCheckInvokeTestsBlock,
);
const releaseCheckExactPowerShellTestLoop = [
  "    $expectedPowerShellTestSuccess = @{",
  '        "common.test.ps1" = "POWERSHELL_RELEASE_HELPERS_PASS"',
  '        "verifier-toolset.test.ps1" = "POWERSHELL_VERIFIER_TOOLSET_PASS"',
  "    }",
  '    foreach ($testScriptName in @("common.test.ps1", "verifier-toolset.test.ps1")) {',
  "        $testOutput = @(",
  "            Invoke-Checked -Executable $systemPowerShell -CommandArguments @(",
  '                "-NoLogo",',
  '                "-NoProfile",',
  '                "-NonInteractive",',
  '                "-ExecutionPolicy",',
  '                "Bypass",',
  '                "-File",',
  "                (Join-Path $PSScriptRoot $testScriptName)",
  "            )",
  "        )",
  "        $expectedSuccess = $expectedPowerShellTestSuccess[$testScriptName]",
  "        if (",
  "            $testOutput.Count -ne 1 -or",
  "            -not [System.String]::Equals(",
  "                [string]$testOutput[0],",
  "                $expectedSuccess,",
  "                [System.StringComparison]::Ordinal",
  "            )",
  "        ) {",
  '            throw "Release PowerShell behavior test did not emit its exact success sentinel"',
  "        }",
  "        Write-Output $testOutput[0]",
  "    }",
].join("\n");
const releaseCheckExactPowerShellTestLoopIndexes = activePowerShellLiteralIndexes(
  releaseCheckInvokeTestsAnalysis,
  releaseCheckExactPowerShellTestLoop,
);
const expectedReleaseCheckInvokeTestsBlock = [
  "function Invoke-Tests {",
  "    $approvedTestSha256 = [ordered]@{",
  "        \"audit-extension.test.mjs\" = \"ad38466ba18481611a6e55575231b313c12644464d643580edc9aaede73a6906\"",
  "        \"generate-inventories.test.mjs\" = \"cf6a80cd902dc3a35fc88a8cb5c65fe84790254bc1e9693a0404a311223f7dbc\"",
  "        \"release-manifest.test.mjs\" = \"4549e101f37087dcde8ed02ceeef9fb68db88c6593475a3a06b9496c7b11eb6a\"",
  "        \"release-verifier-integration.test.mjs\" = \"9094bc4d988c3290d6f7b3bf7243367ac90499c470e500205f5c49a40993b80e\"",
  "        \"review-evidence-set.test.mjs\" = \"b556b49d3c349c6519edddf5817e16972540ed55f613cb208a738c4e3ed6f470\"",
  "    }",
  "    $tests = @(Get-ChildItem -LiteralPath $PSScriptRoot -Filter \"*.test.mjs\" -File | Sort-Object -Property Name | ForEach-Object { $_.FullName })",
  "    if ($tests.Count -ne $approvedTestSha256.Count) {",
  "        throw \"Release-policy test inventory is not approved\"",
  "    }",
  "    $approvedTestNames = @($approvedTestSha256.Keys)",
  "    for ($index = 0; $index -lt $approvedTestNames.Count; $index += 1) {",
  "        $testName = [System.IO.Path]::GetFileName($tests[$index])",
  "        if (",
  "            -not [System.String]::Equals(",
  "                $testName,",
  "                [string]$approvedTestNames[$index],",
  "                [System.StringComparison]::Ordinal",
  "            )",
  "        ) {",
  "            throw \"Release-policy test inventory is not approved\"",
  "        }",
  "        $sha256 = [System.Security.Cryptography.SHA256]::Create()",
  "        try {",
  "            $digest = $sha256.ComputeHash([System.IO.File]::ReadAllBytes($tests[$index]))",
  "        }",
  "        finally {",
  "            $sha256.Dispose()",
  "        }",
  "        $actualSha256 = ([System.BitConverter]::ToString($digest)).Replace(\"-\", \"\").ToLowerInvariant()",
  "        if (",
  "            -not [System.String]::Equals(",
  "                $actualSha256,",
  "                [string]$approvedTestSha256[$testName],",
  "                [System.StringComparison]::Ordinal",
  "            )",
  "        ) {",
  "            throw \"Release-policy test source is not approved\"",
  "        }",
  "    }",
  "    $stderrRejected = $false",
  "    try {",
  "        $null = Invoke-Checked `",
  "            -Executable $NodeExecutable `",
  "            -CommandArguments @(",
  "                \"-e\",",
  "                'process.stdout.write(\"EXACT_STDOUT\");process.stderr.write(\"REJECTED_STDERR\")'",
  "            )",
  "    }",
  "    catch {",
  "        $stderrRejected = $true",
  "    }",
  "    if (-not $stderrRejected) {",
  "        throw \"Release check accepted child stderr\"",
  "    }",
  "    Invoke-Checked -Executable $NodeExecutable -CommandArguments (@(\"--test\") + $tests)",
  "    $systemPowerShell = [System.IO.Path]::Combine(",
  "        [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::System),",
  "        \"WindowsPowerShell\",",
  "        \"v1.0\",",
  "        \"powershell.exe\"",
  "    )",
  "    if (-not [System.IO.File]::Exists($systemPowerShell)) {",
  "        throw \"System Windows PowerShell is unavailable\"",
  "    }",
  "    $expectedPowerShellTestSuccess = @{",
  "        \"common.test.ps1\" = \"POWERSHELL_RELEASE_HELPERS_PASS\"",
  "        \"verifier-toolset.test.ps1\" = \"POWERSHELL_VERIFIER_TOOLSET_PASS\"",
  "    }",
  "    foreach ($testScriptName in @(\"common.test.ps1\", \"verifier-toolset.test.ps1\")) {",
  "        $testOutput = @(",
  "            Invoke-Checked -Executable $systemPowerShell -CommandArguments @(",
  "                \"-NoLogo\",",
  "                \"-NoProfile\",",
  "                \"-NonInteractive\",",
  "                \"-ExecutionPolicy\",",
  "                \"Bypass\",",
  "                \"-File\",",
  "                (Join-Path $PSScriptRoot $testScriptName)",
  "            )",
  "        )",
  "        $expectedSuccess = $expectedPowerShellTestSuccess[$testScriptName]",
  "        if (",
  "            $testOutput.Count -ne 1 -or",
  "            -not [System.String]::Equals(",
  "                [string]$testOutput[0],",
  "                $expectedSuccess,",
  "                [System.StringComparison]::Ordinal",
  "            )",
  "        ) {",
  "            throw \"Release PowerShell behavior test did not emit its exact success sentinel\"",
  "        }",
  "        Write-Output $testOutput[0]",
  "    }",
  "}",
].join("\n");
const sealedReleaseBootstrapTestBlock = powerShellFunctionBlock(
  releaseVerifierToolsetTests,
  "Assert-SealedReleasePowerShellBootstrap",
);
const sealedReleaseBootstrapTestAnalysis = analyzePowerShellSource(
  sealedReleaseBootstrapTestBlock,
);
const sealedReleaseBootstrapAttackMatrix = [
  "    $bootstrapAttacks = @(",
  "        [pscustomobject]@{",
  '            Name = "directory-lock-type"',
  "            Prelude = $typePreludeTemplate.Replace(",
  '                "__TYPE_NAME__",',
  '                "YourWallet.ReleaseDirectoryLock"',
  "            )",
  "        },",
  "        [pscustomobject]@{",
  '            Name = "toolset-process-type"',
  "            Prelude = $typePreludeTemplate.Replace(",
  '                "__TYPE_NAME__",',
  '                "YourWallet.ReleaseToolsetProcess"',
  "            )",
  "        },",
  "        [pscustomobject]@{",
  '            Name = "toolset-process-result-type"',
  "            Prelude = $typePreludeTemplate.Replace(",
  '                "__TYPE_NAME__",',
  '                "YourWallet.ReleaseToolsetProcessResult"',
  "            )",
  "        },",
  "        [pscustomobject]@{",
  '            Name = "loaded-security-module"',
  "            Prelude = $loadedModulePrelude",
  "        },",
  "        [pscustomobject]@{",
  '            Name = "join-path-shadow"',
  "            Prelude = $joinPathShadowPrelude",
  "        },",
  "        [pscustomobject]@{",
  '            Name = "add-type-shadow"',
  "            Prelude = $addTypeShadowPrelude",
  "        },",
  "        [pscustomobject]@{",
  '            Name = "long-form-alias-shadow"',
  "            Prelude = $longAliasPrelude",
  "        }",
  "    )",
].join("\n");
const sealedReleaseBootstrapAttackMatrixIndexes = activePowerShellLiteralIndexes(
  sealedReleaseBootstrapTestAnalysis,
  sealedReleaseBootstrapAttackMatrix,
);
const sealedReleaseBootstrapAttackExecutionMarkers = [
  "$bootstrapAttacks.Count -ne 7",
  "$executedBootstrapAttackCount = 0",
  "foreach ($bootstrapAttack in $bootstrapAttacks) {",
  "$executedBootstrapAttackCount += 1",
  "$executedBootstrapAttackCount -ne 7",
].map((literal) => ({
  indexes: activePowerShellLiteralIndexes(
    sealedReleaseBootstrapTestAnalysis,
    literal,
  ),
  literal,
}));
const sealedReleaseBootstrapAttackExecutionBlock = [
  "    if ($bootstrapAttacks.Count -ne 7) {",
  '        throw "Release PowerShell bootstrap attack matrix is incomplete"',
  "    }",
  "    $executedBootstrapAttackCount = 0",
  "    foreach ($bootstrapAttack in $bootstrapAttacks) {",
  "        $attackProbeRoot = Join-Path $probeRoot $bootstrapAttack.Name",
  "        [void][System.IO.Directory]::CreateDirectory($attackProbeRoot)",
  '        $probePath = Join-Path $attackProbeRoot "common.test.ps1"',
  "        $probeSource = $bootstrapFailureTemplate.Replace(",
  '            "__PRELUDE__",',
  "            $bootstrapAttack.Prelude",
  '        ).Replace("__COMMON_PATH__", $commonPathLiteral)',
  "        Write-NewUtf8File -LiteralPath $probePath -Content $probeSource",
  "        $probeResult = Invoke-TestRawProcess `",
  "            -Executable $systemPowerShell `",
  "            -WorkingDirectory $RepoRoot `",
  "            -Arguments @(",
  '                "-NoLogo",',
  '                "-NoProfile",',
  '                "-NonInteractive",',
  '                "-ExecutionPolicy",',
  '                "Bypass",',
  '                "-File",',
  "                $probePath",
  "            ) `",
  "            -TimeoutMilliseconds 30000",
  "        if (",
  "            $probeResult.ExitCode -ne 0 -or",
  "            -not [System.String]::Equals(",
  "                $probeResult.Stdout,",
  '                "RELEASE_POWERSHELL_BOOTSTRAP_REJECTED`n",',
  "                [System.StringComparison]::Ordinal",
  "            ) -or",
  "            -not [System.String]::Equals(",
  "                $probeResult.Stderr,",
  '                "",',
  "                [System.StringComparison]::Ordinal",
  "            )",
  "        ) {",
  '            throw "Release PowerShell bootstrap accepted ambient runtime state"',
  "        }",
  "        $executedBootstrapAttackCount += 1",
  "    }",
  "    if ($executedBootstrapAttackCount -ne 7) {",
  '        throw "Release PowerShell bootstrap attack matrix did not execute completely"',
  "    }",
].join("\n");
const sealedReleaseBootstrapAttackExecutionBlockIndexes =
  activePowerShellLiteralIndexes(
    sealedReleaseBootstrapTestAnalysis,
    sealedReleaseBootstrapAttackExecutionBlock,
  );
const commandShadowMarkerGuardBlock = [
  "    if ([System.IO.File]::Exists($commandShadowMarker)) {",
  '        throw "Release PowerShell bootstrap invoked an ambient command shadow"',
  "    }",
].join("\n");
const authenticodeMarkerGuardBlock = [
  "    if (",
  "        $lateModuleProbeResult.ExitCode -ne 0 -or",
  "        -not [System.String]::Equals(",
  "            $lateModuleProbeResult.Stdout,",
  '            "AUTHENTICODE_COMMAND_SHADOW_REJECTED`n",',
  "            [System.StringComparison]::Ordinal",
  "        ) -or",
  "        -not [System.String]::Equals(",
  "            $lateModuleProbeResult.Stderr,",
  '            "",',
  "            [System.StringComparison]::Ordinal",
  "        ) -or",
  "        [System.IO.File]::Exists($authenticodeMarker)",
  "    ) {",
  '        throw "Trusted Authenticode command accepted a late same-name module"',
  "    }",
].join("\n");
const externalModuleMarkerGuardBlock = [
  "    if ([System.IO.File]::Exists($moduleMarker)) {",
  '        throw "Release wrapper auto-loaded an external module path"',
  "    }",
].join("\n");
const commandShadowMarkerGuardIndexes = activePowerShellLiteralIndexes(
  sealedReleaseBootstrapTestAnalysis,
  commandShadowMarkerGuardBlock,
);
const authenticodeMarkerGuardIndexes = activePowerShellLiteralIndexes(
  sealedReleaseBootstrapTestAnalysis,
  authenticodeMarkerGuardBlock,
);
const externalModuleMarkerGuardIndexes = activePowerShellLiteralIndexes(
  sealedReleaseBootstrapTestAnalysis,
  externalModuleMarkerGuardBlock,
);
const sealedReleaseBootstrapTopLevelSequence = [
  "try {",
  "    Assert-X86VerifierHostPreflight",
  "    Assert-SealedReleasePowerShellBootstrap",
  "    if (-not $script:SealedReleasePowerShellBootstrapVerified) {",
  '        throw "Release PowerShell bootstrap behavior tests did not complete"',
  "    }",
].join("\n");
const sealedReleaseBootstrapTopLevelSequenceIndexes = activePowerShellLiteralIndexes(
  releaseVerifierToolsetTestsPowerShellAnalysis,
  sealedReleaseBootstrapTopLevelSequence,
);
const sealedReleaseBootstrapFlagInitializationIndexes = activePowerShellLiteralIndexes(
  releaseVerifierToolsetTestsPowerShellAnalysis,
  "$script:SealedReleasePowerShellBootstrapVerified = $false",
);
const sealedReleaseBootstrapFlagCompletionIndexes = activePowerShellLiteralIndexes(
  sealedReleaseBootstrapTestAnalysis,
  "$script:SealedReleasePowerShellBootstrapVerified = $true",
);
const commonPowerShellTestSuccessTail = [
  '    Write-Output "POWERSHELL_RELEASE_HELPERS_PASS"',
  "}",
  "finally {",
].join("\n");
const verifierPowerShellTestSuccessTail = [
  '    Write-Output "POWERSHELL_VERIFIER_TOOLSET_PASS"',
  "}",
  "finally {",
].join("\n");
const commonPowerShellTestSuccessTailIndexes = activePowerShellLiteralIndexes(
  releaseCommonTestsPowerShellAnalysis,
  commonPowerShellTestSuccessTail,
);
const verifierPowerShellTestSuccessTailIndexes = activePowerShellLiteralIndexes(
  releaseVerifierToolsetTestsPowerShellAnalysis,
  verifierPowerShellTestSuccessTail,
);
const blockCommentPowerShellCallDecoy = analyzePowerShellSource(
  "<#\nAssert-SealedReleasePowerShellBootstrap\n#>",
);
const lineCommentPowerShellCallDecoy = analyzePowerShellSource(
  "# Assert-SealedReleasePowerShellBootstrap",
);
const hereStringPowerShellCallDecoy = analyzePowerShellSource(
  "$decoy = @'\nAssert-SealedReleasePowerShellBootstrap\n'@",
);
const multilineStringPowerShellCallDecoy = analyzePowerShellSource(
  "$decoy = '\nAssert-SealedReleasePowerShellBootstrap\n'",
);
const expandableStringPowerShellCallDecoy = analyzePowerShellSource(
  '$decoy = "$(Assert-SealedReleasePowerShellBootstrap)"',
);
const expandableHereStringPowerShellCallDecoy = analyzePowerShellSource(
  '$decoy = @"\n$(Assert-SealedReleasePowerShellBootstrap)\n"@',
);
const unreachablePowerShellCallDecoy = analyzePowerShellSource(
  "try {\n    if ($false) {\n        Assert-SealedReleasePowerShellBootstrap\n    }\n}",
);
const unreachablePowerShellMarkerDecoy = analyzePowerShellSource(
  "function Test-Decoy {\n    if ($false) {\n        if ([System.IO.File]::Exists($commandShadowMarker)) {\n        }\n    }\n}",
);
const releaseCheckHereStringCallDecoy = analyzePowerShellSource(
  [
    "function Invoke-Tests {",
    "    $decoy = @'",
    "        Invoke-Checked -Executable $systemPowerShell -CommandArguments @(",
    '            "-NoLogo",',
    '            "-NoProfile",',
    '            "-NonInteractive",',
    '            "-ExecutionPolicy",',
    '            "Bypass",',
    '            "-File",',
    "            (Join-Path $PSScriptRoot $testScriptName)",
    "        )",
    "'@",
    "}",
  ].join("\n"),
);
const earlyTerminationPowerShellDecoys = [
  'Write-Output "POWERSHELL_VERIFIER_TOOLSET_PASS"; return',
  'Write-Output "POWERSHELL_VERIFIER_TOOLSET_PASS"; exit 0',
  'if ($true) { break }',
  'if ($true) { continue }',
  '[System.Environment]::Exit(0)',
].map((source) => analyzePowerShellSource(source));
const namedFunctionReturnPowerShellControl = analyzePowerShellSource(
  "function Invoke-Decoy { return }\nWrite-Output \"continued\"",
);
const powerShellUsingWhitespaceDecoys = ["\u000b", "\u000c", "\u00a0"].map(
  (whitespace) => analyzePowerShellSource(`${whitespace}using module ambient`),
);
const sealedPowerShellEntryPrefix = [
  '$PSModuleAutoLoadingPreference = "None"',
  '$ErrorActionPreference = "Stop"',
  "$script:ReleasePowerShellEntryScriptPath = $PSCommandPath",
].join("\n");
const exactReleaseCommonDotSource =
  '. ([System.IO.Path]::Combine($PSScriptRoot, "common.ps1"))';
for (const { path, source } of sealedReleasePowerShellEntries) {
  const analysis = analyzePowerShellSource(source);
  requireInvariant(
    analysis.valid,
    `sealed release PowerShell lexical analysis is invalid: ${path}`,
  );
  requireInvariant(
    hasSealedPowerShellExecutablePrefix(source, sealedPowerShellEntryPrefix),
    `sealed release PowerShell executable prefix is invalid: ${path}`,
  );
  requireInvariant(
    activePowerShellLiteralIndexes(analysis, exactReleaseCommonDotSource).length === 1,
    `sealed release PowerShell common binding is not unique: ${path}`,
  );
  requireInvariant(
    activePowerShellLiteralIndexes(
      analysis,
      '. (Join-Path $PSScriptRoot "common.ps1")',
    ).length === 0,
    `sealed release PowerShell entry uses an unapproved common binding: ${path}`,
  );
}
requireInvariant(
  hasExactCaseInsensitivePathInventory(
    repositoryPowerShellScripts.map(({ path }) => path),
    approvedRepositoryPowerShellScriptPaths,
  ) &&
    hasExactSourcePins(
      repositoryPowerShellScripts,
      approvedPowerShellSourceSha256,
    ) &&
    !hasExactSourcePins(
      repositoryPowerShellScripts.map((source, index) =>
        index === 0 ? { ...source, sha256: "0".repeat(64) } : source,
      ),
      approvedPowerShellSourceSha256,
    ) &&
    hasExactCaseInsensitivePathInventory(
      discoveredReleaseCommonConsumerPaths,
      approvedSealedReleasePowerShellEntryPaths,
    ) &&
    powerShellReferencesReleaseCommon(
      '. ([System.IO.Path]::Combine($PSScriptRoot, "common" + ".ps1"))',
    ) &&
    powerShellReferencesReleaseCommon(
      "$script:ReleasePowerShellEntryScriptPath = $PSCommandPath",
    ) &&
    !hasExactCaseInsensitivePathInventory(
      [
        ...repositoryPowerShellScripts.map(({ path }) => path),
        "scripts/release/dynamic-common-entry.ps1",
      ],
      approvedRepositoryPowerShellScriptPaths,
    ) &&
    !hasExactCaseInsensitivePathInventory(
      [
        ...repositoryPowerShellScripts.map(({ path }) => path),
        "scripts/release/dynamic-common-module.psm1",
      ],
      approvedRepositoryPowerShellScriptPaths,
    ) &&
    !hasExactCaseInsensitivePathInventory(
      [
        ...repositoryPowerShellScripts.map(({ path }) => path),
        repositoryPowerShellScripts[0].path.toUpperCase(),
      ],
      approvedRepositoryPowerShellScriptPaths,
    ) &&
  sealedReleasePowerShellEntries.every(
    ({ source }) => {
      const analysis = analyzePowerShellSource(source);
      return (
        analysis.valid &&
        hasSealedPowerShellExecutablePrefix(source, sealedPowerShellEntryPrefix) &&
        activePowerShellLiteralIndexes(analysis, exactReleaseCommonDotSource).length === 1 &&
        activePowerShellLiteralIndexes(
          analysis,
          '. (Join-Path $PSScriptRoot "common.ps1")',
        ).length === 0
      );
    },
  ) &&
    sealedReleasePowerShellEntries.length ===
      approvedSealedReleasePowerShellEntryPaths.length &&
    !hasSealedPowerShellExecutablePrefix(
      '[CmdletBinding()]\nparam(\n    [ValidateScript({ Write-Output "ran"; $true })]\n    [string]$Path\n)\n\n' +
        sealedPowerShellEntryPrefix,
      sealedPowerShellEntryPrefix,
    ) &&
    !hasSealedPowerShellExecutablePrefix(
      `${sealedPowerShellEntryPrefix} + ".different"\n. ([System.IO.Path]::Combine($PSScriptRoot, "common.ps1"))`,
      sealedPowerShellEntryPrefix,
    ) &&
    !hasSealedPowerShellExecutablePrefix(
      `${sealedPowerShellEntryPrefix}; Write-Output "ran"\n. ([System.IO.Path]::Combine($PSScriptRoot, "common.ps1"))`,
      sealedPowerShellEntryPrefix,
    ) &&
    !hasSealedPowerShellExecutablePrefix(
      `${sealedPowerShellEntryPrefix}\nWrite-Output "ran"\n. ([System.IO.Path]::Combine($PSScriptRoot, "common.ps1"))`,
      sealedPowerShellEntryPrefix,
    ) &&
    !hasSealedPowerShellExecutablePrefix(
      `${sealedPowerShellEntryPrefix}\n#Requires -Modules Microsoft.PowerShell.Utility\n${exactReleaseCommonDotSource}`,
      sealedPowerShellEntryPrefix,
    ) &&
    !hasSealedPowerShellExecutablePrefix(
      `${sealedPowerShellEntryPrefix}\nfunction Invoke-Decoy {\n    #Requires -Version 5.1\n}\ntry {\n    ${exactReleaseCommonDotSource}\n}`,
      sealedPowerShellEntryPrefix,
    ) &&
    !hasSealedPowerShellExecutablePrefix(
      `${sealedPowerShellEntryPrefix}\n$decoy = @'\n${exactReleaseCommonDotSource}\n'@`,
      sealedPowerShellEntryPrefix,
    ) &&
    [
      ` > $([System.Console]::WriteLine("ran"))`,
      ' | ForEach-Object { Write-Output "ran" }',
      '; Write-Output "ran"',
    ].every(
      (suffix) =>
        !hasSealedPowerShellExecutablePrefix(
          `${sealedPowerShellEntryPrefix}\nfunction Invoke-Decoy { }\ntry {\n    ${exactReleaseCommonDotSource}${suffix}\n}`,
          sealedPowerShellEntryPrefix,
        ),
    ) &&
    hasSealedPowerShellExecutablePrefix(
      `${sealedPowerShellEntryPrefix}\n<# #Requires is inert here #>\n${exactReleaseCommonDotSource}`,
      sealedPowerShellEntryPrefix,
    ) &&
    activePowerShellMatches(
      blockCommentPowerShellCallDecoy,
      /^[ \t]*Assert-SealedReleasePowerShellBootstrap[ \t]*$/gmu,
    ).length === 0 &&
    activePowerShellMatches(
      lineCommentPowerShellCallDecoy,
      /^[ \t]*Assert-SealedReleasePowerShellBootstrap[ \t]*$/gmu,
    ).length === 0 &&
    activePowerShellMatches(
      hereStringPowerShellCallDecoy,
      /^[ \t]*Assert-SealedReleasePowerShellBootstrap[ \t]*$/gmu,
    ).length === 0 &&
    activePowerShellMatches(
      multilineStringPowerShellCallDecoy,
      /^[ \t]*Assert-SealedReleasePowerShellBootstrap[ \t]*$/gmu,
    ).length === 0 &&
    !expandableStringPowerShellCallDecoy.valid &&
    !expandableHereStringPowerShellCallDecoy.valid &&
    !hasOneActivePowerShellMatchAtBraceDepth(
      unreachablePowerShellCallDecoy,
      /^[ \t]*Assert-SealedReleasePowerShellBootstrap[ \t]*$/gmu,
      1,
    ) &&
    !hasOneActivePowerShellMatchAtBraceDepth(
      unreachablePowerShellMarkerDecoy,
      /^[ \t]*if \(\[System\.IO\.File\]::Exists\(\$commandShadowMarker\)\) \{/gmu,
      1,
    ) &&
    earlyTerminationPowerShellDecoys.every((analysis) =>
      hasPowerShellEarlyTerminationOutsideNamedFunctions(analysis),
    ) &&
    !hasPowerShellEarlyTerminationOutsideNamedFunctions(
      namedFunctionReturnPowerShellControl,
    ) &&
    powerShellUsingWhitespaceDecoys.every(
      (analysis) => analysis.hasPreExecutionDirective,
    ) &&
    releaseCommonPowerShellAnalysis.valid &&
    !releaseCommonPowerShellAnalysis.hasPreExecutionDirective &&
    releaseCommonPowerShellAnalysis.commentFreeCode.startsWith(
      '$PSModuleAutoLoadingPreference = "None"\n$ErrorActionPreference = "Stop"\n',
    ) &&
    JSON.stringify(approvedReleaseEntryScriptNames) ===
      JSON.stringify(
        approvedSealedReleasePowerShellEntryPaths.map((path) =>
          path.slice(path.lastIndexOf("/") + 1),
        ),
      ) &&
    releaseCommon.includes(
      "[System.IO.Path]::GetFileName(\n        [System.IO.Path]::GetFullPath($script:ReleasePowerShellEntryScriptPath)",
    ) &&
    releaseCommon.includes("if (-not $approvedEntryScript) {") &&
    releaseCommon.includes("function Initialize-ReleasePowerShellRuntime") &&
    releaseCommon.includes("[System.Environment]::Is64BitOperatingSystem") &&
    releaseCommon.includes("[System.Environment]::Is64BitProcess") &&
    releaseCommon.includes('[string]$PSVersionTable.PSEdition,\n            "Desktop"') &&
    releaseCommon.includes("$PSVersionTable.PSVersion.Major -ne 5") &&
    releaseCommon.includes("$PSVersionTable.PSVersion.Minor -ne 1") &&
    releaseCommon.includes("[System.Environment]::GetCommandLineArgs()") &&
    releaseCommon.includes("$commandLine.Count -lt 8") &&
    ["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File"].every(
      (argument) => releaseCommon.includes(`"${argument}"`),
    ) &&
    releaseCommon.includes("$script:ReleasePowerShellEntryScriptPath") &&
    releaseCommon.includes("$currentProcess.MainModule.FileName") &&
    releaseCommon.includes("[System.Environment+SpecialFolder]::System") &&
    releaseCommon.includes('"WindowsPowerShell", "v1.0"') &&
    releaseCommon.includes('"powershell.exe"') &&
    releaseCommon.includes('throw "Release PowerShell runtime bootstrap failed closed"'),
  "the exact approved PowerShell inventory must use one unambiguous encoding and exact reviewed raw-byte SHA-256 pins, and every sealed release entry must reject pre-execution directives, disable autoload before ambient code, and bind common.ps1 to one exact direct system Windows PowerShell 5.1 invocation",
);
requireInvariant(
  releaseCommon.includes('"YourWallet.ReleaseDirectoryLock"') &&
    releaseCommon.includes('"YourWallet.ReleaseToolsetProcessResult"') &&
    releaseCommon.includes('"YourWallet.ReleaseToolsetProcess"') &&
    releaseCommon.includes("@(& $getModuleCommand -All -ErrorAction Stop).Count -ne 0") &&
    releaseCommon.includes("[System.Management.Automation.CommandTypes]::Cmdlet") &&
    releaseCommon.includes("$visibleCommands.Count -ne 1") &&
    releaseCommon.includes("release core command surface is shadowed before module import") &&
    releaseCommon.includes("release module command surface is shadowed before module import") &&
    releaseBootstrapPreflightOrder.every(
      (index, position, indexes) =>
        index >= 0 && (position === 0 || index > indexes[position - 1]),
    ) &&
    [
      "Microsoft.PowerShell.Management",
      "Microsoft.PowerShell.Utility",
      "Microsoft.PowerShell.Security",
    ].every((moduleName) => releaseCommon.includes(`"${moduleName}"`)) &&
    JSON.stringify(trustedReleaseModuleNames) ===
      JSON.stringify([
        "Microsoft.PowerShell.Management",
        "Microsoft.PowerShell.Utility",
        "Microsoft.PowerShell.Security",
      ]) &&
    (releaseCommon.match(/& \$importModuleCommand\s*`/gu) ?? []).length === 1 &&
    !/^\s*Import-Module\b/gmu.test(releaseCommon) &&
    !releaseCommon.includes('"Microsoft.PowerShell.Archive"') &&
    releaseCommon.includes("$expectedPowerShellHome") &&
    releaseCommon.includes("$trustedModules.Add($moduleName, $importedModules[0])") &&
    releaseCommon.includes('"Add-Type" = "Microsoft.PowerShell.Utility"') &&
    releaseCommon.includes(
      '"Get-AuthenticodeSignature" = "Microsoft.PowerShell.Security"',
    ) &&
    releaseCommon.includes("$script:ReleaseTrustedCommands = $trustedCommands") &&
    releaseCommon.includes('$visibleAlias.Name.Contains("-")') &&
    releaseCommon.includes("$initializeRuntimeCommands[0]") &&
    releaseCommon.includes('$trustedCommands["Add-Type"]') &&
    releaseCommon.includes('-AssemblyName "System.IO.Compression"') &&
    releaseCommon.includes("$frameworkAssembly.GlobalAssemblyCache") &&
    releaseCommon.includes("$script:ReleaseZipArchiveType = $zipArchiveType") &&
    releaseCommon.includes("$script:ReleaseZipArchiveModeType = $zipArchiveModeType") &&
    releaseCommon.includes("$script:ReleaseCompressionLevelType = $compressionLevelType") &&
    !/^\s*Add-Type\b/gmu.test(releaseCommon) &&
    !releaseCommon.includes("[System.IO.Compression.ZipArchive]::") &&
    !releaseCommon.includes("[System.IO.Compression.ZipArchiveMode]::") &&
    !releaseCommon.includes("[System.IO.Compression.CompressionLevel]::") &&
    !releaseCommon.includes("Microsoft.PowerShell.Security\\Get-AuthenticodeSignature") &&
    releaseCommon.includes("function Get-ReleaseAuthenticodeSignature") &&
    releaseCommon.includes('$trustedCommand = $script:ReleaseTrustedCommands["Get-AuthenticodeSignature"]') &&
    releaseCommon.includes("$signatures = @(& $trustedCommand -LiteralPath $LiteralPath -ErrorAction Stop)") &&
    releaseVerifier.includes("Get-ReleaseAuthenticodeSignature -LiteralPath $filePath") &&
    releaseAuthenticodeVerifier.includes("Get-ReleaseAuthenticodeSignature -LiteralPath $filePath"),
  "release PowerShell bootstrap must reject loaded modules, protected types, and command shadows, import only binary-safe exact system manifests, and retain exact Authenticode and compression identities",
);
requireInvariant(
  releaseCommon.includes("$script:ReleaseDirectoryLockType = $compiledType") &&
    releaseCommon.includes("$script:ReleaseToolsetProcessType = $compiledProcessType") &&
    releaseCommon.includes("$script:ReleaseToolsetProcessResultType = $compiledResultType") &&
    releaseCommon.includes("[object]::ReferenceEquals($resolvedType, $compiledType)") &&
    releaseCommon.includes(
      "[object]::ReferenceEquals($resolvedProcessType, $compiledProcessType)",
    ) &&
    releaseCommon.includes("$script:ReleaseDirectoryLockType::OpenDirectory") &&
    releaseCommon.includes("$script:ReleaseDirectoryLockType::OpenFile") &&
    releaseCommon.includes("$script:ReleaseToolsetProcessType::Run") &&
    !releaseCommon.includes("[YourWallet.ReleaseDirectoryLock]::") &&
    !releaseCommon.includes("[YourWallet.ReleaseToolsetProcess]::") &&
    !/if \(\$null -ne \("YourWallet\.Release(?:DirectoryLock|ToolsetProcess)" -as \[type\]\)\) \{\s*return/gu.test(
      releaseCommon,
    ) &&
    releaseCommonTestsPowerShellAnalysis.valid &&
    !hasPowerShellEarlyTerminationOutsideNamedFunctions(
      releaseCommonTestsPowerShellAnalysis,
    ) &&
    commonPowerShellTestSuccessTailIndexes.length === 1 &&
    powerShellBraceDepthAt(
      releaseCommonTestsPowerShellAnalysis,
      commonPowerShellTestSuccessTailIndexes[0],
    ) === 1 &&
    releaseVerifierToolsetTestsPowerShellAnalysis.valid &&
    !hasPowerShellEarlyTerminationOutsideNamedFunctions(
      releaseVerifierToolsetTestsPowerShellAnalysis,
    ) &&
    verifierPowerShellTestSuccessTailIndexes.length === 1 &&
    powerShellBraceDepthAt(
      releaseVerifierToolsetTestsPowerShellAnalysis,
      verifierPowerShellTestSuccessTailIndexes[0],
    ) === 1 &&
    releaseVerifierToolsetTestsPowerShellAnalysis.executableCode.includes(
      "function Assert-SealedReleasePowerShellBootstrap",
    ) &&
    activePowerShellMatches(
      releaseVerifierToolsetTestsPowerShellAnalysis,
      /(?:^|\n)[ \t]*function[ \t]+Assert-SealedReleasePowerShellBootstrap[ \t]*\{/gimu,
    ).length === 1 &&
    activePowerShellMatches(
      releaseVerifierToolsetTestsPowerShellAnalysis,
      /\bAssert-SealedReleasePowerShellBootstrap\b/gimu,
    ).length === 2 &&
    activePowerShellMatches(
      releaseVerifierToolsetTestsPowerShellAnalysis,
      /\bSealedReleasePowerShellBootstrapVerified\b/gimu,
    ).length === 3 &&
    sealedReleaseBootstrapTestBlock.length > 0 &&
    sealedReleaseBootstrapTestAnalysis.valid &&
    !/\b(?:return|exit|break|continue)\b/iu.test(
      sealedReleaseBootstrapTestAnalysis.executableCode,
    ) &&
    sealedReleaseBootstrapTopLevelSequenceIndexes.length === 1 &&
    powerShellBraceDepthAt(
      releaseVerifierToolsetTestsPowerShellAnalysis,
      sealedReleaseBootstrapTopLevelSequenceIndexes[0],
    ) === 0 &&
    sealedReleaseBootstrapFlagInitializationIndexes.length === 1 &&
    powerShellBraceDepthAt(
      releaseVerifierToolsetTestsPowerShellAnalysis,
      sealedReleaseBootstrapFlagInitializationIndexes[0],
    ) === 0 &&
    sealedReleaseBootstrapFlagCompletionIndexes.length === 1 &&
    powerShellBraceDepthAt(
      sealedReleaseBootstrapTestAnalysis,
      sealedReleaseBootstrapFlagCompletionIndexes[0],
    ) === 1 &&
    /\$script:SealedReleasePowerShellBootstrapVerified = \$true[ \t]*\n[ \t]*\}[ \t]*$/u.test(
      sealedReleaseBootstrapTestAnalysis.commentFreeCode,
    ) &&
    hasOneActivePowerShellMatchAtBraceDepth(
      releaseVerifierToolsetTestsPowerShellAnalysis,
      /^[ \t]*Assert-SealedReleasePowerShellBootstrap[ \t]*$/gmu,
      1,
    ) &&
    sealedReleaseBootstrapAttackMatrixIndexes.length === 1 &&
    powerShellBraceDepthAt(
      sealedReleaseBootstrapTestAnalysis,
      sealedReleaseBootstrapAttackMatrixIndexes[0],
    ) === 1 &&
    sealedReleaseBootstrapAttackExecutionBlockIndexes.length === 1 &&
    powerShellBraceDepthAt(
      sealedReleaseBootstrapTestAnalysis,
      sealedReleaseBootstrapAttackExecutionBlockIndexes[0],
    ) === 1 &&
    sealedReleaseBootstrapAttackExecutionMarkers.every(
      ({ indexes }, position, markers) =>
        indexes.length === 1 &&
        powerShellBraceDepthAt(
          sealedReleaseBootstrapTestAnalysis,
          indexes[0],
        ) === [1, 1, 1, 2, 1][position] &&
        (position === 0 || indexes[0] > markers[position - 1].indexes[0]),
    ) &&
    hasOneActivePowerShellLiteralAtBraceDepth(
      sealedReleaseBootstrapTestAnalysis,
      'Name = "directory-lock-type"',
      2,
    ) &&
    hasOneActivePowerShellLiteralAtBraceDepth(
      sealedReleaseBootstrapTestAnalysis,
      'Name = "toolset-process-type"',
      2,
    ) &&
    hasOneActivePowerShellLiteralAtBraceDepth(
      sealedReleaseBootstrapTestAnalysis,
      'Name = "toolset-process-result-type"',
      2,
    ) &&
    hasOneActivePowerShellLiteralAtBraceDepth(
      sealedReleaseBootstrapTestAnalysis,
      'Name = "loaded-security-module"',
      2,
    ) &&
    hasOneActivePowerShellLiteralAtBraceDepth(
      sealedReleaseBootstrapTestAnalysis,
      'Name = "join-path-shadow"',
      2,
    ) &&
    hasOneActivePowerShellLiteralAtBraceDepth(
      sealedReleaseBootstrapTestAnalysis,
      'Name = "add-type-shadow"',
      2,
    ) &&
    hasOneActivePowerShellLiteralAtBraceDepth(
      sealedReleaseBootstrapTestAnalysis,
      'Name = "long-form-alias-shadow"',
      2,
    ) &&
    sealedReleaseBootstrapTestAnalysis.commentFreeCode.includes(
      "Release PowerShell bootstrap invoked an ambient command shadow",
    ) &&
    commandShadowMarkerGuardIndexes.length === 1 &&
    powerShellBraceDepthAt(
      sealedReleaseBootstrapTestAnalysis,
      commandShadowMarkerGuardIndexes[0],
    ) === 1 &&
    hasOneActivePowerShellMatchAtBraceDepth(
      sealedReleaseBootstrapTestAnalysis,
      /^[ \t]*if \(\[System\.IO\.File\]::Exists\(\$commandShadowMarker\)\) \{/gmu,
      1,
    ) &&
    sealedReleaseBootstrapTestAnalysis.commentFreeCode.includes(
      "AUTHENTICODE_COMMAND_SHADOW_REJECTED",
    ) &&
    authenticodeMarkerGuardIndexes.length === 1 &&
    powerShellBraceDepthAt(
      sealedReleaseBootstrapTestAnalysis,
      authenticodeMarkerGuardIndexes[0],
    ) === 1 &&
    hasOneActivePowerShellMatchAtBraceDepth(
      sealedReleaseBootstrapTestAnalysis,
      /^[ \t]*\[System\.IO\.File\]::Exists\(\$authenticodeMarker\)[ \t]*$/gmu,
      1,
    ) &&
    sealedReleaseBootstrapTestAnalysis.commentFreeCode.includes(
      "Release PowerShell bootstrap accepted a different -File target",
    ) &&
    sealedReleaseBootstrapTestAnalysis.commentFreeCode.includes(
      "Release PowerShell bootstrap accepted an unapproved entry script",
    ) &&
    sealedReleaseBootstrapTestAnalysis.commentFreeCode.includes(
      "Release PowerShell bootstrap accepted a missing exact host flag",
    ) &&
    activePowerShellLiteralIndexes(
      releaseVerifierToolsetTestsPowerShellAnalysis,
      '$missingFlagProbePath = Join-Path $probeRoot "missing-host-flag.ps1"',
    ).length === 1 &&
    missingHostFlagProbeBlock.length > 0 &&
    !missingHostFlagProbeBlock.includes('"-UnknownPrivatePath"') &&
    activePowerShellLiteralIndexes(
      sealedReleaseBootstrapTestAnalysis,
      '-Label "external-first module path"',
    ).length === 1 &&
    releaseVerifierToolsetTests.includes(
      '[System.IO.File]::WriteAllText(__MARKER_PATH__, "module-loaded")',
    ) &&
    sealedReleaseBootstrapTestAnalysis.commentFreeCode.includes(
      "Release wrapper auto-loaded an external module path",
    ) &&
    externalModuleMarkerGuardIndexes.length === 1 &&
    powerShellBraceDepthAt(
      sealedReleaseBootstrapTestAnalysis,
      externalModuleMarkerGuardIndexes[0],
    ) === 1 &&
    hasOneActivePowerShellMatchAtBraceDepth(
      sealedReleaseBootstrapTestAnalysis,
      /^[ \t]*if \(\[System\.IO\.File\]::Exists\(\$moduleMarker\)\) \{/gmu,
      1,
    ) &&
    releaseCommon.includes("function Expand-ReleaseZipArchive") &&
    releaseCommon.includes("Release source archive contains a noncanonical path") &&
    releaseCommon.includes('$segment.Contains("~")') &&
    releaseUnsignedPreparation.includes(
      "Expand-ReleaseZipArchive -LiteralPath $sourceArchive",
    ) &&
    !releaseUnsignedPreparation.includes("Expand-Archive") &&
    releaseCommonTests.includes("Sealed release ZIP extraction accepted a traversal entry") &&
    releaseCommonTests.includes(
      "Sealed release ZIP extraction accepted an NTFS short-name alias",
    ) &&
    releaseCommonTests.includes(
      "Sealed release ZIP extraction accepted a reserved Windows device alias",
    ) &&
    releaseCommon.includes(
      "[System.Management.Automation.CommandTypes]::Application",
    ) &&
    releaseCommonTests.includes(
      "Release application resolution accepted an ambient function",
    ) &&
    releaseCommonTests.includes("function global:node") &&
    releaseCheckPowerShellAnalysis.valid &&
    !releaseCheckPowerShellAnalysis.hasPreExecutionDirective &&
    !hasPowerShellEarlyTerminationOutsideNamedFunctions(
      releaseCheckPowerShellAnalysis,
    ) &&
    releaseCheckInvokeCheckedBlock.trim() ===
      expectedReleaseCheckInvokeCheckedBlock &&
    [ciWorkflow, releaseEvidencePolicyWorkflow].every(
      (workflow) =>
        workflow.split(exactSealedReleaseCheckWorkflowInvocation).length === 2,
    ) &&
    releaseCheck.includes(
      "if (-not [System.IO.Path]::IsPathRooted($NodeExecutable))",
    ) &&
    (releaseCheck.match(/Invoke-Checked -Executable \$NodeExecutable/gu) ?? [])
      .length === 3 &&
    releaseCheckInvokeTestsBlock.includes(
      "$null = Invoke-Checked `\n            -Executable $NodeExecutable `",
    ) &&
    !releaseCheck.includes('Invoke-Checked -Executable "node"') &&
    hasOneActivePowerShellLiteralAtBraceDepth(
      releaseCheckPowerShellAnalysis,
      "[System.Environment+SpecialFolder]::System",
      1,
    ) &&
    releaseCheckInvokeTestsBlock.length > 0 &&
    releaseCheckInvokeTestsAnalysis.valid &&
    releaseCheckInvokeTestsAnalysis.commentFreeCode.trim() ===
      expectedReleaseCheckInvokeTestsBlock &&
    releaseCheckExactPowerShellTestLoopIndexes.length === 1 &&
    powerShellBraceDepthAt(
      releaseCheckInvokeTestsAnalysis,
      releaseCheckExactPowerShellTestLoopIndexes[0],
    ) === 1 &&
    hasOneActivePowerShellMatchAtBraceDepth(
      releaseCheckPowerShellAnalysis,
      /^[ \t]*Invoke-Checked -Executable \$systemPowerShell -CommandArguments @\(/gmu,
      2,
    ) &&
    hasOneActivePowerShellMatchAtBraceDepth(
      releaseCheckInvokeTestsAnalysis,
      /^[ \t]*Invoke-Checked -Executable \$systemPowerShell -CommandArguments @\(\n[ \t]*"-NoLogo",\n[ \t]*"-NoProfile",\n[ \t]*"-NonInteractive",\n[ \t]*"-ExecutionPolicy",\n[ \t]*"Bypass",\n[ \t]*"-File",\n[ \t]*\(Join-Path \$PSScriptRoot \$testScriptName\)\n[ \t]*\)/gmu,
      2,
    ) &&
    activePowerShellMatches(
      releaseCheckHereStringCallDecoy,
      /^[ \t]*Invoke-Checked -Executable \$systemPowerShell -CommandArguments @\(\n[ \t]*"-NoLogo",\n[ \t]*"-NoProfile",\n[ \t]*"-NonInteractive",\n[ \t]*"-ExecutionPolicy",\n[ \t]*"Bypass",\n[ \t]*"-File",\n[ \t]*\(Join-Path \$PSScriptRoot \$testScriptName\)\n[ \t]*\)/gmu,
    ).length === 0,
  "compiled release runtime types must retain exact Type identity, the sealed release check must require an absolute Node application with empty child stderr, and behavior tests must prove fail-closure against type, module, command, argv, and PSModulePath preloads",
);
requireInvariant(
  releaseSecurity.includes("Every release entry that consumes `common.ps1` sets") &&
    releaseSecurity.includes("exact system 64-bit Desktop Windows PowerShell 5.1 image") &&
    releaseSecurity.includes("It never searches `PSModulePath`") &&
    releaseSecurity.includes("zero pre-existing protected `YourWallet.*` types") &&
    releaseSecurity.includes("zero long-form aliases") &&
    releaseSecurity.includes(
      "does not import the script-based `Microsoft.PowerShell.Archive` module",
    ) &&
    releaseSecurity.includes("strong-named GAC assemblies") &&
    releaseSecurity.includes("automatic `~`-form DOS 8.3 aliases") &&
    releaseSecurity.includes(
      "no concurrent same-user mutation of its fresh temporary extraction tree",
    ) &&
    releaseSecurity.includes("verified `CmdletInfo` objects directly") &&
    releaseSecurity.includes("module, protected-type, and command-shadow cleanliness is verified by code") &&
    releaseSecurity.includes("absence of live same-integrity process injection") &&
    releaseSecurity.includes("exact-system-host bootstrap transcript") &&
    sepoliaArchitectureDoc.includes("Every entry that consumes `common.ps1` begins") &&
    sepoliaArchitectureDoc.includes("`PSModulePath` is never searched") &&
    sepoliaArchitectureDoc.includes("zero pre-existing protected `YourWallet.*` types") &&
    sepoliaArchitectureDoc.includes(
      "script-based `Microsoft.PowerShell.Archive` module is not imported",
    ) &&
    sepoliaArchitectureDoc.includes("long-form alias") &&
    sepoliaArchitectureDoc.includes("automatic `~`-form DOS 8.3") &&
    sepoliaArchitectureDoc.includes(
      "no concurrent same-user mutation of its fresh",
    ) &&
    sepoliaArchitectureDoc.includes("verified `CmdletInfo` objects directly"),
  "release documentation must distinguish code-enforced PowerShell namespace cleanliness from the residual system-host, write-protected-toolset, and live-injection trust boundary",
);
for (const pinnedInput of [
  "ExpectedReleaseKeyIdSha256",
  "ExpectedReviewerKeyIdSha256",
  "ExpectedSignerCertificateSha256",
]) {
  requireInvariant(
    offlineReleaseVerificationBlock.includes(`[Parameter(Mandatory = $true)][ValidatePattern("^[0-9a-f]{64}$")][string]$${pinnedInput}`),
    `offline release verification must require independently pinned ${pinnedInput}`,
  );
}
const offlineSequenceShapeOrder = [
  '$hasPreviousManifest = $PSBoundParameters.ContainsKey("PreviousManifest")',
  '$hasPreviousHash = $PSBoundParameters.ContainsKey("ExpectedPreviousManifestSha256")',
  '$isInitialRelease = [string]::Equals($ExpectedReleaseSequence, "1", [System.StringComparison]::Ordinal)',
  "if ($isInitialRelease -and ($hasPreviousManifest -or $hasPreviousHash))",
  "if (-not $isInitialRelease -and (-not $hasPreviousManifest -or -not $hasPreviousHash))",
  "if ($hasPreviousManifest -and [string]::IsNullOrWhiteSpace($PreviousManifest))",
  "Open-VerifiedReleaseToolset",
  "Open-ReadOnlyReleaseTreeLocks",
].map((marker) => offlineReleaseVerificationBlock.indexOf(marker));
requireInvariant(
  JSON.stringify(offlineReleaseRequiredValueNames) === JSON.stringify([
    "Manifest",
    "Signature",
    "ReleasePublicKey",
    "BundleRoot",
    "ExpectedReleaseSequence",
    "ExpectedReleaseKeyIdSha256",
    "ExpectedExtensionId",
    "ExpectedReviewerKeyIdSha256",
    "ExpectedSignerCertificateSha256",
    "ExpectedVerifierToolsetSha256",
  ]) &&
    releaseVerifier.includes(
      '-OptionalValueNames @("PreviousManifest", "ExpectedPreviousManifestSha256")',
    ) &&
    offlineReleaseVerificationBlock.includes(
      '[Parameter(Mandatory = $true)][ValidatePattern("\\A[1-9][0-9]{0,31}\\z", Options = [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)][string]$ExpectedReleaseSequence',
    ) &&
    (offlineReleaseVerificationBlock.match(/\$ExpectedReleaseSequence\b/gu) ?? []).length === 3 &&
    (offlineReleaseVerificationBlock.match(/"--expected-release-sequence"/gu) ?? []).length === 1 &&
    offlineReleaseVerificationBlock.includes(
      '"--expected-release-sequence", $ExpectedReleaseSequence',
    ) &&
    offlineReleaseVerificationBlock.includes(
      'throw "Initial release verification must not supply a previous manifest checkpoint"',
    ) &&
    offlineReleaseVerificationBlock.includes(
      'throw "Successor release verification requires the complete previous manifest checkpoint"',
    ) &&
    offlineReleaseVerificationBlock.includes(
      'throw "Previous manifest checkpoint path must not be empty"',
    ) &&
    offlineSequenceShapeOrder.every((position) => position !== -1) &&
    offlineSequenceShapeOrder.every(
      (position, index, positions) => index === 0 || positions[index - 1] < position,
    ) &&
    (offlineReleaseVerificationBlock.match(/Invoke-ReleaseToolsetNode/gu) ?? []).length === 2,
  "offline release verification must require one canonical external sequence, derive exact initial/successor inputs before candidate reads, and pass one immutable sequence argument twice",
);
requireInvariant(
  offlineReleaseVerificationBlock.includes(
    '[Parameter(Mandatory = $true)][ValidatePattern("^[a-p]{32}$", Options = [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)][string]$ExpectedExtensionId',
  ) &&
    (offlineReleaseVerificationBlock.match(/\$ExpectedExtensionId\b/gu) ?? []).length === 2 &&
    (offlineReleaseVerificationBlock.match(/\bExpectedExtensionId\b/gu) ?? []).length === 2 &&
    (offlineReleaseVerificationBlock.match(/"--expected-extension-id"/gu) ?? []).length === 1 &&
    offlineReleaseVerificationBlock.includes('"--expected-extension-id", $ExpectedExtensionId') &&
    (offlineReleaseVerificationBlock.match(/\$verifyArguments\b/gu) ?? []).length === 4 &&
    (offlineReleaseVerificationBlock.match(/\bverifyArguments\b/gu) ?? []).length === 4 &&
    offlineReleaseVerificationBlock.includes("[string]$ExpectedVerifierToolsetSha256") &&
    (offlineReleaseVerificationBlock.match(/Invoke-ReleaseToolsetNode/gu) ?? []).length === 2 &&
    offlineReleaseVerificationBlock.includes("Open-VerifiedReleaseToolset") &&
    offlineReleaseVerificationBlock.includes("Assert-ReleaseTreesDisjoint") &&
    offlineReleaseVerificationBlock.includes(
      "Get-ReleaseAuthenticodeSignature -LiteralPath $filePath",
    ) &&
    offlineReleaseVerificationBlock.includes(
      'CRYPTOGRAPHIC_BUNDLE_VERIFICATION_PASS_REQUIRES_WINDOWS_WRAPPER`n',
    ) &&
    (offlineReleaseVerificationBlock.match(/\$firstPass\.(?:ExitCode|Stderr|Stdout)/gu) ?? [])
      .length === 3 &&
    (offlineReleaseVerificationBlock.match(/\$secondPass\.(?:ExitCode|Stderr|Stdout)/gu) ?? [])
      .length === 3 &&
    !offlineReleaseVerificationBlock.includes('Get-Command "node"') &&
    !offlineReleaseVerificationBlock.includes('Invoke-ReleaseCommand -Executable "node"') &&
    !/\b(?:Set|Get|New|Remove)-Variable\b|\bInvoke-Expression\b|\biex\b/iu.test(
      releaseVerifier,
    ),
  "offline release verification must retain one immutable two-pass argument list and authenticate a separately pinned verifier toolset",
);
requireInvariant(
  (offlineReleaseVerificationBlock.match(/Invoke-ReleaseToolsetNode/gu) ?? []).length === 2 &&
    offlineReleaseVerificationBlock.includes("$firstPass.ExitCode -ne 0") &&
    offlineReleaseVerificationBlock.includes("$secondPass.ExitCode -ne 0") &&
    offlineReleaseVerificationBlock.includes(
      '[Console]::Out.Write("PRIVATE_MAINNET_CANARY_RELEASE_ELIGIBLE_AFTER_OFFLINE_VERIFICATION`n")',
    ),
  "offline release verification must require two exact sealed cryptographic passes around Authenticode inspection",
);
requireInvariant(
  releaseVerifier.includes("function Invoke-OfflineReleaseVerification") &&
    releaseVerifier.includes("Invoke-OfflineReleaseVerification @boundArguments") &&
    releaseVerifier.includes("ConvertFrom-ExactNamedArguments") &&
    releaseVerifier.includes(
      'RELEASE_VERIFICATION_FAILED: offline release verification failed closed',
    ) &&
    !/^\uFEFF?\[CmdletBinding\(\)\]/u.test(releaseVerifier) &&
    !releaseVerifier.includes("Resolve-Path -LiteralPath $BundleRoot") &&
    releaseVerifier.includes(
      "Open-ReadOnlyReleaseTreeLocks -BundleRoot $BundleRoot -AdditionalFiles $additionalInputs",
    ) &&
    releaseVerifier.includes("$bundle = $releaseLocks.CanonicalBundleRoot") &&
    releaseVerifier.includes(
      "$canonicalInputs = @($releaseLocks.CanonicalAdditionalFiles)",
    ) &&
    (releaseVerifier.match(/\$BundleRoot\b/gu) ?? []).length === 2 &&
    releaseCommon.includes("GetFinalPathNameByHandleW") &&
    releaseCommon.includes("private const uint VolumeNameGuid = 0x00000001") &&
    releaseCommon.includes("FileInfoByHandleClass.FileIdInfo") &&
    releaseCommon.includes("information.VolumeSerialNumber == UInt64.MaxValue") &&
    releaseCommon.includes("information.FileId.LowPart == UInt64.MaxValue") &&
    releaseCommon.includes("information.FileId.HighPart == UInt64.MaxValue") &&
    releaseCommon.includes("Release paths must canonicalize to a local volume GUID") &&
    releaseCommon.includes("Open-PinnedReleaseDirectoryPath") &&
    releaseCommon.includes("Open-PinnedReleaseFilePath") &&
    releaseCommon.includes(
      "SameIdentity($bootstrap, $handles[$handles.Count - 1])",
    ) &&
    releaseCommon.includes("SameIdentity($bootstrap, $fileHandle)") &&
    releaseCommon.includes("CanonicalBundleRoot = $canonicalRoot") &&
    releaseCommon.includes("CanonicalAdditionalFiles = $canonicalAdditionalFiles.ToArray()") &&
    releaseCommon.includes("function Open-VerifiedReleaseToolset") &&
    releaseCommon.includes("function Invoke-ReleaseToolsetNode") &&
    releaseCommon.includes("function Close-VerifiedReleaseToolset") &&
    releaseCommon.includes("function Assert-ReleaseTreesDisjoint") &&
    releaseCommon.includes("scripts/release/review-evidence-set.ps1") &&
    releaseCommon.includes("scripts/release/verify-release-offline.ps1") &&
    releaseCommon.includes("Release toolset files must have exactly one hard link") &&
    releaseCommon.includes("Release toolset files may not contain alternate data streams") &&
    releaseCommon.includes("function ConvertFrom-ExactNamedArguments") &&
    releaseCommon.includes(
      "Dictionary[string, object]]::new([System.StringComparer]::Ordinal)",
    ) &&
    releaseCommon.includes("Release command received a duplicate value argument") &&
    releaseCommon.includes("Release command is missing a required argument") &&
    !/\b(?:Invoke-Expression|iex)\b/iu.test(releaseCommon) &&
    releaseCommonTests.includes("function Test-ExactReviewBinding") &&
    releaseCommonTests.includes("Test-ExactReviewBinding @exactArguments") &&
    releaseCommonTests.includes('"-bundleroot", "wrong-case"') &&
    releaseCommonTests.includes('New-Item -ItemType Junction -Path $aliasPath -Target $aliasTargetA') &&
    releaseCommonTests.includes('[System.IO.Directory]::Delete($aliasPath)') &&
    releaseCommonTests.includes('New-Item -ItemType Junction -Path $aliasPath -Target $aliasTargetB') &&
    releaseCommonTests.includes("$aliasLockSet.CanonicalBundleRoot") &&
    releaseCommonTests.includes("$aliasLockSet.CanonicalAdditionalFiles") &&
    releaseCommonTests.includes(
      "$authenticodePathProbe = Get-ReleaseAuthenticodeSignature -LiteralPath",
    ) &&
    releaseCommonTests.includes(
      "Authenticode inspection did not accept the canonical volume-GUID path",
    ),
  "offline release paths must discard aliases only after canonical volume ancestry and full Win32 identity are pinned, with live junction-retarget evidence",
);
requireInvariant(
  releaseManifestVerifier.includes(
    "const WINDOWS_VOLUME_GUID_PATH_RE = /^\\\\\\\\\\?\\\\Volume\\{[0-9A-Fa-f]{8}-",
  ) &&
    resolveExactReleasePathBlock.includes('process.platform === "win32"') &&
    resolveExactReleasePathBlock.includes("WINDOWS_VOLUME_GUID_PATH_RE.test(input)") &&
    resolveExactReleasePathBlock.includes("path.win32.normalize(input) === input") &&
    resolveExactReleasePathBlock.includes("const entries = await readdir(current)") &&
    resolveExactReleasePathBlock.includes("entries.filter((entry) => entry === segment).length !== 1") &&
    resolveExactReleasePathBlock.includes("return input") &&
    resolveExactReleasePathBlock.includes("return realpath(input)") &&
    (assertNoReparseComponentsBlock.match(/resolveExactReleasePath\(/gu) ?? []).length === 2 &&
    (releaseReviewEvidenceSet.match(/resolveExactReleasePath\(/gu) ?? []).length === 3 &&
    (releaseManifestAssembler.match(/resolveExactReleasePath\(/gu) ?? []).length === 2 &&
    releaseCommonTests.includes(
      "import{resolveExactReleasePath}from'./scripts/release/release-manifest.mjs'",
    ) &&
    releaseCommonTests.includes("await resolveExactReleasePath(process.argv[1])") &&
    releaseCommonTests.includes("$subjectLocks.CanonicalBundleRoot") &&
    releaseCommonTests.includes("$caseAliasCapitalized") &&
    releaseCommonTests.includes("result.status===0||result.stdout!==''") &&
    releaseCommonTests.includes("REVIEW_EVIDENCE_SET_FAILED: staged evidence set is not exact\\n"),
  "the deterministic Node consumers must accept only normalized, exact-case local volume-GUID paths without re-resolving their pinned Windows alias, while retaining realpath elsewhere",
);
const releaseCreateProcessIndex = releaseCommon.indexOf("if (!CreateProcessW(");
const releaseCreateEventIndex = releaseCommon.indexOf(
  "if (eventCode != CreateProcessDebugEvent || Invalid(eventFile))",
);
const releaseMappedIdentityIndex = releaseCommon.indexOf(
  "FileIdInformation mappedIdentity = Identity(eventFile);",
);
const releasePreDetachSuspendIndex = releaseCommon.indexOf(
  "previousSuspendCount = SuspendThread(primaryThread);",
  releaseMappedIdentityIndex,
);
const releaseContinueDebugIndex = releaseCommon.indexOf(
  "if (!ContinueDebugEvent(eventProcessId, eventThreadId, DbgContinue))",
  releasePreDetachSuspendIndex,
);
const releaseDetachDebugIndex = releaseCommon.indexOf(
  "if (!DebugActiveProcessStop(processId))",
  releaseContinueDebugIndex,
);
const releaseFinalResumeIndex = releaseCommon.indexOf(
  "previousSuspendCount = ResumeThread(primaryThread);",
  releaseDetachDebugIndex,
);
const releaseRunOnFreshThread = rustItemBlock(
  releaseCommon,
  /private static ReleaseToolsetProcessResult RunOnFreshThread\(/u,
);
const releaseFreshWorkerEntry = rustItemBlock(
  releaseCommon,
  /public static ReleaseToolsetProcessResult Run\(/u,
);
const releaseCreationCriticalOrder = [
  "Monitor.TryEnter(",
  "CreatePipe(out stdoutRead",
  "SetHandleInformation(stdoutRead, HandleFlagInherit, 0)",
  "Marshal.WriteIntPtr(inheritedHandles, 0, stdinRead.DangerousGetHandle())",
  "if (!CreateProcessW(",
  "rawProcess = information.Process",
  "process = AdoptRawHandle(ref rawProcess)",
  "primaryThread = AdoptRawHandle(ref rawThread)",
  "DisposeHandle(ref stdoutWrite)",
  "DisposeHandle(ref stderrWrite)",
  "DisposeHandle(ref stdinRead)",
  "DisposeHandle(ref stdinWrite)",
  "DeleteProcThreadAttributeList(attributeList)",
  "FreeBuffer(ref attributeList)",
  "Monitor.Exit(ProcessCreationSync)",
  "Invalid(process) ||",
].map((marker) => releaseRunOnFreshThread.indexOf(marker));
requireInvariant(
  releaseRunOnFreshThread.length > 0 &&
    releaseFreshWorkerEntry.length > 0 &&
    (releaseCommon.match(
      /private static readonly object ProcessCreationSync = new object\(\);/gu,
    ) ?? []).length === 1 &&
    (releaseRunOnFreshThread.match(/Monitor\.TryEnter\(/gu) ?? []).length === 1 &&
    (releaseRunOnFreshThread.match(/Monitor\.Exit\(ProcessCreationSync\)/gu) ?? [])
      .length === 1 &&
    !releaseCommon.includes("lock (ProcessCreationSync)") &&
    releaseRunOnFreshThread.includes(
      "checked((int)RemainingMilliseconds(\n                        timer,",
    ) &&
    releaseRunOnFreshThread.includes("ref processCreationLockTaken") &&
    releaseRunOnFreshThread.includes("if (!processCreationLockTaken)") &&
    (releaseRunOnFreshThread.match(/CreatePipe\(out /gu) ?? []).length === 3 &&
    (releaseRunOnFreshThread.match(/SetHandleInformation\(/gu) ?? []).length === 3 &&
    releaseRunOnFreshThread.includes(
      "SetHandleInformation(stderrRead, HandleFlagInherit, 0)",
    ) &&
    releaseRunOnFreshThread.includes(
      "SetHandleInformation(stdinWrite, HandleFlagInherit, 0)",
    ) &&
    releaseRunOnFreshThread.includes(
      "Marshal.WriteIntPtr(inheritedHandles, IntPtr.Size, stdoutWrite.DangerousGetHandle())",
    ) &&
    releaseRunOnFreshThread.includes(
      "Marshal.WriteIntPtr(inheritedHandles, IntPtr.Size * 2, stderrWrite.DangerousGetHandle())",
    ) &&
    (releaseRunOnFreshThread.match(/if \(!CreateProcessW\(/gu) ?? []).length === 1 &&
    releaseRunOnFreshThread.includes("rawThread = information.Thread") &&
    releaseRunOnFreshThread.includes("information.Process = IntPtr.Zero") &&
    releaseRunOnFreshThread.includes("information.Thread = IntPtr.Zero") &&
    releaseRunOnFreshThread.includes("rawEventFile = observedFile") &&
    releaseRunOnFreshThread.includes("eventFile = AdoptRawHandle(ref rawEventFile)") &&
    releaseRunOnFreshThread.includes("TerminateAndReapRaw(") &&
    releaseRunOnFreshThread.includes("CloseRawHandle(ref rawEventFile)") &&
    releaseRunOnFreshThread.includes("CloseRawHandle(ref rawThread)") &&
    releaseRunOnFreshThread.includes("CloseRawHandle(ref rawProcess)") &&
    (releaseFreshWorkerEntry.match(/RunOnFreshThread\(/gu) ?? []).length === 1 &&
    releaseFreshWorkerEntry.includes("Thread worker = new Thread(delegate()") &&
    releaseCreationCriticalOrder.every((position) => position !== -1) &&
    releaseCreationCriticalOrder.every(
      (position, index, positions) => index === 0 || positions[index - 1] < position,
    ),
  "the C# verifier runner must bound one fresh-thread coordination wait, create every inheritable pipe inside it, close all child ends before attribute cleanup and release, and retain raw-handle cleanup fallbacks",
);
requireInvariant(
  releaseCommon.includes("private const uint DebugOnlyThisProcess = 0x00000002") &&
    releaseCommon.includes("private const uint CreateSuspended = 0x00000004") &&
    releaseCommon.includes("private const long ProcThreadAttributeHandleList = 0x00020002") &&
    releaseCommon.includes("private const long ProcThreadAttributeMitigationPolicy = 0x00020007") &&
    releaseCommon.includes("new IntPtr(IntPtr.Size * 3)") &&
    releaseCommon.includes('"PATH=" + systemDirectory') &&
    releaseCommon.includes('"SystemRoot=" + windowsDirectory') &&
    releaseCommon.includes('"WINDIR=" + windowsDirectory') &&
    /environment,\r?\n\s*systemDirectory,/u.test(releaseCommon) &&
    releaseCommon.includes("WaitForDebugEventEx(debugEvent, eventWait)") &&
    releaseCommon.includes("GetProcessIdFromEvent(eventProcess)") &&
    releaseCommon.includes("GetThreadIdFromEvent(eventThread)") &&
    releaseCommon.includes("FileIdInformation mappedIdentity = Identity(eventFile);") &&
    releaseCommon.includes("if (!SameIdentity(expectedIdentity, mappedIdentity))") &&
    releaseCommon.includes('previousSuspendCount != 0') &&
    releaseCommon.includes('previousSuspendCount != 2') &&
    releaseCommon.includes('previousSuspendCount != 1') &&
    releaseCommon.includes("using System.Runtime.ExceptionServices;") &&
    releaseCommon.includes("Thread worker = new Thread(delegate()") &&
    releaseCommon.includes("result = RunOnFreshThread(") &&
    releaseCommon.includes("failure = ExceptionDispatchInfo.Capture(error)") &&
    releaseCommon.includes("worker.IsBackground = false") &&
    releaseCommon.includes("worker.Join()") &&
    releaseCommon.includes("private static ReleaseToolsetProcessResult RunOnFreshThread(") &&
    releaseCommon.includes("[System.Environment]::Is64BitOperatingSystem") &&
    releaseCommon.includes("[System.Environment]::Is64BitProcess") &&
    releaseCreateProcessIndex !== -1 &&
    releaseCreateProcessIndex < releaseCreateEventIndex &&
    releaseCreateEventIndex < releaseMappedIdentityIndex &&
    releaseMappedIdentityIndex < releasePreDetachSuspendIndex &&
    releasePreDetachSuspendIndex < releaseContinueDebugIndex &&
    releaseContinueDebugIndex < releaseDetachDebugIndex &&
    releaseDetachDebugIndex < releaseFinalResumeIndex,
  "the sealed verifier runner must isolate one fresh 64-bit debugger thread and authenticate the first mapped image by full file identity before a guarded detach and final user-mode resume",
);
requireInvariant(
  releaseCommon.includes('"--no-addons"') &&
    releaseCommon.includes('"--no-global-search-paths"') &&
    releaseCommon.includes('"--experimental-vm-modules"') &&
    releaseCommon.includes("new TextDecoder(\"utf-8\", { fatal: true })") &&
    releaseCommon.includes("new vm.SourceTextModule(readSource(name)") &&
    releaseCommon.includes("new vm.SyntheticModule(names") &&
    releaseCommon.includes("const sealedArgv = Object.freeze([") &&
    releaseCommon.includes("const processFacade = Object.create(null)") &&
    releaseCommon.includes("Object.freeze(processFacade)") &&
    releaseCommon.includes('Object.defineProperty(sandbox, "Buffer"') &&
    releaseCommon.includes('Object.defineProperty(sandbox, "TextDecoder"') &&
    releaseCommon.includes("const context = vm.createContext(sandbox") &&
    releaseCommon.includes("codeGeneration: { strings: false, wasm: false }") &&
    releaseCommon.includes('if (specifier === "node:process")') &&
    releaseCommon.includes('synthetic.setExport("default", processFacade)') &&
    releaseCommon.includes('"node:crypto"') &&
    releaseCommon.includes('"node:fs/promises"') &&
    releaseCommon.includes('"node:path"') &&
    releaseCommon.includes('"node:process"') &&
    releaseCommon.includes('"node:url"') &&
    releaseCommon.includes('specifier === "./release-manifest.mjs"') &&
    releaseCommon.includes(
      'specifier === "../../extension/native-host/validate-manifest.mjs"',
    ) &&
    releaseCommon.includes('throw new Error("sealed loader refused an unapproved module edge")') &&
    releaseCommon.includes('importModuleDynamically() { throw new Error("dynamic module loading is disabled"); }') &&
    !releaseCommon.includes("process.argv = [") &&
    releaseCommon.includes('$record.VolumePaths["extension/native-host/validate-manifest.mjs"]') &&
    releaseCommon.includes('$record.VolumePaths["scripts/release/release-manifest.mjs"]') &&
    releaseCommon.includes('$record.VolumePaths["scripts/release/review-evidence-set.mjs"]') &&
    /\$record\.IdentityHandles\["node\.exe"\],\r?\n\s*\$record\.DosPaths\["node\.exe"\]/u.test(
      releaseCommon,
    ),
  "the sealed verifier must run only the retained Node image and a fatal-UTF-8 isolated module context with a minimal process facade, exact edges, built-ins, and volume-GUID sources",
);
requireInvariant(
  releaseCommon.includes(".your-wallet-file-write-probe-") &&
    releaseCommon.includes(".your-wallet-directory-write-probe-") &&
    releaseCommon.includes("[System.IO.Directory]::CreateDirectory($directoryProbePath)") &&
    releaseCommon.includes("[System.IO.Directory]::Delete($directoryProbePath, $false)") &&
    (releaseCommon.match(/\$nativeError -eq 19/gu) ?? []).length === 2 &&
    releaseCommon.includes("could not prove that a staging directory denies file creation") &&
    releaseCommon.includes("could not prove that a staging directory denies subdirectory creation") &&
    !releaseCommon.includes("Get-FileHash") &&
    !releaseVerifierToolsetPreparation.includes("Get-FileHash") &&
    (releaseCommon.match(/Get-Sha256Lower -LiteralPath/gu) ?? []).length >= 2 &&
    releaseVerifierToolsetPreparation.includes("Get-Sha256Lower -LiteralPath"),
  "release tree write protection must deny both file and subdirectory creation for only proven access/write-protect reasons, while security hashes bypass ambient cmdlets",
);
requireInvariant(
  releaseCommonTests.includes("$wrapperJob = Start-Job -ScriptBlock") &&
    releaseCommonTests.includes("public static class BlockingReviewNodeProxy") &&
    releaseCommonTests.includes('File.WriteAllText(ReadyPath, "ready"') &&
    releaseCommonTests.includes(
      "while (!File.Exists(ContinuePath))",
    ) &&
    releaseCommonTests.includes(
      '"-ExpectedVerifierToolsetSha256"',
    ) &&
    releaseCommonTests.includes("$wrapperToolsetHash = Get-InventorySha256") &&
    releaseCommonTests.includes("$wrapperToolsetRoot") &&
    releaseCommonTests.includes("$wrapperResult.Stdout") &&
    releaseCommonTests.includes("$wrapperResult.Stderr") &&
    releaseCommonTests.includes('$subject.Stdout + "`n"') &&
    !releaseCommonTests.includes("$wrapperResult.Output.Trim()") &&
    releaseWrapperCeremonyBlock.length > 0 &&
    !/function\s+(?:global:)?node\s*\{/u.test(releaseWrapperCeremonyBlock) &&
    releaseCommonTests.includes("if ([System.IO.File]::Exists($taskReadyPath))") &&
    (releaseCommonTests.match(/\[System\.IO\.Directory\]::Move\(\$subjectRoot, \$subjectMoveProbe\)/gu) ?? [])
      .length === 2 &&
    (releaseCommonTests.match(/\[System\.IO\.Directory\]::Move\(\$subjectMoveProbe, \$subjectRoot\)/gu) ?? [])
      .length === 2 &&
    releaseCommonTests.includes(
      "Review wrapper released canonical locks before its Node child completed",
    ) &&
    releaseCommonTests.includes('[System.IO.Directory]::Delete($subjectAlias)') &&
    releaseCommonTests.includes(
      'New-Item -ItemType Junction -Path $subjectAlias -Target $subjectReplacementParent',
    ) &&
    releaseCommonTests.includes(
      '[System.IO.File]::WriteAllText($taskContinuePath, "continue")',
    ) &&
    releaseCommonTests.includes('$replacementSubject.Stdout + "`n"') &&
    releaseCommonTests.includes(
      "Review wrapper followed the replacement ancestor alias",
    ) &&
    releaseCheck.includes(
      'foreach ($testScriptName in @("common.test.ps1", "verifier-toolset.test.ps1"))',
    ) &&
    releaseCheck.includes("Invoke-Checked -Executable $systemPowerShell") &&
    releaseCheck.includes("(Join-Path $PSScriptRoot $testScriptName)"),
  "the release gate must execute a real successful sealed-toolset wrapper ceremony whose pinned blocked child survives an ancestor junction retarget while returning exact canonical A bytes",
);
const normalizedValidateReleaseManifest = validateReleaseManifestBlock
  .replace(/\s+/gu, " ")
  .trim();
requireInvariant(
  normalizedValidateReleaseManifest ===
    'export function validateManifest(manifest, previousManifest) { const current = validateCore(manifest); if (current.top.sequence === "1") { if (previousManifest !== undefined && previousManifest !== null) fail("initial release must not be verified with a previous manifest"); return current; } if (previousManifest === undefined || previousManifest === null) fail("a non-initial release requires the exact previous manifest"); const previous = validateCore(previousManifest); if (current.top.extension.id !== previous.top.extension.id) { fail("stable extension identity changed across release lineage"); } const expectedSequence = (BigInt(previous.top.sequence) + 1n).toString(); requireExact(current.top.sequence, expectedSequence, "manifest.sequence"); requireExact(current.top.lineage.previousSequence, previous.top.sequence, "manifest.lineage.previousSequence"); requireExact(current.top.lineage.previousVersion, previous.top.version, "manifest.lineage.previousVersion"); const previousHash = sha256Hex(Buffer.from(canonicalEncode(previous.top), "utf8")); requireExact(current.top.lineage.previousManifestSha256, previousHash, "manifest.lineage.previousManifestSha256"); if (compareSemver(current.top.version, previous.top.version) <= 0) fail("release version rollback or reuse is forbidden"); return current; }',
  "successor validation must retain the same stable extension identity before accepting sequence, hash, or version lineage",
);
requireInvariant(
  verifyExpectedExtensionIdBlock.replace(/\s+/gu, " ").trim() ===
    'export function verifyExpectedExtensionId(validated, expectedExtensionId) { requireString( expectedExtensionId, "independently pinned extension identifier", EXTENSION_ID_RE, 32, ); if (validated.top.extension.id !== expectedExtensionId) { fail("independently pinned extension identifier mismatch"); } }' &&
    releaseManifestVerifier.includes('const EXTENSION_ID_RE = /^[a-p]{32}$/u;') &&
    (releaseManifestVerifier.match(/\bverifyExpectedExtensionId\b/gu) ?? []).length === 2 &&
    (releaseManifestVerifier.match(/\bvalidateManifest\b/gu) ?? []).length === 3 &&
    !/\b(?:eval|Function)\s*\(|globalThis\s*\[/u.test(releaseManifestVerifier),
  "the final Node verifier must compare one exact lowercase candidate extension ID with one independent pin without echoing either value",
);
requireInvariant(
  releaseManifestVerifier.includes("const RELEASE_SEQUENCE_RE = /^[1-9][0-9]{0,31}$/u;") &&
    validateExpectedReleaseSequenceBlock.includes(
      'typeof expectedReleaseSequence !== "string"',
    ) &&
    validateExpectedReleaseSequenceBlock.includes(
      "!RELEASE_SEQUENCE_RE.test(expectedReleaseSequence)",
    ) &&
    validateExpectedReleaseSequenceBlock.includes(
      'fail("independently pinned release sequence has an invalid format")',
    ) &&
    validateExpectedReleaseSequenceBlock.includes("return expectedReleaseSequence") &&
    verifyExpectedReleaseSequenceBlock.includes(
      "validateExpectedReleaseSequence(expectedReleaseSequence)",
    ) &&
    verifyExpectedReleaseSequenceBlock.includes(
      "validated.top.sequence !== expectedReleaseSequence",
    ) &&
    verifyExpectedReleaseSequenceBlock.includes(
      'fail("independently pinned release sequence mismatch")',
    ) &&
    (releaseManifestVerifier.match(/\bverifyExpectedReleaseSequence\b/gu) ?? []).length === 2 &&
    (releaseManifestVerifier.match(/\bvalidateExpectedReleaseSequence\b/gu) ?? []).length === 3,
  "the final Node verifier must export one exact canonical external-sequence comparison with fixed non-echoing failures",
);
const releaseVerifyCliStart = runReleaseManifestCliBlock.indexOf('if (command === "verify")');
const releaseVerifyCliBlock = runReleaseManifestCliBlock.slice(releaseVerifyCliStart);
const normalizedReleaseVerifyCliBlock = releaseVerifyCliBlock.replace(/\s+/gu, " ").trim();
const releaseSequencePreReadOrder = [
  "const expectedReleaseSequence = validateExpectedReleaseSequence(",
  'requireArgument(values, "--expected-release-sequence")',
  'const initialRelease = expectedReleaseSequence === "1"',
  'const hasPrevious = values.has("--previous")',
  'const hasExpectedPrevious = values.has("--expected-previous-manifest-sha256")',
  "if (initialRelease && (hasPrevious || hasExpectedPrevious))",
  "if (!initialRelease && (!hasPrevious || !hasExpectedPrevious))",
  "const requiredNames = [",
  "const expectedValueCount = initialRelease ? 9 : 11",
  "requiredNames.length !== expectedValueCount",
  "values.size !== expectedValueCount",
  "for (const name of requiredNames) requireArgument(values, name)",
  "const requireCanonical = true",
  "const manifest = await readStrictJsonFile",
].map((marker) => releaseVerifyCliBlock.indexOf(marker));
const releaseSequenceFirstCandidateRead = releaseVerifyCliBlock.indexOf(
  "const manifest = await readStrictJsonFile",
);
const releaseSequencePreReadPrefix = releaseVerifyCliBlock.slice(
  0,
  releaseSequenceFirstCandidateRead,
);
requireInvariant(
  releaseVerifyCliStart !== -1 &&
    releaseSequenceFirstCandidateRead !== -1 &&
    releaseSequencePreReadOrder.every((position) => position !== -1) &&
    releaseSequencePreReadOrder.every(
      (position, index, positions) => index === 0 || positions[index - 1] < position,
    ) &&
    releaseVerifyCliBlock.includes(
      'fail("initial verification must not supply --previous or --expected-previous-manifest-sha256")',
    ) &&
    releaseVerifyCliBlock.includes(
      'fail("successor verification requires --previous and --expected-previous-manifest-sha256 from the offline checkpoint")',
    ) &&
    releaseVerifyCliBlock.includes('"--expected-release-sequence"') &&
    releaseVerifyCliBlock.includes(
      '...(initialRelease ? [] : ["--previous", "--expected-previous-manifest-sha256"])',
    ) &&
    !/\b(?:readFile|readStrictJsonFile|verifyBundleFiles|verifyEvidenceAttestations)\s*\(/u.test(
      releaseSequencePreReadPrefix,
    ),
  "the Node CLI must validate the external sequence, exact 9/11-value arity, and previous-input shape before every candidate read",
);
const externalPinCliOrder = [
  'const validated = validateManifest(manifest, previous)',
  'verifyExpectedReleaseKeyId(validated, requireArgument(values, "--expected-release-key-id"))',
  'verifyExpectedExtensionId(validated, requireArgument(values, "--expected-extension-id"))',
  "verifyExpectedReleaseSequence(validated, expectedReleaseSequence)",
  "verifyExpectedSignerCertificateSha256(",
  "verifyExpectedPreviousManifestSha256(validated, expectedPreviousManifestSha256)",
  'const bundleRoot = requireArgument(values, "--bundle-root")',
  "await verifyBundleFiles(validated, bundleRoot)",
  "await verifyEvidenceAttestations(",
  "await verifyDetachedManifestSignature(",
  'process.stdout.write("CRYPTOGRAPHIC_BUNDLE_VERIFICATION_PASS_REQUIRES_WINDOWS_WRAPPER\\n")',
].map((marker) => releaseVerifyCliBlock.indexOf(marker));
requireInvariant(
  externalPinCliOrder.every((position) => position !== -1) &&
    externalPinCliOrder.every(
      (position, index, positions) => index === 0 || positions[index - 1] < position,
    ) &&
    releaseVerifyCliBlock.includes("const expectedValueCount = initialRelease ? 9 : 11") &&
    normalizedReleaseVerifyCliBlock.includes(
      'verifyExpectedReleaseKeyId(validated, requireArgument(values, "--expected-release-key-id")); verifyExpectedExtensionId(validated, requireArgument(values, "--expected-extension-id")); verifyExpectedReleaseSequence(validated, expectedReleaseSequence);',
    ),
  "extension identity and external release sequence must be pinned immediately after the release key and before signer/previous hash pins, bundle/evidence reads, or signature acceptance",
);
requireInvariant(
  extensionPinUnitTestBlock.includes(
    "verifyExpectedExtensionId(validated, manifest.extension.id)",
  ) &&
    extensionPinUnitTestBlock.includes('const alternate = "b".repeat(32)') &&
    extensionPinUnitTestBlock.includes("assert.doesNotMatch(error.message") &&
    extensionPinUnitTestBlock.includes('verifyExpectedExtensionId(validated, "A".repeat(32))') &&
    extensionLineageUnitTestBlock.includes('current.extension.id = "b".repeat(32)') &&
    extensionLineageUnitTestBlock.includes(
      "stable extension identity changed across release lineage",
    ),
  "unit evidence must cover exact extension pinning, case rejection, no-value diagnostics, and successor continuity",
);
requireInvariant(
  releaseSequenceSuccessUnitTestBlock.includes(
    'verifyExpectedReleaseSequence(validatedInitial, "1")',
  ) &&
    releaseSequenceSuccessUnitTestBlock.includes(
      'verifyExpectedReleaseSequence(validatedSuccessor, "2")',
    ) &&
    releaseSequenceReplayUnitTestBlock.includes(
      'verifyExpectedReleaseSequence(validated, "2")',
    ) &&
    releaseSequenceReplayUnitTestBlock.includes(
      'assert.equal(error.message, "independently pinned release sequence mismatch")',
    ) &&
    releaseSequenceReplayUnitTestBlock.includes(
      "assert.doesNotMatch(error.message, /[12]/u)",
    ) &&
    releaseSequenceFormatUnitTestBlock.includes(
      '["0", "01", "+1", "1.0", "1".repeat(33), "latest", "1\\n", "1\\r\\n", "1\\u2028"]',
    ) &&
    releaseSequenceFormatUnitTestBlock.includes(
      "independently pinned release sequence has an invalid format",
    ),
  "unit evidence must cover exact initial/successor sequence pins, canonical-decimal rejection, and non-echoing old-sequence replay denial",
);
requireInvariant(
  releaseSequenceRequiredCliTestBlock.includes(
    'argumentsList.indexOf("--expected-release-sequence")',
  ) &&
    releaseSequenceRequiredCliTestBlock.includes("argumentsList.splice(sequenceIndex, 2)") &&
    releaseSequenceRequiredCliTestBlock.includes(
      '"missing required argument --expected-release-sequence"',
    ) &&
    releaseSequenceArityCliTestBlock.includes(
      '[...verifyCliArguments(), "--unexpected", "value"]',
    ) &&
    releaseSequenceArityCliTestBlock.includes('for (const malformed of ["01", "latest"])') &&
    releaseSequencePairCliTestBlock.includes('verifyCliArguments("2")') &&
    releaseSequencePairCliTestBlock.includes(
      '"successor verification requires --previous and --expected-previous-manifest-sha256 from the offline checkpoint"',
    ) &&
    releaseSequencePairCliTestBlock.includes(
      '...verifyCliArguments("1")',
    ) &&
    releaseSequencePairCliTestBlock.includes(
      '"initial verification must not supply --previous or --expected-previous-manifest-sha256"',
    ) &&
    releaseManifestTests.includes(
      "assert.doesNotMatch(result.stderr, /unread-(?:manifest|signature|public-key|bundle)/u)",
    ),
  "CLI evidence must reject missing, surplus, malformed, initial-pair, and successor-without-pair shapes before reading candidate paths",
);
requireInvariant(
  extensionPinSuccessIntegrationTestBlock.includes(
    "const invocation = await createVerifyCliInvocation(fixture)",
  ) &&
    extensionPinSuccessIntegrationTestBlock.includes(
      "const { stdout } = await execFileAsync(process.execPath, invocation.arguments)",
    ) &&
    extensionPinSuccessIntegrationTestBlock.includes(
      'assert.equal(stdout, "CRYPTOGRAPHIC_BUNDLE_VERIFICATION_PASS_REQUIRES_WINDOWS_WRAPPER\\n")',
    ) &&
    extensionPinArityIntegrationTestBlock.includes(
      'invocation.arguments.indexOf("--expected-extension-id")',
    ) &&
    extensionPinArityIntegrationTestBlock.includes("missing.splice(extensionArgument, 2)") &&
    extensionPinArityIntegrationTestBlock.includes(
      'const extra = [...invocation.arguments, "--candidate-extension-id", "c".repeat(32)]',
    ) &&
    (extensionPinArityIntegrationTestBlock.match(/await assert\.rejects\s*\(/gu) ?? [])
      .length === 2,
  "integration evidence must preserve exact success output and reject both missing and surplus extension-pin arguments",
);
requireInvariant(
  rebindSyntheticExtensionIdentityBlock.includes(
    "fixture.manifest.extension.id = extensionId",
  ) &&
    rebindSyntheticExtensionIdentityBlock.includes(
      "allowed_origins: [`chrome-extension://${extensionId}/`]",
    ) &&
    rebindSyntheticExtensionIdentityBlock.includes(
      'for (const key of ["installerAclNegative", "nativeHostRegistration"])',
    ) &&
    rebindSyntheticExtensionIdentityBlock.includes("evidence.extensionId = extensionId") &&
    rebindSyntheticExtensionIdentityBlock.includes(
      "evidence.nativeHostManifestSha256 = nativeHostManifestRecord.sha256",
    ) &&
    rebindSyntheticExtensionIdentityBlock.includes(
      "fixture.manifest.evidence[key] = await fileRecord(fixture.root, relativePath)",
    ),
  "alternate-ID evidence must rebind the signed manifest, native origin, installer ACL, registration, and exact evidence digests before the external pin rejects it",
);
requireInvariant(
    extensionPinAttackerIntegrationTestBlock.includes(
      "await rebindSyntheticExtensionIdentity(fixture, attackerExtensionId)",
    ) &&
    extensionPinAttackerIntegrationTestBlock.includes(
      "await reissueIndependentReview(fixture)",
    ) &&
    extensionPinAttackerIntegrationTestBlock.includes(
      "verifyExpectedExtensionId(validated, attackerExtensionId)",
    ) &&
    extensionPinAttackerIntegrationTestBlock.includes(
      "await assert.doesNotReject(() => verifySyntheticBundle(fixture))",
    ) &&
    extensionPinAttackerIntegrationTestBlock.includes(
      "const invocation = await createVerifyCliInvocation(fixture, EXTENSION_ID)",
    ) &&
    extensionPinAttackerIntegrationTestBlock
      .replace(/\s+/gu, " ")
      .includes(
        'assert.equal( error.stderr, "RELEASE_INELIGIBLE: independently pinned extension identifier mismatch\\n", )',
      ) &&
    extensionPinAttackerIntegrationTestBlock.includes('assert.equal(error.stdout, "")') &&
    extensionPinWrapperIntegrationTestBlock.includes("RegexOptions]::CultureInvariant") &&
    extensionPinWrapperIntegrationTestBlock.includes('"A".repeat(32)') &&
    extensionPinWrapperIntegrationTestBlock.includes(
      "ExpectedVerifierToolsetSha256",
    ) &&
    extensionPinWrapperIntegrationTestBlock.includes("Open-VerifiedReleaseToolset") &&
    extensionPinWrapperIntegrationTestBlock.includes("Invoke-ReleaseToolsetNode") &&
    extensionPinWrapperIntegrationTestBlock.includes(
      "CRYPTOGRAPHIC_BUNDLE_VERIFICATION_PASS_REQUIRES_WINDOWS_WRAPPER`n",
    ) &&
    extensionPinWrapperIntegrationTestBlock.includes(
      "PRIVATE_MAINNET_CANARY_RELEASE_ELIGIBLE_AFTER_OFFLINE_VERIFICATION`n",
    ),
  "integration evidence must reject an internally self-consistent signed alternate ID and prove the case-sensitive sealed two-pass wrapper stays silent",
);
requireInvariant(
  releaseManifestVerifier.includes(
    'export const INDEPENDENT_REVIEW_SCHEMA = "your-wallet-independent-security-review-v2";',
  ) &&
    releaseManifestVerifier.includes(
      'export const REVIEW_EVIDENCE_SUBJECT_SCHEMA = "your-wallet-reviewed-evidence-set-subject-v1";',
    ) &&
    /export const REVIEW_EVIDENCE_EXCLUDED_KEYS = Object\.freeze\(\[\s*"reviewAttestation",\s*"reviewSignature",\s*\]\);/u.test(
      releaseManifestVerifier,
    ) &&
    releaseManifestVerifier.includes(
      ".filter(([key]) => !REVIEW_EVIDENCE_EXCLUDED_KEYS.includes(key))",
    ) &&
    releaseManifestVerifier.includes(
      "...REQUIRED_WINDOWS_NEGATIVE_TESTS.map((id) => `evidence/windows-negative/${id}.json`)",
    ) &&
    !releaseManifestVerifier.includes("your-wallet-independent-security-review-v1") &&
    !releaseManifestAssembler.includes("your-wallet-independent-security-review-v1") &&
    !releaseReviewEvidenceSet.includes("your-wallet-independent-security-review-v1"),
  "independent review v2 must exclude only its attestation/signature cycle while retaining every other evidence path and all Windows logs",
);
requireInvariant(
  computeReviewedEvidenceSetBlock.includes(
    "reviewedRecords.length !== REQUIRED_REVIEWED_EVIDENCE_PATHS.length",
  ) &&
    computeReviewedEvidenceSetBlock.includes("validateFileRecord(") &&
    computeReviewedEvidenceSetBlock.includes("record.path.toLowerCase()") &&
    computeReviewedEvidenceSetBlock.includes(
      "reviewed evidence set contains a duplicate Windows path",
    ) &&
    computeReviewedEvidenceSetBlock.includes("record.path !== expectedPath") &&
    computeReviewedEvidenceSetBlock.includes(
      "return { bytes: record.bytes, path: record.path, sha256: record.sha256 }",
    ) &&
    computeReviewedEvidenceSetBlock.includes(
      'return sha256Hex(Buffer.from(canonicalEncode(summaries), "utf8"))',
    ) &&
    computeManifestReviewedEvidenceSetBlock.includes(
      "const manifestEvidence = validateEvidence(evidence)",
    ) &&
    computeManifestReviewedEvidenceSetBlock.includes(
      ".filter(([key]) => !REVIEW_EVIDENCE_EXCLUDED_KEYS.includes(key))",
    ) &&
    computeManifestReviewedEvidenceSetBlock.includes(
      "for (const test of tests) records.push(test?.log)",
    ) &&
    computeManifestReviewedEvidenceSetBlock.includes(
      "return computeReviewedEvidenceSetSha256(records)",
    ),
  "the reviewed evidence commitment must canonicalize the exact case-sensitive path set, lengths, and hashes without trusting caller order",
);
const normalizedReviewAttestationValidator = validateIndependentReviewAttestationBlock
  .replace(/\s+/gu, " ")
  .trim();
requireInvariant(
  normalizedReviewAttestationValidator.includes(
    '"independenceAttestation", "reviewedEvidenceSetSha256", "reviewerKeyIdSha256", "scope",',
  ) &&
    normalizedReviewAttestationValidator.includes(
      "INDEPENDENT_REVIEW_SCHEMA, current,",
    ) &&
    normalizedReviewAttestationValidator.includes(
      "computeManifestReviewedEvidenceSetSha256( current.evidence, current.top.windowsNegativeTests, )",
    ) &&
    normalizedReviewAttestationValidator.includes(
      'if (review.reviewedEvidenceSetSha256 !== expectedEvidenceSetSha256) { fail("independent review evidence-set commitment mismatch"); }',
    ) &&
    normalizedReviewAttestationValidator.includes(
      "canonicalEncode(scope) !== canonicalEncode(REQUIRED_REVIEW_SCOPE)",
    ),
  "review attestation v2 must bind the exact manifest evidence commitment and canonical scope before it can be signed or accepted",
);
const reviewVerificationOrder = [
  "validateIndependentReviewAttestation(",
  "readCanonicalEvidenceJson(",
  "verifyExpectedReviewerKeyId(",
  "readVerifiedRecord(bundleRoot, evidence.reviewSignature)",
  "readVerifiedRecord(bundleRoot, evidence.reviewPublicKey)",
  "verifyEd25519Bytes(",
].map((marker) => verifyEvidenceAttestationsBlock.indexOf(marker));
const reviewAssemblyOrder = [
  "const validated = validateManifest(manifest, previous)",
  "validateIndependentReviewAttestation(review, validated)",
  "await writeFile(outputPath, canonicalEncode(manifest)",
].map((marker) => assembleReleaseManifestRunBlock.indexOf(marker));
requireInvariant(
  reviewVerificationOrder.every((position) => position !== -1) &&
    reviewVerificationOrder.every(
      (position, index, positions) => index === 0 || positions[index - 1] < position,
    ) &&
    reviewAssemblyOrder.every((position) => position !== -1) &&
    reviewAssemblyOrder.every(
      (position, index, positions) => index === 0 || positions[index - 1] < position,
    ) &&
    assembleReleaseManifestRunBlock.includes(
      'if (key === "reviewAttestation" && value.text !== canonicalEncode(value.value))',
    ) &&
    assembleReleaseManifestRunBlock.includes(
      "independent review attestation must contain the exact canonical signed bytes",
    ),
  "assembly and final verification must independently recompute review v2 binding before output or reviewer-signature acceptance",
);
requireInvariant(
  reviewEvidenceSetTreeBlock.includes(
    "REQUIRED_REVIEWED_EVIDENCE_PATHS.map((item) => [item.toLowerCase(), item])",
  ) &&
    reviewEvidenceSetTreeBlock.includes(
      "expectedFiles.get(windowsPathKey) !== relativePath",
    ) &&
    reviewEvidenceSetTreeBlock.includes(
      "expectedDirs.get(windowsPathKey) !== relativePath",
    ) &&
    reviewEvidenceSetTreeBlock.includes("status.isSymbolicLink()") &&
    reviewEvidenceSetTreeBlock.includes("status.nlink !== 1") &&
    reviewEvidenceSetTreeBlock.includes("seenFiles.size !== expectedFiles.size") &&
    reviewEvidenceSetPinnedFileBlock.includes('const handle = await open(resolved, "r")') &&
    reviewEvidenceSetPinnedFileBlock.includes('handle.stat({ bigint: true })') &&
    (reviewEvidenceSetPinnedFileBlock.match(/handle\.stat\(\{ bigint: true \}\)/gu) ?? [])
      .length === 2 &&
    reviewEvidenceSetPinnedFileBlock.includes("!hasSupportedPinnedIdentity(before)") &&
    reviewEvidenceSetPinnedFileBlock.includes(
      "!samePinnedMetadata(before, after) || bytes !== after.size",
    ) &&
    reviewEvidenceSetPinnedFileBlock.includes("await handle.close()") &&
    reviewEvidenceSetPinnedPathBlock.includes('const pathHandle = await open(resolved, "r")') &&
    reviewEvidenceSetPinnedPathBlock.includes('pathHandle.stat({ bigint: true })') &&
    reviewEvidenceSetPinnedPathBlock.includes('pinned.handle.stat({ bigint: true })') &&
    reviewEvidenceSetPinnedPathBlock.includes(
      "!hasSupportedPinnedIdentity(pathHandleStatus)",
    ) &&
    reviewEvidenceSetPinnedPathBlock.includes(
      "!samePinnedMetadata(pinned.metadata, pinnedHandleStatus)",
    ) &&
    reviewEvidenceSetPinnedPathBlock.includes(
      "!samePinnedMetadata(pinnedHandleStatus, pathHandleStatus)",
    ) &&
    reviewEvidenceSetPinnedPathBlock.includes("await pathHandle.close()") &&
    reviewEvidenceSetMetadataIdentityBlock.includes(
      "left.dev === right.dev",
    ) &&
    reviewEvidenceSetMetadataIdentityBlock.includes(
      "left.ino === right.ino",
    ) &&
    reviewEvidenceSetMetadataIdentityBlock.includes(
      "left.ctimeNs === right.ctimeNs",
    ) &&
    reviewEvidenceSetSupportedIdentityBlock.replace(/\s+/gu, " ").trim() ===
      "function hasSupportedPinnedIdentity(status) { return status.ino !== 0n && status.ino !== UINT64_MAX; }" &&
    releaseReviewEvidenceSet.includes("const UINT64_MAX = (1n << 64n) - 1n;") &&
    !releaseReviewEvidenceSet.includes("samePinnedPathIdentity") &&
    !reviewEvidenceSetSupportedIdentityBlock.includes("status.dev !== 0n") &&
    !reviewEvidenceSetSupportedIdentityBlock.includes("status.dev !== UINT64_MAX") &&
    reviewEvidenceSetPinnedPathBlock.includes(
      "!pathHandleStatus.isFile()",
    ) &&
    (collectReviewedEvidenceSetSubjectBlock.match(/await verifyExactEvidenceTree\(bundleReal\)/gu) ?? [])
      .length === 2 &&
    collectReviewedEvidenceSetSubjectBlock.includes(
      "for (const relativePath of REQUIRED_REVIEWED_EVIDENCE_PATHS)",
    ) &&
    collectReviewedEvidenceSetSubjectBlock.includes(
      "pinnedFiles.push(await openPinnedFileRecord(bundleReal, relativePath))",
    ) &&
    collectReviewedEvidenceSetSubjectBlock.includes(
      "for (const pinned of pinnedFiles) await verifyPinnedFilePath(bundleReal, pinned)",
    ) &&
    collectReviewedEvidenceSetSubjectBlock.includes(
      "await Promise.all(pinnedFiles.map((pinned) => pinned.handle.close()))",
    ) &&
    collectReviewedEvidenceSetSubjectBlock.includes(
      "pinnedFiles.map((pinned) => pinned.record)",
    ) &&
    !/\b(?:writeFile|appendFile|rename|rm|unlink|mkdir|copyFile|fetch|exec|spawn)\b/u.test(
      releaseReviewEvidenceSet,
    ) &&
    !releaseReviewEvidenceSet.includes('"--manifest"') &&
    releaseReviewEvidenceSet.includes(
      'process.stdout.write(`${canonicalEncode(subject)}\\n`)',
    ) &&
    releaseReviewEvidenceSet.includes(
      "REVIEW_EVIDENCE_SET_FAILED: ${message}",
    ),
  "the reviewer subject command must read only an exact non-reparse non-hard-linked staging set, pin each file through hashing, and never trust a candidate manifest",
);
requireInvariant(
  releaseReviewEvidenceSetWrapper.includes(
    "[Parameter(Mandatory = $true)][switch]$OperatorConfirmedNetworkIsolation",
  ) &&
    releaseReviewEvidenceSetWrapper.includes("[string]$ExpectedVerifierToolsetSha256") &&
    releaseReviewEvidenceSetWrapper.includes(
      'if ($env:OS -ne "Windows_NT")',
    ) &&
    (releaseReviewEvidenceSetWrapper.match(/Assert-NoReparseTree -LiteralPath \$bundle/gu) ?? [])
      .length === 2 &&
    (releaseReviewEvidenceSetWrapper.match(/Assert-ReleaseTreeEffectivelyReadOnly -BundleRoot \$bundle/gu) ?? [])
      .length === 2 &&
    (releaseReviewEvidenceSetWrapper.match(/Open-ReadOnlyReleaseTreeLocks -BundleRoot \$BundleRoot/gu) ?? [])
      .length === 1 &&
    releaseReviewEvidenceSetWrapper.includes(
      "$bundle = $releaseLocks.CanonicalBundleRoot",
    ) &&
    releaseReviewEvidenceSetWrapper.includes("Open-VerifiedReleaseToolset") &&
    releaseReviewEvidenceSetWrapper.includes("Assert-ReleaseTreesDisjoint") &&
    (releaseReviewEvidenceSetWrapper.match(/Invoke-ReleaseToolsetNode/gu) ?? []).length === 1 &&
    !releaseReviewEvidenceSetWrapper.includes('Get-Command "node"') &&
    !releaseReviewEvidenceSetWrapper.includes('Invoke-ReleaseCommand -Executable "node"') &&
    !releaseReviewEvidenceSetWrapper.includes(
      "Resolve-Path -LiteralPath $BundleRoot",
    ) &&
    (releaseReviewEvidenceSetWrapper.match(/\$BundleRoot\b/gu) ?? []).length === 2 &&
    releaseReviewEvidenceSetWrapper.includes("function Invoke-ReviewEvidenceSetCeremony") &&
    releaseReviewEvidenceSetWrapper.includes(
      "Invoke-ReviewEvidenceSetCeremony @boundArguments",
    ) &&
    releaseReviewEvidenceSetWrapper.includes("ConvertFrom-ExactNamedArguments") &&
    !/^\uFEFF?\[CmdletBinding\(\)\]/u.test(releaseReviewEvidenceSetWrapper) &&
    (releaseReviewEvidenceSetWrapper.match(/review-evidence-set\.mjs/gu) ?? []).length === 1 &&
    (releaseReviewEvidenceSetWrapper.match(/"--bundle-root"/gu) ?? []).length === 1 &&
    releaseReviewEvidenceSetWrapper.includes("$result.ExitCode -ne 0") &&
    releaseReviewEvidenceSetWrapper.includes(
      '[string]::Equals($result.Stderr, "", [System.StringComparison]::Ordinal)',
    ) &&
    releaseReviewEvidenceSetWrapper.includes(
      "your-wallet-reviewed-evidence-set-subject-v1",
    ) &&
    releaseReviewEvidenceSetWrapper.includes("\\n\\z'") &&
    releaseReviewEvidenceSetWrapper.includes(
      "[System.Text.RegularExpressions.RegexOptions]::CultureInvariant",
    ) &&
    !releaseReviewEvidenceSetWrapper.includes("-match") &&
    !releaseReviewEvidenceSetWrapper.includes("-notmatch") &&
    releaseReviewEvidenceSetWrapper.includes(
      "REVIEW_EVIDENCE_SET_FAILED: offline review evidence ceremony failed closed",
    ) &&
    releaseReviewEvidenceSetWrapper.includes("[Console]::Out.Write($result.Stdout)") &&
    (releaseReviewEvidenceSetWrapper.match(/Close-ReadOnlyReleaseTreeLocks -LockSet \$releaseLocks/gu) ?? [])
      .length === 1 &&
    (releaseReviewEvidenceSetWrapper.match(/Close-VerifiedReleaseToolset -Toolset \$toolset/gu) ?? [])
      .length === 1 &&
    !/\b(?:Set|Get|New|Remove)-Variable\b|\bInvoke-Expression\b|\biex\b/iu.test(
      releaseReviewEvidenceSetWrapper,
    ),
  "the Windows reviewer wrapper must hold disjoint sealed runtime and evidence trees around one exact-byte canonical subject calculation",
);
requireInvariant(
  releaseVerifierToolsetPreparation.includes("function Invoke-PrepareVerifierToolset") &&
    releaseVerifierToolsetPreparation.includes("[string]$NodeExecutable") &&
    releaseVerifierToolsetPreparation.includes("[string]$OutputDirectory") &&
    releaseVerifierToolsetPreparation.includes("[switch]$OperatorConfirmedPreparationOnly") &&
    releaseVerifierToolsetPreparation.includes("Open-PinnedReleaseFilePath") &&
    releaseVerifierToolsetPreparation.includes('"node.exe" = $nodePath') &&
    releaseVerifierToolsetPreparation.includes(
      '"extension/native-host/validate-manifest.mjs"',
    ) &&
    releaseVerifierToolsetPreparation.includes(
      '"scripts/release/review-evidence-set.ps1"',
    ) &&
    releaseVerifierToolsetPreparation.includes(
      '"scripts/release/verify-release-offline.ps1"',
    ) &&
    releaseVerifierToolsetPreparation.includes("Get-InventorySha256") &&
    releaseVerifierToolsetPreparation.includes(
      "VERIFIER_TOOLSET_PREPARED_NOT_RELEASE_ELIGIBLE",
    ) &&
    releaseVerifierToolsetPreparation.includes(
      "deletion would be unsafe if an untrusted writer added an unexpected",
    ) &&
    !releaseVerifierToolsetPreparation.includes(
      "PRIVATE_MAINNET_CANARY_RELEASE_ELIGIBLE_AFTER_OFFLINE_VERIFICATION",
    ),
  "verifier-toolset preparation must stage only the pinned runtime graph, print its aggregate as non-eligibility output, and fail without destructive cleanup",
);
requireInvariant(
  releaseVerifierToolsetTests.includes(
    "Test toolset fixture was not the exact seven-file/four-directory shape",
  ) &&
    releaseVerifierToolsetTests.includes("extra-file") &&
    releaseVerifierToolsetTests.includes("empty-extra-directory") &&
    releaseVerifierToolsetTests.includes('Name = "case-alias"') &&
    releaseVerifierToolsetTests.includes("hard-link") &&
    releaseVerifierToolsetTests.includes('Label "alternate data stream"') &&
    releaseVerifierToolsetTests.includes('Label "writable tree"') &&
    releaseVerifierToolsetTests.includes('-Label "directory-writable tree"') &&
    releaseVerifierToolsetTests.includes("Protect-TestTree -Root $directoryWritableRoot -DenyFilesOnly") &&
    /Name = "case-alias";[\s\S]*?Pin = "exact"/u.test(releaseVerifierToolsetTests) &&
    releaseVerifierToolsetTests.includes("function node") &&
    releaseVerifierToolsetTests.includes(
      "Ambient Get-FileHash shadow must not be called by the verifier",
    ) &&
    releaseVerifierToolsetTests.includes("NODE_OPTIONS") &&
    releaseVerifierToolsetTests.includes("invalid-utf8") &&
    releaseVerifierToolsetTests.includes("oversize") &&
    releaseVerifierToolsetTests.includes("Bounded verifier subprocess timeout") &&
    releaseVerifierToolsetTests.includes(
      "Exact-image runner accepted an executable path that did not match its expected handle",
    ) &&
    releaseVerifierToolsetTests.includes(
      "Exact-image mismatch cleanup prevented a subsequent matched execution",
    ) &&
    releaseVerifierToolsetTests.includes("public static class RawProcess") &&
    releaseVerifierToolsetTests.includes("strictUtf8.GetString(stdout.Bytes.ToArray())") &&
    releaseVerifierToolsetTests.includes(
      "Held verifier toolset root unexpectedly allowed a concurrent rename",
    ) &&
    releaseVerifierToolsetTests.includes(
      "Disjoint-root guard accepted equal verifier and evidence roots",
    ) &&
    releaseVerifierToolsetTests.includes("$realResultFirst = Invoke-ReleaseToolsetNode") &&
    releaseVerifierToolsetTests.includes("$realResultSecond = Invoke-ReleaseToolsetNode") &&
    releaseVerifierToolsetTests.includes(
      "Sealed real-Node review/release/validate graph was not exact and deterministic",
    ) &&
    releaseVerifierToolsetTests.includes(
      "Sealed real-Node release entry did not reach its exact direct-file guard",
    ) &&
    releaseVerifierToolsetTests.includes(
      "Sealed VM context exposed ambient globals, process capabilities, or string code generation",
    ) &&
    releaseVerifierToolsetTests.includes('Name = "source-bom"') &&
    releaseVerifierToolsetTests.includes('Name = "source-invalid-utf8"') &&
    releaseVerifierToolsetTests.includes('Name = "unapproved-static-import"') &&
    releaseVerifierToolsetTests.includes('Name = "unapproved-dynamic-import"') &&
    releaseVerifierToolsetTests.includes(
      "function Assert-ReleaseSequenceBinderRejectsTerminalLineFeed",
    ) &&
    releaseVerifierToolsetTests.includes(
      '$_.FullyQualifiedErrorId -like "ParameterArgumentValidationError,*"',
    ) &&
    (releaseVerifierToolsetTests.match(/Assert-ReleaseSequenceBinderRejectsTerminalLineFeed/gu) ?? [])
      .length === 2 &&
    releaseVerifierToolsetTests.includes(
      "Sealed VM loader accepted a forbidden source or import graph",
    ) &&
    releaseVerifierToolsetTests.includes("POWERSHELL_VERIFIER_TOOLSET_PASS"),
  "the release gate must behaviorally reject verifier-toolset inventory, identity, ambient-runtime, output, timeout, and root-overlap attacks",
);
requireInvariant(
  releaseVerifierToolsetTests.includes("$preparationResult = Invoke-TestRawProcess") &&
    releaseVerifierToolsetTests.includes("VERIFIER_TOOLSET_SHA256=${preparedToolsetHash}`n") &&
    releaseVerifierToolsetTests.includes("VERIFIER_TOOLSET_PREPARED_NOT_RELEASE_ELIGIBLE`n") &&
    releaseVerifierToolsetTests.includes("$preparedFiles.Count -ne 7") &&
    releaseVerifierToolsetTests.includes("$preparedDirectories.Count -ne 4") &&
    releaseVerifierToolsetTests.includes(
      "Preparation-only output was accepted without effective write protection",
    ) &&
    releaseVerifierToolsetTests.includes("$existingPreparationResult = Invoke-TestRawProcess") &&
    releaseVerifierToolsetTests.includes("$invalidPreparationResult = Invoke-TestRawProcess") &&
    releaseVerifierToolsetTests.includes(
      "Verifier toolset preparation argument failure disclosed a path or changed its fixed line",
    ),
  "the release gate must execute preparation as a non-eligible exact-shape subprocess and reject existing outputs or private malformed arguments with fixed bytes",
);
requireInvariant(
  reviewEvidenceDigestUnitTestBlock.includes("reordered.windowsNegativeTests.reverse()") &&
    reviewEvidenceDigestUnitTestBlock.includes("duplicate[1] = duplicate[0]") &&
    reviewEvidenceDigestUnitTestBlock.includes("[...reviewedRecords, reviewedRecords[0]]") &&
    reviewEvidenceDigestUnitTestBlock.includes("replacement-review-attestation") &&
    reviewEvidenceDigestUnitTestBlock.includes("replacement-review-signature") &&
    reviewEvidenceDigestUnitTestBlock.includes("replacement-review-public-key") &&
    reviewEvidenceDigestUnitTestBlock.includes("assert.notEqual(") &&
    reviewEvidenceDigestUnitTestBlock.includes("missing.windowsNegativeTests.pop()") &&
    reviewEvidenceDigestUnitTestBlock.includes(".toUpperCase()") &&
    reviewAttestationV2UnitTestBlock.includes(
      'schema: "your-wallet-independent-security-review-v2"',
    ) &&
    reviewAttestationV2UnitTestBlock.includes("stale-reviewed-evidence-set") &&
    reviewAttestationV2UnitTestBlock.includes(
      'versionOne.schema = "your-wallet-independent-security-review-v1"',
    ),
  "unit evidence must cover canonical order, the exact non-circular exclusion, public-key inclusion, path fail-closure, stale binding, and v1 refusal",
);
requireInvariant(
  reviewNativeReplacementTestBlock.includes(
    "await replaceNativeHostDescriptionAndBindings(fixture)",
  ) &&
    reviewNativeReplacementTestBlock.includes("await expectReviewEvidenceMismatch(fixture)") &&
    reviewWindowsReplacementTestBlock.includes(
      "await replaceWindowsNegativeLog(fixture)",
    ) &&
    reviewWindowsReplacementTestBlock.includes("await expectReviewEvidenceMismatch(fixture)") &&
    reviewAdvisoryReplacementTestBlock.includes(
      "await replaceOsvEvidenceAndPolicy(fixture)",
    ) &&
    reviewAdvisoryReplacementTestBlock.includes("await expectReviewEvidenceMismatch(fixture)") &&
    reviewAdvisoryReplacementTestBlock.includes("await reissueIndependentReview(fixture)") &&
    reviewAdvisoryReplacementTestBlock.includes(
      'assert.equal(stdout, "CRYPTOGRAPHIC_BUNDLE_VERIFICATION_PASS_REQUIRES_WINDOWS_WRAPPER\\n")',
    ) &&
    reviewV1RejectionTestBlock.includes(
      'versionOne.schema = "your-wallet-independent-security-review-v1"',
    ) &&
    reviewV1RejectionTestBlock.includes("delete versionOne.reviewedEvidenceSetSha256") &&
    reviewV1RejectionTestBlock.includes("fixture.reviewerPrivateKey") &&
    reviewAssemblyIntegrationTestBlock.includes(
      "const first = await createAssembleCliInvocation(fixture)",
    ) &&
    reviewAssemblyIntegrationTestBlock.includes(
      'assert.equal(await readFile(first.outputPath, "utf8"), canonicalEncode(fixture.manifest))',
    ) &&
    reviewAssemblyIntegrationTestBlock.includes(
      "await replaceNativeHostDescriptionAndBindings(fixture)",
    ) &&
    reviewAssemblyIntegrationTestBlock.includes(
      '"MANIFEST_ASSEMBLY_FAILED: independent review evidence-set commitment mismatch\\n"',
    ) &&
    reviewAssemblyIntegrationTestBlock.includes(
      'assert.rejects(() => stat(second.outputPath), { code: "ENOENT" })',
    ),
  "integration evidence must reject release-key-only evidence substitutions and old review signatures while accepting a newly reviewed exact set",
);
requireInvariant(
  reviewRefreshedCommitmentOldSignatureTestBlock.includes(
    "const oldReviewSignature = await readFile(",
  ) &&
    reviewRefreshedCommitmentOldSignatureTestBlock.includes(
      "await replaceNativeHostDescriptionAndBindings(fixture)",
    ) &&
    reviewRefreshedCommitmentOldSignatureTestBlock.includes(
      "reviewedEvidenceSetSha256: computeReviewedEvidenceSetSha256(reviewedEvidenceRecords)",
    ) &&
    reviewRefreshedCommitmentOldSignatureTestBlock.includes(
      "fixture.manifest.evidence.reviewAttestation = await fileRecord(",
    ) &&
    reviewRefreshedCommitmentOldSignatureTestBlock.includes(
      "assert.deepEqual(",
    ) &&
    reviewRefreshedCommitmentOldSignatureTestBlock.includes(
      "await createVerifyCliInvocation(fixture)",
    ) &&
    reviewRefreshedCommitmentOldSignatureTestBlock.includes(
      "RELEASE_INELIGIBLE: independent review attestation signature is invalid",
    ) &&
    reviewExternalRolePinsTestBlock.includes('"--expected-release-key-id"') &&
    reviewExternalRolePinsTestBlock.includes(
      '"--expected-signer-certificate-sha256"',
    ) &&
    reviewExternalRolePinsTestBlock.includes('"--expected-reviewer-key-id"') &&
    reviewExternalRolePinsTestBlock.includes(
      "fixture.reviewerPrivateKey = fixture.releasePrivateKey",
    ) &&
    reviewExternalRolePinsTestBlock.includes(
      "fixture.reviewerKeyIdSha256 = fixture.manifest.signing.keyIdSha256",
    ) &&
    reviewExternalRolePinsTestBlock.includes(
      "independent reviewer key must differ from the release-manifest key",
    ),
  "behavioral evidence must reach old-review-signature verification and keep all external trust pins plus self-review separation wired at the CLI boundary",
);
requireInvariant(
  reviewSubjectSuccessTestBlock.includes("const before = await metadataSnapshot(stage.root)") &&
    reviewSubjectSuccessTestBlock.includes("assert.deepEqual(after, before)") &&
    reviewSubjectSuccessTestBlock.includes("computeReviewedEvidenceSetSha256(stage.records)") &&
    reviewSubjectSuccessTestBlock.includes("assert.equal(cli.stderr, \"\")") &&
    reviewSubjectFileSetTestBlock.includes("await unlink(") &&
    reviewSubjectFileSetTestBlock.includes('"evidence", "unreviewed.txt"') &&
    reviewSubjectFileSetTestBlock.includes("path.basename(canonicalCargoLockPath).toLowerCase()") &&
    reviewSubjectFileSetTestBlock.includes(
      "for (const root of [missing.root, extra.root, caseAlias.root])",
    ) &&
    reviewSubjectFileSetTestBlock.includes(
      '"REVIEW_EVIDENCE_SET_FAILED: staged evidence set is not exact\\n"',
    ) &&
    reviewSubjectHardlinkTestBlock.includes("await link(source, target)") &&
    reviewSubjectHardlinkTestBlock.includes("/hard-linked file/u") &&
    reviewSubjectArityTestBlock.includes('["--bundle-root", ".", "--output", "ignored"]') &&
    reviewSubjectWrapperTestBlock.includes(
      "Open-ReadOnlyReleaseTreeLocks -BundleRoot $BundleRoot",
    ) &&
    reviewSubjectWrapperTestBlock.includes(
      "$bundle = $releaseLocks.CanonicalBundleRoot",
    ) &&
    reviewSubjectWrapperTestBlock.includes(
      "Close-ReadOnlyReleaseTreeLocks -LockSet $releaseLocks",
    ) &&
    reviewSubjectWrapperTestBlock.includes("Open-VerifiedReleaseToolset") &&
    reviewSubjectWrapperTestBlock.includes("Invoke-ReleaseToolsetNode") &&
    reviewSubjectWrapperTestBlock.includes("Assert-ReleaseTreesDisjoint") &&
    reviewSubjectWrapperTestBlock.includes("ExpectedVerifierToolsetSha256") &&
    reviewSubjectWrapperTestBlock.includes("[Console]::Out.Write($result.Stdout)") &&
    reviewSubjectWrapperTestBlock.includes(
      "Assert-ReleaseTreeEffectivelyReadOnly -BundleRoot \\$bundle",
    ) &&
    reviewSubjectWrapperPrivacyTestBlock.includes(
      '"-UnknownPrivateParameter", privateParent',
    ) &&
    reviewSubjectWrapperPrivacyTestBlock.includes('["-BundleRoot"]') &&
    reviewSubjectWrapperPrivacyTestBlock.includes(
      "REVIEW_EVIDENCE_SET_FAILED: offline review evidence ceremony failed closed",
    ) &&
    reviewSubjectWrapperPrivacyTestBlock.includes(
      "!stderr.includes(privateParent)",
    ) &&
    reviewSubjectWrapperPrivacyTestBlock.includes(
      '"-ExpectedVerifierToolsetSha256"',
    ) &&
    extensionPinWrapperIntegrationTestBlock.includes(
      '["unknown raw argument", ["-UnknownPrivateParameter", probeRoot]]',
    ) &&
    extensionPinWrapperIntegrationTestBlock.includes(
      "RELEASE_VERIFICATION_FAILED: offline release verification failed closed",
    ) &&
    extensionPinWrapperIntegrationTestBlock.includes(
      "const privateValues = [",
    ) &&
    extensionPinWrapperIntegrationTestBlock.includes(
      "for (const privateValue of privateValues)",
    ) &&
    extensionPinWrapperIntegrationTestBlock.includes(
      "assert.ok(!stderr.includes(privateValue)",
    ) &&
    extensionPinWrapperIntegrationTestBlock.includes(
      '"-ExpectedVerifierToolsetSha256", "4".repeat(64)',
    ) &&
    extensionPinWrapperIntegrationTestBlock.includes("const sequenceValidation =") &&
    extensionPinWrapperIntegrationTestBlock.includes(
      'wrapper.match(/"--expected-release-sequence", \\$ExpectedReleaseSequence/gu)?.length',
    ) &&
    extensionPinWrapperIntegrationTestBlock.includes(
      'wrapper.match(/^\\s*"ExpectedReleaseSequence",?\\s*$/gmu)?.length',
    ) &&
    extensionPinWrapperIntegrationTestBlock.includes(
      "wrapper.match(/-CommandArguments \\$verifyArguments/gu)?.length",
    ) &&
    extensionPinWrapperIntegrationTestBlock.includes(
      "sequenceShapeGate !== -1 && sequenceShapeGate < toolsetOpen",
    ) &&
    extensionPinWrapperIntegrationTestBlock.includes(
      '["missing release sequence", [...argumentPrefix, ...argumentSuffix]]',
    ) &&
    extensionPinWrapperIntegrationTestBlock.includes(
      '"initial release with previous checkpoint"',
    ) &&
    extensionPinWrapperIntegrationTestBlock.includes(
      '"successor release without previous checkpoint pair"',
    ),
  "review subject and offline wrapper evidence must prove deterministic success plus sealed-toolset, file-set, arity, preflight, and parameter-binding fail-closure without path disclosure",
);
requireInvariant(
  releaseSecurity.includes("independently sourced `ExpectedExtensionId`") &&
    releaseSecurity.includes("A mismatch is rejected before bundle/evidence reads") &&
    releaseSecurity.includes("Every successor manifest must retain") &&
    releaseSecurity.includes(
      "-ExpectedExtensionId <independently pinned 32-lowercase-a-through-p>",
    ) &&
    releaseSecurity.includes(
      "-ExpectedVerifierToolsetSha256 <independently checkpointed 64-lower-hex>",
    ) &&
    releaseSecurity.includes("exactly four directories and these seven files") &&
    releaseSecurity.includes("VERIFIER_TOOLSET_PREPARED_NOT_RELEASE_ELIGIBLE") &&
    releaseSecurity.includes("consistency and version pin") &&
    releaseSecurity.includes("cannot make an untrusted `common.ps1`") &&
    releaseSecurity.includes("The toolset and candidate trees must be disjoint") &&
    releaseSecurity.includes("first pre-user-mode `CREATE_PROCESS_DEBUG_EVENT`") &&
    releaseSecurity.includes("in-memory `vm.SourceTextModule` graph") &&
    releaseSecurity.includes("ambient `NODE_OPTIONS`") &&
    releaseSecurity.includes("CRLF, a BOM, trailing bytes") &&
    releaseSecurity.includes("same held executable/module identities") &&
    releaseSecurity.includes("stable extension ID") &&
    releaseSecurity.includes("no stable production extension ID") &&
    releaseSecurity.includes("your-wallet-independent-security-review-v2") &&
    releaseSecurity.includes("reviewedEvidenceSetSha256") &&
    releaseSecurity.includes("Do not copy a digest out of the candidate manifest") &&
    releaseSecurity.includes("review-evidence-set.ps1") &&
    releaseSecurity.includes("The review entry runs exactly once") &&
    releaseSecurity.includes("no write/delete sharing") &&
    releaseSecurity.includes("handle-derived local volume-GUID path") &&
    releaseSecurity.includes("The original path alias is then discarded") &&
    releaseSecurity.includes("full canonical ancestor chain") &&
    releaseSecurity.includes("one fixed wrapper error line without path disclosure") &&
    releaseSecurity.includes("ancestor junction is retargeted from tree A") &&
    releaseSecurity.includes("rename probe proves the canonical root is still locked") &&
    releaseSecurity.includes("merely re-signing the release manifest is insufficient") &&
    sepoliaArchitectureDoc.includes("The independent-review attestation is schema v2") &&
    sepoliaArchitectureDoc.includes("excluding only the review attestation and its") &&
    sepoliaArchitectureDoc.includes("v1 or stale attestations fail closed") &&
    sepoliaArchitectureDoc.includes("handle-derived local volume-GUID path") &&
    sepoliaArchitectureDoc.includes("complete 128-bit") &&
    sepoliaArchitectureDoc.includes("separately controlled verifier toolset") &&
    sepoliaArchitectureDoc.includes("first `CREATE_PROCESS_DEBUG_EVENT`") &&
    sepoliaArchitectureDoc.includes("in-memory `vm.SourceTextModule` graph") &&
    sepoliaArchitectureDoc.includes("DOS script/module path race") &&
    sepoliaArchitectureDoc.includes("fixed category lines") &&
    sepoliaArchitectureDoc.includes("without path disclosure") &&
    sepoliaArchitectureDoc.includes("retargets") &&
    sepoliaArchitectureDoc.includes("still denies rename") &&
    sepoliaArchitectureDoc.includes("exact subject bytes to remain A plus one LF") &&
    releaseSecurity.includes("`ExpectedReleaseSequence` is a mandatory external assertion") &&
    releaseSecurity.includes("`[1-9][0-9]{0,31}`") &&
    releaseSecurity.includes("an older, correctly signed sequence-1 bundle cannot be replayed") &&
    sepoliaArchitectureDoc.includes(
      "rollback-resistant checkpoint-derived\n`ExpectedReleaseSequence`",
    ) &&
    releaseSecurity.includes(
      "must come only from the write-protected, rollback-resistant offline checkpoint",
    ) &&
    releaseSecurity.includes("never from the candidate bundle, a copied command") &&
    sepoliaArchitectureDoc.includes("exact initial/successor argument counts before any candidate file or tree") &&
    sepoliaArchitectureDoc.includes("correctly signed old sequence-1 tree") &&
    rootReadme.includes("릴리스 정책·검증기 테스트 60개 통과") &&
    rootReadme.includes("rollback-resistant offline checkpoint에서") &&
    rootReadme.includes("유효하게 서명된 과거 sequence-1") &&
    rootReadme.includes("봉인된 Windows 검증 도구셋") &&
    rootReadme.includes("첫 디버그 생성 이벤트의 실제 이미지"),
  "release documentation must distinguish external identity/toolset pins and mapped-image/module-graph guarantees from still-absent production evidence",
);
const releasePolicyTestCount = [
  releaseExtensionAuditTests,
  releaseInventoryTests,
  releaseManifestTests,
  releaseVerifierIntegrationTests,
  releaseReviewEvidenceSetTests,
].reduce(
  (count, source) => count + (source.match(/(?:^|\n)test\s*\(/gu) ?? []).length,
  0,
);
requireInvariant(
  hasExactSourcePins(
    releasePolicyTests,
    approvedReleasePolicyTestSha256,
  ) &&
    !hasExactSourcePins(
      releasePolicyTests.map((source, index) =>
        index === 0 ? { ...source, sha256: "0".repeat(64) } : source,
      ),
      approvedReleasePolicyTestSha256,
    ) &&
    JSON.stringify(releaseTestSuiteNames) === JSON.stringify([
      "audit-extension.test.mjs",
      "generate-inventories.test.mjs",
      "release-manifest.test.mjs",
      "release-verifier-integration.test.mjs",
      "review-evidence-set.test.mjs",
    ]) &&
    releasePolicyTestCount === 60,
  "the five executed Node suites must match their exact reviewed raw-byte SHA-256 pins and documented 60-test total",
);

process.stdout.write("architecture scan passed\n");
