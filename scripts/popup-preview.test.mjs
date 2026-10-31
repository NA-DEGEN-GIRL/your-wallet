// The screenshot tour's popup preview (scripts/popup-preview.html, DEV ONLY) must show the real
// popup: its <body> is extension/popup/popup.html's, with only the module path rewritten. A stale
// copy rendered a popup without the Solana/Bitcoin cards (popup.js then stopped at a missing id).
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const body = (html) => {
  const start = html.indexOf("<body>");
  const end = html.indexOf("</body>");
  assert.ok(start >= 0 && end > start);
  return html.slice(start, end).replace(/\r\n/gu, "\n");
};

test("popup preview body equals the extension popup body", async () => {
  const popup = await readFile(new URL("../extension/popup/popup.html", import.meta.url), "utf8");
  const preview = await readFile(new URL("./popup-preview.html", import.meta.url), "utf8");
  assert.equal(
    body(preview),
    body(popup).replace('src="../src/popup.js"', 'src="../extension/src/popup.js"')
  );
});
