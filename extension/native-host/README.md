# Native messaging host registration

Summary of spec/05 §9. There is no Web Store package and no prebuilt binary (D1). The source installer
(`install.cmd` at the repository root, which runs `scripts/install.ps1`, spec/01 §9.2 and
docs/install.ko.md) builds `yw-app.exe`/`yw-host.exe` on this PC, copies them and the extension runtime
files to `%LOCALAPPDATA%\Programs\YourWallet`, and registers the host. Use the same script during
development (run it again after rebuilding the executables).

## Register (`install.cmd` / `scripts/install.ps1`)

Windows PowerShell 5.1 or PowerShell 7, current user only (HKCU), no admin rights, no Node.js needed.

```
install.cmd [-InstallDir <dir>] [-NoShortcut] [-NoNativeHost] [-NoBuild] [-DryRun]
```

1. The ID computed from the `key` in `extension/manifest.json` must equal the pinned ID
   (`extension/extension-id.txt`, `nnpjlobjgbanccjddghlpaafpohfkeph`).
2. `-InstallDir` (default `%LOCALAPPDATA%\Programs\YourWallet`) is made absolute and rejected if it contains
   `"` `%` `&` `^` `|` `<` `>` `!` or control characters (Chrome may launch the host through cmd.exe).
3. `cargo build --release --locked -p yw-app -p yw-host` (skipped with `-NoBuild`); both executables are
   copied to the install folder. If a file is in use, the script asks to close yw-app and Chrome (it never
   kills them).
4. `<InstallDir>\com.your_wallet.native.json` is written as UTF-8 without BOM:
   name `com.your_wallet.native`, description `Your Wallet native messaging host`,
   path `<InstallDir>\yw-host.exe`, type `stdio`, `allowed_origins` = `["chrome-extension://<id>/"]`.
5. The manifest is validated by a PowerShell port of `validate-manifest.mjs` (same rules; the two are
   compared by `scripts/install.test.mjs`).
6. The default value of `HKCU:\Software\Google\Chrome\NativeMessagingHosts\com.your_wallet.native`
   is set to the manifest path and read back (skipped with `-NoNativeHost`).

yw-app normally runs as `<InstallDir>\yw-app.exe` (yw-host starts the yw-app next to itself).

## Unregister (`uninstall.cmd` / `scripts/uninstall.ps1`)

```
uninstall.cmd [-InstallDir <dir>] [-NoShortcut] [-NoNativeHost] [-RemoveWalletData] [-DryRun]
```

Removes the registry key (only if it points at this install's manifest), the manifest, the Start menu
shortcut and the program files listed in `yw-install.json`. The vault and settings
(`%LOCALAPPDATA%\YourWallet\v3\`) are kept unless `-RemoveWalletData` and the typed confirmation phrase are given.

## Validator (`validate-manifest.mjs`)

`node validate-manifest.mjs <file> [--expect-id <id>]` reads the file as UTF-8 (a BOM is an error),
prints `OK <id>` and exits 0, or prints `INVALID` and exits 1. It requires exactly the five keys above,
one `chrome-extension://<32 a-p>/` origin, an absolute Windows path whose last component is
`yw-host.exe`, and no `%` `&` `^` `!` in the path. `validateNativeManifest(value)` is the same check
as a function. `com.your_wallet.native.json.template` keeps placeholders and is a test fixture only:
it is never valid.

## Loading the extension

1. `chrome://extensions` → Developer mode → "Load unpacked" → select `<InstallDir>\extension` (the
   installer puts this path on the clipboard). While editing extension sources you may load the
   repository `extension\` folder instead: the pinned `key` gives the same ID.
2. The displayed ID must equal `extension/extension-id.txt`.
3. Run `install.cmd` (before or after step 1). After reinstalling or editing extension sources, press the
   extension card's reload button and reload open tabs: MV3 does not reinject content scripts, and old
   content scripts become DEAD.
4. Chrome may warn about developer-mode extensions at startup.
