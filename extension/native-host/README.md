# Native messaging host registration

Summary of spec/05 §9 (source builds). There is no Web Store package (D1). The release zip has its
own per-user installer, `install.ps1` (spec/01 §9.3, docs/install.ko.md), which installs to
`%LOCALAPPDATA%\Programs\YourWallet` and registers the same HKCU key; the scripts below are for
running a build from this repository (default `-BinDir` `%LOCALAPPDATA%\YourWallet\bin`).

## Register (`scripts/register-native-host.ps1`)

Windows PowerShell 5.1 or PowerShell 7, current user only (HKCU), no admin rights.

```
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\register-native-host.ps1 [-BinDir <dir>] [-BuildProfile release|debug]
```

1. `node scripts/extension-key.mjs check` must pass; the ID is read from `extension/extension-id.txt`.
2. `-BinDir` (default `%LOCALAPPDATA%\YourWallet\bin`) is made absolute and rejected if it contains
   `"` `%` `&` `^` `|` `<` `>` `!` or control characters (Chrome may launch the host through cmd.exe).
3. `target\<profile>\yw-host.exe` and `yw-app.exe` must exist (otherwise build with
   `cargo build -p yw-host -p yw-app [--release]`); both are copied to `-BinDir`.
   If the copy fails because a file is in use, close yw-app and Chrome and run again.
4. `<BinDir>\com.your_wallet.native.json` is written as UTF-8 without BOM:
   name `com.your_wallet.native`, description `Your Wallet native messaging host`,
   path `<BinDir>\yw-host.exe`, type `stdio`, `allowed_origins` = `["chrome-extension://<id>/"]`.
5. `node extension/native-host/validate-manifest.mjs <manifest> --expect-id <id>` must print `OK <id>`.
6. The default value of `HKCU:\Software\Google\Chrome\NativeMessagingHosts\com.your_wallet.native`
   is set to the manifest path and read back.

yw-app normally runs as `<BinDir>\yw-app.exe` (yw-host starts the yw-app next to itself).

## Unregister (`scripts/unregister-native-host.ps1`)

```
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\unregister-native-host.ps1 [-BinDir <dir>] [-RemoveBinaries]
```

Removes the registry key and `<BinDir>\com.your_wallet.native.json`; with `-RemoveBinaries` also the
two executables. The vault and settings (`%LOCALAPPDATA%\YourWallet\v3\`) are never touched.

## Validator (`validate-manifest.mjs`)

`node validate-manifest.mjs <file> [--expect-id <id>]` reads the file as UTF-8 (a BOM is an error),
prints `OK <id>` and exits 0, or prints `INVALID` and exits 1. It requires exactly the five keys above,
one `chrome-extension://<32 a-p>/` origin, an absolute Windows path whose last component is
`yw-host.exe`, and no `%` `&` `^` `!` in the path. `validateNativeManifest(value)` is the same check
as a function. `com.your_wallet.native.json.template` keeps placeholders and is a test fixture only:
it is never valid.

## Loading the extension

1. `chrome://extensions` → Developer mode → "Load unpacked" → select the repository `extension\` folder.
2. The displayed ID must equal `extension/extension-id.txt`.
3. Run `register-native-host.ps1` (before or after step 1). After editing extension sources, press the
   extension card's reload button and reload open tabs: MV3 does not reinject content scripts, and old
   content scripts become DEAD.
4. Chrome may warn about developer-mode extensions at startup.
