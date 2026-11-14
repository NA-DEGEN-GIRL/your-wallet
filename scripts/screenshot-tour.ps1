# scripts/screenshot-tour.ps1 — DEV ONLY: 화면 투어 스크린샷을 만든다(docs/screenshots/).
# 사용: powershell -NoProfile -ExecutionPolicy Bypass -File scripts/screenshot-tour.ps1 [-Lang ko|en] [-OutDir <폴더>] [-SkipApp] [-SkipPopup]
# -Lang en(2026-11-14, spec/14): 앱 장면을 영어로(YW_TOUR_LANG=en), 팝업도 영어로 찍고 기본 출력은 docs/screenshots/en.
#
# 1. yw-app의 #[ignore] 테스트 ui::tour(디버그 테스트 빌드에만 있음)를 실행한다. 버리는 임시 데이터 폴더와
#    공개 BIP39 시험 니모닉·가짜 잔액만 쓰고 %LOCALAPPDATA%\YourWallet은 건드리지 않는다. 창이 잠깐 화면에 뜬다.
# 2. BMP를 PNG로 바꾼다(System.Drawing, 개발 단계 전용).
# 3. 확장 팝업(extension/popup/popup.html)을 chrome.* 대역(scripts/popup-preview.html)과 함께
#    헤드리스 Edge/Chrome으로 찍는다(브라우저가 없으면 건너뛴다).
[CmdletBinding()]
param(
    [ValidateSet("ko", "en")]
    [string]$Lang = "ko",
    [string]$OutDir = "",
    [switch]$SkipApp,
    [switch]$SkipPopup
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$Root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
if ($OutDir -eq "") {
    $OutDir = Join-Path $Root "docs\screenshots"
    if ($Lang -eq "en") { $OutDir = Join-Path $OutDir "en" }
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$Raw = Join-Path $Root "target\screenshot-tour"
New-Item -ItemType Directory -Force -Path $Raw | Out-Null
Add-Type -AssemblyName System.Drawing

function Convert-Bmp([string]$Bmp, [string]$Png) {
    $image = [System.Drawing.Image]::FromFile($Bmp)
    try { $image.Save($Png, [System.Drawing.Imaging.ImageFormat]::Png) } finally { $image.Dispose() }
}

if (-not $SkipApp) {
    Get-ChildItem -LiteralPath $Raw -Filter "*.bmp" -File | Remove-Item -Force
    $env:YW_TOUR_DIR = $Raw
    $env:YW_TOUR_LANG = $Lang
    Push-Location $Root
    try {
        & cargo test -p yw-app --lib --locked ui::tour::screenshot_tour -- --ignored --exact --nocapture
        if ($LASTEXITCODE -ne 0) { throw "tour failed (exit $LASTEXITCODE)" }
    } finally {
        Pop-Location
        Remove-Item Env:\YW_TOUR_DIR -ErrorAction SilentlyContinue
        Remove-Item Env:\YW_TOUR_LANG -ErrorAction SilentlyContinue
    }
    foreach ($bmp in Get-ChildItem -LiteralPath $Raw -Filter "*.bmp" -File | Sort-Object Name) {
        $png = Join-Path $OutDir ($bmp.BaseName + ".png")
        Convert-Bmp $bmp.FullName $png
        Write-Host "tour: $png"
    }
}

if (-not $SkipPopup) {
    $browsers = @(
        "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
        "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
        "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
        "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }
    $browser = $browsers | Select-Object -First 1
    if (-not $browser) {
        Write-Host "tour: popup skipped (no Edge/Chrome found)"
    } else {
        # Module scripts need http: a throwaway static server on 127.0.0.1 that serves only
        # scripts/popup-preview.html and the extension's popup/src files.
        $port = 18000 + (Get-Random -Maximum 2000)
        $server = Join-Path $Raw "popup-preview-server.mjs"
        @"
import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import path from "node:path";
const root = process.argv[2];
const types = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8" };
createServer(async (request, response) => {
  const name = (request.url ?? "/").split("?")[0];
  const allowed = name === "/scripts/popup-preview.html" || /^\/extension\/(popup|src)\/[A-Za-z0-9_-]+\.(css|js|html)$/u.test(name);
  if (!allowed) { response.writeHead(404).end(); return; }
  try {
    const body = await readFile(path.join(root, name));
    response.writeHead(200, { "Content-Type": types[path.extname(name)], "Cache-Control": "no-store" }).end(body);
  } catch { response.writeHead(404).end(); }
}).listen(Number(process.argv[3]), "127.0.0.1");
"@ | Set-Content -LiteralPath $server -Encoding utf8
        $node = Start-Process -FilePath "node" -ArgumentList @("`"$server`"", "`"$Root`"", "$port") -PassThru -WindowStyle Hidden
        try {
            Start-Sleep -Milliseconds 700
            $profile = Join-Path $Raw "browser-profile"
            $png = Join-Path $OutDir "19-extension-popup.png"
            $arguments = @(
                "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
                "--disable-extensions", "--hide-scrollbars", "--force-device-scale-factor=1",
                "--user-data-dir=`"$profile`"", "--virtual-time-budget=3000",
                "--window-size=360,860", "--screenshot=`"$png`"",
                "http://127.0.0.1:$port/scripts/popup-preview.html?lang=$Lang"
            )
            $process = Start-Process -FilePath $browser -ArgumentList $arguments -PassThru -Wait -WindowStyle Hidden
            if (Test-Path -LiteralPath $png) { Write-Host "tour: $png" } else { Write-Host "tour: popup capture failed (exit $($process.ExitCode))" }
            Remove-Item -Recurse -Force -LiteralPath $profile -ErrorAction SilentlyContinue
        } finally {
            Stop-Process -Id $node.Id -Force -ErrorAction SilentlyContinue
        }
    }
}
