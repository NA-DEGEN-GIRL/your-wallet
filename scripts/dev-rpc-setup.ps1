# 개발용 RPC 설정 도우미 (spec.md D13, spec/01 §4.6)
# - QuickNode 엔드포인트 이름과 API 키만 입력하면 네트워크별 URL을 만들고 실제로 호출해 확인한 뒤
#   %USERPROFILE%\.yw-dev\rpc.json 에 저장한다.
# - URL·토큰은 화면에 표시하지 않는다(입력은 별표로 가려진다).
# - 지갑 앱(yw-app)은 이 파일을 읽지 않는다. 개발 프로브·E2E 전용이다.
# 실행: powershell -NoProfile -ExecutionPolicy Bypass -File scripts\dev-rpc-setup.ps1

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2

$dir  = Join-Path $env:USERPROFILE '.yw-dev'
$file = Join-Path $dir 'rpc.json'

# 네트워크 표: QuickNode 서브도메인/경로와 기대값(체인 ID 또는 제네시스 해시)
$nets = @(
    @{ id = 'eip155:1';        name = 'Ethereum mainnet';  sub = '';                 path = '';    kind = 'evm'; expect = '0x1' },
    @{ id = 'eip155:11155111'; name = 'Ethereum Sepolia';  sub = 'ethereum-sepolia'; path = '';    kind = 'evm'; expect = '0xaa36a7' },
    @{ id = 'eip155:999';      name = 'HyperEVM mainnet';  sub = 'hype-mainnet';     path = 'nanoreth'; kind = 'evm'; expect = '0x3e7' },
    @{ id = 'eip155:42161';    name = 'Arbitrum One';      sub = 'arbitrum-mainnet'; path = '';    kind = 'evm'; expect = '0xa4b1' },
    @{ id = 'eip155:8453';     name = 'Base mainnet';      sub = 'base-mainnet';     path = '';    kind = 'evm'; expect = '0x2105' },
    @{ id = 'eip155:56';       name = 'BNB Smart Chain';   sub = 'bsc';              path = '';    kind = 'evm'; expect = '0x38' },
    @{ id = 'eip155:4663';     name = 'Robinhood Chain';   sub = 'robinhood-mainnet'; path = '';   kind = 'evm'; expect = '0x1237' },
    @{ id = 'solana:mainnet';  name = 'Solana mainnet';    sub = 'solana-mainnet';   path = '';    kind = 'sol'; expect = '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d' },
    @{ id = 'solana:devnet';   name = 'Solana devnet';     sub = 'solana-devnet';    path = '';    kind = 'sol'; expect = 'EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG' },
    @{ id = 'bitcoin:mainnet'; name = 'Bitcoin mainnet';   sub = 'btc';              path = '';    kind = 'btc'; expect = '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f' },
    @{ id = 'bitcoin:testnet4';name = 'Bitcoin testnet4';  sub = 'btc-testnet4';     path = '';    kind = 'btc'; expect = '00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043' },
    # Zcash (spec/12 §2): QuickNode 문서 예시 서브도메인 zec-mainnet; testnet zec-testnet은 첫 사용 때 확인. 제네시스로 확인(getblockhash 0).
    @{ id = 'zcash:mainnet';   name = 'Zcash mainnet';     sub = 'zec-mainnet';      path = '';    kind = 'btc'; expect = '00040fe8ec8471911baa1db1266ea15dd06b4a8a5c453883c000b031973dce08' },
    @{ id = 'zcash:testnet';   name = 'Zcash testnet';     sub = 'zec-testnet';      path = '';    kind = 'btc'; expect = '05a60a92d99d85997cce3b87616c089f6124d7342af37106edc76126334a2c38' }
)

function Read-Secret([string]$prompt) {
    $s = Read-Host -Prompt $prompt -AsSecureString
    $p = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($s)
    try { return ([Runtime.InteropServices.Marshal]::PtrToStringBSTR($p)).Trim() }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($p) }
}

function Test-Endpoint([string]$url, $net) {
    switch ($net.kind) {
        'evm' { $body = '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' }
        'sol' { $body = '{"jsonrpc":"2.0","id":1,"method":"getGenesisHash"}' }
        'btc' { $body = '{"jsonrpc":"2.0","id":1,"method":"getblockhash","params":[0]}' }
    }
    try {
        $r = Invoke-RestMethod -Uri $url -Method Post -ContentType 'application/json' -Body $body -TimeoutSec 20
    } catch {
        $code = $null
        try { $code = [int]$_.Exception.Response.StatusCode } catch { }
        if ($code) { return "실패(HTTP $code)" } else { return '실패(연결 오류)' }
    }
    if ($null -eq $r -or -not ($r.PSObject.Properties.Name -contains 'result')) { return '실패(결과 없음)' }
    if ([string]$r.result -eq $net.expect) { return 'OK' }
    return '실패(다른 네트워크 응답)'
}

# 기존 설정 불러오기(있으면 유지·덮어쓰기)
$cfg = [ordered]@{}
if (Test-Path -LiteralPath $file) {
    $old = Get-Content -LiteralPath $file -Raw -Encoding UTF8 | ConvertFrom-Json
    foreach ($p in $old.PSObject.Properties) { $cfg[$p.Name] = [string]$p.Value }
}

Write-Host ''
Write-Host 'QuickNode 멀티체인 엔드포인트 정보를 입력하세요. URL 형식: https://<이름>.<체인>.quiknode.pro/<API 키>/'
Write-Host '  1) 엔드포인트 이름: URL 맨 앞의 <이름> 부분 (예: wild-fragrant-sea)'
Write-Host '  2) API 키: quiknode.pro/ 뒤의 토큰 (입력 내용은 화면에 표시되지 않습니다)'
$epName = (Read-Host -Prompt '엔드포인트 이름').Trim()
if ($epName -match '^https://([a-z0-9-]+)(\.[a-z0-9-]+)?\.quiknode\.pro/([A-Za-z0-9_-]{8,})(/.*)?$') {
    # 전체 URL을 붙여넣은 경우: 이름과 키를 함께 뽑는다
    $epName = $Matches[1]; $token = $Matches[3]
} else {
    if ($epName -notmatch '^[a-z0-9][a-z0-9-]{0,62}$') { throw '엔드포인트 이름 형식이 아닙니다 (소문자·숫자·하이픈).' }
    $token = Read-Secret 'API 키'
    if ($token -notmatch '^[A-Za-z0-9_-]{8,128}$') { throw 'API 키 형식이 아닙니다.' }
}

$results = @()
foreach ($n in $nets) {
    if ($n.sub -eq '') { $url = "https://$epName.quiknode.pro/$token/" }
    else { $url = "https://$epName.$($n.sub).quiknode.pro/$token/" }
    if ($n.path -ne '') { $url = $url + $n.path }

    Write-Host -NoNewline ("{0,-18} 확인 중... " -f $n.name)
    $st = Test-Endpoint $url $n
    if ($st -ne 'OK') {
        Write-Host $st
        Write-Host '  이 네트워크 URL을 직접 붙여넣으려면 입력하세요 (Enter = 건너뛰기).'
        $manual = Read-Secret ('  ' + $n.id + ' URL')
        if ($manual -ne '') {
            if ($manual -notmatch '^https://') { $st = '건너뜀(https 아님)' }
            else {
                Write-Host -NoNewline '  다시 확인 중... '
                $st = Test-Endpoint $manual $n
                if ($st -eq 'OK') { $url = $manual }
            }
        } else { $st = '건너뜀' }
        $manual = $null
    }
    Write-Host $st
    if ($st -eq 'OK') { $cfg[$n.id] = $url }
    $results += [pscustomobject]@{ 네트워크 = $n.id; 이름 = $n.name; 결과 = $st }
    $url = $null
}
$token = $null

if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
$json = ($cfg | ConvertTo-Json -Depth 2)
[IO.File]::WriteAllText($file, $json, (New-Object Text.UTF8Encoding $false))
$json = $null; $cfg = $null

Write-Host ''
$results | Format-Table -AutoSize
Write-Host ("저장 위치: {0}" -f $file)
Write-Host '실패한 네트워크는 QuickNode 대시보드에서 해당 체인을 엔드포인트에 추가(Multichain)한 뒤 다시 실행하면 됩니다.'
