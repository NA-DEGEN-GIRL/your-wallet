[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

try {
    . (Join-Path $PSScriptRoot 'common.ps1')
    Import-ServiceProbeNative
    $checks = [YourWallet.ServiceProbe.Harness]::SelfTest()
    if ($checks -ne 30) { throw 'blocked' }
    Write-Output 'SERVICE_PROBE_NATIVE_TEST_PASS_30_NO_SCM_OR_POLICY_CALLS'
    exit 0
}
catch {
    Write-Output 'SERVICE_PROBE_NATIVE_TEST_FAILED'
    exit 1
}
