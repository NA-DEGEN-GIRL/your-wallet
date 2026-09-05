Set-StrictMode -Version Latest

function Import-ServiceProbeNative {
    $stream = $null
    $reader = $null
    try {
        if ($null -ne ('YourWallet.ServiceProbe.Harness' -as [type])) { return }
        $source = Join-Path $PSScriptRoot 'ServiceProbeNative.cs'
        if (([IO.File]::GetAttributes($source) -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'blocked'
        }
        $stream = [IO.FileStream]::new($source, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        if ($stream.Length -le 0 -or $stream.Length -gt 262144) { throw 'blocked' }
        $reader = [IO.StreamReader]::new($stream, [Text.UTF8Encoding]::new($false, $true), $false)
        $code = $reader.ReadToEnd()
        Add-Type -TypeDefinition $code -Language CSharp -ErrorAction Stop
    }
    catch { throw 'SERVICE_PROBE_NATIVE_IMPORT_FAILED' }
    finally {
        if ($null -ne $reader) { $reader.Dispose() }
        elseif ($null -ne $stream) { $stream.Dispose() }
    }
}
