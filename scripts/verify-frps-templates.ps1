param(
    [string]$ConfigDir = '',
    [string]$FrpsBinary = ''
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($ConfigDir)) {
    $ConfigDir = Join-Path $root 'deploy/frps'
} elseif (-not [IO.Path]::IsPathRooted($ConfigDir)) {
    $ConfigDir = Join-Path $root $ConfigDir
}
$mainPath = Join-Path $ConfigDir 'frps.toml.example'
$wssPath = Join-Path $ConfigDir 'frps-wss.toml.example'
foreach ($path in @($mainPath, $wssPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing FRPS template: $path" }
}

function Get-TomlScalar {
    param(
        [Parameter(Mandatory=$true)][string]$Text,
        [Parameter(Mandatory=$true)][string]$Key,
        [Parameter(Mandatory=$true)][string]$File
    )
    $pattern = '(?m)^[ \t]*' + [regex]::Escape($Key) + '[ \t]*=[ \t]*(?:"([^"]*)"|([^ \t#]+))[ \t]*(?:#.*)?\r?$'
    $matches = [regex]::Matches($Text, $pattern)
    if ($matches.Count -ne 1) {
        throw "Expected exactly one '$Key' assignment in $File; found $($matches.Count)."
    }
    $match = $matches[0]
    if ($match.Groups[1].Success) { return $match.Groups[1].Value }
    return $match.Groups[2].Value
}

function Assert-Value {
    param(
        [Parameter(Mandatory=$true)][string]$Text,
        [Parameter(Mandatory=$true)][string]$Key,
        [Parameter(Mandatory=$true)][string]$Expected,
        [Parameter(Mandatory=$true)][string]$File
    )
    $actual = Get-TomlScalar -Text $Text -Key $Key -File $File
    if ($actual -ne $Expected) {
        throw "FRPS template mismatch: $File has $Key='$actual', expected '$Expected'."
    }
}

$mainText = [IO.File]::ReadAllText($mainPath)
$wssText = [IO.File]::ReadAllText($wssPath)
$expected = @(
    @{ Text = $mainText; File = $mainPath; Key = 'bindAddr'; Value = '0.0.0.0' },
    @{ Text = $mainText; File = $mainPath; Key = 'bindPort'; Value = '7000' },
    @{ Text = $mainText; File = $mainPath; Key = 'kcpBindPort'; Value = '7002' },
    @{ Text = $mainText; File = $mainPath; Key = 'quicBindPort'; Value = '7003' },
    @{ Text = $mainText; File = $mainPath; Key = 'proxyBindAddr'; Value = '0.0.0.0' },
    @{ Text = $mainText; File = $mainPath; Key = 'vhostHTTPPort'; Value = '18080' },
    @{ Text = $mainText; File = $mainPath; Key = 'vhostHTTPSPort'; Value = '18443' },
    @{ Text = $mainText; File = $mainPath; Key = 'tcpmuxHTTPConnectPort'; Value = '18081' },
    @{ Text = $mainText; File = $mainPath; Key = 'subDomainHost'; Value = 'frp.8-163-21-82.nip.io' },
    @{ Text = $mainText; File = $mainPath; Key = 'transport.tls.force'; Value = 'true' },
    @{ Text = $wssText; File = $wssPath; Key = 'bindAddr'; Value = '127.0.0.1' },
    @{ Text = $wssText; File = $wssPath; Key = 'bindPort'; Value = '7001' },
    @{ Text = $wssText; File = $wssPath; Key = 'proxyBindAddr'; Value = '0.0.0.0' },
    @{ Text = $wssText; File = $wssPath; Key = 'vhostHTTPPort'; Value = '18082' },
    @{ Text = $wssText; File = $wssPath; Key = 'vhostHTTPSPort'; Value = '18444' },
    @{ Text = $wssText; File = $wssPath; Key = 'tcpmuxHTTPConnectPort'; Value = '18083' },
    @{ Text = $wssText; File = $wssPath; Key = 'subDomainHost'; Value = 'frp.8-163-21-82.nip.io' },
    @{ Text = $wssText; File = $wssPath; Key = 'transport.tls.force'; Value = 'false' }
)
foreach ($item in $expected) {
    Assert-Value -Text $item.Text -Key $item.Key -Expected $item.Value -File $item.File
}

$listeners = @(
    [pscustomobject]@{ Name = 'main bindPort'; Protocol = 'tcp'; Port = 7000 },
    [pscustomobject]@{ Name = 'main kcpBindPort'; Protocol = 'udp'; Port = 7002 },
    [pscustomobject]@{ Name = 'main quicBindPort'; Protocol = 'udp'; Port = 7003 },
    [pscustomobject]@{ Name = 'main vhostHTTPPort'; Protocol = 'tcp'; Port = 18080 },
    [pscustomobject]@{ Name = 'main vhostHTTPSPort'; Protocol = 'tcp'; Port = 18443 },
    [pscustomobject]@{ Name = 'main tcpmuxHTTPConnectPort'; Protocol = 'tcp'; Port = 18081 },
    [pscustomobject]@{ Name = 'wss bindPort'; Protocol = 'tcp'; Port = 7001 },
    [pscustomobject]@{ Name = 'wss vhostHTTPPort'; Protocol = 'tcp'; Port = 18082 },
    [pscustomobject]@{ Name = 'wss vhostHTTPSPort'; Protocol = 'tcp'; Port = 18444 },
    [pscustomobject]@{ Name = 'wss tcpmuxHTTPConnectPort'; Protocol = 'tcp'; Port = 18083 }
)
foreach ($listener in $listeners) {
    if ($listener.Port -lt 1 -or $listener.Port -gt 65535) {
        throw "Invalid listener port for $($listener.Name): $($listener.Port)"
    }
}
$conflicts = $listeners | Group-Object { "$($_.Protocol)/$($_.Port)" } | Where-Object Count -gt 1
if ($conflicts) {
    $details = ($conflicts | ForEach-Object { "$($_.Name): " + (($_.Group | ForEach-Object Name) -join ', ') }) -join '; '
    throw "FRPS listener conflict: $details"
}
$installerPath = Join-Path $ConfigDir 'install-frps.sh'
if (-not (Test-Path -LiteralPath $installerPath -PathType Leaf)) { throw "Missing FRPS installer: $installerPath" }
$installerText = [IO.File]::ReadAllText($installerPath)
foreach ($firewallPort in @('7000/tcp','18080/tcp','18081/tcp','18082/tcp','18083/tcp','18443/tcp','18444/tcp','7002/udp','7003/udp','30000-30999/tcp','30000-30999/udp')) {
    if (-not $installerText.Contains($firewallPort)) { throw "FRPS installer firewall list is missing $firewallPort" }
}
if ($installerText -match '7001/tcp') { throw 'FRPS installer must not expose loopback listener 7001/tcp.' }
$buildScriptPath = Join-Path $root 'build-debian-server.ps1'
if (-not (Test-Path -LiteralPath $buildScriptPath -PathType Leaf)) { throw "Missing build script: $buildScriptPath" }
$buildScriptText = [IO.File]::ReadAllText($buildScriptPath)
if (-not $buildScriptText.Contains('docs\FRPS-DEPLOY.md')) { throw 'FRPS package build must include docs\FRPS-DEPLOY.md.' }
Write-Host 'PASS static FRPS template values, listener conflict checks, firewall list and package copy scope.'

$onWindows = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
$candidates = [System.Collections.Generic.List[string]]::new()
if (-not [string]::IsNullOrWhiteSpace($FrpsBinary)) {
    $candidates.Add($FrpsBinary)
} elseif ($onWindows) {
    $candidates.Add((Join-Path $root '.tmp-runtime/frps-v0.71.1.exe'))
} else {
    $candidates.Add((Join-Path $root '.tmp-runtime/frps-v0.71.1-linux'))
    $candidates.Add((Join-Path $root 'assets/frp/linux-amd64/frps'))
}
$binary = $null
foreach ($candidate in $candidates) {
    if (Test-Path -LiteralPath $candidate -PathType Leaf) { $binary = (Resolve-Path -LiteralPath $candidate).Path; break }
}
if (-not $binary) {
    Write-Warning 'No runnable pinned frps binary found; static validation passed but real frps verify was skipped.'
    return
}
$version = (& $binary --version 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $version -notmatch '(^|\s)0\.71\.1(\s|$)') {
    throw "Unable to run frps 0.71.1 from $binary (output: $version)"
}
foreach ($path in @($mainPath, $wssPath)) {
    $output = (& $binary verify -c $path 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw "frps verify failed for $path`n$output"
    }
    Write-Host "PASS frps verify $path"
}
Write-Host "PASS real frps verify using $binary"