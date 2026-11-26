<#
.SYNOPSIS
Stages and verifies the bundled FRP core binaries.

.DESCRIPTION
Copies frpc/frps from a local directory into the TLAN distribution layout and
verifies each binary against the SHA-256 recorded in deploy/frp-core/pins.json.
The script is fail-closed: a missing pin, a missing binary or a digest mismatch
aborts without writing anything. It never downloads anything, so the build stays
offline and reproducible.

.PARAMETER Platform
Target platform folder, for example windows-amd64 or linux-amd64.

.PARAMETER SourceDir
Directory containing the raw frpc/frps files to stage.

.PARAMETER OutDir
Staging directory. Defaults to dist/frp-core.

.PARAMETER PinsPath
Path to the pin file. Defaults to deploy/frp-core/pins.json.

.PARAMETER VerifyOnly
Only verify the source binaries; do not copy or write a manifest.

.EXAMPLE
./build-frp-core.ps1 -Platform linux-amd64 -SourceDir ./.tmp-runtime/frp-dist
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('windows-amd64', 'linux-amd64')]
    [string]$Platform,

    [string]$SourceDir = '',
    [string]$OutDir = '',
    [string]$PinsPath = '',
    [switch]$VerifyOnly
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
if (-not $PinsPath) { $PinsPath = Join-Path $root 'deploy/frp-core/pins.json' }
if (-not $OutDir) { $OutDir = Join-Path $root 'dist/frp-core' }

function Get-Sha256([string]$Path) {
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

if (-not (Test-Path -LiteralPath $PinsPath)) {
    throw "Pin file not found: $PinsPath"
}
$pins = Get-Content -Raw -Encoding UTF8 $PinsPath | ConvertFrom-Json
$version = $pins.version
if (-not $version) { throw "Pin file $PinsPath does not declare a version." }
if (-not $pins.artifacts.PSObject.Properties.Name -contains $Platform) {
    throw "Pin file $PinsPath has no artifact set for platform '$Platform'."
}
$expected = $pins.artifacts.$Platform

if (-not $VerifyOnly) {
    if (-not $SourceDir) { throw 'SourceDir is required unless -VerifyOnly is used.' }
    if (-not (Test-Path -LiteralPath $SourceDir)) { throw "SourceDir not found: $SourceDir" }
}

$targets = @($expected.PSObject.Properties | ForEach-Object { $_.Name })
if ($targets.Count -eq 0) { throw "No artifacts listed for platform '$Platform'." }

$verified = @()
foreach ($name in $targets) {
    $want = [string]$expected.$name
    if (-not $want) {
        throw "No SHA-256 pin recorded for $Platform/$name. Run the official release download, compute the digest and fill deploy/frp-core/pins.json before building."
    }
    $path = if ($VerifyOnly) { Join-Path $SourceDir $name } else { Join-Path $SourceDir $name }
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Binary not found: $path"
    }
    $got = Get-Sha256 $path
    if ($got -ne $want) {
        throw "Digest mismatch for $name.`n  expected: $want`n  actual:   $got`nRefusing to package a FRP core that does not match the recorded pin."
    }
    Write-Host "verified  $name  sha256=$got"
    $verified += [pscustomobject]@{ Name = $name; SourcePath = $path; Sha256 = $got }
}

if ($VerifyOnly) { return }

foreach ($entry in $verified) {
    $destinationDir = Join-Path $OutDir "runtime/frp/$version/$Platform"
    New-Item -ItemType Directory -Force -Path $destinationDir | Out-Null
    Copy-Item -LiteralPath $entry.SourcePath -Destination (Join-Path $destinationDir $entry.Name) -Force
}
$manifest = [ordered]@{
    version  = $version
    platform = $Platform
    sha256   = ($verified | Where-Object { $_.Name -like 'frpc*' } | Select-Object -First 1).Sha256
    source   = 'https://github.com/fatedier/frp/releases/tag/v' + $version
    license  = 'Apache-2.0'
    artifacts = ($verified | ForEach-Object { [ordered]@{ name = $_.Name; sha256 = $_.Sha256 } })
}
$manifestPath = Join-Path $OutDir "runtime/frp/$version/$Platform/manifest.json"
$manifest | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 -Path $manifestPath
Write-Host "staged    $($verified.Count) artifact(s) into $OutDir"
Write-Host "manifest  $manifestPath"

