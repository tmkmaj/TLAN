param(
    [string]$Version = ''
)

$ErrorActionPreference = 'Stop'

$versionTag = if ($Version) { if ($Version.StartsWith('v')) { $Version } else { "v$Version" } } else { '' }
$versionSuffix = if ($versionTag) { "-$versionTag" } else { '' }

$root = $PSScriptRoot
$outputDir = Join-Path $root 'dist\linux'
$binPath = Join-Path $outputDir 'tlan-server'
$zipPath = Join-Path $root "dist\TLAN-server$versionSuffix-linux-amd64.zip"
$frpsAssetsDir = Join-Path $root 'assets\frp\linux-amd64'
$frpsBinPath = Join-Path $frpsAssetsDir 'frps'
$expectedFrpsSHA256 = '2FB8DA8392CF2B332BFCC540F075E928A82D1A106DF0B8FCFCF13497149F8C48'
$frpsPkgDir = Join-Path $root '.tmp-build\frps-pkg'
$frpsTarPath = Join-Path $root "dist\TLAN-frps$versionSuffix-linux-amd64.tar.gz"

if (-not (Test-Path $frpsBinPath)) {
    throw "Missing linux/amd64 frps binary: $frpsBinPath"
}
$actualFrpsSHA256 = (Get-FileHash -Algorithm SHA256 $frpsBinPath).Hash.ToUpperInvariant()
if ($actualFrpsSHA256 -ne $expectedFrpsSHA256) {
    throw "frps SHA256 mismatch: got $actualFrpsSHA256, want $expectedFrpsSHA256"
}

$global:LASTEXITCODE = 0
& (Join-Path $root 'scripts\verify-frps-templates.ps1')
if ($LASTEXITCODE -ne 0) {
    throw 'frps template verification failed'
}

New-Item -ItemType Directory -Force -Path $outputDir | Out-Null

Push-Location $root
try {
    $env:GOOS = 'linux'
    $env:GOARCH = 'amd64'
    $env:CGO_ENABLED = '0'
    go build -mod=vendor -ldflags '-s -w' -o $binPath ./cmd/server
    if ($LASTEXITCODE -ne 0) {
        throw 'go build ./cmd/server failed'
    }
}
finally {
    Remove-Item Env:GOOS -ErrorAction SilentlyContinue
    Remove-Item Env:GOARCH -ErrorAction SilentlyContinue
    Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue
    Pop-Location
}

$stagingDir = Join-Path $root '.tmp-build\server-zip-staging'
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $stagingDir
New-Item -ItemType Directory -Force -Path (Join-Path $stagingDir 'systemd') | Out-Null
Copy-Item -Force $binPath (Join-Path $stagingDir 'tlan-server')
Copy-Item -Force (Join-Path $root 'install.sh') (Join-Path $stagingDir 'install.sh')
Copy-Item -Force (Join-Path $root 'deploy\Caddyfile') (Join-Path $stagingDir 'Caddyfile')
Copy-Item -Force (Join-Path $root 'deploy\systemd\tlan.service') (Join-Path $stagingDir 'systemd\tlan.service')
Copy-Item -Force (Join-Path $root 'deploy\systemd\tlan-https.service') (Join-Path $stagingDir 'systemd\tlan-https.service')
Copy-Item -Force (Join-Path $root 'deploy\systemd\tlan-graceful-restart.sh') (Join-Path $stagingDir 'systemd\tlan-graceful-restart.sh')
if (Test-Path (Join-Path $root 'docs\INSTALL-LINUX.md')) {
    Copy-Item -Force (Join-Path $root 'docs\INSTALL-LINUX.md') (Join-Path $stagingDir 'INSTALL-LINUX.md')
}

Remove-Item -Force -ErrorAction SilentlyContinue $zipPath
Compress-Archive -Path (Join-Path $stagingDir '*') -DestinationPath $zipPath

Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $frpsPkgDir
$frpsOptDir = Join-Path $frpsPkgDir 'opt\tlan-frp'
New-Item -ItemType Directory -Force -Path $frpsOptDir | Out-Null
Copy-Item -Force $frpsBinPath (Join-Path $frpsOptDir 'frps')
Copy-Item -Force (Join-Path $root 'deploy\frps\frps.toml.example') (Join-Path $frpsOptDir 'frps.toml.example')
Copy-Item -Force (Join-Path $root 'deploy\frps\frps-wss.toml.example') (Join-Path $frpsOptDir 'frps-wss.toml.example')
Copy-Item -Force (Join-Path $root 'deploy\frps\install-frps.sh') (Join-Path $frpsOptDir 'install-frps.sh')
Copy-Item -Force (Join-Path $root 'deploy\frps\tlan-frps.service') (Join-Path $frpsOptDir 'tlan-frps.service')
Copy-Item -Force (Join-Path $root 'deploy\frps\tlan-frps-wss.service') (Join-Path $frpsOptDir 'tlan-frps-wss.service')
Copy-Item -Force (Join-Path $root 'deploy\frps\README.md') (Join-Path $frpsOptDir 'README.md')

Remove-Item -Force -ErrorAction SilentlyContinue $frpsTarPath
tar -czf $frpsTarPath -C $frpsPkgDir opt

Write-Host "Built Linux server: $binPath"
Write-Host "Packaged server ZIP: $zipPath"
Write-Host "Packaged FRPS tarball: $frpsTarPath"
