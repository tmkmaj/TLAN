param(
    [string]$ServerURL = '',
    [string]$STUNAddress = '',
    [string]$Version = ''
)

$ErrorActionPreference = 'Stop'

$versionTag = if ($Version) { if ($Version.StartsWith('v')) { $Version } else { "v$Version" } } else { '' }
$versionSuffix = if ($versionTag) { "-$versionTag" } else { '' }

$root = $PSScriptRoot
$outputDir = Join-Path $root 'dist\windows'
$exePath = Join-Path $outputDir 'TLAN.exe'
$zipPath = Join-Path $root "dist\TLAN-client$versionSuffix-windows-amd64.zip"
$clientDir = Join-Path $root 'cmd\client'
$iconPath = Join-Path $root 'assets\branding\tlan-icon.png'
$manifestPath = Join-Path $clientDir 'TLAN.exe.manifest'
$winresJsonPath = Join-Path $clientDir 'winres.json'
$sysoPath = Join-Path $clientDir 'tlan_windows_amd64.syso'
$wintunPath = Join-Path $root 'assets\windows\amd64\wintun.dll'
$wintunLicensePath = Join-Path $root 'assets\windows\WINTUN-LICENSE.txt'
$frpcPath = Join-Path $root 'assets\frp\windows-amd64\frpc.exe'
$frpLicensePath = Join-Path $root 'assets\frp\licenses\FRP-LICENSE.txt'
$expectedWintunSHA256 = 'E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE'
$expectedFrpcSHA256 = '509F4FA082BF9B85F9AD27B45D37A89A8ACCB011F3B724CFF352DFAC90A94FEB'

foreach ($required in @($iconPath, $manifestPath, $winresJsonPath, $wintunPath, $frpcPath)) {
    if (-not (Test-Path $required)) {
        throw "Required build asset is missing: $required"
    }
}

$actualWintunSHA256 = (Get-FileHash -Algorithm SHA256 $wintunPath).Hash.ToUpperInvariant()
if ($actualWintunSHA256 -ne $expectedWintunSHA256) {
    throw "wintun.dll SHA256 mismatch: got $actualWintunSHA256, want $expectedWintunSHA256"
}
$actualFrpcSHA256 = (Get-FileHash -Algorithm SHA256 $frpcPath).Hash.ToUpperInvariant()
if ($actualFrpcSHA256 -ne $expectedFrpcSHA256) {
    throw "frpc.exe SHA256 mismatch: got $actualFrpcSHA256, want $expectedFrpcSHA256"
}

$winresExe = Get-Command 'go-winres' -ErrorAction SilentlyContinue
if (-not $winresExe) {
    $fallbackWinres = Join-Path (go env GOPATH) 'bin\go-winres.exe'
    if (Test-Path $fallbackWinres) {
        $winresExe = Get-Command $fallbackWinres
    }
}
if (-not $winresExe) {
    throw 'go-winres is required to embed the TLAN icon, manifest, and version metadata. Install with: go install github.com/tc-hib/go-winres@latest'
}

New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
Remove-Item -Force -ErrorAction SilentlyContinue $sysoPath

Push-Location $clientDir
try {
    & $winresExe.Source make --in winres.json --out tlan --arch amd64
    if ($LASTEXITCODE -ne 0) {
        throw 'go-winres failed to generate Windows resources'
    }
}
finally {
    Pop-Location
}

$ldflags = '-H windowsgui -s -w'
if ($ServerURL) {
    $ldflags += " -X 'main.bundledServerURL=$ServerURL'"
}
if ($STUNAddress) {
    $ldflags += " -X 'main.bundledSTUNAddress=$STUNAddress'"
}

Push-Location $root
try {
    $env:GOOS = 'windows'
    $env:GOARCH = 'amd64'
    $env:CGO_ENABLED = '0'
    go build -mod=vendor -ldflags $ldflags -o $exePath ./cmd/client
    if ($LASTEXITCODE -ne 0) {
        throw 'go build ./cmd/client failed'
    }
}
finally {
    Remove-Item Env:GOOS -ErrorAction SilentlyContinue
    Remove-Item Env:GOARCH -ErrorAction SilentlyContinue
    Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue
    Pop-Location
    # The generated resource object carries the requireAdministrator manifest,
    # and Go links it into every binary of this package, test binaries included.
    # Removing it keeps "go test ./cmd/client" runnable without elevation after
    # a client build; the next build regenerates it from scratch anyway.
    Remove-Item -Force -ErrorAction SilentlyContinue $sysoPath
}

Copy-Item -Force $wintunPath (Join-Path $outputDir 'wintun.dll')
Copy-Item -Force $frpcPath (Join-Path $outputDir 'frpc.exe')
Copy-Item -Force $iconPath (Join-Path $outputDir 'tlan-icon.png')
if (Test-Path $wintunLicensePath) { Copy-Item -Force $wintunLicensePath (Join-Path $outputDir 'WINTUN-LICENSE.txt') }
if (Test-Path $frpLicensePath) { Copy-Item -Force $frpLicensePath (Join-Path $outputDir 'FRP-LICENSE.txt') }

Remove-Item -Force -ErrorAction SilentlyContinue $zipPath
Compress-Archive -Path (Join-Path $outputDir '*') -DestinationPath $zipPath

Write-Host "Built Windows client: $exePath"
Write-Host "Packaged ZIP: $zipPath"
