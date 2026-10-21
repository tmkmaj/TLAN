param(
    [switch]$AuditRegression
)
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot | Split-Path -Parent
Push-Location $root
$previous = @{}
foreach ($key in @('GOOS','GOARCH','CGO_ENABLED','GOCACHE')) {
    $previous[$key] = [Environment]::GetEnvironmentVariable($key,'Process')
}

function Invoke-Go {
    param(
        [Parameter(Mandatory=$true)][string]$Label,
        [Parameter(Mandatory=$true)][string[]]$Arguments
    )
    & $script:goPath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed with exit code $LASTEXITCODE"
    }
}

try {
    $script:goPath = (Get-Command go -ErrorAction SilentlyContinue).Source
    if (-not $script:goPath) { throw 'Go is required but was not found in PATH' }
    $goVersionText = (& $script:goPath env GOVERSION).Trim()
    if ($goVersionText -notmatch '^go(\d+\.\d+(?:\.\d+)?)$') {
        throw "Unable to parse Go version: $goVersionText"
    }
    $goVersion = [version]$Matches[1]
    if ($goVersion -lt [version]'1.23.1') {
        throw "Go 1.23.1 or newer is required; found $goVersionText"
    }

    $expected = @{
        'assets\frp\windows-amd64\frpc.exe' = '509F4FA082BF9B85F9AD27B45D37A89A8ACCB011F3B724CFF352DFAC90A94FEB'
        'assets\frp\linux-amd64\frps' = '2FB8DA8392CF2B332BFCC540F075E928A82D1A106DF0B8FCFCF13497149F8C48'
        'assets\windows\amd64\wintun.dll' = 'E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE'
    }
    foreach ($relative in $expected.Keys) {
        if (-not (Test-Path -LiteralPath $relative)) { throw "Missing pinned asset: $relative" }
        $actual = (Get-FileHash -LiteralPath $relative -Algorithm SHA256).Hash
        if ($actual -ne $expected[$relative]) { throw "SHA-256 mismatch for ${relative}: $actual" }
        Write-Host "PASS hash $relative"
    }

    $env:GOCACHE = Join-Path $root '.tmp-build\go-cache'
    $env:GOOS = 'windows'
    $env:GOARCH = 'amd64'
    $env:CGO_ENABLED = '0'
    Invoke-Go -Label 'Windows tests' -Arguments @('test','-mod=vendor','./...','-count=1','-timeout','180s')
    Invoke-Go -Label 'Windows vet' -Arguments @('vet','-mod=vendor','./...')

    if ($AuditRegression) {
        Invoke-Go -Label 'FRP audit regression probes' -Arguments @('test','-mod=vendor','-tags','frp_audit_regression','./internal/frp','-run','TestAuditRegression','-count=1','-v','-timeout','120s')
    }

    $linuxOut = Join-Path $root '.tmp-build\baseline-verify\linux-tests'
    New-Item -ItemType Directory -Force -Path $linuxOut | Out-Null
    $env:GOOS = 'linux'
    $env:GOARCH = 'amd64'
    $env:CGO_ENABLED = '0'
    Invoke-Go -Label 'Linux vet' -Arguments @('vet','-mod=vendor','./...')
    $packages = @(& $script:goPath list -mod=vendor ./...)
    if ($LASTEXITCODE -ne 0) { throw 'Linux package listing failed' }
    foreach ($package in $packages) {
        $safeName = $package -replace '[^A-Za-z0-9._-]', '_'
        Invoke-Go -Label "Linux test compile $package" -Arguments @('test','-mod=vendor','-c','-o',(Join-Path $linuxOut "$safeName.test"),$package)
    }
    Invoke-Go -Label 'Linux server build' -Arguments @('build','-mod=vendor','-trimpath','-o',(Join-Path $root '.tmp-build\baseline-verify\tmknetworklan-server'),'./cmd/server')
    Invoke-Go -Label 'Linux install-helper build' -Arguments @('build','-mod=vendor','-trimpath','-o',(Join-Path $root '.tmp-build\baseline-verify\tmknetworklan-install-helper'),'./cmd/install-helper')

    $tracked = @()
    if (Get-Command git -ErrorAction SilentlyContinue) {
        $tracked = @(& git -C $root ls-files)
        if ($LASTEXITCODE -ne 0) { throw 'git ls-files failed' }
    }
    if ($tracked.Count -eq 0) {
        Write-Warning 'Git has no tracked project files; this verification does not establish a commit baseline or a clean reviewable diff.'
    } else {
        Write-Host "PASS Git tracks $($tracked.Count) files"
    }

    Write-Host "PASS baseline verification with $goVersionText"
} finally {
    foreach ($key in $previous.Keys) {
        [Environment]::SetEnvironmentVariable($key,$previous[$key],'Process')
    }
    Pop-Location
}