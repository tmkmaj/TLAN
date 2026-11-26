param(
    [switch]$IncludeWindowsTest,
    [string]$OutDir = '.tmp-build\baseline'
)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $repoRoot
try {
    $outputDir = Join-Path $repoRoot $OutDir
    if (-not (Test-Path $outputDir)) {
        New-Item -ItemType Directory -Path $outputDir | Out-Null
    }

    Write-Host '==> Verifying frps templates and ports'
    $global:LASTEXITCODE = 0
    & (Join-Path $PSScriptRoot 'verify-frps-templates.ps1')
    if ($LASTEXITCODE -ne 0) {
        throw "verify-frps-templates failed with exit code $LASTEXITCODE"
    }

    Write-Host '==> Building tlan-server (linux/amd64)'
    $env:GOOS = 'linux'
    $env:GOARCH = 'amd64'
    $env:CGO_ENABLED = '0'
    go build -mod=vendor -ldflags '-s -w' -o (Join-Path $outputDir 'tlan-server') ./cmd/server
    if ($LASTEXITCODE -ne 0) {
        throw "linux/amd64 server build failed with exit code $LASTEXITCODE"
    }

    Write-Host '==> Building tlan-install-helper (linux/amd64)'
    go build -mod=vendor -ldflags '-s -w' -o (Join-Path $outputDir 'tlan-install-helper') ./cmd/install-helper
    if ($LASTEXITCODE -ne 0) {
        throw "linux/amd64 install-helper build failed with exit code $LASTEXITCODE"
    }

    Write-Host '==> Cross-checking linux/amd64 go vet'
    go vet -mod=vendor ./cmd/server ./cmd/install-helper ./internal/... ./core/...
    if ($LASTEXITCODE -ne 0) {
        throw "linux/amd64 go vet failed with exit code $LASTEXITCODE"
    }

    Remove-Item Env:GOOS -ErrorAction SilentlyContinue
    Remove-Item Env:GOARCH -ErrorAction SilentlyContinue
    Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue

    if ($IncludeWindowsTest) {
        Write-Host '==> Running go test (windows/amd64)'
        go test -mod=vendor ./cmd/... ./core/... ./internal/...
        if ($LASTEXITCODE -ne 0) {
            throw "go test failed with exit code $LASTEXITCODE"
        }
    }

    Write-Host 'Build baseline verification succeeded.'
}
finally {
    Remove-Item Env:GOOS -ErrorAction SilentlyContinue
    Remove-Item Env:GOARCH -ErrorAction SilentlyContinue
    Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue
    Pop-Location
}
