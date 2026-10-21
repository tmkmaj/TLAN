$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
Push-Location $root
$previous = @{}
foreach ($key in @('GOOS','GOARCH','CGO_ENABLED','GOCACHE')) { $previous[$key] = [Environment]::GetEnvironmentVariable($key,'Process') }
try {
    $env:GOOS = 'linux'
    $env:GOARCH = 'amd64'
    $env:CGO_ENABLED = '0'
    $env:GOCACHE = Join-Path $root '.tmp-build\go-cache'
    $frps = 'assets\frp\linux-amd64\frps'
    if (-not (Test-Path -LiteralPath $frps)) { throw 'Missing pinned FRP server binary.' }
    if ((Get-FileHash -LiteralPath $frps -Algorithm SHA256).Hash -ne '2FB8DA8392CF2B332BFCC540F075E928A82D1A106DF0B8FCFCF13497149F8C48') { throw 'FRP server checksum mismatch' }
    & (Join-Path $root 'scripts\verify-frps-templates.ps1')
    New-Item -ItemType Directory -Force 'dist\linux' | Out-Null
    go build -mod=vendor -trimpath -ldflags '-s -w' -o dist/linux/tmknetworklan-server ./cmd/server
    if ($LASTEXITCODE -ne 0) { throw 'Debian server build failed' }
    foreach ($legacy in @('dist/linux/lanmesh-server','dist/linux/lanmesh.env.example','dist/linux/tmknetworklan.env.example','dist/linux/lanmesh.service')) {
        if (Test-Path -LiteralPath $legacy) { Remove-Item -LiteralPath $legacy -Force }
    }
    Copy-Item -LiteralPath deploy/systemd/tmknetworklan.service -Destination dist/linux/tmknetworklan.service -Force
    Copy-Item -LiteralPath deploy/Caddyfile -Destination dist/linux/Caddyfile -Force
    Copy-Item -LiteralPath README.md -Destination dist/linux/README.md -Force
    New-Item -ItemType Directory -Force 'dist/linux/docs' | Out-Null
    Copy-Item -LiteralPath docs/IP-DEPLOYMENT.md -Destination dist/linux/docs/IP-DEPLOYMENT.md -Force
    Copy-Item -LiteralPath docs/R0-BUILD-AND-TEST-BASELINE.md -Destination dist/linux/docs/R0-BUILD-AND-TEST-BASELINE.md -Force
    Copy-Item -LiteralPath docs/R1-R2-IMPLEMENTATION-REPORT-2026-10-21.md -Destination dist/linux/docs/R1-R2-IMPLEMENTATION-REPORT-2026-10-21.md -Force
    Copy-Item -LiteralPath docs/ADVANCED-FEATURES-IMPLEMENTATION-2026-10-21.md -Destination dist/linux/docs/ADVANCED-FEATURES-IMPLEMENTATION-2026-10-21.md -Force
    Copy-Item -LiteralPath docs/CORE-UPDATE-INFRASTRUCTURE.md -Destination dist/linux/docs/CORE-UPDATE-INFRASTRUCTURE.md -Force
    Copy-Item -LiteralPath docs/FRPC-DESKTOP-COVERAGE.md -Destination dist/linux/docs/FRPC-DESKTOP-COVERAGE.md -Force
    Copy-Item -LiteralPath THIRD-PARTY-NOTICES.md -Destination dist/linux/THIRD-PARTY-NOTICES.md -Force
    New-Item -ItemType Directory -Force 'dist/linux/licenses' | Out-Null
    Copy-Item -LiteralPath 'vendor/golang.org/x/sys/LICENSE' -Destination 'dist/linux/licenses/go-sys.txt' -Force
    Copy-Item -LiteralPath 'vendor/golang.org/x/crypto/LICENSE' -Destination 'dist/linux/licenses/go-crypto.txt' -Force
    Copy-Item -LiteralPath 'vendor/gopkg.in/yaml.v3/LICENSE' -Destination 'dist/linux/licenses/go-yaml.txt' -Force
    Copy-Item -LiteralPath 'vendor/gopkg.in/yaml.v3/NOTICE' -Destination 'dist/linux/licenses/go-yaml-NOTICE.txt' -Force
    Compress-Archive -Path 'dist\linux\*' -DestinationPath 'dist\TmkNetworkLAN-server-debian-amd64.zip' -Force

    $frpRoot = Join-Path $root 'dist\frps-package'
    $distRoot = [System.IO.Path]::GetFullPath((Join-Path $root 'dist'))
    $frpRootFull = [System.IO.Path]::GetFullPath($frpRoot)
    if (-not $frpRootFull.StartsWith($distRoot + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe FRPS package path' }
    if (Test-Path -LiteralPath $frpRootFull) { Remove-Item -LiteralPath $frpRootFull -Recurse -Force }
    New-Item -ItemType Directory -Force -Path (Join-Path $frpRootFull 'opt\tlan-frp\licenses') | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path $frpRootFull 'opt\tlan-frp\docs') | Out-Null
    Copy-Item -LiteralPath $frps -Destination (Join-Path $frpRootFull 'opt\tlan-frp\frps') -Force
    Copy-Item -LiteralPath 'deploy\frps\install-frps.sh' -Destination (Join-Path $frpRootFull 'opt\tlan-frp\install-frps.sh') -Force
    Copy-Item -LiteralPath 'deploy\frps\frps.toml.example' -Destination (Join-Path $frpRootFull 'opt\tlan-frp\frps.toml.example') -Force
    Copy-Item -LiteralPath 'deploy\frps\frps-wss.toml.example' -Destination (Join-Path $frpRootFull 'opt\tlan-frp\frps-wss.toml.example') -Force
    Copy-Item -LiteralPath 'deploy\frps\tlan-frps.service' -Destination (Join-Path $frpRootFull 'opt\tlan-frp\tlan-frps.service') -Force
    Copy-Item -LiteralPath 'deploy\frps\tlan-frps-wss.service' -Destination (Join-Path $frpRootFull 'opt\tlan-frp\tlan-frps-wss.service') -Force
    Copy-Item -LiteralPath 'deploy\frps\README.md' -Destination (Join-Path $frpRootFull 'opt\tlan-frp\README.md') -Force
    Copy-Item -LiteralPath 'docs\FRPS-DEPLOY.md' -Destination (Join-Path $frpRootFull 'opt\tlan-frp\docs\FRPS-DEPLOY.md') -Force
    Copy-Item -LiteralPath 'assets\frp\linux-amd64\manifest.json' -Destination (Join-Path $frpRootFull 'opt\tlan-frp\manifest.json') -Force
    Copy-Item -LiteralPath 'assets\frp\licenses\FRP-LICENSE.txt' -Destination (Join-Path $frpRootFull 'opt\tlan-frp\licenses\FRP-LICENSE.txt') -Force
    Copy-Item -LiteralPath 'THIRD-PARTY-NOTICES.md' -Destination (Join-Path $frpRootFull 'opt\tlan-frp\THIRD-PARTY-NOTICES.md') -Force
    tar -czf 'dist\TmkNetworkLAN-frps-debian-amd64.tar.gz' -C $frpRootFull .
    if ($LASTEXITCODE -ne 0) { throw 'FRPS Debian package creation failed' }
    Write-Output (Join-Path $root 'dist\linux\tmknetworklan-server')
    Write-Output (Join-Path $root 'dist\TmkNetworkLAN-frps-debian-amd64.tar.gz')
} finally {
    foreach ($key in $previous.Keys) { [Environment]::SetEnvironmentVariable($key,$previous[$key],'Process') }
    Pop-Location
}

