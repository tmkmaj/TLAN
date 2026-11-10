param(
    [string]$ServerURL = 'https://8.163.21.82:8443',
    [string]$STUNAddress = '8.163.21.82:3478'
)
$ErrorActionPreference = 'Stop'
$serviceURI = $null
if (-not [Uri]::TryCreate($ServerURL,[UriKind]::Absolute,[ref]$serviceURI) -or $serviceURI.Scheme -notin @('http','https') -or $serviceURI.UserInfo -or $serviceURI.Query -or $serviceURI.Fragment -or $ServerURL -match '[\s"''`]' -or $STUNAddress -match '[\s"''`]') { throw 'Use a plain HTTP(S) URL without credentials or query; STUN must be host:port' }
$root = $PSScriptRoot
Push-Location $root
$previous = @{}
foreach ($key in @('GOOS','GOARCH','CGO_ENABLED','GOCACHE')) { $previous[$key] = [Environment]::GetEnvironmentVariable($key,'Process') }
try {
    $goPath = (Get-Command go -ErrorAction SilentlyContinue).Source
    if (-not $goPath) { throw 'Go 1.23.1 or newer is required' }
    $env:GOOS = 'windows'
    $env:GOARCH = 'amd64'
    $env:CGO_ENABLED = '0'
    $env:GOCACHE = Join-Path $root '.tmp-build\go-cache'
    $resourceTool = (Get-Command go-winres -ErrorAction SilentlyContinue).Source
    if (-not $resourceTool) { $resourceTool = Join-Path $env:USERPROFILE 'go\bin\go-winres.exe' }
    if (-not (Test-Path -LiteralPath 'assets\branding\tmknetworklan-icon.png')) { throw 'Missing TmkNetworkLAN application icon.' }
    if (-not (Test-Path -LiteralPath $resourceTool)) { throw 'Install github.com/tc-hib/go-winres@v0.3.3 to regenerate the current icon/manifest resources.' }
    & $resourceTool make --in cmd/client/winres.json --arch amd64 --out cmd/client/tmknetworklan
    if ($LASTEXITCODE -ne 0) { throw 'Manifest resource generation failed' }
    if (-not (Test-Path -LiteralPath 'cmd\client\tmknetworklan_windows_amd64.syso')) { throw 'Missing icon/manifest resource. Install github.com/tc-hib/go-winres@v0.3.3 and rebuild.' }
    $driver = 'assets\windows\amd64\wintun.dll'
    if ((Get-FileHash -LiteralPath $driver -Algorithm SHA256).Hash -ne 'E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE') { throw 'Wintun DLL checksum mismatch' }
    $frpc = 'assets\frp\windows-amd64\frpc.exe'
    if (-not (Test-Path -LiteralPath $frpc)) { throw 'Missing pinned FRP client binary.' }
    if ((Get-FileHash -LiteralPath $frpc -Algorithm SHA256).Hash -ne '509F4FA082BF9B85F9AD27B45D37A89A8ACCB011F3B724CFF352DFAC90A94FEB') { throw 'FRP client checksum mismatch' }
    New-Item -ItemType Directory -Force -Path 'dist\windows' | Out-Null
    if (Test-Path -LiteralPath 'dist\windows\runtime\egress') { Remove-Item -LiteralPath 'dist\windows\runtime\egress' -Recurse -Force }
    $clientFlags = "-H=windowsgui -s -w -X main.bundledServerURL=$($ServerURL.TrimEnd('/')) -X main.bundledSTUNAddress=$STUNAddress"
    & $goPath build -mod=vendor -trimpath -ldflags $clientFlags -o 'dist\windows\TmkNetworkLAN.exe' '.\cmd\client'
    if ($LASTEXITCODE -ne 0) { throw 'Windows client build failed' }
    # The explicit-proxy helper is a separate binary so the GUI never implements
    # the data plane. It is packaged next to the client and launched on demand.
    Copy-Item -LiteralPath 'cmd\client\TmkNetworkLAN.exe.manifest' -Destination 'dist\windows\TmkNetworkLAN.exe.manifest' -Force
    foreach ($legacy in @('dist\windows\lanmesh-client.exe','dist\windows\lanmesh-client.exe.manifest')) {
        if (Test-Path -LiteralPath $legacy) { Remove-Item -LiteralPath $legacy -Force }
    }
    Copy-Item -LiteralPath 'assets\branding\tmknetworklan-icon.png' -Destination 'dist\windows\tmknetworklan-icon.png' -Force
    Copy-Item -LiteralPath $driver -Destination 'dist\windows\wintun.dll' -Force
    Copy-Item -LiteralPath 'assets\windows\WINTUN-LICENSE.txt' -Destination 'dist\windows\WINTUN-LICENSE.txt' -Force
    $frpRuntime = 'dist\windows\runtime\frp\0.71.1\windows-amd64'
    New-Item -ItemType Directory -Force -Path $frpRuntime | Out-Null
    Copy-Item -LiteralPath $frpc -Destination (Join-Path $frpRuntime 'frpc.exe') -Force
    Copy-Item -LiteralPath 'assets\frp\windows-amd64\manifest.json' -Destination 'dist\windows\runtime\frp\0.71.1\manifest.json' -Force
    New-Item -ItemType Directory -Force -Path 'dist\windows\runtime\frp\licenses' | Out-Null
    Copy-Item -LiteralPath 'assets\frp\licenses\FRP-LICENSE.txt' -Destination 'dist\windows\runtime\frp\licenses\FRP-LICENSE.txt' -Force
    Copy-Item -LiteralPath 'README.md' -Destination 'dist\windows\README.md' -Force
    New-Item -ItemType Directory -Force 'dist/windows/docs' | Out-Null
    foreach ($legacy in @('dist\windows\docs\EGRESS-DESIGN.md','dist\windows\docs\EGRESS-VALIDATION.md','dist\windows\docs\screenshots\egress-explicit-proxy-2026-11-10.png')) { if (Test-Path -LiteralPath $legacy) { Remove-Item -LiteralPath $legacy -Force } }
    Copy-Item -LiteralPath 'docs\IP-DEPLOYMENT.md' -Destination 'dist\windows\docs\IP-DEPLOYMENT.md' -Force
    Copy-Item -LiteralPath 'docs\FRPS-DEPLOY.md' -Destination 'dist\windows\docs\FRPS-DEPLOY.md' -Force
    Copy-Item -LiteralPath 'docs\R0-BUILD-AND-TEST-BASELINE.md' -Destination 'dist\windows\docs\R0-BUILD-AND-TEST-BASELINE.md' -Force
    Copy-Item -LiteralPath 'docs\R1-R2-IMPLEMENTATION-REPORT-2026-10-21.md' -Destination 'dist\windows\docs\R1-R2-IMPLEMENTATION-REPORT-2026-10-21.md' -Force
    Copy-Item -LiteralPath 'docs\ADVANCED-FEATURES-IMPLEMENTATION-2026-10-21.md' -Destination 'dist\windows\docs\ADVANCED-FEATURES-IMPLEMENTATION-2026-10-21.md' -Force
    Copy-Item -LiteralPath 'docs\CORE-UPDATE-INFRASTRUCTURE.md' -Destination 'dist\windows\docs\CORE-UPDATE-INFRASTRUCTURE.md' -Force
    Copy-Item -LiteralPath 'docs\FRPC-DESKTOP-COVERAGE.md' -Destination 'dist\windows\docs\FRPC-DESKTOP-COVERAGE.md' -Force
    New-Item -ItemType Directory -Force 'dist/windows/docs/screenshots' | Out-Null
    Copy-Item -LiteralPath 'docs\screenshots\frp-p2.png' -Destination 'dist\windows\docs\screenshots\frp-p2.png' -Force
    Copy-Item -LiteralPath 'docs\screenshots\sidebar-refinement-2026-11-10.png' -Destination 'dist\windows\docs\screenshots\sidebar-refinement-2026-11-10.png' -Force
    Copy-Item -LiteralPath 'docs\screenshots\sidebar-focus-2026-11-10.png' -Destination 'dist\windows\docs\screenshots\sidebar-focus-2026-11-10.png' -Force
    Copy-Item -LiteralPath 'docs\screenshots\admin-client-panel-2026-11-10.png' -Destination 'dist\windows\docs\screenshots\admin-client-panel-2026-11-10.png' -Force
    Copy-Item -LiteralPath 'THIRD-PARTY-NOTICES.md' -Destination 'dist\windows\THIRD-PARTY-NOTICES.md' -Force
    $licenses = @('github.com/lxn/walk','github.com/lxn/win','golang.zx2c4.com/wireguard','golang.zx2c4.com/wintun','golang.org/x/sys','golang.org/x/net','golang.org/x/crypto','gopkg.in/Knetic/govaluate.v3')
    New-Item -ItemType Directory -Force 'dist/windows/licenses' | Out-Null
    Copy-Item -LiteralPath 'assets\frp\licenses\FRP-LICENSE.txt' -Destination 'dist\windows\licenses\FRP-Apache-2.0.txt' -Force
    foreach ($dependency in $licenses) { $label=$dependency.Replace('/','_'); Copy-Item -LiteralPath (Join-Path "vendor/$dependency" 'LICENSE') -Destination "dist/windows/licenses/$label.txt" -Force }
    Compress-Archive -Path 'dist\windows\*' -DestinationPath 'dist\TmkNetworkLAN-client-windows-amd64.zip' -Force
    Write-Output (Join-Path $root 'dist\windows\TmkNetworkLAN.exe')
} finally {
    foreach ($key in $previous.Keys) { [Environment]::SetEnvironmentVariable($key,$previous[$key],'Process') }
    Pop-Location
}






