param([switch]$Offline)
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$caddyVersion = '2.11.7'
$caddySHA512 = 'a7a433a1b133efc3c8d10eb0b99d52a24b5ef5c322dc77f5282182b1c0402139ab83f3a99f0c52409df77d20123fb0b523edad8a66d8f5e49136197bf61ef0e7'
$cache = Join-Path $root '.tmp-build/caddy-linux'
$stage = Join-Path $root '.tmp-build/server-installer-payload'
$previous = @{}
foreach ($key in @('GOOS','GOARCH','GOAMD64','CGO_ENABLED','GOCACHE')) { $previous[$key] = [Environment]::GetEnvironmentVariable($key,'Process') }
Push-Location $root
try {
    New-Item -ItemType Directory -Force $cache, $stage, "$stage/licenses", 'dist' | Out-Null
    $archive = Join-Path $cache 'caddy.tar.gz'
    if (!(Test-Path -LiteralPath $archive)) {
        if ($Offline) { throw 'Caddy cache missing; run once without -Offline.' }
        Invoke-WebRequest "https://github.com/caddyserver/caddy/releases/download/v$caddyVersion/caddy_${caddyVersion}_linux_amd64.tar.gz" -OutFile $archive
    }
    if ((Get-FileHash -Algorithm SHA512 -LiteralPath $archive).Hash.ToLowerInvariant() -ne $caddySHA512) { throw 'Official Caddy archive checksum mismatch.' }
    tar -xzf $archive -C $cache caddy LICENSE
    if ($LASTEXITCODE -ne 0) { throw 'Caddy extraction failed.' }
    $env:GOOS = 'linux'; $env:GOARCH = 'amd64'; $env:GOAMD64 = 'v1'; $env:CGO_ENABLED = '0'
    $env:GOCACHE = Join-Path $root '.tmp-build/go-cache'
    foreach ($binary in @(@{Name='tmknetworklan-server'; Package='./cmd/server'}, @{Name='install-helper'; Package='./cmd/install-helper'})) {
        go build -mod=vendor -trimpath -ldflags '-s -w' -o "$stage/$($binary.Name)" $binary.Package
        if ($LASTEXITCODE -ne 0) { throw "Build failed: $($binary.Name)" }
    }
    Copy-Item "$cache/caddy" "$stage/caddy" -Force
    Copy-Item "$cache/LICENSE" "$stage/licenses/caddy-Apache-2.0.txt" -Force
    Copy-Item 'deploy/Caddyfile' "$stage/Caddyfile" -Force
    Copy-Item 'deploy/systemd/tmknetworklan.service' "$stage/tmknetworklan.service" -Force
    Copy-Item 'deploy/systemd/tmknetworklan-https.service' "$stage/tmknetworklan-https.service" -Force
    Copy-Item 'docs/INSTALL-LINUX.md' "$stage/INSTALL-LINUX.md" -Force
    Copy-Item 'docs/IP-DEPLOYMENT.md' "$stage/IP-DEPLOYMENT.md" -Force
    Copy-Item 'THIRD-PARTY-NOTICES.md' "$stage/licenses/THIRD-PARTY-NOTICES.md" -Force
    foreach ($dep in @('sys','crypto')) { Copy-Item "vendor/golang.org/x/$dep/LICENSE" "$stage/licenses/go-$dep.txt" -Force }
    Copy-Item 'vendor/gopkg.in/yaml.v3/LICENSE' "$stage/licenses/go-yaml.txt" -Force
    Copy-Item 'vendor/gopkg.in/yaml.v3/NOTICE' "$stage/licenses/go-yaml-NOTICE.txt" -Force
    # Use a native checker to prove all shipped ELF executables are static amd64.
    $env:GOOS = 'windows'
    go run -mod=vendor ./cmd/install-helper verify-elf "$stage/tmknetworklan-server" "$stage/caddy" "$stage/install-helper"
    if ($LASTEXITCODE -ne 0) { throw 'Static Linux executable verification failed.' }
    $payload = Join-Path $root '.tmp-build/server-installer-payload.tar.gz'
    # Explicit entries avoid unintentionally packaging stale files from the build cache.
    tar -czf $payload -C $stage tmknetworklan-server caddy install-helper Caddyfile tmknetworklan.service tmknetworklan-https.service INSTALL-LINUX.md IP-DEPLOYMENT.md licenses
    if ($LASTEXITCODE -ne 0) { throw 'Payload creation failed.' }
    $payloadHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $payload).Hash.ToLowerInvariant()
    $header = [IO.File]::ReadAllText((Join-Path $root 'deploy/install-server.sh')).Replace("`r`n", "`n").Replace('@PAYLOAD_SHA256@', $payloadHash)
    if (!$header.EndsWith("`n")) { $header += "`n" }
    $output = Join-Path $root 'dist/TmkNetworkLAN-server-linux-amd64.run'
    $stream = [IO.File]::Create($output)
    try {
        $headerBytes = [Text.UTF8Encoding]::new($false).GetBytes($header)
        $stream.Write($headerBytes, 0, $headerBytes.Length)
        $inputStream = [IO.File]::OpenRead($payload)
        try { $inputStream.CopyTo($stream) } finally { $inputStream.Dispose() }
    } finally { $stream.Dispose() }
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $output).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText("$output.sha256", "$hash  TmkNetworkLAN-server-linux-amd64.run`n", [Text.UTF8Encoding]::new($false))
    Copy-Item 'docs/INSTALL-LINUX.md' 'dist/INSTALL-LINUX.md' -Force
    Copy-Item 'docs/IP-DEPLOYMENT.md' 'dist/IP-DEPLOYMENT.md' -Force
    Write-Output "Installer: $output"
    Write-Output "SHA256: $hash"
} finally {
    foreach ($key in $previous.Keys) { [Environment]::SetEnvironmentVariable($key,$previous[$key],'Process') }
    Pop-Location
}
