param([string]$CaddyArchive = '')
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$caddyVersion = '2.11.7'
$caddyUrl = "https://github.com/caddyserver/caddy/releases/download/v$caddyVersion/caddy_${caddyVersion}_linux_amd64.tar.gz"
$caddySha512 = 'b152a5c32fb94a8b01e84d60c7fa6ad9b86c970bb52354f2f2b31b2fe6e39321899832f53a4dd83f7979f68b96763826d18a96136b9d3b8333a91ed3fd4f3a84'
$tmp = Join-Path $root '.tmp-build'
$cache = Join-Path $tmp 'cache'
$payload = Join-Path $tmp 'server-installer-payload'
$out = Join-Path $root 'dist\TLAN-server-linux-amd64.run'
New-Item -ItemType Directory -Force $cache, (Split-Path $out) | Out-Null
Remove-Item -Recurse -Force $payload -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $payload | Out-Null

if (-not $CaddyArchive) { $CaddyArchive = Join-Path $cache "caddy_${caddyVersion}_linux_amd64.tar.gz" }
if (-not (Test-Path $CaddyArchive)) {
    Invoke-WebRequest -UseBasicParsing -Uri $caddyUrl -OutFile $CaddyArchive
}
if ((Get-FileHash -Algorithm SHA512 $CaddyArchive).Hash.ToLowerInvariant() -ne $caddySha512) {
    throw "Caddy archive SHA512 mismatch: $CaddyArchive"
}
tar -xzf $CaddyArchive -C $payload caddy
if ($LASTEXITCODE -ne 0 -or -not (Test-Path "$payload\caddy")) { throw 'Failed to extract caddy binary.' }

$env:GOOS = 'linux'; $env:GOARCH = 'amd64'; $env:CGO_ENABLED = '0'
try {
    go build -mod=vendor -ldflags '-s -w' -o "$payload\tlan-server" ./cmd/server
    if ($LASTEXITCODE -ne 0) { throw 'go build ./cmd/server failed.' }
    go build -mod=vendor -ldflags '-s -w' -o "$payload\install-helper" ./cmd/install-helper
    if ($LASTEXITCODE -ne 0) { throw 'go build ./cmd/install-helper failed.' }
} finally {
    Remove-Item Env:GOOS, Env:GOARCH, Env:CGO_ENABLED -ErrorAction SilentlyContinue
}

foreach ($item in @(
    @{Src='deploy\Caddyfile'; Dst='Caddyfile'},
    @{Src='deploy\systemd\tlan.service'; Dst='tlan.service'},
    @{Src='deploy\systemd\tlan-https.service'; Dst='tlan-https.service'},
    @{Src='deploy\systemd\tlan-graceful-restart.sh'; Dst='tlan-graceful-restart.sh'},
    @{Src='docs\INSTALL-LINUX.md'; Dst='INSTALL-LINUX.md'},
    @{Src='docs\IP-DEPLOYMENT.md'; Dst='IP-DEPLOYMENT.md'}
)) {
    $srcPath = Join-Path $root $item.Src
    $dstPath = Join-Path $payload $item.Dst
    $text = [IO.File]::ReadAllText($srcPath) -replace "`r`n", "`n"
    [IO.File]::WriteAllText($dstPath, $text, [Text.UTF8Encoding]::new($false))
}

$archive = Join-Path $tmp 'server-payload.tar.gz'
Remove-Item -Force $archive -ErrorAction SilentlyContinue
tar -czf $archive -C $payload tlan-server caddy install-helper Caddyfile tlan.service tlan-https.service tlan-graceful-restart.sh INSTALL-LINUX.md IP-DEPLOYMENT.md
if ($LASTEXITCODE -ne 0) { throw 'Failed to create installer payload archive.' }
$archiveBytes = [IO.File]::ReadAllBytes($archive)
$payloadSha256 = (Get-FileHash -Algorithm SHA256 $archive).Hash.ToLowerInvariant()
$header = ([IO.File]::ReadAllText((Join-Path $root 'deploy\install-server.sh')) -replace "`r`n", "`n").Replace('@PAYLOAD_SHA256@', $payloadSha256)
$headerBytes = [Text.UTF8Encoding]::new($false).GetBytes($header)
$stream = [IO.File]::Create($out)
try { $stream.Write($headerBytes, 0, $headerBytes.Length); $stream.Write($archiveBytes, 0, $archiveBytes.Length) } finally { $stream.Dispose() }
$runSha256 = (Get-FileHash -Algorithm SHA256 $out).Hash.ToLowerInvariant()
[IO.File]::WriteAllText("$out.sha256", "$runSha256  $(Split-Path -Leaf $out)`n", [Text.UTF8Encoding]::new($false))
Write-Output "$out SHA256=$runSha256 PAYLOAD_SHA256=$payloadSha256 SIZE=$($archiveBytes.Length + $headerBytes.Length)"
