param([string]$Bash)
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$previousPath = $env:PATH
Push-Location $root
try {
    $path = Join-Path $root 'dist/TmkNetworkLAN-server-linux-amd64.run'
    $bytes = [IO.File]::ReadAllBytes($path)
    $marker = [Text.Encoding]::ASCII.GetBytes("`n__TMK_PAYLOAD_BELOW__`n")
    $offset = -1
    # The header is small; do not scan compressed payload as text.
    for ($i = 0; $i -lt [Math]::Min($bytes.Length - $marker.Length, 131072); $i++) {
        if ($bytes[$i] -ne $marker[0]) { continue }
        $match = $true
        for ($j = 1; $j -lt $marker.Length; $j++) { if ($bytes[$i + $j] -ne $marker[$j]) { $match = $false; break } }
        if ($match) { $offset = $i + $marker.Length; break }
    }
    if ($offset -lt 0) { throw 'Payload marker not found.' }
    $header = [Text.Encoding]::UTF8.GetString($bytes, 0, $offset)
    if ($header.Contains("`r") -or $header.Contains('@PAYLOAD_SHA256@')) { throw 'Invalid header encoding/checksum substitution.' }
    if ($header -notmatch "printf '%s  %s\\n' '([0-9a-f]{64})'") { throw 'Expected payload SHA256 is missing.' }
    $expected = $Matches[1]
    $verify = Join-Path $root ('.tmp-build/installer-verify-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory $verify | Out-Null
    $archive = Join-Path $verify 'payload.tar.gz'
    $stream = [IO.File]::Create($archive)
    try { $stream.Write($bytes, $offset, $bytes.Length - $offset) } finally { $stream.Dispose() }
    if ((Get-FileHash -Algorithm SHA256 $archive).Hash.ToLowerInvariant() -ne $expected) { throw 'Appended payload checksum mismatch.' }
    $expectedFull = ([IO.File]::ReadAllText("$path.sha256") -split '\s+')[0]
    if ((Get-FileHash -Algorithm SHA256 $path).Hash.ToLowerInvariant() -ne $expectedFull) { throw 'Installer checksum mismatch.' }
    tar -xzf $archive -C $verify
    if ($LASTEXITCODE -ne 0) { throw 'Payload extraction failed.' }
    foreach ($name in @('tmknetworklan-server','caddy','install-helper','Caddyfile','tmknetworklan.service','tmknetworklan-https.service','INSTALL-LINUX.md','IP-DEPLOYMENT.md')) {
        $stagedHash = (Get-FileHash -Algorithm SHA256 ".tmp-build/server-installer-payload/$name").Hash
        if ((Get-FileHash -Algorithm SHA256 "$verify/$name").Hash -ne $stagedHash) { throw "Payload differs from build output: $name" }
    }
    foreach ($unit in @('tmknetworklan.service','tmknetworklan-https.service')) {
        $text = Get-Content -Raw "$verify/$unit"
        if ($text -match '(?m)^(StateDirectory|ReadWritePaths|AmbientCapabilities)=|^ProtectSystem=strict') { throw "Unit contains directives incompatible with systemd 219: $unit" }
    }
    if ($Bash) {
        $env:PATH = (Split-Path -Parent $Bash) + [IO.Path]::PathSeparator + $previousPath
        & $Bash -n deploy/install-server.sh
        if ($LASTEXITCODE -ne 0) { throw 'Bash syntax check failed.' }
        & $Bash deploy/tests/installer-rollback-test.sh
        if ($LASTEXITCODE -ne 0) { throw 'Rollback test failed.' }
        & $Bash dist/TmkNetworkLAN-server-linux-amd64.run --help
        if ($LASTEXITCODE -ne 0) { throw 'Installer help smoke test failed.' }
    }
    Write-Output 'PASS: header, payload checksum, full checksum, extraction, shipped files and systemd compatibility checks.'
} finally { $env:PATH = $previousPath; Pop-Location }
