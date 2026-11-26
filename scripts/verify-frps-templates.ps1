$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$frpsPrimaryPath = Join-Path $repoRoot 'deploy\frps\frps.toml.example'
$frpsWssPath = Join-Path $repoRoot 'deploy\frps\frps-wss.toml.example'
$installScriptPath = Join-Path $repoRoot 'deploy\frps\install-frps.sh'

$errors = New-Object System.Collections.Generic.List[string]

function Assert-Contains {
    param(
        [string]$Text,
        [string]$Needle,
        [string]$Label
    )
    if (-not $Text.Contains($Needle)) {
        $errors.Add("Missing in ${Label}: $Needle")
    }
}

$primaryText = Get-Content -Path $frpsPrimaryPath -Raw -Encoding UTF8
foreach ($needle in @(
    "bindAddr = '0.0.0.0'",
    'bindPort = 7000',
    'kcpBindPort = 7002',
    'quicBindPort = 7003',
    'vhostHTTPPort = 18080',
    'vhostHTTPSPort = 18443',
    'tcpmuxHTTPConnectPort = 18081',
    "subDomainHost = 'frp.example.com'",
    "auth.method = 'token'",
    "auth.tokenSource.type = 'file'",
    "auth.tokenSource.file.path = '/etc/tlan-frp/token'",
    'transport.tls.force = true',
    "transport.tls.certFile = '/etc/tlan-frp/server.crt'",
    "transport.tls.keyFile = '/etc/tlan-frp/server.key'",
    'transport.tcpMux = true',
    'start = 60000, end = 61000'
)) {
    Assert-Contains -Text $primaryText -Needle $needle -Label 'frps.toml.example'
}

$wssText = Get-Content -Path $frpsWssPath -Raw -Encoding UTF8
foreach ($needle in @(
    "bindAddr = '127.0.0.1'",
    'bindPort = 7001',
    'vhostHTTPPort = 18082',
    'vhostHTTPSPort = 18444',
    'tcpmuxHTTPConnectPort = 18083',
    "subDomainHost = 'frp.example.com'",
    "auth.method = 'token'",
    "auth.tokenSource.type = 'file'",
    "auth.tokenSource.file.path = '/etc/tlan-frp/token'",
    'transport.tls.force = false',
    'transport.tcpMux = true',
    'start = 60000, end = 61000'
)) {
    Assert-Contains -Text $wssText -Needle $needle -Label 'frps-wss.toml.example'
}

$installText = Get-Content -Path $installScriptPath -Raw -Encoding UTF8
foreach ($needle in @(
    'check_capabilities',
    'kcpBindPort:7002',
    'quicBindPort:7003',
    'tcpmuxHTTPConnectPort:18081',
    'tcpmuxHTTPConnectPort:18083',
    'subDomainHost:frp.example.com',
    'tlan-frps.service',
    'tlan-frps-wss.service'
)) {
    Assert-Contains -Text $installText -Needle $needle -Label 'install-frps.sh'
}

if ($errors.Count -gt 0) {
    $errors | ForEach-Object { Write-Error $_ }
    exit 1
}

Write-Host 'frps template verification succeeded.'
