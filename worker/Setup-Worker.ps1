<#
.SYNOPSIS
  One-time setup of the password reset worker on the IT staff PC.

.DESCRIPTION
  Run this while signed in to Windows as the service identity that has the
  delegated Reset Password right on the Student Users OU. It:
    - creates the RSA key pair (3072-bit). The private key never leaves this PC
      and is stored with DPAPI so only this Windows account can read it;
    - creates a random worker token and stores it the same way;
    - writes worker-config.json;
    - prints PUBLIC_KEY_JWK and WORKER_TOKEN to paste into the cloud host's
      environment variables.

.EXAMPLE
  .\Setup-Worker.ps1 -ServerUrl https://sbc-passwordreset.onrender.com `
      -StudentOU "OU=Student Users,DC=lambeth,DC=ac,DC=uk"
#>
param(
    [Parameter(Mandatory)] [string]$ServerUrl,
    [Parameter(Mandatory)] [string]$StudentOU,
    [string]$DomainController = '',
    [int]$PollSeconds = 3,
    [string]$OutDir = $PSScriptRoot,
    [switch]$Force
)

. (Join-Path $PSScriptRoot 'WorkerCommon.ps1')

if ($ServerUrl -notmatch '^https://' -and $ServerUrl -notmatch '^http://localhost(:\d+)?$') {
    throw 'ServerUrl must start with https:// (http is allowed only for localhost testing).'
}
if ($StudentOU -notmatch '^OU=') { throw 'StudentOU must be a distinguished name such as OU=Student Users,DC=example,DC=ac,DC=uk' }

$keyPath = Join-Path $OutDir 'worker-key.dat'
$tokenPath = Join-Path $OutDir 'worker-token.dat'
$configPath = Join-Path $OutDir 'worker-config.json'
if ((Test-Path $keyPath) -and -not $Force) {
    throw "A key already exists at $keyPath. Re-run with -Force to replace it (the cloud PUBLIC_KEY_JWK must then be updated too)."
}

$pair = New-WorkerKeyPair
try { Write-ProtectedFile $keyPath $pair.PrivateBytes }
finally { [Array]::Clear($pair.PrivateBytes, 0, $pair.PrivateBytes.Length) }

$tokenBytes = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($tokenBytes)
$token = ConvertTo-Base64Url $tokenBytes
Write-ProtectedFile $tokenPath ([Text.Encoding]::UTF8.GetBytes($token))

[ordered]@{
    ServerUrl        = $ServerUrl.TrimEnd('/')
    StudentOU        = $StudentOU
    DomainController = $DomainController
    PollSeconds      = $PollSeconds
} | ConvertTo-Json | Set-Content -Path $configPath -Encoding UTF8

Write-Host ''
Write-Host 'Setup complete. Set these two environment variables on the cloud host:' -ForegroundColor Green
Write-Host ''
Write-Host 'PUBLIC_KEY_JWK'
Write-Host $pair.PublicJwk
Write-Host ''
Write-Host 'WORKER_TOKEN'
Write-Host $token
Write-Host ''
Write-Host 'Then clear this window (cls). The token is stored protected in worker-token.dat.'
Write-Host "Files written to $OutDir. They only work for Windows user $([Environment]::UserName) on this PC."
