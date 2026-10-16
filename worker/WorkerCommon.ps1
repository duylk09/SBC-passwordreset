# Shared functions for Setup-Worker.ps1 and Start-ResetWorker.ps1.
# Works in Windows PowerShell 5.1 (.NET Framework 4.7.2+) and PowerShell 7.

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$script:IsWin = [System.Environment]::OSVersion.Platform -eq 'Win32NT'
# Tests on Linux/macOS have no DPAPI. This switch stores secrets unprotected and
# must never be set on the real staff PC.
$script:PlainFiles = $env:SBC_WORKER_TEST_PLAINTEXT -eq '1'

if ($script:IsWin) {
    try { Add-Type -AssemblyName System.Security } catch { }
    if ($PSVersionTable.PSVersion.Major -lt 6) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    }
}

function ConvertTo-Base64Url([byte[]]$Bytes) {
    [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function ConvertFrom-Base64Url([string]$Text) {
    $s = $Text.Replace('-', '+').Replace('_', '/')
    switch ($s.Length % 4) { 2 { $s += '==' } 3 { $s += '=' } }
    [Convert]::FromBase64String($s)
}

# DPAPI, CurrentUser scope: only the Windows account that ran the setup can
# read these files, and only on this PC.
function Write-ProtectedFile([string]$Path, [byte[]]$Bytes) {
    if ($script:PlainFiles) { $out = $Bytes }
    elseif ($script:IsWin) {
        $out = [System.Security.Cryptography.ProtectedData]::Protect($Bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    }
    else { throw 'DPAPI is only available on Windows.' }
    [IO.File]::WriteAllBytes($Path, $out)
}

function Read-ProtectedFile([string]$Path) {
    $bytes = [IO.File]::ReadAllBytes($Path)
    if ($script:PlainFiles) { return , $bytes }
    if (-not $script:IsWin) { throw 'DPAPI is only available on Windows.' }
    , [System.Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
}

function New-RsaForDecrypt {
    # RSACng supports OAEP with SHA-256 on .NET Framework; RSA.Create() elsewhere.
    if ($script:IsWin) { New-Object System.Security.Cryptography.RSACng }
    else { [System.Security.Cryptography.RSA]::Create() }
}

$script:RsaFields = 'Modulus', 'Exponent', 'D', 'P', 'Q', 'DP', 'DQ', 'InverseQ'

# Returns @{ PrivateBytes = <JSON bytes to protect>; PublicJwk = <JSON string> }
function New-WorkerKeyPair {
    if ($script:IsWin) { $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider 3072 }
    else { $rsa = [System.Security.Cryptography.RSA]::Create(3072) }
    try {
        $p = $rsa.ExportParameters($true)
        $priv = [ordered]@{}
        foreach ($f in $script:RsaFields) { $priv[$f] = [Convert]::ToBase64String($p.$f) }
        $jwk = [ordered]@{ kty = 'RSA'; alg = 'RSA-OAEP-256'; n = (ConvertTo-Base64Url $p.Modulus); e = (ConvertTo-Base64Url $p.Exponent) }
        @{
            PrivateBytes = [Text.Encoding]::UTF8.GetBytes(($priv | ConvertTo-Json -Compress))
            PublicJwk    = ($jwk | ConvertTo-Json -Compress)
        }
    }
    finally { $rsa.Dispose() }
}

function Import-WorkerKey([string]$Path) {
    $bytes = Read-ProtectedFile $Path
    try {
        $obj = [Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json
        $p = New-Object System.Security.Cryptography.RSAParameters
        foreach ($f in $script:RsaFields) { $p.$f = [Convert]::FromBase64String($obj.$f) }
        $rsa = New-RsaForDecrypt
        $rsa.ImportParameters($p)
        $rsa
    }
    finally { [Array]::Clear($bytes, 0, $bytes.Length) }
}

# Decrypts a ticket. Payload is UTF-8 "<header JSON>\n<password>".
# The password goes straight from bytes into a SecureString and the buffers are
# wiped; it is never held in a .NET string, written out, or logged.
# Returns @{ Password = <SecureString> } or @{ Error = '<code>' }.
function Open-ResetPayload($Rsa, $Ticket) {
    try {
        $plain = $Rsa.Decrypt((ConvertFrom-Base64Url $Ticket.ciphertext), [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
    }
    catch { return @{ Error = 'decrypt_failed' } }
    $chars = $null
    try {
        $nl = [Array]::IndexOf($plain, [byte]10)
        if ($nl -lt 1) { return @{ Error = 'payload_mismatch' } }
        try { $header = [Text.Encoding]::UTF8.GetString($plain, 0, $nl) | ConvertFrom-Json }
        catch { return @{ Error = 'payload_mismatch' } }
        if ($header.v -ne 1 -or $header.sid -cne $Ticket.sessionId -or $header.id -cne $Ticket.studentId) {
            return @{ Error = 'payload_mismatch' }
        }
        $chars = [Text.Encoding]::UTF8.GetChars($plain, $nl + 1, $plain.Length - $nl - 1)
        if ($chars.Length -lt 1) { return @{ Error = 'payload_mismatch' } }
        $secure = New-Object System.Security.SecureString
        foreach ($c in $chars) { $secure.AppendChar($c) }
        $secure.MakeReadOnly()
        @{ Password = $secure }
    }
    finally {
        [Array]::Clear($plain, 0, $plain.Length)
        if ($chars) { [Array]::Clear($chars, 0, $chars.Length) }
    }
}
