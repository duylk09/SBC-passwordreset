<#
.SYNOPSIS
  Polls the cloud queue and resets approved student passwords in Active Directory.

.DESCRIPTION
  Makes outbound HTTPS requests only; it never listens on a port. For each
  approved ticket it decrypts the password into a SecureString, finds the
  student by sAMAccountName inside the Student Users OU only, resets the
  password, and sets "must change password at next logon" to off.

  The password is never printed, logged, written to disk or passed on a command
  line. The console shows only ticket ID, student ID and the outcome.

  Run it as the delegated service identity (the same Windows account that ran
  Setup-Worker.ps1). Requires the ActiveDirectory module (RSAT).

.PARAMETER DryRun
  Decrypt and look up the account, but do not change the password. The ticket is
  reported back as "dry_run". Use this for the first trial against production.

.PARAMETER Once
  Process at most one poll and exit (for testing).
#>
param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'worker-config.json'),
    [switch]$DryRun,
    [switch]$Once
)

. (Join-Path $PSScriptRoot 'WorkerCommon.ps1')

$config = Get-Content -Raw -Path $ConfigPath | ConvertFrom-Json
$dir = Split-Path -Parent (Resolve-Path $ConfigPath)
$rsa = Import-WorkerKey (Join-Path $dir 'worker-key.dat')
$tokenBytes = Read-ProtectedFile (Join-Path $dir 'worker-token.dat')
$headers = @{ Authorization = 'Bearer ' + [Text.Encoding]::UTF8.GetString($tokenBytes) }
[Array]::Clear($tokenBytes, 0, $tokenBytes.Length)

function Write-Log([string]$Message) { Write-Host ('{0:yyyy-MM-dd HH:mm:ss}  {1}' -f (Get-Date), $Message) }

if ($script:IsWin) {
    $tr = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -ErrorAction SilentlyContinue
    if ($tr -and $tr.PSObject.Properties['EnableTranscripting'] -and $tr.EnableTranscripting -eq 1) {
        Write-Warning 'PowerShell transcription is enabled by policy. This worker never prints passwords, but check with IT security that transcripts are acceptable on this PC.'
    }
}

$adAvailable = [bool](Get-Module -ListAvailable -Name ActiveDirectory)
if ($adAvailable) { Import-Module ActiveDirectory -ErrorAction Stop }
elseif (-not $env:SBC_WORKER_FAKE_AD) { throw 'The ActiveDirectory PowerShell module (RSAT) is not installed.' }

# Returns @{ ok = $true } or @{ ok = $false; error = '<code>' }
function Invoke-StudentReset([string]$StudentId, [System.Security.SecureString]$Password) {
    if ($StudentId -notmatch '^[A-Za-z0-9]{3,20}$') { return @{ ok = $false; error = 'not_found' } }

    if ($env:SBC_WORKER_FAKE_AD) {
        # Test hook only: pretend the account exists and the reset worked.
        if ($env:SBC_WORKER_FAKE_AD_EXPECT) {
            $plain = (New-Object System.Net.NetworkCredential('', $Password)).Password
            if ($plain -cne $env:SBC_WORKER_FAKE_AD_EXPECT) { return @{ ok = $false; error = 'error' } }
        }
        return $(if ($DryRun) { @{ ok = $false; error = 'dry_run' } } else { @{ ok = $true } })
    }

    $ad = @{}
    if ($config.DomainController) { $ad.Server = $config.DomainController }
    try {
        # The regex above guarantees no LDAP filter metacharacters in $StudentId.
        $users = @(Get-ADUser @ad -LDAPFilter "(sAMAccountName=$StudentId)" -SearchBase $config.StudentOU -SearchScope Subtree)
    }
    catch { Write-Log "  lookup error: $($_.Exception.GetType().Name)"; return @{ ok = $false; error = 'error' } }
    if ($users.Count -eq 0) { return @{ ok = $false; error = 'not_found' } }
    if ($users.Count -gt 1) { return @{ ok = $false; error = 'not_unique' } }
    if ($DryRun) { return @{ ok = $false; error = 'dry_run' } }

    try {
        Set-ADAccountPassword @ad -Identity $users[0] -Reset -NewPassword $Password
        Set-ADUser @ad -Identity $users[0] -ChangePasswordAtLogon $false
        @{ ok = $true }
    }
    catch {
        $name = $_.Exception.GetType().Name
        Write-Log "  reset error: $name"
        if ($name -match 'PasswordComplexity|PasswordPolicy' -or $_.Exception.Message -match 'password does not meet') {
            @{ ok = $false; error = 'policy' }
        } else { @{ ok = $false; error = 'error' } }
    }
}

function Invoke-Poll {
    $resp = Invoke-RestMethod -Method Post -Uri "$($config.ServerUrl)/api/worker/next" -Headers $headers -TimeoutSec 20
    $ticket = $resp.ticket
    if (-not $ticket) { return $false }

    # Once a ticket is taken it must always get a result, or it stays "processing".
    try {
        $opened = Open-ResetPayload $rsa $ticket
        if ($opened.ContainsKey('Error')) { $result = @{ ok = $false; error = $opened.Error } }
        else {
            try { $result = Invoke-StudentReset $ticket.studentId $opened.Password }
            finally { $opened.Password.Dispose() }
        }
    }
    catch {
        Write-Log "  unexpected error: $($_.Exception.GetType().Name)"
        $result = @{ ok = $false; error = 'error' }
    }

    Invoke-RestMethod -Method Post -Uri "$($config.ServerUrl)/api/worker/tickets/$($ticket.id)/result" -Headers $headers `
        -ContentType 'application/json' -Body ($result | ConvertTo-Json -Compress) -TimeoutSec 20 | Out-Null
    $outcome = if ($result.ok) { 'password reset' } else { 'not reset: ' + $result.error }
    Write-Log "ticket $($ticket.id)  student $($ticket.studentId)  $outcome"
    $true
}

Write-Log "Worker started. Polling $($config.ServerUrl) every $($config.PollSeconds)s$(if ($DryRun) { ' (DRY RUN: no passwords will be changed)' }). Press Ctrl+C to stop."
$delay = [int]$config.PollSeconds
try {
    while ($true) {
        try {
            $worked = Invoke-Poll
            $delay = [int]$config.PollSeconds
        }
        catch {
            Write-Log "poll failed: $($_.Exception.Message)"
            $worked = $false
            $delay = [Math]::Min($delay * 2, 60)
        }
        if ($Once) { break }
        if (-not $worked) { Start-Sleep -Seconds $delay }
    }
}
finally { $rsa.Dispose() }
