param(
    [Parameter(Mandatory = $true)]
    [string] $LockboxBin,
    [string] $WorkDir = "$env:TEMP\lockbox-agent-sleep-test",
    [switch] $NoSleep
)

$ErrorActionPreference = "Stop"

function Assert-Contains {
    param(
        [string] $Text,
        [string] $Needle,
        [string] $Message
    )
    if (-not $Text.Contains($Needle)) {
        throw $Message
    }
}

function Run-Step {
    param(
        [string] $Name,
        [scriptblock] $Action
    )
    Write-Host "stage: $Name"
    & $Action
    if ($LASTEXITCODE -ne 0) {
        throw "stage failed: $Name exit=$LASTEXITCODE"
    }
    Write-Host "stage-ok: $Name"
}

function Test-SleepStateAvailable {
    $state = powercfg /a | Out-String
    Write-Host $state
    return (
        $state.Contains("Standby (S0") -or
        $state.Contains("Standby (S1") -or
        $state.Contains("Standby (S2") -or
        $state.Contains("Standby (S3")
    )
}

if (Test-Path $WorkDir) {
    Remove-Item -Recurse -Force $WorkDir
}
New-Item -ItemType Directory -Force "$WorkDir\agent" | Out-Null
New-Item -ItemType Directory -Force "$WorkDir\vault" | Out-Null
$agentProcess = [System.IO.Path]::GetFileNameWithoutExtension($LockboxBin)
Get-Process $agentProcess -ErrorAction SilentlyContinue | Stop-Process -Force

if (-not $NoSleep) {
    Write-Host "Disabling hibernate for a suspend/resume test. This may require Administrator rights."
    powercfg /hibernate off | Out-Null

    if (-not (Test-SleepStateAvailable)) {
        throw "this Windows VM does not expose a usable standby sleep state"
    }
}

$env:LOCKBOX_PASSWORD = "test-lockbox-password"
$env:LOCKBOX_VAULT_PASSWORD = "test-vault-password"
$env:LOCKBOX_SESSION_AGENT_DIR = "$WorkDir\agent"
$env:LOCKBOX_SESSION_AGENT_LOG = "$WorkDir\agent.log"
$env:LOCKBOX_VAULT_DIR = "$WorkDir\vault"

Run-Step "vault init" { & $LockboxBin vault init | Out-Null }

Run-Step "create" { & $LockboxBin create "$WorkDir\test.lbox" | Out-Null }

Run-Step "open" { & $LockboxBin open "$WorkDir\test.lbox" | Out-Null }

Write-Host "stage: sessions before"
$before = & $LockboxBin vault sessions --format tsv
if ($LASTEXITCODE -ne 0) { throw "vault sessions failed before sleep" }
Assert-Contains $before "open" "expected lockbox to be cached before sleep"
Write-Host "stage-ok: sessions before"

$log = Get-Content -Raw $env:LOCKBOX_SESSION_AGENT_LOG
Assert-Contains $log "sleep watcher started" "agent log did not show a running sleep watcher"

if ($NoSleep) {
    Write-Host "prepared: cache is populated and sleep watcher is active"
    Write-Host "log: $env:LOCKBOX_SESSION_AGENT_LOG"
    exit 0
}

Write-Host "sleeping now; resume the VM if the hypervisor does not do it automatically"
rundll32.exe powrprof.dll,SetSuspendState 0,1,0
Start-Sleep -Seconds 8

$after = & $LockboxBin vault sessions --format tsv
if ($LASTEXITCODE -ne 0) { throw "vault sessions failed after sleep" }
if ($after.Trim() -ne "empty") {
    Get-Content -Raw $env:LOCKBOX_SESSION_AGENT_LOG | Write-Host
    throw "expected cache to be empty after resume; sessions output: $after"
}

$log = Get-Content -Raw $env:LOCKBOX_SESSION_AGENT_LOG
Assert-Contains $log "suspend requested; cleared" "agent log did not show a suspend cache clear"

Write-Host "pass: cache cleared on sleep"
Write-Host "log: $env:LOCKBOX_SESSION_AGENT_LOG"
