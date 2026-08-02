$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$Project = Split-Path -Parent $PSScriptRoot
$Python = Join-Path (Split-Path -Parent $Project) ".venv-claimsieve-v034\Scripts\python.exe"
$Repository = "ethanduley-png/claimsieve-mainstreet"
$Workspace = Join-Path $Project ".claimsieve-github"
$RequestPath = Join-Path ([System.IO.Path]::GetTempPath()) ("claimsieve-github-canary-" + [guid]::NewGuid().ToString("N") + ".json")
$ExitCode = 0
$ReadSecret = $null
$WriteSecret = $null
$ReadToken = $null
$WriteToken = $null

function Invoke-Checked {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    & $Python @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "ClaimSieve command failed with exit code $LASTEXITCODE"
    }
}

try {
    if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
        throw "ClaimSieve Python environment was not found: $Python"
    }
    if (Test-Path -LiteralPath $Workspace) {
        throw "The one-time canary workspace already exists. Refusing to retry an earlier GitHub write: $Workspace"
    }

    Write-Host "ClaimSieve GitHub canary" -ForegroundColor Cyan
    Write-Host "Repository: $Repository"
    Write-Host "The token prompts are masked and the values are never written to disk."
    Write-Host ""

    $ReadSecret = Read-Host "Paste the OBSERVER token (Issues read-only)" -AsSecureString
    $WriteSecret = Read-Host "Paste the WRITER token (Issues read/write)" -AsSecureString
    $ReadToken = [System.Net.NetworkCredential]::new("", $ReadSecret).Password
    $WriteToken = [System.Net.NetworkCredential]::new("", $WriteSecret).Password
    if (-not $ReadToken -or -not $WriteToken) {
        throw "Both tokens are required"
    }
    if ($ReadToken -eq $WriteToken) {
        throw "Observer and writer tokens must be different"
    }

    $env:CLAIMSIEVE_GITHUB_READ_TOKEN = $ReadToken
    $env:CLAIMSIEVE_GITHUB_WRITE_TOKEN = $WriteToken
    $env:PYTHONPATH = Join-Path $Project "python"

    Write-Host ""
    Write-Host "1/2 Read-only repository check" -ForegroundColor Cyan
    Invoke-Checked @("python\github_integration.py", "check", $Repository)

    $Suffix = Get-Date -Format "yyyyMMddHHmmss"
    $Request = [ordered]@{
        body = "Governed canary created by ClaimSieve after exact permit validation and independent GitHub read-back."
        campaign_id = "founder-campaign-github-canary-$Suffix"
        proposal_id = "founder-proposal-github-canary-$Suffix"
        repository = $Repository
        requested_at_seq = 10
        session_id = "founder-session-github-canary-$Suffix"
        title = "ClaimSieve GitHub integration canary"
        trace_id = "founder-trace-github-canary-$Suffix"
        work_item_id = "work-item-github-canary-$Suffix"
    }
    $Request | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $RequestPath -Encoding UTF8

    Write-Host ""
    Write-Host "2/2 Non-sending authorization plan" -ForegroundColor Cyan
    Invoke-Checked @("python\github_integration.py", "plan", $RequestPath)

    Write-Host ""
    Write-Host "NEXT ACTION CREATES ONE EXTERNAL GITHUB ISSUE" -ForegroundColor Yellow
    Write-Host "Title: ClaimSieve GitHub integration canary"
    Write-Host "Repository: $Repository"
    $Confirmation = Read-Host "Type CREATE to authorize this exact issue"
    if ($Confirmation -cne "CREATE") {
        Write-Host "Cancelled. No GitHub issue was created." -ForegroundColor Yellow
    } else {
        $env:CLAIMSIEVE_ENABLE_LIVE_GITHUB_WRITE = "1"
        Invoke-Checked @(
            "python\github_integration.py",
            "execute",
            $RequestPath,
            "--workspace", $Workspace,
            "--confirm-repository", $Repository,
            "--execute-live-write"
        )
        Write-Host "Canary command completed. Review the independent_outcome above." -ForegroundColor Green
    }
} catch {
    $ExitCode = 1
    Write-Host ""
    Write-Host ("Stopped: " + $_.Exception.Message) -ForegroundColor Red
} finally {
    Remove-Item Env:CLAIMSIEVE_GITHUB_READ_TOKEN -ErrorAction SilentlyContinue
    Remove-Item Env:CLAIMSIEVE_GITHUB_WRITE_TOKEN -ErrorAction SilentlyContinue
    Remove-Item Env:CLAIMSIEVE_ENABLE_LIVE_GITHUB_WRITE -ErrorAction SilentlyContinue
    Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $RequestPath -ErrorAction SilentlyContinue
    $ReadToken = $null
    $WriteToken = $null
    if ($ReadSecret) { $ReadSecret.Dispose() }
    if ($WriteSecret) { $WriteSecret.Dispose() }
}

Write-Host ""
[void](Read-Host "Press Enter to close")
exit $ExitCode
