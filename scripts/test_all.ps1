$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments
    )
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed ($LASTEXITCODE): $Command $($Arguments -join ' ')"
    }
}

function Resolve-Tool {
    param([string]$EnvironmentName, [string]$CommandName, [string[]]$Fallbacks)
    $configured = [Environment]::GetEnvironmentVariable($EnvironmentName)
    if ($configured -and (Test-Path -LiteralPath $configured -PathType Leaf)) {
        return (Resolve-Path -LiteralPath $configured).Path
    }
    $command = Get-Command $CommandName -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    foreach ($candidate in $Fallbacks) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    throw "$CommandName is required but was not found"
}

$Python = Resolve-Tool "CLAIMSIEVE_PYTHON" "python" @()
$Node = Resolve-Tool "CLAIMSIEVE_NODE" "node" @(
    "${env:USERPROFILE}\.cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe"
)
$Cargo = Resolve-Tool "CLAIMSIEVE_CARGO" "cargo" @("${env:USERPROFILE}\.cargo\bin\cargo.exe")
$Rocq = Resolve-Tool "CLAIMSIEVE_ROCQ" "rocq" @("${env:USERPROFILE}\Rocq-Platform9.0.2025.08\bin\rocq.exe")

$env:PYTHONPATH = Join-Path $Root "python"
if (-not $env:ROCQLIB) {
    $env:ROCQLIB = Join-Path (Split-Path -Parent (Split-Path -Parent $Rocq)) "lib\coq"
}
$mingwBin = "${env:USERPROFILE}\msys64\mingw64\bin"
if (Test-Path -LiteralPath $mingwBin -PathType Container) {
    $env:PATH = "$mingwBin;$env:PATH"
}

if ($env:VERIFY_MANIFEST -eq "1") {
    foreach ($line in Get-Content -LiteralPath "MANIFEST.sha256") {
        if ($line -notmatch '^([a-f0-9]{64})  (.+)$') { throw "Malformed manifest line: $line" }
        $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Matches[2]).Hash.ToLowerInvariant()
        if ($actual -ne $Matches[1]) { throw "Manifest mismatch: $($Matches[2])" }
    }
    Write-Output "MANIFEST VERIFICATION: PASS"
}

Invoke-Checked $Python "-m" "unittest" "discover" "-s" "python\tests" "-v"
Invoke-Checked $Python "python\generate_bundle.py"
Invoke-Checked $Python "python\generate_durable_vector.py"
Invoke-Checked $Python "python\verify_bundle.py" "vectors\valid_evidence_bundle.json" "trust\fixture-trust-root.json"
Invoke-Checked $Node "--test" "mainstreet\test\*.test.js"
Invoke-Checked $Node "--check" "mainstreet\src\index.js"
Invoke-Checked $Node "--check" "mainstreet\src\founder-os.js"
Invoke-Checked $Python "python\founder_os_demo.py"
Invoke-Checked $Python "scripts\run_founder_os_red_team.py"
Invoke-Checked $Python "scripts\source_gate.py"
Invoke-Checked $Python "evidence\V033_PATCHED_TRACE_PROBE.py"
Invoke-Checked $Python "scripts\provider_contract_gate.py"
Invoke-Checked $Python "scripts\semantic_divergence_gate.py"
Invoke-Checked $Python "scripts\run_red_team.py"
Invoke-Checked $Python "scripts\run_durable_red_team.py"

Push-Location "rust"
try {
    Invoke-Checked $Cargo "fmt" "--all" "--" "--check"
    Invoke-Checked $Cargo "clippy" "--workspace" "--all-targets" "--all-features" "--" "-D" "warnings"
    Invoke-Checked $Cargo "test" "--workspace" "--all-features"
} finally {
    Pop-Location
}

Push-Location "rocq"
try {
    foreach ($file in @("Claimsieve.v", "DurableState.v", "Check.v", "CheckDurableState.v")) {
        Invoke-Checked $Rocq "compile" "-Q" "." "ClaimSieve" $file
    }
} finally {
    Pop-Location
}

Write-Output "ALL AVAILABLE EXECUTABLE GATES PASSED"
