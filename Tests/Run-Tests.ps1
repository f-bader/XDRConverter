<#
.SYNOPSIS
Run all Pester tests for the XDRConverter module.

.DESCRIPTION
Executes all Pester tests in the Tests directory and generates a report.

.PARAMETER OutputFormat
Output format for the test results (NUnitXml, JUnitXml, None)

.PARAMETER OutputPath
Path where to save the test results file

.EXAMPLE
.\Run-Tests.ps1
.\Run-Tests.ps1 -OutputFormat NUnitXml -OutputPath ./testresults.xml
#>

param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('NUnitXml', 'JUnitXml', 'None')]
    [string]$OutputFormat = 'None',

    [Parameter(Mandatory = $false)]
    [string]$OutputPath
)

Write-Host "==== XDRConverter Pester Test Runner ====" -ForegroundColor Cyan

# Check if Pester is installed
$pesterModule = Get-Module -ListAvailable -Name 'Pester'
if (-not $pesterModule) {
    Write-Host "Pester module not found. Installing..." -ForegroundColor Yellow
    try {
        Install-Module -Name 'Pester' -Scope CurrentUser -Force -SkipPublisherCheck -ErrorAction Stop
        Write-Host "Pester installed successfully." -ForegroundColor Green
    } catch {
        Write-Host "ERROR: Failed to install Pester: $_" -ForegroundColor Red
        exit 1
    }
}

# Import Pester
Import-Module -Name 'Pester' -Force

# Get test files
$testFiles = Get-ChildItem -Path $PSScriptRoot -Filter '*.Tests.ps1'

if ($testFiles.Count -eq 0) {
    Write-Host "No test files found in $testPath" -ForegroundColor Yellow
    exit 0
}

Write-Host "`nFound $($testFiles.Count) test file(s):" -ForegroundColor Green
$testFiles | ForEach-Object { Write-Host "  - $($_.Name)" -ForegroundColor Green }

# Run Pester tests
Write-Host "`nRunning tests..." -ForegroundColor Cyan
$configuration = [PesterConfiguration]@{
    Run    = @{
        Path     = $testPath
        PassThru = $true
    }
    Output = @{
        Verbosity = 'Detailed'
    }
}

if ($OutputFormat -ne 'None' -and $OutputPath) {
    $configuration.TestResult = @{
        Enabled      = $true
        OutputFormat = $OutputFormat
        OutputPath   = $OutputPath
    }
}

$testResults = Invoke-Pester -Configuration $configuration

# Display summary
Write-Host "`n==== Test Summary ====" -ForegroundColor Cyan
Write-Host "Total Tests: $($testResults.Tests.Count)" -ForegroundColor White
Write-Host "Passed: $($testResults.Passed.Count)" -ForegroundColor Green
Write-Host "Failed: $($testResults.Failed.Count)" -ForegroundColor $(if ($testResults.Failed.Count -gt 0) { "Red" } else { "Green" })
Write-Host "Skipped: $($testResults.Skipped.Count)" -ForegroundColor Yellow

if ($testResults.Failed.Count -gt 0) {
    Write-Host "`n==== Failed Tests ====" -ForegroundColor Red
    $testResults.Failed | ForEach-Object {
        Write-Host "  ✗ $($_.Name)" -ForegroundColor Red
        Write-Host "    Error: $($_.ErrorRecord.Exception.Message)" -ForegroundColor Red
    }
}

if ($OutputFormat -ne 'None' -and $OutputPath) {
    Write-Host "`nResults saved to: $OutputPath" -ForegroundColor Green
}

# Exit with appropriate code
exit $(if ($testResults.Failed.Count -gt 0) { 1 } else { 0 })
