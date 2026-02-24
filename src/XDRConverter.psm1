<#
.SYNOPSIS
PowerShell module for converting Defender XDR detection rules between YAML and JSON formats.

.DESCRIPTION
The XDRConverter module provides cmdlets to convert Defender XDR custom detection rules
from YAML to JSON format and vice versa, with support for modifying enabled status and severity.
#>

# Get module root directory
$script:ModuleRoot = $PSScriptRoot

# Module-scoped cache for detection IDs
$script:DetectionIdsCache = @{
    Data      = $null
    ExpiresAt = [datetime]::MinValue
}

# Dot-source private then public functions via auto-discovery
foreach ($scope in 'Private', 'Public') {
    $scopePath = Join-Path -Path $script:ModuleRoot -ChildPath $scope
    if (Test-Path -Path $scopePath) {
        Get-ChildItem -Path $scopePath -Filter '*.ps1' -File | ForEach-Object {
            . $_.FullName
        }
    }
}

# Export only public functions (match filenames without extension)
$publicFunctions = (Get-ChildItem -Path (Join-Path $script:ModuleRoot 'Public') -Filter '*.ps1' -File).BaseName
Export-ModuleMember -Function $publicFunctions

