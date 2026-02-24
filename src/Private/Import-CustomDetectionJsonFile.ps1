function Import-CustomDetectionJsonFile {
    <#
    .SYNOPSIS
        Imports a JSON file and converts it to a PowerShell object.

    .DESCRIPTION
        Reads a JSON file and parses it into a PowerShell object.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
        [string]$FilePath
    )

    $content = Get-Content -Path $FilePath -Raw
    $content | ConvertFrom-Json
}

