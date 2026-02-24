function Import-CustomDetectionYamlFile {
    <#
    .SYNOPSIS
        Imports a YAML file and converts it to a PowerShell object.

    .DESCRIPTION
        Reads a YAML file and parses it into a PowerShell object.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
        [string]$FilePath
    )

    $content = Get-Content -Path $FilePath -Raw
    $content | ConvertFrom-Yaml
}

