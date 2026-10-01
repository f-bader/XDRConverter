function Resolve-CustomDetectionOutputFile {
    <#
    .SYNOPSIS
        Builds the output path for a rule written under its own name.

    .DESCRIPTION
        The file goes to the folder given, or to the temp directory, and is
        named after the display name in CamelCase or after the rule's guid.
        A missing folder is created.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [PSObject]$Rule,

        [Parameter(Mandatory)]
        [string]$Extension,

        [Parameter()]
        [string]$OutputFolder,

        [Parameter()]
        [switch]$UseDisplayName
    )

    $folder = if ($OutputFolder) { $OutputFolder } else { [System.IO.Path]::GetTempPath() }
    if (-not (Test-Path $folder)) {
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
    }
    if ($UseDisplayName) {
        # Characters a filename cannot carry become underscores, then the words join in CamelCase
        $safeName = $Rule.displayName -replace '[\\/:*?"<>|]', '_'
        $safeName = ($safeName -split '\s+' | ForEach-Object { $_.Substring(0, 1).ToUpper() + $_.Substring(1) }) -join ''
        return Join-Path $folder "$safeName$Extension"
    }
    return Join-Path $folder "$(Get-CustomDetectionIdentity -Rule $Rule)$Extension"
}
