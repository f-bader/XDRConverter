function Get-CustomDetectionLegacyAction {
    <#
    .SYNOPSIS
        Resolves a legacy response action to its action map entry.

    .DESCRIPTION
        A legacy responseActions item carries an OData type whose trailing
        word names the action. Returns that type and the matching entry of
        the action map. The entry is null when the type is unknown.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$ResponseAction,

        [Parameter(Mandatory)]
        [object[]]$ActionMap
    )

    $odataType = "$($ResponseAction['@odata.type'])"
    $suffix = if ($odataType -match '([A-Za-z]+)$') { $Matches[1] } else { $odataType }
    $entry = $ActionMap | Where-Object { $_.LegacyType -eq $suffix } | Select-Object -First 1
    return [PSCustomObject]@{ OdataType = $odataType; Entry = $entry }
}
