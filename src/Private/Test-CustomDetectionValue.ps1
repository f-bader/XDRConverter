function Test-CustomDetectionValue {
    <#
    .SYNOPSIS
        Tells whether a value carries content.

    .DESCRIPTION
        Null, a blank string, an empty dictionary and an empty collection
        count as absent. Everything else counts as present.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Position = 0)]
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) { return $false }
    if ($Value -is [string]) { return -not [string]::IsNullOrWhiteSpace($Value) }
    if ($Value -is [System.Collections.IDictionary]) { return $Value.Count -gt 0 }
    if ($Value -is [System.Collections.IEnumerable]) { return @($Value).Count -gt 0 }
    return $true
}
