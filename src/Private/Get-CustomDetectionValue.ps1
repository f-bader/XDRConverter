function Get-CustomDetectionValue {
    <#
    .SYNOPSIS
        Reads a dot-separated path from a dictionary or object.

    .DESCRIPTION
        Walks the path one segment at a time through hashtables, ordered
        dictionaries and PSCustomObjects. Returns $null as soon as a segment
        is missing, so callers can read deep paths without guarding each step.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [object]$Object,

        [Parameter(Mandatory)]
        [string]$Path
    )

    $current = $Object
    foreach ($segment in $Path.Split('.')) {
        if ($null -eq $current) { return $null }
        $map = ConvertTo-CustomDetectionHashtable -InputObject $current
        if ($null -eq $map) { return $null }
        if (-not $map.Contains($segment)) { return $null }
        $current = $map[$segment]
    }
    return $current
}
