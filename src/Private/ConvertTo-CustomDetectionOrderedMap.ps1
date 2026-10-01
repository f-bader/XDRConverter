function ConvertTo-CustomDetectionOrderedMap {
    <#
    .SYNOPSIS
        Orders the keys of a map.

    .DESCRIPTION
        Keys named in Order come first, in that order. The remaining keys
        follow in the order the map holds them. Returns a new ordered
        dictionary and leaves the map untouched.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Map,

        [Parameter()]
        [AllowEmptyCollection()]
        [string[]]$Order = @()
    )

    $sorted = [ordered]@{}
    foreach ($key in $Order) {
        if ($Map.Contains($key)) { $sorted[$key] = $Map[$key] }
    }
    foreach ($key in $Map.Keys) {
        if (-not $sorted.Contains($key)) { $sorted[$key] = $Map[$key] }
    }
    return $sorted
}
