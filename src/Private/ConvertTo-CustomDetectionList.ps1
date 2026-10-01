function ConvertTo-CustomDetectionList {
    <#
    .SYNOPSIS
        Wraps a value as a list of items.

    .DESCRIPTION
        Null becomes an empty list. A string, a dictionary or a scalar becomes
        a one-item list. An enumerable is returned as an array of its items.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter()]
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) { return , [object[]]@() }
    return , [object[]]@($Value)
}
