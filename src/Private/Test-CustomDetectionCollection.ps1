function Test-CustomDetectionCollection {
    <#
    .SYNOPSIS
        Tells whether a collection dictionary holds at least one item.

    .DESCRIPTION
        The Graph API returns entity mappings and automated actions as a
        dictionary of collections, most of them null. This returns $true when
        any collection carries an item.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter()]
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) { return $false }
    $map = ConvertTo-CustomDetectionHashtable -InputObject $Value
    if ($null -eq $map) { return $false }
    foreach ($key in $map.Keys) {
        $item = $map[$key]
        if ($null -ne $item -and @($item).Count -gt 0) { return $true }
    }
    return $false
}
