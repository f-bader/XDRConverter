function Get-CustomDetectionPopulatedEntry {
    <#
    .SYNOPSIS
        Returns the entries of a map that carry a value.

    .DESCRIPTION
        OData annotations and entries whose value is null or an empty string
        are left out. The result keeps the order of the map.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter()]
        [AllowNull()]
        [object]$Map
    )

    $result = [ordered]@{}
    $source = ConvertTo-CustomDetectionHashtable -InputObject $Map
    if ($null -eq $source) { return $result }
    foreach ($key in @($source.Keys)) {
        if ("$key".StartsWith('@')) { continue }
        $value = $source[$key]
        if ($null -eq $value -or "$value" -eq '') { continue }
        $result[[string]$key] = $value
    }
    return $result
}
