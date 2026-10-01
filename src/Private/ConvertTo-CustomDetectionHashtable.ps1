function ConvertTo-CustomDetectionHashtable {
    <#
    .SYNOPSIS
        Returns a shallow ordered hashtable copy of a dictionary or object.

    .DESCRIPTION
        Normalises hashtables, ordered dictionaries and PSCustomObjects into one
        shape so callers can iterate keys without caring about the input type.
        Returns $null for anything that is not a dictionary or an object with
        properties.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter()]
        [AllowNull()]
        [object]$InputObject
    )

    if ($null -eq $InputObject) {
        return $null
    }

    $result = [ordered]@{}

    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($key in $InputObject.Keys) {
            $result[[string]$key] = $InputObject[$key]
        }
        return $result
    }

    if ($InputObject -is [string] -or $InputObject -is [System.Collections.IEnumerable] -or $InputObject -is [ValueType]) {
        return $null
    }

    foreach ($property in $InputObject.PSObject.Properties) {
        $result[$property.Name] = $property.Value
    }

    return $result
}
