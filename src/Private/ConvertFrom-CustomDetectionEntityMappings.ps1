function ConvertFrom-CustomDetectionEntityMappings {
    <#
    .SYNOPSIS
        Converts Graph entity mappings into the YAML entityMappings shape.

    .DESCRIPTION
        Drops null collections and empty columns as returned by the Graph API,
        wraps single items into lists, and translates the legacy impactedAssets
        collection into the same shape.
    #>
    [CmdletBinding(DefaultParameterSetName = 'EntityMappings')]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(ParameterSetName = 'EntityMappings')]
        [AllowNull()]
        [object]$EntityMappings,

        [Parameter(ParameterSetName = 'ImpactedAssets')]
        [AllowNull()]
        [object[]]$ImpactedAssets,

        [Parameter()]
        [switch]$ValidateIdentifiers
    )

    if ($PSCmdlet.ParameterSetName -eq 'ImpactedAssets') {
        $entities = [System.Collections.Generic.List[object]]::new()
        foreach ($asset in @($ImpactedAssets)) {
            $map = ConvertTo-CustomDetectionHashtable -InputObject $asset
            if (-not $map) { continue }
            $odataType = "$($map['@odata.type'])"
            if ($odataType -notmatch 'impacted(\w+)Asset') { continue }
            $entities.Add(@{ entityType = $Matches[1]; entityIdentifier = "$($map['identifier'])" })
        }
        if ($entities.Count -eq 0) {
            return $null
        }
        return ConvertTo-CustomDetectionEntityMappings -ImpactedEntities $entities.ToArray() -SkipIdentifierValidation:(-not $ValidateIdentifiers)
    }

    if ($null -eq $EntityMappings) {
        return $null
    }

    return ConvertTo-CustomDetectionEntityMappings -EntityMappings $EntityMappings -SkipIdentifierValidation:(-not $ValidateIdentifiers)
}
